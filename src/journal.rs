//! An append-only record of each rotation. It holds key ids and step names, never values.
//! A rotation resumes from this record after a crash.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Started {
        old_id: Option<String>,
    },
    Created {
        new_id: String,
    },
    PendingStored,
    Verified,
    SinkUpdated {
        sink: String,
    },
    Promoted {
        revoke_after: u64,
    },
    OldRevoked,
    Completed,
    RollbackStarted {
        reason: String,
    },
    RolledBack {
        reason: String,
    },
    ManualAction {
        what: String,
    },
    /// The key was replaced by hand, so the id on record belongs to a key this one is not.
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub rotation: u64,
    pub key: String,
    pub at: u64,
    #[serde(flatten)]
    pub event: Event,
}

/// Where a rotation stands, derived from the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Started,
    Created,
    PendingStored,
    Verified,
    Promoted,
    OldRevoked,
    RollingBack,
}

pub trait Backend {
    fn read_lines(&self) -> io::Result<Vec<String>>;
    /// Returns only once the line is durable.
    fn append(&mut self, line: &str) -> io::Result<()>;
}

pub struct Journal {
    backend: Box<dyn Backend>,
    entries: Vec<Entry>,
}

impl Journal {
    pub fn open(backend: Box<dyn Backend>) -> io::Result<Self> {
        let lines = backend.read_lines()?;
        let mut entries = Vec::with_capacity(lines.len());
        for (index, line) in lines.iter().enumerate() {
            match serde_json::from_str(line) {
                Ok(entry) => entries.push(entry),
                // A crash can tear the last line, and only the last one.
                Err(_) if index + 1 == lines.len() => {}
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("journal line {} is damaged", index + 1),
                    ))
                }
            }
        }
        Ok(Self { backend, entries })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn append(&mut self, key: &str, at: u64, event: Event) -> io::Result<()> {
        let rotation = self
            .entries
            .iter()
            .filter(|entry| entry.key == key && matches!(entry.event, Event::Started { .. }))
            .count() as u64;
        let rotation = if matches!(event, Event::Started { .. }) {
            rotation + 1
        } else {
            rotation
        };
        let entry = Entry {
            rotation,
            key: key.to_owned(),
            at,
            event,
        };
        let line = serde_json::to_string(&entry).map_err(io::Error::other)?;
        self.backend.append(&line)?;
        self.entries.push(entry);
        Ok(())
    }

    /// The events of the latest rotation of this key.
    pub fn latest(&self, key: &str) -> Vec<&Event> {
        let Some(rotation) = self
            .entries
            .iter()
            .filter(|entry| entry.key == key)
            .map(|entry| entry.rotation)
            .max()
        else {
            return Vec::new();
        };
        self.entries
            .iter()
            .filter(|entry| entry.key == key && entry.rotation == rotation)
            .map(|entry| &entry.event)
            .collect()
    }

    pub fn phase(&self, key: &str) -> Phase {
        let mut phase = Phase::Idle;
        for event in self.latest(key) {
            phase = match event {
                Event::Started { .. } => Phase::Started,
                Event::Created { .. } => Phase::Created,
                Event::PendingStored => Phase::PendingStored,
                Event::Verified => Phase::Verified,
                Event::Promoted { .. } => Phase::Promoted,
                Event::OldRevoked => Phase::OldRevoked,
                Event::RollbackStarted { .. } => Phase::RollingBack,
                Event::Completed | Event::RolledBack { .. } => Phase::Idle,
                Event::SinkUpdated { .. } | Event::ManualAction { .. } | Event::Replaced => phase,
            };
        }
        phase
    }

    /// The id of the key that the last completed rotation left in place.
    pub fn current_id(&self, key: &str) -> Option<String> {
        let mut current = None;
        let mut candidate = None;
        for entry in self.entries.iter().filter(|entry| entry.key == key) {
            match &entry.event {
                Event::Created { new_id } => candidate = Some(new_id.clone()),
                Event::Promoted { .. } => current = candidate.clone(),
                Event::Replaced => {
                    current = None;
                    candidate = None;
                }
                _ => {}
            }
        }
        current
    }
}

/// A journal in a file with mode 0600, synced to disk on each append.
pub struct FileBackend {
    path: PathBuf,
}

impl FileBackend {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
        }
    }
}

/// A crash can leave half a line at the end. Writing after it would bury it in the middle, and the
/// journal refuses damage in the middle, so the half line goes first. A whole line missing only its
/// break keeps its content.
fn repair_torn_end(path: &Path) -> io::Result<()> {
    // Almost always whole: one byte says so, and only a torn end is read in full.
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok(());
    }
    let mut last = [0u8; 1];
    file.seek(SeekFrom::End(-1))?;
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }
    let mut text = Vec::new();
    file.seek(SeekFrom::Start(0))?;
    file.read_to_end(&mut text)?;
    let start = text
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |at| at + 1);
    let mut file = OpenOptions::new().write(true).open(path)?;
    if serde_json::from_slice::<Entry>(&text[start..]).is_ok() {
        file.seek(SeekFrom::End(0))?;
        file.write_all(b"\n")?;
    } else {
        file.set_len(start as u64)?;
    }
    file.sync_all()
}

impl Backend for FileBackend {
    fn read_lines(&self) -> io::Result<Vec<String>> {
        let mut bytes = Vec::new();
        match File::open(&self.path) {
            Ok(mut file) => {
                file.read_to_end(&mut bytes)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        }
        // A crash can cut a line inside a letter, and that must read as a torn line and not stop
        // every rotation on this machine from resuming.
        Ok(String::from_utf8_lossy(&bytes)
            .lines()
            .map(str::to_owned)
            .collect())
    }

    fn append(&mut self, line: &str) -> io::Result<()> {
        let created = !self.path.exists();
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path)?;
        repair_torn_end(&self.path)?;
        file.write_all(format!("{line}\n").as_bytes())?;
        file.sync_all()?;
        if created {
            if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::File::open(parent)?.sync_all()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "keyreeve-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn survives_reopening_and_a_torn_last_line() {
        let path = temp_path("torn");
        let mut journal = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        journal
            .append("k", 1, Event::Started { old_id: None })
            .unwrap();
        journal.append("k", 2, Event::PendingStored).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"rotation\":1,\"ke").unwrap();

        let journal = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        assert_eq!(journal.entries().len(), 2);
        assert_eq!(journal.phase("k"), Phase::PendingStored);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn writing_after_a_torn_line_leaves_a_journal_that_opens() {
        let path = temp_path("torn-append");
        let mut journal = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        journal
            .append("k", 1, Event::Started { old_id: None })
            .unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"rotation\":1,\"ke").unwrap();

        let mut journal = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        journal.append("k", 2, Event::PendingStored).unwrap();
        journal.append("k", 3, Event::Verified).unwrap();
        let journal = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        assert_eq!(journal.entries().len(), 3);
        assert_eq!(journal.phase("k"), Phase::Verified);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_line_cut_inside_a_letter_still_opens() {
        let path = temp_path("torn-utf8");
        let mut journal = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        journal
            .append("ñ", 1, Event::Started { old_id: None })
            .unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&"{\"key\":\"ñ".as_bytes()[..8]).unwrap();
        let journal = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        assert_eq!(journal.entries().len(), 1);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn replacing_a_key_forgets_its_id() {
        let path = temp_path("replaced");
        let mut journal = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        journal
            .append("k", 1, Event::Started { old_id: None })
            .unwrap();
        journal
            .append("k", 2, Event::Created { new_id: "b".into() })
            .unwrap();
        journal
            .append("k", 3, Event::Promoted { revoke_after: 0 })
            .unwrap();
        journal.append("k", 4, Event::Completed).unwrap();
        assert_eq!(journal.current_id("k").as_deref(), Some("b"));
        journal.append("k", 5, Event::Replaced).unwrap();
        assert_eq!(journal.current_id("k"), None);
        assert_eq!(journal.phase("k"), Phase::Idle);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn refuses_damage_in_the_middle() {
        let path = temp_path("damaged");
        fs::write(&path, "not json\n{}\n").unwrap();
        assert!(Journal::open(Box::new(FileBackend::new(&path))).is_err());
        fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("mode");
        let mut journal = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        journal
            .append("k", 1, Event::Started { old_id: None })
            .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_file(&path).unwrap();
    }
}
