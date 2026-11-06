//! The places that use a key, which a rotation updates before it revokes the old one.

use crate::engine::{Sink, SinkError};
use crate::keys::{holds_key, swap_key};
use crate::providers;
use crate::script;
use crate::secret::Secret;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// A file on disk that holds the key. Whichever value of this rotation it has is replaced.
pub struct FileSink {
    pub(crate) label: String,
    pub(crate) path: PathBuf,
    pub(crate) known: Vec<Secret>,
}

impl FileSink {
    fn replace(&self, text: &str, value: &Secret) -> Option<String> {
        let mut out = text.to_owned();
        for known in &self.known {
            if known != value {
                out = swap_key(&out, known.expose(), value.expose());
            }
        }
        holds_key(&out, value.expose()).then_some(out)
    }
}

static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

/// Opens a new file only this user can read. It refuses anything already there, so a file or link
/// someone prepared under that name cannot receive the key.
fn create_private(folder: &Path, stem: &std::ffi::OsStr) -> std::io::Result<(fs::File, PathBuf)> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    loop {
        let mut name = stem.to_owned();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.subsec_nanos());
        name.push(format!(
            ".keyreeve-{}-{}-{nanos}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::SeqCst)
        ));
        let path = folder.join(name);
        match options.open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
}

/// Writes next to the real file and renames over it, so a crash leaves the old text or the new. A link
/// is followed first: replacing the link itself would leave its target with a revoked key.
fn write_in_place(path: &Path, text: &str) -> std::io::Result<()> {
    let target = fs::canonicalize(path)?;
    let meta = fs::metadata(&target)?;
    let folder = target.parent().ok_or(std::io::ErrorKind::NotFound)?;
    let stem = target.file_name().ok_or(std::io::ErrorKind::NotFound)?;
    let (mut file, temp) = create_private(folder, stem)?;
    let result = (|| {
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&temp, meta.permissions())?;
        fs::rename(&temp, &target)?;
        // Without this, a power cut can undo the rename after the journal recorded the step.
        fs::File::open(folder)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

impl Sink for FileSink {
    fn name(&self) -> &str {
        &self.label
    }

    fn update(&mut self, value: &Secret) -> Result<(), SinkError> {
        let text = Zeroizing::new(fs::read_to_string(&self.path).map_err(|_| SinkError)?);
        // A file holding none of these values is the wrong file, and it stays untouched.
        let new_text = Zeroizing::new(self.replace(&text, value).ok_or(SinkError)?);
        if *new_text != *text {
            write_in_place(&self.path, &new_text).map_err(|_| SinkError)?;
        }
        if !self.known.contains(value) {
            self.known.push(value.clone());
        }
        Ok(())
    }
}

/// A button of yours, from a provider file you approved, that receives the new key on stdin.
pub struct ActionSink {
    label: String,
    run: crate::recipe::CustomRun,
    action: String,
}

impl Sink for ActionSink {
    fn name(&self) -> &str {
        &self.label
    }

    fn update(&mut self, value: &Secret) -> Result<(), SinkError> {
        script::run(
            &providers::programs_folder(),
            &self.run,
            &self.action,
            Some(value),
        )
        .map(|_| ())
        .map_err(|_| SinkError)
    }
}

pub(crate) fn action_sink(place: &str) -> Result<ActionSink, String> {
    let (provider, action) = place
        .split_once('/')
        .ok_or_else(|| format!("{place} is not provider/action"))?;
    let recipe = providers::load(provider)?;
    let found = recipe
        .actions
        .iter()
        .find(|candidate| candidate.id == action)
        .ok_or_else(|| format!("{provider} has no action {action}"))?;
    let run = found
        .run
        .clone()
        .ok_or_else(|| format!("{place} runs no program"))?;
    Ok(ActionSink {
        label: format!("action:{place}"),
        run,
        action: action.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> Secret {
        Secret::new(value)
    }

    fn folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyreeve-rotate-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_file_keeps_everything_but_the_key_and_can_go_back() {
        let dir = folder("file");
        let path = dir.join("app.env");
        fs::write(&path, "# note\nTOKEN=old-value\nOTHER=stays\n").unwrap();
        let mut sink = FileSink {
            label: "file".into(),
            path: path.clone(),
            known: vec![secret("old-value")],
        };
        sink.update(&secret("new-value")).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# note\nTOKEN=new-value\nOTHER=stays\n"
        );
        sink.update(&secret("new-value")).unwrap();
        sink.update(&secret("old-value")).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# note\nTOKEN=old-value\nOTHER=stays\n"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_file_without_the_key_is_refused_and_untouched() {
        let dir = folder("wrong");
        let path = dir.join("other.env");
        fs::write(&path, "NOTHING=here\n").unwrap();
        let mut sink = FileSink {
            label: "file".into(),
            path: path.clone(),
            known: vec![secret("old-value")],
        };
        assert!(sink.update(&secret("new-value")).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "NOTHING=here\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_file_keeps_its_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = folder("mode");
        let path = dir.join("key");
        fs::write(&path, "old-value").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let mut sink = FileSink {
            label: "file".into(),
            path: path.clone(),
            known: vec![secret("old-value")],
        };
        sink.update(&secret("new-value")).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_longer_value_in_the_same_file_stays() {
        let dir = folder("overlap");
        let path = dir.join("app.env");
        fs::write(&path, "TOKEN=old-value\nOTHER=old-value-2\n").unwrap();
        let mut sink = FileSink {
            label: "file".into(),
            path: path.clone(),
            known: vec![secret("old-value")],
        };
        sink.update(&secret("old-value-new")).unwrap();
        sink.update(&secret("old-value-new")).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "TOKEN=old-value-new\nOTHER=old-value-2\n"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_link_stays_a_link_and_its_target_gets_the_key() {
        let dir = folder("link");
        let target = dir.join("shared.env");
        fs::write(&target, "T=old-value\n").unwrap();
        let link = dir.join("app.env");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut sink = FileSink {
            label: "file".into(),
            path: link.clone(),
            known: vec![secret("old-value")],
        };
        sink.update(&secret("new-value")).unwrap();
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&target).unwrap(), "T=new-value\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_temporary_file_is_new_and_private_from_its_first_byte() {
        use std::os::unix::fs::PermissionsExt;
        let dir = folder("temp");
        let (_file, path) = create_private(&dir, std::ffi::OsStr::new("x")).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
