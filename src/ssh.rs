//! Checks an SSH key by greeting the server, through the system's own `ssh`. The key stays in its
//! file, and only the account named in the server's greeting comes back.

use crate::recipe::Recipe;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

/// A private copy of a key, for the one call to `ssh` that needs a file. It is overwritten and
/// removed when this value is dropped. A crash in between leaves it, readable only by you.
pub struct TempKey(PathBuf);

/// True only for a name this file writes: `.ssh-key-<process>-<count>`.
fn is_our_copy(name: &str) -> bool {
    name.strip_prefix(".ssh-key-")
        .and_then(|rest| rest.split_once('-'))
        .is_some_and(|(process, count)| {
            let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
            digits(process) && digits(count)
        })
}

/// Removes what a crash left. A copy lives for one call to `ssh`, so an hour old is nobody's. Only
/// plain files with this exact name count, and a link is never followed.
fn sweep_old_copies(folder: &Path) {
    let Ok(entries) = fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let stale = meta
            .modified()
            .ok()
            .and_then(|time| time.elapsed().ok())
            .is_some_and(|age| age.as_secs() > 3600);
        if stale && meta.is_file() && is_our_copy(&entry.file_name().to_string_lossy()) {
            drop(TempKey(entry.path()));
        }
    }
}

impl TempKey {
    pub fn write(text: &str) -> Result<Self, String> {
        let folder = crate::providers::home();
        let failed = |_| "could not prepare the key for ssh".to_owned();
        fs::create_dir_all(&folder).map_err(failed)?;
        sweep_old_copies(&folder);
        let name = format!(
            ".ssh-key-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::SeqCst)
        );
        let path = folder.join(name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(failed)?;
        // Dropping this on the way out of an error still removes the file.
        let key = Self(path);
        file.write_all(text.as_bytes()).map_err(failed)?;
        if !text.ends_with('\n') {
            file.write_all(b"\n").map_err(failed)?;
        }
        Ok(key)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempKey {
    fn drop(&mut self) {
        // Overwriting through a link would destroy whatever it points to.
        if let Ok(meta) = fs::symlink_metadata(&self.0) {
            if meta.is_file() {
                let _ = fs::write(&self.0, vec![0u8; meta.len() as usize]);
            }
        }
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    Accepted(String),
    Refused,
    Unknown,
}

pub fn greet(recipe: &Recipe, file: &Path) -> Result<Reply, String> {
    let host = recipe.hosts.first().ok_or("no host")?;
    let user = recipe.auth.user.as_deref().ok_or("no user")?;
    if !file.is_file() {
        return Err("the key file was not found".into());
    }
    let output = Command::new("/usr/bin/ssh")
        .arg("-i")
        .arg(file)
        .args([
            "-T",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "StrictHostKeyChecking=yes",
        ])
        .arg(format!("{user}@{host}"))
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "ssh could not start".to_owned())?;
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let between = recipe.auth.reply_between.as_deref().unwrap_or_default();
    Ok(read_reply(&text, between))
}

fn read_reply(text: &str, between: &[String]) -> Reply {
    if let [start, end] = between {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix(start.as_str()) {
                if let Some((account, _)) = rest.split_once(end.as_str()) {
                    return Reply::Accepted(account.to_owned());
                }
            }
        }
    }
    if text.contains("Permission denied") {
        Reply::Refused
    } else {
        Reply::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn between() -> Vec<String> {
        vec!["Hi ".to_owned(), "!".to_owned()]
    }

    #[test]
    fn reads_the_account_from_the_greeting() {
        let text = "Hi me/repo! You've successfully authenticated, but GitHub does not provide shell access.\n";
        assert_eq!(
            read_reply(text, &between()),
            Reply::Accepted("me/repo".into())
        );
    }

    #[test]
    fn only_its_own_names_can_be_swept() {
        assert!(is_our_copy(".ssh-key-123-0"));
        for name in [
            ".ssh-key-backup",
            ".ssh-key-1",
            ".ssh-key-1-a",
            ".ssh-key--1",
            "ssh-key-1-1",
        ] {
            assert!(!is_our_copy(name), "{name}");
        }
    }

    #[test]
    fn the_sweep_takes_only_old_copies_of_its_own() {
        let dir = std::env::temp_dir().join(format!("keyreeve-sweep-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        let write = |name: &str, aged: bool| {
            let path = dir.join(name);
            fs::write(&path, "x").unwrap();
            if aged {
                fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(old)
                    .unwrap();
            }
            path
        };
        let stale = write(".ssh-key-1-1", true);
        let running = write(".ssh-key-1-2", false);
        let backup = write(".ssh-key-backup", true);
        sweep_old_copies(&dir);
        assert!(!stale.exists());
        assert!(running.exists());
        assert!(backup.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dropping_a_link_leaves_its_target_alone() {
        let dir = std::env::temp_dir().join(format!("keyreeve-ssh-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        fs::write(&target, "keep").unwrap();
        let link = dir.join(".ssh-key-1-1");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        drop(TempKey(link.clone()));
        assert!(fs::symlink_metadata(&link).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn tells_a_refusal_from_a_failed_connection() {
        assert_eq!(
            read_reply(
                "git@github.com: Permission denied (publickey).\n",
                &between()
            ),
            Reply::Refused
        );
        assert_eq!(
            read_reply("Host key verification failed.\n", &between()),
            Reply::Unknown
        );
        assert_eq!(
            read_reply(
                "connect to host github.com port 22: timed out\n",
                &between()
            ),
            Reply::Unknown
        );
    }
}
