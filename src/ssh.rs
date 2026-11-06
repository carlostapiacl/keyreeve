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

/// Removes what a crash left. A copy lives for one call to `ssh`, so an hour old is nobody's.
fn sweep_old_copies(folder: &Path) {
    let Ok(entries) = fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let stale = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|time| time.elapsed().ok())
            .is_some_and(|age| age.as_secs() > 3600);
        if stale && name.to_string_lossy().starts_with(".ssh-key-") {
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
        if let Ok(size) = fs::metadata(&self.0).map(|meta| meta.len()) {
            let _ = fs::write(&self.0, vec![0u8; size as usize]);
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
