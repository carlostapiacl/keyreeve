//! Checks an SSH key by greeting the server, through the system's own `ssh`. The key stays in its
//! file, and only the account named in the server's greeting comes back.

use crate::recipe::Recipe;
use std::path::Path;
use std::process::{Command, Stdio};

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
