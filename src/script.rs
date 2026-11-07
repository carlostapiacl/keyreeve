//! Your own checks and actions, as programs in `~/.keyreeve/providers`. This is the one place
//! keyreeve runs code from a file, so a file that ships can never use it, and yours runs only
//! after you approve it. Changing the file or its program undoes the approval.
//!
//! The program gets the key on stdin, never in its arguments, and answers with one JSON object:
//! `{"result":"works","fields":{"account":"me"},"message":"Done"}`.

use crate::recipe::CustomRun;
use crate::secret::Secret;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TIME_LIMIT: Duration = Duration::from_secs(60);
const MAX_ANSWER_BYTES: u64 = 64 * 1024;
const MAX_MESSAGE_CHARS: usize = 200;

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Answer {
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(default)]
    pub message: String,
}

/// The program a file names, which must stay inside that file's folder.
pub fn program_path(folder: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("a program must be a path inside the providers folder".into());
    }
    Ok(folder.join(relative))
}

/// Runs a program with a clean environment. Its stderr is dropped, because it could quote the key.
pub fn run(
    folder: &Path,
    run: &CustomRun,
    mode: &str,
    key: Option<&Secret>,
) -> Result<Answer, String> {
    let program = program_path(folder, &run.program)?;
    let mut child = Command::new(&program)
        .args(&run.args)
        .current_dir(folder)
        .env_clear()
        .env(
            "PATH",
            "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
        )
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .env("KEYREEVE_MODE", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "the program could not start".to_owned())?;

    let mut stdin = child.stdin.take().ok_or("the program could not start")?;
    let input = key.cloned();
    let writer = thread::spawn(move || {
        if let Some(key) = input {
            let _ = stdin.write_all(key.expose().as_bytes());
        }
    });
    let stdout = child.stdout.take().ok_or("the program could not start")?;
    let reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.take(MAX_ANSWER_BYTES).read_to_string(&mut text);
        text
    });

    let started = Instant::now();
    let status = loop {
        match child
            .try_wait()
            .map_err(|_| "the program could not be read".to_owned())?
        {
            Some(status) => break status,
            None if started.elapsed() > TIME_LIMIT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("the program took too long".into());
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    };
    let _ = writer.join();
    let text = reader.join().unwrap_or_default();
    if !status.success() {
        return Err(format!(
            "the program stopped with status {}",
            status.code().unwrap_or(-1)
        ));
    }
    let mut answer: Answer = serde_json::from_str(text.trim())
        .map_err(|_| "the program's answer could not be read".to_owned())?;
    answer.message = safe_message(&answer.message, key);
    Ok(answer)
}

/// A program of yours is still not trusted to keep the key out of what it says.
fn safe_message(message: &str, key: Option<&Secret>) -> String {
    let leaked = key.is_some_and(|key| {
        let whole = key.expose();
        (!whole.is_empty() && message.contains(whole))
            || whole
                .split(':')
                .any(|part| part.len() >= 8 && message.contains(part))
    });
    if leaked || message.chars().any(char::is_control) {
        return String::new();
    }
    message.chars().take(MAX_MESSAGE_CHARS).collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn program(dir: &Path, name: &str, body: &str) -> CustomRun {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        CustomRun {
            program: name.to_owned(),
            args: vec!["--flag".to_owned()],
        }
    }

    fn folder(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("keyreeve-script-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn gets_the_key_on_stdin_and_answers_in_json() {
        let dir = folder("ok");
        let run_it = program(
            &dir,
            "p.sh",
            r#"key=$(cat); [ "$key" = "CANARYkey" ] && [ "$1" = "--flag" ] && [ "$KEYREEVE_MODE" = "check" ] && echo '{"result":"works","fields":{"account":"me"},"message":"Done"}'"#,
        );
        let answer = run(&dir, &run_it, "check", Some(&Secret::new("CANARYkey"))).unwrap();
        assert_eq!(answer.result, "works");
        assert_eq!(answer.fields["account"], "me");
        assert_eq!(answer.message, "Done");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_key_is_not_in_the_environment_or_the_arguments() {
        let dir = folder("env");
        std::env::set_var("KEYREEVE_TEST_LEAK", "CANARYenv");
        let run_it = program(
            &dir,
            "p.sh",
            r#"cat >/dev/null; printf '{"result":"works","message":"%s"}' "${KEYREEVE_TEST_LEAK:-clean} $*""#,
        );
        let answer = run(&dir, &run_it, "check", Some(&Secret::new("CANARYkey"))).unwrap();
        assert_eq!(answer.message, "clean --flag");
        std::env::remove_var("KEYREEVE_TEST_LEAK");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_message_that_repeats_the_key_is_dropped() {
        let dir = folder("leak");
        let run_it = program(
            &dir,
            "p.sh",
            r#"key=$(cat); printf '{"result":"works","message":"key %s"}' "$key""#,
        );
        let answer = run(&dir, &run_it, "check", Some(&Secret::new("CANARYkey"))).unwrap();
        assert_eq!(answer.message, "");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn errors_quote_nothing_from_the_program() {
        let dir = folder("err");
        let garbled = program(&dir, "g.sh", "cat >/dev/null; echo CANARYoutput");
        let error = run(&dir, &garbled, "check", None).unwrap_err();
        assert!(!error.contains("CANARY"));
        let failed = program(&dir, "f.sh", "echo CANARYerr >&2; exit 3");
        let error = run(&dir, &failed, "check", None).unwrap_err();
        assert!(error.contains('3') && !error.contains("CANARY"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_program_must_be_inside_the_folder() {
        let dir = folder("path");
        for bad in ["../evil.sh", "/bin/sh", "a/../../evil", ""] {
            assert!(program_path(&dir, bad).is_err(), "{bad}");
        }
        assert!(program_path(&dir, "scripts/ok.sh").is_ok());
    }
}
