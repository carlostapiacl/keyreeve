//! Your own checks and actions, as programs in `~/.keyreeve/providers`. This is the one place
//! keyreeve runs code from a file, so a file that ships can never use it, and yours runs only
//! after you approve it. Changing the file or its program undoes the approval.
//!
//! The program gets the key on stdin, never in its arguments, and answers with one JSON object:
//! `{"result":"works","fields":{"account":"me"},"message":"Done"}`.
//!
//! A file with `rotates: true` also makes and revokes keys with the same program. `KEYREEVE_MODE`
//! says which: `create` gets the name for the new key in `KEYREEVE_KEY_NAME` and answers
//! `{"result":"created","fields":{"id":"42"},"value":"<the new key>"}`, or `"refused"` when it made
//! none; `revoke` gets the id in `KEYREEVE_ID` and answers `"revoked"`, or `"not_found"`.

use crate::recipe::{CustomRun, Rendered, PROGRAM_CREATE_PATH, PROGRAM_REVOKE_PATH};
use crate::secret::Secret;
use crate::transport::{Request, Response, Transport, TransportError};
use serde::{Deserialize, Deserializer};
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
    /// Only in `create`: the new key. Never shown, and dropped from the message.
    #[serde(default, deserialize_with = "secret_value")]
    pub value: Option<Secret>,
}

fn secret_value<'de, D: Deserializer<'de>>(input: D) -> Result<Option<Secret>, D::Error> {
    Ok(Option::<String>::deserialize(input)?.map(Secret::new))
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
    run_with(folder, run, mode, key, &[])
}

/// The same, with a few more variables that are not secret, such as the id of a key to revoke.
fn run_with(
    folder: &Path,
    run: &CustomRun,
    mode: &str,
    key: Option<&Secret>,
    vars: &[(&str, &str)],
) -> Result<Answer, String> {
    let program = program_path(folder, &run.program)?;
    let mut command = Command::new(&program);
    command.env_clear();
    for (name, value) in vars {
        command.env(name, value);
    }
    let mut child = command
        .args(&run.args)
        .current_dir(folder)
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
    let text = zeroize::Zeroizing::new(text);
    let mut answer: Answer = serde_json::from_str(text.trim())
        .map_err(|_| "the program's answer could not be read".to_owned())?;
    answer.message = safe_message(&answer.message, key);
    if answer.value.is_some() {
        answer.message = safe_message(&answer.message, answer.value.as_ref());
    }
    Ok(answer)
}

/// Lets the rotation engine make, check and revoke keys with a program of yours, as if it were a
/// provider's web service. It answers the engine's requests and sends nothing over the network.
pub struct ProgramTransport {
    pub folder: PathBuf,
    pub run: CustomRun,
}

/// An id goes in the journal and in a variable, so it is short and plain.
fn plain_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn status_only(status: u16) -> Response {
    Response {
        status,
        headers: Vec::new(),
        body: Secret::new(""),
    }
}

impl ProgramTransport {
    fn answer(
        &self,
        mode: &str,
        key: &Secret,
        vars: &[(&str, &str)],
    ) -> Result<Answer, TransportError> {
        run_with(&self.folder, &self.run, mode, Some(key), vars).map_err(|_| TransportError::Failed)
    }
}

impl Transport for ProgramTransport {
    fn send(&mut self, request: &Request) -> Result<Response, TransportError> {
        let Rendered { method, path, .. } = &request.rendered;
        let credential = &request.auth.1;
        let create_prefix = PROGRAM_CREATE_PATH.trim_end_matches("{key_name}");
        let revoke_prefix = PROGRAM_REVOKE_PATH.trim_end_matches("{id}");
        if method == "POST" {
            if let Some(name) = path.strip_prefix(create_prefix) {
                let name = decode(name).ok_or(TransportError::Failed)?;
                let answer = self.answer("create", credential, &[("KEYREEVE_KEY_NAME", &name)])?;
                return match answer.result.as_str() {
                    "created" => {
                        let id = answer.fields.get("id").filter(|id| plain_id(id));
                        let (Some(id), Some(value)) = (id, answer.value) else {
                            return Err(TransportError::Failed);
                        };
                        let body = serde_json::json!({ "id": id, "value": value.expose() });
                        Ok(Response {
                            status: 200,
                            headers: Vec::new(),
                            body: Secret::new(body.to_string()),
                        })
                    }
                    "refused" => Ok(status_only(400)),
                    _ => Err(TransportError::Failed),
                };
            }
            if let Some(id) = path.strip_prefix(revoke_prefix) {
                let id = decode(id)
                    .filter(|id| plain_id(id))
                    .ok_or(TransportError::Failed)?;
                let answer = self.answer("revoke", credential, &[("KEYREEVE_ID", &id)])?;
                return match answer.result.as_str() {
                    "revoked" => Ok(status_only(200)),
                    "not_found" => Ok(status_only(404)),
                    _ => Ok(status_only(500)),
                };
            }
        }
        let answer = self.answer("check", credential, &[])?;
        match answer.result.as_str() {
            "works" => Ok(status_only(200)),
            "rejected" => Ok(status_only(401)),
            "forbidden" => Ok(status_only(403)),
            _ => Err(TransportError::Failed),
        }
    }
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
