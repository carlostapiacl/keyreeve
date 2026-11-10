//! Procedures: small programs that know how to update one kind of place where a key lives, such as a
//! variable in an env file on a server or a secret at GitHub. A procedure never holds a key, so it can live
//! in git. Some ship with keyreeve, and the rest live in a folder the person chooses.
//!
//! The contract:
//!
//! - `<procedure> apply --name=value...` gets the new value on stdin and puts it in place. Exit 0 means it
//!   is there. What it prints is ignored.
//! - `<procedure> check --name=value...` prints one line: the SHA-256 of the value in place, in hex,
//!   `absent` when the place has no such value, or `present` when it has one that cannot be read back.
//!   Never the value. Anything else is an error, and is never shown.
//! - Each parameter also arrives as `PLACE_<NAME>` in the environment, which is otherwise clean.
//!
//! A place is pinned to its procedure's SHA-256 when a person approves it, because a place receives the
//! real key. A procedure that changed by a byte is not run until the person approves it again.

use crate::engine::{Sink, SinkError};
use crate::providers;
use crate::secret::Secret;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The procedures that ship. A file in the person's folder cannot take one of these names.
const BUILTIN: &[(&str, &str)] = &[
    ("coolify-env", include_str!("../procedures/coolify-env.sh")),
    (
        "github-secret",
        include_str!("../procedures/github-secret.sh"),
    ),
    ("netlify-env", include_str!("../procedures/netlify-env.sh")),
    ("ssh-env", include_str!("../procedures/ssh-env.sh")),
    (
        "supabase-secret",
        include_str!("../procedures/supabase-secret.sh"),
    ),
    ("vercel-env", include_str!("../procedures/vercel-env.sh")),
];

const MAX_PROCEDURE_BYTES: u64 = 256 * 1024;
const MAX_ANSWER_BYTES: u64 = 4096;
const MAX_PARAMS: usize = 16;
const MAX_VALUE_CHARS: usize = 512;
const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin";

pub type Params = BTreeMap<String, String>;

/// The folder of the person's own procedures: `procedures` in keyreeve's home.
pub fn default_folder() -> PathBuf {
    providers::home().join("procedures")
}

/// Lower case letters, digits and dashes, as a file name without its `.sh`.
pub fn is_valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Builtin,
    Folder,
}

#[derive(Debug, Clone)]
pub struct Procedure {
    pub name: String,
    pub origin: Origin,
    pub text: Vec<u8>,
    pub sha256: String,
}

/// Finds a procedure by name: one that ships, or a file `<name>.sh` or `<name>` in the folder.
pub fn load(name: &str, folder: &Path) -> Result<Procedure, String> {
    if !is_valid_name(name) {
        return Err(format!(
            "{name} is not a procedure name: lower case letters, digits and dashes"
        ));
    }
    if let Some((_, text)) = BUILTIN.iter().find(|(id, _)| *id == name) {
        return Ok(Procedure {
            name: name.to_owned(),
            origin: Origin::Builtin,
            text: text.as_bytes().to_vec(),
            sha256: sha256_hex(text.as_bytes()),
        });
    }
    for candidate in [folder.join(format!("{name}.sh")), folder.join(name)] {
        let Ok(meta) = fs::metadata(&candidate) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if meta.len() > MAX_PROCEDURE_BYTES {
            return Err(format!("the procedure {name} is too large"));
        }
        let text = fs::read(&candidate).map_err(|_| format!("{name} could not be read"))?;
        return Ok(Procedure {
            name: name.to_owned(),
            origin: Origin::Folder,
            sha256: sha256_hex(&text),
            text,
        });
    }
    Err(format!("there is no procedure called {name}"))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub optional: bool,
    pub about: String,
}

/// What a procedure is, for a person to read before approving it. The text goes too, since that is
/// what they approve.
#[derive(Debug, Clone, Serialize)]
pub struct Listed {
    pub name: String,
    pub origin: Origin,
    pub sha256: String,
    pub description: String,
    pub params: Vec<Param>,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

/// Reads the header a procedure declares itself with: `# keyreeve-procedure: what it updates` and one
/// `# param name: what it is` per parameter, `(optional)` first for one that can be left out.
pub fn describe(text: &str) -> (String, Vec<Param>) {
    let mut description = String::new();
    let mut params = Vec::new();
    for line in text.lines().take(40) {
        let Some(line) = line.strip_prefix('#') else {
            continue;
        };
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("keyreeve-procedure:") {
            description = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("param ") {
            let Some((name, about)) = rest.split_once(':') else {
                continue;
            };
            let about = about.trim();
            let optional = about.starts_with("(optional)");
            params.push(Param {
                name: name.trim().to_owned(),
                optional,
                about: about.trim_start_matches("(optional)").trim().to_owned(),
            });
        }
    }
    (description, params)
}

fn listed(procedure: &Procedure, problem: Option<String>) -> Listed {
    let text = String::from_utf8_lossy(&procedure.text).into_owned();
    let (description, params) = describe(&text);
    Listed {
        name: procedure.name.clone(),
        origin: procedure.origin,
        sha256: procedure.sha256.clone(),
        description,
        params,
        text,
        problem,
    }
}

/// Every procedure: those that ship, then the folder's, by name.
pub fn list(folder: &Path) -> Vec<Listed> {
    let mut out: Vec<Listed> = BUILTIN
        .iter()
        .filter_map(|(name, _)| load(name, folder).ok())
        .map(|procedure| listed(&procedure, None))
        .collect();
    let mut names: Vec<String> = fs::read_dir(folder)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| !name.starts_with('.'))
                .map(|name| name.strip_suffix(".sh").unwrap_or(&name).to_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.dedup();
    for name in names {
        if BUILTIN.iter().any(|(id, _)| *id == name) {
            if let Ok(builtin) = load(&name, folder) {
                out.push(Listed {
                    origin: Origin::Folder,
                    problem: Some(
                        "a procedure that ships has this name, so this file is never used".into(),
                    ),
                    ..listed(&builtin, None)
                });
            }
            continue;
        }
        if !is_valid_name(&name) {
            continue;
        }
        if let Ok(procedure) = load(&name, folder) {
            out.push(listed(&procedure, None));
        }
    }
    out
}

/// Names are lower case words and values one line of plain text, so a parameter cannot smuggle an option
/// or a second command.
pub fn check_params(params: &Params) -> Result<(), String> {
    if params.len() > MAX_PARAMS {
        return Err(format!("at most {MAX_PARAMS} parameters"));
    }
    for (name, value) in params {
        let good_name = (1..=32).contains(&name.len())
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !good_name {
            return Err(format!(
                "{name} is not a parameter name: lower case letters, digits and _"
            ));
        }
        if value.chars().count() > MAX_VALUE_CHARS || value.chars().any(char::is_control) {
            return Err(format!("the parameter {name} must be one short line"));
        }
    }
    Ok(())
}

/// What a check found in a place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Found {
    /// The SHA-256 of the value in place.
    Hash {
        sha256: String,
    },
    Absent,
    /// A value is there, and the place does not give it back.
    Present,
}

/// Reads a check's answer. It must be a hash or one of two words: anything else could be the value itself,
/// so it is refused without being quoted.
pub fn parse_check(text: &str) -> Result<Found, String> {
    let answer = text.trim();
    match answer {
        "absent" => Ok(Found::Absent),
        "present" => Ok(Found::Present),
        _ if answer.len() == 64 && answer.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
            Ok(Found::Hash {
                sha256: answer.to_ascii_lowercase(),
            })
        }
        _ => Err("the procedure did not answer with a hash, absent or present".into()),
    }
}

/// A procedure's exit status in words. The statuses are a convention the built-in procedures follow.
fn status_words(code: Option<i32>) -> String {
    match code {
        Some(64) => "a parameter is missing or is not plain text".into(),
        Some(65) => "that value cannot go in this place".into(),
        Some(66) => "the place was not found".into(),
        Some(69) => "a program the procedure needs is missing".into(),
        Some(70) => "the place did not answer as expected".into(),
        Some(75) => "the value is in place, but the restart after it failed".into(),
        Some(code) => format!("the procedure stopped with status {code}"),
        None => "the procedure was stopped".into(),
    }
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A folder only this user can open, for the copy of a procedure that runs.
fn private_folder() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.subsec_nanos());
    let path = std::env::temp_dir().join(format!(
        "keyreeve-procedure-{}-{}-{nanos}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&path)
        .map_err(|_| "the procedure could not be prepared".to_owned())?;
    Ok(path)
}

/// Runs procedures for places. What runs is a private copy of the exact bytes that were hashed, so the
/// file cannot change between the check of its pin and its run.
#[derive(Debug, Clone)]
pub struct Runner {
    pub folder: PathBuf,
    /// The PATH procedures get.
    pub path: String,
    /// `keyreeve-vault`, for a procedure that reaches an API with a key of the person's through the proxy.
    pub vault_tool: Option<PathBuf>,
    pub limit: Duration,
}

impl Runner {
    pub fn new(folder: PathBuf) -> Self {
        Runner {
            folder,
            path: DEFAULT_PATH.to_owned(),
            vault_tool: None,
            limit: Duration::from_secs(120),
        }
    }

    /// The procedure, if it is still the one the person approved.
    pub fn pinned(&self, name: &str, pin: &str) -> Result<Procedure, String> {
        let procedure = load(name, &self.folder)?;
        if pin.is_empty() || !procedure.sha256.eq_ignore_ascii_case(pin) {
            return Err(format!(
                "the procedure {name} changed since it was approved, so it does not run until it is approved again"
            ));
        }
        Ok(procedure)
    }

    pub fn check(&self, name: &str, pin: &str, params: &Params) -> Result<Found, String> {
        let procedure = self.pinned(name, pin)?;
        let (code, text) = self.run(&procedure, "check", params, None)?;
        if code != Some(0) {
            return Err(status_words(code));
        }
        parse_check(&text)
    }

    pub fn apply(
        &self,
        name: &str,
        pin: &str,
        params: &Params,
        value: &Secret,
    ) -> Result<(), String> {
        let procedure = self.pinned(name, pin)?;
        let (code, _) = self.run(&procedure, "apply", params, Some(value))?;
        if code != Some(0) {
            return Err(status_words(code));
        }
        Ok(())
    }

    fn run(
        &self,
        procedure: &Procedure,
        verb: &str,
        params: &Params,
        value: Option<&Secret>,
    ) -> Result<(Option<i32>, String), String> {
        check_params(params)?;
        let folder = private_folder()?;
        let result = self.run_in(&folder, procedure, verb, params, value);
        let _ = fs::remove_dir_all(&folder);
        result
    }

    fn run_in(
        &self,
        folder: &Path,
        procedure: &Procedure,
        verb: &str,
        params: &Params,
        value: Option<&Secret>,
    ) -> Result<(Option<i32>, String), String> {
        let program = folder.join(&procedure.name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let mut file = options
            .open(&program)
            .map_err(|_| "the procedure could not be prepared".to_owned())?;
        file.write_all(&procedure.text)
            .and_then(|()| file.sync_all())
            .map_err(|_| "the procedure could not be prepared".to_owned())?;
        drop(file);

        let mut command = Command::new(&program);
        command
            .arg(verb)
            .args(
                params
                    .iter()
                    .map(|(name, value)| format!("--{name}={value}")),
            )
            .current_dir(folder)
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", std::env::var_os("HOME").unwrap_or_default())
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("KEYREEVE_VERB", verb)
            .stdin(if value.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // What ssh, mktemp and keyreeve-vault need to find the person's agent, temporary folder and home.
        for name in [
            "SSH_AUTH_SOCK",
            "TMPDIR",
            "KEYREEVE_HOME",
            "USER",
            "LOGNAME",
        ] {
            if let Some(found) = std::env::var_os(name) {
                command.env(name, found);
            }
        }
        if let Some(tool) = &self.vault_tool {
            command.env("KEYREEVE_VAULT", tool);
        }
        for (name, value) in params {
            command.env(format!("PLACE_{}", name.to_ascii_uppercase()), value);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Its own group, so a time out ends what it started too, such as ssh.
            command.process_group(0);
        }
        // A file written a moment ago can still be open in a child another thread is starting, until that child
        // runs its own program, and the system refuses to run it meanwhile. That passes in a moment.
        let mut tries = 0;
        let mut child = loop {
            match command.spawn() {
                Ok(child) => break child,
                Err(error) if error.raw_os_error() == Some(26) && tries < 20 => {
                    tries += 1;
                    thread::sleep(Duration::from_millis(25));
                }
                Err(_) => return Err("the procedure could not start".to_owned()),
            }
        };

        let writer = match (child.stdin.take(), value) {
            (Some(mut stdin), Some(value)) => {
                let value = value.clone();
                Some(thread::spawn(move || {
                    let _ = stdin.write_all(value.expose().as_bytes());
                }))
            }
            _ => None,
        };
        let stdout = child.stdout.take().ok_or("the procedure could not start")?;
        let reader = thread::spawn(move || {
            let mut text = String::new();
            let _ = stdout.take(MAX_ANSWER_BYTES).read_to_string(&mut text);
            text
        });

        let started = Instant::now();
        let status = loop {
            match child
                .try_wait()
                .map_err(|_| "the procedure could not be read".to_owned())?
            {
                Some(status) => break status,
                None if started.elapsed() > self.limit => {
                    stop_group(child.id());
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("the procedure took too long".into());
                }
                None => thread::sleep(Duration::from_millis(20)),
            }
        };
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        // What the procedure left running keeps the pipe open, so it is ended before the answer is read.
        stop_group(child.id());
        let text = reader.join().unwrap_or_default();
        Ok((status.code(), text))
    }
}

/// Ends a procedure's process group, with the system's own command, since this crate runs no unsafe code.
fn stop_group(pid: u32) {
    #[cfg(unix)]
    {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &format!("-{pid}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// A place a procedure updates, as a rotation step: the new value goes in, and going back puts the old
/// one in the same way.
pub struct ProcedureSink {
    pub label: String,
    pub runner: Runner,
    pub procedure: String,
    pub pin: String,
    pub params: Params,
}

impl Sink for ProcedureSink {
    fn name(&self) -> &str {
        &self.label
    }

    fn update(&mut self, value: &Secret) -> Result<(), SinkError> {
        self.runner
            .apply(&self.procedure, &self.pin, &self.params, value)
            .map_err(|_| SinkError)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Temp(PathBuf);

    impl Temp {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "keyreeve-procedure-test-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Temp(dir)
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_program(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// An ssh that runs the server's command here, so the built-in ssh-env is tested as it is.
    fn fake_ssh(temp: &Temp) -> Runner {
        let bin = temp.0.join("bin");
        fs::create_dir_all(&bin).unwrap();
        write_program(
            &bin.join("ssh"),
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) shift 2;; -*) shift;; *) break;; esac; done\nshift\nexec /bin/sh -c \"$1\"\n",
        );
        let mut runner = Runner::new(temp.0.join("procedures"));
        runner.path = format!("{}:{DEFAULT_PATH}", bin.display());
        runner.limit = Duration::from_secs(30);
        runner
    }

    fn ssh_params(file: &Path, variable: &str) -> Params {
        Params::from([
            ("host".to_owned(), "vps2".to_owned()),
            ("file".to_owned(), file.display().to_string()),
            ("variable".to_owned(), variable.to_owned()),
        ])
    }

    fn pin(name: &str) -> String {
        load(name, Path::new("/nonexistent")).unwrap().sha256
    }

    #[test]
    fn ssh_env_replaces_one_variable_and_keeps_every_other_line() {
        let temp = Temp::new("ssh-apply");
        let runner = fake_ssh(&temp);
        let file = temp.0.join("app.env");
        fs::write(
            &file,
            "# the app's settings\nexport OPENAI_API_KEY=\"CANARY-old\"\n\nOTHER=stays # a note\nOPENAI_API_KEY=CANARY-old\n",
        )
        .unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        let params = ssh_params(&file, "OPENAI_API_KEY");
        runner
            .apply(
                "ssh-env",
                &pin("ssh-env"),
                &params,
                &Secret::new("CANARY-new_1"),
            )
            .unwrap();
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "# the app's settings\nexport OPENAI_API_KEY=\"CANARY-new_1\"\n\nOTHER=stays # a note\nOPENAI_API_KEY=CANARY-new_1\n"
        );
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o640
        );
        // Nothing is left beside it.
        let left: Vec<_> = fs::read_dir(&temp.0)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(left.len(), 2, "{left:?}");
        assert_eq!(
            runner.check("ssh-env", &pin("ssh-env"), &params).unwrap(),
            Found::Hash {
                sha256: sha256_hex(b"CANARY-new_1")
            }
        );
    }

    #[test]
    fn ssh_env_is_atomic_a_failed_write_leaves_the_file_as_it_was() {
        let temp = Temp::new("ssh-atomic");
        let runner = fake_ssh(&temp);
        let folder = temp.0.join("locked");
        fs::create_dir_all(&folder).unwrap();
        let file = folder.join("app.env");
        fs::write(&file, "A=CANARY-old\nB=2\n").unwrap();
        // The folder takes no new file, so the temporary file cannot be made: the old file stays whole.
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o500)).unwrap();
        let result = runner.apply(
            "ssh-env",
            &pin("ssh-env"),
            &ssh_params(&file, "A"),
            &Secret::new("CANARY-new"),
        );
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
        let error = result.unwrap_err();
        assert!(!error.contains("CANARY"));
        assert_eq!(fs::read_to_string(&file).unwrap(), "A=CANARY-old\nB=2\n");
    }

    #[test]
    fn ssh_env_adds_a_missing_variable_and_a_check_says_absent_before() {
        let temp = Temp::new("ssh-absent");
        let runner = fake_ssh(&temp);
        let file = temp.0.join("app.env");
        fs::write(&file, "# only a comment\nB=2").unwrap();
        let params = ssh_params(&file, "NEW_KEY");
        assert_eq!(
            runner.check("ssh-env", &pin("ssh-env"), &params).unwrap(),
            Found::Absent
        );
        runner
            .apply(
                "ssh-env",
                &pin("ssh-env"),
                &params,
                &Secret::new("CANARY-v"),
            )
            .unwrap();
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "# only a comment\nB=2\nNEW_KEY=CANARY-v\n"
        );
    }

    #[test]
    fn ssh_env_refuses_parameters_that_are_not_plain() {
        let temp = Temp::new("ssh-plain");
        let runner = fake_ssh(&temp);
        let file = temp.0.join("app.env");
        fs::write(&file, "A=1\n").unwrap();
        let marker = temp.0.join("ran");
        for (name, value) in [
            ("variable", format!("A;touch {}", marker.display())),
            ("host", "-oProxyCommand=touch".to_owned()),
            (
                "file",
                format!("{}'; touch '{}", file.display(), marker.display()),
            ),
            ("service", "$(touch x)".to_owned()),
        ] {
            let mut params = ssh_params(&file, "A");
            params.insert(name.to_owned(), value);
            let error = runner
                .check("ssh-env", &pin("ssh-env"), &params)
                .unwrap_err();
            assert!(error.contains("parameter"), "{name}: {error}");
        }
        assert!(!marker.exists());
    }

    #[test]
    fn a_check_returns_a_hash_only_and_never_the_value() {
        let temp = Temp::new("canary");
        let folder = temp.0.join("procedures");
        fs::create_dir_all(&folder).unwrap();
        let runner = Runner::new(folder.clone());
        for (body, expected) in [
            ("echo CANARY-value", None),
            ("printf 'CANARY\\n%s\\n' abc", None),
            ("echo ABSENT", None),
            ("echo absent", Some(Found::Absent)),
            ("echo present", Some(Found::Present)),
            (
                "printf '%s\\n' FFEEDDCCBBAA99887766554433221100ffeeddccbbaa99887766554433221100",
                Some(Found::Hash {
                    sha256: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
                        .into(),
                }),
            ),
            ("echo CANARY-err >&2; exit 9", None),
        ] {
            let path = folder.join("mine.sh");
            write_program(&path, &format!("#!/bin/sh\n{body}\n"));
            let pinned = sha256_hex(&fs::read(&path).unwrap());
            let result = runner.check("mine", &pinned, &Params::new());
            match expected {
                Some(found) => assert_eq!(result.unwrap(), found, "{body}"),
                None => {
                    let error = result.unwrap_err();
                    assert!(!error.contains("CANARY"), "{body}: {error}");
                }
            }
        }
    }

    #[test]
    fn apply_gets_the_value_on_stdin_and_never_in_arguments_or_environment() {
        let temp = Temp::new("stdin");
        let folder = temp.0.join("procedures");
        fs::create_dir_all(&folder).unwrap();
        let seen = temp.0.join("seen");
        write_program(
            &folder.join("mine.sh"),
            &format!(
                "#!/bin/sh\nvalue=$(cat)\n{{ echo \"value=$value\"; echo \"args=$*\"; env; }} > '{}'\necho CANARY-printed\n",
                seen.display()
            ),
        );
        let pinned = sha256_hex(&fs::read(folder.join("mine.sh")).unwrap());
        std::env::set_var("KEYREEVE_TEST_LEAK", "CANARY-env");
        let runner = Runner::new(folder);
        runner
            .apply(
                "mine",
                &pinned,
                &Params::from([("repo".to_owned(), "me/app".to_owned())]),
                &Secret::new("CANARY-secret"),
            )
            .unwrap();
        std::env::remove_var("KEYREEVE_TEST_LEAK");
        let text = fs::read_to_string(seen).unwrap();
        assert!(text.contains("value=CANARY-secret"));
        assert!(text.contains("args=apply --repo=me/app"));
        assert!(text.contains("PLACE_REPO=me/app"));
        assert_eq!(text.matches("CANARY-secret").count(), 1, "{text}");
        assert!(!text.contains("CANARY-env"));
    }

    #[test]
    fn a_changed_procedure_does_not_run_until_approved_again() {
        let temp = Temp::new("pin");
        let folder = temp.0.join("procedures");
        fs::create_dir_all(&folder).unwrap();
        let marker = temp.0.join("ran");
        let path = folder.join("mine.sh");
        write_program(&path, "#!/bin/sh\necho absent\n");
        let approved = sha256_hex(&fs::read(&path).unwrap());
        write_program(
            &path,
            &format!("#!/bin/sh\ntouch '{}'\necho absent\n", marker.display()),
        );
        let runner = Runner::new(folder.clone());
        let mut sink = ProcedureSink {
            label: "mine".into(),
            runner: runner.clone(),
            procedure: "mine".into(),
            pin: approved.clone(),
            params: Params::new(),
        };
        assert!(sink.update(&Secret::new("CANARY")).is_err());
        assert!(runner.check("mine", &approved, &Params::new()).is_err());
        assert!(runner.check("mine", "", &Params::new()).is_err());
        assert!(!marker.exists());
        let again = sha256_hex(&fs::read(&path).unwrap());
        assert_eq!(
            runner.check("mine", &again, &Params::new()).unwrap(),
            Found::Absent
        );
        assert!(marker.exists());
    }

    #[test]
    fn a_folder_file_cannot_take_a_builtin_name_and_names_stay_inside_the_folder() {
        let temp = Temp::new("names");
        let folder = temp.0.join("procedures");
        fs::create_dir_all(&folder).unwrap();
        write_program(&folder.join("ssh-env.sh"), "#!/bin/sh\necho absent\n");
        let found = load("ssh-env", &folder).unwrap();
        assert_eq!(found.origin, Origin::Builtin);
        for bad in ["../x", "/bin/sh", "A", "", "-x", "a/b"] {
            assert!(load(bad, &folder).is_err(), "{bad}");
        }
        let listed = list(&folder);
        assert!(listed
            .iter()
            .any(|entry| entry.name == "ssh-env" && entry.problem.is_some()));
        assert_eq!(
            listed
                .iter()
                .filter(|entry| entry.origin == Origin::Builtin)
                .count(),
            BUILTIN.len()
        );
    }

    #[test]
    fn every_builtin_declares_what_it_is_and_its_parameters() {
        for (name, text) in BUILTIN {
            assert!(text.starts_with("#!/bin/sh\n"), "{name}");
            let (description, params) = describe(text);
            assert!(!description.is_empty(), "{name}");
            assert!(params.iter().any(|param| !param.optional), "{name}");
            // Every parameter it reads is declared, so the review shows all of them.
            for param in &params {
                assert!(
                    text.contains(&format!("PLACE_{}", param.name.to_ascii_uppercase())),
                    "{name}: {}",
                    param.name
                );
            }
        }
    }

    #[test]
    fn a_procedure_that_hangs_is_stopped() {
        let temp = Temp::new("hang");
        let folder = temp.0.join("procedures");
        fs::create_dir_all(&folder).unwrap();
        write_program(&folder.join("slow.sh"), "#!/bin/sh\nsleep 30 &\nsleep 30\n");
        let pinned = sha256_hex(&fs::read(folder.join("slow.sh")).unwrap());
        let mut runner = Runner::new(folder);
        runner.limit = Duration::from_millis(300);
        let started = Instant::now();
        let error = runner.check("slow", &pinned, &Params::new()).unwrap_err();
        assert!(error.contains("too long"));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn parameters_are_plain() {
        assert!(check_params(&Params::from([("host".into(), "vps2".into())])).is_ok());
        for (name, value) in [
            ("Host", "x"),
            ("1x", "x"),
            ("host-name", "x"),
            ("host", "a\nb"),
        ] {
            assert!(
                check_params(&Params::from([(name.to_owned(), value.to_owned())])).is_err(),
                "{name}"
            );
        }
    }
}
