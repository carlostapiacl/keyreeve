//! Checks whether a key still works, with one read-only request. The result says nothing about
//! the key's value, and no error quotes the file it came from.

use crate::inventory::{split_label, strip_comment};
use crate::providers;
use crate::recipe::{extract, Recipe};
use crate::secret::Secret;
use crate::transport::{HttpTransport, Request, Transport, TransportError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const MAX_KEY_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Works {
        host: String,
    },
    Rejected,
    /// A 403 can mean a live key without this permission, or a bad key.
    Forbidden,
    NoResult(String),
}

impl Verdict {
    pub fn works(&self) -> bool {
        matches!(self, Self::Works { .. })
    }

    /// A short word for the history. The history never holds more than this.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Works { .. } => "works",
            Self::Rejected => "rejected",
            Self::Forbidden => "forbidden",
            Self::NoResult(_) => "no_result",
        }
    }
}

/// One line of the history: which file, which recipe, when and the result.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub at: u64,
    pub file: String,
    pub recipe: String,
    pub result: String,
}

/// Adds lines to a private file. A check that ran stays on record even if a later one fails.
pub fn append_history(path: &Path, entries: &[HistoryEntry]) -> io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    for entry in entries {
        let line = serde_json::to_string(entry).map_err(io::Error::other)?;
        writeln!(file, "{line}")?;
    }
    file.sync_all()
}

/// Reads a history, ignoring a line torn by a crash.
pub fn parse_history(text: &str) -> Vec<HistoryEntry> {
    text.lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Works { host } => write!(f, "works ({host})"),
            Self::Rejected => f.write_str("REJECTED"),
            Self::Forbidden => f.write_str(
                "no result (HTTP 403: a bad key, or a live key without this permission)",
            ),
            Self::NoResult(why) => write!(f, "no result ({why})"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub(crate) keys: Vec<PlanKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlanKey {
    pub(crate) file: String,
    pub(crate) recipe: String,
    pub(crate) field: Option<String>,
}

/// Sends the recipe's verify step. Only a GET runs, so a check cannot change anything.
pub fn check(recipe: &Recipe, key: &Secret, transport: &mut dyn Transport) -> Verdict {
    let step = &recipe.verify;
    if step.method != "GET" {
        return Verdict::NoResult("this recipe's check is not a GET".into());
    }
    if step.path.contains("{id}") {
        return Verdict::NoResult("this recipe's check needs a key id".into());
    }
    let request = Request::for_step(recipe, step, &[], key);
    let host = request.rendered.host.clone();
    match transport.send(&request) {
        Ok(response) if step.accepts(response.status) => Verdict::Works { host },
        Ok(response) if response.status == 401 || step.reject.contains(&response.status) => {
            Verdict::Rejected
        }
        Ok(response) if response.status == 403 => Verdict::Forbidden,
        Ok(response) => Verdict::NoResult(format!("HTTP {}", response.status)),
        Err(TransportError::HostNotAllowed(host)) => {
            Verdict::NoResult(format!("host {host} is not in the recipe"))
        }
        Err(TransportError::Failed) => Verdict::NoResult("the request did not complete".into()),
    }
}

/// Reads a key from a file: the whole file, or named fields of an env file, JSON, CSV or loose
/// notes. `A+B` joins two fields with `:`, for providers whose key has two parts.
pub fn read_key(text: &str, field: Option<&str>) -> Result<Secret, String> {
    let trimmed = text.trim().trim_start_matches('\u{FEFF}');
    let Some(field) = field else {
        if trimmed.is_empty() {
            return Err("the file is empty".into());
        }
        if trimmed.contains(char::is_whitespace) {
            return Err("the file holds more than one value, so name one with --field".into());
        }
        return Ok(Secret::new(trimmed));
    };
    let parts: Vec<Secret> = field
        .split('+')
        .map(|name| read_field(trimmed, name))
        .collect::<Result<_, _>>()?;
    if let [only] = parts.as_slice() {
        return Ok(only.clone());
    }
    let joined: Vec<&str> = parts.iter().map(Secret::expose).collect();
    Ok(Secret::new(joined.join(":")))
}

fn read_field(text: &str, field: &str) -> Result<Secret, String> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
        return extract(&json, &format!("$.{field}"))
            .map(Secret::new)
            .ok_or_else(|| format!("field {field} was not found"));
    }
    let mut lines = text.lines();
    if let (Some(head), Some(row)) = (lines.next(), lines.next()) {
        let cells = |line: &str| -> Vec<String> {
            line.split(',')
                .map(|c| c.trim().trim_matches('"').to_owned())
                .collect()
        };
        let names = cells(head);
        if let Some(index) = names
            .iter()
            .position(|name| name.eq_ignore_ascii_case(field))
        {
            let values = cells(row);
            if names.len() == values.len() && !values[index].is_empty() {
                return Ok(Secret::new(values[index].clone()));
            }
        }
    }
    for line in text.lines().map(str::trim) {
        if strip_comment(line).is_some() {
            continue;
        }
        if let Some((label, value)) = split_label(line) {
            if label == field {
                let value = value.trim().trim_matches(['"', '\'']);
                if value.is_empty() {
                    return Err(format!("field {field} is empty"));
                }
                return Ok(Secret::new(value));
            }
        }
    }
    Err(format!("field {field} was not found"))
}

pub(crate) fn load_recipe(name: &str) -> Result<Recipe, String> {
    providers::load(name)
}

pub(crate) fn load_key(path: &Path, field: Option<&str>) -> Result<Secret, String> {
    let shown = path.display();
    let size = fs::metadata(path)
        .map_err(|e| format!("{shown}: {}", e.kind()))?
        .len();
    if size > MAX_KEY_FILE_BYTES {
        return Err(format!("{shown}: too large for a key file"));
    }
    let text = fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("{shown}: {}", e.kind()))?;
    let text = std::str::from_utf8(&text).map_err(|_| format!("{shown}: not UTF-8 text"))?;
    read_key(text, field).map_err(|e| format!("{shown}: {e}"))
}

pub fn run_one(name: &str, file: &Path, field: Option<&str>) -> Result<Verdict, String> {
    let recipe = load_recipe(name)?;
    let key = load_key(file, field)?;
    Ok(check(
        &recipe,
        &key,
        &mut HttpTransport::for_recipe(&recipe),
    ))
}

/// A problem with one key is reported on its line, so it does not hide the others.
pub fn run_plan(
    plan: &Path,
    keys: &Path,
    history: Option<&Path>,
) -> Result<Vec<(String, Verdict)>, String> {
    let text = fs::read_to_string(plan).map_err(|e| format!("{}: {e}", plan.display()))?;
    let plan: Plan =
        serde_norway::from_str(&text).map_err(|e| format!("{}: {e}", plan.display()))?;
    let at = now();
    let mut records = Vec::with_capacity(plan.keys.len());
    let lines = plan
        .keys
        .iter()
        .map(|entry| {
            let label = format!("{} [{}]", entry.file, entry.recipe);
            let verdict = run_entry(entry, keys).unwrap_or_else(|why| {
                let why = why
                    .strip_prefix(&format!("{}: ", keys.join(&entry.file).display()))
                    .map_or(why.clone(), str::to_owned);
                Verdict::NoResult(why)
            });
            records.push(HistoryEntry {
                at,
                file: entry.file.clone(),
                recipe: entry.recipe.clone(),
                result: verdict.code().to_owned(),
            });
            (label, verdict)
        })
        .collect();
    if let Some(history) = history {
        append_history(history, &records).map_err(|e| format!("{}: {e}", history.display()))?;
    }
    Ok(lines)
}

/// A plan names files inside the keys folder and nowhere else.
pub(crate) fn inside_folder(file: &str) -> Result<(), String> {
    if Path::new(file)
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err("the file must be a path inside the keys folder".into());
    }
    Ok(())
}

fn run_entry(entry: &PlanKey, keys: &Path) -> Result<Verdict, String> {
    inside_folder(&entry.file)?;
    run_one(
        &entry.recipe,
        &keys.join(&entry.file),
        entry.field.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Response;

    struct Fixed {
        status: Option<u16>,
        sent: Vec<(String, String, String)>,
    }

    impl Transport for Fixed {
        fn send(&mut self, request: &Request) -> Result<Response, TransportError> {
            self.sent.push((
                request.rendered.method.clone(),
                request.auth.0.clone(),
                request.auth.1.expose().to_owned(),
            ));
            match self.status {
                Some(status) => Ok(Response {
                    status,
                    body: Secret::new("CANARYbody"),
                }),
                None => Err(TransportError::Failed),
            }
        }
    }

    fn verdict(recipe: &str, status: Option<u16>) -> Verdict {
        let recipe = load_recipe(recipe).unwrap();
        let mut transport = Fixed {
            status,
            sent: Vec::new(),
        };
        check(&recipe, &Secret::new("CANARYkey"), &mut transport)
    }

    #[test]
    fn reads_the_answer_of_each_status() {
        assert!(verdict("hetzner", Some(200)).works());
        assert_eq!(verdict("hetzner", Some(401)), Verdict::Rejected);
        assert_eq!(verdict("hetzner", Some(403)), Verdict::Forbidden);
        assert_eq!(
            verdict("hetzner", Some(500)),
            Verdict::NoResult("HTTP 500".into())
        );
        assert_eq!(
            verdict("hetzner", Some(302)),
            Verdict::NoResult("HTTP 302".into())
        );
        assert!(matches!(verdict("hetzner", None), Verdict::NoResult(_)));
        assert_eq!(
            verdict("hetzner", Some(400)),
            Verdict::NoResult("HTTP 400".into())
        );
        assert_eq!(verdict("meta", Some(400)), Verdict::Rejected);
        assert_eq!(verdict("langsmith", Some(403)), Verdict::Rejected);
    }

    #[test]
    fn no_verdict_shows_the_key_or_the_answer() {
        for status in [Some(200), Some(401), Some(403), Some(500), None] {
            let text = format!("{0} {0:?}", verdict("hetzner", status));
            assert!(!text.contains("CANARY"), "{text}");
        }
    }

    #[test]
    fn sends_the_key_only_in_the_recipes_header() {
        let recipe = load_recipe("anthropic").unwrap();
        let mut transport = Fixed {
            status: Some(200),
            sent: Vec::new(),
        };
        check(&recipe, &Secret::new("CANARYkey"), &mut transport);
        assert_eq!(
            transport.sent,
            [("GET".into(), "x-api-key".into(), "CANARYkey".into())]
        );
    }

    #[test]
    fn a_check_that_could_write_does_not_run() {
        let recipe = Recipe::parse(
            "schema: 1\nprovider: x\nhosts: [api.x.com]\nauth: { header: A }\nverify: { method: POST, path: /me }\n",
        )
        .unwrap();
        let mut transport = Fixed {
            status: Some(200),
            sent: Vec::new(),
        };
        assert!(!check(&recipe, &Secret::new("k"), &mut transport).works());
        assert!(transport.sent.is_empty());
    }

    #[test]
    fn reads_a_key_from_each_kind_of_file() {
        let value = |text: &str, field| read_key(text, field).unwrap().expose().to_owned();
        assert_eq!(value("  abc\n", None), "abc");
        assert_eq!(value("# note\nexport A=b=c:d\n", Some("A")), "b=c:d");
        assert_eq!(value("# A=old\nA=new\n", Some("A")), "new");
        assert_eq!(value("token: \"abc\"\nother = x\n", Some("token")), "abc");
        assert_eq!(
            value("Clave Netlify => abc\n", Some("Clave Netlify")),
            "abc"
        );
        assert_eq!(value(r#"{"a":{"b":"abc"}}"#, Some("a.b")), "abc");
    }

    #[test]
    fn an_error_never_quotes_the_file() {
        for (text, field) in [
            ("CANARYa CANARYb", None),
            ("A=CANARYa\n", Some("B")),
            (r#"{"a":"CANARYa"}"#, Some("b")),
            ("A=\n# CANARYa\n", Some("A")),
            ("", None),
        ] {
            let error = read_key(text, field).unwrap_err();
            assert!(!error.contains("CANARY"), "{error}");
        }
    }

    #[test]
    fn a_plan_stays_inside_the_keys_folder() {
        let entry = PlanKey {
            file: "../outside.txt".into(),
            recipe: "hetzner".into(),
            field: None,
        };
        assert!(run_entry(&entry, Path::new("/tmp"))
            .unwrap_err()
            .contains("inside"));
        let entry = PlanKey {
            file: "/etc/passwd".into(),
            recipe: "hetzner".into(),
            field: None,
        };
        assert!(run_entry(&entry, Path::new("/tmp")).is_err());
    }

    #[test]
    fn the_history_holds_only_the_result() {
        let dir = std::env::temp_dir().join(format!("keyreeve-history-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("k.txt"), "CANARYhistory\n").unwrap();
        fs::write(
            dir.join("plan.yaml"),
            "keys: [{ file: missing.txt, recipe: hetzner }]\n",
        )
        .unwrap();
        let history = dir.join("private/history.jsonl");
        let lines = run_plan(&dir.join("plan.yaml"), &dir, Some(&history)).unwrap();
        assert_eq!(lines.len(), 1);
        let text = fs::read_to_string(&history).unwrap();
        let entries = parse_history(&format!("{text}{{\"torn"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file, "missing.txt");
        assert_eq!(entries[0].result, "no_result");
        assert!(!text.contains("CANARY"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_a_key_in_two_parts_from_a_csv() {
        let text = "User name,Access key ID,Secret access key\nu,AKIACANARY,CANARYsecret\n";
        let key = read_key(text, Some("Access key ID+Secret access key")).unwrap();
        assert_eq!(key.expose(), "AKIACANARY:CANARYsecret");
        let error = read_key(text, Some("Access key ID+Missing")).unwrap_err();
        assert!(!error.contains("CANARY"), "{error}");
    }

    #[test]
    fn a_signed_request_does_not_send_the_secret() {
        let recipe = load_recipe("aws").unwrap();
        let mut transport = Fixed {
            status: Some(403),
            sent: Vec::new(),
        };
        let verdict = check(
            &recipe,
            &Secret::new("AKIACANARY:CANARYsecret"),
            &mut transport,
        );
        assert_eq!(verdict, Verdict::Rejected);
        assert!(transport.sent[0].2.contains("AWS4-HMAC-SHA256"));
        assert!(!transport.sent[0].2.contains("CANARYsecret"));
    }
}
