//! Checks whether a key still works, with one read-only request. The result says nothing about
//! the key's value, and no error quotes the file it came from.

pub use crate::history::{append_history, now, parse_history, HistoryEntry};
pub use crate::keys::{read_key, read_key_for, KeySource, Sealed};
use crate::providers;
use crate::recipe::{extract, Recipe};
use crate::script;
use crate::secret::Secret;
use crate::ssh;
use crate::transport::{exchange_token, HttpTransport, Request, Transport, TransportError};
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;

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

    /// Why a check gave no answer. It is written by this tool, and never quotes a key or a reply.
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::NoResult(why) => Some(why.clone()),
            Self::Forbidden => Some("HTTP 403".to_owned()),
            _ => None,
        }
    }
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
    /// The server, for a provider each person runs themselves.
    pub(crate) host: Option<String>,
}

/// Sends the recipe's verify step. Only a GET runs, or the token exchange a provider requires,
/// so a check cannot change anything.
pub fn check(recipe: &Recipe, key: &Secret, transport: &mut dyn Transport) -> Verdict {
    let step = &recipe.verify;
    if step.method != "GET" {
        return Verdict::NoResult("this recipe's check is not a GET".into());
    }
    if step.path.contains("{id}") {
        return Verdict::NoResult("this recipe's check needs a key id".into());
    }
    let credential = if recipe.auth.kind.as_deref() == Some("oauth_token") {
        match exchange_token(recipe, key, transport) {
            Err(error) => return failed(error),
            Ok(response) if !(200..=299).contains(&response.status) => {
                return if (400..=499).contains(&response.status) {
                    Verdict::Rejected
                } else {
                    Verdict::NoResult(format!("HTTP {}", response.status))
                };
            }
            Ok(response) => {
                if recipe.auth.token_is_proof {
                    return Verdict::Works {
                        host: recipe.auth.token_host.clone().unwrap_or_default(),
                    };
                }
                let token = serde_json::from_str::<serde_json::Value>(response.body.expose())
                    .ok()
                    .and_then(|json| extract(&json, "$.access_token"));
                let Some(token) = token else {
                    return Verdict::NoResult("the answer could not be read".into());
                };
                Secret::new(token)
            }
        }
    } else {
        key.clone()
    };
    let request = Request::for_step(recipe, step, &[], &credential);
    let host = request.rendered.host.clone();
    match transport.send(&request) {
        Ok(response) if step.accepts(response.status) => Verdict::Works { host },
        Ok(response)
            if step.alive_if.as_ref().is_some_and(|alive| {
                alive.status == response.status && response.body.expose().contains(&alive.contains)
            }) =>
        {
            Verdict::Works { host }
        }
        Ok(response) if response.status == 401 || step.reject.contains(&response.status) => {
            Verdict::Rejected
        }
        Ok(response) if response.status == 403 => Verdict::Forbidden,
        Ok(response) => Verdict::NoResult(format!("HTTP {}", response.status)),
        Err(error) => failed(error),
    }
}

/// Runs a button of your own. A program that needs the key gets it on stdin.
pub fn run_action(
    provider: &str,
    action: &str,
    source: Option<&KeySource>,
    field: Option<&str>,
) -> Result<String, String> {
    let recipe = load_recipe(provider)?;
    let action = recipe
        .actions
        .iter()
        .find(|candidate| candidate.id == action)
        .ok_or_else(|| format!("{provider} has no action {action}"))?;
    let run = action.run.as_ref().ok_or("this action opens a page")?;
    let key = match (action.needs_key, source) {
        (true, Some(source)) => Some(source.load(field, &recipe)?),
        (true, None) => return Err("this action needs a key".into()),
        (false, _) => None,
    };
    let answer = script::run(&providers::programs_folder(), run, &action.id, key.as_ref())?;
    Ok(answer.message)
}

fn failed(error: TransportError) -> Verdict {
    match error {
        TransportError::HostNotAllowed(host) => {
            Verdict::NoResult(format!("host {host} is not in the recipe"))
        }
        TransportError::Failed => Verdict::NoResult("the request did not complete".into()),
    }
}

pub(crate) fn load_recipe(name: &str) -> Result<Recipe, String> {
    providers::load(name)
}

/// The provider's file, pointed at the server when each person runs their own.
pub(crate) fn resolve(name: &str, host: Option<&str>) -> Result<Recipe, String> {
    let recipe = load_recipe(name)?;
    if !recipe.self_hosted {
        return Ok(recipe);
    }
    let host = host.ok_or_else(|| format!("{name} needs the address of your server"))?;
    if !providers::host_approved(name, host) {
        return Err(format!("{host} is not approved for {name}"));
    }
    Ok(recipe.at_host(host))
}

/// One check typed at the command, where a path to a recipe is allowed.
pub fn run_one(name: &str, file: &Path, field: Option<&str>) -> Result<Verdict, String> {
    let source = KeySource::File(file.to_owned());
    if providers::is_path(name) {
        return run_recipe(&providers::load_file(name)?, &source, field);
    }
    run_at(name, &source, field, None)
}

pub fn run_at(
    name: &str,
    source: &KeySource,
    field: Option<&str>,
    host: Option<&str>,
) -> Result<Verdict, String> {
    run_recipe(&resolve(name, host)?, source, field)
}

fn run_recipe(recipe: &Recipe, source: &KeySource, field: Option<&str>) -> Result<Verdict, String> {
    if recipe.auth.kind.as_deref() == Some("ssh") {
        return source.greet(recipe).map(|reply| match reply {
            ssh::Reply::Accepted(_) => Verdict::Works {
                host: recipe.hosts[0].clone(),
            },
            ssh::Reply::Refused => Verdict::Rejected,
            ssh::Reply::Unknown => Verdict::NoResult("could not connect".into()),
        });
    }
    let key = source.load(field, recipe)?;
    if let Some(run) = &recipe.auth.run {
        let answer = script::run(&providers::programs_folder(), run, "check", Some(&key))?;
        return Ok(program_verdict(&answer));
    }
    Ok(check(recipe, &key, &mut HttpTransport::for_recipe(recipe)))
}

/// What a program of yours said. An answer it did not mean to give is not read as a live key.
fn program_verdict(answer: &script::Answer) -> Verdict {
    match answer.result.as_str() {
        "works" => Verdict::Works {
            host: "your program".into(),
        },
        "rejected" => Verdict::Rejected,
        "forbidden" => Verdict::Forbidden,
        "no_result" if !answer.message.is_empty() => Verdict::NoResult(answer.message.clone()),
        _ => Verdict::NoResult("the program gave no result".into()),
    }
}

/// How many checks run at once. Providers see few requests, and a slow one holds up no others.
const WORKERS: usize = 6;

/// A problem with one key is reported on its line, so it does not hide the others.
pub fn run_plan(
    plan: &Path,
    keys: &Path,
    history: Option<&Path>,
) -> Result<Vec<(String, Verdict)>, String> {
    run_plan_with(plan, keys, history, &Sealed::default(), &|_, _| {})
}

/// The same, and it reports each finished key with how many are done and how many there are.
pub fn run_plan_with(
    plan: &Path,
    keys: &Path,
    history: Option<&Path>,
    sealed: &Sealed,
    progress: &(dyn Fn(usize, usize) + Sync),
) -> Result<Vec<(String, Verdict)>, String> {
    let text = fs::read_to_string(plan).map_err(|e| format!("{}: {e}", plan.display()))?;
    let plan: Plan =
        serde_norway::from_str(&text).map_err(|e| format!("{}: {e}", plan.display()))?;
    let at = now();
    let total = plan.keys.len();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let verdicts: Vec<Mutex<Option<Verdict>>> =
        plan.keys.iter().map(|_| Mutex::new(None)).collect();
    thread::scope(|scope| {
        for _ in 0..WORKERS.min(total.max(1)) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::SeqCst);
                let Some(entry) = plan.keys.get(index) else {
                    return;
                };
                let verdict = run_entry(entry, keys, sealed).unwrap_or_else(|why| {
                    let why = why
                        .strip_prefix(&format!("{}: ", keys.join(&entry.file).display()))
                        .map_or(why.clone(), str::to_owned);
                    Verdict::NoResult(why)
                });
                *verdicts[index].lock().unwrap_or_else(|e| e.into_inner()) = Some(verdict);
                progress(done.fetch_add(1, Ordering::SeqCst) + 1, total);
            });
        }
    });
    let mut records = Vec::with_capacity(total);
    let mut lines = Vec::with_capacity(total);
    for (entry, slot) in plan.keys.iter().zip(verdicts) {
        let verdict = slot
            .into_inner()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or_else(|| Verdict::NoResult("the check did not run".into()));
        records.push(HistoryEntry {
            at,
            file: entry.file.clone(),
            recipe: entry.recipe.clone(),
            result: verdict.code().to_owned(),
            reason: verdict.reason(),
        });
        lines.push((format!("{} [{}]", entry.file, entry.recipe), verdict));
    }
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

fn run_entry(entry: &PlanKey, keys: &Path, sealed: &Sealed) -> Result<Verdict, String> {
    inside_folder(&entry.file)?;
    run_at(
        &entry.recipe,
        &sealed.source(keys, &entry.file),
        entry.field.as_deref(),
        entry.host.as_deref(),
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
                    headers: Vec::new(),
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
            host: None,
        };
        assert!(run_entry(&entry, Path::new("/tmp"), &Sealed::default())
            .unwrap_err()
            .contains("inside"));
        let entry = PlanKey {
            file: "/etc/passwd".into(),
            recipe: "hetzner".into(),
            field: None,
            host: None,
        };
        assert!(run_entry(&entry, Path::new("/tmp"), &Sealed::default()).is_err());
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
        assert!(entries[0].reason.is_some());
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
    fn a_plan_keeps_its_order_and_reports_each_key() {
        let dir = std::env::temp_dir().join(format!("keyreeve-batch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut text = String::from("keys:\n");
        for index in 0..20 {
            text.push_str(&format!(
                "  - {{ file: missing-{index}.txt, recipe: hetzner }}\n"
            ));
        }
        fs::write(dir.join("plan.yaml"), text).unwrap();
        let seen = AtomicUsize::new(0);
        let lines = run_plan_with(
            &dir.join("plan.yaml"),
            &dir,
            None,
            &Sealed::default(),
            &|_, total| {
                assert_eq!(total, 20);
                seen.fetch_add(1, Ordering::SeqCst);
            },
        )
        .unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 20);
        assert_eq!(lines[7].0, "missing-7.txt [hetzner]");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_restricted_key_counts_as_alive_only_with_the_declared_answer() {
        struct Answer(u16, &'static str);
        impl Transport for Answer {
            fn send(&mut self, _: &Request) -> Result<Response, TransportError> {
                Ok(Response {
                    headers: Vec::new(),
                    status: self.0,
                    body: Secret::new(self.1),
                })
            }
        }
        let recipe = load_recipe("resend").unwrap();
        let key = Secret::new("re_x");
        assert!(check(
            &recipe,
            &key,
            &mut Answer(401, "{\"name\":\"restricted_api_key\"}")
        )
        .works());
        assert_eq!(
            check(&recipe, &key, &mut Answer(401, "{\"name\":\"invalid\"}")),
            Verdict::Rejected
        );
    }

    #[test]
    fn a_key_in_the_address_stays_out_of_the_verdict() {
        let recipe = load_recipe("telegram").unwrap();
        let mut transport = Fixed {
            status: Some(404),
            sent: Vec::new(),
        };
        let verdict = check(&recipe, &Secret::new("123:CANARY/x"), &mut transport);
        assert_eq!(verdict, Verdict::Rejected);
        assert!(transport.sent[0].1.is_empty(), "no header carries it");
        assert!(!format!("{verdict} {verdict:?}").contains("CANARY"));
    }

    #[test]
    fn a_token_exchange_proves_the_key_without_another_request() {
        let recipe = load_recipe("paypal").unwrap();
        let mut transport = Fixed {
            status: Some(200),
            sent: Vec::new(),
        };
        assert!(check(&recipe, &Secret::new("id:secret"), &mut transport).works());
        assert_eq!(transport.sent.len(), 1);
        assert_eq!(transport.sent[0].0, "POST");
        let mut refused = Fixed {
            status: Some(401),
            sent: Vec::new(),
        };
        assert_eq!(
            check(&recipe, &Secret::new("id:secret"), &mut refused),
            Verdict::Rejected
        );
    }

    #[test]
    fn finds_a_key_in_notes_by_its_prefix_and_refuses_to_guess() {
        let recipe = load_recipe("resend").unwrap();
        let one = "cuenta: yo\nclave re_CANARY1 para envios\n";
        assert_eq!(
            read_key_for(one, None, &recipe).unwrap().expose(),
            "re_CANARY1"
        );
        let two = "re_CANARY1 y re_CANARY2\n";
        let error = read_key_for(two, None, &recipe).unwrap_err();
        assert!(error.contains("several") && !error.contains("CANARY"));
        let none = "nada util aqui\n";
        assert!(read_key_for(none, None, &recipe).is_err());
    }

    #[test]
    fn a_self_hosted_provider_needs_an_approved_address() {
        assert!(resolve("coolify", None).unwrap_err().contains("address"));
        assert!(resolve("coolify", Some("not-approved.example.com"))
            .unwrap_err()
            .contains("not approved"));
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
