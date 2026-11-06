//! Rotates one key held in the vault. The engine decides the order, and this file connects it to
//! the real world: the vault for storage and the places that use the key.
//!
//! This program cannot open the vault. The caller opens what it needs, with a fingerprint, and sends
//! it on stdin. Writing needs no fingerprint, so each write goes straight to the vault's own tool
//! and is durable before the engine records the step.

use crate::engine::{Engine, KeyConfig, Outcome, Sink};
use crate::journal::{Event, FileBackend, Journal, Phase};
use crate::keys::{holds_key, swap_key, MIN_SWAP_CHARS};
use crate::places::{action_sink, FileSink};
use crate::recipe::Recipe;
use crate::secret::Secret;
use crate::store::{Store, StoreError};
use crate::transport::HttpTransport;
use crate::verify::{now, read_key_for, resolve, Sealed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// The key's name in the vault, which is its file's path.
    pub key: String,
    pub recipe: String,
    pub field: Option<String>,
    pub host: Option<String>,
    /// Another key in the vault that may create and revoke, when this one cannot.
    pub admin: Option<String>,
    pub admin_field: Option<String>,
    #[serde(default)]
    pub overlap_secs: u64,
    pub known_id: Option<String>,
    /// The name the provider will show for the new key.
    pub issued_name: String,
    /// The key's original file, while it is still on disk.
    pub original: Option<String>,
    /// Other files that hold this key. The old value is replaced wherever it appears.
    #[serde(default)]
    pub place_files: Vec<String>,
    /// `provider/action`: a button of yours that receives the new key on stdin.
    #[serde(default)]
    pub place_actions: Vec<String>,
    /// False when the key was replaced by hand after its last rotation.
    #[serde(default = "yes")]
    pub trust_recorded_id: bool,
}

fn yes() -> bool {
    true
}

/// The places a rotation started with. Undoing one must reach every place that got the new key,
/// even if the settings changed in between, so these are kept until the rotation closes.
#[derive(Debug, Serialize, Deserialize)]
struct FrozenPlaces {
    files: Vec<String>,
    actions: Vec<String>,
}

fn frozen_path(journal: &Path, key: &str) -> PathBuf {
    let digest: String = Sha256::digest(key.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    journal.with_extension(format!("places-{digest}"))
}

fn freeze_places(journal: &Path, plan: &Plan) -> Result<(), String> {
    let frozen = FrozenPlaces {
        files: plan.place_files.clone(),
        actions: plan.place_actions.clone(),
    };
    let text = serde_json::to_vec(&frozen).map_err(|e| e.to_string())?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let path = frozen_path(journal, &plan.key);
    let mut file = options
        .open(&path)
        .map_err(|e| format!("the places: {e}"))?;
    file.write_all(&text)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("the places: {e}"))
}

fn restore_places(journal: &Path, plan: &mut Plan) {
    let frozen = fs::read(frozen_path(journal, &plan.key))
        .ok()
        .and_then(|text| serde_json::from_slice::<FrozenPlaces>(&text).ok());
    if let Some(frozen) = frozen {
        plan.place_files = frozen.files;
        plan.place_actions = frozen.actions;
    }
}

fn pending_name(key: &str) -> String {
    format!("{key}#pending")
}

fn previous_name(key: &str) -> String {
    format!("{key}#previous")
}

fn store_error(what: &str) -> StoreError {
    StoreError(format!("the vault could not {what}"))
}

/// The engine's view of the vault. A sealed copy holds a whole file, so the key is swapped inside
/// its text, and the rest of the file stays as it was.
pub struct VaultStore {
    tool: PathBuf,
    key: String,
    text: Zeroizing<String>,
    current: Secret,
    admin: Option<(String, Secret)>,
    temporary: HashMap<String, Secret>,
}

impl VaultStore {
    /// Runs the vault's tool with a value on stdin. Its output is discarded.
    fn write(&self, name: &str, value: &str) -> Result<(), StoreError> {
        let mut child = Command::new(&self.tool)
            .args(["put", name])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| store_error("start"))?;
        let mut stdin = child.stdin.take().ok_or_else(|| store_error("start"))?;
        let wrote = stdin.write_all(value.as_bytes());
        drop(stdin);
        let status = child.wait().map_err(|_| store_error("save a key"))?;
        if wrote.is_err() || !status.success() {
            return Err(store_error("save a key"));
        }
        Ok(())
    }

    fn drop_temporary(&self, name: &str) -> Result<(), StoreError> {
        let status = Command::new(&self.tool)
            .args(["drop", name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| store_error("start"))?;
        if !status.success() {
            return Err(store_error("remove a temporary copy"));
        }
        Ok(())
    }
}

impl Store for VaultStore {
    fn get(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        if name == self.key {
            return Ok(Some(self.current.clone()));
        }
        if let Some((admin, value)) = &self.admin {
            if admin == name {
                return Ok(Some(value.clone()));
            }
        }
        Ok(self.temporary.get(name).cloned())
    }

    fn put(&mut self, name: &str, value: &Secret) -> Result<(), StoreError> {
        if name == self.key {
            let text = Zeroizing::new(swap_key(&self.text, self.current.expose(), value.expose()));
            self.write(name, &text)?;
            self.text = text;
            self.current = value.clone();
        } else {
            // Too short to swap safely later, so it never becomes the key.
            if name == pending_name(&self.key) && value.expose().chars().count() < MIN_SWAP_CHARS {
                return Err(StoreError(
                    "the new key is too short to handle safely".into(),
                ));
            }
            self.write(name, value.expose())?;
            self.temporary.insert(name.to_owned(), value.clone());
        }
        Ok(())
    }

    fn delete(&mut self, name: &str) -> Result<(), StoreError> {
        self.drop_temporary(name)?;
        self.temporary.remove(name);
        Ok(())
    }
}

fn load_sealed_key(
    text: &str,
    field: Option<&str>,
    recipe: &Recipe,
    starting: bool,
) -> Result<Secret, String> {
    let key = read_key_for(text, field, recipe)?;
    // A key joined from two fields cannot be swapped inside the file.
    if !text.contains(key.expose()) {
        return Err("this key is made of two fields, and that cannot rotate yet".into());
    }
    // These refuse a new rotation. One already open must always be able to finish or undo.
    if !starting {
        return Ok(key);
    }
    if key.expose().chars().count() < MIN_SWAP_CHARS {
        return Err("this key is too short to find safely in a file".into());
    }
    if !holds_key(text, key.expose()) {
        return Err("this key is part of a longer value in its file".into());
    }
    Ok(key)
}

/// What happened, without any value. Ids and step names are not secret.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Report {
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_after: Option<u64>,
    pub manual: Vec<String>,
}

impl Report {
    pub fn json(&self) -> String {
        serde_json::to_string(self).expect("a report always serializes")
    }
}

fn report(outcome: Outcome, journal: &Journal, key: &str) -> Report {
    let (name, reason, revoke_after) = match outcome {
        Outcome::Completed => ("completed", None, None),
        Outcome::RolledBack { reason } => ("rolled_back", Some(reason), None),
        Outcome::AwaitingOverlap { revoke_after } => ("waiting", None, Some(revoke_after)),
        Outcome::RevokePending => ("revoke_pending", None, None),
        Outcome::RollbackBlocked { sink } => ("rollback_blocked", Some(sink), None),
        Outcome::NothingToDo => ("nothing_to_do", None, None),
    };
    Report {
        outcome: name,
        reason,
        revoke_after,
        manual: manual_of(journal, key),
    }
}

fn manual_of(journal: &Journal, key: &str) -> Vec<String> {
    journal
        .latest(key)
        .iter()
        .filter_map(|event| match event {
            Event::ManualAction { what } => Some(what.clone()),
            _ => None,
        })
        .collect()
}

pub fn run(
    plan: &Path,
    tool: &Path,
    journal: &Path,
    sealed: &Sealed,
    resume: bool,
) -> Result<Report, String> {
    let text = fs::read_to_string(plan).map_err(|e| format!("{}: {e}", plan.display()))?;
    let mut plan: Plan = serde_json::from_str(&text).map_err(|e| format!("the plan: {e}"))?;
    if plan.key.ends_with("#pending") || plan.key.ends_with("#previous") {
        return Err("that name is kept for a rotation's temporary copies".into());
    }
    // Two rotations at once would each trust a journal the other is changing.
    let lock = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(journal.with_extension("lock"))
        .map_err(|e| format!("the journal: {e}"))?;
    lock.try_lock()
        .map_err(|_| "another rotation is running".to_owned())?;
    let recipe = resolve(&plan.recipe, plan.host.as_deref())?;
    if !recipe.can_rotate() {
        return Err(format!(
            "keyreeve does not know how to rotate {}",
            plan.recipe
        ));
    }
    let mut record = Journal::open(Box::new(FileBackend::new(journal)))
        .map_err(|e| format!("the journal: {e}"))?;
    let open = record.phase(&plan.key) != Phase::Idle;
    if resume && open {
        restore_places(journal, &mut plan);
    }
    let (mut store, mut sinks) = prepare(&plan, &recipe, tool, sealed, !open)?;
    if !resume && !open {
        freeze_places(journal, &plan)?;
    }
    let config = KeyConfig {
        key: plan.key.clone(),
        admin: plan.admin.clone().unwrap_or_else(|| plan.key.clone()),
        overlap_secs: plan.overlap_secs,
        issued_name: plan.issued_name.clone(),
        known_id: plan.known_id.clone(),
        trust_recorded_id: plan.trust_recorded_id,
    };
    let mut transport = HttpTransport::for_recipe(&recipe);
    let outcome = {
        let mut places: Vec<&mut dyn Sink> = Vec::with_capacity(sinks.len());
        for sink in &mut sinks {
            places.push(sink.as_mut());
        }
        let mut engine = Engine {
            recipe: &recipe,
            config: &config,
            transport: &mut transport,
            store: &mut store,
            journal: &mut record,
            sinks: places,
            now: &now,
        };
        if resume {
            engine.resume()
        } else {
            engine.rotate()
        }
        .map_err(|e| e.to_string())?
    };
    if record.phase(&plan.key) == Phase::Idle {
        let _ = fs::remove_file(frozen_path(journal, &plan.key));
    }
    Ok(report(outcome, &record, &plan.key))
}

type Prepared = (VaultStore, Vec<Box<dyn Sink>>);

/// Everything that can be refused before a key exists at the provider.
fn prepare(
    plan: &Plan,
    recipe: &Recipe,
    tool: &Path,
    sealed: &Sealed,
    starting: bool,
) -> Result<Prepared, String> {
    let text = sealed
        .text(&plan.key)
        .ok_or("the key's sealed copy did not arrive")?;
    let current = load_sealed_key(text, plan.field.as_deref(), recipe, starting)?;
    let mut temporary = HashMap::new();
    let mut known = vec![current.clone()];
    for name in [pending_name(&plan.key), previous_name(&plan.key)] {
        if let Some(value) = sealed.text(&name) {
            let value = Secret::new(value);
            known.push(value.clone());
            temporary.insert(name, value);
        }
    }
    let admin = match &plan.admin {
        Some(name) => {
            let text = sealed
                .text(name)
                .ok_or("the admin key's sealed copy did not arrive")?;
            Some((
                name.clone(),
                read_key_for(text, plan.admin_field.as_deref(), recipe)?,
            ))
        }
        None => None,
    };
    let mut sinks: Vec<Box<dyn Sink>> = Vec::new();
    let files = plan
        .original
        .iter()
        .map(|path| ("original".to_owned(), path))
        .chain(
            plan.place_files
                .iter()
                .map(|path| (format!("file:{path}"), path)),
        );
    for (label, path) in files {
        let sink = FileSink {
            label,
            path: PathBuf::from(path),
            known: known.clone(),
        };
        let held = fs::read_to_string(&sink.path)
            .map(Zeroizing::new)
            .map_err(|_| format!("{path} could not be read"))?;
        if !known.iter().any(|value| holds_key(&held, value.expose())) {
            return Err(format!("{path} does not hold this key"));
        }
        sinks.push(Box::new(sink));
    }
    for place in &plan.place_actions {
        sinks.push(Box::new(action_sink(place)?));
    }
    let store = VaultStore {
        tool: tool.to_owned(),
        key: plan.key.clone(),
        text: Zeroizing::new(text.to_owned()),
        current,
        admin,
        temporary,
    };
    Ok((store, sinks))
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Status {
    pub key: String,
    pub phase: &'static str,
    pub at: u64,
    pub revoke_after: Option<u64>,
    pub reason: Option<String>,
    pub manual: Vec<String>,
}

fn phase_name(phase: Phase, events: &[&Event]) -> &'static str {
    match phase {
        Phase::Idle if events.iter().any(|e| matches!(e, Event::Completed)) => "completed",
        Phase::Idle if events.iter().any(|e| matches!(e, Event::RolledBack { .. })) => {
            "rolled_back"
        }
        Phase::Idle => "idle",
        Phase::Promoted => "waiting",
        Phase::RollingBack => "rolling_back",
        _ => "unfinished",
    }
}

/// Where each key's latest rotation stands.
pub fn statuses(journal: &Journal) -> Vec<Status> {
    let mut keys: Vec<&str> = journal.entries().iter().map(|e| e.key.as_str()).collect();
    keys.sort_unstable();
    keys.dedup();
    keys.into_iter()
        .map(|key| {
            let events = journal.latest(key);
            let at = journal
                .entries()
                .iter()
                .filter(|entry| entry.key == key)
                .map(|entry| entry.at)
                .max()
                .unwrap_or(0);
            Status {
                key: key.to_owned(),
                phase: phase_name(journal.phase(key), &events),
                at,
                revoke_after: events.iter().find_map(|event| match event {
                    Event::Promoted { revoke_after } => Some(*revoke_after),
                    _ => None,
                }),
                reason: events.iter().find_map(|event| match event {
                    Event::RolledBack { reason } | Event::RollbackStarted { reason } => {
                        Some(reason.clone())
                    }
                    _ => None,
                }),
                manual: manual_of(journal, key),
            }
        })
        .collect()
}

pub fn statuses_json(journal: &Path) -> Result<String, String> {
    let record = Journal::open(Box::new(FileBackend::new(journal)))
        .map_err(|e| format!("the journal: {e}"))?;
    serde_json::to_string(&statuses(&record)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    use crate::transport::{Request, Response, Transport, TransportError};

    const RECIPE: &str = "schema: 1\nprovider: fake\nhosts: [api.example.com]\nauth: { header: Authorization, prefix: \"Bearer \" }\ncreate: { method: POST, path: /keys, body: { name: \"{key_name}\" }, value_from: $.secret, id_from: $.id }\nverify: { method: GET, path: /me }\nrevoke: { method: DELETE, path: \"/keys/{id}\" }\n";

    /// A provider that issues one key, and remembers what it was asked.
    struct Fake {
        verify_status: u16,
        calls: Vec<(String, String, String)>,
    }

    impl Transport for Fake {
        fn send(&mut self, request: &Request) -> Result<Response, TransportError> {
            let method = request.rendered.method.clone();
            self.calls.push((
                method.clone(),
                request.rendered.path.clone(),
                request.auth.1.expose().to_owned(),
            ));
            let (status, body) = match method.as_str() {
                "POST" => (200, r#"{"secret":"CANARY-new-0123456789","id":"new-id"}"#),
                "GET" => (self.verify_status, "{}"),
                _ => (200, "{}"),
            };
            Ok(Response {
                headers: Vec::new(),
                status,
                body: Secret::new(body),
            })
        }
    }

    /// Stands in for the vault's tool: one file per name.
    fn tool(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let vault = dir.join("vault");
        fs::create_dir_all(&vault).unwrap();
        let path = dir.join("tool.sh");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nname=$(printf '%s' \"$2\" | tr '/#' '__')\nif [ \"$1\" = put ]; then cat > '{0}'/\"$name\"; else rm -f '{0}'/\"$name\"; fi\n",
                vault.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn rotate_with(name: &str, verify_status: u16) -> (PathBuf, Outcome, Fake, String) {
        let dir = folder(name);
        let tool = tool(&dir);
        let place = dir.join("service.env");
        fs::write(&place, "TOKEN=CANARY-old-0123456\nOTHER=stays\n").unwrap();
        let original = dir.join("key.env");
        fs::write(&original, "# note\nTOKEN=CANARY-old-0123456\n").unwrap();
        let recipe = Recipe::parse(RECIPE).unwrap();
        let plan = Plan {
            key: "dir/key.env".into(),
            recipe: "fake".into(),
            field: Some("TOKEN".into()),
            host: None,
            admin: None,
            admin_field: None,
            overlap_secs: 0,
            known_id: Some("old-id".into()),
            issued_name: "keyreeve-today".into(),
            original: Some(original.to_string_lossy().into_owned()),
            place_files: vec![place.to_string_lossy().into_owned()],
            place_actions: Vec::new(),
            trust_recorded_id: true,
        };
        let input =
            serde_json::json!({ "dir/key.env": "# note\nTOKEN=CANARY-old-0123456\n" }).to_string();
        let sealed = Sealed::read(input.as_bytes()).unwrap();
        let (mut store, mut sinks) = prepare(&plan, &recipe, &tool, &sealed, true).unwrap();
        let mut record = Journal::open(Box::new(FileBackend::new(dir.join("journal")))).unwrap();
        let config = KeyConfig {
            key: plan.key.clone(),
            admin: plan.key.clone(),
            overlap_secs: 0,
            issued_name: plan.issued_name.clone(),
            known_id: plan.known_id.clone(),
            trust_recorded_id: true,
        };
        let mut fake = Fake {
            verify_status,
            calls: Vec::new(),
        };
        let mut places: Vec<&mut dyn Sink> = Vec::new();
        for sink in &mut sinks {
            places.push(sink.as_mut());
        }
        let outcome = Engine {
            recipe: &recipe,
            config: &config,
            transport: &mut fake,
            store: &mut store,
            journal: &mut record,
            sinks: places,
            now: &|| 100,
        }
        .rotate()
        .unwrap();
        let journal = fs::read_to_string(dir.join("journal")).unwrap();
        (dir, outcome, fake, journal)
    }

    #[test]
    fn a_rotation_reaches_the_vault_and_every_place_and_revokes_the_old_key() {
        let (dir, outcome, fake, journal) = rotate_with("whole", 200);
        assert_eq!(outcome, Outcome::Completed);
        assert_eq!(
            fs::read_to_string(dir.join("vault/dir_key.env")).unwrap(),
            "# note\nTOKEN=CANARY-new-0123456789\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join("key.env")).unwrap(),
            "# note\nTOKEN=CANARY-new-0123456789\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join("service.env")).unwrap(),
            "TOKEN=CANARY-new-0123456789\nOTHER=stays\n"
        );
        assert!(!dir.join("vault/dir_key.env_pending").exists());
        assert!(!dir.join("vault/dir_key.env_previous").exists());
        let revoke = fake.calls.last().unwrap();
        assert_eq!(revoke.0, "DELETE");
        assert!(revoke.1.ends_with("/keys/old-id"));
        assert_eq!(revoke.2, "Bearer CANARY-new-0123456789");
        assert!(!journal.contains("CANARY"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_new_key_that_fails_changes_nothing_anywhere() {
        let (dir, outcome, fake, journal) = rotate_with("failed", 401);
        assert!(matches!(outcome, Outcome::RolledBack { .. }));
        assert_eq!(
            fs::read_to_string(dir.join("key.env")).unwrap(),
            "# note\nTOKEN=CANARY-old-0123456\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join("service.env")).unwrap(),
            "TOKEN=CANARY-old-0123456\nOTHER=stays\n"
        );
        assert!(!dir.join("vault/dir_key.env_pending").exists());
        let revoke = fake.calls.last().unwrap();
        assert!(revoke.1.ends_with("/keys/new-id"));
        assert_eq!(revoke.2, "Bearer CANARY-old-0123456");
        assert!(!journal.contains("CANARY"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_place_that_does_not_hold_the_key_stops_it_before_the_provider() {
        let dir = folder("preflight");
        let place = dir.join("service.env");
        fs::write(&place, "NOTHING=here\n").unwrap();
        let plan = Plan {
            key: "k".into(),
            recipe: "fake".into(),
            field: None,
            host: None,
            admin: None,
            admin_field: None,
            overlap_secs: 0,
            known_id: None,
            issued_name: "n".into(),
            original: None,
            place_files: vec![place.to_string_lossy().into_owned()],
            place_actions: Vec::new(),
            trust_recorded_id: true,
        };
        let sealed = Sealed::read(r#"{"k":"CANARY-old-0123456"}"#.as_bytes()).unwrap();
        let recipe = Recipe::parse(RECIPE).unwrap();
        let error = prepare(&plan, &recipe, &dir.join("tool"), &sealed, true)
            .err()
            .unwrap();
        assert!(error.contains("does not hold this key"));
        assert!(!error.contains("CANARY"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_short_or_embedded_key_is_refused_before_the_provider() {
        let recipe = Recipe::parse(RECIPE).unwrap();
        let short = load_sealed_key("abc", None, &recipe, true).err().unwrap();
        assert!(short.contains("too short"));
        assert!(load_sealed_key("abc", None, &recipe, false).is_ok());
        let text = "TOKEN=abcdefghijklmnopqrstuvwx\nOTHER=abcdefghijklmnopqrstuvwx-2\n";
        assert!(load_sealed_key(text, Some("TOKEN"), &recipe, true).is_ok());
    }

    #[test]
    fn places_stay_as_they_were_when_the_rotation_started() {
        let dir = folder("frozen");
        let journal = dir.join("rotations.jsonl");
        let plan = |files: Vec<String>| Plan {
            key: "k".into(),
            recipe: "fake".into(),
            field: None,
            host: None,
            admin: None,
            admin_field: None,
            overlap_secs: 0,
            known_id: None,
            issued_name: "n".into(),
            original: None,
            place_files: files,
            place_actions: Vec::new(),
            trust_recorded_id: true,
        };
        freeze_places(&journal, &plan(vec!["/first".into()])).unwrap();
        let mut later = plan(Vec::new());
        restore_places(&journal, &mut later);
        assert_eq!(later.place_files, ["/first"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_new_key_too_short_never_lands() {
        let dir = folder("short");
        let tool = tool(&dir);
        let mut store = VaultStore {
            tool,
            key: "k".into(),
            text: Zeroizing::new("old-value-0123456789".into()),
            current: Secret::new("old-value-0123456789"),
            admin: None,
            temporary: HashMap::new(),
        };
        assert!(store.put("k#pending", &Secret::new("short")).is_err());
        assert!(store
            .put("k#pending", &Secret::new("long-enough-0123456789"))
            .is_ok());
        fs::remove_dir_all(dir).unwrap();
    }

    /// A key whose last rotation left id `b`, rotated again.
    fn revoked_after_rerotating(trust_recorded_id: bool) -> Vec<(String, String, String)> {
        let dir = folder(if trust_recorded_id {
            "id-kept"
        } else {
            "id-dropped"
        });
        let recipe = Recipe::parse(RECIPE).unwrap();
        let mut record = Journal::open(Box::new(FileBackend::new(dir.join("journal")))).unwrap();
        record
            .append("k", 1, Event::Started { old_id: None })
            .unwrap();
        record
            .append("k", 2, Event::Created { new_id: "b".into() })
            .unwrap();
        record
            .append("k", 3, Event::Promoted { revoke_after: 0 })
            .unwrap();
        record.append("k", 4, Event::Completed).unwrap();
        let mut store = VaultStore {
            tool: tool(&dir),
            key: "k".into(),
            text: Zeroizing::new("key-replaced-by-hand-0123".into()),
            current: Secret::new("key-replaced-by-hand-0123"),
            admin: None,
            temporary: HashMap::new(),
        };
        let config = KeyConfig {
            key: "k".into(),
            admin: "k".into(),
            overlap_secs: 0,
            issued_name: "n".into(),
            known_id: None,
            trust_recorded_id,
        };
        let mut fake = Fake {
            verify_status: 200,
            calls: Vec::new(),
        };
        Engine {
            recipe: &recipe,
            config: &config,
            transport: &mut fake,
            store: &mut store,
            journal: &mut record,
            sinks: Vec::new(),
            now: &|| 100,
        }
        .rotate()
        .unwrap();
        fs::remove_dir_all(dir).unwrap();
        fake.calls
    }

    #[test]
    fn a_key_replaced_by_hand_does_not_revoke_the_one_before_it() {
        let deletes = |calls: Vec<(String, String, String)>| {
            calls.into_iter().filter(|call| call.0 == "DELETE").count()
        };
        assert_eq!(deletes(revoked_after_rerotating(true)), 1);
        assert_eq!(deletes(revoked_after_rerotating(false)), 0);
    }

    #[test]
    fn statuses_say_where_each_key_stands_with_no_value() {
        let dir = folder("status");
        let mut record = Journal::open(Box::new(FileBackend::new(dir.join("j")))).unwrap();
        record
            .append("a", 1, Event::Started { old_id: None })
            .unwrap();
        record
            .append("a", 2, Event::Promoted { revoke_after: 9 })
            .unwrap();
        record
            .append("b", 3, Event::Started { old_id: None })
            .unwrap();
        record.append("b", 4, Event::OldRevoked).unwrap();
        record.append("b", 5, Event::Completed).unwrap();
        let list = statuses(&record);
        assert_eq!(list[0].phase, "waiting");
        assert_eq!(list[0].revoke_after, Some(9));
        assert_eq!(list[1].phase, "completed");
        fs::remove_dir_all(dir).unwrap();
    }
}
