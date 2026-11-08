//! Rotates one key held in the vault. The engine decides the order, and this file connects it to
//! the real world: the vault for storage and the places that use the key.
//!
//! This program cannot open the vault. The caller opens what it needs, with a fingerprint, and sends
//! it on stdin. Writing needs no fingerprint, so each write goes straight to the vault's own tool
//! and is durable before the engine records the step.

#[cfg(test)]
use crate::engine::SinkError;
use crate::engine::{Engine, KeyConfig, Outcome, Sink};
use crate::journal::{Event, FileBackend, Journal, Phase};
use crate::keys::{holds_key, MIN_SWAP_CHARS};
use crate::places::{action_sink, FileSink};
use crate::recipe::Recipe;
use crate::secret::Secret;
use crate::transport::HttpTransport;
use crate::verify::{now, read_key_for, resolve, Sealed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

mod status;
mod vault_store;

pub use status::{statuses, statuses_json, Status};
use vault_store::check_new_key;
pub use vault_store::VaultStore;

#[derive(Debug, Serialize, Deserialize)]
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
    /// How many lines the journal held for this key when its copy was opened. A different count
    /// means another window rotated it since then, and the opened copy may be a revoked key.
    pub expected_events: Option<usize>,
}

fn frozen_path(journal: &Path, key: &str) -> PathBuf {
    let digest: String = Sha256::digest(key.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    journal.with_extension(format!("plan-{digest}"))
}

/// Keeps the plan a rotation started with. Undoing one must reach every place that got the new
/// key, even if the settings or the keys folder changed in between. It holds no value.
fn freeze_plan(journal: &Path, plan: &Plan) -> Result<(), String> {
    let text = serde_json::to_vec(plan).map_err(|e| e.to_string())?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let path = frozen_path(journal, &plan.key);
    let mut file = options.open(&path).map_err(|e| format!("the plan: {e}"))?;
    file.write_all(&text)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("the plan: {e}"))
}

pub(super) fn frozen_plan(journal: &Path, key: &str) -> Option<Plan> {
    fs::read(frozen_path(journal, key))
        .ok()
        .and_then(|text| serde_json::from_slice(&text).ok())
}

/// A key a person made by hand, sent once on stdin and never saved under this name.
fn incoming_name(key: &str) -> String {
    format!("{key}#incoming")
}

pub(super) fn pending_name(key: &str) -> String {
    format!("{key}#pending")
}

fn previous_name(key: &str) -> String {
    format!("{key}#previous")
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
        Outcome::NewKeyFailing => ("new_key_failing", None, None),
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

pub(super) fn manual_of(journal: &Journal, key: &str) -> Vec<String> {
    journal
        .latest(key)
        .iter()
        .filter_map(|event| match event {
            Event::ManualAction { what } => Some(what.clone()),
            _ => None,
        })
        .collect()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RunOptions {
    pub resume: bool,
    /// End the overlap now, because a person said their services use the new key.
    pub revoke_now: bool,
}

/// A pasted key must be a new one. The old key gets revoked after this, so pasting the current key
/// by mistake would end with every service holding a dead key.
fn check_handed_over(value: &Secret, current: &Secret) -> Result<(), String> {
    check_new_key(value.expose())?;
    if value == current {
        return Err("that is the key you already have, so make a new one at the provider".into());
    }
    Ok(())
}

pub fn run(
    plan: &Path,
    tool: &Path,
    journal: &Path,
    sealed: &Sealed,
    options: RunOptions,
) -> Result<Report, String> {
    let text = fs::read_to_string(plan).map_err(|e| format!("{}: {e}", plan.display()))?;
    let mut plan: Plan = serde_json::from_str(&text).map_err(|e| format!("the plan: {e}"))?;
    if plan.key.ends_with("#pending")
        || plan.key.ends_with("#previous")
        || plan.key.ends_with("#incoming")
    {
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
    let mut record = Journal::open(Box::new(FileBackend::new(journal)))
        .map_err(|e| format!("the journal: {e}"))?;
    let events = record
        .entries()
        .iter()
        .filter(|e| e.key == plan.key)
        .count();
    if plan
        .expected_events
        .is_some_and(|expected| expected != events)
    {
        return Err("this key changed while it was being opened, so try again".into());
    }
    let phase = record.phase(&plan.key);
    let open = phase != Phase::Idle;
    if open {
        match frozen_plan(journal, &plan.key) {
            Some(frozen) => plan = frozen,
            // The places and actions it started with are what undoing it needs. Today's settings may
            // name others, so going on with them could leave the new key in some places and the old in
            // others, or revoke the only one that works.
            None => {
                return Err(
                    "this rotation's saved plan is missing, so it stops here. Finish it by hand at the provider, then mark the key replaced"
                        .into(),
                )
            }
        }
    }
    let recipe = resolve(&plan.recipe, plan.host.as_deref())?;
    let handed_over = sealed.text(&incoming_name(&plan.key)).map(Secret::new);
    if !open {
        if recipe.can_rotate() && handed_over.is_some() {
            return Err(format!(
                "{} makes its own keys, so none is pasted",
                plan.recipe
            ));
        }
        let by_hand = recipe.can_rotate_by_hand() && handed_over.is_some();
        if !recipe.can_rotate() && !by_hand {
            return Err(format!(
                "keyreeve does not know how to rotate {}",
                plan.recipe
            ));
        }
    }
    // After promotion only the revocation is left, so a retired service cannot block it.
    let places_needed = !matches!(phase, Phase::Promoted | Phase::OldRevoked);
    let (mut store, mut sinks) = prepare(&plan, &recipe, tool, sealed, !open, places_needed)?;
    if !open {
        // Checked here, since a person pasting a key should hear about a bad one at once.
        if let Some(value) = &handed_over {
            check_handed_over(value, &store.current)?;
        }
        freeze_plan(journal, &plan)?;
    }
    let config = KeyConfig {
        key: plan.key.clone(),
        admin: plan.admin.clone().unwrap_or_else(|| plan.key.clone()),
        overlap_secs: plan.overlap_secs,
        issued_name: plan.issued_name.clone(),
        known_id: plan.known_id.clone(),
        handed_over,
        revoke_now: options.revoke_now,
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
        if options.resume {
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
    places_needed: bool,
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
    if places_needed {
        for (label, path) in files {
            let sink = FileSink {
                label,
                path: PathBuf::from(path),
                known: known.clone(),
            };
            // Only a new rotation can stop here. An open one must reach its undo, which reports
            // a place it cannot restore.
            if starting {
                let held = fs::read_to_string(&sink.path)
                    .map(Zeroizing::new)
                    .map_err(|_| format!("{path} could not be read"))?;
                if !known.iter().any(|value| holds_key(&held, value.expose())) {
                    return Err(format!("{path} does not hold this key"));
                }
            }
            sinks.push(Box::new(sink));
        }
        for place in &plan.place_actions {
            sinks.push(Box::new(action_sink(place)?));
        }
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

/// Notes that a key was replaced by hand, so the next rotation does not revoke by its old id.
pub fn forget_id(journal: &Path, key: &str) -> Result<(), String> {
    // The same lock as a rotation, read after taking it, so the two never write over each other.
    let lock = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(journal.with_extension("lock"))
        .map_err(|e| format!("the journal: {e}"))?;
    // A moment's wait: a process starting elsewhere can hold a copy of the lock for an instant after a
    // rotation let go of it, and that is not a rotation running.
    let mut tries = 0;
    while lock.try_lock().is_err() {
        tries += 1;
        if tries == 10 {
            return Err("a rotation is running".to_owned());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut record = Journal::open(Box::new(FileBackend::new(journal)))
        .map_err(|e| format!("the journal: {e}"))?;
    if record.phase(key) != Phase::Idle {
        return Err("a rotation of this key is open".into());
    }
    if record.current_id(key).is_some() {
        record
            .append(key, now(), Event::Replaced)
            .map_err(|e| format!("the journal: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
