//! The rotation itself.
//!
//! The order is what keeps services running: the new key is saved before anything uses it,
//! it is verified before any service receives it, and the old key is revoked last. Each step
//! is recorded first, so `resume` can finish or undo a rotation that stopped halfway.

use crate::journal::{Event, Journal, Phase};
use crate::recipe::{extract, Recipe, Step};
use crate::secret::Secret;
use crate::store::{Store, StoreError};
use crate::transport::{Request, Response, Transport, TransportError};
use std::fmt;
use std::io;

/// A place that uses the key, such as a CI secret, a hosting variable or a `.env` file.
pub trait Sink {
    fn name(&self) -> &str;
    /// Must be safe to repeat with the same value.
    fn update(&mut self, value: &Secret) -> Result<(), SinkError>;
}

#[derive(Debug)]
pub struct SinkError;

#[derive(Debug, Clone)]
pub struct KeyConfig {
    /// The name of the key in the store.
    pub key: String,
    /// The store entry allowed to create and revoke keys. May be the key itself.
    pub admin: String,
    /// How long old and new keys stay valid together, in seconds.
    pub overlap_secs: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    RolledBack {
        reason: String,
    },
    /// The new key is in place. The old one is revoked after this time.
    AwaitingOverlap {
        revoke_after: u64,
    },
    /// The new key is in place, but the provider refused to revoke the old one. Safe to retry.
    RevokePending,
    /// A service could not be restored, so its key is not revoked. Safe to retry.
    RollbackBlocked {
        sink: String,
    },
    NothingToDo,
}

#[derive(Debug)]
pub enum Error {
    /// The recipe has no `create` and `revoke`, so it can only check a key.
    CannotRotate,
    /// A rotation of this key is unfinished. Run `resume`.
    Unfinished,
    KeyMissing(String),
    Store(StoreError),
    Journal(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotRotate => f.write_str("this recipe can only check a key"),
            Self::Unfinished => f.write_str("a rotation of this key is unfinished, resume it"),
            Self::KeyMissing(name) => write!(f, "{name} is not in the store"),
            Self::Store(error) => write!(f, "{error}"),
            Self::Journal(error) => write!(f, "journal: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Journal(error)
    }
}

pub struct Engine<'a> {
    pub recipe: &'a Recipe,
    pub config: &'a KeyConfig,
    pub transport: &'a mut dyn Transport,
    pub store: &'a mut dyn Store,
    pub journal: &'a mut Journal,
    pub sinks: Vec<&'a mut dyn Sink>,
    pub now: &'a dyn Fn() -> u64,
}

enum Create {
    Issued {
        id: String,
        value: Secret,
    },
    /// The provider said no, so no key exists.
    Refused(String),
    /// A key may exist that nobody can see.
    Unknown(String),
}

impl Engine<'_> {
    pub fn rotate(&mut self) -> Result<Outcome, Error> {
        if !self.recipe.can_rotate() {
            return Err(Error::CannotRotate);
        }
        let key = self.config.key.clone();
        if self.journal.phase(&key) != Phase::Idle {
            return Err(Error::Unfinished);
        }
        let current = self
            .store
            .get(&key)?
            .ok_or_else(|| Error::KeyMissing(key.clone()))?;
        let admin = self.admin()?;
        let old_id = self.journal.current_id(&key);

        // Recorded first: a copy saved before the record exists could never be cleaned up.
        self.record(Event::Started { old_id })?;
        self.store.put(&self.previous_name(), &current)?;

        match self.create(&admin) {
            Create::Issued { id, value } => {
                self.record(Event::Created { new_id: id })?;
                self.store.put(&self.pending_name(), &value)?;
                self.record(Event::PendingStored)?;
                self.drive()
            }
            Create::Refused(reason) => self.close_without_key(reason),
            Create::Unknown(reason) => {
                self.manual("a key may have been created: check the provider")?;
                self.close_without_key(reason)
            }
        }
    }

    /// Finishes or undoes whatever the record says is open. Safe to call at any time.
    pub fn resume(&mut self) -> Result<Outcome, Error> {
        if !self.recipe.can_rotate() {
            return Err(Error::CannotRotate);
        }
        let key = self.config.key.clone();
        match self.journal.phase(&key) {
            Phase::Idle => Ok(Outcome::NothingToDo),
            Phase::Started => {
                self.manual("a key may have been created: check the provider")?;
                self.close_without_key("stopped_during_create".into())
            }
            Phase::Created => {
                if self.store.get(&self.pending_name())?.is_some() {
                    self.record(Event::PendingStored)?;
                    self.drive()
                } else {
                    self.begin_rollback("new_key_not_saved")
                }
            }
            _ => self.drive(),
        }
    }

    fn drive(&mut self) -> Result<Outcome, Error> {
        let key = self.config.key.clone();
        loop {
            match self.journal.phase(&key) {
                Phase::PendingStored => {
                    let Some(pending) = self.store.get(&self.pending_name())? else {
                        return self.begin_rollback("new_key_not_saved");
                    };
                    if !self.verify(&pending) {
                        return self.begin_rollback("verify_failed");
                    }
                    self.record(Event::Verified)?;
                }
                Phase::Verified => {
                    let Some(pending) = self.store.get(&self.pending_name())? else {
                        return self.begin_rollback("new_key_not_saved");
                    };
                    let done: Vec<String> = self.updated_sinks();
                    for index in 0..self.sinks.len() {
                        let name = self.sinks[index].name().to_owned();
                        if done.contains(&name) {
                            continue;
                        }
                        if self.sinks[index].update(&pending).is_err() {
                            return self.begin_rollback(&format!("sink_failed:{name}"));
                        }
                        self.record(Event::SinkUpdated { sink: name })?;
                    }
                    self.store.put(&key, &pending)?;
                    let revoke_after = (self.now)().saturating_add(self.config.overlap_secs);
                    self.record(Event::Promoted { revoke_after })?;
                }
                Phase::Promoted => {
                    self.store.delete(&self.pending_name())?;
                    let revoke_after = self.revoke_after();
                    if (self.now)() < revoke_after {
                        return Ok(Outcome::AwaitingOverlap { revoke_after });
                    }
                    match self.old_id() {
                        Some(old_id) => {
                            let admin = self.admin()?;
                            if !self.revoke(&admin, &old_id) {
                                return Ok(Outcome::RevokePending);
                            }
                        }
                        None => {
                            self.manual("the id of the previous key is unknown: revoke it by hand")?
                        }
                    }
                    self.record(Event::OldRevoked)?;
                }
                Phase::OldRevoked => {
                    self.store.delete(&self.previous_name())?;
                    self.record(Event::Completed)?;
                    return Ok(Outcome::Completed);
                }
                Phase::RollingBack => return self.rollback(),
                Phase::Idle | Phase::Started | Phase::Created => return Ok(Outcome::NothingToDo),
            }
        }
    }

    fn begin_rollback(&mut self, reason: &str) -> Result<Outcome, Error> {
        self.record(Event::RollbackStarted {
            reason: reason.to_owned(),
        })?;
        self.rollback()
    }

    fn rollback(&mut self) -> Result<Outcome, Error> {
        let key = self.config.key.clone();
        let events = self.journal.latest(&key);
        let reason = events
            .iter()
            .find_map(|event| match event {
                Event::RollbackStarted { reason } => Some(reason.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let reached_sinks = events.iter().any(|event| matches!(event, Event::Verified));
        let new_id = self.new_id();
        drop(events);

        // A sink can hold the new key before the record says so, so restore all of them.
        // Nothing is revoked until every service is back on the old key.
        if let Some(old) = self.store.get(&self.previous_name())? {
            if reached_sinks {
                for sink in &mut self.sinks {
                    if sink.update(&old).is_err() {
                        let name = sink.name().to_owned();
                        self.manual(&format!("{name} still holds the new key"))?;
                        return Ok(Outcome::RollbackBlocked { sink: name });
                    }
                }
            }
            self.store.put(&key, &old)?;
        }
        if let Some(new_id) = new_id {
            let admin = self.admin()?;
            if !self.revoke(&admin, &new_id) {
                self.manual(&format!("revoke the unused key {new_id} by hand"))?;
            }
        }
        self.store.delete(&self.pending_name())?;
        self.store.delete(&self.previous_name())?;
        self.record(Event::RolledBack {
            reason: reason.clone(),
        })?;
        Ok(Outcome::RolledBack { reason })
    }

    fn close_without_key(&mut self, reason: String) -> Result<Outcome, Error> {
        self.store.delete(&self.previous_name())?;
        self.record(Event::RolledBack {
            reason: reason.clone(),
        })?;
        Ok(Outcome::RolledBack { reason })
    }

    fn create(&mut self, admin: &Secret) -> Create {
        let recipe = self.recipe;
        let vars = [("key_name", self.config.key.as_str())];
        let response = match self.send(recipe.create_step(), &vars, admin) {
            Ok(response) => response,
            Err(_) => return Create::Unknown("create_failed".into()),
        };
        if !recipe.create_step().accepts(response.status) {
            let reason = format!("create_status_{}", response.status);
            return if (400..500).contains(&response.status) {
                Create::Refused(reason)
            } else {
                Create::Unknown(reason)
            };
        }
        let Ok(json) = serde_json::from_str(response.body.expose()) else {
            return Create::Unknown("create_unreadable".into());
        };
        let value = recipe
            .create_step()
            .value_from
            .as_deref()
            .and_then(|path| extract(&json, path));
        let id = recipe
            .create_step()
            .id_from
            .as_deref()
            .and_then(|path| extract(&json, path));
        match (id, value) {
            (Some(id), Some(value)) => Create::Issued {
                id,
                value: Secret::new(value),
            },
            _ => Create::Unknown("create_unreadable".into()),
        }
    }

    fn verify(&mut self, value: &Secret) -> bool {
        let recipe = self.recipe;
        let id = self.new_id().unwrap_or_default();
        match self.send(&recipe.verify, &[("id", id.as_str())], value) {
            Ok(response) => recipe.verify.accepts(response.status),
            Err(_) => false,
        }
    }

    /// A 404 counts as revoked, so a retry after a crash does not get stuck.
    fn revoke(&mut self, admin: &Secret, id: &str) -> bool {
        let recipe = self.recipe;
        match self.send(recipe.revoke_step(), &[("id", id)], admin) {
            Ok(response) => recipe.revoke_step().accepts(response.status) || response.status == 404,
            Err(_) => false,
        }
    }

    fn send(
        &mut self,
        step: &Step,
        vars: &[(&str, &str)],
        credential: &Secret,
    ) -> Result<Response, TransportError> {
        self.transport
            .send(&Request::for_step(self.recipe, step, vars, credential))
    }

    fn admin(&self) -> Result<Secret, Error> {
        self.store
            .get(&self.config.admin)?
            .ok_or_else(|| Error::KeyMissing(self.config.admin.clone()))
    }

    fn record(&mut self, event: Event) -> Result<(), Error> {
        let at = (self.now)();
        self.journal.append(&self.config.key, at, event)?;
        Ok(())
    }

    fn manual(&mut self, what: &str) -> Result<(), Error> {
        self.record(Event::ManualAction {
            what: what.to_owned(),
        })
    }

    fn pending_name(&self) -> String {
        format!("{}#pending", self.config.key)
    }

    fn previous_name(&self) -> String {
        format!("{}#previous", self.config.key)
    }

    fn new_id(&self) -> Option<String> {
        self.journal
            .latest(&self.config.key)
            .iter()
            .find_map(|event| match event {
                Event::Created { new_id } => Some(new_id.clone()),
                _ => None,
            })
    }

    fn old_id(&self) -> Option<String> {
        self.journal
            .latest(&self.config.key)
            .iter()
            .find_map(|event| match event {
                Event::Started { old_id } => old_id.clone(),
                _ => None,
            })
    }

    fn revoke_after(&self) -> u64 {
        self.journal
            .latest(&self.config.key)
            .iter()
            .find_map(|event| match event {
                Event::Promoted { revoke_after } => Some(*revoke_after),
                _ => None,
            })
            .unwrap_or(0)
    }

    fn updated_sinks(&self) -> Vec<String> {
        self.journal
            .latest(&self.config.key)
            .iter()
            .filter_map(|event| match event {
                Event::SinkUpdated { sink } => Some(sink.clone()),
                _ => None,
            })
            .collect()
    }
}
