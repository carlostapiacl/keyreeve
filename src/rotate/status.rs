//! Where each rotation stands, for people. It holds ids and step names, and never a value.

use super::{frozen_plan, manual_of};
use crate::journal::{Event, FileBackend, Journal, Phase};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Status {
    pub key: String,
    /// How many lines the journal holds for this key.
    pub events: usize,
    /// The other key this rotation uses to create and revoke, which has to be opened too.
    pub admin: Option<String>,
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
                events: journal.entries().iter().filter(|e| e.key == key).count(),
                admin: None,
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
    let mut list = statuses(&record);
    for status in &mut list {
        status.admin = frozen_plan(journal, &status.key).and_then(|plan| plan.admin);
    }
    serde_json::to_string(&list).map_err(|e| e.to_string())
}
