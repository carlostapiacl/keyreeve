//! What each check found, one line per key. It holds results and never a value.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// One line of the history: which file, which recipe, when and the result.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub at: u64,
    pub file: String,
    pub recipe: String,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
