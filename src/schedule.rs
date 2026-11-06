//! A periodic check, for keys you allowed agents to use. It needs no fingerprint and no window, so
//! it covers those alone, and says only how many keys stopped working.

use crate::catalog;
use crate::providers;
use crate::verify::{append_history, now, parse_history, run_at, HistoryEntry};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize)]
struct Settings {
    keys_folder: String,
}

fn read_or_empty(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Builds the catalog rows from the private files, as the app and the command do.
pub fn rows(home: &Path) -> Result<Vec<catalog::Row>, String> {
    let inventory =
        fs::read_to_string(home.join("inventory.json")).map_err(|e| format!("inventory: {e}"))?;
    let items = catalog::parse_inventory(&inventory)?;
    let rules_text = read_or_empty(&home.join("rules.yaml"));
    let mut rules = if rules_text.is_empty() {
        catalog::Rules::default()
    } else {
        catalog::parse_rules(&rules_text)?
    };
    let edits = read_or_empty(&home.join("edits.json"));
    if !edits.is_empty() {
        rules.edits = catalog::parse_edits(&edits)?;
    }
    let history = parse_history(&read_or_empty(&home.join("history.jsonl")));
    Ok(catalog::build(&items, &rules, &history))
}

/// Which keys this check may touch. Only those you set to "agents can use it", which is the same
/// promise: no fingerprint.
pub fn eligible(rows: &[catalog::Row]) -> Vec<&catalog::Row> {
    rows.iter()
        .filter(|row| row.level == catalog::Level::Free)
        .filter(|row| !row.recipes.is_empty())
        .filter(|row| {
            !row.tags
                .iter()
                .any(|tag| tag == "internal" || tag == "status:archived")
        })
        .collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub checked: usize,
    pub works: usize,
    pub stopped: usize,
}

pub fn run(home: &Path) -> Result<Summary, String> {
    let settings: Settings = serde_json::from_str(&read_or_empty(&home.join("app-settings.json")))
        .map_err(|_| "no keys folder is set".to_owned())?;
    let keys = PathBuf::from(settings.keys_folder);
    let rows = rows(home)?;
    let at = now();
    let mut records = Vec::new();
    let mut summary = Summary::default();
    for row in eligible(&rows) {
        let field = (!row.field.is_empty()).then_some(row.field.as_str());
        let host = (!row.host.is_empty()).then_some(row.host.as_str());
        let mut worked = false;
        for recipe in &row.recipes {
            let verdict = run_at(recipe, &keys.join(&row.path), field, host);
            let (result, reason) = match &verdict {
                Ok(verdict) => (verdict.code(), verdict.reason()),
                Err(why) => (
                    "no_result",
                    Some(why.rsplit(": ").next().unwrap_or(why).to_owned()),
                ),
            };
            worked |= result == "works";
            records.push(HistoryEntry {
                at,
                file: row.path.clone(),
                recipe: recipe.clone(),
                result: result.to_owned(),
                reason,
            });
        }
        summary.checked += 1;
        if worked {
            summary.works += 1;
        } else if row.last_result == "works" {
            summary.stopped += 1;
        }
    }
    append_history(&home.join("history.jsonl"), &records).map_err(|e| e.to_string())?;
    let fresh = self::rows(home)?;
    catalog::write_csv(&fresh, &home.join("catalog.csv")).map_err(|e| e.to_string())?;
    Ok(summary)
}

/// A notification holds counts only, and no name of a key.
pub fn notify(summary: &Summary, spanish: bool) {
    if summary.stopped == 0 {
        return;
    }
    let text = match (spanish, summary.stopped) {
        (true, 1) => "1 clave dejó de funcionar".to_owned(),
        (true, n) => format!("{n} claves dejaron de funcionar"),
        (false, 1) => "1 key stopped working".to_owned(),
        (false, n) => format!("{n} keys stopped working"),
    };
    let script = format!("display notification \"{text}\" with title \"Keyreeve\"");
    let _ = Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output();
}

pub fn default_home() -> PathBuf {
    providers::home()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(path: &str, level: catalog::Level, recipes: &[&str], tags: &[&str]) -> catalog::Row {
        catalog::Row {
            path: path.into(),
            level,
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            format: String::new(),
            labels: Vec::new(),
            modified: String::new(),
            mode: String::new(),
            reviewed: true,
            last_result: String::new(),
            last_checked: String::new(),
            last_reason: String::new(),
            recipes: recipes.iter().map(|r| (*r).to_owned()).collect(),
            field: String::new(),
            name: String::new(),
            description: String::new(),
            criticality: 0,
            criticality_suggested: false,
            rotate_days: 0,
            host: String::new(),
        }
    }

    #[test]
    fn only_keys_set_for_agents_are_checked_without_you() {
        use catalog::Level::{Ask, Free, Never};
        let rows = [
            row("yes", Free, &["github"], &[]),
            row("asks", Ask, &["github"], &[]),
            row("mine", Never, &["github"], &[]),
            row("nowhere", Free, &[], &[]),
            row("internal", Free, &["github"], &["internal"]),
            row("archived", Free, &["github"], &["status:archived"]),
        ];
        let chosen: Vec<&str> = eligible(&rows).iter().map(|r| r.path.as_str()).collect();
        assert_eq!(chosen, ["yes"]);
    }

    #[test]
    fn a_missing_setup_is_an_error_and_does_not_panic() {
        let dir = std::env::temp_dir().join(format!("keyreeve-schedule-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(run(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
