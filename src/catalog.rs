//! Turns an inventory into a catalog: each file with its tags and an access level.
//!
//! The rules live in a file you own, because which project a key belongs to is your business.
//! The catalog reads only the inventory, so it never opens a key file.

use crate::inventory::write_private;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Not a secret, such as a public key.
    None,
    /// Low risk, so an agent may use it without asking.
    Free,
    /// An agent must ask each time.
    Ask,
    /// Only a person uses it.
    Never,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Free => "free",
            Self::Ask => "ask",
            Self::Never => "never",
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Exact paths, which replace whatever the rules decided about that file's level.
    #[serde(default)]
    pub files: BTreeMap<String, FileOverride>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Matches when any of these appears, ignoring case, in the path, a label or a kind.
    #[serde(rename = "match")]
    pub matches: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub level: Option<Level>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileOverride {
    #[serde(default)]
    pub tags: Vec<String>,
    pub level: Option<Level>,
}

/// The parts of an inventory that a catalog uses.
#[derive(Debug, Deserialize)]
pub struct InventoryItem {
    pub path: String,
    pub modified: u64,
    pub mode: Option<String>,
    pub format: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub kinds: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Inventory {
    schema: u32,
    items: Vec<InventoryItem>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Row {
    pub path: String,
    pub level: Level,
    pub tags: Vec<String>,
    pub format: String,
    pub labels: Vec<String>,
    pub modified: String,
    pub mode: String,
    /// True if one of your rules or overrides covers this file.
    pub reviewed: bool,
}

pub fn parse_inventory(text: &str) -> Result<Vec<InventoryItem>, String> {
    let inventory: Inventory = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if inventory.schema != 1 {
        return Err(format!(
            "unknown inventory schema {}, expected 1",
            inventory.schema
        ));
    }
    Ok(inventory.items)
}

pub fn parse_rules(text: &str) -> Result<Rules, String> {
    let rules: Rules = serde_norway::from_str(text).map_err(|e| e.to_string())?;
    if let Some(rule) = rules
        .rules
        .iter()
        .find(|rule| rule.matches.iter().any(String::is_empty) || rule.matches.is_empty())
    {
        return Err(format!(
            "a rule needs at least one non-empty match: {rule:?}"
        ));
    }
    Ok(rules)
}

pub fn build(items: &[InventoryItem], rules: &Rules) -> Vec<Row> {
    items.iter().map(|item| build_row(item, rules)).collect()
}

fn build_row(item: &InventoryItem, rules: &Rules) -> Row {
    let mut tags: BTreeSet<String> = item.kinds.iter().map(|k| format!("kind:{k}")).collect();
    let is_public_key = item.path.ends_with(".pub");
    let mut level = None::<Level>;
    let mut reviewed = false;

    let haystack: Vec<String> = std::iter::once(&item.path)
        .chain(&item.fields)
        .chain(&item.kinds)
        .map(|text| text.to_lowercase())
        .collect();
    for rule in &rules.rules {
        let hit = rule.matches.iter().any(|needle| {
            let needle = needle.to_lowercase();
            haystack.iter().any(|text| text.contains(&needle))
        });
        if hit {
            reviewed = true;
            tags.extend(rule.tags.iter().cloned());
            // The most restrictive rule wins, so a broad rule cannot loosen a narrow one.
            level = level.max(rule.level);
        }
    }
    if let Some(file) = rules.files.get(&item.path) {
        reviewed = true;
        tags.extend(file.tags.iter().cloned());
        level = file.level.or(level);
    }
    let level = level.unwrap_or(if is_public_key {
        Level::None
    } else {
        Level::Ask
    });
    Row {
        path: item.path.clone(),
        level,
        tags: tags.into_iter().collect(),
        format: item.format.clone(),
        labels: item.fields.clone(),
        modified: date_of(item.modified),
        mode: item.mode.clone().unwrap_or_default(),
        reviewed,
    }
}

pub fn to_csv(rows: &[Row]) -> String {
    let mut out = String::from("path,level,tags,format,labels,modified,mode,reviewed\n");
    for row in rows {
        let cells = [
            csv_cell(&row.path),
            row.level.to_string(),
            csv_cell(&row.tags.join(" ")),
            csv_cell(&row.format),
            csv_cell(&row.labels.join(" ")),
            row.modified.clone(),
            csv_cell(&row.mode),
            row.reviewed.to_string(),
        ];
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

pub fn write_csv(rows: &[Row], out: &Path) -> io::Result<()> {
    write_private(out, &to_csv(rows))
}

/// A cell that starts with these runs as a formula in a spreadsheet, and file names are not trusted.
fn csv_cell(text: &str) -> String {
    let guarded = if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{text}")
    } else {
        text.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// Converts Unix seconds to `YYYY-MM-DD` in UTC.
fn date_of(seconds: u64) -> String {
    let z = (seconds / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(path: &str) -> InventoryItem {
        InventoryItem {
            path: path.into(),
            modified: 0,
            mode: Some("600".into()),
            format: "single-value".into(),
            fields: Vec::new(),
            kinds: Vec::new(),
        }
    }

    fn rules(text: &str) -> Rules {
        parse_rules(text).unwrap()
    }

    #[test]
    fn with_no_rules_everything_asks_except_a_public_key() {
        let rows = build(&[item("a.txt"), item("b.pub")], &Rules::default());
        assert_eq!(rows[0].level, Level::Ask);
        assert_eq!(rows[1].level, Level::None);
        assert!(!rows[0].reviewed);
    }

    #[test]
    fn tags_add_up_and_the_most_restrictive_level_wins() {
        let rows = build(
            &[item("Billing/STRIPE-prod.txt")],
            &rules(
                r#"
rules:
  - { match: [stripe], tags: [provider:stripe], level: never }
  - { match: [prod], tags: [env:prod], level: free }
  - { match: [nothing-here], tags: [wrong] }
"#,
            ),
        );
        assert_eq!(rows[0].tags, ["env:prod", "provider:stripe"]);
        assert_eq!(rows[0].level, Level::Never);
        assert!(rows[0].reviewed);
    }

    #[test]
    fn a_rule_can_match_a_label_or_a_kind() {
        let mut by_label = item("a.env");
        by_label.fields = vec!["STRIPE_KEY".into()];
        let mut by_kind = item("b.txt");
        by_kind.kinds = vec!["stripe-live".into()];
        let rows = build(
            &[by_label, by_kind],
            &rules("rules: [{ match: [stripe], tags: [billing] }]"),
        );
        assert_eq!(rows[0].tags, ["billing"]);
        assert_eq!(rows[1].tags, ["billing", "kind:stripe-live"]);
    }

    #[test]
    fn an_exact_file_overrides_the_level_and_adds_tags() {
        let rows = build(
            &[item("deploy.key")],
            &rules(
                r#"
rules: [{ match: [deploy], tags: [ops], level: never }]
files: { deploy.key: { tags: [shared], level: ask } }
"#,
            ),
        );
        assert_eq!(rows[0].tags, ["ops", "shared"]);
        assert_eq!(rows[0].level, Level::Ask);
    }

    #[test]
    fn refuses_a_rule_that_would_match_everything_or_a_typo() {
        assert!(parse_rules("rules: [{ match: [''], tags: [x] }]").is_err());
        assert!(parse_rules("rules: [{ match: [], tags: [x] }]").is_err());
        assert!(parse_rules("rules: [{ match: [x], tag: [x] }]").is_err());
        assert!(parse_rules("rules: [{ match: [x], level: sometimes }]").is_err());
    }

    #[test]
    fn a_hostile_file_name_cannot_become_a_formula_or_break_a_row() {
        let rows = build(
            &[item("=cmd,\"x\".txt"), item("@sum.txt")],
            &Rules::default(),
        );
        let csv = to_csv(&rows);
        assert!(csv.contains("\"'=cmd,\"\"x\"\".txt\",ask"), "{csv}");
        assert!(csv.contains("'@sum.txt,ask"), "{csv}");
        assert_eq!(csv.lines().count(), 3);
    }

    #[test]
    fn reads_the_inventory_it_writes() {
        let dir = std::env::temp_dir().join(format!("keyreeve-catalog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("k.env"), "API_KEY=CANARYcatalog\n").unwrap();
        let report = crate::inventory::scan(&dir, &Default::default()).unwrap();
        let text = serde_json::to_string(&report).unwrap();
        let items = parse_inventory(&text).unwrap();
        let csv = to_csv(&build(&items, &Rules::default()));
        assert!(csv.contains("k.env,ask,,env,API_KEY,"), "{csv}");
        assert!(!csv.contains("CANARY"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_an_unknown_schema() {
        assert!(parse_inventory(r#"{"schema":9,"items":[]}"#).is_err());
    }

    #[test]
    fn dates_are_correct() {
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(date_of(951_782_400), "2000-02-29");
        assert_eq!(date_of(1_793_923_200), "2026-11-06");
    }
}
