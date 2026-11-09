//! Turns an inventory into a catalog: each file with its tags and an access level.
//!
//! The rules live in a file you own, because which project a key belongs to is your business.
//! The catalog reads only the inventory, so it never opens a key file.
//!
//! A check sends a key to a provider, so a key gets a recipe only if your rules name one, or if
//! its own prefix proves the provider. A tag is not enough: a wrong tag would send the key to
//! the wrong company.

use crate::inventory::write_private;
use crate::verify::HistoryEntry;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
    /// Edits made in the app. They come last, and they replace rather than add.
    #[serde(skip)]
    pub edits: BTreeMap<String, Edit>,
}

/// What the app saved for one file. A missing part leaves what the rules decided.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    pub tags: Option<Vec<String>>,
    pub level: Option<Level>,
    pub recipes: Option<Vec<String>>,
    pub field: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub criticality: Option<u8>,
    pub host: Option<String>,
    /// The day the key stops working, `yyyy-mm-dd`, as the person or an agent wrote it.
    pub expires: Option<String>,
}

pub fn parse_edits(text: &str) -> Result<BTreeMap<String, Edit>, String> {
    serde_norway::from_str(text).map_err(|e| e.to_string())
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
    /// How bad it would be if this key leaked, from 1 to 5. The highest rule wins.
    pub criticality: Option<u8>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileOverride {
    pub criticality: Option<u8>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub level: Option<Level>,
    /// Recipes that may check this key. With several, a pass from any of them counts.
    #[serde(default)]
    pub recipes: Vec<String>,
    /// The label or JSON path that holds the key, in a file with more than one value.
    pub field: Option<String>,
    /// Your server, for a provider each person runs themselves.
    pub host: Option<String>,
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
    pub last_result: String,
    pub last_checked: String,
    /// Why the last check gave no answer, in this tool's own words.
    pub last_reason: String,
    /// The day the key stops working, `yyyy-mm-dd`, when someone said so.
    pub expires: String,
    pub recipes: Vec<String>,
    pub field: String,
    pub name: String,
    pub description: String,
    /// 1 to 5, or 0 if nobody rated it.
    pub criticality: u8,
    /// True if the number came from the provider's file, and not from you.
    pub criticality_suggested: bool,
    /// How often the provider's file suggests changing this key, or 0.
    pub rotate_days: u32,
    pub host: String,
}

/// Adds the files moved out after sealing, from the ledger at `path`. They stay on the list, since
/// the vault still holds them. A missing ledger means nothing was moved.
pub fn add_moved(items: &mut Vec<InventoryItem>, path: &std::path::Path) -> Result<(), String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let moved = parse_inventory(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut known: std::collections::HashSet<String> =
        items.iter().map(|item| item.path.clone()).collect();
    for item in moved {
        if known.insert(item.path.clone()) {
            items.push(item);
        }
    }
    Ok(())
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

pub fn build(items: &[InventoryItem], rules: &Rules, history: &[HistoryEntry]) -> Vec<Row> {
    // The history only grows, so each file finds its own lines without reading all of them.
    let mut by_file: HashMap<&str, Vec<&HistoryEntry>> = HashMap::new();
    for entry in history {
        by_file.entry(entry.file.as_str()).or_default().push(entry);
    }
    // A provider of your own is a file to read; each is read once a build, not once per key it names.
    let mut hints: HashMap<String, (Option<u8>, Option<u32>)> = HashMap::new();
    items
        .iter()
        .map(|item| {
            let mut row = build_row(item, rules, &mut hints);
            // With several recipes for one file, a pass from any of them counts, because a
            // check against the wrong provider says nothing about the key.
            let checks = by_file
                .get(item.path.as_str())
                .map_or(&[][..], Vec::as_slice);
            if let Some(at) = checks.iter().map(|h| h.at).max() {
                let latest = checks.iter().filter(|h| h.at == at);
                let shown = latest
                    .clone()
                    .find(|h| h.result == "works")
                    .or_else(|| latest.clone().next());
                row.last_result = shown.map(|h| h.result.clone()).unwrap_or_default();
                row.last_reason = shown.and_then(|h| h.reason.clone()).unwrap_or_default();
                row.last_checked = date_of(at);
            }
            row
        })
        .collect()
}

fn build_row(
    item: &InventoryItem,
    rules: &Rules,
    hints: &mut HashMap<String, (Option<u8>, Option<u32>)>,
) -> Row {
    let mut tags: BTreeSet<String> = item.kinds.iter().map(|k| format!("kind:{k}")).collect();
    let is_public_key = item.path.ends_with(".pub");
    let mut level = None::<Level>;
    let mut reviewed = false;
    let mut criticality = 0_u8;

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
            criticality = criticality.max(rule.criticality.unwrap_or(0));
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
    let file = rules.files.get(&item.path);
    let mut recipes = file.map(|f| f.recipes.clone()).unwrap_or_default();
    if recipes.is_empty() && item.format == "single-value" {
        if let [kind] = item.kinds.as_slice() {
            if crate::providers::proven(kind) {
                recipes.push(kind.clone());
            }
        }
    }
    if let Some(rated) = file.and_then(|f| f.criticality) {
        criticality = rated;
    }
    let mut field = file.and_then(|f| f.field.clone()).unwrap_or_default();
    let (mut name, mut description) = (String::new(), String::new());
    let mut host = file.and_then(|f| f.host.clone()).unwrap_or_default();
    let mut expires = String::new();
    let mut level = level;
    let mut tags: Vec<String> = tags.into_iter().collect();
    if let Some(edit) = rules.edits.get(&item.path) {
        reviewed = true;
        if let Some(edited) = &edit.tags {
            tags = edited.clone();
        }
        level = edit.level.unwrap_or(level);
        if let Some(edited) = &edit.recipes {
            recipes = edited.clone();
        }
        // An empty field in an edit says nothing, so it never takes away the field the rules give.
        if let Some(edited) = edit.field.as_ref().filter(|f| !f.is_empty()) {
            field = edited.clone();
        }
        name = edit.name.clone().unwrap_or_default();
        description = edit.description.clone().unwrap_or_default();
        criticality = edit.criticality.unwrap_or(criticality);
        host = edit.host.clone().unwrap_or(host);
        expires = edit
            .expires
            .clone()
            .filter(|day| is_day(day))
            .unwrap_or_default();
    }
    let (hint, rotate_days) = recipes.first().map_or((None, None), |recipe| {
        *hints
            .entry(recipe.clone())
            .or_insert_with(|| crate::providers::hints(recipe))
    });
    let criticality_suggested = criticality == 0 && hint.is_some();
    if criticality_suggested {
        criticality = hint.unwrap_or(0);
    }
    Row {
        path: item.path.clone(),
        level,
        tags,
        format: item.format.clone(),
        labels: item.fields.clone(),
        modified: date_of(item.modified),
        mode: item.mode.clone().unwrap_or_default(),
        reviewed,
        last_result: String::new(),
        last_checked: String::new(),
        last_reason: String::new(),
        expires,
        recipes,
        field,
        name,
        description,
        criticality: criticality.min(5),
        criticality_suggested,
        rotate_days: rotate_days.unwrap_or(0),
        host,
    }
}

/// A day as `yyyy-mm-dd`, the only shape kept for when a key expires.
fn is_day(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    matches!(parts.as_slice(), [y, m, d] if y.len() == 4 && m.len() == 2 && d.len() == 2
        && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()))
        && (1..=12).contains(&m.parse::<u8>().unwrap_or(0)) && (1..=31).contains(&d.parse::<u8>().unwrap_or(0)))
}

pub fn to_csv(rows: &[Row]) -> String {
    let mut out = String::from(
        "path,level,tags,format,labels,modified,mode,reviewed,last_result,last_checked,recipes,field,name,description,criticality,criticality_suggested,rotate_days,host,last_reason,expires\n",
    );
    for row in rows {
        let cells = [
            csv_cell(&row.path),
            row.level.to_string(),
            csv_cell(&row.tags.join(" ")),
            csv_cell(&row.format),
            csv_cell(&row.labels.join("|")),
            row.modified.clone(),
            csv_cell(&row.mode),
            row.reviewed.to_string(),
            csv_cell(&row.last_result),
            row.last_checked.clone(),
            csv_cell(&row.recipes.join(" ")),
            csv_cell(&row.field),
            csv_cell(&row.name),
            csv_cell(&row.description),
            row.criticality.to_string(),
            row.criticality_suggested.to_string(),
            row.rotate_days.to_string(),
            csv_cell(&row.host),
            csv_cell(&row.last_reason),
            csv_cell(&row.expires),
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
        let rows = build(&[item("a.txt"), item("b.pub")], &Rules::default(), &[]);
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
            &[],
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
            &[],
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
            &[],
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
            &[],
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
        let csv = to_csv(&build(&items, &Rules::default(), &[]));
        assert!(csv.contains("k.env,ask,,env,API_KEY,"), "{csv}");
        assert!(!csv.contains("CANARY"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shows_the_latest_check_and_a_pass_from_any_recipe() {
        let check = |at, recipe: &str, result: &str| HistoryEntry {
            at,
            file: "a.txt".into(),
            recipe: recipe.into(),
            result: result.into(),
            reason: None,
        };
        let history = [
            check(0, "meta", "works"),
            check(86_400, "meta", "rejected"),
            check(86_400, "instagram", "works"),
        ];
        let rows = build(&[item("a.txt"), item("b.txt")], &Rules::default(), &history);
        assert_eq!(rows[0].last_result, "works");
        assert_eq!(rows[0].last_checked, "1970-01-02");
        assert_eq!(rows[1].last_result, "");

        let rows = build(&[item("a.txt")], &Rules::default(), &history[..2]);
        assert_eq!(rows[0].last_result, "rejected");
    }

    #[test]
    fn a_key_gets_a_recipe_only_if_you_name_one_or_its_prefix_proves_it() {
        let mut proven = item("a.txt");
        proven.kinds = vec!["github".into()];
        let mut env = item("c.env");
        env.format = "env".into();
        env.kinds = vec!["github".into()];
        let mut mixed = item("d.txt");
        mixed.kinds = vec!["github".into(), "gitlab".into()];
        let rows = build(
            &[proven, item("b-stripe.txt"), env, mixed, item("e.env")],
            &rules(
                r#"
rules: [{ match: [stripe], tags: [provider:stripe] }]
files: { e.env: { recipes: [meta, instagram], field: TOKEN } }
"#,
            ),
            &[],
        );
        assert_eq!(rows[0].recipes, ["github"]);
        assert!(rows[1].recipes.is_empty(), "a tag is not proof");
        assert!(
            rows[2].recipes.is_empty(),
            "which value in the file is unknown"
        );
        assert!(rows[3].recipes.is_empty(), "two providers in one file");
        assert_eq!(rows[4].recipes, ["meta", "instagram"]);
        assert_eq!(rows[4].field, "TOKEN");
    }

    #[test]
    fn an_edit_from_the_app_comes_last_and_replaces() {
        let mut with_rules = rules(
            r#"
rules: [{ match: [deploy], tags: [ops], level: never }]
files: { deploy.key: { recipes: [github] } }
"#,
        );
        with_rules.edits = parse_edits(
            r#"{"deploy.key":{"tags":["mine"],"level":"free","recipes":[],"field":"TOKEN"}}"#,
        )
        .unwrap();
        let rows = build(
            &[item("deploy.key"), item("deploy.other")],
            &with_rules,
            &[],
        );
        assert_eq!(rows[0].tags, ["mine"]);
        assert_eq!(rows[0].level, Level::Free);
        assert!(rows[0].recipes.is_empty());
        assert_eq!(rows[0].field, "TOKEN");
        assert_eq!(rows[1].level, Level::Never);
        assert_eq!(rows[1].tags, ["ops"]);
        assert!(parse_edits(r#"{"a":{"level":"sometimes"}}"#).is_err());
    }

    #[test]
    fn an_empty_field_in_an_edit_never_takes_away_the_field_of_the_rules() {
        let mut with_rules = rules(
            r#"
rules: []
files: { gsc.json: { recipes: [google], field: "client_id+client_secret+refresh_token" } }
"#,
        );
        with_rules.edits =
            parse_edits(r#"{"gsc.json":{"field":"","description":"Search Console"}}"#).unwrap();
        let rows = build(&[item("gsc.json")], &with_rules, &[]);
        assert_eq!(rows[0].field, "client_id+client_secret+refresh_token");
        assert_eq!(rows[0].description, "Search Console");
    }

    #[test]
    fn the_day_a_key_expires_is_kept_only_as_a_day() {
        let mut with_rules = rules("rules: []");
        with_rules.edits = parse_edits(
            r#"{"a.txt":{"expires":"2026-12-31"},"b.txt":{"expires":"next week"},"c.txt":{"expires":"2026-13-01"}}"#,
        )
        .unwrap();
        let rows = build(
            &[item("a.txt"), item("b.txt"), item("c.txt")],
            &with_rules,
            &[],
        );
        assert_eq!(rows[0].expires, "2026-12-31");
        assert!(rows[1].expires.is_empty() && rows[2].expires.is_empty());
        let csv = to_csv(&rows[..1]);
        assert!(csv.lines().next().unwrap().ends_with(",expires"));
        assert!(csv.lines().nth(1).unwrap().ends_with(",2026-12-31"));
    }

    #[test]
    fn criticality_takes_the_highest_rule_and_an_edit_has_the_last_word() {
        let mut with_rules = rules(
            r#"
rules:
  - { match: [prod], criticality: 3 }
  - { match: [pay], criticality: 5 }
files: { fixed.txt: { criticality: 2 } }
"#,
        );
        with_rules.edits = parse_edits(r#"{"edited-pay.txt":{"criticality":1}}"#).unwrap();
        let rows = build(
            &[
                item("prod-pay.txt"),
                item("prod.txt"),
                item("fixed.txt"),
                item("edited-pay.txt"),
                item("other.txt"),
            ],
            &with_rules,
            &[],
        );
        let levels: Vec<u8> = rows.iter().map(|row| row.criticality).collect();
        assert_eq!(levels, [5, 3, 2, 1, 0]);

        let rated =
            rules("files: { a: { recipes: [stripe] }, b: { recipes: [stripe], criticality: 1 } }");
        let rows = build(&[item("a"), item("b")], &rated, &[]);
        assert_eq!(
            (
                rows[0].criticality,
                rows[0].criticality_suggested,
                rows[0].rotate_days
            ),
            (5, true, 180)
        );
        assert_eq!(
            (rows[1].criticality, rows[1].criticality_suggested),
            (1, false)
        );
    }

    #[test]
    fn moved_files_join_once_and_in_order() {
        let item =
            |path: &str| format!(r#"{{"path":"{path}","modified":0,"mode":null,"format":"env"}}"#);
        let mut items =
            parse_inventory(&format!(r#"{{"schema":1,"items":[{}]}}"#, item("a.env"))).unwrap();
        let ledger =
            std::env::temp_dir().join(format!("keyreeve-moved-{}.json", std::process::id()));
        std::fs::write(
            &ledger,
            format!(
                r#"{{"schema":1,"items":[{},{},{},{}]}}"#,
                item("b.env"),
                item("a.env"),
                item("c.env"),
                item("b.env")
            ),
        )
        .unwrap();
        add_moved(&mut items, &ledger).unwrap();
        std::fs::remove_file(&ledger).unwrap();
        let paths: Vec<&str> = items.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(paths, ["a.env", "b.env", "c.env"]);
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
