//! Moves what is known of each key into `keys.toml`, so that one file says what a key is.
//!
//! Today a key is a path described by the rules, the app's edits, the provider's answer and, for the
//! keys agents use, an identifier in `keys.toml`. This reads all of them as the catalog does, and writes
//! a book with one entry per key: the identifiers it had keep their name and what they said, and only
//! what they lacked is filled; every other file gets an identifier of its own, not offered to agents.
//! Nothing is taken away: the files it read stay where they are, and a copy of each goes to a folder
//! of its own first. Run twice, it changes nothing the second time.

use crate::catalog::Row;
use crate::keybook::{self, BookKey, KeyBook, SCHEMA};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// The files read, copied before `keys.toml` is written.
pub const READ: &[&str] = &[
    "keys.toml",
    "rules.yaml",
    "edits.json",
    "details.json",
    "catalog.csv",
    "inventory.json",
    "moved.json",
];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Identifiers that were there, kept with their name.
    pub kept: usize,
    /// Of those, how many gained something they lacked.
    pub filled: usize,
    /// Files that had no identifier and got one, not offered to agents.
    pub added: Vec<String>,
    /// Identifiers whose provider differs from the recipes the list checks the file with.
    pub differ: Vec<String>,
    /// Identifiers that point to an archived file.
    pub archived: Vec<String>,
    /// Identifiers whose file is not on the list, so nothing could be added to them.
    pub missing: Vec<String>,
    /// Identifiers whose own description differs from the one the app wrote for their file. The
    /// identifier's is kept, since it is the one agents read.
    pub described_apart: Vec<String>,
    /// True when `keys.toml` already said all of it.
    pub unchanged: bool,
    /// Where the files read were copied, when something was written.
    pub backup: Option<PathBuf>,
}

/// What the provider said of each file, from `details.json`: only the account is kept here.
fn accounts(text: &str) -> HashMap<String, String> {
    let Ok(serde_json::Value::Object(all)) = serde_json::from_str(text) else {
        return HashMap::new();
    };
    all.into_iter()
        .filter_map(|(path, entry)| {
            let account = entry
                .get("fields")?
                .get("account")?
                .as_str()?
                .trim()
                .to_owned();
            (!account.is_empty()).then_some((path, account))
        })
        .collect()
}

/// The new book, from the book there was, the list as the catalog builds it and the providers' accounts.
pub fn plan(old: &KeyBook, rows: &[Row], accounts: &HashMap<String, String>) -> (KeyBook, Report) {
    let mut report = Report::default();
    let mut book = KeyBook {
        schema: SCHEMA,
        keys: old.keys.clone(),
    };
    let by_path: BTreeMap<&str, &Row> = rows.iter().map(|row| (row.path.as_str(), row)).collect();
    let mut sharing: HashMap<String, usize> = HashMap::new();
    for key in &book.keys {
        *sharing.entry(key.source.clone()).or_default() += 1;
    }
    for key in &mut book.keys {
        report.kept += 1;
        let Some(row) = by_path.get(key.source.as_str()) else {
            report.missing.push(key.id.clone());
            continue;
        };
        if let Some(own) = &key.description {
            if !row.description.is_empty() && *own != row.description {
                report.described_apart.push(key.id.clone());
            }
        }
        let before = key.clone();
        let alone = sharing.get(&key.source).copied().unwrap_or(0) == 1;
        fill(key, row, accounts.get(&row.path), alone);
        if *key != before {
            report.filled += 1;
        }
        if let Some(provider) = &key.provider {
            if !row.recipes.is_empty() && !row.recipes.contains(provider) {
                report.differ.push(key.id.clone());
            }
        }
        if key.archived {
            report.archived.push(key.id.clone());
        }
    }
    for row in rows {
        if book.keys.iter().any(|key| key.source == row.path) {
            continue;
        }
        let id = identifier(&book, row);
        let mut key = BookKey::new(&id, &row.path);
        key.offered = false;
        fill(&mut key, row, accounts.get(&row.path), true);
        report.added.push(id);
        book.keys.push(key);
    }
    book.keys.sort_by(|a, b| a.id.cmp(&b.id));
    report.unchanged = old.schema >= SCHEMA && book == *old;
    (book, report)
}

/// Fills what `key` lacks from the list. Provider, recipes and field are taken only when no other
/// identifier shares the file, since two identifiers on one file are two different keys.
fn fill(key: &mut BookKey, row: &Row, account: Option<&String>, alone: bool) {
    let some = |text: &str| (!text.is_empty()).then(|| text.to_owned());
    if key.provider.is_none() && alone {
        key.provider = row.recipes.first().cloned();
    }
    if key.recipes.is_none() && alone && !row.recipes.is_empty() {
        let only_provider = row.recipes.len() == 1 && key.provider.as_ref() == row.recipes.first();
        if !only_provider {
            key.recipes = Some(row.recipes.clone());
        }
    }
    if key.field_text().is_none() && alone && !row.field.is_empty() {
        key.set_field(&row.field);
    }
    if key.account.is_none() {
        key.account = account.cloned();
    }
    if key.description.is_none() {
        key.description = some(&row.description);
    }
    if key.name.is_none() {
        key.name = some(&row.name);
    }
    if key.level.is_none() {
        key.level = Some(row.level);
    }
    if key.tags.is_none() {
        key.tags = Some(row.tags.clone());
    }
    if key.host.is_none() {
        key.host = some(&row.host);
    }
    if key.expires.is_none() {
        key.expires = some(&row.expires);
    }
    if key.criticality.is_none() && row.criticality > 0 && !row.criticality_suggested {
        key.criticality = Some(row.criticality);
    }
    if row.tags.iter().any(|tag| tag == "status:archived") {
        key.archived = true;
    }
}

/// A free identifier for a file: its name when it already says the provider, else the provider and
/// its name, with a number if taken.
fn identifier(book: &KeyBook, row: &Row) -> String {
    let file = Path::new(&row.path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&row.path);
    let stem = keybook::slug(
        file.split('.')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(file),
    );
    let provider = row
        .recipes
        .first()
        .map(|p| keybook::slug(p))
        .unwrap_or_default();
    let base = if provider.is_empty() || stem.contains(&provider) {
        stem
    } else if stem.is_empty() {
        provider
    } else {
        format!("{provider}-{stem}")
    };
    let base = shorten(if base.is_empty() { "key".into() } else { base });
    if !book.has_id(&base) && keybook::valid_id(&base) {
        return base;
    }
    let mut number = 2;
    loop {
        let candidate = format!("{base}-{number}");
        if !book.has_id(&candidate) {
            return candidate;
        }
        number += 1;
    }
}

fn shorten(text: String) -> String {
    let cut: String = text.chars().take(40).collect();
    cut.trim_matches('-').to_owned()
}

/// Reads the private folder `home`, and writes the new `keys.toml` unless `dry_run`. Before writing, each
/// file read is copied to `home/backups/one-source-<now>/`.
pub fn run(home: &Path, now: u64, dry_run: bool) -> Result<Report, String> {
    let old = match fs::read_to_string(home.join("keys.toml")) {
        Ok(text) => KeyBook::parse(&text)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => KeyBook::default(),
        Err(e) => return Err(format!("keys.toml: {e}")),
    };
    let rows = crate::schedule::rows(home)?;
    let accounts = accounts(&fs::read_to_string(home.join("details.json")).unwrap_or_default());
    let (book, mut report) = plan(&old, &rows, &accounts);
    if report.unchanged || dry_run {
        return Ok(report);
    }
    let backup = home.join("backups").join(format!("one-source-{now}"));
    if backup.exists() {
        return Err(format!("{} is already there", backup.display()));
    }
    crate::inventory::create_private_dir(&backup)
        .map_err(|e| format!("{}: {e}", backup.display()))?;
    for name in READ {
        let from = home.join(name);
        if from.exists() {
            // Byte for byte, and as private as the files themselves.
            let to = backup.join(name);
            fs::copy(&from, &to).map_err(|e| format!("{name}: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&to, fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("{name}: {e}"))?;
            }
        }
    }
    let temporary = home.join("keys.toml.writing");
    // It ends the text with a line break of its own, and the app writes the book with exactly one.
    let text = book.to_toml();
    crate::inventory::write_private(&temporary, text.strip_suffix('\n').unwrap_or(&text))
        .map_err(|e| format!("keys.toml: {e}"))?;
    fs::rename(&temporary, home.join("keys.toml")).map_err(|e| format!("keys.toml: {e}"))?;
    report.backup = Some(backup);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{self, parse_edits, parse_inventory, parse_rules, Level};

    /// A list with the shapes of a real one, and none of its names or values: a file with a combined
    /// field, a `.env` with a token and a chat id, an archived copy, a server of one's own, a day it ends,
    /// two identifiers on one file, an identifier on an archived file, a document and a public key.
    const INVENTORY: &str = r#"{"schema":1,"items":[
 {"path":"gsc-token.json","modified":1,"format":"json","fields":["client_id","client_secret","refresh_token","token"],"kinds":[]},
 {"path":"youtube_token.json","modified":1,"format":"json","fields":["client_id","client_secret","refresh_token"],"kinds":[]},
 {"path":"paypal-lh.json","modified":1,"format":"json","fields":["api_base","client_id","secret"],"kinds":[]},
 {"path":"telegram-agentes.env","modified":1,"format":"env","fields":["TELEGRAM_BOT_TOKEN","TELEGRAM_CHAT_ID"],"kinds":["telegram"]},
 {"path":"inbox-ig-token.txt","modified":1,"format":"single-value","fields":[],"kinds":[]},
 {"path":"coolify.env","modified":1,"format":"env","fields":["COOLIFY_TOKEN"],"kinds":[]},
 {"path":"calcom-carlos.txt","modified":1,"format":"single-value","fields":[],"kinds":["calcom"]},
 {"path":"asistente-cobros.env","modified":1,"format":"env","fields":["MP_ACCESS_TOKEN","PAYPAL_CLIENT_ID","PAYPAL_SECRET"],"kinds":[]},
 {"path":"meta-old-2026.txt","modified":1,"format":"single-value","fields":[],"kinds":[]},
 {"path":"meta-new.txt","modified":1,"format":"single-value","fields":[],"kinds":[]},
 {"path":"RUNBOOK.md","modified":1,"format":"text","fields":[],"kinds":[]},
 {"path":"deploy.pub","modified":1,"format":"single-value","fields":[],"kinds":[]},
 {"path":"resend-yumo.txt","modified":1,"format":"single-value","fields":[],"kinds":["resend"]}
]}"#;

    const RULES: &str = r#"
rules:
  - { match: [paypal], level: never }
files:
  "gsc-token.json": { recipes: [google], field: "client_id+client_secret+refresh_token" }
  "telegram-agentes.env": { recipes: [telegram], field: TELEGRAM_BOT_TOKEN }
  "RUNBOOK.md": { tags: [status:doc] }
"#;

    const EDITS: &str = r#"{
 "gsc-token.json": {"field": "", "description": "Search Console del portfolio"},
 "youtube_token.json": {"recipes": ["google"], "field": "client_id+client_secret+refresh_token"},
 "paypal-lh.json": {"recipes": ["paypal"], "field": "client_id+secret", "description": "PayPal de LH"},
 "inbox-ig-token.txt": {"recipes": ["instagram"]},
 "coolify.env": {"recipes": ["coolify-panel"], "host": "panel.example.com"},
 "calcom-carlos.txt": {"recipes": ["calcom"], "expires": "2027-02-08", "criticality": 2},
 "meta-old-2026.txt": {"recipes": ["meta"], "tags": ["status:archived"], "description": "Copia rechazada"},
 "meta-new.txt": {"recipes": ["meta"]},
 "resend-yumo.txt": {"recipes": ["resend"], "description": "Resend de Yumo", "name": "Resend · yumo"}
}"#;

    const BOOK: &str = r#"
[[key]]
id = "google"
provider = "google"
source = "gsc-token.json"
field = "client_id+client_secret+refresh_token"

[[key]]
id = "telegram"
provider = "telegram"
account = "a_bot"
source = "telegram-agentes.env"
field = "TELEGRAM_BOT_TOKEN"
variable = "TELEGRAM_BOT_TOKEN"

[[key]]
id = "ig-inbox"
provider = "instagram"
source = "inbox-ig-token.txt"
variable = "IG_ACCESS_TOKEN"

[[key]]
id = "meta-carlostapia"
provider = "meta"
source = "meta-old-2026.txt"

[[key]]
id = "cobros-mp"
provider = "mercadopago"
source = "asistente-cobros.env"
field = "MP_ACCESS_TOKEN"

[[key]]
id = "cobros-paypal"
provider = "paypal"
source = "asistente-cobros.env"
field = "PAYPAL_CLIENT_ID+PAYPAL_SECRET"
"#;

    fn rows(book: Option<&KeyBook>) -> Vec<Row> {
        let items = parse_inventory(INVENTORY).unwrap();
        let mut rules = parse_rules(RULES).unwrap();
        rules.edits = parse_edits(EDITS).unwrap();
        rules.book = book.cloned();
        catalog::build(&items, &rules, &[])
    }

    fn details() -> HashMap<String, String> {
        accounts(
            r#"{"paypal-lh.json":{"fields":{"account":"lh@example.com"}},"calcom-carlos.txt":{"fields":{"account":" "}}}"#,
        )
    }

    #[test]
    fn every_file_gets_one_entry_and_nothing_known_is_lost() {
        let old = KeyBook::parse(BOOK).unwrap();
        let before = rows(None);
        let (book, report) = plan(&old, &before, &details());
        assert_eq!(book.schema, SCHEMA);
        assert_eq!(report.kept, 6);
        // Every file has at least one entry, and the identifiers there were are all still there.
        for row in &before {
            assert!(
                book.for_source(&row.path).is_some(),
                "{} has no entry",
                row.path
            );
        }
        for key in &old.keys {
            assert!(book.has_id(&key.id), "{} was lost", key.id);
        }
        // The list built from the new book alone says what the old sources said, file by file.
        let items = parse_inventory(INVENTORY).unwrap();
        let only_book = catalog::Rules {
            book: Some(book.clone()),
            ..Default::default()
        };
        let after = catalog::build(&items, &only_book, &[]);
        for (was, now) in before.iter().zip(&after) {
            assert_eq!(was.path, now.path);
            if was.path == "asistente-cobros.env" {
                // Two identifiers on one file: the list, which checks files, now checks it with the
                // field of the first. Before, it had none and could not check it at all.
                assert_eq!(was.field, "");
                assert_eq!(now.field, "MP_ACCESS_TOKEN");
                assert_eq!(now.recipes, vec!["mercadopago".to_string()]);
                continue;
            }
            assert_eq!(was.field, now.field, "{}: field", was.path);
            assert_eq!(was.recipes, now.recipes, "{}: recipes", was.path);
            assert_eq!(was.level, now.level, "{}: level", was.path);
            assert_eq!(was.tags, now.tags, "{}: tags", was.path);
            assert_eq!(
                was.description, now.description,
                "{}: description",
                was.path
            );
            assert_eq!(was.name, now.name, "{}: name", was.path);
            assert_eq!(was.host, now.host, "{}: host", was.path);
            assert_eq!(was.expires, now.expires, "{}: expires", was.path);
            assert_eq!(
                was.criticality, now.criticality,
                "{}: criticality",
                was.path
            );
        }
    }

    #[test]
    fn combined_fields_accounts_servers_and_archived_copies_are_kept() {
        let (book, report) = plan(&KeyBook::parse(BOOK).unwrap(), &rows(None), &details());
        let key = |id: &str| book.keys.iter().find(|k| k.id == id).unwrap().clone();
        assert_eq!(
            key("google").field_text().as_deref(),
            Some("client_id+client_secret+refresh_token")
        );
        assert_eq!(key("google").parts.as_ref().map(Vec::len), Some(3));
        assert_eq!(
            key("google").description.as_deref(),
            Some("Search Console del portfolio")
        );
        let youtube = book.for_source("youtube_token.json").unwrap();
        assert_eq!(
            youtube.field_text().as_deref(),
            Some("client_id+client_secret+refresh_token")
        );
        assert!(!youtube.offered);
        let paypal = book.for_source("paypal-lh.json").unwrap();
        assert_eq!(paypal.id, "paypal-lh");
        assert_eq!(
            paypal.parts,
            Some(vec!["client_id".into(), "secret".into()])
        );
        assert_eq!(paypal.account.as_deref(), Some("lh@example.com"));
        assert_eq!(paypal.level, Some(Level::Never));
        let coolify = book.for_source("coolify.env").unwrap();
        assert_eq!(coolify.host.as_deref(), Some("panel.example.com"));
        let calcom = book.for_source("calcom-carlos.txt").unwrap();
        assert_eq!(calcom.expires.as_deref(), Some("2027-02-08"));
        assert_eq!(calcom.criticality, Some(2));
        assert_eq!(calcom.account, None, "a blank account says nothing");
        // An identifier keeps its own provider and says when the list checks the file another way.
        assert_eq!(key("ig-inbox").provider.as_deref(), Some("instagram"));
        assert!(key("meta-carlostapia").archived);
        assert_eq!(report.archived, vec!["meta-carlostapia".to_string()]);
        // Two identifiers on one file keep their own fields: the file's is not pressed on either.
        assert_eq!(key("cobros-mp").field.as_deref(), Some("MP_ACCESS_TOKEN"));
        assert_eq!(
            key("cobros-paypal").field_text().as_deref(),
            Some("PAYPAL_CLIENT_ID+PAYPAL_SECRET")
        );
        // Identifiers there were stay offered to agents; the new ones wait for a person.
        assert!(key("telegram").offered && key("ig-inbox").offered);
        assert_eq!(
            key("telegram").variable.as_deref(),
            Some("TELEGRAM_BOT_TOKEN")
        );
        assert_eq!(key("telegram").account.as_deref(), Some("a_bot"));
        assert!(report.added.contains(&"resend-yumo".to_string()));
        assert!(report.added.contains(&"meta-new".to_string()));
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let (first, _) = plan(&KeyBook::parse(BOOK).unwrap(), &rows(None), &details());
        let text = first.to_toml();
        let again = KeyBook::parse(&text).unwrap();
        let (second, report) = plan(&again, &rows(Some(&again)), &details());
        assert!(report.unchanged);
        assert!(report.added.is_empty());
        assert_eq!(second.to_toml(), text);
    }

    #[test]
    fn a_book_of_the_first_version_changes_nothing_in_the_list() {
        let old = KeyBook::parse(BOOK).unwrap();
        assert_eq!(rows(Some(&old)), rows(None));
    }

    #[test]
    fn identifiers_are_new_free_and_valid() {
        let mut book = KeyBook::parse(BOOK).unwrap();
        let mut row = rows(None)
            .into_iter()
            .find(|r| r.path == "meta-new.txt")
            .unwrap();
        assert_eq!(identifier(&book, &row), "meta-new");
        book.keys.push(BookKey::new("meta-new", "elsewhere"));
        assert_eq!(identifier(&book, &row), "meta-new-2");
        row.path = "lab/Token de Ñandú.txt".into();
        row.recipes = vec!["github".into()];
        assert_eq!(identifier(&book, &row), "github-token-de-nandu");
    }

    #[test]
    fn running_it_copies_what_it_read_and_a_second_run_writes_nothing() {
        let home = std::env::temp_dir().join(format!("keyreeve-migrate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("inventory.json"), INVENTORY).unwrap();
        fs::write(home.join("rules.yaml"), RULES).unwrap();
        fs::write(home.join("edits.json"), EDITS).unwrap();
        fs::write(home.join("keys.toml"), BOOK).unwrap();
        let dry = run(&home, 100, true).unwrap();
        assert!(dry.backup.is_none());
        assert_eq!(fs::read_to_string(home.join("keys.toml")).unwrap(), BOOK);
        let report = run(&home, 100, false).unwrap();
        let backup = report.backup.unwrap();
        assert_eq!(fs::read_to_string(backup.join("keys.toml")).unwrap(), BOOK);
        assert_eq!(
            fs::read_to_string(backup.join("edits.json")).unwrap(),
            EDITS
        );
        assert_eq!(
            fs::read_to_string(home.join("edits.json")).unwrap(),
            EDITS,
            "edits stay"
        );
        let written = fs::read_to_string(home.join("keys.toml")).unwrap();
        assert!(written.contains("schema = 2"));
        assert_eq!(
            written,
            KeyBook::parse(&written).unwrap().to_toml(),
            "written as the app writes it"
        );
        let second = run(&home, 200, false).unwrap();
        assert!(second.unchanged && second.backup.is_none());
        assert_eq!(fs::read_to_string(home.join("keys.toml")).unwrap(), written);
        let _ = fs::remove_dir_all(&home);
    }
}
