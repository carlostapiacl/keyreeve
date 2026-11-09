//! `keys.toml`, the one place that says what each key is.
//!
//! A key is an identifier with its metadata: provider, field, account, description, level, server, the
//! day it ends and whether it is archived. The file it came from is only where it came from. The file
//! holds no value: values stay sealed in the vault.
//!
//! The first version of this file named only the keys agents could use. `schema = 2` marks a book that
//! holds every key, written by `keyreeve migrate`. Only such a book is read by the catalog, so a book of
//! the first version changes nothing it did not change before.

use crate::catalog::Level;
use std::fmt::Write as _;

/// The schema written by `keyreeve migrate` and read by the catalog.
pub const SCHEMA: u32 = 2;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyBook {
    /// 1 for a book of agents' keys only, 2 for a book of every key.
    pub schema: u32,
    pub keys: Vec<BookKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookKey {
    pub id: String,
    /// The file it came from, as the inventory names it.
    pub source: String,
    /// The label or JSON path that holds the key, in a file with several values.
    pub field: Option<String>,
    /// The labels of a key made of several parts, in order, such as `client_id` and `secret`. A book of
    /// the first version wrote them joined with `+` in `field`; they are read into here.
    pub parts: Option<Vec<String>>,
    /// How the key is used: `static` (the default, a value sent as it is) or `oauth` (a client and a
    /// refresh token kept sealed, from which a short access token is made for each use). Only `static`
    /// works today; `oauth` is kept here so a book need not change again when it does.
    pub auth: Option<Auth>,
    /// `reauthorize` when the provider no longer accepts the grant and a person must sign in again.
    pub state: Option<KeyState>,
    pub provider: Option<String>,
    /// Recipes that may check it, when more than its provider's.
    pub recipes: Option<Vec<String>>,
    pub project: Option<String>,
    pub account: Option<String>,
    pub description: Option<String>,
    pub name: Option<String>,
    pub variable: Option<String>,
    /// SSH server fingerprints, separated by spaces, as the first version wrote them.
    pub servers: Option<String>,
    pub level: Option<Level>,
    pub tags: Option<Vec<String>>,
    /// The person's own server, for a provider each person runs.
    pub host: Option<String>,
    /// `yyyy-mm-dd`.
    pub expires: Option<String>,
    /// 1 to 5, as the person rated it.
    pub criticality: Option<u8>,
    pub archived: bool,
    /// False until a person gives the key to agents. The app lists only keys offered to agents.
    pub offered: bool,
}

impl BookKey {
    pub fn new(id: &str, source: &str) -> Self {
        Self {
            id: id.to_owned(),
            source: source.to_owned(),
            field: None,
            parts: None,
            auth: None,
            state: None,
            provider: None,
            recipes: None,
            project: None,
            account: None,
            description: None,
            name: None,
            variable: None,
            servers: None,
            level: None,
            tags: None,
            host: None,
            expires: None,
            criticality: None,
            archived: false,
            offered: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    Static,
    Oauth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Active,
    Reauthorize,
}

impl BookKey {
    /// The field as the rest of keyreeve names it: one label, or the parts joined with `+`.
    pub fn field_text(&self) -> Option<String> {
        match &self.parts {
            Some(parts) if !parts.is_empty() => Some(parts.join("+")),
            _ => self.field.clone().filter(|f| !f.is_empty()),
        }
    }

    /// Takes a field as the rest of keyreeve writes it: `a+b` becomes two parts.
    pub fn set_field(&mut self, text: &str) {
        if text.contains('+') {
            self.parts = Some(text.split('+').map(str::to_owned).collect());
            self.field = None;
        } else {
            self.field = Some(text.to_owned());
            self.parts = None;
        }
    }
}

const NAMES: &[&str] = &[
    "id",
    "source",
    "field",
    "parts",
    "auth",
    "state",
    "provider",
    "recipes",
    "project",
    "account",
    "description",
    "name",
    "variable",
    "servers",
    "level",
    "tags",
    "host",
    "expires",
    "criticality",
    "archived",
    "offered",
];

enum Value {
    Text(String),
    List(Vec<String>),
    Flag(bool),
    Number(u32),
}

impl KeyBook {
    /// The key a catalog row takes its metadata from: the first by identifier among those from `source`.
    pub fn for_source(&self, source: &str) -> Option<&BookKey> {
        self.keys.iter().find(|key| key.source == source)
    }

    pub fn has_id(&self, id: &str) -> bool {
        self.keys.iter().any(|key| key.id == id)
    }

    /// Reads the part of TOML this file uses and calls anything else an error, since a guess could
    /// send one key where another was meant.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut book = Self {
            schema: 1,
            keys: Vec::new(),
        };
        let mut current: Option<BookKey> = None;
        let mut seen_names: Vec<String> = Vec::new();
        for (number, raw) in text.lines().enumerate() {
            let line = raw.trim();
            let bad = || {
                format!(
                    "keys.toml, line {}, is not something this reads",
                    number + 1
                )
            };
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "[[key]]" {
                if let Some(done) = current.take() {
                    book.push(done)?;
                }
                current = Some(BookKey::new("", ""));
                seen_names.clear();
                continue;
            }
            let (name, rest) = line.split_once('=').ok_or_else(bad)?;
            let name = name.trim();
            let value = parse_value(rest.trim()).ok_or_else(bad)?;
            let Some(key) = current.as_mut() else {
                match (name, value) {
                    ("schema", Value::Number(schema)) => book.schema = schema,
                    _ => return Err(bad()),
                }
                continue;
            };
            if !NAMES.contains(&name) || seen_names.iter().any(|seen| seen == name) {
                return Err(bad());
            }
            seen_names.push(name.to_owned());
            set(key, name, value).ok_or_else(bad)?;
        }
        if let Some(done) = current.take() {
            book.push(done)?;
        }
        book.keys.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(book)
    }

    fn push(&mut self, key: BookKey) -> Result<(), String> {
        if key.id.is_empty() || key.source.is_empty() {
            return Err("each [[key]] in keys.toml needs an id and a source".into());
        }
        if !valid_id(&key.id) {
            return Err(format!(
                "{} is not an identifier: lower case letters, digits and dashes",
                key.id
            ));
        }
        if self.has_id(&key.id) {
            return Err(format!("{} is in keys.toml twice", key.id));
        }
        if key.field.is_some() && key.parts.is_some() {
            return Err(format!(
                "{} names a field and parts: one or the other",
                key.id
            ));
        }
        self.keys.push(key);
        Ok(())
    }

    /// The file as it is written: the same book always gives the same text.
    pub fn to_toml(&self) -> String {
        let mut out = String::from(
            "# Your keys by identifier. This file holds no value. Edit it in the app, or here.\n",
        );
        if self.schema >= SCHEMA {
            let _ = writeln!(out, "schema = {}", self.schema);
        }
        let mut keys: Vec<&BookKey> = self.keys.iter().collect();
        keys.sort_by(|a, b| a.id.cmp(&b.id));
        for key in keys {
            out.push_str("\n[[key]]\n");
            text(&mut out, "id", Some(&key.id));
            text(&mut out, "description", key.description.as_ref());
            text(&mut out, "name", key.name.as_ref());
            text(&mut out, "provider", key.provider.as_ref());
            list(&mut out, "recipes", key.recipes.as_ref());
            text(&mut out, "project", key.project.as_ref());
            text(&mut out, "account", key.account.as_ref());
            text(&mut out, "source", Some(&key.source));
            text(&mut out, "field", key.field.as_ref());
            list(&mut out, "parts", key.parts.as_ref());
            let auth = key.auth.map(|auth| match auth {
                Auth::Static => "static".to_owned(),
                Auth::Oauth => "oauth".to_owned(),
            });
            text(&mut out, "auth", auth.as_ref());
            let state = key.state.map(|state| match state {
                KeyState::Active => "active".to_owned(),
                KeyState::Reauthorize => "reauthorize".to_owned(),
            });
            text(&mut out, "state", state.as_ref());
            text(&mut out, "variable", key.variable.as_ref());
            text(&mut out, "servers", key.servers.as_ref());
            let level = key.level.map(|level| level.to_string());
            text(&mut out, "level", level.as_ref());
            list(&mut out, "tags", key.tags.as_ref());
            text(&mut out, "host", key.host.as_ref());
            text(&mut out, "expires", key.expires.as_ref());
            if let Some(criticality) = key.criticality {
                let _ = writeln!(out, "criticality = {criticality}");
            }
            if key.archived {
                out.push_str("archived = true\n");
            }
            if !key.offered {
                out.push_str("offered = false\n");
            }
        }
        out
    }
}

fn set(key: &mut BookKey, name: &str, value: Value) -> Option<()> {
    match (name, value) {
        ("id", Value::Text(v)) => key.id = v,
        ("source", Value::Text(v)) => key.source = v,
        ("field", Value::Text(v)) => key.set_field(&v),
        ("parts", Value::List(v)) if v.len() > 1 && v.iter().all(|p| !p.is_empty()) => {
            key.parts = Some(v)
        }
        ("auth", Value::Text(v)) => {
            key.auth = Some(match v.as_str() {
                "static" => Auth::Static,
                "oauth" => Auth::Oauth,
                _ => return None,
            });
        }
        ("state", Value::Text(v)) => {
            key.state = Some(match v.as_str() {
                "active" => KeyState::Active,
                "reauthorize" => KeyState::Reauthorize,
                _ => return None,
            });
        }
        ("provider", Value::Text(v)) => key.provider = Some(v),
        ("recipes", Value::List(v)) => key.recipes = Some(v),
        ("project", Value::Text(v)) => key.project = Some(v),
        ("account", Value::Text(v)) => key.account = Some(v),
        ("description", Value::Text(v)) => key.description = Some(v),
        ("name", Value::Text(v)) => key.name = Some(v),
        ("variable", Value::Text(v)) => key.variable = Some(v),
        ("servers", Value::Text(v)) => key.servers = Some(v),
        ("level", Value::Text(v)) => key.level = Some(level(&v)?),
        ("tags", Value::List(v)) => key.tags = Some(v),
        ("host", Value::Text(v)) => key.host = Some(v),
        ("expires", Value::Text(v)) => key.expires = Some(v),
        ("criticality", Value::Number(v)) => key.criticality = Some(u8::try_from(v).ok()?.min(5)),
        ("archived", Value::Flag(v)) => key.archived = v,
        ("offered", Value::Flag(v)) => key.offered = v,
        _ => return None,
    }
    Some(())
}

fn level(text: &str) -> Option<Level> {
    match text {
        "none" => Some(Level::None),
        "free" => Some(Level::Free),
        "ask" => Some(Level::Ask),
        "never" => Some(Level::Never),
        _ => None,
    }
}

/// Lower case letters, digits and single dashes, neither first nor last, at most 64 characters.
pub fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `Mi clave de correo` is `mi-clave-de-correo`: lower case ASCII letters, digits and single dashes.
pub fn slug(text: &str) -> String {
    let mapped: String = text
        .to_lowercase()
        .chars()
        .map(fold)
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    mapped
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn fold(c: char) -> char {
    match c {
        'á' | 'à' | 'ä' | 'â' => 'a',
        'é' | 'è' | 'ë' | 'ê' => 'e',
        'í' | 'ì' | 'ï' | 'î' => 'i',
        'ó' | 'ò' | 'ö' | 'ô' => 'o',
        'ú' | 'ù' | 'ü' | 'û' => 'u',
        'ñ' => 'n',
        'ç' => 'c',
        other => other,
    }
}

fn parse_value(text: &str) -> Option<Value> {
    let (value, rest) = if let Some(after) = text.strip_prefix('"') {
        let (s, rest) = quoted(after)?;
        (Value::Text(s), rest)
    } else if let Some(mut rest) = text.strip_prefix('[') {
        let mut items = Vec::new();
        loop {
            rest = rest.trim_start();
            if let Some(after) = rest.strip_prefix(']') {
                rest = after;
                break;
            }
            let (item, after) = quoted(rest.strip_prefix('"')?)?;
            items.push(item);
            rest = after.trim_start();
            if let Some(after) = rest.strip_prefix(',') {
                rest = after;
            } else if !rest.starts_with(']') {
                return None;
            }
        }
        (Value::List(items), rest)
    } else {
        let end = text
            .find(|c: char| c.is_whitespace() || c == '#')
            .unwrap_or(text.len());
        let (word, rest) = text.split_at(end);
        let value = match word {
            "true" => Value::Flag(true),
            "false" => Value::Flag(false),
            number => Value::Number(number.parse().ok()?),
        };
        (value, rest)
    };
    let rest = rest.trim_start();
    (rest.is_empty() || rest.starts_with('#')).then_some(value)
}

/// A TOML basic string after its opening quote, and the text after its closing one.
fn quoted(text: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Some((out, &text[at + 1..])),
            '\\' => match chars.next()?.1 {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                _ => return None,
            },
            other => out.push(other),
        }
    }
    None
}

fn escaped(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn text(out: &mut String, name: &str, value: Option<&String>) {
    if let Some(value) = value {
        let _ = writeln!(out, "{name} = \"{}\"", escaped(value));
    }
}

fn list(out: &mut String, name: &str, value: Option<&Vec<String>>) {
    if let Some(items) = value {
        let quoted: Vec<String> = items
            .iter()
            .map(|item| format!("\"{}\"", escaped(item)))
            .collect();
        let _ = writeln!(out, "{name} = [{}]", quoted.join(", "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_VERSION: &str = r#"# Your keys by identifier. This file holds no value. Edit it in the app, or here.

[[key]]
id = "calcom"
provider = "calcom"
project = "a-project"
account = "someone@example.com"
source = "cal.json"
field = "key"
variable = "CALCOM_API_KEY"

[[key]]
id = "google"
provider = "google"
source = "gsc-token.json"
field = "client_id+client_secret+refresh_token"
"#;

    #[test]
    fn a_book_of_the_first_version_reads_as_schema_one() {
        let book = KeyBook::parse(FIRST_VERSION).unwrap();
        assert_eq!(book.schema, 1);
        assert_eq!(book.keys.len(), 2);
        let google = book.for_source("gsc-token.json").unwrap();
        assert_eq!(google.field, None);
        assert_eq!(
            google.parts,
            Some(vec![
                "client_id".into(),
                "client_secret".into(),
                "refresh_token".into()
            ])
        );
        assert_eq!(
            google.field_text().as_deref(),
            Some("client_id+client_secret+refresh_token")
        );
        assert!(google.offered);
    }

    #[test]
    fn every_part_survives_writing_and_reading_again() {
        let mut key = BookKey::new("paypal-lh", "paypal-lh.json");
        key.set_field("client_id+secret");
        key.auth = Some(Auth::Oauth);
        key.state = Some(KeyState::Reauthorize);
        key.provider = Some("paypal".into());
        key.recipes = Some(vec!["paypal".into()]);
        key.description = Some("PayPal \"de\" LH\nsegunda línea".into());
        key.level = Some(Level::Never);
        key.tags = Some(vec!["liquidity-hunters".into(), "provider:paypal".into()]);
        key.host = Some("panel.example.com:8443".into());
        key.expires = Some("2027-02-08".into());
        key.criticality = Some(5);
        key.archived = true;
        key.offered = false;
        let book = KeyBook {
            schema: SCHEMA,
            keys: vec![key],
        };
        let text = book.to_toml();
        let read = KeyBook::parse(&text).unwrap();
        assert_eq!(read, book);
        assert_eq!(read.to_toml(), text);
    }

    #[test]
    fn unknown_names_twice_named_parts_and_bad_values_are_refused() {
        assert!(KeyBook::parse("[[key]]\nid = \"a\"\nsource = \"a\"\nvalue = \"x\"\n").is_err());
        assert!(KeyBook::parse("[[key]]\nid = \"a\"\nid = \"b\"\nsource = \"a\"\n").is_err());
        assert!(
            KeyBook::parse("[[key]]\nid = \"a\"\nsource = \"a\"\nlevel = \"sometimes\"\n").is_err()
        );
        assert!(KeyBook::parse("[[key]]\nid = \"A b\"\nsource = \"a\"\n").is_err());
        assert!(KeyBook::parse(
            "[[key]]\nid = \"a\"\nsource = \"a\"\n[[key]]\nid = \"a\"\nsource = \"b\"\n"
        )
        .is_err());
        assert!(KeyBook::parse("other = 1\n").is_err());
        assert!(KeyBook::parse("[[key]]\nid = \"a\"\nsource = \"a\"\nauth = \"magic\"\n").is_err());
        assert!(KeyBook::parse(
            "[[key]]\nid = \"a\"\nsource = \"a\"\nfield = \"x\"\nparts = [\"a\", \"b\"]\n"
        )
        .is_err());
        assert!(KeyBook::parse("[[key]]\nid = \"a\"\nsource = \"a\"\nparts = [\"a\"]\n").is_err());
    }

    #[test]
    fn slugs_and_identifiers() {
        assert_eq!(slug("Mi clave de Correo"), "mi-clave-de-correo");
        assert_eq!(slug("Año.ñandú"), "ano-nandu");
        assert!(valid_id("meta-lh"));
        assert!(!valid_id("-a"));
        assert!(!valid_id("a_b"));
    }
}
