//! Reads a key out of whatever holds it: a file, or a copy opened from the vault. Files come in many
//! shapes, and no error here quotes what it read.

use crate::inventory::{split_label, strip_comment};
use crate::recipe::{extract, Recipe};
use crate::secret::Secret;
use crate::ssh;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_KEY_FILE_BYTES: u64 = 1024 * 1024;
const MAX_SEALED_BYTES: u64 = 64 * 1024 * 1024;

/// Reads a key from a file: the whole file, or named fields of an env file, JSON, CSV or loose
/// notes. `A+B` joins two fields with `:`, for providers whose key has two parts.
pub fn read_key(text: &str, field: Option<&str>) -> Result<Secret, String> {
    let trimmed = text.trim().trim_start_matches('\u{FEFF}');
    let Some(field) = field else {
        if trimmed.is_empty() {
            return Err("the file is empty".into());
        }
        if trimmed.contains(char::is_whitespace) {
            return Err("the file holds more than one value, so name one with --field".into());
        }
        return Ok(Secret::new(trimmed));
    };
    let parts: Vec<Secret> = field
        .split('+')
        .map(|name| read_field(trimmed, name))
        .collect::<Result<_, _>>()?;
    if let [only] = parts.as_slice() {
        return Ok(only.clone());
    }
    let joined: Vec<&str> = parts.iter().map(Secret::expose).collect();
    Ok(Secret::new(joined.join(":")))
}

fn read_field(text: &str, field: &str) -> Result<Secret, String> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
        return extract(&json, &format!("$.{field}"))
            .map(Secret::new)
            .ok_or_else(|| format!("field {field} was not found"));
    }
    let mut lines = text.lines();
    if let (Some(head), Some(row)) = (lines.next(), lines.next()) {
        let cells = |line: &str| -> Vec<String> {
            line.split(',')
                .map(|c| c.trim().trim_matches('"').to_owned())
                .collect()
        };
        let names = cells(head);
        if let Some(index) = names
            .iter()
            .position(|name| name.eq_ignore_ascii_case(field))
        {
            let values = cells(row);
            if names.len() == values.len() && !values[index].is_empty() {
                return Ok(Secret::new(values[index].clone()));
            }
        }
    }
    for line in text.lines().map(str::trim) {
        if strip_comment(line).is_some() {
            continue;
        }
        if let Some((label, value)) = split_label(line) {
            if label == field {
                let value = value.trim().trim_matches(['"', '\'']);
                if value.is_empty() {
                    return Err(format!("field {field} is empty"));
                }
                return Ok(Secret::new(value));
            }
        }
    }
    Err(format!("field {field} was not found"))
}

/// Where a key's text comes from. A vault's copy reaches this program on stdin, and never through
/// an argument, a variable or a file it would have to leave behind.
pub enum KeySource<'a> {
    File(PathBuf),
    Text(&'a str),
}

impl KeySource<'_> {
    pub(crate) fn load(&self, field: Option<&str>, recipe: &Recipe) -> Result<Secret, String> {
        match self {
            Self::File(path) => load_key(path, field, recipe),
            Self::Text(text) => read_key_for(text, field, recipe),
        }
    }

    /// `ssh` reads a key from a file alone, so a vault's copy spends the call in a private one.
    pub(crate) fn greet(&self, recipe: &Recipe) -> Result<ssh::Reply, String> {
        match self {
            Self::File(path) => ssh::greet(recipe, path),
            Self::Text(text) => {
                let file = ssh::TempKey::write(text)?;
                ssh::greet(recipe, file.path())
            }
        }
    }
}

/// Copies of key files opened by whoever called this program, by their place in the keys folder.
#[derive(Default)]
pub struct Sealed(HashMap<String, Zeroizing<String>>);

impl Sealed {
    /// Reads `{"path": "text of the file"}`. Errors never quote the input.
    pub fn read(input: impl Read) -> Result<Self, String> {
        let mut text = Zeroizing::new(String::new());
        input
            .take(MAX_SEALED_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|_| "could not read the keys on stdin".to_owned())?;
        if text.len() as u64 > MAX_SEALED_BYTES {
            return Err("too many keys on stdin".into());
        }
        let parsed: HashMap<String, String> = serde_json::from_str(&text)
            .map_err(|_| "the keys on stdin are not in the expected form".to_owned())?;
        Ok(Self(
            parsed
                .into_iter()
                .map(|(path, value)| (path, Zeroizing::new(value)))
                .collect(),
        ))
    }

    /// The text sent for this name, if any.
    pub(crate) fn text(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|text| text.as_str())
    }

    pub(crate) fn source(&self, keys: &Path, file: &str) -> KeySource<'_> {
        match self.0.get(file) {
            Some(text) => KeySource::Text(text),
            None => KeySource::File(keys.join(file)),
        }
    }
}

pub(crate) fn load_key(
    path: &Path,
    field: Option<&str>,
    recipe: &Recipe,
) -> Result<Secret, String> {
    let shown = path.display();
    let size = fs::metadata(path)
        .map_err(|e| format!("{shown}: {}", e.kind()))?
        .len();
    if size > MAX_KEY_FILE_BYTES {
        return Err(format!("{shown}: too large for a key file"));
    }
    let text = fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("{shown}: {}", e.kind()))?;
    let text = std::str::from_utf8(&text).map_err(|_| format!("{shown}: not UTF-8 text"))?;
    read_key_for(text, field, recipe).map_err(|e| format!("{shown}: {e}"))
}

/// Like `read_key`, and in a file of notes it also finds the one word that starts with this
/// provider's prefix. With two candidates it refuses, because guessing could send the wrong key.
pub fn read_key_for(text: &str, field: Option<&str>, recipe: &Recipe) -> Result<Secret, String> {
    match read_key(text, field) {
        Ok(key) => Ok(key),
        Err(error) if field.is_some() || recipe.prefixes.is_empty() => Err(error),
        Err(error) => {
            let mut found: Vec<&str> = text
                .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
                .filter(|word| {
                    recipe
                        .prefixes
                        .iter()
                        .any(|prefix| word.starts_with(prefix.as_str()))
                })
                .collect();
            found.sort_unstable();
            found.dedup();
            match found.as_slice() {
                [only] => Ok(Secret::new(*only)),
                [] => Err(error),
                _ => Err(
                    "the file holds several keys of this provider, so name one with --field".into(),
                ),
            }
        }
    }
}

/// The shortest key that can rotate. Swapping text in a file needs a value too long to appear there
/// by accident.
pub(crate) const MIN_SWAP_CHARS: usize = 16;

fn part_of_a_word(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '+')
}

/// Replaces `old` where it stands alone. Inside a longer value it is another value, and is left as it
/// is, which also makes repeating this safe when the new key starts with the old one.
pub(crate) fn swap_key(text: &str, old: &str, new: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(old) {
        let before = rest[..at]
            .chars()
            .next_back()
            .or_else(|| out.chars().next_back());
        let after = rest[at + old.len()..].chars().next();
        out.push_str(&rest[..at]);
        if before.is_some_and(part_of_a_word) || after.is_some_and(part_of_a_word) {
            out.push_str(old);
        } else {
            out.push_str(new);
        }
        rest = &rest[at + old.len()..];
    }
    out.push_str(rest);
    out
}

/// True if `value` appears in `text` as a value of its own.
pub(crate) fn holds_key(text: &str, value: &str) -> bool {
    !value.is_empty() && swap_key(text, value, "\u{0}") != text
}

#[cfg(test)]
mod swap_tests {
    use super::*;

    #[test]
    fn only_the_whole_value_changes() {
        assert_eq!(
            swap_key("TOKEN=abc\nOTHER=abc123\nX=xabc\nY=abc\n", "abc", "new"),
            "TOKEN=new\nOTHER=abc123\nX=xabc\nY=new\n"
        );
        assert_eq!(swap_key("\"abc\" abc,abc", "abc", "n"), "\"n\" n,n");
    }

    #[test]
    fn repeating_with_a_key_that_starts_with_the_old_one_is_safe() {
        let once = swap_key("T=abc\n", "abc", "abcXYZ");
        assert_eq!(once, "T=abcXYZ\n");
        assert_eq!(swap_key(&once, "abc", "abcXYZ"), once);
    }

    #[test]
    fn holds_needs_the_value_on_its_own() {
        assert!(holds_key("T=abc\n", "abc"));
        assert!(!holds_key("T=abc123\n", "abc"));
    }
}
