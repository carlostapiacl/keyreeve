//! `bring.toml` in keyreeve's folder: the folders Bring in never looks in, as the person wrote them. The app's
//! "Don't look here" and `keyreeve bring ignore` both edit it.
//!
//! ```toml
//! ignore = ["~/Desktop/proyectos/99-archivo", "~/wapentake-bench-swe"]
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = "bring.toml";
/// More than enough for a person's list, and a bound on what a damaged file can make a walk compare.
pub const MAX_RULES: usize = 200;

pub fn file(keyreeve_home: &Path) -> PathBuf {
    keyreeve_home.join(FILE_NAME)
}

/// The list in the file, or none when there is no file. A file that is there and cannot be read is an error,
/// never an empty list, so a typo is not taken as "look everywhere" in silence.
pub fn load(path: &Path) -> Result<Vec<String>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(format!("{} could not be read", path.display())),
    };
    parse(&text).map_err(|line| {
        format!(
            "{}, line {line}, is not something this reads",
            path.display()
        )
    })
}

/// Reads `ignore = [...]`, on one line or several, with comments. Any other setting is an error.
pub fn parse(text: &str) -> Result<Vec<String>, usize> {
    let mut rules: Option<Vec<String>> = None;
    let mut open: Option<usize> = None;
    let mut list = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rest = if open.is_some() {
            line
        } else {
            let Some(rest) = line.strip_prefix("ignore") else {
                return Err(number);
            };
            let Some(rest) = rest.trim_start().strip_prefix('=') else {
                return Err(number);
            };
            if rules.is_some() {
                return Err(number);
            }
            let Some(rest) = rest.trim_start().strip_prefix('[') else {
                return Err(number);
            };
            open = Some(number);
            rest
        };
        let closed = strings(rest, &mut list).ok_or(number)?;
        if closed {
            open = None;
            if list.len() > MAX_RULES {
                return Err(number);
            }
            rules = Some(std::mem::take(&mut list));
        }
    }
    match open {
        Some(number) => Err(number),
        None => Ok(rules.unwrap_or_default()),
    }
}

/// Quoted strings separated by commas, until `]` or the end of the line. Returns whether `]` was reached.
fn strings(text: &str, out: &mut Vec<String>) -> Option<bool> {
    let mut chars = text.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }
        match chars.next() {
            None => return Some(false),
            Some('#') => return Some(false),
            Some(']') => {
                let rest: String = chars.collect();
                let rest = rest.trim();
                return (rest.is_empty() || rest.starts_with('#')).then_some(true);
            }
            Some('"') => {
                let mut value = String::new();
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => match chars.next()? {
                            '"' => value.push('"'),
                            '\\' => value.push('\\'),
                            _ => return None,
                        },
                        c if c.is_control() => return None,
                        c => value.push(c),
                    }
                }
                out.push(value);
            }
            Some(_) => return None,
        }
    }
}

pub fn render(rules: &[String]) -> String {
    let mut out = String::from(
        "# Folders Bring in never looks in. A full path (or ~/path) leaves out that folder and all under it;\n\
         # a name with no / leaves out every folder of that name.\nignore = [\n",
    );
    for rule in rules {
        let quoted = rule.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str(&format!("  \"{quoted}\",\n"));
    }
    out.push_str("]\n");
    out
}

/// Writes the list in one rename, private to this user.
pub fn save(path: &Path, rules: &[String]) -> Result<(), String> {
    let folder = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(folder).map_err(|_| format!("{} could not be made", folder.display()))?;
    let temp = folder.join(format!(".{FILE_NAME}.{}", std::process::id()));
    let written = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(render(rules).as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
        return Err(format!("{} could not be written", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_one_line_or_many_and_refuses_anything_else() {
        assert_eq!(
            parse("ignore = [\"~/a\", \"b\"]\n").unwrap(),
            vec!["~/a".to_owned(), "b".to_owned()]
        );
        let many = "# mine\nignore = [\n  \"~/x\", # old\n  \"/y \\\"z\\\"\",\n]\n";
        assert_eq!(
            parse(many).unwrap(),
            vec!["~/x".to_owned(), "/y \"z\"".to_owned()]
        );
        assert_eq!(parse("").unwrap(), Vec::<String>::new());
        assert_eq!(parse("other = 1\n"), Err(1));
        assert_eq!(parse("ignore = [\"a\"\n"), Err(1));
        assert_eq!(parse("ignore = [\"a\"]\nignore = []\n"), Err(2));
        assert_eq!(parse("ignore = [a]\n"), Err(1));
        let rules = vec!["~/a b".to_owned(), "c\"d".to_owned()];
        assert_eq!(parse(&render(&rules)).unwrap(), rules);
    }
}
