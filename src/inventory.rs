//! Describes a folder of credentials without revealing them.
//!
//! The report holds file names, dates, formats, variable names and the kind of each key.
//! Values stay out, so the report can be read by a person or an agent that must not see them.
//!
//! Real files mix everything: comments, `key=value`, `key: value`, notes and bare values, so
//! anything to the right of a separator is ignored, and free text never reaches the report.
//! From a comment or a note, only words on a closed list are kept.

use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use zeroize::Zeroizing;

const MAX_BYTES_READ: u64 = 1024 * 1024;
const MAX_FIELD_LEN: usize = 40;
const MIN_TOKEN_LEN: usize = 16;

/// Separators between a label and a value. The earliest one in the line wins.
const SEPARATORS: &[&str] = &["=>", "->", "=", ":", "|", "\t", " - "];
const COMMENT_MARKS: &[&str] = &["#", "//", ";", "--", "REM "];
const MAX_LABEL_WORDS: usize = 4;

/// Words that may leave a note or a label. A word outside this list never does.
const KNOWN_WORDS: &[&str] = &[
    "account",
    "admin",
    "anthropic",
    "api",
    "app",
    "auth",
    "aws",
    "azure",
    "bearer",
    "bot",
    "claude",
    "clave",
    "cliente",
    "client",
    "cloudflare",
    "code",
    "codigo",
    "código",
    "contrasena",
    "contraseña",
    "coolify",
    "correo",
    "credential",
    "credentials",
    "cuenta",
    "database",
    "db",
    "dev",
    "digitalocean",
    "docker",
    "dsn",
    "email",
    "facebook",
    "fly",
    "github",
    "gitlab",
    "gmail",
    "google",
    "hetzner",
    "host",
    "id",
    "instagram",
    "jwt",
    "key",
    "keys",
    "llave",
    "llaves",
    "local",
    "login",
    "mail",
    "mercadopago",
    "meta",
    "mqtt",
    "mysql",
    "netlify",
    "oauth",
    "openai",
    "pass",
    "passwd",
    "password",
    "paypal",
    "pat",
    "pin",
    "port",
    "postgres",
    "prod",
    "production",
    "produccion",
    "producción",
    "project",
    "proyecto",
    "pwd",
    "qa",
    "railway",
    "redis",
    "refresh",
    "render",
    "resend",
    "secret",
    "secreto",
    "sendgrid",
    "sentry",
    "server",
    "servidor",
    "slack",
    "smtp",
    "ssh",
    "staging",
    "stripe",
    "supabase",
    "telegram",
    "test",
    "token",
    "url",
    "user",
    "username",
    "usuario",
    "vercel",
    "webhook",
    "whatsapp",
    "youtube",
    // Other languages.
    "chave",
    "clé",
    "kennwort",
    "passwort",
    "schlüssel",
    "senha",
    "usuário",
    "utilisateur",
];

/// Your own words that may leave a note or a label, such as project names.
pub type ExtraWords = BTreeSet<String>;

/// Reads one word per line. Blank lines and lines starting with `#` are skipped.
pub fn parse_words(text: &str) -> ExtraWords {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_lowercase)
        .collect()
}

/// Prefixes that providers publish or that are widely known. Longer prefixes go first.
const KINDS: &[(&str, &str)] = &[
    ("sk-ant-", "anthropic"),
    ("github_pat_", "github"),
    ("ghp_", "github"),
    ("gho_", "github"),
    ("ghs_", "github"),
    ("glpat-", "gitlab"),
    ("sk_live_", "stripe-live"),
    ("sk_test_", "stripe-test"),
    ("rk_live_", "stripe-live"),
    ("whsec_", "webhook-secret"),
    ("sk-", "sk-style"),
    ("AKIA", "aws"),
    ("AIza", "google"),
    ("ya29.", "google-oauth"),
    ("xoxb-", "slack"),
    ("xoxp-", "slack"),
    ("SG.", "sendgrid"),
    ("re_", "resend"),
    ("nfp_", "netlify"),
    ("sntrys_", "sentry"),
    ("sntryu_", "sentry"),
    ("sbp_", "supabase"),
    ("dop_v1_", "digitalocean"),
    ("APP_USR-", "mercadopago"),
    ("eyJ", "jwt"),
];

#[derive(Debug, Serialize, Default)]
pub struct Item {
    pub path: String,
    pub bytes: u64,
    /// Seconds since the Unix epoch.
    pub modified: u64,
    pub mode: Option<String>,
    pub format: &'static str,
    /// Variable names or top-level JSON keys.
    pub fields: Vec<String>,
    /// Names found in commented-out lines, such as `# OLD_KEY=...`.
    pub commented_fields: Vec<String>,
    /// Known words found in comments and notes, such as `netlify` or `token`.
    pub hints: Vec<String>,
    /// Names left out because they could themselves be a secret.
    pub fields_hidden: usize,
    /// Kinds of key recognized by prefix.
    pub kinds: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub items: Vec<Item>,
}

pub fn scan(root: &Path, extra: &ExtraWords) -> io::Result<Report> {
    let mut paths = Vec::new();
    collect(root, &mut paths)?;
    paths.sort();
    let items = paths
        .iter()
        .map(|path| describe(root, path, extra))
        .collect::<io::Result<_>>()?;
    Ok(Report { schema: 1, items })
}

/// Writes a report outside the scanned folder.
pub fn write_report(report: &Report, root: &Path, out: &Path) -> io::Result<()> {
    let parent = parent_of(out);
    create_private_dir(parent)?;
    if fs::canonicalize(parent)?.starts_with(fs::canonicalize(root)?) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the report must be outside the scanned folder",
        ));
    }
    let text = serde_json::to_string_pretty(report).map_err(io::Error::other)?;
    write_private(out, &text)
}

/// Writes a file only this user can read, creating a private folder if needed.
pub fn write_private(out: &Path, text: &str) -> io::Result<()> {
    create_private_dir(parent_of(out))?;
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(out)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    write_all(file, text)
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn write_all(mut file: fs::File, text: &str) -> io::Result<()> {
    use std::io::Write;
    file.write_all(text.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

pub fn create_private_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn collect(dir: &Path, paths: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            if entry.file_name() != ".git" {
                collect(&entry.path(), paths)?;
            }
        } else {
            paths.push(entry.path());
        }
    }
    Ok(())
}

fn describe(root: &Path, path: &Path, extra: &ExtraWords) -> io::Result<Item> {
    let meta = fs::symlink_metadata(path)?;
    let mut item = Item {
        path: path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string(),
        bytes: meta.len(),
        modified: meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |elapsed| elapsed.as_secs()),
        mode: mode_of(&meta),
        ..Item::default()
    };
    if meta.file_type().is_symlink() {
        item.format = "symlink";
    } else if !meta.is_file() {
        item.format = "other";
    } else if meta.len() > MAX_BYTES_READ {
        item.format = "too-large";
    } else {
        let bytes = Zeroizing::new(fs::read(path)?);
        classify(&bytes, extra, &mut item);
    }
    Ok(item)
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    Some(format!("{:o}", meta.permissions().mode() & 0o777))
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> Option<String> {
    None
}

/// Files come in whatever encoding the editor used. Bytes with no NUL are Latin-1 at worst.
fn decode(bytes: &[u8]) -> Option<Zeroizing<String>> {
    if let Some(rest) = bytes
        .strip_prefix(&[0xFF, 0xFE])
        .or_else(|| bytes.strip_prefix(&[0xFE, 0xFF]))
    {
        let big_endian = bytes[0] == 0xFE;
        let (pairs, _odd_byte) = rest.as_chunks::<2>();
        let units: Zeroizing<Vec<u16>> = Zeroizing::new(
            pairs
                .iter()
                .map(|&pair| {
                    if big_endian {
                        u16::from_be_bytes(pair)
                    } else {
                        u16::from_le_bytes(pair)
                    }
                })
                .collect(),
        );
        return Some(Zeroizing::new(String::from_utf16_lossy(&units)));
    }
    if bytes.contains(&0) {
        return None;
    }
    Some(Zeroizing::new(match std::str::from_utf8(bytes) {
        Ok(text) => text.trim_start_matches('\u{FEFF}').to_owned(),
        Err(_) => bytes.iter().map(|&byte| byte as char).collect(),
    }))
}

fn classify(bytes: &[u8], extra: &ExtraWords, item: &mut Item) {
    let Some(text) = decode(bytes) else {
        item.format = "binary";
        return;
    };
    item.kinds = kinds_in(&text);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        item.format = "empty";
    } else if trimmed.starts_with("-----BEGIN") {
        item.format = "pem";
        if trimmed.contains("PRIVATE KEY") {
            item.kinds.push("private-key".to_owned());
        }
    } else if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(trimmed) {
        item.format = "json";
        add_fields(map.keys().map(String::as_str), item);
    } else if !trimmed.contains(char::is_whitespace) && separator_at(trimmed).is_none() {
        item.format = "single-value";
    } else {
        read_lines(trimmed, extra, item);
    }
}

fn read_lines(text: &str, extra: &ExtraWords, item: &mut Item) {
    let mut assignments = 0;
    let mut other_lines = 0;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if let Some(comment) = strip_comment(line) {
            if let Some((label, _value)) = split_label(comment) {
                if is_identifier(label) {
                    item.commented_fields.push(label.to_owned());
                }
            }
            add_hints(comment, extra, item);
        } else if let Some((label, _value)) = split_label(line) {
            if is_identifier(label) && line.contains('=') {
                assignments += 1;
                item.fields.push(label.to_owned());
            } else if safe_label(label, extra) {
                other_lines += 1;
                item.fields.push(label.to_owned());
            } else {
                other_lines += 1;
                item.fields_hidden += 1;
            }
        } else if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            add_hints(section, extra, item);
        } else {
            other_lines += 1;
            add_hints(line, extra, item);
        }
    }
    item.format = match (assignments, other_lines, item.fields.is_empty()) {
        (1.., 0, _) => "env",
        (_, _, false) => "labeled",
        (0, 0, true) => "comments-only",
        _ => "text",
    };
    for list in [
        &mut item.fields,
        &mut item.commented_fields,
        &mut item.hints,
    ] {
        list.sort();
        list.dedup();
    }
}

pub(crate) fn strip_comment(line: &str) -> Option<&str> {
    COMMENT_MARKS
        .iter()
        .find_map(|mark| line.strip_prefix(mark))
        .map(|rest| rest.trim_start_matches(['#', '/', ';', '-', ' ', '\t']))
}

fn separator_at(line: &str) -> Option<(usize, usize)> {
    SEPARATORS
        .iter()
        .filter_map(|separator| line.find(separator).map(|at| (at, separator.len())))
        .min_by_key(|(at, len)| (*at, usize::MAX - *len))
}

/// Splits a line into its label and whatever follows. The second part is never kept.
pub(crate) fn split_label(line: &str) -> Option<(&str, &str)> {
    let (at, len) = separator_at(line)?;
    let rest = &line[at + len..];
    if rest.starts_with("//") {
        return None; // A URL, whose scheme is not a label.
    }
    let label = line[..at]
        .trim()
        .trim_start_matches("- ")
        .trim_start_matches("export ")
        .trim_start_matches("set ")
        .trim()
        .trim_matches(['"', '\'', '`', '*']);
    (!label.is_empty()).then_some((label, rest))
}

fn is_identifier(label: &str) -> bool {
    label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && safe_field(label)
        && (label.contains('_') || label.bytes().all(|b| !b.is_ascii_lowercase()))
}

/// A label from a loose file passes only if every word is on the closed list, because the
/// left side of a separator can hold a password, as in `pass:user` or `password hunter: x`.
fn safe_label(label: &str, extra: &ExtraWords) -> bool {
    if label.chars().count() > MAX_FIELD_LEN {
        return false;
    }
    let words: Vec<&str> = label
        .split([' ', '_', '-', '.'])
        .filter(|word| !word.is_empty())
        .collect();
    !words.is_empty()
        && words.len() <= MAX_LABEL_WORDS
        && words.iter().all(|w| known_label_word(w, extra))
}

/// Allows a short counter after the word, as in `token2`.
fn known_label_word(word: &str, extra: &ExtraWords) -> bool {
    let letters = word.trim_end_matches(|c: char| c.is_ascii_digit());
    word.len() - letters.len() <= 2 && known_word(letters, extra)
}

fn known_word(word: &str, extra: &ExtraWords) -> bool {
    let word = word.to_lowercase();
    KNOWN_WORDS.contains(&word.as_str()) || extra.contains(&word)
}

fn add_hints(text: &str, extra: &ExtraWords, item: &mut Item) {
    let words = text
        .split(|c: char| !c.is_alphabetic())
        .filter(|word| known_word(word, extra))
        .map(str::to_lowercase);
    item.hints.extend(words);
}

fn add_fields<'a>(names: impl Iterator<Item = &'a str>, item: &mut Item) {
    for name in names {
        if safe_field(name) {
            item.fields.push(name.to_owned());
        } else {
            item.fields_hidden += 1;
        }
    }
    item.fields.sort();
    item.fields.dedup();
}

/// A name in a credentials file can be a secret, so only plain, short names pass.
pub(crate) fn safe_field(name: &str) -> bool {
    let plain = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    let starts_well = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    let digits = name.bytes().filter(u8::is_ascii_digit).count();
    plain
        && starts_well
        && name.len() <= MAX_FIELD_LEN
        && digits <= 4
        && kind_of(name).is_none()
        && reads_like_a_name(name)
}

/// A key can stand where a name goes, as in a loose `AbCd_EfGh...=`. Names are made of words: a
/// few capitals at most in mixed case, no very long run of letters, and vowels in the long ones.
/// A real name this refuses is only counted as hidden, while a key it passes would be written out.
fn reads_like_a_name(name: &str) -> bool {
    let uppers = name.bytes().filter(u8::is_ascii_uppercase).count();
    let lowers = name.bytes().filter(u8::is_ascii_lowercase).count();
    if uppers >= 5 && lowers > 0 {
        return false;
    }
    // Base32 and the like mix letters and digits inside one long word, while `S3` and `v2` are short.
    let mixes_digits = name.split(['_', '-', '.']).any(|part| {
        let first_digit = part.bytes().position(|b| b.is_ascii_digit());
        part.len() >= 8
            && first_digit
                .is_some_and(|at| part.as_bytes()[at..].iter().any(u8::is_ascii_alphabetic))
    });
    if mixes_digits {
        return false;
    }
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphabetic() || (c.is_ascii_uppercase() && previous_lower) {
            words.push(std::mem::take(&mut word));
        }
        if c.is_ascii_alphabetic() {
            word.push(c.to_ascii_lowercase());
        }
        previous_lower = c.is_ascii_lowercase();
    }
    words.push(word);
    words.iter().all(|word| {
        let vowels = word.chars().filter(|c| "aeiouy".contains(*c)).count();
        word.len() < 17 && (word.len() < 10 || vowels * 5 >= word.len())
    })
}

fn kinds_in(text: &str) -> Vec<String> {
    let mut kinds: Vec<String> = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
        .filter(|token| token.len() >= MIN_TOKEN_LEN)
        .filter_map(kind_of)
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

/// The longest known start wins, wherever it is listed; on a tie the providers' files win, so a new
/// provider is recognized with no change here.
pub(crate) fn kind_of(token: &str) -> Option<String> {
    let from_files = crate::providers::longest_prefix(token);
    let from_list = KINDS
        .iter()
        .filter(|(prefix, _)| token.starts_with(prefix))
        .max_by_key(|(prefix, _)| prefix.len());
    match (from_files, from_list) {
        (Some((_, len)), Some((prefix, kind))) if prefix.len() > len => Some((*kind).to_owned()),
        (Some((name, _)), _) => Some(name.to_owned()),
        (None, Some((_, kind))) => Some((*kind).to_owned()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARIES: &[&str] = &[
        "CANARYvalue111",
        "ghp_CANARY222222222222222222",
        "CANARY333plainpassword",
        "sk-ant-CANARY44444444444",
        "CANARY555notes",
        "CANARY666inkeyname12345678",
        "CANARY777nested",
        "CANARY888pem",
    ];

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "keyreeve-inventory-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(path.join("sub")).unwrap();
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample() -> Dir {
        let dir = Dir::new("sample");
        let root = &dir.0;
        fs::write(root.join("token.txt"), "ghp_CANARY222222222222222222\n").unwrap();
        fs::write(root.join("password.txt"), "CANARY333plainpassword\n").unwrap();
        fs::write(
            root.join("app.env"),
            "# comment\nexport API_KEY=CANARYvalue111\nANTHROPIC=sk-ant-CANARY44444444444\n",
        )
        .unwrap();
        fs::write(
            root.join("sub/auth.json"),
            r#"{"client_id":"CANARY777nested","CANARY666inkeyname12345678":"x","a1b2c3d4e5":"y"}"#,
        )
        .unwrap();
        fs::write(root.join("notes.txt"), "user: me\npass: CANARY555notes\n").unwrap();
        fs::write(
            root.join("id.pem"),
            "-----BEGIN PRIVATE KEY-----\nCANARY888pem\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        fs::write(root.join("blob.bin"), [0_u8, 1, 2, 255]).unwrap();
        fs::write(root.join("empty.txt"), "\n").unwrap();
        dir
    }

    fn item<'a>(report: &'a Report, path: &str) -> &'a Item {
        report.items.iter().find(|i| i.path == path).unwrap()
    }

    #[test]
    fn no_value_reaches_the_report() {
        let dir = sample();
        let report = scan(&dir.0, &ExtraWords::new()).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let debug = format!("{report:?}");
        for canary in CANARIES {
            assert!(!json.contains(canary), "{canary} reached the report");
            assert!(!debug.contains(canary), "{canary} reached debug output");
        }
        assert!(!json.contains("CANARY"));
    }

    #[test]
    fn describes_each_format() {
        let dir = sample();
        let report = scan(&dir.0, &ExtraWords::new()).unwrap();
        assert_eq!(report.items.len(), 8);

        let token = item(&report, "token.txt");
        assert_eq!(token.format, "single-value");
        assert_eq!(token.kinds, ["github"]);

        assert_eq!(item(&report, "password.txt").format, "single-value");
        assert!(item(&report, "password.txt").kinds.is_empty());

        let env = item(&report, "app.env");
        assert_eq!(env.format, "env");
        assert_eq!(env.fields, ["ANTHROPIC", "API_KEY"]);
        assert_eq!(env.kinds, ["anthropic"]);

        let json = item(&report, "sub/auth.json");
        assert_eq!(json.format, "json");
        assert_eq!(json.fields, ["client_id"]);
        assert_eq!(json.fields_hidden, 2);

        let notes = item(&report, "notes.txt");
        assert_eq!(notes.format, "labeled");
        assert_eq!(notes.fields, ["pass", "user"]);
        assert_eq!(item(&report, "id.pem").format, "pem");
        assert_eq!(item(&report, "id.pem").kinds, ["private-key"]);
        assert_eq!(item(&report, "blob.bin").format, "binary");
        assert_eq!(item(&report, "empty.txt").format, "empty");
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symlinks() {
        let dir = sample();
        let outside = Dir::new("outside");
        fs::write(outside.0.join("real.txt"), "CANARYoutside\n").unwrap();
        std::os::unix::fs::symlink(outside.0.join("real.txt"), dir.0.join("link.txt")).unwrap();
        std::os::unix::fs::symlink(&outside.0, dir.0.join("linkdir")).unwrap();
        let report = scan(&dir.0, &ExtraWords::new()).unwrap();
        assert_eq!(item(&report, "link.txt").format, "symlink");
        assert_eq!(item(&report, "linkdir").format, "symlink");
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("CANARYoutside"));
    }

    #[cfg(unix)]
    #[test]
    fn the_report_is_private_and_stays_outside_the_folder() {
        use std::os::unix::fs::PermissionsExt;
        let dir = sample();
        let outside = Dir::new("report");
        let report = scan(&dir.0, &ExtraWords::new()).unwrap();

        let out = outside.0.join("private/report.json");
        write_report(&report, &dir.0, &out).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&out), 0o600);
        assert_eq!(mode(out.parent().unwrap()), 0o700);

        fs::set_permissions(&out, fs::Permissions::from_mode(0o644)).unwrap();
        write_report(&report, &dir.0, &out).unwrap();
        assert_eq!(mode(&out), 0o600);

        assert!(write_report(&report, &dir.0, &dir.0.join("report.json")).is_err());
    }

    fn classified(bytes: &[u8]) -> Item {
        let mut item = Item::default();
        classify(bytes, &ExtraWords::new(), &mut item);
        item
    }

    #[test]
    fn an_env_file_with_comments_keeps_its_names() {
        let item = classified(
            b"# netlify sandbox\n\nexport API_KEY=abc\n# OLD_TOKEN=viejo\nDB_PASS=x=y:z\n",
        );
        assert_eq!(item.format, "env");
        assert_eq!(item.fields, ["API_KEY", "DB_PASS"]);
        assert_eq!(item.commented_fields, ["OLD_TOKEN"]);
        assert_eq!(item.hints, ["netlify", "token"]);
    }

    #[test]
    fn one_odd_line_does_not_lose_the_rest_of_the_file() {
        let item = classified(b"API_KEY=abc\na loose note\nDB_PASS=x\n");
        assert_eq!(item.format, "labeled");
        assert_eq!(item.fields, ["API_KEY", "DB_PASS"]);
    }

    #[test]
    fn reads_every_separator() {
        for line in [
            "password = v",
            "password=v",
            "password: v",
            "password:v",
            "password => v",
            "password -> v",
            "password | v",
            "password\tv",
            "password - v",
            "\"password\": \"v\",",
            "- password: v",
            "**password**: v",
        ] {
            let item = classified(format!("{line}\nnota\n").as_bytes());
            assert_eq!(item.fields, ["password"], "in {line:?}");
        }
    }

    #[test]
    fn labels_can_be_in_spanish_and_have_words() {
        let item = classified("Clave Netlify: a\nContraseña: b\nusuario admin = c\n".as_bytes());
        assert_eq!(
            item.fields,
            ["Clave Netlify", "Contraseña", "usuario admin"]
        );
    }

    #[test]
    fn no_value_leaks_from_a_messy_file() {
        let text = "\
# token netlify CANARYa1 for testing
// password: CANARYa2
; CANARYa3 old
-- clave CANARYa4
[CANARYa5]
CANARYa6: usuario
CANARYa7 = valor
Passw0rdCANARY8:admin
yo@CANARYa9.com:secreta
https://user:CANARYb1@example.com/path
token=CANARYb2:CANARYb3=CANARYb4
app key CANARYb5
CANARYb6
password CANARYb7: valor
";
        let item = classified(text.as_bytes());
        let report = format!("{item:?}");
        assert!(!report.contains("CANARY"), "{report}");
        assert_eq!(item.fields, ["token"]);
        assert!(item.hints.contains(&"netlify".to_owned()));
        assert!(item.fields_hidden >= 5, "{report}");
        assert_eq!(classified(b"password hunter: x\nnota\n").fields_hidden, 1);
        assert_eq!(classified(b"Token2: x\nnota\n").fields, ["Token2"]);
    }

    #[test]
    fn a_key_in_a_comment_is_recognized_without_being_copied() {
        let item = classified(b"# antes: ghp_CANARY000000000000000000\nAPI=x\n");
        assert_eq!(item.kinds, ["github"]);
        assert!(!format!("{item:?}").contains("CANARY"));
    }

    #[test]
    fn reads_other_encodings_and_line_endings() {
        let latin1 = classified(b"contrase\xF1a: CANARY\r\nusuario: x\r\n");
        assert_eq!(latin1.fields, ["contraseña", "usuario"]);

        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend("API_KEY=CANARY\n".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(classified(&utf16).fields, ["API_KEY"]);

        let bom = classified("\u{FEFF}API_KEY=CANARY\n".as_bytes());
        assert_eq!(bom.format, "env");
    }

    #[test]
    fn a_lone_value_is_not_read_as_a_label() {
        assert_eq!(classified(b"abc123longvalue\n").format, "single-value");
        let colon = classified(b"hunter:Passw0rd\n");
        assert!(colon.fields.is_empty());
        assert_eq!(colon.fields_hidden, 1);
    }

    #[test]
    fn your_own_words_can_appear_only_if_you_list_them() {
        let text = b"# shop netlify\nshop token: x\nnote\n";
        let plain = classified(text);
        assert_eq!(plain.hints, ["netlify"]);
        assert!(plain.fields.is_empty());

        let mut item = Item::default();
        classify(text, &parse_words("# mine\n\nSHOP\n"), &mut item);
        assert_eq!(item.hints, ["netlify", "shop"]);
        assert_eq!(item.fields, ["shop token"]);
    }

    #[test]
    fn a_stripe_key_is_not_taken_for_elevenlabs() {
        assert_eq!(
            kind_of("sk_test_51abcdefghijklmnop").as_deref(),
            Some("stripe")
        );
        assert_eq!(
            kind_of("sk_0123456789abcdefghij").as_deref(),
            Some("elevenlabs")
        );
        assert_eq!(
            kind_of("sk-ant-api03-abcdefghij").as_deref(),
            Some("anthropic")
        );
        assert_eq!(
            kind_of("sk-proj-abcdefghijklmnop").as_deref(),
            Some("openai")
        );
        assert_eq!(
            kind_of("sk-abcdefghijklmnopqrst").as_deref(),
            Some("sk-style")
        );
        assert_eq!(
            kind_of("whsec_abcdefghijklmnop").as_deref(),
            Some("webhook-secret")
        );
        assert_eq!(kinds_in("sk_test_51abcdefghijklmnopqrstuvwx\n"), ["stripe"]);
    }

    #[test]
    fn a_short_token_with_a_known_prefix_is_not_a_kind() {
        assert!(kinds_in("re_view sk-short AKIA").is_empty());
    }

    #[test]
    fn a_key_standing_where_a_name_goes_stays_out() {
        for key in [
            "AbCd_EfGhIjKlMnOpQrStUvWx",
            "JBSWY3DPEHPK3PXP",
            "QWRTYPLKJHGFDSZXCVBNM",
            "abc_qwrtplkjhgfdszxcvbnm",
        ] {
            assert!(!safe_field(key), "{key}");
        }
        for name in [
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "client_secret",
            "accessToken",
            "serviceAccountKeyFile",
            "DEPLOYMENT_URL",
            "CLOUDFLARE_API_TOKEN",
            "S3_BUCKET",
            "OAUTH2_TOKEN",
        ] {
            assert!(safe_field(name), "{name}");
        }
    }
}
