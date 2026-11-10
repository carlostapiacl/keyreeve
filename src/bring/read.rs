//! Finds the files worth reading and splits each into pieces. A piece is one value with where it
//! stands in its file. Values live in memory only, and every name that leaves here passed the same
//! test the inventory uses, so a key written where a name goes stays out of the report.

use crate::inventory::{safe_field, split_label, strip_comment};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Deeper than this under a project folder, a `.env` is someone else's code.
pub const MAX_DEPTH: usize = 6;
/// A file of keys or settings is small. Larger ones are counted and left unread.
pub const MAX_FILE_BYTES: u64 = 256 * 1024;
/// A walk stops after this many entries, so a huge folder cannot hold the scan for minutes.
pub const MAX_ENTRIES: usize = 50_000;
/// Only the start of an SSH key is read: enough to see its header, and never the key.
const SSH_HEADER_BYTES: u64 = 64;

/// Folders that hold dependencies, builds, caches or the system's own files.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "Library",
    "venv",
    "env",
    "__pycache__",
    "Pods",
    "DerivedData",
    "vendor",
    "dist",
    "build",
    "Caches",
    "caches",
];

/// How a file is read. Each kind of file has its own shape, and reading it as what it is keeps a
/// setting from being taken for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// `NAME=value`, with or without `export`.
    Env,
    /// A shell's startup file: only `export NAME=value` lines, since the rest is the shell's own.
    Exports,
    /// `[section]` and `name = value`, as in `~/.aws/credentials`, `~/.pypirc` or a TOML file.
    Ini,
    /// `machine host login name password secret`.
    Netrc,
    /// `//registry/:_authToken=value`.
    Npmrc,
    Json,
    /// `host:` and indented `name: value` under it.
    Yaml,
    /// An SSH key: only its header is read.
    Ssh,
    /// Anything, in a folder the person chose.
    Any,
}

/// Where a file was found, which says how much of it is worth showing and whether scripts use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Area {
    /// A tool's file in the home folder, such as `~/.aws/credentials`.
    Home,
    /// A `.env` file in a project folder: a script reads it today.
    Project,
    /// A folder the person chose.
    Folder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locate {
    /// Bytes of the file, from and to.
    Span(usize, usize),
    /// The keys to follow in a JSON file.
    Json(Vec<String>),
    /// The whole file.
    Whole,
}

pub struct Piece {
    /// The name, when it may be shown.
    pub name: Option<String>,
    /// The name as written, kept in memory to read what kind of value this is.
    pub label: Zeroizing<String>,
    pub section: Option<String>,
    pub line: usize,
    pub locate: Locate,
    pub value: Zeroizing<String>,
    /// A server named next to the value, such as a `.netrc` machine or an npm registry.
    pub server: Option<String>,
    /// An SSH or PEM key, a certificate, or a file that cannot be read as text.
    pub whole: Option<WholeFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WholeFile {
    PrivateKey,
    PublicKey,
    Certificate,
    /// A keystore such as `.p12` or `.jks`: a key, in a form only its own tools read.
    Keystore,
    /// Notes or a document with no value in a form this can name.
    Document,
    TooLarge,
}

impl Piece {
    fn new(label: &str, line: usize, locate: Locate, value: &str) -> Self {
        Self {
            name: shown_name(label),
            label: Zeroizing::new(label.to_owned()),
            section: None,
            line,
            locate,
            value: Zeroizing::new(value.to_owned()),
            server: None,
            whole: None,
        }
    }

    fn whole(kind: WholeFile) -> Self {
        Self {
            name: None,
            label: Zeroizing::new(String::new()),
            section: None,
            line: 1,
            locate: Locate::Whole,
            value: Zeroizing::new(String::new()),
            server: None,
            whole: Some(kind),
        }
    }
}

/// A name may be shown if it reads as a name.
fn shown_name(label: &str) -> Option<String> {
    (!label.is_empty() && safe_field(label)).then(|| label.to_owned())
}

pub struct FileFound {
    pub path: PathBuf,
    pub area: Area,
    pub shape: Shape,
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct Skipped {
    /// Larger than a file of keys would be.
    pub too_large: usize,
    /// Could not be opened, or not text.
    pub unreadable: usize,
    /// Below the depth a project folder is searched to.
    pub too_deep: usize,
    /// `.env.example` and the like, which hold no real keys.
    pub examples: usize,
    /// The walk reached its limit of entries.
    pub stopped_early: bool,
}

/// The known files under a home folder. Only those that exist are returned.
pub fn home_files(home: &Path) -> Vec<FileFound> {
    // Each is a file a common tool keeps a credential in, in a form it documents.
    const KNOWN: &[(&str, Shape)] = &[
        (".aws/credentials", Shape::Ini),
        (".aws/config", Shape::Ini),
        (".config/gh/hosts.yml", Shape::Yaml),
        (".config/hub", Shape::Yaml),
        (".config/ngrok/ngrok.yml", Shape::Yaml),
        (
            ".config/gcloud/application_default_credentials.json",
            Shape::Json,
        ),
        (".config/stripe/config.toml", Shape::Ini),
        (".netrc", Shape::Netrc),
        (".npmrc", Shape::Npmrc),
        (".pypirc", Shape::Ini),
        (".docker/config.json", Shape::Json),
        (".zshrc", Shape::Exports),
        (".zprofile", Shape::Exports),
        (".zshenv", Shape::Exports),
        (".bashrc", Shape::Exports),
        (".bash_profile", Shape::Exports),
        (".profile", Shape::Exports),
    ];
    let mut found: Vec<FileFound> = KNOWN
        .iter()
        .map(|(path, shape)| (home.join(path), *shape))
        .filter(|(path, _)| is_plain_file(path))
        .map(|(path, shape)| FileFound {
            path,
            area: Area::Home,
            shape,
        })
        .collect();
    let mut ssh: Vec<PathBuf> = fs::read_dir(home.join(".ssh"))
        .map(|dir| dir.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    ssh.sort();
    for path in ssh {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let skip = matches!(
            name,
            "config" | "known_hosts" | "known_hosts.old" | "authorized_keys" | "environment"
        ) || name.starts_with('.');
        if !skip && is_plain_file(&path) {
            found.push(FileFound {
                path,
                area: Area::Home,
                shape: Shape::Ssh,
            });
        }
    }
    found
}

/// Folders under a home where projects usually live, if they are there.
pub fn suggested_projects(home: &Path) -> Vec<PathBuf> {
    ["Desktop", "Documents", "code", "src", "Projects", "dev"]
        .iter()
        .map(|name| home.join(name))
        .filter(|path| {
            fs::symlink_metadata(path)
                .map(|meta| meta.is_dir())
                .unwrap_or(false)
        })
        .collect()
}

fn is_plain_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
}

/// `.env`, `.env.local`, `prod.env` or `.envrc`, but not the examples a project ships.
pub fn is_env_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == ".env" || lower == ".envrc" || lower.starts_with(".env.") || lower.ends_with(".env")
}

fn is_example(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["example", "sample", "template", "dist", "defaults"]
        .iter()
        .any(|word| lower.contains(word))
}

/// Walks a folder without following links, and returns the files `want` takes.
pub fn walk(
    root: &Path,
    area: Area,
    shape: Shape,
    want: &dyn Fn(&str) -> bool,
    avoid: &[PathBuf],
    skipped: &mut Skipped,
) -> Vec<FileFound> {
    let mut found = Vec::new();
    let mut entries = 0;
    let mut examples = 0;
    walk_dir(
        root,
        0,
        &mut |path, name| {
            if want(name) {
                if area == Area::Project && is_example(name) {
                    examples += 1;
                } else {
                    found.push(FileFound {
                        path: path.to_owned(),
                        area,
                        shape,
                    });
                }
            }
        },
        avoid,
        &mut entries,
        skipped,
    );
    skipped.examples += examples;
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

fn walk_dir(
    dir: &Path,
    depth: usize,
    visit: &mut dyn FnMut(&Path, &str),
    avoid: &[PathBuf],
    entries: &mut usize,
    skipped: &mut Skipped,
) {
    let Ok(read) = fs::read_dir(dir) else {
        skipped.unreadable += 1;
        return;
    };
    let mut children: Vec<_> = read.flatten().collect();
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        *entries += 1;
        if *entries > MAX_ENTRIES {
            skipped.stopped_early = true;
            return;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let path = entry.path();
        if kind.is_dir() {
            let hidden = name.starts_with('.');
            if hidden || SKIP_DIRS.contains(&name) || avoid.contains(&path) {
                continue;
            }
            if depth + 1 > MAX_DEPTH {
                skipped.too_deep += 1;
                continue;
            }
            walk_dir(&path, depth + 1, visit, avoid, entries, skipped);
        } else if kind.is_file() {
            visit(&path, name);
        }
    }
}

/// How far a walk of the whole home folder goes, and for how long. When it runs out, the folders not
/// finished are named, so the search can go on in those alone.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub entries: usize,
    pub seconds: u64,
    pub depth: usize,
}

impl Budget {
    pub const EVERYWHERE: Budget = Budget {
        entries: 600_000,
        seconds: 120,
        depth: 16,
    };
}

/// What a walk of whole folders found, and the folders it did not finish.
pub struct Walked {
    pub files: Vec<FileFound>,
    pub unfinished: Vec<PathBuf>,
}

/// Hidden folders that hold keys people keep by hand. Every other hidden folder is a tool's own.
const HIDDEN_KEPT: &[&str] = &[".config", ".secrets", ".credentials", ".keys"];
/// Besides `SKIP_DIRS`: where nothing a person wrote a key into lives, or that iCloud would download.
const SKIP_EVERYWHERE: &[&str] = &[
    "Mobile Documents",
    "CloudStorage",
    "Photos Library",
    "Music",
    "Movies",
    "Pictures",
    "Applications",
    "anaconda3",
    "miniconda3",
    "site-packages",
];
/// Bundles: a folder the Finder shows as one file, such as an app or a photo library.
const BUNDLES: &[&str] = &[
    ".app",
    ".photoslibrary",
    ".photolibrary",
    ".musiclibrary",
    ".tvlibrary",
    ".imovielibrary",
    ".fcpbundle",
    ".logicx",
    ".band",
    ".bundle",
    ".framework",
    ".xcarchive",
    ".xcodeproj",
    ".xcworkspace",
    ".pkg",
];
/// Files whose name says what they are: keys and keystores.
const KEY_EXTENSIONS: &[&str] = &["pem", "p12", "pfx", "key", "jks", "keystore"];
/// Files that may hold keys, read when their name says so or their start shows a known prefix.
const NOTE_EXTENSIONS: &[&str] = &["txt", "json", "toml", "yaml", "yml"];
/// Words in a file's name that say it holds a key.
const KEY_WORDS: &[&str] = &[
    "key",
    "secret",
    "token",
    "credential",
    "password",
    "passwd",
    "auth",
    "service-account",
    "serviceaccount",
    "private",
];
/// Files a project ships that are never a key file, however their contents read.
const NOISE: &[&str] = &[
    "package.json",
    "package-lock.json",
    "composer.json",
    "tsconfig.json",
    "jsconfig.json",
    "cargo.toml",
    "pyproject.toml",
    "manifest.json",
    "requirements.txt",
    "license.txt",
];
/// A file is opened only to look for a known prefix while it is this small.
const SNIFF_BYTES: u64 = 16 * 1024;

fn skip_everywhere(name: &str) -> bool {
    if SKIP_DIRS.contains(&name) || SKIP_EVERYWHERE.contains(&name) {
        return true;
    }
    if name.starts_with('.') {
        return !HIDDEN_KEPT.contains(&name);
    }
    let lower = name.to_ascii_lowercase();
    BUNDLES
        .iter()
        .any(|ext| lower.ends_with(&ext.to_ascii_lowercase()))
}

/// Whether a file found in a walk of whole folders is worth reading, and how: `.env` files, keys and
/// keystores, and notes whose name says key or whose start holds a provider's prefix.
fn choose(path: &Path, name: &str, size: u64, skipped: &mut Skipped) -> Option<(Shape, Area)> {
    let lower = name.to_ascii_lowercase();
    if is_env_name(name) {
        if is_example(name) {
            skipped.examples += 1;
            return None;
        }
        return (size <= MAX_FILE_BYTES)
            .then_some((Shape::Env, Area::Project))
            .or_else(|| {
                skipped.too_large += 1;
                None
            });
    }
    let (stem, ext) = match lower.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, ext),
        _ => return None,
    };
    let keyish = KEY_EXTENSIONS.contains(&ext);
    let note = NOTE_EXTENSIONS.contains(&ext);
    if !keyish && !note {
        return None;
    }
    if is_example(name) || NOISE.contains(&lower.as_str()) {
        return None;
    }
    if size > MAX_FILE_BYTES {
        skipped.too_large += 1;
        return None;
    }
    let named = KEY_WORDS.iter().any(|word| stem.contains(word));
    if ext == "key" {
        // A Keynote file is called .key too: only text that starts like a key is one.
        return starts_like_pem(path).then_some((Shape::Any, Area::Folder));
    }
    if keyish || named {
        return Some((Shape::Any, Area::Folder));
    }
    (size <= SNIFF_BYTES && holds_known_prefix(path)).then_some((Shape::Any, Area::Folder))
}

fn starts_like_pem(path: &Path) -> bool {
    let mut head = Vec::new();
    let read =
        fs::File::open(path).and_then(|file| file.take(SSH_HEADER_BYTES).read_to_end(&mut head));
    read.is_ok() && head.starts_with(b"-----BEGIN")
}

/// A word in the file that starts with a prefix a provider publishes. JSON web tokens are left out,
/// since many files that hold no key carry one.
fn holds_known_prefix(path: &Path) -> bool {
    let Ok(bytes) = fs::read(path).map(Zeroizing::new) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return false;
    };
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
        .filter(|word| word.len() >= 16)
        .any(|word| crate::inventory::kind_of(word).is_some_and(|kind| kind != "jwt"))
}

/// Walks whole folders for files that hold keys, within a budget. Files right under each folder come
/// first, then its folders one by one; a folder the budget did not reach, or left halfway, is named
/// in `unfinished`.
pub fn walk_everywhere(
    roots: &[PathBuf],
    avoid: &[PathBuf],
    budget: Budget,
    skipped: &mut Skipped,
) -> Walked {
    let mut state = Walk {
        entries: 0,
        until: std::time::Instant::now() + std::time::Duration::from_secs(budget.seconds),
        budget,
        avoid,
        files: Vec::new(),
        out: false,
    };
    let mut unfinished = Vec::new();
    for root in roots {
        let Ok(read) = fs::read_dir(root) else {
            skipped.unreadable += 1;
            continue;
        };
        let mut children: Vec<_> = read.flatten().collect();
        children.sort_by_key(|entry| entry.file_name());
        let mut folders = Vec::new();
        for entry in children {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if kind.is_dir() {
                if !skip_everywhere(name) && !avoid.contains(&entry.path()) {
                    folders.push(entry.path());
                }
            } else if kind.is_file() {
                state.file(&entry.path(), name, skipped);
            }
        }
        for folder in folders {
            if state.out || !state.dir(&folder, 1, skipped) {
                unfinished.push(folder);
            }
        }
    }
    if state.out {
        skipped.stopped_early = true;
    }
    let mut files = state.files;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Walked { files, unfinished }
}

struct Walk<'a> {
    entries: usize,
    until: std::time::Instant,
    budget: Budget,
    avoid: &'a [PathBuf],
    files: Vec<FileFound>,
    /// The budget ran out: nothing more is read.
    out: bool,
}

impl Walk<'_> {
    fn spend(&mut self) -> bool {
        self.entries += 1;
        if self.entries > self.budget.entries
            || (self.entries.is_multiple_of(256) && std::time::Instant::now() >= self.until)
        {
            self.out = true;
        }
        !self.out
    }

    fn file(&mut self, path: &Path, name: &str, skipped: &mut Skipped) {
        let size = fs::symlink_metadata(path).map_or(0, |meta| meta.len());
        if let Some((shape, area)) = choose(path, name, size, skipped) {
            self.files.push(FileFound {
                path: path.to_owned(),
                area,
                shape,
            });
        }
    }

    /// Returns whether the folder was walked to its end.
    fn dir(&mut self, dir: &Path, depth: usize, skipped: &mut Skipped) -> bool {
        let Ok(read) = fs::read_dir(dir) else {
            skipped.unreadable += 1;
            return true;
        };
        let mut children: Vec<_> = read.flatten().collect();
        children.sort_by_key(|entry| entry.file_name());
        for entry in children {
            if !self.spend() {
                return false;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let path = entry.path();
            if kind.is_dir() {
                if skip_everywhere(name) || self.avoid.contains(&path) {
                    continue;
                }
                if depth + 1 > self.budget.depth {
                    skipped.too_deep += 1;
                    continue;
                }
                if !self.dir(&path, depth + 1, skipped) {
                    return false;
                }
            } else if kind.is_file() {
                self.file(&path, name, skipped);
            }
        }
        true
    }
}

/// Reads one file into pieces. A file that cannot be read gives none, and is counted.
pub fn pieces(file: &FileFound, skipped: &mut Skipped) -> Vec<Piece> {
    let Ok(meta) = fs::symlink_metadata(&file.path) else {
        skipped.unreadable += 1;
        return Vec::new();
    };
    if !meta.is_file() {
        return Vec::new();
    }
    if file.shape == Shape::Ssh {
        return ssh_key(&file.path).into_iter().collect();
    }
    let name = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if file.shape == Shape::Any && is_keystore_name(&name) {
        return vec![Piece::whole(WholeFile::Keystore)];
    }
    if meta.len() > MAX_FILE_BYTES {
        skipped.too_large += 1;
        return match file.shape {
            Shape::Any => vec![Piece::whole(WholeFile::TooLarge)],
            _ => Vec::new(),
        };
    }
    let Ok(bytes) = fs::read(&file.path).map(Zeroizing::new) else {
        skipped.unreadable += 1;
        return Vec::new();
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        skipped.unreadable += 1;
        return match file.shape {
            Shape::Any => vec![Piece::whole(WholeFile::Document)],
            _ => Vec::new(),
        };
    };
    match file.shape {
        Shape::Env => env_lines(text, false),
        Shape::Exports => env_lines(text, true),
        Shape::Ini => ini(text),
        Shape::Netrc => netrc(text),
        Shape::Npmrc => npmrc(text),
        Shape::Json => json(text),
        Shape::Yaml => yaml(text),
        Shape::Ssh => Vec::new(),
        Shape::Any => any(text, &name),
    }
}

fn is_keystore_name(name: &str) -> bool {
    [".p12", ".pfx", ".jks", ".keystore", ".der"]
        .iter()
        .any(|ext| name.ends_with(ext))
}

fn ssh_key(path: &Path) -> Option<Piece> {
    let name = path.file_name()?.to_str()?;
    if name.ends_with(".pub") {
        return Some(Piece::whole(WholeFile::PublicKey));
    }
    let mut head = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(SSH_HEADER_BYTES)
        .read_to_end(&mut head)
        .ok()?;
    let head = String::from_utf8_lossy(&head);
    (head.starts_with("-----BEGIN") && head.contains("PRIVATE KEY"))
        .then(|| Piece::whole(WholeFile::PrivateKey))
}

/// Where each line starts, so a value's place is a count of bytes in the file.
fn lines_with_offsets(text: &str) -> impl Iterator<Item = (usize, usize, &str)> {
    let mut at = 0;
    text.split_inclusive('\n')
        .enumerate()
        .map(move |(index, line)| {
            let start = at;
            at += line.len();
            (index + 1, start, line.trim_end_matches(['\n', '\r']))
        })
}

/// The value after a separator: quotes come off, and an unquoted value ends at ` #`. Returns where
/// it starts and ends inside `rest`.
fn value_in(rest: &str) -> Option<(usize, usize)> {
    let lead = rest.len() - rest.trim_start().len();
    let body = &rest[lead..];
    let (start, end) = match body.chars().next() {
        Some(quote @ ('"' | '\'' | '`')) => {
            let close = body[1..].find(quote)?;
            (lead + 1, lead + 1 + close)
        }
        _ => {
            let cut = body.find(" #").unwrap_or(body.len());
            let value = body[..cut].trim_end();
            (lead, lead + value.len())
        }
    };
    (end > start).then_some((start, end))
}

fn env_lines(text: &str, exports_only: bool) -> Vec<Piece> {
    let mut found = Vec::new();
    for (number, start, line) in lines_with_offsets(text) {
        let lead = line.len() - line.trim_start().len();
        let mut body = &line[lead..];
        let mut skip = lead;
        if let Some(rest) = body.strip_prefix("export ") {
            skip += body.len() - rest.len();
            body = rest;
        } else if exports_only {
            continue;
        }
        let Some(eq) = body.find('=') else { continue };
        let name = body[..eq].trim();
        let is_name = !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !name.as_bytes()[0].is_ascii_digit();
        if !is_name {
            continue;
        }
        let rest = &body[eq + 1..];
        let Some((from, to)) = value_in(rest) else {
            continue;
        };
        let at = start + skip + eq + 1;
        let value = &rest[from..to];
        found.push(Piece::new(
            name,
            number,
            Locate::Span(at + from, at + to),
            value,
        ));
    }
    found
}

fn ini(text: &str) -> Vec<Piece> {
    let mut found = Vec::new();
    let mut section: Option<String> = None;
    for (number, start, line) in lines_with_offsets(text) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(name) = trimmed.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let name = name.trim().trim_start_matches("profile ").trim();
            section = Some(name.to_owned());
            continue;
        }
        let Some(at) = line.find(['=', ':']) else {
            continue;
        };
        let name = line[..at].trim();
        let rest = &line[at + 1..];
        let Some((from, to)) = value_in(rest) else {
            continue;
        };
        let mut piece = Piece::new(
            name,
            number,
            Locate::Span(start + at + 1 + from, start + at + 1 + to),
            &rest[from..to],
        );
        piece.section = section.as_deref().and_then(shown_name);
        found.push(piece);
    }
    found
}

fn netrc(text: &str) -> Vec<Piece> {
    // Words with where they start: a .netrc is words, in any lines.
    let mut words = Vec::new();
    let mut at = None;
    for (index, c) in text.char_indices() {
        match (c.is_whitespace(), at) {
            (false, None) => at = Some(index),
            (true, Some(from)) => {
                words.push((from, &text[from..index]));
                at = None;
            }
            _ => {}
        }
    }
    if let Some(from) = at {
        words.push((from, &text[from..]));
    }
    let line_of = |offset: usize| text[..offset].matches('\n').count() + 1;
    let mut found = Vec::new();
    let mut machine: Option<String> = None;
    let mut pairs = words.iter();
    while let Some((_, word)) = pairs.next() {
        match *word {
            "machine" => machine = pairs.next().and_then(|(_, host)| host_name(host)),
            "default" => machine = None,
            "login" | "password" | "account" => {
                if let Some((from, value)) = pairs.next() {
                    let mut piece = Piece::new(
                        word,
                        line_of(*from),
                        Locate::Span(*from, from + value.len()),
                        value,
                    );
                    piece.server = machine.clone();
                    found.push(piece);
                }
            }
            "macdef" => break,
            _ => {}
        }
    }
    found
}

fn npmrc(text: &str) -> Vec<Piece> {
    let mut found = Vec::new();
    for (number, start, line) in lines_with_offsets(text) {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let Some(eq) = line.find('=') else { continue };
        let left = line[..eq].trim();
        let (server, name) = match left.rsplit_once(':') {
            Some((scope, name)) if scope.starts_with("//") => (host_name(scope), name),
            _ => (None, left),
        };
        let rest = &line[eq + 1..];
        let Some((from, to)) = value_in(rest) else {
            continue;
        };
        let mut piece = Piece::new(
            name,
            number,
            Locate::Span(start + eq + 1 + from, start + eq + 1 + to),
            &rest[from..to],
        );
        piece.server = server;
        found.push(piece);
    }
    found
}

/// The host in a URL or a `//host/path`, if it is a plain host name.
pub fn host_name(text: &str) -> Option<String> {
    let rest = text
        .split_once("://")
        .map_or(text, |(_, rest)| rest)
        .trim_start_matches('/');
    if rest.contains('@') {
        return None;
    }
    let host = rest.split(['/', '?', '#']).next()?;
    let ok = !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    ok.then(|| host.to_ascii_lowercase())
}

const MAX_JSON_DEPTH: usize = 4;

fn json(text: &str) -> Vec<Piece> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    json_walk(&value, &mut Vec::new(), None, &mut found);
    found
}

fn json_walk(
    value: &serde_json::Value,
    path: &mut Vec<String>,
    server: Option<&str>,
    found: &mut Vec<Piece>,
) {
    match value {
        serde_json::Value::Object(map) if path.len() < MAX_JSON_DEPTH => {
            for (key, inner) in map {
                // A JSON key a person typed can be a secret: only names and hosts are followed.
                let host = host_name(key).filter(|_| key.contains('.'));
                if !safe_field(key) && host.is_none() {
                    continue;
                }
                path.push(key.clone());
                json_walk(inner, path, host.as_deref().or(server), found);
                path.pop();
            }
        }
        serde_json::Value::String(text) if !path.is_empty() => {
            let label = path.last().cloned().unwrap_or_default();
            let mut piece = Piece::new(&label, 0, Locate::Json(path.clone()), text);
            piece.server = server.map(str::to_owned);
            found.push(piece);
        }
        _ => {}
    }
}

fn yaml(text: &str) -> Vec<Piece> {
    let mut found = Vec::new();
    let mut section: Option<String> = None;
    for (number, start, line) in lines_with_offsets(text) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        let indented = line.len() != trimmed.len();
        let name = line[..colon].trim().trim_start_matches("- ").trim();
        let rest = &line[colon + 1..];
        if rest.trim().is_empty() {
            if !indented {
                section = Some(name.to_owned());
            }
            continue;
        }
        let Some((from, to)) = value_in(rest) else {
            continue;
        };
        let mut piece = Piece::new(
            name,
            number,
            Locate::Span(start + colon + 1 + from, start + colon + 1 + to),
            &rest[from..to],
        );
        if indented {
            piece.server = section.as_deref().and_then(host_name);
            piece.section = section.as_deref().and_then(shown_name);
        }
        found.push(piece);
    }
    found
}

/// A file in a folder the person chose, of any shape.
fn any(text: &str, name: &str) -> Vec<Piece> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with("-----BEGIN") {
        let kind = if trimmed.contains("PRIVATE KEY") {
            WholeFile::PrivateKey
        } else if trimmed.contains("CERTIFICATE") {
            WholeFile::Certificate
        } else {
            WholeFile::PublicKey
        };
        return vec![Piece::whole(kind)];
    }
    if trimmed.starts_with("ssh-") && trimmed.lines().count() == 1 {
        return vec![Piece::whole(WholeFile::PublicKey)];
    }
    if trimmed.starts_with('{') {
        let found = json(text);
        if !found.is_empty() {
            return found;
        }
    }
    if !trimmed.contains(char::is_whitespace) && !trimmed.contains('=') {
        let start = text.find(trimmed).unwrap_or(0);
        return vec![Piece::new(
            "",
            1,
            Locate::Span(start, start + trimmed.len()),
            trimmed,
        )];
    }
    if name.ends_with(".ini") || name.ends_with(".toml") || name.ends_with(".cfg") {
        return ini(text);
    }
    if name.ends_with(".yml") || name.ends_with(".yaml") {
        return yaml(text);
    }
    let found = loose(text);
    if found.is_empty() {
        return vec![Piece::whole(WholeFile::Document)];
    }
    found
}

/// Notes: `label: value` lines, and lone words that look like keys.
fn loose(text: &str) -> Vec<Piece> {
    let mut found = Vec::new();
    for (number, start, line) in lines_with_offsets(text) {
        let trimmed = line.trim();
        if trimmed.is_empty() || strip_comment(trimmed).is_some() {
            continue;
        }
        if let Some((label, rest)) = split_label(line) {
            let rest_at = line.len() - rest.len();
            if let Some((from, to)) = value_in(rest) {
                let value = &rest[from..to];
                if !value.contains(char::is_whitespace) {
                    found.push(Piece::new(
                        label,
                        number,
                        Locate::Span(start + rest_at + from, start + rest_at + to),
                        value,
                    ));
                    continue;
                }
            }
        }
        // Words on a line of their own or inside a sentence: only those that read as a key.
        let mut at = 0;
        for word in line.split(char::is_whitespace) {
            let from = at;
            at += word.len() + 1;
            let word_start = from + (word.len() - word.trim_start_matches(['"', '\'', '(']).len());
            let clean = word.trim_matches(['"', '\'', '(', ')', ',', ';', '.']);
            if clean.len() >= 20 && super::sort::looks_random(clean) {
                found.push(Piece::new(
                    "",
                    number,
                    Locate::Span(start + word_start, start + word_start + clean.len()),
                    clean,
                ));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(text: &str, found: &[Piece]) -> Vec<String> {
        found
            .iter()
            .map(|piece| match piece.locate {
                Locate::Span(from, to) => {
                    assert_eq!(&text[from..to], piece.value.as_str());
                    format!("{}={}", piece.label.as_str(), &text[from..to])
                }
                _ => panic!("expected a span"),
            })
            .collect()
    }

    #[test]
    fn env_lines_point_at_their_values() {
        let text = "# c\nexport A_KEY=\"one two\"\nB='x'\nC=plain # note\n bad line\nD=\n";
        let found = env_lines(text, false);
        assert_eq!(spans(text, &found), ["A_KEY=one two", "B=x", "C=plain"]);
        assert_eq!(found[2].line, 4);
        assert_eq!(spans(text, &env_lines(text, true)), ["A_KEY=one two"]);
    }

    #[test]
    fn ini_keeps_sections() {
        let text = "[default]\naws_access_key_id = AK\n[profile work]\nregion: eu\n";
        let found = ini(text);
        assert_eq!(spans(text, &found), ["aws_access_key_id=AK", "region=eu"]);
        assert_eq!(found[0].section.as_deref(), Some("default"));
        assert_eq!(found[1].section.as_deref(), Some("work"));
    }

    #[test]
    fn netrc_reads_words_across_lines() {
        let text = "machine api.example.com\n  login me\n  password pw1\nmachine x.org login u password pw2\n";
        let found = netrc(text);
        assert_eq!(
            spans(text, &found),
            ["login=me", "password=pw1", "login=u", "password=pw2"]
        );
        assert_eq!(found[1].server.as_deref(), Some("api.example.com"));
        assert_eq!(found[1].line, 3);
        assert_eq!(found[3].server.as_deref(), Some("x.org"));
    }

    #[test]
    fn npmrc_names_the_registry() {
        let text = "//registry.npmjs.org/:_authToken=tok\nsave-exact=true\n";
        let found = npmrc(text);
        assert_eq!(spans(text, &found), ["_authToken=tok", "save-exact=true"]);
        assert_eq!(found[0].server.as_deref(), Some("registry.npmjs.org"));
    }

    #[test]
    fn yaml_names_the_host_above() {
        let text = "github.com:\n    oauth_token: tok\n    user: me\n";
        let found = yaml(text);
        assert_eq!(spans(text, &found), ["oauth_token=tok", "user=me"]);
        assert_eq!(found[0].server.as_deref(), Some("github.com"));
    }

    #[test]
    fn json_follows_names_and_hosts_only() {
        let text = r#"{"auths":{"https://index.docker.io/v1/":{"auth":"abc"}},"Zx9QwErTyUiOpAsDfGhJkL":{"a":"b"}}"#;
        let found = json(text);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].locate,
            Locate::Json(vec![
                "auths".into(),
                "https://index.docker.io/v1/".into(),
                "auth".into()
            ])
        );
        assert_eq!(found[0].server.as_deref(), Some("index.docker.io"));
    }

    #[test]
    fn a_url_with_a_password_has_no_host_to_show() {
        assert_eq!(host_name("https://u:p@db.example.com/x"), None);
        assert_eq!(
            host_name("https://abc.r2.cloudflarestorage.com").as_deref(),
            Some("abc.r2.cloudflarestorage.com")
        );
    }

    #[test]
    fn env_names_and_examples() {
        for name in [".env", ".env.local", ".envrc", "prod.env"] {
            assert!(is_env_name(name), "{name}");
        }
        assert!(!is_env_name("environment.ts"));
        assert!(is_example(".env.example") && is_example(".env.sample"));
        assert!(!is_example(".env.production"));
    }
}
