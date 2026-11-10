//! Bring in: finds keys on this Mac or in a folder, and says what each is, without moving or changing
//! a file. The report names files, the names inside them and where each value stands, and never a
//! value. Keys found twice are told apart by a hash held in memory for this run only.
//!
//! The steps: find the files, split each into pieces, say what each piece is, put the parts of one
//! key together, join the same key found in two places, and check each key with the providers that
//! could own it, the one that answers being the provider.

mod read;
mod sort;

pub use read::{suggested_projects, Area, Skipped};
pub use sort::Class;

use crate::providers;
use crate::recipe::Recipe;
use crate::secret::Secret;
use crate::verify::Verdict;
use read::{FileFound, Locate, Piece, Shape};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sort::{Known, Role};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;

/// Where to look.
pub enum Scope {
    /// The places tools keep keys under `home`, and `.env` files under the project folders given.
    Places {
        home: PathBuf,
        projects: Vec<PathBuf>,
    },
    /// Every file under a folder the person chose.
    Folder(PathBuf),
}

/// Checks one key with one provider. The command sends one real request; tests answer for it.
pub type Checker<'a> = dyn Fn(&Recipe, &Secret) -> Verdict + Sync + 'a;

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub scope: &'static str,
    /// The folders searched for `.env` files, or the folder chosen.
    pub roots: Vec<String>,
    /// Folders under the home where projects usually are, to offer before searching them.
    pub suggested_projects: Vec<String>,
    pub files: usize,
    pub checked: bool,
    pub skipped: Skipped,
    pub summary: Summary,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub works: usize,
    pub doubtful: usize,
    pub other: usize,
    pub dead: usize,
    /// Keys found in more than one place. Each is also counted in its group.
    pub duplicates: usize,
}

/// Where a candidate goes on the review screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// A provider answered that it works.
    Works,
    /// No answer says what it is: the person decides.
    Doubtful,
    /// Configuration, documents and public keys: not sealed.
    Other,
    /// Every provider tried turned it down.
    Dead,
}

#[derive(Debug, Serialize)]
pub struct Candidate {
    pub id: usize,
    pub group: Group,
    pub class: Class,
    /// Why it was read as its class, in a few words.
    pub why: &'static str,
    /// The provider: the one that answered, or the likeliest when none was asked.
    pub provider: Option<String>,
    /// The providers that could check it, best first.
    pub recipes: Vec<String>,
    pub check: Option<Check>,
    /// A server named with the key: a registry, a `.netrc` machine, an S3 endpoint.
    pub server: Option<String>,
    /// Every place this key was found. Two or more is one key found twice.
    pub origins: Vec<Origin>,
    pub duplicate: bool,
    /// Found in a project's `.env`, so a script already uses it.
    pub from_project: bool,
    /// `seal`, `skip` or `decide`.
    pub suggested: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// The provider that gave this result.
    pub recipe: String,
    /// `works`, `rejected`, `forbidden` or `no_result`.
    pub result: &'static str,
    pub reason: Option<String>,
    pub tried: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Origin {
    pub path: String,
    pub area: Area,
    /// The file's size and when it last changed, in seconds since 1970, as read. The app reads a value
    /// from its span only if both are the same, so a file changed since cannot give it the wrong text.
    pub bytes: u64,
    pub modified: u64,
    /// The pieces that make the key, in order. A key of two parts names two.
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Part {
    /// The name in the file, when it reads as a name.
    pub name: Option<String>,
    pub section: Option<String>,
    pub line: usize,
    /// Where the value stands, in bytes: from and to. The app reads the value from here to seal it.
    pub span: Option<[usize; 2]>,
    /// The keys to follow in a JSON file.
    pub json: Option<Vec<String>>,
    /// The whole file is the key.
    pub whole: bool,
}

impl Part {
    fn of(piece: &Piece) -> Self {
        let (span, json, whole) = match &piece.locate {
            Locate::Span(from, to) => (Some([*from, *to]), None, false),
            Locate::Json(path) => (None, Some(path.clone()), false),
            Locate::Whole => (None, None, true),
        };
        Self {
            name: piece.name.clone(),
            section: piece.section.clone(),
            line: piece.line,
            span,
            json,
            whole,
        }
    }
}

/// One key as found, with its value in memory until the report is written.
struct Draft {
    class: Class,
    why: &'static str,
    value: Secret,
    recipes: Vec<String>,
    server: Option<String>,
    origins: Vec<Origin>,
}

/// What the steps need from this Mac: the providers it knows, the servers you approved, and
/// folders never to read.
pub struct Setup<'a> {
    known: Vec<Known>,
    host_approved: &'a (dyn Fn(&str, &str) -> bool + Sync),
    avoid: Vec<PathBuf>,
}

impl Setup<'static> {
    /// The providers and approvals in keyreeve's folder, which itself is never searched.
    pub fn this_mac() -> Self {
        Self {
            known: sort::known(),
            host_approved: &providers::host_approved,
            avoid: vec![providers::home()],
        }
    }
}

/// Finds and sorts. With a checker, each key is checked; without one, nothing leaves this Mac.
pub fn bring(scope: &Scope, checker: Option<&Checker>) -> Report {
    bring_with(scope, &Setup::this_mac(), checker)
}

pub fn bring_with(scope: &Scope, setup: &Setup, checker: Option<&Checker>) -> Report {
    let known = &setup.known;
    let mut skipped = Skipped::default();
    let (files, roots, suggested, scope_name) = match scope {
        Scope::Places { home, projects } => {
            let mut files = read::home_files(home);
            let avoid = &setup.avoid;
            for root in projects {
                files.extend(read::walk(
                    root,
                    Area::Project,
                    Shape::Env,
                    &read::is_env_name,
                    avoid,
                    &mut skipped,
                ));
            }
            let suggested = read::suggested_projects(home);
            (files, projects.clone(), suggested, "places")
        }
        Scope::Folder(folder) => {
            let files = read::walk(
                folder,
                Area::Folder,
                Shape::Any,
                &|_| true,
                &setup.avoid,
                &mut skipped,
            );
            (files, vec![folder.clone()], Vec::new(), "folder")
        }
    };
    let mut drafts: Vec<Draft> = Vec::new();
    for file in &files {
        drafts.extend(drafts_of(file, known, &mut skipped));
    }
    let drafts = join_duplicates(drafts);
    let checks = match checker {
        Some(checker) => check_all(&drafts, setup, checker),
        None => drafts.iter().map(|_| None).collect(),
    };
    let mut summary = Summary::default();
    let candidates: Vec<Candidate> = drafts
        .into_iter()
        .zip(checks)
        .enumerate()
        .map(|(index, (draft, check))| {
            let candidate = finish(index + 1, draft, check);
            match candidate.group {
                Group::Works => summary.works += 1,
                Group::Doubtful => summary.doubtful += 1,
                Group::Other => summary.other += 1,
                Group::Dead => summary.dead += 1,
            }
            summary.duplicates += usize::from(candidate.duplicate);
            candidate
        })
        .collect();
    let shown = |paths: &[PathBuf]| paths.iter().map(|p| p.display().to_string()).collect();
    Report {
        schema: 1,
        scope: scope_name,
        roots: shown(&roots),
        suggested_projects: shown(&suggested),
        files: files.len(),
        checked: checker.is_some(),
        skipped,
        summary,
        candidates,
    }
}

fn finish(id: usize, draft: Draft, check: Option<Check>) -> Candidate {
    let secret = matches!(draft.class, Class::Key | Class::Login);
    let group = match (&check, secret) {
        (_, false) => Group::Other,
        (Some(check), true) if check.result == "works" => Group::Works,
        (Some(check), true) if check.result == "rejected" => Group::Dead,
        _ => Group::Doubtful,
    };
    let provider = match &check {
        Some(check) if check.result == "works" => Some(check.recipe.clone()),
        _ => draft.recipes.first().cloned(),
    };
    let duplicate = draft.origins.len() > 1;
    let from_project = draft.origins.iter().any(|o| o.area == Area::Project);
    Candidate {
        id,
        group,
        class: draft.class,
        why: draft.why,
        provider,
        recipes: draft.recipes,
        check,
        server: draft.server,
        origins: draft.origins,
        duplicate,
        from_project,
        suggested: match group {
            Group::Works => "seal",
            Group::Doubtful => "decide",
            Group::Other | Group::Dead => "skip",
        },
    }
}

/// The pieces of one file, sorted and paired into keys.
fn drafts_of(file: &FileFound, known: &[Known], skipped: &mut Skipped) -> Vec<Draft> {
    let pieces = read::pieces(file, skipped);
    let meta = std::fs::symlink_metadata(&file.path).ok();
    let stamp = Origin {
        path: file.path.display().to_string(),
        area: file.area,
        bytes: meta.as_ref().map_or(0, std::fs::Metadata::len),
        modified: meta
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs()),
        parts: Vec::new(),
    };
    let file_words: Vec<String> = file
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .map(sort::words)
        .unwrap_or_default()
        .into_iter()
        .filter(|w| {
            !matches!(
                w.as_str(),
                "env" | "txt" | "json" | "local" | "yml" | "yaml"
            )
        })
        .collect();
    let mut sorted: Vec<(Piece, Class, &'static str)> = pieces
        .into_iter()
        .filter_map(|piece| {
            let (class, why) = sort::classify(&piece, &file_words)?;
            Some((piece, class, why))
        })
        .collect();
    // A tool's file in the home folder is mostly settings: only what opens something is shown.
    let quiet = file.area == Area::Home;
    let mut drafts = Vec::new();
    let mut used = vec![false; sorted.len()];
    for (members, kind) in pairs(&sorted) {
        let (class, why) = match kind {
            PairKind::Login => (Class::Login, "a user name and its password"),
            PairKind::Oauth => (Class::Key, "a client and its refresh token"),
            PairKind::Client => (Class::Key, "a client id and its secret"),
            PairKind::Access => (Class::Key, "an access key id and its secret"),
        };
        let parts: Vec<&Piece> = members.parts.iter().map(|&i| &sorted[i].0).collect();
        let value = parts
            .iter()
            .map(|p| p.value.as_str())
            .collect::<Vec<_>>()
            .join(":");
        let server = members
            .endpoint
            .and_then(|i| read::host_name(&sorted[i].0.value))
            .or_else(|| parts.iter().find_map(|p| p.server.clone()));
        let mut hint_words: Vec<String> =
            parts.iter().flat_map(|p| sort::words(&p.label)).collect();
        if let Some(server) = &server {
            hint_words.extend(sort::words(server));
        }
        let recipes = if kind == PairKind::Login {
            Vec::new()
        } else {
            sort::guess(
                known,
                &sort::Clues {
                    first: parts[0].value.as_str(),
                    parts: parts.len(),
                    label: "",
                    hint_words,
                    file_words: file_words.clone(),
                    domain_words: parts
                        .iter()
                        .flat_map(|p| sort::domain_words(p.value.as_str()))
                        .collect(),
                },
            )
        };
        drafts.push(Draft {
            class,
            why,
            value: Secret::new(value),
            recipes,
            server,
            origins: vec![Origin {
                parts: parts.iter().map(|p| Part::of(p)).collect(),
                ..stamp.clone()
            }],
        });
        for i in members.parts.into_iter().chain(members.endpoint) {
            used[i] = true;
        }
    }
    for (index, (piece, class, why)) in sorted.drain(..).enumerate() {
        if used[index] || (quiet && class == Class::Configuration) {
            continue;
        }
        let mut hint_words = sort::words(&piece.label);
        if let Some(section) = &piece.section {
            hint_words.extend(sort::words(section));
        }
        if let Some(server) = &piece.server {
            hint_words.extend(sort::words(server));
        }
        let recipes = match class {
            Class::Key if piece.whole.is_none() => sort::guess(
                known,
                &sort::Clues {
                    first: piece.value.as_str(),
                    parts: 1,
                    label: piece.label.as_str(),
                    hint_words,
                    file_words: file_words.clone(),
                    domain_words: Vec::new(),
                },
            ),
            _ => Vec::new(),
        };
        let value = if piece.whole.is_some() {
            // A whole file is not read here, so it is told apart by its place alone.
            Secret::new(format!("\0{}", file.path.display()))
        } else {
            Secret::new(piece.value.as_str())
        };
        drafts.push(Draft {
            class,
            why,
            value,
            recipes,
            server: piece.server.clone(),
            origins: vec![Origin {
                parts: vec![Part::of(&piece)],
                ..stamp.clone()
            }],
        });
    }
    drafts
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairKind {
    Login,
    Oauth,
    Client,
    Access,
}

struct Members {
    parts: Vec<usize>,
    endpoint: Option<usize>,
}

/// Puts together the parts of one key: client id and secret (with a refresh token, Google's three),
/// an access key id and its secret (with an endpoint as the server, as R2 has), and a `.netrc` login.
/// Parts go together when they share the start of their name, or when a file has one of each.
fn pairs(sorted: &[(Piece, Class, &'static str)]) -> Vec<(Members, PairKind)> {
    let mut by_stem: BTreeMap<String, BTreeMap<Role, Vec<usize>>> = BTreeMap::new();
    let mut by_role: BTreeMap<Role, Vec<usize>> = BTreeMap::new();
    for (index, (piece, class, _)) in sorted.iter().enumerate() {
        if *class == Class::Public || piece.whole.is_some() {
            continue;
        }
        if let Some((role, stem)) = sort::role(piece) {
            // A password that is a provider's token is that provider's key, not half of a login.
            if role == Role::Password && *class != Class::Login {
                continue;
            }
            by_stem
                .entry(stem)
                .or_default()
                .entry(role)
                .or_default()
                .push(index);
            by_role.entry(role).or_default().push(index);
        }
    }
    let mut found = Vec::new();
    let mut taken: Vec<usize> = Vec::new();
    for roles in by_stem.values() {
        group_of(roles, &mut taken, &mut found);
    }
    // Names that do not share a start, as `GOOGLE_CLIENT_ID` with `OAUTH_CLIENT_SECRET`, still go
    // together when the file holds one of each.
    group_of(&by_role, &mut taken, &mut found);
    found
}

/// The keys one set of roles makes, from parts no other key took.
fn group_of(
    roles: &BTreeMap<Role, Vec<usize>>,
    taken: &mut Vec<usize>,
    found: &mut Vec<(Members, PairKind)>,
) {
    let one = |role: Role, taken: &[usize]| match roles.get(&role) {
        Some(all) if all.len() == 1 && !taken.contains(&all[0]) => Some(all[0]),
        _ => None,
    };
    if let (Some(id), Some(secret)) = (one(Role::ClientId, taken), one(Role::ClientSecret, taken)) {
        let mut parts = vec![id, secret];
        let kind = match one(Role::Refresh, taken) {
            Some(refresh) => {
                parts.push(refresh);
                PairKind::Oauth
            }
            None => PairKind::Client,
        };
        taken.extend(&parts);
        found.push((
            Members {
                parts,
                endpoint: None,
            },
            kind,
        ));
    }
    if let (Some(id), Some(secret)) = (one(Role::AccessId, taken), one(Role::AccessSecret, taken)) {
        let endpoint = one(Role::Endpoint, taken);
        taken.extend([id, secret].into_iter().chain(endpoint));
        found.push((
            Members {
                parts: vec![id, secret],
                endpoint,
            },
            PairKind::Access,
        ));
    }
    if let (Some(user), Some(password)) = (one(Role::User, taken), one(Role::Password, taken)) {
        taken.extend([user, password]);
        found.push((
            Members {
                parts: vec![user, password],
                endpoint: None,
            },
            PairKind::Login,
        ));
    }
}

/// The same key in two places is one key with two origins. Values are compared by a hash that is
/// kept only while this runs.
fn join_duplicates(drafts: Vec<Draft>) -> Vec<Draft> {
    let mut seen: HashMap<[u8; 32], usize> = HashMap::new();
    let mut joined: Vec<Draft> = Vec::new();
    for draft in drafts {
        let secret = matches!(draft.class, Class::Key | Class::Login);
        if !secret {
            joined.push(draft);
            continue;
        }
        let digest: [u8; 32] = Sha256::digest(draft.value.expose().as_bytes()).into();
        match seen.get(&digest) {
            Some(&at) => {
                let first = &mut joined[at];
                first.origins.extend(draft.origins);
                for recipe in draft.recipes {
                    if !first.recipes.contains(&recipe) && first.recipes.len() < sort::MAX_RECIPES {
                        first.recipes.push(recipe);
                    }
                }
                if first.server.is_none() {
                    first.server = draft.server;
                }
            }
            None => {
                seen.insert(digest, joined.len());
                joined.push(draft);
            }
        }
    }
    joined
}

const WORKERS: usize = 6;

fn check_all(drafts: &[Draft], setup: &Setup, checker: &Checker<'_>) -> Vec<Option<Check>> {
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<Check>>> = drafts.iter().map(|_| Mutex::new(None)).collect();
    thread::scope(|scope| {
        for _ in 0..WORKERS.min(drafts.len().max(1)) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::SeqCst);
                let Some(draft) = drafts.get(index) else {
                    return;
                };
                let check = check_one(draft, setup, checker);
                *results[index].lock().unwrap_or_else(|e| e.into_inner()) = check;
            });
        }
    });
    results
        .into_iter()
        .map(|slot| slot.into_inner().unwrap_or_else(|e| e.into_inner()))
        .collect()
}

/// Tries each provider in turn until one says the key works. A key all of them turn down is dead.
fn check_one(draft: &Draft, setup: &Setup, checker: &Checker<'_>) -> Option<Check> {
    if !matches!(draft.class, Class::Key | Class::Login) || draft.recipes.is_empty() {
        return None;
    }
    let mut results: Vec<(String, Verdict)> = Vec::new();
    for id in &draft.recipes {
        let Some(found) = setup.known.iter().find(|k| &k.id == id) else {
            continue;
        };
        let verdict = if found.recipe.self_hosted {
            match &draft.server {
                Some(host) if (setup.host_approved)(id, host) => {
                    checker(&found.recipe.at_host(host), &draft.value)
                }
                Some(_) => Verdict::NoResult("its server is not approved yet".into()),
                None => Verdict::NoResult("it needs the address of your server".into()),
            }
        } else {
            checker(&found.recipe, &draft.value)
        };
        let works = verdict.works();
        results.push((id.clone(), verdict));
        if works {
            break;
        }
    }
    let tried: Vec<String> = results.iter().map(|(id, _)| id.clone()).collect();
    let rank = |verdict: &Verdict| match verdict {
        Verdict::Works { .. } => 0,
        Verdict::Forbidden => 1,
        Verdict::NoResult(_) => 2,
        Verdict::Rejected => 3,
    };
    let (recipe, verdict) = results.into_iter().min_by_key(|(_, v)| rank(v))?;
    Some(Check {
        recipe,
        result: verdict.code(),
        reason: verdict.reason(),
        tried,
    })
}

/// A line per candidate for a person at a terminal, with paths under the home shortened to `~`.
pub fn lines(report: &Report, home: Option<&Path>) -> Vec<String> {
    let short = |path: &str| match home.and_then(|home| Path::new(path).strip_prefix(home).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.to_owned(),
    };
    let mut out = Vec::new();
    for group in [Group::Works, Group::Doubtful, Group::Dead, Group::Other] {
        let members: Vec<&Candidate> = report
            .candidates
            .iter()
            .filter(|c| c.group == group)
            .collect();
        if members.is_empty() {
            continue;
        }
        let title = match group {
            Group::Works => "Work",
            Group::Doubtful => "To decide",
            Group::Dead => "Turned down",
            Group::Other => "Configuration, documents and public keys",
        };
        out.push(format!("{title} ({})", members.len()));
        for c in members {
            let names: Vec<String> = c.origins[0]
                .parts
                .iter()
                .map(|p| {
                    p.name.clone().unwrap_or_else(|| {
                        if p.whole {
                            "whole file".into()
                        } else {
                            format!("line {}", p.line)
                        }
                    })
                })
                .collect();
            let class = format!("{:?}", c.class).to_lowercase();
            let mut line = format!(
                "  {} · {} · {class}",
                short(&c.origins[0].path),
                names.join("+"),
            );
            if let Some(provider) = &c.provider {
                line.push_str(&format!(" · {provider}"));
            }
            if let Some(check) = &c.check {
                line.push_str(&format!(" · {}", check.result));
                if let Some(reason) = &check.reason {
                    line.push_str(&format!(" ({reason})"));
                }
            }
            if c.duplicate {
                line.push_str(&format!(" · also in {} more", c.origins.len() - 1));
            }
            out.push(line);
        }
    }
    out
}

#[cfg(test)]
mod tests;
