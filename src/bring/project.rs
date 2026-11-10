//! Which project a found file belongs to: the nearest folder above it where a project starts, so keys found in
//! a hundred folders read as a few dozen projects.

use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// What says a project starts in a folder: a repository, a package of a known kind, or a `.env` at its root.
pub const MARKERS: &[&str] = &[
    ".git",
    "package.json",
    "composer.json",
    "Cargo.toml",
    "pyproject.toml",
    "go.mod",
    ".env",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Project {
    pub path: String,
    /// The folder's name.
    pub name: String,
    /// What says it is a project, or none when it is only the folder a file was in.
    pub marker: Option<&'static str>,
}

/// Finds projects without going above the folders searched, and reads each folder once.
pub struct Finder {
    bounds: Vec<PathBuf>,
    seen: HashMap<PathBuf, Option<&'static str>>,
}

impl Finder {
    /// `bounds` are the folders searched: a project is never above the one a file was found under.
    pub fn new(bounds: Vec<PathBuf>) -> Self {
        Self {
            bounds,
            seen: HashMap::new(),
        }
    }

    fn marker(&mut self, dir: &Path) -> Option<&'static str> {
        if let Some(known) = self.seen.get(dir) {
            return *known;
        }
        let found = MARKERS.iter().copied().find(|marker| {
            let path = dir.join(marker);
            match fs::symlink_metadata(&path) {
                // A `.git` can be a folder, or a file in a worktree. A `.env` is a file.
                Ok(meta) if *marker == ".git" => meta.is_dir() || meta.is_file(),
                Ok(meta) => meta.is_file(),
                Err(_) => false,
            }
        });
        self.seen.insert(dir.to_owned(), found);
        found
    }

    /// The nearest folder above `file`, its own included, with a marker, up to the folder it was found under.
    /// With none, the file's own folder. A tool's file in the home folder is its own folder's.
    pub fn project_of(&mut self, file: &Path, tool_file: bool) -> Project {
        let start = file.parent().unwrap_or(file).to_owned();
        let bound = if tool_file {
            Some(start.clone())
        } else {
            self.bounds
                .iter()
                .filter(|bound| start.starts_with(bound))
                .max_by_key(|bound| bound.components().count())
                .cloned()
        };
        let mut dir = start.clone();
        loop {
            if let Some(marker) = self.marker(&dir) {
                return Self::named(&dir, Some(marker));
            }
            match &bound {
                Some(bound) if dir != *bound => {}
                _ => break,
            }
            match dir.parent() {
                Some(parent) => dir = parent.to_owned(),
                None => break,
            }
        }
        Self::named(&start, None)
    }

    fn named(dir: &Path, marker: Option<&'static str>) -> Project {
        Project {
            path: dir.display().to_string(),
            name: dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("/")
                .to_owned(),
            marker,
        }
    }
}
