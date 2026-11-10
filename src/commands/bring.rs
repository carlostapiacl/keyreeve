use super::usage;
use keyreeve::bring::{self, settings, Ignore, Scope, Setup};
use keyreeve::providers;
use keyreeve::transport::HttpTransport;
use keyreeve::verify;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// `keyreeve bring ignore`: lists the folders Bring in never looks in, and adds or removes some.
fn run_ignore(args: &[String]) -> ExitCode {
    let file = settings::file(&providers::home());
    let mut rules = match settings::load(&file) {
        Ok(rules) => rules,
        Err(problem) => {
            eprintln!("bring: {problem}, so it was left as it is");
            return ExitCode::from(2);
        }
    };
    let before = rules.clone();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let Some(rule) = rest.next() else {
            return usage();
        };
        let rule = rule.trim().to_owned();
        if rule.is_empty() {
            return usage();
        }
        match arg.as_str() {
            "--add" => {
                if !rules.contains(&rule) {
                    rules.push(rule);
                }
            }
            "--remove" => rules.retain(|r| *r != rule),
            _ => return usage(),
        }
    }
    if rules.len() > settings::MAX_RULES {
        eprintln!("bring: at most {} folders", settings::MAX_RULES);
        return ExitCode::from(2);
    }
    if rules != before {
        if let Err(problem) = settings::save(&file, &rules) {
            eprintln!("bring: {problem}");
            return ExitCode::FAILURE;
        }
    }
    if rules.is_empty() {
        println!("Bring in looks everywhere it was asked to. Add a folder with --add <folder>.");
    }
    for rule in &rules {
        println!("{rule}");
    }
    ExitCode::SUCCESS
}

/// `keyreeve bring`: reads, sorts and checks, and never moves, copies or changes a file.
pub fn run_bring(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) == Some("ignore") {
        return run_ignore(&args[1..]);
    }
    let mut places = false;
    let mut everywhere = false;
    let mut under: Vec<PathBuf> = Vec::new();
    let mut folder: Option<PathBuf> = None;
    let mut projects: Vec<PathBuf> = Vec::new();
    let (mut dry_run, mut check, mut json) = (false, false, false);
    let mut ignored: Vec<String> = Vec::new();
    let mut hashes_out: Option<PathBuf> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--places" => places = true,
            "--everywhere" => everywhere = true,
            "--under" => match rest.next() {
                Some(dir) => under.push(PathBuf::from(dir)),
                None => return usage(),
            },
            "--folder" => match rest.next() {
                Some(dir) => folder = Some(PathBuf::from(dir)),
                None => return usage(),
            },
            "--projects" => match rest.next() {
                Some(dir) => projects.push(PathBuf::from(dir)),
                None => return usage(),
            },
            "--ignore" => match rest.next() {
                Some(rule) => ignored.push(rule.clone()),
                None => return usage(),
            },
            "--hashes-out" => match rest.next() {
                Some(file) => hashes_out = Some(PathBuf::from(file)),
                None => return usage(),
            },
            "--dry-run" => dry_run = true,
            "--check" => check = true,
            "--json" => json = true,
            _ => return usage(),
        }
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let scope = if everywhere {
        if places || folder.is_some() || !projects.is_empty() {
            return usage();
        }
        let Some(home) = home.clone() else {
            eprintln!("bring: HOME is not set, so there is no home folder to look in");
            return ExitCode::from(2);
        };
        if let Some(missing) = under.iter().find(|dir| !dir.is_dir()) {
            eprintln!("bring: {} is not a folder", missing.display());
            return ExitCode::from(2);
        }
        Scope::Everywhere {
            home,
            under: under.clone(),
        }
    } else if !under.is_empty() {
        return usage();
    } else {
        match (places, folder) {
            (true, None) => {
                let Some(home) = home.clone() else {
                    eprintln!("bring: HOME is not set, so there are no usual places to look in");
                    return ExitCode::from(2);
                };
                Scope::Places {
                    home,
                    projects: projects.clone(),
                }
            }
            (false, Some(folder)) if projects.is_empty() => {
                if !folder.is_dir() {
                    eprintln!("bring: {} is not a folder", folder.display());
                    return ExitCode::from(2);
                }
                Scope::Folder(folder)
            }
            _ => return usage(),
        }
    };
    let checker = |recipe: &keyreeve::recipe::Recipe, key: &keyreeve::secret::Secret| {
        verify::check(recipe, key, &mut HttpTransport::for_recipe(recipe))
    };
    let checks = !dry_run || check;
    let mut rules = match settings::load(&settings::file(&providers::home())) {
        Ok(rules) => rules,
        Err(problem) => {
            eprintln!("bring: {problem}. Fix it, or remove it to look everywhere");
            return ExitCode::from(2);
        }
    };
    rules.extend(ignored);
    let setup = Setup::this_mac_ignoring(Ignore::new(&rules, home.as_deref()));
    let report = bring::bring_with(
        &scope,
        &setup,
        checks.then_some(&checker as &bring::Checker),
    );
    // Each key's SHA-256 goes to a file of its own that must not exist yet, never into the report or the screen.
    if let Some(file) = &hashes_out {
        if report.hashes.write_new(file).is_err() {
            eprintln!(
                "bring: {} could not be made, or is there already",
                file.display()
            );
            return ExitCode::FAILURE;
        }
    }
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(_) => return ExitCode::FAILURE,
        }
        return ExitCode::SUCCESS;
    }
    let s = &report.summary;
    println!(
        "{} files read: {} work, {} to decide, {} turned down, {} configuration, documents or public keys. {} found in more than one place.",
        report.files, s.works, s.doubtful, s.dead, s.other, s.duplicates
    );
    for line in bring::lines(&report, home.as_deref()) {
        println!("{line}");
    }
    if !report.skipped.rules.is_empty() {
        let rules: Vec<String> = report
            .skipped
            .rules
            .iter()
            .map(|(rule, count)| format!("{rule} ({count})"))
            .collect();
        println!("Folders left out: {}.", rules.join(", "));
    }
    if !report.unfinished.is_empty() {
        println!(
            "Stopped before finishing, to keep the search short. Not finished: {}. Go on with --everywhere --under <folder> for each.",
            report.unfinished.join(", ")
        );
    }
    if !report.checked {
        println!("Nothing was checked. Without --dry-run, each key is checked with one read-only request to its provider.");
    }
    if places && projects.is_empty() {
        let short = |path: &str| match home
            .as_deref()
            .and_then(|h| Path::new(path).strip_prefix(h).ok())
        {
            Some(rest) => format!("~/{}", rest.display()),
            None => path.to_owned(),
        };
        let here: Vec<String> = report.suggested_projects.iter().map(|p| short(p)).collect();
        if !here.is_empty() {
            println!(
                "No project folder was searched for .env files. Add --projects <folder> for each you want; these are here: {}",
                here.join(", ")
            );
        }
    }
    println!("No file was moved, copied or changed.");
    ExitCode::SUCCESS
}
