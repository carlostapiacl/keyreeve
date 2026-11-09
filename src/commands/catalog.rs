use super::{options, usage};
use keyreeve::catalog;
use keyreeve::inventory::{self, parse_words, ExtraWords};
use keyreeve::keybook::KeyBook;
use keyreeve::migrate;
use keyreeve::verify;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

pub fn run_inventory(args: &[String]) -> ExitCode {
    let Some((folder, found)) = options(args, &["--out", "--words"]) else {
        return usage();
    };
    let Some(out) = found.get("--out").copied() else {
        return usage();
    };
    let result = found
        .get("--words")
        .map_or(Ok(ExtraWords::new()), |path| {
            fs::read_to_string(path).map(|text| parse_words(&text))
        })
        .and_then(|words| inventory::scan(Path::new(folder), &words))
        .and_then(|report| {
            inventory::write_report(&report, Path::new(folder), Path::new(out))?;
            Ok(report)
        });
    match result {
        Ok(report) => {
            println!("{} files described in {out}", report.items.len());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("inventory: {error}");
            ExitCode::FAILURE
        }
    }
}

pub fn run_catalog(args: &[String]) -> ExitCode {
    let Some((input, found)) = options(
        args,
        &[
            "--out",
            "--rules",
            "--history",
            "--edits",
            "--moved",
            "--keys",
        ],
    ) else {
        return usage();
    };
    let Some(out) = found.get("--out").copied() else {
        return usage();
    };
    let result = (|| -> Result<Vec<catalog::Row>, String> {
        let text = fs::read_to_string(input).map_err(|e| format!("{input}: {e}"))?;
        let mut items = catalog::parse_inventory(&text).map_err(|e| format!("{input}: {e}"))?;
        if let Some(path) = found.get("--moved") {
            catalog::add_moved(&mut items, Path::new(path))?;
        }
        let mut rules = match found.get("--rules") {
            Some(path) => {
                let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                catalog::parse_rules(&text).map_err(|e| format!("{path}: {e}"))?
            }
            None => catalog::Rules::default(),
        };
        if let Some(path) = found.get("--edits") {
            match fs::read_to_string(path) {
                Ok(text) => {
                    rules.edits =
                        catalog::parse_edits(&text).map_err(|e| format!("{path}: {e}"))?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{path}: {e}")),
            }
        }
        if let Some(path) = found.get("--keys") {
            match fs::read_to_string(path) {
                Ok(text) => {
                    rules.book = Some(KeyBook::parse(&text).map_err(|e| format!("{path}: {e}"))?)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{path}: {e}")),
            }
        }
        let history = match found.get("--history") {
            Some(path) => match fs::read_to_string(path) {
                Ok(text) => verify::parse_history(&text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(format!("{path}: {e}")),
            },
            None => Vec::new(),
        };
        let rows = catalog::build(&items, &rules, &history);
        catalog::write_csv(&rows, Path::new(out)).map_err(|e| format!("{out}: {e}"))?;
        Ok(rows)
    })();
    match result {
        Ok(rows) => {
            let pending = rows.iter().filter(|row| !row.reviewed).count();
            println!(
                "{} files in {out}, {pending} not covered by your rules",
                rows.len()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("catalog: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `keyreeve migrate <folder> [--dry-run]`: one entry per key in `keys.toml`, from all that says what a key is.
pub fn run_migrate(args: &[String]) -> ExitCode {
    let (folder, dry_run) = match args {
        [folder] => (folder, false),
        [folder, flag] if flag == "--dry-run" => (folder, true),
        _ => return usage(),
    };
    match migrate::run(Path::new(folder), keyreeve::history::now(), dry_run) {
        Ok(report) => {
            if report.unchanged {
                println!("keys.toml already says what each key is. Nothing changed.");
                return ExitCode::SUCCESS;
            }
            println!(
                "{} identifiers kept, {} of them completed; {} files got an identifier, not offered to agents.",
                report.kept,
                report.filled,
                report.added.len()
            );
            if !report.archived.is_empty() {
                println!(
                    "Identifiers on an archived file: {}",
                    report.archived.join(", ")
                );
            }
            if !report.missing.is_empty() {
                println!(
                    "Identifiers whose file is not on the list: {}",
                    report.missing.join(", ")
                );
            }
            if !report.described_apart.is_empty() {
                println!(
                    "Identifiers that keep their own description over the app's: {}",
                    report.described_apart.join(", ")
                );
            }
            if !report.differ.is_empty() {
                println!(
                    "Identifiers whose provider is not one the list checks the file with: {}",
                    report.differ.join(", ")
                );
            }
            match report.backup {
                Some(backup) => println!(
                    "Written. What it read is copied in {}. To go back, copy keys.toml from there.",
                    backup.display()
                ),
                None => println!("Nothing written: run without --dry-run to write it."),
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("migrate: {error}");
            ExitCode::FAILURE
        }
    }
}
