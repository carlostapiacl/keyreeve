use super::{options, usage};
use keyreeve::catalog;
use keyreeve::inventory::{self, parse_words, ExtraWords};
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
        &["--out", "--rules", "--history", "--edits", "--moved"],
    ) else {
        return usage();
    };
    let Some(out) = found.get("--out").copied() else {
        return usage();
    };
    let result = (|| -> Result<Vec<catalog::Row>, String> {
        let text = fs::read_to_string(input).map_err(|e| format!("{input}: {e}"))?;
        let mut items = catalog::parse_inventory(&text).map_err(|e| format!("{input}: {e}"))?;
        // Files moved out after sealing stay on the list, since the vault still holds them.
        if let Some(path) = found.get("--moved") {
            match fs::read_to_string(path) {
                Ok(text) => {
                    let moved =
                        catalog::parse_inventory(&text).map_err(|e| format!("{path}: {e}"))?;
                    for item in moved {
                        if !items.iter().any(|known| known.path == item.path) {
                            items.push(item);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{path}: {e}")),
            }
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
