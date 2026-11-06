use keyreeve::catalog;
use keyreeve::inventory::{self, parse_words, ExtraWords};
use keyreeve::recipe::Recipe;
use keyreeve::simulate;
use keyreeve::verify;
use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;
use std::{env, fs};

const HELP: &str = "\
keyreeve rotates API keys on your own machine.

Usage:
  keyreeve check <recipe.yaml>...
      Validate recipes.
  keyreeve simulate <recipe.yaml>...
      Run recipes through failures and crashes, offline.
  keyreeve inventory <folder> --out <file.json> [--words <file>]
      Describe a folder of keys, without their values.
  keyreeve catalog <inventory.json> --out <file.csv> [--rules <rules.yaml>]
      Give each file tags and an access level, from your rules.
  keyreeve verify <provider|recipe.yaml> --key-file <file> [--field <name>]
      Check whether a key still works, with one read-only request.
  keyreeve verify --plan <plan.yaml> --keys <folder>
      Check several keys.
  keyreeve recipes
      List the recipes that come with keyreeve.
  keyreeve --version
";

/// Reads `--name value` options after the positional argument.
fn options<'a>(args: &'a [String], names: &[&str]) -> Option<(&'a str, HashMap<String, &'a str>)> {
    let (first, rest) = args.split_first()?;
    let mut found = HashMap::new();
    for pair in rest.chunks(2) {
        let [name, value] = pair else { return None };
        if !names.contains(&name.as_str()) || first.starts_with("--") {
            return None;
        }
        found.insert(name.clone(), value.as_str());
    }
    Some((first, found))
}

fn usage() -> ExitCode {
    eprint!("{HELP}");
    ExitCode::from(2)
}

fn run_inventory(args: &[String]) -> ExitCode {
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

fn run_catalog(args: &[String]) -> ExitCode {
    let Some((input, found)) = options(args, &["--out", "--rules"]) else {
        return usage();
    };
    let Some(out) = found.get("--out").copied() else {
        return usage();
    };
    let result = (|| -> Result<Vec<catalog::Row>, String> {
        let text = fs::read_to_string(input).map_err(|e| format!("{input}: {e}"))?;
        let items = catalog::parse_inventory(&text).map_err(|e| format!("{input}: {e}"))?;
        let rules = match found.get("--rules") {
            Some(path) => {
                let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                catalog::parse_rules(&text).map_err(|e| format!("{path}: {e}"))?
            }
            None => catalog::Rules::default(),
        };
        let rows = catalog::build(&items, &rules);
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

fn run_verify(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) == Some("--plan") {
        let [_, plan, flag, keys] = args else {
            return usage();
        };
        if flag != "--keys" {
            return usage();
        }
        return match verify::run_plan(Path::new(plan), Path::new(keys)) {
            Ok(lines) => {
                let mut code = ExitCode::SUCCESS;
                for (label, verdict) in lines {
                    println!("{label}: {verdict}");
                    if !verdict.works() {
                        code = ExitCode::FAILURE;
                    }
                }
                code
            }
            Err(error) => {
                eprintln!("verify: {error}");
                ExitCode::from(2)
            }
        };
    }
    let Some((name, found)) = options(args, &["--key-file", "--field"]) else {
        return usage();
    };
    let Some(file) = found.get("--key-file").copied() else {
        return usage();
    };
    match verify::run_one(name, Path::new(file), found.get("--field").copied()) {
        Ok(verdict) => {
            println!("{file}: {verdict}");
            if verdict.works() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("verify: {error}");
            ExitCode::from(2)
        }
    }
}

const MAX_VIOLATIONS_SHOWN: usize = 20;

fn load(path: &str) -> Result<Recipe, String> {
    let text = fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
    Recipe::parse(&text).map_err(|error| format!("{path}: {error}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (command, paths) = match args.split_first() {
        Some((command, paths)) => (command.as_str(), paths),
        None => {
            print!("{HELP}");
            return ExitCode::from(2);
        }
    };
    match command {
        "--version" | "-V" => {
            println!("keyreeve {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        "--help" | "-h" | "help" => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        "inventory" => return run_inventory(paths),
        "catalog" => return run_catalog(paths),
        "verify" => return run_verify(paths),
        "recipes" => {
            for (name, recipe) in verify::builtin_recipes() {
                let what = if recipe.can_rotate() {
                    "rotate"
                } else {
                    "check"
                };
                println!("{name}: {what}, talks only to {}", recipe.hosts.join(", "));
            }
            return ExitCode::SUCCESS;
        }
        "check" | "simulate" if !paths.is_empty() => {}
        _ => {
            return usage();
        }
    }

    let mut failed = false;
    for path in paths {
        let recipe = match load(path) {
            Ok(recipe) => recipe,
            Err(error) => {
                eprintln!("{error}");
                failed = true;
                continue;
            }
        };
        if command == "check" {
            println!(
                "{path}: ok, {} talks only to {}{}",
                recipe.provider,
                recipe.hosts.join(", "),
                if recipe.can_rotate() {
                    ""
                } else {
                    ", check only"
                }
            );
            continue;
        }
        if !recipe.can_rotate() {
            println!("{path}: this recipe only checks a key, so there is nothing to simulate");
            continue;
        }
        let report = simulate::run(&recipe);
        if report.violations.is_empty() {
            println!(
                "{path}: ok, {} runs with failures and crashes, nothing broke",
                report.runs
            );
        } else {
            failed = true;
            eprintln!(
                "{path}: {} problems in {} runs",
                report.violations.len(),
                report.runs
            );
            for violation in report.violations.iter().take(MAX_VIOLATIONS_SHOWN) {
                eprintln!("  {violation}");
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
