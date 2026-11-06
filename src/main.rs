use keyreeve::catalog;
use keyreeve::inventory::{self, parse_words, ExtraWords};
use keyreeve::recipe::Recipe;
use keyreeve::simulate;
use keyreeve::verify;
use keyreeve::{identify, providers, schedule};
use std::collections::HashMap;
use std::io::Write;
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
  keyreeve catalog <inventory.json> --out <file.csv> [--rules <rules.yaml>] [--history <file>] [--edits <file>]
      Give each file tags and an access level, from your rules.
  keyreeve verify <provider|recipe.yaml> --key-file <file> [--field <name>]
      Check whether a key still works, with one read-only request.
  keyreeve verify --plan <plan.yaml> --keys <folder> [--history <file>] [--progress]
      Check several keys at once, and keep the results.
  keyreeve action <provider> <action> [--key-file <file>] [--field <name>]
      Run a button of your own, from a provider file of yours.
  keyreeve check-free [--notify] [--spanish]
      Check the keys agents can use, which need no fingerprint. For a weekly schedule.
  keyreeve identify --plan <plan.yaml> --keys <folder> --details <file>
      Ask each provider whose key this is, and keep only the fields its file declares.
  keyreeve recipes [--json]
      List the providers keyreeve knows, from what ships and from ~/.keyreeve/providers.
  keyreeve recipes approve <provider>
      Allow a provider file of yours to receive keys at the hosts it lists.
  keyreeve recipes approve-host <provider> <server>
      Allow your own server, for a provider each person runs themselves.
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
    let Some((input, found)) = options(args, &["--out", "--rules", "--history", "--edits"]) else {
        return usage();
    };
    let Some(out) = found.get("--out").copied() else {
        return usage();
    };
    let result = (|| -> Result<Vec<catalog::Row>, String> {
        let text = fs::read_to_string(input).map_err(|e| format!("{input}: {e}"))?;
        let items = catalog::parse_inventory(&text).map_err(|e| format!("{input}: {e}"))?;
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

fn run_verify(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) == Some("--plan") {
        let Some(((_, plan), rest)) = args
            .split_first_chunk::<2>()
            .map(|(pair, rest)| ((&pair[0], &pair[1]), rest))
        else {
            return usage();
        };
        let show_progress = rest.iter().any(|arg| arg == "--progress");
        let rest: Vec<String> = rest
            .iter()
            .filter(|arg| *arg != "--progress")
            .cloned()
            .collect();
        let mut found = HashMap::new();
        for pair in rest.chunks(2) {
            let [name, value] = pair else {
                return usage();
            };
            if name != "--keys" && name != "--history" {
                return usage();
            }
            found.insert(name.as_str(), value.as_str());
        }
        let Some(keys) = found.get("--keys") else {
            return usage();
        };
        let history = found.get("--history").map(Path::new);
        // One line per key, flushed, so a window can show how far it got. It holds counts alone.
        let report = |done: usize, total: usize| {
            if show_progress {
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "progress {done} {total}");
                let _ = out.flush();
            }
        };
        return match verify::run_plan_with(Path::new(plan), Path::new(keys), history, &report) {
            Ok(lines) => {
                let mut code = ExitCode::SUCCESS;
                for (label, verdict) in lines {
                    if show_progress {
                        if !verdict.works() {
                            code = ExitCode::FAILURE;
                        }
                        continue;
                    }
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

fn run_custom_action(args: &[String]) -> ExitCode {
    let [provider, action, rest @ ..] = args else {
        return usage();
    };
    let mut found = HashMap::new();
    for pair in rest.chunks(2) {
        let [name, value] = pair else {
            return usage();
        };
        if name != "--key-file" && name != "--field" {
            return usage();
        }
        found.insert(name.as_str(), value.as_str());
    }
    let file = found.get("--key-file").map(Path::new);
    match verify::run_action(provider, action, file, found.get("--field").copied()) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("action: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_check_free(args: &[String]) -> ExitCode {
    let notify = args.iter().any(|arg| arg == "--notify");
    let spanish = args.iter().any(|arg| arg == "--spanish");
    match schedule::run(&schedule::default_home()) {
        Ok(summary) => {
            println!(
                "{} checked, {} work, {} stopped working",
                summary.checked, summary.works, summary.stopped
            );
            if notify {
                schedule::notify(&summary, spanish);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("check-free: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_identify(args: &[String]) -> ExitCode {
    let [flag_plan, plan, flag_keys, keys, flag_details, details] = args else {
        return usage();
    };
    if flag_plan != "--plan" || flag_keys != "--keys" || flag_details != "--details" {
        return usage();
    }
    match identify::run_plan(Path::new(plan), Path::new(keys), Path::new(details)) {
        Ok(lines) => {
            for (label, line) in lines {
                println!("{label}: {line}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("identify: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_recipes(args: &[String]) -> ExitCode {
    match args {
        [] => {
            for entry in providers::list() {
                println!("{}", entry.line());
            }
            ExitCode::SUCCESS
        }
        [flag] if flag == "--json" => {
            println!("{}", providers::list_json());
            ExitCode::SUCCESS
        }
        [approve, name, host] if approve == "approve-host" => {
            match providers::approve_host(name, host) {
                Ok(()) => {
                    println!("{host} may now receive keys for {name}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("recipes: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [approve, name] if approve == "approve" => match providers::approve(name) {
            Ok(hosts) => {
                if hosts.is_empty() {
                    println!("{name} is approved");
                } else {
                    println!("{name} may now receive keys at {}", hosts.join(", "));
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("recipes: {error}");
                ExitCode::FAILURE
            }
        },
        _ => usage(),
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
        "identify" => return run_identify(paths),
        "check-free" => return run_check_free(paths),
        "action" => return run_custom_action(paths),
        "recipes" => return run_recipes(paths),
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
