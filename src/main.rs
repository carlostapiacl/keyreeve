use keyreeve::recipe::Recipe;
use keyreeve::simulate;
use std::process::ExitCode;
use std::{env, fs};

const HELP: &str = "\
keyreeve rotates API keys on your own machine.

Usage:
  keyreeve check <recipe.yaml>...      validate recipes
  keyreeve simulate <recipe.yaml>...   run recipes through failures and crashes, offline
  keyreeve --version
";

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
        "check" | "simulate" if !paths.is_empty() => {}
        _ => {
            eprint!("{HELP}");
            return ExitCode::from(2);
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
                "{path}: ok, {} talks only to {}",
                recipe.provider,
                recipe.hosts.join(", ")
            );
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
