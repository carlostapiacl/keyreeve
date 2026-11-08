use super::usage;
use keyreeve::providers;
use keyreeve::recipe::Recipe;
use keyreeve::simulate;
use std::fs;
use std::process::ExitCode;

pub fn run_recipes(args: &[String]) -> ExitCode {
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
        [show, name] if show == "show" => match providers::builtin_text(name) {
            Some(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            None => {
                eprintln!("recipes: no recipe called {name} ships with keyreeve");
                ExitCode::FAILURE
            }
        },
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

/// Validates recipes, and with `simulate` also runs each through failures and crashes.
pub fn run_recipe_files(command: &str, paths: &[String]) -> ExitCode {
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
                if recipe.is_single() {
                    ", single rotation"
                } else if recipe.can_rotate() {
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
        if recipe.is_single() {
            println!("{path}: a single rotation cannot be undone, so the simulator's guarantees do not apply");
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
