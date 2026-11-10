mod commands;

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (command, paths) = match args.split_first() {
        Some((command, paths)) => (command.as_str(), paths),
        None => {
            print!("{}", commands::HELP);
            return ExitCode::from(2);
        }
    };
    match command {
        "--version" | "-V" => {
            println!("keyreeve {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        "--help" | "-h" | "help" => {
            print!("{}", commands::HELP);
            return ExitCode::SUCCESS;
        }
        "inventory" => return commands::run_inventory(paths),
        "bring" => return commands::run_bring(paths),
        "catalog" => return commands::run_catalog(paths),
        "migrate" => return commands::run_migrate(paths),
        "verify" => return commands::run_verify(paths),
        "identify" => return commands::run_identify(paths),
        "rotate" => return commands::run_rotate(paths),
        "rotations" => return commands::run_rotations(paths),
        "proxy" => return commands::run_proxy(paths),
        "check-free" => return commands::run_check_free(paths),
        "action" => return commands::run_custom_action(paths),
        "recipes" => return commands::run_recipes(paths),
        "check" | "simulate" if !paths.is_empty() => {}
        _ => {
            return commands::usage();
        }
    }
    commands::run_recipe_files(command, paths)
}
