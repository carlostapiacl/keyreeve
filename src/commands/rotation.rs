use super::usage;
use keyreeve::{rotate, verify};
use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;

pub fn run_rotate(args: &[String]) -> ExitCode {
    let resume = args.iter().any(|arg| arg == "--resume");
    let rest: Vec<&String> = args.iter().filter(|arg| *arg != "--resume").collect();
    let mut found = HashMap::new();
    for pair in rest.chunks(2) {
        let [name, value] = pair else {
            return usage();
        };
        if !["--plan", "--vault-tool", "--journal"].contains(&name.as_str()) {
            return usage();
        }
        found.insert(name.as_str(), value.as_str());
    }
    let (Some(plan), Some(tool), Some(journal)) = (
        found.get("--plan"),
        found.get("--vault-tool"),
        found.get("--journal"),
    ) else {
        return usage();
    };
    let result = verify::Sealed::read(std::io::stdin()).and_then(|sealed| {
        rotate::run(
            Path::new(plan),
            Path::new(tool),
            Path::new(journal),
            &sealed,
            resume,
        )
    });
    match result {
        Ok(report) => {
            println!("{}", report.json());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rotate: {error}");
            ExitCode::from(2)
        }
    }
}

pub fn run_rotations(args: &[String]) -> ExitCode {
    if let [flag, journal, forget, key] = args {
        if flag != "--journal" || forget != "--forget-id" {
            return usage();
        }
        return match rotate::forget_id(Path::new(journal), key) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("rotations: {error}");
                ExitCode::from(2)
            }
        };
    }
    let [flag, journal] = args else {
        return usage();
    };
    if flag != "--journal" {
        return usage();
    }
    match rotate::statuses_json(Path::new(journal)) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rotations: {error}");
            ExitCode::from(2)
        }
    }
}
