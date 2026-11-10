use super::usage;
use keyreeve::procedure::{self, Params, Runner};
use keyreeve::secret::Secret;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroizing;

/// `keyreeve procedures [--folder <dir>] [--json]`
pub fn run_procedures(args: &[String]) -> ExitCode {
    let mut folder = procedure::default_folder();
    let mut json = false;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--folder" => match rest.next() {
                Some(path) => folder = PathBuf::from(path),
                None => return usage(),
            },
            _ => return usage(),
        }
    }
    let listed = procedure::list(&folder);
    if json {
        match serde_json::to_string(&listed) {
            Ok(text) => println!("{text}"),
            Err(_) => return ExitCode::from(2),
        }
        return ExitCode::SUCCESS;
    }
    for entry in listed {
        let params: Vec<String> = entry
            .params
            .iter()
            .map(|param| {
                if param.optional {
                    format!("[{}]", param.name)
                } else {
                    param.name.clone()
                }
            })
            .collect();
        println!(
            "{} ({}) {}\n  {}\n  sha256 {}{}",
            entry.name,
            if entry.origin == procedure::Origin::Builtin {
                "ships with keyreeve"
            } else {
                "yours"
            },
            params.join(" "),
            entry.description,
            entry.sha256,
            entry
                .problem
                .map(|problem| format!("\n  {problem}"))
                .unwrap_or_default()
        );
    }
    ExitCode::SUCCESS
}

/// `keyreeve place check|apply <procedure> --sha256 <hash> [--param name=value]... [--folder <dir>] [--vault-tool <program>]`
pub fn run_place(args: &[String]) -> ExitCode {
    let [verb, name, rest @ ..] = args else {
        return usage();
    };
    if verb != "check" && verb != "apply" {
        return usage();
    }
    let mut runner = Runner::new(procedure::default_folder());
    let mut pin = None;
    let mut params = Params::new();
    let mut rest = rest.iter();
    while let Some(flag) = rest.next() {
        let Some(value) = rest.next() else {
            return usage();
        };
        match flag.as_str() {
            "--sha256" => pin = Some(value.clone()),
            "--folder" => runner.folder = PathBuf::from(value),
            "--vault-tool" => runner.vault_tool = Some(PathBuf::from(value)),
            "--param" => {
                let Some((key, value)) = value.split_once('=') else {
                    return usage();
                };
                params.insert(key.to_owned(), value.to_owned());
            }
            _ => return usage(),
        }
    }
    let Some(pin) = pin else {
        eprintln!("place: --sha256 is the hash of the procedure a person approved");
        return ExitCode::from(2);
    };
    let result = if verb == "check" {
        runner
            .check(name, &pin, &params)
            .and_then(|found| serde_json::to_string(&found).map_err(|e| e.to_string()))
    } else {
        // The value comes on stdin, whole, and is never printed.
        let mut bytes = Zeroizing::new(Vec::new());
        if std::io::stdin().read_to_end(&mut bytes).is_err() {
            eprintln!("place: the value could not be read");
            return ExitCode::from(2);
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            eprintln!("place: the value is not text");
            return ExitCode::from(2);
        };
        if text.is_empty() {
            eprintln!("place: no value came on stdin");
            return ExitCode::from(2);
        }
        let value = Secret::new(text);
        runner
            .apply(name, &pin, &params, &value)
            .map(|()| r#"{"state":"applied"}"#.to_owned())
    };
    match result {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("place: {error}");
            ExitCode::from(1)
        }
    }
}
