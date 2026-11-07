use super::{options, sealed_from_stdin, usage};
use keyreeve::{identify, schedule, verify};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

pub fn run_verify(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) == Some("--plan") {
        let Some(((_, plan), rest)) = args
            .split_first_chunk::<2>()
            .map(|(pair, rest)| ((&pair[0], &pair[1]), rest))
        else {
            return usage();
        };
        let show_progress = rest.iter().any(|arg| arg == "--progress");
        let wants_sealed = rest.iter().any(|arg| arg == "--sealed-stdin");
        let rest: Vec<String> = rest
            .iter()
            .filter(|arg| *arg != "--progress" && *arg != "--sealed-stdin")
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
        let sealed = match sealed_from_stdin(wants_sealed) {
            Ok(sealed) => sealed,
            Err(error) => {
                eprintln!("verify: {error}");
                return ExitCode::from(2);
            }
        };
        // One line per key, flushed, so a window can show how far it got. It holds counts alone.
        let report = |done: usize, total: usize| {
            if show_progress {
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "progress {done} {total}");
                let _ = out.flush();
            }
        };
        return match verify::run_plan_with(
            Path::new(plan),
            Path::new(keys),
            history,
            &sealed,
            &report,
        ) {
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
    let from_stdin = args.iter().any(|arg| arg == "--key-stdin");
    let rest: Vec<String> = args
        .iter()
        .filter(|arg| *arg != "--key-stdin")
        .cloned()
        .collect();
    let Some((name, found)) = options(&rest, &["--key-file", "--field"]) else {
        return usage();
    };
    if from_stdin {
        return verify_stdin(name, found.get("--field").copied());
    }
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

/// Checks a key's text sent on stdin, and says only the result. Exit 0 means it works, 1 that it does
/// not, and 2 that nothing could be said.
fn verify_stdin(name: &str, field: Option<&str>) -> ExitCode {
    let mut text = zeroize::Zeroizing::new(String::new());
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).is_err() {
        eprintln!("verify: could not read the key on stdin");
        return ExitCode::from(2);
    }
    match verify::run_at(name, &verify::KeySource::Text(&text), field, None) {
        Ok(verdict) => {
            println!("{}", verdict.code());
            match verdict {
                verify::Verdict::Works { .. } | verify::Verdict::Forbidden => ExitCode::SUCCESS,
                verify::Verdict::Rejected => ExitCode::FAILURE,
                verify::Verdict::NoResult(_) => ExitCode::from(2),
            }
        }
        Err(error) => {
            eprintln!("verify: {error}");
            ExitCode::from(2)
        }
    }
}

pub fn run_custom_action(args: &[String]) -> ExitCode {
    let [provider, action, rest @ ..] = args else {
        return usage();
    };
    let from_stdin = rest.iter().any(|arg| arg == "--key-stdin");
    let rest: Vec<&String> = rest.iter().filter(|arg| *arg != "--key-stdin").collect();
    let mut found = HashMap::new();
    for pair in rest.chunks(2) {
        let [name, value] = pair else {
            return usage();
        };
        if *name != "--key-file" && *name != "--field" {
            return usage();
        }
        found.insert(name.as_str(), value.as_str());
    }
    let mut text = zeroize::Zeroizing::new(String::new());
    if from_stdin && std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).is_err() {
        eprintln!("action: could not read the key on stdin");
        return ExitCode::FAILURE;
    }
    let source = if from_stdin {
        Some(verify::KeySource::Text(&text))
    } else {
        found
            .get("--key-file")
            .map(|file| verify::KeySource::File(file.into()))
    };
    match verify::run_action(
        provider,
        action,
        source.as_ref(),
        found.get("--field").copied(),
    ) {
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

pub fn run_check_free(args: &[String]) -> ExitCode {
    let notify = args.iter().any(|arg| arg == "--notify");
    let spanish = args.iter().any(|arg| arg == "--spanish");
    match schedule::run(&schedule::default_home()) {
        Ok(summary) => {
            println!(
                "{} checked, {} work, {} stopped working, {} not in the folder",
                summary.checked, summary.works, summary.stopped, summary.skipped
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

pub fn run_identify(args: &[String]) -> ExitCode {
    let wants_sealed = args.iter().any(|arg| arg == "--sealed-stdin");
    let args: Vec<&String> = args.iter().filter(|arg| *arg != "--sealed-stdin").collect();
    let [flag_plan, plan, flag_keys, keys, flag_details, details] = args.as_slice() else {
        return usage();
    };
    if *flag_plan != "--plan" || *flag_keys != "--keys" || *flag_details != "--details" {
        return usage();
    }
    let sealed = match sealed_from_stdin(wants_sealed) {
        Ok(sealed) => sealed,
        Err(error) => {
            eprintln!("identify: {error}");
            return ExitCode::from(2);
        }
    };
    match identify::run_plan_with(
        Path::new(plan),
        Path::new(keys),
        Path::new(details),
        &sealed,
    ) {
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
