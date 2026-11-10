//! Runs `keyreeve bring` with a made-up home folder, so it never reads the real one, and with
//! `--dry-run`, so nothing leaves this machine.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Tests run in parallel: each folder gets its own number, so one test's cleanup never removes another's.
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp(name: &str) -> Temp {
    let path = std::env::temp_dir().join(format!(
        "keyreeve-bring-cli-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    Temp(path)
}

fn write(root: &Path, path: &str, text: &str) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_keyreeve"))
        .arg("bring")
        .args(args)
        .env("HOME", home)
        .env("KEYREEVE_HOME", home.join(".keyreeve"))
        .output()
        .unwrap()
}

fn home() -> Temp {
    let home = temp("home");
    write(
        &home.0,
        ".zshrc",
        "export GH_TOKEN=ghp_CANARYzsh000000000000000000\n",
    );
    write(
        &home.0,
        "code/site/.env",
        "RESEND_API_KEY=re_CANARYsite0000000000000000\nSITE_URL=https://example.com\n",
    );
    // keyreeve's own folder is never read, even under a folder searched.
    write(
        &home.0,
        ".keyreeve/x/.env",
        "API_KEY=CANARYkeyreeve000000000\n",
    );
    home
}

#[test]
fn json_names_places_and_never_values() {
    let home = home();
    let code = home.0.join("code");
    let output = run(
        &home.0,
        &[
            "--places",
            "--projects",
            code.to_str().unwrap(),
            "--dry-run",
            "--json",
        ],
    );
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stdout.contains("CANARY") && !stderr.contains("CANARY"));
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["checked"], false);
    assert_eq!(report["scope"], "places");
    let candidates = report["candidates"].as_array().unwrap();
    let providers: Vec<&str> = candidates
        .iter()
        .filter_map(|c| c["provider"].as_str())
        .collect();
    assert_eq!(providers, ["github", "resend"]);
    assert!(candidates
        .iter()
        .any(|c| c["from_project"] == true && c["provider"] == "resend"));
}

#[test]
fn a_person_reads_a_summary_with_no_values() {
    let home = home();
    let output = run(&home.0, &["--places", "--dry-run"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("CANARY"));
    assert!(stdout.contains("~/.zshrc · GH_TOKEN · key · github"));
    assert!(stdout.contains("Nothing was checked"));
    // The project folder was not named, so it was suggested and not searched.
    assert!(stdout.contains("these are here: ~/code"));
    assert!(!stdout.contains("RESEND_API_KEY"));
    assert!(stdout.contains("No file was moved, copied or changed."));
}

#[test]
fn a_folder_and_bad_arguments() {
    let home = home();
    let output = run(
        &home.0,
        &[
            "--folder",
            home.0.join("code").to_str().unwrap(),
            "--dry-run",
            "--json",
        ],
    );
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["scope"], "folder");
    assert_eq!(report["candidates"].as_array().unwrap().len(), 2);

    assert_eq!(
        run(&home.0, &["--folder", "/no/such/folder"]).status.code(),
        Some(2)
    );
    assert_eq!(
        run(&home.0, &["--places", "--folder", "x"]).status.code(),
        Some(2)
    );
    assert_eq!(run(&home.0, &[]).status.code(), Some(2));
}
