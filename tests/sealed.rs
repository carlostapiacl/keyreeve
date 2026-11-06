//! Runs the real program with a provider of its own that needs no network, because its check is a
//! program. The key lives only on stdin, and the program says whether it arrived.
#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const CANARY: &str = "CANARY-sealed-value";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn program(home: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_keyreeve"))
        .args(args)
        .env("KEYREEVE_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn setup() -> Home {
    let number = NEXT.fetch_add(1, Ordering::SeqCst);
    let home =
        Home(std::env::temp_dir().join(format!("keyreeve-sealed-{}-{number}", std::process::id())));
    let providers = home.0.join("providers");
    fs::create_dir_all(&providers).unwrap();
    fs::create_dir_all(home.0.join("keys")).unwrap();
    fs::write(
        providers.join("local-check.yaml"),
        "schema: 1\nprovider: local-check\nname: Local check\nhosts: []\nauth:\n  type: command\n  run: { program: local-check.sh }\nactions:\n  - id: act\n    label: Act\n    run: { program: local-check.sh }\n    needs_key: true\n",
    )
    .unwrap();
    let script = providers.join("local-check.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nkey=$(cat)\nif [ \"$key\" = \"{CANARY}\" ]; then\n  if [ \"$KEYREEVE_MODE\" = check ]; then echo '{{\"result\":\"works\"}}'; else echo '{{\"message\":\"got it\"}}'; fi\nelse\n  if [ \"$KEYREEVE_MODE\" = check ]; then echo '{{\"result\":\"rejected\"}}'; else echo '{{\"message\":\"wrong\"}}'; fi\nfi\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let approved = program(&home.0, &["recipes", "approve", "local-check"], "");
    assert!(approved.status.success());
    fs::write(
        home.0.join("plan.json"),
        r#"{"keys":[{"file":"a.txt","recipe":"local-check"}]}"#,
    )
    .unwrap();
    home
}

fn verify(home: &Path, stdin: &str, sealed: bool) -> Output {
    let plan = home.join("plan.json");
    let keys = home.join("keys");
    let history = home.join("history.jsonl");
    let mut args = vec![
        "verify",
        "--plan",
        plan.to_str().unwrap(),
        "--keys",
        keys.to_str().unwrap(),
        "--history",
        history.to_str().unwrap(),
    ];
    if sealed {
        args.push("--sealed-stdin");
    }
    program(home, &args, stdin)
}

fn assert_no_value(output: &Output, home: &Path) {
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!printed.contains(CANARY), "printed the key");
    let history = fs::read_to_string(home.join("history.jsonl")).unwrap_or_default();
    assert!(!history.contains(CANARY), "the history holds the key");
}

#[test]
fn a_sealed_copy_is_checked_with_no_file_on_disk() {
    let home = setup();
    let input = format!(r#"{{"a.txt":"{CANARY}\n"}}"#);
    let output = verify(&home.0, &input, true);
    assert!(output.status.success());
    assert_no_value(&output, &home.0);
    assert!(fs::read_to_string(home.0.join("history.jsonl"))
        .unwrap()
        .contains("\"works\""));
}

#[test]
fn a_sealed_copy_wins_over_the_file() {
    let home = setup();
    fs::write(home.0.join("keys/a.txt"), "old-value").unwrap();
    let input = format!(r#"{{"a.txt":"{CANARY}"}}"#);
    assert!(verify(&home.0, &input, true).status.success());
}

#[test]
fn a_file_with_no_sealed_copy_is_read_from_disk() {
    let home = setup();
    fs::write(home.0.join("keys/a.txt"), CANARY).unwrap();
    assert!(verify(&home.0, "{}", true).status.success());
    assert!(verify(&home.0, "", false).status.success());
}

#[test]
fn a_program_of_yours_decides_the_result_of_a_check() {
    let home = setup();
    let input = r#"{"a.txt":"another-value"}"#;
    let output = verify(&home.0, input, true);
    assert!(!output.status.success());
    assert!(fs::read_to_string(home.0.join("history.jsonl"))
        .unwrap()
        .contains("\"rejected\""));
}

#[test]
fn a_path_in_a_plan_cannot_skip_an_approval() {
    let home = setup();
    let recipe = home.0.join("elsewhere.yaml");
    fs::write(
        &recipe,
        "schema: 1\nprovider: elsewhere\nhosts: [evil.example.com]\nauth: { header: Authorization }\nverify: { method: GET, path: / }\n",
    )
    .unwrap();
    fs::write(
        home.0.join("plan.json"),
        format!(
            r#"{{"keys":[{{"file":"a.txt","recipe":"{}"}}]}}"#,
            recipe.display()
        ),
    )
    .unwrap();
    let output = verify(&home.0, &format!(r#"{{"a.txt":"{CANARY}"}}"#), true);
    assert!(!output.status.success());
    let history = fs::read_to_string(home.0.join("history.jsonl")).unwrap();
    assert!(history.contains("no_result"));
    assert!(!history.contains("works"));
}

#[test]
fn a_recipe_path_typed_at_the_command_cannot_run_a_program() {
    let home = setup();
    let copy = home.0.join("elsewhere.yaml");
    fs::copy(home.0.join("providers/local-check.yaml"), &copy).unwrap();
    fs::write(home.0.join("key"), CANARY).unwrap();
    let output = program(
        &home.0,
        &[
            "verify",
            copy.to_str().unwrap(),
            "--key-file",
            home.0.join("key").to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(output.status.code(), Some(2));
    assert_no_value(&output, &home.0);
}

#[test]
fn bad_input_on_stdin_stops_without_quoting_it() {
    let home = setup();
    let output = verify(&home.0, CANARY, true);
    assert_eq!(output.status.code(), Some(2));
    assert_no_value(&output, &home.0);
}

#[test]
fn an_action_takes_its_key_from_stdin() {
    let home = setup();
    let output = program(
        &home.0,
        &["action", "local-check", "act", "--key-stdin"],
        CANARY,
    );
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "got it");
}

#[test]
fn a_temporary_ssh_key_is_private_and_goes_away() {
    let home = setup();
    // Only this test reads the variable in this process: the others pass it to their children.
    std::env::set_var("KEYREEVE_HOME", &home.0);
    let path = {
        let key = keyreeve::ssh::TempKey::write("not a real key").unwrap();
        let path = key.path().to_owned();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "not a real key\n");
        path
    };
    assert!(!path.exists());
}
