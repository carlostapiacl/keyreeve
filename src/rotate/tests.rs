use super::*;
use crate::store::Store;

fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyreeve-rotate-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

use crate::transport::{Request, Response, Transport, TransportError};

const RECIPE: &str = "schema: 1\nprovider: fake\nhosts: [api.example.com]\nauth: { header: Authorization, prefix: \"Bearer \" }\ncreate: { method: POST, path: /keys, body: { name: \"{key_name}\" }, value_from: $.secret, id_from: $.id }\nverify: { method: GET, path: /me }\nrevoke: { method: DELETE, path: \"/keys/{id}\" }\n";

/// A provider that issues one key, and remembers what it was asked.
struct Fake {
    verify_status: u16,
    calls: Vec<(String, String, String)>,
}

/// Answers each verify in turn, and each delete with the same status.
struct Scripted {
    verify: std::collections::VecDeque<u16>,
    delete_status: u16,
    deleted: usize,
}

impl Transport for Scripted {
    fn send(&mut self, request: &Request) -> Result<Response, TransportError> {
        let (status, body) = match request.rendered.method.as_str() {
            "POST" => (200, r#"{"secret":"CANARY-new-0123456789","id":"new-id"}"#),
            "GET" => (self.verify.pop_front().unwrap_or(200), "{}"),
            _ => {
                self.deleted += 1;
                (self.delete_status, "{}")
            }
        };
        Ok(Response {
            headers: Vec::new(),
            status,
            body: Secret::new(body),
        })
    }
}

/// Rotates, then resumes after the overlap with these answers from the provider.
fn finish_after_overlap(verify: &[u16], delete_status: u16) -> (Outcome, usize) {
    let dir = folder(&format!("late-{delete_status}-{}", verify.len()));
    let recipe = Recipe::parse(RECIPE).unwrap();
    let mut record = Journal::open(Box::new(FileBackend::new(dir.join("j")))).unwrap();
    let mut store = store_with(&dir);
    let config = KeyConfig {
        key: "k".into(),
        admin: "k".into(),
        overlap_secs: 50,
        issued_name: "n".into(),
        known_id: Some("old-id".into()),
        handed_over: None,
        revoke_now: false,
    };
    let mut first = Scripted {
        verify: [200].into(),
        delete_status,
        deleted: 0,
    };
    let waiting = Engine {
        recipe: &recipe,
        config: &config,
        transport: &mut first,
        store: &mut store,
        journal: &mut record,
        sinks: Vec::new(),
        now: &|| 100,
    }
    .rotate()
    .unwrap();
    assert!(matches!(waiting, Outcome::AwaitingOverlap { .. }));
    let mut later = Scripted {
        verify: verify.iter().copied().collect(),
        delete_status,
        deleted: 0,
    };
    let outcome = Engine {
        recipe: &recipe,
        config: &config,
        transport: &mut later,
        store: &mut store,
        journal: &mut record,
        sinks: Vec::new(),
        now: &|| 1000,
    }
    .resume()
    .unwrap();
    fs::remove_dir_all(dir).unwrap();
    (outcome, later.deleted)
}

#[test]
fn a_new_key_that_died_during_the_overlap_keeps_the_old_one() {
    let (outcome, deleted) = finish_after_overlap(&[401], 200);
    assert_eq!(outcome, Outcome::NewKeyFailing);
    assert_eq!(deleted, 0);
}

#[test]
fn a_404_counts_only_if_the_old_key_is_really_dead() {
    assert_eq!(
        finish_after_overlap(&[200, 200], 404).0,
        Outcome::RevokePending
    );
    assert_eq!(finish_after_overlap(&[200, 401], 404).0, Outcome::Completed);
}

impl Transport for Fake {
    fn send(&mut self, request: &Request) -> Result<Response, TransportError> {
        let method = request.rendered.method.clone();
        self.calls.push((
            method.clone(),
            request.rendered.path.clone(),
            request.auth.1.expose().to_owned(),
        ));
        let (status, body) = match method.as_str() {
            "POST" => (200, r#"{"secret":"CANARY-new-0123456789","id":"new-id"}"#),
            "GET" => (self.verify_status, "{}"),
            _ => (200, "{}"),
        };
        Ok(Response {
            headers: Vec::new(),
            status,
            body: Secret::new(body),
        })
    }
}

/// Stands in for the vault's tool: one file per name.
fn tool(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let vault = dir.join("vault");
    fs::create_dir_all(&vault).unwrap();
    let path = dir.join("tool.sh");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nname=$(printf '%s' \"$2\" | tr '/#' '__')\nif [ \"$1\" = put ]; then cat > '{0}'/\"$name\"; else rm -f '{0}'/\"$name\"; fi\n",
            vault.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn rotate_with(name: &str, verify_status: u16) -> (PathBuf, Outcome, Fake, String) {
    let dir = folder(name);
    let tool = tool(&dir);
    let place = dir.join("service.env");
    fs::write(&place, "TOKEN=CANARY-old-0123456\nOTHER=stays\n").unwrap();
    let original = dir.join("key.env");
    fs::write(&original, "# note\nTOKEN=CANARY-old-0123456\n").unwrap();
    let recipe = Recipe::parse(RECIPE).unwrap();
    let plan = Plan {
        key: "dir/key.env".into(),
        recipe: "fake".into(),
        field: Some("TOKEN".into()),
        host: None,
        admin: None,
        admin_field: None,
        overlap_secs: 0,
        known_id: Some("old-id".into()),
        issued_name: "keyreeve-today".into(),
        original: Some(original.to_string_lossy().into_owned()),
        place_files: vec![place.to_string_lossy().into_owned()],
        place_actions: Vec::new(),
        expected_events: None,
    };
    let input =
        serde_json::json!({ "dir/key.env": "# note\nTOKEN=CANARY-old-0123456\n" }).to_string();
    let sealed = Sealed::read(input.as_bytes()).unwrap();
    let (mut store, mut sinks) = prepare(&plan, &recipe, &tool, &sealed, true, true).unwrap();
    let mut record = Journal::open(Box::new(FileBackend::new(dir.join("journal")))).unwrap();
    let config = KeyConfig {
        key: plan.key.clone(),
        admin: plan.key.clone(),
        overlap_secs: 0,
        issued_name: plan.issued_name.clone(),
        known_id: plan.known_id.clone(),
        handed_over: None,
        revoke_now: false,
    };
    let mut fake = Fake {
        verify_status,
        calls: Vec::new(),
    };
    let mut places: Vec<&mut dyn Sink> = Vec::new();
    for sink in &mut sinks {
        places.push(sink.as_mut());
    }
    let outcome = Engine {
        recipe: &recipe,
        config: &config,
        transport: &mut fake,
        store: &mut store,
        journal: &mut record,
        sinks: places,
        now: &|| 100,
    }
    .rotate()
    .unwrap();
    let journal = fs::read_to_string(dir.join("journal")).unwrap();
    (dir, outcome, fake, journal)
}

#[test]
fn a_rotation_reaches_the_vault_and_every_place_and_revokes_the_old_key() {
    let (dir, outcome, fake, journal) = rotate_with("whole", 200);
    assert_eq!(outcome, Outcome::Completed);
    assert_eq!(
        fs::read_to_string(dir.join("vault/dir_key.env")).unwrap(),
        "# note\nTOKEN=CANARY-new-0123456789\n"
    );
    assert_eq!(
        fs::read_to_string(dir.join("key.env")).unwrap(),
        "# note\nTOKEN=CANARY-new-0123456789\n"
    );
    assert_eq!(
        fs::read_to_string(dir.join("service.env")).unwrap(),
        "TOKEN=CANARY-new-0123456789\nOTHER=stays\n"
    );
    assert!(!dir.join("vault/dir_key.env_pending").exists());
    assert!(!dir.join("vault/dir_key.env_previous").exists());
    let revoke = fake.calls.last().unwrap();
    assert_eq!(revoke.0, "DELETE");
    assert!(revoke.1.ends_with("/keys/old-id"));
    assert_eq!(revoke.2, "Bearer CANARY-new-0123456789");
    assert!(!journal.contains("CANARY"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_new_key_that_fails_changes_nothing_anywhere() {
    let (dir, outcome, fake, journal) = rotate_with("failed", 401);
    assert!(matches!(outcome, Outcome::RolledBack { .. }));
    assert_eq!(
        fs::read_to_string(dir.join("key.env")).unwrap(),
        "# note\nTOKEN=CANARY-old-0123456\n"
    );
    assert_eq!(
        fs::read_to_string(dir.join("service.env")).unwrap(),
        "TOKEN=CANARY-old-0123456\nOTHER=stays\n"
    );
    assert!(!dir.join("vault/dir_key.env_pending").exists());
    let revoke = fake.calls.last().unwrap();
    assert!(revoke.1.ends_with("/keys/new-id"));
    assert_eq!(revoke.2, "Bearer CANARY-old-0123456");
    assert!(!journal.contains("CANARY"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_place_that_does_not_hold_the_key_stops_it_before_the_provider() {
    let dir = folder("preflight");
    let place = dir.join("service.env");
    fs::write(&place, "NOTHING=here\n").unwrap();
    let plan = Plan {
        key: "k".into(),
        recipe: "fake".into(),
        field: None,
        host: None,
        admin: None,
        admin_field: None,
        overlap_secs: 0,
        known_id: None,
        issued_name: "n".into(),
        original: None,
        place_files: vec![place.to_string_lossy().into_owned()],
        place_actions: Vec::new(),
        expected_events: None,
    };
    let sealed = Sealed::read(r#"{"k":"CANARY-old-0123456"}"#.as_bytes()).unwrap();
    let recipe = Recipe::parse(RECIPE).unwrap();
    let error = prepare(&plan, &recipe, &dir.join("tool"), &sealed, true, true)
        .err()
        .unwrap();
    assert!(error.contains("does not hold this key"));
    assert!(!error.contains("CANARY"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_short_or_embedded_key_is_refused_before_the_provider() {
    let recipe = Recipe::parse(RECIPE).unwrap();
    let short = load_sealed_key("abc", None, &recipe, true).err().unwrap();
    assert!(short.contains("too short"));
    assert!(load_sealed_key("abc", None, &recipe, false).is_ok());
    let text = "TOKEN=abcdefghijklmnopqrstuvwx\nOTHER=abcdefghijklmnopqrstuvwx-2\n";
    assert!(load_sealed_key(text, Some("TOKEN"), &recipe, true).is_ok());
}

fn store_with(dir: &Path) -> VaultStore {
    VaultStore {
        tool: tool(dir),
        key: "k".into(),
        text: Zeroizing::new("old-value-0123456789".into()),
        current: Secret::new("old-value-0123456789"),
        admin: None,
        temporary: HashMap::new(),
    }
}

#[test]
fn a_key_replaced_by_hand_does_not_revoke_the_one_before_it() {
    let run = |replaced: bool| {
        let dir = folder(if replaced { "id-dropped" } else { "id-kept" });
        let recipe = Recipe::parse(RECIPE).unwrap();
        let path = dir.join("journal");
        let mut record = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        record
            .append("k", 1, Event::Started { old_id: None })
            .unwrap();
        record
            .append("k", 2, Event::Created { new_id: "b".into() })
            .unwrap();
        record
            .append("k", 3, Event::Promoted { revoke_after: 0 })
            .unwrap();
        record.append("k", 4, Event::Completed).unwrap();
        if replaced {
            forget_id(&path, "k").unwrap();
            record = Journal::open(Box::new(FileBackend::new(&path))).unwrap();
        }
        let mut store = store_with(&dir);
        let config = KeyConfig {
            key: "k".into(),
            admin: "k".into(),
            overlap_secs: 0,
            issued_name: "n".into(),
            known_id: None,
            handed_over: None,
            revoke_now: false,
        };
        let mut fake = Fake {
            verify_status: 200,
            calls: Vec::new(),
        };
        Engine {
            recipe: &recipe,
            config: &config,
            transport: &mut fake,
            store: &mut store,
            journal: &mut record,
            sinks: Vec::new(),
            now: &|| 100,
        }
        .rotate()
        .unwrap();
        fs::remove_dir_all(dir).unwrap();
        fake.calls
            .into_iter()
            .filter(|call| call.0 == "DELETE")
            .count()
    };
    assert_eq!(run(false), 1);
    assert_eq!(run(true), 0);
}

#[test]
fn a_plan_outlives_the_settings() {
    let dir = folder("frozen");
    let journal = dir.join("rotations.jsonl");
    let plan = Plan {
        key: "k".into(),
        recipe: "fake".into(),
        field: None,
        host: None,
        admin: None,
        admin_field: None,
        overlap_secs: 0,
        known_id: None,
        issued_name: "n".into(),
        original: Some("/kept".into()),
        place_files: vec!["/first".into()],
        place_actions: Vec::new(),
        expected_events: None,
    };
    freeze_plan(&journal, &plan).unwrap();
    let later = frozen_plan(&journal, "k").unwrap();
    assert_eq!(later.place_files, ["/first"]);
    assert_eq!(later.original.as_deref(), Some("/kept"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_new_key_that_could_run_in_a_shell_never_lands() {
    let dir = folder("hostile");
    let mut store = store_with(&dir);
    for bad in [
        "short",
        "$(printf CANARY)AAAAAAAAAA",
        "abcdefghijklmnop`id`",
        "abcdefghijklmnop q",
        "abcdefghijklmnop\nX=1",
    ] {
        assert!(store.put("k#pending", &Secret::new(bad)).is_err(), "{bad}");
    }
    for good in [
        "re_abcdefghijklmnop",
        "lsv2_pt_abc-def.GHI+jk/l==",
        "AKIA1234567890ABCDEF:secret",
    ] {
        assert!(store.put("k#pending", &Secret::new(good)).is_ok(), "{good}");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_retired_place_does_not_block_finishing() {
    let dir = folder("retired");
    let recipe = Recipe::parse(RECIPE).unwrap();
    let plan = Plan {
        key: "k".into(),
        recipe: "fake".into(),
        field: None,
        host: None,
        admin: None,
        admin_field: None,
        overlap_secs: 0,
        known_id: None,
        issued_name: "n".into(),
        original: None,
        place_files: vec![dir.join("gone.env").to_string_lossy().into_owned()],
        place_actions: Vec::new(),
        expected_events: None,
    };
    let sealed = Sealed::read(r#"{"k":"old-value-0123456789"}"#.as_bytes()).unwrap();
    assert!(prepare(&plan, &recipe, &dir.join("t"), &sealed, true, true).is_err());
    let (_, sinks) = prepare(&plan, &recipe, &dir.join("t"), &sealed, false, false).unwrap();
    assert!(sinks.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

const CHECK_ONLY: &str = "schema: 1\nprovider: fake\nhosts: [api.example.com]\nauth: { header: Authorization, prefix: \"Bearer \" }\nverify: { method: GET, path: /me }\n";
const SINGLE: &str = "schema: 1\nprovider: fake\nhosts: [api.example.com]\nrotation: single\nauth: { header: Authorization, prefix: \"Bearer \" }\ncreate: { method: POST, path: /rotate, value_from: $.secret, id_from: $.id }\nverify: { method: GET, path: /me }\n";

type Calls = Vec<(String, String, String)>;

/// Runs one rotation with these provider answers. Returns what was asked and how it ended.
fn rotate_kind(
    name: &str,
    text: &str,
    handed_over: Option<&str>,
    verify: u16,
    place: Option<Box<dyn Sink>>,
) -> (Outcome, Calls, Vec<String>, String) {
    let dir = folder(name);
    let recipe = Recipe::parse(text).unwrap();
    let mut record = Journal::open(Box::new(FileBackend::new(dir.join("j")))).unwrap();
    let mut store = store_with(&dir);
    let config = KeyConfig {
        key: "k".into(),
        admin: "k".into(),
        overlap_secs: 0,
        issued_name: "n".into(),
        known_id: None,
        handed_over: handed_over.map(Secret::new),
        revoke_now: false,
    };
    let mut fake = Fake {
        verify_status: verify,
        calls: Vec::new(),
    };
    let mut place = place;
    let sinks: Vec<&mut dyn Sink> = match place.as_mut() {
        Some(sink) => vec![sink.as_mut()],
        None => Vec::new(),
    };
    let outcome = Engine {
        recipe: &recipe,
        config: &config,
        transport: &mut fake,
        store: &mut store,
        journal: &mut record,
        sinks,
        now: &|| 100,
    }
    .rotate()
    .unwrap();
    let manual = manual_of(&record, "k");
    let current = store.current.expose().to_owned();
    fs::remove_dir_all(dir).unwrap();
    (outcome, fake.calls, manual, current)
}

#[test]
fn pasting_the_key_you_already_have_is_refused() {
    let current = Secret::new("current-key-0123456789");
    assert!(check_handed_over(&current, &current)
        .unwrap_err()
        .contains("already have"));
    assert!(check_handed_over(&Secret::new("another-key-0123456789"), &current).is_ok());
    assert!(check_handed_over(&Secret::new("short"), &current).is_err());
}

#[test]
fn a_pasted_key_is_ignored_where_the_engine_makes_its_own() {
    // A provider that makes keys is asked to. The pasted value goes nowhere.
    let (outcome, calls, _, current) = rotate_kind(
        "paste-dual",
        RECIPE,
        Some("pasted-key-0123456789"),
        200,
        None,
    );
    assert_eq!(outcome, Outcome::Completed);
    assert_eq!(current, "CANARY-new-0123456789");
    assert!(calls.iter().any(|call| call.0 == "POST"));
}

#[test]
fn a_refusal_that_proves_the_key_is_alive_passes() {
    const ALIVE: &str = "schema: 1\nprovider: fake\nhosts: [api.example.com]\nauth: { header: Authorization, prefix: \"Bearer \" }\nverify: { method: GET, path: /me, alive_if: { status: 401, contains: missing_permissions } }\n";
    struct Alive;
    impl Transport for Alive {
        fn send(&mut self, _: &Request) -> Result<Response, TransportError> {
            Ok(Response {
                headers: Vec::new(),
                status: 401,
                body: Secret::new("missing_permissions"),
            })
        }
    }
    let dir = folder("alive");
    let recipe = Recipe::parse(ALIVE).unwrap();
    let mut record = Journal::open(Box::new(FileBackend::new(dir.join("j")))).unwrap();
    let mut store = store_with(&dir);
    let config = KeyConfig {
        key: "k".into(),
        admin: "k".into(),
        overlap_secs: 0,
        issued_name: "n".into(),
        known_id: None,
        handed_over: Some(Secret::new("made-by-hand-0123456789")),
        revoke_now: false,
    };
    let outcome = Engine {
        recipe: &recipe,
        config: &config,
        transport: &mut Alive,
        store: &mut store,
        journal: &mut record,
        sinks: Vec::new(),
        now: &|| 100,
    }
    .rotate()
    .unwrap();
    assert_eq!(outcome, Outcome::Completed);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_person_can_end_the_overlap_early() {
    let dir = folder("early");
    let recipe = Recipe::parse(RECIPE).unwrap();
    let mut record = Journal::open(Box::new(FileBackend::new(dir.join("j")))).unwrap();
    let mut store = store_with(&dir);
    let mut config = KeyConfig {
        key: "k".into(),
        admin: "k".into(),
        overlap_secs: 86_400,
        issued_name: "n".into(),
        known_id: Some("old-id".into()),
        handed_over: None,
        revoke_now: false,
    };
    let mut provider = Scripted {
        verify: [200, 200].into(),
        delete_status: 200,
        deleted: 0,
    };
    let waiting = Engine {
        recipe: &recipe,
        config: &config,
        transport: &mut provider,
        store: &mut store,
        journal: &mut record,
        sinks: Vec::new(),
        now: &|| 100,
    }
    .rotate()
    .unwrap();
    assert!(matches!(waiting, Outcome::AwaitingOverlap { .. }));
    config.revoke_now = true;
    let done = Engine {
        recipe: &recipe,
        config: &config,
        transport: &mut provider,
        store: &mut store,
        journal: &mut record,
        sinks: Vec::new(),
        now: &|| 101,
    }
    .resume()
    .unwrap();
    assert_eq!(done, Outcome::Completed);
    assert_eq!(provider.deleted, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_key_made_by_hand_is_tested_and_the_old_one_is_left_to_a_person() {
    let new = "made-by-hand-0123456789";
    let (outcome, calls, manual, current) = rotate_kind("hand", CHECK_ONLY, Some(new), 200, None);
    assert_eq!(outcome, Outcome::Completed);
    assert_eq!(current, new);
    assert!(
        calls.iter().all(|call| call.0 == "GET"),
        "nothing but the check"
    );
    assert_eq!(calls[0].2, format!("Bearer {new}"));
    assert_eq!(manual, ["revoke the old key at the provider"]);
}

#[test]
fn a_key_made_by_hand_that_fails_changes_nothing() {
    let (outcome, calls, manual, current) = rotate_kind(
        "hand-bad",
        CHECK_ONLY,
        Some("made-by-hand-0123456789"),
        401,
        None,
    );
    assert!(matches!(outcome, Outcome::RolledBack { .. }));
    assert_eq!(current, "old-value-0123456789");
    assert!(calls.iter().all(|call| call.0 == "GET"));
    assert_eq!(manual, ["delete the new key you made at the provider"]);
}

#[test]
fn a_single_rotation_keeps_going_since_it_cannot_go_back() {
    let (outcome, calls, manual, current) = rotate_kind("single-ok", SINGLE, None, 200, None);
    assert_eq!(outcome, Outcome::Completed);
    assert_eq!(current, "CANARY-new-0123456789");
    assert!(!calls.iter().any(|call| call.0 == "DELETE"));
    assert!(manual.is_empty());

    let (outcome, _, manual, current) = rotate_kind("single-bad", SINGLE, None, 401, None);
    assert_eq!(outcome, Outcome::Completed);
    assert_eq!(current, "CANARY-new-0123456789");
    assert_eq!(
        manual,
        ["the new key did not pass its check: look at the provider"]
    );
}

#[test]
fn a_place_that_fails_in_a_single_rotation_is_reported_and_the_rest_goes_on() {
    struct Failing;
    impl Sink for Failing {
        fn name(&self) -> &str {
            "broken"
        }
        fn update(&mut self, _: &Secret) -> Result<(), SinkError> {
            Err(SinkError)
        }
    }
    let (outcome, _, manual, current) =
        rotate_kind("single-place", SINGLE, None, 200, Some(Box::new(Failing)));
    assert_eq!(outcome, Outcome::Completed);
    assert_eq!(current, "CANARY-new-0123456789");
    assert_eq!(
        manual,
        ["broken still holds the old key: update it by hand"]
    );
}

#[test]
fn statuses_say_where_each_key_stands_with_no_value() {
    let dir = folder("status");
    let mut record = Journal::open(Box::new(FileBackend::new(dir.join("j")))).unwrap();
    record
        .append("a", 1, Event::Started { old_id: None })
        .unwrap();
    record
        .append("a", 2, Event::Promoted { revoke_after: 9 })
        .unwrap();
    record
        .append("b", 3, Event::Started { old_id: None })
        .unwrap();
    record.append("b", 4, Event::OldRevoked).unwrap();
    record.append("b", 5, Event::Completed).unwrap();
    let list = statuses(&record);
    assert_eq!(list[0].phase, "waiting");
    assert_eq!(list[0].revoke_after, Some(9));
    assert_eq!(list[1].phase, "completed");
    fs::remove_dir_all(dir).unwrap();
}
