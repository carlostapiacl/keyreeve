//! Tests a recipe against a simulated provider, with no network and no real keys.
//!
//! It injects provider failures and stops the process at every single operation, and again
//! at every operation of the recovery. After each stop it checks that nothing is broken.

use crate::engine::{Engine, KeyConfig, Outcome, Sink, SinkError};
use crate::journal::{Backend, Event, Journal};
use crate::recipe::Recipe;
use crate::secret::Secret;
use crate::store::{Store, StoreError};
use crate::transport::{Request, Response, Transport, TransportError};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::rc::Rc;

const KEY: &str = "sim_key";
const ADMIN: &str = "sim_admin";
const VALUE_MARK: &str = "sim-secret-";

#[derive(Debug, Default)]
pub struct Report {
    pub runs: usize,
    pub violations: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    Run,
    RunThenStop,
    Stop,
}

/// Stops every operation after a chosen count, as a crash would. An operation can stop
/// before it happens, or after it happened with the caller never finding out.
#[derive(Default)]
struct Fuse {
    left: Cell<Option<u32>>,
    after: Cell<bool>,
    blown: Cell<bool>,
}

impl Fuse {
    fn arm(&self, count: Option<u32>, after: bool) {
        self.left.set(count);
        self.after.set(after);
        self.blown.set(false);
    }

    fn gate(&self) -> Gate {
        if self.blown.get() {
            return Gate::Stop;
        }
        match self.left.get() {
            None => Gate::Run,
            Some(0) => {
                self.blown.set(true);
                if self.after.get() {
                    Gate::RunThenStop
                } else {
                    Gate::Stop
                }
            }
            Some(count) => {
                self.left.set(Some(count - 1));
                Gate::Run
            }
        }
    }
}

/// A provider built from the recipe's own steps, so it answers what the recipe asks.
pub struct MockProvider {
    recipe: Recipe,
    valid: BTreeMap<String, String>,
    issued: Vec<String>,
    admin: Option<String>,
    counter: u32,
    create_status: u16,
    create_malformed: bool,
    issue_dead_key: bool,
    verify_failures: u32,
    revoke_failures: u32,
}

impl MockProvider {
    fn new(recipe: &Recipe, admin: Option<&str>) -> Self {
        let mut mock = Self {
            recipe: recipe.clone(),
            valid: BTreeMap::new(),
            issued: Vec::new(),
            admin: admin.map(str::to_owned),
            counter: 0,
            create_status: 200,
            create_malformed: false,
            issue_dead_key: false,
            verify_failures: 0,
            revoke_failures: 0,
        };
        mock.issue();
        mock
    }

    fn issue(&mut self) -> (String, String) {
        let id = format!("sim-id-{}", self.counter);
        let value = format!("{VALUE_MARK}{}", self.counter);
        self.counter += 1;
        self.valid.insert(id.clone(), value.clone());
        self.issued.push(id.clone());
        (id, value)
    }

    fn is_valid(&self, value: &str) -> bool {
        self.valid.values().any(|valid| valid == value)
    }

    fn authorized(&self, request: &Request) -> Option<String> {
        let header = request.auth.1.expose();
        let token = header.strip_prefix(self.recipe.auth.prefix.as_str())?;
        (self.is_valid(token) || self.admin.as_deref() == Some(token)).then(|| token.to_owned())
    }

    fn handle(&mut self, request: &Request) -> Response {
        let reply = |status: u16, body: String| Response {
            status,
            body: Secret::new(body),
        };
        let recipe = self.recipe.clone();
        let sent = &request.rendered;
        let token = self.authorized(request);

        if *sent == recipe.create.render(&recipe, &[("key_name", KEY)]) {
            if token.is_none() {
                return reply(401, String::new());
            }
            if self.create_status != 200 {
                let status = self.create_status;
                if status >= 500 {
                    self.issue();
                }
                return reply(status, String::new());
            }
            let (id, value) = self.issue();
            if self.issue_dead_key {
                self.valid.remove(&id);
            }
            if self.create_malformed {
                return reply(200, "{\"unexpected\":true}".into());
            }
            let mut body = json!({});
            set_path(
                &mut body,
                recipe.create.id_from.as_deref().unwrap_or(""),
                &id,
            );
            set_path(
                &mut body,
                recipe.create.value_from.as_deref().unwrap_or(""),
                &value,
            );
            let status = recipe.create.expect.unwrap_or(200);
            return reply(status, body.to_string());
        }
        for id in self.issued.clone() {
            if *sent == recipe.revoke.render(&recipe, &[("id", id.as_str())]) {
                if self.revoke_failures > 0 {
                    self.revoke_failures -= 1;
                    return reply(500, String::new());
                }
                if token.is_none() {
                    return reply(401, String::new());
                }
                return match self.valid.remove(&id) {
                    Some(_) => reply(recipe.revoke.expect.unwrap_or(200), String::new()),
                    None => reply(404, String::new()),
                };
            }
        }
        for id in self.issued.clone() {
            if *sent == recipe.verify.render(&recipe, &[("id", id.as_str())]) {
                if self.verify_failures > 0 {
                    self.verify_failures -= 1;
                    return reply(401, String::new());
                }
                return match token {
                    Some(_) => reply(recipe.verify.expect.unwrap_or(200), String::new()),
                    None => reply(401, String::new()),
                };
            }
        }
        reply(404, String::new())
    }
}

fn set_path(root: &mut Value, path: &str, value: &str) {
    let segments: Vec<&str> = path.split('.').skip(1).collect();
    let mut current = root;
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        let next_is_index = segments
            .get(index + 1)
            .is_some_and(|next| next.parse::<usize>().is_ok());
        let empty = if next_is_index { json!([]) } else { json!({}) };
        if let Ok(position) = segment.parse::<usize>() {
            let items = current.as_array_mut().expect("the parent is an array");
            while items.len() <= position {
                items.push(Value::Null);
            }
            if last {
                items[position] = json!(value);
                return;
            }
            if items[position].is_null() {
                items[position] = empty;
            }
            current = &mut items[position];
        } else {
            let map = current.as_object_mut().expect("the parent is an object");
            if last {
                map.insert((*segment).to_owned(), json!(value));
                return;
            }
            current = map.entry((*segment).to_owned()).or_insert(empty);
        }
    }
}

struct SimTransport {
    mock: Rc<RefCell<MockProvider>>,
    fuse: Rc<Fuse>,
}

impl Transport for SimTransport {
    fn send(&mut self, request: &Request) -> Result<Response, TransportError> {
        match self.fuse.gate() {
            Gate::Stop => Err(TransportError::Failed),
            Gate::Run => Ok(self.mock.borrow_mut().handle(request)),
            Gate::RunThenStop => {
                self.mock.borrow_mut().handle(request);
                Err(TransportError::Failed)
            }
        }
    }
}

struct SimStore {
    values: Rc<RefCell<HashMap<String, Secret>>>,
    fuse: Rc<Fuse>,
}

impl SimStore {
    fn stopped() -> StoreError {
        StoreError("stopped".into())
    }
}

impl Store for SimStore {
    fn get(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        if self.fuse.blown.get() {
            return Err(Self::stopped());
        }
        Ok(self.values.borrow().get(name).cloned())
    }

    fn put(&mut self, name: &str, value: &Secret) -> Result<(), StoreError> {
        let gate = self.fuse.gate();
        if gate != Gate::Stop {
            self.values
                .borrow_mut()
                .insert(name.to_owned(), value.clone());
        }
        match gate {
            Gate::Run => Ok(()),
            _ => Err(Self::stopped()),
        }
    }

    fn delete(&mut self, name: &str) -> Result<(), StoreError> {
        let gate = self.fuse.gate();
        if gate != Gate::Stop {
            self.values.borrow_mut().remove(name);
        }
        match gate {
            Gate::Run => Ok(()),
            _ => Err(Self::stopped()),
        }
    }
}

struct SimSink {
    name: String,
    value: Rc<RefCell<Secret>>,
    failures: Rc<Cell<u32>>,
    fuse: Rc<Fuse>,
}

impl Sink for SimSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn update(&mut self, value: &Secret) -> Result<(), SinkError> {
        if self.failures.get() > 0 {
            self.failures.set(self.failures.get() - 1);
            return Err(SinkError);
        }
        let gate = self.fuse.gate();
        if gate != Gate::Stop {
            *self.value.borrow_mut() = value.clone();
        }
        match gate {
            Gate::Run => Ok(()),
            _ => Err(SinkError),
        }
    }
}

struct SimBackend {
    lines: Rc<RefCell<Vec<String>>>,
    fuse: Rc<Fuse>,
}

impl Backend for SimBackend {
    fn read_lines(&self) -> io::Result<Vec<String>> {
        Ok(self.lines.borrow().clone())
    }

    fn append(&mut self, line: &str) -> io::Result<()> {
        let gate = self.fuse.gate();
        if gate != Gate::Stop {
            self.lines.borrow_mut().push(line.to_owned());
        }
        match gate {
            Gate::Run => Ok(()),
            _ => Err(io::Error::other("stopped")),
        }
    }
}

struct SimSinkState {
    name: String,
    value: Rc<RefCell<Secret>>,
    failures: Rc<Cell<u32>>,
}

struct World {
    recipe: Recipe,
    config: KeyConfig,
    mock: Rc<RefCell<MockProvider>>,
    values: Rc<RefCell<HashMap<String, Secret>>>,
    sinks: Vec<SimSinkState>,
    lines: Rc<RefCell<Vec<String>>>,
    fuse: Rc<Fuse>,
    clock: Rc<Cell<u64>>,
    messages: Vec<String>,
}

impl World {
    fn new(recipe: &Recipe, overlap_secs: u64, self_admin: bool) -> Self {
        let admin_value = "sim-admin-token";
        let mock = MockProvider::new(recipe, (!self_admin).then_some(admin_value));
        let first = Secret::new(format!("{VALUE_MARK}0"));
        let mut values = HashMap::new();
        values.insert(KEY.to_owned(), first.clone());
        if !self_admin {
            values.insert(ADMIN.to_owned(), Secret::new(admin_value));
        }
        // The journal already knows the first key, so the old key has an id to revoke.
        let seeded = |event: Event, rotation: u64| {
            serde_json::to_string(&crate::journal::Entry {
                rotation,
                key: KEY.to_owned(),
                at: 0,
                event,
            })
            .expect("an entry always serializes")
        };
        let lines = vec![
            seeded(Event::Started { old_id: None }, 1),
            seeded(
                Event::Created {
                    new_id: "sim-id-0".into(),
                },
                1,
            ),
            seeded(Event::Promoted { revoke_after: 0 }, 1),
            seeded(Event::Completed, 1),
        ];
        Self {
            recipe: recipe.clone(),
            config: KeyConfig {
                key: KEY.to_owned(),
                admin: if self_admin { KEY } else { ADMIN }.to_owned(),
                overlap_secs,
            },
            mock: Rc::new(RefCell::new(mock)),
            values: Rc::new(RefCell::new(values)),
            sinks: ["hosting", "ci"]
                .iter()
                .map(|name| SimSinkState {
                    name: (*name).to_owned(),
                    value: Rc::new(RefCell::new(first.clone())),
                    failures: Rc::new(Cell::new(0)),
                })
                .collect(),
            lines: Rc::new(RefCell::new(lines)),
            fuse: Rc::new(Fuse::default()),
            clock: Rc::new(Cell::new(1_000)),
            messages: Vec::new(),
        }
    }

    /// Runs a fresh process over the saved state, as a restart would.
    fn run(&mut self, resume: bool) -> Option<Outcome> {
        let mut transport = SimTransport {
            mock: self.mock.clone(),
            fuse: self.fuse.clone(),
        };
        let mut store = SimStore {
            values: self.values.clone(),
            fuse: self.fuse.clone(),
        };
        let mut journal = Journal::open(Box::new(SimBackend {
            lines: self.lines.clone(),
            fuse: self.fuse.clone(),
        }))
        .expect("the simulated journal stays readable");
        let mut sinks: Vec<SimSink> = self
            .sinks
            .iter()
            .map(|state| SimSink {
                name: state.name.clone(),
                value: state.value.clone(),
                failures: state.failures.clone(),
                fuse: self.fuse.clone(),
            })
            .collect();
        let clock = self.clock.clone();
        let now = move || clock.get();
        let mut engine = Engine {
            recipe: &self.recipe,
            config: &self.config,
            transport: &mut transport,
            store: &mut store,
            journal: &mut journal,
            sinks: sinks.iter_mut().map(|sink| sink as &mut dyn Sink).collect(),
            now: &now,
        };
        let result = if resume {
            engine.resume()
        } else {
            engine.rotate()
        };
        match result {
            Ok(outcome) => {
                self.messages.push(format!("{outcome:?}"));
                Some(outcome)
            }
            Err(error) => {
                self.messages.push(error.to_string());
                None
            }
        }
    }

    /// Clears the faults and keeps resuming until the rotation closes.
    fn settle(&mut self) -> Result<(), String> {
        self.fuse.arm(None, false);
        {
            let mut mock = self.mock.borrow_mut();
            mock.verify_failures = 0;
            mock.revoke_failures = 0;
            mock.create_status = 200;
            mock.create_malformed = false;
            mock.issue_dead_key = false;
        }
        for sink in &self.sinks {
            sink.failures.set(0);
        }
        for _ in 0..4 {
            self.clock.set(self.clock.get() + 1_000_000);
            match self.run(true) {
                Some(Outcome::NothingToDo) => return Ok(()),
                Some(_) => {}
                None => return Err("resume returned an error with no faults left".into()),
            }
        }
        Err("the rotation never closed".into())
    }

    /// Must hold at every instant: everything in use can still authenticate.
    fn check_safe(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mock = self.mock.borrow();
        let stored_ok = self
            .values
            .borrow()
            .get(KEY)
            .is_some_and(|value| mock.is_valid(value.expose()));
        if !stored_ok {
            problems.push("the stored key does not work".to_owned());
        }
        for sink in &self.sinks {
            if !mock.is_valid(sink.value.borrow().expose()) {
                problems.push(format!("{} holds a key that does not work", sink.name));
            }
        }
        problems
    }

    /// Must hold when a rotation closes.
    fn check_final(&self) -> Vec<String> {
        let mut problems = self.check_safe();
        let values = self.values.borrow();
        let mock = self.mock.borrow();
        let stored = values.get(KEY).map(|value| value.expose().to_owned());
        for sink in &self.sinks {
            if stored.as_deref() != Some(sink.value.borrow().expose()) {
                problems.push(format!("{} differs from the stored key", sink.name));
            }
        }
        for name in values.keys().filter(|name| name.contains('#')) {
            problems.push(format!("{name} was left in the store"));
        }
        let text = self.lines.borrow().join("\n");
        if mock.valid.len() != 1 && !text.contains("manual_action") {
            problems.push(format!(
                "{} valid keys remain and nobody was told",
                mock.valid.len()
            ));
        }
        if text.contains(VALUE_MARK) {
            problems.push("a key value reached the journal".to_owned());
        }
        if self
            .messages
            .iter()
            .any(|message| message.contains(VALUE_MARK))
        {
            problems.push("a key value reached an error or outcome".to_owned());
        }
        problems
    }
}

type Fault = fn(&World);

fn scenarios() -> Vec<(&'static str, Fault)> {
    vec![
        ("no fault", |_| {}),
        ("create refused", |w| {
            w.mock.borrow_mut().create_status = 403;
        }),
        ("create fails with a server error", |w| {
            w.mock.borrow_mut().create_status = 500;
        }),
        ("create returns an unreadable answer", |w| {
            w.mock.borrow_mut().create_malformed = true;
        }),
        ("the provider issues a key that does not work", |w| {
            w.mock.borrow_mut().issue_dead_key = true;
        }),
        ("verify fails", |w| {
            w.mock.borrow_mut().verify_failures = 1;
        }),
        ("verify fails and the new key cannot be revoked", |w| {
            let mut mock = w.mock.borrow_mut();
            mock.verify_failures = 1;
            mock.revoke_failures = 1;
        }),
        ("first service fails", |w| w.sinks[0].failures.set(1)),
        ("second service fails", |w| w.sinks[1].failures.set(1)),
        ("second service fails and also fails to restore", |w| {
            w.sinks[1].failures.set(2);
        }),
        ("the old key cannot be revoked", |w| {
            w.mock.borrow_mut().revoke_failures = 1;
        }),
    ]
}

/// Runs every scenario and every crash point. An empty `violations` means the recipe and the
/// engine kept their promises against the simulated provider, and says nothing yet about
/// whether the real provider behaves as the recipe describes.
pub fn run(recipe: &Recipe) -> Report {
    let mut report = Report::default();
    for overlap in [0_u64, 3_600] {
        for self_admin in [false, true] {
            let label = format!(
                "overlap {overlap}s, {} credential",
                if self_admin { "self" } else { "admin" }
            );
            run_scenarios(recipe, overlap, self_admin, &label, &mut report);
            run_crashes(recipe, overlap, self_admin, &label, &mut report);
        }
    }
    report
}

fn run_scenarios(
    recipe: &Recipe,
    overlap: u64,
    self_admin: bool,
    label: &str,
    report: &mut Report,
) {
    for (name, fault) in scenarios() {
        let mut world = World::new(recipe, overlap, self_admin);
        fault(&world);
        world.run(false);
        report.runs += 1;
        let mut problems = world.check_safe();
        if let Err(problem) = world.settle() {
            problems.push(problem);
        }
        problems.extend(world.check_final());
        for problem in problems {
            report
                .violations
                .push(format!("{label}, {name}: {problem}"));
        }
    }
}

fn run_crashes(recipe: &Recipe, overlap: u64, self_admin: bool, label: &str, report: &mut Report) {
    for after in [false, true] {
        let mut first = 0_u32;
        loop {
            // A crash at `first`, then a clean recovery.
            let mut world = World::new(recipe, overlap, self_admin);
            world.fuse.arm(Some(first), after);
            world.run(false);
            report.runs += 1;
            let crashed = world.fuse.blown.get();
            let stage = format!("{label}, crash at operation {first} (after: {after})");
            let mut problems = world.check_safe();
            if let Err(problem) = world.settle() {
                problems.push(problem);
            }
            problems.extend(world.check_final());
            for problem in problems {
                report.violations.push(format!("{stage}: {problem}"));
            }
            if !crashed {
                break;
            }

            // The same crash, then another crash at each step of the recovery.
            let mut second = 0_u32;
            loop {
                let mut world = World::new(recipe, overlap, self_admin);
                world.fuse.arm(Some(first), after);
                world.run(false);
                world.clock.set(world.clock.get() + 1_000_000);
                world.fuse.arm(Some(second), after);
                world.run(true);
                report.runs += 1;
                let crashed_again = world.fuse.blown.get();
                let stage = format!("{stage}, crash in recovery at {second}");
                let mut problems = world.check_safe();
                if let Err(problem) = world.settle() {
                    problems.push(problem);
                }
                problems.extend(world.check_final());
                for problem in problems {
                    report.violations.push(format!("{stage}: {problem}"));
                }
                if !crashed_again {
                    break;
                }
                second += 1;
            }
            first += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECIPE: &str = r#"
schema: 1
provider: example
hosts: [api.example.com]
auth: { header: Authorization, prefix: "Bearer " }
create:
  method: POST
  path: /v1/keys
  body: { name: "{key_name}" }
  value_from: $.data.0.secret
  id_from: $.data.0.id
verify: { method: GET, path: /v1/me }
revoke: { method: DELETE, path: "/v1/keys/{id}" }
"#;

    fn recipe() -> Recipe {
        Recipe::parse(RECIPE).unwrap()
    }

    #[test]
    fn the_engine_survives_every_scenario_and_crash() {
        let report = run(&recipe());
        assert!(
            report.violations.is_empty(),
            "{} violations, first: {:#?}",
            report.violations.len(),
            &report.violations[..report.violations.len().min(10)]
        );
        assert!(report.runs > 1_000, "only {} runs", report.runs);
    }

    #[test]
    fn a_clean_rotation_replaces_the_key_everywhere_and_revokes_the_old_one() {
        let mut world = World::new(&recipe(), 0, false);
        assert_eq!(world.run(false), Some(Outcome::Completed));
        assert_eq!(world.mock.borrow().valid.len(), 1);
        assert!(!world.mock.borrow().is_valid(&format!("{VALUE_MARK}0")));
        assert_eq!(
            world.values.borrow()[KEY].expose(),
            format!("{VALUE_MARK}1")
        );
        assert_eq!(
            world.sinks[0].value.borrow().expose(),
            format!("{VALUE_MARK}1")
        );
        assert!(world.check_final().is_empty());
    }

    #[test]
    fn overlap_keeps_both_keys_until_it_ends() {
        let mut world = World::new(&recipe(), 3_600, false);
        assert!(matches!(
            world.run(false),
            Some(Outcome::AwaitingOverlap { .. })
        ));
        assert_eq!(world.mock.borrow().valid.len(), 2);
        assert!(matches!(
            world.run(true),
            Some(Outcome::AwaitingOverlap { .. })
        ));
        world.clock.set(world.clock.get() + 3_600);
        assert_eq!(world.run(true), Some(Outcome::Completed));
        assert_eq!(world.mock.borrow().valid.len(), 1);
    }

    #[test]
    fn a_failed_verify_keeps_the_old_key_and_touches_no_service() {
        let mut world = World::new(&recipe(), 0, false);
        world.mock.borrow_mut().verify_failures = 1;
        assert!(matches!(world.run(false), Some(Outcome::RolledBack { .. })));
        assert!(world.mock.borrow().is_valid(&format!("{VALUE_MARK}0")));
        assert_eq!(world.mock.borrow().valid.len(), 1);
        assert_eq!(
            world.sinks[1].value.borrow().expose(),
            format!("{VALUE_MARK}0")
        );
    }

    #[test]
    fn a_new_key_is_not_revoked_while_a_service_still_holds_it() {
        let mut world = World::new(&recipe(), 0, false);
        world.sinks[1].failures.set(1);
        assert!(matches!(world.run(false), Some(Outcome::RolledBack { .. })));
        assert!(world.check_final().is_empty());

        let mut world = World::new(&recipe(), 0, false);
        world.sinks[1].failures.set(2);
        assert!(matches!(
            world.run(false),
            Some(Outcome::RollbackBlocked { .. })
        ));
        assert_eq!(world.mock.borrow().valid.len(), 2);
        assert!(world.check_safe().is_empty());
    }

    #[test]
    fn a_second_rotation_is_refused_while_one_is_open() {
        let mut world = World::new(&recipe(), 3_600, false);
        world.run(false);
        assert_eq!(world.run(false), None);
        assert!(world.messages.last().unwrap().contains("unfinished"));
    }

    #[test]
    fn the_checks_catch_a_broken_state() {
        let world = World::new(&recipe(), 0, false);
        world.mock.borrow_mut().valid.clear();
        world.mock.borrow_mut().issue();
        assert!(!world.check_safe().is_empty());

        let world = World::new(&recipe(), 0, false);
        *world.sinks[0].value.borrow_mut() = Secret::new("revoked-long-ago");
        assert!(!world.check_safe().is_empty());

        let mut world = World::new(&recipe(), 0, false);
        world.run(false);
        world
            .values
            .borrow_mut()
            .insert(format!("{KEY}#pending"), Secret::new("x"));
        world.messages.push(format!("{VALUE_MARK}9"));
        let problems = world.check_final();
        assert!(problems.iter().any(|p| p.contains("left in the store")));
        assert!(problems.iter().any(|p| p.contains("reached an error")));
    }
}
