//! Every provider is a file. Those that ship are built in, and anyone can add more in
//! `~/.keyreeve/providers` with no new build. The rest of the tool knows no provider by name.

use crate::recipe::{CustomAction, Recipe};
use crate::script;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

const BUILTIN: &[(&str, &str)] = &[
    ("anthropic", include_str!("../recipes/anthropic.yaml")),
    ("aws", include_str!("../recipes/aws.yaml")),
    ("brevo", include_str!("../recipes/brevo.yaml")),
    ("calcom", include_str!("../recipes/calcom.yaml")),
    ("cloudflare", include_str!("../recipes/cloudflare.yaml")),
    ("coolify", include_str!("../recipes/coolify.yaml")),
    ("elevenlabs", include_str!("../recipes/elevenlabs.yaml")),
    ("fred", include_str!("../recipes/fred.yaml")),
    ("gemini", include_str!("../recipes/gemini.yaml")),
    ("github", include_str!("../recipes/github.yaml")),
    (
        "github-deploy",
        include_str!("../recipes/github-deploy.yaml"),
    ),
    ("gitlab", include_str!("../recipes/gitlab.yaml")),
    ("google", include_str!("../recipes/google.yaml")),
    ("hetzner", include_str!("../recipes/hetzner.yaml")),
    ("huggingface", include_str!("../recipes/huggingface.yaml")),
    ("instagram", include_str!("../recipes/instagram.yaml")),
    ("langsmith", include_str!("../recipes/langsmith.yaml")),
    ("mailerlite", include_str!("../recipes/mailerlite.yaml")),
    ("mercadopago", include_str!("../recipes/mercadopago.yaml")),
    (
        "mailerlite-classic",
        include_str!("../recipes/mailerlite-classic.yaml"),
    ),
    ("meta", include_str!("../recipes/meta.yaml")),
    ("netlify", include_str!("../recipes/netlify.yaml")),
    ("openai", include_str!("../recipes/openai.yaml")),
    ("paypal", include_str!("../recipes/paypal.yaml")),
    ("pexels", include_str!("../recipes/pexels.yaml")),
    ("plausible", include_str!("../recipes/plausible.yaml")),
    ("r2", include_str!("../recipes/r2.yaml")),
    ("resend", include_str!("../recipes/resend.yaml")),
    ("runpod", include_str!("../recipes/runpod.yaml")),
    ("sentry", include_str!("../recipes/sentry.yaml")),
    ("stripe", include_str!("../recipes/stripe.yaml")),
    ("supabase", include_str!("../recipes/supabase.yaml")),
    ("telegram", include_str!("../recipes/telegram.yaml")),
];

fn builtin() -> &'static Vec<(&'static str, Recipe)> {
    static ALL: OnceLock<Vec<(&'static str, Recipe)>> = OnceLock::new();
    ALL.get_or_init(|| {
        BUILTIN
            .iter()
            .map(|(name, text)| {
                (
                    *name,
                    Recipe::parse(text).expect("the files that ship are tested"),
                )
            })
            .collect()
    })
}

pub fn home() -> PathBuf {
    std::env::var_os("KEYREEVE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".keyreeve")))
        .unwrap_or_else(|| PathBuf::from(".keyreeve"))
}

fn local_dir() -> PathBuf {
    home().join("providers")
}

fn approved_file() -> PathBuf {
    home().join("approved-providers.json")
}

fn approved() -> BTreeMap<String, Vec<String>> {
    fs::read_to_string(approved_file())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// A local file gets a key only for the hosts you approved. Editing its hosts undoes the
/// approval, so a changed file cannot quietly send keys somewhere new. A file that runs a program
/// is pinned exactly: any change to the file or to its programs undoes the approval.
fn is_approved(recipe: &Recipe) -> bool {
    let hosts_ok = approved()
        .get(&recipe.provider)
        .is_some_and(|hosts| recipe.hosts.iter().all(|host| hosts.contains(host)));
    if !hosts_ok {
        return false;
    }
    if !recipe.runs_code() {
        return true;
    }
    match (
        fingerprint(recipe),
        approved_programs().get(&recipe.provider),
    ) {
        (Ok(now), Some(saved)) => now == *saved,
        _ => false,
    }
}

fn programs_file() -> PathBuf {
    home().join("approved-programs.json")
}

fn approved_programs() -> BTreeMap<String, String> {
    fs::read_to_string(programs_file())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// A hash of the provider's file and of every program it names.
fn fingerprint(recipe: &Recipe) -> Result<String, String> {
    let folder = local_dir();
    let mut hasher = Sha256::new();
    let file =
        fs::read(folder.join(format!("{}.yaml", recipe.provider))).map_err(|e| e.to_string())?;
    hasher.update(&file);
    let runs = recipe.auth.run.iter().chain(
        recipe
            .actions
            .iter()
            .filter_map(|action| action.run.as_ref()),
    );
    for run in runs {
        let path = script::program_path(&folder, &run.program)?;
        hasher.update(fs::read(path).map_err(|_| format!("{} was not found", run.program))?);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn programs_folder() -> PathBuf {
    local_dir()
}

fn runs_of(recipe: &Recipe) -> Vec<String> {
    recipe
        .auth
        .run
        .iter()
        .chain(
            recipe
                .actions
                .iter()
                .filter_map(|action| action.run.as_ref()),
        )
        .map(|run| run.program.clone())
        .collect::<std::collections::BTreeSet<String>>()
        .into_iter()
        .collect()
}

fn read_local(name: &str) -> Result<Recipe, String> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !valid {
        return Err(format!("{name} is not a provider name"));
    }
    let path = local_dir().join(format!("{name}.yaml"));
    let text = fs::read_to_string(&path)
        .map_err(|_| format!("{name} is not a provider keyreeve knows. See `keyreeve recipes`"))?;
    let recipe = Recipe::parse(&text).map_err(|e| format!("{name}: {e}"))?;
    if recipe.provider != name {
        return Err(format!("{name}: the file says it is {}", recipe.provider));
    }
    Ok(recipe)
}

/// A path typed at the command for this one run, which is your explicit choice. It cannot run a
/// program, because programs need an approved file of yours. Nothing read from a plan, your rules
/// or your edits comes through here, so those cannot skip an approval.
pub fn load_file(path: &str) -> Result<Recipe, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let recipe = Recipe::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    if recipe.runs_code() {
        return Err(format!(
            "{path} runs a program, so put it in the providers folder and approve it"
        ));
    }
    Ok(recipe)
}

pub fn is_path(name: &str) -> bool {
    name.contains('/') || name.ends_with(".yaml")
}

/// Finds a provider by name. A name that ships always means the file that ships.
pub fn load(name: &str) -> Result<Recipe, String> {
    if let Some((_, recipe)) = builtin().iter().find(|(builtin, _)| *builtin == name) {
        return Ok(recipe.clone());
    }
    let recipe = read_local(name)?;
    if !is_approved(&recipe) {
        let reach = if recipe.runs_code() {
            format!("run {}", runs_of(&recipe).join(", "))
        } else {
            format!("receive keys at {}", recipe.hosts.join(", "))
        };
        return Err(format!(
            "{name} is your own file, and it would {reach}. Approve it with `keyreeve recipes approve {name}`"
        ));
    }
    Ok(recipe)
}

pub fn approve(name: &str) -> Result<Vec<String>, String> {
    if builtin().iter().any(|(builtin, _)| *builtin == name) {
        return Err(format!("{name} ships with keyreeve and needs no approval"));
    }
    let recipe = read_local(name)?;
    let mut all = approved();
    all.insert(name.to_owned(), recipe.hosts.clone());
    let text = serde_json::to_string_pretty(&all).map_err(|e| e.to_string())?;
    crate::inventory::write_private(&approved_file(), &text).map_err(|e| e.to_string())?;
    if recipe.runs_code() {
        let mut programs = approved_programs();
        programs.insert(name.to_owned(), fingerprint(&recipe)?);
        let text = serde_json::to_string_pretty(&programs).map_err(|e| e.to_string())?;
        crate::inventory::write_private(&programs_file(), &text).map_err(|e| e.to_string())?;
    }
    Ok(recipe.hosts)
}

fn hosts_file() -> PathBuf {
    home().join("approved-hosts.json")
}

fn approved_hosts() -> BTreeMap<String, Vec<String>> {
    fs::read_to_string(hosts_file())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

pub fn host_approved(provider: &str, host: &str) -> bool {
    approved_hosts()
        .get(provider)
        .is_some_and(|hosts| hosts.iter().any(|h| h == host))
}

/// Your server for a provider each person runs. A check sends the key there, so it is your call,
/// and only over HTTPS.
pub fn approve_host(provider: &str, host: &str) -> Result<(), String> {
    let recipe = load(provider)?;
    if !recipe.self_hosted {
        return Err(format!("{provider} has fixed addresses"));
    }
    let name = host.split_once(':').map_or(host, |(name, _)| name);
    let port_ok = host
        .split_once(':')
        .is_none_or(|(_, port)| port.parse::<u16>().is_ok());
    let name_ok = !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !port_ok || !name_ok {
        return Err(format!("{host} is not a server address"));
    }
    let mut all = approved_hosts();
    let hosts = all.entry(provider.to_owned()).or_default();
    if !hosts.iter().any(|h| h == host) {
        hosts.push(host.to_owned());
    }
    let text = serde_json::to_string_pretty(&all).map_err(|e| e.to_string())?;
    crate::inventory::write_private(&hosts_file(), &text).map_err(|e| e.to_string())
}

/// What a provider's file suggests for a key with no rating of its own.
pub fn hints(name: &str) -> (Option<u8>, Option<u32>) {
    builtin()
        .iter()
        .find(|(id, _)| *id == name)
        .map(|(_, recipe)| recipe.clone())
        .or_else(|| read_local(name).ok())
        .map_or((None, None), |recipe| {
            (recipe.criticality_hint, recipe.rotate_every_days)
        })
}

/// The provider whose file claims this start of a key, if only one does.
pub fn kind_from_prefix(token: &str) -> Option<String> {
    builtin()
        .iter()
        .find(|(_, recipe)| {
            recipe
                .prefixes
                .iter()
                .any(|prefix| token.starts_with(prefix))
        })
        .map(|(name, _)| (*name).to_owned())
}

/// A prefix proves a provider only if that provider's own file declares it and it ships.
pub fn proven(kind: &str) -> bool {
    builtin()
        .iter()
        .any(|(name, recipe)| *name == kind && !recipe.prefixes.is_empty())
}

#[derive(Debug, Serialize)]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub dashboard: Option<String>,
    pub hosts: Vec<String>,
    pub source: &'static str,
    pub approved: bool,
    pub can_check: bool,
    pub can_identify: bool,
    pub can_rotate: bool,
    pub can_rotate_by_hand: bool,
    /// A single rotation cannot be undone, which a person should know before pressing the button.
    pub single_rotation: bool,
    pub tested: crate::recipe::Tested,
    pub env_var: Option<String>,
    pub self_hosted: bool,
    pub suggested_name: Option<String>,
    pub problem: Option<String>,
    /// The programs this file runs, shown before you approve it.
    pub programs: Vec<String>,
    pub actions: Vec<CustomAction>,
}

impl Entry {
    fn of(id: &str, recipe: &Recipe, source: &'static str, approved: bool) -> Self {
        Self {
            id: id.to_owned(),
            name: recipe.display_name().to_owned(),
            dashboard: recipe.dashboard.clone(),
            hosts: recipe.hosts.clone(),
            source,
            approved,
            can_check: recipe.verify.method == "GET",
            can_identify: recipe.identify.is_some(),
            can_rotate: recipe.can_rotate(),
            can_rotate_by_hand: recipe.can_rotate_by_hand(),
            single_rotation: recipe.is_single(),
            tested: recipe.tested.clone().unwrap_or_default(),
            env_var: recipe.env_var.clone(),
            self_hosted: recipe.self_hosted,
            suggested_name: recipe.suggested_name.clone(),
            problem: None,
            programs: runs_of(recipe),
            actions: recipe.actions.clone(),
        }
    }

    pub fn line(&self) -> String {
        if let Some(problem) = &self.problem {
            return format!("{}: {problem}", self.id);
        }
        let can: Vec<&str> = [
            (self.can_check, "check"),
            (self.can_identify, "identify"),
            (self.can_rotate, "rotate"),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, word)| *word)
        .collect();
        if !self.programs.is_empty() {
            let state = if self.approved {
                ""
            } else {
                ", needs approval"
            };
            return format!(
                "{}: {}, runs {}{state}",
                self.id,
                can.join(", "),
                self.programs.join(", ")
            );
        }
        let state = if self.source == "local" && !self.approved {
            ", needs approval"
        } else {
            ""
        };
        format!(
            "{}: {}, talks only to {}{state}",
            self.id,
            can.join(", "),
            self.hosts.join(", ")
        )
    }
}

pub fn list() -> Vec<Entry> {
    let mut entries: Vec<Entry> = builtin()
        .iter()
        .map(|(id, recipe)| Entry::of(id, recipe, "builtin", true))
        .collect();
    let mut names: Vec<String> = fs::read_dir(local_dir())
        .map(|dir| {
            dir.flatten()
                .filter_map(|file| {
                    file.file_name()
                        .to_str()
                        .and_then(|name| name.strip_suffix(".yaml"))
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    for name in names {
        if builtin().iter().any(|(builtin, _)| *builtin == name) {
            entries.push(Entry {
                problem: Some("your file has the name of one that ships, so it is ignored".into()),
                ..Entry::of(
                    &name,
                    &builtin()
                        .iter()
                        .find(|(b, _)| *b == name)
                        .expect("just found")
                        .1,
                    "local",
                    false,
                )
            });
            continue;
        }
        match read_local(&name) {
            Ok(recipe) => {
                let ok = is_approved(&recipe);
                entries.push(Entry::of(&name, &recipe, "local", ok));
            }
            Err(problem) => entries.push(Entry {
                id: name,
                name: String::new(),
                dashboard: None,
                hosts: Vec::new(),
                source: "local",
                approved: false,
                can_check: false,
                can_identify: false,
                can_rotate: false,
                can_rotate_by_hand: false,
                single_rotation: false,
                tested: Default::default(),
                env_var: None,
                self_hosted: false,
                suggested_name: None,
                problem: Some(problem),
                programs: Vec::new(),
                actions: Vec::new(),
            }),
        }
    }
    entries
}

pub fn list_json() -> String {
    serde_json::to_string(&list()).expect("the list always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// These tests change one process-wide setting, so they take turns.
    static HOME: Mutex<()> = Mutex::new(());

    fn with_home<T>(name: &str, body: impl FnOnce(&PathBuf) -> T) -> T {
        let _turn = HOME.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("keyreeve-home-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("providers")).unwrap();
        std::env::set_var("KEYREEVE_HOME", &dir);
        let result = body(&dir);
        std::env::remove_var("KEYREEVE_HOME");
        let _ = fs::remove_dir_all(&dir);
        result
    }

    const LOCAL: &str = "schema: 1\nprovider: acme\nname: Acme\nhosts: [api.acme.com]\nauth: { header: A }\nverify: { method: GET, path: /me }\n";

    #[test]
    fn everything_that_ships_only_reads_and_says_who_it_is() {
        assert_eq!(builtin().len(), BUILTIN.len());
        for (name, recipe) in builtin() {
            assert_eq!(recipe.provider, *name);
            assert_eq!(recipe.verify.method, "GET", "{name}");
            assert!(recipe.name.is_some(), "{name}");
            assert!(recipe.dashboard.is_some(), "{name}");
            assert!(!recipe.runs_code(), "{name} must not run a program");
            assert!(recipe.rotate_every_days.is_some(), "{name}");
            assert!(recipe.criticality_hint.is_some(), "{name}");
            if let Some(identify) = &recipe.identify {
                assert_eq!(identify.request.method, "GET", "{name}");
            }
        }
    }

    #[test]
    fn a_new_file_works_only_after_approval() {
        with_home("approve", |dir| {
            fs::write(dir.join("providers/acme.yaml"), LOCAL).unwrap();
            assert!(load("acme").unwrap_err().contains("Approve"));
            let entry = list().into_iter().find(|e| e.id == "acme").unwrap();
            assert!(!entry.approved);
            assert_eq!(entry.name, "Acme");

            assert_eq!(approve("acme").unwrap(), ["api.acme.com"]);
            assert_eq!(load("acme").unwrap().provider, "acme");
        });
    }

    #[test]
    fn changing_the_hosts_undoes_the_approval() {
        with_home("hosts", |dir| {
            fs::write(dir.join("providers/acme.yaml"), LOCAL).unwrap();
            approve("acme").unwrap();
            let moved = LOCAL.replace("api.acme.com", "evil.example.com");
            fs::write(dir.join("providers/acme.yaml"), moved).unwrap();
            assert!(load("acme").unwrap_err().contains("evil.example.com"));
        });
    }

    #[test]
    fn a_local_file_cannot_replace_one_that_ships() {
        with_home("shadow", |dir| {
            let evil = LOCAL
                .replace("acme", "github")
                .replace("api.github.com", "evil.example.com");
            fs::write(dir.join("providers/github.yaml"), evil).unwrap();
            assert_eq!(load("github").unwrap().hosts, ["api.github.com"]);
            assert!(approve("github").is_err());
            assert!(list()
                .iter()
                .any(|e| e.id == "github" && e.problem.is_some()));
        });
    }

    #[test]
    fn a_broken_file_is_reported_and_a_bad_name_goes_nowhere() {
        with_home("broken", |dir| {
            fs::write(dir.join("providers/bad.yaml"), "schema: 9").unwrap();
            assert!(list().iter().any(|e| e.id == "bad" && e.problem.is_some()));
            assert!(read_local("../../etc/passwd").is_err());
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_program_runs_only_as_approved_and_any_change_undoes_it() {
        use std::os::unix::fs::PermissionsExt;
        with_home("program", |dir| {
            let script_path = dir.join("providers/check.sh");
            fs::write(
                &script_path,
                "#!/bin/sh\ncat >/dev/null\necho '{\"result\":\"works\"}'\n",
            )
            .unwrap();
            fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700)).unwrap();
            let file = "schema: 1\nprovider: mine\nname: Mine\nhosts: []\nauth: { type: command, run: { program: check.sh } }\n";
            fs::write(dir.join("providers/mine.yaml"), file).unwrap();

            let error = load("mine").unwrap_err();
            assert!(error.contains("check.sh"), "{error}");
            approve("mine").unwrap();
            assert!(load("mine").is_ok());

            fs::write(&script_path, "#!/bin/sh\necho changed\n").unwrap();
            assert!(load("mine").is_err(), "changing the program undoes it");
            approve("mine").unwrap();
            assert!(load("mine").is_ok());

            let extra = format!("{file}actions: []\n");
            fs::write(dir.join("providers/mine.yaml"), extra).unwrap();
            assert!(load("mine").is_err(), "changing the file undoes it");
        });
    }

    #[test]
    fn a_server_address_is_approved_one_at_a_time() {
        with_home("hosts-approve", |_| {
            assert!(!host_approved("coolify", "panel.example.com"));
            approve_host("coolify", "panel.example.com").unwrap();
            assert!(host_approved("coolify", "panel.example.com"));
            assert!(!host_approved("coolify", "other.example.com"));
            assert!(!host_approved("plausible", "panel.example.com"));
            assert!(approve_host("github", "x.example.com").is_err());
            assert!(approve_host("coolify", "https://x.example.com").is_err());
            assert!(approve_host("coolify", "x.example.com/path").is_err());
            approve_host("coolify", "panel.example.com:8443").unwrap();
        });
    }

    #[test]
    fn prefixes_come_from_the_files() {
        assert_eq!(kind_from_prefix("ghp_abc").as_deref(), Some("github"));
        assert_eq!(kind_from_prefix("AKIAABC").as_deref(), Some("aws"));
        assert_eq!(kind_from_prefix("zzz"), None);
        assert!(proven("github"));
        assert!(!proven("meta"));
    }
}
