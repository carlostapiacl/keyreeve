//! A home folder and a folder of keys made up for each test, under the system's temporary folder. No
//! test reads the real home or keyreeve's own folder, and no check leaves this process.

use super::*;
use std::fs;
use std::sync::atomic::AtomicUsize;

/// Every value below has this in it, so one search proves none reached the report.
const CANARY: &str = "CANARY";

struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "keyreeve-bring-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, path: &str, text: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn setup() -> Setup<'static> {
    Setup {
        known: sort::tests::test_known(),
        host_approved: &|_, _| false,
        avoid: Vec::new(),
        budget: Budget::EVERYWHERE,
    }
}

const OPENAI: &str = "sk-proj-CANARYopenai000000000000";

fn fake_home() -> Temp {
    let home = Temp::new("home");
    home.write(
        ".aws/credentials",
        "[default]\naws_access_key_id = AKIACANARY0000000001\naws_secret_access_key = CANARYawsSecret00000000000000000000001\n",
    );
    home.write(
        ".aws/config",
        "[default]\nregion = us-east-1\noutput = json\n",
    );
    home.write(
        ".config/gcloud/application_default_credentials.json",
        r#"{"client_id":"764-CANARYadc.apps.googleusercontent.com","client_secret":"d-CANARYadcSecret00000","refresh_token":"1//CANARYadcRefresh000000","type":"authorized_user"}"#,
    );
    home.write(
        ".config/gh/hosts.yml",
        "github.com:\n    oauth_token: gho_CANARYgh0000000000000000000\n    user: someone\n    git_protocol: https\n",
    );
    home.write(
        ".ssh/id_ed25519",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARYsshbody\n-----END OPENSSH PRIVATE KEY-----\n",
    );
    home.write(".ssh/id_ed25519.pub", "ssh-ed25519 AAAACANARYpub me@host\n");
    home.write(
        ".ssh/known_hosts",
        "github.com ssh-ed25519 AAAACANARYknown\n",
    );
    home.write(
        ".ssh/config",
        "Host x\n  IdentityFile ~/.ssh/CANARYconfig\n",
    );
    home.write(
        ".netrc",
        "machine example.com\n  login me\n  password CANARYnetrcPassword1\n",
    );
    home.write(
        ".npmrc",
        "//registry.npmjs.org/:_authToken=npm_CANARYnpm00000000000000000\nsave-exact=true\n",
    );
    home.write(
        ".pypirc",
        "[pypi]\nusername = __token__\npassword = pypi-CANARYpypi00000000000000000\n",
    );
    home.write(
        ".docker/config.json",
        r#"{"auths":{"https://index.docker.io/v1/":{"auth":"Q0FOQVJZdXNlcjpwYXNz"}},"credsStore":"desktop"}"#,
    );
    home.write(
        ".zshrc",
        &format!(
            "alias ll='ls -l'\nexport PATH=\"$PATH:/opt/bin\"\nexport OPENAI_API_KEY={OPENAI}\nNOT_EXPORTED=CANARYnotexported0000000\nexport EDITOR=vim\n"
        ),
    );
    // A project, with what a project has around its .env.
    home.write(
        "code/app/.env",
        &format!(
            "\
# bot
TELEGRAM_BOT_TOKEN=123456789:CANARYtelegram0000000000000000000
TELEGRAM_CHAT_ID=-1001234567
OPENAI_API_KEY=\"{OPENAI}\"
R2_ACCESS_KEY_ID=CANARYr2id000000000000000000000
R2_SECRET_ACCESS_KEY=CANARYr2secret0000000000000000000000000000
R2_ENDPOINT=https://abc123.r2.cloudflarestorage.com
GOOGLE_CLIENT_ID=12345-CANARY.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-CANARYgoogle000000000
GOOGLE_REFRESH_TOKEN=1//CANARYrefresh0000000000000000
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJCANARYanon00000000000000000
SITE_URL=https://example.com
EMPTY=
PLACEHOLDER=your-key-here
"
        ),
    );
    home.write("code/app/.env.example", "API_KEY=CANARYexample0000000000\n");
    home.write(
        "code/app/node_modules/pkg/.env",
        "API_KEY=CANARYdependency000000000\n",
    );
    home.write(".hidden/x/.env", "API_KEY=CANARYhidden00000000000\n");
    home.write("code/app/.git/.env", "API_KEY=CANARYgit000000000000000\n");
    home.write(
        "code/a/b/c/d/e/f/g/.env",
        "API_KEY=CANARYdeep00000000000000\n",
    );
    home.write(
        "code/big/.env",
        &format!("API_KEY=CANARYbig\n{}", "# padding\n".repeat(30_000)),
    );
    fs::create_dir_all(home.0.join("Desktop")).unwrap();
    home
}

fn places(home: &Temp) -> Scope {
    Scope::Places {
        home: home.0.clone(),
        projects: vec![home.0.join("code")],
    }
}

/// Answers for providers: these keys work, these are turned down, and every call is counted.
fn fake_checker(calls: &AtomicUsize) -> impl Fn(&Recipe, &Secret) -> Verdict + Sync + '_ {
    move |recipe, key| {
        calls.fetch_add(1, Ordering::SeqCst);
        let value = key.expose();
        match recipe.provider.as_str() {
            "openai" | "github" | "instagram" | "resend" => Verdict::Works {
                host: recipe.hosts[0].clone(),
            },
            "google" if value.split(':').count() == 3 => Verdict::Works {
                host: recipe.hosts[0].clone(),
            },
            "telegram" | "meta" => Verdict::Rejected,
            _ => Verdict::NoResult("HTTP 500".into()),
        }
    }
}

fn names(candidate: &Candidate) -> Vec<String> {
    candidate.origins[0]
        .parts
        .iter()
        .map(|p| p.name.clone().unwrap_or_default())
        .collect()
}

fn find<'a>(report: &'a Report, name: &str) -> &'a Candidate {
    report
        .candidates
        .iter()
        .find(|c| names(c).iter().any(|n| n == name))
        .unwrap_or_else(|| panic!("no candidate named {name}"))
}

fn assert_no_value(report: &Report) {
    let json = serde_json::to_string(report).unwrap();
    let debug = format!("{report:?}");
    let lines = lines(report, None).join("\n");
    for text in [&json, &debug, &lines] {
        assert!(!text.contains(CANARY), "a value reached the report");
    }
}

#[test]
fn a_dry_run_finds_the_usual_places_and_shows_no_value() {
    let home = fake_home();
    let report = bring_with(&places(&home), &setup(), None);
    assert_no_value(&report);
    assert!(!report.checked);
    assert!(report.candidates.iter().all(|c| c.check.is_none()));
    // Nothing was checked, so no key is said to work or to be dead.
    assert_eq!((report.summary.works, report.summary.dead), (0, 0));

    let aws = find(&report, "aws_access_key_id");
    assert_eq!(names(aws), ["aws_access_key_id", "aws_secret_access_key"]);
    assert_eq!(aws.origins[0].parts[0].section.as_deref(), Some("default"));
    assert_eq!(aws.provider.as_deref(), Some("aws"));
    assert_eq!(aws.class, Class::Key);

    // gcloud's sign-in: Google's three parts, named only by the domain of its client id.
    let adc = find(&report, "refresh_token");
    assert_eq!(names(adc), ["client_id", "client_secret", "refresh_token"]);
    assert_eq!(adc.provider.as_deref(), Some("google"));
    assert_eq!(adc.evidence, Some("domain"));
    assert!(adc.origins[0].parts.iter().all(|p| p.json.is_some()));

    let gh = find(&report, "oauth_token");
    assert_eq!(gh.provider.as_deref(), Some("github"));
    assert_eq!(gh.server.as_deref(), Some("github.com"));

    let npm = find(&report, "_authToken");
    assert_eq!(npm.server.as_deref(), Some("registry.npmjs.org"));

    let netrc = find(&report, "password");
    let netrc = if netrc.class == Class::Login {
        netrc
    } else {
        report
            .candidates
            .iter()
            .find(|c| c.class == Class::Login && c.server.as_deref() == Some("example.com"))
            .unwrap()
    };
    assert_eq!(names(netrc), ["login", "password"]);

    let docker = find(&report, "auth");
    assert_eq!(docker.class, Class::Login);
    assert_eq!(docker.server.as_deref(), Some("index.docker.io"));
    assert!(docker.origins[0].parts[0].json.is_some());

    // SSH: the private key is a key and the public one is public; known_hosts and config are not read.
    let ssh: Vec<&Candidate> = report
        .candidates
        .iter()
        .filter(|c| c.origins[0].path.contains("/.ssh/"))
        .collect();
    assert_eq!(ssh.len(), 2);
    assert!(ssh
        .iter()
        .any(|c| c.class == Class::Key && c.origins[0].parts[0].whole));
    assert!(ssh.iter().any(|c| c.class == Class::Public));

    // A shell's file gives its exports that are keys, and nothing else.
    let zshrc: Vec<&Candidate> = report
        .candidates
        .iter()
        .filter(|c| c.origins.iter().any(|o| o.path.ends_with(".zshrc")))
        .collect();
    assert_eq!(
        zshrc.len(),
        1,
        "{:?}",
        zshrc
            .iter()
            .map(|c| (names(c), c.class, c.why))
            .collect::<Vec<_>>()
    );
    assert_eq!(names(zshrc[0]), ["OPENAI_API_KEY"]);

    // A tool's settings in the home folder are not listed: region, output, user.
    assert!(report
        .candidates
        .iter()
        .flat_map(names)
        .all(|n| !matches!(n.as_str(), "region" | "output" | "user" | "save-exact")));

    // Folders that exist are suggested; Documents, src and the rest are not there.
    assert_eq!(report.suggested_projects.len(), 2);
    assert!(report.suggested_projects[0].ends_with("Desktop"));
    assert!(report.suggested_projects[1].ends_with("code"));
}

#[test]
fn project_folders_skip_dependencies_examples_and_deep_or_large_files() {
    let home = fake_home();
    let report = bring_with(&places(&home), &setup(), None);
    let project_files: Vec<&str> = report
        .candidates
        .iter()
        .flat_map(|c| &c.origins)
        .filter(|o| o.area == Area::Project)
        .map(|o| o.path.as_str())
        .collect();
    assert!(!project_files.is_empty());
    assert!(project_files.iter().all(|p| p.ends_with("code/app/.env")));
    assert_eq!(report.skipped.examples, 1);
    assert_eq!(report.skipped.too_deep, 1);
    assert_eq!(report.skipped.too_large, 1);
    // A folder not confirmed is not searched, even if it is the home itself.
    let only_home = Scope::Places {
        home: home.0.clone(),
        projects: Vec::new(),
    };
    let report = bring_with(&only_home, &setup(), None);
    assert!(report
        .candidates
        .iter()
        .all(|c| c.origins[0].area == Area::Home));
}

#[test]
fn parts_of_one_key_go_together() {
    let home = fake_home();
    let report = bring_with(&places(&home), &setup(), None);
    let r2 = find(&report, "R2_ACCESS_KEY_ID");
    assert_eq!(names(r2), ["R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY"]);
    assert_eq!(
        r2.server.as_deref(),
        Some("abc123.r2.cloudflarestorage.com")
    );
    // Only the names say R2, so it is a guess, and nothing names it strongly enough to check.
    assert_eq!(r2.provider, None);
    assert_eq!(r2.guessed, ["r2"]);
    // The endpoint went with the key, so it is not listed apart.
    assert!(report
        .candidates
        .iter()
        .all(|c| !names(c).contains(&"R2_ENDPOINT".to_owned())));

    let google = find(&report, "GOOGLE_CLIENT_ID");
    assert_eq!(
        names(google),
        [
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "GOOGLE_REFRESH_TOKEN"
        ]
    );
    assert_eq!(google.provider.as_deref(), Some("google"));

    let telegram = find(&report, "TELEGRAM_BOT_TOKEN");
    assert_eq!(telegram.provider.as_deref(), Some("telegram"));
    assert_eq!(telegram.evidence, Some("variable"));
    assert_eq!(
        find(&report, "TELEGRAM_CHAT_ID").class,
        Class::Configuration
    );
    assert_eq!(find(&report, "TELEGRAM_CHAT_ID").group, Group::Other);
    assert_eq!(
        find(&report, "NEXT_PUBLIC_SUPABASE_ANON_KEY").class,
        Class::Public
    );
    assert!(report
        .candidates
        .iter()
        .all(|c| !names(c).iter().any(|n| n == "EMPTY" || n == "PLACEHOLDER")));
}

#[test]
fn the_same_key_in_two_places_is_one_key_with_two_origins() {
    let home = fake_home();
    let report = bring_with(&places(&home), &setup(), None);
    let openai: Vec<&Candidate> = report
        .candidates
        .iter()
        .filter(|c| names(c).contains(&"OPENAI_API_KEY".to_owned()))
        .collect();
    assert_eq!(openai.len(), 1);
    let openai = openai[0];
    assert!(openai.duplicate);
    assert_eq!(openai.origins.len(), 2);
    assert!(openai.from_project);
    assert_eq!(report.summary.duplicates, 1);
    // Each origin says where its own copy stands, so the app can read either.
    for origin in &openai.origins {
        let text = fs::read_to_string(&origin.path).unwrap();
        assert_eq!(origin.bytes, text.len() as u64);
        assert!(origin.modified > 0);
        let [from, to] = origin.parts[0].span.unwrap();
        assert_eq!(&text[from..to], OPENAI);
    }
}

#[test]
fn checks_decide_the_group_and_the_provider() {
    let home = fake_home();
    let calls = AtomicUsize::new(0);
    let checker = fake_checker(&calls);
    let report = bring_with(&places(&home), &setup(), Some(&checker));
    assert_no_value(&report);
    assert!(report.checked);
    assert!(calls.load(Ordering::SeqCst) > 0);

    let openai = find(&report, "OPENAI_API_KEY");
    assert_eq!(openai.group, Group::Works);
    assert_eq!(openai.suggested, "seal");
    let telegram = find(&report, "TELEGRAM_BOT_TOKEN");
    assert_eq!(telegram.group, Group::Dead);
    assert_eq!(telegram.suggested, "skip");
    let google = find(&report, "GOOGLE_CLIENT_ID");
    assert_eq!(google.group, Group::Works);
    // R2 is only named by its variables' names: a guess, so the key went nowhere.
    let r2 = find(&report, "R2_ACCESS_KEY_ID");
    assert_eq!(r2.group, Group::Doubtful);
    assert!(r2.check.is_none());
    assert_eq!(r2.unchecked, Some("only its name suggests a provider"));
    // Logins and keys no provider claims are for the person to decide.
    let netrc = report
        .candidates
        .iter()
        .find(|c| c.class == Class::Login && c.server.as_deref() == Some("example.com"))
        .unwrap();
    assert_eq!(netrc.group, Group::Doubtful);
    assert!(netrc.check.is_none());
    assert_eq!(netrc.suggested, "decide");
}

#[test]
fn the_prefix_names_the_provider_and_a_file_name_only_guesses() {
    let folder = Temp::new("prefix");
    folder.write("meta-shop.txt", "IGAACANARYinstagram000000000000\n");
    let calls = AtomicUsize::new(0);
    let checker = fake_checker(&calls);
    let report = bring_with(&Scope::Folder(folder.0.clone()), &setup(), Some(&checker));
    assert_eq!(report.candidates.len(), 1);
    let token = &report.candidates[0];
    assert_eq!(token.provider.as_deref(), Some("instagram"));
    assert_eq!(token.evidence, Some("prefix"));
    assert_eq!(token.guessed, ["meta"]);
    assert_eq!(token.group, Group::Works);
    // Sent to Instagram alone: the file's name never sends it to Meta.
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // A Meta token that Meta turns down is dead.
    folder.write("meta-shop.txt", "EAACANARYmeta0000000000000000\n");
    let report = bring_with(&Scope::Folder(folder.0.clone()), &setup(), Some(&checker));
    assert_eq!(report.candidates[0].group, Group::Dead);
    assert_eq!(report.candidates[0].check.as_ref().unwrap().recipe, "meta");
}

#[test]
fn a_name_alone_sends_nothing_to_the_network() {
    let folder = Temp::new("names");
    folder.write(
        "telegram-bot.env",
        "MY_TELEGRAM_THING=123456789:CANARYname000000000000000\nOPENAI_SECRET_STUFF=CANARYopenaiName0000000000\n",
    );
    folder.write("stripe-notes.txt", "aB3dE5fG7hJ9kL1mN3pQ5rSCANARY\n");
    folder.write(
        "paypal.json",
        r#"{"client_id":"CANARYpaypalId000000000000","client_secret":"CANARYpaypalSecret0000000000"}"#,
    );
    let calls = AtomicUsize::new(0);
    let checker = fake_checker(&calls);
    let report = bring_with(&Scope::Folder(folder.0.clone()), &setup(), Some(&checker));
    assert_no_value(&report);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "a key went out on a guess");
    assert!(!report.candidates.is_empty());
    for candidate in &report.candidates {
        assert!(candidate.check.is_none());
        assert_eq!(candidate.provider, None);
        assert_eq!(candidate.group, Group::Doubtful);
        assert_eq!(
            candidate.unchecked,
            Some("only its name suggests a provider")
        );
    }
    assert_eq!(find(&report, "client_id").guessed, ["paypal"]);
}

#[test]
fn evidence_that_disagrees_sends_nothing() {
    let folder = Temp::new("disagree");
    // The prefix says Anthropic and the variable says OpenAI.
    folder.write("a.env", "OPENAI_API_KEY=sk-ant-CANARYdisagree0000000000\n");
    // The same value under GitHub's variable in one file and OpenAI's in another.
    folder.write("b.env", "GH_TOKEN=CANARYsameValue000000000000\n");
    folder.write("c.env", "OPENAI_API_KEY=CANARYsameValue000000000000\n");
    let calls = AtomicUsize::new(0);
    let checker = fake_checker(&calls);
    let report = bring_with(&Scope::Folder(folder.0.clone()), &setup(), Some(&checker));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(report.candidates.len(), 2);
    for candidate in &report.candidates {
        assert_eq!(candidate.provider, None);
        assert_eq!(candidate.unchecked, Some("two providers could own it"));
        assert_eq!(candidate.group, Group::Doubtful);
    }
    let mut first = report.candidates[0].guessed.clone();
    first.sort();
    assert_eq!(first, ["anthropic", "openai"]);
    let mut second = report.candidates[1].guessed.clone();
    second.sort();
    assert_eq!(second, ["github", "openai"]);
}

#[test]
fn each_key_goes_to_at_most_one_provider() {
    let home = fake_home();
    let sent: Mutex<Vec<(String, [u8; 32])>> = Mutex::new(Vec::new());
    let checker = |recipe: &Recipe, key: &Secret| {
        let digest: [u8; 32] = Sha256::digest(key.expose().as_bytes()).into();
        sent.lock().unwrap().push((recipe.provider.clone(), digest));
        Verdict::Rejected
    };
    let report = bring_with(&places(&home), &setup(), Some(&checker));
    let sent = sent.into_inner().unwrap();
    let mut keys: Vec<[u8; 32]> = sent.iter().map(|(_, d)| *d).collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), sent.len(), "a key was sent twice");
    // Every key sent went to the provider its report names, and that one is strongly named.
    let checked: Vec<&Candidate> = report
        .candidates
        .iter()
        .filter(|c| c.check.is_some())
        .collect();
    assert_eq!(checked.len(), sent.len());
    for candidate in checked {
        let provider = candidate.provider.as_deref().unwrap();
        assert_eq!(candidate.check.as_ref().unwrap().recipe, provider);
        assert!(candidate.evidence.is_some());
        assert!(sent.iter().any(|(p, _)| p == provider));
    }
}

#[test]
fn a_chosen_folder_of_loose_files() {
    let folder = Temp::new("folder");
    folder.write(
        "bot/.env",
        "TELEGRAM_BOT_TOKEN=123456789:CANARYbot0000000000000000000\nTELEGRAM_CHAT_ID=-100999\n",
    );
    folder.write(
        "paypal.json",
        r#"{"client_id":"CANARYpaypalId000000000000","client_secret":"CANARYpaypalSecret0000000000"}"#,
    );
    folder.write(
        "resend.txt",
        "re_CANARYresendOne000000000000\nre_CANARYresendTwo000000000000\n",
    );
    folder.write(
        "notes.txt",
        "keep these safe\naB3dE5fG7hJ9kL1mN3pQ5rSCANARY\nthat was all\n",
    );
    folder.write(
        "copy-of-bot.txt",
        "123456789:CANARYbot0000000000000000000\n",
    );
    folder.write("readme.md", "Nothing to see here.\nJust words.\n");
    folder.write(
        "cert.pem",
        "-----BEGIN CERTIFICATE-----\nCANARYcert\n-----END CERTIFICATE-----\n",
    );
    folder.write("store.p12", "CANARYbinary");
    let report = bring_with(&Scope::Folder(folder.0.clone()), &setup(), None);
    assert_no_value(&report);

    let paypal = find(&report, "client_id");
    assert_eq!(names(paypal), ["client_id", "client_secret"]);
    assert_eq!(paypal.provider, None);
    assert_eq!(paypal.guessed, ["paypal"]);
    assert_eq!(
        paypal.origins[0].parts[1].json.as_deref(),
        Some(&["client_secret".to_owned()][..])
    );

    // Two Resend keys in one file with no names: two keys, each with its own place.
    let resend: Vec<&Candidate> = report
        .candidates
        .iter()
        .filter(|c| c.origins[0].path.ends_with("resend.txt"))
        .collect();
    assert_eq!(resend.len(), 2);
    assert!(resend
        .iter()
        .all(|c| c.provider.as_deref() == Some("resend")));
    assert_ne!(
        resend[0].origins[0].parts[0].line,
        resend[1].origins[0].parts[0].line
    );

    // A note with a key in it and no name for it.
    let note: Vec<&Candidate> = report
        .candidates
        .iter()
        .filter(|c| c.origins[0].path.ends_with("notes.txt"))
        .collect();
    assert_eq!(note.len(), 1);
    assert_eq!(note[0].class, Class::Key);
    assert_eq!(note[0].origins[0].parts[0].line, 2);
    assert_eq!(note[0].group, Group::Doubtful);

    // The bot token copied into a loose file is the same key.
    let bot = find(&report, "TELEGRAM_BOT_TOKEN");
    assert_eq!(bot.origins.len(), 2);

    let class_of = |file: &str| {
        report
            .candidates
            .iter()
            .find(|c| c.origins[0].path.ends_with(file))
            .map(|c| c.class)
    };
    assert_eq!(class_of("readme.md"), Some(Class::Document));
    assert_eq!(class_of("cert.pem"), Some(Class::Public));
    assert_eq!(class_of("store.p12"), Some(Class::Key));
}

#[test]
fn every_span_points_at_a_value_that_makes_the_key() {
    let home = fake_home();
    let report = bring_with(&places(&home), &setup(), None);
    for candidate in &report.candidates {
        for origin in &candidate.origins {
            let text = fs::read(&origin.path).unwrap();
            for part in &origin.parts {
                if let Some([from, to]) = part.span {
                    assert!(from < to && to <= text.len());
                    let value = std::str::from_utf8(&text[from..to]).unwrap();
                    assert!(!value.contains(char::is_whitespace) || part.name.is_none());
                    assert!(!value.starts_with(['"', '\'']));
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn links_are_not_followed() {
    let folder = Temp::new("links");
    let outside = Temp::new("outside");
    outside.write(".env", "API_KEY=CANARYoutside0000000000\n");
    std::os::unix::fs::symlink(outside.0.join(".env"), folder.0.join(".env")).unwrap();
    std::os::unix::fs::symlink(&outside.0, folder.0.join("linked")).unwrap();
    let scope = Scope::Places {
        home: Temp::new("empty-home").0.clone(),
        projects: vec![folder.0.clone()],
    };
    let report = bring_with(&scope, &setup(), None);
    assert!(report.candidates.is_empty());
}

#[test]
fn a_folder_to_avoid_is_never_read() {
    let folder = Temp::new("avoid");
    folder.write("keyreeve/.env", "API_KEY=CANARYkeyreeve00000000\n");
    folder.write("app/.env", "API_KEY=CANARYapp000000000000000\n");
    let setup = Setup {
        avoid: vec![folder.0.join("keyreeve")],
        ..setup()
    };
    let scope = Scope::Places {
        home: folder.0.join("nohome"),
        projects: vec![folder.0.clone()],
    };
    let report = bring_with(&scope, &setup, None);
    assert_eq!(report.candidates.len(), 1);
    assert!(report.candidates[0].origins[0].path.ends_with("app/.env"));
}

fn paths(report: &Report, root: &Path) -> Vec<String> {
    let mut found: Vec<String> = report
        .candidates
        .iter()
        .flat_map(|c| c.origins.iter())
        .map(|o| {
            Path::new(&o.path)
                .strip_prefix(root)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

#[test]
fn everywhere_walks_the_home_folder_for_key_files_and_skips_what_holds_none() {
    let home = Temp::new("everywhere");
    let key = "API_KEY=sk-proj-CANARYeverywhere000000000\n";
    home.write(
        ".aws/credentials",
        "[default]\naws_access_key_id = AKIACANARY0000000009\naws_secret_access_key = CANARYawsSecret00000000000000000000009\n",
    );
    home.write("code/app/.env", key);
    home.write("code/app/.env.example", key);
    home.write(
        ".config/tool/credentials.json",
        r#"{"token":"ghp_CANARYconfig00000000000000000000"}"#,
    );
    home.write("notes/api-key.txt", "CANARYnamedValue000000000000aB1\n");
    home.write(
        "notes/found.txt",
        "an old one: ghp_CANARYsniffed000000000000000000000\n",
    );
    home.write(
        "notes/todo.txt",
        "buy milk, and nothing that looks like a key\n",
    );
    home.write(
        "notes/deploy.pem",
        "-----BEGIN PRIVATE KEY-----\nCANARYpem\n-----END PRIVATE KEY-----\n",
    );
    home.write("notes/talk.key", "PK\u{3}\u{4}CANARYkeynote");
    home.write("notes/photo.jpg", "CANARYjpg");
    home.write(
        "notes/secret.json",
        &format!("\"{}\"", "x".repeat(300 * 1024)),
    );
    // Each of these is skipped, so its key never shows.
    for skipped in [
        "code/app/node_modules/dep/.env",
        "code/app/.git/.env",
        "code/app/target/.env",
        "code/app/.build/.env",
        "code/app/.venv/.env",
        ".cache/tool/.env",
        ".Trash/old/.env",
        "Library/Application Support/x/.env",
        "Documents/Mobile Documents/x/.env",
        "Pictures/Photos Library.photoslibrary/.env",
        "Tools.app/Contents/.env",
        "keyreeve/.env",
    ] {
        home.write(skipped, "SKIPPED_KEY=sk-proj-CANARYskipped00000000000\n");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(home.0.join("code"), home.0.join("link")).unwrap();
    let setup = Setup {
        avoid: vec![home.0.join("keyreeve")],
        ..setup()
    };
    let scope = Scope::Everywhere {
        home: home.0.clone(),
        under: Vec::new(),
    };
    let report = bring_with(&scope, &setup, None);
    assert_eq!(report.scope, "everywhere");
    assert_eq!(
        paths(&report, &home.0),
        [
            ".aws/credentials",
            ".config/tool/credentials.json",
            "code/app/.env",
            "notes/api-key.txt",
            "notes/deploy.pem",
            "notes/found.txt",
        ]
    );
    assert_eq!(report.skipped.examples, 1);
    assert_eq!(report.skipped.too_large, 1);
    assert!(report.unfinished.is_empty());
    assert!(!report.skipped.stopped_early);
    assert_no_value(&report);
}

#[test]
fn a_spent_budget_names_the_folders_not_finished_and_they_can_be_searched_alone() {
    let home = Temp::new("budget");
    for n in 0..20 {
        home.write(&format!("a/{n:02}.txt"), "nothing\n");
    }
    home.write("b/.env", "API_KEY=sk-proj-CANARYbudgetb0000000000000\n");
    home.write("c/.env", "API_KEY=sk-proj-CANARYbudgetc0000000000000\n");
    home.write("top.env", "API_KEY=sk-proj-CANARYbudgettop00000000000\n");
    let setup = Setup {
        budget: Budget {
            entries: 5,
            seconds: 60,
            depth: 16,
        },
        ..setup()
    };
    let report = bring_with(
        &Scope::Everywhere {
            home: home.0.clone(),
            under: Vec::new(),
        },
        &setup,
        None,
    );
    assert!(report.skipped.stopped_early);
    let unfinished: Vec<String> = report
        .unfinished
        .iter()
        .map(|p| {
            Path::new(p)
                .strip_prefix(&home.0)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();
    assert_eq!(unfinished, ["a", "b", "c"]);
    // Files right under the home folder were read before the budget ran out.
    assert_eq!(paths(&report, &home.0), ["top.env"]);
    assert_no_value(&report);
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"unfinished\""));
    // Going on in the folders not finished, with the usual places left out.
    let next = bring_with(
        &Scope::Everywhere {
            home: home.0.clone(),
            under: vec![home.0.join("b"), home.0.join("c")],
        },
        &setup,
        None,
    );
    assert!(next.unfinished.is_empty());
    assert_eq!(paths(&next, &home.0), ["b/.env", "c/.env"]);
}
