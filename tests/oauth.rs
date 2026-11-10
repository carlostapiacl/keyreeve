//! OAuth as authorization: the proxy holds the refresh token, answers a client's token request with a
//! stand-in, and gets real access tokens itself. Between a real `curl`, and Python's google-auth when it is
//! installed, and a local TLS server that plays the token host and an API.
#![cfg(unix)]

use keyreeve::proxy::{Event, OAuthGrant, Options, Proxy};
use keyreeve::recipe::Recipe;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const CLIENT_ID: &str = "764-test.apps.googleusercontent.com";
const SECRET: &str = "GOCSPX-CANARYclientSecret0000000";
const REFRESH: &str = "1//0gCANARYrefreshToken00000000000000000";
const ACCESS: &str = "ya29.CANARYrealAccess000000000000000000000000";
const CANARIES: [&str; 3] = [SECRET, REFRESH, ACCESS];
const TOKEN_HOST: &str = "oauth2.googleapis.com";
const API_HOST: &str = "searchconsole.googleapis.com";
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// What the token host answers, one per exchange, the last kept for any after it.
type Answers = Arc<Mutex<VecDeque<(u16, String)>>>;

struct Upstream {
    port: u16,
    root: CertificateDer<'static>,
    root_pem: String,
    seen: Arc<Mutex<Vec<String>>>,
    exchanges: Arc<AtomicUsize>,
}

fn token(access: &str, expires_in: u64) -> (u16, String) {
    (
        200,
        format!(r#"{{"access_token":"{access}","expires_in":{expires_in},"token_type":"Bearer"}}"#),
    )
}

/// The token host and the API, on one port. `/token` answers from `answers` after `delay`; `/echo` answers
/// with the Authorization header it got; anything else with a small JSON.
fn upstream(answers: Vec<(u16, String)>, delay: Duration) -> Upstream {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![
        "localhost".to_owned(),
        TOKEN_HOST.to_owned(),
        API_HOST.to_owned(),
    ])
    .unwrap()
    .self_signed(&key)
    .unwrap();
    let root = cert.der().clone();
    let root_pem = cert.pem();
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![root.clone()], private)
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let exchanges = Arc::new(AtomicUsize::new(0));
    let answers: Answers = Arc::new(Mutex::new(answers.into()));
    let (record, count) = (seen.clone(), exchanges.clone());
    thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            let (config, record, count, answers) = (
                config.clone(),
                record.clone(),
                count.clone(),
                answers.clone(),
            );
            thread::spawn(move || {
                let connection = rustls::ServerConnection::new(config).unwrap();
                let mut stream = BufReader::new(rustls::StreamOwned::new(connection, socket));
                let mut text = String::new();
                let mut length = 0usize;
                let mut authorization = String::new();
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                    if lower.starts_with("authorization:") {
                        authorization = line["authorization:".len()..].trim().to_owned();
                    }
                    text.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                text.push_str(&String::from_utf8_lossy(&body));
                let path = text.split(' ').nth(1).unwrap_or("").to_owned();
                record.lock().unwrap().push(text);
                let (status, reply) = if path == "/token" {
                    count.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(delay);
                    let mut answers = answers.lock().unwrap();
                    if answers.len() > 1 {
                        answers.pop_front().unwrap()
                    } else {
                        answers.front().cloned().unwrap()
                    }
                } else if path.starts_with("/echo") {
                    (200, format!("you sent {authorization}."))
                } else {
                    (
                        200,
                        r#"{"siteEntry":[{"siteUrl":"https://example.com/"}]}"#.to_owned(),
                    )
                };
                let answer = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let inner = stream.get_mut();
                inner.write_all(answer.as_bytes()).unwrap();
                inner.flush().unwrap();
                inner.conn.send_close_notify();
                let _ = inner.flush();
            });
        }
    });
    Upstream {
        port,
        root,
        root_pem,
        seen,
        exchanges,
    }
}

fn recipe() -> Recipe {
    Recipe::parse(&format!(
        r#"
schema: 1
provider: google-test
hosts: [{TOKEN_HOST}, {API_HOST}]
auth: {{ type: oauth_token, grant: refresh_token, token_host: {TOKEN_HOST}, token_path: /token }}
verify: {{ method: GET, host: {API_HOST}, path: /me }}
"#
    ))
    .unwrap()
}

fn sealed() -> String {
    format!(
        r#"{{"type":"authorized_user","client_id":"{CLIENT_ID}","client_secret":"{SECRET}","refresh_token":"{REFRESH}","quota_project_id":"my-project"}}"#
    )
}

struct Run {
    proxy: Arc<Proxy>,
    port: u16,
    bundle: PathBuf,
    events: Mutex<Receiver<Event>>,
    up: Upstream,
    folder: PathBuf,
    /// The credentials file with stand-ins, as the command gets it.
    file: PathBuf,
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

fn run_with(answers: Vec<(u16, String)>, delay: Duration) -> Run {
    let up = upstream(answers, delay);
    let (proxy, events) = Proxy::new(Options {
        extra_roots: vec![up.root.clone()],
        upstream_port: Some(up.port),
        private_tunnels: true,
        upstream_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    })
    .unwrap();
    let folder = std::env::temp_dir().join(format!(
        "keyreeve-oauth-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let trust = proxy.write_trust(&folder).unwrap();
    let port = proxy.listen().unwrap();
    let grant = OAuthGrant::new(
        "g-1",
        "search-console",
        &recipe(),
        &sealed(),
        None,
        u64::MAX,
        Some(&folder),
    )
    .unwrap();
    let file = PathBuf::from(grant.stand_in());
    proxy.add_oauth(grant);
    Run {
        proxy,
        port,
        bundle: trust.bundle,
        events: Mutex::new(events),
        up,
        folder,
        file,
    }
}

fn run() -> Run {
    run_with(vec![token(ACCESS, 3600)], Duration::ZERO)
}

/// The command's environment, as `use` gives it: the proxy, its CA, and the credentials file.
fn command_env(run: &Run) -> Vec<(String, String)> {
    let address = format!("http://127.0.0.1:{}", run.port);
    let bundle = run.bundle.display().to_string();
    vec![
        ("HTTPS_PROXY".into(), address.clone()),
        ("https_proxy".into(), address),
        ("CURL_CA_BUNDLE".into(), bundle.clone()),
        ("REQUESTS_CA_BUNDLE".into(), bundle.clone()),
        ("SSL_CERT_FILE".into(), bundle.clone()),
        ("HTTPLIB2_CA_CERTS".into(), bundle),
        (
            "GOOGLE_APPLICATION_CREDENTIALS".into(),
            run.file.display().to_string(),
        ),
    ]
}

/// A real curl through the proxy. Returns its body and the status it saw.
fn curl(run: &Run, args: &[&str]) -> (String, String) {
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "15", "-o", "-", "-w", "\n%{http_code}"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .envs(command_env(run))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert_no_canary(&text, "curl's output");
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", ""));
    (body.to_owned(), code.trim().to_owned())
}

fn assert_no_canary(text: &str, place: &str) {
    for canary in CANARIES {
        assert!(!text.contains(canary), "{place} holds a real value: {text}");
    }
    assert!(
        !text.contains("CANARY"),
        "{place} holds a real value: {text}"
    );
}

fn stand_ins(run: &Run) -> serde_json::Value {
    let text = std::fs::read_to_string(&run.file).unwrap();
    assert_no_canary(&text, "the credentials file");
    serde_json::from_str(&text).unwrap()
}

fn form(json: &serde_json::Value) -> String {
    let encode = |value: &str| value.replace('/', "%2F");
    format!(
        "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={}",
        encode(json["client_id"].as_str().unwrap()),
        encode(json["client_secret"].as_str().unwrap()),
        encode(json["refresh_token"].as_str().unwrap()),
    )
}

/// Asks the token endpoint as a library would, and returns the access token it was given.
fn stand_in_access(run: &Run) -> String {
    let (body, code) = curl(
        run,
        &[
            "--data",
            &form(&stand_ins(run)),
            &format!("https://{TOKEN_HOST}/token"),
        ],
    );
    assert_eq!(code, "200", "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["expires_in"].as_u64().unwrap() > 0);
    json["access_token"].as_str().unwrap().to_owned()
}

fn events(run: &Run) -> Vec<Event> {
    let mut all = Vec::new();
    let events = run.events.lock().unwrap();
    while let Ok(event) = events.recv_timeout(Duration::from_millis(200)) {
        all.push(event);
    }
    for event in &all {
        assert_no_canary(&serde_json::to_string(event).unwrap(), "an event");
    }
    all
}

#[test]
fn a_library_shaped_flow_gets_the_api_and_never_the_secrets() {
    let run = run();
    let json = stand_ins(&run);
    assert_eq!(json["client_id"], CLIENT_ID);
    assert_eq!(json["token_uri"], format!("https://{TOKEN_HOST}/token"));
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&run.file).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode, 0o600);

    let access = stand_in_access(&run);
    assert_ne!(access, ACCESS);
    // The token request never left: the provider saw the proxy's own exchange, with the real values.
    {
        let seen = run.up.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].contains(&format!("refresh_token={}", REFRESH.replace('/', "%2F"))));
        assert!(!seen[0].contains(json["client_secret"].as_str().unwrap()));
    }
    let (body, code) = curl(
        &run,
        &[
            "-H",
            &format!("Authorization: Bearer {access}"),
            &format!("https://{API_HOST}/webmasters/v3/sites"),
        ],
    );
    assert_eq!(code, "200", "{body}");
    assert!(body.contains("siteEntry"));
    let seen = run.up.seen.lock().unwrap();
    assert!(seen[1].contains(&format!("Bearer {ACCESS}")), "{}", seen[1]);
    assert!(!seen[1].contains(&access));
    drop(seen);

    let events = events(&run);
    let exchange = events.iter().find(|e| e.path == "/token").unwrap();
    assert_eq!(exchange.authorization.as_deref(), Some("active"));
    assert_eq!((exchange.host.as_str(), exchange.status), (TOKEN_HOST, 200));
    let api = events.iter().find(|e| e.host == API_HOST).unwrap();
    assert_eq!(
        (api.key.as_str(), api.path.as_str(), api.status),
        ("search-console", "/webmasters/v3/sites", 200)
    );
    assert_eq!(run.up.exchanges.load(Ordering::SeqCst), 1);
}

#[test]
fn a_reply_that_echoes_the_access_token_is_scrubbed() {
    let run = run();
    let access = stand_in_access(&run);
    let (body, code) = curl(
        &run,
        &[
            "-H",
            &format!("Authorization: Bearer {access}"),
            &format!("https://{API_HOST}/echo"),
        ],
    );
    assert_eq!(code, "200");
    // Whole, and with the length it was framed with.
    assert_eq!(
        body.len(),
        format!("you sent Bearer {ACCESS}.").len(),
        "{body}"
    );
}

#[test]
fn a_token_request_with_wrong_stand_ins_is_refused_and_not_forwarded() {
    let run = run();
    let json = stand_ins(&run);
    let url = format!("https://{TOKEN_HOST}/token");
    let mut wrong_refresh = json.clone();
    wrong_refresh["refresh_token"] = "1//0gsomethingelse0000000000000000000000".into();
    let mut wrong_client = json.clone();
    wrong_client["client_id"] = "999-other.apps.googleusercontent.com".into();
    for body in [
        form(&wrong_refresh),
        form(&wrong_client),
        // The real values are not stand-ins either. Written here, they never reach curl's output.
        format!(
            "grant_type=refresh_token&client_id={CLIENT_ID}&client_secret={SECRET}&refresh_token={}",
            REFRESH.replace('/', "%2F")
        ),
        "grant_type=client_credentials".to_owned(),
    ] {
        let (answer, code) = curl(&run, &["--data", &body, &url]);
        assert_eq!(code, "401", "{answer}");
        assert!(answer.contains("invalid_client"), "{answer}");
    }
    // A GET, and a stand-in in the address, are refused too.
    assert_eq!(curl(&run, &[&url]).1, "401");
    let in_url = format!(
        "https://{API_HOST}/x?key={}",
        json["refresh_token"].as_str().unwrap()
    );
    assert_eq!(curl(&run, &[&in_url]).1, "400");
    assert!(
        run.up.seen.lock().unwrap().is_empty(),
        "something was forwarded"
    );
    assert_eq!(run.up.exchanges.load(Ordering::SeqCst), 0);
}

#[test]
fn concurrent_uses_of_an_expired_token_make_one_exchange() {
    // The first token lasts a second; the next one an hour.
    let run = run_with(
        vec![token(ACCESS, 1), token(ACCESS, 3600)],
        Duration::from_millis(400),
    );
    let access = stand_in_access(&run);
    assert_eq!(run.up.exchanges.load(Ordering::SeqCst), 1);
    thread::sleep(Duration::from_millis(1200));
    let bearer = format!("Authorization: Bearer {access}");
    let url = format!("https://{API_HOST}/webmasters/v3/sites");
    let codes: Vec<String> = thread::scope(|scope| {
        let uses: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| curl(&run, &["-H", &bearer, &url]).1))
            .collect();
        uses.into_iter().map(|use_| use_.join().unwrap()).collect()
    });
    assert_eq!(codes, ["200", "200"]);
    assert_eq!(run.up.exchanges.load(Ordering::SeqCst), 2, "one refresh");
}

#[test]
fn invalid_grant_marks_the_key_and_is_not_tried_again() {
    let run = run_with(
        vec![(
            400,
            r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#
                .to_owned(),
        )],
        Duration::ZERO,
    );
    let url = format!("https://{TOKEN_HOST}/token");
    let body = form(&stand_ins(&run));
    for _ in 0..3 {
        let (answer, code) = curl(&run, &["--data", &body, &url]);
        assert_eq!(code, "400", "{answer}");
        assert!(answer.contains("invalid_grant"), "{answer}");
        assert!(answer.contains("authorizing again"), "{answer}");
    }
    assert_eq!(run.up.exchanges.load(Ordering::SeqCst), 1);
    let marked: Vec<Event> = events(&run)
        .into_iter()
        .filter(|event| event.authorization.is_some())
        .collect();
    assert_eq!(marked.len(), 1);
    assert_eq!(
        (marked[0].key.as_str(), marked[0].authorization.as_deref()),
        ("search-console", Some("reauthorize"))
    );
    // A new permission for the same credential does not try again either.
    run.proxy.remove("g-1");
    let again = OAuthGrant::new(
        "g-2",
        "search-console",
        &recipe(),
        &sealed(),
        None,
        u64::MAX,
        Some(&run.folder),
    )
    .unwrap();
    let file = PathBuf::from(again.stand_in());
    run.proxy.add_oauth(again);
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    assert_eq!(curl(&run, &["--data", &form(&json), &url]).1, "400");
    assert_eq!(run.up.exchanges.load(Ordering::SeqCst), 1);
}

#[test]
fn the_real_access_token_goes_to_no_host_outside_the_recipe() {
    let run = run();
    let access = stand_in_access(&run);
    // localhost is not one of the recipe's hosts, so the proxy opens a tunnel and reads nothing. curl
    // trusts the test server here, so the request arrives, and with the stand-in as it was.
    let bundle = run.folder.join("with-upstream.pem");
    std::fs::write(
        &bundle,
        std::fs::read_to_string(&run.bundle).unwrap() + &run.up.root_pem,
    )
    .unwrap();
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "15", "-o", "-", "-w", "\n%{http_code}"])
        .args([
            "-H",
            &format!("Authorization: Bearer {access}"),
            &format!("https://localhost:{}/echo", run.up.port),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{}", run.port))
        .env("CURL_CA_BUNDLE", &bundle)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(text.ends_with("200"), "{text}");
    let seen = run.up.seen.lock().unwrap();
    let last = seen.last().unwrap();
    assert!(last.contains(&format!("Bearer {access}")), "{last}");
    assert!(!last.contains(ACCESS));
}

#[test]
fn an_ended_permission_takes_its_file_with_it() {
    let run = run();
    assert!(run.file.exists());
    run.proxy.remove("g-1");
    assert!(!run.file.exists());
}

/// The same flow with Google's own Python libraries, unmodified, when they are installed: google-auth with
/// requests, and the API client over httplib2.
#[test]
fn python_google_auth_works_through_the_proxy() {
    let probe = Command::new("python3")
        .args([
            "-c",
            "import google.auth, google.auth.transport.requests, requests",
        ])
        .output();
    if !probe.is_ok_and(|out| out.status.success()) {
        eprintln!("skipped: python3 with google-auth and requests is not installed");
        return;
    }
    let run = run();
    let script = r#"
import json, os, sys
import google.auth
from google.auth.transport.requests import AuthorizedSession
creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/webmasters.readonly"])
session = AuthorizedSession(creds)
answer = session.get("https://searchconsole.googleapis.com/webmasters/v3/sites")
print("requests", answer.status_code, answer.text)
# Whatever the library holds, and the whole environment, may be printed: none of it is real.
print("held", creds.token, creds.refresh_token, creds.client_secret)
print("env", json.dumps(dict(os.environ)))
try:
    import google_auth_httplib2
    from googleapiclient.discovery import build
except ImportError:
    sys.exit(0)
fresh, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/webmasters.readonly"])
service = build("searchconsole", "v1", credentials=fresh, static_discovery=True, cache_discovery=False)
print("apiclient", json.dumps(service.sites().list().execute()))
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env_remove("GOOGLE_CLOUD_PROJECT")
        .envs(command_env(&run))
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&output.stdout).to_string();
    let err = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "{out}\n{err}");
    assert_no_canary(&out, "the program's output");
    assert_no_canary(&err, "the program's errors");
    assert!(out.contains("requests 200"), "{out}\n{err}");
    assert!(out.contains("siteEntry"), "{out}");
    let seen = run.up.seen.lock().unwrap();
    let api: Vec<&String> = seen.iter().filter(|r| r.contains("/webmasters/")).collect();
    assert!(!api.is_empty());
    for request in api {
        assert!(request.contains(&format!("Bearer {ACCESS}")), "{request}");
    }
    drop(seen);
    events(&run);
    // However many token requests the libraries made, the provider saw one exchange.
    assert_eq!(run.up.exchanges.load(Ordering::SeqCst), 1);
}
