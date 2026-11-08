//! The proxy between a real `curl` and a local TLS server that writes down what reached it.
#![cfg(unix)]

use keyreeve::proxy::{Event, Grant, Options, Proxy};
use keyreeve::secret::Secret;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;

const REAL: &str = "real-key-0123456789";
const FAKE: &str = "fake-key-9876543210";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Upstream {
    port: u16,
    root: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<String>>>,
}

/// Records each request whole, and answers with `reply`.
fn upstream(reply: &'static str) -> Upstream {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let root = cert.der().clone();
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
    let record = seen.clone();
    thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            let config = config.clone();
            let record = record.clone();
            thread::spawn(move || {
                let connection = rustls::ServerConnection::new(config).unwrap();
                let mut stream = BufReader::new(rustls::StreamOwned::new(connection, socket));
                let mut text = String::new();
                let mut length = 0usize;
                let mut chunked = false;
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                    chunked |= lower.starts_with("transfer-encoding:");
                    text.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                if chunked {
                    loop {
                        let mut line = String::new();
                        stream.read_line(&mut line).unwrap();
                        text.push_str(&line);
                        let size = usize::from_str_radix(line.trim(), 16).unwrap();
                        let mut chunk = vec![0; size + 2];
                        stream.read_exact(&mut chunk).unwrap();
                        text.push_str(&String::from_utf8_lossy(&chunk));
                        if size == 0 {
                            break;
                        }
                    }
                } else {
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).unwrap();
                    text.push_str(&String::from_utf8_lossy(&body));
                }
                record.lock().unwrap().push(text);
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
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
    Upstream { port, root, seen }
}

struct Run {
    proxy: Arc<Proxy>,
    port: u16,
    bundle: PathBuf,
    events: Receiver<Event>,
    seen: Arc<Mutex<Vec<String>>>,
    upstream: u16,
    folder: PathBuf,
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

fn run_with(reply: &'static str, hosts: &[&str], in_url: bool, expires: u64) -> Run {
    let up = upstream(reply);
    let (proxy, events) = Proxy::new(Options {
        extra_roots: vec![up.root.clone()],
        upstream_port: Some(up.port),
        private_tunnels: true,
    })
    .unwrap();
    let folder = std::env::temp_dir().join(format!(
        "keyreeve-proxy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let trust = proxy.write_trust(&folder).unwrap();
    let port = proxy.listen().unwrap();
    proxy.add(Grant {
        id: "g-1".into(),
        key: "my-key".into(),
        stand_in: Secret::new(FAKE),
        real: Secret::new(REAL),
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        in_url,
        expires,
    });
    Run {
        proxy,
        port,
        bundle: trust.bundle,
        events,
        seen: up.seen,
        upstream: up.port,
        folder,
    }
}

fn run() -> Run {
    run_with("hello", &["localhost"], false, u64::MAX)
}

/// A real client, with the environment a command would get. Returns its body and the status it saw.
fn curl(run: &Run, args: &[&str]) -> (String, String) {
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "15", "-o", "-", "-w", "\n%{http_code}"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{}", run.port))
        .env("CURL_CA_BUNDLE", &run.bundle)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", ""));
    (body.to_owned(), code.to_owned())
}

fn url(path: &str) -> String {
    format!("https://localhost{path}")
}

#[test]
fn the_real_key_reaches_only_the_provider_and_the_command_never_sees_it() {
    let run = run();
    let (body, code) = curl(
        &run,
        &[
            "-H",
            &format!("Authorization: Bearer {FAKE}"),
            &url("/v1/me?secret=1"),
        ],
    );
    assert_eq!((body.as_str(), code.as_str()), ("hello", "200"));
    let seen = run.seen.lock().unwrap();
    assert!(
        seen[0].contains(&format!("Authorization: Bearer {REAL}")),
        "{}",
        seen[0]
    );
    assert!(!seen[0].contains(FAKE));
    assert!(!seen[0].to_ascii_lowercase().contains("proxy-authorization"));
    let event = run.events.recv().unwrap();
    assert_eq!(
        (
            event.key.as_str(),
            event.method.as_str(),
            event.path.as_str(),
            event.status
        ),
        ("my-key", "GET", "/v1/me", 200)
    );
    assert_eq!(event.host, "localhost");
}

#[test]
fn a_password_in_basic_auth_is_swapped() {
    let run = run();
    let (_, code) = curl(&run, &["-u", &format!("me:{FAKE}"), &url("/")]);
    assert_eq!(code, "200");
    let seen = run.seen.lock().unwrap();
    assert!(!seen[0].contains(FAKE));
    assert!(seen[0].contains("Authorization: Basic "));
    assert!(
        seen[0].contains("bWU6cmVhbC1rZXktMDEyMzQ1Njc4OQ=="),
        "{}",
        seen[0]
    );
}

#[test]
fn a_body_keeps_the_stand_in_in_both_framings() {
    let run = run();
    let body = format!("{{\"key\":\"{FAKE}\"}}");
    assert_eq!(curl(&run, &["--data", &body, &url("/a")]).1, "200");
    let (_, code) = curl(
        &run,
        &[
            "-H",
            "Transfer-Encoding: chunked",
            "--data",
            &body,
            &url("/b"),
        ],
    );
    assert_eq!(code, "200");
    let seen = run.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    for request in seen.iter() {
        assert!(request.contains(FAKE), "{request}");
        assert!(!request.contains(REAL), "{request}");
    }
}

#[test]
fn the_address_is_swapped_only_for_a_provider_that_wants_it_there() {
    // A provider that takes its key in a header: the stand-in never leaves, and the tool hears where it goes.
    let plain = run();
    let (body, code) = curl(&plain, &[&url(&format!("/me?access_token={FAKE}"))]);
    assert_eq!(code, "400");
    assert!(body.contains("takes the key in a header"), "{body}");
    assert!(plain.seen.lock().unwrap().is_empty());
    // Nor when the same request also holds it rightly in a header.
    let (body, code) = curl(
        &plain,
        &[
            "-H",
            &format!("Authorization: Bearer {FAKE}"),
            &url(&format!("/me?access_token={FAKE}")),
        ],
    );
    assert_eq!(code, "400", "{body}");
    assert!(plain.seen.lock().unwrap().is_empty());

    let in_url = run_with("hello", &["localhost"], true, u64::MAX);
    curl(&in_url, &[&url(&format!("/bot{FAKE}/me"))]);
    assert!(in_url.seen.lock().unwrap()[0].contains(REAL));
    let event = in_url.events.recv().unwrap();
    assert_eq!(
        event.path, "/bot{key}/me",
        "the log holds neither the key nor the stand-in, which works while the permission lasts"
    );
}

#[test]
fn a_provider_that_echoes_the_key_gets_the_stand_in_back() {
    let run = run_with(
        "your key is real-key-0123456789!",
        &["localhost"],
        false,
        u64::MAX,
    );
    let auth = format!("Authorization: Bearer {FAKE}");
    let (body, _) = curl(&run, &["-H", &auth, &url("/")]);
    assert_eq!(body, format!("your key is {FAKE}!"));
}

#[test]
fn a_request_with_no_stand_in_goes_out_as_it_came() {
    let run = run();
    let bearer = "Authorization: Bearer somebody-elses-value";
    assert_eq!(curl(&run, &["-H", bearer, &url("/")]).1, "200");
    let seen = run.seen.lock().unwrap();
    assert!(seen[0].contains("somebody-elses-value"));
    assert!(!seen[0].contains(REAL));
    assert!(
        run.events.try_recv().is_err(),
        "no key was used, so nothing to record"
    );
}

#[test]
fn an_ended_permission_no_longer_turns_into_the_key() {
    let auth = format!("Authorization: Bearer {FAKE}");
    let removed = run();
    assert_eq!(curl(&removed, &["-H", &auth, &url("/")]).1, "200");
    assert!(removed.seen.lock().unwrap()[0].contains(REAL));
    removed.proxy.remove("g-1");
    // With no permission for this host, it gets a plain tunnel, which reaches nothing here.
    assert_ne!(curl(&removed, &["-H", &auth, &url("/")]).1, "200");
    assert_eq!(removed.seen.lock().unwrap().len(), 1);

    let expired = run_with("hello", &["localhost"], false, 1);
    assert_ne!(curl(&expired, &["-H", &auth, &url("/")]).1, "200");
    assert!(expired.seen.lock().unwrap().is_empty());
}

#[test]
fn one_keys_stand_in_is_not_another_hosts() {
    // A second permission for this host must not turn the first one's stand-in into its key.
    let run = run_with("hello", &["localhost"], false, u64::MAX);
    run.proxy.add(Grant {
        id: "g-2".into(),
        key: "other".into(),
        stand_in: Secret::new("other-stand-in-000000"),
        real: Secret::new("other-real-key-000000"),
        hosts: vec!["localhost".into()],
        in_url: false,
        expires: u64::MAX,
    });
    let header = "Authorization: Bearer other-stand-in-000000";
    assert_eq!(curl(&run, &["-H", header, &url("/")]).1, "200");
    let seen = run.seen.lock().unwrap();
    assert!(seen[0].contains("other-real-key-000000"));
    assert!(!seen[0].contains(REAL));
}

#[test]
fn another_host_gets_a_tunnel_and_never_the_key() {
    // This key is for another host, so the proxy does not end TLS, and curl's own check of the
    // upstream fails: proof the stand-in was not read, let alone swapped.
    let run = run_with("hello", &["api.example.com"], false, u64::MAX);
    let (_, code) = curl(
        &run,
        &[
            "-H",
            &format!("Authorization: Bearer {FAKE}"),
            &format!("https://localhost:{}/", run.upstream),
        ],
    );
    assert_ne!(code, "200");
    assert!(run.seen.lock().unwrap().is_empty());
}

#[test]
fn the_key_never_reaches_a_host_that_is_not_its_own() {
    // Port 443 of a host this key is not for. Were the proxy to end TLS here, the test's upstream would
    // receive the request with the real key. A tunnel to port 443 of this machine reaches nothing.
    let run = run_with("hello", &["api.example.com"], false, u64::MAX);
    let (_, code) = curl(
        &run,
        &["-H", &format!("Authorization: Bearer {FAKE}"), &url("/")],
    );
    assert_ne!(code, "200");
    assert!(
        run.seen.lock().unwrap().is_empty(),
        "the request got through"
    );
    assert!(run.events.try_recv().is_err(), "the proxy read the request");
}

#[test]
fn a_host_header_naming_elsewhere_is_refused() {
    let run = run();
    let (_, code) = curl(&run, &["-H", "Host: evil.example.com", &url("/")]);
    assert_eq!(code, "421");
    assert!(run.seen.lock().unwrap().is_empty());
}

#[test]
fn a_big_body_arrives_whole() {
    let run = run();
    let body = "x".repeat(300_000);
    let file = run.folder.join("body");
    std::fs::write(&file, &body).unwrap();
    let (_, code) = curl(
        &run,
        &["--data-binary", &format!("@{}", file.display()), &url("/")],
    );
    assert_eq!(code, "200");
    assert!(run.seen.lock().unwrap()[0].ends_with(&body));
}

#[test]
fn trust_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let run = run();
    let mode = std::fs::metadata(&run.bundle).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(std::fs::read_to_string(&run.bundle)
        .unwrap()
        .contains("BEGIN CERTIFICATE"));
}

#[test]
fn a_request_cut_short_does_not_stop_others() {
    let run = run();
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", run.port)).unwrap();
    stream.write_all(b"CONNECT localhost").unwrap();
    drop(stream);
    assert_eq!(curl(&run, &[&url("/")]).1, "200");
}

#[test]
fn a_tunnel_does_not_reach_this_machine_or_a_private_network() {
    // As in use: a program that can reach the proxy, from a sandbox too, must not use it to reach what
    // its own network rules shut out.
    let (proxy, _events) = Proxy::new(Options::default()).unwrap();
    let port = proxy.listen().unwrap();
    for target in [
        "127.0.0.1:22",
        "localhost:5432",
        "169.254.169.254:80",
        "192.168.1.1:443",
    ] {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )
        .unwrap();
        let mut answer = String::new();
        let _ = std::io::BufReader::new(stream).read_line(&mut answer);
        assert!(answer.contains(" 403 "), "{target}: {answer}");
    }
}
