//! The proxy under the traffic a coding agent's harness makes to a model provider: answers that take minutes
//! to start, and streams of events that must arrive as they are sent.
#![cfg(unix)]

use keyreeve::proxy::{Event, Grant, Options, Proxy, REPLY_TIMEOUT};
use keyreeve::secret::Secret;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const REAL: &str = "real-key-0123456789";
const FAKE: &str = "fake-key-9876543210";
static NEXT: AtomicUsize = AtomicUsize::new(0);

type Tls = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

/// A provider that reads each request's head and then does what `answer` says.
fn provider(answer: fn(&mut Tls)) -> (u16, CertificateDer<'static>) {
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
    thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            let config = config.clone();
            thread::spawn(move || {
                let _ = socket.set_nodelay(true);
                let connection = rustls::ServerConnection::new(config).unwrap();
                let mut stream = BufReader::new(rustls::StreamOwned::new(connection, socket));
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                answer(stream.get_mut());
                let inner = stream.get_mut();
                inner.conn.send_close_notify();
                let _ = inner.flush();
            });
        }
    });
    (port, root)
}

struct Run {
    port: u16,
    bundle: PathBuf,
    events: Receiver<Event>,
    folder: PathBuf,
    _proxy: Arc<Proxy>,
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

fn through_proxy(answer: fn(&mut Tls), reply_timeout: Option<Duration>) -> Run {
    let (upstream, root) = provider(answer);
    let (proxy, events) = Proxy::new(Options {
        extra_roots: vec![root],
        upstream_port: Some(upstream),
        private_tunnels: true,
        reply_timeout,
        ..Default::default()
    })
    .unwrap();
    let folder = std::env::temp_dir().join(format!(
        "keyreeve-llm-{}-{}",
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
        hosts: vec!["localhost".into()],
        in_url: false,
        local: None,
        expires: u64::MAX,
    });
    Run {
        port,
        bundle: trust.bundle,
        events,
        folder,
        _proxy: proxy,
    }
}

fn curl(run: &Run) -> Command {
    curl_with(run, true)
}

/// A real client with the environment a command gets, sending the stand-in or not.
fn curl_with(run: &Run, with_key: bool) -> Command {
    let mut command = Command::new("curl");
    command.args([
        "-sS",
        "-N",
        "--max-time",
        "30",
        "-o",
        "-",
        "-w",
        "\n%{http_code}",
    ]);
    if with_key {
        command.args(["-H", &format!("Authorization: Bearer {FAKE}")]);
    }
    command
        .arg("https://localhost/v1/messages")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{}", run.port))
        .env("CURL_CA_BUNDLE", &run.bundle);
    command
}

fn answer_after_two_seconds(stream: &mut Tls) {
    thread::sleep(Duration::from_secs(2));
    let _ =
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone");
}

#[test]
fn the_proxy_waits_as_long_as_the_providers_own_clients_do() {
    // The OpenAI and Anthropic SDKs wait 10 minutes for an answer. A model that thinks for a few minutes
    // before its first byte must not be cut off by the proxy in between.
    assert!(REPLY_TIMEOUT >= Duration::from_secs(600));
}

#[test]
fn an_answer_slower_than_the_wait_is_a_504_that_says_so() {
    let run = through_proxy(answer_after_two_seconds, Some(Duration::from_millis(500)));
    let output = curl(&run).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    let (body, code) = text.rsplit_once('\n').unwrap();
    assert_eq!(code, "504", "{text}");
    assert!(body.contains("did not answer"), "{body}");
    let event = run.events.recv().unwrap();
    assert_eq!(
        (event.status, event.outcome.as_str()),
        (0, "no reply in time")
    );
}

#[test]
fn an_answer_within_the_wait_arrives_whole() {
    let run = through_proxy(answer_after_two_seconds, Some(Duration::from_secs(10)));
    let output = curl(&run).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(text, "done\n200");
    assert_eq!(run.events.recv().unwrap().outcome, "complete");
}

const EVENTS: usize = 6;
const GAP: Duration = Duration::from_millis(300);

fn stream_events(stream: &mut Tls) {
    let _ = stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    );
    let _ = stream.flush();
    for index in 0..EVENTS {
        let event = format!("data: {{\"delta\":\"token {index}\"}}\n\n");
        let _ = write!(stream, "{:x}\r\n{event}\r\n", event.len());
        let _ = stream.flush();
        thread::sleep(GAP);
    }
    let _ = stream.write_all(b"0\r\n\r\n");
}

fn stream_close_delimited(stream: &mut Tls) {
    let _ = stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
    );
    let _ = stream.flush();
    for index in 0..EVENTS {
        let _ = write!(stream, "data: {{\"delta\":\"token {index}\"}}\n\n");
        let _ = stream.flush();
        thread::sleep(GAP);
    }
}

/// When each event reached the command, counted from the first one.
fn arrivals(run: &Run, with_key: bool) -> Vec<Duration> {
    let mut child = curl_with(run, with_key)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut seen = Vec::new();
    let mut first = None;
    loop {
        let mut line = String::new();
        if out.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.starts_with("data:") {
            let now = Instant::now();
            seen.push(now - *first.get_or_insert(now));
        }
    }
    child.wait().unwrap();
    seen
}

fn assert_streamed(seen: &[Duration]) {
    assert_eq!(seen.len(), EVENTS, "{seen:?}");
    for (index, at) in seen.iter().enumerate() {
        let expected = GAP * u32::try_from(index).unwrap();
        // Held back, an event would arrive with the next one, a whole gap late.
        assert!(
            at.abs_diff(expected) < Duration::from_millis(150),
            "event {index} arrived at {at:?}, sent at {expected:?}: {seen:?}"
        );
    }
}

#[test]
fn a_chunked_stream_arrives_event_by_event() {
    let run = through_proxy(stream_events, None);
    assert_streamed(&arrivals(&run, true));
}

#[test]
fn a_stream_with_no_framing_arrives_event_by_event() {
    let run = through_proxy(stream_close_delimited, None);
    assert_streamed(&arrivals(&run, true));
}

#[test]
fn a_stream_to_a_key_host_without_the_key_arrives_event_by_event_too() {
    // A request with no stand-in goes out as it came, through another path that relays the answer.
    let run = through_proxy(stream_close_delimited, None);
    assert_streamed(&arrivals(&run, false));
}

fn answer_at_once(stream: &mut Tls) {
    let _ =
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
}

/// What the proxy adds to each request, against a provider on this machine. Not a test: run with
/// `cargo test --release --test proxy_llm -- --ignored --nocapture`.
#[test]
#[ignore]
fn cost_per_request() {
    const COUNT: usize = 100;
    let run = through_proxy(answer_at_once, None);
    let (direct_port, root) = provider(answer_at_once);
    let root_file = run.folder.join("direct.pem");
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_lines(root.as_ref())
    );
    std::fs::write(&root_file, pem).unwrap();
    let timed = |proxied: bool| {
        let started = Instant::now();
        for _ in 0..COUNT {
            let mut command = Command::new("curl");
            command.args(["-sS", "-o", "/dev/null"]).env_clear();
            if proxied {
                command
                    .args([
                        "-H",
                        &format!("Authorization: Bearer {FAKE}"),
                        "https://localhost/",
                    ])
                    .env("HTTPS_PROXY", format!("http://127.0.0.1:{}", run.port))
                    .env("CURL_CA_BUNDLE", &run.bundle);
            } else {
                command
                    .arg(format!("https://localhost:{direct_port}/"))
                    .env("CURL_CA_BUNDLE", &root_file);
            }
            assert!(command.status().unwrap().success());
        }
        started.elapsed() / u32::try_from(COUNT).unwrap()
    };
    let direct = timed(false);
    let proxied = timed(true);
    println!(
        "per request: direct {direct:?}, through the proxy {proxied:?}, added {:?}",
        proxied.saturating_sub(direct)
    );
    while run.events.try_recv().is_ok() {}
}

fn base64_lines(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                TABLE[(n >> (18 - 6 * i)) as usize & 63] as char
            } else {
                '='
            });
        }
    }
    out.as_bytes()
        .chunks(64)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}
