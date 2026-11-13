//! A key for a service of your own on this Mac: plain HTTP through the proxy to the one loopback address and
//! port approved for it, with real clients, and a local server that writes down what reached it.
#![cfg(unix)]

use keyreeve::proxy::{Event, Grant, LocalService, Options, Proxy};
use keyreeve::secret::Secret;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;

const REAL: &str = "real-key-0123456789abcdefghij";
const FAKE: &str = "fake-key-9876543210zyxwvutsrq";

struct Local {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

/// A plain HTTP server on 127.0.0.1 that records each request whole and answers `reply`.
fn local_server(reply: &'static str) -> Local {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            let record = record.clone();
            thread::spawn(move || {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut text = String::new();
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                    text.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                text.push_str(&String::from_utf8_lossy(&body));
                record.lock().unwrap().push(text);
                let mut socket = socket;
                let _ = write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            });
        }
    });
    Local { port, seen }
}

struct Run {
    proxy: Arc<Proxy>,
    port: u16,
    events: Receiver<Event>,
    local: Local,
}

/// The proxy as `use` runs it, with no way through to this machine, and one key approved for the local server.
fn run_with(reply: &'static str, expires: u64) -> Run {
    let local = local_server(reply);
    let (proxy, events) = Proxy::new(Options::default()).unwrap();
    let port = proxy.listen().unwrap();
    proxy.add(Grant {
        id: "g-1".into(),
        key: "mesa-token".into(),
        stand_in: Secret::new(FAKE),
        real: Secret::new(REAL),
        hosts: Vec::new(),
        in_url: false,
        local: Some(LocalService::parse(&format!("127.0.0.1:{}", local.port)).unwrap()),
        expires,
    });
    Run {
        proxy,
        port,
        events,
        local,
    }
}

fn run() -> Run {
    run_with("hola", u64::MAX)
}

/// curl as a command started by `use` would run it: `http_proxy` set, and nothing else.
fn curl(run: &Run, args: &[&str]) -> (String, String) {
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "15", "-o", "-", "-w", "\n%{http_code}"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("http_proxy", format!("http://127.0.0.1:{}", run.port))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", ""));
    (body.to_owned(), code.to_owned())
}

fn bearer() -> String {
    format!("Authorization: Bearer {FAKE}")
}

#[test]
fn the_real_key_reaches_the_approved_service_and_the_command_never_sees_it() {
    let run = run();
    let address = format!("http://127.0.0.1:{}/v1/eventos?desde=3", run.local.port);
    let (body, code) = curl(&run, &["-H", &bearer(), &address]);
    assert_eq!((body.as_str(), code.as_str()), ("hola", "200"));
    let seen = run.local.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].starts_with("GET /v1/eventos?desde=3 HTTP/1.1\r\n"),
        "{}",
        seen[0]
    );
    assert!(
        seen[0].contains(&format!("Authorization: Bearer {REAL}")),
        "{}",
        seen[0]
    );
    assert!(!seen[0].contains(FAKE));
    assert!(!seen[0].to_ascii_lowercase().contains("proxy-"));
    let event = run.events.recv().unwrap();
    assert_eq!(
        (
            event.key.as_str(),
            event.method.as_str(),
            event.path.as_str(),
            event.status
        ),
        ("mesa-token", "GET", "/v1/eventos", 200)
    );
    assert_eq!(event.host, format!("127.0.0.1:{}", run.local.port));
    assert_eq!(event.outcome, "complete");
}

#[test]
fn a_service_that_echoes_the_key_gives_back_the_stand_in() {
    let run = run_with(REAL, u64::MAX);
    let address = format!("http://127.0.0.1:{}/", run.local.port);
    let (body, code) = curl(&run, &["-H", &bearer(), &address]);
    assert_eq!((body.as_str(), code.as_str()), (FAKE, "200"));
}

#[test]
fn a_body_is_sent_whole_and_keeps_its_stand_in() {
    let run = run();
    let address = format!("http://127.0.0.1:{}/v1/asignaciones", run.local.port);
    let body = format!("{{\"lead\":\"x\",\"echo\":\"{FAKE}\"}}");
    let (_, code) = curl(&run, &["-H", &bearer(), "--data", &body, &address]);
    assert_eq!(code, "200");
    let seen = run.local.seen.lock().unwrap();
    assert!(seen[0].starts_with("POST /v1/asignaciones HTTP/1.1\r\n"));
    assert!(seen[0].ends_with(&body), "{}", seen[0]);
    assert!(seen[0].contains(&format!("Bearer {REAL}")));
}

#[test]
fn another_port_on_this_machine_gets_nothing() {
    let run = run();
    let other = local_server("other");
    for address in [
        format!("http://127.0.0.1:{}/", other.port),
        // The same port, written another way, is another address: only the one approved goes through.
        format!("http://localhost:{}/", run.local.port),
        "http://10.0.0.1/".to_owned(),
        "http://169.254.169.254/latest/meta-data/".to_owned(),
        "http://example.com/".to_owned(),
    ] {
        let (_, code) = curl(&run, &["-H", &bearer(), &address]);
        assert_eq!(code, "403", "{address}");
    }
    assert!(other.seen.lock().unwrap().is_empty());
    assert!(run.local.seen.lock().unwrap().is_empty());
}

#[test]
fn a_request_with_no_stand_in_does_not_reach_the_service() {
    let run = run();
    let address = format!("http://127.0.0.1:{}/v1/eventos", run.local.port);
    let (_, code) = curl(&run, &[&address]);
    assert_eq!(code, "403");
    let (_, code) = curl(
        &run,
        &["-H", "Authorization: Bearer someone-else", &address],
    );
    assert_eq!(code, "403");
    assert!(run.local.seen.lock().unwrap().is_empty());
}

#[test]
fn the_key_never_goes_in_the_address() {
    let run = run();
    let address = format!(
        "http://127.0.0.1:{}/v1/eventos?token={FAKE}",
        run.local.port
    );
    let (body, code) = curl(&run, &["-H", &bearer(), &address]);
    assert_eq!(code, "400", "{body}");
    assert!(body.contains("header"), "{body}");
    assert!(run.local.seen.lock().unwrap().is_empty());
}

#[test]
fn a_host_header_naming_elsewhere_is_refused() {
    let run = run();
    let address = format!("http://127.0.0.1:{}/", run.local.port);
    let (_, code) = curl(
        &run,
        &["-H", &bearer(), "-H", "Host: example.com", &address],
    );
    assert_eq!(code, "421");
    assert!(run.local.seen.lock().unwrap().is_empty());
}

#[test]
fn an_ended_permission_lets_nothing_through() {
    let run = run();
    run.proxy.remove("g-1");
    let address = format!("http://127.0.0.1:{}/", run.local.port);
    assert_eq!(curl(&run, &["-H", &bearer(), &address]).1, "403");
    let expired = run_with("hola", 1);
    let address = format!("http://127.0.0.1:{}/", expired.local.port);
    assert_eq!(curl(&expired, &["-H", &bearer(), &address]).1, "403");
    assert!(run.local.seen.lock().unwrap().is_empty());
    assert!(expired.local.seen.lock().unwrap().is_empty());
}

#[test]
fn a_tunnel_still_does_not_reach_the_local_service() {
    // The approval is for plain HTTP with the key, not a way for any program to reach that port.
    let run = run();
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", run.port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let target = format!("127.0.0.1:{}", run.local.port);
    write!(
        stream,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
    )
    .unwrap();
    let mut answer = String::new();
    let _ = BufReader::new(stream).read_line(&mut answer);
    assert!(answer.contains(" 403 "), "{answer}");
    assert!(run.local.seen.lock().unwrap().is_empty());
}

#[test]
fn nothing_listening_is_written_down_as_not_sent() {
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let (proxy, events) = Proxy::new(Options::default()).unwrap();
    let port = proxy.listen().unwrap();
    proxy.add(Grant {
        id: "g-1".into(),
        key: "mesa-token".into(),
        stand_in: Secret::new(FAKE),
        real: Secret::new(REAL),
        hosts: Vec::new(),
        in_url: false,
        local: Some(LocalService::parse(&format!("127.0.0.1:{closed}")).unwrap()),
        expires: u64::MAX,
    });
    let run = Run {
        proxy,
        port,
        events,
        local: local_server("unused"),
    };
    let address = format!("http://127.0.0.1:{closed}/");
    assert_eq!(curl(&run, &["-H", &bearer(), &address]).1, "502");
    let event = run.events.recv().unwrap();
    assert_eq!((event.outcome.as_str(), event.status), ("not sent", 0));
}

#[test]
fn python_reaches_it_through_the_proxy_too() {
    // The clients of these services are Python scripts with urllib, which must not skip the proxy for 127.0.0.1.
    let Ok(python) = which("python3") else {
        return;
    };
    let run = run();
    let address = format!("http://127.0.0.1:{}/v1/eventos", run.local.port);
    let script = "import os, sys, urllib.request\n\
        r = urllib.request.Request(sys.argv[1], headers={'Authorization': 'Bearer ' + os.environ['MESA_TOKEN']})\n\
        print(urllib.request.urlopen(r, timeout=15).read().decode())";
    let output = Command::new(python)
        .args(["-I", "-c", script, &address])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("MESA_TOKEN", FAKE)
        .env("HTTP_PROXY", format!("http://127.0.0.1:{}", run.port))
        .env("http_proxy", format!("http://127.0.0.1:{}", run.port))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hola",
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let seen = run.local.seen.lock().unwrap();
    assert!(seen[0].contains(&format!("Bearer {REAL}")), "{}", seen[0]);
}

fn which(name: &str) -> Result<String, ()> {
    let output = Command::new("/usr/bin/which")
        .arg(name)
        .output()
        .map_err(|_| ())?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if output.status.success() && !path.is_empty() {
        Ok(path)
    } else {
        Err(())
    }
}
