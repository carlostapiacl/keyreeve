//! Lets a command use a key it never holds. The command gets a stand-in with the key's shape, and calls
//! the real address through this proxy. Only on the way to a host that key belongs to does the proxy
//! end TLS and put the real value in the request's headers. Sent anywhere else, the stand-in is useless.
//!
//! The stand-in is also the credential for the proxy. Holding it is what lets a request use the key, so
//! no token has to live next to it, and it works with clients that do not send proxy credentials.
//!
//! The real value arrives from the vault's service over stdin, and stays in memory. Every other host
//! gets a plain tunnel, with TLS end to end. This does not confine a program: it keeps the key out of
//! the program's hands, and what the program can do with its other permissions is its own matter.

use crate::secret::Secret;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection, StreamOwned};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod authority;
mod control;
mod http;

use authority::{crypto, Authority};
pub use control::{can_stand_in, serve_from_stdin};
use http::{
    answer, base64_decode, base64_encode, body_framing, copy_body, header, read_head, relay_reply,
    split_target, status_of, Scrubber,
};

const IO_TIMEOUT: Duration = Duration::from_secs(60);
const TUNNEL_IDLE: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 128;
const SYSTEM_BUNDLES: &[&str] = &["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"];

/// What one permission lets through.
pub struct Grant {
    pub id: String,
    pub key: String,
    pub stand_in: Secret,
    pub real: Secret,
    pub hosts: Vec<String>,
    /// The provider takes this key in the address, so it is swapped there too.
    pub in_url: bool,
    pub expires: u64,
}

/// One request that went out with a key. It holds no value, and no query string, which can carry anything.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Event {
    pub grant: String,
    pub key: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}

fn random_bytes(count: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; count];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut out)
        .map_err(|_| io::Error::other("no random numbers"))?;
    Ok(out)
}

/// A stand-in of the same length and shape: the provider's prefix stays, and each other letter or
/// digit becomes a random one of its kind. Tools that check a key's format accept it, and swapping it
/// changes no length, so a request's framing stays as it was.
pub fn mint_stand_in(real: &str, prefixes: &[String]) -> Result<String, String> {
    let prefix = prefixes
        .iter()
        .filter(|prefix| real.starts_with(prefix.as_str()))
        .map(String::len)
        .max()
        .unwrap_or(0);
    let random = random_bytes(real.len()).map_err(|e| e.to_string())?;
    let mut out = real[..prefix].to_owned();
    for (index, character) in real[prefix..].chars().enumerate() {
        let pick = random[index % random.len()] as usize;
        out.push(match character {
            'a'..='z' => (b'a' + (pick % 26) as u8) as char,
            'A'..='Z' => (b'A' + (pick % 26) as u8) as char,
            '0'..='9' => (b'0' + (pick % 10) as u8) as char,
            other => other,
        });
    }
    // It works as a password for the proxy, so it needs enough randomness to be one.
    let random_part = real[prefix..]
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .count();
    if random_part < 16 {
        return Err("this key is too short to stand in for, so it needs --real".into());
    }
    Ok(out)
}

/// How the proxy reaches the world. Tests point it at a local server they trust.
#[derive(Default, Clone)]
pub struct Options {
    pub extra_roots: Vec<CertificateDer<'static>>,
    /// Sends what would go to port 443 of a key's host to this port on the same host.
    pub upstream_port: Option<u16>,
}

pub struct Proxy {
    grants: Mutex<HashMap<String, Arc<Grant>>>,
    authority: Authority,
    upstream: Arc<ClientConfig>,
    options: Options,
    events: Mutex<mpsc::Sender<Event>>,
    active: AtomicUsize,
}

pub struct Trust {
    /// The CA alone, for tools that add to what they already trust.
    pub ca: PathBuf,
    /// The CA and the system's roots, for tools that replace what they trust.
    pub bundle: PathBuf,
}

impl Proxy {
    pub fn new(options: Options) -> io::Result<(Arc<Self>, mpsc::Receiver<Event>)> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for root in &options.extra_roots {
            roots.add(root.clone()).map_err(io::Error::other)?;
        }
        let mut upstream = ClientConfig::builder_with_provider(crypto())
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream.alpn_protocols = vec![b"http/1.1".to_vec()];
        let (sender, receiver) = mpsc::channel();
        Ok((
            Arc::new(Self {
                grants: Mutex::new(HashMap::new()),
                authority: Authority::new()?,
                upstream: Arc::new(upstream),
                options,
                events: Mutex::new(sender),
                active: AtomicUsize::new(0),
            }),
            receiver,
        ))
    }

    /// Writes what a command needs to trust this proxy. Private, like everything of yours here.
    pub fn write_trust(&self, folder: &Path) -> io::Result<Trust> {
        std::fs::create_dir_all(folder)?;
        let write = |path: &Path, text: &str| -> io::Result<()> {
            std::fs::write(path, text)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        };
        let ca = folder.join("ca.pem");
        write(&ca, &self.authority.pem)?;
        let mut bundle_text = self.authority.pem.trim_end().to_owned();
        bundle_text.push('\n');
        if let Some(system) = SYSTEM_BUNDLES
            .iter()
            .find_map(|path| std::fs::read_to_string(path).ok())
        {
            bundle_text.push_str(&system);
        }
        let bundle = folder.join("bundle.pem");
        write(&bundle, &bundle_text)?;
        Ok(Trust { ca, bundle })
    }

    pub fn add(&self, grant: Grant) {
        self.grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(grant.id.clone(), Arc::new(grant));
    }

    pub fn remove(&self, id: &str) {
        self.grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }

    /// The permissions in force for this host. An ended one is gone, and its stand-in with it.
    fn grants_for(&self, host: &str) -> Vec<Arc<Grant>> {
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        grants.retain(|_, grant| grant.expires > now());
        grants
            .values()
            .filter(|grant| {
                grant
                    .hosts
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(host))
            })
            .cloned()
            .collect()
    }

    pub fn listen(self: &Arc<Self>) -> io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let proxy = self.clone();
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                if proxy.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    proxy.active.fetch_sub(1, Ordering::SeqCst);
                    let mut client = client;
                    let _ = client.write_all(b"HTTP/1.1 503 Busy\r\nConnection: close\r\n\r\n");
                    continue;
                }
                let proxy = proxy.clone();
                thread::spawn(move || {
                    let _ = proxy.connection(client);
                    proxy.active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Ok(port)
    }

    fn connection(self: &Arc<Self>, client: TcpStream) -> io::Result<()> {
        client.set_read_timeout(Some(IO_TIMEOUT))?;
        client.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut reader = BufReader::new(client.try_clone()?);
        let (first, _) = read_head(&mut reader)?;
        let mut writer = client;
        let mut parts = first.split(' ');
        let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        if method != "CONNECT" {
            return answer(&mut writer, 405, "only CONNECT goes through here");
        }
        let Some((host, port)) = split_target(target) else {
            return answer(&mut writer, 400, "that is not host:port");
        };
        if port == 443 && !self.grants_for(&host).is_empty() {
            writer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
            return self.terminated(&host, writer, reader);
        }
        self.tunnel(&host, port, writer, reader)
    }

    /// Everything else stays end to end. The stand-in is useless there, so nothing needs reading.
    fn tunnel(
        &self,
        host: &str,
        port: u16,
        mut client: TcpStream,
        reader: BufReader<TcpStream>,
    ) -> io::Result<()> {
        let upstream = match TcpStream::connect((host, port)) {
            Ok(stream) => stream,
            Err(_) => return answer(&mut client, 502, "that host could not be reached"),
        };
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
        client.set_read_timeout(Some(TUNNEL_IDLE))?;
        upstream.set_read_timeout(Some(TUNNEL_IDLE))?;
        // A side that stops reading must not hold this thread for good.
        client.set_write_timeout(Some(TUNNEL_IDLE))?;
        upstream.set_write_timeout(Some(TUNNEL_IDLE))?;
        // What the client sent past its CONNECT is already in the reader, so it goes first.
        let mut reader = reader;
        let mut up_write = upstream.try_clone()?;
        let mut client_write = client.try_clone()?;
        let mut up_read = upstream;
        let sending = thread::spawn(move || {
            let _ = io::copy(&mut reader, &mut up_write);
            let _ = up_write.shutdown(Shutdown::Write);
        });
        let _ = io::copy(&mut up_read, &mut client_write);
        let _ = client_write.shutdown(Shutdown::Both);
        let _ = sending.join();
        Ok(())
    }

    fn terminated(
        &self,
        host: &str,
        client: TcpStream,
        leftover: BufReader<TcpStream>,
    ) -> io::Result<()> {
        // A client waits for the 200 before its handshake, so nothing is buffered past the head.
        drop(leftover);
        let config = self.authority.for_host(host)?;
        let connection = ServerConnection::new(config).map_err(io::Error::other)?;
        let mut stream = BufReader::new(StreamOwned::new(connection, client));
        let (first, mut headers) = read_head(&mut stream)?;
        let mut parts = first.split(' ');
        let (method, target, version) = (
            parts.next().unwrap_or("").to_owned(),
            parts.next().unwrap_or("").to_owned(),
            parts.next().unwrap_or(""),
        );
        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            return answer(stream.get_mut(), 400, "bad request");
        }
        // Each of these could name a host other than the one this key was let through for.
        let names_host = |value: &str| {
            split_target(value).map_or(value.eq_ignore_ascii_case(host), |(name, port)| {
                port == 443 && name.eq_ignore_ascii_case(host)
            })
        };
        let sni_matches = stream
            .get_ref()
            .conn
            .server_name()
            .is_none_or(|name| name.eq_ignore_ascii_case(host));
        let hosts: Vec<&(String, String)> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .collect();
        if !target.starts_with('/')
            || !sni_matches
            || hosts.len() > 1
            || hosts.first().is_some_and(|(_, value)| !names_host(value))
        {
            return answer(stream.get_mut(), 421, "this connection is for another host");
        }
        let framing = match body_framing(&headers) {
            Ok(framing) => framing,
            Err(()) => return answer(stream.get_mut(), 400, "bad request framing"),
        };
        if header(&headers, "expect")
            .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
        {
            stream
                .get_mut()
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            stream.get_mut().flush()?;
        }
        // Holding a stand-in is what lets a request use its key. With none, it goes out as it came.
        let grant = self.grants_for(host).into_iter().find(|grant| {
            (grant.in_url && target.contains(grant.stand_in.expose()))
                || headers.iter().any(|(name, value)| {
                    !name.eq_ignore_ascii_case("host") && swap_header(value, grant) != *value
                })
        });
        headers.retain(|(name, _)| {
            ![
                "proxy-authorization",
                "proxy-connection",
                "connection",
                "keep-alive",
                "te",
                "upgrade",
                "expect",
                "accept-encoding",
            ]
            .iter()
            .any(|drop| name.eq_ignore_ascii_case(drop))
        });
        let mut out = format!(
            "{method} {} HTTP/1.1\r\n",
            match &grant {
                Some(grant) if grant.in_url => {
                    target.replace(grant.stand_in.expose(), grant.real.expose())
                }
                _ => target.clone(),
            }
        );
        for (name, value) in &headers {
            let value = match &grant {
                Some(grant) if !name.eq_ignore_ascii_case("host") => swap_header(value, grant),
                _ => value.clone(),
            };
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        // One request per connection keeps the framing simple. Plain text lets the reply be read,
        // in case the provider echoes the real key.
        out.push_str("Accept-Encoding: identity\r\nConnection: close\r\n\r\n");

        let port = self.options.upstream_port.unwrap_or(443);
        let name = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
        let connection =
            ClientConnection::new(self.upstream.clone(), name).map_err(io::Error::other)?;
        let socket = match TcpStream::connect((host, port)) {
            Ok(socket) => socket,
            Err(_) => return answer(stream.get_mut(), 502, "that host could not be reached"),
        };
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut upstream = StreamOwned::new(connection, socket);
        // Connecting takes a moment, and the permission can end during it.
        if let Some(grant) = &grant {
            if !self.grants_for(host).iter().any(|live| live.id == grant.id) {
                return answer(stream.get_mut(), 403, "that permission has ended");
            }
        }
        let sent = (|| -> io::Result<()> {
            upstream.write_all(out.as_bytes())?;
            copy_body(&framing, &mut stream, &mut upstream)?;
            upstream.flush()
        })();
        if sent.is_err() {
            return answer(stream.get_mut(), 502, "the request could not be sent");
        }
        let mut scrub = grant
            .as_ref()
            .map(|grant| Scrubber::new(grant.real.expose(), grant.stand_in.expose()));
        let status = match &mut scrub {
            Some(scrub) => relay_reply(&mut upstream, stream.get_mut(), scrub)?,
            None => {
                let mut status = 0;
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    let count = match upstream.read(&mut buffer) {
                        Ok(count) => count,
                        // Many servers close without a TLS goodbye, once they have said it all.
                        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => 0,
                        Err(error) => return Err(error),
                    };
                    if count == 0 {
                        break status;
                    }
                    if status == 0 {
                        status = status_of(&buffer[..count]);
                    }
                    stream.get_mut().write_all(&buffer[..count])?;
                }
            }
        };
        stream.get_mut().flush()?;
        stream.get_mut().conn.send_close_notify();
        let _ = stream.get_mut().flush();
        let Some(grant) = grant else {
            return Ok(());
        };
        // A provider that takes its key in the address puts the stand-in in the path, and the stand-in
        // works through this proxy while the permission lasts, so neither it nor the key is kept.
        let mut path = target.split('?').next().unwrap_or("").to_owned();
        for secret in [grant.stand_in.expose(), grant.real.expose()] {
            // An empty one would match between every character.
            if !secret.is_empty() {
                path = path.replace(secret, "{key}");
            }
        }
        let path = path.chars().take(200).collect();
        let event = Event {
            grant: grant.id.clone(),
            key: grant.key.clone(),
            host: host.to_owned(),
            method,
            path,
            status,
        };
        let _ = self
            .events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(event);
        Ok(())
    }
}

/// Only in headers: a stand-in in a request's body could be reflected back as the real key by a provider
/// that stores it. A tool that puts the key in a body fails, with the stand-in, and leaks nothing.
fn swap_header(value: &str, grant: &Grant) -> String {
    let (fake, real) = (grant.stand_in.expose(), grant.real.expose());
    if let Some(encoded) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    {
        if let Some(decoded) =
            base64_decode(encoded).and_then(|bytes| String::from_utf8(bytes).ok())
        {
            if decoded.contains(fake) {
                return format!(
                    "Basic {}",
                    base64_encode(decoded.replace(fake, real).as_bytes())
                );
            }
        }
    }
    value.replace(fake, real)
}

#[cfg(test)]
mod tests {
    use super::http::Framing;
    use super::*;

    fn grant() -> Grant {
        Grant {
            id: "g".into(),
            key: "k".into(),
            stand_in: Secret::new("fake-value-0123"),
            real: Secret::new("real-value-9876"),
            hosts: vec!["api.example.com".into()],
            in_url: false,
            expires: u64::MAX,
        }
    }

    #[test]
    fn a_stand_in_keeps_the_shape_and_nothing_else() {
        let real = "re_AbCd-1234.efghIJKLmnop";
        let fake = mint_stand_in(real, &["re_".into()]).unwrap();
        assert_eq!(fake.len(), real.len());
        assert!(fake.starts_with("re_"));
        assert_ne!(fake, real);
        for (a, b) in real.chars().zip(fake.chars()) {
            assert_eq!(a.is_ascii_uppercase(), b.is_ascii_uppercase());
            assert_eq!(a.is_ascii_lowercase(), b.is_ascii_lowercase());
            assert_eq!(a.is_ascii_digit(), b.is_ascii_digit());
        }
        assert!(mint_stand_in("short", &[]).is_err());
        assert!(mint_stand_in("re_abcd", &["re_".into()]).is_err());
        assert_ne!(
            mint_stand_in(real, &[]).unwrap(),
            mint_stand_in(real, &[]).unwrap()
        );
    }

    #[test]
    fn headers_swap_plainly_and_inside_basic() {
        let grant = grant();
        assert_eq!(
            swap_header("Bearer fake-value-0123", &grant),
            "Bearer real-value-9876"
        );
        assert_eq!(swap_header("no match", &grant), "no match");
        let basic = format!("Basic {}", base64_encode(b"user:fake-value-0123"));
        let swapped = swap_header(&basic, &grant);
        let decoded = base64_decode(swapped.strip_prefix("Basic ").unwrap()).unwrap();
        assert_eq!(decoded, b"user:real-value-9876");
    }

    #[test]
    fn base64_round_trips() {
        for text in ["", "a", "ab", "abc", "abcd", "user:pass"] {
            let encoded = base64_encode(text.as_bytes());
            assert_eq!(base64_decode(&encoded).unwrap(), text.as_bytes(), "{text}");
        }
        assert!(base64_decode("not base64!").is_none());
    }

    #[test]
    fn the_scrubber_finds_a_value_split_across_reads() {
        let mut scrub = Scrubber::new("real-value", "fake-value");
        let mut out = scrub.push(b"before real-");
        out.extend(scrub.push(b"value after real-val"));
        out.extend(scrub.push(b"ue end"));
        out.extend(scrub.finish());
        assert_eq!(out, b"before fake-value after fake-value end");
    }

    #[test]
    fn framing_refuses_what_could_smuggle() {
        let pair = |a: &str, b: &str| (a.to_owned(), b.to_owned());
        assert!(matches!(body_framing(&[]), Ok(Framing::None)));
        assert!(matches!(
            body_framing(&[pair("Content-Length", "3")]),
            Ok(Framing::Length(3))
        ));
        assert!(matches!(
            body_framing(&[pair("Transfer-Encoding", "chunked")]),
            Ok(Framing::Chunked)
        ));
        assert!(body_framing(&[
            pair("Content-Length", "3"),
            pair("Transfer-Encoding", "chunked")
        ])
        .is_err());
        assert!(body_framing(&[pair("Content-Length", "3"), pair("content-length", "4")]).is_err());
        assert!(body_framing(&[pair("Content-Length", "x")]).is_err());
        assert!(body_framing(&[pair("Transfer-Encoding", "gzip")]).is_err());
    }
}
