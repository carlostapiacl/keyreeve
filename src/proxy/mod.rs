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
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore, ServerConnection, StreamOwned};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod authority;
mod control;
mod http;
mod oauth;

use authority::{crypto, Authority};
pub use control::{can_stand_in, serve_from_stdin};
use http::{
    answer, base64_decode, base64_encode, body_framing, copy_body, header, read_head, relay_reply,
    split_target, status_of, Scrubber,
};
pub use oauth::OAuthGrant;

const IO_TIMEOUT: Duration = Duration::from_secs(60);
/// A host that does not answer would otherwise hold one of the connections until the system gives up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
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
    /// "complete", or how far it got: "not sent", "sent in part" or "no full reply". A request the provider may
    /// have acted on is written down even when its answer never came back whole.
    pub outcome: String,
    /// For an OAuth token exchange: `active` when the provider gave a token, `reauthorize` when it no longer
    /// accepts the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,
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
    // It works as a password for the proxy while the permission lasts, so what it may be guessed by is its
    // randomness: each digit adds log2(10) bits and each letter log2(26), whatever the length.
    let bits: f64 = real[prefix..]
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' => 26f64.log2(),
            '0'..='9' => 10f64.log2(),
            _ => 0.0,
        })
        .sum();
    if bits < MIN_STAND_IN_BITS {
        return Err(format!(
            "this key's shape leaves a stand-in {} bits of randomness, under {MIN_STAND_IN_BITS}, so it needs --real",
            bits.floor()
        ));
    }
    let mut pool = RandomPool::default();
    let mut out = real[..prefix].to_owned();
    for character in real[prefix..].chars() {
        out.push(match character {
            'a'..='z' => (b'a' + pool.below(26)?) as char,
            'A'..='Z' => (b'A' + pool.below(26)?) as char,
            '0'..='9' => (b'0' + pool.below(10)?) as char,
            other => other,
        });
    }
    Ok(out)
}

/// The least randomness a stand-in may have. It can only be guessed by sending requests to this machine's proxy
/// while its permission lasts, a day at most: at 100,000 a second, 64 bits take millions of years. A higher bar
/// would push short real keys, such as some market-data ones, to --real, which hands over the key itself.
pub const MIN_STAND_IN_BITS: f64 = 64.0;

/// Random numbers below a bound, each as likely as the others: a byte past the last whole multiple of the
/// bound is thrown away and another drawn, rather than folded back, which would favour the low ones.
#[derive(Default)]
struct RandomPool {
    bytes: Vec<u8>,
}

impl RandomPool {
    fn below(&mut self, bound: u8) -> Result<u8, String> {
        let limit = 256 - (256 % u16::from(bound));
        loop {
            if self.bytes.is_empty() {
                self.bytes = random_bytes(64).map_err(|e| e.to_string())?;
            }
            let byte = self.bytes.pop().unwrap_or(0);
            if u16::from(byte) < limit {
                return Ok(byte % bound);
            }
        }
    }
}

/// How the proxy reaches the world. Tests point it at a local server they trust.
#[derive(Default, Clone)]
pub struct Options {
    pub extra_roots: Vec<CertificateDer<'static>>,
    /// Sends what would go to port 443 of a key's host to this port on the same host.
    pub upstream_port: Option<u16>,
    /// Lets a tunnel reach this machine and private networks. Off in use: a program that can reach the
    /// proxy, from inside a sandbox too, must not use it to reach what its own network rules shut out.
    pub private_tunnels: bool,
    /// Sends what would go to a key's host to this address instead, keeping the host's name for TLS.
    pub upstream_address: Option<IpAddr>,
}

/// Whether a tunnel may reach this address: not this machine, a private or link-local network, the
/// cloud metadata address, or anything not meant to be reached across the internet.
fn is_public(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || (a == 100 && (64..128).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || first == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

pub struct Proxy {
    grants: Mutex<HashMap<String, Arc<Grant>>>,
    authority: Authority,
    upstream: Arc<ClientConfig>,
    options: Options,
    events: Mutex<mpsc::Sender<Event>>,
    active: AtomicUsize,
    oauth: Mutex<HashMap<String, Arc<oauth::Held>>>,
    oauth_tokens: Mutex<HashMap<[u8; 32], std::sync::Weak<oauth::Tokens>>>,
    oauth_refused: oauth::Refused,
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
                oauth: Mutex::new(HashMap::new()),
                oauth_tokens: Mutex::new(HashMap::new()),
                oauth_refused: Mutex::new(HashSet::new()),
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
        self.oauth
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
        if port == 443 && (!self.grants_for(&host).is_empty() || !self.oauth_for(&host).is_empty())
        {
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
        // Resolved once, and the connection goes to the address checked, so a name that changes its
        // answer between the two cannot slip through.
        let addresses: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
            Ok(found) => found.collect(),
            Err(_) => return answer(&mut client, 502, "that host could not be reached"),
        };
        let allowed: Vec<SocketAddr> = addresses
            .into_iter()
            .filter(|address| self.options.private_tunnels || is_public(&address.ip()))
            .collect();
        if allowed.is_empty() {
            return answer(
                &mut client,
                403,
                "that host is on this machine or a private network",
            );
        }
        let upstream = match connect_within(&allowed) {
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
        // A token request is answered here, and a stand-in access token becomes the real one.
        let oauth =
            match self.oauth_route(host, &method, &target, &headers, &framing, &mut stream)? {
                oauth::Route::Answered => return Ok(()),
                oauth::Route::Use(grant) => Some(grant),
                oauth::Route::Pass => None,
            };
        // Holding a stand-in is what lets a request use its key. With none, it goes out as it came.
        let grant = oauth.or_else(|| {
            self.grants_for(host).into_iter().find(|grant| {
                (grant.in_url && target.contains(grant.stand_in.expose()))
                    || headers.iter().any(|(name, value)| {
                        !name.eq_ignore_ascii_case("host") && swap_header(value, grant) != *value
                    })
            })
        });
        // A provider that takes its key in a header gets none in the address: the stand-in would go out as it is,
        // and the provider would only say the token is wrong. Stopped here, saying where the key goes.
        // Whether or not a header of the same request holds a stand-in too: the address is never swapped for them.
        if self
            .grants_for(host)
            .iter()
            .any(|grant| !grant.in_url && target.contains(grant.stand_in.expose()))
        {
            return answer(
                stream.get_mut(),
                400,
                "keyreeve: this provider takes the key in a header, such as Authorization: Bearer, not in the URL",
            );
        }
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

        let mut upstream = match self.open_upstream(host) {
            Ok(upstream) => upstream,
            Err(_) => {
                self.record(grant.as_deref(), host, &method, &target, 0, "not sent");
                return answer(stream.get_mut(), 502, "that host could not be reached");
            }
        };
        // Connecting takes a moment, and the permission can end during it.
        if let Some(grant) = &grant {
            if !self.is_live(host, &grant.id) {
                self.record(Some(grant), host, &method, &target, 0, "not sent");
                return answer(stream.get_mut(), 403, "that permission has ended");
            }
        }
        let sent = (|| -> io::Result<()> {
            upstream.write_all(out.as_bytes())?;
            copy_body(&framing, &mut stream, &mut upstream)?;
            upstream.flush()
        })();
        if sent.is_err() {
            // Some of it may have reached the provider, which may have acted on it.
            self.record(grant.as_deref(), host, &method, &target, 0, "sent in part");
            return answer(stream.get_mut(), 502, "the request could not be sent");
        }
        let mut scrub = grant
            .as_ref()
            .map(|grant| Scrubber::new(grant.real.expose(), grant.stand_in.expose()));
        let relayed = (|| -> io::Result<u16> {
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
            Ok(status)
        })();
        match relayed {
            Ok(status) => {
                stream.get_mut().conn.send_close_notify();
                let _ = stream.get_mut().flush();
                self.record(grant.as_deref(), host, &method, &target, status, "complete");
                Ok(())
            }
            Err(error) => {
                // Sent whole, so the provider may have acted on it; only its answer was lost.
                self.record(grant.as_deref(), host, &method, &target, 0, "no full reply");
                Err(error)
            }
        }
    }

    /// Writes down one request that went out with a key, however far it got. No value, no stand-in and no
    /// query string: a provider that takes its key in the address has it in the path, kept as `{key}`.
    fn record(
        &self,
        grant: Option<&Grant>,
        host: &str,
        method: &str,
        target: &str,
        status: u16,
        outcome: &str,
    ) {
        let Some(grant) = grant else {
            return;
        };
        let mut path = target.split('?').next().unwrap_or("").to_owned();
        for secret in [grant.stand_in.expose(), grant.real.expose()] {
            // An empty one would match between every character.
            if !secret.is_empty() {
                path = path.replace(secret, "{key}");
            }
        }
        let path = path.chars().take(200).collect();
        self.emit(Event {
            grant: grant.id.clone(),
            key: grant.key.clone(),
            host: host.to_owned(),
            method: method.to_owned(),
            path,
            status,
            outcome: outcome.to_owned(),
            authorization: None,
        });
    }

    fn emit(&self, event: Event) {
        let _ = self
            .events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(event);
    }
}

/// The first of these addresses that answers in time.
fn connect_within(addresses: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
    for address in addresses {
        match TcpStream::connect_timeout(address, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
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
        let real = "re_AbCd-1234.efghIJKLmnopQRstUVwx";
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
    fn a_stand_in_is_random_enough_or_not_made() {
        // Sixteen digits are 53 bits: not a password.
        assert!(mint_stand_in(&"7".repeat(16), &[]).is_err());
        // Nineteen digits are just under 64 bits, twenty just over; thirteen letters under, fourteen over.
        assert!(mint_stand_in(&"7".repeat(19), &[]).is_err());
        assert!(mint_stand_in(&"7".repeat(20), &[]).is_ok());
        assert!(mint_stand_in(&"k".repeat(13), &[]).is_err());
        assert!(mint_stand_in(&"k".repeat(14), &[]).is_ok());
        // Sixteen capitals and digits, like some market-data keys, are enough.
        assert!(mint_stand_in("A1B2C3D4E5F6G7H8", &[]).is_ok());
        // The prefix counts for nothing.
        assert!(
            mint_stand_in(&format!("sk_live_{}", "k".repeat(13)), &["sk_live_".into()]).is_err()
        );
    }

    #[test]
    fn each_digit_and_letter_is_as_likely_as_the_others() {
        let mut digits = [0u32; 10];
        let mut letters = [0u32; 26];
        for _ in 0..400 {
            let fake =
                mint_stand_in(&format!("{}{}", "7".repeat(40), "k".repeat(40)), &[]).unwrap();
            for c in fake.chars() {
                match c {
                    '0'..='9' => digits[(c as u8 - b'0') as usize] += 1,
                    _ => letters[(c as u8 - b'a') as usize] += 1,
                }
            }
        }
        // 16,000 draws each: every value lands near its share, which a fold of 256 onto 26 skews by about 1.5%.
        for count in digits {
            assert!((1450..=1750).contains(&count), "{digits:?}");
        }
        for count in letters {
            assert!((520..=720).contains(&count), "{letters:?}");
        }
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

#[cfg(test)]
mod tunnel_tests {
    use super::is_public;
    use std::net::IpAddr;

    #[test]
    fn a_tunnel_reaches_the_internet_and_nothing_closer() {
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.10",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(!is_public(&blocked.parse::<IpAddr>().unwrap()), "{blocked}");
        }
        for open in ["1.1.1.1", "140.82.112.3", "2606:4700:4700::1111"] {
            assert!(is_public(&open.parse::<IpAddr>().unwrap()), "{open}");
        }
    }
}
