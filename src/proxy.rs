//! Lets a command use a key it never holds. The command gets a stand-in with the key's shape, and calls
//! the real address through this proxy. Only on the way to a host that key belongs to does the proxy
//! end TLS and put the real value in the request's headers. Sent anywhere else, the stand-in is useless.
//!
//! The real value arrives from the vault's service over stdin, and stays in memory. Every other host
//! gets a plain tunnel, with TLS end to end. This does not confine a program: it keeps the key out of
//! the program's hands, and what the program can do with its other permissions is its own matter.

use crate::providers;
use crate::recipe::Recipe;
use crate::secret::Secret;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const IO_TIMEOUT: Duration = Duration::from_secs(60);
const TUNNEL_IDLE: Duration = Duration::from_secs(300);
const MAX_LINE: usize = 16 * 1024;
const MAX_HEADERS: usize = 128;
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
    if real.chars().count() < 8 {
        return Err("this key is too short to stand in for".into());
    }
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
    if out == real {
        return Err("this key has too little in it to stand in for".into());
    }
    Ok(out)
}

/// Compares every byte of two digests, so timing says nothing about how close a guess came.
fn same_token(known: &str, given: &str) -> bool {
    Sha256::digest(known.as_bytes())
        .iter()
        .zip(Sha256::digest(given.as_bytes()).iter())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let joined = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[(joined >> 18) as usize & 63] as char);
        out.push(TABLE[(joined >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(joined >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[joined as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes = text.trim().as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|byte| **byte == b'=').count();
        let mut joined = 0u32;
        for byte in &chunk[..4 - pad] {
            joined = (joined << 6) | value(*byte)?;
        }
        joined <<= 6 * pad as u32;
        out.push((joined >> 16) as u8);
        if pad < 2 {
            out.push((joined >> 8) as u8);
        }
        if pad < 1 {
            out.push(joined as u8);
        }
    }
    Some(out)
}

/// The CA of this process, whose key never leaves its memory, and the certificates it has made.
struct Authority {
    pem: String,
    der: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn validity(params: &mut rcgen::CertificateParams, days: u32) {
    let day = Duration::from_secs(86_400);
    let time = SystemTime::now();
    params.not_before = (time - day).into();
    params.not_after = (time + day * days).into();
}

impl Authority {
    fn new() -> io::Result<Self> {
        let e = |x: rcgen::Error| io::Error::other(format!("the CA could not be made: {x}"));
        let key = rcgen::KeyPair::generate().map_err(e)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(e)?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "keyreeve proxy");
        validity(&mut params, 30);
        let cert = params.self_signed(&key).map_err(e)?;
        Ok(Self {
            pem: cert.pem(),
            der: cert.der().clone(),
            issuer: rcgen::Issuer::new(params, key),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    fn for_host(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        let mut leaves = self.leaves.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(found) = leaves.get(host) {
            return Ok(found.clone());
        }
        let e = |x: rcgen::Error| io::Error::other(format!("no certificate for {host}: {x}"));
        let key = rcgen::KeyPair::generate().map_err(e)?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_owned()]).map_err(e)?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        validity(&mut params, 7);
        let cert = params.signed_by(&key, &self.issuer).map_err(e)?;
        let chain = vec![cert.der().clone(), self.der.clone()];
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(crypto())
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(chain, private)
            .map_err(io::Error::other)?;
        // One framing to read. A client that offers HTTP/2 falls back.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        leaves.insert(host.to_owned(), config.clone());
        Ok(config)
    }
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

    /// Returns the token that lets a command use this permission through the proxy.
    pub fn add(&self, grant: Grant) -> io::Result<String> {
        let token: String = random_bytes(32)?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        self.grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token.clone(), Arc::new(grant));
        Ok(token)
    }

    pub fn remove(&self, id: &str) {
        self.grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, grant| grant.id != id);
    }

    fn grant_for(&self, token: &str) -> Option<Arc<Grant>> {
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        grants.retain(|_, grant| grant.expires > now());
        // Comparing each one whole, so timing says nothing about how close a guess came.
        let mut found = None;
        for (known, grant) in grants.iter() {
            if same_token(known, token) {
                found = Some(grant.clone());
            }
        }
        found
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
        let (first, headers) = read_head(&mut reader)?;
        let mut writer = client;
        let mut parts = first.split(' ');
        let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        if method != "CONNECT" {
            return answer(&mut writer, 405, "only CONNECT goes through here");
        }
        let Some(grant) = header(&headers, "proxy-authorization")
            .and_then(token_from)
            .and_then(|token| self.grant_for(&token))
        else {
            return writer.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"keyreeve\"\r\nConnection: close\r\n\r\n",
            );
        };
        let Some((host, port)) = split_target(target) else {
            return answer(&mut writer, 400, "that is not host:port");
        };
        if port == 443
            && grant
                .hosts
                .iter()
                .any(|known| known.eq_ignore_ascii_case(&host))
        {
            writer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
            return self.terminated(&grant, &host, writer, reader);
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
        grant: &Grant,
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
            if grant.in_url {
                target.replace(grant.stand_in.expose(), grant.real.expose())
            } else {
                target.clone()
            }
        );
        for (name, value) in &headers {
            let value = if name.eq_ignore_ascii_case("host") {
                value.clone()
            } else {
                swap_header(value, grant)
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
        let sent = (|| -> io::Result<()> {
            upstream.write_all(out.as_bytes())?;
            copy_body(&framing, &mut stream, &mut upstream)?;
            upstream.flush()
        })();
        if sent.is_err() {
            return answer(stream.get_mut(), 502, "the request could not be sent");
        }
        let mut scrub = Scrubber::new(grant.real.expose(), grant.stand_in.expose());
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
                break;
            }
            if status == 0 {
                status = status_of(&buffer[..count]);
            }
            let clean = scrub.push(&buffer[..count]);
            stream.get_mut().write_all(&clean)?;
        }
        stream.get_mut().write_all(&scrub.finish())?;
        stream.get_mut().flush()?;
        stream.get_mut().conn.send_close_notify();
        let _ = stream.get_mut().flush();
        let path = target
            .split('?')
            .next()
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
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

/// Replaces a value in a stream, holding back enough bytes that one split across reads is still found.
struct Scrubber {
    needle: Vec<u8>,
    with: Vec<u8>,
    held: Vec<u8>,
}

impl Scrubber {
    fn new(real: &str, stand_in: &str) -> Self {
        Self {
            needle: real.as_bytes().to_vec(),
            with: stand_in.as_bytes().to_vec(),
            held: Vec::new(),
        }
    }

    fn push(&mut self, data: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(data);
        let mut out = Vec::with_capacity(self.held.len());
        let mut at = 0;
        while let Some(found) = self.held[at..]
            .windows(self.needle.len())
            .position(|window| window == self.needle)
        {
            out.extend_from_slice(&self.held[at..at + found]);
            out.extend_from_slice(&self.with);
            at += found + self.needle.len();
        }
        let keep = self.needle.len().saturating_sub(1);
        let flush_to = self.held.len().saturating_sub(keep).max(at);
        out.extend_from_slice(&self.held[at..flush_to]);
        self.held.drain(..flush_to);
        out
    }

    fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

fn status_of(head: &[u8]) -> u16 {
    std::str::from_utf8(&head[..head.len().min(16)])
        .ok()
        .and_then(|text| text.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn answer(to: &mut impl Write, status: u16, text: &str) -> io::Result<()> {
    write!(
        to,
        "HTTP/1.1 {status} keyreeve\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    )?;
    to.flush()
}

fn split_target(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| (host.to_ascii_lowercase(), port))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn token_from(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(rest.trim().to_owned());
    }
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(base64_decode(rest)?).ok()?;
    decoded.split_once(':').map(|(_, token)| token.to_owned())
}

fn read_line_capped(reader: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(if line.is_empty() {
                None
            } else {
                Some(String::from_utf8(line).map_err(io::Error::other)?)
            });
        }
        let (take, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(at) => (at + 1, true),
            None => (available.len(), false),
        };
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.len() > MAX_LINE {
            return Err(io::Error::other("a line is too long"));
        }
        if done {
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            return Ok(Some(String::from_utf8(line).map_err(io::Error::other)?));
        }
    }
}

fn read_head(reader: &mut impl BufRead) -> io::Result<(String, Vec<(String, String)>)> {
    let first = read_line_capped(reader)?.ok_or_else(|| io::Error::other("no request"))?;
    let mut headers = Vec::new();
    loop {
        let line = read_line_capped(reader)?.ok_or_else(|| io::Error::other("the head was cut"))?;
        if line.is_empty() {
            return Ok((first, headers));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(io::Error::other("too many headers"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::other("a header has no name"))?;
        // A folded or spaced name is how one request gets read as two.
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(io::Error::other("a header has a bad name"));
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
}

enum Framing {
    None,
    Length(u64),
    Chunked,
}

/// Two ways to say where a body ends, or two different lengths, is how a request gets smuggled.
fn body_framing(headers: &[(String, String)]) -> Result<Framing, ()> {
    let lengths: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str())
        .collect();
    match (header(headers, "transfer-encoding"), lengths.as_slice()) {
        (None, []) => Ok(Framing::None),
        (None, [one]) => one.parse().map(Framing::Length).map_err(|_| ()),
        (Some(value), []) if value.eq_ignore_ascii_case("chunked") => Ok(Framing::Chunked),
        _ => Err(()),
    }
}

fn copy_body(framing: &Framing, from: &mut impl BufRead, to: &mut impl Write) -> io::Result<()> {
    match framing {
        Framing::None => Ok(()),
        Framing::Length(count) => {
            let copied = io::copy(&mut from.by_ref().take(*count), to)?;
            if copied == *count {
                Ok(())
            } else {
                Err(io::Error::other("the body was cut"))
            }
        }
        Framing::Chunked => loop {
            let line =
                read_line_capped(from)?.ok_or_else(|| io::Error::other("the body was cut"))?;
            write!(to, "{line}\r\n")?;
            let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| io::Error::other("a bad chunk"))?;
            if size == 0 {
                loop {
                    let trailer = read_line_capped(from)?
                        .ok_or_else(|| io::Error::other("the body was cut"))?;
                    write!(to, "{trailer}\r\n")?;
                    if trailer.is_empty() {
                        return Ok(());
                    }
                }
            }
            let copied = io::copy(&mut from.by_ref().take(size), to)?;
            if copied != size {
                return Err(io::Error::other("the body was cut"));
            }
            let end =
                read_line_capped(from)?.ok_or_else(|| io::Error::other("the body was cut"))?;
            if !end.is_empty() {
                return Err(io::Error::other("a bad chunk"));
            }
            to.write_all(b"\r\n")?;
        },
    }
}

/// What this file can stand in for: one plain request with the key in a header, a password or the
/// address. A token exchange or a signature needs more than swapping one value.
pub fn can_stand_in(recipe: &Recipe) -> bool {
    !recipe.hosts.is_empty()
        && !recipe.self_hosted
        && recipe.auth.run.is_none()
        && !matches!(
            recipe.auth.kind.as_deref(),
            Some("oauth_token") | Some("ssh") | Some("command") | Some("aws_sigv4")
        )
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Control {
    Add {
        grant: String,
        key: String,
        provider: String,
        value: String,
        expires: u64,
    },
    Remove {
        grant: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Reply {
    Ready {
        port: u16,
        ca: String,
        bundle: String,
    },
    Added {
        grant: String,
        stand_in: String,
        token: String,
    },
    Failed {
        grant: String,
        error: String,
    },
    Event(Event),
}

/// The running proxy, driven by the vault's service: requests come on stdin and answers go to stdout.
/// It stops when stdin closes, so it cannot outlive the service that gave it the keys.
pub fn serve_from_stdin(folder: &Path) -> Result<(), String> {
    let (proxy, events) = Proxy::new(Options::default()).map_err(|e| e.to_string())?;
    let trust = proxy.write_trust(folder).map_err(|e| e.to_string())?;
    let port = proxy.listen().map_err(|e| e.to_string())?;
    let out = Arc::new(Mutex::new(io::stdout()));
    let say = {
        let out = out.clone();
        move |reply: &Reply| {
            let mut out = out.lock().unwrap_or_else(|e| e.into_inner());
            let line = serde_json::to_string(reply).unwrap_or_default();
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
    };
    say(&Reply::Ready {
        port,
        ca: trust.ca.display().to_string(),
        bundle: trust.bundle.display().to_string(),
    });
    {
        let say = say.clone();
        thread::spawn(move || {
            for event in events {
                say(&Reply::Event(event));
            }
        });
    }
    for line in io::stdin().lock().lines() {
        let line = zeroize::Zeroizing::new(line.map_err(|e| e.to_string())?);
        // A parse error never quotes the line, which holds a key.
        let Ok(message) = serde_json::from_str::<Control>(&line) else {
            say(&Reply::Failed {
                grant: String::new(),
                error: "a message could not be read".into(),
            });
            continue;
        };
        match message {
            Control::Remove { grant } => proxy.remove(&grant),
            Control::Add {
                grant,
                key,
                provider,
                value,
                expires,
            } => {
                let value = zeroize::Zeroizing::new(value);
                match prepare_grant(&grant, &key, &provider, &value, expires).and_then(|ready| {
                    let stand_in = ready.stand_in.expose().to_owned();
                    let token = proxy.add(ready).map_err(|e| e.to_string())?;
                    Ok((stand_in, token))
                }) {
                    Ok((stand_in, token)) => say(&Reply::Added {
                        grant,
                        stand_in,
                        token,
                    }),
                    Err(error) => say(&Reply::Failed { grant, error }),
                }
            }
        }
    }
    Ok(())
}

fn prepare_grant(
    id: &str,
    key: &str,
    provider: &str,
    value: &str,
    expires: u64,
) -> Result<Grant, String> {
    let recipe = providers::load(provider)?;
    if !can_stand_in(&recipe) {
        return Err(format!(
            "{provider} cannot use a stand-in, so this key needs --real"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err("this key has characters that cannot go in a header".into());
    }
    Ok(Grant {
        id: id.to_owned(),
        key: key.to_owned(),
        stand_in: Secret::new(mint_stand_in(value, &recipe.prefixes)?),
        real: Secret::new(value),
        hosts: recipe.hosts.clone(),
        in_url: recipe.auth.kind.as_deref() == Some("url"),
        expires,
    })
}

#[cfg(test)]
mod tests {
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
        let real = "re_AbCd-1234.efgh";
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

    #[test]
    fn a_token_comes_from_either_scheme() {
        assert_eq!(token_from("Bearer abc").as_deref(), Some("abc"));
        let basic = format!("Basic {}", base64_encode(b"keyreeve:abc"));
        assert_eq!(token_from(&basic).as_deref(), Some("abc"));
        assert_eq!(token_from("Digest abc"), None);
    }
}
