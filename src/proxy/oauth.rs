//! OAuth as authorization. keyreeve holds the refresh token and the client secret, and the proxy gets
//! access tokens itself, from the recipe's token host. A command gets a credentials file of the same
//! shape with stand-ins for the secret parts, so an unmodified client library asks the token host
//! through the proxy, which answers it here with a stand-in access token and never forwards the
//! request. Later requests that carry that stand-in get the real access token, only on the way to the
//! recipe's hosts. The refresh token and the client secret never leave keyreeve except to the token
//! host, in the exchange the proxy makes itself.

use super::http::{answer, base64_decode, header, read_line_capped, Framing};
use super::{connect_within, mint_stand_in, now, Event, Grant, Proxy, IO_TIMEOUT};
use crate::recipe::Recipe;
use crate::secret::Secret;
use crate::transport::{self, Request, Response, Transport, TransportError};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The most a token request's body may hold. A real one is a few hundred bytes.
const MAX_TOKEN_BODY: u64 = 64 * 1024;
/// The most a token host's answer may hold.
const MAX_ANSWER: u64 = 1024 * 1024;
/// After an exchange that failed without a refusal, such as a network error, no other is tried for this
/// long, so a library that retries in a loop does not reach the provider in one.
const REST_AFTER_FAILURE: u64 = 15;
/// The longest a stand-in access token says it lasts. The proxy renews the real one behind it.
const MAX_STAND_IN_LIFE: u64 = 3599;
/// Kept from a credentials file for the stand-in copy: none of these is a secret.
const KEPT_FIELDS: &[&str] = &["quota_project_id", "universe_domain", "account", "scopes"];

/// One permission to use an OAuth credential.
pub struct OAuthGrant {
    pub id: String,
    pub key: String,
    pub hosts: Vec<String>,
    pub expires: u64,
    recipe: Recipe,
    token_host: String,
    token_path: String,
    /// Not a secret: Google shows it in every sign-in address. It stays real so a library can show it and
    /// so a token request names which credential it is for.
    client_id: String,
    credential: Secret,
    fake_secret: Secret,
    fake_refresh: Option<Secret>,
    fake_access: Secret,
    /// The credentials file with stand-ins that the command gets. It goes when the permission does.
    file: Option<PathBuf>,
    text: Secret,
}

impl Drop for OAuthGrant {
    fn drop(&mut self) {
        if let Some(file) = &self.file {
            let _ = std::fs::remove_file(file);
        }
    }
}

impl OAuthGrant {
    /// Reads the credential from a sealed file's text, as a check would, and makes its stand-ins. With a
    /// folder, writes there the credentials file the command gets.
    pub fn new(
        id: &str,
        key: &str,
        recipe: &Recipe,
        text: &str,
        field: Option<&str>,
        expires: u64,
        folder: Option<&Path>,
    ) -> Result<Self, String> {
        if recipe.auth.kind.as_deref() != Some("oauth_token") {
            return Err("this provider does not use OAuth".into());
        }
        let (Some(token_host), Some(token_path)) = (
            recipe.auth.token_host.clone(),
            recipe.auth.token_path.clone(),
        ) else {
            return Err("this provider's file names no token host".into());
        };
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("a permission's id is letters, digits and dashes".into());
        }
        let credential = crate::keys::read_key_for(text, field, recipe)?;
        if let Some(why) = transport::missing_parts(recipe, &credential) {
            return Err(why);
        }
        if credential.expose().chars().any(char::is_control) {
            return Err("this key has characters that cannot go in a request".into());
        }
        let parts: Vec<&str> = credential.expose().splitn(3, ':').collect();
        let client_id = parts[0].to_owned();
        let fake_secret = Secret::new(mint_stand_in(parts[1], &recipe.prefixes)?);
        let fake_refresh = match parts.get(2) {
            Some(refresh) if recipe.auth.grant.as_deref() == Some("refresh_token") => {
                Some(Secret::new(mint_stand_in(refresh, &[])?))
            }
            _ => None,
        };
        // Its own randomness: nothing about the real access token is known yet, and it changes on renewal.
        let fake_access = Secret::new(mint_stand_in(&"aA0".repeat(22), &[])?);
        let mut grant = Self {
            id: id.to_owned(),
            key: key.to_owned(),
            hosts: recipe.hosts.clone(),
            expires,
            recipe: recipe.clone(),
            token_host,
            token_path,
            client_id,
            credential,
            fake_secret,
            fake_refresh,
            fake_access,
            file: None,
            text: Secret::new(text),
        };
        if let Some(folder) = folder {
            let path = folder.join(format!("oauth-{id}.json"));
            write_private(&path, &grant.stand_in_json(text))?;
            grant.file = Some(path);
        }
        Ok(grant)
    }

    /// What the command gets in its variable: the path of the credentials file, or with no folder the
    /// file's text.
    pub fn stand_in(&self) -> String {
        match &self.file {
            Some(path) => path.display().to_string(),
            None => self.stand_in_json(self.text.expose()),
        }
    }

    pub fn token_uri(&self) -> String {
        format!("https://{}{}", self.token_host, self.token_path)
    }

    /// The same shape as the credential, with stand-ins for every secret part. The token address is the
    /// recipe's, so a library asks the host the proxy answers for.
    fn stand_in_json(&self, text: &str) -> String {
        let mut out = serde_json::Map::new();
        if let Ok(serde_json::Value::Object(original)) =
            serde_json::from_str::<serde_json::Value>(text.trim())
        {
            for name in KEPT_FIELDS {
                if let Some(value) = original.get(*name) {
                    if value.is_string() || value.is_array() {
                        out.insert((*name).to_owned(), value.clone());
                    }
                }
            }
        }
        if self.fake_refresh.is_some() {
            out.insert("type".into(), "authorized_user".into());
        }
        out.insert("client_id".into(), self.client_id.clone().into());
        out.insert(
            "client_secret".into(),
            self.fake_secret.expose().to_owned().into(),
        );
        if let Some(refresh) = &self.fake_refresh {
            out.insert("refresh_token".into(), refresh.expose().to_owned().into());
        }
        out.insert("token_uri".into(), self.token_uri().into());
        serde_json::to_string_pretty(&serde_json::Value::Object(out)).unwrap_or_default()
    }

    /// Every stand-in this permission handed out.
    fn stand_ins(&self) -> impl Iterator<Item = &str> {
        [
            Some(&self.fake_secret),
            self.fake_refresh.as_ref(),
            Some(&self.fake_access),
        ]
        .into_iter()
        .flatten()
        .map(Secret::expose)
    }

    /// A token request that carries exactly this permission's stand-ins.
    fn matches(&self, asked: &TokenAsk) -> bool {
        let wanted = self.recipe.auth.grant.as_deref().unwrap_or_default();
        let id_ok = asked
            .client_id
            .as_deref()
            .is_none_or(|id| same(id, &self.client_id));
        let secret_ok = asked
            .client_secret
            .as_deref()
            .is_some_and(|secret| same(secret, self.fake_secret.expose()));
        let refresh_ok = match &self.fake_refresh {
            Some(fake) => asked
                .refresh_token
                .as_deref()
                .is_some_and(|refresh| same(refresh, fake.expose())),
            None => asked.refresh_token.is_none(),
        };
        asked.grant_type.as_deref() == Some(wanted) && id_ok && secret_ok && refresh_ok
    }

    /// One credential, whichever permission holds it: what a real access token is cached under.
    fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.credential.expose().as_bytes()).into()
    }
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    let failed = |_| "the credentials file with stand-ins could not be written".to_owned();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(failed)?;
        file.write_all(text.as_bytes()).map_err(failed)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text).map_err(failed)
    }
}

/// Compares in the same time whatever the values, so the time an answer takes says nothing about a stand-in.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// A permission in force, with the access token of its credential.
pub(super) struct Held {
    pub(super) grant: OAuthGrant,
    tokens: Arc<Tokens>,
}

/// What became of an exchange with the token host.
pub(super) enum Exchanged {
    Token {
        access: Secret,
        expires_in: u64,
        /// A provider that rotates refresh tokens sends a new one. It is used from then on, in memory.
        refresh: Option<Secret>,
    },
    /// The provider no longer accepts the credential: a person has to authorize it again.
    Refused,
    /// No answer, or one that says nothing about the credential.
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum NoToken {
    Reauthorize,
    Unavailable,
}

/// The real access token of one credential. Held locked during an exchange, so uses that find it
/// expired at the same time wait for one exchange, and do not each make their own.
pub(super) struct Tokens {
    state: Mutex<TokenState>,
}

struct TokenState {
    credential: Secret,
    access: Option<Secret>,
    until: u64,
    resting_until: u64,
    refused: bool,
}

impl Tokens {
    pub(super) fn new(credential: Secret, refused: bool) -> Self {
        Self {
            state: Mutex::new(TokenState {
                credential,
                access: None,
                until: 0,
                resting_until: 0,
                refused,
            }),
        }
    }

    pub(super) fn access(
        &self,
        now: u64,
        exchange: impl FnOnce(&Secret) -> Exchanged,
    ) -> Result<Secret, NoToken> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.refused {
            return Err(NoToken::Reauthorize);
        }
        if let Some(access) = &state.access {
            if state.until > now {
                return Ok(access.clone());
            }
        }
        if state.resting_until > now {
            return Err(NoToken::Unavailable);
        }
        match exchange(&state.credential) {
            Exchanged::Token {
                access,
                expires_in,
                refresh,
            } => {
                // Renewed a little before the provider says it ends, so a request does not carry a token that
                // dies on the way.
                let margin = (expires_in / 2).min(60);
                state.until = now + expires_in - margin;
                if let Some(refresh) = refresh {
                    let parts: Vec<&str> = state.credential.expose().splitn(3, ':').collect();
                    if parts.len() == 3 {
                        state.credential =
                            Secret::new(format!("{}:{}:{}", parts[0], parts[1], refresh.expose()));
                    }
                }
                state.access = Some(access.clone());
                Ok(access)
            }
            Exchanged::Refused => {
                state.refused = true;
                state.access = None;
                Err(NoToken::Reauthorize)
            }
            Exchanged::Failed => {
                state.resting_until = now + REST_AFTER_FAILURE;
                Err(NoToken::Unavailable)
            }
        }
    }
}

/// Reads a token host's answer. Only the parts that matter are kept, and nothing of it reaches an error.
pub(super) fn read_exchange(response: &Response) -> Exchanged {
    let json = serde_json::from_str::<serde_json::Value>(response.body.expose()).ok();
    let text = |name: &str| {
        json.as_ref()
            .and_then(|json| json.get(name))
            .and_then(|value| value.as_str())
            .map(str::to_owned)
    };
    if (200..300).contains(&response.status) {
        let Some(access) = text("access_token").filter(|a| !a.is_empty()) else {
            return Exchanged::Failed;
        };
        if access.chars().any(char::is_control) {
            return Exchanged::Failed;
        }
        let expires_in = json
            .as_ref()
            .and_then(|json| json.get("expires_in"))
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(3600)
            .clamp(1, 86_400);
        return Exchanged::Token {
            access: Secret::new(access),
            expires_in,
            refresh: text("refresh_token")
                .filter(|r| !r.is_empty() && !r.chars().any(char::is_control))
                .map(Secret::new),
        };
    }
    let refused = matches!(response.status, 400 | 401)
        && text("error").is_some_and(|error| {
            matches!(
                error.as_str(),
                "invalid_grant" | "invalid_client" | "unauthorized_client"
            )
        });
    if refused {
        Exchanged::Refused
    } else {
        Exchanged::Failed
    }
}

/// What a token request asked for, from its body and its Basic header.
#[derive(Default)]
struct TokenAsk {
    grant_type: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    refresh_token: Option<String>,
}

impl TokenAsk {
    fn read(body: &[u8], headers: &[(String, String)]) -> Self {
        let mut ask = Self::default();
        let text = String::from_utf8_lossy(body);
        let json = header(headers, "content-type")
            .is_some_and(|kind| kind.to_ascii_lowercase().contains("json"));
        let mut put = |name: &str, value: String| {
            let slot = match name {
                "grant_type" => &mut ask.grant_type,
                "client_id" => &mut ask.client_id,
                "client_secret" => &mut ask.client_secret,
                "refresh_token" => &mut ask.refresh_token,
                _ => return,
            };
            *slot = Some(value);
        };
        if json {
            if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(&text) {
                for (name, value) in map {
                    if let Some(value) = value.as_str() {
                        put(&name, value.to_owned());
                    }
                }
            }
        } else {
            for pair in text.split('&') {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                if let (Some(name), Some(value)) = (form_decode(name), form_decode(value)) {
                    put(&name, value);
                }
            }
        }
        // RFC 6749 lets a client send its id and secret as Basic, each form-encoded first.
        if let Some(encoded) = header(headers, "authorization").and_then(|value| {
            value
                .strip_prefix("Basic ")
                .or_else(|| value.strip_prefix("basic "))
        }) {
            if let Some((id, secret)) = base64_decode(encoded)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .and_then(|joined| {
                    let (id, secret) = joined.split_once(':')?;
                    Some((form_decode(id)?, form_decode(secret)?))
                })
            {
                ask.client_id.get_or_insert(id);
                ask.client_secret.get_or_insert(secret);
            }
        }
        ask
    }
}

fn form_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                at += 2;
            }
            other => out.push(other),
        }
        at += 1;
    }
    String::from_utf8(out).ok()
}

/// Reads a request's body whole, up to a limit, undoing chunks.
fn read_body(framing: &Framing, from: &mut impl BufRead, limit: u64) -> io::Result<Vec<u8>> {
    let too_large = || io::Error::other("the body is too large");
    match framing {
        Framing::None => Ok(Vec::new()),
        Framing::Length(count) => {
            if *count > limit {
                return Err(too_large());
            }
            let mut body = vec![0u8; *count as usize];
            from.read_exact(&mut body)?;
            Ok(body)
        }
        Framing::Chunked => {
            let mut body = Vec::new();
            loop {
                let line = read_line_capped(from)?.ok_or_else(|| io::Error::other("cut"))?;
                let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                    .map_err(|_| io::Error::other("a bad chunk"))?;
                if size == 0 {
                    while read_line_capped(from)?.is_some_and(|line| !line.is_empty()) {}
                    return Ok(body);
                }
                if body.len() as u64 + size > limit {
                    return Err(too_large());
                }
                let start = body.len();
                body.resize(start + size as usize, 0);
                from.read_exact(&mut body[start..])?;
                read_line_capped(from)?;
            }
        }
    }
}

fn answer_json(to: &mut impl Write, status: u16, json: &serde_json::Value) -> io::Result<()> {
    let body = json.to_string();
    write!(
        to,
        "HTTP/1.1 {status} keyreeve\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    to.flush()
}

fn refused_json(key: &str, why: NoToken) -> (u16, serde_json::Value) {
    match why {
        NoToken::Reauthorize => (
            400,
            serde_json::json!({
                "error": "invalid_grant",
                "error_description": format!("keyreeve: the provider no longer accepts {key}, so it needs authorizing again. Nothing more is sent until it is replaced in the vault"),
            }),
        ),
        NoToken::Unavailable => (
            503,
            serde_json::json!({
                "error": "temporarily_unavailable",
                "error_description": "keyreeve: the token host did not give a token. Try again in a little while",
            }),
        ),
    }
}

/// What to do with a request to a host an OAuth permission covers.
pub(super) enum Route {
    /// Answered here, and nothing was forwarded.
    Answered,
    /// Goes out with the real access token in place of this stand-in.
    Use(Arc<Grant>),
    /// No OAuth stand-in in it: it goes on as any other request.
    Pass,
}

/// Sends the token exchange through the proxy's own client, so it trusts what the proxy trusts and goes
/// where the proxy sends that host.
struct Upstream<'a> {
    proxy: &'a Proxy,
    host: &'a str,
}

impl Transport for Upstream<'_> {
    fn send(&mut self, request: &Request) -> Result<Response, TransportError> {
        let rendered = &request.rendered;
        if rendered.host != self.host {
            return Err(TransportError::HostNotAllowed(rendered.host.clone()));
        }
        let failed = |_| TransportError::Failed;
        let mut stream = self.proxy.open_upstream(self.host).map_err(failed)?;
        let body = rendered.body.clone().unwrap_or_default();
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {}\r\n",
            rendered.method,
            rendered.path,
            self.host,
            body.len()
        );
        for (name, value) in &request.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        (|| -> io::Result<()> {
            stream.write_all(head.as_bytes())?;
            stream.write_all(&body)?;
            stream.flush()
        })()
        .map_err(failed)?;
        let mut reader = BufReader::new(EndIsEnd(stream));
        let status_line = read_line_capped(&mut reader)
            .map_err(failed)?
            .ok_or(TransportError::Failed)?;
        let status = super::http::status_of(status_line.as_bytes());
        let mut headers = Vec::new();
        loop {
            let line = read_line_capped(&mut reader)
                .map_err(failed)?
                .ok_or(TransportError::Failed)?;
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
            }
            if headers.len() > 128 {
                return Err(TransportError::Failed);
            }
        }
        let framing = if header(&headers, "transfer-encoding")
            .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
        {
            Framing::Chunked
        } else if let Some(length) = header(&headers, "content-length") {
            Framing::Length(length.parse().map_err(|_| TransportError::Failed)?)
        } else {
            let mut body = Vec::new();
            reader
                .take(MAX_ANSWER + 1)
                .read_to_end(&mut body)
                .map_err(failed)?;
            if body.len() as u64 > MAX_ANSWER {
                return Err(TransportError::Failed);
            }
            return Ok(Response {
                status,
                headers,
                body: Secret::new(String::from_utf8_lossy(&body).into_owned()),
            });
        };
        let body = read_body(&framing, &mut reader, MAX_ANSWER).map_err(failed)?;
        Ok(Response {
            status,
            headers,
            body: Secret::new(String::from_utf8_lossy(&body).into_owned()),
        })
    }
}

/// Many servers end without a TLS goodbye, once they have said it all.
struct EndIsEnd<R>(R);

impl<R: Read> Read for EndIsEnd<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        match self.0.read(into) {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            other => other,
        }
    }
}

impl Proxy {
    /// Lets this OAuth permission be used. Its credential's access token is shared with any other
    /// permission for the same credential.
    pub fn add_oauth(&self, grant: OAuthGrant) {
        let fingerprint = grant.fingerprint();
        let refused = self
            .oauth_refused
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&fingerprint);
        let tokens = {
            let mut all = self.oauth_tokens.lock().unwrap_or_else(|e| e.into_inner());
            all.retain(|_, tokens| tokens.strong_count() > 0);
            match all.get(&fingerprint).and_then(std::sync::Weak::upgrade) {
                Some(tokens) => tokens,
                None => {
                    let tokens = Arc::new(Tokens::new(grant.credential.clone(), refused));
                    all.insert(fingerprint, Arc::downgrade(&tokens));
                    tokens
                }
            }
        };
        self.oauth
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(grant.id.clone(), Arc::new(Held { grant, tokens }));
    }

    /// The OAuth permissions in force for this host. An ended one goes, with its file and, once no
    /// permission holds it, its access token.
    pub(super) fn oauth_for(&self, host: &str) -> Vec<Arc<Held>> {
        let mut all = self.oauth.lock().unwrap_or_else(|e| e.into_inner());
        all.retain(|_, held| held.grant.expires > now());
        all.values()
            .filter(|held| {
                held.grant
                    .hosts
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(host))
            })
            .cloned()
            .collect()
    }

    /// The real access token for this permission, from the cache or from one exchange.
    fn access_for(&self, held: &Held) -> Result<Secret, NoToken> {
        held.tokens
            .access(now(), |credential| self.exchange(held, credential))
    }

    fn exchange(&self, held: &Held, credential: &Secret) -> Exchanged {
        let grant = &held.grant;
        let mut upstream = Upstream {
            proxy: self,
            host: &grant.token_host,
        };
        let (status, outcome, exchanged) =
            match transport::exchange_token(&grant.recipe, credential, &mut upstream) {
                Ok(response) => (response.status, "complete", read_exchange(&response)),
                // The credential may have reached the provider before the answer was lost.
                Err(_) => (0, "no full reply", Exchanged::Failed),
            };
        let authorization = match exchanged {
            Exchanged::Token { .. } => Some("active"),
            Exchanged::Refused => {
                self.oauth_refused
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(grant.fingerprint());
                Some("reauthorize")
            }
            Exchanged::Failed => None,
        };
        self.emit(Event {
            grant: grant.id.clone(),
            key: grant.key.clone(),
            host: grant.token_host.clone(),
            method: "POST".into(),
            path: grant.token_path.clone(),
            status,
            outcome: outcome.into(),
            authorization: authorization.map(str::to_owned),
        });
        exchanged
    }

    /// A connection to a key's host, as the proxy makes for a request it forwards.
    pub(super) fn open_upstream(
        &self,
        host: &str,
    ) -> io::Result<StreamOwned<ClientConnection, std::net::TcpStream>> {
        let port = self.options.upstream_port.unwrap_or(443);
        let name = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
        let connection =
            ClientConnection::new(self.upstream.clone(), name).map_err(io::Error::other)?;
        let addresses: Vec<SocketAddr> = match self.options.upstream_address {
            Some(address) => vec![SocketAddr::new(address, port)],
            None => (host, port)
                .to_socket_addrs()
                .map(Iterator::collect)
                .unwrap_or_default(),
        };
        let socket = connect_within(&addresses)?;
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(StreamOwned::new(connection, socket))
    }

    /// Decides a request to a host an OAuth permission covers: a token request is answered here and never
    /// forwarded, and a request with a stand-in access token goes out with the real one.
    pub(super) fn oauth_route<S: Read + Write>(
        &self,
        host: &str,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        framing: &Framing,
        stream: &mut BufReader<S>,
    ) -> io::Result<Route> {
        let held = self.oauth_for(host);
        if held.is_empty() {
            return Ok(Route::Pass);
        }
        if held
            .iter()
            .any(|held| held.grant.stand_ins().any(|fake| target.contains(fake)))
        {
            answer(
                stream.get_mut(),
                400,
                "keyreeve: this credential goes in a header or in a token request's body, not in the URL",
            )?;
            return Ok(Route::Answered);
        }
        let path = target.split('?').next().unwrap_or("");
        let at_token: Vec<&Arc<Held>> = held
            .iter()
            .filter(|held| {
                held.grant.token_host.eq_ignore_ascii_case(host) && held.grant.token_path == path
            })
            .collect();
        if !at_token.is_empty() {
            self.token_request(&at_token, method, headers, framing, stream)?;
            return Ok(Route::Answered);
        }
        for held in &held {
            let fake = held.grant.fake_access.expose();
            let carried = headers
                .iter()
                .any(|(name, value)| !name.eq_ignore_ascii_case("host") && value.contains(fake));
            if !carried {
                continue;
            }
            return Ok(match self.access_for(held) {
                Ok(real) => Route::Use(Arc::new(Grant {
                    id: held.grant.id.clone(),
                    key: held.grant.key.clone(),
                    stand_in: held.grant.fake_access.clone(),
                    real,
                    hosts: held.grant.hosts.clone(),
                    in_url: false,
                    expires: held.grant.expires,
                })),
                Err(why) => {
                    let (status, json) = refused_json(&held.grant.key, why);
                    // An API answers a dead token with 401, which is what a library expects here.
                    let status = if status == 400 { 401 } else { status };
                    answer_json(stream.get_mut(), status, &json)?;
                    Route::Answered
                }
            });
        }
        Ok(Route::Pass)
    }

    /// A token request never leaves. With this permission's stand-ins it gets a stand-in access token,
    /// once the real one is in hand; with anything else it is refused.
    fn token_request<S: Read + Write>(
        &self,
        held: &[&Arc<Held>],
        method: &str,
        headers: &[(String, String)],
        framing: &Framing,
        stream: &mut BufReader<S>,
    ) -> io::Result<()> {
        let refuse = |stream: &mut BufReader<S>| {
            answer_json(
                stream.get_mut(),
                401,
                &serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "keyreeve: these are not the stand-ins of a permission in force here, so nothing was sent",
                }),
            )
        };
        if method != "POST" {
            return refuse(stream);
        }
        let Ok(body) = read_body(framing, stream, MAX_TOKEN_BODY) else {
            return refuse(stream);
        };
        let asked = TokenAsk::read(&body, headers);
        let Some(held) = held.iter().find(|held| held.grant.matches(&asked)) else {
            return refuse(stream);
        };
        match self.access_for(held) {
            Ok(_) => {
                let left = held.grant.expires.saturating_sub(now());
                answer_json(
                    stream.get_mut(),
                    200,
                    &serde_json::json!({
                        "access_token": held.grant.fake_access.expose(),
                        "token_type": "Bearer",
                        "expires_in": left.clamp(1, MAX_STAND_IN_LIFE),
                    }),
                )
            }
            Err(why) => {
                let (status, json) = refused_json(&held.grant.key, why);
                answer_json(stream.get_mut(), status, &json)
            }
        }
    }

    /// Whether a permission is still in force, plain or OAuth.
    pub(super) fn is_live(&self, host: &str, id: &str) -> bool {
        self.grants_for(host).iter().any(|live| live.id == id)
            || self.oauth_for(host).iter().any(|held| held.grant.id == id)
    }
}

/// Credentials whose provider said they are no longer accepted, by fingerprint, for this proxy's life.
pub(super) type Refused = Mutex<HashSet<[u8; 32]>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    fn token(expires_in: u64) -> Exchanged {
        Exchanged::Token {
            access: Secret::new("real-access"),
            expires_in,
            refresh: None,
        }
    }

    #[test]
    fn uses_that_find_it_expired_together_make_one_exchange() {
        let tokens = Arc::new(Tokens::new(Secret::new("id:secret:refresh"), false));
        let exchanges = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (tokens, exchanges, start) = (tokens.clone(), exchanges.clone(), start.clone());
                thread::spawn(move || {
                    start.wait();
                    tokens.access(1_000, |_| {
                        exchanges.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(200));
                        token(3600)
                    })
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap().unwrap().expose(), "real-access");
        }
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_token_is_renewed_before_it_ends_and_not_before() {
        let tokens = Tokens::new(Secret::new("id:secret:refresh"), false);
        let count = AtomicUsize::new(0);
        let get = |at: u64| {
            tokens.access(at, |_| {
                count.fetch_add(1, Ordering::SeqCst);
                token(3600)
            })
        };
        get(0).unwrap();
        get(3000).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        get(3541).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_refusal_is_final_and_a_failure_rests() {
        let tokens = Tokens::new(Secret::new("id:secret:refresh"), false);
        let count = AtomicUsize::new(0);
        let refuse = |at: u64| {
            tokens.access(at, |_| {
                count.fetch_add(1, Ordering::SeqCst);
                Exchanged::Refused
            })
        };
        assert_eq!(refuse(0).err(), Some(NoToken::Reauthorize));
        assert_eq!(refuse(10_000).err(), Some(NoToken::Reauthorize));
        assert_eq!(count.load(Ordering::SeqCst), 1, "no second exchange");

        let flaky = Tokens::new(Secret::new("id:secret:refresh"), false);
        let fail = |at: u64| {
            flaky.access(at, |_| {
                count.fetch_add(1, Ordering::SeqCst);
                Exchanged::Failed
            })
        };
        assert_eq!(fail(100).err(), Some(NoToken::Unavailable));
        assert_eq!(fail(101).err(), Some(NoToken::Unavailable));
        assert_eq!(count.load(Ordering::SeqCst), 2, "resting after a failure");
        fail(100 + REST_AFTER_FAILURE).unwrap_err();
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn a_provider_answer_is_read_for_what_matters() {
        let answer = |status, body: &str| Response {
            status,
            headers: Vec::new(),
            body: Secret::new(body),
        };
        assert!(matches!(
            read_exchange(&answer(200, r#"{"access_token":"a","expires_in":"120"}"#)),
            Exchanged::Token {
                expires_in: 120,
                ..
            }
        ));
        assert!(matches!(
            read_exchange(&answer(400, r#"{"error":"invalid_grant"}"#)),
            Exchanged::Refused
        ));
        assert!(matches!(
            read_exchange(&answer(400, r#"{"error":"invalid_request"}"#)),
            Exchanged::Failed
        ));
        assert!(matches!(read_exchange(&answer(503, "")), Exchanged::Failed));
        assert!(matches!(
            read_exchange(&answer(200, r#"{"token_type":"Bearer"}"#)),
            Exchanged::Failed
        ));
    }

    fn google() -> Recipe {
        crate::verify::load_recipe("google").unwrap()
    }

    const FILE: &str = r#"{"type":"authorized_user","client_id":"764-abc.apps.googleusercontent.com","client_secret":"GOCSPX-CANARYsecret000000000000","refresh_token":"1//0gCANARYrefresh00000000000000000000","quota_project_id":"my-project","token":"ya29.CANARYold-access-token"}"#;

    #[test]
    fn the_command_gets_the_same_shape_with_stand_ins() {
        let grant =
            OAuthGrant::new("g-1", "google", &google(), FILE, None, u64::MAX, None).unwrap();
        let json: serde_json::Value = serde_json::from_str(&grant.stand_in()).unwrap();
        assert_eq!(json["type"], "authorized_user");
        assert_eq!(json["client_id"], "764-abc.apps.googleusercontent.com");
        assert_eq!(json["quota_project_id"], "my-project");
        assert_eq!(json["token_uri"], "https://oauth2.googleapis.com/token");
        let text = grant.stand_in();
        assert!(!text.contains("CANARY"), "{text}");
        assert!(
            json.get("token").is_none(),
            "an old access token is not copied"
        );
        assert_eq!(
            json["client_secret"].as_str().unwrap().len(),
            "GOCSPX-CANARYsecret000000000000".len()
        );
    }

    #[test]
    fn a_token_request_matches_only_its_own_stand_ins() {
        let grant =
            OAuthGrant::new("g-1", "google", &google(), FILE, None, u64::MAX, None).unwrap();
        let json: serde_json::Value = serde_json::from_str(&grant.stand_in()).unwrap();
        let (id, secret, refresh) = (
            json["client_id"].as_str().unwrap(),
            json["client_secret"].as_str().unwrap(),
            json["refresh_token"].as_str().unwrap(),
        );
        let form = |id: &str, secret: &str, refresh: &str| {
            format!(
                "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={}",
                id,
                secret,
                refresh.replace('/', "%2F")
            )
        };
        let ask = |body: String| TokenAsk::read(body.as_bytes(), &[]);
        assert!(grant.matches(&ask(form(id, secret, refresh))));
        // The real values are not stand-ins: the proxy would forward nothing either way.
        assert!(!grant.matches(&ask(form(
            id,
            "GOCSPX-CANARYsecret000000000000",
            "1//0gCANARYrefresh00000000000000000000"
        ))));
        assert!(!grant.matches(&ask(form(id, secret, "1//0gwrong"))));
        assert!(!grant.matches(&ask(form("other-client", secret, refresh))));
        let other_grant = format!("grant_type=client_credentials&client_secret={secret}");
        assert!(!grant.matches(&ask(other_grant)));
        // The id and secret may come as Basic.
        let basic = super::super::http::base64_encode(format!("{id}:{secret}").as_bytes());
        let headers = vec![("Authorization".to_owned(), format!("Basic {basic}"))];
        let body = format!(
            "grant_type=refresh_token&refresh_token={}",
            refresh.replace('/', "%2F")
        );
        assert!(grant.matches(&TokenAsk::read(body.as_bytes(), &headers)));
    }

    #[test]
    fn a_short_credential_is_not_given_stand_ins_that_could_be_guessed() {
        let short = r#"{"client_id":"a","client_secret":"short","refresh_token":"1//0gCANARYrefresh00000000000000000000"}"#;
        assert!(OAuthGrant::new("g-1", "google", &google(), short, None, u64::MAX, None).is_err());
    }
}
