//! Signs keyreeve in to a remote server that uses OAuth, such as an MCP server, once, so the vault holds the
//! refresh token and no program does. It finds the server's authorization server (RFC 9728 and RFC 8414),
//! registers keyreeve as a client (RFC 7591), and sends the person to sign in in their browser, with PKCE
//! (RFC 7636) and a redirect to this machine. What comes back is a credentials file of the shape the proxy reads:
//! client id, client secret and refresh token. It is never printed to a terminal.

use crate::secret::Secret;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

/// How long the person has to sign in.
pub const SIGN_IN_TIME: Duration = Duration::from_secs(300);

/// A status, the headers with their names in lower case, and the body.
pub type Answer = (u16, Vec<(String, String)>, String);

/// One HTTPS exchange. Tests stand in for the network.
pub trait Web {
    /// Sends a request and gives back its status, headers (names in lower case) and body.
    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<Answer, String>;
}

/// Where to sign in, as the server says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// The address the token is for, sent as `resource` (RFC 8707).
    pub resource: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
}

impl Server {
    /// The hosts a recipe for this server needs: the resource's, then the token endpoint's if it is another.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts = vec![host_of(&self.resource).unwrap_or_default()];
        if let Some(token) = host_of(&self.token_endpoint) {
            if !hosts.contains(&token) {
                hosts.push(token);
            }
        }
        hosts
    }

    /// The token endpoint's path, as a recipe's `token_path`.
    pub fn token_path(&self) -> String {
        path_of(&self.token_endpoint)
    }
}

/// The client keyreeve registered as.
pub struct Client {
    pub id: String,
    pub secret: Secret,
}

fn https(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("{url} is not an https address"))?;
    if rest.is_empty() || rest.starts_with('/') {
        return Err(format!("{url} names no host"));
    }
    Ok(())
}

/// The host of an https address, in lower case, with its port if it has one.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty() && !host.contains('@')).then(|| host.to_ascii_lowercase())
}

fn path_of(url: &str) -> String {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    match rest.find('/') {
        Some(at) => rest[at..]
            .split(['?', '#'])
            .next()
            .unwrap_or("/")
            .to_owned(),
        None => "/".into(),
    }
}

fn json(body: &str, what: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(body).map_err(|_| format!("{what} is not JSON"))
}

fn text(json: &serde_json::Value, name: &str) -> Option<String> {
    json.get(name)?.as_str().map(str::to_owned)
}

/// Finds where to sign in for `resource`: its protected resource metadata, then its authorization server's.
pub fn discover(resource: &str, web: &mut dyn Web) -> Result<Server, String> {
    https(resource)?;
    let host = host_of(resource).ok_or("that address names no host")?;
    // The server names its metadata in its 401. Without that, the well-known address for this path, then the root.
    let (_, headers, _) = web.send("GET", resource, &[], None)?;
    let named = headers
        .iter()
        .filter(|(name, _)| name == "www-authenticate")
        .find_map(|(_, value)| {
            let at = value.find("resource_metadata=\"")? + "resource_metadata=\"".len();
            value[at..].split('"').next().map(str::to_owned)
        });
    let path = path_of(resource);
    let mut candidates: Vec<String> = named.into_iter().collect();
    if path != "/" {
        candidates.push(format!(
            "https://{host}/.well-known/oauth-protected-resource{path}"
        ));
    }
    candidates.push(format!(
        "https://{host}/.well-known/oauth-protected-resource"
    ));
    let mut metadata = None;
    for url in candidates {
        https(&url)?;
        let (status, _, body) = web.send("GET", &url, &[("accept", "application/json")], None)?;
        if status == 200 {
            metadata = Some(json(&body, "the resource's metadata")?);
            break;
        }
    }
    let metadata = metadata.ok_or("the server says nothing about where to sign in")?;
    let issuer = metadata
        .get("authorization_servers")
        .and_then(|list| list.as_array())
        .and_then(|list| list.first())
        .and_then(|value| value.as_str())
        .ok_or("the server names no authorization server")?
        .trim_end_matches('/')
        .to_owned();
    https(&issuer)?;
    let issuer_host = host_of(&issuer).ok_or("the authorization server names no host")?;
    let issuer_path = path_of(&issuer);
    let issuer_path = if issuer_path == "/" {
        ""
    } else {
        issuer_path.as_str()
    };
    let url = format!("https://{issuer_host}/.well-known/oauth-authorization-server{issuer_path}");
    let (status, _, body) = web.send("GET", &url, &[("accept", "application/json")], None)?;
    if status != 200 {
        return Err(format!(
            "the authorization server's metadata answered {status}"
        ));
    }
    let auth = json(&body, "the authorization server's metadata")?;
    let endpoint = |name: &str| -> Result<String, String> {
        let url =
            text(&auth, name).ok_or_else(|| format!("the authorization server has no {name}"))?;
        https(&url)?;
        Ok(url)
    };
    // Without S256 the code could be redeemed by whoever saw it on its way back.
    if let Some(methods) = auth
        .get("code_challenge_methods_supported")
        .and_then(|m| m.as_array())
    {
        if !methods.iter().any(|method| method == "S256") {
            return Err("the authorization server does not take PKCE with S256".into());
        }
    }
    let resource = text(&metadata, "resource").unwrap_or_else(|| resource.to_owned());
    if host_of(&resource).as_deref() != Some(host.as_str()) {
        return Err("the server's metadata is for another host".into());
    }
    Ok(Server {
        resource,
        authorization_endpoint: endpoint("authorization_endpoint")?,
        token_endpoint: endpoint("token_endpoint")?,
        registration_endpoint: endpoint("registration_endpoint")?,
    })
}

fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
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

/// Registers keyreeve as a client that signs in with a secret, redirected to this machine.
pub fn register(server: &Server, redirect: &str, web: &mut dyn Web) -> Result<Client, String> {
    let body = serde_json::json!({
        "client_name": "keyreeve",
        "redirect_uris": [redirect],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    })
    .to_string();
    let (status, _, answer) = web.send(
        "POST",
        &server.registration_endpoint,
        &[
            ("content-type", "application/json"),
            ("accept", "application/json"),
        ],
        Some(&body),
    )?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "registering keyreeve as a client answered {status}"
        ));
    }
    let answer = json(&answer, "the registration's answer")?;
    let id = text(&answer, "client_id").ok_or("the registration gave no client id")?;
    // A server that gives no secret registered a client that needs none. The proxy renews with a secret, so stop.
    let secret = text(&answer, "client_secret")
        .filter(|secret| !secret.is_empty())
        .ok_or("the server registered keyreeve with no client secret, which keyreeve cannot renew with yet")?;
    Ok(Client {
        id,
        secret: Secret::new(secret),
    })
}

fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..=chunk.len() {
            out.push(TABLE[(n >> (18 - 6 * index)) as usize & 63] as char);
        }
    }
    out
}

/// A random value for PKCE and for `state`, from the system's generator.
pub fn random_text() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "no random numbers".to_owned())?;
    Ok(base64url(&bytes))
}

/// The PKCE challenge for a verifier.
pub fn challenge(verifier: &str) -> String {
    base64url(&Sha256::digest(verifier.as_bytes()))
}

/// The address the person opens to sign in.
pub fn authorize_url(
    server: &Server,
    client: &Client,
    redirect: &str,
    challenge: &str,
    state: &str,
) -> String {
    let join = if server.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!(
        "{}{join}response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&resource={}",
        server.authorization_endpoint,
        form_encode(&client.id),
        form_encode(redirect),
        form_encode(challenge),
        form_encode(state),
        form_encode(&server.resource),
    )
}

/// Waits on this machine for the browser to come back with the code. Anything without the right state is
/// turned away and the wait goes on, so another page cannot end it with a code of its own.
pub fn wait_for_code(
    listener: &TcpListener,
    state: &str,
    within: Duration,
) -> Result<Secret, String> {
    let deadline = Instant::now() + within;
    listener
        .set_nonblocking(true)
        .map_err(|_| "the local address could not wait")?;
    loop {
        if Instant::now() > deadline {
            return Err("nobody signed in in time".into());
        }
        let (socket, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(_) => return Err("the local address stopped".into()),
        };
        let _ = socket.set_nonblocking(false);
        let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
        let mut reader = BufReader::new(&socket);
        let mut first = String::new();
        if reader.read_line(&mut first).is_err() {
            continue;
        }
        let target = first.split(' ').nth(1).unwrap_or("");
        let query = target.split_once('?').map_or("", |(_, query)| query);
        let mut code = None;
        let mut came_state = None;
        let mut error = None;
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = form_decode(value);
            match name {
                "code" => code = value,
                "state" => came_state = value,
                "error" => error = value,
                _ => {}
            }
        }
        let reply = |mut socket: &std::net::TcpStream, status: &str, text: &str| {
            let page =
                format!("<!doctype html><meta charset=utf-8><title>keyreeve</title><p>{text}</p>");
            let _ = write!(
                socket,
                "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                page.len()
            );
        };
        if came_state.as_deref() != Some(state) {
            reply(
                &socket,
                "400 Bad Request",
                "This is not the sign-in keyreeve is waiting for.",
            );
            continue;
        }
        if let Some(error) = error {
            reply(
                &socket,
                "200 OK",
                "Signing in did not finish. You can close this page.",
            );
            return Err(format!("the server said {error}"));
        }
        let Some(code) = code.filter(|code| !code.is_empty()) else {
            reply(&socket, "400 Bad Request", "The server sent no code.");
            continue;
        };
        reply(
            &socket,
            "200 OK",
            "keyreeve is signed in. You can close this page.",
        );
        return Ok(Secret::new(code));
    }
}

/// Trades the code for tokens and gives back the credentials file: client id, client secret and refresh token.
pub fn redeem(
    server: &Server,
    client: &Client,
    code: &Secret,
    verifier: &str,
    redirect: &str,
    web: &mut dyn Web,
) -> Result<Secret, String> {
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}&resource={}",
        form_encode(code.expose()),
        form_encode(redirect),
        form_encode(&client.id),
        form_encode(client.secret.expose()),
        form_encode(verifier),
        form_encode(&server.resource),
    );
    let (status, _, answer) = web.send(
        "POST",
        &server.token_endpoint,
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "application/json"),
        ],
        Some(&body),
    )?;
    let answer = Secret::new(answer);
    // The answer holds tokens, so none of it goes into an error.
    if !(200..300).contains(&status) {
        return Err(format!("the token endpoint answered {status}"));
    }
    let tokens = json(answer.expose(), "the token endpoint's answer")?;
    let refresh = text(&tokens, "refresh_token")
        .filter(|refresh| !refresh.is_empty())
        .ok_or("the server gave no refresh token, so keyreeve could not renew access on its own")?;
    let file = serde_json::json!({
        "type": "authorized_user",
        "client_id": client.id,
        "client_secret": client.secret.expose(),
        "refresh_token": refresh,
        "token_uri": server.token_endpoint,
        "resource": server.resource,
    });
    Ok(Secret::new(
        serde_json::to_string_pretty(&file).unwrap_or_default(),
    ))
}

/// A recipe for this server, with no value in it: for `~/.keyreeve/providers/<provider>.yaml`.
pub fn recipe_text(provider: &str, server: &Server) -> String {
    let hosts = server.hosts();
    let token_host = host_of(&server.token_endpoint).unwrap_or_default();
    let verify_path = path_of(&server.resource);
    format!(
        "schema: 1\nprovider: {provider}\nname: {}\nhosts: [{}]\n# A program gets a stand-in bearer token; the proxy renews the real one with the refresh token.\nauth: {{ type: oauth_token, grant: refresh_token, token_host: {token_host}, token_path: {}, token_is_proof: true, gives: bearer }}\nverify: {{ method: GET, host: {}, path: {verify_path} }}\n",
        hosts[0],
        hosts.join(", "),
        server.token_path(),
        hosts[0],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The network, as answers by method and address, and what was sent.
    #[derive(Default)]
    struct Fake {
        answers: HashMap<(String, String), Answer>,
        sent: Vec<(String, String, Option<String>)>,
    }

    impl Fake {
        fn answer(&mut self, method: &str, url: &str, status: u16, body: &str) {
            self.answers.insert(
                (method.into(), url.into()),
                (status, Vec::new(), body.into()),
            );
        }
    }

    impl Web for Fake {
        fn send(
            &mut self,
            method: &str,
            url: &str,
            _headers: &[(&str, &str)],
            body: Option<&str>,
        ) -> Result<(u16, Vec<(String, String)>, String), String> {
            self.sent
                .push((method.into(), url.into(), body.map(str::to_owned)));
            Ok(self
                .answers
                .get(&(method.to_owned(), url.to_owned()))
                .cloned()
                .unwrap_or((404, Vec::new(), String::new())))
        }
    }

    fn server_fake() -> Fake {
        let mut web = Fake::default();
        web.answers.insert(
            ("GET".into(), "https://mcp.example.com/mcp".into()),
            (
                401,
                vec![(
                    "www-authenticate".into(),
                    r#"Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp""#.into(),
                )],
                String::new(),
            ),
        );
        web.answer(
            "GET",
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            200,
            r#"{"resource":"https://mcp.example.com/mcp","authorization_servers":["https://mcp.example.com"]}"#,
        );
        web.answer(
            "GET",
            "https://mcp.example.com/.well-known/oauth-authorization-server",
            200,
            r#"{"issuer":"https://mcp.example.com","authorization_endpoint":"https://mcp.example.com/oauth/authorize","token_endpoint":"https://mcp.example.com/oauth/token","registration_endpoint":"https://mcp.example.com/oauth/register","code_challenge_methods_supported":["S256"]}"#,
        );
        web
    }

    #[test]
    fn it_finds_where_to_sign_in_from_the_servers_401() {
        let mut web = server_fake();
        let server = discover("https://mcp.example.com/mcp", &mut web).unwrap();
        assert_eq!(server.token_endpoint, "https://mcp.example.com/oauth/token");
        assert_eq!(
            server.registration_endpoint,
            "https://mcp.example.com/oauth/register"
        );
        assert_eq!(server.hosts(), vec!["mcp.example.com"]);
        assert_eq!(server.token_path(), "/oauth/token");
        let recipe = crate::recipe::Recipe::parse(&recipe_text("example-mcp", &server)).unwrap();
        assert_eq!(recipe.auth.gives.as_deref(), Some("bearer"));
        assert_eq!(recipe.hosts, vec!["mcp.example.com"]);
    }

    #[test]
    fn a_server_without_s256_or_https_is_refused() {
        let mut web = server_fake();
        web.answer(
            "GET",
            "https://mcp.example.com/.well-known/oauth-authorization-server",
            200,
            r#"{"authorization_endpoint":"https://mcp.example.com/a","token_endpoint":"https://mcp.example.com/t","registration_endpoint":"https://mcp.example.com/r","code_challenge_methods_supported":["plain"]}"#,
        );
        assert!(discover("https://mcp.example.com/mcp", &mut web)
            .unwrap_err()
            .contains("S256"));
        let mut web = server_fake();
        web.answer(
            "GET",
            "https://mcp.example.com/.well-known/oauth-authorization-server",
            200,
            r#"{"authorization_endpoint":"http://mcp.example.com/a","token_endpoint":"https://mcp.example.com/t","registration_endpoint":"https://mcp.example.com/r"}"#,
        );
        assert!(discover("https://mcp.example.com/mcp", &mut web).is_err());
        assert!(discover("http://mcp.example.com/mcp", &mut server_fake()).is_err());
    }

    #[test]
    fn the_code_becomes_a_credentials_file_the_proxy_reads() {
        let mut web = server_fake();
        let server = discover("https://mcp.example.com/mcp", &mut web).unwrap();
        web.answer(
            "POST",
            "https://mcp.example.com/oauth/register",
            201,
            r#"{"client_id":"c-1","client_secret":"CANARYclientSecret"}"#,
        );
        let redirect = "http://127.0.0.1:5555/callback";
        let client = register(&server, redirect, &mut web).unwrap();
        let verifier = random_text().unwrap();
        let url = authorize_url(&server, &client, redirect, &challenge(&verifier), "st");
        assert!(url.starts_with(
            "https://mcp.example.com/oauth/authorize?response_type=code&client_id=c-1"
        ));
        assert!(url.contains("code_challenge_method=S256") && !url.contains(&verifier));
        web.answer(
            "POST",
            "https://mcp.example.com/oauth/token",
            200,
            r#"{"access_token":"CANARYaccess","refresh_token":"CANARYrefresh","expires_in":3600}"#,
        );
        let file = redeem(
            &server,
            &client,
            &Secret::new("the-code"),
            &verifier,
            redirect,
            &mut web,
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(file.expose()).unwrap();
        assert_eq!(json["refresh_token"], "CANARYrefresh");
        assert!(
            json.get("access_token").is_none(),
            "the access token is not kept"
        );
        let sent = web.sent.last().unwrap().2.clone().unwrap();
        assert!(sent.contains(&format!("code_verifier={verifier}")));
        // The proxy reads this file as it reads Google's.
        let recipe = crate::recipe::Recipe::parse(&recipe_text("example-mcp", &server)).unwrap();
        let credential = crate::keys::read_key_for(file.expose(), None, &recipe).unwrap();
        assert_eq!(credential.expose(), "c-1:CANARYclientSecret:CANARYrefresh");
    }

    #[test]
    fn a_check_never_spends_a_bearer_servers_refresh_token() {
        struct Never;
        impl crate::transport::Transport for Never {
            fn send(
                &mut self,
                _: &crate::transport::Request,
            ) -> Result<crate::transport::Response, crate::transport::TransportError> {
                panic!("a check sent a request");
            }
        }
        let mut web = server_fake();
        let server = discover("https://mcp.example.com/mcp", &mut web).unwrap();
        let recipe = crate::recipe::Recipe::parse(&recipe_text("example-mcp", &server)).unwrap();
        let key = Secret::new("c:secret:refresh");
        assert!(matches!(
            crate::verify::check(&recipe, &key, &mut Never),
            crate::verify::Verdict::NoResult(_)
        ));
        assert!(crate::identify::identify(&recipe, &key, &mut Never).is_err());
    }

    #[test]
    fn errors_never_quote_the_tokens() {
        let mut web = server_fake();
        let server = discover("https://mcp.example.com/mcp", &mut web).unwrap();
        web.answer(
            "POST",
            "https://mcp.example.com/oauth/token",
            400,
            r#"{"error":"invalid_grant","refresh_token":"CANARY"}"#,
        );
        let client = Client {
            id: "c".into(),
            secret: Secret::new("CANARYsecret"),
        };
        let error = redeem(
            &server,
            &client,
            &Secret::new("CANARYcode"),
            "v",
            "http://127.0.0.1:1/",
            &mut web,
        )
        .err()
        .unwrap();
        assert!(!error.contains("CANARY"), "{error}");
        web.answer(
            "POST",
            "https://mcp.example.com/oauth/register",
            201,
            r#"{"client_id":"c"}"#,
        );
        assert!(register(&server, "http://127.0.0.1:1/", &mut web).is_err());
    }

    #[test]
    fn only_the_right_state_ends_the_wait() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let browser = std::thread::spawn(move || {
            let ask = |path: &str| {
                let mut socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
                write!(socket, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
                let mut answer = String::new();
                let _ = std::io::Read::read_to_string(&mut socket, &mut answer);
                answer
            };
            let wrong = ask("/callback?code=FORGED&state=other");
            let right = ask("/callback?code=real%2Bcode&state=good");
            (wrong, right)
        });
        let code = wait_for_code(&listener, "good", Duration::from_secs(10)).unwrap();
        assert_eq!(code.expose(), "real+code");
        let (wrong, right) = browser.join().unwrap();
        assert!(wrong.starts_with("HTTP/1.1 400"), "{wrong}");
        assert!(right.contains("signed in"));
    }

    #[test]
    fn pkce_matches_the_rfc_example() {
        // RFC 7636, appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
