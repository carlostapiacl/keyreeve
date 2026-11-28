use super::usage;
use keyreeve::oauth_login::{self, Answer, Web, SIGN_IN_TIME};
use std::io::{IsTerminal, Read, Write};
use std::net::TcpListener;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

/// The network for signing in: HTTPS only, no redirects, a short wait.
struct Https(ureq::Agent);

impl Web for Https {
    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<Answer, String> {
        let mut builder = ureq::http::Request::builder().method(method).uri(url);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        // Errors from the client are dropped on purpose: they can quote the request.
        let failed = |_| format!("{url} could not be reached");
        let mut response = match body {
            Some(body) => self.0.run(
                builder
                    .body(body.to_owned())
                    .map_err(|_| "a bad request".to_owned())?,
            ),
            None => self
                .0
                .run(builder.body(()).map_err(|_| "a bad request".to_owned())?),
        }
        .map_err(failed)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                Some((
                    name.as_str().to_ascii_lowercase(),
                    value.to_str().ok()?.to_owned(),
                ))
            })
            .collect();
        let mut text = String::new();
        response
            .body_mut()
            .as_reader()
            .take(1024 * 1024)
            .read_to_string(&mut text)
            .map_err(|_| format!("{url} answered something unreadable"))?;
        Ok((status, headers, text))
    }
}

/// `keyreeve oauth-login <address> [--provider <name>]`: signs keyreeve in to that server in the browser and
/// writes the credentials file to stdout, for `keyreeve add` to seal. Never to a terminal.
pub fn run_oauth_login(args: &[String]) -> ExitCode {
    let (resource, provider) = match args {
        [resource] => (resource.clone(), None),
        [resource, flag, provider] if flag == "--provider" => {
            (resource.clone(), Some(provider.clone()))
        }
        _ => return usage(),
    };
    if std::io::stdout().is_terminal() {
        eprintln!(
            "oauth-login writes a refresh token, so it does not write to a terminal. Send it to the vault:\n  keyreeve-cli oauth-login {resource} | keyreeve add <id> --description \"...\""
        );
        return ExitCode::from(2);
    }
    match sign_in(&resource, provider.as_deref()) {
        Ok(file) => {
            let mut out = std::io::stdout();
            if out
                .write_all(file.expose().as_bytes())
                .and_then(|()| out.flush())
                .is_err()
            {
                eprintln!("oauth-login: the credentials could not be handed on");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("oauth-login: {error}");
            ExitCode::FAILURE
        }
    }
}

fn sign_in(resource: &str, provider: Option<&str>) -> Result<keyreeve::secret::Secret, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let mut web = Https(agent);
    let server = oauth_login::discover(resource, &mut web)?;
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|_| "no local address to come back to")?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let client = oauth_login::register(&server, &redirect, &mut web)?;
    let verifier = oauth_login::random_text()?;
    let state = oauth_login::random_text()?;
    let url = oauth_login::authorize_url(
        &server,
        &client,
        &redirect,
        &oauth_login::challenge(&verifier),
        &state,
    );
    eprintln!(
        "Sign in to {} in your browser. If it does not open:\n  {url}",
        server.hosts()[0]
    );
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = Command::new(opener)
        .arg(&url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let code = oauth_login::wait_for_code(&listener, &state, SIGN_IN_TIME)?;
    let file = oauth_login::redeem(&server, &client, &code, &verifier, &redirect, &mut web)?;
    let name = provider.map_or_else(
        || {
            server.hosts()[0]
                .split('.')
                .next()
                .unwrap_or("server")
                .to_owned()
        },
        str::to_owned,
    );
    eprintln!(
        "Signed in. A provider file for it, with no value, for ~/.keyreeve/providers/{name}.yaml:\n\n{}",
        oauth_login::recipe_text(&name, &server)
    );
    Ok(file)
}
