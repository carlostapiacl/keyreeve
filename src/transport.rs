//! Sends a recipe's requests. Only here does a credential reach the network, and only over
//! HTTPS, to a host the recipe declared, with redirects off.

use crate::recipe::{Recipe, Rendered, Step};
use crate::secret::Secret;
use crate::sigv4;
use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

pub struct Request {
    pub rendered: Rendered,
    pub headers: Vec<(String, String)>,
    pub auth: (String, Secret),
}

impl Request {
    /// Builds a request for a step. The credential goes only in the recipe's auth header, or is
    /// used to sign the request and is not sent at all.
    pub fn for_step(
        recipe: &Recipe,
        step: &Step,
        vars: &[(&str, &str)],
        credential: &Secret,
    ) -> Self {
        let rendered = step.render(recipe, vars);
        let mut headers: Vec<(String, String)> = recipe
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let auth = match recipe.auth.kind.as_deref() {
            Some("aws_sigv4") => {
                let stamp = sigv4::stamp_now();
                let (access, secret) = credential.expose().split_once(':').unwrap_or(("", ""));
                let signed = sigv4::authorization(
                    &sigv4::Signing {
                        service: recipe.auth.service.as_deref().unwrap_or_default(),
                        region: recipe.auth.region.as_deref().unwrap_or_default(),
                        method: &rendered.method,
                        host: &rendered.host,
                        path: &rendered.path,
                        content_type: None,
                        body: rendered.body.as_deref().unwrap_or_default(),
                        stamp: &stamp,
                    },
                    access,
                    &Secret::new(secret),
                );
                headers.push(("x-amz-date".into(), stamp));
                ("authorization".to_owned(), Secret::new(signed))
            }
            _ => (
                recipe.auth.header.clone(),
                Secret::new(format!("{}{}", recipe.auth.prefix, credential.expose())),
            ),
        };
        Self {
            rendered,
            headers,
            auth,
        }
    }
}

pub struct Response {
    pub status: u16,
    /// Can hold a new key, so it stays out of errors and logs.
    pub body: Secret,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    HostNotAllowed(String),
    Failed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostNotAllowed(host) => write!(f, "host {host} is not in the recipe"),
            Self::Failed => f.write_str("the request did not complete"),
        }
    }
}

pub trait Transport {
    fn send(&mut self, request: &Request) -> Result<Response, TransportError>;
}

pub struct HttpTransport {
    agent: ureq::Agent,
    allowed: BTreeSet<String>,
    scheme: &'static str,
}

impl HttpTransport {
    pub fn for_recipe(recipe: &Recipe) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Self {
            agent,
            allowed: recipe.hosts.iter().cloned().collect(),
            scheme: "https",
        }
    }
}

impl Transport for HttpTransport {
    fn send(&mut self, request: &Request) -> Result<Response, TransportError> {
        let rendered = &request.rendered;
        if !self.allowed.contains(&rendered.host) {
            return Err(TransportError::HostNotAllowed(rendered.host.clone()));
        }
        let mut builder = ureq::http::Request::builder()
            .method(rendered.method.as_str())
            .uri(format!(
                "{}://{}{}",
                self.scheme, rendered.host, rendered.path
            ));
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        builder = builder.header(&request.auth.0, request.auth.1.expose());

        // Errors from the client are dropped on purpose: they can quote the request.
        let mut response = match &rendered.body {
            Some(body) => {
                let built = builder
                    .header("content-type", "application/json")
                    .body(body.clone())
                    .map_err(|_| TransportError::Failed)?;
                self.agent.run(built)
            }
            None => {
                let built = builder.body(()).map_err(|_| TransportError::Failed)?;
                self.agent.run(built)
            }
        }
        .map_err(|_| TransportError::Failed)?;

        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(|_| TransportError::Failed)?;
        Ok(Response {
            status,
            body: Secret::new(String::from_utf8_lossy(&body).into_owned()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    /// Answers every connection with `reply` and counts the connections.
    fn server(reply: String) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer);
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        (port, hits)
    }

    fn loopback(port: u16) -> HttpTransport {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .into();
        HttpTransport {
            agent,
            allowed: [format!("127.0.0.1:{port}")].into_iter().collect(),
            scheme: "http",
        }
    }

    fn request(host: String) -> Request {
        Request {
            rendered: Rendered {
                method: "GET".into(),
                host,
                path: "/".into(),
                body: None,
            },
            headers: Vec::new(),
            auth: ("authorization".into(), Secret::new("canary")),
        }
    }

    #[test]
    fn does_not_follow_a_redirect_with_the_credential() {
        let (other, other_hits) = server("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".into());
        let (port, _) = server(format!(
            "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:{other}/\r\ncontent-length: 0\r\n\r\n"
        ));
        let response = loopback(port)
            .send(&request(format!("127.0.0.1:{port}")))
            .unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(other_hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn refuses_a_host_outside_the_recipe() {
        let (port, hits) = server("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".into());
        let error = loopback(port + 1)
            .send(&request(format!("127.0.0.1:{port}")))
            .err()
            .unwrap();
        assert!(matches!(error, TransportError::HostNotAllowed(_)));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_real_transport_refuses_plain_http() {
        let recipe = Recipe::parse(
            r#"
schema: 1
provider: example
hosts: [api.example.com]
auth: { header: Authorization }
create: { method: POST, path: /k, value_from: $.v, id_from: $.i }
verify: { method: GET, path: /me }
revoke: { method: DELETE, path: "/k/{id}" }
"#,
        )
        .unwrap();
        let (port, hits) = server("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".into());
        let mut transport = HttpTransport::for_recipe(&recipe);
        transport.scheme = "http";
        transport.allowed.insert(format!("127.0.0.1:{port}"));
        let error = transport
            .send(&request(format!("127.0.0.1:{port}")))
            .err()
            .unwrap();
        assert_eq!(error, TransportError::Failed);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}
