//! A key for a service of your own on this Mac, such as a server you run on `127.0.0.1:8790`. The command
//! calls it over plain HTTP through this proxy, with the stand-in, and the proxy puts the real value in the
//! headers only on the way to the one address the person approved for that key: loopback, and that port.
//!
//! This is not a way through to this machine. A request that names another address, or that carries no
//! stand-in of a key approved for that address, is refused here and never forwarded. Tunnels keep reaching
//! the internet only.

use super::http::{answer, body_framing, copy_body, header, relay_reply, Scrubber};
use super::{connect_within, now, swap_header, Grant, Proxy, HOP_BY_HOP, IO_TIMEOUT};
use std::io::{self, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;

/// Where a key for a local service may go: loopback, and one port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalService {
    host: Loopback,
    port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loopback {
    V4,
    V6,
    Name,
}

impl LocalService {
    /// `127.0.0.1:8790`, `[::1]:8790` or `localhost:8790`. Nothing else: no other address of this machine,
    /// no private network, no name that a resolver could point elsewhere.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || {
            format!(
                "{text} is not a local service: write 127.0.0.1, [::1] or localhost, a colon and the port, such as 127.0.0.1:8790"
            )
        };
        let (host, port) = text.rsplit_once(':').ok_or_else(bad)?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let port: u16 = port
            .parse()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(bad)?;
        let host = match host.to_ascii_lowercase().as_str() {
            "127.0.0.1" => Loopback::V4,
            "[::1]" => Loopback::V6,
            "localhost" => Loopback::Name,
            _ => return Err(bad()),
        };
        Ok(Self { host, port })
    }

    /// As a client writes it in a URL and in `Host`.
    pub fn authority(&self) -> String {
        let host = match self.host {
            Loopback::V4 => "127.0.0.1",
            Loopback::V6 => "[::1]",
            Loopback::Name => "localhost",
        };
        format!("{host}:{}", self.port)
    }

    /// Where the proxy connects. `localhost` is never looked up, so no resolver can send it elsewhere.
    fn addresses(&self) -> Vec<SocketAddr> {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.port);
        match self.host {
            Loopback::V4 => vec![v4],
            Loopback::V6 => vec![v6],
            Loopback::Name => vec![v4, v6],
        }
    }

    fn is(&self, authority: &str) -> bool {
        self.authority().eq_ignore_ascii_case(authority)
    }
}

/// The parts of a request in absolute form, `http://127.0.0.1:8790/path?query`: its authority and the target
/// to send on. Nil for anything but plain HTTP, or an authority with a user in it.
fn absolute(target: &str) -> Option<(&str, String)> {
    let scheme = target.get(..7)?;
    if !scheme.eq_ignore_ascii_case("http://") {
        return None;
    }
    let rest = &target[7..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    // A fragment never leaves the client, and a query with no path is a query on `/`.
    let path = path.split('#').next().unwrap_or("");
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    Some((authority, path))
}

impl Proxy {
    /// The permissions in force for a local service at this authority.
    fn local_grants(&self, authority: &str) -> Vec<Arc<Grant>> {
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        grants.retain(|_, grant| grant.expires > now());
        grants
            .values()
            .filter(|grant| {
                grant
                    .local
                    .as_ref()
                    .is_some_and(|local| local.is(authority))
            })
            .cloned()
            .collect()
    }

    /// A plain HTTP request, which goes on only to a local service a key in force was approved for, and only
    /// with that key's stand-in in a header.
    pub(super) fn local_request(
        &self,
        first: &str,
        mut headers: Vec<(String, String)>,
        mut reader: BufReader<TcpStream>,
        mut client: TcpStream,
    ) -> io::Result<()> {
        let mut parts = first.split(' ');
        let (method, target, version) = (
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
        );
        let Some((authority, path)) = absolute(target) else {
            return answer(
                &mut client,
                405,
                "keyreeve: only CONNECT goes through here, or plain HTTP to a service on this Mac a key was approved for",
            );
        };
        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            return answer(&mut client, 400, "bad request");
        }
        let grants = self.local_grants(authority);
        if grants.is_empty() {
            return answer(
                &mut client,
                403,
                "keyreeve: plain HTTP goes through here only to a service on this Mac a key was approved for, while its permission lasts",
            );
        }
        let hosts: Vec<&(String, String)> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .collect();
        if hosts.len() > 1
            || hosts
                .first()
                .is_some_and(|(_, value)| !value.trim().eq_ignore_ascii_case(authority))
        {
            return answer(&mut client, 421, "this request is for another host");
        }
        // The value never goes in an address: a local server may log its paths.
        if grants
            .iter()
            .any(|grant| target.contains(grant.stand_in.expose()))
        {
            return answer(
                &mut client,
                400,
                "keyreeve: a key for a local service goes in a header, such as Authorization: Bearer, never in the URL",
            );
        }
        let Some(grant) = grants.into_iter().find(|grant| {
            headers.iter().any(|(name, value)| {
                !name.eq_ignore_ascii_case("host") && swap_header(value, grant) != *value
            })
        }) else {
            return answer(
                &mut client,
                403,
                "keyreeve: a request to a local service goes through only with its key's stand-in in a header",
            );
        };
        let Some(service) = grant.local.clone() else {
            return answer(
                &mut client,
                403,
                "that permission is not for a local service",
            );
        };
        let framing = match body_framing(&headers) {
            Ok(framing) => framing,
            Err(()) => return answer(&mut client, 400, "bad request framing"),
        };
        if header(&headers, "expect")
            .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
        {
            client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            client.flush()?;
        }
        headers.retain(|(name, _)| {
            !HOP_BY_HOP
                .iter()
                .any(|drop| name.eq_ignore_ascii_case(drop))
        });
        let mut out = format!("{method} {path} HTTP/1.1\r\n");
        if headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("host"))
        {
            out.push_str(&format!("Host: {}\r\n", service.authority()));
        }
        for (name, value) in &headers {
            let value = if name.eq_ignore_ascii_case("host") {
                value.clone()
            } else {
                swap_header(value, &grant)
            };
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        out.push_str("Accept-Encoding: identity\r\nConnection: close\r\n\r\n");
        let host = service.authority();
        let mut upstream = match connect_within(&service.addresses()) {
            Ok(stream) => stream,
            Err(_) => {
                self.record(Some(&grant), &host, method, &path, 0, "not sent");
                return answer(
                    &mut client,
                    502,
                    "keyreeve: nothing answers at that local service",
                );
            }
        };
        upstream.set_read_timeout(Some(IO_TIMEOUT))?;
        upstream.set_write_timeout(Some(IO_TIMEOUT))?;
        // Connecting takes a moment, and the permission can end during it.
        if self
            .local_grants(&host)
            .iter()
            .all(|live| live.id != grant.id)
        {
            self.record(Some(&grant), &host, method, &path, 0, "not sent");
            return answer(&mut client, 403, "that permission has ended");
        }
        let sent = (|| -> io::Result<()> {
            upstream.write_all(out.as_bytes())?;
            copy_body(&framing, &mut reader, &mut upstream)?;
            upstream.flush()
        })();
        if sent.is_err() {
            self.record(Some(&grant), &host, method, &path, 0, "sent in part");
            return answer(&mut client, 502, "the request could not be sent");
        }
        let mut scrub = Scrubber::new(grant.real.expose(), grant.stand_in.expose());
        let relayed = relay_reply(&upstream, &mut client, &mut scrub).and_then(|status| {
            client.flush()?;
            Ok(status)
        });
        match relayed {
            Ok(status) => {
                self.record(Some(&grant), &host, method, &path, status, "complete");
                Ok(())
            }
            Err(error) => {
                self.record(Some(&grant), &host, method, &path, 0, "no full reply");
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_service_is_loopback_and_a_port() {
        for (text, authority) in [
            ("127.0.0.1:8790", "127.0.0.1:8790"),
            ("localhost:8787", "localhost:8787"),
            ("LOCALHOST:8787", "localhost:8787"),
            ("[::1]:9000", "[::1]:9000"),
        ] {
            assert_eq!(LocalService::parse(text).unwrap().authority(), authority);
        }
        for refused in [
            "127.0.0.1",
            "127.0.0.1:",
            "127.0.0.1:0",
            "127.0.0.1:+80",
            "127.0.0.1:70000",
            "127.0.0.2:8790",
            "0.0.0.0:8790",
            "::1:8790",
            "10.0.0.5:8790",
            "192.168.1.10:8790",
            "169.254.169.254:80",
            "example.com:8790",
            "localhost.example.com:8790",
            "http://127.0.0.1:8790",
            "user@127.0.0.1:8790",
            "",
        ] {
            assert!(LocalService::parse(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn localhost_is_never_looked_up() {
        let both = LocalService::parse("localhost:8790").unwrap().addresses();
        assert!(both.iter().all(|address| address.ip().is_loopback()));
        assert_eq!(
            LocalService::parse("127.0.0.1:8790").unwrap().addresses(),
            vec!["127.0.0.1:8790".parse().unwrap()]
        );
    }

    #[test]
    fn an_absolute_target_splits_into_authority_and_path() {
        assert_eq!(
            absolute("http://127.0.0.1:8790/v1/eventos?desde=3"),
            Some(("127.0.0.1:8790", "/v1/eventos?desde=3".to_owned()))
        );
        assert_eq!(
            absolute("http://127.0.0.1:8790"),
            Some(("127.0.0.1:8790", "/".to_owned()))
        );
        assert_eq!(
            absolute("http://127.0.0.1:8790?a=1#x"),
            Some(("127.0.0.1:8790", "/?a=1".to_owned()))
        );
        assert_eq!(absolute("https://127.0.0.1:8790/"), None);
        assert_eq!(absolute("http://me@127.0.0.1:8790/"), None);
        assert_eq!(absolute("/v1/eventos"), None);
        assert_eq!(absolute("http:///x"), None);
    }
}
