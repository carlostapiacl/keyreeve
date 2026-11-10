//! The proxy as a process, driven by the vault's service over stdin and stdout.

use super::{mint_stand_in, Event, Grant, OAuthGrant, Options, Proxy};
use crate::providers;
use crate::recipe::Recipe;
use crate::secret::Secret;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

/// What this file can stand in for: one plain request with the key in a header, a password or the
/// address, or an OAuth credential the proxy exchanges for tokens itself. A signature needs more than
/// swapping one value.
pub fn can_stand_in(recipe: &Recipe) -> bool {
    !recipe.hosts.is_empty()
        && !recipe.self_hosted
        && recipe.auth.run.is_none()
        && !matches!(
            recipe.auth.kind.as_deref(),
            Some("ssh") | Some("command") | Some("aws_sigv4")
        )
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Control {
    Add {
        grant: String,
        key: String,
        provider: String,
        /// The sealed file's text, which this reads the key from as a check would.
        text: String,
        field: Option<String>,
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
    forget_stand_in_files(folder);
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
                text,
                field,
                expires,
            } => {
                let text = zeroize::Zeroizing::new(text);
                let prepared = prepare_grant(
                    &grant,
                    &key,
                    &provider,
                    &text,
                    field.as_deref(),
                    expires,
                    folder,
                );
                match prepared {
                    Ok(Prepared::Plain(ready)) => {
                        let stand_in = ready.stand_in.expose().to_owned();
                        proxy.add(ready);
                        say(&Reply::Added { grant, stand_in });
                    }
                    Ok(Prepared::OAuth(ready)) => {
                        // The path of a credentials file with stand-ins, which the command gets as its variable.
                        let stand_in = ready.stand_in();
                        proxy.add_oauth(*ready);
                        say(&Reply::Added { grant, stand_in });
                    }
                    Err(error) => say(&Reply::Failed { grant, error }),
                }
            }
        }
    }
    Ok(())
}

enum Prepared {
    Plain(Grant),
    OAuth(Box<OAuthGrant>),
}

/// Credentials files with stand-ins left by a proxy that did not stop cleanly. Their permissions ended with it.
fn forget_stand_in_files(folder: &Path) {
    for entry in std::fs::read_dir(folder).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("oauth-") && name.ends_with(".json") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn prepare_grant(
    id: &str,
    key: &str,
    provider: &str,
    text: &str,
    field: Option<&str>,
    expires: u64,
    folder: &Path,
) -> Result<Prepared, String> {
    let recipe = providers::load(provider)?;
    if !can_stand_in(&recipe) {
        return Err(format!(
            "{provider} cannot use a stand-in, so this key needs --real"
        ));
    }
    if recipe.auth.kind.as_deref() == Some("oauth_token") {
        return OAuthGrant::new(id, key, &recipe, text, field, expires, Some(folder))
            .map(|grant| Prepared::OAuth(Box::new(grant)));
    }
    // The same reading a check uses, so a file that checks also works here.
    let key_value = crate::verify::read_key_for(text, field, &recipe)?;
    let value = key_value.expose();
    if value.chars().any(char::is_control) {
        return Err("this key has characters that cannot go in a header".into());
    }
    Ok(Prepared::Plain(Grant {
        id: id.to_owned(),
        key: key.to_owned(),
        stand_in: Secret::new(mint_stand_in(value, &recipe.prefixes)?),
        real: Secret::new(value),
        hosts: recipe.hosts.clone(),
        in_url: recipe.auth.kind.as_deref() == Some("url"),
        expires,
    }))
}
