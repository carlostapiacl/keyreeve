//! Asks a provider whose key this is. Only the fields a provider's file declares are kept, and
//! anything that looks like a credential is dropped, so the rest of the answer never lands on disk.

use crate::inventory::{kind_of, write_private};
use crate::providers;
use crate::recipe::{extract, Recipe};
use crate::script;
use crate::secret::Secret;
use crate::ssh;
use crate::transport::{exchange_token, HttpTransport, Request, Transport};
use crate::verify::{inside_folder, now, resolve, Plan, Sealed};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MAX_FIELD_CHARS: usize = 200;
/// Shorter than this, a part of a key is too common to say a value holds it.
const MIN_KEY_PART: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Details {
    pub at: u64,
    pub provider: String,
    pub fields: BTreeMap<String, String>,
    pub suggested_name: Option<String>,
}

/// Returns the declared fields. Errors say what happened, and never quote the answer.
pub fn identify(
    recipe: &Recipe,
    key: &Secret,
    transport: &mut dyn Transport,
) -> Result<BTreeMap<String, String>, String> {
    let Some(identify) = &recipe.identify else {
        return Err("this provider's file has no way to identify a key".into());
    };
    let (credential, token_answer) = if recipe.auth.kind.as_deref() == Some("oauth_token") {
        if let Some(why) = crate::transport::missing_parts(recipe, key) {
            return Err(why);
        }
        let answer = exchange_token(recipe, key, transport).map_err(|e| e.to_string())?;
        if !(200..=299).contains(&answer.status) {
            return Err(format!("HTTP {}", answer.status));
        }
        let json = serde_json::from_str::<serde_json::Value>(answer.body.expose())
            .map_err(|_| "the answer could not be read".to_owned())?;
        let token = extract(&json, "$.access_token").ok_or("the answer holds no token")?;
        (Secret::new(token), Some(json))
    } else {
        (key.clone(), None)
    };
    let request = Request::for_step(recipe, &identify.request, &[], &credential);
    let response = transport.send(&request).map_err(|e| e.to_string())?;
    let accepted = identify.request.accepts(response.status);
    if !accepted && token_answer.is_none() {
        return Err(format!("HTTP {}", response.status));
    }
    let body = response.body.expose();
    let json = match identify.format.as_deref() {
        Some("xml") => None,
        _ if !accepted => None,
        _ => Some(
            serde_json::from_str::<serde_json::Value>(body)
                .map_err(|_| "the answer could not be read".to_owned())?,
        ),
    };
    let read = |path: &str| {
        if let Some(name) = path.strip_prefix("header:") {
            return response
                .headers
                .iter()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone());
        }
        if let Some(name) = path.strip_prefix("token:") {
            return token_answer
                .as_ref()
                .and_then(|json| extract(json, &format!("$.{name}")));
        }
        if !accepted {
            return None;
        }
        match &json {
            Some(json) if path.contains(".*") => crate::recipe::extract_all(json, path),
            Some(json) => extract(json, path),
            None => xml_tag(body, path),
        }
    };
    let mut fields = BTreeMap::new();
    for (name, path) in &identify.fields {
        if let Some(value) = read(path) {
            if safe_value(&value, &credential) && safe_value(&value, key) {
                fields.insert(name.clone(), value);
            }
        }
    }
    Ok(fields)
}

fn xml_tag(body: &str, tag: &str) -> Option<String> {
    let start = body.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = body[start..].find(&format!("</{tag}>"))?;
    Some(body[start..start + end].trim().to_owned())
}

/// A provider's answer is not trusted to hold what its name says.
fn safe_value(value: &str, key: &Secret) -> bool {
    let whole = key.expose();
    let is_key_itself = (!whole.is_empty() && value.contains(whole))
        || whole
            .split(':')
            .any(|part| part.len() >= MIN_KEY_PART && value.contains(part));
    !value.is_empty()
        && value.chars().count() <= MAX_FIELD_CHARS
        && !value.chars().any(char::is_control)
        && !is_key_itself
        && value
            .split_whitespace()
            .all(|word| word.len() < 16 || kind_of(word).is_none())
}

/// The same promise as for an answer over HTTP: only what the file declares, and nothing like the key.
fn program_fields(
    fields: BTreeMap<String, String>,
    recipe: &Recipe,
    key: &Secret,
) -> BTreeMap<String, String> {
    let declared = recipe.identify.as_ref().map(|found| &found.fields);
    fields
        .into_iter()
        .filter(|field| declared.is_some_and(|names| names.contains_key(&field.0)))
        .filter(|field| safe_field(field, key))
        .collect()
}

/// A program can get the name wrong as easily as the value, and both are written to a file.
fn safe_field(field: &(String, String), key: &Secret) -> bool {
    safe_value(&field.1, key) && safe_value(&field.0, key)
}

/// Fills `{field}` in the file's own template, once. A value is a provider's answer, so a brace in
/// it is text and is never read as another field.
pub fn suggest(template: &str, fields: &BTreeMap<String, String>) -> Option<String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let end = start + rest[start..].find('}')?;
        out.push_str(&rest[..start]);
        out.push_str(fields.get(&rest[start + 1..end])?);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

pub fn run_plan(plan: &Path, keys: &Path, details: &Path) -> Result<Vec<(String, String)>, String> {
    run_plan_with(plan, keys, details, &Sealed::default())
}

pub fn run_plan_with(
    plan: &Path,
    keys: &Path,
    details: &Path,
    sealed: &Sealed,
) -> Result<Vec<(String, String)>, String> {
    let text = fs::read_to_string(plan).map_err(|e| format!("{}: {e}", plan.display()))?;
    let plan: Plan =
        serde_norway::from_str(&text).map_err(|e| format!("{}: {e}", plan.display()))?;
    let mut saved: BTreeMap<String, Details> = fs::read_to_string(details)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let mut lines = Vec::with_capacity(plan.keys.len());
    for entry in &plan.keys {
        let label = format!("{} [{}]", entry.file, entry.recipe);
        let result = inside_folder(&entry.file)
            .and_then(|()| resolve(&entry.recipe, entry.host.as_deref()))
            .and_then(|recipe| {
                let source = sealed.source(keys, &entry.file);
                if recipe.auth.kind.as_deref() == Some("ssh") {
                    let mut fields = BTreeMap::new();
                    if let ssh::Reply::Accepted(account) = source.greet(&recipe)? {
                        fields.insert("account".to_owned(), account);
                    }
                    return Ok((recipe, fields, None));
                }
                let key = source.load(entry.field.as_deref(), &recipe)?;
                if let Some(run) = &recipe.auth.run {
                    let answer =
                        script::run(&providers::programs_folder(), run, "identify", Some(&key))?;
                    let fields = program_fields(answer.fields, &recipe, &key);
                    return Ok((recipe, fields, Some(key)));
                }
                let mut transport = HttpTransport::for_recipe(&recipe);
                identify(&recipe, &key, &mut transport).map(|fields| (recipe, fields, Some(key)))
            });
        // The output says how much was found, and the values stay in the private file.
        match result {
            Ok((recipe, fields, key)) if !fields.is_empty() => {
                lines.push((label, format!("identified, {} fields", fields.len())));
                // Pieces that each pass the filter can spell the key once they are joined.
                let suggested_name = recipe
                    .suggested_name
                    .as_deref()
                    .and_then(|t| suggest(t, &fields))
                    .filter(|name| key.as_ref().is_none_or(|key| safe_value(name, key)));
                saved.insert(
                    entry.file.clone(),
                    Details {
                        at: now(),
                        provider: entry.recipe.clone(),
                        fields,
                        suggested_name,
                    },
                );
            }
            Ok(_) => lines.push((label, "the provider gave nothing to identify it".into())),
            Err(why) => {
                let shown = keys.join(&entry.file).display().to_string();
                let why = why
                    .strip_prefix(&format!("{shown}: "))
                    .map_or(why.clone(), str::to_owned);
                lines.push((label, format!("not identified ({why})")));
            }
        }
    }
    let text = serde_json::to_string_pretty(&saved).map_err(|e| e.to_string())?;
    write_private(details, &text).map_err(|e| e.to_string())?;
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Response, TransportError};

    struct Answer(u16, &'static str);

    impl Transport for Answer {
        fn send(&mut self, _request: &Request) -> Result<Response, TransportError> {
            Ok(Response {
                headers: Vec::new(),
                status: self.0,
                body: Secret::new(self.1),
            })
        }
    }

    fn recipe(name: &str) -> Recipe {
        crate::providers::load(name).unwrap()
    }

    #[test]
    fn keeps_only_the_declared_fields() {
        let mut answer = Answer(
            200,
            r#"{"login":"me","email":"me@x.com","name":null,"private_note":"CANARYnote","token":"CANARYtoken"}"#,
        );
        let fields = identify(&recipe("github"), &Secret::new("k"), &mut answer).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields["account"], "me");
        assert!(!format!("{fields:?}").contains("CANARY"));
    }

    #[test]
    fn drops_a_field_that_looks_like_a_credential_or_the_key() {
        let mut answer = Answer(
            200,
            r#"{"login":"ghp_CANARY0000000000000000","email":"mine-CANARYkey-x","name":"ok"}"#,
        );
        let fields = identify(&recipe("github"), &Secret::new("CANARYkey"), &mut answer).unwrap();
        assert_eq!(fields.keys().collect::<Vec<_>>(), ["name"]);
    }

    #[test]
    fn reads_scopes_from_a_header_and_a_token_answer() {
        struct WithHeader;
        impl Transport for WithHeader {
            fn send(&mut self, _: &Request) -> Result<Response, TransportError> {
                Ok(Response {
                    headers: vec![("x-oauth-scopes".into(), "repo, read:org".into())],
                    status: 200,
                    body: Secret::new(r#"{"login":"me"}"#),
                })
            }
        }
        let fields = identify(&recipe("github"), &Secret::new("k"), &mut WithHeader).unwrap();
        assert_eq!(fields["scopes"], "repo, read:org");

        struct Oauth(u32);
        impl Transport for Oauth {
            fn send(&mut self, _: &Request) -> Result<Response, TransportError> {
                self.0 += 1;
                let body = if self.0 == 1 {
                    r#"{"access_token":"CANARYtoken1234","scope":"email drive"}"#
                } else {
                    r#"{"email":"me@x.com","refresh_token":"CANARYother"}"#
                };
                Ok(Response {
                    headers: Vec::new(),
                    status: 200,
                    body: Secret::new(body),
                })
            }
        }
        let fields = identify(&recipe("google"), &Secret::new("a:b:c"), &mut Oauth(0)).unwrap();
        assert_eq!(fields["account"], "me@x.com");
        assert_eq!(fields["scopes"], "email drive");
        assert!(!format!("{fields:?}").contains("CANARY"));
    }

    #[test]
    fn reads_the_answer_from_aws() {
        let mut answer = Answer(
            200,
            "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123:user/u</Arn><Account>123</Account><SecretNote>CANARY</SecretNote></GetCallerIdentityResult></GetCallerIdentityResponse>",
        );
        let aws = recipe("aws");
        let fields = identify(&aws, &Secret::new("AKIAX:s3cretvalue"), &mut answer).unwrap();
        assert_eq!(fields["account"], "123");
        assert_eq!(fields["arn"], "arn:aws:iam::123:user/u");
        assert_eq!(
            suggest(aws.suggested_name.as_deref().unwrap(), &fields).unwrap(),
            "AWS · 123"
        );
    }

    #[test]
    fn an_error_does_not_quote_the_answer() {
        let mut bad = Answer(500, "CANARYbody");
        assert_eq!(
            identify(&recipe("github"), &Secret::new("k"), &mut bad).unwrap_err(),
            "HTTP 500"
        );
        let mut garbled = Answer(200, "CANARYbody");
        let error = identify(&recipe("github"), &Secret::new("k"), &mut garbled).unwrap_err();
        assert!(!error.contains("CANARY"));
    }

    #[test]
    fn a_suggestion_needs_every_field() {
        let mut fields = BTreeMap::new();
        fields.insert("account".to_owned(), "me".to_owned());
        assert_eq!(suggest("X · {account}", &fields).unwrap(), "X · me");
        assert_eq!(suggest("X · {missing}", &fields), None);
    }

    #[test]
    fn a_plan_keeps_earlier_results_and_stays_in_the_folder() {
        let dir = std::env::temp_dir().join(format!("keyreeve-identify-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let details = dir.join("private/details.json");
        fs::create_dir_all(details.parent().unwrap()).unwrap();
        fs::write(
            &details,
            r#"{"old.txt":{"at":1,"provider":"github","fields":{"account":"me"},"suggested_name":null}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("plan.yaml"),
            "keys: [{ file: ../outside.txt, recipe: github }]\n",
        )
        .unwrap();
        let lines = run_plan(&dir.join("plan.yaml"), &dir, &details).unwrap();
        assert!(lines[0].1.contains("inside the keys folder"));
        assert!(fs::read_to_string(&details).unwrap().contains("old.txt"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_key_used_as_a_field_name_is_dropped() {
        let key = Secret::new("CANARYkey1234567890");
        let named = ("CANARYkey1234567890".to_owned(), "account".to_owned());
        assert!(!safe_field(&named, &key));
        assert!(safe_field(&("account".to_owned(), "me".to_owned()), &key));
    }

    #[test]
    fn a_brace_in_an_answer_is_only_text() {
        let fields = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect()
        };
        assert_eq!(
            suggest("GitHub · {account}", &fields(&[("account", "{account}")])).as_deref(),
            Some("GitHub · {account}")
        );
        assert_eq!(
            suggest("{a}", &fields(&[("a", "x{b}"), ("b", "y")])).as_deref(),
            Some("x{b}")
        );
        assert_eq!(suggest("{missing}", &fields(&[])), None);
    }

    #[test]
    fn a_program_keeps_only_the_fields_its_file_declares() {
        let declared = Recipe::parse("schema: 1\nprovider: p\nhosts: []\nauth: { type: command, run: { program: p.sh } }\nidentify: { request: { method: GET, path: / }, fields: { account: \"reply:\" } }\n").unwrap();
        let bare = Recipe::parse(
            "schema: 1\nprovider: p\nhosts: []\nauth: { type: command, run: { program: p.sh } }\n",
        )
        .unwrap();
        let key = Secret::new("CANARYkey1234567890");
        let answer = || -> BTreeMap<String, String> {
            [("account", "me"), ("private_note", "other")]
                .into_iter()
                .map(|(a, b)| (a.to_owned(), b.to_owned()))
                .collect()
        };
        let kept = program_fields(answer(), &declared, &key);
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["account"]);
        assert!(program_fields(answer(), &bare, &key).is_empty());
    }
}
