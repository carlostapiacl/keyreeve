//! Asks a provider whose key this is. Only the fields a provider's file declares are kept, and
//! anything that looks like a credential is dropped, so the rest of the answer never lands on disk.

use crate::inventory::{kind_of, write_private};
use crate::providers;
use crate::recipe::{extract, Recipe};
use crate::secret::Secret;
use crate::transport::{HttpTransport, Request, Transport};
use crate::verify::{inside_folder, load_key, now, Plan};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MAX_FIELD_CHARS: usize = 200;

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
    let request = Request::for_step(recipe, &identify.request, &[], key);
    let response = transport.send(&request).map_err(|e| e.to_string())?;
    if !identify.request.accepts(response.status) {
        return Err(format!("HTTP {}", response.status));
    }
    let body = response.body.expose();
    let json = match identify.format.as_deref() {
        Some("xml") => None,
        _ => Some(
            serde_json::from_str::<serde_json::Value>(body)
                .map_err(|_| "the answer could not be read".to_owned())?,
        ),
    };
    let read = |path: &str| match &json {
        Some(json) => extract(json, path),
        None => xml_tag(body, path),
    };
    let mut fields = BTreeMap::new();
    for (name, path) in &identify.fields {
        if let Some(value) = read(path) {
            if safe_value(&value, key) {
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
    let is_key_itself = key
        .expose()
        .split(':')
        .any(|part| !part.is_empty() && value.contains(part));
    !value.is_empty()
        && value.chars().count() <= MAX_FIELD_CHARS
        && !value.chars().any(char::is_control)
        && !is_key_itself
        && value
            .split_whitespace()
            .all(|word| word.len() < 16 || kind_of(word).is_none())
}

/// Fills `{field}`. With a field missing there is nothing to suggest.
pub fn suggest(template: &str, fields: &BTreeMap<String, String>) -> Option<String> {
    let mut out = template.to_owned();
    while let Some(start) = out.find('{') {
        let end = start + out[start..].find('}')?;
        let value = fields.get(&out[start + 1..end])?;
        out.replace_range(start..=end, value);
    }
    Some(out)
}

pub fn run_plan(plan: &Path, keys: &Path, details: &Path) -> Result<Vec<(String, String)>, String> {
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
            .and_then(|()| providers::load(&entry.recipe))
            .and_then(|recipe| {
                let key = load_key(&keys.join(&entry.file), entry.field.as_deref())?;
                let mut transport = HttpTransport::for_recipe(&recipe);
                identify(&recipe, &key, &mut transport).map(|fields| (recipe, fields))
            });
        // The output says how much was found, and the values stay in the private file.
        match result {
            Ok((recipe, fields)) if !fields.is_empty() => {
                lines.push((label, format!("identified, {} fields", fields.len())));
                let suggested_name = recipe
                    .suggested_name
                    .as_deref()
                    .and_then(|t| suggest(t, &fields));
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
                status: self.0,
                body: Secret::new(self.1),
            })
        }
    }

    fn recipe(name: &str) -> Recipe {
        providers::load(name).unwrap()
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
}
