//! The recipe format: data only, with no code and no way to place a secret in a URL or body.

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

const MAX_RECIPE_BYTES: usize = 64 * 1024;
const FORBIDDEN_HEADERS: &[&str] = &[
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "transfer-encoding",
];

#[derive(Debug)]
pub struct RecipeError(pub String);

impl fmt::Display for RecipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RecipeError {}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub schema: u32,
    pub provider: String,
    pub hosts: Vec<String>,
    pub auth: Auth,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub create: Step,
    pub verify: Step,
    pub revoke: Step,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub header: String,
    #[serde(default)]
    pub prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub body: Option<Value>,
    pub expect: Option<u16>,
    pub value_from: Option<String>,
    pub id_from: Option<String>,
}

/// A request ready to send, with its placeholders filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub method: String,
    pub host: String,
    pub path: String,
    pub body: Option<Vec<u8>>,
}

impl Recipe {
    pub fn parse(text: &str) -> Result<Self, RecipeError> {
        if text.len() > MAX_RECIPE_BYTES {
            return Err(RecipeError(format!(
                "recipe is larger than {MAX_RECIPE_BYTES} bytes"
            )));
        }
        let recipe: Recipe =
            serde_norway::from_str(text).map_err(|e| RecipeError(e.to_string()))?;
        recipe.validate()?;
        Ok(recipe)
    }

    fn validate(&self) -> Result<(), RecipeError> {
        let fail = |message: String| Err(RecipeError(message));
        if self.schema != 1 {
            return fail(format!("unknown schema {}, expected 1", self.schema));
        }
        let name_ok = !self.provider.is_empty()
            && self
                .provider
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !name_ok {
            return fail("provider must use lowercase letters, digits and hyphens".into());
        }
        if self.hosts.is_empty() {
            return fail("hosts must list at least one host".into());
        }
        if let Some(host) = self.hosts.iter().find(|host| !valid_host(host)) {
            return fail(format!(
                "host {host:?} must be a bare domain, with no scheme, port, path or wildcard"
            ));
        }
        if !valid_header_name(&self.auth.header)
            || FORBIDDEN_AUTH_HEADERS.contains(&self.auth.header.to_ascii_lowercase().as_str())
        {
            return fail(format!(
                "auth.header {:?} cannot carry a credential",
                self.auth.header
            ));
        }
        if has_control(&self.auth.prefix) {
            return fail("auth.prefix contains a control character".into());
        }
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            if !valid_header_name(name)
                || FORBIDDEN_HEADERS.contains(&lower.as_str())
                || lower == self.auth.header.to_ascii_lowercase()
            {
                return fail(format!("header {name:?} is not allowed"));
            }
            if has_control(value) {
                return fail(format!("header {name:?} contains a control character"));
            }
        }

        self.validate_step(
            "create",
            &self.create,
            &["POST", "PUT"],
            &["key_name"],
            true,
        )?;
        self.validate_step("verify", &self.verify, &["GET", "POST"], &["id"], false)?;
        self.validate_step(
            "revoke",
            &self.revoke,
            &["DELETE", "POST", "PUT", "PATCH"],
            &["id"],
            false,
        )?;

        let value_from = self.create.value_from.as_deref();
        if value_from == self.create.id_from.as_deref() {
            return fail("create.value_from and create.id_from must differ".into());
        }
        let revoke_names_id = self.revoke.path.contains("{id}")
            || self
                .revoke
                .body
                .as_ref()
                .is_some_and(|body| body.to_string().contains("{id}"));
        if !revoke_names_id {
            return fail("revoke must use {id}, or it cannot say which key to revoke".into());
        }
        Ok(())
    }

    fn validate_step(
        &self,
        name: &str,
        step: &Step,
        methods: &[&str],
        placeholders: &[&str],
        is_create: bool,
    ) -> Result<(), RecipeError> {
        let fail = |message: String| Err(RecipeError(format!("{name}: {message}")));
        if !methods.contains(&step.method.as_str()) {
            return fail(format!(
                "method {:?} is not allowed here, use one of {methods:?}",
                step.method
            ));
        }
        if !step.path.starts_with('/')
            || step.path.starts_with("//")
            || step.path.contains("..")
            || step.path.contains('\\')
            || step.path.contains('#')
            || step
                .path
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return fail(format!("path {:?} is not a clean absolute path", step.path));
        }
        if self.hosts.len() > 1 && step.host.is_none() {
            return fail("host is required when the recipe lists several hosts".into());
        }
        if let Some(host) = &step.host {
            if !self.hosts.contains(host) {
                return fail(format!("host {host:?} is not listed in hosts"));
            }
        }
        if let Some(status) = step.expect {
            if !(200..=299).contains(&status) {
                return fail(format!("expect {status} must be a 2xx status"));
            }
        }
        if step.body.is_some() && !matches!(step.method.as_str(), "POST" | "PUT" | "PATCH") {
            return fail(format!("a {} request cannot carry a body", step.method));
        }
        check_placeholders(&step.path, placeholders)
            .map_err(|message| RecipeError(format!("{name}: {message}")))?;
        if let Some(body) = &step.body {
            check_body_placeholders(body, placeholders)
                .map_err(|message| RecipeError(format!("{name}: {message}")))?;
        }
        if is_create {
            for (field, value) in [("value_from", &step.value_from), ("id_from", &step.id_from)] {
                match value {
                    Some(path) if valid_json_path(path) => {}
                    Some(path) => return fail(format!("{field} {path:?} must look like $.a.b")),
                    None => return fail(format!("{field} is required")),
                }
            }
        } else if step.value_from.is_some() || step.id_from.is_some() {
            return fail("value_from and id_from only belong in create".into());
        }
        Ok(())
    }
}

const FORBIDDEN_AUTH_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "cookie",
    "host",
    "transfer-encoding",
];

impl Step {
    /// Fills `{name}` placeholders. Values are percent-encoded in paths, so an id returned
    /// by a provider cannot change which path or host a request reaches.
    pub fn render(&self, recipe: &Recipe, vars: &[(&str, &str)]) -> Rendered {
        let mut path = self.path.clone();
        for (name, value) in vars {
            path = path.replace(&format!("{{{name}}}"), &percent_encode(value));
        }
        let body = self.body.as_ref().map(|body| {
            serde_json::to_vec(&fill_strings(body, vars)).expect("a JSON value always serializes")
        });
        Rendered {
            method: self.method.clone(),
            host: self.host.clone().unwrap_or_else(|| recipe.hosts[0].clone()),
            path,
            body,
        }
    }

    pub fn accepts(&self, status: u16) -> bool {
        match self.expect {
            Some(expected) => status == expected,
            None => (200..=299).contains(&status),
        }
    }
}

/// Reads a non-empty string or a number from JSON by a `$.a.0.b` path.
pub fn extract(json: &Value, path: &str) -> Option<String> {
    let mut current = json;
    for segment in path.split('.').skip(1) {
        current = match current {
            Value::Object(map) => map.get(segment)?,
            Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    match current {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn fill_strings(value: &Value, vars: &[(&str, &str)]) -> Value {
    match value {
        Value::String(text) => {
            let mut out = text.clone();
            for (name, replacement) in vars {
                out = out.replace(&format!("{{{name}}}"), replacement);
            }
            Value::String(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(|v| fill_strings(v, vars)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, v)| (key.clone(), fill_strings(v, vars)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn check_placeholders(text: &str, allowed: &[&str]) -> Result<(), String> {
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            return Err(format!("unclosed placeholder in {text:?}"));
        };
        let name = &rest[start + 1..start + end];
        if !allowed.contains(&name) {
            return Err(format!(
                "placeholder {{{name}}} is not available here, only {allowed:?}"
            ));
        }
        rest = &rest[start + end + 1..];
    }
    if rest.contains('}') {
        return Err(format!("unopened placeholder in {text:?}"));
    }
    Ok(())
}

fn check_body_placeholders(value: &Value, allowed: &[&str]) -> Result<(), String> {
    match value {
        Value::String(text) => check_placeholders(text, allowed),
        Value::Array(items) => items
            .iter()
            .try_for_each(|item| check_body_placeholders(item, allowed)),
        Value::Object(map) => map
            .values()
            .try_for_each(|item| check_body_placeholders(item, allowed)),
        _ => Ok(()),
    }
}

fn percent_encode(value: &str) -> String {
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

fn valid_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

fn valid_json_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("$.") else {
        return false;
    };
    rest.split('.').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
schema: 1
provider: example
hosts: [api.example.com]
auth: { header: Authorization, prefix: "Bearer " }
create:
  method: POST
  path: /v1/keys
  body: { name: "{key_name}" }
  value_from: $.data.secret
  id_from: $.data.id
verify: { method: GET, path: /v1/me }
revoke: { method: DELETE, path: "/v1/keys/{id}" }
"#;

    fn rejects(from: &str, to: &str, expected: &str) {
        assert!(GOOD.contains(from), "the test does not change {from:?}");
        let error = Recipe::parse(&GOOD.replace(from, to)).unwrap_err().0;
        assert!(error.contains(expected), "got: {error}");
    }

    #[test]
    fn accepts_a_good_recipe() {
        assert_eq!(Recipe::parse(GOOD).unwrap().provider, "example");
    }

    #[test]
    fn rejects_hosts_that_could_mislead() {
        for host in [
            "https://api.example.com",
            "api.example.com:8443",
            "*.example.com",
            "evil.com/api.example.com",
            "user@api.example.com",
            "127.0.0.1",
            "localhost",
        ] {
            rejects("[api.example.com]", &format!("[\"{host}\"]"), "bare domain");
        }
    }

    #[test]
    fn a_step_cannot_leave_the_declared_hosts() {
        rejects(
            "verify: { method: GET,",
            "verify: { host: evil.example.org, method: GET,",
            "not listed",
        );
        rejects(
            "path: /v1/me",
            "path: //evil.example.org/x",
            "clean absolute",
        );
        rejects("path: /v1/me", "path: /v1/../me", "clean absolute");
    }

    #[test]
    fn a_secret_has_no_placeholder() {
        rejects("path: /v1/me", "path: \"/v1/{value}\"", "not available");
        rejects("{key_name}", "{admin}", "not available");
    }

    #[test]
    fn unknown_fields_and_extra_commands_are_refused() {
        rejects("schema: 1", "schema: 1\nrun: curl evil", "unknown field");
    }

    #[test]
    fn redirects_cannot_be_expected() {
        rejects(
            "verify: { method: GET,",
            "verify: { expect: 302, method: GET,",
            "2xx",
        );
    }

    #[test]
    fn headers_cannot_replace_the_credential() {
        rejects(
            "schema: 1",
            "schema: 1\nheaders: { Cookie: a }",
            "not allowed",
        );
        rejects(
            "schema: 1",
            "schema: 1\nheaders: { authorization: a }",
            "not allowed",
        );
    }

    #[test]
    fn revoke_must_name_a_key() {
        rejects("\"/v1/keys/{id}\"", "/v1/keys/all", "must use {id}");
    }

    #[test]
    fn a_returned_id_cannot_escape_the_path() {
        let recipe = Recipe::parse(GOOD).unwrap();
        let rendered = recipe
            .revoke
            .render(&recipe, &[("id", "../../admin?x=@evil.org")]);
        assert_eq!(rendered.path, "/v1/keys/..%2F..%2Fadmin%3Fx%3D%40evil.org");
        assert_eq!(rendered.host, "api.example.com");
    }

    #[test]
    fn extracts_nested_values() {
        let json: Value = serde_json::json!({"data": {"id": 7, "secret": "s", "list": ["a"]}});
        assert_eq!(extract(&json, "$.data.id").as_deref(), Some("7"));
        assert_eq!(extract(&json, "$.data.list.0").as_deref(), Some("a"));
        assert_eq!(extract(&json, "$.data.missing"), None);
    }
}
