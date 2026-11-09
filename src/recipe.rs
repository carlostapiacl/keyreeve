//! The recipe format: data only, with no code and no way to place a secret in a URL or body.

use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tested {
    pub check: Option<String>,
    pub rotate: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub schema: u32,
    pub provider: String,
    /// How people write the provider's name.
    pub name: Option<String>,
    /// Where a person manages this provider's keys.
    pub dashboard: Option<String>,
    /// Starts of keys that belong to this provider and no other.
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// How often a key like this should change, as a suggestion you can ignore.
    pub rotate_every_days: Option<u32>,
    /// How bad a leak usually is, from 1 to 5, until you rate the key yourself.
    pub criticality_hint: Option<u8>,
    /// Each person runs their own server, so its address comes with the key and needs approval.
    #[serde(default)]
    pub self_hosted: bool,
    pub hosts: Vec<String>,
    pub auth: Auth,
    /// Buttons of your own for this provider's keys, in the app.
    #[serde(default)]
    pub actions: Vec<CustomAction>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// `dual`, the default, keeps the old key working until it is revoked. `single` means creating the
    /// new key ends the old one at once, so it cannot be undone and has no `revoke`.
    pub rotation: Option<String>,
    /// The variable tools for this provider read their key from, such as `GH_TOKEN`.
    pub env_var: Option<String>,
    /// When this file was last tried against the real service, as `yyyy-mm`.
    pub tested: Option<Tested>,
    /// With `revoke`, lets the recipe rotate. A recipe without them only checks a key.
    pub create: Option<Step>,
    #[serde(default = "no_request")]
    pub verify: Step,
    pub revoke: Option<Step>,
    /// A read-only request that says whose key this is.
    pub identify: Option<Identify>,
    /// A name to offer, such as `GitHub · {account}`, using the fields of `identify`.
    pub suggested_name: Option<String>,
}

/// A program in the providers folder. See `script.rs`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustomRun {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// A button of your own: a page to open, or a program to run.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustomAction {
    pub id: String,
    pub label: String,
    pub label_es: Option<String>,
    pub open: Option<String>,
    pub run: Option<CustomRun>,
    /// The program receives the key on stdin, which asks for your fingerprint.
    #[serde(default)]
    pub needs_key: bool,
}

fn no_request() -> Step {
    Step {
        method: "GET".into(),
        path: "/".into(),
        host: None,
        body: None,
        expect: None,
        value_from: None,
        id_from: None,
        reject: Vec::new(),
        alive_if: None,
        reject_body: Vec::new(),
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identify {
    pub request: Step,
    /// `json`, the default, or `xml`.
    pub format: Option<String>,
    /// What to keep from the answer. Nothing else in it is stored.
    pub fields: BTreeMap<String, String>,
    /// More read-only requests, tried in order after the first. Each adds only fields not read
    /// yet, a path may name a field read before as `{name}`, and one that fails is skipped.
    #[serde(default)]
    pub also: Vec<Lookup>,
}

/// A further request of `identify`, such as one that says when the key expires.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lookup {
    pub request: Step,
    pub fields: BTreeMap<String, String>,
}

/// At most this many further requests, so identifying a key stays a handful of calls.
pub const MAX_LOOKUPS: usize = 3;

impl Identify {
    /// Every field this can keep, from the first request and the further ones.
    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields
            .keys()
            .chain(self.also.iter().flat_map(|lookup| lookup.fields.keys()))
            .map(String::as_str)
    }
}

/// The names a path asks for as `{name}`.
pub fn placeholders(path: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        found.push(&rest[start + 1..start + end]);
        rest = &rest[start + end + 1..];
    }
    found
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    /// Empty for the usual header. `aws_sigv4` signs each request instead of sending the key.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub prefix: String,
    pub service: Option<String>,
    pub region: Option<String>,
    /// `oauth_token`: `client_credentials` takes id and secret, `refresh_token` adds a refresh token.
    pub grant: Option<String>,
    pub token_host: Option<String>,
    pub token_path: Option<String>,
    /// Getting a token is enough to know the key works.
    #[serde(default)]
    pub token_is_proof: bool,
    /// `command`: a program of yours does the check. Only for your own files.
    pub run: Option<CustomRun>,
    /// `ssh`: the login name, and the text around the account in the server's greeting.
    pub user: Option<String>,
    pub reply_between: Option<Vec<String>>,
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
    /// Statuses a provider uses for a bad key, besides 401. Only in `verify`.
    #[serde(default)]
    pub reject: Vec<u16>,
    /// A refusal that still proves the key exists, such as a restricted key. Only in `verify`.
    pub alive_if: Option<AliveIf>,
    /// Texts that, in the body of an answer that would pass, mean the key was turned down: for a provider that
    /// answers 200 to a bad key and says so inside. Only in `verify`.
    #[serde(default)]
    pub reject_body: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliveIf {
    pub status: u16,
    pub contains: String,
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
        let url_key = self.auth.kind.as_deref() == Some("url");
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
        let is_command = self.auth.kind.as_deref() == Some("command");
        if !is_command && self.self_hosted != self.hosts.is_empty() {
            return fail(
                "a self_hosted recipe lists no hosts, and any other lists at least one".into(),
            );
        }
        if self
            .criticality_hint
            .is_some_and(|hint| !(1..=5).contains(&hint))
        {
            return fail("criticality_hint goes from 1 to 5".into());
        }
        if let Some(host) = self.hosts.iter().find(|host| !valid_host(host)) {
            return fail(format!(
                "host {host:?} must be a bare domain, with no scheme, port, path or wildcard"
            ));
        }
        match self.auth.kind.as_deref() {
            None if !valid_header_name(&self.auth.header)
                || FORBIDDEN_AUTH_HEADERS
                    .contains(&self.auth.header.to_ascii_lowercase().as_str()) =>
            {
                return fail(format!(
                    "auth.header {:?} cannot carry a credential",
                    self.auth.header
                ));
            }
            None => {}
            Some("aws_sigv4") => {
                if self.auth.service.is_none() || self.auth.region.is_none() {
                    return fail("aws_sigv4 needs auth.service and auth.region".into());
                }
                if self.create.is_some() {
                    return fail("a recipe with aws_sigv4 cannot rotate yet".into());
                }
            }
            Some("url") => {
                if self.create.is_some() {
                    return fail("a recipe that puts the key in the address cannot rotate".into());
                }
                if !self.verify.path.contains("{key}") {
                    return fail("auth type url needs {key} in verify.path".into());
                }
            }
            Some("basic") => {}
            Some("command") => {
                if self.auth.run.is_none() || self.create.is_some() {
                    return fail("auth type command needs run, and cannot use create".into());
                }
            }
            Some("oauth_token") => {
                let grant = self.auth.grant.as_deref();
                if !matches!(grant, Some("client_credentials" | "refresh_token")) {
                    return fail(
                        "oauth_token needs grant: client_credentials or refresh_token".into(),
                    );
                }
                let host_ok = self
                    .auth
                    .token_host
                    .as_ref()
                    .is_some_and(|h| self.hosts.contains(h));
                let path_ok = self
                    .auth
                    .token_path
                    .as_ref()
                    .is_some_and(|p| p.starts_with('/'));
                if !host_ok || !path_ok {
                    return fail(
                        "oauth_token needs a token_host listed in hosts, and a token_path".into(),
                    );
                }
            }
            Some("ssh") => {
                if self.auth.user.is_none() || self.hosts.len() != 1 || self.identify.is_none() {
                    return fail("ssh needs auth.user, one host and identify".into());
                }
                if self
                    .auth
                    .reply_between
                    .as_ref()
                    .is_none_or(|parts| parts.len() != 2)
                {
                    return fail("ssh needs reply_between with two texts".into());
                }
            }
            Some(other) => return fail(format!("unknown auth type {other:?}")),
        }
        for action in &self.actions {
            let id_ok = !action.id.is_empty()
                && action
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !id_ok || action.label.is_empty() || has_control(&action.label) {
                return fail(format!(
                    "action {:?} needs a lowercase id and a label",
                    action.id
                ));
            }
            if action.open.is_some() == action.run.is_some() {
                return fail(format!("action {} needs either open or run", action.id));
            }
            if action
                .open
                .as_ref()
                .is_some_and(|url| !url.starts_with("https://"))
            {
                return fail(format!("action {} must open an https address", action.id));
            }
        }
        if let Some(url) = &self.dashboard {
            if !url.starts_with("https://") || has_control(url) || url.contains(' ') {
                return fail("dashboard must be an https address".into());
            }
        }
        if self.prefixes.iter().any(|p| p.len() < 3 || has_control(p)) {
            return fail("a prefix needs at least 3 characters".into());
        }
        if let Some(identify) = &self.identify {
            let vars: &[&str] = if url_key { &["key"] } else { &[] };
            self.validate_step("identify", &identify.request, &["GET"], vars, false)?;
            match identify.format.as_deref() {
                None | Some("json") => {
                    if let Some((_, path)) = identify
                        .fields
                        .iter()
                        .find(|(_, path)| !valid_identify_source(path))
                    {
                        return fail(format!("identify field {path:?} must look like $.a.b"));
                    }
                }
                Some("xml") => {
                    let plain = |tag: &String| tag.bytes().all(|b| b.is_ascii_alphanumeric());
                    if !identify.fields.values().all(plain) {
                        return fail("an xml field is one tag name".into());
                    }
                }
                Some(other) => return fail(format!("unknown identify format {other:?}")),
            }
            if identify.fields.is_empty() {
                return fail("identify needs at least one field".into());
            }
            if identify.also.len() > MAX_LOOKUPS {
                return fail(format!(
                    "identify takes up to {MAX_LOOKUPS} further requests"
                ));
            }
            if !identify.also.is_empty() && identify.format.as_deref() == Some("xml") {
                return fail("identify.also needs a json answer".into());
            }
            let mut known: Vec<&str> = identify.fields.keys().map(String::as_str).collect();
            for (n, lookup) in identify.also.iter().enumerate() {
                let mut available = known.clone();
                if url_key {
                    available.push("key");
                }
                let name = format!("identify.also.{n}");
                self.validate_step(&name, &lookup.request, &["GET"], &available, false)?;
                if lookup.fields.is_empty() {
                    return fail(format!("{name} needs at least one field"));
                }
                if let Some(path) = lookup.fields.values().find(|path| {
                    path.starts_with("token:") || path == &"reply:" || !valid_identify_source(path)
                }) {
                    return fail(format!("{name}: field {path:?} must look like $.a.b"));
                }
                known.extend(lookup.fields.keys().map(String::as_str));
            }
        }
        if let Some(template) = &self.suggested_name {
            let available: Vec<&str> = self
                .identify
                .iter()
                .flat_map(|identify| identify.field_names())
                .collect();
            check_placeholders(template, &available).map_err(RecipeError)?;
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

        let verify_vars: &[&str] = if url_key { &["id", "key"] } else { &["id"] };
        self.validate_step("verify", &self.verify, &["GET", "POST"], verify_vars, false)?;
        if let Some(alive) = &self.verify.alive_if {
            if !(400..=499).contains(&alive.status) || alive.contains.is_empty() {
                return fail("alive_if needs a 4xx status and a text".into());
            }
        }
        if let Some(status) = self
            .verify
            .reject
            .iter()
            .find(|s| !(400..=499).contains(*s))
        {
            return fail(format!("verify: reject {status} must be a 4xx status"));
        }
        // A short text could be in any answer, and a long list is a guess.
        if self.verify.reject_body.len() > 8
            || self
                .verify
                .reject_body
                .iter()
                .any(|text| text.trim().len() < 6 || text.len() > 200)
        {
            return fail("verify: reject_body takes up to 8 texts of 6 to 200 characters".into());
        }
        if !matches!(
            self.rotation.as_deref(),
            None | Some("dual") | Some("single")
        ) {
            return fail("rotation must be dual or single".into());
        }
        if let Some(tested) = &self.tested {
            for date in [&tested.check, &tested.rotate].into_iter().flatten() {
                let (year, month) = date.split_once('-').unwrap_or(("", ""));
                let digits = |part: &str, size: usize| {
                    part.len() == size && part.bytes().all(|b| b.is_ascii_digit())
                };
                if !digits(year, 4) || !digits(month, 2) {
                    return fail(format!("tested: {date} must be yyyy-mm"));
                }
            }
        }
        if self.is_single() {
            let Some(create) = &self.create else {
                return fail("a single rotation needs create".into());
            };
            if self.revoke.is_some() {
                return fail(
                    "a single rotation ends the old key by itself, so it has no revoke".into(),
                );
            }
            if create.id_from.is_some() && create.value_from.as_deref() == create.id_from.as_deref()
            {
                return fail("create.value_from and create.id_from must differ".into());
            }
            return self.validate_step("create", create, &["POST", "PUT"], &["key_name"], true);
        }
        if self.create.is_some() != self.revoke.is_some() {
            return fail("create and revoke go together, or a key could never be removed".into());
        }
        let (Some(create), Some(revoke)) = (&self.create, &self.revoke) else {
            if self.verify.path.contains("{id}") {
                return fail("verify cannot use {id} in a recipe without create".into());
            }
            return Ok(());
        };
        self.validate_step("create", create, &["POST", "PUT"], &["key_name"], true)?;
        self.validate_step(
            "revoke",
            revoke,
            &["DELETE", "POST", "PUT", "PATCH"],
            &["id"],
            false,
        )?;
        if !create.reject.is_empty()
            || !revoke.reject.is_empty()
            || !create.reject_body.is_empty()
            || !revoke.reject_body.is_empty()
        {
            return fail("reject only belongs in verify".into());
        }
        if create.value_from.as_deref() == create.id_from.as_deref() {
            return fail("create.value_from and create.id_from must differ".into());
        }
        let revoke_names_id = revoke.path.contains("{id}")
            || revoke
                .body
                .as_ref()
                .is_some_and(|body| body.to_string().contains("{id}"));
        if !revoke_names_id {
            return fail("revoke must use {id}, or it cannot say which key to revoke".into());
        }
        Ok(())
    }

    /// The same recipe, pointed at one person's server.
    pub fn at_host(&self, host: &str) -> Self {
        let mut recipe = self.clone();
        recipe.hosts = vec![host.to_owned()];
        recipe
    }

    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.provider)
    }

    /// True if this file makes keyreeve run a program, which a file that ships may never do.
    pub fn runs_code(&self) -> bool {
        self.auth.run.is_some() || self.actions.iter().any(|action| action.run.is_some())
    }

    pub fn can_rotate(&self) -> bool {
        self.create.is_some() && (self.revoke.is_some() || self.is_single())
    }

    pub fn is_single(&self) -> bool {
        self.rotation.as_deref() == Some("single")
    }

    /// A person can make the new key at the provider's page and hand it over, if this file can test
    /// it with one plain request. Tokens, programs and ssh need steps the rotation does not take.
    pub fn can_rotate_by_hand(&self) -> bool {
        !self.can_rotate()
            && !self.verify.path.is_empty()
            && self.verify.method == "GET"
            && !matches!(
                self.auth.kind.as_deref(),
                Some("oauth_token") | Some("ssh") | Some("command") | Some("aws_sigv4")
            )
            && self.auth.run.is_none()
    }

    /// Only for recipes where `can_rotate` is true, which the engine checks first.
    pub fn create_step(&self) -> &Step {
        self.create.as_ref().expect("the recipe can rotate")
    }

    /// Only for recipes where `can_rotate` is true, which the engine checks first.
    pub fn revoke_step(&self) -> &Step {
        self.revoke.as_ref().expect("the recipe can rotate")
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
                    // Nothing gets revoked by id in a single rotation, and some answers hold none.
                    None if field == "id_from" && self.is_single() => {}
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
            host: self
                .host
                .clone()
                .or_else(|| recipe.hosts.first().cloned())
                .unwrap_or_default(),
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
            Value::Array(items) => {
                // One spelling per place, so two different paths cannot name the same value.
                let index = segment.parse::<usize>().ok()?;
                if index.to_string() != segment {
                    return None;
                }
                items.get(index)?
            }
            _ => return None,
        };
    }
    match current {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Every value a path with `*` reaches, such as `$.*.slug` for each organization in a list, joined
/// with ", " in the order of the answer and without repeats. Only `identify` reads paths like this:
/// a key or an id taken from a list could be the wrong one.
pub fn extract_all(json: &Value, path: &str) -> Option<String> {
    fn walk<'a>(value: &'a Value, segments: &[&str], found: &mut Vec<&'a Value>) {
        let Some((segment, rest)) = segments.split_first() else {
            found.push(value);
            return;
        };
        match (value, *segment) {
            (Value::Array(items), "*") => items.iter().for_each(|item| walk(item, rest, found)),
            (Value::Object(map), name) => {
                if let Some(next) = map.get(name) {
                    walk(next, rest, found);
                }
            }
            (Value::Array(items), index) => {
                if let Some(next) = index
                    .parse::<usize>()
                    .ok()
                    .filter(|i| i.to_string() == index)
                    .and_then(|i| items.get(i))
                {
                    walk(next, rest, found);
                }
            }
            _ => {}
        }
    }
    let segments: Vec<&str> = path.strip_prefix("$.")?.split('.').collect();
    let mut found = Vec::new();
    walk(json, &segments, &mut found);
    let mut values: Vec<String> = Vec::new();
    for value in found {
        let text = match value {
            Value::String(text) if !text.is_empty() => text.clone(),
            Value::Number(number) => number.to_string(),
            _ => continue,
        };
        if !values.contains(&text) && values.len() < 20 {
            values.push(text);
        }
    }
    (!values.is_empty()).then(|| values.join(", "))
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

/// Where a field of `identify` comes from: the answer, a header, the token answer or a greeting.
fn valid_identify_source(path: &str) -> bool {
    let named = ["header:", "token:"].iter().any(|prefix| {
        path.strip_prefix(prefix).is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
    });
    named || path == "reply:" || valid_json_path(&path.replace(".*", ".0"))
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
            .revoke_step()
            .render(&recipe, &[("id", "../../admin?x=@evil.org")]);
        assert_eq!(rendered.path, "/v1/keys/..%2F..%2Fadmin%3Fx%3D%40evil.org");
        assert_eq!(rendered.host, "api.example.com");
    }

    #[test]
    fn a_recipe_can_only_check_a_key() {
        let text = "schema: 1\nprovider: x\nhosts: [api.x.com]\nauth: { header: Authorization }\nverify: { method: GET, path: /me, reject: [400] }\n";
        let recipe = Recipe::parse(text).unwrap();
        assert!(!recipe.can_rotate());
        assert!(Recipe::parse(&text.replace("/me", "/k/{id}")).is_err());
        assert!(Recipe::parse(&text.replace("[400]", "[500]")).is_err());
        let half = format!("{text}revoke: {{ method: DELETE, path: \"/k/{{id}}\" }}\n");
        assert!(Recipe::parse(&half).unwrap_err().0.contains("go together"));
    }

    #[test]
    fn a_provider_file_is_checked_too() {
        let base = "schema: 1\nprovider: x\nhosts: [api.x.com]\nauth: { header: A }\nverify: { method: GET, path: /me }\n";
        let with = |extra: &str| Recipe::parse(&format!("{base}{extra}"));
        assert!(with("dashboard: http://x.com\n").is_err());
        assert!(with("prefixes: [x]\n").is_err());
        assert!(
            with("identify: { request: { method: POST, path: /me }, fields: { a: $.a } }\n")
                .is_err()
        );
        assert!(with("identify: { request: { method: GET, path: /me }, fields: {} }\n").is_err());
        assert!(with(
            "identify: { request: { method: GET, path: /me }, fields: { a: not-a-path } }\n"
        )
        .is_err());
        assert!(with("suggested_name: \"X {account}\"\n").is_err());
        let good = with(
            "name: X\ndashboard: https://x.com/keys\nprefixes: [xk_]\nidentify: { request: { method: GET, path: /me }, fields: { account: $.a } }\nsuggested_name: \"X · {account}\"\n",
        )
        .unwrap();
        assert_eq!(good.display_name(), "X");
        assert!(Recipe::parse(&base.replace("{ header: A }", "{ type: magic }")).is_err());
        assert!(Recipe::parse(&base.replace("{ header: A }", "{ type: aws_sigv4 }")).is_err());
    }

    #[test]
    fn further_identify_requests_are_checked() {
        let base = "schema: 1\nprovider: x\nhosts: [api.x.com]\nauth: { header: A }\nverify: { method: GET, path: /me }\nidentify:\n  request: { method: GET, path: /me }\n  fields: { id: $.id }\n  also:\n";
        let with = |also: &str| Recipe::parse(&format!("{base}{also}"));
        let good = with("    - request: { method: GET, path: \"/a/{id}/t\" }\n      fields: { expires: $.r.e }\nsuggested_name: \"X {expires}\"\n");
        assert!(good.is_ok(), "{good:?}");
        // Only a GET, only a field read before, only a json path, and only a few.
        assert!(
            with("    - request: { method: POST, path: /t }\n      fields: { e: $.e }\n").is_err()
        );
        assert!(with(
            "    - request: { method: GET, path: \"/a/{nope}\" }\n      fields: { e: $.e }\n"
        )
        .is_err());
        assert!(with(
            "    - request: { method: GET, path: /t }\n      fields: { e: \"token:x\" }\n"
        )
        .is_err());
        assert!(with("    - request: { method: GET, path: /t }\n      fields: {}\n").is_err());
        let four = "    - request: { method: GET, path: /t }\n      fields: { e: $.e }\n".repeat(4);
        assert!(with(&four).unwrap_err().0.contains("up to 3"));
        // A field read by an earlier further request is there for a later one.
        let chained = "    - request: { method: GET, path: /t }\n      fields: { org: $.o }\n    - request: { method: GET, path: \"/o/{org}\" }\n      fields: { e: $.e }\n";
        assert!(with(chained).is_ok());
    }

    #[test]
    fn rotation_modes_and_dates_are_checked() {
        let base = "schema: 1\nprovider: p\nhosts: [a.example.com]\nauth: { header: A }\nverify: { method: GET, path: /m }\n";
        let create = "create: { method: POST, path: /r, value_from: $.k }\n";
        let revoke = "revoke: { method: DELETE, path: \"/k/{id}\" }\n";
        assert!(Recipe::parse(&format!("{base}rotation: single\n{create}"))
            .unwrap()
            .can_rotate());
        assert!(Recipe::parse(&format!("{base}rotation: single\n")).is_err());
        assert!(Recipe::parse(&format!("{base}rotation: single\n{create}{revoke}")).is_err());
        assert!(Recipe::parse(&format!("{base}rotation: weird\n")).is_err());
        assert!(
            Recipe::parse(&format!("{base}{create}{revoke}")).is_err(),
            "dual needs an id"
        );
        assert!(Recipe::parse(&format!("{base}tested: {{ check: 2026-11 }}\n")).is_ok());
        assert!(Recipe::parse(&format!("{base}tested: {{ check: soon }}\n")).is_err());
        let by_hand = Recipe::parse(base).unwrap();
        assert!(by_hand.can_rotate_by_hand());
        let oauth = base.replace("{ header: A }", "{ type: ssh, user: git }");
        if let Ok(recipe) = Recipe::parse(&oauth) {
            assert!(!recipe.can_rotate_by_hand());
        }
    }

    #[test]
    fn extracts_nested_values() {
        let json: Value = serde_json::json!({"data": {"id": 7, "secret": "s", "list": ["a"]}});
        assert_eq!(extract(&json, "$.data.id").as_deref(), Some("7"));
        assert_eq!(extract(&json, "$.data.list.0").as_deref(), Some("a"));
        assert_eq!(extract(&json, "$.data.missing"), None);
        assert_eq!(extract(&json, "$.data.list.00"), None);
        let orgs = serde_json::json!([{"slug": "acme"}, {"slug": "jane-doe"}, {"slug": "acme"}, {"name": "x"}]);
        assert_eq!(
            extract_all(&orgs, "$.*.slug").as_deref(),
            Some("acme, jane-doe")
        );
        assert_eq!(extract_all(&orgs, "$.0.slug").as_deref(), Some("acme"));
        assert_eq!(extract_all(&orgs, "$.*.missing"), None);
        assert_eq!(extract(&orgs, "$.*.slug"), None);
    }
}
