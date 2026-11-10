//! Says what each piece is, puts the parts of one key together, and names the providers that could
//! check it. Everything here reads values in memory and returns words about them, never the values.

use super::read::{Piece, WholeFile};
use crate::inventory::kind_of;
use crate::providers;
use crate::recipe::Recipe;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// A secret that opens something: an API key, a token, a private key.
    Key,
    /// A setting: an id, an address, a region, a name.
    Configuration,
    /// A user name with a password.
    Login,
    /// Notes or a file with nothing to name in it.
    Document,
    /// Made to be seen: a public key, a certificate, a key bundled into a web page.
    Public,
}

/// Names that ship to a browser. What they hold is public, whatever it is called.
const PUBLIC_STARTS: &[&str] = &[
    "NEXT_PUBLIC_",
    "VITE_",
    "EXPO_PUBLIC_",
    "REACT_APP_",
    "GATSBY_",
    "NUXT_PUBLIC_",
    "PUBLIC_",
];

const LOGIN_WORDS: &[&str] = &[
    "password",
    "pass",
    "passwd",
    "pwd",
    "contrasena",
    "contraseña",
    "senha",
    "passwort",
];

/// A last word that makes a name a setting, as in `CLIENT_ID` or `TOKEN_URL`.
const SETTING_ENDS: &[&str] = &[
    "id", "url", "uri", "host", "hostname", "port", "region", "name", "user", "username", "login",
    "email", "domain", "endpoint", "path", "file", "dir", "type", "version", "account", "project",
    "org", "bucket", "zone", "mode", "env", "level", "timeout", "scope", "scopes", "audience",
    "issuer", "location", "output", "format", "expires", "expiry", "ttl",
];

const SECRET_WORDS: &[&str] = &[
    "key",
    "token",
    "secret",
    "auth",
    "credential",
    "credentials",
    "private",
    "pat",
    "apikey",
    "signing",
    "webhook",
    "bearer",
    "session",
    "cookie",
    "salt",
    "jwt",
    "dsn",
    "access",
    "refresh",
    "passphrase",
    "otp",
    "totp",
];

/// The words of a name: `OPENAI_API_KEY`, `openai-api-key` and `openaiApiKey` give the same three.
pub fn words(name: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        let breaks = !c.is_alphanumeric() || (c.is_uppercase() && previous_lower);
        if breaks && !word.is_empty() {
            found.push(std::mem::take(&mut word));
        }
        if c.is_alphanumeric() {
            word.extend(c.to_lowercase());
        }
        previous_lower = c.is_lowercase();
    }
    if !word.is_empty() {
        found.push(word);
    }
    found
}

/// A value that stands for another, such as `$HOME` or `${TOKEN}`, is not a key of its own.
fn is_reference(value: &str) -> bool {
    value.starts_with('$') || value.contains("${") || value.contains("$(") || value.contains('`')
}

/// What a file says before someone puts the real key in.
fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    let same_char = value.chars().all(|c| value.starts_with(c));
    same_char
        || lower.starts_with("your")
        || lower.starts_with('<')
        || lower.contains("xxxx")
        || lower.contains("changeme")
        || lower.contains("change_me")
        || lower.contains("replace")
        || lower.contains("placeholder")
        || lower.contains("...")
        || matches!(lower.as_str(), "todo" | "none" | "null" | "nil" | "secret")
}

/// Mixed letters and digits, long, with no spaces: read as a key when nothing else says what it is.
pub fn looks_random(value: &str) -> bool {
    let allowed = value.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | '/' | '=' | ':' | '~')
    });
    let upper = value.bytes().any(|b| b.is_ascii_uppercase());
    let lower = value.bytes().any(|b| b.is_ascii_lowercase());
    let digit = value.bytes().any(|b| b.is_ascii_digit());
    let classes = [upper, lower, digit].iter().filter(|on| **on).count();
    value.len() >= 16 && allowed && !value.contains("://") && classes >= 2 && (digit || upper)
}

/// What a piece is, and why, in a few words. `None` leaves it out: an empty value, a placeholder,
/// or a value that only points at another.
pub fn classify(piece: &Piece, file_words: &[String]) -> Option<(Class, &'static str)> {
    if let Some(whole) = piece.whole {
        return Some(match whole {
            WholeFile::PrivateKey => (Class::Key, "a private key"),
            WholeFile::Keystore => (Class::Key, "a keystore"),
            WholeFile::PublicKey => (Class::Public, "a public key"),
            WholeFile::Certificate => (Class::Public, "a certificate"),
            WholeFile::Document => (Class::Document, "notes, with no value to name"),
            WholeFile::TooLarge => (Class::Document, "too large for a file of keys"),
        });
    }
    let value = piece.value.trim();
    if value.is_empty() || is_reference(value) || is_placeholder(value) {
        return None;
    }
    let label = piece.label.as_str();
    let mut name_words = words(label);
    if name_words.is_empty() {
        name_words = file_words.to_vec();
    }
    let has = |list: &[&str]| name_words.iter().any(|w| list.contains(&w.as_str()));
    let upper = label.to_ascii_uppercase();
    if value.len() >= 16 && kind_of(value).is_some_and(|kind| kind != "jwt") {
        return Some((Class::Key, "starts as a provider's keys do"));
    }
    let public_name = PUBLIC_STARTS.iter().any(|start| upper.starts_with(start))
        || name_words.iter().any(|w| w == "publishable" || w == "anon")
        || (has(&["public"]) && has(&["key"]));
    if public_name || value.starts_with("pk_live_") || value.starts_with("pk_test_") {
        return Some((Class::Public, "made to be seen in a web page"));
    }
    if let Some((_, rest)) = value.split_once("://") {
        let userinfo = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if userinfo
            .split_once('@')
            .is_some_and(|(user, _)| user.contains(':'))
        {
            return Some((Class::Key, "an address with a password in it"));
        }
        return Some((Class::Configuration, "an address"));
    }
    if label == "auth" && piece.server.is_some() {
        return Some((Class::Login, "a registry login"));
    }
    if has(LOGIN_WORDS) {
        return Some((Class::Login, "a password"));
    }
    let last = name_words.last().map(String::as_str).unwrap_or_default();
    if SETTING_ENDS.contains(&last) {
        return Some((Class::Configuration, "a setting"));
    }
    if has(SECRET_WORDS) {
        return Some((Class::Key, "named as a key"));
    }
    if looks_random(value) && value.len() >= 20 {
        return Some((Class::Key, "reads like a key"));
    }
    Some((Class::Configuration, "a setting"))
}

/// The part a piece plays in a key of several.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    ClientId,
    ClientSecret,
    Refresh,
    AccessId,
    AccessSecret,
    Endpoint,
    User,
    Password,
}

/// The role of a piece and the start of its name it shares with its partners, as `R2` in
/// `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY`.
pub fn role(piece: &Piece) -> Option<(Role, String)> {
    let label = words(&piece.label).join("_");
    let cut = |end: &str| label.strip_suffix(end).map(|s| s.trim_end_matches('_'));
    let in_section = |stem: &str| format!("{}|{stem}", piece.section.as_deref().unwrap_or(""));
    let rules: &[(&str, Role)] = &[
        ("client_id", Role::ClientId),
        ("clientid", Role::ClientId),
        ("client_secret", Role::ClientSecret),
        ("clientsecret", Role::ClientSecret),
        ("refresh_token", Role::Refresh),
        ("secret_access_key", Role::AccessSecret),
        ("access_key_secret", Role::AccessSecret),
        ("access_key_id", Role::AccessId),
        ("secret_key", Role::AccessSecret),
        ("access_key", Role::AccessId),
        ("endpoint_url", Role::Endpoint),
        ("endpoint", Role::Endpoint),
    ];
    for (end, role) in rules {
        if let Some(stem) = cut(end) {
            return Some((*role, in_section(stem)));
        }
    }
    let server = piece.server.clone().unwrap_or_default();
    match label.as_str() {
        "login" | "user" | "username" | "usuario" if !server.is_empty() => {
            Some((Role::User, format!("@{server}")))
        }
        "password" if !server.is_empty() => Some((Role::Password, format!("@{server}"))),
        _ => None,
    }
}

/// A provider keyreeve could check a key with, ready to use.
pub struct Known {
    pub id: String,
    pub name_words: Vec<String>,
    pub recipe: Recipe,
}

/// Every provider that can check a key with one request: those that ship, and your approved files.
pub fn known() -> Vec<Known> {
    known_from(
        providers::list()
            .into_iter()
            .filter(|entry| entry.approved && entry.problem.is_none() && entry.can_check)
            .filter_map(|entry| providers::load(&entry.id).ok())
            .collect(),
    )
}

/// The providers given, leaving out those that check over SSH or with a program of their own.
pub fn known_from(recipes: Vec<Recipe>) -> Vec<Known> {
    recipes
        .into_iter()
        .filter(|recipe| recipe.verify.method == "GET")
        .filter(|recipe| !matches!(recipe.auth.kind.as_deref(), Some("ssh" | "command")))
        .map(|recipe| Known {
            id: recipe.provider.clone(),
            name_words: words(recipe.display_name()),
            recipe,
        })
        .collect()
}

/// How many parts a provider's key has: two for an id and a secret, three with a refresh token.
pub fn parts_needed(recipe: &Recipe) -> usize {
    match (recipe.auth.kind.as_deref(), recipe.auth.grant.as_deref()) {
        (Some("oauth_token"), Some("refresh_token")) => 3,
        (Some("oauth_token"), _) | (Some("aws_sigv4"), _) => 2,
        _ => 1,
    }
}

/// Up to this many providers are tried for one key, so a scan sends few requests.
pub const MAX_RECIPES: usize = 3;

/// What is known about a key when guessing its provider.
#[derive(Default)]
pub struct Clues<'a> {
    /// The key, or its first part.
    pub first: &'a str,
    pub parts: usize,
    /// Its name, to compare with a provider's usual variable.
    pub label: &'a str,
    /// Words of its names, section and server.
    pub hint_words: Vec<String>,
    /// Words of the file's name.
    pub file_words: Vec<String>,
    /// Words of a domain a part ends with, as a Google client id ends with `googleusercontent.com`.
    pub domain_words: Vec<String>,
}

/// The providers that could check a key, best first: one whose prefix the key starts with (the
/// longest wins), one whose usual variable has this name, then one named in the name or the file,
/// then one whose name starts a domain the key carries.
pub fn guess(known: &[Known], clues: &Clues) -> Vec<String> {
    let fits: Vec<&Known> = known
        .iter()
        .filter(|k| parts_needed(&k.recipe) == clues.parts.max(1))
        .collect();
    let mut found: Vec<String> = Vec::new();
    let mut add = |id: &str| {
        if !found.iter().any(|f| f == id) {
            found.push(id.to_owned());
        }
    };
    let first = clues.first;
    let longest = fits
        .iter()
        .flat_map(|k| k.recipe.prefixes.iter())
        .filter(|prefix| first.starts_with(prefix.as_str()))
        .map(String::len)
        .max();
    if let Some(longest) = longest {
        for k in &fits {
            if k.recipe
                .prefixes
                .iter()
                .any(|p| p.len() == longest && first.starts_with(p.as_str()))
            {
                add(&k.id);
            }
        }
    }
    for k in &fits {
        if !clues.label.is_empty() && k.recipe.env_var.as_deref() == Some(clues.label) {
            add(&k.id);
        }
    }
    let plain_id = |k: &Known| k.id.replace('-', "");
    for words in [&clues.hint_words, &clues.file_words] {
        for k in &fits {
            let named = words
                .iter()
                .any(|w| *w == plain_id(k) || k.name_words.len() == 1 && *w == k.name_words[0]);
            if named {
                add(&k.id);
            }
        }
    }
    for k in &fits {
        if clues
            .domain_words
            .iter()
            .any(|w| w.len() > 3 && w.starts_with(&plain_id(k)))
        {
            add(&k.id);
        }
    }
    found.truncate(MAX_RECIPES);
    found
}

/// The words of the domain a value ends with, when it reads as one, as in `x.apps.example.com`.
pub fn domain_words(value: &str) -> Vec<String> {
    let host = value.rsplit('@').next().unwrap_or(value);
    let labels: Vec<&str> = host.split('.').collect();
    let looks_like_domain = labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        && labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_alphabetic()));
    if !looks_like_domain {
        return Vec::new();
    }
    // The name before the last part, as `example` in `x.apps.example.com`.
    labels[labels.len() - 2..labels.len() - 1]
        .iter()
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bring::read::Locate;
    use zeroize::Zeroizing;

    /// Providers that ship, read without touching any folder of this Mac.
    pub(crate) fn test_known() -> Vec<Known> {
        let ids = [
            "anthropic",
            "aws",
            "elevenlabs",
            "github",
            "google",
            "instagram",
            "meta",
            "openai",
            "paypal",
            "r2",
            "resend",
            "stripe",
            "telegram",
        ];
        known_from(ids.iter().map(|id| providers::load(id).unwrap()).collect())
    }

    fn piece(label: &str, value: &str) -> Piece {
        Piece {
            name: None,
            label: Zeroizing::new(label.into()),
            section: None,
            line: 1,
            locate: Locate::Whole,
            value: Zeroizing::new(value.into()),
            server: None,
            whole: None,
        }
    }

    fn class(label: &str, value: &str) -> Option<Class> {
        classify(&piece(label, value), &[]).map(|(class, _)| class)
    }

    #[test]
    fn says_what_each_value_is() {
        use Class::*;
        let cases = [
            ("OPENAI_API_KEY", "sk-proj-abcdefghijklmnop1234", Some(Key)),
            ("TELEGRAM_BOT_TOKEN", "123456:ABCdefGHIjklMNOpqr", Some(Key)),
            ("TELEGRAM_CHAT_ID", "-1001234567", Some(Configuration)),
            (
                "DATABASE_URL",
                "postgres://u:pw@db.example.com/x",
                Some(Key),
            ),
            ("SITE_URL", "https://example.com", Some(Configuration)),
            (
                "NEXT_PUBLIC_SUPABASE_ANON_KEY",
                "eyJhbGciOiJIUzI1NiJ9.e30.abc",
                Some(Public),
            ),
            (
                "STRIPE_PUBLISHABLE_KEY",
                "pk_live_abcdefghijklmnop",
                Some(Public),
            ),
            (
                "NEXT_PUBLIC_OOPS",
                "sk_live_abcdefghijklmnopqrst",
                Some(Key),
            ),
            ("DB_PASSWORD", "hunter2", Some(Login)),
            ("AWS_REGION", "us-east-1", Some(Configuration)),
            ("DEBUG", "true", Some(Configuration)),
            ("SOMETHING", "aB3dE5fG7hJ9kL1mN3pQ5rS", Some(Key)),
            ("API_KEY", "", None),
            ("API_KEY", "your-api-key-here", None),
            ("API_KEY", "${OTHER}", None),
            ("API_KEY", "xxxxxxxx", None),
        ];
        for (label, value, expected) in cases {
            assert_eq!(class(label, value), expected, "{label}");
        }
    }

    #[test]
    fn a_lone_value_takes_its_file_name() {
        let p = piece("", "plainvalue");
        assert_eq!(
            classify(&p, &words("github-token")).map(|c| c.0),
            Some(Class::Key)
        );
    }

    #[test]
    fn names_split_into_words() {
        assert_eq!(words("openaiApiKey"), ["openai", "api", "key"]);
        assert_eq!(
            words("R2_SECRET_ACCESS_KEY"),
            ["r2", "secret", "access", "key"]
        );
    }

    #[test]
    fn roles_share_a_stem() {
        let id = role(&piece("R2_ACCESS_KEY_ID", "x")).unwrap();
        let secret = role(&piece("R2_SECRET_ACCESS_KEY", "x")).unwrap();
        assert_eq!((id.0, secret.0), (Role::AccessId, Role::AccessSecret));
        assert_eq!(id.1, secret.1);
        let endpoint = role(&piece("R2_ENDPOINT", "x")).unwrap();
        assert_eq!(endpoint.1, id.1);
        assert_eq!(role(&piece("client_id", "x")).unwrap().0, Role::ClientId);
        assert!(role(&piece("API_KEY", "x")).is_none());
    }

    #[test]
    fn guesses_by_prefix_variable_and_name() {
        let known = test_known();
        let one = |first: &'static str| Clues {
            first,
            parts: 1,
            ..Clues::default()
        };
        assert_eq!(guess(&known, &one("sk-ant-abc")), ["anthropic"]);
        let telegram = Clues {
            label: "TELEGRAM_BOT_TOKEN",
            ..one("123:abc")
        };
        assert_eq!(guess(&known, &telegram), ["telegram"]);
        // A prefix of Instagram in a file named for Meta: both are tried, the prefix first.
        let instagram = Clues {
            file_words: words("meta-shop"),
            ..one("IGAAabc")
        };
        assert_eq!(guess(&known, &instagram), ["instagram", "meta"]);
        // The longest prefix wins over a shorter one another provider claims.
        assert_eq!(guess(&known, &one("sk_live_abc")), ["stripe"]);
        // A key of two parts is only offered to providers whose key has two.
        let two = Clues {
            parts: 2,
            ..one("AKIAabc")
        };
        assert_eq!(guess(&known, &two), ["aws"]);
        assert!(guess(&known, &one("AKIAabc")).is_empty());
        // A client id that ends with Google's domain, with its secret and refresh token.
        let three = Clues {
            parts: 3,
            domain_words: domain_words("123-abc.apps.googleusercontent.com"),
            ..one("123-abc.apps.googleusercontent.com")
        };
        assert_eq!(guess(&known, &three), ["google"]);
        assert!(domain_words("not a domain").is_empty());
        assert!(domain_words("1.5").is_empty());
    }
}
