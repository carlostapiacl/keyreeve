use std::fmt;
use zeroize::Zeroizing;

/// A credential value. It has no serializer, prints as `[redacted]` and is wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_prints_its_value() {
        let secret = Secret::new("canary-value");
        assert_eq!(format!("{secret} {secret:?}"), "[redacted] [redacted]");
        assert_eq!(secret.expose(), "canary-value");
    }
}
