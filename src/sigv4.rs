//! Signs a request the way AWS requires. The secret never travels: only a signature does.

use crate::secret::Secret;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub struct Signing<'a> {
    pub service: &'a str,
    pub region: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
    /// `YYYYMMDDTHHMMSSZ`
    pub stamp: &'a str,
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Returns the `Authorization` value for this request.
pub fn authorization(signing: &Signing, access_key: &str, secret_key: &Secret) -> String {
    let (uri, query) = signing.path.split_once('?').unwrap_or((signing.path, ""));
    let mut pairs: Vec<&str> = query.split('&').filter(|pair| !pair.is_empty()).collect();
    pairs.sort_unstable();
    let query = pairs.join("&");

    let mut canonical_headers = String::new();
    let mut signed = Vec::new();
    if let Some(content_type) = signing.content_type {
        canonical_headers.push_str(&format!("content-type:{content_type}\n"));
        signed.push("content-type");
    }
    canonical_headers.push_str(&format!(
        "host:{}\nx-amz-date:{}\n",
        signing.host, signing.stamp
    ));
    signed.extend(["host", "x-amz-date"]);
    let signed = signed.join(";");

    let request = format!(
        "{}\n{uri}\n{query}\n{canonical_headers}\n{signed}\n{}",
        signing.method,
        hex(&Sha256::digest(signing.body))
    );
    let date = &signing.stamp[..8];
    let scope = format!("{date}/{}/{}/aws4_request", signing.region, signing.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        signing.stamp,
        hex(&Sha256::digest(request.as_bytes()))
    );
    let start = Secret::new(format!("AWS4{}", secret_key.expose()));
    let key = hmac(start.expose().as_bytes(), date);
    let key = hmac(&key, signing.region);
    let key = hmac(&key, signing.service);
    let key = hmac(&key, "aws4_request");
    let signature = hex(&hmac(&key, &to_sign));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
    )
}

/// The current UTC time in the form AWS expects.
pub fn stamp_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    stamp_of(seconds)
}

pub fn stamp_of(seconds: u64) -> String {
    let z = (seconds / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let rest = seconds % 86_400;
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example in AWS's documentation for Signature Version 4.
    #[test]
    fn matches_the_published_example() {
        let value = authorization(
            &Signing {
                service: "iam",
                region: "us-east-1",
                method: "GET",
                host: "iam.amazonaws.com",
                path: "/?Version=2010-05-08&Action=ListUsers",
                content_type: Some("application/x-www-form-urlencoded; charset=utf-8"),
                body: b"",
                stamp: "20150830T123600Z",
            },
            "AKIDEXAMPLE",
            &Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
        );
        assert!(
            value.ends_with(
                "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
            ),
            "{value}"
        );
    }

    #[test]
    fn writes_the_time_as_aws_expects() {
        assert_eq!(stamp_of(1_440_938_160), "20150830T123600Z");
    }

    #[test]
    fn the_secret_is_not_in_the_header() {
        let value = authorization(
            &Signing {
                service: "sts",
                region: "us-east-1",
                method: "GET",
                host: "sts.amazonaws.com",
                path: "/",
                content_type: None,
                body: b"",
                stamp: "20150830T123600Z",
            },
            "AKIDEXAMPLE",
            &Secret::new("CANARYsecret"),
        );
        assert!(!value.contains("CANARY"));
    }
}
