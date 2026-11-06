use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// The CA of this process, whose key never leaves its memory, and the certificates it has made.
pub(super) struct Authority {
    pub(super) pem: String,
    der: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

pub(super) fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(super) fn validity(params: &mut rcgen::CertificateParams, days: u32) {
    let day = Duration::from_secs(86_400);
    let time = SystemTime::now();
    params.not_before = (time - day).into();
    params.not_after = (time + day * days).into();
}

impl Authority {
    pub(super) fn new() -> io::Result<Self> {
        let e = |x: rcgen::Error| io::Error::other(format!("the CA could not be made: {x}"));
        let key = rcgen::KeyPair::generate().map_err(e)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(e)?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "keyreeve proxy");
        validity(&mut params, 30);
        let cert = params.self_signed(&key).map_err(e)?;
        Ok(Self {
            pem: cert.pem(),
            der: cert.der().clone(),
            issuer: rcgen::Issuer::new(params, key),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub(super) fn for_host(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        let mut leaves = self.leaves.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(found) = leaves.get(host) {
            return Ok(found.clone());
        }
        let e = |x: rcgen::Error| io::Error::other(format!("no certificate for {host}: {x}"));
        let key = rcgen::KeyPair::generate().map_err(e)?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_owned()]).map_err(e)?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        validity(&mut params, 7);
        let cert = params.signed_by(&key, &self.issuer).map_err(e)?;
        let chain = vec![cert.der().clone(), self.der.clone()];
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(crypto())
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(chain, private)
            .map_err(io::Error::other)?;
        // One framing to read. A client that offers HTTP/2 falls back.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        leaves.insert(host.to_owned(), config.clone());
        Ok(config)
    }
}
