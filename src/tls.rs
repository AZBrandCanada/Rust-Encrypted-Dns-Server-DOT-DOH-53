// src/tls.rs
//
// Both DoT and DoH failures traced back to the same root problem:
// there was no real, publicly-trusted certificate anywhere.
//
//   - DoH was served as plain HTTP. RFC 8484 requires HTTPS; browsers
//     and OS DoH clients simply refuse non-TLS endpoints. Any client
//     configured to use it would fail every lookup and silently fall
//     back to whatever DNS was set before.
//
//   - DoT self-signed a cert for "localhost" on first run. Android's
//     Private DNS (hostname mode) validates the certificate chain
//     against a public CA for the *exact hostname you type into
//     Settings*. A self-signed cert can never satisfy that check —
//     there is no code fix for this, it needs a real certificate for
//     a real domain name you control.
//
// This module just loads a cert/key pair from disk. Getting that pair
// is an operational step, not a code one — see the README for how to
// get one for free with certbot. If no real cert is present it falls
// back to a self-signed dev cert so the server still starts and you
// can test locally with `kdig` / `curl -k`, but DoT/DoH will not work
// for real clients (Android, browsers, etc.) until you install a real
// one — the server logs a loud warning every time this happens.

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;

pub struct LoadedCert {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub is_self_signed: bool,
    /// The cert/key file paths actually in use (real ones if found,
    /// otherwise the generated self-signed pair) — pass these to
    /// axum-server for the DoH TLS listener too, so both protocols
    /// always use the same certificate.
    pub cert_file: String,
    pub key_file: String,
}

pub fn load_or_generate(cert_path: &str, key_path: &str) -> Result<LoadedCert, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        let cert_bytes = std::fs::read(cert_path)?;
        let key_bytes = std::fs::read(key_path)?;

        let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice()).collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())?
            .ok_or("No private key found in key file")?;

        tracing::info!(cert_path, key_path, "[TLS] Loaded certificate from disk");
        return Ok(LoadedCert {
            certs,
            key,
            is_self_signed: false,
            cert_file: cert_path.to_string(),
            key_file: key_path.to_string(),
        });
    }

    tracing::warn!(
        "[TLS] No cert/key found at '{}' / '{}'. Generating a SELF-SIGNED dev certificate. \
         DoT and DoH will NOT work for real clients (Android Private DNS, browsers, etc.) \
         until you put a real certificate there — see README.md.",
        cert_path,
        key_path
    );

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let params = rcgen::CertificateParams::new(subject_alt_names)?;
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let _ = std::fs::write("selfsigned_cert.pem", &cert_pem);
    let _ = std::fs::write("selfsigned_key.pem", &key_pem);

    let certs =
        rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or("Failed to parse generated self-signed key")?;

    Ok(LoadedCert {
        certs,
        key,
        is_self_signed: true,
        cert_file: "selfsigned_cert.pem".to_string(),
        key_file: "selfsigned_key.pem".to_string(),
    })
}

/// Build a rustls ServerConfig for raw DNS-over-TLS (ALPN "dot").
pub fn dot_server_config(loaded: &LoadedCert) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(loaded.certs.clone(), loaded.key.clone_key())
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    config.alpn_protocols = vec![b"dot".to_vec()];
    Ok(Arc::new(config))
}
