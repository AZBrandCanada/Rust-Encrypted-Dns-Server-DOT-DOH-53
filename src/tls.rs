// src/tls.rs
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;

pub struct LoadedCert {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub is_self_signed: bool,
    pub cert_file: String,
    pub key_file: String,
}

pub fn load_or_generate(
    cert_path: &str,
    key_path: &str,
) -> Result<LoadedCert, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        let cert_bytes = std::fs::read(cert_path)?;
        let key_bytes = std::fs::read(key_path)?;

        let certs =
            rustls_pemfile::certs(&mut cert_bytes.as_slice()).collect::<Result<Vec<_>, _>>()?;
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
        "[TLS] No cert/key found at '{}' / '{}'. Generating a SELF-SIGNED dev certificate.",
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

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        if let Ok(mut f) = options.open("selfsigned_key.pem") {
            let _ = f.write_all(key_pem.as_bytes());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write("selfsigned_key.pem", &key_pem);
    }

    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
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

pub fn dot_server_config(
    loaded: &LoadedCert,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(loaded.certs.clone(), loaded.key.clone_key())
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    config.alpn_protocols = vec![b"dot".to_vec()];
    Ok(Arc::new(config))
}
