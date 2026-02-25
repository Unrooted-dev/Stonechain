use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use crate::auth::{ensure_node_certificate, NodeCertConfig};

pub async fn load_tls_config_async(cfg: NodeCertConfig) -> Result<Arc<ServerConfig>> {
    let paths = ensure_node_certificate(cfg).await?;
    let cert_path = paths.cert;
    let key_path = paths.key;

    let mut cert_file = BufReader::new(fs::File::open(&cert_path).context("server.crt fehlt")?);
    let mut key_file = BufReader::new(fs::File::open(&key_path).context("server.key fehlt")?);

    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut cert_file)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Cert ungültig")?;

    let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_private_keys(&mut key_file)
        .map(|key| key.map(Into::into))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Key ungültig")?;
    if keys.is_empty() {
        // Fallback für klassische RSA-Schlüssel
        let mut key_file = BufReader::new(fs::File::open(&key_path).context("server.key fehlt")?);
        keys = rsa_private_keys(&mut key_file)
            .map(|key| key.map(Into::into))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Key ungültig (RSA)")?;
    }
    if keys.is_empty() {
        return Err(anyhow::anyhow!(
            "Kein privater Schlüssel gefunden in {}",
            key_path
        ));
    }

    let require_client = std::env::var("STONE_REQUIRE_CLIENT_AUTH")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let builder = ServerConfig::builder();
    let config = if require_client {
        let ca_path = std::env::var("STONE_CA_CERT")
            .ok()
            .or_else(|| std::env::var("RUSTLS_CERTFILE").ok());
        if let Some(ca_path) = ca_path {
            let mut store = RootCertStore::empty();
            let ca_bytes = fs::read(&ca_path).context("CA-Datei nicht lesbar")?;
            let mut reader = BufReader::new(&ca_bytes[..]);
            for cert in certs(&mut reader) {
                let der = cert.context("CA-Zert ungültig")?;
                store.add(der).context("CA in RootStore fehlgeschlagen")?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(store))
                .build()
                .context("Client-Verifier")?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_chain, keys.remove(0))
                .context("TLS Config fehlgeschlagen (mTLS)")?
        } else {
            eprintln!("[tls] STONE_REQUIRE_CLIENT_AUTH=1 aber kein STONE_CA_CERT/RUSTLS_CERTFILE gesetzt – falle auf no-client-auth zurück");
            builder
                .with_no_client_auth()
                .with_single_cert(cert_chain, keys.remove(0))
                .context("TLS Config fehlgeschlagen")?
        }
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, keys.remove(0))
            .context("TLS Config fehlgeschlagen")?
    };

    Ok(Arc::new(config))
}

pub async fn load_tls_config_from_env() -> Result<Arc<ServerConfig>> {
    load_tls_config_async(NodeCertConfig::from_env()).await
}
