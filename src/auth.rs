use anyhow::{Context, Result};
use base64::Engine as _;
use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::x509::X509Name;

use crate::blockchain::data_dir;

fn users_file() -> String { format!("{}/users.json", data_dir()) }
pub const USERS_FILE_COMPAT: &str = "stone_data/users.json"; // für externe Tools

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub name: String,
    pub api_key: String,
    #[serde(default)]
    pub phrase_hash: String,
    #[serde(default = "default_quota_bytes")]
    pub quota_bytes: u64,
}

pub fn default_quota_bytes() -> u64 {
    5 * 1024 * 1024 * 1024
} // 5 GiB

#[derive(Deserialize)]
pub struct SignupRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub id: String,
    pub api_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phrase: Option<String>,
}

pub fn load_users() -> Arc<Mutex<Vec<User>>> {
    if let Ok(data) = fs::read_to_string(users_file()) {
        if let Ok(list) = serde_json::from_str::<Vec<User>>(&data) {
            return Arc::new(Mutex::new(list));
        }
    }
    Arc::new(Mutex::new(Vec::new()))
}

pub fn save_users(users: &[User]) {
    if let Ok(json) = serde_json::to_string_pretty(users) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(users_file(), json);
    }
}

pub fn generate_key() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn hash_phrase(phrase: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(phrase.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn create_user_with_phrase(name: &str) -> (User, String) {
    let phrase = Mnemonic::generate_in(Language::English, 12).expect("mnemonic gen");
    let phrase_str = phrase.to_string();
    let api_key = hash_phrase(&phrase_str);
    let user = User {
        id: String::new(),
        name: name.to_string(),
        api_key: api_key.clone(),
        phrase_hash: api_key.clone(),
        quota_bytes: default_quota_bytes(),
    };
    (user, phrase_str)
}

pub fn create_user_with_random_phrase(name: &str) -> (User, String) {
    create_user_with_phrase(name)
}

pub fn resolve_phrase(phrase: &str) -> Option<String> {
    if Mnemonic::parse_in(Language::English, phrase).is_err() {
        return None;
    }
    Some(hash_phrase(phrase))
}

// ─── Lokale Token-Generierung (kein Auth-Server nötig) ───────────────────────

/// Claims für einen lokal generierten HMAC-Token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTokenClaims {
    /// Node-ID (Subject)
    pub node_id: String,
    /// Ausstellungszeitpunkt (Unix-Sekunden)
    pub issued_at: u64,
    /// Ablaufzeitpunkt (Unix-Sekunden)
    pub expires_at: u64,
    /// Zufälliger Nonce (verhindert Replay-Angriffe)
    pub nonce: String,
}

impl LocalTokenClaims {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }
}

/// Erzeugt einen lokal signierten HMAC-SHA256-Token für einen Node.
///
/// Format: `base64(json_claims).base64(hmac_signature)`
/// Der Token beweist, dass der Node den `cluster_key` kennt — kein
/// zentraler Auth-Server erforderlich.
pub fn generate_local_token(node_id: &str, cluster_key: &str, ttl_secs: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let claims = LocalTokenClaims {
        node_id: node_id.to_string(),
        issued_at: now,
        expires_at: now + ttl_secs,
        nonce: hex::encode(nonce_bytes),
    };

    let claims_json = serde_json::to_string(&claims).unwrap_or_default();
    let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(claims_json.as_bytes());

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cluster_key.as_bytes())
        .expect("HMAC akzeptiert beliebige Schlüssellängen");
    mac.update(claims_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

    format!("{claims_b64}.{sig_b64}")
}

/// Validiert einen lokal signierten Token.
/// Gibt `Some(claims)` zurück wenn Signatur + Ablaufzeit gültig sind.
pub fn validate_local_token(token: &str, cluster_key: &str) -> Option<LocalTokenClaims> {
    let parts: Vec<&str> = token.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let claims_b64 = parts[0];
    let sig_b64 = parts[1];

    // Signatur prüfen
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cluster_key.as_bytes()).ok()?;
    mac.update(claims_b64.as_bytes());
    let expected_sig = mac.finalize().into_bytes();
    let expected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected_sig);
    if expected_b64 != sig_b64 {
        return None;
    }

    // Claims dekodieren
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims_b64)
        .ok()?;
    let claims: LocalTokenClaims = serde_json::from_slice(&claims_bytes).ok()?;

    if claims.is_expired() {
        return None;
    }

    Some(claims)
}

// ─── Selbst-signiertes Zertifikat (kein Auth-Server nötig) ───────────────────

/// Erzeugt ein selbst-signiertes TLS-Zertifikat für einen Node.
/// Wird verwendet wenn kein `STONE_AUTH_URL` gesetzt ist und kein
/// bestehendes Zertifikat vorhanden ist.
fn generate_self_signed_cert(node_name: &str, sans: &[String], paths: &CertPaths) -> Result<()> {
    use rcgen::generate_simple_self_signed;

    let mut subject_alt_names: Vec<String> = sans.to_vec();
    if !subject_alt_names.iter().any(|s| s == "localhost") {
        subject_alt_names.push("localhost".into());
    }
    if !subject_alt_names.iter().any(|s| s == "127.0.0.1") {
        subject_alt_names.push("127.0.0.1".into());
    }

    let cert = generate_simple_self_signed(subject_alt_names)
        .context("Self-signed Cert Generierung fehlgeschlagen")?;

    if let Some(dir) = Path::new(&paths.cert).parent() {
        fs::create_dir_all(dir).context("TLS-Verzeichnis anlegen")?;
    }
    let cert_pem = cert.serialize_pem().context("Cert PEM serialisieren")?;
    let key_pem  = cert.serialize_private_key_pem();

    fs::write(&paths.cert, &cert_pem).context("Zertifikat schreiben")?;
    fs::write(&paths.key, &key_pem).context("Private Key schreiben")?;
    // Self-signed: CA = das Zertifikat selbst
    if let Some(dir) = Path::new(&paths.ca).parent() {
        fs::create_dir_all(dir).ok();
    }
    let _ = fs::write(&paths.ca, &cert_pem);

    println!(
        "[tls] Self-signed Zertifikat generiert für '{}' → {}",
        node_name, paths.cert
    );
    Ok(())
}

#[derive(Clone, Debug)]
pub struct CertPaths {
    pub cert: String,
    pub key: String,
    pub ca: String,
}

#[derive(Clone, Debug)]
pub struct NodeCertConfig {
    pub auth_url: Option<String>,
    pub node_name: String,
    pub sans: Vec<String>,
    pub node_url: Option<String>,
}

impl NodeCertConfig {
    pub fn from_env() -> Self {
        Self {
            auth_url: std::env::var("STONE_AUTH_URL").ok(),
            node_name: std::env::var("STONE_NODE_NAME").unwrap_or_else(|_| "node".into()),
            sans: split_env_list("STONE_NODE_SANS"),
            node_url: std::env::var("STONE_NODE_URL").ok(),
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Deserialize)]
struct CertResponse {
    cert_pem: String,
    key_pem: String,
    ca_pem: String,
}

fn split_env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn cert_paths_from_env() -> CertPaths {
    let tls_dir = format!("{}/tls", data_dir());
    CertPaths {
        cert: std::env::var("STONE_TLS_CERT").unwrap_or_else(|_| format!("{}/node.crt", tls_dir)),
        key: std::env::var("STONE_TLS_KEY").unwrap_or_else(|_| format!("{}/node.key", tls_dir)),
        ca: std::env::var("STONE_CA_CERT").unwrap_or_else(|_| format!("{}/root.crt", tls_dir)),
    }
}

fn allow_insecure_tls() -> bool {
    std::env::var("STONE_INSECURE_SSL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn cert_is_valid(cert_path: &str, margin: Duration) -> bool {
    let data = match std::fs::read(cert_path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let (_, pem) = match parse_x509_pem(&data) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let (_, cert) = match X509Certificate::from_der(&pem.contents) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let not_after_ts = cert.validity().not_after.timestamp();
    if not_after_ts < 0 {
        return false;
    }
    let expiry = match UNIX_EPOCH.checked_add(Duration::from_secs(not_after_ts as u64)) {
        Some(t) => t,
        None => return false,
    };
    match SystemTime::now().checked_add(margin) {
        Some(now_with_margin) => expiry > now_with_margin,
        None => false,
    }
}

fn issuer_matches_ca(cert_path: &str, ca_path: &str) -> bool {
    let cert_bytes = match std::fs::read(cert_path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let ca_bytes = match std::fs::read(ca_path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let (_, cert_pem) = match parse_x509_pem(&cert_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let (_, ca_pem) = match parse_x509_pem(&ca_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let (_, cert) = match X509Certificate::from_der(&cert_pem.contents) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let (_, ca_cert) = match X509Certificate::from_der(&ca_pem.contents) {
        Ok(c) => c,
        Err(_) => return false,
    };
    names_equal(cert.issuer(), ca_cert.subject())
}

fn names_equal(a: &X509Name<'_>, b: &X509Name<'_>) -> bool {
    // X509Name implements PartialEq
    a == b
}

fn cert_has_sans(cert_path: &str, expected: &[String]) -> bool {
    let data = match std::fs::read(cert_path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let (_, pem) = match parse_x509_pem(&data) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let (_, cert) = match X509Certificate::from_der(&pem.contents) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let sans_ext = match cert.subject_alternative_name() {
        Ok(Some(s)) => s,
        _ => return false,
    };
    let mut present = Vec::new();
    for gn in sans_ext.value.general_names.iter() {
        match gn {
            GeneralName::DNSName(dns) => present.push(dns.to_string()),
            GeneralName::IPAddress(ip) => {
                if ip.len() == 4 {
                    use std::net::Ipv4Addr;
                    let addr = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                    present.push(addr.to_string());
                } else if ip.len() == 16 {
                    use std::net::Ipv6Addr;
                    let mut oct = [0u8; 16];
                    oct.copy_from_slice(ip);
                    let addr = Ipv6Addr::from(oct);
                    present.push(addr.to_string());
                }
            }
            _ => {}
        }
    }
    expected.iter().all(|e| present.iter().any(|p| p == e))
}

fn needs_refresh(paths: &CertPaths, margin: Duration, expected_sans: &[String]) -> bool {
    if !Path::new(&paths.cert).exists() || !Path::new(&paths.key).exists() {
        return true;
    }
    if !cert_is_valid(&paths.cert, margin) {
        return true;
    }
    if !Path::new(&paths.ca).exists() {
        return true;
    }
    if !issuer_matches_ca(&paths.cert, &paths.ca) {
        return true;
    }
    if !cert_has_sans(&paths.cert, expected_sans) {
        return true;
    }
    false
}

async fn fetch_cert_bundle(
    auth_url: &str,
    node_name: &str,
    sans: &[String],
    node_url: Option<&str>,
) -> Result<CertResponse> {
    let mut builder = Client::builder().timeout(Duration::from_secs(5));
    if allow_insecure_tls() {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder.build()?;
    let base = auth_url.trim_end_matches('/');

    let tok_resp = client
        .post(format!("{}/token", base))
        .json(&json!({ "role": "admin", "ttl_secs": 3600 }))
        .send()
        .await
        .context("Token anfordern fehlgeschlagen")?
        .error_for_status()
        .context("Token-Response kein Erfolg")?
        .json::<TokenResponse>()
        .await
        .context("Token-Body parsen fehlgeschlagen")?;

    let cert_resp = client
        .post(format!("{}/cert/request", base))
        .header("x-auth-token", tok_resp.token)
        .json(&json!({ "name": node_name, "san": sans, "url": node_url }))
        .send()
        .await
        .context("Zertifikat anfordern fehlgeschlagen")?
        .error_for_status()
        .context("Cert-Response kein Erfolg")?
        .json::<CertResponse>()
        .await
        .context("Cert-Body parsen fehlgeschlagen")?;

    Ok(cert_resp)
}

async fn fetch_root_ca(auth_url: &str) -> Result<String> {
    let mut builder = Client::builder().timeout(Duration::from_secs(5));
    if allow_insecure_tls() {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder.build()?;
    let base = auth_url.trim_end_matches('/');
    let resp = client
        .get(format!("{}/ca/root", base))
        .send()
        .await
        .context("Root-CA abrufen fehlgeschlagen")?
        .error_for_status()
        .context("Root-CA Response kein Erfolg")?
        .text()
        .await
        .context("Root-CA Text fehlgeschlagen")?;
    Ok(resp)
}

fn persist_bundle(paths: &CertPaths, bundle: &CertResponse) -> Result<()> {
    if let Some(dir) = Path::new(&paths.cert).parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(&paths.cert, &bundle.cert_pem)?;
    fs::write(&paths.key, &bundle.key_pem)?;
    if let Some(dir) = Path::new(&paths.ca).parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(&paths.ca, &bundle.ca_pem)?;
    Ok(())
}

pub async fn ensure_node_certificate(cfg: NodeCertConfig) -> Result<CertPaths> {
    let paths = cert_paths_from_env();
    let margin = Duration::from_secs(12 * 60 * 60);
    let mut sans = cfg.sans.clone();
    // Ergänze Host aus node_url (falls gesetzt) und 127.0.0.1 als lokale Schleife
    if let Some(url) = cfg.node_url.as_deref() {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                if !sans.iter().any(|s| s == host) {
                    sans.push(host.to_string());
                }
            }
        }
    }
    if !sans.iter().any(|s| s == "127.0.0.1") {
        sans.push("127.0.0.1".into());
    }

    let auth_url = match cfg
        .auth_url
        .or_else(|| std::env::var("STONE_AUTH_URL").ok())
    {
        Some(u) => u,
        None => {
            // Kein Auth-Server hinterlegt:
            // 1. Bestehendes Zertifikat? → Verwenden
            if Path::new(&paths.cert).exists() && Path::new(&paths.key).exists() {
                println!(
                    "[tls] Keine STONE_AUTH_URL – nutze bestehendes Zertifikat ({})",
                    paths.cert
                );
                return Ok(paths);
            }
            // 2. Kein Zertifikat → Self-signed generieren (kein Auth-Server nötig)
            println!(
                "[tls] Keine STONE_AUTH_URL – generiere self-signed Zertifikat für '{}' …",
                cfg.node_name
            );
            generate_self_signed_cert(&cfg.node_name, &sans, &paths)?;
            return Ok(paths);
        }
    };

    let mut ca_changed = false;
    if let Ok(ca_pem) = fetch_root_ca(&auth_url).await {
        if let Some(dir) = Path::new(&paths.ca).parent() {
            fs::create_dir_all(dir)?;
        }
        let current = std::fs::read_to_string(&paths.ca).unwrap_or_default();
        if current != ca_pem {
            fs::write(&paths.ca, &ca_pem)?;
            ca_changed = true;
            let new_hash = hex::encode(sha2::Sha256::digest(ca_pem.as_bytes()));
            let old_hash = if current.is_empty() {
                "none".to_string()
            } else {
                hex::encode(sha2::Sha256::digest(current.as_bytes()))
            };
            println!(
                "[tls] Root-CA aktualisiert vom Auth-Server (alt: {}, neu: {})",
                old_hash, new_hash
            );
        }
    }

    if !ca_changed && !needs_refresh(&paths, margin, &sans) {
        return Ok(paths);
    }

    println!("[tls] Zertifikat fehlt/abgelaufen/CA gewechselt – hole neues vom Auth-Server");
    let bundle =
        fetch_cert_bundle(&auth_url, &cfg.node_name, &sans, cfg.node_url.as_deref()).await?;
    persist_bundle(&paths, &bundle)?;
    Ok(paths)
}
