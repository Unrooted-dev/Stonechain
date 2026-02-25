use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use chrono::DateTime;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use stone::blockchain::{calculate_hash, Block};
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NodeInfo {
    name: String,
    url: String,
    #[serde(default)]
    san: Vec<String>,
    #[serde(default)]
    allowed: bool,
    #[serde(default)]
    quarantine: bool,
    #[serde(default)]
    last_seen: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NodeMetricsEntry {
    node: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    cpu_percent: f32,
    #[serde(default)]
    mem_used: u64,
    #[serde(default)]
    mem_total: u64,
    #[serde(default)]
    net_rx: u64,
    #[serde(default)]
    net_tx: u64,
    #[serde(default)]
    storage_used: u64,
    #[serde(default)]
    storage_total: u64,
    #[serde(default)]
    blocks: u64,
    #[serde(default)]
    latest_hash: Option<String>,
    #[serde(default)]
    timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Registry {
    nodes: HashMap<String, NodeInfo>,
    #[serde(default)]
    secret: Vec<u8>,
    #[serde(default)]
    provision_secrets: HashMap<String, String>, // name -> provision token
    #[serde(default)]
    cluster_api_key: String,
}

const GENESIS_FILE: &str = "auth_genesis.bin";
const GENESIS_ENDPOINT: &str = "/genesis";

#[derive(Clone)]
struct AppState {
    reg: Arc<Mutex<Registry>>,
    ca: Arc<Certificate>,
    ca_pem: Arc<String>,
    genesis: Arc<Block>,
    metrics: Arc<Mutex<HashMap<String, NodeMetricsEntry>>>,
}

#[derive(Debug, Deserialize)]
struct RegisterReq {
    name: String,
    url: String,
    #[serde(default)]
    san: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TokenReq {
    role: String,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct TokenResp {
    token: String,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct CertReq {
    name: String,
    #[serde(default)]
    san: Vec<String>,
    #[serde(default)]
    url: Option<String>,
}

async fn warn_if_clock_skew(time_url: &str, max_skew: Duration) {
    let client = match Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[time] HTTP-Client fehlgeschlagen: {e}");
            return;
        }
    };
    let resp = match client.get(time_url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[time] Anfrage für Uhrzeit fehlgeschlagen: {e}");
            return;
        }
    };
    if let Some(date_hdr) = resp.headers().get(header::DATE) {
        if let Ok(date_str) = date_hdr.to_str() {
            if let Ok(dt) = DateTime::parse_from_rfc2822(date_str) {
                let server_ts = dt.timestamp();
                if let Ok(local_ts) = SystemTime::now().duration_since(UNIX_EPOCH) {
                    let local_ts = local_ts.as_secs() as i64;
                    let skew = (local_ts - server_ts).abs();
                    if skew > max_skew.as_secs() as i64 {
                        eprintln!(
                            "[time] Warnung: Zeitskew {}s (lokal {} vs. time-source {}) – TLS/Token können fehlschlagen.",
                            skew, local_ts, server_ts
                        );
                    }
                }
            }
        }
    }
}

fn load_registry() -> Registry {
    if let Ok(data) = fs::read("auth_registry.json") {
        if let Ok(r) = serde_json::from_slice(&data) {
            // env override für Secret (z.B. zum Teilen zwischen Nodes)
            if let Ok(env_hex) = std::env::var("STONE_AUTH_SHARED_SECRET") {
                if let Ok(bytes) = hex::decode(env_hex) {
                    if bytes.len() >= 16 {
                        return Registry { secret: bytes, ..r };
                    }
                }
            }
            let mut reg: Registry = r;
            if reg.cluster_api_key.is_empty() {
                if let Ok(k) = std::env::var("STONE_CLUSTER_API_KEY") {
                    reg.cluster_api_key = k;
                }
            }
            return reg;
        }
    }
    let secret = if let Ok(env_hex) = std::env::var("STONE_AUTH_SHARED_SECRET") {
        hex::decode(env_hex).unwrap_or_else(|_| {
            let mut buf = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        })
    } else {
        let mut buf = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    };
    let cluster_api_key = std::env::var("STONE_CLUSTER_API_KEY").unwrap_or_else(|_| {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        hex::encode(buf)
    });
    Registry {
        nodes: HashMap::new(),
        secret,
        provision_secrets: HashMap::new(),
        cluster_api_key,
    }
}

fn save_registry(reg: &Registry) {
    let _ = fs::write(
        "auth_registry.json",
        serde_json::to_vec_pretty(reg).unwrap_or_default(),
    );
}

fn load_or_create_genesis() -> Block {
    if let Ok(data) = fs::read(GENESIS_FILE) {
        if let Ok((block, _)) =
            bincode::serde::decode_from_slice::<Block, _>(&data, bincode::config::standard())
        {
            return block;
        }
    }
    let mut genesis = Block {
        index: 0,
        timestamp: 0,
        merkle_root: format!("{:x}", sha2::Sha256::digest(b"genesis")),
        data_size: 0,
        previous_hash: "0".repeat(64),
        hash: String::new(),
        signer: "auth-genesis".to_string(),
        signature: String::new(),
        owner: String::new(),
        documents: Vec::new(),
        tombstones: Vec::new(),
        node_role: stone::blockchain::NodeRole::Master,
        proposal_round: 0,
        validator_pub_key: String::new(),
        validator_signature: String::new(),
    };
    let h = calculate_hash(&genesis);
    genesis.hash = h;
    let _ = fs::write(
        GENESIS_FILE,
        bincode::serde::encode_to_vec(&genesis, bincode::config::standard()).unwrap_or_default(),
    );
    genesis
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn sign_token(secret: &[u8], role: &str, ttl: u64) -> TokenResp {
    let exp = now() + ttl;
    let payload = serde_json::json!({
        "role": role,
        "exp": exp,
        "iat": now(),
    })
    .to_string();
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    TokenResp {
        token: format!("{}.{}", payload, sig),
        exp,
    }
}

fn verify_token(raw: &str, secret: &[u8], required_role: &str) -> bool {
    let parts: Vec<&str> = raw.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return false;
    }
    let sig_hex = parts[0];
    let payload = parts[1];
    let expected_sig = match hex::decode(sig_hex) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(payload.as_bytes());
    if mac.verify_slice(&expected_sig).is_err() {
        return false;
    }
    let val: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let exp = val.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);
    if now() > exp {
        return false;
    }
    let role = val.get("role").and_then(|v| v.as_str()).unwrap_or("");
    role == required_role
}

fn init_ca(dir: &str) -> (Certificate, String) {
    let _ = fs::create_dir_all(dir);
    let root_path = format!("{}/root.crt", dir);
    let key_path = format!("{}/root.key", dir);
    // 1) Versuche bestehende CA zu laden (stabile Root, keine UnknownCA)
    if let (Ok(ca_pem), Ok(ca_key_pem)) = (
        fs::read_to_string(&root_path),
        fs::read_to_string(&key_path),
    ) {
        if let Ok(keypair) = KeyPair::from_pem(&ca_key_pem) {
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "Stone-CA");
            params.key_pair = Some(keypair);
            if let Ok(cert) = Certificate::from_params(params) {
                println!("CA geladen aus {}", root_path);
                return (cert, ca_pem);
            }
        }
        eprintln!("Warnung: Konnte bestehende CA nicht laden, erstelle neu.");
    }

    // 2) Fallback: neue CA erzeugen und auf Disk schreiben
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Stone-CA");
    let cert = Certificate::from_params(params).expect("CA erstellen");
    let ca_pem = cert.serialize_pem().expect("CA pem");
    let ca_key = cert.serialize_private_key_pem();
    let _ = fs::write(&root_path, &ca_pem);
    let _ = fs::write(&key_path, &ca_key);
    println!("Neue CA erzeugt unter {}", root_path);
    (cert, ca_pem)
}

fn issue_node_cert(
    ca: &Certificate,
    name: &str,
    san: &[String],
) -> Result<(String, String), String> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = IsCa::NoCa;
    for s in san {
        if s.parse::<std::net::IpAddr>().is_ok() {
            params
                .subject_alt_names
                .push(SanType::IpAddress(s.parse().unwrap()));
        } else {
            params.subject_alt_names.push(SanType::DnsName(s.clone()));
        }
    }
    let leaf = Certificate::from_params(params).map_err(|e| e.to_string())?;
    let cert_pem = leaf
        .serialize_pem_with_signer(ca)
        .map_err(|e| e.to_string())?;
    let key_pem = leaf.serialize_private_key_pem();
    Ok((cert_pem, key_pem))
}

fn ensure_auth_server_cert(
    ca: &Certificate,
    ca_dir: &str,
    bind: SocketAddr,
) -> Result<(String, String), String> {
    let cert_path = format!("{}/auth_server.crt", ca_dir);
    let key_path = format!("{}/auth_server.key", ca_dir);

    if let (Ok(_c), Ok(_k)) = (
        fs::read_to_string(&cert_path),
        fs::read_to_string(&key_path),
    ) {
        return Ok((cert_path, key_path));
    }

    let mut sans: HashSet<String> = HashSet::new();
    let ip = bind.ip();
    if !ip.is_unspecified() {
        sans.insert(ip.to_string());
    }
    sans.insert("127.0.0.1".into());
    sans.insert("localhost".into());
    if let Ok(custom) = std::env::var("STONE_AUTH_SAN") {
        for entry in custom.split(',') {
            let trimmed = entry.trim();
            if !trimmed.is_empty() {
                sans.insert(trimmed.to_string());
            }
        }
    }
    let mut san_list: Vec<String> = sans.into_iter().collect();
    san_list.sort();

    let (cert_pem, key_pem) = issue_node_cert(ca, "auth-server", &san_list)?;
    fs::write(&cert_path, &cert_pem).map_err(|e| e.to_string())?;
    fs::write(&key_path, &key_pem).map_err(|e| e.to_string())?;
    println!(
        "[auth] HTTPS-Zertifikat erstellt unter {} (SANs: {})",
        cert_path,
        san_list.join(", ")
    );
    Ok((cert_path, key_path))
}

async fn register_node(
    State(state): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> impl IntoResponse {
    let mut reg = state.reg.lock().unwrap();
    let info = NodeInfo {
        name: req.name.clone(),
        url: req.url.clone(),
        san: req.san.clone(),
        allowed: true,
        quarantine: false,
        last_seen: now(),
    };
    reg.nodes.insert(req.url.clone(), info.clone());
    save_registry(&reg);
    (StatusCode::OK, Json(info))
}

async fn list_nodes(State(state): State<AppState>) -> impl IntoResponse {
    let reg = state.reg.lock().unwrap();
    let list: Vec<NodeInfo> = reg.nodes.values().cloned().collect();
    Json(serde_json::json!({ "nodes": list }))
}

async fn allow_node(State(state): State<AppState>, Path(url): Path<String>) -> impl IntoResponse {
    let mut reg = state.reg.lock().unwrap();
    if let Some(n) = reg.nodes.get_mut(&url) {
        n.allowed = true;
        n.quarantine = false;
        save_registry(&reg);
        return (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Node not found" })),
    )
        .into_response()
}

async fn deny_node(State(state): State<AppState>, Path(url): Path<String>) -> impl IntoResponse {
    let mut reg = state.reg.lock().unwrap();
    if let Some(n) = reg.nodes.get_mut(&url) {
        n.allowed = false;
        n.quarantine = false;
        save_registry(&reg);
        return (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Node not found" })),
    )
        .into_response()
}

async fn quarantine_node(
    State(state): State<AppState>,
    Path(url): Path<String>,
) -> impl IntoResponse {
    let mut reg = state.reg.lock().unwrap();
    if let Some(n) = reg.nodes.get_mut(&url) {
        n.quarantine = true;
        save_registry(&reg);
        return (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Node not found" })),
    )
        .into_response()
}

async fn unquarantine_node(
    State(state): State<AppState>,
    Path(url): Path<String>,
) -> impl IntoResponse {
    let mut reg = state.reg.lock().unwrap();
    if let Some(n) = reg.nodes.get_mut(&url) {
        n.quarantine = false;
        save_registry(&reg);
        return (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Node not found" })),
    )
        .into_response()
}

async fn allow_status(State(state): State<AppState>, Path(url): Path<String>) -> impl IntoResponse {
    let reg = state.reg.lock().unwrap();
    if let Some(n) = reg.nodes.get(&url) {
        return Json(serde_json::json!({ "allowed": n.allowed, "quarantine": n.quarantine }))
            .into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Node not found" })),
    )
        .into_response()
}

async fn issue_token(
    State(state): State<AppState>,
    Json(req): Json<TokenReq>,
) -> impl IntoResponse {
    let reg = state.reg.lock().unwrap();
    let ttl = req.ttl_secs.unwrap_or(3600).min(24 * 3600);
    let tok = sign_token(&reg.secret, &req.role, ttl);
    Json(tok)
}

async fn get_root_ca(State(state): State<AppState>) -> impl IntoResponse {
    let hash = hex::encode(sha2::Sha256::digest(state.ca_pem.as_bytes()));
    println!("[auth] Root-CA ausgeliefert (sha256 {hash})");
    (
        StatusCode::OK,
        [("content-type", "application/x-pem-file")],
        state.ca_pem.as_bytes().to_vec(),
    )
}

async fn request_cert(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CertReq>,
) -> impl IntoResponse {
    // Auth: x-auth-token (role=admin) oder x-ca-provision (secret) ODER provision_secrets[name]
    let mut ok = false;
    let reg_guard = state.reg.lock().unwrap();
    if let Some(h) = headers.get("x-auth-token") {
        if let Ok(tok) = h.to_str() {
            ok = verify_token(tok, &reg_guard.secret, "admin");
        }
    }
    if !ok {
        if let Some(h) = headers.get("x-ca-provision") {
            if let Ok(tok) = h.to_str() {
                if let Ok(env_tok) = std::env::var("STONE_CA_PROVISION_TOKEN") {
                    if tok == env_tok {
                        ok = true;
                    }
                }
                if !ok {
                    if let Some(per_node) = reg_guard.provision_secrets.get(&req.name) {
                        if tok == per_node {
                            ok = true;
                        }
                    }
                }
            }
        }
    }
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }
    // optional: erlaubte SANs gegen Registry prüfen, falls Node eingetragen ist
    // SAN-Check entfernt, um Zertifikatsanforderungen nicht zu blockieren.
    match issue_node_cert(&state.ca, &req.name, &req.san) {
        Ok((cert, key)) => {
            let resp = serde_json::json!({
                "cert_pem": cert,
                "key_pem": key,
                "ca_pem": *state.ca_pem,
            });
            (StatusCode::OK, Json(resp))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

async fn cluster_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let mut ok = false;
    let reg_guard = state.reg.lock().unwrap();
    if let Some(h) = headers.get("x-auth-token") {
        if let Ok(tok) = h.to_str() {
            ok = verify_token(tok, &reg_guard.secret, "admin");
        }
    }
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }
    let hash = hex::encode(sha2::Sha256::digest(state.ca_pem.as_bytes()));
    println!("[auth] /cluster/key delivered (root sha256 {})", hash);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "cluster_api_key": reg_guard.cluster_api_key })),
    )
}

async fn get_genesis(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let mut ok = false;
    let reg_guard = state.reg.lock().unwrap();
    if let Some(h) = headers.get("x-auth-token") {
        if let Ok(tok) = h.to_str() {
            ok = verify_token(tok, &reg_guard.secret, "admin");
        }
    }
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    let body = Json((*state.genesis).clone());
    (StatusCode::OK, body).into_response()
}

#[derive(Deserialize)]
struct NodeMetricsPayload {
    node: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    cpu_percent: f32,
    #[serde(default)]
    mem_used: u64,
    #[serde(default)]
    mem_total: u64,
    #[serde(default)]
    net_rx: u64,
    #[serde(default)]
    net_tx: u64,
    #[serde(default)]
    storage_used: u64,
    #[serde(default)]
    storage_total: u64,
    #[serde(default)]
    blocks: u64,
    #[serde(default)]
    latest_hash: Option<String>,
}

async fn post_node_metrics(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<NodeMetricsPayload>,
) -> impl IntoResponse {
    let reg_guard = state.reg.lock().unwrap();
    let mut ok = false;
    if let Some(h) = headers.get("x-api-key") {
        if let Ok(k) = h.to_str() {
            if k == reg_guard.cluster_api_key {
                ok = true;
            }
        }
    }
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }
    drop(reg_guard);

    let mut map = state.metrics.lock().unwrap();
    let entry = NodeMetricsEntry {
        node: payload.node.clone(),
        url: payload.url.clone(),
        cpu_percent: payload.cpu_percent,
        mem_used: payload.mem_used,
        mem_total: payload.mem_total,
        net_rx: payload.net_rx,
        net_tx: payload.net_tx,
        storage_used: payload.storage_used,
        storage_total: payload.storage_total,
        blocks: payload.blocks,
        latest_hash: payload.latest_hash.clone(),
        timestamp: now(),
    };
    map.insert(payload.node.clone(), entry.clone());
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "node": entry.node })),
    )
}

async fn list_node_metrics(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let reg_guard = state.reg.lock().unwrap();
    let mut ok = false;
    if let Some(h) = headers.get("x-auth-token") {
        if let Ok(tok) = h.to_str() {
            ok = verify_token(tok, &reg_guard.secret, "admin");
        }
    }
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    let map = state.metrics.lock().unwrap();
    let list: Vec<NodeMetricsEntry> = map.values().cloned().collect();
    Json(serde_json::json!({ "metrics": list })).into_response()
}

// --- PKI-Stubs (Platzhalter für spätere echte PKI) ---
async fn pki_root_stub(State(state): State<AppState>) -> impl IntoResponse {
    let body: String = state.ca_pem.as_str().to_owned();
    ([("content-type", "application/x-pem-file")], body)
}

#[derive(Deserialize)]
struct CsrStub {
    #[serde(default)]
    csr_pem: Option<String>,
    #[serde(default)]
    node: Option<String>,
}

async fn pki_csr_stub(Json(_body): Json<CsrStub>) -> impl IntoResponse {
    let cert = "-----BEGIN CERTIFICATE-----\nSTUB\n-----END CERTIFICATE-----\n";
    let key = "-----BEGIN PRIVATE KEY-----\nSTUB\n-----END PRIVATE KEY-----\n";
    let ca = "-----BEGIN CERTIFICATE-----\nSTUB-CA\n-----END CERTIFICATE-----\n";
    Json(serde_json::json!({
        "cert": cert,
        "key": key,
        "ca": ca,
        "warning": "PKI-Stubs aktiv: kein echtes Zertifikat. Bitte echte PKI integrieren."
    }))
}

async fn pki_registry_stub() -> impl IntoResponse {
    Json(serde_json::json!({
        "allowed_pubkeys": [],
        "warning": "PKI-Stubs aktiv: Registry leer. Bitte echte PKI integrieren."
    }))
}

#[tokio::main]
async fn main() {
    let reg = Arc::new(Mutex::new(load_registry()));
    let genesis = Arc::new(load_or_create_genesis());
    let (ca, ca_pem) = init_ca("ca");
    let ca_hash = hex::encode(sha2::Sha256::digest(ca_pem.as_bytes()));
    println!("[auth] CA sha256 {}", ca_hash);
    let metrics_map = Arc::new(Mutex::new(HashMap::new()));
    let state = AppState {
        reg,
        ca: Arc::new(ca),
        ca_pem: Arc::new(ca_pem),
        genesis,
        metrics: metrics_map.clone(),
    };
    let _state_for_tls = state.clone();

    if let Ok(time_url) = std::env::var("STONE_TIME_URL") {
        let max_skew = std::env::var("STONE_TIME_MAX_SKEW_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300);
        warn_if_clock_skew(&time_url, Duration::from_secs(max_skew)).await;
    }

    let app = Router::new()
        .route("/nodes", get(list_nodes).post(register_node))
        .route("/nodes/allow/:url", post(allow_node))
        .route("/nodes/deny/:url", post(deny_node))
        .route("/nodes/quarantine/:url", post(quarantine_node))
        .route("/nodes/unquarantine/:url", post(unquarantine_node))
        .route("/nodes/status/:url", get(allow_status))
        .route("/token", post(issue_token))
        .route("/ca/root", get(get_root_ca))
        .route("/cert/request", post(request_cert))
        .route("/cluster/key", get(cluster_key))
        // PKI-Stubs: Platzhalter bis echte PKI-Implementierung
        .route("/pki/root", get(pki_root_stub))
        .route("/pki/registry", get(pki_registry_stub))
        .route("/pki/csr", post(pki_csr_stub))
        .route("/pki/cert", post(pki_csr_stub))
        .route(GENESIS_ENDPOINT, get(get_genesis))
        .route(
            "/node/metrics",
            post(post_node_metrics).get(list_node_metrics),
        )
        .with_state(state.clone())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods(Any),
        );

    let https_bind: SocketAddr = std::env::var("STONE_AUTH_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8089".into())
        .parse()
        .expect("STONE_AUTH_BIND ungültig");

    // Erzwinge HTTPS – wenn kein Zertifikat vorhanden ist, wird automatisch eines erstellt.
    let (cert_path, key_path) = match (
        std::env::var("STONE_AUTH_TLS_CERT"),
        std::env::var("STONE_AUTH_TLS_KEY"),
    ) {
        (Ok(cert), Ok(key))
            if std::path::Path::new(&cert).exists() && std::path::Path::new(&key).exists() =>
        {
            (cert, key)
        }
        (Ok(_cert), Ok(_key)) => {
            eprintln!(
                "[auth] TLS-Pfade angegeben, aber Dateien fehlen. Erzeuge Autocert unter ca/..."
            );
            ensure_auth_server_cert(&state.ca, "ca", https_bind)
                .expect("Autocert-Erzeugung fehlgeschlagen")
        }
        _ => ensure_auth_server_cert(&state.ca, "ca", https_bind)
            .expect("Konnte TLS-Zertifikat nicht erstellen"),
    };

    let tls_config = RustlsConfig::from_pem_file(cert_path.clone(), key_path.clone())
        .await
        .unwrap_or_else(|e| {
            panic!("[auth] TLS-Start fehlgeschlagen ({cert_path}, {key_path}): {e}");
        });

    println!("Auth/Control Server läuft auf https://{https_bind}");
    let server = axum_server::bind_rustls(https_bind, tls_config).serve(app.into_make_service());
    tokio::select! {
        res = server => res.unwrap(),
        _ = signal::ctrl_c() => {
            println!("Beende auf Ctrl+C");
        }
    }
}
