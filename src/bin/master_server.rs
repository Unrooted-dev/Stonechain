//! Stone Master Node – API Server
//!
//! Stellt eine vollständige REST + WebSocket API für die externe Web-UI bereit.
//! Kein lokales GUI – alle Steuerung erfolgt über die vom Benutzer entwickelte Webseite.
//!
//! API-Übersicht:
//!   GET    /api/v1/status                    – Node- & Chain-Status
//!   GET    /api/v1/health                    – Einfacher Healthcheck (kein Auth)
//!   GET    /api/v1/metrics                   – Master-Node-Metriken
//!   GET    /api/v1/blocks                    – Alle Blöcke (paginiert)
//!   GET    /api/v1/blocks/:index             – Block nach Index
//!   GET    /api/v1/documents                 – Alle aktiven Dokumente (admin)
//!   GET    /api/v1/documents/user/:user_id   – Dokumente eines Nutzers
//!   GET    /api/v1/documents/:doc_id         – Dokument per ID
//!   GET    /api/v1/documents/:doc_id/history – Versionshistorie
//!   GET    /api/v1/documents/:doc_id/data    – Roh-Bytes (Chunk-Rekonstruktion)
//!   POST   /api/v1/documents                       – Dokument hochladen (Multipart)
//!   POST   /api/v1/documents/:doc_id/transfer       – Eigentum übertragen
//!   DELETE /api/v1/documents/:doc_id               – Soft-Delete
//!   GET    /api/v1/peers                     – Peer-Liste
//!   POST   /api/v1/peers                     – Peer hinzufügen
//!   DELETE /api/v1/peers/:idx                – Peer entfernen
//!   POST   /api/v1/sync                      – Manuelle Synchronisation
//!   POST   /api/v1/auth/signup               – Neuen Nutzer anlegen
//!   POST   /api/v1/auth/login                – Phrase-Login
//!   GET    /api/v1/chain/verify              – Chain-Integrität prüfen
//!   GET    /ws                               – WebSocket Event-Stream

use axum::{
    Router,
    body::Body,
    extract::{
        DefaultBodyLimit, Multipart, Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, atomic::Ordering},
    time::{Duration, Instant},
};
use stone::{
    auth::{
        User, create_user_with_phrase, load_users, resolve_phrase, save_users,
    },
    blockchain::{
        ChunkRef, data_dir, CHUNK_SIZE, Document, DocumentTombstone, NodeRole,
    },
    consensus::{
        ValidatorInfo, VoteMessage,
        load_or_create_validator_key, local_validator_pubkey_hex,
        ForkCandidate, resolve_fork, detect_forks,
    },
    crypto::{
        NodeKeyPair, encrypt_document, decrypt_document, sign_document,
        verify_document_signature, load_public_key, EncryptedBlob,
    },
    master_node::{
        AddPeerRequest, MasterNodeState, NodeEvent, NodeStatusResponse, PeerInfo, PeerStatus,
    },
    network::{NetworkHandle, start_network},
    storage::ChunkStore,
};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};

// ─── Konstanten ──────────────────────────────────────────────────────────────

const MAX_UPLOAD_BYTES: usize = 5 * 1024 * 1024 * 1024; // 5 GiB
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const AUTO_SYNC_INTERVAL: Duration = Duration::from_secs(30);
fn peers_file() -> String { format!("{}/peers.json", data_dir()) }

// ─── Shared App State ────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    node: Arc<MasterNodeState>,
    users: Arc<Mutex<Vec<User>>>,
    api_key: Arc<String>,
    /// P2P-Netzwerk-Handle (None = P2P deaktiviert)
    network: Option<NetworkHandle>,
}

// ─── API-Key Authentifizierung ────────────────────────────────────────────────

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn resolve_user_by_key(key: &str, users: &Arc<Mutex<Vec<User>>>, admin_key: &str) -> Option<User> {
    if key == admin_key {
        return Some(User {
            id: "admin".into(),
            name: "admin".into(),
            api_key: key.to_string(),
            phrase_hash: String::new(),
            quota_bytes: u64::MAX,
        });
    }
    users
        .lock()
        .unwrap()
        .iter()
        .find(|u| u.api_key == key)
        .cloned()
}

fn require_user(headers: &HeaderMap, state: &AppState) -> Result<User, Response> {
    let key = extract_api_key(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "x-api-key Header fehlt"})),
        )
            .into_response()
    })?;
    resolve_user_by_key(&key, &state.users, &state.api_key).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "Ungültiger API-Key"})),
        )
            .into_response()
    })
}

fn require_admin(headers: &HeaderMap, state: &AppState) -> Result<(), Response> {
    let key = extract_api_key(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "x-api-key Header fehlt"})),
        )
            .into_response()
    })?;
    if key == state.api_key.as_str() {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Admin-Rechte erforderlich"})),
        )
            .into_response())
    }
}

// ─── API-Key laden ────────────────────────────────────────────────────────────

fn load_api_key() -> String {
    // Priorität 1: STONE_CLUSTER_API_KEY (gesetzt von stone_init.py via .env)
    // Priorität 2: STONE_API_KEY (Legacy/manuell)
    // Priorität 3: stone_data/token.bin
    // Priorität 4: Neu generieren und in token.bin speichern
    for var in ["STONE_CLUSTER_API_KEY", "STONE_API_KEY"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                println!("[auth] API-Key aus Umgebungsvariable {var}");
                return v;
            }
        }
    }
    let token_path = format!("{}/token.bin", data_dir());
    if let Ok(data) = std::fs::read_to_string(&token_path) {
        let t = data.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    // Erster Start: neuen Key generieren und speichern
    let key = generate_api_key();
    let _ = std::fs::create_dir_all(data_dir());
    if let Err(e) = std::fs::write(&token_path, &key) {
        eprintln!("[auth] WARNUNG: API-Key konnte nicht gespeichert werden: {e}");
    } else {
        println!("[auth] Neuer Admin-API-Key generiert und gespeichert: {token_path}");
        println!("[auth] ╔══════════════════════════════════════════════════╗");
        println!("[auth] ║  Admin API-Key: {key}  ║");
        println!("[auth] ╚══════════════════════════════════════════════════╝");
        println!("[auth] Setze x-api-key: {key} in deinen Web-UI Anfragen.");
    }
    key
}

fn generate_api_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let mut h = Sha256::new();
    h.update(b"stone-master-key-v1-");
    h.update(ts.to_le_bytes());
    // PID als zusätzliche Entropie
    h.update(std::process::id().to_le_bytes());
    // Hostname
    if let Ok(hn) = hostname::get() {
        h.update(hn.to_string_lossy().as_bytes());
    }
    format!("sk_{}", hex::encode(h.finalize()))
}

// ─── Chunk-Verwaltung ─────────────────────────────────────────────────────────

fn chunk_data(data: &[u8]) -> Result<Vec<ChunkRef>, String> {
    let store = ChunkStore::new().map_err(|e| e.to_string())?;
    store.write_chunks(data, CHUNK_SIZE).map_err(|e| e.to_string())
}

fn reconstruct_document_data(doc: &Document) -> Result<Vec<u8>, String> {
    let store = ChunkStore::new().map_err(|e| e.to_string())?;
    store.reconstruct_document(doc).map_err(|e| e.to_string())
}

// ─── Peer-Persistenz ─────────────────────────────────────────────────────────

fn save_peers(peers: &[PeerInfo]) {
    let _ = std::fs::create_dir_all(data_dir());
    if let Ok(json) = serde_json::to_string_pretty(peers) {
        let _ = std::fs::write(peers_file(), json);
    }
}

fn load_peers_from_disk() -> Vec<PeerInfo> {
    if let Ok(data) = std::fs::read_to_string(peers_file()) {
        if let Ok(list) = serde_json::from_str::<Vec<PeerInfo>>(&data) {
            return list;
        }
    }
    Vec::new()
}

// ─── Route-Handler ────────────────────────────────────────────────────────────

/// GET /api/v1/health – Kein Auth erforderlich
async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let summary = state.node.chain_summary();
    (
        StatusCode::OK,
        axum::Json(json!({
            "status": "ok",
            "node_id": state.node.node_id,
            "role": format!("{:?}", state.node.role),
            "block_height": summary.block_height,
            "latest_hash": &summary.latest_hash[..12.min(summary.latest_hash.len())],
        })),
    )
}

/// GET /api/v1/status – Vollständiger Node-Status (Admin)
async fn handle_status(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let resp = NodeStatusResponse {
        node_id: state.node.node_id.clone(),
        role: format!("{:?}", state.node.role),
        chain: state.node.chain_summary(),
        metrics: state.node.snapshot_metrics(),
        peers: state.node.get_peers(),
        started_at: state.node.started_at,
    };
    Ok((StatusCode::OK, axum::Json(resp)))
}

/// GET /api/v1/metrics
async fn handle_metrics(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    Ok((StatusCode::OK, axum::Json(state.node.snapshot_metrics())))
}

/// GET /api/v1/network — P2P-Netzwerkstatus + Server-Ressourcen
async fn handle_network_stats(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    // ── P2P-Status vom Swarm holen ─────────────────────────────────────────
    let net = if let Some(h) = &state.network {
        h.get_status().await
    } else {
        None
    };

    let (local_peer_id, connected_peers, total_known, mesh_size, p2p_peers) =
        if let Some(ref s) = net {
            (
                s.local_peer_id.clone(),
                s.connected_peers,
                s.total_known_peers,
                s.gossipsub_mesh_size,
                s.peers.iter().map(|p| json!({
                    "peer_id":        p.peer_id,
                    "addresses":      p.addresses,
                    "connected":      p.connected,
                    "agent":          p.agent_version,
                    "last_seen_secs": p.last_seen_ago_secs,
                    "blocks_received": p.blocks_received,
                    "in_mesh":        p.in_gossipsub_mesh,
                })).collect::<Vec<_>>(),
            )
        } else {
            (String::from("–"), 0, 0, 0, vec![])
        };

    // ── Server-Ressourcen (plattformübergreifend via /proc oder sysinfo) ──
    // Uptime in Sekunden
    let uptime_secs = (chrono::Utc::now().timestamp() - state.node.started_at) as u64;

    // Prozess-Speicher (RSS) via /proc/self/status auf Linux, auf macOS via sysctl
    let memory_rss_kb: u64 = {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        { 0 }
    };

    // CPU-Zeit (user + system) in Millisekunden via /proc/self/stat
    let cpu_time_ms: u64 = {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/self/stat")
                .unwrap_or_default()
                .split_whitespace()
                .enumerate()
                .filter(|(i, _)| *i == 13 || *i == 14) // utime + stime (CLK_TCK=100)
                .map(|(_, v)| v.parse::<u64>().unwrap_or(0))
                .sum::<u64>() * 10 // CLK_TCK=100 → *10 = ms
        }
        #[cfg(not(target_os = "linux"))]
        { 0 }
    };

    // Disk-Nutzung des stone_data-Verzeichnisses
    let data_dir_bytes: u64 = {
        fn dir_size(path: &std::path::Path) -> u64 {
            std::fs::read_dir(path)
                .map(|e| e.filter_map(|e| e.ok())
                    .map(|e| {
                        let meta = e.metadata().ok();
                        if meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) {
                            dir_size(&e.path())
                        } else {
                            meta.map(|m| m.len()).unwrap_or(0)
                        }
                    }).sum())
                .unwrap_or(0)
        }
        dir_size(std::path::Path::new(&stone::blockchain::data_dir()))
    };

    // Metriken
    let m = state.node.snapshot_metrics();

    Ok((StatusCode::OK, axum::Json(json!({
        "p2p": {
            "enabled":          state.network.is_some(),
            "local_peer_id":    local_peer_id,
            "connected_peers":  connected_peers,
            "total_known":      total_known,
            "gossipsub_mesh":   mesh_size,
            "peers":            p2p_peers,
        },
        "server": {
            "uptime_secs":      uptime_secs,
            "uptime_human":     format_uptime(uptime_secs),
            "memory_rss_kb":    memory_rss_kb,
            "cpu_time_ms":      cpu_time_ms,
            "data_dir_bytes":   data_dir_bytes,
        },
        "chain": {
            "blocks":           m.peers_total,   // peers_total als Proxy-Feld
            "requests_total":   m.requests_total,
            "sync_runs":        m.sync_runs,
            "sync_success":     m.sync_success,
            "sync_failure":     m.sync_failure,
            "docs_uploaded":    m.documents_uploaded,
            "ws_connections":   m.ws_connections,
        }
    }))))
}

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 { format!("{d}d {h}h {m}m") }
    else if h > 0 { format!("{h}h {m}m {s}s") }
    else if m > 0 { format!("{m}m {s}s") }
    else { format!("{s}s") }
}
async fn handle_verify(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let chain = state.node.chain.lock().unwrap();
    let valid = chain.verify(&state.node.cluster_key);
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "valid": valid,
            "blocks": chain.blocks.len(),
        })),
    ))
}

// ─── Blöcke ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PaginationQuery {
    #[serde(default)]
    page: Option<u64>,
    #[serde(default)]
    per_page: Option<u64>,
}

/// GET /api/v1/blocks
async fn handle_list_blocks(
    headers: HeaderMap,
    Query(q): Query<PaginationQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    // Block-Liste ist für Peer-Sync öffentlich zugänglich.
    // Wenn ein x-api-key gesetzt ist, muss er gültig sein (Admin oder User).
    // Kein Key → trotzdem erlaubt (read-only, Blockchain-Daten sind öffentlich).
    if let Some(key) = extract_api_key(&headers) {
        if key != state.api_key.as_str() {
            // Kein Admin-Key → als normalen User prüfen
            if resolve_user_by_key(&key, &state.users, &state.api_key).is_none() {
                return Err((
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({"error": "Ungültiger API-Key"})),
                )
                    .into_response());
            }
        }
    }
    let chain = state.node.chain.lock().unwrap();
    let per_page = q.per_page.unwrap_or(50).min(500) as usize;
    let page = q.page.unwrap_or(0) as usize;
    let total = chain.blocks.len();
    let blocks: Vec<stone::master_node::BlockResponse> = chain
        .blocks
        .iter()
        .rev()
        .skip(page * per_page)
        .take(per_page)
        .map(|b| stone::master_node::BlockResponse::from(b))
        .collect();
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "blocks": blocks,
        })),
    ))
}

/// GET /api/v1/blocks/:index
async fn handle_get_block(
    headers: HeaderMap,
    Path(index): Path<u64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    // Ebenfalls für Peer-Sync öffentlich (Block-Metadaten, kein Chunk-Inhalt)
    if let Some(key) = extract_api_key(&headers) {
        if key != state.api_key.as_str() {
            if resolve_user_by_key(&key, &state.users, &state.api_key).is_none() {
                return Err((
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({"error": "Ungültiger API-Key"})),
                )
                    .into_response());
            }
        }
    }
    let chain = state.node.chain.lock().unwrap();
    let block = chain
        .blocks
        .iter()
        .find(|b| b.index == index)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Block nicht gefunden"})),
            )
                .into_response()
        })?;
    Ok((
        StatusCode::OK,
        axum::Json(stone::master_node::BlockResponse::from(block)),
    ))
}

// ─── Dokumente ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DocQuery {
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    page: Option<u64>,
    #[serde(default)]
    per_page: Option<u64>,
}

/// GET /api/v1/documents – Alle aktiven Dokumente (Admin)
async fn handle_list_documents(
    headers: HeaderMap,
    Query(q): Query<DocQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let chain = state.node.chain.lock().unwrap();
    let per_page = q.per_page.unwrap_or(50).min(500) as usize;
    let page = q.page.unwrap_or(0) as usize;

    let mut docs: Vec<stone::master_node::DocumentResponse> = chain
        .list_all_documents()
        .into_iter()
        .filter(|(d, _)| {
            if let Some(ref tag) = q.tag {
                if !d.tags.contains(tag) {
                    return false;
                }
            }
            if let Some(ref ct) = q.content_type {
                if &d.content_type != ct {
                    return false;
                }
            }
            true
        })
        .map(|(d, _)| stone::master_node::DocumentResponse::from(d))
        .collect();

    docs.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let total = docs.len();
    let paginated: Vec<_> = docs.into_iter().skip(page * per_page).take(per_page).collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "documents": paginated,
        })),
    ))
}

/// GET /api/v1/documents/user/:user_id
async fn handle_list_user_documents(
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(q): Query<DocQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let requesting_user = require_user(&headers, &state)?;
    // Nur Admin oder der Nutzer selbst darf die Dokumente sehen
    if requesting_user.id != "admin" && requesting_user.id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Kein Zugriff auf fremde Dokumente"})),
        )
            .into_response());
    }

    let chain = state.node.chain.lock().unwrap();
    let per_page = q.per_page.unwrap_or(50).min(500) as usize;
    let page = q.page.unwrap_or(0) as usize;

    let mut docs: Vec<stone::master_node::DocumentResponse> = chain
        .list_documents_for_user(&user_id)
        .into_iter()
        .map(|(d, _)| stone::master_node::DocumentResponse::from(d))
        .collect();

    docs.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let total = docs.len();
    let paginated: Vec<_> = docs.into_iter().skip(page * per_page).take(per_page).collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "documents": paginated,
        })),
    ))
}

/// GET /api/v1/documents/:doc_id
async fn handle_get_document(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;
    let chain = state.node.chain.lock().unwrap();
    let (doc, block_index) = chain.find_document(&doc_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Dokument nicht gefunden"})),
        )
            .into_response()
    })?;

    if user.id != "admin" && doc.owner != user.id {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Kein Zugriff"})),
        )
            .into_response());
    }

    let resp = stone::master_node::DocumentResponse::from(doc);
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "document": resp,
            "block_index": block_index,
        })),
    ))
}

/// GET /api/v1/documents/:doc_id/history
async fn handle_document_history(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;
    let chain = state.node.chain.lock().unwrap();

    let history: Vec<_> = chain
        .document_history(&doc_id)
        .into_iter()
        .filter(|(d, _)| user.id == "admin" || d.owner == user.id)
        .map(|(d, block_idx)| {
            json!({
                "block_index": block_idx,
                "version": d.version,
                "updated_at": d.updated_at,
                "size": d.size,
                "title": d.title,
            })
        })
        .collect();

    if history.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Dokument nicht gefunden"})),
        )
            .into_response());
    }

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "doc_id": doc_id,
            "history": history,
        })),
    ))
}

/// GET /api/v1/documents/:doc_id/data – Rohdaten des Dokuments zurückgeben
async fn handle_get_document_data(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Response, Response> {
    let user = require_user(&headers, &state)?;
    let (doc_owned, content_type) = {
        let chain = state.node.chain.lock().unwrap();
        let (doc, _) = chain.find_document(&doc_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Dokument nicht gefunden"})),
            )
                .into_response()
        })?;
        if user.id != "admin" && doc.owner != user.id {
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "Kein Zugriff"})),
            )
                .into_response());
        }
        (doc.clone(), doc.content_type.clone())
    };

    // Rohdaten aus Chunks rekonstruieren
    let raw_data = reconstruct_document_data(&doc_owned).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": e})),
        )
            .into_response()
    })?;

    // Signatur prüfen (falls vorhanden)
    if !doc_owned.doc_signature.is_empty() && !doc_owned.public_key_hint.is_empty() {
        // Public Key des Besitzers laden
        if let Some(pub_key) = load_public_key(&doc_owned.owner) {
            if let Err(e) = verify_document_signature(
                &pub_key,
                &doc_owned.doc_signature,
                &doc_owned.doc_id,
                doc_owned.version,
                doc_owned.size,
                &doc_owned.content_type,
            ) {
                eprintln!("[crypto] Signaturprüfung fehlgeschlagen für {}: {e}", doc_owned.doc_id);
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    axum::Json(json!({"error": "Dokument-Signatur ungültig – mögliche Manipulation"})),
                )
                    .into_response());
            }
        }
    }

    // Entschlüsseln falls verschlüsselt
    let plaintext = if doc_owned.encrypted && !doc_owned.encryption_meta.is_empty() {
        // Schlüsselpaar des Besitzers laden
        let keypair = NodeKeyPair::load(&doc_owned.owner).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": format!("Schlüssel laden: {e}")})),
            )
                .into_response()
        })?;
        match keypair {
            Some(kp) => {
                // EncryptedBlob aus Metadaten + Ciphertext aus raw_data zusammensetzen
                let mut blob: EncryptedBlob = serde_json::from_str(&doc_owned.encryption_meta)
                    .map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(json!({"error": "Verschlüsselungs-Metadaten korrupt"})),
                        )
                            .into_response()
                    })?;
                // Ciphertext kommt aus den Chunks (raw_data)
                blob.ciphertext = hex::encode(&raw_data);
                decrypt_document(&kp, &blob).map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(json!({"error": format!("Entschlüsselung: {e}")})),
                    )
                        .into_response()
                })?
            }
            None => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(json!({"error": "Privater Schlüssel nicht gefunden"})),
                )
                    .into_response());
            }
        }
    } else {
        raw_data
    };

    Ok(Response::builder()
        .status(200)
        .header("content-type", content_type)
        .header(
            "content-disposition",
            format!("attachment; filename=\"{}\"", doc_owned.title),
        )
        .body(Body::from(plaintext))
        .unwrap())
}

/// POST /api/v1/documents – Dokument hochladen (Multipart)
///
/// Erwartet Felder:
///   - `file`         – Pflicht: die Datei-Bytes
///   - `title`        – Optional: Anzeigename
///   - `doc_id`       – Optional: für Updates (neue Version)
///   - `tags`         – Optional: kommasepariert
///   - `metadata`     – Optional: JSON-String
///   - `content_type` – Optional: MIME-Type (sonst auto-detect)
async fn handle_upload_document(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;

    let mut file_data: Option<Vec<u8>> = None;
    let mut title: Option<String> = None;
    let mut doc_id: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut metadata: serde_json::Value = serde_json::Value::Null;
    let mut content_type_override: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or("") {
            "file" => {
                if title.is_none() {
                    title = field.file_name().map(|s| s.to_string());
                    content_type_override = field
                        .content_type()
                        .map(|s| s.to_string());
                }
                file_data = Some(field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({"error": format!("Datei lesen fehlgeschlagen: {e}")})),
                    )
                        .into_response()
                })?.to_vec());
            }
            "title" => {
                title = Some(
                    field.text().await.map_err(|e| {
                        (
                            StatusCode::BAD_REQUEST,
                            axum::Json(json!({"error": format!("Feld lesen: {e}")})),
                        )
                            .into_response()
                    })?,
                );
            }
            "doc_id" => {
                doc_id = Some(
                    field.text().await.map_err(|e| {
                        (
                            StatusCode::BAD_REQUEST,
                            axum::Json(json!({"error": format!("Feld lesen: {e}")})),
                        )
                            .into_response()
                    })?,
                );
            }
            "tags" => {
                let raw = field.text().await.unwrap_or_default();
                tags = raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "metadata" => {
                let raw = field.text().await.unwrap_or_default();
                metadata = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
            }
            "content_type" => {
                content_type_override = Some(field.text().await.unwrap_or_default());
            }
            _ => {}
        }
    }

    let file_bytes = file_data.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Kein 'file' Feld gefunden"})),
        )
            .into_response()
    })?;

    let title = title.unwrap_or_else(|| "Untitled".to_string());
    let content_type = content_type_override
        .unwrap_or_else(|| "application/octet-stream".to_string());

    // Quota prüfen
    let current_usage = {
        let chain = state.node.chain.lock().unwrap();
        chain.user_usage_bytes(&user.id)
    };
    if current_usage + file_bytes.len() as u64 > user.quota_bytes {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Speicher-Quota überschritten"})),
        )
            .into_response());
    }

    // Chunks speichern (ggf. verschlüsselt)
    // Schlüsselpaar des Nutzers laden oder erstellen
    let keypair = NodeKeyPair::load_or_create(&user.id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": format!("Schlüsselpaar-Fehler: {e}")})),
        )
            .into_response()
    })?;

    // Dokument verschlüsseln (AES-256-GCM via ECDH X25519)
    let (stored_bytes, encrypted, encryption_meta) = {
        match encrypt_document(&keypair.public_key_hex, &file_bytes) {
            Ok(blob) => {
                // Ciphertext als Nutzdaten (Chunk-Bytes) speichern
                let cipher_bytes = hex::decode(&blob.ciphertext).unwrap_or_default();
                // Im Block-Metadaten NUR ephemeral_pubkey + nonce speichern,
                // NICHT den Ciphertext (der ist bereits in den Chunks auf Disk).
                let meta_only = EncryptedBlob {
                    ephemeral_pubkey: blob.ephemeral_pubkey.clone(),
                    nonce: blob.nonce.clone(),
                    ciphertext: String::new(), // leer – Ciphertext in Chunks
                };
                let meta = serde_json::to_string(&meta_only).unwrap_or_default();
                (cipher_bytes, true, meta)
            }
            Err(e) => {
                eprintln!("[crypto] Verschlüsselung fehlgeschlagen: {e} – speichere unverschlüsselt");
                (file_bytes.clone(), false, String::new())
            }
        }
    };

    let chunks = chunk_data(&stored_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": e})),
        )
            .into_response()
    })?;

    // Version bestimmen
    let version = {
        let chain = state.node.chain.lock().unwrap();
        if let Some(id) = &doc_id {
            chain
                .find_document(id)
                .map(|(d, _)| d.version + 1)
                .unwrap_or(1)
        } else {
            1
        }
    };

    let new_doc_id = doc_id.unwrap_or_else(|| {
        let mut h = Sha256::new();
        h.update(user.id.as_bytes());
        h.update(title.as_bytes());
        h.update(&chrono::Utc::now().timestamp().to_le_bytes());
        hex::encode(h.finalize())[..24].to_string()
    });

    // Dokument signieren (Ed25519 über doc_id | version | size | content_type)
    let doc_signature = sign_document(
        &keypair,
        &new_doc_id,
        version,
        file_bytes.len() as u64,
        &content_type,
    );
    let public_key_hint = keypair.public_key_hex[..16].to_string();

    let doc = Document {
        doc_id: new_doc_id.clone(),
        title: title.clone(),
        content_type,
        tags,
        metadata,
        version,
        size: file_bytes.len() as u64,
        chunks,
        deleted: false,
        updated_at: chrono::Utc::now().timestamp(),
        owner: user.id.clone(),
        doc_signature,
        public_key_hint,
        encrypted,
        encryption_meta,
    };

    let block = state
        .node
        .commit_documents(vec![doc], vec![], user.id.clone(), user.id.clone())
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": e})),
            )
                .into_response()
        })?;

    // Neuen Block per P2P an alle Peers broadcasten + Chain-Count aktualisieren
    if let Some(ref network) = state.network {
        let block_clone = block.clone();
        let network_clone = network.clone();
        let chain_count = state.node.chain.lock().unwrap().blocks.len() as u64;
        tokio::spawn(async move {
            network_clone.broadcast_block(block_clone).await;
            network_clone.set_chain_count(chain_count).await;
        });
    }

    state.node.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "doc_id": new_doc_id,
            "block_index": block.index,
            "block_hash": block.hash,
            "version": version,
            "title": title,
            "encrypted": encrypted,
            "signed": true,
        })),
    ))
}

/// DELETE /api/v1/documents/:doc_id – Soft-Delete
async fn handle_delete_document(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;

    // Dokument-Besitzer prüfen
    {
        let chain = state.node.chain.lock().unwrap();
        let (doc, _) = chain.find_document(&doc_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Dokument nicht gefunden"})),
            )
                .into_response()
        })?;
        if user.id != "admin" && doc.owner != user.id {
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "Kein Zugriff"})),
            )
                .into_response());
        }
    }

    let tombstone = DocumentTombstone {
        block_index: 0, // wird beim commit gesetzt
        doc_id: doc_id.clone(),
        owner: user.id.clone(),
    };

    let block = state
        .node
        .commit_documents(vec![], vec![tombstone], user.id.clone(), user.id.clone())
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": e})),
            )
                .into_response()
        })?;

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "deleted": true,
            "doc_id": doc_id,
            "block_index": block.index,
        })),
    ))
}

// ─── Dokument-Metadata-Update ────────────────────────────────────────────────

#[derive(Deserialize)]
struct PatchDocumentRequest {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    content_type: Option<String>,
}

/// PATCH /api/v1/documents/:doc_id – Metadaten aktualisieren ohne Re-Upload
async fn handle_patch_document(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<PatchDocumentRequest>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;

    let updated_doc = {
        let chain = state.node.chain.lock().unwrap();
        let (doc, _) = chain.find_document(&doc_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Dokument nicht gefunden"})),
            )
                .into_response()
        })?;
        if user.id != "admin" && doc.owner != user.id {
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "Kein Zugriff"})),
            )
                .into_response());
        }
        Document {
            title: req.title.unwrap_or_else(|| doc.title.clone()),
            tags: req.tags.unwrap_or_else(|| doc.tags.clone()),
            metadata: req.metadata.unwrap_or_else(|| doc.metadata.clone()),
            content_type: req.content_type.unwrap_or_else(|| doc.content_type.clone()),
            version: doc.version + 1,
            updated_at: chrono::Utc::now().timestamp(),
            // Unveränderliche Felder + Krypto-Felder beibehalten
            doc_id: doc.doc_id.clone(),
            size: doc.size,
            chunks: doc.chunks.clone(),
            deleted: false,
            owner: doc.owner.clone(),
            doc_signature: doc.doc_signature.clone(),
            public_key_hint: doc.public_key_hint.clone(),
            encrypted: doc.encrypted,
            encryption_meta: doc.encryption_meta.clone(),
        }
    };

    let block = state.node.commit_documents(
        vec![updated_doc.clone()],
        vec![],
        user.id.clone(),
        user.id.clone(),
    ).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": e})),
        )
            .into_response()
    })?;

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "doc_id": updated_doc.doc_id,
            "version": updated_doc.version,
            "block_index": block.index,
            "updated": true,
        })),
    ))
}

// ─── Dokument-Transfer ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TransferDocumentRequest {
    /// Ziel-User-ID (nicht der Name, die interne ID)
    to_user_id: String,
}

/// POST /api/v1/documents/:doc_id/transfer
///
/// Überträgt das Eigentum eines Dokuments an einen anderen Nutzer.
///
/// Regeln:
///  - Nur der aktuelle Owner (oder Admin) darf übertragen.
///  - Der Zielnutzer muss existieren.
///  - Das Dokument darf nicht gelöscht sein.
///  - Ein neuer Block wird mit dem aktualisierten `owner`-Feld committed.
///  - Die Chunks/Bytes bleiben unverändert; nur Metadaten in der Chain ändern sich.
async fn handle_transfer_document(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<TransferDocumentRequest>,
) -> Result<impl IntoResponse, Response> {
    let caller = require_user(&headers, &state)?;

    let to_id = req.to_user_id.trim().to_string();
    if to_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "to_user_id darf nicht leer sein"})),
        )
            .into_response());
    }

    // Ziel-User muss existieren (oder ist "admin")
    let target_exists = {
        to_id == "admin"
            || state
                .users
                .lock()
                .unwrap()
                .iter()
                .any(|u| u.id == to_id)
    };
    if !target_exists {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": format!("Zielnutzer '{}' nicht gefunden", to_id)})),
        )
            .into_response());
    }

    // Dokument laden + Zugriff prüfen
    // Wir clonen sofort, damit der MutexGuard vor den ?-Propagierungen wegfällt.
    let current_doc: Document = {
        let chain = state.node.chain.lock().unwrap();
        let maybe = chain.find_document(&doc_id).map(|(d, _)| d.clone());
        drop(chain); // Lock explizit freigeben bevor wir Fehler propagieren
        maybe.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Dokument nicht gefunden"})),
            )
                .into_response()
        })?
    };

    if current_doc.deleted {
        return Err((
            StatusCode::GONE,
            axum::Json(json!({"error": "Dokument wurde gelöscht"})),
        )
            .into_response());
    }
    if caller.id != "admin" && current_doc.owner != caller.id {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Nur der Eigentümer kann ein Dokument übertragen"})),
        )
            .into_response());
    }
    if current_doc.owner == to_id {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Dokument gehört diesem Nutzer bereits"})),
        )
            .into_response());
    }

    // Neues Dokument-Objekt mit aktualisiertem Owner + erhöhter Version
    let transferred_doc = Document {
        owner:      to_id.clone(),
        version:    current_doc.version + 1,
        updated_at: chrono::Utc::now().timestamp(),
        // Alle übrigen Felder beibehalten
        doc_id:          current_doc.doc_id.clone(),
        title:           current_doc.title.clone(),
        content_type:    current_doc.content_type.clone(),
        tags:            current_doc.tags.clone(),
        metadata:        current_doc.metadata.clone(),
        size:            current_doc.size,
        chunks:          current_doc.chunks.clone(),
        deleted:         false,
        doc_signature:   current_doc.doc_signature.clone(),
        public_key_hint: current_doc.public_key_hint.clone(),
        encrypted:       current_doc.encrypted,
        encryption_meta: current_doc.encryption_meta.clone(),
    };

    let block = state
        .node
        .commit_documents(
            vec![transferred_doc],
            vec![],
            caller.id.clone(),
            caller.id.clone(),
        )
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": e})),
            )
                .into_response()
        })?;

    // P2P-Broadcast
    if let Some(ref network) = state.network {
        let block_clone  = block.clone();
        let network_clone = network.clone();
        let chain_count  = state.node.chain.lock().unwrap().blocks.len() as u64;
        tokio::spawn(async move {
            network_clone.broadcast_block(block_clone).await;
            network_clone.set_chain_count(chain_count).await;
        });
    }

    state.node.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "transferred": true,
            "doc_id":      doc_id,
            "from_user":   caller.id,
            "to_user":     to_id,
            "version":     block.index,
            "block_index": block.index,
            "block_hash":  block.hash,
        })),
    ))
}

// ─── Dokument-Suche ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    page: Option<u64>,
    #[serde(default)]
    per_page: Option<u64>,
}

/// GET /api/v1/documents/search – Volltextsuche
async fn handle_search_documents(
    headers: HeaderMap,
    Query(q): Query<SearchQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;

    let per_page = q.per_page.unwrap_or(50).min(500) as usize;
    let page = q.page.unwrap_or(0) as usize;

    let query_text = q.q.as_deref().unwrap_or("").to_lowercase();

    let chain = state.node.chain.lock().unwrap();

    let mut docs: Vec<stone::master_node::DocumentResponse> = chain
        .list_all_documents()
        .into_iter()
        .filter(|(d, _)| {
            // Zugriffssteuerung: User sieht nur eigene Dokumente, Admin alles
            if user.id != "admin" && d.owner != user.id {
                return false;
            }
            // Owner-Filter (Admin-only sinnvoll)
            if let Some(ref owner_filter) = q.owner {
                if &d.owner != owner_filter {
                    return false;
                }
            }
            // Tag-Filter
            if let Some(ref tag) = q.tag {
                if !d.tags.contains(tag) {
                    return false;
                }
            }
            // Content-Type-Filter
            if let Some(ref ct) = q.content_type {
                if &d.content_type != ct {
                    return false;
                }
            }
            // Freitext: title, tags, metadata (JSON-Text)
            if !query_text.is_empty() {
                let title_match = d.title.to_lowercase().contains(&query_text);
                let tag_match = d.tags.iter().any(|t| t.to_lowercase().contains(&query_text));
                let meta_match = d.metadata.to_string().to_lowercase().contains(&query_text);
                if !title_match && !tag_match && !meta_match {
                    return false;
                }
            }
            true
        })
        .map(|(d, _)| stone::master_node::DocumentResponse::from(d))
        .collect();

    docs.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let total = docs.len();
    let paginated: Vec<_> = docs.into_iter().skip(page * per_page).take(per_page).collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "query": q.q,
            "documents": paginated,
        })),
    ))
}

// ─── Nutzer-Verwaltung ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct UserQuery {
    #[serde(default)]
    q: Option<String>,         // Name oder ID enthält diesen String
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    per_page: Option<usize>,
}

/// GET /api/v1/users – Alle Nutzer mit Quota-Info (Admin)
/// Query-Parameter: q=<suchbegriff>, page=<n>, per_page=<n>
async fn handle_list_users(
    headers: HeaderMap,
    Query(q): Query<UserQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let users = state.users.lock().unwrap().clone();
    let chain = state.node.chain.lock().unwrap();

    let search = q.q.as_deref().unwrap_or("").to_lowercase();
    let per_page = q.per_page.unwrap_or(50).min(500);
    let page     = q.page.unwrap_or(0);

    let mut result: Vec<serde_json::Value> = users
        .iter()
        .filter(|u| {
            if search.is_empty() { return true; }
            u.name.to_lowercase().contains(&search) || u.id.to_lowercase().contains(&search)
        })
        .map(|u| {
            let used = chain.user_usage_bytes(&u.id);
            json!({
                "id": u.id,
                "name": u.name,
                "quota_bytes": u.quota_bytes,
                "used_bytes": used,
                "quota_pct": if u.quota_bytes == 0 || u.quota_bytes == u64::MAX { 0.0 } else {
                    used as f64 / u.quota_bytes as f64 * 100.0
                },
                "document_count": chain.list_documents_for_user(&u.id).len(),
            })
        })
        .collect();

    // Sort: most documents first
    result.sort_by(|a, b| {
        let da = a["document_count"].as_u64().unwrap_or(0);
        let db = b["document_count"].as_u64().unwrap_or(0);
        db.cmp(&da)
    });

    let total = result.len();
    let paginated: Vec<_> = result.into_iter().skip(page * per_page).take(per_page).collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "users": paginated,
        })),
    ))
}

/// DELETE /api/v1/users/:user_id – Nutzer und alle seine Dokumente löschen (Admin)
async fn handle_delete_user(
    headers: HeaderMap,
    Path(user_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    if user_id == "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Admin-Konto kann nicht gelöscht werden"})),
        ).into_response());
    }

    let mut users = state.users.lock().unwrap();
    let before = users.len();
    users.retain(|u| u.id != user_id);
    if users.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Nutzer nicht gefunden"})),
        ).into_response());
    }
    save_users(&users);
    drop(users);

    Ok((
        StatusCode::OK,
        axum::Json(json!({"message": format!("Nutzer {user_id} gelöscht")})),
    ))
}

// ─── PoA Validators ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AddValidatorRequest {
    node_id: String,
    public_key_hex: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    endpoint: String,
}

/// GET /api/v1/validators – Validator-Whitelist abrufen (Admin)
async fn handle_list_validators(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let vs = state.node.validator_set.read().unwrap();
    Ok((StatusCode::OK, axum::Json(json!({
        "validators": vs.validators,
        "active_count": vs.active_count(),
        "supermajority_threshold": vs.supermajority_threshold(),
        "poa_active": !vs.validators.is_empty(),
    }))))
}

/// POST /api/v1/validators – Validator hinzufügen (Admin)
async fn handle_add_validator(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<AddValidatorRequest>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    if req.node_id.trim().is_empty() || req.public_key_hex.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "node_id und public_key_hex sind erforderlich"})),
        ).into_response());
    }

    // Public-Key-Format validieren (muss 64 Hex-Zeichen sein = 32 Byte)
    if req.public_key_hex.len() != 64 || hex::decode(&req.public_key_hex).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "public_key_hex muss ein 64-Zeichen-Hex-String (32 Byte) sein"})),
        ).into_response());
    }

    let mut info = ValidatorInfo::new(&req.node_id, &req.public_key_hex);
    info.name = req.name.clone();
    info.endpoint = req.endpoint.clone();

    let node_id = info.node_id.clone();
    {
        let mut vs = state.node.validator_set.write().unwrap();
        vs.add(info);
    }

    state.node.events.publish(stone::master_node::NodeEvent::ValidatorAdded {
        node_id: node_id.clone(),
        pub_key_hex: req.public_key_hex.clone(),
        name: req.name.clone(),
    });

    Ok((StatusCode::CREATED, axum::Json(json!({
        "message": format!("Validator {} hinzugefügt", node_id),
        "node_id": node_id,
        "public_key_hex": req.public_key_hex,
    }))))
}

/// DELETE /api/v1/validators/:node_id – Validator entfernen (Admin)
async fn handle_remove_validator(
    headers: HeaderMap,
    Path(node_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let removed = {
        let mut vs = state.node.validator_set.write().unwrap();
        vs.remove(&node_id)
    };

    if !removed {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": format!("Validator '{}' nicht gefunden", node_id)})),
        ).into_response());
    }

    state.node.events.publish(stone::master_node::NodeEvent::ValidatorRemoved {
        node_id: node_id.clone(),
    });

    Ok((StatusCode::OK, axum::Json(json!({
        "message": format!("Validator {} entfernt", node_id),
        "node_id": node_id,
    }))))
}

/// PATCH /api/v1/validators/:node_id/activate – Validator (de-)aktivieren (Admin)
async fn handle_set_validator_active(
    headers: HeaderMap,
    Path(node_id): Path<String>,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(true);

    let ok = {
        let mut vs = state.node.validator_set.write().unwrap();
        vs.set_active(&node_id, active)
    };

    if !ok {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": format!("Validator '{}' nicht gefunden", node_id)})),
        ).into_response());
    }

    state.node.events.publish(stone::master_node::NodeEvent::ValidatorStatusChanged {
        node_id: node_id.clone(),
        active,
    });

    Ok((StatusCode::OK, axum::Json(json!({
        "node_id": node_id,
        "active": active,
    }))))
}

/// GET /api/v1/validators/self – Public Key dieser Node zurückgeben
/// Validator-Nodes brauchen diesen Wert um sich in die Whitelist eintragen zu lassen
async fn handle_validator_self(
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let sk = load_or_create_validator_key();
    let pk = local_validator_pubkey_hex(&sk);
    (StatusCode::OK, axum::Json(json!({
        "public_key_hex": pk,
        "note": "Diesen Public Key verwenden um diese Node als Validator zu registrieren",
    })))
}

// ─── Konsensus / Voting ───────────────────────────────────────────────────────

/// GET /api/v1/consensus/status – Aktuelle Voting-Runde (Admin)
async fn handle_consensus_status(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let vs = state.node.validator_set.read().unwrap();
    let voting = state.node.active_voting.lock().unwrap();

    let status = if let Some(ref round) = *voting {
        let tally = round.tally(&vs);
        json!({
            "active": true,
            "round": round.round,
            "block_hash": round.block_hash,
            "proposer_id": round.proposer_id,
            "started_at": round.started_at,
            "finalized": round.finalized,
            "accepted": round.accepted,
            "tally": tally,
            "votes": round.votes.values().collect::<Vec<_>>(),
        })
    } else {
        json!({ "active": false })
    };

    Ok((StatusCode::OK, axum::Json(status)))
}

#[derive(Deserialize)]
struct CastVoteRequest {
    round: u64,
    block_hash: String,
    accept: bool,
    #[serde(default)]
    reason: String,
}

/// POST /api/v1/consensus/vote – Stimme für aktive Runde abgeben (Validator)
async fn handle_cast_vote(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<CastVoteRequest>,
) -> Result<impl IntoResponse, Response> {
    // Jede authentifizierte Node darf abstimmen (Admin-Token oder API-Key)
    // In Produktion: nur registrierte Validatoren
    require_admin(&headers, &state)?;

    let sk = load_or_create_validator_key();
    let pk_hex = local_validator_pubkey_hex(&sk);

    // Node-ID aus dem Validator-Set ermitteln (matcht nach pub key)
    let voter_id = {
        let vs = state.node.validator_set.read().unwrap();
        vs.validators.iter()
            .find(|v| v.public_key_hex == pk_hex)
            .map(|v| v.node_id.clone())
            .unwrap_or_else(|| state.node.node_id.clone())
    };

    let vote = VoteMessage::new(
        req.round,
        req.block_hash.clone(),
        voter_id.clone(),
        req.accept,
        &sk,
        req.reason.clone(),
    );

    let tally = {
        let vs = state.node.validator_set.read().unwrap();
        let mut voting = state.node.active_voting.lock().unwrap();

        if let Some(ref mut round) = *voting {
            round.add_vote(vote, &vs).map_err(|e| {
                (StatusCode::BAD_REQUEST, axum::Json(json!({"error": e}))).into_response()
            })?;
            Some(round.tally(&vs))
        } else {
            return Err((
                StatusCode::CONFLICT,
                axum::Json(json!({"error": "Keine aktive Voting-Runde"})),
            ).into_response());
        }
    };

    if let Some(t) = &tally {
        state.node.events.publish(stone::master_node::NodeEvent::VoteReceived {
            round: req.round,
            block_hash: req.block_hash.clone(),
            voter_id: voter_id.clone(),
            accept: req.accept,
            accepts: t.accepts,
            needed: t.threshold,
        });
    }

    Ok((StatusCode::OK, axum::Json(json!({
        "vote_recorded": true,
        "voter_id": voter_id,
        "tally": tally,
    }))))
}

// ─── Fork-Erkennung & Auflösung ──────────────────────────────────────────────

/// GET /api/v1/forks – Forks in der lokalen Chain erkennen (Admin)
async fn handle_detect_forks(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let chain = state.node.chain.lock().unwrap();
    let vs = state.node.validator_set.read().unwrap();

    let mut fork_groups = detect_forks(&chain.blocks);

    // Signaturen verifizieren
    for group in &mut fork_groups {
        for candidate in group.iter_mut() {
            let result = vs.verify_block(
                &candidate.block_hash,
                &candidate.signer_id,
                &candidate.validator_signature,
            );
            candidate.signature_valid = result.is_acceptable();
        }
    }

    Ok((StatusCode::OK, axum::Json(json!({
        "forks_detected": fork_groups.len(),
        "fork_groups": fork_groups,
    }))))
}

/// POST /api/v1/forks/resolve – Fork manuell auflösen (Admin)
async fn handle_resolve_fork(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let candidates: Vec<ForkCandidate> = serde_json::from_value(
        body.get("candidates").cloned().unwrap_or(json!([])),
    ).map_err(|e| {
        (StatusCode::BAD_REQUEST, axum::Json(json!({"error": format!("Ungültige Kandidaten: {e}")}))).into_response()
    })?;

    if candidates.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Keine Kandidaten angegeben"})),
        ).into_response());
    }

    let vs = state.node.validator_set.read().unwrap();
    let resolution = resolve_fork(candidates, &vs);

    match resolution {
        Some(res) => {
            state.node.events.publish(stone::master_node::NodeEvent::ForkResolved {
                winning_hash: res.winning_hash.clone(),
                dropped_blocks: 0,
                reason: format!("{:?}", res.reason),
            });
            Ok((StatusCode::OK, axum::Json(json!({
                "winning_hash": res.winning_hash,
                "reason": format!("{:?}", res.reason),
                "candidates": res.candidates,
            }))))
        }
        None => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "Fork-Auflösung fehlgeschlagen"})),
        ).into_response()),
    }
}

// ─── Peers ─────────────────────────────────────────────────────────────────────

/// GET /api/v1/peers
async fn handle_list_peers(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    Ok((StatusCode::OK, axum::Json(state.node.get_peers())))
}

/// POST /api/v1/peers
async fn handle_add_peer(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<AddPeerRequest>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let peer = PeerInfo {
        url: req.url.clone(),
        name: req.name,
        ca: req.ca,
        status: PeerStatus::Unreachable,
        last_seen: 0,
        last_hash: None,
        block_height: 0,
        latency_ms: None,
        sync_failures: 0,
    };

    state.node.upsert_peer(peer);
    let peers = state.node.get_peers();
    save_peers(&peers);

    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "ok": true,
            "peers_total": peers.len(),
            "url": req.url,
        })),
    ))
}

/// DELETE /api/v1/peers/:idx
async fn handle_remove_peer(
    headers: HeaderMap,
    Path(idx): Path<usize>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let mut peers = state.node.get_peers();
    if idx >= peers.len() {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Peer-Index nicht gefunden"})),
        )
            .into_response());
    }
    let removed = peers.remove(idx);
    state.node.replace_peers(peers.clone());
    save_peers(&peers);

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "removed": removed.url,
            "peers_remaining": peers.len(),
        })),
    ))
}

// ─── Sync ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SyncRequest {
    #[serde(default)]
    peer_url: Option<String>,
}

/// POST /api/v1/sync – Manuelle Synchronisation
async fn handle_sync(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<SyncRequest>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let peers = state.node.get_peers();
    let targets: Vec<String> = if let Some(url) = req.peer_url {
        vec![url]
    } else {
        peers.into_iter().map(|p| p.url).collect()
    };

    if targets.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Keine Peers konfiguriert"})),
        )
            .into_response());
    }

    // Sync asynchron starten
    let node = state.node.clone();
    let api_key = state.api_key.clone();
    tokio::spawn(async move {
        for peer_url in targets {
            pull_from_peer(&node, &peer_url, &api_key).await;
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        axum::Json(json!({"ok": true, "message": "Synchronisation gestartet"})),
    ))
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SignupRequest {
    name: String,
}

#[derive(Deserialize)]
struct LoginPhraseRequest {
    phrase: String,
}

/// POST /api/v1/auth/signup
async fn handle_signup(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<SignupRequest>,
) -> impl IntoResponse {
    if req.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Name darf nicht leer sein"})),
        );
    }
    let mut users = state.users.lock().unwrap();
    let id = format!("user-{}", users.len() + 1);
    let (mut user, phrase) = create_user_with_phrase(req.name.trim());
    user.id = id.clone();
    users.push(user.clone());
    save_users(&users);

    (
        StatusCode::CREATED,
        axum::Json(json!({
            "id": id,
            "name": user.name,
            "api_key": user.api_key,
            "phrase": phrase,
            "message": "Bitte die Phrase sicher aufbewahren – sie wird nur einmal angezeigt.",
        })),
    )
}

/// POST /api/v1/auth/login
async fn handle_login(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<LoginPhraseRequest>,
) -> impl IntoResponse {
    let Some(hash) = resolve_phrase(&req.phrase) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültige Wiederherstellungs-Phrase"})),
        );
    };
    let users = state.users.lock().unwrap();
    if let Some(user) = users.iter().find(|u| u.phrase_hash == hash).cloned() {
        return (
            StatusCode::OK,
            axum::Json(json!({
                "id": user.id,
                "name": user.name,
                "api_key": user.api_key,
            })),
        );
    }
    drop(users);
    (
        StatusCode::NOT_FOUND,
        axum::Json(json!({"error": "Phrase nicht bekannt – bitte zuerst registrieren"})),
    )
}

// ─── WebSocket Event-Stream ───────────────────────────────────────────────────

/// GET /ws – WebSocket-Verbindung für Live-Events
async fn handle_websocket(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    state
        .node
        .metrics
        .ws_connections
        .fetch_add(1, Ordering::Relaxed);
    let events = state.node.events.subscribe();
    let node = state.node.clone();
    ws.on_upgrade(move |socket| websocket_handler(socket, events, node))
}

async fn websocket_handler(
    mut socket: WebSocket,
    mut events: broadcast::Receiver<NodeEvent>,
    node: Arc<MasterNodeState>,
) {
    // Initialen vollständigen Status senden
    let init = {
        let chain = node.chain.lock().unwrap();
        let peers = node.peers.read().unwrap();
        let peers_healthy = peers.iter().filter(|p| p.is_healthy()).count();
        let documents_total = chain.list_all_documents().len() as u64;
        let now = chrono::Utc::now().timestamp();
        NodeEvent::InitialState {
            node_id: node.node_id.clone(),
            role: format!("{:?}", node.role),
            block_height: chain.blocks.len() as u64,
            latest_hash: chain.latest_hash.clone(),
            documents_total,
            peers_total: peers.len(),
            peers_healthy,
            requests_total: node.metrics.requests_total.load(Ordering::Relaxed),
            ws_connections: node.metrics.ws_connections.load(Ordering::Relaxed),
            uptime_seconds: now - node.started_at,
        }
    };
    if let Ok(msg) = serde_json::to_string(&init) {
        let _ = socket.send(Message::Text(msg.into())).await;
    }

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Ok(ev) => {
                        if let Ok(msg) = serde_json::to_string(&ev) {
                            if socket.send(Message::Text(msg.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    node.metrics
        .ws_connections
        .fetch_sub(1, Ordering::Relaxed);
}

// ─── Peer-Sync-Logik ──────────────────────────────────────────────────────────

async fn pull_from_peer(node: &Arc<MasterNodeState>, peer_url: &str, api_key: &str) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL")
                .map(|v| v == "1")
                .unwrap_or(false),
        )
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[sync] HTTP-Client Fehler: {e}");
            node.set_peer_status(peer_url, PeerStatus::Unreachable);
            return;
        }
    };

    node.metrics.sync_runs.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();

    // Health-Check
    let health_url = format!("{}/api/v1/health", peer_url.trim_end_matches('/'));
    let health_resp = client.get(&health_url).send().await;
    let peer_height = match health_resp {
        Ok(r) if r.status().is_success() => {
            if let Ok(val) = r.json::<serde_json::Value>().await {
                val.get("block_height")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            } else {
                0
            }
        }
        _ => {
            node.set_peer_status(peer_url, PeerStatus::Unreachable);
            node.metrics.sync_failure.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let local_height = {
        let chain = node.chain.lock().unwrap();
        chain.blocks.len() as u64
    };

    if peer_height <= local_height {
        let latency = start.elapsed().as_millis();
        let local_hash = {
            let chain = node.chain.lock().unwrap();
            chain.latest_hash.clone()
        };
        let mut peers = node.peers.write().unwrap();
        if let Some(p) = peers.iter_mut().find(|p| p.url == peer_url) {
            p.mark_healthy(local_hash, local_height, latency);
        }
        node.metrics.sync_success.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Blöcke abrufen
    let blocks_url = format!("{}/api/v1/blocks?per_page=500", peer_url.trim_end_matches('/'));
    let resp = match client
        .get(&blocks_url)
        .header("x-api-key", api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[sync] {peer_url} blocks request: {e}");
            node.set_peer_status(peer_url, PeerStatus::Unreachable);
            node.metrics.sync_failure.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let val: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[sync] {peer_url} parse error: {e}");
            node.metrics.sync_failure.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let blocks: Vec<stone::blockchain::Block> = match val
        .get("blocks")
        .and_then(|b| serde_json::from_value(b.clone()).ok())
    {
        Some(b) => b,
        None => {
            eprintln!("[sync] {peer_url}: Kein 'blocks' Feld");
            node.metrics.sync_failure.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let mut added = 0u64;

    // Chunk-URLs sammeln BEVOR wir den Lock halten (wegen .await)
    let (_local_len, _local_gen_hash, pending_blocks) = {
        let chain = node.chain.lock().unwrap();
        let local_len = chain.blocks.len() as u64;
        let local_gen_hash = chain.blocks.first().map(|b| b.hash.clone()).unwrap_or_default();

        // Genesis prüfen
        if let Some(peer_gen) = blocks.first() {
            if !local_gen_hash.is_empty() && local_gen_hash != peer_gen.hash {
                eprintln!("[sync] {peer_url}: Genesis-Mismatch");
                node.metrics.sync_failure.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        // Neue Blöcke filtern und Hash prüfen
        let pending: Vec<stone::blockchain::Block> = blocks
            .into_iter()
            .filter(|b| b.index >= local_len)
            .filter(|b| stone::blockchain::calculate_hash(b) == b.hash)
            .collect();

        (local_len, local_gen_hash, pending)
    };

    // Chunks laden (async, ohne Mutex)
    let chunk_store = ChunkStore::new().unwrap_or_default();
    for block in &pending_blocks {
        for doc in &block.documents {
            for ch in &doc.chunks {
                if chunk_store.has_chunk(&ch.hash) {
                    continue;
                }
                let chunk_url =
                    format!("{}/api/v1/chunk/{}", peer_url.trim_end_matches('/'), ch.hash);
                if let Ok(r) = client
                    .get(&chunk_url)
                    .header("x-api-key", api_key)
                    .send()
                    .await
                {
                    if let Ok(bytes) = r.bytes().await {
                        let _ = chunk_store.write_chunk(&bytes);
                    }
                }
            }
        }
    }

    // Blöcke in Chain eintragen (sync, kein await)
    {
        let mut chain = node.chain.lock().unwrap();
        for block in pending_blocks {
            chain.latest_hash = block.hash.clone();
            chain.blocks.push(block.clone());
            chain.persist_last_block();
            added += 1;
        }
    }

    if added > 0 {
        node.events.publish(NodeEvent::SyncCompleted {
            peer_url: peer_url.to_string(),
            blocks_added: added,
        });
        eprintln!("[sync] {peer_url}: {} Blöcke hinzugefügt", added);
    }

    let latency = start.elapsed().as_millis();
    let latest_hash = {
        let chain = node.chain.lock().unwrap();
        chain.latest_hash.clone()
    };
    let mut peers = node.peers.write().unwrap();
    if let Some(p) = peers.iter_mut().find(|p| p.url == peer_url) {
        p.mark_healthy(latest_hash, local_height + added, latency);
    }
    node.metrics.sync_success.fetch_add(1, Ordering::Relaxed);
}

/// GET /api/v1/chunk/:hash – Chunk-Daten abrufen (für Peer-Sync)
/// Auth: normaler API-Key ODER `x-node-request: internal` von localhost
async fn handle_get_chunk(
    headers: HeaderMap,
    Path(hash): Path<String>,
    State(state): State<AppState>,
) -> Result<Response, Response> {
    // Interne Node-zu-Node Anfragen: kein normaler Auth nötig
    // (Chunk-Hashes sind content-addressable und nicht geheim)
    let is_internal = headers
        .get("x-node-request")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "internal")
        .unwrap_or(false);

    if !is_internal {
        require_user(&headers, &state)?;
    }

    // Hash validieren
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültiger Chunk-Hash"})),
        )
            .into_response());
    }

    let chunk_store = ChunkStore::new().map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR,
         axum::Json(json!({"error": "ChunkStore nicht verfügbar"}))).into_response()
    })?;
    let bytes = chunk_store.read_chunk(&hash).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Chunk nicht gefunden"})),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes))
        .unwrap())
}

// ─── Hintergrund-Tasks ────────────────────────────────────────────────────────

/// Holt fehlende Chunks für einen empfangenen Peer-Block via HTTP.
/// Lädt alle Chunks aller Dokumente im Block vom Peer herunter, falls lokal nicht vorhanden.
async fn fetch_missing_chunks(block: &stone::blockchain::Block, peer_base_url: &str, _api_key: &str) {
    let chunk_store = match ChunkStore::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[sync] ChunkStore nicht verfügbar: {e}");
            return;
        }
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    for doc in &block.documents {
        for chunk_ref in &doc.chunks {
            // Prüfen ob Chunk bereits lokal vorhanden
            if chunk_store.read_chunk(&chunk_ref.hash).is_ok() {
                continue;
            }
            let url = format!(
                "{}/api/v1/chunk/{}",
                peer_base_url.trim_end_matches('/'), chunk_ref.hash
            );
            // Nutze internen Node-Request Header (kein Auth nötig für Chunk-Transfer)
            match client.get(&url).header("x-node-request", "internal").send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.bytes().await {
                        Ok(bytes) => {
                            // write_chunk ist content-addressable: hash wird aus bytes berechnet
                            match chunk_store.write_chunk(&bytes) {
                                Ok(written_hash) if written_hash == chunk_ref.hash => {
                                    println!("[sync] ✓ Chunk {} von {peer_base_url} geholt", &chunk_ref.hash[..8]);
                                }
                                Ok(written_hash) => {
                                    eprintln!("[sync] Chunk-Hash-Mismatch: erwartet {}, bekommen {}", &chunk_ref.hash[..8], &written_hash[..8]);
                                }
                                Err(e) => {
                                    eprintln!("[sync] Chunk {} speichern fehlgeschlagen: {e}", &chunk_ref.hash[..8]);
                                }
                            }
                        }
                        Err(e) => eprintln!("[sync] Chunk {} lesen fehlgeschlagen: {e}", &chunk_ref.hash[..8]),
                    }
                }
                Ok(resp) => {
                    eprintln!("[sync] Chunk {} – HTTP {}", &chunk_ref.hash[..8], resp.status());
                }
                Err(e) => {
                    eprintln!("[sync] Chunk {} – Fehler: {e}", &chunk_ref.hash[..8]);
                }
            }
        }
    }
}

fn spawn_auto_sync_task(node: Arc<MasterNodeState>, api_key: Arc<String>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(AUTO_SYNC_INTERVAL);
        loop {
            interval.tick().await;
            let peers = node.get_peers();
            for peer in peers {
                pull_from_peer(&node, &peer.url, &api_key).await;
            }
        }
    });
}

// ─── CORS-Konfiguration ───────────────────────────────────────────────────────

fn build_cors() -> CorsLayer {
    let allowed_origins: Vec<axum::http::HeaderValue> =
        std::env::var("STONE_CORS_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .filter_map(|s| s.trim().parse().ok())
            .collect();

    if allowed_origins.is_empty() {
        // Entwicklungs-Default: alle Origins erlauben
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PATCH, Method::OPTIONS])
            .allow_headers(Any)
    } else {
        CorsLayer::new()
            .allow_origin(
                tower_http::cors::AllowOrigin::list(allowed_origins),
            )
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PATCH, Method::OPTIONS])
            .allow_headers(Any)
    }
}

// ─── P2P-Handler ─────────────────────────────────────────────────────────────

/// GET /api/v1/p2p/peers – alle verbundenen P2P-Peers
async fn handle_p2p_peers(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let peers = match &state.network {
        Some(h) => h.get_peers().await,
        None => vec![],
    };
    Ok(axum::Json(json!({ "peers": peers, "count": peers.len() })))
}

/// POST /api/v1/p2p/dial – manuell einen Peer hinzufügen
/// Body: `{ "addr": "/ip4/1.2.3.4/tcp/7654/p2p/<PeerId>" }`
async fn handle_p2p_dial(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let addr_str = body["addr"].as_str().ok_or_else(|| {
        (StatusCode::BAD_REQUEST, axum::Json(json!({"error": "Feld 'addr' fehlt"}))).into_response()
    })?;

    let addr = stone::network::parse_multiaddr(addr_str).map_err(|e| {
        (StatusCode::BAD_REQUEST, axum::Json(json!({"error": e}))).into_response()
    })?;

    match &state.network {
        Some(h) => {
            h.dial(addr).await;
            Ok(axum::Json(json!({ "ok": true, "addr": addr_str })))
        }
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "P2P nicht aktiv"})),
        ).into_response()),
    }
}

/// GET /api/v1/p2p/info – lokale P2P-Node-Informationen
async fn handle_p2p_info(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_user(&headers, &state)?;
    let p2p_port: u16 = std::env::var("STONE_P2P_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(stone::network::DEFAULT_P2P_PORT);

    let (peer_id, local_addr) = match &state.network {
        Some(h) => (
            h.local_peer_id.clone(),
            stone::network::local_p2p_addr(p2p_port),
        ),
        None => (String::from("P2P deaktiviert"), None),
    };

    Ok(axum::Json(json!({
        "peer_id": peer_id,
        "p2p_addr": local_addr,
        "p2p_port": p2p_port,
        "p2p_active": state.network.is_some(),
    })))
}

/// GET /api/v1/p2p/config – aktuelle P2P-Konfiguration
async fn handle_p2p_config(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let config = stone::network::P2pConfig::load_or_default();
    Ok(axum::Json(config))
}

/// GET /api/v1/p2p/status – vollständiger Verbindungsstatus aller Peers
async fn handle_p2p_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let Some(net) = &state.network else {
        return axum::Json(json!({
            "p2p": "disabled",
            "connected_peers": 0,
            "total_known_peers": 0,
            "peers": []
        })).into_response();
    };
    match net.get_status().await {
        Some(s) => axum::Json(json!({
            "local_peer_id":       s.local_peer_id,
            "connected_peers":     s.connected_peers,
            "total_known_peers":   s.total_known_peers,
            "gossipsub_mesh_size": s.gossipsub_mesh_size,
            "chain_block_count":   s.chain_block_count,
            "peers": s.peers.iter().map(|p| json!({
                "peer_id":         p.peer_id,
                "addresses":       p.addresses,
                "agent":           p.agent_version,
                "connected":       p.connected,
                "last_seen_ago_s": p.last_seen_ago_secs,
                "blocks_received": p.blocks_received,
                "in_mesh":         p.in_gossipsub_mesh,
            })).collect::<Vec<_>>(),
        })).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "P2P-Task antwortet nicht"})),
        ).into_response(),
    }
}

/// POST /api/v1/p2p/ping/:peer_id – pingt einen Peer, misst Latenz
async fn handle_p2p_ping(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Path(peer_id_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let net = state.network.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({"error": "P2P nicht aktiv"}))).into_response()
    })?;

    let peer_id = peer_id_str.parse::<libp2p::PeerId>().map_err(|_| {
        (StatusCode::BAD_REQUEST, axum::Json(json!({"error": format!("Ungültige PeerId: {peer_id_str}")}))).into_response()
    })?;

    let result = net.ping(peer_id).await;
    let status = if result.reachable { StatusCode::OK } else { StatusCode::REQUEST_TIMEOUT };
    Ok((status, axum::Json(json!({
        "peer_id":    result.peer_id,
        "reachable":  result.reachable,
        "latency_ms": result.latency_ms,
        "error":      result.error,
    }))))
}

// ─── Router-Aufbau ────────────────────────────────────────────────────────────

fn build_router(state: AppState) -> Router {
    Router::new()
        // Health (kein Auth)
        .route("/api/v1/health", get(handle_health))
        // Status & Metriken (Admin)
        .route("/api/v1/status", get(handle_status))
        .route("/api/v1/metrics", get(handle_metrics))
        .route("/api/v1/network", get(handle_network_stats))
        .route("/api/v1/chain/verify", get(handle_verify))
        // Blöcke (Admin)
        .route("/api/v1/blocks", get(handle_list_blocks))
        .route("/api/v1/blocks/:index", get(handle_get_block))
        // Dokumente
        .route(
            "/api/v1/documents",
            get(handle_list_documents).post(handle_upload_document),
        )
        // Suche (vor /:doc_id, damit /search nicht als doc_id geparst wird)
        .route("/api/v1/documents/search", get(handle_search_documents))
        .route(
            "/api/v1/documents/user/:user_id",
            get(handle_list_user_documents),
        )
        .route(
            "/api/v1/documents/:doc_id",
            get(handle_get_document).patch(handle_patch_document),
        )
        .route(
            "/api/v1/documents/:doc_id/delete",
            post(handle_delete_document),
        )
        .route(
            "/api/v1/documents/:doc_id/history",
            get(handle_document_history),
        )
        .route("/api/v1/documents/:doc_id/transfer", post(handle_transfer_document))
        .route("/api/v1/documents/:doc_id/data", get(handle_get_document_data))
        .route("/api/v1/documents/:doc_id/download", get(handle_get_document_data))
        // Chunk-API für Peer-Sync
        .route("/api/v1/chunk/:hash", get(handle_get_chunk))
        // Peers (Admin)
        .route(
            "/api/v1/peers",
            get(handle_list_peers).post(handle_add_peer),
        )
        .route("/api/v1/peers/:idx", delete(handle_remove_peer))
        // Sync (Admin)
        .route("/api/v1/sync", post(handle_sync))
        // P2P-Netzwerk
        .route("/api/v1/p2p/peers",         get(handle_p2p_peers))
        .route("/api/v1/p2p/status",        get(handle_p2p_status))
        .route("/api/v1/p2p/ping/:peer_id", post(handle_p2p_ping))
        .route("/api/v1/p2p/dial",          post(handle_p2p_dial))
        .route("/api/v1/p2p/info",          get(handle_p2p_info))
        .route("/api/v1/p2p/config",        get(handle_p2p_config))
        // Nutzer (Admin)
        .route("/api/v1/users", get(handle_list_users))
        .route("/api/v1/users/:user_id", delete(handle_delete_user))
        // Auth
        .route("/api/v1/auth/signup", post(handle_signup))
        .route("/api/v1/auth/login", post(handle_login))
        // PoA: Validators
        .route("/api/v1/validators",          get(handle_list_validators).post(handle_add_validator))
        .route("/api/v1/validators/self",     get(handle_validator_self))
        .route("/api/v1/validators/:node_id", delete(handle_remove_validator))
        .route("/api/v1/validators/:node_id/activate", post(handle_set_validator_active))
        // PoA: Consensus Voting
        .route("/api/v1/consensus/status",    get(handle_consensus_status))
        .route("/api/v1/consensus/vote",      post(handle_cast_vote))
        // Fork-Erkennung
        .route("/api/v1/forks",               get(handle_detect_forks))
        .route("/api/v1/forks/resolve",       post(handle_resolve_fork))
        // WebSocket
        .route("/ws", get(handle_websocket))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES))
        .layer(build_cors())
        .with_state(state)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // ── .env laden (falls vorhanden) ──────────────────────────────────────────
    // Liest die .env Datei im aktuellen Verzeichnis und setzt die Variablen als
    // Umgebungsvariablen. Bereits gesetzte Variablen werden NICHT überschrieben
    // (dotenvy::dotenv_override() würde .env bevorzugen).
    // Reihenfolge: bestehende Env-Vars > .env > token.bin (Fallback)
    match dotenvy::dotenv() {
        Ok(path) => println!("[master] .env geladen: {}", path.display()),
        Err(dotenvy::Error::Io(_)) => { /* .env nicht gefunden – kein Fehler */ }
        Err(e) => eprintln!("[master] .env Warnung: {e}"),
    }

    std::fs::create_dir_all(data_dir()).expect("DATA_DIR anlegen");
    ChunkStore::new().expect("ChunkStore anlegen");

    let api_key = Arc::new(load_api_key());
    let node_id = std::env::var("STONE_NODE_ID")
        .or_else(|_| std::env::var("STONE_NODE_NAME"))
        .unwrap_or_else(|_| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "stone-master".into())
        });

    println!("[master] Node-ID: {node_id}");
    println!("[master] API-Key geladen: {}...", &api_key[..8.min(api_key.len())]);

    // Master Node State initialisieren
    let node = MasterNodeState::new(node_id.clone(), api_key.as_ref().clone(), NodeRole::Master);

    // Gespeicherte Peers laden
    let saved_peers = load_peers_from_disk();
    if !saved_peers.is_empty() {
        println!("[master] {} Peer(s) aus Datei geladen", saved_peers.len());
        node.replace_peers(saved_peers);
    }

    let users = load_users();

    // Hintergrund-Tasks starten
    MasterNodeState::start_heartbeat(node.clone(), HEARTBEAT_INTERVAL);
    spawn_auto_sync_task(node.clone(), api_key.clone());

    // P2P-Netzwerk starten (optional – deaktivieren via STONE_P2P_DISABLED=1)
    let network_handle = if std::env::var("STONE_P2P_DISABLED").as_deref() == Ok("1") {
        println!("[master] P2P-Netzwerk deaktiviert (STONE_P2P_DISABLED=1)");
        None
    } else {
        match start_network(None).await {
            Ok(handle) => {
                println!("[master] P2P-Netzwerk gestartet – PeerId: {}", handle.local_peer_id);

                // Eigene Chain-Länge dem Swarm mitteilen (für Sync-Handshake)
                {
                    let count = node.chain.lock().unwrap().blocks.len() as u64;
                    handle.set_chain_count(count).await;
                }

                // Hintergrund-Task: empfangene Blöcke in die lokale Chain einfügen
                {
                    use stone::network::NetworkEvent;
                    let mut event_rx = handle.subscribe();
                    let node_bg = node.clone();
                    let handle_bg = handle.clone();
                    let api_key_bg = api_key.clone();
                    tokio::spawn(async move {
                        while let Ok(event) = event_rx.recv().await {
                            if let NetworkEvent::BlockReceived { block, from_peer } = event {
                                // Fehlende Chunks von bekannten HTTP-Peers holen
                                let peer_urls: Vec<String> = {
                                    node_bg.get_peers()
                                        .into_iter()
                                        .filter(|p| p.is_healthy())
                                        .map(|p| p.url.clone())
                                        .collect()
                                };
                                for url in &peer_urls {
                                    fetch_missing_chunks(&block, url, &api_key_bg).await;
                                }

                                let new_count = {
                                    // PoA: Validator-Signatur vorab prüfen (außerhalb des Chain-Locks)
                                    let poa_ok = {
                                        let vs = node_bg.validator_set.read().unwrap();
                                        if vs.validators.is_empty() {
                                            None // PoA inaktiv
                                        } else {
                                            let result = vs.verify_block(
                                                &block.hash,
                                                &block.signer,
                                                &block.validator_signature,
                                            );
                                            Some(result.is_acceptable())
                                        }
                                    };

                                    let mut chain = node_bg.chain.lock().unwrap();
                                    // Duplikat-Prüfung: Block bereits in der Chain?
                                    let already_known = chain.blocks.iter().any(|b| b.hash == block.hash);
                                    if !already_known {
                                        let idx = block.index;
                                        match chain.accept_peer_block(*block, poa_ok) {
                                            Ok(_) => {
                                                println!("[p2p] ✓ Block #{idx} von {from_peer} in Chain aufgenommen");
                                                Some(chain.blocks.len() as u64)
                                            }
                                            Err(e) => {
                                                eprintln!("[p2p] Block #{idx} abgelehnt: {e}");
                                                None
                                            }
                                        }
                                    } else {
                                        None
                                    }
                                };
                                // Chain-Count im P2P-Layer aktualisieren (außerhalb des Locks)
                                if let Some(count) = new_count {
                                    handle_bg.set_chain_count(count).await;
                                }
                            }
                        }
                    });
                }

                Some(handle)
            }
            Err(e) => {
                eprintln!("[master] P2P-Netzwerk konnte nicht gestartet werden: {e}");
                None
            }
        }
    };

    let state = AppState {
        node: node.clone(),
        users,
        api_key: api_key.clone(),
        network: network_handle,
    };

    let router = build_router(state);

    // TLS-Konfiguration
    let use_tls = std::env::var("STONE_TLS_CERT").is_ok()
        && std::env::var("STONE_TLS_KEY").is_ok();
    let preferred_port: u16 = std::env::var("STONE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if use_tls { 443 } else { 8080 });

    if use_tls {
        let cert_path = std::env::var("STONE_TLS_CERT").unwrap();
        let key_path = std::env::var("STONE_TLS_KEY").unwrap();
        let addr = SocketAddr::from(([0, 0, 0, 0], preferred_port));
        println!("[master] HTTPS auf {addr} (TLS: {cert_path})");
        println!("[master] Stone Master Node läuft auf https://{addr}");
        println!("[master] Web-UI kann sich via wss://{addr}/ws verbinden");

        axum_server::bind_rustls(
            addr,
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .expect("TLS-Konfiguration laden"),
        )
        .serve(router.into_make_service())
        .await
        .expect("HTTPS-Server Fehler");
    } else {
        // Port-Fallback: falls bevorzugter Port belegt → nächsten freien suchen
        let listener = bind_with_fallback(preferred_port).await;
        let bound_port = listener.local_addr().unwrap().port();
        println!("[master] HTTP auf 0.0.0.0:{bound_port} (kein TLS – nur für Entwicklung!)");
        println!("[master] Stone Master Node läuft auf http://0.0.0.0:{bound_port}");
        println!("[master] Web-UI kann sich via ws://0.0.0.0:{bound_port}/ws verbinden");
        if bound_port != preferred_port {
            println!("[master] ⚠️  Port {preferred_port} war belegt – nutze {bound_port}");
            println!("[master] Tipp: STONE_PORT={bound_port} setzen um diesen Port fest zu konfigurieren");
        }
        println!("[master] Hinweis: Für Produktion STONE_TLS_CERT und STONE_TLS_KEY setzen.");
        axum::serve(listener, router).await.expect("HTTP-Server Fehler");
    }
}

/// Bindet an `preferred_port`, fällt automatisch auf einen freien Port zurück.
async fn bind_with_fallback(preferred_port: u16) -> tokio::net::TcpListener {
    let addr = SocketAddr::from(([0, 0, 0, 0], preferred_port));
    match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("[master] Port {preferred_port} belegt ({e}) – suche freien Port...");
            let fallback = SocketAddr::from(([0, 0, 0, 0], 0));
            tokio::net::TcpListener::bind(fallback)
                .await
                .expect("Kein freier TCP-Port verfügbar")
        }
        Err(e) => panic!("TCP-Bind fehlgeschlagen: {e}"),
    }
}
