//! Shared application state, constants, chunk helpers, and peer persistence.

use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use stone::{
    auth::User,
    blockchain::{ChunkRef, data_dir, CHUNK_SIZE, Document},
    master_node::{MasterNodeState, PeerInfo},
    network::NetworkHandle,
    storage::ChunkStore,
};

// ─── Konstanten ──────────────────────────────────────────────────────────────

pub const MAX_UPLOAD_BYTES: usize = 5 * 1024 * 1024 * 1024; // 5 GiB
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
pub const AUTO_SYNC_INTERVAL: Duration = Duration::from_secs(30);
pub fn peers_file() -> String {
    format!("{}/peers.json", data_dir())
}

// ─── Shared App State ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub node: Arc<MasterNodeState>,
    pub users: Arc<Mutex<Vec<User>>>,
    pub api_key: Arc<String>,
    /// P2P-Netzwerk-Handle (None = P2P deaktiviert)
    pub network: Option<NetworkHandle>,
}

// ─── API-Key laden ────────────────────────────────────────────────────────────

pub fn load_api_key() -> String {
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

pub fn generate_api_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let mut h = Sha256::new();
    h.update(b"stone-master-key-v1-");
    h.update(ts.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    if let Ok(hn) = hostname::get() {
        h.update(hn.to_string_lossy().as_bytes());
    }
    format!("sk_{}", hex::encode(h.finalize()))
}

// ─── Chunk-Verwaltung ─────────────────────────────────────────────────────────

pub fn chunk_data(data: &[u8]) -> Result<Vec<ChunkRef>, String> {
    let store = ChunkStore::new().map_err(|e| e.to_string())?;
    store.write_chunks(data, CHUNK_SIZE).map_err(|e| e.to_string())
}

pub fn reconstruct_document_data(doc: &Document) -> Result<Vec<u8>, String> {
    let store = ChunkStore::new().map_err(|e| e.to_string())?;
    store.reconstruct_document(doc).map_err(|e| e.to_string())
}

// ─── Peer-Persistenz ─────────────────────────────────────────────────────────

pub fn save_peers(peers: &[PeerInfo]) {
    let _ = std::fs::create_dir_all(data_dir());
    if let Ok(json) = serde_json::to_string_pretty(peers) {
        let _ = std::fs::write(peers_file(), json);
    }
}

pub fn load_peers_from_disk() -> Vec<PeerInfo> {
    if let Ok(data) = std::fs::read_to_string(peers_file()) {
        if let Ok(list) = serde_json::from_str::<Vec<PeerInfo>>(&data) {
            return list;
        }
    }
    Vec::new()
}
