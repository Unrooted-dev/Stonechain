//! Master Node – Koordinations- und Konsensus-Schicht
//!
//! Die Master Node ist der zentrale Koordinator des Stone-Clusters.
//! Sie verwaltet den Cluster-State, koordiniert Peer-Synchronisation,
//! und stellt die API-Schicht für die externe Web-UI bereit.

use crate::blockchain::{Block, Document, DocumentTombstone, NodeRole, StoneChain};
use crate::consensus::{
    load_or_create_validator_key, local_validator_pubkey_hex, sign_block,
    ValidatorSet, VotingRound,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

// ─── Peer-Status ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeerStatus {
    /// Erreichbar, Chain in Sync
    Healthy,
    /// Erreichbar, aber Chain divergiert
    Diverged,
    /// Nicht erreichbar
    Unreachable,
    /// Quarantäne (Integritätsfehler)
    Quarantined,
}

impl Default for PeerStatus {
    fn default() -> Self {
        PeerStatus::Unreachable
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub url: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ca: Option<String>,
    #[serde(default)]
    pub status: PeerStatus,
    #[serde(default)]
    pub last_seen: i64,
    #[serde(default)]
    pub last_hash: Option<String>,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub latency_ms: Option<u128>,
    #[serde(default)]
    pub sync_failures: u32,
}

impl PeerInfo {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            name: None,
            ca: None,
            status: PeerStatus::Unreachable,
            last_seen: 0,
            last_hash: None,
            block_height: 0,
            latency_ms: None,
            sync_failures: 0,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.status == PeerStatus::Healthy
    }

    pub fn mark_healthy(&mut self, hash: String, height: u64, latency_ms: u128) {
        self.status = PeerStatus::Healthy;
        self.last_seen = Utc::now().timestamp();
        self.last_hash = Some(hash);
        self.block_height = height;
        self.latency_ms = Some(latency_ms);
        self.sync_failures = 0;
    }

    pub fn mark_unreachable(&mut self) {
        self.status = PeerStatus::Unreachable;
        self.sync_failures += 1;
    }

    pub fn mark_diverged(&mut self, peer_hash: String, peer_height: u64) {
        self.status = PeerStatus::Diverged;
        self.last_seen = Utc::now().timestamp();
        self.last_hash = Some(peer_hash);
        self.block_height = peer_height;
    }
}

// ─── Konsensus-Runde ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusRound {
    pub round: u64,
    pub proposed_hash: String,
    pub votes: HashMap<String, bool>,
    pub started_at: i64,
    pub finalized: bool,
}

impl ConsensusRound {
    pub fn new(round: u64, proposed_hash: String) -> Self {
        Self {
            round,
            proposed_hash,
            votes: HashMap::new(),
            started_at: Utc::now().timestamp(),
            finalized: false,
        }
    }

    /// Stimme eines Peers registrieren (url → accept)
    pub fn vote(&mut self, peer_url: String, accept: bool) {
        self.votes.insert(peer_url, accept);
    }

    /// Einfache Mehrheit: mehr als 50% aller abgegebenen Stimmen = accept
    pub fn quorum_reached(&self, total_peers: usize) -> bool {
        let accepts = self.votes.values().filter(|&&v| v).count();
        let needed = (total_peers / 2) + 1;
        accepts >= needed
    }
}

// ─── Master Node Events (für WebSocket-Broadcast) ────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum NodeEvent {
    /// Neuer Block wurde zur Chain hinzugefügt
    BlockAdded {
        index: u64,
        hash: String,
        docs: usize,
        owner: String,
        timestamp: i64,
    },
    /// Dokument hochgeladen/aktualisiert
    DocumentUpdated {
        doc_id: String,
        title: String,
        owner: String,
        version: u32,
        block_index: u64,
    },
    /// Dokument gelöscht (Soft-Delete)
    DocumentDeleted {
        doc_id: String,
        owner: String,
        block_index: u64,
    },
    /// Peer-Status geändert
    PeerStatusChanged {
        url: String,
        status: PeerStatus,
    },
    /// Chain-Synchronisation abgeschlossen
    SyncCompleted {
        peer_url: String,
        blocks_added: u64,
    },
    /// Integritätsfehler entdeckt
    IntegrityError {
        description: String,
    },
    /// Node gestartet
    NodeStarted {
        node_id: String,
        role: String,
        timestamp: i64,
    },
    /// Metriken-Update
    MetricsUpdate {
        blocks: u64,
        documents: u64,
        peers_healthy: u64,
        peers_total: u64,
    },
    /// Initialer Status bei WebSocket-Verbindung
    InitialState {
        node_id: String,
        role: String,
        block_height: u64,
        latest_hash: String,
        documents_total: u64,
        peers_total: usize,
        peers_healthy: usize,
        requests_total: u64,
        ws_connections: u64,
        uptime_seconds: i64,
    },
    // ─── PoA / Konsensus Events ───────────────────────────────────────────────
    /// Validator zur Whitelist hinzugefügt
    ValidatorAdded {
        node_id: String,
        pub_key_hex: String,
        name: String,
    },
    /// Validator aus der Whitelist entfernt
    ValidatorRemoved {
        node_id: String,
    },
    /// Validator deaktiviert / reaktiviert
    ValidatorStatusChanged {
        node_id: String,
        active: bool,
    },
    /// Block-Proposal erstellt und an Peers verschickt
    ProposalCreated {
        block_hash: String,
        block_index: u64,
        proposer_id: String,
        round: u64,
    },
    /// Stimme für eine Konsensus-Runde empfangen
    VoteReceived {
        round: u64,
        block_hash: String,
        voter_id: String,
        accept: bool,
        accepts: usize,
        needed: usize,
    },
    /// Konsensus für einen Block erreicht
    ConsensusReached {
        round: u64,
        block_hash: String,
        block_index: u64,
        votes_for: usize,
    },
    /// Konsensus abgelehnt (nicht genug Stimmen)
    ConsensusRejected {
        round: u64,
        block_hash: String,
        votes_for: usize,
        votes_against: usize,
        needed: usize,
    },
    /// Fork in der Chain erkannt
    ForkDetected {
        block_index: u64,
        our_hash: String,
        peer_hash: String,
        peer_url: String,
    },
    /// Fork aufgelöst
    ForkResolved {
        winning_hash: String,
        dropped_blocks: u64,
        reason: String,
    },
}

// ─── Event-Bus ───────────────────────────────────────────────────────────────

/// Einfacher In-Memory Event-Bus für WebSocket-Broadcasts.
/// Subscriber registrieren sich mit einem tokio::sync::broadcast-Receiver.
#[derive(Clone)]
pub struct EventBus {
    sender: tokio::sync::broadcast::Sender<NodeEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: NodeEvent) {
        // Fehler ignorieren falls kein Subscriber aktiv ist
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<NodeEvent> {
        self.sender.subscribe()
    }
}

// ─── Master Node State ───────────────────────────────────────────────────────

/// Globaler State der Master Node.
/// Wird als `Arc<MasterNodeState>` durch den gesamten Server geteilt.
pub struct MasterNodeState {
    /// Eindeutige Node-ID (z.B. Hostname oder UUID)
    pub node_id: String,
    /// Rolle dieser Node im Cluster
    pub role: NodeRole,
    /// Cluster-Schlüssel für HMAC-Signierung
    pub cluster_key: String,
    /// Die Blockchain
    pub chain: Mutex<StoneChain>,
    /// Bekannte Peers
    pub peers: RwLock<Vec<PeerInfo>>,
    /// Aktive Konsensus-Runde (falls vorhanden)
    pub consensus: Mutex<Option<ConsensusRound>>,
    /// PoA Validator-Whitelist
    pub validator_set: RwLock<ValidatorSet>,
    /// Aktive PoA Voting-Runde (falls vorhanden)
    pub active_voting: Mutex<Option<VotingRound>>,
    /// Monoton ansteigender Runden-Zähler
    pub round_counter: AtomicU64,
    /// Event-Bus für WebSocket-Broadcasts
    pub events: EventBus,
    /// Counters für Metriken
    pub metrics: MasterMetrics,
    /// Zeitpunkt des Starts
    pub started_at: i64,
}

#[derive(Default)]
pub struct MasterMetrics {
    pub requests_total: AtomicU64,
    pub documents_uploaded: AtomicU64,
    pub documents_deleted: AtomicU64,
    pub sync_runs: AtomicU64,
    pub sync_success: AtomicU64,
    pub sync_failure: AtomicU64,
    pub ws_connections: AtomicU64,
}

impl MasterNodeState {
    pub fn new(node_id: String, cluster_key: String, role: NodeRole) -> Arc<Self> {
        let chain = StoneChain::load_or_create(&cluster_key);
        let started_at = Utc::now().timestamp();
        let state = Arc::new(Self {
            node_id: node_id.clone(),
            role,
            cluster_key,
            chain: Mutex::new(chain),
            peers: RwLock::new(Vec::new()),
            consensus: Mutex::new(None),
            validator_set: RwLock::new(ValidatorSet::load()),
            active_voting: Mutex::new(None),
            round_counter: AtomicU64::new(1),
            events: EventBus::new(256),
            metrics: MasterMetrics::default(),
            started_at,
        });

        // Node-gestartet Event senden
        state.events.publish(NodeEvent::NodeStarted {
            node_id,
            role: "master".into(),
            timestamp: started_at,
        });

        state
    }

    /// Dokumente zur Blockchain hinzufügen und Event publizieren.
    ///
    /// PoA prüft die **Node-ID** (`self.node_id`), nicht den User/Signer.
    /// User sind Dokument-Owner — die Node ist der Validator.
    /// Wenn PoA aktiv ist (ValidatorSet nicht leer):
    ///   - Prüft ob diese Node ein aktiver Validator ist → Err falls nicht
    ///   - Signiert den Block-Hash mit dem lokalen Validator-Schlüssel
    ///   - Setzt `validator_pub_key` und `validator_signature` im Block
    pub fn commit_documents(
        &self,
        documents: Vec<Document>,
        tombstones: Vec<DocumentTombstone>,
        owner: String,
        signer: String,
    ) -> Result<Block, String> {
        // PoA: Validator-Prüfung auf Node-Ebene (nicht User-Ebene)
        // Der Signer/User ist der Dokument-Owner — die Node ist der Validator.
        {
            let vs = self.validator_set.read().unwrap();
            if !vs.validators.is_empty() && !vs.is_active_validator(&self.node_id) {
                return Err(format!(
                    "PoA: Diese Node ('{}') ist kein aktiver Validator. \
                     Bitte Node als Validator registrieren.",
                    self.node_id
                ));
            }
        }

        let mut chain = self.chain.lock().unwrap();
        let mut block = chain.add_documents(
            documents.clone(),
            tombstones.clone(),
            owner.clone(),
            signer.clone(),
            &self.cluster_key,
            self.role.clone(),
        );

        // PoA: Block-Signierung mit Validator-Schlüssel
        {
            let vs = self.validator_set.read().unwrap();
            if !vs.validators.is_empty() {
                let signing_key = load_or_create_validator_key();
                let pub_key_hex = local_validator_pubkey_hex(&signing_key);
                let sig = sign_block(&signing_key, &block.hash);
                block.validator_pub_key = pub_key_hex;
                block.validator_signature = sig;

                // Signierter Block in RocksDB aktualisieren (mit WAL-Sync)
                use crate::storage::ChainStore;
                if let Ok(store) = ChainStore::open() {
                    let _ = store.write_block_sync(&block);
                }
                // Auch in der in-memory chain aktualisieren
                if let Some(last) = chain.blocks.last_mut() {
                    last.validator_pub_key = block.validator_pub_key.clone();
                    last.validator_signature = block.validator_signature.clone();
                }

                // Statistik: blocks_signed auf der Node-ID (nicht User) erhöhen
                drop(vs);
                let mut vs_w = self.validator_set.write().unwrap();
                if let Some(v) = vs_w.get_mut(&self.node_id) {
                    v.blocks_signed += 1;
                    vs_w.save();
                }
            }
        }

        // Events publizieren
        self.events.publish(NodeEvent::BlockAdded {
            index: block.index,
            hash: block.hash.clone(),
            docs: block.documents.len(),
            owner: block.owner.clone(),
            timestamp: block.timestamp,
        });

        for doc in &block.documents {
            self.events.publish(NodeEvent::DocumentUpdated {
                doc_id: doc.doc_id.clone(),
                title: doc.title.clone(),
                owner: doc.owner.clone(),
                version: doc.version,
                block_index: block.index,
            });
            self.metrics.documents_uploaded.fetch_add(1, Ordering::Relaxed);
        }

        for ts in &block.tombstones {
            self.events.publish(NodeEvent::DocumentDeleted {
                doc_id: ts.doc_id.clone(),
                owner: ts.owner.clone(),
                block_index: block.index,
            });
            self.metrics.documents_deleted.fetch_add(1, Ordering::Relaxed);
        }

        Ok(block)
    }

    /// Peer hinzufügen oder aktualisieren
    pub fn upsert_peer(&self, peer: PeerInfo) {
        let mut peers = self.peers.write().unwrap();
        if let Some(existing) = peers.iter_mut().find(|p| p.url == peer.url) {
            *existing = peer;
        } else {
            peers.push(peer);
        }
    }

    /// Peer-Status aktualisieren
    pub fn set_peer_status(&self, url: &str, status: PeerStatus) {
        let mut peers = self.peers.write().unwrap();
        if let Some(p) = peers.iter_mut().find(|p| p.url == url) {
            let changed = p.status != status;
            p.status = status.clone();
            if changed {
                self.events.publish(NodeEvent::PeerStatusChanged {
                    url: url.to_string(),
                    status,
                });
            }
        }
    }

    /// Alle Peers entfernen und neu setzen
    pub fn replace_peers(&self, peers: Vec<PeerInfo>) {
        let mut locked = self.peers.write().unwrap();
        *locked = peers;
    }

    /// Peers lesen
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().unwrap().clone()
    }

    /// Chain-Zusammenfassung für API-Antworten
    pub fn chain_summary(&self) -> ChainSummary {
        let chain = self.chain.lock().unwrap();
        let total_docs: usize = chain
            .list_all_documents()
            .len();
        ChainSummary {
            block_height: chain.blocks.len() as u64,
            latest_hash: chain.latest_hash.clone(),
            total_documents: total_docs as u64,
            is_valid: chain.verify(&self.cluster_key),
        }
    }

    /// Metriken für API
    pub fn snapshot_metrics(&self) -> MasterMetricsSnapshot {
        let peers = self.peers.read().unwrap();
        let healthy = peers.iter().filter(|p| p.is_healthy()).count();
        MasterMetricsSnapshot {
            requests_total: self.metrics.requests_total.load(Ordering::Relaxed),
            documents_uploaded: self.metrics.documents_uploaded.load(Ordering::Relaxed),
            documents_deleted: self.metrics.documents_deleted.load(Ordering::Relaxed),
            sync_runs: self.metrics.sync_runs.load(Ordering::Relaxed),
            sync_success: self.metrics.sync_success.load(Ordering::Relaxed),
            sync_failure: self.metrics.sync_failure.load(Ordering::Relaxed),
            ws_connections: self.metrics.ws_connections.load(Ordering::Relaxed),
            peers_total: peers.len() as u64,
            peers_healthy: healthy as u64,
            uptime_secs: (Utc::now().timestamp() - self.started_at) as u64,
        }
    }

    /// Hintergrund-Task: Peer-Heartbeat alle N Sekunden
    pub fn start_heartbeat(state: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let peers = state.get_peers();
                let chain_summary = state.chain_summary();

                state.events.publish(NodeEvent::MetricsUpdate {
                    blocks: chain_summary.block_height,
                    documents: chain_summary.total_documents,
                    peers_healthy: peers.iter().filter(|p| p.is_healthy()).count() as u64,
                    peers_total: peers.len() as u64,
                });
            }
        });
    }
}

// ─── API-Typen ───────────────────────────────────────────────────────────────

/// Kompakte Chain-Zusammenfassung für Status-Endpunkte
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSummary {
    pub block_height: u64,
    pub latest_hash: String,
    pub total_documents: u64,
    pub is_valid: bool,
}

/// Metriken-Snapshot für Monitoring-Endpunkt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterMetricsSnapshot {
    pub requests_total: u64,
    pub documents_uploaded: u64,
    pub documents_deleted: u64,
    pub sync_runs: u64,
    pub sync_success: u64,
    pub sync_failure: u64,
    pub ws_connections: u64,
    pub peers_total: u64,
    pub peers_healthy: u64,
    pub uptime_secs: u64,
}

/// Anfrage zum Hinzufügen/Aktualisieren eines Dokuments über die API
#[derive(Debug, Deserialize)]
pub struct SubmitDocumentRequest {
    pub doc_id: Option<String>,
    pub title: String,
    pub content_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Anfrage zum Soft-Delete eines Dokuments
#[derive(Debug, Deserialize)]
pub struct DeleteDocumentRequest {
    pub doc_id: String,
}

/// Anfrage zum Hinzufügen eines Peers
#[derive(Debug, Deserialize)]
pub struct AddPeerRequest {
    pub url: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ca: Option<String>,
}

/// Antwort auf Block-Anfragen
#[derive(Debug, Serialize)]
pub struct BlockResponse {
    pub index: u64,
    pub timestamp: i64,
    pub hash: String,
    pub previous_hash: String,
    pub merkle_root: String,
    pub data_size: u64,
    pub owner: String,
    pub signer: String,
    pub documents: Vec<DocumentResponse>,
    pub tombstones_count: usize,
    pub node_role: String,
    pub validator_pub_key: String,
    pub validator_signature: String,
}

impl From<&Block> for BlockResponse {
    fn from(b: &Block) -> Self {
        BlockResponse {
            index: b.index,
            timestamp: b.timestamp,
            hash: b.hash.clone(),
            previous_hash: b.previous_hash.clone(),
            merkle_root: b.merkle_root.clone(),
            data_size: b.data_size,
            owner: b.owner.clone(),
            signer: b.signer.clone(),
            documents: b.documents.iter().map(DocumentResponse::from).collect(),
            tombstones_count: b.tombstones.len(),
            node_role: format!("{:?}", b.node_role),
            validator_pub_key: b.validator_pub_key.clone(),
            validator_signature: b.validator_signature.clone(),
        }
    }
}

/// Dokument-Antwort (ohne Chunk-Daten)
#[derive(Debug, Serialize)]
pub struct DocumentResponse {
    pub doc_id: String,
    pub title: String,
    pub content_type: String,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
    pub version: u32,
    pub size: u64,
    pub owner: String,
    pub updated_at: i64,
    pub chunks_count: usize,
}

impl From<&crate::blockchain::Document> for DocumentResponse {
    fn from(d: &crate::blockchain::Document) -> Self {
        DocumentResponse {
            doc_id: d.doc_id.clone(),
            title: d.title.clone(),
            content_type: d.content_type.clone(),
            tags: d.tags.clone(),
            metadata: d.metadata.0.clone(),
            version: d.version,
            size: d.size,
            owner: d.owner.clone(),
            updated_at: d.updated_at,
            chunks_count: d.chunks.len(),
        }
    }
}

/// Node-Status-Antwort für `/api/v1/status`
#[derive(Debug, Serialize)]
pub struct NodeStatusResponse {
    pub node_id: String,
    pub role: String,
    pub chain: ChainSummary,
    pub metrics: MasterMetricsSnapshot,
    pub peers: Vec<PeerInfo>,
    pub started_at: i64,
}
