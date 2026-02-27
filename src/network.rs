//! Stone P2P-Netzwerkschicht
//!
//! ## Architektur
//!
//! ```text
//!  ┌────────────────────────────────────────────────────────┐
//!  │  StoneSwarm                                            │
//!  │                                                        │
//!  │  Transport: TCP + Noise (Ed25519) + Yamux              │
//!  │           + Relay (für NAT-Traversal)                  │
//!  │                                                        │
//!  │  Protokolle:                                           │
//!  │  ├── Identify   – Peer-Metadaten austauschen           │
//!  │  ├── Kademlia   – Bootstrap + Peer-Discovery           │
//!  │  ├── mDNS       – Lokale/private Netz-Discovery        │
//!  │  ├── Gossipsub  – Block-Broadcast (pub/sub)            │
//!  │  ├── RequestResponse – Block-/Chunk-Austausch          │
//!  │  ├── Relay (Client) – NAT-Traversal via Relay-Server   │
//!  │  ├── DCUtR      – Direct Connection Upgrade (Hole-     │
//!  │  │                Punching nach Relay-Verbindung)       │
//!  │  ├── AutoNAT    – Automatische NAT-Erkennung           │
//!  │  └── UPnP       – Automatisches Port-Forwarding        │
//!  │                                                        │
//!  │  Identität: Ed25519-Keypair (stone_data/p2p.key)       │
//!  └────────────────────────────────────────────────────────┘
//! ```
//!
//! ## NAT-Traversal Strategie
//!
//! Nodes hinter NAT/Firewall können sich **ohne Port-Freigabe** verbinden:
//!
//! 1. **UPnP** – Versucht automatisch den Router zu konfigurieren (funktioniert
//!    bei ca. 50% der Home-Router)
//! 2. **AutoNAT** – Erkennt automatisch ob wir hinter NAT sind
//! 3. **Relay** – Wenn hinter NAT: Verbindung über einen öffentlichen Relay-Node
//!    als Zwischenstation (langsamer, aber funktioniert immer)
//! 4. **DCUtR** (Hole-Punching) – Nach der Relay-Verbindung wird automatisch
//!    ein direkter UDP/TCP-Tunnel versucht (schneller als Relay)
//!
//! ## Sicherheitsmodell
//!
//! - Jeder Node besitzt ein Ed25519-Keypair (`stone_data/p2p.key`)
//! - Noise-Protokoll authentifiziert + verschlüsselt **jeden** TCP-Stream
//! - `PeerId` = SHA-256 des Public Keys → kryptographische Peer-Identität
//! - Bootstrap-Nodes sind fest konfiguriert (ENV oder Config-Datei)
//! - Kein unbekannter Peer kann sich ohne gültigen Noise-Handshake verbinden
//!
//! ## Topics (Gossipsub)
//!
//! | Topic              | Inhalt                               |
//! |--------------------|--------------------------------------|
//! | `stone/blocks/v1`  | Neue Blöcke (JSON-serialisiert)      |
//! | `stone/peers/v1`   | Peer-Ankündigungen                   |

use crate::blockchain::Block;
use crate::psk::load_pnet_key;
use futures_util::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, Transport as _,
    autonat,
    dcutr,
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identify,
    kad::{self, store::MemoryStore},
    mdns,
    noise,
    pnet,
    relay,
    request_response::{self, ProtocolSupport},
    swarm::SwarmEvent,
    tcp,
    upnp,
    yamux,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc};

// ─── Duplikat-Filter Kapazität ────────────────────────────────────────────────
/// Wie viele Block-Hashes im Seen-Cache behalten werden (LRU-Approximation via VecDeque)
const SEEN_CACHE_SIZE: usize = 2048;

// ─── Konstanten ───────────────────────────────────────────────────────────────

const DEFAULT_DATA_DIR: &str = "stone_data";
const P2P_KEY_FILENAME: &str = "p2p.key";
const P2P_CONFIG_FILENAME: &str = "p2p_config.json";

pub const TOPIC_BLOCKS: &str = "stone/blocks/v1";
pub const TOPIC_PEERS: &str = "stone/peers/v1";

/// Standard-libp2p-Port des Stone-Netzwerks
pub const DEFAULT_P2P_PORT: u16 = 7654;

// ─── Built-in Seed-Nodes ──────────────────────────────────────────────────────
//
// Mindestens ein Seed-Node ist nötig damit neue Nodes das Netzwerk finden können.
// Die Seed-Nodes werden als Bootstrap UND als Relay genutzt.
// Weitere Nodes können per ENV (STONE_BOOTSTRAP_NODES) hinzugefügt werden.
//
// Format: "/ip4/<IP>/tcp/<PORT>/p2p/<PeerId>"
//
// HINWEIS: Diese Liste kann per `STONE_NO_SEED=1` deaktiviert werden.
//          Das ist nützlich für komplett private / isolierte Netzwerke.

/// Eingebaute Seed-Nodes – der erste Einstiegspunkt ins Stone-Netzwerk.
/// Jeder dieser Nodes ist gleichzeitig Relay-Server und Bootstrap-Node.
const SEED_NODES: &[&str] = &[
    // Server-Node (unrootles) – Öffentliche IPv6
    "/ip6/2a0d:3341:b16b:4808:5054:ff:fea7:bab0/tcp/4001/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd",
    // Server-Node (unrootles) – Tailscale (Fallback)
    "/ip4/100.90.28.68/tcp/4001/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd",
];

/// Gibt das aktive Daten-Verzeichnis zurück.
/// Kann per `STONE_DATA_DIR` überschrieben werden.
fn data_dir() -> String {
    std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string())
}

fn p2p_key_file() -> String {
    format!("{}/{}", data_dir(), P2P_KEY_FILENAME)
}

fn p2p_config_file() -> String {
    format!("{}/{}", data_dir(), P2P_CONFIG_FILENAME)
}

// ─── P2P-Konfiguration ────────────────────────────────────────────────────────

/// Persistente Konfiguration für das P2P-Netzwerk.
/// Wird in `stone_data/p2p_config.json` gespeichert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Feste Bootstrap-Nodes: `["/ip4/1.2.3.4/tcp/7654/p2p/<PeerId>", ...]`
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,

    /// Lokaler Listen-Adresse (Standard: `/ip4/0.0.0.0/tcp/7654`)
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// mDNS aktivieren (für private / lokale Netzwerke)
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,

    /// Kademlia DHT aktivieren (für öffentliche Bootstrap-Nodes)
    #[serde(default = "default_true")]
    pub kad_enabled: bool,

    /// Maximale Peer-Anzahl
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,

    /// Verbindungs-Timeout in Sekunden
    #[serde(default = "default_timeout")]
    pub connection_timeout_secs: u64,

    /// Reconnect-Intervall für Bootstrap-Nodes in Sekunden (0 = kein Reconnect)
    #[serde(default = "default_reconnect")]
    pub reconnect_interval_secs: u64,

    /// Chain-Sync bei Connect: fehlende Blöcke automatisch nachladen
    #[serde(default = "default_true")]
    pub auto_sync_on_connect: bool,

    // ─── NAT-Traversal ──────────────────────────────────────────────────────

    /// Relay-Nodes für NAT-Traversal (Multiaddr mit PeerId).
    /// Nodes hinter NAT reservieren einen Platz auf diesen Relays,
    /// damit andere Nodes sie über den Relay erreichen können.
    /// Format: `["/ip4/1.2.3.4/tcp/7654/p2p/<PeerId>", ...]`
    #[serde(default)]
    pub relay_nodes: Vec<String>,

    /// AutoNAT aktivieren – erkennt automatisch ob wir hinter NAT sind
    #[serde(default = "default_true")]
    pub autonat_enabled: bool,

    /// UPnP aktivieren – versucht automatisches Port-Forwarding am Router
    #[serde(default = "default_true")]
    pub upnp_enabled: bool,

    /// DCUtR (Hole-Punching) aktivieren – direkter Tunnel nach Relay-Verbindung
    #[serde(default = "default_true")]
    pub dcutr_enabled: bool,

    /// Dieser Node fungiert als Relay-Server für andere Nodes.
    /// Standardmäßig aktiviert – jeder Node hilft dem Netzwerk indem er
    /// als Relay für Nodes hinter NAT fungiert.
    #[serde(default = "default_true")]
    pub relay_server_enabled: bool,
}

fn default_listen_addr() -> String {
    format!("/ip4/0.0.0.0/tcp/{DEFAULT_P2P_PORT}")
}
fn default_true() -> bool { true }
fn default_max_peers() -> usize { 50 }
fn default_timeout() -> u64 { 30 }
fn default_reconnect() -> u64 { 60 }

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: Vec::new(),
            listen_addr: default_listen_addr(),
            mdns_enabled: true,
            kad_enabled: true,
            max_peers: 50,
            connection_timeout_secs: 30,
            reconnect_interval_secs: 60,
            auto_sync_on_connect: true,
            relay_nodes: Vec::new(),
            autonat_enabled: true,
            upnp_enabled: true,
            dcutr_enabled: true,
            relay_server_enabled: true,
        }
    }
}

impl P2pConfig {
    pub fn load_or_default() -> Self {
        if let Ok(data) = fs::read_to_string(p2p_config_file()) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            let cfg = Self::default();
            cfg.save();
            cfg
        }
    }

    pub fn save(&self) {
        let dir = data_dir();
        let _ = fs::create_dir_all(&dir);
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(p2p_config_file(), json);
        }
    }

    /// Bootstrap-Nodes aus ENV `STONE_BOOTSTRAP_NODES` (kommagetrennt) laden
    /// und eingebaute Seed-Nodes hinzufügen.
    pub fn merge_env(&mut self) {
        // ── Seed-Nodes automatisch hinzufügen ─────────────────────────────────
        // Kann per STONE_NO_SEED=1 deaktiviert werden (für isolierte Netze)
        if std::env::var("STONE_NO_SEED").as_deref() != Ok("1") {
            for seed in SEED_NODES {
                let seed_str = seed.to_string();
                // Als Bootstrap-Node
                if !self.bootstrap_nodes.contains(&seed_str) {
                    self.bootstrap_nodes.push(seed_str.clone());
                }
                // Auch als Relay-Node (für NAT-Traversal)
                if !self.relay_nodes.contains(&seed_str) {
                    self.relay_nodes.push(seed_str);
                }
            }
        }

        if let Ok(raw) = std::env::var("STONE_BOOTSTRAP_NODES") {
            for addr in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if !self.bootstrap_nodes.contains(&addr.to_string()) {
                    self.bootstrap_nodes.push(addr.to_string());
                }
            }
        }
        // STONE_P2P_LISTEN: volle Multiaddr, z.B. /ip4/0.0.0.0/tcp/7655
        if let Ok(addr) = std::env::var("STONE_P2P_LISTEN") {
            self.listen_addr = addr;
        }
        // STONE_P2P_PORT: nur Portnummer – überschreibt Port in listen_addr
        if let Ok(port_str) = std::env::var("STONE_P2P_PORT") {
            if let Ok(port) = port_str.parse::<u16>() {
                // Schema (ip4/ip6) der bestehenden listen_addr beibehalten
                if self.listen_addr.starts_with("/ip6/") {
                    self.listen_addr = format!("/ip6/::/tcp/{port}");
                } else {
                    self.listen_addr = format!("/ip4/0.0.0.0/tcp/{port}");
                }
            }
        }
        // STONE_RELAY_NODES: kommagetrennte Relay-Node-Adressen
        if let Ok(raw) = std::env::var("STONE_RELAY_NODES") {
            for addr in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if !self.relay_nodes.contains(&addr.to_string()) {
                    self.relay_nodes.push(addr.to_string());
                }
            }
        }
        // STONE_RELAY_SERVER=1 → diesen Node als Relay-Server aktivieren
        if std::env::var("STONE_RELAY_SERVER").as_deref() == Ok("1") {
            self.relay_server_enabled = true;
        }
    }
}

// ─── Nachrichten zwischen Swarm-Task und AppState ─────────────────────────────

/// Events die der Swarm-Task an den Rest der Anwendung sendet.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// Neuer Peer verbunden
    PeerConnected { peer_id: String, addr: String },
    /// Peer getrennt
    PeerDisconnected { peer_id: String },
    /// Neuer Block per Gossipsub empfangen (bereits dedupliziert)
    BlockReceived { block: Box<Block>, from_peer: String },
    /// Peer hat sich identifiziert
    PeerIdentified { peer_id: String, agent: String, addresses: Vec<String> },
    /// Chain-Sync gestartet: Peer hat mehr Blöcke als wir
    SyncStarted { peer_id: String, local_count: u64, remote_count: u64 },
    /// Chain-Sync abgeschlossen
    SyncCompleted { peer_id: String, blocks_added: u64 },
    /// Listener gestartet
    Listening { addr: String },
    /// Fehler
    Error { message: String },

    // ── Shard-Events ──────────────────────────────────────────────────────
    /// Ein angeforderter Shard wurde empfangen
    ShardReceived {
        chunk_hash: String,
        shard_index: u8,
        data: Vec<u8>,
        from_peer: String,
    },
    /// Ein Shard wurde erfolgreich auf einem Peer gespeichert
    ShardStored {
        chunk_hash: String,
        shard_index: u8,
        peer_id: String,
        success: bool,
        error: Option<String>,
    },
    /// Shard-Store-Anfrage fehlgeschlagen (Netzwerk)
    ShardRequestFailed {
        chunk_hash: String,
        shard_index: u8,
        peer_id: String,
        error: String,
    },
}

/// Befehle die von außen an den Swarm-Task gesendet werden.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Block an alle Peers broadcasten
    BroadcastBlock(Box<Block>),
    /// Manuell einen Peer hinzufügen
    DialPeer(Multiaddr),
    /// Chain-Sync mit einem bestimmten Peer anstoßen
    SyncWithPeer { peer_id: PeerId, our_block_count: u64 },
    /// Aktuelle Peer-Liste abfragen
    GetPeers(tokio::sync::oneshot::Sender<Vec<PeerInfo>>),
    /// Anzahl der bekannten Blöcke mitteilen (für Sync-Handshake)
    SetLocalChainCount(u64),
    /// Einen Peer anpingen – Latenz messen via Request/Response
    Ping {
        peer_id: PeerId,
        reply: tokio::sync::oneshot::Sender<PingResult>,
    },
    /// Vollständigen Netzwerkstatus abfragen
    GetStatus(tokio::sync::oneshot::Sender<NetworkStatus>),
    /// Swarm beenden
    Shutdown,

    // ── Shard-Befehle ─────────────────────────────────────────────────────
    /// Shard von einem Peer anfordern
    RequestShard {
        peer_id: PeerId,
        chunk_hash: String,
        shard_index: u8,
    },
    /// Shard an einen Peer zum Speichern senden
    StoreShard {
        peer_id: PeerId,
        chunk_hash: String,
        shard_index: u8,
        shard_hash: String,
        data: Vec<u8>,
    },
    /// Shard-Liste eines Peers für einen bestimmten Chunk abfragen
    ListPeerShards {
        peer_id: PeerId,
        chunk_hash: String,
        reply: tokio::sync::oneshot::Sender<Vec<u8>>,
    },
}

/// Ergebnis eines Pings an einen Peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub peer_id: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Vollständiger Verbindungsstatus aller bekannten Peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub local_peer_id: String,
    pub connected_peers: usize,
    pub total_known_peers: usize,
    pub gossipsub_mesh_size: usize,
    pub chain_block_count: u64,
    pub peers: Vec<PeerStatus>,
}

/// Detaillierter Status eines einzelnen Peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub peer_id: String,
    pub addresses: Vec<String>,
    pub agent_version: String,
    pub connected: bool,
    pub last_seen: i64,
    pub last_seen_ago_secs: i64,
    pub blocks_received: u64,
    pub in_gossipsub_mesh: bool,
}

/// Vereinfachte Peer-Info für die API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub addresses: Vec<String>,
    pub agent_version: String,
    pub connected: bool,
    /// Zeitpunkt der letzten Verbindung (Unix-Sekunden)
    pub last_seen: i64,
    /// Anzahl empfangener Blöcke von diesem Peer
    pub blocks_received: u64,
}

// ─── Request/Response Typen ───────────────────────────────────────────────────

/// Anfrage an einen Peer: gib mir Block mit Index `index`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub block_index: u64,
}

/// Antwort: der Block (oder None wenn nicht vorhanden)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub block: Option<Block>,
}

// ─── Shard Exchange Typen ─────────────────────────────────────────────────────

/// Anfrage an einen Peer: Shard-Operationen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardRequest {
    /// Frage: Hast du diesen Shard? Gib mir die Daten.
    GetShard {
        chunk_hash: String,
        shard_index: u8,
    },
    /// Speichere diesen Shard für mich (bei Upload-Verteilung).
    StoreShard {
        chunk_hash: String,
        shard_index: u8,
        shard_hash: String,
        data: Vec<u8>,
    },
    /// Welche Shards hast du für diesen Chunk?
    ListShards {
        chunk_hash: String,
    },
}

/// Antwort auf eine Shard-Anfrage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardResponse {
    /// Shard-Daten (None wenn nicht vorhanden)
    ShardData {
        chunk_hash: String,
        shard_index: u8,
        data: Option<Vec<u8>>,
    },
    /// Bestätigung: Shard wurde gespeichert (oder Fehler)
    StoreResult {
        chunk_hash: String,
        shard_index: u8,
        success: bool,
        error: Option<String>,
    },
    /// Liste lokaler Shard-Indices für einen Chunk
    ShardList {
        chunk_hash: String,
        indices: Vec<u8>,
    },
}

// ─── Keypair-Persistenz ───────────────────────────────────────────────────────

/// Lädt das Ed25519-Keypair für die P2P-Identität oder erstellt ein neues.
///
/// Das Keypair wird unter `stone_data/p2p.key` gespeichert (protobuf-kodiert).
/// Der zugehörige `PeerId` ist der SHA-256 des Public Keys.
pub fn load_or_create_keypair() -> libp2p::identity::Keypair {
    let key_file = p2p_key_file();
    let dir = data_dir();
    fs::create_dir_all(&dir).unwrap_or(());

    if let Ok(bytes) = fs::read(&key_file) {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return kp;
        }
    }

    // Neues Keypair generieren
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let encoded = kp.to_protobuf_encoding().expect("Keypair-Kodierung fehlgeschlagen");

    if let Err(e) = fs::write(&key_file, &encoded) {
        eprintln!("[p2p] WARNUNG: Keypair konnte nicht gespeichert werden: {e}");
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mut perms) = fs::metadata(&key_file).map(|m| m.permissions()) {
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&key_file, perms);
            }
        }
        let peer_id = libp2p::PeerId::from_public_key(&kp.public());
        println!("[p2p] Neues P2P-Keypair generiert. PeerId: {peer_id}");
        println!("[p2p] Gespeichert: {key_file}");
    }

    kp
}

/// Liest die PeerId ohne den vollen Keypair zu laden (für Logging).
pub fn read_peer_id() -> Option<String> {
    let bytes = fs::read(p2p_key_file()).ok()?;
    let kp = libp2p::identity::Keypair::from_protobuf_encoding(&bytes).ok()?;
    Some(libp2p::PeerId::from_public_key(&kp.public()).to_string())
}

// ─── Swarm Behaviour ──────────────────────────────────────────────────────────

#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct StoneBehaviour {
    pub identify: identify::Behaviour,
    pub kad: kad::Behaviour<MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub block_exchange: request_response::cbor::Behaviour<BlockRequest, BlockResponse>,
    pub shard_exchange: request_response::cbor::Behaviour<ShardRequest, ShardResponse>,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: relay::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::Behaviour,
    pub upnp: upnp::tokio::Behaviour,
}

// ─── Swarm aufbauen ───────────────────────────────────────────────────────────

/// Erstellt den libp2p-Swarm mit allen Protokollen + NAT-Traversal.
///
/// Transport-Schichtung:
///   TCP → Noise → Yamux  (direkte Verbindungen)
///   +  Relay-Transport   (für Nodes hinter NAT)
///
/// Die Relay-Client-Behaviour wird automatisch mit dem Transport verknüpft.
/// DCUtR versucht nach einer Relay-Verbindung einen direkten Tunnel (Hole-Punch).
pub fn build_swarm(
    keypair: libp2p::identity::Keypair,
    config: &P2pConfig,
) -> Result<Swarm<StoneBehaviour>, Box<dyn std::error::Error>> {
    let peer_id = PeerId::from_public_key(&keypair.public());

    // ── Gossipsub ─────────────────────────────────────────────────────────────
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(4 * 1024 * 1024) // 4 MiB pro Block
        .build()
        .map_err(|e| format!("Gossipsub-Config: {e}"))?;

    let gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| format!("Gossipsub init: {e}"))?;

    // ── Kademlia ──────────────────────────────────────────────────────────────
    let mut kad_config = kad::Config::new(
        libp2p::StreamProtocol::new("/stone/kad/1.0.0"),
    );
    kad_config.set_query_timeout(Duration::from_secs(config.connection_timeout_secs));
    let kad = kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kad_config);

    // ── Identify ──────────────────────────────────────────────────────────────
    let identify = identify::Behaviour::new(identify::Config::new(
        "/stone/id/1.0.0".to_string(),
        keypair.public(),
    ));

    // ── mDNS ──────────────────────────────────────────────────────────────────
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;

    // ── Request/Response (Block-Austausch) ────────────────────────────────────
    let block_exchange = request_response::cbor::Behaviour::new(
        [(
            libp2p::StreamProtocol::new("/stone/block-exchange/1.0.0"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    );

    // ── Request/Response (Shard-Austausch) ────────────────────────────────────
    let shard_exchange = request_response::cbor::Behaviour::new(
        [(
            libp2p::StreamProtocol::new("/stone/shard-exchange/1.0.0"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    );

    // ── AutoNAT – erkennt ob wir hinter NAT sind ─────────────────────────────
    let autonat = autonat::Behaviour::new(peer_id, autonat::Config {
        boot_delay: Duration::from_secs(10),
        refresh_interval: Duration::from_secs(60),
        retry_interval: Duration::from_secs(30),
        throttle_server_period: Duration::from_secs(15),
        ..Default::default()
    });

    // ── UPnP – automatisches Port-Forwarding ──────────────────────────────────
    let upnp = upnp::tokio::Behaviour::default();

    // ── Relay Server – jeder Node ist potentiell ein Relay ────────────────────
    // Öffentlich erreichbare Nodes leiten Traffic für Nodes hinter NAT weiter.
    // Rate-Limiting schützt vor Missbrauch.
    let relay_server = relay::Behaviour::new(
        peer_id,
        relay::Config {
            max_reservations: 128,
            max_reservations_per_peer: 4,
            reservation_duration: Duration::from_secs(3600),   // 1h
            max_circuits: 64,
            max_circuits_per_peer: 4,
            max_circuit_duration: Duration::from_secs(600),    // 10min pro Circuit
            max_circuit_bytes: 16 * 1024 * 1024,               // 16 MiB pro Circuit
            ..Default::default()
        },
    );

    // ── Swarm mit Relay-Client-Transport aufbauen ─────────────────────────────
    //
    // SwarmBuilder.with_relay_client() gibt uns:
    //  1. Den Relay-Client-Transport (für eingehende relayed Verbindungen)
    //  2. Die Relay-Client-Behaviour (wird im StoneBehaviour gehalten)
    //
    // DCUtR baut auf dem Relay auf: nach einer Relay-Verbindung wird
    // automatisch versucht eine direkte Verbindung herzustellen (Hole-Punching).

    let pnet_key = load_pnet_key();

    let swarm = if let Some(psk) = pnet_key {
        // PSK aktiv: pnet-Layer vor Noise einschalten
        // HINWEIS: Mit PSK ist Relay-Transport nicht kompatibel (pnet erwartet
        // direkte TCP-Verbindung). Relay wird übersprungen.
        let pnet_config = pnet::PnetConfig::new(psk);
        println!("[p2p] ⚠ PSK aktiv – Relay/DCUtR/UPnP deaktiviert (nur direkte Verbindungen)");
        // Dummy relay_client + dcutr für das Behaviour-Struct
        SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|key| {
                let noise_config = noise::Config::new(key)?;
                let base = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
                let transport = base
                    .and_then(move |socket, _endpoint| pnet_config.handshake(socket))
                    .upgrade(libp2p::core::upgrade::Version::V1)
                    .authenticate(noise_config)
                    .multiplex(yamux::Config::default())
                    .boxed();
                Ok(transport)
            })?
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| {
                let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());
                StoneBehaviour {
                    identify: identify,
                    kad: kad,
                    mdns: mdns,
                    gossipsub: gossipsub,
                    block_exchange: block_exchange,
                    shard_exchange: shard_exchange,
                    relay_client,
                    relay_server,
                    dcutr,
                    autonat,
                    upnp,
                }
            })?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(
                    config.connection_timeout_secs * 2,
                ))
            })
            .build()
    } else {
        // Ohne PSK: voller NAT-Traversal Stack
        //   TCP + Noise + Yamux + Relay-Client + DCUtR
        SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| {
                let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());
                StoneBehaviour {
                    identify: identify,
                    kad: kad,
                    mdns: mdns,
                    gossipsub: gossipsub,
                    block_exchange: block_exchange,
                    shard_exchange: shard_exchange,
                    relay_client,
                    relay_server,
                    dcutr,
                    autonat,
                    upnp,
                }
            })?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(
                    config.connection_timeout_secs * 2,
                ))
            })
            .build()
    };

    Ok(swarm)
}

// ─── Swarm-Task ───────────────────────────────────────────────────────────────

/// Zustand des laufenden Swarm-Tasks.
struct SwarmTask {
    swarm: Swarm<StoneBehaviour>,
    event_tx: broadcast::Sender<NetworkEvent>,
    cmd_rx: mpsc::Receiver<NetworkCommand>,

    /// Bekannte Peers: PeerId → PeerInfo
    peers: HashMap<PeerId, PeerInfo>,

    /// Seen-Cache: Block-Hashes die bereits verarbeitet wurden (Duplicate-Filter).
    seen_hashes: HashSet<String>,
    seen_order: VecDeque<String>,

    /// Unsere aktuelle Chain-Länge (für Sync-Handshake)
    local_chain_count: u64,

    /// Bootstrap-Adressen für Reconnect
    bootstrap_addrs: Vec<String>,

    /// Zeitpunkt des letzten Reconnect-Versuchs
    last_reconnect: Instant,

    config: P2pConfig,

    /// Ausstehende Pings: request_id → (peer_id_str, start_instant, reply_channel)
    pending_pings: HashMap<
        request_response::OutboundRequestId,
        (String, std::time::Instant, tokio::sync::oneshot::Sender<PingResult>),
    >,

    // ─── NAT-Traversal Zustand ──────────────────────────────────────────────

    /// Erkannter NAT-Status
    nat_status: NatStatus,

    /// Relay-Nodes bei denen wir eine Reservation haben
    active_relays: HashSet<PeerId>,

    /// Relay-Adressen die wir versuchen sollen
    relay_addrs: Vec<String>,

    // ─── Sicherheit: Peer-Scoring ───────────────────────────────────────────

    /// Penalty-Score pro Peer: wenn > BAN_THRESHOLD → Peer wird gebannt
    peer_penalties: HashMap<PeerId, PeerPenalty>,

    /// Shard-Speicher für eingehende Shard-Requests
    shard_store: crate::shard::ShardStore,

    /// Ausstehende Shard-Listen-Anfragen: request_id → reply
    pending_shard_lists: HashMap<
        request_response::OutboundRequestId,
        (String, tokio::sync::oneshot::Sender<Vec<u8>>),
    >,
}

/// Tracking für Fehlverhalten eines Peers
struct PeerPenalty {
    score: u32,
    last_offense: Instant,
    reasons: Vec<String>,
}

/// Ab diesem Score wird ein Peer gebannt (Verbindung getrennt, kein Re-Dial)
const BAN_THRESHOLD: u32 = 200;

/// Penalty-Punkte verfallen nach dieser Zeit (Minuten)
const PENALTY_DECAY_MINS: u64 = 30;

/// NAT-Status des Nodes
#[derive(Debug, Clone, PartialEq)]
enum NatStatus {
    Unknown,
    Public,
    Private,
}

/// Entfernt die `/p2p/<PeerId>`-Komponente am Ende einer Multiaddr.
/// mDNS liefert Adressen wie `/ip4/1.2.3.4/tcp/7654/p2p/12D3Koo…`.
/// libp2p lehnt es ab, wenn man diese an `DialOpts::peer_id(...).addresses(…)`
/// übergibt — die PeerId wäre dann doppelt vorhanden → EINVAL (os error 22).
fn strip_p2p_suffix(addr: libp2p::Multiaddr) -> libp2p::Multiaddr {
    use libp2p::multiaddr::Protocol;
    let without: libp2p::Multiaddr = addr
        .into_iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect();
    without
}

impl SwarmTask {
    async fn run(mut self) {
        let listen_addr: Multiaddr = match self.config.listen_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                let _ = self.event_tx.send(NetworkEvent::Error {
                    message: format!("Ungültige Listen-Adresse: {e}"),
                });
                return;
            }
        };

        // Port-Fallback: falls konfigurierter Port belegt → zufälligen Port nehmen
        if let Err(e) = self.swarm.listen_on(listen_addr.clone()) {
            eprintln!("[p2p] ⚠️  Konnte {listen_addr} nicht binden: {e}");
            let fallback: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
            if let Err(e2) = self.swarm.listen_on(fallback) {
                let _ = self.event_tx.send(NetworkEvent::Error {
                    message: format!("Kein P2P-Port verfügbar: {e2}"),
                });
                return;
            }
            eprintln!("[p2p] ℹ️  Nutze zufälligen P2P-Port (STONE_P2P_PORT setzen um festen Port zu erzwingen)");
        }

        // Dual-Stack: wenn IPv6 konfiguriert, zusätzlich auf IPv4 lauschen
        if self.config.listen_addr.starts_with("/ip6/") {
            // Port aus listen_addr extrahieren
            let port = listen_addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::Tcp(port) = p {
                    Some(port)
                } else {
                    None
                }
            }).unwrap_or(4001);
            let ipv4_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap();
            match self.swarm.listen_on(ipv4_addr.clone()) {
                Ok(_) => println!("[p2p] Dual-Stack: lausche zusätzlich auf {ipv4_addr}"),
                Err(e) => eprintln!("[p2p] ⚠️  IPv4-Dual-Stack fehlgeschlagen: {e}"),
            }
        }

        // Bootstrap-Nodes einwählen
        for addr_str in self.bootstrap_addrs.clone() {
            self.dial_bootstrap(&addr_str);
        }

        if !self.bootstrap_addrs.is_empty() && self.config.kad_enabled {
            let _ = self.swarm.behaviour_mut().kad.bootstrap();
        }

        // Relay-Reservierungen herstellen (falls konfiguriert)
        if !self.relay_addrs.is_empty() {
            println!("[p2p] 📡 {} Relay-Node(s) konfiguriert – stelle Verbindungen her...", self.relay_addrs.len());
            self.establish_relay_reservations();
        }

        // Reconnect-Intervall (0 = deaktiviert)
        let reconnect_interval = if self.config.reconnect_interval_secs > 0 {
            Duration::from_secs(self.config.reconnect_interval_secs)
        } else {
            Duration::from_secs(u64::MAX / 2) // praktisch nie
        };

        let mut reconnect_ticker = tokio::time::interval(reconnect_interval);
        reconnect_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = self.swarm.next() => {
                    match event {
                        Some(ev) => self.handle_swarm_event(ev).await,
                        None => break,
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(c) => { if self.handle_command(c) { break; } }
                        None => break,
                    }
                }
                _ = reconnect_ticker.tick() => {
                    self.reconnect_bootstrap_nodes();
                }
            }
        }
        println!("[p2p] Swarm-Task beendet.");
    }

    // ── Duplicate-Filter ─────────────────────────────────────────────────────

    /// Gibt true zurück wenn der Hash bereits gesehen wurde (Duplikat).
    fn is_duplicate(&mut self, hash: &str) -> bool {
        if self.seen_hashes.contains(hash) {
            return true;
        }
        // Neu: in Cache aufnehmen
        if self.seen_order.len() >= SEEN_CACHE_SIZE {
            // Ältesten Eintrag entfernen
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_hashes.remove(&oldest);
            }
        }
        self.seen_hashes.insert(hash.to_string());
        self.seen_order.push_back(hash.to_string());
        false
    }

    // ── Bootstrap / Reconnect ────────────────────────────────────────────────

    fn dial_bootstrap(&mut self, addr_str: &str) {
        // Placeholder-Adressen aus der Beispiel-Config überspringen
        if addr_str.contains("12D3KooW...") || addr_str.contains("1.2.3.4") {
            println!("[p2p] Bootstrap '{addr_str}' übersprungen (Placeholder) – bitte echte Adresse eintragen");
            return;
        }
        if addr_str.trim().is_empty() {
            return;
        }
        match addr_str.parse::<Multiaddr>() {
            Ok(addr) => {
                use libp2p::multiaddr::Protocol;
                let peer_id = addr.iter().find_map(|p| {
                    if let Protocol::P2p(pid) = p { Some(pid) } else { None }
                });
                if let Some(pid) = peer_id {
                    // Eigene PeerId nicht anwählen (Seed-Node wählt sich sonst selbst an)
                    if pid == *self.swarm.local_peer_id() {
                        return;
                    }
                    self.swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                    println!("[p2p] Bootstrap-Node: {pid} @ {addr}");
                }
                if let Err(e) = self.swarm.dial(addr.clone()) {
                    eprintln!("[p2p] Dial {addr} fehlgeschlagen: {e}");
                }
            }
            Err(e) => eprintln!("[p2p] Ungültige Bootstrap-Adresse '{addr_str}': {e}"),
        }
    }

    fn reconnect_bootstrap_nodes(&mut self) {
        // Nur Bootstrap-Nodes reconnecten die gerade nicht verbunden sind
        let disconnected_count = self.peers.values()
            .filter(|p| !p.connected)
            .count();

        if disconnected_count == 0 && !self.peers.is_empty() {
            return; // alle bereits verbunden
        }

        let connected_peer_ids: HashSet<String> = self.peers.values()
            .filter(|p| p.connected)
            .map(|p| p.peer_id.clone())
            .collect();

        for addr_str in self.bootstrap_addrs.clone() {
            use libp2p::multiaddr::Protocol;
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                let peer_id_str = addr.iter().find_map(|p| {
                    if let Protocol::P2p(pid) = p {
                        Some(pid.to_string())
                    } else {
                        None
                    }
                });
                if let Some(pid) = peer_id_str {
                    // Eigene PeerId nicht anwählen
                    let local = self.swarm.local_peer_id().to_string();
                    if pid == local {
                        continue;
                    }
                    if !connected_peer_ids.contains(&pid) {
                        println!("[p2p] Reconnect-Versuch: {pid}");
                        let _ = self.swarm.dial(addr);
                    }
                }
            }
        }
        self.last_reconnect = Instant::now();
    }

    // ── Swarm-Events ─────────────────────────────────────────────────────────

    async fn handle_swarm_event(&mut self, event: SwarmEvent<StoneBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                // Gebannte Peers sofort trennen
                if self.is_peer_banned(&peer_id) {
                    eprintln!("[p2p] 🔨 Verbindung von gebantem Peer {peer_id} getrennt");
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                let addr = endpoint.get_remote_address().to_string();
                let now = chrono::Utc::now().timestamp();
                println!("[p2p] ✓ Verbunden: {peer_id} @ {addr}");

                let entry = self.peers.entry(peer_id).or_insert_with(|| PeerInfo {
                    peer_id: peer_id.to_string(),
                    addresses: vec![addr.clone()],
                    agent_version: String::new(),
                    connected: false,
                    last_seen: now,
                    blocks_received: 0,
                });
                entry.connected = true;
                entry.last_seen = now;
                if !entry.addresses.contains(&addr) {
                    entry.addresses.push(addr.clone());
                }

                let _ = self.event_tx.send(NetworkEvent::PeerConnected {
                    peer_id: peer_id.to_string(),
                    addr,
                });

                // Chain-Sync anstoßen: Handshake-Nachricht via Gossipsub senden
                if self.config.auto_sync_on_connect {
                    self.send_sync_handshake();
                }
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                let reason = cause.map(|e| e.to_string()).unwrap_or_default();
                println!("[p2p] ✗ Getrennt: {peer_id} ({reason})");

                if let Some(info) = self.peers.get_mut(&peer_id) {
                    info.connected = false;
                }
                let _ = self.event_tx.send(NetworkEvent::PeerDisconnected {
                    peer_id: peer_id.to_string(),
                });
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                let local_peer = *self.swarm.local_peer_id();
                let full_addr = format!("{address}/p2p/{local_peer}");
                println!("[p2p] 🎧 Lausche auf: {full_addr}");
                let _ = self.event_tx.send(NetworkEvent::Listening { addr: full_addr });
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let local = *self.swarm.local_peer_id();
                // Selbst-Dial-Fehler (eigene VPN/Multi-Interface-Adressen) unterdrücken
                if peer_id == Some(local) {
                    return;
                }
                // Harmlose Race-Conditions komplett stumm schalten:
                // - "Already connected" / "Pending" → bereits verbunden, kein Problem
                // - os error 48 (EADDRINUSE, macOS) → TCP-Quelladresse kurz belegt, Peer
                //   verbindet sich gleichzeitig von der anderen Seite → ignorieren
                // - os error 22 (EINVAL) → /p2p/-Suffix im Dial-Addr, bereits gefixt aber
                //   kann noch aus alten Kademlia-Einträgen kommen → ignorieren
                let err_str = error.to_string();
                let is_harmless = err_str.contains("Already connected")
                    || err_str.contains("Pending connection")
                    || err_str.contains("WrongPeerId")
                    || err_str.contains("os error 48")   // EADDRINUSE (macOS)
                    || err_str.contains("os error 22")   // EINVAL
                    || err_str.contains("Address already in use")
                    || err_str.contains("Invalid argument");

                // Wenn der Peer jetzt bereits verbunden ist, war der Fehler eine Race-Condition
                let peer_now_connected = peer_id
                    .map(|id| self.swarm.is_connected(&id))
                    .unwrap_or(false);

                if is_harmless || peer_now_connected {
                    // Nur als Debug ausgeben, kein Fehler
                    return;
                }
                eprintln!("[p2p] Verbindungsfehler zu {:?}: {error}", peer_id);
            }

            SwarmEvent::Behaviour(bev) => self.handle_behaviour_event(bev),

            SwarmEvent::ExternalAddrConfirmed { address } => {
                println!("[p2p] 🌍 Externe Adresse bestätigt: {address}");
                // Adresse in Kademlia eintragen damit andere Nodes uns finden
                let local_peer = *self.swarm.local_peer_id();
                self.swarm.behaviour_mut().kad.add_address(
                    &local_peer,
                    address,
                );
            }

            _ => {}
        }
    }

    // ── Behaviour-Events ─────────────────────────────────────────────────────

    fn handle_behaviour_event(&mut self, event: StoneBehaviourEvent) {
        match event {
            // ── Identify ──────────────────────────────────────────────────────
            StoneBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                let addrs: Vec<String> = info.listen_addrs.iter().map(|a| a.to_string()).collect();
                println!("[p2p] Identify: {peer_id} – agent={}", info.agent_version);

                for addr in &info.listen_addrs {
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                }

                if let Some(entry) = self.peers.get_mut(&peer_id) {
                    entry.agent_version = info.agent_version.clone();
                    entry.addresses = addrs.clone();
                }

                let _ = self.event_tx.send(NetworkEvent::PeerIdentified {
                    peer_id: peer_id.to_string(),
                    agent: info.agent_version,
                    addresses: addrs,
                });
            }

            // ── mDNS ──────────────────────────────────────────────────────────
            StoneBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                let local_peer = *self.swarm.local_peer_id();

                // Adressen je Peer sammeln (Original-Addrs inkl. /p2p-Suffix behalten)
                let mut by_peer: std::collections::HashMap<
                    libp2p::PeerId,
                    Vec<libp2p::Multiaddr>,
                > = std::collections::HashMap::new();

                for (peer_id, addr) in list {
                    if peer_id == local_peer {
                        continue; // Selbst-Dial verhindern
                    }
                    println!("[p2p] mDNS entdeckt: {peer_id} @ {addr}");
                    // Kademlia bekommt die Adresse OHNE /p2p-Suffix
                    let addr_bare = strip_p2p_suffix(addr.clone());
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, addr_bare);
                    // Dial-Liste behält die Original-Adresse (mit /p2p wenn vorhanden)
                    by_peer.entry(peer_id).or_default().push(addr);
                }

                for (peer_id, addrs) in by_peer {
                    // Bereits verbunden (laut Swarm-State) → kein erneuter Dial
                    if self.swarm.is_connected(&peer_id) {
                        continue;
                    }
                    // Bereits verbunden (laut unserer Peer-Map) → überspringen
                    if self.peers.get(&peer_id).map(|p| p.connected).unwrap_or(false) {
                        continue;
                    }

                    // Bevorzuge LAN-Adressen (10.x / 192.168.x / 172.x)
                    fn is_lan(addr: &libp2p::Multiaddr) -> bool {
                        use libp2p::multiaddr::Protocol;
                        addr.iter().any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_private() && !ip.is_loopback()))
                    }

                    // Adressen sortieren: LAN-Adressen zuerst, dann Rest
                    let mut sorted_addrs = addrs.clone();
                    sorted_addrs.sort_by_key(|a| if is_lan(a) { 0u8 } else { 1u8 });

                    // Beste Adresse für das Log
                    let best_addr = sorted_addrs.first().cloned();

                    // DialOpts mit allen Adressen + NotDialing-Condition:
                    // - libp2p dedupliziert selbst (kein zweiter Dial wenn bereits pending)
                    // - strip_p2p_suffix: Kademlia braucht Adressen ohne /p2p-Suffix,
                    //   aber swarm.dial() braucht die vollständige Adresse MIT /p2p-Suffix
                    //   damit libp2p die PeerId verifizieren kann.
                    use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
                    let opts = DialOpts::peer_id(peer_id)
                        .addresses(sorted_addrs)
                        .condition(PeerCondition::NotDialing)
                        .build();

                    match self.swarm.dial(opts) {
                        Ok(_) => {
                            if let Some(a) = best_addr {
                                println!("[p2p] mDNS-Dial → {a}");
                            }
                        }
                        Err(e) => {
                            let s = e.to_string();
                            // Alle bekannten Race-Conditions stumm schalten
                            if !s.contains("condition")
                                && !s.contains("Already")
                                && !s.contains("connected")
                                && !s.contains("Pending")
                            {
                                eprintln!("[p2p] mDNS-Dial {peer_id}: {e}");
                            }
                        }
                    }
                }
            }

            StoneBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer_id, addr) in list {
                    println!("[p2p] mDNS abgelaufen: {peer_id} @ {addr}");
                }
            }

            // ── Gossipsub ─────────────────────────────────────────────────────
            StoneBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                propagation_source,
                message_id,
                ..
            }) => {
                let topic = message.topic.as_str().to_string();

                if topic == TOPIC_BLOCKS {
                    self.handle_gossip_block(message.data, propagation_source);
                } else if topic == TOPIC_SYNC_HANDSHAKE {
                    self.handle_sync_handshake(message.data, propagation_source);
                } else {
                    let _ = message_id; // acknowledged
                }
            }

            StoneBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                println!("[p2p] {peer_id} hat '{topic}' abonniert");
            }

            StoneBehaviourEvent::Gossipsub(gossipsub::Event::GossipsubNotSupported { peer_id }) => {
                eprintln!("[p2p] Gossipsub nicht unterstützt von: {peer_id}");
            }

            // ── Kademlia ──────────────────────────────────────────────────────
            StoneBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. }) => {
                println!("[p2p] Kademlia Routing: {peer}");
            }
            StoneBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })),
                ..
            }) => {
                if num_remaining == 0 {
                    println!("[p2p] ✓ Kademlia Bootstrap abgeschlossen");
                }
            }

            // ── Request/Response (Block-Sync + Ping) ──────────────────────
            StoneBehaviourEvent::BlockExchange(
                request_response::Event::Message { peer, message }
            ) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    if request.block_index == u64::MAX {
                        // Ping-Marker → sofort leere Antwort senden
                        println!("[p2p] 🏓 Ping von {peer} – antworte");
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse { block: None },
                        );
                    } else {
                        println!("[p2p] Block-Anfrage #{} von {peer}", request.block_index);
                        let _ = self.event_tx.send(NetworkEvent::Error {
                            message: format!("block-request:{}:{}", peer, request.block_index),
                        });
                        let _ = self.swarm.behaviour_mut().block_exchange.send_response(
                            channel,
                            BlockResponse { block: None },
                        );
                    }
                }
                request_response::Message::Response { request_id, response, .. } => {
                    // Ping-Antwort?
                    if let Some((peer_id_str, start, reply)) = self.pending_pings.remove(&request_id) {
                        let ms = start.elapsed().as_millis() as u64;
                        println!("[p2p] 🏓 Pong von {peer_id_str} – {ms}ms");
                        let _ = reply.send(PingResult {
                            peer_id: peer_id_str,
                            reachable: true,
                            latency_ms: Some(ms),
                            error: None,
                        });
                    } else if let Some(block) = response.block {
                        // Normaler Block-Sync
                        let hash = block.hash.clone();
                        if !self.is_duplicate(&hash) {
                            println!("[p2p] ← Block #{} via Sync von {peer}", block.index);
                            if let Some(entry) = self.peers.get_mut(&peer) {
                                entry.blocks_received += 1;
                            }
                            let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                                block: Box::new(block),
                                from_peer: peer.to_string(),
                            });
                        }
                    }
                }
            },

            // Request-Fehler (Timeout, Verbindungsabbruch)
            StoneBehaviourEvent::BlockExchange(
                request_response::Event::OutboundFailure { peer, request_id, error, .. }
            ) => {
                if let Some((peer_id_str, _, reply)) = self.pending_pings.remove(&request_id) {
                    let _ = reply.send(PingResult {
                        peer_id: peer_id_str,
                        reachable: false,
                        latency_ms: None,
                        error: Some(error.to_string()),
                    });
                } else {
                    eprintln!("[p2p] Request-Fehler zu {peer}: {error}");
                }
            }

            // ── Relay-Client Events ──────────────────────────────────────────────

            StoneBehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                ..
            }) => {
                println!("[p2p] ✅ Relay-Reservation akzeptiert");
            }

            StoneBehaviourEvent::RelayClient(relay::client::Event::OutboundCircuitEstablished {
                limit, ..
            }) => {
                println!("[p2p] 🔗 Ausgehender Relay-Circuit hergestellt (limit: {limit:?})");
            }

            StoneBehaviourEvent::RelayClient(relay::client::Event::InboundCircuitEstablished {
                src_peer_id,
                limit,
            }) => {
                println!("[p2p] 🔗 Eingehender Relay-Circuit von {src_peer_id} (limit: {limit:?})");
            }

            // ── DCUtR (Direct Connection Upgrade / Hole-Punching) ────────────────

            StoneBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            }) => {
                match result {
                    Ok(_) => {
                        println!("[p2p] 🕳️  Hole-Punch erfolgreich zu {remote_peer_id}!");
                    }
                    Err(e) => {
                        eprintln!("[p2p] ⚠ Hole-Punch fehlgeschlagen zu {remote_peer_id}: {e:?}");
                    }
                }
            }

            // ── AutoNAT (NAT-Erkennung) ──────────────────────────────────────────

            StoneBehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new }) => {
                println!("[p2p] 🌐 NAT-Status: {old:?} → {new:?}");
                match new {
                    autonat::NatStatus::Public(_addr) => {
                        self.nat_status = NatStatus::Public;
                        println!("[p2p] ✅ NAT-Status: Öffentlich erreichbar");
                    }
                    autonat::NatStatus::Private => {
                        self.nat_status = NatStatus::Private;
                        println!("[p2p] 🔒 NAT-Status: Privat – nutze Relay für Erreichbarkeit");
                        // Bei privatem NAT automatisch Relay-Reservierungen herstellen
                        self.establish_relay_reservations();
                    }
                    autonat::NatStatus::Unknown => {
                        self.nat_status = NatStatus::Unknown;
                    }
                }
            }

            StoneBehaviourEvent::Autonat(_) => {}

            // ── UPnP (Automatische Port-Weiterleitung) ──────────────────────────

            StoneBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(addr)) => {
                println!("[p2p] 🔌 UPnP: Externe Adresse hinzugefügt: {addr}");
            }

            StoneBehaviourEvent::Upnp(upnp::Event::GatewayNotFound) => {
                println!("[p2p] ℹ️  UPnP: Kein Gateway gefunden – Relay wird genutzt");
            }

            StoneBehaviourEvent::Upnp(upnp::Event::NonRoutableGateway) => {
                println!("[p2p] ℹ️  UPnP: Gateway ist nicht routbar");
            }

            StoneBehaviourEvent::Upnp(upnp::Event::ExpiredExternalAddr(addr)) => {
                println!("[p2p] ⏰ UPnP: Externe Adresse abgelaufen: {addr}");
            }

            // ── Relay-Server Events (wir leiten Traffic für andere weiter) ───────

            #[allow(deprecated)]
            StoneBehaviourEvent::RelayServer(relay::Event::ReservationReqAccepted {
                src_peer_id,
                ..
            }) => {
                println!("[p2p] 📡 Relay: Reservation von {src_peer_id} akzeptiert (wir sind Relay für diesen Node)");
            }

            StoneBehaviourEvent::RelayServer(relay::Event::ReservationReqDenied {
                src_peer_id,
            }) => {
                println!("[p2p] 📡 Relay: Reservation von {src_peer_id} abgelehnt (Limit erreicht)");
            }

            StoneBehaviourEvent::RelayServer(relay::Event::ReservationTimedOut {
                src_peer_id,
            }) => {
                println!("[p2p] 📡 Relay: Reservation von {src_peer_id} abgelaufen");
            }

            StoneBehaviourEvent::RelayServer(_) => {}

            // ── Shard-Exchange (Request/Response) ────────────────────────────
            StoneBehaviourEvent::ShardExchange(
                request_response::Event::Message { peer, message }
            ) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    match request {
                        ShardRequest::GetShard { chunk_hash, shard_index } => {
                            println!("[p2p] 📦 Shard-Anfrage: {chunk_hash}[{shard_index}] von {peer}");
                            let data = self.shard_store.read_shard(&chunk_hash, shard_index).ok();
                            let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                channel,
                                ShardResponse::ShardData { chunk_hash, shard_index, data },
                            );
                        }
                        ShardRequest::StoreShard { chunk_hash, shard_index, shard_hash, data } => {
                            println!("[p2p] 💾 Shard-Store: {chunk_hash}[{shard_index}] von {peer} ({} bytes)", data.len());
                            match self.shard_store.write_shard(&chunk_hash, shard_index, &data) {
                                Ok(written_hash) => {
                                    let ok = written_hash == shard_hash;
                                    if !ok {
                                        eprintln!("[p2p] ⚠ Shard-Hash Mismatch: erwartet {shard_hash}, got {written_hash}");
                                    }
                                    let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                        channel,
                                        ShardResponse::StoreResult {
                                            chunk_hash,
                                            shard_index,
                                            success: ok,
                                            error: if ok { None } else { Some("Hash mismatch".into()) },
                                        },
                                    );
                                }
                                Err(e) => {
                                    eprintln!("[p2p] ❌ Shard-Store Fehler: {e}");
                                    let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                        channel,
                                        ShardResponse::StoreResult {
                                            chunk_hash,
                                            shard_index,
                                            success: false,
                                            error: Some(e.to_string()),
                                        },
                                    );
                                }
                            }
                        }
                        ShardRequest::ListShards { chunk_hash } => {
                            let indices = self.shard_store.local_shard_indices(&chunk_hash);
                            println!("[p2p] 📋 Shard-Liste für {chunk_hash}: {:?} (an {peer})", indices);
                            let _ = self.swarm.behaviour_mut().shard_exchange.send_response(
                                channel,
                                ShardResponse::ShardList { chunk_hash, indices },
                            );
                        }
                    }
                }
                request_response::Message::Response { request_id, response, .. } => {
                    match response {
                        ShardResponse::ShardData { chunk_hash, shard_index, data } => {
                            if let Some(data) = data {
                                println!("[p2p] ← Shard empfangen: {chunk_hash}[{shard_index}] ({} bytes) von {peer}", data.len());
                                let _ = self.event_tx.send(NetworkEvent::ShardReceived {
                                    chunk_hash,
                                    shard_index,
                                    data,
                                    from_peer: peer.to_string(),
                                });
                            } else {
                                println!("[p2p] ← Shard nicht gefunden: {chunk_hash}[{shard_index}] bei {peer}");
                                let _ = self.event_tx.send(NetworkEvent::ShardRequestFailed {
                                    chunk_hash,
                                    shard_index,
                                    peer_id: peer.to_string(),
                                    error: "Shard nicht vorhanden".into(),
                                });
                            }
                        }
                        ShardResponse::StoreResult { chunk_hash, shard_index, success, error } => {
                            println!("[p2p] ← Shard-Store Ergebnis: {chunk_hash}[{shard_index}] bei {peer} → {success}");
                            let _ = self.event_tx.send(NetworkEvent::ShardStored {
                                chunk_hash,
                                shard_index,
                                peer_id: peer.to_string(),
                                success,
                                error,
                            });
                        }
                        ShardResponse::ShardList { chunk_hash, indices } => {
                            // Antwort auf ListPeerShards
                            if let Some((_, reply)) = self.pending_shard_lists.remove(&request_id) {
                                let _ = reply.send(indices);
                            } else {
                                println!("[p2p] Shard-Liste von {peer}: {chunk_hash} → {indices:?}");
                            }
                        }
                    }
                }
            },

            StoneBehaviourEvent::ShardExchange(
                request_response::Event::OutboundFailure { peer, request_id, error, .. }
            ) => {
                if let Some((_chunk_hash, reply)) = self.pending_shard_lists.remove(&request_id) {
                    eprintln!("[p2p] Shard-Liste Fehler zu {peer}: {error}");
                    let _ = reply.send(vec![]);
                } else {
                    eprintln!("[p2p] Shard-Request Fehler zu {peer}: {error}");
                }
            }

            StoneBehaviourEvent::ShardExchange(_) => {}

            _ => {}
        }
    }

    // ── Relay-Reservierungen ───────────────────────────────────────────────

    /// Stellt Relay-Reservierungen bei allen konfigurierten Relay-Nodes her.
    /// Wird automatisch aufgerufen wenn AutoNAT „Private" meldet.
    fn establish_relay_reservations(&mut self) {
        let addrs: Vec<String> = self.relay_addrs.clone();
        for addr_str in &addrs {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => {
                    // Versuche die Relay-PeerId aus der Multiaddr zu extrahieren
                    let relay_peer_id = addr.iter().find_map(|p| {
                        if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
                            Some(peer_id)
                        } else {
                            None
                        }
                    });

                    if let Some(relay_peer_id) = relay_peer_id {
                        // Eigene PeerId überspringen
                        if relay_peer_id == *self.swarm.local_peer_id() {
                            continue;
                        }
                        if self.active_relays.contains(&relay_peer_id) {
                            continue; // Bereits reserviert
                        }
                        println!("[p2p] 📡 Verbinde mit Relay {relay_peer_id}...");

                        // Dial den Relay-Node
                        if let Err(e) = self.swarm.dial(addr.clone()) {
                            eprintln!("[p2p] Relay-Dial fehlgeschlagen für {addr}: {e}");
                            continue;
                        }

                        // Lausche auf der Relay-Circuit-Adresse
                        let circuit_addr = addr.clone()
                            .with(libp2p::multiaddr::Protocol::P2pCircuit);
                        if let Err(e) = self.swarm.listen_on(circuit_addr.clone()) {
                            eprintln!("[p2p] Relay-Listen fehlgeschlagen: {e}");
                        } else {
                            println!("[p2p] 📡 Lausche via Relay-Circuit: {circuit_addr}");
                        }
                    } else {
                        eprintln!("[p2p] ⚠ Relay-Adresse hat keine PeerId: {addr_str}");
                    }
                }
                Err(e) => {
                    eprintln!("[p2p] Ungültige Relay-Adresse '{addr_str}': {e}");
                }
            }
        }
    }

    // ── Peer-Scoring & Banning ────────────────────────────────────────────────

    /// Fügt einem Peer Penalty-Punkte hinzu. Bei Überschreitung des Schwellwerts
    /// wird der Peer gebannt (Verbindung getrennt).
    fn add_peer_penalty(&mut self, peer: &PeerId, points: u32, reason: &str) {
        let entry = self.peer_penalties.entry(*peer).or_insert_with(|| PeerPenalty {
            score: 0,
            last_offense: Instant::now(),
            reasons: Vec::new(),
        });

        // Penalty-Verfall: wenn letzte Offense > PENALTY_DECAY_MINS her → Score halbieren
        if entry.last_offense.elapsed() > Duration::from_secs(PENALTY_DECAY_MINS * 60) {
            entry.score /= 2;
            entry.reasons.clear();
        }

        entry.score += points;
        entry.last_offense = Instant::now();
        entry.reasons.push(reason.to_string());

        eprintln!(
            "[p2p] 🚨 Penalty für {peer}: +{points} = {} (Grund: {reason})",
            entry.score
        );

        if entry.score >= BAN_THRESHOLD {
            eprintln!(
                "[p2p] 🔨 BANNED: {peer} (Score: {}, Gründe: {:?})",
                entry.score,
                entry.reasons,
            );
            // Verbindung trennen
            let _ = self.swarm.disconnect_peer_id(*peer);
            // Aus Peer-Liste entfernen
            if let Some(info) = self.peers.get_mut(peer) {
                info.connected = false;
            }
        }
    }

    /// Prüft ob ein Peer gebannt ist.
    fn is_peer_banned(&self, peer: &PeerId) -> bool {
        self.peer_penalties
            .get(peer)
            .map(|p| {
                // Ban verfällt nach dem doppelten Decay-Zeitraum
                if p.last_offense.elapsed() > Duration::from_secs(PENALTY_DECAY_MINS * 60 * 2) {
                    false
                } else {
                    p.score >= BAN_THRESHOLD
                }
            })
            .unwrap_or(false)
    }

    // ── Gossip Block verarbeiten ──────────────────────────────────────────────

    fn handle_gossip_block(&mut self, data: Vec<u8>, source: PeerId) {
        // Gebannte Peers ignorieren
        if self.is_peer_banned(&source) {
            return;
        }

        // ── Größenlimit: Blöcke > 10 MiB sind verdächtig ──────────────────────
        const MAX_GOSSIP_BLOCK_BYTES: usize = 10 * 1024 * 1024;
        if data.len() > MAX_GOSSIP_BLOCK_BYTES {
            eprintln!(
                "[p2p] ⚠ Block von {source} zu groß ({} Bytes) – ignoriert + Penalty",
                data.len()
            );
            self.add_peer_penalty(&source, 50, "oversized block");
            return;
        }

        match serde_json::from_slice::<Block>(&data) {
            Ok(block) => {
                // ── Duplicate-Filter ──────────────────────────────────────────
                if self.is_duplicate(&block.hash) {
                    return;
                }

                // ── Hash-Integrität ───────────────────────────────────────────
                let expected_hash = crate::blockchain::calculate_hash(&block);
                if expected_hash != block.hash {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat ungültigen Hash – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 100, "invalid hash");
                    return;
                }

                // ── Merkle-Root-Verifikation ──────────────────────────────────
                let expected_merkle = crate::blockchain::compute_merkle_root(
                    &block.documents,
                    &block.tombstones,
                );
                if expected_merkle != block.merkle_root {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat ungültigen Merkle-Root – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 100, "invalid merkle root");
                    return;
                }

                // ── Timestamp-Drift-Check ─────────────────────────────────────
                // Block-Timestamp darf nicht > 5 Minuten in der Zukunft liegen
                // und nicht > 24 Stunden in der Vergangenheit (außer Genesis)
                let now = chrono::Utc::now().timestamp();
                let max_future = 5 * 60;       // 5 Minuten Toleranz
                let max_past = 24 * 60 * 60;   // 24 Stunden
                if block.index > 0 {
                    if block.timestamp > now + max_future {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} liegt {} Sek. in der Zukunft – ignoriert",
                            block.index,
                            block.timestamp - now,
                        );
                        self.add_peer_penalty(&source, 30, "future timestamp");
                        return;
                    }
                    if block.timestamp < now - max_past {
                        eprintln!(
                            "[p2p] ⚠ Block #{} von {source} ist {} Stunden alt – ignoriert",
                            block.index,
                            (now - block.timestamp) / 3600,
                        );
                        self.add_peer_penalty(&source, 10, "stale timestamp");
                        return;
                    }
                }

                // ── Signer darf nicht leer sein ───────────────────────────────
                if block.signer.is_empty() && block.index > 0 {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source} hat keinen Signer – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 50, "missing signer");
                    return;
                }

                // ── Block-Größe vs. data_size Plausibilität ───────────────────
                let actual_data_size: u64 = block.documents.iter().map(|d| d.size).sum();
                if block.data_size > 0 && actual_data_size == 0 && !block.documents.is_empty() {
                    eprintln!(
                        "[p2p] ⚠ Block #{} von {source}: data_size Mismatch – ignoriert",
                        block.index
                    );
                    self.add_peer_penalty(&source, 30, "data_size mismatch");
                    return;
                }

                println!("[p2p] 📦 Block #{} von {source} (hash={}...) ✓ validiert", block.index, &block.hash[..8]);

                if let Some(entry) = self.peers.get_mut(&source) {
                    entry.blocks_received += 1;
                    entry.last_seen = chrono::Utc::now().timestamp();
                }

                let _ = self.event_tx.send(NetworkEvent::BlockReceived {
                    block: Box::new(block),
                    from_peer: source.to_string(),
                });
            }
            Err(e) => {
                eprintln!("[p2p] Gossip Block-Dekodierung fehlgeschlagen von {source}: {e}");
                self.add_peer_penalty(&source, 20, "malformed block");
            }
        }
    }

    // ── Chain-Sync Handshake ──────────────────────────────────────────────────

    /// Sendet unsere Chain-Länge an alle Peers (Gossipsub).
    /// Peers die mehr Blöcke haben werden uns antworten.
    fn send_sync_handshake(&mut self) {
        let msg = SyncHandshake {
            block_count: self.local_chain_count,
            peer_id: self.swarm.local_peer_id().to_string(),
        };
        if let Ok(data) = serde_json::to_vec(&msg) {
            let topic = IdentTopic::new(TOPIC_SYNC_HANDSHAKE);
            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                // InsufficientPeers ist kein Fehler beim Start
                if !e.to_string().contains("InsufficientPeers") {
                    eprintln!("[p2p] Sync-Handshake fehlgeschlagen: {e}");
                }
            }
        }
    }

    /// Empfängt einen Sync-Handshake von einem Peer.
    /// Falls der Peer mehr Blöcke hat → fehlende per Request/Response abrufen.
    fn handle_sync_handshake(&mut self, data: Vec<u8>, source: PeerId) {
        let Ok(msg) = serde_json::from_slice::<SyncHandshake>(&data) else {
            return;
        };

        if msg.peer_id == self.swarm.local_peer_id().to_string() {
            return; // eigene Nachricht
        }

        if msg.block_count > self.local_chain_count {
            println!(
                "[p2p] 🔄 Sync: Peer {source} hat {} Blöcke, wir haben {}",
                msg.block_count, self.local_chain_count
            );
            let _ = self.event_tx.send(NetworkEvent::SyncStarted {
                peer_id: source.to_string(),
                local_count: self.local_chain_count,
                remote_count: msg.block_count,
            });

            // Fehlende Blöcke einzeln per Request/Response abrufen
            for idx in self.local_chain_count..msg.block_count {
                let _ = self.swarm.behaviour_mut().block_exchange.send_request(
                    &source,
                    BlockRequest { block_index: idx },
                );
            }
        } else if msg.block_count < self.local_chain_count {
            // Wir haben mehr Blöcke → eigenen Handshake senden damit der Peer synct
            self.send_sync_handshake();
        }
    }

    // ── Externe Befehle ───────────────────────────────────────────────────────

    fn handle_command(&mut self, cmd: NetworkCommand) -> bool {
        match cmd {
            NetworkCommand::BroadcastBlock(block) => {
                let hash = block.hash.clone();

                // Eigenen Block sofort als "gesehen" markieren (kein Re-Broadcast)
                if !self.is_duplicate(&hash) {
                    // Duplicate-Filter hat ihn gerade neu eingetragen → gut
                }

                match serde_json::to_vec(&*block) {
                    Ok(data) => {
                        let topic = IdentTopic::new(TOPIC_BLOCKS);
                        match self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            Ok(_) => {
                                println!("[p2p] 📡 Block #{} gebroadcastet (hash={}...)", block.index, &hash[..8.min(hash.len())]);
                                // Chain-Count aktualisieren
                                if block.index + 1 > self.local_chain_count {
                                    self.local_chain_count = block.index + 1;
                                }
                            }
                            Err(gossipsub::PublishError::InsufficientPeers) => {
                                // Kein Peer verbunden – kein Fehler, nur Info
                                println!("[p2p] Block #{} – keine Peers verbunden, Broadcast übersprungen", block.index);
                            }
                            Err(e) => eprintln!("[p2p] Broadcast-Fehler: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[p2p] Block-Serialisierung: {e}"),
                }
                false
            }

            NetworkCommand::DialPeer(addr) => {
                println!("[p2p] Manueller Dial: {addr}");
                if let Err(e) = self.swarm.dial(addr) {
                    eprintln!("[p2p] Dial fehlgeschlagen: {e}");
                }
                false
            }

            NetworkCommand::SyncWithPeer { peer_id, our_block_count } => {
                // Expliziten Sync-Handshake an einen Peer senden
                let _ = self.swarm.behaviour_mut().block_exchange.send_request(
                    &peer_id,
                    BlockRequest { block_index: our_block_count },
                );
                false
            }

            NetworkCommand::SetLocalChainCount(count) => {
                self.local_chain_count = count;
                false
            }

            NetworkCommand::GetPeers(tx) => {
                let list: Vec<PeerInfo> = self.peers.values().cloned().collect();
                let _ = tx.send(list);
                false
            }

            NetworkCommand::Ping { peer_id, reply } => {
                let connected = self.peers.get(&peer_id).map(|p| p.connected).unwrap_or(false);
                if !connected {
                    let _ = reply.send(PingResult {
                        peer_id: peer_id.to_string(),
                        reachable: false,
                        latency_ms: None,
                        error: Some("Peer nicht verbunden".to_string()),
                    });
                    return false;
                }
                // Ping-Marker: block_index = u64::MAX
                let req_id = self.swarm.behaviour_mut().block_exchange.send_request(
                    &peer_id,
                    BlockRequest { block_index: u64::MAX },
                );
                self.pending_pings.insert(req_id, (peer_id.to_string(), std::time::Instant::now(), reply));
                false
            }

            NetworkCommand::GetStatus(reply) => {
                let now = chrono::Utc::now().timestamp();
                let mesh_peers: HashSet<String> = self.swarm
                    .behaviour()
                    .gossipsub
                    .mesh_peers(&gossipsub::TopicHash::from_raw(TOPIC_BLOCKS))
                    .map(|p| p.to_string())
                    .collect();

                // Direkt aus dem Swarm die verbundenen Peers holen —
                // das ist die einzig zuverlässige Quelle, unabhängig von peers-Map.
                let swarm_connected: HashSet<String> = self.swarm
                    .connected_peers()
                    .map(|p| p.to_string())
                    .collect();

                // peers-Map mit Swarm-Status synchronisieren
                for (peer_id, info) in self.peers.iter_mut() {
                    info.connected = swarm_connected.contains(&peer_id.to_string());
                }
                // Peers die im Swarm verbunden sind aber noch nicht in unserer Map
                for peer_str in &swarm_connected {
                    if let Ok(peer_id) = peer_str.parse::<libp2p::PeerId>() {
                        self.peers.entry(peer_id).or_insert_with(|| PeerInfo {
                            peer_id: peer_str.clone(),
                            addresses: vec![],
                            agent_version: String::new(),
                            connected: true,
                            last_seen: now,
                            blocks_received: 0,
                        });
                    }
                }

                let peers: Vec<PeerStatus> = self.peers.values().map(|p| PeerStatus {
                    peer_id: p.peer_id.clone(),
                    addresses: p.addresses.clone(),
                    agent_version: p.agent_version.clone(),
                    connected: p.connected,
                    last_seen: p.last_seen,
                    last_seen_ago_secs: now - p.last_seen,
                    blocks_received: p.blocks_received,
                    in_gossipsub_mesh: mesh_peers.contains(&p.peer_id),
                }).collect();

                let connected = swarm_connected.len(); // direkt aus Swarm
                let _ = reply.send(NetworkStatus {
                    local_peer_id: self.swarm.local_peer_id().to_string(),
                    connected_peers: connected,
                    total_known_peers: self.peers.len(),
                    gossipsub_mesh_size: mesh_peers.len(),
                    chain_block_count: self.local_chain_count,
                    peers,
                });
                false
            }

            NetworkCommand::Shutdown => {
                println!("[p2p] Shutdown.");
                true
            }

            // ── Shard-Befehle ─────────────────────────────────────────────────

            NetworkCommand::RequestShard { peer_id, chunk_hash, shard_index } => {
                println!("[p2p] → Shard anfordern: {chunk_hash}[{shard_index}] von {peer_id}");
                self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::GetShard { chunk_hash, shard_index },
                );
                false
            }

            NetworkCommand::StoreShard { peer_id, chunk_hash, shard_index, shard_hash, data } => {
                println!("[p2p] → Shard senden: {chunk_hash}[{shard_index}] an {peer_id} ({} bytes)", data.len());
                self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::StoreShard { chunk_hash, shard_index, shard_hash, data },
                );
                false
            }

            NetworkCommand::ListPeerShards { peer_id, chunk_hash, reply } => {
                println!("[p2p] → Shard-Liste anfordern: {chunk_hash} von {peer_id}");
                let req_id = self.swarm.behaviour_mut().shard_exchange.send_request(
                    &peer_id,
                    ShardRequest::ListShards { chunk_hash: chunk_hash.clone() },
                );
                self.pending_shard_lists.insert(req_id, (chunk_hash, reply));
                false
            }
        }
    }
}

// ─── Sync-Handshake Nachricht ─────────────────────────────────────────────────

pub const TOPIC_SYNC_HANDSHAKE: &str = "stone/sync/v1";

/// Kurze Nachricht die beim Verbinden gesendet wird um Chain-Längen zu vergleichen.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncHandshake {
    block_count: u64,
    peer_id: String,
}

// ─── Gossipsub: Topics abonnieren ─────────────────────────────────────────────

fn subscribe_all_topics(gossipsub: &mut gossipsub::Behaviour) -> Result<(), String> {
    for topic in [TOPIC_BLOCKS, TOPIC_PEERS, TOPIC_SYNC_HANDSHAKE] {
        gossipsub.subscribe(&IdentTopic::new(topic))
            .map_err(|e| format!("Subscribe '{topic}': {e}"))?;
    }
    Ok(())
}

// ─── Öffentliche API ──────────────────────────────────────────────────────────

/// Handle für den laufenden P2P-Swarm-Task.
///
/// Wird als `AppState.network` gehalten. Alle Methoden sind `async` und
/// kommunizieren über den `mpsc`-Kanal mit dem Swarm-Task.
#[derive(Clone)]
pub struct NetworkHandle {
    pub cmd_tx: mpsc::Sender<NetworkCommand>,
    pub event_rx: broadcast::Sender<NetworkEvent>,
    pub local_peer_id: String,
}

impl NetworkHandle {
    /// Broadcastet einen Block per Gossipsub an alle Peers.
    pub async fn broadcast_block(&self, block: Block) {
        let _ = self.cmd_tx.send(NetworkCommand::BroadcastBlock(Box::new(block))).await;
    }

    /// Wählt einen Peer manuell an.
    pub async fn dial(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCommand::DialPeer(addr)).await;
    }

    /// Teilt dem Swarm unsere aktuelle Chain-Länge mit (z.B. nach jedem neuen Block).
    pub async fn set_chain_count(&self, count: u64) {
        let _ = self.cmd_tx.send(NetworkCommand::SetLocalChainCount(count)).await;
    }

    /// Startet einen expliziten Chain-Sync mit einem bestimmten Peer.
    pub async fn sync_with(&self, peer_id: PeerId, our_block_count: u64) {
        let _ = self.cmd_tx.send(NetworkCommand::SyncWithPeer { peer_id, our_block_count }).await;
    }

    /// Gibt die aktuelle Peer-Liste zurück.
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.cmd_tx.send(NetworkCommand::GetPeers(tx)).await;
        rx.await.unwrap_or_default()
    }

    /// Gibt alle verbundenen Peers zurück.
    pub async fn connected_peers(&self) -> Vec<PeerInfo> {
        self.get_peers().await.into_iter().filter(|p| p.connected).collect()
    }

    /// Subscribt auf Network-Events (broadcast channel).
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.event_rx.subscribe()
    }

    /// Pingt einen Peer via Request/Response und misst die Latenz.
    /// Timeout: 5 Sekunden. Gibt `PingResult.reachable = false` bei Fehler zurück.
    pub async fn ping(&self, peer_id: PeerId) -> PingResult {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.cmd_tx.send(NetworkCommand::Ping { peer_id: peer_id.clone(), reply: tx }).await.is_err() {
            return PingResult {
                peer_id: peer_id.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("P2P-Task nicht erreichbar".to_string()),
            };
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => PingResult {
                peer_id: peer_id.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("Interner Fehler".to_string()),
            },
            Err(_) => PingResult {
                peer_id: peer_id.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("Timeout (5s)".to_string()),
            },
        }
    }

    /// Gibt den vollständigen Netzwerkstatus zurück (alle Peers, Mesh, Chain-Count).
    pub async fn get_status(&self) -> Option<NetworkStatus> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx.send(NetworkCommand::GetStatus(tx)).await.ok()?;
        tokio::time::timeout(std::time::Duration::from_secs(3), rx)
            .await.ok()?.ok()
    }

    /// Beendet den Swarm-Task.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(NetworkCommand::Shutdown).await;
    }

    // ── Shard-API ─────────────────────────────────────────────────────────────

    /// Fordert einen bestimmten Shard von einem Peer an.
    /// Die Antwort kommt asynchron als `NetworkEvent::ShardReceived`.
    pub async fn request_shard(&self, peer_id: PeerId, chunk_hash: String, shard_index: u8) {
        let _ = self.cmd_tx.send(NetworkCommand::RequestShard {
            peer_id,
            chunk_hash,
            shard_index,
        }).await;
    }

    /// Sendet einen Shard an einen Peer zum Speichern.
    /// Die Bestätigung kommt als `NetworkEvent::ShardStored`.
    pub async fn store_shard_on_peer(
        &self,
        peer_id: PeerId,
        chunk_hash: String,
        shard_index: u8,
        shard_hash: String,
        data: Vec<u8>,
    ) {
        let _ = self.cmd_tx.send(NetworkCommand::StoreShard {
            peer_id,
            chunk_hash,
            shard_index,
            shard_hash,
            data,
        }).await;
    }

    /// Fragt ab welche Shards ein Peer für einen bestimmten Chunk hat.
    /// Timeout: 5 Sekunden.
    pub async fn list_peer_shards(&self, peer_id: PeerId, chunk_hash: String) -> Vec<u8> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.cmd_tx.send(NetworkCommand::ListPeerShards {
            peer_id,
            chunk_hash,
            reply: tx,
        }).await.is_err() {
            return vec![];
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(indices)) => indices,
            _ => vec![],
        }
    }
}

// ─── start_network ────────────────────────────────────────────────────────────

/// Startet den P2P-Swarm-Task und gibt ein `NetworkHandle` zurück.
pub async fn start_network(
    config_override: Option<P2pConfig>,
) -> Result<NetworkHandle, Box<dyn std::error::Error>> {
    let mut config = config_override.unwrap_or_else(P2pConfig::load_or_default);
    config.merge_env();

    let keypair = load_or_create_keypair();
    let local_peer_id = PeerId::from_public_key(&keypair.public()).to_string();

    println!("[p2p] Stone P2P-Netzwerk startet");
    println!("[p2p] PeerId: {local_peer_id}");
    println!("[p2p] Listen: {}", config.listen_addr);
    if config.bootstrap_nodes.is_empty() {
        println!("[p2p] Keine Bootstrap-Nodes – nur mDNS/lokale Discovery");
    } else {
        for b in &config.bootstrap_nodes {
            println!("[p2p] Bootstrap: {b}");
        }
    }

    // NAT-Traversal Konfiguration loggen
    println!("[p2p] NAT-Traversal:");
    println!("[p2p]   AutoNAT:  {}", if config.autonat_enabled { "✅" } else { "❌" });
    println!("[p2p]   UPnP:     {}", if config.upnp_enabled { "✅" } else { "❌" });
    println!("[p2p]   DCUtR:    {}", if config.dcutr_enabled { "✅" } else { "❌" });
    if !config.relay_nodes.is_empty() {
        for r in &config.relay_nodes {
            println!("[p2p]   Relay:    {r}");
        }
    } else {
        println!("[p2p]   Relay:    Keine Relay-Nodes konfiguriert (STONE_RELAY_NODES)");
    }

    let mut swarm = build_swarm(keypair, &config)?;

    // Gossipsub: alle Topics abonnieren
    subscribe_all_topics(&mut swarm.behaviour_mut().gossipsub)
        .map_err(|e| format!("Gossipsub-Subscribe: {e}"))?;

    let (event_tx, _) = broadcast::channel(512);
    let (cmd_tx, cmd_rx) = mpsc::channel(128);

    let bootstrap_addrs = config.bootstrap_nodes.clone();

    let relay_addrs = config.relay_nodes.clone();

    let task = SwarmTask {
        swarm,
        event_tx: event_tx.clone(),
        cmd_rx,
        peers: HashMap::new(),
        seen_hashes: HashSet::new(),
        seen_order: VecDeque::new(),
        local_chain_count: 0,
        bootstrap_addrs,
        last_reconnect: Instant::now(),
        config,
        pending_pings: HashMap::new(),
        nat_status: NatStatus::Unknown,
        active_relays: HashSet::new(),
        relay_addrs,
        peer_penalties: HashMap::new(),
        shard_store: crate::shard::ShardStore::new().expect("ShardStore erstellen"),
        pending_shard_lists: HashMap::new(),
    };

    tokio::spawn(task.run());

    Ok(NetworkHandle {
        cmd_tx,
        event_rx: event_tx,
        local_peer_id,
    })
}

// ─── Hilfsfunktionen für die REST-API ─────────────────────────────────────────

/// Parst eine Multiaddr aus einem String.
pub fn parse_multiaddr(s: &str) -> Result<Multiaddr, String> {
    s.parse::<Multiaddr>().map_err(|e| format!("Ungültige Multiaddr: {e}"))
}

/// Gibt die vollständige eigene P2P-Adresse zurück (für Bootstrap-Konfiguration anderer Nodes).
pub fn local_p2p_addr(port: u16) -> Option<String> {
    let peer_id = read_peer_id()?;
    let ip = local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    Some(format!("/ip4/{ip}/tcp/{port}/p2p/{peer_id}"))
}

fn local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip().to_string())
}
