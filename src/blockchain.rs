use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Datenverzeichnis – überschreibbar per `STONE_DATA_DIR` env var.
/// Verwendet von: token, RocksDB, chunks, users, peers.
pub fn data_dir() -> String {
    std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| "stone_data".to_string())
}

pub const MAX_BLOCK_SIZE: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB
pub fn chunk_dir() -> String { format!("{}/chunks", data_dir()) }
pub const CHUNK_SIZE: usize = 8 * 1024 * 1024; // 8 MiB

// ─── Block-Hashing ───────────────────────────────────────────────────────────
//
// Jeder Block enthält:
//   index          – Position in der Chain (0 = Genesis)
//   timestamp      – Unix-Sekunden (i64)
//   previous_hash  – SHA-256-Hash des Vorgänger-Blocks (64 Hex-Zeichen)
//   merkle_root    – SHA-256 über alle Dokument- und Tombstone-Hashes (Merkle-ähnlich)
//   data_size      – Gesamtgröße der Dokument-Bytes in diesem Block
//   hash           – SHA-256 über (index || timestamp || previous_hash || merkle_root || data_size)
//   signer         – Node-ID des Erstellers
//   signature      – HMAC-SHA-256(cluster_key, hash)
//   node_role      – Master / Replica
//   documents      – Liste der Dokumente in diesem Block
//   tombstones     – Soft-Delete-Einträge
//
// Die Hash-Eingabe ist binär kodiert (Little-Endian für Zahlen), nie als
// String-Konkatenation, um Kollisionen wie (1,"23") == (12,"3") zu vermeiden.

// ─── Dokument-Modell ─────────────────────────────────────────────────────────

/// Ein Dokument ist eine atomare, versionierte Dateneinheit.
/// Kein Ordner-Konzept – Kategorisierung erfolgt über tags + metadata.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Document {
    pub doc_id: String,
    pub title: String,
    pub content_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default = "default_version")]
    pub version: u32,
    pub size: u64,
    #[serde(default)]
    pub chunks: Vec<ChunkRef>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub owner: String,

    // ─── Kryptographie-Felder ────────────────────────────────────────────────

    /// Ed25519-Signatur über (doc_id | version | size | content_type).
    /// 128 Hex-Zeichen (64 Byte). Leer = nicht signiert.
    #[serde(default)]
    pub doc_signature: String,

    /// Erste 16 Hex-Zeichen des signierende Public Keys – zur schnellen Zuordnung.
    /// Leer = nicht signiert.
    #[serde(default)]
    pub public_key_hint: String,

    /// Gibt an ob die Chunks AES-256-GCM verschlüsselt sind.
    /// Falls true, enthält `encryption_blob` die nötigen Entschlüsselungsmetadaten.
    #[serde(default)]
    pub encrypted: bool,

    /// JSON-serialisierter `EncryptedBlob` (ephemeral_pubkey, nonce, ciphertext leer –
    /// nur Metadaten; der eigentliche Ciphertext ist in den Chunks gespeichert).
    /// Leer = nicht verschlüsselt.
    #[serde(default)]
    pub encryption_meta: String,
}

fn default_version() -> u32 { 1 }

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ChunkRef {
    pub hash: String,
    pub size: u64,
}

/// Soft-Delete: markiert ein Dokument als gelöscht
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DocumentTombstone {
    pub block_index: u64,
    pub doc_id: String,
    #[serde(default)]
    pub owner: String,
}

// ─── Node-Rolle ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub enum NodeRole {
    #[default]
    Master,
    Replica,
}

// ─── Block ───────────────────────────────────────────────────────────────────

/// Ein Block ist die atomare Einheit der Stone-Chain.
///
/// Hash-Input (binär, deterministisch):
///   SHA-256(
///     index.to_le_bytes()       [8 Byte]
///     timestamp.to_le_bytes()   [8 Byte]
///     previous_hash.as_bytes()  [64 Byte, Hex-ASCII]
///     merkle_root.as_bytes()    [64 Byte, Hex-ASCII]
///     data_size.to_le_bytes()   [8 Byte]
///     signer.as_bytes()         [variabel]
///   )
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    /// Position in der Chain (0 = Genesis)
    pub index: u64,
    /// Unix-Timestamp in Sekunden
    pub timestamp: i64,
    /// Merkle-ähnlicher Root-Hash über alle Dokument- und Tombstone-Hashes
    pub merkle_root: String,
    /// Gesamtgröße der Nutzdaten in Bytes
    pub data_size: u64,
    /// SHA-256 des Vorgänger-Blocks (64 Hex-Zeichen; "000...0" beim Genesis)
    pub previous_hash: String,
    /// SHA-256 dieses Blocks (über die o.g. Felder)
    pub hash: String,
    /// Node-ID des Signierers
    #[serde(default)]
    pub signer: String,
    /// HMAC-SHA-256(cluster_key, hash) – Cluster-Authentizität
    #[serde(default)]
    pub signature: String,
    /// Besitzer / Ersteller dieses Blocks
    #[serde(default)]
    pub owner: String,
    /// Dokumente in diesem Block
    #[serde(default)]
    pub documents: Vec<Document>,
    /// Soft-Delete-Einträge
    #[serde(default)]
    pub tombstones: Vec<DocumentTombstone>,
    /// Rolle der Node die diesen Block erstellt hat
    #[serde(default)]
    pub node_role: NodeRole,
    /// Konsensus-Runden-ID (0 = kein Konsensus nötig)
    #[serde(default)]
    pub proposal_round: u64,
    // ─── PoA-Felder ──────────────────────────────────────────────────────────
    /// Ed25519-Public-Key des Validators der diesen Block signiert hat (64 Hex-Zeichen)
    /// Leer = Block wurde vor PoA-Aktivierung erstellt (rückwärtskompatibel)
    #[serde(default)]
    pub validator_pub_key: String,
    /// Ed25519-Signatur über `block.hash` (128 Hex-Zeichen, 64 Byte)
    /// Gehört NICHT zum Hash-Input (calculate_hash), damit Signaturen ohne Re-Hash möglich sind
    #[serde(default)]
    pub validator_signature: String,
}

// ─── Chain ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct StoneChain {
    pub blocks: Vec<Block>,
    pub latest_hash: String,
}

impl StoneChain {
    /// Lädt die Chain aus RocksDB oder erstellt eine neue mit Genesis-Block.
    pub fn load_or_create(cluster_key: &str) -> Self {
        use crate::storage::ChainStore;

        std::fs::create_dir_all(data_dir()).unwrap_or(());
        std::fs::create_dir_all(chunk_dir()).unwrap_or(());

        match ChainStore::open() {
            Ok(store) if !store.is_empty() => {
                match store.read_all_blocks() {
                    Ok(blocks) if !blocks.is_empty() => {
                        let latest_hash = blocks.last().map(|b| b.hash.clone()).unwrap_or_default();
                        println!("[chain] RocksDB geladen: {} Blöcke, Latest: {}...", blocks.len(), &latest_hash[..8]);
                        return StoneChain { blocks, latest_hash };
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        // Leere oder neue Datenbank → Genesis-Block erstellen
        let genesis = genesis_block(cluster_key);
        let chain = StoneChain {
            blocks: vec![genesis.clone()],
            latest_hash: genesis.hash.clone(),
        };
        chain.persist_last_block();
        println!("[chain] Neue Stone-Chain erstellt – Genesis Block: {}...", &genesis.hash[..8]);
        chain
    }

    /// Persistiert den letzten Block in RocksDB.
    ///
    /// Wird nach `add_documents()` automatisch aufgerufen.
    pub fn persist_last_block(&self) {
        use crate::storage::ChainStore;
        if let Some(block) = self.blocks.last() {
            match ChainStore::open() {
                Ok(store) => {
                    if let Err(e) = store.write_block(block) {
                        eprintln!("[chain] RocksDB-Schreibfehler: {e}");
                    }
                }
                Err(e) => eprintln!("[chain] RocksDB konnte nicht geöffnet werden: {e}"),
            }
        }
    }

    /// Persistiert alle Blöcke in RocksDB (für Migration / Rebuild).
    pub fn persist_all(&self) {
        use crate::storage::ChainStore;
        match ChainStore::open() {
            Ok(store) => {
                for block in &self.blocks {
                    if let Err(e) = store.write_block(block) {
                        eprintln!("[chain] Fehler beim Schreiben von Block #{}: {e}", block.index);
                    }
                }
            }
            Err(e) => eprintln!("[chain] RocksDB konnte nicht geöffnet werden: {e}"),
        }
    }

    /// Neuen Block mit Dokumenten hinzufügen
    pub fn add_documents(
        &mut self,
        documents: Vec<Document>,
        tombstones: Vec<DocumentTombstone>,
        owner: String,
        signer: String,
        cluster_key: &str,
        node_role: NodeRole,
    ) -> Block {
        let manifest = serde_json::to_vec(&documents).unwrap_or_default();
        let merkle_root = compute_merkle_root(&documents, &tombstones);

        let new_block = Block {
            index: self.blocks.len() as u64,
            timestamp: Utc::now().timestamp(),
            merkle_root,
            data_size: manifest.len() as u64,
            previous_hash: self.latest_hash.clone(),
            hash: String::new(),
            signer,
            signature: String::new(),
            owner,
            documents,
            tombstones,
            node_role,
            proposal_round: 0,
            validator_pub_key: String::new(),
            validator_signature: String::new(),
        };

        let hash = calculate_hash(&new_block);
        let final_block = Block {
            hash: hash.clone(),
            signature: sign_hash(cluster_key, &hash),
            ..new_block
        };

        self.blocks.push(final_block.clone());
        self.latest_hash = hash;
        self.persist_last_block();

        println!(
            "[chain] Block #{} – {} Dok., {} Bytes",
            final_block.index,
            final_block.documents.len(),
            final_block.data_size,
        );
        final_block
    }

    /// Nimmt einen von einem Peer empfangenen fertigen Block in die lokale Chain auf.
    /// Prüft Verkettung (previous_hash) und Hash-Integrität. Gibt Err zurück wenn ungültig.
    ///
    /// `poa_ok` – Ergebnis der externen PoA-Signaturprüfung (durch ValidatorSet).
    ///   - `None`  → PoA-Prüfung wird übersprungen (kein Validator-Set geladen)
    ///   - `Some(true)`  → Prüfung bestanden
    ///   - `Some(false)` → Prüfung fehlgeschlagen → Block wird abgelehnt
    pub fn accept_peer_block(
        &mut self,
        block: Block,
        poa_ok: Option<bool>,
    ) -> Result<(), String> {
        let expected_index = self.blocks.len() as u64;
        if block.index != expected_index {
            return Err(format!(
                "Index-Mismatch: erwartet {expected_index}, empfangen {}",
                block.index
            ));
        }
        if block.previous_hash != self.latest_hash {
            return Err(format!(
                "previous_hash passt nicht: erwartet {}, empfangen {}",
                &self.latest_hash[..12.min(self.latest_hash.len())],
                &block.previous_hash[..12.min(block.previous_hash.len())],
            ));
        }
        let expected_hash = calculate_hash(&block);
        if block.hash != expected_hash {
            return Err(format!(
                "Hash ungültig: erwartet {}, empfangen {}",
                &expected_hash[..12.min(expected_hash.len())],
                &block.hash[..12.min(block.hash.len())],
            ));
        }

        // PoA: externer Signatur-Check
        if poa_ok == Some(false) {
            return Err(format!(
                "PoA-Signaturprüfung fehlgeschlagen für Signer '{}'",
                block.signer
            ));
        }

        self.latest_hash = block.hash.clone();
        self.blocks.push(block);
        self.persist_last_block();
        Ok(())
    }

    /// Aktives Dokument per doc_id finden
    pub fn find_document(&self, doc_id: &str) -> Option<(&Document, u64)> {
        let deleted: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .flat_map(|b| b.tombstones.iter())
            .map(|t| t.doc_id.clone())
            .collect();

        if deleted.contains(doc_id) {
            return None;
        }

        for block in self.blocks.iter().rev() {
            if let Some(doc) = block.documents.iter().find(|d| d.doc_id == doc_id) {
                return Some((doc, block.index));
            }
        }
        None
    }

    /// Alle aktiven Dokumente eines Nutzers (neueste Version je doc_id)
    pub fn list_documents_for_user(&self, user_id: &str) -> Vec<(&Document, u64)> {
        let deleted: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .flat_map(|b| b.tombstones.iter())
            .map(|t| t.doc_id.clone())
            .collect();

        let mut seen: std::collections::HashMap<String, (&Document, u64)> =
            std::collections::HashMap::new();
        for block in &self.blocks {
            for doc in &block.documents {
                if doc.owner == user_id && !deleted.contains(&doc.doc_id) {
                    seen.insert(doc.doc_id.clone(), (doc, block.index));
                }
            }
        }
        seen.into_values().collect()
    }

    /// Alle aktiven Dokumente (admin)
    pub fn list_all_documents(&self) -> Vec<(&Document, u64)> {
        let deleted: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .flat_map(|b| b.tombstones.iter())
            .map(|t| t.doc_id.clone())
            .collect();

        let mut seen: std::collections::HashMap<String, (&Document, u64)> =
            std::collections::HashMap::new();
        for block in &self.blocks {
            for doc in &block.documents {
                if !deleted.contains(&doc.doc_id) {
                    seen.insert(doc.doc_id.clone(), (doc, block.index));
                }
            }
        }
        seen.into_values().collect()
    }

    /// Versionshistorie eines Dokuments
    pub fn document_history(&self, doc_id: &str) -> Vec<(&Document, u64)> {
        self.blocks
            .iter()
            .flat_map(|b| {
                b.documents
                    .iter()
                    .filter(|d| d.doc_id == doc_id)
                    .map(move |d| (d, b.index))
            })
            .collect()
    }

    /// Speicherverbrauch eines Nutzers (nur aktive Dokumente)
    pub fn user_usage_bytes(&self, user_id: &str) -> u64 {
        let deleted: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .flat_map(|b| b.tombstones.iter())
            .map(|t| t.doc_id.clone())
            .collect();

        self.blocks
            .iter()
            .flat_map(|b| b.documents.iter())
            .filter(|d| d.owner == user_id && !deleted.contains(&d.doc_id))
            .map(|d| d.size)
            .sum()
    }

    pub fn verify(&self, cluster_key: &str) -> bool {
        for i in 1..self.blocks.len() {
            let block = &self.blocks[i];
            let prev = &self.blocks[i - 1];
            if block.previous_hash != prev.hash {
                return false;
            }
            if block.hash != calculate_hash(block) {
                return false;
            }
            if !block.signature.is_empty()
                && block.signature != sign_hash(cluster_key, &block.hash)
            {
                return false;
            }
        }
        true
    }
}

// ─── Hash & Signatur ─────────────────────────────────────────────────────────

/// Merkle-ähnlicher Root-Hash über alle Dokumente und Tombstones eines Blocks.
///
/// Ablauf:
///   1. Für jedes Dokument: SHA-256(doc_id || version || size || content_type)
///   2. Für jeden Tombstone: SHA-256("del:" || doc_id)
///   3. Alle Einzel-Hashes sortieren (kanonische Reihenfolge, unabhängig von Einfüge-Reihenfolge)
///   4. SHA-256 über die Konkatenation aller sortierten Hashes
///   → Leere Liste → SHA-256("empty")
pub fn compute_merkle_root(documents: &[Document], tombstones: &[DocumentTombstone]) -> String {
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();

    for doc in documents {
        let mut h = Sha256::new();
        h.update(doc.doc_id.as_bytes());
        h.update(b"|");
        h.update(doc.version.to_le_bytes());
        h.update(b"|");
        h.update(doc.size.to_le_bytes());
        h.update(b"|");
        h.update(doc.content_type.as_bytes());
        leaf_hashes.push(h.finalize().into());
    }

    for t in tombstones {
        let mut h = Sha256::new();
        h.update(b"del:");
        h.update(t.doc_id.as_bytes());
        leaf_hashes.push(h.finalize().into());
    }

    if leaf_hashes.is_empty() {
        return format!("{:x}", Sha256::digest(b"empty"));
    }

    // Kanonische Reihenfolge: nach Hex-Darstellung sortieren
    leaf_hashes.sort_unstable();

    let mut root = Sha256::new();
    for lh in &leaf_hashes {
        root.update(lh);
    }
    format!("{:x}", root.finalize())
}

/// Block-Hash: SHA-256 über binär kodierte Felder.
///
/// Kodierung (in dieser Reihenfolge, kein Trennzeichen):
///   index          8 Byte LE
///   timestamp      8 Byte LE
///   previous_hash  64 Byte (Hex-ASCII, immer 64 Zeichen)
///   merkle_root    64 Byte (Hex-ASCII, immer 64 Zeichen)
///   data_size      8 Byte LE
///   signer         variable (UTF-8)
///
/// Durch die feste Byte-Länge der Zahlen sind Kollisionen ausgeschlossen.
pub fn calculate_hash(block: &Block) -> String {
    let mut h = Sha256::new();
    h.update(block.index.to_le_bytes());
    h.update(block.timestamp.to_le_bytes());
    h.update(block.previous_hash.as_bytes());
    h.update(block.merkle_root.as_bytes());
    h.update(block.data_size.to_le_bytes());
    h.update(block.signer.as_bytes());
    format!("{:x}", h.finalize())
}

/// HMAC-SHA-256(cluster_key, hash) – beweist Cluster-Zugehörigkeit
pub fn sign_hash(key: &str, hash: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC init");
    mac.update(hash.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Signatur eines einzelnen Blocks prüfen
pub fn verify_signature(block: &Block, key: &str) -> bool {
    if block.signature.is_empty() {
        return true;
    }
    sign_hash(key, &block.hash) == block.signature
}

/// Genesis-Block: fester Startpunkt der Chain.
///
/// - index = 0
/// - timestamp = 0  (deterministisch, unabhängig vom Startzeitpunkt)
/// - previous_hash = "0000...0000" (64 Nullen)
/// - merkle_root = SHA-256("genesis")
/// - Kein Dokument, keine Tombstones
/// - Hash wird normal berechnet → ist deterministisch für denselben cluster_key
fn genesis_block(cluster_key: &str) -> Block {
    let merkle_root = format!("{:x}", Sha256::digest(b"genesis"));
    let mut genesis = Block {
        index: 0,
        timestamp: 0,
        merkle_root,
        data_size: 0,
        previous_hash: "0".repeat(64),
        hash: String::new(),
        signer: "genesis".to_string(),
        signature: String::new(),
        owner: "system".to_string(),
        documents: Vec::new(),
        tombstones: Vec::new(),
        node_role: NodeRole::Master,
        proposal_round: 0,
        validator_pub_key: String::new(),
        validator_signature: String::new(),
    };
    let hash = calculate_hash(&genesis);
    genesis.hash = hash.clone();
    genesis.signature = sign_hash(cluster_key, &hash);
    genesis
}
