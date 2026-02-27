//! Stone Storage-Schicht
//!
//! Zwei unabhängige Speicher-Backends:
//!
//! ## 1. ChainStore (RocksDB)
//!
//! Persistiert die Blockchain in einer RocksDB-Datenbank mit 3 Column Families:
//!
//! | CF        | Key              | Value                          |
//! |-----------|------------------|--------------------------------|
//! | `blocks`  | index (8 Byte LE)| bincode-serialisierter Block   |
//! | `meta`    | UTF-8-String     | UTF-8-Wert                     |
//! | `index`   | doc_id (UTF-8)   | block_index (8 Byte LE)        |
//!
//! Meta-Einträge:
//!   - `"latest_hash"`    → aktueller Chain-Hash
//!   - `"block_count"`    → Anzahl Blöcke (8 Byte LE)
//!   - `"genesis_hash"`   → Hash des Genesis-Blocks
//!
//! ## 2. ChunkStore (Lokales Dateisystem)
//!
//! Speichert Dokument-Chunks als einzelne Dateien unter `stone_data/chunks/<sha256-hex>`.
//! - Inhaltsadressiert: Dateiname = SHA-256 des Inhalts
//! - Deduplizierung automatisch (gleiche Bytes → gleicher Hash → eine Datei)
//! - Lesen, Schreiben, Existenz-Check, Größe, Aufräumen (Garbage Collection)

use crate::blockchain::{Block, Document, chunk_dir, data_dir, ChunkRef, CHUNK_SIZE as BLOCK_CHUNK_SIZE};
use crate::shard::{self, ShardStore};
use bincode::config::standard;
use rocksdb::{ColumnFamilyDescriptor, DB, Options, WriteBatch, WriteOptions};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

// ─── Pfade ───────────────────────────────────────────────────────────────────

pub fn chain_db_path() -> String { format!("{}/chain_db", data_dir()) }

// ─── Fehler ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StorageError {
    Rocks(rocksdb::Error),
    Encode(String),
    Decode(String),
    Io(std::io::Error),
    NotFound(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rocks(e) => write!(f, "RocksDB: {e}"),
            Self::Encode(s) => write!(f, "Kodierung: {s}"),
            Self::Decode(s) => write!(f, "Dekodierung: {s}"),
            Self::Io(e) => write!(f, "IO: {e}"),
            Self::NotFound(s) => write!(f, "Nicht gefunden: {s}"),
        }
    }
}

impl From<rocksdb::Error> for StorageError {
    fn from(e: rocksdb::Error) -> Self { Self::Rocks(e) }
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

// ─── ChainStore ───────────────────────────────────────────────────────────────

/// RocksDB-basierter Chain-Speicher.
///
/// Wird als `Arc<ChainStore>` geteilt – RocksDB selbst ist thread-safe.
pub struct ChainStore {
    db: Arc<DB>,
}

impl ChainStore {
    /// Öffnet (oder erstellt) die RocksDB-Datenbank.
    pub fn open() -> Result<Arc<Self>, StorageError> {
        std::fs::create_dir_all(data_dir())?;

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Snappy);

        // Column Families definieren
        let cf_blocks = ColumnFamilyDescriptor::new("blocks", Options::default());
        let cf_meta   = ColumnFamilyDescriptor::new("meta",   Options::default());
        let cf_index  = ColumnFamilyDescriptor::new("index",  Options::default());

        let db = DB::open_cf_descriptors(
            &opts,
            chain_db_path(),
            vec![cf_blocks, cf_meta, cf_index],
        )?;

        Ok(Arc::new(Self { db: Arc::new(db) }))
    }

    // ─── Schreiben ────────────────────────────────────────────────────────────

    /// Schreibt einen Block atomar in RocksDB.
    ///
    /// - `blocks` CF:  index_le → bincode(Block)
    /// - `index`  CF:  doc_id → block_index_le  (für jeden doc_id im Block)
    /// - `meta`   CF:  "latest_hash" + "block_count" aktualisieren
    pub fn write_block(&self, block: &Block) -> Result<(), StorageError> {
        let cf_blocks = self.db.cf_handle("blocks")
            .ok_or_else(|| StorageError::NotFound("CF 'blocks' nicht gefunden".into()))?;
        let cf_meta = self.db.cf_handle("meta")
            .ok_or_else(|| StorageError::NotFound("CF 'meta' nicht gefunden".into()))?;
        let cf_index = self.db.cf_handle("index")
            .ok_or_else(|| StorageError::NotFound("CF 'index' nicht gefunden".into()))?;

        // Block bincode-serialisieren
        let encoded = bincode::serde::encode_to_vec(block, standard())
            .map_err(|e| StorageError::Encode(e.to_string()))?;

        let key_index = block.index.to_le_bytes();
        let block_index_bytes = block.index.to_le_bytes();

        let mut batch = WriteBatch::default();

        // Block speichern
        batch.put_cf(cf_blocks, key_index, &encoded);

        // Dokument-Index aktualisieren
        for doc in &block.documents {
            batch.put_cf(cf_index, doc.doc_id.as_bytes(), block_index_bytes);
        }

        // Metadaten
        batch.put_cf(cf_meta, b"latest_hash", block.hash.as_bytes());
        let count = (block.index + 1).to_le_bytes();
        batch.put_cf(cf_meta, b"block_count", count);

        // Genesis-Hash beim ersten Block merken
        if block.index == 0 {
            batch.put_cf(cf_meta, b"genesis_hash", block.hash.as_bytes());
        }

        self.db.write(batch)?;
        Ok(())
    }

    /// Schreibt einen Block mit sofortigem WAL-Sync (für kritische Persistenz).
    ///
    /// Identisch zu `write_block`, aber mit `sync = true` in den WriteOptions,
    /// damit der Block nach dem Aufruf garantiert auf Disk ist.
    pub fn write_block_sync(&self, block: &Block) -> Result<(), StorageError> {
        let cf_blocks = self.db.cf_handle("blocks")
            .ok_or_else(|| StorageError::NotFound("CF 'blocks' nicht gefunden".into()))?;
        let cf_meta = self.db.cf_handle("meta")
            .ok_or_else(|| StorageError::NotFound("CF 'meta' nicht gefunden".into()))?;
        let cf_index = self.db.cf_handle("index")
            .ok_or_else(|| StorageError::NotFound("CF 'index' nicht gefunden".into()))?;

        let encoded = bincode::serde::encode_to_vec(block, standard())
            .map_err(|e| StorageError::Encode(e.to_string()))?;

        let key_index = block.index.to_le_bytes();
        let block_index_bytes = block.index.to_le_bytes();

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_blocks, key_index, &encoded);
        for doc in &block.documents {
            batch.put_cf(cf_index, doc.doc_id.as_bytes(), block_index_bytes);
        }
        batch.put_cf(cf_meta, b"latest_hash", block.hash.as_bytes());
        let count = (block.index + 1).to_le_bytes();
        batch.put_cf(cf_meta, b"block_count", count);
        if block.index == 0 {
            batch.put_cf(cf_meta, b"genesis_hash", block.hash.as_bytes());
        }

        // WAL sofort auf Disk flushen → überlebt Absturz / abruptes Beenden
        let mut wo = WriteOptions::default();
        wo.set_sync(true);
        self.db.write_opt(batch, &wo)?;
        Ok(())
    }

    // ─── Lesen ───────────────────────────────────────────────────────────────

    /// Liest einen einzelnen Block anhand seines Index.
    pub fn read_block(&self, index: u64) -> Result<Block, StorageError> {
        let cf = self.db.cf_handle("blocks")
            .ok_or_else(|| StorageError::NotFound("CF 'blocks'".into()))?;
        let key = index.to_le_bytes();
        let data = self.db.get_cf(cf, key)?
            .ok_or_else(|| StorageError::NotFound(format!("Block #{index}")))?;
        let (block, _) = bincode::serde::decode_from_slice::<Block, _>(&data, standard())
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        Ok(block)
    }

    /// Liest alle Blöcke in Reihenfolge (0 → n).
    pub fn read_all_blocks(&self) -> Result<Vec<Block>, StorageError> {
        let cf = self.db.cf_handle("blocks")
            .ok_or_else(|| StorageError::NotFound("CF 'blocks'".into()))?;

        let count = self.block_count()?;
        let mut blocks = Vec::with_capacity(count as usize);

        for i in 0..count {
            let key = i.to_le_bytes();
            if let Some(data) = self.db.get_cf(cf, key)? {
                let (block, _) = bincode::serde::decode_from_slice::<Block, _>(&data, standard())
                    .map_err(|e| StorageError::Decode(e.to_string()))?;
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    /// Liest eine Range von Blöcken (von `from` bis `to` exklusiv).
    pub fn read_blocks_range(&self, from: u64, to: u64) -> Result<Vec<Block>, StorageError> {
        let cf = self.db.cf_handle("blocks")
            .ok_or_else(|| StorageError::NotFound("CF 'blocks'".into()))?;
        let mut blocks = Vec::new();
        for i in from..to {
            let key = i.to_le_bytes();
            if let Some(data) = self.db.get_cf(cf, key)? {
                let (block, _) = bincode::serde::decode_from_slice::<Block, _>(&data, standard())
                    .map_err(|e| StorageError::Decode(e.to_string()))?;
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    // ─── Dokument-Abfragen ────────────────────────────────────────────────────

    /// Gibt den Block-Index zurück in dem `doc_id` zuletzt gespeichert wurde.
    pub fn find_block_for_doc(&self, doc_id: &str) -> Result<Option<u64>, StorageError> {
        let cf = self.db.cf_handle("index")
            .ok_or_else(|| StorageError::NotFound("CF 'index'".into()))?;
        match self.db.get_cf(cf, doc_id.as_bytes())? {
            Some(bytes) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes.try_into().unwrap();
                Ok(Some(u64::from_le_bytes(arr)))
            }
            _ => Ok(None),
        }
    }

    /// Gibt den Block direkt zurück der `doc_id` enthält (neueste Version).
    pub fn find_block_containing_doc(&self, doc_id: &str) -> Result<Option<Block>, StorageError> {
        if let Some(idx) = self.find_block_for_doc(doc_id)? {
            Ok(Some(self.read_block(idx)?))
        } else {
            Ok(None)
        }
    }

    // ─── Metadaten ────────────────────────────────────────────────────────────

    /// Aktueller Latest-Hash der Chain.
    pub fn latest_hash(&self) -> Result<String, StorageError> {
        let cf = self.db.cf_handle("meta")
            .ok_or_else(|| StorageError::NotFound("CF 'meta'".into()))?;
        match self.db.get_cf(cf, b"latest_hash")? {
            Some(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
            None => Ok(String::new()),
        }
    }

    /// Anzahl gespeicherter Blöcke.
    pub fn block_count(&self) -> Result<u64, StorageError> {
        let cf = self.db.cf_handle("meta")
            .ok_or_else(|| StorageError::NotFound("CF 'meta'".into()))?;
        match self.db.get_cf(cf, b"block_count")? {
            Some(bytes) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes.try_into().unwrap();
                Ok(u64::from_le_bytes(arr))
            }
            _ => Ok(0),
        }
    }

    /// Genesis-Hash (leer = keine Chain vorhanden).
    pub fn genesis_hash(&self) -> Result<String, StorageError> {
        let cf = self.db.cf_handle("meta")
            .ok_or_else(|| StorageError::NotFound("CF 'meta'".into()))?;
        match self.db.get_cf(cf, b"genesis_hash")? {
            Some(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
            None => Ok(String::new()),
        }
    }

    /// Gibt true zurück wenn die Datenbank leer ist (kein Genesis-Block).
    pub fn is_empty(&self) -> bool {
        self.block_count().unwrap_or(0) == 0
    }

    // ─── Diagnose / Admin ─────────────────────────────────────────────────────

    /// Gibt eine Zusammenfassung der gespeicherten Daten zurück.
    pub fn summary(&self) -> StoreSummary {
        let block_count = self.block_count().unwrap_or(0);
        let latest_hash = self.latest_hash().unwrap_or_default();
        let genesis_hash = self.genesis_hash().unwrap_or_default();
        StoreSummary { block_count, latest_hash, genesis_hash }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StoreSummary {
    pub block_count: u64,
    pub latest_hash: String,
    pub genesis_hash: String,
}

// ─── ChunkStore ───────────────────────────────────────────────────────────────

/// Lokaler inhaltsadressierter Speicher für Dokument-Chunks.
///
/// Layout: `stone_data/chunks/<sha256-hex-64>` (eine Datei pro Chunk)
///
/// Vorteile:
/// - Automatische Deduplizierung (gleicher Inhalt = gleiche Datei)
/// - Kein Datenbankoverhead für Binärdaten
/// - Einfaches Backup: Verzeichnis kopieren
/// - Peer-Sync: fehlt eine Datei → bei Peer abrufen
#[derive(Clone)]
pub struct ChunkStore {
    base_dir: PathBuf,
}

impl ChunkStore {
    /// Erstellt einen ChunkStore (legt Verzeichnis an falls nötig).
    pub fn new() -> Result<Self, StorageError> {
        let base_dir = PathBuf::from(chunk_dir());
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Pfad zu einem Chunk anhand seines Hashes.
    fn chunk_path(&self, hash: &str) -> PathBuf {
        self.base_dir.join(hash)
    }

    // ─── Schreiben ────────────────────────────────────────────────────────────

    /// Schreibt einen Chunk und gibt seinen SHA-256-Hash zurück.
    ///
    /// Wenn der Chunk bereits existiert wird er nicht überschrieben (Deduplizierung).
    pub fn write_chunk(&self, data: &[u8]) -> Result<String, StorageError> {
        let hash = self.compute_hash(data);
        let path = self.chunk_path(&hash);
        if !path.exists() {
            std::fs::write(&path, data)?;
        }
        Ok(hash)
    }

    /// Schreibt mehrere Chunks auf einmal und gibt ihre Hashes zurück.
    pub fn write_chunks(&self, data: &[u8], chunk_size: usize) -> Result<Vec<crate::blockchain::ChunkRef>, StorageError> {
        let mut refs = Vec::new();
        for chunk in data.chunks(chunk_size.max(1)) {
            let hash = self.write_chunk(chunk)?;
            refs.push(crate::blockchain::ChunkRef {
                hash,
                size: chunk.len() as u64,
                shards: Vec::new(),
                ec_k: 0,
                ec_m: 0,
            });
        }
        Ok(refs)
    }

    // ─── Lesen ───────────────────────────────────────────────────────────────

    /// Liest einen einzelnen Chunk anhand seines Hashes.
    pub fn read_chunk(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.chunk_path(hash);
        std::fs::read(&path).map_err(|_| {
            StorageError::NotFound(format!("Chunk {hash} nicht gefunden"))
        })
    }

    /// Rekonstruiert ein Dokument aus seinen Chunks.
    pub fn reconstruct_document(&self, doc: &Document) -> Result<Vec<u8>, StorageError> {
        if doc.chunks.is_empty() {
            return Err(StorageError::NotFound(format!(
                "Dokument '{}' hat keine Chunks", doc.doc_id
            )));
        }
        let mut data = Vec::new();
        for ch in &doc.chunks {
            let bytes = self.read_chunk(&ch.hash)?;
            if bytes.len() as u64 != ch.size {
                return Err(StorageError::Decode(format!(
                    "Chunk {}: Größe stimmt nicht ({} != {})", ch.hash, bytes.len(), ch.size
                )));
            }
            data.extend_from_slice(&bytes);
        }
        Ok(data)
    }

    // ─── Abfragen ────────────────────────────────────────────────────────────

    /// Gibt true zurück wenn ein Chunk mit diesem Hash vorhanden ist.
    pub fn has_chunk(&self, hash: &str) -> bool {
        self.chunk_path(hash).exists()
    }

    /// Gibt die Größe eines Chunks zurück (None falls nicht vorhanden).
    pub fn chunk_size(&self, hash: &str) -> Option<u64> {
        std::fs::metadata(self.chunk_path(hash)).ok().map(|m| m.len())
    }

    /// Gibt alle gespeicherten Chunk-Hashes zurück.
    pub fn list_chunks(&self) -> Vec<String> {
        std::fs::read_dir(&self.base_dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                            Some(name)
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gesamtgröße aller gespeicherten Chunks in Bytes.
    pub fn total_size_bytes(&self) -> u64 {
        self.list_chunks()
            .iter()
            .filter_map(|h| self.chunk_size(h))
            .sum()
    }

    /// Anzahl gespeicherter Chunks.
    pub fn chunk_count(&self) -> usize {
        self.list_chunks().len()
    }

    // ─── Garbage Collection ──────────────────────────────────────────────────

    /// Entfernt alle Chunks die von keinem Block mehr referenziert werden.
    ///
    /// Gibt zurück wie viele Chunks gelöscht wurden und wie viele Bytes freigegeben.
    pub fn gc(&self, referenced_hashes: &std::collections::HashSet<String>) -> GcResult {
        let all = self.list_chunks();
        let mut deleted = 0usize;
        let mut freed_bytes = 0u64;

        for hash in &all {
            if !referenced_hashes.contains(hash.as_str()) {
                if let Some(size) = self.chunk_size(hash) {
                    let _ = std::fs::remove_file(self.chunk_path(hash));
                    deleted += 1;
                    freed_bytes += size;
                }
            }
        }

        GcResult { deleted, freed_bytes }
    }

    // ─── Intern ──────────────────────────────────────────────────────────────

    fn compute_hash(&self, data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }
}

impl Default for ChunkStore {
    fn default() -> Self {
        Self::new().expect("ChunkStore konnte nicht erstellt werden")
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GcResult {
    pub deleted: usize,
    pub freed_bytes: u64,
}

// ─── Kombinierter Store ───────────────────────────────────────────────────────

/// Fasst ChainStore, ChunkStore und ShardStore zusammen.
/// Wird als `Arc<StoneStore>` in der gesamten Anwendung geteilt.
pub struct StoneStore {
    pub chain: Arc<ChainStore>,
    pub chunks: ChunkStore,
    pub shards: ShardStore,
}

impl StoneStore {
    pub fn open() -> Result<Arc<Self>, StorageError> {
        let chain = ChainStore::open()?;
        let chunks = ChunkStore::new()?;
        let shards = ShardStore::new().map_err(|e| StorageError::Io(
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        ))?;
        Ok(Arc::new(Self { chain, chunks, shards }))
    }

    /// Sammelt alle von der aktuellen Chain referenzierten Chunk-Hashes.
    pub fn referenced_chunks(&self) -> Result<std::collections::HashSet<String>, StorageError> {
        let blocks = self.chain.read_all_blocks()?;
        let mut hashes = std::collections::HashSet::new();
        for block in &blocks {
            for doc in &block.documents {
                for ch in &doc.chunks {
                    hashes.insert(ch.hash.clone());
                }
            }
        }
        Ok(hashes)
    }

    /// Garbage Collection: entfernt alle nicht mehr referenzierten Chunks.
    pub fn gc(&self) -> Result<GcResult, StorageError> {
        let referenced = self.referenced_chunks()?;
        Ok(self.chunks.gc(&referenced))
    }

    /// Liest Dokument-Daten — automatisch aus Chunks (Legacy) oder Shards (Erasure-Coded).
    pub fn read_document_data(&self, doc: &Document) -> Result<Vec<u8>, StorageError> {
        let mut data = Vec::new();
        for chunk_ref in &doc.chunks {
            let chunk_data = if chunk_ref.shards.is_empty() {
                // Legacy: Full-Replication Chunk
                self.chunks.read_chunk(&chunk_ref.hash)?
            } else {
                // Neu: Erasure-Coded Shards – lokale Rekonstruktion versuchen
                self.shards
                    .try_reconstruct_local(
                        &chunk_ref.hash,
                        chunk_ref.ec_k,
                        chunk_ref.ec_m,
                        chunk_ref.size as usize,
                    )
                    .map_err(|e| StorageError::NotFound(e.to_string()))?
            };
            data.extend_from_slice(&chunk_data);
        }
        Ok(data)
    }

    /// Erasure-Coded ein Dokument: Nimmt die Roh-Bytes und bestehende ChunkRefs,
    /// encoded jeden Chunk mit Reed-Solomon, speichert alle Shards lokal,
    /// und gibt aktualisierte ChunkRefs mit ShardRef-Infos zurück.
    ///
    /// Der `local_peer_id` wird als `holder` für die lokal gespeicherten Shards gesetzt.
    ///
    /// Parameter:
    /// - `raw_data`: Die vollständigen Dokument-Bytes (vor oder nach Verschlüsselung)
    /// - `chunk_refs`: Bestehende ChunkRefs (aus `write_chunks()`)
    /// - `local_peer_id`: PeerId dieser Node (als Holder-Referenz)
    /// - `k`: Anzahl Daten-Shards (Default: 4)
    /// - `m`: Anzahl Parity-Shards (Default: 2)
    pub fn erasure_code_chunks(
        &self,
        raw_data: &[u8],
        chunk_refs: &[ChunkRef],
        local_peer_id: &str,
        k: u8,
        m: u8,
    ) -> Result<Vec<ChunkRef>, StorageError> {
        let chunk_size = BLOCK_CHUNK_SIZE;
        let mut coded_refs = Vec::with_capacity(chunk_refs.len());

        for (i, chunk_ref) in chunk_refs.iter().enumerate() {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(raw_data.len());
            let chunk_data = &raw_data[start..end];

            // Reed-Solomon Encoding
            let shard_pieces = shard::encode_chunk(chunk_data, k as usize, m as usize)
                .map_err(|e| StorageError::Encode(format!("Erasure-Coding Chunk {}: {e}", chunk_ref.hash)))?;

            // Alle Shards lokal speichern (diese Node hält erstmal alle)
            let shard_tuples: Vec<(u8, Vec<u8>)> = shard_pieces
                .into_iter()
                .enumerate()
                .map(|(idx, data)| (idx as u8, data))
                .collect();

            let mut shard_refs = self.shards
                .write_my_shards(&chunk_ref.hash, &shard_tuples)
                .map_err(|e| StorageError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                ))?;

            // Holder auf local_peer_id setzen
            for sr in &mut shard_refs {
                sr.holder = local_peer_id.to_string();
            }

            coded_refs.push(ChunkRef {
                hash: chunk_ref.hash.clone(),
                size: chunk_ref.size,
                shards: shard_refs,
                ec_k: k,
                ec_m: m,
            });
        }

        Ok(coded_refs)
    }
}

// ─── Shard-Verteilung (async) ─────────────────────────────────────────────────

/// Verteilt Shards eines Dokuments an verbundene Peers via P2P ShardExchange.
///
/// Strategie:
/// - Holt die Liste der verbundenen Peers
/// - Weist Shards per Round-Robin an Peers zu (assign_shards_to_peers)
/// - Sendet jeden zugewiesenen Shard via `store_shard_on_peer()`
/// - Wartet NICHT auf Bestätigung (fire-and-forget; Bestätigungen kommen als NetworkEvent)
///
/// Gibt die aktualisierten ChunkRefs zurück mit den Holder-Infos.
pub async fn distribute_shards(
    chunk_refs: &[ChunkRef],
    shard_store: &ShardStore,
    network: &crate::network::NetworkHandle,
) -> Vec<ChunkRef> {
    // Verbundene Peers holen
    let peers = network.connected_peers().await;
    if peers.is_empty() {
        println!("[sharding] ⚠ Keine verbundenen Peers – Shards bleiben nur lokal");
        return chunk_refs.to_vec();
    }

    let peer_ids: Vec<String> = peers.iter().map(|p| p.peer_id.clone()).collect();
    println!(
        "[sharding] 📤 Verteile Shards an {} Peer(s): {:?}",
        peer_ids.len(),
        peer_ids.iter().map(|p| &p[..8.min(p.len())]).collect::<Vec<_>>()
    );

    let mut updated_refs = Vec::with_capacity(chunk_refs.len());

    for chunk_ref in chunk_refs {
        if chunk_ref.shards.is_empty() || chunk_ref.ec_k == 0 {
            // Nicht erasure-coded → überspringen
            updated_refs.push(chunk_ref.clone());
            continue;
        }

        let k = chunk_ref.ec_k;
        let m = chunk_ref.ec_m;

        // Shard-Zuweisung berechnen
        let assignments = shard::assign_shards_to_peers(
            &chunk_ref.hash,
            &peer_ids,
            k,
            m,
        );

        let mut updated_shards = chunk_ref.shards.clone();

        for (shard_index, target_peer_id) in &assignments {
            // Shard lokal lesen
            let shard_data = match shard_store.read_shard(&chunk_ref.hash, *shard_index) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!(
                        "[sharding] ❌ Kann Shard {}[{}] nicht lesen: {e}",
                        &chunk_ref.hash[..8], shard_index
                    );
                    continue;
                }
            };

            // Shard-Hash für Integrität
            let hash = shard::shard_hash(&shard_data);

            // PeerId parsen
            let peer_id: libp2p::PeerId = match target_peer_id.parse() {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("[sharding] ❌ Ungültige PeerId {target_peer_id}: {e}");
                    continue;
                }
            };

            println!(
                "[sharding] → Shard {}[{}] ({} bytes) → {}",
                &chunk_ref.hash[..8.min(chunk_ref.hash.len())],
                shard_index,
                shard_data.len(),
                &target_peer_id[..8.min(target_peer_id.len())]
            );

            // An Peer senden (fire-and-forget)
            network
                .store_shard_on_peer(
                    peer_id,
                    chunk_ref.hash.clone(),
                    *shard_index,
                    hash,
                    shard_data,
                )
                .await;

            // Holder in den ShardRefs aktualisieren
            if let Some(sr) = updated_shards
                .iter_mut()
                .find(|s| s.shard_index == *shard_index)
            {
                // Zusätzlichen Holder vermerken (Komma-getrennt)
                if !sr.holder.is_empty() {
                    sr.holder = format!("{},{}", sr.holder, target_peer_id);
                } else {
                    sr.holder = target_peer_id.clone();
                }
            }
        }

        updated_refs.push(ChunkRef {
            hash: chunk_ref.hash.clone(),
            size: chunk_ref.size,
            shards: updated_shards,
            ec_k: k,
            ec_m: m,
        });
    }

    println!(
        "[sharding] ✅ Verteilung für {} Chunk(s) abgeschlossen",
        updated_refs.len()
    );
    updated_refs
}

// ─── Shard-Download (async) ───────────────────────────────────────────────────

/// Holt fehlende Shards von Peers und rekonstruiert ein Dokument.
///
/// Ablauf für jeden Chunk eines Dokuments:
/// 1. Versucht lokale Rekonstruktion (try_reconstruct_local)
/// 2. Bei Fehler: Prüft welche Shards lokal fehlen
/// 3. Holt fehlende Shards von Peers (anhand der Holder-Infos in ShardRef)
/// 4. Rekonstruiert mit reconstruct_with_remote()
///
/// Gibt die vollständigen Dokument-Bytes zurück.
pub async fn read_document_with_remote_shards(
    doc: &Document,
    shard_store: &ShardStore,
    chunk_store: &ChunkStore,
    network: &crate::network::NetworkHandle,
) -> Result<Vec<u8>, StorageError> {
    let mut data = Vec::new();

    for chunk_ref in &doc.chunks {
        let chunk_data = if chunk_ref.shards.is_empty() {
            // Legacy: kein Erasure Coding → direkt aus Chunk-Store
            chunk_store.read_chunk(&chunk_ref.hash)?
        } else {
            // Erasure-Coded: Erst lokal versuchen
            match shard_store.try_reconstruct_local(
                &chunk_ref.hash,
                chunk_ref.ec_k,
                chunk_ref.ec_m,
                chunk_ref.size as usize,
            ) {
                Ok(bytes) => bytes,
                Err(local_err) => {
                    // Lokale Rekonstruktion fehlgeschlagen → Remote-Shards holen
                    println!(
                        "[sharding] ⬇️ Lokale Rekonstruktion fehlgeschlagen für {}: {local_err}",
                        &chunk_ref.hash[..8.min(chunk_ref.hash.len())]
                    );

                    let remote_shards = fetch_missing_shards_for_chunk(
                        chunk_ref,
                        shard_store,
                        network,
                    ).await;

                    if remote_shards.is_empty() {
                        return Err(StorageError::NotFound(format!(
                            "Chunk {} nicht rekonstruierbar: keine Remote-Shards verfügbar",
                            chunk_ref.hash
                        )));
                    }

                    // Jetzt mit lokalen + remote Shards rekonstruieren
                    shard_store
                        .reconstruct_with_remote(
                            &chunk_ref.hash,
                            &remote_shards,
                            chunk_ref.ec_k,
                            chunk_ref.ec_m,
                            chunk_ref.size as usize,
                        )
                        .map_err(|e| StorageError::NotFound(format!(
                            "Rekonstruktion fehlgeschlagen für Chunk {}: {e}",
                            chunk_ref.hash
                        )))?
                }
            }
        };
        data.extend_from_slice(&chunk_data);
    }

    Ok(data)
}

/// Holt fehlende Shards für einen bestimmten Chunk von Peers.
///
/// Strategie:
/// 1. Ermittelt welche Shard-Indices lokal fehlen
/// 2. Für jeden fehlenden Shard: prüft die Holder-Liste in ShardRef
/// 3. Fordert Shard von dem/den Holder-Peer(s) an
/// 4. Wartet auf Antwort (mit Timeout)
///
/// Gibt eine Map shard_index → shard_data zurück.
async fn fetch_missing_shards_for_chunk(
    chunk_ref: &ChunkRef,
    shard_store: &ShardStore,
    network: &crate::network::NetworkHandle,
) -> std::collections::HashMap<u8, Vec<u8>> {
    use std::collections::HashMap;
    use tokio::sync::broadcast;

    let local_indices = shard_store.local_shard_indices(&chunk_ref.hash);
    let k = chunk_ref.ec_k as usize;

    // Wie viele Shards brauchen wir noch?
    let needed = if local_indices.len() >= k {
        return HashMap::new(); // Genug lokal!
    } else {
        k - local_indices.len()
    };

    println!(
        "[sharding] 🔍 Brauche {} weitere Shard(s) für {} (lokal: {:?})",
        needed,
        &chunk_ref.hash[..8.min(chunk_ref.hash.len())],
        local_indices
    );

    // Fehlende Shard-Indices bestimmen
    let total_shards = (chunk_ref.ec_k + chunk_ref.ec_m) as u8;
    let missing_indices: Vec<u8> = (0..total_shards)
        .filter(|i| !local_indices.contains(i))
        .collect();

    // Event-Listener für eingehende Shards
    let mut event_rx = network.subscribe();
    let mut fetched: HashMap<u8, Vec<u8>> = HashMap::new();

    // Shard-Anfragen senden
    for shard_ref in &chunk_ref.shards {
        if !missing_indices.contains(&shard_ref.shard_index) {
            continue; // Haben wir schon lokal
        }

        // Holder kann kommagetrennt mehrere PeerIds enthalten
        let holders: Vec<&str> = shard_ref.holder.split(',').collect();
        for holder_id in holders {
            let holder_id = holder_id.trim();
            if holder_id.is_empty() || holder_id == network.local_peer_id {
                continue;
            }

            if let Ok(peer_id) = holder_id.parse::<libp2p::PeerId>() {
                println!(
                    "[sharding] → Anfrage Shard {}[{}] von {}",
                    &chunk_ref.hash[..8.min(chunk_ref.hash.len())],
                    shard_ref.shard_index,
                    &holder_id[..8.min(holder_id.len())]
                );
                network
                    .request_shard(peer_id, chunk_ref.hash.clone(), shard_ref.shard_index)
                    .await;
                break; // Nur von einem Holder anfordern (retry bei nächstem Versuch)
            }
        }
    }

    // Fallback: Wenn keine Holder bekannt sind, alle verbundenen Peers fragen
    if chunk_ref.shards.iter().all(|s| s.holder.is_empty()) {
        let peers = network.connected_peers().await;
        for missing_idx in &missing_indices {
            if fetched.len() >= needed {
                break;
            }
            for peer in &peers {
                if let Ok(peer_id) = peer.peer_id.parse::<libp2p::PeerId>() {
                    println!(
                        "[sharding] → Broadcast-Anfrage Shard {}[{}] an {}",
                        &chunk_ref.hash[..8.min(chunk_ref.hash.len())],
                        missing_idx,
                        &peer.peer_id[..8.min(peer.peer_id.len())]
                    );
                    network
                        .request_shard(peer_id, chunk_ref.hash.clone(), *missing_idx)
                        .await;
                }
            }
        }
    }

    // Auf Antworten warten (Timeout: 10 Sekunden)
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);

    loop {
        if fetched.len() >= needed {
            break;
        }

        let remaining = deadline - tokio::time::Instant::now();
        if remaining.is_zero() {
            eprintln!(
                "[sharding] ⏰ Timeout: {} von {} benötigten Shards empfangen",
                fetched.len(),
                needed
            );
            break;
        }

        match tokio::time::timeout(remaining, event_rx.recv()).await {
            Ok(Ok(crate::network::NetworkEvent::ShardReceived {
                chunk_hash,
                shard_index,
                data,
                from_peer,
            })) if chunk_hash == chunk_ref.hash => {
                println!(
                    "[sharding] ← Shard {}[{}] empfangen von {} ({} bytes)",
                    &chunk_hash[..8.min(chunk_hash.len())],
                    shard_index,
                    &from_peer[..8.min(from_peer.len())],
                    data.len()
                );

                // Shard lokal cachen für zukünftige Anfragen
                if let Err(e) = shard_store.write_shard(&chunk_hash, shard_index, &data) {
                    eprintln!("[sharding] ⚠ Shard lokal cachen fehlgeschlagen: {e}");
                }

                fetched.insert(shard_index, data);
            }
            Ok(Ok(crate::network::NetworkEvent::ShardRequestFailed {
                chunk_hash,
                shard_index,
                peer_id,
                error,
            })) if chunk_hash == chunk_ref.hash => {
                eprintln!(
                    "[sharding] ⚠ Shard {}[{}] von {} fehlgeschlagen: {error}",
                    &chunk_hash[..8.min(chunk_hash.len())],
                    shard_index,
                    &peer_id[..8.min(peer_id.len())]
                );
            }
            Ok(Ok(_)) => {
                // Anderes Event → ignorieren, weiter warten
                continue;
            }
            Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                eprintln!("[sharding] Event-Buffer übergelaufen ({n} verpasst)");
                continue;
            }
            Ok(Err(_)) => break, // Channel geschlossen
            Err(_) => break,     // Timeout
        }
    }

    println!(
        "[sharding] 📦 {} Remote-Shard(s) für {} empfangen",
        fetched.len(),
        &chunk_ref.hash[..8.min(chunk_ref.hash.len())]
    );
    fetched
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{Block, NodeRole};

    fn make_test_block(index: u64, prev_hash: &str) -> Block {
        Block {
            index,
            timestamp: 0,
            merkle_root: format!("{:x}", Sha256::digest(b"test")),
            data_size: 0,
            previous_hash: prev_hash.to_string(),
            hash: format!("hash{index:064}"),
            signer: "test".into(),
            signature: String::new(),
            owner: "test".into(),
            documents: Vec::new(),
            tombstones: Vec::new(),
            node_role: NodeRole::Master,
            proposal_round: 0,
            validator_pub_key: String::new(),
            validator_signature: String::new(),
        }
    }

    #[test]
    fn test_chunk_roundtrip() {
        let store = ChunkStore::new().unwrap();
        let data = b"Hello Stone Storage!";
        let hash = store.write_chunk(data).unwrap();
        assert_eq!(hash.len(), 64);
        let read_back = store.read_chunk(&hash).unwrap();
        assert_eq!(data.as_ref(), read_back.as_slice());
    }

    #[test]
    fn test_chunk_deduplication() {
        let store = ChunkStore::new().unwrap();
        let data = b"Deduplizierter Inhalt";
        let h1 = store.write_chunk(data).unwrap();
        let h2 = store.write_chunk(data).unwrap();
        assert_eq!(h1, h2, "Gleicher Inhalt muss gleichen Hash produzieren");
    }

    #[test]
    fn test_chunk_not_found() {
        let store = ChunkStore::new().unwrap();
        let result = store.read_chunk(&"0".repeat(64));
        assert!(result.is_err());
    }
}
