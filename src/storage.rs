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

use crate::blockchain::{Block, Document, chunk_dir, data_dir};
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

/// Fasst ChainStore und ChunkStore zusammen.
/// Wird als `Arc<StoneStore>` in der gesamten Anwendung geteilt.
pub struct StoneStore {
    pub chain: Arc<ChainStore>,
    pub chunks: ChunkStore,
}

impl StoneStore {
    pub fn open() -> Result<Arc<Self>, StorageError> {
        let chain = ChainStore::open()?;
        let chunks = ChunkStore::new()?;
        Ok(Arc::new(Self { chain, chunks }))
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
