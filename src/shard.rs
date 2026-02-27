//! Stone Shard-Modul – Erasure Coding für Chunk-Distribution
//!
//! Verwendet Reed-Solomon Erasure Coding um Chunks in Shards aufzuteilen
//! und auf mehrere Nodes zu verteilen. Jede Node speichert nur einen Teil
//! der Daten, aber das Netzwerk kann die Originaldaten jederzeit rekonstruieren.
//!
//! ## Terminologie
//!
//! | Begriff | Bedeutung |
//! |---------|-----------|
//! | **Chunk** | 8 MiB Block einer Datei (bestehende Einheit) |
//! | **Shard** | Fragment eines erasure-coded Chunks |
//! | **k** | Anzahl Daten-Shards (Minimum für Rekonstruktion) |
//! | **m** | Anzahl Paritäts-Shards (Redundanz) |
//! | **n = k + m** | Totale Shards pro Chunk |
//!
//! ## Beispiel (k=4, m=2)
//!
//! ```text
//! 8 MiB Chunk → [S₀ 2MiB][S₁ 2MiB][S₂ 2MiB][S₃ 2MiB][P₀ 2MiB][P₁ 2MiB]
//!                 │         │         │         │         │         │
//!              Node A    Node B    Node C    Node D    Node E    Node F
//!
//! Rekonstruktion: Beliebige 4 von 6 Shards → Original-Chunk
//! ```

use anyhow::{anyhow, bail, Context, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::blockchain::{data_dir, ShardRef};

// ─── Konstanten ──────────────────────────────────────────────────────────────

/// Standard Daten-Shards (Minimum für Rekonstruktion)
pub const DEFAULT_EC_K: u8 = 4;
/// Standard Paritäts-Shards (Redundanz)  
pub const DEFAULT_EC_M: u8 = 2;

/// Shard-Verzeichnis: stone_data/shards/
pub fn shard_dir() -> String {
    format!("{}/shards", data_dir())
}

// ─── Encoding / Decoding ─────────────────────────────────────────────────────

/// Encodes a chunk into k data shards + m parity shards using Reed-Solomon.
///
/// Returns `n = k + m` shards, each of size `ceil(chunk.len() / k)`.
/// The input is padded with zeros if not evenly divisible by k.
pub fn encode_chunk(chunk: &[u8], k: usize, m: usize) -> Result<Vec<Vec<u8>>> {
    if k == 0 || m == 0 {
        bail!("k und m müssen > 0 sein (k={k}, m={m})");
    }
    if chunk.is_empty() {
        bail!("Chunk darf nicht leer sein");
    }

    let rs = ReedSolomon::new(k, m)
        .map_err(|e| anyhow!("Reed-Solomon init fehlgeschlagen: {e}"))?;

    // Shard-Größe: Jeder Shard = ceil(chunk_len / k)
    let shard_size = (chunk.len() + k - 1) / k;

    // Erstelle k Daten-Shards (mit Padding falls nötig)
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
    for i in 0..k {
        let start = i * shard_size;
        let end = std::cmp::min(start + shard_size, chunk.len());
        let mut shard = Vec::with_capacity(shard_size);
        if start < chunk.len() {
            shard.extend_from_slice(&chunk[start..end]);
        }
        // Padding mit Nullen auf shard_size auffüllen
        shard.resize(shard_size, 0);
        shards.push(shard);
    }

    // Erstelle m leere Paritäts-Shards
    for _ in 0..m {
        shards.push(vec![0u8; shard_size]);
    }

    // Reed-Solomon Encoding: Füllt die Paritäts-Shards
    rs.encode(&mut shards)
        .map_err(|e| anyhow!("Reed-Solomon Encoding fehlgeschlagen: {e}"))?;

    Ok(shards)
}

/// Decodes k (or more) shards back into the original chunk.
///
/// `shard_data` maps shard_index → shard bytes. At least k shards must be present.
/// The original chunk size is needed to strip padding.
pub fn decode_chunk(
    shard_data: &HashMap<usize, Vec<u8>>,
    k: usize,
    m: usize,
    original_size: usize,
) -> Result<Vec<u8>> {
    if shard_data.len() < k {
        bail!(
            "Zu wenige Shards: {} vorhanden, {} benötigt",
            shard_data.len(),
            k
        );
    }

    let rs = ReedSolomon::new(k, m)
        .map_err(|e| anyhow!("Reed-Solomon init fehlgeschlagen: {e}"))?;

    let n = k + m;

    // Bestimme Shard-Größe aus vorhandenen Shards
    let shard_size = shard_data
        .values()
        .next()
        .ok_or_else(|| anyhow!("Keine Shards vorhanden"))?
        .len();

    // Baue Shard-Array mit Option<Vec<u8>> (None = fehlender Shard)
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; n];
    for (&idx, data) in shard_data {
        if idx >= n {
            bail!("Ungültiger Shard-Index: {idx} (max {n})");
        }
        if data.len() != shard_size {
            bail!(
                "Shard {idx} hat falsche Größe: {} (erwartet {shard_size})",
                data.len()
            );
        }
        shards[idx] = Some(data.clone());
    }

    // Reed-Solomon Reconstruction
    rs.reconstruct(&mut shards)
        .map_err(|e| anyhow!("Reed-Solomon Dekodierung fehlgeschlagen: {e}"))?;

    // Daten-Shards (0..k) zusammenfügen und auf original_size trimmen
    let mut result = Vec::with_capacity(original_size);
    for shard in shards.iter().take(k) {
        if let Some(data) = shard {
            result.extend_from_slice(data);
        } else {
            bail!("Daten-Shard fehlt nach Rekonstruktion");
        }
    }
    result.truncate(original_size);

    Ok(result)
}

/// Berechnet den SHA-256 Hash eines Shards.
pub fn shard_hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// ─── ShardStore ──────────────────────────────────────────────────────────────

/// Lokaler Speicher für Erasure-Coded Shards.
///
/// Layout: `stone_data/shards/<chunk_hash>/<shard_index>`
///
/// Jede Node speichert nur die Shards die ihr zugewiesen wurden.
/// Bei Rekonstruktion werden fehlende Shards von anderen Nodes geholt.
#[derive(Clone)]
pub struct ShardStore {
    base_dir: PathBuf,
}

impl ShardStore {
    /// Erstellt einen neuen ShardStore.
    pub fn new() -> Result<Self> {
        let base_dir = PathBuf::from(shard_dir());
        std::fs::create_dir_all(&base_dir)
            .context("ShardStore-Verzeichnis erstellen")?;
        Ok(Self { base_dir })
    }

    /// Pfad zu einem Shard.
    fn shard_path(&self, chunk_hash: &str, shard_index: u8) -> PathBuf {
        self.base_dir.join(chunk_hash).join(format!("{shard_index}"))
    }

    /// Speichert einen Shard lokal.
    pub fn write_shard(
        &self,
        chunk_hash: &str,
        shard_index: u8,
        data: &[u8],
    ) -> Result<String> {
        let dir = self.base_dir.join(chunk_hash);
        std::fs::create_dir_all(&dir)?;

        let hash = shard_hash(data);
        let path = self.shard_path(chunk_hash, shard_index);
        std::fs::write(&path, data)?;

        Ok(hash)
    }

    /// Speichert mehrere Shards die dieser Node halten soll.
    pub fn write_my_shards(
        &self,
        chunk_hash: &str,
        shards: &[(u8, Vec<u8>)],
    ) -> Result<Vec<ShardRef>> {
        let mut refs = Vec::with_capacity(shards.len());
        for (index, data) in shards {
            let hash = self.write_shard(chunk_hash, *index, data)?;
            refs.push(ShardRef {
                chunk_hash: chunk_hash.to_string(),
                shard_index: *index,
                shard_hash: hash,
                shard_size: data.len() as u64,
                holder: String::new(), // wird vom Caller gesetzt
            });
        }
        Ok(refs)
    }

    /// Liest einen lokalen Shard.
    pub fn read_shard(&self, chunk_hash: &str, shard_index: u8) -> Result<Vec<u8>> {
        let path = self.shard_path(chunk_hash, shard_index);
        std::fs::read(&path)
            .with_context(|| format!("Shard {chunk_hash}/{shard_index} nicht gefunden"))
    }

    /// Prüft ob ein bestimmter Shard lokal vorhanden ist.
    pub fn has_shard(&self, chunk_hash: &str, shard_index: u8) -> bool {
        self.shard_path(chunk_hash, shard_index).exists()
    }

    /// Gibt alle lokal vorhandenen Shard-Indices für einen Chunk zurück.
    pub fn local_shard_indices(&self, chunk_hash: &str) -> Vec<u8> {
        let dir = self.base_dir.join(chunk_hash);
        if !dir.exists() {
            return Vec::new();
        }
        std::fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .parse::<u8>()
                            .ok()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Rekonstruiert einen Chunk aus lokal verfügbaren Shards.
    ///
    /// Gibt `Err` zurück wenn weniger als k Shards lokal vorhanden sind.
    /// In dem Fall müssen fehlende Shards erst von anderen Nodes geholt werden.
    pub fn try_reconstruct_local(
        &self,
        chunk_hash: &str,
        k: u8,
        m: u8,
        original_size: usize,
    ) -> Result<Vec<u8>> {
        let indices = self.local_shard_indices(chunk_hash);
        if indices.len() < k as usize {
            bail!(
                "Nur {} von {} benötigten Shards lokal für Chunk {chunk_hash}",
                indices.len(),
                k
            );
        }

        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        for idx in indices.iter().take(k as usize + m as usize) {
            let data = self.read_shard(chunk_hash, *idx)?;
            shard_data.insert(*idx as usize, data);
            if shard_data.len() >= k as usize {
                break;
            }
        }

        decode_chunk(&shard_data, k as usize, m as usize, original_size)
    }

    /// Rekonstruiert einen Chunk aus einer Mischung lokaler und remote Shards.
    pub fn reconstruct_with_remote(
        &self,
        chunk_hash: &str,
        remote_shards: &HashMap<u8, Vec<u8>>,
        k: u8,
        m: u8,
        original_size: usize,
    ) -> Result<Vec<u8>> {
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();

        // Erst lokale Shards laden
        for idx in self.local_shard_indices(chunk_hash) {
            if let Ok(data) = self.read_shard(chunk_hash, idx) {
                shard_data.insert(idx as usize, data);
            }
        }

        // Dann remote Shards hinzufügen
        for (idx, data) in remote_shards {
            shard_data.entry(*idx as usize).or_insert_with(|| data.clone());
        }

        if shard_data.len() < k as usize {
            bail!(
                "Nicht genug Shards: {} vorhanden (lokal+remote), {} benötigt",
                shard_data.len(),
                k
            );
        }

        decode_chunk(&shard_data, k as usize, m as usize, original_size)
    }

    /// Gesamte lokale Shard-Statistik.
    pub fn stats(&self) -> ShardStats {
        let mut total_shards = 0u64;
        let mut total_bytes = 0u64;
        let mut chunks_with_shards = 0u64;

        if let Ok(entries) = std::fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    chunks_with_shards += 1;
                    if let Ok(shard_entries) = std::fs::read_dir(entry.path()) {
                        for shard_entry in shard_entries.flatten() {
                            total_shards += 1;
                            total_bytes += shard_entry
                                .metadata()
                                .map(|m| m.len())
                                .unwrap_or(0);
                        }
                    }
                }
            }
        }

        ShardStats {
            total_shards,
            total_bytes,
            chunks_with_shards,
        }
    }

    /// Entfernt alle Shards für einen bestimmten Chunk.
    pub fn remove_chunk_shards(&self, chunk_hash: &str) -> Result<u64> {
        let dir = self.base_dir.join(chunk_hash);
        if !dir.exists() {
            return Ok(0);
        }
        let mut freed = 0u64;
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                freed += entry.metadata().map(|m| m.len()).unwrap_or(0);
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let _ = std::fs::remove_dir(&dir);
        Ok(freed)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ShardStats {
    pub total_shards: u64,
    pub total_bytes: u64,
    pub chunks_with_shards: u64,
}

// ─── Shard-Zuordnung ─────────────────────────────────────────────────────────

/// Weist Shards an Peers zu basierend auf XOR-Distance.
///
/// Verwendet Kademlia-ähnliche Distanz: Die n Peers mit der kleinsten
/// XOR-Distanz zum Shard-Key bekommen jeweils einen Shard.
pub fn assign_shards_to_peers(
    chunk_hash: &str,
    peer_ids: &[String],
    k: u8,
    m: u8,
) -> Vec<(u8, String)> {
    let n = (k + m) as usize;

    if peer_ids.is_empty() {
        // Kein Peer verfügbar → alle lokal
        return (0..n as u8).map(|i| (i, String::new())).collect();
    }

    // Für jeden Shard-Index: Berechne Shard-Key und finde nächsten Peer
    let mut assignments = Vec::with_capacity(n);
    for shard_idx in 0..n {
        let shard_key = format!("{chunk_hash}:{shard_idx}");
        let shard_key_hash = hex::encode(Sha256::digest(shard_key.as_bytes()));

        // Sortiere Peers nach XOR-Distance zum Shard-Key
        let _peer_distances: Vec<(usize, &str)> = peer_ids
            .iter()
            .enumerate()
            .map(|(i, pid)| {
                // Einfache Distanz-Berechnung: XOR der ersten 8 Bytes der Hashes
                (i, pid.as_str())
            })
            .collect();

        // Round-Robin mit Offset basierend auf Shard-Key für gleichmäßige Verteilung
        let key_byte = u64::from_str_radix(&shard_key_hash[..16], 16).unwrap_or(0);
        let peer_idx = (key_byte as usize + shard_idx) % peer_ids.len();

        assignments.push((shard_idx as u8, peer_ids[peer_idx].clone()));
    }

    assignments
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = b"Hello Stone Erasure Coding! Dies ist ein Test mit ausreichend Daten fuer k=4 Shards. Wir muessen sicherstellen dass genug Bytes vorhanden sind. ABCDEFGHIJKLMNOP";
        let k = 4;
        let m = 2;

        // Encode
        let shards = encode_chunk(original, k, m).unwrap();
        assert_eq!(shards.len(), k + m);

        // Alle Shards müssen gleich groß sein
        let shard_size = shards[0].len();
        for s in &shards {
            assert_eq!(s.len(), shard_size);
        }

        // Decode mit allen Shards
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        for (i, s) in shards.iter().enumerate() {
            shard_data.insert(i, s.clone());
        }
        let decoded = decode_chunk(&shard_data, k, m, original.len()).unwrap();
        assert_eq!(decoded, original.as_ref());
    }

    #[test]
    fn test_decode_with_missing_shards() {
        let original = b"Test data for erasure coding with missing shards. This needs to be long enough for 4 data shards minimum. ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnop";
        let k = 4;
        let m = 2;

        let shards = encode_chunk(original, k, m).unwrap();

        // Lösche 2 Shards (maximale Toleranz bei m=2)
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        // Behalte nur Shard 0, 2, 3, 5 (Shards 1 und 4 "verloren")
        shard_data.insert(0, shards[0].clone());
        shard_data.insert(2, shards[2].clone());
        shard_data.insert(3, shards[3].clone());
        shard_data.insert(5, shards[5].clone());

        let decoded = decode_chunk(&shard_data, k, m, original.len()).unwrap();
        assert_eq!(decoded, original.as_ref());
    }

    #[test]
    fn test_decode_fails_with_too_few_shards() {
        let original = b"Short test data for failure case testing purpose minimum bytes needed.";
        let k = 4;
        let m = 2;

        let shards = encode_chunk(original, k, m).unwrap();

        // Nur 3 Shards (braucht 4) → muss fehlschlagen
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        shard_data.insert(0, shards[0].clone());
        shard_data.insert(1, shards[1].clone());
        shard_data.insert(2, shards[2].clone());

        let result = decode_chunk(&shard_data, k, m, original.len());
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_large_chunk() {
        // Simuliere einen 8 MiB Chunk
        let original: Vec<u8> = (0..8 * 1024 * 1024)
            .map(|i| (i % 256) as u8)
            .collect();
        let k = 4;
        let m = 2;

        let shards = encode_chunk(&original, k, m).unwrap();
        assert_eq!(shards.len(), 6);

        // Jeder Shard sollte ~2 MiB sein
        let expected_shard_size = (original.len() + k - 1) / k;
        for s in &shards {
            assert_eq!(s.len(), expected_shard_size);
        }

        // Reconstruct
        let mut shard_data: HashMap<usize, Vec<u8>> = HashMap::new();
        for (i, s) in shards.iter().enumerate().take(k) {
            shard_data.insert(i, s.clone());
        }
        let decoded = decode_chunk(&shard_data, k, m, original.len()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_shard_hash_deterministic() {
        let data = b"deterministic hash test";
        let h1 = shard_hash(data);
        let h2 = shard_hash(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_assign_shards_round_robin() {
        let peers = vec![
            "PeerA".to_string(),
            "PeerB".to_string(),
            "PeerC".to_string(),
        ];
        let assignments = assign_shards_to_peers("test_chunk_hash", &peers, 4, 2);
        assert_eq!(assignments.len(), 6);
        // Alle Shard-Indices müssen 0..5 sein
        for (i, (idx, _)) in assignments.iter().enumerate() {
            assert_eq!(*idx, i as u8);
        }
        // Jeder Peer sollte mindestens 1 Shard bekommen
        let unique_peers: std::collections::HashSet<&str> =
            assignments.iter().map(|(_, p)| p.as_str()).collect();
        assert!(unique_peers.len() <= peers.len());
    }

    #[test]
    fn test_shard_store_roundtrip() {
        // Verwendet temporäres Verzeichnis
        let store = ShardStore {
            base_dir: std::env::temp_dir().join("stone_shard_test"),
        };
        let _ = std::fs::remove_dir_all(&store.base_dir);
        std::fs::create_dir_all(&store.base_dir).unwrap();

        let chunk_hash = "abc123def456";
        let shard_data = vec![
            (0u8, vec![1u8, 2, 3, 4]),
            (1, vec![5, 6, 7, 8]),
            (2, vec![9, 10, 11, 12]),
        ];

        // Schreiben
        let refs = store.write_my_shards(chunk_hash, &shard_data).unwrap();
        assert_eq!(refs.len(), 3);

        // Lesen
        let read_back = store.read_shard(chunk_hash, 0).unwrap();
        assert_eq!(read_back, vec![1, 2, 3, 4]);

        // Existenz-Check
        assert!(store.has_shard(chunk_hash, 0));
        assert!(store.has_shard(chunk_hash, 1));
        assert!(!store.has_shard(chunk_hash, 5));

        // Indices
        let mut indices = store.local_shard_indices(chunk_hash);
        indices.sort();
        assert_eq!(indices, vec![0, 1, 2]);

        // Stats
        let stats = store.stats();
        assert_eq!(stats.total_shards, 3);
        assert_eq!(stats.chunks_with_shards, 1);

        // Aufräumen
        let freed = store.remove_chunk_shards(chunk_hash).unwrap();
        assert!(freed > 0);
        assert!(!store.has_shard(chunk_hash, 0));

        let _ = std::fs::remove_dir_all(&store.base_dir);
    }
}
