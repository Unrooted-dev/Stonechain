//! Peer synchronisation logic: pull_from_peer, pull_users_from_peer,
//! fetch_missing_chunks, spawn_auto_sync_task.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use stone::{
    auth::{save_users, User},
    master_node::{MasterNodeState, NodeEvent, PeerStatus},
    storage::ChunkStore,
};

use super::state::AUTO_SYNC_INTERVAL;

pub async fn pull_from_peer(node: &Arc<MasterNodeState>, peer_url: &str, api_key: &str) {
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

    node.metrics.sync_runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        node.metrics.sync_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    }

    // Blöcke abrufen
    let blocks_url = format!(
        "{}/api/v1/blocks?per_page=500",
        peer_url.trim_end_matches('/')
    );
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
            node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
    };

    let val: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[sync] {peer_url} parse error: {e}");
            node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
    };

    let mut blocks: Vec<stone::blockchain::Block> = match val
        .get("blocks")
        .and_then(|b| serde_json::from_value(b.clone()).ok())
    {
        Some(b) => b,
        None => {
            eprintln!("[sync] {peer_url}: Kein 'blocks' Feld");
            node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
    };

    // Aufsteigend nach Index sortieren
    blocks.sort_by_key(|b| b.index);

    let mut added = 0u64;

    // Hash-Integrität aller Peer-Blöcke prüfen
    let blocks: Vec<_> = blocks
        .into_iter()
        .filter(|b| stone::blockchain::calculate_hash(b) == b.hash)
        .collect();

    // Fork-Erkennung + Rollback
    let (pending_blocks, did_rollback) = {
        let mut chain = node.chain.lock().unwrap();
        let local_len = chain.blocks.len() as u64;
        let local_gen_hash = chain
            .blocks
            .first()
            .map(|b| b.hash.clone())
            .unwrap_or_default();

        if let Some(peer_gen) = blocks.first() {
            if !local_gen_hash.is_empty() && local_gen_hash != peer_gen.hash {
                eprintln!("[sync] {peer_url}: Genesis-Mismatch – inkompatibler Peer");
                node.metrics.sync_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        }

        let mut fork_at: Option<usize> = None;
        for peer_block in &blocks {
            let idx = peer_block.index as usize;
            if idx < chain.blocks.len() && chain.blocks[idx].hash != peer_block.hash {
                fork_at = Some(idx);
                break;
            }
        }

        let did_rollback = if let Some(fork_idx) = fork_at {
            let peer_len = blocks.len() as u64;
            if peer_len >= local_len {
                eprintln!(
                    "[sync] {peer_url}: Fork bei Index {fork_idx} erkannt – \
                     Peer-Chain ({peer_len} Blöcke) >= lokal ({local_len}) → Rollback & Übernahme"
                );
                chain.blocks.truncate(fork_idx);
                chain.latest_hash = chain
                    .blocks
                    .last()
                    .map(|b| b.hash.clone())
                    .unwrap_or_default();
                chain.persist_all();
                true
            } else {
                eprintln!(
                    "[sync] {peer_url}: Fork bei Index {fork_idx} – \
                     unsere Chain ({local_len}) > Peer ({peer_len}) → behalte lokale Chain"
                );
                false
            }
        } else {
            false
        };

        let cur_len = chain.blocks.len() as u64;
        let pending: Vec<stone::blockchain::Block> =
            blocks.into_iter().filter(|b| b.index >= cur_len).collect();

        (pending, did_rollback)
    };

    if did_rollback {
        eprintln!(
            "[sync] {peer_url}: Rollback abgeschlossen, übernehme {} neue Blöcke",
            pending_blocks.len()
        );
    }

    // Chunks laden
    let chunk_store = ChunkStore::new().unwrap_or_default();
    for block in &pending_blocks {
        for doc in &block.documents {
            for ch in &doc.chunks {
                if chunk_store.has_chunk(&ch.hash) {
                    continue;
                }
                let chunk_url = format!(
                    "{}/api/v1/chunk/{}",
                    peer_url.trim_end_matches('/'),
                    ch.hash
                );
                match client
                    .get(&chunk_url)
                    .header("x-api-key", api_key)
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(bytes) = r.bytes().await {
                            let _ = chunk_store.write_chunk(&bytes);
                            println!("[sync] ✓ Chunk {} von {peer_url} geholt", &ch.hash[..8]);
                        }
                    }
                    Ok(r) => eprintln!("[sync] Chunk {} – HTTP {}", &ch.hash[..8], r.status()),
                    Err(e) => eprintln!("[sync] Chunk {} – Fehler: {e}", &ch.hash[..8]),
                }
            }
        }
    }

    // Blöcke in Chain eintragen
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
    node.metrics.sync_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Holt fehlende Chunks für einen empfangenen Peer-Block via HTTP.
pub async fn fetch_missing_chunks(
    block: &stone::blockchain::Block,
    peer_base_url: &str,
    _api_key: &str,
) {
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
            if chunk_store.read_chunk(&chunk_ref.hash).is_ok() {
                continue;
            }
            let url = format!(
                "{}/api/v1/chunk/{}",
                peer_base_url.trim_end_matches('/'),
                chunk_ref.hash
            );
            match client
                .get(&url)
                .header("x-node-request", "internal")
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.bytes().await {
                        Ok(bytes) => {
                            match chunk_store.write_chunk(&bytes) {
                                Ok(written_hash) if written_hash == chunk_ref.hash => {
                                    println!(
                                        "[sync] ✓ Chunk {} von {peer_base_url} geholt",
                                        &chunk_ref.hash[..8]
                                    );
                                }
                                Ok(written_hash) => {
                                    eprintln!(
                                        "[sync] Chunk-Hash-Mismatch: erwartet {}, bekommen {}",
                                        &chunk_ref.hash[..8],
                                        &written_hash[..8]
                                    );
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[sync] Chunk {} speichern fehlgeschlagen: {e}",
                                        &chunk_ref.hash[..8]
                                    );
                                }
                            }
                        }
                        Err(e) => eprintln!(
                            "[sync] Chunk {} lesen fehlgeschlagen: {e}",
                            &chunk_ref.hash[..8]
                        ),
                    }
                }
                Ok(resp) => {
                    eprintln!(
                        "[sync] Chunk {} – HTTP {}",
                        &chunk_ref.hash[..8],
                        resp.status()
                    );
                }
                Err(e) => {
                    eprintln!("[sync] Chunk {} – Fehler: {e}", &chunk_ref.hash[..8]);
                }
            }
        }
    }
}

pub fn spawn_auto_sync_task(
    node: Arc<MasterNodeState>,
    api_key: Arc<String>,
    users: Arc<Mutex<Vec<User>>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(AUTO_SYNC_INTERVAL);
        loop {
            interval.tick().await;
            let peers = node.get_peers();
            for peer in peers {
                pull_from_peer(&node, &peer.url, &api_key).await;
                pull_users_from_peer(&peer.url, &api_key, &users).await;
            }
        }
    });
}

/// Holt die Nutzerliste von einem Peer und merged sie lokal.
pub async fn pull_users_from_peer(
    peer_url: &str,
    api_key: &str,
    users: &Arc<Mutex<Vec<User>>>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL")
                .map(|v| v == "1")
                .unwrap_or(false),
        )
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let url = format!("{}/api/v1/users", peer_url.trim_end_matches('/'));
    let resp = match client
        .get(&url)
        .header("x-api-key", api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return,
    };

    if !resp.status().is_success() {
        return;
    }

    let remote_users: Vec<User> = match resp.json().await {
        Ok(u) => u,
        Err(_) => return,
    };

    let mut local = users.lock().unwrap();
    let mut added = 0usize;
    for ru in &remote_users {
        if !local.iter().any(|u| u.id == ru.id) {
            local.push(ru.clone());
            added += 1;
        }
    }
    if added > 0 {
        save_users(&local);
        println!("[sync] {added} neue Nutzer von {peer_url} übernommen");
    }
}

/// Meldet die eigene öffentliche URL (STONE_PUBLIC_URL) an alle bekannten Peers.
///
/// Wird nach dem Tunnel-Start aufgerufen damit Peers sofort die neue URL kennen.
/// Peers speichern die URL über `POST /api/v1/peers` — alte Einträge werden überschrieben.
pub async fn announce_public_url(node: Arc<MasterNodeState>, api_key: Arc<String>) {
    let public_url = match std::env::var("STONE_PUBLIC_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => return, // Kein Tunnel aktiv → nichts zu melden
    };

    let node_id = node.node_id.clone();
    let peers = node.get_peers();

    if peers.is_empty() {
        println!("[tunnel] Keine Peers bekannt – URL-Announcement übersprungen.");
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(
            std::env::var("STONE_INSECURE_SSL")
                .map(|v| v == "1")
                .unwrap_or(false),
        )
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    println!(
        "[tunnel] Melde öffentliche URL an {} Peer(s): {}",
        peers.len(),
        public_url
    );

    for peer in &peers {
        let url = format!("{}/api/v1/peers", peer.url.trim_end_matches('/'));
        let body = serde_json::json!({
            "url":  public_url,
            "name": node_id,
        });
        match client
            .post(&url)
            .header("x-api-key", api_key.as_str())
            .json(&body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                println!("[tunnel] ✓ URL gemeldet an {}", peer.url);
            }
            Ok(r) => {
                eprintln!("[tunnel] {} – HTTP {} beim URL-Announcement", peer.url, r.status());
            }
            Err(e) => {
                eprintln!("[tunnel] {} – Fehler beim URL-Announcement: {e}", peer.url);
            }
        }
    }
}
