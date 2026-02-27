//! Status, health, metrics, network, and chain-verify handlers.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use stone::master_node::NodeStatusResponse;

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

/// GET /api/v1/health – Kein Auth erforderlich
pub async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
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

/// GET /api/v1/info — Öffentliche Node-Info (kein Auth), für Peer-Discovery
pub async fn handle_info(State(state): State<AppState>) -> impl IntoResponse {
    let summary = state.node.chain_summary();
    (
        StatusCode::OK,
        axum::Json(json!({
            "node_id":    state.node.node_id,
            "role":       format!("{:?}", state.node.role),
            "block_height": summary.block_height,
        })),
    )
}

/// GET /api/v1/status – Vollständiger Node-Status (Admin)
pub async fn handle_status(
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
        trust: state.node.trust_summary(),
    };
    Ok((StatusCode::OK, axum::Json(resp)))
}

/// GET /api/v1/metrics
pub async fn handle_metrics(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    Ok((StatusCode::OK, axum::Json(state.node.snapshot_metrics())))
}

/// GET /api/v1/network — P2P-Netzwerkstatus + Server-Ressourcen
pub async fn handle_network_stats(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

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

    let uptime_secs = (chrono::Utc::now().timestamp() - state.node.started_at) as u64;

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
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        { 0 }
    };

    let cpu_time_ms: u64 = {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/self/stat")
                .unwrap_or_default()
                .split_whitespace()
                .enumerate()
                .filter(|(i, _)| *i == 13 || *i == 14)
                .map(|(_, v)| v.parse::<u64>().unwrap_or(0))
                .sum::<u64>() * 10
        }
        #[cfg(not(any(target_os = "linux")))]
        { 0 }
    };

    let data_dir_bytes: u64 = {
        fn dir_size(path: &std::path::Path) -> u64 {
            std::fs::read_dir(path)
                .map(|e| {
                    e.filter_map(|e| e.ok())
                        .map(|e| {
                            let meta = e.metadata().ok();
                            if meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) {
                                dir_size(&e.path())
                            } else {
                                meta.map(|m| m.len()).unwrap_or(0)
                            }
                        })
                        .sum()
                })
                .unwrap_or(0)
        }
        dir_size(std::path::Path::new(&stone::blockchain::data_dir()))
    };

    let m = state.node.snapshot_metrics();
    let block_count = {
        let chain = state.node.chain.lock().unwrap();
        chain.blocks.len() as u64
    };

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
            "blocks":           block_count,
            "requests_total":   m.requests_total,
            "sync_runs":        m.sync_runs,
            "sync_success":     m.sync_success,
            "sync_failure":     m.sync_failure,
            "docs_uploaded":    m.documents_uploaded,
            "ws_connections":   m.ws_connections,
        }
    }))))
}

pub fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// GET /api/v1/chain/verify
pub async fn handle_verify(
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

/// GET /api/v1/shards/health — Erasure-Coding Shard-Gesundheitsübersicht
pub async fn handle_shard_health(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    // 1. Lokale Shard-Statistik vom Dateisystem
    let local_stats = match stone::shard::ShardStore::new() {
        Ok(store) => {
            let s = store.stats();
            json!({
                "total_shards":       s.total_shards,
                "total_bytes":        s.total_bytes,
                "chunks_with_shards": s.chunks_with_shards,
            })
        }
        Err(_) => json!({
            "total_shards": 0,
            "total_bytes": 0,
            "chunks_with_shards": 0,
        }),
    };

    // 2. Aus der Blockchain: alle Dokumente mit EC-Shards analysieren
    let chain = state.node.chain.lock().unwrap();
    let mut total_docs_ec = 0u64;
    let mut total_chunks_ec = 0u64;
    let mut total_shards_blockchain = 0u64;
    let mut total_data_bytes = 0u64;
    let mut healthy_chunks = 0u64;
    let mut degraded_chunks = 0u64;
    let mut critical_chunks = 0u64;
    let mut doc_details: Vec<serde_json::Value> = Vec::new();

    // ShardStore für lokale Prüfung
    let shard_store = stone::shard::ShardStore::new().ok();

    for block in &chain.blocks {
        for doc in &block.documents {
            let ec_chunks: Vec<_> = doc.chunks.iter().filter(|c| !c.shards.is_empty()).collect();
            if ec_chunks.is_empty() {
                continue;
            }
            total_docs_ec += 1;

            let mut doc_healthy = 0u64;
            let mut doc_degraded = 0u64;
            let mut doc_critical = 0u64;

            for chunk in &ec_chunks {
                total_chunks_ec += 1;
                total_shards_blockchain += chunk.shards.len() as u64;
                total_data_bytes += chunk.size;

                let k = chunk.ec_k as u64;

                // Lokale Shard-Verfügbarkeit prüfen
                let local_count = if let Some(ref store) = shard_store {
                    store.local_shard_indices(&chunk.hash).len() as u64
                } else {
                    0
                };

                // Holders zählen (unique Nodes mit Shards)
                let holder_count = chunk.shards.iter()
                    .filter(|s| !s.holder.is_empty())
                    .count() as u64;

                // Gesundheits-Bewertung:
                //   healthy:  >= k Shards lokal ODER holder >= k
                //   degraded: einige Shards fehlen, aber k erreichbar
                //   critical: weniger als k Shards bekannt
                if local_count >= k || holder_count >= k {
                    healthy_chunks += 1;
                    doc_healthy += 1;
                } else if local_count + holder_count >= k {
                    degraded_chunks += 1;
                    doc_degraded += 1;
                } else {
                    critical_chunks += 1;
                    doc_critical += 1;
                }
            }

            // Status des gesamten Dokuments
            let doc_status = if doc_critical > 0 {
                "critical"
            } else if doc_degraded > 0 {
                "degraded"
            } else {
                "healthy"
            };

            doc_details.push(json!({
                "doc_id":    &doc.doc_id,
                "title":     &doc.title,
                "chunks":    ec_chunks.len(),
                "ec_k":      ec_chunks.first().map(|c| c.ec_k).unwrap_or(0),
                "ec_m":      ec_chunks.first().map(|c| c.ec_m).unwrap_or(0),
                "status":    doc_status,
                "healthy":   doc_healthy,
                "degraded":  doc_degraded,
                "critical":  doc_critical,
                "size":      doc.chunks.iter().map(|c| c.size).sum::<u64>(),
            }));
        }
    }

    // Gesamtstatus
    let overall_status = if critical_chunks > 0 {
        "critical"
    } else if degraded_chunks > 0 {
        "degraded"
    } else if total_chunks_ec > 0 {
        "healthy"
    } else {
        "no_ec_data"
    };

    Ok((StatusCode::OK, axum::Json(json!({
        "status": overall_status,
        "local_store": local_stats,
        "blockchain": {
            "ec_documents":       total_docs_ec,
            "ec_chunks":          total_chunks_ec,
            "total_shards":       total_shards_blockchain,
            "total_data_bytes":   total_data_bytes,
            "healthy_chunks":     healthy_chunks,
            "degraded_chunks":    degraded_chunks,
            "critical_chunks":    critical_chunks,
        },
        "documents": doc_details,
    }))))
}
