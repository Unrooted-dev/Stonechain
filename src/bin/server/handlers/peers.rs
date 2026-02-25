//! HTTP-Peer and manual-sync handlers.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use stone::master_node::{AddPeerRequest, PeerInfo, PeerStatus};

use super::super::auth_middleware::require_admin;
use super::super::state::{save_peers, AppState};
use super::super::sync::pull_from_peer;

/// GET /api/v1/peers
pub async fn handle_list_peers(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    Ok((StatusCode::OK, axum::Json(state.node.get_peers())))
}

/// POST /api/v1/peers
pub async fn handle_add_peer(
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
pub async fn handle_remove_peer(
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

// ─── Manual sync ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SyncRequest {
    #[serde(default)]
    pub peer_url: Option<String>,
}

/// POST /api/v1/sync – Manuelle Synchronisation
pub async fn handle_sync(
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
