//! P2P network handlers.

use axum::{
    extract::{State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::super::auth_middleware::{require_admin, require_user};
use super::super::state::AppState;

/// GET /api/v1/p2p/peers
pub async fn handle_p2p_peers(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let peers = match &state.network {
        Some(h) => h.get_peers().await,
        None => vec![],
    };
    Ok(axum::Json(json!({ "peers": peers, "count": peers.len() })))
}

/// POST /api/v1/p2p/dial
pub async fn handle_p2p_dial(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let addr_str = body["addr"].as_str().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Feld 'addr' fehlt"})),
        )
            .into_response()
    })?;

    let addr = stone::network::parse_multiaddr(addr_str).map_err(|e| {
        (StatusCode::BAD_REQUEST, axum::Json(json!({"error": e}))).into_response()
    })?;

    match &state.network {
        Some(h) => {
            h.dial(addr).await;
            Ok(axum::Json(json!({ "ok": true, "addr": addr_str })))
        }
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "P2P nicht aktiv"})),
        )
            .into_response()),
    }
}

/// GET /api/v1/p2p/info
pub async fn handle_p2p_info(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_user(&headers, &state)?;
    let p2p_port: u16 = std::env::var("STONE_P2P_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(stone::network::DEFAULT_P2P_PORT);

    let (peer_id, local_addr) = match &state.network {
        Some(h) => (
            h.local_peer_id.clone(),
            stone::network::local_p2p_addr(p2p_port),
        ),
        None => (String::from("P2P deaktiviert"), None),
    };

    let psk_disabled = std::env::var("STONE_P2P_PSK_DISABLED").as_deref() == Ok("1");
    let psk_active = !psk_disabled;
    // Build a short fingerprint from the first 16 hex chars of the PSK secret
    let psk_fingerprint: Option<String> = if psk_active {
        stone::psk::export_psk_hex().map(|s| format!("sha256:{}…", &s[..16.min(s.len())]))
    } else {
        None
    };

    let listen_addrs: Vec<String> = match &state.network {
        Some(_) => {
            vec![local_addr.clone().unwrap_or_default()]
        }
        None => vec![],
    };

    Ok(axum::Json(json!({
        "peer_id":          peer_id,
        "p2p_addr":         local_addr,
        "p2p_port":         p2p_port,
        "p2p_active":       state.network.is_some(),
        "psk_active":       psk_active,
        "psk_fingerprint":  psk_fingerprint,
        "listen_addrs":     listen_addrs,
    })))
}

/// GET /api/v1/p2p/config
pub async fn handle_p2p_config(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let config = stone::network::P2pConfig::load_or_default();
    Ok(axum::Json(config))
}

/// GET /api/v1/p2p/status
pub async fn handle_p2p_status(State(state): State<AppState>) -> impl IntoResponse {
    let Some(net) = &state.network else {
        return axum::Json(json!({
            "p2p": "disabled",
            "connected_peers": 0,
            "total_known_peers": 0,
            "peers": []
        }))
        .into_response();
    };
    match net.get_status().await {
        Some(s) => axum::Json(json!({
            "local_peer_id":       s.local_peer_id,
            "connected_peers":     s.connected_peers,
            "total_known_peers":   s.total_known_peers,
            "gossipsub_mesh_size": s.gossipsub_mesh_size,
            "chain_block_count":   s.chain_block_count,
            "peers": s.peers.iter().map(|p| json!({
                "peer_id":         p.peer_id,
                "addresses":       p.addresses,
                "agent":           p.agent_version,
                "connected":       p.connected,
                "last_seen_ago_s": p.last_seen_ago_secs,
                "blocks_received": p.blocks_received,
                "in_mesh":         p.in_gossipsub_mesh,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "P2P-Task antwortet nicht"})),
        )
            .into_response(),
    }
}

/// POST /api/v1/p2p/ping/:peer_id
pub async fn handle_p2p_ping(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Path(peer_id_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let net = state.network.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "P2P nicht aktiv"})),
        )
            .into_response()
    })?;

    let peer_id = peer_id_str.parse::<libp2p::PeerId>().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(
                json!({"error": format!("Ungültige PeerId: {peer_id_str}")}),
            ),
        )
            .into_response()
    })?;

    let result = net.ping(peer_id).await;
    let status = if result.reachable {
        StatusCode::OK
    } else {
        StatusCode::REQUEST_TIMEOUT
    };
    Ok((
        status,
        axum::Json(json!({
            "peer_id":    result.peer_id,
            "reachable":  result.reachable,
            "latency_ms": result.latency_ms,
            "error":      result.error,
        })),
    ))
}
