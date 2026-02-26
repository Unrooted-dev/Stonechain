//! Web-of-Trust handlers
//!
//! Implements decentralised node-join approval:
//!
//!   POST  /api/v1/trust/request          – New node submits join request
//!   GET   /api/v1/trust/pending          – List open requests (admin)
//!   GET   /api/v1/trust/registry         – Full registry (admin)
//!   POST  /api/v1/trust/approve/:peer_id – Vote to approve (admin/validator)
//!   POST  /api/v1/trust/revoke/:peer_id  – Vote to revoke (admin/validator)
//!   GET   /api/v1/trust/history          – Audit log (admin)
//!   GET   /api/v1/trust/check/:peer_id   – Check trust status (no auth)

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use stone::master_node::TrustStatus;

use super::super::auth_middleware::require_admin;
use super::super::state::{save_trust, AppState};

// ─── Request Bodies ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TrustRequestBody {
    /// libp2p PeerId (or any canonical node identifier)
    pub peer_id: String,
    /// Ed25519 public key, hex-encoded
    pub public_key_hex: String,
    /// Optional human-readable name
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TrustVoteBody {
    /// The peer_id of the voting node (must match authenticated node)
    pub voter_peer_id: String,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/v1/trust/request
///
/// A new node submits a join request. No auth required — the request is
/// placed in Pending state and must be approved by a majority of active
/// validators.
pub async fn handle_trust_request(
    State(state): State<AppState>,
    axum::Json(body): axum::Json<TrustRequestBody>,
) -> impl IntoResponse {
    if body.peer_id.trim().is_empty() || body.public_key_hex.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "peer_id and public_key_hex are required"})),
        );
    }

    match state
        .node
        .trust_request(body.peer_id.clone(), body.public_key_hex, body.name)
    {
        Ok(()) => {
            save_trust(&state);
            (
                StatusCode::CREATED,
                axum::Json(json!({
                    "ok": true,
                    "peer_id": body.peer_id,
                    "status": "pending",
                    "message": "Join request submitted. Awaiting validator approval."
                })),
            )
        }
        Err(e) => (
            StatusCode::CONFLICT,
            axum::Json(json!({"error": e})),
        ),
    }
}

/// GET /api/v1/trust/pending
///
/// List all open (Pending) trust requests. Requires admin auth.
pub async fn handle_trust_pending(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let pending = state.node.trust_pending();
    Ok((StatusCode::OK, axum::Json(pending)))
}

/// GET /api/v1/trust/registry
///
/// Full trust registry (all statuses). Requires admin auth.
pub async fn handle_trust_registry(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let registry = state.node.trust_registry.read().unwrap().clone();
    Ok((StatusCode::OK, axum::Json(registry)))
}

/// POST /api/v1/trust/approve/:peer_id
///
/// Cast an approval vote for a pending (or revoked) node.
/// The voter's peer_id must be provided in the request body.
/// Requires admin auth.
pub async fn handle_trust_approve(
    headers: HeaderMap,
    Path(peer_id): Path<String>,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<TrustVoteBody>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    match state.node.trust_vote(&body.voter_peer_id, &peer_id, true) {
        Ok(new_status) => {
            save_trust(&state);
            let status_str = match new_status {
                TrustStatus::Active => "active",
                TrustStatus::Pending => "pending",
                TrustStatus::Revoked => "revoked",
            };
            Ok((
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "peer_id": peer_id,
                    "status": status_str,
                    "voter": body.voter_peer_id,
                })),
            ))
        }
        Err(e) => Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": e})),
        )
            .into_response()),
    }
}

/// POST /api/v1/trust/revoke/:peer_id
///
/// Cast a revocation vote against a trusted or pending node.
/// Requires admin auth.
pub async fn handle_trust_revoke(
    headers: HeaderMap,
    Path(peer_id): Path<String>,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<TrustVoteBody>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    match state.node.trust_vote(&body.voter_peer_id, &peer_id, false) {
        Ok(new_status) => {
            save_trust(&state);
            let status_str = match new_status {
                TrustStatus::Active => "active",
                TrustStatus::Pending => "pending",
                TrustStatus::Revoked => "revoked",
            };
            Ok((
                StatusCode::OK,
                axum::Json(json!({
                    "ok": true,
                    "peer_id": peer_id,
                    "status": status_str,
                    "voter": body.voter_peer_id,
                    "message": if new_status == TrustStatus::Revoked {
                        "Node has been revoked by majority vote."
                    } else {
                        "Revocation vote recorded."
                    },
                })),
            ))
        }
        Err(e) => Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": e})),
        )
            .into_response()),
    }
}

/// GET /api/v1/trust/history
///
/// Returns the full vote audit log. Requires admin auth.
pub async fn handle_trust_history(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let history = state.node.trust_history_snapshot();
    Ok((StatusCode::OK, axum::Json(history)))
}

/// GET /api/v1/trust/check/:peer_id
///
/// Quick trust check — no auth required.
/// Returns {"trusted": true/false, "status": "active"|"pending"|"revoked"|"unknown"}
pub async fn handle_trust_check(
    Path(peer_id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let registry = state.node.trust_registry.read().unwrap();
    match registry.iter().find(|e| e.peer_id == peer_id) {
        Some(entry) => {
            let status_str = match entry.status {
                TrustStatus::Active => "active",
                TrustStatus::Pending => "pending",
                TrustStatus::Revoked => "revoked",
            };
            (
                StatusCode::OK,
                axum::Json(json!({
                    "peer_id": peer_id,
                    "trusted": entry.status == TrustStatus::Active,
                    "status": status_str,
                    "name": entry.name,
                    "votes_approve": entry.votes_approve.len(),
                    "votes_reject": entry.votes_reject.len(),
                    "requested_at": entry.requested_at,
                    "decided_at": entry.decided_at,
                })),
            )
        }
        None => (
            StatusCode::OK,
            axum::Json(json!({
                "peer_id": peer_id,
                "trusted": false,
                "status": "unknown",
            })),
        ),
    }
}
