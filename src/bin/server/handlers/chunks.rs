//! Chunk-get handler (used in peer sync).

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use stone::storage::ChunkStore;

use super::super::auth_middleware::require_user;
use super::super::state::AppState;

/// GET /api/v1/chunk/:hash – Chunk-Daten abrufen (für Peer-Sync)
pub async fn handle_get_chunk(
    headers: HeaderMap,
    Path(hash): Path<String>,
    State(state): State<AppState>,
) -> Result<Response, Response> {
    let is_internal = headers
        .get("x-node-request")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "internal")
        .unwrap_or(false);

    if !is_internal {
        require_user(&headers, &state)?;
    }

    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültiger Chunk-Hash"})),
        )
            .into_response());
    }

    let chunk_store = ChunkStore::new().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "ChunkStore nicht verfügbar"})),
        )
            .into_response()
    })?;
    let bytes = chunk_store.read_chunk(&hash).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Chunk nicht gefunden"})),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes))
        .unwrap())
}
