//! Block list and get-by-index handlers.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

#[derive(Deserialize)]
pub struct PaginationQuery {
    #[serde(default)]
    pub page: Option<u64>,
    #[serde(default)]
    pub per_page: Option<u64>,
}

/// GET /api/v1/blocks
pub async fn handle_list_blocks(
    headers: HeaderMap,
    Query(q): Query<PaginationQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let chain = state.node.chain.lock().unwrap();
    let per_page = q.per_page.unwrap_or(50).min(500) as usize;
    let page = q.page.unwrap_or(0) as usize;
    let total = chain.blocks.len();
    let blocks: Vec<_> = chain
        .blocks
        .iter()
        .rev()
        .skip(page * per_page)
        .take(per_page)
        .collect();
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "blocks": blocks,
        })),
    ))
}

/// GET /api/v1/blocks/:index
pub async fn handle_get_block(
    headers: HeaderMap,
    Path(index): Path<u64>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let chain = state.node.chain.lock().unwrap();
    let block = chain.blocks.get(index as usize).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Block nicht gefunden"})),
        )
            .into_response()
    })?.clone();
    Ok((StatusCode::OK, axum::Json(block)))
}
