//! User management handlers.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use stone::auth::save_users;

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

#[derive(Deserialize)]
pub struct UserQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub page: Option<usize>,
    #[serde(default)]
    pub per_page: Option<usize>,
}

/// GET /api/v1/users – Alle Nutzer mit Quota-Info (Admin)
pub async fn handle_list_users(
    headers: HeaderMap,
    Query(q): Query<UserQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let users = state.users.lock().unwrap().clone();
    let chain = state.node.chain.lock().unwrap();

    let search = q.q.as_deref().unwrap_or("").to_lowercase();
    let per_page = q.per_page.unwrap_or(50).min(500);
    let page = q.page.unwrap_or(0);

    let mut result: Vec<serde_json::Value> = users
        .iter()
        .filter(|u| {
            if search.is_empty() {
                return true;
            }
            u.name.to_lowercase().contains(&search) || u.id.to_lowercase().contains(&search)
        })
        .map(|u| {
            let used = chain.user_usage_bytes(&u.id);
            json!({
                "id": u.id,
                "name": u.name,
                "quota_bytes": u.quota_bytes,
                "used_bytes": used,
                "quota_pct": if u.quota_bytes == 0 || u.quota_bytes == u64::MAX { 0.0 } else {
                    used as f64 / u.quota_bytes as f64 * 100.0
                },
                "document_count": chain.list_documents_for_user(&u.id).len(),
            })
        })
        .collect();

    result.sort_by(|a, b| {
        let da = a["document_count"].as_u64().unwrap_or(0);
        let db = b["document_count"].as_u64().unwrap_or(0);
        db.cmp(&da)
    });

    let total = result.len();
    let paginated: Vec<_> = result
        .into_iter()
        .skip(page * per_page)
        .take(per_page)
        .collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "users": paginated,
        })),
    ))
}

/// DELETE /api/v1/users/:user_id – Nutzer löschen (Admin)
pub async fn handle_delete_user(
    headers: HeaderMap,
    Path(user_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    if user_id == "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Admin-Konto kann nicht gelöscht werden"})),
        )
            .into_response());
    }

    let mut users = state.users.lock().unwrap();
    let before = users.len();
    users.retain(|u| u.id != user_id);
    if users.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Nutzer nicht gefunden"})),
        )
            .into_response());
    }
    save_users(&users);
    drop(users);

    Ok((
        StatusCode::OK,
        axum::Json(json!({"message": format!("Nutzer {user_id} gelöscht")})),
    ))
}
