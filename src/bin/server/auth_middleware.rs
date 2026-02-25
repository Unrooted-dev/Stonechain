//! API-Key authentication helpers: extract_api_key, require_user, require_admin.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use stone::auth::User;

use super::state::AppState;

pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

pub fn resolve_user_by_key(
    key: &str,
    users: &Arc<Mutex<Vec<User>>>,
    admin_key: &str,
) -> Option<User> {
    if key == admin_key {
        return Some(User {
            id: "admin".into(),
            name: "admin".into(),
            api_key: key.to_string(),
            phrase_hash: String::new(),
            quota_bytes: u64::MAX,
        });
    }
    users
        .lock()
        .unwrap()
        .iter()
        .find(|u| u.api_key == key)
        .cloned()
}

pub fn require_user(headers: &HeaderMap, state: &AppState) -> Result<User, Response> {
    let key = extract_api_key(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "x-api-key Header fehlt"})),
        )
            .into_response()
    })?;
    resolve_user_by_key(&key, &state.users, &state.api_key).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "Ungültiger API-Key"})),
        )
            .into_response()
    })
}

pub fn require_admin(headers: &HeaderMap, state: &AppState) -> Result<(), Response> {
    let key = extract_api_key(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "x-api-key Header fehlt"})),
        )
            .into_response()
    })?;
    if key == state.api_key.as_str() {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Admin-Rechte erforderlich"})),
        )
            .into_response())
    }
}
