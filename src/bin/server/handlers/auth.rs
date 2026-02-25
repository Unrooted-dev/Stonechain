//! Auth handlers: signup, login, sync-users, push_user_to_peers.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use stone::{
    auth::{create_user_with_phrase, resolve_phrase, save_users, User},
    master_node::PeerInfo,
};

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

#[derive(Deserialize)]
pub struct SignupRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct LoginPhraseRequest {
    pub phrase: String,
}

/// POST /api/v1/auth/signup
pub async fn handle_signup(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<SignupRequest>,
) -> impl IntoResponse {
    if req.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Name darf nicht leer sein"})),
        );
    }
    let (id, new_user, phrase) = {
        let mut users = state.users.lock().unwrap();
        let id = format!("user-{}", users.len() + 1);
        let (mut user, phrase) = create_user_with_phrase(req.name.trim());
        user.id = id.clone();
        users.push(user.clone());
        save_users(&users);
        (id, user, phrase)
    };

    let peers = state.node.get_peers();
    let api_key = state.api_key.clone();
    let push_user = new_user.clone();
    tokio::spawn(async move {
        push_user_to_peers(&push_user, &peers, &api_key).await;
    });

    (
        StatusCode::CREATED,
        axum::Json(json!({
            "id": id,
            "name": new_user.name,
            "api_key": new_user.api_key,
            "phrase": phrase,
            "message": "Bitte die Phrase sicher aufbewahren – sie wird nur einmal angezeigt.",
        })),
    )
}

/// POST /api/v1/admin/sync-users  (Admin-Key erforderlich)
pub async fn handle_sync_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(incoming): axum::Json<Vec<User>>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&headers, &state) {
        return e;
    }
    let mut users = state.users.lock().unwrap();
    let mut added = 0usize;
    let mut updated = 0usize;
    for inc in &incoming {
        if let Some(existing) = users.iter_mut().find(|u| u.id == inc.id) {
            if existing.api_key != inc.api_key || existing.name != inc.name {
                *existing = inc.clone();
                updated += 1;
            }
        } else {
            users.push(inc.clone());
            added += 1;
        }
    }
    if added > 0 || updated > 0 {
        save_users(&users);
    }
    (
        StatusCode::OK,
        axum::Json(json!({ "ok": true, "added": added, "updated": updated })),
    )
    .into_response()
}

/// Pusht einen einzelnen Nutzer an alle bekannten HTTP-Peers.
pub async fn push_user_to_peers(user: &User, peers: &[PeerInfo], api_key: &str) {
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
    for peer in peers {
        let url = format!("{}/api/v1/admin/sync-users", peer.url.trim_end_matches('/'));
        match client
            .post(&url)
            .header("x-api-key", api_key)
            .json(&vec![user])
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                println!("[auth] Nutzer '{}' an Peer {} gepusht", user.name, peer.url);
            }
            Ok(r) => {
                eprintln!("[auth] Peer {} sync-users: HTTP {}", peer.url, r.status());
            }
            Err(e) => {
                eprintln!("[auth] Peer {} nicht erreichbar: {e}", peer.url);
            }
        }
    }
}

/// POST /api/v1/auth/login
pub async fn handle_login(
    State(state): State<AppState>,
    axum::Json(req): axum::Json<LoginPhraseRequest>,
) -> impl IntoResponse {
    let Some(hash) = resolve_phrase(&req.phrase) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Ungültige Wiederherstellungs-Phrase"})),
        );
    };
    let users = state.users.lock().unwrap();
    if let Some(user) = users.iter().find(|u| u.phrase_hash == hash).cloned() {
        return (
            StatusCode::OK,
            axum::Json(json!({
                "id": user.id,
                "name": user.name,
                "api_key": user.api_key,
            })),
        );
    }
    drop(users);
    (
        StatusCode::NOT_FOUND,
        axum::Json(
            json!({"error": "Phrase nicht bekannt – bitte zuerst registrieren"}),
        ),
    )
}
