//! Router assembly and CORS configuration.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::Method,
    routing::{delete, get, post},
};
use tower_http::cors::{Any, CorsLayer};

use super::state::{AppState, MAX_UPLOAD_BYTES};
use super::handlers::{
    auth::{handle_login, handle_signup, handle_sync_users},
    blocks::{handle_get_block, handle_list_blocks},
    chunks::handle_get_chunk,
    documents::{
        handle_delete_document, handle_document_history, handle_get_document,
        handle_get_document_data, handle_list_documents, handle_list_user_documents,
        handle_patch_document, handle_search_documents, handle_transfer_document,
        handle_upload_document,
    },
    p2p::{
        handle_p2p_config, handle_p2p_dial, handle_p2p_info, handle_p2p_peers,
        handle_p2p_ping, handle_p2p_status,
    },
    peers::{handle_add_peer, handle_list_peers, handle_remove_peer, handle_sync},
    poa::{
        handle_add_validator, handle_cast_vote, handle_consensus_status,
        handle_detect_forks, handle_list_validators, handle_remove_validator,
        handle_resolve_fork, handle_set_validator_active, handle_validator_self,
    },
    status::{handle_health, handle_info, handle_metrics, handle_network_stats, handle_shard_health, handle_status, handle_verify},
    trust::{
        handle_trust_approve, handle_trust_check, handle_trust_history,
        handle_trust_pending, handle_trust_registry, handle_trust_request,
        handle_trust_revoke,
    },
    users::{handle_delete_user, handle_list_users},
    ws::handle_websocket,
};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Health (kein Auth)
        .route("/api/v1/health", get(handle_health))
        // Öffentliche Node-Info (kein Auth, für Peer-Discovery)
        .route("/api/v1/info", get(handle_info))
        // Status & Metriken (Admin)
        .route("/api/v1/status", get(handle_status))
        .route("/api/v1/metrics", get(handle_metrics))
        .route("/api/v1/network", get(handle_network_stats))
        .route("/api/v1/chain/verify", get(handle_verify))
        // Shard-Health (Erasure Coding Monitoring)
        .route("/api/v1/shards/health", get(handle_shard_health))
        // Blöcke (Admin)
        .route("/api/v1/blocks", get(handle_list_blocks))
        .route("/api/v1/blocks/:index", get(handle_get_block))
        // Dokumente
        .route(
            "/api/v1/documents",
            get(handle_list_documents).post(handle_upload_document),
        )
        // Suche (vor /:doc_id, damit /search nicht als doc_id geparst wird)
        .route("/api/v1/documents/search", get(handle_search_documents))
        .route(
            "/api/v1/documents/user/:user_id",
            get(handle_list_user_documents),
        )
        .route(
            "/api/v1/documents/:doc_id",
            get(handle_get_document).patch(handle_patch_document),
        )
        .route(
            "/api/v1/documents/:doc_id/delete",
            post(handle_delete_document),
        )
        .route(
            "/api/v1/documents/:doc_id/history",
            get(handle_document_history),
        )
        .route(
            "/api/v1/documents/:doc_id/transfer",
            post(handle_transfer_document),
        )
        .route(
            "/api/v1/documents/:doc_id/data",
            get(handle_get_document_data),
        )
        .route(
            "/api/v1/documents/:doc_id/download",
            get(handle_get_document_data),
        )
        // Chunk-API für Peer-Sync
        .route("/api/v1/chunk/:hash", get(handle_get_chunk))
        // Peers (Admin)
        .route(
            "/api/v1/peers",
            get(handle_list_peers).post(handle_add_peer),
        )
        .route("/api/v1/peers/:idx", delete(handle_remove_peer))
        // Sync (Admin)
        .route("/api/v1/sync", post(handle_sync))
        // P2P-Netzwerk
        .route("/api/v1/p2p/peers", get(handle_p2p_peers))
        .route("/api/v1/p2p/status", get(handle_p2p_status))
        .route("/api/v1/p2p/ping/:peer_id", post(handle_p2p_ping))
        .route("/api/v1/p2p/dial", post(handle_p2p_dial))
        .route("/api/v1/p2p/info", get(handle_p2p_info))
        .route("/api/v1/p2p/config", get(handle_p2p_config))
        // Nutzer (Admin)
        .route("/api/v1/users", get(handle_list_users))
        .route("/api/v1/users/:user_id", delete(handle_delete_user))
        // Auth
        .route("/api/v1/auth/signup", post(handle_signup))
        .route("/api/v1/auth/login", post(handle_login))
        // Admin: User-Sync zwischen Nodes
        .route("/api/v1/admin/sync-users", post(handle_sync_users))
        // PoA: Validators
        .route(
            "/api/v1/validators",
            get(handle_list_validators).post(handle_add_validator),
        )
        .route("/api/v1/validators/self", get(handle_validator_self))
        .route(
            "/api/v1/validators/:node_id",
            delete(handle_remove_validator),
        )
        .route(
            "/api/v1/validators/:node_id/activate",
            post(handle_set_validator_active),
        )
        // PoA: Consensus Voting
        .route("/api/v1/consensus/status", get(handle_consensus_status))
        .route("/api/v1/consensus/vote", post(handle_cast_vote))
        // Fork-Erkennung
        .route("/api/v1/forks", get(handle_detect_forks))
        .route("/api/v1/forks/resolve", post(handle_resolve_fork))
        // WebSocket
        .route("/ws", get(handle_websocket))
        // ─── Web-of-Trust ────────────────────────────────────────────────────
        // Join-Anfrage (kein Auth – neue Node meldet sich an)
        .route("/api/v1/trust/request", post(handle_trust_request))
        // Trust-Check (kein Auth – öffentlich abfragbar)
        .route("/api/v1/trust/check/:peer_id", get(handle_trust_check))
        // Admin-Endpunkte
        .route("/api/v1/trust/pending", get(handle_trust_pending))
        .route("/api/v1/trust/registry", get(handle_trust_registry))
        .route("/api/v1/trust/approve/:peer_id", post(handle_trust_approve))
        .route("/api/v1/trust/revoke/:peer_id", post(handle_trust_revoke))
        .route("/api/v1/trust/history", get(handle_trust_history))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES))
        .layer(build_cors())
        .with_state(state)
}

pub fn build_cors() -> CorsLayer {
    let allowed_origins: Vec<axum::http::HeaderValue> =
        std::env::var("STONE_CORS_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .filter_map(|s| s.trim().parse().ok())
            .collect();

    if allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::DELETE,
                Method::PATCH,
                Method::OPTIONS,
            ])
            .allow_headers(Any)
    } else {
        CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list(allowed_origins))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::DELETE,
                Method::PATCH,
                Method::OPTIONS,
            ])
            .allow_headers(Any)
    }
}
