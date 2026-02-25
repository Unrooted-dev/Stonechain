//! WebSocket event-stream handler.

use axum::{
    extract::{State, WebSocketUpgrade},
    extract::ws::{Message, WebSocket},
    response::IntoResponse,
};
use std::{sync::Arc, sync::atomic::Ordering};
use stone::master_node::{MasterNodeState, NodeEvent};
use tokio::sync::broadcast;

use super::super::state::AppState;

/// GET /ws – WebSocket-Verbindung für Live-Events
pub async fn handle_websocket(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    state
        .node
        .metrics
        .ws_connections
        .fetch_add(1, Ordering::Relaxed);
    let events = state.node.events.subscribe();
    let node = state.node.clone();
    ws.on_upgrade(move |socket| websocket_handler(socket, events, node))
}

pub async fn websocket_handler(
    mut socket: WebSocket,
    mut events: broadcast::Receiver<NodeEvent>,
    node: Arc<MasterNodeState>,
) {
    let init = {
        let chain = node.chain.lock().unwrap();
        let peers = node.peers.read().unwrap();
        let peers_healthy = peers.iter().filter(|p| p.is_healthy()).count();
        let documents_total = chain.list_all_documents().len() as u64;
        let now = chrono::Utc::now().timestamp();
        NodeEvent::InitialState {
            node_id: node.node_id.clone(),
            role: format!("{:?}", node.role),
            block_height: chain.blocks.len() as u64,
            latest_hash: chain.latest_hash.clone(),
            documents_total,
            peers_total: peers.len(),
            peers_healthy,
            requests_total: node.metrics.requests_total.load(Ordering::Relaxed),
            ws_connections: node.metrics.ws_connections.load(Ordering::Relaxed),
            uptime_seconds: now - node.started_at,
        }
    };
    if let Ok(msg) = serde_json::to_string(&init) {
        let _ = socket.send(Message::Text(msg.into())).await;
    }

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Ok(ev) => {
                        if let Ok(msg) = serde_json::to_string(&ev) {
                            if socket.send(Message::Text(msg.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    node.metrics.ws_connections.fetch_sub(1, Ordering::Relaxed);
}
