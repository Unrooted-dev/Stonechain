//! PoA validators, consensus voting, and fork detection handlers.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use stone::{
    consensus::{
        detect_forks, load_or_create_validator_key, local_validator_pubkey_hex, resolve_fork,
        ForkCandidate, ValidatorInfo, VoteMessage,
    },
    master_node::NodeEvent,
};

use super::super::auth_middleware::require_admin;
use super::super::state::AppState;

#[derive(Deserialize)]
pub struct AddValidatorRequest {
    pub node_id: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub endpoint: String,
}

#[derive(Deserialize)]
pub struct CastVoteRequest {
    pub round: u64,
    pub block_hash: String,
    pub accept: bool,
    #[serde(default)]
    pub reason: String,
}

/// GET /api/v1/validators
pub async fn handle_list_validators(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let vs = state.node.validator_set.read().unwrap();
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "validators": vs.validators,
            "active_count": vs.active_count(),
            "supermajority_threshold": vs.supermajority_threshold(),
            "poa_active": !vs.validators.is_empty(),
        })),
    ))
}

/// POST /api/v1/validators
pub async fn handle_add_validator(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<AddValidatorRequest>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    if req.node_id.trim().is_empty() || req.public_key_hex.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(
                json!({"error": "node_id und public_key_hex sind erforderlich"}),
            ),
        )
            .into_response());
    }

    if req.public_key_hex.len() != 64 || hex::decode(&req.public_key_hex).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "public_key_hex muss ein 64-Zeichen-Hex-String (32 Byte) sein"})),
        )
            .into_response());
    }

    let mut info = ValidatorInfo::new(&req.node_id, &req.public_key_hex);
    info.name = req.name.clone();
    info.endpoint = req.endpoint.clone();

    let node_id = info.node_id.clone();
    {
        let mut vs = state.node.validator_set.write().unwrap();
        vs.add(info);
    }

    state.node.events.publish(NodeEvent::ValidatorAdded {
        node_id: node_id.clone(),
        pub_key_hex: req.public_key_hex.clone(),
        name: req.name.clone(),
    });

    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "message": format!("Validator {} hinzugefügt", node_id),
            "node_id": node_id,
            "public_key_hex": req.public_key_hex,
        })),
    ))
}

/// DELETE /api/v1/validators/:node_id
pub async fn handle_remove_validator(
    headers: HeaderMap,
    Path(node_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let removed = {
        let mut vs = state.node.validator_set.write().unwrap();
        vs.remove(&node_id)
    };

    if !removed {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": format!("Validator '{}' nicht gefunden", node_id)})),
        )
            .into_response());
    }

    state.node.events.publish(NodeEvent::ValidatorRemoved {
        node_id: node_id.clone(),
    });

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "message": format!("Validator {} entfernt", node_id),
            "node_id": node_id,
        })),
    ))
}

/// PATCH /api/v1/validators/:node_id/activate
pub async fn handle_set_validator_active(
    headers: HeaderMap,
    Path(node_id): Path<String>,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(true);

    let ok = {
        let mut vs = state.node.validator_set.write().unwrap();
        vs.set_active(&node_id, active)
    };

    if !ok {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": format!("Validator '{}' nicht gefunden", node_id)})),
        )
            .into_response());
    }

    state
        .node
        .events
        .publish(NodeEvent::ValidatorStatusChanged {
            node_id: node_id.clone(),
            active,
        });

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "node_id": node_id,
            "active": active,
        })),
    ))
}

/// GET /api/v1/validators/self
pub async fn handle_validator_self(
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let sk = load_or_create_validator_key();
    let pk = local_validator_pubkey_hex(&sk);
    (
        StatusCode::OK,
        axum::Json(json!({
            "public_key_hex": pk,
            "note": "Diesen Public Key verwenden um diese Node als Validator zu registrieren",
        })),
    )
}

/// GET /api/v1/consensus/status
pub async fn handle_consensus_status(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let vs = state.node.validator_set.read().unwrap();
    let voting = state.node.active_voting.lock().unwrap();

    let status = if let Some(ref round) = *voting {
        let tally = round.tally(&vs);
        json!({
            "active": true,
            "round": round.round,
            "block_hash": round.block_hash,
            "proposer_id": round.proposer_id,
            "started_at": round.started_at,
            "finalized": round.finalized,
            "accepted": round.accepted,
            "tally": tally,
            "votes": round.votes.values().collect::<Vec<_>>(),
        })
    } else {
        json!({ "active": false })
    };

    Ok((StatusCode::OK, axum::Json(status)))
}

/// POST /api/v1/consensus/vote
pub async fn handle_cast_vote(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<CastVoteRequest>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let sk = load_or_create_validator_key();
    let pk_hex = local_validator_pubkey_hex(&sk);

    let voter_id = {
        let vs = state.node.validator_set.read().unwrap();
        vs.validators
            .iter()
            .find(|v| v.public_key_hex == pk_hex)
            .map(|v| v.node_id.clone())
            .unwrap_or_else(|| state.node.node_id.clone())
    };

    let vote = VoteMessage::new(
        req.round,
        req.block_hash.clone(),
        voter_id.clone(),
        req.accept,
        &sk,
        req.reason.clone(),
    );

    let tally = {
        let vs = state.node.validator_set.read().unwrap();
        let mut voting = state.node.active_voting.lock().unwrap();

        if let Some(ref mut round) = *voting {
            round.add_vote(vote, &vs).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error": e})),
                )
                    .into_response()
            })?;
            Some(round.tally(&vs))
        } else {
            return Err((
                StatusCode::CONFLICT,
                axum::Json(json!({"error": "Keine aktive Voting-Runde"})),
            )
                .into_response());
        }
    };

    if let Some(t) = &tally {
        state.node.events.publish(NodeEvent::VoteReceived {
            round: req.round,
            block_hash: req.block_hash.clone(),
            voter_id: voter_id.clone(),
            accept: req.accept,
            accepts: t.accepts,
            needed: t.threshold,
        });
    }

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "vote_recorded": true,
            "voter_id": voter_id,
            "tally": tally,
        })),
    ))
}

/// GET /api/v1/forks
pub async fn handle_detect_forks(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let chain = state.node.chain.lock().unwrap();
    let vs = state.node.validator_set.read().unwrap();

    let mut fork_groups = detect_forks(&chain.blocks);

    for group in &mut fork_groups {
        for candidate in group.iter_mut() {
            let result = vs.verify_block(
                &candidate.block_hash,
                &candidate.signer_id,
                &candidate.validator_signature,
            );
            candidate.signature_valid = result.is_acceptable();
        }
    }

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "forks_detected": fork_groups.len(),
            "fork_groups": fork_groups,
        })),
    ))
}

/// POST /api/v1/forks/resolve
pub async fn handle_resolve_fork(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;

    let candidates: Vec<ForkCandidate> = serde_json::from_value(
        body.get("candidates").cloned().unwrap_or(json!([])),
    )
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": format!("Ungültige Kandidaten: {e}")})),
        )
            .into_response()
    })?;

    if candidates.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Keine Kandidaten angegeben"})),
        )
            .into_response());
    }

    let vs = state.node.validator_set.read().unwrap();
    let resolution = resolve_fork(candidates, &vs);

    match resolution {
        Some(res) => {
            state.node.events.publish(NodeEvent::ForkResolved {
                winning_hash: res.winning_hash.clone(),
                dropped_blocks: 0,
                reason: format!("{:?}", res.reason),
            });
            Ok((
                StatusCode::OK,
                axum::Json(json!({
                    "winning_hash": res.winning_hash,
                    "reason": format!("{:?}", res.reason),
                    "candidates": res.candidates,
                })),
            ))
        }
        None => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "Fork-Auflösung fehlgeschlagen"})),
        )
            .into_response()),
    }
}
