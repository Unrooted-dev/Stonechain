//! Document handlers: list, user, get, history, data, upload, delete, patch, transfer, search.

use axum::{
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use stone::{
    blockchain::{Document, DocumentTombstone},
    crypto::{
        decrypt_document, encrypt_document, sign_document, verify_document_signature,
        EncryptedBlob, NodeKeyPair, load_public_key,
    },
};

use super::super::auth_middleware::{require_admin, require_user};
use super::super::state::{chunk_data, reconstruct_document_data, AppState};

// ─── Query structs ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DocQuery {
    #[serde(default)]
    pub page: Option<u64>,
    #[serde(default)]
    pub per_page: Option<u64>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub page: Option<u64>,
    #[serde(default)]
    pub per_page: Option<u64>,
}

#[derive(Deserialize)]
pub struct PatchDocumentRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Deserialize)]
pub struct TransferDocumentRequest {
    pub to_user_id: String,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// GET /api/v1/documents – Alle aktiven Dokumente (Admin)
pub async fn handle_list_documents(
    headers: HeaderMap,
    Query(q): Query<DocQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    require_admin(&headers, &state)?;
    let chain = state.node.chain.lock().unwrap();
    let per_page = q.per_page.unwrap_or(50).min(500) as usize;
    let page = q.page.unwrap_or(0) as usize;

    let mut docs: Vec<stone::master_node::DocumentResponse> = chain
        .list_all_documents()
        .into_iter()
        .filter(|(d, _)| {
            if let Some(ref tag) = q.tag {
                if !d.tags.contains(tag) {
                    return false;
                }
            }
            if let Some(ref ct) = q.content_type {
                if &d.content_type != ct {
                    return false;
                }
            }
            true
        })
        .map(|(d, _)| stone::master_node::DocumentResponse::from(d))
        .collect();

    docs.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let total = docs.len();
    let paginated: Vec<_> = docs.into_iter().skip(page * per_page).take(per_page).collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "documents": paginated,
        })),
    ))
}

/// GET /api/v1/documents/user/:user_id
pub async fn handle_list_user_documents(
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(q): Query<DocQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let requesting_user = require_user(&headers, &state)?;
    if requesting_user.id != "admin" && requesting_user.id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Kein Zugriff auf fremde Dokumente"})),
        )
            .into_response());
    }

    let chain = state.node.chain.lock().unwrap();
    let per_page = q.per_page.unwrap_or(50).min(500) as usize;
    let page = q.page.unwrap_or(0) as usize;

    let mut docs: Vec<stone::master_node::DocumentResponse> = chain
        .list_documents_for_user(&user_id)
        .into_iter()
        .map(|(d, _)| stone::master_node::DocumentResponse::from(d))
        .collect();

    docs.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let total = docs.len();
    let paginated: Vec<_> = docs.into_iter().skip(page * per_page).take(per_page).collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "documents": paginated,
        })),
    ))
}

/// GET /api/v1/documents/:doc_id
pub async fn handle_get_document(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;
    let chain = state.node.chain.lock().unwrap();
    let (doc, block_index) = chain.find_document(&doc_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Dokument nicht gefunden"})),
        )
            .into_response()
    })?;

    if user.id != "admin" && doc.owner != user.id {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Kein Zugriff"})),
        )
            .into_response());
    }

    let resp = stone::master_node::DocumentResponse::from(doc);
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "document": resp,
            "block_index": block_index,
        })),
    ))
}

/// GET /api/v1/documents/:doc_id/history
pub async fn handle_document_history(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;
    let chain = state.node.chain.lock().unwrap();

    let history: Vec<_> = chain
        .document_history(&doc_id)
        .into_iter()
        .filter(|(d, _)| user.id == "admin" || d.owner == user.id)
        .map(|(d, block_idx)| {
            json!({
                "block_index": block_idx,
                "version": d.version,
                "updated_at": d.updated_at,
                "size": d.size,
                "title": d.title,
            })
        })
        .collect();

    if history.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Dokument nicht gefunden"})),
        )
            .into_response());
    }

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "doc_id": doc_id,
            "history": history,
        })),
    ))
}

/// GET /api/v1/documents/:doc_id/data – Rohdaten des Dokuments zurückgeben
pub async fn handle_get_document_data(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Response, Response> {
    let user = require_user(&headers, &state)?;
    let (doc_owned, content_type) = {
        let chain = state.node.chain.lock().unwrap();
        let (doc, _) = chain.find_document(&doc_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Dokument nicht gefunden"})),
            )
                .into_response()
        })?;
        if user.id != "admin" && doc.owner != user.id {
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "Kein Zugriff"})),
            )
                .into_response());
        }
        (doc.clone(), doc.content_type.clone())
    };

    let raw_data = reconstruct_document_data(&doc_owned).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": e})),
        )
            .into_response()
    })?;

    if !doc_owned.doc_signature.is_empty() && !doc_owned.public_key_hint.is_empty() {
        if let Some(pub_key) = load_public_key(&doc_owned.owner) {
            if let Err(e) = verify_document_signature(
                &pub_key,
                &doc_owned.doc_signature,
                &doc_owned.doc_id,
                doc_owned.version,
                doc_owned.size,
                &doc_owned.content_type,
            ) {
                eprintln!(
                    "[crypto] Signaturprüfung fehlgeschlagen für {}: {e}",
                    doc_owned.doc_id
                );
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    axum::Json(
                        json!({"error": "Dokument-Signatur ungültig – mögliche Manipulation"}),
                    ),
                )
                    .into_response());
            }
        }
    }

    let plaintext = if doc_owned.encrypted && !doc_owned.encryption_meta.is_empty() {
        let keypair = NodeKeyPair::load(&doc_owned.owner).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": format!("Schlüssel laden: {e}")})),
            )
                .into_response()
        })?;
        match keypair {
            Some(kp) => {
                let mut blob: EncryptedBlob =
                    serde_json::from_str(&doc_owned.encryption_meta).map_err(|_| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(
                                json!({"error": "Verschlüsselungs-Metadaten korrupt"}),
                            ),
                        )
                            .into_response()
                    })?;
                blob.ciphertext = hex::encode(&raw_data);
                decrypt_document(&kp, &blob).map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(json!({"error": format!("Entschlüsselung: {e}")})),
                    )
                        .into_response()
                })?
            }
            None => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(json!({"error": "Privater Schlüssel nicht gefunden"})),
                )
                    .into_response());
            }
        }
    } else {
        raw_data
    };

    Ok(Response::builder()
        .status(200)
        .header("content-type", content_type)
        .header(
            "content-disposition",
            format!("attachment; filename=\"{}\"", doc_owned.title),
        )
        .body(Body::from(plaintext))
        .unwrap())
}

/// POST /api/v1/documents – Dokument hochladen (Multipart)
pub async fn handle_upload_document(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;

    let mut file_data: Option<Vec<u8>> = None;
    let mut title: Option<String> = None;
    let mut doc_id: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut metadata: serde_json::Value = serde_json::Value::Null;
    let mut content_type_override: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or("") {
            "file" => {
                if title.is_none() {
                    title = field.file_name().map(|s| s.to_string());
                    content_type_override = field.content_type().map(|s| s.to_string());
                }
                file_data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| {
                            (
                                StatusCode::BAD_REQUEST,
                                axum::Json(
                                    json!({"error": format!("Datei lesen fehlgeschlagen: {e}")}),
                                ),
                            )
                                .into_response()
                        })?
                        .to_vec(),
                );
            }
            "title" => {
                title = Some(field.text().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({"error": format!("Feld lesen: {e}")})),
                    )
                        .into_response()
                })?);
            }
            "doc_id" => {
                doc_id = Some(field.text().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({"error": format!("Feld lesen: {e}")})),
                    )
                        .into_response()
                })?);
            }
            "tags" => {
                let raw = field.text().await.unwrap_or_default();
                tags = raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "metadata" => {
                let raw = field.text().await.unwrap_or_default();
                metadata = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
            }
            "content_type" => {
                content_type_override = Some(field.text().await.unwrap_or_default());
            }
            _ => {}
        }
    }

    let file_bytes = file_data.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Kein 'file' Feld gefunden"})),
        )
            .into_response()
    })?;

    let title = title.unwrap_or_else(|| "Untitled".to_string());
    let content_type =
        content_type_override.unwrap_or_else(|| "application/octet-stream".to_string());

    let current_usage = {
        let chain = state.node.chain.lock().unwrap();
        chain.user_usage_bytes(&user.id)
    };
    if current_usage + file_bytes.len() as u64 > user.quota_bytes {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Speicher-Quota überschritten"})),
        )
            .into_response());
    }

    let keypair = NodeKeyPair::load_or_create(&user.id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": format!("Schlüsselpaar-Fehler: {e}")})),
        )
            .into_response()
    })?;

    let (stored_bytes, encrypted, encryption_meta) = {
        match encrypt_document(&keypair.public_key_hex, &file_bytes) {
            Ok(blob) => {
                let cipher_bytes = hex::decode(&blob.ciphertext).unwrap_or_default();
                let meta_only = EncryptedBlob {
                    ephemeral_pubkey: blob.ephemeral_pubkey.clone(),
                    nonce: blob.nonce.clone(),
                    ciphertext: String::new(),
                };
                let meta = serde_json::to_string(&meta_only).unwrap_or_default();
                (cipher_bytes, true, meta)
            }
            Err(e) => {
                eprintln!(
                    "[crypto] Verschlüsselung fehlgeschlagen: {e} – speichere unverschlüsselt"
                );
                (file_bytes.clone(), false, String::new())
            }
        }
    };

    let chunks = chunk_data(&stored_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": e})),
        )
            .into_response()
    })?;

    let version = {
        let chain = state.node.chain.lock().unwrap();
        if let Some(id) = &doc_id {
            chain
                .find_document(id)
                .map(|(d, _)| d.version + 1)
                .unwrap_or(1)
        } else {
            1
        }
    };

    let new_doc_id = doc_id.unwrap_or_else(|| {
        let mut h = Sha256::new();
        h.update(user.id.as_bytes());
        h.update(title.as_bytes());
        h.update(&chrono::Utc::now().timestamp().to_le_bytes());
        hex::encode(h.finalize())[..24].to_string()
    });

    let doc_signature = sign_document(
        &keypair,
        &new_doc_id,
        version,
        file_bytes.len() as u64,
        &content_type,
    );
    let public_key_hint = keypair.public_key_hex[..16].to_string();

    let doc = Document {
        doc_id: new_doc_id.clone(),
        title: title.clone(),
        content_type,
        tags,
        metadata: stone::blockchain::JsonValue(metadata),
        version,
        size: file_bytes.len() as u64,
        chunks,
        deleted: false,
        updated_at: chrono::Utc::now().timestamp(),
        owner: user.id.clone(),
        doc_signature,
        public_key_hint,
        encrypted,
        encryption_meta,
    };

    let block = state
        .node
        .commit_documents(vec![doc], vec![], user.id.clone(), user.id.clone())
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": e})),
            )
                .into_response()
        })?;

    if let Some(ref network) = state.network {
        let block_clone = block.clone();
        let network_clone = network.clone();
        let chain_count = state.node.chain.lock().unwrap().blocks.len() as u64;
        tokio::spawn(async move {
            network_clone.broadcast_block(block_clone).await;
            network_clone.set_chain_count(chain_count).await;
        });
    }

    state
        .node
        .metrics
        .requests_total
        .fetch_add(1, Ordering::Relaxed);

    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "doc_id": new_doc_id,
            "block_index": block.index,
            "block_hash": block.hash,
            "version": version,
            "title": title,
            "encrypted": encrypted,
            "signed": true,
        })),
    ))
}

/// DELETE /api/v1/documents/:doc_id – Soft-Delete
pub async fn handle_delete_document(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;

    {
        let chain = state.node.chain.lock().unwrap();
        let (doc, _) = chain.find_document(&doc_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Dokument nicht gefunden"})),
            )
                .into_response()
        })?;
        if user.id != "admin" && doc.owner != user.id {
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "Kein Zugriff"})),
            )
                .into_response());
        }
    }

    let tombstone = DocumentTombstone {
        block_index: 0,
        doc_id: doc_id.clone(),
        owner: user.id.clone(),
    };

    let block = state
        .node
        .commit_documents(vec![], vec![tombstone], user.id.clone(), user.id.clone())
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": e})),
            )
                .into_response()
        })?;

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "deleted": true,
            "doc_id": doc_id,
            "block_index": block.index,
        })),
    ))
}

/// PATCH /api/v1/documents/:doc_id – Metadaten aktualisieren ohne Re-Upload
pub async fn handle_patch_document(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<PatchDocumentRequest>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;

    let updated_doc = {
        let chain = state.node.chain.lock().unwrap();
        let (doc, _) = chain.find_document(&doc_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Dokument nicht gefunden"})),
            )
                .into_response()
        })?;
        if user.id != "admin" && doc.owner != user.id {
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "Kein Zugriff"})),
            )
                .into_response());
        }
        Document {
            title: req.title.unwrap_or_else(|| doc.title.clone()),
            tags: req.tags.unwrap_or_else(|| doc.tags.clone()),
            metadata: stone::blockchain::JsonValue(
                req.metadata.unwrap_or_else(|| doc.metadata.0.clone()),
            ),
            content_type: req
                .content_type
                .unwrap_or_else(|| doc.content_type.clone()),
            version: doc.version + 1,
            updated_at: chrono::Utc::now().timestamp(),
            doc_id: doc.doc_id.clone(),
            size: doc.size,
            chunks: doc.chunks.clone(),
            deleted: false,
            owner: doc.owner.clone(),
            doc_signature: doc.doc_signature.clone(),
            public_key_hint: doc.public_key_hint.clone(),
            encrypted: doc.encrypted,
            encryption_meta: doc.encryption_meta.clone(),
        }
    };

    let block = state
        .node
        .commit_documents(
            vec![updated_doc.clone()],
            vec![],
            user.id.clone(),
            user.id.clone(),
        )
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": e})),
            )
                .into_response()
        })?;

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "doc_id": updated_doc.doc_id,
            "version": updated_doc.version,
            "block_index": block.index,
            "updated": true,
        })),
    ))
}

/// POST /api/v1/documents/:doc_id/transfer
pub async fn handle_transfer_document(
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    State(state): State<AppState>,
    axum::Json(req): axum::Json<TransferDocumentRequest>,
) -> Result<impl IntoResponse, Response> {
    let caller = require_user(&headers, &state)?;

    let to_id = req.to_user_id.trim().to_string();
    if to_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "to_user_id darf nicht leer sein"})),
        )
            .into_response());
    }

    let target_exists = to_id == "admin"
        || state
            .users
            .lock()
            .unwrap()
            .iter()
            .any(|u| u.id == to_id);
    if !target_exists {
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(
                json!({"error": format!("Zielnutzer '{}' nicht gefunden", to_id)}),
            ),
        )
            .into_response());
    }

    let current_doc: Document = {
        let chain = state.node.chain.lock().unwrap();
        let maybe = chain.find_document(&doc_id).map(|(d, _)| d.clone());
        drop(chain);
        maybe.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "Dokument nicht gefunden"})),
            )
                .into_response()
        })?
    };

    if current_doc.deleted {
        return Err((
            StatusCode::GONE,
            axum::Json(json!({"error": "Dokument wurde gelöscht"})),
        )
            .into_response());
    }
    if caller.id != "admin" && current_doc.owner != caller.id {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(
                json!({"error": "Nur der Eigentümer kann ein Dokument übertragen"}),
            ),
        )
            .into_response());
    }
    if current_doc.owner == to_id {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "Dokument gehört diesem Nutzer bereits"})),
        )
            .into_response());
    }

    let transferred_doc = Document {
        owner: to_id.clone(),
        version: current_doc.version + 1,
        updated_at: chrono::Utc::now().timestamp(),
        doc_id: current_doc.doc_id.clone(),
        title: current_doc.title.clone(),
        content_type: current_doc.content_type.clone(),
        tags: current_doc.tags.clone(),
        metadata: current_doc.metadata.clone(),
        size: current_doc.size,
        chunks: current_doc.chunks.clone(),
        deleted: false,
        doc_signature: current_doc.doc_signature.clone(),
        public_key_hint: current_doc.public_key_hint.clone(),
        encrypted: current_doc.encrypted,
        encryption_meta: current_doc.encryption_meta.clone(),
    };

    let block = state
        .node
        .commit_documents(
            vec![transferred_doc],
            vec![],
            caller.id.clone(),
            caller.id.clone(),
        )
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": e})),
            )
                .into_response()
        })?;

    if let Some(ref network) = state.network {
        let block_clone = block.clone();
        let network_clone = network.clone();
        let chain_count = state.node.chain.lock().unwrap().blocks.len() as u64;
        tokio::spawn(async move {
            network_clone.broadcast_block(block_clone).await;
            network_clone.set_chain_count(chain_count).await;
        });
    }

    state
        .node
        .metrics
        .requests_total
        .fetch_add(1, Ordering::Relaxed);

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "transferred": true,
            "doc_id":      doc_id,
            "from_user":   caller.id,
            "to_user":     to_id,
            "version":     block.index,
            "block_index": block.index,
            "block_hash":  block.hash,
        })),
    ))
}

/// GET /api/v1/documents/search – Volltextsuche
pub async fn handle_search_documents(
    headers: HeaderMap,
    Query(q): Query<SearchQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, Response> {
    let user = require_user(&headers, &state)?;

    let per_page = q.per_page.unwrap_or(50).min(500) as usize;
    let page = q.page.unwrap_or(0) as usize;
    let query_text = q.q.as_deref().unwrap_or("").to_lowercase();

    let chain = state.node.chain.lock().unwrap();

    let mut docs: Vec<stone::master_node::DocumentResponse> = chain
        .list_all_documents()
        .into_iter()
        .filter(|(d, _)| {
            if user.id != "admin" && d.owner != user.id {
                return false;
            }
            if let Some(ref owner_filter) = q.owner {
                if &d.owner != owner_filter {
                    return false;
                }
            }
            if let Some(ref tag) = q.tag {
                if !d.tags.contains(tag) {
                    return false;
                }
            }
            if let Some(ref ct) = q.content_type {
                if &d.content_type != ct {
                    return false;
                }
            }
            if !query_text.is_empty() {
                let title_match = d.title.to_lowercase().contains(&query_text);
                let tag_match = d
                    .tags
                    .iter()
                    .any(|t| t.to_lowercase().contains(&query_text));
                let meta_match = d
                    .metadata
                    .0
                    .to_string()
                    .to_lowercase()
                    .contains(&query_text);
                if !title_match && !tag_match && !meta_match {
                    return false;
                }
            }
            true
        })
        .map(|(d, _)| stone::master_node::DocumentResponse::from(d))
        .collect();

    docs.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let total = docs.len();
    let paginated: Vec<_> = docs.into_iter().skip(page * per_page).take(per_page).collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "total": total,
            "page": page,
            "per_page": per_page,
            "query": q.q,
            "documents": paginated,
        })),
    ))
}
