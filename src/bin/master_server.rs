//! Stone Master Node – entry point
//!
//! Stellt eine vollständige REST + WebSocket API für die externe Web-UI bereit.
//! Kein lokales GUI – alle Steuerung erfolgt über die vom Benutzer entwickelte Webseite.
//!
//! API-Übersicht:
//!   GET    /api/v1/status                    – Node- & Chain-Status
//!   GET    /api/v1/health                    – Einfacher Healthcheck (kein Auth)
//!   GET    /api/v1/metrics                   – Master-Node-Metriken
//!   GET    /api/v1/blocks                    – Alle Blöcke (paginiert)
//!   GET    /api/v1/blocks/:index             – Block nach Index
//!   GET    /api/v1/documents                 – Alle aktiven Dokumente (admin)
//!   GET    /api/v1/documents/user/:user_id   – Dokumente eines Nutzers
//!   GET    /api/v1/documents/:doc_id         – Dokument per ID
//!   GET    /api/v1/documents/:doc_id/history – Versionshistorie
//!   GET    /api/v1/documents/:doc_id/data    – Roh-Bytes (Chunk-Rekonstruktion)
//!   POST   /api/v1/documents                       – Dokument hochladen (Multipart)
//!   POST   /api/v1/documents/:doc_id/transfer       – Eigentum übertragen
//!   DELETE /api/v1/documents/:doc_id               – Soft-Delete
//!   GET    /api/v1/peers                     – Peer-Liste
//!   POST   /api/v1/peers                     – Peer hinzufügen
//!   DELETE /api/v1/peers/:idx                – Peer entfernen
//!   POST   /api/v1/sync                      – Manuelle Synchronisation
//!   POST   /api/v1/auth/signup               – Neuen Nutzer anlegen (pusht an Peers)
//!   POST   /api/v1/auth/login                – Phrase-Login
//!   POST   /api/v1/admin/sync-users          – Nutzer-Liste von Peer empfangen & mergen
//!   GET    /api/v1/chain/verify              – Chain-Integrität prüfen
//!   GET    /ws                               – WebSocket Event-Stream

#[path = "server/mod.rs"]
mod server;

use std::{net::SocketAddr, sync::Arc};

use stone::{
    auth::load_users,
    blockchain::{data_dir, NodeRole},
    master_node::MasterNodeState,
    network::{start_network, NetworkHandle},
    storage::ChunkStore,
};

use server::{
    router::build_router,
    state::{load_api_key, load_peers_from_disk, AppState, HEARTBEAT_INTERVAL},
    sync::{fetch_missing_chunks, pull_from_peer, spawn_auto_sync_task},
};

#[tokio::main]
async fn main() {
    // ── .env laden (falls vorhanden) ──────────────────────────────────────────
    match dotenvy::dotenv() {
        Ok(path) => println!("[master] .env geladen: {}", path.display()),
        Err(dotenvy::Error::Io(_)) => { /* .env nicht gefunden – kein Fehler */ }
        Err(e) => eprintln!("[master] .env Warnung: {e}"),
    }

    std::fs::create_dir_all(data_dir()).expect("DATA_DIR anlegen");
    ChunkStore::new().expect("ChunkStore anlegen");

    let api_key = Arc::new(load_api_key());
    let node_id = std::env::var("STONE_NODE_ID")
        .or_else(|_| std::env::var("STONE_NODE_NAME"))
        .unwrap_or_else(|_| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "stone-master".into())
        });

    println!("[master] Node-ID: {node_id}");
    println!(
        "[master] API-Key geladen: {}...",
        &api_key[..8.min(api_key.len())]
    );

    // Master Node State initialisieren
    let node = MasterNodeState::new(node_id.clone(), api_key.as_ref().clone(), NodeRole::Master);

    // Gespeicherte Peers laden
    let saved_peers = load_peers_from_disk();
    if !saved_peers.is_empty() {
        println!("[master] {} Peer(s) aus Datei geladen", saved_peers.len());
        node.replace_peers(saved_peers);
    }

    let users = load_users();

    // Hintergrund-Tasks starten
    MasterNodeState::start_heartbeat(node.clone(), HEARTBEAT_INTERVAL);
    spawn_auto_sync_task(node.clone(), api_key.clone(), users.clone());

    // P2P-Netzwerk starten (optional – deaktivieren via STONE_P2P_DISABLED=1)
    let network_handle: Option<NetworkHandle> =
        if std::env::var("STONE_P2P_DISABLED").as_deref() == Ok("1") {
            println!("[master] P2P-Netzwerk deaktiviert (STONE_P2P_DISABLED=1)");
            None
        } else {
            match start_network(None).await {
                Ok(handle) => {
                    println!(
                        "[master] P2P-Netzwerk gestartet – PeerId: {}",
                        handle.local_peer_id
                    );

                    {
                        let count = node.chain.lock().unwrap().blocks.len() as u64;
                        handle.set_chain_count(count).await;
                    }

                    {
                        use stone::network::NetworkEvent;
                        let mut event_rx = handle.subscribe();
                        let node_bg = node.clone();
                        let handle_bg = handle.clone();
                        let api_key_bg = api_key.clone();
                        tokio::spawn(async move {
                            while let Ok(event) = event_rx.recv().await {
                                if let NetworkEvent::BlockReceived { block, from_peer } = event {
                                    let peer_urls: Vec<String> = {
                                        node_bg
                                            .get_peers()
                                            .into_iter()
                                            .filter(|p| p.is_healthy())
                                            .map(|p| p.url.clone())
                                            .collect()
                                    };
                                    for url in &peer_urls {
                                        fetch_missing_chunks(&block, url, &api_key_bg).await;
                                    }

                                    let new_count = {
                                        let poa_ok = {
                                            let vs = node_bg.validator_set.read().unwrap();
                                            if vs.validators.is_empty() {
                                                None
                                            } else {
                                                let result = vs.verify_block(
                                                    &block.hash,
                                                    &block.signer,
                                                    &block.validator_signature,
                                                );
                                                Some(result.is_acceptable())
                                            }
                                        };

                                        let mut chain = node_bg.chain.lock().unwrap();
                                        let already_known =
                                            chain.blocks.iter().any(|b| b.hash == block.hash);
                                        if !already_known {
                                            let idx = block.index;
                                            match chain.accept_peer_block(*block, poa_ok) {
                                                Ok(_) => {
                                                    println!(
                                                        "[p2p] ✓ Block #{idx} von {from_peer} in Chain aufgenommen"
                                                    );
                                                    Some(chain.blocks.len() as u64)
                                                }
                                                Err(ref e) if e.starts_with("Stale:") => None,
                                                Err(ref e)
                                                    if e.starts_with("Gap:")
                                                        || e.contains("previous_hash") =>
                                                {
                                                    eprintln!(
                                                        "[p2p] Block #{idx} von {from_peer}: {e} → starte HTTP-Resync"
                                                    );
                                                    drop(chain);
                                                    let node_r = node_bg.clone();
                                                    let url_r = from_peer.clone();
                                                    let key_r = api_key_bg.clone();
                                                    tokio::spawn(async move {
                                                        pull_from_peer(&node_r, &url_r, &key_r)
                                                            .await;
                                                    });
                                                    None
                                                }
                                                Err(e) => {
                                                    eprintln!(
                                                        "[p2p] Block #{idx} abgelehnt: {e}"
                                                    );
                                                    None
                                                }
                                            }
                                        } else {
                                            None
                                        }
                                    };
                                    if let Some(count) = new_count {
                                        handle_bg.set_chain_count(count).await;
                                    }
                                }
                            }
                        });
                    }

                    Some(handle)
                }
                Err(e) => {
                    eprintln!("[master] P2P-Netzwerk konnte nicht gestartet werden: {e}");
                    None
                }
            }
        };

    let state = AppState {
        node: node.clone(),
        users,
        api_key: api_key.clone(),
        network: network_handle,
    };

    let router = build_router(state);

    // TLS-Konfiguration
    let use_tls = std::env::var("STONE_TLS_CERT").is_ok()
        && std::env::var("STONE_TLS_KEY").is_ok();
    let preferred_port: u16 = std::env::var("STONE_HTTP_PORT")
        .or_else(|_| std::env::var("STONE_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if use_tls { 443 } else { 8080 });

    if use_tls {
        let cert_path = std::env::var("STONE_TLS_CERT").unwrap();
        let key_path = std::env::var("STONE_TLS_KEY").unwrap();
        let addr = SocketAddr::from(([0, 0, 0, 0], preferred_port));
        println!("[master] HTTPS auf {addr} (TLS: {cert_path})");
        println!("[master] Stone Master Node läuft auf https://{addr}");
        println!("[master] Web-UI kann sich via wss://{addr}/ws verbinden");

        axum_server::bind_rustls(
            addr,
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .expect("TLS-Konfiguration laden"),
        )
        .serve(router.into_make_service())
        .await
        .expect("HTTPS-Server Fehler");
    } else {
        let listener = bind_with_fallback(preferred_port).await;
        let bound_port = listener.local_addr().unwrap().port();
        println!(
            "[master] HTTP auf 0.0.0.0:{bound_port} (kein TLS – nur für Entwicklung!)"
        );
        println!(
            "[master] Stone Master Node läuft auf http://0.0.0.0:{bound_port}"
        );
        println!(
            "[master] Web-UI kann sich via ws://0.0.0.0:{bound_port}/ws verbinden"
        );
        println!(
            "[master] Hinweis: Für Produktion STONE_TLS_CERT und STONE_TLS_KEY setzen."
        );
        axum::serve(listener, router).await.expect("HTTP-Server Fehler");
    }
}

/// Bindet an `preferred_port`. Bei Port-Konflikt: harter Fehler statt zufälligem Port.
async fn bind_with_fallback(preferred_port: u16) -> tokio::net::TcpListener {
    let addr = SocketAddr::from(([0, 0, 0, 0], preferred_port));
    match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("[master] ❌ Port {preferred_port} ist bereits belegt!");
            eprintln!("[master] Lösungen:");
            eprintln!(
                "[master]   1) Alte Prozesse beenden:  pkill -f stone-master"
            );
            eprintln!(
                "[master]   2) Anderen Port nutzen:    STONE_HTTP_PORT={} cargo run --bin stone-master",
                preferred_port + 1
            );
            eprintln!(
                "[master]   3) Belegenden Prozess prüfen: lsof -i :{preferred_port}"
            );
            std::process::exit(1);
        }
        Err(e) => panic!("TCP-Bind fehlgeschlagen: {e}"),
    }
}
