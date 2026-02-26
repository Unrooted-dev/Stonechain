//! Cloudflare Tunnel Integration
//!
//! Startet `cloudflared tunnel` als Hintergrundprozess neben dem Stone Master Node.
//! Unterstützt zwei Modi:
//!
//!   1. **Quick-Tunnel** (kein Account nötig) — `STONE_TUNNEL=quick`
//!      Cloudflare vergibt eine temporäre URL (*.trycloudflare.com).
//!      Ideal zum Testen, URL ändert sich bei jedem Neustart.
//!
//!   2. **Named-Tunnel** (Cloudflare-Account + Token) — `STONE_TUNNEL=named`
//!      Feste Subdomain via `STONE_TUNNEL_TOKEN` (aus `cloudflared tunnel create`).
//!      Produktiv-Einsatz: z.B. `meinnode.unrooted.dev`.
//!
//! Umgebungsvariablen:
//!   STONE_TUNNEL=quick|named|0|1   — Tunnel aktivieren (0/leer = aus)
//!   STONE_TUNNEL_TOKEN=<token>     — Cloudflare Tunnel-Token (nur Named-Tunnel)
//!   STONE_TUNNEL_URL_FILE=<path>   — Datei in die die öffentliche URL geschrieben wird
//!                                    (default: {data_dir}/tunnel.url)

use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Ergebnis des Tunnel-Starts
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    /// Öffentliche HTTPS-URL (z.B. https://abc-def.trycloudflare.com)
    pub public_url: String,
    /// Tunnel-Modus
    pub mode: TunnelMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TunnelMode {
    QuickTunnel,
    NamedTunnel,
}

/// Handle auf den laufenden cloudflared-Prozess.
/// Beim Drop wird der Prozess beendet.
pub struct TunnelHandle {
    child: Arc<Mutex<Child>>,
    pub info: TunnelInfo,
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }
}

/// Liest STONE_TUNNEL aus der Umgebung.
/// Gibt zurück: None (kein Tunnel), Some("quick"), Some("named")
pub fn tunnel_mode_from_env() -> Option<TunnelMode> {
    match std::env::var("STONE_TUNNEL")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "quick" | "1" | "true" | "yes" => Some(TunnelMode::QuickTunnel),
        "named"                         => Some(TunnelMode::NamedTunnel),
        _                               => None,
    }
}

/// Startet cloudflared als Hintergrundprozess.
/// Gibt Ok(TunnelHandle) zurück sobald die öffentliche URL bekannt ist (max. 15s Timeout).
pub fn start_tunnel(local_port: u16) -> Result<TunnelHandle, String> {
    let mode = tunnel_mode_from_env()
        .ok_or("STONE_TUNNEL nicht gesetzt oder deaktiviert")?;

    let cloudflared = find_cloudflared()?;

    match mode {
        TunnelMode::QuickTunnel  => start_quick_tunnel(&cloudflared, local_port),
        TunnelMode::NamedTunnel  => start_named_tunnel(&cloudflared, local_port),
    }
}

/// Sucht das cloudflared-Binary in PATH + bekannten Pfaden.
fn find_cloudflared() -> Result<String, String> {
    // 1. Explizit per Env
    if let Ok(p) = std::env::var("STONE_CLOUDFLARED_BIN") {
        if Path::new(&p).is_file() {
            return Ok(p);
        }
    }

    // 2. Standard-Pfade
    let candidates = [
        "cloudflared",
        "/opt/homebrew/bin/cloudflared",
        "/usr/local/bin/cloudflared",
        "/usr/bin/cloudflared",
    ];

    for c in candidates {
        if which_exists(c) {
            return Ok(c.to_string());
        }
    }

    Err("cloudflared nicht gefunden. Installieren mit: brew install cloudflared".into())
}

fn which_exists(bin: &str) -> bool {
    std::process::Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || Path::new(bin).is_file()
}

/// Quick-Tunnel: cloudflared tunnel --url https://localhost:<port>
/// Parst die trycloudflare.com URL aus stderr.
fn start_quick_tunnel(cloudflared: &str, port: u16) -> Result<TunnelHandle, String> {
    let url = format!("https://localhost:{port}");

    let mut child = Command::new(cloudflared)
        // --no-tls-verify muss NACH --url stehen (origin-request Flag in cloudflared 2026).
        // Stone nutzt selbst-signiertes Embedded-CA Cert → ohne dieses Flag gibt
        // Cloudflare Fehler 1033 ("SSL handshake failed / unable to connect to origin").
        .args(["tunnel", "--url", &url, "--no-tls-verify"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cloudflared starten fehlgeschlagen: {e}"))?;

    let stderr = child
        .stderr
        .take()
        .ok_or("cloudflared stderr nicht verfügbar")?;

    // URL aus stderr lesen (cloudflared gibt sie als Log-Zeile aus)
    let public_url = read_tunnel_url_from_output(stderr, Duration::from_secs(20))?;

    // URL in Datei schreiben
    write_tunnel_url_file(&public_url);

    println!("[tunnel] ✓ Quick-Tunnel aktiv: {}", public_url);
    println!("[tunnel]   → Kein Port-Forwarding nötig. URL ändert sich bei Neustart.");
    println!("[tunnel]   → Für feste URL: STONE_TUNNEL=named + STONE_TUNNEL_TOKEN setzen");

    Ok(TunnelHandle {
        child: Arc::new(Mutex::new(child)),
        info: TunnelInfo {
            public_url,
            mode: TunnelMode::QuickTunnel,
        },
    })
}

/// Named-Tunnel: cloudflared tunnel run --token <TOKEN>
/// Feste Domain aus dem Cloudflare-Dashboard.
fn start_named_tunnel(cloudflared: &str, _port: u16) -> Result<TunnelHandle, String> {
    let token = std::env::var("STONE_TUNNEL_TOKEN")
        .map_err(|_| "STONE_TUNNEL=named gesetzt, aber STONE_TUNNEL_TOKEN fehlt in .env".to_string())?;

    if token.trim().is_empty() {
        return Err("STONE_TUNNEL_TOKEN ist leer".into());
    }

    let mut child = Command::new(cloudflared)
        .args(["tunnel", "run", "--token", &token])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cloudflared named tunnel starten fehlgeschlagen: {e}"))?;

    let stderr = child
        .stderr
        .take()
        .ok_or("cloudflared stderr nicht verfügbar")?;

    // Bei Named-Tunnel: warten bis "Registered tunnel connection" auftaucht
    let public_url = read_named_tunnel_ready(stderr, Duration::from_secs(20))?;

    write_tunnel_url_file(&public_url);

    println!("[tunnel] ✓ Named-Tunnel aktiv: {}", public_url);
    println!("[tunnel]   → Feste URL, kein Port-Forwarding nötig.");

    Ok(TunnelHandle {
        child: Arc::new(Mutex::new(child)),
        info: TunnelInfo {
            public_url,
            mode: TunnelMode::NamedTunnel,
        },
    })
}

/// Liest stderr von cloudflared und sucht nach der öffentlichen URL.
/// Gibt Ok(url) zurück sobald gefunden, oder Err nach Timeout.
fn read_tunnel_url_from_output(
    stderr: impl std::io::Read + Send + 'static,
    timeout: Duration,
) -> Result<String, String> {
    let (tx, rx) = std::sync::mpsc::channel::<String>();

    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut prev_line = String::new();
        let mut found = false;

        for line in reader.lines().map_while(Result::ok) {
            // cloudflared 2026: URL erscheint in einer Zeile wie:
            // "INF |  https://abc-def.trycloudflare.com                            |"
            // Oder aufgeteilt auf zwei Zeilen wenn das Terminal wrap macht.
            // Erkennungsmerkmal: "trycloudflare.com"
            if !found {
                let combined = format!("{} {}", prev_line.trim(), line.trim());

                for candidate in [&line, &combined] {
                    if candidate.contains("trycloudflare.com") {
                        if let Some(url) = extract_trycloudflare_url(candidate) {
                            let _ = tx.send(url);
                            found = true;
                            break;
                        }
                    }
                }

                prev_line = line;
            }
            // WICHTIG: Nach dem Finden der URL weiterlesen!
            // Würden wir hier returnen, würde die Pipe geschlossen und cloudflared
            // beendet sich mit SIGPIPE (führt zu Fehler 1033).
        }
    });

    rx.recv_timeout(timeout)
        .map_err(|_| "Timeout: cloudflared URL wurde nicht gefunden. Ist cloudflared korrekt installiert?".to_string())
}

/// Wartet auf "Registered tunnel connection" bei Named-Tunnels und liest die konfigurierte Domain.
fn read_named_tunnel_ready(
    stderr: impl std::io::Read + Send + 'static,
    timeout: Duration,
) -> Result<String, String> {
    let domain = std::env::var("STONE_TUNNEL_DOMAIN")
        .unwrap_or_else(|_| "Ihre konfigurierte Domain".into());

    let (tx, rx) = std::sync::mpsc::channel::<String>();

    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut found = false;
        for line in reader.lines().map_while(Result::ok) {
            if !found && (line.contains("Registered tunnel connection")
                || line.contains("Connection registered")
                || line.contains("Connected to Cloudflare"))
            {
                let _ = tx.send(format!("https://{}", domain));
                found = true;
            }
            // Pipe offen halten – nicht returnen nach dem Fund!
        }
    });

    rx.recv_timeout(timeout)
        .map_err(|_| "Timeout: Named-Tunnel konnte keine Verbindung herstellen. Token korrekt?".to_string())
}

/// Extrahiert die trycloudflare.com URL aus einer Log-Zeile.
/// Format: "INF |  https://abc-def.trycloudflare.com                            |"
fn extract_trycloudflare_url(line: &str) -> Option<String> {
    let start = line.find("https://")
        .or_else(|| line.find("http://"))?;
    let rest  = &line[start..];
    // URL endet beim ersten Whitespace, | oder "
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '|' || c == '"' || c == '\'' || c == ')')
        .unwrap_or(rest.len());
    let url = rest[..end].trim_end_matches('/').to_string();
    // Muss mindestens domain.tld enthalten
    if url.len() > 12 && (url.contains("trycloudflare.com") || url.contains('.')) {
        // Cloudflare-AGB-Links ausschließen
        if url.contains("cloudflare.com/website") || url.contains("developers.cloudflare") {
            return None;
        }
        Some(url)
    } else {
        None
    }
}

/// Extrahiert eine https:// URL aus einer Log-Zeile.
#[allow(dead_code)]
fn extract_https_url(line: &str) -> Option<String> {
    extract_trycloudflare_url(line)
}

/// Schreibt die öffentliche Tunnel-URL in eine Datei (für andere Prozesse/Skripte).
fn write_tunnel_url_file(url: &str) {
    let path = std::env::var("STONE_TUNNEL_URL_FILE").unwrap_or_else(|_| {
        let data_dir = crate::blockchain::data_dir();
        format!("{}/tunnel.url", data_dir)
    });
    let _ = std::fs::write(&path, url);
}

/// Liest die zuletzt gespeicherte Tunnel-URL aus der Datei (falls vorhanden).
pub fn read_last_tunnel_url() -> Option<String> {
    let path = std::env::var("STONE_TUNNEL_URL_FILE").unwrap_or_else(|_| {
        let data_dir = crate::blockchain::data_dir();
        format!("{}/tunnel.url", data_dir)
    });
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}
