//! Stone P2P Pre-Shared Key (PSK) via libp2p::pnet
//!
//! ## Übersicht
//!
//! Der PSK ersetzt den zentralen Auth-Server für Node-Joins.
//! Jeder Node, der Teil des privaten Stone-Clusters sein soll,
//! benötigt denselben PSK — ohne diesen Schlüssel ist kein
//! TCP-Handshake auf dem P2P-Port möglich.
//!
//! ## Schlüssel-Hierarchie
//!
//! ```text
//!  STONE_PSK_SECRET  (Env oder stone_data/psk.key)
//!         │
//!         ▼  PBKDF2-HMAC-SHA256 (10 000 Iter., salt = "stone-pnet-v1")
//!  32-Byte PreSharedKey
//!         │
//!         ▼  libp2p::pnet::PreSharedKey
//!  Pnet-Handshake auf TCP-Ebene (vor Noise/Yamux)
//! ```
//!
//! ## Datei-Layout
//!
//! ```
//! stone_data/
//!   psk.key    ← hex-kodierter 32-Byte-Zufallsschlüssel (auto-generiert)
//! ```
//!
//! ## DHT-Distribution (konzeptionell)
//!
//! Der PSK selbst wird *nicht* über das Netz verteilt (Henne-Ei-Problem).
//! Stattdessen kann der Admin den PSK-Wert einmalig per sicheren
//! Out-of-Band-Kanal (z.B. `GET /api/v1/psk/export` mit mTLS oder
//! `stone-auth gen-psk`) auf neue Nodes kopieren.
//! Danach ist das Netz selbst-ausreichend — kein Auth-Server nötig.

use anyhow::{Context, Result};
use libp2p::pnet::PreSharedKey;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::fs;

// PBKDF2-Parameter
const PBKDF2_ITERS: u32 = 10_000;
const PBKDF2_SALT: &[u8] = b"stone-pnet-v1";

fn data_dir() -> String {
    std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| "stone_data".to_string())
}

fn psk_file() -> String {
    format!("{}/psk.key", data_dir())
}

// ─── Schlüssel laden / generieren ─────────────────────────────────────────────

/// Liefert das PSK-Secret (32 Hex-Bytes) aus:
///  1. Umgebungsvariable `STONE_PSK_SECRET`
///  2. Datei `stone_data/psk.key`
///  3. Neu generiert und in `stone_data/psk.key` gespeichert
pub fn load_or_generate_psk_secret() -> Result<String> {
    // 1. Umgebungsvariable hat Vorrang
    if let Ok(val) = std::env::var("STONE_PSK_SECRET") {
        let clean = val.trim().to_string();
        if clean.len() >= 32 {
            return Ok(clean);
        }
    }

    // 2. Datei
    let path = psk_file();
    if let Ok(data) = fs::read_to_string(&path) {
        let clean = data.trim().to_string();
        if clean.len() >= 32 {
            return Ok(clean);
        }
    }

    // 3. Neu generieren
    let secret = generate_psk_secret();
    let dir = data_dir();
    fs::create_dir_all(&dir).context("PSK-Verzeichnis anlegen")?;
    fs::write(&path, &secret).context("PSK-Datei schreiben")?;
    println!(
        "[psk] Neuer PSK generiert und gespeichert: {} (ersten 8 Zeichen: {}...)",
        path,
        &secret[..8]
    );
    println!("[psk] ⚠  Kopiere stone_data/psk.key auf alle Cluster-Nodes!");
    Ok(secret)
}

/// Erzeugt einen kryptographisch zufälligen 32-Byte PSK als Hex-String.
pub fn generate_psk_secret() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

// ─── PreSharedKey ableiten ────────────────────────────────────────────────────

/// Leitet aus dem Secret (beliebige Länge) einen `libp2p::pnet::PreSharedKey` ab.
/// Verwendet PBKDF2-HMAC-SHA256 mit festem Salt, damit derselbe Secret auf
/// verschiedenen Plattformen identische Keys ergibt.
pub fn derive_pnet_key(secret: &str) -> PreSharedKey {
    let mut dk = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        secret.as_bytes(),
        PBKDF2_SALT,
        PBKDF2_ITERS,
        &mut dk,
    );
    PreSharedKey::new(dk)
}

// ─── Öffentliche API ──────────────────────────────────────────────────────────

/// Lädt oder generiert den PSK und gibt den fertig abgeleiteten `PreSharedKey` zurück.
/// Gibt `None` zurück wenn PSK per `STONE_P2P_PSK_DISABLED=1` deaktiviert wurde.
pub fn load_pnet_key() -> Option<PreSharedKey> {
    if std::env::var("STONE_P2P_PSK_DISABLED").as_deref() == Ok("1") {
        println!("[psk] PSK deaktiviert (STONE_P2P_PSK_DISABLED=1) – offenes Netzwerk");
        return None;
    }

    match load_or_generate_psk_secret() {
        Ok(secret) => {
            let key = derive_pnet_key(&secret);
            println!("[psk] PSK geladen – Cluster-Netzwerk ist privat (pnet aktiv)");
            Some(key)
        }
        Err(e) => {
            eprintln!("[psk] Fehler beim Laden des PSK: {e} – pnet deaktiviert");
            None
        }
    }
}

/// Exportiert den aktuellen PSK als Hex-String für den Admin-Export-Endpunkt.
/// Gibt `None` wenn PSK deaktiviert oder nicht vorhanden.
pub fn export_psk_hex() -> Option<String> {
    if std::env::var("STONE_P2P_PSK_DISABLED").as_deref() == Ok("1") {
        return None;
    }
    load_or_generate_psk_secret().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_is_deterministic() {
        let a = derive_pnet_key("mysecret");
        let b = derive_pnet_key("mysecret");
        // PreSharedKey implements Display but not PartialEq – compare via fingerprint
        assert_eq!(format!("{a}"), format!("{b}"));
    }

    #[test]
    fn test_derive_differs_for_different_secrets() {
        let a = derive_pnet_key("secret-a");
        let b = derive_pnet_key("secret-b");
        assert_ne!(format!("{a}"), format!("{b}"));
    }
}
