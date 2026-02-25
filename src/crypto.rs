//! Stone Kryptographie-Modul
//!
//! Stellt drei Bausteine bereit:
//!
//! 1. **Schlüsselpaar (Ed25519)**
//!    - Generierung eines neuen Ed25519-Schlüsselpaars
//!    - Persistierung: Private Key → `stone_data/keys/<id>.key` (600)
//!                     Public Key  → `stone_data/keys/<id>.pub`  (644)
//!    - Laden eines bestehenden Schlüsselpaars
//!
//! 2. **Dokument-Signierung (Ed25519)**
//!    - `sign_document()` – signiert die kanonische Dokument-ID (doc_id + version + size)
//!    - `verify_document_signature()` – prüft Signatur gegen gespeicherten Public Key
//!
//! 3. **Dokument-Verschlüsselung (AES-256-GCM)**
//!    - `encrypt_document()` – verschlüsselt Rohdaten mit AES-256-GCM
//!    - `decrypt_document()` – entschlüsselt wieder
//!    - Schlüsselableitung: ECDH (X25519) zwischen Sender-Ephemeral und Empfänger-Public-Key
//!      → SHA-256 des gemeinsamen Geheimnisses als AES-Key
//!
//! Alle Fehler sind angehängte `CryptoError`-Werte – kein Panic außer bei Systemfehlern.

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use aes_gcm::aead::generic_array::GenericArray;
use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey,
    ed25519::signature::Signer,
    ed25519::signature::Verifier,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

// ─── Pfade ───────────────────────────────────────────────────────────────────

fn keys_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("STONE_DATA_DIR").unwrap_or_else(|_| "stone_data".to_string())
    ).join("keys")
}

fn priv_key_path(id: &str) -> PathBuf {
    keys_dir().join(format!("{}.key", id))
}

fn pub_key_path(id: &str) -> PathBuf {
    keys_dir().join(format!("{}.pub", id))
}

// ─── Fehler ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CryptoError {
    Io(std::io::Error),
    InvalidKey(String),
    SignatureMismatch,
    EncryptionFailed,
    DecryptionFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO-Fehler: {e}"),
            Self::InvalidKey(s) => write!(f, "Ungültiger Schlüssel: {s}"),
            Self::SignatureMismatch => write!(f, "Signatur ungültig"),
            Self::EncryptionFailed => write!(f, "Verschlüsselung fehlgeschlagen"),
            Self::DecryptionFailed => write!(f, "Entschlüsselung fehlgeschlagen"),
        }
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ─── Schlüsselpaar ───────────────────────────────────────────────────────────

/// Ed25519-Schlüsselpaar für eine Node oder einen Nutzer.
///
/// Felder:
/// - `signing_key`   – 64-Byte privater Schlüssel (Ed25519)
/// - `verifying_key` – 32-Byte öffentlicher Schlüssel (Ed25519)
/// - `public_key_hex`– Hex-kodierter Public Key (64 Zeichen)
pub struct NodeKeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub public_key_hex: String,
}

impl NodeKeyPair {
    /// Neues Ed25519-Schlüsselpaar zufällig generieren.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.as_bytes());
        Self { signing_key, verifying_key, public_key_hex }
    }

    /// Schlüsselpaar auf Disk speichern.
    ///
    /// - Private Key → `stone_data/keys/<id>.key`  (Rohdaten, 32 Byte)
    /// - Public Key  → `stone_data/keys/<id>.pub`  (Hex, 64 Zeichen + Newline)
    pub fn save(&self, id: &str) -> Result<(), CryptoError> {
        fs::create_dir_all(keys_dir())?;

        // Private Key – Rohdaten
        let priv_path = priv_key_path(id);
        fs::write(&priv_path, self.signing_key.as_bytes())?;
        // Unix: nur Besitzer darf lesen
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600))?;
        }

        // Public Key – Hex
        let pub_path = pub_key_path(id);
        fs::write(&pub_path, format!("{}\n", self.public_key_hex))?;

        Ok(())
    }

    /// Schlüsselpaar von Disk laden. Gibt `None` zurück wenn kein Key existiert.
    pub fn load(id: &str) -> Result<Option<Self>, CryptoError> {
        let priv_path = priv_key_path(id);
        if !priv_path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&priv_path)?;
        if raw.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "Privater Schlüssel hat falsche Länge: {} (erwartet 32)",
                raw.len()
            )));
        }
        let bytes: [u8; 32] = raw.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.as_bytes());
        Ok(Some(Self { signing_key, verifying_key, public_key_hex }))
    }

    /// Schlüsselpaar laden – oder neu generieren und speichern falls keines existiert.
    pub fn load_or_create(id: &str) -> Result<Self, CryptoError> {
        if let Some(kp) = Self::load(id)? {
            return Ok(kp);
        }
        let kp = Self::generate();
        kp.save(id)?;
        println!("[crypto] Neues Ed25519-Schlüsselpaar erstellt für '{id}': {}", &kp.public_key_hex[..16]);
        Ok(kp)
    }
}

// ─── Public-Key-Verzeichnis ───────────────────────────────────────────────────

/// Lädt den Public Key (Hex) eines Nutzers/Nodes von Disk.
/// Gibt `None` zurück falls kein Schlüssel vorhanden.
pub fn load_public_key(id: &str) -> Option<String> {
    let path = pub_key_path(id);
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Gibt alle gespeicherten Public Keys zurück (id → public_key_hex).
pub fn list_public_keys() -> Vec<(String, String)> {
    let dir = keys_dir();
    let mut result = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "pub") {
                let id = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                if let Ok(key) = fs::read_to_string(&path) {
                    result.push((id, key.trim().to_string()));
                }
            }
        }
    }
    result
}

// ─── Dokument-Signierung ──────────────────────────────────────────────────────

/// Kanonische Nachricht die für eine Dokument-Signatur signiert wird:
///   SHA-256(doc_id | "|" | version_le | "|" | size_le | "|" | content_type)
///
/// Durch SHA-256 wird die Eingabelänge normiert – das Ergebnis ist immer 32 Byte.
fn document_signing_message(
    doc_id: &str,
    version: u32,
    size: u64,
    content_type: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(doc_id.as_bytes());
    h.update(b"|");
    h.update(version.to_le_bytes());
    h.update(b"|");
    h.update(size.to_le_bytes());
    h.update(b"|");
    h.update(content_type.as_bytes());
    h.finalize().into()
}

/// Signiert ein Dokument mit dem Ed25519-Schlüsselpaar des Erstellers.
///
/// Gibt die Signatur als 128-Zeichen-Hex-String zurück (64 Byte Ed25519-Signatur).
pub fn sign_document(
    keypair: &NodeKeyPair,
    doc_id: &str,
    version: u32,
    size: u64,
    content_type: &str,
) -> String {
    let msg = document_signing_message(doc_id, version, size, content_type);
    let signature: Signature = keypair.signing_key.sign(&msg);
    hex::encode(signature.to_bytes())
}

/// Verifiziert die Signatur eines Dokuments gegen einen gespeicherten Public Key.
///
/// `public_key_hex` – 64-Zeichen-Hex (32 Byte Ed25519-Public-Key)
/// `signature_hex`  – 128-Zeichen-Hex (64 Byte Ed25519-Signatur)
pub fn verify_document_signature(
    public_key_hex: &str,
    signature_hex: &str,
    doc_id: &str,
    version: u32,
    size: u64,
    content_type: &str,
) -> Result<(), CryptoError> {
    let pub_bytes = hex::decode(public_key_hex)
        .map_err(|_| CryptoError::InvalidKey("Public Key kein gültiges Hex".into()))?;
    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Public Key muss 32 Byte sein".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

    let sig_bytes = hex::decode(signature_hex)
        .map_err(|_| CryptoError::InvalidKey("Signatur kein gültiges Hex".into()))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Signatur muss 64 Byte sein".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    let msg = document_signing_message(doc_id, version, size, content_type);
    verifying_key
        .verify(&msg, &signature)
        .map_err(|_| CryptoError::SignatureMismatch)
}

// ─── Dokument-Verschlüsselung ─────────────────────────────────────────────────

/// Verschlüsselter Blob: enthält alles was zur Entschlüsselung nötig ist.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedBlob {
    /// Ephemeral X25519 Public Key des Senders (32 Byte, Hex)
    pub ephemeral_pubkey: String,
    /// 12-Byte AES-GCM Nonce (Hex)
    pub nonce: String,
    /// Verschlüsselter Ciphertext (Hex)
    pub ciphertext: String,
}

/// Verschlüsselt Rohdaten für einen Empfänger mit seinem Ed25519-Public-Key.
///
/// Ablauf:
///   1. Ed25519-Public-Key → X25519-Kurven-Punkt (via SHA-512-Clamp wie in libsodium)
///   2. Ephemeral X25519-Secret generieren
///   3. ECDH: shared_secret = ephemeral_secret * recipient_x25519_pubkey
///   4. AES-256-GCM-Key = SHA-256(shared_secret)
///   5. Zufälligen 12-Byte-Nonce generieren
///   6. AES-256-GCM-Encrypt(key, nonce, plaintext)
///
/// Gibt einen `EncryptedBlob` zurück der alles zur Entschlüsselung enthält.
pub fn encrypt_document(
    recipient_ed25519_pub_hex: &str,
    plaintext: &[u8],
) -> Result<EncryptedBlob, CryptoError> {
    // Ed25519-PubKey → X25519-Kurven-Punkt
    let recipient_x25519 = ed25519_pubkey_to_x25519(recipient_ed25519_pub_hex)?;

    // Ephemeral X25519-Keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_pubkey = X25519PublicKey::from(&ephemeral_secret);

    // ECDH
    let shared = ephemeral_secret.diffie_hellman(&recipient_x25519);

    // AES-Key aus ECDH-Geheimnis ableiten
    let aes_key = derive_aes_key(shared.as_bytes());

    // Zufälligen Nonce generieren
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // AES-256-GCM verschlüsseln
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedBlob {
        ephemeral_pubkey: hex::encode(ephemeral_pubkey.as_bytes()),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Entschlüsselt einen `EncryptedBlob` mit dem Ed25519-Private-Key des Empfängers.
///
/// Ablauf:
///   1. Ed25519-Private-Key → X25519-Static-Secret (via SHA-512-Clamp)
///   2. Ephemeral X25519-PubKey aus Blob lesen
///   3. ECDH: shared_secret = static_secret * ephemeral_pubkey
///   4. AES-256-GCM-Key = SHA-256(shared_secret)
///   5. AES-256-GCM-Decrypt(key, nonce, ciphertext)
pub fn decrypt_document(
    keypair: &NodeKeyPair,
    blob: &EncryptedBlob,
) -> Result<Vec<u8>, CryptoError> {
    // Ed25519-Private-Key → X25519-Static-Secret
    let x25519_secret = ed25519_privkey_to_x25519(keypair.signing_key.as_bytes());

    // Ephemeral Public Key dekodieren
    let eph_bytes = hex::decode(&blob.ephemeral_pubkey)
        .map_err(|_| CryptoError::InvalidKey("Ephemeral PubKey kein gültiges Hex".into()))?;
    let eph_array: [u8; 32] = eph_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Ephemeral PubKey muss 32 Byte sein".into()))?;
    let ephemeral_pubkey = X25519PublicKey::from(eph_array);

    // ECDH
    let shared = x25519_secret.diffie_hellman(&ephemeral_pubkey);

    // AES-Key ableiten
    let aes_key = derive_aes_key(shared.as_bytes());

    // Nonce dekodieren
    let nonce_bytes = hex::decode(&blob.nonce)
        .map_err(|_| CryptoError::InvalidKey("Nonce kein gültiges Hex".into()))?;
    let nonce_array: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Nonce muss 12 Byte sein".into()))?;

    // Ciphertext dekodieren
    let ciphertext = hex::decode(&blob.ciphertext)
        .map_err(|_| CryptoError::InvalidKey("Ciphertext kein gültiges Hex".into()))?;

    // AES-256-GCM entschlüsseln
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(&nonce_array);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)
}

// ─── Interne Hilfsfunktionen ──────────────────────────────────────────────────

/// Ed25519-Public-Key (32 Byte) → X25519-Kurven-Punkt (Montgomery).
///
/// Konvertierung via birationale Äquivalenz Edwards ↔ Montgomery:
///   montgomery_u = (1 + edwards_y) / (1 - edwards_y)
/// Das entspricht genau der `to_montgomery()` Methode von `ed25519_dalek::VerifyingKey`.
fn ed25519_pubkey_to_x25519(pub_hex: &str) -> Result<X25519PublicKey, CryptoError> {
    let bytes = hex::decode(pub_hex)
        .map_err(|_| CryptoError::InvalidKey("Public Key kein gültiges Hex".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Public Key muss 32 Byte sein".into()))?;

    // Ed25519 VerifyingKey parsen
    let verifying_key = VerifyingKey::from_bytes(&arr)
        .map_err(|_| CryptoError::InvalidKey("Ungültiger Ed25519 Public Key".into()))?;

    // Edwards → Montgomery (birationale Äquivalenz)
    let montgomery = verifying_key.to_montgomery();
    Ok(X25519PublicKey::from(*montgomery.as_bytes()))
}

/// Ed25519-Private-Key (32 Byte Seed) → X25519-Static-Secret.
///
/// Konvertierung nach RFC 8032 / libsodium-Konvention:
///   x25519_scalar = clamp(SHA-512(ed25519_seed)[0..32])
fn ed25519_privkey_to_x25519(priv_bytes: &[u8]) -> StaticSecret {
    use sha2::Sha512;
    let hash = Sha512::digest(priv_bytes);
    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&hash[..32]);
    // X25519-Clamping (RFC 7748)
    x25519_bytes[0] &= 248;
    x25519_bytes[31] &= 127;
    x25519_bytes[31] |= 64;
    StaticSecret::from(x25519_bytes)
}

/// ECDH-Shared-Secret → AES-256-Key via SHA-256.
fn derive_aes_key(shared_secret: &[u8]) -> [u8; 32] {
    Sha256::digest(shared_secret).into()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let kp = NodeKeyPair::generate();
        let sig = sign_document(&kp, "doc-abc", 1, 1024, "application/pdf");
        assert_eq!(sig.len(), 128, "Signatur muss 128 Hex-Zeichen sein");

        verify_document_signature(&kp.public_key_hex, &sig, "doc-abc", 1, 1024, "application/pdf")
            .expect("Gültige Signatur muss akzeptiert werden");
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let kp = NodeKeyPair::generate();
        let sig = sign_document(&kp, "doc-abc", 1, 1024, "application/pdf");
        // Version manipuliert
        let result = verify_document_signature(
            &kp.public_key_hex, &sig, "doc-abc", 2, 1024, "application/pdf"
        );
        assert!(result.is_err(), "Manipulierte Nachricht muss abgelehnt werden");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let kp = NodeKeyPair::generate();
        let plaintext = b"Hello Stone! Das ist ein geheimer Dokumenten-Inhalt.";

        let blob = encrypt_document(&kp.public_key_hex, plaintext)
            .expect("Verschlüsselung muss funktionieren");
        let decrypted = decrypt_document(&kp, &blob)
            .expect("Entschlüsselung muss funktionieren");

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_decrypt_fails() {
        let sender_kp = NodeKeyPair::generate();
        let wrong_kp = NodeKeyPair::generate();
        let plaintext = b"Geheimnis";

        let blob = encrypt_document(&sender_kp.public_key_hex, plaintext).unwrap();
        let result = decrypt_document(&wrong_kp, &blob);
        assert!(result.is_err(), "Falscher Key muss Entschlüsselung verweigern");
    }
}
