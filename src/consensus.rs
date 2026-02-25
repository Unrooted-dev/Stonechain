//! Proof-of-Authority Konsensus-Schicht
//!
//! # Überblick
//!
//! Stone verwendet einen PoA-Mechanismus (Proof-of-Authority):
//!
//! 1. **Validator-Whitelist** – nur bekannte, registrierte Nodes dürfen Blöcke erstellen.
//!    Jeder Validator hat eine Node-ID und einen Ed25519-Public-Key.
//!    Die Liste wird persistent in `{data_dir}/validators.json` gespeichert.
//!
//! 2. **Block-Signatur** – der Validator signiert den Block-Hash mit seinem Ed25519-Schlüssel.
//!    Peers prüfen diese Signatur beim Accept eines fremden Blocks.
//!
//! 3. **Voting** – bei einem Konflikt (Fork) schickt der aktive Proposer einen `BlockProposal`
//!    an alle Peers. Jeder Validator antwortet mit einer `VoteMessage` (accept/reject).
//!    Eine Supermajorität (⌊2/3⌋ + 1 der bekannten Validatoren) ist ausreichend.
//!
//! 4. **Fork-Erkennung & Auflösung** – wenn zwei Blöcke mit gleichem Index aber
//!    verschiedenen Hashes existieren, wird der Block mit:
//!    a) der gültigsten Validator-Signatur, und
//!    b) der meisten Folge-Blöcke (longest-chain)
//!    bevorzugt. Bei Gleichstand gewinnt der lexikographisch kleinere Hash.

use crate::blockchain::{Block, data_dir};
use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey,
    ed25519::signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::Utc;

// ─── Validator-Info ──────────────────────────────────────────────────────────

/// Ein registrierter Validator im PoA-Netzwerk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Node-ID (z.B. "node-1", Hostname, UUID)
    pub node_id: String,
    /// Ed25519-Public-Key als 64-Zeichen-Hex (32 Byte)
    pub public_key_hex: String,
    /// Optionaler Anzeigename
    #[serde(default)]
    pub name: String,
    /// HTTP-Endpunkt der Validator-Node (für Voting)
    #[serde(default)]
    pub endpoint: String,
    /// Zeitpunkt der Aufnahme (Unix-Sekunden)
    #[serde(default)]
    pub added_at: i64,
    /// Aktiv / Deaktiviert (weiche Sperre ohne Löschen)
    #[serde(default = "bool_true")]
    pub active: bool,
    /// Anzahl signierter Blöcke (Statistik)
    #[serde(default)]
    pub blocks_signed: u64,
}

fn bool_true() -> bool { true }

impl ValidatorInfo {
    pub fn new(node_id: impl Into<String>, public_key_hex: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            public_key_hex: public_key_hex.into(),
            name: String::new(),
            endpoint: String::new(),
            added_at: Utc::now().timestamp(),
            active: true,
            blocks_signed: 0,
        }
    }

    /// Ed25519-Public-Key aus Hex dekodieren
    pub fn verifying_key(&self) -> Result<VerifyingKey, String> {
        let bytes = hex::decode(&self.public_key_hex)
            .map_err(|e| format!("PubKey Hex ungültig: {e}"))?;
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| "PubKey muss 32 Byte sein".to_string())?;
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| format!("PubKey ungültig: {e}"))
    }

    /// Block-Hash-Signatur verifizieren
    pub fn verify_block_signature(&self, block_hash: &str, signature_hex: &str) -> bool {
        if signature_hex.is_empty() { return false; }
        let Ok(vk) = self.verifying_key() else { return false; };
        let Ok(sig_bytes) = hex::decode(signature_hex) else { return false; };
        let Ok(arr): Result<[u8; 64], _> = sig_bytes.try_into() else { return false; };
        let sig = Signature::from_bytes(&arr);
        vk.verify(block_hash.as_bytes(), &sig).is_ok()
    }
}

// ─── Validator-Set ───────────────────────────────────────────────────────────

/// Persistente Whitelist aller bekannten Validatoren.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorInfo>,
}

impl ValidatorSet {
    fn path() -> String {
        format!("{}/validators.json", data_dir())
    }

    pub fn load() -> Self {
        match std::fs::read_to_string(Self::path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => ValidatorSet::default(),
        }
    }

    pub fn save(&self) {
        let path = Self::path();
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, s);
        }
    }

    /// Validator aufnehmen (oder aktualisieren falls node_id bereits vorhanden)
    pub fn add(&mut self, info: ValidatorInfo) {
        if let Some(existing) = self.validators.iter_mut().find(|v| v.node_id == info.node_id) {
            *existing = info;
        } else {
            self.validators.push(info);
        }
        self.save();
    }

    /// Validator entfernen
    pub fn remove(&mut self, node_id: &str) -> bool {
        let before = self.validators.len();
        self.validators.retain(|v| v.node_id != node_id);
        let removed = self.validators.len() < before;
        if removed { self.save(); }
        removed
    }

    /// Validator (de-)aktivieren
    pub fn set_active(&mut self, node_id: &str, active: bool) -> bool {
        if let Some(v) = self.validators.iter_mut().find(|v| v.node_id == node_id) {
            v.active = active;
            self.save();
            return true;
        }
        false
    }

    /// Prüfen ob node_id ein aktiver Validator ist
    pub fn is_active_validator(&self, node_id: &str) -> bool {
        self.validators.iter().any(|v| v.node_id == node_id && v.active)
    }

    /// Validator per node_id finden
    pub fn get(&self, node_id: &str) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| v.node_id == node_id)
    }

    /// Validator per node_id finden (mutable)
    pub fn get_mut(&mut self, node_id: &str) -> Option<&mut ValidatorInfo> {
        self.validators.iter_mut().find(|v| v.node_id == node_id)
    }

    /// Anzahl aktiver Validatoren
    pub fn active_count(&self) -> usize {
        self.validators.iter().filter(|v| v.active).count()
    }

    /// Supermajorität: ⌊2/3⌋ + 1 der aktiven Validatoren
    pub fn supermajority_threshold(&self) -> usize {
        let n = self.active_count();
        if n == 0 { return 1; }
        (n * 2 / 3) + 1
    }

    /// Einfache Mehrheit: > 50%
    pub fn simple_majority_threshold(&self) -> usize {
        let n = self.active_count();
        if n == 0 { return 1; }
        (n / 2) + 1
    }

    /// Block-Signatur durch einen bekannten aktiven Validator prüfen
    pub fn verify_block(
        &self,
        block_hash: &str,
        signer_node_id: &str,
        signature_hex: &str,
    ) -> BlockVerifyResult {
        if self.validators.is_empty() {
            // Kein Validator konfiguriert → PoA deaktiviert, alles erlaubt
            return BlockVerifyResult::NoValidatorsConfigured;
        }
        let Some(validator) = self.get(signer_node_id) else {
            return BlockVerifyResult::UnknownValidator;
        };
        if !validator.active {
            return BlockVerifyResult::ValidatorInactive;
        }
        if validator.verify_block_signature(block_hash, signature_hex) {
            BlockVerifyResult::Valid
        } else {
            BlockVerifyResult::InvalidSignature
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BlockVerifyResult {
    /// Keine Validatoren konfiguriert → PoA inaktiv, Block akzeptiert
    NoValidatorsConfigured,
    /// Signatur gültig, Validator bekannt und aktiv
    Valid,
    /// Signer ist nicht in der Whitelist
    UnknownValidator,
    /// Validator bekannt aber deaktiviert
    ValidatorInactive,
    /// Signatur mathematisch falsch
    InvalidSignature,
}

impl BlockVerifyResult {
    pub fn is_acceptable(&self) -> bool {
        matches!(self, Self::NoValidatorsConfigured | Self::Valid)
    }
}

// ─── Block-Signierung ─────────────────────────────────────────────────────────

/// Block-Hash mit einem Validator-Schlüssel signieren.
/// Gibt die Signatur als 128-Zeichen-Hex zurück.
pub fn sign_block(signing_key: &SigningKey, block_hash: &str) -> String {
    let sig: Signature = signing_key.sign(block_hash.as_bytes());
    hex::encode(sig.to_bytes())
}

// ─── Block-Proposal ──────────────────────────────────────────────────────────

/// Ein Validator schlägt einen neuen Block vor.
/// Wird an alle bekannten Validator-Peers geschickt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposal {
    /// Der vorgeschlagene Block
    pub block: Block,
    /// Node-ID des Proposers
    pub proposer_id: String,
    /// Ed25519-Signatur über block.hash (128 Hex-Zeichen)
    pub proposer_signature: String,
    /// Vorschlags-Zeitpunkt
    pub proposed_at: i64,
    /// Runden-Nummer (für Deduplizierung)
    pub round: u64,
}

impl BlockProposal {
    pub fn new(block: Block, proposer_id: String, signing_key: &SigningKey, round: u64) -> Self {
        let sig = sign_block(signing_key, &block.hash);
        Self {
            block,
            proposer_id,
            proposer_signature: sig,
            proposed_at: Utc::now().timestamp(),
            round,
        }
    }

    /// Signatur des Proposers gegen seinen Public Key prüfen
    pub fn verify_proposer(&self, validator_set: &ValidatorSet) -> bool {
        matches!(
            validator_set.verify_block(&self.block.hash, &self.proposer_id, &self.proposer_signature),
            BlockVerifyResult::Valid | BlockVerifyResult::NoValidatorsConfigured
        )
    }
}

// ─── Vote ─────────────────────────────────────────────────────────────────────

/// Abstimmungs-Nachricht eines Validators für einen vorgeschlagenen Block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteMessage {
    /// Runden-Nummer (muss mit Proposal übereinstimmen)
    pub round: u64,
    /// Hash des Blocks über den abgestimmt wird
    pub block_hash: String,
    /// Node-ID des Abstimmenden
    pub voter_id: String,
    /// true = Zustimmung, false = Ablehnung
    pub accept: bool,
    /// Ed25519-Signatur über (round.to_le_bytes() || block_hash || accept_byte)
    pub signature: String,
    /// Zeitpunkt
    pub voted_at: i64,
    /// Optionale Begründung bei Ablehnung
    #[serde(default)]
    pub reason: String,
}

impl VoteMessage {
    pub fn new(
        round: u64,
        block_hash: String,
        voter_id: String,
        accept: bool,
        signing_key: &SigningKey,
        reason: String,
    ) -> Self {
        let mut msg = round.to_le_bytes().to_vec();
        msg.extend_from_slice(block_hash.as_bytes());
        msg.push(if accept { 1 } else { 0 });
        let sig: Signature = signing_key.sign(&msg);
        Self {
            round,
            block_hash,
            voter_id,
            accept,
            signature: hex::encode(sig.to_bytes()),
            voted_at: Utc::now().timestamp(),
            reason,
        }
    }

    /// Signatur verifizieren
    pub fn verify(&self, validator_set: &ValidatorSet) -> bool {
        let Some(v) = validator_set.get(&self.voter_id) else { return false; };
        let Ok(vk) = v.verifying_key() else { return false; };
        let Ok(sig_bytes) = hex::decode(&self.signature) else { return false; };
        let Ok(arr): Result<[u8; 64], _> = sig_bytes.try_into() else { return false; };
        let sig = Signature::from_bytes(&arr);
        let mut msg = self.round.to_le_bytes().to_vec();
        msg.extend_from_slice(self.block_hash.as_bytes());
        msg.push(if self.accept { 1 } else { 0 });
        vk.verify(&msg, &sig).is_ok()
    }
}

// ─── Voting-Tally ─────────────────────────────────────────────────────────────

/// Sammelt Stimmen für eine laufende Konsensus-Runde.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VotingRound {
    pub round: u64,
    pub block_hash: String,
    pub proposer_id: String,
    pub started_at: i64,
    /// voter_id → VoteMessage
    pub votes: HashMap<String, VoteMessage>,
    pub finalized: bool,
    pub accepted: bool,
}

impl VotingRound {
    pub fn new(round: u64, block_hash: String, proposer_id: String) -> Self {
        Self {
            round,
            block_hash,
            proposer_id,
            started_at: Utc::now().timestamp(),
            votes: HashMap::new(),
            finalized: false,
            accepted: false,
        }
    }

    /// Stimme hinzufügen (nur wenn Signatur gültig)
    pub fn add_vote(&mut self, vote: VoteMessage, validator_set: &ValidatorSet) -> Result<(), String> {
        if vote.round != self.round {
            return Err(format!("Falsche Runde: {} ≠ {}", vote.round, self.round));
        }
        if vote.block_hash != self.block_hash {
            return Err("Block-Hash stimmt nicht überein".into());
        }
        if !vote.verify(validator_set) {
            return Err("Ungültige Stimm-Signatur".into());
        }
        self.votes.insert(vote.voter_id.clone(), vote);
        Ok(())
    }

    /// Auswertung: Supermajorität erreicht?
    pub fn tally(&self, validator_set: &ValidatorSet) -> VoteTally {
        let accepts = self.votes.values().filter(|v| v.accept).count();
        let rejects = self.votes.values().filter(|v| !v.accept).count();
        let total_active = validator_set.active_count();
        let threshold = validator_set.supermajority_threshold();
        VoteTally {
            accepts,
            rejects,
            abstentions: total_active.saturating_sub(self.votes.len()),
            total_validators: total_active,
            threshold,
            quorum_reached: accepts >= threshold,
        }
    }

    pub fn finalize(&mut self, validator_set: &ValidatorSet) -> VoteTally {
        let tally = self.tally(validator_set);
        self.finalized = true;
        self.accepted = tally.quorum_reached;
        tally
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTally {
    pub accepts: usize,
    pub rejects: usize,
    pub abstentions: usize,
    pub total_validators: usize,
    pub threshold: usize,
    pub quorum_reached: bool,
}

// ─── Fork-Erkennung & Auflösung ──────────────────────────────────────────────

/// Ein Fork-Kandidat: ein Block auf einem bestimmten Index der eine Alternative darstellt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkCandidate {
    pub block_index: u64,
    pub block_hash: String,
    pub signer_id: String,
    pub validator_signature: String,
    /// Anzahl der Folge-Blöcke auf diesem Ast (chain length after this block)
    pub chain_length_after: u64,
    /// Zeitpunkt der Erstellung
    pub timestamp: i64,
    /// Signatur gültig laut ValidatorSet
    pub signature_valid: bool,
}

/// Ergebnis der Fork-Auflösung
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkResolution {
    pub winning_hash: String,
    pub reason: ForkResolutionReason,
    pub candidates: Vec<ForkCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForkResolutionReason {
    /// Nur ein Kandidat mit gültiger Validator-Signatur
    OnlyValidSignature,
    /// Längerer Ast gewinnt (longest-chain)
    LongestChain,
    /// Gleiche Länge → lexikographisch kleinerer Hash
    LexicographicTiebreak,
    /// Kein Validator konfiguriert → erster Block gewinnt
    NoValidatorsFirstWins,
}

/// Löst einen Fork auf.
///
/// Priorität:
/// 1. Nur Blöcke mit gültiger Validator-Signatur (wenn PoA aktiv)
/// 2. Längerer Folge-Chain (longest-chain rule)
/// 3. Lexikographisch kleinerer Hash (deterministischer Tiebreak)
pub fn resolve_fork(
    candidates: Vec<ForkCandidate>,
    validator_set: &ValidatorSet,
) -> Option<ForkResolution> {
    if candidates.is_empty() { return None; }

    let ranked = candidates.clone();

    if validator_set.validators.is_empty() {
        // PoA deaktiviert → einfach ersten nehmen
        return Some(ForkResolution {
            winning_hash: ranked[0].block_hash.clone(),
            reason: ForkResolutionReason::NoValidatorsFirstWins,
            candidates,
        });
    }

    // Nur gültig signierte Kandidaten
    let valid_only: Vec<_> = ranked.iter().filter(|c| c.signature_valid).cloned().collect();
    if valid_only.len() == 1 {
        return Some(ForkResolution {
            winning_hash: valid_only[0].block_hash.clone(),
            reason: ForkResolutionReason::OnlyValidSignature,
            candidates,
        });
    }

    let pool = if valid_only.is_empty() { ranked.clone() } else { valid_only };

    // Längster Ast
    let max_len = pool.iter().map(|c| c.chain_length_after).max().unwrap_or(0);
    let longest: Vec<_> = pool.iter().filter(|c| c.chain_length_after == max_len).cloned().collect();

    if longest.len() == 1 {
        return Some(ForkResolution {
            winning_hash: longest[0].block_hash.clone(),
            reason: ForkResolutionReason::LongestChain,
            candidates,
        });
    }

    // Tiebreak: lexikographisch kleinster Hash
    let winner = longest.iter().min_by(|a, b| a.block_hash.cmp(&b.block_hash)).unwrap();
    Some(ForkResolution {
        winning_hash: winner.block_hash.clone(),
        reason: ForkResolutionReason::LexicographicTiebreak,
        candidates,
    })
}

/// Erkennt Forks in einer Chain: mehrere Blöcke mit demselben `previous_hash`
/// → unterschiedliche Äste auf demselben Index.
pub fn detect_forks(blocks: &[Block]) -> Vec<Vec<ForkCandidate>> {
    // Gruppiere Blöcke nach (index, previous_hash)
    let mut by_index: HashMap<u64, Vec<&Block>> = HashMap::new();
    for b in blocks {
        by_index.entry(b.index).or_default().push(b);
    }

    let mut forks = Vec::new();
    for (_, group) in &by_index {
        if group.len() > 1 {
            let candidates = group.iter().map(|b| ForkCandidate {
                block_index: b.index,
                block_hash: b.hash.clone(),
                signer_id: b.signer.clone(),
                validator_signature: b.validator_signature.clone(),
                chain_length_after: blocks.iter().filter(|x| x.index > b.index).count() as u64,
                timestamp: b.timestamp,
                signature_valid: false, // caller fills this in with ValidatorSet
            }).collect();
            forks.push(candidates);
        }
    }
    forks
}

// ─── Validator-Schlüsselpaar (lokal, für diese Node) ─────────────────────────

/// Lädt oder erstellt das Ed25519-Schlüsselpaar dieser Validator-Node.
/// Gespeichert in `{data_dir}/validator_key.bin` (32 Byte Seed, binär).
pub fn load_or_create_validator_key() -> SigningKey {
    let path = format!("{}/validator_key.bin", data_dir());
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().unwrap();
            return SigningKey::from_bytes(&arr);
        }
    }
    // Neu generieren
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let _ = std::fs::write(&path, key.to_bytes());
    println!("[consensus] Neuer Validator-Schlüssel erstellt: {}", &data_dir());
    key
}

/// Public Key dieser Node als Hex
pub fn local_validator_pubkey_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}
