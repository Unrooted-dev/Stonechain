# Stone — Dezentrales Blockchain-Dokumentensystem

Stone ist ein Proof-of-Authority (PoA) Blockchain-Node für die sichere, unveränderliche Speicherung von Dokumenten. Er stellt eine REST + WebSocket API bereit und lässt sich direkt mit dem **Eigenen* Web-Frontend verbinden.

---

## Inhaltsverzeichnis

1. [Architektur](#architektur)
2. [Komponenten](#komponenten)
3. [Schnellstart (Entwicklung)](#schnellstart)
4. [Konfiguration (Umgebungsvariablen)](#konfiguration)
5. [API-Referenz](#api-referenz)
6. [Authentifizierung](#authentifizierung)
7. [PoA-Konsensus](#poa-konsensus)
8. [Deployment (Produktion)](#deployment)
9. [Projektstruktur](#projektstruktur)

---

## Architektur

```
Internet
   │
   ▼
Nginx (443 HTTPS)
   │
   ├─► forge-Nomad Flask App  (Port 5002)
   │       │  Session-Auth, UI, Proxying
   │       │
   │       └─► stone-master  (Port 8080, nur intern)
   │               │  REST + WebSocket API
   │               │  x-api-key Auth
   │               │
   │               ├── RocksDB  (Chain + Dokument-Index)
   │               ├── Chunks/  (Binär-Daten, Content-Addressed)
   │               └── P2P      (libp2p, optional)
   │
   └─► stone-auth  (Port 8443, optional)
           TLS-Zertifikats-Ausstelldienst für Cluster-Nodes
```

**Schlüsselprinzip:** Port `8080` (stone-master) ist nie direkt aus dem Internet erreichbar. Alle Anfragen laufen über Flask, das den Admin-API-Key server-seitig hinzufügt.

---

## Komponenten

| Binär | Datei | Funktion |
|---|---|---|
| `stone-master` | `src/bin/master_server.rs` | Haupt-Node: Chain, Dokumente, PoA, P2P, WebSocket |
| `stone-auth` | `src/bin/auth_server.rs` | Auth-Server: TLS-Zertifikate für Cluster-Nodes ausstellen |

| Modul | Datei | Funktion |
|---|---|---|
| `auth` | `src/auth.rs` | User-Verwaltung, BIP-39 Phrasen, TLS-Cert-Fetch |
| `blockchain` | `src/blockchain.rs` | Block/Document Structs, Chain-Logik, RocksDB-Storage |
| `consensus` | `src/consensus.rs` | PoA Validator-Set, Voting, Fork-Erkennung |
| `crypto` | `src/crypto.rs` | Ed25519 Signaturen, X25519 ECDH, AES-256-GCM Verschlüsselung |
| `master_node` | `src/master_node.rs` | MasterNodeState, Dokument-Upload-Logik, Events |
| `network` | `src/network.rs` | libp2p P2P-Netzwerk, Gossipsub, Kademlia |
| `storage` | `src/storage.rs` | Chunk-Store (Content-Addressed Binary Storage) |
| `tls` | `src/tls.rs` | rustls Server-Config-Helpers |

---

## Schnellstart

### Voraussetzungen

- Rust (stable) ≥ 1.75
- `cargo` im PATH

### Build & Start

```bash
# Projekt bauen
cargo build

# Node mit persistentem API-Key starten (empfohlen)
# .env enthält: STONE_CLUSTER_API_KEY=sk_...
./start.sh

# Alternativ direkt:
STONE_CLUSTER_API_KEY=sk_meinkey STONE_DATA_DIR=/var/lib/stone ./target/debug/stone-master
```

### forge-Nomad verbinden

In `/Webfrontend/path/.env`:
```env
BLOCKCHAIN_URL=http://localhost:8080
BLOCKCHAIN_API_KEY=sk_<gleicher key wie STONE_CLUSTER_API_KEY>
```

### Token synchronisieren (nach manuellem Reset)

```bash
./sync_token.sh
```

---

## Konfiguration

Alle Einstellungen per Umgebungsvariable (oder `.env` Datei im Projektroot):

| Variable | Standard | Beschreibung |
|---|---|---|
| `STONE_CLUSTER_API_KEY` | — | **Primär:** Fixer Admin-API-Key (Priorität 1) |
| `STONE_API_KEY` | — | Fallback Admin-API-Key (Priorität 2) |
| `STONE_DATA_DIR` | `stone_data` | Verzeichnis für Chain-DB, Chunks, Keys |
| `STONE_PORT` | `8080` | HTTP-API Port |
| `STONE_NODE_ID` | Hostname | Node-Identifikator |
| `STONE_P2P_PORT` | `9000` | libp2p Port |
| `STONE_P2P_DISABLED` | `0` | P2P deaktivieren (`1` = aus) |
| `STONE_TLS_CERT` | — | Pfad zum TLS-Zertifikat (aktiviert HTTPS) |
| `STONE_TLS_KEY` | — | Pfad zum TLS-Key |
| `STONE_CORS_ORIGINS` | `*` | CORS-Whitelist (kommagetrennt) |
| `STONE_INSECURE_SSL` | `0` | TLS-Verifikation deaktivieren (nur Dev) |

**Token-Priorität:** `STONE_CLUSTER_API_KEY` → `STONE_API_KEY` → `token.bin` → neu generieren

---

## API-Referenz

Alle Endpunkte sind unter `http://localhost:8080` erreichbar.  
Admin-Endpunkte erfordern den Header: `x-api-key: <ADMIN_KEY>`

### System

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `GET` | `/api/v1/health` | Nein | Einfacher Liveness-Check |
| `GET` | `/api/v1/status` | Admin | Node-Status, Chain-Höhe, Peers |
| `GET` | `/api/v1/metrics` | Admin | Upload/Download-Zähler, Uptime |
| `GET` | `/api/v1/chain/verify` | Admin | Chain-Integrität vollständig prüfen |

### Dokumente

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `GET` | `/api/v1/documents` | Admin | Alle aktiven Dokumente (paginiert) |
| `GET` | `/api/v1/documents?q=&page=&per_page=` | Admin | Suche + Pagination |
| `GET` | `/api/v1/documents/search?q=` | User | Volltextsuche |
| `GET` | `/api/v1/documents/user/:user_id` | User¹ | Dokumente eines Nutzers |
| `GET` | `/api/v1/documents/:doc_id` | User¹ | Dokument-Metadaten |
| `GET` | `/api/v1/documents/:doc_id/history` | User¹ | Versionshistorie |
| `GET` | `/api/v1/documents/:doc_id/data` | User¹ | Roh-Bytes (rekonstruiert aus Chunks) |
| `POST` | `/api/v1/documents` | User | Dokument hochladen (Multipart) |
| `PATCH` | `/api/v1/documents/:doc_id` | User¹ | Metadaten aktualisieren |
| `DELETE` | `/api/v1/documents/:doc_id` | User¹ | Soft-Delete (Tombstone) |

¹ User kann nur eigene Dokumente sehen/bearbeiten; Admin sieht alle.

**Upload-Felder (Multipart):**
```
file     — Binärdaten (erforderlich)
title    — Anzeigename (optional)
tags     — Kommagetrennte Tags (optional)
owner    — User-ID des Besitzers (optional, Standard: aufrufender User)
encrypt  — "true" für AES-256-GCM Verschlüsselung (optional)
```

### Blöcke

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `GET` | `/api/v1/blocks` | Admin | Alle Blöcke (paginiert) |
| `GET` | `/api/v1/blocks/:index` | Admin | Block nach Index |

### Nutzer

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `POST` | `/api/v1/auth/signup` | Nein | Neuen Nutzer anlegen |
| `POST` | `/api/v1/auth/login` | Nein | BIP-39 Phrase → API-Key |
| `GET` | `/api/v1/users` | Admin | Alle Nutzer mit Quota-Info |
| `DELETE` | `/api/v1/users/:user_id` | Admin | Nutzer löschen |

**Signup-Request:**
```json
{ "name": "Max Mustermann" }
```
**Signup-Response:**
```json
{
  "id": "user-3",
  "api_key": "abc123...",
  "phrase": "word1 word2 ... word12"
}
```
⚠️ Die Phrase wird nur einmal zurückgegeben und ist der einzige Wiederherstellungsweg.

### Peers & Sync

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `GET` | `/api/v1/peers` | Admin | Peer-Liste mit Status |
| `POST` | `/api/v1/peers` | Admin | Peer hinzufügen |
| `DELETE` | `/api/v1/peers/:idx` | Admin | Peer entfernen |
| `POST` | `/api/v1/sync` | Admin | Manuelle Synchronisation |

### PoA Konsensus

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `GET` | `/api/v1/validators` | Admin | Validator-Whitelist |
| `POST` | `/api/v1/validators` | Admin | Validator hinzufügen |
| `DELETE` | `/api/v1/validators/:node_id` | Admin | Validator entfernen |
| `PATCH` | `/api/v1/validators/:node_id/active` | Admin | Validator aktivieren/deaktivieren |
| `GET` | `/api/v1/validators/self` | Admin | Eigener Validator-Status + Public Key |
| `GET` | `/api/v1/consensus/status` | Admin | Konsensus-Status, aktive Runde |
| `POST` | `/api/v1/consensus/vote` | Admin | Vote abgeben |
| `GET` | `/api/v1/consensus/forks` | Admin | Fork-Kandidaten erkennen |
| `POST` | `/api/v1/consensus/resolve` | Admin | Fork auflösen |

### P2P

| Methode | Pfad | Auth | Beschreibung |
|---|---|---|---|
| `GET` | `/api/v1/p2p/peers` | Admin | Verbundene P2P-Peers |
| `POST` | `/api/v1/p2p/dial` | Admin | Peer per Multiaddr verbinden |
| `GET` | `/api/v1/p2p/info` | Admin | Lokale P2P-Identität |
| `GET` | `/api/v1/p2p/config` | Admin | P2P-Konfiguration |
| `GET` | `/api/v1/p2p/status` | Admin | P2P-Netzwerk-Status |
| `POST` | `/api/v1/p2p/ping/:peer_id` | Admin | Peer anpingen |

### WebSocket

```
ws://localhost:8080/ws
```
Sendet JSON-Events für alle Node-Aktivitäten (Uploads, Blocks, Peer-Änderungen).

**Event-Format:**
```json
{ "type": "document_uploaded", "payload": { "doc_id": "...", "owner": "user-1" } }
```

---

## Authentifizierung

### Admin-Key

Für alle Admin-Endpunkte:
```http
x-api-key: sk_38e597...
```

### User-Keys

Nutzer authentifizieren sich mit ihrem persönlichen API-Key (erhalten beim Signup):
```http
x-api-key: d3af03c706...
```

### BIP-39 Wiederherstellung

Der API-Key wird aus der 12-Wort-Mnemonic-Phrase abgeleitet (SHA-256 Hash). Bei Verlust des Keys kann er via `/api/v1/auth/login` mit der Phrase wiederhergestellt werden.

---

## PoA-Konsensus

Stone nutzt **Proof of Authority**: Nur explizit zugelassene Nodes (Validatoren) dürfen Blöcke schreiben.

### Wie es funktioniert

1. **Validator-Whitelist** — Jede Node hat eine Ed25519-Identität. Der Admin trägt `node_id` + `public_key_hex` in die Whitelist ein.
2. **Upload** — Beim Dokument-Upload prüft der Node ob seine eigene `node_id` ein aktiver Validator ist.
3. **Signatur** — Der Node signiert den Block mit seinem privaten Validator-Key.
4. **Verifikation** — Andere Nodes prüfen Signatur gegen die Whitelist beim Sync.

### Validator hinzufügen

```bash
# Eigenen Public Key abrufen
curl -H "x-api-key: $ADMIN_KEY" http://localhost:8080/api/v1/validators/self

# Validator registrieren
curl -X POST -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"node_id":"mein-node","public_key_hex":"abc123...","name":"Mein Node"}' \
  http://localhost:8080/api/v1/validators
```

---

## Deployment

### Produktions-Setup (Ubuntu/Debian)

```bash
# Einmaliges Server-Setup (Domain erforderlich)
sudo bash deploy/setup.sh meine-domain.de
```

Siehe `deploy/` für:
- `nginx.conf` — Reverse-Proxy + TLS-Terminierung
- `stone-master.service` — Systemd Unit
- `forge-nomad.service` — Systemd Unit  
- `setup.sh` — Automatisches Server-Setup

### Wichtige Sicherheitshinweise

- Port `8080` muss durch Firewall geblockt sein (`ufw deny 8080`)
- `.env` enthält den Admin-Key — **nie committen** (steht in `.gitignore`)
- `stone_data/keys/` enthält private Schlüssel — **nie committen**
- In Produktion: `STONE_CLUSTER_API_KEY` als Systemd-EnvironmentFile setzen

---

## Projektstruktur

```
stone/
├── src/
│   ├── lib.rs               # Modul-Baum
│   ├── auth.rs              # User-Verwaltung, BIP-39, TLS-Cert-Fetch
│   ├── blockchain.rs        # Block/Document Structs, Chain, RocksDB
│   ├── consensus.rs         # PoA: Validators, Voting, Fork-Erkennung
│   ├── crypto.rs            # Ed25519, X25519 ECDH, AES-256-GCM
│   ├── master_node.rs       # MasterNodeState, Upload-Logik, Events
│   ├── network.rs           # libp2p P2P (Kademlia, Gossipsub)
│   ├── storage.rs           # Chunk-Store
│   ├── tls.rs               # rustls Server-Config-Helpers
│   └── bin/
│       ├── master_server.rs # Haupt-Binary: REST API + WebSocket
│       └── auth_server.rs   # Auth-Binary: TLS-Zertifikate ausstellen
├── web/
│   ├── blockhain.html       # Management-Panel (Admin)
│   ├── stonechain.html      # Public-Panel (Nutzer)
│   └── blockchain.css       # Gemeinsame Styles
├── deploy/
│   ├── nginx.conf           # Nginx Reverse-Proxy Konfiguration
│   ├── stone-master.service # Systemd Unit für stone-master
│   ├── forge-nomad.service  # Systemd Unit für forge-Nomad
│   └── setup.sh             # Automatisches Server-Setup (Ubuntu/Debian)
├── stone_data/              # Laufzeit-Daten (gitignored)
│   ├── chain_db/            # RocksDB (Chain-Daten)
│   ├── chunks/              # Binäre Dokument-Chunks
│   ├── keys/                # Ed25519 Schlüsselpaare
│   └── users.json           # Nutzer-Datenbank
├── .env                     # Lokale Konfiguration (gitignored)
├── start.sh                 # Node starten (lädt .env)
├── sync_token.sh            # API-Key zwischen .env-Dateien synchronisieren
└── Cargo.toml
```

---

## Curl-Beispiele

```bash
export ADMIN_KEY="sk_38e597..."
export BASE="http://localhost:8080"

# Status
curl -H "x-api-key: $ADMIN_KEY" "$BASE/api/v1/status"

# Dokument hochladen
curl -X POST -H "x-api-key: $ADMIN_KEY" \
  -F "file=@/pfad/zur/datei.pdf" \
  -F "title=Mein Dokument" \
  -F "tags=intern,v1" \
  "$BASE/api/v1/documents"

# Alle Nutzer
curl -H "x-api-key: $ADMIN_KEY" "$BASE/api/v1/users"

# Neuen Nutzer anlegen
curl -X POST -H "Content-Type: application/json" \
  -d '{"name":"Max Mustermann"}' \
  "$BASE/api/v1/auth/signup"

# Validators anzeigen
curl -H "x-api-key: $ADMIN_KEY" "$BASE/api/v1/validators"
```
