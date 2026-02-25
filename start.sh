#!/usr/bin/env bash
# Stone Master Node — Start Script
# Lädt .env und exportiert alle Variablen, damit der Token persistent bleibt.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# .env laden (falls vorhanden)
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
    echo "[stone] .env geladen: $(wc -l < "$SCRIPT_DIR/.env") Einträge"
fi

# STONE_CLUSTER_API_KEY prüfen
if [ -z "${STONE_CLUSTER_API_KEY:-}" ]; then
    echo "[stone] WARNUNG: STONE_CLUSTER_API_KEY nicht gesetzt — Token kann sich bei Neustart ändern!"
else
    echo "[stone] API-Key aus .env: ${STONE_CLUSTER_API_KEY:0:12}... (fix)"
fi

# Binary starten (Debug oder Release je nach Argument)
if [ "${1:-}" = "--release" ]; then
    BINARY="$SCRIPT_DIR/target/release/server"
else
    BINARY="$SCRIPT_DIR/target/debug/server"
fi

if [ ! -f "$BINARY" ]; then
    echo "[stone] Binary nicht gefunden: $BINARY"
    echo "        Bitte erst: cargo build [--release]"
    exit 1
fi

echo "[stone] Starte: $BINARY"
exec "$BINARY" "${@}"
