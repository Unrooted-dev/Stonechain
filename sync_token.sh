#!/usr/bin/env bash
# Synchronisiert den Stone API-Key zwischen stone/.env und forge-Nomad/.env
# Nützlich wenn token.bin manuell neu generiert wurde.

set -euo pipefail

STONE_DIR="/Users/leon/Schreibtisch/stonechain"
NOMAD_ENV="/Users/leon/forge-Nomad/.env"
TOKEN_BIN="/tmp/stone-test/token.bin"

# Aktuellen Key ermitteln (Priorität: .env > token.bin)
if [ -f "$STONE_DIR/.env" ] && grep -q "STONE_CLUSTER_API_KEY=" "$STONE_DIR/.env"; then
    CURRENT_KEY=$(grep "STONE_CLUSTER_API_KEY=" "$STONE_DIR/.env" | cut -d= -f2 | tr -d '[:space:]')
    echo "[sync] Key aus stone/.env: ${CURRENT_KEY:0:16}..."
elif [ -f "$TOKEN_BIN" ]; then
    CURRENT_KEY=$(tr -d '[:space:]' < "$TOKEN_BIN")
    echo "[sync] Key aus token.bin: ${CURRENT_KEY:0:16}..."
    # In stone/.env schreiben
    echo "STONE_CLUSTER_API_KEY=$CURRENT_KEY" > "$STONE_DIR/.env"
    echo "[sync] stone/.env aktualisiert"
else
    echo "[sync] FEHLER: Weder stone/.env noch token.bin gefunden!"
    exit 1
fi

# forge-Nomad .env aktualisieren
python3 -c "
import pathlib, re
p = pathlib.Path('$NOMAD_ENV')
txt = p.read_bytes()
key = '$CURRENT_KEY'

# Zeilenweises Ersetzen (robust gegen terminal-wrap)
lines = []
skip = False
for line in txt.split(b'\n'):
    if skip and b'=' not in line:
        skip = False
        continue
    skip = False
    if line.startswith(b'BLOCKCHAIN_API_KEY='):
        lines.append(f'BLOCKCHAIN_API_KEY={key}'.encode())
        skip = True
    else:
        lines.append(line)
p.write_bytes(b'\n'.join(lines))
print('[sync] forge-Nomad BLOCKCHAIN_API_KEY aktualisiert')
"

echo ""
echo "=== Ergebnis ==="
echo "stone/.env:      $(grep STONE_CLUSTER_API_KEY "$STONE_DIR/.env")"
echo "forge-Nomad .env: $(python3 -c "
import pathlib
data = pathlib.Path('$NOMAD_ENV').read_bytes()
idx = data.find(b'BLOCKCHAIN_API_KEY=')
end = data.find(b'\n', idx)
print(data[idx:end].decode())
")"
echo ""
echo "✅ Sync abgeschlossen. Flask neu starten nicht vergessen!"
