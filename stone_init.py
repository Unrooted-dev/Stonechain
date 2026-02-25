#!/usr/bin/env python3
"""
stone_init.py — Node-Bootstrap-CLI
====================================
Vor dem ersten Node-Start ausführen:

    python stone_init.py

Was das Script macht:
  1. Liest NOMAD_URL und NODE_SECRET aus der .env Datei
  2. POST /stone/node/bootstrap → forge-Nomad Server
  3. Schreibt den erhaltenen api_key als STONE_CLUSTER_API_KEY in die .env
  4. Schreibt den Key auch in stone_data/token.bin (für direkte API-Calls)

Danach einfach die Node starten:
    ./target/debug/stone-master
    (oder: cargo run --bin stone-master)

Voraussetzungen:
  - .env Datei mit NOMAD_URL und NODE_SECRET muss existieren
  - forge-Nomad Server muss erreichbar sein
  - NODE_SECRET muss mit dem auf dem Server übereinstimmen
"""
from __future__ import annotations

import os
import sys
import json
import pathlib
import urllib.request
import urllib.error
from datetime import datetime

# ── Farben für Terminal-Output ────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg: str)   -> None: print(f"{GREEN}  ✓ {msg}{RESET}")
def err(msg: str)  -> None: print(f"{RED}  ✗ {msg}{RESET}")
def info(msg: str) -> None: print(f"{CYAN}  → {msg}{RESET}")
def warn(msg: str) -> None: print(f"{YELLOW}  ⚠ {msg}{RESET}")


# ── .env Parser / Writer ──────────────────────────────────────────────────────

def load_env(path: pathlib.Path) -> dict[str, str]:
    """Liest eine .env Datei und gibt die Variablen als Dict zurück."""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        # Anführungszeichen entfernen
        value = value.strip().strip('"').strip("'")
        env[key.strip()] = value
    return env


def set_env_value(path: pathlib.Path, key: str, value: str) -> None:
    """Setzt einen Key in der .env Datei (erstellt sie falls nötig)."""
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    else:
        lines = []

    new_lines: list[str] = []
    found = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(f"{key}=") or stripped.startswith(f"{key} ="):
            new_lines.append(f"{key}={value}")
            found = True
        else:
            new_lines.append(line)

    if not found:
        new_lines.append(f"{key}={value}")

    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


# ── Bootstrap ─────────────────────────────────────────────────────────────────

def bootstrap(nomad_url: str, node_secret: str, node_url: str) -> str:
    """
    Sendet Bootstrap-Request an forge-Nomad.
    Gibt den api_key zurück oder wirft eine Exception.
    """
    url     = nomad_url.rstrip("/") + "/stone/node/bootstrap"
    payload = json.dumps({
        "secret":   node_secret,
        "node_url": node_url,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data    = payload,
        method  = "POST",
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "stone-node/0.2.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = {}
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            pass
        raise RuntimeError(
            f"HTTP {exc.code}: {body.get('error', exc.reason)}"
        )
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Verbindung zu {nomad_url} fehlgeschlagen: {exc.reason}")

    if not body.get("ok"):
        raise RuntimeError(body.get("error", "Unbekannter Fehler vom Server"))

    return body["api_key"]


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    print(f"\n{BOLD}{'═'*55}{RESET}")
    print(f"{BOLD}  Stone Node Bootstrap{RESET}")
    print(f"{BOLD}{'═'*55}{RESET}\n")

    # .env Datei finden (im selben Verzeichnis wie dieses Script)
    script_dir = pathlib.Path(__file__).parent
    env_path   = script_dir / ".env"

    if not env_path.exists():
        err(f".env nicht gefunden: {env_path}")
        info("Erstelle eine .env Datei. Vorlage:")
        print(f"""
{YELLOW}  NOMAD_URL=https://dein-forge-nomad-server.de
  NODE_SECRET=dein-geheimes-passwort
  STONE_HTTP_PORT=8080
  STONE_P2P_PORT=7654
  STONE_NODE_ID=mein-node-name{RESET}
""")
        return 1

    env = load_env(env_path)
    info(f".env geladen: {env_path}")

    # Pflichtfelder prüfen
    nomad_url   = env.get("NOMAD_URL", "").rstrip("/")
    node_secret = env.get("NODE_SECRET", "")

    if not nomad_url:
        err("NOMAD_URL fehlt in der .env Datei")
        return 1
    if not node_secret:
        err("NODE_SECRET fehlt in der .env Datei")
        return 1

    # Optionale Felder
    http_port = env.get("STONE_HTTP_PORT", "8080")
    node_id   = env.get("STONE_NODE_ID", "stone-node")

    # Eigene Node-URL bestimmen
    node_url = env.get("STONE_NODE_URL", f"http://127.0.0.1:{http_port}")

    print(f"  Server:   {CYAN}{nomad_url}{RESET}")
    print(f"  Node-URL: {CYAN}{node_url}{RESET}")
    print(f"  Node-ID:  {CYAN}{node_id}{RESET}")
    print()

    # Bereits vorhandenen Key prüfen
    existing_key = env.get("STONE_CLUSTER_API_KEY", "")
    if existing_key:
        warn(f"Bereits ein API-Key vorhanden: {existing_key[:12]}…")
        try:
            answer = input("  Neu bootstrappen? (j/N) ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("j", "ja", "y", "yes"):
            ok("Bootstrap übersprungen — vorhandener Key bleibt.")
            return 0
        print()

    # Bootstrap durchführen
    info(f"Sende Bootstrap-Request an {nomad_url}/stone/node/bootstrap …")
    try:
        api_key = bootstrap(nomad_url, node_secret, node_url)
    except RuntimeError as exc:
        err(f"Bootstrap fehlgeschlagen: {exc}")
        return 1

    ok(f"API-Key erhalten: {api_key[:16]}…")

    # In .env schreiben
    set_env_value(env_path, "STONE_CLUSTER_API_KEY", api_key)
    ok(f"STONE_CLUSTER_API_KEY in {env_path} gespeichert")

    # In stone_data/token.bin schreiben
    data_dir = script_dir / "stone_data"
    data_dir.mkdir(exist_ok=True)
    token_path = data_dir / "token.bin"
    token_path.write_text(api_key, encoding="utf-8")
    ok(f"token.bin geschrieben: {token_path}")

    # Timestamp in .env speichern
    set_env_value(env_path, "STONE_BOOTSTRAP_AT", datetime.utcnow().isoformat() + "Z")

    print(f"\n{GREEN}{BOLD}{'═'*55}{RESET}")
    print(f"{GREEN}{BOLD}  ✅ Bootstrap erfolgreich!{RESET}")
    print(f"{GREEN}{BOLD}{'═'*55}{RESET}")
    print(f"\n  Jetzt Node starten:")
    print(f"  {CYAN}cargo run --bin stone-master{RESET}")
    print(f"  oder: {CYAN}./target/debug/stone-master{RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
