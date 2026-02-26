//! stone-setup — Interaktiver Setup-Wizard
//!
//! Führt beim ersten Start (oder auf Wunsch) durch alle nötigen Konfigurationsschritte:
//!   0.  TLS-Bootstrap (automatisch, vor dem Wizard — keine Eingabe nötig)
//!   1.  Data-Directory wählen / anlegen
//!   2.  HTTP-Port festlegen
//!   3.  Node-Name vergeben
//!   4.  Max. Storage (GB) konfigurieren
//!   5.  Bootstrap-Peers auswählen / eigene eingeben
//!   6.  P2P-Port + PSK-Modus wählen
//!   7.  Admin API-Key generieren
//!   8.  .env schreiben (TLS immer aktiv — Zertifikate automatisch verwaltet)
//!   9.  Initialer Ping / Sync-Check gegen Bootstrap-Nodes
//!  10.  Zusammenfassung + optionaler Node-Start

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use console::{style, Term};
use dialoguer::{
    theme::ColorfulTheme, Confirm, FuzzySelect, Input, MultiSelect, Password,
};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use stone::auth::{bootstrap_tls, TlsBootstrapStatus};

// ─── Vordefinierte Bootstrap-Nodes ──────────────────────────────────────────

const BOOTSTRAP_NODES: &[(&str, &str)] = &[
    ("stone-boot-1  (Frankfurt)", "http://boot1.stonechain.network:8080"),
    ("stone-boot-2  (Amsterdam)", "http://boot2.stonechain.network:8080"),
    ("stone-boot-3  (Zürich)",    "http://boot3.stonechain.network:8080"),
    ("stone-boot-4  (London)",    "http://boot4.stonechain.network:8080"),
    ("stone-boot-5  (Stockholm)", "http://boot5.stonechain.network:8080"),
    ("Eigene Adresse eingeben…",  "__custom__"),
];

// ─── Hilfs-Typen ─────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Config {
    data_dir:        PathBuf,
    http_port:       u16,
    node_name:       String,
    max_storage_gb:  u32,
    bootstrap_peers: Vec<String>,
    p2p_port:        u16,
    psk_enabled:     bool,
    psk_secret:      Option<String>,
    api_key:         String,
}

// ─── Einstiegspunkt ──────────────────────────────────────────────────────────

fn main() {
    let term = Term::stdout();
    let _ = term.clear_screen();

    print_banner();

    let env_exists = Path::new(".env").exists();

    // ── TLS Bootstrap (still before wizard) ──────────────────────────────────
    // Determine data_dir from existing .env, or use the default
    let boot_data_dir = if env_exists {
        let content = fs::read_to_string(".env").unwrap_or_default();
        content
            .lines()
            .find(|l| l.starts_with("STONE_DATA_DIR="))
            .and_then(|l| l.splitn(2, '=').nth(1))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./stone_data"))
    } else {
        PathBuf::from("./stone_data")
    };

    {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::with_template("{spinner:.cyan} {msg}").unwrap());
        pb.set_message("TLS-Zertifikate werden geprüft…");
        pb.enable_steady_tick(Duration::from_millis(80));

        match bootstrap_tls(&boot_data_dir) {
            Ok(TlsBootstrapStatus::Created) => pb.finish_with_message(format!(
                "{} TLS bereit — Root-CA + Node-Zertifikat neu erstellt ({})",
                style("✓").green(),
                style(boot_data_dir.join("tls/node.crt").display().to_string()).cyan()
            )),
            Ok(TlsBootstrapStatus::Renewed) => pb.finish_with_message(format!(
                "{} TLS bereit — Zertifikat erneuert ({})",
                style("✓").green(),
                style(boot_data_dir.join("tls/node.crt").display().to_string()).cyan()
            )),
            Ok(TlsBootstrapStatus::Reused) => pb.finish_with_message(format!(
                "{} TLS bereit — bestehendes Zertifikat gültig",
                style("✓").green()
            )),
            Err(e) => {
                pb.finish_with_message(format!(
                    "{} TLS-Bootstrap Warnung: {e} (Node läuft weiter im HTTP-Modus)",
                    style("!").yellow()
                ));
            }
        }
    }
    println!();

    // ── Startmenü ─────────────────────────────────────────────────────────────
    let choice = if env_exists {
        // .env vorhanden → drei Optionen anbieten
        show_existing_config_summary();

        let options = &[
            "🚀  Node direkt starten  (bestehende Konfiguration verwenden)",
            "🔧  Neu konfigurieren    (Setup-Wizard erneut durchlaufen)",
            "📋  Konfiguration anzeigen & starten",
            "❌  Beenden",
        ];
        FuzzySelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Was möchtest du tun?")
            .items(options)
            .default(0)
            .interact()
            .unwrap_or(3)
    } else {
        // Erste Installation → direkt in den Wizard
        println!(
            "{} Keine .env gefunden – Setup-Wizard wird gestartet.\n",
            style("ℹ").cyan()
        );
        1 // → Neu konfigurieren
    };

    match choice {
        0 => {
            // Direkt starten
            println!(
                "\n{} Bestehende Konfiguration wird verwendet.",
                style("✓").green()
            );
            launch_node();
            return;
        }
        2 => {
            // Anzeigen + starten
            show_full_env();
            println!();
            let go = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Node jetzt starten?")
                .default(true)
                .interact()
                .unwrap_or(false);
            if go {
                launch_node();
            }
            return;
        }
        3 | _ if choice == 3 => {
            println!("\n{} Abgebrochen.", style("ℹ").dim());
            return;
        }
        _ => {
            // choice == 1 → Wizard durchlaufen (fall-through)
        }
    }

    // ── Schritt 1: Data-Directory ─────────────────────────────────────────────
    section("1 / 7", "Data-Directory");
    let data_dir: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Pfad zum Datenspeicher")
        .default("./stone_data".into())
        .interact_text()
        .unwrap();
    let data_dir = PathBuf::from(&data_dir);

    fs::create_dir_all(&data_dir).unwrap_or_else(|e| {
        eprintln!("{} Verzeichnis konnte nicht erstellt werden: {e}", style("✗").red());
        std::process::exit(1);
    });
    println!("{} Verzeichnis: {}", style("✓").green(), style(data_dir.display()).cyan());

    // ── Schritt 2: HTTP-Port ──────────────────────────────────────────────────
    section("2 / 7", "HTTP API Port");
    let http_port: u16 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Port (1–65535)")
        .default(8080)
        .validate_with(|p: &u16| {
            if *p < 1 { Err("Port muss ≥ 1 sein") } else { Ok(()) }
        })
        .interact_text()
        .unwrap();
    println!("{} Port: {}", style("✓").green(), style(http_port).cyan());

    // ── Schritt 3: Node-Name ──────────────────────────────────────────────────
    section("3 / 7", "Node-Name");
    let default_name = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "stone-node".into());
    let node_name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Name dieses Nodes (wird in der Trust-Registry angezeigt)")
        .default(default_name)
        .interact_text()
        .unwrap();
    println!("{} Node-Name: {}", style("✓").green(), style(&node_name).cyan());

    // ── Schritt 4: Max. Storage ───────────────────────────────────────────────
    section("4 / 7", "Maximaler Speicherplatz");
    let max_storage_gb: u32 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Maximaler Speicher in GB (0 = unbegrenzt)")
        .default(10u32)
        .interact_text()
        .unwrap();
    if max_storage_gb == 0 {
        println!("{} Speicher: unbegrenzt", style("✓").green());
    } else {
        println!("{} Speicher: {} GB", style("✓").green(), style(max_storage_gb).cyan());
    }

    // ── Schritt 5: Bootstrap-Peers ────────────────────────────────────────────
    section("5 / 7", "Bootstrap-Peers");
    println!(
        "{}",
        style("Wähle Peers zum initialen Sync (Leertaste = auswählen, Enter = bestätigen):").dim()
    );

    let labels: Vec<&str> = BOOTSTRAP_NODES.iter().map(|(l, _)| *l).collect();
    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Bootstrap-Nodes")
        .items(&labels)
        .interact()
        .unwrap_or_default();

    let mut bootstrap_peers: Vec<String> = Vec::new();
    let mut needs_custom = false;

    for idx in &selections {
        let (_, url) = BOOTSTRAP_NODES[*idx];
        if url == "__custom__" {
            needs_custom = true;
        } else {
            bootstrap_peers.push(url.to_string());
        }
    }

    // Eigene Adressen eingeben
    if needs_custom || selections.is_empty() {
        if selections.is_empty() {
            println!(
                "{}",
                style("Keine vordefinierten Peers gewählt. Eigene Adresse eingeben:").yellow()
            );
        }
        loop {
            let custom: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Peer-URL (leer lassen zum Beenden)")
                .allow_empty(true)
                .interact_text()
                .unwrap();
            if custom.trim().is_empty() {
                break;
            }
            let url = custom.trim().to_string();
            // Einfache Validierung
            if url.starts_with("http://") || url.starts_with("https://") {
                bootstrap_peers.push(url);
            } else {
                println!("{} URL muss mit http:// oder https:// beginnen.", style("!").yellow());
            }
        }
    }

    // Deduplizieren
    let bootstrap_peers: Vec<String> = bootstrap_peers
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    if bootstrap_peers.is_empty() {
        println!(
            "{} Keine Bootstrap-Peers — Node startet isoliert.",
            style("ℹ").cyan()
        );
    } else {
        println!(
            "{} {} Peer(s) konfiguriert.",
            style("✓").green(),
            bootstrap_peers.len()
        );
        for p in &bootstrap_peers {
            println!("   {}", style(p).dim());
        }
    }

    // ── Schritt 6: P2P-Port + PSK ─────────────────────────────────────────────
    section("6 / 7", "P2P-Netzwerk & PSK");

    let p2p_port: u16 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("P2P-Lauschport (libp2p TCP)")
        .default(4001u16)
        .interact_text()
        .unwrap();

    let psk_choices = &[
        "Automatisch neuen PSK generieren (empfohlen für private Cluster)",
        "Bestehenden PSK-Secret eingeben",
        "PSK deaktivieren (offenes Netzwerk)",
    ];
    let psk_choice = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Pre-Shared Key (PSK) für pnet")
        .items(psk_choices)
        .default(0)
        .interact()
        .unwrap();

    let (psk_enabled, psk_secret) = match psk_choice {
        0 => {
            let secret = generate_hex(32);
            println!("{} PSK generiert: {}", style("✓").green(), style(&secret).cyan());
            (true, Some(secret))
        }
        1 => {
            let secret: String = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("PSK-Secret eingeben")
                .with_confirmation("Bestätigen", "Eingaben stimmen nicht überein")
                .interact()
                .unwrap();
            (true, Some(secret))
        }
        _ => {
            println!("{} PSK deaktiviert.", style("ℹ").yellow());
            (false, None)
        }
    };

    // ── Schritt 7: API-Key ────────────────────────────────────────────────────
    section("7 / 7", "Admin API-Key");
    let api_key_choices = &[
        "Automatisch generieren (empfohlen)",
        "Eigenen API-Key eingeben",
    ];
    let api_key_choice = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("API-Key")
        .items(api_key_choices)
        .default(0)
        .interact()
        .unwrap();

    let api_key = match api_key_choice {
        1 => {
            let key: String = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("API-Key eingeben (mind. 32 Zeichen)")
                .validate_with(|s: &String| {
                    if s.len() >= 32 {
                        Ok(())
                    } else {
                        Err("Mind. 32 Zeichen erforderlich")
                    }
                })
                .interact()
                .unwrap();
            key
        }
        _ => {
            let key = format!("sk_{}", generate_hex(32));
            println!("{} API-Key generiert.", style("✓").green());
            key
        }
    };

    let config = Config {
        data_dir,
        http_port,
        node_name,
        max_storage_gb,
        bootstrap_peers,
        p2p_port,
        psk_enabled,
        psk_secret,
        api_key,
    };

    // ── .env schreiben ────────────────────────────────────────────────────────
    write_env(&config);

    // ── PSK-Datei schreiben ───────────────────────────────────────────────────
    if let Some(ref secret) = config.psk_secret {
        let psk_path = config.data_dir.join("psk.key");
        fs::write(&psk_path, secret)
            .unwrap_or_else(|e| eprintln!("{} PSK konnte nicht gespeichert werden: {e}", style("!").yellow()));
        println!("{} PSK-Secret gespeichert: {}", style("✓").green(), psk_path.display());
    }

    // ── Zusammenfassung ───────────────────────────────────────────────────────
    print_summary(&config);

    // ── Initialer Sync-Check ──────────────────────────────────────────────────
    if !config.bootstrap_peers.is_empty() {
        let run_check = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Erreichbarkeit der Bootstrap-Peers jetzt prüfen?")
            .default(true)
            .interact()
            .unwrap_or(false);

        if run_check {
            check_bootstrap_peers(&config.bootstrap_peers);
        }
    }

    // ── Node starten? ─────────────────────────────────────────────────────────
    let start_node = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Node jetzt starten?")
        .default(true)
        .interact()
        .unwrap_or(false);

    if start_node {
        launch_node();
    } else {
        println!("\n{}", style("╔══════════════════════════════════════════════════╗").cyan());
        println!("{}", style("║  Setup abgeschlossen. Node starten mit:          ║").cyan());
        println!("{}", style("║                                                  ║").cyan());
        println!(
            "{}  {}  {}",
            style("║").cyan(),
            style("  cargo run --release --bin stone-master         ").green(),
            style("║").cyan()
        );
        println!("{}", style("║                                                  ║").cyan());
        println!("{}", style("╚══════════════════════════════════════════════════╝").cyan());
    }
}

// ─── .env schreiben ──────────────────────────────────────────────────────────

fn write_env(cfg: &Config) {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}").unwrap(),
    );
    pb.set_message(".env wird geschrieben…");
    pb.enable_steady_tick(Duration::from_millis(80));

    let bootstrap_str = cfg.bootstrap_peers.join(",");
    let storage_bytes: u64 = if cfg.max_storage_gb == 0 {
        0
    } else {
        cfg.max_storage_gb as u64 * 1024 * 1024 * 1024
    };

    let mut lines: Vec<String> = vec![
        "# ── Stone Master Node — generiert von stone-setup ──────────────────────".into(),
        format!("# Erstellt: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")),
        "".into(),
        "# ── Basis ───────────────────────────────────────────────────────────────".into(),
        format!("STONE_DATA_DIR={}", cfg.data_dir.display()),
        format!("STONE_PORT={}", cfg.http_port),
        format!("STONE_NODE_NAME={}", cfg.node_name),
        format!("STONE_NODE_ID={}", cfg.node_name),
        "".into(),
        "# ── API-Sicherheit ──────────────────────────────────────────────────────".into(),
        format!("STONE_CLUSTER_API_KEY={}", cfg.api_key),
        format!("STONE_API_KEY={}", cfg.api_key),
        "".into(),
        "# ── Speicher ─────────────────────────────────────────────────────────────".into(),
        format!("STONE_MAX_STORAGE_BYTES={}", storage_bytes),
        "".into(),
        "# ── P2P-Netzwerk ────────────────────────────────────────────────────────".into(),
        format!("STONE_P2P_LISTEN=/ip4/0.0.0.0/tcp/{}", cfg.p2p_port),
        format!("STONE_P2P_PORT={}", cfg.p2p_port),
    ];

    if cfg.bootstrap_peers.is_empty() {
        lines.push("# STONE_BOOTSTRAP_NODES=".into());
    } else {
        lines.push(format!("STONE_BOOTSTRAP_NODES={}", bootstrap_str));
    }

    lines.push("".into());
    lines.push("# ── PSK / pnet ──────────────────────────────────────────────────────────".into());
    if cfg.psk_enabled {
        if let Some(ref secret) = cfg.psk_secret {
            lines.push(format!("STONE_PSK_SECRET={}", secret));
        }
        lines.push("STONE_P2P_PSK_DISABLED=0".into());
    } else {
        lines.push("STONE_P2P_PSK_DISABLED=1".into());
    }

    lines.push("".into());
    lines.push("# ── TLS ─────────────────────────────────────────────────────────────────".into());
    lines.push("# Zertifikate werden automatisch verwaltet (Embedded-CA).".into());
    lines.push("# Für Cluster-Betrieb: stone_data/tls/root.crt + root.key auf alle Nodes kopieren.".into());
    lines.push(format!("STONE_TLS_CERT={}/tls/node.crt", cfg.data_dir.display()));
    lines.push(format!("STONE_TLS_KEY={}/tls/node.key", cfg.data_dir.display()));

    let content = lines.join("\n") + "\n";
    fs::write(".env", &content).unwrap_or_else(|e| {
        eprintln!("{} .env konnte nicht geschrieben werden: {e}", style("✗").red());
        std::process::exit(1);
    });

    pb.finish_with_message(format!("{} .env geschrieben.", style("✓").green()));
}

// ─── Bootstrap-Peers pingen ──────────────────────────────────────────────────

fn check_bootstrap_peers(peers: &[String]) {
    println!("\n{}", style("── Erreichbarkeits-Check ─────────────────────────────────────────").dim());

    let pb = ProgressBar::new(peers.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} [{bar:30.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap()
        .progress_chars("━─ "),
    );

    let mut reachable = 0usize;

    for peer in peers {
        pb.set_message(format!("Prüfe {}…", peer));

        let health_url = format!(
            "{}/api/v1/health",
            peer.trim_end_matches('/')
        );

        let ok = std::process::Command::new("curl")
            .args(["-sf", "--max-time", "4", &health_url])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if ok {
            pb.println(format!("  {} {}", style("✓").green(), style(peer).cyan()));
            reachable += 1;
        } else {
            pb.println(format!("  {} {} (nicht erreichbar)", style("✗").red(), style(peer).dim()));
        }

        pb.inc(1);
        std::thread::sleep(Duration::from_millis(200));
    }

    pb.finish_and_clear();

    if reachable == 0 && !peers.is_empty() {
        println!(
            "\n{} Kein Bootstrap-Peer erreichbar — der Node startet im Standalone-Modus.",
            style("ℹ").yellow()
        );
        println!("{}", style("  (Das ist ok für lokale Entwicklung)").dim());
    } else {
        println!(
            "\n{} {}/{} Peer(s) erreichbar.",
            style("✓").green(),
            reachable,
            peers.len()
        );
    }
}

// ─── Node starten ────────────────────────────────────────────────────────────

fn launch_node() {
    println!("\n{}", style("── Node wird gestartet ───────────────────────────────────────────").cyan());

    // Zuerst binary prüfen
    let bin = if Path::new("./target/release/stone-master").exists() {
        "./target/release/stone-master"
    } else if Path::new("./target/debug/stone-master").exists() {
        "./target/debug/stone-master"
    } else {
        println!("{} Kein kompiliertes Binary gefunden.", style("!").yellow());
        println!("Bitte zuerst ausführen: {}", style("cargo build --release --bin stone-master").green());
        return;
    };

    println!("{} Starte: {}", style("▶").cyan(), style(bin).green());
    println!("{}", style("(Ctrl+C zum Beenden)").dim());
    println!();

    // Stdin/Stdout/Stderr erben → interaktives Erlebnis
    let status = Command::new(bin)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("{} Fehler beim Starten: {e}", style("✗").red());
            std::process::exit(1);
        });

    if !status.success() {
        eprintln!("{} Node beendet mit Code: {}", style("✗").red(), status);
    }
}

// ─── Banner + UI-Helpers ──────────────────────────────────────────────────────

/// Liest relevante Werte aus .env und zeigt eine kompakte Zusammenfassung.
fn show_existing_config_summary() {
    let Ok(content) = fs::read_to_string(".env") else { return };

    let get = |key: &str| -> String {
        content
            .lines()
            .find(|l| l.starts_with(&format!("{key}=")))
            .and_then(|l| l.splitn(2, '=').nth(1))
            .unwrap_or("–")
            .to_string()
    };

    println!("{}", style("  ── Vorhandene Konfiguration ─────────────────────────────────────────").dim());
    kv("Node-Name",  &get("STONE_NODE_NAME"));
    kv("Port",       &get("STONE_PORT"));
    kv("Data-Dir",   &get("STONE_DATA_DIR"));
    let key = get("STONE_CLUSTER_API_KEY");
    let short_key = if key.len() > 14 { format!("{}…", &key[..14]) } else { key };
    kv("API-Key",    &short_key);
    let psk_dis = get("STONE_P2P_PSK_DISABLED");
    kv("PSK/pnet",   if psk_dis == "1" { "deaktiviert" } else { "aktiv" });
    println!();
}

/// Gibt alle gesetzten (nicht-kommentierten) Zeilen aus .env aus.
fn show_full_env() {
    let Ok(content) = fs::read_to_string(".env") else {
        println!("{} .env nicht gefunden.", style("✗").red());
        return;
    };
    println!("\n{}", style("  ── .env Inhalt ──────────────────────────────────────────────────────").cyan());
    for line in content.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        // API-Keys/Secrets kürzen
        if let Some((k, v)) = line.splitn(2, '=').collect::<Vec<_>>().as_slice().split_first() {
            let k = *k;
            let v = v.join("=");
            let display_val = if k.contains("KEY") || k.contains("SECRET") || k.contains("PASSWORD") {
                if v.len() > 14 { format!("{}…", &v[..14]) } else { v }
            } else {
                v
            };
            println!("    {:<30} {}", style(k).dim(), style(display_val).cyan());
        }
    }
    println!();
}

fn print_banner() {
    println!("{}", style(r#"
  ███████╗████████╗ ██████╗ ███╗   ██╗███████╗
  ██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
  ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
  ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
  ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝
    "#).cyan().bold());
    println!("{}", style("  Setup-Wizard — StoneChain Master Node").bold());
    println!("{}", style("  ─────────────────────────────────────────────────").dim());
    println!();
    println!("{}", style("  Dieser Wizard führt dich durch die Erstkonfiguration.").dim());
    println!("{}", style("  Alle Einstellungen werden in '.env' gespeichert.").dim());
    println!();
}

fn section(step: &str, title: &str) {
    println!();
    println!(
        "{}  {}",
        style(format!("  ── Schritt {step} ──")).cyan().bold(),
        style(title).bold()
    );
    println!();
}

fn print_summary(cfg: &Config) {
    println!();
    println!("{}", style("  ── Zusammenfassung ──────────────────────────────────────────────────").cyan().bold());
    println!();
    kv("Data-Directory",  &cfg.data_dir.display().to_string());
    kv("HTTP-Port",       &cfg.http_port.to_string());
    kv("Node-Name",       &cfg.node_name);
    kv("Max. Storage",    &if cfg.max_storage_gb == 0 { "unbegrenzt".into() } else { format!("{} GB", cfg.max_storage_gb) });
    kv("Bootstrap-Peers", &if cfg.bootstrap_peers.is_empty() { "keine (standalone)".to_string() } else { cfg.bootstrap_peers.join(", ") });
    kv("P2P-Port",        &cfg.p2p_port.to_string());
    kv("PSK / pnet",      if cfg.psk_enabled { "aktiviert" } else { "deaktiviert" });
    kv("API-Key",         &format!("{}…", &cfg.api_key[..12.min(cfg.api_key.len())]));
    kv("TLS",             "aktiv (Embedded-CA, auto-verwaltet)");
    println!();
}

fn kv(key: &str, val: &str) {
    println!(
        "    {:<22} {}",
        style(key).dim(),
        style(val).cyan()
    );
}

// ─── Kryptographische Hilfsfunktionen ─────────────────────────────────────────

/// Generiert `n` zufällige Bytes als lowercase Hex-String.
fn generate_hex(n: usize) -> String {
    let bytes: Vec<u8> = (0..n).map(|_| rand::thread_rng().gen::<u8>()).collect();
    hex::encode(bytes)
}
