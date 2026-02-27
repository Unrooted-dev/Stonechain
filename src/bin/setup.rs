//! stone-setup — Interaktiver Setup-Wizard (Streamlined)
//!
//! Beim **ersten Start** (keine .env vorhanden):
//!   1. Node-Name eingeben (oder Hostname übernehmen)
//!   2. Seed-Peers eingeben (Multiaddr von bestehenden Nodes)
//!   → Alles andere wird automatisch generiert:
//!     - Admin API-Key
//!     - P2P-Keypair
//!     - Ports (8080 HTTP, 4001 P2P)
//!     - .env Datei
//!   → Node wird gestartet, verbindet sich, holt Peer-Liste, fertig.
//!
//! Bei **weiteren Starts** (.env vorhanden):
//!   - 🚀 Direkt starten
//!   - 🔧 Konfiguration anpassen (einzelne Werte ändern)
//!   - 🔄 Komplett neu konfigurieren (Wizard erneut)
//!   - ❌ Beenden

use std::{
    collections::HashSet,
    fs,
    net::TcpStream,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use console::{style, Term};
use dialoguer::{
    theme::ColorfulTheme, Confirm, FuzzySelect, Input, MultiSelect,
};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;

// ─── Vordefinierte Seed-Nodes ────────────────────────────────────────────────

const WELL_KNOWN_SEEDS: &[(&str, &str)] = &[
    (
        "stone-seed-1  (unrootles / Tailscale)",
        "/ip4/100.90.28.68/tcp/4001/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd",
    ),
];

// ─── Config-Struct ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct Config {
    data_dir:       PathBuf,
    http_port:      u16,
    node_name:      String,
    max_storage_gb: u32,
    seed_peers:     Vec<String>,
    p2p_port:       u16,
    api_key:        String,
}

// ─── Einstiegspunkt ──────────────────────────────────────────────────────────

fn main() {
    let term = Term::stdout();
    let _ = term.clear_screen();

    print_banner();

    let env_exists = Path::new(".env").exists();

    if env_exists {
        handle_existing_config();
    } else {
        println!(
            "{} Willkommen! Keine Konfiguration gefunden — Setup-Wizard wird gestartet.\n",
            style("ℹ").cyan()
        );
        run_first_time_wizard();
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ERSTER START — Minimaler Wizard (nur Node-Name + Seed-Peers)
// ═════════════════════════════════════════════════════════════════════════════

fn run_first_time_wizard() {
    println!(
        "{}",
        style("  Du musst nur 2 Dinge angeben — alles andere wird automatisch eingerichtet.")
            .dim()
    );
    println!();

    // ── Schritt 1: Node-Name ──────────────────────────────────────────────────
    section("1 / 2", "Node-Name");
    println!(
        "{}",
        style("  Der Name identifiziert deinen Node im Netzwerk.").dim()
    );
    println!();

    let default_name = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "stone-node".into());

    let node_name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Node-Name")
        .default(default_name)
        .interact_text()
        .unwrap();
    println!(
        "{} Node-Name: {}",
        style("✓").green(),
        style(&node_name).cyan()
    );

    // ── Schritt 2: Seed-Peers ─────────────────────────────────────────────────
    section("2 / 2", "Seed-Peers (Netzwerk-Einstieg)");
    println!(
        "{}",
        style("  Wähle mindestens einen Seed-Node um dem Netzwerk beizutreten.").dim()
    );
    println!(
        "{}",
        style("  Die Peer-Liste wird danach automatisch vom Netzwerk synchronisiert.").dim()
    );
    println!();

    let seed_peers = select_seed_peers();

    // ── Alles andere automatisch generieren ───────────────────────────────────
    println!();
    println!(
        "{}",
        style("  ── Automatische Konfiguration ──────────────────────────────────────")
            .cyan()
            .bold()
    );
    println!();

    let data_dir = PathBuf::from("./stone_data");
    let http_port: u16 = 8080;
    let p2p_port: u16 = 4001;
    let max_storage_gb: u32 = 0; // unbegrenzt
    let api_key = format!("sk_{}", generate_hex(32));

    fs::create_dir_all(&data_dir).unwrap_or_else(|e| {
        eprintln!(
            "{} Verzeichnis konnte nicht erstellt werden: {e}",
            style("✗").red()
        );
        std::process::exit(1);
    });

    auto_step("Data-Directory", &format!("{}", data_dir.display()));
    auto_step("HTTP-Port", &http_port.to_string());
    auto_step("P2P-Port", &p2p_port.to_string());
    auto_step("Speicher", "unbegrenzt");
    auto_step("PSK/pnet", "deaktiviert (offenes Netzwerk)");
    auto_step("API-Key", &format!("{}…", &api_key[..14]));

    let config = Config {
        data_dir,
        http_port,
        node_name,
        max_storage_gb,
        seed_peers,
        p2p_port,
        api_key,
    };

    // ── .env schreiben ────────────────────────────────────────────────────────
    write_env(&config);

    // ── Zusammenfassung ───────────────────────────────────────────────────────
    print_summary(&config);

    // ── Erreichbarkeit prüfen ─────────────────────────────────────────────────
    if !config.seed_peers.is_empty() {
        println!();
        check_seed_peers(&config.seed_peers);
    }

    // ── Node starten ──────────────────────────────────────────────────────────
    println!();
    let info_text = if config.seed_peers.is_empty() {
        "Node startet im Standalone-Modus (keine Seed-Peers)."
    } else {
        "Node startet, verbindet sich mit dem Netzwerk und synchronisiert die Peer-Liste automatisch."
    };
    println!("{} {}", style("ℹ").cyan(), style(info_text).dim());
    println!();

    let start = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Node jetzt starten?")
        .default(true)
        .interact()
        .unwrap_or(false);

    if start {
        launch_node();
    } else {
        print_manual_start_hint();
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// BESTEHENDE CONFIG — Menü mit Optionen
// ═════════════════════════════════════════════════════════════════════════════

fn handle_existing_config() {
    show_existing_config_summary();

    let options = &[
        "🚀  Node direkt starten",
        "🔧  Konfiguration anpassen",
        "🔄  Komplett neu konfigurieren (Wizard)",
        "📋  Konfiguration anzeigen",
        "❌  Beenden",
    ];
    let choice = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Was möchtest du tun?")
        .items(options)
        .default(0)
        .interact()
        .unwrap_or(4);

    match choice {
        0 => {
            println!(
                "\n{} Bestehende Konfiguration wird verwendet.",
                style("✓").green()
            );
            launch_node();
        }
        1 => adjust_config(),
        2 => {
            println!(
                "\n{} Bestehende .env wird überschrieben.\n",
                style("ℹ").cyan()
            );
            run_first_time_wizard();
        }
        3 => {
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
        }
        _ => {
            println!("\n{} Abgebrochen.", style("ℹ").dim());
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// KONFIGURATION ANPASSEN — Einzelne Werte ändern
// ═════════════════════════════════════════════════════════════════════════════

fn adjust_config() {
    println!();
    println!(
        "{}",
        style("  ── Konfiguration anpassen ──────────────────────────────────────────")
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("  Wähle was du ändern möchtest. Leere Eingabe = Wert beibehalten.").dim()
    );
    println!();

    let adjustable = &[
        "Node-Name",
        "HTTP-Port",
        "P2P-Port",
        "Seed-Peers",
        "API-Key neu generieren",
        "Max. Speicher (GB)",
        "← Zurück",
    ];

    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Was anpassen? (Leertaste = auswählen, Enter = bestätigen)")
        .items(adjustable)
        .interact()
        .unwrap_or_default();

    if selections.is_empty() || selections.contains(&6) {
        println!("{} Nichts geändert.", style("ℹ").dim());
        handle_existing_config();
        return;
    }

    let env_content = fs::read_to_string(".env").unwrap_or_default();
    let mut changes: Vec<(String, String)> = Vec::new();

    for &idx in &selections {
        match idx {
            0 => {
                let current = extract_env_val(&env_content, "STONE_NODE_NAME");
                let new_val: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Neuer Node-Name")
                    .default(current)
                    .interact_text()
                    .unwrap();
                changes.push(("STONE_NODE_NAME".into(), new_val.clone()));
                changes.push(("STONE_NODE_ID".into(), new_val));
            }
            1 => {
                let current: u16 = extract_env_val(&env_content, "STONE_PORT")
                    .parse()
                    .unwrap_or(8080);
                let new_val: u16 = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Neuer HTTP-Port")
                    .default(current)
                    .interact_text()
                    .unwrap();
                changes.push(("STONE_PORT".into(), new_val.to_string()));
            }
            2 => {
                let current: u16 = extract_env_val(&env_content, "STONE_P2P_PORT")
                    .parse()
                    .unwrap_or(4001);
                let new_val: u16 = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Neuer P2P-Port")
                    .default(current)
                    .interact_text()
                    .unwrap();
                changes.push(("STONE_P2P_PORT".into(), new_val.to_string()));
                changes.push((
                    "STONE_P2P_LISTEN".into(),
                    format!("/ip4/0.0.0.0/tcp/{new_val}"),
                ));
            }
            3 => {
                println!();
                let peers = select_seed_peers();
                if !peers.is_empty() {
                    changes.push(("STONE_SEED_NODES".into(), peers.join(",")));
                }
            }
            4 => {
                let new_key = format!("sk_{}", generate_hex(32));
                println!(
                    "{} Neuer API-Key: {}…",
                    style("✓").green(),
                    style(&new_key[..14]).cyan()
                );
                changes.push(("STONE_CLUSTER_API_KEY".into(), new_key.clone()));
                changes.push(("STONE_API_KEY".into(), new_key));
            }
            5 => {
                let current: u32 = {
                    let bytes_str = extract_env_val(&env_content, "STONE_MAX_STORAGE_BYTES");
                    let bytes: u64 = bytes_str.parse().unwrap_or(0);
                    (bytes / 1_073_741_824) as u32
                };
                let new_val: u32 = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Max. Speicher in GB (0 = unbegrenzt)")
                    .default(current)
                    .interact_text()
                    .unwrap();
                let bytes = if new_val == 0 { 0u64 } else { new_val as u64 * 1024 * 1024 * 1024 };
                changes.push(("STONE_MAX_STORAGE_BYTES".into(), bytes.to_string()));
            }
            _ => {}
        }
    }

    if changes.is_empty() {
        println!("{} Nichts geändert.", style("ℹ").dim());
    } else {
        let mut content = env_content;
        for (key, val) in &changes {
            content = patch_env_line(&content, key, val);
        }
        fs::write(".env", &content).unwrap_or_else(|e| {
            eprintln!("{} .env konnte nicht geschrieben werden: {e}", style("✗").red());
        });
        println!();
        println!(
            "{} {} Wert(e) in .env aktualisiert.",
            style("✓").green(),
            changes.len()
        );
    }

    println!();
    let start = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Node jetzt starten?")
        .default(true)
        .interact()
        .unwrap_or(false);

    if start {
        launch_node();
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SEED-PEER AUSWAHL
// ═════════════════════════════════════════════════════════════════════════════

fn select_seed_peers() -> Vec<String> {
    let mut labels: Vec<String> = WELL_KNOWN_SEEDS
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    labels.push("✏️  Eigene Adresse eingeben…".into());

    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Seed-Nodes (Leertaste = auswählen, Enter = bestätigen)")
        .items(&labels)
        .interact()
        .unwrap_or_default();

    let mut peers: Vec<String> = Vec::new();
    let mut needs_custom = false;

    for idx in &selections {
        if *idx < WELL_KNOWN_SEEDS.len() {
            peers.push(WELL_KNOWN_SEEDS[*idx].1.to_string());
        } else {
            needs_custom = true;
        }
    }

    if needs_custom || selections.is_empty() {
        if selections.is_empty() {
            println!(
                "{}",
                style("  Keine vordefinierten Peers gewählt. Gib die Adresse eines bestehenden Nodes ein:").yellow()
            );
            println!(
                "{}",
                style("  Format: /ip4/<IP>/tcp/<PORT>/p2p/<PeerId>").dim()
            );
        }
        loop {
            let custom: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Peer-Adresse (leer = fertig)")
                .allow_empty(true)
                .interact_text()
                .unwrap();
            let addr = custom.trim().to_string();
            if addr.is_empty() {
                break;
            }
            if addr.starts_with("/ip4/")
                || addr.starts_with("/ip6/")
                || addr.starts_with("/dns")
            {
                peers.push(addr);
            } else {
                println!(
                    "{} Ungültiges Format. Beispiel: /ip4/1.2.3.4/tcp/4001/p2p/12D3Koo...",
                    style("!").yellow()
                );
            }
        }
    }

    // Deduplizieren
    let peers: Vec<String> = peers
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    if peers.is_empty() {
        println!(
            "{} Keine Seed-Peers — Node startet isoliert (nur mDNS-Discovery).",
            style("ℹ").yellow()
        );
    } else {
        println!(
            "{} {} Seed-Peer(s) konfiguriert:",
            style("✓").green(),
            peers.len()
        );
        for p in &peers {
            println!("   {}", style(p).dim());
        }
    }

    peers
}

// ═════════════════════════════════════════════════════════════════════════════
// .ENV SCHREIBEN
// ═════════════════════════════════════════════════════════════════════════════

fn write_env(cfg: &Config) {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::with_template("{spinner:.cyan} {msg}").unwrap());
    pb.set_message(".env wird geschrieben…");
    pb.enable_steady_tick(Duration::from_millis(80));

    let storage_bytes: u64 = if cfg.max_storage_gb == 0 {
        0
    } else {
        cfg.max_storage_gb as u64 * 1024 * 1024 * 1024
    };

    let seed_str = cfg.seed_peers.join(",");

    let lines: Vec<String> = vec![
        "# ── Stone Node — generiert von stone-setup ─────────────────────────────".into(),
        format!("# Erstellt: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")),
        format!("# Node: {}", cfg.node_name),
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
        "".into(),
        "# ── Seed-Nodes (Netzwerk-Einstieg) ──────────────────────────────────────".into(),
        if seed_str.is_empty() {
            "# STONE_SEED_NODES=".into()
        } else {
            format!("STONE_SEED_NODES={}", seed_str)
        },
        "".into(),
        "# ── PSK / pnet ──────────────────────────────────────────────────────────".into(),
        "STONE_P2P_PSK_DISABLED=1".into(),
        "".into(),
    ];

    let content = lines.join("\n") + "\n";
    fs::write(".env", &content).unwrap_or_else(|e| {
        eprintln!(
            "{} .env konnte nicht geschrieben werden: {e}",
            style("✗").red()
        );
        std::process::exit(1);
    });

    pb.finish_with_message(format!("{} .env geschrieben.", style("✓").green()));
}

// ═════════════════════════════════════════════════════════════════════════════
// SEED-PEER ERREICHBARKEIT
// ═════════════════════════════════════════════════════════════════════════════

fn check_seed_peers(peers: &[String]) {
    println!(
        "{}",
        style("  ── Erreichbarkeits-Check ─────────────────────────────────────────").dim()
    );

    let pb = ProgressBar::new(peers.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} [{bar:30.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("━─ "),
    );

    let mut reachable = 0usize;

    for peer in peers {
        pb.set_message(format!("Prüfe {}…", truncate_addr(peer)));
        let ok = check_multiaddr_reachable(peer);

        if ok {
            pb.println(format!(
                "  {} {}",
                style("✓").green(),
                style(truncate_addr(peer)).cyan()
            ));
            reachable += 1;
        } else {
            pb.println(format!(
                "  {} {} (nicht erreichbar)",
                style("✗").red(),
                style(truncate_addr(peer)).dim()
            ));
        }

        pb.inc(1);
        std::thread::sleep(Duration::from_millis(200));
    }

    pb.finish_and_clear();

    if reachable == 0 && !peers.is_empty() {
        println!(
            "\n{} Kein Seed-Peer erreichbar — Node startet trotzdem und versucht es später erneut.",
            style("ℹ").yellow()
        );
    } else {
        println!(
            "\n{} {}/{} Seed-Peer(s) erreichbar.",
            style("✓").green(),
            reachable,
            peers.len()
        );
    }
}

fn check_multiaddr_reachable(addr: &str) -> bool {
    let parts: Vec<&str> = addr.split('/').collect();
    let mut ip = None;
    let mut port = None;

    for i in 0..parts.len() {
        if (parts[i] == "ip4" || parts[i] == "ip6") && i + 1 < parts.len() {
            ip = Some(parts[i + 1]);
        }
        if parts[i] == "tcp" && i + 1 < parts.len() {
            port = parts[i + 1].parse::<u16>().ok();
        }
    }

    if let (Some(ip), Some(port)) = (ip, port) {
        let target = format!("{ip}:{port}");
        if let Ok(addr) = target.parse() {
            TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
        } else {
            false
        }
    } else {
        false
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// NODE STARTEN
// ═════════════════════════════════════════════════════════════════════════════

fn launch_node() {
    println!(
        "\n{}",
        style("  ── Node wird gestartet ─────────────────────────────────────────────").cyan()
    );

    let bin = if Path::new("./target/release/stone-master").exists() {
        "./target/release/stone-master"
    } else if Path::new("./target/debug/stone-master").exists() {
        "./target/debug/stone-master"
    } else {
        println!(
            "{} Kein kompiliertes Binary gefunden.",
            style("!").yellow()
        );
        println!(
            "  Bitte zuerst: {}",
            style("cargo build --release --bin stone-master").green()
        );
        return;
    };

    println!(
        "{} Starte: {}",
        style("▶").cyan(),
        style(bin).green()
    );
    println!("{}", style("  (Ctrl+C zum Beenden)").dim());
    println!();

    let status = Command::new(bin).status().unwrap_or_else(|e| {
        eprintln!("{} Fehler beim Starten: {e}", style("✗").red());
        std::process::exit(1);
    });

    if !status.success() {
        eprintln!(
            "{} Node beendet mit Code: {}",
            style("✗").red(),
            status
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// .ENV HILFSFUNKTIONEN
// ═════════════════════════════════════════════════════════════════════════════

fn extract_env_opt(content: &str, key: &str) -> Option<String> {
    content
        .lines()
        .find(|l| {
            let t = l.trim();
            !t.starts_with('#') && t.starts_with(&format!("{key}="))
        })
        .and_then(|l| l.splitn(2, '=').nth(1))
        .map(|v| v.to_string())
}

fn extract_env_val(content: &str, key: &str) -> String {
    extract_env_opt(content, key).unwrap_or_default()
}

fn patch_env_line(content: &str, key: &str, val: &str) -> String {
    let prefix = format!("{key}=");
    let mut found = false;
    let lines: Vec<String> = content
        .lines()
        .map(|line| {
            let t = line.trim();
            if !t.starts_with('#') && t.starts_with(&prefix) {
                found = true;
                format!("{key}={val}")
            } else {
                line.to_string()
            }
        })
        .collect();

    let mut result = lines.join("\n");
    if !found {
        if !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(&format!("{key}={val}\n"));
    }
    result
}

// ═════════════════════════════════════════════════════════════════════════════
// UI HELPERS
// ═════════════════════════════════════════════════════════════════════════════

fn print_banner() {
    println!(
        "{}",
        style(
            r#"
  ███████╗████████╗ ██████╗ ███╗   ██╗███████╗
  ██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
  ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
  ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
  ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝
    "#
        )
        .cyan()
        .bold()
    );
    println!("{}", style("  Stone Node — Setup-Wizard").bold());
    println!(
        "{}",
        style("  ─────────────────────────────────────────────────").dim()
    );
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

fn auto_step(label: &str, value: &str) {
    println!(
        "    {} {:<20} {}",
        style("⚙").dim(),
        style(label).dim(),
        style(value).cyan()
    );
}

fn kv(key: &str, val: &str) {
    println!(
        "    {:<22} {}",
        style(key).dim(),
        style(val).cyan()
    );
}

fn show_existing_config_summary() {
    let Ok(content) = fs::read_to_string(".env") else { return };
    let get = |key: &str| extract_env_val(&content, key);

    println!(
        "{}",
        style("  ── Aktuelle Konfiguration ───────────────────────────────────────────").dim()
    );
    kv("Node-Name", &get("STONE_NODE_NAME"));
    kv("HTTP-Port", &get("STONE_PORT"));
    kv("P2P-Port", &get("STONE_P2P_PORT"));
    kv("Data-Dir", &get("STONE_DATA_DIR"));

    let key = get("STONE_CLUSTER_API_KEY");
    let short_key = if key.len() > 14 {
        format!("{}…", &key[..14])
    } else if key.is_empty() {
        "–".into()
    } else {
        key
    };
    kv("API-Key", &short_key);

    let seeds = get("STONE_SEED_NODES");
    let seed_count = if seeds.is_empty() { 0 } else { seeds.split(',').count() };
    kv("Seed-Peers", &format!("{} konfiguriert", seed_count));
    println!();
}

fn show_full_env() {
    let Ok(content) = fs::read_to_string(".env") else {
        println!("{} .env nicht gefunden.", style("✗").red());
        return;
    };
    println!(
        "\n{}",
        style("  ── .env Inhalt ──────────────────────────────────────────────────────").cyan()
    );
    for line in content.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let display_val = if k.contains("KEY") || k.contains("SECRET") || k.contains("TOKEN") {
                if v.len() > 14 { format!("{}…", &v[..14]) } else { v.to_string() }
            } else {
                v.to_string()
            };
            println!(
                "    {:<30} {}",
                style(k).dim(),
                style(display_val).cyan()
            );
        }
    }
    println!();
}

fn print_summary(cfg: &Config) {
    println!();
    println!(
        "{}",
        style("  ── Zusammenfassung ──────────────────────────────────────────────────")
            .cyan()
            .bold()
    );
    println!();
    kv("Node-Name", &cfg.node_name);
    kv("Data-Directory", &cfg.data_dir.display().to_string());
    kv("HTTP-Port", &cfg.http_port.to_string());
    kv("P2P-Port", &cfg.p2p_port.to_string());
    kv(
        "Seed-Peers",
        &if cfg.seed_peers.is_empty() { "keine (standalone)".into() } else { format!("{}", cfg.seed_peers.len()) },
    );
    kv(
        "Max. Speicher",
        &if cfg.max_storage_gb == 0 { "unbegrenzt".into() } else { format!("{} GB", cfg.max_storage_gb) },
    );
    kv("API-Key", &format!("{}…", &cfg.api_key[..14.min(cfg.api_key.len())]));
    println!();
}

fn print_manual_start_hint() {
    println!(
        "\n{}",
        style("╔══════════════════════════════════════════════════╗").cyan()
    );
    println!(
        "{}",
        style("║  Setup abgeschlossen. Node starten mit:          ║").cyan()
    );
    println!(
        "{}",
        style("║                                                  ║").cyan()
    );
    println!(
        "{}  {}  {}",
        style("║").cyan(),
        style("  cargo run --release --bin stone-master         ").green(),
        style("║").cyan()
    );
    println!(
        "{}",
        style("║                                                  ║").cyan()
    );
    println!(
        "{}",
        style("╚══════════════════════════════════════════════════╝").cyan()
    );
}

fn truncate_addr(addr: &str) -> String {
    if addr.len() <= 60 {
        return addr.to_string();
    }
    if let Some(p2p_idx) = addr.rfind("/p2p/") {
        let peer_id = &addr[p2p_idx + 5..];
        let prefix = &addr[..p2p_idx];
        if peer_id.len() > 12 {
            format!("{}/p2p/{}…", prefix, &peer_id[..12])
        } else {
            addr.to_string()
        }
    } else {
        format!("{}…", &addr[..57])
    }
}

fn generate_hex(n: usize) -> String {
    let bytes: Vec<u8> = (0..n).map(|_| rand::thread_rng().gen::<u8>()).collect();
    hex::encode(bytes)
}
