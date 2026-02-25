/// Kleines Debug-Tool: Liest die RocksDB und gibt Block-Count + alle Block-Hashes aus.
/// Ausführen: cargo run --bin db_dump
fn main() {
    dotenvy::dotenv().ok();

    let store = match stone::storage::ChainStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("DB öffnen fehlgeschlagen: {e}");
            std::process::exit(1);
        }
    };

    let summary = store.summary();
    println!("=== Stone DB Dump ===");
    println!("block_count (meta): {}", summary.block_count);
    println!("latest_hash (meta): {}", summary.latest_hash);
    println!("genesis_hash (meta): {}", summary.genesis_hash);
    println!();

    match store.read_all_blocks() {
        Ok(blocks) => {
            println!("Tatsächlich gelesene Blöcke: {}", blocks.len());
            for b in &blocks {
                println!(
                    "  Block #{}: hash={}... docs={} ts={}",
                    b.index,
                    &b.hash[..8.min(b.hash.len())],
                    b.documents.len(),
                    b.timestamp,
                );
            }
        }
        Err(e) => eprintln!("read_all_blocks Fehler: {e}"),
    }
}
