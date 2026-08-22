//! Reports what chain a set of Bitcoin Core block files actually contains.
//!
//! Written for one specific job: after a `blk00000.dat` was destroyed and
//! rebuilt from the network, something had to answer "does the replacement
//! really join up with the surviving archive, and at what height?" — before
//! committing to a 12-to-30-hour reindex on the strength of a guess.
//!
//! It reads only the 88-byte prefix of each record, so it can answer that in
//! seconds rather than by parsing hundreds of megabytes of transactions.
//!
//! ```text
//! cargo run --release -p blk-scan -- <blocks-dir> [file ...]
//! ```
//!
//! With no files named, it scans `blk00000.dat` and `blk00001.dat` — the two
//! that matter for checking a rebuilt first file against the archive.

use blk_scan::obfuscation::ObfuscationKey;
use blk_scan::scan;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);

    let blocks_dir = PathBuf::from(
        args.next()
            .ok_or("usage: blk-scan <blocks-dir> [file ...]")?,
    );

    let files: Vec<String> = {
        let named: Vec<String> = args.collect();
        if named.is_empty() {
            vec!["blk00000.dat".to_owned(), "blk00001.dat".to_owned()]
        } else {
            named
        }
    };

    let key = ObfuscationKey::from_blocks_dir(&blocks_dir)?;
    println!("blocks dir : {}", blocks_dir.display());
    println!(
        "xor key    : {}\n",
        if key.is_active() { key.to_hex() } else { "(none - unobfuscated)".to_owned() }
    );

    let mut all = Vec::new();

    for name in &files {
        let path = blocks_dir.join(name);
        if !path.exists() {
            println!("{name:<16} MISSING");
            continue;
        }

        let scan = scan::scan_file(&path, key)?;
        let size = std::fs::metadata(&path)?.len();

        println!(
            "{name:<16} {:>7} blocks   {:>13} bytes   stopped at {} ({:?})",
            scan.records.len(),
            size,
            scan.stopped_at,
            scan.reason
        );

        // The first and last record positions say whether the file is packed
        // end to end or has stopped early, which is what matters when checking
        // that a rebuilt file reaches far enough to meet the next one.
        if let (Some(first), Some(last)) = (scan.records.first(), scan.records.last()) {
            println!("  first block at offset {:>10}  {}", first.offset, first.hash);
            println!("  last  block at offset {:>10}  {} ({} bytes)", last.offset, last.hash, last.size);
        }

        // A file that ends in anything but padding or a clean EOF is the one
        // thing worth shouting about.
        if let scan::StopReason::Corrupt { found } = &scan.reason {
            println!("  !! unexpected bytes {found} at offset {} !!", scan.stopped_at);
        }

        all.extend(scan.records);
    }

    println!("\n--- combined ---");
    let summary = scan::summarise(&all);

    println!("blocks found     : {}", summary.blocks);
    println!("genesis present  : {}", summary.has_genesis);
    println!("orphan roots     : {}", summary.orphan_roots);

    match (summary.tip_height, summary.tip_hash) {
        (Some(height), Some(hash)) => {
            println!("connected chain  : genesis -> height {height}");
            println!("tip hash         : {hash}");
            println!(
                "\n{} blocks are reachable from genesis; {} are not.",
                summary.connected,
                summary.blocks - summary.connected
            );
        }
        _ => println!("connected chain  : none (genesis absent from this set)"),
    }

    Ok(())
}
