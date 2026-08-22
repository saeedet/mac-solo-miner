//! Joins block files into one, re-keying the obfuscation as it goes.
//!
//! ```text
//! cargo run --release --bin blk-concat -- <blocks-dir> <output> <file> [file ...]
//! ```
//!
//! # Why this is not `cat`
//!
//! Two reasons, and both would produce a silently broken file if ignored.
//!
//! **The obfuscation key is position-dependent.** Core XORs byte `i` of a file
//! with `key[i % 8]`. Appending file B to file A shifts every one of B's bytes
//! to a new offset, so unless the join lands on a multiple of 8 the key no
//! longer lines up. Each byte has to be decoded at its old position and
//! re-encoded at its new one.
//!
//! **Block files end in preallocated zero padding.** Core sizes files in 16 MiB
//! chunks, so the tail after the last block is zeros. Copying that padding into
//! the middle of the output would look like end-of-data to every reader,
//! including Core — everything after it would be invisible. So each input is
//! copied only as far as its last real block record, which is what
//! [`scan::scan_file`] reports.

use blk_scan::obfuscation::ObfuscationKey;
use blk_scan::scan;

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Copy buffer size. Large enough that USB throughput dominates, small enough
/// to stay off the stack.
const CHUNK: usize = 1 << 20;

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
            .ok_or("usage: blk-concat <blocks-dir> <output> <file> [file ...]")?,
    );
    let output_path = PathBuf::from(args.next().ok_or("missing output path")?);
    let inputs: Vec<String> = args.collect();

    if inputs.is_empty() {
        return Err("no input files given".into());
    }

    let key = ObfuscationKey::from_blocks_dir(&blocks_dir)?;
    println!("key    : {}", key.to_hex());
    println!("output : {}\n", output_path.display());

    let mut output = BufWriter::new(File::create(&output_path)?);
    let mut written = 0u64;

    for name in &inputs {
        let path = blocks_dir.join(name);

        // Find where the real records stop, so the padding is left behind.
        let summary = scan::scan_file(&path, key)?;
        let payload = summary.stopped_at;

        println!(
            "{name:<16} {:>7} blocks  copying {payload} bytes from offset 0 -> {written}",
            summary.records.len()
        );

        let mut input = File::open(&path)?;
        input.seek(SeekFrom::Start(0))?;

        let mut buffer = vec![0u8; CHUNK];
        let mut copied = 0u64;

        while copied < payload {
            let want = CHUNK.min((payload - copied) as usize);
            input.read_exact(&mut buffer[..want])?;

            // Decode at the source position, re-encode at the destination.
            // Doing both explicitly is slower than computing a combined mask,
            // and much easier to be sure of.
            key.apply(&mut buffer[..want], copied);
            key.apply(&mut buffer[..want], written);

            output.write_all(&buffer[..want])?;

            copied += want as u64;
            written += want as u64;
        }
    }

    output.flush()?;
    println!("\nwrote {written} bytes");
    Ok(())
}
