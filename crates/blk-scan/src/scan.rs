//! Reading the block records inside a `blk*.dat` file.
//!
//! The format is a flat sequence of records, with no index and no footer:
//!
//! ```text
//!   [4 bytes magic f9beb4d9] [4 bytes size, LE] [size bytes of block]
//!   [4 bytes magic f9beb4d9] [4 bytes size, LE] [size bytes of block]
//!   ...
//!   [zero padding to the end of the preallocated file]
//! ```
//!
//! Two things follow from that shape, and both matter here:
//!
//! - **Order is arrival order, not height order.** Core writes each block as it
//!   is received, and during initial sync blocks arrive from several peers at
//!   once. A file is not a contiguous run of heights, which is why the chain
//!   has to be reconstructed by following `prev_block` links rather than
//!   assumed from position.
//! - **Only the first 88 bytes of each record are read here.** The magic, the
//!   size, and the 80-byte header are enough to identify a block and link it to
//!   its parent; the transactions are skipped over. That turns scanning a
//!   134 MB file into a few thousand small reads instead of 134 MB of parsing.

use btc_primitives::{BlockHeader, Sha256dHash};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::obfuscation::ObfuscationKey;

/// Bitcoin mainnet's message-start bytes, which prefix every record.
pub const MAINNET_MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

/// One block found in a file.
#[derive(Debug, Clone)]
pub struct BlockRecord {
    /// Byte offset of the record's magic within the file.
    pub offset: u64,
    /// Declared size of the block that follows the length field.
    pub size: u32,
    /// The block's hash.
    pub hash: Sha256dHash,
    /// Its parent's hash.
    pub previous: Sha256dHash,
}

/// Everything a scan found in one file.
#[derive(Debug)]
pub struct FileScan {
    /// The blocks, in the order they appear on disk.
    pub records: Vec<BlockRecord>,
    /// Offset at which scanning stopped.
    pub stopped_at: u64,
    /// Why it stopped.
    pub reason: StopReason,
}

/// Why a scan ended.
#[derive(Debug, PartialEq, Eq)]
pub enum StopReason {
    /// Reached the end of the file cleanly.
    EndOfFile,
    /// Hit the zero padding Core preallocates after the last block. Normal.
    Padding,
    /// Found bytes that were neither a record nor padding. Suspicious.
    Corrupt {
        /// What was there instead of the magic.
        found: String,
    },
}

/// Scans one block file, returning every block record it contains.
pub fn scan_file(path: &Path, key: ObfuscationKey) -> std::io::Result<FileScan> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    let mut reader = BufReader::new(file);

    let mut records = Vec::new();
    let mut offset = 0u64;

    loop {
        // A record needs at least a magic, a length, and an 80-byte header.
        if offset + 88 > length {
            return Ok(FileScan { records, stopped_at: offset, reason: StopReason::EndOfFile });
        }

        let mut prefix = [0u8; 8];
        reader.seek(SeekFrom::Start(offset))?;
        reader.read_exact(&mut prefix)?;
        key.apply(&mut prefix, offset);

        let magic = &prefix[..4];

        if magic == [0u8; 4] {
            // Preallocated space after the final block.
            return Ok(FileScan { records, stopped_at: offset, reason: StopReason::Padding });
        }
        if magic != MAINNET_MAGIC {
            return Ok(FileScan {
                records,
                stopped_at: offset,
                reason: StopReason::Corrupt { found: btc_primitives::hex::encode(magic) },
            });
        }

        let size = u32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);

        let mut header_bytes = [0u8; 80];
        reader.read_exact(&mut header_bytes)?;
        key.apply(&mut header_bytes, offset + 8);

        let header = BlockHeader::deserialize(&header_bytes);
        records.push(BlockRecord {
            offset,
            size,
            hash: header.hash(),
            previous: header.prev_block,
        });

        // Skip the transactions; only the header was needed.
        offset += 8 + u64::from(size);
    }
}

/// What a set of block records adds up to as a chain.
#[derive(Debug)]
pub struct ChainSummary {
    /// How many distinct blocks were found.
    pub blocks: usize,
    /// Whether the genesis block is present.
    pub has_genesis: bool,
    /// How many blocks are reachable by walking forward from genesis.
    pub connected: usize,
    /// The height reached, if genesis was present.
    pub tip_height: Option<usize>,
    /// The hash at that height.
    pub tip_hash: Option<Sha256dHash>,
    /// Blocks whose parent is not in this set and which are not genesis.
    ///
    /// One is expected when scanning a file that continues from an earlier one.
    /// Many means the set is fragmented.
    pub orphan_roots: usize,
}

/// Bitcoin mainnet's genesis block hash, in display form.
pub const GENESIS: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/// Works out what chain a collection of records represents.
pub fn summarise(records: &[BlockRecord]) -> ChainSummary {
    use std::collections::{HashMap, HashSet};
    use std::str::FromStr;

    let genesis = Sha256dHash::from_str(GENESIS).expect("valid constant");

    let present: HashSet<Sha256dHash> = records.iter().map(|record| record.hash).collect();

    // Parent -> child. Forks would make this many-valued; on the main chain in
    // practice it is one child per parent, and taking the first is enough to
    // measure coverage.
    let mut children: HashMap<Sha256dHash, Sha256dHash> = HashMap::new();
    for record in records {
        children.entry(record.previous).or_insert(record.hash);
    }

    let orphan_roots = records
        .iter()
        .filter(|record| record.hash != genesis && !present.contains(&record.previous))
        .count();

    let has_genesis = present.contains(&genesis);
    if !has_genesis {
        return ChainSummary {
            blocks: present.len(),
            has_genesis: false,
            connected: 0,
            tip_height: None,
            tip_hash: None,
            orphan_roots,
        };
    }

    // Walk forward from genesis for as far as the records allow.
    let mut current = genesis;
    let mut height = 0usize;
    while let Some(next) = children.get(&current) {
        current = *next;
        height += 1;
    }

    ChainSummary {
        blocks: present.len(),
        has_genesis: true,
        connected: height + 1,
        tip_height: Some(height),
        tip_hash: Some(current),
        orphan_roots,
    }
}
