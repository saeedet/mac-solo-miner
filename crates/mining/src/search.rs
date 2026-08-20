//! The nonce search — the loop that actually does the mining.
//!
//! Everything else in this project exists to set up this function. It takes a
//! header, tries nonces, and stops when one produces a hash at or below the
//! target.
//!
//! ```text
//!   for nonce in range:
//!       header.nonce = nonce
//!       if sha256d(header) <= target:
//!           you have found a block
//! ```
//!
//! There is no cleverness available. The hash is unpredictable by design, so
//! there is no way to steer toward a solution, no partial progress, and nothing
//! learned from a failed attempt. Mining is a memoryless search: every nonce is
//! an independent trial, which is exactly why stopping and restarting a miner
//! costs nothing.
//!
//! This version re-hashes all 80 bytes every attempt. Phase 5 will exploit the
//! fact that the first 64 bytes never change within a search, and precompute
//! their compression once (the "midstate").

use btc_primitives::header::NONCE_OFFSET;
use btc_primitives::{BlockHeader, Sha256dHash, Target};

/// What a search found.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The winning nonce, if the target was met.
    pub solution: Option<Solution>,
    /// How many hashes were computed. Used for hashrate reporting.
    pub hashes: u64,
    /// The lowest hash seen, and the nonce that produced it.
    ///
    /// This is the "how close did I get" figure. It is not consensus-relevant
    /// in solo mining — a near miss is worth precisely nothing — but it is the
    /// only feedback a solo miner ever gets, and Phase 7 surfaces it.
    pub best: Sha256dHash,
    /// The nonce that produced [`Self::best`].
    pub best_nonce: u32,
}

/// A header that meets its target.
#[derive(Debug, Clone, Copy)]
pub struct Solution {
    /// The nonce that solved it.
    pub nonce: u32,
    /// The resulting block hash.
    pub hash: Sha256dHash,
}

/// Tries every nonce in `range`, stopping early if one solves the block.
///
/// `header`'s nonce field is ignored; the range supplies it.
pub fn search(header: &BlockHeader, target: &Target, range: std::ops::Range<u32>) -> SearchResult {
    // Serialise once and overwrite four bytes per attempt, rather than
    // rebuilding all 80 bytes each time.
    let mut bytes = header.serialize();

    let mut hashes = 0u64;
    let mut best = Sha256dHash::from_internal_bytes([0xFF; 32]);
    let mut best_nonce = 0u32;

    for nonce in range {
        bytes[NONCE_OFFSET..].copy_from_slice(&nonce.to_le_bytes());

        let hash = Sha256dHash::hash(&bytes);
        hashes += 1;

        // Display order is big-endian, so this is a numeric comparison.
        if hash.to_display_bytes() < best.to_display_bytes() {
            best = hash;
            best_nonce = nonce;
        }

        if target.is_met_by(&hash) {
            return SearchResult {
                solution: Some(Solution { nonce, hash }),
                hashes,
                best: hash,
                best_nonce: nonce,
            };
        }
    }

    SearchResult {
        solution: None,
        hashes,
        best,
        best_nonce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Re-mining the genesis block: given its header and an empty nonce, the
    /// search must land on the nonce Satoshi found.
    ///
    /// A real end-to-end proof of the search loop, at difficulty 1.
    #[test]
    fn rediscovers_the_genesis_nonce() {
        let header = BlockHeader {
            version: 1,
            prev_block: Sha256dHash::ZERO,
            merkle_root: Sha256dHash::from_str(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            )
            .expect("valid"),
            time: 1_231_006_505,
            bits: 0x1d00_ffff,
            nonce: 0,
        };
        let target = header.target().expect("valid bits");

        // Start just below the known answer so the test stays fast.
        let known = 2_083_236_893;
        let result = search(&header, &target, known - 500..known + 1);

        let solution = result.solution.expect("the genesis nonce is in range");
        assert_eq!(solution.nonce, known);
        assert_eq!(
            solution.hash.to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    /// An exhausted range reports no solution but still counts its work.
    #[test]
    fn exhausted_range_reports_progress() {
        let header = BlockHeader {
            version: 1,
            prev_block: Sha256dHash::ZERO,
            merkle_root: Sha256dHash::ZERO,
            time: 0,
            // Difficulty far beyond anything reachable in a test.
            bits: 0x0300_0001,
            nonce: 0,
        };
        let target = header.target().expect("valid bits");

        let result = search(&header, &target, 0..1000);

        assert!(result.solution.is_none());
        assert_eq!(result.hashes, 1000);
        // Something must have been the best of the thousand.
        assert_ne!(result.best, Sha256dHash::from_internal_bytes([0xFF; 32]));
    }
}
