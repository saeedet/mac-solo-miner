//! The 80-byte block header — the only thing mining actually hashes.
//!
//! Every Bitcoin block, from the genesis block to the one mined a minute ago,
//! has a header of exactly this shape and exactly this size:
//!
//! | Offset | Size | Field | Encoding |
//! |---|---|---|---|
//! | 0  | 4  | `version`     | little-endian `i32` |
//! | 4  | 32 | `prev_block`  | internal order |
//! | 36 | 32 | `merkle_root` | internal order |
//! | 68 | 4  | `time`        | little-endian `u32`, Unix seconds |
//! | 72 | 4  | `bits`        | little-endian `u32`, the compact target |
//! | 76 | 4  | `nonce`       | little-endian `u32` |
//!
//! Mining is: serialise this, hash it, check the result against the target,
//! change the nonce, repeat. The 80 bytes never grow and the loop never gets
//! cleverer than that. Everything else in a mining stack — templates, the pool
//! protocol, extranonces — exists to keep this loop supplied with fresh headers
//! once the four nonce bytes have been exhausted.

use crate::hash::Sha256dHash;
use crate::target::{Target, TargetError};

/// A block header is always exactly this many bytes.
pub const HEADER_SIZE: usize = 80;

/// Byte offset of the nonce within a serialised header.
///
/// The mining loop overwrites these four bytes in place rather than
/// re-serialising the whole header each time.
pub const NONCE_OFFSET: usize = 76;

/// A Bitcoin block header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockHeader {
    /// Block version, also carrying soft-fork signalling bits.
    pub version: i32,
    /// Hash of the previous block's header — the link that makes it a chain.
    pub prev_block: Sha256dHash,
    /// Commitment to every transaction in this block.
    pub merkle_root: Sha256dHash,
    /// Block timestamp, Unix seconds. Only loosely constrained by consensus,
    /// which is why it doubles as extra mining entropy.
    pub time: u32,
    /// The difficulty target, in compact form. See [`Target::from_compact`].
    pub bits: u32,
    /// The free-running counter miners increment. Only 2^32 values, which a
    /// modern miner exhausts in well under a second — hence extranonces.
    pub nonce: u32,
}

impl BlockHeader {
    /// Serialises the header to its canonical 80 bytes.
    pub fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];

        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(self.prev_block.as_internal_bytes());
        out[36..68].copy_from_slice(self.merkle_root.as_internal_bytes());
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[NONCE_OFFSET..80].copy_from_slice(&self.nonce.to_le_bytes());

        out
    }

    /// Parses a header from its canonical 80 bytes.
    pub fn deserialize(bytes: &[u8; HEADER_SIZE]) -> Self {
        // Reads a fixed-size little-endian field. Every `expect` here is
        // unreachable: the slice lengths are compile-time constants within a
        // fixed 80-byte array.
        fn le_u32(bytes: &[u8]) -> u32 {
            u32::from_le_bytes(bytes.try_into().expect("4-byte slice"))
        }
        fn hash_at(bytes: &[u8]) -> Sha256dHash {
            Sha256dHash::from_internal_bytes(bytes.try_into().expect("32-byte slice"))
        }

        Self {
            version: le_u32(&bytes[0..4]) as i32,
            prev_block: hash_at(&bytes[4..36]),
            merkle_root: hash_at(&bytes[36..68]),
            time: le_u32(&bytes[68..72]),
            bits: le_u32(&bytes[72..76]),
            nonce: le_u32(&bytes[NONCE_OFFSET..80]),
        }
    }

    /// The block's hash: `sha256d` of the serialised header.
    pub fn hash(&self) -> Sha256dHash {
        Sha256dHash::hash(&self.serialize())
    }

    /// The decoded difficulty target this header claims to meet.
    pub fn target(&self) -> Result<Target, TargetError> {
        Target::from_compact(self.bits)
    }

    /// Whether this header's hash actually meets its own stated target.
    ///
    /// This is the proof-of-work check, and it is the whole of what makes a
    /// block valid *as work* — every other validity rule is about its contents.
    pub fn is_valid_proof_of_work(&self) -> Result<bool, TargetError> {
        Ok(self.target()?.is_met_by(&self.hash()))
    }
}
