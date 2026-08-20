//! The SegWit commitment (BIP 141) that every modern block must carry.
//!
//! SegWit moved signatures out of the transaction body, which raised an
//! obvious question: if witness data is not covered by the merkle root, what
//! stops a miner from serving a block with the witnesses swapped out?
//!
//! The answer is a *second* merkle tree, over witness transaction ids, whose
//! root is committed to inside the coinbase — in an `OP_RETURN` output that
//! costs nothing and that old nodes ignore. That is how SegWit shipped as a
//! soft fork rather than a hard one.
//!
//! # The construction
//!
//! ```text
//! witness_root = merkle_root([0x00 * 32, wtxid_1, wtxid_2, ...])
//! commitment   = sha256d(witness_root || witness_reserved_value)
//! scriptPubKey = OP_RETURN PUSH36 0xaa21a9ed <commitment>
//! ```
//!
//! Two details are easy to get wrong and both are fatal:
//!
//! - The **coinbase's own wtxid is defined as 32 zero bytes** in this tree, not
//!   its actual hash. It has to be: the commitment lives inside the coinbase,
//!   so using the real wtxid would be circular.
//! - The **witness reserved value** is a 32-byte item in the coinbase input's
//!   witness stack. It is free entropy that nothing constrains, and everyone
//!   uses zeros. It must be present and exactly 32 bytes, or Bitcoin Core
//!   rejects the block with `bad-witness-nonce-size`.
//!
//! A useful consequence: the commitment does **not** depend on the coinbase's
//! contents. A miner can change its extranonce or payout freely without
//! recomputing it.

use btc_primitives::{Sha256dHash, merkle};

/// The four bytes that mark an `OP_RETURN` output as a witness commitment.
///
/// Chosen to be recognisable and unlikely to occur by accident. A block may
/// contain several `OP_RETURN` outputs; the commitment is the last one whose
/// pushed data starts with this header.
pub const COMMITMENT_HEADER: [u8; 4] = [0xAA, 0x21, 0xA9, 0xED];

/// The witness reserved value, which is 32 zero bytes by universal convention.
pub const RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// The placeholder wtxid used for the coinbase in the witness merkle tree.
pub const COINBASE_WTXID_PLACEHOLDER: Sha256dHash = Sha256dHash::ZERO;

/// Computes the witness merkle root over a block's transactions.
///
/// `wtxids` must be the non-coinbase transactions, in block order. The coinbase
/// placeholder is prepended here so callers cannot forget it.
pub fn witness_merkle_root(wtxids: &[Sha256dHash]) -> Sha256dHash {
    let mut leaves = Vec::with_capacity(wtxids.len() + 1);
    leaves.push(COINBASE_WTXID_PLACEHOLDER);
    leaves.extend_from_slice(wtxids);

    merkle::merkle_root(&leaves).expect("at least the coinbase placeholder is present")
}

/// Computes the 32-byte commitment value.
pub fn commitment(witness_root: Sha256dHash, reserved_value: &[u8; 32]) -> Sha256dHash {
    let mut buffer = [0u8; 64];
    buffer[..32].copy_from_slice(witness_root.as_internal_bytes());
    buffer[32..].copy_from_slice(reserved_value);
    Sha256dHash::hash(&buffer)
}

/// Builds the complete `scriptPubKey` for the commitment output.
///
/// The result is always 38 bytes: `OP_RETURN`, a 36-byte push, the 4-byte
/// header, and the 32-byte commitment.
pub fn commitment_script(wtxids: &[Sha256dHash]) -> Vec<u8> {
    const OP_RETURN: u8 = 0x6A;
    const PUSH_36: u8 = 0x24;

    let value = commitment(witness_merkle_root(wtxids), &RESERVED_VALUE);

    let mut script = Vec::with_capacity(38);
    script.push(OP_RETURN);
    script.push(PUSH_36);
    script.extend_from_slice(&COMMITMENT_HEADER);
    script.extend_from_slice(value.as_internal_bytes());

    debug_assert_eq!(script.len(), 38);
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::hex;

    /// An empty block's commitment, checked against what bitcoind produced.
    ///
    /// This exact string came from `getblocktemplate` on the project's regtest
    /// node at height 1, so it is ground truth from Bitcoin Core rather than
    /// our own reading of BIP 141.
    #[test]
    fn empty_block_matches_bitcoind() {
        assert_eq!(
            hex::encode(&commitment_script(&[])),
            "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
        );
    }

    /// With no transactions the witness root is just the placeholder, so the
    /// commitment is `sha256d` of 64 zero bytes.
    #[test]
    fn empty_block_root_is_the_placeholder() {
        assert_eq!(witness_merkle_root(&[]), Sha256dHash::ZERO);
        assert_eq!(
            commitment(Sha256dHash::ZERO, &RESERVED_VALUE),
            Sha256dHash::hash(&[0u8; 64])
        );
    }

    #[test]
    fn script_is_always_thirty_eight_bytes() {
        for count in 0..8 {
            let wtxids: Vec<_> = (0..count).map(|n| Sha256dHash::hash(&[n as u8])).collect();
            let script = commitment_script(&wtxids);

            assert_eq!(script.len(), 38);
            assert_eq!(script[0], 0x6A, "OP_RETURN");
            assert_eq!(script[1], 0x24, "36-byte push");
            assert_eq!(&script[2..6], &COMMITMENT_HEADER);
        }
    }

    /// Changing any witness must change the commitment — that is its purpose.
    #[test]
    fn commitment_depends_on_the_wtxids() {
        let a = commitment_script(&[Sha256dHash::hash(b"one")]);
        let b = commitment_script(&[Sha256dHash::hash(b"two")]);
        assert_ne!(a, b);
    }
}
