//! Difficulty target decoding, checked against values the network published.

use btc_primitives::{BlockHeader, Sha256dHash, Target};
use std::str::FromStr;

/// The genesis target, `0x1d00ffff` — difficulty 1 by definition.
#[test]
fn genesis_bits_decode_to_difficulty_one() {
    let target = Target::from_compact(0x1d00_ffff).expect("valid");

    assert_eq!(
        target.to_string(),
        "00000000ffff0000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(target, Target::DIFFICULTY_ONE);
    assert!((Target::difficulty(0x1d00_ffff) - 1.0).abs() < 1e-9);
}

/// The regtest target, cross-checked against our own running node.
///
/// `bitcoin-cli getblockchaininfo` on the Phase 0 regtest node reports exactly
/// this target for exactly these bits, so this test is verified against Bitcoin
/// Core's own decoder rather than against our reading of the spec.
#[test]
fn regtest_bits_match_what_bitcoind_reports() {
    let target = Target::from_compact(0x207f_ffff).expect("valid");

    assert_eq!(
        target.to_string(),
        "7fffff0000000000000000000000000000000000000000000000000000000000"
    );
}

/// Block 100000's difficulty, as recorded in the chain.
#[test]
fn block_100000_difficulty() {
    let difficulty = Target::difficulty(0x1b04_864c);
    assert!(
        (difficulty - 14_484.162_361_225_4).abs() < 0.001,
        "got {difficulty}"
    );
}

/// The sign bit is meaningless for a target and must be rejected.
#[test]
fn rejects_negative_and_overflowing_targets() {
    assert!(Target::from_compact(0x1d80_ffff).is_err(), "sign bit set");
    assert!(Target::from_compact(0x2200_ffff).is_err(), "exceeds 256 bits");

    // A large exponent with a zero mantissa is fine: nothing overflows.
    assert!(Target::from_compact(0x2200_0000).is_ok());
}

/// The comparison itself: a hash at exactly the target passes, one above fails.
///
/// This is the boundary that decides whether a block is worth submitting, and
/// getting the inequality backwards or comparing the wrong byte order would
/// mean either never finding a block or submitting invalid ones.
#[test]
fn target_comparison_is_inclusive_at_the_boundary() {
    let target = Target::from_compact(0x1d00_ffff).expect("valid");

    let exactly_at =
        Sha256dHash::from_str("00000000ffff0000000000000000000000000000000000000000000000000000")
            .expect("valid");
    let just_below =
        Sha256dHash::from_str("00000000fffeffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .expect("valid");
    let just_above =
        Sha256dHash::from_str("00000000ffff0000000000000000000000000000000000000000000000000001")
            .expect("valid");

    assert!(target.is_met_by(&exactly_at), "equal to target must pass");
    assert!(target.is_met_by(&just_below));
    assert!(!target.is_met_by(&just_above));
}

/// The genesis block really does meet its own target, and by a wide margin.
#[test]
fn genesis_hash_beats_its_target() {
    let hash =
        Sha256dHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid");

    assert!(Target::from_compact(0x1d00_ffff).expect("valid").is_met_by(&hash));

    // The target demanded 32 leading zero bits. The genesis hash has 43 — it
    // beat the requirement by a factor of 2^11, about 2000x. Whether that is
    // luck or Satoshi re-mining the block until it looked good is unknown, but
    // it is why the genesis hash has that distinctive run of zeros.
    assert_eq!(hash.leading_zero_bits(), 43);
}

/// A header whose nonce has been tampered with must fail its own PoW check.
#[test]
fn tampered_nonce_fails_proof_of_work() {
    let mut header = BlockHeader {
        version: 1,
        prev_block: Sha256dHash::ZERO,
        merkle_root: Sha256dHash::from_str(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        )
        .expect("valid"),
        time: 1_231_006_505,
        bits: 0x1d00_ffff,
        nonce: 2_083_236_893,
    };
    assert!(header.is_valid_proof_of_work().expect("valid bits"));

    header.nonce += 1;
    assert!(
        !header.is_valid_proof_of_work().expect("valid bits"),
        "a single nonce increment must invalidate the work"
    );
}
