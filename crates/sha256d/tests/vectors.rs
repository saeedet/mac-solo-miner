//! Known-answer tests: NIST vectors for SHA-256, real block headers for sha256d.
//!
//! The NIST vectors prove the compression function is right. The Bitcoin
//! vectors prove that everything *around* it — the double hash, the byte order,
//! the header layout — is right too. Both matter: a hasher can pass every NIST
//! vector and still fail to mine a block if it gets the byte order wrong.

mod common;
use common::{bitcoin_display, hex, to_hex};

// ---------------------------------------------------------------------------
// NIST FIPS 180-4 vectors — plain SHA-256
// ---------------------------------------------------------------------------

#[test]
fn nist_empty_string() {
    assert_eq!(
        to_hex(&sha256d::sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn nist_abc() {
    assert_eq!(
        to_hex(&sha256d::sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// 448 bits — one byte short of needing a second block, so this catches
/// off-by-one errors in the padding logic.
#[test]
fn nist_two_block_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(
        to_hex(&sha256d::sha256(msg)),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

/// One million 'a' characters. Exercises the multi-block path properly.
#[test]
fn nist_one_million_a() {
    let msg = vec![b'a'; 1_000_000];
    assert_eq!(
        to_hex(&sha256d::sha256(&msg)),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

// ---------------------------------------------------------------------------
// Bitcoin vectors — real 80-byte block headers
// ---------------------------------------------------------------------------
//
// A block header is exactly 80 bytes, always, laid out as:
//
//   version      4 bytes, little-endian
//   prev block  32 bytes, natural (internal) order
//   merkle root 32 bytes, natural (internal) order
//   time         4 bytes, little-endian, Unix seconds
//   bits         4 bytes, little-endian, the packed difficulty target
//   nonce        4 bytes, little-endian  <-- the only field mining changes
//
// Mining is: hash these 80 bytes, check if the result is below the target,
// increment the nonce, repeat. That is genuinely all of it.

/// The genesis block, mined by Satoshi on 3 January 2009.
///
/// If this test passes, the entire hashing layer is correct: the compression
/// function, the padding, the double hash, and the byte order all have to be
/// right simultaneously to land on this exact value.
#[test]
fn genesis_block_header() {
    let header = hex(concat!(
        "01000000",                                                         // version 1
        "0000000000000000000000000000000000000000000000000000000000000000", // no previous block
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a", // merkle root
        "29ab5f49",                                                         // 2009-01-03 18:15:05 UTC
        "ffff001d",                                                         // bits 0x1d00ffff
        "1dac2b7c",                                                         // nonce 2083236893
    ));
    assert_eq!(header.len(), 80, "a block header is always 80 bytes");

    let hash = sha256d::sha256d(&header);

    // The famous hash, as any block explorer shows it.
    assert_eq!(
        bitcoin_display(&hash),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );

    // And the same value in the order it actually lives in memory — note the
    // leading zeros have moved to the *end*.
    assert_eq!(
        to_hex(&hash),
        "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
    );
}

/// Block 100000, mined 29 December 2010.
///
/// A second, independent vector with a non-zero previous-block hash and a real
/// merkle root, so it exercises fields the genesis block leaves empty.
#[test]
fn block_100000_header() {
    let header = hex(concat!(
        "01000000",
        "50120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd0020000000000",
        "6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3",
        "37221b4d",
        "4c86041b",
        "0f2b5710",
    ));
    assert_eq!(header.len(), 80);

    assert_eq!(
        bitcoin_display(&sha256d::sha256d(&header)),
        "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
    );
}
