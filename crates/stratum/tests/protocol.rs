//! Round-trip tests for the wire encodings.
//!
//! The pool encodes and the miner decodes, so anything that survives a round
//! trip here cannot be misread at the other end. These are the tests that would
//! catch a byte-order regression before it turned into a miner that runs
//! perfectly and finds nothing.

use btc_primitives::{Sha256dHash, hex};
use serde_json::json;
use std::str::FromStr;
use stratum::{Job, Share};

fn sample_job() -> Job {
    Job {
        job_id: "0f1e".to_owned(),
        prev_hash: Sha256dHash::from_str(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .expect("valid"),
        coinbase_prefix: hex::decode("01000000010000000000").expect("valid"),
        coinbase_suffix: hex::decode("ffffffff0100f2052a01").expect("valid"),
        merkle_branch: vec![Sha256dHash::hash(b"left"), Sha256dHash::hash(b"right")],
        version: 0x2000_0000,
        bits: 0x1d00_ffff,
        time: 1_231_006_505,
        clean_jobs: true,
    }
}

#[test]
fn job_survives_a_round_trip() {
    let job = sample_job();
    let decoded = Job::from_notify_params(&job.to_notify_params()).expect("decodes");
    assert_eq!(decoded, job);
}

/// The exact wire shape, field by field.
///
/// Pinned so that a change to the encoding has to be deliberate — a real miner
/// on the other end has no tolerance for a reordered or reformatted field.
#[test]
fn notify_params_have_the_documented_shape() {
    let params = sample_job().to_notify_params();
    let array = params.as_array().expect("an array");

    assert_eq!(array.len(), 9);
    assert_eq!(array[0], json!("0f1e"), "job_id");

    // prevhash goes out word-swapped, so it is not the display form.
    let prevhash = array[1].as_str().expect("a string");
    assert_eq!(prevhash.len(), 64);
    assert_ne!(
        prevhash,
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "prevhash must not be sent in display order"
    );

    // Numeric fields are 8-character big-endian hex.
    assert_eq!(array[5], json!("20000000"), "version");
    assert_eq!(array[6], json!("1d00ffff"), "nbits");
    assert_eq!(array[7], json!("495fab29"), "ntime");
    assert_eq!(array[8], json!(true), "clean_jobs");
}

/// Splicing must land the extranonce exactly between the two halves.
#[test]
fn coinbase_splices_the_extranonce_in_the_middle() {
    let job = sample_job();
    let coinbase = job.coinbase(&[0xAA, 0xBB], &[0xCC, 0xDD]);

    assert_eq!(
        hex::encode(&coinbase),
        "01000000010000000000aabbccddffffffff0100f2052a01"
    );
}

/// Different extranonces must give different merkle roots — that is the entire
/// point of the extranonce, and if it fails, two miners search identical space.
#[test]
fn extranonce_changes_the_merkle_root() {
    let job = sample_job();

    let first = job.merkle_root(&[0x00, 0x00], &[0x00, 0x01]);
    let second = job.merkle_root(&[0x00, 0x00], &[0x00, 0x02]);
    assert_ne!(first, second);

    // And extranonce1 must matter as much as extranonce2, or two connections
    // with the same extranonce2 would collide.
    let third = job.merkle_root(&[0x00, 0x01], &[0x00, 0x01]);
    assert_ne!(first, third);
}

/// The header a miner hashes must carry the job's fields unchanged.
#[test]
fn header_carries_the_job_fields() {
    let job = sample_job();
    let header = job.header(&[0xAA, 0xBB], &[0xCC, 0xDD], 1_700_000_000, 42);

    assert_eq!(header.version, job.version);
    assert_eq!(header.prev_block, job.prev_hash);
    assert_eq!(header.bits, job.bits);
    assert_eq!(header.time, 1_700_000_000, "the miner's time, not the job's");
    assert_eq!(header.nonce, 42);
    assert_eq!(header.merkle_root, job.merkle_root(&[0xAA, 0xBB], &[0xCC, 0xDD]));
}

#[test]
fn share_survives_a_round_trip() {
    let share = Share {
        worker: "mac.0".to_owned(),
        job_id: "0f1e".to_owned(),
        extranonce2: vec![0x00, 0x00, 0x00, 0x07],
        time: 1_700_000_000,
        nonce: 0xDEAD_BEEF,
    };

    let decoded = Share::from_submit_params(&share.to_submit_params()).expect("decodes");
    assert_eq!(decoded, share);

    // Numeric fields are hex, not decimal — a real pool rejects decimal.
    let params = share.to_submit_params();
    assert_eq!(params[4], json!("deadbeef"));
}

/// Malformed input must error rather than panic; the pool parses hostile bytes.
#[test]
fn malformed_input_is_rejected_cleanly() {
    assert!(Job::from_notify_params(&json!("not an array")).is_err());
    assert!(Job::from_notify_params(&json!([1, 2, 3])).is_err());
    assert!(Share::from_submit_params(&json!([])).is_err());
    assert!(Share::from_submit_params(&json!(["w", "j", "zz", "0", "0"])).is_err());
}
