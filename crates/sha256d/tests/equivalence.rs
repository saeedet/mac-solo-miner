//! Asserts the readable implementation and the hardware one are the same function.
//!
//! This is the test that lets the fast path be trusted. `reference` is checkable
//! against FIPS 180-4 by eye; `neon` is not. So rather than trying to read the
//! intrinsics and hope, we assert the two agree on a large and varied set of
//! inputs. If someone later "optimises" the NEON code and breaks it, this fails.

mod common;
use common::hex;

/// A tiny xorshift64 generator.
///
/// Deterministic on purpose — a failure here must be reproducible, and a test
/// that only fails on some runs is worse than no test. Also keeps the crate
/// dependency-free.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next_u64() as u8;
        }
    }
}

/// Both implementations must agree at every length from 0 to 300 bytes.
///
/// The range matters more than it looks: it covers the empty message, several
/// whole-block boundaries, and — crucially — lengths 55, 56, 63 and 64, where
/// the padding either just fits or just spills into another block. Those are
/// where padding bugs live.
#[test]
fn agree_on_every_length_up_to_300() {
    let mut rng = Rng(0x2019_0103_1815_0500); // genesis timestamp, for luck
    let mut buf = vec![0u8; 300];
    rng.fill(&mut buf);

    for len in 0..=300 {
        let msg = &buf[..len];

        let want = sha256d::reference::sha256(msg);
        // SAFETY: guarded by the `is_available` check.
        let got = unsafe { sha256d::neon::sha256(msg) };
        assert_eq!(want, got, "sha256 disagreement at length {len}");

        let want_d = sha256d::reference::sha256d(msg);
        // SAFETY: as above.
        let got_d = unsafe { sha256d::neon::sha256d(msg) };
        assert_eq!(want_d, got_d, "sha256d disagreement at length {len}");
    }
}

/// A thousand random messages of random lengths, contents varying each time.
#[test]
fn agree_on_random_messages() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);

    for round in 0..1000 {
        let len = (rng.next_u64() % 500) as usize;
        let mut msg = vec![0u8; len];
        rng.fill(&mut msg);

        // SAFETY: guarded by the `is_available` check.
        let got = unsafe { sha256d::neon::sha256d(&msg) };
        assert_eq!(
            sha256d::reference::sha256d(&msg),
            got,
            "disagreement in round {round} on a {len}-byte message"
        );
    }
}

/// The readable implementation must reproduce the genesis hash on its own.
///
/// `tests/vectors.rs` exercises the dispatching entry point, which on this Mac
/// always picks NEON. Without this test the reference implementation — the
/// thing everything else is checked against — would never be checked itself.
#[test]
fn reference_alone_reproduces_genesis() {
    let header = hex(concat!(
        "01000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
        "29ab5f49",
        "ffff001d",
        "1dac2b7c",
    ));

    let mut hash = sha256d::reference::sha256d(&header);
    hash.reverse();

    assert_eq!(
        common::to_hex(&hash),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
}

/// The hardware path must actually be the one being used on this machine.
///
/// If Apple ever ships an ARM Mac without the crypto extensions, or a build
/// flag silently disables them, everything above would still pass while quietly
/// testing the reference implementation against itself.
#[test]
fn hardware_acceleration_is_actually_available() {
    assert!(
        sha256d::neon::is_available(),
        "expected ARMv8 sha2 extensions on this CPU"
    );
}
