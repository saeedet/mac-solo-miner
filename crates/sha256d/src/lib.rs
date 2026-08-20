//! SHA-256 and double-SHA-256 (`sha256d`), the hash function Bitcoin is built on.
//!
//! Bitcoin almost never uses SHA-256 alone. It uses **double** SHA-256:
//!
//! ```text
//!     sha256d(x) = sha256(sha256(x))
//! ```
//!
//! That is what secures block headers, what builds merkle trees, and what
//! mining actually searches over. Mining is nothing more exotic than calling
//! [`sha256d`] on an 80-byte block header over and over, changing four of those
//! bytes each time, until the result happens to be a small enough number.
//!
//! # Two implementations
//!
//! This crate contains the same function twice, on purpose:
//!
//! - [`reference`] follows FIPS 180-4 step by step. It is slow and readable,
//!   and it is the *definition* of what correct means here.
//! - [`neon`] uses the ARMv8 crypto extensions this Mac has. It is roughly an
//!   order of magnitude faster and considerably harder to read.
//!
//! The test suite asserts the two agree on thousands of inputs, so the slow one
//! teaches and the fast one is held to what it teaches. [`sha256`] and
//! [`sha256d`] pick whichever is available at runtime.
//!
//! # A warning about byte order
//!
//! These functions return the digest in its **natural** order — the bytes as
//! SHA-256 produces them. Bitcoin *displays* hashes byte-reversed, which is why
//! the genesis block hash starts with zeros on a block explorer but ends with
//! them in memory. This crate deliberately has no opinion about that; the
//! reversal is a display convention, and it gets a proper type in the
//! `btc-primitives` crate rather than being left as a comment.

mod constants;
mod padding;

pub mod midstate;

pub mod reference;

pub use midstate::HeaderHasher;

#[cfg(target_arch = "aarch64")]
pub mod neon;

/// Computes SHA-256 of `message`.
///
/// Uses the hardware implementation where the CPU supports it, and the
/// portable one otherwise. Both produce identical output.
pub fn sha256(message: &[u8]) -> [u8; 32] {
    #[cfg(target_arch = "aarch64")]
    if neon::is_available() {
        // SAFETY: `is_available` just confirmed the `sha2` feature is present,
        // which is the whole of `neon::sha256`'s safety contract.
        return unsafe { neon::sha256(message) };
    }

    reference::sha256(message)
}

/// Computes `sha256(sha256(message))` — the hash Bitcoin uses everywhere.
pub fn sha256d(message: &[u8]) -> [u8; 32] {
    #[cfg(target_arch = "aarch64")]
    if neon::is_available() {
        // SAFETY: as above.
        return unsafe { neon::sha256d(message) };
    }

    reference::sha256d(message)
}
