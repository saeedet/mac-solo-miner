//! Message padding, from FIPS 180-4 §5.1.1.
//!
//! SHA-256 consumes the message in fixed 64-byte blocks, so a message of any
//! other length has to be extended to a multiple of 64. The padding is:
//!
//! ```text
//!   <message> 0x80 <zero or more 0x00> <original bit length, 8 bytes big-endian>
//! ```
//!
//! Two details worth understanding, because both are load-bearing:
//!
//! - The `0x80` byte (a single 1 bit followed by seven 0 bits) marks where the
//!   real message stopped. Without it, `"abc"` and `"abc\0"` would pad to the
//!   same block and collide trivially.
//! - The trailing length is what makes the padding unambiguous. It is the
//!   length in **bits**, not bytes, and it is big-endian like everything else
//!   inside SHA-256.
//!
//! This allocates, which is fine everywhere except the mining hot loop. Phase 5
//! replaces it there with a version specialised to the fixed 80-byte block
//! header, where the padding is known at compile time.

/// Returns `message` padded to a whole number of 64-byte blocks.
///
/// # Panics
///
/// Never in practice: it would require a message of 2^61 bytes (2 exabytes)
/// to overflow the bit-length counter.
pub fn pad(message: &[u8]) -> Vec<u8> {
    let bit_len = (message.len() as u64)
        .checked_mul(8)
        .expect("message length in bits overflows u64");

    let mut padded = Vec::with_capacity(padded_len(message.len()));
    padded.extend_from_slice(message);

    // The mandatory single 1 bit.
    padded.push(0x80);

    // Zero-fill until the only thing left to write is the 8-byte length, i.e.
    // until we are 56 bytes into the final block.
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }

    padded.extend_from_slice(&bit_len.to_be_bytes());

    debug_assert_eq!(padded.len() % 64, 0);
    padded
}

/// How long `pad` will make a message of `len` bytes.
///
/// The `+ 9` is the `0x80` byte plus the 8 length bytes; rounding up to the
/// next multiple of 64 accounts for the zero fill.
pub fn padded_len(len: usize) -> usize {
    (len + 9).div_ceil(64) * 64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_message_pads_to_one_block() {
        let padded = pad(b"");
        assert_eq!(padded.len(), 64);
        assert_eq!(padded[0], 0x80);
        // Length field is zero for an empty message.
        assert_eq!(&padded[56..], &[0u8; 8]);
    }

    #[test]
    fn abc_records_twenty_four_bits() {
        let padded = pad(b"abc");
        assert_eq!(padded.len(), 64);
        assert_eq!(padded[3], 0x80);
        // 3 bytes = 24 bits, big-endian in the last 8 bytes.
        assert_eq!(&padded[56..], &24u64.to_be_bytes());
    }

    /// A 56-byte message is the awkward case: the `0x80` fits in the first
    /// block but the length field does not, so padding spills into a second.
    #[test]
    fn fifty_six_bytes_spills_into_a_second_block() {
        let padded = pad(&[0xAA; 56]);
        assert_eq!(padded.len(), 128);
        assert_eq!(padded[56], 0x80);
        assert_eq!(&padded[120..], &(56u64 * 8).to_be_bytes());
    }

    #[test]
    fn padded_len_agrees_with_pad() {
        for len in 0..200 {
            assert_eq!(padded_len(len), pad(&vec![0; len]).len(), "len = {len}");
        }
    }
}
