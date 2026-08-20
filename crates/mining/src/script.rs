//! The two script-building primitives a coinbase needs.
//!
//! This is not a Script interpreter and never will be. A miner writes exactly
//! two scripts: the coinbase `scriptSig`, which is unconstrained data with a
//! block height on the front, and the witness commitment output, which is a
//! fixed template. Neither needs opcodes beyond a data push.

/// Appends a minimal push of `data` to `out`.
///
/// Bitcoin Script has several ways to push the same bytes, and consensus rules
/// in some contexts require the shortest one. We always emit the shortest.
///
/// | Length | Encoding |
/// |---|---|
/// | 1..=75 | the length itself as the opcode |
/// | 76..=255 | `OP_PUSHDATA1` then a 1-byte length |
/// | 256..=520 | `OP_PUSHDATA2` then a 2-byte little-endian length |
///
/// # Panics
///
/// If `data` exceeds 520 bytes, Script's maximum element size. A coinbase
/// scriptSig is capped at 100 bytes by consensus, so this cannot fire in
/// practice — it is a guard against a caller passing something absurd.
pub fn push_data(data: &[u8], out: &mut Vec<u8>) {
    const OP_PUSHDATA1: u8 = 0x4C;
    const OP_PUSHDATA2: u8 = 0x4D;

    match data.len() {
        0..=75 => out.push(data.len() as u8),
        76..=255 => {
            out.push(OP_PUSHDATA1);
            out.push(data.len() as u8);
        }
        256..=520 => {
            out.push(OP_PUSHDATA2);
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        other => panic!("script push of {other} bytes exceeds the 520-byte limit"),
    }

    out.extend_from_slice(data);
}

/// Encodes a block height exactly as Bitcoin Core's `CScript() << height` does.
///
/// This is the BIP 34 prefix, and it is **not** simply a push of
/// [`encode_script_number`]. Bitcoin Core validates the coinbase by building
/// its own expected prefix with `CScript::push_int64`, which has a special
/// case:
///
/// ```text
///     height == 0        -> OP_0                 (0x00)
///     1 <= height <= 16  -> OP_1 + (height - 1)   (0x51..0x60)
///     otherwise          -> a minimal push of the Script number
/// ```
///
/// Heights 1 to 16 therefore encode as a *single opcode* carrying the value,
/// with no data push at all. Emitting `01 01` for height 1 instead of `51`
/// gets the block rejected with `bad-cb-height`.
///
/// Mainnet passed height 16 in January 2009, so this case is invisible there —
/// but every fresh regtest chain starts at height 1, so it is the first thing
/// a from-scratch miner hits.
pub fn encode_block_height(height: u32) -> Vec<u8> {
    const OP_0: u8 = 0x00;
    const OP_1: u8 = 0x51;

    match height {
        0 => vec![OP_0],
        // OP_1 encodes 1, OP_2 encodes 2, and so on up to OP_16.
        1..=16 => vec![OP_1 + (height as u8) - 1],
        _ => {
            let mut script = Vec::new();
            push_data(&encode_script_number(height), &mut script);
            script
        }
    }
}

/// Encodes a non-negative integer the way Bitcoin Script represents numbers.
///
/// Script numbers are little-endian with an explicit sign bit in the top bit of
/// the most significant byte. That last detail is the whole subtlety: if the
/// value's own top bit is set, a zero byte has to be appended, or the number
/// would be read back as negative.
///
/// BIP 34 requires the block height in exactly this encoding at the start of
/// the coinbase `scriptSig`, and Bitcoin Core rejects a block whose height is
/// encoded any other way with `bad-cb-height`.
pub fn encode_script_number(mut value: u32) -> Vec<u8> {
    // Zero is the empty byte string, not a zero byte.
    if value == 0 {
        return Vec::new();
    }

    let mut encoded = Vec::new();
    while value > 0 {
        encoded.push((value & 0xFF) as u8);
        value >>= 8;
    }

    // Top bit set means this would decode as a negative number, so pad.
    if encoded.last().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0x00);
    }

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_numbers_are_little_endian() {
        assert_eq!(encode_script_number(0), Vec::<u8>::new());
        assert_eq!(encode_script_number(1), vec![0x01]);
        assert_eq!(encode_script_number(127), vec![0x7F]);
        // 0x80 has its top bit set, so it needs a zero byte to stay positive.
        assert_eq!(encode_script_number(128), vec![0x80, 0x00]);
        assert_eq!(encode_script_number(255), vec![0xFF, 0x00]);
        assert_eq!(encode_script_number(256), vec![0x00, 0x01]);
        // Block 100000, the height from the Phase 2 tests.
        assert_eq!(encode_script_number(100_000), vec![0xA0, 0x86, 0x01]);
    }

    /// Heights near a byte boundary are where the sign-bit padding matters, and
    /// they are also heights the real chain has passed through.
    #[test]
    fn realistic_heights_encode_minimally() {
        // 800000 = 0x0C3500, top byte 0x0C, no padding needed.
        assert_eq!(encode_script_number(800_000), vec![0x00, 0x35, 0x0C]);
        // 8388608 = 0x800000, top byte 0x80, padding needed.
        assert_eq!(encode_script_number(8_388_608), vec![0x00, 0x00, 0x80, 0x00]);
    }

    /// The BIP 34 prefix must match what Bitcoin Core builds, opcode for opcode.
    ///
    /// The values below were derived from Core's `CScript::push_int64`, and the
    /// 1..=16 cases are the ones that produced a real `bad-cb-height` rejection
    /// from a live node before this function existed.
    #[test]
    fn block_heights_match_bitcoin_core() {
        // Small heights are a bare opcode, with no length prefix.
        assert_eq!(encode_block_height(1), vec![0x51], "OP_1");
        assert_eq!(encode_block_height(2), vec![0x52], "OP_2");
        assert_eq!(encode_block_height(16), vec![0x60], "OP_16");

        // 17 is the first height that becomes an ordinary data push.
        assert_eq!(encode_block_height(17), vec![0x01, 0x11]);
        assert_eq!(encode_block_height(100_000), vec![0x03, 0xA0, 0x86, 0x01]);
    }

    /// Every small height is one byte; every larger one carries a length.
    #[test]
    fn small_heights_are_a_single_opcode() {
        for height in 1..=16u32 {
            let encoded = encode_block_height(height);
            assert_eq!(encoded.len(), 1, "height {height} should be one opcode");
            assert_eq!(encoded[0], 0x50 + height as u8);
        }
        assert_eq!(encode_block_height(17).len(), 2);
    }

    #[test]
    fn pushes_use_the_shortest_encoding() {
        let mut out = Vec::new();
        push_data(&[0xAA; 3], &mut out);
        assert_eq!(out, vec![0x03, 0xAA, 0xAA, 0xAA]);

        let mut out = Vec::new();
        push_data(&[0xBB; 76], &mut out);
        assert_eq!(&out[..2], &[0x4C, 76], "OP_PUSHDATA1 above 75 bytes");

        let mut out = Vec::new();
        push_data(&[0xCC; 300], &mut out);
        assert_eq!(&out[..3], &[0x4D, 0x2C, 0x01], "OP_PUSHDATA2 above 255");
    }
}
