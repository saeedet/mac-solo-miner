//! Bitcoin Core's block file obfuscation (v28 and later).
//!
//! Since v28, Core XORs everything it writes to `blk*.dat` and `rev*.dat` with
//! an 8-byte key stored alongside them in `xor.dat`. The key is generated once
//! per blocks directory and never changes.
//!
//! It is not encryption and is not meant to be — the key sits in plain sight in
//! the same folder. Its purpose is to stop antivirus software and cloud backup
//! scanners from pattern-matching on raw blockchain contents, which used to
//! cause them to quarantine or corrupt block files.
//!
//! The consequence that matters here: **without `xor.dat`, the block files are
//! unreadable noise.** It is eight bytes standing in front of 810 GB.
//!
//! The key is applied by position within the file, so the byte at offset `i` is
//! stored as `plain[i] ^ key[i % 8]`. That makes it seekable — any offset can
//! be decoded without reading what came before — which is exactly what Core
//! needs to jump straight to a block.

/// The 8-byte key from `xor.dat`.
#[derive(Clone, Copy)]
pub struct ObfuscationKey([u8; 8]);

impl ObfuscationKey {
    /// Reads the key from a blocks directory's `xor.dat`.
    ///
    /// A missing file means the directory predates v28, where blocks were
    /// stored in the clear — represented here as an all-zero key, which XORs to
    /// a no-op.
    pub fn from_blocks_dir(blocks_dir: &std::path::Path) -> std::io::Result<Self> {
        let path = blocks_dir.join("xor.dat");

        match std::fs::read(&path) {
            Ok(bytes) => Ok(Self(bytes.try_into().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} is not exactly 8 bytes", path.display()),
                )
            })?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self([0u8; 8])),
            Err(error) => Err(error),
        }
    }

    /// Whether this key actually obfuscates anything.
    pub fn is_active(&self) -> bool {
        self.0 != [0u8; 8]
    }

    /// De-obfuscates `buffer`, which begins at `file_offset` within its file.
    ///
    /// XOR is its own inverse, so this both encodes and decodes.
    pub fn apply(&self, buffer: &mut [u8], file_offset: u64) {
        if !self.is_active() {
            return;
        }

        for (index, byte) in buffer.iter_mut().enumerate() {
            let position = file_offset.wrapping_add(index as u64);
            *byte ^= self.0[(position % 8) as usize];
        }
    }

    /// The key as hex, for logging.
    pub fn to_hex(self) -> String {
        btc_primitives::hex::encode(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real key and the real first bytes of the recovered archive's
    /// `blk00001.dat`, which must decode to the mainnet magic bytes.
    ///
    /// This is a genuine end-to-end check: if the key application is wrong by
    /// even one position, `f9beb4d9` does not appear.
    #[test]
    fn decodes_a_real_block_file_header() {
        let key = ObfuscationKey([0xc6, 0x82, 0xa2, 0xde, 0xb4, 0x15, 0xe9, 0xa7]);

        let mut bytes = [
            0x3f, 0x3c, 0x16, 0x07, 0x2b, 0x22, 0xe9, 0xa7, 0xc7, 0x82, 0xa2, 0xde,
        ];
        key.apply(&mut bytes, 0);

        assert_eq!(&bytes[..4], &[0xf9, 0xbe, 0xb4, 0xd9], "mainnet magic");
        assert_eq!(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 14_239);
        assert_eq!(u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]), 1, "version");
    }

    #[test]
    fn applying_twice_restores_the_original() {
        let key = ObfuscationKey([1, 2, 3, 4, 5, 6, 7, 8]);
        let original = [0xAAu8; 32];

        let mut bytes = original;
        key.apply(&mut bytes, 12_345);
        assert_ne!(bytes, original);
        key.apply(&mut bytes, 12_345);
        assert_eq!(bytes, original);
    }

    /// The offset must be honoured, or decoding mid-file produces garbage.
    #[test]
    fn offset_shifts_the_key() {
        let key = ObfuscationKey([1, 2, 3, 4, 5, 6, 7, 8]);

        let mut at_zero = [0u8; 8];
        key.apply(&mut at_zero, 0);

        let mut at_three = [0u8; 8];
        key.apply(&mut at_three, 3);

        assert_ne!(at_zero, at_three);
        assert_eq!(at_three[0], 4, "offset 3 starts at key[3]");
    }

    #[test]
    fn absent_key_is_a_no_op() {
        let key = ObfuscationKey([0u8; 8]);
        assert!(!key.is_active());

        let mut bytes = [0x11u8; 16];
        key.apply(&mut bytes, 0);
        assert_eq!(bytes, [0x11u8; 16]);
    }
}
