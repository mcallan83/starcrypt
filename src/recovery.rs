//! Cryptomator recovery encoding: AES key || MAC key, two little-endian CRC32
//! bytes, then big-endian 12-bit indices into the official 4096-word dictionary.
use anyhow::Result;
use oxcrypt_core::crypto::keys::MasterKey;
use zeroize::Zeroizing;

const WORDS: &str = include_str!("recovery_words.txt");

pub(crate) fn encode(key: &MasterKey) -> Result<Zeroizing<String>> {
    Ok(key.with_raw_key(encode_raw)?)
}

fn encode_raw(raw: &[u8]) -> Zeroizing<String> {
    assert_eq!(raw.len(), 64);
    let words: Vec<_> = WORDS.lines().collect();
    let mut padded = Zeroizing::new([0u8; 66]);
    padded[..64].copy_from_slice(raw);
    // Guava HashCode.asBytes()/writeBytesTo use little-endian CRC bytes,
    // despite the reference implementation's "most significant bits" comment.
    padded[64..].copy_from_slice(&crc32(raw).to_le_bytes()[..2]);
    // Reserve enough space so appending never reallocates secret phrase storage.
    let mut phrase = Zeroizing::new(String::with_capacity(44 * 32));
    for chunk in padded.as_chunks::<3>().0 {
        let first = (usize::from(chunk[0]) << 4) | (usize::from(chunk[1]) >> 4);
        let second = ((usize::from(chunk[1]) & 15) << 8) | usize::from(chunk[2]);
        for index in [first, second] {
            if !phrase.is_empty() {
                phrase.push(' ');
            }
            phrase.push_str(words[index]);
        }
    }
    phrase
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_and_crc_are_stable() {
        let words: Vec<_> = WORDS.lines().collect();
        assert_eq!(words.len(), 4096);
        assert_eq!(
            words.iter().collect::<std::collections::HashSet<_>>().len(),
            4096
        );
        assert!(
            words
                .iter()
                .all(|word| word.len() < 32 && word.bytes().all(|b| b.is_ascii_lowercase()))
        );
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn official_recovery_phrase_vector() {
        // Valid-key vector from Cryptomator RecoveryKeyFactoryTest at revision
        // 6f3e1938f1d9786cee893ca224d170be1fe289f7. Decode its indices here
        // independently of the production bit packing.
        let expected = "pathway lift abuse plenty export texture gentleman landscape beyond ceiling around leaf cafe charity border breakdown victory surely computer cat linger restrict infer crowd live computer true written amazed investor boot depth left theory snow whereby terminal weekly reject happiness circuit partial cup ad";
        let words: Vec<_> = WORDS.lines().collect();
        let mut bits = Vec::new();
        for word in expected.split_whitespace() {
            let index = words
                .iter()
                .position(|&candidate| candidate == word)
                .unwrap();
            bits.extend((0..12).rev().map(|shift| ((index >> shift) & 1) as u8));
        }
        let bytes: Vec<u8> = bits
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| chunk.iter().fold(0, |byte, bit| (byte << 1) | bit))
            .collect();
        assert_eq!(bytes.len(), 66);
        assert_eq!(&*encode_raw(&bytes[..64]), expected);
        assert_eq!(&crc32(&bytes[..64]).to_le_bytes()[..2], &bytes[64..]);
    }
}
