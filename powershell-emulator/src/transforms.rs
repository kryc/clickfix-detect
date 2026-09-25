#![cfg_attr(not(test), allow(dead_code))]

use crate::Value;
use aes::{Aes128, Aes192, Aes256};
use base64::Engine as _;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit as _};
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use std::borrow::Cow;
use std::io::{self, Read, Write};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TransformError {
    #[error("key must not be empty")]
    EmptyKey,
    #[error("RC4 keys must be at most 256 bytes, got {0}")]
    InvalidRc4KeyLength(usize),
    #[error("AES keys must be 16, 24, or 32 bytes, got {0}")]
    InvalidAesKeyLength(usize),
    #[error("AES-CBC IVs must be 16 bytes, got {0}")]
    InvalidAesIvLength(usize),
    #[error("AES-CBC ciphertext must be a non-empty multiple of 16 bytes, got {0}")]
    InvalidCiphertextLength(usize),
    #[error("invalid PKCS#7 padding")]
    InvalidPkcs7Padding,
}

pub(crate) fn decode_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    decode_base64_standard(input, false)
}

pub(crate) fn encode_base64_standard(input: &[u8], padded: bool) -> String {
    if padded {
        base64::engine::general_purpose::STANDARD.encode(input)
    } else {
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(input)
    }
}

pub(crate) fn encode_base64_url_safe(input: &[u8], padded: bool) -> String {
    if padded {
        base64::engine::general_purpose::URL_SAFE.encode(input)
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
    }
}

pub(crate) fn decode_base64_standard(
    input: &str,
    recover_padding: bool,
) -> Result<Vec<u8>, base64::DecodeError> {
    let normalized = recover_base64_padding(input.trim(), recover_padding);
    base64::engine::general_purpose::STANDARD.decode(normalized.as_bytes())
}

pub(crate) fn decode_base64_url_safe(
    input: &str,
    recover_padding: bool,
) -> Result<Vec<u8>, base64::DecodeError> {
    let normalized = recover_base64_padding(input.trim(), recover_padding);
    base64::engine::general_purpose::URL_SAFE.decode(normalized.as_bytes())
}

fn recover_base64_padding(input: &str, recover_padding: bool) -> Cow<'_, str> {
    let missing = (4 - input.len() % 4) % 4;
    if !recover_padding || missing == 0 {
        return Cow::Borrowed(input);
    }

    let mut padded = String::with_capacity(input.len() + missing);
    padded.push_str(input);
    padded.extend(std::iter::repeat_n('=', missing));
    Cow::Owned(padded)
}

pub(crate) fn decode_candidate(input: &str) -> Option<(&'static str, Vec<u8>)> {
    let trimmed = input.trim();
    if trimmed.len() >= 12
        && trimmed.len() % 4 == 0
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        if let Ok(bytes) = decode_base64(trimmed) {
            if is_meaningful_decoded(&bytes) {
                return Some(("base64", decompress_if_needed(bytes)));
            }
        }
    }
    if trimmed.len() >= 16
        && trimmed.len() % 2 == 0
        && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        if let Some(bytes) = hex_decode(trimmed) {
            if is_meaningful_decoded(&bytes) {
                return Some(("hex", decompress_if_needed(bytes)));
            }
        }
    }
    if trimmed.contains('%') {
        let decoded = percent_decode(trimmed);
        if decoded != trimmed {
            return Some(("url", decoded.into_bytes()));
        }
    }
    None
}

fn decompress_if_needed(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        if let Ok(output) = gzip_decompress(&bytes) {
            return output;
        }
    }
    if bytes.first() == Some(&0x78) {
        if let Ok(output) = zlib_decompress(&bytes) {
            return output;
        }
    }
    bytes
}

fn is_meaningful_decoded(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.starts_with(&[0x1f, 0x8b]) || bytes.first() == Some(&0x78) {
        return true;
    }
    if std::str::from_utf8(bytes).is_ok() {
        let printable = bytes
            .iter()
            .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
            .count();
        return printable * 100 / bytes.len() >= 75;
    }
    if bytes.len() >= 4 && bytes.len() % 2 == 0 {
        let zeroes = bytes
            .iter()
            .skip(1)
            .step_by(2)
            .filter(|byte| **byte == 0)
            .count();
        return zeroes * 4 >= bytes.len();
    }
    false
}

pub(crate) fn bytes_to_value(bytes: &[u8]) -> Value {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Value::String(text.into());
    }
    if bytes.len() % 2 == 0 {
        let text = decode_utf16_le(bytes);
        if !text.contains('\u{fffd}') {
            return Value::String(text);
        }
    }
    Value::Bytes(bytes.to_vec())
}

pub(crate) fn decode_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

pub(crate) fn encode_utf8(input: &str) -> Vec<u8> {
    input.as_bytes().to_vec()
}

pub(crate) fn decode_utf16_le(bytes: &[u8]) -> String {
    String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn decode_utf16_be(bytes: &[u8]) -> String {
    String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn decode_ascii(bytes: Vec<u8>) -> String {
    bytes.into_iter().map(char::from).collect()
}

pub(crate) fn encode_utf16_le(input: &str) -> Vec<u8> {
    input.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub(crate) fn encode_utf16_be(input: &str) -> Vec<u8> {
    input.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

pub(crate) fn decode_utf32_le(bytes: &[u8]) -> String {
    decode_utf32(bytes, u32::from_le_bytes)
}

pub(crate) fn decode_utf32_be(bytes: &[u8]) -> String {
    decode_utf32(bytes, u32::from_be_bytes)
}

fn decode_utf32(bytes: &[u8], from_bytes: fn([u8; 4]) -> u32) -> String {
    bytes
        .chunks_exact(4)
        .map(|chunk| from_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .map(|code_point| char::from_u32(code_point).unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

pub(crate) fn encode_utf32_le(input: &str) -> Vec<u8> {
    input
        .chars()
        .flat_map(|character| u32::to_le_bytes(character.into()))
        .collect()
}

pub(crate) fn encode_utf32_be(input: &str) -> Vec<u8> {
    input
        .chars()
        .flat_map(|character| u32::to_be_bytes(character.into()))
        .collect()
}

pub(crate) fn hex_encode(input: &[u8]) -> String {
    hex::encode(input)
}

pub(crate) fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let normalized = input
        .trim()
        .trim_start_matches("0x")
        .replace([' ', '-', ':'], "");
    (normalized.len() % 2 == 0)
        .then(|| hex::decode(normalized).ok())
        .flatten()
}

pub(crate) fn gzip_compress(input: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    encoder.finish()
}

pub(crate) fn gzip_decompress(input: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    GzDecoder::new(input).read_to_end(&mut output)?;
    Ok(output)
}

pub(crate) fn zlib_compress(input: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    encoder.finish()
}

pub(crate) fn zlib_decompress(input: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    ZlibDecoder::new(input).read_to_end(&mut output)?;
    Ok(output)
}

pub(crate) fn reverse_string(input: &str) -> String {
    input.chars().rev().collect()
}

pub(crate) fn reverse_bytes(input: &[u8]) -> Vec<u8> {
    input.iter().rev().copied().collect()
}

pub(crate) fn repeating_key_xor(input: &[u8], key: &[u8]) -> Result<Vec<u8>, TransformError> {
    if key.is_empty() {
        return Err(TransformError::EmptyKey);
    }

    Ok(input
        .iter()
        .zip(key.iter().cycle())
        .map(|(byte, key_byte)| byte ^ key_byte)
        .collect())
}

pub(crate) fn rc4(input: &[u8], key: &[u8]) -> Result<Vec<u8>, TransformError> {
    if key.is_empty() {
        return Err(TransformError::EmptyKey);
    }
    if key.len() > 256 {
        return Err(TransformError::InvalidRc4KeyLength(key.len()));
    }

    let mut state = [0_u8; 256];
    for (index, value) in state.iter_mut().enumerate() {
        *value = u8::try_from(index).expect("RC4 state indices fit in u8");
    }

    let mut state_index = 0;
    let mut index = 0;
    while index < state.len() {
        state_index =
            (state_index + usize::from(state[index]) + usize::from(key[index % key.len()])) % 256;
        state.swap(index, state_index);
        index += 1;
    }

    let mut first_index = 0;
    let mut second_index = 0;
    Ok(input
        .iter()
        .map(|byte| {
            first_index = (first_index + 1) % 256;
            second_index = (second_index + usize::from(state[first_index])) % 256;
            state.swap(first_index, second_index);
            let key_byte =
                state[(usize::from(state[first_index]) + usize::from(state[second_index])) % 256];
            byte ^ key_byte
        })
        .collect())
}

pub(crate) fn sha1_hash(input: &[u8]) -> [u8; 20] {
    Sha1::digest(input).into()
}

pub(crate) fn sha256_hash(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

pub(crate) fn md5_hash(input: &[u8]) -> [u8; 16] {
    Md5::digest(input).into()
}

pub(crate) fn aes_cbc_encrypt(
    input: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, TransformError> {
    validate_aes_key_and_iv(key, iv)?;

    match key.len() {
        16 => Ok(cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| TransformError::InvalidAesKeyLength(key.len()))?
            .encrypt_padded_vec_mut::<Pkcs7>(input)),
        24 => Ok(cbc::Encryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| TransformError::InvalidAesKeyLength(key.len()))?
            .encrypt_padded_vec_mut::<Pkcs7>(input)),
        32 => Ok(cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| TransformError::InvalidAesKeyLength(key.len()))?
            .encrypt_padded_vec_mut::<Pkcs7>(input)),
        _ => Err(TransformError::InvalidAesKeyLength(key.len())),
    }
}

pub(crate) fn aes_cbc_decrypt(
    input: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, TransformError> {
    validate_aes_key_and_iv(key, iv)?;
    if input.is_empty() || input.len() % 16 != 0 {
        return Err(TransformError::InvalidCiphertextLength(input.len()));
    }

    let plaintext = match key.len() {
        16 => cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| TransformError::InvalidAesKeyLength(key.len()))?
            .decrypt_padded_vec_mut::<Pkcs7>(input),
        24 => cbc::Decryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| TransformError::InvalidAesKeyLength(key.len()))?
            .decrypt_padded_vec_mut::<Pkcs7>(input),
        32 => cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| TransformError::InvalidAesKeyLength(key.len()))?
            .decrypt_padded_vec_mut::<Pkcs7>(input),
        _ => return Err(TransformError::InvalidAesKeyLength(key.len())),
    };
    plaintext.map_err(|_| TransformError::InvalidPkcs7Padding)
}

fn validate_aes_key_and_iv(key: &[u8], iv: &[u8]) -> Result<(), TransformError> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(TransformError::InvalidAesKeyLength(key.len()));
    }
    if iv.len() != 16 {
        return Err(TransformError::InvalidAesIvLength(iv.len()));
    }
    Ok(())
}

pub(crate) fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
            {
                let value = (high << 4) | low;
                output.push(value);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn unescape_powershell(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut characters = input.chars();
    while let Some(character) = characters.next() {
        if character == '`' {
            if let Some(escaped) = characters.next() {
                output.push(match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
            }
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_supports_standard_url_safe_and_padding_recovery() {
        let input = [0xfb, 0xff];

        assert_eq!(encode_base64_standard(&input, true), "+/8=");
        assert_eq!(encode_base64_standard(&input, false), "+/8");
        assert_eq!(encode_base64_url_safe(&input, true), "-_8=");
        assert_eq!(encode_base64_url_safe(&input, false), "-_8");
        assert_eq!(
            decode_base64_standard("+/8", true).unwrap(),
            input.as_slice()
        );
        assert_eq!(
            decode_base64_url_safe("-_8", true).unwrap(),
            input.as_slice()
        );
        assert!(decode_base64_standard("+/8", false).is_err());
        assert!(decode_base64_url_safe("-_8", false).is_err());
        assert_eq!(decode_base64(" +/8= ").unwrap(), input.as_slice());
    }

    #[test]
    fn hex_round_trips_and_accepts_common_separators() {
        let bytes = [0x00, 0xab, 0xcd, 0xef];
        assert_eq!(hex_encode(&bytes), "00abcdef");
        assert_eq!(hex_decode(" 0x00:ab-cd ef "), Some(bytes.to_vec()));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn unicode_encodings_round_trip() {
        let text = "Aé💣";

        assert_eq!(decode_utf8(&encode_utf8(text)), text);
        assert_eq!(decode_utf16_le(&encode_utf16_le(text)), text);
        assert_eq!(decode_utf16_be(&encode_utf16_be(text)), text);
        assert_eq!(decode_utf32_le(&encode_utf32_le(text)), text);
        assert_eq!(decode_utf32_be(&encode_utf32_be(text)), text);

        assert_eq!(encode_utf16_le("A"), [0x41, 0x00]);
        assert_eq!(encode_utf16_be("A"), [0x00, 0x41]);
        assert_eq!(encode_utf32_le("A"), [0x41, 0x00, 0x00, 0x00]);
        assert_eq!(encode_utf32_be("A"), [0x00, 0x00, 0x00, 0x41]);
        assert_eq!(
            decode_utf32_le(&[0x00, 0x00, 0x11, 0x00]),
            char::REPLACEMENT_CHARACTER.to_string()
        );
    }

    #[test]
    fn gzip_and_zlib_round_trip() {
        let input = b"compress me compress me compress me";

        let gzip = gzip_compress(input).unwrap();
        assert!(gzip.starts_with(&[0x1f, 0x8b]));
        assert_eq!(gzip_decompress(&gzip).unwrap(), input);

        let zlib = zlib_compress(input).unwrap();
        assert_eq!(zlib.first(), Some(&0x78));
        assert_eq!(zlib_decompress(&zlib).unwrap(), input);

        assert!(gzip_decompress(b"not gzip").is_err());
        assert!(zlib_decompress(b"not zlib").is_err());
    }

    #[test]
    fn reversal_handles_characters_and_raw_bytes() {
        assert_eq!(reverse_string("ab💣"), "💣ba");
        assert_eq!(reverse_bytes(&[0, 1, 2, 3]), [3, 2, 1, 0]);
    }

    #[test]
    fn percent_decode_handles_unicode_around_escape_sequences() {
        assert_eq!(percent_decode("λ%20中"), "λ 中");
        assert_eq!(percent_decode("💥%ZZ"), "💥%ZZ");
    }

    #[test]
    fn repeating_key_xor_round_trips() {
        let ciphertext = repeating_key_xor(b"ABC", b"XY").unwrap();
        assert_eq!(ciphertext, [0x19, 0x1b, 0x1b]);
        assert_eq!(
            repeating_key_xor(&ciphertext, b"XY").unwrap(),
            b"ABC".as_slice()
        );
        assert_eq!(
            repeating_key_xor(b"data", b""),
            Err(TransformError::EmptyKey)
        );
    }

    #[test]
    fn rc4_matches_a_known_vector_and_is_symmetric() {
        let ciphertext = rc4(b"Plaintext", b"Key").unwrap();
        assert_eq!(hex_encode(&ciphertext), "bbf316e8d940af0ad3");
        assert_eq!(rc4(&ciphertext, b"Key").unwrap(), b"Plaintext");
        assert_eq!(rc4(b"data", b""), Err(TransformError::EmptyKey));
        assert_eq!(
            rc4(b"data", &[0; 257]),
            Err(TransformError::InvalidRc4KeyLength(257))
        );
    }

    #[test]
    fn hashes_match_known_vectors() {
        assert_eq!(
            hex_encode(&sha1_hash(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex_encode(&sha256_hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_encode(&md5_hash(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn aes_cbc_matches_known_vector_and_round_trips_all_key_sizes() {
        let key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plaintext = hex_decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let ciphertext = aes_cbc_encrypt(&plaintext, &key, &iv).unwrap();

        assert_eq!(
            hex_encode(&ciphertext[..16]),
            "7649abac8119b246cee98e9b12e9197d"
        );
        assert_eq!(ciphertext.len(), 32);
        assert_eq!(aes_cbc_decrypt(&ciphertext, &key, &iv).unwrap(), plaintext);

        for key in [&[0_u8; 16][..], &[0_u8; 24][..], &[0_u8; 32][..]] {
            let encrypted = aes_cbc_encrypt(b"PKCS7 padded data", key, &[0_u8; 16]).unwrap();
            assert_eq!(
                aes_cbc_decrypt(&encrypted, key, &[0_u8; 16]).unwrap(),
                b"PKCS7 padded data"
            );
        }
    }

    #[test]
    fn aes_cbc_rejects_invalid_parameters_and_padding() {
        assert_eq!(
            aes_cbc_encrypt(b"data", &[0; 15], &[0; 16]),
            Err(TransformError::InvalidAesKeyLength(15))
        );
        assert_eq!(
            aes_cbc_encrypt(b"data", &[0; 16], &[0; 15]),
            Err(TransformError::InvalidAesIvLength(15))
        );
        assert_eq!(
            aes_cbc_decrypt(&[], &[0; 16], &[0; 16]),
            Err(TransformError::InvalidCiphertextLength(0))
        );
        assert_eq!(
            aes_cbc_decrypt(&[0; 15], &[0; 16], &[0; 16]),
            Err(TransformError::InvalidCiphertextLength(15))
        );

        let ciphertext = aes_cbc_encrypt(b"", &[0; 16], &[0; 16]).unwrap();
        let mut wrong_iv = [0_u8; 16];
        wrong_iv[15] = 1;
        assert_eq!(
            aes_cbc_decrypt(&ciphertext, &[0; 16], &wrong_iv),
            Err(TransformError::InvalidPkcs7Padding)
        );
    }
}
