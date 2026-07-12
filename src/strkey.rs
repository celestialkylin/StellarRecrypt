//! Stellar strkey encoding/decoding for account public keys (`G...`) and secret seeds (`S...`).
//!
//! Spec: SEP-0023 / Stellar StrKey
//! - Version byte public:  0x30 → base32 starts with `G`
//! - Version byte private: 0x90 → base32 starts with `S`
//! - Layout: version(1) || payload(32) || crc16-xmodem(2), then base32 (no padding)

use crate::error::{Error, Result};

const VERSION_PUBKEY: u8 = 0x30;
const VERSION_SEED: u8 = 0x90;

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// CRC16-XMODEM checksum used by Stellar strkeys.
pub fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in range_8() {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[inline]
fn range_8() -> impl Iterator<Item = u8> {
    0u8..8
}

fn b32_encode(data: &[u8]) -> String {
    // Stellar uses standard base32 without padding.
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(B32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(B32_ALPHABET[idx] as char);
    }
    out
}

fn b32_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().replace('-', "");
    let s = s.to_ascii_uppercase();
    if s.is_empty() {
        return Err(Error::InvalidStrkey("empty strkey".into()));
    }

    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);

    for c in s.bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => {
                return Err(Error::InvalidStrkey(format!(
                    "invalid base32 character: {}",
                    c as char
                )));
            }
        };
        buffer = (buffer << 5) | val as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn encode_with_version(version: u8, payload: &[u8; 32]) -> String {
    let mut body = Vec::with_capacity(35);
    body.push(version);
    body.extend_from_slice(payload);
    let crc = crc16_xmodem(&body);
    body.push((crc & 0xff) as u8);
    body.push((crc >> 8) as u8);
    b32_encode(&body)
}

fn decode_with_version(s: &str, expected_version: u8) -> Result<[u8; 32]> {
    let raw = b32_decode(s)?;
    if raw.len() < 35 {
        return Err(Error::InvalidStrkey(format!(
            "strkey too short: {} bytes",
            raw.len()
        )));
    }
    // Base32 may leave trailing zero bits; take first 35 bytes.
    let raw = &raw[..35];
    let version = raw[0];
    if version != expected_version {
        return Err(Error::InvalidStrkey(format!(
            "unexpected version 0x{version:02x}, expected 0x{expected_version:02x}"
        )));
    }
    let payload = &raw[1..33];
    let checksum = u16::from_le_bytes([raw[33], raw[34]]);
    let expected = crc16_xmodem(&raw[..33]);
    if checksum != expected {
        return Err(Error::InvalidStrkey("checksum mismatch".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(payload);
    Ok(out)
}

/// Decode a Stellar account public key `G...` to 32-byte Ed25519 public key.
pub fn decode_public(g: &str) -> Result<[u8; 32]> {
    let g = g.trim();
    if !g.starts_with('G') {
        return Err(Error::InvalidStrkey(
            "public key must start with G".into(),
        ));
    }
    decode_with_version(g, VERSION_PUBKEY)
}

/// Decode a Stellar secret seed `S...` to 32-byte Ed25519 seed.
pub fn decode_seed(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if !s.starts_with('S') {
        return Err(Error::InvalidStrkey(
            "secret key must start with S".into(),
        ));
    }
    decode_with_version(s, VERSION_SEED)
}

/// Encode 32-byte Ed25519 public key as Stellar `G...` strkey.
pub fn encode_public(ed_pub: &[u8; 32]) -> String {
    encode_with_version(VERSION_PUBKEY, ed_pub)
}

/// Encode 32-byte Ed25519 seed as Stellar `S...` strkey.
pub fn encode_seed(seed: &[u8; 32]) -> String {
    encode_with_version(VERSION_SEED, seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn roundtrip_random() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let s = encode_seed(&seed);
        assert!(s.starts_with('S'));
        assert_eq!(decode_seed(&s).unwrap(), seed);

        let mut pubk = [0u8; 32];
        OsRng.fill_bytes(&mut pubk);
        // force valid-looking length only; no point validity required for encode
        let g = encode_public(&pubk);
        assert!(g.starts_with('G'));
        assert_eq!(decode_public(&g).unwrap(), pubk);
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut s = encode_seed(&seed);
        // Flip last character when possible
        let last = s.pop().unwrap();
        let flipped = if last == 'A' { 'B' } else { 'A' };
        s.push(flipped);
        assert!(decode_seed(&s).is_err());
    }
}
