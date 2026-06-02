//! Crypto-agility envelope: the self-describing frame that wraps every
//! encrypted record.
//!
//! STATUS: pre-audit skeleton. This is the **wire-format codec only** — it
//! serialises and parses the bytes that the (future) AEAD and KEM layers will
//! fill in. It performs **no encryption**. The point of landing this now is
//! that the algorithm-suite byte travels *inside* the frame, so we can migrate
//! suites without a flag-day re-encryption (see `docs/crypto-spec.md`).
//!
//! ## Concrete layout (envelope format version `0x01`)
//!
//! ```text
//! [0]   version   u8     == ENVELOPE_VERSION (0x01)
//! [1]   suite_id  u8     algorithm suite (e.g. 0x12)
//! [2]   flags     u8     bit0 = has_kem_ct
//!       aad        len-prefixed bytes   (uvarint length, then bytes)
//!       nonce      len-prefixed bytes
//!       ciphertext len-prefixed bytes
//!       tag        len-prefixed bytes
//!       kem_ct     len-prefixed bytes   (only if flags.bit0 set)
//! ```
//!
//! Length prefixes are unsigned LEB128 varints. The brief's prose layout left
//! the nonce/ciphertext/tag boundaries implicit-by-suite; we make the frame
//! explicitly self-describing so it parses unambiguously and is testable.

use crate::{AlgorithmSuite, ENVELOPE_VERSION};
use alloc::vec::Vec;

const FLAG_HAS_KEM_CT: u8 = 0b0000_0001;

/// Errors returned by [`Envelope::decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// Input ended before a complete envelope was read.
    Truncated,
    /// The format-version byte is not one this codec understands.
    UnsupportedVersion(u8),
    /// The suite byte is not in the registry.
    UnknownSuite(u8),
    /// A length prefix (varint) was malformed or overflowed.
    BadLength,
    /// Bytes remained after a complete envelope was parsed.
    TrailingBytes,
}

/// A parsed, owned crypto-agility envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Which algorithm suite produced this record.
    pub suite: AlgorithmSuite,
    /// Additional authenticated data (bound by the AEAD, not encrypted).
    pub aad: Vec<u8>,
    /// AEAD nonce.
    pub nonce: Vec<u8>,
    /// Encrypted payload.
    pub ciphertext: Vec<u8>,
    /// AEAD authentication tag.
    pub tag: Vec<u8>,
    /// KEM ciphertext — present only on key-rotation records.
    pub kem_ct: Option<Vec<u8>>,
}

impl Envelope {
    /// Serialise this envelope to its on-wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(ENVELOPE_VERSION);
        out.push(self.suite.as_byte());

        let mut flags = 0u8;
        if self.kem_ct.is_some() {
            flags |= FLAG_HAS_KEM_CT;
        }
        out.push(flags);

        put_bytes(&mut out, &self.aad);
        put_bytes(&mut out, &self.nonce);
        put_bytes(&mut out, &self.ciphertext);
        put_bytes(&mut out, &self.tag);
        if let Some(kem) = &self.kem_ct {
            put_bytes(&mut out, kem);
        }
        out
    }

    /// Parse an envelope from its on-wire bytes.
    ///
    /// # Errors
    /// Returns [`EnvelopeError`] if the input is truncated, carries an
    /// unsupported version or unknown suite, has a malformed length prefix, or
    /// has trailing bytes after a complete envelope.
    pub fn decode(input: &[u8]) -> Result<Envelope, EnvelopeError> {
        let mut r = Reader::new(input);

        let version = r.read_u8()?;
        if version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }

        let suite_byte = r.read_u8()?;
        let suite =
            AlgorithmSuite::from_byte(suite_byte).ok_or(EnvelopeError::UnknownSuite(suite_byte))?;

        let flags = r.read_u8()?;
        let aad = r.read_bytes()?;
        let nonce = r.read_bytes()?;
        let ciphertext = r.read_bytes()?;
        let tag = r.read_bytes()?;
        let kem_ct = if flags & FLAG_HAS_KEM_CT != 0 {
            Some(r.read_bytes()?)
        } else {
            None
        };

        if !r.is_at_end() {
            return Err(EnvelopeError::TrailingBytes);
        }
        Ok(Envelope {
            suite,
            aad,
            nonce,
            ciphertext,
            tag,
            kem_ct,
        })
    }
}

fn put_uvarint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_uvarint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, EnvelopeError> {
        let byte = *self.buf.get(self.pos).ok_or(EnvelopeError::Truncated)?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_uvarint(&mut self) -> Result<u64, EnvelopeError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if shift >= 64 {
                return Err(EnvelopeError::BadLength);
            }
            let byte = self.read_u8()?;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, EnvelopeError> {
        let len = usize::try_from(self.read_uvarint()?).map_err(|_| EnvelopeError::BadLength)?;
        let end = self.pos.checked_add(len).ok_or(EnvelopeError::BadLength)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(EnvelopeError::Truncated)?;
        self.pos = end;
        Ok(slice.to_vec())
    }

    fn is_at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kem: Option<Vec<u8>>) -> Envelope {
        Envelope {
            suite: AlgorithmSuite::HybridPq,
            aad: b"record-id-42".to_vec(),
            nonce: vec![7u8; 24],
            ciphertext: b"this-is-not-real-ciphertext".to_vec(),
            tag: vec![9u8; 16],
            kem_ct: kem,
        }
    }

    #[test]
    fn round_trip_without_kem() {
        let env = sample(None);
        let decoded = Envelope::decode(&env.encode()).expect("decodes");
        assert_eq!(decoded, env);
        assert!(decoded.kem_ct.is_none());
    }

    #[test]
    fn round_trip_with_kem() {
        let env = sample(Some(vec![3u8; 1088])); // ML-KEM-768 ciphertext size
        let bytes = env.encode();
        let decoded = Envelope::decode(&bytes).expect("decodes");
        assert_eq!(decoded, env);
        assert_eq!(decoded.kem_ct.as_ref().map(Vec::len), Some(1088));
    }

    #[test]
    fn header_starts_with_version_and_suite() {
        let bytes = sample(None).encode();
        assert_eq!(bytes[0], ENVELOPE_VERSION);
        assert_eq!(bytes[1], 0x12);
    }

    #[test]
    fn empty_fields_round_trip() {
        let env = Envelope {
            suite: AlgorithmSuite::Classical,
            aad: Vec::new(),
            nonce: Vec::new(),
            ciphertext: Vec::new(),
            tag: Vec::new(),
            kem_ct: None,
        };
        assert_eq!(Envelope::decode(&env.encode()).unwrap(), env);
    }

    #[test]
    fn multibyte_varint_length_round_trips() {
        // A field longer than 127 forces a 2-byte varint length prefix.
        let env = Envelope {
            suite: AlgorithmSuite::HybridPq,
            aad: Vec::new(),
            nonce: vec![1u8; 24],
            ciphertext: vec![2u8; 5000],
            tag: vec![3u8; 16],
            kem_ct: None,
        };
        let decoded = Envelope::decode(&env.encode()).unwrap();
        assert_eq!(decoded.ciphertext.len(), 5000);
        assert_eq!(decoded, env);
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = sample(None).encode();
        bytes[0] = 0xFE;
        assert_eq!(
            Envelope::decode(&bytes),
            Err(EnvelopeError::UnsupportedVersion(0xFE))
        );
    }

    #[test]
    fn rejects_unknown_suite() {
        let mut bytes = sample(None).encode();
        bytes[1] = 0x00; // not in the registry
        assert_eq!(
            Envelope::decode(&bytes),
            Err(EnvelopeError::UnknownSuite(0x00))
        );
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes = sample(None).encode();
        assert_eq!(
            Envelope::decode(&bytes[..bytes.len() - 3]),
            Err(EnvelopeError::Truncated)
        );
        assert_eq!(Envelope::decode(&[]), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample(None).encode();
        bytes.push(0xAA);
        assert_eq!(Envelope::decode(&bytes), Err(EnvelopeError::TrailingBytes));
    }
}
