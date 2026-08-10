//! [`Bytes`] — the DIG-owned payload container for [`DigMessage`](crate::DigMessage).
//!
//! ## Why this is not `chia_protocol::Bytes`
//!
//! The DIG peer wire is a native protocol, not a chia protocol that happens to carry extra
//! opcodes. A DIG frame's payload type is part of DIG's public API: every consumer that builds
//! or reads a DIG message names it. Sourcing that type from `chia-protocol` meant a `chia-protocol`
//! version bump was a breaking change to the DIG wire API, and it is what let chia types leak
//! into consumers that have no chia traffic at all.
//!
//! ## Byte-identity is the whole constraint
//!
//! This is a live network. The [`Streamable`] encoding below is deliberately identical to the one
//! it replaces — a `u32` big-endian length prefix followed by the raw bytes — so a DIG peer on the
//! old type and a DIG peer on this one exchange the same frames. `tests/golden_wire_vectors.rs`
//! pins that as absolute hex; it is not inferred from a round-trip.

use std::{fmt, io::Cursor, ops::Deref};

use chia_sha2::Sha256;
use chia_traits::{Error, Result, Streamable};

/// A length-prefixed byte payload.
///
/// Cheap to build from anything that owns or borrows bytes, and derefs to `[u8]`, so it reads as
/// a slice everywhere it is consumed.
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Wrap an owned byte vector, taking ownership without copying.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Number of payload bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the payload is empty. A zero-length payload is a valid DIG frame.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume into the underlying vector, without copying.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

/// Hex, because a payload is read against a wire dump far more often than as a decimal list.
impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Same hex rendering as [`Display`](fmt::Display) — a `Vec<u8>`'s derived `Debug` is unreadable
/// at payload sizes, and a payload is almost always inspected inside a larger `Debug` dump.
impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({self})")
    }
}

impl Streamable for Bytes {
    fn update_digest(&self, digest: &mut Sha256) {
        #[allow(clippy::cast_possible_truncation)]
        (self.0.len() as u32).update_digest(digest);
        digest.update(&self.0);
    }

    fn stream(&self, out: &mut Vec<u8>) -> Result<()> {
        // The length prefix is a u32, so a payload that cannot be described by one is not
        // expressible on the wire at all — refused here rather than silently truncated.
        if self.0.len() > u32::MAX as usize {
            return Err(Error::SequenceTooLarge);
        }
        #[allow(clippy::cast_possible_truncation)]
        (self.0.len() as u32).stream(out)?;
        out.extend_from_slice(&self.0);
        Ok(())
    }

    fn parse<const TRUSTED: bool>(input: &mut Cursor<&[u8]>) -> Result<Self> {
        let len = u32::parse::<TRUSTED>(input)? as usize;
        let start = usize::try_from(input.position()).map_err(|_| Error::EndOfBuffer)?;
        let end = start.checked_add(len).ok_or(Error::EndOfBuffer)?;
        let buf = *input.get_ref();
        if buf.len() < end {
            return Err(Error::EndOfBuffer);
        }
        input.set_position(end as u64);
        Ok(Self(buf[start..end].to_vec()))
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Bytes {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(value: Bytes) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoding is pinned as an absolute value, not compared against another encoder: a
    /// four-byte big-endian length followed by the raw payload. An encoder using a narrower
    /// prefix, or little-endian, produces different bytes here.
    #[test]
    fn streams_a_u32_big_endian_length_prefix_then_the_raw_payload() {
        let bytes = Bytes::new(vec![0xab, 0xcd, 0xef]);
        assert_eq!(
            bytes.to_bytes().expect("encode"),
            vec![0x00, 0x00, 0x00, 0x03, 0xab, 0xcd, 0xef]
        );
    }

    /// A length that no narrower prefix could express, so a `u8` or `u16` prefix masquerading as
    /// a `u32` cannot pass. 300 needs two bytes; the prefix must still occupy four.
    #[test]
    fn a_length_beyond_one_byte_still_occupies_four_prefix_bytes() {
        let encoded = Bytes::new(vec![7u8; 300]).to_bytes().expect("encode");
        assert_eq!(&encoded[..4], &[0x00, 0x00, 0x01, 0x2c]);
        assert_eq!(encoded.len(), 4 + 300);
    }

    #[test]
    fn empty_payload_streams_as_a_bare_zero_length() {
        assert_eq!(
            Bytes::default().to_bytes().expect("encode"),
            vec![0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn round_trips_through_parse() {
        let original = Bytes::new((0..300).map(|i| (i % 251) as u8).collect());
        let decoded = Bytes::from_bytes(&original.to_bytes().expect("encode")).expect("decode");
        assert_eq!(decoded, original);
    }

    /// A length prefix that promises more bytes than the buffer holds must be an error, not a
    /// panic and not a short read — the prefix is peer-controlled.
    #[test]
    fn a_length_prefix_longer_than_the_buffer_is_rejected() {
        let truncated = [0x00, 0x00, 0x00, 0x08, 0xab, 0xcd];
        assert!(Bytes::from_bytes(&truncated).is_err());
    }

    /// `u32::MAX` as a length must not overflow the cursor arithmetic on any pointer width.
    #[test]
    fn a_maximal_length_prefix_errors_rather_than_overflowing() {
        let hostile = [0xff, 0xff, 0xff, 0xff, 0x00];
        assert!(Bytes::from_bytes(&hostile).is_err());
    }

    #[test]
    fn renders_as_hex_in_both_display_and_debug() {
        let bytes = Bytes::new(vec![0x00, 0x0f, 0xff]);
        assert_eq!(bytes.to_string(), "000fff");
        assert_eq!(format!("{bytes:?}"), "Bytes(000fff)");
    }

    #[test]
    fn converts_to_and_from_the_shapes_callers_actually_hold() {
        let from_vec: Bytes = vec![1u8, 2, 3].into();
        let from_slice: Bytes = [1u8, 2, 3].as_slice().into();
        assert_eq!(from_vec, from_slice);
        assert_eq!(from_vec.as_ref(), &[1, 2, 3]);
        assert_eq!(&*from_slice, &[1, 2, 3]);
        assert_eq!(Vec::<u8>::from(from_vec.clone()), vec![1, 2, 3]);
        assert_eq!(from_vec.into_inner(), vec![1, 2, 3]);
    }

    #[test]
    fn reports_its_own_length_and_emptiness() {
        assert!(Bytes::default().is_empty());
        assert_eq!(Bytes::default().len(), 0);
        assert!(!Bytes::new(vec![1]).is_empty());
        assert_eq!(Bytes::new(vec![1, 2]).len(), 2);
    }
}
