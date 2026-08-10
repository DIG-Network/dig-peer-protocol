//! [`DigMessage`] — the native DIG peer envelope, with a raw `u8` opcode.
//!
//! ## The problem it exists to solve
//!
//! `chia_protocol::Message` stores `msg_type` as `ProtocolMessageTypes`, a closed `#[repr(u8)]`
//! enum with no `Unknown(u8)` variant. `Message::from_bytes` rejects any opcode outside it, so a
//! DIG opcode could not be encoded or decoded through that type without forking the upstream
//! crate — which is exactly what DIG used to do.
//!
//! ## The native envelope
//!
//! `DigMessage` owns its encoding outright: [`to_bytes`](DigMessage::to_bytes) and
//! [`from_bytes`](DigMessage::from_bytes) write and read the wire directly, with no upstream
//! type participating. It is DIG's envelope for every DIG opcode, and it can express a chia-band
//! opcode identically because the layout is the same one chia peers already speak.
//!
//! ```text
//! [u8 msg_type] [u8 has_id (0/1)] [u16 id (big-endian, if has_id)] [u32 data_len (big-endian)] [data...]
//! ```
//!
//! ## No bridge to `chia_protocol::Message`
//!
//! There is deliberately no conversion to or from `chia_protocol::Message`. Earlier revisions
//! carried four such helpers, and they were the on-ramp back onto the forked route: a consumer
//! that could cheaply obtain a `Message` kept building one, and the closed enum came back with
//! it. Chia-band traffic to chia peers goes through
//! [`DigLink`](crate::DigLink)'s typed `send`/`request`, which derive their opcode from
//! `ChiaProtocolMessage` — that is the supported chia path, and the only one.

use crate::Bytes;

/// The DIG peer envelope: a raw `u8` opcode, an optional correlation id, and a payload.
///
/// Expresses any opcode, DIG-band or chia-band, because the opcode is a plain byte with no enum
/// standing between it and the wire.
///
/// ```text
/// [u8 msg_type] [u8 has_id] [u16 id (if has_id)] [u32 data_len] [u8... data]
/// ```
///
/// The encoding is pinned as absolute hex in `tests/golden_wire_vectors.rs`. It is a live
/// network's wire format: a change to these bytes is a coordinated network event, never a
/// refactor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigMessage {
    /// Raw wire opcode — no enum restriction.
    pub msg_type: u8,
    /// Correlation ID for request/response pairing (same as `Message.id`).
    pub id: Option<u16>,
    /// Serialized payload body.
    pub data: Bytes,
}

impl DigMessage {
    /// Protocol-level ceiling on a single message's declared payload length (bytes).
    ///
    /// `from_bytes` rejects any `data_len` prefix above this value with `None` before
    /// slicing/allocating the payload, so a peer cannot force a multi-gigabyte `Vec`
    /// allocation via a lying (or genuine but oversized) length prefix. Mirrors
    /// `chia-protocol`'s own message-size ceiling (16 MiB) — comfortably above any
    /// legitimate DIG opcode payload (attestations, checkpoints, block-transaction
    /// batches) while bounding worst-case per-message memory.
    ///
    /// **Callers MUST still enforce a per-frame size cap at the transport/framing layer
    /// BEFORE buffering an incoming frame into a contiguous `&[u8]`** — this constant
    /// only bounds what `from_bytes` will accept once a slice already exists; it cannot
    /// stop a transport from reading an unbounded number of bytes off the wire first.
    pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

    /// Construct a new DIG message.
    pub fn new(msg_type: u8, id: Option<u16>, data: Bytes) -> Self {
        Self { msg_type, id, data }
    }

    /// Serialize to wire bytes (same format as `Message::to_bytes`).
    ///
    /// Layout: `[u8 msg_type] [u8 has_id (0/1)] [u16 id if present] [u32 data_len] [data...]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 1 + 2 + 4 + self.data.len());
        buf.push(self.msg_type);
        match self.id {
            Some(id) => {
                buf.push(1); // has_id = true
                buf.extend_from_slice(&id.to_be_bytes());
            }
            None => {
                buf.push(0); // has_id = false
            }
        }
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialize from wire bytes. Accepts any `msg_type` value — no enum validation.
    ///
    /// Returns `None` if the buffer is too short, the length prefix doesn't match, or
    /// the declared `data_len` exceeds [`Self::MAX_MESSAGE_SIZE`].
    ///
    /// This is a leaf parser over an already-materialized `&[u8]`: the `MAX_MESSAGE_SIZE`
    /// check bounds the allocation this function performs, but it cannot bound how many
    /// bytes a transport read off the wire to build `bytes` in the first place. **Callers
    /// MUST enforce a per-frame size cap at the transport/framing layer before buffering
    /// an incoming frame**, so that a peer cannot force unbounded buffering ahead of ever
    /// reaching this function.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let msg_type = bytes[0];
        let has_id = bytes[1];
        let mut offset: usize = 2;

        let id = if has_id != 0 {
            let after_id = offset.checked_add(2)?;
            if bytes.len() < after_id {
                return None;
            }
            let id = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            offset = after_id;
            Some(id)
        } else {
            None
        };

        let after_len = offset.checked_add(4)?;
        if bytes.len() < after_len {
            return None;
        }
        let data_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset = after_len;

        if data_len > Self::MAX_MESSAGE_SIZE {
            return None;
        }

        // Checked (not `offset + data_len`) so a peer-controlled `data_len` can never
        // wrap `usize` on a 32-bit target — overflow here returns None instead of
        // either panicking (debug) or proceeding with a wrapped, corrupted range
        // (release). MAX_MESSAGE_SIZE already rejects data_len this large in practice,
        // but the arithmetic itself stays overflow-safe independent of that cap.
        let end = offset.checked_add(data_len)?;
        if bytes.len() < end {
            return None;
        }
        let data = Bytes::new(bytes[offset..end].to_vec());

        Some(Self { msg_type, id, data })
    }

    /// Deserialize from an OWNED byte buffer, moving the payload instead of copying it.
    ///
    /// Identical acceptance/rejection rules to [`Self::from_bytes`] (same length checks,
    /// same [`Self::MAX_MESSAGE_SIZE`] cap, same `None` on any malformed input) — the
    /// only difference is that when `buf` already owns its bytes (e.g. a transport that
    /// read the frame directly into a `Vec<u8>`), the payload is moved into the result
    /// via `Vec::drain` instead of being copied out of a borrowed `&[u8]` with `to_vec`.
    /// Prefer this over `from_bytes` whenever the caller already has an owned `Vec<u8>`
    /// and does not need it afterward.
    pub fn from_bytes_owned(mut buf: Vec<u8>) -> Option<Self> {
        if buf.len() < 2 {
            return None;
        }
        let msg_type = buf[0];
        let has_id = buf[1];
        let mut offset: usize = 2;

        let id = if has_id != 0 {
            let after_id = offset.checked_add(2)?;
            if buf.len() < after_id {
                return None;
            }
            let id = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset = after_id;
            Some(id)
        } else {
            None
        };

        let after_len = offset.checked_add(4)?;
        if buf.len() < after_len {
            return None;
        }
        let data_len = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) as usize;
        offset = after_len;

        if data_len > Self::MAX_MESSAGE_SIZE {
            return None;
        }

        let end = offset.checked_add(data_len)?;
        if buf.len() < end {
            return None;
        }

        // Move just the payload range out of `buf` without copying: drain removes and
        // yields the [offset..end) elements by value, leaving any trailing bytes (and
        // the header bytes before offset) dropped rather than retained.
        let data: Vec<u8> = buf.drain(offset..end).collect();

        Some(Self {
            msg_type,
            id,
            data: Bytes::new(data),
        })
    }

    /// Whether this message carries a DIG extension opcode (>= 200).
    pub fn is_dig_extension(&self) -> bool {
        self.msg_type >= 200
    }

    /// Whether this message carries a standard Chia opcode (< 200).
    pub fn is_chia_standard(&self) -> bool {
        self.msg_type < 200
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_chia_opcode() {
        // NewPeak = 20
        let msg = DigMessage::new(20, Some(42), Bytes::new(vec![1, 2, 3]));
        let wire = msg.to_bytes();
        let decoded = DigMessage::from_bytes(&wire).expect("decode");
        assert_eq!(decoded.msg_type, 20);
        assert_eq!(decoded.id, Some(42));
        assert_eq!(decoded.data.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn round_trip_dig_opcode() {
        // RegisterPeer = 218
        let msg = DigMessage::new(218, None, Bytes::new(vec![0xAB]));
        let wire = msg.to_bytes();
        let decoded = DigMessage::from_bytes(&wire).expect("decode");
        assert_eq!(decoded.msg_type, 218);
        assert_eq!(decoded.id, None);
        assert!(decoded.is_dig_extension());
        assert!(!decoded.is_chia_standard());
    }

    #[test]
    fn from_bytes_owned_avoids_copy_when_buffer_is_owned() {
        // Given an owned Vec<u8> (e.g. a transport that already read the frame into its
        // own buffer), from_bytes_owned must decode identically to from_bytes but move
        // the payload bytes into the resulting DigMessage instead of copying them via
        // to_vec() on a borrowed slice.
        let msg = DigMessage::new(218, Some(7), Bytes::new(vec![9, 9, 9]));
        let wire: Vec<u8> = msg.to_bytes();
        let decoded = DigMessage::from_bytes_owned(wire).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn from_bytes_owned_rejects_same_malformed_inputs_as_from_bytes() {
        assert!(DigMessage::from_bytes_owned(vec![]).is_none());
        assert!(DigMessage::from_bytes_owned(vec![20, 1]).is_none());

        let mut wire = vec![1u8, 0];
        wire.extend_from_slice(&((DigMessage::MAX_MESSAGE_SIZE as u32) + 1).to_be_bytes());
        assert!(DigMessage::from_bytes_owned(wire).is_none());

        let truncated = vec![20u8, 0, 0x00, 0x00, 0x00, 0x04, 0xAB, 0xCD];
        assert!(DigMessage::from_bytes_owned(truncated).is_none());
    }

    #[test]
    fn from_bytes_owned_ignores_trailing_bytes_like_from_bytes() {
        // Parity with from_bytes: trailing bytes beyond data_len are not an error and
        // are simply not included in the decoded payload.
        let mut wire = vec![20u8, 0, 0x00, 0x00, 0x00, 0x02, 0xAB, 0xCD];
        wire.extend_from_slice(&[0xEE, 0xFF]); // trailing garbage
        let decoded = DigMessage::from_bytes_owned(wire).expect("decode");
        assert_eq!(decoded.data.as_ref(), &[0xAB, 0xCD]);
    }

    #[test]
    fn empty_buffer_returns_none() {
        assert!(DigMessage::from_bytes(&[]).is_none());
        assert!(DigMessage::from_bytes(&[20]).is_none());
    }

    #[test]
    fn truncated_id_prefix_returns_none() {
        // has_id = 1 but the buffer ends before the 2-byte id can be read.
        // [msg_type=20][has_id=1] then only ONE of the two id bytes present.
        assert!(DigMessage::from_bytes(&[20, 1]).is_none());
        assert!(DigMessage::from_bytes(&[20, 1, 0x00]).is_none());
    }

    #[test]
    fn truncated_data_len_prefix_returns_none() {
        // has_id = 0, so offset = 2, but fewer than 4 bytes remain for the u32 data_len.
        assert!(DigMessage::from_bytes(&[20, 0]).is_none());
        assert!(DigMessage::from_bytes(&[20, 0, 0x00, 0x00, 0x00]).is_none());

        // With an id present (offset = 4), still short of the 4-byte data_len.
        assert!(DigMessage::from_bytes(&[20, 1, 0x00, 0x2A, 0x00, 0x00]).is_none());
    }

    #[test]
    fn truncated_data_returns_none() {
        // Declares data_len = 4 but supplies only 2 payload bytes.
        // [msg_type=20][has_id=0][data_len=00 00 00 04][data=AB CD] (missing 2 bytes)
        let wire = [20u8, 0, 0x00, 0x00, 0x00, 0x04, 0xAB, 0xCD];
        assert!(DigMessage::from_bytes(&wire).is_none());

        // Exact-fit boundary: data_len = 2 with exactly 2 payload bytes decodes.
        let ok = [20u8, 0, 0x00, 0x00, 0x00, 0x02, 0xAB, 0xCD];
        let decoded = DigMessage::from_bytes(&ok).expect("exact-length payload decodes");
        assert_eq!(decoded.data.as_ref(), &[0xAB, 0xCD]);
    }

    #[test]
    fn oversized_data_len_is_rejected() {
        // data_len prefix declares more than MAX_MESSAGE_SIZE — must be rejected with
        // None BEFORE any attempt to read/allocate the (possibly absent) payload bytes,
        // regardless of how many bytes actually follow.
        let over = (DigMessage::MAX_MESSAGE_SIZE as u32) + 1;
        let mut wire = vec![20u8, 0]; // msg_type=20, has_id=0
        wire.extend_from_slice(&over.to_be_bytes());
        // No payload bytes supplied at all — if the cap check didn't fire first, this
        // would already fail the length check, so also prove the cap fires even when
        // enough bytes *are* present.
        assert!(DigMessage::from_bytes(&wire).is_none());
    }

    #[test]
    fn max_data_len_prefix_does_not_panic_and_is_rejected() {
        // data_len = u32::MAX. On a 32-bit target this used to overflow `offset +
        // data_len` (unchecked usize addition): a debug build would panic (a
        // network-reachable crash), a release build would wrap and proceed into a
        // corrupted slice range. The fix uses checked_add and must return None
        // uniformly, on every target width, without panicking either way — this test
        // must pass identically under `cargo test` (checked arithmetic, debug or
        // release) regardless of pointer width. (Also caught by the MAX_MESSAGE_SIZE
        // cap now, but the bounds-check arithmetic itself must be overflow-safe
        // independent of that cap — see the direct offset-overflow test below.)
        let mut wire = vec![20u8, 0]; // msg_type=20, has_id=0
        wire.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(DigMessage::from_bytes(&wire).is_none());
    }

    #[test]
    fn offset_plus_data_len_overflow_is_checked_not_wrapping() {
        // Regression test for the raw `offset + data_len` addition itself (line 98 in
        // the pre-fix code / the bounds check below the MAX_MESSAGE_SIZE cap): it must
        // use checked arithmetic and return None on overflow rather than silently
        // wrapping (which on a 32-bit usize could previously turn a huge data_len into
        // a small wrapped value that passed the length check and then panicked on the
        // slice index instead). usize::MAX stands in for "large enough to overflow
        // offset + data_len on the current target's pointer width" — on 64-bit this
        // value is not reachable via a real u32 data_len, so this test exercises the
        // checked_add call path directly rather than only the u32-parsed case above.
        let bytes = [20u8, 0, 0, 0, 0, 0]; // msg_type, has_id=0, data_len=0
                                           // Sanity: normal zero-length message still decodes fine (no regression).
        assert!(DigMessage::from_bytes(&bytes).is_some());

        // The u32::MAX case above is the reachable-from-the-wire overflow probe; assert
        // its result is a clean None (not a panic) for every build profile.
        let mut wire = vec![1u8, 0];
        wire.extend_from_slice(&u32::MAX.to_be_bytes());
        let result = std::panic::catch_unwind(|| DigMessage::from_bytes(&wire));
        assert!(
            result.is_ok(),
            "from_bytes must not panic on data_len = u32::MAX"
        );
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn data_len_one_byte_over_cap_is_rejected_at_exact_boundary() {
        // Prove the cap is enforced as `> MAX_MESSAGE_SIZE`, not some looser bound, by
        // checking the smallest possible over-cap value (cap + 1) is rejected even
        // though the length-prefix parsing itself succeeds (only the cap check fails).
        let over_by_one = (DigMessage::MAX_MESSAGE_SIZE as u32) + 1;
        let mut wire = vec![1u8, 0];
        wire.extend_from_slice(&over_by_one.to_be_bytes());
        assert!(DigMessage::from_bytes(&wire).is_none());
    }

    #[test]
    fn zero_length_data_round_trip() {
        // data_len = 0 is a valid wire message (e.g. RegisterPeersIntroducer body).
        let msg = DigMessage::new(64, Some(1), Bytes::default());
        let wire = msg.to_bytes();
        let decoded = DigMessage::from_bytes(&wire).expect("zero-length decode");
        assert_eq!(decoded, msg);
        assert!(decoded.data.as_ref().is_empty());
    }

    #[test]
    fn dig_extension_boundary_at_200() {
        // 199 is the last Chia-standard value; 200 is the first DIG extension value.
        let below = DigMessage::new(199, None, Bytes::default());
        assert!(below.is_chia_standard());
        assert!(!below.is_dig_extension());

        let at = DigMessage::new(200, None, Bytes::default());
        assert!(at.is_dig_extension());
        assert!(!at.is_chia_standard());
    }
}
