//! Absolute golden vectors for every byte `dig-peer-protocol` puts on the DIG peer wire.
//!
//! ## Why these exist, when `wire_compatibility.rs` already asserts equality
//!
//! `wire_compatibility.rs` proves `DigMessage` encodes *the same bytes as*
//! `chia_protocol::Message`. That is a **relative** proof: if an upstream chia release changed
//! `Message`'s layout, both sides of the comparison would move together and the test would stay
//! green while the live network broke. It measures agreement, not stability.
//!
//! These vectors are **absolute**. Every expected value below is a hex literal transcribed from
//! the encoder as it behaved on the chia 0.26 line — the bytes real DIG peers are exchanging
//! right now. Nothing in this file derives an expectation from the code under test, from an
//! upstream crate, or from a round-trip; a change to any encoder, upstream or DIG-owned, shows up
//! here as a diff.
//!
//! ## What they are the instrument for
//!
//! The DIG peer wire is decoupling from `chia-protocol`, and the DIG opcode band is carried by a
//! live network. A decoupling is only safe if it is byte-preserving, and "byte-preserving" is not
//! checkable against a moving reference. These vectors are the fixed reference.
//!
//! **If a vector in this file changes, the wire changed.** That is a coordinated network event,
//! never a refactor.
//!
//! ## Fixture design
//!
//! Each vector is chosen against the nearest wrong encoder rather than for convenience:
//!
//! | Axis | Value | The wrong encoder it catches |
//! |---|---|---|
//! | `id` | `Some(0x0102)` | little-endian id, or a wrong `Option` tag byte |
//! | payload length | `0x0140` (320) | a `u8`/`u16` length prefix masquerading as `u32` |
//! | payload bytes | a non-constant ramp | a truncated, padded or misaligned copy |
//! | opcode | 218/219/220 **and** a chia opcode | an encoder that special-cases one band |
//! | `NodeType` | `FullNode` **and** `Introducer` | a hard-coded discriminant |
//! | `String` field | non-empty, non-ASCII-boundary length | a missing or narrow length prefix |

use chia_protocol::TimestampedPeerInfo;
use chia_traits::Streamable;
use dig_peer_protocol::{
    Bytes, DigMessage, NodeType, RegisterAck, RegisterPeer, RequestPeersIntroducer,
    RespondPeersIntroducer,
};

/// Render bytes as lowercase hex so a failure prints a diffable value rather than a `Vec` dump.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A payload whose bytes all differ from one another modulo 251, so a copy that is short by one,
/// offset by one, or zero-padded cannot coincidentally match.
fn ramp(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// An id whose two bytes differ, so a little-endian encoding cannot pass by accident.
const ASYMMETRIC_ID: u16 = 0x0102;

// ---------------------------------------------------------------------------
// DigMessage framing — the envelope every DIG peer message rides in
// ---------------------------------------------------------------------------

#[test]
fn golden_dig_message_frame_with_id_and_large_payload() {
    // Opcode 220 (DigMessage) with a 320-byte payload: 320 > 255, so a u8 length prefix cannot
    // encode it, and the u32 prefix must read 00 00 01 40.
    let msg = DigMessage::new(220, Some(ASYMMETRIC_ID), Bytes::new(ramp(320)));
    let wire = msg.to_bytes();

    assert_eq!(
        hex(&wire[..8]),
        "dc01010200000140",
        "frame header changed: opcode/has_id/id/length-prefix"
    );
    assert_eq!(wire.len(), 1 + 1 + 2 + 4 + 320);
}

#[test]
fn golden_dig_message_frame_without_id_and_empty_payload() {
    // The degenerate frame: no id, no payload. Pins the `has_id = 0` tag and the zero length.
    let msg = DigMessage::new(218, None, Bytes::default());
    assert_eq!(hex(&msg.to_bytes()), "da0000000000");
}

#[test]
fn golden_dig_message_frame_chia_band_opcode() {
    // A chia-band opcode through the DIG encoder must produce the identical envelope shape —
    // an encoder that branched on the band would diverge here.
    let msg = DigMessage::new(20, Some(ASYMMETRIC_ID), Bytes::new(vec![0xab, 0xcd]));
    assert_eq!(hex(&msg.to_bytes()), "1401010200000002abcd");
}

// ---------------------------------------------------------------------------
// DIG-extension bodies (opcodes 218/219) — carried inside the envelope above
// ---------------------------------------------------------------------------

#[test]
fn golden_register_peer_body_full_node() {
    let rp = RegisterPeer::new("192.168.1.1".into(), 9444, NodeType::FullNode);
    assert_eq!(
        hex(&rp.to_bytes().expect("encode")),
        "0000000b3139322e3136382e312e3124e401"
    );
}

#[test]
fn golden_register_peer_body_introducer_node_type() {
    // A second NodeType, so the discriminant byte is proven to vary with the field rather than
    // being a constant that happens to match FullNode.
    let rp = RegisterPeer::new("203.0.113.7".into(), 18444, NodeType::Introducer);
    assert_eq!(
        hex(&rp.to_bytes().expect("encode")),
        "0000000b3230332e302e3131332e37480c05"
    );
}

#[test]
fn golden_register_ack_body_both_polarities() {
    // Both values, because a bool encoder that emitted a constant would pass a one-sided test.
    assert_eq!(
        hex(&RegisterAck::new(true).to_bytes().expect("encode")),
        "01"
    );
    assert_eq!(
        hex(&RegisterAck::new(false).to_bytes().expect("encode")),
        "00"
    );
}

// ---------------------------------------------------------------------------
// Chia-standard introducer bodies (opcodes 63/64)
// ---------------------------------------------------------------------------

#[test]
fn golden_request_peers_introducer_body_is_empty() {
    assert_eq!(
        hex(&RequestPeersIntroducer::new().to_bytes().expect("encode")),
        ""
    );
}

#[test]
fn golden_respond_peers_introducer_body_with_two_peers() {
    // A populated list pins the Vec length prefix, the per-entry field order and the u64
    // timestamp width — all of which are upstream `TimestampedPeerInfo`'s encoding, and so the
    // most likely thing to shift under a chia bump.
    let resp = RespondPeersIntroducer::new(vec![
        TimestampedPeerInfo::new("203.0.113.7".into(), 9444, 1_700_000_000),
        TimestampedPeerInfo::new("198.51.100.42".into(), 18444, 1_700_000_500),
    ]);
    assert_eq!(
        hex(&resp.to_bytes().expect("encode")),
        concat!(
            "00000002", // Vec length prefix (u32, big-endian)
            "0000000b",
            "3230332e302e3131332e37",
            "24e4",
            "000000006553f100", // peer 0
            "0000000d",
            "3139382e35312e3130302e3432",
            "480c",
            "000000006553f2f4", // peer 1
        )
    );
}

#[test]
fn golden_respond_peers_introducer_body_empty_list() {
    assert_eq!(
        hex(&RespondPeersIntroducer::new(vec![])
            .to_bytes()
            .expect("encode")),
        "00000000"
    );
}

// ---------------------------------------------------------------------------
// Decode direction — the blessed bytes must still be READ correctly
// ---------------------------------------------------------------------------
//
// Every vector above proves the *encode* direction: our encoder still emits the bytes the live
// network expects. That is only half the contract, and the half that a symmetric change cannot
// break silently is the other half. If an upstream release moved both the encoder and the decoder
// together — a renumbered discriminant, a widened length prefix, a reordered field — the encode
// vectors above would fail loudly, but a change that moved *only* the decoder (a newly tolerated
// prefix, a relaxed bound, a shifted field offset) would not be visible at all from the encode
// side.
//
// So each vector below feeds a hex literal transcribed from the chia 0.26 line — the bytes a
// deployed peer is putting on the wire today — into our decoder and asserts the reconstructed
// value field by field. The literals are the *same* constants as the encode vectors, deliberately:
// pairing one fixed byte string against both directions is what makes the pair a compatibility
// proof rather than two independent round-trips.

/// Parse a lowercase hex literal into bytes. Panics on malformed input, which can only be a typo
/// in a fixture — a test-authoring error, never a runtime condition.
fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex literal must have even length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn golden_decode_dig_message_frame_with_id_and_large_payload() {
    let wire = {
        let mut w = unhex("dc01010200000140");
        w.extend_from_slice(&ramp(320));
        w
    };
    let msg = DigMessage::from_bytes(&wire).expect("0.26-blessed frame must decode");
    assert_eq!(msg.msg_type, 220);
    assert_eq!(msg.id, Some(ASYMMETRIC_ID));
    assert_eq!(msg.data.as_ref(), &ramp(320)[..]);
}

#[test]
fn golden_decode_dig_message_frame_without_id_and_empty_payload() {
    let msg = DigMessage::from_bytes(&unhex("da0000000000")).expect("blessed frame must decode");
    assert_eq!(msg.msg_type, 218);
    assert_eq!(msg.id, None);
    assert!(msg.data.as_ref().is_empty());
}

#[test]
fn golden_decode_dig_message_frame_chia_band_opcode() {
    let msg =
        DigMessage::from_bytes(&unhex("1401010200000002abcd")).expect("blessed frame must decode");
    assert_eq!(msg.msg_type, 20);
    assert_eq!(msg.id, Some(ASYMMETRIC_ID));
    assert_eq!(msg.data.as_ref(), &[0xab, 0xcd]);
}

#[test]
fn golden_decode_register_peer_body_full_node() {
    let rp = RegisterPeer::from_bytes(&unhex("0000000b3139322e3136382e312e3124e401"))
        .expect("0.26-blessed RegisterPeer must decode");
    assert_eq!(rp.ip, "192.168.1.1");
    assert_eq!(rp.port, 9444);
    assert_eq!(rp.node_type, NodeType::FullNode);
}

#[test]
fn golden_decode_register_peer_body_introducer_node_type() {
    // The second NodeType, so the decoder is proven to read the discriminant rather than to
    // return a constant that happens to match FullNode.
    let rp = RegisterPeer::from_bytes(&unhex("0000000b3230332e302e3131332e37480c05"))
        .expect("0.26-blessed RegisterPeer must decode");
    assert_eq!(rp.ip, "203.0.113.7");
    assert_eq!(rp.port, 18444);
    assert_eq!(rp.node_type, NodeType::Introducer);
}

#[test]
fn golden_decode_register_ack_body_both_polarities() {
    assert!(
        RegisterAck::from_bytes(&unhex("01"))
            .expect("blessed RegisterAck must decode")
            .success
    );
    assert!(
        !RegisterAck::from_bytes(&unhex("00"))
            .expect("blessed RegisterAck must decode")
            .success
    );
}

#[test]
fn golden_decode_respond_peers_introducer_body_with_two_peers() {
    let resp = RespondPeersIntroducer::from_bytes(&unhex(concat!(
        "00000002",
        "0000000b",
        "3230332e302e3131332e37",
        "24e4",
        "000000006553f100",
        "0000000d",
        "3139382e35312e3130302e3432",
        "480c",
        "000000006553f2f4",
    )))
    .expect("0.26-blessed peer list must decode");
    assert_eq!(
        resp.peer_list,
        vec![
            TimestampedPeerInfo::new("203.0.113.7".into(), 9444, 1_700_000_000),
            TimestampedPeerInfo::new("198.51.100.42".into(), 18444, 1_700_000_500),
        ]
    );
}

#[test]
fn golden_decode_respond_peers_introducer_body_empty_list() {
    let resp = RespondPeersIntroducer::from_bytes(&unhex("00000000")).expect("must decode");
    assert!(resp.peer_list.is_empty());
}
