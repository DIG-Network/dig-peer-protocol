//! Golden proof that [`DigMessage`] is byte-identical to `chia_protocol::Message` on the wire.
//!
//! The whole DIG peer link rests on this equality: `DigLink` frames every outbound message —
//! Chia opcode or DIG opcode — with `DigMessage`, so a stock Chia peer on the far end must see
//! exactly the bytes `Message` would have produced. This is asserted here, never inferred from
//! a doc comment.
//!
//! The fixture is deliberately built to be able to FAIL. An encoder that agrees with Chia only
//! on the easy cases would pass a lazier test, so every axis below is chosen against the nearest
//! plausibly-wrong encoder:
//!
//! | Axis | Values | The wrong encoder it catches |
//! |---|---|---|
//! | opcode | **every** valid `ProtocolMessageTypes`, derived by probing all 256 `u8`s | one that only works for the low/contiguous opcodes |
//! | `id` | `None`, and `Some(0x0102)` — asymmetric, so BE ≠ LE | a little-endian id, or a wrong `Option` tag |
//! | payload len | 0, 1, 300, 65_600 | a `u8` (>255) or `u16` (>65_535) length prefix masquerading as `u32` |

use chia_protocol::{Bytes, Message, ProtocolMessageTypes};
use chia_traits::Streamable;
use dig_peer_protocol::DigMessage;

/// Every opcode `chia_protocol` actually accepts, derived by probing the decoder over all 256
/// byte values rather than transcribing the enum — a hand-written list would silently drift from
/// upstream, and the gaps in Chia's numbering make transcription error-prone.
fn all_chia_opcodes() -> Vec<u8> {
    (0..=u8::MAX)
        .filter(|byte| ProtocolMessageTypes::from_bytes(&[*byte]).is_ok())
        .collect()
}

/// Payload lengths that discriminate a `u32` length prefix from every narrower one, plus the
/// degenerate empty and single-byte cases.
const PAYLOAD_LENGTHS: [usize; 4] = [0, 1, 300, 65_600];

/// An id whose two bytes differ, so a little-endian encoding cannot pass by accident.
const ASYMMETRIC_ID: u16 = 0x0102;

#[test]
fn dig_message_encodes_byte_identically_to_chia_message() {
    let opcodes = all_chia_opcodes();
    assert!(
        opcodes.len() > 100,
        "probe found only {} opcodes — the fixture is not exercising the real namespace",
        opcodes.len()
    );

    for opcode in opcodes {
        let chia_type = ProtocolMessageTypes::from_bytes(&[opcode]).expect("probed as valid");

        for id in [None, Some(ASYMMETRIC_ID)] {
            for len in PAYLOAD_LENGTHS {
                // A varying payload, so a truncated or misaligned copy shows up as a diff
                // rather than as a run of identical bytes.
                let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

                let chia = Message {
                    msg_type: chia_type,
                    id,
                    data: Bytes::new(payload.clone()),
                };
                let dig = DigMessage::new(opcode, id, Bytes::new(payload));

                assert_eq!(
                    dig.to_bytes(),
                    chia.to_bytes().expect("chia encode"),
                    "encoding diverged for opcode {opcode} (id={id:?}, payload_len={len})"
                );
            }
        }
    }
}

#[test]
fn dig_message_decodes_what_chia_message_encoded() {
    for opcode in all_chia_opcodes() {
        let chia_type = ProtocolMessageTypes::from_bytes(&[opcode]).expect("probed as valid");

        for id in [None, Some(ASYMMETRIC_ID)] {
            for len in PAYLOAD_LENGTHS {
                let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let wire = Message {
                    msg_type: chia_type,
                    id,
                    data: Bytes::new(payload.clone()),
                }
                .to_bytes()
                .expect("chia encode");

                let decoded = DigMessage::from_bytes(&wire)
                    .unwrap_or_else(|| panic!("DigMessage rejected a real Chia frame ({opcode})"));

                assert_eq!(decoded.msg_type, opcode);
                assert_eq!(decoded.id, id);
                assert_eq!(decoded.data.as_ref(), payload.as_slice());
            }
        }
    }
}
