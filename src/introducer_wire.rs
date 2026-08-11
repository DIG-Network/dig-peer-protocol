//! Introducer wire types for both Chia-standard and DIG-extension opcodes.
//!
//! ## Chia-standard (opcodes 63/64)
//!
//! [`RequestPeersIntroducer`] and [`RespondPeersIntroducer`] use `#[streamable(message)]`
//! because opcodes 63/64 exist in stock `ProtocolMessageTypes`. These work with
//! `Peer::request_infallible` directly.
//!
//! ## DIG-extension (opcodes 218/219)
//!
//! [`RegisterPeer`] and [`RegisterAck`] are DIG-specific (DSC-005). Since opcodes 218/219
//! don't exist in stock `ProtocolMessageTypes`, these structs implement `Streamable`
//! manually and provide `to_dig_message`/`from_dig_message` helpers for wire encoding
//! via [`DigMessage`] instead of the `ChiaProtocolMessage` trait.

use chia_protocol::TimestampedPeerInfo;
use chia_streamable_macro::streamable;
use chia_traits::Streamable;

use crate::dig_message::DigMessage;
use crate::dig_message_type::DigMessageType;
use crate::node_type::NodeType;

// ---------------------------------------------------------------------------
// Chia-standard introducer types (opcodes 63/64)
// ---------------------------------------------------------------------------

/// Empty introducer "get peers" request (protocol opcode **63**).
#[streamable(message)]
pub struct RequestPeersIntroducer {}

/// Introducer peer list response (protocol opcode **64**).
#[streamable(message)]
pub struct RespondPeersIntroducer {
    peer_list: Vec<TimestampedPeerInfo>,
}

// ---------------------------------------------------------------------------
// DIG-extension introducer types (opcodes 218/219)
// ---------------------------------------------------------------------------

/// Registration request: advertise this node's P2P reachability to the introducer.
///
/// Opcode **218** (`DigMessageType::RegisterPeer`). Not in stock `ProtocolMessageTypes`.
/// Use [`RegisterPeer::to_dig_message`] to encode for wire send.
#[streamable]
pub struct RegisterPeer {
    /// Externally reachable IP or hostname.
    ip: String,
    /// P2P listening port.
    port: u16,
    /// Declared service role — gossip nodes register as `NodeType::FullNode`.
    node_type: NodeType,
}

/// Introducer acknowledgement. `success == false` is a valid wire outcome (policy rejection).
///
/// Opcode **219** (`DigMessageType::RegisterAck`).
#[streamable]
pub struct RegisterAck {
    success: bool,
}

impl RegisterPeer {
    /// Encode as a [`DigMessage`] with opcode 218 and the given correlation `id`.
    pub fn to_dig_message(&self, id: Option<u16>) -> Result<DigMessage, chia_traits::Error> {
        let data = self.to_bytes()?;
        Ok(DigMessage::new(
            DigMessageType::RegisterPeer as u8,
            id,
            data.into(),
        ))
    }

    /// Decode from a [`DigMessage`]. Returns `None` if opcode is not 218.
    pub fn from_dig_message(msg: &DigMessage) -> Option<Result<Self, chia_traits::Error>> {
        if msg.msg_type != DigMessageType::RegisterPeer as u8 {
            return None;
        }
        Some(Self::from_bytes(&msg.data))
    }
}

impl RegisterAck {
    /// Encode as a [`DigMessage`] with opcode 219 and the given correlation `id`.
    pub fn to_dig_message(&self, id: Option<u16>) -> Result<DigMessage, chia_traits::Error> {
        let data = self.to_bytes()?;
        Ok(DigMessage::new(
            DigMessageType::RegisterAck as u8,
            id,
            data.into(),
        ))
    }

    /// Decode from a [`DigMessage`]. Returns `None` if opcode is not 219.
    pub fn from_dig_message(msg: &DigMessage) -> Option<Result<Self, chia_traits::Error>> {
        if msg.msg_type != DigMessageType::RegisterAck as u8 {
            return None;
        }
        Some(Self::from_bytes(&msg.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_peer_round_trip() {
        let rp = RegisterPeer::new("192.168.1.1".into(), 9444, NodeType::FullNode);
        let msg = rp.to_dig_message(Some(42)).expect("encode");
        assert_eq!(msg.msg_type, 218);
        assert_eq!(msg.id, Some(42));

        let decoded = RegisterPeer::from_dig_message(&msg)
            .expect("correct opcode")
            .expect("decode");
        assert_eq!(decoded.ip, "192.168.1.1");
        assert_eq!(decoded.port, 9444);
        assert_eq!(decoded.node_type, NodeType::FullNode);
    }

    #[test]
    fn register_ack_round_trip() {
        let ack = RegisterAck::new(true);
        let msg = ack.to_dig_message(None).expect("encode");
        assert_eq!(msg.msg_type, 219);
        assert_eq!(msg.id, None);

        let decoded = RegisterAck::from_dig_message(&msg)
            .expect("correct opcode")
            .expect("decode");
        assert!(decoded.success);
    }

    #[test]
    fn wrong_opcode_returns_none() {
        let msg = DigMessage::new(200, None, crate::Bytes::default());
        assert!(RegisterPeer::from_dig_message(&msg).is_none());
        assert!(RegisterAck::from_dig_message(&msg).is_none());
    }

    #[test]
    fn request_peers_introducer_streamable() {
        let req = RequestPeersIntroducer::new();
        let bytes = req.to_bytes().expect("encode");
        let _back = RequestPeersIntroducer::from_bytes(&bytes).expect("decode");
    }

    #[test]
    fn respond_peers_introducer_streamable() {
        let resp = RespondPeersIntroducer::new(vec![]);
        let bytes = resp.to_bytes().expect("encode");
        let back = RespondPeersIntroducer::from_bytes(&bytes).expect("decode");
        assert!(back.peer_list.is_empty());
    }

    #[test]
    fn respond_peers_introducer_with_populated_list_round_trips() {
        // A non-empty peer_list exercises the Vec<TimestampedPeerInfo> serialization path.
        // TimestampedPeerInfo fields are private to chia-protocol, so build via the
        // generated `new()` and compare by derived equality rather than field access.
        let peers = vec![
            TimestampedPeerInfo::new("203.0.113.7".into(), 9444, 1_700_000_000),
            TimestampedPeerInfo::new("198.51.100.42".into(), 18444, 1_700_000_500),
        ];
        let resp = RespondPeersIntroducer::new(peers.clone());
        let bytes = resp.to_bytes().expect("encode");
        let back = RespondPeersIntroducer::from_bytes(&bytes).expect("decode");
        assert_eq!(back.peer_list.len(), 2);
        assert_eq!(back.peer_list, peers);
        // A different list must NOT compare equal (guards against a trivial all-pass).
        let other = vec![TimestampedPeerInfo::new("10.0.0.1".into(), 1, 1)];
        assert_ne!(back.peer_list, other);
    }

    #[test]
    fn register_peer_from_dig_message_decode_error() {
        // Correct opcode (218) but a corrupt/truncated body: the opcode check passes
        // (Some(..)), so the inner Streamable::from_bytes returns Err — covering the
        // decode-error arm rather than the wrong-opcode None arm.
        let bad = DigMessage::new(
            DigMessageType::RegisterPeer as u8,
            None,
            crate::Bytes::new(vec![0xFF]), // not a valid RegisterPeer encoding
        );
        let result = RegisterPeer::from_dig_message(&bad);
        let inner = result.expect("opcode matched, so we get Some(..)");
        assert!(inner.is_err(), "corrupt body must surface a decode Err");
    }

    #[test]
    fn register_ack_from_dig_message_decode_error() {
        // Same path for RegisterAck (opcode 219) with an empty body — a bool needs 1 byte.
        let bad = DigMessage::new(
            DigMessageType::RegisterAck as u8,
            None,
            crate::Bytes::default(),
        );
        let result = RegisterAck::from_dig_message(&bad);
        let inner = result.expect("opcode matched, so we get Some(..)");
        assert!(
            inner.is_err(),
            "empty body must surface a decode Err for a bool field"
        );
    }

    #[test]
    fn register_ack_false_round_trips() {
        // success == false is an explicit valid wire outcome (policy rejection).
        let ack = RegisterAck::new(false);
        let msg = ack.to_dig_message(Some(9)).expect("encode");
        assert_eq!(msg.msg_type, 219);
        assert_eq!(msg.id, Some(9));
        let decoded = RegisterAck::from_dig_message(&msg)
            .expect("correct opcode")
            .expect("decode");
        assert!(!decoded.success);
    }
}
