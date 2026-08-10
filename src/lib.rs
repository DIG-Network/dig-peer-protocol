//! # dig-peer-protocol
//!
//! The DIG Network peer wire — a **native** protocol, plus the narrow chia surface a DIG node
//! needs to also speak to chia full nodes.
//!
//! ## The native DIG wire
//!
//! [`DigMessage`] is the envelope for every DIG message: a raw `u8` opcode, an optional
//! correlation id, and a [`Bytes`] payload, encoded by this crate and nothing else. It carries
//! the `200..=222` DIG opcode band, which `chia_protocol::Message` structurally cannot express —
//! its `ProtocolMessageTypes` is a closed `#[repr(u8)]` enum with no `Unknown(u8)`, so a DIG
//! opcode is neither constructible nor decodable through it, and one inbound DIG frame drops a
//! whole `chia-sdk-client` connection rather than that one frame.
//!
//! DIG answered that with vendored forks of `chia-protocol` and `chia-sdk-client`. This crate
//! replaces the forks: [`DigLink`] is a websocket peer link written directly against the wire
//! format, and the DIG types it carries — [`Bytes`], [`NodeType`], [`DigMessage`],
//! [`DigMessageType`], [`RegisterPeer`], [`RegisterAck`] — are DIG's own.
//!
//! ## What is deliberately still chia, and why
//!
//! Decoupling from `chia-protocol` is not the same as decoupling from every crate whose name
//! starts with `chia`. Two are kept ON PURPOSE. **Do not "finish the decoupling" by removing
//! them** — they were assessed and retained:
//!
//! - **`chia-traits` ([`Streamable`]) and `chia_streamable_macro` ([`macro@streamable`])** — a
//!   serialization trait and a derive macro. Neither has the property this crate is escaping:
//!   there is no closed enum and no private-field wire authority in either. They serialize the
//!   *bodies* of DIG messages, and they do it with an encoding that is already live on the
//!   network. Replacing them would mean owning a serializer — new surface, and a fresh
//!   byte-identity risk — to buy nothing that matters.
//! - **`chia-protocol`'s `ChiaProtocolMessage` and `TimestampedPeerInfo`, and
//!   `chia-sdk-client`** — these serve genuine *chia* traffic. A DIG node talks to chia full
//!   nodes too: [`DigLink`]'s typed `send`/`request` derive a chia opcode from
//!   `ChiaProtocolMessage`, [`RespondPeersIntroducer`] is chia opcode 64, and
//!   [`OpcodeRateLimits`] re-keys chia's own published rate-limit table so a chia opcode is
//!   limited exactly as a stock peer would limit it. Chia types for chia traffic is the design,
//!   not a leftover.
//!
//! There is no blanket `pub use chia_protocol::*`. A glob re-export is how chia types reach
//! consumers that never asked for them, and it made a chia version bump a breaking change to
//! every downstream crate. What a chia-full-node path needs is named explicitly below.
//!
//! ## Feature flags
//!
//! | Flag | Forwards to | Effect |
//! |------|-------------|--------|
//! | `native-tls` | `chia-sdk-client/native-tls` | OS-native TLS; enables `Client`, `ClientState`, `Connector`, `create_native_tls_connector`, `DigLink::connect` |
//! | `rustls` | `chia-sdk-client/rustls` | Pure-Rust TLS; enables `Client`, `ClientState`, `Connector`, `create_rustls_connector`, `DigLink::connect` |
//!
//! Neither is enabled by default. Without one, the TLS-dependent items above are unavailable;
//! [`DigLink::from_websocket`] and [`DigLink::from_server_websocket`] stay available, since
//! adopting an already-established socket needs no TLS backend of its own.

// ============================================================================
// Re-export: chia-protocol — NAMED, for chia-full-node paths only
// ============================================================================
// Explicitly not a glob. `ChiaProtocolMessage` is what `DigLink`'s typed send/request bound
// their generics on, and `TimestampedPeerInfo` is a field of chia opcode 64; a consumer needing
// any other chia wire type depends on `chia-protocol` directly and says so in its own manifest.
pub use chia_protocol::{ChiaProtocolMessage, ProtocolMessageTypes, TimestampedPeerInfo};

// ============================================================================
// Re-export: chia-sdk-client (peer IO, TLS, rate limiting)
// ============================================================================
// Backend-agnostic types — always available.
pub use chia_sdk_client::{
    load_ssl_cert, ClientError, Network, Peer, PeerOptions, RateLimit, RateLimiter, RateLimits,
    V2_RATE_LIMITS,
};

// `Client`, `ClientState`, and `Connector` require a TLS backend in `chia-sdk-client`.
// Enable either the `native-tls` or `rustls` feature to use them.
#[cfg(any(feature = "native-tls", feature = "rustls"))]
pub use chia_sdk_client::{Client, ClientState, Connector};

#[cfg(feature = "native-tls")]
pub use chia_sdk_client::create_native_tls_connector;

#[cfg(feature = "rustls")]
pub use chia_sdk_client::create_rustls_connector;

// ============================================================================
// Re-export: chia-ssl (certificate types)
// ============================================================================
pub use chia_ssl::ChiaCertificate;

// ============================================================================
// Re-export: chia-traits (serialization)
// ============================================================================
pub use chia_traits::Streamable;

// ============================================================================
// Re-export: chia_streamable_macro (proc macro for wire structs)
// ============================================================================
pub use chia_streamable_macro::streamable;

// ============================================================================
// DIG extensions
// ============================================================================
mod bytes;
mod dig_message;
mod dig_message_type;
mod error;
mod introducer_wire;
mod link;
mod node_type;
mod opcodes;
mod rate_limit;
mod request_map;

pub use bytes::Bytes;
pub use dig_message::DigMessage;
pub use dig_message_type::{DigMessageType, UnknownDigMessageType};
pub use error::LinkError;
pub use introducer_wire::{
    RegisterAck, RegisterPeer, RequestPeersIntroducer, RespondPeersIntroducer,
};
pub use link::{DigLink, LinkOptions};
pub use node_type::{NodeType, UnknownNodeType};
pub use opcodes::{
    is_dig_opcode, ALL_DIG_OPCODES, DIG_BAND_START, DIG_MESSAGE, FREE_BAND_START,
    HOLDINGS_ANNOUNCE, STORE_MELTED,
};
pub use rate_limit::{Admission, OpcodeRateLimiter, OpcodeRateLimits};

#[cfg(test)]
mod dig_message_opcode_tests {
    use super::{DigMessage, DigMessageType, DIG_MESSAGE};

    /// The opcode frames a real [`DigMessage`] and survives a wire round-trip with its
    /// `msg_type` intact — the canonical value (220) exercised through the actual encoder.
    #[test]
    fn dig_message_opcode_frames_and_round_trips() {
        let msg = DigMessage::new(DIG_MESSAGE, Some(9), vec![1, 2, 3].into());
        let back = DigMessage::from_bytes(&msg.to_bytes()).expect("round-trip");
        assert_eq!(back.msg_type, 220);
        assert_eq!(back.msg_type, DIG_MESSAGE);
        assert_eq!(back.data.as_ref(), &[1, 2, 3]);
    }

    /// 220 is in the free band: it is NOT a consensus `DigMessageType` discriminant, so a
    /// consensus-band decode of the opcode fails — the two bands can never collide.
    #[test]
    fn dig_message_opcode_is_not_a_consensus_type() {
        assert!(DigMessageType::try_from(DIG_MESSAGE).is_err());
    }
}
