//! # dig-peer-protocol
//!
//! DIG Network L2 protocol types — a superset of `chia-protocol`.
//!
//! This crate re-exports the entire Chia protocol ecosystem (`chia-protocol`,
//! `chia-sdk-client`, `chia-ssl`, `chia-traits`) plus DIG's own extensions: the
//! `200..=222` opcode band, the [`DigMessage`] framing that can express it, and
//! [`DigLink`], the websocket peer link that carries it. Consumers depend on
//! `dig-peer-protocol` alone instead of importing multiple `chia-*` crates individually.
//!
//! ## The closed-enum problem, and how this crate closes it
//!
//! `chia_protocol::Message` stores its opcode as `ProtocolMessageTypes`, an enum that stops
//! at `RespondCostInfo = 107` with no `Unknown(u8)`. A DIG opcode has no value in that enum, so
//! it is neither constructible nor decodable through it — and worse, `chia-sdk-client`'s
//! receive loop calls `Message::from_bytes`, so one inbound DIG frame drops the whole
//! connection rather than that one frame.
//!
//! [`DigMessage`] answers the first half: the same wire bytes with a raw `u8` opcode.
//! [`DigLink`] answers the second: a websocket link that frames `DigMessage` end to end.
//! Together they replace the vendored `chia-protocol` / `chia-sdk-client` forks DIG used to
//! carry, so `chia-protocol` is an ordinary dependency with no `[patch.crates-io]`.
//!
//! ## What's included
//!
//! | Source crate | What's re-exported |
//! |-------------|-------------------|
//! | `chia-protocol` | All wire types: `Message`, `Handshake`, `ProtocolMessageTypes`, `NodeType`, etc. |
//! | `chia-sdk-client` | `Peer`, `Client`, `ClientError`, `ClientState`, `Network`, `PeerOptions`, rate limiting, TLS connectors |
//! | `chia-ssl` | `ChiaCertificate` |
//! | `chia-traits` | `Streamable` trait |
//! | `chia_streamable_macro` | `#[streamable]` proc macro |
//! | **DIG extensions** | `DigMessage`, `DigMessageType`, the `200..=222` opcode band, `RegisterPeer`, `RegisterAck`, introducer wire types |
//! | **DIG peer link** | `DigLink`, `LinkOptions`, `LinkError`, `Admission`, `OpcodeRateLimiter`, `OpcodeRateLimits` |
//!
//! ## Feature flags
//!
//! | Flag | Forwards to | Effect |
//! |------|-------------|--------|
//! | `native-tls` | `chia-sdk-client/native-tls` | OS-native TLS; enables `Client`, `ClientState`, `Connector`, `create_native_tls_connector`, `DigLink::connect` |
//! | `rustls` | `chia-sdk-client/rustls` | Pure-Rust TLS; enables `Client`, `ClientState`, `Connector`, `create_rustls_connector`, `DigLink::connect` |
//!
//! Neither feature is enabled by default. The crate builds without either but TLS-dependent
//! items (`Client`, `ClientState`, `Connector`, and `DigLink::connect`) become unavailable;
//! [`DigLink::from_websocket`] and [`DigLink::from_server_websocket`] stay available, since
//! adopting an already-established socket needs no TLS backend of its own.

// ============================================================================
// Re-export: chia-protocol (all wire types)
// ============================================================================
pub use chia_protocol::*;

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
mod dig_message;
mod dig_message_type;
mod error;
mod introducer_wire;
mod link;
mod opcodes;
mod rate_limit;
mod request_map;

pub use dig_message::DigMessage;
pub use dig_message_type::{DigMessageType, UnknownDigMessageType};
pub use error::LinkError;
pub use introducer_wire::{
    RegisterAck, RegisterPeer, RequestPeersIntroducer, RespondPeersIntroducer,
};
pub use link::{DigLink, LinkOptions};
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
