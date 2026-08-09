//! Errors a [`DigLink`](crate::DigLink) can produce.

use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

/// Everything that can go wrong on a DIG peer link.
///
/// Opcodes appear as raw `u8` rather than `ProtocolMessageTypes` on purpose: a DIG opcode has no
/// `ProtocolMessageTypes` representation, and an error type that could not name the opcode it
/// rejected would be useless for exactly the messages this link exists to carry.
#[derive(Debug, Error)]
pub enum LinkError {
    /// A body failed to encode or decode.
    #[error("streamable error: {0}")]
    Streamable(#[from] chia_traits::Error),

    /// The websocket itself failed.
    ///
    /// Boxed because `tungstenite::Error` is by far the largest variant (~136 bytes) and would
    /// otherwise set the size of every `Result` the link returns, on the success path too.
    #[error("websocket error: {0}")]
    WebSocket(Box<tungstenite::Error>),

    /// The underlying socket failed, typically while reading the peer address.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The peer replied with an opcode none of the expected ones matched.
    #[error("expected a response with opcode in {0:?}, found {1}")]
    InvalidResponse(Vec<u8>, u8),

    /// The link closed before the awaited reply arrived.
    #[error("the link closed before a response arrived")]
    Recv(#[from] RecvError),

    /// The websocket is carried over a TLS backend this build does not support — enable the
    /// `native-tls` or `rustls` feature.
    #[error("the websocket's TLS backend is not supported by this build")]
    UnsupportedTls,

    /// The message exceeds a rate-limit bound no window will ever admit — typically the
    /// per-message size cap. Retrying is futile; the body must be split.
    #[error("a message with opcode {0} and a {1}-byte body exceeds the per-message limit")]
    Unsendable(u8, usize),

    /// Rate-limit budget did not free up within `LinkOptions::send_timeout`.
    #[error("timed out waiting for rate-limit budget to send opcode {0}")]
    SendTimeout(u8),

    /// No correlated reply arrived within `LinkOptions::request_timeout`.
    #[error("timed out waiting for a response to opcode {0}")]
    RequestTimeout(u8),

    /// A Chia message type did not encode to a single-byte opcode. Unreachable with any real
    /// `ChiaProtocolMessage`; present so the encoding is never silently assumed.
    #[error("message type did not encode to a single-byte opcode")]
    MalformedOpcode,
}

// Hand-written rather than `#[from]`, because the variant boxes its payload: callers still get
// the ergonomic `?` conversion from a bare `tungstenite::Error`.
impl From<tungstenite::Error> for LinkError {
    fn from(error: tungstenite::Error) -> Self {
        Self::WebSocket(Box::new(error))
    }
}
