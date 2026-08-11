//! [`DigLink`] — a websocket peer link that frames [`DigMessage`].
//!
//! ## Why this exists
//!
//! `chia_sdk_client::Peer` speaks `chia_protocol::Message`, whose `msg_type` is the closed
//! `ProtocolMessageTypes` enum (it stops at `RespondCostInfo = 107`, with no `Unknown(u8)` and no
//! `#[non_exhaustive]`). Two consequences make it unusable as a DIG transport:
//!
//! 1. A DIG opcode has no `ProtocolMessageTypes` value, so no `Message` can name one. The
//!    fields are public — `tests/wire_compatibility.rs` builds one with a struct literal — but
//!    the closed enum is a sufficient blocker on its own.
//! 2. Its inbound loop calls `Message::from_bytes`, which returns `Err` on any unknown opcode —
//!    and that error terminates the receive loop. A single inbound DIG frame therefore kills the
//!    whole connection, not just that frame.
//!
//! DIG previously worked around this by vendoring forks of `chia-protocol` and
//! `chia-sdk-client`. `DigLink` replaces the forks with an implementation written directly
//! against the wire format, which is possible because [`DigMessage`] is byte-identical to
//! `chia_protocol::Message` (asserted exhaustively in `tests/wire_compatibility.rs`).
//!
//! ## What it is not
//!
//! It is not a port of upstream's `Peer`. Most of that type is Chia wallet RPC
//! (`request_puzzle_state`, `register_for_ph_updates`, …) which a gossip transport never calls;
//! those helpers stay upstream, where `chia_sdk_client::Peer` is still re-exported for anyone who
//! wants them.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use chia_protocol::ChiaProtocolMessage;
use chia_traits::Streamable;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, Mutex},
    task::JoinHandle,
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, warn};

use crate::{
    rate_limit::{Admission, Direction, OpcodeRateLimiter, OpcodeRateLimits},
    request_map::RequestMap,
    Bytes, DigMessage, LinkError,
};

#[cfg(any(feature = "native-tls", feature = "rustls"))]
use tokio_tungstenite::Connector;

/// How many inbound messages may queue for the application before the reader backs up.
const INBOUND_CHANNEL_CAPACITY: usize = 32;

/// How long to wait before re-testing the rate limiter after it refuses an outbound message.
const RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(1);

/// The window over which outbound rate-limit budgets reset.
const RATE_LIMIT_WINDOW_SECONDS: u64 = 60;

/// Tunables for a single link.
///
/// The type is `#[non_exhaustive]` because a link acquires tunables as it hardens — two arrived
/// in one release — and this crate is released ahead of every consumer of it. Without the
/// attribute each new tunable would be a major bump cascading through dig-gossip and everything
/// downstream of it; with it, adding one is additive.
///
/// The cost is that consumers cannot name the type in a struct expression at all — not even with
/// `..Default::default()`, which Rust also forbids for a `#[non_exhaustive]` struct. Start from
/// [`Default`] and assign the fields you care about:
///
/// ```
/// use std::time::Duration;
/// use dig_peer_protocol::LinkOptions;
///
/// let mut options = LinkOptions::default();
/// options.request_timeout = Duration::from_secs(5);
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct LinkOptions {
    /// Scales every outbound rate-limit budget. `1.0` is the nominal Chia allowance.
    pub rate_limit_factor: f64,

    /// How long [`DigLink::send_message`] may wait for rate-limit budget before giving up.
    ///
    /// Only a *deferrable* refusal waits at all — an oversized message is refused immediately,
    /// since no amount of waiting makes it fit.
    pub send_timeout: Duration,

    /// How long a correlated request waits for its reply before erroring.
    ///
    /// Without a deadline a silent or wedged peer leaves the caller pending forever, which is
    /// indistinguishable from a lost future.
    pub request_timeout: Duration,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            rate_limit_factor: 0.6,
            // Two full windows: long enough that a genuinely transient budget exhaustion always
            // clears (a roll resets every counter), short enough to surface a stuck sender.
            send_timeout: Duration::from_secs(RATE_LIMIT_WINDOW_SECONDS * 2),
            request_timeout: Duration::from_secs(60),
        }
    }
}

/// The write half, type-erased.
///
/// Boxing keeps [`DigLink`] non-generic while still accepting a **server-side** TLS stream (e.g.
/// `tokio_rustls::server::TlsStream`), which cannot inhabit the `#[non_exhaustive]`,
/// client-oriented [`MaybeTlsStream`] enum that [`DigLink::from_websocket`] takes.
type BoxedSink =
    Box<dyn futures_util::Sink<tungstenite::Message, Error = tungstenite::Error> + Send + Unpin>;

/// The read half, type-erased — counterpart to [`BoxedSink`].
type BoxedStream = Box<
    dyn futures_util::Stream<Item = Result<tungstenite::Message, tungstenite::Error>>
        + Send
        + Unpin,
>;

/// A live websocket link to one peer, framing every message as a [`DigMessage`].
///
/// Cheap to clone: every clone shares one connection, one request map and one rate-limit budget.
#[derive(Debug, Clone)]
pub struct DigLink(Arc<LinkInner>);

struct LinkInner {
    sink: Mutex<BoxedSink>,
    inbound_handle: JoinHandle<()>,
    requests: Arc<RequestMap>,
    socket_addr: SocketAddr,
    outbound_rate_limiter: Mutex<OpcodeRateLimiter>,
    options: LinkOptions,
}

// Hand-written because `BoxedSink`/`JoinHandle` carry no useful `Debug`; only the stable,
// printable identity of the link is worth showing.
impl std::fmt::Debug for LinkInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DigLink")
            .field("socket_addr", &self.socket_addr)
            .finish_non_exhaustive()
    }
}

impl Drop for LinkInner {
    fn drop(&mut self) {
        self.inbound_handle.abort();
    }
}

impl DigLink {
    /// Connect to a peer at `socket_addr` over TLS.
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    pub async fn connect(
        socket_addr: SocketAddr,
        connector: Connector,
        options: LinkOptions,
    ) -> Result<(Self, mpsc::Receiver<DigMessage>), LinkError> {
        Self::connect_full_uri(&format!("wss://{socket_addr}/ws"), connector, options).await
    }

    /// Connect to a peer at a full websocket URI, for example `wss://127.0.0.1:8444/ws`.
    ///
    /// Needed where the URI is not derivable from a socket address — an introducer reached by
    /// hostname, or a peer behind a path-routed relay.
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    pub async fn connect_full_uri(
        uri: &str,
        connector: Connector,
        options: LinkOptions,
    ) -> Result<(Self, mpsc::Receiver<DigMessage>), LinkError> {
        let (ws, _) =
            tokio_tungstenite::connect_async_tls_with_config(uri, None, false, Some(connector))
                .await?;
        Self::from_websocket(ws, options)
    }

    /// Adopt an already-established **client-side** websocket.
    ///
    /// The peer address is recovered from the underlying stream. The connection is expected to
    /// be TLS-secured, so that a peer id can be derived from the certificate.
    pub fn from_websocket(
        ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
        options: LinkOptions,
    ) -> Result<(Self, mpsc::Receiver<DigMessage>), LinkError> {
        let socket_addr = peer_addr_of(&ws)?;
        let (sink, stream) = ws.split();
        Ok(Self::from_parts(
            Box::new(sink),
            Box::new(stream),
            socket_addr,
            options,
        ))
    }

    /// Adopt an already-established **server-side** websocket.
    ///
    /// An inbound acceptor already knows `socket_addr` and holds a server-side TLS stream that
    /// cannot inhabit [`MaybeTlsStream`], hence the separate constructor generic over the
    /// transport.
    ///
    /// The caller must derive the peer id from the client certificate *before* calling this: the
    /// certificate is no longer reachable once the stream has been split.
    pub fn from_server_websocket<S>(
        ws: WebSocketStream<S>,
        socket_addr: SocketAddr,
        options: LinkOptions,
    ) -> (Self, mpsc::Receiver<DigMessage>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (sink, stream) = ws.split();
        Self::from_parts(Box::new(sink), Box::new(stream), socket_addr, options)
    }

    /// Wire split halves into a live link plus its inbound channel — the one construction path
    /// both public constructors funnel through, so client and server links behave identically.
    fn from_parts(
        sink: BoxedSink,
        stream: BoxedStream,
        socket_addr: SocketAddr,
        options: LinkOptions,
    ) -> (Self, mpsc::Receiver<DigMessage>) {
        let (sender, receiver) = mpsc::channel(INBOUND_CHANNEL_CAPACITY);
        let requests = Arc::new(RequestMap::new());
        let requests_for_reader = requests.clone();

        let inbound_handle = tokio::spawn(async move {
            if let Err(error) = read_inbound(stream, sender, requests_for_reader).await {
                debug!("dig link inbound loop ended: {error}");
            }
        });

        let link = Self(Arc::new(LinkInner {
            sink: Mutex::new(sink),
            inbound_handle,
            requests,
            socket_addr,
            outbound_rate_limiter: Mutex::new(OpcodeRateLimiter::new(
                // The send path: we chose not to send, so a refusal must not penalise a caller
                // that backs off and retries.
                Direction::Outbound,
                RATE_LIMIT_WINDOW_SECONDS,
                options.rate_limit_factor,
                OpcodeRateLimits::default(),
            )),
            options,
        }));

        (link, receiver)
    }

    /// The address of the peer on the other end.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        self.0.socket_addr
    }

    /// Send a Chia-typed body with no correlation id and no expected reply.
    pub async fn send<T>(&self, body: T) -> Result<(), LinkError>
    where
        T: Streamable + ChiaProtocolMessage,
    {
        self.send_message(DigMessage::new(
            opcode_of::<T>()?,
            None,
            body.to_bytes()?.into(),
        ))
        .await
    }

    /// Send a DIG-band body with no correlation id and no expected reply.
    ///
    /// The payload is opaque to the link: framing an opcode says nothing about what its body
    /// means, which is precisely what lets the free band (220+) carry protocols this crate does
    /// not know about.
    pub async fn send_dig(&self, opcode: u8, data: Bytes) -> Result<(), LinkError> {
        self.send_message(DigMessage::new(opcode, None, data)).await
    }

    /// Send a fully-formed message, preserving its `id`.
    ///
    /// This is how an inbound *request* is answered: the reply must carry the requester's id,
    /// which neither [`Self::send`] nor [`Self::send_dig`] can express.
    /// Rate-limit refusals are handled by kind, never by blanket retry: an over-budget message
    /// waits for the next window (up to [`LinkOptions::send_timeout`]), while a message that no
    /// window could ever admit fails immediately. Retrying the latter is an infinite loop with
    /// no error, which is how a caller silently disappears.
    pub async fn send_message(&self, message: DigMessage) -> Result<(), LinkError> {
        let deadline = tokio::time::Instant::now() + self.0.options.send_timeout;

        loop {
            match self.0.outbound_rate_limiter.lock().await.admit(&message) {
                Admission::Admitted => break,
                Admission::Unsendable => {
                    return Err(LinkError::Unsendable(message.msg_type, message.data.len()))
                }
                Admission::Deferred => {}
            }

            if tokio::time::Instant::now() + RATE_LIMIT_BACKOFF > deadline {
                return Err(LinkError::SendTimeout(message.msg_type));
            }
            tokio::time::sleep(RATE_LIMIT_BACKOFF).await;
        }

        self.0
            .sink
            .lock()
            .await
            .send(tungstenite::Message::Binary(message.to_bytes()))
            .await?;
        Ok(())
    }

    /// Send a Chia-typed body and await the correlated reply, unparsed.
    pub async fn request_raw<T>(&self, body: T) -> Result<DigMessage, LinkError>
    where
        T: Streamable + ChiaProtocolMessage,
    {
        self.request_message(opcode_of::<T>()?, body.to_bytes()?.into())
            .await
    }

    /// Send a DIG-band body and await the correlated reply, unparsed.
    pub async fn request_dig(&self, opcode: u8, data: Bytes) -> Result<DigMessage, LinkError> {
        self.request_message(opcode, data).await
    }

    /// Send a Chia-typed body and await a reply of exactly one expected type.
    pub async fn request_infallible<T, B>(&self, body: B) -> Result<T, LinkError>
    where
        T: Streamable + ChiaProtocolMessage,
        B: Streamable + ChiaProtocolMessage,
    {
        let expected = opcode_of::<T>()?;
        let message = self.request_raw(body).await?;
        if message.msg_type != expected {
            return Err(LinkError::InvalidResponse(vec![expected], message.msg_type));
        }
        Ok(T::from_bytes(&message.data)?)
    }

    /// Send a Chia-typed body and await either the expected reply or its rejection.
    pub async fn request_fallible<T, E, B>(&self, body: B) -> Result<Result<T, E>, LinkError>
    where
        T: Streamable + ChiaProtocolMessage,
        E: Streamable + ChiaProtocolMessage,
        B: Streamable + ChiaProtocolMessage,
    {
        let (accepted, rejected) = (opcode_of::<T>()?, opcode_of::<E>()?);
        let message = self.request_raw(body).await?;

        if message.msg_type == accepted {
            Ok(Ok(T::from_bytes(&message.data)?))
        } else if message.msg_type == rejected {
            Ok(Err(E::from_bytes(&message.data)?))
        } else {
            Err(LinkError::InvalidResponse(
                vec![accepted, rejected],
                message.msg_type,
            ))
        }
    }

    /// Register a correlation id, send, and await the reply routed back to it.
    ///
    /// The wait is bounded by [`LinkOptions::request_timeout`]. On expiry the id is reclaimed
    /// immediately rather than left occupying the map until the link drops — an unbounded wait
    /// against a silent peer leaks ids as well as hanging the caller.
    async fn request_message(&self, opcode: u8, data: Bytes) -> Result<DigMessage, LinkError> {
        let (sender, receiver) = oneshot::channel();
        let id = self.0.requests.insert(sender).await;

        if let Err(error) = self
            .send_message(DigMessage::new(opcode, Some(id), data))
            .await
        {
            self.0.requests.remove(id).await;
            return Err(error);
        }

        match tokio::time::timeout(self.0.options.request_timeout, receiver).await {
            Ok(received) => Ok(received?),
            Err(_) => {
                self.0.requests.remove(id).await;
                Err(LinkError::RequestTimeout(opcode))
            }
        }
    }

    /// Close the connection.
    pub async fn close(&self) -> Result<(), LinkError> {
        self.0.sink.lock().await.close().await?;
        Ok(())
    }
}

/// The wire opcode of a Chia message type, via its single-byte `Streamable` encoding.
fn opcode_of<T: ChiaProtocolMessage>() -> Result<u8, LinkError> {
    T::msg_type()
        .to_bytes()?
        .first()
        .copied()
        .ok_or(LinkError::MalformedOpcode)
}

/// Recover the peer address from a client-side websocket's underlying transport.
fn peer_addr_of(ws: &WebSocketStream<MaybeTlsStream<TcpStream>>) -> Result<SocketAddr, LinkError> {
    let addr = match ws.get_ref() {
        #[cfg(feature = "native-tls")]
        MaybeTlsStream::NativeTls(tls) => tls.get_ref().get_ref().get_ref().peer_addr()?,
        #[cfg(feature = "rustls")]
        MaybeTlsStream::Rustls(tls) => tls.get_ref().0.peer_addr()?,
        MaybeTlsStream::Plain(plain) => plain.peer_addr()?,
        _ => return Err(LinkError::UnsupportedTls),
    };
    Ok(addr)
}

/// The inbound loop: decode every binary frame as a [`DigMessage`] and route it.
///
/// Three deliberate differences from `chia_sdk_client`'s loop, all of which are the reason a DIG
/// transport could not use it. Each removes one way for a single frame to kill a whole link:
///
/// 1. **Decoding never depends on the opcode being known.** `DigMessage::from_bytes` accepts any
///    `u8`, so an inbound DIG opcode is a normal message rather than a fatal decode error.
/// 2. **An unmatched correlation id is delivered, not fatal.** Upstream returns `Err` — which
///    ends the loop and drops the connection — when a reply arrives for an id it is not waiting
///    on. But ids are chosen independently by each side, so a peer's *request* id routinely
///    collides with one of our outstanding request ids; and a hostile peer could drop the link at
///    will by sending one unknown id. Here, anything not matching a live waiter goes to the
///    application, which is where an inbound request belongs anyway.
/// 3. **A frame that does not decode is skipped, not fatal.** Websocket frames are
///    self-delimiting: tungstenite hands this loop whole `Binary` payloads, and the loop never
///    reads a length off a byte stream itself. So an undecodable payload costs exactly that
///    payload — there is no shared stream position for it to corrupt, and the frames after it
///    decode normally. Ending the loop instead would restore the same one-frame kill switch that
///    difference 2 exists to remove, and would do it *silently*: the reader stops, but every
///    outstanding request stays parked in the [`RequestMap`] until its own deadline expires, so
///    the caller sees an unexplained stall rather than a dropped connection.
///
/// ## Why unmatched frames are dropped rather than queued
///
/// Delivery to the application is non-blocking: a full inbound channel drops the frame instead
/// of parking the loop. Parking looks harmless and is not — a peer that floods ids nobody is
/// waiting on fills the channel, the loop stops, and from then on **no correlated reply is ever
/// routed**, so every outstanding request hangs with no error. Correlated routing is the one
/// thing on this link that has no fallback, so it is never allowed to queue behind traffic the
/// application has not kept up with. A dropped inbound frame is a visible, recoverable loss on
/// a best-effort transport; a wedged reader is not.
async fn read_inbound(
    mut stream: BoxedStream,
    sender: mpsc::Sender<DigMessage>,
    requests: Arc<RequestMap>,
) -> Result<(), LinkError> {
    use tungstenite::Message::{Binary, Close, Frame, Ping, Pong, Text};

    while let Some(frame) = stream.next().await {
        match frame? {
            Close(..) => break,
            Ping(..) | Pong(..) | Frame(..) => {}
            Text(text) => warn!("dig link received an unexpected text frame: {text}"),
            Binary(binary) => {
                let Some(message) = DigMessage::from_bytes_owned(binary) else {
                    warn!("dig link skipped a malformed frame");
                    continue;
                };

                let unmatched = match message.id {
                    Some(id) => match requests.remove(id).await {
                        Some(waiter) => {
                            waiter.send(message);
                            continue;
                        }
                        None => message,
                    },
                    None => message,
                };

                if let Err(mpsc::error::TrySendError::Full(dropped)) = sender.try_send(unmatched) {
                    warn!(
                        "dig link dropped an inbound frame (opcode {}): the application is not \
                         keeping up",
                        dropped.msg_type
                    );
                }
            }
        }
    }
    Ok(())
}
