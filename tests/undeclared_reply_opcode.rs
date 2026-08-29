//! A frame that carries a live request id but an opcode the waiter never declared.
//!
//! Two situations produce such a frame and they are the SAME BYTES on the wire: an honest peer's
//! own request that happened to allocate the same id (its real reply still in flight), and a peer
//! answering with junk (no real reply is coming). Nothing at arrival time can tell them apart, so
//! the link records the collision and lets the deadline decide.
//!
//! `link_liveness.rs` already pins the honest half — the waiter survives the collision and is
//! answered by the real reply. This file pins the other half, which had **no test at all**:
//! `LinkError::InvalidResponse`, `request_infallible` and `request_fallible` were unreferenced by
//! any test in the crate, which is why nobody noticed that the error was promised by `SPEC.md`
//! and produced by nothing.
//!
//! Each test rules out a specific wrong implementation:
//!
//! 1. [`a_junk_reply_reports_invalid_response_rather_than_a_bare_timeout`] fails against the
//!    behaviour on `main`, where the request reports `RequestTimeout` — indistinguishable from a
//!    peer that said nothing at all, and nothing a peer-penalty layer can charge for. The
//!    assertion is on the error VARIANT and its payload, not on `is_err()`, because both
//!    behaviours are errors.
//! 2. [`a_silent_peer_still_reports_a_plain_timeout`] is the control. Without it an
//!    implementation that reported `InvalidResponse` for every expiry would pass test 1, and the
//!    distinction the whole change exists to make would be lost in the other direction.
//! 3. [`request_infallible_rejects_a_body_typed_reply_it_did_not_ask_for`] reaches the typed
//!    helpers, which had no coverage whatsoever.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use dig_peer_protocol::{
    Bytes, DigLink, DigMessage, LinkError, LinkOptions, DIG_MESSAGE, HOLDINGS_ANNOUNCE,
    STORE_MELTED,
};
use tokio::io::DuplexStream;
use tokio_tungstenite::{tungstenite::protocol::Role, WebSocketStream};

/// Long enough that a bounded implementation resolves comfortably inside it, short enough that an
/// unbounded one is caught rather than hanging CI.
const PATIENCE: Duration = Duration::from_secs(5);

/// Short, because every test here is *about* what the expiry reports. It must stay well inside
/// [`PATIENCE`] so a request that expires is observed rather than timed out by the harness.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(300);

/// A pair of links joined by an in-memory duplex, standing in for two TLS-terminated peers.
async fn linked_pair() -> (
    DigLink,
    tokio::sync::mpsc::Receiver<DigMessage>,
    DigLink,
    tokio::sync::mpsc::Receiver<DigMessage>,
) {
    let mut options = LinkOptions::default();
    options.request_timeout = REQUEST_TIMEOUT;

    let (left, right) = tokio::io::duplex(1024 * 1024);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 8444));

    let client: WebSocketStream<DuplexStream> =
        WebSocketStream::from_raw_socket(left, Role::Client, None).await;
    let server: WebSocketStream<DuplexStream> =
        WebSocketStream::from_raw_socket(right, Role::Server, None).await;

    let (a, a_rx) = DigLink::from_server_websocket(client, addr, options);
    let (b, b_rx) = DigLink::from_server_websocket(server, addr, options);
    (a, a_rx, b, b_rx)
}

/// A peer that answers on our id with an opcode we never asked for, and then says nothing.
#[tokio::test]
async fn a_junk_reply_reports_invalid_response_rather_than_a_bare_timeout() {
    let (peer, mut peer_rx, requester, mut requester_rx) = linked_pair().await;

    let peer_task = tokio::spawn(async move {
        let ours = peer_rx.recv().await.expect("the peer receives our request");
        peer.send_message(DigMessage::new(
            DIG_MESSAGE,
            ours.id,
            Bytes::new(b"answers-nothing-we-asked".to_vec()),
        ))
        .await
        .expect("the peer sends the undeclared-opcode frame");
        // And then nothing: the real reply never comes, so the deadline is what decides.
    });

    let outcome = tokio::time::timeout(
        PATIENCE,
        requester.request_dig(
            HOLDINGS_ANNOUNCE,
            &[STORE_MELTED],
            Bytes::new(b"ping".to_vec()),
        ),
    )
    .await
    .expect("the request hung past its deadline");

    match outcome {
        Ok(message) => panic!(
            "an undeclared opcode ({}) was delivered as the answer",
            message.msg_type
        ),
        Err(LinkError::InvalidResponse(expected, found)) => {
            assert_eq!(
                expected,
                vec![STORE_MELTED],
                "the diagnostic must name the opcodes the request declared"
            );
            assert_eq!(
                found, DIG_MESSAGE,
                "the diagnostic must name the opcode that actually arrived"
            );
        }
        Err(other) => panic!(
            "expected InvalidResponse naming the junk opcode, got {other} — a caller cannot \
             tell this peer apart from one that said nothing"
        ),
    }

    // The frame is still the application's: it is normally an inbound request, and dropping it
    // would strand a request the peer is waiting on.
    let delivered = tokio::time::timeout(PATIENCE, requester_rx.recv())
        .await
        .expect("the undeclared frame was never delivered to the application")
        .expect("the inbound channel closed");
    assert_eq!(delivered.msg_type, DIG_MESSAGE);
    assert_eq!(delivered.data.as_ref(), b"answers-nothing-we-asked");

    peer_task.await.expect("the peer finished");
}

/// The control: a genuinely silent peer must still report `RequestTimeout`.
///
/// Without this, an implementation that reported `InvalidResponse` on every expiry would satisfy
/// the test above while destroying the very distinction it exists to draw.
#[tokio::test]
async fn a_silent_peer_still_reports_a_plain_timeout() {
    let (_peer, _peer_rx, requester, _requester_rx) = linked_pair().await;

    let outcome = tokio::time::timeout(
        PATIENCE,
        requester.request_dig(
            HOLDINGS_ANNOUNCE,
            &[STORE_MELTED],
            Bytes::new(b"ping".to_vec()),
        ),
    )
    .await
    .expect("the request hung past its deadline");

    match outcome {
        Err(LinkError::RequestTimeout(opcode)) => assert_eq!(
            opcode, HOLDINGS_ANNOUNCE,
            "the timeout must name the request's own opcode"
        ),
        Err(other) => panic!("a silent peer must report RequestTimeout, got {other}"),
        Ok(_) => panic!("a request nobody answered resolved successfully"),
    }
}

/// The typed helper path, which had no coverage at all.
///
/// `request_infallible` asks for a `NewPeakWallet` and the peer answers on the same id with a
/// DIG-band opcode. The caller must learn that its request was answered with the wrong thing —
/// not that the peer was silent, and certainly not a body parsed out of the wrong frame.
#[tokio::test]
async fn request_infallible_rejects_a_body_typed_reply_it_did_not_ask_for() {
    use chia_protocol::NewPeakWallet;

    let (peer, mut peer_rx, requester, _requester_rx) = linked_pair().await;

    let peer_task = tokio::spawn(async move {
        let ours = peer_rx.recv().await.expect("the peer receives our request");
        peer.send_message(DigMessage::new(
            HOLDINGS_ANNOUNCE,
            ours.id,
            Bytes::new(b"not-a-new-peak-wallet".to_vec()),
        ))
        .await
        .expect("the peer sends the undeclared-opcode frame");
    });

    let request = NewPeakWallet::new(Default::default(), 0, Default::default(), 0);
    let outcome = tokio::time::timeout(
        PATIENCE,
        requester.request_infallible::<NewPeakWallet, _>(request),
    )
    .await
    .expect("the request hung past its deadline");

    match outcome {
        Err(LinkError::InvalidResponse(_, found)) => assert_eq!(
            found, HOLDINGS_ANNOUNCE,
            "the diagnostic must name the opcode that actually arrived"
        ),
        Err(other) => panic!("expected InvalidResponse, got {other}"),
        Ok(_) => panic!("a frame of the wrong opcode was parsed as the reply body"),
    }

    peer_task.await.expect("the peer finished");
}
