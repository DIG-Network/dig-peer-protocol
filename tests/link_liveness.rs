//! A link must never hang a caller silently.
//!
//! Two failure modes are pinned here, both of which present as "the future simply never
//! resolves" — the worst shape a transport bug can take, because there is nothing to log and
//! nothing to retry:
//!
//! 1. An outbound message that can NEVER fit the rate-limit budget (its size exceeds the
//!    per-message cap, which no amount of waiting changes) must be refused, not retried forever.
//! 2. Inbound traffic that nobody is waiting on must not be able to wedge the reader and, with
//!    it, the routing of every correlated reply.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use chia_protocol::Bytes;
use dig_peer_protocol::{DigLink, DigMessage, LinkOptions, HOLDINGS_ANNOUNCE};
use tokio::io::DuplexStream;
use tokio_tungstenite::{tungstenite::protocol::Role, WebSocketStream};

/// Long enough that a bounded implementation resolves comfortably inside it, short enough that
/// an unbounded one is caught rather than hanging CI.
const PATIENCE: Duration = Duration::from_secs(5);

/// A pair of links joined by an in-memory duplex, standing in for two TLS-terminated peers.
async fn linked_pair(
    options: LinkOptions,
) -> (
    DigLink,
    tokio::sync::mpsc::Receiver<DigMessage>,
    DigLink,
    tokio::sync::mpsc::Receiver<DigMessage>,
) {
    let (left, right) = tokio::io::duplex(8 * 1024 * 1024);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 8444));

    let client: WebSocketStream<DuplexStream> =
        WebSocketStream::from_raw_socket(left, Role::Client, None).await;
    let server: WebSocketStream<DuplexStream> =
        WebSocketStream::from_raw_socket(right, Role::Server, None).await;

    let (a, a_rx) = DigLink::from_server_websocket(client, addr, options);
    let (b, b_rx) = DigLink::from_server_websocket(server, addr, options);
    (a, a_rx, b, b_rx)
}

/// A `HoldingsAnnounce` batch larger than the per-message size cap is refused promptly.
///
/// The size cap is the one budget a window roll never clears, so retrying is not merely slow —
/// it can never succeed. dig-gossip announces holdings in batches that exceed 1 MiB, so this is
/// the shape a real caller sends, not a synthetic extreme.
///
/// The control is the load-bearing half: a payload just UNDER the cap must still send. Without
/// it, an implementation that refused every message at all would pass.
#[tokio::test]
async fn an_unsendably_large_message_is_refused_rather_than_retried_forever() {
    let (link, _rx, _peer, _peer_rx) = linked_pair(LinkOptions::default()).await;

    let over_cap = Bytes::new(vec![0u8; 1024 * 1024 + 1]);
    let refusal = tokio::time::timeout(PATIENCE, link.send_dig(HOLDINGS_ANNOUNCE, over_cap))
        .await
        .expect("send spun instead of refusing a message that can never fit");
    assert!(
        refusal.is_err(),
        "an oversized message reported success without being sendable"
    );

    let at_cap = Bytes::new(vec![0u8; 1024 * 1024]);
    tokio::time::timeout(PATIENCE, link.send_dig(HOLDINGS_ANNOUNCE, at_cap))
        .await
        .expect("the at-cap control send spun")
        .expect("the at-cap control send was refused, so the refusal above proves nothing");
}

/// Inbound frames nobody is waiting on must not starve the correlated path.
///
/// The application receiver is deliberately never drained, so the inbound channel fills. A
/// reader that parks on a full channel stops routing entirely, and every outstanding request
/// hangs forever with no error. The correlated reply is sent LAST, after the flood, so only an
/// implementation that keeps routing under that pressure resolves it.
#[tokio::test]
async fn a_flood_of_unmatched_ids_cannot_wedge_the_correlated_reply_path() {
    // The nominal Chia allowance, so the flood is bounded by the inbound channel under test
    // rather than by the sender's own outbound budget — which would stall the fixture and make
    // the test fail for a reason unrelated to routing.
    let options = LinkOptions {
        rate_limit_factor: 1.0,
        ..LinkOptions::default()
    };
    let (peer, mut peer_rx, requester, _requester_rx) = linked_pair(options).await;

    let peer_task = tokio::spawn(async move {
        let request = peer_rx.recv().await.expect("the request arrives");

        // Comfortably more than the inbound channel's 32 slots, with ids chosen from the top of
        // the space so they cannot collide with the requester's own outstanding id.
        for offset in 0..64u16 {
            peer.send_message(DigMessage::new(
                HOLDINGS_ANNOUNCE,
                Some(u16::MAX - offset),
                Bytes::new(b"unmatched".to_vec()),
            ))
            .await
            .expect("send an unmatched frame");
        }

        peer.send_message(DigMessage::new(
            HOLDINGS_ANNOUNCE,
            request.id,
            Bytes::new(b"pong".to_vec()),
        ))
        .await
        .expect("send the correlated reply");
    });

    let response = tokio::time::timeout(
        PATIENCE,
        requester.request_dig(HOLDINGS_ANNOUNCE, Bytes::new(b"ping".to_vec())),
    )
    .await
    .expect("the flood wedged the reader: no correlated reply was ever routed")
    .expect("the request failed");

    assert_eq!(response.data.as_ref(), b"pong");
    peer_task.await.expect("the peer finished");
}

/// A request whose reply never comes must eventually error rather than stay pending forever.
///
/// The peer here receives the request and deliberately says nothing — the silent-peer case a
/// deadline exists for.
#[tokio::test]
async fn an_unanswered_request_errors_on_its_deadline() {
    let options = LinkOptions {
        request_timeout: Duration::from_millis(300),
        ..LinkOptions::default()
    };
    let (_peer, _peer_rx, requester, _requester_rx) = linked_pair(options).await;

    let outcome = tokio::time::timeout(
        PATIENCE,
        requester.request_dig(HOLDINGS_ANNOUNCE, Bytes::new(b"ping".to_vec())),
    )
    .await
    .expect("the request hung past its deadline");

    assert!(
        outcome.is_err(),
        "an unanswered request resolved successfully"
    );
}
