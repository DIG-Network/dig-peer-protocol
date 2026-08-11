//! A link must never hang a caller silently.
//!
//! Three failure modes are pinned here, all of which present as "the future simply never
//! resolves" — the worst shape a transport bug can take, because there is nothing to log and
//! nothing to retry:
//!
//! 1. An outbound message that can NEVER fit the rate-limit budget (its size exceeds the
//!    per-message cap, which no amount of waiting changes) must be refused, not retried forever.
//! 2. Inbound traffic that nobody is waiting on must not be able to wedge the reader and, with
//!    it, the routing of every correlated reply.
//! 3. A late reply to a timed-out request must not be misrouted to a new waiter that was
//!    assigned the same id after the timeout reclaimed it.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use dig_peer_protocol::Bytes;
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
    let mut options = LinkOptions::default();
    options.rate_limit_factor = 1.0;
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
        requester.request_dig(HOLDINGS_ANNOUNCE, &[HOLDINGS_ANNOUNCE], Bytes::new(b"ping".to_vec())),
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
    let mut options = LinkOptions::default();
    options.request_timeout = Duration::from_millis(300);
    let (_peer, _peer_rx, requester, _requester_rx) = linked_pair(options).await;

    let outcome = tokio::time::timeout(
        PATIENCE,
        requester.request_dig(HOLDINGS_ANNOUNCE, &[HOLDINGS_ANNOUNCE], Bytes::new(b"ping".to_vec())),
    )
    .await
    .expect("the request hung past its deadline");

    assert!(
        outcome.is_err(),
        "an unanswered request resolved successfully"
    );
}

/// A late reply to a timed-out request must not be misrouted to a new waiter.
///
/// When a request times out its id is reclaimed immediately.  If ids are allocated
/// lowest-free-first the *next* request receives the same id, and a delayed reply from the peer
/// (answering the first request) is then delivered to the second waiter — silently wrong.
///
/// With a monotonic wrapping cursor the recycled id does not reappear until 65 535 other ids
/// have been cycled, making accidental collision effectively impossible under normal concurrency.
/// This test pins the regression: request A times out, request B is issued, the peer then sends
/// A's reply before sending B's reply, and B must receive its own answer rather than A's.
#[tokio::test]
async fn a_late_reply_to_a_timed_out_request_is_not_misrouted_to_the_next_waiter() {
    // Short timeout so request A expires quickly and B starts before the peer answers A.
    let mut options = LinkOptions::default();
    options.request_timeout = Duration::from_millis(200);
    let (peer, mut peer_rx, requester, _requester_rx) = linked_pair(options).await;

    // Send request A and wait for it to time out.
    let a_id = {
        // Peek at the id the peer will see by doing the request and capturing the timeout error.
        // The peer_rx will deliver the message regardless.
        let _ = tokio::time::timeout(
            PATIENCE,
            requester.request_dig(HOLDINGS_ANNOUNCE, &[HOLDINGS_ANNOUNCE], Bytes::new(b"question-A".to_vec())),
        )
        .await
        .expect("request A should have timed out, not hung");
        // Retrieve the id from the peer side so we can send a reply to it later.
        peer_rx.recv().await.expect("peer receives question-A").id
    };

    // Now issue request B.  With a monotonic cursor it gets a *different* id than A.
    let peer_task = tokio::spawn(async move {
        let b_msg = peer_rx.recv().await.expect("peer receives question-B");

        // Send A's late reply first (after A has already timed out), then B's real reply.
        peer.send_message(DigMessage::new(
            HOLDINGS_ANNOUNCE,
            a_id,
            Bytes::new(b"answer-to-A".to_vec()),
        ))
        .await
        .expect("peer sends late answer-to-A");

        peer.send_message(DigMessage::new(
            HOLDINGS_ANNOUNCE,
            b_msg.id,
            Bytes::new(b"answer-to-B".to_vec()),
        ))
        .await
        .expect("peer sends answer-to-B");
    });

    let b_response = tokio::time::timeout(
        PATIENCE,
        requester.request_dig(HOLDINGS_ANNOUNCE, &[HOLDINGS_ANNOUNCE], Bytes::new(b"question-B".to_vec())),
    )
    .await
    .expect("request B hung")
    .expect("request B errored");

    assert_eq!(
        b_response.data.as_ref(),
        b"answer-to-B",
        "MISROUTED: question-B received a reply intended for question-A"
    );

    peer_task.await.expect("peer task finished");
}
