//! Correlation-id bookkeeping for outstanding requests on a [`DigLink`](crate::DigLink).

use std::{collections::HashMap, sync::Arc};

use tokio::sync::{oneshot, Mutex, OwnedSemaphorePermit, Semaphore};

use crate::DigMessage;

/// One caller waiting for a reply.
///
/// The permit is held for the request's whole lifetime, so the semaphore's count IS the number of
/// live requests and the id space cannot be oversubscribed.
#[derive(Debug)]
pub(crate) struct Request {
    sender: oneshot::Sender<DigMessage>,
    /// The opcodes that can complete this waiter.
    ///
    /// Correlation ids are chosen independently by each side and both start at 0, so a peer's
    /// own *request* routinely carries an id we are waiting on. Matching on the id ALONE would
    /// hand that request to this waiter, which then fails to parse it as a response while the
    /// application never sees the request at all — and both ends time each other out. Recording
    /// what a waiter is waiting FOR makes that misdelivery unexpressible, without teaching the
    /// link any protocol semantics.
    expected: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

impl Request {
    /// Hand the reply to the waiter. A caller that has since given up is not an error.
    pub(crate) fn send(self, message: DigMessage) {
        self.sender.send(message).ok();
    }
}

/// The live requests on one link, keyed by wire correlation id.
#[derive(Debug)]
pub(crate) struct RequestMap {
    items: Mutex<HashMap<u16, Request>>,
    /// Bounds concurrent requests to the size of the `u16` id space, so [`Self::insert`] always
    /// has a free id to hand out — it waits here rather than failing to find one.
    capacity: Arc<Semaphore>,
    /// Monotonic wrapping cursor for id allocation.  Starting the search from `next_id` rather
    /// than from 0 means a recycled id does not appear again until 65 535 other ids have been
    /// used, so a late reply to a timed-out request cannot accidentally match a new waiter that
    /// was allocated the same id moments later.
    next_id: Mutex<u16>,
}

impl RequestMap {
    pub(crate) fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
            capacity: Arc::new(Semaphore::new(u16::MAX as usize)),
            next_id: Mutex::new(0),
        }
    }

    /// Reserve an unused correlation id for `sender`, waiting if the id space is saturated.
    ///
    /// `expected` lists the opcodes that may complete the waiter; any other frame carrying this
    /// id belongs to the application (see [`Self::take_matching`]).
    pub(crate) async fn insert(
        &self,
        sender: oneshot::Sender<DigMessage>,
        expected: Vec<u8>,
    ) -> u16 {
        let permit = self
            .capacity
            .clone()
            .acquire_owned()
            .await
            .expect("request capacity semaphore is never closed");

        let mut items = self.items.lock().await;

        // Callers that dropped their receiver will never be woken; reclaim their ids first so a
        // long-lived link does not leak its way up to the id ceiling.
        items.retain(|_, request| !request.sender.is_closed());

        // Advance the cursor monotonically so that a recycled id is not reissued until the full
        // 65 535-id space has been cycled.  The semaphore guarantees at least one free slot.
        let mut next_id = self.next_id.lock().await;
        let mut id = *next_id;
        loop {
            if !items.contains_key(&id) {
                break;
            }
            id = id.wrapping_add(1);
        }
        *next_id = id.wrapping_add(1);
        drop(next_id);

        items.insert(
            id,
            Request {
                sender,
                expected,
                _permit: permit,
            },
        );
        id
    }

    /// Take the waiter for `id` **only if** `msg_type` is a reply it is waiting for.
    ///
    /// A frame that carries a live id but a different opcode is not this waiter's reply — it is
    /// the peer's own request, which merely allocated the same id — so it is left for the
    /// application and the waiter stays parked for its real answer.
    pub(crate) async fn take_matching(&self, id: u16, msg_type: u8) -> Option<Request> {
        let mut items = self.items.lock().await;
        if !items.get(&id)?.expected.contains(&msg_type) {
            return None;
        }
        items.remove(&id)
    }

    /// Take the waiter for `id` whatever it was waiting for — used to reclaim an id when the
    /// request itself is abandoned (a failed send, an expired deadline).
    pub(crate) async fn cancel(&self, id: u16) -> Option<Request> {
        self.items.lock().await.remove(&id)
    }
}
