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
    pub(crate) async fn insert(&self, sender: oneshot::Sender<DigMessage>) -> u16 {
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
                _permit: permit,
            },
        );
        id
    }

    /// Take the waiter for `id`, if one is still live.
    pub(crate) async fn remove(&self, id: u16) -> Option<Request> {
        self.items.lock().await.remove(&id)
    }
}
