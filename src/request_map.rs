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
}

impl RequestMap {
    pub(crate) fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
            capacity: Arc::new(Semaphore::new(u16::MAX as usize)),
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

        let id = (0..=u16::MAX)
            .find(|candidate| !items.contains_key(candidate))
            .expect("the semaphore bounds live requests below the id space");

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
