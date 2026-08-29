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
    /// The most recent opcode that arrived on this id without being one of `expected`.
    ///
    /// This is the evidence that turns an expiring request from "the peer said nothing" into
    /// "the peer answered with opcode N, which answers nothing I asked" — see
    /// [`Self::into_diagnosis`].
    ///
    /// The most recent is kept rather than the first because a genuine id collision is followed
    /// by the real reply (which completes the waiter, so nothing is kept at all), whereas a peer
    /// emitting junk keeps emitting it; the last frame before the deadline is the one most worth
    /// naming.
    undeclared: Option<u8>,
    _permit: OwnedSemaphorePermit,
}

impl Request {
    /// Hand the reply to the waiter. A caller that has since given up is not an error.
    pub(crate) fn send(self, message: DigMessage) {
        self.sender.send(message).ok();
    }

    /// What this request should report now that its deadline has passed.
    ///
    /// `Some((expected, found))` when at least one frame arrived on its id under an opcode it
    /// never declared — the caller reports [`LinkError::InvalidResponse`]; `None` when the peer
    /// simply never answered, which is a plain timeout.
    ///
    /// [`LinkError::InvalidResponse`]: crate::LinkError::InvalidResponse
    pub(crate) fn into_diagnosis(self) -> Option<(Vec<u8>, u8)> {
        self.undeclared.map(|found| (self.expected, found))
    }
}

/// How an inbound frame relates to the request, if any, holding its correlation id.
///
/// The three cases are kept distinct because they have three different correct handlings, and
/// collapsing any two of them has been a real defect: an undeclared opcode must not answer the
/// waiter (that is the hijack), and it must not be indistinguishable from an id nobody holds
/// (that is what leaves a request reporting a bare timeout it did not suffer).
pub(crate) enum Correlation {
    /// No live waiter holds this id: the frame belongs to the application.
    Unknown,

    /// A waiter declared this opcode: the frame is its answer.
    Answer(Request),

    /// A live waiter holds this id, but never declared this opcode.
    ///
    /// The waiter stays parked — the frame is not its answer, and its real answer may still be
    /// in flight — but the collision has been recorded against it, so if the deadline does
    /// expire the caller learns what arrived instead of merely that nothing did. The frame
    /// itself belongs to the application, which is where an inbound request is answered.
    Undeclared,
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
    /// id belongs to the application (see [`Self::take`]).
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
                undeclared: None,
                _permit: permit,
            },
        );
        id
    }

    /// Classify an inbound frame against the waiter, if any, holding `id`.
    ///
    /// A waiter is removed only when the frame answers it. On a mismatch the waiter is kept and
    /// the offending opcode is recorded against it, because the two situations that produce a
    /// mismatch are indistinguishable at this point — an honest peer's own request that happened
    /// to allocate the same id, whose real reply is still coming, and a peer answering with
    /// junk, whose real reply never will. Failing the waiter here would resolve that ambiguity
    /// in favour of the second and break the first.
    pub(crate) async fn take(&self, id: u16, msg_type: u8) -> Correlation {
        let mut items = self.items.lock().await;

        let Some(request) = items.get_mut(&id) else {
            return Correlation::Unknown;
        };
        if !request.expected.contains(&msg_type) {
            request.undeclared = Some(msg_type);
            return Correlation::Undeclared;
        }

        Correlation::Answer(
            items
                .remove(&id)
                .expect("the entry was observed under the same lock"),
        )
    }

    /// Take the waiter for `id` whatever it was waiting for — used to reclaim an id when the
    /// request itself is abandoned (a failed send, an expired deadline).
    pub(crate) async fn cancel(&self, id: u16) -> Option<Request> {
        self.items.lock().await.remove(&id)
    }
}
