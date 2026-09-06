//! Local queued operation admission. This is neither QUV authorization nor a
//! qualified wall-clock service guarantee. Each enrolled domain can have one
//! waiting foreground request; the lifecycle owns exactly one preparation worker.

use anyhow::{anyhow, Result};
use ioi_types::app::QuvHash;
use std::{collections::BTreeMap, future::Future, sync::Arc, time::Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Shared lifetime of all work belonging to one admitted operation. The final
/// share releases the semaphore before sampling its service completion.
pub(super) struct QuvActiveAdmissionV0 {
    permit: Option<OwnedSemaphorePermit>,
    nonce: QuvHash,
    started: Instant,
    deadline: Option<Instant>,
}

/// Carries operation ownership across delivery of a process-local continuation.
/// The consuming callback must finish the synchronous consequence or install
/// transition before returning. Dropping an undelivered/cancelled continuation
/// releases its share; already-started blocking work owns its own share.
pub(crate) struct QuvAdmittedContinuationV0<T> {
    value: T,
    admission: Arc<QuvActiveAdmissionV0>,
}

impl<T> QuvAdmittedContinuationV0<T> {
    pub(super) fn new(value: T, admission: Arc<QuvActiveAdmissionV0>) -> Self {
        Self { value, admission }
    }

    pub(crate) fn with_continuation<R>(self, work: impl FnOnce(T) -> R) -> R {
        let Self { value, admission } = self;
        let result = work(value);
        drop(admission);
        result
    }
}

impl QuvActiveAdmissionV0 {
    pub(super) fn new(
        permit: OwnedSemaphorePermit,
        nonce: QuvHash,
        started: Instant,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            permit: Some(permit),
            nonce,
            started,
            deadline,
        }
    }
}

fn release_and_observe(
    permit: OwnedSemaphorePermit,
    deadline: Option<Instant>,
    now: impl FnOnce() -> Instant,
) -> (Instant, bool) {
    drop(permit);
    let observed = now();
    (
        observed,
        deadline.is_some_and(|deadline| observed < deadline),
    )
}

impl Drop for QuvActiveAdmissionV0 {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let (released_at, service_budget_met) =
            release_and_observe(permit, self.deadline, Instant::now);
        let service_budgeted = self.deadline.is_some();
        if service_budgeted && !service_budget_met {
            tracing::warn!(target: "quv", event = "operation_service_expired", nonce = %hex::encode(self.nonce), phase = "admission_release");
        }
        tracing::debug!(target: "quv", event = "operation_admission_released", nonce = %hex::encode(self.nonce), service_budgeted, service_budget_met, elapsed_micros = %released_at.saturating_duration_since(self.started).as_micros());
    }
}

/// Pending-table removal does not imply startup/dispatch has finished.
pub(super) async fn retain_admission_until_complete<T>(
    admission: Arc<QuvActiveAdmissionV0>,
    work: impl Future<Output = T>,
) -> T {
    let result = work.await;
    drop(admission);
    result
}

/// An async waiter may be cancelled after blocking durable work starts. Keep
/// admission owned by that work until it returns or unwinds; dropping its join
/// handle cannot stop a running blocking closure.
pub(super) fn spawn_durable_with_admission<T: Send + 'static>(
    admission: Arc<QuvActiveAdmissionV0>,
    work: impl FnOnce() -> T + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    tokio::task::spawn_blocking(move || {
        let result = work();
        drop(admission);
        result
    })
}

pub(crate) struct QuvOperationAdmissionV0 {
    active: Arc<Semaphore>,
    waiting_domains: BTreeMap<QuvHash, Arc<Semaphore>>,
    waiting_preparation: Arc<Semaphore>,
    receipts: Arc<Semaphore>,
    waiting_receipts: BTreeMap<QuvHash, Arc<Semaphore>>,
    waiting_historical_receipt: Arc<Semaphore>,
    waiting_owned_receipt: Arc<Semaphore>,
}

impl QuvOperationAdmissionV0 {
    pub(crate) fn new(domains: impl IntoIterator<Item = QuvHash>) -> Self {
        let domains: Vec<_> = domains.into_iter().collect();
        Self {
            active: Arc::new(Semaphore::new(1)),
            waiting_preparation: Arc::new(Semaphore::new(1)),
            waiting_domains: domains
                .iter()
                .copied()
                .map(|domain| (domain, Arc::new(Semaphore::new(1))))
                .collect(),
            receipts: Arc::new(Semaphore::new(1)),
            waiting_receipts: domains
                .into_iter()
                .map(|domain| (domain, Arc::new(Semaphore::new(1))))
                .collect(),
            waiting_historical_receipt: Arc::new(Semaphore::new(1)),
            waiting_owned_receipt: Arc::new(Semaphore::new(1)),
        }
    }

    /// Bound initial inspection/result waiters by committed domain. Historical
    /// domains share one additional slot: lookup does not require a current
    /// candidate signature, head, authority fence or fresh live authorization.
    pub(crate) async fn receipt_access(&self, domain: QuvHash) -> Result<OwnedSemaphorePermit> {
        let waiting = self
            .waiting_receipts
            .get(&domain)
            .unwrap_or(&self.waiting_historical_receipt);
        self.enter_receipts(waiting).await
    }

    /// The one active QUV operation has separate waiting capacity, so terminal
    /// request traffic cannot occupy its slot when it reopens storage. This
    /// only serializes filesystem access; it creates no effect authority.
    pub(crate) async fn owned_receipt_access(&self) -> Result<OwnedSemaphorePermit> {
        self.enter_receipts(self.waiting_receipts.values().next().unwrap()).await
    }

    async fn enter_receipts(&self, capacity: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit> {
        let waiting = capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("QUV receipt waiting capacity is occupied"))?;
        let active = self
            .receipts
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("QUV receipt access is closed"))?;
        drop(waiting);
        Ok(active)
    }

    /// Wait for exclusive operation ownership, with at most one waiting
    /// foreground request per configured domain. The waiting-domain permit is
    /// released on admission or cancellation; the active permit is retained
    /// through the durable accepted-head transition.
    pub(super) fn reserve_foreground(&self, domain: QuvHash) -> Result<QuvWaitingForegroundV0> {
        let waiting = self
            .waiting_domains
            .get(&domain)
            .ok_or_else(|| anyhow!("QUV operation domain is not enrolled"))?
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("QUV domain already has a waiting foreground request"))?;
        Ok(QuvWaitingForegroundV0 {
            waiting,
            active: self.active.clone(),
        })
    }

    #[cfg(test)]
    pub(super) async fn foreground(&self, domain: QuvHash) -> Result<OwnedSemaphorePermit> {
        self.reserve_foreground(domain)?.enter().await
    }

    /// The lifecycle preparation worker joins the same FIFO as foreground
    /// operations. Enforce one waiting preparation even if another caller is
    /// introduced: the finite queue bound must not depend on call-site convention.
    pub(super) async fn preparation(&self) -> Result<OwnedSemaphorePermit> {
        let waiting = self
            .waiting_preparation
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("QUV preparation already has a waiting request"))?;
        let active = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("QUV operation admission is closed"))?;
        drop(waiting);
        Ok(active)
    }
}

/// Holds only this domain's waiting capacity while child readiness elapses.
/// The independent preparation worker can still enter the active lane.
pub(super) struct QuvWaitingForegroundV0 {
    waiting: OwnedSemaphorePermit,
    active: Arc<Semaphore>,
}

impl QuvWaitingForegroundV0 {
    pub(super) async fn enter_after(
        self,
        deadline: Option<Instant>,
    ) -> Result<OwnedSemaphorePermit> {
        if let Some(deadline) = deadline {
            tokio::time::sleep_until(deadline.into()).await;
        }
        self.enter().await
    }

    pub(super) async fn enter(self) -> Result<OwnedSemaphorePermit> {
        let active = self
            .active
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("QUV operation admission is closed"))?;
        drop(self.waiting);
        Ok(active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{poll_fn, Future},
        pin::Pin,
        task::Poll,
    };

    async fn require_pending<F: Future>(mut future: Pin<&mut F>) {
        poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn receipt_admission_bounds_history_preserves_fifo_and_protects_live_reopen() {
        use agentgres::consequence::ConsequenceStore;
        let gate = QuvOperationAdmissionV0::new([[1; 32], [2; 32]]);
        let temp = tempfile::tempdir().unwrap();
        let active = gate.receipt_access([1; 32]).await.unwrap();
        let store = ConsequenceStore::open(temp.path()).unwrap();
        let mut domain = Box::pin(gate.receipt_access([1; 32]));
        require_pending(domain.as_mut()).await;
        assert!(gate.receipt_access([1; 32]).await.is_err());
        let mut owned = Box::pin(gate.owned_receipt_access());
        require_pending(owned.as_mut()).await;
        assert!(gate.owned_receipt_access().await.is_err());
        let mut historical = Box::pin(gate.receipt_access([8; 32]));
        require_pending(historical.as_mut()).await;
        assert!(gate.receipt_access([9; 32]).await.is_err());
        // Cancellation frees the shared historical slot and removes its FIFO
        // position. Repeated terminal arrivals cannot overtake the live owner.
        drop(historical);
        let mut historical = Box::pin(gate.receipt_access([9; 32]));
        require_pending(historical.as_mut()).await;
        drop(store);
        drop(active);
        let domain = domain.await.unwrap();
        let store = ConsequenceStore::open(temp.path()).unwrap();
        require_pending(owned.as_mut()).await;
        require_pending(historical.as_mut()).await;
        drop(store);
        drop(domain);
        let owned = owned.await.unwrap();
        let store = ConsequenceStore::open(temp.path()).unwrap();
        require_pending(historical.as_mut()).await;
        drop(store);
        drop(owned);
        let historical = historical.await.unwrap();
        let store = ConsequenceStore::open(temp.path()).unwrap();
        drop(store);
        drop(historical);
        // No waiting capacity or filesystem exclusion leaks after cancellation
        // and normal completion, including a different historical identity.
        let _access = gate.receipt_access([8; 32]).await.unwrap();
        let _store = ConsequenceStore::open(temp.path()).unwrap();
    }

    #[tokio::test]
    async fn delivered_continuation_holds_admission_through_effect_and_cancelled_worker() {
        let gate = QuvOperationAdmissionV0::new([[1; 32]]);
        let admission = Arc::new(QuvActiveAdmissionV0::new(
            gate.preparation().await.unwrap(),
            [2; 32],
            Instant::now(),
            None,
        ));
        let continuation = QuvAdmittedContinuationV0::new(7, admission.clone());
        let (sender, receiver) = tokio::sync::oneshot::channel();
        assert!(sender.send(continuation).is_ok());
        drop(admission); // Pending operation and dispatch have both finished.
        let mut waiting = Box::pin(gate.foreground([1; 32]));
        require_pending(waiting.as_mut()).await;
        let continuation = receiver.await.unwrap();
        let active = gate.active.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            continuation.with_continuation(|value| {
                assert_eq!(value, 7);
                assert_eq!(active.available_permits(), 0);
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                assert_eq!(active.available_permits(), 0);
            });
            finished_tx.send(()).unwrap();
        });
        started_rx.await.unwrap();
        drop(worker); // Cancelling observation cannot stop started durable work.
        require_pending(waiting.as_mut()).await;
        release_tx.send(()).unwrap();
        finished_rx.await.unwrap();
        let next = waiting.await.unwrap();
        drop(next);

        // An abandoned delivery has no surviving continuation or worker.
        let admission = Arc::new(QuvActiveAdmissionV0::new(
            gate.preparation().await.unwrap(),
            [3; 32],
            Instant::now(),
            None,
        ));
        let (sender, receiver) = tokio::sync::oneshot::channel();
        drop(receiver);
        let rejected = sender.send(QuvAdmittedContinuationV0::new(8, admission.clone()));
        drop(admission);
        assert_eq!(gate.active.available_permits(), 0);
        drop(rejected);
        assert_eq!(gate.active.available_permits(), 1);
    }

    #[tokio::test]
    async fn readiness_wait_keeps_domain_capacity_and_leaves_preparation_lane_free() {
        let gate = QuvOperationAdmissionV0::new([[1; 32]]);
        let waiting = gate.reserve_foreground([1; 32]).unwrap();
        let mut child = Box::pin(
            waiting.enter_after(Some(Instant::now() + std::time::Duration::from_millis(100))),
        );
        require_pending(child.as_mut()).await;
        assert!(gate.reserve_foreground([1; 32]).is_err());
        // Inspect actual capacity: entering before the wait must fail here.
        assert_eq!(gate.active.available_permits(), 1);
        let worker = gate.preparation().await.unwrap();
        drop(worker);
        let admitted = tokio::time::timeout(std::time::Duration::from_secs(5), child)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(gate.active.available_permits(), 0);
        assert!(gate.reserve_foreground([1; 32]).is_ok());
        drop(admitted);
        let waiting = gate.reserve_foreground([1; 32]).unwrap();
        let mut canceled = Box::pin(
            waiting.enter_after(Some(Instant::now() + std::time::Duration::from_secs(60))),
        );
        require_pending(canceled.as_mut()).await;
        drop(canceled);
        assert!(gate.reserve_foreground([1; 32]).is_ok());
        assert_eq!(gate.active.available_permits(), 1);
    }

    #[tokio::test]
    async fn pending_removal_keeps_admission_until_dispatch_returns_or_is_canceled() {
        for cancel in [false, true] {
            let gate = QuvOperationAdmissionV0::new([[1; 32]]);
            let pending = Arc::new(QuvActiveAdmissionV0::new(
                gate.preparation().await.unwrap(),
                [1; 32],
                Instant::now(),
                None,
            ));
            let startup = pending.clone();
            let (entered, ready) = tokio::sync::oneshot::channel();
            let (release, done) = tokio::sync::oneshot::channel();
            let owner = tokio::spawn(retain_admission_until_complete(startup, async move {
                drop(pending);
                let _ = entered.send(());
                let _ = done.await;
            }));
            ready.await.unwrap();
            let mut next = Box::pin(gate.foreground([1; 32]));
            require_pending(next.as_mut()).await;
            if cancel {
                owner.abort();
                assert!(owner.await.unwrap_err().is_cancelled());
            } else {
                release.send(()).unwrap();
                owner.await.unwrap();
            }
            drop(
                tokio::time::timeout(std::time::Duration::from_secs(5), next)
                    .await
                    .unwrap()
                    .unwrap(),
            );
            assert_eq!(gate.active.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn admission_release_is_observed_after_semaphore_release() {
        let gate = QuvOperationAdmissionV0::new([[1; 32]]);
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        for observed in [
            deadline - std::time::Duration::from_nanos(1),
            deadline,
            deadline + std::time::Duration::from_nanos(1),
        ] {
            let permit = gate.preparation().await.unwrap();
            let (released_at, met) = release_and_observe(permit, Some(deadline), || {
                assert_eq!(gate.active.available_permits(), 1);
                observed
            });
            assert_eq!(released_at, observed);
            assert_eq!(met, observed < deadline);
        }
    }

    #[tokio::test]
    async fn canceled_durable_waiter_retains_admission_until_work_finishes() {
        let gate = QuvOperationAdmissionV0::new([[1; 32]]);
        let admission = Arc::new(QuvActiveAdmissionV0::new(
            gate.preparation().await.unwrap(),
            [1; 32],
            Instant::now(),
            None,
        ));
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let owner = tokio::spawn(async move {
            let work = spawn_durable_with_admission(admission.clone(), move || {
                let _ = entered.send(());
                released.recv().unwrap();
            });
            let result = work.await;
            drop(admission);
            result
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), started)
            .await
            .unwrap()
            .unwrap();
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        let mut next = Box::pin(gate.foreground([1; 32]));
        require_pending(next.as_mut()).await;
        assert_eq!(gate.active.available_permits(), 0);
        release.send(()).unwrap();
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), next)
            .await
            .unwrap()
            .unwrap();
        drop(next);
        assert_eq!(gate.active.available_permits(), 1);
    }

    #[tokio::test]
    async fn preparation_waiter_is_bounded_and_cancellation_preserves_fifo() {
        let gate = QuvOperationAdmissionV0::new([[1; 32], [2; 32]]);
        let active = gate.foreground([1; 32]).await.unwrap();
        let mut first = Box::pin(gate.preparation());
        require_pending(first.as_mut()).await;
        let mut duplicate = Box::pin(gate.preparation());
        poll_fn(|cx| {
            assert!(matches!(duplicate.as_mut().poll(cx), Poll::Ready(Err(_))));
            Poll::Ready(())
        })
        .await;
        let mut foreground = Box::pin(gate.foreground([2; 32]));
        require_pending(foreground.as_mut()).await;
        drop(first);
        assert_eq!(gate.waiting_preparation.available_permits(), 1);
        let mut replacement = Box::pin(gate.preparation());
        require_pending(replacement.as_mut()).await;
        drop(active);
        let foreground = foreground.await.unwrap();
        require_pending(replacement.as_mut()).await;
        drop(foreground);
        drop(replacement.await.unwrap());
        assert_eq!(gate.waiting_preparation.available_permits(), 1);
        assert_eq!(gate.active.available_permits(), 1);
    }

    #[tokio::test]
    async fn admission_serializes_and_preserves_queued_worker_order() {
        let gate = QuvOperationAdmissionV0::new([[1; 32], [2; 32]]);
        let active = gate.foreground([1; 32]).await.unwrap();
        let mut worker = Box::pin(gate.preparation());
        require_pending(worker.as_mut()).await;
        let mut foreground = Box::pin(gate.foreground([2; 32]));
        require_pending(foreground.as_mut()).await;
        let mut duplicate = Box::pin(gate.foreground([2; 32]));
        poll_fn(|cx| {
            assert!(matches!(duplicate.as_mut().poll(cx), Poll::Ready(Err(_))));
            Poll::Ready(())
        })
        .await;
        assert!(gate.foreground([3; 32]).await.is_err());
        drop(active);
        let worker = worker.await.unwrap();
        require_pending(foreground.as_mut()).await;
        drop(worker);
        let foreground = foreground.await.unwrap();
        assert_eq!(gate.active.available_permits(), 0);
        drop(foreground);
        assert_eq!(gate.active.available_permits(), 1);
    }

    #[tokio::test]
    async fn admission_cancellation_releases_domain_and_queue_capacity() {
        let gate = QuvOperationAdmissionV0::new([[1; 32]]);
        let active = gate.preparation().await.unwrap();
        let mut canceled = Box::pin(gate.foreground([1; 32]));
        require_pending(canceled.as_mut()).await;
        drop(canceled);
        let mut replacement = Box::pin(gate.foreground([1; 32]));
        require_pending(replacement.as_mut()).await;
        let mut later_worker = Box::pin(gate.preparation());
        require_pending(later_worker.as_mut()).await;
        drop(active);
        let replacement = replacement.await.unwrap();
        require_pending(later_worker.as_mut()).await;
        drop(replacement);
        drop(later_worker.await.unwrap());
        assert_eq!(gate.active.available_permits(), 1);
        assert_eq!(gate.waiting_domains[&[1; 32]].available_permits(), 1);
    }
}
