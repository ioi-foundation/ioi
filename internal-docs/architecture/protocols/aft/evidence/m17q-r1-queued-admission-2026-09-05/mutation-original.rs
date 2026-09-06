//! Local queued operation admission. This is neither QUV authorization nor a
//! qualified wall-clock service guarantee. Each enrolled domain can have one
//! waiting foreground request; the lifecycle owns exactly one preparation worker.

use anyhow::{anyhow, Result};
use ioi_types::app::QuvHash;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) struct QuvOperationAdmissionV0 {
    active: Arc<Semaphore>,
    waiting_domains: BTreeMap<QuvHash, Arc<Semaphore>>,
}

impl QuvOperationAdmissionV0 {
    pub(crate) fn new(domains: impl IntoIterator<Item = QuvHash>) -> Self {
        Self {
            active: Arc::new(Semaphore::new(1)),
            waiting_domains: domains
                .into_iter()
                .map(|domain| (domain, Arc::new(Semaphore::new(1))))
                .collect(),
        }
    }

    /// Wait for exclusive operation ownership, with at most one waiting
    /// foreground request per configured domain. The waiting-domain permit is
    /// released on admission or cancellation; the active permit is retained
    /// through the durable accepted-head transition.
    pub(super) async fn foreground(&self, domain: QuvHash) -> Result<OwnedSemaphorePermit> {
        let waiting = self
            .waiting_domains
            .get(&domain)
            .ok_or_else(|| anyhow!("QUV operation domain is not enrolled"))?
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("QUV domain already has a waiting foreground request"))?;
        let active = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("QUV operation admission is closed"))?;
        drop(waiting);
        Ok(active)
    }

    /// Only the single lifecycle preparation worker calls this method. It joins
    /// the same semaphore queue as foreground operations, rather than racing
    /// them for an observed idle flag.
    pub(super) async fn preparation(&self) -> Result<OwnedSemaphorePermit> {
        self.active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("QUV operation admission is closed"))
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
