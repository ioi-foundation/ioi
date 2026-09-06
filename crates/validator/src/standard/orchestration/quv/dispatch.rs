//! Cancellation-safe accounting for local dispatch to the exact configured set.
//! Outbox admission is not delivery or a member reply; the complete live QUV
//! decision and its timing assumptions remain independently required.

use anyhow::{anyhow, Result};
use ioi_types::app::AccountId;
use std::{collections::BTreeSet, time::Duration};

pub(super) struct QuvDispatchV0 {
    remaining: BTreeSet<AccountId>,
    interval: Duration,
}

impl QuvDispatchV0 {
    pub(super) fn new(members: BTreeSet<AccountId>, interval: Duration) -> Result<Self> {
        if members.is_empty() || interval.is_zero() {
            return Err(anyhow!(
                "QUV dispatch requires a nonempty configured set and nonzero interval"
            ));
        }
        Ok(Self {
            remaining: members,
            interval,
        })
    }

    /// Record successful durable remote outbox admission or successful local
    /// write-before-reply processing. Duplicate/unconfigured completion is invalid.
    pub(super) fn record(&mut self, member: AccountId, observed_elapsed: Duration) -> Result<()> {
        if observed_elapsed > self.interval {
            return Err(anyhow!(
                "QUV dispatch completed after the rooted decision interval"
            ));
        }
        if !self.remaining.remove(&member) {
            return Err(anyhow!(
                "QUV dispatch completion is duplicate or unconfigured"
            ));
        }
        Ok(())
    }

    /// No live decision, acceptance audit, or head transition may run before
    /// every configured recipient's dispatch has completed.
    pub(super) fn finish<T>(self, decide: impl FnOnce() -> Result<T>) -> Result<T> {
        if !self.remaining.is_empty() {
            return Err(anyhow!("QUV request dispatch is incomplete"));
        }
        decide()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        future::{poll_fn, Future},
        task::Poll,
    };

    fn members() -> BTreeSet<AccountId> {
        (1..=4).map(|n| AccountId([n; 32])).collect()
    }

    #[test]
    fn dispatch_requires_every_exact_member_before_decision() {
        assert!(QuvDispatchV0::new(BTreeSet::new(), Duration::from_secs(1)).is_err());
        for omitted in members() {
            let mut dispatch = QuvDispatchV0::new(members(), Duration::from_secs(1)).unwrap();
            for member in members().into_iter().filter(|member| *member != omitted) {
                dispatch.record(member, Duration::ZERO).unwrap();
                let before = dispatch.remaining.clone();
                assert!(dispatch.record(member, Duration::ZERO).is_err());
                assert_eq!(dispatch.remaining, before);
            }
            let before = dispatch.remaining.clone();
            assert!(dispatch
                .record(AccountId([99; 32]), Duration::ZERO)
                .is_err());
            assert_eq!(dispatch.remaining, before);
            let called = Cell::new(false);
            assert!(dispatch
                .finish(|| {
                    called.set(true);
                    Ok(())
                })
                .is_err());
            assert!(!called.get());
        }
        let mut dispatch = QuvDispatchV0::new(members(), Duration::from_secs(1)).unwrap();
        for member in members() {
            dispatch.record(member, Duration::ZERO).unwrap();
        }
        assert_eq!(dispatch.finish(|| Ok(42)).unwrap(), 42);
        let mut dispatch = QuvDispatchV0::new(members(), Duration::from_secs(1)).unwrap();
        for member in members() {
            dispatch.record(member, Duration::ZERO).unwrap();
        }
        assert!(dispatch
            .finish::<()>(|| Err(anyhow!("live query refused")))
            .is_err());
    }

    #[test]
    fn dispatch_completion_obeys_before_equal_after_deadline() {
        let interval = Duration::from_secs(1);
        assert!(QuvDispatchV0::new(members(), Duration::ZERO).is_err());
        for elapsed in [interval - Duration::from_nanos(1), interval] {
            let mut dispatch = QuvDispatchV0::new(members(), interval).unwrap();
            for member in members() {
                dispatch.record(member, elapsed).unwrap();
            }
            dispatch.finish(|| Ok(())).unwrap();
        }
        for omitted in members() {
            let mut dispatch = QuvDispatchV0::new(members(), interval).unwrap();
            for member in members().into_iter().filter(|member| *member != omitted) {
                dispatch.record(member, Duration::ZERO).unwrap();
            }
            let before = dispatch.remaining.clone();
            assert!(dispatch
                .record(omitted, interval + Duration::from_nanos(1))
                .is_err());
            assert_eq!(dispatch.remaining, before);
            assert!(dispatch.finish(|| Ok(())).is_err());
        }
    }

    #[tokio::test]
    async fn canceled_dispatch_never_runs_the_live_decision() {
        for completed in 0..4 {
            let mut dispatch = QuvDispatchV0::new(members(), Duration::from_secs(1)).unwrap();
            let mut sender = Box::pin(async {
                for member in members().into_iter().take(completed) {
                    dispatch.record(member, Duration::ZERO).unwrap();
                }
                std::future::pending::<()>().await;
            });
            poll_fn(|cx| {
                assert!(sender.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(sender);
            let called = Cell::new(false);
            assert!(dispatch
                .finish(|| {
                    called.set(true);
                    Ok(())
                })
                .is_err());
            assert!(!called.get());
        }
    }
}
