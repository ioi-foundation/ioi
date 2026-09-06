//! Separate bounded PUSHQUERY admission from nonce-bound reply observation.
//! This removes one queue dependency, not the remaining service/timing obligations.

use ioi_networking::libp2p::QuvNetworkEvent;
use std::future::Future;
use tokio::sync::{mpsc, watch};

struct AbortAdmissionOnDrop(tokio::task::AbortHandle);

impl Drop for AbortAdmissionOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) async fn run<P, R, O, PF, RF>(
    mut receiver: mpsc::Receiver<QuvNetworkEvent>,
    mut shutdown: watch::Receiver<bool>,
    capacity: usize,
    mut push: P,
    mut reply: R,
    mut overflow: O,
) where
    P: FnMut(QuvNetworkEvent) -> PF + Send + 'static,
    R: FnMut(QuvNetworkEvent) -> RF,
    O: FnMut(QuvNetworkEvent),
    PF: Future<Output = ()> + Send + 'static,
    RF: Future<Output = ()>,
{
    let (push_sender, mut push_receiver) = mpsc::channel(capacity);
    let mut worker = tokio::spawn(async move {
        while let Some(event) = push_receiver.recv().await {
            push(event).await;
        }
    });
    // The validator may abort this outer task after its shutdown grace period.
    // Dropping a JoinHandle alone would detach the blocked admission worker.
    let _worker_lifetime = AbortAdmissionOnDrop(worker.abort_handle());
    let mut worker_finished = false;
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            result = &mut worker => {
                worker_finished = true;
                tracing::error!(target: "quv", event = "push_admission_worker_stopped", ?result, "QUV admission worker stopped; event routing stopped");
                break;
            }
            event = receiver.recv() => match event {
                Some(event @ QuvNetworkEvent::PushQueryReceived { .. }) => {
                    // Never await push admission here: replies share this input.
                    if let Err(error) = push_sender.try_send(event) {
                        overflow(error.into_inner());
                    }
                }
                Some(event @ QuvNetworkEvent::ReplyReceived { .. }) => reply(event).await,
                None => break,
            }
        }
    }
    drop(push_sender);
    if !worker_finished {
        worker.abort();
        if let Err(error) = worker.await {
            if !error.is_cancelled() {
                tracing::error!(target: "quv", event = "push_admission_worker_stopped", %error, "QUV admission worker failed during shutdown");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{
        AccountId, QuvAuthorityModeV0, QuvCandidateV0, QuvPushQueryV0, QuvReplyV0, QuvSlotV0,
    };
    use libp2p::PeerId;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn aborting_event_drain_cancels_blocked_admission_worker() {
        struct SignalDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for SignalDrop {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }
        let (sender, receiver) = mpsc::channel(1);
        let (_shutdown, stopped) = watch::channel(false);
        let (started, ready) = tokio::sync::oneshot::channel();
        let (dropped, finished) = tokio::sync::oneshot::channel();
        let mut started = Some(started);
        let mut dropped = Some(dropped);
        let task = tokio::spawn(run(
            receiver,
            stopped,
            1,
            move |_| {
                let started = started.take().unwrap();
                let dropped = dropped.take().unwrap();
                async move {
                    let _signal = SignalDrop(Some(dropped));
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                }
            },
            |_| async {},
            |_| panic!("unexpected overflow"),
        ));
        sender.send(event(false, 1)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        // Match the validator's forced abort after its shutdown grace period.
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(5), finished)
            .await
            .unwrap()
            .unwrap();
    }

    fn event(is_reply: bool, nonce: u8) -> QuvNetworkEvent {
        let member = AccountId([1; 32]);
        let slot = QuvSlotV0 {
            configuration_root: [2; 32],
            policy_root: [3; 32],
            network_id: [4; 32],
            domain_id: [5; 32],
            slot: 1,
            predecessor: [6; 32],
            authority_mode: QuvAuthorityModeV0::Unowned,
        };
        if is_reply {
            QuvNetworkEvent::ReplyReceived {
                reply: QuvReplyV0 {
                    verifier_nonce: [nonce; 32],
                    member,
                    slot,
                    candidate_hash: [7; 32],
                    snapshot_hash: [8; 32],
                    complete_snapshot: vec![],
                    signature: vec![],
                },
                authenticated_account: member,
                from: PeerId::random(),
            }
        } else {
            QuvNetworkEvent::PushQueryReceived {
                query: QuvPushQueryV0 {
                    verifier_nonce: [nonce; 32],
                    candidate: QuvCandidateV0 {
                        slot,
                        payload_hash: [7; 32],
                        authorizer: member,
                        authority_signature: vec![],
                    },
                },
                authenticated_account: member,
                from: PeerId::random(),
            }
        }
    }

    #[tokio::test]
    async fn blocked_push_admission_does_not_block_reply_or_hide_overflow() {
        let (sender, receiver) = mpsc::channel(8);
        let (shutdown, stopped) = watch::channel(false);
        let (started, mut starts) = mpsc::channel(8);
        let (observed, mut observations) = mpsc::unbounded_channel();
        let (refused, mut refusals) = mpsc::unbounded_channel();
        let gate = Arc::new(Semaphore::new(0));
        let task = tokio::spawn(run(
            receiver,
            stopped,
            1,
            move |_| {
                let started = started.clone();
                let gate = gate.clone();
                async move {
                    started.send(()).await.unwrap();
                    let _permit = gate.acquire().await.unwrap();
                }
            },
            move |event| {
                observed.send(event).unwrap();
                async {}
            },
            move |event| {
                refused.send(event).unwrap();
            },
        ));
        sender.send(event(false, 1)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), starts.recv())
            .await
            .unwrap()
            .unwrap();
        sender.send(event(false, 2)).await.unwrap();
        sender.send(event(false, 3)).await.unwrap();
        sender.send(event(true, 4)).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), observations.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, QuvNetworkEvent::ReplyReceived { reply, .. } if reply.verifier_nonce == [4; 32])
        );
        assert!(
            matches!(refusals.try_recv().unwrap(), QuvNetworkEvent::PushQueryReceived { query, .. } if query.verifier_nonce == [3; 32])
        );
        assert!(starts.try_recv().is_err());
        assert!(refusals.try_recv().is_err());
        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}
