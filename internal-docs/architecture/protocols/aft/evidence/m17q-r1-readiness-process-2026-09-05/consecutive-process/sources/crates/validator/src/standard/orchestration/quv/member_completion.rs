//! Captured routing handles for already completed durable member work.
//! Completion cannot acquire the main orchestration context through this API.

use anyhow::Result;
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::{
    app::{AccountId, QuvReplyV0},
    codec,
};
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};

pub(super) struct QuvMemberCompletionV0 {
    notify: Arc<Notify>,
    commander: mpsc::Sender<SwarmCommand>,
}

pub(super) struct QuvMemberResponseV0 {
    pub(super) recipient: AccountId,
    pub(super) reply: QuvReplyV0,
    commander: mpsc::Sender<SwarmCommand>,
}

impl QuvMemberCompletionV0 {
    pub(super) fn new(notify: Arc<Notify>, commander: mpsc::Sender<SwarmCommand>) -> Self {
        Self { notify, commander }
    }

    /// Wake selection after the durable task returns, including a refused task.
    /// No reply exists on error; notification itself confers no authority.
    pub(super) fn finish(
        self,
        result: Result<(AccountId, QuvReplyV0)>,
    ) -> Result<QuvMemberResponseV0> {
        self.notify.notify_one();
        result.map(|(recipient, reply)| QuvMemberResponseV0 {
            recipient,
            reply,
            commander: self.commander,
        })
    }
}

impl QuvMemberResponseV0 {
    pub(super) async fn send(self) -> Result<()> {
        let nonce = self.reply.verifier_nonce;
        let recipient = self.recipient;
        let data = codec::to_bytes_canonical(&self.reply).map_err(anyhow::Error::msg)?;
        tracing::debug!(target: "quv", event = "reply_command_waiting", nonce = %hex::encode(nonce), ?recipient);
        tracing::debug!(target: "quv", event = "reply_command_sending", nonce = %hex::encode(nonce), ?recipient);
        self.commander
            .send(SwarmCommand::QueueQuvReply { recipient, data })
            .await?;
        // Channel admission is not durable outbox admission or delivery.
        tracing::debug!(target: "quv", event = "reply_command_sent", nonce = %hex::encode(nonce), ?recipient);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{QuvAuthorityModeV0, QuvSlotV0};
    use std::{
        future::{poll_fn, Future},
        task::Poll,
    };

    fn reply() -> QuvReplyV0 {
        QuvReplyV0 {
            verifier_nonce: [1; 32],
            member: AccountId([2; 32]),
            slot: QuvSlotV0 {
                configuration_root: [3; 32],
                policy_root: [4; 32],
                network_id: [5; 32],
                domain_id: [6; 32],
                slot: 1,
                predecessor: [7; 32],
                authority_mode: QuvAuthorityModeV0::Unowned,
            },
            candidate_hash: [8; 32],
            snapshot_hash: [9; 32],
            complete_snapshot: vec![],
            signature: vec![10],
        }
    }

    #[tokio::test]
    async fn captured_completion_notifies_and_forwards_exact_reply_under_backpressure() {
        let notify = Arc::new(Notify::new());
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .send(SwarmCommand::CompleteQuvOperation { nonce: [0; 32] })
            .await
            .unwrap();
        let route = QuvMemberCompletionV0::new(notify.clone(), sender);
        let expected = reply();
        let recipient = AccountId([11; 32]);
        let response = route.finish(Ok((recipient, expected.clone()))).unwrap();
        let mut notification = Box::pin(notify.notified());
        poll_fn(|cx| {
            assert!(notification.as_mut().poll(cx).is_ready());
            Poll::Ready(())
        })
        .await;
        let mut send = Box::pin(response.send());
        poll_fn(|cx| {
            assert!(send.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        receiver.recv().await.unwrap();
        send.await.unwrap();
        match receiver.recv().await.unwrap() {
            SwarmCommand::QueueQuvReply {
                recipient: actual,
                data,
            } => {
                assert_eq!(actual, recipient);
                assert_eq!(
                    codec::from_bytes_canonical::<QuvReplyV0>(&data).unwrap(),
                    expected
                );
            }
            _ => panic!("wrong command kind"),
        }
    }

    #[tokio::test]
    async fn refused_completion_notifies_without_reply_and_closed_lane_returns_error() {
        let notify = Arc::new(Notify::new());
        let (sender, mut receiver) = mpsc::channel(1);
        let route = QuvMemberCompletionV0::new(notify.clone(), sender.clone());
        assert!(route
            .finish(Err(anyhow::anyhow!("durable work refused")))
            .is_err());
        let mut notification = Box::pin(notify.notified());
        poll_fn(|cx| {
            assert!(notification.as_mut().poll(cx).is_ready());
            Poll::Ready(())
        })
        .await;
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        drop(receiver);
        let response = QuvMemberCompletionV0::new(notify.clone(), sender)
            .finish(Ok((AccountId([11; 32]), reply())))
            .unwrap();
        assert!(response.send().await.is_err());
    }
}
