#[tokio::test]
async fn finalization_releases_node_state_before_waiting_for_context() {
    use std::{
        future::{poll_fn, Future},
        task::Poll,
    };
    for initial in [NodeState::Syncing, NodeState::Synced] {
        let context = tokio::sync::Mutex::new(());
        let node_state = tokio::sync::Mutex::new(initial);
        // A sync handler owns context and will need node state. Meanwhile the
        // finalizer updates node state and then needs context in its continuation.
        let sync_context = context.lock().await;
        let mut finalizer = Box::pin(super::post_commit::after_synced_node_state(
            &node_state,
            async {
                let _context = context.lock().await;
            },
        ));
        poll_fn(|cx| {
            assert!(matches!(finalizer.as_mut().poll(cx), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        let sync_state = node_state
            .try_lock()
            .expect("finalizer must not hold node state while waiting for context");
        assert_eq!(*sync_state, NodeState::Synced);
        drop(sync_state);
        drop(sync_context);
        finalizer.await;
    }
}
