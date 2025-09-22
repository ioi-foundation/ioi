// Path: crates/api/src/state/pins.rs

//! A thread-safe mechanism for pinning state versions to prevent premature pruning.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;

/// A thread-safe, reference-counted map for pinning specific state versions by height.
///
/// This service is used to prevent the garbage collector from pruning a state version
/// that is still being used by an in-flight operation (e.g., a `StateOverlay` for
/// transaction simulation or an RPC handler generating a historical proof).
#[derive(Default, Debug, Clone)]
pub struct StateVersionPins {
    counts: Arc<Mutex<HashMap<u64, u32>>>,
}

impl StateVersionPins {
    /// Increments the pin count for a given height, preventing it from being pruned.
    pub async fn pin(&self, height: u64) {
        let mut counts = self.counts.lock().await;
        *counts.entry(height).or_insert(0) += 1;
    }

    /// Asynchronously decrements the pin count for a given height. The height is unpinned
    /// and becomes eligible for pruning once its count reaches zero.
    pub async fn unpin(&self, height: u64) {
        let mut counts = self.counts.lock().await;
        if let Some(count) = counts.get_mut(&height) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&height);
            }
        }
    }

    /// Synchronously decrements the pin count for a given height, using a non-blocking lock.
    /// This is intended as a best-effort fallback for Drop implementations.
    pub fn unpin_sync(&self, height: u64) {
        if let Ok(mut counts) = self.counts.try_lock() {
            if let Some(count) = counts.get_mut(&height) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(&height);
                }
            }
        }
        // If try_lock fails, skip; the GC reads a snapshot and will be conservative.
    }

    /// Returns a snapshot of all currently pinned heights.
    pub async fn snapshot(&self) -> BTreeSet<u64> {
        self.counts.lock().await.keys().copied().collect()
    }
}

/// An RAII guard that automatically pins a state version on creation and unpins it on drop.
///
/// This is the primary mechanism for ensuring safety. Any code that needs a stable,
/// temporary view of a specific state version should create a `PinGuard` for that height.
pub struct PinGuard {
    pins: Arc<StateVersionPins>,
    height: u64,
}

impl PinGuard {
    /// Creates a new guard, immediately pinning the specified height.
    pub async fn new(pins: Arc<StateVersionPins>, height: u64) -> Self {
        pins.pin(height).await;
        Self { pins, height }
    }
}

impl Drop for PinGuard {
    /// Automatically unpins the height when the guard goes out of scope.
    /// This is runtime-aware to avoid panicking if dropped outside an active Tokio runtime.
    fn drop(&mut self) {
        let pins = self.pins.clone();
        let h = self.height;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // If in an async context, spawn a task to perform the async unpin.
            handle.spawn(async move {
                pins.unpin(h).await;
            });
        } else {
            // If not in an async context, use the synchronous, non-blocking fallback.
            pins.unpin_sync(h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_pinguard_drop_no_runtime() {
        // This test runs outside a tokio runtime.
        let pins = Arc::new(StateVersionPins::default());
        let height_to_pin = 42;

        // Create a guard inside a block to control its drop timing.
        // We can't use `PinGuard::new` as it's async, so we manually construct.
        {
            let _guard = PinGuard {
                pins: pins.clone(),
                height: height_to_pin,
            };
            // Manually pin to simulate what `new` would do.
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(pins.pin(height_to_pin));
            assert_eq!(
                *pins.counts.try_lock().unwrap().get(&height_to_pin).unwrap(),
                1
            );
        } // _guard is dropped here, calling unpin_sync.

        // After drop, the count should be zero and the key removed.
        std::thread::sleep(Duration::from_millis(10)); // Give a moment for potential race.
        let counts = pins.counts.try_lock().unwrap();
        assert!(!counts.contains_key(&height_to_pin));
    }

    #[tokio::test]
    async fn test_pinguard_drop_with_runtime() {
        let pins = Arc::new(StateVersionPins::default());
        let height_to_pin = 84;

        {
            // The `new` function is async and must be awaited.
            let _guard = PinGuard::new(pins.clone(), height_to_pin).await;
            assert_eq!(*pins.counts.lock().await.get(&height_to_pin).unwrap(), 1);
        } // _guard is dropped here, spawning a task to call async unpin.

        // Give the spawned task a moment to run and acquire the lock.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let counts = pins.counts.lock().await;
        assert!(!counts.contains_key(&height_to_pin));
    }
}
