// Path: crates/api/src/state/pins.rs

//! A lock-free, thread-safe mechanism for pinning state versions to prevent premature pruning.

use crate::state::PruningGuard;
use dashmap::DashMap;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// A type alias for clarity.
pub type Height = u64;

/// A thread-safe, reference-counted map for pinning specific state versions by height.
/// This implementation uses a concurrent map of atomic counters, making pin/unpin
/// operations lock-free and safe to call from any context, including `Drop` implementations
/// during a panic.
#[derive(Default, Debug)]
pub struct StateVersionPins {
    // One counter per height; map ops are sharded, counters are atomic.
    inner: DashMap<Height, Arc<AtomicU32>>,
}

impl StateVersionPins {
    /// Creates a new, empty set of version pins.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments the pin count for a given height, preventing it from being pruned.
    /// This operation is lock-free.
    #[inline]
    pub fn pin(&self, h: Height) {
        let entry = self
            .inner
            .entry(h)
            .or_insert_with(|| Arc::new(AtomicU32::new(0)));
        entry.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the pin count for a given height. This operation is lock-free and panic-safe.
    /// It performs an opportunistic removal of the counter if it reaches zero to keep the map tidy.
    #[inline]
    pub fn unpin(&self, h: Height) {
        // Determine if we *might* need to prune, releasing the read lock immediately.
        let should_prune = if let Some(v) = self.inner.get(&h) {
            // If the previous value was 1, we are the ones decrementing to 0.
            v.fetch_sub(1, Ordering::Release) == 1
        } else {
            false
        };

        // If we were the last unpin, perform an opportunistic prune.
        // This is now outside the scope of the read-lock guard from `get()`.
        if should_prune {
            // Remove the entry only if the count is still zero. This is safe against races
            // where another thread pins the same height immediately after our fetch_sub.
            self.inner
                .remove_if(&h, |_, val_arc| val_arc.load(Ordering::Acquire) == 0);
        }
    }

    /// Returns a snapshot of all currently pinned heights (i.e., with a count > 0).
    pub fn snapshot(&self) -> BTreeSet<u64> {
        self.inner
            .iter()
            .filter(|entry| entry.value().load(Ordering::Acquire) > 0)
            .map(|entry| *entry.key())
            .collect()
    }

    /// Returns the minimum height currently pinned by any consumer.
    /// Returns `u64::MAX` if no heights are pinned.
    pub fn min_pinned_height(&self) -> u64 {
        let mut min_h = u64::MAX;

        for entry in self.inner.iter() {
            if entry.value().load(Ordering::Acquire) > 0 {
                let h = *entry.key();
                if h < min_h {
                    min_h = h;
                }
            }
        }

        min_h
    }
}

impl PruningGuard for StateVersionPins {
    fn min_required_height(&self) -> u64 {
        self.min_pinned_height()
    }
}

/// An RAII guard that automatically pins a state version on creation and unpins it on drop.
///
/// This is the primary mechanism for ensuring safety. Any code that needs a stable,
/// temporary view of a specific state version should create a `PinGuard` for that height.
#[must_use = "PinGuard must be bound to a variable to ensure the pin is held for the correct scope"]
pub struct PinGuard {
    pins: Arc<StateVersionPins>,
    height: u64,
}

impl PinGuard {
    /// Creates a new guard, immediately pinning the specified height. This operation is synchronous.
    pub fn new(pins: Arc<StateVersionPins>, height: u64) -> Self {
        pins.pin(height);
        Self { pins, height }
    }
}

impl Drop for PinGuard {
    /// Automatically unpins the height when the guard goes out of scope.
    /// This implementation is now fully synchronous, non-blocking, and panic-safe.
    fn drop(&mut self) {
        self.pins.unpin(self.height);
    }
}

#[cfg(test)]
#[path = "pins/tests.rs"]
mod tests;
