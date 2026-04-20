// Path: crates/consensus/src/aft/guardian_majority/pacemaker.rs

//! Manages the timing and view progression for the Aft deterministic consensus engine.
//!
//! The Pacemaker decouples the "when" from the "what" of consensus. It tracks
//! the current view, calculates timeouts based on exponential backoff, and
//! signals when a view change is required due to lack of progress.

use std::time::{Duration, Instant};

/// Manages view timers and timeouts.
#[derive(Debug)]
pub struct Pacemaker {
    /// The current consensus view.
    pub current_view: u64,
    /// The instant when the current view started.
    pub view_start_time: Instant,
    /// The base duration for a view timeout.
    pub base_timeout: Duration,
    /// The multiplier for exponential backoff on timeouts.
    pub backoff_factor: f64,
}

impl Pacemaker {
    /// Creates a new Pacemaker with the specified base timeout.
    pub fn new(base_timeout: Duration) -> Self {
        Self {
            current_view: 0,
            view_start_time: Instant::now(),
            base_timeout,
            backoff_factor: 1.2, // Conservative exponential backoff
        }
    }

    /// Checks if the current view has timed out.
    /// Returns true if `now - view_start_time > timeout_for_view`.
    pub fn check_timeout(&self) -> bool {
        let elapsed = self.view_start_time.elapsed();
        let timeout = self.timeout_for_view(self.current_view);
        elapsed > timeout
    }

    /// Advances the pacemaker to a new view, resetting the timer.
    /// If `new_view` is not greater than `current_view`, this is a no-op (idempotency).
    pub fn advance_view(&mut self, new_view: u64) {
        if new_view > self.current_view {
            self.current_view = new_view;
            self.view_start_time = Instant::now();
        }
    }

    /// Records forward progress for the current height. A valid proposal in the
    /// current or a newer view should suppress spurious timeouts while the node
    /// is verifying and voting on that proposal.
    pub fn observe_progress(&mut self, view: u64) {
        if view > self.current_view {
            self.current_view = view;
        }
        self.view_start_time = Instant::now();
    }

    /// Calculates the timeout duration for a specific view.
    /// Formula: `base_timeout * (backoff_factor ^ view_delta)`
    /// Note: `view_delta` is relative to a successful round, but for simplicity here
    /// we just scale slightly or keep flat if we assume steady state.
    /// A robust implementation tracks consecutive failures.
    ///
    /// For this version, we use a simple linear scaling cap to avoid excessive delays.
    fn timeout_for_view(&self, _view: u64) -> Duration {
        // In a real BFT, this scales with the number of *failed* views since the last commit.
        // Since we don't track `last_commit_view` here yet, we return base_timeout.
        // Future optimization: pass `last_committed_view` to this function.
        self.base_timeout
    }
}

#[cfg(test)]
#[path = "pacemaker/tests.rs"]
mod tests;
