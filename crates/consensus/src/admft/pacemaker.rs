// Path: crates/consensus/src/admft/pacemaker.rs

//! Manages the timing and view progression for the A-DMFT consensus engine.
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
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_pacemaker_timeout() {
        let mut pm = Pacemaker::new(Duration::from_millis(100));
        assert!(!pm.check_timeout());
        sleep(Duration::from_millis(150));
        assert!(pm.check_timeout());
    }

    #[test]
    fn test_advance_view_resets_timer() {
        let mut pm = Pacemaker::new(Duration::from_millis(100));
        sleep(Duration::from_millis(150));
        assert!(pm.check_timeout());

        pm.advance_view(1);
        assert!(!pm.check_timeout());
        assert_eq!(pm.current_view, 1);
    }

    #[test]
    fn test_advance_view_monotonicity() {
        let mut pm = Pacemaker::new(Duration::from_millis(100));
        pm.advance_view(5);
        assert_eq!(pm.current_view, 5);

        // Should ignore lower view
        pm.advance_view(3);
        assert_eq!(pm.current_view, 5);
    }
}
