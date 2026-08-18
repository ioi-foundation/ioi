// Path: crates/consensus/src/aft/guardian_majority/pacemaker.rs

//! Manages the timing and view progression for the Aft deterministic consensus engine.
//!
//! The Pacemaker decouples the "when" from the "what" of consensus. It tracks
//! the current view, calculates timeouts based on exponential backoff, and
//! signals when a view change is required due to lack of progress.
//!
//! AFT-CB RES-R10 D1 (adaptive backoff): the timeout for a view now scales
//! with the number of CONSECUTIVE failed views since the last observed
//! progress, so a partition that keeps failing views widens the timeout
//! window geometrically (bounded by a cap) and stops the pathological case
//! where a fixed timeout shorter than the actual post-GST delay can never
//! let a view complete. Real progress resets the backoff to the base. This
//! is assumption-neutral --- it changes only WHEN the pacemaker fires, never
//! the safety rules --- and it is the buildable half of the R10 fallback
//! design (the D2--D4 pessimistic path with a common coin remains a named
//! residual gated on a fresh theorem review).

use std::time::{Duration, Instant};

/// The largest consecutive-failure exponent the backoff applies. Beyond
/// this the timeout is held flat, so a permanently stalled height cannot
/// drive the timeout to an unbounded value.
const MAX_BACKOFF_EXPONENT: u32 = 8;

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
    /// Consecutive views entered without an intervening progress
    /// observation (AFT-CB RES-R10 D1). Zero in steady state; each view
    /// advance without progress increments it, and any observed progress
    /// resets it. This is the exponent the backoff raises `backoff_factor`
    /// to.
    consecutive_timeouts: u32,
}

impl Pacemaker {
    /// Creates a new Pacemaker with the specified base timeout.
    pub fn new(base_timeout: Duration) -> Self {
        Self {
            current_view: 0,
            view_start_time: Instant::now(),
            base_timeout,
            backoff_factor: 1.2, // Conservative exponential backoff
            consecutive_timeouts: 0,
        }
    }

    /// Checks if the current view has timed out.
    /// Returns true if `now - view_start_time > timeout_for_view`.
    pub fn check_timeout(&self) -> bool {
        let elapsed = self.view_start_time.elapsed();
        let timeout = self.timeout_for_view();
        elapsed > timeout
    }

    /// Advances the pacemaker to a new view, resetting the timer.
    /// If `new_view` is not greater than `current_view`, this is a no-op (idempotency).
    ///
    /// A forward advance is a view that failed to commit before it was
    /// superseded (a timeout certificate formed, or a relayed one was
    /// adopted), so it counts toward the consecutive-failure backoff until
    /// real progress resets it (AFT-CB RES-R10 D1).
    pub fn advance_view(&mut self, new_view: u64) {
        if new_view > self.current_view {
            self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
            self.current_view = new_view;
            self.view_start_time = Instant::now();
        }
    }

    /// Adopts a view learned from a RELAYED timeout certificate (AFT-CB
    /// RES-R10 D1, the synchronizer edge): a node that did not itself
    /// witness the quorum forming a TC still enters the new view within one
    /// message delay of the relayer rather than waiting out its own timer.
    /// Semantically identical to [`advance_view`] --- the distinct name
    /// documents the synchronizer intent at the call site in the runtime,
    /// where the relay broadcast lives.
    pub fn adopt_relayed_view(&mut self, relayed_view: u64) {
        self.advance_view(relayed_view);
    }

    /// Records forward progress for the current height. A valid proposal in the
    /// current or a newer view should suppress spurious timeouts while the node
    /// is verifying and voting on that proposal.
    ///
    /// Progress resets the consecutive-failure backoff: the timeout window
    /// returns to the base for the next view (AFT-CB RES-R10 D1).
    pub fn observe_progress(&mut self, view: u64) {
        if view > self.current_view {
            self.current_view = view;
        }
        self.consecutive_timeouts = 0;
        self.view_start_time = Instant::now();
    }

    /// The consecutive-failure exponent currently applied to the backoff
    /// (AFT-CB RES-R10 D1). Exposed for observability and tests.
    pub fn consecutive_timeouts(&self) -> u32 {
        self.consecutive_timeouts
    }

    /// Calculates the timeout duration for the current view.
    ///
    /// AFT-CB RES-R10 D1: `base_timeout * backoff_factor^consecutive_timeouts`,
    /// with the exponent capped at [`MAX_BACKOFF_EXPONENT`] so an
    /// indefinitely stalled height holds a bounded (not unbounded) timeout.
    /// With `consecutive_timeouts == 0` this is exactly `base_timeout`, so
    /// steady-state behavior is unchanged.
    fn timeout_for_view(&self) -> Duration {
        let exponent = self.consecutive_timeouts.min(MAX_BACKOFF_EXPONENT);
        if exponent == 0 {
            return self.base_timeout;
        }
        let scale = self.backoff_factor.powi(exponent as i32);
        // Guard against a non-finite or non-positive factor collapsing the
        // timeout; fall back to the base rather than to zero.
        if !scale.is_finite() || scale <= 0.0 {
            return self.base_timeout;
        }
        self.base_timeout.mul_f64(scale)
    }
}

#[cfg(test)]
#[path = "pacemaker/tests.rs"]
mod tests;
