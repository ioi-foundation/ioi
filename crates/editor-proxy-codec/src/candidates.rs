//! The candidate cap (DESIGN v2 (3), a stated HTTP policy change).

use crate::wire::MAX_DIGESTS;
use ioi_proxy_digest::Sha256Digest;

/// More than eight lease-token candidate occurrences in one request: the proxy answers the HTTP
/// request with a fixed typed 400, sends NO ADMIT, makes no connector attempt, echoes no token,
/// and closes the connection. The ninth candidate is never truncated away.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TooManyLeaseCandidates;

/// One request's lease-token candidates: counts nonempty matching header/cookie candidate
/// OCCURRENCES in parse order, duplicates included (never deduplicated to hide a ninth), and keeps
/// each one's digest for a forward-mode ADMIT. The ninth occurrence refuses. For a lease exchange
/// the single parsed nonempty form token is counted here too; for static serving every occurrence
/// is counted although only the selected token authenticates.
pub struct LeaseCandidates {
    n: usize,
    digests: [[u8; 32]; MAX_DIGESTS],
    refused: bool,
}

impl LeaseCandidates {
    /// No candidates yet.
    pub const fn new() -> LeaseCandidates {
        LeaseCandidates {
            n: 0,
            digests: [[0u8; 32]; MAX_DIGESTS],
            refused: false,
        }
    }

    /// Counts one candidate occurrence (an EMPTY candidate does not count) and keeps its digest.
    /// The ninth nonempty occurrence, and every push after it, refuses.
    pub fn push(&mut self, candidate: &[u8]) -> Result<(), TooManyLeaseCandidates> {
        if self.refused {
            return Err(TooManyLeaseCandidates);
        }
        if candidate.is_empty() {
            return Ok(());
        }
        if self.n == MAX_DIGESTS {
            // RED: the ninth candidate is TRUNCATED away (T-CANDIDATES fails here).
            return Ok(());
        }
        self.digests[self.n] = *Sha256Digest::of(candidate).as_bytes();
        self.n += 1;
        Ok(())
    }

    /// How many nonempty occurrences were counted (0..=8 while not refused).
    pub fn count(&self) -> usize {
        self.n
    }

    /// True once a ninth occurrence was pushed.
    pub fn is_refused(&self) -> bool {
        self.refused
    }

    pub(crate) fn digests(&self) -> &[[u8; 32]] {
        &self.digests[..self.n]
    }

    pub(crate) fn digest_array(&self) -> [[u8; 32]; MAX_DIGESTS] {
        self.digests
    }
}

impl Default for LeaseCandidates {
    fn default() -> LeaseCandidates {
        LeaseCandidates::new()
    }
}
