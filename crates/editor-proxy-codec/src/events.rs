//! Bounded event aggregation (DESIGN v2 (3)). Events are lease-scoped aggregates: conn is 0 for
//! all twelve codes, counts saturate, and neither side keeps a record or a frame per event.

use crate::types::EventCode;
use crate::wire::OutboundEvent;

/// The proxy's local event window: at most one EVENT per nonzero counter per window.
pub const PROXY_EVENT_WINDOW_NS: u64 = 1_000_000_000;
/// The daemon's local persistence window: at most one record per code per window.
pub const DAEMON_EVENT_WINDOW_NS: u64 = 10_000_000_000;

/// One closed daemon window's records: at most one per code (only nonzero counts), labelled by
/// the daemon's own trusted window index. Records hold only closed names and counts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventRecords {
    window: u64,
    counts: [u32; 12],
}

impl EventRecords {
    /// The daemon-local window index (monotonic ns / [`DAEMON_EVENT_WINDOW_NS`]).
    pub fn window(&self) -> u64 {
        self.window
    }

    /// The saturated count for `code` in this window.
    pub fn count(&self, code: EventCode) -> u32 {
        self.counts[code.index()]
    }

    /// How many records (nonzero codes) this window persists: at most 12.
    pub fn len(&self) -> usize {
        self.counts.iter().filter(|c| **c != 0).count()
    }

    /// True if no code is nonzero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The nonzero (code, count) records.
    pub fn records(&self) -> impl Iterator<Item = (EventCode, u32)> + '_ {
        EventCode::ALL
            .iter()
            .map(move |code| (*code, self.counts[code.index()]))
            .filter(|(_, count)| *count != 0)
    }
}

/// The daemon's twelve saturating counters for its current local window.
pub(crate) struct DaemonEventWindow {
    open: u64,
    counts: [u32; 12],
    final_taken: bool,
}

impl DaemonEventWindow {
    pub(crate) const fn new(now: u64) -> DaemonEventWindow {
        DaemonEventWindow {
            open: now / DAEMON_EVENT_WINDOW_NS,
            counts: [0; 12],
            final_taken: false,
        }
    }

    /// Folds one valid EVENT frame into the open window (saturating).
    pub(crate) fn add(&mut self, code: EventCode, count: u32) {
        let slot = &mut self.counts[code.index()];
        *slot = slot.saturating_add(count);
    }

    /// At a window boundary: the closed window's records (if any nonzero), once.
    pub(crate) fn roll(&mut self, now: u64) -> Option<EventRecords> {
        let index = now / DAEMON_EVENT_WINDOW_NS;
        if index <= self.open {
            return None;
        }
        let closed = EventRecords {
            window: self.open,
            counts: self.counts,
        };
        self.open = index;
        self.counts = [0; 12];
        if closed.is_empty() {
            None
        } else {
            Some(closed)
        }
    }

    /// The one final bounded summary (the open window's counts), once.
    pub(crate) fn final_summary(&mut self) -> Option<EventRecords> {
        if self.final_taken {
            return None;
        }
        self.final_taken = true;
        let summary = EventRecords {
            window: self.open,
            counts: self.counts,
        };
        self.counts = [0; 12];
        if summary.is_empty() {
            None
        } else {
            Some(summary)
        }
    }
}

/// The proxy's twelve saturating counters, offered at most once per nonzero counter per local
/// one-second window, with snapshot/subtract accounting under the actor (an increment is lost
/// only to intentional saturation).
pub(crate) struct ProxyEventCounters {
    counts: [u32; 12],
    offered: [bool; 12],
    window: u64,
}

impl ProxyEventCounters {
    pub(crate) const fn new(now: u64) -> ProxyEventCounters {
        ProxyEventCounters {
            counts: [0; 12],
            offered: [false; 12],
            window: now / PROXY_EVENT_WINDOW_NS,
        }
    }

    /// One observation of `count` occurrences (a 1025-pair cookie line contributes 1025).
    pub(crate) fn observe(&mut self, code: EventCode, count: u32) {
        let slot = &mut self.counts[code.index()];
        *slot = slot.saturating_add(count);
    }

    /// The next EVENT to offer at `now`: the first nonzero counter not yet offered in this window
    /// (`flush_all` ignores the per-window marks, for the bounded final flush). It snapshots the
    /// counter; [`ProxyEventCounters::commit`] subtracts the snapshot after a whole send.
    pub(crate) fn next_offer(&mut self, now: u64, flush_all: bool) -> Option<OutboundEvent> {
        let index = now / PROXY_EVENT_WINDOW_NS;
        if index > self.window {
            self.window = index;
            self.offered = [false; 12];
        }
        for (i, code) in EventCode::ALL.iter().enumerate() {
            if self.counts[i] != 0 && (flush_all || !self.offered[i]) {
                self.offered[i] = true;
                return OutboundEvent::new(*code, self.counts[i]);
            }
        }
        None
    }

    /// After a whole EVENT send: subtract its snapshot.
    pub(crate) fn commit(&mut self, sent: &OutboundEvent) {
        let slot = &mut self.counts[sent.code().index()];
        *slot = slot.saturating_sub(sent.count());
    }

    /// True if any counter is nonzero (tests and the fuzz interpreter).
    #[cfg(any(test, fuzzing))]
    pub(crate) fn any_nonzero(&self) -> bool {
        self.counts.iter().any(|c| *c != 0)
    }

    /// The current count for `code` (tests and the fuzz interpreter).
    #[cfg(any(test, fuzzing))]
    pub(crate) fn current(&self, code: EventCode) -> u32 {
        self.counts[code.index()]
    }
}
