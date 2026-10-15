//! The bounded pending map (at most 64 unanswered admissions) and the FIFO of the 64 most recently
//! completed ids (DESIGN v2 (2), "Admission IDs, windows and verdict legality"). No digest is kept.

use crate::limits::{COMPLETED_FIFO, MAX_PENDING};
use crate::types::{AdmissionId, Purpose};

#[derive(Clone, Copy)]
pub(crate) struct Entry {
    pub(crate) id: AdmissionId,
    pub(crate) purpose: Purpose,
    pub(crate) sending: bool,
    pub(crate) deadline: u64,
}

pub(crate) struct PendingMap {
    slots: [Option<Entry>; MAX_PENDING],
    len: usize,
}

impl PendingMap {
    pub(crate) const fn new() -> PendingMap {
        PendingMap {
            slots: [None; MAX_PENDING],
            len: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_full(&self) -> bool {
        self.len == MAX_PENDING
    }

    /// Inserts a new entry (the caller checked `!is_full()` and that the id is new).
    pub(crate) fn insert(&mut self, entry: Entry) -> bool {
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.len += 1;
                return true;
            }
        }
        false
    }

    pub(crate) fn get_mut(&mut self, id: AdmissionId) -> Option<&mut Entry> {
        self.slots.iter_mut().flatten().find(|entry| entry.id == id)
    }

    pub(crate) fn remove(&mut self, id: AdmissionId) -> Option<Entry> {
        for slot in self.slots.iter_mut() {
            if matches!(slot, Some(entry) if entry.id == id) {
                self.len -= 1;
                return slot.take();
            }
        }
        None
    }

    /// True if any entry's deadline has passed (`now >= deadline`).
    pub(crate) fn any_expired(&self, now: u64) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|entry| now >= entry.deadline)
    }

    pub(crate) fn clear(&mut self) {
        self.slots = [None; MAX_PENDING];
        self.len = 0;
    }

    /// The oldest-inserted id still pending and not sending (tests and the fuzz interpreter).
    #[cfg(any(test, fuzzing))]
    pub(crate) fn any_answerable(&self) -> Option<AdmissionId> {
        self.slots
            .iter()
            .flatten()
            .filter(|entry| !entry.sending)
            .map(|entry| entry.id)
            .min()
    }
}

pub(crate) struct CompletedFifo {
    ids: [u32; COMPLETED_FIFO],
    len: usize,
    next: usize,
}

impl CompletedFifo {
    pub(crate) const fn new() -> CompletedFifo {
        CompletedFifo {
            ids: [0; COMPLETED_FIFO],
            len: 0,
            next: 0,
        }
    }

    /// Records a completed id, evicting the oldest when full.
    pub(crate) fn push(&mut self, id: AdmissionId) {
        self.ids[self.next] = id.get();
        self.next = (self.next + 1) % COMPLETED_FIFO;
        if self.len < COMPLETED_FIFO {
            self.len += 1;
        }
    }

    pub(crate) fn contains(&self, id: AdmissionId) -> bool {
        self.ids[..self.len].contains(&id.get())
    }

    /// The most recently completed id (tests and the fuzz interpreter).
    #[cfg(any(test, fuzzing))]
    pub(crate) fn last(&self) -> Option<AdmissionId> {
        if self.len == 0 {
            None
        } else {
            let at = (self.next + COMPLETED_FIFO - 1) % COMPLETED_FIFO;
            Some(AdmissionId::from_raw(self.ids[at]))
        }
    }
}
