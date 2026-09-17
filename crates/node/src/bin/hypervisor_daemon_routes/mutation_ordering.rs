//! MUTATION ORDERING — the daemon's outer record-scope writer lock, and the one place its
//! acquisition order is written down.
//!
//! WHY THIS MODULE EXISTS. The outer lock was `outcome_room_routes::ROOM_MUTATION_LOCK`, declared
//! inside an ioi.ai application module that two platform-side modules had to reach into to take
//! it, and its ordering was documented three times — once in the room module, once beside
//! `GOAL_RUN_MUTATION_LOCK`, once beside `DELTA_ADMISSION_LOCK`. Three copies of a lock order is
//! how a lock order drifts. It moved here on 2026-09-17 (R-172 slice S4c) so the room module can
//! be deleted without taking the daemon's write serialization with it, and so the order has ONE
//! owner.
//!
//! WHAT IT SERIALIZES. One writer per data directory over the owner-scoped record critical
//! sections: WorkResult and OutcomeDelta admission, and the GoalRun projection fences and
//! membership compare-and-swap. It was introduced to close the close-vs-admission TOCTOU found in
//! the #72 review (finding 3) — a reader that checked a record's state and a writer that changed
//! it could interleave, so the check and the write are taken under one guard.
//!
//! THE ORDER IS FIXED, and every site obeys it:
//!
//! ```text
//! RECORD_SCOPE_MUTATION_LOCK
//!   -> DELTA_ADMISSION_LOCK        (work_result_routes)
//!   -> INVOCATION_MUTATION_LOCK    (goalrun_routes)
//!     -> GOAL_RUN_MUTATION_LOCK    (goalrun_routes)
//! ```
//!
//! NO `.await` EXECUTES UNDER ANY OF THEM. Every guarded section is synchronous, which is what
//! makes a `std::sync::Mutex` correct here rather than an async one: a future held across an
//! await point under this guard would park the single writer and deadlock the data directory.
//!
//! A POISONED LOCK IS NOT A REFUSAL. Every site recovers with `unwrap_or_else(|poisoned|
//! poisoned.into_inner())`: a panic in one guarded section must not make the data directory
//! permanently unwritable, and the records themselves are content-addressed and head-checked, so
//! a partially-written record is refused by its own admission rather than by a poisoned mutex.

use std::sync::Mutex;

/// The outer writer guard. See the module header for what it serializes and in which order.
pub(crate) static RECORD_SCOPE_MUTATION_LOCK: Mutex<()> = Mutex::new(());
