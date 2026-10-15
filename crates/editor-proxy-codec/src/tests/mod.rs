//! The codec's unit tests (cfg(test) only). Named assertion families (DESIGN v2 (1)-(3)):
//!
//! - T-DIGEST (compare-only half): `digest.rs`.
//! - T-CANONICAL (the test-only encoder; every accepted frame re-encodes byte for byte): `canonical.rs`.
//! - decoder layout, field refusals and precedence pairs: `decode.rs`.
//! - T-SESSION (the table-driven reference model of both machines): `session.rs`.
//! - T-LIMITS, T-TIME, T-SEND, T-VERDICT: `limits.rs`.
//! - T-LATCH: `latch.rs`.
//! - T-D2P (pure: descriptor facts and closure on rejection): `d2p.rs`.
//! - T-EVENT and T-CANDIDATES (U1's part): `events.rs`.
//! - the stable corpus replay and the named fuzz seeds: `replay.rs`.
//! - T-SHAPE (the ADMIT digest-count limits by purpose and mode, Codex r1 MAJOR 1): `shape.rs`.

mod canonical;
mod d2p;
mod decode;
mod digest;
mod events;
mod latch;
mod limits;
mod replay;
mod session;
mod shape;
mod support;
