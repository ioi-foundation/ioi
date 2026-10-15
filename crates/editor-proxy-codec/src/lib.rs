//! THE DAEMON <-> EDITOR/PREVIEW PROXY IPC, version 2 (BUILD-DELTA #85, DESIGN v2 (1)-(3)): a
//! TRUST BOUNDARY, as pure code.
//!
//! The proxy is its own sandboxed OS process (one per lease) that may be fully compromised. This
//! crate is everything the daemon accepts from it and everything the proxy accepts from the
//! daemon:
//!
//! - **Frames** ([`wire`] constants): `"IP" | version:u8=2 | kind:u8 | body_len:u16 LE |
//!   reserved:u16 LE=0 | body`, at most [`MAX_FRAME`] bytes INCLUDING the 8-byte header, one frame
//!   per AF_UNIX SOCK_SEQPACKET message, every body length exact per kind. No version-1 path.
//! - **Directional digests** (DESIGN v2 (1)): the proxy builds [`OutboundAdmit`]s from
//!   [`Sha256Digest`]s (hash-only, `ioi-proxy-digest`); the daemon decodes [`InboundAdmit`]s
//!   holding [`CompareOnlyDigest`]s it can only COMPARE, in constant time, with a stored lowercase
//!   hex hash. [`encode_p2d`] accepts only outbound messages. The canonical re-encoding property
//!   is tested by a `cfg(test)` encoder inside this crate's unit tests, never a production API.
//! - **Two state machines** (DESIGN v2 (2)): [`DaemonSession`] and [`ProxySession`], each one
//!   actor's complete transition table over explicit inputs (a monotonic clock, receives with
//!   MSG_TRUNC / MSG_CTRUNC and an ancillary summary, prepared sends and their results, F0
//!   results, local termination, transport end). Every operation not legal in its phase refuses;
//!   the FIRST refusal LATCHES (a fieldless [`IpcRefusal`], chosen by a fixed precedence, one
//!   cleanup request, then only [`DaemonStep::Terminal`] / [`ProxyStep::Terminal`]).
//! - **Candidate cap and event aggregation** (DESIGN v2 (3)): [`LeaseCandidates`] counts candidate
//!   OCCURRENCES and refuses the ninth ([`TooManyLeaseCandidates`]) before any IPC; event counts
//!   are saturating per-window aggregates on both sides, so ordinary parser output never kills a
//!   lease and the daemon persists at most one record per code per window.
//!
//! The CLAIM is narrow: restricted use after trusted decoding. It is not remote hash provenance
//! and not prevention of every information transfer (a compromised proxy can encode information
//! in allowed fields or timing). Pure: no I/O, no unsafe code, no allocation (`no_std` without
//! `alloc`), no cargo features. File descriptors are an opaque handle type `H` owned by the trusted
//! adapter; their kernel facts arrive as an adapter-validated [`FdFacts`] summary; a refused
//! receive DROPS every handle it was given (the adapter's `H` closes on drop).
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(any(test, fuzzing))]
extern crate std;

mod candidates;
mod daemon;
mod digest;
mod events;
mod fds;
mod limits;
mod pending;
mod proxy;
mod refusal;
mod types;
pub mod wire;

/// The sequence interpreter and seed builders behind the three fuzz targets and the stable corpus
/// replay (compiled only under `cfg(test)` or `cfg(fuzzing)`; it holds no encoder of inbound values).
#[cfg(any(test, fuzzing))]
pub mod fuzz_support;

#[cfg(test)]
mod tests;

pub use candidates::{LeaseCandidates, TooManyLeaseCandidates};
pub use daemon::{
    DaemonConfig, DaemonInput, DaemonPhase, DaemonSession, DaemonStep, DaemonStepKind, VerdictSpec,
    WelcomeSpec,
};
pub use digest::CompareOnlyDigest;
pub use events::{EventRecords, DAEMON_EVENT_WINDOW_NS, PROXY_EVENT_WINDOW_NS};
pub use fds::{FdBatch, FdFacts, ReceivedFd, SocketClass};
pub use ioi_proxy_digest::Sha256Digest;
pub use limits::{
    COMPLETED_FIFO, MAX_FRAMES_PER_BATCH, MAX_PENDING, RATE_MAX_ADMITS, RATE_WINDOW_NS,
    SEND_DEADLINE_NS, STARTUP_DEADLINE_NS,
};
pub use proxy::{
    AdmitBlocked, ProxyConfig, ProxyInput, ProxyPhase, ProxySession, ProxyStep, ProxyStepKind,
};
pub use refusal::IpcRefusal;
pub use types::{
    AdmissionId, EventCode, F0Result, ModeKind, OpId, Outcome, Purpose, SendOutcome, ServingMode,
    StopReason,
};
pub use wire::{
    decode_d2p, decode_p2d, encode_p2d, D2pRecv, EncodeP2d, Frame, InboundAdmit, InboundD2p,
    InboundEvent, InboundP2d, InboundWelcome, OutboundAdmit, OutboundEvent, OutboundP2d, Outgoing,
    P2dRecv, MAX_FRAME,
};
