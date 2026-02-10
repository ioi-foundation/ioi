// Path: crates/scs/src/lib.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

//! # IOI Sovereign Context Substrate (SCS)
//!
//! The SCS is the "Brain" of an IOI Agent. It is a verifiable, append-only
//! storage engine derived from the Memvid format (`.mv2`), adapted for the
//! rigorous security requirements of the Internet of Intelligence.
//!
//! ## Key Features
//!
//! *   **Verifiable Memory:** Uses `mHNSW` (Merkelized Hierarchical Navigable
//!     Small World) indices to provide cryptographic "Proof of Retrieval."
//!     An agent cannot "lie by omission" about what it remembers.
//!
//! *   **Time-Travel Debugging:** Stores a linear timeline of "Frames"
//!     (Observations + Actions), allowing deterministic replay and debugging
//!     of agent behavior at any block height.
//!
//! *   **Privacy-First:** Supports "Scrub-on-Export." Data is stored raw locally
//!     but rigorously redacted via the Semantic Firewall before leaving the
//!     user's device.
//!
//! *   **Zero-Copy Access:** Designed for memory-mapped I/O, allowing
//!     instantaneous loading of massive context windows into the Workload container.

pub mod format;
pub mod index;
pub mod scrubber;
pub mod store;

// Re-export primary types for consumer ergonomics
// [FIX] Added RetentionClass to re-exports
pub use format::{Frame, FrameId, FrameType, RetentionClass, ScsHeader};
pub use index::{RetrievalProof, VectorIndex};
pub use store::{SovereignContextStore, StoreConfig};

/// The standard file extension for SCS containers.
pub const SCS_FILE_EXTENSION: &str = "scs";

/// The magic bytes identifying an IOI-SCS file.
/// Distinct from Memvid to prevent confusion with non-verifiable files.
pub const SCS_MAGIC: &[u8; 8] = b"IOI-SCS!";
