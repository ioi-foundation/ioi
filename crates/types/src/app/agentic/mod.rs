// Path: crates/types/src/app/agentic/mod.rs
//! Core data structures for the Agentic Economy and Semantic Consensus.
//!
//! This module defines the primitives for:
//! - **Market**: Assets, Manifests, and Licenses.
//! - **Execution**: Runtime traces, history, and proofs.
//! - **Knowledge**: Static context and UI lenses.
//! - **Security**: Firewall policies.
//! - **Tools**: Native driver capabilities.

/// Runtime artifacts like execution traces, chat history, and committee certificates.
pub mod execution;

/// Static knowledge structures, including UI lenses and semantic facts.
pub mod knowledge;

/// Market definitions for assets, manifests, and licenses.
pub mod market;

/// Security policy definitions for the Agency Firewall.
pub mod security;

/// Definitions for native driver tools and capabilities.
pub mod tools;

/// Typed web retrieval evidence bundles (sources, quotes, provenance).
pub mod web;

// Re-export all types to maintain a flat API surface for consumers
pub use execution::*;
pub use knowledge::*;
pub use market::*;
pub use security::*;
pub use tools::*;
pub use web::*;
