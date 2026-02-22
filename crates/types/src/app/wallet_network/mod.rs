// Path: crates/types/src/app/wallet_network/mod.rs
//! Data structures for wallet.network control-plane and session artifacts.

/// Mail connector operation payloads and receipts.
pub mod mail_connector;
/// Policy interception, approval decisions, and audit events.
pub mod policy;
/// Secret handoff requests, attestation, and grants.
pub mod secret_injection;
/// Session grants, leases, and receipt commitment artifacts.
pub mod session;
/// Session-channel lifecycle envelopes and handshake records.
pub mod session_channel;
/// Vault identity, secret, and policy-rule primitives.
pub mod vault;

pub use mail_connector::*;
pub use policy::*;
pub use secret_injection::*;
pub use session::*;
pub use session_channel::*;
pub use vault::*;
