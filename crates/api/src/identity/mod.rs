// Path: crates/api/src/identity/mod.rs

//! Defines the `CredentialsView` trait for decoupled identity lookups.

use crate::services::BlockchainService;
use crate::state::StateAccess;
use ioi_types::app::{AccountId, Credential};
use ioi_types::error::TransactionError;

/// A read-only view of an account's cryptographic credentials.
///
/// This trait is implemented by services like `IdentityHub` and used by core
/// transaction validation logic to look up keys without a direct dependency.
pub trait CredentialsView: BlockchainService {
    /// Fetches the active (index 0) and staged (index 1) credentials for an account.
    ///
    /// An empty array `[None, None]` indicates the account has not been bootstrapped.
    fn get_credentials(
        &self,
        state: &dyn StateAccess,
        account_id: &AccountId,
    ) -> Result<[Option<Credential>; 2], TransactionError>;

    /// Returns the chain's policy on whether to accept signatures from a new,
    /// staged key during its grace period before it becomes active.
    fn accept_staged_during_grace(&self) -> bool {
        true
    }
}
