// Path: crates/core/src/state/manager.rs

use crate::error::StateError;
use crate::state::StateTree;

/// State manager interface for the DePIN SDK.
///
/// `StateManager` is a higher-level abstraction that must also be a `StateTree`.
/// It provides all the same core methods as `StateTree` (via inheritance) and
/// adds batching capabilities.
pub trait StateManager: StateTree {
    // REMOVED: All redundant associated types and method signatures from StateTree are gone.
    // They are inherited automatically.

    /// Set multiple key-value pairs in a single batch operation.
    /// This is now a required method for any implementor of StateManager.
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError>;

    /// Get multiple values by keys in a single batch operation.
    /// This is now a required method.
    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError>;
}