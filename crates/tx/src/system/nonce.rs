// Path: crates/tx/src/system/nonce.rs

//! Core, non-optional system logic for transaction nonce management.

use ioi_api::state::StateAccess;
use ioi_types::app::{AccountId, ChainTransaction};
use ioi_types::error::TransactionError::{self, NonceMismatch};
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use tracing::warn;

/// Generates the canonical state key for an account's nonce.
fn get_tx_nonce_key(account_id: &AccountId) -> Vec<u8> {
    [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat()
}

/// A private helper to extract the account ID and nonce from a transaction, if applicable.
fn get_tx_details(tx: &ChainTransaction) -> Option<(AccountId, u64)> {
    match tx {
        ChainTransaction::System(sys_tx) => Some((sys_tx.header.account_id, sys_tx.header.nonce)),
        // [FIX] Added Settlement
        ChainTransaction::Settlement(settle_tx) => {
            Some((settle_tx.header.account_id, settle_tx.header.nonce))
        }
        ChainTransaction::Application(app_tx) => match app_tx {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                Some((header.account_id, header.nonce))
            }
            // UTXO removed from types
            _ => None,
        },
        ChainTransaction::Semantic { .. } => None,
    }
}

/// Strictly asserts that a transaction's nonce is exactly the next expected value.
pub fn assert_next_nonce<S: StateAccess + ?Sized>(
    state: &S,
    tx: &ChainTransaction,
) -> Result<(), TransactionError> {
    if let Some((account_id, nonce)) = get_tx_details(tx) {
        let key = get_tx_nonce_key(&account_id);

        let expected: u64 = match state.get(&key)? {
            Some(b) => ioi_types::codec::from_bytes_canonical(&b)
                .map_err(TransactionError::Deserialization)?,
            None => {
                if nonce == 0 {
                    warn!(
                        target: "ante",
                        "nonce record missing for signer {}; allowing nonce=0 for bootstrap",
                        hex::encode(account_id.as_ref())
                    );
                    0
                } else {
                    return Err(TransactionError::Invalid(
                        "Nonce record not found in state".into(),
                    ));
                }
            }
        };

        if nonce != expected {
            return Err(NonceMismatch {
                expected,
                got: nonce,
            });
        }
    }
    Ok(())
}

/// Relaxed nonce assertion that allows nonces greater than or equal to the current state.
pub fn assert_nonce_at_least<S: StateAccess + ?Sized>(
    state: &S,
    tx: &ChainTransaction,
) -> Result<(), TransactionError> {
    if let Some((account_id, nonce)) = get_tx_details(tx) {
        let key = get_tx_nonce_key(&account_id);

        let current_state_nonce: u64 = match state.get(&key)? {
            Some(b) => ioi_types::codec::from_bytes_canonical(&b)
                .map_err(TransactionError::Deserialization)?,
            None => 0,
        };

        if nonce < current_state_nonce {
            return Err(NonceMismatch {
                expected: current_state_nonce,
                got: nonce,
            });
        }
    }
    Ok(())
}

/// Atomically increments the transaction nonce for the signer in the state.
pub fn bump_nonce<S: StateAccess + ?Sized>(
    state: &mut S,
    tx: &ChainTransaction,
) -> Result<(), TransactionError> {
    if let Some((account_id, nonce)) = get_tx_details(tx) {
        let key = get_tx_nonce_key(&account_id);
        state.insert(&key, &(nonce + 1).to_le_bytes())?;
    }
    Ok(())
}
