// Path: crates/transaction_models/src/system/nonce.rs

//! Core, non-optional system logic for transaction nonce management.

use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::app::{AccountId, ChainTransaction, SystemPayload};
use depin_sdk_types::error::TransactionError::{self, NonceMismatch};
use depin_sdk_types::keys::ACCOUNT_NONCE_PREFIX;

// Helper to read u64 from state bytes
fn u64_from_le_bytes(bytes: Option<&Vec<u8>>) -> u64 {
    bytes
        .and_then(|b| b.as_slice().try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn get_tx_nonce_key(account_id: &AccountId) -> Vec<u8> {
    [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat()
}

/// A private helper to extract the account ID and nonce from a transaction, if applicable.
/// Returns None for transaction types that do not use the account-based nonce system.
fn get_tx_details(tx: &ChainTransaction) -> Option<(AccountId, u64)> {
    match tx {
        ChainTransaction::System(sys_tx) => match sys_tx.payload {
            // These system payloads are not signed by a user account and don't use nonces.
            SystemPayload::UpdateAuthorities { .. } | SystemPayload::SubmitOracleData { .. } => {
                None
            }
            // While VerifyForeignReceipt is unsigned, it's replay-protected by its content hash,
            // so we can also exclude it from the nonce system.
            SystemPayload::VerifyForeignReceipt { .. } => None,
            // All other system transactions are signed by a user and must have a valid nonce.
            _ => Some((sys_tx.header.account_id, sys_tx.header.nonce)),
        },
        ChainTransaction::Application(app_tx) => match app_tx {
            depin_sdk_types::app::ApplicationTransaction::DeployContract { header, .. }
            | depin_sdk_types::app::ApplicationTransaction::CallContract { header, .. } => {
                Some((header.account_id, header.nonce))
            }
            // UTXO transactions do not use this account-based nonce system.
            _ => None,
        },
    }
}

/// A core system function to assert that a transaction's nonce is correct.
/// This is a READ-ONLY check.
pub fn assert_next_nonce<S: StateAccessor>(
    state: &S,
    tx: &ChainTransaction,
) -> Result<(), TransactionError> {
    if let Some((account_id, nonce)) = get_tx_details(tx) {
        let key = get_tx_nonce_key(&account_id);
        let current_nonce = u64_from_le_bytes(state.get(&key)?.as_ref());

        if nonce != current_nonce {
            return Err(NonceMismatch {
                expected: current_nonce,
                got: nonce,
            });
        }
    }
    Ok(())
}

/// A core system function to atomically bump a transaction nonce.
/// This is a WRITE operation and should be called after all validation has passed.
pub fn bump_nonce<S: StateAccessor>(
    state: &mut S,
    tx: &ChainTransaction,
) -> Result<(), TransactionError> {
    if let Some((account_id, nonce)) = get_tx_details(tx) {
        let key = get_tx_nonce_key(&account_id);
        // The nonce has already been asserted, so we just write the next value.
        state.insert(&key, &(nonce + 1).to_le_bytes())?;
    }
    Ok(())
}
