// Path: crates/transaction_models/src/system/nonce.rs
//! Core, non-optional system logic for transaction nonce management.

use depin_sdk_api::state::StateManager;
use depin_sdk_types::app::{AccountId, ChainTransaction, SystemPayload};
use depin_sdk_types::error::TransactionError;
use depin_sdk_types::keys::ACCOUNT_NONCE_PREFIX;

// Helper to read u64 from state bytes
fn u64_from_le_bytes(bytes: Option<&Vec<u8>>) -> u64 {
    bytes
        .and_then(|b| b.as_slice().try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn get_tx_nonce_key(account_id: &AccountId) -> Vec<u8> {
    // --- FIX: Use .as_ref() to convert AccountId to &[u8] ---
    [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat()
}

/// A core system function to check and atomically bump a transaction nonce.
/// This is not an optional service and is a required first step in validation.
pub fn check_and_bump_tx_nonce<S: StateManager + ?Sized>(
    state: &mut S,
    tx: &ChainTransaction,
) -> Result<(), TransactionError> {
    let (account_id, nonce) = match tx {
        ChainTransaction::System(sys_tx) => match sys_tx.payload {
            SystemPayload::VerifyForeignReceipt { .. }
            | SystemPayload::UpdateAuthorities { .. }
            | SystemPayload::SubmitOracleData { .. } => return Ok(()),
            _ => (sys_tx.header.account_id, sys_tx.header.nonce),
        },
        ChainTransaction::Application(app_tx) => match app_tx {
            depin_sdk_types::app::ApplicationTransaction::DeployContract { header, .. }
            | depin_sdk_types::app::ApplicationTransaction::CallContract { header, .. } => {
                (header.account_id, header.nonce)
            }
            // UTXO transactions do not use this account-based nonce system.
            _ => return Ok(()),
        },
    };

    let key = get_tx_nonce_key(&account_id);
    let current_nonce = u64_from_le_bytes(state.get(&key)?.as_ref());

    if nonce != current_nonce {
        return Err(TransactionError::Invalid(format!(
            "Nonce mismatch for account {}. Expected {}, got {}",
            hex::encode(account_id),
            current_nonce,
            nonce
        )));
    }

    // Atomically bump the nonce in the state
    state.insert(&key, &(current_nonce + 1).to_le_bytes())?;
    Ok(())
}
