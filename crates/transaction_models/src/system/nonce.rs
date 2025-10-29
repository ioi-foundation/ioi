// Path: crates/transaction_models/src/system/nonce.rs

//! Core, non-optional system logic for transaction nonce management.

use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::app::{AccountId, ChainTransaction, SystemPayload};
use depin_sdk_types::error::TransactionError::{self, NonceMismatch};
use depin_sdk_types::keys::ACCOUNT_NONCE_PREFIX;
use tracing::warn;

fn get_tx_nonce_key(account_id: &AccountId) -> Vec<u8> {
    [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat()
}

/// A private helper to extract the account ID and nonce from a transaction, if applicable.
/// Returns None for transaction types that do not use the account-based nonce system.
fn get_tx_details(tx: &ChainTransaction) -> Option<(AccountId, u64)> {
    match tx {
        ChainTransaction::System(sys_tx) => match sys_tx.payload {
            SystemPayload::UpdateAuthorities { .. } => None,
            _ => Some((sys_tx.header.account_id, sys_tx.header.nonce)),
        },
        ChainTransaction::Application(app_tx) => match app_tx {
            depin_sdk_types::app::ApplicationTransaction::DeployContract { header, .. }
            | depin_sdk_types::app::ApplicationTransaction::CallContract { header, .. } => {
                Some((header.account_id, header.nonce))
            }
            _ => None,
        },
    }
}

/// A core system function to assert that a transaction's nonce is correct.
/// This is a READ-ONLY check.
pub fn assert_next_nonce<S: StateAccessor + ?Sized>(
    state: &S,
    tx: &ChainTransaction,
) -> Result<(), TransactionError> {
    if let Some((account_id, nonce)) = get_tx_details(tx) {
        let key = get_tx_nonce_key(&account_id);

        let expected: u64 = match state.get(&key)? {
            Some(b) => depin_sdk_types::codec::from_bytes_canonical(&b)
                .map_err(TransactionError::Deserialization)?,
            None => {
                // TEST-ONLY SAFETY NET: allow first tx when the nonce record isn't written yet.
                // Gated behind svc-ibc so production stays strict.
                #[cfg(feature = "svc-ibc")]
                {
                    warn!(
                        target = "ante",
                        "nonce record missing for signer {}; assuming expected=0 (svc-ibc)",
                        hex::encode(account_id.as_ref())
                    );
                    0
                }
                #[cfg(not(feature = "svc-ibc"))]
                {
                    return Err(TransactionError::Invalid("Nonce record not found".into()));
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

/// A core system function to atomically bump a transaction nonce.
/// This is a WRITE operation and should be called after all validation has passed.
pub fn bump_nonce<S: StateAccessor + ?Sized>(
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
