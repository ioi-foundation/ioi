// Path: crates/tx/src/system/nonce.rs

//! Core, non-optional system logic for transaction nonce management.

use ioi_api::state::StateAccess;
use ioi_types::app::{AccountId, ChainTransaction};
use ioi_types::error::TransactionError::{self, NonceMismatch};
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use tracing::warn;

fn get_tx_nonce_key(account_id: &AccountId) -> Vec<u8> {
    [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat()
}

/// A private helper to extract the account ID and nonce from a transaction, if applicable.
/// Returns None for transaction types that do not use the account-based nonce system.
fn get_tx_details(tx: &ChainTransaction) -> Option<(AccountId, u64)> {
    match tx {
        ChainTransaction::System(sys_tx) => {
            // After refactoring, all SystemTransactions are CallService and are signed.
            // The UpdateAuthorities special case is gone.
            Some((sys_tx.header.account_id, sys_tx.header.nonce))
        }
        ChainTransaction::Application(app_tx) => match app_tx {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                Some((header.account_id, header.nonce))
            }
            _ => None,
        },
        // [FIX] Semantic transactions are signed by a committee, not a single account with a nonce.
        // They effectively bypass the standard nonce check because their replay protection
        // is provided by the CommitteeCertificate (epoch + committee_id).
        ChainTransaction::Semantic { .. } => None,
    }
}

/// A core system function to assert that a transaction's nonce is correct.
/// This is a READ-ONLY check.
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
                // If the nonce record doesn't exist, it must be the account's first transaction (nonce 0).
                if nonce == 0 {
                    warn!(
                        target = "ante",
                        "nonce record missing for signer {}; allowing nonce=0 for bootstrap",
                        hex::encode(account_id.as_ref())
                    );
                    0
                } else {
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
pub fn bump_nonce<S: StateAccess + ?Sized>(
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