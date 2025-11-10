// Path: crates/validator/src/ante/mod.rs
//! Transaction pre-execution logic (ante handlers).

/// Logic for pre-checking `CallService` transactions.
pub mod service_call;

use crate::ante::service_call::precheck_call_service;
use ibc_primitives::Timestamp;
use ioi_api::state::{StateAccess, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_tx::system::{nonce, validation};
use ioi_types::app::{ChainTransaction, SystemPayload};
use ioi_types::error::TransactionError;

/// Unified ante check used by mempool admission and block recheck.
/// This function mirrors the validation and decorator logic from the chain's `process_transaction`
/// and requires an authoritative block timestamp to ensure consistency.
pub async fn check_tx(
    state: &dyn StateAccess,
    services: &ioi_api::services::access::ServiceDirectory,
    tx: &ChainTransaction,
    chain_id: ioi_types::app::ChainId,
    next_block_height: u64,
    expected_timestamp_secs: u64,
) -> Result<(), TransactionError> {
    let mut overlay = StateOverlay::new(state);

    let signer_account_id = match tx {
        ChainTransaction::System(s) => s.header.account_id,
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. } => {
                header.account_id
            }
            ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                header.account_id
            }
            ioi_types::app::ApplicationTransaction::UTXO(_) => ioi_types::app::AccountId::default(),
        },
    };

    // to prevent potential overflows and ensure correct Timestamp creation.
    let next_timestamp_ns = (expected_timestamp_secs as u128)
        .saturating_mul(1_000_000_000u128);
    let next_timestamp = Timestamp::from_nanoseconds(
        next_timestamp_ns
            .try_into() // u128 -> u64
            .map_err(|_| TransactionError::Invalid("Timestamp overflow".to_string()))?,
    )
    .map_err(|e| {
        TransactionError::Invalid(format!("Failed to create timestamp from nanoseconds: {}", e))
    })?;

    let tx_ctx = TxContext {
        block_height: next_block_height,
        block_timestamp: next_timestamp,
        chain_id,
        signer_account_id,
        services,
        simulation: true,   // This is a pre-check/simulation
        is_internal: false, // User transactions are never internal
    };

    // 1. Core validation: signature and nonce (read-only against the overlay).
    validation::verify_transaction_signature(&overlay, services, tx, &tx_ctx)?;
    nonce::assert_next_nonce(&overlay, tx)?;

    // 2. Service-level precheck for CallService.
    if let ChainTransaction::System(sys) = tx {
        if let SystemPayload::CallService {
            service_id, method, ..
        } = &sys.payload
        {
            let _perm = precheck_call_service(&overlay, service_id, method, tx_ctx.is_internal)?;
        }
    }

    // 3. Run TxDecorators.
    for svc in services.services_in_deterministic_order() {
        if let Some(decorator) = svc.as_tx_decorator() {
            decorator.ante_handle(&mut overlay, tx, &tx_ctx).await?;
        }
    }

    // 4. Bump nonce in the overlay so subsequent txs in the same batch see the correct next nonce.
    nonce::bump_nonce(&mut overlay, tx)?;

    Ok(())
}