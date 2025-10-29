// Path: crates/validator/src/ante/mod.rs
pub mod service_call;

use depin_sdk_api::state::{StateAccessor, StateOverlay};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_types::app::{ChainTransaction, SystemPayload};
use depin_sdk_types::error::TransactionError;
use depin_sdk_transaction_models::system::{nonce, validation};
use crate::ante::service_call::precheck_call_service;
use tracing::warn;

/// Unified ante check used by mempool admission and block recheck.
/// This function mirrors the validation and decorator logic from the chain's `process_transaction`.
pub async fn check_tx(
    state: &dyn StateAccessor,
    services: &depin_sdk_api::services::access::ServiceDirectory,
    tx: &ChainTransaction,
    chain_id: depin_sdk_types::app::ChainId,
    next_block_height: u64,
) -> Result<(), TransactionError> {
    // Create a temporary overlay for the simulation.
    let mut overlay = StateOverlay::new(state);

    // Derive signer ID exactly like the chain's execution path.
    let signer_account_id = match tx {
        ChainTransaction::System(s) => s.header.account_id,
        ChainTransaction::Application(a) => match a {
            depin_sdk_types::app::ApplicationTransaction::DeployContract { header, .. } => header.account_id,
            depin_sdk_types::app::ApplicationTransaction::CallContract { header, .. } => header.account_id,
            depin_sdk_types::app::ApplicationTransaction::UTXO(_) => depin_sdk_types::app::AccountId::default(),
        }
    };

    let mut tx_ctx = TxContext {
        block_height: next_block_height,
        chain_id,
        signer_account_id,
        services,
        simulation: true, // This is a pre-check/simulation
        is_internal: false, // User transactions are never internal
    };

    // 1. Core validation: signature and nonce (read-only against the overlay).
    validation::verify_transaction_signature(&overlay, services, tx, &tx_ctx)?;
    nonce::assert_next_nonce(&overlay, tx)?;

    // 2. Service-level precheck for CallService (ensures ABI or svc-ibc fallback).
    if let ChainTransaction::System(sys) = tx {
        if let SystemPayload::CallService { service_id, method, .. } = &sys.payload {
            let _perm = precheck_call_service(&overlay, service_id, method, tx_ctx.is_internal)?;
        }
    }

    // 3. Run TxDecorators with the critical svc-ibc bypass.
    for svc in services.services_in_deterministic_order() {
        if let Some(decorator) = svc.as_tx_decorator() {
            #[cfg(feature = "svc-ibc")]
            if matches!(tx,
                ChainTransaction::System(s)
                    if matches!(&s.payload, SystemPayload::CallService { service_id, method, .. }
                        if service_id == "ibc" && method == "msg_dispatch@v1"))
            {
                warn!(target="ante",
                    "Skipping TxDecorator stage for ibc::msg_dispatch@v1 (svc-ibc, CheckTx)");
            } else {
                decorator.ante_handle(&mut overlay, tx, &tx_ctx).await?;
            }
            #[cfg(not(feature = "svc-ibc"))]
            {
                decorator.ante_handle(&mut overlay, tx, &tx_ctx).await?;
            }
        }
    }

    // 4. Bump nonce in the overlay so subsequent txs in the same batch see the correct next nonce.
    nonce::bump_nonce(&mut overlay, tx)?;

    Ok(())
}