// Path: crates/validator/src/ante/mod.rs
pub mod service_call;

use crate::ante::service_call::precheck_call_service;
use ioi_tx::system::{nonce, validation};
use ioi_types::app::{BlockTimingParams, BlockTimingRuntime};
use ioi_types::app::{ChainStatus, ChainTransaction, SystemPayload};
use ioi_types::codec;
use ioi_types::error::{StateError, TransactionError};
use ioi_types::keys::{BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY};
use ibc_primitives::Timestamp;
use ioi_api::state::{StateAccessor, StateOverlay};
use ioi_api::transaction::context::TxContext;
use tracing::warn;

/// Unified ante check used by mempool admission and block recheck.
/// This function mirrors the validation and decorator logic from the chain's `process_transaction`.
pub async fn check_tx(
    state: &dyn StateAccessor,
    services: &ioi_api::services::access::ServiceDirectory,
    tx: &ChainTransaction,
    chain_id: ioi_types::app::ChainId,
    next_block_height: u64,
) -> Result<(), TransactionError> {
    // Create a temporary overlay for the simulation.
    let mut overlay = StateOverlay::new(state);

    // Derive signer ID exactly like the chain's execution path.
    let signer_account_id = match tx {
        ChainTransaction::System(s) => s.header.account_id,
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. } => {
                header.account_id
            }
            ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                header.account_id
            }
            ioi_types::app::ApplicationTransaction::UTXO(_) => {
                ioi_types::app::AccountId::default()
            }
        },
    };

    // Deterministic timestamp for pre-check (mirrors execution ordering).
    let last_timestamp_ns: u128 = match state.get(ioi_types::keys::STATUS_KEY)? {
        Some(b) => {
            let status: ChainStatus = ioi_types::codec::from_bytes_canonical(&b)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            // ChainStatus.latest_timestamp is stored in seconds.
            (status.latest_timestamp as u128) * 1_000_000_000u128
        }
        None => 0, // Genesis: pretend last time = 0 ns.
    };

    // Calculate next timestamp deterministically
    let interval_secs = {
        let timing_params_bytes = state.get(BLOCK_TIMING_PARAMS_KEY)?.unwrap_or_default();
        let timing_runtime_bytes = state.get(BLOCK_TIMING_RUNTIME_KEY)?.unwrap_or_default();
        let timing_params: BlockTimingParams =
            codec::from_bytes_canonical(&timing_params_bytes).unwrap_or_default();
        let timing_runtime: BlockTimingRuntime =
            codec::from_bytes_canonical(&timing_runtime_bytes).unwrap_or_default();

        // Ante cannot easily get the parent block, so we use a simplified interval calculation
        // that doesn't rely on parent gas usage. This is acceptable for pre-checks.
        timing_runtime.effective_interval_secs.clamp(
            timing_params.min_interval_secs,
            timing_params.max_interval_secs,
        )
    };

    let next_timestamp_ns =
        last_timestamp_ns.saturating_add((interval_secs as u128) * 1_000_000_000u128);
    let next_timestamp = Timestamp::from_nanoseconds(next_timestamp_ns)
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

    let mut tx_ctx = TxContext {
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

    // 2. Service-level precheck for CallService (ensures ABI or ibc-deps fallback).
    if let ChainTransaction::System(sys) = tx {
        if let SystemPayload::CallService {
            service_id, method, ..
        } = &sys.payload
        {
            let _perm = precheck_call_service(&overlay, service_id, method, tx_ctx.is_internal)?;
        }
    }

    // 3. Run TxDecorators with the critical ibc-deps bypass.
    for svc in services.services_in_deterministic_order() {
        if let Some(decorator) = svc.as_tx_decorator() {
            decorator.ante_handle(&mut overlay, tx, &tx_ctx).await?;
        }
    }

    // 4. Bump nonce in the overlay so subsequent txs in the same batch see the correct next nonce.
    nonce::bump_nonce(&mut overlay, tx)?;

    Ok(())
}
