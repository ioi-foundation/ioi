// Path: crates/validator/src/ante/mod.rs

//! Transaction pre-execution logic (ante handlers).

/// Logic for pre-checking `CallService` transactions.
pub mod service_call;

use crate::ante::service_call::precheck_call_service;
use ibc_primitives::Timestamp;
use ioi_api::state::namespaced::{NamespacedStateAccess, ReadOnlyNamespacedStateAccess};
use ioi_api::state::{service_namespace_prefix, StateAccess, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_tx::system::{nonce, validation};
use ioi_types::app::{ChainTransaction, SystemPayload};
use ioi_types::error::TransactionError;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;

/// Unified ante check used by mempool admission and block recheck.
///
/// This function mirrors the validation and decorator logic from the chain's `process_transaction`.
///
/// # Arguments
/// * `skip_stateless_checks`: If true, assumes signatures have already been verified (e.g. by a batch verifier).
/// * `allow_future_nonce`: If true, allows nonces higher than the current state (Mempool mode). 
///    In this mode, state mutations (Phase 2) are skipped to prevent inconsistent simulations.
pub async fn check_tx(
    state: &mut dyn StateAccess,
    services: &ioi_api::services::access::ServiceDirectory,
    tx: &ChainTransaction,
    chain_id: ioi_types::app::ChainId,
    next_block_height: u64,
    expected_timestamp_secs: u64,
    skip_stateless_checks: bool,
    allow_future_nonce: bool,
) -> Result<(), TransactionError> {
    let mut overlay = StateOverlay::new(state);

    // 1. Identify the Signer
    let signer_account_id = match tx {
        ChainTransaction::System(s) => s.header.account_id,
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                header.account_id
            }
            ioi_types::app::ApplicationTransaction::UTXO(_) => ioi_types::app::AccountId::default(),
        },
        ChainTransaction::Semantic { header, .. } => header.account_id,
    };

    // 2. Construct Execution Context
    let next_timestamp_ns = (expected_timestamp_secs as u128).saturating_mul(1_000_000_000u128);
    let next_timestamp = Timestamp::from_nanoseconds(
        next_timestamp_ns
            .try_into()
            .map_err(|_| TransactionError::Invalid("Timestamp overflow".to_string()))?,
    );

    let tx_ctx = TxContext {
        block_height: next_block_height,
        block_timestamp: next_timestamp,
        chain_id,
        signer_account_id,
        services,
        simulation: true,
        is_internal: false,
    };

    // --- PHASE 1: READ-ONLY VALIDATION ---

    // 1.1 Cryptographic Signatures
    if !skip_stateless_checks {
        validation::verify_stateless_signature(tx)?;
    }
    validation::verify_stateful_authorization(&overlay, services, tx, &tx_ctx)?;

    // 1.2 Nonce Assertion
    if allow_future_nonce {
        // For mempool admission: Allow pipelining nonces (e.g. 5, 6, 7)
        nonce::assert_nonce_at_least(&overlay, tx)?;
    } else {
        // For block execution: Enforce strict sequential order
        nonce::assert_next_nonce(&overlay, tx)?;
    }

    // 1.3 Service-level precheck for System Transactions
    if let ChainTransaction::System(sys) = tx {
        let SystemPayload::CallService {
            service_id, method, ..
        } = &sys.payload;
        let _perm = precheck_call_service(&overlay, service_id, method, tx_ctx.is_internal)?;
    }

    // 1.4 Run TxDecorators (Validation Mode)
    let decorators: Vec<(&str, &dyn ioi_api::transaction::decorator::TxDecorator)> = services
        .services_in_deterministic_order()
        .filter_map(|s| s.as_tx_decorator().map(|d| (s.id(), d)))
        .collect();

    for (id, decorator) in &decorators {
        let meta_key = active_service_key(id);
        let meta_bytes = overlay.get(&meta_key)?.ok_or_else(|| {
            TransactionError::Unsupported(format!("Service '{}' is not active", id))
        })?;
        let meta: ActiveServiceMeta = ioi_types::codec::from_bytes_canonical(&meta_bytes)?;

        let prefix = service_namespace_prefix(id);
        let namespaced_view = ReadOnlyNamespacedStateAccess::new(&overlay, prefix, &meta);

        decorator
            .validate_ante(&namespaced_view, tx, &tx_ctx)
            .await?;
    }

    // --- PHASE 2: STATE MUTATION (Writes) ---
    
    // We only simulate writes if we are NOT in mempool admission mode.
    // If allow_future_nonce is true, we might be missing intermediate transactions,
    // making a full simulation of write-effects (like fee deduction) inaccurate.
    if !allow_future_nonce {
        for (id, decorator) in &decorators {
            let meta_key = active_service_key(id);
            let meta_bytes = overlay.get(&meta_key)?.unwrap(); // Verified in Phase 1
            let meta: ActiveServiceMeta = ioi_types::codec::from_bytes_canonical(&meta_bytes)?;

            let prefix = service_namespace_prefix(id);
            let mut namespaced_write = NamespacedStateAccess::new(&mut overlay, prefix, &meta);

            decorator
                .write_ante(&mut namespaced_write, tx, &tx_ctx)
                .await?;
        }

        // Increment the nonce in the state overlay.
        nonce::bump_nonce(&mut overlay, tx)?;
    }

    Ok(())
}