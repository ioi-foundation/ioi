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
/// This function mirrors the validation and decorator logic from the chain's `process_transaction`
/// and requires an authoritative block timestamp to ensure consistency.
pub async fn check_tx(
    state: &mut dyn StateAccess,
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

    let next_timestamp_ns = (expected_timestamp_secs as u128).saturating_mul(1_000_000_000u128);
    let next_timestamp = Timestamp::from_nanoseconds(
        next_timestamp_ns
            .try_into()
            .map_err(|_| TransactionError::Invalid("Timestamp overflow".to_string()))?,
    )
    .map_err(|e| {
        TransactionError::Invalid(format!(
            "Failed to create timestamp from nanoseconds: {}",
            e
        ))
    })?;

    let tx_ctx = TxContext {
        block_height: next_block_height,
        block_timestamp: next_timestamp,
        chain_id,
        signer_account_id,
        services,
        simulation: true,
        is_internal: false,
    };

    // 1. Phase 1: Read-Only Validation
    // Pass immutable reference to overlay to satisfy StateAccess
    validation::verify_transaction_signature(&overlay, services, tx, &tx_ctx)?;
    nonce::assert_next_nonce(&overlay, tx)?;

    // 2. Service-level precheck for CallService.
    if let ChainTransaction::System(sys) = tx {
        let SystemPayload::CallService {
            service_id, method, ..
        } = &sys.payload;
        let _perm = precheck_call_service(&overlay, service_id, method, tx_ctx.is_internal)?;
    }

    // 3. Run TxDecorators (Validation Phase)
    // We collect decorators first to avoid borrowing issues
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
        // Use ReadOnly wrapper to enforce immutability
        let namespaced_view = ReadOnlyNamespacedStateAccess::new(&overlay, prefix, &meta);

        decorator
            .validate_ante(&namespaced_view, tx, &tx_ctx)
            .await?;
    }

    // 4. Phase 2: Writes (Mutable)
    // Run TxDecorators (Write Phase)
    for (id, decorator) in &decorators {
        // We need to re-fetch meta or clone it. Since we are inside an async loop, re-fetching is safer/easier.
        let meta_key = active_service_key(id);
        // Safe to unwrap here as it was checked in Phase 1
        let meta_bytes = overlay.get(&meta_key)?.unwrap();
        let meta: ActiveServiceMeta = ioi_types::codec::from_bytes_canonical(&meta_bytes)?;

        let prefix = service_namespace_prefix(id);
        let mut namespaced_write = NamespacedStateAccess::new(&mut overlay, prefix, &meta);

        decorator
            .write_ante(&mut namespaced_write, tx, &tx_ctx)
            .await?;
    }

    // 5. System Writes (Nonce Bump)
    nonce::bump_nonce(&mut overlay, tx)?;

    Ok(())
}