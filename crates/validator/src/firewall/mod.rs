// Path: crates/validator/src/firewall/mod.rs

//! The Agency Firewall: Pre-execution policy enforcement and validation.

/// The policy engine logic for evaluating rules.
pub mod policy;
/// Definitions for ActionRules and policy configuration.
pub mod rules;

use crate::firewall::policy::PolicyEngine;
use ibc_primitives::Timestamp;
use ioi_api::state::namespaced::{NamespacedStateAccess, ReadOnlyNamespacedStateAccess};
use ioi_api::state::{service_namespace_prefix, StateAccess, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_tx::system::{nonce, validation};
use ioi_types::app::{ChainTransaction, SystemPayload};
use ioi_types::error::TransactionError;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;

/// The main firewall entry point.
/// Replaces the old `check_tx` function.
pub async fn enforce_firewall(
    state: &mut dyn StateAccess,
    services: &ioi_api::services::access::ServiceDirectory,
    tx: &ChainTransaction,
    chain_id: ioi_types::app::ChainId,
    next_block_height: u64,
    expected_timestamp_secs: u64,
    skip_stateless_checks: bool,
    is_simulation: bool, // True for mempool/RPC, False for block execution
) -> Result<(), TransactionError> {
    let mut overlay = StateOverlay::new(state);

    // 1. Identify Signer
    let signer_account_id = match tx {
        ChainTransaction::System(s) => s.header.account_id,
        ChainTransaction::Settlement(s) => s.header.account_id,
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                header.account_id
            }
        },
        ChainTransaction::Semantic { header, .. } => header.account_id,
    };

    // 2. Context
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
        simulation: is_simulation,
        is_internal: false,
    };

    // --- LAYER 1: CRYPTOGRAPHIC HARDENING ---
    if !skip_stateless_checks {
        validation::verify_stateless_signature(tx)?;
    }
    validation::verify_stateful_authorization(&overlay, services, tx, &tx_ctx)?;

    // --- LAYER 2: REPLAY PROTECTION ---
    if is_simulation {
        nonce::assert_nonce_at_least(&overlay, tx)?;
    } else {
        nonce::assert_next_nonce(&overlay, tx)?;
    }

    // --- LAYER 3: POLICY ENGINE (The Firewall) ---
    // If this is a System transaction invoking a service, we check permissions.
    // If this is an Agentic transaction, we inspect the ActionRequest.
    if let ChainTransaction::System(sys) = tx {
        // [FIX] Changed `if let` to `let` as SystemPayload currently has only one variant (irrefutable pattern).
        let SystemPayload::CallService {
            service_id, method, ..
        } = &sys.payload;

        // Policy check for service calls
        PolicyEngine::check_service_call(&overlay, service_id, method, false)?;
    }

    // --- LAYER 4: SERVICE DECORATORS (Custom Logic) ---
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

    // --- LAYER 5: STATE MUTATION (Fee/Nonce) ---
    if !is_simulation {
        for (id, decorator) in &decorators {
            let meta_key = active_service_key(id);
            let meta_bytes = overlay.get(&meta_key)?.unwrap();
            let meta: ActiveServiceMeta = ioi_types::codec::from_bytes_canonical(&meta_bytes)?;
            let prefix = service_namespace_prefix(id);
            let mut namespaced_write = NamespacedStateAccess::new(&mut overlay, prefix, &meta);

            decorator
                .write_ante(&mut namespaced_write, tx, &tx_ctx)
                .await?;
        }
        nonce::bump_nonce(&mut overlay, tx)?;
    }

    Ok(())
}
