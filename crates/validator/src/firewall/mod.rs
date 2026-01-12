// Path: crates/validator/src/firewall/mod.rs

//! The Agency Firewall: Pre-execution policy enforcement and validation.

/// The inference engine interface for classification.
pub mod inference;
/// The policy engine logic.
pub mod policy;
/// Rules and policy configuration.
pub mod rules;
/// Policy Synthesizer for Ghost Mode.
pub mod synthesizer;

use crate::firewall::policy::PolicyEngine;
use crate::firewall::rules::Verdict;
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_services::agentic::scrubber::SemanticScrubber;

use ibc_primitives::Timestamp;
use ioi_api::state::namespaced::{NamespacedStateAccess, ReadOnlyNamespacedStateAccess};
use ioi_api::state::{service_namespace_prefix, StateAccess, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_tx::system::{nonce, validation};
// [FIX] Removed unused ActionRequest import
use ioi_types::app::{action::ApprovalToken, ChainTransaction, SystemPayload}; 
use ioi_types::error::TransactionError;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;
use std::sync::Arc;

/// The main firewall entry point.
pub async fn enforce_firewall(
    state: &mut dyn StateAccess,
    services: &ioi_api::services::access::ServiceDirectory,
    tx: &ChainTransaction,
    chain_id: ioi_types::app::ChainId,
    next_block_height: u64,
    expected_timestamp_secs: u64,
    skip_stateless_checks: bool,
    is_simulation: bool,
    safety_model: Arc<dyn LocalSafetyModel>,
) -> Result<(), TransactionError> {
    let mut overlay = StateOverlay::new(state);

    // [FIX] Use underscore to suppress unused warning, as scrubber instantiation has side effects (loading model) or is reserved for future use.
    let _scrubber = SemanticScrubber::new(safety_model.clone());

    // 1. Identify Signer
    // [FIX] Use underscore for unused session_auth
    let (signer_account_id, _session_auth) = match tx {
        ChainTransaction::System(s) => (s.header.account_id, s.header.session_auth.as_ref()),
        ChainTransaction::Settlement(s) => (s.header.account_id, s.header.session_auth.as_ref()),
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                (header.account_id, header.session_auth.as_ref())
            }
        },
        ChainTransaction::Semantic { header, .. } => {
            (header.account_id, header.session_auth.as_ref())
        }
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

    // --- LAYER 3: POLICY ENGINE & SEMANTIC SCRUBBING ---
    if let ChainTransaction::System(sys) = tx {
        let SystemPayload::CallService {
            service_id,
            method,
            params,
        } = &sys.payload;

        PolicyEngine::check_service_call(&overlay, service_id, method, false)?;

        if service_id == "agentic" || service_id == "compute_market" {
            let rules = crate::firewall::rules::ActionRules::default();

            let dummy_request = ioi_types::app::ActionRequest {
                target: ioi_types::app::ActionTarget::Custom(method.clone()),
                params: params.clone(),
                context: ioi_types::app::ActionContext {
                    agent_id: "unknown".into(),
                    session_id: None,
                    window_id: None,
                },
                nonce: 0,
            };

            let approval_token: Option<ApprovalToken> = None;

            let verdict = PolicyEngine::evaluate(
                &rules,
                &dummy_request,
                &safety_model,
                approval_token.as_ref(),
            )
            .await;

            match verdict {
                Verdict::Allow => {}
                Verdict::Block => {
                    return Err(TransactionError::Invalid("Blocked by Policy".into()));
                }
                Verdict::RequireApproval => {
                    let req_hash = hex::encode(dummy_request.hash());
                    return Err(TransactionError::PendingApproval(req_hash));
                }
            }

            if let Ok(input_str) = std::str::from_utf8(params) {
                let classification = safety_model
                    .classify_intent(input_str)
                    .await
                    .unwrap_or(ioi_api::vm::inference::SafetyVerdict::Safe);
                if let ioi_api::vm::inference::SafetyVerdict::ContainsPII = classification {
                    tracing::warn!(target: "firewall", "Transaction contains PII. Scrubbing required.");
                    return Err(TransactionError::Invalid(
                        "PII detected in transaction payload.".into(),
                    ));
                }
            }
        }
    }

    // --- LAYER 4: SERVICE DECORATORS ---
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

    // --- LAYER 5: STATE MUTATION ---
    if !is_simulation {
        for (id, decorator) in decorators {
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