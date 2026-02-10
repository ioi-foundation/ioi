// Path: crates/validator/src/firewall/mod.rs

//! The Agency Firewall: Pre-execution policy enforcement and validation.

/// The inference engine interface for classification.
pub mod inference;
// REMOVED: pub mod policy;
// REMOVED: pub mod rules;
/// Policy Synthesizer for Ghost Mode.
pub mod synthesizer;

// [FIX] Import PolicyEngine and Verdict from ioi-services
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, Verdict};
// [NEW] Imports for state lookup
use ioi_services::agentic::desktop::keys::get_state_key;
use ioi_services::agentic::desktop::{AgentState, StepAgentParams};

use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_services::agentic::scrubber::SemanticScrubber;

use ibc_primitives::Timestamp;
use ioi_api::state::namespaced::{NamespacedStateAccess, ReadOnlyNamespacedStateAccess};
use ioi_api::state::{service_namespace_prefix, StateAccess, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_tx::system::{nonce, validation};
use ioi_types::app::{action::ApprovalToken, ChainTransaction, KernelEvent, SystemPayload};
use ioi_types::codec;
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
    os_driver: Arc<dyn OsDriver>,
    // [NEW] Added event_broadcaster to emit UI events (gates, blocks)
    event_broadcaster: &Option<tokio::sync::broadcast::Sender<KernelEvent>>,
) -> Result<(), TransactionError> {
    let mut overlay = StateOverlay::new(state);

    let _scrubber = SemanticScrubber::new(safety_model.clone());

    // 1. Identify Signer
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
    // [FIX] Use raw u64
    let next_timestamp = next_timestamp_ns
        .try_into()
        .map_err(|_| TransactionError::Invalid("Timestamp overflow".to_string()))?;

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

        if service_id == "agentic"
            || service_id == "desktop_agent"
            || service_id == "compute_market"
        {
            // [NEW] Attempt to extract session_id and approval token from state
            let mut session_id_opt = None;
            let mut approval_token: Option<ApprovalToken> = None;

            if service_id == "desktop_agent" && method == "step@v1" {
                if let Ok(p) = codec::from_bytes_canonical::<StepAgentParams>(params) {
                    session_id_opt = Some(p.session_id);

                    // Look up agent state to see if approval token exists
                    let key = get_state_key(&p.session_id);

                    let ns_prefix = service_namespace_prefix("desktop_agent");
                    let full_key = [ns_prefix.as_slice(), key.as_slice()].concat();

                    if let Ok(Some(bytes)) = overlay.get(&full_key) {
                        if let Ok(agent_state) = codec::from_bytes_canonical::<AgentState>(&bytes) {
                            approval_token = agent_state.pending_approval;
                        }
                    }
                }
            }

            // [FIX] Load active policy from state (Global Fallback)
            // We use the global policy key (zero session ID) defined in `ioi-local.rs`.
            // Canonical prefix: b"agent::policy::"
            // The namespaced prefix is not applied here because we are reading raw state in the firewall,
            // but the policy was inserted in ioi-local via raw insert which might or might not be namespaced.
            // Wait, ioi-local.rs uses `workload_container.state_tree().write()` which is raw access.
            // But `ioi-local.rs` inserts keys `agent::policy::{session_id}`.

            // NOTE: The `ioi-local` setup writes to raw state.
            // The policy prefix is `b"agent::policy::"`.
            // The global policy uses a zeroed session ID.

            let policy_prefix = b"agent::policy::";

            let rules = if let Some(sid) = session_id_opt {
                // Try session specific policy first
                let session_policy_key = [policy_prefix, sid.as_slice()].concat();
                if let Ok(Some(bytes)) = overlay.get(&session_policy_key) {
                    codec::from_bytes_canonical::<ActionRules>(&bytes).unwrap_or_default()
                } else {
                    // Fallback to global
                    let global_key = [policy_prefix, [0u8; 32].as_slice()].concat();
                    if let Ok(Some(bytes)) = overlay.get(&global_key) {
                        codec::from_bytes_canonical::<ActionRules>(&bytes).unwrap_or_default()
                    } else {
                        ActionRules::default()
                    }
                }
            } else {
                // Global fallback
                let global_key = [policy_prefix, [0u8; 32].as_slice()].concat();
                if let Ok(Some(bytes)) = overlay.get(&global_key) {
                    codec::from_bytes_canonical::<ActionRules>(&bytes).unwrap_or_default()
                } else {
                    ActionRules::default()
                }
            };

            let dummy_request = ioi_types::app::ActionRequest {
                target: ioi_types::app::ActionTarget::Custom(method.clone()),
                params: params.clone(),
                context: ioi_types::app::ActionContext {
                    agent_id: "unknown".into(),
                    session_id: session_id_opt,
                    window_id: None,
                },
                nonce: 0,
            };

            let verdict = PolicyEngine::evaluate(
                &rules,
                &dummy_request,
                &safety_model,
                &os_driver,
                approval_token.as_ref(),
            )
            .await;

            match verdict {
                Verdict::Allow => {
                    // Proceed
                }
                Verdict::Block => {
                    // [NEW] Emit Block Event
                    if let Some(tx) = event_broadcaster {
                        let _ = tx.send(KernelEvent::FirewallInterception {
                            verdict: "BLOCK".to_string(),
                            target: method.clone(),
                            request_hash: dummy_request.hash(),
                            session_id: session_id_opt,
                        });
                    }
                    return Err(TransactionError::Invalid("Blocked by Policy".into()));
                }
                Verdict::RequireApproval => {
                    let req_hash_bytes = dummy_request.hash();
                    let req_hash_hex = hex::encode(req_hash_bytes);

                    // [NEW] Attempt to extract visual hash from params for the event
                    // This allows the UI to display the screenshot the agent saw when requesting the action.
                    let mut visual_hash_opt: Option<[u8; 32]> = None;
                    if let Ok(json) =
                        serde_json::from_slice::<serde_json::Value>(&dummy_request.params)
                    {
                        if let Some(hex_hash) =
                            json.get("expected_visual_hash").and_then(|s| s.as_str())
                        {
                            if let Ok(bytes) = hex::decode(hex_hash) {
                                if bytes.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&bytes);
                                    visual_hash_opt = Some(arr);
                                }
                            }
                        }
                    }

                    // [NEW] Emit RequireApproval Event (Triggers Gate UI)
                    if let Some(tx) = event_broadcaster {
                        let _ = tx.send(KernelEvent::FirewallInterception {
                            verdict: "REQUIRE_APPROVAL".to_string(),
                            target: method.clone(),
                            request_hash: req_hash_bytes,
                            session_id: session_id_opt,
                            // KernelEvent currently doesn't have a visual_hash field in FirewallInterception.
                            // The UI must fetch the StepTrace or reconstruct it.
                            // For now, we rely on the `request_hash` matching the pending tool call in state.
                        });
                    }

                    tracing::info!(target: "firewall", "Gating action {} (Hash: {})", method, req_hash_hex);
                    return Err(TransactionError::PendingApproval(req_hash_hex));
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
