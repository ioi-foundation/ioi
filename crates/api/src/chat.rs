//! Shared Chat harness semantics.
//!
//! This module is the reusable runtime/policy boundary for Chat-shaped work:
//! routing, topology, policy contracts, artifact generation contracts, render
//! evaluation, and other execution semantics that should not depend on the
//! desktop shell.
//!
//! Keep product-shell concerns out of this layer. Session wiring, event
//! emission, task mutation, navigator state, and renderer-specific shell
//! surfaces belong in `apps/autopilot/.../kernel/chat`.
//!
//! New product-agnostic shell consumers should prefer
//! `crate::runtime_harness`. This module remains the compatibility/product-
//! shaped facade while the reusable runtime core is extracted under neutral
//! naming.

use crate::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    ChatArtifactClass, ChatArtifactFailure, ChatArtifactFileRole, ChatExecutionStrategy,
    ChatExecutionSubstrate, ChatOutcomeArtifactRequest, ChatOutcomeKind, ChatPresentationSurface,
    ChatRendererKind, ChatRuntimeProvenance, ChatRuntimeProvenanceKind,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::Cell;
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;

mod domain_topology;
mod generation;
mod html;
mod html_registry;
mod intent_context;
mod intent_signals;
mod payload;
mod pdf;
mod planning;
mod render_eval;
mod runtime_locality;
mod specialized_policy;
mod types;
mod validation;

tokio::task_local! {
    static STUDIO_MODAL_FIRST_HTML_TASK_OVERRIDE: bool;
}

thread_local! {
    static STUDIO_MODAL_FIRST_HTML_THREAD_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
}

fn truthy_env_var(key: &str) -> bool {
    std::env::var(key)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn chat_modal_first_html_override() -> Option<bool> {
    STUDIO_MODAL_FIRST_HTML_TASK_OVERRIDE
        .try_with(|enabled| *enabled)
        .ok()
        .or_else(|| STUDIO_MODAL_FIRST_HTML_THREAD_OVERRIDE.with(|enabled| enabled.get()))
}

fn chat_modal_first_html_enabled() -> bool {
    chat_modal_first_html_override().unwrap_or_else(|| {
        truthy_env_var("AUTOPILOT_CHAT_ARTIFACT_MODAL_FIRST_HTML")
            || truthy_env_var("AUTOPILOT_LOCAL_GPU_DEV")
    })
}

#[doc(hidden)]
pub fn with_chat_modal_first_html_override<T>(enabled: bool, f: impl FnOnce() -> T) -> T {
    struct ModalFirstHtmlOverrideGuard(Option<bool>);

    impl Drop for ModalFirstHtmlOverrideGuard {
        fn drop(&mut self) {
            STUDIO_MODAL_FIRST_HTML_THREAD_OVERRIDE.with(|override_cell| {
                override_cell.set(self.0);
            });
        }
    }

    STUDIO_MODAL_FIRST_HTML_THREAD_OVERRIDE.with(|override_cell| {
        let previous = override_cell.replace(Some(enabled));
        let _guard = ModalFirstHtmlOverrideGuard(previous);
        f()
    })
}

#[doc(hidden)]
pub async fn with_chat_modal_first_html_override_async<T, F>(
    enabled: bool,
    f: impl FnOnce() -> F,
) -> T
where
    F: Future<Output = T>,
{
    STUDIO_MODAL_FIRST_HTML_TASK_OVERRIDE
        .scope(enabled, async move { f().await })
        .await
}

#[doc(hidden)]
pub fn chat_modal_first_html_enabled_for_tests_and_runtime() -> bool {
    chat_modal_first_html_enabled()
}

pub use domain_topology::{
    apply_inline_answer_clarification_gate, artifact_connector_grounding_for_outcome_request,
    build_chat_decision_record_payload, build_chat_runtime_handoff_prompt_prefix,
    derive_chat_domain_policy_bundle, derive_chat_topology_projection,
    inline_answer_operator_steps, inline_answer_route_notes, inline_answer_route_summary,
    inline_answer_route_title, inline_answer_status_message, inline_answer_verification_receipts,
    inline_answer_verified_reply_evidence, inline_answer_work_graph_plan,
    inline_answer_worker_receipts, route_decision_for_outcome_request,
    route_family_for_outcome_request, route_topology_for_outcome_request,
    selected_route_label_for_outcome_request, verification_status_for_lifecycle,
    verified_reply_evidence_for_manifest, verifier_state_for_outcome_event, ChatTopologyProjection,
    TopologyProjection,
};
use html::*;
use html_registry::*;
pub use intent_context::extract_user_request_from_contextualized_intent;
pub use intent_signals::ChatIntentContext;
pub use specialized_policy::{
    chat_normalized_request_clarification_slots, chat_normalized_request_missing_slots,
    chat_specialized_domain_kind, chat_specialized_domain_kind_for_frame,
    chat_specialized_domain_policy, ChatSpecializedDomainKind, ChatSpecializedDomainPolicySpec,
};

pub use generation::{
    build_chat_artifact_candidate_refinement_prompt,
    build_chat_artifact_candidate_refinement_repair_prompt,
    build_chat_artifact_materialization_prompt, build_chat_artifact_materialization_repair_prompt,
    derive_chat_artifact_prepared_context, generate_chat_artifact_bundle_with_runtime,
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context,
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy,
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator,
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_render_evaluator,
    generate_chat_artifact_bundle_with_runtimes,
    generate_chat_artifact_bundle_with_runtimes_and_planning_context,
    generate_chat_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator,
    materialize_chat_artifact_candidate_with_runtime, materialize_chat_artifact_with_runtime,
    render_eval_timeout_for_runtime, resolve_chat_artifact_runtime_plan,
    ChatArtifactActivityObserver, ChatArtifactGenerationProgressObserver,
    ChatArtifactResolvedRuntimePlan,
};
#[cfg(test)]
pub(crate) use payload::validate_generated_artifact_payload_against_brief;
pub(crate) use payload::{
    enforce_renderer_validation_contract, enrich_generated_artifact_payload,
    extract_first_json_object, normalize_generated_artifact_payload,
    parse_and_validate_generated_artifact_payload,
    validate_generated_artifact_payload_against_brief_with_edit_intent,
};
pub use payload::{parse_chat_generated_artifact_payload, validate_generated_artifact_payload};
pub use pdf::{count_pdf_structural_sections, extract_searchable_pdf_text, pdf_artifact_bytes};
pub use planning::{
    apply_artifact_connector_grounding_to_brief, build_chat_artifact_brief_prompt,
    build_chat_artifact_brief_repair_prompt, build_chat_artifact_edit_intent_prompt,
    build_chat_artifact_edit_intent_repair_prompt, build_chat_artifact_exemplar_query,
    build_chat_outcome_router_prompt, chat_execution_strategy_for_outcome,
    compile_chat_artifact_ir, derive_chat_artifact_blueprint,
    derive_request_grounded_chat_artifact_brief, parse_chat_artifact_brief,
    parse_chat_artifact_edit_intent, parse_chat_outcome_planning_payload,
    plan_chat_artifact_brief_with_runtime, plan_chat_artifact_edit_intent_with_runtime,
    plan_chat_outcome_with_runtime,
    synthesize_chat_artifact_brief_for_execution_strategy_with_runtime,
};
pub use render_eval::{
    build_chat_artifact_render_acceptance_policy, evaluate_chat_artifact_render_if_configured,
    merge_chat_artifact_render_evaluation_into_validation, ChatArtifactRenderEvaluator,
};
pub use runtime_locality::{
    resolve_runtime_locality_placeholder, runtime_locality_scope_hint,
    with_runtime_locality_scope_hint_override,
};
pub use types::*;
pub use validation::{
    build_chat_artifact_validation_prompt, build_chat_artifact_validation_repair_prompt,
    parse_chat_artifact_validation_result, validate_chat_artifact_candidate_with_runtime,
};

#[cfg(test)]
mod tests;
