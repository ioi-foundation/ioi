//! Shared Studio harness semantics.
//!
//! This module is the reusable runtime/policy boundary for Studio-shaped work:
//! routing, topology, policy contracts, artifact generation contracts, render
//! evaluation, and other execution semantics that should not depend on the
//! desktop shell.
//!
//! Keep product-shell concerns out of this layer. Session wiring, event
//! emission, task mutation, navigator state, and renderer-specific shell
//! surfaces belong in `apps/autopilot/.../kernel/studio`.

use crate::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    StudioArtifactClass, StudioArtifactFailure, StudioArtifactFileRole, StudioExecutionStrategy,
    StudioExecutionSubstrate, StudioOutcomeArtifactRequest, StudioOutcomeKind,
    StudioPresentationSurface, StudioRendererKind, StudioRuntimeProvenance,
    StudioRuntimeProvenanceKind,
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

fn studio_modal_first_html_override() -> Option<bool> {
    STUDIO_MODAL_FIRST_HTML_TASK_OVERRIDE
        .try_with(|enabled| *enabled)
        .ok()
        .or_else(|| STUDIO_MODAL_FIRST_HTML_THREAD_OVERRIDE.with(|enabled| enabled.get()))
}

fn studio_modal_first_html_enabled() -> bool {
    studio_modal_first_html_override().unwrap_or_else(|| {
        truthy_env_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML")
            || truthy_env_var("AUTOPILOT_LOCAL_GPU_DEV")
    })
}

#[doc(hidden)]
pub fn with_studio_modal_first_html_override<T>(enabled: bool, f: impl FnOnce() -> T) -> T {
    STUDIO_MODAL_FIRST_HTML_THREAD_OVERRIDE.with(|override_cell| {
        let previous = override_cell.replace(Some(enabled));
        let result = f();
        override_cell.set(previous);
        result
    })
}

#[doc(hidden)]
pub async fn with_studio_modal_first_html_override_async<T, F>(
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
pub fn studio_modal_first_html_enabled_for_tests_and_runtime() -> bool {
    studio_modal_first_html_enabled()
}

pub use domain_topology::{
    apply_non_artifact_clarification_gate, artifact_connector_grounding_for_outcome_request,
    build_studio_route_contract_payload, build_studio_runtime_handoff_prompt_prefix,
    derive_studio_domain_policy_bundle, derive_studio_topology_projection,
    non_artifact_operator_steps, non_artifact_route_notes, non_artifact_route_status_message,
    non_artifact_route_summary, non_artifact_route_title, non_artifact_swarm_plan,
    non_artifact_verification_receipts, non_artifact_verified_reply_evidence,
    non_artifact_worker_receipts, route_decision_for_outcome_request,
    route_family_for_outcome_request, route_topology_for_outcome_request,
    selected_route_label_for_outcome_request, verification_status_for_lifecycle,
    verified_reply_evidence_for_manifest, verifier_state_for_outcome_event,
    StudioTopologyProjection,
};
use html::*;
use html_registry::*;
pub use intent_signals::StudioIntentContext;
pub use specialized_policy::{
    studio_request_frame_clarification_slots, studio_request_frame_missing_slots,
    studio_specialized_domain_kind, studio_specialized_domain_kind_for_frame,
    studio_specialized_domain_policy, StudioSpecializedDomainKind,
    StudioSpecializedDomainPolicySpec,
};

pub use generation::{
    build_studio_artifact_candidate_refinement_prompt,
    build_studio_artifact_candidate_refinement_repair_prompt,
    build_studio_artifact_materialization_prompt,
    build_studio_artifact_materialization_repair_prompt, derive_studio_artifact_prepared_context,
    generate_studio_artifact_bundle_with_runtime,
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context,
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy,
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator,
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_render_evaluator,
    generate_studio_artifact_bundle_with_runtimes,
    generate_studio_artifact_bundle_with_runtimes_and_planning_context,
    generate_studio_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator,
    materialize_studio_artifact_candidate_with_runtime, materialize_studio_artifact_with_runtime,
    render_eval_timeout_for_runtime, resolve_studio_artifact_runtime_plan,
    StudioArtifactActivityObserver, StudioArtifactGenerationProgressObserver,
    StudioArtifactResolvedRuntimePlan,
};
#[cfg(test)]
pub(crate) use payload::validate_generated_artifact_payload_against_brief;
pub(crate) use payload::{
    enforce_renderer_validation_contract, enrich_generated_artifact_payload,
    extract_first_json_object, normalize_generated_artifact_payload,
    parse_and_validate_generated_artifact_payload,
    validate_generated_artifact_payload_against_brief_with_edit_intent,
};
pub use payload::{parse_studio_generated_artifact_payload, validate_generated_artifact_payload};
pub use pdf::{count_pdf_structural_sections, extract_searchable_pdf_text, pdf_artifact_bytes};
pub use planning::{
    apply_artifact_connector_grounding_to_brief, build_studio_artifact_brief_prompt,
    build_studio_artifact_brief_repair_prompt, build_studio_artifact_edit_intent_prompt,
    build_studio_artifact_edit_intent_repair_prompt, build_studio_artifact_exemplar_query,
    build_studio_outcome_router_prompt, compile_studio_artifact_ir,
    derive_request_grounded_studio_artifact_brief, derive_studio_artifact_blueprint,
    parse_studio_artifact_brief, parse_studio_artifact_edit_intent,
    parse_studio_outcome_planning_payload, plan_studio_artifact_brief_with_runtime,
    plan_studio_artifact_edit_intent_with_runtime, plan_studio_outcome_with_runtime,
    studio_execution_strategy_for_outcome,
    synthesize_studio_artifact_brief_for_execution_strategy_with_runtime,
};
pub use render_eval::{
    build_studio_artifact_render_acceptance_policy, evaluate_studio_artifact_render_if_configured,
    merge_studio_artifact_render_evaluation_into_validation, StudioArtifactRenderEvaluator,
};
pub use runtime_locality::{
    resolve_runtime_locality_placeholder, runtime_locality_scope_hint,
    with_runtime_locality_scope_hint_override,
};
pub use types::*;
pub use validation::{
    build_studio_artifact_validation_prompt, build_studio_artifact_validation_repair_prompt,
    parse_studio_artifact_validation_result, validate_studio_artifact_candidate_with_runtime,
};

#[cfg(test)]
mod tests;
