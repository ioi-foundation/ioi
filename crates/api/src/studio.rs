use crate::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    StudioArtifactClass, StudioArtifactDeliverableShape, StudioArtifactFailure,
    StudioArtifactFileRole, StudioArtifactPersistenceMode, StudioExecutionStrategy,
    StudioExecutionSubstrate, StudioOutcomeArtifactRequest, StudioOutcomeArtifactScope,
    StudioOutcomeArtifactVerificationRequest, StudioOutcomeKind, StudioOutcomePlanningPayload,
    StudioPresentationSurface, StudioRendererKind, StudioRuntimeProvenance,
    StudioRuntimeProvenanceKind,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::Cell;
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;

mod generation;
mod html;
mod html_registry;
mod judging;
mod payload;
mod pdf;
mod planning;
mod render_eval;
mod types;

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

use html::*;
use html_registry::*;

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
pub use judging::{
    build_studio_artifact_judge_prompt, build_studio_artifact_judge_repair_prompt,
    judge_studio_artifact_candidate_with_runtime, parse_studio_artifact_judge_result,
};
#[cfg(test)]
pub(crate) use payload::validate_generated_artifact_payload_against_brief;
pub(crate) use payload::{
    enforce_renderer_judge_contract, enrich_generated_artifact_payload, extract_first_json_object,
    normalize_generated_artifact_payload, parse_and_validate_generated_artifact_payload,
    validate_generated_artifact_payload_against_brief_with_edit_intent,
};
pub use payload::{parse_studio_generated_artifact_payload, validate_generated_artifact_payload};
pub use pdf::{count_pdf_structural_sections, extract_searchable_pdf_text, pdf_artifact_bytes};
pub use planning::{
    build_studio_artifact_brief_prompt, build_studio_artifact_brief_repair_prompt,
    build_studio_artifact_edit_intent_prompt, build_studio_artifact_edit_intent_repair_prompt,
    build_studio_artifact_exemplar_query, build_studio_outcome_router_prompt,
    compile_studio_artifact_ir, derive_request_grounded_studio_artifact_brief,
    derive_studio_artifact_blueprint, parse_studio_artifact_brief,
    parse_studio_artifact_edit_intent, parse_studio_outcome_planning_payload,
    plan_studio_artifact_brief_with_runtime, plan_studio_artifact_edit_intent_with_runtime,
    plan_studio_outcome_with_runtime, studio_execution_strategy_for_outcome,
    synthesize_studio_artifact_brief_for_execution_strategy_with_runtime,
};
pub use render_eval::{
    build_studio_artifact_render_acceptance_policy, evaluate_studio_artifact_render_if_configured,
    merge_studio_artifact_render_evaluation_into_judge, StudioArtifactRenderEvaluator,
};
pub use types::*;

#[cfg(test)]
mod tests;
