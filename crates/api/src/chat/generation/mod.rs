use super::validation::{
    candidate_generation_config, candidate_seed_for, chat_artifact_refinement_candidate_view,
    chat_artifact_refinement_context_view, html_first_paint_section_blueprint,
    materialization_max_tokens, output_origin_from_provenance, refined_candidate_root,
    renderer_supports_semantic_refinement, runtime_model_label, semantic_refinement_pass_limit,
    summarized_guidance_terms, validation_clears_primary_view, validation_total_score,
};
use super::*;
use crate::execution::{
    annotate_execution_envelope, build_execution_envelope_from_swarm,
    committed_execution_mode_decision, completion_invariant_for_direct_execution,
    ExecutionCompletionInvariantStatus, ExecutionDomainKind, ExecutionEnvelope,
    ExecutionLivePreview, ExecutionLivePreviewKind,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::{
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::MissedTickBehavior,
};

mod adaptive_search;
mod candidate_materialization;
mod common;
mod compact_html_materialization;
mod compact_html_swarm;
mod materialization_prompt;
mod materialization_repair_prompt;
mod non_swarm_bundle;
mod non_swarm_entrypoints;
mod non_swarm_finalize;
mod planning_and_validation;
mod refinement_prompt;
mod runtime_materialization;
mod runtime_plan;
mod swarm;
mod swarm_bundle;
mod swarm_bundle_finalize;
mod swarm_patch_parse;
mod swarm_patch_worker;
mod swarm_plan;
mod swarm_progress;
mod validation_preview;

#[cfg(test)]
pub(crate) use adaptive_search::requested_follow_up_pass;
use adaptive_search::*;
pub(crate) use adaptive_search::{
    derive_chat_adaptive_search_budget, ranked_candidate_indices_by_score,
    shortlisted_candidate_indices_for_budget, target_candidate_count_after_initial_search,
};
#[cfg(test)]
pub(crate) use candidate_materialization::direct_author_runtime_failure_reason;
#[cfg(test)]
pub(crate) use candidate_materialization::local_download_bundle_candidate_prevalidation;
#[cfg(test)]
pub(crate) use candidate_materialization::materialize_and_locally_validation_candidate;
use candidate_materialization::*;
use common::*;
use compact_html_materialization::*;
use compact_html_swarm::*;
#[cfg(test)]
pub(crate) use materialization_prompt::build_chat_artifact_direct_author_continuation_prompt_for_runtime;
pub use materialization_prompt::build_chat_artifact_materialization_prompt;
use materialization_prompt::*;
pub use materialization_repair_prompt::build_chat_artifact_materialization_repair_prompt;
pub use non_swarm_bundle::generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator;
use non_swarm_entrypoints::*;
pub use non_swarm_entrypoints::{
    generate_chat_artifact_bundle_with_runtime,
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context,
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy,
    generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_render_evaluator,
    generate_chat_artifact_bundle_with_runtimes,
    generate_chat_artifact_bundle_with_runtimes_and_planning_context,
    generate_chat_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator,
};
use non_swarm_finalize::*;
pub use planning_and_validation::derive_chat_artifact_prepared_context;
pub(crate) use planning_and_validation::evaluate_candidate_render_with_fallback;
#[allow(unused_imports)]
pub(crate) use planning_and_validation::render_evaluation_required;
use planning_and_validation::*;
pub(crate) use refinement_prompt::build_chat_artifact_candidate_refinement_prompt_for_runtime;
use refinement_prompt::*;
pub use refinement_prompt::{
    build_chat_artifact_candidate_refinement_prompt,
    build_chat_artifact_candidate_refinement_repair_prompt,
};
pub use runtime_materialization::{
    materialize_chat_artifact_candidate_with_runtime, materialize_chat_artifact_with_runtime,
};
pub(crate) use runtime_materialization::{
    materialize_chat_artifact_candidate_with_runtime_detailed,
    materialize_chat_artifact_candidate_with_runtime_direct_author_detailed,
    refine_chat_artifact_candidate_with_runtime,
    repair_direct_author_generated_candidate_with_runtime_error,
    repair_materialized_candidate_with_runtime_error,
    try_local_html_interaction_truth_rescue_document,
};
use runtime_plan::{
    chat_runtime_provenance_matches, compact_local_html_materialization_prompt,
    effective_direct_author_temperature, warm_local_html_generation_runtime_if_needed,
};
pub(crate) use runtime_plan::{
    effective_candidate_generation_temperature, materialization_max_tokens_for_execution_strategy,
    materialization_max_tokens_for_runtime, materialization_repair_pass_limit,
    materialization_repair_runtime_for_request,
};
pub use runtime_plan::{
    render_eval_timeout_for_runtime, resolve_chat_artifact_runtime_plan,
    ChatArtifactResolvedRuntimePlan,
};
use swarm::{
    chat_artifact_uses_swarm_execution, chat_swarm_execution_summary, chat_swarm_now_iso,
    chat_swarm_soft_validation_error, chat_swarm_strategy_for_request,
    default_chat_artifact_execution_strategy, default_generated_artifact_file_for_renderer,
    push_unique_focus_strings, section_region_id, update_swarm_work_item_status,
    validation_status_id,
};
use swarm_bundle::*;
use swarm_bundle_finalize::*;
use swarm_patch_parse::*;
pub(crate) use swarm_patch_parse::{
    ChatArtifactPatchEnvelope, ChatArtifactPatchOperation, ChatArtifactPatchOperationKind,
};
use swarm_patch_worker::*;
pub(crate) use swarm_plan::build_chat_artifact_swarm_plan;
pub(crate) use swarm_progress::apply_chat_swarm_patch_envelope;
use swarm_progress::*;
pub(crate) use validation_preview::validate_swarm_generated_artifact_payload;
use validation_preview::*;
pub use validation_preview::{
    ChatArtifactActivityObserver, ChatArtifactGenerationProgressObserver,
};

pub(crate) use materialization_prompt::{
    build_chat_artifact_direct_author_prompt_for_runtime,
    build_chat_artifact_materialization_prompt_for_runtime,
};
pub(crate) use materialization_repair_prompt::build_chat_artifact_materialization_repair_prompt_for_runtime;
