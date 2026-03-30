use crate::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    StudioArtifactClass, StudioArtifactDeliverableShape, StudioArtifactFailure,
    StudioArtifactFileRole, StudioArtifactPersistenceMode, StudioExecutionSubstrate,
    StudioOutcomeArtifactRequest, StudioOutcomeArtifactScope,
    StudioOutcomeArtifactVerificationRequest, StudioOutcomePlanningPayload,
    StudioPresentationSurface, StudioRendererKind, StudioRuntimeProvenance,
    StudioRuntimeProvenanceKind,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;

mod generation;
mod html;
mod judging;
mod payload;
mod pdf;
mod planning;
mod types;

use html::*;

pub use generation::{
    build_studio_artifact_candidate_refinement_prompt,
    build_studio_artifact_candidate_refinement_repair_prompt,
    build_studio_artifact_materialization_prompt,
    build_studio_artifact_materialization_repair_prompt,
    generate_studio_artifact_bundle_with_runtime, generate_studio_artifact_bundle_with_runtimes,
    materialize_studio_artifact_candidate_with_runtime, materialize_studio_artifact_with_runtime,
};
pub use judging::{
    build_studio_artifact_judge_prompt, build_studio_artifact_judge_repair_prompt,
    judge_studio_artifact_candidate_with_runtime, parse_studio_artifact_judge_result,
};
pub(crate) use payload::{
    enforce_renderer_judge_contract, enrich_generated_artifact_payload, extract_first_json_object,
    normalize_generated_artifact_payload, parse_and_validate_generated_artifact_payload,
    validate_generated_artifact_payload_against_brief,
    validate_generated_artifact_payload_against_brief_with_edit_intent,
};
pub use payload::{parse_studio_generated_artifact_payload, validate_generated_artifact_payload};
pub use pdf::{count_pdf_structural_sections, extract_searchable_pdf_text, pdf_artifact_bytes};
pub use planning::{
    build_studio_artifact_brief_prompt, build_studio_artifact_brief_repair_prompt,
    build_studio_artifact_edit_intent_prompt, build_studio_artifact_edit_intent_repair_prompt,
    build_studio_outcome_router_prompt, parse_studio_artifact_brief,
    parse_studio_artifact_edit_intent, parse_studio_outcome_planning_payload,
    plan_studio_artifact_brief_with_runtime, plan_studio_artifact_edit_intent_with_runtime,
    plan_studio_outcome_with_runtime,
};
pub use types::*;

#[cfg(test)]
mod tests;
