use super::revisions::{
    studio_artifact_exemplar_from_archival_record, STUDIO_ARTIFACT_EXEMPLAR_SCOPE,
};
use super::source_research::retrieve_research_sources_for_brief;
use super::*;
use crate::kernel::state::connect_public_api;
use crate::models::AppState;
use ioi_api::studio::{
    apply_artifact_connector_grounding_to_brief, build_studio_artifact_exemplar_query,
    compile_studio_artifact_ir, derive_request_grounded_studio_artifact_brief,
    derive_studio_artifact_blueprint, derive_studio_artifact_prepared_context,
    synthesize_studio_artifact_brief_for_execution_strategy_with_runtime,
    ArtifactConnectorGrounding, StudioArtifactBlueprint, StudioArtifactExemplar,
    StudioArtifactGenerationProgress, StudioArtifactGenerationProgressObserver, StudioArtifactIR,
    StudioArtifactOperatorPhase, StudioArtifactOperatorRunStatus, StudioArtifactOperatorStep,
    StudioArtifactPlanningContext, StudioArtifactPreparationNeeds,
    StudioArtifactRuntimeEventStatus, StudioArtifactSelectedSkill,
    StudioArtifactSkillDiscoveryResolution, StudioArtifactSkillNeed, StudioArtifactSkillNeedKind,
    StudioArtifactSkillNeedPriority, StudioArtifactSourceReference, StudioArtifactTasteMemory,
};
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_memory::{HybridArchivalMemoryQuery, MemoryRuntime, SemanticArchivalMemoryQuery};
use ioi_services::agentic::runtime::keys::{
    get_skill_doc_key, get_skill_record_key, get_skill_stats_key,
};
use ioi_services::agentic::skill_registry::{
    adjusted_skill_discovery_score, skill_guidance_markdown, skill_hash_from_archival_record,
    skill_is_runtime_eligible, skill_reliability_score, SKILL_ARCHIVAL_SCOPE,
};
use ioi_types::app::agentic::{PublishedSkillDoc, SkillRecord, SkillStats};
use ioi_types::app::StudioExecutionStrategy;
use ioi_types::codec;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Manager};
use tonic::transport::Channel;

const STUDIO_SKILL_DISCOVERY_LIMIT: usize = 4;
const STUDIO_EXEMPLAR_DISCOVERY_LIMIT: usize = 3;

#[derive(Debug, Clone)]
struct StudioSkillAccumulator {
    name: String,
    description: String,
    lifecycle_state: String,
    source_type: String,
    reliability_bps: u32,
    semantic_score_bps: u32,
    adjusted_score_bps: u32,
    relative_path: Option<String>,
    matched_need_ids: Vec<String>,
    matched_need_kinds: Vec<StudioArtifactSkillNeedKind>,
    match_rationale: String,
    guidance_markdown: Option<String>,
    required_matches: usize,
}

fn studio_skill_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-skill-trace] {}", message.as_ref());
    }
}

fn skill_kind_label(kind: StudioArtifactSkillNeedKind) -> String {
    serde_json::to_string(&kind)
        .unwrap_or_else(|_| "\"unknown\"".to_string())
        .trim_matches('"')
        .to_string()
}

fn skill_priority_label(priority: StudioArtifactSkillNeedPriority) -> String {
    serde_json::to_string(&priority)
        .unwrap_or_else(|_| "\"recommended\"".to_string())
        .trim_matches('"')
        .to_string()
}

fn normalized_relative_path(
    published_doc: Option<&PublishedSkillDoc>,
    record: &SkillRecord,
) -> Option<String> {
    published_doc
        .map(|doc| doc.relative_path.clone())
        .or_else(|| {
            record
                .publication
                .as_ref()
                .map(|publication| publication.relative_path.clone())
        })
}

fn score_bps(score: f32) -> u32 {
    (score.clamp(0.0, 1.0) * 10_000.0).round() as u32
}

fn sort_and_truncate_selected_skills(
    mut selected: Vec<(usize, usize, StudioArtifactSelectedSkill)>,
) -> Vec<StudioArtifactSelectedSkill> {
    selected.sort_by(|left, right| {
        right
            .2
            .adjusted_score_bps
            .cmp(&left.2.adjusted_score_bps)
            .then(right.0.cmp(&left.0))
            .then(right.1.cmp(&left.1))
            .then(left.2.name.cmp(&right.2.name))
    });
    selected.truncate(STUDIO_SKILL_DISCOVERY_LIMIT);
    selected.into_iter().map(|(_, _, skill)| skill).collect()
}

async fn connect_cached_public_api_async(
    app: &AppHandle,
) -> Result<PublicApiClient<Channel>, String> {
    let state = app.state::<Mutex<AppState>>();
    if let Ok(guard) = state.lock() {
        if let Some(client) = guard.rpc_client.clone() {
            return Ok(client);
        }
    }

    let client = connect_public_api().await?;
    if let Ok(mut guard) = state.lock() {
        if guard.rpc_client.is_none() {
            guard.rpc_client = Some(client.clone());
        }
    }
    Ok(client)
}

fn planning_context_discovery_timeout(planning_timeout: Duration) -> Duration {
    planning_timeout.min(Duration::from_secs(8))
}

async fn query_raw_state(
    client: &mut PublicApiClient<Channel>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    let response = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .map_err(|status| format!("RPC error: {}", status))?
        .into_inner();
    if response.found {
        Ok(Some(response.value))
    } else {
        Ok(None)
    }
}

fn build_skill_need_query(
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
    need: &StudioArtifactSkillNeed,
    need_id: &str,
) -> String {
    let section_roles = blueprint
        .section_plan
        .iter()
        .map(|section| section.role.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let interaction_families = blueprint
        .interaction_plan
        .iter()
        .map(|interaction| interaction.family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let component_families = blueprint
        .component_plan
        .iter()
        .map(|component| component.component_family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let evidence_kinds = blueprint
        .evidence_plan
        .iter()
        .map(|entry| entry.kind.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let design_tokens = artifact_ir
        .design_tokens
        .iter()
        .map(|token| format!("{}={}", token.name, token.value))
        .take(6)
        .collect::<Vec<_>>()
        .join(", ");

    let required_interactions = brief.required_interaction_summaries().join(", ");

    format!(
        "Artifact skill discovery request.\nNeed id: {need_id}\nNeed kind: {}\nNeed priority: {}\nNeed rationale: {}\nRenderer: {:?}\nScaffold family: {}\nNarrative arc: {}\nAudience: {}\nJob to be done: {}\nArtifact thesis: {}\nDesign system: color={}, typography={}, density={}, motion={}\nSection roles: {}\nInteraction families: {}\nEvidence kinds: {}\nComponent families: {}\nRequired concepts: {}\nRequired interactions: {}\nVisual tone: {}\nReference hints: {}\nStatic audit expectations: {}\nRender evaluation checklist: {}\nDesign tokens: {}\nLook for reusable procedural skill guidance that would improve this structural requirement in a renderer-native artifact pipeline.",
        skill_kind_label(need.kind),
        skill_priority_label(need.priority),
        need.rationale,
        blueprint.renderer,
        blueprint.scaffold_family,
        blueprint.narrative_arc,
        brief.audience,
        brief.job_to_be_done,
        brief.artifact_thesis,
        blueprint.design_system.color_strategy,
        blueprint.design_system.typography_strategy,
        blueprint.design_system.density,
        blueprint.design_system.motion_style,
        section_roles,
        interaction_families,
        evidence_kinds,
        component_families,
        brief.required_concepts.join(", "),
        required_interactions,
        brief.visual_tone.join(", "),
        brief.reference_hints.join(", "),
        artifact_ir.static_audit_expectations.join(", "),
        artifact_ir.render_eval_checklist.join(", "),
        design_tokens,
    )
}

fn emit_planning_context_progress(
    observer: Option<&StudioArtifactGenerationProgressObserver>,
    current_step: impl Into<String>,
    planning_context: &StudioArtifactPlanningContext,
    operator_steps: Vec<StudioArtifactOperatorStep>,
) {
    let Some(observer) = observer else {
        return;
    };

    observer(StudioArtifactGenerationProgress {
        current_step: current_step.into(),
        artifact_brief: Some(planning_context.brief.clone()),
        preparation_needs: planning_context.preparation_needs.clone(),
        prepared_context_resolution: planning_context.prepared_context_resolution.clone(),
        skill_discovery_resolution: planning_context.skill_discovery_resolution.clone(),
        blueprint: planning_context.blueprint.clone(),
        artifact_ir: planning_context.artifact_ir.clone(),
        selected_skills: planning_context.selected_skills.clone(),
        retrieved_exemplars: planning_context.retrieved_exemplars.clone(),
        retrieved_sources: planning_context.retrieved_sources.clone(),
        execution_envelope: None,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation: None,
        validation: None,
        operator_steps,
    });
}

fn emit_skill_discovery_progress(
    observer: Option<&StudioArtifactGenerationProgressObserver>,
    current_step: impl Into<String>,
    preparation_needs: Option<StudioArtifactPreparationNeeds>,
    skill_discovery_resolution: Option<StudioArtifactSkillDiscoveryResolution>,
    selected_skills: Vec<StudioArtifactSelectedSkill>,
    operator_steps: Vec<StudioArtifactOperatorStep>,
) {
    let Some(observer) = observer else {
        return;
    };

    observer(StudioArtifactGenerationProgress {
        current_step: current_step.into(),
        artifact_brief: None,
        preparation_needs,
        prepared_context_resolution: None,
        skill_discovery_resolution,
        blueprint: None,
        artifact_ir: None,
        selected_skills,
        retrieved_exemplars: Vec::new(),
        retrieved_sources: Vec::new(),
        execution_envelope: None,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation: None,
        validation: None,
        operator_steps,
    });
}

fn operator_status_from_runtime_status(
    status: StudioArtifactRuntimeEventStatus,
) -> StudioArtifactOperatorRunStatus {
    match status {
        StudioArtifactRuntimeEventStatus::Pending => StudioArtifactOperatorRunStatus::Pending,
        StudioArtifactRuntimeEventStatus::Active => StudioArtifactOperatorRunStatus::Active,
        StudioArtifactRuntimeEventStatus::Complete => StudioArtifactOperatorRunStatus::Complete,
        StudioArtifactRuntimeEventStatus::Failed
        | StudioArtifactRuntimeEventStatus::Interrupted => StudioArtifactOperatorRunStatus::Failed,
        StudioArtifactRuntimeEventStatus::Blocked => StudioArtifactOperatorRunStatus::Blocked,
        StudioArtifactRuntimeEventStatus::Other => StudioArtifactOperatorRunStatus::Other,
    }
}

fn operator_step(
    phase: StudioArtifactOperatorPhase,
    step_id: &str,
    label: impl Into<String>,
    detail: impl Into<String>,
    status: StudioArtifactRuntimeEventStatus,
) -> StudioArtifactOperatorStep {
    let status = operator_status_from_runtime_status(status);
    StudioArtifactOperatorStep {
        step_id: step_id.to_string(),
        origin_prompt_event_id: String::new(),
        phase,
        engine: "planning_context".to_string(),
        status,
        label: label.into(),
        detail: detail.into(),
        started_at_ms: 0,
        finished_at_ms: matches!(
            status,
            StudioArtifactOperatorRunStatus::Complete
                | StudioArtifactOperatorRunStatus::Blocked
                | StudioArtifactOperatorRunStatus::Failed
        )
        .then_some(0),
        preview: None,
        file_refs: Vec::new(),
        source_refs: Vec::new(),
        verification_refs: Vec::new(),
        attempt: 1,
    }
}

fn skill_discovery_active_step() -> StudioArtifactOperatorStep {
    operator_step(
        StudioArtifactOperatorPhase::SearchSources,
        "skill_discovery",
        "Check for guidance",
        "Studio is checking whether published runtime guidance should be attached before authoring.",
        StudioArtifactRuntimeEventStatus::Active,
    )
}

fn skill_discovery_complete_steps(
    resolution: &StudioArtifactSkillDiscoveryResolution,
    selected_skills: &[StudioArtifactSelectedSkill],
) -> Vec<StudioArtifactOperatorStep> {
    let mut steps = vec![operator_step(
        StudioArtifactOperatorPhase::SearchSources,
        "skill_discovery",
        skill_discovery_title(resolution),
        resolution.rationale.clone(),
        if resolution.status.eq_ignore_ascii_case("blocked") {
            StudioArtifactRuntimeEventStatus::Blocked
        } else if resolution.status.eq_ignore_ascii_case("failed") {
            StudioArtifactRuntimeEventStatus::Failed
        } else {
            StudioArtifactRuntimeEventStatus::Complete
        },
    )];
    if !selected_skills.is_empty() {
        steps.push(operator_step(
            StudioArtifactOperatorPhase::ReadSources,
            "skill_read",
            if selected_skills.len() == 1 {
                format!("Read {}", selected_skills[0].name)
            } else {
                "Read guidance".to_string()
            },
            if selected_skills.len() == 1 {
                format!(
                    "Studio read {} before authoring the artifact.",
                    selected_skills[0].name
                )
            } else {
                format!(
                    "Studio read {} skill guides before authoring the artifact.",
                    selected_skills.len()
                )
            },
            StudioArtifactRuntimeEventStatus::Complete,
        ));
    }
    steps
}

fn artifact_brief_active_step() -> StudioArtifactOperatorStep {
    operator_step(
        StudioArtifactOperatorPhase::UnderstandRequest,
        "artifact_brief",
        "Shape artifact brief",
        "Studio is shaping the artifact brief that will guide authoring.",
        StudioArtifactRuntimeEventStatus::Active,
    )
}

fn artifact_brief_complete_step(
    planning_context: &StudioArtifactPlanningContext,
) -> StudioArtifactOperatorStep {
    operator_step(
        StudioArtifactOperatorPhase::UnderstandRequest,
        "artifact_brief",
        "Shape artifact brief",
        format!(
            "Studio prepared a typed artifact brief for {}.",
            planning_context.brief.subject_domain
        ),
        StudioArtifactRuntimeEventStatus::Complete,
    )
}

fn skill_discovery_title(resolution: &StudioArtifactSkillDiscoveryResolution) -> String {
    match resolution
        .guidance_status
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "attached" => "Guidance attached".to_string(),
        "not_needed" => "Guidance not needed".to_string(),
        "unavailable" => "Guidance unavailable".to_string(),
        _ => "Check for guidance".to_string(),
    }
}

fn skill_discovery_completion_message(
    resolution: &StudioArtifactSkillDiscoveryResolution,
    selected_skills: &[StudioArtifactSelectedSkill],
) -> String {
    match resolution.guidance_status.trim().to_ascii_lowercase().as_str() {
        "attached" => {
            if selected_skills.len() == 1 {
                format!(
                    "Skill discovery is complete. Read {} before authoring.",
                    selected_skills[0].name
                )
            } else {
                format!(
                    "Skill discovery is complete. Read {} selected skill guides before authoring.",
                    selected_skills.len()
                )
            }
        }
        "not_needed" => {
            "Skill discovery is complete. No extra skill guide was needed before authoring."
                .to_string()
        }
        "unavailable" => "Skill discovery is complete. Studio checked for guidance before authoring but did not find a qualifying skill to attach."
            .to_string(),
        _ => "Skill discovery is complete.".to_string(),
    }
}

pub(super) fn prepare_studio_artifact_planning_context(
    app: &AppHandle,
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    connector_grounding: Option<&ArtifactConnectorGrounding>,
    execution_strategy: StudioExecutionStrategy,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<StudioArtifactPlanningContext, String> {
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        return Err(
            "Prepared artifact context is unavailable for workspace-surface requests.".to_string(),
        );
    }

    let planning_timeout = Duration::from_secs(90).min(
        super::studio_generation_timeout_for_runtime(&inference_runtime),
    );
    let mut discovery_brief =
        derive_request_grounded_studio_artifact_brief(title, intent, request, refinement);
    apply_artifact_connector_grounding_to_brief(&mut discovery_brief, connector_grounding);
    let discovery_blueprint = derive_studio_artifact_blueprint(request, &discovery_brief);
    let discovery_artifact_ir =
        compile_studio_artifact_ir(request, &discovery_brief, &discovery_blueprint);
    let discovery_context = derive_studio_artifact_prepared_context(
        request,
        &discovery_brief,
        Some(discovery_blueprint.clone()),
        Some(discovery_artifact_ir.clone()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let pending_skill_discovery_resolution =
        discovery_context
            .preparation_needs
            .as_ref()
            .map(|preparation_needs| StudioArtifactSkillDiscoveryResolution {
                status: "active".to_string(),
                guidance_status: "pending".to_string(),
                guidance_evaluated: false,
                guidance_recommended: !preparation_needs.skill_needs.is_empty(),
                guidance_found: false,
                guidance_attached: false,
                skill_need_count: preparation_needs.skill_needs.len() as u32,
                selected_skill_count: 0,
                selected_skill_names: Vec::new(),
                search_scope: "published_runtime_skills".to_string(),
                rationale:
                    "Studio is checking the published runtime guidance corpus before authoring."
                        .to_string(),
                failure_reason: None,
            });
    emit_skill_discovery_progress(
        progress_observer.as_ref(),
        "Deciding whether to read skill guidance before authoring.",
        discovery_context.preparation_needs.clone(),
        pending_skill_discovery_resolution,
        Vec::new(),
        vec![skill_discovery_active_step()],
    );
    let discovery_timeout = planning_context_discovery_timeout(planning_timeout);
    let selected_skills = match tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            discovery_timeout,
            resolve_selected_skills(
                app,
                memory_runtime,
                inference_runtime.clone(),
                &discovery_brief,
                &discovery_blueprint,
                &discovery_artifact_ir,
            ),
        )
        .await
    }) {
        Ok(Ok(skills)) => skills,
        Ok(Err(error)) => {
            studio_skill_trace(format!("planning_context:skill_error {}", error));
            Vec::new()
        }
        Err(_) => {
            studio_skill_trace("planning_context:skill_timeout");
            Vec::new()
        }
    };
    let skill_discovery_context = derive_studio_artifact_prepared_context(
        request,
        &discovery_brief,
        Some(discovery_blueprint),
        Some(discovery_artifact_ir),
        selected_skills.clone(),
        Vec::new(),
        Vec::new(),
    );
    let skill_discovery_step = skill_discovery_context
        .skill_discovery_resolution
        .as_ref()
        .map(|resolution| skill_discovery_completion_message(resolution, &selected_skills))
        .unwrap_or_else(|| "Skill discovery is complete.".to_string());
    emit_skill_discovery_progress(
        progress_observer.as_ref(),
        skill_discovery_step,
        skill_discovery_context.preparation_needs.clone(),
        skill_discovery_context.skill_discovery_resolution.clone(),
        selected_skills.clone(),
        skill_discovery_context
            .skill_discovery_resolution
            .as_ref()
            .map(|resolution| skill_discovery_complete_steps(resolution, &selected_skills))
            .unwrap_or_default(),
    );
    emit_skill_discovery_progress(
        progress_observer.as_ref(),
        "Preparing the artifact brief before authoring.",
        skill_discovery_context.preparation_needs.clone(),
        skill_discovery_context.skill_discovery_resolution.clone(),
        selected_skills.clone(),
        vec![artifact_brief_active_step()],
    );
    let mut brief = match tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            planning_timeout,
            synthesize_studio_artifact_brief_for_execution_strategy_with_runtime(
                inference_runtime.clone(),
                title,
                intent,
                request,
                refinement,
                execution_strategy,
            ),
        )
        .await
    }) {
        Ok(Ok(brief)) => brief,
        Ok(Err(error)) => {
            studio_skill_trace(format!("planning_context:brief_error {}", error));
            discovery_brief.clone()
        }
        Err(_) => {
            studio_skill_trace("planning_context:brief_timeout");
            discovery_brief.clone()
        }
    };
    apply_artifact_connector_grounding_to_brief(&mut brief, connector_grounding);
    let blueprint = derive_studio_artifact_blueprint(request, &brief);
    let artifact_ir = compile_studio_artifact_ir(request, &brief, &blueprint);
    let retrieved_exemplars = match tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            discovery_timeout,
            retrieve_studio_artifact_exemplars(
                memory_runtime,
                inference_runtime.clone(),
                &brief,
                &blueprint,
                &artifact_ir,
                refinement.and_then(|context| context.taste_memory.as_ref()),
            ),
        )
        .await
    }) {
        Ok(Ok(exemplars)) => exemplars,
        Ok(Err(error)) => {
            studio_skill_trace(format!("planning_context:exemplar_error {}", error));
            Vec::new()
        }
        Err(_) => {
            studio_skill_trace("planning_context:exemplar_timeout");
            Vec::new()
        }
    };
    let retrieved_sources = match tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            Duration::from_secs(6),
            retrieve_research_sources_for_brief(inference_runtime.clone(), &brief),
        )
        .await
    }) {
        Ok(sources) => sources,
        Err(_) => {
            studio_skill_trace("planning_context:source_timeout");
            Vec::<StudioArtifactSourceReference>::new()
        }
    };
    let planning_context = derive_studio_artifact_prepared_context(
        request,
        &brief,
        Some(blueprint),
        Some(artifact_ir),
        selected_skills,
        retrieved_exemplars,
        retrieved_sources,
    );
    emit_planning_context_progress(
        progress_observer.as_ref(),
        "Prepared the artifact brief. Authoring can begin.",
        &planning_context,
        vec![artifact_brief_complete_step(&planning_context)],
    );

    Ok(planning_context)
}

async fn resolve_selected_skills(
    app: &AppHandle,
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
) -> Result<Vec<StudioArtifactSelectedSkill>, String> {
    let mut client = connect_cached_public_api_async(app).await?;
    resolve_selected_skills_with_client(
        &mut client,
        memory_runtime,
        inference_runtime,
        brief,
        blueprint,
        artifact_ir,
    )
    .await
}

async fn retrieve_studio_artifact_exemplars(
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
    taste_memory: Option<&StudioArtifactTasteMemory>,
) -> Result<Vec<StudioArtifactExemplar>, String> {
    let query = build_studio_artifact_exemplar_query(brief, blueprint, artifact_ir, taste_memory);
    let embedding = inference_runtime
        .embed_text(&query)
        .await
        .map_err(|error| format!("Failed to embed Studio exemplar query: {}", error))?;
    let mut exemplars = memory_runtime
        .hybrid_search_archival_memory(&HybridArchivalMemoryQuery {
            scopes: vec![STUDIO_ARTIFACT_EXEMPLAR_SCOPE.to_string()],
            thread_id: None,
            text: query,
            embedding: Some(embedding),
            limit: STUDIO_EXEMPLAR_DISCOVERY_LIMIT * 2,
            candidate_limit: STUDIO_EXEMPLAR_DISCOVERY_LIMIT * 4,
            allowed_trust_levels: vec!["runtime_observed".to_string()],
        })
        .map_err(|error| format!("Failed to search Studio exemplars: {}", error))?
        .into_iter()
        .filter_map(|hit| studio_artifact_exemplar_from_archival_record(&hit.record))
        .filter(|exemplar| exemplar.renderer == blueprint.renderer)
        .collect::<Vec<_>>();

    exemplars.sort_by(|left, right| {
        (right.scaffold_family == blueprint.scaffold_family)
            .cmp(&(left.scaffold_family == blueprint.scaffold_family))
            .then(right.score_total.cmp(&left.score_total))
            .then(right.record_id.cmp(&left.record_id))
    });
    exemplars.dedup_by(|left, right| left.source_revision_id == right.source_revision_id);
    exemplars.truncate(STUDIO_EXEMPLAR_DISCOVERY_LIMIT);
    Ok(exemplars)
}

async fn resolve_selected_skills_with_client(
    client: &mut PublicApiClient<Channel>,
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: Arc<dyn InferenceRuntime>,
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
) -> Result<Vec<StudioArtifactSelectedSkill>, String> {
    let mut accumulators = HashMap::<[u8; 32], StudioSkillAccumulator>::new();

    for (need_index, need) in blueprint.skill_needs.iter().enumerate() {
        let need_id = format!("{}-{}", skill_kind_label(need.kind), need_index + 1);
        let query = build_skill_need_query(brief, blueprint, artifact_ir, need, &need_id);
        let embedding = inference_runtime
            .embed_text(&query)
            .await
            .map_err(|error| format!("Failed to embed Studio skill query: {}", error))?;
        let hits = memory_runtime
            .semantic_search_archival_memory(&SemanticArchivalMemoryQuery {
                scope: SKILL_ARCHIVAL_SCOPE.to_string(),
                thread_id: None,
                text_filter: None,
                embedding,
                limit: STUDIO_SKILL_DISCOVERY_LIMIT * 2,
            })
            .map_err(|error| format!("Failed to search Studio skill corpus: {}", error))?;

        for hit in hits {
            let Some(skill_hash) = skill_hash_from_archival_record(&hit.record) else {
                continue;
            };
            let Some(record_bytes) =
                query_raw_state(client, get_skill_record_key(&skill_hash)).await?
            else {
                continue;
            };
            let Ok(record) = codec::from_bytes_canonical::<SkillRecord>(&record_bytes) else {
                continue;
            };
            if !skill_is_runtime_eligible(&record) {
                continue;
            }
            let published_doc = if let Some(doc_bytes) =
                query_raw_state(client, get_skill_doc_key(&skill_hash)).await?
            {
                codec::from_bytes_canonical::<PublishedSkillDoc>(&doc_bytes).ok()
            } else {
                None
            };
            let stats = if let Some(stats_bytes) =
                query_raw_state(client, get_skill_stats_key(&skill_hash)).await?
            {
                codec::from_bytes_canonical::<SkillStats>(&stats_bytes).ok()
            } else {
                None
            };
            let reliability = skill_reliability_score(record.benchmark.as_ref(), stats.as_ref());
            let adjusted_score = adjusted_skill_discovery_score(hit.score, reliability);
            let entry = accumulators
                .entry(skill_hash)
                .or_insert_with(|| StudioSkillAccumulator {
                    name: record.macro_body.definition.name.clone(),
                    description: record.macro_body.definition.description.clone(),
                    lifecycle_state: format!("{:?}", record.lifecycle_state).to_ascii_lowercase(),
                    source_type: format!("{:?}", record.source_type).to_ascii_lowercase(),
                    reliability_bps: score_bps(reliability),
                    semantic_score_bps: score_bps(hit.score),
                    adjusted_score_bps: score_bps(adjusted_score),
                    relative_path: normalized_relative_path(published_doc.as_ref(), &record),
                    matched_need_ids: Vec::new(),
                    matched_need_kinds: Vec::new(),
                    match_rationale: need.rationale.clone(),
                    guidance_markdown: Some(skill_guidance_markdown(
                        &record,
                        published_doc.as_ref(),
                    )),
                    required_matches: 0,
                });
            entry.semantic_score_bps = entry.semantic_score_bps.max(score_bps(hit.score));
            entry.adjusted_score_bps = entry.adjusted_score_bps.max(score_bps(adjusted_score));
            entry.reliability_bps = entry.reliability_bps.max(score_bps(reliability));
            if !entry.matched_need_ids.iter().any(|value| value == &need_id) {
                entry.matched_need_ids.push(need_id.clone());
            }
            if !entry
                .matched_need_kinds
                .iter()
                .any(|kind| *kind == need.kind)
            {
                entry.matched_need_kinds.push(need.kind);
            }
            if need.priority == StudioArtifactSkillNeedPriority::Required {
                entry.required_matches += 1;
            }
            entry.match_rationale = format!(
                "Matched {} from the {} scaffold with {} reliability.",
                entry
                    .matched_need_kinds
                    .iter()
                    .map(|kind| skill_kind_label(*kind))
                    .collect::<Vec<_>>()
                    .join(", "),
                blueprint.scaffold_family,
                entry.reliability_bps,
            );
        }
    }

    let selected = accumulators
        .into_iter()
        .map(|(skill_hash, accumulator)| {
            let required_matches = accumulator.required_matches;
            let coverage = accumulator.matched_need_ids.len();
            (
                required_matches,
                coverage,
                StudioArtifactSelectedSkill {
                    skill_hash: hex::encode(skill_hash),
                    name: accumulator.name,
                    description: accumulator.description,
                    lifecycle_state: accumulator.lifecycle_state,
                    source_type: accumulator.source_type,
                    reliability_bps: accumulator.reliability_bps,
                    semantic_score_bps: accumulator.semantic_score_bps,
                    adjusted_score_bps: accumulator.adjusted_score_bps,
                    relative_path: accumulator.relative_path,
                    matched_need_ids: accumulator.matched_need_ids,
                    matched_need_kinds: accumulator.matched_need_kinds,
                    match_rationale: accumulator.match_rationale,
                    guidance_markdown: accumulator.guidance_markdown,
                },
            )
        })
        .collect::<Vec<_>>();

    Ok(sort_and_truncate_selected_skills(selected))
}

#[cfg(test)]
#[path = "skills/tests.rs"]
mod tests;
