// Path: crates/services/src/agentic/runtime/service/skills.rs

use super::RuntimeAgentService;
use crate::agentic::runtime::keys::{
    get_skill_session_outcome_key, get_skill_stats_key, TRACE_PREFIX,
};
use crate::agentic::runtime::tools::skills::discover_skill_candidates;
use crate::agentic::skill_registry::{
    build_benchmark_report, generate_published_skill_doc, load_doc_catalog_index,
    load_published_skill_doc, load_skill_catalog_index, load_skill_record, next_lifecycle_state,
    now_ms, skill_is_runtime_eligible, upsert_published_skill_doc, upsert_skill_record,
};
use hex;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::StepTrace;
use ioi_types::app::agentic::{
    AgentMacro, AgentSkill, PublishedSkillDoc, SkillBenchmarkReport, SkillLifecycleState,
    SkillRecord, SkillStats,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::Value;
use std::collections::HashSet;

pub async fn recall_skills(
    service: &RuntimeAgentService,
    state: &dyn StateAccess,
    goal: &str,
) -> Result<Vec<AgentSkill>, TransactionError> {
    if let Some(memory_runtime) = service.memory_runtime.as_ref() {
        let semantic_matches = discover_skill_candidates(
            state,
            memory_runtime,
            goal,
            service.reasoning_inference.clone(),
            4,
        )
        .await;
        if !semantic_matches.is_empty() {
            return Ok(semantic_matches
                .into_iter()
                .map(|candidate| AgentSkill {
                    name: candidate.definition.name,
                    description: format!(
                        "{} (Reliability: {:.0}%)",
                        candidate.definition.description,
                        candidate.reliability * 100.0
                    ),
                    content: candidate.guidance_markdown,
                    resources: candidate.relative_path.into_iter().collect(),
                })
                .collect());
        }
    }

    let mut relevant_skills = Vec::new();
    let goal_lower = goal.to_lowercase();
    let doc_index = load_doc_catalog_index(state)?;
    for hash in doc_index.skills {
        let Some(doc) = load_published_skill_doc(state, &hash)? else {
            continue;
        };
        let name_lower = doc.name.to_lowercase();
        let markdown_lower = doc.markdown.to_lowercase();
        if goal_lower.contains(&name_lower)
            || name_lower.contains(&goal_lower)
            || markdown_lower.contains(&goal_lower)
        {
            relevant_skills.push(agent_skill_from_published_doc(&doc));
        }
    }
    Ok(relevant_skills)
}

pub fn fetch_skill_macro(
    _service: &RuntimeAgentService,
    state: &dyn StateAccess,
    tool_name: &str,
) -> Option<(AgentMacro, [u8; 32])> {
    let index = load_skill_catalog_index(state).ok()?;
    let mut best_match: Option<(AgentMacro, [u8; 32], SkillBenchmarkReport)> = None;
    for hash in index.skills {
        let Some(record) = load_skill_record(state, &hash).ok().flatten() else {
            continue;
        };
        if !skill_is_runtime_eligible(&record) {
            continue;
        }
        let name = record.macro_body.definition.name.as_str();
        if name != tool_name && !name.ends_with(&format!("__{}", tool_name)) {
            continue;
        }
        let benchmark = record.benchmark.clone().unwrap_or_default();
        match &best_match {
            Some((_, _, existing)) if existing.success_rate_bps > benchmark.success_rate_bps => {}
            _ => best_match = Some((record.macro_body.clone(), hash, benchmark)),
        }
    }
    best_match.map(|(macro_body, hash, _)| (macro_body, hash))
}

pub fn expand_macro(
    _service: &RuntimeAgentService,
    skill: &AgentMacro,
    args: &serde_json::Map<String, Value>,
) -> Result<Vec<ioi_types::app::ActionRequest>, TransactionError> {
    let mut expanded_steps = Vec::new();

    for step in &skill.steps {
        let mut params_json: Value = serde_json::from_slice(&step.params)
            .map_err(|e| TransactionError::Serialization(e.to_string()))?;

        interpolate_values(&mut params_json, args);

        let new_params = serde_json::to_vec(&params_json)
            .map_err(|e| TransactionError::Serialization(e.to_string()))?;

        let mut new_step = step.clone();
        new_step.params = new_params;
        new_step.nonce = 0;

        expanded_steps.push(new_step);
    }

    Ok(expanded_steps)
}

fn interpolate_values(target: &mut Value, args: &serde_json::Map<String, Value>) {
    match target {
        Value::String(s) => {
            if s.starts_with("{{") && s.ends_with("}}") {
                let key = &s[2..s.len() - 2];
                if let Some(val) = args.get(key) {
                    *target = val.clone();
                    return;
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                interpolate_values(item, args);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                interpolate_values(val, args);
            }
        }
        _ => {}
    }
}

fn agent_skill_from_published_doc(doc: &PublishedSkillDoc) -> AgentSkill {
    AgentSkill {
        name: doc.name.clone(),
        description: format!(
            "Generated skill doc for {} (hash: 0x{})",
            doc.name,
            hex::encode(&doc.skill_hash[..4])
        ),
        content: doc.markdown.clone(),
        resources: vec![],
    }
}

pub fn fetch_session_traces(
    state: &dyn StateAccess,
    session_id: [u8; 32],
) -> Result<Vec<StepTrace>, TransactionError> {
    let prefix = [TRACE_PREFIX, session_id.as_slice()].concat();
    let mut traces = Vec::new();
    if let Ok(iter) = state.prefix_scan(&prefix) {
        for item in iter {
            if let Ok((_, bytes)) = item {
                if let Ok(trace) = codec::from_bytes_canonical::<StepTrace>(&bytes) {
                    traces.push(trace);
                }
            }
        }
    }
    traces.sort_by_key(|trace| trace.step_index);
    Ok(traces)
}

pub async fn update_skill_reputation(
    _service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    session_success: bool,
    block_height: u64,
) -> Result<(), TransactionError> {
    let session_outcome_key = get_skill_session_outcome_key(&session_id);
    if state.get(&session_outcome_key)?.is_some() {
        return Ok(());
    }

    let mut unique_skills = HashSet::new();
    for trace in fetch_session_traces(state, session_id)? {
        if let Some(hash) = trace.skill_hash {
            unique_skills.insert(hash);
        }
    }

    if unique_skills.is_empty() {
        return Ok(());
    }

    log::info!(
        "Updating reputation for {} skills used in session (Success: {})",
        unique_skills.len(),
        session_success
    );

    for hash in unique_skills {
        let key = get_skill_stats_key(&hash);
        let mut stats: SkillStats = if let Some(bytes) = state.get(&key)? {
            codec::from_bytes_canonical(&bytes).unwrap_or_default()
        } else {
            SkillStats::default()
        };

        stats.uses += 1;
        stats.last_used_height = block_height;

        if session_success {
            stats.successes += 1;
        } else {
            stats.failures += 1;
        }

        let estimated_cost = 1000;
        stats.avg_cost =
            (stats.avg_cost * (stats.uses as u64 - 1) + estimated_cost) / stats.uses as u64;

        state.insert(&key, &codec::to_bytes_canonical(&stats)?)?;

        if let Some(mut record) = load_skill_record(state, &hash)? {
            let previous_state = record.lifecycle_state;
            let benchmark = build_benchmark_report(&stats, block_height);
            record.benchmark = Some(benchmark.clone());
            record.lifecycle_state = next_lifecycle_state(record.lifecycle_state, &benchmark);
            record.updated_at = now_ms();
            if record.lifecycle_state == SkillLifecycleState::Promoted {
                let (doc, publication) = generate_published_skill_doc(&record)?;
                record.publication = Some(publication);
                upsert_published_skill_doc(state, &doc)?;
            } else if let Some(publication) = record.publication.as_mut() {
                publication.stale = true;
            }
            upsert_skill_record(state, &record)?;
            refresh_published_doc_state(state, &record, previous_state)?;
        }

        log::info!(
            "Skill 0x{} reliability: {:.2}",
            hex::encode(&hash[0..4]),
            stats.reliability()
        );
    }

    state.insert(
        &session_outcome_key,
        &codec::to_bytes_canonical(&session_success)?,
    )?;

    Ok(())
}

fn refresh_published_doc_state(
    state: &mut dyn StateAccess,
    record: &SkillRecord,
    previous_state: SkillLifecycleState,
) -> Result<(), TransactionError> {
    let Some(mut doc) = load_published_skill_doc(state, &record.skill_hash)? else {
        return Ok(());
    };
    doc.lifecycle_state = record.lifecycle_state;
    doc.source_evidence_hash = record.source_evidence_hash;
    doc.generated_at = record
        .publication
        .as_ref()
        .map(|publication| publication.generated_at)
        .unwrap_or(doc.generated_at);
    doc.generator_version = record
        .publication
        .as_ref()
        .map(|publication| publication.generator_version.clone())
        .unwrap_or_else(|| doc.generator_version.clone());
    doc.doc_hash = record
        .publication
        .as_ref()
        .map(|publication| publication.doc_hash)
        .unwrap_or(doc.doc_hash);
    doc.relative_path = record
        .publication
        .as_ref()
        .map(|publication| publication.relative_path.clone())
        .unwrap_or_else(|| doc.relative_path.clone());
    doc.stale = record
        .publication
        .as_ref()
        .map(|publication| publication.stale)
        .unwrap_or(
            previous_state == SkillLifecycleState::Promoted
                && record.lifecycle_state != SkillLifecycleState::Promoted,
        );
    upsert_published_skill_doc(state, &doc)
}
