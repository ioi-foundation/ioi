use crate::agentic::desktop::keys::get_skill_stats_key;
use crate::agentic::skill_registry::{
    adjusted_skill_discovery_score, load_published_skill_doc, load_skill_record,
    skill_guidance_markdown, skill_hash_from_archival_record, skill_is_runtime_eligible,
    skill_reliability_score, SKILL_ARCHIVAL_SCOPE,
};
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_memory::{MemoryRuntime, SemanticArchivalMemoryQuery};
use ioi_types::app::agentic::{LlmToolDefinition, PublishedSkillDoc, SkillRecord, SkillStats};
use ioi_types::codec;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct DiscoveredSkillCandidate {
    pub definition: LlmToolDefinition,
    pub reliability: f32,
    pub adjusted_score: f32,
    pub guidance_markdown: String,
    pub relative_path: Option<String>,
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

fn load_skill_stats(state: &dyn StateAccess, skill_hash: &[u8; 32]) -> Option<SkillStats> {
    let stats_key = get_skill_stats_key(skill_hash);
    state
        .get(&stats_key)
        .ok()
        .flatten()
        .and_then(|bytes| codec::from_bytes_canonical::<SkillStats>(&bytes).ok())
}

pub(crate) async fn discover_skill_candidates(
    state: &dyn StateAccess,
    memory_runtime: &MemoryRuntime,
    query: &str,
    runtime: Arc<dyn InferenceRuntime>,
    limit: usize,
) -> Vec<DiscoveredSkillCandidate> {
    let trimmed_query = query.trim();
    if trimmed_query.is_empty() || limit == 0 {
        return Vec::new();
    }

    let query_vec = match runtime.embed_text(trimmed_query).await {
        Ok(vector) => vector,
        Err(_) => return Vec::new(),
    };

    let semantic_limit = limit.max(5).saturating_mul(2);
    let candidates =
        match memory_runtime.semantic_search_archival_memory(&SemanticArchivalMemoryQuery {
            scope: SKILL_ARCHIVAL_SCOPE.to_string(),
            thread_id: None,
            text_filter: None,
            embedding: query_vec,
            limit: semantic_limit,
        }) {
            Ok(hits) => hits,
            Err(_) => return Vec::new(),
        };

    let mut ranked_skills = Vec::new();
    let mut seen_skills = HashSet::new();

    for hit in candidates {
        let Some(skill_hash) = skill_hash_from_archival_record(&hit.record) else {
            continue;
        };
        if !seen_skills.insert(skill_hash) {
            continue;
        }

        let Some(skill_record) = load_skill_record(state, &skill_hash).ok().flatten() else {
            continue;
        };
        if !skill_is_runtime_eligible(&skill_record) {
            continue;
        }

        let stats = load_skill_stats(state, &skill_hash);
        let reliability = skill_reliability_score(skill_record.benchmark.as_ref(), stats.as_ref());
        let adjusted_score = adjusted_skill_discovery_score(hit.score, reliability);
        let published_doc = load_published_skill_doc(state, &skill_hash).ok().flatten();
        ranked_skills.push(DiscoveredSkillCandidate {
            definition: skill_record.macro_body.definition.clone(),
            reliability,
            adjusted_score,
            guidance_markdown: skill_guidance_markdown(&skill_record, published_doc.as_ref()),
            relative_path: normalized_relative_path(published_doc.as_ref(), &skill_record),
        });
    }

    ranked_skills.sort_by(|a, b| {
        b.adjusted_score
            .partial_cmp(&a.adjusted_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked_skills.truncate(limit);
    ranked_skills
}

pub(super) async fn inject_skill_tools(
    state: &dyn StateAccess,
    memory_runtime: &MemoryRuntime,
    query: &str,
    runtime: Arc<dyn InferenceRuntime>,
    tools: &mut Vec<LlmToolDefinition>,
) {
    for candidate in discover_skill_candidates(state, memory_runtime, query, runtime, 5).await {
        let mut def_with_stats = candidate.definition;
        def_with_stats.description = format!(
            "{} (Reliability: {:.0}%)",
            def_with_stats.description,
            candidate.reliability * 100.0
        );
        log::debug!(
            "Injecting Skill: {} (Reliability: {:.2})",
            def_with_stats.name,
            candidate.reliability
        );
        tools.push(def_with_stats);
    }
}
