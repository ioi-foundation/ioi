use crate::agentic::desktop::keys::get_skill_stats_key;
use crate::agentic::skill_registry::{
    load_skill_record, skill_hash_from_archival_record, skill_is_runtime_eligible,
    SKILL_ARCHIVAL_SCOPE,
};
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_memory::{MemoryRuntime, SemanticArchivalMemoryQuery};
use ioi_types::app::agentic::{LlmToolDefinition, SkillStats};
use ioi_types::codec;
use std::collections::HashSet;
use std::sync::Arc;

pub(super) async fn inject_skill_tools(
    state: &dyn StateAccess,
    memory_runtime: &MemoryRuntime,
    query: &str,
    runtime: Arc<dyn InferenceRuntime>,
    tools: &mut Vec<LlmToolDefinition>,
) {
    let query_vec = match runtime.embed_text(query).await {
        Ok(vector) => vector,
        Err(_) => return,
    };

    let candidates =
        match memory_runtime.semantic_search_archival_memory(&SemanticArchivalMemoryQuery {
            scope: SKILL_ARCHIVAL_SCOPE.to_string(),
            thread_id: None,
            text_filter: None,
            embedding: query_vec,
            limit: 10,
        }) {
            Ok(hits) => hits,
            Err(_) => return,
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

        let stats_key = get_skill_stats_key(&skill_hash);
        let reliability = if let Ok(Some(bytes)) = state.get(&stats_key) {
            if let Ok(stats) = codec::from_bytes_canonical::<SkillStats>(&bytes) {
                stats.reliability()
            } else {
                0.5
            }
        } else {
            0.5
        };

        let adjusted_score = hit.score + (reliability * 0.2);
        ranked_skills.push((
            adjusted_score,
            skill_record.macro_body.definition,
            reliability,
        ));
    }

    ranked_skills.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    for (_, def, rel) in ranked_skills.into_iter().take(5) {
        let mut def_with_stats = def;
        def_with_stats.description = format!(
            "{} (Reliability: {:.0}%)",
            def_with_stats.description,
            rel * 100.0
        );
        log::debug!(
            "Injecting Skill: {} (Reliability: {:.2})",
            def_with_stats.name,
            rel
        );
        tools.push(def_with_stats);
    }
}
