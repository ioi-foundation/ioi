use crate::agentic::desktop::keys::get_skill_stats_key;
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_scs::{FrameType, SovereignContextStore};
use ioi_types::app::agentic::AgentMacro;
use ioi_types::app::agentic::{LlmToolDefinition, SkillStats};
use ioi_types::codec;
use std::sync::Arc;

pub(super) async fn inject_skill_tools(
    state: &dyn StateAccess,
    scs: &std::sync::Mutex<SovereignContextStore>,
    query: &str,
    runtime: Arc<dyn InferenceRuntime>,
    tools: &mut Vec<LlmToolDefinition>,
) {
    // Skill Discovery via Semantic Search + Reputation Ranking (RSI)
    if let Ok(query_vec) = runtime.embed_text(query).await {
        // A. Get Candidates from Vector Index
        let candidates = {
            if let Ok(store) = scs.lock() {
                if let Ok(index_arc) = store.get_vector_index() {
                    if let Ok(index) = index_arc.lock() {
                        if let Some(idx) = index.as_ref() {
                            idx.search_hybrid(&query_vec, 10).unwrap_or_default()
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        };

        // B. Re-Rank based on Reputation (RSI)
        // We fetch stats for each candidate from the State.
        let mut ranked_skills = Vec::new();

        for (frame_id, distance, f_type, visual_hash) in candidates {
            if f_type != FrameType::Skill {
                continue;
            }

            // Fetch stats
            let stats_key = get_skill_stats_key(&visual_hash);
            let reliability = if let Ok(Some(bytes)) = state.get(&stats_key) {
                if let Ok(s) = codec::from_bytes_canonical::<SkillStats>(&bytes) {
                    s.reliability()
                } else {
                    0.5 // Default (Laplace smoothing baseline)
                }
            } else {
                0.5
            };

            // Adjusted Score: Lower distance is better.
            // We subtract reliability from distance (bonus).
            let adjusted_score = distance - (reliability * 0.2);

            // Retrieve definition
            if let Ok(store) = scs.lock() {
                if let Ok(payload) = store.read_frame_payload(frame_id) {
                    if let Ok(skill) = codec::from_bytes_canonical::<AgentMacro>(&payload) {
                        ranked_skills.push((adjusted_score, skill.definition, reliability));
                    }
                }
            }
        }

        // Sort by adjusted score (ascending)
        ranked_skills.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        // Take top 5
        for (_, def, rel) in ranked_skills.into_iter().take(5) {
            let mut def_with_stats = def;
            // Append reliability to description so the LLM knows it's a good tool.
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
}
