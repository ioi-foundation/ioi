// Path: crates/services/src/agentic/desktop/service/skills.rs

use super::DesktopAgentService;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{AgentMacro, AgentSkill, SkillStats};
use ioi_types::codec;
use ioi_types::error::TransactionError;
// [FIX] Import keys from local desktop module, not ioi_types
use crate::agentic::desktop::keys::{get_skill_stats_key, SKILL_INDEX_PREFIX, TRACE_PREFIX};
use hex;
use ioi_types::app::agentic::StepTrace;
use serde_json::Value;
use std::collections::HashSet;

pub async fn recall_skills(
    _service: &DesktopAgentService,
    state: &dyn StateAccess,
    goal: &str,
) -> Result<Vec<AgentSkill>, TransactionError> {
    let mut relevant_skills = Vec::new();
    let goal_lower = goal.to_lowercase();
    if let Ok(iter) = state.prefix_scan(SKILL_INDEX_PREFIX) {
        for item in iter {
            if let Ok((_, val_bytes)) = item {
                if let Ok(skill) = codec::from_bytes_canonical::<AgentSkill>(&val_bytes) {
                    let name_lower = skill.name.to_lowercase();
                    let desc_lower = skill.description.to_lowercase();
                    if goal_lower.contains(&name_lower)
                        || name_lower.contains(&goal_lower)
                        || desc_lower.contains(&goal_lower)
                    {
                        relevant_skills.push(skill);
                    }
                }
            }
        }
    }
    Ok(relevant_skills)
}

pub fn fetch_skill_macro(
    service: &DesktopAgentService,
    tool_name: &str,
) -> Option<(AgentMacro, [u8; 32])> {
    if let Some(store_mutex) = &service.scs {
        if let Ok(store) = store_mutex.lock() {
            let payloads = store.scan_skills();
            for p in payloads {
                if let Ok(skill) = codec::from_bytes_canonical::<AgentMacro>(&p) {
                    if skill.definition.name == tool_name
                        || skill.definition.name.ends_with(&format!("__{}", tool_name))
                    {
                        if let Ok(hash) = ioi_crypto::algorithms::hash::sha256(&p) {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(hash.as_ref());
                            return Some((skill, arr));
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn expand_macro(
    _service: &DesktopAgentService,
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

pub async fn update_skill_reputation(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    session_success: bool,
    block_height: u64,
) -> Result<(), TransactionError> {
    let _scs_mutex = service
        .scs
        .as_ref()
        .ok_or(TransactionError::Invalid("SCS required".into()))?;

    let prefix = [TRACE_PREFIX, session_id.as_slice()].concat();
    let mut unique_skills = HashSet::new();

    if let Ok(iter) = state.prefix_scan(&prefix) {
        for item in iter {
            if let Ok((_, val)) = item {
                if let Ok(trace) = codec::from_bytes_canonical::<StepTrace>(&val) {
                    if let Some(hash) = trace.skill_hash {
                        unique_skills.insert(hash);
                    }
                }
            }
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

        log::info!(
            "Skill 0x{} reliability: {:.2}",
            hex::encode(&hash[0..4]),
            stats.reliability()
        );
    }

    Ok(())
}
