use crate::agentic::runtime::types::AgentState;
use ioi_types::app::agentic::{InstructionSideEffectMode, IntentScopeProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserSnapshotCompletion {
    pub(crate) summary: String,
    pub(crate) matched_success_criteria: Vec<String>,
}

fn normalize_semantic_text(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn browser_snapshot_contains_value(snapshot_xml: &str, value: &str) -> bool {
    let normalized_snapshot = normalize_semantic_text(snapshot_xml);
    let normalized_value = normalize_semantic_text(value);
    if normalized_snapshot.is_empty() || normalized_value.is_empty() {
        return false;
    }

    let padded_snapshot = format!(" {} ", normalized_snapshot);
    let padded_value = format!(" {} ", normalized_value);
    padded_snapshot.contains(&padded_value)
}

fn criterion_expected_value(criterion: &str) -> Option<String> {
    let trimmed = criterion.trim();
    for marker in [
        ".updated_to_",
        ".changed_to_",
        ".set_to_",
        ".becomes_",
        ".equals_",
        ".is_",
    ] {
        if let Some((_, value)) = trimmed.rsplit_once(marker) {
            let normalized = value.trim().replace('_', " ");
            if !normalized.is_empty() {
                return Some(normalized);
            }
        }
    }
    None
}

pub(crate) fn browser_snapshot_completion(
    agent_state: &AgentState,
    tool_name: &str,
    snapshot_output: Option<&str>,
) -> Option<BrowserSnapshotCompletion> {
    if tool_name != "browser__inspect" || agent_state.pending_search_completion.is_some() {
        return None;
    }

    let resolved = agent_state.resolved_intent.as_ref()?;
    if resolved.scope != IntentScopeProfile::UiInteraction {
        return None;
    }

    let instruction_contract = resolved.instruction_contract.as_ref()?;
    if !matches!(
        instruction_contract.side_effect_mode,
        InstructionSideEffectMode::DraftOnly
            | InstructionSideEffectMode::Send
            | InstructionSideEffectMode::Create
            | InstructionSideEffectMode::Update
            | InstructionSideEffectMode::Delete
    ) {
        return None;
    }

    let snapshot_output = snapshot_output?.trim();
    if snapshot_output.is_empty() || instruction_contract.success_criteria.is_empty() {
        return None;
    }

    let mut matched_success_criteria = Vec::new();
    for criterion in &instruction_contract.success_criteria {
        let expected_value = criterion_expected_value(criterion)?;
        if !browser_snapshot_contains_value(snapshot_output, &expected_value) {
            return None;
        }
        matched_success_criteria.push(criterion.trim().to_string());
    }

    if matched_success_criteria.is_empty() {
        return None;
    }

    let operation = instruction_contract.operation.trim();
    let summary = if operation.is_empty() {
        format!(
            "Verified requested browser state in page snapshot (success_criteria={}). Task completed.",
            matched_success_criteria.join(",")
        )
    } else {
        format!(
            "Verified requested browser state in page snapshot (operation={}; success_criteria={}). Task completed.",
            operation,
            matched_success_criteria.join(",")
        )
    };

    Some(BrowserSnapshotCompletion {
        summary,
        matched_success_criteria,
    })
}

#[cfg(test)]
#[path = "browser_completion/tests.rs"]
mod tests;
