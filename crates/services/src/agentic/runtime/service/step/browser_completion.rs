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
mod tests {
    use super::browser_snapshot_completion;
    use crate::agentic::runtime::types::{AgentMode, AgentState, ExecutionTier};
    use ioi_types::app::agentic::{
        CapabilityId, InstructionContract, InstructionSideEffectMode, IntentConfidenceBand,
        IntentScopeProfile, ResolvedIntentState,
    };
    use std::collections::{BTreeMap, VecDeque};

    fn resolved_ui_interaction(
        side_effect_mode: InstructionSideEffectMode,
        success_criteria: Vec<&str>,
    ) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "ui.interaction".to_string(),
            scope: IntentScopeProfile::UiInteraction,
            band: IntentConfidenceBand::High,
            score: 1.0,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("ui.interact")],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "visual_last".to_string(),
            matrix_version: "test".to_string(),
            embedding_model_id: String::new(),
            embedding_model_version: String::new(),
            similarity_function_id: String::new(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: String::new(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: Some(InstructionContract {
                operation: "click".to_string(),
                side_effect_mode,
                slot_bindings: vec![],
                negative_constraints: vec![],
                success_criteria: success_criteria.into_iter().map(str::to_string).collect(),
            }),
            constrained: false,
        }
    }

    fn agent_state_with_resolved_intent(resolved_intent: ResolvedIntentState) -> AgentState {
        AgentState {
            session_id: [9u8; 32],
            goal: "Click Mark complete so the status becomes done.".to_string(),
            transcript_root: [0u8; 32],
            status: crate::agentic::runtime::types::AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::default(),
            current_tier: ExecutionTier::default(),
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: Some(resolved_intent),
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    #[test]
    fn browser_snapshot_completion_matches_update_success_criteria() {
        let state = agent_state_with_resolved_intent(resolved_ui_interaction(
            InstructionSideEffectMode::Update,
            vec!["status_text.updated_to_done"],
        ));
        let snapshot = r#"
            <root id="root_dom_fallback_tree">
              <generic id="grp_done" name="done" />
              <button id="btn_mark_complete" name="Mark complete" />
            </root>
        "#;

        let completion =
            browser_snapshot_completion(&state, "browser__inspect", Some(snapshot)).unwrap();
        assert!(completion.summary.contains("operation=click"));
        assert!(completion
            .summary
            .contains("success_criteria=status_text.updated_to_done"));
        assert_eq!(
            completion.matched_success_criteria,
            vec!["status_text.updated_to_done".to_string()]
        );
    }

    #[test]
    fn browser_snapshot_completion_rejects_read_only_contracts() {
        let state = agent_state_with_resolved_intent(resolved_ui_interaction(
            InstructionSideEffectMode::ReadOnly,
            vec!["status_text.updated_to_done"],
        ));
        let snapshot = r#"<root><generic id="grp_done" name="done" /></root>"#;

        assert!(browser_snapshot_completion(&state, "browser__inspect", Some(snapshot)).is_none());
    }

    #[test]
    fn browser_snapshot_completion_rejects_unrecognized_success_criteria() {
        let state = agent_state_with_resolved_intent(resolved_ui_interaction(
            InstructionSideEffectMode::Update,
            vec!["mail.reply.completed"],
        ));
        let snapshot = r#"<root><generic id="grp_done" name="done" /></root>"#;

        assert!(browser_snapshot_completion(&state, "browser__inspect", Some(snapshot)).is_none());
    }

    #[test]
    fn browser_snapshot_completion_requires_ui_interaction_scope() {
        let mut resolved = resolved_ui_interaction(
            InstructionSideEffectMode::Update,
            vec!["status_text.updated_to_done"],
        );
        resolved.scope = IntentScopeProfile::Conversation;
        let state = agent_state_with_resolved_intent(resolved);
        let snapshot = r#"<root><generic id="grp_done" name="done" /></root>"#;

        assert!(browser_snapshot_completion(&state, "browser__inspect", Some(snapshot)).is_none());
    }
}
