use crate::agentic::desktop::types::{
    AgentPlaybookDefinition, AgentPlaybookStepDefinition, WorkerCompletionContract, WorkerMergeMode,
};
use ioi_types::app::agentic::{LlmToolDefinition, ResolvedIntentState};

fn normalized_query_text(query: &str) -> String {
    let normalized_chars = query
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>();
    format!(
        " {} ",
        normalized_chars
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn query_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn query_requests_code_change_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    let code_action = query_contains_any(
        &normalized,
        &[
            " fix ",
            " patch ",
            " implement ",
            " refactor ",
            " port ",
            " bug ",
            " regression ",
            " code ",
            " write ",
            " add ",
            " update ",
            " modify ",
            " edit ",
            " failing test ",
            " failing tests ",
            " broken test ",
            " broken tests ",
            " compile error ",
        ],
    );
    let code_context = query_contains_any(
        &normalized,
        &[
            " repo ",
            " repository ",
            " codebase ",
            " function ",
            " module ",
            " component ",
            " class ",
            " method ",
            " crate ",
            " rust ",
            " typescript ",
            " javascript ",
            " python ",
            " test ",
            " tests ",
            " file ",
            " source ",
            " workspace ",
        ],
    );
    code_action && code_context
}

fn query_requests_research_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    query_contains_any(
        &normalized,
        &[
            " research ",
            " investigate ",
            " look up ",
            " find sources ",
            " gather evidence ",
            " latest ",
            " current ",
            " compare sources ",
            " fact check ",
            " fact-check ",
        ],
    )
}

fn query_requests_verification_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    query_contains_any(
        &normalized,
        &[
            " verify ",
            " verification ",
            " validate ",
            " validation ",
            " check ",
            " double check ",
            " double-check ",
            " audit ",
            " review ",
            " confirm ",
            " inspect ",
            " parity ",
        ],
    )
}

pub fn builtin_agent_playbooks() -> Vec<AgentPlaybookDefinition> {
    vec![AgentPlaybookDefinition {
        playbook_id: "evidence_audited_patch".to_string(),
        label: "Evidence-Audited Patch".to_string(),
        summary:
            "Higher-order parent playbook for LocalAI-style issue work: gather current evidence, land a narrow patch, then audit whether the requested postcondition actually holds."
                .to_string(),
        goal_template:
            "Close {topic} by first gathering current evidence, then applying a narrow workspace patch, then auditing whether the requested postcondition now holds."
                .to_string(),
        trigger_intents: vec!["workspace.ops".to_string(), "delegation.task".to_string()],
        recommended_for: vec![
            "Ports, parity work, and bugfixes that need evidence gathering before coding and an explicit audit afterward."
                .to_string(),
            "Complex code changes where the parent should keep planner authority while bounded workers handle research, implementation, and verification."
                .to_string(),
        ],
        default_budget: 196,
        completion_contract: WorkerCompletionContract {
            success_criteria:
                "Return a parent-level handoff that includes the research brief, implementation summary, verification command outcomes, and a final postcondition verdict."
                    .to_string(),
            expected_output:
                "Evidence-backed implementation handoff with cited constraints, patch summary, and audit verdict."
                    .to_string(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: Some(
                "Parent confirms the research brief informed the patch, the patch verification commands ran, and the audit verdict actually resolves the requested postcondition."
                    .to_string(),
            ),
        },
        steps: vec![
            AgentPlaybookStepDefinition {
                step_id: "research".to_string(),
                label: "Research current state".to_string(),
                summary:
                    "Bound the task with current evidence, cited constraints, and open questions before any patch lands."
                        .to_string(),
                worker_template_id: "researcher".to_string(),
                worker_workflow_id: "live_research_brief".to_string(),
                goal_template:
                    "Research {topic} using current web, workspace, and local memory evidence, then return a cited brief with constraints, uncertainties, and next checks."
                        .to_string(),
                depends_on: Vec::new(),
            },
            AgentPlaybookStepDefinition {
                step_id: "implement".to_string(),
                label: "Patch the workspace".to_string(),
                summary:
                    "Apply the narrowest viable code change informed by the evidence brief and run focused verification commands."
                        .to_string(),
                worker_template_id: "coder".to_string(),
                worker_workflow_id: "patch_build_verify".to_string(),
                goal_template:
                    "Implement {topic} as a narrow workspace patch informed by the evidence brief, run focused verification commands, and return touched files, command results, and residual risk."
                        .to_string(),
                depends_on: vec!["research".to_string()],
            },
            AgentPlaybookStepDefinition {
                step_id: "audit".to_string(),
                label: "Audit the postcondition".to_string(),
                summary:
                    "Collapse the final proof: inspect receipts, diff evidence, and focused verification output, then issue a pass/fail verdict."
                        .to_string(),
                worker_template_id: "verifier".to_string(),
                worker_workflow_id: "postcondition_audit".to_string(),
                goal_template:
                    "Verify whether {topic} now holds by inspecting the patch handoff, receipts, and focused verification evidence, then return a pass/fail audit with blockers and next checks."
                        .to_string(),
                depends_on: vec!["implement".to_string()],
            },
        ],
    }]
}

pub fn builtin_agent_playbook(playbook_id: Option<&str>) -> Option<AgentPlaybookDefinition> {
    let playbook_id = playbook_id
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    builtin_agent_playbooks()
        .into_iter()
        .find(|playbook| playbook.playbook_id == playbook_id)
}

pub fn recommended_agent_playbook(
    goal: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Option<AgentPlaybookDefinition> {
    let resolved_intent = resolved_intent?;
    let intent_id = resolved_intent.intent_id.trim();
    if !matches!(intent_id, "workspace.ops" | "delegation.task") {
        return None;
    }
    let code_change = query_requests_code_change_work(goal);
    let evidence_heavy =
        query_requests_research_work(goal) || query_requests_verification_work(goal);
    if code_change && (evidence_heavy || goal.to_ascii_lowercase().contains("port")) {
        builtin_agent_playbook(Some("evidence_audited_patch"))
    } else {
        None
    }
}

pub fn render_agent_playbook_catalog(
    tools: &[LlmToolDefinition],
    goal: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Option<String> {
    let supports_delegation = tools.iter().any(|tool| tool.name == "agent__delegate");
    if !supports_delegation {
        return None;
    }

    let mut lines = vec!["[PARENT PLAYBOOKS]".to_string()];
    if let Some(recommended) = recommended_agent_playbook(goal, resolved_intent) {
        lines.push(format!(
            "Recommended now: `{}` for code-change tasks that need current evidence before the patch and an explicit audit after it.",
            recommended.playbook_id
        ));
    }

    for playbook in builtin_agent_playbooks() {
        lines.push(format!(
            "- `{}` -> {} Trigger intents: {}. Budget {}. Final merge `{}`. Expected output: {}.",
            playbook.playbook_id,
            playbook.summary,
            if playbook.trigger_intents.is_empty() {
                "none".to_string()
            } else {
                playbook.trigger_intents.join(", ")
            },
            playbook.default_budget,
            playbook.completion_contract.merge_mode.as_label(),
            playbook.completion_contract.expected_output
        ));
        lines.push(format!("  Goal template: {}", playbook.goal_template));
        for step in playbook.steps {
            let dependency_suffix = if step.depends_on.is_empty() {
                String::new()
            } else {
                format!(" depends on {}", step.depends_on.join(", "))
            };
            lines.push(format!(
                "  Step `{}` -> {}/{}{}: {} Goal template: {}",
                step.step_id,
                step.worker_template_id,
                step.worker_workflow_id,
                dependency_suffix,
                step.summary,
                step.goal_template
            ));
        }
    }

    Some(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::{
        builtin_agent_playbooks, recommended_agent_playbook, render_agent_playbook_catalog,
    };
    use ioi_types::app::agentic::{
        CapabilityId, IntentConfidenceBand, IntentScopeProfile, LlmToolDefinition,
        ResolvedIntentState,
    };

    fn workspace_ops_intent() -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "workspace.ops".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::High,
            score: 0.98,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("filesystem.patch")],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "medium".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: None,
            constrained: false,
        }
    }

    #[test]
    fn builtin_agent_playbook_catalog_contains_evidence_audited_patch() {
        let playbook = builtin_agent_playbooks()
            .into_iter()
            .find(|entry| entry.playbook_id == "evidence_audited_patch")
            .expect("evidence-audited patch playbook should exist");
        assert_eq!(playbook.steps.len(), 3);
        assert_eq!(playbook.steps[0].worker_template_id, "researcher");
        assert_eq!(playbook.steps[0].worker_workflow_id, "live_research_brief");
        assert_eq!(playbook.steps[1].worker_template_id, "coder");
        assert_eq!(playbook.steps[1].worker_workflow_id, "patch_build_verify");
        assert_eq!(playbook.steps[2].worker_template_id, "verifier");
        assert_eq!(playbook.steps[2].worker_workflow_id, "postcondition_audit");
    }

    #[test]
    fn recommends_evidence_audited_patch_for_port_with_verification() {
        let recommendation = recommended_agent_playbook(
            "Port the LocalAI parity fix in the Rust crate, research the current behavior, patch the workspace, and verify the postcondition.",
            Some(&workspace_ops_intent()),
        )
        .expect("playbook should be recommended");
        assert_eq!(recommendation.playbook_id, "evidence_audited_patch");
    }

    #[test]
    fn render_agent_playbook_catalog_includes_recommendation_and_steps() {
        let rendered = render_agent_playbook_catalog(
            &[LlmToolDefinition {
                name: "agent__delegate".to_string(),
                description: "Spawn a bounded child worker.".to_string(),
                parameters: "{}".to_string(),
            }],
            "Port the LocalAI parity fix in the Rust crate, research the current behavior, patch the workspace, and verify the postcondition.",
            Some(&workspace_ops_intent()),
        )
        .expect("catalog should render");

        assert!(rendered.contains("[PARENT PLAYBOOKS]"));
        assert!(rendered.contains("Recommended now: `evidence_audited_patch`"));
        assert!(rendered.contains("researcher/live_research_brief"));
        assert!(rendered.contains("coder/patch_build_verify"));
        assert!(rendered.contains("verifier/postcondition_audit"));
    }
}
