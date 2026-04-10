use crate::agentic::runtime::agent_playbooks::playbook_route_contract;
use crate::agentic::runtime::types::{
    AgentPlaybookDefinition, AgentPlaybookStepDefinition, ParentPlaybookRun, ParentPlaybookStepRun,
    ParentPlaybookStepStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParentPlaybookRouteReceiptMetadata {
    pub(crate) route_family: String,
    pub(crate) topology: String,
    pub(crate) planner_authority: String,
    pub(crate) verifier_state: String,
    pub(crate) verifier_role: String,
    pub(crate) verifier_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParentPlaybookPrepReceiptMetadata {
    pub(crate) selected_skills: Vec<String>,
    pub(crate) prep_summary: Option<String>,
}

fn playbook_step_is_verifier(step: &AgentPlaybookStepDefinition) -> bool {
    step.worker_template_id.trim() == "verifier"
        || matches!(
            step.worker_workflow_id.trim(),
            "artifact_quality_audit"
                | "postcondition_audit"
                | "browser_postcondition_audit"
                | "citation_audit"
                | "targeted_test_audit"
        )
}

fn parent_playbook_verifier_state(
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
) -> &'static str {
    let verifier_indices = playbook
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| playbook_step_is_verifier(step).then_some(index))
        .collect::<Vec<_>>();
    if verifier_indices.is_empty() {
        return "not_engaged";
    }

    let mut any_running = false;
    let mut any_blocked = false;
    let mut all_completed = true;

    for index in verifier_indices {
        let status = run
            .steps
            .get(index)
            .map(|step| step.status)
            .unwrap_or(ParentPlaybookStepStatus::Pending);
        match status {
            ParentPlaybookStepStatus::Running => {
                any_running = true;
                all_completed = false;
            }
            ParentPlaybookStepStatus::Completed => {}
            ParentPlaybookStepStatus::Blocked | ParentPlaybookStepStatus::Failed => {
                any_blocked = true;
                all_completed = false;
            }
            ParentPlaybookStepStatus::Pending => {
                all_completed = false;
            }
        }
    }

    if any_blocked {
        "blocked"
    } else if any_running {
        "active"
    } else if all_completed {
        "passed"
    } else {
        "queued"
    }
}

fn normalize_verifier_outcome(value: Option<&str>) -> &'static str {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "ok" | "ready" => "pass",
        "blocked" | "failed" | "unsafe" => "blocked",
        _ => "warning",
    }
}

fn step_verifier_outcome(step: &ParentPlaybookStepRun) -> Option<&'static str> {
    if let Some(scorecard) = step.research_scorecard.as_ref() {
        return Some(normalize_verifier_outcome(Some(scorecard.verdict.as_str())));
    }
    if let Some(scorecard) = step.coding_scorecard.as_ref() {
        return Some(normalize_verifier_outcome(Some(scorecard.verdict.as_str())));
    }
    if let Some(scorecard) = step.computer_use_verification.as_ref() {
        return Some(normalize_verifier_outcome(Some(scorecard.verdict.as_str())));
    }
    if let Some(scorecard) = step.artifact_quality.as_ref() {
        return Some(normalize_verifier_outcome(Some(scorecard.verdict.as_str())));
    }
    None
}

fn parent_playbook_verifier_outcome(
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
) -> &'static str {
    let verifier_indices = playbook
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| playbook_step_is_verifier(step).then_some(index))
        .collect::<Vec<_>>();
    if verifier_indices.is_empty() {
        return "";
    }

    let mut any_pending_or_running = false;
    let mut any_blocked = false;
    let mut latest_terminal_outcome: Option<&'static str> = None;

    for index in verifier_indices {
        let step = run.steps.get(index);
        let status = step
            .map(|value| value.status)
            .unwrap_or(ParentPlaybookStepStatus::Pending);
        match status {
            ParentPlaybookStepStatus::Running | ParentPlaybookStepStatus::Pending => {
                any_pending_or_running = true;
            }
            ParentPlaybookStepStatus::Blocked | ParentPlaybookStepStatus::Failed => {
                any_blocked = true;
            }
            ParentPlaybookStepStatus::Completed => {}
        }
        if let Some(step) = step {
            if let Some(outcome) = step_verifier_outcome(step) {
                latest_terminal_outcome = Some(outcome);
            }
        }
    }

    if any_blocked {
        "blocked"
    } else if any_pending_or_running {
        ""
    } else {
        latest_terminal_outcome.unwrap_or("warning")
    }
}

pub(crate) fn build_parent_playbook_route_receipt_metadata(
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
) -> ParentPlaybookRouteReceiptMetadata {
    let route_contract = playbook_route_contract(&run.playbook_id);
    ParentPlaybookRouteReceiptMetadata {
        route_family: route_contract.route_family.to_string(),
        topology: route_contract.topology.to_string(),
        planner_authority: route_contract.planner_authority.to_string(),
        verifier_state: parent_playbook_verifier_state(playbook, run).to_string(),
        verifier_role: route_contract.verifier_role.unwrap_or("").to_string(),
        verifier_outcome: parent_playbook_verifier_outcome(playbook, run).to_string(),
    }
}

pub(crate) fn build_parent_playbook_prep_receipt_metadata(
    run: &ParentPlaybookRun,
) -> ParentPlaybookPrepReceiptMetadata {
    let mut seen = std::collections::BTreeSet::new();
    let mut selected_skills = Vec::new();
    let mut prep_summary = None;

    for step in &run.steps {
        for skill in &step.selected_skills {
            let trimmed = skill.trim();
            if trimmed.is_empty() {
                continue;
            }
            let dedupe_key = trimmed.to_ascii_lowercase();
            if seen.insert(dedupe_key) {
                selected_skills.push(trimmed.to_string());
            }
        }

        if prep_summary.is_none() {
            prep_summary = step
                .prep_summary
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
        }
    }

    ParentPlaybookPrepReceiptMetadata {
        selected_skills,
        prep_summary,
    }
}
