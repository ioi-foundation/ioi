use crate::agentic::runtime::agent_playbooks::playbook_route_contract;
use crate::agentic::runtime::execution::workload;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::WorkerAssignment;
use ioi_api::state::StateAccess;
use ioi_types::app::WorkloadReceipt;
use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub(crate) struct DelegatedChildPrepBundle {
    pub selected_skills: Vec<String>,
    pub prep_summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DelegatedPrepMode {
    Research,
    Coding,
    Artifact,
    ComputerUse,
}

pub(crate) fn delegated_prep_mode(assignment: &WorkerAssignment) -> Option<DelegatedPrepMode> {
    match assignment
        .playbook_id
        .as_deref()
        .map(playbook_route_contract)
        .map(|contract| contract.route_family)
    {
        Some("research") => return Some(DelegatedPrepMode::Research),
        Some("coding")
            if matches!(
                assignment.workflow_id.as_deref().map(str::trim),
                Some("repo_context_brief" | "patch_build_verify")
            ) || matches!(
                assignment.template_id.as_deref().map(str::trim),
                Some("context_worker" | "coder")
            ) =>
        {
            return Some(DelegatedPrepMode::Coding);
        }
        Some("artifacts")
            if matches!(
                assignment.workflow_id.as_deref().map(str::trim),
                Some("artifact_context_brief" | "artifact_generate_repair")
            ) || matches!(
                assignment.template_id.as_deref().map(str::trim),
                Some("context_worker" | "artifact_builder")
            ) =>
        {
            return Some(DelegatedPrepMode::Artifact);
        }
        Some("computer_use")
            if matches!(
                assignment.workflow_id.as_deref().map(str::trim),
                Some("ui_state_brief" | "browser_postcondition_pass")
            ) || matches!(
                assignment.template_id.as_deref().map(str::trim),
                Some("perception_worker" | "browser_operator")
            ) =>
        {
            return Some(DelegatedPrepMode::ComputerUse);
        }
        _ => {}
    }

    if matches!(
        assignment.workflow_id.as_deref().map(str::trim),
        Some("live_research_brief")
    ) || matches!(
        assignment.template_id.as_deref().map(str::trim),
        Some("researcher")
    ) {
        return Some(DelegatedPrepMode::Research);
    }

    if matches!(
        assignment.workflow_id.as_deref().map(str::trim),
        Some("repo_context_brief" | "patch_build_verify")
    ) || matches!(
        assignment.template_id.as_deref().map(str::trim),
        Some("context_worker" | "coder")
    ) {
        return Some(DelegatedPrepMode::Coding);
    }

    if matches!(
        assignment.workflow_id.as_deref().map(str::trim),
        Some("artifact_context_brief" | "artifact_generate_repair")
    ) || matches!(
        assignment.template_id.as_deref().map(str::trim),
        Some("artifact_builder")
    ) {
        return Some(DelegatedPrepMode::Artifact);
    }

    if matches!(
        assignment.workflow_id.as_deref().map(str::trim),
        Some("ui_state_brief" | "browser_postcondition_pass")
    ) || matches!(
        assignment.template_id.as_deref().map(str::trim),
        Some("perception_worker" | "browser_operator")
    ) {
        return Some(DelegatedPrepMode::ComputerUse);
    }

    None
}

fn summarize_prep_output(output: &str) -> Option<String> {
    let lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(2)
        .collect::<Vec<_>>();
    let snippet_first = lines
        .iter()
        .filter_map(|line| {
            line.split_once("Snippet: ")
                .or_else(|| line.split_once("Summary: "))
                .or_else(|| line.split_once("Likely files: "))
                .or_else(|| line.split_once("Targeted checks: "))
                .map(|(_, tail)| tail.trim().trim_matches('"').trim_end_matches("..."))
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let preview = if snippet_first.is_empty() {
        lines.join(" ")
    } else {
        snippet_first.join(" ")
    };
    let trimmed = preview.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut summary: String = trimmed.chars().take(260).collect();
    if trimmed.chars().count() > 260 {
        summary.push_str("...");
    }
    Some(summary)
}

fn prep_workload_id(
    parent_session_id: [u8; 32],
    step_index: u32,
    assignment: &WorkerAssignment,
    mode: DelegatedPrepMode,
) -> String {
    let preview: String = assignment.goal.chars().take(96).collect();
    let prefix = match mode {
        DelegatedPrepMode::Research => "research-prep",
        DelegatedPrepMode::Coding => "coding-prep",
        DelegatedPrepMode::Artifact => "artifact-prep",
        DelegatedPrepMode::ComputerUse => "computer-use-prep",
    };
    workload::compute_workload_id(
        parent_session_id,
        step_index,
        "memory__search",
        &format!("{prefix} {preview}"),
    )
}

fn fallback_prep_summary(mode: DelegatedPrepMode, retrieval_succeeded: bool) -> String {
    match (mode, retrieval_succeeded) {
        (DelegatedPrepMode::Research, true) => {
            "No matching local memory retrieved before spawn.".to_string()
        }
        (DelegatedPrepMode::Research, false) => {
            "Local memory retrieval unavailable before spawn.".to_string()
        }
        (DelegatedPrepMode::Coding, true) => {
            "No matching repo memory retrieved before spawn; context worker will inspect the workspace directly."
                .to_string()
        }
        (DelegatedPrepMode::Coding, false) => {
            "Repo memory retrieval unavailable before spawn; context worker will rely on direct workspace inspection."
                .to_string()
        }
        (DelegatedPrepMode::Artifact, true) => {
            "No matching artifact memory retrieved before spawn; the context worker will shape the brief directly."
                .to_string()
        }
        (DelegatedPrepMode::Artifact, false) => {
            "Artifact memory retrieval unavailable before spawn; the context worker will rely on direct brief inspection."
                .to_string()
        }
        (DelegatedPrepMode::ComputerUse, true) => {
            "No matching UI-state memory retrieved before spawn; the perception worker will inspect the live surface directly."
                .to_string()
        }
        (DelegatedPrepMode::ComputerUse, false) => {
            "UI-state memory retrieval unavailable before spawn; the perception worker will rely on direct surface inspection."
                .to_string()
        }
    }
}

fn prep_log_label(mode: DelegatedPrepMode) -> &'static str {
    match mode {
        DelegatedPrepMode::Research => "research",
        DelegatedPrepMode::Coding => "coding",
        DelegatedPrepMode::Artifact => "artifact",
        DelegatedPrepMode::ComputerUse => "computer-use",
    }
}

pub(super) async fn build_delegated_child_prep_bundle(
    service: &RuntimeAgentService,
    state: &dyn StateAccess,
    parent_session_id: [u8; 32],
    step_index: u32,
    assignment: &WorkerAssignment,
) -> DelegatedChildPrepBundle {
    let Some(mode) = delegated_prep_mode(assignment) else {
        return DelegatedChildPrepBundle::default();
    };

    let selected_skills = match service.recall_skills(state, &assignment.goal).await {
        Ok(skills) => {
            let mut seen = HashSet::new();
            skills
                .into_iter()
                .map(|skill| skill.name.trim().to_string())
                .filter(|name| !name.is_empty())
                .filter(|name| seen.insert(name.to_ascii_lowercase()))
                .take(4)
                .collect()
        }
        Err(error) => {
            log::warn!(
                "Failed to recall {} prep skills for delegated child {}: {}",
                prep_log_label(mode),
                hex::encode(&parent_session_id[..4]),
                error
            );
            Vec::new()
        }
    };

    let retrieval = service
        .retrieve_context_hybrid_with_receipt(&assignment.goal, None)
        .await;
    if let (Some(tx), Some(receipt)) = (&service.event_sender, retrieval.receipt.clone()) {
        workload::emit_workload_receipt(
            tx,
            parent_session_id,
            step_index,
            prep_workload_id(parent_session_id, step_index, assignment, mode),
            WorkloadReceipt::MemoryRetrieve(receipt),
        );
    }

    let prep_summary = summarize_prep_output(&retrieval.output).or_else(|| {
        Some(fallback_prep_summary(
            mode,
            retrieval
                .receipt
                .as_ref()
                .map(|receipt| receipt.success)
                .unwrap_or(false),
        ))
    });

    DelegatedChildPrepBundle {
        selected_skills,
        prep_summary,
    }
}
