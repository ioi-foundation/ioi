use crate::agentic::desktop::agent_playbooks::playbook_route_contract;
use crate::agentic::desktop::execution::workload;
use crate::agentic::desktop::keys::{
    get_incident_key, get_remediation_key, get_state_key, AGENT_POLICY_PREFIX,
};
use crate::agentic::desktop::service::step::signals::infer_interaction_target;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, SessionSummary, WorkerAssignment,
};
use crate::agentic::desktop::utils::persist_agent_state;
use crate::agentic::desktop::worker_templates::builtin_worker_workflow;
use crate::agentic::desktop::worker_templates::default_worker_role_label;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{
    ArgumentOrigin, CapabilityId, InstructionBindingKind, InstructionContract,
    InstructionSideEffectMode, InstructionSlotBinding, IntentConfidenceBand, IntentScopeProfile,
    ProtectedSlotKind, ResolvedIntentState,
};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, KernelEvent, WorkloadReceipt};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use super::{
    load_worker_assignment, persist_worker_assignment, register_parent_playbook_step_spawn,
    resolve_worker_assignment,
};

const PARENT_PLAYBOOK_CONTEXT_MARKER: &str = "[PARENT PLAYBOOK CONTEXT]";

#[derive(Debug, Clone)]
pub struct DelegatedChildSpawnOutcome {
    pub child_session_id: [u8; 32],
    pub assignment: WorkerAssignment,
}

#[derive(Debug, Clone, Default)]
pub struct DelegatedChildPrepBundle {
    pub selected_skills: Vec<String>,
    pub prep_summary: Option<String>,
}

fn resolve_worker_role(template_id: Option<&str>, requested_role: Option<&str>) -> String {
    requested_role
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| default_worker_role_label(template_id).to_string())
}

fn resolve_worker_name(role: &str, child_session_id: &[u8; 32]) -> String {
    let compact = role
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if compact.is_empty() {
        format!("Agent-{}", hex::encode(&child_session_id[0..2]))
    } else {
        format!("{}-{}", compact, hex::encode(&child_session_id[0..2]))
    }
}

fn split_parent_playbook_context(goal: &str) -> (&str, Option<&str>) {
    if let Some((head, tail)) = goal.split_once(PARENT_PLAYBOOK_CONTEXT_MARKER) {
        (head.trim(), Some(tail.trim()))
    } else {
        (goal.trim(), None)
    }
}

fn normalize_worker_context_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

fn extract_worker_context_field(text: &str, keys: &[&str]) -> Option<String> {
    let normalized_keys = keys
        .iter()
        .map(|key| normalize_worker_context_key(key))
        .collect::<Vec<_>>();
    for line in text.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches('-')
            .trim_start_matches('*')
            .trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        if normalized_keys
            .iter()
            .any(|candidate| *candidate == normalize_worker_context_key(key))
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn quoted_goal_literals(goal: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut current = String::new();
    let mut delimiter: Option<char> = None;

    for ch in goal.chars() {
        if let Some(active) = delimiter {
            if ch == active {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    literals.push(trimmed.to_string());
                }
                current.clear();
                delimiter = None;
            } else {
                current.push(ch);
            }
            continue;
        }

        if matches!(ch, '"' | '\'' | '`') {
            delimiter = Some(ch);
        }
    }

    literals
}

fn looks_like_command_literal(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lowered = trimmed.to_ascii_lowercase();
    lowered.contains("python")
        || lowered.contains("cargo")
        || lowered.contains("pytest")
        || lowered.contains("unittest")
        || lowered.contains("npm")
        || lowered.contains("pnpm")
        || lowered.contains("yarn")
        || lowered.contains("bash")
        || trimmed.contains(' ')
}

fn looks_like_file_hint(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(|ch| ch.is_whitespace()) {
        return false;
    }
    let normalized = trimmed.replace('\\', "/");
    let path = Path::new(trimmed);
    path.extension().is_some() || normalized.starts_with("tests/") || normalized.contains("/tests/")
}

fn parent_goal_likely_files(goal: &str) -> Vec<String> {
    let (_, parent_context) = split_parent_playbook_context(goal);
    if let Some(value) =
        parent_context.and_then(|text| extract_worker_context_field(text, &["likely_files"]))
    {
        return value
            .split(';')
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
            .map(str::to_string)
            .collect();
    }

    let mut seen = HashSet::new();
    quoted_goal_literals(goal)
        .into_iter()
        .map(|literal| literal.trim().to_string())
        .filter(|literal| looks_like_file_hint(literal))
        .filter(|literal| seen.insert(literal.to_ascii_lowercase()))
        .collect()
}

fn parent_goal_targeted_checks(goal: &str) -> Option<String> {
    let (_, parent_context) = split_parent_playbook_context(goal);
    if let Some(value) = parent_context.and_then(|text| {
        extract_worker_context_field(
            text,
            &[
                "targeted_checks",
                "targeted_check",
                "verification_plan",
                "verification",
            ],
        )
    }) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    quoted_goal_literals(goal)
        .into_iter()
        .find(|literal| looks_like_command_literal(literal))
}

fn enrich_patch_build_verify_goal_with_parent_context(parent_goal: &str, raw_goal: &str) -> String {
    let (raw_head, raw_context) = split_parent_playbook_context(raw_goal);
    let raw_context_text = raw_context.unwrap_or("");
    let parent_head = split_parent_playbook_context(parent_goal).0;
    let mut context_lines = raw_context
        .map(|text| {
            text.lines()
                .map(str::trim_end)
                .filter(|line| !line.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut added = false;

    if !parent_head.is_empty()
        && extract_worker_context_field(
            raw_context_text,
            &["delegated_task_contract", "task_contract", "parent_goal"],
        )
        .is_none()
        && !raw_goal.contains(parent_head)
    {
        context_lines.push(format!("- delegated_task_contract: {parent_head}"));
        added = true;
    }

    if extract_worker_context_field(raw_context_text, &["likely_files"]).is_none() {
        let likely_files = parent_goal_likely_files(parent_goal);
        if !likely_files.is_empty() {
            context_lines.push(format!("- likely_files: {}", likely_files.join("; ")));
            added = true;
        }
    }

    if extract_worker_context_field(
        raw_context_text,
        &[
            "targeted_checks",
            "targeted_check",
            "verification_plan",
            "verification",
        ],
    )
    .is_none()
    {
        if let Some(targeted_checks) = parent_goal_targeted_checks(parent_goal) {
            context_lines.push(format!("- targeted_checks: {targeted_checks}"));
            added = true;
        }
    }

    if !added {
        return raw_goal.to_string();
    }

    let head = if raw_head.is_empty() {
        raw_goal.trim()
    } else {
        raw_head
    };
    format!(
        "{}\n\n{}\n{}",
        head,
        PARENT_PLAYBOOK_CONTEXT_MARKER,
        context_lines.join("\n")
    )
}

fn enrich_delegated_child_goal(
    parent_goal: &str,
    raw_goal: &str,
    workflow_id: Option<&str>,
) -> String {
    if workflow_id.map(str::trim) == Some("patch_build_verify") {
        enrich_patch_build_verify_goal_with_parent_context(parent_goal, raw_goal)
    } else {
        raw_goal.to_string()
    }
}

fn normalize_existing_goal_path(candidate: &str) -> Option<PathBuf> {
    let trimmed = candidate
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ',' | ';' | ')'));
    if trimmed.is_empty() {
        return None;
    }

    let path = PathBuf::from(trimmed);
    let metadata = std::fs::metadata(&path).ok()?;
    if metadata.is_dir() {
        Some(path)
    } else {
        path.parent().map(Path::to_path_buf)
    }
}

pub(crate) fn infer_delegated_child_working_directory(
    parent_working_directory: &str,
    goal: &str,
) -> String {
    for literal in quoted_goal_literals(goal) {
        if let Some(path) = normalize_existing_goal_path(&literal) {
            return path.to_string_lossy().to_string();
        }
    }

    let parent_trimmed = parent_working_directory.trim();
    if parent_trimmed.is_empty() {
        ".".to_string()
    } else {
        parent_trimmed.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DelegatedPrepMode {
    Research,
    Coding,
    Artifact,
}

fn delegated_prep_mode(assignment: &WorkerAssignment) -> Option<DelegatedPrepMode> {
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
                Some("repo_context_brief")
            ) || matches!(
                assignment.template_id.as_deref().map(str::trim),
                Some("context_worker")
            ) =>
        {
            return Some(DelegatedPrepMode::Coding);
        }
        Some("artifacts")
            if matches!(
                assignment.workflow_id.as_deref().map(str::trim),
                Some("artifact_context_brief")
            ) || matches!(
                assignment.template_id.as_deref().map(str::trim),
                Some("context_worker")
            ) =>
        {
            return Some(DelegatedPrepMode::Artifact);
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
        Some("repo_context_brief")
    ) || matches!(
        assignment.template_id.as_deref().map(str::trim),
        Some("context_worker")
    ) {
        return Some(DelegatedPrepMode::Coding);
    }

    if matches!(
        assignment.workflow_id.as_deref().map(str::trim),
        Some("artifact_context_brief")
    ) {
        return Some(DelegatedPrepMode::Artifact);
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
    }
}

fn prep_log_label(mode: DelegatedPrepMode) -> &'static str {
    match mode {
        DelegatedPrepMode::Research => "research",
        DelegatedPrepMode::Coding => "coding",
        DelegatedPrepMode::Artifact => "artifact",
    }
}

fn delegated_research_bootstrap_query(goal: &str) -> Option<String> {
    let trimmed = goal.trim().trim_end_matches(['.', '!', '?']);
    if trimmed.is_empty() {
        return None;
    }

    let mut topic = trimmed.to_string();
    let lowercase = topic.to_ascii_lowercase();
    for prefix in ["research ", "investigate ", "look up ", "find "] {
        if lowercase.starts_with(prefix) {
            let suffix = topic[prefix.len()..]
                .trim_start_matches([':', '-', ' '])
                .trim();
            if !suffix.is_empty() {
                topic = suffix.to_string();
            }
            break;
        }
    }

    let lowercase = topic.to_ascii_lowercase();
    for marker in [
        " using current web",
        " using web",
        " and local memory",
        " then return",
        " then write",
        " then produce",
    ] {
        if let Some(index) = lowercase.find(marker) {
            let candidate = topic[..index].trim();
            if !candidate.is_empty() {
                topic = candidate.to_string();
            }
            break;
        }
    }

    let normalized = topic.trim().trim_end_matches(['.', '!', '?']).trim();
    (!normalized.is_empty()).then(|| normalized.to_string())
}

fn delegated_child_contract_slot(slot: &str, value: &str) -> InstructionSlotBinding {
    InstructionSlotBinding {
        slot: slot.to_string(),
        binding_kind: InstructionBindingKind::UserLiteral,
        value: Some(value.to_string()),
        origin: ArgumentOrigin::ModelInferred,
        protected_slot_kind: ProtectedSlotKind::Unknown,
    }
}

fn delegated_child_contract_slots(
    assignment: &WorkerAssignment,
    workflow_id: Option<&str>,
) -> Vec<InstructionSlotBinding> {
    let mut slot_bindings = Vec::new();
    if let Some(playbook_id) = assignment
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        slot_bindings.push(delegated_child_contract_slot("playbook_id", playbook_id));
    }
    if let Some(template_id) = assignment
        .template_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        slot_bindings.push(delegated_child_contract_slot("template_id", template_id));
    }
    if let Some(workflow_id) = workflow_id {
        slot_bindings.push(delegated_child_contract_slot("workflow_id", workflow_id));
    }
    slot_bindings
}

fn queue_delegated_child_web_search(
    child_state: &mut AgentState,
    child_session_id: [u8; 32],
    query: &str,
    query_contract: &str,
) -> Result<bool, TransactionError> {
    let trimmed_query = query.trim();
    if trimmed_query.is_empty() {
        return Ok(false);
    }
    let trimmed_contract = query_contract.trim();
    let params = serde_jcs::to_vec(&json!({
        "query": trimmed_query,
        "query_contract": (!trimmed_contract.is_empty()).then_some(trimmed_contract),
        "limit": 15,
    }))
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::WebRetrieve,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(child_session_id),
            window_id: None,
        },
        nonce: child_state.step_count as u64 + child_state.execution_queue.len() as u64 + 1,
    };
    let duplicate = child_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    child_state.execution_queue.insert(0, request);
    Ok(true)
}

fn complete_delegated_child_immediately(child_state: &mut AgentState, result: &str) -> bool {
    let trimmed_result = result.trim();
    if trimmed_result.is_empty() {
        return false;
    }

    child_state.execution_queue.clear();
    child_state.status = AgentStatus::Completed(Some(trimmed_result.to_string()));
    true
}

fn extract_http_url_candidates(text: &str) -> BTreeSet<String> {
    let mut urls = BTreeSet::new();
    for token in text.split_whitespace() {
        let Some(start) = token.find("https://").or_else(|| token.find("http://")) else {
            continue;
        };
        let candidate = token[start..]
            .trim_matches(|ch: char| matches!(ch, ')' | ']' | '}' | ',' | ';' | '"' | '\'' | '.'));
        let Ok(parsed) = Url::parse(candidate) else {
            continue;
        };
        if matches!(parsed.scheme(), "http" | "https") {
            urls.insert(parsed.to_string());
        }
    }
    urls
}

fn distinct_url_domain_count(urls: &BTreeSet<String>) -> usize {
    urls.iter()
        .filter_map(|url| Url::parse(url).ok())
        .filter_map(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .map(|host| host.trim_start_matches("www.").to_string())
        .collect::<BTreeSet<_>>()
        .len()
}

fn inherited_brief_has_temporal_anchor(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase();
    (normalized.contains("run date (utc):") && normalized.contains("run timestamp (utc):"))
        || normalized.contains("(as of ")
        || normalized.contains("freshness note:")
}

fn inherited_brief_has_evidence_sections(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase();
    normalized.contains("what happened:")
        && normalized.contains("key evidence:")
        && (normalized.contains("citations:") || normalized.contains("sources:"))
}

fn delegated_citation_audit_bootstrap_scorecard(goal: &str) -> Option<String> {
    let urls = extract_http_url_candidates(goal);
    if urls.is_empty() {
        return None;
    }

    let distinct_domain_count = distinct_url_domain_count(&urls);
    let source_count = urls.len();
    let freshness_passed = inherited_brief_has_temporal_anchor(goal);
    let quote_grounding_passed = inherited_brief_has_evidence_sections(goal) && source_count >= 2;
    let source_independence_passed = distinct_domain_count >= 2;
    let verdict = if freshness_passed && quote_grounding_passed && source_independence_passed {
        "passed"
    } else {
        "needs_attention"
    };
    let freshness_status = if freshness_passed {
        "passed"
    } else {
        "needs_attention"
    };
    let quote_grounding_status = if quote_grounding_passed {
        "passed"
    } else {
        "needs_attention"
    };
    let supporting_evidence = urls.iter().take(4).cloned().collect::<Vec<_>>().join("; ");
    let notes = if verdict == "passed" {
        format!(
            "Inherited cited brief already contains {} cited source(s) across {} distinct domain(s) with temporal anchoring and evidence sections.",
            source_count, distinct_domain_count
        )
    } else {
        let mut blockers = Vec::new();
        if !freshness_passed {
            blockers.push("missing temporal anchor");
        }
        if !quote_grounding_passed {
            blockers.push("missing evidence sections or cited-brief grounding");
        }
        if !source_independence_passed {
            blockers.push("source independence floor below 2 distinct domains");
        }
        format!(
            "Receipt-bound verifier bootstrap found: {}.",
            blockers.join(", ")
        )
    };

    Some(format!(
        "- verdict: {}\n- freshness_status: {}\n- quote_grounding_status: {}\n- notes: {}\n- supporting_evidence: cited_sources={}; distinct_domains={}; urls={}",
        verdict,
        freshness_status,
        quote_grounding_status,
        notes,
        source_count,
        distinct_domain_count,
        supporting_evidence
    ))
}

fn extract_prefixed_items(text: &str, prefixes: &[&str]) -> BTreeSet<String> {
    let mut items = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        for prefix in prefixes {
            if let Some(value) = trimmed.strip_prefix(prefix) {
                let value = value.trim();
                if !value.is_empty() {
                    items.insert(value.to_string());
                }
            }
        }
    }
    items
}

fn extract_prefixed_value(text: &str, prefixes: &[&str]) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        for prefix in prefixes {
            if let Some(value) = trimmed.strip_prefix(prefix) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn looks_like_executed_verification_item(value: &str) -> bool {
    let normalized = value.trim();
    if normalized.is_empty() {
        return false;
    }
    let lowered = normalized.to_ascii_lowercase();
    if !(lowered.contains("(passed)")
        || lowered.contains("(failed)")
        || lowered.contains(" exit_code=")
        || lowered.contains(" exit code ")
        || lowered.contains(" (ok)")
        || lowered.contains(" (error)"))
    {
        return false;
    }

    let command_fragment = normalized
        .split_once(" (")
        .map(|(head, _)| head)
        .unwrap_or(normalized)
        .trim();
    let lowered_command = command_fragment.to_ascii_lowercase();
    lowered_command.contains("python")
        || lowered_command.contains("cargo")
        || lowered_command.contains("pytest")
        || lowered_command.contains("unittest")
        || lowered_command.contains("npm")
        || lowered_command.contains("pnpm")
        || lowered_command.contains("yarn")
        || lowered_command.contains("bash")
        || lowered_command.starts_with("./")
}

fn delegated_targeted_test_audit_bootstrap_scorecard(goal: &str) -> Option<String> {
    let verification_items =
        extract_prefixed_items(goal, &["Verification:", "Targeted verification:"])
            .into_iter()
            .filter(|item| looks_like_executed_verification_item(item))
            .collect::<BTreeSet<_>>();
    if verification_items.is_empty() {
        return None;
    }

    let targeted_command_count = verification_items.len() as u32;
    let targeted_pass_count = verification_items
        .iter()
        .filter(|item| item.to_ascii_lowercase().contains("(passed)"))
        .count() as u32;
    let targeted_fail_count = verification_items
        .iter()
        .filter(|item| {
            let lowered = item.to_ascii_lowercase();
            lowered.contains("(failed)") || lowered.contains("(error)")
        })
        .count() as u32;
    if targeted_pass_count == 0 && targeted_fail_count == 0 {
        return None;
    }

    let normalized_goal = goal.to_ascii_lowercase();
    let widening_status = if targeted_fail_count > 0 {
        "blocked"
    } else if normalized_goal.contains("broader checks were rerun")
        || normalized_goal.contains("broader verification rerun")
        || normalized_goal.contains("widened coverage")
    {
        "performed"
    } else if normalized_goal.contains("broader checks were not rerun")
        || normalized_goal.contains("widen only if needed")
    {
        "not_needed"
    } else {
        "unknown"
    };
    let verdict = if targeted_fail_count > 0 {
        "needs_attention"
    } else if targeted_pass_count == targeted_command_count {
        "passed"
    } else {
        return None;
    };
    let regression_status = if verdict == "passed" {
        "clear"
    } else {
        "needs_attention"
    };
    let notes = extract_prefixed_value(goal, &["Residual risk:", "Notes:"]).unwrap_or_else(|| {
        if verdict == "passed" {
            "Inherited coding handoff already records focused verification passing without widened coverage.".to_string()
        } else {
            "Inherited coding handoff includes failing targeted verification and needs follow-up.".to_string()
        }
    });
    let supporting_evidence = verification_items
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");

    Some(format!(
        "- verdict: {}\n- targeted_command_count: {}\n- targeted_pass_count: {}\n- widening_status: {}\n- regression_status: {}\n- notes: {}\n- supporting_evidence: {}",
        verdict,
        targeted_command_count,
        targeted_pass_count,
        widening_status,
        regression_status,
        notes,
        supporting_evidence
    ))
}

fn count_compact_prefixed_items(items: &BTreeSet<String>) -> u32 {
    let mut normalized = BTreeSet::new();
    for item in items {
        for value in item.split(|ch| matches!(ch, ';' | ',' | '\n')) {
            let value = value.trim();
            if !value.is_empty() {
                normalized.insert(value.to_string());
            }
        }
    }
    normalized.len() as u32
}

fn normalize_delegated_patch_synthesis_status(value: &str) -> &'static str {
    match value.trim().to_ascii_lowercase().as_str() {
        "pass" | "passed" | "ok" | "ready" => "ready",
        "blocked" | "unsafe" => "blocked",
        _ => "needs_attention",
    }
}

fn delegated_patch_synthesis_bootstrap_summary(goal: &str) -> Option<String> {
    let touched_files = extract_prefixed_items(goal, &["Touched files:", "Touched file:"]);
    let touched_file_count = count_compact_prefixed_items(&touched_files);
    if touched_file_count == 0 {
        return None;
    }

    let verifier_verdict = extract_prefixed_value(goal, &["- verdict:", "verdict:"])?;
    let status = normalize_delegated_patch_synthesis_status(&verifier_verdict);
    let verification_ready = status == "ready";
    let notes = extract_prefixed_value(goal, &["- notes:", "notes:"]).unwrap_or_else(|| {
        if verification_ready {
            "Inherited verifier context already marks the focused coding handoff as passed."
                .to_string()
        } else {
            "Inherited verifier context still needs attention before the patch handoff is ready."
                .to_string()
        }
    });
    let residual_risk = extract_prefixed_value(
        goal,
        &["Residual risk:", "- residual_risk:", "residual_risk:"],
    )
    .unwrap_or_else(|| {
        if verification_ready {
            "Focused verification passed; broader checks were not rerun.".to_string()
        } else {
            "Verifier context is not yet ready, so the final patch handoff remains blocked."
                .to_string()
        }
    });

    Some(format!(
        "- status: {}\n- touched_file_count: {}\n- verification_ready: {}\n- notes: {}\n- residual_risk: {}",
        status,
        touched_file_count,
        if verification_ready { "yes" } else { "no" },
        notes,
        residual_risk
    ))
}

fn seed_delegated_child_execution_queue(
    child_state: &mut AgentState,
    child_session_id: [u8; 32],
    assignment: &WorkerAssignment,
) -> Result<(), TransactionError> {
    let workflow = builtin_worker_workflow(
        assignment.template_id.as_deref(),
        assignment.workflow_id.as_deref(),
    );
    let workflow_id = workflow
        .as_ref()
        .map(|workflow| workflow.workflow_id.as_str());

    if matches!(workflow_id, Some("live_research_brief")) {
        let Some(query) = delegated_research_bootstrap_query(&assignment.goal) else {
            return Ok(());
        };

        let _ = queue_delegated_child_web_search(
            child_state,
            child_session_id,
            &query,
            &assignment.goal,
        )?;
        return Ok(());
    }

    if matches!(workflow_id, Some("citation_audit")) {
        if let Some(scorecard) = delegated_citation_audit_bootstrap_scorecard(&assignment.goal) {
            let _ = complete_delegated_child_immediately(child_state, &scorecard);
        }
        return Ok(());
    }

    if matches!(workflow_id, Some("targeted_test_audit")) {
        if let Some(scorecard) = delegated_targeted_test_audit_bootstrap_scorecard(&assignment.goal)
        {
            let _ = complete_delegated_child_immediately(child_state, &scorecard);
        }
        return Ok(());
    }

    if matches!(workflow_id, Some("patch_synthesis_handoff")) {
        if let Some(summary) = delegated_patch_synthesis_bootstrap_summary(&assignment.goal) {
            let _ = complete_delegated_child_immediately(child_state, &summary);
        }
        return Ok(());
    }

    Ok(())
}

fn delegated_child_preset_resolved_intent(
    assignment: &WorkerAssignment,
) -> Option<ResolvedIntentState> {
    let workflow = builtin_worker_workflow(
        assignment.template_id.as_deref(),
        assignment.workflow_id.as_deref(),
    );
    let workflow_id = workflow
        .as_ref()
        .map(|workflow| workflow.workflow_id.as_str());
    let slot_bindings = delegated_child_contract_slots(assignment, workflow_id);

    match workflow_id {
        Some("patch_build_verify") => Some(ResolvedIntentState {
            intent_id: "workspace.ops".to_string(),
            scope: IntentScopeProfile::WorkspaceOps,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![
                CapabilityId::from("filesystem.read"),
                CapabilityId::from("filesystem.write"),
                CapabilityId::from("command.exec"),
                CapabilityId::from("command.probe"),
                CapabilityId::from("conversation.reply"),
            ],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            provider_selection: None,
            instruction_contract: Some(InstructionContract {
                operation: "workspace.ops".to_string(),
                side_effect_mode: InstructionSideEffectMode::Update,
                slot_bindings,
                negative_constraints: vec![
                    "Keep edits bounded to the delegated implementation slice, run the focused verifier commands before widening coverage, and do not replace executor evidence with chat-only summaries."
                        .to_string(),
                ],
                success_criteria: vec![
                    "Return a deterministic patch/build/test handoff with touched files, focused command results, and residual risk."
                        .to_string(),
                ],
            }),
            constrained: false,
        }),
        Some("live_research_brief") => Some(ResolvedIntentState {
            intent_id: "web.research".to_string(),
            scope: IntentScopeProfile::WebResearch,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![
                CapabilityId::from("web.retrieve"),
                CapabilityId::from("sys.time.read"),
                CapabilityId::from("memory.access"),
            ],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            provider_selection: None,
            instruction_contract: Some(InstructionContract {
                operation: "web.research".to_string(),
                side_effect_mode: InstructionSideEffectMode::ReadOnly,
                slot_bindings,
                negative_constraints: vec![
                    "Do not bypass typed web retrieval or answer from stale memory alone; use `web__search` and `web__read` for current evidence before completing the brief.".to_string(),
                ],
                success_criteria: vec![
                    "Return a cited research brief with findings, freshness notes, and unresolved questions or blockers.".to_string(),
                ],
            }),
            constrained: false,
        }),
        Some("citation_audit") => Some(ResolvedIntentState {
            intent_id: "delegation.task".to_string(),
            scope: IntentScopeProfile::Delegation,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("memory.access")],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            provider_selection: None,
            instruction_contract: Some(InstructionContract {
                operation: "verify".to_string(),
                side_effect_mode: InstructionSideEffectMode::ReadOnly,
                slot_bindings,
                negative_constraints: vec![
                    "Do not issue `memory__search` or raw web retrieval from the verifier lane; audit the inherited cited brief from receipt-bound context first and use `memory__inspect` only for a named evidence gap.".to_string(),
                ],
                success_criteria: vec![
                    "Return a deterministic citation-verifier scorecard with verdict, freshness_status, quote_grounding_status, notes, and supporting evidence.".to_string(),
                ],
            }),
            constrained: false,
        }),
        Some("targeted_test_audit") => Some(ResolvedIntentState {
            intent_id: "workspace.ops".to_string(),
            scope: IntentScopeProfile::WorkspaceOps,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![
                CapabilityId::from("filesystem.read"),
                CapabilityId::from("command.exec"),
                CapabilityId::from("command.probe"),
                CapabilityId::from("memory.access"),
            ],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            provider_selection: None,
            instruction_contract: Some(InstructionContract {
                operation: "verify".to_string(),
                side_effect_mode: InstructionSideEffectMode::ReadOnly,
                slot_bindings,
                negative_constraints: vec![
                    "Do not write files in the verifier lane; run the named targeted checks first, widen only if the evidence requires it, and keep regression risk separate from executor summaries.".to_string(),
                ],
                success_criteria: vec![
                    "Return a deterministic coding verifier scorecard with verdict, targeted command coverage, widening status, regression status, and clearly named blockers.".to_string(),
                ],
            }),
            constrained: false,
        }),
        Some("patch_synthesis_handoff") => Some(ResolvedIntentState {
            intent_id: "workspace.ops".to_string(),
            scope: IntentScopeProfile::WorkspaceOps,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![
                CapabilityId::from("filesystem.read"),
                CapabilityId::from("memory.access"),
            ],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [1u8; 32],
            receipt_hash: [2u8; 32],
            provider_selection: None,
            instruction_contract: Some(InstructionContract {
                operation: "synthesize".to_string(),
                side_effect_mode: InstructionSideEffectMode::ReadOnly,
                slot_bindings,
                negative_constraints: vec![
                    "Do not request clarification or rerun executor or verifier work when inherited parent evidence already names touched files, verification state, and residual risk; synthesize from the inherited handoff first and only inspect named files if a specific evidence gap remains.".to_string(),
                ],
                success_criteria: vec![
                    "Return a deterministic patch synthesis summary with status, touched files, verification readiness, notes, and residual risk.".to_string(),
                ],
            }),
            constrained: false,
        }),
        _ => None,
    }
}

async fn build_delegated_child_prep_bundle(
    service: &DesktopAgentService,
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

pub async fn spawn_delegated_child_session(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    tool_hash: [u8; 32],
    goal: &str,
    budget: u64,
    playbook_id: Option<&str>,
    template_id: Option<&str>,
    workflow_id: Option<&str>,
    requested_role: Option<&str>,
    success_criteria: Option<&str>,
    merge_mode: Option<&str>,
    expected_output: Option<&str>,
    step_index: u32,
    block_height: u64,
) -> Result<DelegatedChildSpawnOutcome, TransactionError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"ioi::agent_delegate_child::v1::");
    payload.extend_from_slice(parent_state.session_id.as_slice());
    payload.extend_from_slice(&step_index.to_le_bytes());
    payload.extend_from_slice(tool_hash.as_slice());

    let child_session_id = sha256(payload)
        .map_err(|e| TransactionError::Invalid(format!("Delegate hash failed: {}", e)))?;

    let child_key = get_state_key(&child_session_id);
    if state.get(&child_key)?.is_some() {
        if parent_state.child_session_ids.contains(&child_session_id) {
            let assignment = load_worker_assignment(state, child_session_id)
                .map_err(TransactionError::Invalid)?
                .ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "ERROR_CLASS=UnexpectedState Delegated child session {} exists without a worker assignment artifact.",
                        hex::encode(child_session_id)
                    ))
                })?;
            return Ok(DelegatedChildSpawnOutcome {
                child_session_id,
                assignment,
            });
        }

        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=UnexpectedState Delegated child session {} already exists but is not linked to parent session {}.",
            hex::encode(child_session_id),
            hex::encode(parent_state.session_id)
        )));
    }

    let enriched_goal = enrich_delegated_child_goal(&parent_state.goal, goal, workflow_id);
    let assignment = resolve_worker_assignment(
        child_session_id,
        step_index,
        budget,
        &enriched_goal,
        playbook_id,
        template_id,
        workflow_id,
        requested_role,
        success_criteria,
        merge_mode,
        expected_output,
    );

    if parent_state.budget < assignment.budget {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=UnexpectedState Insufficient parent budget for delegation (needed {}, have {}).",
            assignment.budget, parent_state.budget
        )));
    }

    let prep_bundle = build_delegated_child_prep_bundle(
        service,
        state,
        parent_state.session_id,
        step_index,
        &assignment,
    )
    .await;

    let target = infer_interaction_target(&assignment.goal);

    // Initialize transcript BEFORE mutating chain state so failures do not burn budget.
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let initial_message = ioi_types::app::agentic::ChatMessage {
        role: "user".to_string(),
        content: assignment.goal.clone(),
        timestamp: timestamp_ms,
        trace_hash: None,
    };
    let transcript_root = service
        .append_chat_to_scs(child_session_id, &initial_message, block_height)
        .await?;

    // Ensure stale remediation/incident metadata cannot leak across deterministic child ids.
    state.delete(&get_remediation_key(&child_session_id))?;
    state.delete(&get_incident_key(&child_session_id))?;

    let child_state = AgentState {
        session_id: child_session_id,
        goal: assignment.goal.clone(),
        transcript_root,
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: parent_state.max_steps,
        last_action_type: None,
        parent_session_id: Some(parent_state.session_id),
        child_session_ids: Vec::new(),
        budget: assignment.budget,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: Vec::new(),
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: Vec::new(),
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target,
        resolved_intent: delegated_child_preset_resolved_intent(&assignment),
        awaiting_intent_clarification: false,
        working_directory: infer_delegated_child_working_directory(
            &parent_state.working_directory,
            &assignment.goal,
        ),
        command_history: Default::default(),
        active_lens: None,
    };
    let mut child_state = child_state;
    seed_delegated_child_execution_queue(&mut child_state, child_session_id, &assignment)?;

    persist_agent_state(
        state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )?;
    let parent_policy_key = [AGENT_POLICY_PREFIX, parent_state.session_id.as_slice()].concat();
    let child_policy_key = [AGENT_POLICY_PREFIX, child_session_id.as_slice()].concat();
    if let Some(policy_bytes) = state.get(&parent_policy_key)? {
        state.insert(&child_policy_key, &policy_bytes)?;
    }
    persist_worker_assignment(state, child_session_id, &assignment)?;

    // Update session history if present; best-effort to avoid blocking delegation on history corruption.
    let history_key = b"agent::history".to_vec();
    let mut history: Vec<SessionSummary> = state
        .get(&history_key)?
        .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok())
        .unwrap_or_default();

    let title_line = assignment.goal.lines().next().unwrap_or("Agent Task");
    let title = if title_line.len() > 30 {
        format!("{}...", &title_line[..30])
    } else {
        title_line.to_string()
    };
    history.insert(
        0,
        SessionSummary {
            session_id: child_session_id,
            title,
            timestamp: timestamp_ms,
        },
    );
    if history.len() > 50 {
        history.truncate(50);
    }

    if let Ok(bytes) = codec::to_bytes_canonical(&history) {
        if let Err(e) = state.insert(&history_key, &bytes) {
            log::warn!(
                "Failed to update agent::history for delegated child session {}: {}",
                hex::encode(&child_session_id[..4]),
                e
            );
        }
    }

    parent_state.budget -= assignment.budget;
    parent_state.child_session_ids.push(child_session_id);
    register_parent_playbook_step_spawn(
        service,
        state,
        parent_state,
        step_index,
        child_session_id,
        &assignment,
        &prep_bundle,
    )
    .map_err(TransactionError::Invalid)?;

    if let Some(tx) = &service.event_sender {
        let resolved_role = resolve_worker_role(template_id, requested_role);
        let _ = tx.send(KernelEvent::AgentSpawn {
            parent_session_id: parent_state.session_id,
            new_session_id: child_session_id,
            name: resolve_worker_name(&resolved_role, &child_session_id),
            role: resolved_role,
            budget: assignment.budget,
            goal: assignment.goal.clone(),
        });
    }

    Ok(DelegatedChildSpawnOutcome {
        child_session_id,
        assignment,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        delegated_child_preset_resolved_intent, delegated_research_bootstrap_query,
        enrich_patch_build_verify_goal_with_parent_context,
        infer_delegated_child_working_directory, resolve_worker_name, resolve_worker_role,
        seed_delegated_child_execution_queue, PARENT_PLAYBOOK_CONTEXT_MARKER,
    };
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, ExecutionTier, WorkerAssignment,
    };
    use ioi_types::app::agentic::{CapabilityId, InstructionSideEffectMode, IntentScopeProfile};
    use ioi_types::app::ActionTarget;
    use tempfile::tempdir;

    #[test]
    fn researcher_template_defaults_to_research_worker_role() {
        assert_eq!(
            resolve_worker_role(Some("researcher"), None),
            "Research Worker"
        );
        assert_eq!(
            resolve_worker_role(Some("researcher"), Some("")),
            "Research Worker"
        );
        assert_eq!(
            resolve_worker_role(Some("researcher"), Some("Source Analyst")),
            "Source Analyst"
        );
    }

    #[test]
    fn worker_name_uses_role_prefix_when_available() {
        let child_session_id = [0xabu8; 32];
        let name = resolve_worker_name("Research Worker", &child_session_id);
        assert!(name.starts_with("Research-Worker-"));
    }

    #[test]
    fn delegated_child_working_directory_prefers_explicit_repo_path_from_goal() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("fixture-repo");
        std::fs::create_dir_all(&repo_root).expect("fixture repo should exist");

        let goal = format!(
            "Inspect repo context for the coding task in \"{}\" and keep `tests/test_path_utils.py` unchanged.",
            repo_root.display()
        );

        let inferred = infer_delegated_child_working_directory(".", &goal);
        assert_eq!(inferred, repo_root.to_string_lossy());
    }

    #[test]
    fn delegated_child_working_directory_falls_back_to_parent_directory() {
        let inferred = infer_delegated_child_working_directory(
            "/tmp/parent-workspace",
            "Research the current blockers and summarize them.",
        );

        assert_eq!(inferred, "/tmp/parent-workspace");
    }

    fn test_agent_state(goal: &str) -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: goal.to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 90,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: Default::default(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: Default::default(),
            active_lens: None,
        }
    }

    fn research_assignment(goal: &str) -> WorkerAssignment {
        WorkerAssignment {
            step_key: "delegate:0:abcd".to_string(),
            budget: 90,
            goal: goal.to_string(),
            success_criteria: "Return a cited research brief.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some([1u8; 32]),
            status: "running".to_string(),
            playbook_id: Some("citation_grounded_brief".to_string()),
            template_id: Some("researcher".to_string()),
            workflow_id: Some("live_research_brief".to_string()),
            role: Some("Research Worker".to_string()),
            allowed_tools: vec![
                "web__search".to_string(),
                "web__read".to_string(),
                "agent__complete".to_string(),
                "agent__await_result".to_string(),
            ],
            completion_contract: Default::default(),
        }
    }

    fn citation_audit_assignment(goal: &str) -> WorkerAssignment {
        WorkerAssignment {
            step_key: "delegate:1:beef".to_string(),
            budget: 48,
            goal: goal.to_string(),
            success_criteria: "Return a verifier scorecard.".to_string(),
            max_retries: 0,
            retries_used: 0,
            assigned_session_id: Some([2u8; 32]),
            status: "running".to_string(),
            playbook_id: Some("citation_grounded_brief".to_string()),
            template_id: Some("verifier".to_string()),
            workflow_id: Some("citation_audit".to_string()),
            role: Some("Verification Worker".to_string()),
            allowed_tools: vec![
                "memory__inspect".to_string(),
                "agent__complete".to_string(),
                "agent__await_result".to_string(),
            ],
            completion_contract: Default::default(),
        }
    }

    fn patch_build_verify_assignment(goal: &str) -> WorkerAssignment {
        WorkerAssignment {
            step_key: "delegate:2:cafe".to_string(),
            budget: 96,
            goal: goal.to_string(),
            success_criteria:
                "Return a deterministic implementation handoff with verification results."
                    .to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some([3u8; 32]),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "filesystem__read_file".to_string(),
                "filesystem__list_directory".to_string(),
                "filesystem__search".to_string(),
                "filesystem__patch".to_string(),
                "filesystem__edit_line".to_string(),
                "filesystem__write_file".to_string(),
                "sys__change_directory".to_string(),
                "sys__exec_session".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: Default::default(),
        }
    }

    fn targeted_test_audit_assignment(goal: &str) -> WorkerAssignment {
        WorkerAssignment {
            step_key: "delegate:3:feed".to_string(),
            budget: 56,
            goal: goal.to_string(),
            success_criteria: "Return a deterministic coding verifier scorecard.".to_string(),
            max_retries: 0,
            retries_used: 0,
            assigned_session_id: Some([4u8; 32]),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("verifier".to_string()),
            workflow_id: Some("targeted_test_audit".to_string()),
            role: Some("Verification Worker".to_string()),
            allowed_tools: vec![
                "filesystem__read_file".to_string(),
                "filesystem__list_directory".to_string(),
                "filesystem__search".to_string(),
                "memory__inspect".to_string(),
                "memory__search".to_string(),
                "sys__change_directory".to_string(),
                "sys__exec_session".to_string(),
                "agent__complete".to_string(),
                "agent__await_result".to_string(),
            ],
            completion_contract: Default::default(),
        }
    }

    fn patch_synthesis_assignment(goal: &str) -> WorkerAssignment {
        WorkerAssignment {
            step_key: "delegate:4:fade".to_string(),
            budget: 40,
            goal: goal.to_string(),
            success_criteria:
                "Return a deterministic patch synthesis summary with touched files and residual risk."
                    .to_string(),
            max_retries: 0,
            retries_used: 0,
            assigned_session_id: Some([5u8; 32]),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("patch_synthesizer".to_string()),
            workflow_id: Some("patch_synthesis_handoff".to_string()),
            role: Some("Patch Synthesizer".to_string()),
            allowed_tools: vec![
                "filesystem__read_file".to_string(),
                "filesystem__list_directory".to_string(),
                "filesystem__search".to_string(),
                "memory__inspect".to_string(),
                "memory__search".to_string(),
                "agent__complete".to_string(),
                "agent__await_result".to_string(),
            ],
            completion_contract: Default::default(),
        }
    }

    #[test]
    fn delegated_research_bootstrap_query_strips_worker_template_suffixes() {
        let query = delegated_research_bootstrap_query(
            "Research the latest NIST post-quantum cryptography standards using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.",
        )
        .expect("query should be derived");

        assert_eq!(query, "the latest NIST post-quantum cryptography standards");
    }

    #[test]
    fn live_research_worker_starts_with_seeded_web_search() {
        let goal = "Research the latest NIST post-quantum cryptography standards using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let mut child_state = test_agent_state(goal);
        let assignment = research_assignment(goal);

        seed_delegated_child_execution_queue(&mut child_state, [1u8; 32], &assignment)
            .expect("seed should succeed");

        assert_eq!(child_state.execution_queue.len(), 1);
        assert_eq!(
            child_state.execution_queue[0].target,
            ActionTarget::WebRetrieve
        );
        let args: serde_json::Value =
            serde_json::from_slice(&child_state.execution_queue[0].params)
                .expect("seeded search params should decode");
        assert_eq!(
            args.get("query").and_then(|value| value.as_str()),
            Some("the latest NIST post-quantum cryptography standards")
        );
    }

    #[test]
    fn citation_audit_worker_does_not_seed_memory_search() {
        let goal = "Verify whether the cited brief for the latest NIST post-quantum cryptography standards is current, grounded, and supported by independent sources, then return a citation verifier scorecard with blockers and next checks.";
        let mut child_state = test_agent_state(goal);
        let assignment = citation_audit_assignment(goal);

        seed_delegated_child_execution_queue(&mut child_state, [2u8; 32], &assignment)
            .expect("seed should succeed");

        assert!(child_state.execution_queue.is_empty());
    }

    #[test]
    fn citation_audit_worker_completes_immediately_when_handoff_is_auditable() {
        let goal = "Verify whether the cited brief for the latest NIST post-quantum cryptography standards is current, grounded, and sufficiently independent, then return a citation verifier scorecard with blockers and next checks.\n\n[PARENT PLAYBOOK CONTEXT]\n- Gather current sources full_handoff (research_full): Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-04-01T05:16:29Z UTC)\n\nWhat happened:\n- NIST's NCCoE draft migration practice guide remains a current public authority source for PQC migration activity.\n\nKey evidence:\n- NCCoE published the draft migration practice guide and IBM summarized the NIST cybersecurity framework updates.\n\nCitations:\n- Migration to Post-Quantum Cryptography Quantum Read-iness: Testing Draft Standards | https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf | 2026-04-01T05:16:29Z | retrieved_utc\n- IBM NIST cybersecurity framework summary | https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2 | 2026-04-01T05:16:29Z | retrieved_utc\n\nRun date (UTC): 2026-04-01\nRun timestamp (UTC): 2026-04-01T05:16:29Z\nOverall confidence: medium";
        let mut child_state = test_agent_state(goal);
        let assignment = citation_audit_assignment(goal);

        seed_delegated_child_execution_queue(&mut child_state, [2u8; 32], &assignment)
            .expect("seed should succeed");

        assert!(child_state.execution_queue.is_empty());
        let result = match &child_state.status {
            AgentStatus::Completed(Some(result)) => result.as_str(),
            other => panic!("expected completed verifier bootstrap, got {:?}", other),
        };
        assert!(result.contains("- verdict: passed"));
        assert!(result.contains("- freshness_status: passed"));
        assert!(result.contains("- quote_grounding_status: passed"));
        assert!(result.contains("distinct_domains=2"));
        assert!(result.contains("https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf"));
    }

    #[test]
    fn citation_audit_worker_bootstraps_to_delegation_intent() {
        let assignment = citation_audit_assignment("Verify the cited brief.");

        let resolved =
            delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

        assert_eq!(resolved.intent_id, "delegation.task");
        assert_eq!(resolved.scope, IntentScopeProfile::Delegation);
        assert_eq!(
            resolved.required_capabilities,
            vec![CapabilityId::from("memory.access")]
        );
        let contract = resolved
            .instruction_contract
            .as_ref()
            .expect("verifier child contract should be seeded");
        assert_eq!(contract.operation, "verify");
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "playbook_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("citation_grounded_brief")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "template_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("verifier")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "workflow_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("citation_audit")
        );
    }

    #[test]
    fn targeted_test_audit_worker_completes_immediately_when_handoff_is_auditable() {
        let goal = "Verify the coding result for Port the path-normalization parity fix by running targeted checks first, widen only if needed, and return a coding verifier scorecard with blockers and next checks.\n\n[PARENT PLAYBOOK CONTEXT]\n- Implement patch (implement): Worker evidence\nTouched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)\nResidual risk: Focused verification passed; broader checks were not rerun.\nVerification: Parent checks the concrete diff, verifies the named build or test commands, and confirms the delegated implementation slice is actually closed.";
        let mut child_state = test_agent_state(goal);
        let assignment = targeted_test_audit_assignment(goal);

        seed_delegated_child_execution_queue(&mut child_state, [4u8; 32], &assignment)
            .expect("seed should succeed");

        assert!(child_state.execution_queue.is_empty());
        let result = match &child_state.status {
            AgentStatus::Completed(Some(result)) => result.as_str(),
            other => panic!("expected completed verifier bootstrap, got {:?}", other),
        };
        assert!(result.contains("- verdict: passed"));
        assert!(result.contains("- targeted_command_count: 1"));
        assert!(result.contains("- targeted_pass_count: 1"));
        assert!(result.contains("- widening_status: not_needed"));
        assert!(result.contains("- regression_status: clear"));
        assert!(result.contains("python3 -m unittest tests.test_path_utils -v (passed)"));
        assert!(!result.contains("Parent checks the concrete diff"));
    }

    #[test]
    fn targeted_test_audit_worker_bootstraps_to_read_only_workspace_verifier_intent() {
        let assignment = targeted_test_audit_assignment(
            "Verify the coding result for the path normalizer by running targeted checks first.",
        );

        let resolved =
            delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

        assert_eq!(resolved.intent_id, "workspace.ops");
        assert_eq!(resolved.scope, IntentScopeProfile::WorkspaceOps);
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("filesystem.read")));
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("command.exec")));
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("command.probe")));
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("memory.access")));
        let contract = resolved
            .instruction_contract
            .as_ref()
            .expect("verifier child contract should be seeded");
        assert_eq!(contract.operation, "verify");
        assert_eq!(
            contract.side_effect_mode,
            InstructionSideEffectMode::ReadOnly
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "playbook_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("evidence_audited_patch")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "template_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("verifier")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "workflow_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("targeted_test_audit")
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "sys__exec_session",
            )
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "filesystem__read_file",
            )
        );
        assert!(
            !crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "filesystem__write_file",
            )
        );
    }

    #[test]
    fn patch_synthesis_handoff_worker_bootstraps_to_read_only_workspace_synthesizer_intent() {
        let assignment = patch_synthesis_assignment(
            "Synthesize the verified patch for the path normalizer into a final handoff.",
        );

        let resolved =
            delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

        assert_eq!(resolved.intent_id, "workspace.ops");
        assert_eq!(resolved.scope, IntentScopeProfile::WorkspaceOps);
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("filesystem.read")));
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("memory.access")));
        let contract = resolved
            .instruction_contract
            .as_ref()
            .expect("patch synthesizer contract should be seeded");
        assert_eq!(contract.operation, "synthesize");
        assert_eq!(
            contract.side_effect_mode,
            InstructionSideEffectMode::ReadOnly
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "playbook_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("evidence_audited_patch")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "template_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("patch_synthesizer")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "workflow_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("patch_synthesis_handoff")
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "filesystem__read_file",
            )
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "memory__inspect",
            )
        );
        assert!(
            !crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "sys__exec_session",
            )
        );
    }

    #[test]
    fn live_research_worker_bootstraps_to_web_research_intent() {
        let assignment = research_assignment("Research the latest standards.");

        let resolved =
            delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

        assert_eq!(resolved.intent_id, "web.research");
        assert_eq!(
            resolved.scope,
            ioi_types::app::agentic::IntentScopeProfile::WebResearch
        );
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("web.retrieve")));
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("memory.access")));
        let contract = resolved
            .instruction_contract
            .as_ref()
            .expect("research child contract should be seeded");
        assert_eq!(contract.operation, "web.research");
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "playbook_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("citation_grounded_brief")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "template_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("researcher")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "workflow_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("live_research_brief")
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "web__search",
            )
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "web__read",
            )
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "memory__search",
            )
        );
    }

    #[test]
    fn patch_build_verify_worker_bootstraps_to_workspace_ops_with_exec_capabilities() {
        let assignment = patch_build_verify_assignment(
            "Patch the parser regression, run focused verification, and summarize the outcome.",
        );

        let resolved =
            delegated_child_preset_resolved_intent(&assignment).expect("intent should exist");

        assert_eq!(resolved.intent_id, "workspace.ops");
        assert_eq!(resolved.scope, IntentScopeProfile::WorkspaceOps);
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("filesystem.read")));
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("filesystem.write")));
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("command.exec")));
        assert!(resolved
            .required_capabilities
            .contains(&CapabilityId::from("command.probe")));
        let contract = resolved
            .instruction_contract
            .as_ref()
            .expect("coding child contract should be seeded");
        assert_eq!(contract.operation, "workspace.ops");
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "playbook_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("evidence_audited_patch")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "template_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("coder")
        );
        assert_eq!(
            contract
                .slot_bindings
                .iter()
                .find(|binding| binding.slot == "workflow_id")
                .and_then(|binding| binding.value.as_deref()),
            Some("patch_build_verify")
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "sys__exec_session",
            )
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "filesystem__patch",
            )
        );
        assert!(
            crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution(
                Some(&resolved),
                "filesystem__write_file",
            )
        );
    }

    #[test]
    fn patch_synthesis_handoff_worker_completes_immediately_when_verifier_context_is_auditable() {
        let goal = "Synthesize the verified patch for the path normalizer into a final handoff.\n\n[PARENT PLAYBOOK CONTEXT]\n- Patch the workspace (implement): Coding Worker handoff\nTouched files: path_utils.py; tests/test_path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)\nResidual risk: Focused verification passed; broader checks were not rerun.\n- Verify targeted tests (verify): Worker evidence\n- verdict: passed\n- targeted_command_count: 1\n- targeted_pass_count: 1\n- widening_status: not_needed\n- regression_status: clear\n- notes: Focused unittest verification passed without widening.";
        let mut child_state = test_agent_state(goal);
        let assignment = patch_synthesis_assignment(goal);

        seed_delegated_child_execution_queue(&mut child_state, [5u8; 32], &assignment)
            .expect("seed should succeed");

        assert!(child_state.execution_queue.is_empty());
        let result = match &child_state.status {
            AgentStatus::Completed(Some(result)) => result.as_str(),
            other => panic!("expected completed synth bootstrap, got {:?}", other),
        };
        assert!(result.contains("- status: ready"));
        assert!(result.contains("- touched_file_count: 2"));
        assert!(result.contains("- verification_ready: yes"));
        assert!(result.contains("Focused unittest verification passed without widening."));
        assert!(result.contains("Focused verification passed; broader checks were not rerun."));
    }

    #[test]
    fn patch_build_verify_goal_enrichment_inherits_parent_contract_and_checks() {
        let parent_goal = concat!(
            "Port the path-normalization parity fix into the repo at \"/tmp/example\". Work inside that repo root, patch only `path_utils.py`, ",
            "keep `tests/test_path_utils.py` unchanged, update `normalize_fixture_path` so it converts backslashes to forward slashes, ",
            "collapses duplicate separators, and preserves a leading `./` or `/`. Run the focused verification command ",
            "`python3 -m unittest tests.test_path_utils -v` first, widen only if needed, verify the final postcondition, ",
            "and report the touched files plus command results."
        );
        let raw_goal =
            "Edit the code in the specified file to match the regex pattern for replacing text blocks.";

        let enriched = enrich_patch_build_verify_goal_with_parent_context(parent_goal, raw_goal);

        assert!(enriched.starts_with(raw_goal));
        assert!(enriched.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
        assert!(
            enriched.contains("delegated_task_contract: Port the path-normalization parity fix")
        );
        assert!(enriched.contains("- likely_files: path_utils.py; tests/test_path_utils.py"));
        assert!(
            enriched.contains("- targeted_checks: python3 -m unittest tests.test_path_utils -v")
        );
        assert!(enriched.contains("converts backslashes to forward slashes"));
        assert!(enriched.contains("preserves a leading `./` or `/`"));
    }
}
