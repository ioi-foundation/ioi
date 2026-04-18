use super::*;

pub(crate) const RESEARCH_SOURCE_FLOOR: u32 = 2;
pub(crate) const RESEARCH_DOMAIN_FLOOR: u32 = 2;

pub(crate) fn normalize_research_verifier_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "ok" | "ready" => "passed".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "attention" | "partial" | "warning" => {
            "needs_attention".to_string()
        }
        "blocked" | "unsafe" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn parse_scorecard_fields(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches('-')
            .trim_start_matches('*')
            .trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let normalized_key = key.trim().to_ascii_lowercase().replace([' ', '-'], "_");
        let normalized_value = value.trim();
        if normalized_key.is_empty() || normalized_value.is_empty() {
            continue;
        }
        fields
            .entry(normalized_key)
            .or_insert_with(|| normalized_value.to_string());
    }
    fields
}

pub(crate) fn first_scorecard_note(
    fields: &BTreeMap<String, String>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        fields
            .get(*key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

pub(crate) fn extract_http_url_candidates(text: &str) -> BTreeSet<String> {
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

pub(crate) fn count_research_brief_sources(text: &str) -> (u32, u32) {
    let urls = extract_http_url_candidates(text);
    let domains = urls
        .iter()
        .filter_map(|url| Url::parse(url).ok())
        .filter_map(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .map(|host| host.trim_start_matches("www.").to_string())
        .collect::<BTreeSet<_>>();
    (urls.len() as u32, domains.len() as u32)
}

pub(crate) fn build_research_verification_scorecard(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ResearchVerificationScorecard> {
    scorecards::build_research_verification_scorecard(state, run, playbook, step_idx, result)
}

pub(crate) fn parent_playbook_research_scorecard(
    run: &ParentPlaybookRun,
) -> Option<ResearchVerificationScorecard> {
    scorecards::parent_playbook_research_scorecard(run)
}

pub(crate) fn count_compact_list_items(text: &str) -> u32 {
    let items = text
        .split(|ch| matches!(ch, ';' | ',' | '\n'))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    if items.is_empty() {
        u32::from(!text.trim().is_empty())
    } else {
        items.len() as u32
    }
}

pub(crate) fn normalize_artifact_generation_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "generated" | "generated_ready" | "ready" | "complete" | "completed" | "success" | "ok" => {
            "generated".to_string()
        }
        "partial" | "repairable" | "needs_attention" => "partial".to_string(),
        "blocked" | "failed" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_artifact_signal_status(value: Option<&str>, fallback: &str) -> String {
    let normalized = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase();
    match normalized.as_str() {
        "retained" | "captured" | "present" | "passed" | "ready" | "yes" => "retained".to_string(),
        "partial" | "incomplete" => "partial".to_string(),
        "missing" | "none" | "no" => "missing".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        _ if normalized.contains("captur")
            || normalized.contains("pass")
            || normalized.contains("verif")
            || normalized.contains("preview")
            || normalized.contains("screenshot") =>
        {
            "retained".to_string()
        }
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_artifact_presentation_status(
    value: Option<&str>,
    fallback: &str,
) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "ready" | "presentation_ready" | "ship" | "shippable" => "ready".to_string(),
        "needs_validation" | "review" | "open" => "needs_validation".to_string(),
        "needs_repair" | "repairable" | "not_ready" | "fix" => "needs_repair".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_artifact_verdict(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "ready" | "approved" => "passed".to_string(),
        "fail" | "failed" | "open" | "repairable" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" | "unsafe" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_artifact_fidelity_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "faithful" | "grounded" | "matched" | "clear" | "passed" => "faithful".to_string(),
        "partial" | "open" | "needs_attention" | "drift" => "needs_attention".to_string(),
        "blocked" | "failed" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_artifact_repair_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "not_needed" | "clear" => "not_needed".to_string(),
        "recommended" | "suggested" | "follow_up" | "needs_validation" => "recommended".to_string(),
        "required" | "needed" | "needs_repair" | "repairable" => "required".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn build_artifact_generation_summary(
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ArtifactGenerationSummary> {
    scorecards::build_artifact_generation_summary(run, playbook, step_idx, result)
}

pub(crate) fn parent_playbook_artifact_generation(
    run: &ParentPlaybookRun,
) -> Option<ArtifactGenerationSummary> {
    scorecards::parent_playbook_artifact_generation(run)
}

pub(crate) fn build_artifact_quality_scorecard(
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ArtifactQualityScorecard> {
    scorecards::build_artifact_quality_scorecard(run, playbook, step_idx, result)
}

pub(crate) fn parent_playbook_artifact_quality(
    run: &ParentPlaybookRun,
) -> Option<ArtifactQualityScorecard> {
    scorecards::parent_playbook_artifact_quality(run)
}

pub(crate) fn build_artifact_repair_summary(
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ArtifactRepairSummary> {
    scorecards::build_artifact_repair_summary(run, playbook, step_idx, result)
}

pub(crate) fn parent_playbook_artifact_repair(
    run: &ParentPlaybookRun,
) -> Option<ArtifactRepairSummary> {
    scorecards::parent_playbook_artifact_repair(run)
}

pub(crate) fn normalize_computer_use_surface_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "clear" | "observed" | "ready" | "visible" => "clear".to_string(),
        "partial" | "uncertain" => "partial".to_string(),
        "blocked" | "missing" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_computer_use_approval_risk(value: Option<&str>) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "clear" | "low" => "none".to_string(),
        "possible" | "medium" | "watch" => "possible".to_string(),
        "required" | "pending" | "high" => "required".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_computer_use_verdict(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "ok" | "ready" => "passed".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" | "unsafe" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_computer_use_postcondition_status(
    value: Option<&str>,
    fallback: &str,
) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "met" | "passed" | "holds" | "verified" | "complete" => "met".to_string(),
        "open" | "not_met" | "missing" | "partial" | "needs_attention" => "open".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_computer_use_approval_state(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pending" | "require_approval" | "approval_required" => "pending".to_string(),
        "approved" => "approved".to_string(),
        "denied" => "denied".to_string(),
        "clear" | "cleared" | "none" | "allowed" | "not_needed" => "clear".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_computer_use_recovery_status(
    value: Option<&str>,
    fallback: &str,
) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "not_needed" | "clear" => "not_needed".to_string(),
        "recommended" | "retry" | "retryable" | "suggested" => "recommended".to_string(),
        "required" | "needed" | "needs_recovery" => "required".to_string(),
        "pending_approval" | "approval_pending" => "pending_approval".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn build_computer_use_perception_summary(
    _state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ComputerUsePerceptionSummary> {
    scorecards::build_computer_use_perception_summary(_state, run, playbook, step_idx, result)
}

pub(crate) fn parent_playbook_computer_use_perception(
    run: &ParentPlaybookRun,
) -> Option<ComputerUsePerceptionSummary> {
    scorecards::parent_playbook_computer_use_perception(run)
}

pub(crate) fn load_step_raw_output(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    step_id: &str,
) -> Option<String> {
    run.steps
        .iter()
        .find(|step| step.step_id == step_id)
        .and_then(|step| {
            step.child_session_id
                .and_then(|child_session_id| {
                    load_worker_session_result(state, child_session_id)
                        .ok()
                        .flatten()
                })
                .and_then(|result| result.raw_output)
                .or_else(|| step.output_preview.clone())
        })
}

pub(crate) fn extract_prefixed_items(text: &str, prefixes: &[&str]) -> BTreeSet<String> {
    let mut items = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        for prefix in prefixes {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                for item in rest.split(';') {
                    let normalized = item.trim().trim_matches('.');
                    if !normalized.is_empty() {
                        items.insert(normalized.to_string());
                    }
                }
            }
        }
    }
    items
}

pub(crate) fn extract_prefixed_value(text: &str, prefixes: &[&str]) -> Option<String> {
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

pub(crate) fn count_passed_items(items: &BTreeSet<String>) -> u32 {
    items
        .iter()
        .filter(|item| {
            let lower = item.to_ascii_lowercase();
            lower.contains("(passed)")
                || lower.ends_with(" passed")
                || lower.contains(" status=passed")
        })
        .count() as u32
}

pub(crate) fn count_touched_files(text: &str) -> u32 {
    let files = extract_prefixed_items(text, &["Touched files:", "Touched file:"]);
    files.len() as u32
}

pub(crate) fn patch_build_verify_handoff_is_structured(text: &str) -> bool {
    count_touched_files(text) > 0
        && !extract_prefixed_items(text, &["Verification:", "Targeted verification:"]).is_empty()
}

pub(crate) fn synthesize_patch_build_verify_completion_result(
    child_state: &AgentState,
    assignment: &WorkerAssignment,
    explicit_summary: Option<&str>,
) -> Option<String> {
    let command_literal = latest_successful_goal_command(child_state, assignment)?;
    let mut touched_files = Vec::<String>::new();

    if let Some(path) = latest_workspace_edit_path(child_state) {
        let candidate = Path::new(&path)
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_string)
            .unwrap_or(path);
        if !candidate.trim().is_empty() {
            touched_files.push(candidate);
        }
    }

    for hint in patch_build_verify_goal_likely_files(&assignment.goal) {
        if !touched_files
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&hint))
        {
            touched_files.push(hint);
        }
    }

    let touched_files_line = if touched_files.is_empty() {
        "Touched files: none recorded".to_string()
    } else {
        format!("Touched files: {}", touched_files.join("; "))
    };

    let mut lines = vec![
        touched_files_line,
        format!("Verification: {} (passed)", command_literal.trim()),
        "Residual risk: Focused verification passed; broader checks were not rerun.".to_string(),
    ];
    if let Some(summary) = explicit_summary
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        lines.push(format!("Summary: {}", normalize_whitespace(summary)));
    }

    Some(lines.join("\n"))
}

pub(crate) fn maybe_enrich_patch_build_verify_completion_result(
    child_state: &AgentState,
    assignment: &WorkerAssignment,
    explicit_result: Option<String>,
) -> Option<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return explicit_result;
    }
    if explicit_result
        .as_deref()
        .map(patch_build_verify_handoff_is_structured)
        .unwrap_or(false)
    {
        return explicit_result;
    }

    synthesize_patch_build_verify_completion_result(
        child_state,
        assignment,
        explicit_result.as_deref(),
    )
}

pub(crate) fn patch_synthesis_handoff_is_structured(text: &str) -> bool {
    let fields = parse_scorecard_fields(text);
    fields.contains_key("status")
        && fields.contains_key("touched_file_count")
        && fields.contains_key("verification_ready")
}

pub(crate) fn synthesize_patch_synthesis_completion_result(
    state: &dyn StateAccess,
    parent_session_id: [u8; 32],
    assignment: &WorkerAssignment,
    explicit_summary: Option<&str>,
) -> Option<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_synthesis_handoff") {
        return None;
    }

    let playbook_id = assignment
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("evidence_audited_patch");
    let run = load_parent_playbook_run(state, parent_session_id, playbook_id)
        .ok()
        .flatten()?;
    if run.playbook_id.trim() != "evidence_audited_patch" {
        return None;
    }

    let implement_output = load_step_raw_output(state, &run, "implement").unwrap_or_default();
    let touched_file_count = count_touched_files(&implement_output);
    if touched_file_count == 0 {
        return None;
    }

    let verifier_scorecard = parent_playbook_coding_scorecard(&run);
    let verification_ready = verifier_scorecard
        .as_ref()
        .map(|scorecard| scorecard.verdict == "passed")
        .unwrap_or(false);
    let status = if verification_ready {
        "ready"
    } else {
        "needs_attention"
    };
    let notes = explicit_summary
        .map(normalize_whitespace)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            verifier_scorecard
                .as_ref()
                .and_then(|scorecard| scorecard.notes.clone())
        })
        .unwrap_or_else(|| {
            if verification_ready {
                "Inherited verifier receipts already mark the focused coding handoff as passed."
                    .to_string()
            } else {
                "Inherited verifier receipts still need attention before the final patch handoff is ready."
                    .to_string()
            }
        });
    let residual_risk = extract_prefixed_value(&implement_output, &["Residual risk:", "Notes:"])
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

pub(crate) fn maybe_enrich_patch_synthesis_completion_result(
    state: &dyn StateAccess,
    parent_session_id: [u8; 32],
    assignment: &WorkerAssignment,
    explicit_result: Option<String>,
) -> Option<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_synthesis_handoff") {
        return explicit_result;
    }
    if explicit_result
        .as_deref()
        .map(patch_synthesis_handoff_is_structured)
        .unwrap_or(false)
    {
        return explicit_result;
    }

    synthesize_patch_synthesis_completion_result(
        state,
        parent_session_id,
        assignment,
        explicit_result.as_deref(),
    )
    .or(explicit_result)
}

pub(crate) fn synthesize_observed_patch_build_verify_completion(
    child_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }
    if child_state.pending_tool_call.is_some() || !child_state.execution_queue.is_empty() {
        return None;
    }
    latest_successful_goal_command_after_edit(child_state, assignment)?;
    synthesize_patch_build_verify_completion_result(child_state, assignment, None)
}

pub(crate) fn normalize_coding_verdict(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "ok" | "ready" => "passed".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" | "unsafe" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_widening_status(value: Option<&str>) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "not_needed" | "targeted_only" | "contained" => "not_needed".to_string(),
        "performed" | "widened" | "expanded" => "performed".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_regression_status(value: Option<&str>) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "clear" | "clean" | "pass" | "passed" | "ok" => "clear".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn normalize_patch_synthesis_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "ready" | "pass" | "passed" | "ok" => "ready".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

pub(crate) fn parse_bool_like(value: Option<&str>) -> Option<bool> {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_ascii_lowercase()
        .as_str()
    {
        "true" | "yes" | "ready" | "accepted" => Some(true),
        "false" | "no" | "open" | "blocked" => Some(false),
        _ => None,
    }
}

pub(crate) fn build_coding_verification_scorecard(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<CodingVerificationScorecard> {
    scorecards::build_coding_verification_scorecard(state, run, playbook, step_idx, result)
}

pub(crate) fn parent_playbook_coding_scorecard(
    run: &ParentPlaybookRun,
) -> Option<CodingVerificationScorecard> {
    scorecards::parent_playbook_coding_scorecard(run)
}

pub(crate) fn build_computer_use_verification_scorecard(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ComputerUseVerificationScorecard> {
    scorecards::build_computer_use_verification_scorecard(state, run, playbook, step_idx, result)
}

pub(crate) fn parent_playbook_computer_use_verification(
    run: &ParentPlaybookRun,
) -> Option<ComputerUseVerificationScorecard> {
    scorecards::parent_playbook_computer_use_verification(run)
}

pub(crate) fn build_patch_synthesis_summary(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<PatchSynthesisSummary> {
    scorecards::build_patch_synthesis_summary(state, run, playbook, step_idx, result)
}

pub(crate) fn parent_playbook_patch_synthesis(
    run: &ParentPlaybookRun,
) -> Option<PatchSynthesisSummary> {
    scorecards::parent_playbook_patch_synthesis(run)
}

pub(crate) fn build_computer_use_recovery_summary(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ComputerUseRecoverySummary> {
    scorecards::build_computer_use_recovery_summary(state, run, playbook, step_idx, result)
}

pub(crate) fn parent_playbook_computer_use_recovery(
    run: &ParentPlaybookRun,
) -> Option<ComputerUseRecoverySummary> {
    scorecards::parent_playbook_computer_use_recovery(run)
}
