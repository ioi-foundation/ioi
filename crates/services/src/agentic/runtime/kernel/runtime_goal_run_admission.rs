//! GoalRun orchestration admission planner.
//!
//! Pure validation + canonicalization (no IO) for the daemon-owned GoalRun plane — the
//! multi-harness orchestration ladder (GoalRun → RoleTopology → ContextCell/ContextLease →
//! ContextHandoff/TaskBriefPayload → HarnessInvocation → ImplementationResultPayload →
//! VerifierPath → reconciliation). The daemon passes live registry facts (lifecycle, execution
//! wiring, probed runnability, model-route availability, provider trust); the planner asserts
//! the fail-closed rules:
//!   - a role invokes only an ACTIVE, RUNNABLE, execution-WIRED harness profile
//!   - over an AVAILABLE model route
//!   - bound to a real project/session workspace
//!   - within the run's bounded invocation budget, receipts required
//!   - never a non-local-trust provider without an explicit acceptance ref
//! Reconciliation admits only verified candidates (or an explicitly blocked partial result);
//! candidate outputs never reach the target workspace without it. Raw prompts are not part of
//! any request here — the durable contract is the typed task brief and result refs.

use serde_json::{json, Value};
use std::collections::HashSet;

pub const GOAL_RUN_ADMISSION_SCHEMA_VERSION: &str = "ioi.runtime.goal_run_admission.v1";

/// The first orchestration policy: parallel implementation + verifier reconciliation.
pub const GOAL_RUN_POLICY_PARALLEL_IMPLEMENT_RECONCILE: &str = "parallel_implement_reconcile";

const ROLE_KINDS: &[&str] = &["conductor", "implementer", "verifier"];

const MERGE_STRATEGIES: &[&str] = &["select_single_best", "merge_disjoint", "none_blocked"];

const EXECUTION_WIRINGS: &[&str] = &["lane_a_host_spawn", "terminal_pty", "adapter_slot_unwired"];

const PROVIDER_TRUST: &[&str] = &["local", "remote", "remote_attested"];

/// The bounded budget for the first policy: one conductor, at most two parallel implementers,
/// one deterministic verifier pass. The planner rejects anything wider.
pub const GOAL_RUN_MAX_PARALLEL_INVOCATIONS: u64 = 2;

/// Structured admission rejection (HTTP status + code + message + details); the daemon renders
/// it as `{error: {code, message, details}}`.
#[derive(Debug, Clone)]
pub struct RuntimeGoalRunAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeGoalRunAdmissionError {
    fn new(status: u16, code: &str, message: &str, details: Value) -> Self {
        Self {
            status,
            code: code.to_string(),
            message: message.to_string(),
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimeGoalRunAdmissionError>;

#[derive(Default)]
pub struct RuntimeGoalRunAdmissionCore;

impl RuntimeGoalRunAdmissionCore {
    /// goal_run_admit — validate + canonicalize a GoalRun creation request.
    pub fn admit_goal_run(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        let goal_ref = prefixed_string(request, "goal_ref", "goal://")?;
        let normalized_goal = required_text(request, "normalized_goal", 4)?;
        let target_session_ref = prefixed_string(request, "target_session_ref", "session:")?;
        let project_ref = prefixed_string(request, "project_ref", "project:")?;
        let policy = required_text(request, "orchestration_policy", 1)?;
        if policy != GOAL_RUN_POLICY_PARALLEL_IMPLEMENT_RECONCILE {
            return Err(admission_error(
                "goal_run_policy_unsupported",
                "The only admitted orchestration policy in this cut is parallel_implement_reconcile.",
                json!({ "orchestration_policy": policy }),
            ));
        }
        let max_parallel = request
            .get("max_parallel_invocations")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if max_parallel == 0 || max_parallel > GOAL_RUN_MAX_PARALLEL_INVOCATIONS {
            return Err(admission_error(
                "goal_run_invocation_budget_invalid",
                "A GoalRun must declare a bounded invocation budget (1..=2 parallel invocations).",
                json!({ "max_parallel_invocations": max_parallel, "max_allowed": GOAL_RUN_MAX_PARALLEL_INVOCATIONS }),
            ));
        }
        if request.get("receipt_required").and_then(Value::as_bool) != Some(true) {
            return Err(admission_error(
                "goal_run_receipt_required",
                "A GoalRun is receipt-required; every consequential step must bind a receipt.",
                json!({}),
            ));
        }
        let authority_scope_refs = prefixed_refs(request, "authority_scope_refs", "scope:", false)?;
        require_scope(&authority_scope_refs, "scope:goal.run.orchestrate")?;
        let state_root_ref =
            prefixed_string(request, "state_root_ref", "agentgres://state-root/goal-run/")?;

        let admission_id = format!("goal-run-admission:{}:create", safe_id(&goal_ref));
        let receipt_ref = format!("receipt://goal-run/{}/create", safe_id(&goal_ref));
        Ok(json!({
            "schema_version": GOAL_RUN_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "decision": "admitted",
            "admission_state": "admitted_for_goal_run_plane",
            "goal_ref": goal_ref,
            "normalized_goal": normalized_goal,
            "target_session_ref": target_session_ref,
            "project_ref": project_ref,
            "orchestration_policy": policy,
            "max_parallel_invocations": max_parallel,
            "authority_scope_refs": authority_scope_refs,
            "receipt_refs": [receipt_ref],
            "state_root_ref": state_root_ref,
            "admitted_at": now_iso,
            "goal_run_invariant": "A GoalRun is admitted only with a normalized goal, a real target session/project binding, the bounded parallel_implement_reconcile policy, the goal.run.orchestrate scope, receipts required, and a state-root ref; raw chat text is never the durable contract.",
            "runtimeTruthSource": "daemon-runtime",
        }))
    }

    /// role_topology_select — pure selection of the first policy's role topology from live
    /// harness facts. Never widens eligibility: an implementer whose facts fail the fail-closed
    /// rules is EXCLUDED with an explicit reason (the run continues as an admitted partial).
    /// Facts per candidate: {role, profile_ref, harness, lifecycle_status, execution_wiring,
    /// runnability_state, provider_trust, model_route_state, provider_trust_acceptance_ref?}.
    pub fn select_role_topology(&self, request: &Value) -> AdmitResult<Value> {
        let goal_ref = prefixed_string(request, "goal_ref", "goal://")?;
        let conductor = request.get("conductor").cloned().unwrap_or(Value::Null);
        let conductor_ref = conductor
            .get("profile_ref")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !conductor_ref.starts_with("harness-profile:") {
            return Err(admission_error(
                "goal_run_conductor_required",
                "RoleTopology selection requires a conductor harness profile.",
                json!({ "conductor": conductor }),
            ));
        }
        let candidates = request
            .get("implementer_candidates")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if candidates.is_empty() {
            return Err(admission_error(
                "goal_run_implementers_required",
                "RoleTopology selection requires at least one implementer candidate.",
                json!({}),
            ));
        }
        let mut implementers: Vec<Value> = Vec::new();
        let mut excluded: Vec<Value> = Vec::new();
        for candidate in &candidates {
            match eligibility_reason(candidate) {
                None => implementers.push(candidate.clone()),
                Some(reason) => excluded.push(json!({
                    "profile_ref": candidate.get("profile_ref").cloned().unwrap_or(Value::Null),
                    "harness": candidate.get("harness").cloned().unwrap_or(Value::Null),
                    "reason_code": reason,
                })),
            }
            if implementers.len() as u64 == GOAL_RUN_MAX_PARALLEL_INVOCATIONS {
                break;
            }
        }
        if implementers.is_empty() {
            return Err(admission_error(
                "goal_run_no_eligible_implementer",
                "No implementer candidate is active, runnable, execution-wired, and route-available.",
                json!({ "excluded": excluded }),
            ));
        }
        Ok(json!({
            "schema_version": GOAL_RUN_ADMISSION_SCHEMA_VERSION,
            "decision": "selected",
            "goal_ref": goal_ref,
            // Canon RoleTopologyEnvelope kind: independent implementer cells reviewed/reconciled
            // by the conductor-run verifier path.
            "topology_kind": "multi_context_review",
            "orchestration_policy": GOAL_RUN_POLICY_PARALLEL_IMPLEMENT_RECONCILE,
            "conductor_ref": conductor_ref,
            "implementer_refs": implementers
                .iter()
                .filter_map(|c| c.get("profile_ref").and_then(Value::as_str))
                .collect::<Vec<_>>(),
            "verifier_ref": conductor_ref,
            "conductor_verifies_by_default": true,
            "excluded_implementers": excluded,
            "runtimeTruthSource": "daemon-runtime",
        }))
    }

    /// harness_invocation_admit — one role invocation against live facts. Fail-closed.
    pub fn admit_harness_invocation(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        let goal_ref = prefixed_string(request, "goal_ref", "goal://")?;
        let role = enum_value(request, "role", ROLE_KINDS)?;
        let profile_ref = prefixed_string(request, "profile_ref", "harness-profile:")?;
        let task_brief_ref = prefixed_string(request, "task_brief_ref", "task_brief://")?;
        let context_cell_ref = prefixed_string(request, "context_cell_ref", "context_cell://")?;
        let session_ref = prefixed_string(request, "session_ref", "session:")?;
        let model_route_ref = prefixed_string(request, "model_route_ref", "model-route:")?;
        let lifecycle_status = required_text(request, "lifecycle_status", 1)?;
        let execution_wiring = enum_value(request, "execution_wiring", EXECUTION_WIRINGS)?;
        let runnability_state = required_text(request, "runnability_state", 1)?;
        let provider_trust = enum_value(request, "provider_trust", PROVIDER_TRUST)?;
        let model_route_state = required_text(request, "model_route_state", 1)?;

        if lifecycle_status != "active" {
            return Err(admission_error(
                "goal_run_invocation_profile_not_active",
                "A GoalRun invokes only an ACTIVE harness profile.",
                json!({ "profile_ref": profile_ref, "lifecycle_status": lifecycle_status }),
            ));
        }
        if execution_wiring != "lane_a_host_spawn" {
            return Err(admission_error(
                "goal_run_invocation_execution_unwired",
                "A GoalRun invokes only an execution-wired harness profile; adapter slots stay fail-closed.",
                json!({ "profile_ref": profile_ref, "execution_wiring": execution_wiring }),
            ));
        }
        if runnability_state != "runnable" {
            return Err(admission_error(
                "goal_run_invocation_not_runnable",
                "A GoalRun invokes a harness only when its latest runnability probe passed.",
                json!({ "profile_ref": profile_ref, "runnability_state": runnability_state }),
            ));
        }
        if model_route_state != "available" {
            return Err(admission_error(
                "goal_run_invocation_model_route_unavailable",
                "A GoalRun invokes a harness only over an AVAILABLE model route.",
                json!({ "model_route_ref": model_route_ref, "model_route_state": model_route_state }),
            ));
        }
        if provider_trust != "local" {
            let acceptance = request
                .get("provider_trust_acceptance_ref")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !acceptance.starts_with("approval://provider-trust/") {
                return Err(admission_error(
                    "goal_run_invocation_provider_trust_acceptance_required",
                    "Routing goal work to a non-local-trust provider requires an explicit provider-trust acceptance.",
                    json!({ "profile_ref": profile_ref, "provider_trust": provider_trust }),
                ));
            }
        }

        let invocation_ref = prefixed_string(request, "invocation_ref", "harness_invocation://")?;
        let admission_id = format!(
            "goal-run-admission:{}:invoke_{}",
            safe_id(&goal_ref),
            safe_id(&role)
        );
        let receipt_ref = format!(
            "receipt://goal-run/{}/invoke/{}",
            safe_id(&goal_ref),
            safe_id(&profile_ref)
        );
        Ok(json!({
            "schema_version": GOAL_RUN_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "decision": "admitted",
            "admission_state": "admitted_for_harness_invocation",
            "goal_ref": goal_ref,
            "role": role,
            "invocation_ref": invocation_ref,
            "profile_ref": profile_ref,
            "task_brief_ref": task_brief_ref,
            "context_cell_ref": context_cell_ref,
            "session_ref": session_ref,
            "model_route_ref": model_route_ref,
            "receipt_refs": [receipt_ref],
            "admitted_at": now_iso,
            "runtimeTruthSource": "daemon-runtime",
        }))
    }

    /// reconciliation_admit — the commitment boundary: candidate outputs may reach the target
    /// workspace only through an admitted reconciliation with verifier evidence; an empty
    /// selection must be an EXPLICIT blocked partial, never a silent success.
    pub fn admit_reconciliation(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        let goal_ref = prefixed_string(request, "goal_ref", "goal://")?;
        let merge_strategy = enum_value(request, "merge_strategy", MERGE_STRATEGIES)?;
        let selected = string_refs(request.get("selected_candidate_refs"));
        let rejected = string_refs(request.get("rejected_candidate_refs"));
        let verifier_evidence_refs = prefixed_refs(
            request,
            "verifier_evidence_refs",
            "agentgres://goal-run-verification/",
            false,
        )?;
        for candidate in selected.iter().chain(rejected.iter()) {
            if !candidate.starts_with("implementation_result://") {
                return Err(admission_error(
                    "goal_run_reconciliation_candidate_ref_invalid",
                    "Reconciliation candidates are implementation_result:// refs.",
                    json!({ "ref": candidate }),
                ));
            }
        }
        match merge_strategy.as_str() {
            "none_blocked" => {
                if !selected.is_empty() {
                    return Err(admission_error(
                        "goal_run_reconciliation_blocked_must_select_none",
                        "A blocked reconciliation selects no candidate.",
                        json!({ "selected_candidate_refs": selected }),
                    ));
                }
                let reason = required_text(request, "reason_code", 1)?;
                if reason.is_empty() {
                    unreachable!();
                }
            }
            "merge_disjoint" => {
                if selected.len() < 2 {
                    return Err(admission_error(
                        "goal_run_reconciliation_merge_requires_multiple",
                        "merge_disjoint requires at least two verified candidates.",
                        json!({ "selected_candidate_refs": selected }),
                    ));
                }
            }
            _ => {
                if selected.len() != 1 {
                    return Err(admission_error(
                        "goal_run_reconciliation_selection_invalid",
                        "select_single_best selects exactly one verified candidate.",
                        json!({ "selected_candidate_refs": selected }),
                    ));
                }
            }
        }
        if request.get("receipt_required").and_then(Value::as_bool) != Some(true) {
            return Err(admission_error(
                "goal_run_reconciliation_receipt_required",
                "Reconciliation is receipt-required.",
                json!({}),
            ));
        }
        let admission_id = format!("goal-run-admission:{}:reconcile", safe_id(&goal_ref));
        let receipt_ref = format!("receipt://goal-run/{}/reconcile", safe_id(&goal_ref));
        Ok(json!({
            "schema_version": GOAL_RUN_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "decision": "admitted",
            "admission_state": "admitted_for_reconciliation",
            "goal_ref": goal_ref,
            "merge_strategy": merge_strategy,
            "selected_candidate_refs": selected,
            "rejected_candidate_refs": rejected,
            "verifier_evidence_refs": verifier_evidence_refs,
            "receipt_refs": [receipt_ref],
            "admitted_at": now_iso,
            "reconciliation_invariant": "Candidate outputs reach the target workspace only through an admitted reconciliation bound to verifier evidence; an empty selection is an explicit blocked partial with a reason code.",
            "runtimeTruthSource": "daemon-runtime",
        }))
    }
}

impl RuntimeGoalRunAdmissionCore {
    /// select_ioi_agent_execution — the IOI Agent strategy planner (pure, deterministic v1).
    ///
    /// The user-facing product mode is IOI Agent; this decides how a launch is realized:
    /// `direct` (one admitted harness binding) or `goal_run` (multi-harness compare/reconcile).
    /// The v1 policy is deliberately deterministic and explainable — reason codes, no model
    /// call, no fabricated "intelligence":
    ///   - `direct`        → direct (the standard single-harness session, unchanged);
    ///   - `compare`       → goal_run; fails closed when fewer than 2 implementers are eligible;
    ///   - `private_local` → candidates restricted to local provider trust + a local model
    ///                       route, then the auto rule applies (remote slots disabled);
    ///   - `auto`          → goal_run when ≥2 implementers are eligible AND the goal reads
    ///                       large/ambiguous (length ≥ 120 chars or an explicit compare-shaped
    ///                       keyword); otherwise direct.
    pub fn select_ioi_agent_execution(&self, request: &Value) -> AdmitResult<Value> {
        const STRATEGIES: &[&str] = &["auto", "direct", "compare", "private_local"];
        let strategy = enum_value(request, "strategy", STRATEGIES)?;
        let goal = required_text(request, "normalized_goal", 4)?;
        let conductor_ref = required_text(request, "conductor_ref", 1)?;
        if !conductor_ref.starts_with("harness-profile:") {
            return Err(admission_error(
                "ioi_agent_conductor_invalid",
                "IOI Agent selection requires a conductor harness profile.",
                json!({ "conductor_ref": conductor_ref }),
            ));
        }
        let privacy_posture = if strategy == "private_local" { "private_local" } else { "standard" };
        let candidates = request
            .get("implementer_candidates")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let preferred: Vec<String> = string_refs(request.get("preferred_harness_refs"));

        let mut eligible: Vec<Value> = Vec::new();
        let mut excluded: Vec<Value> = Vec::new();
        for candidate in &candidates {
            // Private-local is a categorical boundary: it excludes non-local trust and non-local
            // routes BEFORE ordinary eligibility (an acceptance ref cannot opt remote trust in).
            let mut reason: Option<String> = None;
            if privacy_posture == "private_local" {
                let trust = candidate.get("provider_trust").and_then(Value::as_str).unwrap_or("");
                let route_local = candidate.get("model_route_local").and_then(Value::as_bool);
                if trust != "local" {
                    reason = Some("private_local_excludes_remote_trust".to_string());
                } else if route_local == Some(false) {
                    reason = Some("private_local_requires_local_model_route".to_string());
                }
            }
            if reason.is_none() {
                reason = eligibility_reason(candidate).map(str::to_string);
            }
            if reason.is_none()
                && !preferred.is_empty()
                && !preferred.iter().any(|p| {
                    Some(p.as_str()) == candidate.get("profile_ref").and_then(Value::as_str)
                })
            {
                reason = Some("not_in_preferred_harnesses".to_string());
            }
            match reason {
                None => eligible.push(candidate.clone()),
                Some(code) => excluded.push(json!({
                    "profile_ref": candidate.get("profile_ref").cloned().unwrap_or(Value::Null),
                    "harness": candidate.get("harness").cloned().unwrap_or(Value::Null),
                    "reason_code": code,
                })),
            }
        }

        let compare_shaped = goal.len() >= 120
            || ["compare", "review", "refactor", "migrate", "audit", "redesign", "multiple approaches"]
                .iter()
                .any(|kw| goal.to_lowercase().contains(kw));
        let (kind, reason_code): (&str, &str) = match strategy.as_str() {
            "direct" => ("direct", "strategy_direct_requested"),
            "compare" => {
                if eligible.len() < 2 {
                    return Err(admission_error(
                        "ioi_agent_compare_insufficient_implementers",
                        "Compare needs at least two eligible local implementer harnesses.",
                        json!({ "eligible": eligible.len(), "excluded": excluded }),
                    ));
                }
                ("goal_run", "strategy_compare_requested")
            }
            _ => {
                // auto / private_local share the auto rule over their (possibly filtered) pool.
                if eligible.len() >= 2 && compare_shaped {
                    ("goal_run", "auto_selected_goal_run_ambiguous_or_large")
                } else {
                    ("direct", "auto_selected_direct_simple")
                }
            }
        };

        // Direct selection order: an eligible preferred/implementer harness first (it was asked
        // for), else the conductor-native worker — the standard session path, unchanged.
        let selected_harness_ref = if kind == "direct" {
            eligible
                .first()
                .and_then(|c| c.get("profile_ref").and_then(Value::as_str))
                .unwrap_or(&conductor_ref)
                .to_string()
        } else {
            String::new()
        };

        Ok(json!({
            "schema_version": GOAL_RUN_ADMISSION_SCHEMA_VERSION,
            "decision": "selected",
            "agent": "ioi-agent",
            "strategy": strategy,
            "planned_execution_kind": kind,
            "reason_codes": [reason_code],
            "privacy_posture": privacy_posture,
            "remote_slots_disabled": privacy_posture == "private_local",
            "conductor_ref": conductor_ref,
            "selected_harness_ref": if selected_harness_ref.is_empty() { Value::Null } else { json!(selected_harness_ref) },
            "eligible_harness_refs": eligible
                .iter()
                .filter_map(|c| c.get("profile_ref").and_then(Value::as_str))
                .collect::<Vec<_>>(),
            "excluded_harnesses": excluded,
            "max_parallel_invocations": GOAL_RUN_MAX_PARALLEL_INVOCATIONS,
            "runtimeTruthSource": "daemon-runtime",
        }))
    }
}

/// Why a candidate is ineligible for an implementer role (None = eligible).
fn eligibility_reason(candidate: &Value) -> Option<&'static str> {
    let text = |key: &str| candidate.get(key).and_then(Value::as_str).unwrap_or("");
    if !text("profile_ref").starts_with("harness-profile:") {
        return Some("profile_ref_invalid");
    }
    if text("lifecycle_status") != "active" {
        return Some("profile_not_active");
    }
    if text("execution_wiring") != "lane_a_host_spawn" {
        return Some("execution_unwired");
    }
    if text("runnability_state") != "runnable" {
        return Some("not_runnable");
    }
    if text("model_route_state") != "available" {
        return Some("model_route_unavailable");
    }
    if text("provider_trust") != "local"
        && !text("provider_trust_acceptance_ref").starts_with("approval://provider-trust/")
    {
        return Some("provider_trust_acceptance_required");
    }
    None
}

fn admission_error(code: &str, message: &str, details: Value) -> RuntimeGoalRunAdmissionError {
    RuntimeGoalRunAdmissionError::new(403, code, message, details)
}

fn required_text(request: &Value, field: &str, min_len: usize) -> AdmitResult<String> {
    let value = request
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if value.len() < min_len {
        return Err(RuntimeGoalRunAdmissionError::new(
            400,
            &format!("goal_run_{field}_required"),
            &format!("GoalRun admission requires {field}."),
            json!({ "field": field }),
        ));
    }
    Ok(value.to_string())
}

fn enum_value(request: &Value, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let value = request
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(RuntimeGoalRunAdmissionError::new(
            400,
            &format!("goal_run_{field}_invalid"),
            &format!("GoalRun admission requires a valid {field}."),
            json!({ field: value, "allowed_values": allowed }),
        ))
    }
}

fn prefixed_string(request: &Value, field: &str, prefix: &str) -> AdmitResult<String> {
    let value = required_text(request, field, 1)?;
    if !value.starts_with(prefix) {
        return Err(RuntimeGoalRunAdmissionError::new(
            400,
            "goal_run_ref_prefix_invalid",
            &format!("{field} must use {prefix} refs."),
            json!({ "field": field, "ref": value, "expected_prefix": prefix }),
        ));
    }
    Ok(value)
}

fn prefixed_refs(
    request: &Value,
    field: &str,
    prefix: &str,
    allow_empty: bool,
) -> AdmitResult<Vec<String>> {
    let refs = string_refs(request.get(field));
    if !allow_empty && refs.is_empty() {
        return Err(RuntimeGoalRunAdmissionError::new(
            400,
            "goal_run_required_refs_missing",
            &format!("GoalRun admission requires non-empty {field}."),
            json!({ "field": field }),
        ));
    }
    for reference in &refs {
        if !reference.starts_with(prefix) {
            return Err(RuntimeGoalRunAdmissionError::new(
                400,
                "goal_run_ref_prefix_invalid",
                &format!("{field} must use {prefix} refs."),
                json!({ "field": field, "ref": reference, "expected_prefix": prefix }),
            ));
        }
    }
    Ok(refs)
}

fn string_refs(value: Option<&Value>) -> Vec<String> {
    let mut seen = HashSet::new();
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty() && seen.insert(s.to_string()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn require_scope(scopes: &[String], required: &str) -> AdmitResult<()> {
    if scopes.iter().any(|scope| scope == required) {
        return Ok(());
    }
    Err(admission_error(
        "goal_run_authority_scope_missing",
        &format!("GoalRun admission requires {required}."),
        json!({ "required_scope": required, "authority_scope_refs": scopes }),
    ))
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn goal_request() -> Value {
        json!({
            "goal_ref": "goal://gr_test",
            "normalized_goal": "Create a status file",
            "target_session_ref": "session:hyp-target",
            "project_ref": "project:hypervisor",
            "orchestration_policy": "parallel_implement_reconcile",
            "max_parallel_invocations": 2,
            "receipt_required": true,
            "authority_scope_refs": ["scope:goal.run.orchestrate"],
            "state_root_ref": "agentgres://state-root/goal-run/gr_test",
        })
    }

    fn implementer(harness: &str, lifecycle: &str, runnable: &str) -> Value {
        json!({
            "profile_ref": format!("harness-profile:hp_{harness}"),
            "harness": harness,
            "lifecycle_status": lifecycle,
            "execution_wiring": "lane_a_host_spawn",
            "runnability_state": runnable,
            "provider_trust": "local",
            "model_route_state": "available",
        })
    }

    #[test]
    fn goal_run_admit_shape_and_budget() {
        let core = RuntimeGoalRunAdmissionCore;
        let admitted = core.admit_goal_run(&goal_request(), "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(
            admitted["admission_id"],
            json!("goal-run-admission:goal___gr_test:create")
        );
        let mut over_budget = goal_request();
        over_budget["max_parallel_invocations"] = json!(3);
        let err = core
            .admit_goal_run(&over_budget, "2026-01-01T00:00:00Z")
            .unwrap_err();
        assert_eq!(err.code, "goal_run_invocation_budget_invalid");
    }

    #[test]
    fn topology_excludes_ineligible_with_reason() {
        let core = RuntimeGoalRunAdmissionCore;
        let request = json!({
            "goal_ref": "goal://gr_test",
            "conductor": { "profile_ref": "harness-profile:hp_hypervisor_worker" },
            "implementer_candidates": [
                implementer("opencode", "active", "runnable"),
                implementer("deepseek_tui", "disabled", "runnable"),
            ],
        });
        let selected = core.select_role_topology(&request).unwrap();
        assert_eq!(selected["implementer_refs"], json!(["harness-profile:hp_opencode"]));
        assert_eq!(
            selected["excluded_implementers"][0]["reason_code"],
            json!("profile_not_active")
        );
    }

    #[test]
    fn invocation_fails_closed_on_unwired_and_remote_trust() {
        let core = RuntimeGoalRunAdmissionCore;
        let mut request = json!({
            "goal_ref": "goal://gr_test",
            "role": "implementer",
            "profile_ref": "harness-profile:hp_codex",
            "task_brief_ref": "task_brief://tb_1",
            "context_cell_ref": "context_cell://cc_1",
            "session_ref": "session:goalrun-a",
            "model_route_ref": "model-route:mrt_local_default",
            "lifecycle_status": "active",
            "execution_wiring": "adapter_slot_unwired",
            "runnability_state": "runnable",
            "provider_trust": "remote",
            "model_route_state": "available",
            "invocation_ref": "harness_invocation://hi_1",
        });
        let err = core
            .admit_harness_invocation(&request, "2026-01-01T00:00:00Z")
            .unwrap_err();
        assert_eq!(err.code, "goal_run_invocation_execution_unwired");
        request["execution_wiring"] = json!("lane_a_host_spawn");
        let err = core
            .admit_harness_invocation(&request, "2026-01-01T00:00:00Z")
            .unwrap_err();
        assert_eq!(
            err.code,
            "goal_run_invocation_provider_trust_acceptance_required"
        );
    }

    #[test]
    fn ioi_agent_strategy_selection_is_deterministic() {
        let core = RuntimeGoalRunAdmissionCore;
        let base = |strategy: &str, goal: &str| json!({
            "strategy": strategy,
            "normalized_goal": goal,
            "conductor_ref": "harness-profile:hp_hypervisor_worker",
            "implementer_candidates": [
                implementer("opencode", "active", "runnable"),
                implementer("deepseek_tui", "active", "runnable"),
            ],
        });
        let auto_small = core.select_ioi_agent_execution(&base("auto", "Create a status file")).unwrap();
        assert_eq!(auto_small["planned_execution_kind"], json!("direct"));
        assert_eq!(auto_small["selected_harness_ref"], json!("harness-profile:hp_opencode"));
        let auto_big = core
            .select_ioi_agent_execution(&base("auto", "Compare two approaches to the retry loop and pick the safer one"))
            .unwrap();
        assert_eq!(auto_big["planned_execution_kind"], json!("goal_run"));
        let compare = core.select_ioi_agent_execution(&base("compare", "Small goal")).unwrap();
        assert_eq!(compare["planned_execution_kind"], json!("goal_run"));
        // compare fails closed with one implementer
        let mut one = base("compare", "Small goal");
        one["implementer_candidates"] = json!([implementer("opencode", "active", "runnable")]);
        assert_eq!(
            core.select_ioi_agent_execution(&one).unwrap_err().code,
            "ioi_agent_compare_insufficient_implementers"
        );
        // private_local excludes non-local trust with an explicit reason
        let mut private = base("private_local", "Small goal");
        private["implementer_candidates"][1]["provider_trust"] = json!("remote");
        let selected = core.select_ioi_agent_execution(&private).unwrap();
        assert_eq!(selected["remote_slots_disabled"], json!(true));
        assert_eq!(
            selected["excluded_harnesses"][0]["reason_code"],
            json!("private_local_excludes_remote_trust")
        );
    }

    #[test]
    fn reconciliation_blocked_partial_is_explicit() {
        let core = RuntimeGoalRunAdmissionCore;
        let blocked = json!({
            "goal_ref": "goal://gr_test",
            "merge_strategy": "none_blocked",
            "selected_candidate_refs": [],
            "rejected_candidate_refs": ["implementation_result://ir_1"],
            "verifier_evidence_refs": ["agentgres://goal-run-verification/gv_1"],
            "reason_code": "no_verified_candidate",
            "receipt_required": true,
        });
        let admitted = core
            .admit_reconciliation(&blocked, "2026-01-01T00:00:00Z")
            .unwrap();
        assert_eq!(admitted["merge_strategy"], json!("none_blocked"));
        let single = json!({
            "goal_ref": "goal://gr_test",
            "merge_strategy": "select_single_best",
            "selected_candidate_refs": ["implementation_result://ir_1", "implementation_result://ir_2"],
            "rejected_candidate_refs": [],
            "verifier_evidence_refs": ["agentgres://goal-run-verification/gv_1"],
            "receipt_required": true,
        });
        let err = core
            .admit_reconciliation(&single, "2026-01-01T00:00:00Z")
            .unwrap_err();
        assert_eq!(err.code, "goal_run_reconciliation_selection_invalid");
    }
}
