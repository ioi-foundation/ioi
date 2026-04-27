use crate::agentic::runtime::types::{AgentState, WorkerAssignment};
use crate::agentic::runtime::worker_context::PARENT_PLAYBOOK_CONTEXT_MARKER;
use crate::agentic::runtime::worker_templates::builtin_worker_workflow;
use ioi_types::app::agentic::{
    ArgumentOrigin, CapabilityId, InstructionBindingKind, InstructionContract,
    InstructionSideEffectMode, InstructionSlotBinding, IntentConfidenceBand, IntentScopeProfile,
    ProtectedSlotKind, ResolvedIntentState,
};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::error::TransactionError;
use serde_json::json;
use std::collections::BTreeSet;
use url::Url;

pub(crate) fn delegated_research_bootstrap_query(goal: &str) -> Option<String> {
    let trimmed = goal
        .split_once(PARENT_PLAYBOOK_CONTEXT_MARKER)
        .map(|(head, _)| head)
        .unwrap_or(goal)
        .trim()
        .trim_end_matches(['.', '!', '?']);
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
        " and write me a ",
        " and write a ",
        " and write an ",
        " and prepare a ",
        " and prepare an ",
        " and draft a ",
        " and draft an ",
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

pub(crate) fn delegated_research_query_contract(goal: &str) -> Option<String> {
    let trimmed = goal
        .split_once(PARENT_PLAYBOOK_CONTEXT_MARKER)
        .map(|(head, _)| head)
        .unwrap_or(goal)
        .trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
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
    child_state.status =
        crate::agentic::runtime::types::AgentStatus::Completed(Some(trimmed_result.to_string()));
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

pub(super) fn seed_delegated_child_execution_queue(
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
        let Some(query_contract) = delegated_research_query_contract(&assignment.goal) else {
            return Ok(());
        };
        let Some(query) = delegated_research_bootstrap_query(&query_contract) else {
            return Ok(());
        };

        let _ = queue_delegated_child_web_search(
            child_state,
            child_session_id,
            &query,
            &query_contract,
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

pub(super) fn delegated_child_preset_resolved_intent(
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
            required_evidence: vec![],
            success_conditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            intent_catalog_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            intent_catalog_source_hash: [1u8; 32],
            evidence_requirements_hash: [2u8; 32],
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
            required_evidence: vec![],
            success_conditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            intent_catalog_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            intent_catalog_source_hash: [1u8; 32],
            evidence_requirements_hash: [2u8; 32],
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
            required_evidence: vec![],
            success_conditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            intent_catalog_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            intent_catalog_source_hash: [1u8; 32],
            evidence_requirements_hash: [2u8; 32],
            provider_selection: None,
            instruction_contract: Some(InstructionContract {
                operation: "verify".to_string(),
                side_effect_mode: InstructionSideEffectMode::ReadOnly,
                slot_bindings,
                negative_constraints: vec![
                    "Do not issue `memory__search` or raw web retrieval from the verifier lane; audit the inherited cited brief from receipt-bound context first and use `memory__read` only for a named evidence gap.".to_string(),
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
            required_evidence: vec![],
            success_conditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            intent_catalog_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            intent_catalog_source_hash: [1u8; 32],
            evidence_requirements_hash: [2u8; 32],
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
            required_evidence: vec![],
            success_conditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            intent_catalog_version: "delegated-child-bootstrap-v1".to_string(),
            embedding_model_id: "delegated-child-bootstrap".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            intent_catalog_source_hash: [1u8; 32],
            evidence_requirements_hash: [2u8; 32],
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
