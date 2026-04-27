use super::*;
use crate::agentic::pii_substrate;
use crate::agentic::runtime::agent_playbooks::builtin_agent_playbook;
use crate::agentic::runtime::connectors::{
    connector_id_for_tool_name, connector_protected_slot_bindings,
    connector_symbolic_reference_bindings, connector_symbolic_reference_inference_bindings,
    ConnectorProtectedSlotBinding, ConnectorSymbolicReferenceBinding,
    ConnectorSymbolicReferenceInferenceBinding, ResolvedSymbolicReference,
};
use crate::agentic::runtime::execution::filesystem::resolve_tool_path;
use crate::agentic::runtime::keys::get_parent_playbook_run_key;
use crate::agentic::runtime::service::lifecycle::load_worker_assignment;
use crate::agentic::runtime::service::step::action::command_contract::contract_requires_evidence_with_rules;
use crate::agentic::runtime::service::step::action::support::{
    execution_evidence_key, record_execution_evidence_with_value,
};
use crate::agentic::runtime::types::{ParentPlaybookRun, WorkerAssignment};
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{
    ArgumentOrigin, InstructionBindingKind, InstructionSlotBinding, PiiClass, ProtectedSlotKind,
    ResolvedIntentState,
};
use ioi_types::codec;
use lettre::message::Mailbox;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

fn selected_connector_id(
    resolved: &ResolvedIntentState,
    tool_name: Option<&str>,
) -> Option<String> {
    resolved
        .provider_selection
        .as_ref()
        .and_then(|selection| selection.selected_connector_id.as_deref())
        .map(str::to_string)
        .or_else(|| {
            tool_name
                .and_then(connector_id_for_tool_name)
                .map(str::to_string)
        })
}

fn lookup_symbolic_reference_binding(
    connector_id: &str,
) -> Option<ConnectorSymbolicReferenceBinding> {
    connector_symbolic_reference_bindings()
        .into_iter()
        .find(|binding| binding.connector_id == connector_id)
}

fn lookup_symbolic_reference_inference_binding(
    connector_id: &str,
) -> Option<ConnectorSymbolicReferenceInferenceBinding> {
    connector_symbolic_reference_inference_bindings()
        .into_iter()
        .find(|binding| binding.connector_id == connector_id)
}

fn validate_protected_literal(
    slot: &InstructionSlotBinding,
    raw: &str,
) -> Result<Value, TransactionError> {
    match slot.protected_slot_kind {
        ProtectedSlotKind::EmailAddress | ProtectedSlotKind::AccountEmail => {
            let mailbox = raw.trim().parse::<Mailbox>().map_err(|error| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=GroundingMissing Protected slot '{}' requires a valid email literal: {}",
                    slot.slot, error
                ))
            })?;
            Ok(Value::String(mailbox.to_string()))
        }
        _ => Ok(Value::String(raw.trim().to_string())),
    }
}

fn normalize_grounding_phrase(raw: &str) -> String {
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

fn query_attests_email_literal(query: &str, raw: &str) -> bool {
    let query_lower = query.to_ascii_lowercase();
    let candidate = raw.trim().to_ascii_lowercase();
    !candidate.is_empty() && query_lower.contains(&candidate)
}

fn is_redacted_email_placeholder(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("<redacted:email>")
        || normalized == "redacted:email"
        || normalized == "redacted_email"
}

fn recover_single_explicit_email_literal(query: &str) -> Option<String> {
    let evidence = pii_substrate::build_evidence_graph(query).ok()?;
    let mut emails = evidence
        .spans
        .iter()
        .filter(|span| span.pii_class == PiiClass::Email)
        .filter_map(|span| {
            let start = usize::try_from(span.start_index).ok()?;
            let end = usize::try_from(span.end_index).ok()?;
            if start >= end
                || end > query.len()
                || !query.is_char_boundary(start)
                || !query.is_char_boundary(end)
            {
                return None;
            }
            query[start..end].trim().parse::<Mailbox>().ok()
        })
        .map(|mailbox| mailbox.to_string())
        .collect::<Vec<_>>();
    emails.sort_by_key(|value| value.to_ascii_lowercase());
    emails.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    if emails.len() == 1 {
        emails.into_iter().next()
    } else {
        None
    }
}

fn recover_redacted_protected_literal_from_query(
    query: &str,
    binding: &InstructionSlotBinding,
    raw: &str,
) -> Option<String> {
    if !is_redacted_email_placeholder(raw) {
        return None;
    }
    match binding.protected_slot_kind {
        ProtectedSlotKind::EmailAddress | ProtectedSlotKind::AccountEmail => {
            recover_single_explicit_email_literal(query)
        }
        _ => None,
    }
}

fn query_attests_phrase_literal(query: &str, raw: &str) -> bool {
    let normalized_query = format!(" {} ", normalize_grounding_phrase(query));
    let normalized_candidate = normalize_grounding_phrase(raw);
    !normalized_candidate.is_empty()
        && normalized_query.contains(&format!(" {} ", normalized_candidate))
}

fn query_attests_protected_literal(query: &str, slot: &InstructionSlotBinding, raw: &str) -> bool {
    match slot.protected_slot_kind {
        ProtectedSlotKind::EmailAddress | ProtectedSlotKind::AccountEmail => {
            query_attests_email_literal(query, raw) || query_attests_phrase_literal(query, raw)
        }
        ProtectedSlotKind::CalendarId
        | ProtectedSlotKind::ResourceId
        | ProtectedSlotKind::ProjectId
        | ProtectedSlotKind::FileId => query_attests_phrase_literal(query, raw),
        ProtectedSlotKind::Unknown => true,
    }
}

fn current_argument_literal<'a>(arguments: &'a Map<String, Value>, slot: &str) -> Option<&'a str> {
    arguments.get(slot).and_then(Value::as_str)
}

fn slot_bindings_by_name(
    resolved: &ResolvedIntentState,
) -> BTreeMap<String, InstructionSlotBinding> {
    resolved
        .instruction_contract
        .as_ref()
        .map(|contract| {
            contract
                .slot_bindings
                .iter()
                .cloned()
                .filter(|binding| !binding.slot.trim().is_empty())
                .map(|binding| (binding.slot.clone(), binding))
                .collect()
        })
        .unwrap_or_default()
}

fn tool_name_for_grounding(tool_value: &Value) -> Option<&str> {
    tool_value.get("name").and_then(Value::as_str)
}

fn instruction_contract_slot_value<'a>(
    resolved: &'a ResolvedIntentState,
    slot_name: &str,
) -> Option<&'a str> {
    resolved
        .instruction_contract
        .as_ref()?
        .slot_bindings
        .iter()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case(slot_name))
        .and_then(|binding| binding.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn should_synthesize_root_delegate_tool(
    agent_state: &AgentState,
    resolved: &ResolvedIntentState,
    resolved_intent_id: &str,
    root_playbook_started: bool,
) -> bool {
    if resolved_intent_id
        .trim()
        .eq_ignore_ascii_case("delegation.task")
    {
        return false;
    }
    if agent_state.parent_session_id.is_some() {
        return false;
    }
    if root_playbook_started {
        return false;
    }
    let Some(playbook_id) = instruction_contract_slot_value(resolved, "playbook_id") else {
        return false;
    };
    builtin_agent_playbook(Some(playbook_id)).is_some()
}

fn root_playbook_run_exists(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    resolved: &ResolvedIntentState,
) -> bool {
    let Some(playbook_id) = instruction_contract_slot_value(resolved, "playbook_id") else {
        return false;
    };
    let key = get_parent_playbook_run_key(&agent_state.session_id, playbook_id);
    state.get(&key).ok().flatten().is_some()
}

fn synthesize_root_delegate_tool(
    agent_state: &AgentState,
    resolved: &ResolvedIntentState,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let playbook_id = instruction_contract_slot_value(resolved, "playbook_id")?;
    verification_checks.push("root_playbook_delegate_synthesized=true".to_string());
    verification_checks.push(format!("root_playbook_delegate_playbook={playbook_id}"));
    if let Some(template_id) = instruction_contract_slot_value(resolved, "template_id") {
        verification_checks.push(format!("root_playbook_delegate_template={template_id}"));
    }
    if let Some(workflow_id) = instruction_contract_slot_value(resolved, "workflow_id") {
        verification_checks.push(format!("root_playbook_delegate_workflow={workflow_id}"));
    }
    Some(AgentTool::AgentDelegate {
        goal: agent_state.goal.clone(),
        budget: 0,
        playbook_id: Some(playbook_id.to_string()),
        template_id: instruction_contract_slot_value(resolved, "template_id").map(str::to_string),
        workflow_id: instruction_contract_slot_value(resolved, "workflow_id").map(str::to_string),
        role: None,
        success_criteria: None,
        merge_mode: None,
        expected_output: None,
    })
}

fn canonicalize_filesystem_read_directory_tool(
    tool: AgentTool,
    working_directory: &str,
    verification_checks: &mut Vec<String>,
) -> AgentTool {
    let AgentTool::FsRead { path } = tool else {
        return tool;
    };

    let resolved_path = match resolve_tool_path(&path, Some(working_directory)) {
        Ok(path) => path,
        Err(_) => return AgentTool::FsRead { path },
    };
    if !resolved_path.is_dir() {
        return AgentTool::FsRead { path };
    }

    verification_checks
        .push("filesystem_read_directory_rewritten_to_list_directory=true".to_string());
    verification_checks.push(format!(
        "filesystem_read_directory_target={}",
        resolved_path.display()
    ));
    AgentTool::FsList { path }
}

fn split_parent_playbook_context(goal: &str) -> (&str, Option<&str>) {
    if let Some((head, tail)) = goal.split_once("[PARENT PLAYBOOK CONTEXT]") {
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

fn patch_build_verify_likely_files(assignment: &WorkerAssignment) -> Vec<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return Vec::new();
    }
    let (_, inherited_context) = split_parent_playbook_context(&assignment.goal);
    let Some(value) =
        inherited_context.and_then(|text| extract_worker_context_field(text, &["likely_files"]))
    else {
        return Vec::new();
    };

    value
        .split(['\n', ';', ','])
        .map(str::trim)
        .map(|item| item.trim_matches('`').trim())
        .filter(|item| !item.is_empty() && !item.to_ascii_lowercase().starts_with("repo root:"))
        .map(str::to_string)
        .collect()
}

fn resolved_path_matches_likely_file(
    requested: &Path,
    working_directory: &str,
    likely_file: &str,
) -> bool {
    if let Ok(candidate) = resolve_tool_path(likely_file, Some(working_directory)) {
        if candidate == requested {
            return true;
        }
    }

    let requested_name = requested.file_name().and_then(|value| value.to_str());
    let likely_name = Path::new(likely_file)
        .file_name()
        .and_then(|value| value.to_str());
    requested_name.is_some() && requested_name == likely_name
}

fn redirect_patch_build_verify_reads_to_likely_file(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    tool: AgentTool,
    verification_checks: &mut Vec<String>,
) -> AgentTool {
    let AgentTool::FsRead { path } = tool else {
        return tool;
    };

    let Some(assignment) = load_worker_assignment(state, agent_state.session_id)
        .ok()
        .flatten()
    else {
        return AgentTool::FsRead { path };
    };
    let likely_files = patch_build_verify_likely_files(&assignment);
    if likely_files.is_empty() {
        return AgentTool::FsRead { path };
    }

    let resolved_path = match resolve_tool_path(&path, Some(&agent_state.working_directory)) {
        Ok(path) => path,
        Err(_) => return AgentTool::FsRead { path },
    };
    if likely_files.iter().any(|candidate| {
        resolved_path_matches_likely_file(&resolved_path, &agent_state.working_directory, candidate)
    }) {
        return AgentTool::FsRead { path };
    }

    let Some(primary_likely_file) = likely_files.first().cloned() else {
        return AgentTool::FsRead { path };
    };
    verification_checks.push("filesystem_read_redirected_to_likely_file=true".to_string());
    verification_checks.push(format!(
        "filesystem_read_redirect_source={}",
        resolved_path.display()
    ));
    verification_checks.push(format!(
        "filesystem_read_redirect_target={}",
        primary_likely_file
    ));
    AgentTool::FsRead {
        path: primary_likely_file,
    }
}

fn active_parent_playbook_child_session_id(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    resolved: &ResolvedIntentState,
) -> Option<[u8; 32]> {
    let playbook_id = instruction_contract_slot_value(resolved, "playbook_id")?;
    let key = get_parent_playbook_run_key(&agent_state.session_id, playbook_id);
    let bytes = state.get(&key).ok().flatten()?;
    let run = codec::from_bytes_canonical::<ParentPlaybookRun>(&bytes).ok()?;
    run.active_child_session_id
}

fn should_synthesize_parent_playbook_await(
    resolved_intent_id: &str,
    tool_name: Option<&str>,
    active_child_session_id: Option<[u8; 32]>,
) -> bool {
    if resolved_intent_id
        .trim()
        .eq_ignore_ascii_case("delegation.task")
    {
        return false;
    }
    if active_child_session_id.is_none() {
        return false;
    }
    !matches!(tool_name, Some("agent__await"))
}

fn synthesize_parent_playbook_await(
    child_session_id: [u8; 32],
    verification_checks: &mut Vec<String>,
) -> AgentTool {
    let child_session_id_hex = hex::encode(child_session_id);
    verification_checks.push("parent_playbook_await_synthesized=true".to_string());
    verification_checks.push(format!(
        "parent_playbook_await_child={child_session_id_hex}"
    ));
    AgentTool::AgentAwait {
        child_session_id_hex,
    }
}

fn apply_delegate_template_binding(
    tool_name: Option<&str>,
    arguments: &mut Map<String, Value>,
    bindings: &mut BTreeMap<String, InstructionSlotBinding>,
    grounded_slots: &mut Vec<Value>,
    verification_checks: &mut Vec<String>,
) -> bool {
    if !matches!(tool_name, Some("agent__delegate")) {
        return false;
    }

    let mut applied = false;
    for slot_name in ["playbook_id", "template_id", "workflow_id"] {
        let Some(binding) = bindings.get(slot_name).cloned() else {
            continue;
        };
        if !matches!(binding.binding_kind, InstructionBindingKind::UserLiteral)
            || !matches!(binding.protected_slot_kind, ProtectedSlotKind::Unknown)
        {
            continue;
        }
        if current_argument_literal(arguments, slot_name)
            .map(str::trim)
            .map(|value| !value.is_empty())
            .unwrap_or(false)
        {
            continue;
        }
        let Some(value) = binding
            .value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        arguments.insert(slot_name.to_string(), Value::String(value.to_string()));
        grounded_slots.push(json!({
            "slot": slot_name,
            "bindingKind": "user_literal",
            "value": value,
            "origin": binding.origin,
            "protectedSlotKind": binding.protected_slot_kind,
        }));
        verification_checks.push(format!("grounding_slot={}::user_literal", slot_name));
        bindings.remove(slot_name);
        applied = true;
    }

    applied
}

fn merge_slot_binding_with_protected_slot_metadata(
    mut existing: InstructionSlotBinding,
    protected_slot: &ConnectorProtectedSlotBinding,
    arguments: &Map<String, Value>,
) -> InstructionSlotBinding {
    if existing.protected_slot_kind == ProtectedSlotKind::Unknown {
        existing.protected_slot_kind = protected_slot.protected_slot_kind;
    }
    if existing.value.is_none() {
        existing.value =
            current_argument_literal(arguments, &protected_slot.slot).map(str::to_string);
    }
    if matches!(existing.origin, ArgumentOrigin::ToolDefault) {
        existing.origin = ArgumentOrigin::ModelInferred;
    }
    existing
}

fn protected_slot_bindings_by_name(
    resolved: &ResolvedIntentState,
    tool_name: Option<&str>,
    arguments: &Map<String, Value>,
) -> BTreeMap<String, InstructionSlotBinding> {
    let mut bindings = slot_bindings_by_name(resolved);
    let Some(tool_name) = tool_name else {
        return bindings;
    };

    for protected_slot in connector_protected_slot_bindings()
        .into_iter()
        .filter(|binding| binding.tool_name == tool_name)
    {
        let synthetic = InstructionSlotBinding {
            slot: protected_slot.slot.clone(),
            binding_kind: if current_argument_literal(arguments, &protected_slot.slot).is_some() {
                InstructionBindingKind::UserLiteral
            } else {
                InstructionBindingKind::Unresolved
            },
            value: current_argument_literal(arguments, &protected_slot.slot).map(str::to_string),
            origin: ArgumentOrigin::ModelInferred,
            protected_slot_kind: protected_slot.protected_slot_kind,
        };
        match bindings.remove(&protected_slot.slot) {
            Some(existing) => {
                bindings.insert(
                    protected_slot.slot.clone(),
                    merge_slot_binding_with_protected_slot_metadata(
                        existing,
                        &protected_slot,
                        arguments,
                    ),
                );
            }
            None => {
                bindings.insert(protected_slot.slot.clone(), synthetic);
            }
        }
    }

    bindings
}

async fn resolve_symbolic_reference(
    resolver_binding: ConnectorSymbolicReferenceBinding,
    agent_state: &AgentState,
    slot: &InstructionSlotBinding,
    reference: &str,
) -> Result<ResolvedSymbolicReference, TransactionError> {
    let Some(resolved_reference) = (resolver_binding.resolve)(agent_state, reference)
        .await
        .map_err(|error| {
            TransactionError::Invalid(format!("ERROR_CLASS=GroundingMissing {}", error))
        })?
    else {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=GroundingMissing Symbolic reference '{}' for slot '{}' could not be resolved.",
            reference, slot.slot
        )));
    };
    Ok(resolved_reference)
}

async fn infer_symbolic_reference_from_query(
    inference_binding: Option<ConnectorSymbolicReferenceInferenceBinding>,
    agent_state: &AgentState,
    slot: &InstructionSlotBinding,
    query: &str,
) -> Result<Option<String>, TransactionError> {
    let Some(inference_binding) = inference_binding else {
        return Ok(None);
    };
    (inference_binding.infer)(agent_state, &slot.slot, query, slot.protected_slot_kind)
        .await
        .map_err(|error| {
            TransactionError::Invalid(format!("ERROR_CLASS=GroundingMissing {}", error))
        })
}

fn record_grounded_symbolic_reference(
    service: &RuntimeAgentService,
    arguments: &mut Map<String, Value>,
    grounded_slots: &mut Vec<Value>,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    slot: &InstructionSlotBinding,
    reference: &str,
    resolved_reference: ResolvedSymbolicReference,
) {
    let provider_id = resolved_reference.provider_id.clone();
    arguments.insert(slot.slot.clone(), resolved_reference.value.clone());
    grounded_slots.push(json!({
        "slot": slot.slot,
        "bindingKind": "symbolic_ref",
        "reference": reference,
        "resolvedValue": resolved_reference.value,
        "origin": resolved_reference.origin,
        "protectedSlotKind": slot.protected_slot_kind,
        "providerId": provider_id,
    }));
    verification_checks.push(format!(
        "grounding_slot={}::symbolic_ref::{}",
        slot.slot, reference
    ));
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        "grounding",
        true,
        &resolved_reference.evidence,
        Some("instruction_contract"),
        Some(reference),
        Some("symbolic_ref"),
        None,
        resolved_reference.provider_id,
        synthesized_payload_hash,
    );
}

pub(super) async fn apply_instruction_contract_grounding(
    state: &dyn StateAccess,
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    tool: AgentTool,
    rules: &ActionRules,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<AgentTool, TransactionError> {
    let Some(resolved) = agent_state.resolved_intent.as_ref() else {
        return Ok(tool);
    };
    let requires_grounding = contract_requires_evidence_with_rules(agent_state, rules, "grounding");
    let tool_name = serde_json::to_value(&tool)
        .ok()
        .and_then(|value| tool_name_for_grounding(&value).map(str::to_string));
    let active_playbook_child =
        active_parent_playbook_child_session_id(state, agent_state, resolved);
    let root_playbook_started = root_playbook_run_exists(state, agent_state, resolved);
    let tool = if should_synthesize_parent_playbook_await(
        resolved_intent_id,
        tool_name.as_deref(),
        active_playbook_child,
    ) {
        synthesize_parent_playbook_await(
            active_playbook_child.expect("active playbook child should exist"),
            verification_checks,
        )
    } else if should_synthesize_root_delegate_tool(
        agent_state,
        resolved,
        resolved_intent_id,
        root_playbook_started,
    ) {
        synthesize_root_delegate_tool(agent_state, resolved, verification_checks).unwrap_or(tool)
    } else {
        tool
    };
    let tool = redirect_patch_build_verify_reads_to_likely_file(
        state,
        agent_state,
        tool,
        verification_checks,
    );
    let tool = canonicalize_filesystem_read_directory_tool(
        tool,
        &agent_state.working_directory,
        verification_checks,
    );

    let mut tool_value =
        serde_json::to_value(&tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let tool_name = tool_name_for_grounding(&tool_value).map(str::to_string);
    let Some(arguments) = tool_value
        .get_mut("arguments")
        .and_then(Value::as_object_mut)
    else {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=GroundingMissing Tool arguments were unavailable for grounding."
                .to_string(),
        ));
    };

    let mut grounded_slots = Vec::<Value>::new();
    let mut bindings = protected_slot_bindings_by_name(resolved, tool_name.as_deref(), arguments);
    let applied_delegate_template = apply_delegate_template_binding(
        tool_name.as_deref(),
        arguments,
        &mut bindings,
        &mut grounded_slots,
        verification_checks,
    );
    if !requires_grounding {
        if applied_delegate_template {
            return serde_json::from_value::<AgentTool>(Value::Object(
                tool_value.as_object().cloned().unwrap_or_else(Map::new),
            ))
            .map_err(|error| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=GroundingMissing Failed to rebuild grounded tool payload: {}",
                    error
                ))
            });
        }
        return Ok(tool);
    }

    let connector_id = selected_connector_id(resolved, tool_name.as_deref()).ok_or_else(|| {
        TransactionError::Invalid(
            "ERROR_CLASS=GroundingMissing Connector selection missing for grounded intent."
                .to_string(),
        )
    })?;
    let resolver_binding = lookup_symbolic_reference_binding(&connector_id).ok_or_else(|| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=GroundingMissing No symbolic reference resolver registered for connector '{}'.",
            connector_id
        ))
    })?;
    let inference_binding = lookup_symbolic_reference_inference_binding(&connector_id);
    let user_query = agent_state.goal.clone();

    for binding in bindings.into_values() {
        match binding.binding_kind {
            InstructionBindingKind::SymbolicRef => {
                let reference = binding.value.as_deref().ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "ERROR_CLASS=GroundingMissing Symbolic slot '{}' was missing a reference.",
                        binding.slot
                    ))
                })?;
                let resolved_reference =
                    resolve_symbolic_reference(resolver_binding, agent_state, &binding, reference)
                        .await?;
                record_grounded_symbolic_reference(
                    service,
                    arguments,
                    &mut grounded_slots,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash.clone(),
                    &binding,
                    reference,
                    resolved_reference,
                );
            }
            InstructionBindingKind::UserLiteral => {
                let literal = current_argument_literal(arguments, &binding.slot)
                    .or_else(|| binding.value.as_deref())
                    .ok_or_else(|| {
                        TransactionError::Invalid(format!(
                        "ERROR_CLASS=GroundingMissing User literal slot '{}' was missing a value.",
                        binding.slot
                    ))
                    })?;
                let literal =
                    recover_redacted_protected_literal_from_query(&user_query, &binding, literal)
                        .unwrap_or_else(|| literal.trim().to_string());
                let attested = query_attests_protected_literal(&user_query, &binding, &literal);
                let validated_literal = validate_protected_literal(&binding, &literal).ok();
                if matches!(binding.protected_slot_kind, ProtectedSlotKind::Unknown) {
                    let grounded_value =
                        validated_literal.unwrap_or(Value::String(literal.clone()));
                    arguments.insert(binding.slot.clone(), grounded_value.clone());
                    grounded_slots.push(json!({
                        "slot": binding.slot,
                        "bindingKind": "user_literal",
                        "value": grounded_value,
                        "origin": binding.origin,
                        "protectedSlotKind": binding.protected_slot_kind,
                    }));
                    verification_checks
                        .push(format!("grounding_slot={}::user_literal", binding.slot));
                    continue;
                }

                if attested {
                    if let Some(grounded_value) = validated_literal {
                        arguments.insert(binding.slot.clone(), grounded_value.clone());
                        grounded_slots.push(json!({
                            "slot": binding.slot,
                            "bindingKind": "user_literal",
                            "value": grounded_value,
                            "origin": binding.origin,
                            "protectedSlotKind": binding.protected_slot_kind,
                        }));
                        verification_checks.push(format!(
                            "grounding_slot={}::user_literal_attested",
                            binding.slot
                        ));
                        continue;
                    }
                }

                if let Some(reference) = infer_symbolic_reference_from_query(
                    inference_binding,
                    agent_state,
                    &binding,
                    &user_query,
                )
                .await?
                {
                    let resolved_reference = resolve_symbolic_reference(
                        resolver_binding,
                        agent_state,
                        &binding,
                        &reference,
                    )
                    .await?;
                    record_grounded_symbolic_reference(
                        service,
                        arguments,
                        &mut grounded_slots,
                        verification_checks,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        synthesized_payload_hash.clone(),
                        &binding,
                        &reference,
                        resolved_reference,
                    );
                    verification_checks.push(format!(
                        "grounding_slot={}::query_inferred_symbolic_ref",
                        binding.slot
                    ));
                    continue;
                }

                if attested {
                    return Err(TransactionError::Invalid(format!(
                        "ERROR_CLASS=GroundingMissing Protected slot '{}' was attested by the user request but could not be validated as a canonical literal or resolved from connector state.",
                        binding.slot
                    )));
                }

                return Err(TransactionError::Invalid(format!(
                    "ERROR_CLASS=GroundingMissing Protected slot '{}' literal was not directly attested by the user request and could not be resolved from connector state.",
                    binding.slot
                )));
            }
            InstructionBindingKind::Unresolved => {
                if !matches!(binding.protected_slot_kind, ProtectedSlotKind::Unknown) {
                    if let Some(reference) = infer_symbolic_reference_from_query(
                        inference_binding,
                        agent_state,
                        &binding,
                        &user_query,
                    )
                    .await?
                    {
                        let resolved_reference = resolve_symbolic_reference(
                            resolver_binding,
                            agent_state,
                            &binding,
                            &reference,
                        )
                        .await?;
                        record_grounded_symbolic_reference(
                            service,
                            arguments,
                            &mut grounded_slots,
                            verification_checks,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            synthesized_payload_hash.clone(),
                            &binding,
                            &reference,
                            resolved_reference,
                        );
                        verification_checks.push(format!(
                            "grounding_slot={}::unresolved_query_inferred_symbolic_ref",
                            binding.slot
                        ));
                        continue;
                    }
                    return Err(TransactionError::Invalid(format!(
                        "ERROR_CLASS=GroundingMissing Protected slot '{}' remained unresolved.",
                        binding.slot
                    )));
                }
            }
        }
    }

    let grounding_commit = serde_jcs::to_vec(&grounded_slots)
        .ok()
        .and_then(|bytes| sha256(&bytes).ok())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|| "sha256:unavailable".to_string());
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        "grounding",
        grounding_commit.clone(),
    );
    verification_checks.push(execution_evidence_key("grounding"));
    verification_checks.push(format!("grounding_commit={}", grounding_commit));

    serde_json::from_value::<AgentTool>(Value::Object(
        tool_value.as_object().cloned().unwrap_or_else(Map::new),
    ))
    .map_err(|error| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=GroundingMissing Failed to rebuild grounded tool payload: {}",
            error
        ))
    })
}

#[cfg(test)]
#[path = "grounding/tests.rs"]
mod tests;
