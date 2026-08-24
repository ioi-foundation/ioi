use crate::agentic::runtime::service::decision_loop::intent_resolver::{
    is_tool_allowed_for_resolution, is_tool_allowed_for_selected_provider,
};
use crate::agentic::runtime::service::lifecycle::load_worker_assignment;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::tools::contracts::{
    observed_primitive_capabilities_for_action_target, observed_runtime_tool_boundary,
    validate_admitted_runtime_tool_contract, ResolvedRuntimeToolContract,
};
use crate::agentic::runtime::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use ioi_types::error::TransactionError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

const ADMISSION_RECEIPT_SCHEMA_VERSION: &str = "ioi.runtime-tool-invocation-admission.v1";
const ADMISSION_RECEIPT_PREFIX: &[u8] = b"runtime_tool_invocation_admission::";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct RuntimeToolInvocationAdmissionReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub session_id: String,
    pub step_index: u32,
    pub tool_name: String,
    pub tool_revision_ref: String,
    pub tool_content_hash: String,
    pub contract_admission_receipt_ref: String,
    pub arguments_hash: String,
    pub policy_target: String,
    pub action_target: String,
    pub effect_class: String,
    pub primitive_capability_grants: Vec<String>,
    pub authority_scope_grants: Vec<String>,
    pub grant_source_ref: String,
    pub effective_data_class: String,
    pub effective_destination: String,
    pub status: String,
}

fn invalid(message: impl Into<String>) -> TransactionError {
    TransactionError::Invalid(format!(
        "ERROR_CLASS=RuntimeToolContractAdmission {}",
        message.into()
    ))
}

fn sha256_hex(bytes: &[u8]) -> Result<String, TransactionError> {
    sha256(bytes)
        .map(|digest| hex::encode(digest.as_ref()))
        .map_err(|error| invalid(format!("hash failed: {error}")))
}

fn resolve_contract(
    service: &RuntimeAgentService,
    tool: &AgentTool,
) -> Result<(ResolvedRuntimeToolContract, String), TransactionError> {
    let tool_name = tool.name_string();
    let registered = service
        .runtime_tool_contract_registry
        .read()
        .map_err(|_| invalid("RuntimeToolContract registry lock poisoned"))?
        .resolve_current_for_name(&tool_name)
        .map_err(|error| invalid(format!("{}: {}", error.code, error.message)))?;
    let observed = observed_runtime_tool_boundary(&tool_name).map_err(invalid)?;
    let action_target = tool.target().canonical_label();
    let observed_action_primitives =
        observed_primitive_capabilities_for_action_target(&action_target);
    if registered.contract.effect_class != observed.contract.effect_class
        || registered.contract.risk_class != observed.contract.risk_class
        || registered.contract.primitive_capabilities_required
            != observed.contract.primitive_capabilities_required
        || registered.contract.authority_scopes_required
            != observed.contract.authority_scopes_required
    {
        return Err(invalid(format!(
            "actual daemon boundary for '{tool_name}' drifts from registered contract {}",
            registered.contract.revision_ref
        )));
    }
    if observed_action_primitives.is_empty()
        || observed_action_primitives.iter().any(|primitive| {
            !registered
                .contract
                .primitive_capabilities_required
                .contains(primitive)
        })
    {
        return Err(invalid(format!(
            "actual daemon target '{action_target}' exceeds registered primitive boundary for '{tool_name}'"
        )));
    }
    Ok((
        ResolvedRuntimeToolContract {
            contract: registered.contract,
            policy_target: observed.policy_target,
            action_target,
        },
        registered.admission_receipt_ref,
    ))
}

fn exact_grant_source(
    state: Option<&dyn StateAccess>,
    agent_state: &AgentState,
    session_id: [u8; 32],
    tool_name: &str,
) -> Result<String, TransactionError> {
    if let Some(state) = state {
        if let Some(assignment) = load_worker_assignment(state, session_id).map_err(invalid)? {
            if assignment.allowed_tools.is_empty() {
                return Err(invalid(format!(
                    "worker assignment '{}' has no bounded tool grants",
                    assignment.step_key
                )));
            }
            if !assignment
                .allowed_tools
                .iter()
                .any(|allowed| allowed == tool_name)
            {
                return Err(invalid(format!(
                    "worker assignment '{}' does not grant tool '{tool_name}'",
                    assignment.step_key
                )));
            }
            return Ok(format!("worker-assignment://{}", assignment.step_key));
        }
    }

    if let Some(resolved) = agent_state.resolved_intent.as_ref() {
        if !is_tool_allowed_for_resolution(Some(resolved), tool_name)
            || !is_tool_allowed_for_selected_provider(Some(resolved), tool_name)
        {
            return Err(invalid(format!(
                "resolved intent '{}' does not grant tool '{tool_name}'",
                resolved.intent_id
            )));
        }
        return Ok(format!(
            "intent-resolution://{}/{}",
            resolved.intent_id,
            hex::encode(resolved.evidence_requirements_hash)
        ));
    }

    #[cfg(test)]
    {
        // Unit-level executor tests exercise the private handler without a
        // transaction/session bootstrap. Production callers always carry state
        // and a resolved intent or a worker assignment.
        if state.is_none() {
            return Ok("test-fixture://private-handler".to_string());
        }
    }

    Err(invalid(format!(
        "tool '{tool_name}' has neither a resolved-intent grant nor a worker assignment grant"
    )))
}

fn invocation_arguments(tool: &AgentTool) -> Value {
    serde_json::to_value(tool)
        .ok()
        .and_then(|value| value.get("arguments").cloned())
        .unwrap_or_else(|| json!({}))
}

fn effective_data_class(_arguments: &Value) -> String {
    // RuntimeToolContract admission never trusts a model/adapter-supplied
    // classification field. Until the wider IFC label plane is bound here,
    // the daemon applies its conservative internal default.
    "internal".to_string()
}

fn effective_destination(
    contract: &ResolvedRuntimeToolContract,
    tool_name: &str,
    arguments: &Value,
) -> String {
    let declared_url = || {
        arguments
            .get("url")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_string())
    };
    if tool_name.starts_with("connector__")
        || tool_name.starts_with("wallet_network__mail_")
        || tool_name.starts_with("wallet_mail_")
        || tool_name.starts_with("mail__")
    {
        return format!("connector://{}/*", tool_name.to_ascii_lowercase());
    }
    if contract.policy_target.starts_with("model::") {
        return "provider://model-runtime/bound".to_string();
    }
    if contract.policy_target.starts_with("media::")
        || contract.policy_target.starts_with("media__")
        || contract.policy_target.starts_with("gallery__")
    {
        return declared_url().unwrap_or_else(|| "provider://media-runtime/bound".to_string());
    }
    if contract.policy_target.starts_with("browser::") {
        return declared_url().unwrap_or_else(|| "browser-session://bound".to_string());
    }
    if contract.policy_target == "web::retrieve" {
        return declared_url().unwrap_or_else(|| "provider://web-retrieval/bound".to_string());
    }
    if contract.policy_target == "net::fetch" {
        return declared_url().unwrap_or_else(|| "invalid://missing-net-destination".to_string());
    }
    if let Some(merchant_url) = arguments
        .get("merchant_url")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return merchant_url.trim().to_string();
    }
    "local://daemon".to_string()
}

fn destination_matches(pattern: &str, destination: &str) -> bool {
    match pattern.split_once('*') {
        Some((prefix, suffix)) => destination.starts_with(prefix) && destination.ends_with(suffix),
        None => pattern == destination,
    }
}

fn enforce_information_flow(
    contract: &ResolvedRuntimeToolContract,
    data_class: &str,
    destination: &str,
) -> Result<(), TransactionError> {
    if !contract
        .contract
        .data_class_allowlist
        .iter()
        .any(|allowed| allowed == data_class)
    {
        return Err(invalid(format!(
            "data class '{data_class}' exceeds contract {}",
            contract.contract.revision_ref
        )));
    }
    let egress = &contract.contract.egress_policy;
    if destination == "local://daemon" {
        return Ok(());
    }
    if egress.default != "allow_declared"
        || !egress
            .allowed_destination_patterns
            .iter()
            .any(|pattern| destination_matches(pattern, destination))
    {
        return Err(invalid(format!(
            "destination '{destination}' is outside contract {}",
            contract.contract.revision_ref
        )));
    }
    Ok(())
}

fn persist_receipt(
    state: &mut dyn StateAccess,
    receipt: &RuntimeToolInvocationAdmissionReceipt,
) -> Result<(), TransactionError> {
    let bytes = serde_jcs::to_vec(receipt)
        .map_err(|error| invalid(format!("receipt canonicalization failed: {error}")))?;
    let mut key = ADMISSION_RECEIPT_PREFIX.to_vec();
    key.extend_from_slice(receipt.receipt_id.as_bytes());
    if let Some(existing) = state.get(&key)? {
        if existing != bytes {
            return Err(invalid(format!(
                "receipt replay conflict for {}",
                receipt.receipt_id
            )));
        }
        return Ok(());
    }
    state.insert(&key, &bytes)?;
    Ok(())
}

pub(super) async fn admit_runtime_tool_invocation(
    service: &RuntimeAgentService,
    state: &mut Option<&mut dyn StateAccess>,
    tool: &AgentTool,
    agent_state: &AgentState,
    session_id: [u8; 32],
    step_index: u32,
    _os_driver: &Arc<dyn OsDriver>,
) -> Result<RuntimeToolInvocationAdmissionReceipt, TransactionError> {
    let (resolved, contract_admission_receipt_ref) = resolve_contract(service, tool)?;
    validate_admitted_runtime_tool_contract(&resolved.contract).map_err(invalid)?;

    let tool_name = tool.name_string();
    let grant_source_ref = exact_grant_source(
        state.as_deref().map(|value| value as &dyn StateAccess),
        agent_state,
        session_id,
        &tool_name,
    )?;
    let arguments = invocation_arguments(tool);
    let arguments_jcs = serde_jcs::to_vec(&arguments)
        .map_err(|error| invalid(format!("argument canonicalization failed: {error}")))?;
    let arguments_hash = format!("sha256:{}", sha256_hex(&arguments_jcs)?);
    let data_class = effective_data_class(&arguments);
    let destination = effective_destination(&resolved, &tool_name, &arguments);
    enforce_information_flow(&resolved, &data_class, &destination)?;

    if resolved.contract.primitive_capabilities_required.is_empty() {
        return Err(invalid(format!(
            "contract {} grants no primitive capability to its final invoker",
            resolved.contract.revision_ref
        )));
    }
    if resolved.contract.effect_class != "read"
        && resolved.contract.authority_scopes_required.is_empty()
    {
        return Err(invalid(format!(
            "effectful contract {} has no bounded authority scope",
            resolved.contract.revision_ref
        )));
    }

    let intent = serde_jcs::to_vec(&json!({
        "session_id": hex::encode(session_id),
        "step_index": step_index,
        "tool_name": tool_name,
        "tool_revision_ref": resolved.contract.revision_ref,
        "tool_content_hash": resolved.contract.content_hash,
        "grant_source_ref": grant_source_ref,
        "arguments_hash": arguments_hash,
    }))
    .map_err(|error| invalid(format!("receipt identity failed: {error}")))?;
    let receipt_id = format!("runtime-tool-admission://{}", sha256_hex(&intent)?);
    let receipt = RuntimeToolInvocationAdmissionReceipt {
        schema_version: ADMISSION_RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id,
        session_id: hex::encode(session_id),
        step_index,
        tool_name,
        tool_revision_ref: resolved.contract.revision_ref,
        tool_content_hash: resolved.contract.content_hash,
        contract_admission_receipt_ref,
        arguments_hash,
        policy_target: resolved.policy_target,
        action_target: resolved.action_target,
        effect_class: resolved.contract.effect_class,
        primitive_capability_grants: resolved.contract.primitive_capabilities_required,
        authority_scope_grants: resolved.contract.authority_scopes_required,
        grant_source_ref,
        effective_data_class: data_class,
        effective_destination: destination,
        status: "admitted_pre_invocation".to_string(),
    };
    if let Some(state) = state.as_deref_mut() {
        persist_receipt(state, &receipt)?;
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::tools::contracts::admitted_runtime_tool_contract_for_native;

    #[test]
    fn released_native_contract_is_content_addressed_and_scope_separated() {
        let tool = AgentTool::FsWrite {
            path: "a.txt".to_string(),
            content: "hello".to_string(),
            line_number: None,
        };
        let resolved = admitted_runtime_tool_contract_for_native(&tool).unwrap();
        validate_admitted_runtime_tool_contract(&resolved.contract).unwrap();
        assert_eq!(
            resolved.contract.primitive_capabilities_required,
            vec!["prim:fs.write"]
        );
        assert!(resolved
            .contract
            .authority_scopes_required
            .contains(&"scope:fs.write".to_string()));
        assert_ne!(resolved.contract.content_hash, "sha256:");
    }

    #[test]
    fn changed_contract_body_is_rejected_under_same_hash() {
        let tool = AgentTool::FsRead {
            path: "a.txt".to_string(),
        };
        let mut contract = admitted_runtime_tool_contract_for_native(&tool)
            .unwrap()
            .contract;
        contract.effect_class = "destructive".to_string();
        assert!(validate_admitted_runtime_tool_contract(&contract)
            .unwrap_err()
            .contains("content_hash mismatch"));
    }

    #[test]
    fn destination_and_data_class_fail_closed() {
        let tool = AgentTool::NetFetch {
            url: "https://example.com".to_string(),
            max_chars: None,
        };
        let resolved = admitted_runtime_tool_contract_for_native(&tool).unwrap();
        enforce_information_flow(&resolved, "restricted", "https://example.com").unwrap_err();
        enforce_information_flow(&resolved, "internal", "file:///etc/passwd").unwrap_err();
        enforce_information_flow(&resolved, "internal", "https://example.com").unwrap();

        assert_eq!(
            effective_data_class(&json!({"data_class": "public"})),
            "internal"
        );
        let model = observed_runtime_tool_boundary("model__responses").unwrap();
        assert_eq!(
            effective_destination(
                &model,
                "model__responses",
                &json!({"destination": "local://daemon"}),
            ),
            "provider://model-runtime/bound"
        );
    }
}
