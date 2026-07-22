//! Narrow Authority Gateway acceptance slice for the existing coding-agent workflow-edit route.
//!
//! This module owns no route, application, policy, authority, receipt store, or coverage
//! lifecycle. It freezes one exact proposal, validates invocation-scoped coverage snapshots
//! against the registered generated contract, executes only the sealed local file effect, and
//! prepares existing WorkResult / OutcomeDelta admission bodies. Authority issue/revocation/
//! one-shot consumption remains in `authority_routes`; durable result truth remains in
//! `work_result_routes`.

use std::fs;
use std::path::{Path, PathBuf};

use axum::http::StatusCode;
use ioi_services::agentic::runtime::tools::contracts::runtime_tool_contract_for_definition;
use ioi_types::app::agentic::LlmToolDefinition;
use ioi_types::app::generated::architecture_contracts::EnforcementCoverageDeclarationV1;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{iso_now, AppError};

pub(crate) const FINAL_INVOKER_REF: &str =
    "runtime://hypervisor-daemon/workflow-edit-final-invoker";
pub(crate) const EXACT_ACTION: &str = "workflow.edit.apply";

#[derive(Debug)]
pub(crate) struct PreparedWorkflowEditProposal {
    pub(crate) record: Value,
    pub(crate) review: Value,
}

fn bad(code: &str, message: impl Into<String>) -> AppError {
    AppError(
        StatusCode::BAD_REQUEST,
        format!("{code}: {}", message.into()),
    )
}

fn jcs_hash(value: &Value) -> Result<String, AppError> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        bad(
            "authority_gateway_canonicalization_failed",
            error.to_string(),
        )
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn bytes_hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn exact_json_bytes(value: &Value) -> Result<Vec<u8>, AppError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| bad("workflow_patch_serialization_failed", error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_workspace_target(
    workspace_root: &str,
    requested_path: &str,
) -> Result<(PathBuf, String), AppError> {
    if requested_path.trim().is_empty() {
        return Err(bad(
            "authority_gateway_target_required",
            "workflow edit requires one exact workspace target",
        ));
    }
    let root = fs::canonicalize(workspace_root).map_err(|error| {
        bad(
            "authority_gateway_workspace_unavailable",
            format!("workspace root cannot be resolved: {error}"),
        )
    })?;
    let requested = Path::new(requested_path);
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    };
    let target = fs::canonicalize(&joined).map_err(|error| {
        bad(
            "authority_gateway_target_unavailable",
            format!("workflow target cannot be resolved: {error}"),
        )
    })?;
    if !target.starts_with(&root) {
        return Err(bad(
            "authority_gateway_target_outside_workspace",
            "workflow target escapes the admitted workspace",
        ));
    }
    let relative = target
        .strip_prefix(&root)
        .map_err(|_| {
            bad(
                "authority_gateway_target_outside_workspace",
                "target escape",
            )
        })?
        .to_string_lossy()
        .replace('\\', "/");
    if relative.is_empty() {
        return Err(bad(
            "authority_gateway_target_invalid",
            "workspace root itself is not a workflow file target",
        ));
    }
    Ok((target, relative))
}

fn optional_gateway_string(body: &Value, key: &str, fallback: &str) -> String {
    body.get("authority_gateway")
        .and_then(|gateway| gateway.get(key))
        .or_else(|| body.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

fn workflow_edit_tool_contract() -> Value {
    let contract = runtime_tool_contract_for_definition(&LlmToolDefinition {
        name: "file__write".to_string(),
        description: "Apply one exact reviewed workflow document replacement.".to_string(),
        parameters: r#"{"type":"object","required":["path","workflow_patch"]}"#.to_string(),
    });
    json!({
        "stable_tool_id": contract.stable_tool_id,
        "version": contract.version,
        "effect_class": contract.effect_class,
        "risk_domain": contract.risk_domain,
        "policy_target": contract.policy_target,
        "primitive_capabilities": contract.primitive_capabilities,
        "authority_scope_requirements": contract.authority_scope_requirements,
        "approval_required": contract.approval_required,
        "receipt_behavior": contract.receipt_behavior,
    })
}

pub(crate) fn prepare_workflow_edit_proposal(
    thread_id: &str,
    agent_id: &str,
    workspace_root: &str,
    proposal_id: &str,
    approval_id: &str,
    body: &Value,
) -> Result<PreparedWorkflowEditProposal, AppError> {
    let requested_path = body
        .get("workflow_path")
        .or_else(|| body.get("workflowPath"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            bad(
                "authority_gateway_target_required",
                "workflow_path is required",
            )
        })?;
    let workflow_patch = body
        .get("workflow_patch")
        .or_else(|| body.get("workflowPatch"))
        .filter(|value| !value.is_null())
        .cloned()
        .ok_or_else(|| {
            bad(
                "authority_gateway_body_required",
                "workflow_patch is required",
            )
        })?;
    let (target, relative_path) = canonical_workspace_target(workspace_root, requested_path)?;
    let canonical_root = fs::canonicalize(workspace_root)
        .map_err(|error| bad("authority_gateway_workspace_unavailable", error.to_string()))?;
    let before_bytes = fs::read(&target).map_err(|error| {
        bad(
            "authority_gateway_target_read_failed",
            format!("cannot freeze target predecessor: {error}"),
        )
    })?;
    let desired_bytes = exact_json_bytes(&workflow_patch)?;
    let before_hash = bytes_hash(&before_bytes);
    let after_hash = bytes_hash(&desired_bytes);
    let adapter_ref = optional_gateway_string(
        body,
        "adapter_ref",
        "agent-harness-adapter://hypervisor/coding-agent/workflow-edit/v1",
    );
    let adapter_version = optional_gateway_string(body, "adapter_version", "1.0.0");
    let profile_ref = optional_gateway_string(
        body,
        "profile_ref",
        "authority-gateway-profile://hypervisor/workflow-edit/v1",
    );
    let profile_version = optional_gateway_string(body, "profile_version", "1.0.0");
    let goal_ref = body
        .get("goal_ref")
        .or_else(|| body.get("goalRef"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("goal://authority-gateway-{thread_id}"));
    if !goal_ref.starts_with("goal://") {
        return Err(bad(
            "authority_gateway_goal_ref_invalid",
            "goal_ref must be a goal:// identity",
        ));
    }
    let tool_contract = workflow_edit_tool_contract();
    if tool_contract.get("approval_required") != Some(&Value::Bool(true)) {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "workflow edit RuntimeToolContract unexpectedly permits unreviewed mutation".into(),
        ));
    }
    let required_scope = tool_contract
        .get("authority_scope_requirements")
        .and_then(Value::as_array)
        .and_then(|scopes| scopes.first())
        .and_then(Value::as_str)
        .unwrap_or("tool.invoke:fs::write")
        .to_string();
    let proposal_ref = format!("proposal://workflow-edit/{proposal_id}");
    let target_identity_hash = jcs_hash(&json!({
        "domain": "ioi.authority-gateway.workspace-target.v1",
        "workspace_root": canonical_root.to_string_lossy(),
        "workspace_relative_path": relative_path.clone(),
    }))?;
    let target_ref = format!(
        "state://workspace-target/{}",
        target_identity_hash
            .strip_prefix("sha256:")
            .unwrap_or(&target_identity_hash)
    );
    let exact_action = json!({
        "domain": "ioi.authority-gateway.workflow-edit.exact-action.v1",
        "action": EXACT_ACTION,
        "proposal_ref": proposal_ref,
        "thread_ref": format!("thread://{thread_id}"),
        "agent_ref": format!("agent://{agent_id}"),
        "goal_ref": goal_ref,
        "adapter_ref": adapter_ref,
        "adapter_version": adapter_version,
        "authority_gateway_profile_ref": profile_ref,
        "authority_gateway_profile_version": profile_version,
        "runtime_tool_contract": tool_contract,
        "required_authority_scope": required_scope,
        "workspace_relative_path": relative_path,
        "target_ref": target_ref,
        "before_hash": before_hash,
        "after_hash": after_hash,
        "workflow_patch": workflow_patch,
        "final_invoker_ref": FINAL_INVOKER_REF,
    });
    let effect_hash = jcs_hash(&exact_action)?;
    let policy_material = json!({
        "domain": "ioi.authority-gateway.workflow-edit.policy.v1",
        "authority_lane": "sovereign_local",
        "profile_ref": exact_action["authority_gateway_profile_ref"],
        "profile_version": exact_action["authority_gateway_profile_version"],
        "required_authority_scope": exact_action["required_authority_scope"],
        "final_invoker_ref": FINAL_INVOKER_REF,
        "failure_posture": "fail_closed",
    });
    let policy_hash = jcs_hash(&policy_material)?;
    let request_material = json!({
        "domain": "ioi.authority-gateway.workflow-edit.request.v1",
        "subject": exact_action["agent_ref"],
        "thread_ref": exact_action["thread_ref"],
        "action": EXACT_ACTION,
        "proposal_ref": proposal_ref,
        "effect_hash": effect_hash,
        "policy_hash": policy_hash,
    });
    let request_hash = jcs_hash(&request_material)?;
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.authority-gateway-workflow-edit-proposal.v1",
        "proposal_id": proposal_id,
        "proposal_ref": proposal_ref,
        "approval_id": approval_id,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "goal_ref": goal_ref,
        "decision": "pending",
        "reviewed_effect_hash": Value::Null,
        "review_receipt_ref": Value::Null,
        "authority_grant_ref": Value::Null,
        "authority_lane": "sovereign_local",
        "portable_authority_alternative": "CapabilityLease",
        "applied_event_id": Value::Null,
        "execution_response": Value::Null,
        "workspace_root": canonical_root.to_string_lossy(),
        "workflow_path": relative_path,
        "workflow_patch": exact_action["workflow_patch"],
        "source": body.get("source").cloned().unwrap_or_else(|| json!("agent_harness")),
        "turn_id": body.get("turn_id").or_else(|| body.get("turnId")).cloned().unwrap_or(Value::Null),
        "target_ref": target_ref,
        "exact_action": exact_action,
        "effect_hash": effect_hash,
        "policy_material": policy_material,
        "policy_hash": policy_hash,
        "request_material": request_material,
        "request_hash": request_hash,
        "created_at": now,
        "workflow_graph_id": body.get("workflow_graph_id").or_else(|| body.get("workflowGraphId")),
        "workflow_node_id": body.get("workflow_node_id").or_else(|| body.get("workflowNodeId")),
    });
    let review = json!({
        "review_type": "exact_action",
        "proposal_ref": record["proposal_ref"],
        "subject_ref": record["exact_action"]["agent_ref"],
        "action": EXACT_ACTION,
        "target_ref": record["target_ref"],
        "workspace_relative_path": record["workflow_path"],
        "before_hash": record["exact_action"]["before_hash"],
        "after_hash": record["exact_action"]["after_hash"],
        "workflow_patch": record["workflow_patch"],
        "runtime_tool_contract": record["exact_action"]["runtime_tool_contract"],
        "effect_hash": record["effect_hash"],
        "policy_hash": record["policy_hash"],
        "request_hash": record["request_hash"],
        "authority_lane": "sovereign_local",
        "portable_authority_alternative": "CapabilityLease",
    });
    Ok(PreparedWorkflowEditProposal { record, review })
}

pub(crate) fn validate_apply_request(record: &Value, body: &Value) -> Result<String, AppError> {
    let expected_effect_hash = body
        .get("expected_effect_hash")
        .or_else(|| body.get("expectedEffectHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            bad(
                "authority_gateway_expected_effect_hash_required",
                "apply must name the exact reviewed effect hash",
            )
        })?;
    if record.get("effect_hash").and_then(Value::as_str) != Some(expected_effect_hash) {
        return Err(bad(
            "authority_gateway_body_substitution_refused",
            "apply effect hash differs from the reviewed proposal",
        ));
    }
    if let Some(candidate) = body
        .get("workflow_patch")
        .or_else(|| body.get("workflowPatch"))
    {
        if candidate != &record["workflow_patch"] {
            return Err(bad(
                "authority_gateway_body_substitution_refused",
                "apply body differs from the reviewed workflow patch",
            ));
        }
    }
    if let Some(candidate) = body
        .get("workflow_path")
        .or_else(|| body.get("workflowPath"))
        .and_then(Value::as_str)
    {
        let (_, relative) = canonical_workspace_target(
            record
                .get("workspace_root")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            candidate,
        )?;
        if record.get("workflow_path").and_then(Value::as_str) != Some(relative.as_str()) {
            return Err(bad(
                "authority_gateway_target_substitution_refused",
                "apply target differs from the reviewed workflow target",
            ));
        }
    }
    body.get("authority_grant_ref")
        .or_else(|| body.get("authorityGrantRef"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            bad(
                "authority_gateway_grant_required",
                "the selected sovereign-local AuthorityGrant is required",
            )
        })
}

pub(crate) fn execute_sealed_workflow_edit(record: &Value) -> Result<Value, String> {
    let exact_action = record
        .get("exact_action")
        .ok_or_else(|| "sealed proposal lacks exact_action".to_string())?;
    let recomputed_effect = jcs_hash(exact_action).map_err(|error| error.1)?;
    if record.get("effect_hash").and_then(Value::as_str) != Some(recomputed_effect.as_str()) {
        return Err("sealed exact action no longer matches its effect hash".into());
    }
    let recomputed_policy = jcs_hash(&record["policy_material"]).map_err(|error| error.1)?;
    if record.get("policy_hash").and_then(Value::as_str) != Some(recomputed_policy.as_str()) {
        return Err("sealed policy no longer matches its policy hash".into());
    }
    let recomputed_request = jcs_hash(&record["request_material"]).map_err(|error| error.1)?;
    if record.get("request_hash").and_then(Value::as_str) != Some(recomputed_request.as_str()) {
        return Err("sealed request no longer matches its request hash".into());
    }
    let workspace_root = record
        .get("workspace_root")
        .and_then(Value::as_str)
        .ok_or_else(|| "sealed proposal lacks workspace_root".to_string())?;
    let relative_path = record
        .get("workflow_path")
        .and_then(Value::as_str)
        .ok_or_else(|| "sealed proposal lacks workflow_path".to_string())?;
    let (target, canonical_relative) =
        canonical_workspace_target(workspace_root, relative_path).map_err(|error| error.1)?;
    if canonical_relative != relative_path {
        return Err("resolved final target differs from sealed workspace path".into());
    }
    let before_bytes = fs::read(&target).map_err(|error| error.to_string())?;
    let observed_before_hash = bytes_hash(&before_bytes);
    let sealed_before_hash = exact_action
        .get("before_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if observed_before_hash != sealed_before_hash {
        return Err("workflow target changed after review; stale exact action refused".into());
    }
    let desired_bytes = exact_json_bytes(&record["workflow_patch"]).map_err(|error| error.1)?;
    let observed_after_hash = bytes_hash(&desired_bytes);
    if exact_action.get("after_hash").and_then(Value::as_str) != Some(observed_after_hash.as_str())
    {
        return Err("sealed workflow patch differs from its reviewed after hash".into());
    }
    let temp = target.with_extension(format!(
        "ioi-authority-gateway-{}.tmp",
        recomputed_effect
            .strip_prefix("sha256:")
            .unwrap_or(&recomputed_effect)
            .chars()
            .take(16)
            .collect::<String>()
    ));
    fs::write(&temp, &desired_bytes).map_err(|error| error.to_string())?;
    fs::rename(&temp, &target).map_err(|error| {
        let _ = fs::remove_file(&temp);
        error.to_string()
    })?;
    let committed = fs::read(&target).map_err(|error| error.to_string())?;
    let committed_hash = bytes_hash(&committed);
    if committed_hash != observed_after_hash {
        return Err("final invoker could not observe the reviewed postcondition".into());
    }
    Ok(json!({
        "effect_class": "filesystem_mutation",
        "target_ref": record["target_ref"],
        "workspace_relative_path": relative_path,
        "before_hash": observed_before_hash,
        "after_hash": committed_hash,
        "effect_hash": recomputed_effect,
        "final_invoker_ref": FINAL_INVOKER_REF,
    }))
}

pub(crate) fn coverage_declaration(
    record: &Value,
    operating_mode: &str,
    evidence_ref: &str,
) -> Result<(Value, String), AppError> {
    let active = operating_mode == "active_enforcement";
    let effect_hash = record
        .get("effect_hash")
        .and_then(Value::as_str)
        .unwrap_or("sha256:unknown");
    let hash_tail = effect_hash.strip_prefix("sha256:").unwrap_or(effect_hash);
    let exact = &record["exact_action"];
    let profile_material = json!({
        "profile_ref": exact["authority_gateway_profile_ref"],
        "profile_version": exact["authority_gateway_profile_version"],
        "adapter_ref": exact["adapter_ref"],
        "adapter_version": exact["adapter_version"],
        "scope": "workflow_edit_exact_route",
    });
    let profile_hash = jcs_hash(&profile_material)?;
    let now = iso_now();
    let mechanisms = if active {
        json!([
            {
                "mechanism_id": "coding-agent-workflow-edit-adapter",
                "kind": "application_adapter",
                "implementation_ref": exact["adapter_ref"],
                "version": exact["adapter_version"],
                "roles": ["discovery", "observation", "attribution", "mediation"]
            },
            {
                "mechanism_id": "daemon-exact-action-gate",
                "kind": "daemon_gate",
                "implementation_ref": "runtime://hypervisor-daemon/workflow-edit-final-invoker",
                "version": "1.0.0",
                "roles": ["mediation", "prevention", "receipt_emission"]
            }
        ])
    } else {
        json!([{
            "mechanism_id": "coding-agent-workflow-edit-adapter",
            "kind": "application_adapter",
            "implementation_ref": exact["adapter_ref"],
            "version": exact["adapter_version"],
            "roles": ["discovery", "observation", "attribution", "receipt_emission"]
        }])
    };
    let declaration = json!({
        "schema_version": "ioi.components.daemon-runtime.enforcement-coverage-declaration.v1",
        "declaration_id": format!("enforcement-coverage://hypervisor/workflow-edit/{hash_tail}/{operating_mode}"),
        "subject": {
            "kind": "authority_gateway_profile",
            "profile_or_adapter_ref": exact["authority_gateway_profile_ref"],
            "version": exact["authority_gateway_profile_version"],
            "content_hash": profile_hash,
            "implementation_ref": exact["adapter_ref"],
            "deployment_profile_ref": "deployment-profile://hypervisor/local-workflow-edit"
        },
        "scope": {
            "surface": "developer_workspace",
            "action_class": "workflow_edit",
            "boundary": "application",
            "scope_ref": format!("enforcement-scope://hypervisor/workflow-edit/{hash_tail}")
        },
        "claims": {
            "discovered": true,
            "observable": true,
            "attributable": true,
            "mediated": active,
            "preventable": active,
            "receipted": true,
            "uncovered": false
        },
        "mechanisms": mechanisms,
        "platform": {
            "family": "portable",
            "version": "profile-qualified",
            "architecture": "portable",
            "execution_context": "user_session",
            "native_security_facility_refs": []
        },
        "required_privilege": "user",
        "custom_os_kernel_module_required_for_claim": false,
        "bypass": {
            "resistance": "cooperative",
            "assumptions": ["the selected effect enters through this exact workflow-edit route"],
            "known_bypass_refs": ["gap://hypervisor/opaque-direct-filesystem-writes"]
        },
        "operating_mode": operating_mode,
        "decision_source": if active { json!({
            "kind": "owner_policy_service",
            "decision_source_ref": "authority://local-operator/exact-action-review",
            "policy_ref": "policy://hypervisor/workflow-edit/exact-action/v1",
            "authority_provider_ref": "authority://local-operator"
        }) } else { json!({
            "kind": "none",
            "decision_source_ref": Value::Null,
            "policy_ref": Value::Null,
            "authority_provider_ref": Value::Null
        }) },
        "final_invoker": if active { json!({
            "kind": "daemon",
            "invoker_ref": FINAL_INVOKER_REF
        }) } else { json!({
            "kind": "none",
            "invoker_ref": Value::Null
        }) },
        "availability": {
            "online_behavior": if active { "enforce" } else { "audit" },
            "offline_behavior": "deny",
            "failure_posture": if active { "fail_closed" } else { "audit_only" }
        },
        "receipt": {
            "scope": if active { "observation_decision_and_effect" } else { "observation" },
            "contract_refs": [if active {
                "schema://ioi/hypervisor/authority-grant-consumption-receipt/v1"
            } else {
                "schema://ioi/runtime/workflow-edit-control-event/v1"
            }],
            "evidence_refs": [evidence_ref]
        },
        "verification": {
            "verifier_ref": "verifier://hypervisor/authority-gateway-runtime",
            "verification_method_ref": "test-profile://hypervisor/workflow-edit-exact-route/v1",
            "evidence_refs": [evidence_ref],
            "evaluated_at": now,
            "freshness_status": "unverified",
            "valid_until": Value::Null,
            "freshness_policy_ref": Value::Null
        },
        "known_gaps": [{
            "gap_id": "opaque-direct-filesystem-writes",
            "description": "Direct OS or editor writes outside this admitted route are not intercepted by this declaration.",
            "affected_path": "external_or_opaque_filesystem_paths",
            "mitigation_ref": Value::Null
        }],
        "limitations": [
            "This declaration covers only the exact workflow-edit route and effect hash.",
            "It makes no endpoint-wide or universal interception claim."
        ],
        "status": "draft"
    });
    let typed: EnforcementCoverageDeclarationV1 = serde_json::from_value(declaration.clone())
        .map_err(|error| {
            AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("generated coverage contract rejected runtime snapshot: {error}"),
            )
        })?;
    let canonical = serde_json::to_value(typed).map_err(|error| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("coverage snapshot projection failed: {error}"),
        )
    })?;
    let hash = jcs_hash(&canonical)?;
    Ok((canonical, hash))
}

pub(crate) fn coverage_artifact_ref(content_hash: &str) -> String {
    format!(
        "artifact://hypervisor/enforcement-coverage/{}",
        content_hash.strip_prefix("sha256:").unwrap_or(content_hash)
    )
}

/// Build the route-scoped observation receipt that backs the audit-only declaration. The
/// lifecycle route persists this in the existing authority-receipts family; this helper does
/// not introduce a second receipt store or claim that the observation mediated the effect.
pub(crate) fn observation_receipt(record: &Value, event: &Value) -> Value {
    let effect_hash = record
        .get("effect_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let receipt_id = format!(
        "agr_observation_{}",
        effect_hash
            .strip_prefix("sha256:")
            .unwrap_or(effect_hash)
            .chars()
            .take(32)
            .collect::<String>()
    );
    json!({
        "schema_version": "ioi.hypervisor.authority-gateway-observation-receipt.v1",
        "receipt_id": receipt_id,
        "receipt_ref": format!("receipt://hypervisor/authority-gateway-observation/{receipt_id}"),
        "receipt_type": "AuthorityGatewayObservationReceipt",
        "proposal_ref": record["proposal_ref"],
        "subject_ref": record["exact_action"]["agent_ref"],
        "thread_ref": record["exact_action"]["thread_ref"],
        "agent_ref": record["exact_action"]["agent_ref"],
        "goal_ref": record["goal_ref"],
        "adapter_ref": record["exact_action"]["adapter_ref"],
        "action": EXACT_ACTION,
        "target_ref": record["target_ref"],
        "effect_hash": effect_hash,
        "event_id": event.get("event_id").cloned().unwrap_or(Value::Null),
        "mediation_claimed": false,
        "prevention_claimed": false,
        "at": iso_now(),
    })
}

pub(crate) fn work_result_body(record: &Value, effect_receipt: &Value) -> Value {
    let effect_hash = record
        .get("effect_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let hash_tail = effect_hash.strip_prefix("sha256:").unwrap_or(effect_hash);
    json!({
        "goal_ref": record["goal_ref"],
        "goal_run_ref": record["goal_ref"],
        "invocation_or_run_ref": format!("run://authority-gateway/{}", record.get("proposal_id").and_then(Value::as_str).unwrap_or("workflow-edit")),
        "result_profile": "software_implementation",
        "result_profile_ref": "profile://hypervisor/authority-gateway-workflow-edit/v1",
        "result_payload_ref": format!("artifact://hypervisor/workflow-edit/{hash_tail}"),
        "declared_method_and_lineage_refs": ["method://hypervisor/authority-gateway-workflow-edit"],
        "outcome_class": "positive",
        "status": "completed",
        "uncertainty": { "coverage_status": "draft", "universal_interception": false },
        "supporting_evidence_refs": [
            effect_receipt["receipt_ref"],
            format!("evidence://hypervisor/authority-gateway/{hash_tail}")
        ],
        "artifact_receipt_and_trace_refs": [effect_receipt["receipt_ref"]],
        "authority_and_policy_refs": [
            effect_receipt["authority_grant_ref"],
            "policy://hypervisor/workflow-edit/exact-action/v1"
        ],
        "reproduction_state": "unreviewed",
        "next_action": "verify"
    })
}

pub(crate) fn outcome_delta_body(record: &Value, work_result_ref: &str) -> Value {
    let effect_hash = record
        .get("effect_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let hash_tail = effect_hash.strip_prefix("sha256:").unwrap_or(effect_hash);
    json!({
        "goal_ref": record["goal_ref"],
        "proposed_by_ref": work_result_ref,
        "target_ref": record["target_ref"],
        "delta_kind": "update",
        "payload_ref": format!("patch://hypervisor/workflow-edit/{hash_tail}"),
        "precondition_and_invariant_refs": [
            "policy://hypervisor/workflow-edit/exact-action/v1",
            format!("state://workspace/predecessor/{hash_tail}")
        ],
        "expected_effect_ref": format!("effect://hypervisor/workflow-edit/{hash_tail}"),
        "verifier_and_acceptance_refs": ["verifier_path://hypervisor/workflow-edit-postcondition/v1"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn must<T>(result: Result<T, AppError>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{}", error.1),
        }
    }

    fn temp_workspace() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ioi-authority-gateway-proof-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("workflow.json"), b"{\n  \"version\": 1\n}\n").unwrap();
        root
    }

    #[test]
    fn proposal_freezes_exact_action_and_generated_coverage_contract_accepts_both_modes() {
        let root = temp_workspace();
        let prepared = must(prepare_workflow_edit_proposal(
            "thread_test",
            "agent_test",
            root.to_str().unwrap(),
            "proposal_test",
            "approval_test",
            &json!({
                "workflow_path": "workflow.json",
                "workflow_patch": {"version": 2},
                "goal_ref": "goal://authority-gateway-test"
            }),
        ));
        assert_eq!(
            prepared.record["exact_action"]["runtime_tool_contract"]["approval_required"],
            json!(true)
        );
        assert_ne!(
            prepared.record["exact_action"]["before_hash"],
            prepared.record["exact_action"]["after_hash"]
        );
        let (audit, _) = must(coverage_declaration(
            &prepared.record,
            "audit_only",
            "receipt://hypervisor/workflow-edit/proposed",
        ));
        assert_eq!(audit["claims"]["mediated"], json!(false));
        assert_eq!(audit["claims"]["preventable"], json!(false));
        let (active, _) = must(coverage_declaration(
            &prepared.record,
            "active_enforcement",
            "receipt://hypervisor/workflow-edit/effect",
        ));
        assert_eq!(active["claims"]["mediated"], json!(true));
        assert_eq!(active["claims"]["preventable"], json!(true));
        assert_eq!(
            active["custom_os_kernel_module_required_for_claim"],
            json!(false)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn apply_refuses_body_and_target_substitution_before_authority() {
        let root = temp_workspace();
        fs::write(root.join("other.json"), b"{}\n").unwrap();
        let prepared = must(prepare_workflow_edit_proposal(
            "thread_test",
            "agent_test",
            root.to_str().unwrap(),
            "proposal_test",
            "approval_test",
            &json!({
                "workflow_path": "workflow.json",
                "workflow_patch": {"version": 2}
            }),
        ));
        let effect_hash = prepared.record["effect_hash"].as_str().unwrap();
        let body_swap = validate_apply_request(
            &prepared.record,
            &json!({
                "expected_effect_hash": effect_hash,
                "authority_grant_ref": "grant://authority.local/test",
                "workflow_patch": {"version": 3}
            }),
        )
        .unwrap_err();
        assert!(body_swap.1.contains("body_substitution_refused"));
        let target_swap = validate_apply_request(
            &prepared.record,
            &json!({
                "expected_effect_hash": effect_hash,
                "authority_grant_ref": "grant://authority.local/test",
                "workflow_path": "other.json"
            }),
        )
        .unwrap_err();
        assert!(target_swap.1.contains("target_substitution_refused"));
        fs::remove_dir_all(root).unwrap();
    }
}
