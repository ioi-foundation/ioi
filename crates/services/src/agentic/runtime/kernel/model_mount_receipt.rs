use serde::Deserialize;
use serde_json::{json, Value};

use super::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresOperationProposal, AGENTGRES_ADMISSION_SCHEMA_VERSION,
};
use super::model_mount::{
    ModelMountAcceptedReceiptHeadRequest, ModelMountAcceptedReceiptTransition,
    ModelMountAcceptedReceiptTransitionRequest, ModelMountCore,
};
use super::projection::RustProjectionCore;
use super::receipt_binder::{
    AcceptedReceiptAppendIssuer, AcceptedReceiptAppendRequest, ReceiptBinder,
    ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION,
};
use super::step_module::{
    StepModuleBackend, StepModuleInvocation, StepModuleKind, StepModuleResult,
};
use super::step_router::StepModuleRouterCore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelMountReceiptError {
    code: &'static str,
    message: String,
}

impl ModelMountReceiptError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Deserialize)]
pub struct ModelMountAcceptedReceiptHeadBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: ModelMountAcceptedReceiptHeadRequest,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountAcceptedReceiptTransitionBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: ModelMountAcceptedReceiptTransitionRequest,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountInvocationReceiptBindingBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub invocation: StepModuleInvocation,
    pub result: StepModuleResult,
    #[serde(default)]
    pub expected_heads: Vec<String>,
    #[serde(default)]
    pub accepted_receipt_transition: Option<ModelMountAcceptedReceiptTransition>,
    #[serde(default)]
    pub receipt_ref: Option<String>,
}

pub fn plan_model_mount_accepted_receipt_head_response(
    request: ModelMountAcceptedReceiptHeadBridgeRequest,
) -> Result<Value, ModelMountReceiptError> {
    let head = ModelMountCore
        .plan_accepted_receipt_head(&request.request)
        .map_err(|error| {
            ModelMountReceiptError::new(
                "model_mount_accepted_receipt_head_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_accepted_receipt_head_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_accepted_receipt_head".to_string()),
        "head": head.clone(),
        "sequence": head.sequence,
        "head_ref": head.head_ref,
        "state_root": head.state_root,
        "projection_watermark": head.projection_watermark,
        "head_hash": head.head_hash,
        "evidence_refs": head.evidence_refs,
    }))
}

pub fn plan_model_mount_accepted_receipt_transition_response(
    request: ModelMountAcceptedReceiptTransitionBridgeRequest,
) -> Result<Value, ModelMountReceiptError> {
    let transition = ModelMountCore
        .plan_accepted_receipt_transition(&request.request)
        .map_err(|error| {
            ModelMountReceiptError::new(
                "model_mount_accepted_receipt_transition_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_accepted_receipt_transition_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_accepted_receipt_transition".to_string()),
        "transition": transition.clone(),
        "operation_id": transition.operation_id,
        "operation_ref": transition.operation_ref,
        "expected_heads": transition.expected_heads,
        "state_root_before": transition.state_root_before,
        "state_root_after": transition.state_root_after,
        "resulting_head": transition.resulting_head,
        "projection_watermark": transition.projection_watermark,
        "transition_hash": transition.transition_hash,
        "evidence_refs": transition.evidence_refs,
    }))
}

pub fn bind_model_mount_invocation_receipt_response(
    request: ModelMountInvocationReceiptBindingBridgeRequest,
) -> Result<Value, ModelMountReceiptError> {
    if request.invocation.module_ref.kind != StepModuleKind::ModelMount
        || request.invocation.execution.backend != StepModuleBackend::ModelMount
    {
        return Err(ModelMountReceiptError::new(
            "model_mount_step_module_required",
            "model invocation receipt binding requires a model_mount StepModule invocation"
                .to_string(),
        ));
    }
    if !request.expected_heads.is_empty() {
        return Err(ModelMountReceiptError::new(
            "model_mount_caller_supplied_expected_heads",
            "model mount invocation expected heads must come from the Rust accepted-receipt transition planner".to_string(),
        ));
    }
    let expected_heads = expected_heads_from_transition(&request)?;
    let router_admission = StepModuleRouterCore
        .admit_execution(&request.invocation, &request.result)
        .map_err(|error| {
            ModelMountReceiptError::new("router_admission_invalid", format!("{error:?}"))
        })?;
    let receipt_binding = ReceiptBinder
        .bind_step_module_result(&request.invocation, &request.result, expected_heads)
        .map_err(|error| {
            ModelMountReceiptError::new("receipt_binding_invalid", format!("{error:?}"))
        })?;
    let receipt_ref = request
        .receipt_ref
        .clone()
        .or_else(|| request.result.receipt_refs.first().cloned())
        .ok_or_else(|| {
            ModelMountReceiptError::new(
                "receipt_ref_required",
                "model invocation receipt binding requires a receipt ref".to_string(),
            )
        })?;
    let accepted_receipt_append = ReceiptBinder
        .append_accepted_receipt(
            &AcceptedReceiptAppendRequest {
                schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
                receipt_ref: receipt_ref.clone(),
                invocation_id: request.invocation.invocation_id.clone(),
                receipt_binding_ref: receipt_binding.binding_hash.clone(),
                issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
                state_root_before: receipt_binding.state_root_before.clone(),
                state_root_after: receipt_binding.state_root_after.clone(),
                resulting_head: receipt_binding.resulting_head.clone(),
            },
            &receipt_binding,
        )
        .map_err(|error| {
            ModelMountReceiptError::new("accepted_receipt_append_invalid", format!("{error:?}"))
        })?;
    let agentgres_admission = if request.result.agentgres_operation_refs.is_empty() {
        Value::Null
    } else {
        let proposal = AgentgresOperationProposal {
            schema_version: AGENTGRES_ADMISSION_SCHEMA_VERSION.to_string(),
            operation_ref: request
                .result
                .agentgres_operation_refs
                .first()
                .cloned()
                .unwrap_or_default(),
            invocation_id: request.result.invocation_id.clone(),
            receipt_binding_ref: receipt_binding.binding_hash.clone(),
            receipt_refs: request.result.receipt_refs.clone(),
            artifact_refs: request.result.artifact_refs.clone(),
            payload_refs: request.result.payload_refs.clone(),
            expected_heads: receipt_binding.expected_heads.clone(),
            state_root_before: receipt_binding.state_root_before.clone(),
            state_root_after: request.result.state_root_after.clone(),
            resulting_head: request.result.resulting_head.clone(),
        };
        match AgentgresAdmissionCore.admit(&proposal, &receipt_binding) {
            Ok(record) => json!(record),
            Err(error) => {
                return Err(ModelMountReceiptError::new(
                    "agentgres_admission_invalid",
                    format!("{error:?}"),
                ));
            }
        }
    };
    let projection_record = RustProjectionCore
        .project_step_module_result(&request.invocation, &request.result, &receipt_binding)
        .map_err(|error| {
            ModelMountReceiptError::new("projection_record_invalid", format!("{error:?}"))
        })?;
    let receipt_refs = request.result.receipt_refs.clone();
    let binding_hash = receipt_binding.binding_hash.clone();
    let append_hash = accepted_receipt_append.append_hash.clone();
    Ok(json!({
        "source": "rust_model_mount_receipt_binding_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "invocation": request.invocation,
        "result": request.result,
        "router_admission": router_admission,
        "receipt_binding": receipt_binding,
        "accepted_receipt_append": accepted_receipt_append,
        "agentgres_admission": agentgres_admission,
        "projection_record": projection_record,
        "receipt_refs": receipt_refs,
        "evidence_refs": [
            "rust_receipt_binder_core",
            binding_hash,
            append_hash,
        ],
    }))
}

fn expected_heads_from_transition(
    request: &ModelMountInvocationReceiptBindingBridgeRequest,
) -> Result<Vec<String>, ModelMountReceiptError> {
    if request.result.agentgres_operation_refs.is_empty() {
        return Ok(vec![]);
    }
    let transition = request.accepted_receipt_transition.as_ref().ok_or_else(|| {
        ModelMountReceiptError::new(
            "model_mount_accepted_receipt_transition_required",
            "model invocation Agentgres admission requires a Rust-planned accepted receipt transition"
                .to_string(),
        )
    })?;
    ModelMountCore
        .validate_accepted_receipt_transition(transition)
        .map_err(|error| {
            ModelMountReceiptError::new(
                "model_mount_accepted_receipt_transition_invalid",
                format!("{error:?}"),
            )
        })?;
    let operation_ref = request
        .result
        .agentgres_operation_refs
        .first()
        .cloned()
        .unwrap_or_default();
    if operation_ref != transition.operation_ref
        || request.result.state_root_after.as_deref() != Some(transition.state_root_after.as_str())
        || request.result.resulting_head.as_deref() != Some(transition.resulting_head.as_str())
        || request.invocation.input.state_root_before.as_deref()
            != Some(transition.state_root_before.as_str())
    {
        return Err(ModelMountReceiptError::new(
            "model_mount_accepted_receipt_transition_mismatch",
            "model invocation StepModule result must match the Rust-planned accepted receipt transition"
                .to_string(),
        ));
    }
    Ok(transition.expected_heads.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::{
        MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION,
        MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION,
    };
    use crate::agentic::runtime::kernel::step_module::{
        StepModuleActor, StepModuleAuthority, StepModuleCustody, StepModuleExecution,
        StepModuleInput, StepModuleNext, StepModulePlaintextPolicy, StepModulePrivacyProfile,
        StepModuleProjectionStatus, StepModuleRef, StepModuleStatus, StepModuleWorkflowProjection,
        STEP_MODULE_INVOCATION_SCHEMA_VERSION, STEP_MODULE_RESULT_SCHEMA_VERSION,
    };

    fn transition() -> ModelMountAcceptedReceiptTransition {
        ModelMountCore
            .plan_accepted_receipt_transition(&ModelMountAcceptedReceiptTransitionRequest {
                schema_version: MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION.to_string(),
                current_sequence: 0,
                current_head_ref: "agentgres://model-mounting/accepted-receipts/head/0".to_string(),
                current_state_root: "sha256:state-0".to_string(),
                receipt_id: "receipt.test".to_string(),
                receipt_kind: "model_invocation".to_string(),
                route_decision_ref: Some("model_mount://route_decision/test".to_string()),
                invocation_admission_ref: Some(
                    "model_mount://invocation_admission/test".to_string(),
                ),
                invocation_admission_hash: Some("sha256:admission".to_string()),
                input_hash: Some("sha256:input".to_string()),
                output_hash: None,
            })
            .expect("accepted receipt transition")
    }

    fn invocation(transition: &ModelMountAcceptedReceiptTransition) -> StepModuleInvocation {
        StepModuleInvocation {
            schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
            invocation_id: "model-invocation://receipt.test".to_string(),
            run_id: "run:model-mount".to_string(),
            task_id: "task:model-mount".to_string(),
            thread_id: None,
            workflow_graph_id: Some("workflow.graph".to_string()),
            workflow_node_id: Some("workflow.node".to_string()),
            context_chamber_ref: None,
            action_proposal_ref: "action:model-mount:receipt.test".to_string(),
            gate_result_ref: "gate:model-mount:receipt.test".to_string(),
            module_ref: StepModuleRef {
                kind: StepModuleKind::ModelMount,
                id: "chat:route.local-first:endpoint.local".to_string(),
                version: "migration".to_string(),
                manifest_ref: None,
            },
            actor: StepModuleActor {
                actor_id: "runtime:hypervisor-daemon".to_string(),
                runtime_node_ref: "node://local".to_string(),
            },
            authority: StepModuleAuthority {
                authority_grant_refs: vec!["grant://wallet/model-chat".to_string()],
                policy_hash: "sha256:policy".to_string(),
                primitive_capabilities: vec!["model:chat".to_string()],
                authority_scopes: vec![],
                approval_ref: None,
            },
            input: StepModuleInput {
                input_hash: "sha256:input".to_string(),
                expected_schema_ref: "schema://model-mount/chat/input".to_string(),
                context_refs: vec![
                    "model_mount://route_decision/test".to_string(),
                    "receipt://route/test".to_string(),
                ],
                artifact_refs: vec![],
                payload_refs: vec![],
                state_root_before: Some(transition.state_root_before.clone()),
                projection_watermark: Some("model-mounting-accepted-receipts:0".to_string()),
                data_plane_handle: None,
            },
            custody: StepModuleCustody {
                privacy_profile: StepModulePrivacyProfile::Internal,
                plaintext_policy: StepModulePlaintextPolicy {
                    node_plaintext_allowed: false,
                    declassification_required: false,
                },
                custody_proof_ref: None,
                leakage_profile_ref: None,
            },
            execution: StepModuleExecution {
                backend: StepModuleBackend::ModelMount,
                idempotency_key: "model_invocation:receipt.test".to_string(),
                deadline_ms: 300_000,
                resource_lease_ref: None,
                retry_policy_ref: None,
            },
        }
    }

    fn result(transition: &ModelMountAcceptedReceiptTransition) -> StepModuleResult {
        StepModuleResult {
            schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
            invocation_id: "model-invocation://receipt.test".to_string(),
            status: StepModuleStatus::Success,
            execution_result_ref: "result://model-mount/receipt.test".to_string(),
            normalized_observation_ref: "observation://model-mount/receipt.test".to_string(),
            receipt_refs: vec!["receipt://receipt.test".to_string()],
            artifact_refs: vec![],
            payload_refs: vec![],
            agentgres_operation_refs: vec![transition.operation_ref.clone()],
            state_root_after: Some(transition.state_root_after.clone()),
            resulting_head: Some(transition.resulting_head.clone()),
            workflow_projection: StepModuleWorkflowProjection {
                workflow_graph_id: "workflow.graph".to_string(),
                workflow_node_id: "workflow.node".to_string(),
                component_kind: "ModelInvocationNode".to_string(),
                status: StepModuleProjectionStatus::Live,
                attempt_id: "attempt://model-mount/receipt.test".to_string(),
                evidence_refs: vec!["model_mount://invocation_admission/test".to_string()],
                receipt_refs: vec!["receipt://receipt.test".to_string()],
            },
            next: StepModuleNext {
                model_reentry_required: false,
                verifier_required: false,
            },
        }
    }

    #[test]
    fn rust_core_shapes_accepted_receipt_head_response() {
        let response = plan_model_mount_accepted_receipt_head_response(
            ModelMountAcceptedReceiptHeadBridgeRequest {
                backend: Some("rust_model_mount_accepted_receipt_head".to_string()),
                request: ModelMountAcceptedReceiptHeadRequest {
                    schema_version: MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION.to_string(),
                    sequence: 7,
                },
            },
        )
        .expect("head response");

        assert_eq!(
            response["source"],
            "rust_model_mount_accepted_receipt_head_command"
        );
        assert_eq!(response["sequence"], 7);
        assert!(response["head_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:")));
    }

    #[test]
    fn rust_core_binds_model_mount_receipt_and_admits_agentgres() {
        let transition = transition();
        let response = bind_model_mount_invocation_receipt_response(
            ModelMountInvocationReceiptBindingBridgeRequest {
                backend: Some("rust_model_mount_live".to_string()),
                invocation: invocation(&transition),
                result: result(&transition),
                expected_heads: vec![],
                accepted_receipt_transition: Some(transition),
                receipt_ref: Some("receipt://receipt.test".to_string()),
            },
        )
        .expect("receipt binding response");

        assert_eq!(
            response["source"],
            "rust_model_mount_receipt_binding_command"
        );
        assert_eq!(response["router_admission"]["backend"], "model_mount");
        assert_eq!(
            response["accepted_receipt_append"]["receipt_ref"],
            "receipt://receipt.test"
        );
        assert_eq!(
            response["receipt_binding"]["expected_heads"][0],
            "agentgres://model-mounting/accepted-receipts/head/0"
        );
        assert_eq!(
            response["agentgres_admission"]["operation_ref"],
            "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation"
        );
        assert_eq!(
            response["projection_record"]["component_kind"],
            "ModelInvocationNode"
        );
    }

    #[test]
    fn rust_core_rejects_transition_mismatch_before_receipt_binding() {
        let transition = transition();
        let mut result = result(&transition);
        result.resulting_head =
            Some("agentgres://model-mounting/accepted-receipts/head/tampered".to_string());

        let error = bind_model_mount_invocation_receipt_response(
            ModelMountInvocationReceiptBindingBridgeRequest {
                backend: Some("rust_model_mount_live".to_string()),
                invocation: invocation(&transition),
                result,
                expected_heads: vec![],
                accepted_receipt_transition: Some(transition),
                receipt_ref: Some("receipt://receipt.test".to_string()),
            },
        )
        .expect_err("mismatched transition must fail");

        assert_eq!(
            error.code(),
            "model_mount_accepted_receipt_transition_mismatch"
        );
    }
}
