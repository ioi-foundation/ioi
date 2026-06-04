use serde::{Deserialize, Serialize};

pub const STEP_MODULE_INVOCATION_SCHEMA_VERSION: &str = "ioi.step_module_invocation.v1";
pub const STEP_MODULE_RESULT_SCHEMA_VERSION: &str = "ioi.step_module_result.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepModuleValidationError {
    InvalidSchemaVersion {
        field: &'static str,
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    BackendKindMismatch {
        kind: StepModuleKind,
        backend: StepModuleBackend,
    },
    CteePlaintextCustodyForbidden,
    AcceptedResultMissingReceipt,
    AgentgresOperationMissingStateBinding,
    WorkflowProjectionMissingNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepModuleKind {
    DaemonNativeTool,
    RustWasmServiceModule,
    WorkloadJob,
    ModelMount,
    PrivateWorkspaceCteeAction,
    Verifier,
    AiipCapabilityExit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepModuleBackend {
    DaemonJs,
    RustWasm,
    WorkloadGrpc,
    ModelMount,
    CteeOperator,
    Aiip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepModuleStatus {
    Success,
    Failure,
    Partial,
    Blocked,
    Denied,
    Timeout,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepModuleProjectionStatus {
    Projected,
    Shadow,
    Gated,
    Live,
    Blocked,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepModulePrivacyProfile {
    Public,
    Internal,
    Redacted,
    PrivateWorkspaceCtee,
    TeeConfidential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleRef {
    pub kind: StepModuleKind,
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleActor {
    pub actor_id: String,
    pub runtime_node_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleAuthority {
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    pub policy_hash: String,
    #[serde(default)]
    pub primitive_capabilities: Vec<String>,
    #[serde(default)]
    pub authority_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleDataPlaneHandle {
    pub region_id: String,
    pub offset: u64,
    pub length: u64,
    pub codec: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleInput {
    pub input_hash: String,
    pub expected_schema_ref: String,
    #[serde(default)]
    pub context_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub payload_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_watermark: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_plane_handle: Option<StepModuleDataPlaneHandle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModulePlaintextPolicy {
    pub node_plaintext_allowed: bool,
    pub declassification_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleCustody {
    pub privacy_profile: StepModulePrivacyProfile,
    pub plaintext_policy: StepModulePlaintextPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_proof_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leakage_profile_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleExecution {
    pub backend: StepModuleBackend,
    pub idempotency_key: String,
    pub deadline_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_lease_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_policy_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleInvocation {
    pub schema_version: String,
    pub invocation_id: String,
    pub run_id: String,
    pub task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_chamber_ref: Option<String>,
    pub action_proposal_ref: String,
    pub gate_result_ref: String,
    pub module_ref: StepModuleRef,
    pub actor: StepModuleActor,
    pub authority: StepModuleAuthority,
    pub input: StepModuleInput,
    pub custody: StepModuleCustody,
    pub execution: StepModuleExecution,
}

impl StepModuleInvocation {
    pub fn validate(&self) -> Result<(), Vec<StepModuleValidationError>> {
        let mut errors = Vec::new();

        require_schema(
            &mut errors,
            "schema_version",
            STEP_MODULE_INVOCATION_SCHEMA_VERSION,
            &self.schema_version,
        );
        require_non_empty(&mut errors, "invocation_id", &self.invocation_id);
        require_non_empty(&mut errors, "run_id", &self.run_id);
        require_non_empty(&mut errors, "task_id", &self.task_id);
        require_non_empty(
            &mut errors,
            "action_proposal_ref",
            &self.action_proposal_ref,
        );
        require_non_empty(&mut errors, "gate_result_ref", &self.gate_result_ref);
        require_non_empty(&mut errors, "module_ref.id", &self.module_ref.id);
        require_non_empty(&mut errors, "module_ref.version", &self.module_ref.version);
        require_non_empty(&mut errors, "actor.actor_id", &self.actor.actor_id);
        require_non_empty(
            &mut errors,
            "actor.runtime_node_ref",
            &self.actor.runtime_node_ref,
        );
        require_non_empty(
            &mut errors,
            "authority.policy_hash",
            &self.authority.policy_hash,
        );
        require_non_empty(&mut errors, "input.input_hash", &self.input.input_hash);
        require_non_empty(
            &mut errors,
            "input.expected_schema_ref",
            &self.input.expected_schema_ref,
        );
        require_non_empty(
            &mut errors,
            "execution.idempotency_key",
            &self.execution.idempotency_key,
        );
        if self.execution.deadline_ms == 0 {
            errors.push(StepModuleValidationError::MissingField(
                "execution.deadline_ms",
            ));
        }
        if !backend_allowed_for_kind(&self.module_ref.kind, &self.execution.backend) {
            errors.push(StepModuleValidationError::BackendKindMismatch {
                kind: self.module_ref.kind.clone(),
                backend: self.execution.backend.clone(),
            });
        }
        if self.custody.privacy_profile == StepModulePrivacyProfile::PrivateWorkspaceCtee
            && self.custody.plaintext_policy.node_plaintext_allowed
        {
            errors.push(StepModuleValidationError::CteePlaintextCustodyForbidden);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleWorkflowProjection {
    pub workflow_graph_id: String,
    pub workflow_node_id: String,
    pub component_kind: String,
    pub status: StepModuleProjectionStatus,
    pub attempt_id: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleNext {
    pub model_reentry_required: bool,
    pub verifier_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleResult {
    pub schema_version: String,
    pub invocation_id: String,
    pub status: StepModuleStatus,
    pub execution_result_ref: String,
    pub normalized_observation_ref: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub payload_refs: Vec<String>,
    #[serde(default)]
    pub agentgres_operation_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_head: Option<String>,
    pub workflow_projection: StepModuleWorkflowProjection,
    pub next: StepModuleNext,
}

impl StepModuleResult {
    pub fn validate(&self) -> Result<(), Vec<StepModuleValidationError>> {
        let mut errors = Vec::new();

        require_schema(
            &mut errors,
            "schema_version",
            STEP_MODULE_RESULT_SCHEMA_VERSION,
            &self.schema_version,
        );
        require_non_empty(&mut errors, "invocation_id", &self.invocation_id);
        require_non_empty(
            &mut errors,
            "execution_result_ref",
            &self.execution_result_ref,
        );
        require_non_empty(
            &mut errors,
            "normalized_observation_ref",
            &self.normalized_observation_ref,
        );
        require_non_empty(
            &mut errors,
            "workflow_projection.workflow_graph_id",
            &self.workflow_projection.workflow_graph_id,
        );
        require_non_empty(
            &mut errors,
            "workflow_projection.workflow_node_id",
            &self.workflow_projection.workflow_node_id,
        );
        require_non_empty(
            &mut errors,
            "workflow_projection.attempt_id",
            &self.workflow_projection.attempt_id,
        );

        if matches!(
            self.status,
            StepModuleStatus::Success | StepModuleStatus::Partial
        ) && self.receipt_refs.is_empty()
        {
            errors.push(StepModuleValidationError::AcceptedResultMissingReceipt);
        }
        if !self.agentgres_operation_refs.is_empty()
            && (self.state_root_after.is_none() || self.resulting_head.is_none())
        {
            errors.push(StepModuleValidationError::AgentgresOperationMissingStateBinding);
        }
        if self.workflow_projection.workflow_graph_id.trim().is_empty()
            || self.workflow_projection.workflow_node_id.trim().is_empty()
        {
            errors.push(StepModuleValidationError::WorkflowProjectionMissingNode);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn require_schema(
    errors: &mut Vec<StepModuleValidationError>,
    field: &'static str,
    expected: &'static str,
    actual: &str,
) {
    if actual != expected {
        errors.push(StepModuleValidationError::InvalidSchemaVersion {
            field,
            expected,
            actual: actual.to_string(),
        });
    }
}

fn require_non_empty(
    errors: &mut Vec<StepModuleValidationError>,
    field: &'static str,
    value: &str,
) {
    if value.trim().is_empty() {
        errors.push(StepModuleValidationError::MissingField(field));
    }
}

fn backend_allowed_for_kind(kind: &StepModuleKind, backend: &StepModuleBackend) -> bool {
    matches!(
        (kind, backend),
        (
            StepModuleKind::DaemonNativeTool,
            StepModuleBackend::DaemonJs
        ) | (
            StepModuleKind::DaemonNativeTool,
            StepModuleBackend::RustWasm
        ) | (
            StepModuleKind::RustWasmServiceModule,
            StepModuleBackend::RustWasm
        ) | (StepModuleKind::WorkloadJob, StepModuleBackend::WorkloadGrpc)
            | (StepModuleKind::ModelMount, StepModuleBackend::ModelMount)
            | (
                StepModuleKind::PrivateWorkspaceCteeAction,
                StepModuleBackend::CteeOperator
            )
            | (StepModuleKind::Verifier, StepModuleBackend::RustWasm)
            | (StepModuleKind::Verifier, StepModuleBackend::WorkloadGrpc)
            | (StepModuleKind::AiipCapabilityExit, StepModuleBackend::Aiip)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_invocation() -> StepModuleInvocation {
        StepModuleInvocation {
            schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://test".to_string(),
            run_id: "run:test".to_string(),
            task_id: "task:test".to_string(),
            thread_id: Some("thread:test".to_string()),
            workflow_graph_id: Some("workflow:test".to_string()),
            workflow_node_id: Some("node:test".to_string()),
            context_chamber_ref: Some("chamber:test".to_string()),
            action_proposal_ref: "action:test".to_string(),
            gate_result_ref: "gate:test".to_string(),
            module_ref: StepModuleRef {
                kind: StepModuleKind::DaemonNativeTool,
                id: "workspace.status".to_string(),
                version: "1".to_string(),
                manifest_ref: None,
            },
            actor: StepModuleActor {
                actor_id: "runtime:hypervisor-daemon".to_string(),
                runtime_node_ref: "node://local".to_string(),
            },
            authority: StepModuleAuthority {
                authority_grant_refs: vec![],
                policy_hash: "sha256:test-policy".to_string(),
                primitive_capabilities: vec!["prim:workspace.status".to_string()],
                authority_scopes: vec![],
                approval_ref: None,
            },
            input: StepModuleInput {
                input_hash: "sha256:test-input".to_string(),
                expected_schema_ref: "schema://coding-tool/workspace.status/input".to_string(),
                context_refs: vec![],
                artifact_refs: vec![],
                payload_refs: vec![],
                state_root_before: Some("sha256:before".to_string()),
                projection_watermark: Some("domain_seq:1".to_string()),
                data_plane_handle: None,
            },
            custody: StepModuleCustody {
                privacy_profile: StepModulePrivacyProfile::Internal,
                plaintext_policy: StepModulePlaintextPolicy {
                    node_plaintext_allowed: true,
                    declassification_required: false,
                },
                custody_proof_ref: None,
                leakage_profile_ref: None,
            },
            execution: StepModuleExecution {
                backend: StepModuleBackend::DaemonJs,
                idempotency_key: "idem:test".to_string(),
                deadline_ms: 1_000,
                resource_lease_ref: None,
                retry_policy_ref: None,
            },
        }
    }

    fn valid_result() -> StepModuleResult {
        StepModuleResult {
            schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://test".to_string(),
            status: StepModuleStatus::Success,
            execution_result_ref: "result:test".to_string(),
            normalized_observation_ref: "observation:test".to_string(),
            receipt_refs: vec!["receipt:test".to_string()],
            artifact_refs: vec![],
            payload_refs: vec![],
            agentgres_operation_refs: vec!["agentgres://operation/test".to_string()],
            state_root_after: Some("sha256:after".to_string()),
            resulting_head: Some("sha256:head".to_string()),
            workflow_projection: StepModuleWorkflowProjection {
                workflow_graph_id: "workflow:test".to_string(),
                workflow_node_id: "node:test".to_string(),
                component_kind: "CodingToolNode".to_string(),
                status: StepModuleProjectionStatus::Projected,
                attempt_id: "attempt:test".to_string(),
                evidence_refs: vec![],
                receipt_refs: vec!["receipt:test".to_string()],
            },
            next: StepModuleNext {
                model_reentry_required: false,
                verifier_required: false,
            },
        }
    }

    #[test]
    fn valid_step_module_invocation_passes() {
        assert_eq!(valid_invocation().validate(), Ok(()));
    }

    #[test]
    fn ctee_plaintext_mount_is_rejected() {
        let mut invocation = valid_invocation();
        invocation.module_ref.kind = StepModuleKind::PrivateWorkspaceCteeAction;
        invocation.execution.backend = StepModuleBackend::CteeOperator;
        invocation.custody.privacy_profile = StepModulePrivacyProfile::PrivateWorkspaceCtee;
        invocation.custody.plaintext_policy.node_plaintext_allowed = true;

        let errors = invocation.validate().expect_err("ctee plaintext must fail");
        assert!(errors.contains(&StepModuleValidationError::CteePlaintextCustodyForbidden));
    }

    #[test]
    fn result_with_agentgres_operation_requires_state_binding() {
        let mut result = valid_result();
        result.state_root_after = None;

        let errors = result.validate().expect_err("missing state root must fail");
        assert!(errors.contains(&StepModuleValidationError::AgentgresOperationMissingStateBinding));
    }

    #[test]
    fn accepted_result_requires_receipt() {
        let mut result = valid_result();
        result.receipt_refs.clear();

        let errors = result.validate().expect_err("missing receipt must fail");
        assert!(errors.contains(&StepModuleValidationError::AcceptedResultMissingReceipt));
    }
}
