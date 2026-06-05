use super::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresAdmissionError, AgentgresAdmissionRecord,
    AgentgresOperationProposal, AGENTGRES_ADMISSION_SCHEMA_VERSION,
};
use super::projection::{ProjectionError, RustProjectionCore, StepModuleProjectionRecord};
use super::receipt_binder::{ReceiptBinder, ReceiptBindingError, StepModuleReceiptBinding};
use super::step_module::{
    StepModuleBackend, StepModuleInvocation, StepModuleKind, StepModuleNext,
    StepModulePrivacyProfile, StepModuleProjectionStatus, StepModuleResult, StepModuleStatus,
    StepModuleValidationError, StepModuleWorkflowProjection, STEP_MODULE_RESULT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CTEE_PRIVATE_WORKSPACE_MODULE_PATH: &str = "ctee_private_workspace_module_path";
pub const CTEE_PRIVATE_WORKSPACE_EXECUTION_SCHEMA_VERSION: &str =
    "ioi.ctee_private_workspace_execution.v1";
pub const CTEE_PRIVATE_WORKSPACE_RECEIPT_SCHEMA_VERSION: &str =
    "ioi.ctee_private_workspace_receipt.v1";
pub const CTEE_PLAINTEXT_UNTRUSTED_NEGATIVE_CONFORMANCE: &str =
    "cTEE private workspace plaintext mount on an untrusted node fails";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CteePrivateWorkspaceError {
    InvalidStepModule(Vec<StepModuleValidationError>),
    WrongModuleKind,
    WrongExecutionBackend,
    WrongPrivacyProfile,
    MissingCustodyProof,
    MissingLeakageProfile,
    MissingDeclassificationApproval,
    MissingStateRootBefore,
    UntrustedNodePlaintextMountForbidden,
    ReceiptBinding(ReceiptBindingError),
    AgentgresAdmission(AgentgresAdmissionError),
    Projection(ProjectionError),
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CteeNodeTrust {
    pub runtime_node_ref: String,
    pub trusted_for_plaintext: bool,
    pub attestation_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CteePrivateWorkspaceReceipt {
    pub schema_version: String,
    pub module_path: String,
    pub invocation_id: String,
    pub runtime_node_ref: String,
    pub custody_proof_ref: String,
    pub leakage_profile_ref: String,
    pub node_plaintext_allowed: bool,
    pub declassification_required: bool,
    pub declassification_ref: Option<String>,
    pub receipt_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CteePrivateWorkspaceExecutionRecord {
    pub schema_version: String,
    pub receipt: CteePrivateWorkspaceReceipt,
    pub result: StepModuleResult,
    pub receipt_binding: StepModuleReceiptBinding,
    pub agentgres_admission: AgentgresAdmissionRecord,
    pub projection: StepModuleProjectionRecord,
}

#[derive(Debug, Default, Clone)]
pub struct PrivateWorkspaceCteeModule;

pub type CteePrivateWorkspaceRunner = PrivateWorkspaceCteeModule;

impl PrivateWorkspaceCteeModule {
    pub fn execute_and_admit(
        &self,
        invocation: &StepModuleInvocation,
        node_trust: &CteeNodeTrust,
        expected_heads: Vec<String>,
    ) -> Result<CteePrivateWorkspaceExecutionRecord, CteePrivateWorkspaceError> {
        let receipt = self.validate_invocation(invocation, node_trust)?;
        let result = ctee_step_module_result(invocation, &receipt)?;
        let receipt_binding = ReceiptBinder
            .bind_step_module_result(invocation, &result, expected_heads)
            .map_err(CteePrivateWorkspaceError::ReceiptBinding)?;
        let agentgres_admission = AgentgresAdmissionCore
            .admit(
                &ctee_agentgres_operation_proposal(&result, &receipt_binding),
                &receipt_binding,
            )
            .map_err(CteePrivateWorkspaceError::AgentgresAdmission)?;
        let projection = RustProjectionCore
            .project_step_module_result(invocation, &result, &receipt_binding)
            .map_err(CteePrivateWorkspaceError::Projection)?;

        Ok(CteePrivateWorkspaceExecutionRecord {
            schema_version: CTEE_PRIVATE_WORKSPACE_EXECUTION_SCHEMA_VERSION.to_string(),
            receipt,
            result,
            receipt_binding,
            agentgres_admission,
            projection,
        })
    }

    pub fn validate_invocation(
        &self,
        invocation: &StepModuleInvocation,
        node_trust: &CteeNodeTrust,
    ) -> Result<CteePrivateWorkspaceReceipt, CteePrivateWorkspaceError> {
        invocation
            .validate()
            .map_err(CteePrivateWorkspaceError::InvalidStepModule)?;
        if invocation.module_ref.kind != StepModuleKind::PrivateWorkspaceCteeAction {
            return Err(CteePrivateWorkspaceError::WrongModuleKind);
        }
        if invocation.execution.backend != StepModuleBackend::CteeOperator {
            return Err(CteePrivateWorkspaceError::WrongExecutionBackend);
        }
        if invocation.custody.privacy_profile != StepModulePrivacyProfile::PrivateWorkspaceCtee {
            return Err(CteePrivateWorkspaceError::WrongPrivacyProfile);
        }
        if invocation.custody.plaintext_policy.node_plaintext_allowed
            && !node_trust.trusted_for_plaintext
        {
            return Err(CteePrivateWorkspaceError::UntrustedNodePlaintextMountForbidden);
        }
        let custody_proof_ref = invocation
            .custody
            .custody_proof_ref
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(CteePrivateWorkspaceError::MissingCustodyProof)?;
        let leakage_profile_ref = invocation
            .custody
            .leakage_profile_ref
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(CteePrivateWorkspaceError::MissingLeakageProfile)?;
        if invocation
            .custody
            .plaintext_policy
            .declassification_required
            && invocation.authority.approval_ref.is_none()
        {
            return Err(CteePrivateWorkspaceError::MissingDeclassificationApproval);
        }

        Ok(CteePrivateWorkspaceReceipt {
            schema_version: CTEE_PRIVATE_WORKSPACE_RECEIPT_SCHEMA_VERSION.to_string(),
            module_path: CTEE_PRIVATE_WORKSPACE_MODULE_PATH.to_string(),
            invocation_id: invocation.invocation_id.clone(),
            runtime_node_ref: node_trust.runtime_node_ref.clone(),
            custody_proof_ref,
            leakage_profile_ref,
            node_plaintext_allowed: invocation.custody.plaintext_policy.node_plaintext_allowed,
            declassification_required: invocation
                .custody
                .plaintext_policy
                .declassification_required,
            declassification_ref: invocation.authority.approval_ref.clone(),
            receipt_ref: format!(
                "receipt://ctee/private-workspace/{}",
                stable_receipt_suffix(&invocation.invocation_id)
            ),
        })
    }
}

fn ctee_step_module_result(
    invocation: &StepModuleInvocation,
    receipt: &CteePrivateWorkspaceReceipt,
) -> Result<StepModuleResult, CteePrivateWorkspaceError> {
    let state_root_before = invocation
        .input
        .state_root_before
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CteePrivateWorkspaceError::MissingStateRootBefore)?;
    let suffix = stable_receipt_suffix(&invocation.invocation_id);
    let state_root_after = ctee_state_root_after(&state_root_before, invocation, receipt)?;
    let head_suffix = state_root_after
        .trim_start_matches("sha256:")
        .chars()
        .take(24)
        .collect::<String>();
    let receipt_refs = vec![receipt.receipt_ref.clone()];
    let artifact_refs = vec![
        receipt.custody_proof_ref.clone(),
        receipt.leakage_profile_ref.clone(),
    ];
    let evidence_refs = ctee_projection_evidence_refs(receipt);

    Ok(StepModuleResult {
        schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
        invocation_id: invocation.invocation_id.clone(),
        status: StepModuleStatus::Success,
        execution_result_ref: format!("ctee://private-workspace/result/{suffix}"),
        normalized_observation_ref: format!("ctee://private-workspace/observation/{suffix}"),
        receipt_refs: receipt_refs.clone(),
        artifact_refs,
        payload_refs: invocation.input.payload_refs.clone(),
        agentgres_operation_refs: vec![format!(
            "agentgres://ctee/private-workspace/operations/{suffix}"
        )],
        state_root_after: Some(state_root_after),
        resulting_head: Some(format!(
            "agentgres://ctee/private-workspace/head/{head_suffix}"
        )),
        workflow_projection: StepModuleWorkflowProjection {
            workflow_graph_id: invocation
                .workflow_graph_id
                .clone()
                .unwrap_or_else(|| format!("workflow://ctee/private-workspace/{suffix}")),
            workflow_node_id: invocation
                .workflow_node_id
                .clone()
                .unwrap_or_else(|| format!("node://ctee/private-workspace/{suffix}")),
            component_kind: "PrivateWorkspaceCteeAction".to_string(),
            status: StepModuleProjectionStatus::Live,
            attempt_id: format!("attempt://ctee/private-workspace/{suffix}"),
            evidence_refs,
            receipt_refs,
        },
        next: StepModuleNext {
            model_reentry_required: false,
            verifier_required: false,
        },
    })
}

fn ctee_agentgres_operation_proposal(
    result: &StepModuleResult,
    binding: &StepModuleReceiptBinding,
) -> AgentgresOperationProposal {
    AgentgresOperationProposal {
        schema_version: AGENTGRES_ADMISSION_SCHEMA_VERSION.to_string(),
        operation_ref: result
            .agentgres_operation_refs
            .first()
            .cloned()
            .unwrap_or_default(),
        invocation_id: result.invocation_id.clone(),
        receipt_binding_ref: binding.binding_hash.clone(),
        receipt_refs: result.receipt_refs.clone(),
        artifact_refs: result.artifact_refs.clone(),
        payload_refs: result.payload_refs.clone(),
        expected_heads: binding.expected_heads.clone(),
        state_root_before: binding.state_root_before.clone(),
        state_root_after: binding.state_root_after.clone(),
        resulting_head: binding.resulting_head.clone(),
    }
}

fn ctee_projection_evidence_refs(receipt: &CteePrivateWorkspaceReceipt) -> Vec<String> {
    let mut refs = vec![
        receipt.custody_proof_ref.clone(),
        receipt.leakage_profile_ref.clone(),
    ];
    if let Some(declassification_ref) = receipt.declassification_ref.clone() {
        refs.push(declassification_ref);
    }
    refs
}

fn ctee_state_root_after(
    state_root_before: &str,
    invocation: &StepModuleInvocation,
    receipt: &CteePrivateWorkspaceReceipt,
) -> Result<String, CteePrivateWorkspaceError> {
    let bytes = serde_json::to_vec(&(state_root_before, invocation, receipt))
        .map_err(|error| CteePrivateWorkspaceError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn stable_receipt_suffix(value: &str) -> String {
    let suffix = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(24)
        .collect::<String>();
    if suffix.is_empty() {
        "unknown".to_string()
    } else {
        suffix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::receipt_binder::ReceiptBindingError;
    use crate::agentic::runtime::kernel::step_module::{
        StepModuleActor, StepModuleAuthority, StepModuleCustody, StepModuleExecution,
        StepModuleInput, StepModulePlaintextPolicy, StepModuleProjectionStatus, StepModuleRef,
        StepModuleStatus, STEP_MODULE_INVOCATION_SCHEMA_VERSION,
    };

    fn ctee_invocation() -> StepModuleInvocation {
        StepModuleInvocation {
            schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://ctee-test".to_string(),
            run_id: "run:ctee".to_string(),
            task_id: "task:ctee".to_string(),
            thread_id: Some("thread:ctee".to_string()),
            workflow_graph_id: Some("workflow:ctee".to_string()),
            workflow_node_id: Some("node:ctee".to_string()),
            context_chamber_ref: Some("chamber:ctee".to_string()),
            action_proposal_ref: "action:ctee".to_string(),
            gate_result_ref: "gate:ctee".to_string(),
            module_ref: StepModuleRef {
                kind: StepModuleKind::PrivateWorkspaceCteeAction,
                id: "private_workspace.mount".to_string(),
                version: "1".to_string(),
                manifest_ref: Some("module://ctee/private-workspace@1".to_string()),
            },
            actor: StepModuleActor {
                actor_id: "runtime:hypervisor-daemon".to_string(),
                runtime_node_ref: "node://private-workspace".to_string(),
            },
            authority: StepModuleAuthority {
                authority_grant_refs: vec!["grant://ctee".to_string()],
                policy_hash: "sha256:ctee-policy".to_string(),
                primitive_capabilities: vec!["prim:private_workspace.mount".to_string()],
                authority_scopes: vec!["scope:ctee.private_workspace".to_string()],
                approval_ref: Some("approval://declassify".to_string()),
            },
            input: StepModuleInput {
                input_hash: "sha256:ctee-input".to_string(),
                expected_schema_ref: "schema://ctee/private-workspace/input".to_string(),
                context_refs: vec!["ctx://redacted".to_string()],
                artifact_refs: vec!["artifact://encrypted-capsule".to_string()],
                payload_refs: vec!["payload://sealed".to_string()],
                state_root_before: Some("sha256:before".to_string()),
                projection_watermark: Some("domain_seq:ctee".to_string()),
                data_plane_handle: None,
            },
            custody: StepModuleCustody {
                privacy_profile: StepModulePrivacyProfile::PrivateWorkspaceCtee,
                plaintext_policy: StepModulePlaintextPolicy {
                    node_plaintext_allowed: false,
                    declassification_required: true,
                },
                custody_proof_ref: Some("artifact://custody-proof".to_string()),
                leakage_profile_ref: Some("artifact://leakage-profile".to_string()),
            },
            execution: StepModuleExecution {
                backend: StepModuleBackend::CteeOperator,
                idempotency_key: "idem:ctee".to_string(),
                deadline_ms: 1_000,
                resource_lease_ref: Some("lease://ctee".to_string()),
                retry_policy_ref: None,
            },
        }
    }

    fn untrusted_node() -> CteeNodeTrust {
        CteeNodeTrust {
            runtime_node_ref: "node://rented-untrusted".to_string(),
            trusted_for_plaintext: false,
            attestation_ref: None,
        }
    }

    #[test]
    fn ctee_private_workspace_plaintext_mount_on_an_untrusted_node_fails() {
        assert_eq!(
            CTEE_PLAINTEXT_UNTRUSTED_NEGATIVE_CONFORMANCE,
            "cTEE private workspace plaintext mount on an untrusted node fails"
        );
        let mut invocation = ctee_invocation();
        invocation.custody.plaintext_policy.node_plaintext_allowed = true;

        let error = PrivateWorkspaceCteeModule
            .validate_invocation(&invocation, &untrusted_node())
            .expect_err("untrusted node plaintext mount fails");

        assert_eq!(
            error,
            CteePrivateWorkspaceError::InvalidStepModule(vec![
                StepModuleValidationError::CteePlaintextCustodyForbidden
            ])
        );
    }

    #[test]
    fn ctee_private_workspace_validates_plaintext_free_mount() {
        let receipt = PrivateWorkspaceCteeModule
            .validate_invocation(&ctee_invocation(), &untrusted_node())
            .expect("plaintext-free cTEE mount should validate");

        assert_eq!(
            receipt.schema_version,
            CTEE_PRIVATE_WORKSPACE_RECEIPT_SCHEMA_VERSION
        );
        assert_eq!(receipt.module_path, CTEE_PRIVATE_WORKSPACE_MODULE_PATH);
        assert_eq!(receipt.custody_proof_ref, "artifact://custody-proof");
        assert_eq!(receipt.leakage_profile_ref, "artifact://leakage-profile");
        assert!(!receipt.node_plaintext_allowed);
        assert_eq!(
            receipt.declassification_ref.as_deref(),
            Some("approval://declassify")
        );
    }

    #[test]
    fn ctee_private_workspace_executes_with_receipt_admission_and_projection() {
        let record = PrivateWorkspaceCteeModule
            .execute_and_admit(
                &ctee_invocation(),
                &untrusted_node(),
                vec!["agentgres://ctee/private-workspace/head/before".to_string()],
            )
            .expect("ctee execution record");

        assert_eq!(
            record.schema_version,
            CTEE_PRIVATE_WORKSPACE_EXECUTION_SCHEMA_VERSION
        );
        assert_eq!(record.result.status, StepModuleStatus::Success);
        assert_eq!(
            record.result.receipt_refs,
            vec![record.receipt.receipt_ref.clone()]
        );
        assert_eq!(
            record.agentgres_admission.operation_ref,
            record.result.agentgres_operation_refs[0]
        );
        assert_eq!(
            record.agentgres_admission.receipt_binding_ref,
            record.receipt_binding.binding_hash
        );
        assert_eq!(
            record.agentgres_admission.projection_watermark.as_deref(),
            Some("domain_seq:ctee")
        );
        assert_eq!(
            record.projection.component_kind,
            "PrivateWorkspaceCteeAction"
        );
        assert_eq!(record.projection.status, StepModuleProjectionStatus::Live);
        assert_eq!(
            record.projection.agentgres_operation_refs,
            record.result.agentgres_operation_refs
        );
    }

    #[test]
    fn ctee_private_workspace_agentgres_admission_requires_expected_heads() {
        let error = PrivateWorkspaceCteeModule
            .execute_and_admit(&ctee_invocation(), &untrusted_node(), vec![])
            .expect_err("ctee Agentgres admission must require expected heads");

        assert_eq!(
            error,
            CteePrivateWorkspaceError::ReceiptBinding(
                ReceiptBindingError::AgentgresOperationMissingExpectedHeads
            )
        );
    }

    #[test]
    fn ctee_private_workspace_requires_declassification_approval() {
        let mut invocation = ctee_invocation();
        invocation.authority.approval_ref = None;

        let error = PrivateWorkspaceCteeModule
            .validate_invocation(&invocation, &untrusted_node())
            .expect_err("declassification approval is required");

        assert_eq!(
            error,
            CteePrivateWorkspaceError::MissingDeclassificationApproval
        );
    }

    #[test]
    fn ctee_private_workspace_requires_custody_and_leakage_refs() {
        let mut invocation = ctee_invocation();
        invocation.custody.custody_proof_ref = None;

        let error = PrivateWorkspaceCteeModule
            .validate_invocation(&invocation, &untrusted_node())
            .expect_err("custody proof is required");

        assert_eq!(error, CteePrivateWorkspaceError::MissingCustodyProof);

        invocation.custody.custody_proof_ref = Some("artifact://custody-proof".to_string());
        invocation.custody.leakage_profile_ref = None;
        let error = PrivateWorkspaceCteeModule
            .validate_invocation(&invocation, &untrusted_node())
            .expect_err("leakage profile is required");

        assert_eq!(error, CteePrivateWorkspaceError::MissingLeakageProfile);
    }
}
