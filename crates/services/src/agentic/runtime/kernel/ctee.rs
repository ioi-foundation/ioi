use super::step_module::{
    StepModuleBackend, StepModuleInvocation, StepModuleKind, StepModulePrivacyProfile,
    StepModuleValidationError,
};
use serde::{Deserialize, Serialize};

pub const CTEE_PRIVATE_WORKSPACE_MODULE_PATH: &str = "ctee_private_workspace_module_path";
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
    UntrustedNodePlaintextMountForbidden,
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

#[derive(Debug, Default, Clone)]
pub struct PrivateWorkspaceCteeModule;

pub type CteePrivateWorkspaceRunner = PrivateWorkspaceCteeModule;

impl PrivateWorkspaceCteeModule {
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
    use crate::agentic::runtime::kernel::step_module::{
        StepModuleActor, StepModuleAuthority, StepModuleCustody, StepModuleExecution,
        StepModuleInput, StepModulePlaintextPolicy, StepModuleRef,
        STEP_MODULE_INVOCATION_SCHEMA_VERSION,
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
