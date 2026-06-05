use super::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresAdmissionError, AgentgresAdmissionRecord,
    AgentgresOperationProposal, AGENTGRES_ADMISSION_SCHEMA_VERSION,
};
use super::projection::{ProjectionError, RustProjectionCore, StepModuleProjectionRecord};
use super::receipt_binder::{ReceiptBinder, ReceiptBindingError, StepModuleReceiptBinding};
use super::step_module::{
    StepModuleBackend, StepModuleInvocation, StepModuleKind, StepModuleResult,
};
use super::step_router::{
    StepModuleExecutionAdmissionRecord, StepModuleRouterCore, StepModuleRouterError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION: &str =
    "ioi.worker_service_package_invocation.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplaceSchemaVersion {
    pub schema_name: String,
    pub version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplaceServiceContract {
    pub service_id: String,
    pub kind: MarketplaceServiceKind,
    #[serde(default)]
    pub schema_versions: Vec<MarketplaceSchemaVersion>,
    #[serde(default)]
    pub declared_capabilities: Vec<String>,
    #[serde(default)]
    pub declared_scopes: Vec<String>,
    #[serde(default)]
    pub deadline_policies: Vec<String>,
    #[serde(default)]
    pub evidence_manifests: Vec<String>,
    pub admission_profile: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerServicePackageKind {
    WorkerPackage,
    ServicePackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerServicePackageInvocationRequest {
    pub schema_version: String,
    pub package_kind: WorkerServicePackageKind,
    pub package_ref: String,
    pub manifest_ref: String,
    pub invocation: StepModuleInvocation,
    pub result: StepModuleResult,
    #[serde(default)]
    pub expected_heads: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerServicePackageInvocationRecord {
    pub schema_version: String,
    pub package_kind: WorkerServicePackageKind,
    pub package_ref: String,
    pub manifest_ref: String,
    pub invocation_id: String,
    pub module_kind: StepModuleKind,
    pub execution_backend: StepModuleBackend,
    pub router_admission: StepModuleExecutionAdmissionRecord,
    pub receipt_binding: StepModuleReceiptBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agentgres_admission: Option<AgentgresAdmissionRecord>,
    pub projection: StepModuleProjectionRecord,
    pub authority_grant_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub payload_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceServiceKind {
    Tool,
    Connector,
    Plugin,
    Workflow,
    Agent,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MarketplaceAdmissionError {
    #[error("marketplace service id is missing")]
    MissingServiceId,
    #[error("marketplace schema version is missing: {0}")]
    MissingSchemaVersion(&'static str),
    #[error("marketplace capabilities are missing")]
    MissingCapabilities,
    #[error("marketplace scopes are missing")]
    MissingScopes,
    #[error("marketplace deadline policy is missing")]
    MissingDeadlinePolicy,
    #[error("marketplace evidence manifest is missing")]
    MissingEvidenceManifest,
    #[error("worker/service package invocation schema is invalid: expected {expected}, received {actual}")]
    InvalidPackageInvocationSchema {
        expected: &'static str,
        actual: String,
    },
    #[error("worker/service package ref is missing")]
    MissingPackageRef,
    #[error("worker/service package manifest ref is missing")]
    MissingPackageManifestRef,
    #[error("worker package ref must use worker://")]
    InvalidWorkerPackageRef,
    #[error("service package ref must use service://")]
    InvalidServicePackageRef,
    #[error("package manifest ref must match StepModule manifest_ref")]
    PackageManifestRefMismatch,
    #[error("package invocation module kind is unsupported")]
    UnsupportedPackageModuleKind,
    #[error("package invocation must carry an authority grant")]
    MissingPackageAuthorityGrant,
    #[error("package invocation receipt refs are missing")]
    MissingPackageReceipt,
    #[error("package invocation router admission failed: {0:?}")]
    StepRouter(StepModuleRouterError),
    #[error("package invocation receipt binding failed: {0:?}")]
    ReceiptBinding(ReceiptBindingError),
    #[error("package invocation Agentgres admission failed: {0:?}")]
    AgentgresAdmission(AgentgresAdmissionError),
    #[error("package invocation projection failed: {0:?}")]
    Projection(ProjectionError),
}

impl MarketplaceServiceContract {
    pub fn validate(&self) -> Result<(), MarketplaceAdmissionError> {
        if self.service_id.trim().is_empty() {
            return Err(MarketplaceAdmissionError::MissingServiceId);
        }
        for required in REQUIRED_SCHEMA_NAMES {
            if !self
                .schema_versions
                .iter()
                .any(|schema| schema.schema_name == *required && schema.version > 0)
            {
                return Err(MarketplaceAdmissionError::MissingSchemaVersion(required));
            }
        }
        if self.declared_capabilities.is_empty() {
            return Err(MarketplaceAdmissionError::MissingCapabilities);
        }
        if self.declared_scopes.is_empty() {
            return Err(MarketplaceAdmissionError::MissingScopes);
        }
        if self.deadline_policies.is_empty() {
            return Err(MarketplaceAdmissionError::MissingDeadlinePolicy);
        }
        if self.evidence_manifests.is_empty() {
            return Err(MarketplaceAdmissionError::MissingEvidenceManifest);
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct WorkerServicePackageInvocationCore;

impl WorkerServicePackageInvocationCore {
    pub fn admit_invocation(
        &self,
        request: &WorkerServicePackageInvocationRequest,
    ) -> Result<WorkerServicePackageInvocationRecord, MarketplaceAdmissionError> {
        request.validate()?;
        let router_admission = StepModuleRouterCore
            .admit_execution(&request.invocation, &request.result)
            .map_err(MarketplaceAdmissionError::StepRouter)?;
        let receipt_binding = ReceiptBinder
            .bind_step_module_result(
                &request.invocation,
                &request.result,
                request.expected_heads.clone(),
            )
            .map_err(MarketplaceAdmissionError::ReceiptBinding)?;
        let agentgres_admission = if request.result.agentgres_operation_refs.is_empty() {
            None
        } else {
            Some(
                AgentgresAdmissionCore
                    .admit(
                        &worker_service_package_agentgres_proposal(
                            &request.result,
                            &receipt_binding,
                        ),
                        &receipt_binding,
                    )
                    .map_err(MarketplaceAdmissionError::AgentgresAdmission)?,
            )
        };
        let projection = RustProjectionCore
            .project_step_module_result(&request.invocation, &request.result, &receipt_binding)
            .map_err(MarketplaceAdmissionError::Projection)?;

        Ok(WorkerServicePackageInvocationRecord {
            schema_version: WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION.to_string(),
            package_kind: request.package_kind,
            package_ref: request.package_ref.clone(),
            manifest_ref: request.manifest_ref.clone(),
            invocation_id: request.invocation.invocation_id.clone(),
            module_kind: request.invocation.module_ref.kind.clone(),
            execution_backend: request.invocation.execution.backend.clone(),
            router_admission,
            receipt_binding,
            agentgres_admission,
            projection,
            authority_grant_refs: request.invocation.authority.authority_grant_refs.clone(),
            receipt_refs: request.result.receipt_refs.clone(),
            artifact_refs: request.result.artifact_refs.clone(),
            payload_refs: request.result.payload_refs.clone(),
        })
    }
}

impl WorkerServicePackageInvocationRequest {
    pub fn validate(&self) -> Result<(), MarketplaceAdmissionError> {
        if self.schema_version != WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION {
            return Err(MarketplaceAdmissionError::InvalidPackageInvocationSchema {
                expected: WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.package_ref.trim().is_empty() {
            return Err(MarketplaceAdmissionError::MissingPackageRef);
        }
        if self.manifest_ref.trim().is_empty() {
            return Err(MarketplaceAdmissionError::MissingPackageManifestRef);
        }
        match self.package_kind {
            WorkerServicePackageKind::WorkerPackage => {
                if !self.package_ref.starts_with("worker://") {
                    return Err(MarketplaceAdmissionError::InvalidWorkerPackageRef);
                }
            }
            WorkerServicePackageKind::ServicePackage => {
                if !self.package_ref.starts_with("service://") {
                    return Err(MarketplaceAdmissionError::InvalidServicePackageRef);
                }
            }
        }
        if self.invocation.module_ref.manifest_ref.as_deref() != Some(self.manifest_ref.as_str()) {
            return Err(MarketplaceAdmissionError::PackageManifestRefMismatch);
        }
        if !package_module_kind_allowed(self.package_kind, &self.invocation.module_ref.kind) {
            return Err(MarketplaceAdmissionError::UnsupportedPackageModuleKind);
        }
        if self.invocation.authority.authority_grant_refs.is_empty() {
            return Err(MarketplaceAdmissionError::MissingPackageAuthorityGrant);
        }
        if self.result.receipt_refs.is_empty() {
            return Err(MarketplaceAdmissionError::MissingPackageReceipt);
        }
        Ok(())
    }
}

fn package_module_kind_allowed(
    package_kind: WorkerServicePackageKind,
    module_kind: &StepModuleKind,
) -> bool {
    match package_kind {
        WorkerServicePackageKind::WorkerPackage => matches!(
            module_kind,
            StepModuleKind::WorkloadJob
                | StepModuleKind::RustWasmServiceModule
                | StepModuleKind::AiipCapabilityExit
        ),
        WorkerServicePackageKind::ServicePackage => matches!(
            module_kind,
            StepModuleKind::RustWasmServiceModule
                | StepModuleKind::WorkloadJob
                | StepModuleKind::AiipCapabilityExit
                | StepModuleKind::PrivateWorkspaceCteeAction
        ),
    }
}

fn worker_service_package_agentgres_proposal(
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

pub const REQUIRED_SCHEMA_NAMES: &[&str] = &[
    "tool",
    "capability_lease",
    "policy_decision",
    "approval_grant",
    "receipt_manifest",
    "settlement_bundle",
    "artifact_promotion",
    "trace_bundle",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::receipt_binder::ReceiptBindingError;
    use crate::agentic::runtime::kernel::step_module::{
        StepModuleActor, StepModuleAuthority, StepModuleCustody, StepModuleExecution,
        StepModuleInput, StepModuleNext, StepModulePlaintextPolicy, StepModulePrivacyProfile,
        StepModuleProjectionStatus, StepModuleRef, StepModuleStatus, StepModuleWorkflowProjection,
        STEP_MODULE_INVOCATION_SCHEMA_VERSION, STEP_MODULE_RESULT_SCHEMA_VERSION,
    };

    fn worker_package_request() -> WorkerServicePackageInvocationRequest {
        let package_ref = "worker://runtime-auditor";
        let manifest_ref = "worker://runtime-auditor@1";
        WorkerServicePackageInvocationRequest {
            schema_version: WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION.to_string(),
            package_kind: WorkerServicePackageKind::WorkerPackage,
            package_ref: package_ref.to_string(),
            manifest_ref: manifest_ref.to_string(),
            invocation: StepModuleInvocation {
                schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
                invocation_id: "invocation://worker-package/test".to_string(),
                run_id: "run:worker-package".to_string(),
                task_id: "task:worker-package".to_string(),
                thread_id: Some("thread:worker-package".to_string()),
                workflow_graph_id: Some("workflow:worker-package".to_string()),
                workflow_node_id: Some("node:worker-package".to_string()),
                context_chamber_ref: None,
                action_proposal_ref: "action:worker-package".to_string(),
                gate_result_ref: "gate:worker-package".to_string(),
                module_ref: StepModuleRef {
                    kind: StepModuleKind::WorkloadJob,
                    id: package_ref.to_string(),
                    version: "1".to_string(),
                    manifest_ref: Some(manifest_ref.to_string()),
                },
                actor: StepModuleActor {
                    actor_id: "runtime:hypervisor-daemon".to_string(),
                    runtime_node_ref: "node://local".to_string(),
                },
                authority: StepModuleAuthority {
                    authority_grant_refs: vec!["grant://wallet/worker-package".to_string()],
                    policy_hash: "sha256:worker-policy".to_string(),
                    primitive_capabilities: vec!["prim:worker.invoke".to_string()],
                    authority_scopes: vec!["scope:repo.read".to_string()],
                    approval_ref: Some("approval://worker-package".to_string()),
                },
                input: StepModuleInput {
                    input_hash: "sha256:worker-input".to_string(),
                    expected_schema_ref: "schema://worker-package/runtime-auditor/input"
                        .to_string(),
                    context_refs: vec!["agentgres://project/hypervisor".to_string()],
                    artifact_refs: vec![],
                    payload_refs: vec!["payload://worker-package/input".to_string()],
                    state_root_before: Some("sha256:package-before".to_string()),
                    projection_watermark: Some("agentgres:worker-package:0".to_string()),
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
                    backend: StepModuleBackend::WorkloadGrpc,
                    idempotency_key: "idem:worker-package".to_string(),
                    deadline_ms: 300_000,
                    resource_lease_ref: Some("lease://worker-package".to_string()),
                    retry_policy_ref: None,
                },
            },
            result: StepModuleResult {
                schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
                invocation_id: "invocation://worker-package/test".to_string(),
                status: StepModuleStatus::Success,
                execution_result_ref: "result://worker-package/test".to_string(),
                normalized_observation_ref: "observation://worker-package/test".to_string(),
                receipt_refs: vec!["receipt://worker-package/test".to_string()],
                artifact_refs: vec!["artifact://worker-package/report".to_string()],
                payload_refs: vec!["payload://worker-package/output".to_string()],
                agentgres_operation_refs: vec![
                    "agentgres://worker-service-package/operations/test".to_string(),
                ],
                state_root_after: Some("sha256:package-after".to_string()),
                resulting_head: Some("agentgres://worker-service-package/head/test".to_string()),
                workflow_projection: StepModuleWorkflowProjection {
                    workflow_graph_id: "workflow:worker-package".to_string(),
                    workflow_node_id: "node:worker-package".to_string(),
                    component_kind: "WorkerPackageNode".to_string(),
                    status: StepModuleProjectionStatus::Live,
                    attempt_id: "attempt://worker-package/test".to_string(),
                    evidence_refs: vec!["artifact://worker-package/report".to_string()],
                    receipt_refs: vec!["receipt://worker-package/test".to_string()],
                },
                next: StepModuleNext {
                    model_reentry_required: false,
                    verifier_required: true,
                },
            },
            expected_heads: vec!["agentgres://worker-service-package/head/before".to_string()],
        }
    }

    #[test]
    fn admits_worker_package_invocation_through_step_module_contract() {
        let record = WorkerServicePackageInvocationCore
            .admit_invocation(&worker_package_request())
            .expect("worker package admitted");

        assert_eq!(
            record.schema_version,
            WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION
        );
        assert_eq!(record.package_kind, WorkerServicePackageKind::WorkerPackage);
        assert_eq!(record.module_kind, StepModuleKind::WorkloadJob);
        assert_eq!(record.execution_backend, StepModuleBackend::WorkloadGrpc);
        assert!(record.router_admission.authoritative_transition);
        assert_eq!(
            record.receipt_binding.expected_heads,
            vec!["agentgres://worker-service-package/head/before"]
        );
        assert_eq!(
            record
                .agentgres_admission
                .as_ref()
                .expect("agentgres admission")
                .operation_ref,
            "agentgres://worker-service-package/operations/test"
        );
        assert_eq!(record.projection.component_kind, "WorkerPackageNode");
        assert_eq!(
            record.authority_grant_refs,
            vec!["grant://wallet/worker-package"]
        );
    }

    #[test]
    fn package_invocation_agentgres_transition_requires_expected_heads() {
        let mut request = worker_package_request();
        request.expected_heads.clear();

        let error = WorkerServicePackageInvocationCore
            .admit_invocation(&request)
            .expect_err("expected heads must be required");

        assert_eq!(
            error,
            MarketplaceAdmissionError::ReceiptBinding(
                ReceiptBindingError::AgentgresOperationMissingExpectedHeads
            )
        );
    }
}
