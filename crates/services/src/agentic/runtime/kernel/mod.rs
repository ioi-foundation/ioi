//! Shared bounded-runtime kernel primitives.
//!
//! New runtime code should use chat/artifact, graph, workflow, connector, and
//! plugin language. Legacy surface names are treated as compatibility debt.

pub mod agentgres_admission;
pub mod approval;
pub mod capability;
pub mod ctee;
pub mod deadline;
pub mod evidence;
pub mod inference;
pub mod intent;
pub mod intervention;
pub mod invocation;
pub mod marketplace;
pub mod plan;
pub mod policy;
pub mod profile;
pub mod projection;
pub mod receipt_binder;
pub mod scope;
pub mod settlement;
pub mod step_module;
pub mod trace;

use agentgres_admission::{
    AgentgresAdmissionCore, AgentgresAdmissionError, AgentgresAdmissionRecord,
    AgentgresOperationProposal,
};
use approval::{ApprovalScopeContext, AuthorityScopeMatcher, ScopeMatchDecision};
use capability::CapabilityLeaseDecision;
use ctee::{
    CteeNodeTrust, CteePrivateWorkspaceError, CteePrivateWorkspaceReceipt,
    PrivateWorkspaceCteeModule,
};
use evidence::ReceiptManifestKind;
use invocation::ToolInvocationEnvelope;
use marketplace::{MarketplaceAdmissionError, MarketplaceServiceContract};
use plan::{validate_plan, ExecutablePlan, PlanValidationError};
use profile::{RuntimeProfileConfig, RuntimeProfileValidator, RuntimeProfileViolation};
use projection::{ProjectionError, RustProjectionCore, StepModuleProjectionRecord};
use receipt_binder::{ReceiptBinder, ReceiptBindingError, StepModuleReceiptBinding};
use settlement::{ArtifactPromotionReceipt, PromotionValidationError, SettlementReceiptBundleV2};
use step_module::{StepModuleInvocation, StepModuleResult, StepModuleValidationError};

use ioi_types::app::ApprovalAuthority;

#[derive(Debug, Default, Clone)]
pub struct RuntimeKernelService;

impl RuntimeKernelService {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_plan(&self, plan: &ExecutablePlan) -> Result<(), Vec<PlanValidationError>> {
        validate_plan(plan)
    }

    pub fn validate_approval_scope(
        &self,
        authority: &ApprovalAuthority,
        context: &ApprovalScopeContext,
    ) -> ScopeMatchDecision {
        AuthorityScopeMatcher::evaluate(authority, context)
    }

    pub fn issue_capability_lease(
        &self,
        lease_hash: [u8; 32],
        scope: impl Into<String>,
        satisfied: bool,
        reason: Option<String>,
    ) -> CapabilityLeaseDecision {
        CapabilityLeaseDecision {
            lease_hash,
            satisfied,
            scope: scope.into(),
            reason,
        }
    }

    pub fn validate_tool_invocation(
        &self,
        envelope: &ToolInvocationEnvelope,
    ) -> Result<(), String> {
        if envelope.tool_name.trim().is_empty() {
            return Err("tool_invocation_missing_tool_name".to_string());
        }
        envelope
            .base
            .required_receipt_manifest
            .verify()
            .map_err(|error| format!("tool_invocation_receipt_manifest_invalid:{error}"))?;
        if envelope.base.idempotency_key.trim().is_empty() {
            return Err("tool_invocation_missing_idempotency_key".to_string());
        }
        Ok(())
    }

    pub fn validate_step_module_invocation(
        &self,
        invocation: &StepModuleInvocation,
    ) -> Result<(), Vec<StepModuleValidationError>> {
        invocation.validate()
    }

    pub fn validate_step_module_result(
        &self,
        result: &StepModuleResult,
    ) -> Result<(), Vec<StepModuleValidationError>> {
        result.validate()
    }

    pub fn bind_step_module_result(
        &self,
        invocation: &StepModuleInvocation,
        result: &StepModuleResult,
        expected_heads: Vec<String>,
    ) -> Result<StepModuleReceiptBinding, ReceiptBindingError> {
        ReceiptBinder.bind_step_module_result(invocation, result, expected_heads)
    }

    pub fn admit_agentgres_operation(
        &self,
        proposal: &AgentgresOperationProposal,
        binding: &StepModuleReceiptBinding,
    ) -> Result<AgentgresAdmissionRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.admit(proposal, binding)
    }

    pub fn validate_private_workspace_ctee_invocation(
        &self,
        invocation: &StepModuleInvocation,
        node_trust: &CteeNodeTrust,
    ) -> Result<CteePrivateWorkspaceReceipt, CteePrivateWorkspaceError> {
        PrivateWorkspaceCteeModule.validate_invocation(invocation, node_trust)
    }

    pub fn project_step_module_result(
        &self,
        invocation: &StepModuleInvocation,
        result: &StepModuleResult,
        binding: &StepModuleReceiptBinding,
    ) -> Result<StepModuleProjectionRecord, ProjectionError> {
        RustProjectionCore.project_step_module_result(invocation, result, binding)
    }

    pub fn reject_workflow_compositor_accepted_truth_attempt(&self) -> Result<(), ProjectionError> {
        RustProjectionCore.reject_workflow_compositor_accepted_truth_attempt()
    }

    pub fn validate_receipt_manifest(
        &self,
        manifest: &ReceiptManifestKind,
    ) -> Result<[u8; 32], Vec<&'static str>> {
        let missing = manifest.missing_required_evidence();
        if !missing.is_empty() {
            return Err(missing);
        }
        manifest
            .canonical_hash()
            .map_err(|_| vec!["canonical_hash"])
    }

    pub fn validate_artifact_promotion(
        &self,
        receipt: &ArtifactPromotionReceipt,
    ) -> Result<(), PromotionValidationError> {
        receipt.validate()
    }

    pub fn settlement_hash(&self, bundle: &SettlementReceiptBundleV2) -> Result<[u8; 32], String> {
        bundle.compute_settlement_hash()
    }

    pub fn validate_runtime_profile(
        &self,
        config: &RuntimeProfileConfig,
    ) -> Result<(), Vec<RuntimeProfileViolation>> {
        RuntimeProfileValidator::validate(config)
    }

    pub fn validate_marketplace_contract(
        &self,
        contract: &MarketplaceServiceContract,
    ) -> Result<(), MarketplaceAdmissionError> {
        contract.validate()
    }
}
