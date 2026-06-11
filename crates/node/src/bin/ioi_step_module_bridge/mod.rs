use ioi_client::workload_client::WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION;

#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

mod agentgres_command;
mod approval_command;
mod authority_command;
mod bridge_dispatch;
mod coding_tool_command;
mod coding_tool_helpers;
mod command_dispatch;
mod computer_use;
mod context_policy_command;
mod governed_admission_command;
mod mcp_memory_command;
mod model_mount_command;
mod policy_command;
mod projection_command;
mod runtime_control_command;
mod thread_lifecycle_command;
mod workspace_restore_command;

use agentgres_command::{
    admit_storage_backend_write, commit_runtime_agent_state, commit_runtime_artifact_state,
    commit_runtime_memory_state, commit_runtime_model_mount_receipt_state,
    commit_runtime_model_mount_record_state, commit_runtime_run_state,
    commit_runtime_subagent_state, RuntimeAgentStateCommitBridgeRequest,
    RuntimeArtifactStateCommitBridgeRequest, RuntimeMemoryStateCommitBridgeRequest,
    RuntimeModelMountReceiptStateCommitBridgeRequest,
    RuntimeModelMountRecordStateCommitBridgeRequest, RuntimeRunStateCommitBridgeRequest,
    RuntimeSubagentStateCommitBridgeRequest, StorageBackendWriteBridgeRequest,
};
use approval_command::{
    plan_approval_decision_state_update, plan_approval_request_state_update,
    plan_approval_revoke_state_update, plan_coding_tool_approval_manifest,
    ApprovalDecisionStateUpdateBridgeRequest, ApprovalRequestStateUpdateBridgeRequest,
    ApprovalRevokeStateUpdateBridgeRequest, CodingToolApprovalBridgeRequest,
};
use authority_command::{
    authorize_external_capability_exit, ExternalCapabilityExitAuthorityBridgeRequest,
};
pub use bridge_dispatch::run_bridge_response_from_stdin;
use coding_tool_command::*;
use coding_tool_helpers::*;
use context_policy_command::{
    evaluate_coding_tool_budget_policy, evaluate_compaction_policy, evaluate_context_budget_policy,
    plan_context_compaction, plan_context_compaction_state_update, CompactionPolicyBridgeRequest,
    ContextBudgetPolicyBridgeRequest, ContextCompactionPlanBridgeRequest,
    ContextCompactionStateUpdateBridgeRequest,
};
use governed_admission_command::{
    admit_governed_runtime_improvement_proposal, admit_l1_settlement_attempt,
    admit_worker_service_package_invocation, execute_private_workspace_ctee_action,
    CteePrivateWorkspaceBridgeRequest, GovernedRuntimeImprovementBridgeRequest,
    L1SettlementAdmissionBridgeRequest, WorkerServicePackageInvocationBridgeRequest,
};
use ioi_services::agentic::runtime::kernel::command_protocol::{
    command_family, expected_command_schema_version, is_step_module_operation,
    validate_command_envelope, CommandOperation, COMMAND_SCHEMA_VERSION,
    DAEMON_CORE_COMMAND_SCHEMA_VERSION, STEP_MODULE_COMMAND_SCHEMA_VERSION,
};
use mcp_memory_command::{
    plan_mcp_control_agent_state_update, plan_mcp_manager_catalog_projection,
    plan_mcp_manager_catalog_summary_projection, plan_mcp_manager_status_projection,
    plan_mcp_manager_validation_projection, plan_memory_manager_status_projection,
    plan_memory_manager_validation_projection, plan_thread_memory_agent_state_update,
    project_mcp_server_validation_input, validate_mcp_servers,
    McpControlAgentStateUpdateBridgeRequest, McpManagerCatalogProjectionBridgeRequest,
    McpManagerCatalogSummaryProjectionBridgeRequest, McpManagerStatusProjectionBridgeRequest,
    McpManagerValidationProjectionBridgeRequest, McpServerValidationBridgeRequest,
    McpServerValidationInputBridgeRequest, MemoryManagerStatusProjectionBridgeRequest,
    MemoryManagerValidationProjectionBridgeRequest, ThreadMemoryAgentStateUpdateBridgeRequest,
};
use model_mount_command::{
    admit_model_mount_invocation, admit_model_mount_provider_execution,
    admit_model_mount_provider_result, admit_model_mount_route_decision,
    bind_model_mount_invocation_receipt, execute_model_mount_provider_invocation,
    execute_model_mount_provider_stream_invocation, plan_model_mount_accepted_receipt_head,
    plan_model_mount_accepted_receipt_transition, plan_model_mount_backend_lifecycle_required,
    plan_model_mount_backend_process, plan_model_mount_instance_lifecycle,
    plan_model_mount_provider_inventory, plan_model_mount_provider_lifecycle,
    plan_model_mount_read_projection, plan_model_mount_route_control_required,
    plan_model_mount_runtime_engine_required, plan_model_mount_server_control_required,
    plan_model_mount_tokenizer_required, ModelMountAcceptedReceiptHeadBridgeRequest,
    ModelMountAcceptedReceiptTransitionBridgeRequest,
    ModelMountBackendLifecycleRequiredBridgeRequest, ModelMountBackendProcessPlanBridgeRequest,
    ModelMountInstanceLifecycleBridgeRequest, ModelMountInvocationAdmissionBridgeRequest,
    ModelMountInvocationReceiptBindingBridgeRequest, ModelMountProviderExecutionBridgeRequest,
    ModelMountProviderInventoryBridgeRequest, ModelMountProviderInvocationBridgeRequest,
    ModelMountProviderLifecycleBridgeRequest, ModelMountProviderResultAdmissionBridgeRequest,
    ModelMountReadProjectionBridgeRequest, ModelMountRouteControlRequiredBridgeRequest,
    ModelMountRouteDecisionBridgeRequest, ModelMountRuntimeEngineRequiredBridgeRequest,
    ModelMountServerControlRequiredBridgeRequest, ModelMountTokenizerRequiredBridgeRequest,
};
use policy_command::{
    plan_diagnostics_repair_admission_required, plan_workflow_edit_admission_required,
    DiagnosticsRepairAdmissionRequiredBridgeRequest, WorkflowEditAdmissionRequiredBridgeRequest,
};
use projection_command::{
    plan_repository_workflow_projection_required, plan_runtime_lifecycle_projection_required,
    plan_runtime_tool_catalog_projection_required, plan_skill_hook_registry_projection_required,
    RepositoryWorkflowProjectionRequiredBridgeRequest,
    RuntimeLifecycleProjectionRequiredBridgeRequest,
    RuntimeToolCatalogProjectionRequiredBridgeRequest,
    SkillHookRegistryProjectionRequiredBridgeRequest,
};
use runtime_control_command::{
    plan_coding_tool_budget_recovery_admission_required,
    plan_coding_tool_budget_recovery_state_update, plan_diagnostics_operator_override_state_update,
    plan_operator_interrupt_state_update, plan_operator_steer_state_update,
    plan_run_cancel_admission_required, plan_run_cancel_state_update,
    CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest,
    CodingToolBudgetRecoveryStateUpdateBridgeRequest,
    DiagnosticsOperatorOverrideStateUpdateBridgeRequest, OperatorInterruptStateUpdateBridgeRequest,
    OperatorSteerStateUpdateBridgeRequest, RunCancelAdmissionRequiredBridgeRequest,
    RunCancelStateUpdateBridgeRequest,
};
use thread_lifecycle_command::{
    plan_agent_create_state_update, plan_agent_status_state_update, plan_run_create_state_update,
    plan_runtime_bridge_thread_start_agent_state_update, plan_runtime_bridge_turn_run_state_update,
    plan_subagent_record_state_update, plan_thread_control_agent_state_update,
    AgentCreateStateUpdateBridgeRequest, AgentStatusStateUpdateBridgeRequest,
    RunCreateStateUpdateBridgeRequest, RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest,
    RuntimeBridgeTurnRunStateUpdateBridgeRequest, SubagentRecordStateUpdateBridgeRequest,
    ThreadControlAgentStateUpdateBridgeRequest,
};
use workspace_restore_command::{
    apply_workspace_restore_operations, capture_workspace_snapshot_files,
    plan_workspace_restore_apply_policy, preview_workspace_restore_operations,
    WorkspaceRestoreApplyPolicyBridgeRequest, WorkspaceRestoreOperationsBridgeRequest,
    WorkspaceSnapshotCaptureBridgeRequest,
};

const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
const MODEL_MOUNT_RUNTIME_SCHEMA_VERSION: &str = "ioi.model-mounting.runtime.v1";
const DEFAULT_PREVIEW_BYTES: u64 = 16 * 1024;
const MAX_PREVIEW_BYTES: u64 = 64 * 1024;
const MAX_DIFF_BYTES: u64 = 64 * 1024;
const DIAGNOSTIC_DEFAULT_TIMEOUT_MS: u64 = 30 * 1000;
const DIAGNOSTIC_MAX_TIMEOUT_MS: u64 = 2 * 60 * 1000;
const DIAGNOSTIC_DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024;
const DIAGNOSTIC_MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const TEST_DEFAULT_TIMEOUT_MS: u64 = 60 * 1000;
const TEST_MAX_TIMEOUT_MS: u64 = 5 * 60 * 1000;
const TEST_DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024;
const TEST_MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const APPLY_PATCH_MAX_FILE_BYTES: u64 = 1024 * 1024;
const APPLY_PATCH_MAX_DIFF_BYTES: usize = 32 * 1024;
const APPLY_PATCH_MAX_EDITS: usize = 20;
const DEFAULT_PREVIEW_LINES: usize = 200;
const MAX_PREVIEW_LINES: usize = 500;
const DIAGNOSTIC_COMMAND_IDS: [&str; 3] = ["auto", "node.check", "typescript.check"];
const TEST_COMMAND_IDS: [&str; 4] = ["node.test", "npm.test", "cargo.test", "cargo.check"];

#[derive(Debug)]
struct BridgeError {
    code: &'static str,
    message: String,
}

impl BridgeError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_services::agentic::runtime::kernel::command_protocol::CommandEnvelope;
    use ioi_services::agentic::runtime::kernel::model_mount::{
        ModelMountAcceptedReceiptTransitionRequest, ModelMountCore,
    };
    use serde_json::json;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn bridge_command_schema_version_alias_is_retired() {
        let canonical: CommandEnvelope = serde_json::from_value(json!({
            "schema_version": COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        }))
        .expect("canonical bridge envelope");

        assert_eq!(canonical.schema_version, COMMAND_SCHEMA_VERSION);

        let retired_alias = serde_json::from_value::<CommandEnvelope>(json!({
            "schemaVersion": COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        }));

        assert!(
            retired_alias.is_err(),
            "Rust bridge command intake must require canonical schema_version"
        );
    }

    #[test]
    fn bridge_unknown_operation_has_no_command_schema_family() {
        assert_eq!(command_family("unknown_operation"), None);
        assert_eq!(expected_command_schema_version("unknown_operation"), None);
        assert_eq!(
            validate_command_envelope("unknown_operation", COMMAND_SCHEMA_VERSION)
                .unwrap_err()
                .code(),
            "operation_unknown"
        );
        assert!(!is_step_module_operation("unknown_operation"));
    }

    #[test]
    fn bridge_schema_family_mismatch_is_rejected_by_rust_protocol() {
        let error = validate_command_envelope(
            "admit_model_mount_route_decision",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("schema mismatch should fail closed");

        assert_eq!(error.code(), "schema_version_invalid");
    }

    fn temp_workspace(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ioi-step-module-bridge-workspace-restore-{}-{}",
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).expect("workspace dir");
        path
    }

    #[test]
    fn bridge_admits_model_mount_route_decision_through_rust_core() {
        let request: ModelMountRouteDecisionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_model_mount_route_decision",
            "backend": "rust_model_mount_live",
            "request": {
                "schema_version": "ioi.model_mount.route_decision.v1",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "policy_hash": "sha256:policy",
                "idempotency_key": "model_route_decision:test",
                "receipt_refs": ["receipt://route"],
                "authority_grant_refs": [],
                "authority_receipt_refs": [],
                "privacy_profile": "local_private",
                "node_plaintext_allowed": false
            }
        }))
        .expect("bridge request");

        let response = admit_model_mount_route_decision(request).expect("admitted");

        assert_eq!(response["source"], "rust_model_mount_command");
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(response["record"]["model_ref"], "model.local");
        assert_eq!(response["record"]["receipt_refs"][0], "receipt://route");
        assert!(response["route_decision_ref"]
            .as_str()
            .expect("route decision ref")
            .starts_with("model_mount://route_decision/"));
    }

    #[test]
    fn model_mount_route_decision_rejects_step_module_command_schema() {
        let request: ModelMountRouteDecisionBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_model_mount_route_decision",
            "backend": "rust_model_mount_live",
            "request": {
                "schema_version": "ioi.model_mount.route_decision.v1",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "policy_hash": "sha256:policy",
                "idempotency_key": "model_route_decision:test",
                "receipt_refs": ["receipt://route"],
                "authority_grant_refs": [],
                "authority_receipt_refs": [],
                "privacy_profile": "local_private",
                "node_plaintext_allowed": false
            }
        }))
        .expect("bridge request");

        let error = admit_model_mount_route_decision(request)
            .expect_err("daemon-core model_mount rejects StepModule command schema");

        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_model_mount_invocation_through_rust_core() {
        let request: ModelMountInvocationAdmissionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_model_mount_invocation",
            "backend": "rust_model_mount_live",
            "request": {
                "schema_version": "ioi.model_mount.invocation_admission.v1",
                "invocation_ref": "model-invocation://response/test",
                "route_decision_ref": "model_mount://route_decision/test",
                "route_receipt_ref": "receipt://route/test",
                "invocation_receipt_ref": "receipt://invocation/test",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "invocation_kind": "responses",
                "policy_hash": "sha256:policy",
                "input_hash": "sha256:input",
                "output_hash": "sha256:output",
                "idempotency_key": "model_invocation:test",
                "receipt_refs": ["receipt://route/test", "receipt://invocation/test"],
                "authority_grant_refs": ["grant://wallet/model-chat"],
                "authority_receipt_refs": ["receipt://wallet/model-chat"],
                "provider_auth_evidence_refs": [],
                "backend_evidence_refs": [],
                "tool_receipt_refs": [],
                "privacy_profile": "local_private",
                "node_plaintext_allowed": false
            }
        }))
        .expect("bridge request");

        let response = admit_model_mount_invocation(request).expect("admitted");

        assert_eq!(response["source"], "rust_model_mount_invocation_command");
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(response["record"]["model_ref"], "model.local");
        assert_eq!(
            response["record"]["route_receipt_ref"],
            "receipt://route/test"
        );
        assert_eq!(
            response["record"]["invocation_receipt_ref"],
            "receipt://invocation/test"
        );
        assert!(response["invocation_admission_ref"]
            .as_str()
            .expect("invocation admission ref")
            .starts_with("model_mount://invocation_admission/"));
    }

    #[test]
    fn bridge_admits_model_mount_provider_execution_through_rust_core() {
        let request: ModelMountProviderExecutionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_model_mount_provider_execution",
            "backend": "rust_model_mount_live",
            "request": {
                "schema_version": "ioi.model_mount.provider_execution.v1",
                "invocation_ref": "model-provider-execution://response/test",
                "route_decision_ref": "model_mount://route_decision/test",
                "route_receipt_ref": "receipt://route/test",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "invocation_kind": "responses",
                "policy_hash": "sha256:policy",
                "input_hash": "sha256:input",
                "request_hash": "sha256:request",
                "idempotency_key": "model_provider_execution:test",
                "receipt_refs": ["receipt://route/test"],
                "authority_grant_refs": ["grant://wallet/model-chat"],
                "authority_receipt_refs": ["receipt://wallet/model-chat"],
                "provider_auth_evidence_refs": [],
                "backend_evidence_refs": ["backend://native-local"],
                "tool_receipt_refs": [],
                "privacy_profile": "local_private",
                "node_plaintext_allowed": false
            }
        }))
        .expect("bridge request");

        let response = admit_model_mount_provider_execution(request).expect("admitted");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_execution_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(response["record"]["request_hash"], "sha256:request");
        assert_eq!(
            response["record"]["route_receipt_ref"],
            "receipt://route/test"
        );
        assert!(response["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref")
            .starts_with("model_mount://provider_execution/"));
    }

    #[test]
    fn bridge_executes_model_mount_provider_invocation_through_rust_core() {
        let provider_execution_request: ModelMountProviderExecutionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_execution",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_execution.v1",
                    "invocation_ref": "model-provider-execution://response/test",
                    "route_decision_ref": "model_mount://route_decision/test",
                    "route_receipt_ref": "receipt://route/test",
                    "route_ref": "route.local-first",
                    "provider_ref": "provider.local",
                    "endpoint_ref": "endpoint.local",
                    "model_ref": "model.local",
                    "capability": "chat",
                    "invocation_kind": "chat.completions",
                    "policy_hash": "sha256:policy",
                    "input_hash": "sha256:input",
                    "request_hash": "sha256:request",
                    "idempotency_key": "model_provider_execution:test",
                    "receipt_refs": ["receipt://route/test"],
                    "authority_grant_refs": ["grant://wallet/model-chat"],
                    "authority_receipt_refs": ["receipt://wallet/model-chat"],
                    "provider_auth_evidence_refs": [],
                    "backend_evidence_refs": ["backend.fixture"],
                    "tool_receipt_refs": [],
                    "privacy_profile": "local_private",
                    "node_plaintext_allowed": false
                }
            }))
            .expect("provider execution request");
        let admission_response =
            admit_model_mount_provider_execution(provider_execution_request).expect("admitted");
        let admission = admission_response["record"].clone();
        let provider_execution_ref = admission["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref");
        let provider_execution_hash = admission["provider_execution_hash"]
            .as_str()
            .expect("provider execution hash");

        let request: ModelMountProviderInvocationBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "execute_model_mount_provider_invocation",
            "backend": "rust_model_mount_fixture",
            "request": {
                "schema_version": "ioi.model_mount.provider_invocation.v1",
                "provider_execution_ref": provider_execution_ref,
                "provider_execution_hash": provider_execution_hash,
                "route_decision_ref": "model_mount://route_decision/test",
                "route_receipt_ref": "receipt://route/test",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "provider_kind": "local_folder",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "invocation_kind": "chat.completions",
                "input": "user: hello",
                "request_hash": "sha256:request",
                "execution_backend": "rust_model_mount_fixture",
                "api_format": "ioi_fixture",
                "driver": "fixture",
                "backend_ref": "backend.fixture",
                "receipt_refs": ["receipt://route/test"],
                "evidence_refs": [provider_execution_ref],
                "admitted_provider_execution": admission.clone()
            }
        }))
        .expect("provider invocation bridge request");

        let response = execute_model_mount_provider_invocation(request).expect("fixture executed");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_invocation_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_fixture");
        assert_eq!(response["execution_backend"], "rust_model_mount_fixture");
        assert_eq!(response["backendId"], "backend.fixture");
        assert!(response["outputText"]
            .as_str()
            .expect("output text")
            .starts_with("IOI model router fixture response from model.local."));
        assert_eq!(
            response["provider_execution_ref"],
            admission["provider_execution_ref"]
        );
        assert!(response["invocation_hash"]
            .as_str()
            .expect("invocation hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_executes_native_local_model_mount_provider_invocation_through_rust_core() {
        let provider_execution_request: ModelMountProviderExecutionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_execution",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_execution.v1",
                    "invocation_ref": "model-provider-execution://native-local/response/test",
                    "route_decision_ref": "model_mount://route_decision/native-local/test",
                    "route_receipt_ref": "receipt://route/native-local/test",
                    "route_ref": "route.native-local",
                    "provider_ref": "provider.autopilot.local",
                    "endpoint_ref": "endpoint.native-local",
                    "model_ref": "model://qwen/qwen3.5-9b",
                    "capability": "responses",
                    "invocation_kind": "responses",
                    "policy_hash": "sha256:policy",
                    "input_hash": "sha256:input",
                    "request_hash": "sha256:request",
                    "idempotency_key": "model_provider_execution:native-local:test",
                    "receipt_refs": ["receipt://route/native-local/test"],
                    "authority_grant_refs": ["grant://wallet/model-responses"],
                    "authority_receipt_refs": ["receipt://wallet/model-responses"],
                    "provider_auth_evidence_refs": [],
                    "backend_evidence_refs": ["backend.autopilot.native-local.fixture"],
                    "tool_receipt_refs": [],
                    "privacy_profile": "local_private",
                    "node_plaintext_allowed": false
                }
            }))
            .expect("native-local provider execution request");
        let admission_response =
            admit_model_mount_provider_execution(provider_execution_request).expect("admitted");
        let admission = admission_response["record"].clone();
        let provider_execution_ref = admission["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref");
        let provider_execution_hash = admission["provider_execution_hash"]
            .as_str()
            .expect("provider execution hash");

        let request: ModelMountProviderInvocationBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "execute_model_mount_provider_invocation",
            "backend": "rust_model_mount_native_local",
            "request": {
                "schema_version": "ioi.model_mount.provider_invocation.v1",
                "provider_execution_ref": provider_execution_ref,
                "provider_execution_hash": provider_execution_hash,
                "route_decision_ref": "model_mount://route_decision/native-local/test",
                "route_receipt_ref": "receipt://route/native-local/test",
                "route_ref": "route.native-local",
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "capability": "responses",
                "invocation_kind": "responses",
                "input": "user: hello",
                "request_hash": "sha256:request",
                "execution_backend": "rust_model_mount_native_local",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "receipt_refs": ["receipt://route/native-local/test"],
                "evidence_refs": [provider_execution_ref],
                "admitted_provider_execution": admission.clone()
            }
        }))
        .expect("native-local provider invocation bridge request");

        let response = execute_model_mount_provider_invocation(request)
            .expect("native-local provider invocation executed");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_invocation_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_native_local");
        assert_eq!(
            response["execution_backend"],
            "rust_model_mount_native_local"
        );
        assert_eq!(
            response["result"]["backend"],
            "autopilot.native_local.fixture"
        );
        assert_eq!(
            response["backendId"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(
            response["providerResponseKind"],
            "rust_model_mount.native_local"
        );
        assert!(response["outputText"]
            .as_str()
            .expect("output text")
            .starts_with("Autopilot native local model response from model://qwen/qwen3.5-9b."));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_backend"));
    }

    #[test]
    fn bridge_executes_native_local_model_mount_provider_stream_through_rust_core() {
        let provider_execution_request: ModelMountProviderExecutionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_execution",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_execution.v1",
                    "invocation_ref": "model-provider-execution://native-local/stream/test",
                    "route_decision_ref": "model_mount://route_decision/native-local/stream/test",
                    "route_receipt_ref": "receipt://route/native-local/stream/test",
                    "route_ref": "route.native-local",
                    "provider_ref": "provider.autopilot.local",
                    "endpoint_ref": "endpoint.native-local",
                    "model_ref": "model://qwen/qwen3.5-9b",
                    "capability": "responses",
                    "invocation_kind": "responses",
                    "policy_hash": "sha256:policy",
                    "input_hash": "sha256:input",
                    "request_hash": "sha256:request",
                    "idempotency_key": "model_provider_execution:native-local-stream:test",
                    "receipt_refs": ["receipt://route/native-local/stream/test"],
                    "authority_grant_refs": ["grant://wallet/model-responses"],
                    "authority_receipt_refs": ["receipt://wallet/model-responses"],
                    "provider_auth_evidence_refs": [],
                    "backend_evidence_refs": ["backend.autopilot.native-local.fixture"],
                    "tool_receipt_refs": [],
                    "privacy_profile": "local_private",
                    "node_plaintext_allowed": false,
                    "stream_status": "started"
                }
            }))
            .expect("native-local stream provider execution request");
        let admission_response =
            admit_model_mount_provider_execution(provider_execution_request).expect("admitted");
        let admission = admission_response["record"].clone();
        let provider_execution_ref = admission["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref");
        let provider_execution_hash = admission["provider_execution_hash"]
            .as_str()
            .expect("provider execution hash");

        let request: ModelMountProviderInvocationBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "execute_model_mount_provider_stream_invocation",
            "backend": "rust_model_mount_native_local_stream",
            "request": {
                "schema_version": "ioi.model_mount.provider_invocation.v1",
                "provider_execution_ref": provider_execution_ref,
                "provider_execution_hash": provider_execution_hash,
                "route_decision_ref": "model_mount://route_decision/native-local/stream/test",
                "route_receipt_ref": "receipt://route/native-local/stream/test",
                "route_ref": "route.native-local",
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "capability": "responses",
                "invocation_kind": "responses",
                "input": "user: hello",
                "request_hash": "sha256:request",
                "execution_backend": "rust_model_mount_native_local_stream",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "stream_status": "started",
                "receipt_refs": ["receipt://route/native-local/stream/test"],
                "evidence_refs": [provider_execution_ref],
                "admitted_provider_execution": admission.clone()
            }
        }))
        .expect("native-local provider stream invocation bridge request");

        let response = execute_model_mount_provider_stream_invocation(request)
            .expect("native-local provider stream executed");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_stream_invocation_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_native_local_stream");
        assert_eq!(
            response["execution_backend"],
            "rust_model_mount_native_local_stream"
        );
        assert_eq!(response["streamFormat"], "ioi_jsonl");
        assert_eq!(response["streamKind"], "openai_responses_native_local");
        assert_eq!(
            response["providerResponseKind"],
            "rust_model_mount.native_local.stream"
        );
        assert!(response["streamChunks"]
            .as_array()
            .expect("stream chunks")
            .iter()
            .any(|value| value.as_str().unwrap_or("").contains("\"done\":true")));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_stream_backend"));
    }

    #[test]
    fn bridge_plans_native_local_model_mount_provider_lifecycle_through_rust_core() {
        let request: ModelMountProviderLifecycleBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_provider_lifecycle",
            "backend": "rust_model_mount_native_local_lifecycle",
            "request": {
                "schema_version": "ioi.model_mount.provider_lifecycle.v1",
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "action": "load",
                "execution_backend": "rust_model_mount_native_local_lifecycle",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "evidence_refs": ["daemon_model_load_request"],
                "process_evidence_refs": ["autopilot_native_local_process_started"]
            }
        }))
        .expect("native-local lifecycle bridge request");

        let response =
            plan_model_mount_provider_lifecycle(request).expect("lifecycle planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_lifecycle_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_native_local_lifecycle"
        );
        assert_eq!(response["status"], "loaded");
        assert_eq!(
            response["backend_id"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(
            response["provider_backend"],
            "autopilot.native_local.fixture"
        );
        assert!(response.get("backendId").is_none());
        assert!(response.get("providerBackend").is_none());
        assert_eq!(response["driver"], "native_local");
        assert!(response["lifecycle_hash"]
            .as_str()
            .expect("lifecycle hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_lifecycle_backend"));
    }

    #[test]
    fn bridge_plans_model_mount_backend_process_through_rust_core() {
        let request: ModelMountBackendProcessPlanBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_backend_process",
            "backend": "rust_model_mount_backend_process",
            "request": {
                "schema_version": "ioi.model_mount.backend_process_plan.v1",
                "backend_ref": "backend.llama",
                "backend_kind": "llama_cpp",
                "base_url": "http://127.0.0.1:8091/v1",
                "model_ref": "model://qwen/qwen3.5-9b",
                "artifact_path": "/models/private/model.gguf",
                "binary_configured": true,
                "load_options": {
                    "context_length": 4096,
                    "parallel": 2,
                    "gpu": "auto",
                    "identifier": "llama profile",
                    "embeddings": true
                }
            }
        }))
        .expect("backend process bridge request");

        let response =
            plan_model_mount_backend_process(request).expect("backend process planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_backend_process_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_backend_process");
        assert_eq!(response["supports_supervision"], true);
        assert_eq!(response["spawn_status"], "spawn_ready");
        assert_eq!(response["spawn_required"], true);
        assert!(response.get("spawnStatus").is_none());
        assert!(response["public_args"]
            .as_array()
            .expect("public args")
            .iter()
            .any(|value| value.as_str().unwrap_or("").starts_with("artifact:")));
        assert_eq!(response["spawn_args"][0], "--model");
        assert_eq!(response["spawn_args"][1], "/models/private/model.gguf");
        assert!(response["plan_hash"]
            .as_str()
            .expect("plan hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_backend_process_plan"));
    }

    #[test]
    fn bridge_plans_model_mount_backend_lifecycle_required_through_rust_core() {
        let request: ModelMountBackendLifecycleRequiredBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_backend_lifecycle_required",
                "backend": "rust_model_mount_backend_lifecycle_required",
                "request": {
                    "schema_version": "ioi.model_mount.backend_lifecycle_required.v1",
                    "operation": "model_mount.backend_lifecycle",
                    "operation_kind": "model_mount.backend.start",
                    "backend_id": "backend.llama_cpp",
                    "source": "runtime-daemon.model_mounting.backend_lifecycle"
                }
            }))
            .expect("backend lifecycle required bridge request");

        let response = plan_model_mount_backend_lifecycle_required(request)
            .expect("backend lifecycle required planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_backend_lifecycle_required_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_backend_lifecycle_required"
        );
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "model_mount_backend_lifecycle_rust_core_required"
        );
        assert_eq!(response["operation_kind"], "model_mount.backend.start");
        assert_eq!(
            response["rust_core_boundary"],
            "model_mount.backend_lifecycle"
        );
        assert_eq!(response["details"]["backend_id"], "backend.llama_cpp");
        assert_eq!(response["details"]["backend_kind"], Value::Null);
        assert!(response["details"].get("backendId").is_none());
        assert!(response["details"].get("operationKind").is_none());
    }

    #[test]
    fn bridge_plans_model_mount_server_control_required_through_rust_core() {
        let request: ModelMountServerControlRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_server_control_required",
            "backend": "rust_model_mount_server_control_required",
            "request": {
                "schema_version": "ioi.model_mount.server_control_required.v1",
                "operation": "model_mount.server_control",
                "operation_kind": "model_mount.server_control.record_operation",
                "source": "runtime-daemon.model_mounting.server_control",
                "details": {
                    "base_url": "http://daemon.test",
                    "reason": "test",
                    "server_control_id": "server-control.default"
                }
            }
        }))
        .expect("server control required bridge request");

        let response = plan_model_mount_server_control_required(request)
            .expect("server control required planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_server_control_required_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_server_control_required"
        );
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "model_mount_server_control_rust_core_required"
        );
        assert_eq!(
            response["operation_kind"],
            "model_mount.server_control.record_operation"
        );
        assert_eq!(response["rust_core_boundary"], "model_mount.server_control");
        assert_eq!(response["details"]["base_url"], "http://daemon.test");
        assert_eq!(
            response["details"]["server_control_id"],
            "server-control.default"
        );
        assert!(response["details"].get("operationKind").is_none());
        assert!(response["details"].get("serverControlId").is_none());
    }

    #[test]
    fn bridge_plans_model_mount_runtime_engine_required_through_rust_core() {
        let request: ModelMountRuntimeEngineRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_runtime_engine_required",
            "backend": "rust_model_mount_runtime_engine_required",
            "request": {
                "schema_version": "ioi.model_mount.runtime_engine_required.v1",
                "operation": "model_mount.runtime_engine",
                "operation_kind": "model_mount.runtime_engine_profile.write",
                "source": "runtime-daemon.model_mounting.runtime_engine",
                "details": {
                    "engine_id": "backend.llama-cpp"
                }
            }
        }))
        .expect("runtime engine required bridge request");

        let response = plan_model_mount_runtime_engine_required(request)
            .expect("runtime engine required planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_runtime_engine_required_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_runtime_engine_required"
        );
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "model_mount_runtime_engine_rust_core_required"
        );
        assert_eq!(
            response["operation_kind"],
            "model_mount.runtime_engine_profile.write"
        );
        assert_eq!(response["rust_core_boundary"], "model_mount.runtime_engine");
        assert_eq!(response["details"]["engine_id"], "backend.llama-cpp");
        assert!(response["details"].get("engineId").is_none());
        assert!(response["details"].get("operationKind").is_none());
    }

    #[test]
    fn bridge_plans_model_mount_tokenizer_required_through_rust_core() {
        let request: ModelMountTokenizerRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_tokenizer_required",
            "backend": "rust_model_mount_tokenizer_required",
            "request": {
                "schema_version": "ioi.model_mount.tokenizer_required.v1",
                "operation": "context_fit",
                "source": "runtime-daemon.model_mounting.tokenizer",
                "details": {
                    "model": "llama-test",
                    "route_id": "route.local-first",
                    "requested_scope": "model.context:*"
                }
            }
        }))
        .expect("tokenizer required bridge request");

        let response = plan_model_mount_tokenizer_required(request)
            .expect("tokenizer required planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_tokenizer_required_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_tokenizer_required");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(response["code"], "model_mount_tokenizer_rust_core_required");
        assert_eq!(response["operation"], "context_fit");
        assert_eq!(response["rust_core_boundary"], "model_mount.tokenizer");
        assert_eq!(response["details"]["model"], "llama-test");
        assert_eq!(response["details"]["route_id"], "route.local-first");
        assert_eq!(response["details"]["requested_scope"], "model.context:*");
        assert!(response["details"].get("routeId").is_none());
        assert!(response["details"].get("requestedScope").is_none());
    }

    #[test]
    fn bridge_plans_model_mount_route_control_required_through_rust_core() {
        let request: ModelMountRouteControlRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_route_control_required",
            "backend": "rust_model_mount_route_control_required",
            "request": {
                "schema_version": "ioi.model_mount.route_control_required.v1",
                "operation": "model_mount.route_control",
                "operation_kind": "model_mount.route.selection_update",
                "source": "runtime-daemon.model_mounting.route_control",
                "details": {
                    "route_id": "route.local-first",
                    "selected_model": "model.local",
                    "receipt_id": "receipt-route-test",
                    "route_selection_boundary": "model_mount.route_selection"
                }
            }
        }))
        .expect("route control required bridge request");

        let response = plan_model_mount_route_control_required(request)
            .expect("route control required planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_route_control_required_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_route_control_required"
        );
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "model_mount_route_control_rust_core_required"
        );
        assert_eq!(response["operation"], "model_mount.route_control");
        assert_eq!(
            response["operation_kind"],
            "model_mount.route.selection_update"
        );
        assert_eq!(response["rust_core_boundary"], "model_mount.route_control");
        assert_eq!(response["details"]["route_id"], "route.local-first");
        assert_eq!(response["details"]["selected_model"], "model.local");
        assert_eq!(response["details"]["receipt_id"], "receipt-route-test");
        assert!(response["details"].get("routeId").is_none());
        assert!(response["details"].get("selectedModel").is_none());
        assert!(response["details"].get("receiptId").is_none());
    }

    #[test]
    fn bridge_plans_model_mount_accepted_receipt_transition_through_rust_core() {
        let request: ModelMountAcceptedReceiptTransitionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_accepted_receipt_transition",
                "backend": "rust_model_mount_accepted_receipt_transition",
                "request": {
                    "schema_version": "ioi.model_mount.accepted_receipt_transition.v1",
                    "current_sequence": 0,
                    "current_head_ref": "agentgres://model-mounting/accepted-receipts/head/0",
                    "current_state_root": "sha256:state-0",
                    "receipt_id": "receipt.invoke",
                    "receipt_kind": "model_invocation",
                    "route_decision_ref": "model_mount://route_decision/test",
                    "invocation_admission_ref": "model_mount://invocation_admission/test",
                    "invocation_admission_hash": "sha256:invocation-test",
                    "input_hash": "sha256:input",
                    "output_hash": "sha256:output"
                }
            }))
            .expect("accepted receipt transition bridge request");

        let response = plan_model_mount_accepted_receipt_transition(request)
            .expect("accepted receipt transition planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_accepted_receipt_transition_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_accepted_receipt_transition"
        );
        assert_eq!(response["operation_id"], "op_00000001_model_invocation");
        assert_eq!(
            response["operation_ref"],
            "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation"
        );
        assert_eq!(
            response["expected_heads"][0],
            "agentgres://model-mounting/accepted-receipts/head/0"
        );
        assert_eq!(response["state_root_before"], "sha256:state-0");
        assert!(response["state_root_after"]
            .as_str()
            .expect("state root after")
            .starts_with("sha256:"));
        assert_eq!(
            response["resulting_head"],
            "agentgres://model-mounting/accepted-receipts/head/1"
        );
        assert_eq!(
            response["projection_watermark"],
            "model-mounting-accepted-receipts:1"
        );
        assert!(response["transition_hash"]
            .as_str()
            .expect("transition hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_plans_model_mount_accepted_receipt_head_through_rust_core() {
        let request: ModelMountAcceptedReceiptHeadBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_accepted_receipt_head",
            "backend": "rust_model_mount_accepted_receipt_head",
            "request": {
                "schema_version": "ioi.model_mount.accepted_receipt_head.v1",
                "sequence": 2
            }
        }))
        .expect("accepted receipt head bridge request");

        let response =
            plan_model_mount_accepted_receipt_head(request).expect("accepted receipt head planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_accepted_receipt_head_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_accepted_receipt_head"
        );
        assert_eq!(response["sequence"], 2);
        assert_eq!(
            response["head_ref"],
            "agentgres://model-mounting/accepted-receipts/head/2"
        );
        assert!(response["state_root"]
            .as_str()
            .expect("state root")
            .starts_with("sha256:"));
        assert_eq!(
            response["projection_watermark"],
            "model-mounting-accepted-receipts:2"
        );
        assert!(response["head_hash"]
            .as_str()
            .expect("head hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_plans_model_mount_read_projection_through_rust_core() {
        let state = json!({
            "artifacts": [{
                "id": "artifact.local",
                "modelId": "model.local",
                "providerId": "provider.local.folder",
                "privacyClass": "local_private",
                "family": "local",
                "capabilities": ["chat"],
                "lastReceiptId": "receipt-artifact"
            }, {
                "id": "artifact.fixture",
                "modelId": "local:auto",
                "providerId": "provider.fixture",
                "privacyClass": "local_private",
                "family": "fixture",
                "capabilities": ["chat"]
            }],
            "endpoints": [{
                "id": "endpoint.local",
                "modelId": "model.local",
                "providerId": "provider.local",
                "status": "mounted",
                "capabilities": ["chat"],
                "privacyClass": "local_private",
                "lastReceiptId": "receipt-endpoint"
            }],
            "instances": [],
            "routes": [{
                "id": "route.local-first",
                "role": "default",
                "status": "active",
                "fallback": ["endpoint.local"],
                "privacy": "local_private",
                "providerEligibility": ["provider.local"],
                "deniedProviders": [],
                "maxCostUsd": 0,
                "maxLatencyMs": 1000
            }],
            "backends": [],
            "backend_processes": [],
            "providers": [{
                "id": "provider.local",
                "kind": "local",
                "status": "running",
                "lastReceiptId": "receipt-provider"
            }],
            "catalog_status_input": {
                "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                "checked_at": "2026-06-08T00:00:00.000Z",
                "providers": [{
                    "id": "catalog.fixture",
                    "label": "Fixture catalog",
                    "status": "available",
                    "formats": ["gguf"],
                    "adapterPort": "ModelCatalogProviderPort",
                    "operations": ["search", "resolveVariant", "importUrl", "download", "health"],
                    "evidenceRefs": ["provider_neutral_model_catalog_adapter_boundary"]
                }],
                "storage": {
                    "rootHash": "sha256:model-root",
                    "totalBytes": 42,
                    "quotaBytes": null,
                    "quotaStatus": "ok",
                    "fileCount": 1,
                    "orphanCount": 0,
                    "destructiveActionsRequireUnload": true,
                    "evidenceRefs": ["model_storage_quota_boundary", "artifact_delete_unload_guard"]
                },
                "last_search": {
                    "searched_at": "2026-06-08T00:00:00.000Z",
                    "query": "local",
                    "filters": {"limit": 2},
                    "result_count": 1
                },
                "results": [{
                    "id": "catalog.local",
                    "modelId": "model.local"
                }]
            },
            "oauth_sessions": [{
                "id": "oauth-session.local",
                "accessTokenRef": "vault://oauth/session/access-token"
            }],
            "oauth_states": [{
                "id": "oauth-state.local",
                "verifierRef": "vault://oauth/state/verifier"
            }],
            "downloads": [],
            "provider_health": [],
            "product_artifact_policy": {"include_internal_fixtures": false},
            "runtime_engines": [],
            "runtime_engine_profiles": [],
            "runtime_preference": {"routeId": "route.local-first"},
            "runtime_survey": null,
            "grants": [],
            "vault_refs": [],
            "mcp_servers": [],
            "conversation_states": [],
            "wallet": {"port": "WalletAuthorityPort"},
            "vault": {"port": "VaultPort"},
            "agentgres_store": {"port": "AgentgresStorePort"},
            "receipts": [
                {
                    "id": "receipt-route",
                    "kind": "model_route_selection",
                    "createdAt": "2026-06-08T00:00:00.000Z",
                    "details": {
                        "model_route_decision": {
                            "schema_version": "ioi.model-route-decision.v1",
                            "route_id": "route.local-first",
                            "selected_model": "model.local"
                        },
                        "route_id": "route.local-first",
                        "endpoint_id": "endpoint.local",
                        "provider_id": "provider.local"
                    }
                },
                {
                    "id": "receipt-provider-health",
                    "kind": "provider_health",
                    "createdAt": "2026-06-08T00:01:00.000Z",
                    "details": {
                        "provider_id": "provider.local",
                        "status": "healthy"
                    }
                },
                {
                    "id": "receipt-vault-health",
                    "kind": "vault_adapter_health",
                    "createdAt": "2026-06-08T00:02:00.000Z",
                    "details": {
                        "status": "healthy",
                        "implementation": "runtime_memory_vault"
                    }
                }
            ]
        });
        let state_with_health = state.clone();
        let request: ModelMountReadProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_read_projection",
            "backend": "rust_model_mount_read_projection",
            "request": {
                "projection_kind": "projection",
                "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                "generated_at": "2026-06-08T00:00:00.000Z",
                "state": state.clone()
            }
        }))
        .expect("model_mount read projection bridge request");

        let response =
            plan_model_mount_read_projection(request).expect("read projection planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_read_projection_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_read_projection");
        assert_eq!(response["projection_kind"], "projection");
        assert_eq!(
            response["projection"]["source"],
            "agentgres_model_mounting_projection"
        );
        assert_eq!(response["projection"]["watermark"], 3);
        assert_eq!(
            response["projection"]["routeDecisions"][0]["receipt_id"],
            "receipt-route"
        );
        assert_eq!(
            response["projection"]["adapterBoundaries"]["agentgres"]["port"],
            "AgentgresStorePort"
        );
        assert_eq!(
            response["projection"]["adapterBoundaries"]["oauth"]["plaintextPersistence"],
            false
        );
        assert_eq!(
            response["projection"]["workflowBindings"]
                .as_array()
                .expect("workflow bindings")
                .len(),
            10
        );
        assert_eq!(
            response["projection"]["workflowBindings"][4]["capability"],
            "embeddings"
        );
        assert_eq!(
            response["projection"]["workflowBindings"][9]["daemonApi"],
            "/api/v1/workflows/receipt-gate"
        );
        assert_eq!(
            response["projection"]["routeDecisions"][0]["selected_model"],
            "model.local"
        );
        assert_eq!(
            response["projection"]["productArtifacts"]
                .as_array()
                .expect("product artifacts")
                .len(),
            0
        );
        assert_eq!(
            response["projection"]["runtimeModelCatalog"]
                .as_array()
                .expect("runtime model catalog")
                .len(),
            0
        );
        assert_eq!(
            response["projection"]["openAiModelList"]["data"]
                .as_array()
                .expect("openai model list data")
                .len(),
            0
        );
        assert_eq!(
            response["projection"]["modelCapabilities"]
                .as_array()
                .expect("model capabilities")
                .len(),
            0
        );
        assert_eq!(
            response["projection"]["oauthSessions"]
                .as_array()
                .expect("oauth sessions")
                .len(),
            0
        );
        assert_eq!(
            response["projection"]["oauthStates"]
                .as_array()
                .expect("oauth states")
                .len(),
            0
        );
        assert_eq!(
            response["projection"]["routes"]
                .as_array()
                .expect("routes")
                .len(),
            0
        );
        let backend_projection_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "backends",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {}
                }
            }))
            .expect("backend read projection bridge request");
        let backend_projection = plan_model_mount_read_projection(backend_projection_request)
            .expect("backend projection planned in Rust");
        assert_eq!(backend_projection["projection_kind"], "backends");
        assert_eq!(
            backend_projection["projection"]
                .as_array()
                .expect("backend projection")
                .len(),
            0
        );
        assert_eq!(
            response["projection"]["catalog"]["adapterBoundary"]["port"],
            "ModelCatalogProviderPort"
        );
        assert_eq!(
            response["projection"]["catalog"]["providers"]
                .as_array()
                .expect("catalog providers")
                .len(),
            0
        );
        assert_eq!(
            response["projection"]["catalog"]["results"]
                .as_array()
                .expect("catalog results")
                .len(),
            0
        );
        assert_eq!(response["projection"]["catalog"]["lastSearch"], Value::Null);
        assert_eq!(response["projection"]["catalog"]["storage"], Value::Null);
        assert!(response["projection"].get("route_decisions").is_none());
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "model_mount_js_read_projection_authoring_retired"));

        let receipt_replay_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "receipt_replay",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "receipt_id": "receipt-route",
                    "state": {
                        "receipts": state["receipts"].clone()
                    }
                }
            }))
            .expect("model_mount receipt replay request");

        let receipt_replay_response = plan_model_mount_read_projection(receipt_replay_request)
            .expect("receipt replay projected from receipt-only Rust context");
        assert_eq!(receipt_replay_response["projection_kind"], "receipt_replay");
        assert_eq!(
            receipt_replay_response["projection"]["receipt"]["id"],
            "receipt-route"
        );
        assert_eq!(receipt_replay_response["projection"]["route"], Value::Null);
        assert_eq!(
            receipt_replay_response["projection"]["endpoint"],
            Value::Null
        );
        assert_eq!(
            receipt_replay_response["projection"]["provider"],
            Value::Null
        );
        assert_eq!(
            receipt_replay_response["projection"]["projectionWatermark"],
            3
        );

        let workflow_bindings_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "workflow_bindings",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {}
                }
            }))
            .expect("model_mount workflow bindings request");

        let workflow_bindings_response =
            plan_model_mount_read_projection(workflow_bindings_request)
                .expect("workflow bindings projected in Rust");
        assert_eq!(
            workflow_bindings_response["projection_kind"],
            "workflow_bindings"
        );
        assert_eq!(
            workflow_bindings_response["projection"][9]["daemonApi"],
            "/api/v1/workflows/receipt-gate"
        );

        let adapter_boundaries_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "adapter_boundaries",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {}
                }
            }))
            .expect("model_mount adapter boundaries request");

        let adapter_boundaries_response =
            plan_model_mount_read_projection(adapter_boundaries_request)
                .expect("adapter boundaries projected in Rust");
        assert_eq!(
            adapter_boundaries_response["projection_kind"],
            "adapter_boundaries"
        );
        assert_eq!(
            adapter_boundaries_response["projection"]["agentgres"]["port"],
            "AgentgresStorePort"
        );
        assert_eq!(
            adapter_boundaries_response["projection"]["oauth"]["plaintextPersistence"],
            false
        );

        let server_status_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "server_status",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "base_url": "http://127.0.0.1:3200",
                    "state": {}
                }
            }))
            .expect("model_mount server status request");
        let server_status_response = plan_model_mount_read_projection(server_status_request)
            .expect("server status projected in Rust");
        assert_eq!(server_status_response["projection_kind"], "server_status");
        assert_eq!(server_status_response["projection"]["status"], "stopped");
        assert_eq!(
            server_status_response["projection"]["nativeBaseUrl"],
            "http://127.0.0.1:3200/api/v1"
        );
        assert_eq!(
            server_status_response["projection"]["providerStates"]["available"],
            0
        );
        assert_eq!(
            server_status_response["projection"]["providerStates"]["degraded"],
            0
        );
        assert_eq!(
            server_status_response["projection"]["backendStates"]["degraded"],
            0
        );

        let catalog_status_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "catalog_status",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "catalog_status_input": state["catalog_status_input"].clone()
                    }
                }
            }))
            .expect("model_mount catalog status request");
        let catalog_status_response = plan_model_mount_read_projection(catalog_status_request)
            .expect_err("catalog status fails closed until Rust catalog projection owns readback");
        assert_eq!(
            catalog_status_response.code,
            "model_catalog_status_js_readback_retired"
        );

        let oauth_sessions_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "oauth_sessions",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "oauth_sessions": [{
                            "id": "oauth-session.local",
                            "accessTokenRef": "vault://oauth/session/access-token"
                        }]
                    }
                }
            }))
            .expect("model_mount oauth sessions request");
        let oauth_sessions_error = plan_model_mount_read_projection(oauth_sessions_request)
            .expect_err(
                "oauth sessions fail closed until Rust wallet/cTEE projection owns readback",
            );
        assert_eq!(
            oauth_sessions_error.code,
            "model_mount_oauth_read_projection_js_retired"
        );

        let oauth_states_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "oauth_states",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "oauth_states": [{
                            "id": "oauth-state.local",
                            "verifierRef": "vault://oauth/state/verifier"
                        }]
                    }
                }
            }))
            .expect("model_mount oauth states request");
        let oauth_states_error = plan_model_mount_read_projection(oauth_states_request)
            .expect_err("oauth states fail closed until Rust wallet/cTEE projection owns readback");
        assert_eq!(
            oauth_states_error.code,
            "model_mount_oauth_read_projection_js_retired"
        );

        let runtime_engines_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_engines",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "runtime_engines": [{
                            "id": "backend.llama-cpp",
                            "status": "available"
                        }]
                    }
                }
            }))
            .expect("model_mount runtime engines request");
        let runtime_engines_response = plan_model_mount_read_projection(runtime_engines_request)
            .expect("runtime engines projected in Rust");
        assert_eq!(
            runtime_engines_response["projection_kind"],
            "runtime_engines"
        );
        assert_eq!(
            runtime_engines_response["projection"]
                .as_array()
                .expect("runtime engines projection array")
                .len(),
            0
        );

        let runtime_profiles_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_engine_profiles",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "runtime_engine_profiles": [{
                            "engineId": "backend.llama-cpp",
                            "profile": "local"
                        }]
                    }
                }
            }))
            .expect("model_mount runtime engine profiles request");
        let runtime_profiles_response = plan_model_mount_read_projection(runtime_profiles_request)
            .expect("runtime engine profiles projected in Rust");
        assert_eq!(
            runtime_profiles_response["projection_kind"],
            "runtime_engine_profiles"
        );
        assert_eq!(
            runtime_profiles_response["projection"]
                .as_array()
                .expect("runtime engine profiles projection array")
                .len(),
            0
        );

        let runtime_preference_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_preference",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "runtime_preference": {"routeId": "route.local-first"}
                    }
                }
            }))
            .expect("model_mount runtime preference request");
        let runtime_preference_response =
            plan_model_mount_read_projection(runtime_preference_request)
                .expect("runtime preference projected in Rust");
        assert_eq!(runtime_preference_response["projection"], Value::Null);

        let runtime_endpoint_preference_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_preference_for_endpoint",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "runtime_preference": {"routeId": "route.local-first"}
                    }
                }
            }))
            .expect("model_mount endpoint runtime preference request");
        let runtime_endpoint_preference_response =
            plan_model_mount_read_projection(runtime_endpoint_preference_request)
                .expect("endpoint runtime preference projected in Rust");
        assert_eq!(
            runtime_endpoint_preference_response["projection"],
            Value::Null
        );

        let runtime_default_load_options_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_default_load_options",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "engine_id": "backend.llama-cpp",
                    "state": {
                        "default_load_options": {"gpuLayers": 42}
                    }
                }
            }))
            .expect("model_mount runtime default load options request");
        let runtime_default_load_options_response =
            plan_model_mount_read_projection(runtime_default_load_options_request)
                .expect("runtime default load options projected in Rust");
        assert_eq!(
            runtime_default_load_options_response["projection"],
            Value::Null
        );

        let runtime_engine_detail_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_engine_detail",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "engine_id": "backend.llama-cpp",
                    "state": {
                        "runtime_engine": {
                            "id": "backend.llama-cpp",
                            "status": "available"
                        }
                    }
                }
            }))
            .expect("model_mount runtime engine detail request");
        let runtime_engine_detail_error =
            plan_model_mount_read_projection(runtime_engine_detail_request)
                .expect_err("runtime engine detail fails closed without Rust-owned engine state");
        assert_eq!(
            runtime_engine_detail_error.code,
            "model_mount_runtime_engine_not_found"
        );

        let missing_runtime_engine_detail_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_engine_detail",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "engine_id": "backend.missing",
                    "state": {}
                }
            }))
            .expect("missing model_mount runtime engine detail request");
        let missing_runtime_engine_detail_error =
            plan_model_mount_read_projection(missing_runtime_engine_detail_request)
                .expect_err("runtime engine detail fails closed when engine is missing");
        assert_eq!(
            missing_runtime_engine_detail_error.code,
            "model_mount_runtime_engine_not_found"
        );

        let latest_runtime_survey_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_runtime_survey",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "receipts": []
                    }
                }
            }))
            .expect("model_mount latest runtime survey request");
        let latest_runtime_survey_response =
            plan_model_mount_read_projection(latest_runtime_survey_request)
                .expect("latest runtime survey default projected in Rust");
        assert_eq!(
            latest_runtime_survey_response["projection_kind"],
            "latest_runtime_survey"
        );
        assert_eq!(
            latest_runtime_survey_response["projection"]["status"],
            "not_checked"
        );
        assert_eq!(
            latest_runtime_survey_response["projection"]["engineCount"],
            0
        );
        assert_eq!(
            latest_runtime_survey_response["projection"]["runtimePreference"],
            Value::Null
        );
        assert_eq!(
            latest_runtime_survey_response["projection"]["hardware"],
            Value::Null
        );

        let checked_runtime_survey_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_runtime_survey",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "receipts": [{
                            "id": "receipt-runtime-survey",
                            "kind": "runtime_survey",
                            "createdAt": "2026-06-08T00:03:00.000Z",
                            "details": {
                                "checked_at": "2026-06-08T00:03:00.000Z",
                                "engine_count": 1,
                                "selected_engines": ["backend.llama-cpp"],
                                "runtime_preference": {"selectedEngineId": "backend.llama-cpp"},
                                "hardware": {"cpuCount": 16},
                                "lm_studio": {"status": "available"}
                            }
                        }]
                    }
                }
            }))
            .expect("checked model_mount latest runtime survey request");
        let checked_runtime_survey_response =
            plan_model_mount_read_projection(checked_runtime_survey_request)
                .expect("latest runtime survey receipt projected in Rust");
        assert_eq!(
            checked_runtime_survey_response["projection"]["receiptId"],
            "receipt-runtime-survey"
        );
        assert_eq!(
            checked_runtime_survey_response["projection"]["selectedEngines"][0],
            "backend.llama-cpp"
        );
        assert_eq!(
            checked_runtime_survey_response["projection"]["hardware"]["cpuCount"],
            16
        );

        let snapshot_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "snapshot",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": state
                }
            }))
            .expect("model_mount snapshot bridge request");

        let snapshot_response = plan_model_mount_read_projection(snapshot_request)
            .expect("snapshot projection planned in Rust");

        assert_eq!(snapshot_response["projection_kind"], "snapshot");
        assert_eq!(
            snapshot_response["projection"]["projection"]["source"],
            "agentgres_model_mounting_projection"
        );
        assert_eq!(
            snapshot_response["projection"]["projection"]["watermark"],
            3
        );
        assert_eq!(
            snapshot_response["projection"]["projection"]["receiptCount"],
            3
        );
        assert_eq!(
            snapshot_response["projection"]["adapterBoundaries"]["agentgres"]["port"],
            "AgentgresStorePort"
        );
        assert_eq!(
            snapshot_response["projection"]["catalog"]["adapterBoundary"]["port"],
            "ModelCatalogProviderPort"
        );
        assert_eq!(
            snapshot_response["projection"]["catalog"]["providers"]
                .as_array()
                .expect("snapshot catalog providers")
                .len(),
            0
        );
        assert_eq!(
            snapshot_response["projection"]["catalog"]["results"]
                .as_array()
                .expect("snapshot catalog results")
                .len(),
            0
        );
        assert_eq!(
            snapshot_response["projection"]["catalog"]["lastSearch"],
            Value::Null
        );
        assert_eq!(
            snapshot_response["projection"]["catalog"]["storage"],
            Value::Null
        );
        assert_eq!(
            snapshot_response["projection"]["workflowNodes"]
                .as_array()
                .expect("snapshot workflow nodes")
                .len(),
            10
        );
        assert_eq!(
            snapshot_response["projection"]["oauthSessions"]
                .as_array()
                .expect("snapshot oauth sessions")
                .len(),
            0
        );
        assert_eq!(
            snapshot_response["projection"]["oauthStates"]
                .as_array()
                .expect("snapshot oauth states")
                .len(),
            0
        );
        assert!(snapshot_response["projection"]
            .get("workflow_bindings")
            .is_none());

        let provider_health_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_provider_health",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "provider_id": "provider.local",
                    "state": {
                        "receipts": state_with_health["receipts"].clone()
                    }
                }
            }))
            .expect("model_mount latest provider health request");

        let provider_health_response = plan_model_mount_read_projection(provider_health_request)
            .expect("latest provider health projected in Rust");

        assert_eq!(
            provider_health_response["projection_kind"],
            "latest_provider_health"
        );
        assert_eq!(
            provider_health_response["projection"]["receipt"]["id"],
            "receipt-provider-health"
        );
        assert_eq!(
            provider_health_response["projection"]["replay"]["receipt"]["id"],
            "receipt-provider-health"
        );
        assert_eq!(
            provider_health_response["projection"]["health"]["provider_id"],
            "provider.local"
        );

        let missing_provider_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_provider_health",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "provider_id": "provider.local",
                    "state": {
                        "receipts": []
                    }
                }
            }))
            .expect("missing provider latest health request");
        let missing_provider_error = plan_model_mount_read_projection(missing_provider_request)
            .expect_err(
                "latest provider health fails closed when provider health receipt is missing",
            );
        assert_eq!(
            missing_provider_error.code,
            "model_mount_provider_health_not_found"
        );

        let vault_health_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_vault_health",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": state_with_health.clone()
                }
            }))
            .expect("model_mount latest vault health request");

        let vault_health_response = plan_model_mount_read_projection(vault_health_request)
            .expect("latest vault health projected in Rust");

        assert_eq!(
            vault_health_response["projection_kind"],
            "latest_vault_health"
        );
        assert_eq!(
            vault_health_response["projection"]["receipt"]["id"],
            "receipt-vault-health"
        );
        assert_eq!(
            vault_health_response["projection"]["replay"]["receipt"]["id"],
            "receipt-vault-health"
        );

        let mut missing_vault_health_state = state_with_health;
        missing_vault_health_state["receipts"] = json!([]);
        let missing_vault_health_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_vault_health",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": missing_vault_health_state
                }
            }))
            .expect("missing vault health request");
        let missing_vault_health_error =
            plan_model_mount_read_projection(missing_vault_health_request)
                .expect_err("latest vault health fails closed when health receipt is missing");
        assert_eq!(
            missing_vault_health_error.code,
            "model_mount_vault_health_not_found"
        );
    }

    #[test]
    fn bridge_plans_local_model_mount_provider_inventory_through_rust_core() {
        let request: ModelMountProviderInventoryBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_provider_inventory",
            "backend": "rust_model_mount_native_local_inventory",
            "request": {
                "schema_version": "ioi.model_mount.provider_inventory.v1",
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "action": "list_loaded",
                "execution_backend": "rust_model_mount_native_local_inventory",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "item_refs": ["model_instance://native/qwen3"],
                "evidence_refs": ["daemon_native_local_list_loaded_request"]
            }
        }))
        .expect("native-local inventory bridge request");

        let response =
            plan_model_mount_provider_inventory(request).expect("inventory planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_inventory_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_native_local_inventory"
        );
        assert_eq!(response["status"], "listed");
        assert_eq!(
            response["backend_id"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(
            response["provider_backend"],
            "autopilot.native_local.fixture"
        );
        assert_eq!(response["driver"], "native_local");
        assert_eq!(response["item_count"], 1);
        assert!(response.get("backendId").is_none());
        assert!(response.get("providerBackend").is_none());
        assert!(response.get("itemRefs").is_none());
        assert!(response.get("itemCount").is_none());
        assert!(response["inventory_hash"]
            .as_str()
            .expect("inventory hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_inventory_backend"));
    }

    #[test]
    fn bridge_plans_model_mount_instance_lifecycle_through_rust_core() {
        let request: ModelMountInstanceLifecycleBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_instance_lifecycle",
            "backend": "rust_model_mount_instance_lifecycle",
            "request": {
                "schema_version": "ioi.model_mount.instance_lifecycle.v1",
                "instance_ref": "model_instance://native/qwen3",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "provider_ref": "provider.autopilot.local",
                "action": "load",
                "target_status": "loaded",
                "execution_backend": "rust_model_mount_instance_lifecycle",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "driver": "native_local",
                "provider_lifecycle_hash": "sha256:provider-lifecycle",
                "evidence_refs": ["rust_model_mount_provider_lifecycle"]
            }
        }))
        .expect("instance lifecycle bridge request");

        let response =
            plan_model_mount_instance_lifecycle(request).expect("instance lifecycle planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_instance_lifecycle_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_instance_lifecycle");
        assert_eq!(response["status"], "loaded");
        assert_eq!(
            response["backendId"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(response["driver"], "native_local");
        assert_eq!(
            response["provider_lifecycle_hash"],
            "sha256:provider-lifecycle"
        );
        assert!(response.get("providerLifecycleHash").is_none());
        assert!(response["instance_lifecycle_hash"]
            .as_str()
            .expect("instance lifecycle hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_instance_lifecycle"));
    }

    #[test]
    fn bridge_admits_model_mount_provider_result_through_rust_core() {
        let provider_execution_request: ModelMountProviderExecutionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_execution",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_execution.v1",
                    "invocation_ref": "model-provider-execution://response/test",
                    "route_decision_ref": "model_mount://route_decision/test",
                    "route_receipt_ref": "receipt://route/test",
                    "route_ref": "route.local-first",
                    "provider_ref": "provider.fixture",
                    "endpoint_ref": "endpoint.fixture",
                    "model_ref": "fixture:model",
                    "capability": "chat",
                    "invocation_kind": "chat.completions",
                    "policy_hash": "sha256:policy",
                    "input_hash": "sha256:input",
                    "request_hash": "sha256:request",
                    "idempotency_key": "model_provider_execution:test",
                    "receipt_refs": ["receipt://route/test"],
                    "authority_grant_refs": ["grant://wallet/model-chat"],
                    "authority_receipt_refs": ["receipt://wallet/model-chat"],
                    "provider_auth_evidence_refs": [],
                    "backend_evidence_refs": ["backend.fixture"],
                    "tool_receipt_refs": [],
                    "privacy_profile": "local_private",
                    "node_plaintext_allowed": false
                }
            }))
            .expect("provider execution request");
        let admission_response =
            admit_model_mount_provider_execution(provider_execution_request).expect("admitted");
        let admission = admission_response["record"].clone();
        let provider_execution_ref = admission["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref");
        let provider_execution_hash = admission["provider_execution_hash"]
            .as_str()
            .expect("provider execution hash");
        let output_text = "fixture provider answer";
        let output_hash = format!(
            "sha256:{}",
            sha256_hex(output_text.as_bytes()).expect("output hash")
        );

        let request: ModelMountProviderResultAdmissionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_result",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_result.v1",
                    "provider_execution_ref": provider_execution_ref,
                    "provider_execution_hash": provider_execution_hash,
                    "route_decision_ref": "model_mount://route_decision/test",
                    "route_receipt_ref": "receipt://route/test",
                    "route_ref": "route.local-first",
                    "provider_ref": "provider.fixture",
                    "provider_kind": "local_folder",
                    "endpoint_ref": "endpoint.fixture",
                    "model_ref": "fixture:model",
                    "capability": "chat",
                    "invocation_kind": "chat.completions",
                    "request_hash": "sha256:request",
                    "output_text": output_text,
                    "output_hash": output_hash,
                    "token_count": { "prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3 },
                    "provider_response_kind": "rust_model_mount.fixture",
                    "execution_backend": "rust_model_mount_fixture",
                    "backend_ref": "backend.fixture",
                    "receipt_refs": ["receipt://route/test"],
                    "provider_auth_evidence_refs": [],
                    "backend_evidence_refs": ["rust_model_mount_fixture_backend"],
                    "evidence_refs": [provider_execution_ref],
                    "admitted_provider_execution": admission.clone()
                }
            }))
            .expect("provider result bridge request");

        let response = admit_model_mount_provider_result(request).expect("result admitted");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_result_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(
            response["record"]["execution_backend"],
            "rust_model_mount_fixture"
        );
        assert_eq!(response["record"]["output_hash"], output_hash);
        assert!(response["record"]["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_provider_result_backend_bound"));
        assert!(!response["record"]["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "js_provider_driver_observation_bound"));
        assert!(response["provider_result_ref"]
            .as_str()
            .expect("provider result ref")
            .starts_with("model_mount://provider_result/"));
        assert!(response["provider_result_hash"]
            .as_str()
            .expect("provider result hash")
            .starts_with("sha256:"));

        let mut retired_observation_request = response["record"].clone();
        retired_observation_request["schema_version"] = json!("ioi.model_mount.provider_result.v1");
        retired_observation_request["output_text"] = json!(output_text);
        retired_observation_request["execution_backend"] = json!("js_provider_driver_observation");
        retired_observation_request["admitted_provider_execution"] = admission.clone();
        let request: ModelMountProviderResultAdmissionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_result",
                "backend": "rust_model_mount_live",
                "request": retired_observation_request
            }))
            .expect("retired provider result bridge request");
        let error = admit_model_mount_provider_result(request)
            .expect_err("retired JS provider result observations fail in Rust core");
        assert_eq!(error.code, "model_mount_provider_result_rejected");
        assert!(error.message.contains("UnsupportedProviderResultBackend"));
    }

    #[test]
    fn bridge_binds_model_mount_invocation_receipt_through_rust_core() {
        let accepted_receipt_transition = ModelMountCore
            .plan_accepted_receipt_transition(&ModelMountAcceptedReceiptTransitionRequest {
                schema_version: "ioi.model_mount.accepted_receipt_transition.v1".to_string(),
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
            .expect("accepted receipt transition planned");
        let request: ModelMountInvocationReceiptBindingBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "bind_model_mount_invocation_receipt",
                "backend": "rust_model_mount_live",
                "invocation": {
                    "schema_version": "ioi.step_module_invocation.v1",
                    "invocation_id": "model-invocation://receipt.test",
                    "run_id": "run:model-mount",
                    "task_id": "task:model-mount",
                    "thread_id": null,
                    "workflow_graph_id": "workflow.graph",
                    "workflow_node_id": "workflow.node",
                    "context_chamber_ref": null,
                    "action_proposal_ref": "action:model-mount:receipt.test",
                    "gate_result_ref": "gate:model-mount:receipt.test",
                    "module_ref": {
                        "kind": "model_mount",
                        "id": "chat:route.local-first:endpoint.local",
                        "version": "migration",
                        "manifest_ref": null
                    },
                    "actor": {
                        "actor_id": "runtime:hypervisor-daemon",
                        "runtime_node_ref": "node://local"
                    },
                    "authority": {
                        "authority_grant_refs": ["grant://wallet/model-chat"],
                        "policy_hash": "sha256:policy",
                        "primitive_capabilities": ["model:chat"],
                        "authority_scopes": [],
                        "approval_ref": null
                    },
                    "input": {
                        "input_hash": "sha256:input",
                        "expected_schema_ref": "schema://model-mount/chat/input",
                        "context_refs": [
                            "model_mount://route_decision/test",
                            "receipt://route/test"
                        ],
                        "artifact_refs": [],
                        "payload_refs": [],
                        "state_root_before": accepted_receipt_transition.state_root_before.clone(),
                        "projection_watermark": "model-mounting-accepted-receipts:0",
                        "data_plane_handle": null
                    },
                    "custody": {
                        "privacy_profile": "internal",
                        "plaintext_policy": {
                            "node_plaintext_allowed": false,
                            "declassification_required": false
                        },
                        "custody_proof_ref": null,
                        "leakage_profile_ref": null
                    },
                    "execution": {
                        "backend": "model_mount",
                        "idempotency_key": "model_invocation:receipt.test",
                        "deadline_ms": 300000,
                        "resource_lease_ref": null,
                        "retry_policy_ref": null
                    }
                },
                "result": {
                    "schema_version": "ioi.step_module_result.v1",
                    "invocation_id": "model-invocation://receipt.test",
                    "status": "success",
                    "execution_result_ref": "result://model-mount/receipt.test",
                    "normalized_observation_ref": "observation://model-mount/receipt.test",
                    "receipt_refs": ["receipt://receipt.test"],
                    "artifact_refs": [],
                    "payload_refs": [],
                    "agentgres_operation_refs": [accepted_receipt_transition.operation_ref.clone()],
                    "state_root_after": accepted_receipt_transition.state_root_after.clone(),
                    "resulting_head": accepted_receipt_transition.resulting_head.clone(),
                    "workflow_projection": {
                        "workflow_graph_id": "workflow.graph",
                        "workflow_node_id": "workflow.node",
                        "component_kind": "ModelInvocationNode",
                        "status": "live",
                        "attempt_id": "attempt://model-mount/receipt.test",
                        "evidence_refs": ["model_mount://invocation_admission/test"],
                        "receipt_refs": ["receipt://receipt.test"]
                    },
                    "next": {
                        "model_reentry_required": false,
                        "verifier_required": false
                    }
                },
                "accepted_receipt_transition": accepted_receipt_transition.clone(),
                "receipt_ref": "receipt://receipt.test"
            }))
            .expect("bridge request");

        let response = bind_model_mount_invocation_receipt(request).expect("receipt bound");

        assert_eq!(
            response["source"],
            "rust_model_mount_receipt_binding_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(response["router_admission"]["backend"], "model_mount");
        assert_eq!(
            response["accepted_receipt_append"]["receipt_ref"],
            "receipt://receipt.test"
        );
        assert_eq!(
            response["projection_record"]["component_kind"],
            "ModelInvocationNode"
        );
        assert_eq!(
            response["receipt_binding"]["receipt_refs"][0],
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
    }

    #[test]
    fn bridge_executes_private_workspace_ctee_action_through_rust_core() {
        let request: CteePrivateWorkspaceBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "execute_private_workspace_ctee_action",
            "backend": "ctee_operator",
            "invocation": {
                "schema_version": "ioi.step_module_invocation.v1",
                "invocation_id": "invocation://ctee.bridge.test",
                "run_id": "run:ctee",
                "task_id": "task:ctee",
                "thread_id": "thread:ctee",
                "workflow_graph_id": "workflow.ctee",
                "workflow_node_id": "node.ctee.private-workspace",
                "context_chamber_ref": "chamber:ctee",
                "action_proposal_ref": "action:ctee:private-workspace",
                "gate_result_ref": "gate:ctee:private-workspace",
                "module_ref": {
                    "kind": "private_workspace_ctee_action",
                    "id": "private_workspace.mount",
                    "version": "1",
                    "manifest_ref": "module://ctee/private-workspace@1"
                },
                "actor": {
                    "actor_id": "runtime:hypervisor-daemon",
                    "runtime_node_ref": "node://private-workspace"
                },
                "authority": {
                    "authority_grant_refs": ["grant://ctee/private-workspace"],
                    "policy_hash": "sha256:ctee-policy",
                    "primitive_capabilities": ["prim:private_workspace.mount"],
                    "authority_scopes": ["scope:ctee.private_workspace"],
                    "approval_ref": "approval://declassify"
                },
                "input": {
                    "input_hash": "sha256:ctee-input",
                    "expected_schema_ref": "schema://ctee/private-workspace/input",
                    "context_refs": ["ctx://redacted"],
                    "artifact_refs": ["artifact://encrypted-capsule"],
                    "payload_refs": ["payload://sealed-private-workspace"],
                    "state_root_before": "sha256:ctee-before",
                    "projection_watermark": "agentgres:ctee:0",
                    "data_plane_handle": null
                },
                "custody": {
                    "privacy_profile": "private_workspace_ctee",
                    "plaintext_policy": {
                        "node_plaintext_allowed": false,
                        "declassification_required": true
                    },
                    "custody_proof_ref": "artifact://custody-proof",
                    "leakage_profile_ref": "artifact://leakage-profile"
                },
                "execution": {
                    "backend": "ctee_operator",
                    "idempotency_key": "idem:ctee.bridge",
                    "deadline_ms": 300000,
                    "resource_lease_ref": "lease://ctee",
                    "retry_policy_ref": null
                }
            },
            "node_trust": {
                "runtime_node_ref": "node://rented-untrusted",
                "trusted_for_plaintext": false,
                "attestation_ref": null
            }
        }))
        .expect("ctee bridge request");

        let response =
            execute_private_workspace_ctee_action(request).expect("ctee action executed");

        assert_eq!(response["source"], "rust_ctee_private_workspace_command");
        assert_eq!(response["backend"], "ctee_operator");
        assert_eq!(response["result"]["status"], "success");
        assert_eq!(
            response["receipt"]["custody_proof_ref"],
            "artifact://custody-proof"
        );
        assert_eq!(
            response["receipt_binding"]["expected_heads"][0],
            "agentgres://ctee/private-workspace/head/current"
        );
        assert_eq!(
            response["accepted_receipt_append"]["receipt_ref"],
            response["receipt"]["receipt_ref"]
        );
        assert_eq!(
            response["agentgres_admission"]["operation_ref"],
            response["result"]["agentgres_operation_refs"][0]
        );
        assert_eq!(
            response["projection_record"]["component_kind"],
            "PrivateWorkspaceCteeAction"
        );
        assert_eq!(response["projection_record"]["status"], "live");
    }

    #[test]
    fn ctee_private_workspace_rejects_step_module_command_schema() {
        let error = validate_command_envelope(
            "execute_private_workspace_ctee_action",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("Rust command protocol rejects StepModule schema before cTEE dispatch");

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_worker_service_package_invocation_through_rust_core() {
        let request: WorkerServicePackageInvocationBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_worker_service_package_invocation",
                "backend": "rust_package_invocation",
                "request": {
                    "schema_version": "ioi.worker_service_package_invocation.v1",
                    "package_kind": "worker_package",
                    "package_ref": "worker://runtime-auditor",
                    "manifest_ref": "worker://runtime-auditor@1",
                    "invocation": {
                        "schema_version": "ioi.step_module_invocation.v1",
                        "invocation_id": "invocation://worker-package/bridge",
                        "run_id": "run:worker-package",
                        "task_id": "task:worker-package",
                        "thread_id": "thread:worker-package",
                        "workflow_graph_id": "workflow.worker-package",
                        "workflow_node_id": "node.worker-package",
                        "context_chamber_ref": null,
                        "action_proposal_ref": "action:worker-package",
                        "gate_result_ref": "gate:worker-package",
                        "module_ref": {
                            "kind": "workload_job",
                            "id": "worker://runtime-auditor",
                            "version": "1",
                            "manifest_ref": "worker://runtime-auditor@1"
                        },
                        "actor": {
                            "actor_id": "runtime:hypervisor-daemon",
                            "runtime_node_ref": "node://local"
                        },
                        "authority": {
                            "authority_grant_refs": ["grant://wallet/worker-package"],
                            "policy_hash": "sha256:worker-policy",
                            "primitive_capabilities": ["prim:worker.invoke"],
                            "authority_scopes": ["scope:repo.read"],
                            "approval_ref": "approval://worker-package"
                        },
                        "input": {
                            "input_hash": "sha256:worker-input",
                            "expected_schema_ref": "schema://worker-package/runtime-auditor/input",
                            "context_refs": ["agentgres://project/hypervisor"],
                            "artifact_refs": [],
                            "payload_refs": ["payload://worker-package/input"],
                            "state_root_before": "sha256:package-before",
                            "projection_watermark": "agentgres:worker-package:0",
                            "data_plane_handle": null
                        },
                        "custody": {
                            "privacy_profile": "internal",
                            "plaintext_policy": {
                                "node_plaintext_allowed": true,
                                "declassification_required": false
                            },
                            "custody_proof_ref": null,
                            "leakage_profile_ref": null
                        },
                        "execution": {
                            "backend": "workload_grpc",
                            "idempotency_key": "idem:worker-package-bridge",
                            "deadline_ms": 300000,
                            "resource_lease_ref": "lease://worker-package",
                            "retry_policy_ref": null
                        }
                    },
                    "result": {
                        "schema_version": "ioi.step_module_result.v1",
                        "invocation_id": "invocation://worker-package/bridge",
                        "status": "success",
                        "execution_result_ref": "result://worker-package/bridge",
                        "normalized_observation_ref": "observation://worker-package/bridge",
                        "receipt_refs": ["receipt://worker-package/bridge"],
                        "artifact_refs": ["artifact://worker-package/report"],
                        "payload_refs": ["payload://worker-package/output"],
                        "agentgres_operation_refs": ["agentgres://worker-service-package/operations/bridge"],
                        "state_root_after": "sha256:package-after",
                        "resulting_head": "agentgres://worker-service-package/head/bridge",
                        "workflow_projection": {
                            "workflow_graph_id": "workflow.worker-package",
                            "workflow_node_id": "node.worker-package",
                            "component_kind": "WorkerPackageNode",
                            "status": "live",
                            "attempt_id": "attempt://worker-package/bridge",
                            "evidence_refs": ["artifact://worker-package/report"],
                            "receipt_refs": ["receipt://worker-package/bridge"]
                        },
                        "next": {
                            "model_reentry_required": false,
                            "verifier_required": true
                        }
                    }
                }
            }))
            .expect("worker package bridge request");

        let response = admit_worker_service_package_invocation(request)
            .expect("worker package invocation admitted");

        assert_eq!(
            response["source"],
            "rust_worker_service_package_invocation_command"
        );
        assert_eq!(response["backend"], "rust_package_invocation");
        assert_eq!(response["record"]["package_kind"], "worker_package");
        assert_eq!(response["router_admission"]["backend"], "workload_grpc");
        assert_eq!(
            response["accepted_receipt_append"]["receipt_ref"],
            "receipt://worker-package/bridge"
        );
        assert_eq!(
            response["agentgres_admission"]["operation_ref"],
            "agentgres://worker-service-package/operations/bridge"
        );
        assert_eq!(
            response["receipt_binding"]["expected_heads"][0],
            "agentgres://worker-service-package/head/current"
        );
        assert_eq!(
            response["projection_record"]["component_kind"],
            "WorkerPackageNode"
        );
        assert_eq!(
            response["authority_grant_refs"][0],
            "grant://wallet/worker-package"
        );
    }

    #[test]
    fn worker_service_package_rejects_step_module_command_schema() {
        let error = validate_command_envelope(
            "admit_worker_service_package_invocation",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("Rust command protocol rejects StepModule schema before package dispatch");

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_l1_settlement_attempt_through_rust_core() {
        let request: L1SettlementAdmissionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_l1_settlement_attempt",
            "backend": "l1_settlement_guard",
            "attempt": {
                "schema_version": "ioi.l1_settlement_admission.v1",
                "settlement_ref": "l1://settlement/marketplace-transaction",
                "domain_ref": "domain://marketplace/services",
                "state_root_ref": "state-root://agentgres/marketplace/after",
                "trigger_refs": ["l1-trigger://service-contract/payment"],
                "receipt_refs": ["receipt://local-settlement/payment"]
            }
        }))
        .expect("L1 settlement bridge request");

        let response = admit_l1_settlement_attempt(request).expect("L1 settlement admitted");

        assert_eq!(response["source"], "rust_l1_settlement_guard_command");
        assert_eq!(response["backend"], "l1_settlement_guard");
        assert_eq!(
            response["settlement_ref"],
            "l1://settlement/marketplace-transaction"
        );
        assert_eq!(
            response["trigger_refs"][0],
            "l1-trigger://service-contract/payment"
        );
        assert_eq!(
            response["record"]["receipt_refs"][0],
            "receipt://local-settlement/payment"
        );
        assert_ne!(response["admission_hash"][0], 0);
    }

    #[test]
    fn l1_settlement_rejects_step_module_command_schema() {
        let error = validate_command_envelope(
            "admit_l1_settlement_attempt",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("Rust command protocol rejects StepModule schema before L1 dispatch");

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_authorizes_external_capability_exit_through_rust_authority_core() {
        let request: ExternalCapabilityExitAuthorityBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "authorize_external_capability_exit",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.external_capability_exit_authority.v1",
                "exit_ref": "exit://aiip/slack-post-message",
                "capability_ref": "capability://connector/slack.postMessage",
                "target_ref": "aiip://workspace/channel/runtime",
                "policy_hash": "sha256:external-capability-policy",
                "idempotency_key": "idem:external-capability-exit",
                "authority_grant_refs": [
                    "wallet.network://grant/external-capability/slack-post-message"
                ],
                "authority_receipt_refs": [
                    "receipt://wallet.network/authority/slack-post-message"
                ]
            }
        }))
        .expect("external capability exit bridge request");

        let response = authorize_external_capability_exit(request)
            .expect("external capability exit authorized");

        assert_eq!(
            response["source"],
            "rust_external_capability_exit_authority_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(
            response["wallet_network_grant_refs"][0],
            "wallet.network://grant/external-capability/slack-post-message"
        );
        assert_eq!(
            response["authority_receipt_refs"][0],
            "receipt://wallet.network/authority/slack-post-message"
        );
        assert!(response["authority_hash"]
            .as_str()
            .expect("authority hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_rejects_external_capability_exit_without_wallet_network_authority() {
        let request: ExternalCapabilityExitAuthorityBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "authorize_external_capability_exit",
            "request": {
                "schema_version": "ioi.external_capability_exit_authority.v1",
                "exit_ref": "exit://aiip/slack-post-message",
                "capability_ref": "capability://connector/slack.postMessage",
                "target_ref": "aiip://workspace/channel/runtime",
                "policy_hash": "sha256:external-capability-policy",
                "idempotency_key": "idem:external-capability-exit",
                "authority_grant_refs": ["grant://local-debug-only"],
                "authority_receipt_refs": [
                    "receipt://wallet.network/authority/slack-post-message"
                ]
            }
        }))
        .expect("external capability exit bridge request");

        let error = authorize_external_capability_exit(request)
            .expect_err("wallet.network authority is required");

        assert_eq!(error.code, "external_capability_exit_authority_invalid");
        assert!(error.message.contains("MissingWalletNetworkAuthority"));
    }

    #[test]
    fn external_capability_authority_rejects_step_module_command_schema() {
        let error = validate_command_envelope(
            "authorize_external_capability_exit",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("Rust command protocol rejects StepModule schema before authority dispatch");

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_governed_runtime_improvement_proposal_through_rust_core() {
        let request: GovernedRuntimeImprovementBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_governed_runtime_improvement_proposal",
            "backend": "rust_governed_evolution",
            "proposal": {
                "schema_version": "ioi.governed_runtime_improvement.v1",
                "proposal_id": "proposal://runtime-improvement/bridge",
                "target_ref": "skill://runtime-auditor/current",
                "candidate_ref": "skill-candidate://runtime-auditor/from-trace",
                "surface": "skill",
                "source_trace_ref": "trace://runtime-improvement/high-fitness",
                "eval_receipt_refs": ["receipt://eval/bridge-holdout-pass"],
                "verifier_receipt_refs": ["receipt://verifier/bridge-regression-pass"],
                "approval_ref": "approval://wallet/runtime-improvement/bridge",
                "rollback_ref": "rollback://skill/runtime-auditor/current"
            }
        }))
        .expect("governed runtime improvement bridge request");

        let response = admit_governed_runtime_improvement_proposal(request)
            .expect("governed runtime improvement proposal admitted");

        assert_eq!(response["source"], "rust_governed_meta_improvement_command");
        assert_eq!(response["backend"], "rust_governed_evolution");
        assert_eq!(
            response["record"]["proposal_id"],
            "proposal://runtime-improvement/bridge"
        );
        assert!(response["agentgres_operation_ref"]
            .as_str()
            .expect("operation ref")
            .starts_with("agentgres://runtime-improvement/operations/"));
        assert_eq!(
            response["expected_heads"][0],
            "agentgres://runtime-improvement/head/current"
        );
        assert!(response["state_root_before"]
            .as_str()
            .expect("state root before")
            .starts_with("sha256:"));
        assert!(response["state_root_after"]
            .as_str()
            .expect("state root after")
            .starts_with("sha256:"));
        assert!(response["resulting_head"]
            .as_str()
            .expect("resulting head")
            .starts_with("agentgres://runtime-improvement/head/"));
        assert_eq!(
            response["eval_receipt_refs"][0],
            "receipt://eval/bridge-holdout-pass"
        );
        assert_eq!(
            response["verifier_receipt_refs"][0],
            "receipt://verifier/bridge-regression-pass"
        );
        assert_eq!(
            response["approval_ref"],
            "approval://wallet/runtime-improvement/bridge"
        );
        assert_eq!(
            response["rollback_ref"],
            "rollback://skill/runtime-auditor/current"
        );
        assert!(response["admission_hash"]
            .as_str()
            .expect("admission hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn governed_improvement_rejects_step_module_command_schema() {
        let error = validate_command_envelope(
            "admit_governed_runtime_improvement_proposal",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("Rust command protocol rejects StepModule schema before governed dispatch");

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_plans_workspace_restore_apply_policy_through_rust_core() {
        let request: WorkspaceRestoreApplyPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_workspace_restore_apply_policy",
            "backend": "rust_workspace_restore",
            "request": {
                "schema_version": "ioi.workspace_restore_apply_policy_request.v1",
                "snapshot_id": "workspace_snapshot_alpha",
                "confirm_restore_apply": true,
                "restore_conflict_policy": "override_conflicts",
                "operations": [
                    {
                        "path": "src/app.js",
                        "status": "conflict"
                    }
                ],
                "counts": {
                    "file_count": 1,
                    "conflict_count": 1,
                    "applied_count": 1
                }
            }
        }))
        .expect("workspace restore apply policy bridge request");

        let response = plan_workspace_restore_apply_policy(request)
            .expect("workspace restore apply policy planned");

        assert_eq!(response["source"], "rust_workspace_restore_policy_command");
        assert_eq!(response["backend"], "rust_workspace_restore");
        assert_eq!(response["approval"]["satisfied"], true);
        assert_eq!(response["allow_conflicts"], true);
        assert_eq!(response["conflict_policy"], "override_conflicts");
        assert_eq!(response["apply_status"], "applied");
        assert_eq!(
            response["policy_decision_refs"][1],
            "policy_workspace_restore_apply_workspace_snapshot_alpha_conflict_override"
        );
        assert_eq!(
            response["summary"],
            "Restore apply restored 1 file(s) from workspace_snapshot_alpha with conflict override."
        );
    }

    #[test]
    fn bridge_applies_workspace_restore_operations_through_rust_core() {
        let workspace = temp_workspace("apply");
        let target = workspace.join("src/app.js");
        fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        fs::write(&target, "new").expect("write current");
        let old_hash = sha256_hex(b"old").expect("old hash");
        let new_hash = sha256_hex(b"new").expect("new hash");
        let request: WorkspaceRestoreOperationsBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "apply_workspace_restore_operations",
            "backend": "rust_workspace_restore",
            "request": {
                "schema_version": "ioi.workspace_restore_apply_operations_request.v1",
                "workspace_root": workspace.to_string_lossy(),
                "max_diff_bytes": 4096,
                "allow_conflicts": false,
                "files": [
                    {
                        "path": "src/app.js",
                        "before": {
                            "exists": true,
                            "content_hash": old_hash,
                            "content": "old"
                        },
                        "after": {
                            "exists": true,
                            "content_hash": new_hash
                        }
                    }
                ]
            }
        }))
        .expect("workspace restore operations bridge request");

        let response = apply_workspace_restore_operations(request)
            .expect("workspace restore operations applied");

        assert_eq!(
            response["source"],
            "rust_workspace_restore_operations_command"
        );
        assert_eq!(response["backend"], "rust_workspace_restore");
        assert_eq!(response["operation"], "apply_workspace_restore_operations");
        assert_eq!(response["operations"][0]["status"], "ready");
        assert_eq!(response["operations"][0]["apply_status"], "applied");
        assert_eq!(fs::read_to_string(&target).expect("restored"), "old");
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn workspace_restore_apply_rejects_step_module_command_schema() {
        let error = validate_command_envelope(
            "apply_workspace_restore_operations",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("Rust command protocol rejects StepModule schema before restore dispatch");

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_captures_workspace_snapshot_files_through_rust_core() {
        let old_hash = sha256_hex(b"old").expect("old hash");
        let new_hash = sha256_hex(b"new").expect("new hash");
        let request: WorkspaceSnapshotCaptureBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "capture_workspace_snapshot_files",
            "backend": "rust_workspace_restore",
            "request": {
                "schema_version": "ioi.workspace_snapshot_capture_request.v1",
                "max_content_bytes": 262144,
                "changed_files": [
                    {
                        "path": "src/app.js",
                        "before_hash": old_hash,
                        "after_hash": new_hash,
                        "before_exists": true,
                        "after_exists": true,
                        "before_size_bytes": 3,
                        "after_size_bytes": 3
                    }
                ],
                "content_drafts": [
                    {
                        "path": "src/app.js",
                        "before_content": "old",
                        "after_content": "new"
                    }
                ]
            }
        }))
        .expect("workspace snapshot capture bridge request");

        let response =
            capture_workspace_snapshot_files(request).expect("workspace snapshot files captured");

        assert_eq!(
            response["source"],
            "rust_workspace_snapshot_capture_command"
        );
        assert_eq!(response["backend"], "rust_workspace_restore");
        assert_eq!(response["captured_file_count"], 1);
        assert_eq!(response["omitted_file_count"], 0);
        assert_eq!(response["files"][0]["path"], "src/app.js");
        assert_eq!(response["files"][0]["before"]["content"].is_null(), true);
        assert_eq!(response["content_files"][0]["before"]["content"], "old");
    }

    #[test]
    fn bridge_plans_coding_tool_approval_manifest_through_rust_core() {
        let request: CodingToolApprovalBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_coding_tool_approval_manifest",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.coding-tool-approval-request.v1",
                "thread_id": "thread_approval",
                "turn_id": "turn_approval",
                "tool_id": "file.apply_patch",
                "tool_call_id": "call_approval",
                "effect_class": "workspace_write",
                "risk_domain": "workspace",
                "authority_scope_requirements": ["workspace.write", "workspace.write"],
                "primitive_capabilities": ["fs.write"],
                "thread_mode": "plan",
                "approval_mode": "suggest",
                "trust_profile": "local_private",
                "requested_mode": "agent",
                "normalized_requested_mode": "agent",
                "requested_approval_mode": "human_required",
                "workflow_graph_id": "graph_approval",
                "workflow_node_id": "node_approval",
                "workflow_policy": {
                    "node_approval_override": "inherit",
                    "approval_mode": "human_required",
                    "trust_profile": "restricted",
                    "requires_approval": false
                },
                "input_summary": {
                    "path": "src/app.js",
                    "dryRun": false
                },
                "input": {
                    "path": "src/app.js",
                    "dry_run": false
                }
            }
        }))
        .expect("coding-tool approval bridge request");

        let response = plan_coding_tool_approval_manifest(request)
            .expect("coding-tool approval manifest planned");

        assert_eq!(response["source"], "rust_coding_tool_approval_command");
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["approval_required"], true);
        assert_eq!(
            response["manifest"]["schema_version"],
            "ioi.runtime.coding-tool-approval-manifest.v1"
        );
        assert_eq!(
            response["manifest"]["policy_reason"],
            "thread_plan_mode_requires_approval"
        );
        assert_eq!(
            response["manifest"]["authority_scope_requirements"],
            json!(["workspace.write"])
        );
        assert!(response["input_hash"]
            .as_str()
            .expect("input hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_plans_approval_request_state_update_through_rust_core() {
        let request: ApprovalRequestStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_approval_request_state_update",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.approval-request-state-update-request.v1",
                "thread_id": "thread_alpha",
                "run_id": "run_alpha",
                "run": {
                    "id": "run_alpha",
                    "agentId": "agent_alpha",
                    "status": "running",
                    "turnStatus": "running",
                    "trace": {}
                },
                "event_id": "event_approval",
                "seq": 3,
                "created_at": "2026-06-06T04:30:00.000Z",
                "approval_id": "approval_alpha",
                "source": "runtime_auto",
                "reason": "Need permission",
                "receipt_refs": ["receipt_approval"],
                "policy_decision_refs": ["policy_approval"]
            }
        }))
        .expect("approval request state update bridge request");

        let response =
            plan_approval_request_state_update(request).expect("approval state update planned");

        assert_eq!(
            response["source"],
            "rust_approval_request_state_update_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.required");
        assert_eq!(
            response["operator_control"]["approval_id"],
            "approval_alpha"
        );
        assert!(response["operator_control"].get("approvalId").is_none());
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("receiptRefs").is_none());
        assert!(response["operator_control"]
            .get("policyDecisionRefs")
            .is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(response["run"]["status"], "blocked");
        assert_eq!(
            response["run"]["trace"]["approvalRequests"][0]["event_id"],
            "event_approval"
        );
    }

    #[test]
    fn bridge_plans_approval_request_agent_state_update_through_rust_core() {
        let request: ApprovalRequestStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_approval_request_state_update",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.approval-request-state-update-request.v1",
                "target_kind": "agent",
                "thread_id": "thread_alpha",
                "run_id": null,
                "run": null,
                "agent": {
                    "id": "agent_alpha",
                    "cwd": "/workspace/project"
                },
                "event_id": "event_approval",
                "seq": 3,
                "created_at": "2026-06-06T04:30:00.000Z",
                "approval_id": "approval_alpha",
                "source": "runtime_auto",
                "reason": "Need permission",
                "receipt_refs": ["receipt_approval"],
                "policy_decision_refs": ["policy_approval"]
            }
        }))
        .expect("approval request agent state update bridge request");

        let response = plan_approval_request_state_update(request)
            .expect("approval agent state update planned");

        assert_eq!(
            response["source"],
            "rust_approval_request_state_update_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.required");
        assert_eq!(response["target_kind"], "agent");
        assert!(response["run"].is_null());
        assert_eq!(response["agent"]["id"], "agent_alpha");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T04:30:00.000Z");
    }

    #[test]
    fn bridge_plans_approval_decision_state_update_through_rust_core() {
        let request: ApprovalDecisionStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_approval_decision_state_update",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.approval-decision-state-update-request.v1",
                "thread_id": "thread_alpha",
                "run_id": "run_alpha",
                "run": {
                    "id": "run_alpha",
                    "agentId": "agent_alpha",
                    "status": "blocked",
                    "turnStatus": "waiting_for_approval",
                    "trace": {}
                },
                "event_id": "event_decision",
                "seq": 4,
                "created_at": "2026-06-06T04:35:00.000Z",
                "approval_id": "approval_alpha",
                "lease_id": "lease_alpha",
                "lease_status": "active",
                "decision": "approve",
                "status": "approved",
                "source": "runtime_auto",
                "reason": "Looks good",
                "receipt_refs": ["receipt_decision"],
                "policy_decision_refs": ["policy_decision"]
            }
        }))
        .expect("approval decision state update bridge request");

        let response =
            plan_approval_decision_state_update(request).expect("approval decision planned");

        assert_eq!(
            response["source"],
            "rust_approval_decision_state_update_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.approve");
        assert_eq!(response["operator_control"]["lease_id"], "lease_alpha");
        assert!(response["operator_control"].get("approvalId").is_none());
        assert!(response["operator_control"].get("leaseId").is_none());
        assert!(response["operator_control"].get("leaseStatus").is_none());
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("receiptRefs").is_none());
        assert!(response["operator_control"]
            .get("policyDecisionRefs")
            .is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["approvalDecisions"][0]["event_id"],
            "event_decision"
        );
    }

    #[test]
    fn bridge_plans_approval_revoke_state_update_through_rust_core() {
        let request: ApprovalRevokeStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_approval_revoke_state_update",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.approval-revoke-state-update-request.v1",
                "thread_id": "thread_alpha",
                "run_id": "run_alpha",
                "run": {
                    "id": "run_alpha",
                    "agentId": "agent_alpha",
                    "status": "blocked",
                    "turnStatus": "waiting_for_approval",
                    "trace": {}
                },
                "event_id": "event_revoke",
                "seq": 5,
                "created_at": "2026-06-06T04:40:00.000Z",
                "approval_id": "approval_alpha",
                "lease_id": "lease_alpha",
                "source": "runtime_auto",
                "reason": "Changed my mind",
                "receipt_refs": ["receipt_revoke"],
                "policy_decision_refs": ["policy_revoke"]
            }
        }))
        .expect("approval revoke state update bridge request");

        let response = plan_approval_revoke_state_update(request).expect("approval revoke planned");

        assert_eq!(
            response["source"],
            "rust_approval_revoke_state_update_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.revoke");
        assert_eq!(response["operator_control"]["lease_status"], "revoked");
        assert!(response["operator_control"].get("approvalId").is_none());
        assert!(response["operator_control"].get("leaseId").is_none());
        assert!(response["operator_control"].get("leaseStatus").is_none());
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("receiptRefs").is_none());
        assert!(response["operator_control"]
            .get("policyDecisionRefs")
            .is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(response["run"]["turnStatus"], "waiting_for_input");
        assert_eq!(
            response["run"]["trace"]["approvalRevocations"][0]["event_id"],
            "event_revoke"
        );
    }

    #[test]
    fn approval_authority_rejects_step_module_command_schema() {
        let error = validate_command_envelope(
            "plan_coding_tool_approval_manifest",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("Rust command protocol rejects StepModule schema before approval dispatch");

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn approval_state_rejects_step_module_command_schema() {
        let error = validate_command_envelope(
            "plan_approval_request_state_update",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err(
            "Rust command protocol rejects StepModule schema before approval-state dispatch",
        );

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_evaluates_context_budget_policy_through_rust_core() {
        let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "evaluate_context_budget_policy",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.context-budget-policy-request.v1",
                "usage_telemetry": {
                    "total_tokens": 120,
                    "estimated_cost_usd": 0.03,
                    "context_pressure": 0.2
                },
                "thresholds": {
                    "max_total_tokens": 100,
                    "warn_at_ratio": 0.8
                },
                "mode": "block",
                "scope": "thread",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget",
                "workflow_graph_id": "graph_budget",
                "workflow_node_id": "node_budget",
                "source": "react_flow"
            }
        }))
        .expect("context budget bridge request");

        let response =
            evaluate_context_budget_policy(request).expect("context budget policy evaluated");

        assert_eq!(response["source"], "rust_context_budget_policy_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(
            response["record"]["event_kind"],
            "RuntimeContextBudget.Evaluate"
        );
        assert_eq!(response["record"]["component_kind"], "context_budget");
        assert_eq!(response["usage_summary"]["total_tokens"], 120.0);
        assert_eq!(response["violations"][0]["id"], "total_tokens");
        assert_eq!(response["runtime_event_kind"], "policy.blocked");
        assert_eq!(response["runtime_event_status"], "blocked");
        assert!(response["runtime_event_item_id"]
            .as_str()
            .expect("runtime event item id")
            .starts_with("turn_budget:item:context-budget:policy_context_budget_thread_"));
        assert!(response["runtime_event_idempotency_key"]
            .as_str()
            .expect("runtime event idempotency key")
            .starts_with("thread:thread_budget:context-budget:policy_context_budget_thread_"));
    }

    #[test]
    fn context_policy_rejects_step_module_command_schema() {
        let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "evaluate_context_budget_policy",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.context-budget-policy-request.v1",
                "usage_telemetry": { "total_tokens": 10 },
                "thresholds": { "max_total_tokens": 100 },
                "mode": "simulate",
                "scope": "thread",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget"
            }
        }))
        .expect("context budget bridge request");

        let error = evaluate_context_budget_policy(request)
            .expect_err("context policy must reject StepModule bridge schema");
        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_evaluates_coding_tool_budget_policy_through_rust_core() {
        let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "evaluate_coding_tool_budget_policy",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.coding-tool-budget-policy-request.v1",
                "usage_telemetry": {
                    "total_tokens": 120,
                    "estimated_cost_usd": 0.03,
                    "context_pressure": 0.2
                },
                "thresholds": {
                    "max_total_tokens": 100,
                    "warn_at_ratio": 0.8
                },
                "mode": "block",
                "scope": "thread",
                "thread_id": "thread_budget",
                "tool_id": "file.inspect",
                "tool_call_id": "call_budget",
                "workflow_graph_id": "graph_budget",
                "workflow_node_id": "node_budget",
                "source": "react_flow"
            }
        }))
        .expect("coding-tool budget bridge request");

        let response = evaluate_coding_tool_budget_policy(request)
            .expect("coding-tool budget policy evaluated");

        assert_eq!(response["source"], "rust_coding_tool_budget_policy_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["usage_summary"]["total_tokens"], 120.0);
        assert_eq!(response["violations"][0]["id"], "total_tokens");
        assert!(response["policy_decision_id"]
            .as_str()
            .expect("policy decision")
            .starts_with("policy_context_budget_thread_"));
        assert_eq!(
            response["policy_decision_refs"][0],
            response["policy_decision_id"]
        );
    }

    #[test]
    fn bridge_evaluates_compaction_policy_through_rust_core() {
        let request: CompactionPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "evaluate_compaction_policy",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.compaction-policy-request.v1",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget",
                "context_budget": {
                    "status": "blocked",
                    "summary": "Context budget blocked: total tokens exceeded."
                },
                "actions": {
                    "blocked_action": "compact",
                    "warn_action": "warn",
                    "ok_action": "noop"
                },
                "approval": {
                    "approval_required": true,
                    "approval_granted": false
                },
                "compact": {
                    "execute_compaction": false,
                    "compact_workflow_node_id": "node_compact",
                    "compact_scope": "thread"
                },
                "workflow_graph_id": "graph_budget",
                "workflow_node_id": "node_policy",
                "source": "react_flow"
            }
        }))
        .expect("compaction policy bridge request");

        let response = evaluate_compaction_policy(request).expect("compaction policy evaluated");

        assert_eq!(response["source"], "rust_compaction_policy_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "waiting");
        assert_eq!(response["action"], "approval_required");
        assert_eq!(response["selected_action"], "compact");
        assert_eq!(response["budget_status"], "blocked");
        assert_eq!(response["runtime_event_kind"], "approval.required");
        assert_eq!(response["runtime_event_status"], "waiting");
        assert!(response["runtime_event_item_id"]
            .as_str()
            .expect("runtime event item id")
            .starts_with("turn_budget:item:compaction-policy:policy_compaction_thread_budget_"));
        assert!(response["compact_idempotency_key"]
            .as_str()
            .expect("compact idempotency key")
            .starts_with(
                "thread:thread_budget:compaction-policy:compact:policy_compaction_thread_budget_"
            ));
        assert!(response["approval_id"]
            .as_str()
            .expect("approval id")
            .starts_with("approval_compaction_thread_budget_"));
    }

    #[test]
    fn bridge_plans_context_compaction_through_rust_core() {
        let request: ContextCompactionPlanBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_context_compaction",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.context-compaction-plan-request.v1",
                "thread_id": "thread_budget",
                "agent_id": "agent_budget",
                "turn_id": "turn_budget",
                "run_id": "run_budget",
                "session_id": "session_budget",
                "workspace_root": "/workspace",
                "reason": "trim context",
                "scope": "thread",
                "source": "react_flow",
                "requested_by": "operator_one",
                "workflow_graph_id": "graph_budget",
                "workflow_node_id": "node_compact",
                "event_stream_id": "thread_budget:events",
                "previous_latest_seq": 7
            }
        }))
        .expect("context compaction plan bridge request");

        let response = plan_context_compaction(request).expect("context compaction planned");

        assert_eq!(response["source"], "rust_context_compaction_plan_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["event_kind"], "context.compacted");
        assert_eq!(response["component_kind"], "context_compaction");
        assert_eq!(
            response["payload_schema_version"],
            "ioi.runtime.context-compaction.v1"
        );
        assert!(response["item_id"]
            .as_str()
            .expect("item id")
            .starts_with("turn_budget:item:context-compact:"));
        assert!(response["idempotency_key"]
            .as_str()
            .expect("idempotency key")
            .starts_with("thread:thread_budget:context.compact:"));
        assert!(response["receipt_refs"][0]
            .as_str()
            .expect("receipt ref")
            .starts_with("receipt_run_budget_context_compaction_"));
        assert_eq!(
            response["policy_decision_refs"][0],
            "policy_run_budget_context_compaction_allow"
        );
        assert_eq!(response["payload"]["reason"], "trim context");
        assert_eq!(response["payload"]["requested_by"], "operator_one");
        assert_eq!(response["payload"]["previous_latest_seq"], 7);
    }

    #[test]
    fn bridge_plans_context_compaction_state_update_through_rust_core() {
        let request: ContextCompactionStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_context_compaction_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.context-compaction-state-update-request.v1",
                "target_kind": "run",
                "thread_id": "thread_budget",
                "agent_id": "agent_budget",
                "run_id": "run_budget",
                "run": {
                    "id": "run_budget",
                    "agentId": "agent_budget",
                    "trace": {}
                },
                "agent": {
                    "id": "agent_budget",
                    "cwd": "/workspace"
                },
                "event_id": "event_budget",
                "seq": 8,
                "created_at": "2026-06-06T03:40:00.000Z",
                "source": "react_flow",
                "reason": "trim context",
                "scope": "thread"
            }
        }))
        .expect("context compaction state update bridge request");

        let response = plan_context_compaction_state_update(request)
            .expect("context compaction state update planned");

        assert_eq!(
            response["source"],
            "rust_context_compaction_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["target_kind"], "run");
        assert_eq!(response["operation_kind"], "thread.compact");
        assert_eq!(response["operator_control"]["event_id"], "event_budget");
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["contextCompaction"]["event_id"],
            "event_budget"
        );
        assert!(response["run"]["trace"]["contextCompaction"]
            .get("eventId")
            .is_none());
        assert_eq!(
            response["run"]["trace"]["contextCompaction"]["reason"],
            "trim context"
        );
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["control"],
            "compact"
        );
    }

    #[test]
    fn bridge_plans_coding_tool_budget_recovery_state_update_through_rust_core() {
        let request: CodingToolBudgetRecoveryStateUpdateBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_coding_tool_budget_recovery_state_update",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.coding-tool-budget-recovery-state-update-request.v1",
                    "thread_id": "thread_budget",
                    "run_id": "run_budget",
                    "run": {
                        "id": "run_budget",
                        "agentId": "agent_budget",
                        "trace": {}
                    },
                    "event_id": "event_retry",
                    "seq": 9,
                    "created_at": "2026-06-06T04:05:00.000Z",
                    "approval_id": "approval_budget",
                    "source": "runtime_auto",
                    "receipt_refs": ["receipt_retry"],
                    "policy_decision_refs": ["policy_retry"]
                }
            }))
            .expect("coding tool budget recovery state update bridge request");

        let response = plan_coding_tool_budget_recovery_state_update(request)
            .expect("coding tool budget recovery state update planned");

        assert_eq!(
            response["source"],
            "rust_coding_tool_budget_recovery_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "workflow.run.retry_completed");
        assert_eq!(
            response["operator_control"]["approval_id"],
            "approval_budget"
        );
        assert!(response["operator_control"].get("approvalId").is_none());
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("receiptRefs").is_none());
        assert!(response["operator_control"]
            .get("policyDecisionRefs")
            .is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["control"],
            "coding_tool_budget_recovery"
        );
    }

    #[test]
    fn bridge_plans_workflow_edit_admission_required_through_rust_core() {
        let request: WorkflowEditAdmissionRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_workflow_edit_admission_required",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.workflow-edit-admission-required-request.v1",
                "operation": "workflow_edit_proposal",
                "operation_kind": "workflow.edit_proposed",
                "thread_id": "thread_alpha",
                "turn_id": "turn_alpha",
                "proposal_id": "proposal_alpha",
                "edit_intent_id": "intent_alpha",
                "approval_id": "approval_alpha",
                "workflow_graph_id": "graph_alpha",
                "workflow_node_id": "node_alpha",
                "workflow_path": "workflows/demo.json",
                "source": "agent_studio",
                "evidence_refs": [
                    "workflow_edit_proposal_js_facade_retired",
                    "rust_daemon_core_workflow_edit_proposal_required",
                    "agentgres_workflow_edit_proposal_truth_required"
                ]
            }
        }))
        .expect("workflow edit admission required bridge request");

        let response = plan_workflow_edit_admission_required(request)
            .expect("workflow edit admission refusal planned");

        assert_eq!(
            response["source"],
            "rust_workflow_edit_admission_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(response["code"], "runtime_workflow_edit_rust_core_required");
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.workflow_edit"
        );
        assert_eq!(response["details"]["operation"], "workflow_edit_proposal");
        assert_eq!(
            response["details"]["operation_kind"],
            "workflow.edit_proposed"
        );
        assert_eq!(response["details"]["thread_id"], "thread_alpha");
        assert!(response["details"].get("threadId").is_none());
        assert!(response["details"].get("proposalId").is_none());
        assert_eq!(
            response["details"]["evidence_refs"][0],
            "workflow_edit_proposal_js_facade_retired"
        );
    }

    #[test]
    fn bridge_plans_coding_tool_budget_recovery_admission_required_through_rust_core() {
        let request: CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_coding_tool_budget_recovery_admission_required",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.coding-tool-budget-recovery-admission-required-request.v1",
                    "operation": "coding_tool_budget_recovery_control",
                    "operation_kind": "workflow.run.coding_tool_budget_recovery",
                    "run_id": "run_alpha",
                    "thread_id": "thread_alpha",
                    "action": "retry_approved",
                    "approval_id": "approval_alpha",
                    "source_event_id": "event_budget",
                    "source": "agent_studio",
                    "evidence_refs": [
                        "coding_tool_budget_recovery_js_facade_retired",
                        "rust_daemon_core_budget_recovery_admission_required",
                        "agentgres_budget_recovery_state_truth_required"
                    ]
                }
            }))
            .expect("coding-tool budget recovery admission required bridge request");

        let response = plan_coding_tool_budget_recovery_admission_required(request)
            .expect("coding-tool budget recovery admission refusal planned");

        assert_eq!(
            response["source"],
            "rust_coding_tool_budget_recovery_admission_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "runtime_coding_tool_budget_recovery_rust_core_required"
        );
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.coding_tool_budget_recovery"
        );
        assert_eq!(
            response["details"]["operation"],
            "coding_tool_budget_recovery_control"
        );
        assert_eq!(
            response["details"]["operation_kind"],
            "workflow.run.coding_tool_budget_recovery"
        );
        assert_eq!(response["details"]["run_id"], "run_alpha");
        assert_eq!(response["details"]["approval_id"], "approval_alpha");
        assert!(response["details"].get("runId").is_none());
        assert!(response["details"].get("approvalId").is_none());
    }

    #[test]
    fn bridge_plans_diagnostics_repair_admission_required_through_rust_core() {
        let request: DiagnosticsRepairAdmissionRequiredBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_diagnostics_repair_admission_required",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.diagnostics-repair-admission-required-request.v1",
                    "operation": "diagnostics_repair_decision_execution",
                    "operation_kind": "diagnostics.repair_decision.execute",
                    "thread_id": "thread_alpha",
                    "decision_id": "decision_alpha",
                    "gate_event_id": "event_gate",
                    "gate_id": "gate_alpha",
                    "snapshot_id": "snapshot_alpha",
                    "source": "agent_studio",
                    "evidence_refs": [
                        "diagnostics_repair_decision_execution_js_facade_retired",
                        "rust_daemon_core_diagnostics_repair_admission_required",
                        "agentgres_diagnostics_repair_state_truth_required"
                    ]
                }
            }))
            .expect("diagnostics repair admission required bridge request");

        let response = plan_diagnostics_repair_admission_required(request)
            .expect("diagnostics repair admission refusal planned");

        assert_eq!(
            response["source"],
            "rust_diagnostics_repair_admission_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "runtime_diagnostics_repair_rust_core_required"
        );
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.diagnostics_repair"
        );
        assert_eq!(
            response["details"]["operation"],
            "diagnostics_repair_decision_execution"
        );
        assert_eq!(
            response["details"]["operation_kind"],
            "diagnostics.repair_decision.execute"
        );
        assert_eq!(response["details"]["thread_id"], "thread_alpha");
        assert_eq!(response["details"]["decision_id"], "decision_alpha");
        assert_eq!(response["details"]["gate_event_id"], "event_gate");
        assert_eq!(response["details"]["snapshot_id"], "snapshot_alpha");
        assert!(response["details"].get("threadId").is_none());
        assert!(response["details"].get("decisionId").is_none());
        assert!(response["details"].get("gateEventId").is_none());
    }

    #[test]
    fn bridge_plans_diagnostics_operator_override_state_update_through_rust_core() {
        let request: DiagnosticsOperatorOverrideStateUpdateBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_diagnostics_operator_override_state_update",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.diagnostics-operator-override-state-update-request.v1",
                    "thread_id": "thread_budget",
                    "run_id": "run_blocked",
                    "run": {
                        "id": "run_blocked",
                        "agentId": "agent_budget",
                        "status": "blocked",
                        "turnStatus": "waiting_for_input",
                        "diagnosticsBlockingGate": {
                            "status": "blocked"
                        },
                        "trace": {
                            "stopCondition": {
                                "reason": "lsp_diagnostics_blocked"
                            }
                        },
                        "operatorControls": []
                    },
                    "event_id": "event_override",
                    "seq": 10,
                    "created_at": "2026-06-06T04:15:00.000Z",
                    "decision_id": "decision_override",
                    "gate_event_id": "event_gate",
                    "source": "runtime_auto",
                    "approval_required": true,
                    "approval_satisfied": true,
                    "approval_source": "boolean_confirmation",
                    "snapshot_id": "snapshot_alpha"
                }
            }))
            .expect("diagnostics operator override state update bridge request");

        let response = plan_diagnostics_operator_override_state_update(request)
            .expect("diagnostics operator override state update planned");

        assert_eq!(
            response["source"],
            "rust_diagnostics_operator_override_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(
            response["operation_kind"],
            "diagnostics.operator_override.event"
        );
        assert_eq!(
            response["operator_control"]["control"],
            "diagnostics_operator_override"
        );
        assert_eq!(
            response["operator_control"]["decision_id"],
            "decision_override"
        );
        for field in [
            "decisionId",
            "gateEventId",
            "approvalRequired",
            "approvalSatisfied",
            "approvalSource",
            "snapshotId",
            "eventId",
            "createdAt",
        ] {
            assert!(response["operator_control"].get(field).is_none());
        }
        assert_eq!(response["run"]["status"], "completed");
        assert_eq!(
            response["run"]["diagnosticsBlockingGate"]["status"],
            "overridden"
        );
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["event_id"],
            "event_override"
        );
    }

    #[test]
    fn bridge_plans_operator_interrupt_state_update_through_rust_core() {
        let request: OperatorInterruptStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_operator_interrupt_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.operator-interrupt-state-update-request.v1",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget",
                "run_id": "run_budget",
                "run": {
                    "id": "run_budget",
                    "agentId": "agent_budget",
                    "status": "running",
                    "turnStatus": "running",
                    "trace": {
                        "qualityLedger": {
                            "failureOntologyLabels": ["existing_label"]
                        }
                    },
                    "operatorControls": []
                },
                "event_id": "event_interrupt",
                "seq": 11,
                "created_at": "2026-06-06T04:25:00.000Z",
                "source": "runtime_auto",
                "reason": "operator_stop"
            }
        }))
        .expect("operator interrupt state update bridge request");

        let response = plan_operator_interrupt_state_update(request)
            .expect("operator interrupt state update planned");

        assert_eq!(
            response["source"],
            "rust_operator_interrupt_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.interrupt");
        assert_eq!(response["operator_control"]["control"], "interrupt");
        assert_eq!(response["operator_control"]["event_id"], "event_interrupt");
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["event_id"],
            "event_interrupt"
        );
        assert_eq!(response["run"]["status"], "canceled");
        assert_eq!(response["run"]["turnStatus"], "interrupted");
        assert_eq!(
            response["run"]["trace"]["qualityLedger"]["failureOntologyLabels"][1],
            "operator_interrupt"
        );
    }

    #[test]
    fn bridge_plans_operator_steer_state_update_through_rust_core() {
        let request: OperatorSteerStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_operator_steer_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.operator-steer-state-update-request.v1",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget",
                "run_id": "run_budget",
                "run": {
                    "id": "run_budget",
                    "agentId": "agent_budget",
                    "status": "running",
                    "turnStatus": "running",
                    "trace": {},
                    "operatorControls": []
                },
                "event_id": "event_steer",
                "seq": 12,
                "created_at": "2026-06-06T04:35:00.000Z",
                "source": "react_flow",
                "guidance": "focus on the failing bridge assertion"
            }
        }))
        .expect("operator steer state update bridge request");

        let response =
            plan_operator_steer_state_update(request).expect("operator steer state update planned");

        assert_eq!(
            response["source"],
            "rust_operator_steer_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.steer");
        assert_eq!(response["operator_control"]["control"], "steer");
        assert_eq!(
            response["operator_control"]["guidance"],
            "focus on the failing bridge assertion"
        );
        assert_eq!(response["operator_control"]["event_id"], "event_steer");
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(response["run"]["status"], "running");
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["event_id"],
            "event_steer"
        );
    }

    #[test]
    fn bridge_plans_run_cancel_state_update_through_rust_core() {
        let request: RunCancelStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_run_cancel_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.run-cancel-state-update-request.v1",
                "run_id": "run_cancel_bridge",
                "canceled_at": "2026-06-06T04:45:00.000Z",
                "run": {
                    "id": "run_cancel_bridge",
                    "agentId": "agent_bridge",
                    "status": "running",
                    "objective": "Cancel bridge run",
                    "mode": "send",
                    "createdAt": "2026-06-04T00:00:00.000Z",
                    "updatedAt": "2026-06-04T00:00:01.000Z",
                    "events": [
                        {
                            "id": "run_cancel_bridge:event:000:delta",
                            "type": "delta",
                            "data": { "text": "partial" }
                        },
                        {
                            "id": "run_cancel_bridge:event:001:completed",
                            "type": "completed",
                            "data": { "status": "completed" }
                        }
                    ],
                    "trace": {
                        "events": [],
                        "receipts": [],
                        "qualityLedger": {
                            "failureOntologyLabels": []
                        }
                    },
                    "receipts": [],
                    "artifacts": []
                }
            }
        }))
        .expect("run cancel bridge request");

        let response =
            plan_run_cancel_state_update(request).expect("run cancel state update planned");

        assert_eq!(response["source"], "rust_run_cancel_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "run.cancel");
        assert_eq!(response["run"]["status"], "canceled");
        assert_eq!(response["run"]["events"][1]["type"], "runtime_task");
        assert_eq!(response["run"]["events"][3]["type"], "job_canceled");
        assert_eq!(response["runtime_job"]["status"], "canceled");
    }

    #[test]
    fn bridge_plans_run_cancel_admission_required_through_rust_core() {
        let request: RunCancelAdmissionRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_run_cancel_admission_required",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.run-cancel-admission-required-request.v1",
                "operation": "run_cancel",
                "operation_kind": "run.cancel",
                "run_id": "run_cancel_bridge",
                "run_status": "running",
                "source": "operator",
                "evidence_refs": [
                    "runtime_run_cancel_js_facade_retired",
                    "rust_daemon_core_run_cancel_required",
                    "agentgres_run_cancel_state_truth_required"
                ]
            }
        }))
        .expect("run cancel admission required bridge request");

        let response = plan_run_cancel_admission_required(request)
            .expect("run cancel admission refusal planned");

        assert_eq!(
            response["source"],
            "rust_run_cancel_admission_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(response["code"], "runtime_run_cancel_rust_core_required");
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.run_cancel"
        );
        assert_eq!(response["details"]["operation"], "run_cancel");
        assert_eq!(response["details"]["operation_kind"], "run.cancel");
        assert_eq!(response["details"]["run_id"], "run_cancel_bridge");
        assert_eq!(response["details"]["run_status"], "running");
        assert!(response["details"].get("runId").is_none());
        assert!(response["details"].get("runStatus").is_none());
    }

    #[test]
    fn bridge_plans_skill_hook_registry_projection_required_through_rust_core() {
        let request: SkillHookRegistryProjectionRequiredBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_skill_hook_registry_projection_required",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.skill-hook-registry-projection-required-request.v1",
                    "operation": "skill_hook_registry_hooks",
                    "operation_kind": "skill_hook.registry.hooks",
                    "registry_kind": "hooks",
                    "workspace_root": "/workspace/project",
                    "source": "runtime.skill_hook_surface",
                    "evidence_refs": [
                        "runtime_skill_hook_registry_js_projection_retired",
                        "rust_daemon_core_skill_hook_registry_required",
                        "agentgres_skill_hook_registry_truth_required"
                    ]
                }
            }))
            .expect("skill hook registry projection required bridge request");

        let response = plan_skill_hook_registry_projection_required(request)
            .expect("skill hook registry projection refusal planned");

        assert_eq!(
            response["source"],
            "rust_skill_hook_registry_projection_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "runtime_skill_hook_registry_rust_core_required"
        );
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.skill_hook_registry"
        );
        assert_eq!(
            response["details"]["operation"],
            "skill_hook_registry_hooks"
        );
        assert_eq!(
            response["details"]["operation_kind"],
            "skill_hook.registry.hooks"
        );
        assert_eq!(response["details"]["registry_kind"], "hooks");
        assert_eq!(response["details"]["workspace_root"], "/workspace/project");
        assert!(response["details"].get("registryKind").is_none());
        assert!(response["details"].get("workspaceRoot").is_none());
    }

    #[test]
    fn bridge_plans_repository_workflow_projection_required_through_rust_core() {
        let request: RepositoryWorkflowProjectionRequiredBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_repository_workflow_projection_required",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.repository-workflow-projection-required-request.v1",
                    "operation": "repository_workflow_review_gate",
                    "operation_kind": "repository_workflow.projection.review_gate",
                    "projection_kind": "review_gate",
                    "workspace_root": "/workspace/project",
                    "source": "runtime.repository_surface",
                    "evidence_refs": [
                        "runtime_repository_workflow_js_projection_retired",
                        "rust_daemon_core_repository_workflow_projection_required",
                        "agentgres_repository_workflow_truth_required"
                    ]
                }
            }))
            .expect("repository workflow projection required bridge request");

        let response = plan_repository_workflow_projection_required(request)
            .expect("repository workflow projection refusal planned");

        assert_eq!(
            response["source"],
            "rust_repository_workflow_projection_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "runtime_repository_workflow_projection_rust_core_required"
        );
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.repository_workflow_projection"
        );
        assert_eq!(
            response["details"]["operation"],
            "repository_workflow_review_gate"
        );
        assert_eq!(
            response["details"]["operation_kind"],
            "repository_workflow.projection.review_gate"
        );
        assert_eq!(response["details"]["projection_kind"], "review_gate");
        assert_eq!(response["details"]["workspace_root"], "/workspace/project");
        assert!(response["details"].get("projectionKind").is_none());
        assert!(response["details"].get("workspaceRoot").is_none());
    }

    #[test]
    fn bridge_plans_runtime_tool_catalog_projection_required_through_rust_core() {
        let request: RuntimeToolCatalogProjectionRequiredBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_runtime_tool_catalog_projection_required",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.tool-catalog-projection-required-request.v1",
                    "operation": "runtime_tool_catalog",
                    "operation_kind": "runtime.tool_catalog.projection.tools",
                    "projection_kind": "tools",
                    "pack": "coding",
                    "workspace_root": "/workspace/project",
                    "source": "runtime.tool_surface",
                    "evidence_refs": [
                        "runtime_tool_catalog_js_projection_retired",
                        "rust_daemon_core_runtime_tool_catalog_required",
                        "agentgres_runtime_tool_catalog_truth_required"
                    ]
                }
            }))
            .expect("runtime tool catalog projection required bridge request");

        let response = plan_runtime_tool_catalog_projection_required(request)
            .expect("runtime tool catalog projection refusal planned");

        assert_eq!(
            response["source"],
            "rust_runtime_tool_catalog_projection_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(response["code"], "runtime_tool_catalog_rust_core_required");
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.tool_catalog"
        );
        assert_eq!(response["details"]["operation"], "runtime_tool_catalog");
        assert_eq!(
            response["details"]["operation_kind"],
            "runtime.tool_catalog.projection.tools"
        );
        assert_eq!(response["details"]["projection_kind"], "tools");
        assert_eq!(response["details"]["pack"], "coding");
        assert_eq!(response["details"]["workspace_root"], "/workspace/project");
        assert!(response["details"].get("projectionKind").is_none());
        assert!(response["details"].get("workspaceRoot").is_none());
    }

    #[test]
    fn bridge_plans_runtime_lifecycle_projection_required_through_rust_core() {
        let request: RuntimeLifecycleProjectionRequiredBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_runtime_lifecycle_projection_required",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.lifecycle-projection-required-request.v1",
                    "operation": "runtime_lifecycle_projection",
                    "operation_kind": "runtime.lifecycle_projection.agent_runs",
                    "projection_kind": "agent_runs",
                    "agent_id": "agent_123",
                    "thread_id": "thread_123",
                    "turn_id": "turn_123",
                    "run_id": "run_123",
                    "artifact_ref": "artifact_123",
                    "workspace_root": "/workspace/project",
                    "source": "runtime.lifecycle_projection_surface",
                    "evidence_refs": [
                        "runtime_lifecycle_js_projection_retired",
                        "rust_daemon_core_runtime_lifecycle_projection_required",
                        "agentgres_runtime_lifecycle_truth_required"
                    ]
                }
            }))
            .expect("runtime lifecycle projection required bridge request");

        let response = plan_runtime_lifecycle_projection_required(request)
            .expect("runtime lifecycle projection refusal planned");

        assert_eq!(
            response["source"],
            "rust_runtime_lifecycle_projection_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "runtime_lifecycle_projection_rust_core_required"
        );
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.lifecycle_projection"
        );
        assert_eq!(
            response["details"]["operation_kind"],
            "runtime.lifecycle_projection.agent_runs"
        );
        assert_eq!(response["details"]["projection_kind"], "agent_runs");
        assert_eq!(response["details"]["agent_id"], "agent_123");
        assert_eq!(response["details"]["thread_id"], "thread_123");
        assert_eq!(response["details"]["turn_id"], "turn_123");
        assert_eq!(response["details"]["run_id"], "run_123");
        assert_eq!(response["details"]["artifact_ref"], "artifact_123");
        assert_eq!(response["details"]["workspace_root"], "/workspace/project");
        assert!(response["details"].get("projectionKind").is_none());
        assert!(response["details"].get("agentId").is_none());
        assert!(response["details"].get("threadId").is_none());
        assert!(response["details"].get("turnId").is_none());
        assert!(response["details"].get("artifactRef").is_none());
        assert!(response["details"].get("workspaceRoot").is_none());
    }

    #[test]
    fn bridge_plans_thread_control_agent_state_update_through_rust_core() {
        let request: ThreadControlAgentStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_thread_control_agent_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.thread-control-agent-state-update-request.v1",
                "thread_id": "thread_1",
                "agent": {
                    "id": "agent_1",
                    "cwd": "/workspace",
                    "runtimeControls": {
                        "mode": "agent",
                        "approvalMode": "suggest",
                        "model": {
                            "id": "auto",
                            "routeId": "route.local-first"
                        }
                    }
                },
                "control_kind": "thinking",
                "controls": {
                    "mode": "agent",
                    "approvalMode": "suggest",
                    "model": {
                        "id": "auto",
                            "routeId": "route.local-first",
                            "selectedModel": "local-model"
                    },
                    "updatedAt": "2026-06-06T05:00:00.000Z"
                },
                "event_id": "evt_thread_control",
                "seq": 7,
                "created_at": "2026-06-06T05:00:00.000Z",
                "model_route": {
                    "requested_model_id": "auto",
                    "selected_model": "local-model",
                    "route_id": "route.local-first",
                    "endpoint_id": "endpoint_1",
                    "provider_id": "provider_1",
                    "receipt_id": "receipt_route_1",
                    "decision": {
                        "workflow_node_id": "runtime.model-router.custom"
                    }
                }
            }
        }))
        .expect("thread control agent state update bridge request");

        let response = plan_thread_control_agent_state_update(request)
            .expect("thread control agent state update planned");

        assert_eq!(
            response["source"],
            "rust_thread_control_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.thinking");
        assert_eq!(response["control"]["control_kind"], "thinking");
        assert_eq!(response["control"]["event_id"], "evt_thread_control");
        for field in [
            "controlKind",
            "eventId",
            "createdAt",
            "workspaceTrustWarningEventId",
        ] {
            assert!(response["control"].get(field).is_none());
        }
        assert_eq!(
            response["agent"]["runtimeControls"]["model"]["selectedModel"],
            "local-model"
        );
        assert_eq!(response["agent"]["modelId"], "local-model");
        assert_eq!(response["agent"]["modelRouteReceiptId"], "receipt_route_1");
    }

    #[test]
    fn bridge_plans_mcp_control_agent_state_update_through_rust_core() {
        let request: McpControlAgentStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_mcp_control_agent_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-control-agent-state-update-request.v1",
                "thread_id": "thread_1",
                "agent": {
                    "id": "agent_1",
                    "cwd": "/workspace",
                    "mcpRegistry": {
                        "servers": [
                            {
                                "id": "mcp.docs",
                                "enabled": true,
                                "tools": [{ "name": "search" }]
                            }
                        ]
                    }
                },
                "control_kind": "mcp_add",
                "event_id": "event_mcp_add",
                "seq": 5,
                "created_at": "2026-06-06T05:45:00.000Z"
            }
        }))
        .expect("mcp control agent state update bridge request");

        let response = plan_mcp_control_agent_state_update(request)
            .expect("mcp control agent state update planned");

        assert_eq!(
            response["source"],
            "rust_mcp_control_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.mcp_add");
        assert_eq!(response["control"]["control_kind"], "mcp_add");
        assert_eq!(response["control"]["event_id"], "event_mcp_add");
        assert!(response["control"].get("controlKind").is_none());
        assert!(response["control"].get("eventId").is_none());
        assert!(response["control"].get("createdAt").is_none());
        assert_eq!(response["agent"]["id"], "agent_1");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T05:45:00.000Z");
        assert_eq!(
            response["agent"]["mcpRegistry"]["servers"][0]["id"],
            "mcp.docs"
        );
    }

    #[test]
    fn bridge_validates_mcp_servers_through_rust_core() {
        let request: McpServerValidationBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "validate_mcp_servers",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-server-validation-request.v1",
                "servers": [
                    {
                        "id": "mcp.remote",
                        "transport": "http",
                        "server_url": "file:///tmp/socket",
                        "allowed_tools": ["fetch"],
                        "containment": {
                            "allow_network_egress": false
                        }
                    }
                ]
            }
        }))
        .expect("mcp server validation bridge request");

        let response = validate_mcp_servers(request).expect("mcp server validation planned");

        assert_eq!(response["source"], "rust_mcp_server_validation_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["ok"], false);
        assert_eq!(response["issue_count"], 2);
        assert_eq!(response["issues"][0]["code"], "mcp_remote_url_invalid");
        assert_eq!(response["issues"][1]["code"], "mcp_remote_network_blocked");
        assert!(response["issues"][0].get("serverId").is_none());
    }

    #[test]
    fn bridge_projects_mcp_server_validation_input_through_rust_core() {
        let request: McpServerValidationInputBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "project_mcp_server_validation_input",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-server-validation-input-request.v1",
                "workspace_root": "/workspace",
                "input": {
                    "mcp_json": {
                        "mcp_servers": {
                            "docs": {
                                "transport": "stdio",
                                "command": "npx",
                                "tools": {
                                    "search": { "description": "Search docs" }
                                }
                            }
                        }
                    },
                    "mcpJson": {
                        "mcpServers": {
                            "retired": {
                                "transport": "stdio",
                                "command": "retired"
                            }
                        }
                    }
                }
            }
        }))
        .expect("mcp server validation input bridge request");

        let response = project_mcp_server_validation_input(request)
            .expect("mcp server validation input projected");

        assert_eq!(
            response["source"],
            "rust_mcp_server_validation_input_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "projected");
        assert_eq!(response["workspace_root"], "/workspace");
        assert_eq!(response["server_count"], 1);
        assert_eq!(response["servers"][0]["id"], "mcp.docs");
        assert_eq!(response["servers"][0]["tool_count"], 1);
        assert!(response["servers"][0].get("sourceScope").is_none());
    }

    #[test]
    fn bridge_projects_mcp_manager_status_through_rust_core() {
        let request: McpManagerStatusProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_mcp_manager_status_projection",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-manager-status-projection-request.v1",
                "status_schema_version": "ioi.runtime.mcp-manager-status.v1",
                "validation": {
                    "ok": true,
                    "status": "pass",
                    "issues": [],
                    "warnings": []
                },
                "servers": [
                    { "id": "mcp.docs", "enabled": true },
                    { "id": "mcp.disabled", "enabled": false }
                ],
                "tools": [{ "stable_tool_id": "mcp.docs.search" }],
                "enabled_tools": [{ "stable_tool_id": "mcp.docs.search" }],
                "resources": [{ "uri": "mcp.docs://root" }],
                "prompts": [{ "name": "ask" }],
                "routes": {
                    "search_tools": "/v1/mcp/tools/search"
                }
            }
        }))
        .expect("mcp manager status projection bridge request");

        let response = plan_mcp_manager_status_projection(request)
            .expect("mcp manager status projection planned");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_status_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "ready");
        assert_eq!(response["server_count"], 2);
        assert_eq!(response["enabled_server_count"], 1);
        assert_eq!(response["enabled_tool_count"], 1);
        assert_eq!(response["validation"]["server_count"], 2);
        assert_eq!(
            response["validation"]["tools"][0]["stable_tool_id"],
            "mcp.docs.search"
        );
        assert_eq!(response["routes"]["search_tools"], "/v1/mcp/tools/search");
        assert!(response.get("serverCount").is_none());
        assert!(response["routes"].get("searchTools").is_none());
    }

    #[test]
    fn bridge_projects_memory_manager_status_through_rust_core() {
        let request: MemoryManagerStatusProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_memory_manager_status_projection",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.memory-manager-status-projection-request.v1",
                "status_schema_version": "ioi.runtime.memory-manager-status.v1",
                "validation_schema_version": "ioi.runtime.memory-manager-validation.v1",
                "projection": {
                    "policy": {
                        "id": "policy.thread",
                        "scope": "thread",
                        "injection_enabled": true,
                        "read_only": false,
                        "write_requires_approval": true,
                        "writeRequiresApproval": false
                    },
                    "paths": {
                        "records_path": "/state/memory",
                        "policies_path": "/state/policies"
                    },
                    "records": [{
                        "id": "memory.one",
                        "fact": "Remember the runtime boundary.",
                        "scope": "thread",
                        "memoryKey": "retired.project",
                        "memory_key": "project"
                    }]
                }
            }
        }))
        .expect("memory manager status projection bridge request");

        let response = plan_memory_manager_status_projection(request)
            .expect("memory manager status projection planned");

        assert_eq!(
            response["source"],
            "rust_memory_manager_status_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "ready");
        assert_eq!(response["record_count"], 1);
        assert_eq!(response["memory_key_count"], 1);
        assert_eq!(response["memory_keys"][0], "project");
        assert_eq!(response["write_requires_approval"], true);
        assert_eq!(
            response["write_blocked_reason"],
            "memory_write_requires_approval"
        );
        assert_eq!(
            response["routes"]["status"],
            "/v1/threads/{thread_id}/memory/status"
        );
        assert!(response.get("memoryKeys").is_none());
        assert!(response.get("writeRequiresApproval").is_none());
    }

    #[test]
    fn bridge_projects_memory_manager_validation_through_rust_core() {
        let request: MemoryManagerValidationProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_memory_manager_validation_projection",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.memory-manager-validation-projection-request.v1",
                    "validation_schema_version": "ioi.runtime.memory-manager-validation.v1",
                    "projection": {
                        "policy": {
                            "id": "policy.thread",
                            "scope": "thread"
                        },
                        "paths": {},
                        "records": [{
                            "id": "memory.one",
                            "fact": "Remember the runtime boundary.",
                            "scope": "thread"
                        }]
                    }
                }
            }))
            .expect("memory manager validation projection bridge request");

        let response = plan_memory_manager_validation_projection(request)
            .expect("memory manager validation projection planned");

        assert_eq!(
            response["source"],
            "rust_memory_manager_validation_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["ok"], false);
        assert_eq!(response["issue_count"], 2);
        assert_eq!(response["issues"][0]["code"], "memory_records_path_missing");
        assert_eq!(
            response["issues"][1]["code"],
            "memory_policies_path_missing"
        );
        assert!(response.get("issueCount").is_none());
        assert!(response.get("recordCount").is_none());
    }

    #[test]
    fn bridge_projects_mcp_manager_catalog_through_rust_core() {
        let request: McpManagerCatalogProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_mcp_manager_catalog_projection",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-manager-catalog-projection-request.v1",
                "servers": [
                    {
                        "id": "mcp.docs",
                        "label": "Docs",
                        "enabled": true,
                        "allowed_tools": [{ "name": "search" }],
                        "resources": [{ "uri": "docs://index" }],
                        "prompts": [{ "name": "summarize" }]
                    },
                    {
                        "id": "mcp.disabled",
                        "label": "Disabled",
                        "enabled": false,
                        "allowed_tools": ["noop"]
                    }
                ]
            }
        }))
        .expect("mcp manager catalog projection bridge request");

        let response = plan_mcp_manager_catalog_projection(request)
            .expect("mcp manager catalog projection planned");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_catalog_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "projected");
        assert_eq!(response["server_count"], 2);
        assert_eq!(response["tool_count"], 2);
        assert_eq!(response["enabled_tool_count"], 1);
        assert_eq!(response["tools"][0]["stable_tool_id"], "mcp.Docs.search");
        assert_eq!(response["tools"][1]["status"], "disabled");
        assert_eq!(
            response["resources"][0]["stable_resource_id"],
            "mcp.Docs.resource.docs_index"
        );
        assert_eq!(
            response["prompts"][0]["stable_prompt_id"],
            "mcp.Docs.prompt.summarize"
        );
        assert!(response.get("stableToolId").is_none());
        assert!(response["tools"][0].get("stableToolId").is_none());
    }

    #[test]
    fn bridge_projects_mcp_manager_catalog_summary_through_rust_core() {
        let request: McpManagerCatalogSummaryProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_mcp_manager_catalog_summary_projection",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.mcp-manager-catalog-summary-projection-request.v1",
                    "server": {
                        "id": "mcp.docs",
                        "label": "Docs",
                        "transport": "stdio"
                    },
                    "tools": [{
                        "stable_tool_id": "mcp.docs.search",
                        "tool_name": "search.index",
                        "input_schema": { "type": "object" }
                    }],
                    "resources": [{ "stable_resource_id": "mcp.docs.resource.docs", "uri": "docs://index" }],
                    "prompts": [{ "stable_prompt_id": "mcp.docs.prompt.summarize", "name": "summarize" }],
                    "live_mode": "declared_catalog",
                    "preview_limit": 25,
                    "deferred": false
                }
            }))
            .expect("mcp manager catalog summary projection bridge request");

        let response = plan_mcp_manager_catalog_summary_projection(request)
            .expect("mcp manager catalog summary projection planned");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_catalog_summary_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["object"], "ioi.runtime_mcp_catalog_summary");
        assert_eq!(response["status"], "completed");
        assert_eq!(response["server_id"], "mcp.docs");
        assert_eq!(response["tool_count"], 1);
        assert_eq!(response["resource_count"], 1);
        assert_eq!(response["prompt_count"], 1);
        assert_eq!(response["namespaces"][0], "search");
        assert_eq!(response["preview_tool_names"][0], "search.index");
        assert_eq!(response["search_route"], "/v1/mcp/tools/search");
        assert!(response.get("catalogHash").is_none());
        assert!(response.get("toolCount").is_none());
    }

    #[test]
    fn bridge_projects_mcp_manager_validation_through_rust_core() {
        let request: McpManagerValidationProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_mcp_manager_validation_projection",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-manager-validation-projection-request.v1",
                "validation_schema_version": "ioi.runtime.mcp-manager-validation.v1",
                "validation": {
                    "ok": false,
                    "status": "blocked",
                    "issues": [{ "code": "mcp_server_transport_missing", "server_id": "mcp.docs" }],
                    "warnings": []
                },
                "servers": [{ "id": "mcp.docs" }],
                "tools": [{ "stable_tool_id": "mcp.docs.search" }],
                "resources": [{ "uri": "docs://index" }],
                "prompts": [{ "name": "summarize" }]
            }
        }))
        .expect("mcp manager validation projection bridge request");

        let response = plan_mcp_manager_validation_projection(request)
            .expect("mcp manager validation projection planned");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_validation_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(
            response["schema_version"],
            "ioi.runtime.mcp-manager-validation.v1"
        );
        assert_eq!(response["object"], "ioi.runtime_mcp_manager_validation");
        assert_eq!(response["ok"], false);
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["server_count"], 1);
        assert_eq!(response["tool_count"], 1);
        assert_eq!(response["issue_count"], 1);
        assert_eq!(response["issues"][0]["server_id"], "mcp.docs");
        assert_eq!(response["tools"][0]["stable_tool_id"], "mcp.docs.search");
        assert!(response.get("serverCount").is_none());
        assert!(response["tools"][0].get("stableToolId").is_none());
    }

    #[test]
    fn bridge_plans_thread_memory_agent_state_update_through_rust_core() {
        let request: ThreadMemoryAgentStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_thread_memory_agent_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.thread-memory-agent-state-update-request.v1",
                "thread_id": "thread_1",
                "agent": {
                    "id": "agent_1",
                    "cwd": "/workspace",
                    "updatedAt": "2026-06-06T05:00:00.000Z"
                },
                "control_kind": "memory_status",
                "event_id": "event_memory_status",
                "seq": 6,
                "created_at": "2026-06-06T06:05:00.000Z"
            }
        }))
        .expect("thread memory agent state update bridge request");

        let response = plan_thread_memory_agent_state_update(request)
            .expect("thread memory agent state update planned");

        assert_eq!(
            response["source"],
            "rust_thread_memory_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.memory_status");
        assert_eq!(response["control"]["control_kind"], "memory_status");
        assert_eq!(response["control"]["event_id"], "event_memory_status");
        assert!(response["control"].get("controlKind").is_none());
        assert!(response["control"].get("eventId").is_none());
        assert!(response["control"].get("createdAt").is_none());
        assert_eq!(response["agent"]["id"], "agent_1");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T06:05:00.000Z");
    }

    #[test]
    fn bridge_plans_runtime_bridge_thread_start_agent_state_update_through_rust_core() {
        let request: RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_runtime_bridge_thread_start_agent_state_update",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.runtime-bridge-thread-start-agent-state-update-request.v1",
                    "thread_id": "thread_1",
                    "agent": {
                        "id": "agent_1",
                        "cwd": "/workspace",
                        "fixtureProfile": "fixture.local",
                        "updatedAt": "2026-06-06T05:00:00.000Z"
                    },
                    "runtime_profile": "runtime_service",
                    "session_id": "session_runtime",
                    "bridge_id": "bridge_runtime",
                    "status": "active",
                    "source": "runtime_service",
                    "updated_at": "2026-06-06T06:15:00.000Z"
                }
            }))
            .expect("runtime bridge thread start agent state update bridge request");

        let response = plan_runtime_bridge_thread_start_agent_state_update(request)
            .expect("runtime bridge thread start agent state update planned");

        assert_eq!(
            response["source"],
            "rust_runtime_bridge_thread_start_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.runtime_bridge.start");
        assert_eq!(response["bridge_start"]["session_id"], "session_runtime");
        assert_eq!(response["bridge_start"]["bridge_id"], "bridge_runtime");
        for field in ["runtimeProfile", "sessionId", "bridgeId", "updatedAt"] {
            assert!(response["bridge_start"].get(field).is_none());
        }
        assert_eq!(response["agent"]["runtimeSessionId"], "session_runtime");
        assert_eq!(response["agent"]["runtimeBridgeId"], "bridge_runtime");
        assert_eq!(response["agent"]["fixtureProfile"], Value::Null);
    }

    #[test]
    fn bridge_plans_runtime_bridge_turn_run_state_update_through_rust_core() {
        let request: RuntimeBridgeTurnRunStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_runtime_bridge_turn_run_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.runtime-bridge-turn-run-state-update-request.v1",
                "thread_id": "thread_1",
                "agent": {
                    "id": "agent_1",
                    "cwd": "/workspace"
                },
                "projection": {
                    "run_id": "run_runtime_bridge",
                    "turn_id": "turn_runtime_bridge"
                },
                "run": {
                    "id": "run_runtime_bridge",
                    "agentId": "agent_1",
                    "mode": "send",
                    "status": "completed",
                    "createdAt": "2026-06-06T06:34:00.000Z",
                    "updatedAt": "2026-06-06T06:35:00.000Z"
                }
            }
        }))
        .expect("runtime bridge turn run state update bridge request");

        let response = plan_runtime_bridge_turn_run_state_update(request)
            .expect("runtime bridge turn run state update planned");

        assert_eq!(
            response["source"],
            "rust_runtime_bridge_turn_run_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.runtime_bridge.submit");
        assert_eq!(response["run"]["id"], "run_runtime_bridge");
        assert_eq!(response["run"]["agentId"], "agent_1");
    }

    #[test]
    fn bridge_plans_subagent_record_state_update_through_rust_core() {
        let request: SubagentRecordStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_subagent_record_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.subagent-record-state-update-request.v1",
                "operation_kind": "subagent.wait",
                "thread_id": "thread_1",
                "subagent": {
                    "schema_version": "ioi.runtime.subagent.v1",
                    "object": "ioi.runtime_subagent",
                    "subagent_id": "subagent_1",
                    "parent_thread_id": "thread_1",
                    "status": "completed",
                    "lifecycle_status": "completed",
                    "updated_at": "2026-06-06T07:04:00.000Z"
                }
            }
        }))
        .expect("subagent record state update bridge request");

        let response =
            plan_subagent_record_state_update(request).expect("subagent state update planned");

        assert_eq!(
            response["source"],
            "rust_subagent_record_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "subagent.wait");
        assert_eq!(response["subagent"]["subagent_id"], "subagent_1");
    }

    #[test]
    fn bridge_plans_agent_create_state_update_through_rust_core() {
        let request: AgentCreateStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_agent_create_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.agent-create-state-update-request.v1",
                "agent": {
                    "id": "agent_create_bridge",
                    "status": "active",
                    "runtime": "local",
                    "cwd": "/workspace",
                    "runtimeControls": {
                        "mode": "agent"
                    },
                    "createdAt": "2026-06-06T05:15:00.000Z",
                    "updatedAt": "2026-06-06T05:15:00.000Z"
                }
            }
        }))
        .expect("agent create state update bridge request");

        let response =
            plan_agent_create_state_update(request).expect("agent create state update planned");

        assert_eq!(response["source"], "rust_agent_create_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.create");
        assert_eq!(response["agent"]["id"], "agent_create_bridge");
    }

    #[test]
    fn bridge_plans_agent_status_state_update_through_rust_core() {
        let request: AgentStatusStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_agent_status_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.agent-status-state-update-request.v1",
                "agent": {
                    "id": "agent_status_bridge",
                    "status": "active",
                    "createdAt": "2026-06-06T05:15:00.000Z",
                    "updatedAt": "2026-06-06T05:15:00.000Z"
                },
                "status": "archived",
                "operation_kind": "agent.archive",
                "updated_at": "2026-06-06T06:25:00.000Z"
            }
        }))
        .expect("agent status state update bridge request");

        let response =
            plan_agent_status_state_update(request).expect("agent status state update planned");

        assert_eq!(response["source"], "rust_agent_status_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.archive");
        assert_eq!(response["agent"]["id"], "agent_status_bridge");
        assert_eq!(response["agent"]["status"], "archived");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T06:25:00.000Z");
    }

    #[test]
    fn bridge_plans_run_create_state_update_through_rust_core() {
        let request: RunCreateStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_run_create_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.run-create-state-update-request.v1",
                "run": {
                    "id": "run_create_bridge",
                    "agentId": "agent_create_bridge",
                    "status": "completed",
                    "mode": "send",
                    "createdAt": "2026-06-06T05:16:00.000Z",
                    "updatedAt": "2026-06-06T05:16:00.000Z",
                    "usage": {
                        "total_tokens": 7
                    },
                    "usage_telemetry": {
                        "total_tokens": 7
                    },
                    "trace": {
                        "usage_telemetry": {
                            "total_tokens": 7
                        }
                    }
                }
            }
        }))
        .expect("run create state update bridge request");

        let response =
            plan_run_create_state_update(request).expect("run create state update planned");

        assert_eq!(response["source"], "rust_run_create_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "run.create");
        assert_eq!(response["run"]["id"], "run_create_bridge");
        assert_eq!(
            response["run"]["trace"]["usage_telemetry"]["total_tokens"],
            7
        );
    }

    #[test]
    fn runtime_agentgres_storage_rejects_step_module_command_schema() {
        let request: StorageBackendWriteBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_storage_backend_write",
            "backend": "rust_agentgres_storage",
            "request": {
                "schema_version": "ioi.storage_backend_write_admission.v1",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "object_ref": "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
                "content_hash": "sha256:runtime-state-write",
                "artifact_refs": [],
                "payload_refs": ["payload://runtime/runs/run_1/records/runs/run_1.json"],
                "receipt_refs": ["receipt_policy"]
            }
        }))
        .expect("storage write bridge request");

        let error = admit_storage_backend_write(request)
            .expect_err("runtime Agentgres storage admission must reject StepModule bridge schema");
        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn runtime_agentgres_commit_rejects_step_module_command_schema() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeAgentStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_agent_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_agent_state_commit.v1",
                "agent_id": "agent_1",
                "operation_kind": "agent.create",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "agent": {
                    "id": "agent_1",
                    "status": "active",
                    "runtime": "local",
                    "updated_at": "2026-06-06T00:00:00.000Z",
                    "receipt_refs": ["receipt_agent"]
                }
            }
        }))
        .expect("runtime agent-state commit bridge request");

        let error = commit_runtime_agent_state(request)
            .expect_err("runtime Agentgres commit must reject StepModule bridge schema");
        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_storage_backend_write_through_rust_core() {
        let request: StorageBackendWriteBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_storage_backend_write",
            "backend": "rust_agentgres_storage",
            "request": {
                "schema_version": "ioi.storage_backend_write_admission.v1",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "object_ref": "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
                "content_hash": "sha256:runtime-state-write",
                "artifact_refs": [],
                "payload_refs": ["payload://runtime/runs/run_1/records/runs/run_1.json"],
                "receipt_refs": ["receipt_policy"]
            }
        }))
        .expect("storage write bridge request");

        let response = admit_storage_backend_write(request).expect("storage write admitted");

        assert_eq!(
            response["source"],
            "rust_agentgres_storage_write_admission_command"
        );
        assert_eq!(response["backend"], "rust_agentgres_storage");
        assert_eq!(
            response["record"]["storage_backend_ref"],
            "storage://runtime-agentgres/local-json"
        );
        assert_eq!(
            response["object_ref"],
            "agentgres://runtime-state/runs/run_1/records/runs/run_1.json"
        );
        assert!(response["admission_hash"]
            .as_str()
            .expect("admission hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_storage_write_admission"));
    }

    #[test]
    fn bridge_commits_runtime_run_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        fs::create_dir_all(state_dir.join("tasks")).expect("tasks dir");
        fs::write(
            state_dir.join("tasks/run_1.json"),
            serde_json::to_string_pretty(&json!({
                "runId": "run_1",
                "agentgresTransition": {
                    "state_root_after": "sha256:previous-state-root",
                    "resulting_head": "agentgres://runtime-state/runs/run_1/head/previous"
                }
            }))
            .expect("previous transition"),
        )
        .expect("previous transition file");
        let request: RuntimeRunStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_run_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_run_state_commit.v1",
                "run_id": "run_1",
                "operation_kind": "run.cancel",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "run": {
                    "id": "run_1",
                    "agentId": "agent_1",
                    "status": "canceled",
                    "mode": "send",
                    "objective": "Ship the runtime state slice",
                    "createdAt": "2026-06-04T00:00:00.000Z",
                    "updatedAt": "2026-06-04T00:00:01.000Z",
                    "events": [
                        { "type": "started" },
                        { "type": "canceled" }
                    ],
                    "receipts": [
                        {
                            "id": "receipt_cancel",
                            "kind": "run_cancel"
                        }
                    ],
                    "artifacts": [],
                    "trace": {
                        "traceBundleId": "trace_bundle_1",
                        "taskState": {
                            "state": "canceled"
                        },
                        "postconditions": [],
                        "semanticImpact": {
                            "impact": "local"
                        },
                        "stopCondition": {
                            "reason": "operator_cancel"
                        },
                        "scorecard": {
                            "score": 1
                        },
                        "qualityLedger": {
                            "entries": []
                        }
                    }
                },
                "agent": {
                    "id": "agent_1",
                    "status": "active",
                    "runtime": "local",
                    "updatedAt": "2026-06-04T00:00:01.000Z"
                },
                "canonical_projection": {
                    "runId": "run_1",
                    "projection": "canonical"
                }
            }
        }))
        .expect("runtime run-state commit bridge request");

        let response = commit_runtime_run_state(request).expect("run state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_run_state_commit_command"
        );
        assert_eq!(
            response["transition"]["expected_heads"][0],
            "agentgres://runtime-state/runs/run_1/head/previous"
        );
        assert_eq!(
            response["transition"]["state_root_before"],
            "sha256:previous-state-root"
        );
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("tasks/run_1.json").exists());
        assert!(state_dir.join("agents/agent_1.json").exists());
        let agent_record =
            fs::read_to_string(state_dir.join("agents/agent_1.json")).expect("agent record");
        assert!(agent_record.contains("\"id\": \"agent_1\""));
        let task_record =
            fs::read_to_string(state_dir.join("tasks/run_1.json")).expect("task record");
        assert!(task_record.contains("\"agentgresTransition\""));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_run_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_agent_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeAgentStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_agent_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_agent_state_commit.v1",
                "agent_id": "agent_1",
                "operation_kind": "agent.create",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "agent": {
                    "id": "agent_1",
                    "status": "active",
                    "runtime": "local",
                    "updated_at": "2026-06-06T00:00:00.000Z",
                    "receipt_refs": ["receipt_agent"]
                }
            }
        }))
        .expect("runtime agent-state commit bridge request");

        let response = commit_runtime_agent_state(request).expect("agent state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_agent_state_commit_command"
        );
        assert_eq!(response["agent_id"], "agent_1");
        assert_eq!(response["operation_kind"], "agent.create");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("agents/agent_1.json").exists());
        let agent_record =
            fs::read_to_string(state_dir.join("agents/agent_1.json")).expect("agent record");
        assert!(agent_record.contains("\"id\": \"agent_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/agents/agent_1/records/agents/agent_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_agent_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_memory_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeMemoryStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_memory_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_memory_state_commit.v1",
                "memory_state_kind": "record",
                "state_id": "memory_1",
                "operation_kind": "memory.write",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "payload": {
                    "schemaVersion": "ioi.agent-runtime.memory.v1",
                    "id": "memory_1",
                    "object": "ioi.agent_memory_record",
                    "fact": "Remember the launch checklist.",
                    "threadId": "thread_1",
                    "agentId": "agent_1",
                    "receipt_refs": ["receipt_memory"]
                }
            }
        }))
        .expect("runtime memory-state commit bridge request");

        let response = commit_runtime_memory_state(request).expect("memory state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_memory_state_commit_command"
        );
        assert_eq!(response["memory_state_kind"], "record");
        assert_eq!(response["state_id"], "memory_1");
        assert_eq!(response["operation_kind"], "memory.write");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("memory-records/memory_1.json").exists());
        let memory_record = fs::read_to_string(state_dir.join("memory-records/memory_1.json"))
            .expect("memory record");
        assert!(memory_record.contains("\"id\": \"memory_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/memory/record/memory_1/records/memory-records/memory_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_memory_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_subagent_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeSubagentStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_subagent_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_subagent_state_commit.v1",
                "subagent_id": "subagent_1",
                "operation_kind": "subagent.wait",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "subagent": {
                    "subagent_id": "subagent_1",
                    "parent_thread_id": "thread_1",
                    "agent_id": "agent_1",
                    "role": "research",
                    "lifecycle_status": "completed",
                    "updated_at": "2026-06-06T00:00:00.000Z",
                    "receipt_refs": ["receipt_subagent"]
                }
            }
        }))
        .expect("runtime subagent-state commit bridge request");

        let response = commit_runtime_subagent_state(request).expect("subagent state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_subagent_state_commit_command"
        );
        assert_eq!(response["subagent_id"], "subagent_1");
        assert_eq!(response["operation_kind"], "subagent.wait");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("subagents/subagent_1.json").exists());
        let subagent_record = fs::read_to_string(state_dir.join("subagents/subagent_1.json"))
            .expect("subagent record");
        assert!(subagent_record.contains("\"subagent_id\": \"subagent_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/subagents/subagent_1/records/subagents/subagent_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_subagent_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_artifact_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeArtifactStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_artifact_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_artifact_state_commit.v1",
                "artifact_id": "artifact_1",
                "operation_kind": "artifact.coding_tool_draft",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "artifact": {
                    "schema_version": "ioi.runtime.coding-tool-artifact.v1",
                    "id": "artifact_1",
                    "thread_id": "thread_1",
                    "tool_name": "file.read",
                    "tool_call_id": "tool_call_1",
                    "channel": "stdout",
                    "media_type": "text/plain",
                    "receipt_id": "receipt_artifact",
                    "content": "hello",
                    "content_bytes": 5,
                    "content_hash": "sha256:content"
                }
            }
        }))
        .expect("runtime artifact-state commit bridge request");

        let response = commit_runtime_artifact_state(request).expect("artifact state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_artifact_state_commit_command"
        );
        assert_eq!(response["artifact_id"], "artifact_1");
        assert_eq!(response["operation_kind"], "artifact.coding_tool_draft");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("artifacts/artifact_1.json").exists());
        let artifact_record = fs::read_to_string(state_dir.join("artifacts/artifact_1.json"))
            .expect("artifact record");
        assert!(artifact_record.contains("\"id\": \"artifact_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/artifacts/artifact_1/records/artifacts/artifact_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_artifact_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_model_mount_record_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeModelMountRecordStateCommitBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "commit_runtime_model_mount_record_state",
                "backend": "rust_agentgres_storage",
                "state_dir": state_dir,
                "request": {
                    "schema_version": "ioi.runtime_model_mount_record_state_commit.v1",
                    "record_dir": "provider-health",
                    "record_id": "health.provider_openai",
                    "operation_kind": "model_mount.provider_health.write",
                    "storage_backend_ref": "storage://runtime-agentgres/local-json",
                    "record": {
                        "id": "health.provider_openai",
                        "provider_id": "provider.openai",
                        "status": "available",
                        "checked_at": "2026-06-04T00:00:00.000Z",
                        "receipt_id": "receipt_provider_health",
                        "evidence_refs": ["provider_http_health"]
                    }
                }
            }))
            .expect("runtime model-mount record-state commit bridge request");

        let response =
            commit_runtime_model_mount_record_state(request).expect("model-mount record committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_model_mount_record_state_commit_command"
        );
        assert_eq!(response["record_dir"], "provider-health");
        assert_eq!(response["record_id"], "health.provider_openai");
        assert_eq!(
            response["operation_kind"],
            "model_mount.provider_health.write"
        );
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir
            .join("provider-health/health.provider_openai.json")
            .exists());
        let health_record =
            fs::read_to_string(state_dir.join("provider-health/health.provider_openai.json"))
                .expect("provider health record");
        assert!(health_record.contains("\"id\": \"health.provider_openai\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_model_mount_record_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_model_mount_receipt_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeModelMountReceiptStateCommitBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "commit_runtime_model_mount_receipt_state",
                "backend": "rust_agentgres_storage",
                "state_dir": state_dir,
                "request": {
                    "schema_version": "ioi.runtime_model_mount_receipt_state_commit.v1",
                    "receipt_id": "receipt_model_invocation",
                    "operation_kind": "model_mount.receipt.write",
                    "storage_backend_ref": "storage://runtime-agentgres/local-json",
                    "receipt": {
                        "id": "receipt_model_invocation",
                        "kind": "model_invocation",
                        "redaction": "redacted",
                        "evidenceRefs": ["rust_receipt_binder_core", "rust_agentgres_admission"],
                        "details": {
                            "model_mount_receipt_binding_ref": "sha256:binding",
                            "model_mount_accepted_receipt_append_hash": "sha256:append",
                            "model_mount_agentgres_operation_ref": "agentgres://model-mounting/accepted-receipts/op_1",
                            "model_mount_agentgres_admission_hash": "sha256:agentgres"
                        }
                    }
                }
            }))
            .expect("runtime model-mount receipt-state commit bridge request");

        let response = commit_runtime_model_mount_receipt_state(request)
            .expect("model-mount receipt committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_model_mount_receipt_state_commit_command"
        );
        assert_eq!(response["receipt_id"], "receipt_model_invocation");
        assert_eq!(response["operation_kind"], "model_mount.receipt.write");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir
            .join("receipts/receipt_model_invocation.json")
            .exists());
        let receipt_record =
            fs::read_to_string(state_dir.join("receipts/receipt_model_invocation.json"))
                .expect("model-mount receipt record");
        assert!(receipt_record.contains("\"id\": \"receipt_model_invocation\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_model_mount_receipt_state_commit"));
    }

    #[test]
    fn workspace_status_reads_git_porcelain_status() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        run_test_git(&workspace, &["init"]);
        run_test_git(&workspace, &["config", "user.email", "test@example.com"]);
        run_test_git(&workspace, &["config", "user.name", "IOI Test"]);
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        run_test_git(&workspace, &["add", "README.md"]);
        run_test_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "after\n").expect("updated file");
        fs::write(workspace.join("new.txt"), "new\n").expect("new file");

        let result = inspect_workspace_status(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "includeIgnored": true
            }),
        )
        .expect("status result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["git"]["available"], true);
        assert!(
            result["git"]["branch"]
                .as_str()
                .expect("branch")
                .contains("main")
                || result["git"]["branch"]
                    .as_str()
                    .expect("branch")
                    .contains("master")
        );
        assert!(result["changedFiles"]
            .as_array()
            .expect("changed files")
            .iter()
            .any(|entry| entry["path"] == "README.md"));
        assert!(result["changedFiles"]
            .as_array()
            .expect("changed files")
            .iter()
            .any(|entry| entry["path"] == "new.txt" && entry["status"] == "??"));
        assert_eq!(result["counts"]["changed"], 2);
        assert_eq!(result["counts"]["untracked"], 1);
        assert_eq!(
            result["git"]["porcelainHash"].as_str().expect("hash").len(),
            64
        );
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn workspace_status_reports_not_git_repository_without_failing_step() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let result = inspect_workspace_status(workspace.to_str().expect("utf8 path"), &json!({}))
            .expect("status result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["git"]["available"], false);
        assert_eq!(result["git"]["status"], "not_git_repository");
        assert_eq!(result["changedFiles"], json!([]));
        assert_eq!(result["counts"]["changed"], 0);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn test_run_node_test_reports_passed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(
            workspace.join("passing.test.mjs"),
            "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('passes', () => assert.equal(1, 1));\n",
        )
        .expect("fixture file");

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.test",
                "path": "passing.test.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("test result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["commandId"], "node.test");
        assert_eq!(result["command"], "node --test");
        assert_eq!(result["args"], json!(["--test", "passing.test.mjs"]));
        assert_eq!(result["testStatus"], "passed");
        assert_eq!(result["exitCode"], 0);
        assert_eq!(result["timedOut"], false);
        assert_eq!(result["shellFallbackUsed"], false);
        assert_eq!(result["outputHash"].as_str().expect("hash").len(), 64);
    }

    #[test]
    fn test_run_node_test_reports_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(
            workspace.join("failing.test.mjs"),
            "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('fails', () => assert.equal(1, 2));\n",
        )
        .expect("fixture file");

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.test",
                "path": "failing.test.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("test result");

        assert_eq!(result["commandId"], "node.test");
        assert_eq!(result["testStatus"], "failed");
        assert_ne!(result["exitCode"], 0);
        assert_eq!(result["timedOut"], false);
    }

    #[cfg(unix)]
    #[test]
    fn test_run_npm_test_uses_sanitized_env_and_extra_args() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let bin = temp.path().join("bin");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::create_dir(&bin).expect("bin dir");
        write_fake_executable(
            &bin.join("npm"),
            "#!/bin/sh\nif [ -n \"$SECRET_TOKEN\" ]; then exit 7; fi\nif [ -n \"$NODE_TEST_CONTEXT\" ]; then exit 8; fi\necho fake npm \"$@\"\n",
        );
        let path_env = format!(
            "{}:{}",
            bin.to_string_lossy(),
            std::env::var("PATH").unwrap_or_default()
        );

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "npm.test",
                "args": ["--", "unit"],
                "timeoutMs": 5000,
                "env": {
                    "PATH": path_env,
                    "SECRET_TOKEN": "must-not-leak",
                    "NODE_TEST_CONTEXT": "must-not-leak"
                }
            }),
        )
        .expect("test result");

        assert_eq!(result["commandId"], "npm.test");
        assert_eq!(result["command"], "npm test");
        assert_eq!(result["executable"], "npm");
        assert_eq!(result["args"], json!(["test", "--", "unit"]));
        assert_eq!(result["testStatus"], "passed");
        assert!(result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("fake npm test -- unit"));
    }

    #[cfg(unix)]
    #[test]
    fn test_run_cargo_backends_use_rust_live_command_mapping() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let bin = temp.path().join("bin");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::create_dir(&bin).expect("bin dir");
        write_fake_executable(
            &bin.join("cargo"),
            "#!/bin/sh\nif [ -n \"$SECRET_TOKEN\" ]; then exit 7; fi\necho fake cargo \"$@\"\n",
        );
        let path_env = format!(
            "{}:{}",
            bin.to_string_lossy(),
            std::env::var("PATH").unwrap_or_default()
        );

        let check_result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "cargo.check",
                "timeoutMs": 5000,
                "env": {
                    "PATH": path_env,
                    "SECRET_TOKEN": "must-not-leak"
                }
            }),
        )
        .expect("cargo check result");
        let test_result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "cargo.test",
                "timeoutMs": 5000,
                "env": {
                    "PATH": path_env,
                    "SECRET_TOKEN": "must-not-leak"
                }
            }),
        )
        .expect("cargo test result");

        assert_eq!(check_result["command"], "cargo check");
        assert_eq!(check_result["args"], json!(["check"]));
        assert_eq!(check_result["testStatus"], "passed");
        assert!(check_result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("fake cargo check"));
        assert_eq!(test_result["command"], "cargo test");
        assert_eq!(test_result["args"], json!(["test"]));
        assert_eq!(test_result["testStatus"], "passed");
        assert!(test_result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("fake cargo test"));
    }

    #[test]
    fn test_run_disallowed_command_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let error = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "python.test"
            }),
        )
        .expect_err("unknown command should fail closed");

        assert_eq!(error.code, "test_run_command_not_allowed");
    }

    #[test]
    fn file_apply_patch_writes_and_binds_agentgres_admission() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        let request = bridge_request(
            "file.apply_patch",
            workspace.to_str().expect("utf8 path"),
            json!({
                "path": "README.md",
                "oldText": "before",
                "newText": "after"
            }),
        );

        let response = file_apply_patch_response(request).expect("patch response");

        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).expect("updated file"),
            "after\n"
        );
        assert_eq!(response["workload_observation"]["result"]["applied"], true);
        assert_eq!(response["workload_observation"]["result"]["changed"], true);
        assert_eq!(
            response["router_admission"]["authoritative_transition"],
            true
        );
        assert_eq!(
            response["workload_dispatch"]["schema_version"],
            WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION,
        );
        assert_eq!(
            response["workload_dispatch"]["module_ref"],
            "file.apply_patch"
        );
        assert_eq!(response["workload_dispatch"]["transport"], "workload_grpc");
        assert!(response["workload_dispatch"]["evidence_refs"]
            .as_array()
            .expect("workload dispatch evidence")
            .iter()
            .any(|value| value == "rust_workload_client_step_module_dispatch"));
        assert!(response["result"]["workflow_projection"]["evidence_refs"]
            .as_array()
            .expect("projection evidence")
            .iter()
            .any(|value| value == "rust_workload_client_step_module_dispatch"));
        assert_eq!(
            response["result"]["agentgres_operation_refs"][0],
            response["agentgres_admission"]["operation_ref"],
        );
        assert!(response["result"]["state_root_after"]
            .as_str()
            .expect("state root")
            .starts_with("state://workspace/"));
        assert!(response["receipt_binding"]["expected_heads"]
            .as_array()
            .expect("expected heads")
            .first()
            .and_then(Value::as_str)
            .expect("expected head")
            .starts_with("head://workspace/"));
        assert_eq!(
            response["agentgres_admission"]["state_root_after"],
            response["result"]["state_root_after"],
        );
        assert_eq!(
            response["projection_record"]["status"],
            response["result"]["workflow_projection"]["status"],
        );
    }

    #[test]
    fn file_apply_patch_dry_run_has_no_agentgres_transition() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        let request = bridge_request(
            "file.apply_patch",
            workspace.to_str().expect("utf8 path"),
            json!({
                "path": "README.md",
                "oldText": "before",
                "newText": "after",
                "dryRun": true
            }),
        );

        let response = file_apply_patch_response(request).expect("patch response");

        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).expect("original file"),
            "before\n"
        );
        assert_eq!(response["workload_observation"]["result"]["applied"], false);
        assert_eq!(response["workload_observation"]["result"]["changed"], true);
        assert_eq!(
            response["router_admission"]["authoritative_transition"],
            true
        );
        assert_eq!(response["result"]["agentgres_operation_refs"], json!([]));
        assert_eq!(response["agentgres_admission"], Value::Null);
        assert_eq!(response["result"]["state_root_after"], Value::Null);
    }

    #[test]
    fn artifact_read_uses_prefetched_data_plane_payload() {
        let request = bridge_request(
            "artifact.read",
            "/tmp",
            json!({
                "artifactId": "artifact_alpha",
                "rustWorkloadDataPlane": {
                    "schemaVersion": "ioi.runtime.coding-tool-data-plane.v1",
                    "source": "daemon_artifact_store",
                    "operation": "artifact.read",
                    "artifactId": "artifact_alpha",
                    "result": {
                        "schemaVersion": "ioi.runtime.coding-tool-result.v1",
                        "artifactId": "artifact_alpha",
                        "artifactRef": "artifact_alpha",
                        "artifactRefs": ["artifact_alpha"],
                        "content": "hello artifact\n",
                        "contentHash": "prefetch-hash",
                        "fullContentHash": "full-hash",
                        "offsetBytes": 0,
                        "lengthBytes": 15,
                        "totalBytes": 15,
                        "truncated": false,
                        "receiptRefs": ["receipt_artifact_prefetch"],
                        "shellFallbackUsed": true
                    }
                }
            }),
        );

        let response = artifact_read_response(request).expect("artifact read response");

        assert_eq!(
            response["workload_observation"]["result"]["backend"],
            "rust_artifact_read"
        );
        assert_eq!(
            response["workload_observation"]["result"]["dataPlaneSource"],
            "daemon_artifact_store"
        );
        assert_eq!(
            response["workload_observation"]["result"]["shellFallbackUsed"],
            false
        );
        assert_eq!(
            response["workload_observation"]["result"]["contentHash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        assert_ne!(
            response["workload_observation"]["result"]["contentHash"],
            "prefetch-hash"
        );
        assert_eq!(
            response["result"]["artifact_refs"],
            json!(["artifact_alpha"])
        );
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| value == "receipt_artifact_prefetch"));
        assert_eq!(response["agentgres_admission"], Value::Null);
        assert_eq!(
            response["projection_record"]["status"],
            response["result"]["workflow_projection"]["status"],
        );
    }

    #[test]
    fn tool_retrieve_result_uses_prefetched_data_plane_payload() {
        let request = bridge_request(
            "tool.retrieve_result",
            "/tmp",
            json!({
                "toolCallId": "tool_patch",
                "channel": "stdout",
                "rustWorkloadDataPlane": {
                    "schemaVersion": "ioi.runtime.coding-tool-data-plane.v1",
                    "source": "daemon_artifact_store",
                    "operation": "tool.retrieve_result",
                    "query": {
                        "toolCallId": "tool_patch",
                        "channel": "stdout"
                    },
                    "result": {
                        "schemaVersion": "ioi.runtime.coding-tool-result.v1",
                        "toolCallId": "tool_patch",
                        "artifactId": "artifact_result",
                        "artifactRef": "artifact_result",
                        "artifactRefs": ["artifact_result"],
                        "channel": "stdout",
                        "content": "stored stdout\n",
                        "contentHash": "prefetch-hash",
                        "fullContentHash": "full-hash",
                        "availableArtifacts": [{
                            "artifactId": "artifact_result",
                            "channel": "stdout"
                        }],
                        "receiptRefs": ["receipt_tool_result_prefetch"],
                        "shellFallbackUsed": true
                    }
                }
            }),
        );

        let response = tool_retrieve_result_response(request).expect("retrieve response");

        assert_eq!(
            response["workload_observation"]["result"]["backend"],
            "rust_tool_result_retrieve"
        );
        assert_eq!(
            response["workload_observation"]["result"]["toolCallId"],
            "tool_patch"
        );
        assert_eq!(
            response["workload_observation"]["result"]["contentHash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        assert_eq!(
            response["result"]["artifact_refs"],
            json!(["artifact_result"])
        );
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| value == "receipt_tool_result_prefetch"));
        assert_eq!(response["agentgres_admission"], Value::Null);
    }

    #[test]
    fn artifact_read_requires_prefetched_data_plane_payload() {
        let request = bridge_request(
            "artifact.read",
            "/tmp",
            json!({
                "artifactId": "artifact_alpha"
            }),
        );

        let error = artifact_read_response(request).expect_err("missing payload should fail");

        assert_eq!(error.code, "data_plane_payload_required");
    }

    #[test]
    fn computer_use_request_lease_records_wallet_gated_act_request() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Open the browser and click the sign in button.",
                "lane": "native_browser",
                "session_mode": "controlled_relaunch",
                "action_kind": "click",
                "url": "https://example.test"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["lane"],
            "native_browser"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.act"
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            true
        );
        assert_eq!(
            response["workload_observation"]["result"]["wallet_network_authority_boundary"]
                ["authority_layer"],
            "wallet.network"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.native_browser"
        );
        assert!(response["workload_observation"]["result"]["request_ref"]
            .as_str()
            .expect("request ref")
            .starts_with("computer_use_lease_request_"));
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| {
                value
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("receipt_computer_use_lease_request_")
            }));
        assert_eq!(response["agentgres_admission"], Value::Null);
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_lane_alias() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the lane through a retired alias.",
                "computerUseLane": "sandboxed_hosted",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["lane"],
            "native_browser"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.native_browser"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_action_kind_alias() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to escalate authority through a retired action alias.",
                "lane": "native_browser",
                "actionKind": "click"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["action_kind"],
            "inspect"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.read"
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            false
        );
        assert_eq!(
            response["workload_observation"]["result"]["wallet_network_authority_boundary"]
                ["required_before_execution"],
            false
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_approval_alias() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to satisfy approval through a retired alias.",
                "lane": "native_browser",
                "action_kind": "click",
                "approvalRef": "approval_legacy"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.act"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["approval_ref"],
            Value::Null
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            true
        );
        assert_eq!(
            response["workload_observation"]["result"]["wallet_network_authority_boundary"]
                ["required_before_execution"],
            true
        );
    }

    #[test]
    fn computer_use_request_lease_records_unavailable_provider_fail_closed() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Open a hosted sandbox.",
                "lane": "sandboxed_hosted",
                "session_mode": "hosted_sandbox",
                "sandbox_provider": "local_container",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["provider_id"],
            "ioi.computer_use.sandboxed_hosted.local_container"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            Value::Null
        );
        assert!(
            response["workload_observation"]["result"]["thread_tool"]["unavailable_reason"]
                .as_str()
                .expect("unavailable reason")
                .contains("no container runtime adapter")
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            false
        );
        assert_eq!(response["agentgres_admission"], Value::Null);
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_provider_aliases() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the provider through retired aliases.",
                "lane": "sandboxed_hosted",
                "session_mode": "local_sandbox",
                "sandboxProvider": "local_container",
                "providerKind": "local_container",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["provider_id"],
            "ioi.computer_use.sandboxed_hosted.local_fixture"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["provider_kind"],
            "local_fixture"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.sandboxed_hosted"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["unavailable_reason"],
            Value::Null
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_target_ref_alias() {
        let retired_alias_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the target through a retired alias.",
                "lane": "native_browser",
                "action_kind": "inspect",
                "targetRef": "target_retired"
            }),
        );
        let baseline_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the target through a retired alias.",
                "lane": "native_browser",
                "action_kind": "inspect"
            }),
        );

        let retired_alias_response = computer_use_request_lease_response(retired_alias_request)
            .expect("retired alias lease request response");
        let baseline_response =
            computer_use_request_lease_response(baseline_request).expect("baseline response");

        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["request_ref"],
            baseline_response["workload_observation"]["result"]["request_ref"]
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["target_ref"],
            Value::Null
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["lease_request"]
                ["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_session_mode_alias() {
        let retired_alias_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the session mode through a retired alias.",
                "lane": "sandboxed_hosted",
                "sessionMode": "hosted_sandbox",
                "action_kind": "inspect"
            }),
        );
        let baseline_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the session mode through a retired alias.",
                "lane": "sandboxed_hosted",
                "action_kind": "inspect"
            }),
        );

        let retired_alias_response = computer_use_request_lease_response(retired_alias_request)
            .expect("retired alias lease request response");
        let baseline_response =
            computer_use_request_lease_response(baseline_request).expect("baseline response");

        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["request_ref"],
            baseline_response["workload_observation"]["result"]["request_ref"]
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["lease_request"]
                ["session_mode"],
            "local_sandbox"
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["session_mode"],
            "local_sandbox"
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.sandboxed_hosted"
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_observation_retention_alias() {
        let retired_alias_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer retention through a retired alias.",
                "lane": "native_browser",
                "action_kind": "inspect",
                "observationRetentionMode": "local_raw_artifacts"
            }),
        );
        let canonical_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Use canonical retention.",
                "lane": "native_browser",
                "action_kind": "inspect",
                "observation_retention_mode": "local_raw_artifacts"
            }),
        );

        let retired_alias_response = computer_use_request_lease_response(retired_alias_request)
            .expect("retired alias lease request response");
        let canonical_response =
            computer_use_request_lease_response(canonical_request).expect("canonical response");

        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["observation_retention_mode"],
            "prompt_visible_summary_only"
        );
        assert_eq!(
            canonical_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["observation_retention_mode"],
            "local_raw_artifacts"
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["lease_request"]
                ["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn computer_use_request_lease_binds_canonical_receipt_and_request_refs() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Bind canonical computer-use refs.",
                "lane": "native_browser",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");
        let workload_result = &response["workload_observation"]["result"];
        let canonical_receipt_ref = workload_result["receipt_refs"][0]
            .as_str()
            .expect("canonical receipt ref");
        let canonical_request_ref = workload_result["request_ref"]
            .as_str()
            .expect("canonical request ref");
        let evidence_ref =
            format!("evidence://rust-workload/computer_use.request_lease/{canonical_request_ref}");

        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("result receipt refs")
            .iter()
            .any(|value| value == canonical_receipt_ref));
        assert!(response["result"]["workflow_projection"]["evidence_refs"]
            .as_array()
            .expect("projection evidence refs")
            .iter()
            .any(|value| value == &evidence_ref));
        for retired_field in [
            "schemaVersion",
            "requestRef",
            "workspaceRoot",
            "leaseRequest",
            "threadTool",
            "providerRegistry",
            "approvalRequiredBeforeExecution",
            "walletNetworkAuthorityBoundary",
            "evidenceRefs",
            "receiptRefs",
            "shellFallbackUsed",
        ] {
            assert!(
                workload_result.get(retired_field).is_none(),
                "retired workload result field {retired_field} must not be emitted"
            );
        }
        for retired_field in [
            "sessionMode",
            "actionKind",
            "authorityScope",
            "repoAuthorityScope",
            "sharedClipboardPolicy",
            "artifactPolicy",
            "approvalRef",
            "failClosedWhenUnavailable",
            "providerId",
            "providerKind",
            "walletNetworkAuthorityRequiredBeforeExecution",
        ] {
            assert!(
                workload_result["lease_request"]
                    .get(retired_field)
                    .is_none(),
                "retired lease_request field {retired_field} must not be emitted"
            );
        }
        for retired_field in ["toolPack", "toolName", "unavailableReason"] {
            assert!(
                workload_result["thread_tool"].get(retired_field).is_none(),
                "retired thread_tool field {retired_field} must not be emitted"
            );
        }
        for retired_field in [
            "actionKind",
            "sessionMode",
            "targetRef",
            "approvalRef",
            "observationRetentionMode",
        ] {
            assert!(
                workload_result["thread_tool"]["input"]
                    .get(retired_field)
                    .is_none(),
                "retired thread_tool input field {retired_field} must not be emitted"
            );
        }
    }

    #[test]
    fn lsp_diagnostics_node_check_reports_clean_javascript() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("ok.mjs"), "const value = 1;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.check",
                "path": "ok.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["resolvedCommandId"], "node.check");
        assert_eq!(result["diagnosticStatus"], "clean");
        assert_eq!(result["diagnosticCount"], 0);
        assert_eq!(result["paths"], json!(["ok.mjs"]));
        assert_eq!(result["exitCode"], 0);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn lsp_diagnostics_node_check_reports_syntax_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("broken.mjs"), "const = ;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.check",
                "path": "broken.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["diagnosticStatus"], "findings");
        assert_eq!(result["diagnosticCount"], 1);
        assert_ne!(result["exitCode"], 0);
        assert_eq!(result["diagnostics"][0]["path"], "broken.mjs");
        assert_eq!(result["diagnostics"][0]["severity"], "error");
    }

    #[test]
    fn lsp_diagnostics_auto_routes_javascript_to_node_check() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("ok.mjs"), "const value = 1;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "auto",
                "path": "ok.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["resolvedCommandId"], "node.check");
        assert_eq!(result["diagnosticStatus"], "clean");
        assert_eq!(result["fallbackUsed"], false);
    }

    #[cfg(unix)]
    #[test]
    fn lsp_diagnostics_typescript_check_reports_tsc_diagnostic() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let source_dir = workspace.join("src");
        let bin = workspace.join("node_modules").join(".bin");
        fs::create_dir_all(&source_dir).expect("source dir");
        fs::create_dir_all(&bin).expect("bin dir");
        fs::write(
            workspace.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}"#,
        )
        .expect("tsconfig");
        fs::write(
            source_dir.join("broken.ts"),
            "const value: number = 'oops';\n",
        )
        .expect("ts fixture");
        write_fake_executable(
            &bin.join("tsc"),
            "#!/bin/sh\necho \"src/broken.ts(1,7): error TS2322: Type 'string' is not assignable to type 'number'.\"\nexit 2\n",
        );

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "typescript.check",
                "path": "src/broken.ts",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "typescript.project.check");
        assert_eq!(result["resolvedCommandId"], "typescript.check");
        assert_eq!(
            result["command"],
            "tsc --noEmit --pretty false -p tsconfig.json"
        );
        assert_eq!(result["backendStatus"], "available");
        assert_eq!(result["diagnosticStatus"], "findings");
        assert_eq!(result["diagnosticCount"], 1);
        assert_eq!(result["diagnostics"][0]["path"], "src/broken.ts");
        assert_eq!(result["diagnostics"][0]["code"], "TS2322");
        assert_eq!(result["diagnostics"][0]["line"], 1);
        assert_eq!(result["diagnostics"][0]["column"], 7);
        assert_eq!(result["projectContext"]["tsconfigPath"], "tsconfig.json");
        assert_eq!(result["projectContext"]["tscAvailable"], true);
    }

    #[test]
    fn lsp_diagnostics_auto_typescript_degrades_without_local_tsc() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let source_dir = workspace.join("src");
        fs::create_dir_all(&source_dir).expect("source dir");
        fs::write(
            workspace.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}"#,
        )
        .expect("tsconfig");
        fs::write(
            source_dir.join("broken.ts"),
            "const value: number = 'oops';\n",
        )
        .expect("ts fixture");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "auto",
                "path": "src/broken.ts",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "typescript.project.check");
        assert_eq!(result["resolvedCommandId"], "typescript.check");
        assert_eq!(result["backendStatus"], "degraded");
        assert_eq!(result["backendReason"], "typescript_executable_missing");
        assert_eq!(result["diagnosticStatus"], "degraded");
        assert_eq!(result["projectContext"]["tscAvailable"], false);
        assert_eq!(result["fallbackUsed"], false);
    }

    #[test]
    fn git_diff_reads_bounded_workspace_diff() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        run_test_git(&workspace, &["init"]);
        run_test_git(&workspace, &["config", "user.email", "test@example.com"]);
        run_test_git(&workspace, &["config", "user.name", "IOI Test"]);
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        run_test_git(&workspace, &["add", "README.md"]);
        run_test_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "before\nafter\n").expect("updated file");

        let result = inspect_git_diff(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "path": "README.md",
                "maxBytes": 4096
            }),
        )
        .expect("diff result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["paths"], json!(["README.md"]));
        assert_eq!(result["git"]["available"], true);
        assert!(result["diff"].as_str().expect("diff").contains("+after"));
        assert!(result["stat"].as_str().expect("stat").contains("README.md"));
        assert_eq!(result["diffHash"].as_str().expect("hash").len(), 64);
        assert_eq!(result["truncated"], false);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn git_diff_rejects_paths_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let error = inspect_git_diff(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "path": "../outside.txt"
            }),
        )
        .expect_err("outside path should fail");

        assert_eq!(error.code, "path_outside_workspace");
    }

    #[test]
    fn file_inspect_reads_workspace_file_preview() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "# IOI\nsecond line\n").expect("fixture file");

        let result = inspect_workspace_path(
            workspace.to_str().expect("utf8 path"),
            "README.md",
            &json!({
                "maxBytes": 128,
                "previewLines": 1
            }),
        )
        .expect("inspect result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["path"], "README.md");
        assert_eq!(result["kind"], "file");
        assert_eq!(result["preview"], "# IOI");
        assert_eq!(result["previewLineCount"], 1);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn file_inspect_rejects_paths_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(temp.path().join("outside.txt"), "outside").expect("outside fixture");

        let error = inspect_workspace_path(
            workspace.to_str().expect("utf8 path"),
            "../outside.txt",
            &json!({}),
        )
        .expect_err("outside path should fail");

        assert_eq!(error.code, "path_outside_workspace");
    }

    fn run_test_git(workspace: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn bridge_request(
        tool_id: &str,
        workspace_root: &str,
        input: Value,
    ) -> StepModuleBridgeRequest {
        let invocation = serde_json::from_value(json!({
            "schema_version": "ioi.step_module_invocation.v1",
            "invocation_id": format!("invocation://test/{tool_id}"),
            "run_id": "run:test",
            "task_id": "task:test",
            "thread_id": "thread:test",
            "workflow_graph_id": "graph:test",
            "workflow_node_id": format!("node:test:{tool_id}"),
            "context_chamber_ref": null,
            "action_proposal_ref": format!("action:test:{tool_id}"),
            "gate_result_ref": format!("gate:test:{tool_id}"),
            "module_ref": {
                "kind": "workload_job",
                "id": tool_id,
                "version": "test",
                "manifest_ref": null
            },
            "actor": {
                "actor_id": "runtime:hypervisor-daemon",
                "runtime_node_ref": "node://local"
            },
            "authority": {
                "authority_grant_refs": [],
                "policy_hash": "sha256:policy",
                "primitive_capabilities": ["prim:fs.apply_patch", "prim:fs.write"],
                "authority_scopes": ["scope:workspace.write"],
                "approval_ref": "approval:test"
            },
            "input": {
                "input_hash": "sha256:input",
                "expected_schema_ref": format!("schema://coding-tool/{tool_id}/input"),
                "context_refs": [],
                "artifact_refs": [],
                "payload_refs": [],
                "state_root_before": null,
                "projection_watermark": null,
                "data_plane_handle": null
            },
            "custody": {
                "privacy_profile": "internal",
                "plaintext_policy": {
                    "node_plaintext_allowed": true,
                    "declassification_required": false
                },
                "custody_proof_ref": null,
                "leakage_profile_ref": null
            },
            "execution": {
                "backend": "workload_grpc",
                "idempotency_key": format!("idempotency:test:{tool_id}"),
                "deadline_ms": 60000,
                "resource_lease_ref": null,
                "retry_policy_ref": null
            }
        }))
        .expect("test invocation");
        StepModuleBridgeRequest {
            schema_version: COMMAND_SCHEMA_VERSION.to_string(),
            operation: "run_coding_tool_step_module".to_string(),
            backend: "rust_workload_live".to_string(),
            invocation,
            workspace_root: Some(workspace_root.to_string()),
            input,
        }
    }

    #[cfg(unix)]
    fn write_fake_executable(path: &Path, content: &str) {
        fs::write(path, content).expect("fake executable");
        let mut permissions = fs::metadata(path)
            .expect("fake executable metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("fake executable permissions");
    }
}
