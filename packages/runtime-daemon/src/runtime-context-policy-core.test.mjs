import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_BLOCK_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_RECOVERY_CONTROL_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_RESULT_ENVELOPE_PLAN_REQUEST_SCHEMA_VERSION,
  CONTEXT_LIFECYCLE_CODING_TOOL_BUDGET_BLOCK_API_METHOD,
  CONTEXT_LIFECYCLE_CODING_TOOL_BUDGET_POLICY_API_METHOD,
  CONTEXT_LIFECYCLE_COMPACTION_POLICY_API_METHOD,
  CONTEXT_LIFECYCLE_CONTEXT_BUDGET_POLICY_API_METHOD,
  CONTEXT_LIFECYCLE_CONTEXT_COMPACTION_PLAN_API_METHOD,
  CONTEXT_LIFECYCLE_CONTEXT_COMPACTION_STATE_UPDATE_API_METHOD,
  RUNTIME_CONTROL_CODING_TOOL_ARTIFACT_DRAFTS_API_METHOD,
  RUNTIME_CONTROL_CODING_TOOL_BUDGET_RECOVERY_CONTROL_API_METHOD,
  RUNTIME_CONTROL_CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_API_METHOD,
  RUNTIME_CONTROL_CODING_TOOL_RESULT_ENVELOPE_API_METHOD,
  RUNTIME_CONTROL_DIAGNOSTICS_REPAIR_CONTROL_API_METHOD,
  RUNTIME_CONTROL_DIAGNOSTICS_REPAIR_RETRY_RUN_API_METHOD,
  RUNTIME_CONTROL_DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_API_METHOD,
  RUNTIME_CONTROL_DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_API_METHOD,
  RUNTIME_CONTROL_OPERATOR_INTERRUPT_STATE_UPDATE_API_METHOD,
  RUNTIME_CONTROL_OPERATOR_STEER_STATE_UPDATE_API_METHOD,
  RUNTIME_CONTROL_OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_API_METHOD,
  RUNTIME_CONTROL_RUN_CANCEL_STATE_UPDATE_API_METHOD,
  RUNTIME_CONTROL_TASK_JOB_CANCEL_STATE_UPDATE_API_METHOD,
  RUNTIME_CONTROL_TASK_JOB_CREATE_STATE_UPDATE_API_METHOD,
  RUNTIME_CONTROL_WORKFLOW_EDIT_CONTROL_API_METHOD,
  RUNTIME_CONTROL_WORKFLOW_EDIT_ADMISSION_REQUIRED_API_METHOD,
  RUNTIME_CONTROL_MANAGED_SESSION_API_METHOD,
  RUNTIME_CONTROL_WORKSPACE_CHANGE_API_METHOD,
  RUNTIME_CONTROL_THREAD_FORK_API_METHOD,
  RUNTIME_CONTROL_CONVERSATION_ARTIFACT_API_METHOD,
  RUNTIME_CONTROL_SUBAGENT_API_METHOD,
  RUNTIME_CONTROL_POST_EDIT_DIAGNOSTICS_FEEDBACK_API_METHOD,
  RUNTIME_PROJECTION_CODING_TOOL_ARTIFACT_READ_API_METHOD,
  RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_RETRY_RESULT_API_METHOD,
  RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_POLICY_API_METHOD,
  RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_PROJECTION_API_METHOD,
  RUNTIME_PROJECTION_TASK_JOB_API_METHOD,
  RUNTIME_PROJECTION_LIFECYCLE_API_METHOD,
  RUNTIME_PROJECTION_DOCTOR_REPORT_API_METHOD,
  RUNTIME_PROJECTION_COMPUTER_USE_API_METHOD,
  RUNTIME_PROJECTION_STUDIO_INTENT_FRAME_API_METHOD,
  RUNTIME_PROJECTION_MANAGED_SESSION_API_METHOD,
  RUNTIME_PROJECTION_REPOSITORY_WORKFLOW_API_METHOD,
  RUNTIME_PROJECTION_SKILL_HOOK_REGISTRY_API_METHOD,
  RUNTIME_PROJECTION_WORKSPACE_CHANGE_API_METHOD,
  RUNTIME_PROJECTION_CONVERSATION_ARTIFACT_API_METHOD,
  RUNTIME_PROJECTION_SUBAGENT_API_METHOD,
  RUNTIME_PROJECTION_TOOL_CATALOG_API_METHOD,
  THREAD_MEMORY_AGENT_STATE_UPDATE_API_METHOD,
  THREAD_MEMORY_MANAGER_STATUS_PROJECTION_API_METHOD,
  THREAD_MEMORY_MANAGER_VALIDATION_PROJECTION_API_METHOD,
  THREAD_MEMORY_RUNTIME_MEMORY_COMMAND_API_METHOD,
  THREAD_MEMORY_RUNTIME_MEMORY_CONTROL_API_METHOD,
  THREAD_MEMORY_RUNTIME_MEMORY_PROJECTION_API_METHOD,
  THREAD_LIFECYCLE_AGENT_CREATE_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_AGENT_DELETE_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_AGENT_STATUS_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_LIFECYCLE_ADMISSION_REQUIRED_API_METHOD,
  THREAD_LIFECYCLE_RUN_CREATE_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_SUBAGENT_RECORD_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_THREAD_CONTROL_AGENT_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_THREAD_CREATE_STATE_UPDATE_API_METHOD,
  THREAD_LIFECYCLE_THREAD_TURN_ADMISSION_REQUIRED_API_METHOD,
  RUNTIME_CODING_TOOL_ARTIFACT_DRAFT_PLAN_REQUEST_SCHEMA_VERSION,
  RUNTIME_CODING_TOOL_ARTIFACT_READ_PROJECTION_REQUEST_SCHEMA_VERSION,
  COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
  CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  RuntimeContextPolicyCoreError,
  DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RUN_REQUEST_SCHEMA_VERSION,
  RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION,
  DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  MCP_CONTROL_AGENT_STATE_UPDATE_API_METHOD,
  MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  MCP_LIVE_BACKEND_EXECUTION_API_METHOD,
  MCP_LIVE_BACKEND_EXECUTION_REQUEST_SCHEMA_VERSION,
  MCP_LIVE_RESULT_REPLAY_API_METHOD,
  MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_CATALOG_PROJECTION_API_METHOD,
  MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_API_METHOD,
  MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_TOOL_FETCH_PROJECTION_API_METHOD,
  MCP_TOOL_FETCH_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_TOOL_SEARCH_PROJECTION_API_METHOD,
  MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_VALIDATION_PROJECTION_API_METHOD,
  MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_STATUS_PROJECTION_API_METHOD,
  MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_SERVER_VALIDATION_INPUT_API_METHOD,
  MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
  MCP_SERVER_VALIDATION_API_METHOD,
  MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
  MCP_SERVE_TOOL_CALL_PLAN_API_METHOD,
  MCP_SERVE_TOOL_RESULT_PROJECTION_API_METHOD,
  MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
  MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
  OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_REQUEST_SCHEMA_VERSION,
  REPOSITORY_WORKFLOW_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_TOOL_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_LIFECYCLE_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_DOCTOR_REPORT_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_COMPUTER_USE_PROJECTION_REQUEST_SCHEMA_VERSION,
  STUDIO_INTENT_FRAME_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_MEMORY_COMMAND_PLAN_REQUEST_SCHEMA_VERSION,
  RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_MEMORY_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_REQUEST_SCHEMA_VERSION,
  RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_WORKFLOW_EDIT_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_MANAGED_SESSION_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_WORKSPACE_CHANGE_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_WORKSPACE_CHANGE_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_THREAD_FORK_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_CONVERSATION_ARTIFACT_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_SUBAGENT_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_SUBAGENT_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_TASK_JOB_PROJECTION_REQUEST_SCHEMA_VERSION,
  RuntimeContextPolicyCore,
  SKILL_HOOK_REGISTRY_PROJECTION_REQUEST_SCHEMA_VERSION,
  SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  WORKSPACE_TRUST_CONTROL_STATE_UPDATE_API_METHOD,
  WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  WORKFLOW_EDIT_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  createRuntimeContextPolicyCore,
  normalizeAgentCreateStateUpdateApiResult,
  normalizeAgentDeleteStateUpdateApiResult,
  normalizeAgentStatusStateUpdateApiResult,
  normalizeCodingToolBudgetBlockResult,
  normalizeCodingToolBudgetRecoveryStateUpdateApiResult,
  normalizeCodingToolResultEnvelopePlanResult,
  normalizeRuntimeCodingToolArtifactDraftPlanResult,
  normalizeRuntimeCodingToolArtifactReadProjectionResult,
  normalizeCompactionPolicyResult,
  normalizeContextBudgetPolicyResult,
  normalizeContextCompactionPlanResult,
  normalizeContextCompactionStateUpdateResult,
  normalizeDiagnosticsOperatorOverrideStateUpdateApiResult,
  normalizeMcpControlAgentStateUpdateApiResult,
  normalizeMcpLiveBackendExecutionApiResult,
  normalizeMcpManagerCatalogProjectionApiResult,
  normalizeMcpManagerCatalogSummaryProjectionApiResult,
  normalizeMcpManagerStatusProjectionApiResult,
  normalizeMcpManagerValidationProjectionApiResult,
  normalizeMcpToolFetchProjectionApiResult,
  normalizeMcpToolSearchProjectionApiResult,
  normalizeMemoryManagerStatusProjectionResult,
  normalizeMemoryManagerValidationProjectionResult,
  normalizeOperatorInterruptStateUpdateApiResult,
  normalizeOperatorSteerStateUpdateApiResult,
  normalizePostEditDiagnosticsFeedbackPlanResult,
  normalizeRunCancelStateUpdateApiResult,
  normalizeRuntimeTaskJobCancelStateUpdateResult,
  normalizeRuntimeTaskJobCreateStateUpdateResult,
  normalizeRuntimeTaskJobProjectionResult,
  normalizeRuntimeToolCatalogProjectionResult,
  normalizeRuntimeLifecycleProjectionResult,
  normalizeRuntimeDoctorReportProjectionResult,
  normalizeRuntimeComputerUseProjectionResult,
  normalizeStudioIntentFrameProjectionResult,
  normalizeRuntimeMemoryCommandPlanResult,
  normalizeRuntimeMemoryControlResult,
  normalizeRuntimeMcpServeToolCallPlanResult,
  normalizeRuntimeMcpServeToolResultProjectionResult,
  normalizeRuntimeMemoryProjectionResult,
  normalizeRuntimeDiagnosticsRepairProjectionResult,
  normalizeRuntimeDiagnosticsRepairPolicyResult,
  normalizeRuntimeWorkflowEditControlResult,
  normalizeRuntimeManagedSessionControlResult,
  normalizeRuntimeManagedSessionProjectionResult,
  normalizeRuntimeWorkspaceChangeControlResult,
  normalizeRuntimeWorkspaceChangeProjectionResult,
  normalizeRuntimeThreadForkControlResult,
  normalizeRuntimeConversationArtifactControlResult,
  normalizeRuntimeConversationArtifactProjectionResult,
  normalizeRuntimeSubagentControlResult,
  normalizeRuntimeSubagentProjectionResult,
  normalizeRepositoryWorkflowProjectionResult,
  normalizeSkillHookRegistryProjectionResult,
  normalizeRunCreateStateUpdateApiResult,
  normalizeRuntimeBridgeThreadStartAgentStateUpdateApiResult,
  normalizeRuntimeBridgeThreadControlAgentStateUpdateApiResult,
  normalizeRuntimeBridgeTurnRunStateUpdateApiResult,
  normalizeSubagentRecordStateUpdateApiResult,
  normalizeThreadCreateStateUpdateApiResult,
  normalizeThreadControlAgentStateUpdateApiResult,
  normalizeThreadMemoryAgentStateUpdateResult,
  normalizeWorkspaceTrustControlStateUpdateResult,
} from "./runtime-context-policy-core.mjs";

function assertNoRetiredOperationKindDetailAliases(details) {
  for (const key of ["operationKind", "expectedOperationKind", "expectedOperationKinds", "expectedPrefix"]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
}

function createContextLifecycleDirectCore(method, handler) {
  const calls = [];
  const runner = new RuntimeContextPolicyCore({
    daemonCoreContextLifecycleApi: {
      [method](request) {
        calls.push({ method, request });
        return handler(request);
      },
    },
  });
  return { calls, runner };
}

function createRuntimeControlDirectCore(method, handler) {
  const calls = [];
  const runner = new RuntimeContextPolicyCore({
    daemonCoreRuntimeControlApi: {
      [method](request) {
        calls.push({ method, request });
        return handler(request);
      },
    },
  });
  return { calls, runner };
}

function createRuntimeProjectionDirectCore(method, handler) {
  const calls = [];
  const runner = new RuntimeContextPolicyCore({
    daemonCoreRuntimeProjectionApi: {
      [method](request) {
        calls.push({ method, request });
        return handler(request);
      },
    },
  });
  return { calls, runner };
}

function createThreadLifecycleDirectCore(method, handler) {
  const calls = [];
  const runner = new RuntimeContextPolicyCore({
    daemonCoreThreadLifecycleApi: {
      [method](request) {
        calls.push({ method, request });
        return handler(request);
      },
    },
  });
  return { calls, runner };
}

function createWorkspaceTrustDirectCore(method, handler) {
  const calls = [];
  const runner = new RuntimeContextPolicyCore({
    daemonCoreWorkspaceTrustApi: {
      [method](request) {
        calls.push({ method, request });
        return handler(request);
      },
    },
  });
  return { calls, runner };
}

function createMcpDirectCore(method, handler) {
  const calls = [];
  const runner = new RuntimeContextPolicyCore({
    daemonCoreMcpApi: {
      [method](request) {
        calls.push({ method, request });
        return handler(request);
      },
    },
  });
  return { calls, runner };
}

function createThreadMemoryDirectCore(method, handler) {
  const calls = [];
  const runner = new RuntimeContextPolicyCore({
    daemonCoreThreadMemoryApi: {
      [method](request) {
        calls.push({ method, request });
        return handler(request);
      },
    },
  });
  return { calls, runner };
}

test("runtime context policy core uses daemon-level context lifecycle API", () => {
  const { calls, runner } = createContextLifecycleDirectCore(
    CONTEXT_LIFECYCLE_CONTEXT_BUDGET_POLICY_API_METHOD,
    () => ({
      source: "direct_context_lifecycle_api",
      backend: "rust_policy",
      status: "allowed",
      mode: "monitor",
      policy_decision_id: "policy_context_direct",
      policy_decision_refs: ["policy_context_direct"],
    }),
  );

  const result = runner.evaluateContextBudgetPolicy({
    usage_telemetry: { total_tokens: 1 },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, CONTEXT_LIFECYCLE_CONTEXT_BUDGET_POLICY_API_METHOD);
  assert.equal(calls[0].request.schema_version, CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "direct_context_lifecycle_api");
});

test("runtime context policy core rejects retired daemon-core command option", () => {
  assert.throws(
    () =>
      createRuntimeContextPolicyCore({
        command: "ioi-runtime-daemon-core",
      }),
    (error) =>
      error instanceof RuntimeContextPolicyCoreError &&
      error.code === "runtime_context_policy_core_command_retired",
  );
});

test("runtime context policy core daemonCoreInvoker option fails closed", () => {
  assert.throws(
    () => new RuntimeContextPolicyCore({ daemonCoreInvoker() {} }),
    (error) =>
      error instanceof RuntimeContextPolicyCoreError &&
      error.code === "runtime_context_policy_core_daemonCoreInvoker_retired",
  );
});

test("runtime context policy core daemonCoreApi option fails closed", () => {
  assert.throws(
    () =>
      new RuntimeContextPolicyCore({
        daemonCoreApi: {
          contextLifecycle: {
            [CONTEXT_LIFECYCLE_CONTEXT_BUDGET_POLICY_API_METHOD]() {},
          },
        },
      }),
    (error) =>
      error instanceof RuntimeContextPolicyCoreError &&
      error.code === "runtime_context_policy_core_daemonCoreApi_retired" &&
      Object.hasOwn(error.details, "retired_daemonCoreApi"),
  );
});

test("runtime context policy core env option fails closed", () => {
  assert.throws(
    () =>
      createRuntimeContextPolicyCore({
        env: { IOI_RUNTIME_DAEMON_CORE_COMMAND: "ioi-runtime-daemon-core" },
      }),
    (error) =>
      error instanceof RuntimeContextPolicyCoreError &&
      error.code === "runtime_context_policy_core_env_retired",
  );
});

test("runtime context policy core command args constructor option fails closed", () => {
  assert.throws(
    () => new RuntimeContextPolicyCore({ args: ["--json"] }),
    (error) =>
      error instanceof RuntimeContextPolicyCoreError &&
      error.code === "runtime_context_policy_core_args_retired",
  );
});

test("runtime context policy core command constructor option fails closed", () => {
  assert.throws(
    () => new RuntimeContextPolicyCore({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof RuntimeContextPolicyCoreError &&
      error.code === "runtime_context_policy_core_command_retired",
  );
});

test("context budget policy core sends Rust policy through direct context lifecycle API", () => {
  const { calls, runner } = createContextLifecycleDirectCore(
    CONTEXT_LIFECYCLE_CONTEXT_BUDGET_POLICY_API_METHOD,
    () => ({
            source: "rust_context_budget_policy_api",
            backend: "rust_policy",
            status: "blocked",
            mode: "block",
            usage_telemetry: { total_tokens: 120 },
            usage_summary: { total_tokens: 120 },
            policy_decision_id: "policy_context_budget_thread_test_blocked",
            policy_decision: { status: "blocked" },
            receipt_refs: ["receipt_context_budget_thread_test"],
            policy_decision_refs: ["policy_context_budget_thread_test_blocked"],
            violations: [{ id: "total_tokens" }],
            warnings: [],
            would_block: true,
            runtime_event_kind: "policy.blocked",
            runtime_event_status: "blocked",
            runtime_event_item_id: "turn_1:item:context-budget:policy_context_budget_thread_test_blocked",
            runtime_event_idempotency_key:
              "thread:thread_1:context-budget:policy_context_budget_thread_test_blocked",
            summary: "Context budget blocked: total tokens exceeded.",
          }),
  );

  const result = runner.evaluateContextBudgetPolicy({
    usage_telemetry: { total_tokens: 120 },
    thresholds: { max_total_tokens: 100, warn_at_ratio: 0.8 },
    mode: "block",
    thread_id: "thread_1",
    turn_id: "turn_1",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, CONTEXT_LIFECYCLE_CONTEXT_BUDGET_POLICY_API_METHOD);
  assert.equal(calls[0].request.schema_version, CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[0].request.usage_telemetry.total_tokens, 120);
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_context_budget_policy_api");
  assert.equal(result.status, "blocked");
  assert.equal(result.runtime_event_kind, "policy.blocked");
  assert.equal(result.runtime_event_status, "blocked");
  assert.equal(
    result.runtime_event_idempotency_key,
    "thread:thread_1:context-budget:policy_context_budget_thread_test_blocked",
  );
  assert.deepEqual(result.policy_decision_refs, ["policy_context_budget_thread_test_blocked"]);
});

test("coding tool budget core sends Rust policy through direct context lifecycle API", () => {
  const { calls, runner } = createContextLifecycleDirectCore(
    CONTEXT_LIFECYCLE_CODING_TOOL_BUDGET_POLICY_API_METHOD,
    () => ({
            source: "rust_coding_tool_budget_policy_api",
            backend: "rust_policy",
            status: "blocked",
            mode: "block",
            usage_telemetry: { total_tokens: 120 },
            usage_summary: { total_tokens: 120 },
            policy_decision_id: "policy_context_budget_thread_test_blocked",
            policy_decision: { status: "blocked" },
            receipt_refs: ["receipt_context_budget_thread_test"],
            policy_decision_refs: ["policy_context_budget_thread_test_blocked"],
            violations: [{ id: "total_tokens" }],
            warnings: [],
            would_block: true,
            summary: "Context budget blocked: total tokens exceeded.",
          }),
  );

  const result = runner.evaluateCodingToolBudgetPolicy({
    usage_telemetry: { total_tokens: 120 },
    thresholds: { max_total_tokens: 100, warn_at_ratio: 0.8 },
    mode: "block",
    thread_id: "thread_1",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, CONTEXT_LIFECYCLE_CODING_TOOL_BUDGET_POLICY_API_METHOD);
  assert.equal(calls[0].request.schema_version, CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[0].request.usage_telemetry.total_tokens, 120);
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_coding_tool_budget_policy_api");
  assert.equal(result.status, "blocked");
  assert.deepEqual(result.policy_decision_refs, ["policy_context_budget_thread_test_blocked"]);
});

test("compaction policy core sends Rust policy through direct context lifecycle API", () => {
  const { calls, runner } = createContextLifecycleDirectCore(
    CONTEXT_LIFECYCLE_COMPACTION_POLICY_API_METHOD,
    () => ({
            source: "rust_compaction_policy_api",
            backend: "rust_policy",
            status: "waiting",
            action: "approval_required",
            selected_action: "compact",
            budget_status: "blocked",
            policy_decision_id: "policy_compaction_thread_test_waiting",
            receipt_refs: ["receipt_compaction_policy_thread_test"],
            policy_decision_refs: ["policy_compaction_thread_test_waiting"],
            approval_id: "approval_compaction_thread_test",
            approval_required: true,
            approval_granted: false,
            approval_satisfied: false,
            execute_compaction: false,
            compaction_requested: false,
            compact_reason: "Compaction policy blocked: Context budget blocked.",
            compact_scope: "thread",
            runtime_event_kind: "approval.required",
            runtime_event_status: "waiting",
            runtime_event_item_id: "turn_1:item:compaction-policy:policy_compaction_thread_test_waiting",
            runtime_event_idempotency_key:
              "thread:thread_1:compaction-policy:policy_compaction_thread_test_waiting",
            compact_idempotency_key:
              "thread:thread_1:compaction-policy:compact:policy_compaction_thread_test_waiting",
            compact_workflow_node_id: "runtime.context-compact",
            continuation_allowed: true,
            summary: "Compaction policy requires operator approval before compacting.",
          }),
  );

  const result = runner.evaluateCompactionPolicy({
    thread_id: "thread_1",
    context_budget: { status: "blocked" },
    actions: { blocked_action: "compact" },
    approval: { approval_required: true, approval_granted: false },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, CONTEXT_LIFECYCLE_COMPACTION_POLICY_API_METHOD);
  assert.equal(calls[0].request.schema_version, COMPACTION_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[0].request.context_budget.status, "blocked");
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_compaction_policy_api");
  assert.equal(result.action, "approval_required");
  assert.equal(result.approval_required, true);
  assert.equal(result.runtime_event_kind, "approval.required");
  assert.equal(result.runtime_event_status, "waiting");
  assert.equal(
    result.compact_idempotency_key,
    "thread:thread_1:compaction-policy:compact:policy_compaction_thread_test_waiting",
  );
});

test("context compaction core sends Rust plan through direct context lifecycle API", () => {
  const { calls, runner } = createContextLifecycleDirectCore(
    CONTEXT_LIFECYCLE_CONTEXT_COMPACTION_PLAN_API_METHOD,
    () => ({
            source: "rust_context_compaction_plan_api",
            backend: "rust_policy",
            status: "planned",
            item_id: "turn_1:item:context-compact:hash_one",
            idempotency_key: "thread:thread_1:context.compact:hash_one",
            compact_hash: "hash_one",
            source_event_kind: "OperatorControl.Compact",
            event_kind: "context.compacted",
            component_kind: "context_compaction",
            payload_schema_version: "ioi.runtime.context-compaction.v1",
            payload: {
              reason: "trim context",
              requested_by: "operator_one",
              previous_latest_seq: 7,
            },
            receipt_refs: ["receipt_run_1_context_compaction_hash_one"],
            policy_decision_refs: ["policy_run_1_context_compaction_allow"],
            artifact_refs: [],
            rollback_refs: [],
            redaction_profile: "internal",
            reason: "trim context",
            scope: "thread",
            requested_by: "operator_one",
            previous_latest_seq: 7,
          }),
  );

  const result = runner.planContextCompaction({
    thread_id: "thread_1",
    agent_id: "agent_1",
    run_id: "run_1",
    reason: "trim context",
    previous_latest_seq: 7,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, CONTEXT_LIFECYCLE_CONTEXT_COMPACTION_PLAN_API_METHOD);
  assert.equal(calls[0].request.schema_version, CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION);
  assert.equal(calls[0].request.thread_id, "thread_1");
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_context_compaction_plan_api");
  assert.equal(result.event_kind, "context.compacted");
  assert.equal(result.item_id, "turn_1:item:context-compact:hash_one");
  assert.deepEqual(result.receipt_refs, ["receipt_run_1_context_compaction_hash_one"]);
});

test("context compaction state update core sends Rust state update through direct context lifecycle API", () => {
  const { calls, runner } = createContextLifecycleDirectCore(
    CONTEXT_LIFECYCLE_CONTEXT_COMPACTION_STATE_UPDATE_API_METHOD,
    () => ({
            source: "rust_context_compaction_state_update_api",
            backend: "rust_policy",
            status: "planned",
            target_kind: "run",
            operation_kind: "thread.compact",
            updated_at: "2026-06-05T12:00:00.000Z",
            operator_control: {
              control: "compact",
              event_id: "event_1",
              seq: 1,
            },
            context_compaction: {
              event_id: "event_1",
              seq: 1,
              compacted_tokens: 0,
            },
            run: {
              id: "run_1",
              updatedAt: "2026-06-05T12:00:00.000Z",
              trace: {
                contextCompaction: {
                  event_id: "event_1",
                },
              },
            },
          }),
  );

  const result = runner.planContextCompactionStateUpdate({
    thread_id: "thread_1",
    agent_id: "agent_1",
    run_id: "run_1",
    target_kind: "run",
    run: { id: "run_1" },
    agent: { id: "agent_1" },
    event_id: "event_1",
    seq: 1,
    created_at: "2026-06-05T12:00:00.000Z",
    source: "sdk_client",
    reason: "trim context",
    scope: "thread",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, CONTEXT_LIFECYCLE_CONTEXT_COMPACTION_STATE_UPDATE_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.thread_id, "thread_1");
  assert.equal(calls[0].request.event_id, "event_1");
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_context_compaction_state_update_api");
  assert.equal(result.target_kind, "run");
  assert.equal(result.operation_kind, "thread.compact");
  assert.equal(result.operator_control.event_id, "event_1");
  assert.equal(Object.hasOwn(result.operator_control, "eventId"), false);
  assert.equal(Object.hasOwn(result.operator_control, "createdAt"), false);
  assert.equal(result.context_compaction.compacted_tokens, 0);
  assert.equal(Object.hasOwn(result.context_compaction, "eventId"), false);
  assert.equal(Object.hasOwn(result.context_compaction, "compactedTokens"), false);
  assert.equal(result.run.trace.contextCompaction.event_id, "event_1");
});

test("runtime context lifecycle core does not synthesize Rust-owned public fields", () => {
  const budget = normalizeContextBudgetPolicyResult({
    source: "rust_context_budget_policy_api",
    usage_telemetry: {},
    usage_summary: {},
  });
  assert.equal(budget.object, null);
  assert.equal(budget.status, null);
  assert.equal(budget.mode, null);
  assert.equal(budget.would_block, null);
  assert.equal(budget.runtime_event_kind, null);
  assert.equal(budget.runtime_event_status, null);

  const policy = normalizeCompactionPolicyResult({
    source: "rust_compaction_policy_api",
  });
  assert.equal(policy.object, null);
  assert.equal(policy.status, null);
  assert.equal(policy.action, null);
  assert.equal(policy.selected_action, null);
  assert.equal(policy.budget_status, null);
  assert.equal(policy.approval_required, null);
  assert.equal(policy.approval_granted, null);
  assert.equal(policy.approval_satisfied, null);
  assert.equal(policy.execute_compaction, null);
  assert.equal(policy.compaction_requested, null);
  assert.equal(policy.compaction_executed, null);
  assert.equal(policy.compact_scope, null);
  assert.equal(policy.runtime_event_kind, null);
  assert.equal(policy.runtime_event_status, null);
  assert.equal(policy.compact_workflow_node_id, null);
  assert.equal(policy.continuation_allowed, null);

  const plan = normalizeContextCompactionPlanResult({
    source: "rust_context_compaction_plan_api",
  });
  assert.equal(plan.object, null);
  assert.equal(plan.status, null);
  assert.equal(plan.event_source, null);
  assert.equal(plan.actor, null);
  assert.equal(plan.source_event_kind, null);
  assert.equal(plan.event_kind, null);
  assert.equal(plan.component_kind, null);
  assert.equal(plan.payload_schema_version, null);
  assert.equal(plan.redaction_profile, null);
  assert.equal(plan.scope, null);
  assert.equal(plan.requested_by, null);
  assert.equal(plan.previous_latest_seq, null);

  const update = normalizeContextCompactionStateUpdateResult({
    source: "rust_context_compaction_state_update_api",
    operation_kind: "thread.compact",
  });
  assert.equal(update.object, null);
  assert.equal(update.status, null);
  assert.equal(update.target_kind, null);
  assert.equal(update.operation_kind, "thread.compact");
});

test("runtime state-update core does not synthesize Rust-owned envelopes", () => {
  const sparseCases = [
    [
      normalizeCodingToolBudgetRecoveryStateUpdateApiResult,
      {
        source: "rust_coding_tool_budget_recovery_state_update_api",
        operation_kind: "workflow.run.retry_completed",
      },
    ],
    [
      normalizeDiagnosticsOperatorOverrideStateUpdateApiResult,
      {
        source: "rust_diagnostics_operator_override_state_update_api",
        operation_kind: "diagnostics.operator_override.event",
      },
    ],
    [
      normalizeOperatorInterruptStateUpdateApiResult,
      {
        source: "rust_operator_interrupt_state_update_api",
        operation_kind: "turn.interrupt",
      },
    ],
    [
      normalizeOperatorSteerStateUpdateApiResult,
      {
        source: "rust_operator_steer_state_update_api",
        operation_kind: "turn.steer",
      },
    ],
    [
      normalizeRunCancelStateUpdateApiResult,
      {
        source: "rust_run_cancel_state_update_api",
        operation_kind: "run.cancel",
      },
    ],
    [
      normalizeThreadControlAgentStateUpdateApiResult,
      {
        source: "rust_thread_control_agent_state_update_api",
        operation_kind: "thread.pause",
      },
    ],
    [
      normalizeMcpControlAgentStateUpdateApiResult,
      {
        source: "rust_mcp_control_agent_state_update_api",
        operation_kind: "thread.mcp_import",
      },
    ],
    [
      normalizeThreadMemoryAgentStateUpdateResult,
      {
        source: "rust_thread_memory_agent_state_update_api",
        operation_kind: "thread.memory_append",
      },
    ],
    [
      normalizeRuntimeBridgeThreadStartAgentStateUpdateApiResult,
      {
        source: "rust_runtime_bridge_thread_start_agent_state_update_api",
        operation_kind: "thread.runtime_bridge.start",
      },
    ],
    [
      normalizeRuntimeBridgeTurnRunStateUpdateApiResult,
      {
        source: "rust_runtime_bridge_turn_run_state_update_api",
        operation_kind: "turn.runtime_bridge.submit",
      },
    ],
    [
      normalizeSubagentRecordStateUpdateApiResult,
      {
        source: "rust_subagent_record_state_update_api",
        operation_kind: "subagent.spawn",
      },
    ],
    [
      normalizeThreadCreateStateUpdateApiResult,
      {
        source: "rust_thread_create_state_update_api",
        operation_kind: "thread.create",
      },
    ],
    [
      normalizeAgentCreateStateUpdateApiResult,
      {
        source: "rust_agent_create_state_update_api",
        operation_kind: "agent.create",
      },
    ],
    [
      normalizeRunCreateStateUpdateApiResult,
      {
        source: "rust_run_create_state_update_api",
        operation_kind: "run.create",
      },
    ],
    [
      normalizeAgentStatusStateUpdateApiResult,
      {
        source: "rust_agent_status_state_update_api",
        operation_kind: "agent.status",
      },
    ],
  ];

  for (const [normalize, input] of sparseCases) {
    const result = normalize(input);
    assert.equal(result.object, null, `${input.source} object`);
    assert.equal(result.status, null, `${input.source} status`);
    assert.equal(result.operation_kind, input.operation_kind);
  }
});

test("coding tool budget recovery state update core sends Rust state update through direct runtime-control API", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_API_METHOD,
    () => ({
            source: "rust_coding_tool_budget_recovery_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "workflow.run.retry_completed",
            updated_at: "2026-06-06T04:05:00.000Z",
            operator_control: {
              control: "coding_tool_budget_recovery",
              approval_id: "approval_budget",
              event_id: "event_retry",
            },
            run: {
              id: "run_budget",
              updatedAt: "2026-06-06T04:05:00.000Z",
              trace: {
                operatorControls: [
                  {
                    control: "coding_tool_budget_recovery",
                    event_id: "event_retry",
                  },
                ],
              },
            },
          }),
  );

  const result = runner.planCodingToolBudgetRecoveryStateUpdate({
    thread_id: "thread_budget",
    run_id: "run_budget",
    run: { id: "run_budget", trace: {} },
    event_id: "event_retry",
    seq: 9,
    created_at: "2026-06-06T04:05:00.000Z",
    approval_id: "approval_budget",
    source: "runtime_auto",
    receipt_refs: ["receipt_retry"],
    policy_decision_refs: ["policy_retry"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.approval_id, "approval_budget");
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_coding_tool_budget_recovery_state_update_api");
  assert.equal(result.operation_kind, "workflow.run.retry_completed");
  assert.equal(result.operator_control.approval_id, "approval_budget");
  for (const field of ["approvalId", "eventId", "receiptRefs", "policyDecisionRefs", "createdAt"]) {
    assert.equal(Object.hasOwn(result.operator_control, field), false);
  }
  assert.equal(result.run.trace.operatorControls[0].event_id, "event_retry");
});

test("coding tool budget block core sends Rust block request through direct context lifecycle API", () => {
  const { calls, runner } = createContextLifecycleDirectCore(
    CONTEXT_LIFECYCLE_CODING_TOOL_BUDGET_BLOCK_API_METHOD,
    () => ({
        source: "rust_coding_tool_budget_block_api",
        backend: "rust_policy",
        status: "blocked",
        operation_kind: "coding_tool.budget.block",
        reason: "coding_tool_budget_exceeded",
        context_budget_status: "blocked",
        receipt_refs: ["receipt_budget"],
        policy_decision_refs: ["policy_budget"],
        artifact_refs: [],
        rollback_refs: ["rollback_budget"],
        result: {
          schema_version: "ioi.runtime.coding-tool-result.v1",
          status: "blocked",
          rust_budget_block: true,
          context_budget_status: "blocked",
        },
        event: {
          event_stream_id: "thread_budget:events",
          event_kind: "tool.blocked",
          status: "blocked",
          payload_summary: {
            schema_version: "ioi.runtime.coding-tool-result.v1",
            rust_budget_block: true,
            context_budget_status: "blocked",
            receipt_refs: ["receipt_budget"],
          },
          receipt_refs: ["receipt_budget"],
        },
        record: {
          schema_version: "ioi.runtime.coding-tool-budget-block-result.v1",
          status: "blocked",
          operation_kind: "coding_tool.budget.block",
        },
      }),
  );

  const result = runner.planCodingToolBudgetBlock({
    thread_id: "thread_budget",
    turn_id: "turn_budget",
    tool_id: "file.inspect",
    tool_call_id: "call_budget",
    budget_policy: {
      status: "blocked",
      usage_telemetry: { prompt_tokens: 10 },
      policy_decision_refs: ["policy_budget"],
    },
    receipt_refs: ["receipt_invocation"],
    rollback_refs: ["rollback_budget"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, CONTEXT_LIFECYCLE_CODING_TOOL_BUDGET_BLOCK_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    CODING_TOOL_BUDGET_BLOCK_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.tool_id, "file.inspect");
  assert.equal(calls[0].request.budget_policy.status, "blocked");
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_coding_tool_budget_block_api");
  assert.equal(result.operation_kind, "coding_tool.budget.block");
  assert.equal(result.reason, "coding_tool_budget_exceeded");
  assert.equal(result.context_budget_status, "blocked");
  assert.deepEqual(result.receipt_refs, ["receipt_budget"]);
  assert.deepEqual(result.policy_decision_refs, ["policy_budget"]);
  assert.equal(result.result.rust_budget_block, true);
  assert.equal(result.event.event_kind, "tool.blocked");
  assert.equal(Object.hasOwn(result, "contextBudgetStatus"), false);
  assert.equal(Object.hasOwn(result.event.payload_summary, "receiptRefs"), false);
});

test("coding-tool budget recovery control core sends Rust request through direct runtime-control API", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_CODING_TOOL_BUDGET_RECOVERY_CONTROL_API_METHOD,
    () => ({
        source: "rust_coding_tool_budget_recovery_control_api",
        backend: "rust_policy",
        status: "planned",
        action: "approve_override",
        operation_kind: "workflow.run.coding_tool_budget_recovery.approve_override",
        operator_control: {
          control: "coding_tool_budget_recovery",
          action: "approve_override",
          approval_id: "approval_alpha",
          event_id: "event_budget_override",
          authority_hash: "sha256:budget-authority",
          wallet_network_grant_refs: ["wallet.network://grant/coding-tool-budget-recovery"],
          authority_receipt_refs: ["receipt://wallet.network/coding-tool-budget-recovery"],
        },
        run: { id: "run_alpha" },
      }),
  );

  const result = runner.planCodingToolBudgetRecoveryControl({
    operation: "coding_tool_budget_recovery_control",
    operation_kind: "workflow.run.coding_tool_budget_recovery",
    run_id: "run_alpha",
    thread_id: "thread_alpha",
    action: "approve_override",
    approval_id: "approval_alpha",
    run: { id: "run_alpha" },
    event_id: "event_budget_override",
    seq: 19,
    created_at: "2026-06-12T10:41:00.000Z",
    authority_grant_refs: ["wallet.network://grant/coding-tool-budget-recovery"],
    authority_receipt_refs: ["receipt://wallet.network/coding-tool-budget-recovery"],
    evidence_refs: ["coding_tool_budget_recovery_control_rust_owned"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_CODING_TOOL_BUDGET_RECOVERY_CONTROL_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    CODING_TOOL_BUDGET_RECOVERY_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.operation, "coding_tool_budget_recovery_control");
  assert.equal(
    calls[0].request.operation_kind,
    "workflow.run.coding_tool_budget_recovery",
  );
  assert.equal(calls[0].request.action, "approve_override");
  assert.deepEqual(calls[0].request.authority_grant_refs, [
    "wallet.network://grant/coding-tool-budget-recovery",
  ]);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_coding_tool_budget_recovery_control_api");
  assert.equal(result.status, "planned");
  assert.equal(result.operator_control.authority_hash, "sha256:budget-authority");
  assert.equal(Object.hasOwn(result.operator_control, "authorityHash"), false);
});

test("workflow-edit admission-required core sends typed Rust daemon-core request", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_WORKFLOW_EDIT_ADMISSION_REQUIRED_API_METHOD,
    () => ({
      status_code: 501,
      code: "runtime_workflow_edit_rust_core_required",
      message: "Runtime workflow edit control requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.workflow_edit",
        operation: "workflow_edit_proposal",
        operation_kind: "workflow.edit_proposed",
        thread_id: "thread_alpha",
        proposal_id: "proposal_alpha",
        evidence_refs: ["workflow_edit_proposal_js_facade_retired"],
      },
    }),
  );

  const result = runner.planWorkflowEditAdmissionRequired({
    operation: "workflow_edit_proposal",
    operation_kind: "workflow.edit_proposed",
    thread_id: "thread_alpha",
    proposal_id: "proposal_alpha",
    evidence_refs: ["workflow_edit_proposal_js_facade_retired"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_WORKFLOW_EDIT_ADMISSION_REQUIRED_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    WORKFLOW_EDIT_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.operation, "workflow_edit_proposal");
  assert.equal(calls[0].request.operation_kind, "workflow.edit_proposed");
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.status_code, 501);
  assert.equal(result.details.thread_id, "thread_alpha");
  assert.equal(Object.hasOwn(result.details, "threadId"), false);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
  assert.equal(Object.hasOwn(result, "record"), false);
});

test("diagnostics repair admission-required core sends typed Rust daemon-core request", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_API_METHOD,
    () => ({
      status_code: 501,
      code: "runtime_diagnostics_repair_rust_core_required",
      message:
        "Runtime diagnostics repair control requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.diagnostics_repair",
        operation: "diagnostics_repair_decision_execution",
        operation_kind: "diagnostics.repair_decision.execute",
        thread_id: "thread_alpha",
        decision_id: "decision_alpha",
        gate_event_id: "event_gate",
        snapshot_id: "snapshot_alpha",
        evidence_refs: ["diagnostics_repair_decision_execution_js_facade_retired"],
      },
    }),
  );

  const result = runner.planDiagnosticsRepairAdmissionRequired({
    operation: "diagnostics_repair_decision_execution",
    operation_kind: "diagnostics.repair_decision.execute",
    thread_id: "thread_alpha",
    decision_id: "decision_alpha",
    gate_event_id: "event_gate",
    snapshot_id: "snapshot_alpha",
    evidence_refs: ["diagnostics_repair_decision_execution_js_facade_retired"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.operation, "diagnostics_repair_decision_execution");
  assert.equal(
    calls[0].request.operation_kind,
    "diagnostics.repair_decision.execute",
  );
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.status_code, 501);
  assert.equal(result.details.thread_id, "thread_alpha");
  assert.equal(Object.hasOwn(result.details, "threadId"), false);
  assert.equal(Object.hasOwn(result.details, "gateEventId"), false);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
  assert.equal(Object.hasOwn(result, "record"), false);
});

test("runtime diagnostics repair control core sends Rust daemon-core request", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_DIAGNOSTICS_REPAIR_CONTROL_API_METHOD,
    () => ({
        source: "rust_runtime_diagnostics_repair_control_api",
        backend: "rust_policy",
        record: {
          schema_version: "ioi.runtime.diagnostics_repair_control.v1",
          object: "ioi.runtime_diagnostics_repair_control",
          status: "planned",
          operation: "diagnostics_repair_decision_execution",
          operation_kind: "diagnostics.repair_decision.execute",
          thread_id: "thread_alpha",
          decision_id: "decision_alpha",
          control_status: "accepted",
          event: {
            event_id: "event_diagnostics_repair_decision_alpha",
            event_kind: "diagnostics.repair_decision.execute",
            thread_id: "thread_alpha",
            payload: { decision_id: "decision_alpha" },
          },
          receipt_refs: ["receipt_diagnostics_repair_decision_alpha"],
          policy_decision_refs: ["policy_diagnostics_repair_decision_alpha"],
          evidence_refs: ["runtime_diagnostics_repair_decision_execution_rust_owned"],
        },
      }),
  );

  const result = runner.planRuntimeDiagnosticsRepairControl({
    operation: "diagnostics_repair_decision_execution",
    operation_kind: "diagnostics.repair_decision.execute",
    thread_id: "thread_alpha",
    event_stream_id: "event_stream_thread_alpha",
    decision_id: "decision_alpha",
    gate_event_id: "event_gate",
    snapshot_id: "snapshot_alpha",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_DIAGNOSTICS_REPAIR_CONTROL_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.operation, "diagnostics_repair_decision_execution");
  assert.equal(
    calls[0].request.operation_kind,
    "diagnostics.repair_decision.execute",
  );
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_runtime_diagnostics_repair_control_api");
  assert.equal(result.operation_kind, "diagnostics.repair_decision.execute");
  assert.equal(result.decision_id, "decision_alpha");
  assert.equal(result.event.event_kind, "diagnostics.repair_decision.execute");
  assert.deepEqual(result.receipt_refs, ["receipt_diagnostics_repair_decision_alpha"]);
});

test("runtime diagnostics repair retry-run core sends Rust daemon-core request", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_DIAGNOSTICS_REPAIR_RETRY_RUN_API_METHOD,
    () => ({
        source: "rust_runtime_diagnostics_repair_retry_run_api",
        backend: "rust_policy",
        record: {
          schema_version: "ioi.runtime.diagnostics_repair_retry_run.v1",
          object: "ioi.runtime_diagnostics_repair_retry_run",
          status: "planned",
          operation: "diagnostics_repair_retry_run_create",
          operation_kind: "diagnostics.repair_retry.run_create",
          thread_id: "thread_alpha",
          agent_id: "agent_alpha",
          decision_id: "decision_retry",
          run_request: {
            mode: "send",
            prompt: "Retry the diagnostics repair.",
            options: {
              diagnostics_repair: {
                action: "repair_retry",
                decision_id: "decision_retry",
              },
            },
            diagnostics_feedback: {
              mode: "repair_retry",
              decision_id: "decision_retry",
            },
          },
          retry_event_request: {
            decision_id: "decision_retry",
            action: "repair_retry",
            target_run_id: "run_blocked",
            summary: "Retry queued.",
          },
          receipt_refs: ["receipt_retry"],
          policy_decision_refs: ["policy_retry"],
          evidence_refs: ["runtime_diagnostics_repair_retry_run_request_rust_owned"],
        },
      }),
  );

  const result = runner.planRuntimeDiagnosticsRepairRetryRun({
    operation: "diagnostics_repair_retry_run_create",
    operation_kind: "diagnostics.repair_retry.run_create",
    thread_id: "thread_alpha",
    agent_id: "agent_alpha",
    decision_id: "decision_retry",
    target_run_id: "run_blocked",
    request: { prompt: "Retry the diagnostics repair." },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_DIAGNOSTICS_REPAIR_RETRY_RUN_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RUN_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.operation, "diagnostics_repair_retry_run_create");
  assert.equal(
    calls[0].request.operation_kind,
    "diagnostics.repair_retry.run_create",
  );
  assert.equal(calls[0].request.agent_id, "agent_alpha");
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_runtime_diagnostics_repair_retry_run_api");
  assert.equal(result.operation_kind, "diagnostics.repair_retry.run_create");
  assert.equal(result.run_request.options.diagnostics_repair.action, "repair_retry");
  assert.equal(result.retry_event_request.target_run_id, "run_blocked");
  assert.deepEqual(result.receipt_refs, ["receipt_retry"]);
});

test("runtime diagnostics repair retry-result projection core sends Rust daemon-core request", () => {
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_RETRY_RESULT_API_METHOD,
    () => ({
        source: "rust_runtime_diagnostics_repair_retry_result_projection_api",
        backend: "rust_policy",
        record: {
          schema_version: "ioi.runtime.diagnostics_repair_retry_result_projection.v1",
          object: "ioi.runtime_diagnostics_repair_retry",
          status: "created",
          operation: "project_runtime_diagnostics_repair_retry_result",
          operation_kind: "runtime.diagnostics_repair_retry.result",
          thread_id: "thread_alpha",
          turn_id: "turn_retry",
          request_id: "run_retry",
          repair_turn: null,
          event: {
            event_id: "event_retry",
            thread_id: "thread_alpha",
            event_kind: "diagnostics.repair_retry.created",
            payload: {
              retry_turn_id: "turn_retry",
              retry_request_id: "run_retry",
              summary: "Retry queued.",
            },
          },
          repair_retry_event: {
            event_id: "event_retry",
            thread_id: "thread_alpha",
            event_kind: "diagnostics.repair_retry.created",
          },
          receipt_refs: ["receipt_retry_event"],
          artifact_refs: ["artifact_retry"],
          policy_decision_refs: ["policy_retry"],
          rollback_refs: ["snapshot_retry"],
          summary: "Retry queued.",
          evidence_refs: ["runtime_diagnostics_repair_retry_result_projection_rust_owned"],
        },
      }),
  );

  const result = runner.projectRuntimeDiagnosticsRepairRetryResult({
    operation: "project_runtime_diagnostics_repair_retry_result",
    operation_kind: "runtime.diagnostics_repair_retry.result",
    thread_id: "thread_alpha",
    event: {
      event_id: "event_retry",
      thread_id: "thread_alpha",
      event_kind: "diagnostics.repair_retry.created",
      payload: {
        retry_turn_id: "turn_retry",
        retry_request_id: "run_retry",
      },
    },
    run: { id: "run_retry" },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_RETRY_RESULT_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(
    calls[0].request.operation,
    "project_runtime_diagnostics_repair_retry_result",
  );
  assert.equal(calls[0].request.operation_kind, "runtime.diagnostics_repair_retry.result");
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(Object.hasOwn(calls[0].request.event.payload, "retryTurnId"), false);
  assert.equal(result.source, "rust_runtime_diagnostics_repair_retry_result_projection_api");
  assert.equal(result.object, "ioi.runtime_diagnostics_repair_retry");
  assert.equal(result.operation_kind, "runtime.diagnostics_repair_retry.result");
  assert.equal(result.turn_id, "turn_retry");
  assert.equal(result.request_id, "run_retry");
  assert.deepEqual(result.receipt_refs, ["receipt_retry_event"]);
  assert.deepEqual(result.evidence_refs, ["runtime_diagnostics_repair_retry_result_projection_rust_owned"]);
});

test("runtime diagnostics repair retry-result projection core rejects partial Rust records", () => {
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_RETRY_RESULT_API_METHOD,
    () => ({
      source: "rust_runtime_diagnostics_repair_retry_result_projection_api",
      backend: "rust_policy",
      record: {
        status: "created",
        operation_kind: "runtime.diagnostics_repair_retry.result",
        thread_id: "thread_alpha",
        evidence_refs: ["runtime_diagnostics_repair_retry_result_projection_rust_owned"],
      },
    }),
  );

  assert.throws(
    () =>
      runner.projectRuntimeDiagnosticsRepairRetryResult({
        operation: "project_runtime_diagnostics_repair_retry_result",
        operation_kind: "runtime.diagnostics_repair_retry.result",
        thread_id: "thread_alpha",
      }),
    (error) => {
      assert.equal(error instanceof RuntimeContextPolicyCoreError, true);
      assert.equal(
        error.code,
        "runtime_diagnostics_repair_retry_result_projection_invalid",
      );
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.turn_id, null);
      assert.equal(error.details.request_id, null);
      assert.equal(error.details.has_event, false);
      assert.equal(error.details.has_repair_retry_event, false);
      return true;
    },
  );
  assert.equal(calls.length, 1);
});

test("runtime diagnostics repair projection core sends Rust daemon-core request", () => {
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_PROJECTION_API_METHOD,
    () => ({
        source: "rust_runtime_diagnostics_repair_projection_api",
        backend: "rust_policy",
        record: {
          schema_version: "ioi.runtime.diagnostics_repair_projection.v1",
          object: "ioi.runtime_diagnostics_repair_projection",
          status: "projected",
          operation: "runtime_diagnostics_repair_projection",
          operation_kind: "runtime.diagnostics_repair_projection.decision",
          projection_kind: "decision",
          thread_id: "thread_alpha",
          decision_id: "decision_alpha",
          gate_id: "gate_alpha",
          projection: {
            schema_version: "ioi.runtime.diagnostics_repair_decision.v1",
            object: "ioi.runtime_diagnostics_repair_decision",
            decision_id: "decision_alpha",
            thread_id: "thread_alpha",
            gate_id: "gate_alpha",
            action: "restore_apply",
            status: "accepted",
          },
          record_count: 1,
          receipt_refs: ["receipt_runtime_diagnostics_repair_projection_decision"],
          evidence_refs: ["runtime_diagnostics_repair_decision_projection_rust_owned"],
        },
      }),
  );

  const result = runner.projectRuntimeDiagnosticsRepairProjection({
    operation: "runtime_diagnostics_repair_projection",
    operation_kind: "runtime.diagnostics_repair_projection.decision",
    projection_kind: "decision",
    thread_id: "thread_alpha",
    decision_id: "decision_alpha",
    gate_id: "gate_alpha",
    state_dir: "/runtime-state",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_PROJECTION_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.operation, "runtime_diagnostics_repair_projection");
  assert.equal(
    calls[0].request.operation_kind,
    "runtime.diagnostics_repair_projection.decision",
  );
  assert.equal(calls[0].request.projection_kind, "decision");
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(calls[0].request.decision_id, "decision_alpha");
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(Object.hasOwn(calls[0].request, "projection"), false);
  assert.equal(result.source, "rust_runtime_diagnostics_repair_projection_api");
  assert.equal(result.projection_kind, "decision");
  assert.equal(result.projection.decision_id, "decision_alpha");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeDiagnosticsRepairProjectionResult({
        record: {
          operation_kind: "runtime.diagnostics_repair_projection.retired",
          projection_kind: "decision",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_diagnostics_repair_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime diagnostics repair policy core sends Rust daemon-core request", () => {
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_POLICY_API_METHOD,
    () => ({
        source: "rust_runtime_diagnostics_repair_policy_api",
        backend: "rust_policy",
        projected: true,
        record: {
          schema_version: "ioi.runtime.diagnostics_repair_policy_projection.v1",
          object: "ioi.runtime_diagnostics_repair_policy_projection",
          status: "projected",
          operation: "project_runtime_diagnostics_repair_policy",
          operation_kind: "runtime.diagnostics_repair_policy.projection",
          thread_id: "thread_alpha",
          injection_id: "injection_alpha",
          mode: "blocking",
          diagnostic_status: "findings",
          diagnostic_count: 2,
          repair_policy_config: {
            restore_policy: "preview_only",
            restore_conflict_policy: "require_approval",
            diagnostics_repair_default: "restore_preview",
            operator_override_requires_approval: false,
          },
          repair_policy: {
            schema_version: "ioi.runtime.diagnostics-rollback-repair-policy.v1",
            object: "ioi.runtime_diagnostics_rollback_repair_policy",
            policy_id: "policy_alpha",
            thread_id: "thread_alpha",
            injection_id: "injection_alpha",
            decisions: [{ decision_id: "decision_alpha", action: "repair_retry" }],
            decision_refs: ["decision_alpha"],
          },
          receipt_refs: ["receipt_runtime_diagnostics_repair_policy_projection"],
          evidence_refs: ["runtime_diagnostics_repair_policy_projection_rust_owned"],
          projection_hash: "sha256:policy",
        },
      }),
  );

  const result = runner.projectRuntimeDiagnosticsRepairPolicy({
    thread_id: "thread_alpha",
    mode: "blocking",
    state_dir: "/runtime-state",
    diagnostic_event_ids: ["event_diagnostics_alpha"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_DIAGNOSTICS_REPAIR_POLICY_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.deepEqual(calls[0].request.diagnostic_event_ids, ["event_diagnostics_alpha"]);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  for (const field of [
    "injection_id",
    "diagnostic_status",
    "diagnostic_count",
    "workspace_snapshot_refs",
    "rollback_refs",
    "source_tool_call_ids",
    "diagnostics_repair_contexts",
    "receipt_refs",
  ]) {
    assert.equal(Object.hasOwn(calls[0].request, field), false, `${field} must not be sent`);
  }
  assert.equal(result.source, "rust_runtime_diagnostics_repair_policy_api");
  assert.equal(result.operation_kind, "runtime.diagnostics_repair_policy.projection");
  assert.equal(result.repair_policy.policy_id, "policy_alpha");
  assert.equal(result.repair_policy_config.restore_policy, "preview_only");
  assert.deepEqual(result.receipt_refs, ["receipt_runtime_diagnostics_repair_policy_projection"]);
  assert.equal(Object.hasOwn(result, "repairPolicy"), false);

  assert.throws(
    () =>
      normalizeRuntimeDiagnosticsRepairPolicyResult({
        record: {
          operation_kind: "runtime.diagnostics_repair_policy.retired",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_diagnostics_repair_policy_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("diagnostics operator override state update core sends Rust state update through direct runtime-control API", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_API_METHOD,
    () => ({
            source: "rust_diagnostics_operator_override_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "diagnostics.operator_override.event",
            updated_at: "2026-06-06T04:15:00.000Z",
            operator_control: {
              control: "diagnostics_operator_override",
              decision_id: "decision_override",
              event_id: "event_override",
              approval_required: true,
              approval_satisfied: true,
              authority_hash: "sha256:diagnostics-operator-override-authority",
              wallet_network_grant_refs: [
                "wallet.network://grant/diagnostics/operator-override",
              ],
              authority_receipt_refs: [
                "receipt://wallet.network/diagnostics/operator-override",
              ],
            },
            run: {
              id: "run_blocked",
              status: "completed",
              diagnosticsBlockingGate: { status: "overridden" },
              trace: {
                operatorControls: [
                  {
                    control: "diagnostics_operator_override",
                    event_id: "event_override",
                  },
                ],
              },
            },
          }),
  );

  const result = runner.planDiagnosticsOperatorOverrideStateUpdate({
    thread_id: "thread_budget",
    run_id: "run_blocked",
    run: { id: "run_blocked", status: "blocked", trace: {} },
    event_id: "event_override",
    seq: 10,
    created_at: "2026-06-06T04:15:00.000Z",
    decision_id: "decision_override",
    gate_event_id: "event_gate",
    source: "runtime_auto",
    operator_override_request: {
      operator_override_approval: "override",
    },
    decision: {
      requires_approval: true,
    },
    repair_policy: {
      operator_override_requires_approval: true,
    },
    authority_grant_refs: [
      "wallet.network://grant/diagnostics/operator-override",
    ],
    authority_receipt_refs: [
      "receipt://wallet.network/diagnostics/operator-override",
    ],
    policy_decision_refs: ["policy_diagnostics_operator_override"],
    authority_context: {},
    snapshot_id: "snapshot_alpha",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.decision_id, "decision_override");
  assert.equal(calls[0].request.operator_override_request.operator_override_approval, "override");
  assert.equal(calls[0].request.decision.requires_approval, true);
  assert.equal(calls[0].request.repair_policy.operator_override_requires_approval, true);
  assert.deepEqual(calls[0].request.authority_grant_refs, [
    "wallet.network://grant/diagnostics/operator-override",
  ]);
  assert.deepEqual(calls[0].request.authority_receipt_refs, [
    "receipt://wallet.network/diagnostics/operator-override",
  ]);
  assert.deepEqual(calls[0].request.policy_decision_refs, ["policy_diagnostics_operator_override"]);
  for (const field of ["approval_required", "approval_satisfied", "approval_source"]) {
    assert.equal(Object.hasOwn(calls[0].request, field), false);
  }
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_diagnostics_operator_override_state_update_api");
  assert.equal(result.operation_kind, "diagnostics.operator_override.event");
  assert.equal(result.operator_control.decision_id, "decision_override");
  assert.equal(result.operator_control.authority_hash, "sha256:diagnostics-operator-override-authority");
  for (const field of [
    "decisionId",
    "gateEventId",
    "approvalRequired",
    "approvalSatisfied",
    "approvalSource",
    "snapshotId",
    "eventId",
    "createdAt",
  ]) {
    assert.equal(Object.hasOwn(result.operator_control, field), false);
  }
  assert.equal(result.run.trace.operatorControls[0].event_id, "event_override");
});

test("coding-tool result envelope core sends Rust daemon-core plan request", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_CODING_TOOL_RESULT_ENVELOPE_API_METHOD,
    () => ({
        source: "rust_coding_tool_result_envelope_plan_api",
        backend: "rust_runtime_coding_tool_event",
        planned: true,
        phase: "result_event",
        operation_kind: "runtime.coding_tool.result_envelope",
        step_module_context: {
          thread_id: "thread_alpha",
          workflow_node_id: "node_status",
          workflow_projection_status: "live",
        },
        event: {
          event_stream_id: "thread_alpha:events",
          thread_id: "thread_alpha",
          tool_call_id: "tool_status",
          payload_schema_version: "ioi.runtime.coding-tool-result.v1",
          payload_summary: {
            schema_version: "ioi.runtime.coding-tool-result.v1",
            tool_name: "workspace.status",
          },
        },
        record: {
          schema_version: "ioi.runtime.coding-tool-result-envelope-plan.v1",
          object: "ioi.runtime_coding_tool_result_envelope_plan",
          status: "planned",
          operation_kind: "runtime.coding_tool.result_envelope",
          phase: "result_event",
        },
        envelope_hash: "sha256:envelope",
      }),
  );

  const result = runner.planCodingToolResultEnvelope({
    phase: "result_event",
    event_stream_id: "thread_alpha:events",
    thread_id: "thread_alpha",
    tool_id: "workspace.status",
    tool_call_id: "tool_status",
    workflow_node_id: "node_status",
    idempotency_key: "thread:thread_alpha:coding-tool:tool_status",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_CODING_TOOL_RESULT_ENVELOPE_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    CODING_TOOL_RESULT_ENVELOPE_PLAN_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(calls[0].request.tool_id, "workspace.status");
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_coding_tool_result_envelope_plan_api");
  assert.equal(result.operation_kind, "runtime.coding_tool.result_envelope");
  assert.equal(result.phase, "result_event");
  assert.equal(result.planned, true);
  assert.equal(result.step_module_context.workflow_projection_status, "live");
  assert.equal(result.event.payload_summary.tool_name, "workspace.status");
  assert.equal(result.envelope_hash, "sha256:envelope");
});

test("coding-tool artifact draft core sends Rust daemon-core plan request", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_CODING_TOOL_ARTIFACT_DRAFTS_API_METHOD,
    () => ({
        source: "rust_runtime_coding_tool_artifact_draft_plan_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_coding_tool_artifact_draft_plan",
          status: "planned",
          operation: "coding_tool_artifact_draft_materialization",
          operation_kind: "artifact.coding_tool_draft",
          thread_id: "thread_alpha",
          tool_name: "git.diff",
          tool_call_id: "tool_diff",
          workspace_root: "/workspace",
          receipt_id: "receipt_alpha",
          artifact_records: [
            {
              schema_version: "ioi.runtime.coding-tool-artifact.v1",
              id: "artifact_rust_planned",
              thread_id: "thread_alpha",
              tool_name: "git.diff",
              tool_call_id: "tool_diff",
              channel: "stdout",
              content: "diff body",
              receipt_refs: ["receipt_alpha"],
            },
          ],
          artifact_refs: ["artifact_rust_planned"],
          receipt_refs: ["receipt_alpha"],
          evidence_refs: ["coding_tool_artifact_draft_rust_owned"],
          plan_hash: "sha256:artifact-plan",
        },
      }),
  );

  const result = runner.planRuntimeCodingToolArtifactDrafts({
    operation: "coding_tool_artifact_draft_materialization",
    operation_kind: "artifact.coding_tool_draft",
    thread_id: "thread_alpha",
    tool_id: "git.diff",
    tool_call_id: "tool_diff",
    workspace_root: "/workspace",
    receipt_id: "receipt_alpha",
    artifact_drafts: [{ channel: "stdout", content: "diff body" }],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_CODING_TOOL_ARTIFACT_DRAFTS_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    RUNTIME_CODING_TOOL_ARTIFACT_DRAFT_PLAN_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(calls[0].request.tool_id, "git.diff");
  assert.equal(calls[0].request.artifact_drafts[0].content, "diff body");
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_runtime_coding_tool_artifact_draft_plan_api");
  assert.equal(result.operation_kind, "artifact.coding_tool_draft");
  assert.equal(result.artifact_records[0].id, "artifact_rust_planned");
  assert.deepEqual(result.artifact_refs, ["artifact_rust_planned"]);
  assert.equal(result.plan_hash, "sha256:artifact-plan");
  assert.equal(Object.hasOwn(result, "operationKind"), false);
});

test("coding-tool artifact draft normalizer rejects missing Rust records", () => {
  assert.throws(
    () =>
      normalizeRuntimeCodingToolArtifactDraftPlanResult({
        record: {
          operation_kind: "artifact.coding_tool_draft",
          artifact_records: [],
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_coding_tool_artifact_draft_plan_records_missing");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("coding-tool artifact read projection core sends Rust daemon-core request", () => {
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_CODING_TOOL_ARTIFACT_READ_API_METHOD,
    () => ({
        source: "rust_runtime_coding_tool_artifact_read_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_coding_tool_artifact_read_projection",
          status: "projected",
          operation: "artifact.read",
          operation_kind: "artifact.read_projection",
          thread_id: "thread_alpha",
          query: {
            artifact_id: "artifact_rust",
            range: { offset_bytes: 0, length_bytes: 64 },
          },
          result: {
            schema_version: "ioi.runtime.coding-tool-artifact.v1",
            artifact_id: "artifact_rust",
            artifact_refs: ["artifact_rust"],
            content: "hello",
            receipt_refs: ["receipt_alpha"],
            shell_fallback_used: false,
          },
          artifact_refs: ["artifact_rust"],
          receipt_refs: ["receipt_alpha"],
          evidence_refs: ["coding_tool_artifact_read_projection_rust_owned"],
          projection_hash: "sha256:artifact-read-projection",
        },
      }),
  );

  const result = runner.projectRuntimeCodingToolArtifactRead({
    operation: "artifact.read",
    operation_kind: "artifact.read_projection",
    thread_id: "thread_alpha",
    artifact_id: "artifact_rust",
    range: { offset_bytes: 0, length_bytes: 64 },
    state_dir: "/runtime-state",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_CODING_TOOL_ARTIFACT_READ_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    RUNTIME_CODING_TOOL_ARTIFACT_READ_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(calls[0].request.artifact_id, "artifact_rust");
  assert.equal(calls[0].request.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(Object.hasOwn(calls[0].request, "artifact_records"), false);
  assert.equal(result.source, "rust_runtime_coding_tool_artifact_read_projection_api");
  assert.equal(result.operation_kind, "artifact.read_projection");
  assert.equal(result.result.content, "hello");
  assert.deepEqual(result.artifact_refs, ["artifact_rust"]);
  assert.equal(result.projection_hash, "sha256:artifact-read-projection");
  assert.equal(Object.hasOwn(result, "operationKind"), false);
});

test("coding-tool artifact read projection normalizer rejects missing Rust result", () => {
  assert.throws(
    () =>
      normalizeRuntimeCodingToolArtifactReadProjectionResult({
        record: {
          operation_kind: "artifact.read_projection",
          artifact_refs: ["artifact_rust"],
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_coding_tool_artifact_read_projection_result_missing");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("coding-tool result envelope normalizer rejects wrong operation kind", () => {
  assert.throws(
    () =>
      normalizeCodingToolResultEnvelopePlanResult({
        operation_kind: "runtime.coding_tool.result_event_compat",
        record: {
          operation_kind: "runtime.coding_tool.result_event_compat",
        },
      }),
    (error) => {
      assert.equal(error.code, "coding_tool_result_envelope_plan_operation_kind_mismatch");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("post-edit diagnostics feedback core sends Rust daemon-core plan request", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_POST_EDIT_DIAGNOSTICS_FEEDBACK_API_METHOD,
    () => ({
        source: "rust_post_edit_diagnostics_feedback_plan_api",
        backend: "rust_runtime_diagnostics_feedback",
        planned: true,
        request: {
          workflow_node_id: "runtime.coding-tool.lsp-diagnostics.auto",
          input: { paths: ["src/app.js"] },
        },
        record: {
          schema_version: "ioi.runtime.post-edit-diagnostics-feedback-plan.v1",
          object: "ioi.runtime_post_edit_diagnostics_feedback_plan",
          status: "planned",
          operation_kind: "runtime.post_edit_diagnostics_feedback",
          tool_id: "lsp.diagnostics",
          paths: ["src/app.js"],
          rollback_refs: ["snapshot_alpha"],
        },
      }),
  );

  const result = runner.planPostEditDiagnosticsFeedback({
    thread_id: "thread_alpha",
    turn_id: "turn_alpha",
    patch_tool_call_id: "patch_alpha",
    workflow_graph_id: "graph_alpha",
    request: { diagnostics_mode: "blocking" },
    input: { cwd: "/workspace" },
    patch_result: { changed_files: [{ path: "src/app.js" }] },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_POST_EDIT_DIAGNOSTICS_FEEDBACK_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.thread_id, "thread_alpha");
  assert.equal(calls[0].request.patch_tool_call_id, "patch_alpha");
  assert.deepEqual(calls[0].request.patch_result.changed_files, [{ path: "src/app.js" }]);
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_post_edit_diagnostics_feedback_plan_api");
  assert.equal(result.backend, "rust_runtime_diagnostics_feedback");
  assert.equal(result.operation_kind, "runtime.post_edit_diagnostics_feedback");
  assert.equal(result.planned, true);
  assert.deepEqual(result.paths, ["src/app.js"]);
  assert.deepEqual(result.request.input.paths, ["src/app.js"]);
});

test("post-edit diagnostics feedback plan normalizer preserves Rust-owned request envelope", () => {
  const result = normalizePostEditDiagnosticsFeedbackPlanResult({
    source: "rust_post_edit_diagnostics_feedback_plan_command",
    record: {
      status: "planned",
      operation_kind: "runtime.post_edit_diagnostics_feedback",
      tool_id: "lsp.diagnostics",
      request: {
        workflow_node_id: "runtime.coding-tool.lsp-diagnostics.auto",
        input: { paths: ["src/app.js"] },
      },
      diagnostics_repair_context: {
        source_tool_name: "file.apply_patch",
      },
      rollback_refs: ["snapshot_alpha"],
    },
  });

  assert.equal(result.status, "planned");
  assert.equal(result.planned, true);
  assert.equal(result.tool_id, "lsp.diagnostics");
  assert.deepEqual(result.request.input.paths, ["src/app.js"]);
  assert.equal(result.diagnostics_repair_context.source_tool_name, "file.apply_patch");
  assert.deepEqual(result.rollback_refs, ["snapshot_alpha"]);
});

test("operator turn control admission-required core sends Rust request through direct runtime-control API", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_API_METHOD,
    () => ({
            source: "rust_operator_turn_control_admission_required_api",
            backend: "rust_policy",
            record: {
              status: "rust_core_required",
              status_code: 501,
              code: "runtime_operator_turn_control_rust_core_required",
              message:
                "Operator turn control requires direct Rust daemon-core state admission and persistence.",
              details: {
                rust_core_boundary: "runtime.operator_turn_control",
                operation: "operator_interrupt",
                operation_kind: "turn.interrupt",
                thread_id: "thread_budget",
                turn_id: "turn_budget",
                requested_action: "cancel",
                evidence_refs: ["operator_interrupt_js_facade_retired"],
              },
            },
          }),
  );

  const result = runner.planOperatorTurnControlAdmissionRequired({
    operation: "operator_interrupt",
    operation_kind: "turn.interrupt",
    thread_id: "thread_budget",
    turn_id: "turn_budget",
    requested_action: "cancel",
    evidence_refs: ["operator_interrupt_js_facade_retired"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.operation_kind, "turn.interrupt");
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_operator_turn_control_admission_required_api");
  assert.equal(result.record.code, "runtime_operator_turn_control_rust_core_required");
  assert.equal(result.record.details.thread_id, "thread_budget");
  assert.equal(Object.hasOwn(result.record.details, "threadId"), false);
  assert.equal(Object.hasOwn(result.record.details, "operationKind"), false);
  assert.equal(Object.hasOwn(result.record.details, "requestedAction"), false);
});

test("operator interrupt state update core sends Rust state update through direct runtime-control API", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_OPERATOR_INTERRUPT_STATE_UPDATE_API_METHOD,
    () => ({
            source: "rust_operator_interrupt_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "turn.interrupt",
            updated_at: "2026-06-06T04:25:00.000Z",
            operator_control: {
              control: "interrupt",
              reason: "operator_stop",
              event_id: "event_interrupt",
            },
            stop_condition: {
              reason: "operator_interrupt",
            },
            run: {
              id: "run_budget",
              status: "canceled",
              turnStatus: "interrupted",
              trace: {
                operatorControls: [
                  {
                    control: "interrupt",
                    event_id: "event_interrupt",
                  },
                ],
              },
            },
          }),
  );

  const result = runner.planOperatorInterruptStateUpdate({
    thread_id: "thread_budget",
    turn_id: "turn_budget",
    run_id: "run_budget",
    run: { id: "run_budget", status: "running", trace: {} },
    event_id: "event_interrupt",
    seq: 11,
    created_at: "2026-06-06T04:25:00.000Z",
    source: "runtime_auto",
    reason: "operator_stop",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_OPERATOR_INTERRUPT_STATE_UPDATE_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.reason, "operator_stop");
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_operator_interrupt_state_update_api");
  assert.equal(result.operation_kind, "turn.interrupt");
  assert.equal(result.operator_control.reason, "operator_stop");
  assert.equal(result.operator_control.event_id, "event_interrupt");
  assert.equal(Object.hasOwn(result.operator_control, "eventId"), false);
  assert.equal(Object.hasOwn(result.operator_control, "createdAt"), false);
  assert.equal(result.stop_condition.reason, "operator_interrupt");
  assert.equal(result.run.turnStatus, "interrupted");
  assert.equal(result.run.trace.operatorControls[0].event_id, "event_interrupt");
});

test("operator steer state update core sends Rust state update through direct runtime-control API", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_OPERATOR_STEER_STATE_UPDATE_API_METHOD,
    () => ({
            source: "rust_operator_steer_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "turn.steer",
            updated_at: "2026-06-06T04:35:00.000Z",
            operator_control: {
              control: "steer",
              guidance: "focus on the failing bridge assertion",
              event_id: "event_steer",
            },
            run: {
              id: "run_budget",
              status: "running",
              turnStatus: "running",
              trace: {
                operatorControls: [
                  {
                    control: "steer",
                    event_id: "event_steer",
                  },
                ],
              },
            },
          }),
  );

  const result = runner.planOperatorSteerStateUpdate({
    thread_id: "thread_budget",
    turn_id: "turn_budget",
    run_id: "run_budget",
    run: { id: "run_budget", status: "running", trace: {} },
    event_id: "event_steer",
    seq: 12,
    created_at: "2026-06-06T04:35:00.000Z",
    source: "react_flow",
    guidance: "focus on the failing bridge assertion",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_OPERATOR_STEER_STATE_UPDATE_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.guidance, "focus on the failing bridge assertion");
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_operator_steer_state_update_api");
  assert.equal(result.operation_kind, "turn.steer");
  assert.equal(result.operator_control.guidance, "focus on the failing bridge assertion");
  assert.equal(result.operator_control.event_id, "event_steer");
  assert.equal(Object.hasOwn(result.operator_control, "eventId"), false);
  assert.equal(Object.hasOwn(result.operator_control, "createdAt"), false);
  assert.equal(result.run.trace.operatorControls[0].event_id, "event_steer");
});

test("run cancel state update core sends Rust state update through direct runtime-control API", () => {
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_RUN_CANCEL_STATE_UPDATE_API_METHOD,
    () => ({
            source: "rust_run_cancel_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "run.cancel",
            updated_at: "2026-06-06T04:45:00.000Z",
            stop_condition: {
              reason: "marginal_improvement_too_low",
            },
            runtime_task: {
              taskId: "task_run_cancel_one",
              status: "canceled",
            },
            runtime_job: {
              jobId: "job_run_cancel_one",
              status: "canceled",
            },
            runtime_checklist: {
              checklistId: "checklist_run_cancel_one",
              status: "canceled",
            },
            run: {
              id: "run_cancel_one",
              status: "canceled",
              events: [
                { type: "delta" },
                { type: "runtime_task" },
                { type: "runtime_checklist" },
                { type: "job_canceled" },
                { type: "canceled" },
              ],
            },
          }),
  );

  const result = runner.planRunCancelStateUpdate({
    run_id: "run_cancel_one",
    run: { id: "run_cancel_one", status: "running", trace: {} },
    canceled_at: "2026-06-06T04:45:00.000Z",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_RUN_CANCEL_STATE_UPDATE_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.canceled_at, "2026-06-06T04:45:00.000Z");
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.source, "rust_run_cancel_state_update_api");
  assert.equal(result.operation_kind, "run.cancel");
  assert.equal(result.runtime_job.status, "canceled");
  assert.equal(result.run.events.at(-1).type, "canceled");
});

test("run cancel admission-required direct runtime-control API remains retired", () => {
  const runner = createRuntimeContextPolicyCore({
    daemonCoreRuntimeControlApi: {
      invoke() {
        assert.fail("Retired run-cancel admission-required API must not be invoked.");
      },
    },
  });

  assert.equal(
    Object.hasOwn(RuntimeContextPolicyCore.prototype, "planRunCancelAdmissionRequired"),
    false,
  );
  assert.equal(typeof runner.planRunCancelAdmissionRequired, "undefined");
});

test("runtime task job cancel core sends Rust state update through typed runtime-control API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_TASK_JOB_CANCEL_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_task_job_cancel_state_update_api",
        backend: "rust_policy",
        status: "planned",
        operation_kind: "task.cancel",
        cancel_kind: "task",
        task_id: "task_run_cancel_one",
        run_id: "run_cancel_one",
        updated_at: "2026-06-06T04:45:00.000Z",
        runtime_task: {
          taskId: "task_run_cancel_one",
          status: "canceled",
        },
        runtime_job: {
          jobId: "job_run_cancel_one",
          status: "canceled",
        },
        runtime_checklist: {
          checklistId: "checklist_run_cancel_one",
          status: "canceled",
        },
        run: {
          id: "run_cancel_one",
          status: "canceled",
          events: [{ type: "job_canceled" }, { type: "canceled" }],
          receipts: [{ id: "receipt_cancel" }],
          artifacts: [{ id: "artifact_cancel" }],
        },
      };
    },
  );

  const result = runner.planRuntimeTaskJobCancelStateUpdate({
    cancel_kind: "task",
    task_id: "task_run_cancel_one",
    run_id: "run_cancel_one",
    run: { id: "run_cancel_one", status: "running", trace: {} },
    canceled_at: "2026-06-06T04:45:00.000Z",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_TASK_JOB_CANCEL_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.cancel_kind, "task");
  assert.equal(captured.task_id, "task_run_cancel_one");
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_task_job_cancel_state_update_api");
  assert.equal(result.operation_kind, "task.cancel");
  assert.equal(result.cancel_kind, "task");
  assert.equal(result.task_id, "task_run_cancel_one");
  assert.equal(result.runtime_task.status, "canceled");
  assert.equal(result.run.status, "canceled");
});

test("runtime task job cancel normalizer accepts job cancel operation kind", () => {
  const result = normalizeRuntimeTaskJobCancelStateUpdateResult({
    source: "rust_runtime_task_job_cancel_state_update_api",
    backend: "rust_policy",
    record: {
      status: "planned",
      operation_kind: "job.cancel",
      cancel_kind: "job",
      job_id: "job_run_cancel_one",
      run_id: "run_cancel_one",
      runtime_job: { status: "canceled" },
      run: { id: "run_cancel_one", status: "canceled" },
    },
  });

  assert.equal(result.operation_kind, "job.cancel");
  assert.equal(result.cancel_kind, "job");
  assert.equal(result.job_id, "job_run_cancel_one");
  assert.equal(result.runtime_job.status, "canceled");
});

test("runtime task job create core sends Rust state update through typed runtime-control API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_TASK_JOB_CREATE_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_task_job_create_state_update_api",
        backend: "rust_policy",
        status: "planned",
        operation_kind: "task.create",
        task_id: "task_run_create_one",
        job_id: "job_run_create_one",
        run_id: "run_create_one",
        agent_id: "agent-one",
        created_at: "2026-06-06T04:45:00.000Z",
        updated_at: "2026-06-06T04:45:00.000Z",
        runtime_task: {
          taskId: "task_run_create_one",
          runId: "run_create_one",
          status: "completed",
        },
        runtime_job: {
          jobId: "job_run_create_one",
          status: "completed",
        },
        runtime_checklist: {
          checklistId: "checklist_run_create_one",
          status: "completed",
        },
        run: {
          id: "run_create_one",
          agentId: "agent-one",
          status: "completed",
        },
      };
    },
  );

  const result = runner.planRuntimeTaskJobCreateStateUpdate({
    agent_id: "agent-one",
    run: { id: "run_create_one", agentId: "agent-one", status: "completed" },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_TASK_JOB_CREATE_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.agent_id, "agent-one");
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_task_job_create_state_update_api");
  assert.equal(result.operation_kind, "task.create");
  assert.equal(result.task_id, "task_run_create_one");
  assert.equal(result.runtime_task.status, "completed");
  assert.equal(result.run.id, "run_create_one");
});

test("runtime task job create normalizer requires task create operation kind", () => {
  const result = normalizeRuntimeTaskJobCreateStateUpdateResult({
    source: "rust_runtime_task_job_create_state_update_api",
    backend: "rust_policy",
    record: {
      status: "planned",
      operation_kind: "task.create",
      task_id: "task_run_create_one",
      job_id: "job_run_create_one",
      run_id: "run_create_one",
      agent_id: "agent-one",
      runtime_task: { status: "completed" },
      runtime_job: { status: "completed" },
      runtime_checklist: { status: "completed" },
      run: { id: "run_create_one", status: "completed" },
    },
  });

  assert.equal(result.operation_kind, "task.create");
  assert.equal(result.task_id, "task_run_create_one");
  assert.equal(result.runtime_checklist.status, "completed");
});

test("runtime task job projection core sends Rust projection through typed runtime-projection API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_TASK_JOB_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_task_job_projection_api",
        backend: "rust_policy",
        status: "projected",
        operation_kind: "task.list",
        projection_kind: "task.list",
        agent_id: "agent-one",
        status_filter: "running",
        records: [
          {
            taskId: "task_run-one",
            runId: "run-one",
            agentId: "agent-one",
            status: "running",
          },
        ],
        record_count: 1,
      };
    },
  );

  const result = runner.projectRuntimeTaskJobProjection({
    projection_kind: "task.list",
    state_dir: "/tmp/ioi-runtime-state",
    agent_id: "agent-one",
    status: "running",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_TASK_JOB_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_TASK_JOB_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.projection_kind, "task.list");
  assert.equal(captured.state_dir, "/tmp/ioi-runtime-state");
  assert.equal(captured.agent_id, "agent-one");
  assert.equal(Object.hasOwn(captured, "runs"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_task_job_projection_api");
  assert.equal(result.operation_kind, "task.list");
  assert.equal(result.projection_kind, "task.list");
  assert.equal(result.records[0].taskId, "task_run-one");
  assert.equal(result.record_count, 1);
});

test("runtime task job projection normalizer accepts get operation kinds", () => {
  const taskResult = normalizeRuntimeTaskJobProjectionResult({
    source: "rust_runtime_task_job_projection_api",
    backend: "rust_policy",
    record: {
      status: "projected",
      operation_kind: "task.get",
      projection_kind: "task.get",
      task_id: "task_run-one",
      runtime_task: { taskId: "task_run-one", runId: "run-one" },
      records: [{ taskId: "task_run-one" }],
      record_count: 1,
    },
  });
  const jobResult = normalizeRuntimeTaskJobProjectionResult({
    source: "rust_runtime_task_job_projection_api",
    backend: "rust_policy",
    record: {
      status: "projected",
      operation_kind: "job.get",
      projection_kind: "job.get",
      job_id: "job_run-one",
      runtime_job: { jobId: "job_run-one", runId: "run-one" },
      records: [{ jobId: "job_run-one" }],
      record_count: 1,
    },
  });

  assert.equal(taskResult.operation_kind, "task.get");
  assert.equal(taskResult.runtime_task.taskId, "task_run-one");
  assert.equal(jobResult.operation_kind, "job.get");
  assert.equal(jobResult.runtime_job.jobId, "job_run-one");
});

test("skill hook registry projection core sends Rust daemon-core request", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_SKILL_HOOK_REGISTRY_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_skill_hook_registry_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_skill_hook_registry_projection",
          status: "projected",
          operation_kind: "skill_hook.registry.skills",
          registry_kind: "skills",
          workspace_root: "/workspace/project",
          projection: {
            schemaVersion: "ioi.agent-runtime.skills.v1",
            object: "ioi.agent_skill_registry_projection",
            status: "pass",
            skillCount: 1,
            skills: [{ id: "skill.repo", name: "Repo Cartographer" }],
          },
          skills: [{ id: "skill.repo", name: "Repo Cartographer" }],
          hooks: [],
          sources: [],
          record_count: 1,
          evidence_refs: ["rust_daemon_core_skill_hook_registry_projection"],
          receipt_refs: ["receipt_skill_hook_registry_projection_skills"],
        },
      };
    },
  );

  const result = runner.projectSkillHookRegistry({
    operation_kind: "skill_hook.registry.skills",
    registry_kind: "skills",
    workspace_root: "/workspace/project",
    home_dir: "/home/operator",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_SKILL_HOOK_REGISTRY_API_METHOD);
  assert.equal(
    captured.schema_version,
    SKILL_HOOK_REGISTRY_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(captured.operation_kind, "skill_hook.registry.skills");
  assert.equal(captured.registry_kind, "skills");
  assert.equal(captured.home_dir, "/home/operator");
  assert.equal(result.source, "rust_skill_hook_registry_projection_api");
  assert.equal(result.registry_kind, "skills");
  assert.equal(result.projection.skillCount, 1);
  assert.equal(result.skills[0].id, "skill.repo");
  assert.equal(Object.hasOwn(result, "operation"), false);
  assert.equal(Object.hasOwn(result, "registryKind"), false);

  assert.throws(
    () =>
      normalizeSkillHookRegistryProjectionResult({
        record: {
          operation_kind: "skill_hook.registry.retired",
          registry_kind: "skills",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "skill_hook_registry_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("repository workflow projection core sends Rust daemon-core request", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_REPOSITORY_WORKFLOW_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_repository_workflow_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_repository_workflow_projection",
          status: "projected",
          operation: "repository_workflow_pr_attempts",
          operation_kind: "repository_workflow.projection.pr_attempts",
          projection_kind: "pr_attempts",
          workspace_root: "/workspace/project",
          projection: [
            {
              schemaVersion: "ioi.agent-runtime.pr-attempt.v1",
              object: "ioi.pr_attempt",
              attemptId: "pr_attempt_one",
            },
          ],
          pr_attempt: {
            schemaVersion: "ioi.agent-runtime.pr-attempt.v1",
            object: "ioi.pr_attempt",
            attemptId: "pr_attempt_one",
          },
          repositories: [],
          record_count: 1,
          evidence_refs: ["runtime_repository_workflow_rust_projection"],
          receipt_refs: ["receipt_repository_workflow_projection_pr_attempts"],
        },
      };
    },
  );

  const result = runner.projectRepositoryWorkflow({
    operation: "repository_workflow_pr_attempts",
    operation_kind: "repository_workflow.projection.pr_attempts",
    projection_kind: "pr_attempts",
    workspace_root: "/workspace/project",
    evidence_refs: ["runtime_repository_workflow_rust_projection"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_REPOSITORY_WORKFLOW_API_METHOD);
  assert.equal(
    captured.schema_version,
    REPOSITORY_WORKFLOW_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.operation, "repository_workflow_pr_attempts");
  assert.equal(
    captured.operation_kind,
    "repository_workflow.projection.pr_attempts",
  );
  assert.equal(captured.projection_kind, "pr_attempts");
  assert.equal(
    result.source,
    "rust_repository_workflow_projection_api",
  );
  assert.equal(result.projection_kind, "pr_attempts");
  assert.equal(result.projection[0].attemptId, "pr_attempt_one");
  assert.equal(result.pr_attempt.attemptId, "pr_attempt_one");
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRepositoryWorkflowProjectionResult({
        record: {
          operation_kind: "repository_workflow.projection.retired",
          projection_kind: "pr_attempts",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "repository_workflow_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime tool catalog projection core sends Rust daemon-core request", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_TOOL_CATALOG_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_tool_catalog_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_tool_catalog_projection",
          status: "projected",
          operation: "runtime_tool_catalog",
          operation_kind: "runtime.tool_catalog.projection.tools",
          projection_kind: "tools",
          pack: "coding",
          workspace_root: "/workspace/project",
          tools: [{ stable_tool_id: "file.apply_patch", pack: "coding" }],
          record_count: 1,
          evidence_refs: ["rust_daemon_core_runtime_tool_catalog_projection"],
          receipt_refs: ["receipt_runtime_tool_catalog_projection_tools"],
        },
      };
    },
  );

  const result = runner.projectRuntimeToolCatalog({
    operation: "runtime_tool_catalog",
    operation_kind: "runtime.tool_catalog.projection.tools",
    projection_kind: "tools",
    pack: "coding",
    workspace_root: "/workspace/project",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_TOOL_CATALOG_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_TOOL_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), true);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_tool_catalog_projection_api");
  assert.equal(result.projection_kind, "tools");
  assert.equal(result.tools[0].stable_tool_id, "file.apply_patch");
  assert.equal(Object.hasOwn(result.tools[0], "stableToolId"), false);

  assert.throws(
    () =>
      normalizeRuntimeToolCatalogProjectionResult({
        record: {
          operation_kind: "runtime.tool_catalog.projection.retired",
          projection_kind: "tools",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_tool_catalog_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime lifecycle projection core sends Rust daemon-core request", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_LIFECYCLE_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_lifecycle_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_lifecycle_projection",
          status: "projected",
          operation: "runtime_lifecycle_projection",
          operation_kind: "runtime.lifecycle_projection.run_artifact",
          projection_kind: "run_artifact",
          agent_id: "agent_123",
          thread_id: "thread_123",
          turn_id: "turn_123",
          run_id: "run_123",
          artifact_ref: "artifact_123",
          workspace_root: "/workspace/project",
          projection: { id: "artifact_123", name: "trace.json" },
          record_count: 1,
          evidence_refs: ["runtime_lifecycle_rust_projection"],
          receipt_refs: ["receipt_runtime_lifecycle_projection_run_artifact"],
        },
      };
    },
  );

  const result = runner.projectRuntimeLifecycle({
    operation: "runtime_lifecycle_projection",
    operation_kind: "runtime.lifecycle_projection.run_artifact",
    projection_kind: "run_artifact",
    agent_id: "agent_123",
    thread_id: "thread_123",
    turn_id: "turn_123",
    run_id: "run_123",
    artifact_ref: "artifact_123",
    workspace_root: "/workspace/project",
    evidence_refs: ["runtime_lifecycle_rust_projection"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_LIFECYCLE_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_LIFECYCLE_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.operation, "runtime_lifecycle_projection");
  assert.equal(
    captured.operation_kind,
    "runtime.lifecycle_projection.run_artifact",
  );
  assert.equal(captured.projection_kind, "run_artifact");
  assert.equal(captured.agent_id, "agent_123");
  assert.equal(captured.thread_id, "thread_123");
  assert.equal(captured.turn_id, "turn_123");
  assert.equal(captured.run_id, "run_123");
  assert.equal(captured.artifact_ref, "artifact_123");
  assert.equal(
    result.source,
    "rust_runtime_lifecycle_projection_api",
  );
  assert.equal(result.projection_kind, "run_artifact");
  assert.equal(result.projection.id, "artifact_123");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeLifecycleProjectionResult({
        record: {
          operation_kind: "runtime.lifecycle_projection.retired",
          projection_kind: "run_artifact",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_lifecycle_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime doctor report projection core sends Rust daemon-core request", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_DOCTOR_REPORT_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_doctor_report_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_doctor_report_projection",
          status: "projected",
          operation: "runtime_doctor_report_projection",
          operation_kind: "runtime.doctor_report.projection",
          workspace_root: "/workspace/project",
          state_dir: "/state",
          report: {
            schemaVersion: "ioi.agent-runtime.doctor.v1",
            object: "ioi.agent_runtime_doctor_report",
            status: "degraded",
            readiness: "ready",
            evidenceRefs: ["rust_daemon_core_runtime_doctor_report_projection"],
          },
          record_count: 1,
          evidence_refs: ["rust_daemon_core_runtime_doctor_report_projection"],
          receipt_refs: ["receipt_runtime_doctor_report_projection"],
        },
      };
    },
  );

  const result = runner.projectRuntimeDoctorReport({
    operation: "runtime_doctor_report_projection",
    operation_kind: "runtime.doctor_report.projection",
    base_url: "http://daemon.test",
    workspace_root: "/workspace/project",
    state_dir: "/state",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_DOCTOR_REPORT_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_DOCTOR_REPORT_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.operation, "runtime_doctor_report_projection");
  assert.equal(captured.operation_kind, "runtime.doctor_report.projection");
  assert.equal(captured.state_dir, "/state");
  assert.equal(result.source, "rust_runtime_doctor_report_projection_api");
  assert.equal(result.report.schemaVersion, "ioi.agent-runtime.doctor.v1");
  assert.equal(result.report.evidenceRefs[0], "rust_daemon_core_runtime_doctor_report_projection");
  assert.equal(Object.hasOwn(result.report, "runtimeDoctorReport"), false);

  assert.throws(
    () =>
      normalizeRuntimeDoctorReportProjectionResult({
        record: {
          operation_kind: "runtime.doctor_report.retired_js_aggregate",
          report: {},
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_doctor_report_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime computer-use projection core sends Rust daemon-core request", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_COMPUTER_USE_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_computer_use_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_computer_use_projection",
          status: "projected",
          operation: "runtime_computer_use_projection",
          operation_kind: "runtime.computer_use.projection.browser_discovery",
          projection_kind: "browser_discovery",
          browser_discovery: {
            schema_version: "ioi.computer-use.browser-discovery.v1",
            object: "ioi.computer_use.browser_discovery_report",
            browser_process_count: 0,
            cdp_endpoint_count: 0,
            safety: { cdp_probe_enabled: request.include_cdp_probe },
          },
          record_count: 1,
          evidence_refs: ["rust_daemon_core_runtime_computer_use_projection"],
          receipt_refs: ["receipt_runtime_computer_use_projection_browser_discovery"],
        },
      };
    },
  );

  const result = runner.projectRuntimeComputerUse({
    operation: "runtime_computer_use_projection",
    operation_kind: "runtime.computer_use.projection.browser_discovery",
    projection_kind: "browser_discovery",
    workspace_root: "/workspace/project",
    state_dir: "/state",
    include_cdp_probe: false,
    include_tab_metadata: true,
    reveal_tab_titles: false,
    includeTabs: true,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_COMPUTER_USE_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_COMPUTER_USE_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(Object.hasOwn(captured, "includeTabs"), false);
  assert.equal(captured.operation, "runtime_computer_use_projection");
  assert.equal(captured.operation_kind, "runtime.computer_use.projection.browser_discovery");
  assert.equal(captured.projection_kind, "browser_discovery");
  assert.equal(captured.include_cdp_probe, false);
  assert.equal(captured.include_tab_metadata, true);
  assert.equal(result.source, "rust_runtime_computer_use_projection_api");
  assert.equal(result.browser_discovery.object, "ioi.computer_use.browser_discovery_report");
  assert.equal(result.browser_discovery.safety.cdp_probe_enabled, false);
  assert.equal(Object.hasOwn(result, "browserDiscovery"), false);

  assert.throws(
    () =>
      normalizeRuntimeComputerUseProjectionResult({
        record: {
          operation_kind: "runtime.computer_use.retired_js_browser_discovery",
          projection_kind: "browser_discovery",
          browser_discovery: {},
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_computer_use_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("studio intent frame projection core sends Rust daemon-core request", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_STUDIO_INTENT_FRAME_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_studio_intent_frame_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.studio_intent_frame_projection",
          status: "projected",
          operation: "studio_intent_frame_projection",
          operation_kind: "studio.intent_frame.projection",
          frame: {
            schemaVersion: "ioi.studio.intent-frame.v1",
            object: "ioi.studio_intent_frame",
            target: request.prompt,
            route_directive: "agent",
            execution_mode: request.execution_mode,
            decision_material: {
              source: "rust_studio_intent_frame_projection",
              matched_features: ["workspace_context_required"],
            },
          },
          record_count: 1,
          evidence_refs: ["rust_daemon_core_studio_intent_frame_projection"],
          receipt_refs: ["receipt_studio_intent_frame_projection"],
        },
      };
    },
  );

  const result = runner.projectStudioIntentFrame({
    operation: "studio_intent_frame_projection",
    operation_kind: "studio.intent_frame.projection",
    prompt: "Where are model providers registered in this repo?",
    execution_mode: "agent",
    executionMode: "ask",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_STUDIO_INTENT_FRAME_API_METHOD);
  assert.equal(
    captured.schema_version,
    STUDIO_INTENT_FRAME_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.operation, "studio_intent_frame_projection");
  assert.equal(captured.operation_kind, "studio.intent_frame.projection");
  assert.equal(captured.prompt, "Where are model providers registered in this repo?");
  assert.equal(captured.execution_mode, "agent");
  assert.equal(Object.hasOwn(captured, "executionMode"), false);
  assert.equal(result.source, "rust_studio_intent_frame_projection_api");
  assert.equal(result.frame.schemaVersion, "ioi.studio.intent-frame.v1");
  assert.equal(result.frame.decision_material.source, "rust_studio_intent_frame_projection");

  assert.throws(
    () =>
      normalizeStudioIntentFrameProjectionResult({
        record: {
          operation_kind: "studio.intent_frame.retired_js_resolver",
          frame: {},
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "studio_intent_frame_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime memory projection core sends Rust projection through typed Rust daemon-core thread-memory API", () => {
  let captured = null;
  const { calls, runner } = createThreadMemoryDirectCore(
    THREAD_MEMORY_RUNTIME_MEMORY_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_memory_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_memory_projection",
          status: "projected",
          operation: "runtime_memory_projection",
          operation_kind: "runtime.memory_projection.records",
          projection_kind: "records",
          agent_id: "agent_123",
          thread_id: "thread_123",
          workspace_root: "/workspace/project",
          projection: {
            schema_version: "ioi.agent-runtime.memory.v1",
            thread_id: "thread_123",
            agent_id: "agent_123",
            records: [{ id: "memory_123" }],
            total_matches: 1,
          },
          record_count: 1,
          evidence_refs: ["runtime_memory_public_projection_rust_owned"],
          receipt_refs: ["receipt_runtime_memory_projection_records"],
        },
      };
    },
  );

  const result = runner.projectRuntimeMemoryProjection({
    operation: "runtime_memory_projection",
    operation_kind: "runtime.memory_projection.records",
    projection_kind: "records",
    agent_id: "agent_123",
    thread_id: "thread_123",
    workspace_root: "/workspace/project",
    state_dir: "/runtime-state",
    filters: { query: "deploy", scope: null },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_MEMORY_RUNTIME_MEMORY_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_MEMORY_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.operation, "runtime_memory_projection");
  assert.notEqual(captured.operation, "project_runtime_memory_projection");
  assert.equal(captured.operation_kind, "runtime.memory_projection.records");
  assert.equal(captured.projection_kind, "records");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.deepEqual(captured.filters, { query: "deploy", scope: null });
  assert.equal(Object.hasOwn(captured, "projection"), false);
  assert.equal(result.source, "rust_runtime_memory_projection_api");
  assert.equal(result.projection_kind, "records");
  assert.equal(result.projection.records[0].id, "memory_123");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeMemoryProjectionResult({
        record: {
          operation_kind: "runtime.memory_projection.retired",
          projection_kind: "records",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_memory_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime memory command planner sends Rust command grammar through typed Rust daemon-core thread-memory API", () => {
  let captured = null;
  const { calls, runner } = createThreadMemoryDirectCore(
    THREAD_MEMORY_RUNTIME_MEMORY_COMMAND_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_memory_command_plan_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_memory_command_plan",
          status: "planned",
          operation: "runtime_memory_command_plan",
          operation_kind: "memory.run_command.plan",
          command_kind: "remember",
          thread_id: "thread_123",
          agent_id: "agent_123",
          command: {
            kind: "remember",
            text: "Remember release window",
          },
          evidence_refs: [
            "rust_daemon_core_memory_command_parser",
            "runtime_memory_command_parser_js_retired",
          ],
          receipt_refs: ["receipt_runtime_memory_command_plan"],
        },
      };
    },
  );

  const result = runner.planRuntimeMemoryCommand({
    operation: "runtime_memory_command_plan",
    operation_kind: "memory.run_command.plan",
    prompt: "#remember Remember release window",
    thread_id: "thread_123",
    agent_id: "agent_123",
    source: "runtime_run_memory_resolution",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_MEMORY_RUNTIME_MEMORY_COMMAND_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_MEMORY_COMMAND_PLAN_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.operation, "runtime_memory_command_plan");
  assert.equal(captured.operation_kind, "memory.run_command.plan");
  assert.equal(captured.prompt, "#remember Remember release window");
  assert.equal(result.source, "rust_runtime_memory_command_plan_api");
  assert.equal(result.command_kind, "remember");
  assert.deepEqual(result.command, {
    kind: "remember",
    text: "Remember release window",
  });
  assert.equal(
    result.evidence_refs.includes("runtime_memory_command_parser_js_retired"),
    true,
  );
  assert.equal(Object.hasOwn(result, "commandKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeMemoryCommandPlanResult({
        record: {
          operation_kind: "memory.run_command.plan",
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_memory_command_plan_command_missing");
      assert.equal(error.details.operation_kind, "memory.run_command.plan");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime memory control core sends Rust control through typed Rust daemon-core thread-memory API", () => {
  let captured = null;
  const { calls, runner } = createThreadMemoryDirectCore(
    THREAD_MEMORY_RUNTIME_MEMORY_CONTROL_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_memory_control_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_memory_control",
          status: "planned",
          operation: "write",
          operation_kind: "memory.write",
          memory_state_kind: "record",
          state_id: "memory_123",
          thread_id: "thread_123",
          agent_id: "agent_123",
          workspace_root: "/workspace/project",
          payload: {
            schema_version: "ioi.agent-runtime.memory.v1",
            object: "ioi.agent_memory_record",
            id: "memory_123",
            thread_id: "thread_123",
            agent_id: "agent_123",
            fact: "Remember release window",
            receipt_refs: ["receipt_memory_write"],
          },
          evidence_refs: ["runtime_memory_write_control_rust_owned"],
          receipt_refs: ["receipt_memory_write"],
        },
      };
    },
  );

  const result = runner.planRuntimeMemoryControl({
    operation: "write",
    operation_kind: "memory.write",
    thread_id: "thread_123",
    agent_id: "agent_123",
    workspace_root: "/workspace/project",
    state_dir: "/runtime-state",
    request: { text: "Remember release window" },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_MEMORY_RUNTIME_MEMORY_CONTROL_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.notEqual(captured.operation, "plan_runtime_memory_control");
  assert.equal(captured.operation_kind, "memory.write");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(captured.request.text, "Remember release window");
  assert.equal(Object.hasOwn(captured, "current_record"), false);
  assert.equal(Object.hasOwn(captured, "current_policy"), false);
  assert.equal(result.source, "rust_runtime_memory_control_api");
  assert.equal(result.operation_kind, "memory.write");
  assert.equal(result.memory_state_kind, "record");
  assert.equal(result.payload.id, "memory_123");
  assert.equal(result.receipt_refs[0], "receipt_memory_write");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeMemoryControlResult({
        record: {
          operation_kind: "memory.write",
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_memory_control_payload_missing");
      assert.equal(error.details.operation_kind, "memory.write");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime workflow-edit control core sends Rust request through typed runtime-control API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_WORKFLOW_EDIT_CONTROL_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_workflow_edit_control_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_workflow_edit_control",
          status: "planned",
          operation: "workflow_edit_proposal",
          operation_kind: "workflow.edit_proposed",
          thread_id: "thread_123",
          proposal_id: "proposal_123",
          control_status: "pending_approval",
          event: {
            event_stream_id: "thread_123:events",
            thread_id: "thread_123",
            turn_id: "turn_123",
            event_kind: "workflow.edit_proposed",
            source_event_kind: "WorkflowEdit.Proposed",
            receipt_refs: ["receipt_workflow_edit"],
          },
          evidence_refs: ["runtime_workflow_edit_proposal_control_rust_owned"],
          receipt_refs: ["receipt_workflow_edit"],
          policy_decision_refs: ["policy_workflow_edit"],
        },
      };
    },
  );

  const result = runner.planRuntimeWorkflowEditControl({
    operation: "workflow_edit_proposal",
    operation_kind: "workflow.edit_proposed",
    thread_id: "thread_123",
    event_stream_id: "thread_123:events",
    turn_id: "turn_123",
    proposal_id: "proposal_123",
    request: {
      workflow_patch: { nodes: [{ id: "node_123" }] },
      receipt_refs: ["receipt_request"],
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_WORKFLOW_EDIT_CONTROL_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_WORKFLOW_EDIT_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation_kind, "workflow.edit_proposed");
  assert.equal(captured.request.workflow_patch.nodes[0].id, "node_123");
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_workflow_edit_control_api");
  assert.equal(result.operation_kind, "workflow.edit_proposed");
  assert.equal(result.event.event_kind, "workflow.edit_proposed");
  assert.equal(result.receipt_refs[0], "receipt_workflow_edit");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeWorkflowEditControlResult({
        record: {
          operation_kind: "workflow.edit_proposed",
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_workflow_edit_control_event_missing");
      assert.equal(error.details.operation_kind, "workflow.edit_proposed");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime managed-session projection core sends Rust request through typed runtime-projection API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_MANAGED_SESSION_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_managed_session_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_managed_session_projection",
          status: "projected",
          operation: "managed_session_inspection",
          operation_kind: "managed_session.inspect",
          projection_kind: "list",
          thread_id: "thread_123",
          projection: [{ managed_session_id: "sandbox_browser:1", thread_id: "thread_123" }],
          record_count: 1,
          evidence_refs: ["runtime_managed_session_projection_rust_owned"],
          receipt_refs: ["receipt_runtime_managed_session_projection_list"],
        },
      };
    },
  );

  const result = runner.projectRuntimeManagedSessionProjection({
    operation: "managed_session_inspection",
    operation_kind: "managed_session.inspect",
    projection_kind: "list",
    thread_id: "thread_123",
    state_dir: "/runtime-state",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_MANAGED_SESSION_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation_kind, "managed_session.inspect");
  assert.equal(captured.projection_kind, "list");
  assert.equal(captured.thread_id, "thread_123");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(captured, "projection"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_managed_session_projection_api");
  assert.equal(result.operation_kind, "managed_session.inspect");
  assert.equal(result.projection[0].managed_session_id, "sandbox_browser:1");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeManagedSessionProjectionResult({
        record: {
          operation_kind: "managed_session.retired",
          projection_kind: "list",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_managed_session_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime managed-session control core sends Rust request through typed runtime-control API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_MANAGED_SESSION_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_managed_session_control_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_managed_session_control",
          status: "planned",
          operation: "managed_session_control",
          operation_kind: "managed_session.control",
          thread_id: "thread_123",
          managed_session_id: "sandbox_browser:1",
          control_state: "take_over",
          event: {
            event_stream_id: "thread_123:events",
            thread_id: "thread_123",
            event_kind: "managed_session.controlled",
            source_event_kind: "OperatorControl.ManagedSessionControl",
            receipt_refs: ["receipt_managed_session_control"],
          },
          evidence_refs: ["runtime_managed_session_control_rust_owned"],
          receipt_refs: ["receipt_managed_session_control"],
          policy_decision_refs: ["policy_managed_session_control"],
        },
      };
    },
  );

  const result = runner.planRuntimeManagedSessionControl({
    operation: "managed_session_control",
    operation_kind: "managed_session.control",
    thread_id: "thread_123",
    event_stream_id: "thread_123:events",
    state_dir: "/runtime-state",
    managed_session_id: "sandbox_browser:1",
    control_state: "take_over",
    request: { receipt_refs: ["receipt_request"] },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_MANAGED_SESSION_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_MANAGED_SESSION_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation_kind, "managed_session.control");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(captured.managed_session_id, "sandbox_browser:1");
  assert.equal(captured.control_state, "take_over");
  assert.equal(Object.hasOwn(captured, "managed_session"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_managed_session_control_api");
  assert.equal(result.operation_kind, "managed_session.control");
  assert.equal(result.event.event_kind, "managed_session.controlled");
  assert.equal(result.receipt_refs[0], "receipt_managed_session_control");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeManagedSessionControlResult({
        record: {
          operation_kind: "managed_session.control",
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_managed_session_control_event_missing");
      assert.equal(error.details.operation_kind, "managed_session.control");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime workspace-change projection core sends Rust request through typed runtime-projection API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_WORKSPACE_CHANGE_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_workspace_change_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_workspace_change_projection",
          status: "projected",
          operation: "workspace_change_inspection",
          operation_kind: "workspace_change.inspect",
          projection_kind: "list",
          thread_id: "thread_123",
          projection: [{ workspace_change_id: "workspace_change:file:1", thread_id: "thread_123" }],
          record_count: 1,
          evidence_refs: ["runtime_workspace_change_projection_rust_owned"],
          receipt_refs: ["receipt_runtime_workspace_change_projection_list"],
        },
      };
    },
  );

  const result = runner.projectRuntimeWorkspaceChangeProjection({
    operation: "workspace_change_inspection",
    operation_kind: "workspace_change.inspect",
    projection_kind: "list",
    thread_id: "thread_123",
    state_dir: "/runtime-state",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_WORKSPACE_CHANGE_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_WORKSPACE_CHANGE_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation_kind, "workspace_change.inspect");
  assert.equal(captured.projection_kind, "list");
  assert.equal(captured.thread_id, "thread_123");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(captured, "projection"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_workspace_change_projection_api");
  assert.equal(result.operation_kind, "workspace_change.inspect");
  assert.equal(result.projection[0].workspace_change_id, "workspace_change:file:1");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeWorkspaceChangeProjectionResult({
        record: {
          operation_kind: "workspace_change.retired",
          projection_kind: "list",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_workspace_change_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime workspace-change control core sends Rust request through typed runtime-control API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_WORKSPACE_CHANGE_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_workspace_change_control_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_workspace_change_control",
          status: "planned",
          operation: "workspace_change_control",
          operation_kind: "workspace_change.control",
          thread_id: "thread_123",
          workspace_change_id: "workspace_change:file:1",
          control_state: "accept",
          event: {
            event_stream_id: "thread_123:events",
            thread_id: "thread_123",
            event_kind: "workspace_change.controlled",
            source_event_kind: "OperatorControl.WorkspaceChangeControl",
            receipt_refs: ["receipt_workspace_change_control"],
          },
          evidence_refs: ["runtime_workspace_change_control_rust_owned"],
          receipt_refs: ["receipt_workspace_change_control"],
          policy_decision_refs: ["policy_workspace_change_control"],
        },
      };
    },
  );

  const result = runner.planRuntimeWorkspaceChangeControl({
    operation: "workspace_change_control",
    operation_kind: "workspace_change.control",
    thread_id: "thread_123",
    event_stream_id: "thread_123:events",
    state_dir: "/runtime-state",
    workspace_change_id: "workspace_change:file:1",
    control_state: "accept",
    request: { receipt_refs: ["receipt_request"] },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_WORKSPACE_CHANGE_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_WORKSPACE_CHANGE_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation_kind, "workspace_change.control");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(captured.workspace_change_id, "workspace_change:file:1");
  assert.equal(captured.control_state, "accept");
  assert.equal(Object.hasOwn(captured, "workspace_change"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_workspace_change_control_api");
  assert.equal(result.operation_kind, "workspace_change.control");
  assert.equal(result.event.event_kind, "workspace_change.controlled");
  assert.equal(result.receipt_refs[0], "receipt_workspace_change_control");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeWorkspaceChangeControlResult({
        record: {
          operation_kind: "workspace_change.control",
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_workspace_change_control_event_missing");
      assert.equal(error.details.operation_kind, "workspace_change.control");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime thread-fork control core sends Rust request through typed runtime-control API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_THREAD_FORK_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_thread_fork_control_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_thread_fork_control",
          status: "planned",
          operation: "thread_fork",
          operation_kind: "thread.fork",
          thread_id: "thread_123",
          forked_thread_id: "thread_fork_123",
          agent_id: "agent_fork_123",
          source_agent_id: "agent_123",
          agent: {
            id: "agent_fork_123",
            cwd: "/workspace",
            forkedFromThreadId: "thread_123",
          },
          thread: {
            thread_id: "thread_fork_123",
            agent_id: "agent_fork_123",
            event_stream_id: "thread_fork_123:events",
          },
          event: {
            event_stream_id: "thread_123:events",
            thread_id: "thread_123",
            event_kind: "thread.forked",
            source_event_kind: "OperatorControl.ThreadFork",
            receipt_refs: ["receipt_thread_fork_control"],
          },
          evidence_refs: ["runtime_thread_fork_control_rust_owned"],
          receipt_refs: ["receipt_thread_fork_control"],
          policy_decision_refs: ["policy_thread_fork_control_allow"],
        },
      };
    },
  );

  const result = runner.planRuntimeThreadForkControl({
    operation: "thread_fork",
    operation_kind: "thread.fork",
    thread_id: "thread_123",
    event_stream_id: "thread_123:events",
    source_thread: { thread_id: "thread_123", agent_id: "agent_123" },
    source_agent: { id: "agent_123", cwd: "/workspace" },
    request: { idempotency_key: "fork-key" },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_THREAD_FORK_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_THREAD_FORK_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation_kind, "thread.fork");
  assert.equal(captured.thread_id, "thread_123");
  assert.equal(captured.source_agent.id, "agent_123");
  assert.equal(captured.request.idempotency_key, "fork-key");
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_thread_fork_control_api");
  assert.equal(result.operation_kind, "thread.fork");
  assert.equal(result.agent.id, "agent_fork_123");
  assert.equal(result.thread.thread_id, "thread_fork_123");
  assert.equal(result.event.event_kind, "thread.forked");
  assert.equal(result.receipt_refs[0], "receipt_thread_fork_control");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeThreadForkControlResult({
        record: {
          operation_kind: "thread.fork",
          agent: { id: "agent_fork_123" },
          thread: { thread_id: "thread_fork_123" },
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_thread_fork_control_event_missing");
      assert.equal(error.details.operation_kind, "thread.fork");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime conversation artifact projection core sends Rust request through typed runtime-projection API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_CONVERSATION_ARTIFACT_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_conversation_artifact_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_conversation_artifact_projection",
          status: "projected",
          operation: "runtime_conversation_artifact_projection",
          operation_kind: "runtime.conversation_artifact_projection.list",
          projection_kind: "list",
          thread_id: "thread_123",
          artifact_id: null,
          projection: [{ id: "artifact_123", thread_id: "thread_123" }],
          record_count: 1,
          evidence_refs: ["runtime_conversation_artifact_read_projection_rust_owned"],
          receipt_refs: ["receipt_runtime_conversation_artifact_projection_list"],
        },
      };
    },
  );

  const result = runner.projectRuntimeConversationArtifactProjection({
    operation: "runtime_conversation_artifact_projection",
    operation_kind: "runtime.conversation_artifact_projection.list",
    projection_kind: "list",
    thread_id: "thread_123",
    state_dir: "/runtime-state",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_CONVERSATION_ARTIFACT_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_CONVERSATION_ARTIFACT_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation, "runtime_conversation_artifact_projection");
  assert.equal(
    captured.operation_kind,
    "runtime.conversation_artifact_projection.list",
  );
  assert.equal(captured.projection_kind, "list");
  assert.equal(captured.thread_id, "thread_123");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(captured, "projection"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_conversation_artifact_projection_api");
  assert.equal(result.projection_kind, "list");
  assert.equal(result.projection[0].id, "artifact_123");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeConversationArtifactProjectionResult({
        record: {
          operation_kind: "runtime.conversation_artifact_projection.retired",
          projection_kind: "list",
        },
      }),
    (error) => {
      assert.equal(
        error.code,
        "runtime_conversation_artifact_projection_operation_kind_mismatch",
      );
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime conversation artifact control core sends Rust request through typed runtime-control API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_CONVERSATION_ARTIFACT_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_conversation_artifact_control_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_conversation_artifact_control",
          status: "planned",
          operation: "conversation_artifact_create",
          operation_kind: "artifact.conversation.create",
          thread_id: "thread_123",
          artifact_id: "artifact_123",
          artifact: {
            id: "artifact_123",
            artifact_id: "artifact_123",
            thread_id: "thread_123",
            title: "Draft",
            receipt_refs: ["receipt_runtime_conversation_artifact_control"],
          },
          result: {
            status: "created",
            operation_kind: "artifact.conversation.create",
            artifact_id: "artifact_123",
          },
          evidence_refs: ["runtime_conversation_artifact_control_rust_owned"],
          receipt_refs: ["receipt_runtime_conversation_artifact_control"],
          policy_decision_refs: ["policy_runtime_conversation_artifact_control_allow"],
        },
      };
    },
  );

  const result = runner.planRuntimeConversationArtifactControl({
    operation: "conversation_artifact_create",
    operation_kind: "artifact.conversation.create",
    thread_id: "thread_123",
    request: {
      title: "Draft",
      idempotency_key: "artifact-key",
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_CONVERSATION_ARTIFACT_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation, "conversation_artifact_create");
  assert.equal(captured.operation_kind, "artifact.conversation.create");
  assert.equal(captured.thread_id, "thread_123");
  assert.equal(captured.request.idempotency_key, "artifact-key");
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_conversation_artifact_control_api");
  assert.equal(result.operation_kind, "artifact.conversation.create");
  assert.equal(result.artifact.id, "artifact_123");
  assert.equal(result.result.status, "created");
  assert.equal(result.receipt_refs[0], "receipt_runtime_conversation_artifact_control");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeConversationArtifactControlResult({
        record: {
          operation_kind: "artifact.conversation.create",
          result: { status: "created" },
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_conversation_artifact_control_artifact_missing");
      assert.equal(error.details.operation_kind, "artifact.conversation.create");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime subagent projection core sends Rust request through typed runtime-projection API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeProjectionDirectCore(
    RUNTIME_PROJECTION_SUBAGENT_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_subagent_projection_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_subagent_projection",
          status: "projected",
          operation: "runtime_subagent_projection",
          operation_kind: "runtime.subagent_projection.list",
          projection_kind: "list",
          thread_id: "thread_123",
          subagent_id: null,
          role: "reviewer",
          projection: [{ subagent_id: "subagent_123", parent_thread_id: "thread_123" }],
          record_count: 1,
          evidence_refs: ["runtime_subagent_read_projection_rust_owned"],
          receipt_refs: ["receipt_runtime_subagent_projection_list"],
        },
      };
    },
  );

  const result = runner.projectRuntimeSubagentProjection({
    operation: "runtime_subagent_projection",
    operation_kind: "runtime.subagent_projection.list",
    projection_kind: "list",
    thread_id: "thread_123",
    role: "reviewer",
    state_dir: "/runtime-state",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_PROJECTION_SUBAGENT_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_SUBAGENT_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation, "runtime_subagent_projection");
  assert.equal(captured.operation_kind, "runtime.subagent_projection.list");
  assert.equal(captured.projection_kind, "list");
  assert.equal(captured.thread_id, "thread_123");
  assert.equal(captured.role, "reviewer");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(captured, "projection"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_subagent_projection_api");
  assert.equal(result.projection_kind, "list");
  assert.equal(result.projection[0].subagent_id, "subagent_123");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeSubagentProjectionResult({
        record: {
          operation_kind: "runtime.subagent_projection.retired",
          projection_kind: "list",
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_subagent_projection_operation_kind_mismatch");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("runtime subagent wait control core sends Rust request through typed runtime-control API", () => {
  let captured = null;
  const { calls, runner } = createRuntimeControlDirectCore(
    RUNTIME_CONTROL_SUBAGENT_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_subagent_control_api",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_subagent_control",
          status: "planned",
          operation: "wait",
          operation_kind: "subagent.wait",
          thread_id: "thread_123",
          subagent_id: "subagent_123",
          control_status: "completed",
          event: {
            event_stream_id: "thread_123:events",
            thread_id: "thread_123",
            turn_id: "turn_123",
            event_kind: "subagent.wait_completed",
            source_event_kind: "OperatorControl.SubagentWait",
            receipt_refs: ["receipt_wait"],
          },
          evidence_refs: ["runtime_subagent_wait_control_rust_owned"],
          receipt_refs: ["receipt_wait"],
          policy_decision_refs: ["policy_wait"],
        },
      };
    },
  );

  const result = runner.planRuntimeSubagentControl({
    operation: "wait",
    operation_kind: "subagent.wait",
    thread_id: "thread_123",
    event_stream_id: "thread_123:events",
    subagent: { subagent_id: "subagent_123", parent_thread_id: "thread_123" },
    request: { receipt_refs: ["receipt_request"] },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, RUNTIME_CONTROL_SUBAGENT_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_SUBAGENT_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.operation_kind, "subagent.wait");
  assert.equal(captured.subagent.subagent_id, "subagent_123");
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_runtime_subagent_control_api");
  assert.equal(result.operation_kind, "subagent.wait");
  assert.equal(result.event.event_kind, "subagent.wait_completed");
  assert.equal(result.receipt_refs[0], "receipt_wait");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeSubagentControlResult({
        record: {
          operation_kind: "subagent.wait",
        },
      }),
    (error) => {
      assert.equal(error.code, "runtime_subagent_control_event_missing");
      assert.equal(error.details.operation_kind, "subagent.wait");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});

test("thread control agent state update core sends Rust state update through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_THREAD_CONTROL_AGENT_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_thread_control_agent_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "thread.thinking",
            updated_at: "2026-06-06T05:00:00.000Z",
            receipt_refs: ["receipt_route_1"],
            control: {
              control_kind: "thinking",
              event_id: "evt_thread_control",
              receipt_refs: ["receipt_route_1"],
            },
            agent: {
              id: "agent_1",
              modelId: "local-model",
              receipt_refs: ["receipt_route_1"],
              runtimeControls: {
                model: {
                  selectedModel: "local-model",
                },
              },
            },
          };
    },
  );

  const result = runner.planThreadControlAgentStateUpdate({
    thread_id: "thread_1",
    agent: { id: "agent_1", runtimeControls: {} },
    control_kind: "thinking",
    controls: { model: { selectedModel: "local-model" } },
    event_id: "evt_thread_control",
    seq: 7,
    created_at: "2026-06-06T05:00:00.000Z",
    model_route: {
      requested_model_id: "auto",
      selected_model: "local-model",
      route_id: "route.local-first",
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_THREAD_CONTROL_AGENT_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.control_kind, "thinking");
  assert.equal(captured.model_route.selected_model, "local-model");
  assert.equal(captured.model_route.route_id, "route.local-first");
  for (const field of ["selectedModel", "requestedModelId", "routeId"]) {
    assert.equal(Object.hasOwn(captured.model_route, field), false);
  }
  assert.equal(result.source, "rust_thread_control_agent_state_update_api");
  assert.equal(result.operation_kind, "thread.thinking");
  assert.deepEqual(result.receipt_refs, ["receipt_route_1"]);
  assert.equal(result.control.control_kind, "thinking");
  assert.equal(result.control.event_id, "evt_thread_control");
  assert.deepEqual(result.control.receipt_refs, ["receipt_route_1"]);
  for (const field of [
    "controlKind",
    "eventId",
    "createdAt",
    "workspaceTrustWarningEventId",
    "receiptRefs",
  ]) {
    assert.equal(Object.hasOwn(result.control, field), false);
  }
  assert.equal(result.agent.modelId, "local-model");
});

test("workspace trust control state update core sends Rust state update through typed Rust daemon-core Agentgres API", () => {
  let captured = null;
  const { calls, runner } = createWorkspaceTrustDirectCore(
    WORKSPACE_TRUST_CONTROL_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_workspace_trust_control_state_update_api",
        backend: "rust_policy",
        status: "planned",
        operation_kind: "workspace_trust.acknowledge",
        thread_id: "thread_1",
        event_stream_id: "stream_thread_1",
        warning_id: "workspace_trust_warning_1",
        source_event_id: "evt_workspace_warning",
        receipt_refs: ["receipt_workspace_trust_ack_1"],
        policy_decision_refs: ["policy_workspace_trust_ack_1"],
        workspace_trust_acknowledgement: {
          warning_id: "workspace_trust_warning_1",
          status: "acknowledged",
        },
        event: {
          event_id: "evt_workspace_ack",
          thread_id: "thread_1",
          event_kind: "workspace.trust_acknowledged",
          receipt_refs: ["receipt_workspace_trust_ack_1"],
        },
      };
    },
  );

  const result = runner.planWorkspaceTrustControlStateUpdate({
    operation_kind: "workspace_trust.acknowledge",
    thread_id: "thread_1",
    event_stream_id: "stream_thread_1",
    agent: { id: "agent_1", cwd: "/workspace" },
    warning_id: "workspace_trust_warning_1",
    source_event_id: "evt_workspace_warning",
    events: [
      {
        event_id: "evt_workspace_warning",
        event_kind: "workspace.trust_warning",
        payload_summary: { warning_id: "workspace_trust_warning_1" },
        receipt_refs: ["receipt_workspace_trust_warning_1"],
      },
    ],
    created_at: "2026-06-06T05:00:01.000Z",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, WORKSPACE_TRUST_CONTROL_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.operation_kind, "workspace_trust.acknowledge");
  assert.equal(captured.warning_id, "workspace_trust_warning_1");
  assert.equal(result.source, "rust_workspace_trust_control_state_update_api");
  assert.equal(result.operation_kind, "workspace_trust.acknowledge");
  assert.equal(result.workspace_trust_acknowledgement.status, "acknowledged");
  assert.equal(result.event.event_kind, "workspace.trust_acknowledged");
  assert.deepEqual(result.receipt_refs, ["receipt_workspace_trust_ack_1"]);
});

test("thread turn admission-required core sends typed Rust daemon-core request", () => {
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_THREAD_TURN_ADMISSION_REQUIRED_API_METHOD,
    () => ({
      status: "rust_core_required",
      status_code: 501,
      code: "runtime_thread_turn_rust_core_required",
      message:
        "Thread resume and turn creation require direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.thread_turn",
        operation: "thread_turn_create",
        operation_kind: "turn.create",
        thread_id: "thread_1",
        agent_id: "agent_1",
        runtime_profile: "fixture",
        evidence_refs: ["thread_turn_create_js_run_creation_retired"],
      },
    }),
  );

  const result = runner.planThreadTurnAdmissionRequired({
    operation: "thread_turn_create",
    operation_kind: "turn.create",
    thread_id: "thread_1",
    agent_id: "agent_1",
    runtime_profile: "fixture",
    evidence_refs: ["thread_turn_create_js_run_creation_retired"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_THREAD_TURN_ADMISSION_REQUIRED_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.operation_kind, "turn.create");
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.code, "runtime_thread_turn_rust_core_required");
  assert.equal(result.details.thread_id, "thread_1");
  assert.equal(Object.hasOwn(result.details, "threadId"), false);
  assert.equal(Object.hasOwn(result.details, "operationKind"), false);
  assert.equal(Object.hasOwn(result.details, "runtimeProfile"), false);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
  assert.equal(Object.hasOwn(result, "record"), false);
});

test("lifecycle admission-required core sends typed Rust daemon-core request", () => {
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_LIFECYCLE_ADMISSION_REQUIRED_API_METHOD,
    () => ({
      status: "rust_core_required",
      status_code: 501,
      code: "runtime_agent_status_control_rust_core_required",
      message:
        "Agent lifecycle/status control requires direct Rust daemon-core admission and projection.",
      details: {
        rust_core_boundary: "runtime.agent_status_control",
        operation: "agent_status_control",
        operation_kind: "agent_status_update",
        agent_id: "agent_1",
        requested_status: "archived",
        requested_operation_kind: "agent.archive",
        evidence_refs: ["runtime_agent_status_control_js_facade_retired"],
      },
    }),
  );

  const result = runner.planLifecycleAdmissionRequired({
    operation: "agent_status_control",
    operation_kind: "agent_status_update",
    agent_id: "agent_1",
    requested_status: "archived",
    requested_operation_kind: "agent.archive",
    evidence_refs: ["runtime_agent_status_control_js_facade_retired"],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_LIFECYCLE_ADMISSION_REQUIRED_API_METHOD);
  assert.equal(
    calls[0].request.schema_version,
    LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(calls[0].request.operation_kind, "agent_status_update");
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(result.code, "runtime_agent_status_control_rust_core_required");
  assert.equal(result.details.agent_id, "agent_1");
  assert.equal(Object.hasOwn(result.details, "agentId"), false);
  assert.equal(Object.hasOwn(result.details, "operationKind"), false);
  assert.equal(Object.hasOwn(result.details, "requestedStatus"), false);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
  assert.equal(Object.hasOwn(result, "record"), false);
});

test("mcp control agent state update core sends Rust state update through typed Rust daemon-core MCP API", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_CONTROL_AGENT_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_mcp_control_agent_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "thread.mcp_add",
            updated_at: "2026-06-06T05:45:00.000Z",
            control: {
              control_kind: "mcp_add",
              event_id: "event_mcp_add",
            },
            agent: {
              id: "agent_1",
              updatedAt: "2026-06-06T05:45:00.000Z",
              mcpRegistry: {
                servers: [{ id: "mcp.docs" }],
              },
            },
          };
    },
  );

  const result = runner.planMcpControlAgentStateUpdate({
    thread_id: "thread_1",
    agent_id: "agent_1",
    state_dir: "/runtime-state",
    control_kind: "mcp_add",
    event_id: "event_mcp_add",
    seq: 5,
    created_at: "2026-06-06T05:45:00.000Z",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_CONTROL_AGENT_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.control_kind, "mcp_add");
  assert.equal(captured.agent_id, "agent_1");
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(captured, "agent"), false);
  assert.equal(result.source, "rust_mcp_control_agent_state_update_api");
  assert.equal(result.operation_kind, "thread.mcp_add");
  assert.equal(result.control.control_kind, "mcp_add");
  assert.equal(result.control.event_id, "event_mcp_add");
  assert.equal(Object.hasOwn(result.control, "controlKind"), false);
  assert.equal(Object.hasOwn(result.control, "eventId"), false);
  assert.equal(Object.hasOwn(result.control, "createdAt"), false);
  assert.equal(result.agent.mcpRegistry.servers[0].id, "mcp.docs");
});

test("MCP live-result replay sends typed Rust daemon-core MCP state replay request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_LIVE_RESULT_REPLAY_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_mcp_live_result_replay_api",
        backend: "rust_policy",
        schema_version: "ioi.runtime.mcp-live-result-replay.v1",
        object: "ioi.runtime_mcp_live_result_replay",
        status: "projected",
        result_count: 1,
        result_ids: ["result_runtime_mcp_live_exit"],
        latest_result: {
          schema_version: "ioi.runtime.mcp-live-result.v1",
          id: "result_runtime_mcp_live_exit",
          kind: "runtime_mcp_live_result",
          receipt_id: "receipt_runtime_mcp_live_exit",
        },
        results: [
          {
            schema_version: "ioi.runtime.mcp-live-result.v1",
            id: "result_runtime_mcp_live_exit",
            kind: "runtime_mcp_live_result",
            receipt_id: "receipt_runtime_mcp_live_exit",
          },
        ],
        replay_hash: "sha256:replay",
      };
    },
  );

  const result = runner.projectMcpLiveResultReplay({
    state_dir: "/runtime-state",
    result_id: "result_runtime_mcp_live_exit",
    receipt_id: "receipt_runtime_mcp_live_exit",
    thread_id: "thread_1",
    agent_id: "agent_1",
    control_kind: "mcp_invoke",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_LIVE_RESULT_REPLAY_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(captured.result_id, "result_runtime_mcp_live_exit");
  assert.equal(captured.receipt_id, "receipt_runtime_mcp_live_exit");
  assert.equal(result.source, "rust_mcp_live_result_replay_api");
  assert.equal(result.latest_result.id, "result_runtime_mcp_live_exit");
  assert.equal(result.replay_hash, "sha256:replay");
});

test("MCP live backend execution sends typed Rust daemon-core MCP backend request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_LIVE_BACKEND_EXECUTION_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_mcp_live_backend_execution_api",
        backend: "rust_policy",
        schema_version: "ioi.runtime.mcp-live-backend-execution.v1",
        object: "ioi.runtime_mcp_live_backend_execution",
        status: "rust_driver_executed",
        control_kind: "mcp_invoke",
        event_id: "event_mcp_invoke",
        thread_id: "thread_1",
        agent_id: "agent_1",
        server_id: "mcp.docs",
        tool_ref: "mcp.docs.search",
        backend_execution: {
          schema_version: "ioi.runtime.mcp-backend-execution.v1",
          status: "rust_driver_executed",
          owner: "ioi_drivers::mcp::McpManager",
          transport_owner: "ioi_drivers::mcp::transport::McpTransport",
          method: "tools/call",
          js_backend_execution: false,
          command_transport_fallback: false,
          binary_bridge_fallback: false,
          compatibility_fallback: false,
        },
        result: {
          schema_version: "ioi.runtime.mcp-live-result.v1",
          id: "result_runtime_mcp_live_exit",
          kind: "runtime_mcp_live_result",
          receipt_id: "receipt_runtime_mcp_live_exit",
          details: {
            runtime_mcp_live_backend_execution_status: "rust_driver_executed",
            runtime_mcp_live_backend_execution_required: true,
          },
        },
        evidence_refs: ["runtime_mcp_live_backend_rust_driver_executed"],
      };
    },
  );

  const result = runner.executeRuntimeMcpLiveBackend({
    state_dir: "/runtime-state",
    thread_id: "thread_1",
    agent_id: "agent_1",
    control_kind: "mcp_invoke",
    event_id: "event_mcp_invoke",
    server_id: "mcp.docs",
    tool_id: "mcp.docs.search",
    backend_execution: {
      schema_version: "ioi.runtime.mcp-backend-execution.v1",
      status: "rust_driver_contract_bound",
    },
    planned_result: {
      id: "result_runtime_mcp_live_exit",
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_LIVE_BACKEND_EXECUTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_LIVE_BACKEND_EXECUTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.state_dir, "/runtime-state");
  assert.equal(captured.control_kind, "mcp_invoke");
  assert.equal(captured.backend_execution.status, "rust_driver_contract_bound");
  assert.equal(result.source, "rust_mcp_live_backend_execution_api");
  assert.equal(result.status, "rust_driver_executed");
  assert.equal(result.backend_execution.status, "rust_driver_executed");
  assert.equal(result.result.id, "result_runtime_mcp_live_exit");
  assert.equal(
    result.result.details.runtime_mcp_live_backend_execution_status,
    "rust_driver_executed",
  );
});

test("MCP tool search projection sends typed Rust daemon-core MCP catalog search request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_TOOL_SEARCH_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_mcp_tool_search_projection_api",
        backend: "rust_policy",
        schema_version: "ioi.runtime.mcp-tool-search.v1",
        object: "ioi.runtime_mcp_tool_search",
        status: "completed",
        query: "diff",
        q: "diff",
        exact: false,
        live_discovery: false,
        rust_mcp_live_discovery_deferred: false,
        rust_mcp_live_discovery_materialized: false,
        server_count: 1,
        tool_count: 1,
        returned_count: 1,
        limit: 25,
        deferred: false,
        tools: [{ stable_tool_id: "mcp.agent.git.diff", server_id: "mcp.agent.git", tool_name: "diff" }],
        catalog_summaries: [],
        failures: [],
        routes: { get_tool: "/v1/threads/{thread_id}/mcp/tools/{tool_id}" },
        evidence_refs: ["runtime_mcp_tool_search_rust_projection"],
      };
    },
  );

  const result = runner.projectMcpToolSearchProjection({
    state_dir: "/runtime-state",
    thread_id: "thread_1",
    server_id: "mcp.agent.git",
    query: "diff",
    exact: false,
    live_discovery: false,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_TOOL_SEARCH_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.thread_id, "thread_1");
  assert.equal(captured.server_id, "mcp.agent.git");
  assert.equal(captured.query, "diff");
  assert.equal(Object.hasOwn(captured, "threadId"), false);
  assert.equal(Object.hasOwn(captured, "serverId"), false);
  assert.equal(result.source, "rust_mcp_tool_search_projection_api");
  assert.equal(result.tools[0].stable_tool_id, "mcp.agent.git.diff");
  assert.equal(result.returned_count, 1);
  assert.equal(result.rust_mcp_live_discovery_deferred, false);
  assert.equal(result.rust_mcp_live_discovery_materialized, false);
});

test("MCP tool fetch projection sends typed Rust daemon-core MCP fetch request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_TOOL_FETCH_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_mcp_tool_fetch_projection_api",
        backend: "rust_policy",
        schema_version: "ioi.runtime.mcp-tool-fetch.v1",
        object: "ioi.runtime_mcp_tool_fetch",
        status: "completed",
        tool_id: "mcp.agent.git.diff",
        server_id: "mcp.agent.git",
        tool_name: "diff",
        tool: { stable_tool_id: "mcp.agent.git.diff", server_id: "mcp.agent.git", tool_name: "diff" },
        tools: [{ stable_tool_id: "mcp.agent.git.diff", server_id: "mcp.agent.git", tool_name: "diff" }],
        returned_count: 1,
        search_projection: { object: "ioi.runtime_mcp_tool_search" },
        catalog_summaries: [],
        routes: { get_tool: "/v1/threads/{thread_id}/mcp/tools/{tool_id}" },
        evidence_refs: ["runtime_mcp_tool_fetch_rust_projection"],
      };
    },
  );

  const result = runner.projectMcpToolFetchProjection({
    state_dir: "/runtime-state",
    thread_id: "thread_1",
    server_id: "mcp.agent.git",
    tool_id: "mcp.agent.git.diff",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_TOOL_FETCH_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_TOOL_FETCH_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.tool_id, "mcp.agent.git.diff");
  assert.equal(captured.server_id, "mcp.agent.git");
  assert.equal(Object.hasOwn(captured, "toolId"), false);
  assert.equal(result.source, "rust_mcp_tool_fetch_projection_api");
  assert.equal(result.tool.stable_tool_id, "mcp.agent.git.diff");
  assert.equal(result.returned_count, 1);
});

test("MCP server validation core sends typed Rust daemon-core MCP validation request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_SERVER_VALIDATION_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_mcp_server_validation_api",
            backend: "rust_policy",
            status: "blocked",
            ok: false,
            issue_count: 1,
            warning_count: 0,
            issues: [
              {
                code: "mcp_secret_not_vault_ref",
                severity: "error",
                server_id: "mcp.secret",
                key: "Authorization",
                message: "MCP env/header secrets must be represented as vault:// refs before activation.",
              },
            ],
            warnings: [],
          };
    },
  );

  const result = runner.validateMcpServers({
    servers: [
      {
        id: "mcp.secret",
        transport: "stdio",
        command: "npx",
        secret_refs: {
          Authorization: { invalidVaultRef: true },
        },
      },
    ],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_SERVER_VALIDATION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.servers[0].secret_refs.Authorization.invalidVaultRef, true);
  assert.equal(result.source, "rust_mcp_server_validation_api");
  assert.equal(result.status, "blocked");
  assert.equal(result.ok, false);
  assert.equal(result.issue_count, 1);
  assert.equal(result.issues[0].server_id, "mcp.secret");
  assert.equal(Object.hasOwn(result.issues[0], "serverId"), false);
});

test("MCP server validation input core sends typed Rust daemon-core MCP projection request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_SERVER_VALIDATION_INPUT_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_mcp_server_validation_input_api",
            backend: "rust_policy",
            status: "projected",
            workspace_root: "/workspace",
            server_count: 1,
            servers: [
              {
                id: "mcp.docs",
                label: "docs",
                source_scope: "validation",
                workspace_root: "/workspace",
              },
            ],
          };
    },
  );

  const result = runner.projectMcpServerValidationInput({
    input: {
      mcp_json: {
        mcp_servers: {
          docs: { transport: "stdio", command: "npx" },
        },
      },
    },
    workspace_root: "/workspace",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_SERVER_VALIDATION_INPUT_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.workspace_root, "/workspace");
  assert.equal(captured.input.mcp_json.mcp_servers.docs.command, "npx");
  assert.equal(result.source, "rust_mcp_server_validation_input_api");
  assert.equal(result.status, "projected");
  assert.equal(result.server_count, 1);
  assert.equal(result.servers[0].source_scope, "validation");
  assert.equal(Object.hasOwn(result.servers[0], "sourceScope"), false);
});

test("runtime MCP serve tool-call planner sends Rust daemon-core request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_SERVE_TOOL_CALL_PLAN_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_mcp_serve_tool_call_plan_api",
        backend: "rust_policy",
        record: {
          schema_version: "ioi.runtime.mcp_serve_tool_call_plan.v1",
          object: "ioi.runtime_mcp_serve_tool_call_plan",
          status: "planned",
          operation: "runtime_mcp_serve_tool_call",
          operation_kind: "mcp.serve.tools.call",
          thread_id: "thread-one",
          tool_id: "git.diff",
          tool_name: "git.diff",
          method: "tools/call",
          tool_call_id: "mcp_serve_git_diff_hash",
          idempotency_key: "thread:thread-one:mcp-serve:mcp_serve_git_diff_hash",
          workflow_graph_id: "runtime.mcp_serve",
          workflow_node_id: "runtime.mcp_serve.git_diff",
          request_hash: "hash",
          request: {
            include_stat: true,
            source: "mcp_serve",
            tool_call_id: "mcp_serve_git_diff_hash",
            idempotency_key: "thread:thread-one:mcp-serve:mcp_serve_git_diff_hash",
            workflow_graph_id: "runtime.mcp_serve",
            workflow_node_id: "runtime.mcp_serve.git_diff",
            mcp_serve_request: {
              method: "tools/call",
              thread_id: "thread-one",
              tool_id: "git.diff",
            },
          },
          receipt_refs: ["receipt_runtime_mcp_serve_tool_call_plan_git_diff"],
          policy_decision_refs: ["policy_runtime_mcp_serve_tool_call_plan_git_diff"],
          evidence_refs: ["runtime_mcp_serve_tool_call_rust_owned"],
        },
      };
    },
  );

  const result = runner.planRuntimeMcpServeToolCall({
    thread_id: "thread-one",
    tool_id: "git.diff",
    tool_name: "git.diff",
    method: "tools/call",
    params: { name: "git.diff", arguments: { include_stat: true } },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_SERVE_TOOL_CALL_PLAN_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.params.arguments.include_stat, true);
  assert.equal(result.source, "rust_runtime_mcp_serve_tool_call_plan_api");
  assert.equal(result.operation_kind, "mcp.serve.tools.call");
  assert.equal(result.request.source, "mcp_serve");
  assert.equal(result.request.mcp_serve_request.method, "tools/call");
  assert.deepEqual(result.evidence_refs, ["runtime_mcp_serve_tool_call_rust_owned"]);
});

test("runtime MCP serve tool-call planner rejects missing Rust request envelope", () => {
  assert.throws(
    () =>
      normalizeRuntimeMcpServeToolCallPlanResult({
        source: "rust_runtime_mcp_serve_tool_call_plan_api",
        operation_kind: "mcp.serve.tools.call",
      }),
    (error) =>
      error instanceof RuntimeContextPolicyCoreError &&
      error.code === "runtime_mcp_serve_tool_call_plan_request_missing",
  );
});

test("runtime MCP serve tool-result projector sends Rust daemon-core projection request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_SERVE_TOOL_RESULT_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
        source: "rust_runtime_mcp_serve_tool_result_projection_api",
        backend: "rust_policy",
        record: {
          schema_version: "ioi.runtime.mcp_serve_tool_result_projection.v1",
          object: "ioi.runtime_mcp_serve_tool_result_projection",
          status: "projected",
          operation: "runtime_mcp_serve_tool_result",
          operation_kind: "mcp.serve.tools.result",
          thread_id: request.thread_id,
          tool_id: request.tool_id,
          tool_name: request.tool_name,
          tool_call_id: "call-one",
          workflow_graph_id: "runtime.mcp_serve",
          workflow_node_id: "runtime.mcp_serve.git_diff",
          event_id: "event-one",
          tool_status: "completed",
          result: {
            content: [{ type: "text", text: "git diff completed" }],
            structuredContent: {
              schema_version: "ioi.runtime.mcp-serve.test",
              object: "ioi.runtime_mcp_serve_tool_result",
              status: "completed",
              thread_id: request.thread_id,
              tool_name: request.tool_name,
              tool_call_id: "call-one",
              event_id: "event-one",
              receipt_refs: ["receipt-one"],
            },
            isError: false,
          },
          receipt_refs: ["receipt-one"],
          policy_decision_refs: ["policy-one"],
          evidence_refs: ["runtime_mcp_serve_tool_result_rust_owned"],
        },
      };
    },
  );

  const result = runner.projectRuntimeMcpServeToolResult({
    thread_id: "thread-one",
    tool_id: "git.diff",
    tool_name: "git.diff",
    jsonrpc_id: 7,
    plan: { thread_id: "thread-one", tool_id: "git.diff" },
    invocation: { status: "completed" },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_SERVE_TOOL_RESULT_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.invocation.status, "completed");
  assert.equal(result.source, "rust_runtime_mcp_serve_tool_result_projection_api");
  assert.equal(result.operation_kind, "mcp.serve.tools.result");
  assert.equal(result.result.structuredContent.event_id, "event-one");
  assert.deepEqual(result.evidence_refs, ["runtime_mcp_serve_tool_result_rust_owned"]);
});

test("runtime MCP serve tool-result projector rejects missing Rust result envelope", () => {
  assert.throws(
    () =>
      normalizeRuntimeMcpServeToolResultProjectionResult({
        source: "rust_runtime_mcp_serve_tool_result_projection_api",
        operation_kind: "mcp.serve.tools.result",
      }),
    (error) =>
      error instanceof RuntimeContextPolicyCoreError &&
      error.code === "runtime_mcp_serve_tool_result_projection_missing",
  );
});

test("MCP manager status projection core sends typed Rust daemon-core MCP projection request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_MANAGER_STATUS_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_mcp_manager_status_projection_api",
            backend: "rust_policy",
            schema_version: "ioi.runtime.mcp-manager-status.v1",
            object: "ioi.runtime_mcp_manager_status",
            status: "ready",
            server_count: 2,
            tool_count: 1,
            resource_count: 1,
            prompt_count: 1,
            enabled_server_count: 1,
            enabled_tool_count: 1,
            validation: {
              ok: true,
              server_count: 2,
              tools: [{ stable_tool_id: "mcp.docs.search" }],
            },
            routes: {
              search_tools: "/v1/threads/{thread_id}/mcp/tools/search",
            },
          };
    },
  );

  const result = runner.planMcpManagerStatusProjection({
    status_schema_version: "ioi.runtime.mcp-manager-status.v1",
    validation: { ok: true },
    servers: [{ id: "mcp.docs", enabled: true }, { id: "mcp.disabled", enabled: false }],
    tools: [{ stable_tool_id: "mcp.docs.search" }],
    resources: [{ uri: "mcp.docs://root" }],
    prompts: [{ name: "ask" }],
    routes: { search_tools: "/v1/threads/{thread_id}/mcp/tools/search" },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_MANAGER_STATUS_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.servers.length, 2);
  assert.equal(result.source, "rust_mcp_manager_status_projection_api");
  assert.equal(result.status, "ready");
  assert.equal(result.server_count, 2);
  assert.equal(result.enabled_server_count, 1);
  assert.equal(result.enabled_tool_count, 1);
  assert.equal(result.validation.server_count, 2);
  assert.equal(result.validation.tools[0].stable_tool_id, "mcp.docs.search");
  assert.equal(result.routes.search_tools, "/v1/threads/{thread_id}/mcp/tools/search");
  assert.equal(Object.hasOwn(result, "serverCount"), false);
  assert.equal(Object.hasOwn(result.routes, "searchTools"), false);
});

test("memory manager status projection core sends Rust projection through typed Rust daemon-core thread-memory API", () => {
  let captured = null;
  const { calls, runner } = createThreadMemoryDirectCore(
    THREAD_MEMORY_MANAGER_STATUS_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_memory_manager_status_projection_api",
            backend: "rust_policy",
            schema_version: "ioi.runtime.memory-manager-status.v1",
            object: "ioi.runtime_memory_manager_status",
            status: "ready",
            disabled: false,
            injection_enabled: true,
            read_only: false,
            write_requires_approval: true,
            write_blocked_reason: "memory_write_requires_approval",
            record_count: 1,
            scope_count: 1,
            memory_key_count: 1,
            scopes: ["thread"],
            memory_keys: ["project"],
            policy: { id: "policy.thread" },
            paths: { records_path: "/state/memory" },
            filters: {},
            records: [{ id: "memory.one" }],
            validation: { ok: true },
            routes: { status: "/v1/threads/{thread_id}/memory/status" },
            evidence_refs: ["runtime_memory_manager"],
          };
    },
  );

  const projection = { policy: { id: "policy.thread" }, records: [{ id: "memory.one" }] };
  const result = runner.planMemoryManagerStatusProjection({
    status_schema_version: "ioi.runtime.memory-manager-status.v1",
    projection,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_MEMORY_MANAGER_STATUS_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.deepEqual(captured.projection, projection);
  assert.equal(result.source, "rust_memory_manager_status_projection_api");
  assert.equal(result.status, "ready");
  assert.equal(result.write_requires_approval, true);
  assert.deepEqual(result.memory_keys, ["project"]);
  assert.equal(result.routes.status, "/v1/threads/{thread_id}/memory/status");
  assert.equal(Object.hasOwn(result, "memoryKeys"), false);
  assert.equal(Object.hasOwn(result, "writeRequiresApproval"), false);
});

test("memory manager validation projection core sends Rust projection through typed Rust daemon-core thread-memory API", () => {
  let captured = null;
  const { calls, runner } = createThreadMemoryDirectCore(
    THREAD_MEMORY_MANAGER_VALIDATION_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_memory_manager_validation_projection_api",
            backend: "rust_policy",
            schema_version: "ioi.runtime.memory-manager-validation.v1",
            object: "ioi.runtime_memory_manager_validation",
            ok: false,
            status: "blocked",
            issue_count: 1,
            warning_count: 0,
            record_count: 1,
            issues: [{ code: "memory_records_path_missing" }],
            warnings: [],
            policy: { id: "policy.thread" },
            paths: {},
            filters: {},
            records: [{ id: "memory.one" }],
          };
    },
  );

  const projection = { policy: { id: "policy.thread" }, records: [{ id: "memory.one" }] };
  const result = runner.planMemoryManagerValidationProjection({
    validation_schema_version: "ioi.runtime.memory-manager-validation.v1",
    projection,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_MEMORY_MANAGER_VALIDATION_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.deepEqual(captured.projection, projection);
  assert.equal(result.source, "rust_memory_manager_validation_projection_api");
  assert.equal(result.ok, false);
  assert.equal(result.issue_count, 1);
  assert.equal(result.issues[0].code, "memory_records_path_missing");
  assert.equal(Object.hasOwn(result, "issueCount"), false);
  assert.equal(Object.hasOwn(result, "recordCount"), false);
});

test("MCP manager catalog projection core sends typed Rust daemon-core MCP projection request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_MANAGER_CATALOG_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_mcp_manager_catalog_projection_api",
            backend: "rust_policy",
            schema_version: "ioi.runtime.mcp-manager-catalog-projection.v1",
            object: "ioi.runtime_mcp_manager_catalog_projection",
            status: "projected",
            server_count: 1,
            tool_count: 1,
            resource_count: 1,
            prompt_count: 1,
            enabled_tool_count: 1,
            tools: [{ stable_tool_id: "mcp.docs.search" }],
            resources: [{ stable_resource_id: "mcp.docs.resource.docs_index" }],
            prompts: [{ stable_prompt_id: "mcp.docs.prompt.summarize" }],
            enabled_tools: [{ stable_tool_id: "mcp.docs.search" }],
          };
    },
  );

  const result = runner.planMcpManagerCatalogProjection({
    servers: [{ id: "mcp.docs", enabled: true, allowed_tools: ["search"] }],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_MANAGER_CATALOG_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.servers.length, 1);
  assert.equal(result.source, "rust_mcp_manager_catalog_projection_api");
  assert.equal(result.status, "projected");
  assert.equal(result.tool_count, 1);
  assert.equal(result.enabled_tool_count, 1);
  assert.equal(result.tools[0].stable_tool_id, "mcp.docs.search");
  assert.equal(result.resources[0].stable_resource_id, "mcp.docs.resource.docs_index");
  assert.equal(result.prompts[0].stable_prompt_id, "mcp.docs.prompt.summarize");
  assert.equal(Object.hasOwn(result, "toolCount"), false);
  assert.equal(Object.hasOwn(result.tools[0], "stableToolId"), false);
});

test("MCP manager catalog summary projection core sends typed Rust daemon-core MCP projection request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_mcp_manager_catalog_summary_projection_api",
            backend: "rust_policy",
            schema_version: "ioi.runtime.mcp-catalog-summary.v1",
            object: "ioi.runtime_mcp_catalog_summary",
            status: "completed",
            server_id: "mcp.docs",
            server_label: "Docs",
            execution_mode: "declared_catalog",
            catalog_hash: "abc123",
            tool_count: 1,
            resource_count: 0,
            prompt_count: 0,
            namespace_count: 1,
            namespaces: ["search"],
            preview_limit: 25,
            preview_tool_names: ["search"],
            deferred: false,
            full_catalog_included: true,
            search_route: "/v1/threads/{thread_id}/mcp/tools/search",
            fetch_route: "/v1/threads/{thread_id}/mcp/tools/{tool_id}",
          };
    },
  );

  const result = runner.planMcpManagerCatalogSummaryProjection({
    server: { id: "mcp.docs", label: "Docs" },
    tools: [{ stable_tool_id: "mcp.docs.search", tool_name: "search" }],
    live_mode: "declared_catalog",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(result.source, "rust_mcp_manager_catalog_summary_projection_api");
  assert.equal(result.object, "ioi.runtime_mcp_catalog_summary");
  assert.equal(result.tool_count, 1);
  assert.equal(result.namespaces[0], "search");
  assert.equal(result.search_route, "/v1/threads/{thread_id}/mcp/tools/search");
  assert.equal(Object.hasOwn(result, "toolCount"), false);
  assert.equal(Object.hasOwn(result, "catalogHash"), false);
});

test("MCP manager validation projection core sends typed Rust daemon-core MCP projection request", () => {
  let captured = null;
  const { calls, runner } = createMcpDirectCore(
    MCP_MANAGER_VALIDATION_PROJECTION_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_mcp_manager_validation_projection_api",
            backend: "rust_policy",
            schema_version: "ioi.runtime.mcp-manager-validation.v1",
            object: "ioi.runtime_mcp_manager_validation",
            ok: false,
            status: "blocked",
            server_count: 1,
            tool_count: 1,
            resource_count: 1,
            prompt_count: 1,
            issue_count: 1,
            warning_count: 0,
            issues: [{ code: "invalid", server_id: "mcp.docs" }],
            warnings: [],
            servers: [{ id: "mcp.docs" }],
            tools: [{ stable_tool_id: "mcp.docs.search" }],
            resources: [{ uri: "docs://index" }],
            prompts: [{ name: "summarize" }],
          };
    },
  );

  const result = runner.planMcpManagerValidationProjection({
    validation_schema_version: "ioi.runtime.mcp-manager-validation.v1",
    validation: { ok: false, issues: [{ code: "invalid", server_id: "mcp.docs" }], warnings: [] },
    servers: [{ id: "mcp.docs" }],
    tools: [{ stable_tool_id: "mcp.docs.search" }],
    resources: [{ uri: "docs://index" }],
    prompts: [{ name: "summarize" }],
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, MCP_MANAGER_VALIDATION_PROJECTION_API_METHOD);
  assert.equal(
    captured.schema_version,
    MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.validation.ok, false);
  assert.equal(result.source, "rust_mcp_manager_validation_projection_api");
  assert.equal(result.status, "blocked");
  assert.equal(result.ok, false);
  assert.equal(result.server_count, 1);
  assert.equal(result.tool_count, 1);
  assert.equal(result.issue_count, 1);
  assert.equal(result.issues[0].server_id, "mcp.docs");
  assert.equal(result.tools[0].stable_tool_id, "mcp.docs.search");
  assert.equal(Object.hasOwn(result, "serverCount"), false);
  assert.equal(Object.hasOwn(result.tools[0], "stableToolId"), false);
});

test("MCP and memory manager projection core does not synthesize Rust-owned projection envelopes", () => {
  const mcpStatus = normalizeMcpManagerStatusProjectionApiResult({
    source: "legacy_mcp_status_projection_fixture",
    servers: [{ id: "mcp.docs" }],
    tools: [{ stable_tool_id: "mcp.docs.search" }],
  });
  assert.equal(mcpStatus.object, null);
  assert.equal(mcpStatus.status, null);
  assert.equal(mcpStatus.server_count, null);
  assert.equal(mcpStatus.tool_count, null);

  const mcpValidation = normalizeMcpManagerValidationProjectionApiResult({
    source: "legacy_mcp_validation_projection_fixture",
    ok: true,
    issues: [],
    warnings: [],
  });
  assert.equal(mcpValidation.object, null);
  assert.equal(mcpValidation.status, null);
  assert.equal(mcpValidation.issue_count, null);
  assert.equal(mcpValidation.warning_count, null);

  const memoryStatus = normalizeMemoryManagerStatusProjectionResult({
    source: "legacy_memory_status_projection_fixture",
    records: [{ id: "memory.one" }],
  });
  assert.equal(memoryStatus.object, null);
  assert.equal(memoryStatus.status, null);
  assert.equal(memoryStatus.injection_enabled, null);
  assert.equal(memoryStatus.record_count, null);

  const memoryValidation = normalizeMemoryManagerValidationProjectionResult({
    source: "legacy_memory_validation_projection_fixture",
    ok: false,
    issues: [{ code: "invalid" }],
    warnings: [],
  });
  assert.equal(memoryValidation.object, null);
  assert.equal(memoryValidation.status, null);
  assert.equal(memoryValidation.issue_count, null);
  assert.equal(memoryValidation.record_count, null);

  const mcpCatalog = normalizeMcpManagerCatalogProjectionApiResult({
    source: "legacy_mcp_catalog_projection_fixture",
    tools: [{ stable_tool_id: "mcp.docs.search" }],
    enabled_tools: [{ stable_tool_id: "mcp.docs.search" }],
  });
  assert.equal(mcpCatalog.object, null);
  assert.equal(mcpCatalog.status, null);
  assert.equal(mcpCatalog.tool_count, null);
  assert.equal(mcpCatalog.enabled_tool_count, null);

  const mcpSummary = normalizeMcpManagerCatalogSummaryProjectionApiResult({
    source: "legacy_mcp_summary_projection_fixture",
    namespaces: ["search"],
  });
  assert.equal(mcpSummary.object, null);
  assert.equal(mcpSummary.status, null);
  assert.equal(mcpSummary.namespace_count, null);
  assert.equal(mcpSummary.preview_limit, null);
  assert.equal(mcpSummary.search_route, null);
  assert.equal(mcpSummary.fetch_route, null);

  const mcpToolSearch = normalizeMcpToolSearchProjectionApiResult({
    source: "legacy_mcp_tool_search_fixture",
    tools: [{ stable_tool_id: "mcp.docs.search" }],
  });
  assert.equal(mcpToolSearch.object, null);
  assert.equal(mcpToolSearch.status, null);
  assert.equal(mcpToolSearch.tool_count, null);
  assert.equal(mcpToolSearch.returned_count, null);

  const mcpToolFetch = normalizeMcpToolFetchProjectionApiResult({
    source: "legacy_mcp_tool_fetch_fixture",
    tools: [{ stable_tool_id: "mcp.docs.search" }],
  });
  assert.equal(mcpToolFetch.object, null);
  assert.equal(mcpToolFetch.status, null);
  assert.equal(mcpToolFetch.returned_count, null);
});

test("thread memory agent state update core sends Rust state update through typed Rust daemon-core thread-memory API", () => {
  let captured = null;
  const { calls, runner } = createThreadMemoryDirectCore(
    THREAD_MEMORY_AGENT_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_thread_memory_agent_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "thread.memory_status",
            updated_at: "2026-06-06T06:05:00.000Z",
            control: {
              control_kind: "memory_status",
              event_id: "event_memory_status",
            },
            agent: {
              id: "agent_1",
              updatedAt: "2026-06-06T06:05:00.000Z",
            },
          };
    },
  );

  const result = runner.planThreadMemoryAgentStateUpdate({
    thread_id: "thread_1",
    agent: { id: "agent_1", cwd: "/workspace" },
    control_kind: "memory_status",
    event_id: "event_memory_status",
    seq: 6,
    created_at: "2026-06-06T06:05:00.000Z",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_MEMORY_AGENT_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.control_kind, "memory_status");
  assert.equal(result.source, "rust_thread_memory_agent_state_update_api");
  assert.equal(result.operation_kind, "thread.memory_status");
  assert.equal(result.control.control_kind, "memory_status");
  assert.equal(result.control.event_id, "event_memory_status");
  assert.equal(Object.hasOwn(result.control, "controlKind"), false);
  assert.equal(Object.hasOwn(result.control, "eventId"), false);
  assert.equal(Object.hasOwn(result.control, "createdAt"), false);
  assert.equal(result.agent.updatedAt, "2026-06-06T06:05:00.000Z");
});

test("runtime bridge thread start agent state update core sends Rust state update through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_runtime_bridge_thread_start_agent_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "thread.runtime_bridge.start",
            updated_at: "2026-06-06T06:15:00.000Z",
            bridge_start: {
              session_id: "session_runtime",
              bridge_id: "bridge_runtime",
              runtime_profile: "runtime_service",
              source: "runtime_service",
              updated_at: "2026-06-06T06:15:00.000Z",
            },
            agent: {
              id: "agent_1",
              runtime_session_id: "session_runtime",
              runtime_bridge_id: "bridge_runtime",
              runtime_profile: "runtime_service",
              runtime_bridge_source: "runtime_service",
              updatedAt: "2026-06-06T06:15:00.000Z",
            },
          };
    },
  );

  const result = runner.planRuntimeBridgeThreadStartAgentStateUpdate({
    thread_id: "thread_1",
    agent: { id: "agent_1", cwd: "/workspace" },
    runtime_profile: "runtime_service",
    session_id: "session_runtime",
    bridge_id: "bridge_runtime",
    status: "active",
    source: "runtime_service",
    updated_at: "2026-06-06T06:15:00.000Z",
  });

  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].method,
    THREAD_LIFECYCLE_RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_API_METHOD,
  );
  assert.equal(
    captured.schema_version,
    RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.session_id, "session_runtime");
  assert.equal(result.source, "rust_runtime_bridge_thread_start_agent_state_update_api");
  assert.equal(result.operation_kind, "thread.runtime_bridge.start");
  assert.equal(result.bridge_start.bridge_id, "bridge_runtime");
  for (const field of ["runtimeProfile", "sessionId", "bridgeId", "updatedAt"]) {
    assert.equal(Object.hasOwn(result.bridge_start, field), false);
  }
  assert.equal(result.agent.runtime_session_id, "session_runtime");
  assert.equal(result.agent.runtime_bridge_id, "bridge_runtime");
  assert.equal(result.agent.runtime_profile, "runtime_service");
  assert.equal(result.agent.runtime_bridge_source, "runtime_service");
  for (const field of [
    "runtimeProfile",
    "runtimeSessionId",
    "runtimeBridgeId",
    "runtimeBridgeStatus",
    "runtimeBridgeSource",
    "fixtureProfile",
  ]) {
    assert.equal(Object.hasOwn(result.agent, field), false);
  }
});

test("runtime bridge thread control agent state update core sends Rust state update through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_runtime_bridge_thread_control_agent_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "thread.runtime_bridge.control",
            updated_at: "2026-06-06T06:20:00.000Z",
            control: {
              action: "resume",
              runtime_bridge_status: "active",
              updated_at: "2026-06-06T06:20:00.000Z",
              evidence_refs: ["runtime_bridge_thread_control_rust_owned"],
            },
            agent: {
              id: "agent_1",
              status: "active",
              runtime_bridge_status: "active",
              updatedAt: "2026-06-06T06:20:00.000Z",
            },
          };
    },
  );

  const result = runner.planRuntimeBridgeThreadControlAgentStateUpdate({
    thread_id: "thread_1",
    agent: { id: "agent_1", cwd: "/workspace", runtime_profile: "runtime_service" },
    action: "resume",
    reason: "operator requested resume",
    updated_at: "2026-06-06T06:20:00.000Z",
    evidence_refs: ["runtime_bridge_thread_control_rust_owned"],
  });

  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].method,
    THREAD_LIFECYCLE_RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_API_METHOD,
  );
  assert.equal(
    captured.schema_version,
    RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.thread_id, "thread_1");
  assert.equal(captured.action, "resume");
  assert.equal(Object.hasOwn(captured, "threadId"), false);
  assert.equal(result.source, "rust_runtime_bridge_thread_control_agent_state_update_api");
  assert.equal(result.operation_kind, "thread.runtime_bridge.control");
  assert.equal(result.control.action, "resume");
  assert.equal(result.control.runtime_bridge_status, "active");
  assert.equal(Object.hasOwn(result.control, "runtimeBridgeStatus"), false);
  assert.equal(result.agent.status, "active");
  assert.equal(result.agent.runtime_bridge_status, "active");
  assert.equal(Object.hasOwn(result.agent, "runtimeBridgeStatus"), false);
});

test("runtime bridge lifecycle normalizers reject retired agent aliases", () => {
  assert.throws(
    () => normalizeRuntimeBridgeThreadStartAgentStateUpdateApiResult({
      status: "planned",
      operation_kind: "thread.runtime_bridge.start",
      agent: {
        id: "agent_1",
        runtimeProfile: "runtime_service",
        runtime_profile: "runtime_service",
      },
    }),
    (error) =>
      error.code === "runtime_bridge_thread_start_agent_state_update_retired_agent_aliases" &&
      error.details?.retired_aliases?.includes("runtimeProfile"),
  );

  assert.throws(
    () => normalizeRuntimeBridgeThreadControlAgentStateUpdateApiResult({
      status: "planned",
      operation_kind: "thread.runtime_bridge.control",
      agent: {
        id: "agent_1",
        runtimeBridgeStatus: "active",
        runtime_bridge_status: "active",
      },
    }),
    (error) =>
      error.code === "runtime_bridge_thread_control_agent_state_update_retired_agent_aliases" &&
      error.details?.retired_aliases?.includes("runtimeBridgeStatus"),
  );
});

test("runtime bridge turn run state update core sends Rust state update through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_runtime_bridge_turn_run_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "turn.runtime_bridge.submit",
            updated_at: "2026-06-06T06:35:00.000Z",
            run: {
              id: "run_runtime",
              agentId: "agent_1",
              status: "completed",
              updatedAt: "2026-06-06T06:35:00.000Z",
            },
          };
    },
  );

  const result = runner.planRuntimeBridgeTurnRunStateUpdate({
    thread_id: "thread_1",
    agent: { id: "agent_1", cwd: "/workspace" },
    run: {
      id: "run_runtime",
      agentId: "agent_1",
      mode: "send",
      status: "completed",
      createdAt: "2026-06-06T06:34:00.000Z",
      updatedAt: "2026-06-06T06:35:00.000Z",
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(Object.hasOwn(captured, "projection"), false);
  assert.equal(result.source, "rust_runtime_bridge_turn_run_state_update_api");
  assert.equal(result.operation_kind, "turn.runtime_bridge.submit");
  assert.equal(result.run.id, "run_runtime");
});

test("subagent record state update core sends Rust state update through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_SUBAGENT_RECORD_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_subagent_record_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "subagent.wait",
            updated_at: "2026-06-06T07:04:00.000Z",
            subagent: {
              subagent_id: "subagent_1",
              parent_thread_id: "thread_1",
              status: "completed",
              updated_at: "2026-06-06T07:04:00.000Z",
            },
          };
    },
  );

  const result = runner.planSubagentRecordStateUpdate({
    operation_kind: "subagent.wait",
    thread_id: "thread_1",
    subagent: {
      subagent_id: "subagent_1",
      parent_thread_id: "thread_1",
      status: "completed",
      updated_at: "2026-06-06T07:04:00.000Z",
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_SUBAGENT_RECORD_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.operation_kind, "subagent.wait");
  assert.equal(captured.subagent.subagent_id, "subagent_1");
  assert.equal(result.source, "rust_subagent_record_state_update_api");
  assert.equal(result.operation_kind, "subagent.wait");
  assert.equal(result.subagent.subagent_id, "subagent_1");
});

test("agent create state update core sends Rust state update through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_AGENT_CREATE_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_agent_create_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "agent.create",
            created_at: "2026-06-06T05:15:00.000Z",
            updated_at: "2026-06-06T05:15:00.000Z",
            agent: {
              id: "agent_create_one",
              status: "active",
            },
          };
    },
  );

  const result = runner.planAgentCreateStateUpdate({
    agent: {
      id: "agent_create_one",
      status: "active",
      createdAt: "2026-06-06T05:15:00.000Z",
      updatedAt: "2026-06-06T05:15:00.000Z",
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_AGENT_CREATE_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.agent.id, "agent_create_one");
  assert.equal(result.source, "rust_agent_create_state_update_api");
  assert.equal(result.operation_kind, "agent.create");
  assert.equal(result.agent.id, "agent_create_one");
});

test("thread create state update core sends Rust state update through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_THREAD_CREATE_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_thread_create_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "thread.create",
            thread_id: "thread_create_one",
            agent_id: "agent_create_one",
            created_at: "2026-06-06T05:15:00.000Z",
            updated_at: "2026-06-06T05:15:00.000Z",
            agent: {
              id: "agent_create_one",
              status: "active",
            },
            thread: {
              thread_id: "thread_create_one",
              agent_id: "agent_create_one",
              event_stream_id: "thread_create_one:events",
            },
          };
    },
  );

  const result = runner.planThreadCreateStateUpdate({
    agent: {
      id: "agent_create_one",
      status: "active",
      runtime: "local",
      cwd: "/workspace",
      runtimeControls: { mode: "agent" },
      createdAt: "2026-06-06T05:15:00.000Z",
      updatedAt: "2026-06-06T05:15:00.000Z",
    },
    thread: {
      thread_id: "thread_create_one",
      agent_id: "agent_create_one",
      event_stream_id: "thread_create_one:events",
      status: "active",
      created_at: "2026-06-06T05:15:00.000Z",
      updated_at: "2026-06-06T05:15:00.000Z",
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_THREAD_CREATE_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.agent.id, "agent_create_one");
  assert.equal(captured.thread.thread_id, "thread_create_one");
  assert.equal(result.source, "rust_thread_create_state_update_api");
  assert.equal(result.operation_kind, "thread.create");
  assert.equal(result.thread.thread_id, "thread_create_one");
  assert.equal(result.agent.id, "agent_create_one");
});

test("agent status state update core sends Rust state update through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_AGENT_STATUS_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_agent_status_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "agent.archive",
            updated_at: "2026-06-06T06:25:00.000Z",
            agent: {
              id: "agent_1",
              status: "archived",
              updatedAt: "2026-06-06T06:25:00.000Z",
            },
          };
    },
  );

  const result = runner.planAgentStatusStateUpdate({
    agent: { id: "agent_1", status: "active" },
    status: "archived",
    operation_kind: "agent.archive",
    updated_at: "2026-06-06T06:25:00.000Z",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_AGENT_STATUS_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.status, "archived");
  assert.equal(result.source, "rust_agent_status_state_update_api");
  assert.equal(result.operation_kind, "agent.archive");
  assert.equal(result.agent.status, "archived");
});

test("agent delete state update core sends Rust tombstone through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_AGENT_DELETE_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_agent_delete_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "agent.delete",
            deleted_at: "2026-06-06T06:40:00.000Z",
            updated_at: "2026-06-06T06:40:00.000Z",
            agent: {
              id: "agent_1",
              status: "deleted",
              deletedAt: "2026-06-06T06:40:00.000Z",
              updatedAt: "2026-06-06T06:40:00.000Z",
            },
          };
    },
  );

  const result = runner.planAgentDeleteStateUpdate({
    agent: { id: "agent_1", status: "active" },
    operation_kind: "agent.delete",
    deleted_at: "2026-06-06T06:40:00.000Z",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_AGENT_DELETE_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.operation_kind, "agent.delete");
  assert.equal(result.source, "rust_agent_delete_state_update_api");
  assert.equal(result.operation_kind, "agent.delete");
  assert.equal(result.agent.status, "deleted");
  assert.equal(result.agent.deletedAt, "2026-06-06T06:40:00.000Z");
});

test("run create state update core sends Rust state update through typed thread-lifecycle API", () => {
  let captured = null;
  const { calls, runner } = createThreadLifecycleDirectCore(
    THREAD_LIFECYCLE_RUN_CREATE_STATE_UPDATE_API_METHOD,
    (request) => {
      captured = request;
      return {
            source: "rust_run_create_state_update_api",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "run.create",
            created_at: "2026-06-06T05:16:00.000Z",
            updated_at: "2026-06-06T05:16:00.000Z",
            run: {
              id: "run_create_one",
              agentId: "agent_create_one",
              usage_telemetry: { total_tokens: 7 },
            },
          };
    },
  );

  const result = runner.planRunCreateStateUpdate({
    run: {
      id: "run_create_one",
      agentId: "agent_create_one",
      status: "completed",
      mode: "send",
      createdAt: "2026-06-06T05:16:00.000Z",
      updatedAt: "2026-06-06T05:16:00.000Z",
      usage: { total_tokens: 7 },
      usage_telemetry: { total_tokens: 7 },
      trace: { usage_telemetry: { total_tokens: 7 } },
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, THREAD_LIFECYCLE_RUN_CREATE_STATE_UPDATE_API_METHOD);
  assert.equal(
    captured.schema_version,
    RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(Object.hasOwn(captured, "operation"), false);
  assert.equal(Object.hasOwn(captured, "backend"), false);
  assert.equal(captured.run.id, "run_create_one");
  assert.equal(result.source, "rust_run_create_state_update_api");
  assert.equal(result.operation_kind, "run.create");
  assert.equal(result.run.usage_telemetry.total_tokens, 7);
});

test("runtime context lifecycle core fails closed without direct context lifecycle API", () => {
  const runner = new RuntimeContextPolicyCore();

  assert.throws(
    () => runner.evaluateContextBudgetPolicy({ usage_telemetry: { total_tokens: 1 } }),
    (error) => {
      assert.equal(error instanceof RuntimeContextPolicyCoreError, true);
      assert.equal(
        error.code,
        "runtime_context_policy_core_direct_context_lifecycle_api_unconfigured",
      );
      assert.equal(
        error.details.boundary,
        "daemonCoreContextLifecycleApi.evaluateContextBudgetPolicy",
      );
      return true;
    },
  );
});

test("runtime context policy state-update core fails closed without Rust-planned operation kinds", () => {
  assert.throws(
    () =>
      normalizeContextCompactionStateUpdateResult({
        status: "planned",
        target_kind: "agent",
        agent: { id: "agent_alpha" },
      }),
    (error) => {
      assert.equal(error.code, "context_compaction_state_update_operation_kind_missing");
      assert.equal(error.details.operation_kind, "thread.compact");
      assert.deepEqual(error.details.expected_operation_kinds, ["thread.compact"]);
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () =>
      normalizeOperatorInterruptStateUpdateApiResult({
        status: "planned",
        operation_kind: "turn.steer",
        run: { id: "run_alpha" },
      }),
    (error) => {
      assert.equal(error.code, "operator_interrupt_state_update_operation_kind_mismatch");
      assert.equal(error.details.expected_operation_kind, "turn.interrupt");
      assert.deepEqual(error.details.expected_operation_kinds, ["turn.interrupt"]);
      assert.equal(error.details.operation_kind, "turn.steer");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () =>
      normalizeThreadControlAgentStateUpdateApiResult({
        status: "planned",
        operation_kind: "agent.status",
        agent: { id: "agent_alpha" },
      }),
    (error) => {
      assert.equal(error.code, "thread_control_agent_state_update_operation_kind_mismatch");
      assert.equal(error.details.expected_prefix, "thread.");
      assert.equal(error.details.operation_kind, "agent.status");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () =>
      normalizeWorkspaceTrustControlStateUpdateResult({
        status: "planned",
        operation_kind: "thread.mode",
        event: { event_kind: "workspace.trust_warning" },
      }),
    (error) => {
      assert.equal(error.code, "workspace_trust_control_state_update_operation_kind_mismatch");
      assert.equal(error.details.expected_operation_kind, "workspace_trust.warning");
      assert.deepEqual(error.details.expected_operation_kinds, [
        "workspace_trust.warning",
        "workspace_trust.acknowledge",
      ]);
      assert.equal(error.details.operation_kind, "thread.mode");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () =>
      normalizeSubagentRecordStateUpdateApiResult({
        status: "planned",
        subagent: { id: "subagent_alpha" },
      }),
    (error) => {
      assert.equal(error.code, "subagent_record_state_update_operation_kind_missing");
      assert.equal(error.details.operation_kind, "subagent.");
      assert.equal(error.details.expected_prefix, "subagent.");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () =>
      normalizeAgentCreateStateUpdateApiResult({
        status: "planned",
        operation_kind: "run.create",
        agent: { id: "agent_alpha" },
      }),
    (error) => {
      assert.equal(error.code, "agent_create_state_update_operation_kind_mismatch");
      assert.equal(error.details.expected_operation_kind, "agent.create");
      assert.deepEqual(error.details.expected_operation_kinds, ["agent.create"]);
      assert.equal(error.details.operation_kind, "run.create");
      assertNoRetiredOperationKindDetailAliases(error.details);
      return true;
    },
  );
});
