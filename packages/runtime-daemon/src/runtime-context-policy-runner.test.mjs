import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_BLOCK_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_RESULT_ENVELOPE_PLAN_REQUEST_SCHEMA_VERSION,
  COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
  CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_POLICY_COMMAND_SCHEMA_VERSION,
  ContextPolicyRunnerError,
  DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION,
  DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
  MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
  MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
  MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
  OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_REQUEST_SCHEMA_VERSION,
  REPOSITORY_WORKFLOW_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_TOOL_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_LIFECYCLE_PROJECTION_REQUEST_SCHEMA_VERSION,
  RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION,
  RUNTIME_MEMORY_PROJECTION_REQUEST_SCHEMA_VERSION,
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
  RUN_CANCEL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_TASK_JOB_PROJECTION_REQUEST_SCHEMA_VERSION,
  RustContextPolicyRunner,
  SKILL_HOOK_REGISTRY_PROJECTION_REQUEST_SCHEMA_VERSION,
  SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  WORKFLOW_EDIT_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  createContextPolicyRunnerFromEnv,
  normalizeAgentCreateStateUpdateBridgeResult,
  normalizeAgentDeleteStateUpdateBridgeResult,
  normalizeAgentStatusStateUpdateBridgeResult,
  normalizeCodingToolBudgetBlockBridgeResult,
  normalizeCodingToolBudgetRecoveryStateUpdateBridgeResult,
  normalizeCodingToolResultEnvelopePlanBridgeResult,
  normalizeCompactionPolicyBridgeResult,
  normalizeContextBudgetPolicyBridgeResult,
  normalizeContextCompactionPlanBridgeResult,
  normalizeContextCompactionStateUpdateBridgeResult,
  normalizeDiagnosticsOperatorOverrideStateUpdateBridgeResult,
  normalizeMcpControlAgentStateUpdateBridgeResult,
  normalizeMcpManagerCatalogProjectionBridgeResult,
  normalizeMcpManagerCatalogSummaryProjectionBridgeResult,
  normalizeMcpManagerStatusProjectionBridgeResult,
  normalizeMcpManagerValidationProjectionBridgeResult,
  normalizeMemoryManagerStatusProjectionBridgeResult,
  normalizeMemoryManagerValidationProjectionBridgeResult,
  normalizeOperatorInterruptStateUpdateBridgeResult,
  normalizeOperatorSteerStateUpdateBridgeResult,
  normalizePostEditDiagnosticsFeedbackPlanBridgeResult,
  normalizeRunCancelStateUpdateBridgeResult,
  normalizeRuntimeTaskJobCancelStateUpdateBridgeResult,
  normalizeRuntimeTaskJobCreateStateUpdateBridgeResult,
  normalizeRuntimeTaskJobProjectionBridgeResult,
  normalizeRuntimeToolCatalogProjectionBridgeResult,
  normalizeRuntimeLifecycleProjectionBridgeResult,
  normalizeRuntimeMemoryControlBridgeResult,
  normalizeRuntimeMemoryProjectionBridgeResult,
  normalizeRuntimeDiagnosticsRepairProjectionBridgeResult,
  normalizeRuntimeDiagnosticsRepairPolicyBridgeResult,
  normalizeRuntimeWorkflowEditControlBridgeResult,
  normalizeRuntimeManagedSessionControlBridgeResult,
  normalizeRuntimeManagedSessionProjectionBridgeResult,
  normalizeRuntimeWorkspaceChangeControlBridgeResult,
  normalizeRuntimeWorkspaceChangeProjectionBridgeResult,
  normalizeRuntimeThreadForkControlBridgeResult,
  normalizeRuntimeConversationArtifactControlBridgeResult,
  normalizeRuntimeConversationArtifactProjectionBridgeResult,
  normalizeRuntimeSubagentControlBridgeResult,
  normalizeRuntimeSubagentProjectionBridgeResult,
  normalizeRepositoryWorkflowProjectionBridgeResult,
  normalizeSkillHookRegistryProjectionBridgeResult,
  normalizeRunCreateStateUpdateBridgeResult,
  normalizeRuntimeBridgeThreadStartAgentStateUpdateBridgeResult,
  normalizeRuntimeBridgeThreadControlAgentStateUpdateBridgeResult,
  normalizeRuntimeBridgeTurnRunStateUpdateBridgeResult,
  normalizeSubagentRecordStateUpdateBridgeResult,
  normalizeThreadCreateStateUpdateBridgeResult,
  normalizeThreadControlAgentStateUpdateBridgeResult,
  normalizeThreadMemoryAgentStateUpdateBridgeResult,
  normalizeWorkspaceTrustControlStateUpdateBridgeResult,
} from "./runtime-context-policy-runner.mjs";

function assertNoRetiredOperationKindDetailAliases(details) {
  for (const key of ["operationKind", "expectedOperationKind", "expectedOperationKinds", "expectedPrefix"]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
}

test("context policy runner env uses daemon-level direct invoker", () => {
  const calls = [];
  const runner = createContextPolicyRunnerFromEnv({
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired",
  }, {
    daemonCoreInvoker(request) {
      calls.push(request);
      return {
        source: "direct_daemon_core_api",
        backend: "rust_policy",
        status: "allowed",
        mode: "monitor",
        policy_decision_id: "policy_context_direct",
        policy_decision_refs: ["policy_context_direct"],
      };
    },
  });

  const result = runner.evaluateContextBudgetPolicy({
    usage_telemetry: { total_tokens: 1 },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].operation, "evaluate_context_budget_policy");
  assert.equal(result.source, "direct_daemon_core_api");
});

test("context policy runner rejects retired daemon-core command env", () => {
  assert.throws(
    () =>
      createContextPolicyRunnerFromEnv(
        {
          IOI_RUNTIME_DAEMON_CORE_COMMAND: "ioi-runtime-daemon-core",
        },
        {
          daemonCoreInvoker() {
            return {};
          },
        },
      ),
    (error) =>
      error instanceof ContextPolicyRunnerError &&
      error.code === "context_policy_command_selection_retired",
  );
});

test("context policy runner command args env fails closed", () => {
  assert.throws(
    () =>
      createContextPolicyRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--json",
      }),
    (error) =>
      error instanceof ContextPolicyRunnerError &&
      error.code === "context_policy_command_args_retired",
  );
});

test("context policy runner command args constructor option fails closed", () => {
  assert.throws(
    () => new RustContextPolicyRunner({ args: ["--json"] }),
    (error) =>
      error instanceof ContextPolicyRunnerError &&
      error.code === "context_policy_command_args_retired",
  );
});

test("context policy runner command constructor option fails closed", () => {
  assert.throws(
    () => new RustContextPolicyRunner({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof ContextPolicyRunnerError &&
      error.code === "context_policy_command_selection_retired",
  );
});

test("context budget policy runner sends generic Rust policy through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_context_budget_policy_command",
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
          };
    },
  });

  const result = runner.evaluateContextBudgetPolicy({
    usage_telemetry: { total_tokens: 120 },
    thresholds: { max_total_tokens: 100, warn_at_ratio: 0.8 },
    mode: "block",
    thread_id: "thread_1",
    turn_id: "turn_1",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "evaluate_context_budget_policy");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(captured.request.schema_version, CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.request.usage_telemetry.total_tokens, 120);
  assert.equal(result.source, "rust_context_budget_policy_command");
  assert.equal(result.status, "blocked");
  assert.equal(result.runtime_event_kind, "policy.blocked");
  assert.equal(result.runtime_event_status, "blocked");
  assert.equal(
    result.runtime_event_idempotency_key,
    "thread:thread_1:context-budget:policy_context_budget_thread_test_blocked",
  );
  assert.deepEqual(result.policy_decision_refs, ["policy_context_budget_thread_test_blocked"]);
});

test("coding tool budget runner sends Rust policy through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_coding_tool_budget_policy_command",
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
          };
    },
  });

  const result = runner.evaluateCodingToolBudgetPolicy({
    usage_telemetry: { total_tokens: 120 },
    thresholds: { max_total_tokens: 100, warn_at_ratio: 0.8 },
    mode: "block",
    thread_id: "thread_1",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "evaluate_coding_tool_budget_policy");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(captured.request.schema_version, CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.request.usage_telemetry.total_tokens, 120);
  assert.equal(result.source, "rust_coding_tool_budget_policy_command");
  assert.equal(result.status, "blocked");
  assert.deepEqual(result.policy_decision_refs, ["policy_context_budget_thread_test_blocked"]);
});

test("compaction policy runner sends Rust policy through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_compaction_policy_command",
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
          };
    },
  });

  const result = runner.evaluateCompactionPolicy({
    thread_id: "thread_1",
    context_budget: { status: "blocked" },
    actions: { blocked_action: "compact" },
    approval: { approval_required: true, approval_granted: false },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "evaluate_compaction_policy");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(captured.request.schema_version, COMPACTION_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.request.context_budget.status, "blocked");
  assert.equal(result.source, "rust_compaction_policy_command");
  assert.equal(result.action, "approval_required");
  assert.equal(result.approval_required, true);
  assert.equal(result.runtime_event_kind, "approval.required");
  assert.equal(result.runtime_event_status, "waiting");
  assert.equal(
    result.compact_idempotency_key,
    "thread:thread_1:compaction-policy:compact:policy_compaction_thread_test_waiting",
  );
});

test("context compaction runner sends Rust plan through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_context_compaction_plan_command",
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
          };
    },
  });

  const result = runner.planContextCompaction({
    thread_id: "thread_1",
    agent_id: "agent_1",
    run_id: "run_1",
    reason: "trim context",
    previous_latest_seq: 7,
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_context_compaction");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(captured.request.schema_version, CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.request.thread_id, "thread_1");
  assert.equal(result.source, "rust_context_compaction_plan_command");
  assert.equal(result.event_kind, "context.compacted");
  assert.equal(result.item_id, "turn_1:item:context-compact:hash_one");
  assert.deepEqual(result.receipt_refs, ["receipt_run_1_context_compaction_hash_one"]);
});

test("context compaction state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_context_compaction_state_update_command",
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
          };
    },
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_context_compaction_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.thread_id, "thread_1");
  assert.equal(captured.request.event_id, "event_1");
  assert.equal(result.source, "rust_context_compaction_state_update_command");
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

test("context lifecycle runners do not synthesize Rust-owned public fields", () => {
  const budget = normalizeContextBudgetPolicyBridgeResult({
    source: "rust_context_budget_policy_command",
    usage_telemetry: {},
    usage_summary: {},
  });
  assert.equal(budget.object, null);
  assert.equal(budget.status, null);
  assert.equal(budget.mode, null);
  assert.equal(budget.would_block, null);
  assert.equal(budget.runtime_event_kind, null);
  assert.equal(budget.runtime_event_status, null);

  const policy = normalizeCompactionPolicyBridgeResult({
    source: "rust_compaction_policy_command",
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

  const plan = normalizeContextCompactionPlanBridgeResult({
    source: "rust_context_compaction_plan_command",
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

  const update = normalizeContextCompactionStateUpdateBridgeResult({
    source: "rust_context_compaction_state_update_command",
    operation_kind: "thread.compact",
  });
  assert.equal(update.object, null);
  assert.equal(update.status, null);
  assert.equal(update.target_kind, null);
  assert.equal(update.operation_kind, "thread.compact");
});

test("runtime state-update runners do not synthesize Rust-owned envelopes", () => {
  const sparseCases = [
    [
      normalizeCodingToolBudgetRecoveryStateUpdateBridgeResult,
      {
        source: "rust_coding_tool_budget_recovery_state_update_command",
        operation_kind: "workflow.run.retry_completed",
      },
    ],
    [
      normalizeDiagnosticsOperatorOverrideStateUpdateBridgeResult,
      {
        source: "rust_diagnostics_operator_override_state_update_command",
        operation_kind: "diagnostics.operator_override.event",
      },
    ],
    [
      normalizeOperatorInterruptStateUpdateBridgeResult,
      {
        source: "rust_operator_interrupt_state_update_command",
        operation_kind: "turn.interrupt",
      },
    ],
    [
      normalizeOperatorSteerStateUpdateBridgeResult,
      {
        source: "rust_operator_steer_state_update_command",
        operation_kind: "turn.steer",
      },
    ],
    [
      normalizeRunCancelStateUpdateBridgeResult,
      {
        source: "rust_run_cancel_state_update_command",
        operation_kind: "run.cancel",
      },
    ],
    [
      normalizeThreadControlAgentStateUpdateBridgeResult,
      {
        source: "rust_thread_control_agent_state_update_command",
        operation_kind: "thread.pause",
      },
    ],
    [
      normalizeMcpControlAgentStateUpdateBridgeResult,
      {
        source: "rust_mcp_control_agent_state_update_command",
        operation_kind: "thread.mcp_import",
      },
    ],
    [
      normalizeThreadMemoryAgentStateUpdateBridgeResult,
      {
        source: "rust_thread_memory_agent_state_update_command",
        operation_kind: "thread.memory_append",
      },
    ],
    [
      normalizeRuntimeBridgeThreadStartAgentStateUpdateBridgeResult,
      {
        source: "rust_runtime_bridge_thread_start_agent_state_update_command",
        operation_kind: "thread.runtime_bridge.start",
      },
    ],
    [
      normalizeRuntimeBridgeTurnRunStateUpdateBridgeResult,
      {
        source: "rust_runtime_bridge_turn_run_state_update_command",
        operation_kind: "turn.runtime_bridge.submit",
      },
    ],
    [
      normalizeSubagentRecordStateUpdateBridgeResult,
      {
        source: "rust_subagent_record_state_update_command",
        operation_kind: "subagent.spawn",
      },
    ],
    [
      normalizeThreadCreateStateUpdateBridgeResult,
      {
        source: "rust_thread_create_state_update_command",
        operation_kind: "thread.create",
      },
    ],
    [
      normalizeAgentCreateStateUpdateBridgeResult,
      {
        source: "rust_agent_create_state_update_command",
        operation_kind: "agent.create",
      },
    ],
    [
      normalizeRunCreateStateUpdateBridgeResult,
      {
        source: "rust_run_create_state_update_command",
        operation_kind: "run.create",
      },
    ],
    [
      normalizeAgentStatusStateUpdateBridgeResult,
      {
        source: "rust_agent_status_state_update_command",
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

test("coding tool budget recovery state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_coding_tool_budget_recovery_state_update_command",
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
          };
    },
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_coding_tool_budget_recovery_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.approval_id, "approval_budget");
  assert.equal(result.source, "rust_coding_tool_budget_recovery_state_update_command");
  assert.equal(result.operation_kind, "workflow.run.retry_completed");
  assert.equal(result.operator_control.approval_id, "approval_budget");
  for (const field of ["approvalId", "eventId", "receiptRefs", "policyDecisionRefs", "createdAt"]) {
    assert.equal(Object.hasOwn(result.operator_control, field), false);
  }
  assert.equal(result.run.trace.operatorControls[0].event_id, "event_retry");
});

test("coding tool budget block runner sends Rust block request through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_coding_tool_budget_block_command",
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
      };
    },
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_coding_tool_budget_block");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    CODING_TOOL_BUDGET_BLOCK_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.tool_id, "file.inspect");
  assert.equal(captured.request.budget_policy.status, "blocked");
  assert.equal(result.source, "rust_coding_tool_budget_block_command");
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

test("coding-tool budget recovery admission-required runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_coding_tool_budget_recovery_admission_required_command",
            backend: "rust_policy",
            record: {
              status_code: 501,
              code: "runtime_coding_tool_budget_recovery_rust_core_required",
              message:
                "Runtime coding-tool budget recovery requires direct Rust daemon-core admission and persistence.",
              details: {
                rust_core_boundary: "runtime.coding_tool_budget_recovery",
                operation: "coding_tool_budget_recovery_control",
                operation_kind: "workflow.run.coding_tool_budget_recovery",
                run_id: "run_alpha",
                thread_id: "thread_alpha",
                approval_id: "approval_alpha",
                evidence_refs: ["coding_tool_budget_recovery_js_facade_retired"],
              },
            },
          };
    },
  });

  const result = runner.planCodingToolBudgetRecoveryAdmissionRequired({
    operation: "coding_tool_budget_recovery_control",
    operation_kind: "workflow.run.coding_tool_budget_recovery",
    run_id: "run_alpha",
    thread_id: "thread_alpha",
    approval_id: "approval_alpha",
    evidence_refs: ["coding_tool_budget_recovery_js_facade_retired"],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_coding_tool_budget_recovery_admission_required");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "coding_tool_budget_recovery_control");
  assert.equal(
    captured.request.operation_kind,
    "workflow.run.coding_tool_budget_recovery",
  );
  assert.equal(result.source, "rust_coding_tool_budget_recovery_admission_required_command");
  assert.equal(result.record.status_code, 501);
  assert.equal(result.record.details.run_id, "run_alpha");
  assert.equal(Object.hasOwn(result.record.details, "runId"), false);
});

test("workflow-edit admission-required runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_workflow_edit_admission_required_command",
            backend: "rust_policy",
            record: {
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
            },
          };
    },
  });

  const result = runner.planWorkflowEditAdmissionRequired({
    operation: "workflow_edit_proposal",
    operation_kind: "workflow.edit_proposed",
    thread_id: "thread_alpha",
    proposal_id: "proposal_alpha",
    evidence_refs: ["workflow_edit_proposal_js_facade_retired"],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_workflow_edit_admission_required");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    WORKFLOW_EDIT_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "workflow_edit_proposal");
  assert.equal(captured.request.operation_kind, "workflow.edit_proposed");
  assert.equal(result.source, "rust_workflow_edit_admission_required_command");
  assert.equal(result.record.status_code, 501);
  assert.equal(result.record.details.thread_id, "thread_alpha");
  assert.equal(Object.hasOwn(result.record.details, "threadId"), false);
});

test("diagnostics repair admission-required runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_diagnostics_repair_admission_required_command",
            backend: "rust_policy",
            record: {
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
            },
          };
    },
  });

  const result = runner.planDiagnosticsRepairAdmissionRequired({
    operation: "diagnostics_repair_decision_execution",
    operation_kind: "diagnostics.repair_decision.execute",
    thread_id: "thread_alpha",
    decision_id: "decision_alpha",
    gate_event_id: "event_gate",
    snapshot_id: "snapshot_alpha",
    evidence_refs: ["diagnostics_repair_decision_execution_js_facade_retired"],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_diagnostics_repair_admission_required");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "diagnostics_repair_decision_execution");
  assert.equal(
    captured.request.operation_kind,
    "diagnostics.repair_decision.execute",
  );
  assert.equal(result.source, "rust_diagnostics_repair_admission_required_command");
  assert.equal(result.record.status_code, 501);
  assert.equal(result.record.details.thread_id, "thread_alpha");
  assert.equal(Object.hasOwn(result.record.details, "threadId"), false);
  assert.equal(Object.hasOwn(result.record.details, "gateEventId"), false);
});

test("runtime diagnostics repair control runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_diagnostics_repair_control_command",
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
      };
    },
  });

  const result = runner.planRuntimeDiagnosticsRepairControl({
    operation: "diagnostics_repair_decision_execution",
    operation_kind: "diagnostics.repair_decision.execute",
    thread_id: "thread_alpha",
    event_stream_id: "event_stream_thread_alpha",
    decision_id: "decision_alpha",
    gate_event_id: "event_gate",
    snapshot_id: "snapshot_alpha",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_diagnostics_repair_control");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "diagnostics_repair_decision_execution");
  assert.equal(
    captured.request.operation_kind,
    "diagnostics.repair_decision.execute",
  );
  assert.equal(result.source, "rust_runtime_diagnostics_repair_control_command");
  assert.equal(result.operation_kind, "diagnostics.repair_decision.execute");
  assert.equal(result.decision_id, "decision_alpha");
  assert.equal(result.event.event_kind, "diagnostics.repair_decision.execute");
  assert.deepEqual(result.receipt_refs, ["receipt_diagnostics_repair_decision_alpha"]);
});

test("runtime diagnostics repair projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_diagnostics_repair_projection_command",
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
      };
    },
  });

  const projection = {
    decisions: [{
      decision_id: "decision_alpha",
      thread_id: "thread_alpha",
      gate_id: "gate_alpha",
      action: "restore_apply",
      status: "accepted",
    }],
  };
  const result = runner.projectRuntimeDiagnosticsRepairProjection({
    operation: "runtime_diagnostics_repair_projection",
    operation_kind: "runtime.diagnostics_repair_projection.decision",
    projection_kind: "decision",
    thread_id: "thread_alpha",
    decision_id: "decision_alpha",
    gate_id: "gate_alpha",
    projection,
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_diagnostics_repair_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "runtime_diagnostics_repair_projection");
  assert.equal(
    captured.request.operation_kind,
    "runtime.diagnostics_repair_projection.decision",
  );
  assert.equal(captured.request.projection_kind, "decision");
  assert.equal(captured.request.thread_id, "thread_alpha");
  assert.equal(captured.request.decision_id, "decision_alpha");
  assert.deepEqual(captured.request.projection, projection);
  assert.equal(result.source, "rust_runtime_diagnostics_repair_projection_command");
  assert.equal(result.projection_kind, "decision");
  assert.equal(result.projection.decision_id, "decision_alpha");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeDiagnosticsRepairProjectionBridgeResult({
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

test("runtime diagnostics repair policy runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_diagnostics_repair_policy_command",
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
      };
    },
  });

  const diagnosticsRepairContexts = [{
    restore_policy: "preview",
    restore_conflict_policy: "approval",
    default_repair_decision: "restore_preview",
    operator_override_requires_approval: false,
  }];
  const result = runner.projectRuntimeDiagnosticsRepairPolicy({
    thread_id: "thread_alpha",
    injection_id: "injection_alpha",
    mode: "blocking",
    diagnostic_status: "findings",
    diagnostic_count: 2,
    workspace_snapshot_refs: ["snapshot_alpha"],
    rollback_refs: ["rollback_alpha"],
    source_tool_call_ids: ["tool_call_alpha"],
    diagnostics_repair_contexts: diagnosticsRepairContexts,
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_diagnostics_repair_policy");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.thread_id, "thread_alpha");
  assert.equal(captured.request.injection_id, "injection_alpha");
  assert.deepEqual(captured.request.diagnostics_repair_contexts, diagnosticsRepairContexts);
  assert.equal(result.source, "rust_runtime_diagnostics_repair_policy_command");
  assert.equal(result.operation_kind, "runtime.diagnostics_repair_policy.projection");
  assert.equal(result.repair_policy.policy_id, "policy_alpha");
  assert.equal(result.repair_policy_config.restore_policy, "preview_only");
  assert.deepEqual(result.receipt_refs, ["receipt_runtime_diagnostics_repair_policy_projection"]);
  assert.equal(Object.hasOwn(result, "repairPolicy"), false);

  assert.throws(
    () =>
      normalizeRuntimeDiagnosticsRepairPolicyBridgeResult({
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

test("diagnostics operator override state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_diagnostics_operator_override_state_update_command",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "diagnostics.operator_override.event",
            updated_at: "2026-06-06T04:15:00.000Z",
            operator_control: {
              control: "diagnostics_operator_override",
              decision_id: "decision_override",
              event_id: "event_override",
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
          };
    },
  });

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
    approval_required: true,
    approval_satisfied: true,
    approval_source: "boolean_confirmation",
    snapshot_id: "snapshot_alpha",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_diagnostics_operator_override_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.decision_id, "decision_override");
  assert.equal(result.source, "rust_diagnostics_operator_override_state_update_command");
  assert.equal(result.operation_kind, "diagnostics.operator_override.event");
  assert.equal(result.operator_control.decision_id, "decision_override");
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

test("coding-tool result envelope runner sends Rust daemon-core plan request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_coding_tool_result_envelope_plan_command",
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
      };
    },
  });

  const result = runner.planCodingToolResultEnvelope({
    phase: "result_event",
    event_stream_id: "thread_alpha:events",
    thread_id: "thread_alpha",
    tool_id: "workspace.status",
    tool_call_id: "tool_status",
    workflow_node_id: "node_status",
    idempotency_key: "thread:thread_alpha:coding-tool:tool_status",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_coding_tool_result_envelope");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    CODING_TOOL_RESULT_ENVELOPE_PLAN_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.thread_id, "thread_alpha");
  assert.equal(captured.request.tool_id, "workspace.status");
  assert.equal(result.source, "rust_coding_tool_result_envelope_plan_command");
  assert.equal(result.operation_kind, "runtime.coding_tool.result_envelope");
  assert.equal(result.phase, "result_event");
  assert.equal(result.planned, true);
  assert.equal(result.step_module_context.workflow_projection_status, "live");
  assert.equal(result.event.payload_summary.tool_name, "workspace.status");
  assert.equal(result.envelope_hash, "sha256:envelope");
});

test("coding-tool result envelope normalizer rejects wrong operation kind", () => {
  assert.throws(
    () =>
      normalizeCodingToolResultEnvelopePlanBridgeResult({
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

test("post-edit diagnostics feedback runner sends Rust daemon-core plan request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_post_edit_diagnostics_feedback_plan_command",
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
      };
    },
  });

  const result = runner.planPostEditDiagnosticsFeedback({
    thread_id: "thread_alpha",
    turn_id: "turn_alpha",
    patch_tool_call_id: "patch_alpha",
    workflow_graph_id: "graph_alpha",
    request: { diagnostics_mode: "blocking" },
    input: { cwd: "/workspace" },
    patch_result: { changed_files: [{ path: "src/app.js" }] },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_post_edit_diagnostics_feedback");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.thread_id, "thread_alpha");
  assert.equal(captured.request.patch_tool_call_id, "patch_alpha");
  assert.deepEqual(captured.request.patch_result.changed_files, [{ path: "src/app.js" }]);
  assert.equal(result.source, "rust_post_edit_diagnostics_feedback_plan_command");
  assert.equal(result.backend, "rust_runtime_diagnostics_feedback");
  assert.equal(result.operation_kind, "runtime.post_edit_diagnostics_feedback");
  assert.equal(result.planned, true);
  assert.deepEqual(result.paths, ["src/app.js"]);
  assert.deepEqual(result.request.input.paths, ["src/app.js"]);
});

test("post-edit diagnostics feedback plan normalizer preserves Rust-owned request envelope", () => {
  const result = normalizePostEditDiagnosticsFeedbackPlanBridgeResult({
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

test("operator turn control admission-required runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_operator_turn_control_admission_required_command",
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
          };
    },
  });

  const result = runner.planOperatorTurnControlAdmissionRequired({
    operation: "operator_interrupt",
    operation_kind: "turn.interrupt",
    thread_id: "thread_budget",
    turn_id: "turn_budget",
    requested_action: "cancel",
    evidence_refs: ["operator_interrupt_js_facade_retired"],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_operator_turn_control_admission_required");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "turn.interrupt");
  assert.equal(result.source, "rust_operator_turn_control_admission_required_command");
  assert.equal(result.record.code, "runtime_operator_turn_control_rust_core_required");
  assert.equal(result.record.details.thread_id, "thread_budget");
  assert.equal(Object.hasOwn(result.record.details, "threadId"), false);
  assert.equal(Object.hasOwn(result.record.details, "operationKind"), false);
  assert.equal(Object.hasOwn(result.record.details, "requestedAction"), false);
});

test("operator interrupt state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_operator_interrupt_state_update_command",
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
          };
    },
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_operator_interrupt_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.reason, "operator_stop");
  assert.equal(result.source, "rust_operator_interrupt_state_update_command");
  assert.equal(result.operation_kind, "turn.interrupt");
  assert.equal(result.operator_control.reason, "operator_stop");
  assert.equal(result.operator_control.event_id, "event_interrupt");
  assert.equal(Object.hasOwn(result.operator_control, "eventId"), false);
  assert.equal(Object.hasOwn(result.operator_control, "createdAt"), false);
  assert.equal(result.stop_condition.reason, "operator_interrupt");
  assert.equal(result.run.turnStatus, "interrupted");
  assert.equal(result.run.trace.operatorControls[0].event_id, "event_interrupt");
});

test("operator steer state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_operator_steer_state_update_command",
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
          };
    },
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_operator_steer_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.guidance, "focus on the failing bridge assertion");
  assert.equal(result.source, "rust_operator_steer_state_update_command");
  assert.equal(result.operation_kind, "turn.steer");
  assert.equal(result.operator_control.guidance, "focus on the failing bridge assertion");
  assert.equal(result.operator_control.event_id, "event_steer");
  assert.equal(Object.hasOwn(result.operator_control, "eventId"), false);
  assert.equal(Object.hasOwn(result.operator_control, "createdAt"), false);
  assert.equal(result.run.trace.operatorControls[0].event_id, "event_steer");
});

test("run cancel state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_run_cancel_state_update_command",
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
          };
    },
  });

  const result = runner.planRunCancelStateUpdate({
    run_id: "run_cancel_one",
    run: { id: "run_cancel_one", status: "running", trace: {} },
    canceled_at: "2026-06-06T04:45:00.000Z",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_run_cancel_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.canceled_at, "2026-06-06T04:45:00.000Z");
  assert.equal(result.source, "rust_run_cancel_state_update_command");
  assert.equal(result.operation_kind, "run.cancel");
  assert.equal(result.runtime_job.status, "canceled");
  assert.equal(result.run.events.at(-1).type, "canceled");
});

test("run cancel admission-required runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_run_cancel_admission_required_command",
            backend: "rust_policy",
            record: {
              status_code: 501,
              code: "runtime_run_cancel_rust_core_required",
              message:
                "Run cancellation requires direct Rust daemon-core state admission and persistence.",
              details: {
                rust_core_boundary: "runtime.run_cancel",
                operation: "run_cancel",
                operation_kind: "run.cancel",
                run_id: "run_cancel_one",
                run_status: "running",
                evidence_refs: ["runtime_run_cancel_js_facade_retired"],
              },
            },
          };
    },
  });

  const result = runner.planRunCancelAdmissionRequired({
    operation: "run_cancel",
    operation_kind: "run.cancel",
    run_id: "run_cancel_one",
    run_status: "running",
    evidence_refs: ["runtime_run_cancel_js_facade_retired"],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_run_cancel_admission_required");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUN_CANCEL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "run_cancel");
  assert.equal(captured.request.operation_kind, "run.cancel");
  assert.equal(result.source, "rust_run_cancel_admission_required_command");
  assert.equal(result.record.status_code, 501);
  assert.equal(result.record.details.run_id, "run_cancel_one");
  assert.equal(Object.hasOwn(result.record.details, "runId"), false);
  assert.equal(Object.hasOwn(result.record.details, "runStatus"), false);
});

test("runtime task job cancel runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_runtime_task_job_cancel_state_update_command",
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
  });

  const result = runner.planRuntimeTaskJobCancelStateUpdate({
    cancel_kind: "task",
    task_id: "task_run_cancel_one",
    run_id: "run_cancel_one",
    run: { id: "run_cancel_one", status: "running", trace: {} },
    canceled_at: "2026-06-06T04:45:00.000Z",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_task_job_cancel_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.cancel_kind, "task");
  assert.equal(captured.request.task_id, "task_run_cancel_one");
  assert.equal(result.source, "rust_runtime_task_job_cancel_state_update_command");
  assert.equal(result.operation_kind, "task.cancel");
  assert.equal(result.cancel_kind, "task");
  assert.equal(result.task_id, "task_run_cancel_one");
  assert.equal(result.runtime_task.status, "canceled");
  assert.equal(result.run.status, "canceled");
});

test("runtime task job cancel normalizer accepts job cancel operation kind", () => {
  const result = normalizeRuntimeTaskJobCancelStateUpdateBridgeResult({
    source: "rust_runtime_task_job_cancel_state_update_command",
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

test("runtime task job create runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_task_job_create_state_update_command",
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
  });

  const result = runner.planRuntimeTaskJobCreateStateUpdate({
    agent_id: "agent-one",
    run: { id: "run_create_one", agentId: "agent-one", status: "completed" },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_task_job_create_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.agent_id, "agent-one");
  assert.equal(result.source, "rust_runtime_task_job_create_state_update_command");
  assert.equal(result.operation_kind, "task.create");
  assert.equal(result.task_id, "task_run_create_one");
  assert.equal(result.runtime_task.status, "completed");
  assert.equal(result.run.id, "run_create_one");
});

test("runtime task job create normalizer requires task create operation kind", () => {
  const result = normalizeRuntimeTaskJobCreateStateUpdateBridgeResult({
    source: "rust_runtime_task_job_create_state_update_command",
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

test("runtime task job projection runner sends Rust projection through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_task_job_projection_command",
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
  });

  const result = runner.projectRuntimeTaskJobProjection({
    projection_kind: "task.list",
    agent_id: "agent-one",
    status: "running",
    runs: [{ id: "run-one", agentId: "agent-one", status: "running" }],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_task_job_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_TASK_JOB_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.projection_kind, "task.list");
  assert.equal(captured.request.agent_id, "agent-one");
  assert.equal(result.source, "rust_runtime_task_job_projection_command");
  assert.equal(result.operation_kind, "task.list");
  assert.equal(result.projection_kind, "task.list");
  assert.equal(result.records[0].taskId, "task_run-one");
  assert.equal(result.record_count, 1);
});

test("runtime task job projection normalizer accepts get operation kinds", () => {
  const taskResult = normalizeRuntimeTaskJobProjectionBridgeResult({
    source: "rust_runtime_task_job_projection_command",
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
  const jobResult = normalizeRuntimeTaskJobProjectionBridgeResult({
    source: "rust_runtime_task_job_projection_command",
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

test("skill hook registry projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_skill_hook_registry_projection_command",
        backend: "rust_policy",
        record: {
          object: "ioi.runtime_skill_hook_registry_projection",
          status: "projected",
          operation: "skill_hook_registry_skills",
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
  });

  const result = runner.projectSkillHookRegistry({
    operation: "skill_hook_registry_skills",
    operation_kind: "skill_hook.registry.skills",
    registry_kind: "skills",
    workspace_root: "/workspace/project",
    home_dir: "/home/operator",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_skill_hook_registry");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    SKILL_HOOK_REGISTRY_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "skill_hook_registry_skills");
  assert.equal(captured.request.operation_kind, "skill_hook.registry.skills");
  assert.equal(captured.request.registry_kind, "skills");
  assert.equal(captured.request.home_dir, "/home/operator");
  assert.equal(result.source, "rust_skill_hook_registry_projection_command");
  assert.equal(result.registry_kind, "skills");
  assert.equal(result.projection.skillCount, 1);
  assert.equal(result.skills[0].id, "skill.repo");
  assert.equal(Object.hasOwn(result, "registryKind"), false);

  assert.throws(
    () =>
      normalizeSkillHookRegistryProjectionBridgeResult({
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

test("repository workflow projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_repository_workflow_projection_command",
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
  });

  const result = runner.projectRepositoryWorkflow({
    operation: "repository_workflow_pr_attempts",
    operation_kind: "repository_workflow.projection.pr_attempts",
    projection_kind: "pr_attempts",
    workspace_root: "/workspace/project",
    evidence_refs: ["runtime_repository_workflow_rust_projection"],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_repository_workflow");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    REPOSITORY_WORKFLOW_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "repository_workflow_pr_attempts");
  assert.equal(
    captured.request.operation_kind,
    "repository_workflow.projection.pr_attempts",
  );
  assert.equal(captured.request.projection_kind, "pr_attempts");
  assert.equal(
    result.source,
    "rust_repository_workflow_projection_command",
  );
  assert.equal(result.projection_kind, "pr_attempts");
  assert.equal(result.projection[0].attemptId, "pr_attempt_one");
  assert.equal(result.pr_attempt.attemptId, "pr_attempt_one");
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRepositoryWorkflowProjectionBridgeResult({
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

test("runtime tool catalog projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_tool_catalog_projection_command",
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
  });

  const result = runner.projectRuntimeToolCatalog({
    operation: "runtime_tool_catalog",
    operation_kind: "runtime.tool_catalog.projection.tools",
    projection_kind: "tools",
    pack: "coding",
    workspace_root: "/workspace/project",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_tool_catalog");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_TOOL_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(result.source, "rust_runtime_tool_catalog_projection_command");
  assert.equal(result.projection_kind, "tools");
  assert.equal(result.tools[0].stable_tool_id, "file.apply_patch");
  assert.equal(Object.hasOwn(result.tools[0], "stableToolId"), false);

  assert.throws(
    () =>
      normalizeRuntimeToolCatalogProjectionBridgeResult({
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

test("runtime lifecycle projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_lifecycle_projection_command",
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
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_lifecycle");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_LIFECYCLE_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "runtime_lifecycle_projection");
  assert.equal(
    captured.request.operation_kind,
    "runtime.lifecycle_projection.run_artifact",
  );
  assert.equal(captured.request.projection_kind, "run_artifact");
  assert.equal(captured.request.agent_id, "agent_123");
  assert.equal(captured.request.thread_id, "thread_123");
  assert.equal(captured.request.turn_id, "turn_123");
  assert.equal(captured.request.run_id, "run_123");
  assert.equal(captured.request.artifact_ref, "artifact_123");
  assert.equal(
    result.source,
    "rust_runtime_lifecycle_projection_command",
  );
  assert.equal(result.projection_kind, "run_artifact");
  assert.equal(result.projection.id, "artifact_123");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeLifecycleProjectionBridgeResult({
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

test("runtime memory projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_memory_projection_command",
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
  });

  const projection = {
    schema_version: "ioi.agent-runtime.memory.v1",
    records: [{ id: "memory_123" }],
    total_matches: 1,
  };
  const result = runner.projectRuntimeMemoryProjection({
    operation: "runtime_memory_projection",
    operation_kind: "runtime.memory_projection.records",
    projection_kind: "records",
    agent_id: "agent_123",
    thread_id: "thread_123",
    workspace_root: "/workspace/project",
    projection,
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_memory_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_MEMORY_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "runtime_memory_projection");
  assert.equal(captured.request.operation_kind, "runtime.memory_projection.records");
  assert.equal(captured.request.projection_kind, "records");
  assert.deepEqual(captured.request.projection, projection);
  assert.equal(result.source, "rust_runtime_memory_projection_command");
  assert.equal(result.projection_kind, "records");
  assert.equal(result.projection.records[0].id, "memory_123");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeMemoryProjectionBridgeResult({
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

test("runtime memory control runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_memory_control_command",
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
  });

  const result = runner.planRuntimeMemoryControl({
    operation: "write",
    operation_kind: "memory.write",
    thread_id: "thread_123",
    agent_id: "agent_123",
    workspace_root: "/workspace/project",
    request: { text: "Remember release window" },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_memory_control");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "memory.write");
  assert.equal(captured.request.request.text, "Remember release window");
  assert.equal(result.source, "rust_runtime_memory_control_command");
  assert.equal(result.operation_kind, "memory.write");
  assert.equal(result.memory_state_kind, "record");
  assert.equal(result.payload.id, "memory_123");
  assert.equal(result.receipt_refs[0], "receipt_memory_write");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeMemoryControlBridgeResult({
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

test("runtime workflow-edit control runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_workflow_edit_control_command",
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
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_workflow_edit_control");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_WORKFLOW_EDIT_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "workflow.edit_proposed");
  assert.equal(captured.request.request.workflow_patch.nodes[0].id, "node_123");
  assert.equal(result.source, "rust_runtime_workflow_edit_control_command");
  assert.equal(result.operation_kind, "workflow.edit_proposed");
  assert.equal(result.event.event_kind, "workflow.edit_proposed");
  assert.equal(result.receipt_refs[0], "receipt_workflow_edit");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeWorkflowEditControlBridgeResult({
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

test("runtime managed-session projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_managed_session_projection_command",
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
  });

  const projection = {
    sessions: [{ managed_session_id: "sandbox_browser:1", thread_id: "thread_123" }],
  };
  const result = runner.projectRuntimeManagedSessionProjection({
    operation: "managed_session_inspection",
    operation_kind: "managed_session.inspect",
    projection_kind: "list",
    thread_id: "thread_123",
    projection,
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_managed_session_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "managed_session.inspect");
  assert.equal(captured.request.projection_kind, "list");
  assert.equal(captured.request.thread_id, "thread_123");
  assert.deepEqual(captured.request.projection, projection);
  assert.equal(result.source, "rust_runtime_managed_session_projection_command");
  assert.equal(result.operation_kind, "managed_session.inspect");
  assert.equal(result.projection[0].managed_session_id, "sandbox_browser:1");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeManagedSessionProjectionBridgeResult({
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

test("runtime managed-session control runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_managed_session_control_command",
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
  });

  const result = runner.planRuntimeManagedSessionControl({
    operation: "managed_session_control",
    operation_kind: "managed_session.control",
    thread_id: "thread_123",
    event_stream_id: "thread_123:events",
    managed_session_id: "sandbox_browser:1",
    control_state: "take_over",
    managed_session: { managed_session_id: "sandbox_browser:1", control_state: "observe" },
    request: { receipt_refs: ["receipt_request"] },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_managed_session_control");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_MANAGED_SESSION_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "managed_session.control");
  assert.equal(captured.request.managed_session_id, "sandbox_browser:1");
  assert.equal(captured.request.control_state, "take_over");
  assert.equal(result.source, "rust_runtime_managed_session_control_command");
  assert.equal(result.operation_kind, "managed_session.control");
  assert.equal(result.event.event_kind, "managed_session.controlled");
  assert.equal(result.receipt_refs[0], "receipt_managed_session_control");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeManagedSessionControlBridgeResult({
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

test("runtime workspace-change projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_workspace_change_projection_command",
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
  });

  const projection = {
    changes: [{ workspace_change_id: "workspace_change:file:1", thread_id: "thread_123" }],
  };
  const result = runner.projectRuntimeWorkspaceChangeProjection({
    operation: "workspace_change_inspection",
    operation_kind: "workspace_change.inspect",
    projection_kind: "list",
    thread_id: "thread_123",
    projection,
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_workspace_change_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_WORKSPACE_CHANGE_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "workspace_change.inspect");
  assert.equal(captured.request.projection_kind, "list");
  assert.equal(captured.request.thread_id, "thread_123");
  assert.deepEqual(captured.request.projection, projection);
  assert.equal(result.source, "rust_runtime_workspace_change_projection_command");
  assert.equal(result.operation_kind, "workspace_change.inspect");
  assert.equal(result.projection[0].workspace_change_id, "workspace_change:file:1");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeWorkspaceChangeProjectionBridgeResult({
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

test("runtime workspace-change control runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_workspace_change_control_command",
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
  });

  const result = runner.planRuntimeWorkspaceChangeControl({
    operation: "workspace_change_control",
    operation_kind: "workspace_change.control",
    thread_id: "thread_123",
    event_stream_id: "thread_123:events",
    workspace_change_id: "workspace_change:file:1",
    control_state: "accept",
    workspace_change: { workspace_change_id: "workspace_change:file:1", lifecycle: "proposed" },
    request: { receipt_refs: ["receipt_request"] },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_workspace_change_control");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_WORKSPACE_CHANGE_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "workspace_change.control");
  assert.equal(captured.request.workspace_change_id, "workspace_change:file:1");
  assert.equal(captured.request.control_state, "accept");
  assert.equal(result.source, "rust_runtime_workspace_change_control_command");
  assert.equal(result.operation_kind, "workspace_change.control");
  assert.equal(result.event.event_kind, "workspace_change.controlled");
  assert.equal(result.receipt_refs[0], "receipt_workspace_change_control");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeWorkspaceChangeControlBridgeResult({
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

test("runtime thread-fork control runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_thread_fork_control_command",
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
  });

  const result = runner.planRuntimeThreadForkControl({
    operation: "thread_fork",
    operation_kind: "thread.fork",
    thread_id: "thread_123",
    event_stream_id: "thread_123:events",
    source_thread: { thread_id: "thread_123", agent_id: "agent_123" },
    source_agent: { id: "agent_123", cwd: "/workspace" },
    request: { idempotency_key: "fork-key" },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_thread_fork_control");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_THREAD_FORK_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "thread.fork");
  assert.equal(captured.request.thread_id, "thread_123");
  assert.equal(captured.request.source_agent.id, "agent_123");
  assert.equal(captured.request.request.idempotency_key, "fork-key");
  assert.equal(result.source, "rust_runtime_thread_fork_control_command");
  assert.equal(result.operation_kind, "thread.fork");
  assert.equal(result.agent.id, "agent_fork_123");
  assert.equal(result.thread.thread_id, "thread_fork_123");
  assert.equal(result.event.event_kind, "thread.forked");
  assert.equal(result.receipt_refs[0], "receipt_thread_fork_control");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeThreadForkControlBridgeResult({
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

test("runtime conversation artifact projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_conversation_artifact_projection_command",
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
  });

  const projection = {
    artifacts: [{ id: "artifact_123", thread_id: "thread_123" }],
  };
  const result = runner.projectRuntimeConversationArtifactProjection({
    operation: "runtime_conversation_artifact_projection",
    operation_kind: "runtime.conversation_artifact_projection.list",
    projection_kind: "list",
    thread_id: "thread_123",
    projection,
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_conversation_artifact_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_CONVERSATION_ARTIFACT_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "runtime_conversation_artifact_projection");
  assert.equal(
    captured.request.operation_kind,
    "runtime.conversation_artifact_projection.list",
  );
  assert.equal(captured.request.projection_kind, "list");
  assert.equal(captured.request.thread_id, "thread_123");
  assert.deepEqual(captured.request.projection, projection);
  assert.equal(result.source, "rust_runtime_conversation_artifact_projection_command");
  assert.equal(result.projection_kind, "list");
  assert.equal(result.projection[0].id, "artifact_123");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeConversationArtifactProjectionBridgeResult({
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

test("runtime conversation artifact control runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_conversation_artifact_control_command",
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
  });

  const result = runner.planRuntimeConversationArtifactControl({
    operation: "conversation_artifact_create",
    operation_kind: "artifact.conversation.create",
    thread_id: "thread_123",
    request: {
      title: "Draft",
      idempotency_key: "artifact-key",
    },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_conversation_artifact_control");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_CONVERSATION_ARTIFACT_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "conversation_artifact_create");
  assert.equal(captured.request.operation_kind, "artifact.conversation.create");
  assert.equal(captured.request.thread_id, "thread_123");
  assert.equal(captured.request.request.idempotency_key, "artifact-key");
  assert.equal(result.source, "rust_runtime_conversation_artifact_control_command");
  assert.equal(result.operation_kind, "artifact.conversation.create");
  assert.equal(result.artifact.id, "artifact_123");
  assert.equal(result.result.status, "created");
  assert.equal(result.receipt_refs[0], "receipt_runtime_conversation_artifact_control");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeConversationArtifactControlBridgeResult({
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

test("runtime subagent projection runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_subagent_projection_command",
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
  });

  const projection = {
    subagents: [{ subagent_id: "subagent_123", parent_thread_id: "thread_123" }],
    runs: [],
  };
  const result = runner.projectRuntimeSubagentProjection({
    operation: "runtime_subagent_projection",
    operation_kind: "runtime.subagent_projection.list",
    projection_kind: "list",
    thread_id: "thread_123",
    role: "reviewer",
    projection,
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_runtime_subagent_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_SUBAGENT_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation, "runtime_subagent_projection");
  assert.equal(captured.request.operation_kind, "runtime.subagent_projection.list");
  assert.equal(captured.request.projection_kind, "list");
  assert.equal(captured.request.thread_id, "thread_123");
  assert.equal(captured.request.role, "reviewer");
  assert.deepEqual(captured.request.projection, projection);
  assert.equal(result.source, "rust_runtime_subagent_projection_command");
  assert.equal(result.projection_kind, "list");
  assert.equal(result.projection[0].subagent_id, "subagent_123");
  assert.equal(result.record_count, 1);
  assert.equal(Object.hasOwn(result, "projectionKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeSubagentProjectionBridgeResult({
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

test("runtime subagent wait control runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_runtime_subagent_control_command",
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
  });

  const result = runner.planRuntimeSubagentControl({
    operation: "wait",
    operation_kind: "subagent.wait",
    thread_id: "thread_123",
    event_stream_id: "thread_123:events",
    subagent: { subagent_id: "subagent_123", parent_thread_id: "thread_123" },
    request: { receipt_refs: ["receipt_request"] },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_subagent_control");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_SUBAGENT_CONTROL_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "subagent.wait");
  assert.equal(captured.request.subagent.subagent_id, "subagent_123");
  assert.equal(result.source, "rust_runtime_subagent_control_command");
  assert.equal(result.operation_kind, "subagent.wait");
  assert.equal(result.event.event_kind, "subagent.wait_completed");
  assert.equal(result.receipt_refs[0], "receipt_wait");
  assert.equal(Object.hasOwn(result, "operationKind"), false);

  assert.throws(
    () =>
      normalizeRuntimeSubagentControlBridgeResult({
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

test("thread control agent state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_thread_control_agent_state_update_command",
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
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_thread_control_agent_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.control_kind, "thinking");
  assert.equal(captured.request.model_route.selected_model, "local-model");
  assert.equal(captured.request.model_route.route_id, "route.local-first");
  for (const field of ["selectedModel", "requestedModelId", "routeId"]) {
    assert.equal(Object.hasOwn(captured.request.model_route, field), false);
  }
  assert.equal(result.source, "rust_thread_control_agent_state_update_command");
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

test("workspace trust control state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
        source: "rust_workspace_trust_control_state_update_command",
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
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_workspace_trust_control_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "workspace_trust.acknowledge");
  assert.equal(captured.request.warning_id, "workspace_trust_warning_1");
  assert.equal(result.source, "rust_workspace_trust_control_state_update_command");
  assert.equal(result.operation_kind, "workspace_trust.acknowledge");
  assert.equal(result.workspace_trust_acknowledgement.status, "acknowledged");
  assert.equal(result.event.event_kind, "workspace.trust_acknowledged");
  assert.deepEqual(result.receipt_refs, ["receipt_workspace_trust_ack_1"]);
});

test("thread turn admission-required runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_thread_turn_admission_required_command",
            backend: "rust_policy",
            record: {
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
            },
          };
    },
  });

  const result = runner.planThreadTurnAdmissionRequired({
    operation: "thread_turn_create",
    operation_kind: "turn.create",
    thread_id: "thread_1",
    agent_id: "agent_1",
    runtime_profile: "fixture",
    evidence_refs: ["thread_turn_create_js_run_creation_retired"],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_thread_turn_admission_required");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "turn.create");
  assert.equal(result.source, "rust_thread_turn_admission_required_command");
  assert.equal(result.record.code, "runtime_thread_turn_rust_core_required");
  assert.equal(result.record.details.thread_id, "thread_1");
  assert.equal(Object.hasOwn(result.record.details, "threadId"), false);
  assert.equal(Object.hasOwn(result.record.details, "operationKind"), false);
  assert.equal(Object.hasOwn(result.record.details, "runtimeProfile"), false);
});

test("lifecycle admission-required runner sends Rust daemon-core request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_lifecycle_admission_required_command",
            backend: "rust_policy",
            record: {
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
            },
          };
    },
  });

  const result = runner.planLifecycleAdmissionRequired({
    operation: "agent_status_control",
    operation_kind: "agent_status_update",
    agent_id: "agent_1",
    requested_status: "archived",
    requested_operation_kind: "agent.archive",
    evidence_refs: ["runtime_agent_status_control_js_facade_retired"],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_lifecycle_admission_required");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "agent_status_update");
  assert.equal(result.source, "rust_lifecycle_admission_required_command");
  assert.equal(result.record.code, "runtime_agent_status_control_rust_core_required");
  assert.equal(result.record.details.agent_id, "agent_1");
  assert.equal(Object.hasOwn(result.record.details, "agentId"), false);
  assert.equal(Object.hasOwn(result.record.details, "operationKind"), false);
  assert.equal(Object.hasOwn(result.record.details, "requestedStatus"), false);
});

test("mcp control agent state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_mcp_control_agent_state_update_command",
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
  });

  const result = runner.planMcpControlAgentStateUpdate({
    thread_id: "thread_1",
    agent: { id: "agent_1", mcpRegistry: { servers: [{ id: "mcp.docs" }] } },
    control_kind: "mcp_add",
    event_id: "event_mcp_add",
    seq: 5,
    created_at: "2026-06-06T05:45:00.000Z",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_mcp_control_agent_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.control_kind, "mcp_add");
  assert.equal(result.source, "rust_mcp_control_agent_state_update_command");
  assert.equal(result.operation_kind, "thread.mcp_add");
  assert.equal(result.control.control_kind, "mcp_add");
  assert.equal(result.control.event_id, "event_mcp_add");
  assert.equal(Object.hasOwn(result.control, "controlKind"), false);
  assert.equal(Object.hasOwn(result.control, "eventId"), false);
  assert.equal(Object.hasOwn(result.control, "createdAt"), false);
  assert.equal(result.agent.mcpRegistry.servers[0].id, "mcp.docs");
});

test("MCP server validation runner sends Rust daemon-core validation request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_mcp_server_validation_command",
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
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "validate_mcp_servers");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.servers[0].secret_refs.Authorization.invalidVaultRef, true);
  assert.equal(result.source, "rust_mcp_server_validation_command");
  assert.equal(result.status, "blocked");
  assert.equal(result.ok, false);
  assert.equal(result.issue_count, 1);
  assert.equal(result.issues[0].server_id, "mcp.secret");
  assert.equal(Object.hasOwn(result.issues[0], "serverId"), false);
});

test("MCP server validation input runner sends Rust daemon-core projection request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_mcp_server_validation_input_command",
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
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "project_mcp_server_validation_input");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.workspace_root, "/workspace");
  assert.equal(captured.request.input.mcp_json.mcp_servers.docs.command, "npx");
  assert.equal(result.source, "rust_mcp_server_validation_input_command");
  assert.equal(result.status, "projected");
  assert.equal(result.server_count, 1);
  assert.equal(result.servers[0].source_scope, "validation");
  assert.equal(Object.hasOwn(result.servers[0], "sourceScope"), false);
});

test("MCP manager status projection runner sends Rust daemon-core projection request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_mcp_manager_status_projection_command",
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
              search_tools: "/v1/mcp/tools/search",
            },
          };
    },
  });

  const result = runner.planMcpManagerStatusProjection({
    status_schema_version: "ioi.runtime.mcp-manager-status.v1",
    validation: { ok: true },
    servers: [{ id: "mcp.docs", enabled: true }, { id: "mcp.disabled", enabled: false }],
    tools: [{ stable_tool_id: "mcp.docs.search" }],
    resources: [{ uri: "mcp.docs://root" }],
    prompts: [{ name: "ask" }],
    routes: { search_tools: "/v1/mcp/tools/search" },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_mcp_manager_status_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.servers.length, 2);
  assert.equal(result.source, "rust_mcp_manager_status_projection_command");
  assert.equal(result.status, "ready");
  assert.equal(result.server_count, 2);
  assert.equal(result.enabled_server_count, 1);
  assert.equal(result.enabled_tool_count, 1);
  assert.equal(result.validation.server_count, 2);
  assert.equal(result.validation.tools[0].stable_tool_id, "mcp.docs.search");
  assert.equal(result.routes.search_tools, "/v1/mcp/tools/search");
  assert.equal(Object.hasOwn(result, "serverCount"), false);
  assert.equal(Object.hasOwn(result.routes, "searchTools"), false);
});

test("memory manager status projection runner sends Rust daemon-core projection request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_memory_manager_status_projection_command",
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
  });

  const projection = { policy: { id: "policy.thread" }, records: [{ id: "memory.one" }] };
  const result = runner.planMemoryManagerStatusProjection({
    status_schema_version: "ioi.runtime.memory-manager-status.v1",
    projection,
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_memory_manager_status_projection");
  assert.equal(
    captured.request.schema_version,
    MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.deepEqual(captured.request.projection, projection);
  assert.equal(result.source, "rust_memory_manager_status_projection_command");
  assert.equal(result.status, "ready");
  assert.equal(result.write_requires_approval, true);
  assert.deepEqual(result.memory_keys, ["project"]);
  assert.equal(result.routes.status, "/v1/threads/{thread_id}/memory/status");
  assert.equal(Object.hasOwn(result, "memoryKeys"), false);
  assert.equal(Object.hasOwn(result, "writeRequiresApproval"), false);
});

test("memory manager validation projection runner sends Rust daemon-core projection request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_memory_manager_validation_projection_command",
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
  });

  const projection = { policy: { id: "policy.thread" }, records: [{ id: "memory.one" }] };
  const result = runner.planMemoryManagerValidationProjection({
    validation_schema_version: "ioi.runtime.memory-manager-validation.v1",
    projection,
  });

  assert.equal(captured.operation, "plan_memory_manager_validation_projection");
  assert.equal(
    captured.request.schema_version,
    MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.deepEqual(captured.request.projection, projection);
  assert.equal(result.source, "rust_memory_manager_validation_projection_command");
  assert.equal(result.ok, false);
  assert.equal(result.issue_count, 1);
  assert.equal(result.issues[0].code, "memory_records_path_missing");
  assert.equal(Object.hasOwn(result, "issueCount"), false);
  assert.equal(Object.hasOwn(result, "recordCount"), false);
});

test("MCP manager catalog projection runner sends Rust daemon-core projection request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_mcp_manager_catalog_projection_command",
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
  });

  const result = runner.planMcpManagerCatalogProjection({
    servers: [{ id: "mcp.docs", enabled: true, allowed_tools: ["search"] }],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_mcp_manager_catalog_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.servers.length, 1);
  assert.equal(result.source, "rust_mcp_manager_catalog_projection_command");
  assert.equal(result.status, "projected");
  assert.equal(result.tool_count, 1);
  assert.equal(result.enabled_tool_count, 1);
  assert.equal(result.tools[0].stable_tool_id, "mcp.docs.search");
  assert.equal(result.resources[0].stable_resource_id, "mcp.docs.resource.docs_index");
  assert.equal(result.prompts[0].stable_prompt_id, "mcp.docs.prompt.summarize");
  assert.equal(Object.hasOwn(result, "toolCount"), false);
  assert.equal(Object.hasOwn(result.tools[0], "stableToolId"), false);
});

test("MCP manager catalog summary projection runner sends Rust daemon-core projection request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_mcp_manager_catalog_summary_projection_command",
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
            search_route: "/v1/mcp/tools/search",
            fetch_route: "/v1/mcp/tools/{tool_id}",
          };
    },
  });

  const result = runner.planMcpManagerCatalogSummaryProjection({
    server: { id: "mcp.docs", label: "Docs" },
    tools: [{ stable_tool_id: "mcp.docs.search", tool_name: "search" }],
    live_mode: "declared_catalog",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_mcp_manager_catalog_summary_projection");
  assert.equal(
    captured.request.schema_version,
    MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(result.source, "rust_mcp_manager_catalog_summary_projection_command");
  assert.equal(result.object, "ioi.runtime_mcp_catalog_summary");
  assert.equal(result.tool_count, 1);
  assert.equal(result.namespaces[0], "search");
  assert.equal(result.search_route, "/v1/mcp/tools/search");
  assert.equal(Object.hasOwn(result, "toolCount"), false);
  assert.equal(Object.hasOwn(result, "catalogHash"), false);
});

test("MCP manager validation projection runner sends Rust daemon-core projection request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_mcp_manager_validation_projection_command",
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
  });

  const result = runner.planMcpManagerValidationProjection({
    validation_schema_version: "ioi.runtime.mcp-manager-validation.v1",
    validation: { ok: false, issues: [{ code: "invalid", server_id: "mcp.docs" }], warnings: [] },
    servers: [{ id: "mcp.docs" }],
    tools: [{ stable_tool_id: "mcp.docs.search" }],
    resources: [{ uri: "docs://index" }],
    prompts: [{ name: "summarize" }],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_mcp_manager_validation_projection");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(result.source, "rust_mcp_manager_validation_projection_command");
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

test("MCP and memory manager projection runners do not synthesize Rust-owned projection envelopes", () => {
  const mcpStatus = normalizeMcpManagerStatusProjectionBridgeResult({
    source: "legacy_mcp_status_projection_fixture",
    servers: [{ id: "mcp.docs" }],
    tools: [{ stable_tool_id: "mcp.docs.search" }],
  });
  assert.equal(mcpStatus.object, null);
  assert.equal(mcpStatus.status, null);
  assert.equal(mcpStatus.server_count, null);
  assert.equal(mcpStatus.tool_count, null);

  const mcpValidation = normalizeMcpManagerValidationProjectionBridgeResult({
    source: "legacy_mcp_validation_projection_fixture",
    ok: true,
    issues: [],
    warnings: [],
  });
  assert.equal(mcpValidation.object, null);
  assert.equal(mcpValidation.status, null);
  assert.equal(mcpValidation.issue_count, null);
  assert.equal(mcpValidation.warning_count, null);

  const memoryStatus = normalizeMemoryManagerStatusProjectionBridgeResult({
    source: "legacy_memory_status_projection_fixture",
    records: [{ id: "memory.one" }],
  });
  assert.equal(memoryStatus.object, null);
  assert.equal(memoryStatus.status, null);
  assert.equal(memoryStatus.injection_enabled, null);
  assert.equal(memoryStatus.record_count, null);

  const memoryValidation = normalizeMemoryManagerValidationProjectionBridgeResult({
    source: "legacy_memory_validation_projection_fixture",
    ok: false,
    issues: [{ code: "invalid" }],
    warnings: [],
  });
  assert.equal(memoryValidation.object, null);
  assert.equal(memoryValidation.status, null);
  assert.equal(memoryValidation.issue_count, null);
  assert.equal(memoryValidation.record_count, null);

  const mcpCatalog = normalizeMcpManagerCatalogProjectionBridgeResult({
    source: "legacy_mcp_catalog_projection_fixture",
    tools: [{ stable_tool_id: "mcp.docs.search" }],
    enabled_tools: [{ stable_tool_id: "mcp.docs.search" }],
  });
  assert.equal(mcpCatalog.object, null);
  assert.equal(mcpCatalog.status, null);
  assert.equal(mcpCatalog.tool_count, null);
  assert.equal(mcpCatalog.enabled_tool_count, null);

  const mcpSummary = normalizeMcpManagerCatalogSummaryProjectionBridgeResult({
    source: "legacy_mcp_summary_projection_fixture",
    namespaces: ["search"],
  });
  assert.equal(mcpSummary.object, null);
  assert.equal(mcpSummary.status, null);
  assert.equal(mcpSummary.namespace_count, null);
  assert.equal(mcpSummary.preview_limit, null);
  assert.equal(mcpSummary.search_route, null);
  assert.equal(mcpSummary.fetch_route, null);
});

test("thread memory agent state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_thread_memory_agent_state_update_command",
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
  });

  const result = runner.planThreadMemoryAgentStateUpdate({
    thread_id: "thread_1",
    agent: { id: "agent_1", cwd: "/workspace" },
    control_kind: "memory_status",
    event_id: "event_memory_status",
    seq: 6,
    created_at: "2026-06-06T06:05:00.000Z",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_thread_memory_agent_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.control_kind, "memory_status");
  assert.equal(result.source, "rust_thread_memory_agent_state_update_command");
  assert.equal(result.operation_kind, "thread.memory_status");
  assert.equal(result.control.control_kind, "memory_status");
  assert.equal(result.control.event_id, "event_memory_status");
  assert.equal(Object.hasOwn(result.control, "controlKind"), false);
  assert.equal(Object.hasOwn(result.control, "eventId"), false);
  assert.equal(Object.hasOwn(result.control, "createdAt"), false);
  assert.equal(result.agent.updatedAt, "2026-06-06T06:05:00.000Z");
});

test("runtime bridge thread start agent state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_runtime_bridge_thread_start_agent_state_update_command",
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
              runtimeSessionId: "session_runtime",
              runtime_session_id: "session_runtime",
              runtimeBridgeId: "bridge_runtime",
              runtime_bridge_id: "bridge_runtime",
              runtime_profile: "runtime_service",
              runtime_bridge_source: "runtime_service",
              updatedAt: "2026-06-06T06:15:00.000Z",
            },
          };
    },
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_bridge_thread_start_agent_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.session_id, "session_runtime");
  assert.equal(result.source, "rust_runtime_bridge_thread_start_agent_state_update_command");
  assert.equal(result.operation_kind, "thread.runtime_bridge.start");
  assert.equal(result.bridge_start.bridge_id, "bridge_runtime");
  for (const field of ["runtimeProfile", "sessionId", "bridgeId", "updatedAt"]) {
    assert.equal(Object.hasOwn(result.bridge_start, field), false);
  }
  assert.equal(result.agent.runtimeSessionId, "session_runtime");
  assert.equal(result.agent.runtime_session_id, "session_runtime");
  assert.equal(result.agent.runtime_bridge_id, "bridge_runtime");
  assert.equal(result.agent.runtime_profile, "runtime_service");
  assert.equal(result.agent.runtime_bridge_source, "runtime_service");
});

test("runtime bridge thread control agent state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_runtime_bridge_thread_control_agent_state_update_command",
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
              runtimeBridgeStatus: "active",
              runtime_bridge_status: "active",
              updatedAt: "2026-06-06T06:20:00.000Z",
            },
          };
    },
  });

  const result = runner.planRuntimeBridgeThreadControlAgentStateUpdate({
    thread_id: "thread_1",
    agent: { id: "agent_1", cwd: "/workspace", runtime_profile: "runtime_service" },
    action: "resume",
    reason: "operator requested resume",
    updated_at: "2026-06-06T06:20:00.000Z",
    evidence_refs: ["runtime_bridge_thread_control_rust_owned"],
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_bridge_thread_control_agent_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.thread_id, "thread_1");
  assert.equal(captured.request.action, "resume");
  assert.equal(Object.hasOwn(captured.request, "threadId"), false);
  assert.equal(result.source, "rust_runtime_bridge_thread_control_agent_state_update_command");
  assert.equal(result.operation_kind, "thread.runtime_bridge.control");
  assert.equal(result.control.action, "resume");
  assert.equal(result.control.runtime_bridge_status, "active");
  assert.equal(Object.hasOwn(result.control, "runtimeBridgeStatus"), false);
  assert.equal(result.agent.status, "active");
  assert.equal(result.agent.runtime_bridge_status, "active");
});

test("runtime bridge turn run state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_runtime_bridge_turn_run_state_update_command",
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
  });

  const result = runner.planRuntimeBridgeTurnRunStateUpdate({
    thread_id: "thread_1",
    agent: { id: "agent_1", cwd: "/workspace" },
    projection: { run_id: "run_runtime" },
    run: {
      id: "run_runtime",
      agentId: "agent_1",
      mode: "send",
      status: "completed",
      createdAt: "2026-06-06T06:34:00.000Z",
      updatedAt: "2026-06-06T06:35:00.000Z",
    },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_runtime_bridge_turn_run_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.projection.run_id, "run_runtime");
  assert.equal(Object.hasOwn(captured.request.projection, "runId"), false);
  assert.equal(result.source, "rust_runtime_bridge_turn_run_state_update_command");
  assert.equal(result.operation_kind, "turn.runtime_bridge.submit");
  assert.equal(result.run.id, "run_runtime");
});

test("subagent record state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_subagent_record_state_update_command",
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
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_subagent_record_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "subagent.wait");
  assert.equal(captured.request.subagent.subagent_id, "subagent_1");
  assert.equal(result.source, "rust_subagent_record_state_update_command");
  assert.equal(result.operation_kind, "subagent.wait");
  assert.equal(result.subagent.subagent_id, "subagent_1");
});

test("agent create state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_agent_create_state_update_command",
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
  });

  const result = runner.planAgentCreateStateUpdate({
    agent: {
      id: "agent_create_one",
      status: "active",
      createdAt: "2026-06-06T05:15:00.000Z",
      updatedAt: "2026-06-06T05:15:00.000Z",
    },
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_agent_create_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.agent.id, "agent_create_one");
  assert.equal(result.source, "rust_agent_create_state_update_command");
  assert.equal(result.operation_kind, "agent.create");
  assert.equal(result.agent.id, "agent_create_one");
});

test("thread create state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_thread_create_state_update_command",
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
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_thread_create_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.agent.id, "agent_create_one");
  assert.equal(captured.request.thread.thread_id, "thread_create_one");
  assert.equal(result.source, "rust_thread_create_state_update_command");
  assert.equal(result.operation_kind, "thread.create");
  assert.equal(result.thread.thread_id, "thread_create_one");
  assert.equal(result.agent.id, "agent_create_one");
});

test("agent status state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_agent_status_state_update_command",
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
  });

  const result = runner.planAgentStatusStateUpdate({
    agent: { id: "agent_1", status: "active" },
    status: "archived",
    operation_kind: "agent.archive",
    updated_at: "2026-06-06T06:25:00.000Z",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_agent_status_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.status, "archived");
  assert.equal(result.source, "rust_agent_status_state_update_command");
  assert.equal(result.operation_kind, "agent.archive");
  assert.equal(result.agent.status, "archived");
});

test("agent delete state update runner sends Rust tombstone through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_agent_delete_state_update_command",
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
  });

  const result = runner.planAgentDeleteStateUpdate({
    agent: { id: "agent_1", status: "active" },
    operation_kind: "agent.delete",
    deleted_at: "2026-06-06T06:40:00.000Z",
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_agent_delete_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.operation_kind, "agent.delete");
  assert.equal(result.source, "rust_agent_delete_state_update_command");
  assert.equal(result.operation_kind, "agent.delete");
  assert.equal(result.agent.status, "deleted");
  assert.equal(result.agent.deletedAt, "2026-06-06T06:40:00.000Z");
});

test("run create state update runner sends Rust state update through direct daemon-core invoker", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    daemonCoreInvoker(request) {
      captured = request;
      return {
            source: "rust_run_create_state_update_command",
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
  });

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

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "plan_run_create_state_update");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(
    captured.request.schema_version,
    RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  );
  assert.equal(captured.request.run.id, "run_create_one");
  assert.equal(result.source, "rust_run_create_state_update_command");
  assert.equal(result.operation_kind, "run.create");
  assert.equal(result.run.usage_telemetry.total_tokens, 7);
});

test("context policy runner fails closed without direct invoker", () => {
  const runner = new RustContextPolicyRunner();

  assert.throws(
    () => runner.evaluateContextBudgetPolicy({ usage_telemetry: { total_tokens: 1 } }),
    (error) =>
      error instanceof ContextPolicyRunnerError &&
      error.code === "context_policy_direct_invoker_unconfigured",
  );
});

test("context policy state update runner fails closed without Rust-planned operation kinds", () => {
  assert.throws(
    () =>
      normalizeContextCompactionStateUpdateBridgeResult({
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
      normalizeOperatorInterruptStateUpdateBridgeResult({
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
      normalizeThreadControlAgentStateUpdateBridgeResult({
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
      normalizeWorkspaceTrustControlStateUpdateBridgeResult({
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
      normalizeSubagentRecordStateUpdateBridgeResult({
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
      normalizeAgentCreateStateUpdateBridgeResult({
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
