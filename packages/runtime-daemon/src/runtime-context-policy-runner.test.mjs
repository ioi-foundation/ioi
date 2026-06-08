import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
  CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_POLICY_COMMAND_ARGS_ENV,
  CONTEXT_POLICY_COMMAND_ENV,
  CONTEXT_POLICY_COMMAND_SCHEMA_VERSION,
  DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
  MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
  MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
  OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RustContextPolicyRunner,
  SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  createContextPolicyRunnerFromEnv,
  normalizeAgentCreateStateUpdateBridgeResult,
  normalizeContextCompactionStateUpdateBridgeResult,
  normalizeOperatorInterruptStateUpdateBridgeResult,
  normalizeSubagentRecordStateUpdateBridgeResult,
  normalizeThreadControlAgentStateUpdateBridgeResult,
} from "./runtime-context-policy-runner.mjs";

function assertNoRetiredOperationKindDetailAliases(details) {
  for (const key of ["operationKind", "expectedOperationKind", "expectedOperationKinds", "expectedPrefix"]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
}

test("context policy runner env uses daemon-core command boundary", () => {
  const runner = createContextPolicyRunnerFromEnv({
    [CONTEXT_POLICY_COMMAND_ENV]: "ioi-runtime-daemon-core",
    [CONTEXT_POLICY_COMMAND_ARGS_ENV]: "--json",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired",
  });

  assert.equal(runner.command, "ioi-runtime-daemon-core");
  assert.deepEqual(runner.args, ["--json"]);
});

test("context budget policy runner sends generic Rust policy bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("coding tool budget runner sends Rust policy bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("compaction policy runner sends Rust policy bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("context compaction runner sends Rust plan bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("context compaction state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("coding tool budget recovery state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("diagnostics operator override state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("operator interrupt state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("operator steer state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("run cancel state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("thread control agent state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_thread_control_agent_state_update_command",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "thread.thinking",
            updated_at: "2026-06-06T05:00:00.000Z",
            control: {
              control_kind: "thinking",
              event_id: "evt_thread_control",
            },
            agent: {
              id: "agent_1",
              modelId: "local-model",
              runtimeControls: {
                model: {
                  selectedModel: "local-model",
                },
              },
            },
          },
        }),
        stderr: "",
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
  assert.equal(result.control.control_kind, "thinking");
  assert.equal(result.control.event_id, "evt_thread_control");
  for (const field of [
    "controlKind",
    "eventId",
    "createdAt",
    "workspaceTrustWarningEventId",
  ]) {
    assert.equal(Object.hasOwn(result.control, field), false);
  }
  assert.equal(result.agent.modelId, "local-model");
});

test("mcp control agent state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_mcp_manager_status_projection_command",
            backend: "rust_policy",
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
          },
        }),
        stderr: "",
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

test("MCP manager catalog projection runner sends Rust daemon-core projection request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_mcp_manager_catalog_projection_command",
            backend: "rust_policy",
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
          },
        }),
        stderr: "",
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
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_mcp_manager_catalog_summary_projection_command",
            backend: "rust_policy",
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
          },
        }),
        stderr: "",
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
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("thread memory agent state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("runtime bridge thread start agent state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_runtime_bridge_thread_start_agent_state_update_command",
            backend: "rust_policy",
            status: "planned",
            operation_kind: "thread.runtime_bridge.start",
            updated_at: "2026-06-06T06:15:00.000Z",
            bridge_start: {
              session_id: "session_runtime",
              bridge_id: "bridge_runtime",
              runtime_profile: "runtime_service",
              updated_at: "2026-06-06T06:15:00.000Z",
            },
            agent: {
              id: "agent_1",
              runtimeSessionId: "session_runtime",
              runtimeBridgeId: "bridge_runtime",
              updatedAt: "2026-06-06T06:15:00.000Z",
            },
          },
        }),
        stderr: "",
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
});

test("runtime bridge turn run state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("subagent record state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("agent create state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("agent status state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("run create state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-runtime-daemon-core",
    spawnSyncImpl(_command, _args, options) {
      captured = JSON.parse(options.input);
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
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
          },
        }),
        stderr: "",
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

test("context policy runner fails closed without bridge command", () => {
  const runner = new RustContextPolicyRunner();

  assert.throws(
    () => runner.evaluateContextBudgetPolicy({ usage_telemetry: { total_tokens: 1 } }),
    /Context policy requires IOI_RUNTIME_DAEMON_CORE_COMMAND/,
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
