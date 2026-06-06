import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
  CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_POLICY_COMMAND_SCHEMA_VERSION,
  DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  RustContextPolicyRunner,
  THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
  THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
} from "./runtime-context-policy-runner.mjs";

test("context budget policy runner sends generic Rust policy bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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
    command: "ioi-step-module-bridge",
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
    command: "ioi-step-module-bridge",
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
    command: "ioi-step-module-bridge",
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
    command: "ioi-step-module-bridge",
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
              eventId: "event_1",
              seq: 1,
            },
            context_compaction: {
              eventId: "event_1",
              seq: 1,
              compactedTokens: 0,
            },
            run: {
              id: "run_1",
              updatedAt: "2026-06-05T12:00:00.000Z",
              trace: {
                contextCompaction: {
                  eventId: "event_1",
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
  assert.equal(result.operator_control.eventId, "event_1");
  assert.equal(result.context_compaction.compactedTokens, 0);
  assert.equal(result.run.trace.contextCompaction.eventId, "event_1");
});

test("coding tool budget recovery state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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
              approvalId: "approval_budget",
              eventId: "event_retry",
            },
            run: {
              id: "run_budget",
              updatedAt: "2026-06-06T04:05:00.000Z",
              trace: {
                operatorControls: [
                  {
                    control: "coding_tool_budget_recovery",
                    eventId: "event_retry",
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
  assert.equal(result.operator_control.approvalId, "approval_budget");
  assert.equal(result.run.trace.operatorControls[0].eventId, "event_retry");
});

test("diagnostics operator override state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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
              decisionId: "decision_override",
              eventId: "event_override",
            },
            run: {
              id: "run_blocked",
              status: "completed",
              diagnosticsBlockingGate: { status: "overridden" },
              trace: {
                operatorControls: [
                  {
                    control: "diagnostics_operator_override",
                    eventId: "event_override",
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
  assert.equal(result.operator_control.decisionId, "decision_override");
  assert.equal(result.run.trace.operatorControls[0].eventId, "event_override");
});

test("operator interrupt state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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
              eventId: "event_interrupt",
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
                    eventId: "event_interrupt",
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
  assert.equal(result.stop_condition.reason, "operator_interrupt");
  assert.equal(result.run.turnStatus, "interrupted");
});

test("operator steer state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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
              eventId: "event_steer",
            },
            run: {
              id: "run_budget",
              status: "running",
              turnStatus: "running",
              trace: {
                operatorControls: [
                  {
                    control: "steer",
                    eventId: "event_steer",
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
  assert.equal(result.run.trace.operatorControls[0].eventId, "event_steer");
});

test("run cancel state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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
    command: "ioi-step-module-bridge",
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
              controlKind: "thinking",
              eventId: "evt_thread_control",
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
      requestedModelId: "auto",
      selectedModel: "local-model",
      routeId: "route.local-first",
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
  assert.equal(captured.request.model_route.selectedModel, "local-model");
  assert.equal(result.source, "rust_thread_control_agent_state_update_command");
  assert.equal(result.operation_kind, "thread.thinking");
  assert.equal(result.control.eventId, "evt_thread_control");
  assert.equal(result.agent.modelId, "local-model");
});

test("mcp control agent state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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
              controlKind: "mcp_add",
              eventId: "event_mcp_add",
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
  assert.equal(result.control.eventId, "event_mcp_add");
  assert.equal(result.agent.mcpRegistry.servers[0].id, "mcp.docs");
});

test("thread memory agent state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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
              controlKind: "memory_status",
              eventId: "event_memory_status",
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
  assert.equal(result.control.eventId, "event_memory_status");
  assert.equal(result.agent.updatedAt, "2026-06-06T06:05:00.000Z");
});

test("agent create state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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

test("run create state update runner sends Rust state update bridge request", () => {
  let captured = null;
  const runner = new RustContextPolicyRunner({
    command: "ioi-step-module-bridge",
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
    /Context policy requires IOI_STEP_MODULE_COMMAND/,
  );
});
