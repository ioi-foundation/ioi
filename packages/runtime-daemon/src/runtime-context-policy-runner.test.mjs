import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  CONTEXT_POLICY_COMMAND_SCHEMA_VERSION,
  RustContextPolicyRunner,
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
  });

  assert.equal(captured.schema_version, CONTEXT_POLICY_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "evaluate_context_budget_policy");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(captured.request.schema_version, CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.request.usage_telemetry.total_tokens, 120);
  assert.equal(result.source, "rust_context_budget_policy_command");
  assert.equal(result.status, "blocked");
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
});

test("context policy runner fails closed without bridge command", () => {
  const runner = new RustContextPolicyRunner();

  assert.throws(
    () => runner.evaluateContextBudgetPolicy({ usage_telemetry: { total_tokens: 1 } }),
    /Context policy requires IOI_STEP_MODULE_COMMAND/,
  );
});
