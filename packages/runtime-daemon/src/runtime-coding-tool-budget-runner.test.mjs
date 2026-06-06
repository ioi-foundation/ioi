import assert from "node:assert/strict";
import test from "node:test";

import {
  CODING_TOOL_BUDGET_COMMAND_SCHEMA_VERSION,
  CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
  RustCodingToolBudgetRunner,
} from "./runtime-coding-tool-budget-runner.mjs";

test("coding tool budget runner sends Rust policy bridge request", () => {
  let captured = null;
  const runner = new RustCodingToolBudgetRunner({
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

  const result = runner.evaluateBudgetPolicy({
    usage_telemetry: { total_tokens: 120 },
    thresholds: { max_total_tokens: 100, warn_at_ratio: 0.8 },
    mode: "block",
    thread_id: "thread_1",
  });

  assert.equal(captured.schema_version, CODING_TOOL_BUDGET_COMMAND_SCHEMA_VERSION);
  assert.equal(captured.operation, "evaluate_coding_tool_budget_policy");
  assert.equal(captured.backend, "rust_policy");
  assert.equal(captured.request.schema_version, CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION);
  assert.equal(captured.request.usage_telemetry.total_tokens, 120);
  assert.equal(result.source, "rust_coding_tool_budget_policy_command");
  assert.equal(result.status, "blocked");
  assert.deepEqual(result.policy_decision_refs, ["policy_context_budget_thread_test_blocked"]);
});

test("coding tool budget runner fails closed without bridge command", () => {
  const runner = new RustCodingToolBudgetRunner();

  assert.throws(
    () => runner.evaluateBudgetPolicy({ usage_telemetry: { total_tokens: 1 } }),
    /Coding-tool budget policy requires IOI_STEP_MODULE_COMMAND/,
  );
});
