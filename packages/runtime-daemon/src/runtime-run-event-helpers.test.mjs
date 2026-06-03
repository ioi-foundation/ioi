import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeRunEventHelpers } from "./runtime-run-event-helpers.mjs";

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.length > 0))];
}

function helpers() {
  const computerUseTypes = new Set([
    "computer_use_action_executed",
    "computer_use_cleanup",
    "computer_use_environment_unavailable",
    "computer_use_observation",
  ]);
  return createRuntimeRunEventHelpers({
    isComputerUseRunEventType: (type) => computerUseTypes.has(type),
    normalizeArray,
    objectRecord,
    uniqueStrings,
  });
}

test("runtime run event helpers preserve event status mapping", () => {
  const runtime = helpers();

  assert.equal(runtime.runtimeEventStatusForRunEvent({ type: "job_queued" }), "queued");
  assert.equal(runtime.runtimeEventStatusForRunEvent({ type: "delta" }), "running");
  assert.equal(runtime.runtimeEventStatusForRunEvent({
    type: "context_pressure_alert",
    data: { alert_level: "blocked" },
  }), "blocked");
  assert.equal(runtime.runtimeEventStatusForRunEvent({
    type: "lsp_diagnostics_injected",
    data: { blocking: true, diagnosticStatus: "findings" },
  }), "blocked");
  assert.equal(runtime.runtimeEventStatusForRunEvent({ type: "computer_use_cleanup" }), "completed");
  assert.equal(runtime.runtimeEventStatusForRunEvent({ type: "computer_use_observation" }), "running");
  assert.equal(runtime.runtimeEventStatusForRunEvent({ type: "computer_use_environment_unavailable" }), "blocked");
});

test("runtime run event helpers preserve refs and metadata derivation", () => {
  const runtime = helpers();

  assert.deepEqual(runtime.policyDecisionRefsForRunEvent({
    type: "policy_blocked",
    data: {
      policyDecisionId: "policy-a",
      policy_decision_ref: "policy-b",
      policyDecisionReceipt: { policy_decision_ref: "policy-c" },
      policyDecisionRefs: ["policy-a", "policy-d"],
      policy_decision_refs: ["policy-e"],
    },
  }), ["policy-a", "policy-b", "policy-c", "policy-d", "policy-e"]);

  assert.equal(runtime.componentKindForRunEvent({ type: "memory_update", data: { operation: "policy_update" } }), "memory_policy");
  assert.equal(runtime.componentKindForRunEvent({ type: "policy_blocked", data: { componentKind: "custom_gate" } }), "custom_gate");
  assert.equal(runtime.workflowNodeForRunEvent({
    type: "model_route_decision",
    data: { workflowNodeId: "workflow.route" },
  }), "workflow.route");
  assert.equal(runtime.workflowNodeForRunEvent("context_pressure_alert"), "runtime.context-pressure-alert");
});

test("runtime run event helpers preserve payload records, receipts, and artifacts", () => {
  const runtime = helpers();

  assert.deepEqual(runtime.stringRecord({
    alpha: "one",
    beta: 2,
    gamma: { nested: true },
  }), {
    alpha: "one",
    beta: "2",
    gamma: "{\"nested\":true}",
  });

  assert.deepEqual(runtime.receiptRefsForRunEvent({ type: "run_started", runId: "run-one" }), ["receipt_run-one_policy"]);
  assert.deepEqual(runtime.receiptRefsForRunEvent({
    type: "hook_dry_run_plan",
    data: { receipt_id: "receipt-hook", policy_receipt_id: "receipt-policy" },
  }), ["receipt-hook", "receipt-policy"]);
  assert.deepEqual(runtime.receiptRefsForRunEvent({
    type: "lsp_diagnostics_injected",
    data: { receiptId: "receipt-lsp", receiptRefs: ["receipt-extra"] },
  }), ["receipt-lsp", "receipt-extra"]);

  assert.deepEqual(runtime.artifactRefsForRunEvent({ type: "runtime_task" }), ["runtime-task.json"]);
  assert.deepEqual(runtime.artifactRefsForRunEvent({ type: "artifact", data: { artifactNames: ["one.json"] } }), ["one.json"]);
  assert.deepEqual(runtime.artifactRefsForRunEvent({
    type: "policy_blocked",
    data: { reason: "post_edit_diagnostics_findings" },
  }), ["diagnostics-blocking-gate.json"]);
});

test("runtime run event helpers preserve computer-use artifact refs", () => {
  const runtime = helpers();

  const event = {
    type: "computer_use_action_executed",
    data: {
      observation_bundle: {
        screenshot_ref: "shot.png",
        somRef: "som.json",
        ax_ref: "ax.json",
      },
      cleanupReceipt: {
        retainedArtifactRefs: ["shot.png", "cleanup.json"],
      },
      computer_use_visual_artifact_refs: ["visual.png"],
    },
  };

  assert.deepEqual(runtime.computerUseArtifactRefsForRunEvent(event), [
    "computer-use-trace.json",
    "shot.png",
    "som.json",
    "ax.json",
    "cleanup.json",
    "visual.png",
  ]);
  assert.deepEqual(runtime.artifactRefsForRunEvent(event), [
    "computer-use-trace.json",
    "shot.png",
    "som.json",
    "ax.json",
    "cleanup.json",
    "visual.png",
  ]);
});
