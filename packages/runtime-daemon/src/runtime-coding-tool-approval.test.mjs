import assert from "node:assert/strict";
import test from "node:test";

import { createCodingToolApprovalPolicy } from "./runtime-coding-tool-approval.mjs";

function createPolicy() {
  return createCodingToolApprovalPolicy({
    approvalModeForThreadMode: (mode) => mode === "review" ? "human_required" : "suggest",
    codingToolInputSummary: (toolId, input) => ({ toolId, keys: Object.keys(input || {}).sort() }),
    doctorHash: (value) => `hash_${Buffer.from(String(value)).toString("hex").slice(0, 12)}`,
    normalizeArray: (value) => Array.isArray(value) ? value : [],
    normalizeThreadApprovalMode: (value, fallback) => value || fallback,
    normalizeThreadInteractionMode: (value) => {
      const text = String(value || "agent").trim().toLowerCase().replace(/-/g, "_");
      if (text === "bad") throw new Error("bad mode");
      return text;
    },
    normalizedAgentRuntimeControls: (agent = {}) => agent.runtimeControls || {},
    optionalString: (value) => typeof value === "string" ? value.trim() || null : null,
    uniqueStrings: (values = []) => [...new Set(values.filter(Boolean))],
  });
}

test("coding tool effect approval is not required for local reads", () => {
  const policy = createPolicy();

  assert.equal(policy.codingToolEffectRequiresApproval("local_read"), false);
  assert.equal(policy.codingToolEffectRequiresApproval("workspace_write"), true);
  assert.equal(policy.codingToolApprovalManifestForThread({
    agent: { mode: "agent" },
    threadId: "thread_1",
    toolId: "file__read",
    toolCallId: "call_1",
    toolContract: { effectClass: "local_read" },
    input: { path: "README.md" },
    request: {},
  }), null);
});

test("workflow approval policy normalizes nested coding pack controls", () => {
  const policy = createPolicy();
  const workflow = policy.codingToolWorkflowApprovalPolicy({
    toolPack: {
      coding: {
        nodeApprovalOverride: "require_approval",
        approvalMode: "human_required",
        trustProfile: "restricted",
      },
    },
  });

  assert.equal(workflow.requiresApproval, true);
  assert.equal(workflow.nodeApprovalOverride, "require_approval");
  assert.equal(workflow.approvalMode, "human_required");
  assert.equal(workflow.reason, "workflow_node_requires_approval");
});

test("coding tool approval manifest preserves schema aliases and detects ignored UI overrides", () => {
  const policy = createPolicy();
  const manifest = policy.codingToolApprovalManifestForThread({
    agent: {
      mode: "agent",
      runtimeControls: {
        mode: "plan",
        approvalMode: "suggest",
      },
    },
    threadId: "thread_1",
    turnId: "turn_1",
    toolId: "file__write",
    toolCallId: "call_1",
    toolContract: {
      effectClass: "workspace_write",
      riskDomain: "filesystem",
      authorityScopeRequirements: ["workspace.write", "workspace.write"],
      primitiveCapabilities: ["fs.write"],
    },
    input: { path: "src/app.js" },
    request: {
      approvalGranted: true,
      approvalMode: "human_required",
      threadMode: "agent",
    },
    workflowGraphId: "graph_1",
    workflowNodeId: "node_1",
  });

  assert.equal(manifest.schemaVersion, "ioi.runtime.coding-tool-approval-manifest.v1");
  assert.equal(manifest.status, "approval_required");
  assert.equal(manifest.policyReason, "thread_plan_mode_requires_approval");
  assert.equal(manifest.ui_override_ignored, true);
  assert.equal(manifest.threadMode, "plan");
  assert.equal(manifest.approvalMode, "suggest");
  assert.deepEqual(manifest.authorityScopeRequirements, ["workspace.write"]);
  assert.deepEqual(manifest.inputSummary, { toolId: "file__write", keys: ["path"] });
  assert.match(manifest.inputHash, /^hash_/);
});

test("coding tool approval manifest is omitted when no approval gate applies", () => {
  const policy = createPolicy();

  assert.equal(policy.codingToolApprovalManifestForThread({
    agent: { mode: "agent", runtimeControls: { mode: "agent", approvalMode: "suggest" } },
    threadId: "thread_1",
    toolId: "file__write",
    toolCallId: "call_1",
    toolContract: { effectClass: "workspace_write" },
    input: {},
    request: {},
  }), null);
});

test("coding tool approval retry match rejects retired camelCase manifests", () => {
  const policy = createPolicy();
  const requested = {
    thread_id: "thread_1",
    tool_id: "file__write",
    tool_call_id: "call_1",
    effect_class: "workspace_write",
    input_hash: "hash_1",
    workflow_node_id: "node_1",
  };
  const canonicalRetry = {
    thread_id: "thread_1",
    tool_id: "file__write",
    tool_call_id: "call_1",
    effect_class: "workspace_write",
    input_hash: "hash_1",
    workflow_node_id: "node_1",
  };
  const camelRetry = {
    threadId: "thread_1",
    toolId: "file__write",
    toolCallId: "call_1",
    effectClass: "workspace_write",
    inputHash: "hash_1",
    workflowNodeId: "node_1",
  };

  assert.equal(policy.codingToolApprovalManifestsMatch(requested, canonicalRetry), true);
  assert.equal(policy.codingToolApprovalManifestsMatch(requested, camelRetry), false);
  assert.equal(Object.hasOwn(camelRetry, "threadId"), true);
  assert.equal(policy.codingToolApprovalManifestsMatch(requested, { ...canonicalRetry, input_hash: "hash_2" }), false);
  assert.equal(policy.codingToolApprovalManifestsMatch(requested, { ...canonicalRetry, workflow_node_id: "node_2" }), false);
  assert.equal(policy.codingToolApprovalManifestsMatch(requested, null), false);
});
