import assert from "node:assert/strict";
import test from "node:test";

import { createCodingToolApprovalPolicy } from "./runtime-coding-tool-approval.mjs";

function createPolicy(options = {}) {
  return createCodingToolApprovalPolicy({
    approvalRunner: options.approvalRunner ?? approvalRunnerMock(),
    approvalModeForThreadMode: (mode) => mode === "review" ? "human_required" : "suggest",
    codingToolInputSummary: (toolId, input) => ({ toolId, keys: Object.keys(input || {}).sort() }),
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

function approvalRunnerMock({ capture = null } = {}) {
  return {
    planApprovalManifest(request) {
      capture?.(request);
      if (request.effect_class === "local_read") {
        return {
          approval_required: false,
          workflow_policy: {
            schema_version: "ioi.runtime.workflow-tool-approval-policy.v1",
            source: "react_flow",
            requires_approval: false,
            node_approval_override: "inherit",
            approval_mode: null,
            trust_profile: "local_private",
            reason: "workflow_approval_mode_requires_approval",
          },
          manifest: null,
          input_hash: "sha256:local-read",
        };
      }
      const approvalRequired =
        request.thread_mode === "plan" ||
        request.thread_mode === "review" ||
        request.approval_mode === "human_required" ||
        request.approval_mode === "policy_required" ||
        Boolean(request.workflow_policy.requires_approval) ||
        request.requested_approval_mode === "human_required" ||
        request.requested_approval_mode === "policy_required";
      if (!approvalRequired) {
        return {
          approval_required: false,
          workflow_policy: {
            schema_version: "ioi.runtime.workflow-tool-approval-policy.v1",
            source: "react_flow",
            requires_approval: false,
            node_approval_override: request.workflow_policy.node_approval_override,
            approval_mode: request.workflow_policy.approval_mode,
            trust_profile: request.workflow_policy.trust_profile,
            reason: "workflow_approval_mode_requires_approval",
          },
          manifest: null,
          input_hash: "sha256:no-approval",
        };
      }
      const workflowPolicy = {
        schema_version: "ioi.runtime.workflow-tool-approval-policy.v1",
        source: "react_flow",
        requires_approval: true,
        node_approval_override: request.workflow_policy.node_approval_override,
        approval_mode: request.workflow_policy.approval_mode,
        trust_profile: request.workflow_policy.trust_profile,
        reason: "workflow_node_requires_approval",
      };
      return {
        approval_required: true,
        workflow_policy: workflowPolicy,
        manifest: {
          schema_version: "ioi.runtime.coding-tool-approval-manifest.v1",
          object: "ioi.runtime_coding_tool_approval_manifest",
          action: "coding_tool.invoke",
          status: "approval_required",
          approval_required: true,
          policy_reason: "thread_plan_mode_requires_approval",
          daemon_enforced: true,
          ui_override_ignored: true,
          workflow_policy: workflowPolicy,
          thread_id: request.thread_id,
          turn_id: request.turn_id,
          tool_id: request.tool_id,
          tool_call_id: request.tool_call_id,
          effect_class: request.effect_class,
          risk_domain: request.risk_domain,
          authority_scope_requirements: request.authority_scope_requirements,
          primitive_capabilities: request.primitive_capabilities,
          thread_mode: request.thread_mode,
          approval_mode: request.approval_mode,
          trust_profile: request.trust_profile,
          workflow_trust_profile: workflowPolicy.trust_profile,
          node_requires_approval: workflowPolicy.requires_approval,
          node_approval_override: workflowPolicy.node_approval_override,
          requested_mode: request.requested_mode,
          normalized_requested_mode: request.normalized_requested_mode,
          requested_approval_mode: request.requested_approval_mode,
          workflow_graph_id: request.workflow_graph_id,
          workflow_node_id: request.workflow_node_id,
          input_summary: request.input_summary,
          input_hash: "sha256:rust-planned",
        },
        input_hash: "sha256:rust-planned",
      };
    },
  };
}

test("coding tool approval manifest is omitted for Rust-planned local reads", () => {
  const policy = createPolicy();

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

test("coding tool approval manifest is planned by Rust authority runner", () => {
  let capturedRequest = null;
  const policy = createPolicy({
    approvalRunner: approvalRunnerMock({
      capture: (request) => {
        capturedRequest = request;
      },
    }),
  });
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
      approval_granted: true,
      approvalMode: "human_required",
      threadMode: "agent",
    },
    workflowGraphId: "graph_1",
    workflowNodeId: "node_1",
  });

  assert.equal(capturedRequest.schema_version, "ioi.runtime.coding-tool-approval-request.v1");
  assert.equal(capturedRequest.workflow_policy.node_approval_override, "inherit");
  assert.equal(capturedRequest.workflow_policy.approval_mode, "human_required");
  assert.equal(capturedRequest.ui_override_requested, true);
  assert.deepEqual(capturedRequest.input_summary, { toolId: "file__write", keys: ["path"] });
  assert.equal(manifest.schema_version, "ioi.runtime.coding-tool-approval-manifest.v1");
  assert.equal(manifest.status, "approval_required");
  assert.equal(manifest.policy_reason, "thread_plan_mode_requires_approval");
  assert.equal(manifest.ui_override_ignored, true);
  assert.equal(manifest.thread_mode, "plan");
  assert.equal(manifest.approval_mode, "suggest");
  assert.deepEqual(manifest.authority_scope_requirements, ["workspace.write"]);
  assert.deepEqual(manifest.input_summary, { toolId: "file__write", keys: ["path"] });
  assert.match(manifest.input_hash, /^sha256:/);
});

test("coding tool approval manifest ignores retired UI override aliases", () => {
  const capturedRequests = [];
  const policy = createPolicy({
    approvalRunner: approvalRunnerMock({
      capture: (request) => {
        capturedRequests.push(request);
      },
    }),
  });

  for (const request of [{ approvalGranted: true }, { approved: true }]) {
    policy.codingToolApprovalManifestForThread({
      agent: { mode: "agent", runtimeControls: { mode: "plan", approvalMode: "suggest" } },
      threadId: "thread_1",
      toolId: "file__write",
      toolCallId: "call_1",
      toolContract: { effectClass: "workspace_write" },
      input: { path: "src/app.js" },
      request,
    });
  }

  assert.equal(capturedRequests.length, 2);
  assert.deepEqual(capturedRequests.map((request) => request.ui_override_requested), [false, false]);
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
