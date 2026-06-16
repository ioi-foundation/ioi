import assert from "node:assert/strict";
import test from "node:test";

import { createCodingToolApprovalPolicy } from "./runtime-coding-tool-approval.mjs";

function createPolicy(options = {}) {
  return createCodingToolApprovalPolicy({
    approvalCore: options.approvalCore ?? approvalCoreMock(),
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

function approvalCoreMock({ capture = null } = {}) {
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
    projectApprovalSatisfaction(request) {
      capture?.(request);
      return {
        source: "rust_coding_tool_approval_satisfaction_projection_protocol",
        backend: "rust_authority",
        status: "projected",
        operation_kind: "coding_tool.approval.satisfaction_projection",
        thread_id: request.thread_id,
        approval_id: request.approval_id,
        approval_request: {
          approval_id: request.approval_id,
          thread_id: request.thread_id,
          event_id: "event_approval",
          seq: 3,
          payload_summary: {
            approval_manifest: request.approval_manifest,
          },
        },
        latest_decision: {
          approval_id: request.approval_id,
          thread_id: request.thread_id,
          event_id: "event_decision",
          seq: 4,
          event_kind: "approval.approved",
        },
        lease_state: {
          expired: false,
          lease_id: "lease_alpha",
          status: "active",
          expires_at: "2026-06-06T04:45:00.000Z",
        },
        expected_head: request.expected_head ?? null,
        state_root_before: request.state_root_before ?? null,
      };
    },
    planApprovalSatisfaction(request) {
      capture?.(request);
      return {
        source: "rust_coding_tool_approval_satisfaction_protocol",
        backend: "rust_authority",
        status: "satisfied",
        operation_kind: "coding_tool.approval.satisfaction",
        satisfied: true,
        approval_id: request.approval_id,
        decision_event_id: request.latest_decision?.event_id ?? null,
        decision_seq: request.latest_decision?.seq ?? null,
        lease_id: request.lease_state?.lease_id ?? null,
        expires_at: request.lease_state?.expires_at ?? null,
        reason: "approval_approved",
        receipt_refs: ["receipt_approval"],
        policy_decision_refs: ["policy_approval"],
      };
    },
    planApprovalBlock(request) {
      capture?.(request);
      return {
        source: "rust_coding_tool_approval_block_protocol",
        backend: "rust_authority",
        status: "blocked",
        operation_kind: "coding_tool.approval.block",
        approval_id: request.approval_gate?.approval_id ?? null,
        reason: request.approval_gate?.reason ?? "approval_not_satisfied",
        receipt_refs: ["receipt_block"],
        policy_decision_refs: ["policy_block"],
        artifact_refs: [],
        rollback_refs: request.rollback_refs ?? [],
        result: {
          schema_version: "ioi.runtime.coding-tool-result.v1",
          status: "blocked",
          approval_required: true,
          approval_satisfied: false,
        },
        event: {
          event_kind: "tool.blocked",
          status: "blocked",
          receipt_refs: ["receipt_block"],
          artifact_refs: [],
          rollback_refs: request.rollback_refs ?? [],
          payload_summary: {
            approval_required: true,
            approval_satisfied: false,
            approval_id: request.approval_gate?.approval_id ?? null,
          },
        },
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

test("coding tool approval manifest is planned by Rust authority core", () => {
  let capturedRequest = null;
  const policy = createPolicy({
    approvalCore: approvalCoreMock({
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
        approval_mode: "suggest",
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
      approval_mode: "human_required",
      thread_mode: "agent",
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

test("coding tool approval manifest ignores retired workflow policy aliases", () => {
  const capturedRequests = [];
  const policy = createPolicy({
    approvalCore: approvalCoreMock({
      capture: (request) => {
        capturedRequests.push(request);
      },
    }),
  });

  const manifest = policy.codingToolApprovalManifestForThread({
    agent: { mode: "agent", runtimeControls: { mode: "agent", approval_mode: "suggest" } },
    threadId: "thread_1",
    toolId: "file__write",
    toolCallId: "call_1",
    toolContract: { effectClass: "workspace_write" },
    input: { path: "src/app.js" },
    request: {
      toolPack: {
        coding: {
          approvalMode: "human_required",
          nodeApprovalOverride: "require_approval",
          trustProfile: "untrusted",
          requiresApproval: true,
        },
      },
      nodeApprovalOverride: "require_approval",
      approvalOverride: "require_approval",
      approvalMode: "human_required",
      trustProfile: "untrusted",
      requiresApproval: true,
      threadMode: "review",
    },
  });

  assert.equal(manifest, null);
  assert.equal(capturedRequests.length, 1);
  assert.equal(capturedRequests[0].workflow_policy.node_approval_override, "inherit");
  assert.equal(capturedRequests[0].workflow_policy.approval_mode, null);
  assert.equal(capturedRequests[0].workflow_policy.trust_profile, "local_private");
  assert.equal(capturedRequests[0].workflow_policy.requires_approval, false);
  assert.equal(capturedRequests[0].requested_approval_mode, null);
  assert.equal(capturedRequests[0].requested_mode, null);
});

test("coding tool approval manifest ignores retired UI override aliases", () => {
  const capturedRequests = [];
  const policy = createPolicy({
    approvalCore: approvalCoreMock({
      capture: (request) => {
        capturedRequests.push(request);
      },
    }),
  });

  for (const request of [{ approvalGranted: true }, { approved: true }]) {
    policy.codingToolApprovalManifestForThread({
      agent: { mode: "agent", runtimeControls: { mode: "plan", approval_mode: "suggest" } },
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

test("coding tool approval satisfaction is planned by Rust authority core", () => {
  const capturedProjectionRequests = [];
  const capturedSatisfactionRequests = [];
  const policy = createPolicy({
    approvalCore: approvalCoreMock({
      capture: (request) => {
        if (request.schema_version === "ioi.runtime.coding-tool-approval-satisfaction-projection-request.v1") {
          capturedProjectionRequests.push(request);
        }
        if (request.schema_version === "ioi.runtime.coding-tool-approval-satisfaction-request.v1") {
          capturedSatisfactionRequests.push(request);
        }
      },
    }),
  });
  const store = {
    stateDir: "/runtime-state",
    codingToolApprovalSatisfactionProjection(input) {
      throw new Error(`JS approval satisfaction projection must not be used: ${input.approval_id}`);
    },
    agentForThread() {
      throw new Error("JS approval agent projection must not be used");
    },
    listRuns() {
      throw new Error("JS approval run projection must not be used");
    },
    latestApprovalRequestEvent() {
      throw new Error("JS approval request readback must not be used");
    },
    runtimeEventStream() {
      throw new Error("JS approval decision stream must not be used");
    },
  };
  const approvalManifest = {
    thread_id: "thread_1",
    tool_id: "file.apply_patch",
    tool_call_id: "call_1",
    effect_class: "workspace_write",
    input_hash: "sha256:approval",
  };

  const result = policy.codingToolApprovalSatisfactionForThread({
    store,
    threadId: "thread_1",
    toolId: "file.apply_patch",
    toolCallId: "call_1",
    approval_manifest: approvalManifest,
    request: { approval_id: "approval_alpha" },
    workflowGraphId: "graph_1",
    workflowNodeId: "node_1",
  });

  assert.equal(capturedProjectionRequests.length, 1);
  assert.equal(capturedProjectionRequests[0].approval_id, "approval_alpha");
  assert.equal(capturedProjectionRequests[0].tool_id, "file.apply_patch");
  assert.equal(capturedProjectionRequests[0].state_dir, "/runtime-state");
  assert.equal(Object.hasOwn(capturedProjectionRequests[0], "run"), false);
  assert.equal(Object.hasOwn(capturedProjectionRequests[0], "agent"), false);
  assert.equal(capturedSatisfactionRequests.length, 1);
  assert.equal(capturedSatisfactionRequests[0].schema_version, "ioi.runtime.coding-tool-approval-satisfaction-request.v1");
  assert.equal(capturedSatisfactionRequests[0].thread_id, "thread_1");
  assert.equal(capturedSatisfactionRequests[0].approval_id, "approval_alpha");
  assert.equal(capturedSatisfactionRequests[0].approval_manifest, approvalManifest);
  assert.equal(capturedSatisfactionRequests[0].latest_decision.event_id, "event_decision");
  assert.equal(result.satisfied, true);
  assert.deepEqual(result.receipt_refs, ["receipt_approval"]);
});

test("coding tool approval block is planned by Rust authority core", () => {
  let capturedRequest = null;
  const policy = createPolicy({
    approvalCore: approvalCoreMock({
      capture: (request) => {
        if (request.schema_version === "ioi.runtime.coding-tool-approval-block-request.v1") {
          capturedRequest = request;
        }
      },
    }),
  });
  const approvalManifest = {
    thread_id: "thread_1",
    tool_id: "file.apply_patch",
    tool_call_id: "call_1",
    effect_class: "workspace_write",
    input_hash: "sha256:approval",
  };
  const approvalGate = {
    satisfied: false,
    approval_id: "approval_alpha",
    reason: "approval_required",
    receipt_refs: ["receipt_approval"],
    policy_decision_refs: ["policy_approval"],
  };

  const result = policy.codingToolApprovalBlockForThread({
    threadId: "thread_1",
    turnId: "turn_1",
    toolId: "file.apply_patch",
    toolCallId: "call_1",
    workspaceRoot: "/workspace/project",
    workflowGraphId: "graph_1",
    workflowNodeId: "node_1",
    request: { source: "runtime_auto" },
    approval_manifest: approvalManifest,
    approval_gate: approvalGate,
    input: { path: "src/app.js" },
    rollbackRefs: ["rollback_request"],
    receiptRefs: ["receipt_invocation"],
    policyDecisionRefs: ["policy_invocation"],
    receiptId: "receipt_tool",
    idempotencyKey: "thread:thread_1:coding-tool:call_1",
  });

  assert.equal(capturedRequest.schema_version, "ioi.runtime.coding-tool-approval-block-request.v1");
  assert.equal(capturedRequest.thread_id, "thread_1");
  assert.equal(capturedRequest.turn_id, "turn_1");
  assert.equal(capturedRequest.tool_id, "file.apply_patch");
  assert.equal(capturedRequest.workspace_root, "/workspace/project");
  assert.equal(capturedRequest.workflow_graph_id, "graph_1");
  assert.equal(capturedRequest.approval_manifest, approvalManifest);
  assert.equal(capturedRequest.approval_gate, approvalGate);
  assert.deepEqual(capturedRequest.input_summary, { toolId: "file.apply_patch", keys: ["path"] });
  assert.deepEqual(capturedRequest.rollback_refs, ["rollback_request"]);
  assert.deepEqual(capturedRequest.receipt_refs, ["receipt_invocation"]);
  assert.deepEqual(capturedRequest.policy_decision_refs, ["policy_invocation"]);
  assert.equal(result.status, "blocked");
  assert.equal(result.operation_kind, "coding_tool.approval.block");
  assert.equal(result.event.event_kind, "tool.blocked");
  assert.equal(result.result.status, "blocked");
});

test("coding tool approval manifest is omitted when no approval gate applies", () => {
  const policy = createPolicy();

  assert.equal(policy.codingToolApprovalManifestForThread({
    agent: { mode: "agent", runtimeControls: { mode: "agent", approval_mode: "suggest" } },
    threadId: "thread_1",
    toolId: "file__write",
    toolCallId: "call_1",
    toolContract: { effectClass: "workspace_write" },
    input: {},
    request: {},
  }), null);
});

test("coding tool approval retry match JS helper is retired", () => {
  const policy = createPolicy();

  assert.equal(Object.hasOwn(policy, "codingToolApprovalManifestsMatch"), false);
  assert.equal(policy.codingToolApprovalManifestsMatch, undefined);
});
