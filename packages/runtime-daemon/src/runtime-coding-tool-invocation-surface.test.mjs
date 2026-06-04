import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeCodingToolInvocationSurface } from "./runtime-coding-tool-invocation-surface.mjs";

function createSurface(overrides = {}) {
  return createRuntimeCodingToolInvocationSurface({
    codingToolApprovalManifestForThread: () => null,
    codingToolBudgetPolicyForRequest: () => ({ status: "allowed" }),
    codingToolInvocationResultFromEvent(event, context = {}) {
      return { duplicate: true, event, context };
    },
    codingToolResultWithoutDrafts(result = {}, artifacts = []) {
      const publicResult = { ...result };
      delete publicResult.artifactDrafts;
      delete publicResult.artifact_drafts;
      return {
        ...publicResult,
        artifactRefs: artifacts.map((artifactRecord) => artifactRecord.id),
        receiptRefs: ["receipt_result"],
      };
    },
    diagnosticsRepairContextForRequest: (request = {}) => request.diagnosticsRepairContext ?? null,
    diagnosticsRepairContextForToolPack: (_request, _input, toolId) => ({ source: "tool_pack", toolId }),
    executeCodingTool: () => ({
      status: "completed",
      stdout: "patched",
      artifactDrafts: [{ name: "stdout.txt", content: "patched" }],
    }),
    ...overrides,
  });
}

function createStore() {
  const events = [];
  const idempotency = new Map();
  const calls = [];
  return {
    calls,
    events,
    idempotency,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return { id: "agent_alpha", cwd: "/tmp/workspace" };
    },
    threadForAgent(agent) {
      calls.push({ name: "threadForAgent", agent });
      return { latest_turn_id: "turn_latest" };
    },
    runtimeEventStream(eventStreamId) {
      calls.push({ name: "runtimeEventStream", eventStreamId });
      return { idempotency, events };
    },
    readCodingToolArtifact(threadId, artifactId, range) {
      calls.push({ name: "readArtifact", threadId, artifactId, range });
      return { artifactId };
    },
    retrieveCodingToolResult(threadId, query) {
      calls.push({ name: "retrieveResult", threadId, query });
      return { query };
    },
    materializeCodingToolArtifactDrafts(input) {
      calls.push({ name: "materializeArtifacts", input });
      return [{ id: "artifact_stdout" }];
    },
    prepareWorkspaceSnapshotForPatch(input) {
      calls.push({ name: "prepareSnapshot", input });
      return {
        record: {
          snapshotId: "snapshot_alpha",
          artifactRefs: ["artifact_snapshot"],
          receiptRefs: ["receipt_snapshot"],
        },
      };
    },
    appendCodingToolCommandStreamEvents(input) {
      calls.push({ name: "commandStream", input });
      return [{ event_id: "event_command_stream" }];
    },
    appendRuntimeEvent(event) {
      const stored = {
        ...event,
        event_id: `event_${events.length + 1}`,
        seq: events.length + 1,
        created_at: "2026-06-04T14:00:00.000Z",
      };
      events.push(stored);
      idempotency.set(event.idempotency_key, stored);
      return stored;
    },
    appendWorkspaceSnapshotEvent(input) {
      calls.push({ name: "appendSnapshotEvent", input });
      return { event_id: "event_snapshot" };
    },
    maybeRunPostEditDiagnostics(input) {
      calls.push({ name: "diagnostics", input });
      return { status: "completed", patchToolCallId: input.patchToolCallId };
    },
    codingToolApprovalSatisfaction(input) {
      calls.push({ name: "approvalSatisfaction", input });
      return { satisfied: false, reason: "approval_missing" };
    },
    blockCodingToolForApproval(input) {
      calls.push({ name: "blockApproval", input });
      return { status: "blocked", approval_required: true, approvalManifest: input.approvalManifest };
    },
    blockCodingToolForBudget(input) {
      calls.push({ name: "blockBudget", input });
      return {
        event: { event_id: "event_budget" },
        receipt_refs: ["receipt_budget"],
        policy_decision_refs: ["policy_budget"],
      };
    },
    invokeComputerUseBrowserDiscoveryTool(threadId, toolId, request) {
      calls.push({ name: "browserDiscovery", threadId, toolId, request });
      return { routed: "browser_discovery", toolId };
    },
  };
}

test("coding tool invocation surface completes apply-patch with artifacts, snapshot, and diagnostics", () => {
  const surface = createSurface();
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "file.apply_patch", {
    toolCallId: "tool_alpha",
    workflowGraphId: "graph_alpha",
    source: "runtime_auto",
    rollbackRefs: ["rollback_request"],
    input: { patch: "*** Begin Patch\n*** End Patch\n" },
  });

  assert.equal(result.status, "completed");
  assert.equal(result.tool_name, "file.apply_patch");
  assert.equal(result.tool_call_id, "tool_alpha");
  assert.equal(result.event.event_stream_id, "thread_alpha:events");
  assert.equal(result.event.event_kind, "tool.completed");
  assert.deepEqual(result.event.artifact_refs, ["artifact_stdout", "artifact_snapshot"]);
  assert.deepEqual(result.event.rollback_refs, ["snapshot_alpha", "rollback_request"]);
  assert.equal(result.workspace_snapshot.snapshotId, "snapshot_alpha");
  assert.equal(result.workspace_snapshot_event.event_id, "event_snapshot");
  assert.equal(result.auto_diagnostics.status, "completed");
  assert.equal(result.command_stream_events[0].event_id, "event_command_stream");
  assert.equal(result.event.payload_summary.diagnosticsRepairContext.toolId, "file.apply_patch");
});

test("coding tool invocation surface replays duplicate idempotent tool events", () => {
  const surface = createSurface();
  const store = createStore();
  const duplicateEvent = { event_id: "event_duplicate", payload_summary: { status: "completed" } };
  store.idempotency.set("thread:thread_alpha:coding-tool:tool_alpha", duplicateEvent);

  const result = surface.invokeThreadTool(store, "thread_alpha", "file.inspect", {
    toolCallId: "tool_alpha",
  });

  assert.equal(result.duplicate, true);
  assert.equal(result.event, duplicateEvent);
  assert.equal(result.context.toolId, "file.inspect");
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface fails closed for budget blocks", () => {
  const surface = createSurface({
    codingToolBudgetPolicyForRequest: () => ({
      status: "blocked",
      usageTelemetry: { promptTokens: 10 },
      policy_decision_refs: ["policy_budget"],
    }),
  });
  const store = createStore();

  assert.throws(
    () =>
      surface.invokeThreadTool(store, "thread_alpha", "file.inspect", {
        toolCallId: "tool_budget",
      }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "policy");
      assert.equal(error.details.event_id, "event_budget");
      assert.deepEqual(error.details.receipt_refs, ["receipt_budget"]);
      return true;
    },
  );
  assert.ok(store.calls.some((call) => call.name === "blockBudget"));
});

test("coding tool invocation surface returns approval block results before execution", () => {
  const approvalManifest = {
    thread_mode: "agent",
    approval_mode: "required",
    effect_class: "write",
  };
  const surface = createSurface({
    codingToolApprovalManifestForThread: () => approvalManifest,
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "file.inspect", {
    toolCallId: "tool_approval",
  });

  assert.equal(result.status, "blocked");
  assert.equal(result.approval_required, true);
  assert.equal(result.approvalManifest, approvalManifest);
  assert.ok(store.calls.some((call) => call.name === "approvalSatisfaction"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface preserves computer-use dispatch and not-found behavior", () => {
  const surface = createSurface();
  const store = createStore();

  const routed = surface.invokeThreadTool(store, "thread_alpha", "computer_use.browser_discovery", {});

  assert.equal(routed.routed, "browser_discovery");
  assert.throws(
    () => surface.invokeThreadTool(store, "thread_alpha", "not.a.tool", {}),
    (error) => error.status === 404 && error.details.toolId === "not.a.tool",
  );
});
