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
  assert.equal(result.step_module.backend, "daemon_js");
  assert.equal(result.step_module.invocation.schema_version, "ioi.step_module_invocation.v1");
  assert.equal(result.step_module.result.schema_version, "ioi.step_module_result.v1");
  assert.equal(result.event.payload_summary.step_module_backend, "daemon_js");
  assert.equal(
    result.event.payload_summary.step_module_invocation.invocation_id,
    result.step_module.invocation.invocation_id,
  );
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

test("coding tool invocation surface runs workspace.status through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_command",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/workspace.status",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/workspace.status",
          status: "success",
          execution_result_ref: "result://rust-live/workspace.status",
          normalized_observation_ref: "observation://rust-live/workspace.status",
          receipt_refs: ["receipt://rust-live/workspace.status"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_status",
            component_kind: "CodingToolNode",
            status: "live",
            attempt_id: "attempt://rust-live/workspace.status",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/workspace.status"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        bridge_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          shadow_observation: {
            tool: "workspace.status",
            include_ignored: true,
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
    executeCodingTool() {
      throw new Error("daemon JS execution must not run");
    },
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "workspace.status", {
    toolCallId: "tool_status",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_status",
    input: { includeIgnored: true },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.workflowProjectionStatus, "live");
  assert.equal(result.result.rustWorkload, true);
  assert.equal(result.result.executionResultRef, "result://rust-live/workspace.status");
  assert.equal(result.result.routerAdmission.schema_version, "ioi.step_module_router_admission.v1");
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.equal(result.event.payload_summary.step_module_backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/workspace.status"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs file.inspect through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_command",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/file.inspect",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/file.inspect",
          status: "success",
          execution_result_ref: "result://rust-live/file.inspect",
          normalized_observation_ref: "observation://rust-live/file.inspect",
          receipt_refs: ["receipt://rust-live/file.inspect"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_inspect",
            component_kind: "FilesystemToolNode",
            status: "live",
            attempt_id: "attempt://rust-live/file.inspect",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/file.inspect"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        bridge_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          shadow_observation: {
            tool: "file.inspect",
            result: {
              schemaVersion: "ioi.runtime.coding-tool-result.v1",
              workspaceRoot: "/tmp/workspace",
              path: "README.md",
              kind: "file",
              exists: true,
              sizeBytes: 42,
              preview: "# IOI",
              previewBytes: 5,
              previewHash: "sha256:test",
              truncated: false,
              previewLineCount: 1,
              shellFallbackUsed: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
    executeCodingTool() {
      throw new Error("daemon JS execution must not run");
    },
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "file.inspect", {
    toolCallId: "tool_inspect",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_inspect",
    input: { path: "README.md" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.workflowProjectionStatus, "live");
  assert.equal(result.result.rustWorkload, true);
  assert.equal(result.result.path, "README.md");
  assert.equal(result.result.kind, "file");
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/file.inspect"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs git.diff through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_command",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/git.diff",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/git.diff",
          status: "success",
          execution_result_ref: "result://rust-live/git.diff",
          normalized_observation_ref: "observation://rust-live/git.diff",
          receipt_refs: ["receipt://rust-live/git.diff"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_diff",
            component_kind: "GitToolNode",
            status: "live",
            attempt_id: "attempt://rust-live/git.diff",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/git.diff"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        bridge_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          shadow_observation: {
            tool: "git.diff",
            result: {
              schemaVersion: "ioi.runtime.coding-tool-result.v1",
              workspaceRoot: "/tmp/workspace",
              paths: ["README.md"],
              git: { available: true },
              diff: "diff --git a/README.md b/README.md",
              diffBytes: 128,
              diffHash: "abc123",
              truncated: false,
              stat: " README.md | 1 +",
              shellFallbackUsed: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
    executeCodingTool() {
      throw new Error("daemon JS execution must not run");
    },
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "git.diff", {
    toolCallId: "tool_diff",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_diff",
    input: { path: "README.md" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.workflowProjectionStatus, "live");
  assert.equal(result.result.rustWorkload, true);
  assert.deepEqual(result.result.paths, ["README.md"]);
  assert.equal(result.result.diffHash, "abc123");
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/git.diff"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface keeps non-migrated tools blocked in rust workload live mode", () => {
  const surface = createSurface({
    stepModuleRunner: {
      backend: "rust_workload_live",
      blocksDaemonJsExecution: true,
      runCodingTool() {
        throw new Error("non-migrated tool should not reach StepModule runner");
      },
    },
  });
  const store = createStore();

  assert.throws(
    () =>
      surface.invokeThreadTool(store, "thread_alpha", "file.apply_patch", {
        toolCallId: "tool_patch",
        input: { path: "README.md", oldText: "a", newText: "b" },
      }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "policy");
      assert.equal(error.details.reason, "step_module_rust_workload_not_live");
      return true;
    },
  );
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
