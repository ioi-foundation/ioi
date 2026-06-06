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
    stepModuleRunner: createShadowStepModuleRunner(),
    ...overrides,
  });
}

function createShadowStepModuleRunner() {
  return {
    backend: "rust_workload_shadow",
    blocksDaemonJsExecution: false,
    runCodingTool({ toolId, context = {} }) {
      const invocationId = `invocation://shadow/${toolId}`;
      return {
        backend: "rust_workload_shadow",
        mode: "shadow",
        blocking: false,
        source: "rust_workload_shadow_test",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: invocationId,
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: invocationId,
          status: "success",
          receipt_refs: context.receiptRefs ?? [],
          artifact_refs: context.artifactRefs ?? [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            status: context.workflowProjectionStatus ?? "shadow",
          },
        },
      };
    },
  };
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
      return {
        schema_version: "ioi.runtime.coding-tool-result.v1",
        artifact_id: artifactId,
        artifact_refs: [artifactId],
        content: "stored artifact\n",
        content_hash: "artifact-content-hash",
        full_content_hash: "artifact-full-hash",
        offset_bytes: range?.offsetBytes ?? 0,
        length_bytes: 16,
        total_bytes: 16,
        truncated: false,
        receipt_refs: ["receipt_artifact_read"],
        shell_fallback_used: false,
      };
    },
    retrieveCodingToolResult(threadId, query) {
      calls.push({ name: "retrieveResult", threadId, query });
      return {
        schema_version: "ioi.runtime.coding-tool-result.v1",
        tool_call_id: query.tool_call_id ?? "tool_from_artifact",
        artifact_id: query.artifact_id ?? "artifact_result",
        artifact_refs: [query.artifact_id ?? "artifact_result"],
        channel: query.channel ?? "stdout",
        content: "stored result\n",
        content_hash: "result-content-hash",
        full_content_hash: "result-full-hash",
        offset_bytes: query.range?.offsetBytes ?? 0,
        length_bytes: 14,
        total_bytes: 14,
        truncated: false,
        available_artifacts: [{ artifact_id: query.artifact_id ?? "artifact_result", channel: query.channel ?? "stdout" }],
        receipt_refs: ["receipt_tool_retrieve_result"],
        shell_fallback_used: false,
      };
    },
    materializeCodingToolArtifactDrafts(input) {
      calls.push({ name: "materializeArtifacts", input });
      return [{ id: "artifact_stdout" }];
    },
    prepareWorkspaceSnapshotForPatch(input) {
      calls.push({ name: "prepareSnapshot", input });
      return {
        record: {
          snapshot_id: "snapshot_alpha",
          artifact_refs: ["artifact_snapshot"],
          receipt_refs: ["receipt_snapshot"],
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
      return { status: "blocked", approval_required: true, approval_manifest: input.approvalManifest };
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

test("coding tool invocation surface rejects non-live coding-tool runners before JS execution", () => {
  const surface = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.invokeThreadTool(store, "thread_alpha", "file.apply_patch", {
        toolCallId: "tool_alpha",
        workflowGraphId: "graph_alpha",
        source: "runtime_auto",
        rollbackRefs: ["rollback_request"],
        input: { patch: "*** Begin Patch\n*** End Patch\n" },
      }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "policy");
      assert.equal(error.details.reason, "coding_tool_rust_workload_live_required");
      assert.equal(error.details.backend, "rust_workload_shadow");
      return true;
    },
  );
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
  assert.ok(!store.calls.some((call) => call.name === "commandStream"));
  assert.ok(!store.calls.some((call) => call.name === "prepareSnapshot"));
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
            result: {
              schemaVersion: "ioi.runtime.coding-tool-result.v1",
              workspaceRoot: "/tmp/workspace",
              git: {
                available: true,
                branch: "main",
                porcelainHash: "abc123",
              },
              changedFiles: [{ status: "M", path: "README.md" }],
              counts: { changed: 1, untracked: 0, ignored: 0 },
              shellFallbackUsed: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
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
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.git.available, true);
  assert.equal(result.result.git.branch, "main");
  assert.deepEqual(result.result.changedFiles, [{ status: "M", path: "README.md" }]);
  assert.equal(result.result.counts.changed, 1);
  assert.equal(result.result.execution_result_ref, "result://rust-live/workspace.status");
  assert.equal(result.result.router_admission.schema_version, "ioi.step_module_router_admission.v1");
  assert.equal(Object.hasOwn(result.result, "routerAdmission"), false);
  assert.equal(Object.hasOwn(result.result, "rustWorkload"), false);
  assert.equal(Object.hasOwn(result.result, "stepModuleBackend"), false);
  assert.equal(Object.hasOwn(result.result, "executionResultRef"), false);
  assert.equal(Object.hasOwn(result.result, "normalizedObservationRef"), false);
  assert.equal(Object.hasOwn(result.result, "receiptRefs"), false);
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.equal(result.event.payload_summary.step_module_backend, "rust_workload_live");
  assert.equal(result.event.payload_summary.approval_required, false);
  for (const field of [
    "approvalRequired",
    "approvalSatisfied",
    "approvalId",
    "approvalManifest",
    "approvalDecisionEventId",
    "diagnosticsRepairContext",
  ]) {
    assert.equal(Object.hasOwn(result.event.payload_summary, field), false);
  }
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
  assert.equal(result.result.rust_workload, true);
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
  assert.equal(result.result.rust_workload, true);
  assert.deepEqual(result.result.paths, ["README.md"]);
  assert.equal(result.result.diffHash, "abc123");
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/git.diff"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs lsp.diagnostics through rust workload live path", () => {
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
          invocation_id: "invocation://rust-live/lsp.diagnostics",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/lsp.diagnostics",
          status: "success",
          execution_result_ref: "result://rust-live/lsp.diagnostics",
          normalized_observation_ref: "observation://rust-live/lsp.diagnostics",
          receipt_refs: ["receipt://rust-live/lsp.diagnostics"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_diagnostics",
            component_kind: "LspDiagnosticsNode",
            status: "live",
            attempt_id: "attempt://rust-live/lsp.diagnostics",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/lsp.diagnostics"],
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
            tool: "lsp.diagnostics",
            result: {
              schemaVersion: "ioi.runtime.coding-tool-result.v1",
              workspaceRoot: "/tmp/workspace",
              commandId: "node.check",
              requestedCommandId: "node.check",
              resolvedCommandId: "node.check",
              command: "node --check",
              cwd: ".",
              backend: "node.check",
              backendStatus: "available",
              backendReason: null,
              fallbackUsed: false,
              fallbackFrom: null,
              projectContext: {
                schemaVersion: "ioi.runtime.diagnostics-project-context.v1",
                workspaceRoot: "/tmp/workspace",
                cwd: ".",
                paths: ["src/index.mjs"],
              },
              diagnosticStatus: "clean",
              diagnostics: [],
              diagnosticCount: 0,
              paths: ["src/index.mjs"],
              exitCode: 0,
              timedOut: false,
              durationMs: 12,
              timeoutMs: 30000,
              stdout: "",
              stderr: "",
              outputBytes: 0,
              outputHash: "abc123",
              truncated: false,
              spilloverRecommended: false,
              artifactDrafts: [],
              allowedCommandIds: ["auto", "node.check", "typescript.check"],
              shellFallbackUsed: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "lsp.diagnostics", {
    toolCallId: "tool_diagnostics",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_diagnostics",
    input: { commandId: "node.check", path: "src/index.mjs" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.workflowProjectionStatus, "live");
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.backend, "node.check");
  assert.equal(result.result.diagnosticStatus, "clean");
  assert.equal(result.result.diagnosticCount, 0);
  assert.deepEqual(result.result.paths, ["src/index.mjs"]);
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/lsp.diagnostics"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs test.run through rust workload live path", () => {
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
          invocation_id: "invocation://rust-live/test.run",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/test.run",
          status: "success",
          execution_result_ref: "result://rust-live/test.run",
          normalized_observation_ref: "observation://rust-live/test.run",
          receipt_refs: ["receipt://rust-live/test.run"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_test",
            component_kind: "TestRunNode",
            status: "live",
            attempt_id: "attempt://rust-live/test.run",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/test.run"],
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
            tool: "test.run",
            result: {
              schemaVersion: "ioi.runtime.coding-tool-result.v1",
              workspaceRoot: "/tmp/workspace",
              commandId: "node.test",
              command: "node --test",
              executable: "node",
              args: ["--test", "src/index.test.mjs"],
              cwd: ".",
              exitCode: 0,
              signal: null,
              testStatus: "passed",
              timedOut: false,
              durationMs: 18,
              timeoutMs: 60000,
              stdout: "ok 1 - passes",
              stderr: "",
              stdoutBytes: 13,
              stderrBytes: 0,
              outputBytes: 13,
              outputHash: "abc123",
              truncated: false,
              spilloverRecommended: false,
              artifactDrafts: [],
              allowedCommandIds: ["node.test", "npm.test", "cargo.test", "cargo.check"],
              shellFallbackUsed: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "test.run", {
    toolCallId: "tool_test",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_test",
    input: { commandId: "node.test", path: "src/index.test.mjs" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.workflowProjectionStatus, "live");
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.commandId, "node.test");
  assert.equal(result.result.testStatus, "passed");
  assert.equal(result.result.exitCode, 0);
  assert.deepEqual(result.result.args, ["--test", "src/index.test.mjs"]);
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/test.run"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs file.apply_patch through rust workload live path", () => {
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
          invocation_id: "invocation://rust-live/file.apply_patch",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/file.apply_patch",
          status: "success",
          execution_result_ref: "result://rust-live/file.apply_patch",
          normalized_observation_ref: "observation://rust-live/file.apply_patch",
          receipt_refs: ["receipt://rust-live/file.apply_patch"],
          artifact_refs: [],
          payload_refs: ["payload://workspace/file.apply_patch/README.md/after"],
          agentgres_operation_refs: ["agentgres://operation/file.apply_patch/README.md/after"],
          state_root_after: "state://workspace/README.md/after",
          resulting_head: "head://workspace/README.md/after",
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_patch",
            component_kind: "FilesystemPatchNode",
            status: "live",
            attempt_id: "attempt://rust-live/file.apply_patch",
            evidence_refs: ["evidence://agentgres/file.apply_patch"],
            receipt_refs: ["receipt://rust-live/file.apply_patch"],
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
            authoritative_transition: true,
          },
          agentgres_admission: {
            schema_version: "ioi.agentgres_admission.v1",
            operation_ref: "agentgres://operation/file.apply_patch/README.md/after",
            state_root_after: "state://workspace/README.md/after",
            resulting_head: "head://workspace/README.md/after",
          },
          shadow_observation: {
            tool: "file.apply_patch",
            result: {
              schemaVersion: "ioi.runtime.coding-tool-result.v1",
              workspaceRoot: "/tmp/workspace",
              path: "README.md",
              dryRun: false,
              applied: true,
              changed: true,
              created: false,
              editCount: 1,
              edits: [{ type: "replace", occurrence: "only", matches: 1 }],
              beforeHash: "beforehash",
              afterHash: "afterhash",
              diff: "--- a/README.md\n+++ b/README.md",
              diffBytes: 32,
              diffHash: "diffhash",
              truncated: false,
              changed_files: [
                {
                  path: "README.md",
                  before_hash: "beforehash",
                  after_hash: "afterhash",
                  before_exists: true,
                  after_exists: true,
                  before_size_bytes: 7,
                  after_size_bytes: 6,
                  before_mtime_ms: 1,
                  after_mtime_ms: 2,
                  created: false,
                  diagnostics_recommended: true,
                },
              ],
              workspace_snapshot_drafts: [
                {
                  path: "README.md",
                  encoding: "utf8",
                  before_exists: true,
                  after_exists: true,
                  before_content: "before\n",
                  after_content: "after\n",
                },
              ],
              diagnostics_recommended: true,
              receiptRefs: ["receipt_file_apply_patch_README.md_after"],
              payloadRefs: ["payload://workspace/file.apply_patch/README.md/after"],
              shellFallbackUsed: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "file.apply_patch", {
    toolCallId: "tool_patch",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_patch",
    input: { path: "README.md", oldText: "before", newText: "after" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.workflowProjectionStatus, "live");
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.applied, true);
  assert.equal(result.result.workspaceSnapshotId, "snapshot_alpha");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/file.apply_patch"));
  assert.ok(result.receipt_refs.includes("receipt_snapshot"));
  assert.ok(result.artifact_refs.includes("artifact_snapshot"));
  assert.equal(result.workspace_snapshot.snapshot_id, "snapshot_alpha");
  assert.equal(result.workspace_snapshot_event.event_id, "event_snapshot");
  assert.equal(result.auto_diagnostics.status, "completed");
  assert.equal(result.step_module.result.agentgres_operation_refs[0], "agentgres://operation/file.apply_patch/README.md/after");
  assert.ok(store.calls.some((call) => call.name === "prepareSnapshot"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs artifact.read through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      const artifactResult = input.input.rustWorkloadDataPlane.result;
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_command",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/artifact.read",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/artifact.read",
          status: "success",
          execution_result_ref: "result://rust-live/artifact.read",
          normalized_observation_ref: "observation://rust-live/artifact.read",
          receipt_refs: ["receipt://rust-live/artifact.read"],
          artifact_refs: artifactResult.artifact_refs,
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_artifact",
            component_kind: "ArtifactReadNode",
            status: "live",
            attempt_id: "attempt://rust-live/artifact.read",
            evidence_refs: ["evidence://rust-live/artifact.read"],
            receipt_refs: ["receipt://rust-live/artifact.read"],
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
            tool: "artifact.read",
            result: {
              ...artifactResult,
              backend: "rust_artifact_read",
              data_plane_source: "daemon_artifact_store",
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "artifact.read", {
    toolCallId: "tool_artifact",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_artifact",
    input: { artifact_id: "artifact_alpha", offsetBytes: 2, lengthBytes: 8 },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.workflowProjectionStatus, "live");
  assert.equal(runnerCalls[0].input.rustWorkloadDataPlane.source, "daemon_artifact_store");
  assert.equal(runnerCalls[0].input.rustWorkloadDataPlane.result.content, "stored artifact\n");
  assert.ok(store.calls.some((call) => call.name === "readArtifact"));
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.backend, "rust_artifact_read");
  assert.equal(result.result.artifact_id, "artifact_alpha");
  assert.equal(result.result.data_plane_source, "daemon_artifact_store");
  for (const field of ["artifactId", "dataPlaneSource", "shellFallbackUsed"]) {
    assert.equal(Object.hasOwn(result.result, field), false);
  }
  assert.ok(result.receipt_refs.includes("receipt://rust-live/artifact.read"));
  assert.ok(result.artifact_refs.includes("artifact_alpha"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));

  const readCallsBeforeRetiredAlias = store.calls.filter((call) => call.name === "readArtifact").length;
  const retiredArtifactAlias = surface.invokeThreadTool(store, "thread_alpha", "artifact.read", {
    toolCallId: "tool_artifact_retired",
    input: { artifactId: "artifact_alpha" },
  });
  assert.equal(retiredArtifactAlias.status, "failed");
  assert.equal(retiredArtifactAlias.result.error.code, "artifact_read_id_required");
  assert.equal(store.calls.filter((call) => call.name === "readArtifact").length, readCallsBeforeRetiredAlias);
});

test("coding tool invocation surface runs tool.retrieve_result through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      const retrieveResult = input.input.rustWorkloadDataPlane.result;
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_command",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/tool.retrieve_result",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/tool.retrieve_result",
          status: "success",
          execution_result_ref: "result://rust-live/tool.retrieve_result",
          normalized_observation_ref: "observation://rust-live/tool.retrieve_result",
          receipt_refs: ["receipt://rust-live/tool.retrieve_result"],
          artifact_refs: retrieveResult.artifact_refs,
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_retrieve",
            component_kind: "ToolRetrieveResultNode",
            status: "live",
            attempt_id: "attempt://rust-live/tool.retrieve_result",
            evidence_refs: ["evidence://rust-live/tool.retrieve_result"],
            receipt_refs: ["receipt://rust-live/tool.retrieve_result"],
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
            tool: "tool.retrieve_result",
            result: {
              ...retrieveResult,
              backend: "rust_tool_result_retrieve",
              data_plane_source: "daemon_artifact_store",
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "tool.retrieve_result", {
    toolCallId: "tool_retrieve",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_retrieve",
    input: { tool_call_id: "tool_patch", channel: "stdout", maxBytes: 32 },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.workflowProjectionStatus, "live");
  assert.equal(runnerCalls[0].input.rustWorkloadDataPlane.query.tool_call_id, "tool_patch");
  assert.equal(runnerCalls[0].input.rustWorkloadDataPlane.result.content, "stored result\n");
  assert.ok(store.calls.some((call) => call.name === "retrieveResult"));
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.backend, "rust_tool_result_retrieve");
  assert.equal(result.result.tool_call_id, "tool_patch");
  assert.equal(result.result.data_plane_source, "daemon_artifact_store");
  for (const field of ["toolCallId", "dataPlaneSource", "shellFallbackUsed"]) {
    assert.equal(Object.hasOwn(result.result, field), false);
  }
  assert.ok(result.receipt_refs.includes("receipt://rust-live/tool.retrieve_result"));
  assert.ok(result.artifact_refs.includes("artifact_result"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));

  const retrieveCallsBeforeRetiredAlias = store.calls.filter((call) => call.name === "retrieveResult").length;
  const retiredRetrieveAlias = surface.invokeThreadTool(store, "thread_alpha", "tool.retrieve_result", {
    toolCallId: "tool_retrieve_retired",
    input: { toolCallId: "tool_patch" },
  });
  assert.equal(retiredRetrieveAlias.status, "failed");
  assert.equal(retiredRetrieveAlias.result.error.code, "tool_retrieve_result_target_required");
  assert.equal(store.calls.filter((call) => call.name === "retrieveResult").length, retrieveCallsBeforeRetiredAlias);
});

test("coding tool invocation surface runs computer_use.request_lease through rust workload live path", () => {
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
          invocation_id: "invocation://rust-live/computer_use.request_lease",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/computer_use.request_lease",
          status: "success",
          execution_result_ref: "result://rust-live/computer_use.request_lease",
          normalized_observation_ref: "observation://rust-live/computer_use.request_lease",
          receipt_refs: [
            "receipt://rust-live/computer_use.request_lease",
            "receipt_computer_use_lease_request_alpha",
          ],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_computer_use",
            component_kind: "ComputerUseLeaseRequestNode",
            status: "live",
            attempt_id: "attempt://rust-live/computer_use.request_lease",
            evidence_refs: ["evidence://rust-live/computer_use.request_lease"],
            receipt_refs: ["receipt://rust-live/computer_use.request_lease"],
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
            tool: "computer_use.request_lease",
            result: {
              schemaVersion: "ioi.runtime.coding-tool-result.v1",
              object: "ioi.coding_agent_computer_use_lease_request",
              requestRef: "computer_use_lease_request_alpha",
              workspaceRoot: "/tmp/workspace",
              leaseRequest: {
                prompt: "Open the browser and click sign in.",
                lane: "native_browser",
                sessionMode: "controlled_relaunch",
                actionKind: "click",
                authorityScope: "computer_use.native_browser.act",
                repoAuthorityScope: "workspace.read",
                sharedClipboardPolicy: "disabled_until_explicit_approval",
                artifactPolicy: "redacted_trace_artifacts_only",
                approvalRef: null,
                failClosedWhenUnavailable: true,
                providerId: "ioi.computer_use.native_browser.task_scoped_profile",
                providerKind: "task_scoped_browser_profile",
                walletNetworkAuthorityRequiredBeforeExecution: true,
              },
              threadTool: {
                toolPack: "computer_use",
                toolName: "ioi.computer_use.native_browser",
                unavailableReason: null,
                input: {
                  prompt: "Open the browser and click sign in.",
                  actionKind: "click",
                  sessionMode: "controlled_relaunch",
                },
              },
              approvalRequiredBeforeExecution: true,
              walletNetworkAuthorityBoundary: {
                authorityLayer: "wallet.network",
                requiredBeforeExecution: true,
                grantRefs: [],
                receiptRefs: [],
              },
              evidenceRefs: [
                "computer_use_lease_request_alpha",
                "ioi.computer_use.native_browser.task_scoped_profile",
                "computer_use_lease_request_receipt",
                "coding_tool_receipt",
                "wallet.network.authority_boundary",
              ],
              receiptRefs: ["receipt_computer_use_lease_request_alpha"],
              shellFallbackUsed: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    stepModuleRunner: liveRunner,
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "computer_use.request_lease", {
    toolCallId: "tool_computer_use",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_computer_use",
    input: {
      prompt: "Open the browser and click sign in.",
      lane: "native_browser",
      sessionMode: "controlled_relaunch",
      actionKind: "click",
    },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.workflowProjectionStatus, "live");
  assert.equal(runnerCalls[0].input.actionKind, "click");
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.requestRef, "computer_use_lease_request_alpha");
  assert.equal(result.result.approvalRequiredBeforeExecution, true);
  assert.equal(result.result.walletNetworkAuthorityBoundary.authorityLayer, "wallet.network");
  assert.equal(result.result.leaseRequest.authorityScope, "computer_use.native_browser.act");
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/computer_use.request_lease"));
  assert.ok(result.receipt_refs.includes("receipt_computer_use_lease_request_alpha"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface fails closed for budget blocks", () => {
  const surface = createSurface({
    codingToolBudgetPolicyForRequest: () => ({
      status: "blocked",
      usage_telemetry: { prompt_tokens: 10 },
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
      assert.deepEqual(error.details.budget_usage_telemetry, {
        prompt_tokens: 10,
      });
      assert.equal(error.details.context_budget_status, "blocked");
      assert.deepEqual(error.details.policy_decision_refs, ["policy_budget"]);
      assert.equal(
        Object.prototype.hasOwnProperty.call(
          error.details,
          "budgetUsageTelemetry",
        ),
        false,
      );
      for (const field of [
        "contextBudgetStatus",
        "contextBudget",
        "eventId",
        "receiptRefs",
        "policyDecisionRefs",
      ]) {
        assert.equal(Object.hasOwn(error.details, field), false);
      }
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
  assert.equal(result.approval_manifest, approvalManifest);
  assert.equal(Object.hasOwn(result, "approvalManifest"), false);
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
