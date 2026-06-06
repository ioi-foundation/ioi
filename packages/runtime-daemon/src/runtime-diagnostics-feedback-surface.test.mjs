import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeDiagnosticsFeedbackSurface } from "./runtime-diagnostics-feedback-surface.mjs";

function createSurface() {
  return createRuntimeDiagnosticsFeedbackSurface({
    compactDiagnosticsFeedback({ threadId, mode, diagnosticEvents }) {
      return {
        threadId,
        mode,
        diagnosticCount: diagnosticEvents.length,
        eventIds: diagnosticEvents.map((event) => event.event_id),
      };
    },
    diagnosticsRepairPolicyConfig() {
      return {
        restorePolicy: "snapshot_restore",
        restoreConflictPolicy: "clean_preview_only",
        diagnosticsRepairDefault: "repair_retry",
        operatorOverrideRequiresApproval: true,
      };
    },
    normalizeDiagnosticsMode(value) {
      if (value === "off" || value === "skip") return "skip";
      if (value === "fail" || value === "blocking") return "blocking";
      return "advisory";
    },
    postEditDiagnosticsConfig(request = {}) {
      return {
        mode: request.mode ?? "advisory",
        commandId: "tsc",
        cwd: "/workspace",
        timeoutMs: 1000,
        maxOutputBytes: 4096,
      };
    },
  });
}

function createStore(events = []) {
  const calls = [];
  return {
    calls,
    invokeThreadTool(threadId, toolId, request) {
      calls.push({ threadId, toolId, request });
      return { ok: true, threadId, toolId, request };
    },
    runtimeEventStream() {
      return { events };
    },
  };
}

test("diagnostics feedback surface skips post-edit diagnostics when disabled or pathless", () => {
  const surface = createSurface();
  const store = createStore();

  assert.equal(
    surface.maybeRunPostEditDiagnostics(store, {
      threadId: "thread_alpha",
      patchToolCallId: "patch_alpha",
      request: { mode: "skip" },
      patchResult: { changedFiles: [{ path: "src/app.js" }] },
    }),
    null,
  );
  assert.equal(
    surface.maybeRunPostEditDiagnostics(store, {
      threadId: "thread_alpha",
      patchToolCallId: "patch_alpha",
      patchResult: { changedFiles: [{ diagnosticsRecommended: true }] },
    }),
    null,
  );
  assert.equal(store.calls.length, 0);
});

test("diagnostics feedback surface invokes lsp diagnostics with repair context", () => {
  const surface = createSurface();
  const store = createStore();

  const result = surface.maybeRunPostEditDiagnostics(store, {
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    patchToolCallId: "patch_alpha",
    workflowGraphId: "graph_alpha",
    request: {
      workflow_node_id: "patch_node",
    },
    patchResult: {
      changedFiles: [
        {
          path: "src/app.js",
          beforeHash: "before_hash",
          afterHash: "after_hash",
        },
        {
          path: "README.md",
          diagnosticsRecommended: false,
        },
      ],
      workspaceSnapshotId: "snapshot_alpha",
      workspaceSnapshot: {
        restore: { previewSupported: true },
      },
      rollbackRefs: ["rollback_alpha"],
    },
  });

  assert.equal(result.toolId, "lsp.diagnostics");
  assert.equal(store.calls.length, 1);
  const request = store.calls[0].request;
  assert.equal(request.workflow_node_id, "runtime.coding-tool.lsp-diagnostics.auto");
  assert.deepEqual(request.rollback_refs, ["snapshot_alpha", "rollback_alpha"]);
  assert.equal(request.diagnostics_repair_context.workspace_snapshot_id, "snapshot_alpha");
  assert.equal(request.diagnostics_repair_context.source_workflow_node_id, "patch_node");
  assert.equal(request.diagnostics_repair_context.changed_files[0].before_hash, "before_hash");
  assert.equal(request.diagnostics_repair_context.changed_files[0].after_hash, "after_hash");
  for (const field of [
    "schemaVersion",
    "sourceToolName",
    "sourceToolCallId",
    "sourceWorkflowGraphId",
    "sourceWorkflowNodeId",
    "workspaceSnapshotId",
    "restorePolicy",
    "restoreConflictPolicy",
    "diagnosticsRepairDefault",
    "operatorOverrideRequiresApproval",
    "rollbackRefs",
    "changedFiles",
  ]) {
    assert.equal(Object.hasOwn(request.diagnostics_repair_context, field), false);
  }
  assert.equal(Object.hasOwn(request.diagnostics_repair_context.changed_files[0], "beforeHash"), false);
  assert.equal(Object.hasOwn(request.diagnostics_repair_context.changed_files[0], "afterHash"), false);
  assert.equal(Object.hasOwn(request.diagnostics_repair_context.changed_files[0], "diagnosticsRecommended"), false);
  assert.deepEqual(request.input.paths, ["src/app.js"]);
});

test("diagnostics feedback repair context ignores retired source workflow request alias", () => {
  const surface = createSurface();
  const store = createStore();

  surface.maybeRunPostEditDiagnostics(store, {
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    patchToolCallId: "patch_alpha",
    workflowGraphId: "graph_alpha",
    request: {
      workflowNodeId: "patch_alias",
    },
    patchResult: {
      changedFiles: [{ path: "src/app.js" }],
      workspaceSnapshotId: "snapshot_alpha",
    },
  });

  const request = store.calls[0].request;
  assert.equal(request.diagnostics_repair_context.source_workflow_node_id, null);
  assert.equal(Object.hasOwn(request.diagnostics_repair_context, "sourceWorkflowNodeId"), false);
});

test("diagnostics feedback surface returns pending diagnostics after last injection", () => {
  const surface = createSurface();
  const store = createStore([
    {
      seq: 1,
      event_id: "event_injected",
      event_kind: "lsp.diagnostics.injected",
    },
    {
      seq: 2,
      event_id: "event_old",
      event_kind: "tool.completed",
      source: "runtime_auto",
      payload_summary: { tool_name: "lsp.diagnostics" },
    },
    {
      seq: 3,
      event_id: "event_user",
      event_kind: "tool.completed",
      source: "operator",
      payload_summary: { tool_name: "lsp.diagnostics" },
    },
    {
      seq: 4,
      event_id: "event_diagnostics",
      event_kind: "tool.completed",
      source: "runtime_auto",
      payload_summary: { tool_name: "lsp.diagnostics" },
    },
  ]);

  const feedback = surface.pendingDiagnosticsFeedbackForNextTurn(store, "thread_alpha", {
    diagnostics_mode: "blocking",
  });

  assert.equal(feedback.mode, "blocking");
  assert.equal(feedback.diagnosticCount, 2);
  assert.deepEqual(feedback.eventIds, ["event_old", "event_diagnostics"]);
  assert.equal(
    surface.pendingDiagnosticsFeedbackForNextTurn(store, "thread_alpha", { diagnostics_mode: "skip" }),
    null,
  );
});

test("diagnostics feedback surface rejects retired pending mode aliases", () => {
  const surface = createSurface();
  const store = createStore();

  assert.throws(
    () => surface.pendingDiagnosticsFeedbackForNextTurn(store, "thread_alpha", { diagnosticsMode: "blocking" }),
    (error) =>
      error.code === "pending_diagnostics_feedback_request_aliases_retired" &&
      error.details.retired_aliases.includes("diagnosticsMode") &&
      Object.hasOwn(error.details, "diagnosticsMode") === false,
  );
  assert.throws(
    () =>
      surface.pendingDiagnosticsFeedbackForNextTurn(store, "thread_alpha", {
        options: { diagnosticsMode: "skip" },
      }),
    (error) =>
      error.code === "pending_diagnostics_feedback_request_aliases_retired" &&
      error.details.retired_aliases.includes("options.diagnosticsMode") &&
      Object.hasOwn(error.details, "diagnosticsMode") === false,
  );
});
