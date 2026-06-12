import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeDiagnosticsFeedbackSurface } from "./runtime-diagnostics-feedback-surface.mjs";

function createSurface({ diagnosticsFeedbackPlanner = null } = {}) {
  return createRuntimeDiagnosticsFeedbackSurface({
    compactDiagnosticsFeedback({ threadId, mode, diagnosticEvents }) {
      return {
        threadId,
        mode,
        diagnosticCount: diagnosticEvents.length,
        eventIds: diagnosticEvents.map((event) => event.event_id),
      };
    },
    diagnosticsFeedbackPlanner,
    normalizeDiagnosticsMode(value) {
      if (value === "off" || value === "skip") return "skip";
      if (value === "fail" || value === "blocking") return "blocking";
      return "advisory";
    },
  });
}

function createPlanner(planForRequest) {
  const calls = [];
  return {
    calls,
    planner: {
      planPostEditDiagnosticsFeedback(request) {
        calls.push(request);
        return planForRequest(request);
      },
    },
  };
}

function createStore(events = []) {
  const calls = [];
  return {
    calls,
    codingToolInvocationSurface: {
      invokeThreadTool(surfaceStore, threadId, toolId, request) {
        calls.push({ surfaceStore, threadId, toolId, request });
        return { ok: true, threadId, toolId, request };
      },
    },
    invokeThreadTool() {
      throw new Error("retired invokeThreadTool wrapper must not be used for diagnostics feedback");
    },
    invokeThreadToolAsync() {
      throw new Error("retired invokeThreadToolAsync wrapper must not be used for diagnostics feedback");
    },
    runtimeEventStream() {
      return { events };
    },
  };
}

test("diagnostics feedback surface skips post-edit diagnostics when disabled or pathless", () => {
  const { planner, calls } = createPlanner(() => ({
    source: "rust_post_edit_diagnostics_feedback_plan_command",
    status: "skipped",
    skipped: true,
    record: { status: "skipped", skip_reason: "rust_owned_skip" },
  }));
  const surface = createSurface({ diagnosticsFeedbackPlanner: planner });
  const store = createStore();

  assert.equal(
    surface.maybeRunPostEditDiagnostics(store, {
      threadId: "thread_alpha",
      patchToolCallId: "patch_alpha",
      request: { diagnostics_mode: "skip" },
      patchResult: { changed_files: [{ path: "src/app.js" }] },
    }),
    null,
  );
  assert.equal(
    surface.maybeRunPostEditDiagnostics(store, {
      threadId: "thread_alpha",
      patchToolCallId: "patch_alpha",
      patchResult: { changed_files: [{ diagnostics_recommended: true }] },
    }),
    null,
  );
  assert.equal(calls.length, 2);
  assert.equal(calls[0].thread_id, "thread_alpha");
  assert.equal(calls[0].patch_tool_call_id, "patch_alpha");
  assert.deepEqual(calls[0].request, { diagnostics_mode: "skip" });
  assert.deepEqual(calls[1].patch_result, { changed_files: [{ diagnostics_recommended: true }] });
  assert.equal(store.calls.length, 0);
});

test("diagnostics feedback surface invokes lsp diagnostics with Rust-authored repair context", () => {
  const { planner, calls } = createPlanner((planRequest) => ({
    source: "rust_post_edit_diagnostics_feedback_plan_command",
    planned: true,
    status: "planned",
    tool_id: "lsp.diagnostics",
    record: {
      status: "planned",
      operation_kind: "runtime.post_edit_diagnostics_feedback",
    },
    request: {
      source: "runtime_auto",
      turn_id: planRequest.turn_id,
      workflow_graph_id: planRequest.workflow_graph_id,
      workflow_node_id: "runtime.coding-tool.lsp-diagnostics.auto",
      tool_call_id: "coding_tool_lsp_diagnostics_auto_rust",
      rollback_refs: ["snapshot_alpha", "rollback_alpha"],
      diagnostics_repair_context: {
        schema_version: "ioi.runtime.diagnostics-rollback-repair-context.v1",
        object: "ioi.runtime_diagnostics_rollback_repair_context",
        source_tool_name: "file.apply_patch",
        source_tool_call_id: planRequest.patch_tool_call_id,
        source_workflow_graph_id: planRequest.workflow_graph_id,
        source_workflow_node_id: "patch_node",
        workspace_snapshot_id: "snapshot_alpha",
        restore_policy: "snapshot_restore",
        restore_conflict_policy: "clean_preview_only",
        diagnostics_repair_default: "repair_retry",
        operator_override_requires_approval: true,
        rollback_refs: ["snapshot_alpha", "rollback_alpha"],
        restore: { preview_supported: true },
        changed_files: [
          {
            path: "src/app.js",
            before_hash: "before_hash",
            after_hash: "after_hash",
            diagnostics_recommended: true,
          },
        ],
      },
      input: {
        commandId: "tsc",
        paths: ["src/app.js"],
        cwd: "/workspace",
        timeoutMs: 1000,
        maxOutputBytes: 4096,
      },
    },
  }));
  const surface = createSurface({ diagnosticsFeedbackPlanner: planner });
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
      changed_files: [
        {
          path: "src/app.js",
          before_hash: "before_hash",
          after_hash: "after_hash",
        },
        {
          path: "README.md",
          diagnostics_recommended: false,
        },
      ],
      workspace_snapshot_id: "snapshot_alpha",
      workspace_snapshot: {
        restore: { preview_supported: true },
      },
      rollback_refs: ["rollback_alpha"],
    },
  });

  assert.equal(result.toolId, "lsp.diagnostics");
  assert.equal(store.calls.length, 1);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].thread_id, "thread_alpha");
  assert.equal(calls[0].turn_id, "turn_alpha");
  assert.equal(calls[0].patch_tool_call_id, "patch_alpha");
  assert.equal(calls[0].workflow_graph_id, "graph_alpha");
  assert.equal(calls[0].request.workflow_node_id, "patch_node");
  assert.deepEqual(calls[0].patch_result.changed_files.map((entry) => entry.path), [
    "src/app.js",
    "README.md",
  ]);
  assert.equal(store.calls[0].surfaceStore, store);
  const request = store.calls[0].request;
  assert.equal(request.workflow_node_id, "runtime.coding-tool.lsp-diagnostics.auto");
  assert.deepEqual(request.rollback_refs, ["snapshot_alpha", "rollback_alpha"]);
  assert.equal(request.diagnostics_repair_context.workspace_snapshot_id, "snapshot_alpha");
  assert.equal(request.diagnostics_repair_context.source_workflow_node_id, "patch_node");
  assert.equal(request.diagnostics_repair_context.restore_policy, "snapshot_restore");
  assert.equal(request.diagnostics_repair_context.restore_conflict_policy, "clean_preview_only");
  assert.equal(request.diagnostics_repair_context.diagnostics_repair_default, "repair_retry");
  assert.equal(request.diagnostics_repair_context.operator_override_requires_approval, true);
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
  const { planner } = createPlanner(() => ({
    planned: true,
    tool_id: "lsp.diagnostics",
    request: {
      workflow_node_id: "runtime.coding-tool.lsp-diagnostics.auto",
      diagnostics_repair_context: {
        source_workflow_node_id: null,
      },
      input: { paths: ["src/app.js"] },
    },
  }));
  const surface = createSurface({ diagnosticsFeedbackPlanner: planner });
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
      changed_files: [{ path: "src/app.js" }],
      workspace_snapshot_id: "snapshot_alpha",
    },
  });

  const request = store.calls[0].request;
  assert.equal(request.diagnostics_repair_context.source_workflow_node_id, null);
  assert.equal(Object.hasOwn(request.diagnostics_repair_context, "sourceWorkflowNodeId"), false);
});

test("diagnostics feedback repair context ignores retired snapshot and rollback aliases", () => {
  const { planner } = createPlanner(() => ({
    planned: true,
    tool_id: "lsp.diagnostics",
    request: {
      rollback_refs: ["snapshot_canonical", "rollback_canonical"],
      diagnostics_repair_context: {
        workspace_snapshot_id: "snapshot_canonical",
        rollback_refs: ["snapshot_canonical", "rollback_canonical"],
      },
      input: { paths: ["src/app.js"] },
    },
  }));
  const surface = createSurface({ diagnosticsFeedbackPlanner: planner });
  const store = createStore();

  surface.maybeRunPostEditDiagnostics(store, {
    threadId: "thread_alpha",
    turnId: "turn_alpha",
    patchToolCallId: "patch_alpha",
    workflowGraphId: "graph_alpha",
    request: {
      workflow_node_id: "patch_node",
    },
    patchResult: {
      changed_files: [{ path: "src/app.js" }],
      workspace_snapshot_id: "snapshot_canonical",
      workspaceSnapshotId: "snapshot_retired",
      workspace_snapshot: {
        snapshot_id: "snapshot_nested_canonical",
      },
      workspaceSnapshot: {
        snapshotId: "snapshot_nested_retired",
      },
      rollback_refs: ["rollback_canonical"],
      rollbackRefs: ["rollback_retired"],
    },
  });

  const request = store.calls[0].request;
  assert.equal(request.diagnostics_repair_context.workspace_snapshot_id, "snapshot_canonical");
  assert.deepEqual(request.rollback_refs, ["snapshot_canonical", "rollback_canonical"]);
  assert.deepEqual(request.diagnostics_repair_context.rollback_refs, [
    "snapshot_canonical",
    "rollback_canonical",
  ]);
  assert.equal(request.rollback_refs.includes("snapshot_retired"), false);
  assert.equal(request.rollback_refs.includes("snapshot_nested_retired"), false);
  assert.equal(request.rollback_refs.includes("rollback_retired"), false);
});

test("diagnostics feedback surface ignores retired patch result aliases", () => {
  const { planner, calls } = createPlanner(() => ({
    skipped: true,
    record: { status: "skipped", skip_reason: "no_changed_files" },
  }));
  const surface = createSurface({ diagnosticsFeedbackPlanner: planner });
  const store = createStore();

  assert.equal(
    surface.maybeRunPostEditDiagnostics(store, {
      threadId: "thread_alpha",
      patchToolCallId: "patch_alpha",
      patchResult: {
        changedFiles: [
          {
            path: "src/app.js",
            beforeHash: "before_retired",
            afterHash: "after_retired",
            diagnosticsRecommended: true,
          },
        ],
      },
    }),
    null,
  );
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].patch_result, {
    changedFiles: [
      {
        path: "src/app.js",
        beforeHash: "before_retired",
        afterHash: "after_retired",
        diagnosticsRecommended: true,
      },
    ],
  });
  assert.equal(store.calls.length, 0);
});

test("diagnostics feedback surface fails closed without Rust post-edit planner", () => {
  const surface = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.maybeRunPostEditDiagnostics(store, {
        threadId: "thread_alpha",
        patchToolCallId: "patch_alpha",
        patchResult: { changed_files: [{ path: "src/app.js" }] },
      }),
    (error) =>
      error.code === "runtime_diagnostics_feedback_rust_core_required" &&
      error.details.rust_core_boundary === "runtime.post_edit_diagnostics_feedback" &&
      error.details.evidence_refs.includes(
        "post_edit_diagnostics_feedback_js_planner_retired",
      ),
  );
  assert.equal(store.calls.length, 0);
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
