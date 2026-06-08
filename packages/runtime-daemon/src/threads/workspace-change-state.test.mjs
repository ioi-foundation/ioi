import assert from "node:assert/strict";
import { test } from "node:test";

import {
  controlWorkspaceChangeForThread,
  inspectWorkspaceChangeReviewsForThread,
} from "./workspace-change-state.mjs";

class BridgeUnavailableError extends Error {
  constructor(details = {}) {
    super("bridge unavailable");
    this.details = details;
  }
}

function deps() {
  return {
    RuntimeApiBridgeUnavailableError: BridgeUnavailableError,
    doctorHash: (value) => `hash-${String(value).length}`.padEnd(24, "0"),
    isRuntimeBackedAgent: (agent) => agent.runtimeProfile === "runtime_service",
    optionalString: (value) => {
      if (value === undefined || value === null) return null;
      const text = String(value).trim();
      return text ? text : null;
    },
    runtimeSessionIdForAgent: (agent) => agent.runtimeSessionId ?? `session_${agent.id}`,
    safeId: (value) => String(value ?? "").replace(/[^a-zA-Z0-9._-]+/g, "_"),
  };
}

function fakeStore({ agent, runtimeBridge = {} }) {
  const calls = [];
  return {
    calls,
    runtimeBridge,
    agentForThread(threadId) {
      calls.push({ operation: "agent_for_thread", threadId });
      return agent;
    },
    assertRuntimeBridgeAvailable(input) {
      calls.push({ operation: "assert_bridge", input });
    },
    runtimeBridgeUnavailable(input) {
      const error = new Error("runtime bridge unavailable");
      error.input = input;
      return error;
    },
  };
}

test("workspace change inspection returns empty fallback for fixture threads", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_fixture",
      cwd: "/workspace",
      runtimeProfile: "fixture",
    },
  });

  const inspected = await inspectWorkspaceChangeReviewsForThread(store, "thread_fixture", {}, deps());

  assert.equal(inspected.status, "not_runtime_backed");
  assert.equal(inspected.session_id, "session_agent_fixture");
  assert.deepEqual(inspected.workspace_change_reviews, []);
  assert.deepEqual(inspected.hunk_previews, []);
  assert.equal(Object.hasOwn(inspected, "runtimeProfile"), false);
  assert.equal(Object.hasOwn(inspected, "threadId"), false);
});

test("workspace change inspection calls runtime bridge and normalizes hunk previews", async () => {
  const bridgeCalls = [];
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    runtimeBridge: {
      async inspectThread(input) {
        bridgeCalls.push(input);
        return {
          workspace_change_reviews: [
            {
              change_id: "workspace_change:file:1",
              path: "src/app.js",
              accept_available: true,
            },
          ],
          latest_trajectory: {
            workspace_changes: [
              {
                change_id: "workspace_change:file:1",
                path: "src/app.js",
                hunks: [{ hunk_index: 0, search_text: "before", replace_text: "after" }],
              },
            ],
          },
        };
      },
    },
  });

  const inspected = await inspectWorkspaceChangeReviewsForThread(store, "thread_runtime", {}, deps());

  assert.equal(bridgeCalls[0].projection, "workspace_change_reviews");
  assert.equal(bridgeCalls[0].session_id, "session_runtime");
  assert.equal(bridgeCalls[0].thread_id, "thread_runtime");
  assert.equal(bridgeCalls[0].workspace_root, "/workspace");
  assert.equal(typeof bridgeCalls[0].requested_at, "string");
  assert.equal(Object.hasOwn(bridgeCalls[0], "sessionId"), false);
  assert.equal(Object.hasOwn(bridgeCalls[0], "threadId"), false);
  assert.equal(Object.hasOwn(bridgeCalls[0], "workspaceRoot"), false);
  assert.equal(Object.hasOwn(bridgeCalls[0], "requestedAt"), false);
  assert.equal(inspected.status, "ready");
  assert.equal(inspected.hunk_previews[0].change_id, "workspace_change:file:1");
  assert.equal(Object.hasOwn(inspected.hunk_previews[0], "changeId"), false);
});

test("workspace change inspection rejects retired bridge request aliases", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
  });

  await assert.rejects(
    inspectWorkspaceChangeReviewsForThread(store, "thread_runtime", {
      sessionId: "session_retired",
      threadId: "thread_retired",
      workspaceRoot: "/retired",
      requestedAt: "2026-06-03T00:00:00.000Z",
    }, deps()),
    (error) =>
      error.code === "workspace_change_inspection_request_aliases_retired" &&
      error.details.thread_id === "thread_runtime" &&
      error.details.retired_aliases.includes("sessionId") &&
      error.details.retired_aliases.includes("threadId") &&
      error.details.retired_aliases.includes("workspaceRoot") &&
      error.details.retired_aliases.includes("requestedAt") &&
      Object.hasOwn(error.details, "threadId") === false,
  );
});

function assertWorkspaceChangeControlRustCoreRequired(error) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_workspace_change_control_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.workspace_change_control");
  assert.equal(error.details.operation, "workspace_change_control");
  assert.equal(error.details.operation_kind, "workspace_change_control");
  assert.equal(error.details.thread_id, "thread_runtime");
  assert.deepEqual(error.details.evidence_refs, [
    "workspace_change_control_js_facade_retired",
    "workspace_change_control_bridge_dispatch_retired",
    "workspace_change_control_receipt_synthesis_js_retired",
    "rust_daemon_core_workspace_change_control_required",
    "agentgres_workspace_change_truth_required",
  ]);
  for (const key of ["threadId", "operationKind", "rustCoreBoundary", "evidenceRefs"]) {
    assert.equal(Object.hasOwn(error.details, key), false);
  }
  return true;
}

test("workspace change control facade fails closed before JS bridge dispatch or result envelope", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    runtimeBridge: {
      async controlThread(input) {
        assert.fail(`workspace change JS control bridge dispatch must not run: ${JSON.stringify(input)}`);
      },
    },
  });

  await assert.rejects(
    controlWorkspaceChangeForThread(store, "thread_runtime", {
      tool_id: "workspace_change__reject",
      toolId: "workspace_change__accept",
      input: {
        change_id: "workspace_change:file:0",
        changeId: "workspace_change:file:1",
        workspace_change_id: "workspace_change:file:2",
      },
      created_at: "2026-06-03T00:00:00.000Z",
      requestHash: "retired_hash",
    }, deps()),
    assertWorkspaceChangeControlRustCoreRequired,
  );
  assert.deepEqual(store.calls, []);
});
