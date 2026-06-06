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
  assert.equal(inspected.status, "ready");
  assert.equal(inspected.hunk_previews[0].change_id, "workspace_change:file:1");
  assert.equal(Object.hasOwn(inspected.hunk_previews[0], "changeId"), false);
});

test("workspace change control maps tool ids to bridge actions and result envelope", async () => {
  const bridgeCalls = [];
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
    runtimeBridge: {
      async controlThread(input) {
        bridgeCalls.push(input);
        return {
          action: input.action,
          status: "completed",
          inspection: {
            workspace_change_reviews: [
              {
                change_id: input.changeId,
                path: "src/app.js",
                rollback_available: true,
              },
            ],
          },
        };
      },
    },
  });

  const controlled = await controlWorkspaceChangeForThread(store, "thread_runtime", {
    tool_id: "workspace_change__reject",
    input: {
      change_id: "workspace_change:file:1",
      reason: "operator rejected hunk",
    },
    created_at: "2026-06-03T00:00:00.000Z",
  }, deps());

  assert.equal(bridgeCalls[0].action, "workspace_change_reject");
  assert.equal(bridgeCalls[0].sessionId, "session_runtime");
  assert.equal(bridgeCalls[0].changeId, "workspace_change:file:1");
  assert.equal(controlled.schema_version, "ioi.runtime.workspace-change-control.daemon.v1");
  assert.equal(Object.hasOwn(controlled, "schemaVersion"), false);
  assert.equal(Object.hasOwn(controlled, "changeId"), false);
  assert.equal(Object.hasOwn(controlled, "receiptRefs"), false);
  assert.equal(controlled.status, "rejected");
  assert.equal(controlled.result.change_id, "workspace_change:file:1");
  assert.equal(Object.hasOwn(controlled.result, "changeId"), false);
  assert.match(controlled.receipt_refs[0], /^receipt_workspace_change_workspace_change_reject_/);
});

test("workspace change control requires change id", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
  });

  await assert.rejects(
    controlWorkspaceChangeForThread(store, "thread_runtime", { tool_id: "workspace_change__accept" }, deps()),
    /Workspace change control requires changeId/,
  );
});

test("workspace change control rejects retired request aliases", async () => {
  const store = fakeStore({
    agent: {
      id: "agent_runtime",
      cwd: "/workspace",
      runtimeProfile: "runtime_service",
      runtimeSessionId: "session_runtime",
    },
  });

  await assert.rejects(
    controlWorkspaceChangeForThread(store, "thread_runtime", {
      toolId: "workspace_change__accept",
      input: { changeId: "workspace_change:file:1" },
    }, deps()),
    (error) =>
      error.code === "workspace_change_control_request_aliases_retired" &&
      error.details.thread_id === "thread_runtime" &&
      error.details.retired_aliases.includes("toolId") &&
      error.details.retired_aliases.includes("changeId") &&
      Object.hasOwn(error.details, "threadId") === false,
  );
});
