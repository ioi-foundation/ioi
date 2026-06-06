import assert from "node:assert/strict";
import test from "node:test";

import {
  emptyManagedSessionSnapshot,
  managedSessionControlAction,
  normalizeManagedSessionInspection,
} from "./managed-session-inspection.mjs";

test("managed session control action normalizes operator-facing states", () => {
  assert.equal(managedSessionControlAction("observe"), "observe_session");
  assert.equal(managedSessionControlAction("take over"), "take_over_session");
  assert.equal(managedSessionControlAction("return-agent"), "return_agent");
});

test("managed session control action rejects unsupported states", () => {
  assert.throws(
    () => managedSessionControlAction("steal_focus"),
    /Unsupported managed session control action/,
  );
});

test("managed session inspection normalizes bridge snapshots", () => {
  const normalized = normalizeManagedSessionInspection({
    bridgeResult: {
      bridge_id: "bridge_test",
      managed_sessions: {
        sessions: [{ id: "session_browser", kind: "sandbox_browser" }],
      },
    },
    agent: {
      cwd: "/workspace",
      runtimeBridgeId: "bridge_agent",
      status: "active",
    },
    threadId: "thread_test",
    sessionId: "runtime_session_test",
  });

  assert.equal(normalized.schema_version, "ioi.runtime.managed-session.daemon.v1");
  assert.equal(normalized.bridge_id, "bridge_test");
  assert.equal(normalized.thread_id, "thread_test");
  assert.equal(normalized.session_id, "runtime_session_test");
  for (const field of ["bridgeId", "threadId", "sessionId", "workspaceRoot", "managedSessions"]) {
    assert.equal(Object.hasOwn(normalized, field), false, `retired managed session alias ${field}`);
  }
  assert.deepEqual(normalized.managed_sessions.sessions, [
    { id: "session_browser", kind: "sandbox_browser" },
  ]);
});

test("managed session inspection ignores retired bridge aliases", () => {
  const normalized = normalizeManagedSessionInspection({
    bridgeResult: {
      bridgeId: "bridge_retired",
      threadId: "thread_retired",
      sessionId: "session_retired",
      workspaceRoot: "/retired",
      managedSessions: {
        sessions: [{ id: "session_retired", kind: "sandbox_browser" }],
      },
    },
    agent: {
      cwd: "/workspace",
      runtimeBridgeId: "bridge_agent_retired",
      status: "active",
    },
    threadId: "thread_test",
    sessionId: "runtime_session_test",
  });

  assert.equal(normalized.bridge_id, null);
  assert.equal(normalized.thread_id, "thread_test");
  assert.equal(normalized.session_id, "runtime_session_test");
  assert.equal(normalized.workspace_root, "/workspace");
  assert.deepEqual(normalized.managed_sessions.sessions, []);
});

test("empty managed session snapshot is replay-safe and product-lane empty", () => {
  const snapshot = emptyManagedSessionSnapshot("thread_empty");
  assert.equal(snapshot.schema_version, "ioi.runtime.managed-session.v1");
  assert.equal(snapshot.thread_id, "thread_empty");
  assert.deepEqual(snapshot.sessions, []);
  assert.deepEqual(snapshot.product_lane, []);
  assert.equal(Object.hasOwn(snapshot, "threadId"), false);
  assert.equal(Object.hasOwn(snapshot, "productLane"), false);
  assert.equal(snapshot.replay.available, false);
});
