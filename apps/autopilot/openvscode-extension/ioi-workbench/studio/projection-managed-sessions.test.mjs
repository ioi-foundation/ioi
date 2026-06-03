import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioManagedSessionProjection } = require("./projection-managed-sessions.js");

function stringValue(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function studioRecordValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function studioJsonObjectFromText(value = "") {
  try {
    const parsed = JSON.parse(String(value || ""));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function projection(overrides = {}) {
  return {
    threadId: "thread-1",
    runId: "run-1",
    turnId: "turn-1",
    computerUseSessions: [],
    runtimeCockpit: {},
    turns: [
      { role: "user", content: "open a browser" },
      { role: "assistant", content: "Working", workRecord: { id: "work-1" } },
    ],
    engineReconnectBanners: [],
    ...overrides,
  };
}

function createHarness({ state = projection(), inspection = null } = {}) {
  const bridgeRequests = [];
  const harness = createStudioManagedSessionProjection({
    buildWorkspaceActionContext: (source) => ({ source }),
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token-1",
    firstArray: (value) => (Array.isArray(value) ? value : []),
    getStudioRuntimeProjection: () => state,
    requestJson: async () => inspection,
    stringValue,
    studioJsonObjectFromText,
    studioRecordValue,
    writeBridgeRequest: async (type, payload, context) => {
      bridgeRequests.push({ type, payload, context });
    },
  });
  return { bridgeRequests, harness, state };
}

test("managed session runtime events project browser sessions without leaking raw output", () => {
  const { harness, state } = createHarness();
  const session = harness.studioManagedSessionFromRuntimeEvent({
    event_kind: "computer_use.action",
    run_id: "run-2",
    payload: {
      tool_name: "browser__open",
      computer_use_lease_id: "lease-1",
      output: JSON.stringify({
        browser_observation_receipt: {
          url: "https://example.com",
          title: "Example Domain",
        },
      }),
    },
  }, { status: "running" });

  assert.equal(session.id, "lease-1");
  assert.equal(session.kind, "sandbox_browser");
  assert.equal(session.status, "browsing");
  assert.equal(session.statusLabel, "Browsing");
  assert.equal(session.detail, "Example Domain");

  harness.upsertStudioManagedSession(session);
  harness.upsertStudioManagedSession({ ...session, status: "complete" });
  assert.equal(state.computerUseSessions.length, 1);
  assert.equal(state.computerUseSessions[0].actionCount, 2);
  assert.equal(state.runtimeCockpit.managedLiveViewportObserved, true);
});

test("managed session inspections replace cards and attach them to latest assistant work", () => {
  const { harness, state } = createHarness();
  const sessions = harness.applyStudioManagedSessionInspection({
    managed_sessions: {
      sessions: [
        {
          managed_session_id: "managed-1",
          kind: "local_browser",
          status: "waiting_for_user",
          control_state: "take_over",
          replay_ready: true,
          url: "https://example.com",
        },
      ],
    },
  });

  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].surfaceLabel, "Local browser");
  assert.equal(sessions[0].waitingForUser, true);
  assert.equal(state.runtimeCockpit.managedSessionCount, 1);
  assert.deepEqual(state.turns.at(-1).workRecord.sessionCards, sessions);
});

test("managed session reconnect exercise writes governed bridge proof request", async () => {
  const state = projection({ threadId: null, turns: [] });
  const inspection = {
    session_id: "runtime-1",
    managed_sessions: {
      replay: { replayable: true, source: "store" },
      sessions: [
        {
          managed_session_id: "managed-1",
          status: "waiting_for_user",
          control_state: "return_agent",
          replay_ready: true,
        },
      ],
    },
  };
  const { bridgeRequests, harness } = createHarness({ state, inspection });

  const result = await harness.exerciseStudioManagedSessionReconnect(null, {
    phase: "reconnect",
    threadId: "thread-2",
    expectedManagedSessionId: "managed-1",
    expectedRuntimeSessionId: "runtime-1",
    expectedControlState: "return_agent",
  });

  assert.equal(result.passed, true);
  assert.equal(result.threadId, "thread-2");
  assert.equal(state.engineReconnectBanners.length, 1);
  assert.equal(bridgeRequests.length, 1);
  assert.equal(bridgeRequests[0].type, "studio.managedSessionReconnect.exercised");
  assert.equal(bridgeRequests[0].payload.passed, true);
  assert.equal(bridgeRequests[0].payload.runtimeAuthority, "daemon-owned");
  assert.equal(bridgeRequests[0].payload.projectionOwner, "openvscode-workbench-adapter");
});

test("managed session reconnect summary fails closed on missing replay readiness", () => {
  const { harness } = createHarness();
  const summary = harness.studioManagedSessionReconnectSummary({
    inspection: { session_id: "runtime-1", managed_sessions: { replay: {} } },
    sessions: [{ id: "managed-1", controlState: "observe", waitingForUser: true }],
    expectedManagedSessionId: "managed-1",
    expectedRuntimeSessionId: "runtime-1",
    expectedControlState: "observe",
  });

  assert.equal(summary.checks.replayReady, false);
  assert.equal(summary.passed, false);
});
