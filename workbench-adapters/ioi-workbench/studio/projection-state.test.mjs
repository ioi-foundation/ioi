import { createRequire } from "node:module";
import test from "node:test";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const {
  createInitialStudioRuntimeProjection,
  createStudioProjectionLifecycle,
} = require("./projection-state.js");

test("initial Studio projection keeps daemon-owned product defaults", () => {
  const projection = createInitialStudioRuntimeProjection({
    approvalId: "approval.inline",
    executionMode: "agent",
    permissionMode: "suggest",
    policyLeaseId: "approval.policy",
    runtimeProfile: "runtime_service",
  });

  assert.equal(projection.schemaVersion, "ioi.agent-studio.operational-chat.projection.v1");
  assert.equal(projection.status, "idle");
  assert.equal(projection.executionMode, "agent");
  assert.equal(projection.runtimeProfile, "runtime_service");
  assert.equal(projection.modelRoute, "route.local-first");
  assert.equal(projection.approvalId, "approval.inline");
  assert.equal(projection.hunkApprovalId, "approval.inline");
  assert.equal(projection.policyLeaseId, "approval.policy");
  assert.equal(projection.runtimeCockpit.projectionOnlyRuntimeRejected, true);
  assert.equal(projection.runtimeUx.tracingSeparationAchieved, true);
  assert.match(projection.turns[0].content, /daemon-owned sessions/);
  assert.equal(projection.timeline[0].label, "Studio surface opened");
  assert.equal(projection.terminal[0].label, "No terminal job running");
});

test("projection lifecycle resets daemon-owned thread fields without clearing user preferences", () => {
  let resetCount = 0;
  const projection = createInitialStudioRuntimeProjection({
    approvalId: "approval.inline",
    executionMode: "agent",
    permissionMode: "suggest",
    policyLeaseId: "approval.policy",
    runtimeProfile: "runtime_service",
  });
  Object.assign(projection, {
    threadId: "thread.1",
    sessionId: "session.1",
    turnId: "turn.1",
    runId: "run.1",
    lastModelStream: { streamId: "stream.1" },
    lastIntentFrame: { route: "runtime" },
    modelRoute: "route.custom",
    selectedModel: "model.custom",
    pendingWorklog: [{ label: "Tool running" }],
    runtimeEventSeenIds: ["event.1"],
  });

  const lifecycle = createStudioProjectionLifecycle({
    getProjection: () => projection,
    resetAnswerStream: () => {
      resetCount += 1;
    },
  });

  const resetProjection = lifecycle.resetStudioDaemonThreadProjection();

  assert.equal(resetProjection.threadId, null);
  assert.equal(resetProjection.sessionId, null);
  assert.equal(resetProjection.turnId, null);
  assert.equal(resetProjection.runId, null);
  assert.equal(resetProjection.lastModelStream, null);
  assert.equal(resetProjection.lastIntentFrame, null);
  assert.deepEqual(resetProjection.pendingWorklog, []);
  assert.deepEqual(resetProjection.runtimeEventSeenIds, []);
  assert.equal(resetProjection.modelRoute, "route.custom");
  assert.equal(resetProjection.selectedModel, "model.custom");
  assert.equal(resetCount, 1);
});

test("projection lifecycle starts a new session while preserving model and mode choices", () => {
  let projection = createInitialStudioRuntimeProjection({
    approvalId: "approval.inline",
    executionMode: "ask",
    permissionMode: "full_access",
    policyLeaseId: "approval.policy",
    runtimeProfile: "chat_only",
  });
  projection.executionMode = "ask";
  projection.modelRoute = "route.fast";
  projection.selectedModel = "qwen.local";
  projection.reasoningEffort = "medium";
  projection.approvalMode = "auto_review";
  projection.timeline = [{ label: "Old session", status: "completed" }];

  const lifecycle = createStudioProjectionLifecycle({
    agentRuntimeProfile: "runtime_service",
    createInitialProjection: () => createInitialStudioRuntimeProjection({
      approvalId: "approval.inline",
      executionMode: "agent",
      permissionMode: "suggest",
      policyLeaseId: "approval.policy",
      runtimeProfile: "runtime_service",
    }),
    directModelRuntimeProfile: "chat_only",
    getProjection: () => projection,
    normalizeExecutionMode: (value) => (value === "ask" ? "ask" : "agent"),
    normalizePermissionMode: (value) => value || "suggest",
    normalizeReasoningEffort: (value, fallback) => value || fallback,
    setProjection: (next) => {
      projection = next;
    },
    studioModeAgent: "agent",
  });

  const next = lifecycle.startNewStudioSession("Operator requested reset.");

  assert.equal(next.executionMode, "ask");
  assert.equal(next.runtimeProfile, "chat_only");
  assert.equal(next.modelRoute, "route.fast");
  assert.equal(next.selectedModel, "qwen.local");
  assert.equal(next.reasoningEffort, "medium");
  assert.equal(next.approvalMode, "auto_review");
  assert.deepEqual(next.timeline, [
    {
      label: "New Studio session",
      detail: "Operator requested reset.",
      status: "ready",
    },
  ]);
  assert.equal(next.threadId, null);
});

test("projection lifecycle projects work cursor and documented summary through injected helpers", () => {
  let projection = createInitialStudioRuntimeProjection({
    approvalId: "approval.inline",
    executionMode: "agent",
    permissionMode: "suggest",
    policyLeaseId: "approval.policy",
    runtimeProfile: "runtime_service",
  });
  projection.status = "completed";
  projection.actionCards = [{ id: "action.1" }];
  projection.policyLeases = [{ id: "lease.1" }, { id: "lease.2" }];
  projection.commandOutputs = [{ id: "cmd.1" }];
  projection.diagnosticGates = [{ id: "diag.1" }];
  projection.diffHunks = [{ id: "hunk.1" }];
  projection.browserCards = [{ id: "browser.1" }];
  projection.workerCards = [{ id: "worker.1" }];
  projection.computerUseSessions = [{ id: "session.1" }];
  projection.conversationArtifacts = [{ id: "artifact.1" }];
  projection.pendingWorklog = [{ id: "pending.1" }];
  projection.receipts = [{ id: "receipt.1" }];

  const lifecycle = createStudioProjectionLifecycle({
    documentedWorkRecord: (state, cursor) => ({ status: state.status, cursor }),
    documentedWorkSummary: (record, status) => `${status}:${record.cursor.commandOutputs}`,
    getProjection: () => projection,
    now: () => 1234,
  });

  const cursor = lifecycle.studioWorkCursor();

  assert.deepEqual(cursor, {
    startedAtMs: 1234,
    actionCards: 1,
    policyLeases: 2,
    commandOutputs: 1,
    diagnosticGates: 1,
    diffHunks: 1,
    browserCards: 1,
    workerCards: 1,
    computerUseSessions: 1,
    conversationArtifacts: 1,
    pendingWorklog: 1,
    receipts: 1,
  });
  const record = lifecycle.studioDocumentedWorkRecord(cursor);
  assert.equal(record.status, "completed");
  assert.equal(lifecycle.studioDocumentedWorkSummary(record), "completed:1");
});
