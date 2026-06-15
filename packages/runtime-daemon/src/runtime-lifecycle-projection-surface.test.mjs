import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeLifecycleProjectionSurface } from "./runtime-lifecycle-projection-surface.mjs";

function lifecycleRunner(calls = []) {
  return {
    projectRuntimeLifecycle(request) {
      calls.push(request);
      return {
        source: "rust_runtime_lifecycle_projection_api",
        backend: "rust_policy",
        projection_kind: request.projection_kind,
        operation_kind: request.operation_kind,
        projection: projectionForRequest(request),
        record_count: Array.isArray(projectionForRequest(request)) ? projectionForRequest(request).length : 1,
        evidence_refs: ["runtime_lifecycle_rust_projection"],
        receipt_refs: [`receipt_runtime_lifecycle_projection_${request.projection_kind}`],
      };
    },
  };
}

function projectionForRequest(request) {
  switch (request.projection_kind) {
    case "agents":
      return request.agents;
    case "agent":
      return request.agent;
    case "threads":
      return request.threads;
    case "thread":
      return request.thread;
    case "thread_usage":
    case "run_usage":
      return request.usage;
    case "thread_turns":
      return request.turns;
    case "thread_turn":
      return request.turn;
    case "thread_events":
    case "run_events":
      return request.events;
    case "runs":
      return request.runs;
    case "agent_runs":
      return request.runs.filter((run) => run.agentId === request.agent_id);
    case "run":
    case "run_wait":
      return request.run;
    case "run_conversation":
      return request.conversation;
    case "run_replay":
      return request.replay;
    case "run_trace":
      return request.trace;
    case "run_computer_use_trace":
      return request.computer_use_trace;
    case "run_computer_use_trajectory":
      return request.computer_use_trajectory;
    case "run_scorecard":
      return request.scorecard;
    case "run_artifacts":
      return request.artifacts;
    case "run_artifact":
      return request.artifact;
    default:
      return null;
  }
}

function storeFixture() {
  const run = {
    id: "run_123",
    agentId: "agent_123",
    createdAt: "2026-06-12T01:00:00.000Z",
    conversation: [{ role: "user", content: "ship it" }],
    trace: {
      scorecard: { score: 1 },
      computerUse: {
        trace: { steps: 2 },
        trajectory: [{ x: 1, y: 2 }],
      },
    },
    artifacts: [{ id: "artifact_123", name: "trace.json" }],
  };
  return {
    defaultCwd: "/workspace/project",
    agents: new Map([
      ["agent_123", { id: "agent_123", createdAt: "2026-06-12T00:00:00.000Z" }],
    ]),
    runs: new Map([
      ["run_123", run],
      ["run_other", { id: "run_other", agentId: "agent_other", createdAt: "2026-06-12T02:00:00.000Z" }],
    ]),
    listThreads() {
      return [{ thread_id: "thread_123", agent_id: "agent_123" }];
    },
    usageForThread(threadId) {
      return { thread_id: threadId, total_tokens: 11 };
    },
    listTurns(threadId) {
      return [{ thread_id: threadId, turn_id: "turn_123" }];
    },
    eventsForThread(threadId) {
      return [{ thread_id: threadId, seq: 1, event_id: "event_thread" }];
    },
    usageForRun(runId) {
      return { run_id: runId, total_tokens: 7 };
    },
    eventsForRun(runId) {
      return [{ run_id: runId, seq: 1, event_id: "event_run" }];
    },
    replayFromCanonicalState(runId) {
      return [{ run_id: runId, seq: 1, event_id: "event_replay" }];
    },
  };
}

test("runtime lifecycle surface returns Rust-owned public lifecycle projections", () => {
  const calls = [];
  const surface = createRuntimeLifecycleProjectionSurface({
    lifecycleRunner: lifecycleRunner(calls),
    resolveRunArtifact(run, artifactRef) {
      return run.artifacts.find((artifact) => artifact.id === artifactRef) ?? null;
    },
    workspaceRoot: "/workspace/project",
  });
  const store = storeFixture();

  assert.deepEqual(surface.listAgents(store).map((agent) => agent.id), ["agent_123"]);
  assert.equal(surface.getAgent(store, "agent_123").id, "agent_123");
  assert.deepEqual(surface.listThreads(store), [{ thread_id: "thread_123", agent_id: "agent_123" }]);
  assert.equal(surface.getThread(store, "thread_123").thread_id, "thread_123");
  assert.equal(surface.getThreadUsage(store, "thread_123").total_tokens, 11);
  assert.equal(surface.listThreadTurns(store, "thread_123")[0].turn_id, "turn_123");
  assert.equal(surface.getThreadTurn(store, "thread_123", "turn_123").turn_id, "turn_123");
  assert.equal(surface.listThreadEvents(store, "thread_123")[0].event_id, "event_thread");
  assert.deepEqual(surface.listRuns(store).map((run) => run.id), ["run_123", "run_other"]);
  assert.deepEqual(surface.listRuns(store, "agent_123").map((run) => run.id), ["run_123"]);
  assert.equal(surface.getRun(store, "run_123").id, "run_123");
  assert.equal(surface.waitRun(store, "run_123").id, "run_123");
  assert.equal(surface.getRunConversation(store, "run_123")[0].content, "ship it");
  assert.equal(surface.getRunUsage(store, "run_123").total_tokens, 7);
  assert.equal(surface.listRunEvents(store, "run_123")[0].event_id, "event_run");
  assert.equal(surface.replayRun(store, "run_123")[0].event_id, "event_replay");
  assert.equal(surface.getRunTrace(store, "run_123").scorecard.score, 1);
  assert.equal(surface.getRunComputerUseTrace(store, "run_123").steps, 2);
  assert.equal(surface.getRunComputerUseTrajectory(store, "run_123")[0].x, 1);
  assert.equal(surface.getRunScorecard(store, "run_123").score, 1);
  assert.equal(surface.listRunArtifacts(store, "run_123")[0].id, "artifact_123");
  assert.equal(surface.getRunArtifact(store, "run_123", "artifact_123").name, "trace.json");

  assert.ok(calls.every((call) => call.source === "runtime.lifecycle_projection_surface"));
  assert.ok(calls.every((call) => call.workspace_root === "/workspace/project"));
  assert.ok(calls.every((call) => call.evidence_refs.includes("runtime_lifecycle_rust_projection")));
  assert.deepEqual(calls.map((call) => call.projection_kind), [
    "agents",
    "agent",
    "threads",
    "thread",
    "thread_usage",
    "thread_turns",
    "thread_turn",
    "thread_events",
    "runs",
    "agent_runs",
    "run",
    "run_wait",
    "run_conversation",
    "run_usage",
    "run_events",
    "run_replay",
    "run_trace",
    "run_computer_use_trace",
    "run_computer_use_trajectory",
    "run_scorecard",
    "run_artifacts",
    "run_artifact",
  ]);
  const turnCall = calls.find((call) => call.projection_kind === "thread_turn");
  assert.equal(turnCall.turn_id, "turn_123");
  assert.equal(Object.hasOwn(turnCall, "turnId"), false);
  assert.equal(calls.at(-1).artifact_ref, "artifact_123");
  assert.equal(Object.hasOwn(calls.at(-1), "artifactRef"), false);
});

test("runtime lifecycle surface fails closed when Rust projection is missing", () => {
  const surface = createRuntimeLifecycleProjectionSurface({
    workspaceRoot: "/workspace/project",
  });

  assert.throws(
    () => surface.listAgents(storeFixture()),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_lifecycle_projection_rust_projection_missing");
      assert.equal(error.details.rust_core_boundary, "runtime.lifecycle_projection");
      assert.equal(error.details.projection_kind, "agents");
      assert.equal(error.details.workspace_root, "/workspace/project");
      assert.equal(Object.hasOwn(error.details, "workspaceRoot"), false);
      return true;
    },
  );
});

test("runtime lifecycle surface rejects Rust projection mismatches", () => {
  const surface = createRuntimeLifecycleProjectionSurface({
    lifecycleRunner: {
      projectRuntimeLifecycle() {
        return {
          source: "rust_runtime_lifecycle_projection_api",
          projection_kind: "runs",
          projection: [],
        };
      },
    },
    workspaceRoot: "/workspace/project",
  });

  assert.throws(
    () => surface.listAgents(storeFixture()),
    (error) => {
      assert.equal(error.status, 502);
      assert.equal(error.code, "runtime_lifecycle_projection_rust_projection_invalid");
      assert.equal(error.details.expected_projection_kind, "agents");
      assert.equal(error.details.actual_projection_kind, "runs");
      return true;
    },
  );
});
