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
  switch (request.projection_kind) {
    case "agents":
      return [{ id: "agent_123", createdAt: "2026-06-12T00:00:00.000Z" }];
    case "agent":
      return { id: request.agent_id };
    case "threads":
      return [{ thread_id: "thread_123", agent_id: "agent_123" }];
    case "thread":
      return { thread_id: request.thread_id, agent_id: "agent_123" };
    case "thread_usage":
      return { thread_id: request.thread_id, total_tokens: 11 };
    case "run_usage":
      return { run_id: request.run_id, total_tokens: 7 };
    case "thread_turns":
      return [{ thread_id: request.thread_id, turn_id: "turn_123" }];
    case "thread_turn":
      return { thread_id: request.thread_id, turn_id: request.turn_id };
    case "thread_events":
      return [{ thread_id: request.thread_id, seq: 1, event_id: "event_thread" }];
    case "run_events":
      return [{ run_id: request.run_id, seq: 1, event_id: "event_run" }];
    case "runs":
      return [run, { id: "run_other", agentId: "agent_other", createdAt: "2026-06-12T02:00:00.000Z" }];
    case "agent_runs":
      return request.agent_id === "agent_123" ? [run] : [];
    case "run":
    case "run_wait":
      return run;
    case "run_conversation":
      return run.conversation;
    case "run_replay":
      return [{ run_id: request.run_id, seq: 1, event_id: "event_run" }];
    case "run_trace":
      return run.trace;
    case "run_computer_use_trace":
      return run.trace.computerUse.trace;
    case "run_computer_use_trajectory":
      return run.trace.computerUse.trajectory;
    case "run_scorecard":
      return run.trace.scorecard;
    case "run_artifacts":
      return run.artifacts;
    case "run_artifact":
      return run.artifacts.find((artifact) => artifact.id === request.artifact_ref) ?? null;
    case "usage_list":
      return {
        schema_version: "ioi.runtime.usage-telemetry.v1",
        object: "ioi.runtime_usage_list",
        group_by: request.group_by ?? "run",
        usage: [{ run_id: "run_123", agent_id: request.agent_id ?? null }],
      };
    case "authority_evidence_summary":
      return {
        schema_version: "ioi.authority-evidence-summary-list.v1",
        object: "ioi.authority_evidence_summary_list",
        filters: {
          thread_id: request.thread_id ?? null,
          run_id: request.run_id ?? null,
          capability_ref: request.capability_ref ?? null,
          route_id: request.route_id ?? null,
        },
        items: [{ source_run_id: request.run_id ?? null }],
      };
    default:
      return null;
  }
}

function storeFixture() {
  const retired = () => {
    throw new Error("runtime lifecycle projection must not read JS cache truth");
  };
  return {
    defaultCwd: "/workspace/project",
    stateDir: "/runtime-state",
    get agents() { return retired(); },
    get runs() { return retired(); },
    listThreads: retired,
    usageForThread: retired,
    listTurns: retired,
    eventsForThread: retired,
    usageForRun: retired,
    eventsForRun: retired,
  };
}

test("runtime lifecycle surface returns Rust-owned public lifecycle projections", () => {
  const calls = [];
  const surface = createRuntimeLifecycleProjectionSurface({
    lifecycleRunner: lifecycleRunner(calls),
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
  assert.equal(surface.replayRun(store, "run_123")[0].event_id, "event_run");
  assert.equal(surface.getRunTrace(store, "run_123").scorecard.score, 1);
  assert.equal(surface.getRunComputerUseTrace(store, "run_123").steps, 2);
  assert.equal(surface.getRunComputerUseTrajectory(store, "run_123")[0].x, 1);
  assert.equal(surface.getRunScorecard(store, "run_123").score, 1);
  assert.equal(surface.listRunArtifacts(store, "run_123")[0].id, "artifact_123");
  assert.equal(surface.getRunArtifact(store, "run_123", "artifact_123").name, "trace.json");
  assert.equal(surface.listUsage(store, { agent_id: "agent_123", group_by: "thread" }).group_by, "thread");
  assert.deepEqual(
    surface.authorityEvidenceSummary(store, {
      thread_id: "thread_123",
      run_id: "run_123",
      capability_ref: "capability:model",
      route_id: "route_123",
    }).filters,
    {
      thread_id: "thread_123",
      run_id: "run_123",
      capability_ref: "capability:model",
      route_id: "route_123",
    },
  );

  assert.ok(calls.every((call) => call.source === "runtime.lifecycle_projection_surface"));
  assert.ok(calls.every((call) => call.workspace_root === "/workspace/project"));
  assert.ok(calls.every((call) => call.state_dir === "/runtime-state"));
  assert.ok(calls.every((call) => call.evidence_refs.includes("runtime_lifecycle_rust_projection")));
  assert.ok(calls.every((call) => Object.hasOwn(call, "agents") === false));
  assert.ok(calls.every((call) => Object.hasOwn(call, "runs") === false));
  assert.ok(calls.every((call) => Object.hasOwn(call, "events") === false));
  assert.ok(calls.every((call) => Object.hasOwn(call, "replay") === false));
  assert.ok(calls.every((call) => Object.hasOwn(call, "agent") === false));
  assert.ok(calls.every((call) => Object.hasOwn(call, "run") === false));
  assert.ok(calls.every((call) => Object.hasOwn(call, "usage") === false));
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
    "usage_list",
    "authority_evidence_summary",
  ]);
  const turnCall = calls.find((call) => call.projection_kind === "thread_turn");
  assert.equal(turnCall.turn_id, "turn_123");
  assert.equal(Object.hasOwn(turnCall, "turnId"), false);
  const artifactCall = calls.find((call) => call.projection_kind === "run_artifact");
  assert.equal(artifactCall.artifact_ref, "artifact_123");
  assert.equal(Object.hasOwn(artifactCall, "artifactRef"), false);
  const usageCall = calls.find((call) => call.projection_kind === "usage_list");
  assert.equal(usageCall.agent_id, "agent_123");
  assert.equal(usageCall.group_by, "thread");
  assert.equal(Object.hasOwn(usageCall, "agentId"), false);
  assert.equal(Object.hasOwn(usageCall, "groupBy"), false);
  const authorityCall = calls.find((call) => call.projection_kind === "authority_evidence_summary");
  assert.equal(authorityCall.capability_ref, "capability:model");
  assert.equal(authorityCall.route_id, "route_123");
  assert.equal(Object.hasOwn(authorityCall, "capabilityRef"), false);
  assert.equal(Object.hasOwn(authorityCall, "routeId"), false);
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
