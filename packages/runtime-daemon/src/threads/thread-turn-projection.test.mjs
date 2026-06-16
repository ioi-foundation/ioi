import assert from "node:assert/strict";
import test from "node:test";

import { createThreadTurnProjection } from "./thread-turn-projection.mjs";

function createProjection() {
  return createThreadTurnProjection({
    eventStreamIdForThread: (threadId) => `stream:${threadId}`,
    runtimeThreadSchemaVersion: "thread.schema",
    runtimeTurnIdForRun: (run) => run.runtimeTurnId ?? `turn_${run.id.replace(/^run_/, "")}`,
    runtimeTurnSchemaVersion: "turn.schema",
    runtimeError(input) {
      const error = new Error(input.message);
      Object.assign(error, input);
      return error;
    },
    threadIdForAgent: (agentId) => `thread_${agentId.replace(/^agent_/, "")}`,
  });
}

function failIfCalled(name) {
  return () => {
    throw new Error(`${name} must not be called by JS thread/turn projection`);
  };
}

function createStore() {
  return {
    stateDir: "/tmp/ioi-runtime-state",
    projectionRequests: [],
    listRuns: failIfCalled("listRuns"),
    latestRuntimeEventSeq: failIfCalled("latestRuntimeEventSeq"),
    projectThreadEvents: failIfCalled("projectThreadEvents"),
    projectRunEvents: failIfCalled("projectRunEvents"),
    runtimeEventsForTurn: failIfCalled("runtimeEventsForTurn"),
    getAgent: failIfCalled("getAgent"),
    projectRuntimeThreadTurnProjectionForThread(inputStore, request) {
      this.projectionRequests.push({ inputStore, request });
      return {
        projected: true,
        record: request.projection_kind === "thread"
          ? {
              schema_version: "thread.schema",
              thread_id: request.thread_id,
              agent_id: "agent_one",
              title: "Rust replayed thread",
              latest_seq: 5,
              evidence_refs: ["rust_runtime_thread_turn_projection"],
            }
          : {
              schema_version: "turn.schema",
              thread_id: request.thread_id,
              turn_id: request.turn_id,
              request_id: request.run_id,
              events: [{ event_kind: "turn.completed" }],
              evidence_refs: ["rust_runtime_thread_turn_projection"],
            },
      };
    },
  };
}

function assertStateDirOnlyProjectionRequest(request, expected) {
  assert.deepEqual(request, expected);
  for (const retired of [
    "agent",
    "runs",
    "run",
    "events",
    "runtime_controls",
    "usage_telemetry",
    "memory_count",
    "subagent_ids",
    "latest_seq",
    "created_at_ms",
    "updated_at_ms",
    "mode",
    "approval_mode",
    "status",
    "completed_at",
  ]) {
    assert.equal(Object.hasOwn(request, retired), false, `${retired} must not cross the JS projection boundary`);
  }
}

test("thread projection delegates a state-dir-only request to Rust replay", () => {
  const store = createStore();
  const agent = { id: "agent_one" };

  const thread = createProjection().threadForAgent(store, agent);

  assert.equal(thread.thread_id, "thread_one");
  assert.equal(thread.title, "Rust replayed thread");
  assert.equal(store.projectionRequests[0].inputStore, store);
  assertStateDirOnlyProjectionRequest(store.projectionRequests[0].request, {
    projection_kind: "thread",
    thread_schema_version: "thread.schema",
    thread_id: "thread_one",
    event_stream_id: "stream:thread_one",
    state_dir: "/tmp/ioi-runtime-state",
  });
});

test("turn projection delegates run and turn identity to Rust replay without JS event facts", () => {
  const store = createStore();

  const turn = createProjection().turnForRun(store, {
    id: "run_one",
    agentId: "agent_one",
    runtimeTurnId: "turn_one",
  });

  assert.equal(turn.thread_id, "thread_one");
  assert.equal(turn.turn_id, "turn_one");
  assert.equal(turn.request_id, "run_one");
  assertStateDirOnlyProjectionRequest(store.projectionRequests[0].request, {
    projection_kind: "turn",
    turn_schema_version: "turn.schema",
    thread_id: "thread_one",
    turn_id: "turn_one",
    run_id: "run_one",
    event_stream_id: "stream:thread_one",
    state_dir: "/tmp/ioi-runtime-state",
  });
});

test("thread and turn projection fail closed without Rust projection API", () => {
  const store = createStore();
  delete store.projectRuntimeThreadTurnProjectionForThread;
  const projection = createProjection();

  assert.throws(
    () => projection.threadForAgent(store, { id: "agent_one" }),
    (error) => {
      assert.equal(error.code, "runtime_thread_turn_projection_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.thread_turn_projection");
      assert.equal(error.details.projection_kind, "thread");
      return true;
    },
  );
  assert.throws(
    () => projection.turnForRun(store, { id: "run_one", agentId: "agent_one" }),
    (error) => {
      assert.equal(error.code, "runtime_thread_turn_projection_rust_core_required");
      assert.equal(error.details.projection_kind, "turn");
      assert.equal(error.details.turn_id, "turn_one");
      return true;
    },
  );
});
