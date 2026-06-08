import assert from "node:assert/strict";
import { test } from "node:test";

import {
  appendRuntimeEvent,
  assertRuntimeCursorSeq,
  ensureThreadStartedEvent,
  latestRuntimeEventSeq,
  projectRunEvents,
  projectThreadEvents,
  registerRuntimeEvent,
  runtimeCursorSeq,
  runtimeEventsForStream,
  runtimeEventsForTurn,
  runtimeEventStream,
  runtimeEventStreamPath,
} from "./thread-replay.mjs";

function deps(calls = []) {
  return {
    DAEMON_FIXTURE_PROFILE: "fixture",
    RUNTIME_THREAD_SCHEMA_VERSION: "ioi.runtime.thread.v1",
    eventStreamIdForThread(threadId) {
      return `stream_${threadId}`;
    },
    fs: {
      appendFileSync(file, text) {
        calls.push({ operation: "append_file", file, text });
      },
    },
    isRuntimeBackedAgent(agent) {
      return Boolean(agent.runtimeSessionId);
    },
    normalizeRuntimeEventEnvelope(event, { seq, parentSeq, idempotencyKey }) {
      return {
        ...event,
        seq,
        parent_seq: parentSeq,
        event_id: event.event_id ?? `evt_${seq}`,
        idempotency_key: idempotencyKey,
      };
    },
    runtimeError(input) {
      const error = new Error(input.message);
      Object.assign(error, input);
      return error;
    },
    runtimeEventStreamFileName(eventStreamId) {
      return String(eventStreamId).replaceAll(":", "_");
    },
    threadIdForAgent(agentId) {
      return `thread_${agentId}`;
    },
    threadStatusForAgent(status) {
      return status === "archived" ? "archived" : "active";
    },
    ttiEnvelopeForRunEvent({ event, threadId, turnId, workspaceRoot }) {
      return {
        event_stream_id: `stream_${threadId}`,
        thread_id: threadId,
        turn_id: turnId,
        idempotency_key: `run:${turnId}:${event.event_kind}`,
        event_kind: event.event_kind,
        workspace_root: workspaceRoot,
      };
    },
    turnIdForRun(runId) {
      return `turn_${runId}`;
    },
  };
}

function fakeStore(calls = []) {
  return {
    runtimeEventStreams: new Map(),
    pathFor(kind, fileName) {
      return `/state/${kind}/${fileName}`;
    },
    runtimeEventStream(eventStreamId) {
      return runtimeEventStream(this, eventStreamId);
    },
    runtimeEventStreamPath(eventStreamId) {
      return runtimeEventStreamPath(this, eventStreamId, deps(calls));
    },
    runtimeCursorSeq(stream, cursor) {
      return runtimeCursorSeq(this, stream, cursor, deps(calls));
    },
    appendRuntimeEvent(event) {
      return appendRuntimeEvent(this, event, deps(calls));
    },
    ensureThreadStartedEvent(agent) {
      return ensureThreadStartedEvent(this, agent, deps(calls));
    },
    listRuns(agentId) {
      return this.runs.filter((run) => run.agentId === agentId);
    },
    projectRunEvents(run, agent) {
      return projectRunEvents(this, run, agent, deps(calls));
    },
    runs: [],
    assertRuntimeCursorSeq(cursorSeq, latestSeq, details) {
      return assertRuntimeCursorSeq(cursorSeq, latestSeq, details, deps(calls));
    },
  };
}

test("runtime event append records events once by idempotency key", () => {
  const calls = [];
  const store = fakeStore(calls);
  const event = {
    event_stream_id: "stream:thread",
    thread_id: "thread_1",
    turn_id: "turn_1",
    idempotency_key: "idem_1",
    event_kind: "turn.started",
  };

  const first = appendRuntimeEvent(store, event, deps(calls));
  const duplicate = appendRuntimeEvent(store, event, deps(calls));

  assert.equal(first, duplicate);
  assert.equal(first.seq, 1);
  assert.equal(store.runtimeEventStream("stream:thread").events.length, 1);
  assert.equal(calls.filter((call) => call.operation === "append_file").length, 1);
});

test("runtime events replay by stream and cursor", () => {
  const calls = [];
  const store = fakeStore(calls);
  appendRuntimeEvent(store, {
    event_stream_id: "stream:thread",
    turn_id: "turn_1",
    idempotency_key: "idem_1",
    event_kind: "turn.started",
  }, deps(calls));
  appendRuntimeEvent(store, {
    event_stream_id: "stream:thread",
    turn_id: "turn_1",
    idempotency_key: "idem_2",
    event_kind: "turn.completed",
  }, deps(calls));

  assert.deepEqual(runtimeEventsForStream(store, "stream:thread", { since_seq: 1 }).map((event) => event.seq), [2]);
  assert.deepEqual(runtimeEventsForTurn(store, "turn_1", "evt_1").map((event) => event.seq), [2]);
  assert.equal(latestRuntimeEventSeq(store, "stream:thread"), 2);
});

test("runtime cursor rejects missing and future cursors", () => {
  const calls = [];
  const store = fakeStore(calls);
  appendRuntimeEvent(store, {
    event_stream_id: "stream:thread",
    turn_id: "turn_1",
    idempotency_key: "idem_1",
    event_kind: "turn.started",
  }, deps(calls));
  const stream = store.runtimeEventStream("stream:thread");

  assert.throws(
    () => runtimeCursorSeq(store, stream, { last_event_id: "missing" }, deps(calls)),
    (error) => {
      assert.equal(error.code, "event_cursor_out_of_range");
      assert.equal(error.details.last_event_id, "missing");
      assert.equal(Object.hasOwn(error.details, "lastEventId"), false);
      return true;
    },
  );
  assert.throws(
    () => assertRuntimeCursorSeq(3, 1, { event_stream_id: "stream:thread" }, deps(calls)),
    (error) => {
      assert.equal(error.code, "event_cursor_out_of_range");
      assert.equal(error.details.since_seq, 3);
      assert.equal(Object.hasOwn(error.details, "sinceSeq"), false);
      return true;
    },
  );
});

test("runtime event registration sorts persisted records", () => {
  const store = fakeStore();
  registerRuntimeEvent(store, {
    event_stream_id: "stream:thread",
    idempotency_key: "idem_2",
    seq: 2,
  });
  registerRuntimeEvent(store, {
    event_stream_id: "stream:thread",
    idempotency_key: "idem_1",
    seq: 1,
  });
  registerRuntimeEvent(store, {
    event_stream_id: "stream:thread",
    idempotency_key: "idem_1",
    seq: 1,
  });

  assert.deepEqual(store.runtimeEventStream("stream:thread").events.map((event) => event.seq), [1, 2]);
});

test("runtime event stream path uses runtime event filename helper", () => {
  const store = fakeStore();
  assert.equal(runtimeEventStreamPath(store, "stream:thread", deps()), "/state/events/stream_thread.jsonl");
});

test("thread replay projection appends thread started event", () => {
  const calls = [];
  const store = fakeStore(calls);
  const event = ensureThreadStartedEvent(store, {
    id: "agent_1",
    status: "active",
    createdAt: "2026-06-03T00:00:00.000Z",
    cwd: "/workspace",
    modelRouteReceiptId: "receipt_model",
  }, deps(calls));

  assert.equal(event.event_kind, "thread.started");
  assert.equal(event.event_stream_id, "stream_thread_agent_1");
  assert.equal(event.payload_schema_version, "ioi.runtime.thread.v1");
  assert.deepEqual(event.receipt_refs, ["receipt_model"]);
});

test("thread replay projection appends run events for fixture threads", () => {
  const calls = [];
  const store = fakeStore(calls);
  const agent = {
    id: "agent_1",
    status: "active",
    createdAt: "2026-06-03T00:00:00.000Z",
    cwd: "/workspace",
  };
  store.runs = [{
    id: "run_1",
    agentId: "agent_1",
    events: [{ event_kind: "turn.started" }, { event_kind: "turn.completed" }],
  }];

  projectThreadEvents(store, agent, deps(calls));

  const events = runtimeEventsForStream(store, "stream_thread_agent_1");
  assert.deepEqual(events.map((event) => event.event_kind), [
    "thread.started",
    "turn.started",
    "turn.completed",
  ]);
});

test("thread replay projection skips runtime-backed agents", () => {
  const store = fakeStore();
  const agent = {
    id: "agent_1",
    runtimeSessionId: "session_runtime",
    cwd: "/workspace",
  };

  projectThreadEvents(store, agent, deps());
  projectRunEvents(store, { id: "run_1", events: [{ event_kind: "turn.started" }] }, agent, deps());

  assert.equal([...store.runtimeEventStreams.values()].flatMap((stream) => stream.events).length, 0);
});
