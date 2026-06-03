import assert from "node:assert/strict";
import { test } from "node:test";

import {
  appendRuntimeEvent,
  assertRuntimeCursorSeq,
  latestRuntimeEventSeq,
  registerRuntimeEvent,
  runtimeCursorSeq,
  runtimeEventsForStream,
  runtimeEventsForTurn,
  runtimeEventStream,
  runtimeEventStreamPath,
} from "./thread-replay.mjs";

function deps(calls = []) {
  return {
    fs: {
      appendFileSync(file, text) {
        calls.push({ operation: "append_file", file, text });
      },
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

  assert.deepEqual(runtimeEventsForStream(store, "stream:thread", { sinceSeq: 1 }).map((event) => event.seq), [2]);
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
    () => runtimeCursorSeq(store, stream, { lastEventId: "missing" }, deps(calls)),
    (error) => {
      assert.equal(error.code, "event_cursor_out_of_range");
      assert.equal(error.details.lastEventId, "missing");
      return true;
    },
  );
  assert.throws(
    () => assertRuntimeCursorSeq(3, 1, { eventStreamId: "stream:thread" }, deps(calls)),
    (error) => {
      assert.equal(error.code, "event_cursor_out_of_range");
      assert.equal(error.details.sinceSeq, 3);
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
