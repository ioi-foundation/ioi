import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeThreadEventSurface } from "./runtime-thread-event-surface.mjs";

function harness() {
  const calls = [];
  const agent = { id: "agent-one", cwd: "/workspace" };
  const run = { id: "run-one", agentId: "agent-one" };
  const threadTurnProjection = {
    threadForAgent(store, inputAgent) {
      calls.push({ name: "threadForAgent", agentId: inputAgent.id });
      return { thread_id: `thread-${inputAgent.id}` };
    },
    turnForRun(store, inputRun) {
      calls.push({ name: "turnForRun", runId: inputRun.id });
      return { turn_id: `turn-${inputRun.id}` };
    },
  };
  const surface = createRuntimeThreadEventSurface({
    DAEMON_FIXTURE_PROFILE: "daemon-fixture",
    RUNTIME_THREAD_SCHEMA_VERSION: "thread-schema",
    appendRuntimeEvent(store, event, deps) {
      calls.push({ name: "appendRuntimeEvent", event, depKeys: Object.keys(deps).sort() });
      return { event_id: "event-one" };
    },
    assertRuntimeCursorSeq(cursorSeq, latestSeq, details, deps) {
      calls.push({ name: "assertRuntimeCursorSeq", cursorSeq, latestSeq, details, hasRuntimeError: typeof deps.runtimeError === "function" });
      return cursorSeq;
    },
    ensureThreadStartedEvent(store, inputAgent, deps) {
      calls.push({ name: "ensureThreadStartedEvent", agentId: inputAgent.id, deps });
      return { event_id: "thread-started" };
    },
    eventStreamIdForThread(threadId) {
      return `stream-${threadId}`;
    },
    fs: { appendFileSync() {} },
    isRuntimeBackedAgent(inputAgent) {
      return inputAgent.runtimeProfile === "native";
    },
    latestRuntimeEventSeq(store, eventStreamId) {
      calls.push({ name: "latestRuntimeEventSeq", eventStreamId });
      return 9;
    },
    normalizeRuntimeEventEnvelope(event) {
      return event;
    },
    notFound(message, details) {
      const error = new Error(message);
      error.details = details;
      return error;
    },
    projectRunEvents(store, inputRun, inputAgent, deps) {
      calls.push({ name: "projectRunEvents", runId: inputRun.id, agentId: inputAgent.id, depKeys: Object.keys(deps).sort() });
      return ["projected-run"];
    },
    projectThreadEvents(store, inputAgent, deps) {
      calls.push({ name: "projectThreadEvents", agentId: inputAgent.id, runtimeBacked: deps.isRuntimeBackedAgent(inputAgent) });
      return ["projected-thread"];
    },
    registerRuntimeEvent(store, record) {
      calls.push({ name: "registerRuntimeEvent", record });
    },
    runtimeCursorSeq(store, stream, cursor, deps) {
      calls.push({ name: "runtimeCursorSeq", cursor, hasRuntimeError: typeof deps.runtimeError === "function" });
      return 3;
    },
    runtimeError(input) {
      const error = new Error(input.message);
      error.details = input;
      return error;
    },
    runtimeEventsForStream(store, eventStreamId, cursor) {
      calls.push({ name: "runtimeEventsForStream", eventStreamId, cursor });
      return [{ event_id: "stream-event" }];
    },
    runtimeEventsForTurn(store, turnId, cursor) {
      calls.push({ name: "runtimeEventsForTurn", turnId, cursor });
      return [{ event_id: "turn-event" }];
    },
    runtimeEventStream(store, eventStreamId) {
      calls.push({ name: "runtimeEventStream", eventStreamId });
      return { events: [] };
    },
    runtimeEventStreamFileName(eventStreamId) {
      return `file-${eventStreamId}`;
    },
    runtimeEventStreamPath(store, eventStreamId, deps) {
      calls.push({ name: "runtimeEventStreamPath", eventStreamId, fileName: deps.runtimeEventStreamFileName(eventStreamId) });
      return `/state/events/${eventStreamId}.jsonl`;
    },
    runtimeTurnIdForRun(inputRun) {
      return `runtime-turn-${inputRun.id}`;
    },
    threadIdForAgent(agentId) {
      return `thread-${agentId}`;
    },
    threadStatusForAgent(status) {
      return status === "archived" ? "archived" : "active";
    },
    threadTurnProjection,
    ttiEnvelopeForRunEvent() {
      return { event_id: "tti" };
    },
    turnIdForRun(runId) {
      return `turn-${runId}`;
    },
  });
  const store = {
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return agent;
    },
    getAgent(agentId) {
      calls.push({ name: "getAgent", agentId });
      return agent;
    },
    getRun(runId) {
      calls.push({ name: "getRun", runId });
      return run;
    },
    listRuns(agentId) {
      calls.push({ name: "listRuns", agentId });
      return [run];
    },
    projectThreadEvents(inputAgent) {
      return surface.projectThreadEvents(this, inputAgent);
    },
    runtimeEventsForStream(eventStreamId, cursor) {
      return surface.runtimeEventsForStream(this, eventStreamId, cursor);
    },
    runtimeEventsForTurn(turnId, cursor) {
      return surface.runtimeEventsForTurn(this, turnId, cursor);
    },
    turnForRun(inputRun) {
      return surface.turnForRun(this, inputRun);
    },
  };
  return { agent, calls, run, store, surface };
}

test("runtime thread event surface projects turns and event queries", () => {
  const { calls, store, surface } = harness();

  assert.deepEqual(surface.listTurns(store, "thread-agent-one"), [
    { turn_id: "turn-run-one" },
  ]);
  assert.deepEqual(surface.getTurn(store, "thread-agent-one", "turn-run-one"), {
    turn_id: "turn-run-one",
  });
  assert.throws(
    () => surface.getTurn(store, "thread-agent-one", "missing"),
    /Turn not found: missing/,
  );
  assert.deepEqual(surface.eventsForThread(store, "thread-agent-one", { since_seq: 1 }), [
    { event_id: "stream-event" },
  ]);
  assert.deepEqual(surface.eventsForRun(store, "run-one", { last_event_id: "event-one" }), [
    { event_id: "turn-event" },
  ]);

  assert.deepEqual(calls.filter((call) => call.name === "runtimeEventsForStream"), [
    {
      name: "runtimeEventsForStream",
      eventStreamId: "stream-thread-agent-one",
      cursor: { since_seq: 1 },
    },
  ]);
  assert.deepEqual(calls.filter((call) => call.name === "runtimeEventsForTurn"), [
    {
      name: "runtimeEventsForTurn",
      turnId: "runtime-turn-run-one",
      cursor: { last_event_id: "event-one" },
    },
  ]);
});

test("runtime thread event surface delegates replay and projection helpers", () => {
  const { agent, calls, run, store, surface } = harness();

  assert.equal(surface.ensureThreadStartedEvent(store, agent).event_id, "thread-started");
  assert.deepEqual(surface.projectRunEvents(store, run), ["projected-run"]);
  assert.equal(surface.appendRuntimeEvent(store, { event_kind: "turn.started" }).event_id, "event-one");
  assert.equal(surface.runtimeCursorSeq(store, { events: [] }, { since_seq: 2 }), 3);
  assert.equal(surface.assertRuntimeCursorSeq(2, 4, { eventStreamId: "stream-one" }), 2);
  assert.equal(surface.latestRuntimeEventSeq(store, "stream-one"), 9);
  assert.deepEqual(surface.runtimeEventStream(store, "stream-one"), { events: [] });
  assert.equal(surface.runtimeEventStreamPath(store, "stream-one"), "/state/events/stream-one.jsonl");
  surface.registerRuntimeEvent(store, { event_id: "event-one" });
  assert.deepEqual(surface.threadForAgent(store, agent), { thread_id: "thread-agent-one" });
  assert.deepEqual(surface.turnForRun(store, run), { turn_id: "turn-run-one" });

  assert.deepEqual(calls.find((call) => call.name === "ensureThreadStartedEvent").deps, {
    DAEMON_FIXTURE_PROFILE: "daemon-fixture",
    RUNTIME_THREAD_SCHEMA_VERSION: "thread-schema",
    eventStreamIdForThread: calls.find((call) => call.name === "ensureThreadStartedEvent").deps.eventStreamIdForThread,
    threadIdForAgent: calls.find((call) => call.name === "ensureThreadStartedEvent").deps.threadIdForAgent,
    threadStatusForAgent: calls.find((call) => call.name === "ensureThreadStartedEvent").deps.threadStatusForAgent,
  });
  assert.deepEqual(calls.find((call) => call.name === "projectRunEvents").depKeys, [
    "isRuntimeBackedAgent",
    "threadIdForAgent",
    "ttiEnvelopeForRunEvent",
    "turnIdForRun",
  ]);
  assert.deepEqual(calls.find((call) => call.name === "appendRuntimeEvent").depKeys, [
    "fs",
    "normalizeRuntimeEventEnvelope",
    "runtimeError",
  ]);
});
