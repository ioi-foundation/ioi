import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const { createStudioThreadEvents } = require("./thread-events.js");

test("thread events collect aliases, dedupe identities, and compute max seq", () => {
  const helpers = createStudioThreadEvents({
    firstArray: (value) => (Array.isArray(value) ? value : []),
  });

  assert.deepEqual(
    helpers.collectStudioAgentEventsFromResponse({
      events: [{ id: "event-a" }],
      runtime_events: [{ id: "event-b" }],
      runtimeEvents: [{ id: "event-c" }],
      event_log: [{ id: "event-d" }],
      eventLog: [{ id: "event-e" }],
    }).map((event) => event.id),
    ["event-a", "event-b", "event-c", "event-d", "event-e"],
  );

  assert.deepEqual(
    helpers.uniqueStudioRuntimeEvents([
      { event_id: "one", seq: 1 },
      { event_id: "one", seq: 2 },
      { event_stream_id: "stream", seq: 4 },
      { event_stream_id: "stream", seq: 4 },
      { message: "unkeyed" },
    ]),
    [
      { event_id: "one", seq: 1 },
      { event_stream_id: "stream", seq: 4 },
      { message: "unkeyed" },
    ],
  );
  assert.equal(helpers.studioMaxRuntimeEventSeq([{ seq: 1 }, { seq: 5 }, { seq: "3" }]), 5);
});

test("thread events fetch SSE payloads and stops on terminal event", async () => {
  const output = { lines: [], appendLine(line) { this.lines.push(line); } };
  const seen = [];
  const helpers = createStudioThreadEvents({
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token",
    firstArray: (value) => (Array.isArray(value) ? value : []),
    requestSseJson: async (endpoint, route, options) => {
      seen.push({ endpoint, route, options });
      assert.equal(options.onPayload({ event: { kind: "turn.started", seq: 2 } }), undefined);
      assert.equal(options.onPayload({ kind: "turn.completed", seq: 3 }), false);
      options.onPayload({ kind: "turn.after-terminal", seq: 4 });
    },
    studioRuntimeEventKind: (event) => event.kind || "",
  });

  const events = await helpers.fetchStudioThreadEvents("thread one", output, {
    sinceSeq: 2,
    timeoutMs: 123,
    stopOnTerminal: true,
  });

  assert.equal(seen[0].route, "/v1/threads/thread%20one/events?since_seq=2");
  assert.equal(seen[0].options.token, "token");
  assert.equal(seen[0].options.timeoutMs, 123);
  assert.deepEqual(events.map((event) => event.kind), ["turn.started", "turn.completed", "turn.after-terminal"]);
  assert.deepEqual(output.lines, []);
});

test("thread events fetch turns and expand scoped turn events", async () => {
  const output = { lines: [], appendLine(line) { this.lines.push(line); } };
  const helpers = createStudioThreadEvents({
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token",
    firstArray: (value) => (Array.isArray(value) ? value : []),
    requestJson: async (endpoint, route, options) => {
      assert.equal(endpoint, "http://daemon.test");
      assert.equal(route, "/v1/threads/thread-one/turns");
      assert.equal(options.method, "GET");
      return [
        { turn_id: "turn-a", events: [{ id: "event-a" }] },
        { turnId: "turn-b", runtimeEvents: [{ id: "event-b" }], eventLog: [{ id: "event-c" }] },
      ];
    },
  });

  assert.deepEqual((await helpers.fetchStudioThreadTurns("thread-one", output)).map((turn) => turn.turn_id || turn.turnId), ["turn-a", "turn-b"]);
  assert.deepEqual((await helpers.fetchStudioThreadTurnEvents("thread-one", output, { turnId: "turn-b" })).map((event) => event.id), ["event-b", "event-c"]);
  assert.deepEqual(output.lines, []);
});

test("thread events report fetch failures as empty product-safe lists", async () => {
  const output = { lines: [], appendLine(line) { this.lines.push(line); } };
  const helpers = createStudioThreadEvents({
    daemonEndpoint: () => "http://daemon.test",
    daemonRequestToken: () => "token",
    firstArray: (value) => (Array.isArray(value) ? value : []),
    requestJson: async () => {
      throw new Error("offline");
    },
    requestSseJson: async () => {
      throw new Error("sse offline");
    },
    studioRuntimeEventKind: (event) => event.kind || "",
  });

  assert.deepEqual(await helpers.fetchStudioThreadTurns("thread-one", output), []);
  assert.deepEqual(await helpers.fetchStudioThreadEvents("thread-one", output), []);
  assert.match(output.lines[0], /daemon turn refresh unavailable: offline/);
  assert.match(output.lines[1], /daemon thread event stream unavailable: sse offline/);
});
