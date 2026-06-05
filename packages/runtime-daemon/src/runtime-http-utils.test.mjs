import assert from "node:assert/strict";
import test from "node:test";

import { writeSse } from "./runtime-http-utils.mjs";

function responseRecorder() {
  return {
    headers: {},
    statusCode: 200,
    body: "",
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    end(value = "") {
      this.body = value;
    },
  };
}

test("writeSse uses canonical runtime event ids", () => {
  const response = responseRecorder();

  writeSse(response, [
    { event_id: "events-thread-one:seq:00000001", seq: 1, event_kind: "turn.started" },
    { seq: 2, event_kind: "turn.completed" },
  ]);

  assert.equal(response.statusCode, 200);
  assert.equal(response.headers["content-type"], "text/event-stream");
  assert.match(response.body, /^id: events-thread-one:seq:00000001/m);
  assert.match(response.body, /^id: 2/m);
});
