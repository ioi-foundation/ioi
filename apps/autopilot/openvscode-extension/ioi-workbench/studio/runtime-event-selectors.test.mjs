import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioRuntimeEventSelectors } = require("./runtime-event-selectors.js");

function createSelectors() {
  return createStudioRuntimeEventSelectors({
    firstArray: (value) => Array.isArray(value) ? value : [],
    stringValue: (value, fallback = "") => {
      if (typeof value !== "string") return fallback;
      const trimmed = value.trim();
      return trimmed || fallback;
    },
    studioRuntimeEventKind: (event = {}) => String(event.kind || event.type || ""),
    studioRuntimeEventToolName: (event = {}) => String(event.toolName || event.tool_name || event.payload?.toolName || ""),
  });
}

test("runtime event selectors match tool names case-insensitively and count all matches", () => {
  const selectors = createSelectors();
  const events = [
    { kind: "tool.started", toolName: "Shell__Run" },
    { kind: "tool.completed", tool_name: "shell__run" },
    { kind: "tool.result", payload: { toolName: "web__search" } },
  ];

  assert.equal(selectors.studioRuntimeEventsIncludeTool(events, /shell__run/), true);
  assert.equal(selectors.studioRuntimeEventsIncludeCompletedTool(events, /shell__run/), true);
  assert.equal(selectors.studioRuntimeEventsIncludeCompletedTool(events, /web__read/), false);
  assert.equal(selectors.studioRuntimeToolEventCount(events, /shell__run/), 2);
});

test("runtime event selectors resolve turn ids from aliases and preserve fallback events", () => {
  const selectors = createSelectors();
  const events = [
    { turn_id: "turn-1", toolName: "shell__run" },
    { turnId: "turn-2", toolName: "file__read" },
    { payload: { turn_id: "turn-1" }, toolName: "web__read" },
  ];

  assert.equal(selectors.studioRuntimeEventTurnId(events[0]), "turn-1");
  assert.equal(selectors.studioRuntimeEventTurnId(events[1]), "turn-2");
  assert.equal(selectors.studioRuntimeEventsForTurn(events, "turn-1").length, 2);
  assert.equal(selectors.studioRuntimeEventsForTurn(events, "missing").length, 3);
  assert.equal(selectors.studioRuntimeEventsForTurn(events, "").length, 3);
  assert.deepEqual(selectors.studioRuntimeEventsForTurn(null, "turn-1"), []);
});
