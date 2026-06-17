import assert from "node:assert/strict";
import { buildEventTurnWindows } from "./turnWindows.ts";

const windows = buildEventTurnWindows([
  {
    event_id: "tool-1",
    timestamp: undefined,
    thread_id: "thread",
    step_index: 2,
    event_type: "tool_execution" as any,
    title: "Tool",
    digest: {},
    details: {},
    artifact_refs: [],
    receipt_ref: null,
    input_refs: [],
    status: "complete" as any,
    duration_ms: null,
  },
  {
    event_id: "user-1",
    timestamp: undefined,
    thread_id: "thread",
    step_index: 1,
    event_type: "agent_message" as any,
    title: "User request",
    digest: { query: "install autopilot" },
    details: {},
    artifact_refs: [],
    receipt_ref: null,
    input_refs: [],
    status: "complete" as any,
    duration_ms: null,
  },
] as any);

assert.equal(windows.length, 1);
assert.equal(windows[0]?.prompt, "install autopilot");
assert.equal(windows[0]?.startAtMs, null);

console.log("turnWindows.test.ts: ok");
