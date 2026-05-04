import assert from "node:assert/strict";
import { collectConversationArtifacts } from "./artifactConversationModel.ts";

const entries = collectConversationArtifacts([
  {
    event_id: "event-without-timestamp",
    timestamp: undefined,
    thread_id: "thread",
    step_index: 2,
    event_type: "receipt" as any,
    title: "Receipt",
    digest: {},
    details: {},
    artifact_refs: [],
    receipt_ref: null,
    input_refs: [],
    status: "complete" as any,
    duration_ms: null,
  },
  {
    event_id: "event-with-timestamp",
    timestamp: "2026-05-03T18:20:00.000Z",
    thread_id: "thread",
    step_index: 1,
    event_type: "receipt" as any,
    title: "Receipt",
    digest: {},
    details: {},
    artifact_refs: [],
    receipt_ref: null,
    input_refs: [],
    status: "complete" as any,
    duration_ms: null,
  },
] as any);

assert.equal(entries.length, 0);

console.log("artifactConversationModel.test.ts: ok");
