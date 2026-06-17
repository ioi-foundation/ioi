import assert from "node:assert/strict";
import test from "node:test";

import { buildWorkflowTerminalStreamCard } from "./workflow-terminal-stream-card";

test("terminal stream card projects canonical command stream events", () => {
  const card = buildWorkflowTerminalStreamCard({
    events: [
      {
        event_kind: "COMMAND_STREAM",
        event_stream_id: "events-thread-terminal",
        tool_call_id: "call-terminal",
        seq: 2,
        created_at: "2026-06-07T10:00:02.000Z",
        receipt_refs: ["receipt-event-terminal"],
        artifact_refs: ["artifact-event-terminal"],
        payload_summary: {
          stream_id: "stream-terminal",
          stream_seq: 2,
          output_text: "hello\n",
          is_final: true,
          tool_call_id: "call-terminal",
          tool_name: "terminal.exec",
          receipt_refs: ["receipt-payload-terminal"],
          artifact_refs: ["artifact-payload-terminal"],
        },
      },
    ],
  });

  assert.equal(card.status, "ready");
  assert.equal(card.rows[0]?.streamId, "stream-terminal");
  assert.equal(card.rows[0]?.toolCallId, "call-terminal");
  assert.equal(card.rows[0]?.toolName, "terminal.exec");
  assert.equal(card.rows[0]?.preview, "hello");
  assert.deepEqual(card.rows[0]?.receiptRefs, [
    "receipt-event-terminal",
    "receipt-payload-terminal",
  ]);
  assert.deepEqual(card.rows[0]?.artifactRefs, [
    "artifact-event-terminal",
    "artifact-payload-terminal",
  ]);
});

test("terminal stream card ignores retired command stream aliases", () => {
  const card = buildWorkflowTerminalStreamCard({
    events: [
      {
        eventKind: "COMMAND_STREAM",
        eventStreamId: "events-retired",
        toolCallId: "call-retired",
        createdAt: "2026-06-07T10:00:03.000Z",
        receiptRefs: ["receipt-retired-event"],
        artifactRefs: ["artifact-retired-event"],
        payload: {
          streamId: "stream-retired",
          streamSeq: 3,
          outputText: "retired\n",
          isFinal: true,
          toolCallId: "call-retired",
          toolName: "terminal.retired",
          receiptRefs: ["receipt-retired-payload"],
          artifactRefs: ["artifact-retired-payload"],
        },
      },
    ],
  });

  assert.equal(card.status, "empty");
  assert.equal(card.streamCount, 0);
  assert.deepEqual(card.rows, []);
});
