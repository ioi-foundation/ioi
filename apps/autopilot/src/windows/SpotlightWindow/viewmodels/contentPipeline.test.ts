import assert from "node:assert/strict";
import type { AgentEvent, Artifact, ChatMessage } from "../../../types";
import {
  buildRunPresentation,
  classifyActivityEvent,
  normalizeOutputForHash,
} from "./contentPipeline";

const BASE_TIMESTAMP = "2026-02-19T03:00:00Z";

const baseEvent: AgentEvent = {
  event_id: "evt-1",
  timestamp: BASE_TIMESTAMP,
  thread_id: "thread-a",
  step_index: 1,
  event_type: "COMMAND_RUN",
  title: "Ran chat__reply",
  digest: { tool_name: "chat__reply" },
  details: {
    output:
      "Top 3 stories\nCompletion reason: Completed after meeting the source floor.\nRun timestamp (UTC): 2026-02-19T02:59:18Z\nOverall confidence: medium\nhttps://example.com/a\nhttps://example.com/b",
  },
  artifact_refs: [],
  receipt_ref: null,
  input_refs: [],
  status: "SUCCESS",
  duration_ms: null,
};

function classifyEventTest(): void {
  const receipt: AgentEvent = {
    ...baseEvent,
    event_id: "evt-r",
    event_type: "RECEIPT",
    title: "Receipt",
  };
  const reasoning: AgentEvent = {
    ...baseEvent,
    event_id: "evt-reasoning",
    event_type: "INFO_NOTE",
    title: "Captured reasoning step",
    digest: {},
  };

  assert.equal(classifyActivityEvent(receipt), "receipt_event");
  assert.equal(classifyActivityEvent(baseEvent), "primary_answer_event");
  assert.equal(classifyActivityEvent(reasoning), "reasoning_event");
}

function normalizeOutputTest(): void {
  const normalized = normalizeOutputForHash(
    "a  b   c | 2026-02-19T02:59:18Z | value",
  );
  assert.equal(normalized, "a b c |TIMESTAMP| value");
}

function dedupAndAnswerTest(): void {
  const duplicateAnswerDifferentStep: AgentEvent = {
    ...baseEvent,
    event_id: "evt-2",
    step_index: 2,
  };

  const history: ChatMessage[] = [
    { role: "user", text: "question", timestamp: Date.now() - 10_000 },
    {
      role: "agent",
      text: "final answer\nRun timestamp (UTC): 2026-02-19T03:00:00Z",
      timestamp: Date.now() - 1_000,
    },
  ];

  const presentation = buildRunPresentation(history, [baseEvent, duplicateAnswerDifferentStep], []);
  assert.equal(presentation.prompt?.text, "question");
  assert.equal(presentation.finalAnswer?.message.text.includes("final answer"), true);
  assert.equal(presentation.activityGroups.length, 1);
  assert.equal(presentation.activityGroups[0]?.events.length, 1);
}

function activitySummaryTest(): void {
  const searchEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-search",
    step_index: 2,
    event_type: "COMMAND_RUN",
    digest: { tool_name: "web__search" },
    details: { output: "ok" },
  };

  const readEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-read",
    step_index: 3,
    event_type: "COMMAND_RUN",
    digest: { tool_name: "web__read" },
    details: { output: "ok" },
  };

  const receiptEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-receipt",
    step_index: 4,
    event_type: "RECEIPT",
    title: "Receipt",
    digest: { tool_name: "web__read" },
  };

  const reasoningEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-reasoning",
    step_index: 5,
    event_type: "INFO_NOTE",
    title: "Captured reasoning step",
    digest: {},
    details: { output: "reasoning" },
  };

  const artifacts: Artifact[] = [
    {
      artifact_id: "art-1",
      created_at: BASE_TIMESTAMP,
      thread_id: "thread-a",
      artifact_type: "LOG",
      title: "Log",
      description: "",
      content_ref: "scs://artifact/art-1",
      metadata: {},
      version: 1,
      parent_artifact_id: null,
    },
  ];

  const presentation = buildRunPresentation(
    [],
    [searchEvent, readEvent, receiptEvent, reasoningEvent],
    artifacts,
  );

  assert.equal(presentation.activitySummary.searchCount, 1);
  assert.equal(presentation.activitySummary.readCount, 1);
  assert.equal(presentation.activitySummary.receiptCount, 1);
  assert.equal(presentation.activitySummary.reasoningCount, 1);
  assert.equal(presentation.activitySummary.artifactCount, 1);
  assert.equal(presentation.artifactRefs.length, 1);
}

classifyEventTest();
normalizeOutputTest();
dedupAndAnswerTest();
activitySummaryTest();
