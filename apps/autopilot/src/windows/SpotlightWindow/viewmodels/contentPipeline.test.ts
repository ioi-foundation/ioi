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

function sourceSummaryTest(): void {
  const searchBundle = {
    schema_version: 1,
    retrieved_at_ms: 1771600000000,
    tool: "web__search",
    backend: "edge:ddg",
    query: "current weather Anderson South Carolina",
    sources: [
      {
        source_id: "s1",
        rank: 1,
        url: "https://weather.com/weather/today/l/Anderson+SC",
        title: "weather.com",
        domain: "weather.com",
      },
      {
        source_id: "s2",
        rank: 2,
        url: "https://www.accuweather.com/en/us/anderson/29624/current-weather/330677",
        title: "accuweather",
        domain: "accuweather.com",
      },
    ],
    documents: [],
  };

  const readBundle = {
    schema_version: 1,
    retrieved_at_ms: 1771600001000,
    tool: "web__read",
    backend: "edge:read",
    url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
    sources: [
      {
        source_id: "s3",
        rank: 1,
        url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
        title: "NWS Anderson",
        domain: "forecast.weather.gov",
      },
    ],
    documents: [
      {
        source_id: "s3",
        url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
        title: "NWS Anderson, SC",
        content_text: "ok",
        content_hash: "abc",
        quote_spans: [],
      },
    ],
  };

  const searchEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-web-search",
    step_index: 10,
    digest: { tool_name: "web__search" },
    details: {
      output: JSON.stringify(searchBundle, null, 2),
    },
  };

  const readEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-web-read",
    step_index: 11,
    digest: { tool_name: "web__read" },
    details: {
      output: JSON.stringify(readBundle, null, 2),
    },
  };

  const presentation = buildRunPresentation([], [searchEvent, readEvent], []);
  assert.ok(presentation.sourceSummary);
  assert.equal(presentation.sourceSummary?.totalSources, 3);
  assert.equal(presentation.sourceSummary?.searches.length, 1);
  assert.equal(presentation.sourceSummary?.browses.length, 1);
  assert.equal(
    presentation.sourceSummary?.searches[0]?.query,
    "current weather Anderson South Carolina",
  );
}

function sourceSummaryReceiptOnlyTest(): void {
  const searchBundle = {
    schema_version: 1,
    retrieved_at_ms: 1771600000000,
    tool: "web__search",
    backend: "edge:ddg",
    query: "weather right now near me",
    sources: [
      {
        source_id: "s1",
        rank: 1,
        url: "https://weather.com/weather/today/l/Anderson+SC",
        title: "weather.com",
        domain: "weather.com",
      },
    ],
    documents: [],
  };

  const readBundle = {
    schema_version: 1,
    retrieved_at_ms: 1771600001000,
    tool: "web__read",
    backend: "edge:read",
    url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
    sources: [
      {
        source_id: "s2",
        rank: 1,
        url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
        title: "NWS Anderson",
        domain: "forecast.weather.gov",
      },
    ],
    documents: [],
  };

  const searchReceipt: AgentEvent = {
    ...baseEvent,
    event_id: "evt-receipt-search",
    step_index: 12,
    event_type: "RECEIPT",
    title: "Receipt: web__search",
    digest: { tool_name: "web__search" },
    details: {
      output: JSON.stringify(searchBundle, null, 2),
    },
  };

  const readReceipt: AgentEvent = {
    ...baseEvent,
    event_id: "evt-receipt-read",
    step_index: 13,
    event_type: "RECEIPT",
    title: "Receipt: web__read",
    digest: { tool_name: "web__read" },
    details: {
      output: JSON.stringify(readBundle, null, 2),
    },
  };

  const presentation = buildRunPresentation([], [searchReceipt, readReceipt], []);
  assert.ok(presentation.sourceSummary);
  assert.equal(presentation.sourceSummary?.totalSources, 2);
  assert.equal(presentation.sourceSummary?.searches.length, 1);
  assert.equal(presentation.sourceSummary?.browses.length, 1);
}

function thoughtSummaryTest(): void {
  const reasoningEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-think-1",
    step_index: 20,
    event_type: "INFO_NOTE",
    title: "Captured reasoning step",
    digest: {},
    details: { output: "Compare source agreement and provide concise answer." },
  };

  const systemEvent: AgentEvent = {
    ...baseEvent,
    event_id: "evt-think-2",
    step_index: 21,
    event_type: "INFO_NOTE",
    title: "System update: IntentResolver",
    digest: {},
    details: { output: "Need direct answer with UTC timestamp and citations." },
  };

  const presentation = buildRunPresentation([], [reasoningEvent, systemEvent], []);
  assert.ok(presentation.thoughtSummary);
  assert.equal(presentation.thoughtSummary?.agents.length, 2);
  assert.equal(
    presentation.thoughtSummary?.agents[0]?.notes[0],
    "Compare source agreement and provide concise answer.",
  );
}

classifyEventTest();
normalizeOutputTest();
dedupAndAnswerTest();
activitySummaryTest();
sourceSummaryTest();
sourceSummaryReceiptOnlyTest();
thoughtSummaryTest();
