import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioAgentTurnRecoveryHelpers } = require("./agent-turn-recovery.js");

function helpers({ resultText = "" } = {}) {
  return createStudioAgentTurnRecoveryHelpers({
    collectStudioAgentEventsFromResponse: (turn = {}) => Array.isArray(turn.events) ? turn.events : [],
    firstArray: (value) => Array.isArray(value) ? value : [],
    stringValue: (value, fallback = "") => {
      if (typeof value !== "string") return fallback;
      const trimmed = value.trim();
      return trimmed || fallback;
    },
    studioAgentTurnResultText: () => resultText,
    studioRuntimeEventIsRunningStepCompletion: (event) => event.kind === "running.step.completed",
    studioRuntimeEventKind: (event = {}) => event.kind || event.event_kind || event.eventKind || "",
  });
}

test("agent turn recovery helpers extract prompts from direct, conversation, and started events", () => {
  const studio = helpers();

  assert.equal(studio.studioTurnPromptText({ request: { input: "direct request" } }), "direct request");
  assert.equal(studio.studioTurnPromptText({
    conversation: [
      { role: "assistant", content: "answer" },
      { role: "user", content: "latest user prompt" },
    ],
  }), "latest user prompt");
  assert.equal(studio.studioTurnPromptText({
    events: [{ event_kind: "turn.started", payload_summary: { prompt: "event prompt" } }],
  }), "event prompt");
});

test("agent turn recovery helpers match submitted prompts and timestamps", () => {
  const studio = helpers();
  const submittedAtMs = Date.parse("2026-06-04T12:00:00.000Z");

  assert.equal(studio.studioTurnStartedAtMs({ started_at_ms: submittedAtMs }), submittedAtMs);
  assert.equal(studio.studioTurnStartedAtMs({ createdAt: "2026-06-04T12:00:01.000Z" }), submittedAtMs + 1000);
  assert.equal(studio.studioTurnMatchesSubmittedPrompt({ prompt: "same" }, "same", submittedAtMs), true);
  assert.equal(studio.studioTurnMatchesSubmittedPrompt({ startedAtMs: submittedAtMs - 1000 }, "different", submittedAtMs), true);
  assert.equal(studio.studioTurnMatchesSubmittedPrompt({ startedAtMs: submittedAtMs - 3000 }, "different", submittedAtMs), false);
});

test("agent turn recovery helpers classify terminal turn projections", () => {
  assert.equal(helpers({ resultText: "done" }).studioTurnLooksTerminal({ events: [] }), true);
  assert.equal(helpers().studioTurnLooksTerminal({ status: "waiting_for_approval", events: [] }), true);
  assert.equal(helpers().studioTurnLooksTerminal({ events: [{ event_kind: "turn.completed" }] }), true);
  assert.equal(helpers().studioTurnLooksTerminal({
    status: "completed",
    events: [{ kind: "running.step.completed" }],
  }), false);
});
