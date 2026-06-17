import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioTurnPolicy } = require("./turn-policy.js");

function createPolicy({ requiresRetrieval = false } = {}) {
  return createStudioTurnPolicy({
    firstArray: (value) => Array.isArray(value) ? value : [],
    humanizeStudioToolName: (toolName) => toolName === "file__read" ? "File Read" : String(toolName || "Tool"),
    stringValue: (value, fallback = "") => {
      if (typeof value !== "string") return fallback;
      const trimmed = value.trim();
      return trimmed || fallback;
    },
    studioIntentFramePayload: (frame) => frame?.payload || frame || {},
    studioIntentFrameRequiresRetrieval: () => requiresRetrieval,
    studioRuntimeEventsIncludeCompletedTool: (events, pattern) =>
      events.some((event) => /^tool\.(completed|result)$/i.test(event.kind || "") && pattern.test(event.toolName || "")),
    studioRuntimeEventToolName: (event = {}) => event.toolName || event.tool_name || "",
    uniqueStrings: (values) => [...new Set(values.filter(Boolean).map(String))],
  });
}

test("turn policy chooses max steps from retrieval and workspace intent", () => {
  assert.equal(createPolicy({ requiresRetrieval: true }).studioAgentMaxStepsForIntent({}, "simple prompt"), 24);

  const policy = createPolicy();
  assert.equal(policy.studioAgentMaxStepsForIntent({}, "latest current market sources"), 24);
  assert.equal(policy.studioAgentMaxStepsForIntent({}, "refactor packages/runtime-daemon tests"), 16);
  assert.equal(policy.studioAgentMaxStepsForIntent({}, "say hello"), 12);
});

test("turn policy shapes retrieval and approval pause product copy", () => {
  const policy = createPolicy();
  const searchEvents = [{ kind: "tool.completed", toolName: "web__search" }];
  const fileEvents = [{ kind: "tool.started", toolName: "file__read" }];

  assert.equal(policy.studioRetrievalFailClosedText({ events: [] }), "");
  assert.match(policy.studioRetrievalFailClosedText({ events: searchEvents }), /Details are in Tracing/);
  assert.equal(policy.studioResultTextLooksRetrievalGrounded("Fresh evidence with citations:"), true);
  assert.equal(policy.studioTextIndicatesApprovalPause("Approval required before continuing."), true);
  assert.match(policy.studioApprovalPauseErrorMessage({ resultText: "paused", events: fileEvents }), /File Read/);
  const error = policy.studioApprovalPauseError({ events: fileEvents });
  assert.equal(error.code, "studio_approval_pause");
  assert.equal(error.studioApprovalPause, true);
});

test("turn policy reports policy-blocked file reads without exposing contents", () => {
  const policy = createPolicy();
  const blocked = policy.studioPolicyBlockedRuntimeMessage({
    prompt: "read `/secret/file.txt`",
    resultText: "Blocked by Policy: file__read ignored workspace files are protected",
    events: [{ summary: "Blocked by Policy", toolName: "file__read" }],
  });

  assert.match(blocked, /blocked the file read for `\/secret\/file\.txt`/);
  assert.match(blocked, /ignored workspace files are protected/);
  assert.match(blocked, /I did not expose the file contents/);

  assert.equal(policy.studioPolicyBlockedRuntimeMessage({
    resultText: "Blocked by Policy: shell__run",
    events: [{ toolName: "shell__run" }],
  }), "");
});
