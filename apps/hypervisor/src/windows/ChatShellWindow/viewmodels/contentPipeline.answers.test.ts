import assert from "node:assert/strict";

import { buildAnswerPresentation } from "./contentPipeline.answers.ts";

const directToolCall = buildAnswerPresentation({
  role: "agent",
  text: JSON.stringify({
    name: "chat__reply",
    arguments: {
      message:
        "TOOLCAT_SINGLE_TOOL file__read live IDE probe reached the post-tool final reply path.",
    },
  }),
  timestamp: Date.now(),
});

assert.equal(
  directToolCall.displayText,
  "The live Rust tool catalogue probe completed for file read.",
);
assert.doesNotMatch(directToolCall.displayText, /TOOLCAT_|chat__reply|\{|\}/);
assert.equal(directToolCall.copyText, directToolCall.displayText);

const failedToolCall = buildAnswerPresentation({
  role: "agent",
  text: JSON.stringify({
    name: "chat__reply",
    arguments: {
      message:
        "TOOLCAT_SINGLE_TOOL agent__await live IDE probe failed; concrete trace failure recorded.",
    },
  }),
  timestamp: Date.now(),
});

assert.equal(
  failedToolCall.displayText,
  "The live Rust tool catalogue probe failed for agent await. Details are in Tracing.",
);
assert.doesNotMatch(failedToolCall.displayText, /TOOLCAT_|chat__reply|\{|\}/);

console.log("contentPipeline.answers.test.ts: ok");
