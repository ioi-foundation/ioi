import assert from "node:assert/strict";

import {
  extractUserRequestFromContextualIntent,
  humanizeOperationalTranscriptText,
} from "./contextualIntent";

assert.equal(
  extractUserRequestFromContextualIntent(
    "[Codebase context]\nWorkspace: .\n\n[User request]\nCreate an interactive HTML artifact that explains quantum computers",
  ),
  "Create an interactive HTML artifact that explains quantum computers",
);

assert.equal(
  extractUserRequestFromContextualIntent("Create a chart"),
  "Create a chart",
);

assert.equal(
  extractUserRequestFromContextualIntent(
    "TOOLCAT_SINGLE_TOOL toolcat_tool=file__read workspace_fixture_readme=/tmp/toolcat/readme.md",
  ),
  "Run live Rust tool catalogue verification for file read.",
);

assert.equal(
  humanizeOperationalTranscriptText(
    "TOOLCAT_SINGLE_TOOL file__read live IDE probe reached the post-tool final reply path.",
    "assistant",
  ),
  "The live Rust tool catalogue probe completed for file read.",
);

assert.equal(
  humanizeOperationalTranscriptText(
    "TOOLCAT_SINGLE_TOOL agent__await live IDE probe failed; concrete trace failure recorded.",
    "assistant",
  ),
  "The live Rust tool catalogue probe failed for agent await. Details are in Tracing.",
);

console.log("contextualIntent.test.ts: ok");
