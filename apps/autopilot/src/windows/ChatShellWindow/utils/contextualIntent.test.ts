import assert from "node:assert/strict";

import { extractUserRequestFromContextualIntent } from "./contextualIntent";

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

console.log("contextualIntent.test.ts: ok");
