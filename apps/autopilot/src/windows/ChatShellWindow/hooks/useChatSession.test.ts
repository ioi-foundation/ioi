import assert from "node:assert/strict";
import fs from "node:fs";

const hookSource = fs.readFileSync(
  new URL("./useChatSession.ts", import.meta.url),
  "utf8",
);

assert.match(
  hookSource,
  /export function shouldContinueChatComposerSession\([\s\S]*if \(!task\?\.id \|\| task\.phase === "Failed"\) \{\s*return false;\s*\}[\s\S]*if \(isStudioVariant && task\.phase === "Complete"\) \{\s*[\s\S]*return true;\s*\}[\s\S]*return true;/,
  "Chat should keep completed outcomes attachable so follow-up submits can reuse retained context until the user explicitly starts a new outcome",
);

assert.match(
  hookSource,
  /shouldContinueExistingSession: \(currentTask\) =>\s*shouldContinueChatComposerSession\(isStudioVariant, currentTask\)/,
  "Chat should pass the Chat-aware continuation guard into the shared composer",
);

console.log("useChatSession.test.ts: ok");
