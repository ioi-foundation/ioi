import assert from "node:assert/strict";
import fs from "node:fs";

const hookSource = fs.readFileSync(
  new URL("./useChatSession.ts", import.meta.url),
  "utf8",
);

assert.match(
  hookSource,
  /export function shouldContinueChatComposerSession\([\s\S]*forceNewSession = false[\s\S]*if \(forceNewSession\) \{\s*return false;\s*\}[\s\S]*if \(!task\?\.id \|\| task\.phase === "Failed"\) \{\s*return false;\s*\}[\s\S]*if \(isChatVariant && task\.phase === "Complete"\) \{\s*[\s\S]*return true;\s*\}[\s\S]*return true;/,
  "Chat should keep completed outcomes attachable so follow-up submits can reuse retained context until the user explicitly starts a new outcome",
);

assert.match(
  hookSource,
  /forceNextSubmitToStartSessionRef\.current = true;[\s\S]*handleComposerNewChat\(\);/,
  "Explicit New Session should latch the next submit onto a fresh runtime task even if projection recovery rehydrates the previous turn",
);

assert.match(
  hookSource,
  /shouldContinueExistingSession: \(currentTask\) =>\s*shouldContinueChatComposerSession\(\s*isChatVariant,\s*currentTask,\s*forceNextSubmitToStartSessionRef\.current,\s*\)/,
  "Chat should pass the explicit fresh-session latch into the shared composer",
);

console.log("useChatSession.test.ts: ok");
