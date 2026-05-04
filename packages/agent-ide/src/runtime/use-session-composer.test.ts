import assert from "node:assert/strict";
import fs from "node:fs";

import {
  defaultShouldContinueExistingSession,
  isSessionComposerSubmissionBlocked,
  waitForNextUiPaint,
} from "./use-session-composer.ts";

assert.equal(
  defaultShouldContinueExistingSession({
    id: "session-123",
    phase: "Complete",
  }),
  true,
  "default composer behavior should keep continuing completed sessions unless a shell overrides it",
);

assert.equal(
  defaultShouldContinueExistingSession({
    id: "session-123",
    phase: "Failed",
  }),
  false,
  "failed sessions should never accept implicit continuation",
);

assert.equal(
  isSessionComposerSubmissionBlocked({
    id: "session-123",
    phase: "Running",
  }),
  true,
  "running sessions should continue blocking duplicate submits",
);

assert.equal(
  isSessionComposerSubmissionBlocked({
    id: "session-123",
    phase: "Complete",
    current_step: "Waiting for sudo password",
  }),
  false,
  "stale current_step text must not block a completed chat turn without a typed credential request",
);

assert.equal(
  isSessionComposerSubmissionBlocked({
    id: "session-123",
    phase: "Complete",
    current_step: "Waiting for clarification",
  }),
  false,
  "stale current_step text must not block a completed chat turn without a typed clarification request",
);

assert.equal(
  isSessionComposerSubmissionBlocked({
    id: "session-123",
    phase: "Complete",
    credential_request: { kind: "sudo_password" },
  }),
  true,
  "typed credential requests must still block composer submission",
);

const originalWindow = globalThis.window;

globalThis.window = {
  requestAnimationFrame: () => 1,
} as unknown as typeof window;

const startedAt = Date.now();
await waitForNextUiPaint(10);
assert.ok(
  Date.now() - startedAt < 200,
  "waitForNextUiPaint should fall back to timeout when requestAnimationFrame does not fire",
);

if (originalWindow === undefined) {
  delete (globalThis as { window?: typeof window }).window;
} else {
  globalThis.window = originalWindow;
}

const source = fs.readFileSync(
  new URL("./use-session-composer.ts", import.meta.url),
  "utf8",
);

assert.match(
  source,
  /const handleNewSession = useCallback\(\(\) => \{[\s\S]*resetSession\(\);[\s\S]*setIntent\(""\);[\s\S]*setLocalHistory\(\[\]\);/,
  "New Session must clear the controlled composer value before the next submit",
);

assert.match(
  source,
  /if \(shouldContinueCurrentSession\) \{[\s\S]*setIntent\(""\);[\s\S]*setLocalHistory\(\(current\) => \[[\s\S]*defaultLocalHistoryMessage[\s\S]*await continueTask\(sessionId, text\);/,
  "Retained-session continuations must optimistically record the user turn before handing off to the runtime",
);

assert.match(
  source,
  /const focusComposer = \(\) => \{[\s\S]*inputRef\.current\.style\.height = "auto";[\s\S]*inputRef\.current\.focus\(\);[\s\S]*window\.requestAnimationFrame\(focusComposer\);[\s\S]*window\.setTimeout\(focusComposer, newSessionFocusDelayMs\);/,
  "New Session must synchronously schedule textarea reset/focus for retained-session shells",
);

console.log("use-session-composer.test.ts: ok");
