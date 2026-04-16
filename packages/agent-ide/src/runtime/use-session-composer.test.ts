import assert from "node:assert/strict";

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

console.log("use-session-composer.test.ts: ok");
