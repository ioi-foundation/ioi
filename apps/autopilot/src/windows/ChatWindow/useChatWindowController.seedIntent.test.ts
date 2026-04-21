import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import assert from "node:assert/strict";

const source = readFileSync(
  resolve("src/windows/ChatWindow/useChatWindowController.ts"),
  "utf8",
);

assert.match(
  source,
  /const claimedLaunch = await ackPendingChatLaunchRequest\(launchId\);[\s\S]*if \(!claimedLaunch\) \{[\s\S]*reason: "launch_already_claimed"/,
  "chat launch controller should claim the pending launch before applying it",
);

assert.doesNotMatch(
  source,
  /case "autopilot-intent":[\s\S]*openAutopilotWithIntent[\s\S]*await ackPendingChatLaunchRequest\(launchId\);/,
  "autopilot-intent branch should not ack after applying; the claim should happen up front",
);

assert.match(
  source,
  /function waitForChatAutopilotSurfaceFrame\(\): Promise<void> \{[\s\S]*const timeoutId = window\.setTimeout\(finish, 48\);[\s\S]*window\.requestAnimationFrame\(\(\) => \{[\s\S]*window\.clearTimeout\(timeoutId\);[\s\S]*finish\(\);[\s\S]*\}\);[\s\S]*\}/,
  "chat launch controller should wait for a frame when available but fail open quickly if the webview does not paint before replaying a retained follow-up intent",
);

assert.match(
  source,
  /case "autopilot-intent":[\s\S]*if \(pendingRequest\.sessionId\) \{[\s\S]*await bootstrapAgentSession\(\{\s*refreshCurrentTask: false,\s*\}\);[\s\S]*setActiveView\("chat"\);[\s\S]*await waitForChatAutopilotSurfaceFrame\(\);[\s\S]*await invoke\(\"continue_task\", \{\s*sessionId: pendingRequest\.sessionId,\s*userInput: pendingRequest\.intent,\s*\}\);[\s\S]*void openSessionTarget\(pendingRequest\.sessionId\)\.catch\(\(error\) => \{[\s\S]*submissionMode: "direct_continue_task"[\s\S]*return;[\s\S]*\}[\s\S]*openAutopilotWithIntent\(pendingRequest\.intent\);[\s\S]*submissionMode: "seed_intent"/,
  "autopilot-intent launch requests should submit retained follow-ups directly before reopening the UI session, while fresh launches still flow through the seed-intent path",
);

console.log("useChatWindowController.seedIntent.test.ts: ok");
