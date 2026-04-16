import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import assert from "node:assert/strict";

const source = readFileSync(
  resolve("src/windows/StudioWindow/useStudioWindowController.ts"),
  "utf8",
);

assert.match(
  source,
  /const claimedLaunch = await ackPendingStudioLaunchRequest\(launchId\);[\s\S]*if \(!claimedLaunch\) \{[\s\S]*reason: "launch_already_claimed"/,
  "studio launch controller should claim the pending launch before applying it",
);

assert.doesNotMatch(
  source,
  /case "autopilot-intent":[\s\S]*openAutopilotWithIntent[\s\S]*await ackPendingStudioLaunchRequest\(launchId\);/,
  "autopilot-intent branch should not ack after applying; the claim should happen up front",
);

assert.match(
  source,
  /case "autopilot-intent":[\s\S]*if \(pendingRequest\.sessionId\) \{[\s\S]*await openSessionTarget\(pendingRequest\.sessionId\);[\s\S]*openAutopilotWithIntent\(pendingRequest\.intent\);/,
  "autopilot-intent launch requests should attach an explicit session target before seeding the follow-up intent",
);

console.log("useStudioWindowController.seedIntent.test.ts: ok");
