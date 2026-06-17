import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(
  resolve(__dirname, "useHypervisorShellController.ts"),
  "utf8",
);
const mainSource = readFileSync(
  resolve(__dirname, "../../main.tsx"),
  "utf8",
);
assert.match(
  source,
  /const claimedLaunch = await ackPendingChatLaunchRequest\(launchId\);[\s\S]*if \(!claimedLaunch\) \{[\s\S]*reason: "launch_already_claimed"/,
  "chat launch controller should claim the pending launch before applying it",
);

assert.doesNotMatch(
  source,
  /case "hypervisor-intent":[\s\S]*openHypervisorSessionWithIntent[\s\S]*await ackPendingChatLaunchRequest\(launchId\);/,
  "hypervisor-intent branch should not ack after applying; the claim should happen up front",
);

assert.match(
  source,
  /function waitForChatHypervisorSurfaceFrame\(\): Promise<void> \{[\s\S]*const timeoutId = window\.setTimeout\(finish, 48\);[\s\S]*window\.requestAnimationFrame\(\(\) => \{[\s\S]*window\.clearTimeout\(timeoutId\);[\s\S]*finish\(\);[\s\S]*\}\);[\s\S]*\}/,
  "chat launch controller should wait for a frame when available but fail open quickly if the webview does not paint before replaying a retained follow-up intent",
);

assert.match(
  source,
  /const pathname = window\.location\.pathname\.toLowerCase\(\);[\s\S]*pathname === "\/sessions" \|\| pathname\.startsWith\("\/sessions\/"\)[\s\S]*return "sessions";/,
  "the dedicated /sessions route should boot into the Sessions surface before pending-launch hydration runs",
);

assert.match(
  source,
  /case "hypervisor-intent":[\s\S]*if \(pendingRequest\.sessionId\) \{[\s\S]*await bootstrapHypervisorSession\(\{\s*refreshCurrentTask: false,\s*\}\);[\s\S]*setActiveView\("sessions"\);[\s\S]*await waitForChatHypervisorSurfaceFrame\(\);[\s\S]*await invoke\(\"continue_task\", \{\s*sessionId: pendingRequest\.sessionId,\s*userInput: pendingRequest\.intent,\s*\}\);[\s\S]*void openSessionTarget\(pendingRequest\.sessionId\)\.catch\(\(error\) => \{[\s\S]*submissionMode: "direct_continue_task"[\s\S]*return;[\s\S]*\}[\s\S]*openHypervisorSessionWithIntent\(pendingRequest\.intent\);[\s\S]*submissionMode: "seed_intent"/,
  "hypervisor-intent launch requests should submit retained follow-ups directly before reopening the UI session, while fresh launches still flow through the seed-intent path",
);

assert.match(
  source,
  /if \(isHypervisorSurfaceId\(view\)\) \{[\s\S]*setActiveView\(view\);[\s\S]*if \(view === "automations"\) \{[\s\S]*setWorkflowSurface\("canvas"\);/,
  "workspace bridge view launch targets should accept canonical Hypervisor surfaces directly",
);

assert.match(
  source,
  /candidate\.source\?\.serviceName === "Hypervisor" &&[\s\S]*candidate\.source\.workflowName === "workflow" &&[\s\S]*\(candidate\.sessionId \|\| candidate\.threadId\)[\s\S]*return;/,
  "chat-bound Hypervisor workflow notifications should stay in the Chat UX instead of opening separate pill/native notification surfaces",
);

assert.match(
  mainSource,
  /<Route path="\/sessions" element=\{<HypervisorShellWindow \/>\} \/>/,
  "the canonical /sessions route should render the Hypervisor shell",
);

assert.match(
  mainSource,
  /<Route path="\/chat-session" element=\{<LegacyChatSessionRedirect \/>\} \/>/,
  "the legacy /chat-session route should close the secondary composer instead of rendering a second surface",
);

assert.match(
  mainSource,
  /<Route path="\/pill" element=\{<DisabledPillRoute \/>\} \/>/,
  "the pill route should be disabled so the ready-card window cannot become an operator surface",
);

assert.doesNotMatch(
  mainSource,
  /import \{ PillWindow \}|<PillWindow/,
  "the pill React component must not be routed as an active window",
);

console.log("useHypervisorShellController.seedIntent.test.ts: ok");
