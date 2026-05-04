import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(
  resolve(__dirname, "useAutopilotShellController.ts"),
  "utf8",
);
const mainSource = readFileSync(
  resolve(__dirname, "../../main.tsx"),
  "utf8",
);
const tauriLibSource = readFileSync(
  resolve(__dirname, "../../../src-tauri/src/lib.rs"),
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
  /const pathname = window\.location\.pathname\.toLowerCase\(\);[\s\S]*pathname === "\/chat" \|\| pathname\.startsWith\("\/chat\/"\)[\s\S]*return "chat";/,
  "the dedicated Tauri /chat window should boot into the Chat view before pending-launch hydration runs",
);

assert.match(
  source,
  /case "autopilot-intent":[\s\S]*if \(pendingRequest\.sessionId\) \{[\s\S]*await bootstrapAgentSession\(\{\s*refreshCurrentTask: false,\s*\}\);[\s\S]*setActiveView\("chat"\);[\s\S]*await waitForChatAutopilotSurfaceFrame\(\);[\s\S]*await invoke\(\"continue_task\", \{\s*sessionId: pendingRequest\.sessionId,\s*userInput: pendingRequest\.intent,\s*\}\);[\s\S]*void openSessionTarget\(pendingRequest\.sessionId\)\.catch\(\(error\) => \{[\s\S]*submissionMode: "direct_continue_task"[\s\S]*return;[\s\S]*\}[\s\S]*openAutopilotWithIntent\(pendingRequest\.intent\);[\s\S]*submissionMode: "seed_intent"/,
  "autopilot-intent launch requests should submit retained follow-ups directly before reopening the UI session, while fresh launches still flow through the seed-intent path",
);

assert.match(
  source,
  /case "workflows":[\s\S]*setActiveView\("workflows"\);[\s\S]*case "runs":[\s\S]*setActiveView\("runs"\);[\s\S]*case "inbox":[\s\S]*setActiveView\("inbox"\);[\s\S]*case "policy":[\s\S]*setActiveView\("policy"\);/,
  "workspace bridge view launch targets should include canonical Chat view names, not only legacy aliases",
);

assert.match(
  source,
  /candidate\.source\?\.serviceName === "Autopilot" &&[\s\S]*candidate\.source\.workflowName === "workflow" &&[\s\S]*\(candidate\.sessionId \|\| candidate\.threadId\)[\s\S]*return;/,
  "chat-bound Autopilot workflow notifications should stay in the Chat UX instead of opening separate pill/native notification surfaces",
);

assert.match(
  mainSource,
  /<Route path="\/chat-session" element=\{<LegacyChatSessionRedirect \/>\} \/>/,
  "the legacy /chat-session route should redirect to the primary /chat surface instead of rendering a second composer",
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

assert.doesNotMatch(
  tauriLibSource,
  /Show Pill|\"pill\" => windows::show_pill/,
  "native tray/menu routing should not expose the deprecated pill surface",
);

console.log("useAutopilotShellController.seedIntent.test.ts: ok");
