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
  /const claimedLaunch = await ackPendingHypervisorLaunchRequest\(launchId\);[\s\S]*if \(!claimedLaunch\) \{[\s\S]*reason: "launch_already_claimed"/,
  "Hypervisor launch controller should claim the pending launch before applying it",
);

assert.doesNotMatch(
  source,
  /case "hypervisor-intent":[\s\S]*openHypervisorSessionWithIntent[\s\S]*await ackPendingHypervisorLaunchRequest\(launchId\);/,
  "hypervisor-intent branch should not ack after applying; the claim should happen up front",
);

assert.match(
  source,
  /function waitForHypervisorSurfaceFrame\(\): Promise<void> \{[\s\S]*const timeoutId = window\.setTimeout\(finish, 48\);[\s\S]*window\.requestAnimationFrame\(\(\) => \{[\s\S]*window\.clearTimeout\(timeoutId\);[\s\S]*finish\(\);[\s\S]*\}\);[\s\S]*\}/,
  "Hypervisor launch controller should wait for a frame when available but fail open quickly if the webview does not paint before replaying a retained follow-up intent",
);

assert.match(
  source,
  /function resolvePathnamePrimaryView\(pathname: string\): PrimaryView \| null \{[\s\S]*segment === "ai"[\s\S]*return "home";[\s\S]*segment === "workspaces" \|\| segment === "details" \|\| segment === "logs"[\s\S]*return "sessions";[\s\S]*isSupportedInitialPrimaryView\(segment\) \? segment : null;/,
  "canonical Hypervisor paths should boot into their owning surface before pending-launch hydration runs",
);

assert.match(
  source,
  /function resolveInitialSettingsSectionSeed\(\): SettingsSection \| null \{[\s\S]*params\.get\("user-settings"\)[\s\S]*params\.get\("settings"\)[\s\S]*resolveInitialPrimaryView[\s\S]*if \(resolveInitialSettingsSectionSeed\(\)\) \{[\s\S]*return "settings";/,
  "IOI-reference settings deep links should boot into Settings with a seeded section",
);

for (const route of [
  "/workspaces",
  "/sessions",
  "/details/:sessionId",
  "/details/:sessionId/logs",
  "/projects",
  "/automations",
  "/insights",
  "/models",
  "/providers",
]) {
  assert.match(
    mainSource,
    new RegExp(`"${route.replace("/", "\\/")}"`),
    `${route} should be an explicit Hypervisor product route`,
  );
}

assert.doesNotMatch(
  source,
  /pathname === "\/sessions" \|\| pathname\.startsWith\("\/sessions\/"\)/,
  "surface routing should not preserve the old /sessions-only boot special case",
);

assert.match(
  source,
  /case "hypervisor-intent":[\s\S]*if \(pendingRequest\.sessionId\) \{[\s\S]*await bootstrapHypervisorSession\(\{\s*refreshCurrentTask: false,\s*\}\);[\s\S]*setActiveView\("sessions"\);[\s\S]*await waitForHypervisorSurfaceFrame\(\);[\s\S]*await invoke\(\"continue_task\", \{\s*sessionId: pendingRequest\.sessionId,\s*userInput: pendingRequest\.intent,\s*\}\);[\s\S]*void openSessionTarget\(pendingRequest\.sessionId\)\.catch\(\(error\) => \{[\s\S]*submissionMode: "direct_continue_task"[\s\S]*return;[\s\S]*\}[\s\S]*openHypervisorSessionWithIntent\(pendingRequest\.intent\);[\s\S]*submissionMode: "seed_intent"/,
  "hypervisor-intent launch requests should submit retained follow-ups directly before reopening the UI session, while fresh launches still flow through the seed-intent path",
);

assert.match(
  source,
  /if \(isHypervisorSurfaceId\(view\)\) \{[\s\S]*setActiveView\(view\);[\s\S]*return;/,
  "Hypervisor surface launch targets should accept canonical Hypervisor surfaces directly",
);

assert.doesNotMatch(
  source,
  /setWorkflowSurface|WorkflowSurface/,
  "Automations should no longer retain hidden workflow home/agents/catalog subroutes",
);

assert.match(
  source,
  /candidate\.source\?\.serviceName === "Hypervisor" &&[\s\S]*candidate\.source\.workflowName === "workflow" &&[\s\S]*\(candidate\.sessionId \|\| candidate\.threadId\)[\s\S]*return;/,
  "Hypervisor workflow notifications should stay in the shell instead of opening separate pill/native notification surfaces",
);

console.log("useHypervisorShellController.seedIntent.test.ts: ok");
