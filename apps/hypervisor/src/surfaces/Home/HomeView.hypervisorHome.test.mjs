import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const homeView = readFileSync(
  new URL("./HomeView.tsx", import.meta.url),
  "utf8",
);
const homeCss = readFileSync(new URL("./Home.css", import.meta.url), "utf8");
const homeIndex = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const shellContent = readFileSync(
  new URL(
    "../../windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    import.meta.url,
  ),
  "utf8",
);

test("home dashboard uses the IOI reference prompt surface", () => {
  assert.match(homeView, /aria-label="Hypervisor home"/);
  assert.match(homeView, /data-home-dashboard-variant="ioi-reference-home"/);
  assert.match(homeView, /hypervisor-home-prompt--ioi-reference/);
  assert.match(homeView, /What do you want to get done today\?/);
  assert.match(homeView, /Describe your task or type \/ for commands/);
  assert.match(homeView, /className="hypervisor-home-prompt__stage"/);
  assert.match(homeView, /className="hypervisor-home-prompt__composer"/);
  assert.match(homeView, /className="hypervisor-home-prompt__quickstarts"/);
  assert.match(homeView, /className="hypervisor-home-prompt__sessions"/);
  assert.match(homeView, /data-home-reference-session-list="true"/);
  assert.match(homeView, /recentSessions\.slice\(0, 3\)/);
  assert.match(homeView, /HOME_AGENT_PROMPTS/);
  assert.match(homeView, /data-home-intent-composer="ioi-reference"/);
  assert.match(homeView, /ProjectFocusIcon/);
  assert.match(homeView, /ModelGlyphIcon/);
  assert.match(homeView, /ArrowUpIcon/);
  assert.match(homeView, /ChevronDownIcon/);
  assert.match(homeView, /data-home-agent-prompt/);
  assert.doesNotMatch(homeView, /HOME_RECENT_SESSIONS/);
  assert.doesNotMatch(homeView, /data-home-recent-sessions/);
  assert.doesNotMatch(homeView, /Welcome back, Operator/);
  assert.doesNotMatch(homeView, /Search for anything in Hypervisor/);
  assert.doesNotMatch(homeView, /Get started/);
  assert.doesNotMatch(homeView, /Install examples/);
  assert.doesNotMatch(homeView, /Join Developer Community/);
  assert.doesNotMatch(homeView, /Recommended applications/);
  assert.doesNotMatch(homeView, /Sessions and workspaces/);
  assert.doesNotMatch(homeView, /What's new\?/);
  assert.doesNotMatch(homeView, /HOME_REFERENCE_SURFACES/);
  assert.doesNotMatch(homeView, /chat-home-zero/);
  assert.doesNotMatch(homeView, /chat-home/);
  assert.doesNotMatch(homeView, /hypervisor-home-prompt__workplane/);
  assert.doesNotMatch(homeView, /hypervisor-home-prompt__sidebar/);
  assert.doesNotMatch(homeView, /Welcome back to Autopilot/);
  assert.doesNotMatch(homeView, /Search Autopilot, code, sessions, and commands/);
  assert.doesNotMatch(homeView, />[^<]*(Daemon|runtime truth|configured workers)[^<]*</i);
});

test("home no longer ships a legacy onboarding walkthrough surface", () => {
  assert.equal(
    existsSync(new URL("./HomeWalkthroughDocument.tsx", import.meta.url)),
    false,
  );
  assert.equal(
    existsSync(new URL("./homeOnboardingModel.ts", import.meta.url)),
    false,
  );
  const homeSource = [homeView, homeIndex].join("\n");
  assert.doesNotMatch(homeSource, /AUTOPILOT_ONBOARDING/);
  assert.doesNotMatch(homeSource, /AutopilotOnboarding/);
  assert.doesNotMatch(homeSource, /autopilot\.home\.onboarding/);
  assert.doesNotMatch(homeSource, /autopilot\.onboarding/);
  assert.doesNotMatch(homeSource, /OpenVSCode/);
  assert.doesNotMatch(homeSource, /contained OpenVSCode/);
  assert.doesNotMatch(homeSource, /HomeWalkthroughDocument/);
  assert.doesNotMatch(homeSource, /homeOnboardingModel/);
});

test("home dashboard launches governed sessions from the reference prompt", () => {
  assert.doesNotMatch(homeView, /reviewingCompletedSetup/);
  assert.doesNotMatch(homeView, /const showDashboard = /);
  assert.doesNotMatch(homeView, /HYPERVISOR_NEW_SESSION_SETUP_MODEL/);
  assert.match(homeView, /data-home-intent-composer/);
  assert.match(homeView, /Describe your task or type \/ for commands/);
  assert.match(homeView, /data-home-intent-project/);
  assert.match(homeView, /data-home-intent-model/);
  assert.match(homeView, /Work in a project/);
  assert.match(homeView, /5\.5 Medium/);
  assert.doesNotMatch(homeView, />\s*\^\s*<\/button>/);
  assert.doesNotMatch(homeView, /data-home-intent-submit/);
  assert.doesNotMatch(homeView, /HOME_INTENT_QUICKSTARTS/);
  assert.doesNotMatch(homeView, /HOME_REFERENCE_SURFACES/);
  assert.doesNotMatch(homeView, /chat-home-zero/);
  assert.doesNotMatch(homeView, /chat-home/);
  assert.doesNotMatch(homeView, /hypervisor-home-prompt__reference-header/);
  assert.doesNotMatch(homeView, /hypervisor-home-prompt__workplane/);
  assert.doesNotMatch(homeView, /hypervisor-home-prompt__sidebar/);
  assert.doesNotMatch(homeView, /hypervisor-home-prompt__surface-list/);
  assert.match(homeView, /data-home-start-session/);
  assert.match(homeView, /data-home-reference-session-ref/);
  assert.match(homeView, /data-home-reference-session-state/);
  assert.match(homeView, /onOpenCommandPalette/);
  assert.doesNotMatch(homeView, /Scan recent commits for issues/);
  assert.doesNotMatch(homeView, /Draft weekly release notes/);
  assert.doesNotMatch(homeView, /Add optimized AGENTS\.md/);
  assert.doesNotMatch(homeView, /10x engineer/);
  assert.doesNotMatch(homeView, /data-home-new-session-contract/);
  assert.doesNotMatch(homeView, /newSessionRequiredSections/);
  assert.doesNotMatch(homeView, /newSessionHarnessOptions/);
  assert.doesNotMatch(homeView, /HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE/);
  assert.doesNotMatch(homeView, /data-home-harness-comparison-run/);
  assert.doesNotMatch(homeView, /Harness comparison preview/);
  assert.doesNotMatch(homeView, /buildHarnessCompatibilityVerdict/);
  assert.doesNotMatch(homeView, /getHarnessSelectionRef/);
  assert.match(homeView, /onOpenNewSession: \(seed\?: string \| HomeNewSessionSeed \| null\) => void/);
  assert.match(homeView, /seedIntent,/);
  assert.match(homeView, /recipeId: "ioi-reference-home"/);
  assert.doesNotMatch(homeView, /seedIntent: intentDraft/);
  assert.doesNotMatch(homeView, /recipeId: intentRecipeId/);
  assert.doesNotMatch(homeView, /Runtime status/);
  assert.match(
    shellContent,
    /onOpenNewSession=\{controller\.modals\.openNewSessionModal\}/,
  );
  assert.match(homeCss, /\.hypervisor-home-prompt__shell \{/);
  assert.match(homeCss, /\.hypervisor-home-prompt__stage \{/);
  assert.match(homeCss, /\.hypervisor-home-prompt__composer \{/);
  assert.match(homeCss, /\.hypervisor-home-prompt__quickstarts \{/);
  assert.match(homeCss, /\.hypervisor-home-prompt__sessions \{/);
  assert.match(homeCss, /\.hypervisor-home-prompt__session-rows button \{/);
  assert.doesNotMatch(homeCss, /\.chat-home/);
  assert.doesNotMatch(homeCss, /walkthrough/);
  assert.doesNotMatch(homeCss, /onboarding/);
  assert.doesNotMatch(homeCss, /dashboard-card/);
});

test("home default dashboard does not mount hidden legacy workplanes", () => {
  assert.doesNotMatch(homeView, /aria-label="Hypervisor cockpit status"/);
  assert.doesNotMatch(homeView, /data-home-cockpit-projection/);
  assert.doesNotMatch(homeView, /data-home-cockpit-source/);
  assert.doesNotMatch(homeView, /data-home-cockpit-metric/);
  assert.doesNotMatch(homeView, /data-home-cockpit-surface/);
  assert.doesNotMatch(homeView, /data-home-cockpit-drill-ref/);
  assert.doesNotMatch(homeView, /data-home-cockpit-drill-evidence/);
  assert.doesNotMatch(homeView, /data-home-cockpit-drill-surface/);
  assert.match(homeView, /onOpenCockpitSurface: \(surfaceRef: string\) => void/);
  assert.match(shellContent, /isHypervisorSurfaceId/);
  assert.match(shellContent, /surfaceRef\.replace\(\/\^surface:/);
  assert.match(shellContent, /controller\.changePrimaryView\(surfaceId\)/);
});

test("home dashboard routes model setup to the Models surface", () => {
  assert.match(homeView, /onOpenModels: \(\) => void/);
  assert.match(
    shellContent,
    /onOpenModels=\{\(\) =>[\s\S]*controller\.changePrimaryView\("models"\)/,
  );
});

test("home prompt shell has responsive reference styling", () => {
  assert.match(homeCss, /\.hypervisor-home-prompt__shell\s*\{/);
  assert.match(homeCss, /\.hypervisor-home-prompt::before\s*\{[\s\S]*content: none;[\s\S]*display: none;/);
  assert.match(homeCss, /\.hypervisor-home-prompt__brand\s*\{/);
  assert.match(homeCss, /\.hypervisor-home-prompt__controls\s*\{/);
  assert.match(homeCss, /\.hypervisor-home-prompt__icon\s*\{/);
  assert.match(homeCss, /\.hypervisor-home-prompt__icon--model\s*\{/);
  assert.match(homeCss, /\.hypervisor-home-prompt__submit\s*\{/);
  assert.doesNotMatch(homeCss, /linear-gradient\(30deg/);
  assert.doesNotMatch(homeCss, /\.chat-home/);
  assert.doesNotMatch(homeCss, /\.hypervisor-home-prompt__mark-glyph/);
});

console.log("HomeView.hypervisorHome.test.mjs: ok");
