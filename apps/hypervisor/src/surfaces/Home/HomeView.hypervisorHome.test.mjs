import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const homeView = readFileSync(
  new URL("./HomeView.tsx", import.meta.url),
  "utf8",
);
const homeCss = readFileSync(new URL("./Home.css", import.meta.url), "utf8");
const homeIndex = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const homeOnboardingModel = readFileSync(
  new URL("./homeOnboardingModel.ts", import.meta.url),
  "utf8",
);
const homeWalkthroughDocument = readFileSync(
  new URL("./HomeWalkthroughDocument.tsx", import.meta.url),
  "utf8",
);
const shellContent = readFileSync(
  new URL(
    "../../windows/HypervisorShellWindow/components/HypervisorShellContent.tsx",
    import.meta.url,
  ),
  "utf8",
);

test("home dashboard uses the IOI reference prompt shell", () => {
  assert.match(homeView, /aria-label="Hypervisor home"/);
  assert.match(homeView, /data-home-dashboard-variant="ioi-reference-home"/);
  assert.match(homeView, /What do you want to get done today\?/);
  assert.match(homeView, /className="chat-home-zero-prompt-stage"/);
  assert.match(homeView, /className="chat-home-zero-composer"/);
  assert.match(homeView, /Describe your task or type \/ for commands/);
  assert.match(homeView, /Work in a project/);
  assert.match(homeView, /Local model/);
  assert.match(homeView, /Automate env setup/);
  assert.match(homeView, /Fix a bug/);
  assert.match(homeView, /Boost your test coverage/);
  assert.match(homeView, /chat-home-zero-prompt-tick/);
  assert.doesNotMatch(homeView, /HOME_REFERENCE_RECENT_SESSIONS/);
  assert.doesNotMatch(homeView, /Recent Sessions/);
  assert.doesNotMatch(homeView, /Welcome back to Autopilot/);
  assert.doesNotMatch(homeView, /Search Autopilot, code, sessions, and commands/);
});

test("home onboarding uses Hypervisor and Workbench adapter language", () => {
  const homeSource = [
    homeView,
    homeIndex,
    homeOnboardingModel,
    homeWalkthroughDocument,
  ].join("\n");
  assert.match(homeSource, /HYPERVISOR_ONBOARDING_FAMILIES/);
  assert.match(homeSource, /HypervisorOnboardingStep/);
  assert.match(homeSource, /Get Started with Hypervisor/);
  assert.match(homeSource, /governed Workbench adapter/);
  assert.match(homeSource, /Workbench adapter/);
  assert.doesNotMatch(homeSource, /AUTOPILOT_ONBOARDING/);
  assert.doesNotMatch(homeSource, /AutopilotOnboarding/);
  assert.doesNotMatch(homeSource, /autopilot\.home\.onboarding/);
  assert.doesNotMatch(homeSource, /autopilot\.onboarding/);
  assert.doesNotMatch(homeSource, /OpenVSCode/);
  assert.doesNotMatch(homeSource, /contained OpenVSCode/);
});

test("home dashboard exposes the reference-style prompt workplane", () => {
  assert.match(homeView, /const showDashboard = !reviewingCompletedSetup;/);
  assert.doesNotMatch(homeView, /const showDashboard = allStepsComplete && !reviewingCompletedSetup;/);
  assert.doesNotMatch(homeView, /HYPERVISOR_NEW_SESSION_SETUP_MODEL/);
  assert.doesNotMatch(homeView, /data-home-intent-composer/);
  assert.match(homeView, /Describe your task or type \/ for commands/);
  assert.doesNotMatch(homeView, /data-home-intent-project/);
  assert.doesNotMatch(homeView, /data-home-intent-model/);
  assert.doesNotMatch(homeView, /data-home-intent-submit/);
  assert.doesNotMatch(homeView, /HOME_INTENT_QUICKSTARTS/);
  assert.doesNotMatch(homeView, /HOME_REFERENCE_RECENT_SESSIONS/);
  assert.match(homeView, /chat-home-zero-prompt-logo/);
  assert.match(homeView, /chat-home-zero-prompt-tick/);
  assert.doesNotMatch(homeView, /chat-home-zero-recent-sessions/);
  assert.doesNotMatch(homeView, /HOME_REFERENCE_RECENT_FILES/);
  assert.doesNotMatch(homeView, /HOME_REFERENCE_ACTIONS/);
  assert.doesNotMatch(homeView, /HOME_REFERENCE_TEMPLATES/);
  assert.match(homeView, /HOME_REFERENCE_PROMPTS/);
  assert.doesNotMatch(homeView, /Total Sessions/);
  assert.doesNotMatch(homeView, /Workspaces/);
  assert.doesNotMatch(homeView, /Approvals/);
  assert.doesNotMatch(homeView, /Scope: All/);
  assert.doesNotMatch(homeView, /Sort: Recently opened/);
  assert.doesNotMatch(homeView, /Build governed workspace runtime/);
  assert.doesNotMatch(homeView, /Configure editor adapter bridge/);
  assert.doesNotMatch(homeView, /Review model mount receipts/);
  assert.doesNotMatch(homeView, /No recently viewed files/);
  assert.doesNotMatch(homeView, /Projects & files/);
  assert.doesNotMatch(homeView, /Data Connection/);
  assert.doesNotMatch(homeView, /Pipeline Builder/);
  assert.doesNotMatch(homeView, /Contour/);
  assert.doesNotMatch(homeView, /Ontology Manager/);
  assert.doesNotMatch(homeView, /AIP Logic/);
  assert.doesNotMatch(homeView, /Code Repositories/);
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
  assert.match(homeCss, /Phase 0A hard cut: Home mirrors the IOI reference prompt surface/);
  assert.match(homeCss, /\.chat-home-zero--ioi-reference \.chat-home-zero-prompt-stage \{[\s\S]*width: min\(728px/);
  assert.match(homeCss, /\.chat-home-zero--ioi-reference \.chat-home-zero-prompt-logo \{/);
  assert.match(homeCss, /\.chat-home-zero--ioi-reference \.chat-home-zero-prompt-tick \{/);
  assert.match(homeCss, /\.chat-home-zero--ioi-reference \.chat-home-zero-composer \{[\s\S]*min-height: 174px/);
  assert.match(homeCss, /\.chat-home-zero--ioi-reference \.chat-home-zero-prompt-chips \{/);
  assert.match(homeCss, /\.chat-main:has\(\.chat-home-zero--ioi-reference\),/);
  assert.doesNotMatch(homeCss, /Phase 0A hard cut: default Home mirrors the IOI portal/);
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

test("home prompt has responsive reference styling", () => {
  assert.match(homeCss, /\.chat-home-zero--ioi-reference \.chat-home-zero-prompt-stage\s*\{/);
  assert.match(homeCss, /\.chat-home-zero--ioi-reference \.chat-home-zero-composer\s*\{/);
  assert.match(homeCss, /\.chat-home-zero--ioi-reference \.chat-home-zero-prompt-chips\s*\{/);
  assert.match(
    homeCss,
    /@media \(max-width: 820px\)[\s\S]*\.chat-home-zero--ioi-reference \.chat-home-zero-prompt-stage/,
  );
});

console.log("HomeView.hypervisorHome.test.mjs: ok");
