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

test("home dashboard uses the IOI reference application shell", () => {
  assert.match(homeView, /aria-label="Hypervisor home"/);
  assert.match(homeView, /data-home-dashboard-variant="ioi-reference-home"/);
  assert.match(homeView, /chat-home-zero--ioi-enterprise/);
  assert.match(homeView, /Welcome back, Operator/);
  assert.match(homeView, /Search for anything in Hypervisor/);
  assert.match(homeView, /Get started/);
  assert.match(homeView, /Install examples/);
  assert.match(homeView, /Join Developer Community/);
  assert.match(homeView, /Recommended applications/);
  assert.match(homeView, /Projects & files/);
  assert.match(homeView, /Pipeline Builder/);
  assert.match(homeView, /Workbench/);
  assert.match(homeView, /Agents/);
  assert.match(homeView, /Models/);
  assert.match(homeView, /Authority/);
  assert.match(homeView, /Receipts/);
  assert.doesNotMatch(homeView, /What do you want to get done today\?/);
  assert.doesNotMatch(homeView, /className="chat-home-zero-prompt-stage"/);
  assert.doesNotMatch(homeView, /className="chat-home-zero-composer"/);
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

test("home dashboard exposes the reference-style application workplane", () => {
  assert.match(homeView, /const showDashboard = !reviewingCompletedSetup;/);
  assert.doesNotMatch(homeView, /const showDashboard = allStepsComplete && !reviewingCompletedSetup;/);
  assert.doesNotMatch(homeView, /HYPERVISOR_NEW_SESSION_SETUP_MODEL/);
  assert.doesNotMatch(homeView, /data-home-intent-composer/);
  assert.doesNotMatch(homeView, /Describe your task or type \/ for commands/);
  assert.doesNotMatch(homeView, /data-home-intent-project/);
  assert.doesNotMatch(homeView, /data-home-intent-model/);
  assert.doesNotMatch(homeView, /data-home-intent-submit/);
  assert.doesNotMatch(homeView, /HOME_INTENT_QUICKSTARTS/);
  assert.match(homeView, /HOME_REFERENCE_ACTIONS/);
  assert.match(homeView, /HOME_REFERENCE_APPS/);
  assert.match(homeView, /chat-home-zero-actions/);
  assert.match(homeView, /chat-home-zero-search/);
  assert.match(homeView, /chat-home-zero-body/);
  assert.match(homeView, /chat-home-zero-sidebar/);
  assert.match(homeView, /chat-home-zero-app-grid/);
  assert.match(homeView, /data-home-start-session/);
  assert.match(homeView, /onOpenCommandPalette/);
  assert.match(homeView, /onOpenCockpitSurface/);
  assert.match(homeView, /onSelectProject/);
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
  assert.match(homeCss, /\.chat-home-zero-actions \{/);
  assert.match(homeCss, /\.chat-home-zero-table \{/);
  assert.match(homeCss, /\.chat-home-zero-side-card \{/);
  assert.match(homeCss, /\.chat-home-zero-app-grid \{/);
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

test("home application shell has responsive reference styling", () => {
  assert.match(homeCss, /\.chat-home-zero-shell\s*\{/);
  assert.match(homeCss, /\.chat-home-zero::before\s*\{[\s\S]*height: 500px;[\s\S]*linear-gradient\(30deg/);
  assert.match(homeCss, /\.chat-home-zero-brand-mark__glyph\s*\{[\s\S]*border-bottom-color: rgba\(37, 99, 235, 0\.58\)/);
  assert.match(homeCss, /\.chat-home-zero-actions\s*\{/);
  assert.match(homeCss, /\.chat-home-zero-body\s*\{/);
  assert.match(
    homeCss,
    /@media \(max-width: 1200px\)[\s\S]*\.chat-home-zero-actions/,
  );
});

console.log("HomeView.hypervisorHome.test.mjs: ok");
