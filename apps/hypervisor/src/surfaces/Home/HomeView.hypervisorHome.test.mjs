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
const homeCockpitModel = readFileSync(
  new URL("./homeCockpitModel.ts", import.meta.url),
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

test("home dashboard uses Hypervisor cockpit copy and search intent", () => {
  assert.match(homeView, /aria-label="Hypervisor home"/);
  assert.match(homeView, /Welcome back to Hypervisor/);
  assert.match(
    homeView,
    /Search Hypervisor, sessions, workbench, automations, and commands/,
  );
  assert.doesNotMatch(homeView, /Welcome back to Autopilot/);
  assert.doesNotMatch(
    homeView,
    /Search Autopilot, code, sessions, and commands/,
  );
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

test("home dashboard exposes the New Session setup contract", () => {
  assert.match(homeView, /const showDashboard = !reviewingCompletedSetup;/);
  assert.doesNotMatch(homeView, /const showDashboard = allStepsComplete && !reviewingCompletedSetup;/);
  assert.match(homeView, /HYPERVISOR_NEW_SESSION_SETUP_MODEL/);
  assert.match(homeView, /data-home-intent-composer="ioi-reference-primary"/);
  assert.match(homeView, /What do you want to get done today\?/);
  assert.match(homeView, /Describe your task or type \/ for commands/);
  assert.match(homeView, /data-home-intent-project/);
  assert.doesNotMatch(homeView, /data-home-intent-harness/);
  assert.match(homeView, /data-home-intent-model="default-model-route"/);
  assert.doesNotMatch(homeView, /data-home-intent-privacy="privacy:ctee-private-workspace"/);
  assert.match(homeView, /chat-home-zero-intent-composer__add-context/);
  assert.match(homeView, /data-home-intent-submit="new-session"/);
  assert.match(homeView, /HOME_INTENT_QUICKSTARTS/);
  assert.match(homeView, /data-home-intent-recipe=\{quickstart\.recipeId\}/);
  assert.match(homeView, /recipeId: "automation\.default"/);
  assert.match(homeView, /recipeId: "workbench\.default"/);
  assert.match(homeView, /recipeId: "foundry\.eval"/);
  assert.match(homeView, /HOME_REFERENCE_RECENT_SESSIONS/);
  assert.match(homeView, /data-home-reference-recent-sessions="true"/);
  assert.match(homeView, /Recent Sessions/);
  assert.match(homeView, /Write Parent Harness Evidence Boundary Doc/);
  assert.match(homeView, /data-home-new-session-contract="daemon-runtime"/);
  assert.match(homeView, /newSessionRequiredSections/);
  assert.match(homeView, /newSessionHarnessOptions/);
  assert.match(homeView, /HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE/);
  assert.match(homeView, /data-home-harness-comparison-run/);
  assert.match(homeView, /Harness comparison preview/);
  assert.match(homeView, /buildHarnessCompatibilityVerdict/);
  assert.match(homeView, /getHarnessSelectionRef/);
  assert.match(homeView, /onOpenNewSession: \(seed\?: string \| HomeNewSessionSeed \| null\) => void/);
  assert.match(homeView, /seedIntent: intentDraft/);
  assert.match(homeView, /recipeId: intentRecipeId/);
  assert.match(homeView, /onClick=\{\(\) => onOpenNewSession\(\)\}/);
  assert.match(homeView, /Start New Session/);
  assert.match(homeView, /Configure Models/);
  assert.match(homeView, /Review Authority/);
  assert.match(
    shellContent,
    /onOpenNewSession=\{controller\.modals\.openNewSessionModal\}/,
  );
  assert.match(homeCss, /\.chat-home-zero-intent-composer\s*\{/);
  assert.match(homeCss, /\.chat-home-zero-intent-composer__box\s*\{/);
  assert.match(homeCss, /\.chat-home-zero-intent-composer__submit\s*\{/);
  assert.match(homeCss, /Phase 0A reference parity/);
  assert.match(homeCss, /\.chat-home-zero-actions,[\s\S]*\.chat-home-zero-body \{[\s\S]*display: none;/);
});

test("home dashboard exposes the Core cockpit projection", () => {
  assert.match(homeCockpitModel, /HypervisorHomeCockpitProjection/);
  assert.match(homeCockpitModel, /HYPERVISOR_HOME_COCKPIT_PROJECTION/);
  assert.match(homeCockpitModel, /HYPERVISOR_HOME_COCKPIT_PROJECTION_PATH/);
  assert.match(homeCockpitModel, /loadHypervisorHomeCockpitProjection/);
  assert.match(homeCockpitModel, /normalizeHypervisorHomeCockpitProjection/);
  assert.match(homeCockpitModel, /does not become runtime/);
  assert.match(homeCockpitModel, /Project restore/);
  assert.match(homeCockpitModel, /Active session/);
  assert.match(homeCockpitModel, /Privacy gates/);
  assert.match(homeCockpitModel, /Provider posture/);
  assert.match(homeCockpitModel, /Receipt evidence/);
  assert.match(homeCockpitModel, /Harness comparison/);
  assert.match(homeView, /HYPERVISOR_HOME_COCKPIT_PROJECTION/);
  assert.match(homeView, /loadHypervisorHomeCockpitProjection/);
  assert.match(homeView, /setCockpitProjection/);
  assert.match(homeView, /\[Hypervisor\]\[Home\] cockpit projection unavailable/);
  assert.match(homeView, /aria-label="Hypervisor cockpit status"/);
  assert.match(homeView, /data-home-cockpit-projection/);
  assert.match(homeView, /data-home-cockpit-source/);
  assert.match(homeView, /data-home-cockpit-metric/);
  assert.match(homeView, /data-home-cockpit-surface/);
  assert.match(homeView, /data-home-cockpit-drill-ref/);
  assert.match(homeView, /data-home-cockpit-drill-evidence/);
  assert.match(homeView, /data-home-cockpit-drill-surface/);
  assert.match(homeView, /onOpenCockpitSurface: \(surfaceRef: string\) => void/);
  assert.match(homeView, /onClick=\{\(\) => onOpenCockpitSurface\(metric\.surface_ref\)\}/);
  assert.match(homeView, /onClick=\{\(\) => onOpenCockpitSurface\(drillRef\.surface_ref\)\}/);
  assert.match(shellContent, /isHypervisorSurfaceId/);
  assert.match(shellContent, /surfaceRef\.replace\(\/\^surface:/);
  assert.match(shellContent, /controller\.changePrimaryView\(surfaceId\)/);
  assert.match(homeCss, /\.chat-home-zero-cockpit\s*\{/);
  assert.match(homeCss, /\.chat-home-zero-cockpit-grid\s*\{/);
  assert.match(homeCss, /\.chat-home-zero-cockpit-card\s*\{/);
  assert.match(homeCss, /\.chat-home-zero-cockpit-card__summary/);
  assert.match(homeCss, /\.chat-home-zero-cockpit-card__drill-refs/);
});

test("home dashboard routes model setup to the Models surface", () => {
  assert.match(homeView, /onOpenModels: \(\) => void/);
  assert.match(
    shellContent,
    /onOpenModels=\{\(\) =>[\s\S]*controller\.changePrimaryView\("models"\)/,
  );
});

test("new session card has responsive shell styling", () => {
  assert.match(homeCss, /\.chat-home-zero-session-card\s*\{/);
  assert.match(homeCss, /\.chat-home-zero-session-card__harnesses\s*\{/);
  assert.match(homeCss, /\.chat-home-zero-session-card__comparison\s*\{/);
  assert.match(
    homeCss,
    /@media \(max-width: 860px\)[\s\S]*\.chat-home-zero-session-card,[\s\S]*\.chat-home-zero-session-card__harnesses,[\s\S]*\.chat-home-zero-session-card__comparison/,
  );
});

console.log("HomeView.hypervisorHome.test.mjs: ok");
