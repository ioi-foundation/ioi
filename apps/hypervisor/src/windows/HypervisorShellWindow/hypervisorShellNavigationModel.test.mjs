import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("./hypervisorShellNavigationModel.ts", import.meta.url),
  "utf8",
);
const operatorSubstrate = readFileSync(
  new URL("./operatorSubstrateModel.ts", import.meta.url),
  "utf8",
);
const activityBar = readFileSync(
  new URL("./components/ChatLocalActivityBar.tsx", import.meta.url),
  "utf8",
);
const newSessionModal = readFileSync(
  new URL("./components/HypervisorNewSessionModal.tsx", import.meta.url),
  "utf8",
);
const controller = readFileSync(
  new URL("./useHypervisorShellController.ts", import.meta.url),
  "utf8",
);
const shellWindow = readFileSync(
  new URL("./index.tsx", import.meta.url),
  "utf8",
);
const header = readFileSync(
  new URL("./components/HypervisorClientHeader.tsx", import.meta.url),
  "utf8",
);

test("hypervisor shell exposes the canonical core client and surface taxonomy", () => {
  assert.match(source, /export type HypervisorClientKind/);
  assert.match(source, /export type HypervisorSurfaceId/);
  assert.match(source, /export type HypervisorSessionDetailTab/);
  assert.match(source, /export type HypervisorInspectorPanelId/);
  assert.match(source, /"app"[\s\S]*"web"[\s\S]*"cli_headless"/);
  assert.match(source, /"workbench"[\s\S]*"automations"[\s\S]*"insights"/);
  assert.doesNotMatch(source, /"recipes"/);
});

test("hypervisor shell keeps application surfaces separate from clients", () => {
  assert.match(source, /id: "workbench"[\s\S]*label: "Workbench"/);
  assert.match(
    source,
    /editors, terminals, browsers, and VMs are adapter targets/,
  );
  assert.match(source, /id: "foundry"[\s\S]*label: "Foundry"/);
  assert.match(source, /id: "fleet"[\s\S]*label: "Fleet"/);
  assert.match(source, /Direct provider integrations/);
  assert.doesNotMatch(
    source,
    /Hypervisor IDE|ONA-like|internal-docs\/reverse-engineering\/ona/,
  );
});

test("hypervisor shell models IOI-reference session detail and inspectors", () => {
  assert.match(source, /HYPERVISOR_PRIMARY_ACTION[\s\S]*New Session/);
  assert.match(source, /HYPERVISOR_NEW_SESSION_SETUP_MODEL/);
  assert.match(source, /HYPERVISOR_SESSION_LAUNCH_RECIPES/);
  for (const recipeId of [
    "mission.default",
    "workbench.default",
    "agent.default",
    "automation.default",
    "foundry.eval",
    "fleet.provider",
    "privacy.workspace",
  ]) {
    assert.match(source, new RegExp(recipeId.replace(".", "\\.")));
  }
  assert.match(
    source,
    /Default Harness Profile or daemon-mediated AgentHarnessAdapter/,
  );
  assert.match(source, /harnessOptions: HYPERVISOR_HARNESS_SELECTION_OPTIONS/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(source, /HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL/);
  assert.match(source, /HYPERVISOR_SESSION_DETAIL_TABS/);
  assert.match(
    source,
    /"agent"[\s\S]*"workbench"[\s\S]*"environment"[\s\S]*"changes"[\s\S]*"receipts"[\s\S]*"replay"/,
  );
  assert.match(source, /HYPERVISOR_RIGHT_INSPECTOR_PANELS/);
  assert.match(source, /HYPERVISOR_BOTTOM_INSPECTOR_PANELS/);
  assert.match(
    source,
    /"ports_services"[\s\S]*"tasks"[\s\S]*"terminal"[\s\S]*"logs"/,
  );
});

test("visible shell chrome uses Hypervisor labels over compatibility route keys", () => {
  assert.match(operatorSubstrate, /sessions: "Sessions"/);
  assert.match(operatorSubstrate, /workbench: "Workbench"/);
  assert.match(operatorSubstrate, /automations: "Automations"/);
  assert.match(operatorSubstrate, /insights: "Insights"/);
  assert.match(operatorSubstrate, /models: "Models"/);
  assert.match(operatorSubstrate, /agents: "Agents"/);
  assert.match(operatorSubstrate, /authority: "Authority"/);
  assert.doesNotMatch(operatorSubstrate, /HYPERVISOR_SURFACE_PRIMARY_VIEW_ROUTES/);
  assert.match(operatorSubstrate, /routeState: "active_route"/);
  assert.match(
    operatorSubstrate,
    /Search Hypervisor, sessions, workbench, automations, and commands/,
  );
  assert.match(activityBar, /aria-label="Hypervisor navigation"/);
  assert.match(activityBar, /chat-activity-button--new-session/);
  assert.match(activityBar, /HYPERVISOR_PRIMARY_ACTION/);
  assert.match(activityBar, /aria-label="Applications"/);
  assert.match(activityBar, /aria-label="Governance and infrastructure"/);
  assert.match(activityBar, /data-route-state=\{item\.routeState\}/);
  assert.match(header, /`Hypervisor .*?\$\{windowSurfaceTitle/s);
  assert.doesNotMatch(header, /Autopilot Chat/);
});

test("new session modal is a shell-level governed launch flow", () => {
  assert.match(newSessionModal, /HYPERVISOR_SESSION_LAUNCH_RECIPES/);
  assert.match(newSessionModal, /buildHarnessCompatibilityVerdict/);
  assert.match(newSessionModal, /data-new-session-receipt-preview/);
  assert.match(newSessionModal, /cTEE private workspace/);
  assert.match(newSessionModal, /Launch governed session/);
  assert.match(controller, /newSessionModalOpen/);
  assert.match(controller, /launchNewSession/);
  assert.match(controller, /setCurrentProjectId\(project\.id\)/);
  assert.match(controller, /setActiveView\(recipe\.surface_id\)/);
  assert.match(shellWindow, /<HypervisorNewSessionModal/);
  assert.match(shellWindow, /onLaunch=\{controller\.modals\.launchNewSession\}/);
});

console.log("hypervisorShellNavigationModel.test.mjs: ok");
