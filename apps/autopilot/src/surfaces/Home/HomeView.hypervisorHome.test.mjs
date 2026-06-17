import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const homeView = readFileSync(
  new URL("./HomeView.tsx", import.meta.url),
  "utf8",
);
const homeCss = readFileSync(new URL("./Home.css", import.meta.url), "utf8");
const shellContent = readFileSync(
  new URL(
    "../../windows/AutopilotShellWindow/components/AutopilotShellContent.tsx",
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

test("home dashboard exposes the New Session setup contract", () => {
  assert.match(homeView, /HYPERVISOR_NEW_SESSION_SETUP_MODEL/);
  assert.match(homeView, /data-home-new-session-contract="daemon-runtime"/);
  assert.match(homeView, /newSessionRequiredSections/);
  assert.match(homeView, /newSessionHarnessOptions/);
  assert.match(homeView, /buildHarnessCompatibilityVerdict/);
  assert.match(homeView, /getHarnessSelectionRef/);
  assert.match(homeView, /Start New Session/);
  assert.match(homeView, /Configure Models/);
  assert.match(homeView, /Review Authority/);
});

test("home dashboard routes model setup to the Models surface", () => {
  assert.match(homeView, /onOpenModels: \(\) => void/);
  assert.match(shellContent, /onOpenModels=\{\(\) => controller\.changePrimaryView\("mounts"\)\}/);
});

test("new session card has responsive shell styling", () => {
  assert.match(homeCss, /\.chat-home-zero-session-card\s*\{/);
  assert.match(homeCss, /\.chat-home-zero-session-card__harnesses\s*\{/);
  assert.match(
    homeCss,
    /@media \(max-width: 860px\)[\s\S]*\.chat-home-zero-session-card,[\s\S]*\.chat-home-zero-session-card__harnesses/,
  );
});

console.log("HomeView.hypervisorHome.test.mjs: ok");
