import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const settingsView = fs.readFileSync(
  new URL("./SettingsView.tsx", import.meta.url),
  "utf8",
);
const settingsViewBody = fs.readFileSync(
  new URL("./SettingsViewBody.tsx", import.meta.url),
  "utf8",
);
const settingsAuthoritySection = fs.readFileSync(
  new URL("./SettingsAuthoritySection.tsx", import.meta.url),
  "utf8",
);
const authorityRuntime = fs.readFileSync(
  new URL("../Policy/authorityCenterRuntime.ts", import.meta.url),
  "utf8",
);
const authorityCenterPanel = fs.readFileSync(
  new URL("../Policy/AuthorityCenterPanel.tsx", import.meta.url),
  "utf8",
);
const authorityCenterModel = fs.readFileSync(
  new URL("../Policy/authorityCenter.ts", import.meta.url),
  "utf8",
);
const environmentSection = fs.readFileSync(
  new URL("./SettingsEnvironmentSection.tsx", import.meta.url),
  "utf8",
);
const missionControlControlView = fs.readFileSync(
  new URL("../MissionControl/MissionControlControlView.tsx", import.meta.url),
  "utf8",
);

test("settings authority section is wired to the canonical authority projection", () => {
  assert.match(settingsViewBody, /selectedSection === "authority"/);
  assert.match(settingsViewBody, /SettingsAuthoritySection/);
  assert.match(settingsView, /loadAuthorityCenterRuntimeProjection/);
  assert.match(settingsView, /authorityCenterProjection/);
  assert.match(settingsAuthoritySection, /settings-authority-center/);
  assert.match(settingsAuthoritySection, /settings-authority-fail-closed/);
  assert.match(settingsAuthoritySection, /settings-authority-capability-row/);
  assert.match(settingsAuthoritySection, /data-capability-ref/);
  assert.match(settingsAuthoritySection, /data-grant-status/);
  assert.match(settingsAuthoritySection, /data-policy-status/);
  assert.match(settingsAuthoritySection, /data-receipt-status/);
  assert.match(settingsAuthoritySection, /Runtime refs/);
  assert.match(settingsAuthoritySection, /settings-authority-repair-actions/);
  assert.match(settingsAuthoritySection, /data-repair-action-kind/);
  assert.match(
    settingsAuthoritySection,
    /openWorkflowPreflight[\s\S]*panel: "readiness"[\s\S]*capabilityRef: action\.targetRef[\s\S]*source: "settings-authority"/,
  );
  assert.match(settingsAuthoritySection, /openModelRoute/);
});

test("authority center exposes canonical grant policy receipt posture", () => {
  assert.match(authorityCenterModel, /grantStatus/);
  assert.match(authorityCenterModel, /policyStatus/);
  assert.match(authorityCenterModel, /receiptStatus/);
  assert.match(authorityCenterModel, /capabilityRuntimeReady/);
  assert.match(authorityCenterPanel, /data-capability-ref/);
  assert.match(authorityCenterPanel, /data-grant-status/);
  assert.match(authorityCenterPanel, /data-policy-status/);
  assert.match(authorityCenterPanel, /data-receipt-status/);
  assert.match(authorityCenterPanel, /Runtime refs/);
  assert.match(authorityCenterPanel, /Run-ready/);
});

test("settings authority runtime uses workflow capability endpoints with compatibility fallback", () => {
  assert.match(authorityRuntime, /MODEL_CAPABILITY_BINDING_ENDPOINT/);
  assert.match(authorityRuntime, /TOOL_CAPABILITY_BINDING_ENDPOINT/);
  assert.match(authorityRuntime, /MODEL_AUTHORITY_BINDING_ENDPOINT/);
  assert.match(authorityRuntime, new RegExp('"/v1/model-capabilities"'));
  assert.match(authorityRuntime, new RegExp('"/v1/tools"'));
});

test("environment settings are labeled as compatibility, not authority truth", () => {
  assert.match(environmentSection, /Compatibility bindings/);
  assert.match(environmentSection, /Source of truth/);
  assert.match(environmentSection, /Authority Center/);
});

test("settings authority repair actions route to canonical surfaces", () => {
  assert.match(settingsView, /onOpenModelRoutes/);
  assert.match(settingsView, /onOpenWorkflowPreflight/);
  assert.match(missionControlControlView, /onOpenModelRoutes/);
  assert.match(missionControlControlView, /onOpenWorkflowPreflight/);
});

console.log("settingsAuthorityCenterWiring.test.ts: ok");
