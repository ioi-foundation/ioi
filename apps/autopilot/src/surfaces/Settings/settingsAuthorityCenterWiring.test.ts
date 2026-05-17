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
const environmentSection = fs.readFileSync(
  new URL("./SettingsEnvironmentSection.tsx", import.meta.url),
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

console.log("settingsAuthorityCenterWiring.test.ts: ok");
