import assert from "node:assert/strict";
import test from "node:test";

import { summarizeSettingsAuthorityPosture } from "./settingsAuthorityPosture";

test("settings authority posture flags raw secret bindings", () => {
  const summary = summarizeSettingsAuthorityPosture([
    { key: "OPENAI_API_KEY", value: "sk-test", secret: true },
    { key: "IOI_PROVIDER_KEY", value: "vault://models/openai", secret: true },
    { key: "LOG_LEVEL", value: "debug", secret: false },
  ]);

  assert.equal(summary.tone, "warning");
  assert.equal(summary.totalBindings, 3);
  assert.equal(summary.secretBindings, 2);
  assert.equal(summary.vaultBackedBindings, 1);
  assert.equal(summary.rawSecretBindings, 1);
  assert.equal(summary.publicBindings, 1);
  assert.match(summary.detail, /1 secret binding still use raw values/);
});

test("settings authority posture marks vault-backed bindings ready", () => {
  const summary = summarizeSettingsAuthorityPosture([
    { key: "OPENAI_API_KEY", value: "wallet://models/openai", secret: true },
    { key: "GOOGLE_AUTH", value: "ioi-vault://connectors/google", secret: true },
  ]);

  assert.equal(summary.tone, "ready");
  assert.equal(summary.label, "Vault-aligned");
  assert.equal(summary.rawSecretBindings, 0);
  assert.equal(summary.vaultBackedBindings, 2);
});

test("settings authority posture keeps empty settings explicit", () => {
  const summary = summarizeSettingsAuthorityPosture([]);

  assert.equal(summary.tone, "idle");
  assert.equal(summary.label, "No bindings");
  assert.equal(summary.checklist.includes("0 raw secrets"), true);
});

console.log("settingsAuthorityPosture.test.ts: ok");
