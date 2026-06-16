import assert from "node:assert/strict";
import { test } from "node:test";

import {
  hostedProvider,
  optionalString,
  requiredString,
} from "./provider-registry.mjs";

test("provider registry creates hosted provider records without exposing secrets", () => {
  const configured = hostedProvider("provider.openai", "OpenAI", "openai", { configured: true });
  assert.equal(configured.status, "configured");
  assert.equal(configured.secretRef, "vault://provider.openai/api-key");
  assert.deepEqual(configured.discovery.evidenceRefs, [
    "wallet.network.vault_ref_boundary",
    "provider_request_time_secret_resolution",
    "provider_env_secret_material_fallback_retired",
  ]);

  const blocked = hostedProvider("provider.gemini", "Gemini", "gemini");
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.secretRef, "vault://provider.gemini/api-key");
  assert.throws(
    () => hostedProvider("provider.openai", "OpenAI", "openai", "sk-test"),
    /plaintext secret arguments are retired/,
  );
  assert.throws(
    () => hostedProvider("provider.openai", "OpenAI", "openai", { secretRef: "vault://provider.openai/api-key" }),
    /plaintext secret options are retired/,
  );
});

test("provider registry validates required and optional route strings", () => {
  assert.equal(requiredString(" model-1 ", "model_id"), " model-1 ");
  assert.throws(
    () => requiredString("", "model_id", {
      runtimeError: ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details }),
    }),
    /model_id is required/,
  );
  assert.equal(optionalString(" value "), "value");
  assert.equal(optionalString(" "), null);
  assert.equal(optionalString(12), null);
});
