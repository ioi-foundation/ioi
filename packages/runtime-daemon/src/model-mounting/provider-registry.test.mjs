import assert from "node:assert/strict";
import { test } from "node:test";

import {
  hostedProvider,
  optionalString,
  publicProvider,
  requiredString,
} from "./provider-registry.mjs";

const deps = {
  providerHasVaultRef: (provider) => typeof provider?.secretRef === "string" && provider.secretRef.startsWith("vault://"),
  providerRequiresVaultSecret: (provider) => ["openai", "anthropic", "gemini"].includes(provider?.kind),
  stableHash: (value) => `hash:${String(value).length}`,
};

test("provider registry creates hosted provider records without exposing secrets", () => {
  const configured = hostedProvider("provider.openai", "OpenAI", "openai", "sk-test");
  assert.equal(configured.status, "configured");
  assert.equal(configured.secretRef, "vault://provider.openai/api-key");
  assert.deepEqual(configured.discovery.evidenceRefs, ["OPENAI_API_KEY"]);

  const blocked = hostedProvider("provider.gemini", "Gemini", "gemini", "");
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.secretRef, null);
});

test("provider registry redacts public provider vault metadata", () => {
  const provider = {
    id: "provider.openai",
    kind: "openai",
    status: "configured",
    secretRef: "vault://provider.openai/api-key",
  };
  const projected = publicProvider(provider, { resolvedMaterial: true }, deps);
  assert.deepEqual(projected.secretRef, { redacted: true, hash: "hash:31" });
  assert.equal(projected.secretConfigured, true);
  assert.equal(projected.vaultBoundary.required, true);
  assert.equal(projected.vaultBoundary.failClosed, false);
  assert.equal(projected.vaultBoundary.runtimeBound, true);
});

test("provider registry blocks required vault providers without vault refs", () => {
  const projected = publicProvider({ id: "provider.openai", kind: "openai", status: "configured" }, null, deps);
  assert.equal(projected.status, "blocked");
  assert.equal(projected.secretRef, null);
  assert.equal(projected.vaultBoundary.failClosed, true);
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
