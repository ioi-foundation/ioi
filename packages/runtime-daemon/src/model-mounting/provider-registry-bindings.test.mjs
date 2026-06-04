import assert from "node:assert/strict";
import { test } from "node:test";

import { createProviderRegistryBindings } from "./provider-registry-bindings.mjs";

const deps = {
  providerHasVaultRef: (provider) => typeof provider?.secretRef === "string" && provider.secretRef.startsWith("vault://"),
  providerRequiresVaultSecret: (provider) => provider?.kind === "openai",
  runtimeError: ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details }),
  stableHash: (value) => `hash:${String(value).length}`,
};

test("provider registry bindings keep hosted provider projection compatible", () => {
  const { hostedProvider } = createProviderRegistryBindings(deps);

  const configured = hostedProvider("provider.openai", "OpenAI", "openai", "sk-test");
  assert.equal(configured.status, "configured");
  assert.equal(configured.secretRef, "vault://provider.openai/api-key");

  const blocked = hostedProvider("provider.anthropic", "Anthropic", "anthropic", "");
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.secretRef, null);
});

test("provider registry bindings inject vault dependencies for public provider projection", () => {
  const { publicProvider } = createProviderRegistryBindings(deps);

  const projected = publicProvider(
    {
      id: "provider.openai",
      kind: "openai",
      status: "configured",
      secretRef: "vault://provider.openai/api-key",
    },
    { configured: true, resolvedMaterial: true },
  );

  assert.deepEqual(projected.secretRef, { redacted: true, hash: "hash:31" });
  assert.equal(projected.status, "configured");
  assert.equal(projected.secretConfigured, true);
  assert.equal(projected.vaultBoundary.required, true);
  assert.equal(projected.vaultBoundary.runtimeBound, true);
});

test("provider registry bindings preserve fail-closed dependency validation", () => {
  const { publicProvider } = createProviderRegistryBindings();

  assert.throws(
    () => publicProvider({ id: "provider.openai", kind: "openai", status: "configured" }),
    /publicProvider requires providerHasVaultRef/,
  );
});

test("provider registry bindings inject runtime errors for required route strings", () => {
  const { optionalString, requiredString } = createProviderRegistryBindings(deps);

  assert.equal(requiredString(" model-1 ", "model_id"), " model-1 ");
  assert.throws(
    () => requiredString("", "model_id"),
    (error) => error.status === 400 && error.code === "runtime" && error.details?.field === "model_id",
  );
  assert.equal(optionalString(" response-1 "), "response-1");
  assert.equal(optionalString(" "), null);
  assert.equal(optionalString(42), null);
});
