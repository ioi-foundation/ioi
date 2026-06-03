import test from "node:test";
import assert from "node:assert/strict";

import {
  assertNoPlaintextProviderSecret,
  assertProviderVaultBoundary,
  normalizeProviderAuthHeaderName,
  normalizeProviderAuthScheme,
  providerAuthHeaders,
  providerRequiresVaultSecret,
  providerSecretInput,
  sanitizeVaultRefs,
} from "./provider-auth.mjs";

test("provider auth helpers keep hosted providers fail-closed on vault refs", () => {
  assert.equal(providerRequiresVaultSecret("openai"), true);
  assert.equal(providerRequiresVaultSecret("ollama"), false);
  assert.equal(providerSecretInput({ apiKeyVaultRef: "vault://provider/key" }), "vault://provider/key");

  assert.throws(
    () => assertProviderVaultBoundary({ id: "provider.openai", kind: "openai" }),
    /fail closed/,
  );
  assert.doesNotThrow(() =>
    assertProviderVaultBoundary({ id: "provider.openai", kind: "openai", secretRef: "vault://provider/openai" }),
  );
});

test("provider auth validation rejects plaintext secrets and unsafe headers", () => {
  assert.throws(
    () => assertNoPlaintextProviderSecret({ api_key: "plain-secret" }),
    /wallet.network vault refs/,
  );
  assert.equal(normalizeProviderAuthScheme("api-key"), "api_key");
  assert.equal(normalizeProviderAuthHeaderName("X-API-Key"), "x-api-key");
  assert.throws(() => normalizeProviderAuthScheme("digest"), /bearer, raw, or api_key/);
  assert.throws(() => normalizeProviderAuthHeaderName("cookie"), /not allowed/);
  assert.throws(() => normalizeProviderAuthHeaderName("bad header"), /valid HTTP header token/);
});

test("provider auth headers resolve vault material without exposing secrets", () => {
  const state = {
    vault: {
      resolveVaultRef(vaultRef, purpose) {
        assert.equal(vaultRef, "vault://provider/custom");
        assert.equal(purpose, "provider.auth:provider.custom");
        return {
          vaultRefHash: "hash-provider-custom",
          material: "secret-token",
          evidenceRefs: ["VaultPort.resolveVaultRef"],
        };
      },
    },
  };

  const result = providerAuthHeaders(
    {
      id: "provider.custom",
      kind: "custom_http",
      secretRef: "vault://provider/custom",
      authScheme: "bearer",
      authHeaderName: "X-Provider-Token",
    },
    state,
  );

  assert.deepEqual(result.headers, { "x-provider-token": "Bearer secret-token" });
  assert.deepEqual(result.evidence, {
    vaultRefHash: "hash-provider-custom",
    resolvedMaterial: true,
    evidenceRefs: ["VaultPort.resolveVaultRef"],
    headerNames: ["x-provider-token"],
    authScheme: "bearer",
  });
});

test("vault ref sanitizer redacts non-vault inputs", () => {
  assert.deepEqual(sanitizeVaultRefs({
    good: "vault://provider/key",
    bad: "plain-secret",
  }), {
    good: "vault://provider/key",
    bad: "[REDACTED]",
  });
});
