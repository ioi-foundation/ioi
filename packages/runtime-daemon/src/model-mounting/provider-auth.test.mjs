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
  assert.equal(providerSecretInput({ api_key_vault_ref: "vault://provider/key" }), "vault://provider/key");

  assert.throws(
    () => assertProviderVaultBoundary({ id: "provider.openai", kind: "openai" }),
    (error) => {
      assert.match(error.message, /fail closed/);
      assert.equal(error.details.provider_id, "provider.openai");
      assert.equal(error.details.provider_kind, "openai");
      assert.equal(error.details.vault_ref_configured, false);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      assert.equal(Object.hasOwn(error.details, "vaultRefConfigured"), false);
      return true;
    },
  );
  assert.doesNotThrow(() =>
    assertProviderVaultBoundary({ id: "provider.openai", kind: "openai", secretRef: "vault://provider/openai" }),
  );
});

test("provider secret input rejects retired request aliases", () => {
  assert.throws(
    () =>
      providerSecretInput({
        secretRef: "vault://provider/secret",
        authVaultRef: "vault://provider/auth",
        apiKeyVaultRef: "vault://provider/api-key",
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "provider_secret_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "secretRef",
        "authVaultRef",
        "apiKeyVaultRef",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "secret_ref",
        "auth_vault_ref",
        "api_key_vault_ref",
      ]);
      return true;
    },
  );
});

test("provider auth validation rejects plaintext secrets and unsafe headers", () => {
  assert.throws(
    () => assertNoPlaintextProviderSecret({ api_key: "plain-secret" }),
    /wallet.network vault refs/,
  );
  assert.equal(normalizeProviderAuthScheme("api-key"), "api_key");
  assert.equal(normalizeProviderAuthHeaderName("X-API-Key"), "x-api-key");
  assert.throws(
    () => normalizeProviderAuthScheme("digest"),
    (error) => {
      assert.match(error.message, /bearer, raw, or api_key/);
      assert.equal(error.details.auth_scheme, "digest");
      assert.equal(Object.hasOwn(error.details, "authScheme"), false);
      return true;
    },
  );
  assert.throws(
    () => normalizeProviderAuthHeaderName("cookie"),
    (error) => {
      assert.match(error.message, /not allowed/);
      assert.equal(error.details.auth_header_name, "cookie");
      assert.equal(Object.hasOwn(error.details, "authHeaderName"), false);
      return true;
    },
  );
  assert.throws(
    () => normalizeProviderAuthHeaderName("bad header"),
    (error) => {
      assert.match(error.message, /valid HTTP header token/);
      assert.equal(error.details.auth_header_name, "[REDACTED]");
      assert.equal(Object.hasOwn(error.details, "authHeaderName"), false);
      return true;
    },
  );
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

  assert.throws(
    () => providerAuthHeaders(
      {
        id: "provider.custom",
        kind: "custom_http",
        secretRef: "vault://provider/custom",
      },
      { vault: { resolveVaultRef: () => ({ vaultRefHash: "hash-provider-custom" }) } },
    ),
    (error) => {
      assert.match(error.message, /no runtime vault material/);
      assert.equal(error.details.provider_id, "provider.custom");
      assert.equal(error.details.provider_kind, "custom_http");
      assert.equal(error.details.resolved_material, false);
      assert.equal(typeof error.details.vault_ref_hash, "string");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "vaultRefHash"), false);
      assert.equal(Object.hasOwn(error.details, "resolvedMaterial"), false);
      return true;
    },
  );
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
