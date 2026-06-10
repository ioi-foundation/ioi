import test from "node:test";
import assert from "node:assert/strict";

import {
  assertNoPlaintextProviderSecret,
  providerRequiresVaultSecret,
  providerSecretInput,
  sanitizeVaultRefs,
} from "./provider-auth.mjs";

test("provider auth helpers classify hosted providers and canonical secret input", () => {
  assert.equal(providerRequiresVaultSecret("openai"), true);
  assert.equal(providerRequiresVaultSecret("ollama"), false);
  assert.equal(providerSecretInput({ api_key_vault_ref: "vault://provider/key" }), "vault://provider/key");
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

test("provider auth validation rejects plaintext secrets", () => {
  assert.throws(
    () => assertNoPlaintextProviderSecret({ api_key: "plain-secret" }),
    /wallet.network vault refs/,
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
