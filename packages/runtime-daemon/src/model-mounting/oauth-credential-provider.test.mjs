import assert from "node:assert/strict";
import { test } from "node:test";

import { OAuthCredentialProvider } from "./oauth-credential-provider.mjs";

const FIXED_NOW = new Date("2026-06-03T00:00:00.000Z");

function now() {
  return new Date(FIXED_NOW.getTime());
}

function fakeVault() {
  const bindings = new Map();
  const hashes = new Map();
  const vaultRefHash = (vaultRef) => {
    if (!hashes.has(vaultRef)) hashes.set(vaultRef, `hash-${hashes.size + 1}`);
    return hashes.get(vaultRef);
  };
  return {
    bindings,
    bindVaultRef({ vaultRef, material, purpose, label }) {
      bindings.set(vaultRef, { material, purpose, label });
      return {
        vaultRefHash: vaultRefHash(vaultRef),
        vaultRef: { redacted: true, hash: vaultRefHash(vaultRef) },
        configured: true,
        evidenceRefs: ["VaultPort.bindVaultRef"],
      };
    },
    resolveVaultRef(vaultRef, purpose) {
      const binding = bindings.get(vaultRef);
      return {
        vaultRefHash: vaultRefHash(vaultRef),
        resolvedMaterial: Boolean(binding?.material),
        material: binding?.material ?? null,
        purpose,
        evidenceRefs: ["VaultPort.resolveVaultRef"],
      };
    },
    removeVaultRef(vaultRef) {
      const existed = bindings.delete(vaultRef);
      return {
        vaultRefHash: vaultRefHash(vaultRef),
        configured: false,
        existed,
        evidenceRefs: ["VaultPort.removeVaultRef"],
      };
    },
  };
}

test("OAuth credential provider starts authorization with vault-bound private state", () => {
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ now, vault });

  const started = provider.startAuthorization({
    providerId: "catalog.huggingface",
    body: {
      state_id: "state.one",
      session_id: "session.one",
      authorization_endpoint: "https://auth.example.test/oauth",
      token_endpoint: "https://auth.example.test/token",
      redirect_uri: "https://app.example.test/callback",
      client_id: "client-id",
      scopes: ["repo", "model"],
    },
  });

  assert.equal(started.state.status, "pending");
  assert.equal(typeof started.evidence.stateVaultRefHash, "string");
  assert.match(started.authorizationUrl, /client_id=client-id/);
  assert.doesNotMatch(started.authorizationUrlRedacted, /client-id/);
  assert.match(started.authorizationUrlRedacted, /state=%5BREDACTED%5D/);
  assert.equal(JSON.stringify(started.evidence).includes("vault://"), false);
  assert.equal(vault.bindings.size, 6);
});

test("OAuth credential provider rejects callback when vault material is unavailable", async () => {
  const provider = new OAuthCredentialProvider({
    now,
    vault: {
      resolveVaultRef(vaultRef, purpose) {
        return {
          vaultRefHash: `hash:${vaultRef}`,
          resolvedMaterial: false,
          material: null,
          purpose,
          evidenceRefs: ["VaultPort.resolveVaultRef"],
        };
      },
    },
  });

  await assert.rejects(
    provider.completeAuthorization({
      providerId: "catalog.huggingface",
      stateRecord: {
        id: "state.one",
        providerId: "catalog.huggingface",
        sessionId: "session.one",
        status: "pending",
        expiresAt: "2026-06-03T00:10:00.000Z",
        stateVaultRef: "vault://state",
        tokenEndpointVaultRef: "vault://token-endpoint",
        redirectUriVaultRef: "vault://redirect-uri",
        clientIdVaultRef: "vault://client-id",
        codeVerifierVaultRef: "vault://code-verifier",
        pkceRequired: true,
        scopes: ["repo"],
      },
      body: { state: "state", code: "code" },
    }),
    /OAuth callback requires vault material/,
  );
});

test("OAuth credential provider keeps client secrets behind vault refs", async () => {
  const provider = new OAuthCredentialProvider({ now, vault: fakeVault() });

  await assert.rejects(
    provider.exchangeAuthorizationCode({
      providerId: "catalog.huggingface",
      body: {
        token_endpoint: "https://auth.example.test/token",
        authorization_code: "code",
        client_secret: "plaintext-secret",
      },
    }),
    /OAuth client secrets must be provided through vault refs/,
  );
});

test("OAuth credential provider revokes session vault refs", () => {
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ now, vault });
  vault.bindVaultRef({ vaultRef: "vault://access", material: "access", purpose: "oauth.access_token:test" });
  vault.bindVaultRef({ vaultRef: "vault://refresh", material: "refresh", purpose: "oauth.refresh_token:test" });

  const revoked = provider.revokeSession({
    id: "session.one",
    providerId: "catalog.huggingface",
    status: "active",
    accessVaultRef: "vault://access",
    refreshVaultRef: "vault://refresh",
    evidenceRefs: ["VaultOAuthSession"],
  });

  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.revokedAt, FIXED_NOW.toISOString());
  assert.equal(vault.bindings.has("vault://access"), false);
  assert.equal(vault.bindings.has("vault://refresh"), false);
});
