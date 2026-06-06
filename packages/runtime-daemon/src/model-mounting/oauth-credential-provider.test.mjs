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
      stateId: "state.retired",
      session_id: "session.one",
      sessionId: "session.retired",
      authorization_endpoint: "https://auth.example.test/oauth",
      authorizationEndpoint: "https://retired.example.test/oauth",
      auth_url: "https://retired.example.test/auth-url",
      authUrl: "https://retired.example.test/authUrl",
      token_endpoint: "https://auth.example.test/token",
      tokenEndpoint: "https://retired.example.test/token",
      redirect_uri: "https://app.example.test/callback",
      redirectUri: "https://retired.example.test/callback",
      client_id: "client-id",
      clientId: "retired-client-id",
      pkce_required: true,
      pkceRequired: false,
      state_ttl_seconds: 600,
      stateTtlSeconds: 1,
      state_vault_ref: "vault://oauth/state",
      stateVaultRef: "vault://oauth/retired-state",
      code_verifier_vault_ref: "vault://oauth/code-verifier",
      codeVerifierVaultRef: "vault://oauth/retired-code-verifier",
      authorization_endpoint_vault_ref: "vault://oauth/authorization-endpoint",
      authorizationEndpointVaultRef: "vault://oauth/retired-authorization-endpoint",
      token_endpoint_vault_ref: "vault://oauth/token-endpoint",
      tokenEndpointVaultRef: "vault://oauth/retired-token-endpoint",
      redirect_uri_vault_ref: "vault://oauth/redirect-uri",
      redirectUriVaultRef: "vault://oauth/retired-redirect-uri",
      client_id_vault_ref: "vault://oauth/client-id",
      clientIdVaultRef: "vault://oauth/retired-client-id",
      scopes: ["repo", "model"],
    },
  });

  assert.equal(started.state.id, "state.one");
  assert.equal(started.state.sessionId, "session.one");
  assert.equal(started.state.status, "pending");
  assert.equal(typeof started.evidence.stateVaultRefHash, "string");
  assert.match(started.authorizationUrl, /client_id=client-id/);
  assert.doesNotMatch(started.authorizationUrl, /retired-client-id/);
  assert.doesNotMatch(started.authorizationUrlRedacted, /client-id/);
  assert.match(started.authorizationUrlRedacted, /state=%5BREDACTED%5D/);
  assert.equal(JSON.stringify(started.evidence).includes("vault://"), false);
  assert.equal(vault.bindings.size, 6);
  assert.equal(vault.bindings.has("vault://oauth/state"), true);
  assert.equal(vault.bindings.has("vault://oauth/retired-state"), false);
});

test("OAuth credential provider ignores retired start authorization request aliases", () => {
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ now, vault });

  assert.throws(
    () => provider.startAuthorization({
      providerId: "catalog.huggingface",
      body: {
        stateId: "state.retired",
        sessionId: "session.retired",
        authorizationEndpoint: "https://auth.example.test/oauth",
        authUrl: "https://auth.example.test/auth-url",
        tokenEndpoint: "https://auth.example.test/token",
        redirectUri: "https://app.example.test/callback",
        clientId: "client-id",
        pkceRequired: false,
        stateTtlSeconds: 1,
        stateVaultRef: "vault://oauth/retired-state",
        codeVerifierVaultRef: "vault://oauth/retired-code-verifier",
        authorizationEndpointVaultRef: "vault://oauth/retired-authorization-endpoint",
        tokenEndpointVaultRef: "vault://oauth/retired-token-endpoint",
        redirectUriVaultRef: "vault://oauth/retired-redirect-uri",
        clientIdVaultRef: "vault://oauth/retired-client-id",
      },
    }),
    (error) => error.code === "validation" && /authorization_endpoint is required/.test(error.message),
  );
  assert.equal(vault.bindings.size, 0);
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
    () =>
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
    (error) => {
      assert.match(error.message, /OAuth callback requires vault material/);
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(typeof error.details.oauth_state_hash, "string");
      assert.deepEqual(error.details.missing, ["state", "token_endpoint", "redirect_uri", "client_id", "code_verifier"]);
      assert.deepEqual(error.details.evidence_refs, ["oauth_callback_fail_closed", "VaultPort.resolveVaultRef"]);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "oauthStateHash"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
});

test("OAuth credential provider rejects callback state mismatch with canonical details", async () => {
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
    },
  });

  await assert.rejects(
    () =>
      provider.completeAuthorization({
        providerId: "catalog.huggingface",
        stateRecord: started.state,
        body: { state: "wrong-state", code: "code" },
      }),
    (error) => {
      assert.match(error.message, /state mismatch/);
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(typeof error.details.oauth_state_hash, "string");
      assert.equal(typeof error.details.callback_state_hash, "string");
      assert.deepEqual(error.details.evidence_refs, ["oauth_callback_state_mismatch", "OAuthCredentialProvider.completeAuthorization"]);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "oauthStateHash"), false);
      assert.equal(Object.hasOwn(error.details, "callbackStateHash"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
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
    (error) => {
      assert.match(error.message, /client secrets must be provided through vault refs/);
      assert.equal(error.details.client_secret, "[REDACTED]");
      assert.equal(Object.hasOwn(error.details, "clientSecret"), false);
      return true;
    },
  );

  await assert.rejects(
    () =>
      provider.exchangeAuthorizationCode({
        providerId: "catalog.huggingface",
        body: {
          token_endpoint: "https://auth.example.test/token",
          authorization_code: "code",
          client_secret_vault_ref: "vault://oauth/client-secret",
        },
      }),
    (error) => {
      assert.match(error.message, /client secret vault ref is configured/);
      assert.equal(typeof error.details.client_secret_vault_ref_hash, "string");
      assert.deepEqual(error.details.evidence_refs, ["VaultPort.resolveVaultRef"]);
      assert.equal(Object.hasOwn(error.details, "clientSecretVaultRefHash"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
});

test("OAuth credential provider exchanges authorization code with canonical vault bindings", async () => {
  const previousFetch = globalThis.fetch;
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ now, vault });
  const fetchCalls = [];
  try {
    globalThis.fetch = async (url, options) => {
      fetchCalls.push([url, Object.fromEntries(new URLSearchParams(String(options.body)).entries())]);
      return {
        ok: true,
        json: async () => ({
          access_token: "access-token",
          accessToken: "retired-access-token",
          refresh_token: "refresh-token",
          refreshToken: "retired-refresh-token",
          expires_in: 600,
          expiresIn: 1,
          scope: "repo model",
        }),
      };
    };

    const exchanged = await provider.exchangeAuthorizationCode({
      providerId: "catalog.huggingface",
      body: {
        session_id: "session.exchange",
        sessionId: "session.retired",
        token_endpoint: "https://auth.example.test/token",
        tokenEndpoint: "https://retired.example.test/token",
        token_endpoint_vault_ref: "vault://oauth/token-endpoint",
        tokenEndpointVaultRef: "vault://oauth/retired-token-endpoint",
        authorization_code: "auth-code",
        authorizationCode: "retired-auth-code",
        redirect_uri: "https://app.example.test/callback",
        redirectUri: "https://retired.example.test/callback",
        client_id: "client-id",
        clientId: "retired-client-id",
        client_id_vault_ref: "vault://oauth/client-id",
        clientIdVaultRef: "vault://oauth/retired-client-id",
        code_verifier: "code-verifier",
        codeVerifier: "retired-code-verifier",
        access_vault_ref: "vault://oauth/access",
        accessVaultRef: "vault://oauth/retired-access",
        refresh_vault_ref: "vault://oauth/refresh",
        refreshVaultRef: "vault://oauth/retired-refresh",
        scopes: ["repo"],
      },
    });

    assert.equal(fetchCalls[0][0], "https://auth.example.test/token");
    assert.equal(fetchCalls[0][1].code, "auth-code");
    assert.equal(fetchCalls[0][1].client_id, "client-id");
    assert.equal(fetchCalls[0][1].redirect_uri, "https://app.example.test/callback");
    assert.equal(fetchCalls[0][1].code_verifier, "code-verifier");
    assert.equal(exchanged.session.id, "session.exchange");
    assert.equal(exchanged.session.accessVaultRef, "vault://oauth/access");
    assert.equal(exchanged.session.refreshVaultRef, "vault://oauth/refresh");
    assert.equal(exchanged.session.tokenEndpointVaultRef, "vault://oauth/token-endpoint");
    assert.equal(exchanged.session.clientIdVaultRef, "vault://oauth/client-id");
    assert.equal(vault.bindings.get("vault://oauth/access").material, "access-token");
    assert.equal(vault.bindings.get("vault://oauth/refresh").material, "refresh-token");
    assert.equal(vault.bindings.has("vault://oauth/retired-access"), false);
    assert.equal(vault.bindings.has("vault://oauth/retired-refresh"), false);
    assert.equal(exchanged.session.expiresAt, "2026-06-03T00:10:00.000Z");
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OAuth credential provider ignores retired exchange request aliases", async () => {
  const previousFetch = globalThis.fetch;
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ now, vault });
  let fetched = false;
  try {
    globalThis.fetch = async () => {
      fetched = true;
      return { ok: true, json: async () => ({ access_token: "access-token" }) };
    };
    await assert.rejects(
      () => provider.exchangeAuthorizationCode({
        providerId: "catalog.huggingface",
        body: {
          sessionId: "session.retired",
          tokenEndpoint: "https://auth.example.test/token",
          tokenEndpointVaultRef: "vault://oauth/retired-token-endpoint",
          authorizationCode: "auth-code",
          code: "auth-code",
          redirectUri: "https://app.example.test/callback",
          clientId: "client-id",
          clientIdVaultRef: "vault://oauth/retired-client-id",
          codeVerifier: "code-verifier",
          clientSecretVaultRef: "vault://oauth/retired-client-secret",
          accessVaultRef: "vault://oauth/retired-access",
          refreshVaultRef: "vault://oauth/retired-refresh",
        },
      }),
      (error) => error.code === "validation" && /token_endpoint is required/.test(error.message),
    );
    assert.equal(fetched, false);
    assert.equal(vault.bindings.size, 0);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OAuth credential provider rejects invalid authorization states with canonical details", async () => {
  const provider = new OAuthCredentialProvider({ now, vault: fakeVault() });
  const stateRecord = {
    id: "state.one",
    providerId: "catalog.huggingface",
    sessionId: "session.one",
    status: "pending",
    expiresAt: "2026-06-03T00:10:00.000Z",
  };

  await assert.rejects(
    () => provider.completeAuthorization({ providerId: "catalog.huggingface", stateRecord: null }),
    (error) => {
      assert.match(error.message, /state not found/);
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      return true;
    },
  );

  await assert.rejects(
    () => provider.completeAuthorization({ providerId: "catalog.custom", stateRecord }),
    (error) => {
      assert.match(error.message, /does not belong/);
      assert.equal(error.details.provider_id, "catalog.custom");
      assert.equal(error.details.state_provider_id, "catalog.huggingface");
      assert.equal(typeof error.details.oauth_state_hash, "string");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "stateProviderId"), false);
      assert.equal(Object.hasOwn(error.details, "oauthStateHash"), false);
      return true;
    },
  );

  await assert.rejects(
    () => provider.completeAuthorization({ providerId: "catalog.huggingface", stateRecord: { ...stateRecord, status: "completed" } }),
    (error) => {
      assert.match(error.message, /not pending/);
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.status, "completed");
      assert.equal(typeof error.details.oauth_state_hash, "string");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "oauthStateHash"), false);
      return true;
    },
  );

  await assert.rejects(
    () =>
      provider.completeAuthorization({
        providerId: "catalog.huggingface",
        stateRecord: { ...stateRecord, expiresAt: "2026-06-02T00:00:00.000Z" },
      }),
    (error) => {
      assert.match(error.message, /expired/);
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.status, "expired");
      assert.equal(typeof error.details.oauth_state_hash, "string");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "oauthStateHash"), false);
      return true;
    },
  );
});

test("OAuth credential provider refresh and access failures use canonical details", async () => {
  const provider = new OAuthCredentialProvider({ now, vault: fakeVault() });

  await assert.rejects(
    () => provider.refreshAccessToken({ id: "session.one", status: "revoked" }),
    (error) => {
      assert.match(error.message, /session is not active/);
      assert.equal(error.details.status, "revoked");
      assert.equal(typeof error.details.oauth_session_hash, "string");
      assert.equal(Object.hasOwn(error.details, "oauthSessionHash"), false);
      return true;
    },
  );

  await assert.rejects(
    () => provider.refreshAccessToken({ id: "session.one", status: "active" }),
    (error) => {
      assert.match(error.message, /no refresh token vault ref/);
      assert.equal(typeof error.details.oauth_session_hash, "string");
      assert.deepEqual(error.details.evidence_refs, ["oauth_refresh_fail_closed", "refresh_vault_ref_required"]);
      assert.equal(Object.hasOwn(error.details, "oauthSessionHash"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );

  await assert.rejects(
    () =>
      provider.refreshAccessToken({
        id: "session.one",
        providerId: "catalog.huggingface",
        status: "active",
        refreshVaultRef: "vault://refresh",
        tokenEndpointVaultRef: "vault://token-endpoint",
      }),
    (error) => {
      assert.match(error.message, /refresh requires vault material/);
      assert.equal(typeof error.details.oauth_session_hash, "string");
      assert.deepEqual(error.details.missing, ["refresh_token", "token_endpoint"]);
      assert.deepEqual(error.details.evidence_refs, ["oauth_refresh_fail_closed", "VaultPort.resolveVaultRef"]);
      assert.equal(Object.hasOwn(error.details, "oauthSessionHash"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );

  await assert.rejects(
    () => provider.resolveAccessHeader({ id: "session.one", status: "revoked" }, { headerName: "authorization" }),
    (error) => {
      assert.match(error.message, /session is not active/);
      assert.equal(error.details.status, "revoked");
      assert.equal(error.details.catalog_auth_scheme, "oauth2");
      assert.equal(typeof error.details.catalog_auth_header_name_hash, "string");
      assert.equal(error.details.oauth_boundary.status, "revoked");
      assert.deepEqual(error.details.evidence_refs, ["OAuthCredentialProvider.resolveAccessHeader", "oauth_session_inactive"]);
      assert.equal(Object.hasOwn(error.details, "oauthSessionHash"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthScheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthHeaderNameHash"), false);
      assert.equal(Object.hasOwn(error.details, "oauthBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );

  await assert.rejects(
    () =>
      provider.resolveAccessHeader(
        {
          id: "session.one",
          providerId: "catalog.huggingface",
          status: "active",
          accessVaultRef: "vault://access",
          accessVaultRefHash: "hash:access",
          expiresAt: "2026-06-03T00:10:00.000Z",
        },
        { headerName: "authorization" },
      ),
    (error) => {
      assert.match(error.message, /access token vault ref is configured/);
      assert.equal(typeof error.details.oauth_session_hash, "string");
      assert.equal(typeof error.details.auth_vault_ref_hash, "string");
      assert.equal(error.details.resolved_material, false);
      assert.equal(error.details.catalog_auth_scheme, "oauth2");
      assert.equal(typeof error.details.catalog_auth_header_name_hash, "string");
      assert.equal(error.details.oauth_boundary.status, "active");
      assert.deepEqual(error.details.evidence_refs, ["VaultPort.resolveVaultRef"]);
      assert.equal(Object.hasOwn(error.details, "oauthSessionHash"), false);
      assert.equal(Object.hasOwn(error.details, "authVaultRefHash"), false);
      assert.equal(Object.hasOwn(error.details, "resolvedMaterial"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthScheme"), false);
      assert.equal(Object.hasOwn(error.details, "catalogAuthHeaderNameHash"), false);
      assert.equal(Object.hasOwn(error.details, "oauthBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
});

test("OAuth credential provider refreshes access tokens with canonical response fields", async () => {
  const previousFetch = globalThis.fetch;
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ now, vault });
  vault.bindVaultRef({ vaultRef: "vault://access", material: "old-access", purpose: "oauth.access_token:catalog.huggingface" });
  vault.bindVaultRef({ vaultRef: "vault://refresh", material: "refresh-token", purpose: "oauth.refresh_token:catalog.huggingface" });
  vault.bindVaultRef({ vaultRef: "vault://token-endpoint", material: "https://auth.example.test/token", purpose: "oauth.token_endpoint:catalog.huggingface" });
  vault.bindVaultRef({ vaultRef: "vault://client-id", material: "client-id", purpose: "oauth.client_id:catalog.huggingface" });

  try {
    globalThis.fetch = async (url, options) => {
      const form = Object.fromEntries(new URLSearchParams(String(options.body)).entries());
      assert.equal(url, "https://auth.example.test/token");
      assert.equal(form.grant_type, "refresh_token");
      assert.equal(form.refresh_token, "refresh-token");
      assert.equal(form.client_id, "client-id");
      return {
        ok: true,
        json: async () => ({
          access_token: "new-access-token",
          accessToken: "retired-access-token",
          refresh_token: "new-refresh-token",
          refreshToken: "retired-refresh-token",
          expires_in: 600,
          expiresIn: 1,
          scope: "repo model",
        }),
      };
    };

    const refreshed = await provider.refreshAccessToken({
      id: "session.one",
      providerId: "catalog.huggingface",
      status: "active",
      accessVaultRef: "vault://access",
      refreshVaultRef: "vault://refresh",
      tokenEndpointVaultRef: "vault://token-endpoint",
      clientIdVaultRef: "vault://client-id",
      accessVaultRefHash: "hash:access",
      refreshVaultRefHash: "hash:refresh",
      refreshTokenHash: "hash:old-refresh",
      refreshCount: 2,
      scopes: ["repo"],
      evidenceRefs: ["VaultOAuthSession"],
    });

    assert.equal(vault.bindings.get("vault://access").material, "new-access-token");
    assert.equal(vault.bindings.get("vault://refresh").material, "new-refresh-token");
    assert.equal(refreshed.expiresAt, "2026-06-03T00:10:00.000Z");
    assert.equal(refreshed.refreshCount, 3);
    assert.deepEqual(refreshed.scopes, ["repo", "model"]);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("OAuth credential provider ignores retired refresh token response aliases", async () => {
  const previousFetch = globalThis.fetch;
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ now, vault });
  vault.bindVaultRef({ vaultRef: "vault://access", material: "old-access", purpose: "oauth.access_token:catalog.huggingface" });
  vault.bindVaultRef({ vaultRef: "vault://refresh", material: "refresh-token", purpose: "oauth.refresh_token:catalog.huggingface" });
  vault.bindVaultRef({ vaultRef: "vault://token-endpoint", material: "https://auth.example.test/token", purpose: "oauth.token_endpoint:catalog.huggingface" });

  try {
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({
        accessToken: "retired-access-token",
        refreshToken: "retired-refresh-token",
        expiresIn: 600,
      }),
    });

    await assert.rejects(
      () =>
        provider.refreshAccessToken({
          id: "session.one",
          providerId: "catalog.huggingface",
          status: "active",
          accessVaultRef: "vault://access",
          refreshVaultRef: "vault://refresh",
          tokenEndpointVaultRef: "vault://token-endpoint",
          refreshCount: 0,
          scopes: ["repo"],
        }),
      (error) => error.code === "provider_error" && /did not return an access token/.test(error.message),
    );
    assert.equal(vault.bindings.get("vault://access").material, "old-access");
    assert.equal(vault.bindings.get("vault://refresh").material, "refresh-token");
  } finally {
    globalThis.fetch = previousFetch;
  }
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
