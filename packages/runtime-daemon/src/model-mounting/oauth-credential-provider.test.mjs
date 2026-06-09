import assert from "node:assert/strict";
import { test } from "node:test";

import { OAuthCredentialProvider } from "./oauth-credential-provider.mjs";

function fakeVault() {
  return {
    bindCount: 0,
    resolveCount: 0,
    removeCount: 0,
    bindVaultRef() {
      this.bindCount += 1;
      throw new Error("OAuth JS custody must not bind vault refs");
    },
    resolveVaultRef() {
      this.resolveCount += 1;
      throw new Error("OAuth JS custody must not resolve vault refs");
    },
    removeVaultRef() {
      this.removeCount += 1;
      throw new Error("OAuth JS custody must not remove vault refs");
    },
  };
}

function assertRetiredOAuthError(error, operationKind) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_oauth_credential_provider_js_retired");
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_oauth_custody");
  assert.deepEqual(error.details.evidence_refs, [
    "oauth_credential_provider_js_retired",
    "rust_daemon_core_catalog_provider_oauth_required",
    "rust_daemon_core_wallet_ctee_custody_required",
  ]);
  assert.equal(Object.hasOwn(error.details, "providerId"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
  assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
  return true;
}

test("OAuth credential provider start authorization fails before JS vault binding", () => {
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ vault });

  assert.throws(
    () =>
      provider.startAuthorization({
        providerId: "catalog.huggingface",
        body: {
          state_id: "state.one",
          authorization_endpoint: "https://auth.example.test/oauth",
          token_endpoint: "https://auth.example.test/token",
          redirect_uri: "https://app.example.test/callback",
          client_id: "client-id",
        },
      }),
    (error) => {
      assertRetiredOAuthError(error, "model_mount.catalog_provider_oauth.start_authorization");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(error.details.request_field_count, 5);
      return true;
    },
  );
  assert.equal(vault.bindCount, 0);
});

test("OAuth credential provider completion and exchange fail before token transport", async () => {
  const previousFetch = globalThis.fetch;
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ vault });
  let fetched = false;
  try {
    globalThis.fetch = async () => {
      fetched = true;
      return { ok: true, json: async () => ({ access_token: "token" }) };
    };

    await assert.rejects(
      () =>
        provider.completeAuthorization({
          providerId: "catalog.huggingface",
          stateRecord: { id: "state.one" },
          body: { state: "callback-state", code: "code" },
        }),
      (error) => {
        assertRetiredOAuthError(error, "model_mount.catalog_provider_oauth.complete_authorization");
        assert.equal(error.details.provider_id, "catalog.huggingface");
        assert.equal(typeof error.details.oauth_state_hash, "string");
        assert.equal(error.details.request_field_count, 2);
        return true;
      },
    );

    await assert.rejects(
      () =>
        provider.exchangeAuthorizationCode({
          providerId: "catalog.huggingface",
          body: {
            token_endpoint: "https://auth.example.test/token",
            authorization_code: "auth-code",
            access_vault_ref: "vault://oauth/access",
          },
        }),
      (error) => {
        assertRetiredOAuthError(error, "model_mount.catalog_provider_oauth.exchange_authorization_code");
        assert.equal(error.details.provider_id, "catalog.huggingface");
        assert.equal(error.details.request_field_count, 3);
        return true;
      },
    );
  } finally {
    globalThis.fetch = previousFetch;
  }

  assert.equal(fetched, false);
  assert.equal(vault.bindCount, 0);
  assert.equal(vault.resolveCount, 0);
});

test("OAuth credential provider refresh, revoke, and access-header resolution fail before JS custody", async () => {
  const vault = fakeVault();
  const provider = new OAuthCredentialProvider({ vault });
  const session = {
    id: "session.one",
    providerId: "catalog.huggingface",
    status: "active",
    accessVaultRef: "vault://oauth/access",
    refreshVaultRef: "vault://oauth/refresh",
  };

  await assert.rejects(
    () => provider.refreshAccessToken(session),
    (error) => {
      assertRetiredOAuthError(error, "model_mount.catalog_provider_oauth.refresh_access_token");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(typeof error.details.oauth_session_hash, "string");
      assert.equal(error.details.status, "active");
      return true;
    },
  );

  assert.throws(
    () => provider.revokeSession(session),
    (error) => {
      assertRetiredOAuthError(error, "model_mount.catalog_provider_oauth.revoke_session");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(typeof error.details.oauth_session_hash, "string");
      return true;
    },
  );

  await assert.rejects(
    () => provider.resolveAccessHeader(session, { headerName: "X-Catalog-Key" }),
    (error) => {
      assertRetiredOAuthError(error, "model_mount.catalog_provider_oauth.resolve_access_header");
      assert.equal(error.details.provider_id, "catalog.huggingface");
      assert.equal(typeof error.details.oauth_session_hash, "string");
      assert.equal(error.details.catalog_auth_scheme, "oauth2");
      assert.equal(typeof error.details.catalog_auth_header_name_hash, "string");
      return true;
    },
  );

  assert.equal(vault.bindCount, 0);
  assert.equal(vault.resolveCount, 0);
  assert.equal(vault.removeCount, 0);
});
