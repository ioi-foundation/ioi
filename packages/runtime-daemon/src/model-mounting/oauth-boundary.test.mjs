import test from "node:test";
import assert from "node:assert/strict";

import {
  oauthBoundaryForSession,
  oauthExpiresAt,
  oauthSessionNeedsRefresh,
  oauthSessionVaultRef,
  parseOAuthTokenResponse,
  pkceS256Challenge,
  publicOAuthSession,
  publicOAuthState,
  redactOAuthAuthorizationUrl,
} from "./oauth-boundary.mjs";

test("OAuth boundary helpers build deterministic vault refs and PKCE challenge", () => {
  assert.equal(
    oauthSessionVaultRef("catalog.huggingface", "session.one", "access-token"),
    "vault://ioi/oauth/catalog.huggingface/session.one/access.token",
  );
  assert.equal(pkceS256Challenge("verifier"), "iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ");
});

test("OAuth authorization URL redaction hides client and state material", () => {
  const url = new URL("https://auth.example.test/oauth");
  url.searchParams.set("client_id", "client");
  url.searchParams.set("state", "state");
  url.searchParams.set("code_challenge", "challenge");
  url.searchParams.set("redirect_uri", "https://app.example.test/callback");

  const redacted = redactOAuthAuthorizationUrl(url);

  assert.match(redacted, /client_id=%5BREDACTED%5D/);
  assert.match(redacted, /state=%5BREDACTED%5D/);
  assert.match(redacted, /code_challenge=%5BREDACTED%5D/);
  assert.match(redacted, /redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback/);
});

test("OAuth public projections preserve hashes without vault refs or token material", () => {
  const session = publicOAuthSession({
    id: "session-1",
    providerId: "catalog.huggingface",
    status: "active",
    accessVaultRef: "vault://access",
    refreshVaultRef: "vault://refresh",
    accessTokenHash: "hash-access",
    refreshTokenHash: "hash-refresh",
    scopes: "read write",
    evidenceRefs: ["VaultOAuthSession"],
  });

  assert.equal(session.id, "session-1");
  assert.equal(session.providerId, "catalog.huggingface");
  assert.equal(session.accessTokenHash, "hash-access");
  assert.equal(session.refreshTokenHash, "hash-refresh");
  assert.equal(session.accessVaultRef, undefined);
  assert.deepEqual(session.scopes, ["read", "write"]);

  const state = publicOAuthState({
    id: "state-1",
    providerId: "catalog.huggingface",
    status: "pending",
    stateVaultRef: "vault://state",
    codeVerifierHash: "hash-verifier",
    scopes: ["repo"],
  });

  assert.equal(state.id, "state-1");
  assert.equal(state.codeVerifierHash, "hash-verifier");
  assert.equal(state.stateVaultRef, undefined);
  assert.deepEqual(state.scopes, ["repo"]);
});

test("OAuth boundary status and refresh timing stay product-safe", () => {
  const now = new Date("2026-06-03T12:00:00.000Z");
  assert.equal(oauthExpiresAt(now, 60), "2026-06-03T12:01:00.000Z");
  assert.equal(oauthSessionNeedsRefresh({ expiresAt: "2026-06-03T12:00:20.000Z" }, now), true);
  assert.equal(oauthSessionNeedsRefresh({ expiresAt: "2026-06-03T12:02:00.000Z" }, now), false);

  assert.deepEqual(oauthBoundaryForSession(null), {
    configured: false,
    status: "requires_oauth_exchange",
    tokenExchange: "OAuthCredentialProvider.exchangeAuthorizationCode",
    evidenceRefs: ["catalog_oauth_boundary"],
  });

  const boundary = oauthBoundaryForSession({
    id: "session-1",
    status: "active",
    scopes: ["read"],
    refreshCount: 2,
    evidenceRefs: ["VaultOAuthSession"],
  }, { refreshed: true });

  assert.equal(boundary.configured, true);
  assert.equal(boundary.status, "refreshed");
  assert.equal(boundary.tokenExchange, "OAuthCredentialProvider");
  assert.equal(boundary.refreshCount, 2);
});

test("OAuth token response parsing requires an access token", async () => {
  await assert.rejects(
    () => parseOAuthTokenResponse({ json: async () => ({ token_type: "bearer" }) }),
    /did not return an access token/,
  );
  assert.deepEqual(
    await parseOAuthTokenResponse({ json: async () => ({ access_token: "token", expires_in: 10 }) }),
    { access_token: "token", expires_in: 10 },
  );
});
