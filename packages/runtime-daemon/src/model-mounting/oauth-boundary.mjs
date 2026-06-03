import crypto from "node:crypto";

import {
  fetchWithTimeout,
  normalizeOAuthScopes,
  normalizeScopes,
  runtimeError,
  safeId,
  stableHash,
} from "./io.mjs";
import { modelCatalogTimeoutMs } from "./environment.mjs";

const SECRET_REDACTION = "[REDACTED]";

export function oauthSessionVaultRef(providerId, sessionId, kind) {
  return `vault://ioi/oauth/${safeId(providerId)}/${safeId(sessionId)}/${safeId(kind)}`;
}

export function pkceS256Challenge(codeVerifier) {
  return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
}

export function redactOAuthAuthorizationUrl(authorizationUrl) {
  const redacted = new URL(authorizationUrl.toString());
  for (const key of ["client_id", "state", "code_challenge"]) {
    if (redacted.searchParams.has(key)) redacted.searchParams.set(key, SECRET_REDACTION);
  }
  return redacted.toString();
}

export function oauthExpiresAt(now, expiresIn) {
  const seconds = Number(expiresIn);
  const ttlMs = Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 3600 * 1000;
  return new Date(now.getTime() + ttlMs).toISOString();
}

export function oauthSessionNeedsRefresh(session, now) {
  if (!session?.expiresAt) return false;
  const expiresAt = Date.parse(session.expiresAt);
  if (!Number.isFinite(expiresAt)) return true;
  return expiresAt <= now.getTime() + 30_000;
}

export function oauthBoundaryForSession(session, options = {}) {
  if (!session) {
    return {
      configured: false,
      status: "requires_oauth_exchange",
      tokenExchange: "OAuthCredentialProvider.exchangeAuthorizationCode",
      evidenceRefs: ["catalog_oauth_boundary"],
    };
  }
  return {
    configured: session.status === "active",
    status: session.status === "active" ? (options.refreshed ? "refreshed" : "active") : session.status ?? "unknown",
    tokenExchange: "OAuthCredentialProvider",
    oauthSessionHash: stableHash(session.id),
    expiresAt: session.expiresAt ?? null,
    scopes: normalizeOAuthScopes(session.scopes, []),
    refreshCount: Number(session.refreshCount ?? 0),
    evidenceRefs: normalizeScopes(session.evidenceRefs, ["catalog_oauth_boundary", "VaultOAuthSession"]),
  };
}

export function publicOAuthSession(session) {
  return {
    id: session.id,
    providerId: session.providerId,
    status: session.status,
    oauthSessionHash: stableHash(session.id),
    accessVaultRefHash: session.accessVaultRefHash ?? (session.accessVaultRef ? stableHash(session.accessVaultRef) : null),
    refreshVaultRefHash: session.refreshVaultRefHash ?? (session.refreshVaultRef ? stableHash(session.refreshVaultRef) : null),
    tokenEndpointVaultRefHash: session.tokenEndpointVaultRefHash ?? (session.tokenEndpointVaultRef ? stableHash(session.tokenEndpointVaultRef) : null),
    tokenEndpointHash: session.tokenEndpointHash ?? null,
    clientIdVaultRefHash: session.clientIdVaultRefHash ?? (session.clientIdVaultRef ? stableHash(session.clientIdVaultRef) : null),
    clientIdHash: session.clientIdHash ?? null,
    clientSecretVaultRefHash: session.clientSecretVaultRefHash ?? (session.clientSecretVaultRef ? stableHash(session.clientSecretVaultRef) : null),
    accessTokenHash: session.accessTokenHash ?? null,
    refreshTokenHash: session.refreshTokenHash ?? null,
    scopes: normalizeOAuthScopes(session.scopes, []),
    expiresAt: session.expiresAt ?? null,
    issuedAt: session.issuedAt ?? null,
    lastRefreshedAt: session.lastRefreshedAt ?? null,
    refreshCount: Number(session.refreshCount ?? 0),
    revokedAt: session.revokedAt ?? null,
    evidenceRefs: normalizeScopes(session.evidenceRefs, ["VaultOAuthSession"]),
  };
}

export function publicOAuthState(state) {
  return {
    id: state.id,
    providerId: state.providerId,
    status: state.status,
    oauthStateHash: stableHash(state.id),
    stateVaultRefHash: state.stateVaultRefHash ?? (state.stateVaultRef ? stableHash(state.stateVaultRef) : null),
    stateHash: state.stateHash ?? null,
    codeVerifierVaultRefHash: state.codeVerifierVaultRefHash ?? (state.codeVerifierVaultRef ? stableHash(state.codeVerifierVaultRef) : null),
    codeVerifierHash: state.codeVerifierHash ?? null,
    codeChallengeHash: state.codeChallengeHash ?? null,
    authorizationEndpointVaultRefHash:
      state.authorizationEndpointVaultRefHash ?? (state.authorizationEndpointVaultRef ? stableHash(state.authorizationEndpointVaultRef) : null),
    authorizationEndpointHash: state.authorizationEndpointHash ?? null,
    tokenEndpointVaultRefHash: state.tokenEndpointVaultRefHash ?? (state.tokenEndpointVaultRef ? stableHash(state.tokenEndpointVaultRef) : null),
    tokenEndpointHash: state.tokenEndpointHash ?? null,
    redirectUriVaultRefHash: state.redirectUriVaultRefHash ?? (state.redirectUriVaultRef ? stableHash(state.redirectUriVaultRef) : null),
    redirectUriHash: state.redirectUriHash ?? null,
    clientIdVaultRefHash: state.clientIdVaultRefHash ?? (state.clientIdVaultRef ? stableHash(state.clientIdVaultRef) : null),
    clientIdHash: state.clientIdHash ?? null,
    scopes: normalizeOAuthScopes(state.scopes, []),
    pkceRequired: Boolean(state.pkceRequired),
    createdAt: state.createdAt ?? null,
    expiresAt: state.expiresAt ?? null,
    completedAt: state.completedAt ?? null,
    oauthSessionHash: state.oauthSessionHash ?? null,
    evidenceRefs: normalizeScopes(state.evidenceRefs, ["VaultOAuthAuthorizationState"]),
  };
}

export async function fetchOAuthToken(tokenEndpoint, payload) {
  const response = await fetchWithTimeout(tokenEndpoint, {
    method: "POST",
    timeoutMs: modelCatalogTimeoutMs(),
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(payload),
  });
  if (!response.ok) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "OAuth token endpoint rejected the credential exchange.",
      details: {
        tokenEndpointHash: stableHash(tokenEndpoint),
        errorHash: stableHash(`oauth:${response.status}`),
        evidenceRefs: ["OAuthCredentialProvider.tokenEndpoint", "oauth_exchange_fail_closed"],
      },
    });
  }
  return response;
}

export async function parseOAuthTokenResponse(response) {
  const payload = await response.json();
  if (!payload || typeof payload !== "object" || !payload.access_token) {
    throw runtimeError({
      status: 502,
      code: "provider_error",
      message: "OAuth token endpoint did not return an access token.",
      details: { evidenceRefs: ["OAuthCredentialProvider.tokenEndpoint", "oauth_access_token_required"] },
    });
  }
  return payload;
}
