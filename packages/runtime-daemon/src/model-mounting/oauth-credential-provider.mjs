import crypto from "node:crypto";

import {
  fetchOAuthToken,
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
import {
  normalizeOAuthScopes,
  normalizeScopes,
  runtimeError,
  safeId,
  stableHash,
  truthy,
} from "./io.mjs";

const MODEL_MOUNT_SCHEMA_VERSION = "ioi.model-mounting.runtime.v1";
const SECRET_REDACTION = "[REDACTED]";

export class OAuthCredentialProvider {
  constructor({ now, vault }) {
    this.now = now;
    this.vault = vault;
  }

  startAuthorization({ providerId, body = {} }) {
    const stateId = body.state_id ?? body.stateId ?? `oauth_state.${safeId(providerId)}.${crypto.randomUUID()}`;
    const sessionId = body.session_id ?? body.sessionId ?? `oauth_session.${safeId(providerId)}.${crypto.randomUUID()}`;
    const authorizationEndpointInput = requiredString(
      body.authorization_endpoint ?? body.authorizationEndpoint ?? body.auth_url ?? body.authUrl,
      "authorization_endpoint",
    );
    const tokenEndpointInput = requiredString(body.token_endpoint ?? body.tokenEndpoint, "token_endpoint");
    const redirectUriInput = requiredString(body.redirect_uri ?? body.redirectUri, "redirect_uri");
    const clientIdInput = requiredString(body.client_id ?? body.clientId, "client_id");
    const scopes = normalizeOAuthScopes(body.scopes ?? body.scope, []);
    const pkceRequired =
      body.pkce_required === undefined && body.pkceRequired === undefined ? true : truthy(body.pkce_required ?? body.pkceRequired);
    const stateTtlSeconds = Number(body.state_ttl_seconds ?? body.stateTtlSeconds ?? 600);
    const ttlMs = Number.isFinite(stateTtlSeconds) ? Math.max(0, stateTtlSeconds) * 1000 : 600_000;
    const rawState = crypto.randomBytes(24).toString("base64url");
    const codeVerifier = crypto.randomBytes(48).toString("base64url");
    const codeChallenge = pkceRequired ? pkceS256Challenge(codeVerifier) : null;
    const stateVaultRef = body.state_vault_ref ?? body.stateVaultRef ?? oauthSessionVaultRef(providerId, stateId, "state");
    const codeVerifierVaultRef = pkceRequired
      ? body.code_verifier_vault_ref ?? body.codeVerifierVaultRef ?? oauthSessionVaultRef(providerId, stateId, "code-verifier")
      : null;
    const authorizationEndpointVaultRef =
      body.authorization_endpoint_vault_ref ?? body.authorizationEndpointVaultRef ?? oauthSessionVaultRef(providerId, stateId, "authorization-endpoint");
    const tokenEndpointVaultRef = body.token_endpoint_vault_ref ?? body.tokenEndpointVaultRef ?? oauthSessionVaultRef(providerId, stateId, "token-endpoint");
    const redirectUriVaultRef = body.redirect_uri_vault_ref ?? body.redirectUriVaultRef ?? oauthSessionVaultRef(providerId, stateId, "redirect-uri");
    const clientIdVaultRef = body.client_id_vault_ref ?? body.clientIdVaultRef ?? oauthSessionVaultRef(providerId, stateId, "client-id");
    const stateBinding = this.vault.bindVaultRef({
      vaultRef: stateVaultRef,
      material: rawState,
      purpose: `oauth.state:${providerId}`,
      label: `OAuth authorization state for ${providerId}`,
    });
    const verifierBinding = codeVerifierVaultRef
      ? this.vault.bindVaultRef({
          vaultRef: codeVerifierVaultRef,
          material: codeVerifier,
          purpose: `oauth.code_verifier:${providerId}`,
          label: `OAuth PKCE verifier for ${providerId}`,
        })
      : null;
    const authorizationEndpointBinding = this.vault.bindVaultRef({
      vaultRef: authorizationEndpointVaultRef,
      material: authorizationEndpointInput,
      purpose: `oauth.authorization_endpoint:${providerId}`,
      label: `OAuth authorization endpoint for ${providerId}`,
    });
    const tokenEndpointBinding = this.vault.bindVaultRef({
      vaultRef: tokenEndpointVaultRef,
      material: tokenEndpointInput,
      purpose: `oauth.token_endpoint:${providerId}`,
      label: `OAuth token endpoint for ${providerId}`,
    });
    const redirectUriBinding = this.vault.bindVaultRef({
      vaultRef: redirectUriVaultRef,
      material: redirectUriInput,
      purpose: `oauth.redirect_uri:${providerId}`,
      label: `OAuth redirect URI for ${providerId}`,
    });
    const clientIdBinding = this.vault.bindVaultRef({
      vaultRef: clientIdVaultRef,
      material: clientIdInput,
      purpose: `oauth.client_id:${providerId}`,
      label: `OAuth client id for ${providerId}`,
    });
    const authorizationUrl = new URL(authorizationEndpointInput);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("client_id", clientIdInput);
    authorizationUrl.searchParams.set("redirect_uri", redirectUriInput);
    authorizationUrl.searchParams.set("state", rawState);
    if (scopes.length > 0) authorizationUrl.searchParams.set("scope", scopes.join(" "));
    if (pkceRequired) {
      authorizationUrl.searchParams.set("code_challenge", codeChallenge);
      authorizationUrl.searchParams.set("code_challenge_method", "S256");
    }
    const now = this.now();
    const record = {
      id: stateId,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      providerId,
      sessionId,
      status: "pending",
      stateVaultRef,
      stateVaultRefHash: stateBinding.vaultRefHash,
      stateHash: stableHash(rawState),
      codeVerifierVaultRef,
      codeVerifierVaultRefHash: verifierBinding?.vaultRefHash ?? null,
      codeVerifierHash: pkceRequired ? stableHash(codeVerifier) : null,
      codeChallengeHash: pkceRequired ? stableHash(codeChallenge) : null,
      authorizationEndpointVaultRef,
      authorizationEndpointVaultRefHash: authorizationEndpointBinding.vaultRefHash,
      authorizationEndpointHash: stableHash(authorizationEndpointInput),
      tokenEndpointVaultRef,
      tokenEndpointVaultRefHash: tokenEndpointBinding.vaultRefHash,
      tokenEndpointHash: stableHash(tokenEndpointInput),
      redirectUriVaultRef,
      redirectUriVaultRefHash: redirectUriBinding.vaultRefHash,
      redirectUriHash: stableHash(redirectUriInput),
      clientIdVaultRef,
      clientIdVaultRefHash: clientIdBinding.vaultRefHash,
      clientIdHash: stableHash(clientIdInput),
      scopes,
      pkceRequired: Boolean(pkceRequired),
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
      completedAt: null,
      oauthSessionHash: null,
      evidenceRefs: [
        "OAuthCredentialProvider.startAuthorization",
        pkceRequired ? "OAuthCredentialProvider.pkce_s256" : null,
        "VaultOAuthAuthorizationState",
        "VaultPort.bindVaultRef",
        "oauth_authorization_state_not_persisted",
      ].filter(Boolean),
    };
    const redactedUrl = redactOAuthAuthorizationUrl(authorizationUrl);
    return {
      state: record,
      evidence: publicOAuthState(record),
      authorizationUrl: authorizationUrl.toString(),
      authorizationUrlRedacted: redactedUrl,
      authorizationUrlHash: stableHash(authorizationUrl.toString()),
    };
  }

  async completeAuthorization({ providerId, stateRecord, body = {} }) {
    if (!stateRecord) {
      throw runtimeError({ status: 404, code: "not_found", message: "OAuth authorization state not found.", details: { provider_id: providerId } });
    }
    if (stateRecord.providerId !== providerId) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth authorization state does not belong to the requested provider.",
        details: { provider_id: providerId, state_provider_id: stateRecord.providerId, oauth_state_hash: stableHash(stateRecord.id) },
      });
    }
    if (stateRecord.status !== "pending") {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth authorization state is not pending.",
        details: { provider_id: providerId, status: stateRecord.status, oauth_state_hash: stableHash(stateRecord.id) },
      });
    }
    const expiresAt = Date.parse(stateRecord.expiresAt ?? "");
    if (!Number.isFinite(expiresAt) || expiresAt <= this.now().getTime()) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth authorization state expired.",
        details: { provider_id: providerId, oauth_state_hash: stableHash(stateRecord.id), status: "expired" },
      });
    }
    const callbackState = requiredString(body.state ?? body.oauth_state ?? body.oauthState, "state");
    const code = requiredString(body.code ?? body.authorization_code ?? body.authorizationCode, "code");
    const state = this.vault.resolveVaultRef(stateRecord.stateVaultRef, `oauth.state:${providerId}`);
    const tokenEndpoint = this.vault.resolveVaultRef(stateRecord.tokenEndpointVaultRef, `oauth.token_endpoint:${providerId}`);
    const redirectUri = this.vault.resolveVaultRef(stateRecord.redirectUriVaultRef, `oauth.redirect_uri:${providerId}`);
    const clientId = this.vault.resolveVaultRef(stateRecord.clientIdVaultRef, `oauth.client_id:${providerId}`);
    const codeVerifier = stateRecord.pkceRequired
      ? this.vault.resolveVaultRef(stateRecord.codeVerifierVaultRef, `oauth.code_verifier:${providerId}`)
      : null;
    const missing = [
      !state?.material ? "state" : null,
      !tokenEndpoint?.material ? "token_endpoint" : null,
      !redirectUri?.material ? "redirect_uri" : null,
      !clientId?.material ? "client_id" : null,
      stateRecord.pkceRequired && !codeVerifier?.material ? "code_verifier" : null,
    ].filter(Boolean);
    if (missing.length > 0) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth callback requires vault material that is not currently available.",
        details: {
          provider_id: providerId,
          oauth_state_hash: stableHash(stateRecord.id),
          missing,
          evidence_refs: ["oauth_callback_fail_closed", "VaultPort.resolveVaultRef"],
        },
      });
    }
    if (callbackState !== state.material) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth callback state mismatch.",
        details: {
          provider_id: providerId,
          oauth_state_hash: stableHash(stateRecord.id),
          callback_state_hash: stableHash(callbackState),
          evidence_refs: ["oauth_callback_state_mismatch", "OAuthCredentialProvider.completeAuthorization"],
        },
      });
    }
    const exchanged = await this.exchangeAuthorizationCode({
      providerId,
      body: {
        session_id: stateRecord.sessionId,
        token_endpoint: tokenEndpoint.material,
        token_endpoint_vault_ref: stateRecord.tokenEndpointVaultRef,
        authorization_code: code,
        redirect_uri: redirectUri.material,
        client_id: clientId.material,
        client_id_vault_ref: stateRecord.clientIdVaultRef,
        code_verifier: codeVerifier?.material ?? null,
        scopes: stateRecord.scopes ?? [],
      },
    });
    const completedState = {
      ...stateRecord,
      status: "completed",
      completedAt: this.now().toISOString(),
      oauthSessionHash: stableHash(exchanged.session.id),
      evidenceRefs: normalizeScopes(
        [
          ...normalizeScopes(stateRecord.evidenceRefs, []),
          "OAuthCredentialProvider.completeAuthorization",
          "oauth_callback_state_validated",
          stateRecord.pkceRequired ? "OAuthCredentialProvider.pkce_s256" : null,
        ].filter(Boolean),
        [],
      ),
    };
    return {
      session: exchanged.session,
      sessionEvidence: exchanged.evidence,
      state: completedState,
      stateEvidence: publicOAuthState(completedState),
      tokenResponseKind: exchanged.tokenResponseKind,
    };
  }

  async exchangeAuthorizationCode({ providerId, body = {} }) {
    const sessionId = body.session_id ?? body.sessionId ?? `oauth_session.${safeId(providerId)}.${crypto.randomUUID()}`;
    const tokenEndpointInput = requiredString(body.token_endpoint ?? body.tokenEndpoint, "token_endpoint");
    const authorizationCode = requiredString(body.authorization_code ?? body.authorizationCode ?? body.code, "authorization_code");
    const scopes = normalizeOAuthScopes(body.scopes ?? body.scope, []);
    const redirectUri = body.redirect_uri ?? body.redirectUri ?? null;
    const clientIdInput = body.client_id ?? body.clientId ?? null;
    const codeVerifierInput = body.code_verifier ?? body.codeVerifier ?? null;
    const clientSecretVaultRef = body.client_secret_vault_ref ?? body.clientSecretVaultRef ?? null;
    if (body.client_secret || body.clientSecret) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth client secrets must be provided through vault refs.",
        details: { client_secret: SECRET_REDACTION },
      });
    }
    const tokenEndpointVaultRef = body.token_endpoint_vault_ref ?? body.tokenEndpointVaultRef ?? oauthSessionVaultRef(providerId, sessionId, "token-endpoint");
    const tokenEndpointBinding = this.vault.bindVaultRef({
      vaultRef: tokenEndpointVaultRef,
      material: tokenEndpointInput,
      purpose: `oauth.token_endpoint:${providerId}`,
      label: `OAuth token endpoint for ${providerId}`,
    });
    let clientIdVaultRef = body.client_id_vault_ref ?? body.clientIdVaultRef ?? null;
    let clientIdBinding = null;
    if (typeof clientIdInput === "string" && clientIdInput.trim()) {
      clientIdVaultRef = clientIdVaultRef ?? oauthSessionVaultRef(providerId, sessionId, "client-id");
      clientIdBinding = this.vault.bindVaultRef({
        vaultRef: clientIdVaultRef,
        material: clientIdInput.trim(),
        purpose: `oauth.client_id:${providerId}`,
        label: `OAuth client id for ${providerId}`,
      });
    }
    const clientSecret = clientSecretVaultRef
      ? this.vault.resolveVaultRef(clientSecretVaultRef, `oauth.client_secret:${providerId}`)
      : null;
    if (clientSecretVaultRef && !clientSecret?.material) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth client secret vault ref is configured, but no runtime vault material is available.",
        details: {
          client_secret_vault_ref_hash: clientSecret?.vaultRefHash ?? stableHash(clientSecretVaultRef),
          evidence_refs: normalizeScopes(clientSecret?.evidenceRefs, ["VaultPort.resolveVaultRef", "oauth_client_secret_fail_closed"]),
        },
      });
    }
    const payload = {
      grant_type: "authorization_code",
      code: authorizationCode,
      ...(redirectUri ? { redirect_uri: String(redirectUri) } : {}),
      ...(clientIdInput ? { client_id: String(clientIdInput) } : {}),
      ...(clientSecret?.material ? { client_secret: clientSecret.material } : {}),
      ...(codeVerifierInput ? { code_verifier: String(codeVerifierInput) } : {}),
      ...(scopes.length > 0 ? { scope: scopes.join(" ") } : {}),
    };
    const response = await fetchOAuthToken(tokenEndpointInput, payload);
    const tokenPayload = await parseOAuthTokenResponse(response);
    const now = this.now().toISOString();
    const expiresAt = oauthExpiresAt(this.now(), tokenPayload.expires_in ?? tokenPayload.expiresIn);
    const accessVaultRef = body.access_vault_ref ?? body.accessVaultRef ?? oauthSessionVaultRef(providerId, sessionId, "access-token");
    const accessBinding = this.vault.bindVaultRef({
      vaultRef: accessVaultRef,
      material: requiredString(tokenPayload.access_token ?? tokenPayload.accessToken, "access_token"),
      purpose: `oauth.access_token:${providerId}`,
      label: `OAuth access token for ${providerId}`,
    });
    const refreshToken = tokenPayload.refresh_token ?? tokenPayload.refreshToken ?? null;
    const refreshVaultRef = refreshToken
      ? body.refresh_vault_ref ?? body.refreshVaultRef ?? oauthSessionVaultRef(providerId, sessionId, "refresh-token")
      : null;
    const refreshBinding = refreshToken
      ? this.vault.bindVaultRef({
          vaultRef: refreshVaultRef,
          material: String(refreshToken),
          purpose: `oauth.refresh_token:${providerId}`,
          label: `OAuth refresh token for ${providerId}`,
        })
      : null;
    const session = {
      id: sessionId,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      providerId,
      status: "active",
      accessVaultRef,
      accessVaultRefHash: accessBinding.vaultRefHash,
      accessTokenHash: stableHash(String(tokenPayload.access_token ?? tokenPayload.accessToken)),
      refreshVaultRef,
      refreshVaultRefHash: refreshBinding?.vaultRefHash ?? null,
      refreshTokenHash: refreshToken ? stableHash(String(refreshToken)) : null,
      tokenEndpointVaultRef,
      tokenEndpointVaultRefHash: tokenEndpointBinding.vaultRefHash,
      tokenEndpointHash: stableHash(tokenEndpointInput),
      clientIdVaultRef,
      clientIdVaultRefHash: clientIdBinding?.vaultRefHash ?? (clientIdVaultRef ? stableHash(clientIdVaultRef) : null),
      clientIdHash: clientIdInput ? stableHash(String(clientIdInput)) : null,
      clientSecretVaultRef: clientSecretVaultRef ?? null,
      clientSecretVaultRefHash: clientSecret?.vaultRefHash ?? (clientSecretVaultRef ? stableHash(clientSecretVaultRef) : null),
      codeVerifierHash: codeVerifierInput ? stableHash(String(codeVerifierInput)) : null,
      scopes: normalizeOAuthScopes(tokenPayload.scope, scopes),
      expiresAt,
      issuedAt: now,
      lastRefreshedAt: null,
      refreshCount: 0,
      revokedAt: null,
      evidenceRefs: [
        "OAuthCredentialProvider.exchangeAuthorizationCode",
        codeVerifierInput ? "OAuthCredentialProvider.pkce_s256" : null,
        "VaultOAuthSession",
        "VaultPort.bindVaultRef",
        "oauth_tokens_not_persisted",
      ].filter(Boolean),
    };
    return { session, evidence: publicOAuthSession(session), tokenResponseKind: "authorization_code" };
  }

  async refreshAccessToken(session) {
    if (!session || session.status !== "active") {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth session is not active.",
        details: { oauth_session_hash: session?.id ? stableHash(session.id) : null, status: session?.status ?? "missing" },
      });
    }
    if (!session.refreshVaultRef) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth session has no refresh token vault ref.",
        details: { oauth_session_hash: stableHash(session.id), evidence_refs: ["oauth_refresh_fail_closed", "refresh_vault_ref_required"] },
      });
    }
    const refresh = this.vault.resolveVaultRef(session.refreshVaultRef, `oauth.refresh_token:${session.providerId}`);
    const tokenEndpoint = this.vault.resolveVaultRef(session.tokenEndpointVaultRef, `oauth.token_endpoint:${session.providerId}`);
    const clientId = session.clientIdVaultRef
      ? this.vault.resolveVaultRef(session.clientIdVaultRef, `oauth.client_id:${session.providerId}`)
      : null;
    const clientSecret = session.clientSecretVaultRef
      ? this.vault.resolveVaultRef(session.clientSecretVaultRef, `oauth.client_secret:${session.providerId}`)
      : null;
    const missing = [
      !refresh?.material ? "refresh_token" : null,
      !tokenEndpoint?.material ? "token_endpoint" : null,
      session.clientIdVaultRef && !clientId?.material ? "client_id" : null,
      session.clientSecretVaultRef && !clientSecret?.material ? "client_secret" : null,
    ].filter(Boolean);
    if (missing.length > 0) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth refresh requires vault material that is not currently available.",
        details: {
          oauth_session_hash: stableHash(session.id),
          missing,
          evidence_refs: ["oauth_refresh_fail_closed", "VaultPort.resolveVaultRef"],
        },
      });
    }
    const payload = {
      grant_type: "refresh_token",
      refresh_token: refresh.material,
      ...(clientId?.material ? { client_id: clientId.material } : {}),
      ...(clientSecret?.material ? { client_secret: clientSecret.material } : {}),
      ...(session.scopes?.length ? { scope: session.scopes.join(" ") } : {}),
    };
    const response = await fetchOAuthToken(tokenEndpoint.material, payload);
    const tokenPayload = await parseOAuthTokenResponse(response);
    const accessToken = requiredString(tokenPayload.access_token ?? tokenPayload.accessToken, "access_token");
    const accessBinding = this.vault.bindVaultRef({
      vaultRef: session.accessVaultRef,
      material: accessToken,
      purpose: `oauth.access_token:${session.providerId}`,
      label: `OAuth access token for ${session.providerId}`,
    });
    const nextRefreshToken = tokenPayload.refresh_token ?? tokenPayload.refreshToken ?? null;
    let refreshBinding = null;
    if (nextRefreshToken) {
      refreshBinding = this.vault.bindVaultRef({
        vaultRef: session.refreshVaultRef,
        material: String(nextRefreshToken),
        purpose: `oauth.refresh_token:${session.providerId}`,
        label: `OAuth refresh token for ${session.providerId}`,
      });
    }
    return {
      ...session,
      status: "active",
      accessVaultRefHash: accessBinding.vaultRefHash,
      accessTokenHash: stableHash(accessToken),
      refreshVaultRefHash: refreshBinding?.vaultRefHash ?? session.refreshVaultRefHash ?? null,
      refreshTokenHash: nextRefreshToken ? stableHash(String(nextRefreshToken)) : session.refreshTokenHash ?? null,
      scopes: normalizeOAuthScopes(tokenPayload.scope, session.scopes ?? []),
      expiresAt: oauthExpiresAt(this.now(), tokenPayload.expires_in ?? tokenPayload.expiresIn),
      lastRefreshedAt: this.now().toISOString(),
      refreshCount: Number(session.refreshCount ?? 0) + 1,
      evidenceRefs: normalizeScopes(
        [
          ...normalizeScopes(session.evidenceRefs, []),
          "OAuthCredentialProvider.refreshAccessToken",
          "VaultOAuthSession",
          "oauth_refresh_tokens_not_persisted",
        ],
        [],
      ),
    };
  }

  revokeSession(session) {
    if (!session) {
      throw runtimeError({ status: 404, code: "not_found", message: "OAuth session not found.", details: {} });
    }
    for (const vaultRef of [session.accessVaultRef, session.refreshVaultRef].filter(Boolean)) {
      this.vault.removeVaultRef(vaultRef, `oauth.revoke:${session.providerId}`);
    }
    return {
      ...session,
      status: "revoked",
      revokedAt: this.now().toISOString(),
      evidenceRefs: normalizeScopes([...normalizeScopes(session.evidenceRefs, []), "OAuthCredentialProvider.revokeSession"], []),
    };
  }

  async resolveAccessHeader(session, { headerName = "authorization" } = {}) {
    let current = session;
    let refreshed = false;
    if (!current || current.status !== "active") {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth session is not active.",
        details: {
          oauth_session_hash: current?.id ? stableHash(current.id) : null,
          status: current?.status ?? "missing",
          catalog_auth_scheme: "oauth2",
          catalog_auth_header_name_hash: stableHash(headerName),
          oauth_boundary: oauthBoundaryForSession(current),
          evidence_refs: ["OAuthCredentialProvider.resolveAccessHeader", "oauth_session_inactive"],
        },
      });
    }
    if (oauthSessionNeedsRefresh(current, this.now())) {
      current = await this.refreshAccessToken(current);
      refreshed = true;
    }
    const access = this.vault.resolveVaultRef(current.accessVaultRef, `oauth.access_token:${current.providerId}`);
    if (!access?.material) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth access token vault ref is configured, but no runtime vault material is available.",
        details: {
          oauth_session_hash: stableHash(current.id),
          auth_vault_ref_hash: access?.vaultRefHash ?? current.accessVaultRefHash ?? null,
          resolved_material: false,
          catalog_auth_scheme: "oauth2",
          catalog_auth_header_name_hash: stableHash(headerName),
          oauth_boundary: oauthBoundaryForSession(current),
          evidence_refs: normalizeScopes(access?.evidenceRefs, ["OAuthCredentialProvider.resolveAccessHeader", "oauth_access_fail_closed"]),
        },
      });
    }
    return {
      session: current,
      refreshed,
      headerValue: `Bearer ${access.material}`,
      evidence: {
        authVaultRefHash: access.vaultRefHash,
        oauthSessionHash: stableHash(current.id),
        resolvedMaterial: true,
        catalogAuthResolved: true,
        catalogAuthScheme: "oauth2",
        catalogAuthHeaderNameHash: stableHash(headerName),
        oauthBoundary: oauthBoundaryForSession(current, { refreshed }),
        evidenceRefs: normalizeScopes(
          [
            ...normalizeScopes(access.evidenceRefs, []),
            "OAuthCredentialProvider.resolveAccessHeader",
            refreshed ? "OAuthCredentialProvider.refreshAccessToken" : "oauth_access_token_active",
          ],
          [],
        ),
      },
    };
  }
}

function requiredString(value, field) {
  if (typeof value !== "string" || value.trim() === "") {
    throw runtimeError({
      status: 400,
      code: "validation",
      message: `${field} is required.`,
      details: { field },
    });
  }
  return value.trim();
}
