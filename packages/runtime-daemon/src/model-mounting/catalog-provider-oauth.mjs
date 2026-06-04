export function startCatalogProviderOAuth(state, providerId, body = {}, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
    catalogProviderConfigUpdate,
    catalogProviderStatus,
    publicCatalogProviderConfig,
  } = deps;
  assertConfigurableCatalogProvider(providerId);
  const started = state.oauthCredentialProvider.startAuthorization({ providerId, body });
  state.oauthStates.set(started.state.id, started.state);
  const existing = state.catalogProviderConfigs.get(providerId);
  const update = catalogProviderConfigUpdate(
    providerId,
    {
      enabled: body.enabled ?? existing?.enabled ?? true,
      auth_scheme: "oauth2",
      auth_header_name: body.auth_header_name ?? body.authHeaderName ?? existing?.catalogAuthHeaderName ?? "authorization",
    },
    existing,
    state.nowIso(),
    state,
  );
  state.catalogProviderConfigs.set(providerId, {
    ...update.record,
    oauthBoundary: {
      configured: false,
      status: "pending_authorization",
      tokenExchange: "OAuthCredentialProvider.startAuthorization",
      oauthStateHash: started.evidence.oauthStateHash,
      expiresAt: started.evidence.expiresAt,
      scopes: started.evidence.scopes,
      pkceRequired: started.evidence.pkceRequired,
      evidenceRefs: ["catalog_oauth_boundary", "VaultOAuthAuthorizationState"],
    },
    updatedAt: state.nowIso(),
  });
  if (update.runtimeMaterial) state.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
  state.writeMap("oauth-states", state.oauthStates);
  state.writeMap("model-catalog-providers", state.catalogProviderConfigs);
  state.writeVaultRefs();
  const publicRecord = publicCatalogProviderConfig(
    providerId,
    state.catalogProviderConfigs.get(providerId),
    state.catalogProviderRuntimeMaterial(providerId),
  );
  const receipt = state.receipt("catalog_oauth_start", {
    summary: `${providerId} OAuth authorization started through PKCE and vault-bound state.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.startAuthorization", "VaultOAuthAuthorizationState", providerId],
    details: {
      providerId,
      oauthState: started.evidence,
      authorizationUrlHash: started.authorizationUrlHash,
      authorizationUrlRedacted: started.authorizationUrlRedacted,
      catalogProvider: publicRecord,
    },
  });
  state.writeProjection();
  return {
    ...publicRecord,
    oauthState: started.evidence,
    authorizationUrl: started.authorizationUrl,
    authorizationUrlRedacted: started.authorizationUrlRedacted,
    authorizationUrlHash: started.authorizationUrlHash,
    receiptId: receipt.id,
    provider: catalogProviderStatus(state.catalogProviderPorts().find((port) => port.id === providerId)),
  };
}

export async function completeCatalogProviderOAuth(state, providerId, body = {}, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
    catalogProviderConfigUpdate,
    catalogProviderStatus,
    publicCatalogProviderConfig,
    requiredString,
    stableHash,
  } = deps;
  assertConfigurableCatalogProvider(providerId);
  const callbackState = requiredString(body.state ?? body.oauth_state ?? body.oauthState, "state");
  const stateId = body.state_id ?? body.stateId ?? null;
  const stateRecord = stateId
    ? state.oauthStates.get(String(stateId))
    : [...state.oauthStates.values()].find(
        (candidate) =>
          candidate.providerId === providerId &&
          candidate.status === "pending" &&
          candidate.stateHash === stableHash(callbackState),
      );
  const completed = await state.oauthCredentialProvider.completeAuthorization({ providerId, stateRecord, body });
  state.oauthStates.set(completed.state.id, completed.state);
  state.oauthSessions.set(completed.session.id, completed.session);
  const existing = state.catalogProviderConfigs.get(providerId);
  const update = catalogProviderConfigUpdate(
    providerId,
    {
      enabled: body.enabled ?? existing?.enabled ?? true,
      auth_scheme: "oauth2",
      auth_header_name: body.auth_header_name ?? body.authHeaderName ?? existing?.catalogAuthHeaderName ?? "authorization",
      auth_vault_ref: completed.session.accessVaultRef,
      oauth_session_id: completed.session.id,
    },
    existing,
    state.nowIso(),
    state,
  );
  state.catalogProviderConfigs.set(providerId, update.record);
  if (update.runtimeMaterial) state.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
  state.writeMap("oauth-states", state.oauthStates);
  state.writeMap("oauth-sessions", state.oauthSessions);
  state.writeMap("model-catalog-providers", state.catalogProviderConfigs);
  state.writeVaultRefs();
  const publicRecord = publicCatalogProviderConfig(providerId, update.record, state.catalogProviderRuntimeMaterial(providerId));
  const receipt = state.receipt("catalog_oauth_callback", {
    summary: `${providerId} OAuth callback validated state and bound the session through vault refs.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.completeAuthorization", "VaultOAuthAuthorizationState", "VaultOAuthSession", providerId],
    details: {
      providerId,
      oauthState: completed.stateEvidence,
      oauthSession: completed.sessionEvidence,
      catalogProvider: publicRecord,
    },
  });
  state.writeProjection();
  return {
    ...publicRecord,
    oauthState: completed.stateEvidence,
    oauthSession: completed.sessionEvidence,
    receiptId: receipt.id,
    provider: catalogProviderStatus(state.catalogProviderPorts().find((port) => port.id === providerId)),
  };
}

export async function exchangeCatalogProviderOAuth(state, providerId, body = {}, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
    catalogProviderConfigUpdate,
    catalogProviderStatus,
    publicCatalogProviderConfig,
  } = deps;
  assertConfigurableCatalogProvider(providerId);
  const { session, evidence } = await state.oauthCredentialProvider.exchangeAuthorizationCode({ providerId, body });
  state.oauthSessions.set(session.id, session);
  const existing = state.catalogProviderConfigs.get(providerId);
  const update = catalogProviderConfigUpdate(
    providerId,
    {
      enabled: body.enabled ?? existing?.enabled ?? true,
      auth_scheme: "oauth2",
      auth_header_name: body.auth_header_name ?? body.authHeaderName ?? existing?.catalogAuthHeaderName ?? "authorization",
      auth_vault_ref: session.accessVaultRef,
      oauth_session_id: session.id,
    },
    existing,
    state.nowIso(),
    state,
  );
  state.catalogProviderConfigs.set(providerId, update.record);
  if (update.runtimeMaterial) state.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
  state.writeMap("oauth-sessions", state.oauthSessions);
  state.writeMap("model-catalog-providers", state.catalogProviderConfigs);
  state.writeVaultRefs();
  const publicRecord = publicCatalogProviderConfig(providerId, update.record, state.catalogProviderRuntimeMaterial(providerId));
  const receipt = state.receipt("catalog_oauth_exchange", {
    summary: `${providerId} OAuth session exchanged and bound through vault refs.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.exchangeAuthorizationCode", "VaultOAuthSession", providerId],
    details: {
      providerId,
      oauthSession: evidence,
      catalogProvider: publicRecord,
    },
  });
  state.writeProjection();
  return {
    ...publicRecord,
    oauthSession: evidence,
    receiptId: receipt.id,
    provider: catalogProviderStatus(state.catalogProviderPorts().find((port) => port.id === providerId)),
  };
}

export async function refreshCatalogProviderOAuth(state, providerId, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
    oauthBoundaryForSession,
    publicOAuthSession,
    runtimeError,
    stableHash,
  } = deps;
  assertConfigurableCatalogProvider(providerId);
  const config = state.catalogProviderConfigs.get(providerId);
  const session = config?.oauthSessionId ? state.oauthSessions.get(config.oauthSessionId) : null;
  if (!session) {
    throw runtimeError({
      status: 404,
      code: "not_found",
      message: `OAuth session not found for catalog provider: ${providerId}`,
      details: { providerId, oauthSessionHash: config?.oauthSessionId ? stableHash(config.oauthSessionId) : null },
    });
  }
  const refreshed = await state.oauthCredentialProvider.refreshAccessToken(session);
  state.oauthSessions.set(refreshed.id, refreshed);
  state.catalogProviderConfigs.set(providerId, {
    ...config,
    oauthBoundary: oauthBoundaryForSession(refreshed, { refreshed: true }),
    updatedAt: state.nowIso(),
  });
  state.writeMap("oauth-sessions", state.oauthSessions);
  state.writeMap("model-catalog-providers", state.catalogProviderConfigs);
  state.writeVaultRefs();
  const receipt = state.receipt("catalog_oauth_refresh", {
    summary: `${providerId} OAuth session refreshed through vault refs.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.refreshAccessToken", "VaultOAuthSession", providerId],
    details: {
      providerId,
      oauthSession: publicOAuthSession(refreshed),
    },
  });
  state.writeProjection();
  return { oauthSession: publicOAuthSession(refreshed), receiptId: receipt.id };
}

export function revokeCatalogProviderOAuth(state, providerId, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
    oauthBoundaryForSession,
    publicOAuthSession,
    runtimeError,
    stableHash,
  } = deps;
  assertConfigurableCatalogProvider(providerId);
  const config = state.catalogProviderConfigs.get(providerId);
  const session = config?.oauthSessionId ? state.oauthSessions.get(config.oauthSessionId) : null;
  if (!session) {
    throw runtimeError({
      status: 404,
      code: "not_found",
      message: `OAuth session not found for catalog provider: ${providerId}`,
      details: { providerId, oauthSessionHash: config?.oauthSessionId ? stableHash(config.oauthSessionId) : null },
    });
  }
  const revoked = state.oauthCredentialProvider.revokeSession(session);
  state.oauthSessions.set(revoked.id, revoked);
  state.catalogProviderConfigs.set(providerId, {
    ...config,
    oauthBoundary: oauthBoundaryForSession(revoked),
    updatedAt: state.nowIso(),
  });
  state.writeMap("oauth-sessions", state.oauthSessions);
  state.writeMap("model-catalog-providers", state.catalogProviderConfigs);
  state.writeVaultRefs();
  const receipt = state.receipt("catalog_oauth_revoke", {
    summary: `${providerId} OAuth session revoked through vault refs.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.revokeSession", "VaultOAuthSession", providerId],
    details: {
      providerId,
      oauthSession: publicOAuthSession(revoked),
    },
  });
  state.writeProjection();
  return { oauthSession: publicOAuthSession(revoked), receiptId: receipt.id };
}
