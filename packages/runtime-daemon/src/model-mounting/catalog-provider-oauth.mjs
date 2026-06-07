import { commitModelMountRecordState } from "./record-state-commits.mjs";
import {
  commitOAuthSessionRecordState,
  commitOAuthStateRecordState,
} from "./oauth-record-state.mjs";

export function startCatalogProviderOAuth(state, providerId, body = {}, deps = {}) {
  const {
    assertConfigurableCatalogProvider,
    catalogProviderConfigUpdate,
    catalogProviderStatus,
    publicCatalogProviderConfig,
  } = deps;
  assertConfigurableCatalogProvider(providerId);
  const started = state.oauthCredentialProvider.startAuthorization({ providerId, body });
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
  const storedConfig = {
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
  };
  const publicRecord = publicCatalogProviderConfig(
    providerId,
    storedConfig,
    update.runtimeMaterial ?? state.catalogProviderRuntimeMaterial(providerId),
  );
  const receipt = state.receipt("catalog_oauth_start", {
    summary: `${providerId} OAuth authorization started through PKCE and vault-bound state.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.startAuthorization", "VaultOAuthAuthorizationState", providerId],
    details: {
      provider_id: providerId,
      oauth_state: started.evidence,
      authorization_url_hash: started.authorizationUrlHash,
      authorization_url_redacted: started.authorizationUrlRedacted,
      catalog_provider: publicRecord,
    },
  });
  commitCatalogProviderOAuthConfigState(
    state,
    providerId,
    storedConfig,
    receipt,
    "model_mount.catalog_provider_oauth.start",
  );
  commitOAuthStateRecordState(state, { ...started.state, receiptId: receipt.id }, "model_mount.oauth_state.start", [
    receipt.id,
  ]);
  state.oauthStates.set(started.state.id, { ...started.state, receiptId: receipt.id });
  state.catalogProviderConfigs.set(providerId, { ...storedConfig, receiptId: receipt.id });
  if (update.runtimeMaterial) state.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
  state.writeVaultRefs();
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
  const publicRecord = publicCatalogProviderConfig(
    providerId,
    update.record,
    update.runtimeMaterial ?? state.catalogProviderRuntimeMaterial(providerId),
  );
  const receipt = state.receipt("catalog_oauth_callback", {
    summary: `${providerId} OAuth callback validated state and bound the session through vault refs.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.completeAuthorization", "VaultOAuthAuthorizationState", "VaultOAuthSession", providerId],
    details: {
      provider_id: providerId,
      oauth_state: completed.stateEvidence,
      oauth_session: completed.sessionEvidence,
      catalog_provider: publicRecord,
    },
  });
  commitCatalogProviderOAuthConfigState(
    state,
    providerId,
    update.record,
    receipt,
    "model_mount.catalog_provider_oauth.callback",
  );
  commitOAuthStateRecordState(state, { ...completed.state, receiptId: receipt.id }, "model_mount.oauth_state.callback", [
    receipt.id,
  ]);
  commitOAuthSessionRecordState(
    state,
    { ...completed.session, receiptId: receipt.id },
    "model_mount.oauth_session.callback",
    [receipt.id],
  );
  state.oauthStates.set(completed.state.id, { ...completed.state, receiptId: receipt.id });
  state.oauthSessions.set(completed.session.id, { ...completed.session, receiptId: receipt.id });
  state.catalogProviderConfigs.set(providerId, { ...update.record, receiptId: receipt.id });
  if (update.runtimeMaterial) state.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
  state.writeVaultRefs();
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
  const publicRecord = publicCatalogProviderConfig(
    providerId,
    update.record,
    update.runtimeMaterial ?? state.catalogProviderRuntimeMaterial(providerId),
  );
  const receipt = state.receipt("catalog_oauth_exchange", {
    summary: `${providerId} OAuth session exchanged and bound through vault refs.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.exchangeAuthorizationCode", "VaultOAuthSession", providerId],
    details: {
      provider_id: providerId,
      oauth_session: evidence,
      catalog_provider: publicRecord,
    },
  });
  commitCatalogProviderOAuthConfigState(
    state,
    providerId,
    update.record,
    receipt,
    "model_mount.catalog_provider_oauth.exchange",
  );
  commitOAuthSessionRecordState(
    state,
    { ...session, receiptId: receipt.id },
    "model_mount.oauth_session.exchange",
    [receipt.id],
  );
  state.oauthSessions.set(session.id, { ...session, receiptId: receipt.id });
  state.catalogProviderConfigs.set(providerId, { ...update.record, receiptId: receipt.id });
  if (update.runtimeMaterial) state.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
  state.writeVaultRefs();
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
      details: { provider_id: providerId, oauth_session_hash: config?.oauthSessionId ? stableHash(config.oauthSessionId) : null },
    });
  }
  const refreshed = await state.oauthCredentialProvider.refreshAccessToken(session);
  const storedConfig = {
    ...config,
    oauthBoundary: oauthBoundaryForSession(refreshed, { refreshed: true }),
    updatedAt: state.nowIso(),
  };
  const receipt = state.receipt("catalog_oauth_refresh", {
    summary: `${providerId} OAuth session refreshed through vault refs.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.refreshAccessToken", "VaultOAuthSession", providerId],
    details: {
      provider_id: providerId,
      oauth_session: publicOAuthSession(refreshed),
    },
  });
  commitCatalogProviderOAuthConfigState(
    state,
    providerId,
    storedConfig,
    receipt,
    "model_mount.catalog_provider_oauth.refresh",
  );
  commitOAuthSessionRecordState(
    state,
    { ...refreshed, receiptId: receipt.id },
    "model_mount.oauth_session.refresh",
    [receipt.id],
  );
  state.oauthSessions.set(refreshed.id, { ...refreshed, receiptId: receipt.id });
  state.catalogProviderConfigs.set(providerId, { ...storedConfig, receiptId: receipt.id });
  state.writeVaultRefs();
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
      details: { provider_id: providerId, oauth_session_hash: config?.oauthSessionId ? stableHash(config.oauthSessionId) : null },
    });
  }
  const revoked = state.oauthCredentialProvider.revokeSession(session);
  const storedConfig = {
    ...config,
    oauthBoundary: oauthBoundaryForSession(revoked),
    updatedAt: state.nowIso(),
  };
  const receipt = state.receipt("catalog_oauth_revoke", {
    summary: `${providerId} OAuth session revoked through vault refs.`,
    redaction: "redacted",
    evidenceRefs: ["OAuthCredentialProvider.revokeSession", "VaultOAuthSession", providerId],
    details: {
      provider_id: providerId,
      oauth_session: publicOAuthSession(revoked),
    },
  });
  commitCatalogProviderOAuthConfigState(
    state,
    providerId,
    storedConfig,
    receipt,
    "model_mount.catalog_provider_oauth.revoke",
  );
  commitOAuthSessionRecordState(
    state,
    { ...revoked, receiptId: receipt.id },
    "model_mount.oauth_session.revoke",
    [receipt.id],
  );
  state.oauthSessions.set(revoked.id, { ...revoked, receiptId: receipt.id });
  state.catalogProviderConfigs.set(providerId, { ...storedConfig, receiptId: receipt.id });
  state.writeVaultRefs();
  state.writeProjection();
  return { oauthSession: publicOAuthSession(revoked), receiptId: receipt.id };
}

function commitCatalogProviderOAuthConfigState(state, providerId, record, receipt, operation_kind) {
  commitModelMountRecordState(state, {
    recordDir: "model-catalog-providers",
    record: { ...record, receiptId: receipt.id },
    operation_kind,
    receipt_refs: [receipt.id],
    unconfiguredCode: "model_mount_catalog_provider_oauth_state_commit_unconfigured",
    unconfiguredMessage:
      "Catalog provider OAuth configuration persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: { provider_id: providerId },
  });
}
