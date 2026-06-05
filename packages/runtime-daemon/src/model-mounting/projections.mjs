import * as routeDecision from "./route-decision.mjs";

export function buildAuthoritySnapshot(state, baseUrl, { schemaVersion }) {
  const grants = state.listTokens();
  const vaultRefs = state.listVaultRefs();
  const wallet = state.walletAuthority.adapterStatus();
  const authorityReceipts = state.listReceipts()
    .filter((receipt) =>
      [
        "permission_token",
        "permission_token_revocation",
        "vault_ref_binding",
        "vault_ref_removal",
        "vault_adapter_health",
      ].includes(receipt.kind),
    )
    .slice(-25);
  return {
    schemaVersion: "ioi.wallet-core-lite.authority.v1",
    source: "agentgres_wallet_authority_projection",
    generatedAt: state.nowIso(),
    server: state.serverStatus(baseUrl),
    wallet,
    vault: state.vaultStatus(),
    grants,
    vaultRefs,
    approvals: [],
    approvalQueue: {
      status: "not_configured",
      pendingCount: 0,
      evidenceRefs: ["wallet.network.approval_queue.pending_runtime_adapter"],
    },
    receipts: authorityReceipts,
    summary: {
      activeGrants: grants.filter((grant) => !grant.revokedAt).length,
      revokedGrants: grants.filter((grant) => Boolean(grant.revokedAt)).length,
      vaultRefs: vaultRefs.length,
      pendingApprovals: 0,
      receiptCount: authorityReceipts.length,
      remoteWalletConfigured: Boolean(wallet.remoteAdapter?.configured),
    },
  };
}

export function buildProjectionSummary(projection) {
  return {
    schemaVersion: projection.schemaVersion,
    source: projection.source,
    watermark: projection.watermark,
    receiptCount: projection.receipts.length,
    generatedAt: projection.generatedAt,
  };
}

export function buildModelMountingProjection(state, { schemaVersion }) {
  const receipts = state.listReceipts();
  return {
    schemaVersion,
    source: "agentgres_model_mounting_projection",
    generatedAt: state.nowIso(),
    watermark: receipts.length,
    artifacts: state.listArtifacts(),
    endpoints: state.listEndpoints(),
    instances: state.listInstances(),
    routes: state.listRoutes(),
    modelCapabilities: state.listModelCapabilities(),
    backends: state.listBackends(),
    backendProcesses: state.listBackendProcesses(),
    providers: state.listProviders(),
    catalog: state.catalogStatus(),
    catalogProviderConfigs: state.listCatalogProviderConfigs(),
    oauthSessions: state.listOAuthSessions(),
    oauthStates: state.listOAuthStates(),
    downloads: state.listDownloads(),
    providerHealth: state.listProviderHealth(),
    runtimeEngines: state.listRuntimeEngines(),
    runtimeEngineProfiles: state.listRuntimeEngineProfiles(),
    runtimePreference: state.runtimePreference(),
    runtimeSurvey: state.latestRuntimeSurvey(),
    grants: state.listTokens(),
    vaultRefs: state.listVaultRefs(),
    mcpServers: state.listMcpServers(),
    conversationStates: state.listConversations(),
    workflowBindings: state.workflowNodeBindings(),
    adapterBoundaries: state.adapterBoundaries(),
    lifecycleEvents: receipts.filter((receipt) => receipt.kind === "model_lifecycle"),
    routeReceipts: receipts.filter((receipt) => receipt.kind === "model_route_selection"),
    routeDecisions: state.modelRouteDecisions(),
    providerHealthReceipts: receipts.filter((receipt) => receipt.kind === "provider_health"),
    runtimeSurveyReceipts: receipts.filter((receipt) => receipt.kind === "runtime_survey"),
    invocationReceipts: receipts.filter((receipt) => receipt.kind === "model_invocation"),
    toolReceipts: receipts.filter((receipt) => receipt.kind === "mcp_tool_invocation"),
    receipts,
  };
}

export function buildAdapterBoundaries(state) {
  return {
    wallet: state.walletAuthority.adapterStatus(),
    vault: state.vault.adapterStatus(),
    oauth: {
      port: "OAuthCredentialProvider",
      implementation: "agentgres_vault_oauth_session",
      methods: [
        "startAuthorization",
        "completeAuthorization",
        "exchangeAuthorizationCode",
        "refreshAccessToken",
        "revokeSession",
        "resolveAccessHeader",
      ],
      plaintextPersistence: false,
      evidenceRefs: ["OAuthCredentialProvider", "VaultOAuthAuthorizationState", "VaultOAuthSession", "oauth_tokens_not_persisted"],
    },
    agentgres: state.store.adapterStatus(),
  };
}

export function buildReceiptReplay(state, receiptId, { schemaVersion }) {
  const receipt = state.getReceipt(receiptId);
  const projection = state.projection();
  return {
    schemaVersion,
    source: "agentgres_model_mounting_projection_replay",
    receipt,
    model_route_decision: receipt.details?.model_route_decision ?? null,
    route: receipt.details?.route_id ? projection.routes.find((route) => route.id === receipt.details.route_id) ?? null : null,
    endpoint: receipt.details?.endpoint_id
      ? projection.endpoints.find((endpoint) => endpoint.id === receipt.details.endpoint_id) ?? null
      : null,
    instance: receipt.details?.instance_id
      ? projection.instances.find((instance) => instance.id === receipt.details.instance_id) ?? null
      : null,
    provider: receipt.details?.provider_id
      ? projection.providers.find((provider) => provider.id === receipt.details.provider_id) ?? null
      : null,
    toolReceipts: normalizeReceiptIds(receipt.details?.tool_receipt_ids).map((toolReceiptId) => state.getReceipt(toolReceiptId)),
    projectionWatermark: projection.watermark,
  };
}

export function buildModelRouteDecisions(state) {
  return state.listReceipts()
    .filter((receipt) => receipt.kind === "model_route_selection")
    .map(routeDecision.routeDecisionProjectionFromReceipt)
    .filter(Boolean);
}

function normalizeReceiptIds(value) {
  if (Array.isArray(value)) return value.filter((item) => typeof item === "string" && item.trim());
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}
