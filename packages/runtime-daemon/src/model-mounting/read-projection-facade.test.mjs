import assert from "node:assert/strict";
import { test } from "node:test";

import { createModelMountingReadProjectionFacade } from "./read-projection-facade.mjs";

function createState() {
  const receipts = [
    {
      id: "receipt-route",
      kind: "model_route_selection",
      details: {
        model_route_decision: { route_id: "route.local-first", selected_model: "model.local" },
        route_id: "route.local-first",
        endpoint_id: "endpoint.local",
        provider_id: "provider.local",
      },
    },
    { id: "receipt-lifecycle", kind: "model_lifecycle", details: {} },
    {
      id: "receipt-provider-health",
      kind: "provider_health",
      details: {
        providerId: "provider.local",
        status: "healthy",
      },
    },
    {
      id: "receipt-vault-health",
      kind: "vault_adapter_health",
      details: {
        status: "healthy",
        implementation: "runtime_memory_vault",
      },
    },
  ];
  const state = {
    stateDir: "/state",
    artifacts: new Map([
      ["artifact.fixture", { id: "artifact.fixture", modelId: "fixture", family: "fixture", capabilities: ["chat"], discoveredAt: "2026-06-03T00:00:01.000Z" }],
      ["artifact.local", { id: "artifact.local", modelId: "model.local", family: "local", capabilities: ["chat"], discoveredAt: "2026-06-03T00:00:02.000Z" }],
    ]),
    downloads: new Map([["download.one", { id: "download.one", createdAt: "2026-06-03T00:00:01.000Z" }]]),
    endpoints: new Map([["endpoint.local", { id: "endpoint.local", modelId: "model.local", providerId: "provider.local" }]]),
    instances: new Map(),
    oauthSessions: new Map(),
    oauthStates: new Map(),
    providers: new Map([["provider.local", { id: "provider.local", secretRef: "vault://provider.local/api-key" }]]),
    routes: new Map([["route.local-first", { id: "route.local-first" }]]),
    vault: {
      vaultRefMetadata(secretRef) {
        return { secretRef, configured: true };
      },
      adapterStatus() {
        return { port: "VaultPort" };
      },
    },
    walletAuthority: {
      adapterStatus() {
        return { port: "WalletAuthorityPort", remoteAdapter: { configured: false } };
      },
    },
    store: {
      adapterStatus() {
        return { port: "AgentgresStorePort" };
      },
    },
    evictExpiredInstances() {},
    coalesceLoadedInstances() {},
    nowIso: () => "2026-06-03T00:00:00.000Z",
    serverStatus: () => ({ status: "running" }),
    catalogStatus: () => ({ status: "ready" }),
    listBackends: () => [],
    listBackendProcesses: () => [],
    listCatalogProviderConfigs: () => [],
    listConversations: () => [],
    listMcpServers: () => [],
    listReceipts: () => receipts,
    getReceipt: (receiptId) => receipts.find((receipt) => receipt.id === receiptId),
    provider(providerId) {
      const provider = this.providers.get(providerId);
      if (!provider) throw Object.assign(new Error(`Provider not found: ${providerId}`), { status: 404 });
      return provider;
    },
    listRuntimeEngineProfiles: () => [],
    listRuntimeEngines: () => [],
    listTokens: () => [],
    listVaultRefs: () => [],
    latestRuntimeSurvey: () => null,
    runtimePreference: () => ({ routeId: "route.local-first" }),
    vaultStatus: () => ({ port: "VaultPort" }),
    workflowNodeBindings: () => [],
  };
  const readProjectionRequests = [];
  const readProjectionPlanner = {
    planReadProjection(request) {
      readProjectionRequests.push(request);
      return {
        source: "rust_model_mount_read_projection_command",
        backend: "rust_model_mount_read_projection",
        projection_kind: request.projection_kind,
        projection: rustProjectionFixture(request),
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
  };
  const facade = createModelMountingReadProjectionFacade({
    buildModelCapabilities: ({ artifacts }) => artifacts.map((artifact) => ({ modelId: artifact.modelId })),
    capabilityForWorkflowNode(node) {
      if (node === "Embedding") return "embeddings";
      if (node === "Receipt Gate") return "receipt_gate";
      return "chat";
    },
    internalFixtureModelsEnabled: () => false,
    isFixtureModelRecord: (artifact) => artifact.family === "fixture",
    listJson: () => ["/state/provider-health/provider.local.json"],
    modelMountSchemaVersion: "model.mount.schema",
    path: { join: (...parts) => parts.join("/") },
    providerHasVaultRef: (provider) => Boolean(provider.secretRef),
    publicOAuthSession: (session) => ({ id: session.id }),
    publicOAuthState: (oauthState) => ({ id: oauthState.id }),
    publicProvider: (provider, vaultMetadata) => ({ id: provider.id, vaultMetadata }),
    readJson: () => ({
      providerId: "provider.local",
      receiptId: "receipt-provider-health",
      status: "healthy",
    }),
    readProjectionPlanner,
    notFound: (message, details) => Object.assign(new Error(message), {
      status: 404,
      code: "not_found",
      details,
    }),
  });
  for (const key of Object.keys(facade)) {
    state[key] = (...args) => facade[key](state, ...args);
  }
  state.listProviderHealth = () => [{
    providerId: "provider.local",
    receiptId: "receipt-provider-health",
    status: "healthy",
  }];
  return { facade, state, readProjectionPlanner, readProjectionRequests };
}

function rustProjectionFixture(request) {
  const state = request.state;
  const receipts = state.receipts ?? [];
  const projection = {
    schemaVersion: request.schema_version,
    source: "agentgres_model_mounting_projection",
    generatedAt: request.generated_at,
    watermark: receipts.length,
    artifacts: state.artifacts,
    endpoints: state.endpoints,
    instances: state.instances,
    routes: state.routes,
    modelCapabilities: state.model_capabilities,
    backends: state.backends,
    backendProcesses: state.backend_processes,
    providers: state.providers,
    catalog: state.catalog,
    catalogProviderConfigs: state.catalog_provider_configs,
    oauthSessions: state.oauth_sessions,
    oauthStates: state.oauth_states,
    downloads: state.downloads,
    providerHealth: state.provider_health,
    runtimeEngines: state.runtime_engines,
    runtimeEngineProfiles: state.runtime_engine_profiles,
    runtimePreference: state.runtime_preference,
    runtimeSurvey: state.runtime_survey,
    grants: state.grants,
    vaultRefs: state.vault_refs,
    mcpServers: state.mcp_servers,
    conversationStates: state.conversation_states,
    workflowBindings: state.workflow_bindings,
    adapterBoundaries: state.adapter_boundaries,
    lifecycleEvents: receipts.filter((receipt) => receipt.kind === "model_lifecycle"),
    routeReceipts: receipts.filter((receipt) => receipt.kind === "model_route_selection"),
    routeDecisions: routeDecisionsFromReceipts(receipts),
    providerHealthReceipts: receipts.filter((receipt) => receipt.kind === "provider_health"),
    runtimeSurveyReceipts: receipts.filter((receipt) => receipt.kind === "runtime_survey"),
    invocationReceipts: receipts.filter((receipt) => receipt.kind === "model_invocation"),
    toolReceipts: receipts.filter((receipt) => receipt.kind === "mcp_tool_invocation"),
    receipts,
  };
  if (request.projection_kind === "snapshot") {
    return {
      schemaVersion: request.schema_version,
      server: state.server,
      catalog: state.catalog,
      catalogProviderConfigs: state.catalog_provider_configs,
      oauthSessions: state.oauth_sessions,
      oauthStates: state.oauth_states,
      artifacts: state.artifacts,
      backends: state.backends,
      backendProcesses: state.backend_processes,
      endpoints: state.endpoints,
      instances: state.instances,
      providers: state.providers,
      routes: state.routes,
      modelCapabilities: state.model_capabilities,
      downloads: state.downloads,
      providerHealth: state.provider_health,
      runtimeEngines: state.runtime_engines,
      runtimeEngineProfiles: state.runtime_engine_profiles,
      runtimePreference: state.runtime_preference,
      runtimeSurvey: state.runtime_survey,
      tokens: state.grants,
      vaultRefs: state.vault_refs,
      mcpServers: state.mcp_servers,
      conversationStates: state.conversation_states,
      workflowNodes: state.workflow_bindings,
      receipts: receipts.slice(-25),
      projection: {
        schemaVersion: projection.schemaVersion,
        source: projection.source,
        watermark: projection.watermark,
        receiptCount: projection.receipts.length,
        generatedAt: projection.generatedAt,
      },
      adapterBoundaries: projection.adapterBoundaries,
    };
  }
  if (request.projection_kind === "projection") return projection;
  if (request.projection_kind === "projection_summary") {
    return {
      schemaVersion: projection.schemaVersion,
      source: projection.source,
      watermark: projection.watermark,
      receiptCount: projection.receipts.length,
      generatedAt: projection.generatedAt,
    };
  }
  if (request.projection_kind === "model_route_decisions") return projection.routeDecisions;
  if (request.projection_kind === "authority_snapshot") {
    const authorityReceipts = receipts.filter((receipt) =>
      [
        "permission_token",
        "permission_token_revocation",
        "vault_ref_binding",
        "vault_ref_removal",
        "vault_adapter_health",
      ].includes(receipt.kind),
    ).slice(-25);
    return {
      schemaVersion: "ioi.wallet-core-lite.authority.v1",
      source: "agentgres_wallet_authority_projection",
      generatedAt: request.generated_at,
      server: state.server,
      wallet: state.wallet,
      vault: state.vault,
      grants: state.grants,
      vaultRefs: state.vault_refs,
      approvals: [],
      approvalQueue: {
        status: "not_configured",
        pendingCount: 0,
        evidenceRefs: ["wallet.network.approval_queue.pending_runtime_adapter"],
      },
      receipts: authorityReceipts,
      summary: {
        activeGrants: 0,
        revokedGrants: 0,
        vaultRefs: state.vault_refs.length,
        pendingApprovals: 0,
        receiptCount: authorityReceipts.length,
        remoteWalletConfigured: false,
      },
    };
  }
  if (request.projection_kind === "latest_provider_health") {
    const health = state.provider_health.find((record) => record.providerId === request.provider_id);
    const receipt = receipts.find((candidate) => candidate.id === health?.receiptId);
    return {
      schemaVersion: request.schema_version,
      source: "agentgres_provider_health_latest",
      providerId: request.provider_id,
      health,
      receipt,
      replay: {
        schemaVersion: request.schema_version,
        source: "agentgres_model_mounting_projection_replay",
        receipt,
        projectionWatermark: projection.watermark,
      },
      projectionWatermark: projection.watermark,
    };
  }
  if (request.projection_kind === "latest_vault_health") {
    const receipt = receipts.filter((candidate) => candidate.kind === "vault_adapter_health").at(-1);
    return {
      schemaVersion: request.schema_version,
      source: "agentgres_vault_health_latest",
      health: receipt.details,
      receipt,
      replay: {
        schemaVersion: request.schema_version,
        source: "agentgres_model_mounting_projection_replay",
        receipt,
        projectionWatermark: projection.watermark,
      },
      projectionWatermark: projection.watermark,
    };
  }
  if (request.projection_kind === "receipt_replay") {
    const receipt = receipts.find((candidate) => candidate.id === request.receipt_id);
    return {
      schemaVersion: request.schema_version,
      source: "agentgres_model_mounting_projection_replay",
      receipt,
      model_route_decision: receipt.details?.model_route_decision ?? null,
      route: projection.routes.find((route) => route.id === receipt.details?.route_id) ?? null,
      endpoint: projection.endpoints.find((endpoint) => endpoint.id === receipt.details?.endpoint_id) ?? null,
      instance: projection.instances.find((instance) => instance.id === receipt.details?.instance_id) ?? null,
      provider: projection.providers.find((provider) => provider.id === receipt.details?.provider_id) ?? null,
      toolReceipts: [],
      projectionWatermark: projection.watermark,
    };
  }
  throw new Error(`unsupported projection fixture: ${request.projection_kind}`);
}

function routeDecisionsFromReceipts(receipts) {
  return receipts
    .filter((receipt) => receipt.kind === "model_route_selection")
    .map((receipt) => ({
      ...receipt.details.model_route_decision,
      receipt_id: receipt.id,
      receipt_created_at: receipt.createdAt,
      receipt_kind: receipt.kind,
    }));
}

test("read projection facade delegates product-safe lists and capabilities", () => {
  const { facade, state, readProjectionRequests } = createState();

  assert.deepEqual(facade.runtimeModelCatalogList(state).map((model) => model.id), ["model.local"]);
  assert.deepEqual(facade.openAiModelList(state).data.map((model) => model.id), ["model.local"]);
  assert.deepEqual(facade.listProductArtifacts(state).map((artifact) => artifact.id), ["artifact.local"]);
  assert.deepEqual(facade.listArtifacts(state).map((artifact) => artifact.id), ["artifact.fixture", "artifact.local"]);
  assert.deepEqual(facade.listProviders(state), [
    { id: "provider.local", vaultMetadata: { secretRef: "vault://provider.local/api-key", configured: true } },
  ]);
  assert.deepEqual(facade.listEndpoints(state).map((endpoint) => endpoint.id), ["endpoint.local"]);
  assert.deepEqual(facade.listInstances(state).map((instance) => instance.id), []);
  assert.deepEqual(facade.listRoutes(state).map((route) => route.id), ["route.local-first"]);
  assert.deepEqual(facade.listModelCapabilities(state), [
    { modelId: "fixture" },
    { modelId: "model.local" },
  ]);
  assert.deepEqual(facade.listDownloads(state).map((download) => download.id), ["download.one"]);
  assert.deepEqual(facade.listOAuthSessions(state), []);
  assert.deepEqual(facade.listOAuthStates(state), []);
  assert.deepEqual(facade.listProviderHealth(state).map((health) => health.receiptId), ["receipt-provider-health"]);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "projection",
    "projection",
    "projection",
    "projection",
    "projection",
    "projection",
    "projection",
    "projection",
    "projection",
    "projection",
  ]);
  const workflowBindings = facade.workflowNodeBindings(state);
  assert.equal(workflowBindings.find((binding) => binding.node === "Embedding").capability, "embeddings");
  assert.equal(workflowBindings.find((binding) => binding.node === "Receipt Gate").daemonApi, "/api/v1/workflows/receipt-gate");
  assert.equal(facade.adapterBoundaries(state).agentgres.port, "AgentgresStorePort");
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind).slice(-2), [
    "projection",
    "projection",
  ]);
});

test("read projection facade composes snapshots, projection, and receipt replay", () => {
  const { facade, state, readProjectionRequests } = createState();

  const snapshot = facade.snapshot(state, "http://127.0.0.1:3200");
  assert.equal(snapshot.schemaVersion, "model.mount.schema");
  assert.equal(snapshot.server.status, "running");
  assert.equal(snapshot.artifacts.length, 2);
  assert.equal(snapshot.modelCapabilities.length, 2);
  assert.equal(snapshot.projection.source, "agentgres_model_mounting_projection");

  const projection = facade.projection(state);
  assert.equal(projection.schemaVersion, "model.mount.schema");
  assert.equal(projection.routeReceipts.length, 1);
  assert.equal(projection.lifecycleEvents.length, 1);

  const projectionWritePlan = facade.canonicalProjectionWritePlan(state);
  assert.equal(projectionWritePlan.source, "rust_model_mount_read_projection_command");
  assert.equal(projectionWritePlan.projection_kind, "projection");
  assert.equal(projectionWritePlan.projection.source, "agentgres_model_mounting_projection");
  assert.equal(projectionWritePlan.evidence_refs.includes("agentgres_model_mount_read_truth"), true);

  const summary = facade.projectionSummary(state);
  assert.equal(summary.schemaVersion, "model.mount.schema");
  assert.equal(summary.receiptCount, 4);

  const replay = facade.receiptReplay(state, "receipt-route");
  assert.equal(replay.schemaVersion, "model.mount.schema");
  assert.equal(replay.route.id, "route.local-first");
  assert.equal(replay.endpoint.id, "endpoint.local");
  assert.equal(replay.provider.id, "provider.local");
  assert.equal(replay.model_route_decision.selected_model, "model.local");
  assert.equal(Object.hasOwn(replay, "modelRouteDecision"), false);

  const authority = facade.authoritySnapshot(state, "http://127.0.0.1:3200");
  assert.equal(authority.schemaVersion, "ioi.wallet-core-lite.authority.v1");
  assert.equal(authority.wallet.port, "WalletAuthorityPort");
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "snapshot",
    "projection",
    "projection",
    "projection_summary",
    "receipt_replay",
    "authority_snapshot",
  ]);
  assert.equal(readProjectionRequests.at(-1).state.providers[0].id, "provider.local");
  assert.equal(Object.hasOwn(readProjectionRequests.at(-1).state.providers[0], "providerId"), false);
});

test("read projection facade projects latest provider and vault health envelopes", () => {
  const { facade, state, readProjectionRequests } = createState();

  const providerHealth = facade.latestProviderHealth(state, "provider.local");
  assert.equal(providerHealth.schemaVersion, "model.mount.schema");
  assert.equal(providerHealth.source, "agentgres_provider_health_latest");
  assert.equal(providerHealth.providerId, "provider.local");
  assert.equal(providerHealth.health.status, "healthy");
  assert.equal(providerHealth.receipt.id, "receipt-provider-health");
  assert.equal(providerHealth.replay.receipt.id, "receipt-provider-health");
  assert.equal(providerHealth.projectionWatermark, 4);

  const vaultHealth = facade.latestVaultHealth(state);
  assert.equal(vaultHealth.schemaVersion, "model.mount.schema");
  assert.equal(vaultHealth.source, "agentgres_vault_health_latest");
  assert.equal(vaultHealth.health.implementation, "runtime_memory_vault");
  assert.equal(vaultHealth.receipt.id, "receipt-vault-health");
  assert.equal(vaultHealth.replay.receipt.id, "receipt-vault-health");
  assert.equal(vaultHealth.projectionWatermark, 4);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "latest_provider_health",
    "latest_vault_health",
  ]);
  assert.equal(readProjectionRequests[0].provider_id, "provider.local");
});

test("read projection facade preserves latest health not-found errors", () => {
  const { facade, state, readProjectionPlanner, readProjectionRequests } = createState();

  readProjectionPlanner.planReadProjection = (request) => {
    readProjectionRequests.push(request);
    if (request.projection_kind === "latest_provider_health") {
      throw Object.assign(new Error("provider health has not been checked"), {
        code: "model_mount_provider_health_not_found",
      });
    }
    if (request.projection_kind === "latest_vault_health") {
      throw Object.assign(new Error("vault adapter health has not been checked"), {
        code: "model_mount_vault_health_not_found",
      });
    }
    return {
      source: "rust_model_mount_read_projection_command",
      backend: "rust_model_mount_read_projection",
      projection_kind: request.projection_kind,
      projection: rustProjectionFixture(request),
    };
  };

  assert.throws(
    () => facade.latestProviderHealth(state, "provider.local"),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.providerId === "provider.local",
  );

  assert.throws(
    () => facade.latestVaultHealth(state),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.receiptKind === "vault_adapter_health",
  );
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "latest_provider_health",
    "latest_vault_health",
  ]);
  assert.equal(readProjectionRequests[0].provider_id, "provider.local");
});
