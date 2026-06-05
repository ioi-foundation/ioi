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
        routeId: "route.local-first",
        endpointId: "endpoint.local",
        providerId: "provider.local",
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
  const facade = createModelMountingReadProjectionFacade({
    buildModelCapabilities: ({ artifacts }) => artifacts.map((artifact) => ({ modelId: artifact.modelId })),
    capabilityForWorkflowNode(node) {
      if (node === "Embedding") return "embeddings";
      if (node === "Receipt Gate") return "receipt_gate";
      return "chat";
    },
    internalFixtureModelsEnabled: () => false,
    isFixtureModelRecord: (artifact) => artifact.family === "fixture",
    listJson: () => [],
    modelMountSchemaVersion: "model.mount.schema",
    path: { join: (...parts) => parts.join("/") },
    providerHasVaultRef: (provider) => Boolean(provider.secretRef),
    publicOAuthSession: (session) => ({ id: session.id }),
    publicOAuthState: (oauthState) => ({ id: oauthState.id }),
    publicProvider: (provider, vaultMetadata) => ({ id: provider.id, vaultMetadata }),
    readJson: () => null,
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
  return { facade, state };
}

test("read projection facade delegates product-safe lists and capabilities", () => {
  const { facade, state } = createState();

  assert.deepEqual(facade.runtimeModelCatalogList(state).map((model) => model.id), ["model.local"]);
  assert.deepEqual(facade.openAiModelList(state).data.map((model) => model.id), ["model.local"]);
  assert.deepEqual(facade.listProductArtifacts(state).map((artifact) => artifact.id), ["artifact.local"]);
  assert.deepEqual(facade.listProviders(state), [
    { id: "provider.local", vaultMetadata: { secretRef: "vault://provider.local/api-key", configured: true } },
  ]);
  assert.deepEqual(facade.listModelCapabilities(state), [
    { modelId: "fixture" },
    { modelId: "model.local" },
  ]);
  assert.equal(facade.workflowNodeBindings(state).find((binding) => binding.node === "Embedding").capability, "embeddings");
  assert.equal(facade.workflowNodeBindings(state).find((binding) => binding.node === "Receipt Gate").daemonApi, "/api/v1/workflows/receipt-gate");
});

test("read projection facade composes snapshots, projection, and receipt replay", () => {
  const { facade, state } = createState();

  const snapshot = facade.snapshot(state, "http://127.0.0.1:3200");
  assert.equal(snapshot.schemaVersion, "model.mount.schema");
  assert.equal(snapshot.server.status, "running");
  assert.equal(snapshot.artifacts.length, 2);
  assert.equal(snapshot.modelCapabilities.length, 2);

  const projection = facade.projection(state);
  assert.equal(projection.schemaVersion, "model.mount.schema");
  assert.equal(projection.routeReceipts.length, 1);
  assert.equal(projection.lifecycleEvents.length, 1);

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
});

test("read projection facade projects latest provider and vault health envelopes", () => {
  const { facade, state } = createState();

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
});

test("read projection facade preserves latest health not-found errors", () => {
  const { facade, state } = createState();

  state.listProviderHealth = () => [];
  assert.throws(
    () => facade.latestProviderHealth(state, "provider.local"),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.providerId === "provider.local",
  );

  state.listReceipts = () => [];
  assert.throws(
    () => facade.latestVaultHealth(state),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.receiptKind === "vault_adapter_health",
  );
});
