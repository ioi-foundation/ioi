import assert from "node:assert/strict";
import { test } from "node:test";

import { createModelMountingReadProjectionFacade } from "./read-projection-facade.mjs";

function createState() {
  const receipts = [
    {
      id: "receipt-route",
      kind: "model_route_selection",
      details: {
        modelRouteDecision: { routeId: "route.local-first", selectedModel: "model.local" },
        routeId: "route.local-first",
        endpointId: "endpoint.local",
        providerId: "provider.local",
      },
    },
    { id: "receipt-lifecycle", kind: "model_lifecycle", details: {} },
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
  });
  for (const key of Object.keys(facade)) {
    state[key] = (...args) => facade[key](state, ...args);
  }
  state.listProviderHealth = () => [];
  return { facade, state };
}

test("read projection facade delegates product-safe lists and capabilities", () => {
  const { facade, state } = createState();

  assert.deepEqual(facade.legacyModelList(state).map((model) => model.id), ["model.local"]);
  assert.deepEqual(facade.openAiModelList(state).data.map((model) => model.id), ["model.local"]);
  assert.deepEqual(facade.listProductArtifacts(state).map((artifact) => artifact.id), ["artifact.local"]);
  assert.deepEqual(facade.listProviders(state), [
    { id: "provider.local", vaultMetadata: { secretRef: "vault://provider.local/api-key", configured: true } },
  ]);
  assert.deepEqual(facade.listModelCapabilities(state), [
    { modelId: "fixture" },
    { modelId: "model.local" },
  ]);
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
  assert.equal(summary.receiptCount, 2);

  const replay = facade.receiptReplay(state, "receipt-route");
  assert.equal(replay.schemaVersion, "model.mount.schema");
  assert.equal(replay.route.id, "route.local-first");
  assert.equal(replay.endpoint.id, "endpoint.local");
  assert.equal(replay.provider.id, "provider.local");

  const authority = facade.authoritySnapshot(state, "http://127.0.0.1:3200");
  assert.equal(authority.schemaVersion, "ioi.wallet-core-lite.authority.v1");
  assert.equal(authority.wallet.port, "WalletAuthorityPort");
});
