import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  buildAdapterBoundaries,
  buildAuthoritySnapshot,
  buildModelMountingProjection,
  buildModelRouteDecisions,
  buildProjectionSummary,
  buildReceiptReplay,
} from "./projections.mjs";

const SCHEMA = "ioi.model-mounting.runtime.v1";

function fakeState(stateDir = mkdtempSync(join(tmpdir(), "ioi-model-projection-test-"))) {
  const receipts = [
    {
      id: "receipt.route.1",
      kind: "model_route_selection",
      details: {
        routeId: "route.local-first",
        endpointId: "endpoint.local",
        providerId: "provider.local",
        toolReceiptIds: ["receipt.tool.1"],
        modelRouteDecision: { routeId: "route.local-first", selectedEndpointId: "endpoint.local" },
      },
    },
    { id: "receipt.tool.1", kind: "mcp_tool_invocation", details: {} },
    { id: "receipt.health.1", kind: "provider_health", details: { providerId: "provider.local" } },
    { id: "receipt.lifecycle.1", kind: "model_lifecycle", details: {} },
    { id: "receipt.invoke.1", kind: "model_invocation", details: {} },
    { id: "receipt.wallet.1", kind: "permission_token", details: {} },
  ];
  const byId = new Map(receipts.map((receipt) => [receipt.id, receipt]));
  return {
    stateDir,
    nowIso: () => "2026-06-03T00:00:00.000Z",
    walletAuthority: {
      adapterStatus: () => ({ port: "WalletAuthorityPort", remoteAdapter: { configured: true } }),
    },
    vault: {
      adapterStatus: () => ({ port: "VaultPort" }),
    },
    store: {
      adapterStatus: () => ({ port: "AgentgresStorePort" }),
    },
    serverStatus: () => ({ status: "running" }),
    vaultStatus: () => ({ port: "VaultPort" }),
    listTokens: () => [{ id: "grant.active" }, { id: "grant.revoked", revokedAt: "2026-06-03T00:00:00.000Z" }],
    listVaultRefs: () => [{ vaultRefHash: "hash-vault" }],
    listArtifacts: () => [{ id: "artifact.local" }],
    listEndpoints: () => [{ id: "endpoint.local", providerId: "provider.local" }],
    listInstances: () => [{ id: "instance.local" }],
    listRoutes: () => [{ id: "route.local-first" }],
    listModelCapabilities: () => [{ modelId: "local:auto" }],
    listBackends: () => [{ id: "backend.fixture" }],
    listBackendProcesses: () => [],
    listProviders: () => [{ id: "provider.local" }],
    catalogStatus: () => ({ status: "available" }),
    listCatalogProviderConfigs: () => [],
    listOAuthSessions: () => [],
    listOAuthStates: () => [],
    listDownloads: () => [],
    listProviderHealth: () => [{ id: "health.provider.local", receiptId: "receipt.health.1" }],
    listRuntimeEngines: () => [],
    listRuntimeEngineProfiles: () => [],
    runtimePreference: () => ({ routeId: "route.local-first" }),
    latestRuntimeSurvey: () => null,
    listMcpServers: () => [],
    listConversations: () => [],
    workflowNodeBindings: () => [],
    adapterBoundaries() {
      return buildAdapterBoundaries(this);
    },
    modelRouteDecisions() {
      return buildModelRouteDecisions(this);
    },
    projection() {
      return buildModelMountingProjection(this, { schemaVersion: SCHEMA });
    },
    listReceipts: () => receipts,
    getReceipt: (receiptId) => byId.get(receiptId),
  };
}

test("projection builder composes product-safe model mounting projection categories", () => {
  const state = fakeState();
  try {
    const projection = buildModelMountingProjection(state, { schemaVersion: SCHEMA });
    assert.equal(projection.schemaVersion, SCHEMA);
    assert.equal(projection.source, "agentgres_model_mounting_projection");
    assert.equal(projection.watermark, 6);
    assert.equal(projection.lifecycleEvents.length, 1);
    assert.equal(projection.routeReceipts.length, 1);
    assert.equal(projection.providerHealthReceipts.length, 1);
    assert.equal(projection.invocationReceipts.length, 1);
    assert.equal(projection.toolReceipts.length, 1);

    const summary = buildProjectionSummary(projection);
    assert.equal(summary.receiptCount, 6);
    assert.equal(summary.watermark, 6);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});

test("adapter and authority projections keep expected public boundaries", () => {
  const state = fakeState();
  try {
    const boundaries = buildAdapterBoundaries(state);
    assert.equal(boundaries.wallet.port, "WalletAuthorityPort");
    assert.equal(boundaries.vault.port, "VaultPort");
    assert.equal(boundaries.oauth.plaintextPersistence, false);
    assert.equal(boundaries.agentgres.port, "AgentgresStorePort");

    const authority = buildAuthoritySnapshot(state, "http://127.0.0.1:3200", { schemaVersion: SCHEMA });
    assert.equal(authority.schemaVersion, "ioi.wallet-core-lite.authority.v1");
    assert.equal(authority.summary.activeGrants, 1);
    assert.equal(authority.summary.revokedGrants, 1);
    assert.equal(authority.summary.remoteWalletConfigured, true);
    assert.equal(authority.receipts.length, 1);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});

test("receipt replay links receipt details back to projected rows", () => {
  const state = fakeState();
  try {
    const replay = buildReceiptReplay(state, "receipt.route.1", { schemaVersion: SCHEMA });
    assert.equal(replay.schemaVersion, SCHEMA);
    assert.equal(replay.route.id, "route.local-first");
    assert.equal(replay.endpoint.id, "endpoint.local");
    assert.equal(replay.provider.id, "provider.local");
    assert.equal(replay.toolReceipts[0].id, "receipt.tool.1");
    assert.equal(replay.modelRouteDecision.routeId, "route.local-first");
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});

test("route decision projections are derived only from route selection receipts", () => {
  const state = fakeState();
  try {
    const decisions = buildModelRouteDecisions(state);
    assert.equal(decisions.length, 1);
    assert.equal(decisions[0].routeId, "route.local-first");
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});
