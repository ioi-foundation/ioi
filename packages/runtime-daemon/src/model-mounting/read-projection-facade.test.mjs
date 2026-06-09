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
        provider_id: "provider.local",
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
    {
      id: "receipt-runtime",
      kind: "runtime_engine_profile",
      details: {
        runtime_engine_id: "backend.llama-cpp",
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
    endpoints: new Map([["endpoint.local", {
      id: "endpoint.local",
      modelId: "model.local",
      providerId: "provider.local",
      status: "mounted",
      capabilities: ["chat"],
      privacyClass: "local_private",
      lastReceiptId: "receipt-endpoint",
    }]]),
    instances: new Map(),
    oauthSessions: new Map(),
    oauthStates: new Map(),
    providers: new Map([["provider.local", {
      id: "provider.local",
      kind: "local",
      status: "running",
      secretRef: "vault://provider.local/api-key",
      lastReceiptId: "receipt-provider",
    }]]),
    routes: new Map([["route.local-first", {
      id: "route.local-first",
      role: "default",
      status: "active",
      fallback: ["endpoint.local"],
      privacy: "local_private",
      providerEligibility: ["provider.local"],
      deniedProviders: [],
      maxCostUsd: 0,
      maxLatencyMs: 1000,
    }]]),
    runtimeEngineProfiles: new Map([["backend.llama-cpp", {
      id: "backend.llama-cpp",
      label: "llama.cpp",
      priority: 1,
      defaultLoadOptions: { gpu: "auto" },
      updatedAt: "2026-06-03T00:00:00.000Z",
      receiptId: "receipt-runtime",
      source: "operator_runtime_engine_profile",
    }]]),
    runtimeSelections: new Map([["default", {
      id: "default",
      selectedEngineId: "backend.llama-cpp",
      selectedAt: "2026-06-03T00:00:00.000Z",
      receiptId: "receipt-runtime",
      source: "operator_runtime_engine_preference",
    }]]),
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
    lastCatalogSearch: {
      searchedAt: "2026-06-03T00:00:00.000Z",
      query: "local",
      filters: { limit: 2 },
      results: [{ id: "catalog.local", modelId: "model.local" }],
    },
    catalogProviderPorts: () => [{
      id: "catalog.fixture",
      label: "Fixture catalog",
      status: "available",
      formats: ["gguf"],
      evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
    }],
    storageSummary: () => ({
      rootHash: "sha256:model-root",
      totalBytes: 42,
      quotaBytes: null,
      quotaStatus: "ok",
      fileCount: 1,
      orphanCount: 0,
      destructiveActionsRequireUnload: true,
      evidenceRefs: ["model_storage_quota_boundary", "artifact_delete_unload_guard"],
    }),
    listBackends: () => {
      throw new Error("broad read-projection input must not read JS backend registry");
    },
    listBackendProcesses: () => {
      throw new Error("broad read-projection input must not read JS backend process maps");
    },
    listCatalogProviderConfigs: () => [],
    listConversations: () => {
      throw new Error("broad read-projection input must not read JS conversation state maps");
    },
    listMcpServers: () => {
      throw new Error("broad read-projection input must not read JS MCP server maps");
    },
    listReceipts: () => receipts,
    getReceipt: (receiptId) => receipts.find((receipt) => receipt.id === receiptId),
    provider(providerId) {
      const provider = this.providers.get(providerId);
      if (!provider) throw Object.assign(new Error(`Provider not found: ${providerId}`), { status: 404 });
      return provider;
    },
    backendRegistry: () => [{
      id: "backend.llama-cpp",
      kind: "llama_cpp",
      label: "llama.cpp",
      status: "configured",
      supportedFormats: ["gguf"],
      processStatus: "stopped",
      evidenceRefs: ["receipt-runtime"],
    }],
    listRuntimeEngineProfiles: () => {
      throw new Error("broad read-projection input must not read JS runtime engine profiles");
    },
    listRuntimeEngines: () => {
      throw new Error("broad read-projection input must not read JS runtime engine lists");
    },
    listTokens: () => [],
    listVaultRefs: () => [],
    latestRuntimeSurvey: () => null,
    lmStudioRuntimeEngines: () => [],
    runtimePreference: () => {
      throw new Error("broad read-projection input must not read JS runtime preference");
    },
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
    listJson: () => ["/state/provider-health/provider.local.json"],
    modelMountSchemaVersion: "model.mount.schema",
    path: { join: (...parts) => parts.join("/") },
    readJson: () => ({
      providerId: "provider.local",
      receiptId: "receipt-provider-health",
      status: "healthy",
    }),
    readProjectionPlanner,
    hardwareSnapshot: () => ({ cpuCount: 8 }),
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

function assertOAuthReadProjectionRetired(readFn, operationKind) {
  assert.throws(
    readFn,
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_oauth_read_projection_js_retired");
      assert.equal(error.details.operation_kind, operationKind);
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_oauth_projection");
      assert.equal(error.details.evidence_refs.includes("model_mount_oauth_read_projection_js_retired"), true);
      assert.equal(error.details.evidence_refs.includes("rust_daemon_core_catalog_provider_oauth_projection_required"), true);
      assert.equal(error.details.evidence_refs.includes("rust_daemon_core_wallet_ctee_custody_required"), true);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
}

function rustProjectionFixture(request) {
  const state = request.state;
  const receipts = state.receipts ?? [];
  if (request.projection_kind === "artifacts") return [];
  if (request.projection_kind === "product_artifacts") return [];
  if (request.projection_kind === "providers") return [];
  if (request.projection_kind === "endpoints") return [];
  if (request.projection_kind === "instances") return [];
  if (request.projection_kind === "routes") return [];
  if (request.projection_kind === "model_capabilities") return [];
  if (request.projection_kind === "downloads") return [];
  if (request.projection_kind === "oauth_sessions") return state.oauth_sessions ?? [];
  if (request.projection_kind === "oauth_states") return state.oauth_states ?? [];
  if (request.projection_kind === "provider_health") return [];
  if (request.projection_kind === "server_status") return serverStatusFromRustState(state, request.schema_version);
  if (request.projection_kind === "workflow_bindings") return workflowBindingsFromRust();
  if (request.projection_kind === "adapter_boundaries") return adapterBoundariesFromState(state);
  if (request.projection_kind === "runtime_engines") return [];
  if (request.projection_kind === "runtime_engine_profiles") return [];
  if (request.projection_kind === "runtime_preference") return null;
  if (request.projection_kind === "runtime_preference_for_endpoint") return null;
  if (request.projection_kind === "runtime_default_load_options") return null;
  if (request.projection_kind === "runtime_engine_detail") {
    throw Object.assign(new Error("runtime engine not found"), {
      code: "model_mount_runtime_engine_not_found",
    });
  }
  if (request.projection_kind === "latest_runtime_survey") return latestRuntimeSurveyFromRustState(state);
  if (request.projection_kind === "catalog_status") return catalogStatusFromRustState(state, request.schema_version);
  if (request.projection_kind === "runtime_model_catalog") return [];
  if (request.projection_kind === "open_ai_model_list") return { object: "list", data: [] };
  const projection = {
    schemaVersion: request.schema_version,
    source: "agentgres_model_mounting_projection",
    generatedAt: request.generated_at,
    watermark: receipts.length,
    artifacts: [],
    productArtifacts: [],
    endpoints: [],
    instances: [],
    routes: [],
    modelCapabilities: [],
    runtimeModelCatalog: [],
    openAiModelList: { object: "list", data: [] },
    backends: [],
    backendProcesses: [],
    providers: [],
    catalog: catalogStatusFromRustState(state, request.schema_version),
    oauthSessions: state.oauth_sessions,
    oauthStates: state.oauth_states,
    downloads: [],
    providerHealth: [],
    runtimeEngines: [],
    runtimeEngineProfiles: [],
    runtimePreference: null,
    runtimeSurvey: latestRuntimeSurveyFromRustState(state),
    grants: state.grants ?? [],
    vaultRefs: state.vault_refs ?? [],
    mcpServers: [],
    conversationStates: [],
    workflowBindings: workflowBindingsFromRust(),
    adapterBoundaries: adapterBoundariesFromState(state),
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
      server: serverStatusFromRustState(state, request.schema_version),
      catalog: catalogStatusFromRustState(state, request.schema_version),
      oauthSessions: state.oauth_sessions,
      oauthStates: state.oauth_states,
      artifacts: [],
      productArtifacts: [],
      backends: [],
      backendProcesses: [],
      endpoints: [],
      instances: [],
      providers: [],
      routes: [],
      modelCapabilities: [],
      runtimeModelCatalog: [],
      openAiModelList: { object: "list", data: [] },
      downloads: [],
      providerHealth: [],
      runtimeEngines: [],
      runtimeEngineProfiles: [],
      runtimePreference: null,
      runtimeSurvey: latestRuntimeSurveyFromRustState(state),
      tokens: state.grants ?? [],
      vaultRefs: state.vault_refs ?? [],
      mcpServers: [],
      conversationStates: [],
      workflowNodes: workflowBindingsFromRust(),
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
      server: serverStatusFromRustState(state, request.schema_version),
      wallet: state.wallet ?? null,
      vault: state.vault ?? null,
      grants: state.grants ?? [],
      vaultRefs: state.vault_refs ?? [],
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
        vaultRefs: (state.vault_refs ?? []).length,
        pendingApprovals: 0,
        receiptCount: authorityReceipts.length,
        remoteWalletConfigured: false,
      },
    };
  }
  if (request.projection_kind === "latest_provider_health") {
    const receipt = [...receipts].reverse()
      .find((candidate) =>
        candidate.kind === "provider_health" &&
        candidate.details?.provider_id === request.provider_id);
    if (!receipt) {
      throw Object.assign(new Error("provider health has not been checked"), {
        code: "model_mount_provider_health_not_found",
      });
    }
    return {
      schemaVersion: request.schema_version,
      source: "agentgres_provider_health_latest",
      providerId: request.provider_id,
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
      route: null,
      endpoint: null,
      instance: null,
      provider: null,
      toolReceipts: [],
      projectionWatermark: projection.watermark,
    };
  }
  throw new Error(`unsupported projection fixture: ${request.projection_kind}`);
}

function latestRuntimeSurveyFromRustState(state) {
  const receipt = [...(state.receipts ?? [])].reverse()
    .find((candidate) => candidate.kind === "runtime_survey");
  if (!receipt) {
    return {
      status: "not_checked",
      receiptId: "none",
      checkedAt: null,
      engineCount: 0,
      selectedEngines: [],
      runtimePreference: null,
      hardware: null,
      lmStudio: { status: "not_checked", evidenceRefs: ["runtime_survey_not_checked"] },
    };
  }
  return {
    status: "checked",
    receiptId: receipt.id,
    checkedAt: receipt.details?.checked_at ?? receipt.createdAt,
    engineCount: receipt.details?.engine_count ?? 0,
    selectedEngines: receipt.details?.selected_engines ?? [],
    runtimePreference: receipt.details?.runtime_preference ?? null,
    hardware: receipt.details?.hardware ?? null,
    lmStudio: receipt.details?.lm_studio ?? { status: "unknown" },
  };
}

function serverStatusFromRustState(state, schemaVersion) {
  const input = state.server_status_input ?? {};
  const controlState = input.control_state ?? {};
  const loadedInstances = input.loaded_instances ?? 0;
  const baseUrl = input.base_url ?? null;
  const countStatuses = (statuses = [], accepted = []) => statuses.filter((status) => accepted.includes(status)).length;
  return {
    schemaVersion: input.schema_version ?? schemaVersion,
    status: loadedInstances > 0 ? "running" : "stopped",
    gatewayStatus: controlState.gateway_status ?? "running",
    controlStatus: controlState.status ?? "running",
    lastServerOperation: controlState.operation ?? "server_status",
    lastServerOperationAt: controlState.updated_at ?? null,
    lastServerReceiptId: controlState.receipt_id ?? null,
    nativeBaseUrl: baseUrl ? `${baseUrl}/api/v1` : "/api/v1",
    openAiCompatibleBaseUrl: baseUrl ? `${baseUrl}/v1` : "/v1",
    loadedInstances,
    mountedEndpoints: input.mounted_endpoints ?? 0,
    providerStates: {
      available: countStatuses(input.provider_statuses, ["available", "configured", "running"]),
      degraded: countStatuses(input.provider_statuses, ["blocked", "absent", "stopped"]),
    },
    backendStates: {
      available: countStatuses(input.backend_statuses, ["available", "configured", "running"]),
      degraded: countStatuses(input.backend_statuses, ["blocked", "absent", "stopped", "degraded"]),
    },
    idleTtlSeconds: 900,
    autoEvict: true,
    checkedAt: input.checked_at ?? null,
  };
}

function catalogStatusFromRustState(state, schemaVersion) {
  const input = state.catalog_status_input ?? {};
  const lastSearch = input.last_search
    ? {
        searchedAt: input.last_search.searched_at ?? null,
        query: input.last_search.query ?? null,
        filters: input.last_search.filters ?? null,
        resultCount: input.last_search.result_count ?? 0,
      }
    : null;
  return {
    schemaVersion: input.schema_version ?? schemaVersion,
    checkedAt: input.checked_at ?? null,
    providers: input.providers ?? [],
    adapterBoundary: {
      port: "ModelCatalogProviderPort",
      operations: ["search", "resolveVariant", "importUrl", "download", "health"],
      evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
    },
    filters: {
      formats: ["gguf", "mlx", "safetensors"],
      quantization: ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
      compatibility: ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
    },
    storage: input.storage ?? {},
    lastSearch,
    results: input.results ?? [],
  };
}

function adapterBoundariesFromState(state) {
  void state;
  return {
    wallet: {
      port: "WalletAuthorityPort",
      implementation: "wallet_network_authority",
      methods: ["authorizeCapabilityExit", "listTokens", "revokeToken", "adapterStatus"],
      evidenceRefs: [
        "wallet.network.authority_boundary",
        "rust_daemon_core_wallet_authority_projection_required",
      ],
    },
    vault: {
      port: "VaultPort",
      implementation: "ctee_private_workspace_vault",
      methods: ["bindVaultRef", "resolveVaultRef", "listVaultRefs", "removeVaultRef", "adapterStatus"],
      plaintextPersistence: false,
      evidenceRefs: [
        "ctee_no_plaintext_custody_boundary",
        "rust_daemon_core_vault_projection_required",
      ],
    },
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
      evidenceRefs: [
        "OAuthCredentialProvider",
        "VaultOAuthAuthorizationState",
        "VaultOAuthSession",
        "oauth_tokens_not_persisted",
      ],
    },
    agentgres: {
      port: "AgentgresStorePort",
      implementation: "agentgres_admitted_model_mounting_store",
      methods: ["appendAcceptedReceipt", "recordState", "expectedHeads", "adapterStatus"],
      evidenceRefs: [
        "agentgres_model_mount_read_truth_required",
        "rust_daemon_core_agentgres_projection_required",
      ],
    },
  };
}

function workflowBindingsFromRust() {
  return [
    ["Model Call", "chat"],
    ["Structured Output", "responses"],
    ["Verifier", "chat"],
    ["Planner", "chat"],
    ["Embedding", "embeddings"],
    ["Reranker", "rerank"],
    ["Vision", "vision"],
    ["Local Tool/MCP", "mcp"],
    ["Model Router", "chat"],
    ["Receipt Gate", "receipt_gate"],
  ].map(([node, capability]) => ({
    node,
    modelId: null,
    supportsExplicitModelId: true,
    supportsModelPolicy: true,
    capability,
    receiptRequired: true,
    routeId: "route.local-first",
    daemonApi: node === "Receipt Gate" ? "/api/v1/workflows/receipt-gate" : "/api/v1/workflows/nodes/execute",
  }));
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

  assert.deepEqual(facade.runtimeModelCatalogList(state), []);
  assert.deepEqual(facade.openAiModelList(state), { object: "list", data: [] });
  assert.deepEqual(facade.listProductArtifacts(state), []);
  assert.deepEqual(facade.listArtifacts(state), []);
  assert.deepEqual(facade.listProviders(state), []);
  assert.deepEqual(facade.listEndpoints(state), []);
  assert.deepEqual(facade.listInstances(state).map((instance) => instance.id), []);
  assert.deepEqual(facade.listRoutes(state), []);
  assert.deepEqual(facade.listModelCapabilities(state), []);
  assert.deepEqual(facade.listDownloads(state), []);
  assertOAuthReadProjectionRetired(
    () => facade.listOAuthSessions(state),
    "model_mount.catalog_provider_oauth.sessions",
  );
  assertOAuthReadProjectionRetired(
    () => facade.listOAuthStates(state),
    "model_mount.catalog_provider_oauth.states",
  );
  assert.deepEqual(facade.listProviderHealth(state), []);
  const workflowBindings = facade.workflowNodeBindings(state);
  assert.equal(workflowBindings.find((binding) => binding.node === "Embedding").capability, "embeddings");
  assert.equal(workflowBindings.find((binding) => binding.node === "Reranker").capability, "rerank");
  assert.equal(workflowBindings.find((binding) => binding.node === "Receipt Gate").daemonApi, "/api/v1/workflows/receipt-gate");
  assert.equal(facade.adapterBoundaries(state).agentgres.port, "AgentgresStorePort");
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "runtime_model_catalog",
    "open_ai_model_list",
    "product_artifacts",
    "artifacts",
    "providers",
    "endpoints",
    "instances",
    "routes",
    "model_capabilities",
    "downloads",
    "provider_health",
    "workflow_bindings",
    "adapter_boundaries",
  ]);
  assert.equal(readProjectionRequests.some((request) => request.projection_kind === "oauth_sessions"), false);
  assert.equal(readProjectionRequests.some((request) => request.projection_kind === "oauth_states"), false);
  assert.equal(readProjectionRequests.filter((request) => request.projection_kind !== "projection")
    .every((request) => !Object.hasOwn(request.state, "server")), true);
  const workflowRequest = readProjectionRequests.find((request) => request.projection_kind === "workflow_bindings");
  assert.deepEqual(workflowRequest.state, {});
  const adapterRequest = readProjectionRequests.find((request) => request.projection_kind === "adapter_boundaries");
  assert.deepEqual(adapterRequest.state, {});
  const providerHealthRequest = readProjectionRequests.find((request) => request.projection_kind === "provider_health");
  assert.deepEqual(providerHealthRequest.state, {});
  const topologyRequests = readProjectionRequests.filter((request) =>
    ["artifacts", "providers", "endpoints", "instances", "routes", "model_capabilities", "downloads"].includes(
      request.projection_kind,
    ));
  assert.equal(topologyRequests.every((request) => Object.keys(request.state).length === 0), true);
  assert.equal(readProjectionRequests.slice(0, 3).every((request) => Object.keys(request.state).length === 0), true);
  assert.equal(readProjectionRequests.some((request) => Object.hasOwn(request.state, "adapter_boundaries")), false);
  assert.equal(readProjectionRequests.some((request) => Object.hasOwn(request.state, "workflow_bindings")), false);
  assert.equal(readProjectionRequests.some((request) => Object.hasOwn(request.state, "model_capabilities")), false);
  assert.equal(readProjectionRequests.some((request) => Object.hasOwn(request.state, "product_artifacts")), false);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind).slice(-2), [
    "workflow_bindings",
    "adapter_boundaries",
  ]);
});

test("read projection facade delegates runtime-engine reads through Rust projections", () => {
  const { facade, state, readProjectionRequests } = createState();

  const engines = facade.runtimeEngineList(state);
  assert.deepEqual(engines, []);

  const profiles = facade.runtimeEngineProfileList(state);
  assert.deepEqual(profiles, []);

  const preference = facade.runtimePreferenceProjection(state);
  assert.equal(preference, null);

  const endpointPreference = facade.runtimePreferenceForEndpointProjection(state, {
    backendId: "backend.llama-cpp",
  });
  assert.equal(endpointPreference, null);

  const defaultLoadOptions = facade.runtimeDefaultLoadOptionsProjection(state, "backend.llama-cpp");
  assert.equal(defaultLoadOptions, null);

  assert.throws(
    () => facade.runtimeEngineProjection(state, "backend.llama-cpp"),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.engine_id === "backend.llama-cpp",
  );

  assert.throws(
    () => facade.runtimeEngineProjection(state, "backend.missing"),
    (error) =>
      error.status === 404 &&
      error.code === "not_found" &&
      error.details.engine_id === "backend.missing",
  );

  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "runtime_engines",
    "runtime_engine_profiles",
    "runtime_preference",
    "runtime_preference_for_endpoint",
    "runtime_default_load_options",
    "runtime_engine_detail",
    "runtime_engine_detail",
  ]);
  assert.equal(readProjectionRequests.every((request) => Object.keys(request.state).length === 0), true);
  assert.equal(readProjectionRequests[4].engine_id, "backend.llama-cpp");
  assert.equal(readProjectionRequests[5].engine_id, "backend.llama-cpp");
  assert.equal(readProjectionRequests[6].engine_id, "backend.missing");
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "server")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "projection")), true);
});

test("read projection facade composes snapshots, projection, and receipt replay", () => {
  const { facade, state, readProjectionRequests } = createState();

  const snapshot = facade.snapshot(state, "http://127.0.0.1:3200");
  assert.equal(snapshot.schemaVersion, "model.mount.schema");
  assert.equal(snapshot.server.status, "stopped");
  assert.equal(snapshot.catalog.adapterBoundary.port, "ModelCatalogProviderPort");
  assert.equal(snapshot.catalog.lastSearch, null);
  assert.deepEqual(snapshot.catalog.providers, []);
  assert.deepEqual(snapshot.catalog.results, []);
  assert.equal(Object.hasOwn(snapshot, "catalogProviderConfigs"), false);
  assert.equal(snapshot.artifacts.length, 0);
  assert.equal(snapshot.endpoints.length, 0);
  assert.equal(snapshot.providers.length, 0);
  assert.equal(snapshot.routes.length, 0);
  assert.equal(snapshot.downloads.length, 0);
  assert.equal(snapshot.modelCapabilities.length, 0);
  assert.equal(snapshot.projection.source, "agentgres_model_mounting_projection");
  assert.equal(snapshot.adapterBoundaries.agentgres.port, "AgentgresStorePort");

  const projection = facade.projection(state);
  assert.equal(projection.schemaVersion, "model.mount.schema");
  assert.equal(projection.artifacts.length, 0);
  assert.equal(projection.endpoints.length, 0);
  assert.equal(projection.providers.length, 0);
  assert.equal(projection.routes.length, 0);
  assert.equal(projection.downloads.length, 0);
  assert.equal(projection.modelCapabilities.length, 0);
  assert.equal(projection.routeReceipts.length, 1);
  assert.equal(projection.lifecycleEvents.length, 1);
  assert.equal(projection.catalog.adapterBoundary.port, "ModelCatalogProviderPort");
  assert.equal(projection.catalog.lastSearch, null);
  assert.equal(Object.hasOwn(projection, "catalogProviderConfigs"), false);
  assert.equal(projection.adapterBoundaries.agentgres.port, "AgentgresStorePort");
  assert.equal(projection.adapterBoundaries.oauth.plaintextPersistence, false);

  const projectionWritePlan = facade.canonicalProjectionWritePlan(state);
  assert.equal(projectionWritePlan.source, "rust_model_mount_read_projection_command");
  assert.equal(projectionWritePlan.projection_kind, "projection");
  assert.equal(projectionWritePlan.projection.source, "agentgres_model_mounting_projection");
  assert.equal(projectionWritePlan.evidence_refs.includes("agentgres_model_mount_read_truth"), true);

  const summary = facade.projectionSummary(state);
  assert.equal(summary.schemaVersion, "model.mount.schema");
  assert.equal(summary.receiptCount, 5);

  const replay = facade.receiptReplay(state, "receipt-route");
  assert.equal(replay.schemaVersion, "model.mount.schema");
  assert.equal(replay.route, null);
  assert.equal(replay.endpoint, null);
  assert.equal(replay.provider, null);
  assert.equal(replay.model_route_decision.selected_model, "model.local");
  assert.equal(Object.hasOwn(replay, "modelRouteDecision"), false);

  const routeDecisions = facade.modelRouteDecisions(state);
  assert.equal(routeDecisions[0].receipt_id, "receipt-route");
  assert.equal(routeDecisions[0].selected_model, "model.local");

  const authority = facade.authoritySnapshot(state, "http://127.0.0.1:3200");
  assert.equal(authority.schemaVersion, "ioi.wallet-core-lite.authority.v1");
  assert.equal(authority.wallet, null);
  assert.deepEqual(authority.grants, []);
  assert.deepEqual(authority.vaultRefs, []);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "snapshot",
    "projection",
    "projection",
    "projection_summary",
    "receipt_replay",
    "model_route_decisions",
    "authority_snapshot",
  ]);
  const snapshotRequest = readProjectionRequests[0];
  assert.equal(Object.hasOwn(snapshotRequest.state, "catalog"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "backends"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "backend_processes"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "catalog_status_input"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "catalog_provider_configs"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "oauth_sessions"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "oauth_states"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "runtime_engines"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "runtime_engine_profiles"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "runtime_preference"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "mcp_servers"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "conversation_states"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "grants"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "vault_refs"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "agentgres_store"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "wallet"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "vault"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "provider_health"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "runtime_survey_input"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "server_status_input"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "artifacts"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "endpoints"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "instances"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "routes"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "downloads"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state, "product_artifact_policy"), false);
  const projectionRequest = readProjectionRequests[1];
  assert.equal(Object.hasOwn(projectionRequest.state, "catalog"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "backends"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "backend_processes"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "catalog_status_input"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "catalog_provider_configs"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "oauth_sessions"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "oauth_states"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "runtime_engines"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "runtime_engine_profiles"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "runtime_preference"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "mcp_servers"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "conversation_states"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "grants"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "vault_refs"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "agentgres_store"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "wallet"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "vault"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "provider_health"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "runtime_survey_input"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "server_status_input"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "artifacts"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "endpoints"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "instances"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "routes"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "downloads"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "product_artifact_policy"), false);
  const summaryRequest = readProjectionRequests.find((request) => request.projection_kind === "projection_summary");
  assert.deepEqual(Object.keys(summaryRequest.state), ["receipts"]);
  const replayRequest = readProjectionRequests.find((request) => request.projection_kind === "receipt_replay");
  assert.deepEqual(Object.keys(replayRequest.state), ["receipts"]);
  assert.equal(replayRequest.receipt_id, "receipt-route");
  assert.equal(Object.hasOwn(replayRequest.state, "routes"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "endpoints"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "instances"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "server"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "artifacts"), false);
  const routeDecisionRequest = readProjectionRequests.find((request) => request.projection_kind === "model_route_decisions");
  assert.deepEqual(Object.keys(routeDecisionRequest.state), ["receipts"]);
  const authorityRequest = readProjectionRequests.at(-1);
  assert.deepEqual(Object.keys(authorityRequest.state), ["receipts"]);
  assert.equal(Object.hasOwn(authorityRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "artifacts"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "server_status_input"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "grants"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "vault_refs"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "wallet"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "vault"), false);
});

test("read projection facade delegates server status through Rust projection", () => {
  const { facade, state, readProjectionRequests } = createState();

  const status = facade.serverStatus(state, "http://127.0.0.1:3200");

  assert.equal(status.schemaVersion, "model.mount.schema");
  assert.equal(status.status, "stopped");
  assert.equal(status.gatewayStatus, "running");
  assert.equal(status.nativeBaseUrl, "http://127.0.0.1:3200/api/v1");
  assert.equal(status.openAiCompatibleBaseUrl, "http://127.0.0.1:3200/v1");
  assert.equal(status.loadedInstances, 0);
  assert.equal(status.mountedEndpoints, 1);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), ["server_status"]);
  assert.deepEqual(Object.keys(readProjectionRequests[0].state), ["server_status_input"]);
  assert.equal(readProjectionRequests[0].state.server_status_input.loaded_instances, 0);
  assert.equal(readProjectionRequests[0].state.server_status_input.mounted_endpoints, 1);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state.server_status_input, "status"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state.server_status_input, "provider_statuses"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state.server_status_input, "backend_statuses"), false);
  assert.equal(readProjectionRequests[0].base_url, "http://127.0.0.1:3200");
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "receipts"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "projection"), false);
});

test("read projection facade catalog status fails closed before JS catalog-status input", () => {
  const { facade, state, readProjectionRequests } = createState();

  assert.throws(
    () => facade.catalogStatus(state),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_catalog_status_js_readback_retired");
      assert.equal(error.details.operation_kind, "model_catalog.status");
      assert.equal(error.details.rust_core_boundary, "model_mount.catalog_provider_status_projection");
      return true;
    },
  );
  assert.deepEqual(readProjectionRequests, []);
});

test("read projection facade projects latest provider and vault health envelopes", () => {
  const { facade, state, readProjectionRequests } = createState();

  const providerHealth = facade.latestProviderHealth(state, "provider.local");
  assert.equal(providerHealth.schemaVersion, "model.mount.schema");
  assert.equal(providerHealth.source, "agentgres_provider_health_latest");
  assert.equal(providerHealth.providerId, "provider.local");
  assert.equal(providerHealth.health.status, "healthy");
  assert.equal(providerHealth.health.provider_id, "provider.local");
  assert.equal(providerHealth.receipt.id, "receipt-provider-health");
  assert.equal(providerHealth.replay.receipt.id, "receipt-provider-health");
  assert.equal(providerHealth.projectionWatermark, 5);

  const vaultHealth = facade.latestVaultHealth(state);
  assert.equal(vaultHealth.schemaVersion, "model.mount.schema");
  assert.equal(vaultHealth.source, "agentgres_vault_health_latest");
  assert.equal(vaultHealth.health.implementation, "runtime_memory_vault");
  assert.equal(vaultHealth.receipt.id, "receipt-vault-health");
  assert.equal(vaultHealth.replay.receipt.id, "receipt-vault-health");
  assert.equal(vaultHealth.projectionWatermark, 5);
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "latest_provider_health",
    "latest_vault_health",
  ]);
  assert.equal(readProjectionRequests[0].provider_id, "provider.local");
  assert.deepEqual(Object.keys(readProjectionRequests[0].state), ["receipts"]);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "provider_health"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "providers"), false);
  assert.deepEqual(Object.keys(readProjectionRequests[1].state), ["receipts"]);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "server")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "artifacts")), true);
});

test("read projection facade delegates latest runtime survey through Rust projection", () => {
  const { facade, state, readProjectionRequests } = createState();

  const notChecked = facade.latestRuntimeSurvey(state);
  assert.equal(notChecked.status, "not_checked");
  assert.equal(notChecked.receiptId, "none");
  assert.equal(notChecked.engineCount, 0);
  assert.equal(notChecked.runtimePreference, null);
  assert.equal(notChecked.hardware, null);
  assert.equal(notChecked.lmStudio.status, "not_checked");

  state.listReceipts().push({
    id: "receipt-runtime-survey",
    kind: "runtime_survey",
    createdAt: "2026-06-03T00:01:00.000Z",
    details: {
      checked_at: "2026-06-03T00:01:00.000Z",
      engine_count: 1,
      selected_engines: ["backend.llama-cpp"],
      runtime_preference: { selectedEngineId: "backend.llama-cpp" },
      hardware: { cpuCount: 16 },
      lm_studio: { status: "available" },
    },
  });
  const checked = facade.latestRuntimeSurvey(state);
  assert.equal(checked.status, "checked");
  assert.equal(checked.receiptId, "receipt-runtime-survey");
  assert.deepEqual(checked.selectedEngines, ["backend.llama-cpp"]);
  assert.deepEqual(checked.hardware, { cpuCount: 16 });
  assert.equal(checked.lmStudio.status, "available");

  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), [
    "latest_runtime_survey",
    "latest_runtime_survey",
  ]);
  assert.deepEqual(Object.keys(readProjectionRequests[0].state), ["receipts"]);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "runtime_survey_input"), false);
  assert.equal(readProjectionRequests[1].state.receipts.at(-1).id, "receipt-runtime-survey");
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "server")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "runtime_survey")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "runtime_survey_input")), true);
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
  assert.deepEqual(Object.keys(readProjectionRequests[0].state).sort(), [
    "receipts",
  ]);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "provider_health"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "providers"), false);
  assert.deepEqual(Object.keys(readProjectionRequests[1].state), ["receipts"]);
});
