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
    backendRegistry: () => [{
      id: "backend.llama-cpp",
      kind: "llama_cpp",
      label: "llama.cpp",
      status: "configured",
      supportedFormats: ["gguf"],
      processStatus: "stopped",
      evidenceRefs: ["receipt-runtime"],
    }],
    listRuntimeEngineProfiles: () => [],
    listRuntimeEngines: () => [],
    listTokens: () => [],
    listVaultRefs: () => [],
    latestRuntimeSurvey: () => null,
    lmStudioRuntimeEngines: () => [],
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
    internalFixtureModelsEnabled: () => false,
    isFixtureModelRecord: (artifact) => artifact.family === "fixture",
    listJson: () => ["/state/provider-health/provider.local.json"],
    modelMountSchemaVersion: "model.mount.schema",
    path: { join: (...parts) => parts.join("/") },
    providerHasVaultRef: (provider) => Boolean(provider.secretRef),
    publicOAuthSession: (session) => ({ id: session.id }),
    publicOAuthState: (oauthState) => ({ id: oauthState.id }),
    publicProvider: (provider, vaultMetadata) => ({ ...provider, vaultMetadata }),
    readJson: () => ({
      providerId: "provider.local",
      receiptId: "receipt-provider-health",
      status: "healthy",
    }),
    readProjectionPlanner,
    hardwareSnapshot: () => ({ cpuCount: 8 }),
    catalogProviderStatus: (port) => ({
      id: port.id,
      label: port.label,
      status: port.status,
      formats: port.formats,
      adapterPort: "ModelCatalogProviderPort",
      operations: ["search", "resolveVariant", "importUrl", "download", "health"],
      evidenceRefs: port.evidenceRefs,
    }),
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
  if (request.projection_kind === "artifacts") return state.artifacts ?? [];
  if (request.projection_kind === "product_artifacts") return productArtifactsFromRustState(state);
  if (request.projection_kind === "providers") return state.providers ?? [];
  if (request.projection_kind === "endpoints") return state.endpoints ?? [];
  if (request.projection_kind === "instances") return state.instances ?? [];
  if (request.projection_kind === "routes") return state.routes ?? [];
  if (request.projection_kind === "model_capabilities") return modelCapabilitiesFromRustState(state);
  if (request.projection_kind === "downloads") return state.downloads ?? [];
  if (request.projection_kind === "oauth_sessions") return state.oauth_sessions ?? [];
  if (request.projection_kind === "oauth_states") return state.oauth_states ?? [];
  if (request.projection_kind === "provider_health") return state.provider_health ?? [];
  if (request.projection_kind === "server_status") return serverStatusFromRustState(state, request.schema_version);
  if (request.projection_kind === "workflow_bindings") return workflowBindingsFromRust();
  if (request.projection_kind === "adapter_boundaries") return adapterBoundariesFromState(state);
  if (request.projection_kind === "runtime_engines") return state.runtime_engines ?? [];
  if (request.projection_kind === "runtime_engine_profiles") return state.runtime_engine_profiles ?? [];
  if (request.projection_kind === "runtime_preference") return state.runtime_preference ?? null;
  if (request.projection_kind === "runtime_preference_for_endpoint") return state.runtime_preference ?? null;
  if (request.projection_kind === "runtime_default_load_options") return state.default_load_options ?? {};
  if (request.projection_kind === "runtime_engine_detail") {
    if (!state.runtime_engine) {
      throw Object.assign(new Error("runtime engine not found"), {
        code: "model_mount_runtime_engine_not_found",
      });
    }
    return state.runtime_engine;
  }
  if (request.projection_kind === "latest_runtime_survey") return latestRuntimeSurveyFromRustState(state);
  if (request.projection_kind === "catalog_status") return catalogStatusFromRustState(state, request.schema_version);
  if (request.projection_kind === "runtime_model_catalog") return runtimeModelCatalogFromRustState(state);
  if (request.projection_kind === "open_ai_model_list") return openAiModelListFromRustState(state, request.generated_at);
  const projection = {
    schemaVersion: request.schema_version,
    source: "agentgres_model_mounting_projection",
    generatedAt: request.generated_at,
    watermark: receipts.length,
    artifacts: state.artifacts,
    productArtifacts: productArtifactsFromRustState(state),
    endpoints: state.endpoints,
    instances: state.instances,
    routes: state.routes,
    modelCapabilities: modelCapabilitiesFromRustState(state),
    runtimeModelCatalog: runtimeModelCatalogFromRustState(state),
    openAiModelList: openAiModelListFromRustState(state, request.generated_at),
    backends: state.backends,
    backendProcesses: state.backend_processes,
    providers: state.providers,
    catalog: catalogStatusFromRustState(state, request.schema_version),
    catalogProviderConfigs: state.catalog_provider_configs,
    oauthSessions: state.oauth_sessions,
    oauthStates: state.oauth_states,
    downloads: state.downloads,
    providerHealth: state.provider_health,
    runtimeEngines: state.runtime_engines,
    runtimeEngineProfiles: state.runtime_engine_profiles,
    runtimePreference: state.runtime_preference,
    runtimeSurvey: latestRuntimeSurveyFromRustState(state),
    grants: state.grants,
    vaultRefs: state.vault_refs,
    mcpServers: state.mcp_servers,
    conversationStates: state.conversation_states,
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
      catalogProviderConfigs: state.catalog_provider_configs,
      oauthSessions: state.oauth_sessions,
      oauthStates: state.oauth_states,
      artifacts: state.artifacts,
      productArtifacts: productArtifactsFromRustState(state),
      backends: state.backends,
      backendProcesses: state.backend_processes,
      endpoints: state.endpoints,
      instances: state.instances,
      providers: state.providers,
      routes: state.routes,
      modelCapabilities: modelCapabilitiesFromRustState(state),
      runtimeModelCatalog: runtimeModelCatalogFromRustState(state),
      openAiModelList: openAiModelListFromRustState(state, request.generated_at),
      downloads: state.downloads,
      providerHealth: state.provider_health,
      runtimeEngines: state.runtime_engines,
      runtimeEngineProfiles: state.runtime_engine_profiles,
      runtimePreference: state.runtime_preference,
      runtimeSurvey: latestRuntimeSurveyFromRustState(state),
      tokens: state.grants,
      vaultRefs: state.vault_refs,
      mcpServers: state.mcp_servers,
      conversationStates: state.conversation_states,
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

function latestRuntimeSurveyFromRustState(state) {
  const receipt = [...(state.receipts ?? [])].reverse()
    .find((candidate) => candidate.kind === "runtime_survey");
  const input = state.runtime_survey_input ?? {};
  if (!receipt) {
    return {
      status: "not_checked",
      receiptId: "none",
      checkedAt: null,
      engineCount: input.engine_count ?? 0,
      selectedEngines: [],
      runtimePreference: input.runtime_preference ?? null,
      hardware: input.hardware ?? null,
      lmStudio: { status: "not_checked", evidenceRefs: ["runtime_survey_not_checked"] },
    };
  }
  return {
    status: "checked",
    receiptId: receipt.id,
    checkedAt: receipt.details?.checked_at ?? receipt.createdAt,
    engineCount: receipt.details?.engine_count ?? 0,
    selectedEngines: receipt.details?.selected_engines ?? [],
    runtimePreference: receipt.details?.runtime_preference ?? input.runtime_preference ?? null,
    hardware: receipt.details?.hardware ?? input.hardware ?? null,
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

function productArtifactsFromRustState(state) {
  const includeInternalFixtures = Boolean(state.product_artifact_policy?.include_internal_fixtures);
  return (state.artifacts ?? []).filter((artifact) => includeInternalFixtures || !artifactIsInternalFixture(artifact));
}

function runtimeModelCatalogFromRustState(state) {
  return [...productArtifactsFromRustState(state)]
    .sort((left, right) => String(left.modelId ?? "").localeCompare(String(right.modelId ?? "")))
    .map((artifact) => ({
      id: artifact.modelId ?? null,
      provider: (artifact.providerId === "provider.local.folder" || artifact.providerId === "provider.autopilot.local")
        ? "ioi-daemon-local"
        : artifact.providerId ?? null,
      cost: artifact.privacyClass === "local_private" ? "local" : "metered",
      quality: artifact.family === "fixture" ? "adaptive" : "provider",
      capabilities: artifact.capabilities ?? [],
      privacyClass: artifact.privacyClass ?? null,
      route: "route.local-first",
    }));
}

function openAiModelListFromRustState(state, generatedAt) {
  return {
    object: "list",
    data: productArtifactsFromRustState(state).map((artifact) => ({
      id: artifact.modelId ?? null,
      object: "model",
      created: Math.floor(Date.parse(artifact.discoveredAt ?? generatedAt) / 1000),
      owned_by: artifact.providerId ?? null,
      permission: [],
      root: artifact.modelId ?? null,
      parent: null,
    })),
  };
}

function artifactIsInternalFixture(artifact) {
  const haystack = [
    artifact.id,
    artifact.modelId,
    artifact.model_id,
    artifact.displayName,
    artifact.name,
    artifact.family,
    artifact.quantization,
    artifact.source,
    artifact.driver,
    artifact.providerId,
    artifact.provider_id,
    artifact.artifactPath,
    artifact.artifact_path,
  ].map((value) => String(value ?? "").toLowerCase()).join(" ");
  return haystack.includes("fixture")
    || haystack.includes("local:auto")
    || haystack.includes("autopilot:native-fixture")
    || haystack.includes("stories260k");
}

function modelCapabilitiesFromRustState(state) {
  const endpointById = new Map((state.endpoints ?? []).map((endpoint) => [endpoint.id, endpoint]));
  const providerById = new Map((state.providers ?? []).map((provider) => [provider.id, provider]));
  const artifactByModelId = new Map((state.artifacts ?? []).map((artifact) => [artifact.modelId, artifact]));
  const loadedEndpointIds = new Set(
    (state.instances ?? []).filter((instance) => instance.status === "loaded").map((instance) => instance.endpointId),
  );
  return (state.routes ?? []).map((route) => {
    const candidates = (route.fallback ?? []).map((endpointId, priority) => {
      const endpoint = endpointById.get(endpointId) ?? null;
      const provider = endpoint ? providerById.get(endpoint.providerId) ?? null : null;
      const artifact = endpoint ? artifactByModelId.get(endpoint.modelId) ?? null : null;
      const vaultRequired = Boolean(provider?.vaultBoundary?.required)
        || ["openai", "anthropic", "gemini", "custom_http"].includes(String(provider?.kind));
      const vaultReady = !vaultRequired || Boolean(provider?.secretConfigured || provider?.vaultBoundary?.configured);
      const providerReady = ["available", "configured", "running"].includes(String(provider?.status));
      const endpointReady = endpoint ? endpoint.status === "mounted" || loadedEndpointIds.has(endpoint.id) : false;
      const ready = route.status === "active" && endpointReady && providerReady && vaultReady;
      const reason = !endpoint
        ? "Route fallback endpoint is not registered."
        : !provider
          ? "Endpoint provider is not registered."
          : !providerReady
            ? `Provider status is ${provider.status}.`
            : vaultRequired && !vaultReady
              ? "Provider requires wallet vault credentials."
              : !endpointReady
                ? `Endpoint status is ${endpoint.status}.`
                : "Endpoint, provider, and credential posture are ready.";
      const evidenceRefs = [...new Set([
        endpoint?.lastReceiptId,
        provider?.lastReceiptId,
        artifact?.lastReceiptId,
        ...(endpoint?.evidenceRefs ?? []),
        ...(provider?.evidenceRefs ?? []),
      ].filter((value) => typeof value === "string" && value.trim()))];
      return {
        endpoint_id: endpointId,
        priority,
        model_id: endpoint?.modelId ?? null,
        provider_id: provider?.id ?? null,
        provider_kind: provider?.kind ?? null,
        capability: endpoint?.capabilities?.[0] ?? artifact?.capabilities?.[0] ?? "chat",
        privacy_tier: endpoint?.privacyClass ?? provider?.privacyClass ?? route.privacy,
        status: ready ? "ready" : "blocked",
        ready,
        vault_required: vaultRequired,
        vault_ready: vaultReady,
        reason,
        evidence_refs: evidenceRefs,
        evidence: {
          endpoint_id: endpointId,
          provider_id: provider?.id ?? null,
          status: ready ? "ready" : "blocked",
          reason,
          vault_required: vaultRequired,
          vault_ready: vaultReady,
        },
      };
    });
    const readyCandidates = candidates.filter((candidate) => candidate.ready);
    const selectedCandidate = readyCandidates[0] ?? candidates[0] ?? null;
    const capability = selectedCandidate?.capability ?? "chat";
    const evidenceRefs = [...new Set(candidates.flatMap((candidate) => candidate.evidence_refs))];
    const missingVaultCount = candidates.filter((candidate) => candidate.vault_required && !candidate.vault_ready).length;
    const available = route.status === "active" && readyCandidates.length > 0;
    return {
      schema_version: "ioi.model-capability.v1",
      object: "ioi.model_capability",
      id: `model-capability:${route.id}`,
      route_id: route.id,
      role: route.role ?? null,
      model_role: route.role ?? null,
      capability,
      primitive_capability: `prim:model.${capability}`,
      authority_scope_requirements: [`route.use:${route.id}`, `model.${capability}:*`],
      policy_target: route.id.startsWith("route.") ? `model.${route.id}` : `model.route.${route.id}`,
      privacy_tier: route.privacy ?? null,
      provider_priority: route.providerEligibility ?? null,
      fallback_policy: {
        allowed: (route.fallback ?? []).length > 1,
        endpoint_ids: route.fallback ?? [],
        denied_providers: route.deniedProviders ?? null,
        selected_endpoint_id: selectedCandidate?.endpoint_id ?? null,
        deterministic_order: true,
      },
      fallback_evidence: candidates.map((candidate) => candidate.evidence),
      cost_estimate_visibility: {
        visible: true,
        max_cost_usd: route.maxCostUsd ?? null,
        max_latency_ms: route.maxLatencyMs ?? null,
        source: "model_route_policy",
      },
      credential_readiness: {
        status: route.status !== "active" ? "disabled" : readyCandidates.length > 0 ? "ready" : missingVaultCount > 0 ? "missing" : "degraded",
        reason: route.status !== "active"
          ? "Model route is disabled."
          : readyCandidates.length > 0
            ? "Route has an executable candidate."
            : candidates[0]?.reason ?? "Route has no configured fallback candidates.",
        evidence_refs: evidenceRefs,
      },
      vault_readiness: {
        status: missingVaultCount === 0 ? "ready" : "missing",
        required_count: candidates.filter((candidate) => candidate.vault_required).length,
        configured_count: candidates.filter((candidate) => candidate.vault_required && candidate.vault_ready).length,
        missing_count: missingVaultCount,
      },
      byok_required: candidates.some((candidate) => candidate.vault_required),
      receipt_behavior: {
        receipt_required: true,
        required_receipt_types: ["model_route_selection", "model_invocation"],
      },
      workflow_availability: {
        available,
        reason: available ? "At least one route candidate is executable." : "No executable model route candidate is ready.",
        config_fields: ["model_ref", "route_id", "model_binding"],
        evidence_refs: evidenceRefs,
      },
      agent_availability: {
        available,
        reason: available ? "Agent runtime can request this route capability." : "Agent runtime must resolve model readiness first.",
        evidence_refs: evidenceRefs,
      },
      candidates,
    };
  });
}

function adapterBoundariesFromState(state) {
  return {
    wallet: state.wallet,
    vault: state.vault,
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
    agentgres: state.agentgres_store,
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

  assert.deepEqual(facade.runtimeModelCatalogList(state).map((model) => model.id), ["model.local"]);
  assert.deepEqual(facade.openAiModelList(state).data.map((model) => model.id), ["model.local"]);
  assert.deepEqual(facade.listProductArtifacts(state).map((artifact) => artifact.id), ["artifact.local"]);
  assert.deepEqual(facade.listArtifacts(state).map((artifact) => artifact.id), ["artifact.fixture", "artifact.local"]);
  assert.deepEqual(facade.listProviders(state).map((provider) => ({
    id: provider.id,
    kind: provider.kind,
    status: provider.status,
    vaultMetadata: provider.vaultMetadata,
  })), [
    {
      id: "provider.local",
      kind: "local",
      status: "running",
      vaultMetadata: { secretRef: "vault://provider.local/api-key", configured: true },
    },
  ]);
  assert.deepEqual(facade.listEndpoints(state).map((endpoint) => endpoint.id), ["endpoint.local"]);
  assert.deepEqual(facade.listInstances(state).map((instance) => instance.id), []);
  assert.deepEqual(facade.listRoutes(state).map((route) => route.id), ["route.local-first"]);
  const [modelCapability] = facade.listModelCapabilities(state);
  assert.equal(modelCapability.route_id, "route.local-first");
  assert.equal(modelCapability.credential_readiness.status, "ready");
  assert.equal(modelCapability.candidates[0].model_id, "model.local");
  assert.deepEqual(facade.listDownloads(state).map((download) => download.id), ["download.one"]);
  assert.deepEqual(facade.listOAuthSessions(state), []);
  assert.deepEqual(facade.listOAuthStates(state), []);
  assert.deepEqual(facade.listProviderHealth(state).map((health) => health.receiptId), ["receipt-provider-health"]);
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
    "oauth_sessions",
    "oauth_states",
    "provider_health",
    "workflow_bindings",
    "adapter_boundaries",
  ]);
  assert.equal(readProjectionRequests.filter((request) => request.projection_kind !== "projection")
    .every((request) => !Object.hasOwn(request.state, "server")), true);
  const workflowRequest = readProjectionRequests.find((request) => request.projection_kind === "workflow_bindings");
  assert.deepEqual(workflowRequest.state, {});
  const adapterRequest = readProjectionRequests.find((request) => request.projection_kind === "adapter_boundaries");
  assert.deepEqual(Object.keys(adapterRequest.state).sort(), ["agentgres_store", "vault", "wallet"]);
  assert.equal(adapterRequest.state.agentgres_store.port, "AgentgresStorePort");
  assert.equal(
    readProjectionRequests.slice(0, 4).every((request) =>
      request.state.product_artifact_policy.include_internal_fixtures === false),
    true,
  );
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
  assert.deepEqual(engines.map((engine) => engine.id), ["backend.llama-cpp"]);
  assert.equal(engines[0].operatorProfile.defaultLoadOptions.gpu, "auto");

  const profiles = facade.runtimeEngineProfileList(state);
  assert.deepEqual(profiles.map((profile) => profile.id), ["backend.llama-cpp"]);

  const preference = facade.runtimePreferenceProjection(state);
  assert.equal(preference.selectedEngineId, "backend.llama-cpp");
  assert.equal(preference.defaultLoadOptions.gpu, "auto");

  const endpointPreference = facade.runtimePreferenceForEndpointProjection(state, {
    backendId: "backend.llama-cpp",
  });
  assert.equal(endpointPreference.selectedEngineId, "backend.llama-cpp");

  const defaultLoadOptions = facade.runtimeDefaultLoadOptionsProjection(state, "backend.llama-cpp");
  assert.deepEqual(defaultLoadOptions, { gpu: "auto" });

  const runtimeEngine = facade.runtimeEngineProjection(state, "backend.llama-cpp");
  assert.equal(runtimeEngine.id, "backend.llama-cpp");
  assert.equal(runtimeEngine.profile.id, "backend.llama-cpp");
  assert.equal(runtimeEngine.preference.selectedEngineId, "backend.llama-cpp");
  assert.deepEqual(runtimeEngine.latestReceipts.map((receipt) => receipt.id), ["receipt-runtime"]);

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
  assert.deepEqual(Object.keys(readProjectionRequests[0].state), ["runtime_engines"]);
  assert.deepEqual(Object.keys(readProjectionRequests[1].state), ["runtime_engine_profiles"]);
  assert.deepEqual(Object.keys(readProjectionRequests[2].state), ["runtime_preference"]);
  assert.deepEqual(Object.keys(readProjectionRequests[3].state), ["runtime_preference"]);
  assert.deepEqual(Object.keys(readProjectionRequests[4].state), ["default_load_options"]);
  assert.deepEqual(Object.keys(readProjectionRequests[5].state), ["runtime_engine"]);
  assert.equal(readProjectionRequests[4].engine_id, "backend.llama-cpp");
  assert.equal(readProjectionRequests[5].engine_id, "backend.llama-cpp");
  assert.equal(readProjectionRequests[6].engine_id, "backend.missing");
  assert.equal(readProjectionRequests[6].state.runtime_engine, null);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "server")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "projection")), true);
});

test("read projection facade composes snapshots, projection, and receipt replay", () => {
  const { facade, state, readProjectionRequests } = createState();

  const snapshot = facade.snapshot(state, "http://127.0.0.1:3200");
  assert.equal(snapshot.schemaVersion, "model.mount.schema");
  assert.equal(snapshot.server.status, "stopped");
  assert.equal(snapshot.catalog.adapterBoundary.port, "ModelCatalogProviderPort");
  assert.equal(snapshot.catalog.lastSearch.resultCount, 1);
  assert.equal(snapshot.artifacts.length, 2);
  assert.equal(snapshot.modelCapabilities.length, 1);
  assert.equal(snapshot.modelCapabilities[0].credential_readiness.status, "ready");
  assert.equal(snapshot.projection.source, "agentgres_model_mounting_projection");
  assert.equal(snapshot.adapterBoundaries.agentgres.port, "AgentgresStorePort");

  const projection = facade.projection(state);
  assert.equal(projection.schemaVersion, "model.mount.schema");
  assert.equal(projection.routeReceipts.length, 1);
  assert.equal(projection.lifecycleEvents.length, 1);
  assert.equal(projection.catalog.adapterBoundary.port, "ModelCatalogProviderPort");
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
  assert.equal(replay.route.id, "route.local-first");
  assert.equal(replay.endpoint.id, "endpoint.local");
  assert.equal(replay.provider.id, "provider.local");
  assert.equal(replay.model_route_decision.selected_model, "model.local");
  assert.equal(Object.hasOwn(replay, "modelRouteDecision"), false);

  const routeDecisions = facade.modelRouteDecisions(state);
  assert.equal(routeDecisions[0].receipt_id, "receipt-route");
  assert.equal(routeDecisions[0].selected_model, "model.local");

  const authority = facade.authoritySnapshot(state, "http://127.0.0.1:3200");
  assert.equal(authority.schemaVersion, "ioi.wallet-core-lite.authority.v1");
  assert.equal(authority.wallet.port, "WalletAuthorityPort");
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
  assert.equal(Object.hasOwn(snapshotRequest.state, "catalog_status_input"), true);
  assert.equal(Object.hasOwn(snapshotRequest.state.catalog_status_input, "adapterBoundary"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state.catalog_status_input, "filters"), false);
  assert.equal(Object.hasOwn(snapshotRequest.state.catalog_status_input, "schemaVersion"), false);
  const projectionRequest = readProjectionRequests[1];
  assert.equal(Object.hasOwn(projectionRequest.state, "catalog"), false);
  assert.equal(Object.hasOwn(projectionRequest.state, "catalog_status_input"), true);
  const summaryRequest = readProjectionRequests.find((request) => request.projection_kind === "projection_summary");
  assert.deepEqual(Object.keys(summaryRequest.state), ["receipts"]);
  const replayRequest = readProjectionRequests.find((request) => request.projection_kind === "receipt_replay");
  assert.deepEqual(Object.keys(replayRequest.state).sort(), [
    "endpoints",
    "instances",
    "providers",
    "receipts",
    "routes",
  ]);
  assert.equal(replayRequest.receipt_id, "receipt-route");
  assert.equal(replayRequest.state.routes[0].id, "route.local-first");
  assert.equal(replayRequest.state.endpoints[0].id, "endpoint.local");
  assert.equal(Object.hasOwn(replayRequest.state, "server"), false);
  assert.equal(Object.hasOwn(replayRequest.state, "artifacts"), false);
  const routeDecisionRequest = readProjectionRequests.find((request) => request.projection_kind === "model_route_decisions");
  assert.deepEqual(Object.keys(routeDecisionRequest.state), ["receipts"]);
  const authorityRequest = readProjectionRequests.at(-1);
  assert.deepEqual(Object.keys(authorityRequest.state).sort(), [
    "grants",
    "receipts",
    "server_status_input",
    "vault",
    "vault_refs",
    "wallet",
  ]);
  assert.equal(authorityRequest.state.wallet.port, "WalletAuthorityPort");
  assert.equal(Object.hasOwn(authorityRequest.state, "providers"), false);
  assert.equal(Object.hasOwn(authorityRequest.state, "artifacts"), false);
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
  assert.equal(readProjectionRequests[0].base_url, "http://127.0.0.1:3200");
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "receipts"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "projection"), false);
});

test("read projection facade delegates catalog status through Rust projection", () => {
  const { facade, state, readProjectionRequests } = createState();

  const status = facade.catalogStatus(state);

  assert.equal(status.schemaVersion, "model.mount.schema");
  assert.equal(status.checkedAt, "2026-06-03T00:00:00.000Z");
  assert.equal(status.providers[0].id, "catalog.fixture");
  assert.equal(status.adapterBoundary.port, "ModelCatalogProviderPort");
  assert.equal(status.filters.formats.includes("gguf"), true);
  assert.equal(status.storage.totalBytes, 42);
  assert.equal(status.lastSearch.resultCount, 1);
  assert.equal(status.results[0].id, "catalog.local");
  assert.deepEqual(readProjectionRequests.map((request) => request.projection_kind), ["catalog_status"]);
  assert.deepEqual(Object.keys(readProjectionRequests[0].state), ["catalog_status_input"]);
  assert.equal(readProjectionRequests[0].state.catalog_status_input.schema_version, "model.mount.schema");
  assert.equal(readProjectionRequests[0].state.catalog_status_input.providers[0].adapterPort, "ModelCatalogProviderPort");
  assert.equal(readProjectionRequests[0].state.catalog_status_input.last_search.result_count, 1);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state.catalog_status_input, "adapterBoundary"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state.catalog_status_input, "filters"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state.catalog_status_input, "schemaVersion"), false);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state, "catalog"), false);
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
  assert.deepEqual(Object.keys(readProjectionRequests[0].state).sort(), [
    "provider_health",
    "providers",
    "receipts",
  ]);
  assert.equal(readProjectionRequests[0].state.providers[0].id, "provider.local");
  assert.equal(Object.hasOwn(readProjectionRequests[0].state.providers[0], "providerId"), false);
  assert.deepEqual(Object.keys(readProjectionRequests[1].state), ["receipts"]);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "server")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "artifacts")), true);
});

test("read projection facade delegates latest runtime survey through Rust projection", () => {
  const { facade, state, readProjectionRequests } = createState();

  const notChecked = facade.latestRuntimeSurvey(state);
  assert.equal(notChecked.status, "not_checked");
  assert.equal(notChecked.receiptId, "none");
  assert.equal(notChecked.engineCount, 1);
  assert.equal(notChecked.runtimePreference.selectedEngineId, "backend.llama-cpp");
  assert.deepEqual(notChecked.hardware, { cpuCount: 8 });
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
  assert.deepEqual(Object.keys(readProjectionRequests[0].state).sort(), [
    "receipts",
    "runtime_survey_input",
  ]);
  assert.equal(readProjectionRequests[0].state.runtime_survey_input.engine_count, 1);
  assert.equal(Object.hasOwn(readProjectionRequests[0].state.runtime_survey_input, "status"), false);
  assert.equal(readProjectionRequests[1].state.receipts.at(-1).id, "receipt-runtime-survey");
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "server")), true);
  assert.equal(readProjectionRequests.every((request) => !Object.hasOwn(request.state, "runtime_survey")), true);
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
    "provider_health",
    "providers",
    "receipts",
  ]);
  assert.deepEqual(Object.keys(readProjectionRequests[1].state), ["receipts"]);
});
