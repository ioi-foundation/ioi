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
      server: state.server,
      catalog: state.catalog,
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
      runtimeSurvey: state.runtime_survey,
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
  ]);
  const workflowBindings = facade.workflowNodeBindings(state);
  assert.equal(workflowBindings.find((binding) => binding.node === "Embedding").capability, "embeddings");
  assert.equal(workflowBindings.find((binding) => binding.node === "Reranker").capability, "rerank");
  assert.equal(workflowBindings.find((binding) => binding.node === "Receipt Gate").daemonApi, "/api/v1/workflows/receipt-gate");
  assert.equal(facade.adapterBoundaries(state).agentgres.port, "AgentgresStorePort");
  assert.equal(readProjectionRequests.filter((request) => request.projection_kind === "projection")
    .every((request) => request.state.agentgres_store.port === "AgentgresStorePort"), true);
  assert.equal(readProjectionRequests.filter((request) => request.projection_kind !== "projection")
    .every((request) => !Object.hasOwn(request.state, "server")), true);
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
  assert.equal(snapshot.modelCapabilities.length, 1);
  assert.equal(snapshot.modelCapabilities[0].credential_readiness.status, "ready");
  assert.equal(snapshot.projection.source, "agentgres_model_mounting_projection");
  assert.equal(snapshot.adapterBoundaries.agentgres.port, "AgentgresStorePort");

  const projection = facade.projection(state);
  assert.equal(projection.schemaVersion, "model.mount.schema");
  assert.equal(projection.routeReceipts.length, 1);
  assert.equal(projection.lifecycleEvents.length, 1);
  assert.equal(projection.adapterBoundaries.oauth.plaintextPersistence, false);

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
