import {
  artifactList,
  downloadList,
  endpointList,
  instanceList,
  modelMountingSnapshot,
  oauthSessionList,
  oauthStateList,
  openAiModelList as openAiModelListProjection,
  productArtifactList,
  providerHealthList,
  providerList,
  routeList,
  runtimeModelCatalogList as runtimeModelCatalogListProjection,
  workflowNodeBindings as workflowNodeBindingsProjection,
} from "./read-model.mjs";
import {
  buildAdapterBoundaries,
} from "./projections.mjs";
import { notFound } from "./io.mjs";

export function createModelMountingReadProjectionFacade({
  buildModelCapabilities,
  capabilityForWorkflowNode,
  internalFixtureModelsEnabled,
  isFixtureModelRecord,
  listJson,
  modelMountSchemaVersion,
  notFound: notFoundDep = notFound,
  path,
  providerHasVaultRef,
  publicOAuthSession,
  publicOAuthState,
  publicProvider,
  readJson,
  readProjectionPlanner = null,
} = {}) {
  function runtimeModelCatalogList(state) {
    return runtimeModelCatalogListProjection(state);
  }

  function openAiModelList(state) {
    return openAiModelListProjection(state);
  }

  function listArtifacts(state) {
    return rustProjectionField(state, "artifacts");
  }

  function listProductArtifacts(state) {
    return productArtifactList(state, {
      internalFixtureModelsEnabled,
      isFixtureModelRecord,
    });
  }

  function listProviders(state) {
    return rustProjectionField(state, "providers");
  }

  function listEndpoints(state) {
    return rustProjectionField(state, "endpoints");
  }

  function listInstances(state) {
    return rustProjectionField(state, "instances");
  }

  function listRoutes(state) {
    return rustProjectionField(state, "routes");
  }

  function listModelCapabilities(state) {
    return rustProjectionField(state, "modelCapabilities");
  }

  function listDownloads(state) {
    return rustProjectionField(state, "downloads");
  }

  function listOAuthSessions(state) {
    return rustProjectionField(state, "oauthSessions");
  }

  function listOAuthStates(state) {
    return rustProjectionField(state, "oauthStates");
  }

  function listProviderHealth(state) {
    return rustProjectionField(state, "providerHealth");
  }

  function snapshot(state, baseUrl) {
    return modelMountingSnapshot(state, baseUrl, {
      schemaVersion: modelMountSchemaVersion,
    });
  }

  function authoritySnapshot(state, baseUrl) {
    return rustReadProjection(state, "authority_snapshot", { baseUrl });
  }

  function projectionSummary(state) {
    return rustReadProjection(state, "projection_summary");
  }

  function projection(state) {
    return rustReadProjection(state, "projection");
  }

  function canonicalProjectionWritePlan(state) {
    return rustReadProjectionPlan(state, "projection");
  }

  function adapterBoundaries(state) {
    return buildAdapterBoundaries(state);
  }

  function receiptReplay(state, receiptId) {
    return rustReadProjection(state, "receipt_replay", { receiptId });
  }

  function modelRouteDecisions(state) {
    return rustReadProjection(state, "model_route_decisions");
  }

  function latestProviderHealth(state, providerId) {
    state.provider(providerId);
    const health = state.listProviderHealth()
      .filter((record) => record.providerId === providerId)
      .at(-1);
    if (!health?.receiptId) {
      throw notFoundDep(`Provider health has not been checked: ${providerId}`, { providerId });
    }
    const receipt = state.getReceipt(health.receiptId);
    return {
      schemaVersion: modelMountSchemaVersion,
      source: "agentgres_provider_health_latest",
      providerId,
      health,
      receipt,
      replay: state.receiptReplay(receipt.id),
      projectionWatermark: state.listReceipts().length,
    };
  }

  function latestVaultHealth(state) {
    const receipt = state.listReceipts()
      .filter((item) => item.kind === "vault_adapter_health")
      .at(-1);
    if (!receipt) {
      throw notFoundDep("Vault adapter health has not been checked.", {
        receiptKind: "vault_adapter_health",
      });
    }
    return {
      schemaVersion: modelMountSchemaVersion,
      source: "agentgres_vault_health_latest",
      health: receipt.details,
      receipt,
      replay: state.receiptReplay(receipt.id),
      projectionWatermark: state.listReceipts().length,
    };
  }

  function workflowNodeBindings() {
    return workflowNodeBindingsProjection({ capabilityForWorkflowNode });
  }

  function rustReadProjection(state, projectionKind, { baseUrl = null, receiptId = null } = {}) {
    const result = rustReadProjectionPlan(state, projectionKind, { baseUrl, receiptId });
    return result.projection;
  }

  function rustProjectionField(state, field) {
    const projection = rustReadProjection(state, "projection");
    const value = projection?.[field];
    return Array.isArray(value) ? value : [];
  }

  function rustReadProjectionPlan(state, projectionKind, { baseUrl = null, receiptId = null } = {}) {
    if (!readProjectionPlanner || typeof readProjectionPlanner.planReadProjection !== "function") {
      throwReadProjectionRustCoreRequired(projectionKind, {
        base_url: baseUrl,
        receipt_id: receiptId,
      });
    }
    const result = readProjectionPlanner.planReadProjection({
      projection_kind: projectionKind,
      schema_version: modelMountSchemaVersion,
      generated_at: state.nowIso(),
      base_url: baseUrl,
      receipt_id: receiptId,
      state: readProjectionInput(state, baseUrl),
    });
    if (!result?.projection || typeof result.projection !== "object") {
      throwReadProjectionRustCoreRequired(projectionKind, {
        reason: "missing_rust_projection",
        source: result?.source ?? null,
        backend: result?.backend ?? null,
      });
    }
    return result;
  }

  function readProjectionInput(state, baseUrl = null) {
    const artifacts = artifactList(state);
    const endpoints = endpointList(state);
    const instances = instanceList(state);
    const providers = providerList(state, {
      providerHasVaultRef,
      publicProvider,
    });
    const routes = routeList(state);
    const downloads = downloadList(state);
    const oauthSessions = oauthSessionList(state, {
      publicOAuthSession,
    });
    const oauthStates = oauthStateList(state, {
      publicOAuthState,
    });
    const providerHealth = providerHealthList(state, {
      listJson,
      path,
      readJson,
    });
    const modelCapabilities = buildModelCapabilities({
      routes,
      endpoints,
      providers,
      artifacts,
      instances,
    });
    return {
      server: state.serverStatus(baseUrl),
      catalog: state.catalogStatus(),
      catalog_provider_configs: state.listCatalogProviderConfigs(),
      oauth_sessions: oauthSessions,
      oauth_states: oauthStates,
      artifacts,
      backends: state.listBackends(),
      backend_processes: state.listBackendProcesses(),
      endpoints,
      instances,
      providers,
      routes,
      model_capabilities: modelCapabilities,
      downloads,
      provider_health: providerHealth,
      runtime_engines: state.listRuntimeEngines(),
      runtime_engine_profiles: state.listRuntimeEngineProfiles(),
      runtime_preference: state.runtimePreference(),
      runtime_survey: state.latestRuntimeSurvey(),
      grants: state.listTokens(),
      vault_refs: state.listVaultRefs(),
      mcp_servers: state.listMcpServers(),
      conversation_states: state.listConversations(),
      workflow_bindings: workflowNodeBindingsProjection({ capabilityForWorkflowNode }),
      adapter_boundaries: buildAdapterBoundaries(state),
      receipts: state.listReceipts(),
      wallet: state.walletAuthority.adapterStatus(),
      vault: state.vaultStatus(),
    };
  }

  function throwReadProjectionRustCoreRequired(projectionKind, details = {}) {
    const error = new Error("Model-mount read projection requires Rust daemon-core projection ownership.");
    error.status = 501;
    error.code = "model_mount_read_projection_rust_core_required";
    error.details = {
      rust_core_boundary: "model_mount.projection",
      projection_kind: projectionKind,
      ...details,
      evidence_refs: [
        "model_mount_js_read_projection_authoring_retired",
        "rust_daemon_core_model_mount_projection_required",
        "agentgres_model_mount_read_truth_required",
      ],
    };
    throw error;
  }

  return {
    adapterBoundaries,
    authoritySnapshot,
    canonicalProjectionWritePlan,
    latestProviderHealth,
    latestVaultHealth,
    listArtifacts,
    listDownloads,
    listEndpoints,
    listInstances,
    listModelCapabilities,
    listOAuthSessions,
    listOAuthStates,
    listProductArtifacts,
    listProviderHealth,
    listProviders,
    listRoutes,
    modelRouteDecisions,
    openAiModelList,
    projection,
    projectionSummary,
    receiptReplay,
    runtimeModelCatalogList,
    snapshot,
    workflowNodeBindings,
  };
}
