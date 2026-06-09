import {
  artifactList,
  downloadList,
  endpointList,
  instanceList,
  oauthSessionList,
  oauthStateList,
  providerHealthList,
  providerList,
  routeList,
} from "./read-model.mjs";
import { notFound } from "./io.mjs";

export function createModelMountingReadProjectionFacade({
  internalFixtureModelsEnabled,
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
    return rustReadProjection(state, "runtime_model_catalog");
  }

  function openAiModelList(state) {
    return rustReadProjection(state, "open_ai_model_list");
  }

  function listArtifacts(state) {
    return rustReadProjection(state, "artifacts");
  }

  function listProductArtifacts(state) {
    return rustReadProjection(state, "product_artifacts");
  }

  function listProviders(state) {
    return rustReadProjection(state, "providers");
  }

  function listEndpoints(state) {
    return rustReadProjection(state, "endpoints");
  }

  function listInstances(state) {
    return rustReadProjection(state, "instances");
  }

  function listRoutes(state) {
    return rustReadProjection(state, "routes");
  }

  function listModelCapabilities(state) {
    return rustReadProjection(state, "model_capabilities");
  }

  function listDownloads(state) {
    return rustReadProjection(state, "downloads");
  }

  function listOAuthSessions(state) {
    return rustReadProjection(state, "oauth_sessions");
  }

  function listOAuthStates(state) {
    return rustReadProjection(state, "oauth_states");
  }

  function listProviderHealth(state) {
    return rustReadProjection(state, "provider_health");
  }

  function snapshot(state, baseUrl) {
    return rustReadProjection(state, "snapshot", { baseUrl });
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
    return rustProjectionObjectField(state, "adapterBoundaries");
  }

  function receiptReplay(state, receiptId) {
    return rustReadProjection(state, "receipt_replay", { receiptId });
  }

  function modelRouteDecisions(state) {
    return rustReadProjection(state, "model_route_decisions");
  }

  function latestProviderHealth(state, providerId) {
    try {
      return rustReadProjection(state, "latest_provider_health", { providerId });
    } catch (error) {
      throw translateLatestProviderHealthError(error, providerId);
    }
  }

  function latestVaultHealth(state) {
    try {
      return rustReadProjection(state, "latest_vault_health");
    } catch (error) {
      throw translateLatestVaultHealthError(error);
    }
  }

  function workflowNodeBindings(state) {
    return rustProjectionField(state, "workflowBindings");
  }

  function rustReadProjection(state, projectionKind, { baseUrl = null, providerId = null, receiptId = null } = {}) {
    const result = rustReadProjectionPlan(state, projectionKind, { baseUrl, providerId, receiptId });
    return result.projection;
  }

  function rustProjectionField(state, field) {
    const projection = rustReadProjection(state, "projection");
    const value = projection?.[field];
    return Array.isArray(value) ? value : [];
  }

  function rustProjectionObjectField(state, field) {
    const projection = rustReadProjection(state, "projection");
    const value = projection?.[field];
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  }

  function rustReadProjectionPlan(state, projectionKind, { baseUrl = null, providerId = null, receiptId = null } = {}) {
    if (!readProjectionPlanner || typeof readProjectionPlanner.planReadProjection !== "function") {
      throwReadProjectionRustCoreRequired(projectionKind, {
        base_url: baseUrl,
        provider_id: providerId,
        receipt_id: receiptId,
      });
    }
    const result = readProjectionPlanner.planReadProjection({
      projection_kind: projectionKind,
      schema_version: modelMountSchemaVersion,
      generated_at: state.nowIso(),
      base_url: baseUrl,
      provider_id: providerId,
      receipt_id: receiptId,
      state: readProjectionInput(state, baseUrl, projectionKind),
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

  function translateLatestProviderHealthError(error, providerId) {
    if (
      error?.code === "model_mount_provider_not_found" ||
      error?.code === "model_mount_provider_health_not_found"
    ) {
      return notFoundDep(`Provider health has not been checked: ${providerId}`, { providerId });
    }
    throw error;
  }

  function translateLatestVaultHealthError(error) {
    if (error?.code === "model_mount_vault_health_not_found") {
      return notFoundDep("Vault adapter health has not been checked.", {
        receiptKind: "vault_adapter_health",
      });
    }
    throw error;
  }

  function readProjectionInput(state, baseUrl = null, projectionKind = "projection") {
    const artifacts = artifactList(state);
    const productArtifactPolicy = {
      include_internal_fixtures: Boolean(internalFixtureModelsEnabled?.()),
    };
    if (
      projectionKind === "artifacts" ||
      projectionKind === "product_artifacts" ||
      projectionKind === "runtime_model_catalog" ||
      projectionKind === "open_ai_model_list"
    ) {
      return {
        artifacts,
        product_artifact_policy: productArtifactPolicy,
      };
    }
    const endpoints = endpointList(state);
    if (projectionKind === "endpoints") {
      return { endpoints };
    }
    const instances = instanceList(state);
    if (projectionKind === "instances") {
      return { instances };
    }
    const providers = providerList(state, {
      providerHasVaultRef,
      publicProvider,
    });
    if (projectionKind === "providers") {
      return { providers };
    }
    const routes = routeList(state);
    if (projectionKind === "routes") {
      return { routes };
    }
    if (projectionKind === "model_capabilities") {
      return {
        artifacts,
        endpoints,
        instances,
        providers,
        routes,
      };
    }
    const downloads = downloadList(state);
    if (projectionKind === "downloads") {
      return { downloads };
    }
    const oauthSessions = oauthSessionList(state, {
      publicOAuthSession,
    });
    if (projectionKind === "oauth_sessions") {
      return { oauth_sessions: oauthSessions };
    }
    const oauthStates = oauthStateList(state, {
      publicOAuthState,
    });
    if (projectionKind === "oauth_states") {
      return { oauth_states: oauthStates };
    }
    const providerHealth = providerHealthList(state, {
      listJson,
      path,
      readJson,
    });
    if (projectionKind === "provider_health") {
      return { provider_health: providerHealth };
    }
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
      downloads,
      provider_health: providerHealth,
      product_artifact_policy: productArtifactPolicy,
      runtime_engines: state.listRuntimeEngines(),
      runtime_engine_profiles: state.listRuntimeEngineProfiles(),
      runtime_preference: state.runtimePreference(),
      runtime_survey: state.latestRuntimeSurvey(),
      grants: state.listTokens(),
      vault_refs: state.listVaultRefs(),
      mcp_servers: state.listMcpServers(),
      conversation_states: state.listConversations(),
      agentgres_store: state.store.adapterStatus(),
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
