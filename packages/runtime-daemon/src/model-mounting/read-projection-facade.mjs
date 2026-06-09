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
import {
  listRuntimeEngineProfiles,
  listRuntimeEngines,
  runtimeDefaultLoadOptions,
  runtimePreference,
  runtimePreferenceForEndpoint,
} from "./runtime-engines.mjs";
import {
  latestRuntimeSurveyProjectionInput,
} from "./runtime-survey.mjs";
import {
  serverStatusProjectionInput,
} from "./server-control.mjs";
import {
  catalogStatusProjectionInput,
} from "./catalog-operations.mjs";

export function createModelMountingReadProjectionFacade({
  internalFixtureModelsEnabled,
  listJson,
  modelMountSchemaVersion,
  hardwareSnapshot = () => null,
  notFound: notFoundDep = notFound,
  path,
  providerHasVaultRef,
  publicOAuthSession,
  publicOAuthState,
  publicProvider,
  readJson,
  readProjectionPlanner = null,
  catalogProviderStatus,
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

  function serverStatus(state, baseUrl) {
    return rustReadProjection(state, "server_status", { baseUrl });
  }

  function catalogStatus(state) {
    return rustReadProjection(state, "catalog_status");
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

  function runtimeEngineList(state) {
    return rustReadProjection(state, "runtime_engines");
  }

  function runtimeEngineProfileList(state) {
    return rustReadProjection(state, "runtime_engine_profiles");
  }

  function runtimePreferenceProjection(state) {
    return rustReadProjection(state, "runtime_preference");
  }

  function runtimePreferenceForEndpointProjection(state, endpoint = {}) {
    return rustReadProjection(state, "runtime_preference_for_endpoint", { endpoint });
  }

  function runtimeDefaultLoadOptionsProjection(state, engineId) {
    return rustReadProjection(state, "runtime_default_load_options", { engineId });
  }

  function runtimeEngineProjection(state, engineId) {
    try {
      return rustReadProjection(state, "runtime_engine_detail", { engineId });
    } catch (error) {
      throw translateRuntimeEngineError(error, engineId);
    }
  }

  function canonicalProjectionWritePlan(state) {
    return rustReadProjectionPlan(state, "projection");
  }

  function adapterBoundaries(state) {
    return rustReadProjection(state, "adapter_boundaries");
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

  function latestRuntimeSurvey(state) {
    return rustReadProjection(state, "latest_runtime_survey");
  }

  function workflowNodeBindings(state) {
    return rustReadProjection(state, "workflow_bindings");
  }

  function rustReadProjection(
    state,
    projectionKind,
    { baseUrl = null, engineId = null, endpoint = null, providerId = null, receiptId = null } = {},
  ) {
    const result = rustReadProjectionPlan(state, projectionKind, { baseUrl, engineId, endpoint, providerId, receiptId });
    return result.projection;
  }

  function rustReadProjectionPlan(
    state,
    projectionKind,
    { baseUrl = null, engineId = null, endpoint = null, providerId = null, receiptId = null } = {},
  ) {
    if (!readProjectionPlanner || typeof readProjectionPlanner.planReadProjection !== "function") {
      throwReadProjectionRustCoreRequired(projectionKind, {
        base_url: baseUrl,
        engine_id: engineId,
        provider_id: providerId,
        receipt_id: receiptId,
      });
    }
    const result = readProjectionPlanner.planReadProjection({
      projection_kind: projectionKind,
      schema_version: modelMountSchemaVersion,
      generated_at: state.nowIso(),
      base_url: baseUrl,
      engine_id: engineId,
      provider_id: providerId,
      receipt_id: receiptId,
      state: readProjectionInput(state, baseUrl, projectionKind, { engineId, endpoint }),
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

  function translateRuntimeEngineError(error, engineId) {
    if (error?.code === "model_mount_runtime_engine_not_found") {
      return notFoundDep(`Runtime engine not found: ${engineId}`, { engine_id: engineId });
    }
    throw error;
  }

  function readProjectionInput(state, baseUrl = null, projectionKind = "projection", { engineId = null, endpoint = null } = {}) {
    if (projectionKind === "workflow_bindings") {
      return {};
    }
    if (projectionKind === "runtime_engines") {
      return {
        runtime_engines: listRuntimeEngines(runtimeEngineProjectionState(state)),
      };
    }
    if (projectionKind === "runtime_engine_profiles") {
      return {
        runtime_engine_profiles: listRuntimeEngineProfiles(runtimeEngineProjectionState(state)),
      };
    }
    if (projectionKind === "runtime_preference") {
      return {
        runtime_preference: runtimePreference(runtimeEngineProjectionState(state)),
      };
    }
    if (projectionKind === "runtime_preference_for_endpoint") {
      return {
        runtime_preference: runtimePreferenceForEndpoint(runtimeEngineProjectionState(state), endpoint ?? {}),
      };
    }
    if (projectionKind === "runtime_default_load_options") {
      return {
        default_load_options: runtimeDefaultLoadOptions(runtimeEngineProjectionState(state), engineId),
      };
    }
    if (projectionKind === "runtime_engine_detail") {
      return {
        runtime_engine: runtimeEngineReadInput(state, engineId),
      };
    }
    if (projectionKind === "adapter_boundaries") {
      return {
        agentgres_store: state.store.adapterStatus(),
        wallet: state.walletAuthority.adapterStatus(),
        vault: state.vaultStatus(),
      };
    }
    if (projectionKind === "model_route_decisions" || projectionKind === "projection_summary") {
      return {
        receipts: state.listReceipts(),
      };
    }
    if (projectionKind === "latest_vault_health") {
      return {
        receipts: state.listReceipts(),
      };
    }
    if (projectionKind === "latest_runtime_survey") {
      return {
        receipts: state.listReceipts(),
        runtime_survey_input: latestRuntimeSurveyProjectionInput(runtimeSurveyProjectionState(state), { hardwareSnapshot }),
      };
    }
    if (projectionKind === "latest_provider_health") {
      return {
        providers: providerList(state, {
          providerHasVaultRef,
          publicProvider,
        }),
        provider_health: providerHealthList(state, {
          listJson,
          path,
          readJson,
        }),
        receipts: state.listReceipts(),
      };
    }
    if (projectionKind === "server_status") {
      return {
        server_status_input: serverStatusProjectionInput(state, baseUrl, { schema_version: modelMountSchemaVersion }),
      };
    }
    if (projectionKind === "catalog_status") {
      return {
        catalog_status_input: catalogStatusProjectionInput(state, {
          catalogProviderStatus,
          schemaVersion: modelMountSchemaVersion,
        }),
      };
    }
    if (projectionKind === "receipt_replay") {
      return {
        receipts: state.listReceipts(),
        routes: routeList(state),
        endpoints: endpointList(state),
        instances: instanceList(state),
        providers: providerList(state, {
          providerHasVaultRef,
          publicProvider,
        }),
      };
    }
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
    if (projectionKind === "authority_snapshot") {
      return {
        server_status_input: serverStatusProjectionInput(state, baseUrl, { schema_version: modelMountSchemaVersion }),
        grants: state.listTokens(),
        vault_refs: state.listVaultRefs(),
        receipts: state.listReceipts(),
        wallet: state.walletAuthority.adapterStatus(),
        vault: state.vaultStatus(),
      };
    }
    return {
      server_status_input: serverStatusProjectionInput(state, baseUrl, { schema_version: modelMountSchemaVersion }),
      catalog_status_input: catalogStatusProjectionInput(state, {
        catalogProviderStatus,
        schemaVersion: modelMountSchemaVersion,
      }),
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
      runtime_survey_input: latestRuntimeSurveyProjectionInput(runtimeSurveyProjectionState(state), { hardwareSnapshot }),
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

  function runtimeEngineReadInput(state, engineId) {
    const runtimeState = runtimeEngineProjectionState(state);
    const engine = listRuntimeEngines(runtimeState).find((item) => item.id === engineId) ?? null;
    if (!engine) return null;
    const preference = runtimePreference(runtimeState);
    return {
      ...engine,
      profile: listRuntimeEngineProfiles(runtimeState).find((profile) => profile.id === engineId) ?? null,
      preference: preference.selectedEngineId === engineId ? preference : null,
      loadedInstances: instanceList(state).filter((instance) =>
        instance.runtimeEngineId === engineId || instance.backendId === engineId),
      latestReceipts: state.listReceipts()
        .filter((receipt) =>
          receipt.details?.runtime_engine_id === engineId ||
          receipt.details?.engine_id === engineId ||
          receipt.details?.backend_id === engineId)
        .slice(-8),
    };
  }

  function runtimeEngineProjectionState(state) {
    const runtimeState = Object.create(state);
    runtimeState.listInstances = () => instanceList(state);
    return runtimeState;
  }

  function runtimeSurveyProjectionState(state) {
    const runtimeState = runtimeEngineProjectionState(state);
    runtimeState.listRuntimeEngines = () => listRuntimeEngines(runtimeState);
    runtimeState.runtimePreference = () => runtimePreference(runtimeState);
    return runtimeState;
  }

  return {
    adapterBoundaries,
    authoritySnapshot,
    canonicalProjectionWritePlan,
    catalogStatus,
    latestProviderHealth,
    latestRuntimeSurvey,
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
    serverStatus,
    runtimeDefaultLoadOptionsProjection,
    runtimeEngineList,
    runtimeEngineProfileList,
    runtimeEngineProjection,
    runtimePreferenceForEndpointProjection,
    runtimePreferenceProjection,
    runtimeModelCatalogList,
    snapshot,
    workflowNodeBindings,
  };
}
