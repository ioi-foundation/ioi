import {
  artifactList,
  downloadList,
  endpointList,
  instanceList,
  modelCapabilityList,
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
    return artifactList(state);
  }

  function listProductArtifacts(state) {
    return productArtifactList(state, {
      internalFixtureModelsEnabled,
      isFixtureModelRecord,
    });
  }

  function listProviders(state) {
    return providerList(state, {
      providerHasVaultRef,
      publicProvider,
    });
  }

  function listEndpoints(state) {
    return endpointList(state);
  }

  function listInstances(state) {
    return instanceList(state);
  }

  function listRoutes(state) {
    return routeList(state);
  }

  function listModelCapabilities(state) {
    return modelCapabilityList(state, {
      buildModelCapabilities,
    });
  }

  function listDownloads(state) {
    return downloadList(state);
  }

  function listOAuthSessions(state) {
    return oauthSessionList(state, {
      publicOAuthSession,
    });
  }

  function listOAuthStates(state) {
    return oauthStateList(state, {
      publicOAuthState,
    });
  }

  function listProviderHealth(state) {
    return providerHealthList(state, {
      listJson,
      path,
      readJson,
    });
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
    return result.projection;
  }

  function readProjectionInput(state, baseUrl = null) {
    return {
      server: state.serverStatus(baseUrl),
      catalog: state.catalogStatus(),
      catalog_provider_configs: state.listCatalogProviderConfigs(),
      oauth_sessions: oauthSessionList(state, {
        publicOAuthSession,
      }),
      oauth_states: oauthStateList(state, {
        publicOAuthState,
      }),
      artifacts: artifactList(state),
      backends: state.listBackends(),
      backend_processes: state.listBackendProcesses(),
      endpoints: endpointList(state),
      instances: instanceList(state),
      providers: providerList(state, {
        providerHasVaultRef,
        publicProvider,
      }),
      routes: routeList(state),
      model_capabilities: modelCapabilityList(state, {
        buildModelCapabilities,
      }),
      downloads: downloadList(state),
      provider_health: providerHealthList(state, {
        listJson,
        path,
        readJson,
      }),
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
