import {
  artifactList,
  downloadList,
  endpointList,
  instanceList,
  legacyModelList as legacyModelListProjection,
  modelCapabilityList,
  modelMountingSnapshot,
  oauthSessionList,
  oauthStateList,
  openAiModelList as openAiModelListProjection,
  productArtifactList,
  providerHealthList,
  providerList,
  routeList,
  workflowNodeBindings as workflowNodeBindingsProjection,
} from "./read-model.mjs";
import {
  buildAdapterBoundaries,
  buildAuthoritySnapshot,
  buildModelMountingProjection,
  buildModelRouteDecisions,
  buildProjectionSummary,
  buildReceiptReplay,
} from "./projections.mjs";
import {
  notFound,
  operationCount,
} from "./io.mjs";

export function createModelMountingReadProjectionFacade({
  buildModelCapabilities,
  capabilityForWorkflowNode,
  internalFixtureModelsEnabled,
  isFixtureModelRecord,
  listJson,
  modelMountSchemaVersion,
  notFound: notFoundDep = notFound,
  operationCount: operationCountDep = operationCount,
  path,
  providerHasVaultRef,
  publicOAuthSession,
  publicOAuthState,
  publicProvider,
  readJson,
} = {}) {
  function legacyModelList(state) {
    return legacyModelListProjection(state);
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
    return buildAuthoritySnapshot(state, baseUrl, { schemaVersion: modelMountSchemaVersion });
  }

  function projectionSummary(state) {
    return buildProjectionSummary(state.projection());
  }

  function projection(state) {
    return buildModelMountingProjection(state, { schemaVersion: modelMountSchemaVersion });
  }

  function adapterBoundaries(state) {
    return buildAdapterBoundaries(state);
  }

  function receiptReplay(state, receiptId) {
    return buildReceiptReplay(state, receiptId, { schemaVersion: modelMountSchemaVersion });
  }

  function modelRouteDecisions(state) {
    return buildModelRouteDecisions(state);
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
      projectionWatermark: operationCountDep(state.stateDir),
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
      projectionWatermark: operationCountDep(state.stateDir),
    };
  }

  function workflowNodeBindings() {
    return workflowNodeBindingsProjection({ capabilityForWorkflowNode });
  }

  return {
    adapterBoundaries,
    authoritySnapshot,
    legacyModelList,
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
    snapshot,
    workflowNodeBindings,
  };
}
