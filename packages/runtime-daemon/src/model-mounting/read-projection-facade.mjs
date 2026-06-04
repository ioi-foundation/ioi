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
} from "./read-model.mjs";
import {
  buildAdapterBoundaries,
  buildAuthoritySnapshot,
  buildModelMountingProjection,
  buildModelRouteDecisions,
  buildProjectionSummary,
  buildReceiptReplay,
} from "./projections.mjs";

export function createModelMountingReadProjectionFacade({
  buildModelCapabilities,
  internalFixtureModelsEnabled,
  isFixtureModelRecord,
  listJson,
  modelMountSchemaVersion,
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

  return {
    adapterBoundaries,
    authoritySnapshot,
    legacyModelList,
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
  };
}
