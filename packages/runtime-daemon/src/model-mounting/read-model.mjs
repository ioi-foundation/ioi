export function sortedValues(map, compare) {
  return [...map.values()].sort(compare);
}

export function artifactList(state) {
  return sortedValues(state.artifacts, (left, right) => left.id.localeCompare(right.id));
}

export function productArtifactList(state, deps = {}) {
  const {
    internalFixtureModelsEnabled = () => false,
    isFixtureModelRecord = () => false,
  } = deps;
  const artifacts = artifactList(state);
  if (internalFixtureModelsEnabled()) return artifacts;
  return artifacts.filter((artifact) => !isFixtureModelRecord(artifact));
}

export function runtimeModelCatalogList(state, deps = {}) {
  return state.listProductArtifacts()
    .sort((left, right) => left.modelId.localeCompare(right.modelId))
    .map((artifact) => ({
      id: artifact.modelId,
      provider: artifact.providerId === "provider.local.folder" ? "ioi-daemon-local" : artifact.providerId,
      cost: artifact.privacyClass === "local_private" ? "local" : "metered",
      quality: artifact.family === "fixture" ? "adaptive" : "provider",
      capabilities: artifact.capabilities,
      privacyClass: artifact.privacyClass,
      route: "route.local-first",
    }));
}

export function openAiModelList(state) {
  return {
    object: "list",
    data: state.listProductArtifacts().map((artifact) => ({
      id: artifact.modelId,
      object: "model",
      created: Math.floor(Date.parse(artifact.discoveredAt ?? state.nowIso()) / 1000),
      owned_by: artifact.providerId,
      permission: [],
      root: artifact.modelId,
      parent: null,
    })),
  };
}

export function providerList(state, deps = {}) {
  const {
    providerHasVaultRef = () => false,
    publicProvider = (provider) => provider,
  } = deps;
  return sortedValues(state.providers, (left, right) => left.id.localeCompare(right.id))
    .map((provider) => publicProvider(
      provider,
      providerHasVaultRef(provider) ? state.vault.vaultRefMetadata(provider.secretRef) : null,
    ));
}

export function endpointList(state) {
  return sortedValues(state.endpoints, (left, right) => left.id.localeCompare(right.id));
}

export function instanceList(state) {
  state.evictExpiredInstances();
  state.coalesceLoadedInstances();
  return sortedValues(state.instances, (left, right) => left.loadedAt.localeCompare(right.loadedAt));
}

export function routeList(state) {
  return sortedValues(state.routes, (left, right) => left.id.localeCompare(right.id));
}

export function modelCapabilityList(state, deps = {}) {
  const { buildModelCapabilities } = deps;
  return buildModelCapabilities({
    routes: state.listRoutes(),
    endpoints: state.listEndpoints(),
    providers: state.listProviders(),
    artifacts: state.listArtifacts(),
    instances: state.listInstances(),
  });
}

export function downloadList(state) {
  return sortedValues(state.downloads, (left, right) => left.createdAt.localeCompare(right.createdAt));
}

export function oauthSessionList(state, deps = {}) {
  const { publicOAuthSession } = deps;
  return sortedValues(state.oauthSessions, (left, right) => left.id.localeCompare(right.id))
    .map(publicOAuthSession);
}

export function oauthStateList(state, deps = {}) {
  const { publicOAuthState } = deps;
  return [...state.oauthStates.values()]
    .map(publicOAuthState)
    .sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? "")));
}

export function providerHealthList(state, deps = {}) {
  const {
    listJson,
    path,
    readJson,
  } = deps;
  return listJson(path.join(state.stateDir, "provider-health"))
    .map((filePath) => readJson(filePath))
    .sort((left, right) => String(left.checkedAt ?? "").localeCompare(String(right.checkedAt ?? "")));
}

export function workflowNodeBindings(deps = {}) {
  const { capabilityForWorkflowNode } = deps;
  return [
    "Model Call",
    "Structured Output",
    "Verifier",
    "Planner",
    "Embedding",
    "Reranker",
    "Vision",
    "Local Tool/MCP",
    "Model Router",
    "Receipt Gate",
  ].map((node) => ({
    node,
    modelId: null,
    supportsExplicitModelId: true,
    supportsModelPolicy: true,
    capability: capabilityForWorkflowNode(node),
    receiptRequired: true,
    routeId: "route.local-first",
    daemonApi: node === "Receipt Gate" ? "/api/v1/workflows/receipt-gate" : "/api/v1/workflows/nodes/execute",
  }));
}

export function modelMountingSnapshot(state, baseUrl, deps = {}) {
  const { schemaVersion } = deps;
  return {
    schemaVersion,
    server: state.serverStatus(baseUrl),
    catalog: state.catalogStatus(),
    catalogProviderConfigs: state.listCatalogProviderConfigs(),
    oauthSessions: state.listOAuthSessions(),
    oauthStates: state.listOAuthStates(),
    artifacts: state.listArtifacts(),
    backends: state.listBackends(),
    backendProcesses: state.listBackendProcesses(),
    endpoints: state.listEndpoints(),
    instances: state.listInstances(),
    providers: state.listProviders(),
    routes: state.listRoutes(),
    modelCapabilities: state.listModelCapabilities(),
    downloads: state.listDownloads(),
    providerHealth: state.listProviderHealth(),
    runtimeEngines: state.listRuntimeEngines(),
    runtimeEngineProfiles: state.listRuntimeEngineProfiles(),
    runtimePreference: state.runtimePreference(),
    runtimeSurvey: state.latestRuntimeSurvey(),
    tokens: state.listTokens(),
    vaultRefs: state.listVaultRefs(),
    mcpServers: state.listMcpServers(),
    conversationStates: state.listConversations(),
    workflowNodes: state.workflowNodeBindings(),
    receipts: state.listReceipts().slice(-25),
    projection: state.projectionSummary(),
    adapterBoundaries: state.adapterBoundaries(),
  };
}
