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
      provider: (artifact.providerId === "provider.local.folder" || artifact.providerId === "provider.autopilot.local") ? "ioi-daemon-local" : artifact.providerId,
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

export function providerList(state) {
  return sortedValues(state.providers, (left, right) => left.id.localeCompare(right.id));
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
