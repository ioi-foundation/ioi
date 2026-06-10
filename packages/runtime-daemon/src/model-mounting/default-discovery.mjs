function isFixtureEndpointCandidate(endpoint = {}, provider = {}) {
  const haystack = [
    endpoint.id,
    endpoint.modelId,
    endpoint.apiFormat,
    endpoint.driver,
    endpoint.baseUrl,
    endpoint.backendId,
    provider.id,
    provider.kind,
    provider.driver,
  ]
    .map((value) => String(value ?? "").toLowerCase())
    .join(" ");
  return (
    haystack.includes("fixture") ||
    haystack.includes("local:auto") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("stories260k") ||
    haystack.includes("backend.fixture")
  );
}

function isFixtureModelRecord(record = {}) {
  const haystack = [
    record.id,
    record.modelId,
    record.model_id,
    record.displayName,
    record.name,
    record.family,
    record.quantization,
    record.source,
    record.driver,
    record.providerId,
    record.provider_id,
    record.artifactPath,
    record.artifact_path,
  ]
    .map((value) => String(value ?? "").toLowerCase())
    .join(" ");
  return (
    haystack.includes("fixture") ||
    haystack.includes("local:auto") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("stories260k")
  );
}

export function ensureNativeLocalFixtureArtifact(state, checkedAt) {
  void state;
  return {
    id: "autopilot.native.fixture",
    providerId: "provider.autopilot.local",
    modelId: "autopilot:native-fixture",
    displayName: "Autopilot native local fixture",
    family: "autopilot-native",
    format: "rust_backed_fixture",
    quantization: "deterministic",
    sizeBytes: 0,
    checksum: null,
    contextWindow: 8192,
    capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    privacyClass: "local_private",
    source: "rust_model_mount_native_local_fixture",
    state: "installed",
    discoveredAt: checkedAt,
  };
}

export function pruneInternalFixtureProjectionRecords(state) {
  const removedEndpointIds = new Set();
  const removedModelIds = new Set();
  for (const [id, artifact] of state.artifacts.entries()) {
    if (isFixtureModelRecord(artifact) || String(id).includes("fixture") || String(artifact.modelId ?? "").includes("local:auto")) {
      removedModelIds.add(artifact.modelId);
      state.artifacts.delete(id);
    }
  }
  for (const [id, endpoint] of state.endpoints.entries()) {
    if (
      isFixtureEndpointCandidate(endpoint, state.providers.get(endpoint.providerId)) ||
      String(id).includes("fixture") ||
      String(endpoint.modelId ?? "").includes("local:auto")
    ) {
      removedEndpointIds.add(id);
      removedModelIds.add(endpoint.modelId);
      state.endpoints.delete(id);
    }
  }
  for (const [id, instance] of state.instances.entries()) {
    if (
      removedEndpointIds.has(instance.endpointId) ||
      removedModelIds.has(instance.modelId) ||
      isFixtureModelRecord(instance)
    ) {
      state.instances.delete(id);
    }
  }
}
