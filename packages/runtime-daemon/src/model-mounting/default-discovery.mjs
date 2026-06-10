import fs from "node:fs";
import path from "node:path";

export function ensureNativeLocalFixtureArtifact(state, checkedAt, deps = {}) {
  const { fileSha256, parseLocalModelMetadata } = deps;
  const fixtureDir = path.join(state.modelRoot, "native-fixture");
  const fixturePath = path.join(fixtureDir, "autopilot-native-fixture.Q4_K_M.gguf");
  fs.mkdirSync(fixtureDir, { recursive: true });
  if (!fs.existsSync(fixturePath)) {
    fs.writeFileSync(
      fixturePath,
      [
        "IOI deterministic native-local model fixture",
        "format=gguf",
        "family=autopilot-native",
        "quantization=Q4_K_M",
        "context=8192",
      ].join("\n"),
    );
  }
  const stats = fs.statSync(fixturePath);
  const metadata = parseLocalModelMetadata(fixturePath);
  return {
    id: "autopilot.native.fixture",
    providerId: "provider.autopilot.local",
    modelId: "autopilot:native-fixture",
    displayName: "Autopilot native local fixture",
    family: metadata.family ?? "autopilot-native",
    format: metadata.format ?? "gguf",
    quantization: metadata.quantization ?? "Q4_K_M",
    sizeBytes: stats.size,
    checksum: fileSha256(fixturePath),
    contextWindow: metadata.contextWindow ?? 8192,
    capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
    privacyClass: "local_private",
    source: "autopilot_native_local_fixture",
    state: "installed",
    artifactPath: fixturePath,
    backendRegistry: state.backendRegistry(),
    discoveredAt: checkedAt,
  };
}

export function pruneInternalFixtureProjectionRecords(state, deps = {}) {
  const { isFixtureEndpointCandidate, isFixtureModelRecord } = deps;
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
