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
