export function ensureNativeLocalFixtureArtifact(state, checkedAt) {
  void state;
  return {
    id: "hypervisor.native.fixture",
    providerId: "provider.hypervisor.local",
    modelId: "hypervisor:native-fixture",
    displayName: "Hypervisor native local fixture",
    family: "hypervisor-native",
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
