import path from "node:path";

export const MODEL_MOUNTING_STATE_MAPS = [
  ["model-providers", "providers"],
  ["model-backends", "backends"],
  ["backend-processes", "backendProcesses"],
  ["model-artifacts", "artifacts"],
  ["model-endpoints", "endpoints"],
  ["model-instances", "instances"],
  ["model-routes", "routes"],
  ["model-downloads", "downloads"],
  ["model-catalog-providers", "catalogProviderConfigs"],
  ["oauth-sessions", "oauthSessions"],
  ["oauth-states", "oauthStates"],
  ["runtime-preferences", "runtimeSelections"],
  ["runtime-engine-profiles", "runtimeEngineProfiles"],
  ["tokens", "tokens"],
  ["vault-refs", "vaultRefs"],
  ["mcp-servers", "mcpServers"],
  ["model-conversations", "conversations"],
];

export function loadModelMountingMaps(state, deps = {}) {
  for (const [dir, property] of MODEL_MOUNTING_STATE_MAPS) {
    loadModelMountingMap(state, dir, state[property], deps);
  }
}

export function loadModelMountingMap(state, dir, map, deps = {}) {
  const { listJson, readJson } = deps;
  for (const filePath of listJson(path.join(state.stateDir, dir))) {
    const record = readJson(filePath);
    if (typeof record.id === "string") {
      map.set(record.id, record);
    }
  }
}

export function writeAllModelMountingMaps(state) {
  for (const [dir, property] of MODEL_MOUNTING_STATE_MAPS) {
    if (dir === "vault-refs") {
      state.writeVaultRefs();
    } else {
      state.writeMap(dir, state[property]);
    }
  }
  state.writeProjection();
}

export function writeModelMountingMap(state, dir, map) {
  assertModelInstanceMapRustBound(state, dir, map);
  state.store.writeMap(dir, map);
}

export function writeModelMountingVaultRefs(state) {
  state.vaultRefs = new Map(state.vault.metadataRecords().map((record) => [record.id, record]));
  state.writeMap("vault-refs", state.vaultRefs);
}

function assertModelInstanceMapRustBound(state, dir, map) {
  if (dir !== "model-instances") return;
  const missing = [];
  for (const instance of map.values()) {
    if (!requiresRustInstanceLifecycleBinding(state, instance)) continue;
    const evidenceRefs = Array.isArray(instance.modelMountInstanceLifecycleEvidenceRefs)
      ? instance.modelMountInstanceLifecycleEvidenceRefs
      : [];
    if (!instance.providerLifecycleHash) {
      missing.push(`${instance.id}:providerLifecycleHash`);
    }
    if (!instance.modelMountInstanceLifecycleHash) {
      missing.push(`${instance.id}:modelMountInstanceLifecycleHash`);
    }
    if (!evidenceRefs.includes("rust_model_mount_instance_lifecycle")) {
      missing.push(`${instance.id}:modelMountInstanceLifecycleEvidenceRefs`);
    }
  }
  if (missing.length > 0) {
    const error = new Error("Model instance writes for migrated local providers require Rust model_mount lifecycle bindings.");
    error.status = 500;
    error.code = "model_mount_instance_map_direct_write_forbidden";
    error.details = { missing };
    throw error;
  }
}

function requiresRustInstanceLifecycleBinding(state, instance) {
  if (!["loaded", "unloaded", "evicted", "superseded"].includes(instance?.status)) {
    return false;
  }
  const provider = state.providers?.get?.(instance.providerId);
  return provider?.kind === "ioi_native_local" || provider?.kind === "local_folder";
}
