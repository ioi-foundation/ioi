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
  state.store.writeMap(dir, map);
}

export function writeModelMountingVaultRefs(state) {
  state.vaultRefs = new Map(state.vault.metadataRecords().map((record) => [record.id, record]));
  state.writeMap("vault-refs", state.vaultRefs);
}
