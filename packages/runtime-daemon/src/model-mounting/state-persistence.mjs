import path from "node:path";

export const MODEL_MOUNTING_STATE_MAPS = [
  ["model-providers", "providers"],
  ["model-artifacts", "artifacts"],
  ["model-endpoints", "endpoints"],
  ["model-instances", "instances"],
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
    if (record?.deleted === true && typeof record.id === "string") {
      map.delete(record.id);
      continue;
    }
    if (typeof record.id === "string") {
      map.set(record.id, record);
    }
  }
}

export function writeAllModelMountingMaps(state) {
  const error = new Error("Bulk model-mounting map persistence is retired; use Rust Agentgres record-state commits per record.");
  error.status = 500;
  error.code = "model_mount_bulk_map_write_retired";
  error.details = {
    canonical_persistence: "rust_agentgres_record_state_commit",
  };
  throw error;
}

export function writeModelMountingMap(state, dir, map) {
  const error = new Error("Model-mounting map persistence is retired; use Rust Agentgres record-state commits per record.");
  error.status = 500;
  error.code = "model_mount_map_write_retired";
  error.details = {
    dir: dir ?? null,
    record_count: typeof map?.size === "number" ? map.size : null,
    canonical_persistence: "rust_agentgres_record_state_commit",
  };
  throw error;
}

export function writeModelMountingVaultRefs(state) {
  const error = new Error("Vault ref metadata persistence is Rust-owned; use plan_model_mount_vault_control.");
  error.status = 500;
  error.code = "model_mount_vault_ref_js_metadata_write_retired";
  error.details = {
    record_dir: "vault-refs",
    rust_core_api: "plan_model_mount_vault_control",
    canonical_persistence: "rust_agentgres_record_state_commit",
  };
  throw error;
}
