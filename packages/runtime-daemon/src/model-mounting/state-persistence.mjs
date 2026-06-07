import path from "node:path";

import { commitModelMountRecordState } from "./record-state-commits.mjs";

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
  const records = state.vault.metadataRecords();
  for (const record of records) {
    commitVaultRefRecordState(state, record, "model_mount.vault_ref.write", []);
  }
  state.vaultRefs = new Map(records.map((record) => [record.id, record]));
}

function commitVaultRefRecordState(state, record, operation_kind, receipt_refs) {
  return commitModelMountRecordState(state, {
    recordDir: "vault-refs",
    record,
    operation_kind,
    receipt_refs,
    unconfiguredCode: "model_mount_vault_ref_state_commit_unconfigured",
    unconfiguredMessage:
      "Vault ref metadata persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: {
      vault_ref_id: record?.id ?? null,
      vault_ref_hash: record?.vaultRefHash ?? null,
    },
  });
}
