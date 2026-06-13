import {
  runtimeError,
  stableHash,
} from "./io.mjs";
import { commitModelMountRecordState } from "./record-state-commits.mjs";

export const MODEL_MOUNT_VAULT_CONTROL_SCHEMA_VERSION = "ioi.model_mount.vault_control.v1";

export function throwVaultControlRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? runtimeError)({
    status: 501,
    code: "model_mount_vault_rust_core_required",
    message:
      "Vault mutation, health, and projection facades require Rust daemon-core wallet/cTEE custody ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.vault",
      evidence_refs: [
        "public_vault_js_facade_retired",
        "rust_daemon_core_vault_control",
        "wallet_network_vault_authority_required",
        "ctee_vault_custody_enforced",
        "agentgres_vault_truth_required",
      ],
      ...details,
    },
  });
}

export function vaultControlPlanForState(
  state,
  operation_kind,
  {
    body = {},
    vaultRef = null,
    material = null,
  } = {},
) {
  if (!state || typeof state.planVaultControl !== "function") {
    throwVaultControlRustCoreRequired(operation_kind, {
      vault_ref_hash_required: true,
      rust_core_api: "plan_model_mount_vault_control",
    });
  }
  return state.planVaultControl({
    schema_version: MODEL_MOUNT_VAULT_CONTROL_SCHEMA_VERSION,
    operation_kind,
    vault_ref: vaultRef,
    material_hash: material == null ? null : `sha256:${stableHash(material)}`,
    custody_ref: stringField(body, "custody_ref"),
    source: "runtime-daemon.model_mounting.vault_control",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    state_dir: state.stateDir ?? null,
    body: sanitizedVaultBody(body),
    receipt_refs: stringArrayField(body, "receipt_refs"),
    authority_grant_refs: stringArrayField(body, "authority_grant_refs"),
    authority_receipt_refs: stringArrayField(body, "authority_receipt_refs"),
  });
}

export function commitVaultControlPlan(state, plan, options = {}) {
  return commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    invalidCode: "model_mount_vault_control_record_state_commit_invalid",
    unconfiguredCode: "model_mount_vault_control_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Vault control requires Rust Agentgres record-state commit before wallet/cTEE custody truth can return.",
    ...options,
  });
}

export function vaultControlResponse(plan, commit) {
  const record = plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
    ? plan.record
    : {};
  const plannedResponse =
    plan.public_response && typeof plan.public_response === "object" && !Array.isArray(plan.public_response)
      ? plan.public_response
      : null;
  const recordResponse =
    record.public_response && typeof record.public_response === "object" && !Array.isArray(record.public_response)
      ? record.public_response
      : {};
  const publicResponse = plannedResponse ?? recordResponse;
  return {
    ...publicResponse,
    status: publicResponse.status ?? "committed",
    operation_kind: plan.operation_kind,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record,
    commit,
    receipt_refs: plan.receipt_refs,
    authority_grant_refs: plan.authority_grant_refs,
    authority_receipt_refs: plan.authority_receipt_refs,
    evidence_refs: plan.evidence_refs,
    control_hash: plan.control_hash,
    authority_hash: plan.authority_hash,
  };
}

function sanitizedVaultBody(value) {
  const body = objectBody(value);
  const sanitized = {};
  for (const [field, fieldValue] of Object.entries(body)) {
    if (field === "material" || field === "secret" || field === "value" || field === "vaultRef") continue;
    sanitized[field] = fieldValue;
  }
  return sanitized;
}

function objectBody(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function stringField(value, field) {
  const candidate = objectBody(value)[field];
  return typeof candidate === "string" && candidate.trim() ? candidate.trim() : null;
}

function stringArrayField(value, field) {
  const candidate = objectBody(value)[field];
  if (!Array.isArray(candidate)) return [];
  return candidate.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim());
}
