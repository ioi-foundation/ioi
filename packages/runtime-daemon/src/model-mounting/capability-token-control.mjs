import {
  runtimeError,
} from "./io.mjs";
import { commitModelMountRecordState } from "./record-state-commits.mjs";

export const MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION =
  "ioi.model_mount.capability_token_control.v1";

export function throwCapabilityTokenRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? runtimeError)({
    status: 501,
    code: "model_mount_capability_token_rust_core_required",
    message:
      "Capability token mutation and authorization facades require Rust daemon-core wallet authority ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.capability_token",
      evidence_refs: [
        "public_capability_token_js_facade_retired",
        "rust_daemon_core_wallet_authority_required",
      ],
      ...details,
    },
  });
}

export function capabilityTokenControlPlanForState(
  state,
  operation_kind,
  {
    body = {},
    tokenId = null,
    tokenHash = null,
    requiredScope = null,
  } = {},
) {
  if (!state || typeof state.planCapabilityTokenControl !== "function") {
    throwCapabilityTokenRustCoreRequired(operation_kind, {
      token_id: tokenId,
      required_scope: requiredScope,
      rust_core_api: "plan_model_mount_capability_token_control",
    });
  }
  return state.planCapabilityTokenControl({
    schema_version: MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION,
    operation_kind,
    token_id: tokenId,
    token_hash: tokenHash,
    required_scope: requiredScope,
    source: "runtime-daemon.model_mounting.capability_token_control",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    state_dir: state.stateDir ?? null,
    body: objectBody(body),
    receipt_refs: stringArrayField(body, "receipt_refs"),
    authority_grant_refs: stringArrayField(body, "authority_grant_refs"),
    authority_receipt_refs: stringArrayField(body, "authority_receipt_refs"),
  });
}

export function commitCapabilityTokenControlPlan(state, plan, options = {}) {
  return commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    invalidCode: "model_mount_capability_token_control_record_state_commit_invalid",
    unconfiguredCode: "model_mount_capability_token_control_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Capability token control requires Rust Agentgres record-state commit before wallet authority truth can return.",
    ...options,
  });
}

export function capabilityTokenControlResponse(plan, commit) {
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

function objectBody(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function stringArrayField(value, field) {
  const candidate = objectBody(value)[field];
  if (!Array.isArray(candidate)) return [];
  return candidate.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim());
}
