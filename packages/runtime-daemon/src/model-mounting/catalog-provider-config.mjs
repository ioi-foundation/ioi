import {
  runtimeError,
} from "./io.mjs";
import { commitModelMountRecordState } from "./record-state-commits.mjs";

export const MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS = ["catalog.local_manifest", "catalog.custom_http", "catalog.huggingface"];
const MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_SCHEMA_VERSION = "ioi.model_mount.catalog_provider_control.v1";

export function assertConfigurableCatalogProvider(providerId) {
  if (!MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS.includes(providerId)) {
    throw runtimeError({
      status: 404,
      code: "not_found",
      message: `Catalog provider is not configurable: ${providerId}`,
      details: { provider_id: providerId },
    });
  }
}

export function throwCatalogProviderControlRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? defaultRuntimeError)({
    status: 501,
    code: "model_mount_catalog_provider_control_rust_core_required",
    message:
      "Catalog provider configuration, OAuth, and auth-header mutation facades require Rust daemon-core wallet/cTEE custody ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.catalog_provider_control",
      evidence_refs: [
        "public_catalog_provider_control_js_facade_retired",
        "rust_daemon_core_catalog_provider_control_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ],
      ...details,
    },
  });
}

export function catalogProviderControlPlanForState(
  state,
  operation_kind,
  {
    providerId = null,
    body = {},
    requiredScope = null,
    custodyRef = null,
  } = {},
) {
  if (!state || typeof state.planCatalogProviderControl !== "function") {
    throwCatalogProviderControlRustCoreRequired(operation_kind, {
      provider_id: providerId,
      rust_core_api: "plan_model_mount_catalog_provider_control",
    });
  }
  return state.planCatalogProviderControl({
    schema_version: MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_SCHEMA_VERSION,
    operation_kind,
    provider_id: providerId,
    source: "runtime-daemon.model_mounting.catalog_provider_control",
    generated_at: typeof state.nowIso === "function" ? state.nowIso() : null,
    body: objectBody(body),
    receipt_refs: stringArrayField(body, "receipt_refs"),
    authority_grant_refs: stringArrayField(body, "authority_grant_refs"),
    authority_receipt_refs: stringArrayField(body, "authority_receipt_refs"),
    custody_ref: custodyRef ?? stringField(body, "custody_ref"),
    required_scope: requiredScope,
  });
}

export function commitCatalogProviderControlPlan(state, plan, options = {}) {
  return commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: plan.operation_kind,
    receipt_refs: plan.receipt_refs,
    invalidCode: "model_mount_catalog_provider_control_record_state_commit_invalid",
    unconfiguredCode: "model_mount_catalog_provider_control_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Catalog provider control requires Rust Agentgres record-state commit before public provider truth can return.",
    ...options,
  });
}

export function catalogProviderControlResponse(plan, commit) {
  const record = plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
    ? plan.record
    : {};
  const publicResponse = record.public_response && typeof record.public_response === "object" && !Array.isArray(record.public_response)
    ? record.public_response
    : {};
  return {
    ...publicResponse,
    status: "committed",
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

function stringField(value, field) {
  const candidate = objectBody(value)[field];
  return typeof candidate === "string" && candidate.trim() ? candidate.trim() : null;
}

function stringArrayField(value, field) {
  const candidate = objectBody(value)[field];
  if (!Array.isArray(candidate)) return [];
  return candidate.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim());
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}
