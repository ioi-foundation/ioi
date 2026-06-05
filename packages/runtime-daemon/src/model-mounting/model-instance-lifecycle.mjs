import { RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND } from "./model-mount-admission-runner.mjs";

export const MODEL_MOUNT_INSTANCE_LIFECYCLE_STATUS_ACTIONS = new Map([
  ["loaded", "load"],
  ["unloaded", "unload"],
  ["evicted", "evict"],
  ["superseded", "supersede"],
]);

export function modelMountInstanceLifecycleRequiresRust(provider) {
  return modelMountProviderKindRequiresRustInstanceLifecycle(provider?.kind);
}

export function modelMountProviderKindRequiresRustInstanceLifecycle(providerKind) {
  return providerKind === "ioi_native_local" || providerKind === "local_folder";
}

export function expectedModelMountInstanceLifecycleAction(status) {
  return MODEL_MOUNT_INSTANCE_LIFECYCLE_STATUS_ACTIONS.get(status) ?? null;
}

export function modelMountInstanceLifecycleFields(instanceLifecycle) {
  if (!instanceLifecycle) return {};
  return {
    model_mount_instance_lifecycle_action: instanceLifecycle.action,
    model_mount_instance_lifecycle_status: instanceLifecycle.status,
    model_mount_instance_lifecycle_hash: instanceLifecycle.instance_lifecycle_hash,
    model_mount_instance_lifecycle_evidence_refs: instanceLifecycle.evidence_refs ?? [],
  };
}

export function modelMountInstanceLifecycleBindingIssues(record = {}, { prefix = record.id ?? record.instanceId ?? "model-instance", status = record.status } = {}) {
  const expectedAction = expectedModelMountInstanceLifecycleAction(status);
  if (!expectedAction) return { missing: [], mismatches: [] };
  const evidenceRefs = Array.isArray(record.model_mount_instance_lifecycle_evidence_refs)
    ? record.model_mount_instance_lifecycle_evidence_refs
    : [];
  const missing = [];
  const mismatches = [];
  if (!record.providerLifecycleHash) {
    missing.push(`${prefix}:providerLifecycleHash`);
  }
  if (!record.model_mount_instance_lifecycle_hash) {
    missing.push(`${prefix}:model_mount_instance_lifecycle_hash`);
  }
  if (!evidenceRefs.includes(RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND)) {
    missing.push(`${prefix}:model_mount_instance_lifecycle_evidence_refs`);
  }
  if (!record.model_mount_instance_lifecycle_action) {
    missing.push(`${prefix}:model_mount_instance_lifecycle_action`);
  } else if (record.model_mount_instance_lifecycle_action !== expectedAction) {
    mismatches.push(`${prefix}:model_mount_instance_lifecycle_action`);
  }
  if (!record.model_mount_instance_lifecycle_status) {
    missing.push(`${prefix}:model_mount_instance_lifecycle_status`);
  } else if (record.model_mount_instance_lifecycle_status !== status) {
    mismatches.push(`${prefix}:model_mount_instance_lifecycle_status`);
  }
  return { missing, mismatches };
}

export function planModelMountInstanceLifecycleForMigratedProvider({
  state,
  action,
  targetStatus,
  instanceId,
  endpoint,
  provider,
  backendId,
  driver,
  providerLifecycleHash,
  evidenceRefs = [],
}) {
  if (!modelMountInstanceLifecycleRequiresRust(provider)) return null;
  if (!providerLifecycleHash) {
    const error = new Error("Model instance lifecycle transition requires a Rust provider lifecycle hash.");
    error.status = 502;
    error.code = "model_mount_instance_lifecycle_provider_hash_required";
    error.details = { action, providerId: provider?.id ?? null };
    throw error;
  }
  if (typeof state.planModelMountInstanceLifecycle !== "function") {
    const error = new Error("Model instance lifecycle transition requires Rust model_mount planning.");
    error.status = 502;
    error.code = "model_mount_instance_lifecycle_planning_required";
    error.details = { action, providerId: provider?.id ?? null };
    throw error;
  }
  return requireModelMountInstanceLifecycleResult(state.planModelMountInstanceLifecycle({
    schema_version: "ioi.model_mount.instance_lifecycle.v1",
    instance_ref: instanceId,
    endpoint_ref: endpoint.id,
    model_ref: endpoint.modelId,
    provider_ref: provider.id,
    action,
    target_status: targetStatus,
    execution_backend: RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND,
    backend_ref: backendId,
    driver,
    provider_lifecycle_hash: providerLifecycleHash,
    evidence_refs: normalizeRefs(evidenceRefs),
  }), { action, targetStatus, backendId, driver, providerLifecycleHash });
}

function requireModelMountInstanceLifecycleResult(value, {
  action,
  targetStatus,
  backendId,
  driver,
  providerLifecycleHash,
}) {
  if (
    !value ||
    value.action !== action ||
    value.status !== targetStatus ||
    value.backendId !== backendId ||
    value.driver !== driver ||
    value.executionBackend !== RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND ||
    value.providerLifecycleHash !== providerLifecycleHash ||
    !value.instance_lifecycle_hash
  ) {
    const error = new Error("Model instance lifecycle transition requires a Rust model_mount instance lifecycle result.");
    error.status = 502;
    error.code = "model_mount_instance_lifecycle_planning_required";
    error.details = { action, targetStatus, backendId, driver };
    throw error;
  }
  return value;
}

function normalizeRefs(values = []) {
  return [...new Set((Array.isArray(values) ? values : []).map((value) => String(value).trim()).filter(Boolean))];
}
