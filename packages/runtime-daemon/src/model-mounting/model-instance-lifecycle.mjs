import { RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND } from "./model-mount-admission-runner.mjs";

export const MODEL_MOUNT_INSTANCE_LIFECYCLE_STATUS_ACTIONS = new Map([
  ["loaded", "load"],
  ["unloaded", "unload"],
  ["evicted", "evict"],
  ["superseded", "supersede"],
]);

export function modelMountProviderKindRequiresRustInstanceLifecycle(providerKind) {
  return providerKind === "ioi_native_local" || providerKind === "local_folder";
}

export function expectedModelMountInstanceLifecycleAction(status) {
  return MODEL_MOUNT_INSTANCE_LIFECYCLE_STATUS_ACTIONS.get(status) ?? null;
}

export function modelMountInstanceLifecycleBindingIssues(record = {}, { prefix = record.id ?? record.instanceId ?? "model-instance", status = record.status } = {}) {
  const expectedAction = expectedModelMountInstanceLifecycleAction(status);
  if (!expectedAction) return { missing: [], mismatches: [] };
  const evidenceRefs = Array.isArray(record.model_mount_instance_lifecycle_evidence_refs)
    ? record.model_mount_instance_lifecycle_evidence_refs
    : [];
  const missing = [];
  const mismatches = [];
  if (!record.model_mount_provider_lifecycle_hash) {
    missing.push(`${prefix}:model_mount_provider_lifecycle_hash`);
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
