import { commitModelMountRecordState } from "./record-state-commits.mjs";

const MODEL_MOUNT_TOKENIZER_SCHEMA_VERSION = "ioi.model_mount.tokenizer.v1";

export function tokenizerRequestForMountedState(
  state,
  {
    operation,
    body = {},
    requiredScope = null,
    routeSelection = null,
  } = {},
) {
  return {
    schema_version: MODEL_MOUNT_TOKENIZER_SCHEMA_VERSION,
    operation,
    source: "runtime-daemon.model_mounting.tokenizer",
    generated_at: typeof state?.nowIso === "function" ? state.nowIso() : null,
    required_scope: requiredScope,
    body: body && typeof body === "object" && !Array.isArray(body) ? body : {},
    route_selection: routeSelection,
    artifacts: [...(state?.artifacts?.values?.() ?? [])],
  };
}

export function commitTokenizerControlPlan(state, plan, options = {}) {
  return commitModelMountRecordState(state, {
    recordDir: plan.record_dir,
    record: plan.record,
    operation_kind: `model_mount.tokenizer.${plan.operation}`,
    receipt_refs: plan.receipt_refs,
    invalidCode: "model_mount_tokenizer_record_state_commit_invalid",
    unconfiguredCode: "model_mount_tokenizer_record_state_commit_unconfigured",
    unconfiguredMessage:
      "Model tokenizer control requires Rust Agentgres record-state commit before public tokenizer truth can return.",
    ...options,
  });
}

export function tokenizerControlResponse(plan, commit) {
  const record = plan.record && typeof plan.record === "object" && !Array.isArray(plan.record)
    ? plan.record
    : {};
  return {
    ...record,
    object: "ioi.model_mount_tokenizer",
    status: "committed",
    operation: plan.operation,
    rust_core_boundary: plan.rust_core_boundary,
    record_dir: plan.record_dir,
    record_id: plan.record_id,
    record,
    commit,
    receipt_refs: plan.receipt_refs,
    evidence_refs: plan.evidence_refs,
    control_hash: plan.control_hash,
  };
}
