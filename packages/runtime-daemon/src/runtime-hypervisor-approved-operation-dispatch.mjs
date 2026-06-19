import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";
import {
  HYPERVISOR_APPROVED_OPERATION_EXECUTION_PLAN_SCHEMA_VERSION,
} from "./runtime-hypervisor-approved-operation-admission.mjs";

export const HYPERVISOR_APPROVED_OPERATION_DISPATCH_SCHEMA_VERSION =
  "ioi.runtime.hypervisor_approved_operation_dispatch.v1";

const VALID_EXECUTION_STATUSES = new Set(["completed", "failed", "blocked"]);

export async function dispatchHypervisorApprovedOperationPlan(input = {}, deps = {}) {
  assertNoRetiredAliases(input);

  const plan = requireExecutionPlan(input.execution_plan);
  assertOptionalMatch(
    input.execution_plan_ref,
    plan.execution_plan_ref,
    "execution_plan_ref",
  );
  assertOptionalMatch(input.dispatch_ref, plan.dispatch_ref, "dispatch_ref");
  assertOptionalMatch(input.executor_kind, plan.executor_kind, "executor_kind");

  const executeApprovedOperationPlan = deps.executeApprovedOperationPlan;
  if (typeof executeApprovedOperationPlan !== "function") {
    throw dispatchError({
      status: 501,
      code: "hypervisor_approved_operation_executor_required",
      message:
        "Approved Hypervisor operation dispatch requires a mounted executor for the admitted execution plan.",
      details: {
        execution_plan_ref: plan.execution_plan_ref,
        executor_kind: plan.executor_kind,
      },
    });
  }

  const executorRef = prefixedString(
    input.executor_ref,
    "executor_ref",
    "executor://hypervisor/",
  );
  const startedAt = optionalString(input.started_at) ?? nowIso(deps);
  const executionAttemptRef =
    optionalString(input.execution_attempt_ref) ??
    `execution-attempt://hypervisor/${safeId(plan.dispatch_ref)}`;
  const executorResult = await executeApprovedOperationPlan(plan, {
    executor_ref: executorRef,
    execution_attempt_ref: executionAttemptRef,
  });
  const normalizedResult = normalizeExecutorResult(executorResult, plan);
  const finishedAt = optionalString(input.finished_at) ?? nowIso(deps);

  return {
    schema_version: HYPERVISOR_APPROVED_OPERATION_DISPATCH_SCHEMA_VERSION,
    execution_plan_ref: plan.execution_plan_ref,
    dispatch_ref: plan.dispatch_ref,
    execution_attempt_ref: executionAttemptRef,
    dispatch_status: normalizedResult.dispatch_status,
    execution_status: normalizedResult.execution_status,
    executor_kind: plan.executor_kind,
    executor_ref: executorRef,
    operation_family: plan.operation_family,
    operation_kind: plan.operation_kind,
    proposal_ref: plan.proposal_ref,
    admission_id: plan.admission_id,
    project_ref: plan.project_ref,
    session_ref: plan.session_ref ?? null,
    environment_ref: plan.environment_ref ?? null,
    candidate_ref: plan.candidate_ref ?? null,
    direct_provider_ref: plan.direct_provider_ref ?? null,
    workspace_ref: plan.workspace_ref ?? null,
    template_ref: plan.template_ref ?? null,
    run_recipe_ref: plan.run_recipe_ref ?? null,
    graph_ref: plan.graph_ref ?? null,
    action_proposal_ref: plan.action_proposal_ref ?? null,
    target_ref: plan.target_ref ?? null,
    wallet_lease_ref: plan.wallet_lease_ref,
    required_scope_refs: normalizeArray(plan.required_scope_refs),
    authority_receipt_refs: normalizeArray(plan.authority_receipt_refs),
    agentgres_operation_refs: uniqueStrings([
      ...normalizeArray(plan.agentgres_operation_refs),
      ...normalizedResult.agentgres_operation_refs,
    ]),
    receipt_refs: uniqueStrings([
      ...normalizeArray(plan.receipt_refs),
      ...normalizedResult.receipt_refs,
    ]),
    previous_state_root_ref: plan.state_root_ref,
    next_state_root_ref: normalizedResult.next_state_root_ref,
    artifact_refs: uniqueStrings([
      ...normalizeArray(plan.artifact_refs),
      ...normalizedResult.artifact_refs,
    ]),
    trace_refs: normalizedResult.trace_refs,
    execution_result_ref: normalizedResult.execution_result_ref,
    started_at: startedAt,
    finished_at: finishedAt,
    execution_boundary_invariant:
      "Approved Hypervisor operation dispatch consumes daemon-owned plans only; executors return receipts and state roots without becoming runtime truth.",
    runtimeTruthSource: "daemon-runtime",
  };
}

function requireExecutionPlan(value) {
  const plan = objectRecord(value);
  if (
    !plan ||
    plan.schema_version !== HYPERVISOR_APPROVED_OPERATION_EXECUTION_PLAN_SCHEMA_VERSION
  ) {
    throw dispatchError({
      code: "hypervisor_approved_operation_execution_plan_required",
      message:
        "Approved Hypervisor operation dispatch requires the canonical daemon-owned execution plan.",
      details: {
        expected_schema_version:
          HYPERVISOR_APPROVED_OPERATION_EXECUTION_PLAN_SCHEMA_VERSION,
      },
    });
  }
  if (plan.dispatch_status !== "awaiting_executor") {
    throw dispatchError({
      status: 409,
      code: "hypervisor_approved_operation_dispatch_status_invalid",
      message:
        "Approved Hypervisor operation dispatch only accepts plans awaiting an executor.",
      details: { dispatch_status: plan.dispatch_status },
    });
  }
  if (plan.runtimeTruthSource !== "daemon-runtime") {
    throw dispatchError({
      status: 403,
      code: "hypervisor_approved_operation_plan_truth_invalid",
      message:
        "Approved Hypervisor operation dispatch only accepts daemon-runtime plans.",
      details: { runtimeTruthSource: plan.runtimeTruthSource },
    });
  }
  requiredPlanString(plan.execution_plan_ref, "execution_plan_ref");
  requiredPlanString(plan.dispatch_ref, "dispatch_ref");
  requiredPlanString(plan.executor_kind, "executor_kind");
  requiredPlanString(plan.operation_family, "operation_family");
  requiredPlanString(plan.operation_kind, "operation_kind");
  requiredPlanString(plan.wallet_lease_ref, "wallet_lease_ref");
  prefixedPlanRefs(plan.agentgres_operation_refs, "agentgres_operation_refs", "agentgres://operation/");
  prefixedPlanRefs(plan.receipt_refs, "receipt_refs", "receipt://");
  prefixedPlanString(plan.state_root_ref, "state_root_ref", "agentgres://state-root/");
  return plan;
}

function normalizeExecutorResult(value, plan) {
  const result = objectRecord(value);
  if (!result) {
    throw dispatchError({
      code: "hypervisor_approved_operation_executor_result_required",
      message:
        "Approved Hypervisor operation executors must return a structured result.",
      details: { execution_plan_ref: plan.execution_plan_ref },
    });
  }
  const executionStatus = optionalString(result.execution_status) ?? "completed";
  if (!VALID_EXECUTION_STATUSES.has(executionStatus)) {
    throw dispatchError({
      code: "hypervisor_approved_operation_execution_status_invalid",
      message:
        "Approved Hypervisor operation executor result has an unsupported execution status.",
      details: { execution_status: executionStatus },
    });
  }
  const receiptRefs = prefixedRefs(
    refsFrom(result.receipt_refs, result.execution_receipt_ref),
    "receipt_refs",
    "receipt://",
  );
  const agentgresOperationRefs = prefixedRefs(
    result.agentgres_operation_refs,
    "agentgres_operation_refs",
    "agentgres://operation/",
    { allowEmpty: true },
  );
  const nextStateRootRef =
    optionalString(result.next_state_root_ref) ?? plan.state_root_ref;
  prefixedPlanString(
    nextStateRootRef,
    "next_state_root_ref",
    "agentgres://state-root/",
  );
  return {
    dispatch_status:
      executionStatus === "completed"
        ? "executed"
        : executionStatus === "failed"
          ? "failed"
          : "blocked",
    execution_status: executionStatus,
    receipt_refs: receiptRefs,
    agentgres_operation_refs: agentgresOperationRefs,
    artifact_refs: prefixedRefs(result.artifact_refs, "artifact_refs", "artifact://", {
      allowEmpty: true,
    }),
    trace_refs: prefixedRefs(result.trace_refs, "trace_refs", "trace://", {
      allowEmpty: true,
    }),
    next_state_root_ref: nextStateRootRef,
    execution_result_ref: optionalString(result.execution_result_ref) ?? null,
  };
}

function refsFrom(plural, singular) {
  return uniqueStrings([
    ...normalizeArray(plural),
    ...(optionalString(singular) ? [optionalString(singular)] : []),
  ]);
}

function prefixedRefs(value, field, prefix, { allowEmpty = false } = {}) {
  const refs = uniqueStrings(normalizeArray(value));
  if (!allowEmpty && refs.length === 0) {
    throw dispatchError({
      code: "hypervisor_approved_operation_dispatch_required_refs_missing",
      message: `Approved Hypervisor operation dispatch requires ${field}.`,
      details: { field },
    });
  }
  for (const ref of refs) {
    if (!ref.startsWith(prefix)) {
      throw dispatchError({
        code: "hypervisor_approved_operation_dispatch_ref_prefix_invalid",
        message: `${field} must use ${prefix} refs.`,
        details: { field, ref, expected_prefix: prefix },
      });
    }
  }
  return refs;
}

function prefixedString(value, field, prefix) {
  const text = requiredPlanString(value, field);
  if (!text.startsWith(prefix)) {
    throw dispatchError({
      code: "hypervisor_approved_operation_dispatch_ref_prefix_invalid",
      message: `${field} must use a ${prefix} ref.`,
      details: { field, ref: text, expected_prefix: prefix },
    });
  }
  return text;
}

function prefixedPlanString(value, field, prefix) {
  const text = requiredPlanString(value, field);
  if (!text.startsWith(prefix)) {
    throw dispatchError({
      code: "hypervisor_approved_operation_dispatch_ref_prefix_invalid",
      message: `${field} must use a ${prefix} ref.`,
      details: { field, ref: text, expected_prefix: prefix },
    });
  }
  return text;
}

function prefixedPlanRefs(value, field, prefix) {
  return prefixedRefs(value, field, prefix);
}

function requiredPlanString(value, field) {
  const text = optionalString(value);
  if (!text) {
    throw dispatchError({
      code: "hypervisor_approved_operation_dispatch_required_field_missing",
      message: `Approved Hypervisor operation dispatch requires ${field}.`,
      details: { field },
    });
  }
  return text;
}

function assertOptionalMatch(value, expected, field) {
  const actual = optionalString(value);
  if (actual && actual !== expected) {
    throw dispatchError({
      status: 409,
      code: "hypervisor_approved_operation_dispatch_ref_mismatch",
      message:
        "Approved Hypervisor operation dispatch input must match the daemon-owned execution plan.",
      details: { field, expected, actual },
    });
  }
}

function assertNoRetiredAliases(input) {
  const retired = [
    "executionPlan",
    "executionPlanRef",
    "dispatchRef",
    "executorKind",
    "executorRef",
    "receiptRefs",
    "nextStateRootRef",
  ].filter((field) => Object.prototype.hasOwnProperty.call(input, field));
  if (retired.length > 0) {
    throw dispatchError({
      code: "hypervisor_approved_operation_dispatch_retired_alias",
      message:
        "Approved Hypervisor operation dispatch accepts snake_case fields only.",
      details: { retired_aliases: retired },
    });
  }
}

function nowIso(deps) {
  const clock = deps.nowIso ?? (() => new Date().toISOString());
  return clock();
}

function dispatchError({
  status = 400,
  code = "hypervisor_approved_operation_dispatch_failed",
  message,
  details,
}) {
  return runtimeError({ status, code, message, details });
}
