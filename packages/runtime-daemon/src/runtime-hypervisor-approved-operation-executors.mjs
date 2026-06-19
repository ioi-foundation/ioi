import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const HYPERVISOR_APPROVED_OPERATION_EXECUTOR_REGISTRY_SCHEMA_VERSION =
  "ioi.runtime.hypervisor_approved_operation_executor_registry.v1";

const EXECUTOR_REF_BY_KIND = new Map([
  [
    "session_lifecycle_adapter",
    "executor://hypervisor/session/lifecycle-adapter",
  ],
  [
    "provider_lifecycle_adapter",
    "executor://hypervisor/provider/lifecycle-adapter",
  ],
  [
    "project_lifecycle_adapter",
    "executor://hypervisor/project/lifecycle-adapter",
  ],
  [
    "workflow_compositor_runner",
    "executor://hypervisor/automation/workflow-compositor-runner",
  ],
]);

export function createHypervisorApprovedOperationExecutorRegistry(options = {}) {
  const nowIso = options.nowIso ?? (() => new Date().toISOString());
  const adapterOverrides = objectRecord(options.adapters) ?? {};
  const adapters = new Map([
    ["session_lifecycle_adapter", executeSessionLifecyclePlan],
    ["provider_lifecycle_adapter", executeProviderLifecyclePlan],
    ["project_lifecycle_adapter", executeProjectLifecyclePlan],
    ["workflow_compositor_runner", executeWorkflowCompositorPlan],
  ]);
  for (const [executorKind, adapter] of Object.entries(adapterOverrides)) {
    if (typeof adapter === "function") adapters.set(executorKind, adapter);
  }

  async function executeApprovedOperationPlan(plan, context = {}) {
    const executorKind = requiredString(plan.executor_kind, "executor_kind");
    const adapter = adapters.get(executorKind);
    if (typeof adapter !== "function") {
      throw executorError({
        status: 501,
        code: "hypervisor_approved_operation_executor_not_mounted",
        message:
          "No Hypervisor approved-operation executor is mounted for this executor kind.",
        details: { executor_kind: executorKind },
      });
    }
    assertMountedExecutorRef(plan, context);
    return adapter(plan, {
      ...context,
      nowIso,
      expected_executor_ref: expectedExecutorRefForPlan(plan),
    });
  }

  return {
    schema_version: HYPERVISOR_APPROVED_OPERATION_EXECUTOR_REGISTRY_SCHEMA_VERSION,
    executor_refs: [...EXECUTOR_REF_BY_KIND.values()],
    executeApprovedOperationPlan,
  };
}

export function expectedExecutorRefForPlan(plan = {}) {
  const executorKind = requiredString(plan.executor_kind, "executor_kind");
  const executorRef = EXECUTOR_REF_BY_KIND.get(executorKind);
  if (!executorRef) {
    throw executorError({
      status: 501,
      code: "hypervisor_approved_operation_executor_kind_unknown",
      message:
        "Hypervisor approved-operation executor kind is not registered.",
      details: { executor_kind: executorKind },
    });
  }
  return executorRef;
}

function executeSessionLifecyclePlan(plan, context) {
  return buildExecutionReceiptResult(plan, context, {
    adapter_kind: "session_lifecycle_adapter",
    receipt_kind: "session-lifecycle",
  });
}

function executeProviderLifecyclePlan(plan, context) {
  return buildExecutionReceiptResult(plan, context, {
    adapter_kind: "provider_lifecycle_adapter",
    receipt_kind: "provider-lifecycle",
  });
}

function executeProjectLifecyclePlan(plan, context) {
  return buildExecutionReceiptResult(plan, context, {
    adapter_kind: "project_lifecycle_adapter",
    receipt_kind: "project-lifecycle",
  });
}

function executeWorkflowCompositorPlan(plan, context) {
  return buildExecutionReceiptResult(plan, context, {
    adapter_kind: "workflow_compositor_runner",
    receipt_kind: "workflow-compositor",
  });
}

function buildExecutionReceiptResult(plan, context, { adapter_kind, receipt_kind }) {
  const operationFamily = requiredString(plan.operation_family, "operation_family");
  const operationKind = requiredString(plan.operation_kind, "operation_kind");
  const admissionId = requiredString(plan.admission_id, "admission_id");
  const attemptRef = requiredString(
    context.execution_attempt_ref,
    "execution_attempt_ref",
  );
  const executionId = [
    safeId(operationFamily),
    safeId(operationKind),
    safeId(admissionId),
    safeId(attemptRef),
  ].join("/");
  const existingArtifactRefs = normalizeArray(plan.artifact_refs).filter((ref) =>
    String(ref).startsWith("artifact://"),
  );
  return {
    execution_status: "completed",
    execution_receipt_ref:
      `receipt://hypervisor/${receipt_kind}/${executionId}`,
    agentgres_operation_refs: [
      `agentgres://operation/hypervisor/${receipt_kind}/${executionId}`,
    ],
    artifact_refs: uniqueStrings([
      ...existingArtifactRefs,
      `artifact://hypervisor/${receipt_kind}/${executionId}/execution-summary`,
    ]),
    trace_refs: [`trace://hypervisor/${receipt_kind}/${executionId}`],
    next_state_root_ref:
      `agentgres://state-root/hypervisor/${receipt_kind}/${executionId}`,
    execution_result_ref: `result://hypervisor/${receipt_kind}/${executionId}`,
    executor_metadata: {
      adapter_kind,
      executor_ref: context.executor_ref,
      expected_executor_ref: context.expected_executor_ref,
      executed_at: context.nowIso(),
      admission_id: admissionId,
    },
  };
}

function assertMountedExecutorRef(plan, context = {}) {
  const actual = requiredString(context.executor_ref, "executor_ref");
  const expected = expectedExecutorRefForPlan(plan);
  if (actual !== expected) {
    throw executorError({
      status: 403,
      code: "hypervisor_approved_operation_executor_ref_not_mounted",
      message:
        "Hypervisor approved-operation dispatch can only use the mounted executor ref for the admitted executor kind.",
      details: {
        executor_kind: plan.executor_kind,
        executor_ref: actual,
        expected_executor_ref: expected,
      },
    });
  }
}

function requiredString(value, field) {
  const text = optionalString(value);
  if (!text) {
    throw executorError({
      code: "hypervisor_approved_operation_executor_required_field_missing",
      message: `Hypervisor approved-operation executor requires ${field}.`,
      details: { field },
    });
  }
  return text;
}

function executorError({ status = 400, code, message, details }) {
  return runtimeError({
    status,
    code,
    message,
    details,
  });
}
