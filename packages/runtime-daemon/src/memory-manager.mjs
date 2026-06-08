import { createContextPolicyRunnerFromEnv } from "./runtime-context-policy-runner.mjs";

export const RUNTIME_MEMORY_MANAGER_STATUS_SCHEMA_VERSION =
  "ioi.runtime.memory-manager-status.v1";
export const RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION =
  "ioi.runtime.memory-manager-validation.v1";
export const RUNTIME_MEMORY_MANAGER_MUTATION_SCHEMA_VERSION =
  "ioi.runtime.memory-manager-mutation.v1";

export function memoryStatusForProjection(projection = {}, options = {}) {
  const contextPolicyRunner =
    options.contextPolicyRunner ?? createContextPolicyRunnerFromEnv();
  return contextPolicyRunner.planMemoryManagerStatusProjection({
    status_schema_version: RUNTIME_MEMORY_MANAGER_STATUS_SCHEMA_VERSION,
    validation_schema_version: RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION,
    projection,
  });
}

export function validateMemoryProjection(projection = {}, options = {}) {
  const contextPolicyRunner =
    options.contextPolicyRunner ?? createContextPolicyRunnerFromEnv();
  return contextPolicyRunner.planMemoryManagerValidationProjection({
    validation_schema_version: RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION,
    projection,
  });
}

export function memoryRowsForStatus(status = {}) {
  const threadId = status.thread_id ?? null;
  const receiptRefs = normalizeArray(status.receipt_refs);
  const policyRefs = normalizeArray(status.policy_decision_refs);
  const policy = status.policy ?? {};
  const rows = [
    {
      id: `memory-status-${safeId(threadId ?? "runtime")}`,
      row_kind: "memory_status",
      status: status.status === "ready" ? "completed" : status.status === "disabled" ? "blocked" : "blocked",
      label: "Memory status",
      command: "memory",
      raw_input: "/memory status",
      message: `records=${status.record_count ?? 0} injection=${status.injection_enabled !== false}`,
      thread_id: threadId,
      memory_operation: "status",
      memory_record_id: null,
      memory_scope: policy.scope ?? null,
      memory_key: null,
      workflow_node_id: "runtime.memory-manager",
      receipt_refs: receiptRefs,
      policy_decision_refs: policyRefs,
    },
    {
      id: `memory-policy-${safeId(policy.id ?? threadId ?? "runtime")}`,
      row_kind: "memory_policy",
      status: policy.disabled ? "blocked" : "completed",
      label: "Memory policy",
      command: "memory",
      raw_input: "/memory policy",
      message: `scope=${policy.scope ?? "thread"} readOnly=${Boolean(policy.readOnly)} approval=${Boolean(policy.writeRequiresApproval)}`,
      thread_id: threadId,
      memory_operation: "policy",
      memory_record_id: null,
      memory_scope: policy.scope ?? null,
      memory_key: null,
      workflow_node_id: "runtime.memory-manager.policy",
      receipt_refs: receiptRefs,
      policy_decision_refs: policyRefs,
    },
  ];
  for (const record of normalizeArray(status.records)) {
    rows.push({
      id: `memory-record-${safeId(record.id)}`,
      row_kind: "memory_record",
      status: "completed",
      label: "Memory record",
      command: "memory",
      raw_input: "/memory show",
      message: record.redaction === "redacted" ? "[REDACTED]" : record.fact,
      thread_id: record.thread_id ?? threadId,
      memory_operation: "read",
      memory_record_id: record.id,
      memory_scope: record.scope ?? null,
      memory_key: record.memory_key ?? null,
      workflow_node_id: record.workflow_node_id ?? "runtime.memory",
      receipt_refs: receiptRefs,
      policy_decision_refs: policyRefs,
    });
  }
  return rows;
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
