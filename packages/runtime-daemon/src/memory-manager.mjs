import fs from "node:fs";

export const RUNTIME_MEMORY_MANAGER_STATUS_SCHEMA_VERSION =
  "ioi.runtime.memory-manager-status.v1";
export const RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION =
  "ioi.runtime.memory-manager-validation.v1";

const VALID_MEMORY_SCOPES = new Set([
  "global",
  "workspace",
  "thread",
  "workflow",
  "subagent",
]);
const VALID_REDACTIONS = new Set(["none", "redacted"]);
const VALID_RETENTIONS = new Set(["persistent", "session", "ephemeral"]);
const VALID_SUBAGENT_INHERITANCE = new Set([
  "none",
  "explicit",
  "read_only",
  "full",
]);

export function memoryStatusForProjection(projection = {}) {
  const records = normalizeArray(projection.records);
  const policy = projection.policy ?? {};
  const paths = projection.paths ?? {};
  const validation = validateMemoryProjection(projection);
  const disabled = Boolean(policy.disabled);
  const scopes = uniqueStrings(records.map((record) => record.scope).filter(Boolean));
  const memoryKeys = uniqueStrings(records.map((record) => record.memoryKey).filter(Boolean));
  const writeBlockedReason = memoryWriteBlockedReason(policy);
  const status = validation.ok ? (disabled ? "disabled" : "ready") : "needs_review";
  return {
    schema_version: RUNTIME_MEMORY_MANAGER_STATUS_SCHEMA_VERSION,
    schemaVersion: RUNTIME_MEMORY_MANAGER_STATUS_SCHEMA_VERSION,
    object: "ioi.runtime_memory_manager_status",
    status,
    disabled,
    injection_enabled: policy.injectionEnabled !== false,
    injectionEnabled: policy.injectionEnabled !== false,
    read_only: Boolean(policy.readOnly),
    readOnly: Boolean(policy.readOnly),
    write_requires_approval: Boolean(policy.writeRequiresApproval),
    writeRequiresApproval: Boolean(policy.writeRequiresApproval),
    write_blocked_reason: writeBlockedReason,
    writeBlockedReason,
    record_count: records.length,
    recordCount: records.length,
    scope_count: scopes.length,
    scopeCount: scopes.length,
    memory_key_count: memoryKeys.length,
    memoryKeyCount: memoryKeys.length,
    scopes,
    memory_keys: memoryKeys,
    memoryKeys,
    policy,
    paths,
    filters: projection.filters ?? {},
    records,
    validation,
    routes: {
      records: "/v1/threads/{thread_id}/memory",
      status: "/v1/threads/{thread_id}/memory/status",
      validate: "/v1/threads/{thread_id}/memory/validate",
      policy: "/v1/threads/{thread_id}/memory/policy",
      path: "/v1/threads/{thread_id}/memory/path",
    },
    evidence_refs: uniqueStrings([
      "runtime_memory_manager",
      "memory.status",
      policy.id,
      paths.effectivePolicyId,
      ...records.map((record) => record.id),
    ]),
    evidenceRefs: uniqueStrings([
      "runtime_memory_manager",
      "memory.status",
      policy.id,
      paths.effectivePolicyId,
      ...records.map((record) => record.id),
    ]),
  };
}

export function validateMemoryProjection(projection = {}) {
  const records = normalizeArray(projection.records);
  const policy = projection.policy ?? {};
  const paths = projection.paths ?? {};
  const issues = [];
  const warnings = [];

  validateMemoryPolicy(policy, { issues, warnings });
  validateMemoryPaths(paths, { issues, warnings });
  for (const record of records) validateMemoryRecord(record, { issues, warnings });

  return {
    schema_version: RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION,
    schemaVersion: RUNTIME_MEMORY_MANAGER_VALIDATION_SCHEMA_VERSION,
    object: "ioi.runtime_memory_manager_validation",
    ok: issues.length === 0,
    status: issues.length === 0 ? "pass" : "blocked",
    issue_count: issues.length,
    issueCount: issues.length,
    warning_count: warnings.length,
    warningCount: warnings.length,
    record_count: records.length,
    recordCount: records.length,
    issues,
    warnings,
    policy,
    paths,
    filters: projection.filters ?? {},
    records,
  };
}

export function memoryRowsForStatus(status = {}) {
  const threadId = status.thread_id ?? status.threadId ?? status.policy?.threadId ?? null;
  const receiptRefs = normalizeArray(status.receipt_refs ?? status.receiptRefs);
  const policyRefs = normalizeArray(status.policy_decision_refs ?? status.policyDecisionRefs);
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
      thread_id: record.threadId ?? threadId,
      memory_operation: "read",
      memory_record_id: record.id,
      memory_scope: record.scope ?? null,
      memory_key: record.memoryKey ?? null,
      workflow_node_id: record.workflowNodeId ?? "runtime.memory",
      receipt_refs: receiptRefs,
      policy_decision_refs: policyRefs,
    });
  }
  return rows;
}

function validateMemoryPolicy(policy, { issues, warnings }) {
  if (!policy || typeof policy !== "object") {
    issues.push(issue("memory_policy_missing", "Memory status requires an effective policy."));
    return;
  }
  if (!policy.id) {
    issues.push(issue("memory_policy_id_missing", "Memory policy must have a stable id."));
  }
  if (policy.scope && !VALID_MEMORY_SCOPES.has(String(policy.scope))) {
    issues.push(issue("memory_policy_scope_invalid", "Memory policy scope is not supported.", {
      memory_scope: policy.scope,
      memoryScope: policy.scope,
    }));
  }
  if (policy.redaction && !VALID_REDACTIONS.has(String(policy.redaction))) {
    issues.push(issue("memory_policy_redaction_invalid", "Memory policy redaction must be none or redacted."));
  }
  if (policy.retention && !VALID_RETENTIONS.has(String(policy.retention))) {
    warnings.push(warning("memory_policy_retention_unknown", "Memory retention is not one of the governed presets."));
  }
  if (policy.subagentInheritance && !VALID_SUBAGENT_INHERITANCE.has(String(policy.subagentInheritance))) {
    issues.push(issue("memory_subagent_inheritance_invalid", "Subagent memory inheritance mode is not supported."));
  }
  if (policy.disabled && policy.injectionEnabled !== false) {
    warnings.push(warning("memory_disabled_with_injection_enabled", "Disabled memory should also disable prompt injection."));
  }
  if (policy.readOnly && policy.writeRequiresApproval) {
    warnings.push(warning("memory_read_only_with_approval_required", "Read-only memory makes write approval unreachable."));
  }
}

function validateMemoryPaths(paths, { issues, warnings }) {
  for (const [key, label] of [
    ["recordsPath", "records"],
    ["policiesPath", "policies"],
  ]) {
    const value = paths?.[key];
    if (!value || typeof value !== "string") {
      issues.push(issue(`memory_${label}_path_missing`, `Memory ${label} path is missing.`));
      continue;
    }
    try {
      if (!fs.existsSync(value)) {
        warnings.push(warning(`memory_${label}_path_missing_on_disk`, `Memory ${label} path does not exist yet.`, {
          path: value,
        }));
        continue;
      }
      fs.accessSync(value, fs.constants.R_OK | fs.constants.W_OK);
    } catch {
      issues.push(issue(`memory_${label}_path_not_accessible`, `Memory ${label} path is not readable and writable.`, {
        path: value,
      }));
    }
  }
}

function validateMemoryRecord(record, { issues, warnings }) {
  if (!record || typeof record !== "object") {
    issues.push(issue("memory_record_invalid", "Memory record must be an object."));
    return;
  }
  if (!record.id) {
    issues.push(issue("memory_record_id_missing", "Memory record id is required."));
  }
  if (!record.fact || typeof record.fact !== "string") {
    issues.push(issue("memory_record_fact_missing", "Memory record fact text is required.", {
      memory_record_id: record.id ?? null,
      memoryRecordId: record.id ?? null,
    }));
  }
  if (record.scope && !VALID_MEMORY_SCOPES.has(String(record.scope))) {
    issues.push(issue("memory_record_scope_invalid", "Memory record scope is not supported.", {
      memory_record_id: record.id ?? null,
      memoryRecordId: record.id ?? null,
      memory_scope: record.scope,
      memoryScope: record.scope,
    }));
  }
  if (record.redaction === "redacted" && !record.factHash) {
    warnings.push(warning("memory_record_redacted_hash_missing", "Redacted memory records should include a fact hash.", {
      memory_record_id: record.id ?? null,
      memoryRecordId: record.id ?? null,
    }));
  }
}

function memoryWriteBlockedReason(policy = {}) {
  if (policy.disabled) return "memory_disabled";
  if (policy.readOnly) return "memory_read_only";
  if (policy.writeRequiresApproval) return "memory_write_requires_approval";
  return null;
}

function issue(code, message, extra = {}) {
  return { code, severity: "error", message, ...extra };
}

function warning(code, message, extra = {}) {
  return { code, severity: "warning", message, ...extra };
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values = []) {
  return [...new Set(values.map((value) => optionalString(value)).filter(Boolean))].sort();
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function safeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
