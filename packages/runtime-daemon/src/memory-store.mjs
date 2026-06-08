import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const AGENT_MEMORY_SCHEMA_VERSION = "ioi.agent-runtime.memory.v1";
export const AGENT_MEMORY_POLICY_SCHEMA_VERSION = "ioi.agent-runtime.memory-policy.v1";

const MEMORY_POLICY_FIELDS = [
  "disabled",
  "injection_enabled",
  "read_only",
  "write_requires_approval",
  "retention",
  "redaction",
  "subagent_inheritance",
  "scope",
];

const agentMemoryStoreWriterRetirementEvidenceRefs = [
  "runtime_memory_state_store_js_mutation_retired",
  "agent_memory_store_write_js_writer_retired",
  "agent_memory_store_edit_js_writer_retired",
  "agent_memory_store_delete_js_writer_retired",
  "agent_memory_store_policy_js_writer_retired",
  "rust_daemon_core_thread_memory_control_required",
  "agentgres_thread_memory_state_truth_required",
];

function throwAgentMemoryStoreRustCoreRequired({
  operation,
  operation_kind,
  memory_id = null,
  evidence_ref,
}) {
  const error = new Error(
    "AgentMemoryStore mutations require direct Rust daemon-core memory admission and persistence.",
  );
  error.status = 501;
  error.code = "runtime_memory_state_store_rust_core_required";
  error.details = {
    rust_core_boundary: "runtime.thread_memory_control",
    operation,
    operation_kind,
    ...(memory_id ? { memory_id } : {}),
    evidence_refs: [
      ...agentMemoryStoreWriterRetirementEvidenceRefs,
      evidence_ref,
    ].filter(Boolean),
  };
  throw error;
}

export class AgentMemoryStore {
  constructor(stateDir) {
    this.stateDir = path.resolve(stateDir);
    this.records = new Map();
    this.policies = new Map();
    fs.mkdirSync(this.memoryDir, { recursive: true });
    fs.mkdirSync(this.policyDir, { recursive: true });
    this.load();
  }

  get memoryDir() {
    return path.join(this.stateDir, "memory-records");
  }

  get policyDir() {
    return path.join(this.stateDir, "memory-policies");
  }

  load() {
    if (!fs.existsSync(this.memoryDir)) return;
    for (const entry of fs.readdirSync(this.memoryDir)) {
      if (!entry.endsWith(".json")) continue;
      const record = JSON.parse(fs.readFileSync(path.join(this.memoryDir, entry), "utf8"));
      if (typeof record.id === "string") this.records.set(record.id, record);
    }
    if (!fs.existsSync(this.policyDir)) return;
    for (const entry of fs.readdirSync(this.policyDir)) {
      if (!entry.endsWith(".json")) continue;
      const policy = JSON.parse(fs.readFileSync(path.join(this.policyDir, entry), "utf8"));
      if (typeof policy.id === "string") this.policies.set(policy.id, policy);
    }
  }

  remember({ text, agent, threadId, scope = "thread", workflow = {}, source = "operator_remember" } = {}) {
    void text;
    void agent;
    void threadId;
    void scope;
    void workflow;
    void source;
    throwAgentMemoryStoreRustCoreRequired({
      operation: "memory_write",
      operation_kind: "memory.write",
      evidence_ref: "agent_memory_store_write_js_writer_retired",
    });
  }

  updateRecord({ id, text, source = "memory_edit_api" } = {}) {
    throwAgentMemoryStoreRustCoreRequired({
      operation: "memory_edit",
      operation_kind: "memory.edit",
      memory_id: id,
      evidence_ref: "agent_memory_store_edit_js_writer_retired",
    });
  }

  deleteRecord({ id, source = "memory_delete_api" } = {}) {
    void source;
    throwAgentMemoryStoreRustCoreRequired({
      operation: "memory_delete",
      operation_kind: "memory.delete",
      memory_id: id,
      evidence_ref: "agent_memory_store_delete_js_writer_retired",
    });
  }

  list({ agent, threadId, workspace, includeGlobal = true, scope, memory_key, query, limit, redaction } = {}) {
    const filters = memoryListFilters({ scope, memory_key, query, limit, redaction });
    const records = [...this.records.values()]
      .filter((record) => {
        if (includeGlobal && record.scope === "global") return true;
        if (threadId && record.thread_id === threadId) return true;
        if (agent?.id && record.agent_id === agent.id && record.scope !== "thread") return true;
        if (workspace && record.workspace === workspace && record.scope === "workspace") return true;
        return false;
      })
      .filter((record) => !filters.scope || record.scope === filters.scope)
      .filter((record) => !filters.memory_key || record.memory_key === filters.memory_key)
      .filter((record) => !filters.query || memoryRecordSearchText(record).includes(filters.query))
      .sort((left, right) => left.created_at.localeCompare(right.created_at));
    const limited = filters.limit ? records.slice(0, filters.limit) : records;
    return filters.redaction === "redacted" ? limited.map(redactMemoryRecord) : limited;
  }

  write(record, { operation_kind = "memory.write", receipt_refs = [] } = {}) {
    void receipt_refs;
    throwAgentMemoryStoreRustCoreRequired({
      operation: "memory_write",
      operation_kind,
      memory_id: record?.id ?? null,
      evidence_ref: "agent_memory_store_write_js_writer_retired",
    });
  }

  projection({ agent, threadId, workspace, filters = {} } = {}) {
    const records = this.list({ agent, threadId, workspace: workspace ?? agent?.cwd, ...filters });
    const normalizedFilters = memoryListFilters(filters);
    return {
      schema_version: AGENT_MEMORY_SCHEMA_VERSION,
      object: "ioi.agent_memory_projection",
      thread_id: threadId ?? null,
      agent_id: agent?.id ?? null,
      workspace: workspace ?? agent?.cwd ?? null,
      policy: this.effectivePolicy({ agent, threadId, workspace: workspace ?? agent?.cwd }),
      paths: this.pathProjection({ agent, threadId, workspace: workspace ?? agent?.cwd }),
      filters: normalizedFilters,
      records,
      total_matches: records.length,
    };
  }

  effectivePolicy({ agent, threadId, workspace, overrides = {} } = {}) {
    const agentPolicy = agent?.id ? this.policies.get(policyId("agent", agent.id)) : null;
    const threadPolicy = threadId ? this.policies.get(policyId("thread", threadId)) : null;
    const now = new Date().toISOString();
    return {
      ...defaultPolicy({
        target_type: "thread",
        target_id: threadId ?? agent?.id ?? "runtime",
        agent,
        thread_id: threadId,
        workspace,
        now,
      }),
      ...policyFields(agentPolicy),
      ...policyFields(threadPolicy),
      ...policyFields(overrides),
      id: policyId("thread", threadId ?? agent?.id ?? "runtime"),
      target_type: "thread",
      target_id: threadId ?? agent?.id ?? "runtime",
      agent_id: agent?.id ?? null,
      thread_id: threadId ?? null,
      workspace: workspace ?? agent?.cwd ?? null,
      effective: true,
      policy_refs: [agentPolicy?.id, threadPolicy?.id].filter(Boolean),
    };
  }

  getPolicy({ target_type = "thread", target_id, agent, thread_id, workspace } = {}) {
    const id = policyId(target_type, requiredId(target_id ?? thread_id ?? agent?.id, "memory policy target id"));
    return (
      this.policies.get(id) ??
      defaultPolicy({
        target_type,
        target_id: target_id ?? thread_id ?? agent?.id,
        agent,
        thread_id,
        workspace,
      })
    );
  }

  setPolicy({ target_type = "thread", target_id, agent, thread_id, workspace, updates = {}, source = "memory_policy_api" } = {}) {
    void target_type;
    void target_id;
    void agent;
    void thread_id;
    void workspace;
    void updates;
    void source;
    throwAgentMemoryStoreRustCoreRequired({
      operation: "memory_policy",
      operation_kind: "memory.policy",
      evidence_ref: "agent_memory_store_policy_js_writer_retired",
    });
  }

  writePolicy(policy, { operation_kind = "memory.policy", receipt_refs = [] } = {}) {
    void receipt_refs;
    throwAgentMemoryStoreRustCoreRequired({
      operation: "memory_policy",
      operation_kind,
      memory_id: policy?.id ?? null,
      evidence_ref: "agent_memory_store_policy_js_writer_retired",
    });
  }

  commitMemoryState({ memory_state_kind, state_id, operation_kind, payload, receipt_refs = [] } = {}) {
    void memory_state_kind;
    void payload;
    void receipt_refs;
    throwAgentMemoryStoreRustCoreRequired({
      operation: "memory_state_commit",
      operation_kind: operation_kind ?? "memory.state_commit",
      memory_id: state_id,
      evidence_ref: "runtime_memory_state_store_js_mutation_retired",
    });
  }

  pathProjection({ agent, threadId, workspace } = {}) {
    return {
      schema_version: AGENT_MEMORY_SCHEMA_VERSION,
      object: "ioi.agent_memory_path_projection",
      thread_id: threadId ?? null,
      agent_id: agent?.id ?? null,
      workspace: workspace ?? agent?.cwd ?? null,
      records_path: this.memoryDir,
      policies_path: this.policyDir,
      effective_policy_id: policyId("thread", threadId ?? agent?.id ?? "runtime"),
    };
  }

}

export function parseMemoryCommand(prompt = "") {
  const text = String(prompt ?? "").trim();
  const remember = text.match(/^#\s*remember\s+([\s\S]+)$/i);
  if (remember?.[1]?.trim()) {
    return { kind: "remember", text: remember[1].trim() };
  }
  if (/^\/memory(?:\s+show)?\s*$/i.test(text)) {
    return { kind: "show" };
  }
  if (/^\/memory\s+disable\s*$/i.test(text)) {
    return { kind: "disable" };
  }
  if (/^\/memory\s+enable\s*$/i.test(text)) {
    return { kind: "enable" };
  }
  if (/^\/memory\s+path\s*$/i.test(text)) {
    return { kind: "path" };
  }
  const edit = text.match(/^\/memory\s+edit\s+(\S+)\s+([\s\S]+)$/i);
  if (edit?.[1] && edit?.[2]?.trim()) {
    return { kind: "edit", id: edit[1], text: edit[2].trim() };
  }
  const deletion = text.match(/^\/memory\s+(?:delete|remove|forget)\s+(\S+)\s*$/i);
  if (deletion?.[1]) {
    return { kind: "delete", id: deletion[1] };
  }
  return { kind: "none" };
}

export function defaultMemoryPolicy(overrides = {}) {
  return {
    schema_version: AGENT_MEMORY_POLICY_SCHEMA_VERSION,
    object: "ioi.agent_memory_policy",
    disabled: false,
    injection_enabled: true,
    read_only: false,
    write_requires_approval: false,
    retention: "persistent",
    redaction: "none",
    subagent_inheritance: "explicit",
    scope: "thread",
    ...policyFields(overrides),
  };
}

function requiredId(value, label) {
  const id = String(value ?? "").trim();
  if (!id) {
    const error = new Error(`${label} is required.`);
    error.status = 400;
    error.code = "validation";
    error.details = { field: label };
    throw error;
  }
  return id;
}

function optionalMemoryString(value) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}

function memoryListFilters({ scope, memory_key, query, limit, redaction } = {}) {
  return {
    scope: optionalMemoryString(scope),
    memory_key: optionalMemoryString(memory_key),
    query: optionalMemoryString(query)?.toLowerCase() ?? null,
    limit: normalizeMemoryLimit(limit),
    redaction: redaction === "redacted" ? "redacted" : "none",
  };
}

function normalizeMemoryLimit(value) {
  if (value === undefined || value === null || value === "") return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.min(Math.floor(parsed), 200);
}

function memoryRecordSearchText(record = {}) {
  return [
    record.fact,
    record.id,
    record.scope,
    record.memory_key,
    record.workflow_graph_id,
    record.workflow_node_id,
    record.workflow_node_type,
    record.source,
  ]
    .filter((value) => value !== undefined && value !== null)
    .map((value) => String(value).toLowerCase())
    .join("\n");
}

function redactMemoryRecord(record) {
  return {
    ...record,
    fact: "[REDACTED]",
    fact_hash: stableHash(record.fact ?? ""),
    redaction: "redacted",
  };
}

function stableHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function defaultPolicy({ target_type, target_id, agent, thread_id, workspace, now = new Date().toISOString() } = {}) {
  const resolvedTargetId = target_id ?? thread_id ?? agent?.id ?? "runtime";
  return {
    ...defaultMemoryPolicy(),
    id: policyId(target_type ?? "thread", resolvedTargetId),
    target_type: target_type ?? "thread",
    target_id: resolvedTargetId,
    agent_id: agent?.id ?? null,
    thread_id: thread_id ?? null,
    workspace: workspace ?? agent?.cwd ?? null,
    source: "default",
    created_at: now,
    updated_at: now,
    evidence_refs: ["agent_memory_store", "memory.policy.default"],
  };
}

function policyFields(value = {}) {
  const fields = {};
  for (const key of MEMORY_POLICY_FIELDS) {
    if (value?.[key] !== undefined) fields[key] = value[key];
  }
  return fields;
}

function policyId(targetType, targetId) {
  return `memory_policy_${targetType}_${safeFileId(targetId)}`;
}

function safeFileId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
