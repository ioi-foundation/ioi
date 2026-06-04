import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const AGENT_MEMORY_SCHEMA_VERSION = "ioi.agent-runtime.memory.v1";
export const AGENT_MEMORY_POLICY_SCHEMA_VERSION = "ioi.agent-runtime.memory-policy.v1";

const MEMORY_POLICY_FIELDS = [
  "disabled",
  "injectionEnabled",
  "readOnly",
  "writeRequiresApproval",
  "retention",
  "redaction",
  "subagentInheritance",
  "scope",
];

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
    const fact = requiredMemoryText(text);
    const now = new Date().toISOString();
    const id = `memory_${crypto.randomUUID()}`;
    const record = {
      schemaVersion: AGENT_MEMORY_SCHEMA_VERSION,
      id,
      object: "ioi.agent_memory_record",
      scope,
      fact,
      memoryKey: optionalMemoryString(workflow.memoryKey ?? workflow.memory_key ?? workflow.stateKey ?? workflow.state_key),
      agentId: agent?.id ?? null,
      threadId: threadId ?? null,
      workspace: agent?.cwd ?? null,
      workflowGraphId: workflow.workflowGraphId ?? workflow.workflow_graph_id ?? null,
      workflowNodeId: workflow.workflowNodeId ?? workflow.workflow_node_id ?? "runtime.memory",
      workflowNodeType: workflow.workflowNodeType ?? workflow.workflow_node_type ?? "Memory",
      source,
      redaction: "none",
      createdAt: now,
      updatedAt: now,
      evidenceRefs: ["agent_memory_store", "memory.write", threadId, agent?.id].filter(Boolean),
    };
    const receipt = {
      id: `receipt_${id}_write`,
      kind: "memory_write",
      summary: `Remembered ${scope} memory for ${threadId ?? agent?.id ?? "runtime"}.`,
      redaction: "none",
      evidenceRefs: ["agent_memory_store", "memory.write", id],
      memoryRecordId: id,
    };
    this.records.set(id, record);
    this.write(record);
    return { record, receipt };
  }

  updateRecord({ id, text, source = "memory_edit_api" } = {}) {
    const record = this.records.get(requiredId(id, "memory record id"));
    if (!record) {
      const error = new Error(`Memory record not found: ${id}`);
      error.status = 404;
      error.code = "not_found";
      error.details = { id };
      throw error;
    }
    const updated = {
      ...record,
      fact: requiredMemoryText(text),
      source,
      updatedAt: new Date().toISOString(),
      evidenceRefs: [...new Set([...normalizeArray(record.evidenceRefs), "memory.edit"])],
    };
    const receipt = memoryReceipt(updated, {
      kind: "memory_edit",
      operation: "edit",
      summary: `Edited memory record ${updated.id}.`,
    });
    this.records.set(updated.id, updated);
    this.write(updated);
    return { record: updated, receipt, operation: "edit" };
  }

  deleteRecord({ id, source = "memory_delete_api" } = {}) {
    const record = this.records.get(requiredId(id, "memory record id"));
    if (!record) {
      const error = new Error(`Memory record not found: ${id}`);
      error.status = 404;
      error.code = "not_found";
      error.details = { id };
      throw error;
    }
    const deleted = {
      ...record,
      source,
      deletedAt: new Date().toISOString(),
      evidenceRefs: [...new Set([...normalizeArray(record.evidenceRefs), "memory.delete"])],
    };
    const receipt = memoryReceipt(deleted, {
      kind: "memory_delete",
      operation: "delete",
      summary: `Deleted memory record ${deleted.id}.`,
    });
    this.records.delete(record.id);
    this.removeQuiet(path.join(this.memoryDir, `${record.id}.json`));
    return { record: deleted, receipt, operation: "delete" };
  }

  list({ agent, threadId, workspace, includeGlobal = true, scope, memoryKey, query, q, limit, redaction } = {}) {
    const filters = memoryListFilters({ scope, memoryKey, query, q, limit, redaction });
    const records = [...this.records.values()]
      .filter((record) => {
        if (includeGlobal && record.scope === "global") return true;
        if (threadId && record.threadId === threadId) return true;
        if (agent?.id && record.agentId === agent.id && record.scope !== "thread") return true;
        if (workspace && record.workspace === workspace && record.scope === "workspace") return true;
        return false;
      })
      .filter((record) => !filters.scope || record.scope === filters.scope)
      .filter((record) => !filters.memoryKey || record.memoryKey === filters.memoryKey)
      .filter((record) => !filters.query || memoryRecordSearchText(record).includes(filters.query))
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    const limited = filters.limit ? records.slice(0, filters.limit) : records;
    return filters.redaction === "redacted" ? limited.map(redactMemoryRecord) : limited;
  }

  write(record) {
    fs.mkdirSync(this.memoryDir, { recursive: true });
    fs.writeFileSync(path.join(this.memoryDir, `${record.id}.json`), `${JSON.stringify(record, null, 2)}\n`);
  }

  projection({ agent, threadId, workspace, filters = {} } = {}) {
    const records = this.list({ agent, threadId, workspace: workspace ?? agent?.cwd, ...filters });
    const normalizedFilters = memoryListFilters(filters);
    return {
      schemaVersion: AGENT_MEMORY_SCHEMA_VERSION,
      object: "ioi.agent_memory_projection",
      threadId: threadId ?? null,
      agentId: agent?.id ?? null,
      workspace: workspace ?? agent?.cwd ?? null,
      policy: this.effectivePolicy({ agent, threadId, workspace: workspace ?? agent?.cwd }),
      paths: this.pathProjection({ agent, threadId, workspace: workspace ?? agent?.cwd }),
      filters: normalizedFilters,
      records,
      totalMatches: records.length,
    };
  }

  effectivePolicy({ agent, threadId, workspace, overrides = {} } = {}) {
    const agentPolicy = agent?.id ? this.policies.get(policyId("agent", agent.id)) : null;
    const threadPolicy = threadId ? this.policies.get(policyId("thread", threadId)) : null;
    const now = new Date().toISOString();
    return {
      ...defaultPolicy({
        targetType: "thread",
        targetId: threadId ?? agent?.id ?? "runtime",
        agent,
        threadId,
        workspace,
        now,
      }),
      ...policyFields(agentPolicy),
      ...policyFields(threadPolicy),
      ...policyFields(overrides),
      id: policyId("thread", threadId ?? agent?.id ?? "runtime"),
      targetType: "thread",
      targetId: threadId ?? agent?.id ?? "runtime",
      agentId: agent?.id ?? null,
      threadId: threadId ?? null,
      workspace: workspace ?? agent?.cwd ?? null,
      effective: true,
      policyRefs: [agentPolicy?.id, threadPolicy?.id].filter(Boolean),
    };
  }

  getPolicy({ targetType = "thread", targetId, agent, threadId, workspace } = {}) {
    const id = policyId(targetType, requiredId(targetId ?? threadId ?? agent?.id, "memory policy target id"));
    return (
      this.policies.get(id) ??
      defaultPolicy({
        targetType,
        targetId: targetId ?? threadId ?? agent?.id,
        agent,
        threadId,
        workspace,
      })
    );
  }

  setPolicy({ targetType = "thread", targetId, agent, threadId, workspace, updates = {}, source = "memory_policy_api" } = {}) {
    const resolvedTargetId = requiredId(targetId ?? threadId ?? agent?.id, "memory policy target id");
    const now = new Date().toISOString();
    const id = policyId(targetType, resolvedTargetId);
    const previous =
      this.policies.get(id) ??
      defaultPolicy({
        targetType,
        targetId: resolvedTargetId,
        agent,
        threadId,
        workspace,
        now,
      });
    const policy = {
      ...previous,
      ...policyFields(updates),
      schemaVersion: AGENT_MEMORY_POLICY_SCHEMA_VERSION,
      id,
      object: "ioi.agent_memory_policy",
      targetType,
      targetId: resolvedTargetId,
      agentId: agent?.id ?? previous.agentId ?? null,
      threadId: threadId ?? previous.threadId ?? null,
      workspace: workspace ?? agent?.cwd ?? previous.workspace ?? null,
      source,
      updatedAt: now,
      evidenceRefs: [...new Set([...normalizeArray(previous.evidenceRefs), "memory.policy"])],
    };
    this.policies.set(id, policy);
    this.writePolicy(policy);
    const receipt = {
      id: `receipt_${id}_${stableHash(`${policy.updatedAt}:${source}`).slice(0, 12)}`,
      kind: "memory_policy",
      summary: `Updated ${targetType} memory policy for ${resolvedTargetId}.`,
      redaction: "none",
      evidenceRefs: ["agent_memory_store", "memory.policy", id],
      memoryPolicyId: id,
    };
    return { policy, receipt, operation: "policy_update" };
  }

  writePolicy(policy) {
    fs.mkdirSync(this.policyDir, { recursive: true });
    fs.writeFileSync(path.join(this.policyDir, `${safeFileId(policy.id)}.json`), `${JSON.stringify(policy, null, 2)}\n`);
  }

  pathProjection({ agent, threadId, workspace } = {}) {
    return {
      schemaVersion: AGENT_MEMORY_SCHEMA_VERSION,
      object: "ioi.agent_memory_path_projection",
      threadId: threadId ?? null,
      agentId: agent?.id ?? null,
      workspace: workspace ?? agent?.cwd ?? null,
      recordsPath: this.memoryDir,
      policiesPath: this.policyDir,
      effectivePolicyId: policyId("thread", threadId ?? agent?.id ?? "runtime"),
    };
  }

  removeQuiet(filePath) {
    try {
      fs.rmSync(filePath, { force: true });
    } catch {
      // Best-effort cleanup; canonical state is the in-memory map plus operation log.
    }
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
    schemaVersion: AGENT_MEMORY_POLICY_SCHEMA_VERSION,
    object: "ioi.agent_memory_policy",
    disabled: false,
    injectionEnabled: true,
    readOnly: false,
    writeRequiresApproval: false,
    retention: "persistent",
    redaction: "none",
    subagentInheritance: "explicit",
    scope: "thread",
    ...policyFields(overrides),
  };
}

function requiredMemoryText(value) {
  const text = String(value ?? "").trim();
  if (!text) {
    const error = new Error("Memory text is required.");
    error.status = 400;
    error.code = "validation";
    error.details = { field: "text" };
    throw error;
  }
  return text;
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

function memoryListFilters({ scope, memoryKey, query, q, limit, redaction } = {}) {
  return {
    scope: optionalMemoryString(scope),
    memoryKey: optionalMemoryString(memoryKey),
    query: optionalMemoryString(query ?? q)?.toLowerCase() ?? null,
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
    record.memoryKey,
    record.workflowGraphId,
    record.workflowNodeId,
    record.workflowNodeType,
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
    factHash: stableHash(record.fact ?? ""),
    redaction: "redacted",
  };
}

function stableHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function defaultPolicy({ targetType, targetId, agent, threadId, workspace, now = new Date().toISOString() } = {}) {
  const resolvedTargetId = targetId ?? threadId ?? agent?.id ?? "runtime";
  return {
    ...defaultMemoryPolicy(),
    id: policyId(targetType ?? "thread", resolvedTargetId),
    targetType: targetType ?? "thread",
    targetId: resolvedTargetId,
    agentId: agent?.id ?? null,
    threadId: threadId ?? null,
    workspace: workspace ?? agent?.cwd ?? null,
    source: "default",
    createdAt: now,
    updatedAt: now,
    evidenceRefs: ["agent_memory_store", "memory.policy.default"],
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

function memoryReceipt(record, { kind, operation, summary } = {}) {
  return {
    id: `receipt_${record.id}_${operation ?? kind ?? "memory"}`,
    kind,
    summary,
    redaction: record.redaction ?? "none",
    evidenceRefs: ["agent_memory_store", `memory.${operation ?? kind}`, record.id],
    memoryRecordId: record.id,
  };
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}
