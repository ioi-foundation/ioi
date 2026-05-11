import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const AGENT_MEMORY_SCHEMA_VERSION = "ioi.agent-runtime.memory.v1";

export class AgentMemoryStore {
  constructor(stateDir, { appendOperation } = {}) {
    this.stateDir = path.resolve(stateDir);
    this.records = new Map();
    this.appendOperation = appendOperation;
    fs.mkdirSync(this.memoryDir, { recursive: true });
    this.load();
  }

  get memoryDir() {
    return path.join(this.stateDir, "memory-records");
  }

  load() {
    if (!fs.existsSync(this.memoryDir)) return;
    for (const entry of fs.readdirSync(this.memoryDir)) {
      if (!entry.endsWith(".json")) continue;
      const record = JSON.parse(fs.readFileSync(path.join(this.memoryDir, entry), "utf8"));
      if (typeof record.id === "string") this.records.set(record.id, record);
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
    this.appendOperation?.("memory.remember", {
      objectId: id,
      agentId: agent?.id ?? null,
      threadId: threadId ?? null,
      scope,
      receiptId: receipt.id,
      factHash: stableHash(fact),
    });
    return { record, receipt };
  }

  list({ agent, threadId, workspace, includeGlobal = true } = {}) {
    return [...this.records.values()]
      .filter((record) => {
        if (includeGlobal && record.scope === "global") return true;
        if (threadId && record.threadId === threadId) return true;
        if (agent?.id && record.agentId === agent.id && record.scope !== "thread") return true;
        if (workspace && record.workspace === workspace && record.scope === "workspace") return true;
        return false;
      })
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  write(record) {
    fs.mkdirSync(this.memoryDir, { recursive: true });
    fs.writeFileSync(path.join(this.memoryDir, `${record.id}.json`), `${JSON.stringify(record, null, 2)}\n`);
  }

  projection({ agent, threadId, workspace } = {}) {
    return {
      schemaVersion: AGENT_MEMORY_SCHEMA_VERSION,
      object: "ioi.agent_memory_projection",
      threadId: threadId ?? null,
      agentId: agent?.id ?? null,
      workspace: workspace ?? agent?.cwd ?? null,
      records: this.list({ agent, threadId, workspace: workspace ?? agent?.cwd }),
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
  return { kind: "none" };
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

function stableHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}
