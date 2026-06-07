import fs from "node:fs";
import path from "node:path";

const RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION = "ioi.runtime_run_state_commit.v1";
const RUNTIME_AGENT_STATE_COMMIT_SCHEMA_VERSION = "ioi.runtime_agent_state_commit.v1";
const RUNTIME_SUBAGENT_STATE_COMMIT_SCHEMA_VERSION = "ioi.runtime_subagent_state_commit.v1";
const RUNTIME_STATE_STORAGE_BACKEND_REF = "storage://runtime-agentgres/local-json";

export function terminalEventCount(events = [], terminalEventTypes = new Set()) {
  return events.filter((event) => terminalEventTypes.has(event.type)).length;
}

export const RUNTIME_STATE_DIRS = [
  "agents",
  "runs",
  "tasks",
  "jobs",
  "checklists",
  "artifacts",
  "conversation-artifacts",
  "receipts",
  "quality",
  "policy-decisions",
  "authority-decisions",
  "stop-conditions",
  "scorecards",
  "ledgers",
  "projections",
  "model-artifacts",
  "model-endpoints",
  "model-instances",
  "model-routes",
  "model-providers",
  "model-downloads",
  "tokens",
  "mcp-servers",
  "memory-records",
  "memory-policies",
  "subagents",
  "events",
];

export function statePathFor(store, ...segments) {
  return path.join(store.stateDir, ...segments);
}

export function ensureStateDirs(store, dirs = RUNTIME_STATE_DIRS) {
  for (const dir of dirs) {
    fs.mkdirSync(statePathFor(store, dir), { recursive: true });
  }
}

export function writeStateSchema(store, deps = {}) {
  const { writeJson } = deps;
  writeJson(store.pathFor("schema.json"), {
    schemaVersion: store.schemaVersion,
    relationSchemas: {
      runs: ["id", "agentId", "status", "objective", "mode", "createdAt", "updatedAt"],
      tasks: ["runId", "currentObjective", "facts", "constraints", "evidenceRefs"],
      jobs: ["jobId", "taskId", "runId", "agentId", "status", "createdAt", "updatedAt"],
      checklists: ["checklistId", "taskId", "jobId", "runId", "status", "itemCount", "completedItemCount"],
      artifacts: ["id", "runId", "name", "mediaType", "redaction", "receiptId"],
      conversationArtifacts: ["id", "threadId", "artifactClass", "status", "latestRevisionId"],
      receipts: ["id", "runId", "kind", "summary", "redaction", "evidenceRefs"],
      memoryRecords: ["id", "scope", "threadId", "agentId", "workspace", "createdAt"],
      memoryPolicies: ["id", "targetType", "targetId", "disabled", "readOnly", "writeRequiresApproval", "updatedAt"],
      subagents: ["subagentId", "parentThreadId", "agentId", "role", "status", "runId", "updatedAt"],
      runtimeEvents: [
        "event_stream_id",
        "seq",
        "idempotency_key",
        "thread_id",
        "turn_id",
        "item_id",
        "event_kind",
        "created_at",
      ],
      quality: ["runId", "scorecard", "qualityLedger", "stopCondition"],
      ...store.modelMounting.writeSchemaRelationSchemas(),
    },
    canonicalOwner: "Agentgres",
    sdkCheckpointAuthority: "cache_only",
  });
}

export function loadStateRecords(store, deps = {}) {
  const {
    codingToolArtifactSchemaVersion,
    listJson,
    listJsonl,
    readJson,
    readJsonl,
  } = deps;
  for (const file of listJson(store.pathFor("agents"))) {
    const agent = readJson(file);
    store.agents.set(agent.id, agent);
  }
  for (const file of listJson(store.pathFor("runs"))) {
    const run = readJson(file);
    store.runs.set(run.id, run);
  }
  for (const file of listJson(store.pathFor("subagents"))) {
    const subagent = readJson(file);
    const subagentId = subagent.subagent_id ?? subagent.subagentId ?? subagent.agent_id ?? subagent.agentId;
    if (subagentId) store.subagents.set(String(subagentId), subagent);
  }
  for (const file of listJson(store.pathFor("artifacts"))) {
    const artifactRecord = readJson(file);
    const schemaVersion = artifactRecord.schema_version ?? artifactRecord.schemaVersion;
    if (schemaVersion === codingToolArtifactSchemaVersion && artifactRecord.id) {
      store.codingArtifacts.set(artifactRecord.id, artifactRecord);
    }
  }
  for (const file of listJsonl(store.pathFor("events"))) {
    for (const record of readJsonl(file)) {
      store.registerRuntimeEvent(record);
    }
  }
}

export function removeQuietFile(filePath) {
  try {
    fs.rmSync(filePath, { force: true });
  } catch {
    // Deleting a non-existent projection is not a state transition.
  }
}

function normalizeTransitionRef(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function commitRunState(store, run, operationKind) {
  if (typeof store.commitRuntimeRunState !== "function") {
    throw new Error("Run persistence requires Rust Agentgres run-state commit.");
  }
  const request = {
    schema_version: RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION,
    run_id: run.id,
    operation_kind: operationKind,
    storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
    run,
    agent: store.agents?.get?.(run.agentId) ?? null,
    canonical_projection: store.canonicalProjection(run.id),
  };
  return normalizeRunStateCommit(store.commitRuntimeRunState(request));
}

function normalizeRunStateCommit(commit) {
  const record = commit?.record && typeof commit.record === "object" ? commit.record : commit;
  const transition = commit?.transition && typeof commit.transition === "object"
    ? commit.transition
    : record?.transition;
  const persistence = commit?.persistence && typeof commit.persistence === "object"
    ? commit.persistence
    : record?.persistence;
  const materialization = persistence?.materialization;
  const storageWriteSet = persistence?.storage_write_set;
  const writtenRecords = Array.isArray(commit?.written_records) ? commit.written_records : [];
  const normalized = {
    source: normalizeTransitionRef(commit?.source) ?? "rust_agentgres_runtime_run_state_commit_command",
    operation_ref:
      normalizeTransitionRef(commit?.operation_ref) ??
      normalizeTransitionRef(transition?.operation_ref),
    state_root_after:
      normalizeTransitionRef(commit?.state_root_after) ??
      normalizeTransitionRef(transition?.state_root_after),
    resulting_head:
      normalizeTransitionRef(commit?.resulting_head) ??
      normalizeTransitionRef(transition?.resulting_head),
    transition_hash:
      normalizeTransitionRef(commit?.transition_hash) ??
      normalizeTransitionRef(transition?.transition_hash),
    materialization_hash:
      normalizeTransitionRef(commit?.materialization_hash) ??
      normalizeTransitionRef(materialization?.materialization_hash),
    write_set_hash:
      normalizeTransitionRef(commit?.write_set_hash) ??
      normalizeTransitionRef(storageWriteSet?.write_set_hash),
    persistence_hash:
      normalizeTransitionRef(commit?.persistence_hash) ??
      normalizeTransitionRef(persistence?.persistence_hash),
    commit_hash:
      normalizeTransitionRef(commit?.commit_hash) ??
      normalizeTransitionRef(record?.commit_hash),
    written_records: writtenRecords,
    evidence_refs: Array.isArray(commit?.evidence_refs) ? commit.evidence_refs : [],
    record: record ?? null,
  };
  const missing = [
    ["operation_ref", normalized.operation_ref],
    ["state_root_after", normalized.state_root_after],
    ["resulting_head", normalized.resulting_head],
    ["transition_hash", normalized.transition_hash],
    ["materialization_hash", normalized.materialization_hash],
    ["write_set_hash", normalized.write_set_hash],
    ["persistence_hash", normalized.persistence_hash],
    ["commit_hash", normalized.commit_hash],
    ["written_records", normalized.written_records.length > 0 ? normalized.written_records : null],
  ]
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`Rust Agentgres run-state commit is missing ${missing.join(", ")}.`);
  }
  return normalized;
}

function commitAgentState(store, agent, operationKind, agentId) {
  if (typeof store.commitRuntimeAgentState !== "function") {
    throw new Error("Agent persistence requires Rust Agentgres agent-state commit.");
  }
  const request = {
    schema_version: RUNTIME_AGENT_STATE_COMMIT_SCHEMA_VERSION,
    agent_id: agentId,
    operation_kind: operationKind,
    storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
    agent,
  };
  return normalizeAgentStateCommit(store.commitRuntimeAgentState(request));
}

function normalizeAgentStateCommit(commit) {
  const record = commit?.record && typeof commit.record === "object" ? commit.record : commit;
  const storageRecord = commit?.storage_record && typeof commit.storage_record === "object"
    ? commit.storage_record
    : record?.record;
  const normalized = {
    source: normalizeTransitionRef(commit?.source) ?? "rust_agentgres_runtime_agent_state_commit_command",
    agent_id:
      normalizeTransitionRef(commit?.agent_id) ??
      normalizeTransitionRef(record?.agent_id),
    object_ref:
      normalizeTransitionRef(commit?.object_ref) ??
      normalizeTransitionRef(storageRecord?.object_ref),
    content_hash:
      normalizeTransitionRef(commit?.content_hash) ??
      normalizeTransitionRef(storageRecord?.content_hash),
    admission_hash:
      normalizeTransitionRef(commit?.admission_hash) ??
      normalizeTransitionRef(storageRecord?.admission?.admission_hash),
    commit_hash:
      normalizeTransitionRef(commit?.commit_hash) ??
      normalizeTransitionRef(record?.commit_hash),
    written_record: commit?.written_record ?? null,
    evidence_refs: Array.isArray(commit?.evidence_refs) ? commit.evidence_refs : [],
    record: record ?? null,
  };
  const missing = [
    ["agent_id", normalized.agent_id],
    ["object_ref", normalized.object_ref],
    ["content_hash", normalized.content_hash],
    ["admission_hash", normalized.admission_hash],
    ["commit_hash", normalized.commit_hash],
    ["written_record", normalized.written_record],
  ]
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`Rust Agentgres agent-state commit is missing ${missing.join(", ")}.`);
  }
  return normalized;
}

function commitSubagentState(store, subagent, operationKind, subagentId) {
  if (typeof store.commitRuntimeSubagentState !== "function") {
    throw new Error("Subagent persistence requires Rust Agentgres subagent-state commit.");
  }
  const request = {
    schema_version: RUNTIME_SUBAGENT_STATE_COMMIT_SCHEMA_VERSION,
    subagent_id: subagentId,
    operation_kind: operationKind,
    storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
    subagent,
  };
  return normalizeSubagentStateCommit(store.commitRuntimeSubagentState(request));
}

function normalizeSubagentStateCommit(commit) {
  const record = commit?.record && typeof commit.record === "object" ? commit.record : commit;
  const storageRecord = commit?.storage_record && typeof commit.storage_record === "object"
    ? commit.storage_record
    : record?.record;
  const normalized = {
    source: normalizeTransitionRef(commit?.source) ?? "rust_agentgres_runtime_subagent_state_commit_command",
    subagent_id:
      normalizeTransitionRef(commit?.subagent_id) ??
      normalizeTransitionRef(record?.subagent_id),
    object_ref:
      normalizeTransitionRef(commit?.object_ref) ??
      normalizeTransitionRef(storageRecord?.object_ref),
    content_hash:
      normalizeTransitionRef(commit?.content_hash) ??
      normalizeTransitionRef(storageRecord?.content_hash),
    admission_hash:
      normalizeTransitionRef(commit?.admission_hash) ??
      normalizeTransitionRef(storageRecord?.admission?.admission_hash),
    commit_hash:
      normalizeTransitionRef(commit?.commit_hash) ??
      normalizeTransitionRef(record?.commit_hash),
    written_record: commit?.written_record ?? null,
    evidence_refs: Array.isArray(commit?.evidence_refs) ? commit.evidence_refs : [],
    record: record ?? null,
  };
  const missing = [
    ["subagent_id", normalized.subagent_id],
    ["object_ref", normalized.object_ref],
    ["content_hash", normalized.content_hash],
    ["admission_hash", normalized.admission_hash],
    ["commit_hash", normalized.commit_hash],
    ["written_record", normalized.written_record],
  ]
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`Rust Agentgres subagent-state commit is missing ${missing.join(", ")}.`);
  }
  return normalized;
}

export function writeAgentRecord(store, agent, operationKind, deps = {}) {
  const { runtimeError } = deps;
  const agentId = agent.id;
  if (!agentId) {
    const errorFactory = typeof runtimeError === "function"
      ? runtimeError
      : ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details });
    throw errorFactory({
      status: 500,
      code: "agent_id_required",
      message: "Agent records require a stable id before persistence.",
      details: { operation_kind: operationKind },
    });
  }
  store.agents?.set?.(String(agentId), agent);
  return commitAgentState(store, agent, operationKind, String(agentId));
}

export function writeSubagentRecord(store, subagent, operationKind, deps = {}) {
  const { runtimeError } = deps;
  const subagentId = subagent.subagent_id;
  if (!subagentId) {
    const errorFactory = typeof runtimeError === "function"
      ? runtimeError
      : ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details });
    throw errorFactory({
      status: 500,
      code: "subagent_id_required",
      message: "Subagent records require a stable id before persistence.",
      details: { operation_kind: operationKind },
    });
  }
  store.subagents.set(String(subagentId), subagent);
  return commitSubagentState(store, subagent, operationKind, String(subagentId));
}

export function writeRunRecord(store, run, operationKind, deps = {}) {
  return commitRunState(store, run, operationKind);
}
