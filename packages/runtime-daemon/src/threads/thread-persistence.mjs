import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const RUNTIME_STATE_TRANSITION_SCHEMA_VERSION = "ioi.agentgres_runtime_state_transition.v1";

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

function runStateProjectionWatermark(store, run) {
  const runCount = store.runs instanceof Map ? store.runs.size : 0;
  return Math.max(runCount, run?.id ? 1 : 0);
}

function runStateHash(value) {
  return `sha256:${crypto.createHash("sha256").update(stableJson(value)).digest("hex")}`;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map((entry) => stableJson(entry)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

function initialRunStateHead(runId) {
  return `agentgres://runtime-state/runs/${safeAgentgresComponent(runId)}/head/0`;
}

function initialRunStateRoot(runId) {
  return runStateHash({
    schema: "ioi.agentgres.runtime_state_root.v1",
    runId,
    sequence: 0,
  });
}

function safeAgentgresComponent(value) {
  const safe = String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
  return safe || "runtime";
}

function previousRunStateTransition(store, runId) {
  const current = typeof store.currentRunStateTransition === "function"
    ? store.currentRunStateTransition(runId)
    : null;
  return current && typeof current === "object" && !Array.isArray(current) ? current : null;
}

function normalizeTransitionRef(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function planRunStateTransition(store, run, operationKind, {
  runtimeTask,
  runtimeJob,
  runtimeChecklist,
  terminalEventTypes,
}) {
  const previous = previousRunStateTransition(store, run.id);
  const expectedHead =
    normalizeTransitionRef(previous?.resulting_head) ??
    normalizeTransitionRef(previous?.resultingHead) ??
    initialRunStateHead(run.id);
  const stateRootBefore =
    normalizeTransitionRef(previous?.state_root_after) ??
    normalizeTransitionRef(previous?.stateRootAfter) ??
    initialRunStateRoot(run.id);
  const projectionWatermark = `runtime-state:${runStateProjectionWatermark(store, run)}`;
  const request = {
    schema_version: RUNTIME_STATE_TRANSITION_SCHEMA_VERSION,
    run_id: run.id,
    operation_kind: operationKind,
    expected_heads: [expectedHead],
    state_root_before: stateRootBefore,
    run_state_hash: runStateHash({
      id: run.id,
      agentId: run.agentId,
      status: run.status,
      mode: run.mode,
      createdAt: run.createdAt,
      updatedAt: run.updatedAt,
      eventCount: run.events.length,
      terminalEventCount: terminalEventCount(run.events, terminalEventTypes),
      traceBundleId: run.trace.traceBundleId,
    }),
    task_state_hash: runStateHash({
      runtimeTask,
      runtimeJob,
      runtimeChecklist,
      taskState: run.trace.taskState,
      postconditions: run.trace.postconditions,
      semanticImpact: run.trace.semanticImpact,
      stopCondition: run.trace.stopCondition,
      scorecard: run.trace.scorecard,
      qualityLedger: run.trace.qualityLedger,
    }),
    projection_ref: `projection://runtime/runs/${safeAgentgresComponent(run.id)}`,
    projection_watermark: projectionWatermark,
    receipt_refs: run.receipts.map((receipt) => receipt.id).filter(Boolean),
    artifact_refs: run.artifacts.map((artifact) => artifact.id).filter(Boolean),
    payload_refs: [`payload://runtime/runs/${safeAgentgresComponent(run.id)}`],
  };
  if (typeof store.planRunStateTransition !== "function") {
    throw new Error("Run persistence requires Rust Agentgres state transition planning.");
  }
  const transition = store.planRunStateTransition(request);
  return normalizeRunStateTransition(transition);
}

function normalizeRunStateTransition(transition) {
  const record = transition?.record && typeof transition.record === "object" ? transition.record : transition;
  const normalized = {
    schema_version: record?.schema_version ?? RUNTIME_STATE_TRANSITION_SCHEMA_VERSION,
    operation_ref: normalizeTransitionRef(transition?.operation_ref) ?? normalizeTransitionRef(record?.operation_ref),
    expected_heads: Array.isArray(transition?.expected_heads)
      ? transition.expected_heads
      : Array.isArray(record?.expected_heads)
        ? record.expected_heads
        : [],
    state_root_before:
      normalizeTransitionRef(transition?.state_root_before) ?? normalizeTransitionRef(record?.state_root_before),
    state_root_after:
      normalizeTransitionRef(transition?.state_root_after) ?? normalizeTransitionRef(record?.state_root_after),
    resulting_head: normalizeTransitionRef(transition?.resulting_head) ?? normalizeTransitionRef(record?.resulting_head),
    projection_watermark:
      normalizeTransitionRef(transition?.projection_watermark) ?? normalizeTransitionRef(record?.projection_watermark),
    transition_hash: normalizeTransitionRef(transition?.transition_hash) ?? normalizeTransitionRef(record?.transition_hash),
    evidence_refs: Array.isArray(transition?.evidence_refs) ? transition.evidence_refs : [],
    record: record ?? null,
  };
  const missing = [
    ["operation_ref", normalized.operation_ref],
    ["expected_heads", normalized.expected_heads.length > 0 ? normalized.expected_heads : null],
    ["state_root_before", normalized.state_root_before],
    ["state_root_after", normalized.state_root_after],
    ["resulting_head", normalized.resulting_head],
    ["projection_watermark", normalized.projection_watermark],
    ["transition_hash", normalized.transition_hash],
  ]
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`Rust Agentgres run-state transition is missing ${missing.join(", ")}.`);
  }
  return normalized;
}

export function writeAgentRecord(store, agent, operationKind, deps = {}) {
  const { writeJson } = deps;
  writeJson(store.pathFor("agents", `${agent.id}.json`), agent);
}

export function writeSubagentRecord(store, subagent, operationKind, deps = {}) {
  const { runtimeError, writeJson } = deps;
  const subagentId = subagent.subagent_id ?? subagent.subagentId ?? subagent.agent_id ?? subagent.agentId;
  if (!subagentId) {
    const errorFactory = typeof runtimeError === "function"
      ? runtimeError
      : ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details });
    throw errorFactory({
      status: 500,
      code: "subagent_id_required",
      message: "Subagent records require a stable id before persistence.",
      details: { operationKind },
    });
  }
  store.subagents.set(String(subagentId), subagent);
  writeJson(store.pathFor("subagents", `${subagentId}.json`), subagent);
}

export function writeRunRecord(store, run, operationKind, deps = {}) {
  const {
    runtimeChecklistRecordForRun,
    runtimeJobRecordForRun,
    runtimeTaskRecordForRun,
    terminalEventTypes,
    writeJson,
  } = deps;
  const runtimeTask = runtimeTaskRecordForRun(run);
  const runtimeJob = runtimeJobRecordForRun(run);
  const runtimeChecklist = runtimeChecklistRecordForRun(run);
  const agentgresTransition = planRunStateTransition(store, run, operationKind, {
    runtimeTask,
    runtimeJob,
    runtimeChecklist,
    terminalEventTypes,
  });
  writeJson(store.pathFor("runs", `${run.id}.json`), run);
  writeJson(store.pathFor("tasks", `${run.id}.json`), {
    runId: run.id,
    agentId: run.agentId,
    runtimeTask,
    runtimeChecklist,
    taskState: run.trace.taskState,
    postconditions: run.trace.postconditions,
    semanticImpact: run.trace.semanticImpact,
    projectionWatermark: agentgresTransition.projection_watermark,
    agentgresTransition,
  });
  writeJson(store.pathFor("jobs", `${runtimeJob.jobId}.json`), runtimeJob);
  writeJson(store.pathFor("checklists", `${runtimeChecklist.checklistId}.json`), runtimeChecklist);
  for (const receipt of run.receipts) {
    writeJson(store.pathFor("receipts", `${receipt.id}.json`), { runId: run.id, ...receipt });
  }
  for (const artifact of run.artifacts) {
    writeJson(store.pathFor("artifacts", `${artifact.id}.json`), artifact);
  }
  writeJson(store.pathFor("policy-decisions", `${run.id}.json`), {
    runId: run.id,
    decision: "allowed",
    rationale: "Local daemon run stayed inside bounded local/private runtime contract.",
    primitiveCapabilities: ["prim:model.invoke"],
    authorityScopes: [],
    receiptId: run.receipts.find((receipt) => receipt.kind === "policy_decision")?.id,
  });
  writeJson(store.pathFor("authority-decisions", `${run.id}.json`), {
    runId: run.id,
    decision: "allowed",
    authorityScopes: [],
    walletLayer: "wallet.network",
    receiptId: run.receipts.find((receipt) => receipt.kind === "authority_decision")?.id,
  });
  writeJson(store.pathFor("stop-conditions", `${run.id}.json`), run.trace.stopCondition);
  writeJson(store.pathFor("scorecards", `${run.id}.json`), run.trace.scorecard);
  writeJson(store.pathFor("ledgers", `${run.id}.json`), run.trace.qualityLedger);
  writeJson(store.pathFor("quality", `${run.id}.json`), {
    runId: run.id,
    scorecard: run.trace.scorecard,
    qualityLedger: run.trace.qualityLedger,
    stopCondition: run.trace.stopCondition,
    verifierIndependencePolicy: {
      sameModelAllowed: false,
      evidenceOnlyMode: true,
      humanReviewThreshold: "high_risk",
    },
  });
  writeJson(store.pathFor("projections", `${run.id}.json`), {
    ...store.canonicalProjection(run.id),
    agentgresTransition,
  });
}
