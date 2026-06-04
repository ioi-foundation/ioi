import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

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
      operationLog: ["sequence", "operationId", "kind", "objectId", "createdAt", "digest"],
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

export function operationCountRecord(store) {
  const logPath = statePathFor(store, "operation-log.jsonl");
  if (!fs.existsSync(logPath)) return 0;
  const text = fs.readFileSync(logPath, "utf8").trim();
  return text ? text.split(/\n/).length : 0;
}

export function appendOperationRecord(store, kind, payload) {
  const sequence = operationCountRecord(store) + 1;
  const operation = {
    sequence,
    operationId: `op_${String(sequence).padStart(8, "0")}_${kind.replace(/[^a-z0-9]+/gi, "_")}`,
    kind,
    objectId: payload.objectId ?? payload.agentId ?? payload.runId ?? null,
    createdAt: new Date().toISOString(),
    payload,
  };
  const digest = crypto.createHash("sha256").update(JSON.stringify(operation)).digest("hex");
  const record = { ...operation, digest };
  fs.mkdirSync(store.stateDir, { recursive: true });
  fs.appendFileSync(statePathFor(store, "operation-log.jsonl"), `${JSON.stringify(record)}\n`);
  return record;
}

export function removeQuietFile(filePath) {
  try {
    fs.rmSync(filePath, { force: true });
  } catch {
    // Deleting a non-existent projection is not a state transition.
  }
}

export function writeAgentRecord(store, agent, operationKind, deps = {}) {
  const { writeJson } = deps;
  writeJson(store.pathFor("agents", `${agent.id}.json`), agent);
  store.appendOperation(operationKind, { objectId: agent.id, agent });
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
  store.appendOperation(operationKind, {
    objectId: subagentId,
    subagentId,
    parentThreadId: subagent.parent_thread_id ?? subagent.parentThreadId ?? null,
    agentId: subagent.agent_id ?? subagent.agentId ?? null,
    status: subagent.status ?? subagent.lifecycle_status ?? null,
    role: subagent.role ?? null,
  });
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
  writeJson(store.pathFor("runs", `${run.id}.json`), run);
  writeJson(store.pathFor("tasks", `${run.id}.json`), {
    runId: run.id,
    agentId: run.agentId,
    runtimeTask,
    runtimeChecklist,
    taskState: run.trace.taskState,
    postconditions: run.trace.postconditions,
    semanticImpact: run.trace.semanticImpact,
    projectionWatermark: store.operationCount() + 1,
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
  writeJson(store.pathFor("projections", `${run.id}.json`), store.canonicalProjection(run.id));
  store.appendOperation(operationKind, {
    objectId: run.id,
    runId: run.id,
    agentId: run.agentId,
    status: run.status,
    eventCount: run.events.length,
    terminalEventCount: terminalEventCount(run.events, terminalEventTypes),
    traceBundleId: run.trace.traceBundleId,
  });
}
