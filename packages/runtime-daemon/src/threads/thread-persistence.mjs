import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export function terminalEventCount(events = [], terminalEventTypes = new Set()) {
  return events.filter((event) => terminalEventTypes.has(event.type)).length;
}

export function statePathFor(store, ...segments) {
  return path.join(store.stateDir, ...segments);
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
