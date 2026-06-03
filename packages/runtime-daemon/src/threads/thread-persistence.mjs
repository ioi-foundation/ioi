export function terminalEventCount(events = [], terminalEventTypes = new Set()) {
  return events.filter((event) => terminalEventTypes.has(event.type)).length;
}

export function writeAgentRecord(store, agent, operationKind, deps = {}) {
  const { writeJson } = deps;
  writeJson(store.pathFor("agents", `${agent.id}.json`), agent);
  store.appendOperation(operationKind, { objectId: agent.id, agent });
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
