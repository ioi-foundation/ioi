export function cancelRun(state, runId, deps) {
  const {
    JOB_TERMINAL_EVENT_TYPES,
    TERMINAL_EVENT_TYPES,
    artifact,
    attachChecklistToRuntimeJob,
    makeEvent,
    normalizeArray,
    runtimeChecklistRecord,
    runtimeJobRecord,
    runtimeTaskRecord,
    strategyForMode,
    taskFamilyForMode,
  } = deps;
  const run = state.getRun(runId);
  const status = run.status === "canceled" ? "canceled" : "canceled";
  const updatedAt = new Date().toISOString();
  const nonTerminalEvents = run.events.filter(
    (event) => !TERMINAL_EVENT_TYPES.has(event.type) && !JOB_TERMINAL_EVENT_TYPES.has(event.type),
  );
  const hasRuntimeTaskEvent = nonTerminalEvents.some((event) => event.type === "runtime_task");
  const hasRuntimeChecklistEvent = nonTerminalEvents.some((event) => event.type === "runtime_checklist");
  const finalEventCount =
    nonTerminalEvents.length + (hasRuntimeTaskEvent ? 0 : 1) + (hasRuntimeChecklistEvent ? 0 : 1) + 2;
  const stopCondition = {
    reason: "marginal_improvement_too_low",
    evidenceSufficient: true,
    rationale:
      "Cancellation became the single terminal event and replay cursor continuity was preserved.",
  };
  const runtimeTask = runtimeTaskRecord({
    runId: run.id,
    agent: { id: run.agentId },
    prompt: run.objective,
    mode: run.mode,
    taskFamily: run.trace?.qualityLedger?.taskFamily ?? taskFamilyForMode(run.mode ?? "send"),
    selectedStrategy: run.trace?.qualityLedger?.selectedStrategy ?? strategyForMode(run.mode ?? "send"),
    modelRouteDecision: run.modelRouteDecision ?? run.trace?.modelRouteDecision,
    activeSkillHookManifest: run.activeSkillHookManifest ?? run.trace?.activeSkillHookManifest,
    createdAt: run.createdAt,
    updatedAt,
    status,
  });
  let runtimeJob = runtimeJobRecord({
    runtimeTask,
    status,
    createdAt: run.createdAt,
    updatedAt,
    queuedAt: run.runtimeJob?.queuedAt ?? run.createdAt,
    startedAt: run.runtimeJob?.startedAt ?? run.createdAt,
    completedAt: updatedAt,
    lifecycle: ["queued", "started", "canceled"],
    eventCount: finalEventCount,
    terminalEventCount: 1,
    artifactNames: normalizeArray(run.artifacts).map((artifactItem) => artifactItem.name).filter(Boolean),
    receiptKinds: normalizeArray(run.receipts).map((receipt) => receipt.kind).filter(Boolean),
  });
  const runtimeChecklist = runtimeChecklistRecord({
    runtimeTask,
    runtimeJob,
    status,
    createdAt: run.createdAt,
    updatedAt,
  });
  runtimeJob = attachChecklistToRuntimeJob(runtimeJob, runtimeChecklist);
  const canceledEvents = nonTerminalEvents.map((event) => {
    if (event.type === "runtime_task") {
      return {
        ...event,
        data: {
          ...runtimeTask,
          receiptId: `receipt_${run.id}_runtime_task`,
          eventKind: "RuntimeTaskRecord",
          workflowNodeId: "runtime.runtime-task",
        },
      };
    }
    if (event.type === "runtime_checklist") {
      return {
        ...event,
        data: {
          ...runtimeChecklist,
          receiptId: `receipt_${run.id}_runtime_checklist`,
          eventKind: "RuntimeChecklistRecord",
          workflowNodeId: "runtime.runtime-checklist",
        },
      };
    }
    return event;
  });
  if (!canceledEvents.some((event) => event.type === "runtime_task")) {
    canceledEvents.push(
      makeEvent(run.id, run.agentId, canceledEvents.length, "runtime_task", "Runtime task record written", {
        ...runtimeTask,
        receiptId: `receipt_${run.id}_runtime_task`,
        eventKind: "RuntimeTaskRecord",
        workflowNodeId: "runtime.runtime-task",
      }),
    );
  }
  if (!canceledEvents.some((event) => event.type === "runtime_checklist")) {
    canceledEvents.push(
      makeEvent(run.id, run.agentId, canceledEvents.length, "runtime_checklist", "Runtime checklist recorded", {
        ...runtimeChecklist,
        receiptId: `receipt_${run.id}_runtime_checklist`,
        eventKind: "RuntimeChecklistRecord",
        workflowNodeId: "runtime.runtime-checklist",
      }),
    );
  }
  const jobCanceled = makeEvent(
    run.id,
    run.agentId,
    canceledEvents.length,
    "job_canceled",
    "Runtime job canceled",
    {
      ...runtimeJob,
      lifecycleStatus: "canceled",
      receiptId: `receipt_${run.id}_runtime_job`,
      eventKind: "JobCanceled",
      workflowNodeId: "runtime.runtime-job",
    },
  );
  canceledEvents.push(jobCanceled);
  const canceled = makeEvent(
    run.id,
    run.agentId,
    canceledEvents.length,
    "canceled",
    "Run canceled",
    { reason: "operator_cancel", priorStatus: run.status },
  );
  canceledEvents.push(canceled);
  const runtimeChecklistReceipt = {
    id: `receipt_${run.id}_runtime_checklist`,
    kind: "runtime_checklist",
    summary: runtimeChecklist.summary,
    redaction: "redacted",
    evidenceRefs: [
      runtimeChecklist.checklistId,
      runtimeTask.taskId,
      runtimeJob.jobId,
      "RuntimeChecklistNode",
      "runtime.checklists.durable_projection",
    ].filter(Boolean),
  };
  const receipts = normalizeArray(run.receipts).map((receipt) =>
    receipt.id === runtimeChecklistReceipt.id ? runtimeChecklistReceipt : receipt,
  );
  if (!receipts.some((receipt) => receipt.id === runtimeChecklistReceipt.id)) {
    receipts.push(runtimeChecklistReceipt);
  }
  const trace = {
    ...run.trace,
    events: canceledEvents,
    receipts,
    runtimeTask,
    runtimeJob,
    runtimeChecklist,
    stopCondition,
    qualityLedger: {
      ...run.trace.qualityLedger,
      failureOntologyLabels: [
        ...new Set([...run.trace.qualityLedger.failureOntologyLabels, "operator_cancel"]),
      ],
    },
  };
  const artifacts = normalizeArray(run.artifacts).map((item) => {
    if (item.name === "runtime-task.json") return { ...item, content: runtimeTask };
    if (item.name === "runtime-job.json") return { ...item, content: runtimeJob };
    if (item.name === "runtime-checklist.json") return { ...item, content: runtimeChecklist };
    return item;
  });
  if (!artifacts.some((item) => item.name === "runtime-checklist.json")) {
    artifacts.push(
      artifact(
        run.id,
        "runtime-checklist.json",
        "application/json",
        runtimeChecklistReceipt.id,
        runtimeChecklist,
        "redacted",
      ),
    );
  }
  const updated = {
    ...run,
    status,
    updatedAt,
    events: trace.events,
    trace,
    receipts,
    artifacts,
    runtimeTask: trace.runtimeTask,
    runtimeJob: trace.runtimeJob,
    runtimeChecklist: trace.runtimeChecklist,
    result: "Run canceled with terminal event continuity preserved.",
  };
  state.runs.set(runId, updated);
  state.writeRun(updated, "run.cancel");
  return updated;
}
