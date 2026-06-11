export function createRuntimeRecordProjections(deps) {
  const {
    doctorHash,
    normalizeArray,
    strategyForMode,
    taskFamilyForMode,
    terminalCount,
    threadIdForAgent,
    turnIdForRun,
    uniqueStrings,
  } = deps;

function runtimeTaskRecord({
  runId,
  agent,
  prompt,
  mode,
  taskFamily,
  selectedStrategy,
  modelRouteDecision,
  activeSkillHookManifest,
  createdAt,
  updatedAt,
  status,
} = {}) {
  const id = runId ?? `run_${doctorHash(String(prompt ?? "task")).slice(0, 12)}`;
  const agentId = agent?.id ?? null;
  const promptHash = doctorHash(String(prompt ?? ""));
  return {
    schemaVersion: "ioi.agent-runtime.task-record.v1",
    object: "ioi.runtime_task",
    taskId: `task_${id}`,
    runId: id,
    agentId,
    threadId: agentId ? threadIdForAgent(agentId) : null,
    turnId: turnIdForRun(id),
    status: status ?? "completed",
    mode: mode ?? "send",
    taskFamily: taskFamily ?? taskFamilyForMode(mode ?? "send"),
    selectedStrategy: selectedStrategy ?? strategyForMode(mode ?? "send"),
    summary: `Runtime task for ${taskFamily ?? taskFamilyForMode(mode ?? "send")} is ${status ?? "completed"}.`,
    promptHash,
    promptIncluded: false,
    objectivePreviewIncluded: false,
    modelRouteDecisionId: modelRouteDecision?.decision_id ?? null,
    activeSkillHookManifestId: activeSkillHookManifest?.manifestId ?? null,
    createdAt: createdAt ?? new Date().toISOString(),
    updatedAt: updatedAt ?? createdAt ?? new Date().toISOString(),
    durable: true,
    replayable: true,
    cancelable: status !== "canceled",
    cancelEndpoint: `/v1/tasks/task_${id}/cancel`,
    endpoints: {
      self: `/v1/tasks/task_${id}`,
      cancel: `/v1/tasks/task_${id}/cancel`,
      run: `/v1/runs/${id}`,
      job: `/v1/jobs/job_${id}`,
      events: `/v1/runs/${id}/events`,
      trace: `/v1/runs/${id}/trace`,
    },
    workflowNodeId: "runtime.runtime-task",
    redaction: {
      profile: "runtime_task_safe",
      promptIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "runtime_task",
      "runtime.tasks.durable_projection",
      "RuntimeTaskNode",
      `run:${id}`,
      activeSkillHookManifest?.manifestId,
    ].filter(Boolean),
  };
}

function runtimeTaskRecordForRun(run) {
  return runtimeTaskRecord({
    runId: run?.id,
    agent: { id: run?.agentId },
    prompt: run?.objective,
    mode: run?.mode,
    taskFamily: run?.trace?.qualityLedger?.taskFamily ?? taskFamilyForMode(run?.mode ?? "send"),
    selectedStrategy: run?.trace?.qualityLedger?.selectedStrategy ?? strategyForMode(run?.mode ?? "send"),
    modelRouteDecision: run?.modelRouteDecision ?? run?.trace?.modelRouteDecision,
    activeSkillHookManifest: run?.activeSkillHookManifest ?? run?.trace?.activeSkillHookManifest,
    createdAt: run?.createdAt,
    updatedAt: run?.updatedAt,
    status: jobStatusForRunStatus(run?.status),
  });
}

function runtimeJobRecord({
  runtimeTask,
  runtimeChecklist,
  agent,
  status,
  createdAt,
  updatedAt,
  queuedAt,
  startedAt,
  completedAt,
  lifecycle,
  eventCount,
  terminalEventCount,
  artifactNames,
  receiptKinds,
} = {}) {
  const task = runtimeTask ?? runtimeTaskRecord();
  const jobStatus = status ?? "completed";
  const jobId = `job_${task.runId}`;
  return {
    schemaVersion: "ioi.agent-runtime.job-record.v1",
    object: "ioi.runtime_job",
    jobId,
    taskId: task.taskId,
    runId: task.runId,
    agentId: task.agentId ?? agent?.id ?? null,
    threadId: task.threadId,
    turnId: task.turnId,
    status: jobStatus,
    lifecycle: lifecycle ?? jobLifecycleForStatus(jobStatus),
    summary: `Runtime job ${jobId} is ${jobStatus}.`,
    queueName: "local-agentgres",
    runner: "local-daemon-agentgres",
    jobType: "agent_run",
    priority: "normal",
    background: true,
    durable: true,
    replayable: true,
    createdAt: createdAt ?? task.createdAt,
    updatedAt: updatedAt ?? task.updatedAt,
    queuedAt: queuedAt ?? createdAt ?? task.createdAt,
    startedAt: startedAt ?? createdAt ?? task.createdAt,
    completedAt: completedAt ?? (["completed", "failed", "canceled"].includes(jobStatus) ? updatedAt ?? task.updatedAt : null),
    progress: {
      completedSteps: ["completed", "failed", "canceled"].includes(jobStatus) ? 1 : jobStatus === "running" ? 0 : 0,
      totalSteps: 1,
      percent: ["completed", "failed", "canceled"].includes(jobStatus) ? 100 : jobStatus === "running" ? 50 : 0,
    },
    eventCount: eventCount ?? null,
    terminalEventCount: terminalEventCount ?? null,
    artifactNames: artifactNames ?? ["runtime-task.json", "runtime-job.json", "runtime-checklist.json", "trace.json", "agentgres-projection.json"],
    receiptKinds: receiptKinds ?? ["runtime_task", "runtime_job", "runtime_checklist", "agentgres_canonical_write"],
    checklistId: runtimeChecklist?.checklistId ?? null,
    checklistStatus: runtimeChecklist?.status ?? null,
    checklistItemCount: runtimeChecklist?.itemCount ?? null,
    checklistCompletedItemCount: runtimeChecklist?.completedItemCount ?? null,
    failure: jobStatus === "failed" ? { reason: "runtime_failed", message: "Runtime job failed." } : null,
    cancellation: jobStatus === "canceled" ? { reason: "operator_cancel" } : null,
    retryCount: 0,
    cancelable: jobStatus !== "canceled",
    cancelEndpoint: `/v1/jobs/${jobId}/cancel`,
    endpoints: {
      self: `/v1/jobs/${jobId}`,
      cancel: `/v1/jobs/${jobId}/cancel`,
      run: `/v1/runs/${task.runId}`,
      events: `/v1/runs/${task.runId}/events`,
      trace: `/v1/runs/${task.runId}/trace`,
    },
    workflowNodeId: "runtime.runtime-job",
    redaction: {
      profile: "runtime_job_safe",
      promptIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "runtime_job",
      "runtime.jobs.durable_projection",
      "RuntimeJobNode",
      task.taskId,
      `run:${task.runId}`,
    ],
  };
}

function runtimeChecklistRecord({
  runtimeTask,
  runtimeJob,
  status,
  createdAt,
  updatedAt,
} = {}) {
  const task = runtimeTask ?? runtimeTaskRecord();
  const job = runtimeJob ?? runtimeJobRecord({ runtimeTask: task });
  const checklistStatus = status ?? job.status ?? task.status ?? "completed";
  const checklistId = `checklist_${task.runId}`;
  const terminalLabel =
    checklistStatus === "canceled"
      ? "Job canceled event emitted"
      : checklistStatus === "failed"
        ? "Job failed event emitted"
        : checklistStatus === "blocked"
          ? "Job blocked by policy gate"
        : "Job completed event emitted";
  const terminalEventKind =
    checklistStatus === "canceled"
      ? "JobCanceled"
      : checklistStatus === "failed"
        ? "JobFailed"
        : checklistStatus === "blocked"
          ? "PolicyBlocked"
        : "JobCompleted";
  const terminalItemStatus =
    checklistStatus === "canceled"
      ? "canceled"
      : checklistStatus === "failed"
        ? "failed"
        : checklistStatus === "blocked"
          ? "blocked"
        : "passed";
  const item = (suffix, label, itemStatus, evidenceRefs) => ({
    itemId: `${checklistId}:${suffix}`,
    label,
    status: itemStatus,
    evidenceRefs: uniqueStrings(evidenceRefs),
  });
  const items = [
    item("task_record", "Runtime task record durable", "passed", [
      task.taskId,
      "RuntimeTaskNode",
      "runtime.tasks.durable_projection",
    ]),
    item("job_record", "Runtime job record durable", "passed", [
      job.jobId,
      "RuntimeJobNode",
      "runtime.jobs.durable_projection",
    ]),
    item("job_queued", "Job queued event emitted", "passed", ["JobQueued"]),
    item("job_started", "Job started event emitted", "passed", ["JobStarted"]),
    item("job_terminal", terminalLabel, terminalItemStatus, [terminalEventKind]),
    item("artifacts", "Runtime task/job/checklist artifacts attached", "passed", [
      "runtime-task.json",
      "runtime-job.json",
      "runtime-checklist.json",
    ]),
  ];
  return {
    schemaVersion: "ioi.agent-runtime.checklist-record.v1",
    object: "ioi.runtime_checklist",
    checklistId,
    taskId: task.taskId,
    jobId: job.jobId,
    runId: task.runId,
    agentId: task.agentId,
    threadId: task.threadId,
    turnId: task.turnId,
    status: checklistStatus,
    summary: `Runtime checklist for ${job.jobId} is ${checklistStatus}.`,
    durable: true,
    replayable: true,
    readOnly: true,
    itemCount: items.length,
    completedItemCount: items.filter((entry) => entry.status === "passed").length,
    canceledItemCount: items.filter((entry) => entry.status === "canceled").length,
    failedItemCount: items.filter((entry) => entry.status === "failed").length,
    blockedItemCount: items.filter((entry) => entry.status === "blocked").length,
    items,
    requiredItemIds: items.map((entry) => entry.itemId),
    createdAt: createdAt ?? task.createdAt,
    updatedAt: updatedAt ?? task.updatedAt,
    workflowNodeId: "runtime.runtime-checklist",
    redaction: {
      profile: "runtime_checklist_safe",
      promptIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "runtime_checklist",
      "runtime.checklists.durable_projection",
      "RuntimeChecklistNode",
      task.taskId,
      job.jobId,
      `run:${task.runId}`,
    ],
  };
}

function attachChecklistToRuntimeJob(job, checklist) {
  return {
    ...job,
    checklistId: checklist.checklistId,
    checklistStatus: checklist.status,
    checklistItemCount: checklist.itemCount,
    checklistCompletedItemCount: checklist.completedItemCount,
    artifactNames: uniqueStrings([...normalizeArray(job.artifactNames), "runtime-checklist.json"]),
    receiptKinds: uniqueStrings([...normalizeArray(job.receiptKinds), "runtime_checklist"]),
    evidenceRefs: uniqueStrings([...normalizeArray(job.evidenceRefs), checklist.checklistId, "runtime_checklist"]),
  };
}

function runtimeJobRecordForRun(run) {
  const task = runtimeTaskRecordForRun(run);
  const status = jobStatusForRunStatus(run?.status);
  return runtimeJobRecord({
    runtimeTask: task,
    status,
    createdAt: run?.createdAt,
    updatedAt: run?.updatedAt,
    queuedAt: run?.createdAt,
    startedAt: run?.createdAt,
    completedAt: ["completed", "failed", "canceled"].includes(status) ? run?.updatedAt : null,
    lifecycle: jobLifecycleForStatus(status),
    eventCount: normalizeArray(run?.events).length || null,
    terminalEventCount: terminalCount(normalizeArray(run?.events)) || null,
    artifactNames: normalizeArray(run?.artifacts).map((artifactItem) => artifactItem.name).filter(Boolean),
    receiptKinds: normalizeArray(run?.receipts).map((receipt) => receipt.kind).filter(Boolean),
  });
}

function runtimeChecklistRecordForRun(run) {
  const task = runtimeTaskRecordForRun(run);
  const job = runtimeJobRecordForRun(run);
  return runtimeChecklistRecord({
    runtimeTask: task,
    runtimeJob: job,
    status: job.status,
    createdAt: run?.createdAt,
    updatedAt: run?.updatedAt,
  });
}

function jobStatusForRunStatus(status) {
  if (status === "canceled") return "canceled";
  if (status === "failed" || status === "error") return "failed";
  if (status === "blocked") return "blocked";
  if (status === "running" || status === "active") return "running";
  if (status === "queued" || status === "pending") return "queued";
  return "completed";
}

function jobLifecycleForStatus(status) {
  if (status === "queued") return ["queued"];
  if (status === "running") return ["queued", "started"];
  if (status === "failed") return ["queued", "started", "failed"];
  if (status === "canceled") return ["queued", "started", "canceled"];
  if (status === "blocked") return ["queued", "started", "blocked"];
  return ["queued", "started", "completed"];
}


  return {
    attachChecklistToRuntimeJob,
    runtimeChecklistRecord,
    runtimeChecklistRecordForRun,
    runtimeJobRecord,
    runtimeJobRecordForRun,
    runtimeTaskRecord,
    runtimeTaskRecordForRun,
  };
}
