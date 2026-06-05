import { optionalString } from "./runtime-value-helpers.mjs";

function defaultNotFound(message, details = {}) {
  const error = new Error(message);
  error.status = 404;
  error.details = details;
  return error;
}

function defaultRuntimeTaskRecordForRun(run = {}) {
  return {
    taskId: run.runtimeTask?.taskId ?? run.taskId ?? run.id,
    runId: run.id,
    status: run.status,
    createdAt: run.createdAt ?? "",
  };
}

function defaultRuntimeJobRecordForRun(run = {}) {
  return {
    jobId: run.runtimeJob?.jobId ?? run.jobId ?? run.id,
    runId: run.id,
    status: run.status,
    createdAt: run.createdAt ?? "",
  };
}

export function createRuntimeTaskJobSurface({
  notFound: notFoundDep = defaultNotFound,
  optionalString: optionalStringDep = optionalString,
  runtimeJobRecordForRun: runtimeJobRecordForRunDep = defaultRuntimeJobRecordForRun,
  runtimeTaskRecordForRun: runtimeTaskRecordForRunDep = defaultRuntimeTaskRecordForRun,
} = {}) {
  return {
    listJobs(store, options = {}) {
      const agentId = options.agent_id ?? undefined;
      const status = options.status ?? undefined;
      return store.listRuns(agentId)
        .map((run) => runtimeJobRecordForRunDep(run))
        .filter((job) => !status || job.status === status)
        .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    },
    createTask(store, body = {}) {
      const agentId = optionalStringDep(body.agentId ?? body.agent_id);
      const agent = agentId
        ? store.getAgent(agentId)
        : store.createAgent({
            ...(body.agent ?? body.agent_options ?? body.agentOptions ?? {}),
            local: {
              cwd: body.cwd ?? body.workspace ?? store.defaultCwd,
              ...((body.agent ?? body.agent_options ?? body.agentOptions ?? {}).local ?? {}),
            },
            model: body.model ?? (body.agent ?? body.agent_options ?? body.agentOptions ?? {}).model,
          });
      const options = body.options && typeof body.options === "object" ? body.options : {};
      const run = store.createRun(agent.id, {
        ...body,
        mode: body.mode ?? "send",
        prompt: body.prompt ?? body.objective ?? body.goal ?? "",
        options,
      });
      return runtimeTaskRecordForRunDep(run);
    },
    listTasks(store, options = {}) {
      const agentId = options.agent_id ?? undefined;
      const status = options.status ?? undefined;
      return store.listRuns(agentId)
        .map((run) => runtimeTaskRecordForRunDep(run))
        .filter((task) => !status || task.status === status)
        .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    },
    getTask(store, taskId) {
      const task = this.listTasks(store).find((candidate) => candidate.taskId === taskId || candidate.runId === taskId);
      if (!task) throw notFoundDep(`Task not found: ${taskId}`, { taskId });
      return task;
    },
    cancelTask(store, taskId) {
      const task = this.getTask(store, taskId);
      const canceledRun = store.cancelRun(task.runId);
      return runtimeTaskRecordForRunDep(canceledRun);
    },
    getJob(store, jobId) {
      const job = this.listJobs(store).find((candidate) => candidate.jobId === jobId || candidate.runId === jobId);
      if (!job) throw notFoundDep(`Job not found: ${jobId}`, { jobId });
      return job;
    },
    cancelJob(store, jobId) {
      const job = this.getJob(store, jobId);
      const canceledRun = store.cancelRun(job.runId);
      return runtimeJobRecordForRunDep(canceledRun);
    },
  };
}
