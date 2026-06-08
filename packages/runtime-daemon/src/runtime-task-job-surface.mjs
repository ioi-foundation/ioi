import { optionalString } from "./runtime-value-helpers.mjs";

function defaultNotFound(message, details = {}) {
  const error = new Error(message);
  error.status = 404;
  error.details = details;
  return error;
}

function defaultRuntimeTaskRecordForRun(run = {}) {
  return {
    taskId: run.id,
    runId: run.id,
    status: run.status,
    createdAt: run.createdAt ?? "",
  };
}

function defaultRuntimeJobRecordForRun(run = {}) {
  return {
    jobId: run.id,
    runId: run.id,
    status: run.status,
    createdAt: run.createdAt ?? "",
  };
}

const runtimeTaskJobControlFacadeRetirementEvidenceRefs = [
  "runtime_task_job_control_js_facade_retired",
  "runtime_task_create_js_facade_retired",
  "runtime_task_cancel_js_facade_retired",
  "runtime_job_cancel_js_facade_retired",
  "rust_daemon_core_runtime_task_job_control_required",
  "agentgres_runtime_task_job_truth_required",
];

export function createRuntimeTaskJobSurface({
  notFound: notFoundDep = defaultNotFound,
  optionalString: optionalStringDep = optionalString,
  runtimeJobRecordForRun: runtimeJobRecordForRunDep = defaultRuntimeJobRecordForRun,
  runtimeTaskRecordForRun: runtimeTaskRecordForRunDep = defaultRuntimeTaskRecordForRun,
  runtimeError: runtimeErrorDep = null,
} = {}) {
  function throwRuntimeTaskJobRustCoreRequired({
    operation,
    operationKind,
    taskId = null,
    jobId = null,
  }) {
    const error = runtimeErrorDep
      ? runtimeErrorDep({
          status: 501,
          code: "runtime_task_job_control_rust_core_required",
          message:
            "Runtime task/job lifecycle mutations require direct Rust daemon-core admission and persistence.",
          details: {
            rust_core_boundary: "runtime.task_job_control",
            operation,
            operation_kind: operationKind,
            ...(taskId ? { task_id: taskId } : {}),
            ...(jobId ? { job_id: jobId } : {}),
            evidence_refs: [
              ...runtimeTaskJobControlFacadeRetirementEvidenceRefs,
              `${operation}_js_facade_retired`,
            ],
          },
        })
      : Object.assign(
          new Error(
            "Runtime task/job lifecycle mutations require direct Rust daemon-core admission and persistence.",
          ),
          {
            status: 501,
            code: "runtime_task_job_control_rust_core_required",
            details: {
              rust_core_boundary: "runtime.task_job_control",
              operation,
              operation_kind: operationKind,
              ...(taskId ? { task_id: taskId } : {}),
              ...(jobId ? { job_id: jobId } : {}),
              evidence_refs: [
                ...runtimeTaskJobControlFacadeRetirementEvidenceRefs,
                `${operation}_js_facade_retired`,
              ],
            },
          },
        );
    throw error;
  }

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
      void store;
      void body;
      throwRuntimeTaskJobRustCoreRequired({
        operation: "runtime_task_create",
        operationKind: "task.create",
      });
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
      const task = this.listTasks(store).find((candidate) => candidate.taskId === taskId);
      if (!task) throw notFoundDep(`Task not found: ${taskId}`, { task_id: taskId });
      return task;
    },
    cancelTask(store, taskId) {
      void store;
      throwRuntimeTaskJobRustCoreRequired({
        operation: "runtime_task_cancel",
        operationKind: "task.cancel",
        taskId,
      });
    },
    getJob(store, jobId) {
      const job = this.listJobs(store).find((candidate) => candidate.jobId === jobId);
      if (!job) throw notFoundDep(`Job not found: ${jobId}`, { job_id: jobId });
      return job;
    },
    cancelJob(store, jobId) {
      void store;
      throwRuntimeTaskJobRustCoreRequired({
        operation: "runtime_job_cancel",
        operationKind: "job.cancel",
        jobId,
      });
    },
  };
}
