const runtimeTaskJobControlFacadeRetirementEvidenceRefs = [
  "runtime_task_job_control_js_facade_retired",
  "runtime_task_list_js_facade_retired",
  "runtime_task_get_js_facade_retired",
  "runtime_job_list_js_facade_retired",
  "runtime_job_get_js_facade_retired",
  "runtime_task_create_js_facade_retired",
  "runtime_task_cancel_js_facade_retired",
  "runtime_job_cancel_js_facade_retired",
  "rust_daemon_core_runtime_task_job_control_required",
  "agentgres_runtime_task_job_truth_required",
];

export function createRuntimeTaskJobSurface({
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
            "Runtime task/job lifecycle and projection facades require direct Rust daemon-core admission, persistence, and projection.",
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
            "Runtime task/job lifecycle and projection facades require direct Rust daemon-core admission, persistence, and projection.",
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
      void store;
      void options;
      throwRuntimeTaskJobRustCoreRequired({
        operation: "runtime_job_list",
        operationKind: "job.list",
      });
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
      void store;
      void options;
      throwRuntimeTaskJobRustCoreRequired({
        operation: "runtime_task_list",
        operationKind: "task.list",
      });
    },
    getTask(store, taskId) {
      void store;
      throwRuntimeTaskJobRustCoreRequired({
        operation: "runtime_task_get",
        operationKind: "task.get",
        taskId,
      });
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
      void store;
      throwRuntimeTaskJobRustCoreRequired({
        operation: "runtime_job_get",
        operationKind: "job.get",
        jobId,
      });
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
