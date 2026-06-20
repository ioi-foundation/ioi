import {
  objectRecord,
  optionalString,
} from "./runtime-value-helpers.mjs";

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

export function createRuntimeTaskJobApi({
  contextPolicyCore = null,
  notFound: notFoundDep = null,
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
      return projectRuntimeTaskJob(store, {
        operation: "runtime_job_list",
        operationKind: "job.list",
        projectionKind: "job.list",
        options,
      });
    },
    async createTask(store, body = {}) {
      return await createRuntimeTask(store, body);
    },
    listTasks(store, options = {}) {
      return projectRuntimeTaskJob(store, {
        operation: "runtime_task_list",
        operationKind: "task.list",
        projectionKind: "task.list",
        options,
      });
    },
    getTask(store, taskId) {
      return projectRuntimeTaskJob(store, {
        operation: "runtime_task_get",
        operationKind: "task.get",
        projectionKind: "task.get",
        taskId,
      });
    },
    cancelTask(store, taskId) {
      return cancelRuntimeTaskJob(store, {
        cancelKind: "task",
        operation: "runtime_task_cancel",
        operationKind: "task.cancel",
        publicId: taskId,
      });
    },
    getJob(store, jobId) {
      return projectRuntimeTaskJob(store, {
        operation: "runtime_job_get",
        operationKind: "job.get",
        projectionKind: "job.get",
        jobId,
      });
    },
    cancelJob(store, jobId) {
      return cancelRuntimeTaskJob(store, {
        cancelKind: "job",
        operation: "runtime_job_cancel",
        operationKind: "job.cancel",
        publicId: jobId,
      });
    },
  };

  async function createRuntimeTask(store, body = {}) {
    const operation = "runtime_task_create";
    const operationKind = "task.create";
    if (typeof store.createRun !== "function") {
      throwRuntimeTaskJobStateUpdateError({
        status: 501,
        code: "runtime_task_create_run_lifecycle_unavailable",
        message:
          "Runtime task creation requires the store-owned Rust run-create lifecycle.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          evidence_refs: [
            ...runtimeTaskJobControlFacadeRetirementEvidenceRefs,
            "runtime_run_create_state_update_required",
            `${operation}_js_facade_retired`,
          ],
        },
      });
    }
    const agentId = optionalString(body?.agent_id);
    if (!agentId) {
      throwRuntimeTaskJobStateUpdateError({
        status: 400,
        code: "runtime_task_create_agent_id_required",
        message: "Runtime task creation requires canonical agent_id.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
        },
      });
    }
    if (typeof contextPolicyCore?.projectRuntimeTaskJobProjection !== "function") {
      throwRuntimeTaskJobRustCoreRequired({
        operation: "runtime_task_create_projection",
        operationKind: "task.get",
      });
    }
    const request = canonicalTaskCreateRunRequest(body);
    const plannedRun = objectRecord(await store.createRun(agentId, request));
    const runId = optionalString(plannedRun?.id);
    const plannedTask = objectRecord(plannedRun?.runtimeTask);
    const taskId = optionalString(plannedTask?.taskId);
    if (!runId || !taskId || optionalString(plannedRun?.agentId) !== agentId) {
      throwRuntimeTaskJobStateUpdateError({
        status: 502,
        code: "runtime_task_create_run_lifecycle_projection_missing",
        message:
          "Rust run-create lifecycle did not return a task id for task creation.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          agent_id: agentId,
          run_id: runId ?? null,
          task_id: taskId ?? null,
        },
      });
    }
    let projectedTask;
    try {
      projectedTask = projectRuntimeTaskJob(store, {
        operation: "runtime_task_create_projection",
        operationKind: "task.get",
        projectionKind: "task.get",
        taskId,
      });
    } catch (error) {
      if (error?.code === "runtime_task_job_projection_mismatch") {
        throwRuntimeTaskCreateProjectionMismatch({
          agentId,
          runId,
          taskId,
          projectionError: error,
        });
      }
      throw error;
    }
    if (
      optionalString(projectedTask?.taskId) !== taskId ||
      optionalString(projectedTask?.runId) !== runId ||
      optionalString(projectedTask?.agentId) !== agentId
    ) {
      throwRuntimeTaskCreateProjectionMismatch({
        agentId,
        runId,
        taskId,
        projectedTask,
      });
    }
    return projectedTask;
  }

  function throwRuntimeTaskCreateProjectionMismatch({
    agentId,
    runId,
    taskId,
    projectedTask = null,
    projectionError = null,
  }) {
    throwRuntimeTaskJobStateUpdateError({
      status: 502,
      code: "runtime_task_create_projection_mismatch",
      message:
        "Rust task creation replay projection did not match the admitted run.",
      details: {
        rust_core_boundary: "runtime.task_job_control",
        operation: "runtime_task_create",
        operation_kind: "task.create",
        agent_id: agentId,
        actual_agent_id:
          optionalString(projectedTask?.agentId) ??
          optionalString(projectionError?.details?.actual_agent_id) ??
          null,
        run_id: runId,
        actual_run_id:
          optionalString(projectedTask?.runId) ??
          optionalString(projectionError?.details?.actual_run_id) ??
          null,
        task_id: taskId,
        actual_task_id:
          optionalString(projectedTask?.taskId) ??
          optionalString(projectionError?.details?.actual_task_id) ??
          null,
      },
    });
  }

  function projectRuntimeTaskJob(store, {
    operation,
    operationKind,
    projectionKind,
    options = {},
    taskId = null,
    jobId = null,
  }) {
    const runner = contextPolicyCore;
    if (typeof runner?.projectRuntimeTaskJobProjection !== "function") {
      throwRuntimeTaskJobRustCoreRequired({
        operation,
        operationKind,
        ...(taskId ? { taskId } : {}),
        ...(jobId ? { jobId } : {}),
      });
    }
    const stateDir = optionalString(store.stateDir);
    if (!stateDir) {
      throwRuntimeTaskJobStateUpdateError({
        status: 501,
        code: "runtime_task_job_projection_state_dir_required",
        message:
          "Runtime task/job projection requires runtime state_dir for Rust Agentgres run replay.",
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
      });
    }
    const request = {
      projection_kind: projectionKind,
      state_dir: stateDir,
      ...(optionalString(options?.agent_id) ? { agent_id: optionalString(options.agent_id) } : {}),
      ...(optionalString(options?.status) ? { status: optionalString(options.status) } : {}),
      ...(taskId ? { task_id: taskId } : {}),
      ...(jobId ? { job_id: jobId } : {}),
    };
    const projected = runner.projectRuntimeTaskJobProjection(request);
    validateRuntimeTaskJobProjection(projected, {
      operation,
      operationKind,
      projectionKind,
      taskId,
      jobId,
    });
    if (projectionKind === "task.list" || projectionKind === "job.list") {
      return projected.records;
    }
    const projectedRecord = objectRecord(
      projectionKind === "task.get" ? projected.runtime_task : projected.runtime_job,
    );
    if (!projectedRecord) {
      throwRuntimeTaskJobNotFound({ projectionKind, taskId, jobId });
    }
    return projectedRecord;
  }

  function validateRuntimeTaskJobProjection(projected, {
    operation,
    operationKind,
    projectionKind,
    taskId,
    jobId,
  }) {
    const records = Array.isArray(projected?.records) ? projected.records : null;
    const recordId = optionalString(
      projectionKind === "task.get"
        ? projected?.runtime_task?.taskId
        : projected?.runtime_job?.jobId,
    );
    if (
      optionalString(projected?.status) !== "projected" ||
      optionalString(projected?.operation_kind) !== operationKind ||
      optionalString(projected?.projection_kind) !== projectionKind ||
      !records ||
      (projectionKind === "task.get" && objectRecord(projected?.runtime_task) && recordId !== taskId) ||
      (projectionKind === "job.get" && objectRecord(projected?.runtime_job) && recordId !== jobId)
    ) {
      throwRuntimeTaskJobStateUpdateError({
        status: 502,
        code: "runtime_task_job_projection_mismatch",
        message:
          "Rust daemon-core task/job projection did not match the requested public API boundary.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          expected_operation_kind: operationKind,
          actual_operation_kind: optionalString(projected?.operation_kind) ?? null,
          expected_projection_kind: projectionKind,
          actual_projection_kind: optionalString(projected?.projection_kind) ?? null,
          ...(taskId ? { task_id: taskId, actual_task_id: recordId ?? null } : {}),
          ...(jobId ? { job_id: jobId, actual_job_id: recordId ?? null } : {}),
        },
      });
    }
  }

  function throwRuntimeTaskJobNotFound({ projectionKind, taskId, jobId }) {
    const isTask = projectionKind === "task.get";
    const message = isTask ? `Task not found: ${taskId}` : `Job not found: ${jobId}`;
    const details = {
      rust_core_boundary: "runtime.task_job_control",
      operation_kind: projectionKind,
      ...(isTask ? { task_id: taskId } : { job_id: jobId }),
    };
    if (typeof notFoundDep === "function") {
      throw notFoundDep(message, details);
    }
    throwRuntimeTaskJobStateUpdateError({
      status: 404,
      code: "runtime_task_job_projection_not_found",
      message,
      details,
    });
  }

  function cancelRuntimeTaskJob(store, {
    cancelKind,
    operation,
    operationKind,
    publicId,
  }) {
    const runner = contextPolicyCore;
    const idKey = cancelKind === "task" ? "taskId" : "jobId";
    if (typeof runner?.planRuntimeTaskJobCancelStateUpdate !== "function") {
      throwRuntimeTaskJobRustCoreRequired({
        operation,
        operationKind,
        [idKey]: publicId,
      });
    }
    if (typeof store.getRun !== "function" || typeof store.writeRun !== "function") {
      throwRuntimeTaskJobStateUpdateError({
        status: 501,
        code: "runtime_task_job_cancel_persistence_unavailable",
        message:
          "Runtime task/job cancellation requires Rust Agentgres run-state persistence.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          ...(cancelKind === "task" ? { task_id: publicId } : { job_id: publicId }),
          evidence_refs: [
            ...runtimeTaskJobControlFacadeRetirementEvidenceRefs,
            `${operation}_js_facade_retired`,
          ],
        },
      });
    }
    const runId = runIdForTaskJobPublicId(cancelKind, publicId);
    if (!runId) {
      throwRuntimeTaskJobStateUpdateError({
        status: 400,
        code: "runtime_task_job_public_id_invalid",
        message: "Runtime task/job cancellation requires a canonical public id.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          ...(cancelKind === "task" ? { task_id: publicId } : { job_id: publicId }),
          expected_prefix: cancelKind === "task" ? "task_" : "job_",
        },
      });
    }
    const run = store.getRun(runId);
    if (!objectRecord(run)) {
      throwRuntimeTaskJobStateUpdateError({
        status: 404,
        code: "runtime_task_job_run_not_found",
        message: `Run not found for ${cancelKind}: ${publicId}`,
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          run_id: runId,
          ...(cancelKind === "task" ? { task_id: publicId } : { job_id: publicId }),
        },
      });
    }
    const canceledAt = store.nowIso?.() ?? new Date().toISOString();
    const planned = runner.planRuntimeTaskJobCancelStateUpdate({
      cancel_kind: cancelKind,
      ...(cancelKind === "task" ? { task_id: publicId } : { job_id: publicId }),
      run_id: runId,
      run,
      canceled_at: canceledAt,
    });
    const plannedRun = objectRecord(planned?.run);
    const plannedRecord = objectRecord(
      cancelKind === "task" ? planned?.runtime_task : planned?.runtime_job,
    );
    const plannedOperationKind = optionalString(planned?.operation_kind);
    if (!plannedRun || !plannedRecord) {
      throwRuntimeTaskJobStateUpdateError({
        status: 502,
        code: "runtime_task_job_cancel_state_update_projection_missing",
        message:
          "Rust daemon-core task/job cancellation did not return a complete projection.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          run_id: runId,
          ...(cancelKind === "task" ? { task_id: publicId } : { job_id: publicId }),
        },
      });
    }
    const actualPublicId = optionalString(
      cancelKind === "task" ? plannedRecord.taskId : plannedRecord.jobId,
    );
    if (
      optionalString(planned?.status) !== "planned" ||
      plannedOperationKind !== operationKind ||
      optionalString(planned?.cancel_kind) !== cancelKind ||
      optionalString(planned?.run_id) !== runId ||
      optionalString(plannedRun.id) !== runId ||
      optionalString(plannedRun.status) !== "canceled" ||
      actualPublicId !== publicId ||
      optionalString(plannedRecord.status) !== "canceled" ||
      !objectRecord(planned?.runtime_checklist) ||
      !Array.isArray(plannedRun.events) ||
      !plannedRun.events.some((event) => optionalString(event?.type) === "job_canceled") ||
      !plannedRun.events.some((event) => optionalString(event?.type) === "canceled") ||
      !Array.isArray(plannedRun.receipts) ||
      !Array.isArray(plannedRun.artifacts)
    ) {
      throwRuntimeTaskJobStateUpdateError({
        status: 502,
        code: "runtime_task_job_cancel_state_update_projection_mismatch",
        message:
          "Rust daemon-core task/job cancellation projection did not match the requested public id.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          expected_operation_kind: operationKind,
          actual_operation_kind: plannedOperationKind,
          run_id: runId,
          actual_run_id: optionalString(plannedRun.id) ?? null,
          actual_run_status: optionalString(plannedRun.status) ?? null,
          ...(cancelKind === "task"
            ? { task_id: publicId, actual_task_id: actualPublicId ?? null }
            : { job_id: publicId, actual_job_id: actualPublicId ?? null }),
        },
      });
    }
    store.writeRun(plannedRun, plannedOperationKind);
    return plannedRecord;
  }
}

function runIdForTaskJobPublicId(cancelKind, publicId) {
  const id = optionalString(publicId);
  const prefix = cancelKind === "task" ? "task_" : "job_";
  return id?.startsWith(prefix) ? id.slice(prefix.length) : null;
}

function canonicalTaskCreateRunRequest(body = {}) {
  const options = { ...(objectRecord(body?.options) ?? {}) };
  const model = objectRecord(body?.model);
  const agentOptions = objectRecord(body?.agent_options);
  const cwd = optionalString(body?.cwd);
  if (model) {
    options.model = model;
  }
  if (agentOptions) {
    options.agent_options = agentOptions;
  }
  if (cwd) {
    options.cwd = cwd;
  }
  return {
    mode: optionalString(body?.mode) ?? "send",
    prompt: optionalString(body?.prompt) ?? "",
    options,
  };
}

function throwRuntimeTaskJobStateUpdateError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  throw error;
}
