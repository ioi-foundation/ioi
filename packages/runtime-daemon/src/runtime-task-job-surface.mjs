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

export function createRuntimeTaskJobSurface({
  buildRun = null,
  ensureProviderAvailable = null,
  taskJobCreateRunner = null,
  taskJobCancelRunner = null,
  taskJobProjectionRunner = null,
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
    createTask(store, body = {}) {
      return createRuntimeTask(store, body);
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

  function createRuntimeTask(store, body = {}) {
    const operation = "runtime_task_create";
    const operationKind = "task.create";
    const runner = taskJobCreateRunner ?? store.contextPolicyCore ?? null;
    if (typeof runner?.planRuntimeTaskJobCreateStateUpdate !== "function") {
      throwRuntimeTaskJobRustCoreRequired({
        operation,
        operationKind,
      });
    }
    if (typeof buildRun !== "function") {
      throwRuntimeTaskJobStateUpdateError({
        status: 501,
        code: "runtime_task_create_builder_unavailable",
        message:
          "Runtime task creation requires mounted run candidate construction before Rust state planning.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          evidence_refs: [
            ...runtimeTaskJobControlFacadeRetirementEvidenceRefs,
            `${operation}_js_facade_retired`,
          ],
        },
      });
    }
    if (
      typeof store.getAgent !== "function" ||
      typeof store.writeRun !== "function" ||
      typeof store.resolveRunModelRoute !== "function" ||
      typeof store.resolveRunMemory !== "function"
    ) {
      throwRuntimeTaskJobStateUpdateError({
        status: 501,
        code: "runtime_task_create_persistence_unavailable",
        message:
          "Runtime task creation requires Rust Agentgres agent lookup, run planning, and run-state persistence.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          evidence_refs: [
            ...runtimeTaskJobControlFacadeRetirementEvidenceRefs,
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
    const agent = objectRecord(store.getAgent(agentId));
    if (!agent) {
      throwRuntimeTaskJobStateUpdateError({
        status: 404,
        code: "runtime_task_create_agent_not_found",
        message: `Agent not found: ${agentId}`,
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          agent_id: agentId,
        },
      });
    }
    if (typeof ensureProviderAvailable === "function") {
      ensureProviderAvailable(agent.runtime, agent.options);
    }
    const request = canonicalTaskCreateRunRequest(body);
    const prompt = optionalString(request.prompt) ?? "";
    const mode = optionalString(request.mode) ?? "send";
    const modelRoute = store.resolveRunModelRoute(agent, request);
    const memory = store.resolveRunMemory(agent, request, prompt);
    const candidateRun = buildRun({
      agent,
      mode,
      prompt,
      request,
      source: "local_daemon_agentgres",
      modelRoute,
      memory,
      skillHookCatalog: null,
      diagnosticsFeedback: null,
    });
    const planned = runner.planRuntimeTaskJobCreateStateUpdate({
      agent_id: agentId,
      run: candidateRun,
    });
    const plannedRun = objectRecord(planned?.run);
    const plannedTask = objectRecord(planned?.runtime_task);
    const plannedJob = objectRecord(planned?.runtime_job);
    const plannedChecklist = objectRecord(planned?.runtime_checklist);
    const plannedOperationKind = optionalString(planned?.operation_kind);
    if (!plannedRun || !plannedTask || !plannedJob || !plannedChecklist) {
      throwRuntimeTaskJobStateUpdateError({
        status: 502,
        code: "runtime_task_create_state_update_projection_missing",
        message:
          "Rust daemon-core task creation did not return a complete task/job/checklist projection.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          agent_id: agentId,
        },
      });
    }
    const runId = optionalString(planned?.run_id);
    const taskId = optionalString(planned?.task_id);
    const jobId = optionalString(planned?.job_id);
    if (
      optionalString(planned?.status) !== "planned" ||
      plannedOperationKind !== operationKind ||
      optionalString(planned?.agent_id) !== agentId ||
      !runId ||
      !taskId ||
      !jobId ||
      optionalString(plannedRun.id) !== runId ||
      optionalString(plannedRun.agentId) !== agentId ||
      optionalString(plannedTask.taskId) !== taskId ||
      optionalString(plannedTask.runId) !== runId ||
      optionalString(plannedTask.agentId) !== agentId ||
      optionalString(plannedJob.jobId) !== jobId ||
      optionalString(plannedJob.taskId) !== taskId ||
      optionalString(plannedJob.runId) !== runId ||
      optionalString(plannedChecklist.taskId) !== taskId ||
      optionalString(plannedChecklist.jobId) !== jobId ||
      optionalString(plannedChecklist.runId) !== runId ||
      optionalString(plannedRun.runtimeTask?.taskId) !== taskId ||
      optionalString(plannedRun.runtimeJob?.jobId) !== jobId ||
      optionalString(plannedRun.runtimeChecklist?.checklistId) !==
        optionalString(plannedChecklist.checklistId) ||
      !Array.isArray(plannedRun.events) ||
      !Array.isArray(plannedRun.receipts) ||
      !Array.isArray(plannedRun.artifacts)
    ) {
      throwRuntimeTaskJobStateUpdateError({
        status: 502,
        code: "runtime_task_create_state_update_projection_mismatch",
        message:
          "Rust daemon-core task creation projection did not match the requested public API boundary.",
        details: {
          rust_core_boundary: "runtime.task_job_control",
          operation,
          operation_kind: operationKind,
          expected_operation_kind: operationKind,
          actual_operation_kind: plannedOperationKind,
          agent_id: agentId,
          actual_agent_id: optionalString(planned?.agent_id) ?? null,
          run_id: runId ?? null,
          actual_run_id: optionalString(plannedRun.id) ?? null,
          task_id: taskId ?? null,
          actual_task_id: optionalString(plannedTask.taskId) ?? null,
          job_id: jobId ?? null,
          actual_job_id: optionalString(plannedJob.jobId) ?? null,
        },
      });
    }
    store.writeRun(plannedRun, plannedOperationKind);
    return plannedTask;
  }

  function projectRuntimeTaskJob(store, {
    operation,
    operationKind,
    projectionKind,
    options = {},
    taskId = null,
    jobId = null,
  }) {
    const runner = taskJobProjectionRunner ?? store.contextPolicyCore ?? null;
    if (typeof runner?.projectRuntimeTaskJobProjection !== "function") {
      throwRuntimeTaskJobRustCoreRequired({
        operation,
        operationKind,
        ...(taskId ? { taskId } : {}),
        ...(jobId ? { jobId } : {}),
      });
    }
    if (typeof store.listRuns !== "function") {
      throwRuntimeTaskJobStateUpdateError({
        status: 501,
        code: "runtime_task_job_projection_runs_unavailable",
        message:
          "Runtime task/job projection requires Rust Agentgres run projection candidates.",
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
      ...(optionalString(options?.agent_id) ? { agent_id: optionalString(options.agent_id) } : {}),
      ...(optionalString(options?.status) ? { status: optionalString(options.status) } : {}),
      ...(taskId ? { task_id: taskId } : {}),
      ...(jobId ? { job_id: jobId } : {}),
      runs: store.listRuns(),
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
    const runner = taskJobCancelRunner ?? store.contextPolicyCore ?? null;
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
