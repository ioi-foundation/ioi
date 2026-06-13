import { runtimeError } from "./runtime-http-utils.mjs";
import {
  eventStreamIdForThread,
  lifecycleStatusForRun,
  threadIdForAgent,
} from "./runtime-identifiers.mjs";
import {
  normalizeArray,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";
import { cancelRun } from "./runtime-run-cancellation.mjs";
import {
  RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
  normalizeSubagentRole,
  subagentContractOutputForRun,
  subagentResultForRun,
  validateSubagentOutputContract,
} from "./subagent-manager.mjs";

const retiredSubagentRecordOutputAliasKeys = new Set([
  "schemaVersion",
  "subagentId",
  "agentId",
  "childThreadId",
  "runId",
  "parentThreadId",
  "parentAgentId",
  "parentTurnId",
  "toolPack",
  "modelRouteId",
  "workflowGraphId",
  "workflowNodeId",
  "sessionBootId",
  "lifecycleStatus",
  "restartStatus",
  "restartCount",
  "forkContext",
  "contextMode",
  "maxConcurrency",
  "budgetUsageTelemetry",
  "budgetStatus",
  "budgetPolicyDecision",
  "blockReason",
  "outputContract",
  "outputContractStatus",
  "outputContractValidation",
  "mergePolicy",
  "cancellationInheritance",
  "contextPressureAction",
  "contextPressure",
  "pressure",
  "pressureStatus",
  "alertId",
  "sourceEventId",
  "sourceReceiptRefs",
  "sourcePolicyDecisionRefs",
  "createdAt",
  "updatedAt",
  "eventId",
  "receiptRefs",
  "policyDecisionRefs",
  "evidenceRefs",
  "waitEventId",
  "waitedAt",
  "inputId",
  "inputCount",
  "inputHistory",
  "inputEventId",
  "lastInput",
  "lastInputAt",
  "previousRunIds",
  "resumeId",
  "resumeHistory",
  "resumeEventId",
  "resumedAt",
  "cancellationReason",
  "cancellationInherited",
  "propagatedFromThreadId",
  "cancellationClearedAt",
  "cancellationHistory",
  "assignmentId",
  "assignmentCount",
  "assignmentHistory",
  "assignEventId",
  "assignedAt",
  "targetAgentId",
  "cancelEventId",
  "canceledAt",
]);

const runtimeSubagentReadProjectionEvidenceRefs = [
  "runtime_subagent_read_projection_rust_owned",
  "runtime_subagent_read_projection_js_facade_retired",
  "runtime_subagent_list_js_facade_retired",
  "runtime_subagent_get_js_facade_retired",
  "runtime_subagent_result_js_facade_retired",
  "agentgres_runtime_subagent_projection_truth_required",
];

const runtimeSubagentDirectControlEvidenceRefs = [
  "runtime_subagent_direct_control_rust_owned",
  "runtime_subagent_control_event_rust_owned",
  "agentgres_runtime_subagent_truth_required",
];

function withoutRetiredSubagentRecordOutputAliases(record = {}) {
  return Object.fromEntries(
    Object.entries(record).filter(([key]) => !retiredSubagentRecordOutputAliasKeys.has(key)),
  );
}

function optionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function safeControlId(value) {
  return String(value ?? "")
    .replace(/[^A-Za-z0-9_-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 64) || "control";
}

function subagentControlEvidenceRefs(operationKind) {
  if (operationKind === "subagent.wait") {
    return [
      "runtime_subagent_wait_control_rust_owned",
      "runtime_subagent_control_event_rust_owned",
      "agentgres_runtime_thread_event_truth_required",
    ];
  }
  if (operationKind === "subagent.spawn") {
    return [
      "runtime_subagent_spawn_control_rust_owned",
      "runtime_subagent_agent_create_rust_owned",
      "runtime_subagent_run_create_rust_owned",
      ...runtimeSubagentDirectControlEvidenceRefs,
    ];
  }
  if (operationKind === "subagent.assign") {
    return [
      "runtime_subagent_assign_control_rust_owned",
      ...runtimeSubagentDirectControlEvidenceRefs,
    ];
  }
  if (operationKind === "subagent.input") {
    return [
      "runtime_subagent_input_control_rust_owned",
      "runtime_subagent_run_create_rust_owned",
      ...runtimeSubagentDirectControlEvidenceRefs,
    ];
  }
  if (operationKind === "subagent.resume") {
    return [
      "runtime_subagent_resume_control_rust_owned",
      "runtime_subagent_run_create_rust_owned",
      ...runtimeSubagentDirectControlEvidenceRefs,
    ];
  }
  if (operationKind === "subagent.cancel") {
    return [
      "runtime_subagent_cancel_control_rust_owned",
      "runtime_subagent_cancel_run_rust_owned",
      ...runtimeSubagentDirectControlEvidenceRefs,
    ];
  }
  if (operationKind === "subagent.cancel.propagate") {
    return [
      "runtime_subagent_cancel_propagation_rust_owned",
      "runtime_subagent_cancel_control_rust_owned",
      "runtime_subagent_cancel_run_rust_owned",
      ...runtimeSubagentDirectControlEvidenceRefs,
    ];
  }
  return runtimeSubagentDirectControlEvidenceRefs;
}

function validProjectedSubagentRead(projectionKind, projection) {
  if (projectionKind === "list") return Array.isArray(projection);
  if (projectionKind === "get" || projectionKind === "result") {
    return projection === null || (projection && typeof projection === "object" && !Array.isArray(projection));
  }
  return false;
}

function subagentLifecycleStatus(record = {}) {
  return optionalString(record.lifecycle_status) ?? optionalString(record.status);
}

function subagentIsActiveRecord(record = {}) {
  return ["queued", "running", "waiting_for_input", "interrupted"].includes(
    subagentLifecycleStatus(record),
  );
}

function subagentCancellationPropagatesRecord(record = {}) {
  return (optionalString(record.cancellation_inheritance) ?? "propagate") === "propagate";
}

export function createRuntimeSubagentSurface({
  cancelRun: cancelRunDep = cancelRun,
  contextPolicyRunner = null,
  eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
  lifecycleStatusForRun: lifecycleStatusForRunDep = lifecycleStatusForRun,
  nowIso = () => new Date().toISOString(),
  runtimeError: runtimeErrorDep = runtimeError,
  schemaVersion = RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
  normalizeSubagentRole: normalizeSubagentRoleDep = normalizeSubagentRole,
  subagentContractOutputForRun: subagentContractOutputForRunDep = subagentContractOutputForRun,
  subagentResultForRun: subagentResultForRunDep = subagentResultForRun,
  threadIdForAgent: threadIdForAgentDep = threadIdForAgent,
  validateSubagentOutputContract: validateSubagentOutputContractDep = validateSubagentOutputContract,
} = {}) {
  function subagentProjectionRunner(store, request = {}) {
    const runner = store?.contextPolicyRunner ?? contextPolicyRunner;
    if (runner?.projectRuntimeSubagentProjection) return runner;
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_subagent_read_projection_rust_projection_missing",
      message:
        "Runtime subagent read projections require Rust daemon-core projection over Agentgres subagent truth.",
      details: {
        rust_core_boundary: "runtime.subagent_projection",
        operation: request.route_operation ?? null,
        operation_kind: request.operation_kind ?? null,
        projection_kind: request.projection_kind ?? null,
        thread_id: request.thread_id ?? null,
        subagent_id: request.subagent_id ?? null,
        role: request.role ?? null,
        source: "runtime.subagent_surface.read_projection",
        evidence_refs: runtimeSubagentReadProjectionEvidenceRefs,
      },
    });
  }

  function subagentControlRunner(store, request = {}) {
    const runner = store?.contextPolicyRunner ?? contextPolicyRunner;
    if (
      runner?.planRuntimeSubagentControl &&
      runner?.planSubagentRecordStateUpdate
    ) {
      return runner;
    }
    throw runtimeErrorDep({
      status: 501,
      code: "runtime_subagent_control_rust_projection_missing",
      message:
        "Runtime subagent controls require Rust daemon-core control planning and state planning.",
      details: {
        rust_core_boundary: "runtime.subagent_control",
        operation: request.operation ?? null,
        operation_kind: request.operation_kind ?? null,
        thread_id: request.thread_id ?? null,
        subagent_id: request.subagent_id ?? null,
        evidence_refs: [
          ...subagentControlEvidenceRefs(request.operation_kind),
        ],
      },
    });
  }

  function requiredPlannedSubagentOperationKind(stateUpdate, expectedOperationKind, details = {}) {
    const operationKind = optionalString(stateUpdate?.operation_kind);
    if (!operationKind) {
      throw runtimeErrorDep({
        status: 502,
        code: "subagent_record_state_update_operation_kind_missing",
        message: "Rust policy state-update planning did not return an operation kind.",
        details: { ...details, operation_kind: expectedOperationKind },
      });
    }
    if (operationKind !== expectedOperationKind) {
      throw runtimeErrorDep({
        status: 502,
        code: "subagent_record_state_update_operation_kind_mismatch",
        message: "Rust policy state-update planning returned an unexpected operation kind.",
        details: { ...details, expected_operation_kind: expectedOperationKind, operation_kind: operationKind },
      });
    }
    return operationKind;
  }

  function requirePlannedSubagentRecord(stateUpdate, {
    threadId,
    subagentId,
    operationKind,
  }) {
    const planned = stateUpdate?.subagent;
    if (!planned?.subagent_id) {
      throw runtimeErrorDep({
        status: 502,
        code: "subagent_record_state_update_planner_invalid",
        message: "Rust policy state-update planning did not return a subagent record.",
        details: { thread_id: threadId, subagent_id: subagentId, operation_kind: operationKind },
      });
    }
    return planned;
  }

  function planSubagentControlEvent(store, {
    threadId,
    parentAgent,
    record,
    request,
    operation,
    operationKind,
    status,
  }) {
    const runner = subagentControlRunner(store, {
      operation,
      operation_kind: operationKind,
      thread_id: threadId,
      subagent_id: record?.subagent_id ?? null,
    });
    return runner.planRuntimeSubagentControl({
      operation,
      operation_kind: operationKind,
      thread_id: threadId,
      event_stream_id: eventStreamIdForThreadDep(threadId),
      status,
      event_seed: record?.updated_at ?? nowIso(),
      parent_agent: parentAgent,
      thread: store.threadForAgent(parentAgent),
      subagent: record,
      request,
      evidence_refs: subagentControlEvidenceRefs(operationKind),
    });
  }

  function appendPlannedSubagentControlEvent(store, plannedControl) {
    if (typeof store.appendRuntimeEvent !== "function") {
      throw runtimeErrorDep({
        status: 501,
        code: "runtime_subagent_control_event_admission_missing",
        message: "Subagent control events require Rust Agentgres runtime-event admission.",
        details: {
          rust_core_boundary: "runtime.subagent_control_event",
          operation_kind: plannedControl?.operation_kind ?? null,
        },
      });
    }
    return store.appendRuntimeEvent(plannedControl.event);
  }

  function subagentRecordAgentId(record, { threadId, subagentId, operationKind }) {
    const agentId = optionalString(record?.agent_id);
    if (!agentId) {
      throw runtimeErrorDep({
        status: 500,
        code: "subagent_record_agent_id_required",
        message: "Subagent lifecycle controls require a canonical agent_id on the Rust-projected subagent record.",
        details: { thread_id: threadId, subagent_id: subagentId, operation_kind: operationKind },
      });
    }
    return agentId;
  }

  function createSubagentAgent(store, {
    parentAgent,
    modelRouteId = null,
    operationKind,
    threadId,
  }) {
    const agentCreateSurface = store?.agentRunLifecycleSurface;
    if (typeof agentCreateSurface?.createAgent !== "function") {
      throw runtimeErrorDep({
        status: 501,
        code: "runtime_subagent_agent_create_rust_core_required",
        message: "Subagent spawn requires Rust-owned child-agent creation.",
        details: {
          rust_core_boundary: "runtime.subagent_control.agent_create",
          operation_kind: operationKind,
          thread_id: threadId,
          parent_agent_id: parentAgent?.id ?? null,
          evidence_refs: [
            "runtime_subagent_agent_create_rust_owned",
            "runtime_agent_create_js_facade_retired",
            "agentgres_agent_create_state_truth_required",
          ],
        },
      });
    }
    const agent = agentCreateSurface.createAgent(store, {
      local: { cwd: parentAgent?.cwd ?? store?.defaultCwd },
      model: {
        id: parentAgent?.requestedModelId ?? parentAgent?.modelId ?? "auto",
        route_id: modelRouteId ?? parentAgent?.modelRouteId ?? "route.local-first",
      },
    });
    if (!optionalString(agent?.id)) {
      throw runtimeErrorDep({
        status: 502,
        code: "runtime_subagent_agent_create_invalid",
        message: "Rust-owned child-agent creation did not return an agent projection.",
        details: {
          rust_core_boundary: "runtime.subagent_control.agent_create",
          operation_kind: operationKind,
          thread_id: threadId,
          parent_agent_id: parentAgent?.id ?? null,
        },
      });
    }
    return agent;
  }

  function createSubagentRun(store, {
    agentId,
    prompt,
    role,
    request = {},
    modelRouteId = null,
    operationKind,
    threadId,
    subagentId,
  }) {
    const runCreateSurface = store?.agentRunLifecycleSurface;
    if (typeof runCreateSurface?.createRun !== "function") {
      throw runtimeErrorDep({
        status: 501,
        code: "runtime_subagent_run_create_rust_core_required",
        message: "Subagent input and resume require Rust-owned child-agent run creation.",
        details: {
          rust_core_boundary: "runtime.subagent_control.run_create",
          operation_kind: operationKind,
          thread_id: threadId,
          subagent_id: subagentId,
          agent_id: agentId,
          evidence_refs: [
            "runtime_subagent_run_create_rust_owned",
            "runtime_run_create_js_facade_retired",
            "agentgres_run_create_state_truth_required",
          ],
        },
      });
    }
    const run = runCreateSurface.createRun(store, agentId, {
      mode: "send",
      prompt,
      options: {
        receiver: role,
        memory: request.memory ?? request.options?.memory ?? {},
        ...(modelRouteId ? { model: { id: "auto", route_id: modelRouteId } } : {}),
      },
    });
    if (!optionalString(run?.id)) {
      throw runtimeErrorDep({
        status: 502,
        code: "runtime_subagent_run_create_invalid",
        message: "Rust-owned child-agent run creation did not return a run projection.",
        details: {
          rust_core_boundary: "runtime.subagent_control.run_create",
          operation_kind: operationKind,
          thread_id: threadId,
          subagent_id: subagentId,
          agent_id: agentId,
        },
      });
    }
    return run;
  }

  function candidateSubagentProjectionFacts(store) {
    const subagentValues = store?.subagents?.values;
    const runValues = store?.runs?.values;
    if (typeof subagentValues !== "function" || typeof runValues !== "function") {
      throw runtimeErrorDep({
        status: 500,
        code: "runtime_subagent_read_projection_candidates_missing",
        message: "Runtime subagent read projection candidates are unavailable.",
        details: {
          rust_core_boundary: "runtime.subagent_projection",
          source: "runtime.subagent_surface.read_projection",
        },
      });
    }
    return {
      subagents: Array.from(subagentValues.call(store.subagents)),
      runs: Array.from(runValues.call(store.runs)),
    };
  }

  function projectSubagentRead(store, projectionKind, {
    routeOperation,
    threadId,
    subagentId = null,
    role = null,
  } = {}) {
    const operationKind = `runtime.subagent_projection.${projectionKind}`;
    const requestContext = {
      route_operation: routeOperation,
      operation_kind: operationKind,
      projection_kind: projectionKind,
      thread_id: threadId,
      subagent_id: subagentId,
      role,
    };
    const runner = subagentProjectionRunner(store, requestContext);
    const projection = candidateSubagentProjectionFacts(store);
    const request = {
      operation: "runtime_subagent_projection",
      operation_kind: operationKind,
      projection_kind: projectionKind,
      thread_id: threadId,
      subagent_id: subagentId,
      role,
      source: "runtime.subagent_surface.read_projection",
      projection,
      evidence_refs: runtimeSubagentReadProjectionEvidenceRefs,
    };
    const result = runner.projectRuntimeSubagentProjection(request);
    if (
      result?.projection_kind !== projectionKind ||
      !validProjectedSubagentRead(projectionKind, result?.projection)
    ) {
      throw runtimeErrorDep({
        status: 502,
        code: "runtime_subagent_read_projection_rust_projection_invalid",
        message: "Rust subagent projection returned an invalid route projection.",
        details: {
          rust_core_boundary: "runtime.subagent_projection",
          expected_projection_kind: projectionKind,
          actual_projection_kind: result?.projection_kind ?? null,
          operation: request.operation,
          operation_kind: request.operation_kind,
          source: "runtime.subagent_surface.read_projection",
        },
      });
    }
    return result.projection;
  }

  function commitSubagentControlRecord(store, {
    threadId,
    subagentId,
    operation,
    operationKind,
    updated,
    request,
    status,
    evidenceRefs = [],
    run = null,
    eventField,
  }) {
    const plannedControl = planSubagentControlEvent(store, {
      threadId,
      parentAgent: store.agentForThread(threadId),
      record: updated,
      request,
      operation,
      operationKind,
      status,
    });
    const event = appendPlannedSubagentControlEvent(store, plannedControl);
    const runReceiptRefs = normalizeArray(run?.receipts).map((receipt) => receipt.id);
    const saved = withoutRetiredSubagentRecordOutputAliases({
      ...updated,
      ...(eventField ? { [eventField]: event.event_id } : {}),
      receipt_refs: uniqueStrings([
        ...normalizeArray(updated.receipt_refs),
        ...runReceiptRefs,
        ...normalizeArray(event.receipt_refs),
      ]),
      evidence_refs: uniqueStrings([
        ...normalizeArray(updated.evidence_refs),
        ...evidenceRefs,
        event.event_id,
      ]),
      updated_at: event.created_at,
    });
    if (run) {
      const output = subagentContractOutputForRunDep(run, saved.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        saved.output_contract,
      );
      saved.result = subagentResultForRunDep({ record: saved, run, output, outputContractStatus });
    }
    const runner = subagentControlRunner(store, {
      operation,
      operation_kind: operationKind,
      thread_id: threadId,
      subagent_id: subagentId,
    });
    const stateUpdate = runner.planSubagentRecordStateUpdate({
      operation_kind: operationKind,
      thread_id: threadId,
      subagent: saved,
    });
    const planned = requirePlannedSubagentRecord(stateUpdate, {
      threadId,
      subagentId,
      operationKind,
    });
    store.writeSubagent(
      planned,
      requiredPlannedSubagentOperationKind(stateUpdate, operationKind, {
        thread_id: threadId,
        subagent_id: subagentId,
      }),
    );
    return { event, planned };
  }

  return {
    listSubagents(store, threadId, options = {}) {
      return projectSubagentRead(store, "list", {
        routeOperation: "runtime_subagent_list",
        threadId,
        role: optionalString(options.role),
      });
    },
    getSubagent(store, threadId, subagentId) {
      return projectSubagentRead(store, "get", {
        routeOperation: "runtime_subagent_get",
        threadId,
        subagentId: optionalString(subagentId),
      });
    },
    spawnSubagent(store, threadId, request = {}) {
      const operationKind = "subagent.spawn";
      subagentControlRunner(store, {
        operation: "spawn",
        operation_kind: operationKind,
        thread_id: threadId,
      });
      const prompt = optionalString(request.prompt);
      if (!prompt) {
        throw runtimeErrorDep({
          status: 400,
          code: "runtime_subagent_spawn_prompt_required",
          message: "Subagent spawn requires canonical prompt text.",
          details: { thread_id: threadId, operation_kind: operationKind },
        });
      }
      const parentAgent = store.agentForThread(threadId);
      const parentThread = store.threadForAgent(parentAgent);
      const role = normalizeSubagentRoleDep(request.role);
      const modelRouteId =
        optionalString(request.model_route_id) ??
        parentAgent?.modelRouteId ??
        "route.local-first";
      const childAgent = createSubagentAgent(store, {
        parentAgent,
        modelRouteId,
        operationKind,
        threadId,
      });
      const subagentId = childAgent.id;
      const childThreadId = threadIdForAgentDep(childAgent.id);
      const run = createSubagentRun(store, {
        agentId: childAgent.id,
        prompt,
        role,
        request,
        modelRouteId,
        operationKind,
        threadId,
        subagentId,
      });
      const outputContract = request.output_contract ?? null;
      const output = subagentContractOutputForRunDep(run, outputContract);
      const outputContractStatus = validateSubagentOutputContractDep(output, outputContract);
      const lifecycleStatus = lifecycleStatusForRunDep(run.status);
      const createdAt = nowIso();
      const record = withoutRetiredSubagentRecordOutputAliases({
        schema_version: schemaVersion,
        object: "ioi.runtime_subagent",
        subagent_id: subagentId,
        agent_id: childAgent.id,
        child_thread_id: childThreadId,
        run_id: run.id,
        parent_thread_id: threadId,
        parent_agent_id: parentAgent?.id ?? null,
        parent_turn_id:
          optionalString(request.parent_turn_id) ??
          optionalString(parentThread?.latest_turn_id),
        role,
        tool_pack: optionalString(request.tool_pack),
        model_route_id: modelRouteId,
        workflow_graph_id: optionalString(request.workflow_graph_id),
        workflow_node_id: optionalString(request.workflow_node_id),
        lifecycle_status: lifecycleStatus,
        status: lifecycleStatus,
        restart_status: "not_restarted",
        restart_count: 0,
        fork_context: request.fork_context === true,
        context_mode: optionalString(request.context_mode) ?? "forked",
        output_contract: outputContract,
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        merge_policy: optionalString(request.merge_policy) ?? "manual",
        cancellation_inheritance:
          optionalString(request.cancellation_inheritance) ?? "propagate",
        source_event_id: optionalString(request.source_event_id),
        source_receipt_refs: normalizeArray(request.receipt_refs),
        source_policy_decision_refs: normalizeArray(request.policy_decision_refs),
        created_at: createdAt,
        updated_at: createdAt,
        receipt_refs: uniqueStrings([
          ...normalizeArray(run.receipts).map((receipt) => receipt.id),
          ...normalizeArray(request.receipt_refs),
        ]),
        policy_decision_refs: uniqueStrings(normalizeArray(request.policy_decision_refs)),
        evidence_refs: uniqueStrings([
          "runtime_subagent_spawn_control_rust_owned",
          "runtime_subagent_agent_create_rust_owned",
          "runtime_subagent_run_create_rust_owned",
          "runtime.subagent.spawn",
          childAgent.id,
          run.id,
        ]),
      });
      record.result = subagentResultForRunDep({ record, run, output, outputContractStatus });
      const { event, planned } = commitSubagentControlRecord(store, {
        threadId,
        subagentId,
        operation: "spawn",
        operationKind,
        updated: record,
        request,
        status: record.status,
        evidenceRefs: ["runtime.subagent.spawn", childAgent.id, run.id],
        run,
        eventField: "event_id",
      });
      return {
        ...this.subagentProjection(planned),
        result: planned.result,
        event,
      };
    },
    waitSubagent(store, threadId, subagentId, request = {}) {
      const operationKind = "subagent.wait";
      const record = this.getSubagent(store, threadId, subagentId);
      const run = store.getRun(record.run_id);
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      const previousLifecycleStatus = record.lifecycle_status ?? record.status;
      const lifecycleStatus =
        previousLifecycleStatus === "blocked" ? "blocked" : lifecycleStatusForRunDep(run.status);
      const waitedAt = nowIso();
      const updated = withoutRetiredSubagentRecordOutputAliases({
        ...record,
        lifecycle_status: lifecycleStatus,
        status: lifecycleStatus,
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        waited_at: waitedAt,
        updated_at: waitedAt,
      });
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const plannedControl = planSubagentControlEvent(store, {
        threadId,
        parentAgent: store.agentForThread(threadId),
        record: updated,
        request,
        operation: "wait",
        operationKind,
        status: updated.status,
      });
      const event = appendPlannedSubagentControlEvent(store, plannedControl);
      const saved = withoutRetiredSubagentRecordOutputAliases({
        ...updated,
        wait_event_id: event.event_id,
        receipt_refs: uniqueStrings([
          ...normalizeArray(updated.receipt_refs),
          ...normalizeArray(event.receipt_refs),
        ]),
        evidence_refs: uniqueStrings([
          ...normalizeArray(updated.evidence_refs),
          "runtime.subagent.wait",
          event.event_id,
        ]),
        updated_at: event.created_at,
      });
      saved.result = subagentResultForRunDep({ record: saved, run, output, outputContractStatus });
      const runner = subagentControlRunner(store, {
        operation: "wait",
        operation_kind: operationKind,
        thread_id: threadId,
        subagent_id: subagentId,
      });
      const stateUpdate = runner.planSubagentRecordStateUpdate({
        operation_kind: operationKind,
        thread_id: threadId,
        subagent: saved,
      });
      const planned = requirePlannedSubagentRecord(stateUpdate, {
        threadId,
        subagentId,
        operationKind,
      });
      store.writeSubagent(
        planned,
        requiredPlannedSubagentOperationKind(stateUpdate, operationKind, {
          thread_id: threadId,
          subagent_id: subagentId,
        }),
      );
      return {
        ...planned.result,
        subagent: this.subagentProjection(planned),
        event,
        receipt_refs: event.receipt_refs,
      };
    },
    getSubagentResult(store, threadId, subagentId) {
      return projectSubagentRead(store, "result", {
        routeOperation: "runtime_subagent_result",
        threadId,
        subagentId: optionalString(subagentId),
      });
    },
    sendSubagentInput(store, threadId, subagentId, request = {}) {
      const operationKind = "subagent.input";
      const record = this.getSubagent(store, threadId, subagentId);
      if ((record.lifecycle_status ?? record.status) === "canceled") {
        throw runtimeErrorDep({
          status: 403,
          code: "runtime_subagent_input_canceled",
          message: "Cannot send input to a canceled subagent.",
          details: { thread_id: threadId, subagent_id: subagentId, operation_kind: operationKind },
        });
      }
      const message = optionalString(request.input);
      if (!message) {
        throw runtimeErrorDep({
          status: 400,
          code: "runtime_subagent_input_message_required",
          message: "Subagent input requires canonical input text.",
          details: { thread_id: threadId, subagent_id: subagentId, operation_kind: operationKind },
        });
      }
      const agentId = subagentRecordAgentId(record, { threadId, subagentId, operationKind });
      const previousRunId = optionalString(record.run_id);
      const role = record.role ?? "general";
      const run = createSubagentRun(store, {
        agentId,
        prompt: message,
        role,
        request,
        modelRouteId: optionalString(record.model_route_id),
        operationKind,
        threadId,
        subagentId,
      });
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      const now = nowIso();
      const inputId =
        optionalString(request.input_id) ??
        `subagent_input_${safeControlId(`${threadId}_${subagentId}_${now}`)}`;
      const inputRecord = {
        schema_version: "ioi.runtime.subagent-input.v1",
        input_id: inputId,
        message,
        run_id: run.id,
        previous_run_id: previousRunId ?? null,
        created_at: now,
        actor: optionalString(request.actor) ?? "operator",
        source: optionalString(request.source) ?? "agent_studio",
        workflow_graph_id: optionalString(request.workflow_graph_id),
        workflow_node_id: optionalString(request.workflow_node_id),
      };
      const inputHistory = [...normalizeArray(record.input_history), inputRecord];
      const lifecycleStatus = lifecycleStatusForRunDep(run.status);
      const updated = withoutRetiredSubagentRecordOutputAliases({
        ...record,
        run_id: run.id,
        previous_run_id: previousRunId ?? null,
        previous_run_ids: uniqueStrings([
          ...normalizeArray(record.previous_run_ids),
          ...(previousRunId ? [previousRunId] : []),
        ]),
        lifecycle_status: lifecycleStatus,
        status: lifecycleStatus,
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        input_id: inputId,
        input_count: inputHistory.length,
        input_history: inputHistory,
        last_input: message,
        last_input_at: now,
        updated_at: now,
      });
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const { event, planned } = commitSubagentControlRecord(store, {
        threadId,
        subagentId,
        operation: "send_input",
        operationKind,
        updated,
        request,
        status: updated.status,
        evidenceRefs: ["runtime.subagent.input", run.id],
        run,
        eventField: "input_event_id",
      });
      return {
        ...this.subagentProjection(planned),
        input: inputRecord,
        result: planned.result,
        event,
      };
    },
    resumeSubagent(store, threadId, subagentId, request = {}) {
      const operationKind = "subagent.resume";
      const record = this.getSubagent(store, threadId, subagentId);
      const agentId = subagentRecordAgentId(record, { threadId, subagentId, operationKind });
      const previousRunId = optionalString(record.run_id);
      const previousStatus = record.lifecycle_status ?? record.status ?? null;
      const role = normalizeSubagentRoleDep(request.role ?? record.role);
      const modelRouteId =
        optionalString(request.model_route_id) ??
        record.model_route_id ??
        "route.local-first";
      const prompt = optionalString(request.prompt) ?? `Resume subagent ${role}.`;
      const run = createSubagentRun(store, {
        agentId,
        prompt,
        role,
        request,
        modelRouteId,
        operationKind,
        threadId,
        subagentId,
      });
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      const now = nowIso();
      const resumeId =
        optionalString(request.resume_id) ??
        `subagent_resume_${safeControlId(`${threadId}_${subagentId}_${now}`)}`;
      const restartCount = Number(record.restart_count ?? 0) + 1;
      const resumeRecord = {
        schema_version: "ioi.runtime.subagent-resume.v1",
        resume_id: resumeId,
        run_id: run.id,
        previous_run_id: previousRunId ?? null,
        previous_status: previousStatus,
        prompt,
        role,
        model_route_id: modelRouteId,
        restart_count: restartCount,
        created_at: now,
        actor: optionalString(request.actor) ?? "operator",
        source: optionalString(request.source) ?? "agent_studio",
        workflow_graph_id: optionalString(request.workflow_graph_id),
        workflow_node_id: optionalString(request.workflow_node_id),
      };
      const resumeHistory = [...normalizeArray(record.resume_history), resumeRecord];
      const cancellationHistory = [
        ...normalizeArray(record.cancellation_history),
        ...(record.cancellation ? [record.cancellation] : []),
      ];
      const lifecycleStatus = lifecycleStatusForRunDep(run.status);
      const updated = withoutRetiredSubagentRecordOutputAliases({
        ...record,
        role,
        run_id: run.id,
        previous_run_id: previousRunId ?? null,
        previous_run_ids: uniqueStrings([
          ...normalizeArray(record.previous_run_ids),
          ...(previousRunId ? [previousRunId] : []),
        ]),
        model_route_id: modelRouteId,
        lifecycle_status: lifecycleStatus,
        status: lifecycleStatus,
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        restart_status: "restarted",
        restart_count: restartCount,
        resume_id: resumeId,
        resumed_at: now,
        resume_history: resumeHistory,
        cancellation: null,
        cancellation_reason: null,
        cancellation_cleared_at: now,
        cancellation_history: cancellationHistory,
        updated_at: now,
      });
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const { event, planned } = commitSubagentControlRecord(store, {
        threadId,
        subagentId,
        operation: "resume",
        operationKind,
        updated,
        request,
        status: updated.status,
        evidenceRefs: ["runtime.subagent.resume", run.id],
        run,
        eventField: "resume_event_id",
      });
      return {
        ...planned.result,
        subagent: this.subagentProjection(planned),
        resume: resumeRecord,
        event,
        receipt_refs: event.receipt_refs,
      };
    },
    assignSubagent(store, threadId, subagentId, request = {}) {
      const operationKind = "subagent.assign";
      const record = this.getSubagent(store, threadId, subagentId);
      const previousRole = record.role ?? "general";
      const role = normalizeSubagentRoleDep(request.role ?? previousRole);
      const now = nowIso();
      const assignmentCount = Number(record.assignment_count ?? 0) + 1;
      const assignmentId =
        optionalString(request.assignment_id) ??
        `subagent_assignment_${safeControlId(`${threadId}_${subagentId}_${now}`)}`;
      const run = store.getRun(record.run_id);
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      const assignment = {
        schema_version: "ioi.runtime.subagent-assignment.v1",
        assignment_id: assignmentId,
        previous_role: previousRole,
        role,
        target_agent_id: optionalString(request.target_agent_id) ?? record.agent_id ?? null,
        tool_pack: optionalString(request.tool_pack) ?? record.tool_pack ?? null,
        model_route_id: optionalString(request.model_route_id) ?? record.model_route_id ?? null,
        merge_policy: optionalString(request.merge_policy) ?? record.merge_policy ?? "manual",
        cancellation_inheritance:
          optionalString(request.cancellation_inheritance) ??
          record.cancellation_inheritance ??
          "propagate",
        assignment_count: assignmentCount,
        created_at: now,
        actor: optionalString(request.actor) ?? "operator",
        source: optionalString(request.source) ?? "agent_studio",
        workflow_graph_id: optionalString(request.workflow_graph_id),
        workflow_node_id: optionalString(request.workflow_node_id),
      };
      const updated = withoutRetiredSubagentRecordOutputAliases({
        ...record,
        role,
        target_agent_id: assignment.target_agent_id,
        tool_pack: assignment.tool_pack,
        model_route_id: assignment.model_route_id,
        merge_policy: assignment.merge_policy,
        cancellation_inheritance: assignment.cancellation_inheritance,
        assignment_id: assignmentId,
        assignment_count: assignmentCount,
        assignment_history: [...normalizeArray(record.assignment_history), assignment],
        assigned_at: now,
        lifecycle_status: record.lifecycle_status ?? record.status ?? "running",
        status: record.status ?? record.lifecycle_status ?? "running",
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        updated_at: now,
      });
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const { event, planned } = commitSubagentControlRecord(store, {
        threadId,
        subagentId,
        operation: "assign",
        operationKind,
        updated,
        request,
        status: updated.status,
        evidenceRefs: ["runtime.subagent.assign", assignmentId],
        run,
        eventField: "assign_event_id",
      });
      return {
        ...this.subagentProjection(planned),
        assignment,
        result: planned.result,
        event,
      };
    },
    cancelSubagent(store, threadId, subagentId, request = {}) {
      const operationKind = "subagent.cancel";
      const record = this.getSubagent(store, threadId, subagentId);
      if (!record.run_id) {
        throw runtimeErrorDep({
          status: 502,
          code: "runtime_subagent_cancel_run_id_required",
          message: "Subagent cancellation requires a Rust-owned run cancellation target.",
          details: { thread_id: threadId, subagent_id: subagentId, operation_kind: operationKind },
        });
      }
      const previousStatus = record.lifecycle_status ?? record.status ?? null;
      const reason =
        optionalString(request.reason ?? request.cancellation_reason) ??
        "operator_cancel";
      const canceledAt = nowIso();
      const run = cancelRunDep(store, record.run_id);
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      const cancellation = {
        reason,
        previous_status: previousStatus,
        requested_by: optionalString(request.actor) ?? "operator",
        inherited: request.inherited === true,
        propagated_from_thread_id: optionalString(request.propagated_from_thread_id),
        source: optionalString(request.source) ?? "agent_studio",
      };
      const updated = withoutRetiredSubagentRecordOutputAliases({
        ...record,
        lifecycle_status: "canceled",
        status: "canceled",
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        canceled_at: canceledAt,
        cancellation_reason: reason,
        cancellation_inherited: cancellation.inherited,
        propagated_from_thread_id: cancellation.propagated_from_thread_id,
        cancellation,
        updated_at: canceledAt,
      });
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const { event, planned } = commitSubagentControlRecord(store, {
        threadId,
        subagentId,
        operation: "cancel",
        operationKind,
        updated,
        request,
        status: "canceled",
        evidenceRefs: ["runtime.subagent.cancel", run.id],
        run,
        eventField: "cancel_event_id",
      });
      return {
        ...planned.result,
        subagent: this.subagentProjection(planned),
        event,
        cancellation: planned.cancellation,
        receipt_refs: event.receipt_refs,
      };
    },
    propagateSubagentCancellation(store, threadId, request = {}) {
      const operationKind = "subagent.cancel.propagate";
      subagentControlRunner(store, {
        operation: "cancel",
        operation_kind: operationKind,
        thread_id: threadId,
      });
      const parentAgent = store.agentForThread(threadId);
      const source = optionalString(request.source) ?? "agent_studio";
      const reason =
        optionalString(request.reason ?? request.cancellation_reason) ??
        "parent_cancel";
      const candidates = this.listSubagents(store, threadId);
      const canceledSubagents = [];
      const skippedSubagents = [];
      const eventRefs = [];
      const receiptRefs = [];
      for (const candidate of candidates) {
        const candidateProjection = this.subagentProjection(candidate);
        const subagentId = optionalString(candidateProjection.subagent_id);
        if (
          !subagentId ||
          !subagentIsActiveRecord(candidateProjection) ||
          !subagentCancellationPropagatesRecord(candidateProjection) ||
          !optionalString(candidateProjection.run_id)
        ) {
          skippedSubagents.push(candidateProjection);
          continue;
        }
        const record = this.getSubagent(store, threadId, subagentId);
        const previousStatus = record.lifecycle_status ?? record.status ?? null;
        const canceledAt = nowIso();
        const run = cancelRunDep(store, record.run_id);
        const output = subagentContractOutputForRunDep(run, record.output_contract);
        const outputContractStatus = validateSubagentOutputContractDep(
          output,
          record.output_contract,
        );
        const cancellation = {
          reason,
          previous_status: previousStatus,
          requested_by: optionalString(request.actor) ?? "operator",
          inherited: true,
          propagated_from_thread_id: threadId,
          source,
        };
        const updated = withoutRetiredSubagentRecordOutputAliases({
          ...record,
          lifecycle_status: "canceled",
          status: "canceled",
          output_contract_status: outputContractStatus.status,
          output_contract_validation: outputContractStatus,
          canceled_at: canceledAt,
          cancellation_reason: reason,
          cancellation_inherited: true,
          propagated_from_thread_id: threadId,
          cancellation,
          updated_at: canceledAt,
        });
        updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
        const { event, planned } = commitSubagentControlRecord(store, {
          threadId,
          subagentId,
          operation: "cancel",
          operationKind,
          updated,
          request: {
            ...request,
            source,
            reason,
            cancellation_reason: reason,
            inherited: true,
            propagated_from_thread_id: threadId,
          },
          status: "canceled",
          evidenceRefs: ["runtime.subagent.cancel.propagate", run.id],
          run,
          eventField: "cancel_event_id",
        });
        canceledSubagents.push(this.subagentProjection(planned));
        eventRefs.push(event.event_id);
        receiptRefs.push(...normalizeArray(event.receipt_refs));
      }
      return {
        schema_version: "ioi.runtime.subagent-cancellation-propagation.v1",
        object: "ioi.runtime_subagent_cancellation_propagation",
        thread_id: threadId,
        parent_agent_id: parentAgent?.id ?? null,
        status: canceledSubagents.length > 0 ? "propagated" : "noop",
        source,
        reason,
        propagation_policy: "propagate",
        candidate_count: candidates.length,
        canceled_count: canceledSubagents.length,
        skipped_count: skippedSubagents.length,
        canceled_subagents: canceledSubagents,
        skipped_subagents: skippedSubagents,
        event_refs: uniqueStrings(eventRefs),
        receipt_refs: uniqueStrings(receiptRefs),
      };
    },
    subagentProjection(record = {}) {
      const projection = withoutRetiredSubagentRecordOutputAliases(record);
      return {
        ...projection,
        schema_version: projection.schema_version ?? schemaVersion,
        object: projection.object ?? "ioi.runtime_subagent",
        output_contract_status:
          projection.output_contract_status ??
          projection.output_contract_validation?.status ??
          null,
      };
    },
    appendThreadSubagentControlEvent(store, {
      threadId,
      parentAgent,
      record,
      request,
      operation,
      status,
    }) {
      const normalizedOperation = optionalString(operation) ?? "control";
      const operationKind = `subagent.${normalizedOperation}`;
      const plannedControl = planSubagentControlEvent(store, {
        threadId,
        parentAgent: parentAgent ?? store.agentForThread(threadId),
        record,
        request,
        operation: normalizedOperation,
        operationKind,
        status,
      });
      return appendPlannedSubagentControlEvent(store, plannedControl);
    },
  };
}
