import {
  eventStreamIdForThread,
  fixtureProfileForAgent,
  lifecycleStatusForRun,
  runtimeSessionIdForAgent,
  threadIdForAgent,
} from "./runtime-identifiers.mjs";
import { notFound, policyError, runtimeError } from "./runtime-http-utils.mjs";
import { contextBudgetNumber } from "./threads/context-budget-policy.mjs";
import {
  doctorHash,
  normalizeArray,
  operatorControlSource,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";
import {
  RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
  normalizeSubagentOutputContract,
  normalizeSubagentRole,
  optionalPositiveInteger,
  subagentBudgetForRequest,
  subagentBudgetStatusForRun,
  subagentBudgetUsageTelemetryForRequest,
  subagentContractOutputForRun,
  subagentIsActive,
  subagentManagerEventPayload,
  subagentOperatorControlKind,
  subagentResultForRun,
  subagentRuntimeEventKind,
  validateSubagentOutputContract,
} from "./subagent-manager.mjs";

function withoutRetiredSubagentUsageTelemetry(record = {}) {
  const { usageTelemetry: _retiredUsageTelemetry, ...canonicalRecord } = record;
  return canonicalRecord;
}

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

function withoutRetiredSubagentRecordOutputAliases(record = {}) {
  return Object.fromEntries(
    Object.entries(record).filter(([key]) => !retiredSubagentRecordOutputAliasKeys.has(key)),
  );
}

export function createRuntimeSubagentSurface({
  eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
  fixtureProfileForAgent: fixtureProfileForAgentDep = fixtureProfileForAgent,
  contextBudgetNumber: contextBudgetNumberDep = contextBudgetNumber,
  notFound: notFoundDep = notFound,
  nowMs = () => Date.now(),
  nowIso = () => new Date().toISOString(),
  normalizeSubagentOutputContract: normalizeSubagentOutputContractDep = normalizeSubagentOutputContract,
  operatorControlSource: operatorControlSourceDep = operatorControlSource,
  optionalPositiveInteger: optionalPositiveIntegerDep = optionalPositiveInteger,
  optionalString: optionalStringDep = optionalString,
  policyError: policyErrorDep = policyError,
  runtimeError: runtimeErrorDep = runtimeError,
  runtimeSessionIdForAgent: runtimeSessionIdForAgentDep = runtimeSessionIdForAgent,
  safeId: safeIdDep = safeId,
  schemaVersion = RUNTIME_SUBAGENT_MANAGER_SCHEMA_VERSION,
  threadIdForAgent: threadIdForAgentDep = threadIdForAgent,
  lifecycleStatusForRun: lifecycleStatusForRunDep = lifecycleStatusForRun,
  normalizeSubagentRole: normalizeSubagentRoleDep = normalizeSubagentRole,
  subagentBudgetForRequest: subagentBudgetForRequestDep = subagentBudgetForRequest,
  subagentBudgetStatusForRun: subagentBudgetStatusForRunDep = subagentBudgetStatusForRun,
  subagentBudgetUsageTelemetryForRequest: subagentBudgetUsageTelemetryForRequestDep = subagentBudgetUsageTelemetryForRequest,
  subagentContractOutputForRun: subagentContractOutputForRunDep = subagentContractOutputForRun,
  subagentIsActive: subagentIsActiveDep = subagentIsActive,
  subagentManagerEventPayload: subagentManagerEventPayloadDep = subagentManagerEventPayload,
  subagentOperatorControlKind: subagentOperatorControlKindDep = subagentOperatorControlKind,
  subagentResultForRun: subagentResultForRunDep = subagentResultForRun,
  subagentRuntimeEventKind: subagentRuntimeEventKindDep = subagentRuntimeEventKind,
  validateSubagentOutputContract: validateSubagentOutputContractDep = validateSubagentOutputContract,
  uniqueStrings: uniqueStringsDep = uniqueStrings,
} = {}) {
  return {
    listSubagents(store, threadId, options = {}) {
      const parentAgent = store.agentForThread(threadId);
      const role = optionalStringDep(options.role ?? options.subagent_role);
      const subagents = [...store.subagents.values()]
        .filter((record) => record.parent_thread_id === threadId)
        .filter((record) => !role || record.role === role)
        .sort((left, right) =>
          String(left.created_at ?? "").localeCompare(
            String(right.created_at ?? ""),
          ),
        )
        .map((record) => this.subagentProjection(record));
      return {
        schema_version: schemaVersion,
        object: "ioi.runtime_subagent_list",
        thread_id: threadId,
        parent_agent_id: parentAgent.id,
        status: "ready",
        count: subagents.length,
        active_count: subagents.filter((record) => subagentIsActiveDep(record)).length,
        subagents,
      };
    },
    getSubagent(store, threadId, subagentId) {
      const record = store.subagents.get(subagentId);
      if (!record || record.parent_thread_id !== threadId) {
        throw notFoundDep(`Subagent not found: ${subagentId}`, {
          thread_id: threadId,
          subagent_id: subagentId,
        });
      }
      return record;
    },
    spawnSubagent(store, threadId, request = {}) {
      const parentAgent = store.agentForThread(threadId);
      const parentThread = store.threadForAgent(parentAgent);
      const prompt = optionalStringDep(request.prompt);
      if (!prompt) {
        throw runtimeErrorDep({
          status: 400,
          code: "subagent_prompt_required",
          message: "Subagent spawn requires a prompt.",
          details: { thread_id: threadId },
        });
      }
      const role = normalizeSubagentRoleDep(request.role ?? request.subagent_role);
      const maxConcurrency = optionalPositiveIntegerDep(
        request.max_concurrency,
      );
      if (maxConcurrency) {
        const activeForRole = this.listSubagents(store, threadId, { role }).subagents
          .filter(subagentIsActiveDep).length;
        if (activeForRole >= maxConcurrency) {
          throw policyErrorDep("Subagent role concurrency limit reached.", {
            thread_id: threadId,
            role,
            active_for_role: activeForRole,
            max_concurrency: maxConcurrency,
          });
        }
      }

      const modelRouteId =
        optionalStringDep(request.model_route_id) ??
        parentAgent.modelRouteId ??
        "route.local-first";
      const childAgent = store.createAgent({
        local: { cwd: parentAgent.cwd },
        model: {
          id: parentAgent.requestedModelId ?? parentAgent.modelId ?? "auto",
          routeId: parentAgent.modelRouteId ?? "route.local-first",
        },
      });
      const run = store.createRun(childAgent.id, {
        mode: "send",
        prompt,
        options: {
          receiver: role,
          memory: request.memory ?? request.options?.memory ?? {},
        },
      });
      const now = nowIso();
      const subagentId = childAgent.id;
      const outputContract = normalizeSubagentOutputContractDep(
        request.output_contract,
      );
      const output = subagentContractOutputForRunDep(run, outputContract);
      const outputContractStatus = validateSubagentOutputContractDep(output, outputContract);
      const budget = subagentBudgetForRequestDep(request);
      const budgetUsageTelemetry = subagentBudgetUsageTelemetryForRequestDep(request);
      const budgetStatus = subagentBudgetStatusForRunDep({
        budget,
        run,
        prompt,
        previousUsage: budgetUsageTelemetry ?? {},
      });
      const subagentLifecycleStatus =
        budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRunDep(run.status);
      const workflowGraphId =
        optionalStringDep(request.workflow_graph_id) ?? null;
      const workflowNodeId =
        optionalStringDep(request.workflow_node_id) ??
        `runtime.subagent.spawn.${safeIdDep(role)}`;
      const parentTurnId =
        optionalStringDep(request.parent_turn_id ?? request.turn_id) ??
        parentThread.latest_turn_id ??
        null;
      const contextPressureAction =
        optionalStringDep(request.context_pressure_action) ?? null;
      const contextPressure = contextBudgetNumberDep(
        request.context_pressure,
        request.pressure,
      );
      const pressureStatus =
        optionalStringDep(request.pressure_status) ?? null;
      const alertId = optionalStringDep(request.alert_id) ?? null;
      const sourceEventId =
        optionalStringDep(request.source_event_id) ?? null;
      const requestReceiptRefs = uniqueStringsDep(
        request.receipt_refs,
      );
      const requestPolicyDecisionRefs = uniqueStringsDep(
        request.policy_decision_refs,
      );
      const runReceiptRefs = normalizeArray(run.receipts).map((receipt) => receipt.id);
      const record = {
        schema_version: schemaVersion,
        object: "ioi.runtime_subagent",
        subagent_id: subagentId,
        agent_id: childAgent.id,
        child_thread_id: threadIdForAgentDep(childAgent.id),
        run_id: run.id,
        parent_thread_id: threadId,
        parent_agent_id: parentAgent.id,
        parent_turn_id: parentTurnId,
        role,
        tool_pack: optionalStringDep(request.tool_pack) ?? null,
        model_route_id: modelRouteId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        session_boot_id: runtimeSessionIdForAgentDep(childAgent),
        lifecycle_status: subagentLifecycleStatus,
        status: subagentLifecycleStatus,
        restart_status: "not_restarted",
        fork_context: request.fork_context === true,
        context_mode: request.fork_context === true ? "forked" : "fresh",
        max_concurrency: maxConcurrency,
        budget,
        budget_usage_telemetry: budgetUsageTelemetry,
        budget_status: budgetStatus.status,
        usage_telemetry: budgetStatus.usage,
        budget_policy_decision: budgetStatus.policy_decision,
        block_reason: budgetStatus.status === "exceeded" ? "subagent_budget_exceeded" : null,
        output_contract: outputContract,
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        merge_policy: optionalStringDep(request.merge_policy) ?? "manual",
        cancellation_inheritance:
          optionalStringDep(request.cancellation_inheritance) ?? "propagate",
        context_pressure_action: contextPressureAction,
        context_pressure: contextPressure,
        pressure_status: pressureStatus,
        alert_id: alertId,
        source_event_id: sourceEventId,
        source_receipt_refs: requestReceiptRefs,
        source_policy_decision_refs: requestPolicyDecisionRefs,
        created_at: now,
        updated_at: now,
        result: subagentResultForRunDep({ record: null, run, output, outputContractStatus }),
        receipt_refs: uniqueStringsDep([...runReceiptRefs, ...requestReceiptRefs]),
        policy_decision_refs: requestPolicyDecisionRefs,
        evidence_refs: [
          "runtime.subagent_manager",
          "runtime.subagent.spawn",
          run.id,
          ...runReceiptRefs,
          ...requestReceiptRefs,
          ...requestPolicyDecisionRefs,
        ],
      };
      record.result = subagentResultForRunDep({ record, run, output, outputContractStatus });
      const event = store.appendThreadSubagentControlEvent({
        threadId,
        parentAgent,
        record,
        request,
        operation: "spawn",
        status: subagentLifecycleStatus,
      });
      const saved = withoutRetiredSubagentRecordOutputAliases({
        ...record,
        event_id: event.event_id,
        receipt_refs: uniqueStringsDep([...record.receipt_refs, ...event.receipt_refs]),
        updated_at: event.created_at,
      });
      saved.result = subagentResultForRunDep({
        record: saved,
        run,
        output,
        outputContractStatus,
      });
      store.writeSubagent(saved, "subagent.spawn");
      if (budgetStatus.status === "exceeded") {
        throw policyErrorDep("Subagent budget limit exceeded.", {
          thread_id: threadId,
          role,
          subagent_id: subagentId,
          reason: "subagent_budget_exceeded",
          budget_status: budgetStatus.status,
          subagent: this.subagentProjection(saved),
          event_id: event.event_id,
          receipt_refs: event.receipt_refs,
          policy_decision_refs: event.policy_decision_refs,
        });
      }
      return {
        ...this.subagentProjection(saved),
        event,
      };
    },
    waitSubagent(store, threadId, subagentId, request = {}) {
      const record = store.getSubagent(threadId, subagentId);
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
      const updated = {
        ...record,
        lifecycle_status: lifecycleStatus,
        status: lifecycleStatus,
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        waited_at: waitedAt,
      };
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const event = store.appendThreadSubagentControlEvent({
        threadId,
        parentAgent: store.agentForThread(threadId),
        record: updated,
        request,
        operation: "wait",
        status: updated.status,
      });
      const saved = withoutRetiredSubagentRecordOutputAliases({
        ...updated,
        wait_event_id: event.event_id,
        receipt_refs: uniqueStringsDep([...normalizeArray(updated.receipt_refs), ...event.receipt_refs]),
        updated_at: event.created_at,
      });
      saved.result = subagentResultForRunDep({ record: saved, run, output, outputContractStatus });
      store.writeSubagent(saved, "subagent.wait");
      return {
        ...saved.result,
        subagent: this.subagentProjection(saved),
        event,
        receipt_refs: event.receipt_refs,
      };
    },
    getSubagentResult(store, threadId, subagentId) {
      const record = store.getSubagent(threadId, subagentId);
      const run = store.getRun(record.run_id);
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      return {
        ...subagentResultForRunDep({ record, run, output, outputContractStatus }),
        subagent: this.subagentProjection({
          ...record,
          output_contract_status: outputContractStatus.status,
        }),
      };
    },
    sendSubagentInput(store, threadId, subagentId, request = {}) {
      const record = store.getSubagent(threadId, subagentId);
      if ((record.lifecycle_status ?? record.status) === "canceled") {
        throw policyErrorDep("Cannot send input to a canceled subagent.", {
          thread_id: threadId,
          subagent_id: subagentId,
        });
      }
      const message = optionalStringDep(request.input);
      if (!message) {
        throw runtimeErrorDep({
          status: 400,
          code: "subagent_input_required",
          message: "Subagent input requires a message.",
          details: { thread_id: threadId, subagent_id: subagentId },
        });
      }

      const previousRunId = record.run_id;
      const childAgentId = record.agent_id ?? subagentId;
      const inputId = `subagent_input_${doctorHash(`${threadId}:${subagentId}:${nowMs()}`).slice(0, 12)}`;
      const run = store.createRun(childAgentId, {
        mode: "send",
        prompt: message,
        options: {
          receiver: record.role ?? "general",
          memory: request.memory ?? request.options?.memory ?? {},
        },
      });
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      const budget =
        subagentBudgetForRequestDep(request) ??
        subagentBudgetForRequestDep({ budget: record.budget });
      const budgetUsageTelemetry =
        subagentBudgetUsageTelemetryForRequestDep(request) ??
        record.usage_telemetry ??
        null;
      const budgetStatus = subagentBudgetStatusForRunDep({
        budget,
        run,
        prompt: message,
        previousUsage: budgetUsageTelemetry ?? {},
      });
      const now = nowIso();
      const inputRecord = {
        schema_version: "ioi.runtime.subagent-input.v1",
        input_id: inputId,
        message,
        run_id: run.id,
        previous_run_id: previousRunId ?? null,
        created_at: now,
        actor: optionalStringDep(request.actor) ?? "operator",
        source: operatorControlSourceDep(request.source),
        workflow_graph_id: optionalStringDep(request.workflow_graph_id) ?? null,
        workflow_node_id: optionalStringDep(request.workflow_node_id) ?? null,
      };
      const inputHistory = [...normalizeArray(record.input_history), inputRecord];
      const lifecycleStatus =
        budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRunDep(run.status);
      const canonicalRecord = withoutRetiredSubagentRecordOutputAliases(
        withoutRetiredSubagentUsageTelemetry(record),
      );
      const updated = {
        ...canonicalRecord,
        run_id: run.id,
        previous_run_ids: uniqueStringsDep([
          ...normalizeArray(record.previous_run_ids),
          previousRunId,
        ]),
        lifecycle_status: lifecycleStatus,
        status: lifecycleStatus,
        budget,
        budget_usage_telemetry: budgetUsageTelemetry,
        budget_status: budgetStatus.status,
        usage_telemetry: budgetStatus.usage,
        budget_policy_decision: budgetStatus.policy_decision,
        block_reason: budgetStatus.status === "exceeded" ? "subagent_budget_exceeded" : null,
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        input_count: inputHistory.length,
        input_history: inputHistory,
        last_input: message,
        last_input_at: now,
        input_id: inputId,
        updated_at: now,
      };
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const event = store.appendThreadSubagentControlEvent({
        threadId,
        parentAgent: store.agentForThread(threadId),
        record: updated,
        request,
        operation: "send_input",
        status: updated.status,
      });
      const saved = withoutRetiredSubagentRecordOutputAliases({
        ...updated,
        input_event_id: event.event_id,
        receipt_refs: uniqueStringsDep([
          ...normalizeArray(updated.receipt_refs),
          ...normalizeArray(run.receipts).map((receipt) => receipt.id),
          ...event.receipt_refs,
        ]),
        evidence_refs: uniqueStringsDep([
          ...normalizeArray(updated.evidence_refs),
          "runtime.subagent.input",
          run.id,
        ]),
        updated_at: event.created_at,
      });
      saved.result = subagentResultForRunDep({ record: saved, run, output, outputContractStatus });
      store.writeSubagent(saved, "subagent.input");
      if (budgetStatus.status === "exceeded") {
        throw policyErrorDep("Subagent budget limit exceeded.", {
          thread_id: threadId,
          subagent_id: subagentId,
          reason: "subagent_budget_exceeded",
          budget_status: budgetStatus.status,
          subagent: this.subagentProjection(saved),
          event_id: event.event_id,
          receipt_refs: event.receipt_refs,
          policy_decision_refs: event.policy_decision_refs,
        });
      }
      return {
        ...this.subagentProjection(saved),
        input: inputRecord,
        result: saved.result,
        event,
      };
    },
    resumeSubagent(store, threadId, subagentId, request = {}) {
      const record = store.getSubagent(threadId, subagentId);
      const previousRunId = record.run_id;
      const previousStatus = record.lifecycle_status ?? record.status ?? null;
      const childAgentId = record.agent_id ?? subagentId;
      const role = normalizeSubagentRoleDep(
        request.role ?? request.subagent_role ?? record.role,
      );
      const modelRouteId =
        optionalStringDep(request.model_route_id) ??
        record.model_route_id ??
        "route.local-first";
      const prompt = optionalStringDep(request.prompt) ?? `Resume subagent ${role}.`;
      const resumeId = `subagent_resume_${doctorHash(`${threadId}:${subagentId}:${nowMs()}`).slice(0, 12)}`;
      const run = store.createRun(childAgentId, {
        mode: "send",
        prompt,
        options: {
          receiver: role,
          memory: request.memory ?? request.options?.memory ?? {},
          model: { id: "auto", routeId: modelRouteId },
        },
      });
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      const budget =
        subagentBudgetForRequestDep(request) ??
        subagentBudgetForRequestDep({ budget: record.budget });
      const budgetUsageTelemetry =
        subagentBudgetUsageTelemetryForRequestDep(request) ??
        record.usage_telemetry ??
        null;
      const budgetStatus = subagentBudgetStatusForRunDep({
        budget,
        run,
        prompt,
        previousUsage: budgetUsageTelemetry ?? {},
      });
      const now = nowIso();
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
        actor: optionalStringDep(request.actor) ?? "operator",
        source: operatorControlSourceDep(request.source),
        workflow_graph_id: optionalStringDep(request.workflow_graph_id) ?? null,
        workflow_node_id: optionalStringDep(request.workflow_node_id) ?? null,
      };
      const resumeHistory = [...normalizeArray(record.resume_history), resumeRecord];
      const cancellationHistory = [
        ...normalizeArray(record.cancellation_history),
        ...(record.cancellation ? [record.cancellation] : []),
      ];
      const lifecycleStatus =
        budgetStatus.status === "exceeded" ? "blocked" : lifecycleStatusForRunDep(run.status);
      const canonicalRecord = withoutRetiredSubagentRecordOutputAliases(
        withoutRetiredSubagentUsageTelemetry(record),
      );
      const updated = {
        ...canonicalRecord,
        role,
        run_id: run.id,
        previous_run_ids: uniqueStringsDep([
          ...normalizeArray(record.previous_run_ids),
          previousRunId,
        ]),
        model_route_id: modelRouteId,
        lifecycle_status: lifecycleStatus,
        status: lifecycleStatus,
        budget,
        budget_usage_telemetry: budgetUsageTelemetry,
        budget_status: budgetStatus.status,
        usage_telemetry: budgetStatus.usage,
        budget_policy_decision: budgetStatus.policy_decision,
        block_reason: budgetStatus.status === "exceeded" ? "subagent_budget_exceeded" : null,
        restart_status: "restarted",
        restart_count: restartCount,
        resume_id: resumeId,
        resumed_at: now,
        resume_history: resumeHistory,
        cancellation: null,
        cancellation_reason: null,
        cancellation_cleared_at: now,
        cancellation_history: cancellationHistory,
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        updated_at: now,
      };
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const event = store.appendThreadSubagentControlEvent({
        threadId,
        parentAgent: store.agentForThread(threadId),
        record: updated,
        request,
        operation: "resume",
        status: updated.status,
      });
      const saved = withoutRetiredSubagentRecordOutputAliases({
        ...updated,
        resume_event_id: event.event_id,
        receipt_refs: uniqueStringsDep([
          ...normalizeArray(updated.receipt_refs),
          ...normalizeArray(run.receipts).map((receipt) => receipt.id),
          ...event.receipt_refs,
        ]),
        evidence_refs: uniqueStringsDep([
          ...normalizeArray(updated.evidence_refs),
          "runtime.subagent.resume",
          run.id,
        ]),
        updated_at: event.created_at,
      });
      saved.result = subagentResultForRunDep({ record: saved, run, output, outputContractStatus });
      store.writeSubagent(saved, "subagent.resume");
      if (budgetStatus.status === "exceeded") {
        throw policyErrorDep("Subagent budget limit exceeded.", {
          thread_id: threadId,
          subagent_id: subagentId,
          reason: "subagent_budget_exceeded",
          budget_status: budgetStatus.status,
          subagent: this.subagentProjection(saved),
          event_id: event.event_id,
          receipt_refs: event.receipt_refs,
          policy_decision_refs: event.policy_decision_refs,
        });
      }
      return {
        ...saved.result,
        subagent: this.subagentProjection(saved),
        resume: resumeRecord,
        event,
        receipt_refs: event.receipt_refs,
      };
    },
    assignSubagent(store, threadId, subagentId, request = {}) {
      const record = store.getSubagent(threadId, subagentId);
      const previousRole = record.role ?? "general";
      const role = normalizeSubagentRoleDep(
        request.role ?? request.subagent_role ?? previousRole,
      );
      const toolPack =
        optionalStringDep(request.tool_pack) ??
        record.tool_pack ??
        null;
      const modelRouteId =
        optionalStringDep(request.model_route_id) ??
        record.model_route_id ??
        null;
      const mergePolicy =
        optionalStringDep(request.merge_policy) ??
        record.merge_policy ??
        "manual";
      const cancellationInheritance =
        optionalStringDep(request.cancellation_inheritance) ??
        record.cancellation_inheritance ??
        "propagate";
      const targetAgentId =
        optionalStringDep(request.target_agent_id) ??
        record.agent_id ??
        subagentId;
      const assignmentId = `subagent_assignment_${doctorHash(`${threadId}:${subagentId}:${nowMs()}`).slice(0, 12)}`;
      const now = nowIso();
      const assignmentCount = Number(record.assignment_count ?? 0) + 1;
      const assignmentRecord = {
        schema_version: "ioi.runtime.subagent-assignment.v1",
        assignment_id: assignmentId,
        previous_role: previousRole,
        role,
        target_agent_id: targetAgentId,
        tool_pack: toolPack,
        model_route_id: modelRouteId,
        merge_policy: mergePolicy,
        cancellation_inheritance: cancellationInheritance,
        assignment_count: assignmentCount,
        created_at: now,
        actor: optionalStringDep(request.actor) ?? "operator",
        source: operatorControlSourceDep(request.source),
        workflow_graph_id: optionalStringDep(request.workflow_graph_id) ?? null,
        workflow_node_id: optionalStringDep(request.workflow_node_id) ?? null,
      };
      const assignmentHistory = [
        ...normalizeArray(record.assignment_history),
        assignmentRecord,
      ];
      const run = store.getRun(record.run_id);
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      const canonicalRecord = withoutRetiredSubagentRecordOutputAliases(record);
      const updated = {
        ...canonicalRecord,
        role,
        target_agent_id: targetAgentId,
        tool_pack: toolPack,
        model_route_id: modelRouteId,
        merge_policy: mergePolicy,
        cancellation_inheritance: cancellationInheritance,
        assignment_id: assignmentId,
        assignment_count: assignmentCount,
        assignment_history: assignmentHistory,
        assigned_at: now,
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        updated_at: now,
      };
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const event = store.appendThreadSubagentControlEvent({
        threadId,
        parentAgent: store.agentForThread(threadId),
        record: updated,
        request,
        operation: "assign",
        status: updated.status,
      });
      const saved = withoutRetiredSubagentRecordOutputAliases({
        ...updated,
        assign_event_id: event.event_id,
        receipt_refs: uniqueStringsDep([...normalizeArray(updated.receipt_refs), ...event.receipt_refs]),
        evidence_refs: uniqueStringsDep([
          ...normalizeArray(updated.evidence_refs),
          "runtime.subagent.assign",
          assignmentId,
        ]),
        updated_at: event.created_at,
      });
      saved.result = subagentResultForRunDep({ record: saved, run, output, outputContractStatus });
      store.writeSubagent(saved, "subagent.assign");
      return {
        ...this.subagentProjection(saved),
        assignment: assignmentRecord,
        result: saved.result,
        event,
      };
    },
    cancelSubagent(store, threadId, subagentId, request = {}) {
      const record = store.getSubagent(threadId, subagentId);
      const previousStatus = record.lifecycle_status ?? record.status ?? null;
      const reason =
        optionalStringDep(request.reason ?? request.cancellation_reason) ??
        "operator_cancel";
      const cancellationInherited = Boolean(request.inherited);
      const propagatedFromThreadId =
        optionalStringDep(request.propagated_from_thread_id) ?? null;
      const run = store.cancelRun(record.run_id);
      const output = subagentContractOutputForRunDep(run, record.output_contract);
      const outputContractStatus = validateSubagentOutputContractDep(
        output,
        record.output_contract,
      );
      const budget =
        subagentBudgetForRequestDep(request) ??
        subagentBudgetForRequestDep({ budget: record.budget });
      const budgetUsageTelemetry =
        subagentBudgetUsageTelemetryForRequestDep(request) ??
        record.usage_telemetry ??
        null;
      const prompt = optionalStringDep(record.prompt ?? record.objective ?? record.task) ?? "";
      const budgetStatus = subagentBudgetStatusForRunDep({
        budget,
        run,
        prompt,
        previousUsage: budgetUsageTelemetry ?? {},
      });
      const now = nowIso();
      const canonicalRecord = withoutRetiredSubagentRecordOutputAliases(
        withoutRetiredSubagentUsageTelemetry(record),
      );
      const updated = {
        ...canonicalRecord,
        lifecycle_status: "canceled",
        status: "canceled",
        output_contract_status: outputContractStatus.status,
        output_contract_validation: outputContractStatus,
        canceled_at: now,
        cancellation_reason: reason,
        cancellation_inherited: cancellationInherited,
        propagated_from_thread_id: propagatedFromThreadId,
        cancellation: {
          reason,
          previous_status: previousStatus,
          requested_by: optionalStringDep(request.actor) ?? "operator",
          inherited: cancellationInherited,
          propagated_from_thread_id: propagatedFromThreadId,
          source: operatorControlSourceDep(request.source),
        },
        updated_at: now,
      };
      updated.result = subagentResultForRunDep({ record: updated, run, output, outputContractStatus });
      const event = store.appendThreadSubagentControlEvent({
        threadId,
        parentAgent: store.agentForThread(threadId),
        record: updated,
        request,
        operation: "cancel",
        status: "canceled",
      });
      const saved = withoutRetiredSubagentRecordOutputAliases({
        ...updated,
        cancel_event_id: event.event_id,
        receipt_refs: uniqueStringsDep([
          ...normalizeArray(updated.receipt_refs),
          ...normalizeArray(run.receipts).map((receipt) => receipt.id),
          ...event.receipt_refs,
        ]),
        evidence_refs: uniqueStringsDep([
          ...normalizeArray(updated.evidence_refs),
          "runtime.subagent.cancel",
          run.id,
        ]),
        updated_at: event.created_at,
      });
      saved.result = subagentResultForRunDep({ record: saved, run, output, outputContractStatus });
      store.writeSubagent(saved, "subagent.cancel");
      return {
        ...saved.result,
        subagent: this.subagentProjection(saved),
        event,
        cancellation: saved.cancellation,
        receipt_refs: event.receipt_refs,
      };
    },
    propagateSubagentCancellation(store, threadId, request = {}) {
      const parentAgent = store.agentForThread(threadId);
      const reason =
        optionalStringDep(request.reason ?? request.cancellation_reason) ??
        "parent_cancel";
      const source = operatorControlSourceDep(request.source);
      const requestBase = {
        source,
        reason,
        actor: request.actor,
        workflow_graph_id: request.workflow_graph_id,
        receipt_refs: request.receipt_refs,
        policy_decision_refs: request.policy_decision_refs,
        budget: request.budget,
        budget_usage_telemetry: request.budget_usage_telemetry,
        inherited: true,
        propagated_from_thread_id: threadId,
      };
      const candidates = [...store.subagents.values()]
        .filter((record) => record.parent_thread_id === threadId)
        .sort((left, right) =>
          String(left.created_at ?? "").localeCompare(
            String(right.created_at ?? ""),
          ),
        );
      const canceled = [];
      const skipped = [];
      for (const record of candidates) {
        const targetId = record.subagent_id;
        const inheritance =
          optionalStringDep(record.cancellation_inheritance)?.toLowerCase() ?? "propagate";
        const status = record.lifecycle_status ?? record.status ?? null;
        if (inheritance !== "propagate") {
          skipped.push({
            ...this.subagentProjection(record),
            skip_reason: "cancellation_inheritance_not_propagate",
            cancellation_inheritance: inheritance,
          });
          continue;
        }
        if (status === "canceled") {
          skipped.push({
            ...this.subagentProjection(record),
            skip_reason: "already_canceled",
            cancellation_inheritance: inheritance,
          });
          continue;
        }
        const workflowNodeId =
          optionalStringDep(request.workflow_node_id) ??
          `runtime.subagent.cancel.propagated.${safeIdDep(record.role ?? "general")}`;
        const childRequest = {
          ...requestBase,
          workflow_node_id: workflowNodeId,
        };
        const result = this.cancelSubagent(store, threadId, String(targetId), childRequest);
        canceled.push(result);
      }
      return {
        schema_version: schemaVersion,
        object: "ioi.runtime_subagent_cancellation_propagation",
        thread_id: threadId,
        parent_agent_id: parentAgent.id,
        status: "completed",
        source,
        reason,
        propagation_policy: "cancellationInheritance=propagate",
        candidate_count: candidates.length,
        canceled_count: canceled.length,
        skipped_count: skipped.length,
        canceled_subagents: canceled.map((result) => result.subagent),
        skipped_subagents: skipped,
        event_refs: canceled.map((result) => result.event?.event_id).filter(Boolean),
        receipt_refs: uniqueStringsDep(canceled.flatMap((result) => normalizeArray(result.receipt_refs))),
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
      const thread = store.threadForAgent(parentAgent);
      const source = operatorControlSourceDep(request.source);
      const eventHash = doctorHash(
        `${threadId}:${operation}:${record.subagent_id}:${nowMs()}`,
      ).slice(0, 12);
      const workflowGraphId =
        optionalStringDep(request.workflow_graph_id) ??
        record.workflow_graph_id ??
        null;
      const workflowNodeId =
        optionalStringDep(request.workflow_node_id) ??
        record.workflow_node_id ??
        `runtime.subagent.${operation}`;
      const payload = subagentManagerEventPayloadDep({ record, operation, status });
      const budgetPolicyDecision = record.budget_policy_decision ?? null;
      const budgetStatus =
        record.budget_status ?? budgetPolicyDecision?.reason ?? null;
      const requestReceiptRefs = uniqueStringsDep(request.receipt_refs);
      const requestPolicyDecisionRefs = uniqueStringsDep(
        request.policy_decision_refs,
      );
      const policyDecisionRefs = uniqueStringsDep([
        ...requestPolicyDecisionRefs,
        ...(budgetStatus === "exceeded" && budgetPolicyDecision?.id && typeof budgetPolicyDecision.id === "string"
          ? [budgetPolicyDecision.id]
          : [`policy_subagent_${safeIdDep(operation)}_allow_${eventHash}`]),
      ]);
      return store.appendRuntimeEvent({
        event_stream_id: eventStreamIdForThreadDep(threadId),
        thread_id: threadId,
        turn_id: record.parent_turn_id ?? thread.latest_turn_id ?? "",
        item_id: `${record.parent_turn_id ?? threadId}:item:subagent:${safeIdDep(operation)}:${safeIdDep(record.subagent_id)}`,
        idempotency_key:
          optionalStringDep(request.idempotency_key) ??
          `thread:${threadId}:subagent.${operation}:${record.subagent_id}:${eventHash}`,
        source,
        source_event_kind: subagentOperatorControlKindDep(operation),
        event_kind: subagentRuntimeEventKindDep(operation),
        status,
        actor: "operator",
        workspace_root: parentAgent.cwd,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        component_kind: "subagent_lifecycle",
        payload_schema_version: schemaVersion,
        payload,
        receipt_refs: uniqueStringsDep([
          ...requestReceiptRefs,
          `receipt_subagent_${safeIdDep(operation)}_${eventHash}`,
        ]),
        policy_decision_refs: policyDecisionRefs,
        artifact_refs: [],
        rollback_refs: [],
        redaction_profile: "internal",
        fixture_profile: fixtureProfileForAgentDep(parentAgent),
      });
    },
  };
}
