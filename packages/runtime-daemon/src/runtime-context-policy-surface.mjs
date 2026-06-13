import {
  contextBudgetUsageTelemetryFromRequest,
  evaluateContextBudgetPolicy,
} from "./threads/context-budget-policy.mjs";
import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
} from "./runtime-value-helpers.mjs";

const CONTEXT_COMPACTION_EVIDENCE_REFS = [
  "context_compaction_rust_owned",
  "rust_daemon_core_context_compaction_plan",
  "rust_daemon_core_context_compaction_state_update",
  "agentgres_runtime_thread_event_truth_required",
  "agentgres_context_compaction_state_truth_required",
];

const CONTEXT_COMPACTION_REQUIRED_EVIDENCE_REFS = [
  "context_compaction_js_facade_retired",
  "rust_daemon_core_context_compaction_required",
  "agentgres_context_compaction_state_truth_required",
];

export function createRuntimeContextPolicySurface({
  contextBudgetUsageTelemetryFromRequest: contextBudgetUsageTelemetryFromRequestDep = contextBudgetUsageTelemetryFromRequest,
  contextPolicyRunner = null,
  evaluateContextBudgetPolicy: evaluateContextBudgetPolicyDep = evaluateContextBudgetPolicy,
  eventStreamIdForThread: eventStreamIdForThreadDep = eventStreamIdForThread,
  optionalString: optionalStringDep = optionalString,
  runtimeError,
} = {}) {
  function throwContextPolicyRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_context_policy_rust_core_required",
      message: "Runtime context policy control requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.context_policy",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

  return {
    compactThread(store, threadId, request = {}) {
      const runner = store?.contextPolicyRunner ?? contextPolicyRunner;
      if (
        typeof runner?.planContextCompaction !== "function" ||
        typeof runner?.planContextCompactionStateUpdate !== "function" ||
        typeof store?.agentForThread !== "function" ||
        typeof store?.appendRuntimeEvent !== "function"
      ) {
        throwContextPolicyRustCoreRequired("context_compaction", "thread.compact", {
          thread_id: threadId,
          evidence_refs: CONTEXT_COMPACTION_REQUIRED_EVIDENCE_REFS,
        });
      }

      const agent = objectRecord(store.agentForThread(threadId));
      const agentId = optionalStringDep(agent?.id ?? agent?.agent_id);
      if (!agent || !agentId) {
        throwContextCompactionError({
          status: 404,
          code: "runtime_context_compaction_agent_unavailable",
          message: "Context compaction requires an admitted agent for the requested thread.",
          details: { thread_id: threadId },
        });
      }

      const requestedRunId = optionalStringDep(request.run_id);
      const requestedTurnId = optionalStringDep(request.turn_id);
      const resolved = requestedRunId
        ? {
            run: objectRecord(store.getRun?.(requestedRunId)),
            runId: requestedRunId,
            turnId: requestedTurnId,
          }
        : requestedTurnId && typeof store.resolveRunForThreadTurn === "function"
          ? store.resolveRunForThreadTurn(agent, threadId, requestedTurnId)
          : null;
      const run = objectRecord(resolved?.run);
      const runId = optionalStringDep(resolved?.runId ?? run?.id);
      if ((requestedRunId || requestedTurnId) && !run) {
        throwContextCompactionError({
          status: 404,
          code: "runtime_context_compaction_run_unavailable",
          message: "Context compaction run update requires an admitted run record.",
          details: {
            thread_id: threadId,
            run_id: requestedRunId ?? null,
            turn_id: requestedTurnId ?? null,
          },
        });
      }
      const targetKind =
        optionalStringDep(request.target_kind) === "agent" || !run ? "agent" : "run";
      if (targetKind === "run" && !runId) {
        throwContextCompactionError({
          status: 404,
          code: "runtime_context_compaction_run_unavailable",
          message: "Context compaction run update requires an admitted run record.",
          details: { thread_id: threadId, run_id: requestedRunId ?? null },
        });
      }
      if (targetKind === "run" && typeof store.writeRun !== "function") {
        throwContextPolicyRustCoreRequired("context_compaction", "thread.compact", {
          thread_id: threadId,
          run_id: runId,
          evidence_refs: CONTEXT_COMPACTION_REQUIRED_EVIDENCE_REFS,
        });
      }
      if (targetKind === "agent" && typeof store.writeAgent !== "function") {
        throwContextPolicyRustCoreRequired("context_compaction", "thread.compact", {
          thread_id: threadId,
          agent_id: agentId,
          evidence_refs: CONTEXT_COMPACTION_REQUIRED_EVIDENCE_REFS,
        });
      }

      const eventStreamId = eventStreamIdForThreadDep(threadId);
      const previousLatestSeq = typeof store.latestRuntimeEventSeq === "function"
        ? Number(store.latestRuntimeEventSeq(eventStreamId) ?? 0)
        : 0;
      const seq = Number.isFinite(previousLatestSeq) ? previousLatestSeq + 1 : 1;
      const createdAt = optionalStringDep(request.created_at) ?? new Date().toISOString();
      const reason =
        optionalStringDep(request.reason) ?? "operator requested context compaction";
      const scope = optionalStringDep(request.scope) ?? (targetKind === "run" ? "run" : "thread");
      const source = optionalStringDep(request.source) ?? "sdk_client";
      const plan = runner.planContextCompaction({
        thread_id: threadId,
        agent_id: agentId,
        run_id: targetKind === "run" ? runId : null,
        turn_id: optionalStringDep(resolved?.turnId ?? requestedTurnId) ?? null,
        session_id: optionalStringDep(request.session_id) ?? null,
        workspace_root:
          optionalStringDep(request.workspace_root ?? agent.cwd ?? agent.workspace_root) ?? null,
        event_stream_id: eventStreamId,
        previous_latest_seq: Number.isFinite(previousLatestSeq) ? previousLatestSeq : 0,
        source,
        actor: optionalStringDep(request.actor) ?? "operator",
        requested_by: optionalStringDep(request.requested_by) ?? "operator",
        reason,
        scope,
        workflow_graph_id: optionalStringDep(request.workflow_graph_id) ?? null,
        workflow_node_id: optionalStringDep(request.workflow_node_id) ?? "runtime.context-compact",
        idempotency_key: optionalStringDep(request.idempotency_key) ?? null,
      });
      if (
        optionalStringDep(plan?.status) !== "planned" ||
        optionalStringDep(plan?.event_kind) !== "context.compacted" ||
        !optionalStringDep(plan?.item_id) ||
        !optionalStringDep(plan?.idempotency_key)
      ) {
        throwContextCompactionError({
          code: "runtime_context_compaction_plan_incomplete",
          message: "Rust daemon-core context compaction planning did not return a complete event plan.",
          details: {
            thread_id: threadId,
            run_id: runId ?? null,
            actual_status: optionalStringDep(plan?.status) ?? null,
            actual_event_kind: optionalStringDep(plan?.event_kind) ?? null,
          },
        });
      }

      const eventId =
        optionalStringDep(request.event_id) ??
        contextCompactionEventId(threadId, runId ?? agentId, seq);
      const plannedEvent = {
        event_stream_id: eventStreamId,
        event_id: eventId,
        seq,
        thread_id: threadId,
        turn_id: optionalStringDep(plan?.turn_id ?? resolved?.turnId ?? requestedTurnId) ?? null,
        item_id: plan.item_id,
        idempotency_key: plan.idempotency_key,
        source: plan.source ?? source,
        source_event_kind: plan.source_event_kind,
        event_kind: plan.event_kind,
        status: "completed",
        actor: plan.actor,
        workflow_graph_id: plan.workflow_graph_id ?? null,
        workflow_node_id: plan.workflow_node_id,
        component_kind: plan.component_kind,
        payload_schema_version: plan.payload_schema_version,
        payload: objectRecord(plan.payload) ?? {},
        receipt_refs: stringRefs(plan.receipt_refs),
        policy_decision_refs: stringRefs(plan.policy_decision_refs),
        artifact_refs: stringRefs(plan.artifact_refs),
        rollback_refs: stringRefs(plan.rollback_refs),
        redaction_profile: plan.redaction_profile,
        created_at: createdAt,
        evidence_refs: CONTEXT_COMPACTION_EVIDENCE_REFS,
      };
      const admittedEvent = objectRecord(store.appendRuntimeEvent(plannedEvent));
      const admittedEventId = optionalStringDep(admittedEvent?.event_id);
      const admittedSeq = positiveInteger(admittedEvent?.seq);
      if (!admittedEvent || !admittedEventId || !admittedSeq) {
        throwContextCompactionError({
          code: "runtime_context_compaction_event_admission_incomplete",
          message: "Rust Agentgres runtime-event admission did not return an admitted event identity.",
          details: {
            thread_id: threadId,
            run_id: runId ?? null,
            event_id: eventId,
            seq,
          },
        });
      }
      const stateUpdate = runner.planContextCompactionStateUpdate({
        target_kind: targetKind,
        thread_id: threadId,
        agent_id: agentId,
        run_id: targetKind === "run" ? runId : null,
        run: targetKind === "run" ? run : null,
        agent,
        event_id: admittedEventId,
        seq: admittedSeq,
        created_at: optionalStringDep(admittedEvent?.created_at) ?? createdAt,
        source,
        reason,
        scope,
      });
      const operationKind = optionalStringDep(stateUpdate?.operation_kind);
      const operatorControl = objectRecord(stateUpdate?.operator_control);
      const contextCompaction = objectRecord(stateUpdate?.context_compaction);
      if (
        optionalStringDep(stateUpdate?.status) !== "planned" ||
        operationKind !== "thread.compact" ||
        optionalStringDep(stateUpdate?.target_kind) !== targetKind ||
        !operatorControl ||
        optionalStringDep(operatorControl.control) !== "compact" ||
        !contextCompaction ||
        optionalStringDep(contextCompaction.event_id) !== admittedEventId
      ) {
        throwContextCompactionError({
          code: "runtime_context_compaction_state_update_incomplete",
          message: "Rust daemon-core context compaction state update did not return a complete projection.",
          details: {
            thread_id: threadId,
            run_id: runId ?? null,
            target_kind: targetKind,
            expected_operation_kind: "thread.compact",
            actual_operation_kind: operationKind ?? null,
            actual_status: optionalStringDep(stateUpdate?.status) ?? null,
          },
        });
      }

      const plannedRun = objectRecord(stateUpdate?.run);
      const plannedAgent = objectRecord(stateUpdate?.agent);
      const commit = targetKind === "run"
        ? commitContextCompactionRun(store, plannedRun, runId, operationKind)
        : commitContextCompactionAgent(store, plannedAgent, agentId, operationKind);
      return {
        schema_version: "ioi.runtime.context_compaction.v1",
        object: "ioi.runtime_context_compaction",
        status: "completed",
        operation: "context_compaction",
        operation_kind: operationKind,
        target_kind: targetKind,
        thread_id: threadId,
        agent_id: agentId,
        run_id: targetKind === "run" ? runId : null,
        event_id: admittedEventId,
        seq: admittedSeq,
        event: admittedEvent,
        operator_control: operatorControl,
        context_compaction: contextCompaction,
        run: targetKind === "run" ? plannedRun : null,
        agent: targetKind === "agent" ? plannedAgent : null,
        commit,
        receipt_refs: uniqueRefs(
          plannedEvent.receipt_refs,
          admittedEvent?.receipt_refs,
          commit?.receipt_refs,
        ),
        policy_decision_refs: uniqueRefs(
          plannedEvent.policy_decision_refs,
          admittedEvent?.policy_decision_refs,
          commit?.policy_decision_refs,
        ),
        evidence_refs: CONTEXT_COMPACTION_EVIDENCE_REFS,
      };
    },

    evaluateContextBudget(store, { threadId = null, runId = null, request = {} } = {}) {
      const requestedRunId = optionalStringDep(request.run_id) ?? runId;
      const requestedThreadId = optionalStringDep(request.thread_id) ?? threadId;
      if (requestedThreadId || requestedRunId) {
        throwContextPolicyRustCoreRequired("context_budget_evaluation", "context_budget.evaluate", {
          thread_id: requestedThreadId,
          run_id: requestedRunId,
          evidence_refs: [
            "context_budget_evaluation_js_event_facade_retired",
            "rust_daemon_core_context_budget_event_required",
            "agentgres_context_budget_event_truth_required",
          ],
        });
      }

      const canonicalRequest = { ...request };
      for (const retiredField of [
        "eventKind",
        "runId",
        "threadId",
        "turnId",
        "workflowGraphId",
        "workflowNodeId",
      ]) {
        delete canonicalRequest[retiredField];
      }
      const usageTelemetry =
        contextBudgetUsageTelemetryFromRequestDep(canonicalRequest) ??
        store.listUsage({ group_by: "thread" });

      return evaluateContextBudgetPolicyDep({
        usageTelemetry,
        request: {
          ...canonicalRequest,
          scope: optionalStringDep(canonicalRequest.scope) ?? "workflow",
          thread_id: null,
          turn_id: null,
          run_id: null,
        },
      });
    },

    evaluateCompactionPolicy(store, { threadId, request = {} } = {}) {
      const requestedThreadId = optionalStringDep(request.thread_id) ?? threadId;
      if (!requestedThreadId) {
        throw runtimeError({
          status: 400,
          code: "runtime_compaction_policy_thread_required",
          message: "Compaction policy evaluation requires a thread id.",
        });
      }
      throwContextPolicyRustCoreRequired("compaction_policy_evaluation", "compaction_policy.evaluate", {
        thread_id: requestedThreadId,
        evidence_refs: [
          "compaction_policy_evaluation_js_event_facade_retired",
          "rust_daemon_core_compaction_policy_event_required",
          "agentgres_compaction_policy_event_truth_required",
        ],
      });
    },
  };

  function commitContextCompactionRun(store, plannedRun, runId, operationKind) {
    if (!plannedRun || optionalStringDep(plannedRun.id) !== runId) {
      throwContextCompactionError({
        code: "runtime_context_compaction_run_projection_incomplete",
        message: "Rust daemon-core context compaction did not return the expected run projection.",
        details: { run_id: runId ?? null },
      });
    }
    return store.writeRun(plannedRun, operationKind);
  }

  function commitContextCompactionAgent(store, plannedAgent, agentId, operationKind) {
    if (!plannedAgent || optionalStringDep(plannedAgent.id ?? plannedAgent.agent_id) !== agentId) {
      throwContextCompactionError({
        code: "runtime_context_compaction_agent_projection_incomplete",
        message: "Rust daemon-core context compaction did not return the expected agent projection.",
        details: { agent_id: agentId ?? null },
      });
    }
    return store.writeAgent(plannedAgent, operationKind);
  }

  function throwContextCompactionError({ status = 502, code, message, details = {} }) {
    throw runtimeError({
      status,
      code,
      message,
      details: {
        rust_core_boundary: "runtime.context_policy",
        evidence_refs: CONTEXT_COMPACTION_EVIDENCE_REFS,
        ...details,
      },
    });
  }

  function contextCompactionEventId(threadId, targetId, seq) {
    return [
      "event_context_compaction",
      safeIdSegment(threadId),
      safeIdSegment(targetId),
      String(seq).padStart(8, "0"),
    ].join("_");
  }

  function safeIdSegment(value) {
    return optionalStringDep(value)?.replace(/[^a-zA-Z0-9_.:-]/g, "_") ?? "unknown";
  }

  function positiveInteger(value) {
    const number = Number(value);
    return Number.isInteger(number) && number > 0 ? number : null;
  }

  function stringRefs(values) {
    return normalizeArray(values).map((value) => String(value)).filter(Boolean);
  }

  function uniqueRefs(...values) {
    return [...new Set(values.flatMap((value) => stringRefs(value)))];
  }
}
