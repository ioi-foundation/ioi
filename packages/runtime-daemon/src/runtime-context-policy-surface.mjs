import {
  contextBudgetUsageTelemetryFromRequest,
  evaluateCompactionPolicyDecision,
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

const CONTEXT_BUDGET_EVIDENCE_REFS = [
  "context_budget_evaluation_rust_owned",
  "rust_daemon_core_context_budget_event",
  "agentgres_context_budget_event_truth_required",
];

const CONTEXT_BUDGET_REQUIRED_EVIDENCE_REFS = [
  "context_budget_evaluation_js_event_facade_retired",
  "rust_daemon_core_context_budget_event_required",
  "agentgres_context_budget_event_truth_required",
];

const COMPACTION_POLICY_EVIDENCE_REFS = [
  "compaction_policy_evaluation_rust_owned",
  "rust_daemon_core_compaction_policy_event",
  "agentgres_compaction_policy_event_truth_required",
];

const COMPACTION_POLICY_REQUIRED_EVIDENCE_REFS = [
  "compaction_policy_evaluation_js_event_facade_retired",
  "rust_daemon_core_compaction_policy_event_required",
  "agentgres_compaction_policy_event_truth_required",
];

export function createRuntimeContextPolicySurface({
  contextBudgetUsageTelemetryFromRequest: contextBudgetUsageTelemetryFromRequestDep = contextBudgetUsageTelemetryFromRequest,
  contextPolicyCore = null,
  evaluateCompactionPolicyDecision: evaluateCompactionPolicyDecisionDep = evaluateCompactionPolicyDecision,
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
      const runner = contextPolicyCore;
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
        state_dir: optionalStringDep(store?.stateDir) ?? null,
        workspace_root:
          optionalStringDep(request.workspace_root ?? agent.cwd ?? agent.workspace_root) ?? null,
        event_stream_id: eventStreamId,
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
        contextCompactionEventId(threadId, runId ?? agentId, createdAt);
      const plannedEvent = {
        event_stream_id: eventStreamId,
        event_id: eventId,
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
      const canonicalRequest = canonicalContextPolicyRequest(request);
      const requestedRunId = optionalStringDep(canonicalRequest.run_id) ?? runId;
      const requestedThreadId = optionalStringDep(canonicalRequest.thread_id) ?? threadId;
      if (requestedThreadId || requestedRunId) {
        const runner = contextPolicyCore;
        if (
          typeof runner?.evaluateContextBudgetPolicy !== "function" ||
          typeof store?.appendRuntimeEvent !== "function"
        ) {
          throwContextPolicyRustCoreRequired("context_budget_evaluation", "context_budget.evaluate", {
            thread_id: requestedThreadId,
            run_id: requestedRunId,
            evidence_refs: CONTEXT_BUDGET_REQUIRED_EVIDENCE_REFS,
          });
        }

        const usageTelemetry =
          contextBudgetUsageTelemetryFromRequestDep(canonicalRequest) ??
          contextBudgetUsageForScope(store, { threadId: requestedThreadId, runId: requestedRunId });
        const usageRecord = objectRecord(usageTelemetry);
        const policyThreadId =
          requestedThreadId ?? optionalStringDep(usageRecord?.thread_id) ?? null;
        if (!policyThreadId) {
          throwContextPolicyEventError({
            status: 400,
            code: "runtime_context_budget_thread_required",
            message: "Thread-bound context budget evaluation requires a thread id.",
            evidenceRefs: CONTEXT_BUDGET_EVIDENCE_REFS,
            details: { run_id: requestedRunId ?? null },
          });
        }
        const policyRunId = requestedRunId ?? optionalStringDep(usageRecord?.run_id) ?? null;
        const policyTurnId =
          optionalStringDep(canonicalRequest.turn_id) ??
          optionalStringDep(usageRecord?.turn_id) ??
          null;
        const policy = evaluateContextBudgetPolicyDep({
          usageTelemetry: usageRecord ?? {},
          request: {
            ...canonicalRequest,
            scope: optionalStringDep(canonicalRequest.scope) ?? (policyRunId ? "run" : "thread"),
            thread_id: policyThreadId,
            turn_id: policyTurnId,
            run_id: policyRunId,
          },
          budgetRunner: runner,
        });
        validateContextPolicyEventPlan(policy, {
          code: "runtime_context_budget_event_plan_incomplete",
          componentKind: "context_budget",
          evidenceRefs: CONTEXT_BUDGET_EVIDENCE_REFS,
          threadId: policyThreadId,
          runId: policyRunId,
        });
        const event = admitContextPolicyRuntimeEvent(store, {
          componentKind: "context_budget",
          evidenceRefs: CONTEXT_BUDGET_EVIDENCE_REFS,
          policy,
          request: canonicalRequest,
          threadId: policyThreadId,
          turnId: policyTurnId,
          runId: policyRunId,
        });
        return contextPolicyResultEnvelope(policy, event, CONTEXT_BUDGET_EVIDENCE_REFS);
      }

      const runner = contextPolicyCore;
      if (typeof runner?.evaluateContextBudgetPolicy !== "function") {
        throwContextPolicyRustCoreRequired("context_budget_evaluation", "context_budget.evaluate", {
          thread_id: null,
          run_id: null,
          evidence_refs: CONTEXT_BUDGET_REQUIRED_EVIDENCE_REFS,
        });
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
        budgetRunner: runner,
      });
    },

    evaluateCompactionPolicy(store, { threadId, request = {} } = {}) {
      const canonicalRequest = canonicalContextPolicyRequest(request);
      const requestedThreadId = optionalStringDep(canonicalRequest.thread_id) ?? threadId;
      if (!requestedThreadId) {
        throw runtimeError({
          status: 400,
          code: "runtime_compaction_policy_thread_required",
          message: "Compaction policy evaluation requires a thread id.",
        });
      }
      const runner = contextPolicyCore;
      if (
        typeof runner?.evaluateCompactionPolicy !== "function" ||
        typeof store?.appendRuntimeEvent !== "function"
      ) {
        throwContextPolicyRustCoreRequired("compaction_policy_evaluation", "compaction_policy.evaluate", {
          thread_id: requestedThreadId,
          evidence_refs: COMPACTION_POLICY_REQUIRED_EVIDENCE_REFS,
        });
      }

      const policy = evaluateCompactionPolicyDecisionDep({
        threadId: requestedThreadId,
        turnId: optionalStringDep(canonicalRequest.turn_id) ?? "",
        request: canonicalRequest,
        policyRunner: runner,
      });
      validateContextPolicyEventPlan(policy, {
        code: "runtime_compaction_policy_event_plan_incomplete",
        componentKind: "compaction_policy",
        evidenceRefs: COMPACTION_POLICY_EVIDENCE_REFS,
        threadId: requestedThreadId,
        runId: null,
      });
      const event = admitContextPolicyRuntimeEvent(store, {
        componentKind: "compaction_policy",
        evidenceRefs: COMPACTION_POLICY_EVIDENCE_REFS,
        policy,
        request: canonicalRequest,
        threadId: requestedThreadId,
        turnId: optionalStringDep(canonicalRequest.turn_id) ?? optionalStringDep(policy.turn_id) ?? null,
        runId: null,
      });
      const compaction = policy.execute_compaction === true
        ? this.compactThread(store, requestedThreadId, {
            reason: optionalStringDep(policy.compact_reason) ?? "compaction policy requested context compaction",
            scope: optionalStringDep(policy.compact_scope) ?? "thread",
            source: optionalStringDep(policy.source) ?? optionalStringDep(canonicalRequest.source) ?? "sdk_client",
            actor: optionalStringDep(policy.actor) ?? optionalStringDep(canonicalRequest.actor) ?? "operator",
            requested_by:
              optionalStringDep(policy.requested_by) ??
              optionalStringDep(canonicalRequest.requested_by) ??
              "operator",
            workflow_graph_id:
              optionalStringDep(policy.workflow_graph_id) ??
              optionalStringDep(canonicalRequest.workflow_graph_id) ??
              null,
            workflow_node_id:
              optionalStringDep(policy.compact_workflow_node_id) ?? "runtime.context-compact",
            idempotency_key: optionalStringDep(policy.compact_idempotency_key) ?? null,
            created_at: optionalStringDep(canonicalRequest.created_at) ?? event.created_at ?? null,
          })
        : null;
      return {
        ...contextPolicyResultEnvelope(policy, event, COMPACTION_POLICY_EVIDENCE_REFS),
        context_compaction: compaction,
      };
    },
  };

  function canonicalContextPolicyRequest(request = {}) {
    const canonicalRequest = { ...request };
    for (const retiredField of [
      "compactIdempotencyKey",
      "eventKind",
      "runId",
      "threadId",
      "turnId",
      "workflowGraphId",
      "workflowNodeId",
    ]) {
      delete canonicalRequest[retiredField];
    }
    return canonicalRequest;
  }

  function contextBudgetUsageForScope(store, { threadId = null, runId = null } = {}) {
    if (runId && typeof store?.usageForRun === "function") {
      return store.usageForRun(runId);
    }
    if (threadId && typeof store?.usageForThread === "function") {
      return store.usageForThread(threadId);
    }
    return null;
  }

  function validateContextPolicyEventPlan(policy, {
    code,
    componentKind,
    evidenceRefs,
    threadId,
    runId = null,
  }) {
    if (
      !objectRecord(policy) ||
      !optionalStringDep(policy.status) ||
      optionalStringDep(policy.component_kind) !== componentKind ||
      !optionalStringDep(policy.policy_decision_id) ||
      !optionalStringDep(policy.runtime_event_kind) ||
      !optionalStringDep(policy.runtime_event_status) ||
      !optionalStringDep(policy.runtime_event_item_id) ||
      !optionalStringDep(policy.runtime_event_idempotency_key)
    ) {
      throwContextPolicyEventError({
        code,
        message: "Rust daemon-core context policy evaluation did not return a complete event plan.",
        evidenceRefs,
        details: {
          thread_id: threadId,
          run_id: runId,
          component_kind: componentKind,
          actual_status: optionalStringDep(policy?.status) ?? null,
          actual_component_kind: optionalStringDep(policy?.component_kind) ?? null,
        },
      });
    }
  }

  function admitContextPolicyRuntimeEvent(store, {
    componentKind,
    evidenceRefs,
    policy,
    request,
    threadId,
    turnId = null,
    runId = null,
  }) {
    const eventStreamId = eventStreamIdForThreadDep(threadId);
    const createdAt = optionalStringDep(request.created_at) ?? new Date().toISOString();
    const eventId =
      optionalStringDep(request.event_id) ??
      contextPolicyEventId(componentKind, threadId, policy.policy_decision_id, createdAt);
    const event = {
      event_stream_id: eventStreamId,
      event_id: eventId,
      thread_id: threadId,
      turn_id: optionalStringDep(policy.turn_id) ?? turnId ?? null,
      item_id: policy.runtime_event_item_id,
      idempotency_key: policy.runtime_event_idempotency_key,
      source: optionalStringDep(policy.source) ?? optionalStringDep(request.source) ?? "sdk_client",
      source_event_kind: optionalStringDep(policy.event_kind) ?? null,
      event_kind: policy.runtime_event_kind,
      status: policy.runtime_event_status,
      actor: optionalStringDep(policy.actor) ?? optionalStringDep(request.actor) ?? "operator",
      workflow_graph_id:
        optionalStringDep(policy.workflow_graph_id) ??
        optionalStringDep(request.workflow_graph_id) ??
        null,
      workflow_node_id:
        optionalStringDep(policy.workflow_node_id) ??
        optionalStringDep(request.workflow_node_id) ??
        `runtime.${componentKind.replaceAll("_", "-")}`,
      component_kind: componentKind,
      payload_schema_version:
        optionalStringDep(policy.payload_schema_version) ??
        `ioi.runtime.${componentKind.replaceAll("_", "-")}.v1`,
      payload: contextPolicyEventPayload(policy, componentKind),
      receipt_refs: stringRefs(policy.receipt_refs),
      policy_decision_refs: stringRefs(policy.policy_decision_refs),
      artifact_refs: stringRefs(policy.artifact_refs),
      rollback_refs: stringRefs(policy.rollback_refs),
      redaction_profile: optionalStringDep(policy.redaction_profile) ?? "internal",
      created_at: createdAt,
      evidence_refs: evidenceRefs,
    };
    const admittedEvent = objectRecord(store.appendRuntimeEvent(event));
    const admittedEventId = optionalStringDep(admittedEvent?.event_id);
    const admittedSeq = positiveInteger(admittedEvent?.seq);
    if (!admittedEvent || !admittedEventId || !admittedSeq) {
      throwContextPolicyEventError({
        code: "runtime_context_policy_event_admission_incomplete",
        message: "Rust Agentgres runtime-event admission did not return an admitted event identity.",
        evidenceRefs,
        details: {
          thread_id: threadId,
          run_id: runId,
          event_id: eventId,
          component_kind: componentKind,
        },
      });
    }
    return admittedEvent;
  }

  function contextPolicyEventPayload(policy, componentKind) {
    if (componentKind === "context_budget") {
      return {
        status: policy.status,
        mode: policy.mode ?? null,
        scope: policy.scope ?? null,
        summary: policy.summary ?? null,
        policy_decision_id: policy.policy_decision_id ?? null,
        policy_decision: objectRecord(policy.policy_decision) ?? null,
        usage_telemetry: objectRecord(policy.usage_telemetry) ?? {},
        usage_summary: objectRecord(policy.usage_summary) ?? {},
        thresholds: objectRecord(policy.thresholds) ?? null,
        warnings: normalizeArray(policy.warnings),
        violations: normalizeArray(policy.violations),
        would_block: policy.would_block ?? null,
      };
    }
    return {
      status: policy.status,
      action: policy.action ?? null,
      selected_action: policy.selected_action ?? null,
      budget_status: policy.budget_status ?? null,
      summary: policy.summary ?? null,
      policy_decision_id: policy.policy_decision_id ?? null,
      context_budget: objectRecord(policy.context_budget) ?? {},
      approval_id: policy.approval_id ?? null,
      approval_required: policy.approval_required ?? null,
      approval_granted: policy.approval_granted ?? null,
      approval_satisfied: policy.approval_satisfied ?? null,
      execute_compaction: policy.execute_compaction ?? null,
      compaction_requested: policy.compaction_requested ?? null,
      compact_reason: policy.compact_reason ?? null,
      compact_scope: policy.compact_scope ?? null,
      continuation_allowed: policy.continuation_allowed ?? null,
    };
  }

  function contextPolicyResultEnvelope(policy, event, evidenceRefs) {
    return {
      ...policy,
      event,
      event_id: event.event_id,
      seq: event.seq,
      receipt_refs: uniqueRefs(policy.receipt_refs, event.receipt_refs),
      policy_decision_refs: uniqueRefs(policy.policy_decision_refs, event.policy_decision_refs),
      evidence_refs: evidenceRefs,
    };
  }

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

  function contextCompactionEventId(threadId, targetId, suffix) {
    return [
      "event_context_compaction",
      safeIdSegment(threadId),
      safeIdSegment(targetId),
      safeIdSegment(suffix),
    ].join("_");
  }

  function contextPolicyEventId(componentKind, threadId, policyDecisionId, suffix) {
    return [
      "event",
      safeIdSegment(componentKind),
      safeIdSegment(threadId),
      safeIdSegment(policyDecisionId),
      safeIdSegment(suffix),
    ].join("_");
  }

  function throwContextPolicyEventError({
    status = 502,
    code,
    message,
    evidenceRefs,
    details = {},
  }) {
    throw runtimeError({
      status,
      code,
      message,
      details: {
        rust_core_boundary: "runtime.context_policy",
        evidence_refs: evidenceRefs,
        ...details,
      },
    });
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
