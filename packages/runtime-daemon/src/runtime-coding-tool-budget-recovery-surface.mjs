import {
  eventStreamIdForThread,
  fixtureProfileForAgent,
  threadIdForAgent,
  turnIdForRun,
} from "./runtime-identifiers.mjs";
import { createCodingToolBudgetRecovery } from "./runtime-coding-tool-budget-recovery.mjs";
import {
  WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION,
  WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
  WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
} from "./runtime-contract-constants.mjs";
import {
  appendOperatorControl,
  normalizeArray,
  operatorControlSource,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

function defaultRuntimeError(payload = {}) {
  const error = new Error(payload.message || "Runtime error");
  Object.assign(error, payload);
  return error;
}

function defaultNotFound(message, details) {
  const error = new Error(message);
  error.status = 404;
  error.details = details;
  return error;
}

function defaultApprovalReasonForDecisionEvent(event) {
  const payload = event?.payload_summary ?? event?.payload ?? {};
  return optionalString(payload.reason ?? event?.reason) ?? "approval_not_satisfied";
}

export function createRuntimeCodingToolBudgetRecoverySurface(deps = {}) {
  const {
    approvalReasonForDecisionEvent = defaultApprovalReasonForDecisionEvent,
    notFound = defaultNotFound,
    runtimeError = defaultRuntimeError,
  } = deps;
  const {
    codingToolBudgetRecoveryAction,
    codingToolBudgetRecoveryPolicyFromInputs,
    codingToolBudgetRecoveryResult,
    codingToolBudgetRecoveryTargetNodeIds,
    isCodingToolBudgetBlockedRuntimeEvent,
    recoveryPolicyRetryLimit,
  } = createCodingToolBudgetRecovery({
    WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION,
    WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
    WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
    normalizeArray,
    optionalString,
    runtimeError,
    uniqueStrings,
  });

  function latestCodingToolBudgetBlockedEventForRun(store, runId, sourceEventId = null) {
    const run = store.getRun(runId);
    const agent = store.getAgent(run.agentId);
    store.projectThreadEvents(agent);
    const turnId = turnIdForRun(run.id);
    const events = store.runtimeEventsForTurn(turnId);
    const explicitSourceEventId = optionalString(sourceEventId);
    if (explicitSourceEventId) {
      const explicit = events.find((event) => event.event_id === explicitSourceEventId);
      if (explicit) return explicit;
    }
    return events.filter(isCodingToolBudgetBlockedRuntimeEvent).at(-1) ?? null;
  }

  function codingToolBudgetRecoveryForRun(store, runId, request = {}) {
    const run = store.getRun(runId);
    const agent = store.getAgent(run.agentId);
    const expectedThreadId = threadIdForAgent(agent.id);
    const threadId =
      optionalString(request.thread_id ?? request.threadId) ??
      expectedThreadId;
    if (threadId !== expectedThreadId) {
      throw notFound(`Run not found for thread: ${runId}`, { runId, threadId });
    }
    const turnId = turnIdForRun(run.id);
    const action = codingToolBudgetRecoveryAction(
      request.action ?? request.recovery_action ?? request.recoveryAction,
    );
    const source = operatorControlSource(request.source);
    const actor = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const requestedSourceEventId = optionalString(request.source_event_id ?? request.sourceEventId);
    const blockedEvent = latestCodingToolBudgetBlockedEventForRun(store, run.id, requestedSourceEventId);
    const blockedPayload = blockedEvent?.payload_summary ?? blockedEvent?.payload ?? {};
    const sourceEventId = requestedSourceEventId ?? blockedEvent?.event_id ?? null;
    const targetNodeIds = codingToolBudgetRecoveryTargetNodeIds({ request, blockedEvent, blockedPayload });
    const recoveryPolicy = codingToolBudgetRecoveryPolicyFromInputs({
      request,
      blockedPayload,
      targetNodeIds,
      source,
    });
    const approvalId =
      optionalString(request.approval_id ?? request.approvalId) ??
      optionalString(blockedPayload.approval_id ?? blockedPayload.approvalId) ??
      `approval_workflow_run_coding_tool_budget_${safeId(run.id)}_${safeId(sourceEventId ?? "source")}`;
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ??
      optionalString(blockedEvent?.workflow_graph_id ?? blockedPayload.workflow_graph_id ?? blockedPayload.workflowGraphId) ??
      null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      optionalString(blockedEvent?.workflow_node_id ?? blockedPayload.workflow_node_id ?? blockedPayload.workflowNodeId) ??
      targetNodeIds[0] ??
      "runtime.coding-tool-budget-recovery";
    const receiptRefs = uniqueStrings([
      ...normalizeArray(request.receipt_refs ?? request.receiptRefs),
      ...normalizeArray(blockedEvent?.receipt_refs),
      `receipt_${run.id}_coding_tool_budget_recovery_${safeId(action)}_${safeId(approvalId)}`,
    ]);
    const policyDecisionRefs = uniqueStrings([
      ...normalizeArray(request.policy_decision_refs ?? request.policyDecisionRefs),
      ...normalizeArray(blockedEvent?.policy_decision_refs),
      `policy_${run.id}_coding_tool_budget_recovery_${safeId(action)}`,
    ]);
    const approvalManifest = {
      schema_version: WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
      schemaVersion: WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
      action: "workflow_run.coding_budget_recovery",
      recovery_action: action,
      recoveryAction: action,
      reason: WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
      source_event_id: sourceEventId,
      sourceEventId,
      approval_id: approvalId,
      approvalId,
      run_id: run.id,
      runId: run.id,
      thread_id: threadId,
      threadId,
      turn_id: turnId,
      turnId,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      target_node_ids: targetNodeIds,
      targetNodeIds,
      recovery_policy: recoveryPolicy,
      recoveryPolicy,
    };

    if (action === "request_approval") {
      const approval = store.requestThreadApproval(threadId, {
        ...request,
        source,
        actor,
        turnId,
        workflowGraphId,
        workflowNodeId,
        action: "workflow_run.coding_budget_recovery",
        reason: WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
        scope: "coding_tool_budget_recovery",
        approvalId,
        toolId: "coding_tool",
        effectClass: "coding_tool_budget_recovery",
        riskDomain: "runtime_coding_tool_budget",
        authorityScopeRequirements: ["workflow.run.coding_tool_budget_recovery"],
        approvalManifest,
        receiptRefs,
        policyDecisionRefs,
      });
      const approvalEvent = store.latestApprovalRequestEvent(threadId, approval.approval_id);
      return codingToolBudgetRecoveryResult({
        action,
        status: "waiting_for_approval",
        run,
        threadId,
        turnId,
        approvalId: approval.approval_id,
        sourceEventId,
        targetNodeIds,
        workflowGraphId,
        workflowNodeId,
        recoveryPolicy,
        event: approvalEvent,
        approvalEvent,
        receiptRefs: uniqueStrings([...receiptRefs, ...normalizeArray(approval.receipt_refs)]),
        policyDecisionRefs: uniqueStrings([
          ...policyDecisionRefs,
          ...normalizeArray(approval.policy_decision_refs),
        ]),
      });
    }

    if (action === "approve_override" || action === "reject_override") {
      const decision = action === "approve_override" ? "approve" : "reject";
      const decisionResult = store.decideThreadApproval(threadId, approvalId, {
        ...request,
        source,
        actor,
        turnId,
        decision,
        reason: WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON,
        workflowGraphId,
        workflowNodeId,
      });
      const decisionEvent = store.latestApprovalDecisionEvent(threadId, approvalId);
      return codingToolBudgetRecoveryResult({
        action,
        status: decision === "approve" ? "approved" : "rejected",
        run,
        threadId,
        turnId,
        approvalId,
        sourceEventId,
        targetNodeIds,
        workflowGraphId,
        workflowNodeId,
        recoveryPolicy,
        event: decisionEvent,
        decisionEvent,
        receiptRefs: uniqueStrings([...receiptRefs, ...normalizeArray(decisionResult.receipt_refs)]),
        policyDecisionRefs: uniqueStrings([
          ...policyDecisionRefs,
          ...normalizeArray(decisionResult.policy_decision_refs),
        ]),
      });
    }

    const approvalRequestEvent = store.latestApprovalRequestEvent(threadId, approvalId);
    const approvalDecisionEvent = store.latestApprovalDecisionEvent(threadId, approvalId);
    if (recoveryPolicy.requiresApproval !== false) {
      if (!approvalRequestEvent) {
        return codingToolBudgetRecoveryResult({
          action,
          status: "blocked",
          reason: "approval_request_missing",
          run,
          threadId,
          turnId,
          approvalId,
          sourceEventId,
          targetNodeIds,
          workflowGraphId,
          workflowNodeId,
          recoveryPolicy,
          receiptRefs,
          policyDecisionRefs,
        });
      }
      if (!approvalDecisionEvent || approvalDecisionEvent.event_kind !== "approval.approved") {
        return codingToolBudgetRecoveryResult({
          action,
          status: "blocked",
          reason: approvalDecisionEvent
            ? approvalReasonForDecisionEvent(approvalDecisionEvent)
            : "approval_decision_missing",
          run,
          threadId,
          turnId,
          approvalId,
          sourceEventId,
          targetNodeIds,
          workflowGraphId,
          workflowNodeId,
          recoveryPolicy,
          event: approvalDecisionEvent,
          decisionEvent: approvalDecisionEvent,
          receiptRefs,
          policyDecisionRefs,
        });
      }
    }
    const retryLimit = recoveryPolicyRetryLimit(recoveryPolicy);
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    const retryCount = stream.events.filter((event) => {
      if (event.event_kind !== "workflow.run.retry_completed") return false;
      const payload = event.payload_summary ?? event.payload ?? {};
      return (
        event.approval_id === approvalId ||
        payload.approval_id === approvalId ||
        payload.approvalId === approvalId ||
        (sourceEventId &&
          (payload.source_event_id === sourceEventId || payload.sourceEventId === sourceEventId))
      );
    }).length;
    if (retryCount >= retryLimit) {
      return codingToolBudgetRecoveryResult({
        action,
        status: "blocked",
        reason: "retry_limit_exceeded",
        run,
        threadId,
        turnId,
        approvalId,
        sourceEventId,
        targetNodeIds,
        workflowGraphId,
        workflowNodeId,
        recoveryPolicy,
        event: approvalDecisionEvent,
        decisionEvent: approvalDecisionEvent,
        receiptRefs,
        policyDecisionRefs,
      });
    }
    const now = new Date().toISOString();
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId}:item:coding-tool-budget-recovery:${safeId(approvalId)}:${retryCount + 1}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `run:${run.id}:coding-tool-budget-recovery.retry:${approvalId}:${retryCount + 1}`,
      source,
      source_event_kind: "WorkflowRunCodingToolBudgetApprovedRetry",
      event_kind: "workflow.run.retry_completed",
      status: "completed",
      actor,
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "coding_tool",
      approval_id: approvalId,
      payload_schema_version: WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
      payload: {
        ...approvalManifest,
        event_kind: "WorkflowRunCodingToolBudgetApprovedRetry",
        eventKind: "WorkflowRunCodingToolBudgetApprovedRetry",
        recovery_action: "retry_approved",
        recoveryAction: "retry_approved",
        status: "completed",
        approval_satisfied: true,
        approvalSatisfied: true,
        approval_decision_event_id: approvalDecisionEvent?.event_id ?? null,
        approvalDecisionEventId: approvalDecisionEvent?.event_id ?? null,
        retry_count: retryCount + 1,
        retryCount: retryCount + 1,
        retry_limit: retryLimit,
        retryLimit,
        control_surface: source,
        requested_by: actor,
      },
      receipt_refs: receiptRefs,
      policy_decision_refs: policyDecisionRefs,
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "coding_tool_budget_recovery",
      action: "retry_approved",
      approvalId,
      status: "completed",
      source,
      eventId: event.event_id,
      seq: event.seq,
      receiptRefs: event.receipt_refs,
      policyDecisionRefs: event.policy_decision_refs,
      createdAt: event.created_at,
    };
    const updated = {
      ...run,
      updatedAt: event.created_at,
      trace: {
        ...run.trace,
        operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
      },
      operatorControls: appendOperatorControl(run.operatorControls, control),
    };
    store.runs.set(run.id, updated);
    store.writeRun(updated, "workflow.run.retry_completed");
    return codingToolBudgetRecoveryResult({
      action,
      status: "completed",
      run: updated,
      threadId,
      turnId,
      approvalId,
      sourceEventId,
      targetNodeIds,
      workflowGraphId,
      workflowNodeId,
      recoveryPolicy,
      event,
      decisionEvent: approvalDecisionEvent,
      receiptRefs: event.receipt_refs,
      policyDecisionRefs: event.policy_decision_refs,
    });
  }

  return {
    latestCodingToolBudgetBlockedEventForRun,
    codingToolBudgetRecoveryForRun,
  };
}
