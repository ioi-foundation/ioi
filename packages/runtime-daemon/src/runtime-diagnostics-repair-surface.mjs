import {
  DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_OPERATOR_OVERRIDE_NODE_ID,
  LSP_DIAGNOSTICS_REPAIR_RESTORE_APPLY_NODE_ID,
  LSP_DIAGNOSTICS_REPAIR_RESTORE_PREVIEW_NODE_ID,
  LSP_DIAGNOSTICS_REPAIR_RETRY_NODE_ID,
} from "./runtime-contract-constants.mjs";
import {
  eventStreamIdForThread,
  lifecycleStatusForRun,
  runIdForTurn,
} from "./runtime-identifiers.mjs";
import { createContextPolicyRunnerFromEnv } from "./runtime-context-policy-runner.mjs";
import { notFound, runtimeError as defaultRuntimeError } from "./runtime-http-utils.mjs";
import {
  doctorHash,
  normalizeArray,
  operatorControlSource,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

const RETIRED_DIAGNOSTICS_REPAIR_RESTORE_REQUEST_ALIASES = [
  "snapshotId",
  "workflowGraphId",
  "workflowNodeId",
  "restorePreviewIdempotencyKey",
  "restoreApplyIdempotencyKey",
  "approvalDecision",
  "policyDecision",
  "confirmRestoreApply",
  "applyConfirmed",
  "approvalGranted",
  "allowConflicts",
  "overrideConflicts",
  "restoreConflictPolicy",
  "conflictPolicy",
];

const CANONICAL_DIAGNOSTICS_REPAIR_RESTORE_REQUEST_FIELDS = [
  "snapshot_id",
  "workflow_graph_id",
  "workflow_node_id",
  "restore_preview_idempotency_key",
  "restore_apply_idempotency_key",
  "approval_decision",
  "policy_decision",
  "confirm_restore_apply",
  "apply_confirmed",
  "approval_granted",
  "allow_conflicts",
  "override_conflicts",
  "restore_conflict_policy",
  "conflict_policy",
];

export function createRuntimeDiagnosticsRepairSurface(deps = {}) {
  const {
    diagnosticsRepairApplyApprovalKey,
    diagnosticsRepairExecutionStatus,
    diagnosticsOperatorOverrideApprovalForRequest,
    diagnosticsOperatorOverrideApprovalKey,
    diagnosticsOperatorOverrideResultFromEvent,
    diagnosticsRepairRetryFeedback,
    diagnosticsRepairRetryResultFromEvent,
    contextPolicyRunner: contextPolicyRunnerDep = createContextPolicyRunnerFromEnv(),
    runtimeError = defaultRuntimeError,
  } = deps;

  function plannedDiagnosticsOperatorOverrideRunRecord(stateUpdate, threadId, runId) {
    const updatedRun = stateUpdate.run;
    if (!updatedRun?.id) {
      throw runtimeError({
        status: 502,
        code: "diagnostics_operator_override_state_update_planner_invalid",
        message: "Rust diagnostics operator override state planning did not return a run record.",
        details: { threadId, runId },
      });
    }
    return updatedRun;
  }

  function plannedDiagnosticsOperatorOverrideOperationKind(stateUpdate, threadId, runId) {
    const operationKind = optionalString(stateUpdate.operation_kind);
    if (!operationKind) {
      throw runtimeError({
        status: 502,
        code: "diagnostics_operator_override_state_update_operation_kind_missing",
        message: "Rust diagnostics operator override planning did not return an operation kind.",
        details: { threadId, runId, operationKind: "diagnostics.operator_override.event" },
      });
    }
    if (operationKind !== "diagnostics.operator_override.event") {
      throw runtimeError({
        status: 502,
        code: "diagnostics_operator_override_state_update_operation_kind_mismatch",
        message: "Rust diagnostics operator override planning returned an unexpected operation kind.",
        details: {
          threadId,
          runId,
          expectedOperationKind: "diagnostics.operator_override.event",
          operationKind,
        },
      });
    }
    return operationKind;
  }

  function executeDiagnosticsRepairDecision(store, threadId, decisionRef, request = {}) {
    store.agentForThread(threadId);
    const target = optionalString(decisionRef ?? request.decision_id ?? request.decisionId ?? request.action);
    if (!target) {
      throw runtimeError({
        status: 400,
        code: "diagnostics_repair_decision_required",
        message: "Diagnostics repair decision execution requires a decision id or action.",
        details: { threadId },
      });
    }
    const resolution = store.resolveDiagnosticsRepairDecision(threadId, target, request);
    const { gateEvent, decision, repairPolicy } = resolution;
    const action = optionalString(decision.action)?.toLowerCase();
    if (!action) {
      throw runtimeError({
        status: 409,
        code: "diagnostics_repair_decision_invalid",
        message: "Diagnostics repair decision is missing an action.",
        details: { threadId, decisionRef: target },
      });
    }
    if (!["repair_retry", "restore_preview", "restore_apply", "operator_override"].includes(action)) {
      throw runtimeError({
        status: 409,
        code: "diagnostics_repair_decision_action_unimplemented",
        message: `Diagnostics repair decision action is not executable yet: ${action}.`,
        details: {
          threadId,
          decisionRef: target,
          action,
          supportedActions: ["repair_retry", "restore_preview", "restore_apply", "operator_override"],
        },
      });
    }
    if (decision.status && !["available", "requires_approval"].includes(decision.status)) {
      throw runtimeError({
        status: 409,
        code: "diagnostics_repair_decision_unavailable",
        message: `Diagnostics repair decision is not available: ${decision.status}.`,
        details: { threadId, decisionRef: target, action, status: decision.status },
      });
    }
    assertCanonicalDiagnosticsRepairRestoreRequestBody(action, request);
    const snapshotId =
      optionalString(request.snapshot_id) ??
      uniqueStrings([
        ...normalizeArray(decision.workspaceSnapshotRefs ?? decision.workspace_snapshot_refs),
        ...normalizeArray(repairPolicy.workspaceSnapshotRefs ?? repairPolicy.workspace_snapshot_refs),
        ...normalizeArray(gateEvent.payload_summary?.workspace_snapshot_refs),
      ])[0];
    if (!snapshotId && ["restore_preview", "restore_apply"].includes(action)) {
      throw runtimeError({
        status: 409,
        code: "diagnostics_repair_snapshot_required",
        message: "Restore repair decision requires a workspace snapshot ref.",
        details: { threadId, decisionRef: target, action },
      });
    }
    const workflowGraphId = optionalString(request.workflow_graph_id ?? gateEvent.workflow_graph_id);
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      (action === "repair_retry"
        ? LSP_DIAGNOSTICS_REPAIR_RETRY_NODE_ID
        : action === "operator_override"
        ? LSP_DIAGNOSTICS_OPERATOR_OVERRIDE_NODE_ID
        : action === "restore_apply"
        ? LSP_DIAGNOSTICS_REPAIR_RESTORE_APPLY_NODE_ID
        : LSP_DIAGNOSTICS_REPAIR_RESTORE_PREVIEW_NODE_ID);
    const decisionId = decision.decision_id ?? decision.decisionId ?? target;
    const executionResult =
      action === "repair_retry"
        ? store.createDiagnosticsRepairRetryTurn(threadId, {
            request,
            gateEvent,
            decision,
            repairPolicy,
            snapshotId,
            workflowGraphId,
            workflowNodeId,
          })
        : action === "operator_override"
        ? store.executeDiagnosticsOperatorOverride(threadId, {
            request,
            gateEvent,
            decision,
            repairPolicy,
            snapshotId,
            workflowGraphId,
            workflowNodeId,
          })
        : action === "restore_apply"
        ? store.applyWorkspaceSnapshotRestore(threadId, snapshotId, {
            source: request.source ?? "runtime_auto",
            workflow_graph_id: workflowGraphId,
            workflow_node_id: workflowNodeId,
            idempotency_key:
              optionalString(request.restore_apply_idempotency_key) ??
              `thread:${threadId}:diagnostics-repair-apply:${decisionId}:${snapshotId}:${diagnosticsRepairApplyApprovalKey(request)}`,
            actor: request.actor ?? "operator",
            approval: request.approval,
            approval_decision: request.approval_decision,
            policy_decision: request.policy_decision,
            decision: request.decision,
            confirm: request.confirm,
            confirmed: request.confirmed,
            confirm_restore_apply: request.confirm_restore_apply,
            apply_confirmed: request.apply_confirmed,
            approval_granted: request.approval_granted,
            approved: request.approved,
            allow_conflicts: request.allow_conflicts,
            override_conflicts: request.override_conflicts,
            restore_conflict_policy:
              request.restore_conflict_policy ??
              decision.restore_conflict_policy ??
              repairPolicy.restore_conflict_policy,
            diagnostics_repair_decision_id: decisionId,
            diagnostics_repair_action: action,
            diagnostics_blocking_gate_event_id: gateEvent.event_id,
          })
        : store.previewWorkspaceSnapshotRestore(threadId, snapshotId, {
            source: request.source ?? "runtime_auto",
            workflow_graph_id: workflowGraphId,
            workflow_node_id: workflowNodeId,
            idempotency_key:
              optionalString(request.restore_preview_idempotency_key) ??
              `thread:${threadId}:diagnostics-repair-preview:${decisionId}:${snapshotId}:${action}`,
            actor: request.actor ?? "operator",
            diagnostics_repair_decision_id: decisionId,
            diagnostics_repair_action: action,
            diagnostics_blocking_gate_event_id: gateEvent.event_id,
          });
    const event = store.appendDiagnosticsRepairDecisionExecutedEvent({
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      action,
      snapshotId,
      workflowGraphId,
      workflowNodeId,
      executionResult,
    });
    const repairRetry = action === "repair_retry" ? executionResult : null;
    const operatorOverride = action === "operator_override" ? executionResult : null;
    const restorePreview = action === "restore_preview" ? executionResult : null;
    const restoreApply = action === "restore_apply" ? executionResult : null;
    return {
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      object: "ioi.runtime_diagnostics_repair_decision_execution",
      thread_id: threadId,
      decision_id: decisionId,
      action,
      status: diagnosticsRepairExecutionStatus(executionResult),
      gate_event_id: gateEvent.event_id,
      policy_id: repairPolicy.policy_id ?? repairPolicy.policyId ?? null,
      snapshot_id: snapshotId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      decision,
      repair_policy: repairPolicy,
      repair_retry: repairRetry,
      repair_turn: repairRetry?.repair_turn ?? null,
      repair_retry_event: repairRetry?.event ?? null,
      operator_override: operatorOverride,
      operator_override_event: operatorOverride?.event ?? null,
      restore_preview: restorePreview,
      restore_apply: restoreApply,
      restore_preview_event: restorePreview?.event ?? null,
      restore_apply_event: restoreApply?.event ?? null,
      event,
      receipt_refs: event.receipt_refs,
      artifact_refs: event.artifact_refs,
      policy_decision_refs: event.policy_decision_refs,
      rollback_refs: event.rollback_refs,
      summary: `Executed diagnostics repair decision ${action}${snapshotId ? ` for ${snapshotId}` : ""}.`,
    };
  }

  function assertCanonicalDiagnosticsRepairRestoreRequestBody(action, request = {}) {
    if (!["restore_preview", "restore_apply"].includes(action)) return;
    const retiredAliases = RETIRED_DIAGNOSTICS_REPAIR_RESTORE_REQUEST_ALIASES.filter((field) =>
      Object.prototype.hasOwnProperty.call(request, field),
    );
    if (retiredAliases.length === 0) return;
    throw runtimeError({
      status: 400,
      code: "diagnostics_repair_restore_request_aliases_retired",
      message: "Diagnostics repair restore request aliases are retired; use canonical snake_case fields.",
      details: {
        retired_aliases: retiredAliases,
        canonical_fields: CANONICAL_DIAGNOSTICS_REPAIR_RESTORE_REQUEST_FIELDS,
      },
    });
  }

  function executeDiagnosticsOperatorOverride(store, threadId, {
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    snapshotId = null,
    workflowGraphId = null,
    workflowNodeId = LSP_DIAGNOSTICS_OPERATOR_OVERRIDE_NODE_ID,
  } = {}) {
    const agent = store.agentForThread(threadId);
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? "operator_override";
    const approval = diagnosticsOperatorOverrideApprovalForRequest(request, { decision, repairPolicy });
    const approvalKey = diagnosticsOperatorOverrideApprovalKey(approval);
    const idempotencyKey =
      optionalString(request.operator_override_idempotency_key ?? request.operatorOverrideIdempotencyKey) ??
      `thread:${threadId}:diagnostics-operator-override:${decisionId}:${gateEvent?.event_id ?? "gate"}:${approvalKey}`;
    const duplicate = store.runtimeEventStream(eventStreamIdForThread(threadId)).idempotency.get(idempotencyKey);
    if (duplicate) {
      return diagnosticsOperatorOverrideResultFromEvent({
        threadId,
        event: duplicate,
        turn: turnForOperatorOverrideEvent(store, duplicate),
      });
    }

    const status = approval.required && !approval.satisfied ? "blocked" : "completed";
    const targetTurnId = optionalString(gateEvent?.turn_id ?? gateEvent?.payload_summary?.turn_id);
    const targetRunId = targetTurnId ? runIdForTurn(targetTurnId) : null;
    let previousTurnStatus = null;
    let nextTurnStatus = null;
    let turn = null;
    if (targetRunId && status === "completed") {
      const run = store.getRun(targetRunId);
      if (run.agentId !== agent.id) {
        throw notFound(`Turn not found: ${targetTurnId}`, { threadId, turnId: targetTurnId, runId: targetRunId });
      }
      previousTurnStatus = run.turnStatus ?? lifecycleStatusForRun(run.status);
      nextTurnStatus = "completed";
    }

    const event = store.appendDiagnosticsOperatorOverrideEvent({
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      snapshotId,
      workflowGraphId,
      workflowNodeId,
      approval,
      status,
      targetTurnId,
      targetRunId,
      previousTurnStatus,
      nextTurnStatus,
      idempotencyKey,
    });

    if (targetRunId && status === "completed") {
      const run = store.getRun(targetRunId);
      const stateUpdate = contextPolicyRunnerDep.planDiagnosticsOperatorOverrideStateUpdate({
        thread_id: threadId,
        run_id: run.id,
        run,
        event_id: event.event_id,
        seq: event.seq,
        created_at: event.created_at,
        decision_id: decisionId,
        gate_event_id: gateEvent?.event_id ?? null,
        source: operatorControlSource(request.source),
        approval_required: approval.required,
        approval_satisfied: approval.satisfied,
        approval_source: approval.source,
        snapshot_id: snapshotId,
      });
      const updated = plannedDiagnosticsOperatorOverrideRunRecord(stateUpdate, threadId, run.id);
      const operationKind = plannedDiagnosticsOperatorOverrideOperationKind(stateUpdate, threadId, run.id);
      store.runs.set(run.id, updated);
      store.writeRun(updated, operationKind);
      turn = store.turnForRun(updated);
      nextTurnStatus = turn.status;
    }

    return diagnosticsOperatorOverrideResultFromEvent({ threadId, event, turn });
  }

  function turnForOperatorOverrideEvent(store, event = {}) {
    const payload = event.payload_summary ?? event.payload ?? {};
    const targetTurnId = optionalString(payload.target_turn_id ?? payload.targetTurnId);
    if (!targetTurnId) return null;
    try {
      return store.getTurn(event.thread_id, targetTurnId);
    } catch {
      return null;
    }
  }

  function appendDiagnosticsOperatorOverrideEvent(store, {
    threadId,
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    snapshotId,
    workflowGraphId,
    workflowNodeId,
    approval,
    status,
    targetTurnId,
    targetRunId,
    previousTurnStatus,
    nextTurnStatus,
    idempotencyKey,
  } = {}) {
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? "operator_override";
    const receiptId = `receipt_lsp_diagnostics_operator_override_${doctorHash(
      `${threadId}:${decisionId}:${status}:${approval?.source ?? ""}`,
    ).slice(0, 12)}`;
    const rollbackRefs = uniqueStrings([
      snapshotId,
      ...normalizeArray(decision?.rollbackRefs ?? decision?.rollback_refs),
      ...normalizeArray(repairPolicy?.rollbackRefs ?? repairPolicy?.rollback_refs),
      ...normalizeArray(gateEvent?.rollback_refs),
      ...normalizeArray(gateEvent?.payload_summary?.rollback_refs ?? gateEvent?.payload_summary?.rollbackRefs),
    ]);
    const policyDecisionRefs = uniqueStrings([
      decisionId,
      repairPolicy?.policy_id ?? repairPolicy?.policyId,
      ...normalizeArray(gateEvent?.policy_decision_refs),
      `policy_lsp_diagnostics_operator_override_${approval?.satisfied ? "approval_satisfied" : "approval_required"}`,
      status === "completed" ? "policy_lsp_diagnostics_operator_override_continuation_allowed" : null,
    ]);
    const payloadSummary = {
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      event_kind: "LspDiagnosticsOperatorOverrideExecuted",
      thread_id: threadId,
      decision_id: decisionId,
      action: "operator_override",
      status,
      gate_event_id: gateEvent?.event_id ?? null,
      gate_id: gateEvent?.payload_summary?.gate_id ?? null,
      policy_id: repairPolicy?.policy_id ?? repairPolicy?.policyId ?? null,
      snapshot_id: snapshotId ?? null,
      target_turn_id: targetTurnId ?? null,
      target_run_id: targetRunId ?? null,
      previous_turn_status: previousTurnStatus ?? null,
      next_turn_status: nextTurnStatus ?? null,
      approval_required: Boolean(approval?.required),
      approval_satisfied: Boolean(approval?.satisfied),
      approval_source: approval?.source ?? "missing",
      continuation_allowed: status === "completed",
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      rollback_refs: rollbackRefs,
      receipt_refs: [receiptId],
      artifact_refs: [],
      policy_decision_refs: policyDecisionRefs,
      decision,
      summary:
        status === "completed"
          ? `Diagnostics operator override granted for ${decisionId}.`
          : `Diagnostics operator override blocked for ${decisionId}: approval is required.`,
    };
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: targetTurnId ?? gateEvent?.turn_id ?? "",
      item_id: `${targetTurnId || threadId}:item:diagnostics-operator-override:${safeId(String(decisionId))}`,
      idempotency_key: idempotencyKey,
      source: operatorControlSource(request.source),
      source_event_kind: "LspDiagnostics.OperatorOverrideExecuted",
      event_kind: "diagnostics.operator_override.executed",
      status,
      actor: optionalString(request.actor) ?? "operator",
      workspace_root: gateEvent?.workspace_root ?? store.agentForThread(threadId).cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "lsp_diagnostics_operator_override",
      tool_call_id: snapshotId ?? null,
      receipt_refs: [receiptId],
      artifact_refs: [],
      policy_decision_refs: policyDecisionRefs,
      rollback_refs: rollbackRefs,
      payload_schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
  }

  function createDiagnosticsRepairRetryTurn(store, threadId, {
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    snapshotId = null,
    workflowGraphId = null,
    workflowNodeId = LSP_DIAGNOSTICS_REPAIR_RETRY_NODE_ID,
  } = {}) {
    const agent = store.agentForThread(threadId);
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? "repair_retry";
    const idempotencyKey =
      optionalString(request.repair_retry_idempotency_key ?? request.repairRetryIdempotencyKey) ??
      `thread:${threadId}:diagnostics-repair-retry:${decisionId}:${gateEvent?.event_id ?? "gate"}:${snapshotId ?? "no-snapshot"}`;
    const duplicate = store.runtimeEventStream(eventStreamIdForThread(threadId)).idempotency.get(idempotencyKey);
    if (duplicate) {
      return diagnosticsRepairRetryResultFromEvent({
        threadId,
        event: duplicate,
        turn: turnForRepairRetryEvent(store, duplicate),
      });
    }

    const diagnosticsFeedback = diagnosticsRepairRetryFeedback({
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      snapshotId,
    });
    const prompt =
      optionalString(request.prompt ?? request.message ?? request.input) ??
      "Repair the blocking post-edit diagnostics and retry the turn.";
    const run = store.createRun(agent.id, {
      mode: request.mode ?? "send",
      prompt,
      options: {
        ...(request.options ?? {}),
        diagnosticsMode: "skip",
        diagnostics_mode: "skip",
      },
      memory: request.memory,
      remember: request.remember,
      diagnosticsFeedback,
    });
    const turn = store.turnForRun(run);
    const event = store.appendDiagnosticsRepairRetryTurnEvent({
      threadId,
      request,
      gateEvent,
      decision,
      repairPolicy,
      snapshotId,
      workflowGraphId,
      workflowNodeId,
      run,
      turn,
      diagnosticsFeedback,
      idempotencyKey,
    });
    return diagnosticsRepairRetryResultFromEvent({ threadId, event, turn, run });
  }

  function turnForRepairRetryEvent(store, event = {}) {
    const payload = event.payload_summary ?? event.payload ?? {};
    const retryTurnId = optionalString(payload.retry_turn_id ?? payload.retryTurnId);
    if (!retryTurnId) return null;
    try {
      return store.getTurn(event.thread_id, retryTurnId);
    } catch {
      return null;
    }
  }

  function appendDiagnosticsRepairRetryTurnEvent(store, {
    threadId,
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    snapshotId,
    workflowGraphId,
    workflowNodeId,
    run,
    turn,
    diagnosticsFeedback,
    idempotencyKey,
  } = {}) {
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? "repair_retry";
    const receiptId = `receipt_lsp_diagnostics_repair_retry_${doctorHash(
      `${threadId}:${decisionId}:${turn?.turn_id ?? run?.id ?? ""}`,
    ).slice(0, 12)}`;
    const rollbackRefs = uniqueStrings([
      snapshotId,
      ...normalizeArray(decision?.rollbackRefs ?? decision?.rollback_refs),
      ...normalizeArray(repairPolicy?.rollbackRefs ?? repairPolicy?.rollback_refs),
      ...normalizeArray(gateEvent?.rollback_refs),
      ...normalizeArray(diagnosticsFeedback?.rollbackRefs ?? diagnosticsFeedback?.rollback_refs),
    ]);
    const policyDecisionRefs = uniqueStrings([
      decisionId,
      repairPolicy?.policy_id ?? repairPolicy?.policyId,
      ...normalizeArray(gateEvent?.policy_decision_refs),
    ]);
    const artifactRefs = uniqueStrings(
      normalizeArray(run?.artifacts).map((artifactRecord) => artifactRecord?.id),
    );
    const payloadSummary = {
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      event_kind: "LspDiagnosticsRepairRetryTurnCreated",
      thread_id: threadId,
      decision_id: decisionId,
      action: "repair_retry",
      status: turn?.status ?? "completed",
      gate_event_id: gateEvent?.event_id ?? null,
      gate_id: gateEvent?.payload_summary?.gate_id ?? null,
      policy_id: repairPolicy?.policy_id ?? repairPolicy?.policyId ?? null,
      snapshot_id: snapshotId ?? null,
      retry_turn_id: turn?.turn_id ?? null,
      retry_request_id: turn?.request_id ?? run?.id ?? null,
      repair_prompt_injected: true,
      diagnostics_mode: diagnosticsFeedback?.mode ?? "repair_retry",
      diagnostic_status: diagnosticsFeedback?.diagnosticStatus ?? null,
      diagnostic_count: diagnosticsFeedback?.diagnosticCount ?? null,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      rollback_refs: rollbackRefs,
      receipt_refs: [receiptId],
      artifact_refs: artifactRefs,
      policy_decision_refs: policyDecisionRefs,
      decision,
      summary: `Diagnostics repair retry created turn ${turn?.turn_id ?? "unknown"} for ${decisionId}.`,
    };
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turn?.turn_id ?? "",
      item_id: `${turn?.turn_id || threadId}:item:diagnostics-repair-retry:${safeId(String(decisionId))}`,
      idempotency_key: idempotencyKey,
      source: operatorControlSource(request.source),
      source_event_kind: "LspDiagnostics.RepairRetryTurnCreated",
      event_kind: "diagnostics.repair_retry.created",
      status: "completed",
      actor: optionalString(request.actor) ?? "operator",
      workspace_root: gateEvent?.workspace_root ?? store.agentForThread(threadId).cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "lsp_diagnostics_repair_retry",
      tool_call_id: snapshotId ?? null,
      receipt_refs: [receiptId],
      artifact_refs: artifactRefs,
      policy_decision_refs: policyDecisionRefs,
      rollback_refs: rollbackRefs,
      payload_schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
  }

  function resolveDiagnosticsRepairDecision(store, threadId, decisionRef, request = {}) {
    store.projectThreadEvents(store.agentForThread(threadId));
    const gateId = optionalString(request.gate_id ?? request.gateId);
    const target = optionalString(decisionRef)?.toLowerCase();
    const action = optionalString(request.action ?? request.decision_action ?? request.decisionAction)?.toLowerCase();
    const gateEvents = store.runtimeEventsForStream(eventStreamIdForThread(threadId), { sinceSeq: 0 })
      .filter((event) => event.event_kind === "policy.blocked" && event.component_kind === "lsp_diagnostics_gate")
      .filter((event) => {
        if (!gateId) return true;
        return (
          event.payload_summary?.gate_id === gateId ||
          event.payload_summary?.gateId === gateId ||
          event.payload?.gate_id === gateId ||
          event.payload?.gateId === gateId
        );
      })
      .sort((left, right) => right.seq - left.seq);
    for (const gateEvent of gateEvents) {
      const repairPolicy = gateEvent.payload_summary?.repair_policy ?? gateEvent.payload_summary?.repairPolicy ?? {};
      const decisions = normalizeArray(
        repairPolicy.decisions ??
          gateEvent.payload_summary?.repair_decisions ??
          gateEvent.payload_summary?.repairDecisions,
      );
      const decision = decisions.find((candidate) => {
        const candidateId = optionalString(candidate.decision_id ?? candidate.decisionId)?.toLowerCase();
        const candidateAction = optionalString(candidate.action)?.toLowerCase();
        return candidateId === target || candidateAction === target || (action && candidateAction === action);
      });
      if (decision) return { gateEvent, decision, repairPolicy };
    }
    throw notFound(`Diagnostics repair decision not found: ${decisionRef}`, {
      threadId,
      decisionRef,
      gateId,
    });
  }

  function appendDiagnosticsRepairDecisionExecutedEvent(store, {
    threadId,
    request = {},
    gateEvent,
    decision,
    repairPolicy,
    action,
    snapshotId,
    workflowGraphId,
    workflowNodeId,
    executionResult,
  } = {}) {
    const decisionId = decision?.decision_id ?? decision?.decisionId ?? action;
    const receiptId = `receipt_lsp_diagnostics_repair_${safeId(action)}_${doctorHash(
      `${threadId}:${decisionId}:${snapshotId}:${executionResult?.event?.event_id ?? ""}`,
    ).slice(0, 12)}`;
    const policyDecisionRefs = uniqueStrings([
      decisionId,
      repairPolicy?.policy_id ?? repairPolicy?.policyId,
      ...normalizeArray(gateEvent?.policy_decision_refs),
      ...normalizeArray(executionResult?.policy_decision_refs ?? executionResult?.policyDecisionRefs),
    ]);
    const artifactRefs = uniqueStrings(normalizeArray(executionResult?.artifact_refs ?? executionResult?.artifactRefs));
    const rollbackRefs = uniqueStrings([
      snapshotId,
      ...normalizeArray(executionResult?.rollback_refs ?? executionResult?.rollbackRefs),
    ]);
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: gateEvent?.turn_id ?? "",
      item_id: `${gateEvent?.turn_id || threadId}:item:diagnostics-repair:${safeId(String(decisionId))}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
        `thread:${threadId}:diagnostics-repair:${decisionId}:${snapshotId}:${action}:${
          action === "operator_override"
            ? diagnosticsOperatorOverrideApprovalKey(
                diagnosticsOperatorOverrideApprovalForRequest(request, { decision, repairPolicy }),
              )
            : "default"
        }`,
      source: operatorControlSource(request.source),
      source_event_kind: "LspDiagnostics.RepairDecisionExecuted",
      event_kind: "diagnostics.repair_decision.executed",
      status: diagnosticsRepairExecutionStatus(executionResult),
      actor: optionalString(request.actor) ?? "operator",
      workspace_root: gateEvent?.workspace_root ?? "",
      workflow_graph_id: workflowGraphId,
      workflow_node_id: `${workflowNodeId}.decision`,
      component_kind: "lsp_diagnostics_repair",
      tool_call_id: snapshotId,
      receipt_refs: [receiptId],
      artifact_refs: artifactRefs,
      policy_decision_refs: policyDecisionRefs,
      rollback_refs: rollbackRefs,
      payload_schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      payload_summary: {
        schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
        event_kind: "LspDiagnosticsRepairDecisionExecuted",
        thread_id: threadId,
        decision_id: decisionId,
        action,
        status: diagnosticsRepairExecutionStatus(executionResult),
        gate_event_id: gateEvent?.event_id ?? null,
        gate_id: gateEvent?.payload_summary?.gate_id ?? null,
        policy_id: repairPolicy?.policy_id ?? repairPolicy?.policyId ?? null,
        snapshot_id: snapshotId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        repair_retry_event_id: action === "repair_retry" ? executionResult?.event?.event_id ?? null : null,
        repair_retry_turn_id:
          action === "repair_retry"
            ? executionResult?.repair_turn?.turn_id ?? executionResult?.repairTurn?.turn_id ?? null
            : null,
        repair_retry_request_id:
          action === "repair_retry"
            ? executionResult?.repair_turn?.request_id ?? executionResult?.repairTurn?.request_id ?? null
            : null,
        operator_override_event_id: action === "operator_override" ? executionResult?.event?.event_id ?? null : null,
        operator_override_status:
          action === "operator_override"
            ? executionResult?.override_status ?? executionResult?.overrideStatus ?? executionResult?.status ?? null
            : null,
        operator_override_approval_required:
          action === "operator_override"
            ? executionResult?.approval_required ?? executionResult?.approvalRequired ?? null
            : null,
        operator_override_approval_satisfied:
          action === "operator_override"
            ? executionResult?.approval_satisfied ?? executionResult?.approvalSatisfied ?? null
            : null,
        operator_override_continuation_allowed:
          action === "operator_override"
            ? executionResult?.continuation_allowed ?? executionResult?.continuationAllowed ?? null
            : null,
        restore_preview_event_id: action === "restore_preview" ? executionResult?.event?.event_id ?? null : null,
        restore_preview_status: executionResult?.preview_status ?? executionResult?.previewStatus ?? null,
        restore_apply_event_id: action === "restore_apply" ? executionResult?.event?.event_id ?? null : null,
        restore_apply_status: executionResult?.apply_status ?? executionResult?.applyStatus ?? null,
        approval_satisfied: executionResult?.approval_satisfied ?? executionResult?.approvalSatisfied ?? null,
        rollback_refs: rollbackRefs,
        receipt_refs: [receiptId],
        artifact_refs: artifactRefs,
        policy_decision_refs: policyDecisionRefs,
        decision,
        summary: `Diagnostics repair decision ${action} executed${snapshotId ? ` for ${snapshotId}` : ""}.`,
      },
    });
  }

  return {
    appendDiagnosticsOperatorOverrideEvent,
    appendDiagnosticsRepairDecisionExecutedEvent,
    appendDiagnosticsRepairRetryTurnEvent,
    createDiagnosticsRepairRetryTurn,
    executeDiagnosticsRepairDecision,
    executeDiagnosticsOperatorOverride,
    resolveDiagnosticsRepairDecision,
    turnForOperatorOverrideEvent,
    turnForRepairRetryEvent,
  };
}
