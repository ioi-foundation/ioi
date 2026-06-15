import {
  objectRecord,
  optionalString,
  safeId,
} from "../runtime-value-helpers.mjs";

export function createWorkspaceTrustState({
  contextPolicyCore,
  eventStreamIdForThread,
  runtimeError,
  nowIso = () => new Date().toISOString(),
} = {}) {
  function appendWorkspaceTrustWarningEvent(store, {
    agent,
    threadId,
    controls,
    request = {},
    source,
    requestedBy,
    workflowGraphId,
    modeEvent,
    now,
  } = {}) {
    const planner = workspaceTrustPlanner({ threadId, operation: "warning" });
    const eventStreamId = canonicalEventStreamId(threadId);
    const createdAt = optionalString(now) ?? nowIso();
    const planned = planner({
      operation_kind: "workspace_trust.warning",
      thread_id: threadId,
      event_stream_id: eventStreamId,
      agent,
      controls,
      source_event_id: optionalString(modeEvent?.event_id),
      source: optionalString(source) ?? optionalString(request.source) ?? "runtime_thread_control",
      requested_by:
        optionalString(request.requested_by) ??
        optionalString(request.actor) ??
        optionalString(requestedBy) ??
        "operator",
      workflow_graph_id:
        optionalString(request.workflow_graph_id) ??
        optionalString(workflowGraphId),
      workflow_node_id:
        optionalString(request.workspace_trust_workflow_node_id) ??
        "runtime.workspace-trust",
      event_id:
        optionalString(request.event_id) ??
        `evt_workspace_trust_warning_${safeId(threadId)}_${safeId(createdAt)}`,
      state_dir: optionalString(store?.stateDir) ?? null,
      created_at: createdAt,
      receipt_refs: canonicalStringArray(request.receipt_refs),
      policy_decision_refs: canonicalStringArray(request.policy_decision_refs),
      wallet_authority_refs: canonicalStringArray(request.wallet_authority_refs),
      authority_receipt_refs: canonicalStringArray(request.authority_receipt_refs),
      ctee_receipt_refs: canonicalStringArray(request.ctee_receipt_refs),
    });

    if (planned.status === "not_required" && !planned.event) return planned;
    const event = requireWorkspaceTrustEvent(planned, {
      operationKind: "workspace_trust.warning",
      eventKind: "workspace.trust_warning",
      threadId,
    });
    const admittedEvent = admitWorkspaceTrustEvent(store, event, {
      operationKind: "workspace_trust.warning",
      threadId,
    });
    return {
      ...planned,
      event: admittedEvent,
      workspace_trust_warning_event: admittedEvent,
    };
  }

  function acknowledgeWorkspaceTrustWarning(store, threadId, warningId, request = {}) {
    const planner = workspaceTrustPlanner({ threadId, operation: "acknowledge" });
    const eventStreamId = canonicalEventStreamId(threadId);
    const agent = objectRecord(store.agentForThread?.(threadId));
    if (!agent) {
      throw runtimeError({
        status: 404,
        code: "workspace_trust_agent_not_found",
        message: "Workspace trust acknowledgement requires a canonical agent projection.",
        details: { thread_id: threadId },
      });
    }
    const createdAt = optionalString(request.created_at) ?? nowIso();
    const planned = planner({
      operation_kind: "workspace_trust.acknowledge",
      thread_id: threadId,
      event_stream_id: eventStreamId,
      agent,
      warning_id: warningId,
      source_event_id: optionalString(request.source_event_id),
      reason: optionalString(request.reason),
      source: optionalString(request.source) ?? "runtime_thread_control",
      actor: optionalString(request.actor) ?? "operator",
      workflow_graph_id: optionalString(request.workflow_graph_id),
      workflow_node_id:
        optionalString(request.workflow_node_id) ??
        "runtime.workspace-trust",
      event_id:
        optionalString(request.event_id) ??
        `evt_workspace_trust_ack_${safeId(threadId)}_${safeId(warningId)}_${safeId(createdAt)}`,
      state_dir: optionalString(store?.stateDir) ?? null,
      created_at: createdAt,
      receipt_refs: canonicalStringArray(request.receipt_refs),
      policy_decision_refs: canonicalStringArray(request.policy_decision_refs),
      wallet_authority_refs: canonicalStringArray(request.wallet_authority_refs),
      authority_receipt_refs: canonicalStringArray(request.authority_receipt_refs),
      ctee_receipt_refs: canonicalStringArray(request.ctee_receipt_refs),
    });
    const event = requireWorkspaceTrustEvent(planned, {
      operationKind: "workspace_trust.acknowledge",
      eventKind: "workspace.trust_acknowledged",
      threadId,
    });
    const admittedEvent = admitWorkspaceTrustEvent(store, event, {
      operationKind: "workspace_trust.acknowledge",
      threadId,
    });
    return {
      ...planned,
      event: admittedEvent,
      workspace_trust_acknowledgement_event: admittedEvent,
    };
  }

  function workspaceTrustPlanner({ threadId, operation } = {}) {
    const planner = contextPolicyCore?.planWorkspaceTrustControlStateUpdate;
    if (typeof planner === "function") {
      return planner.bind(contextPolicyCore);
    }
    throwWorkspaceTrustRustCoreRequired({
      operation,
      threadId,
    });
  }

  function canonicalEventStreamId(threadId) {
    const eventStreamId = eventStreamIdForThread?.(threadId);
    if (!eventStreamId) {
      throw runtimeError({
        status: 502,
        code: "workspace_trust_event_stream_missing",
        message: "Workspace trust control requires a canonical runtime event stream id.",
        details: { thread_id: threadId },
      });
    }
    return eventStreamId;
  }

  function admitWorkspaceTrustEvent(store, event, { operationKind, threadId }) {
    if (typeof store.appendRuntimeEvent !== "function") {
      throw runtimeError({
        status: 501,
        code: "workspace_trust_event_admission_rust_core_required",
        message: "Workspace trust control requires Rust runtime-event admission.",
        details: {
          operation_kind: operationKind,
          thread_id: threadId,
        },
      });
    }
    return store.appendRuntimeEvent(event);
  }

  function requireWorkspaceTrustEvent(planned, { operationKind, eventKind, threadId }) {
    if (planned.operation_kind !== operationKind) {
      throw runtimeError({
        status: 502,
        code: "workspace_trust_operation_kind_mismatch",
        message: "Rust workspace-trust planner returned an unexpected operation kind.",
        details: {
          expected_operation_kind: operationKind,
          operation_kind: planned.operation_kind ?? null,
          thread_id: threadId,
        },
      });
    }
    const event = objectRecord(planned.event);
    if (!event || event.event_kind !== eventKind || event.thread_id !== threadId) {
      throw runtimeError({
        status: 502,
        code: "workspace_trust_rust_event_projection_invalid",
        message: "Rust workspace-trust planner did not return the required event projection.",
        details: {
          operation_kind: operationKind,
          expected_event_kind: eventKind,
          event_kind: event?.event_kind ?? null,
          thread_id: threadId,
        },
      });
    }
    if (!Array.isArray(event.receipt_refs) || event.receipt_refs.length === 0) {
      throw runtimeError({
        status: 502,
        code: "workspace_trust_rust_receipt_refs_missing",
        message: "Rust workspace-trust planner returned an event without receipt refs.",
        details: {
          operation_kind: operationKind,
          thread_id: threadId,
        },
      });
    }
    return event;
  }

  function throwWorkspaceTrustRustCoreRequired({
    operation,
    threadId = null,
  } = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_workspace_trust_control_rust_core_required",
      message: "Workspace trust control requires direct Rust daemon-core admission and projection.",
      details: {
        rust_core_boundary: "runtime.workspace_trust_control",
        operation: "workspace_trust_control",
        operation_kind: "workspace_trust_control",
        requested_operation: operation ?? null,
        thread_id: threadId,
        evidence_refs: [
          "runtime_workspace_trust_control_rust_planner_required",
          "runtime_workspace_trust_event_admission_rust_required",
          "runtime_workspace_trust_replay_rust_required",
          "agentgres_workspace_trust_truth_required",
        ],
      },
    });
  }

  return {
    acknowledgeWorkspaceTrustWarning,
    appendWorkspaceTrustWarningEvent,
  };
}

function canonicalStringArray(value) {
  return Array.isArray(value)
    ? value.map((item) => optionalString(item)).filter(Boolean)
    : [];
}
