import crypto from "node:crypto";

export function createWorkspaceTrustState({
  eventStreamIdForThread,
  fixtureProfileForAgent,
  optionalString,
  operatorControlSource,
  runtimeError,
  runtimeSessionIdForAgent,
  safeId,
  workspaceTrustWarningRecordForMode,
  workspaceTrustAcknowledgementSchemaVersion,
  workspaceTrustWarningSchemaVersion,
} = {}) {
  function appendWorkspaceTrustWarningEvent(store, {
    agent,
    threadId,
    controls,
    request,
    source,
    requestedBy,
    workflowGraphId,
    modeEvent,
    now,
  }) {
    const mode = controls.mode;
    if (mode !== "review" && mode !== "yolo") return null;
    const modeWorkflowNodeId =
      request.workflow_node_id ??
      modeEvent?.workflow_node_id ??
      "runtime.thread-mode";
    const workflowNodeId =
      request.workspace_trust_workflow_node_id ??
      request.trust_warning_workflow_node_id ??
      `${modeWorkflowNodeId}.workspace-trust`;
    const payload = workspaceTrustWarningRecordForMode({
      agent,
      threadId,
      controls,
      request,
      source,
      requestedBy,
      workflowGraphId,
      workflowNodeId,
      modeWorkflowNodeId,
      modeEvent,
      now,
    });
    const warningHash = crypto
      .createHash("sha256")
      .update(JSON.stringify({
        threadId,
        mode: controls.mode,
        approvalMode: controls.approvalMode,
        workspaceRootHash: payload.workspace_root_hash,
        branchPolicyStatus: payload.branch_policy_status,
        warningReasons: payload.warning_reasons,
        workflowGraphId,
        workflowNodeId,
      }))
      .digest("hex")
      .slice(0, 16);
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: "",
      item_id: `${threadId}:item:workspace-trust:${warningHash}`,
      idempotency_key: `thread:${threadId}:workspace-trust-warning:${warningHash}`,
      source,
      source_event_kind: "WorkspaceTrust.Warning",
      event_kind: "workspace.trust_warning",
      status: "warning",
      actor: "policy",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "workspace_trust",
      payload_schema_version: workspaceTrustWarningSchemaVersion,
      payload_summary: payload,
      receipt_refs: [`receipt_${agent.id}_workspace_trust_${safeId(mode)}_${warningHash}`],
      policy_decision_refs: [
        `policy_${agent.id}_workspace_trust_${safeId(mode)}_${safeId(payload.severity)}`,
      ],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
  }

  function acknowledgeWorkspaceTrustWarning(store, threadId, warningId, request = {}) {
    const agent = store.agentForThread(threadId);
    const retiredAliases = retiredWorkspaceTrustAcknowledgementAliases(request);
    if (retiredAliases.length > 0) {
      throw runtimeError({
        status: 400,
        code: "workspace_trust_acknowledgement_request_aliases_retired",
        message: "Workspace trust acknowledgement request uses retired aliases.",
        details: { thread_id: threadId, retired_aliases: retiredAliases },
      });
    }
    const normalizedWarningId = optionalString(warningId ?? request.warning_id);
    if (!normalizedWarningId) {
      throw runtimeError({
        status: 400,
        code: "workspace_trust_warning_id_required",
        message: "Workspace trust acknowledgement requires a warning id.",
        details: { thread_id: threadId },
      });
    }
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    const warningEvent = [...stream.events].reverse().find((event) => {
      if (event.event_kind !== "workspace.trust_warning" && event.type !== "workspace_trust_warning") return false;
      const payload = event.payload_summary ?? event.payload ?? {};
      return (
        event.event_id === normalizedWarningId ||
        payload.warning_id === normalizedWarningId
      );
    });
    if (!warningEvent) {
      throw runtimeError({
        status: 404,
        code: "workspace_trust_warning_not_found",
        message: "Workspace trust warning does not exist for this thread.",
        details: { thread_id: threadId, warning_id: normalizedWarningId },
      });
    }
    const warningPayload = warningEvent.payload_summary ?? warningEvent.payload ?? {};
    const now = new Date().toISOString();
    const source = operatorControlSource(request.source);
    const acknowledgedBy =
      optionalString(request.actor ?? request.requested_by) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message) ??
      "Workspace trust warning acknowledged by operator.";
    const workflowGraphId =
      optionalString(request.workflow_graph_id) ??
      warningEvent.workflow_graph_id ??
      warningPayload.workflow_graph_id ??
      null;
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      warningEvent.workflow_node_id ??
      warningPayload.workflow_node_id ??
      "runtime.workspace-trust";
    const sourceEventId =
      optionalString(request.source_event_id) ??
      warningEvent.event_id;
    const acknowledgementHash = crypto
      .createHash("sha256")
      .update(JSON.stringify({
        thread_id: threadId,
        warning_id: normalizedWarningId,
        source_event_id: sourceEventId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        acknowledged_by: acknowledgedBy,
      }))
      .digest("hex")
      .slice(0, 16);
    const payload = {
      schema_version: workspaceTrustAcknowledgementSchemaVersion,
      object: "ioi.workspace_trust_acknowledgement",
      acknowledgement_id: `workspace_trust_ack_${acknowledgementHash}`,
      warning_id: normalizedWarningId,
      warning_event_id: warningEvent.event_id,
      source_event_id: sourceEventId,
      status: "acknowledged",
      acknowledged_at: now,
      acknowledged_by: acknowledgedBy,
      reason,
      mode: warningPayload.mode ?? warningPayload.thread_mode ?? null,
      thread_mode: warningPayload.thread_mode ?? warningPayload.mode ?? null,
      approval_mode: warningPayload.approval_mode ?? null,
      severity: warningPayload.severity ?? null,
      trust_profile: warningPayload.trust_profile ?? "local_private",
      thread_id: threadId,
      agent_id: agent.id,
      session_id: runtimeSessionIdForAgent(agent),
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      control_surface: source,
      daemon_enforced: true,
      canvas_local_trust_state_accepted: false,
      command_executed: false,
    };
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: "",
      item_id: `${threadId}:item:workspace-trust-ack:${acknowledgementHash}`,
      idempotency_key:
        optionalString(request.idempotency_key) ??
        `thread:${threadId}:workspace-trust-acknowledgement:${acknowledgementHash}`,
      source,
      source_event_kind: "WorkspaceTrust.Acknowledged",
      event_kind: "workspace.trust_acknowledged",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "workspace_trust",
      payload_schema_version: workspaceTrustAcknowledgementSchemaVersion,
      payload_summary: payload,
      receipt_refs: [
        `receipt_${agent.id}_workspace_trust_ack_${safeId(normalizedWarningId)}_${acknowledgementHash}`,
      ],
      policy_decision_refs: [
        `policy_${agent.id}_workspace_trust_acknowledged_${acknowledgementHash}`,
      ],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    return {
      ...store.threadForAgent(agent),
      workspace_trust_acknowledgement: payload,
      workspace_trust_acknowledgement_event: event,
      event,
    };
  }

  return {
    acknowledgeWorkspaceTrustWarning,
    appendWorkspaceTrustWarningEvent,
  };
}

function retiredWorkspaceTrustAcknowledgementAliases(request = {}) {
  return [
    "warningId",
    "sourceEventId",
    "requestedBy",
    "workflowGraphId",
    "workflowNodeId",
    "idempotencyKey",
    "eventKind",
    "componentKind",
    "payloadSchemaVersion",
  ].filter((key) => Object.hasOwn(request, key));
}
