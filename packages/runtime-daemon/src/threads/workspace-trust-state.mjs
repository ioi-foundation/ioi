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
      request.workflowNodeId ??
      modeEvent?.workflow_node_id ??
      "runtime.thread-mode";
    const workflowNodeId =
      request.workspace_trust_workflow_node_id ??
      request.workspaceTrustWorkflowNodeId ??
      request.trust_warning_workflow_node_id ??
      request.trustWarningWorkflowNodeId ??
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
    const normalizedWarningId = optionalString(warningId ?? request.warning_id ?? request.warningId);
    if (!normalizedWarningId) {
      throw runtimeError({
        status: 400,
        code: "workspace_trust_warning_id_required",
        message: "Workspace trust acknowledgement requires a warning id.",
        details: { threadId },
      });
    }
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    const warningEvent = [...stream.events].reverse().find((event) => {
      if (event.event_kind !== "workspace.trust_warning" && event.type !== "workspace_trust_warning") return false;
      const payload = event.payload_summary ?? event.payload ?? {};
      return (
        event.event_id === normalizedWarningId ||
        payload.warning_id === normalizedWarningId ||
        payload.warningId === normalizedWarningId
      );
    });
    if (!warningEvent) {
      throw runtimeError({
        status: 404,
        code: "workspace_trust_warning_not_found",
        message: "Workspace trust warning does not exist for this thread.",
        details: { threadId, warningId: normalizedWarningId },
      });
    }
    const warningPayload = warningEvent.payload_summary ?? warningEvent.payload ?? {};
    const now = new Date().toISOString();
    const source = operatorControlSource(request.source);
    const acknowledgedBy =
      optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message) ??
      "Workspace trust warning acknowledged by operator.";
    const workflowGraphId =
      optionalString(request.workflow_graph_id ?? request.workflowGraphId) ??
      warningEvent.workflow_graph_id ??
      warningPayload.workflow_graph_id ??
      null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      warningEvent.workflow_node_id ??
      warningPayload.workflow_node_id ??
      "runtime.workspace-trust";
    const sourceEventId =
      optionalString(request.source_event_id ?? request.sourceEventId) ??
      warningEvent.event_id;
    const acknowledgementHash = crypto
      .createHash("sha256")
      .update(JSON.stringify({
        threadId,
        warningId: normalizedWarningId,
        sourceEventId,
        workflowGraphId,
        workflowNodeId,
        acknowledgedBy,
      }))
      .digest("hex")
      .slice(0, 16);
    const payload = {
      schemaVersion: workspaceTrustAcknowledgementSchemaVersion,
      schema_version: workspaceTrustAcknowledgementSchemaVersion,
      object: "ioi.workspace_trust_acknowledgement",
      acknowledgementId: `workspace_trust_ack_${acknowledgementHash}`,
      acknowledgement_id: `workspace_trust_ack_${acknowledgementHash}`,
      warningId: normalizedWarningId,
      warning_id: normalizedWarningId,
      warningEventId: warningEvent.event_id,
      warning_event_id: warningEvent.event_id,
      sourceEventId,
      source_event_id: sourceEventId,
      status: "acknowledged",
      acknowledgedAt: now,
      acknowledged_at: now,
      acknowledgedBy,
      acknowledged_by: acknowledgedBy,
      reason,
      mode: warningPayload.mode ?? warningPayload.thread_mode ?? null,
      thread_mode: warningPayload.thread_mode ?? warningPayload.mode ?? null,
      approvalMode: warningPayload.approvalMode ?? warningPayload.approval_mode ?? null,
      approval_mode: warningPayload.approval_mode ?? warningPayload.approvalMode ?? null,
      severity: warningPayload.severity ?? null,
      trustProfile: warningPayload.trustProfile ?? warningPayload.trust_profile ?? "local_private",
      trust_profile: warningPayload.trust_profile ?? warningPayload.trustProfile ?? "local_private",
      threadId,
      thread_id: threadId,
      agentId: agent.id,
      agent_id: agent.id,
      sessionId: runtimeSessionIdForAgent(agent),
      session_id: runtimeSessionIdForAgent(agent),
      workflowGraphId,
      workflow_graph_id: workflowGraphId,
      workflowNodeId,
      workflow_node_id: workflowNodeId,
      controlSurface: source,
      control_surface: source,
      daemonEnforced: true,
      daemon_enforced: true,
      canvasLocalTrustStateAccepted: false,
      canvas_local_trust_state_accepted: false,
      commandExecuted: false,
      command_executed: false,
    };
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: "",
      item_id: `${threadId}:item:workspace-trust-ack:${acknowledgementHash}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
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
      workspaceTrustAcknowledgement: payload,
      workspace_trust_acknowledgement_event: event,
      workspaceTrustAcknowledgementEvent: event,
      event,
    };
  }

  return {
    acknowledgeWorkspaceTrustWarning,
    appendWorkspaceTrustWarningEvent,
  };
}
