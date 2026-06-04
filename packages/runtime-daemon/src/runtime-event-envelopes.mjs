export function createRuntimeEventEnvelopeHelpers({
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  DAEMON_FIXTURE_PROFILE,
  LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
  RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
  RUN_EVENT_TO_TTI_EVENT,
  artifactRefsForRunEvent,
  componentKindForRunEvent,
  computerUseSourceEventKind,
  doctorHash,
  eventStreamIdForThread,
  isComputerUseRunEventType,
  normalizeArray,
  payloadSummaryForRunEvent,
  policyDecisionRefsForRunEvent,
  receiptRefsForRunEvent,
  runtimeBridgeComputerUseTrace,
  runtimeBridgeMessagesForProjection,
  runtimeEventStatusForRunEvent,
  stringRecord,
  workflowNodeForRunEvent,
} = {}) {
  function insertRuntimeBridgeComputerUseDerivedEvents({ projection, agent, threadId }) {
    const events = [...normalizeArray(projection.events)];
    const hasActionProposal = events.some((event) => event?.event_kind === "computer_use.action_proposed");
    const hasCommitGate = events.some((event) => event?.event_kind === "computer_use.commit_gate");
    if (hasActionProposal && hasCommitGate) return events;
    const bridgeMessages = runtimeBridgeMessagesForProjection({ agent, projection: { ...projection, events } });
    const trace = runtimeBridgeComputerUseTrace({ projection, events: bridgeMessages });
    if (!trace?.actionProposal || !trace?.commitGate || !trace?.outcomeContract) return events;
    const insertionIndex = Math.max(
      events.findIndex((event) => event?.event_kind === "computer_use.affordance_graph"),
      events.findIndex((event) => event?.event_kind === "computer_use.observation"),
    );
    if (insertionIndex < 0) return events;
    const createdAt = events[insertionIndex]?.created_at ?? projection.updatedAt ?? projection.createdAt;
    const derivedEvents = [
      ...(hasActionProposal
        ? []
        : [
            runtimeBridgeDerivedComputerUseEvent({
              projection,
              threadId,
              createdAt,
              eventKind: "computer_use.action_proposed",
              sourceEventKind: "ComputerUse.ActionProposed",
              itemSuffix: "computer-use-action-proposed",
              workflowNodeId: "computer-use.action-proposal",
              workspaceRoot: agent.cwd,
              payload: {
                computer_use_step: "propose_action",
                computer_use_proposal_ref: trace.actionProposal.proposal_ref,
                computer_use_target_ref: trace.actionProposal.target_ref,
                computer_use_policy_decision_ref: trace.actionProposal.policy_decision_ref,
                action_proposal: trace.actionProposal,
                policy_gate: {
                  policy_decision_ref: trace.actionProposal.policy_decision_ref,
                  outcome: trace.actionProposal.confirmation_required
                    ? "requires_confirmation_before_execution"
                    : "approved_for_proposal_only",
                  authority_scope: trace.commitGate.authority_required,
                },
              },
            }),
          ]),
      ...(hasCommitGate
        ? []
        : [
            runtimeBridgeDerivedComputerUseEvent({
              projection,
              threadId,
              createdAt,
              eventKind: "computer_use.commit_gate",
              sourceEventKind: "ComputerUse.CommitGate",
              itemSuffix: "computer-use-commit-gate",
              workflowNodeId: "computer-use.commit-gate",
              workspaceRoot: agent.cwd,
              payload: {
                computer_use_step: "commit_or_handoff",
                computer_use_commit_gate_ref: trace.commitGate.commit_gate_ref,
                outcome_contract: trace.outcomeContract,
                commit_gate: trace.commitGate,
                human_handoff_state: null,
              },
            }),
          ]),
    ];
    events.splice(insertionIndex + 1, 0, ...derivedEvents);
    return events;
  }

  function runtimeBridgeDerivedComputerUseEvent({
    projection,
    threadId,
    createdAt,
    eventKind,
    sourceEventKind,
    itemSuffix,
    workflowNodeId,
    workspaceRoot,
    payload,
  }) {
    return {
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: projection.turnId,
      item_id: `${projection.turnId}:item:${itemSuffix}`,
      idempotency_key: `turn:${projection.turnId}:${eventKind}`,
      source: "runtime_auto",
      source_event_kind: sourceEventKind,
      event_kind: eventKind,
      status: payload?.commit_gate?.user_confirmation_required
        ? "blocked"
        : eventKind === "computer_use.action_proposed"
          ? "running"
          : "completed",
      actor: "runtime",
      created_at: createdAt,
      workspace_root: workspaceRoot,
      workflow_node_id: workflowNodeId,
      component_kind: "computer_use_harness",
      payload_schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
      payload: {
        schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        event_kind: sourceEventKind,
        ...payload,
      },
      receipt_refs: [`receipt_${projection.runId}_runtime_bridge_computer_use_trace`],
      artifact_refs: ["computer-use-trace.json"],
      policy_decision_refs: [
        payload?.computer_use_policy_decision_ref ??
        payload?.commit_gate?.policy_decision_ref,
      ].filter(Boolean),
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: null,
    };
  }

  function ttiEnvelopeForRunEvent({ event, threadId, turnId, workspaceRoot }) {
    const eventKind = RUN_EVENT_TO_TTI_EVENT[event.type] ?? `item.${event.type}`;
    const payload = payloadSummaryForRunEvent(event);
    const isComputerUseEvent = isComputerUseRunEventType(event.type);
    const isDiagnosticsInjection = event.type === "lsp_diagnostics_injected";
    const isDiagnosticsBlockingGate =
      event.type === "policy_blocked" && event.data?.reason === "post_edit_diagnostics_findings";
    return {
      schema_version: RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId}:item:${doctorHash(event.id).slice(0, 12)}`,
      idempotency_key: `run:${event.runId}:event:${event.id}`,
      source: isDiagnosticsInjection || isDiagnosticsBlockingGate ? "runtime_auto" : "daemon_bridge",
      source_event_kind: isDiagnosticsInjection
        ? "LspDiagnostics.Injected"
        : isDiagnosticsBlockingGate
          ? "LspDiagnostics.BlockingGate"
          : isComputerUseEvent
            ? event.data?.eventKind ?? computerUseSourceEventKind(event.type)
            : `run.${event.type}`,
      event_kind: eventKind,
      status: runtimeEventStatusForRunEvent(event),
      actor: event.type === "delta" ? "assistant" : "runtime",
      created_at: event.createdAt,
      workspace_root: workspaceRoot,
      workflow_graph_id: event.data?.workflowGraphId ?? event.data?.workflow_graph_id ?? null,
      component_kind: componentKindForRunEvent(event),
      workflow_node_id: workflowNodeForRunEvent(event),
      tool_call_id: event.data?.toolCallId ?? event.data?.tool_call_id ?? null,
      approval_id: event.data?.approvalId ?? event.data?.approval_id ?? null,
      policy_decision_refs: policyDecisionRefsForRunEvent(event),
      rollback_refs: normalizeArray(event.data?.rollbackRefs ?? event.data?.rollback_refs),
      payload_schema_version: isDiagnosticsInjection
        ? LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION
        : isDiagnosticsBlockingGate
          ? LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION
          : isComputerUseEvent
            ? COMPUTER_USE_CONTRACT_SCHEMA_VERSION
            : RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
      payload,
      payload_ref: null,
      receipt_refs: receiptRefsForRunEvent(event),
      artifact_refs: artifactRefsForRunEvent(event),
      redaction_profile: "internal",
      fixture_profile: DAEMON_FIXTURE_PROFILE,
    };
  }

  function normalizeRuntimeEventEnvelope(event, { seq, parentSeq, idempotencyKey }) {
    const eventKind = event.event_kind ?? event.event ?? "runtime.event";
    const createdAt = event.created_at ?? new Date().toISOString();
    const payloadSummary = event.payload_summary ?? event.payload ?? {};
    return {
      schema_version: RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
      event_id: event.event_id ?? `${event.event_stream_id}:seq:${String(seq).padStart(8, "0")}`,
      event_stream_id: event.event_stream_id,
      thread_id: event.thread_id ?? "",
      turn_id: event.turn_id ?? "",
      item_id: event.item_id ?? "",
      seq,
      parent_seq: parentSeq,
      idempotency_key: idempotencyKey,
      source: event.source ?? "daemon_bridge",
      source_event_kind: event.source_event_kind ?? eventKind,
      event_kind: eventKind,
      status: event.status ?? "completed",
      actor: event.actor ?? "runtime",
      created_at: createdAt,
      workspace_root: event.workspace_root ?? "",
      workflow_graph_id: event.workflow_graph_id ?? null,
      workflow_node_id: event.workflow_node_id ?? null,
      component_kind: event.component_kind ?? null,
      tool_call_id: event.tool_call_id ?? null,
      approval_id: event.approval_id ?? null,
      artifact_refs: normalizeArray(event.artifact_refs),
      receipt_refs: normalizeArray(event.receipt_refs),
      policy_decision_refs: normalizeArray(event.policy_decision_refs),
      rollback_refs: normalizeArray(event.rollback_refs),
      payload_schema_version: event.payload_schema_version ?? RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
      payload_ref: event.payload_ref ?? null,
      payload: stringRecord(payloadSummary),
      redaction_profile: event.redaction_profile ?? "internal",
      fixture_profile: Object.hasOwn(event, "fixture_profile") ? event.fixture_profile : DAEMON_FIXTURE_PROFILE,
      id: String(seq),
      timestamp_ms: Date.parse(createdAt) || 0,
      event: eventKind,
      payload_summary: payloadSummary,
    };
  }

  return {
    insertRuntimeBridgeComputerUseDerivedEvents,
    normalizeRuntimeEventEnvelope,
    runtimeBridgeDerivedComputerUseEvent,
    ttiEnvelopeForRunEvent,
  };
}
