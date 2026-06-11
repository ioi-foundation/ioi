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
  runtimeEventStatusForRunEvent,
  stringRecord,
  workflowNodeForRunEvent,
} = {}) {
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
      idempotency_key: `run:${event.run_id}:event:${event.id}`,
      source: isDiagnosticsInjection || isDiagnosticsBlockingGate ? "runtime_auto" : "daemon_bridge",
      source_event_kind: isDiagnosticsInjection
        ? "LspDiagnostics.Injected"
        : isDiagnosticsBlockingGate
          ? "LspDiagnostics.BlockingGate"
          : isComputerUseEvent
            ? event.data?.event_kind ?? computerUseSourceEventKind(event.type)
            : `run.${event.type}`,
      event_kind: eventKind,
      status: runtimeEventStatusForRunEvent(event),
      actor: event.type === "delta" ? "assistant" : "runtime",
      created_at: event.created_at,
      workspace_root: workspaceRoot,
      workflow_graph_id: event.data?.workflow_graph_id ?? null,
      component_kind: componentKindForRunEvent(event),
      workflow_node_id: workflowNodeForRunEvent(event),
      tool_call_id: event.data?.tool_call_id ?? null,
      approval_id: event.data?.approval_id ?? null,
      policy_decision_refs: policyDecisionRefsForRunEvent(event),
      rollback_refs: normalizeArray(event.data?.rollback_refs),
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
      payload_summary: payloadSummary,
    };
  }

  return {
    normalizeRuntimeEventEnvelope,
    ttiEnvelopeForRunEvent,
  };
}
