export const AUTHORITY_EVIDENCE_SUMMARY_SCHEMA_VERSION =
  "ioi.authority-evidence-summary.v1";
export const AUTHORITY_EVIDENCE_SUMMARY_LIST_SCHEMA_VERSION =
  "ioi.authority-evidence-summary-list.v1";

export function authorityEvidenceSummaryForEvents(events = [], options = {}) {
  const filters = {
    threadId: optionalString(options.thread_id ?? options.threadId),
    runId: optionalString(options.run_id ?? options.runId),
    capabilityRef: optionalString(options.capability_ref ?? options.capabilityRef),
    routeId: optionalString(options.route_id ?? options.routeId),
  };
  const rows = normalizeArray(events)
    .filter(authorityEvidenceSourceEvent)
    .flatMap((event) => authorityEvidenceRowsFromRuntimeEvent(event))
    .filter((row) => authorityEvidenceRowMatchesFilters(row, filters))
    .sort((left, right) => {
      const timeDelta = (right.createdAtMs ?? 0) - (left.createdAtMs ?? 0);
      if (timeDelta !== 0) return timeDelta;
      return String(right.eventSeq ?? "").localeCompare(String(left.eventSeq ?? ""));
    });
  const generatedAt = new Date().toISOString();
  return {
    schema_version: AUTHORITY_EVIDENCE_SUMMARY_LIST_SCHEMA_VERSION,
    schemaVersion: AUTHORITY_EVIDENCE_SUMMARY_LIST_SCHEMA_VERSION,
    object: "ioi.authority_evidence_summary_list",
    source: "runtime_event_projection",
    generated_at: generatedAt,
    generatedAt,
    row_count: rows.length,
    rowCount: rows.length,
    filters,
    items: rows,
    rows,
  };
}

function authorityEvidenceSourceEvent(event) {
  const payload = event?.payload_summary ?? event?.payload ?? {};
  const haystack = [
    event?.event_kind,
    event?.source_event_kind,
    event?.component_kind,
    event?.payload_schema_version,
    payload.eventKind,
    payload.event_kind,
    payload.reason,
    payload.sourceKind,
    payload.source_kind,
    payload.schemaVersion,
    payload.schema_version,
    payload.issueCode,
    payload.issue_code,
    payload.resultSummary?.reason,
    payload.result_summary?.reason,
  ]
    .map((value) => optionalString(value)?.toLowerCase())
    .filter(Boolean)
    .join(" ");
  return (
    haystack.includes("capability") &&
    (haystack.includes("workflowruncapabilitypreflightblocked") ||
      haystack.includes("workflow_capability_preflight_blocked") ||
      haystack.includes("ioi.workflow.capability-preflight.v1") ||
      haystack.includes("capability_preflight"))
  );
}

function authorityEvidenceRowsFromRuntimeEvent(event) {
  const payload = objectRecord(event?.payload_summary);
  const fallbackPayload = Object.keys(payload).length > 0
    ? payload
    : objectRecord(event?.payload);
  const eventReceiptRefs = uniqueStrings([
    ...normalizeArray(event?.receipt_refs),
    ...normalizeArray(fallbackPayload.receiptRefs ?? fallbackPayload.receipt_refs),
  ]);
  const eventPolicyDecisionRefs = uniqueStrings([
    ...normalizeArray(event?.policy_decision_refs),
    ...normalizeArray(
      fallbackPayload.policyDecisionRefs ?? fallbackPayload.policy_decision_refs,
    ),
  ]);
  const rows = normalizeArray(
    fallbackPayload.rows ??
      fallbackPayload.capabilityRows ??
      fallbackPayload.capability_rows,
  );
  if (rows.length > 0) {
    return rows
      .map((row, index) =>
        authorityEvidenceRowFromPreflightRow({
          event,
          payload: fallbackPayload,
          row: objectRecord(row),
          rowIndex: index,
          eventReceiptRefs,
          eventPolicyDecisionRefs,
        }),
      )
      .filter(Boolean);
  }
  return uniqueStrings(fallbackPayload.capabilityRefs ?? fallbackPayload.capability_refs)
    .map((capabilityRef, index) =>
      authorityEvidenceRowFromPreflightRow({
        event,
        payload: fallbackPayload,
        row: { capabilityRef },
        rowIndex: index,
        eventReceiptRefs,
        eventPolicyDecisionRefs,
      }),
    )
    .filter(Boolean);
}

function authorityEvidenceRowFromPreflightRow({
  event,
  payload,
  row,
  rowIndex,
  eventReceiptRefs,
  eventPolicyDecisionRefs,
}) {
  const capabilityRef =
    optionalString(
      row.capabilityRef ??
        row.capability_ref ??
        row.modelCapabilityRef ??
        row.model_capability_ref ??
        row.toolCapabilityRef ??
        row.tool_capability_ref ??
        row.connectorCapabilityRef ??
        row.connector_capability_ref,
    ) ?? "";
  const routeId =
    optionalString(row.routeId ?? row.route_id ?? payload.routeId ?? payload.route_id) ??
    null;
  const authorityScopes = uniqueStrings([
    ...normalizeArray(row.authorityScopes ?? row.authority_scopes),
    ...normalizeArray(payload.authorityScopes ?? payload.authority_scopes),
  ]);
  const authorityScopeRequirements = uniqueStrings([
    ...normalizeArray(row.authorityScopeRequirements ?? row.authority_scope_requirements),
    ...normalizeArray(
      payload.authorityScopeRequirements ?? payload.authority_scope_requirements,
    ),
  ]);
  const receiptRefs = uniqueStrings([
    ...eventReceiptRefs,
    ...normalizeArray(row.receiptRefs ?? row.receipt_refs),
    ...normalizeArray(row.lastRepairReceiptRefs ?? row.last_repair_receipt_refs),
    ...normalizeArray(row.preflightReceiptRefs ?? row.preflight_receipt_refs),
  ]);
  const policyDecisionRefs = uniqueStrings([
    ...eventPolicyDecisionRefs,
    ...normalizeArray(row.policyDecisionRefs ?? row.policy_decision_refs),
  ]);
  if (
    receiptRefs.length === 0 ||
    (!capabilityRef &&
      !routeId &&
      authorityScopes.length === 0 &&
      authorityScopeRequirements.length === 0)
  ) {
    return null;
  }
  const sourceRunId =
    optionalString(
      payload.runId ??
        payload.run_id ??
        payload.sourceRunId ??
        payload.source_run_id ??
        row.runId ??
        row.run_id ??
        row.sourceRunId ??
        row.source_run_id,
    ) ?? null;
  const eventId = optionalString(event?.event_id) ?? null;
  const createdAt =
    optionalString(event?.created_at) ??
    optionalString(payload.createdAt ?? payload.created_at);
  const createdAtMs = createdAt ? Date.parse(createdAt) : null;
  const nodeId =
    optionalString(
      row.nodeId ??
        row.node_id ??
        event?.workflow_node_id ??
        payload.workflowNodeId ??
        payload.workflow_node_id,
    ) ?? null;
  const id = `authority_evidence_${safeId(eventId ?? sourceRunId ?? "event")}_${
    rowIndex + 1
  }`;
  return {
    schema_version: AUTHORITY_EVIDENCE_SUMMARY_SCHEMA_VERSION,
    schemaVersion: AUTHORITY_EVIDENCE_SUMMARY_SCHEMA_VERSION,
    id,
    capability_ref: capabilityRef,
    capabilityRef,
    route_id: routeId,
    routeId,
    authority_scopes: authorityScopes,
    authorityScopes,
    authority_scope_requirements: authorityScopeRequirements,
    authorityScopeRequirements,
    receipt_refs: receiptRefs,
    receiptRefs,
    policy_decision_refs: policyDecisionRefs,
    policyDecisionRefs,
    source_run_id: sourceRunId,
    sourceRunId,
    source_event_id: eventId,
    sourceEventId: eventId,
    thread_id: optionalString(event?.thread_id) ?? null,
    threadId: optionalString(event?.thread_id) ?? null,
    turn_id: optionalString(event?.turn_id) ?? null,
    turnId: optionalString(event?.turn_id) ?? null,
    workflow_graph_id: optionalString(event?.workflow_graph_id) ?? null,
    workflowGraphId: optionalString(event?.workflow_graph_id) ?? null,
    workflow_node_id: nodeId,
    workflowNodeId: nodeId,
    node_id: optionalString(row.nodeId ?? row.node_id) ?? nodeId,
    nodeId: optionalString(row.nodeId ?? row.node_id) ?? nodeId,
    node_type: optionalString(row.nodeType ?? row.node_type) ?? null,
    nodeType: optionalString(row.nodeType ?? row.node_type) ?? null,
    binding_kind: optionalString(row.bindingKind ?? row.binding_kind) ?? null,
    bindingKind: optionalString(row.bindingKind ?? row.binding_kind) ?? null,
    component_kind: optionalString(event?.component_kind) ?? null,
    componentKind: optionalString(event?.component_kind) ?? null,
    status: optionalString(event?.status ?? payload.status ?? row.status) ?? null,
    reason:
      optionalString(payload.reason ?? payload.issueCode ?? payload.issue_code ?? row.reason) ??
      null,
    created_at: createdAt ?? null,
    createdAt: createdAt ?? null,
    created_at_ms: Number.isFinite(createdAtMs) ? createdAtMs : null,
    createdAtMs: Number.isFinite(createdAtMs) ? createdAtMs : null,
    event_seq: event?.seq ?? null,
    eventSeq: event?.seq ?? null,
  };
}

function authorityEvidenceRowMatchesFilters(row, filters) {
  if (filters.threadId && row.threadId !== filters.threadId) return false;
  if (filters.runId && row.sourceRunId !== filters.runId) return false;
  if (filters.capabilityRef && row.capabilityRef !== filters.capabilityRef) return false;
  if (filters.routeId && row.routeId !== filters.routeId) return false;
  return true;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))];
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function safeId(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "unknown";
}
