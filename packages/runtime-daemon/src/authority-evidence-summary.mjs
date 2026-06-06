export const AUTHORITY_EVIDENCE_SUMMARY_SCHEMA_VERSION =
  "ioi.authority-evidence-summary.v1";
export const AUTHORITY_EVIDENCE_SUMMARY_LIST_SCHEMA_VERSION =
  "ioi.authority-evidence-summary-list.v1";

export function authorityEvidenceSummaryForEvents(events = [], options = {}) {
  const filters = {
    thread_id: optionalString(options.thread_id),
    run_id: optionalString(options.run_id),
    capability_ref: optionalString(options.capability_ref),
    route_id: optionalString(options.route_id),
  };
  const rows = normalizeArray(events)
    .filter(authorityEvidenceSourceEvent)
    .flatMap((event) => authorityEvidenceRowsFromRuntimeEvent(event))
    .filter((row) => authorityEvidenceRowMatchesFilters(row, filters))
    .sort((left, right) => {
      const timeDelta = (right.createdAtMs ?? 0) - (left.createdAtMs ?? 0);
      if (timeDelta !== 0) return timeDelta;
      return String(right.event_seq ?? "").localeCompare(String(left.event_seq ?? ""));
    });
  const generatedAt = new Date().toISOString();
  return {
    schema_version: AUTHORITY_EVIDENCE_SUMMARY_LIST_SCHEMA_VERSION,
    object: "ioi.authority_evidence_summary_list",
    source: "runtime_event_projection",
    generated_at: generatedAt,
    row_count: rows.length,
    filters,
    items: rows,
  };
}

function authorityEvidenceSourceEvent(event) {
  const payload = event?.payload_summary ?? event?.payload ?? {};
  const haystack = [
    event?.event_kind,
    event?.source_event_kind,
    event?.component_kind,
    event?.payload_schema_version,
    payload.event_kind,
    payload.reason,
    payload.source_kind,
    payload.schema_version,
    payload.issue_code,
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
    ...normalizeArray(fallbackPayload.receipt_refs),
  ]);
  const eventPolicyDecisionRefs = uniqueStrings([
    ...normalizeArray(event?.policy_decision_refs),
    ...normalizeArray(fallbackPayload.policy_decision_refs),
  ]);
  const rows = normalizeArray(fallbackPayload.rows ?? fallbackPayload.capability_rows);
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
  return uniqueStrings(fallbackPayload.capability_refs)
    .map((capabilityRef, index) =>
      authorityEvidenceRowFromPreflightRow({
        event,
        payload: fallbackPayload,
        row: { capability_ref: capabilityRef },
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
      row.capability_ref ??
        row.model_capability_ref ??
        row.tool_capability_ref ??
        row.connector_capability_ref,
    ) ?? "";
  const routeId =
    optionalString(row.route_id ?? payload.route_id) ?? null;
  const authorityScopes = uniqueStrings([
    ...normalizeArray(row.authority_scopes),
    ...normalizeArray(payload.authority_scopes),
  ]);
  const authorityScopeRequirements = uniqueStrings([
    ...normalizeArray(row.authority_scope_requirements),
    ...normalizeArray(payload.authority_scope_requirements),
  ]);
  const receiptRefs = uniqueStrings([
    ...eventReceiptRefs,
    ...normalizeArray(row.receipt_refs),
    ...normalizeArray(row.last_repair_receipt_refs),
    ...normalizeArray(row.preflight_receipt_refs),
  ]);
  const policyDecisionRefs = uniqueStrings([
    ...eventPolicyDecisionRefs,
    ...normalizeArray(row.policy_decision_refs),
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
      payload.run_id ??
        payload.source_run_id ??
        row.run_id ??
        row.source_run_id,
    ) ?? null;
  const eventId = optionalString(event?.event_id) ?? null;
  const createdAt =
    optionalString(event?.created_at) ??
    optionalString(payload.created_at);
  const createdAtMs = createdAt ? Date.parse(createdAt) : null;
  const nodeId =
    optionalString(
      row.node_id ??
        event?.workflow_node_id ??
        payload.workflow_node_id,
    ) ?? null;
  const id = `authority_evidence_${safeId(eventId ?? sourceRunId ?? "event")}_${
    rowIndex + 1
  }`;
  return {
    schema_version: AUTHORITY_EVIDENCE_SUMMARY_SCHEMA_VERSION,
    id,
    capability_ref: capabilityRef,
    route_id: routeId,
    authority_scopes: authorityScopes,
    authority_scope_requirements: authorityScopeRequirements,
    receipt_refs: receiptRefs,
    policy_decision_refs: policyDecisionRefs,
    source_run_id: sourceRunId,
    source_event_id: eventId,
    thread_id: optionalString(event?.thread_id) ?? null,
    turn_id: optionalString(event?.turn_id) ?? null,
    workflow_graph_id: optionalString(event?.workflow_graph_id) ?? null,
    workflow_node_id: nodeId,
    node_id: optionalString(row.node_id) ?? nodeId,
    node_type: optionalString(row.node_type) ?? null,
    binding_kind: optionalString(row.binding_kind) ?? null,
    component_kind: optionalString(event?.component_kind) ?? null,
    status: optionalString(event?.status ?? payload.status ?? row.status) ?? null,
    reason:
      optionalString(payload.reason ?? payload.issue_code ?? row.reason) ??
      null,
    created_at: createdAt ?? null,
    created_at_ms: Number.isFinite(createdAtMs) ? createdAtMs : null,
    event_seq: event?.seq ?? null,
  };
}

function authorityEvidenceRowMatchesFilters(row, filters) {
  if (filters.thread_id && row.thread_id !== filters.thread_id) return false;
  if (filters.run_id && row.source_run_id !== filters.run_id) return false;
  if (filters.capability_ref && row.capability_ref !== filters.capability_ref) {
    return false;
  }
  if (filters.route_id && row.route_id !== filters.route_id) return false;
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
