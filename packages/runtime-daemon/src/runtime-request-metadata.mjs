function stringFromSearchParams(params, key) {
  const value = params.get(key);
  if (typeof value !== "string") return null;
  const clean = value.trim();
  return clean ? clean : null;
}

function booleanFromSearchParams(params, key, fallback = false) {
  const value = stringFromSearchParams(params, key);
  if (value === null) return fallback;
  return value !== "false" && value !== "0";
}

export function baseUrlForRequest(request) {
  const host = request.headers.host;
  return host ? `http://${host}` : null;
}

export function runtimeEventCursorFromRequest({ request, url }) {
  if (url.searchParams.has("since_seq")) {
    return { since_seq: Number(url.searchParams.get("since_seq") ?? 0) || 0 };
  }
  return {
    last_event_id: url.searchParams.get("last_event_id") ?? request.headers["last-event-id"] ?? "",
  };
}

export function usageRequestMetadataFromUrl(
  url,
  {
    defaultScope = "workflow",
    runtimeUsageTelemetrySchemaVersion,
  } = {},
) {
  const params = url?.searchParams;
  if (!params) return null;
  const workflowNodeId = stringFromSearchParams(params, "workflow_node_id");
  const workflowGraphId = stringFromSearchParams(params, "workflow_graph_id");
  const source = stringFromSearchParams(params, "source");
  const usageMeterScope =
    stringFromSearchParams(params, "usage_meter_scope") ??
    stringFromSearchParams(params, "scope") ??
    defaultScope;
  if (!workflowNodeId && !workflowGraphId && !source) return null;
  const simulationMode = booleanFromSearchParams(params, "simulation_mode", true);
  const schemaVersion =
    stringFromSearchParams(params, "payload_schema_version") ??
    runtimeUsageTelemetrySchemaVersion;
  const eventKind =
    stringFromSearchParams(params, "event_kind") ??
    "RuntimeUsageTelemetry.Read";
  const componentKind =
    stringFromSearchParams(params, "component_kind") ?? "usage_telemetry";
  return {
    source: source ?? "react_flow",
    actor: stringFromSearchParams(params, "actor") ?? "operator",
    event_kind: eventKind,
    component_kind: componentKind,
    payload_schema_version: schemaVersion,
    workflow_graph_id: workflowGraphId,
    workflow_node_id: workflowNodeId ?? "runtime.usage-meter",
    usage_meter_scope: usageMeterScope,
    simulation_mode: simulationMode,
  };
}

export function usageTelemetryWithRequestMetadata(record, metadata) {
  if (!record || !metadata) return record;
  if (Array.isArray(record.usage)) {
    return {
      ...record,
      ...metadata,
      usage: record.usage.map((entry) => ({ ...entry, ...metadata })),
    };
  }
  return { ...record, ...metadata };
}
