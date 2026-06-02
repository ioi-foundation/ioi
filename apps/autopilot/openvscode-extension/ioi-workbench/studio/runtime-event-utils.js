function stringValue(value, fallback = "") {
  if (value === null || value === undefined) {
    return fallback;
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return fallback;
}

function compactStudioWhitespace(value = "") {
  return stringValue(value).replace(/\s+/g, " ").trim();
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function nestedPayloadValue(value, keys = []) {
  let current = value;
  for (const key of keys) {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    current = current[key];
  }
  return current;
}

function studioRuntimeEventToolName(event = {}) {
  const parsedKernelAction = parsedStudioKernelAction(event);
  return (
    event.tool_name ||
    event.toolName ||
    event.tool_id ||
    event.toolId ||
    event.data?.tool_name ||
    event.data?.toolName ||
    event.data?.tool_id ||
    event.data?.toolId ||
    event.payload?.tool_name ||
    event.payload?.toolName ||
    event.payload?.tool_id ||
    event.payload?.toolId ||
    event.payload_summary?.tool_name ||
    event.payload_summary?.toolName ||
    event.data?.payload?.tool_name ||
    event.data?.payload?.toolName ||
    event.data?.payload_summary?.tool_name ||
    event.data?.payload_summary?.toolName ||
    event.data?.kernel_event?.RoutingReceipt?.tool_name ||
    event.data?.kernel_event?.ToolCall?.tool_name ||
    event.data?.kernel_event?.ToolResult?.tool_name ||
    parsedKernelAction.name ||
    parsedKernelAction.tool ||
    parsedKernelAction.tool_name ||
    parsedKernelAction.toolName ||
    parsedKernelAction.tool_id ||
    parsedKernelAction.toolId ||
    nestedPayloadValue(event, ["raw", "payload", "tool_name"]) ||
    nestedPayloadValue(event, ["raw", "payload", "toolName"]) ||
    ""
  );
}

function studioRuntimeEventKind(event = {}) {
  return String(
    event.event_kind ||
      event.eventKind ||
      event.kind ||
      event.type ||
      event.data?.runtime_event_kind ||
      event.data?.runtimeEventKind ||
      event.data?.event_kind ||
      event.data?.eventKind ||
      event.payload?.event_kind ||
      event.payload?.eventKind ||
      "",
  );
}

function studioRuntimeEventAgentStatus(event = {}) {
  return stringValue(
    event.payload?.agent_status ||
      event.payload?.agentStatus ||
      event.payload_summary?.agent_status ||
      event.payload_summary?.agentStatus ||
      event.data?.agent_status ||
      event.data?.agentStatus,
  );
}

function studioRuntimeEventIsRunningStepCompletion(event = {}) {
  const kind = studioRuntimeEventKind(event).toLowerCase();
  if (!/turn\.completed|completed/.test(kind)) {
    return false;
  }
  const status = studioRuntimeEventAgentStatus(event).toLowerCase();
  const summary = compactStudioWhitespace(
    event.summary ||
      event.payload?.summary ||
      event.payload?.result ||
      event.payload_summary?.summary ||
      event.payload_summary?.result_summary ||
      event.data?.summary ||
      event.data?.result ||
      "",
  );
  return status === "running" || /^Runtime step completed\.?$/i.test(summary);
}

function studioRuntimeEventIdentity(event = {}) {
  return stringValue(
    event.event_id ||
      event.eventId ||
      event.id ||
      (event.event_stream_id && event.seq ? `${event.event_stream_id}:${event.seq}` : "") ||
      (event.eventStreamId && event.seq ? `${event.eventStreamId}:${event.seq}` : ""),
  );
}

function parseStudioMaybeJsonObject(value) {
  const text = stringValue(value);
  if (!text || !/^\s*[\[{]/.test(text)) {
    return null;
  }
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function parsedStudioKernelEvent(event = {}) {
  return parseStudioMaybeJsonObject(
    event.kernel_event ||
      event.kernelEvent ||
      event.payload?.kernel_event ||
      event.payload?.kernelEvent ||
      event.payload_summary?.kernel_event ||
      event.payload_summary?.kernelEvent ||
      event.data?.kernel_event ||
      event.data?.kernelEvent,
  );
}

function parsedStudioKernelAction(event = {}) {
  const kernel = parsedStudioKernelEvent(event) || {};
  const receipt = kernel.RoutingReceipt || {};
  const agentStep = kernel.AgentStep || {};
  const actionResult = kernel.AgentActionResult || {};
  const actionJson = parseStudioMaybeJsonObject(receipt.action_json || receipt.actionJson);
  const rawOutput = parseStudioMaybeJsonObject(agentStep.raw_output || event.payload?.raw_output || event.payload?.rawOutput);
  const preview = parseStudioMaybeJsonObject(actionResult.output?.preview);
  return actionJson || rawOutput || preview || {};
}

function studioRuntimeToolEventDetail(event = {}, toolName = "", summary = "") {
  const payload = event.payload_summary || event.payloadSummary || event.payload || event.data || {};
  const parsedSummary = parseStudioMaybeJsonObject(summary);
  const parsedKernelAction = parsedStudioKernelAction(event);
  const source = parsedSummary || parsedKernelAction || payload;
  const args = source.arguments || source.args || payload.arguments || payload.args || {};
  const query = stringValue(source.query || args.query || payload.query || payload.input_query);
  if (query) {
    return `query: ${compactStudioWhitespace(query).slice(0, 140)}`;
  }
  const pathValue = stringValue(source.path || args.path || source.file || args.file || payload.path);
  if (pathValue) {
    return pathValue;
  }
  const url = stringValue(source.url || args.url || firstArray(source.sources)[0]?.url || payload.url);
  if (url) {
    try {
      const parsed = new URL(url);
      return parsed.hostname || url;
    } catch {
      return compactStudioWhitespace(url).slice(0, 140);
    }
  }
  const title = stringValue(firstArray(source.sources)[0]?.title || source.title || payload.title);
  if (title) {
    return compactStudioWhitespace(title).slice(0, 140);
  }
  if (/shell|command|terminal/.test(toolName)) {
    const command = stringValue(source.command || args.command || payload.command);
    if (command) {
      return compactStudioWhitespace(command).slice(0, 140);
    }
  }
  return "";
}

module.exports = {
  studioRuntimeEventToolName,
  studioRuntimeEventKind,
  studioRuntimeEventAgentStatus,
  studioRuntimeEventIsRunningStepCompletion,
  studioRuntimeEventIdentity,
  studioRuntimeToolEventDetail,
};
