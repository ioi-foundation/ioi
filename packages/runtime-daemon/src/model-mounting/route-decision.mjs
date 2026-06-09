export const MODEL_ROUTE_DECISION_SCHEMA_VERSION = "ioi.model-route-decision.v1";
export const MODEL_ROUTE_DECISION_EVENT_KIND = "ModelRouteDecision";

export function isAutoModelSelector(modelId) {
  return typeof modelId === "string" && modelId.trim().toLowerCase() === "auto";
}

export function routeDecisionProjectionFromReceipt(receipt) {
  const decision = receipt?.details?.model_route_decision;
  if (!decision || typeof decision !== "object") return null;
  return {
    ...decision,
    receipt_id: receipt.id,
    receipt_created_at: receipt.createdAt,
    receipt_kind: receipt.kind,
  };
}

export function providerRequestBodyForRoute(body = {}, endpoint = {}) {
  const requestBody = { ...body };
  if (isAutoModelSelector(requestBody.model)) {
    requestBody.model = endpoint.modelId;
  }
  stripAutopilotOnlyProviderFields(requestBody);
  applyProviderNativeReasoningControls(requestBody, body, endpoint);
  normalizeProviderNativeMessages(requestBody, endpoint);
  return requestBody;
}

export function workflowContextFromRouteRequest(body = {}) {
  return {
    workflow_graph_id: optionalString(body.workflow_graph_id),
    workflow_node_id: optionalString(body.workflow_node_id),
    workflow_node_type: optionalString(body.workflow_node_type),
  };
}

function stripAutopilotOnlyProviderFields(body = {}) {
  for (const key of [
    "route_id",
    "routeId",
    "model_policy",
    "modelPolicy",
    "metadata",
    "workflow_graph_id",
    "workflowGraphId",
    "workflow_node_id",
    "workflowNodeId",
    "workflow_node_type",
    "workflowNodeType",
    "fallback_triggered",
    "fallbackTriggered",
    "fallback_reason",
    "fallbackReason",
    "send_options",
    "sendOptions",
    "memory",
    "integrations",
    "ephemeral_mcp",
    "ephemeralMcp",
    "reasoningEffort",
    "thinkingEffort",
    "chat_template_kwargs",
    "chatTemplateKwargs",
  ]) {
    delete body[key];
  }
}

function applyProviderNativeReasoningControls(requestBody = {}, originalBody = {}, endpoint = {}) {
  if (!isLlamaCppEndpoint(endpoint)) return;
  const policy = originalBody.model_policy ?? {};
  const effort = normalizeReasoningEffortValue(
    originalBody.reasoning_effort ??
      originalBody.thinking ??
      originalBody.thinking_effort ??
      policy.reasoning_effort ??
      policy.thinking,
  );
  if (!effort) return;
  requestBody.reasoning_effort = effort;
  requestBody.chat_template_kwargs = {
    ...(originalBody.chat_template_kwargs && typeof originalBody.chat_template_kwargs === "object" ? originalBody.chat_template_kwargs : {}),
    enable_thinking: !["none", "off", "false", "disabled"].includes(effort),
  };
}

function normalizeProviderNativeMessages(requestBody = {}, endpoint = {}) {
  if (!isLlamaCppEndpoint(endpoint) || !Array.isArray(requestBody.messages)) return;
  const systemMessages = requestBody.messages.filter((message) => String(message?.role ?? "").toLowerCase() === "system");
  if (systemMessages.length <= 1) return;
  const systemContent = systemMessages
    .map((message) => messageContentToProviderText(message.content))
    .filter(Boolean)
    .join("\n\n");
  const nonSystemMessages = requestBody.messages.filter((message) => String(message?.role ?? "").toLowerCase() !== "system");
  requestBody.messages = systemContent
    ? [{ role: "system", content: systemContent }, ...nonSystemMessages]
    : nonSystemMessages;
}

function messageContentToProviderText(content) {
  if (typeof content === "string") return content.trim();
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") return part;
        if (typeof part?.text === "string") return part.text;
        if (typeof part?.content === "string") return part.content;
        return "";
      })
      .filter(Boolean)
      .join("\n")
      .trim();
  }
  if (content && typeof content === "object") {
    if (typeof content.text === "string") return content.text.trim();
    if (typeof content.content === "string") return content.content.trim();
  }
  return "";
}

function isLlamaCppEndpoint(endpoint = {}) {
  const haystack = `${endpoint.driver ?? ""} ${endpoint.apiFormat ?? ""} ${endpoint.providerId ?? ""} ${endpoint.backendId ?? ""}`.toLowerCase();
  return haystack.includes("llama_cpp") || haystack.includes("llama-cpp");
}

function normalizeReasoningEffortValue(value) {
  if (value === true) return "medium";
  if (value === false) return "none";
  const normalized = typeof value === "string" ? value.trim().toLowerCase().replace(/[\s-]+/g, "_") : "";
  if (!normalized) return "";
  if (["none", "off", "false", "disabled", "disable"].includes(normalized)) return "none";
  if (["low", "medium", "high", "xhigh"].includes(normalized)) return normalized;
  return normalized;
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}
