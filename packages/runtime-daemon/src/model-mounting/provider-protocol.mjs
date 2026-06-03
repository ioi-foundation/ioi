import { stableHash } from "./io.mjs";

export function summarizeProviderRequestBodyForTrace(body = {}) {
  const messages = Array.isArray(body.messages) ? body.messages : [];
  return {
    model: typeof body.model === "string" ? body.model : null,
    stream: body.stream === true,
    messageCount: messages.length,
    messageRoles: messages.map((message) => String(message?.role ?? "unknown")),
    messageContentChars: messages.map((message) => messageContentLength(message?.content)),
    toolCount: Array.isArray(body.tools) ? body.tools.length : 0,
    toolChoice: typeof body.tool_choice === "string" ? body.tool_choice : body.tool_choice ? "object" : null,
    parallelToolCalls: body.parallel_tool_calls ?? null,
    responseFormat: body.response_format?.type ?? null,
    reasoningEffort: typeof body.reasoning_effort === "string" ? body.reasoning_effort : null,
    chatTemplateKwargs: body.chat_template_kwargs && typeof body.chat_template_kwargs === "object"
      ? Object.keys(body.chat_template_kwargs).sort()
      : [],
    maxTokens: Number.isFinite(Number(body.max_tokens)) ? Number(body.max_tokens) : null,
    stopCount: Array.isArray(body.stop) ? body.stop.length : 0,
    hasRouteId: body.route_id !== undefined || body.routeId !== undefined,
    hasAutopilotMetadata: body.metadata !== undefined || body.model_policy !== undefined || body.modelPolicy !== undefined,
  };
}

export function messageContentLength(content) {
  if (typeof content === "string") return content.length;
  if (Array.isArray(content)) {
    return content.reduce((total, item) => total + messageContentLength(item?.text ?? item?.content ?? ""), 0);
  }
  if (content && typeof content === "object") {
    return messageContentLength(content.text ?? content.content ?? "");
  }
  return 0;
}

export function parseJsonMaybe(text) {
  try {
    return JSON.parse(text);
  } catch {
    return { text: truncate(text) };
  }
}

export function chatCompletionRequestBody(body, modelId) {
  if (Array.isArray(body.messages)) {
    return { ...body, model: body.model ?? modelId };
  }
  const content = body.input ?? body.prompt ?? "";
  return {
    ...body,
    model: body.model ?? modelId,
    messages: [{ role: "user", content: String(content) }],
  };
}

export function outputTextFromChat(body) {
  return String(
    body?.choices?.[0]?.message?.content ??
      body?.choices?.[0]?.message?.reasoning_content ??
      body?.choices?.[0]?.text ??
      body?.output_text ??
      "",
  );
}

export function outputTextFromResponse(body) {
  if (typeof body?.output_text === "string") return body.output_text;
  const content = body?.output?.[0]?.content;
  if (Array.isArray(content)) {
    const text = content.find((item) => typeof item?.text === "string")?.text;
    if (text) return text;
  }
  return outputTextFromChat(body);
}

export function normalizeUsage(usage, fallback) {
  if (!usage || typeof usage !== "object") return fallback;
  const normalized = {
    prompt_tokens: Number(usage.prompt_tokens ?? usage.input_tokens ?? fallback.prompt_tokens),
    completion_tokens: Number(usage.completion_tokens ?? usage.output_tokens ?? fallback.completion_tokens),
    total_tokens: Number(usage.total_tokens ?? fallback.total_tokens),
  };
  for (const [sourceKey, targetKey] of [
    ["tokens_per_second", "tokens_per_second"],
    ["tokensPerSecond", "tokens_per_second"],
    ["time_to_first_token_ms", "time_to_first_token_ms"],
    ["timeToFirstTokenMs", "time_to_first_token_ms"],
    ["prompt_ms", "prompt_ms"],
    ["completion_ms", "completion_ms"],
    ["elapsed_ms", "elapsed_ms"],
  ]) {
    const value = Number(usage[sourceKey]);
    if (Number.isFinite(value)) normalized[targetKey] = value;
  }
  return normalized;
}

export function truncate(value, limit = 1000) {
  const text = String(value ?? "");
  return text.length > limit ? `${text.slice(0, limit)}...` : text;
}

export function normalizeLimit(value, fallback = 80, maximum = 200) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.floor(parsed), maximum);
}

export function messageContentText(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map(messageContentText).filter(Boolean).join("\n");
  if (content && typeof content === "object") {
    for (const key of ["text", "content", "input_text", "output_text", "value"]) {
      const value = content[key];
      if (typeof value === "string") return value;
      if (Array.isArray(value)) return value.map(messageContentText).filter(Boolean).join("\n");
    }
    return JSON.stringify(content);
  }
  return String(content ?? "");
}

export function inputText(body) {
  if (typeof body.input === "string") return body.input;
  if (Array.isArray(body.input)) return body.input.map(messageContentText).join("\n");
  if (typeof body.prompt === "string") return body.prompt;
  if (Array.isArray(body.messages)) {
    return body.messages
      .map((message) => {
        let content = messageContentText(message.content ?? "");
        if (message.tool_calls) content += " " + JSON.stringify(message.tool_calls);
        if (message.toolCalls) content += " " + JSON.stringify(message.toolCalls);
        if (message.name) content += " name:" + message.name;
        return `${message.role ?? "user"}: ${content}`;
      })
      .join("\n");
  }
  return JSON.stringify(body);
}

export function deterministicOutput({ kind, input, modelId }) {
  const digest = stableHash(input).slice(0, 12);
  if (kind === "embeddings") return `embedding:${modelId}:${digest}`;
  if (kind === "rerank") return `rerank:${modelId}:${digest}`;
  return `IOI model router fixture response from ${modelId}. input_hash=${digest}`;
}

export function estimateTokens(input, output) {
  const inputTokens = Math.max(1, Math.ceil(String(input).length / 4));
  const outputTokens = Math.max(1, Math.ceil(String(output).length / 4));
  return {
    prompt_tokens: inputTokens,
    completion_tokens: outputTokens,
    total_tokens: inputTokens + outputTokens,
  };
}

export function deterministicTokenizeText(input) {
  const text = String(input ?? "");
  if (!text) {
    return [{ index: 0, text: "", token_id: deterministicTokenId(""), byte_start: 0, byte_end: 0 }];
  }
  const matches = [...text.matchAll(/\S+|\s+/g)];
  return matches.map((match, index) => {
    const tokenText = match[0];
    const byteStart = Buffer.byteLength(text.slice(0, match.index), "utf8");
    const byteEnd = byteStart + Buffer.byteLength(tokenText, "utf8");
    return {
      index,
      text: tokenText,
      token_id: deterministicTokenId(tokenText),
      byte_start: byteStart,
      byte_end: byteEnd,
    };
  });
}

export function deterministicTokenId(tokenText) {
  return Number.parseInt(stableHash(tokenText).slice(0, 8), 16);
}

export function truncateToEstimatedTokens(input, tokenBudget) {
  const text = String(input ?? "");
  const budget = Math.max(0, Math.floor(Number(tokenBudget) || 0));
  if (budget <= 0) return "";
  const maxChars = Math.max(1, budget * 4);
  if (text.length <= maxChars) return text;
  return text.slice(text.length - maxChars);
}
