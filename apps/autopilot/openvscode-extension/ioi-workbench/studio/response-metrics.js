function defaultStringValue(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function defaultEscapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function studioNumberOrNull(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function studioFormatMetricNumber(value, digits = 0) {
  const number = studioNumberOrNull(value);
  if (number === null) return "";
  return number.toLocaleString(undefined, {
    maximumFractionDigits: digits,
    minimumFractionDigits: 0,
  });
}

function studioEstimatedTokenCount(text = "", stringValue = defaultStringValue) {
  const value = stringValue(text).trim();
  if (!value) return null;
  return Math.max(1, Math.ceil(value.length / 4));
}

function studioPositiveNumberOrNull(value) {
  const number = studioNumberOrNull(value);
  return number !== null && number > 0 ? number : null;
}

function createStudioResponseMetrics(deps = {}) {
  const escapeHtml = deps.escapeHtml || defaultEscapeHtml;
  const stringValue = deps.stringValue || defaultStringValue;
  const normalizeStudioReasoningEffort = deps.normalizeStudioReasoningEffort || ((value, fallback = "none") => stringValue(value, fallback));
  const normalizeReceiptRefs = deps.normalizeReceiptRefs || (() => []);

  function estimatedTokenCount(text = "") {
    return studioEstimatedTokenCount(text, stringValue);
  }

  function studioResponseMetricsFromUsage({
    usage = {},
    routeId = "",
    model = "",
    provider = "",
    reasoningEffort = "",
    elapsedMs = null,
    timeToFirstTokenMs = null,
    stopReason = "",
    requestedModel = "",
    promptText = "",
    generatedText = "",
  } = {}) {
    const usagePromptTokens = studioPositiveNumberOrNull(usage.prompt_tokens ?? usage.input_tokens);
    const usageGeneratedTokens = studioPositiveNumberOrNull(usage.completion_tokens ?? usage.output_tokens);
    const promptTokens = usagePromptTokens ?? estimatedTokenCount(promptText);
    const generatedTokens = usageGeneratedTokens ?? estimatedTokenCount(generatedText);
    const totalTokens = studioPositiveNumberOrNull(usage.total_tokens) ?? (
      promptTokens !== null && generatedTokens !== null ? promptTokens + generatedTokens : null
    );
    const elapsedSeconds = studioNumberOrNull(elapsedMs) !== null ? Math.max(0.001, Number(elapsedMs) / 1000) : null;
    const tokensPerSecond =
      elapsedSeconds && generatedTokens !== null ? generatedTokens / elapsedSeconds : studioNumberOrNull(usage.tokens_per_second ?? usage.tokensPerSecond);
    return {
      model: stringValue(model || usage.model || requestedModel),
      requestedModel: stringValue(requestedModel),
      provider: stringValue(provider || usage.provider || ""),
      routeId: stringValue(routeId),
      reasoningEffort: normalizeStudioReasoningEffort(reasoningEffort, "none"),
      promptTokens,
      generatedTokens,
      totalTokens,
      elapsedMs: studioNumberOrNull(elapsedMs),
      timeToFirstTokenMs: studioNumberOrNull(timeToFirstTokenMs),
      tokensPerSecond,
      stopReason: stringValue(stopReason || usage.stop_reason || usage.stopReason || ""),
      estimatedTokens: !usagePromptTokens || !usageGeneratedTokens,
    };
  }

  function studioResponseMetricsFromResponse(response = {}, options = {}) {
    return studioResponseMetricsFromUsage({
      usage: response.usage || response.tokenCount || response.token_count || {},
      routeId: response.route_id || response.routeId || options.routeId,
      model: response.model || options.model,
      provider: response.provider || response.providerId || options.provider,
      reasoningEffort: options.reasoningEffort,
      elapsedMs: options.elapsedMs,
      timeToFirstTokenMs: options.timeToFirstTokenMs,
      stopReason: response.choices?.[0]?.finish_reason || response.stop_reason || response.stopReason || options.stopReason,
      requestedModel: response.request_model || response.requestModel || options.requestedModel,
    });
  }

  function studioResponseMetricsRows(turn = {}) {
    const metrics = turn.modelMetrics || turn.modelStream?.metrics || turn.generator?.metrics || null;
    if (!metrics || typeof metrics !== "object") {
      return "";
    }
    const rows = [
      ["Model", metrics.model],
      ["Provider", metrics.provider],
      ["Route", metrics.routeId],
      ["Reasoning", metrics.reasoningEffort && metrics.reasoningEffort !== "none" ? metrics.reasoningEffort : "off"],
      ["Prompt", metrics.promptTokens !== null && metrics.promptTokens !== undefined ? `${metrics.estimatedTokens ? "~" : ""}${studioFormatMetricNumber(metrics.promptTokens)}` : ""],
      ["Generated", metrics.generatedTokens !== null && metrics.generatedTokens !== undefined ? `${metrics.estimatedTokens ? "~" : ""}${studioFormatMetricNumber(metrics.generatedTokens)}` : ""],
      ["Total", metrics.totalTokens !== null && metrics.totalTokens !== undefined ? `${metrics.estimatedTokens ? "~" : ""}${studioFormatMetricNumber(metrics.totalTokens)}` : ""],
      ["Elapsed", metrics.elapsedMs !== null && metrics.elapsedMs !== undefined ? `${studioFormatMetricNumber(Number(metrics.elapsedMs) / 1000, 1)}s` : ""],
      ["Tok/s", studioFormatMetricNumber(metrics.tokensPerSecond, 1)],
      ["TTFT", metrics.timeToFirstTokenMs !== null && metrics.timeToFirstTokenMs !== undefined ? `${studioFormatMetricNumber(Number(metrics.timeToFirstTokenMs), 0)}ms` : ""],
      ["Stop", metrics.stopReason],
    ].filter(([, value]) => stringValue(value));
    if (!rows.length) {
      return "";
    }
    return `
    <footer class="studio-response-metrics" data-testid="studio-response-metrics">
      ${rows.map(([label, value]) => `
        <span><strong>${escapeHtml(label)}</strong>${escapeHtml(value)}</span>
      `).join("")}
    </footer>
  `;
  }

  function studioSplitReasoningFromText(text = "") {
    const raw = stringValue(text);
    const match = raw.match(/<think>\s*([\s\S]*?)\s*<\/think>\s*/i);
    if (!match) {
      return { thinkingText: "", answerText: raw };
    }
    return {
      thinkingText: match[1].trim(),
      answerText: raw.replace(match[0], "").trim(),
    };
  }

  function studioThinkingRows(turn = {}) {
    const thinkingText = stringValue(turn.thinkingText || turn.modelStream?.thinkingText);
    if (!thinkingText) {
      return "";
    }
    return `
    <details class="studio-thinking-block" data-testid="studio-thinking-block">
      <summary>Thinking</summary>
      <p>${escapeHtml(thinkingText)}</p>
    </details>
  `;
  }

  function studioTurnContentRows(turn = {}, displayContent = "") {
    return turn.role === "assistant"
      ? `<div class="studio-markdown" data-testid="${turn.modelStream?.streamId && !turn.modelStream?.completed ? "studio-streaming-output" : "studio-assistant-answer-text"}">${escapeHtml(displayContent)}</div>`
      : `<p>${escapeHtml(displayContent)}</p>`;
  }

  function studioVerifiedBadge(payload = {}, label = "Verified") {
    const receiptRefs = normalizeReceiptRefs(payload);
    const hasReceipt = receiptRefs.length > 0;
    return `
    <span
      class="studio-verified-badge${hasReceipt ? "" : " studio-verified-badge--unverified"}"
      data-testid="studio-verified-badge"
      data-receipt-backed="${hasReceipt ? "true" : "false"}"
      title="${escapeHtml(hasReceipt ? "Backed by daemon receipt refs" : "Waiting for daemon receipt refs")}"
    >
      ${escapeHtml(hasReceipt ? label : "Trace pending")}
    </span>
  `;
  }

  return {
    studioEstimatedTokenCount: estimatedTokenCount,
    studioFormatMetricNumber,
    studioNumberOrNull,
    studioPositiveNumberOrNull,
    studioResponseMetricsFromResponse,
    studioResponseMetricsFromUsage,
    studioResponseMetricsRows,
    studioSplitReasoningFromText,
    studioThinkingRows,
    studioTurnContentRows,
    studioVerifiedBadge,
  };
}

module.exports = {
  createStudioResponseMetrics,
  studioEstimatedTokenCount,
  studioFormatMetricNumber,
  studioNumberOrNull,
  studioPositiveNumberOrNull,
};
