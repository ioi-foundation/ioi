"use strict";

function createStudioToolResponseProjection({
  normalizeReceiptRefs,
}) {
  function safeJsonPreview(value, max = 1200) {
    if (value === undefined || value === null) {
      return "";
    }
    const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
    return text.length > max ? `${text.slice(0, max)}…` : text;
  }

  function commandOutputFromToolResponse(toolId, response = {}) {
    const result = response.result || {};
    const nested = result.result || {};
    return {
      id: response.tool_call_id || response.toolCallId || `${toolId}.${Date.now()}`,
      toolId,
      label: result.command || nested.command || result.commandId || nested.commandId || toolId,
      status: response.status || result.status || nested.status || "completed",
      stdout:
        result.stdout ||
        nested.stdout ||
        result.output ||
        nested.output ||
        safeJsonPreview(result.diagnostics || nested.diagnostics || result.results || nested.results),
      stderr: result.stderr || nested.stderr || result.error?.message || nested.error?.message || "",
      exitCode: result.exitCode ?? nested.exitCode ?? result.exit_code ?? nested.exit_code ?? (response.status === "failed" ? 1 : 0),
      durationMs: result.durationMs ?? nested.durationMs ?? result.duration_ms ?? nested.duration_ms ?? null,
      receiptRefs: normalizeReceiptRefs(response, result, nested),
    };
  }

  return {
    commandOutputFromToolResponse,
    safeJsonPreview,
  };
}

module.exports = {
  createStudioToolResponseProjection,
};
