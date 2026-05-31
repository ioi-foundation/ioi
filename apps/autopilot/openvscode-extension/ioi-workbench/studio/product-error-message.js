function createStudioProductErrorMessage({ stringValue }) {
  function studioCleanProductErrorMessage(error) {
    const text = stringValue(error?.message || error?.code || error);
    if (/timed out|timeout/i.test(text)) {
      return "The selected model route took too long to respond. Details are in Tracing.";
    }
    if (/product_model_unavailable|No product model is mounted|product model route/i.test(text)) {
      return "No product model is mounted for this route. Open Manage models and load a real local model.";
    }
    if (/OpenAI-compatible provider stream failed|Daemon stream failed|provider stream failed|external_blocker/i.test(text)) {
      return "The selected model route failed while streaming. Details are in Tracing.";
    }
    if (/fixture|deterministic .*fixture/i.test(text)) {
      return "The selected product route refused fixture output. Details are in Tracing.";
    }
    return text
      .replace(/\{[\s\S]*\}/g, "Details are in Tracing.")
      .replace(/\[[^\]]+\]\s*/g, "")
      .trim()
      .slice(0, 320) || "Studio could not complete the turn. Details are in Tracing.";
  }

  return { studioCleanProductErrorMessage };
}

module.exports = {
  createStudioProductErrorMessage,
};
