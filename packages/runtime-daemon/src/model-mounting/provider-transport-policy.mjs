export function providerRequestTimeoutMs(provider = {}) {
  const configured = Number(process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS ?? "");
  if (Number.isFinite(configured) && configured >= 1000) return configured;
  if (["llama_cpp", "lm_studio", "ollama", "vllm"].includes(provider.kind)) return 300000;
  return 30000;
}

export function providerStreamRequestTimeoutMs(provider = {}) {
  const configured = Number(process.env.IOI_PROVIDER_STREAM_TIMEOUT_MS ?? "");
  if (Number.isFinite(configured) && configured >= 1000) return configured;
  const httpConfigured = Number(process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS ?? "");
  if (Number.isFinite(httpConfigured) && httpConfigured >= 1000) return httpConfigured;
  if (["llama_cpp", "lm_studio", "ollama", "vllm"].includes(provider.kind)) return 120000;
  return 60000;
}

export function providerOpenRetryPolicy(provider = {}) {
  const rawConfigured = process.env.IOI_PROVIDER_OPEN_RETRY_MS;
  const configured = Number(rawConfigured ?? "");
  const localProvider = ["llama_cpp", "ollama", "vllm"].includes(provider.kind);
  const maxElapsedMs = rawConfigured !== undefined && Number.isFinite(configured) && configured >= 0
    ? configured
    : localProvider
      ? 30000
      : 0;
  return {
    enabled: maxElapsedMs > 0,
    maxElapsedMs,
    retryStatuses: [408, 409, 423, 425, 429, 500, 502, 503, 504],
  };
}

export function providerOpenRetryDelayMs(attempt = 0) {
  return Math.min(2000, 250 * 2 ** Math.max(0, Math.min(4, Number(attempt) || 0)));
}

export function shouldRetryProviderOpen(provider = {}, status, attempt = 0, elapsedMs = 0) {
  const policy = providerOpenRetryPolicy(provider);
  if (!policy.enabled) return false;
  if (elapsedMs >= policy.maxElapsedMs) return false;
  if (attempt >= 8) return false;
  if (status === "network") return true;
  return policy.retryStatuses.includes(Number(status));
}

export function responsesFallbackStatus(status) {
  return [400, 404, 405, 501].includes(Number(status));
}

export function providerHealthFailureStatus(error) {
  if (error?.status === 403 || error?.code === "policy") return "blocked";
  if (error?.status === 404) return "absent";
  return "degraded";
}
