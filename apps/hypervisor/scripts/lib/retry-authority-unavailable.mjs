export const authorityUnavailableDetail = (response) => {
  const error = response?.body?.error ?? response?.body ?? {};
  return [error?.code, error?.message, error?.details]
    .filter((value) => value !== undefined && value !== null && value !== "")
    .map((value) => typeof value === "string" ? value : JSON.stringify(value))
    .join(":")
    .slice(0, 2_000);
};

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

// Retry only the explicit dependency-unavailable response. Every attempt uses
// the caller's exact closure, so governed callers can replay the same request
// bytes and the same recorded grant. No other status is converted or retried.
export const retryAuthorityUnavailable = async (
  operation,
  timeoutMs = 120_000,
  retryDelayMs = 250,
) => {
  const deadline = Date.now() + timeoutMs;
  let attempts = 0;
  let response;
  do {
    attempts += 1;
    response = await operation();
    if (response.status !== 503) return { response, attempts };
    if (Date.now() >= deadline) break;
    await delay(retryDelayMs);
  } while (true);
  return { response, attempts };
};
