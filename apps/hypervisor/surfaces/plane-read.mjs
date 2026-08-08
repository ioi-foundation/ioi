// One deadline for both response headers and response-body parsing. Surfaces use this at owner
// boundaries so one stalled daemon projection degrades honestly instead of hanging the route.
//
// W1.3: `init.signal` (an AbortSignal) cancels the read from the caller's side — component
// unmount, superseded navigation, an abandoned fan-out. Cancellation and deadline are distinct
// outcomes: a timeout is the daemon failing the caller (`plane_timeout`), a cancel is the caller
// releasing the daemon (`plane_cancelled`). Conflating them turns every abandoned page into a
// false availability signal.
export async function readJsonWithDeadline(fetchImpl, url, timeoutMs, init = {}) {
  const controller = new AbortController();
  const { signal: external, ...rest } = init;
  let timer;
  let onExternalAbort;
  try {
    return await Promise.race([
      Promise.resolve().then(async () => {
        const response = await fetchImpl(url, { ...rest, signal: controller.signal });
        const payload = await response.json();
        return { response, payload };
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          const error = new Error(`plane read exceeded ${timeoutMs}ms`);
          error.code = "plane_timeout";
          reject(error);
        }, timeoutMs);
        if (external) {
          onExternalAbort = () => {
            controller.abort();
            const error = new Error("plane read cancelled by caller");
            error.code = "plane_cancelled";
            reject(error);
          };
          if (external.aborted) onExternalAbort();
          else external.addEventListener("abort", onExternalAbort, { once: true });
        }
      }),
    ]);
  } finally {
    clearTimeout(timer);
    if (external && onExternalAbort) external.removeEventListener("abort", onExternalAbort);
    controller.abort();
  }
}
