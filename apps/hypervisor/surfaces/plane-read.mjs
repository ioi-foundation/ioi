// One deadline for both response headers and response-body parsing. Surfaces use this at owner
// boundaries so one stalled daemon projection degrades honestly instead of hanging the route.
export async function readJsonWithDeadline(fetchImpl, url, timeoutMs, init = {}) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(async () => {
        const response = await fetchImpl(url, { ...init, signal: controller.signal });
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
      }),
    ]);
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}
