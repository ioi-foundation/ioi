import { assertProviderVaultBoundary, providerAuthHeaders } from "./provider-auth.mjs";
import { parseJsonMaybe, truncate } from "./provider-protocol.mjs";
import {
  providerOpenRetryDelayMs,
  providerRequestTimeoutMs,
  providerStreamRequestTimeoutMs,
  shouldRetryProviderOpen,
} from "./provider-transport-policy.mjs";
import { runtimeError, stableHash } from "./io.mjs";

export async function fetchProviderJson(provider, route, { method = "GET", body, tolerateHttpError = false, state } = {}) {
  assertProviderVaultBoundary(provider);
  if (!provider.baseUrl || String(provider.baseUrl).startsWith("local://")) {
    throw runtimeError({
      status: 424,
      code: "external_blocker",
      message: "Provider does not expose an HTTP model endpoint.",
      details: { providerId: provider.id, providerKind: provider.kind },
    });
  }
  const timeoutMs = providerRequestTimeoutMs(provider);
  const url = `${String(provider.baseUrl).replace(/\/+$/, "")}/${route.replace(/^\/+/, "")}`;
  const auth = providerAuthHeaders(provider, state);
  const startedAt = Date.now();
  for (let attempt = 0; ; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        method,
        signal: controller.signal,
        headers: {
          accept: "application/json",
          ...auth.headers,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      clearTimeout(timeout);
      const text = await response.text();
      const parsed = text.trim() ? parseJsonMaybe(text) : null;
      const result = { ok: response.ok, status: response.status, body: parsed, authEvidence: auth.evidence };
      if (
        !response.ok &&
        !tolerateHttpError &&
        shouldRetryProviderOpen(provider, response.status, attempt, Date.now() - startedAt)
      ) {
        await retryProviderOpen(provider, route, {
          state,
          mode: "json",
          attempt,
          status: response.status,
          body: parsed,
          startedAt,
        });
        continue;
      }
      if (!response.ok && !tolerateHttpError) {
        throw providerHttpError(provider, "OpenAI-compatible provider request failed.", result);
      }
      return result;
    } catch (error) {
      clearTimeout(timeout);
      if (error?.status || error?.code === "external_blocker") throw error;
      if (shouldRetryProviderOpen(provider, "network", attempt, Date.now() - startedAt)) {
        await retryProviderOpen(provider, route, {
          state,
          mode: "json",
          attempt,
          status: "network",
          error,
          startedAt,
        });
        continue;
      }
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "OpenAI-compatible provider request failed.",
        details: {
          providerId: provider.id,
          providerKind: provider.kind,
          error: String(error?.name ?? error?.message ?? error),
          timeoutMs,
        },
      });
    }
  }
}

export async function fetchProviderStream(provider, route, { method = "GET", body, state } = {}) {
  assertProviderVaultBoundary(provider);
  if (!provider.baseUrl || String(provider.baseUrl).startsWith("local://")) {
    throw runtimeError({
      status: 424,
      code: "external_blocker",
      message: "Provider does not expose an HTTP model endpoint.",
      details: { providerId: provider.id, providerKind: provider.kind },
    });
  }
  const timeoutMs = providerStreamRequestTimeoutMs(provider);
  const url = `${String(provider.baseUrl).replace(/\/+$/, "")}/${route.replace(/^\/+/, "")}`;
  const auth = providerAuthHeaders(provider, state);
  const startedAt = Date.now();
  for (let attempt = 0; ; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        method,
        signal: controller.signal,
        headers: {
          accept: "text/event-stream",
          ...auth.headers,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      clearTimeout(timeout);
      if (!response.ok) {
        const text = await response.text();
        const parsed = text.trim() ? parseJsonMaybe(text) : null;
        if (shouldRetryProviderOpen(provider, response.status, attempt, Date.now() - startedAt)) {
          await retryProviderOpen(provider, route, {
            state,
            mode: "stream",
            attempt,
            status: response.status,
            body: parsed,
            startedAt,
          });
          continue;
        }
        throw providerHttpError(provider, "OpenAI-compatible provider stream failed.", {
          ok: false,
          status: response.status,
          body: parsed,
          authEvidence: auth.evidence,
        });
      }
      if (!response.body) {
        throw runtimeError({
          status: 424,
          code: "external_blocker",
          message: "OpenAI-compatible provider did not return a stream body.",
          details: { providerId: provider.id, providerKind: provider.kind },
        });
      }
      return {
        ok: true,
        status: response.status,
        stream: response.body,
        abort: () => controller.abort(),
        authEvidence: auth.evidence,
      };
    } catch (error) {
      clearTimeout(timeout);
      if (error?.status || error?.code === "external_blocker") throw error;
      if (shouldRetryProviderOpen(provider, "network", attempt, Date.now() - startedAt)) {
        await retryProviderOpen(provider, route, {
          state,
          mode: "stream",
          attempt,
          status: "network",
          error,
          startedAt,
        });
        continue;
      }
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "OpenAI-compatible provider stream failed.",
        details: {
          providerId: provider.id,
          providerKind: provider.kind,
          error: String(error?.name ?? error?.message ?? error),
          timeoutMs,
        },
      });
    }
  }
}

export async function retryProviderOpen(provider, route, { state, mode, attempt = 0, status, body, error, startedAt } = {}) {
  const delayMs = providerOpenRetryDelayMs(attempt);
  state?.appendOperation?.("model.provider_open_retry", {
    providerId: provider.id,
    providerKind: provider.kind,
    route,
    mode,
    attempt: attempt + 1,
    status,
    delayMs,
    elapsedMs: Math.max(0, Date.now() - (startedAt ?? Date.now())),
    providerErrorHash: body ? stableHash(body) : null,
    error: error ? String(error?.name ?? error?.message ?? error) : null,
    evidenceRefs: ["provider_open_retry", `${provider.kind}_transient_backend_readiness`],
  });
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

export function providerHttpError(provider, message, result) {
  const providerError = summarizeProviderErrorBody(result.body);
  return runtimeError({
    status: 424,
    code: "external_blocker",
    message,
    details: {
      providerId: provider.id,
      providerKind: provider.kind,
      httpStatus: result.status ?? null,
      providerErrorHash: stableHash(result.body ?? {}),
      providerErrorCode: providerError.code,
      providerErrorType: providerError.type,
      providerErrorMessage: providerError.message,
      providerErrorText: providerError.text,
    },
  });
}

export function providerCommandError(provider, message, result) {
  return runtimeError({
    status: 424,
    code: "external_blocker",
    message,
    details: {
      providerId: provider.id,
      providerKind: provider.kind,
      commandExitCode: result.status ?? null,
      stderrHash: stableHash(result.stderr ?? ""),
    },
  });
}

function summarizeProviderErrorBody(body) {
  if (!body || typeof body !== "object") {
    return { code: null, type: null, message: null, text: null };
  }
  const error = body.error && typeof body.error === "object" ? body.error : body;
  return {
    code: optionalErrorString(error.code),
    type: optionalErrorString(error.type),
    message: optionalErrorString(error.message),
    text: optionalErrorString(body.text),
  };
}

function optionalErrorString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? truncate(trimmed, 500) : null;
}
