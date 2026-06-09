import { truncate } from "./provider-protocol.mjs";
import { runtimeError, stableHash } from "./io.mjs";

export async function fetchProviderJson(provider, route, { method = "GET", body, tolerateHttpError = false, state } = {}) {
  void body;
  void tolerateHttpError;
  void state;
  throw providerHttpTransportRetiredError(provider, {
    route,
    method,
  });
}

export async function retryProviderOpen(_provider, _route, { attempt = 0 } = {}) {
  void _provider;
  void _route;
  void attempt;
  throw providerHttpTransportRetiredError(_provider, {
    route: _route,
    method: "RETRY",
  });
}

export function providerHttpTransportRetiredError(provider = {}, { route = null, method = null, operation_kind = "model_mount.provider.http_transport" } = {}) {
  return runtimeError({
    status: 501,
    code: "model_mount_provider_http_transport_retired",
    message: "Provider HTTP transport requires Rust daemon-core model_mount provider ownership.",
    details: {
      provider_id: provider?.id ?? null,
      provider_kind: provider?.kind ?? null,
      route,
      method,
      operation_kind,
      rust_core_boundary: "model_mount.provider_transport",
      evidence_refs: [
        "provider_http_transport_js_retired",
        "rust_daemon_core_provider_transport_required",
        "agentgres_provider_projection_required",
      ],
    },
  });
}

export function providerHttpError(provider, message, result) {
  const providerError = summarizeProviderErrorBody(result.body);
  return runtimeError({
    status: 424,
    code: "external_blocker",
    message,
    details: {
      provider_id: provider.id,
      provider_kind: provider.kind,
      http_status: result.status ?? null,
      provider_error_hash: stableHash(result.body ?? {}),
      provider_error_code: providerError.code,
      provider_error_type: providerError.type,
      provider_error_message: providerError.message,
      provider_error_text: providerError.text,
    },
  });
}

export function providerCommandError(provider, message, result) {
  return runtimeError({
    status: 424,
    code: "external_blocker",
    message,
    details: {
      provider_id: provider.id,
      provider_kind: provider.kind,
      command_exit_code: result.status ?? null,
      stderr_hash: stableHash(result.stderr ?? ""),
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
