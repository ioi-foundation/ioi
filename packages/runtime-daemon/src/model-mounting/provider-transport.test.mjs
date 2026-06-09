import assert from "node:assert/strict";
import test from "node:test";

import {
  fetchProviderJson,
  providerCommandError,
  providerHttpError,
  retryProviderOpen,
} from "./provider-transport.mjs";

function provider() {
  return {
    id: "provider.test",
    kind: "openai_compatible",
    baseUrl: "http://127.0.0.1:65535",
    status: "configured",
    authScheme: "none",
  };
}

function assertProviderTransportRetired(error, method) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_provider_http_transport_retired");
  assert.equal(error.details.provider_id, "provider.test");
  assert.equal(error.details.provider_kind, "openai_compatible");
  assert.equal(error.details.method, method);
  assert.equal(error.details.rust_core_boundary, "model_mount.provider_transport");
  assert.deepEqual(error.details.evidence_refs, [
    "provider_http_transport_js_retired",
    "rust_daemon_core_provider_transport_required",
    "agentgres_provider_projection_required",
  ]);
  assert.equal(Object.hasOwn(error.details, "providerId"), false);
  assert.equal(Object.hasOwn(error.details, "providerKind"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  return true;
}

test("provider transport fetch fails closed before live HTTP requests or retries", async () => {
  await assert.rejects(
    () => fetchProviderJson(provider(), "/models", { method: "GET" }),
    (error) => assertProviderTransportRetired(error, "GET"),
  );

  await assert.rejects(
    () => retryProviderOpen(provider(), "/models", { attempt: 1 }),
    (error) => assertProviderTransportRetired(error, "RETRY"),
  );
});

test("provider transport errors redact provider body and command details", () => {
  const httpError = providerHttpError(
    { id: "provider.test", kind: "openai" },
    "Provider failed.",
    {
      status: 503,
      body: {
        error: {
          code: "overloaded",
          type: "service_unavailable",
          message: "x".repeat(800),
        },
        text: "raw provider text",
      },
    },
  );

  assert.equal(httpError.status, 424);
  assert.equal(httpError.details.provider_id, "provider.test");
  assert.equal(httpError.details.provider_kind, "openai");
  assert.equal(httpError.details.http_status, 503);
  assert.equal(httpError.details.provider_error_code, "overloaded");
  assert.equal(httpError.details.provider_error_message.length, 503);
  assert.match(httpError.details.provider_error_message, /^x{500}\.\.\.$/);
  assert.equal(typeof httpError.details.provider_error_hash, "string");
  assert.equal(Object.hasOwn(httpError.details, "providerId"), false);
  assert.equal(Object.hasOwn(httpError.details, "httpStatus"), false);
  assert.equal(Object.hasOwn(httpError.details, "providerErrorCode"), false);
  assert.equal(Object.hasOwn(httpError.details, "providerErrorMessage"), false);

  const commandError = providerCommandError(
    { id: "provider.lmstudio", kind: "lm_studio" },
    "Command failed.",
    { status: 17, stderr: "secret-ish stderr" },
  );

  assert.equal(commandError.details.command_exit_code, 17);
  assert.equal(commandError.details.stderr_hash.length, 64);
  assert.equal(Object.hasOwn(commandError.details, "commandExitCode"), false);
  assert.equal(Object.hasOwn(commandError.details, "stderrHash"), false);
  assert.equal(commandError.details.stderr, undefined);
});
