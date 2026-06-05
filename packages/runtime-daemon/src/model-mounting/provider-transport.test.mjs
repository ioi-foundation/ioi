import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import {
  fetchProviderJson,
  providerCommandError,
  providerHttpError,
} from "./provider-transport.mjs";

async function withJsonServer(handler) {
  let retryCount = 0;
  const server = http.createServer((request, response) => {
    if (request.url === "/models") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ data: [{ id: "model-a" }] }));
      return;
    }
    if (request.url === "/retry") {
      retryCount += 1;
      if (retryCount === 1) {
        response.writeHead(503, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { code: "warming" } }));
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, attempts: retryCount }));
      return;
    }
    if (request.url === "/fail") {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({
        error: {
          code: "provider_down",
          type: "server_error",
          message: "Provider unavailable",
        },
      }));
      return;
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end("{}");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    return await handler(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("provider transport fetches JSON with auth boundary evidence", async () => {
  await withJsonServer(async (baseUrl) => {
    const result = await fetchProviderJson({
      id: "provider.test",
      kind: "ollama",
      baseUrl,
      status: "configured",
      authScheme: "none",
    }, "/models");

    assert.equal(result.ok, true);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, { data: [{ id: "model-a" }] });
    assert.equal(result.authEvidence, null);
  });
});

test("provider transport retries without appending operation-like records", async () => {
  await withJsonServer(async (baseUrl) => {
    const appendOperations = [];
    const result = await fetchProviderJson({
      id: "provider.ollama",
      kind: "ollama",
      baseUrl,
      status: "configured",
      authScheme: "none",
    }, "/retry", {
      state: {
        appendOperation: (kind, payload) => appendOperations.push({ kind, payload }),
      },
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.body, { ok: true, attempts: 2 });
    assert.deepEqual(appendOperations, []);
  });
});

test("provider transport tolerates provider HTTP errors when requested", async () => {
  await withJsonServer(async (baseUrl) => {
    const result = await fetchProviderJson({
      id: "provider.test",
      kind: "ollama",
      baseUrl,
      status: "configured",
      authScheme: "none",
    }, "/fail", { tolerateHttpError: true });

    assert.equal(result.ok, false);
    assert.equal(result.status, 500);
    assert.equal(result.body.error.code, "provider_down");
  });
});

test("provider transport rejects local-only providers without HTTP endpoints", async () => {
  await assert.rejects(
    () => fetchProviderJson({
      id: "provider.local",
      kind: "llama_cpp",
      baseUrl: "local://llama",
      status: "configured",
    }, "/models"),
    (error) => {
      assert.equal(error.status, 424);
      assert.equal(error.code, "external_blocker");
      assert.equal(error.details.provider_id, "provider.local");
      assert.equal(error.details.provider_kind, "llama_cpp");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      return true;
    },
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
