import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import {
  fetchProviderJson,
  providerCommandError,
  providerHttpError,
} from "./provider-transport.mjs";

async function withJsonServer(handler) {
  const server = http.createServer((request, response) => {
    if (request.url === "/models") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ data: [{ id: "model-a" }] }));
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
      assert.equal(error.details.providerId, "provider.local");
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
  assert.equal(httpError.details.httpStatus, 503);
  assert.equal(httpError.details.providerErrorCode, "overloaded");
  assert.equal(httpError.details.providerErrorMessage.length, 503);
  assert.match(httpError.details.providerErrorMessage, /^x{500}\.\.\.$/);
  assert.equal(typeof httpError.details.providerErrorHash, "string");

  const commandError = providerCommandError(
    { id: "provider.lmstudio", kind: "lm_studio" },
    "Command failed.",
    { status: 17, stderr: "secret-ish stderr" },
  );

  assert.equal(commandError.details.commandExitCode, 17);
  assert.equal(commandError.details.stderrHash.length, 64);
  assert.equal(commandError.details.stderr, undefined);
});
