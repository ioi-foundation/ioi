import assert from "node:assert/strict";
import test from "node:test";

import {
  authorityUnavailableDetail,
  retryAuthorityUnavailable,
} from "./retry-authority-unavailable.mjs";

test("dependency 503 retries the exact closure until a non-503 result", async () => {
  const calls = [];
  const result = await retryAuthorityUnavailable(async () => {
    calls.push("same-request-and-grant");
    return calls.length < 3 ? { status: 503 } : { status: 200, body: { admitted: true } };
  }, 1_000, 0);

  assert.equal(result.response.status, 200);
  assert.equal(result.attempts, 3);
  assert.deepEqual(calls, [
    "same-request-and-grant",
    "same-request-and-grant",
    "same-request-and-grant",
  ]);
});

test("non-503 failures are never retried or converted", async () => {
  let calls = 0;
  const result = await retryAuthorityUnavailable(async () => {
    calls += 1;
    return { status: 409, body: { error: { code: "conflict" } } };
  }, 1_000, 0);
  assert.equal(calls, 1);
  assert.equal(result.attempts, 1);
  assert.equal(result.response.status, 409);
});

test("an exhausted 503 remains a 503 with bounded diagnostic detail", async () => {
  const result = await retryAuthorityUnavailable(
    async () => ({
      status: 503,
      body: { error: { code: "resolver_unavailable", message: "retry later", details: "x".repeat(4_000) } },
    }),
    0,
    0,
  );
  assert.equal(result.attempts, 1);
  assert.equal(result.response.status, 503);
  const detail = authorityUnavailableDetail(result.response);
  assert.ok(detail.startsWith("resolver_unavailable:retry later:"));
  assert.equal(detail.length, 2_000);
});
