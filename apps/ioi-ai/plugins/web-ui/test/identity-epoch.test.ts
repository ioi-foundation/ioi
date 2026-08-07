import assert from "node:assert/strict";
import { test } from "node:test";
import { api } from "../src/core-bridge.ts";
import {
  advanceIdentityEpoch,
  assertIdentityEpoch,
  captureIdentityEpoch,
  IdentityEpochChangedError,
} from "../src/identity-epoch.ts";

test("advancing identity invalidates captured work", () => {
  const captured = captureIdentityEpoch();
  assert.doesNotThrow(() => assertIdentityEpoch(captured));
  advanceIdentityEpoch();
  assert.throws(() => assertIdentityEpoch(captured), IdentityEpochChangedError);
});

test("a private API response that finishes after an identity transition cannot resolve into module state", async () => {
  const originalFetch = globalThis.fetch;
  let finish: (response: Response) => void = () => assert.fail("fetch response resolver was not installed");
  globalThis.fetch = (() => new Promise<Response>((resolve) => (finish = resolve))) as typeof fetch;
  try {
    const request = api<{ value: string }>("/api/memory");
    await Promise.resolve();
    advanceIdentityEpoch();
    finish(new Response(JSON.stringify({ value: "old-principal" }), { status: 200 }));
    await assert.rejects(request, IdentityEpochChangedError);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
