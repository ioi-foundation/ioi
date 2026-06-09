import assert from "node:assert/strict";
import { test } from "node:test";

import {
  providerOpenRetryDelayMs,
  providerOpenRetryPolicy,
  providerRequestTimeoutMs,
  shouldRetryProviderOpen,
} from "./provider-transport-policy.mjs";

test("provider transport policy gives local JSON probes a native readiness budget", () => {
  const previousHttp = process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS;
  delete process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS;
  try {
    assert.equal(providerRequestTimeoutMs(), 30000);
    assert.equal(providerRequestTimeoutMs({ kind: "llama_cpp" }), 300000);
  } finally {
    if (previousHttp === undefined) delete process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS;
    else process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS = previousHttp;
  }
});

test("provider transport policy retries transient native backend readiness without affecting hosted routes", () => {
  const previous = process.env.IOI_PROVIDER_OPEN_RETRY_MS;
  delete process.env.IOI_PROVIDER_OPEN_RETRY_MS;
  try {
    assert.equal(providerOpenRetryPolicy({ kind: "llama_cpp" }).maxElapsedMs, 30000);
    assert.equal(providerOpenRetryPolicy({ kind: "openai_compatible" }).enabled, false);
    assert.equal(shouldRetryProviderOpen({ kind: "llama_cpp" }, 503, 0, 100), true);
    assert.equal(shouldRetryProviderOpen({ kind: "llama_cpp" }, "network", 0, 100), true);
    assert.equal(shouldRetryProviderOpen({ kind: "llama_cpp" }, 503, 9, 100), false);
    assert.equal(shouldRetryProviderOpen({ kind: "llama_cpp" }, 503, 0, 31000), false);
    assert.equal(shouldRetryProviderOpen({ kind: "openai_compatible" }, 503, 0, 100), false);
    assert.equal(providerOpenRetryDelayMs(0), 250);
    assert.equal(providerOpenRetryDelayMs(4), 2000);
  } finally {
    if (previous === undefined) delete process.env.IOI_PROVIDER_OPEN_RETRY_MS;
    else process.env.IOI_PROVIDER_OPEN_RETRY_MS = previous;
  }
});
