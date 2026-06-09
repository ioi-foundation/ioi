import assert from "node:assert/strict";
import { test } from "node:test";

import {
  providerHealthFailureStatus,
} from "./provider-transport-policy.mjs";

test("provider transport policy only keeps fail-closed health status classification", () => {
  assert.equal(providerHealthFailureStatus({ status: 403 }), "blocked");
  assert.equal(providerHealthFailureStatus({ code: "policy" }), "blocked");
  assert.equal(providerHealthFailureStatus({ status: 404 }), "absent");
  assert.equal(providerHealthFailureStatus({ status: 500 }), "degraded");
});
