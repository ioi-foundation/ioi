import assert from "node:assert/strict";
import test from "node:test";
import { sealU1Certificate, validateU1Certificate } from "./u1-campaign-certificate.mjs";
import { validU1Fixture } from "./u1-campaign-certificate.test-fixture.mjs";

test("accepts a complete 10-row five-pass campaign chained to verified C8", () => {
  assert.deepEqual(validateU1Certificate(validU1Fixture()), { ok: true, failures: [] });
});

test("rejects a resealed lifecycle root that names different result bytes", () => {
  const certificate = validU1Fixture();
  certificate.lifecycle.result_binding.result_hash = `sha256:${"f".repeat(64)}`;
  const resealed = sealU1Certificate(certificate);
  const result = validateU1Certificate(resealed);
  assert.equal(result.ok, false);
  assert(result.failures.some((failure) => failure.code === "u1_lifecycle_result_binding_invalid"));
});

test("rejects a resealed attempt to claim bare metal without placement attestation", () => {
  const certificate = validU1Fixture();
  certificate.claims.bare_metal_claimed = true;
  const result = validateU1Certificate(certificate);
  assert(result.failures.some((failure) => failure.code === "u1_certificate_hash_mismatch"));
  assert(result.failures.some((failure) => failure.code === "u1_unsupported_bare_metal_claim"));
});
