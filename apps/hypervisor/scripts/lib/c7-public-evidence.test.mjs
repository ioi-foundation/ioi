import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertDisclosureSafe,
  publicProvider,
  writePublicEvidenceBundle,
} from "./c7-public-evidence.mjs";

test("disclosure scan accepts hashes and public provider facts", () => {
  assert.doesNotThrow(() => assertDisclosureSafe({
    dseq: "1787324505416",
    provider: "akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk",
    request_hash: `sha256:${"a".repeat(64)}`,
  }));
});

for (const [name, value] of [
  ["session", { session_token: "ioi_sess_forbidden" }],
  ["email", { operator: "person@example.com" }],
  ["home path", { source: "/home/operator/private/file" }],
  ["provider account", { ref: "provider-account://internal" }],
  ["private key", "-----BEGIN PRIVATE KEY-----"],
]) {
  test(`disclosure scan rejects ${name}`, () => {
    assert.throws(() => assertDisclosureSafe(value), /disclosure scan refused/u);
  });
}

test("disclosure scan rejects a seeded canary wherever it appears", () => {
  assert.throws(
    () => assertDisclosureSafe({ nested: ["safe", "PUBLIC-CANARY-42"] }, "PUBLIC-CANARY-42"),
    /seeded_canary/u,
  );
});

test("public evidence hashes provider-internal locators", () => {
  const certificate = { provider: {
    dseq: "1787000000000",
    provider_address: "akash1public",
    bid_ref: "akash-bid://internal",
    lease_ref: "akash-lease://internal",
    lease_state: "closed",
    endpoint_ref: "akash-endpoint://internal",
    endpoint_discovered: true,
    service_uri_present: true,
    desired_replicas: 1,
    ready_replicas: 0,
    workload_readiness_proven: false,
    workload_result_retrieved: false,
    c6: { retrieved_live: true, provider_response_hash: `sha256:${"a".repeat(64)}` },
  } };
  const provider = publicProvider(certificate);
  assert.equal(provider.dseq, certificate.provider.dseq);
  assert.equal(provider.provider_address, certificate.provider.provider_address);
  assert.equal(provider.bid_ref, undefined);
  assert.equal(provider.lease_ref, undefined);
  assert.equal(provider.endpoint_ref, undefined);
  assert.match(provider.bid_ref_hash, /^sha256:[0-9a-f]{64}$/u);
  assert.match(provider.lease_ref_hash, /^sha256:[0-9a-f]{64}$/u);
  assert.match(provider.endpoint_ref_hash, /^sha256:[0-9a-f]{64}$/u);
});

test("public bundle writes only regular, hashed disclosure-safe artifacts", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-c7-public-evidence-"));
  try {
    const result = writePublicEvidenceBundle(
      directory,
      {
        schema_version: "fixture",
        claims: { certified_scope: "governed_infrastructure_lifecycle" },
        nonclaims: ["provider neutrality"],
        workload: { redacted_sdl: "version: fixture\n" },
      },
      {
        schema_version: "verification-fixture",
        ok: true,
        mutations: { mutation_count: 22, failures: [] },
      },
    );
    assert.equal(result.artifact_count, 6);
    assert.match(fs.readFileSync(path.join(directory, "manifest.sha256"), "utf8"), /public-evidence\.json/u);
    assert.deepEqual(
      fs.readdirSync(directory).filter((name) => fs.lstatSync(path.join(directory, name)).isFile()).length,
      6,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("public bundle retains the passed structural and live mutation matrices", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-c7-public-evidence-"));
  try {
    const result = writePublicEvidenceBundle(
      directory,
      {
        schema_version: "fixture",
        claims: { certified_scope: "governed_infrastructure_lifecycle" },
        nonclaims: ["provider neutrality"],
        workload: { redacted_sdl: "version: fixture\n" },
      },
      {
        schema_version: "verification-fixture",
        ok: true,
        mutations: { mutation_count: 20, cases: [{ case: 1, expected_failure: "provider_selector_changed" }], failures: [] },
      },
      "",
      {
        schema_version: "self-test-fixture",
        ok: true,
        mutation_count: 22,
        cases: [{ case: 1, expected_failure: "run_not_successful" }],
        failures: [],
      },
    );
    assert.equal(result.artifact_count, 7);
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, "verification-summary.json"), "utf8")).mutation_cases.length, 1);
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, "structural-verifier-self-test.json"), "utf8")).mutation_count, 22);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
