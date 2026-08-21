import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertDisclosureSafe,
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
