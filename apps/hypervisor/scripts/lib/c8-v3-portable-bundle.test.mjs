import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  contentHash,
  hashWithout,
  indexPortableArtifacts,
  resolvePortableArtifact,
  sealSelfHash,
  validatePortableBundleShape,
} from "./c8-v3-portable-bundle.mjs";

test("canonical content hash ignores object insertion order", () => {
  assert.equal(contentHash({ b: 2, a: 1 }), contentHash({ a: 1, b: 2 }));
});

test("known contracts exclude exactly their self-hash field", () => {
  const policy = sealSelfHash({ schema_version: "ioi.foundations.relying-party-acceptance-policy.v1", policy_ref: "acceptance-policy://aft/test" });
  assert.equal(policy.policy_hash, hashWithout(policy, "policy_hash"));
  assert.equal(contentHash(policy), policy.policy_hash);
});

test("portable bundle shape rejects a traversal filename", () => {
  const bundle = sealSelfHash({
    schema_version: "ioi.components.hypervisor.c8-portable-evidence-bundle.v1",
    bundle_ref: "evidence-bundle://aft/test",
    certificate_ref: "certificate://c8/v3/test",
    certificate_hash: `sha256:${"1".repeat(64)}`,
    certificate_file: "../certificate.json",
    objects: Array.from({ length: 10 }, (_, index) => ({ index })),
    trust_inputs: [{}, {}],
    created_at: "2026-08-22T12:00:00Z",
  });
  assert.deepEqual(validatePortableBundleShape(bundle).failures, ["certificate_file_invalid"]);
});

test("assembler output creation is exclusive", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "c8-v3-exclusive-"));
  assert.equal(fs.existsSync(directory), true);
  fs.rmSync(directory, { recursive: true });
});

test("versioned object identity resolves the same ref by its committed hash", () => {
  const ref = "trajectory-state://aft/test";
  const before = { ref, hash: `sha256:${"1".repeat(64)}`, file: "before.json" };
  const after = { ref, hash: `sha256:${"2".repeat(64)}`, file: "after.json" };
  const index = indexPortableArtifacts([before, after]);
  assert.equal(resolvePortableArtifact(index, ref, before.hash), before);
  assert.equal(resolvePortableArtifact(index, ref, after.hash), after);
  assert.throws(
    () => resolvePortableArtifact(index, ref),
    /version-ambiguous/u,
  );
});

test("duplicate ref and hash binding remains forbidden", () => {
  const artifact = {
    ref: "trajectory-state://aft/test",
    hash: `sha256:${"1".repeat(64)}`,
    file: "state.json",
  };
  assert.throws(
    () => indexPortableArtifacts([artifact, { ...artifact, file: "duplicate.json" }]),
    /duplicate portable object binding/u,
  );
});
