import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import type {
  AuthorityKeySetV1,
  AuthorityRevocationSnapshotV1,
  ReceiptProofBundleV1,
} from "./generated/architecture-contracts";
import { validateArchitectureContract } from "./generated/architecture-contracts";
import {
  type ReceiptProofVerificationInput,
  verifyReceiptProofBundleV1,
} from "./portable-receipt-proof";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const fixtureRoot = path.join(repoRoot, "docs/architecture/_meta/schemas/fixtures");
const semanticRoot = path.join(repoRoot, "tests/fixtures/receipt-proof");
const NOW = 1_784_203_300;

function fixture<T>(relativePath: string): T {
  return JSON.parse(fs.readFileSync(path.join(fixtureRoot, relativePath), "utf8")) as T;
}

const bundle = () =>
  fixture<ReceiptProofBundleV1>("receipt-proof-bundle-v1/positive-offline.json");
const keys = () => fixture<AuthorityKeySetV1>("authority-key-set-v1/positive-active.json");
const snapshot = () =>
  fixture<AuthorityRevocationSnapshotV1>(
    "authority-revocation-snapshot-v1/positive-current.json",
  );
const delegatorKeys = () =>
  fixture<AuthorityKeySetV1>("authority-key-set-v1/positive-delegator.json");
const revokedSnapshot = () =>
  JSON.parse(
    fs.readFileSync(path.join(semanticRoot, "revoked-signer-snapshot.json"), "utf8"),
  ) as AuthorityRevocationSnapshotV1;

function input(
  overrides: Partial<ReceiptProofVerificationInput> = {},
): ReceiptProofVerificationInput {
  return {
    bundle: bundle(),
    keySet: keys(),
    revocationSnapshot: snapshot(),
    now: NOW,
    maxSnapshotStalenessSeconds: 300,
    ...overrides,
  };
}

async function rejected(
  candidate: ReceiptProofVerificationInput,
  expectedCode: string,
) {
  const result = await verifyReceiptProofBundleV1(candidate);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, expectedCode);
}

test("golden receipt inclusion and checkpoint consistency verify offline", async () => {
  assert.deepEqual(await verifyReceiptProofBundleV1(input()), { ok: true, code: "ok" });
});

test("receipt, type, domain, version, leaf, index, and inclusion tampering fail closed", async () => {
  const receipt = bundle();
  receipt.receipt.receipt_type = "foreign_receipt";
  await rejected(input({ bundle: receipt }), "receipt_body_hash");

  const version = bundle();
  version.schema_version = "ioi.foundations.receipt-proof-bundle.v2";
  await rejected(input({ bundle: version }), "structural");

  const domain = bundle();
  domain.leaf.domain = "ioi.foreign-leaf.v1";
  await rejected(input({ bundle: domain }), "structural");

  const leaf = bundle();
  leaf.leaf.leaf_hash = `sha256:${"a".repeat(64)}`;
  await rejected(input({ bundle: leaf }), "leaf_hash");

  const index = bundle();
  index.leaf.leaf_index = 0;
  index.inclusion_proof.leaf_index = 0;
  await rejected(input({ bundle: index }), "leaf_hash");

  const inclusion = bundle();
  inclusion.inclusion_proof.prefix_root = `sha256:${"b".repeat(64)}`;
  await rejected(input({ bundle: inclusion }), "inclusion");

  const missing = structuredClone(bundle()) as unknown as Record<string, unknown>;
  delete missing.inclusion_proof;
  assert.equal(
    validateArchitectureContract(
      "schema://ioi/foundations/receipt-proof-bundle/v1",
      missing,
    ).ok,
    false,
  );
});

test("checkpoint chain, signature, split-view witness, and manifest tampering fail closed", async () => {
  const consistency = bundle();
  consistency.consistency_proof.extension_leaf_hashes[0] = `sha256:${"c".repeat(64)}`;
  await rejected(input({ bundle: consistency }), "consistency");

  const splitView = bundle();
  splitView.consistency_proof.from_root = `sha256:${"d".repeat(64)}`;
  await rejected(input({ bundle: splitView }), "consistency");

  const signature = bundle();
  signature.checkpoint.signature = "A".repeat(86);
  await rejected(input({ bundle: signature }), "signature");

  const manifest = bundle();
  manifest.verification_instructions.steps[0] = "Trust without verification.";
  await rejected(input({ bundle: manifest }), "manifest_hash");

  const manifestSignature = bundle();
  manifestSignature.manifest_signature = "A".repeat(86);
  await rejected(input({ bundle: manifestSignature }), "signature");
});

test("unknown, revoked, stale, and wrong signer inputs fail closed", async () => {
  const unknown = keys();
  unknown.keys[0].key_id = "key://acme/security/unknown";
  await rejected(input({ keySet: unknown }), "key_unknown");
  await rejected(input({ revocationSnapshot: revokedSnapshot() }), "key_revoked");

  const current = snapshot();
  await rejected(input({ now: current.expires_at + 1 }), "snapshot_stale");

  const stale = keys();
  stale.keys[0].expires_at = 1_784_203_200;
  await rejected(input({ keySet: stale }), "key_stale");
  await rejected(input({ keySet: delegatorKeys() }), "key_set");
});
