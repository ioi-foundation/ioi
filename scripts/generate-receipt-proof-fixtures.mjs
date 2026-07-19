#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaRoot = path.join(root, "docs", "architecture", "_meta", "schemas");
const fixtureRoot = path.join(schemaRoot, "fixtures");
const semanticFixtureRoot = path.join(root, "tests", "fixtures", "receipt-proof");
const check = process.argv.includes("--check");

const RECEIPT_CONTRACT_ID = "schema://ioi/foundations/receipt-envelope/v1";
const CHECKPOINT_PREFIX = Buffer.from("IOI-RECEIPT-CHECKPOINT-V1\0", "utf8");
const MANIFEST_PREFIX = Buffer.from(
  "IOI-RECEIPT-PROOF-BUNDLE-MANIFEST-V1\0",
  "utf8",
);
const LEAF_PREFIX = Buffer.from("IOI-RECEIPT-ACCUMULATOR-LEAF-V1\0", "utf8");
const STEP_PREFIX = Buffer.from("IOI-RECEIPT-ACCUMULATOR-STEP-V1\0", "utf8");
const EMPTY_PREFIX = Buffer.from("IOI-RECEIPT-ACCUMULATOR-EMPTY-V1\0", "utf8");
const REVOCATION_PREFIX = Buffer.from(
  "IOI-AUTHORITY-REVOCATION-SNAPSHOT-V1\0",
  "utf8",
);

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function schemaHash(fileName) {
  const schema = JSON.parse(fs.readFileSync(path.join(schemaRoot, fileName), "utf8"));
  return sha256(canonicalJson(schema));
}

function clone(value) {
  return structuredClone(value);
}

function deterministicKey(label) {
  const seed = createHash("sha256")
    .update(`ioi-portable-authority-fixture:${label}:v1`)
    .digest();
  const privateDer = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  const privateKey = createPrivateKey({ key: privateDer, format: "der", type: "pkcs8" });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return {
    privateKey,
    publicKey: Buffer.from(publicDer).subarray(-32).toString("base64url"),
  };
}

function unsignedSignedArtifact(value) {
  const body = clone(value);
  delete body.body_hash;
  delete body.signature_suite;
  delete body.signature_key_id;
  delete body.signature;
  return body;
}

function checkpointArtifactHash(checkpoint) {
  return sha256(canonicalJson(checkpoint));
}

function signCheckpoint(checkpoint, privateKey) {
  checkpoint.body_hash = sha256(canonicalJson(unsignedSignedArtifact(checkpoint)));
  const material = canonicalJson({
    accumulator_algorithm: checkpoint.accumulator_algorithm,
    accumulator_root: checkpoint.accumulator_root,
    accumulator_size: checkpoint.accumulator_size,
    body_hash: checkpoint.body_hash,
    schema_hash: checkpoint.schema_hash,
    signature_domain: checkpoint.signature_domain,
  });
  checkpoint.signature = sign(
    null,
    Buffer.concat([CHECKPOINT_PREFIX, Buffer.from(material, "utf8")]),
    privateKey,
  ).toString("base64url");
  return checkpoint;
}

function signSnapshot(snapshot, privateKey) {
  snapshot.body_hash = sha256(canonicalJson(unsignedSignedArtifact(snapshot)));
  const material = canonicalJson({
    body_hash: snapshot.body_hash,
    signature_domain: snapshot.signature_domain,
  });
  snapshot.signature = sign(
    null,
    Buffer.concat([REVOCATION_PREFIX, Buffer.from(material, "utf8")]),
    privateKey,
  ).toString("base64url");
  return snapshot;
}

function receiptBodyHash(receipt) {
  return sha256(canonicalJson(receipt));
}

function receiptLeafHash(receiptHash, receiptSchemaHash, leafIndex) {
  const material = canonicalJson({
    domain: "ioi.receipt-accumulator-leaf.v1",
    leaf_index: leafIndex,
    receipt_body_hash: receiptHash,
    receipt_contract_id: RECEIPT_CONTRACT_ID,
    receipt_schema_hash: receiptSchemaHash,
  });
  return sha256(Buffer.concat([LEAF_PREFIX, Buffer.from(material, "utf8")]));
}

function accumulatorStep(previousRoot, leafHash) {
  const material = canonicalJson({
    leaf_hash: leafHash,
    previous_root: previousRoot,
  });
  return sha256(Buffer.concat([STEP_PREFIX, Buffer.from(material, "utf8")]));
}

function accumulate(leaves, initialRoot = sha256(EMPTY_PREFIX)) {
  return leaves.reduce(accumulatorStep, initialRoot);
}

function unsignedManifest(bundle) {
  const manifest = clone(bundle);
  delete manifest.manifest_hash;
  delete manifest.manifest_signature_suite;
  delete manifest.manifest_signature_key_id;
  delete manifest.manifest_signature;
  return manifest;
}

function signManifest(bundle, privateKey) {
  bundle.manifest_hash = sha256(canonicalJson(unsignedManifest(bundle)));
  const material = canonicalJson({
    bundle_schema_hash: bundle.bundle_schema_hash,
    manifest_domain: bundle.manifest_domain,
    manifest_hash: bundle.manifest_hash,
  });
  bundle.manifest_signature = sign(
    null,
    Buffer.concat([MANIFEST_PREFIX, Buffer.from(material, "utf8")]),
    privateKey,
  ).toString("base64url");
  return bundle;
}

function render(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function read(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

const signer = deterministicKey("acme-security-ed25519-4");
const keySet = read(
  "docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/positive-active.json",
);
if (keySet.keys[0].public_key !== signer.publicKey) {
  throw new Error("receipt fixture signer drifted from the shared authority key-set fixture");
}
const snapshot = read(
  "docs/architecture/_meta/schemas/fixtures/authority-revocation-snapshot-v1/positive-current.json",
);
const minimal = read(
  "docs/architecture/_meta/schemas/fixtures/receipt-envelope-v1/positive-minimal.json",
);
const assured = read(
  "docs/architecture/_meta/schemas/fixtures/receipt-envelope-v1/positive-assured.json",
);
const receipts = [
  minimal,
  assured,
  {
    ...clone(minimal),
    receipt_id: "receipt://run-44/tool-execution-2",
    receipt_type: "tool_execution",
    receipt_profile_ref: "schema://ioi/receipts/tool-execution/v1",
    run_id: "run://44",
    actor_id: "runtime://worker-3",
    timestamp: "2026-07-16T12:10:00Z",
  },
  {
    ...clone(minimal),
    receipt_id: "receipt://run-45/validation-3",
    receipt_type: "validation",
    receipt_profile_ref: "schema://ioi/receipts/validation/v1",
    run_id: "run://45",
    actor_id: "system://acme-validator",
    timestamp: "2026-07-16T12:15:00Z",
  },
];

const receiptSchemaHash = schemaHash("receipt-envelope.v1.schema.json");
const checkpointSchemaHash = schemaHash("receipt-checkpoint.v1.schema.json");
const bundleSchemaHash = schemaHash("receipt-proof-bundle.v1.schema.json");
const receiptHashes = receipts.map(receiptBodyHash);
const leaves = receiptHashes.map((bodyHash, index) =>
  receiptLeafHash(bodyHash, receiptSchemaHash, index),
);
const emptyRoot = sha256(EMPTY_PREFIX);
const previousRoot = accumulate(leaves.slice(0, 2), emptyRoot);
const currentRoot = accumulate(leaves, emptyRoot);

const previousCheckpoint = signCheckpoint(
  {
    schema_version: "ioi.foundations.receipt-checkpoint.v1",
    checkpoint_type: "ioi.receipt-checkpoint",
    signature_domain: "ioi.receipt-checkpoint.v1",
    schema_hash: checkpointSchemaHash,
    checkpoint_id: "receipt-checkpoint://acme/audit-log/2",
    receipt_log_id: "receipt-log://acme/audit-log",
    accumulator_algorithm: "ioi.receipt-hash-chain-jcs-sha256.v1",
    receipt_body_hash_profile: "ioi.receipt-envelope-jcs-sha256.v1",
    receipt_contract_id: RECEIPT_CONTRACT_ID,
    receipt_schema_hash: receiptSchemaHash,
    accumulator_size: 2,
    accumulator_root: previousRoot,
    previous_checkpoint_ref: null,
    previous_checkpoint_hash: null,
    previous_accumulator_size: null,
    previous_accumulator_root: null,
    issuer_id: keySet.issuer_id,
    issuer_key_set_ref: keySet.key_set_id,
    issuer_key_set_version: keySet.version,
    issuer_key_id: keySet.keys[0].key_id,
    issued_at: 1784203240,
    build_identity_ref: "build://ioi/hypervisor-daemon/fixture-2026-07-16",
    policy_posture_ref: "policy://acme/receipt-checkpoint/default",
    body_hash: `sha256:${"0".repeat(64)}`,
    signature_suite: "ed25519",
    signature_key_id: keySet.keys[0].key_id,
    signature: "A".repeat(86),
  },
  signer.privateKey,
);

const currentCheckpoint = signCheckpoint(
  {
    ...clone(previousCheckpoint),
    checkpoint_id: "receipt-checkpoint://acme/audit-log/4",
    accumulator_size: 4,
    accumulator_root: currentRoot,
    previous_checkpoint_ref: previousCheckpoint.checkpoint_id,
    previous_checkpoint_hash: checkpointArtifactHash(previousCheckpoint),
    previous_accumulator_size: previousCheckpoint.accumulator_size,
    previous_accumulator_root: previousCheckpoint.accumulator_root,
    issued_at: 1784203300,
  },
  signer.privateKey,
);

const targetIndex = 1;
const bundle = {
  schema_version: "ioi.foundations.receipt-proof-bundle.v1",
  bundle_type: "ioi.receipt-proof-bundle",
  manifest_domain: "ioi.receipt-proof-bundle-manifest.v1",
  bundle_schema_hash: bundleSchemaHash,
  manifest_hash: `sha256:${"0".repeat(64)}`,
  manifest_signature_suite: "ed25519",
  manifest_signature_key_id: keySet.keys[0].key_id,
  manifest_signature: "A".repeat(86),
  bundle_id: "proof://acme/audit-log/4/receipt-1",
  receipt_contract_id: RECEIPT_CONTRACT_ID,
  receipt_schema_hash: receiptSchemaHash,
  receipt_body_hash_profile: "ioi.receipt-envelope-jcs-sha256.v1",
  receipt: receipts[targetIndex],
  receipt_body_hash: receiptHashes[targetIndex],
  leaf: {
    algorithm: "ioi.receipt-hash-chain-jcs-sha256.v1",
    domain: "ioi.receipt-accumulator-leaf.v1",
    leaf_index: targetIndex,
    leaf_hash: leaves[targetIndex],
  },
  inclusion_proof: {
    profile: "ioi.receipt-hash-chain-inclusion.v1",
    leaf_index: targetIndex,
    prefix_root: accumulate(leaves.slice(0, targetIndex), emptyRoot),
    suffix_leaf_hashes: leaves.slice(targetIndex + 1),
  },
  checkpoint: currentCheckpoint,
  previous_checkpoint: previousCheckpoint,
  consistency_proof: {
    profile: "ioi.receipt-hash-chain-consistency.v1",
    from_size: previousCheckpoint.accumulator_size,
    from_root: previousCheckpoint.accumulator_root,
    extension_leaf_hashes: leaves.slice(previousCheckpoint.accumulator_size),
  },
  trusted_input_refs: {
    key_set_ref: keySet.key_set_id,
    key_set_version: keySet.version,
    revocation_snapshot_ref: snapshot.snapshot_id,
    revocation_epoch: snapshot.epoch,
  },
  verification_instructions: {
    profile: "ioi.receipt-proof-verification.v1",
    steps: [
      "Validate registered closed schemas and schema hashes.",
      "Recompute the manifest and exact ReceiptEnvelope RFC 8785 JCS SHA-256 hashes.",
      "Recompute the indexed leaf and hash-chain inclusion root.",
      "Verify the current and previous checkpoint Ed25519 signatures against trusted local inputs.",
      "Recompute append-only consistency from the previous checkpoint root.",
    ],
    offline_required_inputs: [
      "trusted_key_set",
      "signed_revocation_snapshot",
      "trusted_time",
    ],
  },
};
signManifest(bundle, signer.privateKey);

const revokedSignerSnapshot = signSnapshot(
  {
    ...clone(snapshot),
    snapshot_id: "snapshot://acme/security/revocations/9-receipt-signer-revoked",
    epoch: 9,
    revoked_key_ids: [keySet.keys[0].key_id],
  },
  signer.privateKey,
);

const fixtureValues = new Map([
  ["receipt-checkpoint-v1/positive-previous.json", previousCheckpoint],
  ["receipt-checkpoint-v1/positive-current.json", currentCheckpoint],
  ["receipt-proof-bundle-v1/positive-offline.json", bundle],
  ["semantic/revoked-signer-snapshot.json", revokedSignerSnapshot],
]);

const wrongCheckpointDomain = clone(currentCheckpoint);
wrongCheckpointDomain.signature_domain = "ioi.authority-grant-envelope.v2";
fixtureValues.set("receipt-checkpoint-v1/negative-wrong-domain.json", wrongCheckpointDomain);

const staleCheckpointSchema = clone(currentCheckpoint);
staleCheckpointSchema.schema_hash = `sha256:${"f".repeat(64)}`;
fixtureValues.set("receipt-checkpoint-v1/negative-stale-schema-hash.json", staleCheckpointSchema);

const mismatchedCheckpointKey = clone(currentCheckpoint);
mismatchedCheckpointKey.signature_key_id = "key://acme/security/ed25519-99";
fixtureValues.set(
  "receipt-checkpoint-v1/negative-signature-key-mismatch.json",
  mismatchedCheckpointKey,
);

const wrongManifestDomain = clone(bundle);
wrongManifestDomain.manifest_domain = "ioi.authority-grant-envelope.v2";
fixtureValues.set("receipt-proof-bundle-v1/negative-wrong-domain.json", wrongManifestDomain);

const staleBundleSchema = clone(bundle);
staleBundleSchema.bundle_schema_hash = `sha256:${"f".repeat(64)}`;
fixtureValues.set("receipt-proof-bundle-v1/negative-stale-schema-hash.json", staleBundleSchema);

const mismatchedLeafIndex = clone(bundle);
mismatchedLeafIndex.inclusion_proof.leaf_index = 2;
fixtureValues.set(
  "receipt-proof-bundle-v1/negative-leaf-index-mismatch.json",
  mismatchedLeafIndex,
);

const mismatches = [];
for (const [relativePath, value] of fixtureValues) {
  const filePath = relativePath.startsWith("semantic/")
    ? path.join(semanticFixtureRoot, relativePath.slice("semantic/".length))
    : path.join(fixtureRoot, relativePath);
  const content = render(value);
  if (check) {
    if (!fs.existsSync(filePath) || fs.readFileSync(filePath, "utf8") !== content) {
      mismatches.push(path.relative(root, filePath));
    }
  } else {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
}

if (mismatches.length > 0) {
  console.error(`receipt proof fixtures are stale:\n${mismatches.join("\n")}`);
  process.exit(1);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      mode: check ? "check" : "write",
      fixtures: fixtureValues.size,
      accumulator: "ioi.receipt-hash-chain-jcs-sha256.v1",
      proof_complexity: "linear",
      cryptography: "ed25519",
      canonical_encoding: "RFC8785-JCS",
    },
    null,
    2,
  ),
);
