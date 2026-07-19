import type {
  AuthorityKeySetV1,
  AuthorityRevocationSnapshotV1,
  ReceiptCheckpointV1,
  ReceiptProofBundleV1,
} from "./generated/architecture-contracts";
import {
  architectureContractSchemaHash,
  validateArchitectureContract,
} from "./generated/architecture-contracts";
import { canonicalizeJcs } from "./portable-authority-grant";

export const RECEIPT_ENVELOPE_V1_CONTRACT_ID =
  "schema://ioi/foundations/receipt-envelope/v1";
export const RECEIPT_CHECKPOINT_V1_CONTRACT_ID =
  "schema://ioi/foundations/receipt-checkpoint/v1";
export const RECEIPT_PROOF_BUNDLE_V1_CONTRACT_ID =
  "schema://ioi/foundations/receipt-proof-bundle/v1";
export const RECEIPT_CHECKPOINT_V1_SIGNING_PREFIX =
  "IOI-RECEIPT-CHECKPOINT-V1\0";
export const RECEIPT_PROOF_BUNDLE_V1_SIGNING_PREFIX =
  "IOI-RECEIPT-PROOF-BUNDLE-MANIFEST-V1\0";
const RECEIPT_LEAF_V1_PREFIX = "IOI-RECEIPT-ACCUMULATOR-LEAF-V1\0";
const RECEIPT_STEP_V1_PREFIX = "IOI-RECEIPT-ACCUMULATOR-STEP-V1\0";
const RECEIPT_EMPTY_V1_PREFIX = "IOI-RECEIPT-ACCUMULATOR-EMPTY-V1\0";
const REVOCATION_V1_SIGNING_PREFIX = "IOI-AUTHORITY-REVOCATION-SNAPSHOT-V1\0";
const AUTHORITY_KEY_SET_V1_CONTRACT_ID =
  "schema://ioi/foundations/authority-key-set/v1";
const AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT_ID =
  "schema://ioi/foundations/authority-revocation-snapshot/v1";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export type ReceiptProofVerificationCode =
  | "ok"
  | "structural"
  | "schema_hash"
  | "receipt_body_hash"
  | "leaf_hash"
  | "inclusion"
  | "checkpoint_hash"
  | "consistency"
  | "manifest_hash"
  | "signature"
  | "key_set"
  | "key_unknown"
  | "key_revoked"
  | "key_stale"
  | "snapshot_stale"
  | "trusted_input";

export type ReceiptProofVerificationResult =
  | { ok: true; code: "ok" }
  | {
      ok: false;
      code: Exclude<ReceiptProofVerificationCode, "ok">;
      detail: string;
    };

export type ReceiptProofVerificationInput = {
  bundle: ReceiptProofBundleV1;
  keySet: AuthorityKeySetV1;
  revocationSnapshot: AuthorityRevocationSnapshotV1;
  now: number;
  maxSnapshotStalenessSeconds: number;
};

function reject(
  code: Exclude<ReceiptProofVerificationCode, "ok">,
  detail: string,
): ReceiptProofVerificationResult {
  return { ok: false, code, detail };
}

function jcs(value: unknown): string {
  return canonicalizeJcs(value as Json);
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left, 0);
  output.set(right, left.length);
  return output;
}

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  const output = new ArrayBuffer(value.byteLength);
  new Uint8Array(output).set(value);
  return output;
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function sha256Bytes(value: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    ownedArrayBuffer(value),
  );
  return `sha256:${hex(digest)}`;
}

async function sha256Jcs(value: unknown): Promise<string> {
  return sha256Bytes(utf8(jcs(value)));
}

async function prefixedJcsHash(prefix: string, value: unknown): Promise<string> {
  return sha256Bytes(concat(utf8(prefix), utf8(jcs(value))));
}

function without(value: unknown, fields: readonly string[]): Json {
  const body = structuredClone(value) as Record<string, Json>;
  for (const field of fields) delete body[field];
  return body;
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.includes("=")) return null;
  try {
    const padded =
      value.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (value.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

async function verifyEd25519(
  publicKeyValue: string,
  signatureValue: string,
  message: Uint8Array,
): Promise<boolean> {
  const publicKey = decodeBase64Url(publicKeyValue);
  const signature = decodeBase64Url(signatureValue);
  if (!publicKey || publicKey.length !== 32 || !signature || signature.length !== 64) {
    return false;
  }
  try {
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      ownedArrayBuffer(publicKey),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await globalThis.crypto.subtle.verify(
      "Ed25519",
      key,
      ownedArrayBuffer(signature),
      ownedArrayBuffer(message),
    );
  } catch {
    return false;
  }
}

export async function receiptEnvelopeV1BodyHash(
  receipt: Record<string, unknown>,
): Promise<string> {
  return sha256Jcs(receipt);
}

export async function receiptAccumulatorV1LeafHash(
  receiptBodyHash: string,
  receiptSchemaHash: string,
  leafIndex: number,
): Promise<string> {
  return prefixedJcsHash(RECEIPT_LEAF_V1_PREFIX, {
    domain: "ioi.receipt-accumulator-leaf.v1",
    leaf_index: leafIndex,
    receipt_body_hash: receiptBodyHash,
    receipt_contract_id: RECEIPT_ENVELOPE_V1_CONTRACT_ID,
    receipt_schema_hash: receiptSchemaHash,
  });
}

export async function receiptAccumulatorV1EmptyRoot(): Promise<string> {
  return sha256Bytes(utf8(RECEIPT_EMPTY_V1_PREFIX));
}

export async function receiptAccumulatorV1Step(
  previousRoot: string,
  leafHash: string,
): Promise<string> {
  return prefixedJcsHash(RECEIPT_STEP_V1_PREFIX, {
    leaf_hash: leafHash,
    previous_root: previousRoot,
  });
}

async function accumulate(initialRoot: string, leaves: readonly string[]): Promise<string> {
  let root = initialRoot;
  for (const leaf of leaves) root = await receiptAccumulatorV1Step(root, leaf);
  return root;
}

async function checkpointBodyHash(checkpoint: ReceiptCheckpointV1): Promise<string> {
  return sha256Jcs(
    without(checkpoint, ["body_hash", "signature_suite", "signature_key_id", "signature"]),
  );
}

export async function receiptCheckpointV1ArtifactHash(
  checkpoint: ReceiptCheckpointV1,
): Promise<string> {
  return sha256Jcs(checkpoint);
}

export function receiptCheckpointV1SigningBytes(
  checkpoint: ReceiptCheckpointV1,
): Uint8Array {
  return concat(
    utf8(RECEIPT_CHECKPOINT_V1_SIGNING_PREFIX),
    utf8(
      jcs({
        accumulator_algorithm: checkpoint.accumulator_algorithm,
        accumulator_root: checkpoint.accumulator_root,
        accumulator_size: checkpoint.accumulator_size,
        body_hash: checkpoint.body_hash,
        schema_hash: checkpoint.schema_hash,
        signature_domain: checkpoint.signature_domain,
      }),
    ),
  );
}

function snapshotSigningBytes(snapshot: AuthorityRevocationSnapshotV1): Uint8Array {
  return concat(
    utf8(REVOCATION_V1_SIGNING_PREFIX),
    utf8(
      jcs({
        body_hash: snapshot.body_hash,
        signature_domain: snapshot.signature_domain,
      }),
    ),
  );
}

async function verifySnapshot(
  keySet: AuthorityKeySetV1,
  snapshot: AuthorityRevocationSnapshotV1,
  now: number,
  maxStaleness: number,
): Promise<ReceiptProofVerificationResult> {
  const keySetShape = validateArchitectureContract(
    AUTHORITY_KEY_SET_V1_CONTRACT_ID,
    keySet,
  );
  if (!keySetShape.ok) return reject("structural", keySetShape.errors.join("; "));
  const snapshotShape = validateArchitectureContract(
    AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT_ID,
    snapshot,
  );
  if (!snapshotShape.ok) return reject("structural", snapshotShape.errors.join("; "));
  if (
    snapshot.issuer_id !== keySet.issuer_id ||
    snapshot.issuer_key_set_ref !== keySet.key_set_id ||
    snapshot.issuer_key_set_version > keySet.version
  ) {
    return reject("key_set", "revocation snapshot does not bind the trusted key set");
  }
  if (keySet.issued_at > now || keySet.expires_at < now) {
    return reject("key_stale", "trusted issuer key set is outside its validity window");
  }
  if (
    snapshot.issued_at > now ||
    snapshot.expires_at < now ||
    now - snapshot.issued_at > maxStaleness
  ) {
    return reject("snapshot_stale", "revocation snapshot exceeds the freshness bound");
  }
  const expectedBodyHash = await sha256Jcs(
    without(snapshot, ["body_hash", "signature_suite", "signature_key_id", "signature"]),
  );
  if (expectedBodyHash !== snapshot.body_hash) {
    return reject("snapshot_stale", "revocation snapshot body hash mismatch");
  }
  const key = keySet.keys.find((candidate) => candidate.key_id === snapshot.signature_key_id);
  if (!key) return reject("key_unknown", "snapshot signing key is absent");
  if (key.status === "revoked") return reject("key_revoked", "snapshot key is revoked");
  if (snapshot.issued_at < key.not_before || snapshot.issued_at > key.expires_at) {
    return reject("key_stale", "snapshot signing key was invalid at issuance");
  }
  if (!(await verifyEd25519(key.public_key, snapshot.signature, snapshotSigningBytes(snapshot)))) {
    return reject("signature", "revocation snapshot signature is invalid");
  }
  return { ok: true, code: "ok" };
}

async function verifyCheckpoint(
  checkpoint: ReceiptCheckpointV1,
  input: ReceiptProofVerificationInput,
): Promise<ReceiptProofVerificationResult> {
  const shape = validateArchitectureContract(RECEIPT_CHECKPOINT_V1_CONTRACT_ID, checkpoint);
  if (!shape.ok) return reject("structural", shape.errors.join("; "));
  const expectedCheckpointSchema = architectureContractSchemaHash(
    RECEIPT_CHECKPOINT_V1_CONTRACT_ID,
  );
  const expectedReceiptSchema = architectureContractSchemaHash(
    RECEIPT_ENVELOPE_V1_CONTRACT_ID,
  );
  if (
    checkpoint.schema_hash !== expectedCheckpointSchema ||
    checkpoint.receipt_schema_hash !== expectedReceiptSchema
  ) {
    return reject("schema_hash", "checkpoint schema binding mismatch");
  }
  if ((await checkpointBodyHash(checkpoint)) !== checkpoint.body_hash) {
    return reject("checkpoint_hash", "checkpoint body hash mismatch");
  }
  const previousFields = [
    checkpoint.previous_checkpoint_ref,
    checkpoint.previous_checkpoint_hash,
    checkpoint.previous_accumulator_size,
    checkpoint.previous_accumulator_root,
  ];
  const present = previousFields.filter((value) => value !== null).length;
  if (present !== 0 && present !== previousFields.length) {
    return reject("consistency", "checkpoint predecessor tuple is partially populated");
  }
  const { keySet, revocationSnapshot, now, maxSnapshotStalenessSeconds } = input;
  if (
    checkpoint.signature_key_id !== checkpoint.issuer_key_id ||
    checkpoint.issuer_id !== keySet.issuer_id ||
    checkpoint.issuer_key_set_ref !== keySet.key_set_id ||
    checkpoint.issuer_key_set_version > keySet.version
  ) {
    return reject("key_set", "checkpoint issuer/key-set binding mismatch");
  }
  const snapshotResult = await verifySnapshot(
    keySet,
    revocationSnapshot,
    now,
    maxSnapshotStalenessSeconds,
  );
  if (!snapshotResult.ok) return snapshotResult;
  if (revocationSnapshot.revoked_key_ids.includes(checkpoint.signature_key_id)) {
    return reject("key_revoked", "checkpoint signing key is revoked");
  }
  const key = keySet.keys.find(
    (candidate) => candidate.key_id === checkpoint.signature_key_id,
  );
  if (!key) return reject("key_unknown", "checkpoint signing key is absent");
  if (key.status === "revoked") return reject("key_revoked", "checkpoint key is revoked");
  if (checkpoint.issued_at < key.not_before || checkpoint.issued_at > key.expires_at) {
    return reject("key_stale", "checkpoint key was invalid at issuance");
  }
  if (
    !(await verifyEd25519(
      key.public_key,
      checkpoint.signature,
      receiptCheckpointV1SigningBytes(checkpoint),
    ))
  ) {
    return reject("signature", "checkpoint signature is invalid");
  }
  return { ok: true, code: "ok" };
}

export async function verifyReceiptProofBundleV1(
  input: ReceiptProofVerificationInput,
): Promise<ReceiptProofVerificationResult> {
  const { bundle, keySet, revocationSnapshot } = input;
  const shape = validateArchitectureContract(RECEIPT_PROOF_BUNDLE_V1_CONTRACT_ID, bundle);
  if (!shape.ok) return reject("structural", shape.errors.join("; "));
  const expectedBundleSchema = architectureContractSchemaHash(
    RECEIPT_PROOF_BUNDLE_V1_CONTRACT_ID,
  );
  const expectedReceiptSchema = architectureContractSchemaHash(
    RECEIPT_ENVELOPE_V1_CONTRACT_ID,
  );
  if (
    bundle.bundle_schema_hash !== expectedBundleSchema ||
    bundle.receipt_schema_hash !== expectedReceiptSchema
  ) {
    return reject("schema_hash", "proof-bundle schema binding mismatch");
  }
  const receiptShape = validateArchitectureContract(
    RECEIPT_ENVELOPE_V1_CONTRACT_ID,
    bundle.receipt,
  );
  if (!receiptShape.ok) return reject("structural", receiptShape.errors.join("; "));
  if ((await receiptEnvelopeV1BodyHash(bundle.receipt)) !== bundle.receipt_body_hash) {
    return reject("receipt_body_hash", "exact ReceiptEnvelope JCS hash mismatch");
  }
  const expectedLeaf = await receiptAccumulatorV1LeafHash(
    bundle.receipt_body_hash,
    bundle.receipt_schema_hash,
    bundle.leaf.leaf_index,
  );
  if (expectedLeaf !== bundle.leaf.leaf_hash) {
    return reject("leaf_hash", "indexed receipt leaf hash mismatch");
  }
  const checkpoint = bundle.checkpoint as unknown as ReceiptCheckpointV1;
  if (checkpoint.receipt_schema_hash !== bundle.receipt_schema_hash) {
    return reject("schema_hash", "checkpoint and proof bind different receipt schemas");
  }
  if (bundle.leaf.leaf_index >= checkpoint.accumulator_size) {
    return reject("inclusion", "leaf index is outside the checkpoint accumulator");
  }
  const suffixLength = checkpoint.accumulator_size - bundle.leaf.leaf_index - 1;
  if (bundle.inclusion_proof.suffix_leaf_hashes.length !== suffixLength) {
    return reject("inclusion", "inclusion witness has the wrong suffix length");
  }
  let included = await receiptAccumulatorV1Step(
    bundle.inclusion_proof.prefix_root,
    bundle.leaf.leaf_hash,
  );
  included = await accumulate(included, bundle.inclusion_proof.suffix_leaf_hashes);
  if (included !== checkpoint.accumulator_root) {
    return reject("inclusion", "inclusion witness does not produce the signed root");
  }
  const checkpointResult = await verifyCheckpoint(checkpoint, input);
  if (!checkpointResult.ok) return checkpointResult;

  const previous = bundle.previous_checkpoint as unknown as ReceiptCheckpointV1 | null;
  if (previous) {
    const previousResult = await verifyCheckpoint(previous, input);
    if (!previousResult.ok) return previousResult;
    const previousHash = await receiptCheckpointV1ArtifactHash(previous);
    if (
      checkpoint.previous_checkpoint_ref !== previous.checkpoint_id ||
      checkpoint.previous_checkpoint_hash !== previousHash ||
      checkpoint.previous_accumulator_size !== previous.accumulator_size ||
      checkpoint.previous_accumulator_root !== previous.accumulator_root ||
      checkpoint.receipt_log_id !== previous.receipt_log_id ||
      previous.accumulator_size >= checkpoint.accumulator_size
    ) {
      return reject("consistency", "current checkpoint does not bind the predecessor");
    }
    if (
      bundle.consistency_proof.from_size !== previous.accumulator_size ||
      bundle.consistency_proof.from_root !== previous.accumulator_root
    ) {
      return reject("consistency", "consistency witness does not start at predecessor");
    }
  } else if (
    checkpoint.previous_checkpoint_ref !== null ||
    checkpoint.previous_checkpoint_hash !== null ||
    checkpoint.previous_accumulator_size !== null ||
    checkpoint.previous_accumulator_root !== null ||
    bundle.consistency_proof.from_size !== 0 ||
    bundle.consistency_proof.from_root !== (await receiptAccumulatorV1EmptyRoot())
  ) {
    return reject("consistency", "genesis proof has a predecessor or non-empty root");
  }
  const extensionLength =
    checkpoint.accumulator_size - bundle.consistency_proof.from_size;
  if (
    extensionLength < 0 ||
    bundle.consistency_proof.extension_leaf_hashes.length !== extensionLength
  ) {
    return reject("consistency", "append-only witness has the wrong extension length");
  }
  const consistent = await accumulate(
    bundle.consistency_proof.from_root,
    bundle.consistency_proof.extension_leaf_hashes,
  );
  if (consistent !== checkpoint.accumulator_root) {
    return reject("consistency", "append-only witness does not produce current root");
  }
  if (
    bundle.trusted_input_refs.key_set_ref !== keySet.key_set_id ||
    bundle.trusted_input_refs.key_set_version > keySet.version ||
    bundle.trusted_input_refs.revocation_snapshot_ref !== revocationSnapshot.snapshot_id ||
    bundle.trusted_input_refs.revocation_epoch !== revocationSnapshot.epoch
  ) {
    return reject("trusted_input", "manifest does not bind supplied trusted inputs");
  }
  const manifestHash = await sha256Jcs(
    without(bundle, [
      "manifest_hash",
      "manifest_signature_suite",
      "manifest_signature_key_id",
      "manifest_signature",
    ]),
  );
  if (manifestHash !== bundle.manifest_hash) {
    return reject("manifest_hash", "proof export manifest hash mismatch");
  }
  if (bundle.manifest_signature_key_id !== checkpoint.signature_key_id) {
    return reject("key_set", "manifest and checkpoint signer differ");
  }
  const manifestKey = keySet.keys.find(
    (candidate) => candidate.key_id === bundle.manifest_signature_key_id,
  );
  if (!manifestKey) return reject("key_unknown", "manifest signing key is absent");
  const manifestMaterial = {
    bundle_schema_hash: bundle.bundle_schema_hash,
    manifest_domain: bundle.manifest_domain,
    manifest_hash: bundle.manifest_hash,
  };
  if (
    !(await verifyEd25519(
      manifestKey.public_key,
      bundle.manifest_signature,
      concat(
        utf8(RECEIPT_PROOF_BUNDLE_V1_SIGNING_PREFIX),
        utf8(jcs(manifestMaterial)),
      ),
    ))
  ) {
    return reject("signature", "proof export manifest signature is invalid");
  }
  return { ok: true, code: "ok" };
}
