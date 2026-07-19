import {
  architectureContractSchemaHash,
  validateArchitectureContract,
  type AuthorityGrantEnvelopeV2,
  type AuthorityKeySetV1,
  type AuthorityRevocationSnapshotV1,
} from "./generated/architecture-contracts";

export const AUTHORITY_GRANT_V2_CONTRACT_ID =
  "schema://ioi/foundations/authority-grant-envelope/v2";
export const AUTHORITY_KEY_SET_V1_CONTRACT_ID =
  "schema://ioi/foundations/authority-key-set/v1";
export const AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT_ID =
  "schema://ioi/foundations/authority-revocation-snapshot/v1";
export const AUTHORITY_GRANT_V2_SIGNING_PREFIX =
  "IOI-AUTHORITY-GRANT-ENVELOPE-V2\0";
export const AUTHORITY_REVOCATION_V1_SIGNING_PREFIX =
  "IOI-AUTHORITY-REVOCATION-SNAPSHOT-V1\0";

export type PortableAuthorityVerificationCode =
  | "ok"
  | "structural"
  | "schema_hash"
  | "body_hash"
  | "signature"
  | "signature_domain"
  | "signature_key"
  | "key_set"
  | "key_revoked"
  | "audience"
  | "holder"
  | "time"
  | "revocation"
  | "revocation_snapshot_stale"
  | "parent_required"
  | "parent_link"
  | "parent_attenuation"
  | "parent_cycle";

export type PortableAuthorityVerificationResult =
  | { ok: true; code: "ok" }
  | { ok: false; code: Exclude<PortableAuthorityVerificationCode, "ok">; detail: string };

export type PortableAuthorityParentProof = {
  grant: AuthorityGrantEnvelopeV2;
  keySet: AuthorityKeySetV1;
  revocationSnapshot: AuthorityRevocationSnapshotV1;
  parent?: PortableAuthorityParentProof;
};

export type PortableAuthorityVerificationInput = {
  grant: AuthorityGrantEnvelopeV2;
  keySet: AuthorityKeySetV1;
  revocationSnapshot: AuthorityRevocationSnapshotV1;
  expectedAudience: string;
  expectedHolderId: string;
  expectedHolderKeyId: string;
  now: number;
  maxSnapshotStalenessSeconds: number;
  parent?: PortableAuthorityParentProof;
};

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function reject(
  code: Exclude<PortableAuthorityVerificationCode, "ok">,
  detail: string,
): PortableAuthorityVerificationResult {
  return { ok: false, code, detail };
}

/** RFC 8785 JSON Canonicalization Scheme serialization for JSON-domain values. */
export function canonicalizeJcs(value: Json): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JCS rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJcs(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalizeJcs(value[key])}`)
    .join(",")}}`;
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
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Jcs(value: Json): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    ownedArrayBuffer(utf8(canonicalizeJcs(value))),
  );
  return `sha256:${hex(digest)}`;
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.includes("=")) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function unsignedGrantBody(grant: AuthorityGrantEnvelopeV2): Json {
  const body = structuredClone(grant) as unknown as Record<string, Json>;
  delete body.body_hash;
  delete body.signature_suite;
  delete body.signature_key_id;
  delete body.signature;
  return body;
}

function unsignedSnapshotBody(snapshot: AuthorityRevocationSnapshotV1): Json {
  const body = structuredClone(snapshot) as unknown as Record<string, Json>;
  delete body.body_hash;
  delete body.signature_suite;
  delete body.signature_key_id;
  delete body.signature;
  return body;
}

export function authorityGrantV2SigningBytes(grant: AuthorityGrantEnvelopeV2): Uint8Array {
  const material: Json = {
    body_hash: grant.body_hash,
    schema_hash: grant.schema_hash,
    signature_domain: grant.signature_domain as Json,
  };
  return concat(utf8(AUTHORITY_GRANT_V2_SIGNING_PREFIX), utf8(canonicalizeJcs(material)));
}

export function authorityRevocationV1SigningBytes(
  snapshot: AuthorityRevocationSnapshotV1,
): Uint8Array {
  const material: Json = {
    body_hash: snapshot.body_hash,
    signature_domain: snapshot.signature_domain as Json,
  };
  return concat(utf8(AUTHORITY_REVOCATION_V1_SIGNING_PREFIX), utf8(canonicalizeJcs(material)));
}

async function verifyEd25519(
  publicKeyValue: string,
  signatureValue: string,
  message: Uint8Array,
): Promise<boolean> {
  const publicKey = decodeBase64Url(publicKeyValue);
  const signature = decodeBase64Url(signatureValue);
  if (!publicKey || publicKey.length !== 32 || !signature || signature.length !== 64) return false;
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

function keyFor(
  keySet: AuthorityKeySetV1,
  keyId: string,
  at: number,
): AuthorityKeySetV1["keys"][number] | null {
  const key = keySet.keys.find((candidate) => candidate.key_id === keyId);
  if (!key || key.signature_suite !== "ed25519" || key.status === "revoked") return null;
  return key.not_before <= at && at <= key.expires_at ? key : null;
}

function isSubset(child: readonly string[], parent: readonly string[]): boolean {
  const allowed = new Set(parent);
  return child.every((value) => allowed.has(value));
}

function isSuperset(child: readonly string[], parent: readonly string[]): boolean {
  return isSubset(parent, child);
}

function attenuationError(
  child: AuthorityGrantEnvelopeV2,
  parent: AuthorityGrantEnvelopeV2,
): string | null {
  if (child.issuer_id !== parent.holder_id || child.issuer_key_id !== parent.holder_key_id) {
    return "child issuer must be the parent holder";
  }
  if (!isSubset(child.authority_scopes, parent.authority_scopes)) return "child widens authority scopes";
  if (!isSubset(child.primitive_capability_constraints, parent.primitive_capability_constraints)) {
    return "child widens primitive capabilities";
  }
  if (!isSubset(child.resources, parent.resources)) return "child widens resources";
  if (!isSubset(child.risk_restrictions.allowed_risk_classes, parent.risk_restrictions.allowed_risk_classes)) {
    return "child widens risk classes";
  }
  if (!isSuperset(child.attenuating_caveats, parent.attenuating_caveats)) {
    return "child drops an attenuating caveat";
  }
  if (!isSuperset(child.risk_restrictions.approval_required_for, parent.risk_restrictions.approval_required_for)) {
    return "child drops an approval requirement";
  }
  if (child.risk_restrictions.max_budget_microusd > parent.risk_restrictions.max_budget_microusd) {
    return "child widens budget";
  }
  if (child.risk_restrictions.max_calls > parent.risk_restrictions.max_calls) return "child widens calls";
  if (child.not_before < parent.not_before || child.expires_at > parent.expires_at) {
    return "child widens the validity interval";
  }
  if (child.revocation_epoch < parent.revocation_epoch) return "child uses an older revocation epoch";
  return null;
}

async function verifySnapshot(
  snapshot: AuthorityRevocationSnapshotV1,
  keySet: AuthorityKeySetV1,
  now: number,
  maxStaleness: number,
): Promise<PortableAuthorityVerificationResult> {
  const structure = validateArchitectureContract(AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT_ID, snapshot);
  if (!structure.ok) return reject("structural", structure.errors.join("; "));
  if (snapshot.signature_domain !== "ioi.authority-revocation-snapshot.v1") {
    return reject("signature_domain", "unexpected revocation signature domain");
  }
  if (snapshot.issuer_id !== keySet.issuer_id || snapshot.issuer_key_set_ref !== keySet.key_set_id) {
    return reject("key_set", "revocation snapshot issuer/key-set mismatch");
  }
  if (snapshot.issuer_key_set_version > keySet.version) {
    return reject("key_set", "revocation snapshot requires a newer key set");
  }
  if (snapshot.issued_at > now || snapshot.expires_at < now || now - snapshot.issued_at > maxStaleness) {
    return reject("revocation_snapshot_stale", "revocation snapshot is not fresh at verification time");
  }
  if ((await sha256Jcs(unsignedSnapshotBody(snapshot))) !== snapshot.body_hash) {
    return reject("body_hash", "revocation snapshot body hash mismatch");
  }
  const key = keyFor(keySet, snapshot.signature_key_id, snapshot.issued_at);
  if (!key) return reject("signature_key", "revocation signing key is absent, invalid, or revoked");
  if (!(await verifyEd25519(key.public_key, snapshot.signature, authorityRevocationV1SigningBytes(snapshot)))) {
    return reject("signature", "revocation snapshot signature verification failed");
  }
  return { ok: true, code: "ok" };
}

async function verifyInternal(
  input: PortableAuthorityVerificationInput,
  seen: Set<string>,
): Promise<PortableAuthorityVerificationResult> {
  const { grant, keySet, revocationSnapshot } = input;
  if (seen.has(grant.authority_grant_id)) return reject("parent_cycle", "grant delegation cycle detected");
  seen.add(grant.authority_grant_id);

  const structure = validateArchitectureContract(AUTHORITY_GRANT_V2_CONTRACT_ID, grant);
  if (!structure.ok) return reject("structural", structure.errors.join("; "));
  if (grant.signature_domain !== "ioi.authority-grant-envelope.v2") {
    return reject("signature_domain", "unexpected authority-grant signature domain");
  }
  if (grant.schema_hash !== architectureContractSchemaHash(AUTHORITY_GRANT_V2_CONTRACT_ID)) {
    return reject("schema_hash", "authority-grant schema hash mismatch");
  }
  if ((await sha256Jcs(unsignedGrantBody(grant))) !== grant.body_hash) {
    return reject("body_hash", "authority-grant body hash mismatch");
  }
  if (grant.signature_key_id !== grant.issuer_key_id) {
    return reject("signature_key", "signature key must equal issuer key");
  }
  if (grant.audience !== input.expectedAudience) return reject("audience", "grant audience mismatch");
  if (grant.holder_id !== input.expectedHolderId || grant.holder_key_id !== input.expectedHolderKeyId) {
    return reject("holder", "grant holder binding mismatch");
  }
  if (
    grant.issued_at > grant.not_before ||
    grant.not_before >= grant.expires_at ||
    input.now < grant.not_before ||
    input.now > grant.expires_at
  ) {
    return reject("time", "grant is not active at verification time");
  }
  if (
    keySet.key_set_type !== "ioi.authority-key-set" ||
    keySet.issuer_id !== grant.issuer_id ||
    keySet.key_set_id !== grant.issuer_key_set_ref ||
    keySet.version < grant.issuer_key_set_version ||
    keySet.issued_at > input.now ||
    keySet.expires_at < input.now
  ) {
    return reject("key_set", "issuer key set is missing, stale, or mismatched");
  }
  const signingKey = keyFor(keySet, grant.signature_key_id, grant.issued_at);
  if (!signingKey) return reject("signature_key", "issuer signing key is absent, invalid, or revoked");

  const snapshotResult = await verifySnapshot(
    revocationSnapshot,
    keySet,
    input.now,
    input.maxSnapshotStalenessSeconds,
  );
  if (!snapshotResult.ok) return snapshotResult;
  if (revocationSnapshot.epoch < grant.revocation_epoch) {
    return reject("revocation_snapshot_stale", "revocation snapshot predates the grant epoch");
  }
  if (revocationSnapshot.revoked_grant_refs.includes(grant.authority_grant_id)) {
    return reject("revocation", "grant is revoked");
  }
  if (revocationSnapshot.revoked_key_ids.includes(grant.signature_key_id)) {
    return reject("key_revoked", "grant signing key is revoked");
  }
  if (!(await verifyEd25519(signingKey.public_key, grant.signature, authorityGrantV2SigningBytes(grant)))) {
    return reject("signature", "authority-grant signature verification failed");
  }

  if (grant.parent_grant === null) {
    if (input.parent) return reject("parent_link", "root grant supplied an unexpected parent proof");
  } else {
    if (!input.parent) return reject("parent_required", "delegated grant requires its parent proof");
    const parentResult = await verifyInternal(
      {
        grant: input.parent.grant,
        keySet: input.parent.keySet,
        revocationSnapshot: input.parent.revocationSnapshot,
        expectedAudience: grant.audience,
        expectedHolderId: grant.issuer_id,
        expectedHolderKeyId: grant.issuer_key_id,
        now: input.now,
        maxSnapshotStalenessSeconds: input.maxSnapshotStalenessSeconds,
        parent: input.parent.parent,
      },
      seen,
    );
    if (!parentResult.ok) return parentResult;
    if (
      grant.parent_grant.grant_ref !== input.parent.grant.authority_grant_id ||
      grant.parent_grant.body_hash !== input.parent.grant.body_hash
    ) {
      return reject("parent_link", "parent reference/body hash does not bind the supplied parent");
    }
    const attenuation = attenuationError(grant, input.parent.grant);
    if (attenuation) return reject("parent_attenuation", attenuation);
  }
  return { ok: true, code: "ok" };
}

/** Verifies one portable v2 grant against locally resolved trusted key/revocation inputs. */
export async function verifyPortableAuthorityGrantV2(
  input: PortableAuthorityVerificationInput,
): Promise<PortableAuthorityVerificationResult> {
  if (!Number.isSafeInteger(input.now) || !Number.isSafeInteger(input.maxSnapshotStalenessSeconds)) {
    return reject("time", "verification time and snapshot bound must be safe integers");
  }
  return verifyInternal(input, new Set());
}
