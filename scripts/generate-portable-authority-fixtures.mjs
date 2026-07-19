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
const semanticFixtureRoot = path.join(root, "tests", "fixtures", "portable-authority");
const check = process.argv.includes("--check");

const GRANT_PREFIX = Buffer.from("IOI-AUTHORITY-GRANT-ENVELOPE-V2\0", "utf8");
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

function unsigned(value) {
  const body = clone(value);
  delete body.body_hash;
  delete body.signature_suite;
  delete body.signature_key_id;
  delete body.signature;
  return body;
}

function signGrant(grant, privateKey) {
  grant.body_hash = sha256(canonicalJson(unsigned(grant)));
  const material = canonicalJson({
    body_hash: grant.body_hash,
    schema_hash: grant.schema_hash,
    signature_domain: grant.signature_domain,
  });
  grant.signature = sign(
    null,
    Buffer.concat([GRANT_PREFIX, Buffer.from(material, "utf8")]),
    privateKey,
  ).toString("base64url");
  return grant;
}

function signSnapshot(snapshot, privateKey) {
  snapshot.body_hash = sha256(canonicalJson(unsigned(snapshot)));
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

function render(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const issuerKey = deterministicKey("acme-security-ed25519-4");
const delegatorKey = deterministicKey("acme-delegator-ed25519-1");
const grantSchemaHash = schemaHash("authority-grant-envelope.v2.schema.json");

const issuerKeySet = {
  schema_version: "ioi.foundations.authority-key-set.v1",
  key_set_type: "ioi.authority-key-set",
  key_set_id: "keyset://acme/security/4",
  issuer_id: "wallet://acme/security",
  version: 4,
  issued_at: 1784116800,
  expires_at: 1815652800,
  keys: [
    {
      key_id: "key://acme/security/ed25519-4",
      signature_suite: "ed25519",
      public_key: issuerKey.publicKey,
      not_before: 1784116800,
      expires_at: 1815652800,
      status: "active",
    },
  ],
};

const delegatorKeySet = {
  schema_version: "ioi.foundations.authority-key-set.v1",
  key_set_type: "ioi.authority-key-set",
  key_set_id: "keyset://acme/delegator/1",
  issuer_id: "system://acme/delegator",
  version: 1,
  issued_at: 1784116800,
  expires_at: 1815652800,
  keys: [
    {
      key_id: "key://acme/delegator/ed25519-1",
      signature_suite: "ed25519",
      public_key: delegatorKey.publicKey,
      not_before: 1784116800,
      expires_at: 1815652800,
      status: "active",
    },
  ],
};

const rootGrant = signGrant(
  {
    schema_version: "ioi.foundations.authority-grant-envelope.v2",
    envelope_type: "ioi.authority-grant",
    signature_domain: "ioi.authority-grant-envelope.v2",
    schema_hash: grantSchemaHash,
    authority_grant_id: "grant://acme/repo-auditor/2",
    request_id: "authority-request://acme/repo-auditor/2",
    issuer_id: issuerKeySet.issuer_id,
    issuer_key_set_ref: issuerKeySet.key_set_id,
    issuer_key_set_version: issuerKeySet.version,
    issuer_key_id: issuerKeySet.keys[0].key_id,
    holder_id: delegatorKeySet.issuer_id,
    holder_key_id: delegatorKeySet.keys[0].key_id,
    audience: "runtime://acme/hypervisor/node-7",
    issued_at: 1784203200,
    not_before: 1784203200,
    expires_at: 1784289600,
    parent_grant: null,
    authority_scopes: ["scope:repo.read", "scope:repo.write"],
    primitive_capability_constraints: ["prim:fs.read", "prim:fs.write"],
    resources: [
      "agentgres://project/hypervisor/source",
      "agentgres://project/hypervisor/source/src",
    ],
    attenuating_caveats: [],
    risk_restrictions: {
      allowed_risk_classes: ["read", "draft"],
      max_budget_microusd: 10000000,
      max_calls: 100,
      approval_required_for: ["secret_export"],
    },
    revocation_epoch: 7,
    body_hash: `sha256:${"0".repeat(64)}`,
    signature_suite: "ed25519",
    signature_key_id: issuerKeySet.keys[0].key_id,
    signature: "A".repeat(86),
  },
  issuerKey.privateKey,
);

const childGrant = signGrant(
  {
    schema_version: "ioi.foundations.authority-grant-envelope.v2",
    envelope_type: "ioi.authority-grant",
    signature_domain: "ioi.authority-grant-envelope.v2",
    schema_hash: grantSchemaHash,
    authority_grant_id: "grant://acme/repo-auditor/2/child/1",
    request_id: "authority-request://acme/repo-auditor/2/child/1",
    issuer_id: rootGrant.holder_id,
    issuer_key_set_ref: delegatorKeySet.key_set_id,
    issuer_key_set_version: delegatorKeySet.version,
    issuer_key_id: rootGrant.holder_key_id,
    holder_id: "worker://repo-auditor/read-only",
    holder_key_id: "key://acme/repo-auditor/worker-1",
    audience: rootGrant.audience,
    issued_at: 1784203260,
    not_before: 1784203260,
    expires_at: 1784210400,
    parent_grant: {
      grant_ref: rootGrant.authority_grant_id,
      body_hash: rootGrant.body_hash,
      proof_ref: "proof://acme/repo-auditor/2/child/1",
    },
    authority_scopes: ["scope:repo.read"],
    primitive_capability_constraints: ["prim:fs.read"],
    resources: ["agentgres://project/hypervisor/source/src"],
    attenuating_caveats: ["caveat://acme/read-only"],
    risk_restrictions: {
      allowed_risk_classes: ["read"],
      max_budget_microusd: 1000000,
      max_calls: 10,
      approval_required_for: ["secret_export", "external_message"],
    },
    revocation_epoch: 8,
    body_hash: `sha256:${"0".repeat(64)}`,
    signature_suite: "ed25519",
    signature_key_id: delegatorKeySet.keys[0].key_id,
    signature: "A".repeat(86),
  },
  delegatorKey.privateKey,
);

const issuerSnapshot = signSnapshot(
  {
    schema_version: "ioi.foundations.authority-revocation-snapshot.v1",
    snapshot_type: "ioi.authority-revocation-snapshot",
    snapshot_id: "snapshot://acme/security/revocations/8",
    issuer_id: issuerKeySet.issuer_id,
    issuer_key_set_ref: issuerKeySet.key_set_id,
    issuer_key_set_version: issuerKeySet.version,
    epoch: 8,
    issued_at: 1784203200,
    expires_at: 1784203500,
    revoked_grant_refs: ["grant://acme/retired/1"],
    revoked_key_ids: ["key://acme/security/ed25519-3"],
    body_hash: `sha256:${"0".repeat(64)}`,
    signature_domain: "ioi.authority-revocation-snapshot.v1",
    signature_suite: "ed25519",
    signature_key_id: issuerKeySet.keys[0].key_id,
    signature: "A".repeat(86),
  },
  issuerKey.privateKey,
);

const delegatorSnapshot = signSnapshot(
  {
    ...clone(issuerSnapshot),
    snapshot_id: "snapshot://acme/delegator/revocations/8",
    issuer_id: delegatorKeySet.issuer_id,
    issuer_key_set_ref: delegatorKeySet.key_set_id,
    issuer_key_set_version: delegatorKeySet.version,
    revoked_grant_refs: [],
    revoked_key_ids: [],
    signature_key_id: delegatorKeySet.keys[0].key_id,
  },
  delegatorKey.privateKey,
);

const revokedRootSnapshot = signSnapshot(
  {
    ...clone(issuerSnapshot),
    snapshot_id: "snapshot://acme/security/revocations/9-root-revoked",
    epoch: 9,
    revoked_grant_refs: [rootGrant.authority_grant_id],
  },
  issuerKey.privateKey,
);

const widenedChild = clone(childGrant);
widenedChild.authority_scopes.push("scope:repo.admin");
signGrant(widenedChild, delegatorKey.privateKey);

const fixtureValues = new Map([
  ["authority-grant-envelope-v2/positive-root.json", rootGrant],
  ["authority-grant-envelope-v2/positive-attenuated-child.json", childGrant],
  ["semantic/adversarial-widened-child.json", widenedChild],
  ["authority-key-set-v1/positive-active.json", issuerKeySet],
  ["authority-key-set-v1/positive-delegator.json", delegatorKeySet],
  ["authority-revocation-snapshot-v1/positive-current.json", issuerSnapshot],
  ["authority-revocation-snapshot-v1/positive-delegator-current.json", delegatorSnapshot],
  ["semantic/adversarial-revoked-root.json", revokedRootSnapshot],
]);

const emptyCapabilities = clone(rootGrant);
emptyCapabilities.authority_scopes = [];
emptyCapabilities.primitive_capability_constraints = [];
fixtureValues.set("authority-grant-envelope-v2/negative-empty-capabilities.json", emptyCapabilities);

const mismatchedKey = clone(rootGrant);
mismatchedKey.signature_key_id = "key://acme/security/ed25519-99";
fixtureValues.set("authority-grant-envelope-v2/negative-signature-key-mismatch.json", mismatchedKey);

const staleSchema = clone(rootGrant);
staleSchema.schema_hash = `sha256:${"f".repeat(64)}`;
fixtureValues.set("authority-grant-envelope-v2/negative-stale-schema-hash.json", staleSchema);

const paddedSignature = clone(rootGrant);
paddedSignature.signature = `${paddedSignature.signature}==`;
fixtureValues.set("authority-grant-envelope-v2/negative-padded-signature.json", paddedSignature);

const paddedPublicKey = clone(issuerKeySet);
paddedPublicKey.keys[0].public_key = `${paddedPublicKey.keys[0].public_key}=`;
fixtureValues.set("authority-key-set-v1/negative-padded-public-key.json", paddedPublicKey);

const emptyKeyWindow = clone(issuerKeySet);
emptyKeyWindow.expires_at = emptyKeyWindow.issued_at;
fixtureValues.set("authority-key-set-v1/negative-empty-validity-window.json", emptyKeyWindow);

const wrongSnapshotDomain = clone(issuerSnapshot);
wrongSnapshotDomain.signature_domain = "ioi.authority-grant-envelope.v2";
fixtureValues.set("authority-revocation-snapshot-v1/negative-wrong-domain.json", wrongSnapshotDomain);

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
  console.error(`portable authority fixtures are stale:\n${mismatches.join("\n")}`);
  process.exit(1);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      mode: check ? "check" : "write",
      fixtures: fixtureValues.size,
      cryptography: "ed25519",
      canonical_encoding: "RFC8785-JCS",
    },
    null,
    2,
  ),
);
