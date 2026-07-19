import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import type {
  AuthorityGrantEnvelopeV2,
  AuthorityKeySetV1,
  AuthorityRevocationSnapshotV1,
} from "./generated/architecture-contracts";
import {
  type PortableAuthorityVerificationInput,
  verifyPortableAuthorityGrantV2,
} from "./portable-authority-grant";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const fixtureRoot = path.join(repoRoot, "docs/architecture/_meta/schemas/fixtures");
const semanticFixtureRoot = path.join(repoRoot, "tests/fixtures/portable-authority");
const NOW = 1_784_203_300;

function fixture<T>(relativePath: string): T {
  return JSON.parse(fs.readFileSync(path.join(fixtureRoot, relativePath), "utf8")) as T;
}

const rootGrant = () =>
  fixture<AuthorityGrantEnvelopeV2>("authority-grant-envelope-v2/positive-root.json");
const childGrant = () =>
  fixture<AuthorityGrantEnvelopeV2>(
    "authority-grant-envelope-v2/positive-attenuated-child.json",
  );
const widenedChild = () =>
  JSON.parse(
    fs.readFileSync(path.join(semanticFixtureRoot, "adversarial-widened-child.json"), "utf8"),
  ) as AuthorityGrantEnvelopeV2;
const issuerKeys = () =>
  fixture<AuthorityKeySetV1>("authority-key-set-v1/positive-active.json");
const delegatorKeys = () =>
  fixture<AuthorityKeySetV1>("authority-key-set-v1/positive-delegator.json");
const issuerSnapshot = () =>
  fixture<AuthorityRevocationSnapshotV1>(
    "authority-revocation-snapshot-v1/positive-current.json",
  );
const delegatorSnapshot = () =>
  fixture<AuthorityRevocationSnapshotV1>(
    "authority-revocation-snapshot-v1/positive-delegator-current.json",
  );
const revokedRootSnapshot = () =>
  JSON.parse(
    fs.readFileSync(path.join(semanticFixtureRoot, "adversarial-revoked-root.json"), "utf8"),
  ) as AuthorityRevocationSnapshotV1;

function rootInput(overrides: Partial<PortableAuthorityVerificationInput> = {}) {
  const grant = overrides.grant ?? rootGrant();
  return {
    grant,
    keySet: issuerKeys(),
    revocationSnapshot: issuerSnapshot(),
    expectedAudience: grant.audience,
    expectedHolderId: grant.holder_id,
    expectedHolderKeyId: grant.holder_key_id,
    now: NOW,
    maxSnapshotStalenessSeconds: 300,
    ...overrides,
  } satisfies PortableAuthorityVerificationInput;
}

function childInput(grant = childGrant()): PortableAuthorityVerificationInput {
  return {
    grant,
    keySet: delegatorKeys(),
    revocationSnapshot: delegatorSnapshot(),
    expectedAudience: grant.audience,
    expectedHolderId: grant.holder_id,
    expectedHolderKeyId: grant.holder_key_id,
    now: NOW,
    maxSnapshotStalenessSeconds: 300,
    parent: {
      grant: rootGrant(),
      keySet: issuerKeys(),
      revocationSnapshot: issuerSnapshot(),
    },
  };
}

async function assertRejected(
  input: PortableAuthorityVerificationInput,
  expectedCode: string,
) {
  const result = await verifyPortableAuthorityGrantV2(input);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, expectedCode);
}

test("portable authority golden root and attenuated child verify offline", async () => {
  assert.deepEqual(await verifyPortableAuthorityGrantV2(rootInput()), { ok: true, code: "ok" });
  assert.deepEqual(await verifyPortableAuthorityGrantV2(childInput()), { ok: true, code: "ok" });
});

test("payload, type, domain, and version mutations fail closed", async () => {
  const payload = rootGrant();
  payload.resources[0] = "agentgres://project/foreign/source";
  await assertRejected(rootInput({ grant: payload }), "body_hash");

  const envelopeType = rootGrant();
  envelopeType.envelope_type = "ioi.receipt";
  await assertRejected(rootInput({ grant: envelopeType }), "structural");

  const domain = rootGrant();
  domain.signature_domain = "ioi.authority-revocation-snapshot.v1";
  await assertRejected(rootInput({ grant: domain }), "structural");

  const version = rootGrant();
  version.schema_version = "ioi.foundations.authority-grant-envelope.v1";
  await assertRejected(rootInput({ grant: version }), "structural");
});

test("audience, holder, key, expiry, and not-before bindings fail closed", async () => {
  await assertRejected(
    rootInput({ expectedAudience: "runtime://acme/foreign/node-1" }),
    "audience",
  );
  await assertRejected(rootInput({ expectedHolderId: "system://acme/foreign" }), "holder");
  await assertRejected(
    rootInput({ expectedHolderKeyId: "key://acme/delegator/foreign" }),
    "holder",
  );

  const missingKey = issuerKeys();
  missingKey.keys[0].key_id = "key://acme/security/missing";
  await assertRejected(rootInput({ keySet: missingKey }), "signature_key");

  const grant = rootGrant();
  await assertRejected(rootInput({ grant, now: grant.not_before - 1 }), "time");
  await assertRejected(rootInput({ grant, now: grant.expires_at + 1 }), "time");
});

test("revocation, stale snapshots, and cryptographically valid child widening fail closed", async () => {
  await assertRejected(
    rootInput({ revocationSnapshot: revokedRootSnapshot() }),
    "revocation",
  );
  const snapshot = issuerSnapshot();
  await assertRejected(
    rootInput({ revocationSnapshot: snapshot, now: snapshot.expires_at + 1 }),
    "revocation_snapshot_stale",
  );
  await assertRejected(childInput(widenedChild()), "parent_attenuation");
});
