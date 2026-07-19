#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const fixtureRoot = "docs/architecture/_meta/schemas/fixtures";
const shared = [
  "--key-set",
  `${fixtureRoot}/authority-key-set-v1/positive-active.json`,
  "--revocation-snapshot",
  `${fixtureRoot}/authority-revocation-snapshot-v1/positive-current.json`,
  "--now",
  "1784203300",
  "--max-snapshot-staleness-seconds",
  "300",
];

function invoke(bundle) {
  return spawnSync(
    "cargo",
    [
      "run",
      "-q",
      "-p",
      "ioi-node",
      "--bin",
      "verify-receipt-proof",
      "--",
      "--bundle",
      bundle,
      ...shared,
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
}

const positive = invoke(`${fixtureRoot}/receipt-proof-bundle-v1/positive-offline.json`);
assert.equal(positive.status, 0, positive.stderr || positive.stdout);
const accepted = JSON.parse(positive.stdout.trim().split("\n").at(-1));
assert.equal(accepted.ok, true);
assert.equal(accepted.verification_mode, "offline_local_key_set");
assert.equal(accepted.accumulator_algorithm, "ioi.receipt-hash-chain-jcs-sha256.v1");

const negative = invoke(`${fixtureRoot}/receipt-proof-bundle-v1/negative-wrong-domain.json`);
assert.notEqual(negative.status, 0, "wrong-domain proof must fail closed");
const rejected = JSON.parse(negative.stdout.trim().split("\n").at(-1));
assert.equal(rejected.ok, false);
assert.equal(rejected.error.code, "structural");

console.log(
  JSON.stringify(
    {
      ok: true,
      cli: "verify-receipt-proof",
      positive_vector: "accepted",
      negative_wrong_domain_vector: "rejected",
      network_access: false,
    },
    null,
    2,
  ),
);
