#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const fixtureRoot = "docs/architecture/_meta/schemas/fixtures";
const rootGrant = `${fixtureRoot}/authority-grant-envelope-v2/positive-root.json`;
const childGrant = `${fixtureRoot}/authority-grant-envelope-v2/positive-attenuated-child.json`;
const issuerKeySet = `${fixtureRoot}/authority-key-set-v1/positive-active.json`;
const delegatorKeySet = `${fixtureRoot}/authority-key-set-v1/positive-delegator.json`;
const issuerSnapshot = `${fixtureRoot}/authority-revocation-snapshot-v1/positive-current.json`;
const delegatorSnapshot = `${fixtureRoot}/authority-revocation-snapshot-v1/positive-delegator-current.json`;

function invoke(args) {
  return spawnSync(
    "cargo",
    [
      "run",
      "-q",
      "-p",
      "ioi-node",
      "--bin",
      "verify-authority-grant",
      "--",
      ...args,
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
}

function parsed(result) {
  return JSON.parse(result.stdout.trim().split("\n").at(-1));
}

const common = [
  "--now",
  "1784203300",
  "--max-snapshot-staleness-seconds",
  "300",
];

const root = invoke([
  "--grant",
  rootGrant,
  "--key-set",
  issuerKeySet,
  "--revocation-snapshot",
  issuerSnapshot,
  "--audience",
  "runtime://acme/hypervisor/node-7",
  "--holder-id",
  "system://acme/delegator",
  "--holder-key-id",
  "key://acme/delegator/ed25519-1",
  ...common,
]);
assert.equal(root.status, 0, root.stderr || root.stdout);
assert.equal(parsed(root).ok, true);

const child = invoke([
  "--grant",
  childGrant,
  "--key-set",
  delegatorKeySet,
  "--revocation-snapshot",
  delegatorSnapshot,
  "--audience",
  "runtime://acme/hypervisor/node-7",
  "--holder-id",
  "worker://repo-auditor/read-only",
  "--holder-key-id",
  "key://acme/repo-auditor/worker-1",
  "--parent-grant",
  rootGrant,
  "--parent-key-set",
  issuerKeySet,
  "--parent-revocation-snapshot",
  issuerSnapshot,
  ...common,
]);
assert.equal(child.status, 0, child.stderr || child.stdout);
assert.equal(parsed(child).ok, true);

const wrongAudience = invoke([
  "--grant",
  rootGrant,
  "--key-set",
  issuerKeySet,
  "--revocation-snapshot",
  issuerSnapshot,
  "--audience",
  "runtime://acme/foreign/node-1",
  "--holder-id",
  "system://acme/delegator",
  "--holder-key-id",
  "key://acme/delegator/ed25519-1",
  ...common,
]);
assert.notEqual(wrongAudience.status, 0, "wrong-audience grant must fail closed");
const rejected = parsed(wrongAudience);
assert.equal(rejected.ok, false);
assert.equal(rejected.error.code, "audience");

console.log(
  JSON.stringify(
    {
      ok: true,
      cli: "verify-authority-grant",
      positive_root_vector: "accepted",
      positive_attenuated_child_vector: "accepted",
      negative_wrong_audience_vector: "rejected",
      network_access: false,
    },
    null,
    2,
  ),
);
