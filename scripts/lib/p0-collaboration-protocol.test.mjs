import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  MANIFEST_PATH,
  PROTOCOL_PATH,
  validateManifest,
  validateProtocol,
} from "./p0-collaboration-protocol.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const protocolBytes = fs.readFileSync(path.join(repoRoot, PROTOCOL_PATH));
const protocol = JSON.parse(protocolBytes);
const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, MANIFEST_PATH), "utf8"));

const clone = () => structuredClone(protocol);

test("frozen P0 protocol and byte manifest validate without activating a cohort", () => {
  assert.equal(validateProtocol(clone()).status, "frozen_not_activated");
  assert.equal(validateManifest(structuredClone(manifest), protocolBytes).cohort_executed, false);
});

test("activation and observed results fail closed", () => {
  const activated = clone();
  activated.activation.activated = true;
  assert.throws(() => validateProtocol(activated), /activation posture/);
  const observed = clone();
  observed.observed_results = [];
  assert.throws(() => validateProtocol(observed), /observed-result fields/);
});

test("F-N and D-R topology drift fails closed", () => {
  const variableN = clone();
  variableN.arms[1].fixed_n_implementers = 3;
  assert.throws(() => validateProtocol(variableN), /fixed two-implementer/);
  const ambientRoom = clone();
  ambientRoom.arms[2].bounds.max_attempts_per_claim = 2;
  assert.throws(() => validateProtocol(ambientRoom), /bounded topology/);
});

test("guardrail or claim widening fails closed", () => {
  const deletedFailure = clone();
  delete deletedFailure.guardrails.failure;
  assert.throws(() => validateProtocol(deletedFailure), /guardrail census/);
  const widened = clone();
  widened.analysis_plan.claim_ceiling = "general_superiority";
  assert.throws(() => validateProtocol(widened), /claim ceiling/);
});

test("manifest detects any protocol-byte change", () => {
  const changedBytes = Buffer.concat([protocolBytes, Buffer.from("\n")]);
  assert.throws(
    () => validateManifest(structuredClone(manifest), changedBytes),
    /exact protocol bytes/,
  );
});
