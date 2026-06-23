import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { sortedUniqueStrings, uniqueStrings } from "./strings.ts";

const DIR = "packages/hypervisor-workbench/src/runtime/harness-workflow";
const coreSource = readFileSync(`${DIR}/core.ts`, "utf8");
const proofBlockersSource = readFileSync(`${DIR}/proof-blockers.ts`, "utf8");

test("uniqueStrings dedupes and drops empty/nullish values", () => {
  assert.deepEqual(uniqueStrings(["a", "a", "", null, undefined, "b"]), [
    "a",
    "b",
  ]);
  assert.deepEqual(uniqueStrings([]), []);
});

test("sortedUniqueStrings returns sorted unique non-empty values", () => {
  assert.deepEqual(sortedUniqueStrings(["c", "a", "a", "", "b"]), [
    "a",
    "b",
    "c",
  ]);
});

test("proof-blocker validators are owned by the proof-blockers leaf", () => {
  assert.ok(
    proofBlockersSource.includes(
      "export function workflowHarnessActivationIdGateClickProofBlockers",
    ),
    "proof-blockers must own the activation-id gate validator",
  );
  assert.ok(
    proofBlockersSource.includes(
      "export function workflowHarnessPackageImportActivationApplyProofBlockers",
    ),
    "proof-blockers must own the package-import apply validator",
  );
});

test("core.ts delegates the validators to the leaf but preserves the public API", () => {
  // core no longer defines the validators in-file...
  assert.ok(
    !coreSource.includes(
      "export function workflowHarnessActivationIdGateClickProofBlockers",
    ),
    "core must not redefine the activation-id gate validator",
  );
  // ...it imports/re-exports them from the leaf for API stability.
  assert.ok(
    coreSource.includes('from "./proof-blockers"'),
    "core must source the validators from ./proof-blockers",
  );
  // pure string helpers are sourced from the strings leaf, not redefined.
  assert.ok(
    coreSource.includes('from "./strings"'),
    "core must source string helpers from ./strings",
  );
  assert.ok(
    !coreSource.includes("function uniqueStrings("),
    "core must not redefine uniqueStrings",
  );
});
