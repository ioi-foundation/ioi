#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { writeLiteralExitLog } from "../internal-docs/implementation/tools/lib/literal-exit.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const artifactRel = "internal-docs/implementation/evidence/M9/m0-owner-ratification-derived-census-successor.v1.json";
const outRel = "internal-docs/implementation/evidence/M9/m0-owner-ratification-derived-census-successor.exit.v1.txt";
const checks = [
  ["source-disposition-reproduction", "node", ["internal-docs/implementation/tools/check-source-dispositions.mjs"]],
  ["canonical-enum-census-reproduction", "node", ["internal-docs/implementation/tools/enum-member-census.mjs", "--check"]],
];
const results = checks.map(([id, command, args]) => {
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8" });
  return {
    id,
    command: `${command} ${args.join(" ")}`,
    status: result.status ?? 1,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim(),
  };
});
const artifact = {
  evidence_format: "ioi.program.derived_census_successor.v1",
  claim_boundary: "Mechanical reproduction of the source-disposition and canonical-enum generated censuses after the owner-ratified authority transaction. It does not review route classifications, certify product truth, or replace the independent M0 review epoch.",
  results,
  passed: results.every((result) => result.status === 0),
};
mkdirSync(dirname(join(root, artifactRel)), { recursive: true });
writeFileSync(join(root, artifactRel), `${JSON.stringify(artifact, null, 2)}\n`);
if (artifact.passed) {
  writeLiteralExitLog({
    bar: "m0-owner-ratification-derived-census-successor",
    literal: "M0_OWNER_RATIFICATION_DERIVED_CENSUS_SUCCESSOR_EXIT=0",
    artifactRel,
    outRel,
    nonclaim: "This closes only the two generated-census stale bindings; it does not attest the M0 route/final-invoker review lock or close any Hypervisor App primary-attach hold.",
  });
}
process.stdout.write(`owner-ratification derived census successor: ${artifact.passed ? "PASS" : "FAIL"}\n`);
process.exitCode = artifact.passed ? 0 : 1;
