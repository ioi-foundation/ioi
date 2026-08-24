#!/usr/bin/env node
// Global, spend-free floor for the governed-effect boundary after the green T7 capstone.
//
// The paid real-evidence verifier remains owner-local because its inputs are deliberately not
// published. These four checks are self-contained and CI-runnable. This wrapper pins each child
// gate's semantic count as well as its exit status, so deleting a portable-bundle test, a planted
// bypass, or a C8 mutation is red instead of silently reducing what the global floor proves.

import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../../..");
const results = [];

const run = (args) => {
  const outcome = spawnSync("npm", args, { cwd: root, encoding: "utf8", env: process.env });
  if (outcome.stdout) process.stdout.write(outcome.stdout);
  if (outcome.stderr) process.stderr.write(outcome.stderr);
  return outcome;
};

const record = (name, pass, detail) => results.push({ name, pass: Boolean(pass), detail });
const lastJsonLine = (stdout) => {
  const line = String(stdout || "").trim().split("\n").reverse().find((candidate) => candidate.startsWith("{"));
  if (!line) return null;
  try { return JSON.parse(line); } catch { return null; }
};

const boundary = run(["run", "check:workload-bound-effect-boundary"]);
record(
  "workload-bound effect boundary completes its full spend-free fault matrix",
  boundary.status === 0
    && boundary.stdout.includes('"floor_status": "promoted_to_global_verifier_floor_after_green_t7"')
    && boundary.stdout.includes('"daemon_parent_death_terminates_monitor"'),
  `exit=${boundary.status}`,
);

const boundaryMutations = run(["run", "mutate:workload-bound-effect-boundary"]);
const plantedBypasses = (boundaryMutations.stdout.match(/"mutation":/gu) || []).length;
record(
  "workload-bound effect boundary rejects exactly five planted bypass classes",
  boundaryMutations.status === 0 && plantedBypasses === 5,
  `exit=${boundaryMutations.status} mutations=${plantedBypasses}`,
);

const portable = run(["run", "check:c8-v3-portable-bundle", "--workspace=@ioi/hypervisor-app"]);
const portableTotals = Object.fromEntries(
  [...portable.stdout.matchAll(/^# (tests|pass|fail) (\d+)$/gmu)].map((match) => [match[1], Number(match[2])]),
);
record(
  "C8 v3 portable-bundle suite executes exactly six passing tests",
  portable.status === 0 && portableTotals.tests === 6 && portableTotals.pass === 6 && portableTotals.fail === 0,
  `exit=${portable.status} tests=${portableTotals.tests} pass=${portableTotals.pass} fail=${portableTotals.fail}`,
);

const relyingParty = run(["run", "check:c8-v3-relying-party", "--workspace=@ioi/hypervisor-app"]);
const relyingPartyResult = lastJsonLine(relyingParty.stdout);
record(
  "C8 v3 relying party rejects exactly forty fully resealed semantic mutations",
  relyingParty.status === 0
    && relyingPartyResult?.ok === true
    && relyingPartyResult?.accepted_revision === 1
    && relyingPartyResult?.resealed_semantic_mutations_rejected === 40
    && Object.keys(relyingPartyResult?.rejection_codes || {}).length === 40,
  `exit=${relyingParty.status} mutations=${relyingPartyResult?.resealed_semantic_mutations_rejected}`,
);

const failures = results.filter((result) => !result.pass);
for (const result of results) {
  console.log(`${result.pass ? "PASS" : "FAIL"}  ${result.name} — ${result.detail}`);
}
emitVerifierCensus({ verifierId: "governed-effect-assurance", sourceUrl: import.meta.url, results });
process.exit(failures.length === 0 ? 0 : 1);
