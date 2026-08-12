// check-verifier-floors — the CI floor the verifier family never had.
//
// THE HOLE THIS CLOSES (filed by an independent peer during next-legs V): a verifier that asserts
// less still passes. Fourteen journey/cockpit verifiers gated CI, and deleting assertions from any
// of them was SILENTLY GREEN — the deleted assertion simply stopped being checked, the remaining
// ones passed, and CI reported success. Nothing anywhere compared how much a verifier proved today
// against how much it proved yesterday.
//
// WHAT THIS GATE ASSERTS
//   1. Closed world, derived from CI itself. Every `npm run check:*` the hypervisor workspace runs
//      in .github/workflows/ci.yml that resolves to a `verify-*.mjs` script MUST carry a row here —
//      a pinned floor, or an explicit typed exclusion with a reason. A new CI-gated verifier with
//      no row is RED. The world is not a hand-maintained list that can silently omit a verifier;
//      it is re-derived from the workflow file on every run.
//   2. The reverse edge. A pinned floor whose verifier is NOT invoked by CI is RED. A floor on a
//      verifier that gates nothing is decorative, and decorative assertions are the class of defect
//      this program keeps finding.
//   3. RUNTIME counts, never source greps. The count comes from the verifier's own completed run
//      (see lib/verifier-census.mjs). A commented-out `ok(...)` does not execute, so it does not
//      count — which is the whole point. A grep would have counted it.
//   4. Exact pins, ratcheting up only. Below the pin means assertions were deleted. ABOVE the pin
//      is also RED: the floor is stale and must be raised in the same commit that adds the
//      assertions. Exact pinning is what stops a later deletion from hiding under a slack floor.
//      (Same idiom as the rule-H census in audit-admission-evidence-provenance.mjs.)
//   5. Fail closed on absent evidence. A missing census directory, a missing artifact, or an
//      artifact whose source digest disagrees with the file on disk is RED, never "skip". A
//      verifier that crashed, exited early, or was BLOCKED emits no census — and this gate reports
//      that absence rather than passing over it. A false green from a broken probe is the same
//      defect class as a false green from a missing assertion.
//
// WHAT IT DOES NOT ASSERT. A floor counts assertions; it cannot judge them. Nothing here certifies
// that an assertion is meaningful, non-decorative, or that a replaced assertion is as strong as the
// one it replaced. The names digest travels with the count so a reviewer can see "replaced" versus
// "renamed", but the reading is a human's. This gate proves only that the family did not shrink.
//
// Usage:
//   IOI_VERIFIER_CENSUS_DIR=.artifacts/verifier-census npm run check:<each verifier>
//   npm run check:verifier-floors --workspace=@ioi/hypervisor-app
//
// Exit: 0 pass · 1 fail.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const MANIFEST = path.join(APP, "verifier-floors.v1.json");
const CI = path.join(ROOT, ".github", "workflows", "ci.yml");
const PKG = path.join(APP, "package.json");

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

const failures = [];
const notes = [];
const fail = (code, detail) => failures.push({ code, detail });

// ------------------------------------------------------------------ inputs
const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
const pkg = JSON.parse(fs.readFileSync(PKG, "utf8"));
const ciText = fs.readFileSync(CI, "utf8");

const censusDir = process.env.IOI_VERIFIER_CENSUS_DIR
  ? path.resolve(ROOT, process.env.IOI_VERIFIER_CENSUS_DIR)
  : null;

// ------------------------------------------------------------------ closed world, derived from CI
// Every hypervisor-workspace check CI runs. Re-derived here rather than listed, so a verifier
// cannot join or leave CI without this gate noticing.
const ciChecks = new Set(
  [...ciText.matchAll(/npm run (check:[A-Za-z0-9:_-]+) --workspace=@ioi\/hypervisor-app/g)].map((m) => m[1]),
);

// A CI check counts as a verifier when its npm script runs a verify-*.mjs file. Non-verifier checks
// (bundlers, generators) are outside this gate's subject.
const ciVerifierScripts = new Map();
for (const check of ciChecks) {
  const cmd = pkg.scripts?.[check];
  if (!cmd) {
    fail("ci_invokes_unknown_script", `${check} is run by ci.yml but is not a script in apps/hypervisor/package.json`);
    continue;
  }
  const m = cmd.match(/(scripts\/verify-[A-Za-z0-9._-]+\.mjs)/);
  if (m) ciVerifierScripts.set(check, m[1]);
}

const rows = new Map();
for (const row of manifest.verifiers ?? []) rows.set(row.npm_script, row);
const excluded = new Map();
for (const row of manifest.excluded ?? []) excluded.set(row.npm_script, row);

// (1) every CI-gated verifier carries a row
for (const [check, script] of ciVerifierScripts) {
  if (rows.has(check)) continue;
  if (excluded.has(check)) {
    const ex = excluded.get(check);
    if (!ex.reason || String(ex.reason).trim().length < 24) {
      fail("exclusion_without_reason", `${check} is excluded with no substantive reason`);
    }
    continue;
  }
  fail(
    "unregistered_ci_verifier",
    `${check} (${script}) gates CI but carries no floor row and no typed exclusion in verifier-floors.v1.json`,
  );
}

// (2) the reverse edge — a floor on a verifier CI does not run proves nothing
for (const [check] of rows) {
  if (!ciVerifierScripts.has(check)) {
    fail(
      "floor_not_ci_gated",
      `${check} carries a pinned floor but ci.yml does not run it in the hypervisor workspace — the floor gates nothing`,
    );
  }
}
for (const [check] of excluded) {
  if (!ciVerifierScripts.has(check)) {
    fail("exclusion_not_ci_gated", `${check} is excluded but ci.yml does not run it — delete the stale exclusion row`);
  }
}

// ------------------------------------------------------------------ (3)(4)(5) runtime counts
if (!censusDir) {
  fail(
    "census_dir_unset",
    "IOI_VERIFIER_CENSUS_DIR is unset. This gate reads RUNTIME assertion counts emitted by completed " +
      "verifier runs; with no census directory there is no evidence, and absent evidence is RED, not skip.",
  );
} else if (!fs.existsSync(censusDir)) {
  fail("census_dir_missing", `census directory ${path.relative(ROOT, censusDir)} does not exist — no verifier run emitted evidence`);
}

const seenArtifacts = new Set();

if (censusDir && fs.existsSync(censusDir)) {
  for (const row of manifest.verifiers ?? []) {
    const artifact = path.join(censusDir, `${row.id}.json`);
    if (!fs.existsSync(artifact)) {
      fail(
        "census_missing",
        `${row.npm_script}: no runtime census at ${path.relative(ROOT, artifact)} — the verifier did not complete a run ` +
          "(crashed, exited early, or was BLOCKED). A floor cannot be certified from an absent run.",
      );
      continue;
    }
    seenArtifacts.add(`${row.id}.json`);

    let census;
    try {
      census = JSON.parse(fs.readFileSync(artifact, "utf8"));
    } catch (error) {
      fail("census_unreadable", `${row.npm_script}: ${error.message}`);
      continue;
    }

    if (census.census_version !== "ioi.verifier-census.v1") {
      fail("census_version_unknown", `${row.npm_script}: census_version ${census.census_version}`);
      continue;
    }
    if (census.verifier_id !== row.id) {
      fail("census_id_mismatch", `${row.npm_script}: artifact declares verifier_id ${census.verifier_id}, row is ${row.id}`);
      continue;
    }

    // the census may only certify the exact revision it ran against
    const sourceAbs = path.resolve(ROOT, row.source);
    if (!fs.existsSync(sourceAbs)) {
      fail("source_missing", `${row.npm_script}: ${row.source} does not exist`);
      continue;
    }
    const onDisk = sha256(fs.readFileSync(sourceAbs));
    if (census.source_sha256 !== onDisk) {
      fail(
        "census_stale",
        `${row.npm_script}: census was emitted against source sha256:${String(census.source_sha256).slice(0, 12)} but ` +
          `${row.source} is now sha256:${onDisk.slice(0, 12)} — re-run the verifier; a census never certifies a revision it did not run.`,
      );
      continue;
    }
    if (census.source_path !== row.source) {
      fail("census_path_mismatch", `${row.npm_script}: census source_path ${census.source_path} != row source ${row.source}`);
      continue;
    }

    const executed = census.executed_assertions;
    if (!Number.isInteger(executed) || executed < 0) {
      fail("census_count_invalid", `${row.npm_script}: executed_assertions is ${JSON.stringify(executed)}`);
      continue;
    }

    if (executed < row.runtime_assertions) {
      fail(
        "assertions_deleted",
        `${row.npm_script}: executed ${executed} runtime assertions, floor pins ${row.runtime_assertions} ` +
          `(${row.runtime_assertions - executed} fewer). This is the finding this gate exists for: a verifier that ` +
          "asserts less still passes. Restore the assertions, or state in the PR why the family may shrink.",
      );
    } else if (executed > row.runtime_assertions) {
      fail(
        "floor_stale",
        `${row.npm_script}: executed ${executed} runtime assertions but the floor pins ${row.runtime_assertions}. ` +
          "Raise the pin to the observed count IN THE SAME COMMIT that adds the assertions — a slack floor is where a " +
          "later deletion hides.",
      );
    }

    if (census.assertion_names_sha256 && row.assertion_names_sha256 && census.assertion_names_sha256 !== row.assertion_names_sha256) {
      notes.push(
        `${row.npm_script}: assertion set changed at the same count (names sha256 ${String(row.assertion_names_sha256).slice(0, 12)} -> ` +
          `${String(census.assertion_names_sha256).slice(0, 12)}) — assertions were replaced or renamed, not added. Read the diff.`,
      );
    }
  }

  // An artifact with no row is a verifier emitting census outside the closed world.
  for (const file of fs.readdirSync(censusDir)) {
    if (!file.endsWith(".json") || seenArtifacts.has(file)) continue;
    fail("census_outside_world", `${file} was emitted but matches no floor row in verifier-floors.v1.json`);
  }
}

// ------------------------------------------------------------------ report
const registered = (manifest.verifiers ?? []).length;
const pinnedTotal = (manifest.verifiers ?? []).reduce((n, r) => n + r.runtime_assertions, 0);

for (const note of notes) console.log(`NOTE  ${note}`);

if (failures.length) {
  for (const f of failures) console.error(`FAIL  [${f.code}] ${f.detail}`);
  console.error(`\nverifier-floors FAIL — ${failures.length} failure(s) across ${registered} pinned verifier(s)`);
  process.exit(1);
}

console.log(
  `verifier-floors OK — ${registered} CI-gated verifier(s) pinned at ${pinnedTotal} runtime assertions, ` +
    `${excluded.size} typed exclusion(s), closed world re-derived from ci.yml (${ciVerifierScripts.size} verifier check(s) run there).`,
);
process.exit(0);
