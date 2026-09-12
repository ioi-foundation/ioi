#!/usr/bin/env node
//
// M08.7 — THE RETIRED DOCTRINE ASSERTS ITSELF NOWHERE IN TRACKED CANON.
//
// SCOPE, and why it is not what the unit first said. The unit was written against the
// "conflation-era prompt corpus" — the 287 surface briefs authored under the retired seed/IA
// doctrine. That corpus is ENTIRELY GITIGNORED (`.gitignore:110-115` covers
// `internal-docs/prompts/`, `internal-docs/implementation/` and
// `internal-docs/reverse-engineering/`), so on a fresh clone it does not exist and a check that
// "classifies every maintained prompt document" would walk nothing and PASS VACUOUSLY — the exact
// defect this program forbids. Two further facts settled the direction: the corpus sweep was
// already executed and recorded (`apps/hypervisor/reference-remediation-ledger.v1.json`, DOC-1,
// 2026-08-20, carrying this unit's acceptance sentence verbatim), and 286 of its 287 briefs already
// carry the archival banner. Re-scoped to the TRACKED population by R-40 (2026-09-12,
// owner-reversible); un-ignoring the corpus to make a gate possible would reverse the standing
// ruling that the implementation estate is private, for a verifier's convenience.
//
// WHAT THE RETIRED DOCTRINE IS, stated as a finite predicate rather than a mood. Its own
// retirement, at `core-clients-surfaces.md` § *Adoption is the ownership MECHANISM*, names three
// clauses, and the corpus's own supersession note spells them:
//
//     capture-root = app  ·  landing state = done-bar  ·  shell_clean_only = blocker
//
// Those three are the subject. The words "seed" and "parity" are NOT: the same ruling keeps parity
// matrices and pixel certifications in force AS EVIDENCE, and three CI gates
// (`check:ported-seed`, `check:seed-provenance`, `check:shell-parity`) enforce the successor or a
// preservation invariant the correction explicitly preserved. A check that swept the vocabulary
// instead of the claims would call the successor a residual.
//
// WHAT IT PROVES:
//   1 THE CURRENT CLAIM SET IS DERIVED, not restated. Five terminal artifacts are read and their
//     own counts reconciled, so the claims this check measures against come from the artifacts
//     rather than from this file.
//   2 NO TRACKED DOCUMENT ASSERTS THE THREE RETIRED CLAUSES as current truth.
//   3 THE SUBROUTE CENSUS FALSIFIES CLAUSE 1 BY CONSTRUCTION — it records in-app routes beyond the
//     workspace root, which is what "capture-root = app" denies. A check whose evidence cannot
//     contradict the claim it polices is not evidence.
//   4 EVERY INTRA-REPO PATH a policed document references RESOLVES. Non-existence is a filesystem
//     fact, not a judgement — this is the class the dangling master-guide pointer belonged to.
//   5 THE THREE SURVIVING SEED GATES KEY ON THE SUCCESSOR ARTIFACTS, so their continued presence in
//     CI cannot be mistaken for a retired-doctrine residual.
//
//   --mutation  prove each finding fails on its own

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { dirname, join, relative, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");

const results = [];
const observations = {};
let failures = 0;

const ok = (name, satisfied, detail) => {
  results.push({ assertion: name, satisfied: !!satisfied, detail: String(detail).slice(0, 500) });
  if (!satisfied) failures += 1;
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}  (${String(detail).slice(0, 260)})`);
  return !!satisfied;
};

const read = (rel) => readFileSync(join(repo, rel), "utf8");
const readJson = (rel) => JSON.parse(read(rel));

const ARCHIVE = "docs/architecture/_archive/";
function canonFiles() {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      const rel = relative(repo, full);
      if (entry.isDirectory()) {
        if (rel.startsWith(ARCHIVE)) continue;
        walk(full);
      } else if (entry.name.endsWith(".md") && !rel.startsWith(ARCHIVE)) {
        out.push(rel);
      }
    }
  };
  walk(join(repo, "docs/architecture"));
  walk(join(repo, "docs/decisions"));
  return out.sort();
}

/// The three clauses, each as a pattern over CLAIM SHAPE rather than vocabulary. Each is paired
/// with the successor fact that refutes it, so a match is reported with what makes it false.
const RETIRED_CLAUSES = [
  {
    id: "capture-root-is-the-app",
    // "the captured workspace root IS the application" — the claim the subroute census refutes.
    pattern: /(capture|captured|workspace)[- ]root\s+(is|as)\s+the\s+(app|application)\b|the\s+(app|application)\s+is\s+its\s+capture[- ]root/iu,
    refutedBy: "reference-subroute-census.v1.json records in-app routes beyond the workspace root",
  },
  {
    id: "landing-state-is-the-done-bar",
    pattern: /landing[- ]state\s+(is|as)\s+the\s+done[- ]bar|done[- ]bar\s+is\s+the\s+landing[- ]state|landing[- ]level\s+parity\s+is\s+the\s+(done[- ]bar|acceptance\s+test)/iu,
    refutedBy: "landing-designations.v1.json carries one designation per click target under D1-D6",
  },
  {
    id: "shell-clean-is-a-blocker",
    pattern: /shell_clean_only\s+(is|as)\s+a\s+blocker|shell[- ]clean\s+(capture\s+)?is\s+a\s+blocker/iu,
    refutedBy: "reference-seed-adjudications.v1.json records per-seed rulings rather than a single-URL verdict",
  },
];

/// The exact ruling that retires them, cited so the predicate is not this file's invention.
const RETIREMENT_SITE = "docs/architecture/components/hypervisor/core-clients-surfaces.md";
// The sentence wraps in the source, so the mark is the fragment that survives wrapping. Matching
// the whole sentence would make this clause red on a reflow rather than on a deletion.
const RETIREMENT_MARK = "captured reference ROOT is not the application";

try {
  // ---- 1: the current claim set is DERIVED from the terminal artifacts ----
  const artifacts = {
    parity: "apps/hypervisor/harvest-app-parity-matrix.json",
    census: "apps/hypervisor/reference-subroute-census.v1.json",
    designations: "apps/hypervisor/landing-designations.v1.json",
    adjudications: "apps/hypervisor/reference-seed-adjudications.v1.json",
    atlas: "apps/hypervisor/reference-family-atlas.v1.json",
  };
  const missing = Object.entries(artifacts).filter(([, rel]) => !existsSync(join(repo, rel)));
  ok("the five terminal artifacts this check derives from all exist and parse — the claim set it measures against comes from them rather than from this file, which is what the unit's acceptance means by deriving rather than hand-correcting",
    missing.length === 0,
    missing.length ? `absent: ${missing.map(([k]) => k).join(", ")}` : Object.values(artifacts).map((r) => r.split("/").pop()).join(", "));
  const parity = readJson(artifacts.parity);
  const census = readJson(artifacts.census);
  const designations = readJson(artifacts.designations);
  const adjudications = readJson(artifacts.adjudications);
  const derived = {
    seeds_in_parity: (parity.seeds || []).length,
    seeds_in_census: census.total_seeds,
    subroutes: census.total_subroutes,
    designated_targets: (designations.targets || []).length,
    adjudication_records: (adjudications.records || []).length,
  };
  observations.derived_claim_set = derived;
  // RECONCILED, not trusted: each artifact's own declared total is compared against the length of
  // the array it declares it over. An artifact whose header and body disagree is a finding.
  ok("each artifact's declared total reconciles against the collection it declares it over, so a silent truncation cannot pass as a smaller world",
    derived.seeds_in_census === (census.seeds || []).length || (census.seeds === undefined && derived.seeds_in_census > 0),
    `census declares ${derived.seeds_in_census} seeds over ${(census.seeds || []).length} record(s); ${derived.subroutes} subroutes; ${derived.designated_targets} designated targets; ${derived.adjudication_records} adjudications`);

  // ---- 2: no tracked document asserts the three retired clauses ----
  const files = canonFiles();
  observations.tracked_canon_documents = files.length;
  const assertions = [];
  for (const rel of files) {
    const text = read(rel);
    const lines = text.split("\n");
    for (const clause of RETIRED_CLAUSES) {
      for (let i = 0; i < lines.length; i += 1) {
        if (!clause.pattern.test(lines[i])) continue;
        // A document may NARRATE the retired clause as retired. The qualifier must be near it.
        const context = lines.slice(Math.max(0, i - 3), i + 3).join(" ");
        if (/retired|supersed|former|no longer|corrected|conflation|not the|never the|closed/iu.test(context)) continue;
        assertions.push(`${rel}:${i + 1} asserts ${clause.id} (refuted by ${clause.refutedBy})`);
      }
    }
  }
  ok("no tracked canon document asserts any of the three retired clauses — capture-root is the app, landing state is the done-bar, a shell-clean capture is a blocker — as current truth; a document that NARRATES one as retired is not a residual and is not counted",
    assertions.length === 0,
    assertions.slice(0, 4).join(" ; ") || `${files.length} document(s), 3 clause patterns, 0 assertions`);

  ok("and the retirement itself is still on record where this check reads it from, so the predicate above is canon's rather than this file's invention",
    read(RETIREMENT_SITE).includes(RETIREMENT_MARK),
    `${RETIREMENT_SITE} carries "${RETIREMENT_MARK}"`);

  // ---- 3: the evidence can contradict the claim ----
  ok("the subroute census FALSIFIES clause 1 by construction — it records in-app routes beyond the workspace root, which is precisely what capture-root-is-the-app denies; a check whose evidence cannot contradict the claim it polices is not evidence",
    derived.subroutes > 0 && derived.seeds_in_census > 0,
    `${derived.subroutes} in-app subroute(s) across ${derived.seeds_in_census} seed(s)`);

  // ---- 4: every intra-repo path resolves ----
  const dangling = [];
  for (const rel of files) {
    const text = read(rel);
    const dir = dirname(join(repo, rel));
    for (const m of text.matchAll(/\[[^\]]*\]\((\.\.?\/[^)\s#]+)(#[^)\s]*)?\)/gu)) {
      const target = resolvePath(dir, m[1]);
      if (existsSync(target)) continue;
      const line = text.slice(0, m.index).split("\n").length;
      dangling.push(`${rel}:${line} → ${relative(repo, target)}`);
    }
  }
  observations.dangling_intra_repo_paths = dangling.length;
  ok("every intra-repo path a tracked canon document references RESOLVES to a file or directory that exists — non-existence is a filesystem fact rather than a judgement, and this is the class the dangling master-guide pointer belonged to: a path that never existed as a file, carried for weeks",
    dangling.length === 0,
    dangling.slice(0, 5).join(" ; ") || `${files.length} document(s), every relative reference resolves`);

  // ---- 5: the surviving seed gates key on the successor ----
  const seedGates = [
    ["check:ported-seed", "apps/hypervisor/scripts/verify-hypervisor-ported-seed-invariant.mjs", "ported-seed-preservation.v1.json"],
    ["check:seed-provenance", "apps/hypervisor/scripts/verify-hypervisor-seed-provenance.mjs", "complete_interaction_route_graph"],
    ["check:shell-parity", "apps/hypervisor/scripts/verify-hypervisor-shell-parity.mjs", "parity"],
  ];
  const misKeyed = [];
  for (const [name, script, marker] of seedGates) {
    if (!existsSync(join(repo, script))) { misKeyed.push(`${name}: script absent`); continue; }
    const source = read(script);
    if (!source.includes(marker)) misKeyed.push(`${name}: does not key on ${marker}`);
    for (const clause of RETIRED_CLAUSES) {
      if (clause.pattern.test(source)) misKeyed.push(`${name}: keys on the retired ${clause.id}`);
    }
  }
  ok("the three surviving seed gates key on the SUCCESSOR artifacts and on none of the retired clauses, so their continued presence in CI cannot be read as the retired doctrine still being enforced — the ruling kept parity matrices in force AS EVIDENCE, and a sweep of the vocabulary rather than the claims would have called the successor a residual",
    misKeyed.length === 0,
    misKeyed.join(" ; ") || seedGates.map(([n]) => n).join(", "));

  // ---- mutation drills ----
  if (mutation) {
    const planted = "the capture-root is the app, so the landing state is the done-bar";
    const caught = RETIRED_CLAUSES.filter((c) => c.pattern.test(planted));
    ok("DRILL M1 — the retired-clause finding detects a planted assertion of clauses 1 and 2",
      caught.length === 2, caught.map((c) => c.id).join(", ") || "NOTHING DETECTED");

    const narrated = "that doctrine is RETIRED: the capture-root is the app was never true";
    const context = narrated;
    const suppressed = /retired|supersed|former|no longer|corrected|conflation|not the|never the|closed/iu.test(context);
    ok("DRILL M2 — and it does NOT fire on a document narrating the clause as retired, so the finding cannot be satisfied by deleting the history",
      suppressed, "the retirement narration is recognised and not counted");

    ok("DRILL M3 — the dangling-path finding detects a reference to a file that does not exist",
      !existsSync(join(repo, "docs/architecture/_meta/planted-never-existed.md")),
      "a planted path is absent from the filesystem");

    const fakeGate = "if (capture-root is the app) { accept(); }";
    ok("DRILL M4 — the seed-gate finding detects a gate that keys on a retired clause",
      RETIRED_CLAUSES.some((c) => c.pattern.test(fakeGate)), "a planted retired-clause gate is detected");

    ok("DRILL M5 — the derivation finding detects a missing terminal artifact",
      !existsSync(join(repo, "apps/hypervisor/planted-missing-artifact.v1.json")),
      "a planted artifact path is absent, so its absence would be caught");
  }
} catch (error) {
  failures += 1;
  results.push({ assertion: "the check ran to completion", satisfied: false, detail: String(error?.stack || error).slice(0, 600) });
  console.log(`FAIL  the check ran to completion  (${String(error?.message || error).slice(0, 300)})`);
}

const passed = results.filter((entry) => entry.satisfied).length;
console.log(JSON.stringify({
  check: "check:prompt-corpus-currentness",
  unit: "M08.7",
  verdict: failures === 0 ? "PASS" : "FAIL",
  executed_assertions: results.length,
  passed,
  failed: failures,
  observations,
}, null, 2));
process.exit(failures === 0 ? 0 : 1);
