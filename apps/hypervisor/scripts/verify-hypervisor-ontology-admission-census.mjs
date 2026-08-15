#!/usr/bin/env node
// The ontology plane's ADMISSION CENSUS — entailed from the daemon's source by a REAL RUST PARSER.
//
// WHY THIS EXISTS. Next-legs XIII spent five merge-blocking rounds strengthening a black-box JOURNEY
// gate's proof that "no second admission path writes ontology truth"; each round a review defeated
// the PROOF while the code stayed correct. The owner ruled the claim mis-scoped for its observer —
// the observer sat inside the system it was bounding — and commissioned the proof to be built HERE,
// from module source, where the whole program is visible at once.
//
// WHY IT IS NOT A REGEX ANY MORE. XIV Leg 3a first built this by hand-scanning Rust. Three review
// rounds defeated it, and the defeats sorted cleanly into CENSUS LOGIC (a rule wrong or decorative)
// and LANGUAGE READING (a Rust construct the scanner mis-modelled). Round two produced six of the
// latter; round three produced five more — `use super::odk_routes;` then `odk_routes::KIND_ONT`,
// raw strings desyncing a brace walk, `async fn` defeating an enclosing-function heuristic, and
// module-file resolution order shadowing a nested module with a flat sibling. The owner
// PRE-COMMITTED the rule before that round ran: modelling the next construct retires an INSTANCE, a
// real parser retires the CLASS. Extraction runs through `syn` now (`crates/ontology-census`), which
// emits the facts as JSON; this file decides what they mean. Keeping extraction and judgement apart
// is what let the judgement keep every mutation anchor while the substrate underneath changed.
//
// WHAT IT ENTAILS, scoped by owner ruling. For each of the four ONTOLOGY families, exactly one
// module admits it. That is the commissioned claim, and the four assertions below carry it.
//
// AND WHAT IT RATCHETS, which is weaker and labelled as such. The extractor derives all NINETEEN
// written ODK families. Their admitter map is RECORDED here and asserted in both directions per
// scar 4: a family that GAINS an admitter beyond the record is RED; a family that loses one makes
// the record STALE and must be re-derived in the commit that removes it. The label claims exactly
// that ratchet — NOT that every ODK family has one admitter, because FIVE DO NOT. Those five are
// recorded UNDER ADJUDICATION, neither endorsed nor condemned; adjudicating them is next-legs XV
// work, and the question per family is whether the co-admitters are legitimate co-callers of ONE
// kernel-owned admission path or whether a lane hand-mints records beside it.
//
// The hand-written table this replaced named FOUR families and structurally could not have seen the
// other fifteen. Deriving it found five multi-admitter families on the first run. Hand-written
// filter, derived replacement, immediate finding — that sequence is scar 4's whole argument.
//
// WHAT IT DOES NOT ENTAIL. `syn` reads this crate's source. A write performed by a dependency crate
// on the daemon's behalf, produced by macro expansion, or by another process, is outside it.
// Seventy-four writer calls take their family as a runtime parameter and cannot be resolved
// statically at all; that count is pinned as its own ratchet rather than waved through.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = process.env.IOI_CENSUS_ROOT || path.resolve(HERE, "..", "..", "..");
const EXTRACTOR_SRC = path.join(ROOT, "crates/ontology-census/src/main.rs");
const EXTRACTOR_BIN = path.join(ROOT, "target/debug/ioi-ontology-census");
const DAEMON_MAIN = path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

/** The four families this leg's entailment covers, by owner ruling. */
const ONTOLOGY_FAMILIES = {
  "odk-domain-ontologies": "odk_routes",
  "odk-ontology-receipts": "odk_routes",
  "odk-ontology-proposals": "ontology_workbench_routes",
  "odk-saved-object-sets": "ontology_workbench_routes",
};

// The whole written ODK plane as derived at this commit. A RATCHET, not a claim: five of these have
// more than one admitter today and are UNDER ADJUDICATION (next-legs XV).
const RECORDED_PLANE = {
  "odk-capability-lease-plan-receipts": ["capability_lease_plan_routes"],
  "odk-capability-lease-plans": ["capability_lease_plan_routes"],
  "odk-connector-mapping-receipts": ["connector_mapping_routes"],
  "odk-connector-mappings": ["connector_mapping_routes", "policy_bound_data_view_routes"],
  "odk-connector-session-receipts": ["connector_session_routes"],
  "odk-connector-sessions": ["connector_session_routes"],
  "odk-domain-ontologies": ["odk_routes"],
  "odk-materialized-object-sets": ["connector_execution_routes"],
  "odk-materializing-run-receipts": ["connector_execution_routes", "materializing_run_routes"],
  "odk-materializing-runs": ["connector_execution_routes", "materializing_run_routes"],
  "odk-ontology-projection-receipts": ["ontology_projection_routes"],
  "odk-ontology-projections": ["connector_execution_routes", "ontology_projection_routes", "policy_bound_data_view_routes"],
  "odk-ontology-proposals": ["ontology_workbench_routes"],
  "odk-ontology-receipts": ["odk_routes"],
  "odk-policy-bound-data-views": ["policy_bound_data_view_routes"],
  "odk-saved-object-sets": ["ontology_workbench_routes"],
  "odk-surface-descriptors": ["odk_routes"],
  "odk-transformation-run-receipts": ["transformation_run_routes"],
  "odk-transformation-runs": ["policy_bound_data_view_routes", "transformation_run_routes"],
};

/** Writer calls whose family is a runtime parameter, unresolvable from source. Pinned, not waived. */
const UNRESOLVED_WRITER_CALLS = 74;

const WRITERS = new Set(["persist_record", "persist_record_durable", "remove_record", "persist_promoted", "admit_required"]);

/**
 * Derive the census, REBUILDING THE EXTRACTOR FIRST.
 *
 * A gate must never trust a previously-built extractor. XIII poisoned verifier runs with a daemon
 * binary built from a different tree — the runs looked green because the artifact was stale, not
 * because the source was right. The identical hazard applies here, so the extractor is rebuilt every
 * run and its freshness asserted against its own source before a single fact is read.
 */
function deriveCensus() {
  const build = spawnSync("cargo", ["build", "--offline", "-p", "ioi-ontology-census"],
    { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 900000 });
  const built = build.status === 0 && fs.existsSync(EXTRACTOR_BIN);
  const fresh = built && fs.statSync(EXTRACTOR_BIN).mtimeMs >= fs.statSync(EXTRACTOR_SRC).mtimeMs;
  ok("the syn EXTRACTOR is rebuilt and proven fresher than its own source before any fact is read — a gate that trusts a previously-built artifact is the stale-binary defect that silently replayed an old tree through XIII's verifier runs",
    built && fresh,
    built ? (fresh ? "rebuilt, newer than its source" : "STALE: binary older than its source")
      : `build failed: ${(build.stderr || "").split("\n").filter((l) => l.startsWith("error")).slice(0, 2).join(" | ")}`);
  if (!built || !fresh) return null;

  const run = spawnSync(EXTRACTOR_BIN, [DAEMON_MAIN],
    { cwd: ROOT, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: 900000 });
  const parsed = run.status === 0;
  ok("the extractor parses EVERY module of the daemon — a parse failure is RED, because a module `syn` cannot read is a module this census does not cover, and silence there would be indistinguishable from a clean run",
    parsed, parsed ? "all modules parsed" : (run.stderr || "").split("\n").slice(0, 2).join(" | "));
  return parsed ? JSON.parse(run.stdout) : null;
}

function run() {
  const census = deriveCensus();
  if (!census) {
    for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
    console.log(`\n${results.filter((r) => r.pass).length}/${results.length} passed`);
    process.exit(1);
  }
  const modules = census.modules;
  const byName = new Map(modules.map((m) => [m.name, m]));

  ok("the module world is the daemon's own MODULE GRAPH, walked transitively by the parser through `#[path]` declarations — a directory listing misses a module declared elsewhere, and this daemon declares every route module with an explicit path so cargo's autobin will not claim each file as a binary target",
    modules.length > 80 && byName.has("odk_routes") && byName.has("ontology_workbench_routes"),
    `${modules.length} modules reached through the graph`);

  // ---------------------------------------------------------------- name resolution, per module
  const resolveArg = (mod, written) => {
    if (written.startsWith('"')) return written.replace(/^"|"$/gu, "");
    const segs = written.split("::");
    if (segs.length >= 2) {
      const owner = byName.get(segs[segs.length - 2]);
      if (owner) return owner.consts[segs[segs.length - 1]] ?? null;
    }
    const name = segs[segs.length - 1];
    if (mod.consts[name] !== undefined) return mod.consts[name];
    for (const imp of mod.imports) {
      if (imp.local !== name || !imp.from) continue;
      const from = byName.get(imp.from);
      if (from?.consts[imp.item] !== undefined) return from.consts[imp.item];
    }
    return null;
  };

  // AMBIGUITY, CHECKED ON AMBIGUITY. The assertion that carried this label previously verified only
  // that each family literal was declared SOMEWHERE — a declaration-presence check a review defeated
  // by adding a second, conflicting `const KIND_ONT` and watching it stay green.
  const declaredBy = new Map();
  for (const m of modules) {
    for (const [n, lit] of Object.entries(m.consts)) {
      if (!declaredBy.has(n)) declaredBy.set(n, new Map());
      declaredBy.get(n).set(m.name, lit);
    }
  }
  const familyLiterals = new Set(Object.keys(ONTOLOGY_FAMILIES));
  const ambiguous = [];
  for (const [n, byMod] of declaredBy) {
    const values = new Set(byMod.values());
    if (values.size > 1 && [...values].some((v) => familyLiterals.has(v))) {
      ambiguous.push(`${n} means {${[...values].join(" | ")}}`);
    }
  }
  ok("NO CONSTANT NAME THAT MEANS AN ONTOLOGY FAMILY ANYWHERE MEANS SOMETHING ELSE SOMEWHERE — checked against every declaration the parser found, because resolution is per-module and a name meaning two things is exactly how a second admitter reads as innocent",
    ambiguous.length === 0, ambiguous.join(" ; ") || `${declaredBy.size} declared names, none conflicting on a family`);

  // ---------------------------------------------------------------- admitters
  const admits = new Map();
  let unresolvedWrites = 0;
  for (const m of modules) {
    for (const c of m.calls) {
      if (!WRITERS.has(c.callee)) continue;
      const lit = resolveArg(m, c.written);
      if (lit === null) { unresolvedWrites += 1; continue; }
      if (!lit.startsWith("odk-")) continue;
      if (!admits.has(lit)) admits.set(lit, new Set());
      admits.get(lit).add(m.name);
    }
  }

  for (const [lit, owner] of Object.entries(ONTOLOGY_FAMILIES)) {
    const got = [...(admits.get(lit) ?? [])].sort();
    ok(`EXACTLY ONE module admits \`${lit}\` — and it is \`${owner}\`; a second admission path must appear in some module's AST to exist at all, and the parser reads every module of this binary`,
      got.length === 1 && got[0] === owner, `admitted by [${got.join(",") || "none"}]`);
  }

  // ---------------------------------------------------------------- the plane ratchet
  const gained = [];
  const stale = [];
  for (const [fam, recorded] of Object.entries(RECORDED_PLANE)) {
    const got = [...(admits.get(fam) ?? [])].sort();
    if (!got.length) { stale.push(`${fam}: recorded [${recorded.join(",")}], now admitted by nothing`); continue; }
    for (const mod of got) if (!recorded.includes(mod)) gained.push(`${fam}: GAINED ${mod}`);
    for (const mod of recorded) if (!got.includes(mod)) stale.push(`${fam}: recorded ${mod} no longer admits it`);
  }
  for (const fam of admits.keys()) {
    if (!RECORDED_PLANE[fam]) gained.push(`${fam}: an ODK family absent from the record is written by [${[...admits.get(fam)].sort().join(",")}]`);
  }
  const underAdjudication = Object.entries(RECORDED_PLANE).filter(([, v]) => v.length > 1).map(([k]) => k);
  ok("NO ODK FAMILY GAINS AN ADMISSION PATH BEYOND THE RECORDED MAP — a RATCHET over all nineteen written families, and deliberately NOT a claim that each has one admitter: five have more than one today, recorded UNDER ADJUDICATION for next-legs XV, neither endorsed nor condemned. What this refuses is a new one appearing unnoticed",
    gained.length === 0,
    gained.length ? `GAINED: ${gained.join(" ; ")}`
      : `${Object.keys(RECORDED_PLANE).length} families pinned; under adjudication: ${underAdjudication.join(", ")}`);

  ok("and the recorded map is not STALE — every family and admitter it names still admits, so a pin cannot go quietly true over writes that were renamed away; removing one is a deliberate act in the commit that removes it (scar 4, second direction)",
    stale.length === 0, stale.join(" ; ") || "every recorded family and admitter still admits");

  ok("and the count of writer calls whose family is a RUNTIME PARAMETER is pinned — those cannot be resolved from source at all, so they are ratcheted rather than waved through, and a new one must be justified rather than absorbed into a number nobody watches",
    unresolvedWrites === UNRESOLVED_WRITER_CALLS,
    `${unresolvedWrites} unresolvable writer calls (pinned at ${UNRESOLVED_WRITER_CALLS})`);

  // ---------------------------------------------------------------- raw filesystem writes
  // THE WRITER CENSUS CANNOT SEE A LANE THAT BYPASSES THE WRITERS. A module that puts bytes into a
  // family directory with `std::fs::write` admits a record without calling anything this census
  // counts, and that mutation is part of the regression floor this substrate inherited. `syn` gives
  // the resolved call path, so an aliased `use std::fs as sysfs` is the same AST node — the spelling
  // games that defeated a text scan do not arise here.
  const rawWrites = [];
  for (const m of modules) {
    for (const c of m.fs_calls ?? []) {
      if (c.in_test) continue;
      // THE CALL'S OWN ARGUMENTS, AND THE FUNCTION AROUND IT. A family normally reaches a raw write
      // through a local — `let p = dir.join(KIND_ONT); fs::write(p.join(id), …)` — so it appears
      // nowhere in the call itself. The rule is the dataflow-free one: a function that makes a raw
      // filesystem call may not also name an ODK family. Conservative and fail-closed, the same
      // shape as the resolve-and-write rule.
      const named = new Set([...c.args, ...((m.fn_leaves ?? {})[c.in_fn] ?? [])]);
      for (const a of named) {
        const lit = resolveArg(m, a);
        if (lit && lit.startsWith("odk-")) {
          rawWrites.push(`${m.name}::${c.in_fn} makes a raw ${c.callee} and names ${lit}`);
        }
      }
    }
  }
  ok("NO PRODUCTION FUNCTION MAKES A RAW FILESYSTEM CALL AND NAMES AN ODK FAMILY — a lane that writes bytes into a family directory itself admits a record without calling any writer this census counts; the rule is over the FUNCTION rather than the call arguments because the family normally arrives through a local, and test fixtures are excluded by the parser's own `#[cfg(test)]` knowledge rather than by a brace walk",
    rawWrites.length === 0, [...new Set(rawWrites)].join(" ; ") || "no production raw filesystem call names a family");

  // ---------------------------------------------------------------- who may DECLARE a family
  // ONLY THE OWNER NAMES ITS OWN FAMILY. A module that declares `const X: &str =
  // "odk-domain-ontologies"` has minted a second name for someone else's store, and every later use
  // of it reads as innocent local code. This is the shape a review used to slip a family reference
  // past a census that only looked at call sites.
  const foreignDeclarations = [];
  for (const m of modules) {
    for (const [n, lit] of Object.entries(m.consts)) {
      const owner = ONTOLOGY_FAMILIES[lit];
      if (owner && owner !== m.name) foreignDeclarations.push(`${m.name} declares ${n} = "${lit}" (owned by ${owner})`);
    }
  }
  ok("ONLY THE OWNING MODULE DECLARES A CONSTANT NAMING ONE OF ITS ONTOLOGY FAMILIES — a second name minted elsewhere makes every later use of it read as innocent local code, which is precisely how a family reference slips past a census that only inspects call sites",
    foreignDeclarations.length === 0, foreignDeclarations.join(" ; ") || "every ontology family constant is declared by its owner");

  // ---------------------------------------------------------------- resolve-and-write
  // THE GATE DECIDES WHETHER AN ARM NAMES A FAMILY, because the extractor reporting a bare "this
  // function has a `Some(...)` arm" made every `Ok(id) => Some(id.principal_ref)` look like a family
  // resolver — and one such function legitimately writes a record. Extraction reports what is
  // written; judgement belongs here.
  const resolveAndWrite = [];
  for (const m of modules) {
    for (const fn of m.resolve_and_write_fns ?? []) {
      const arms = (m.resolver_arms ?? {})[fn] ?? [];
      const namesFamily = arms.some((a) => {
        const lit = resolveArg(m, a);
        return lit !== null && lit.startsWith("odk-");
      });
      if (namesFamily) resolveAndWrite.push(`${m.name}::${fn}`);
    }
  }
  ok("no function that RESOLVES a family name through a `match` arm also WRITES a record — conservative, dataflow-free and fail-closed: a scheme-mapper that admits is a second spine whatever the plumbing between them looks like, and widening this rule later is a governed act rather than a convenience",
    resolveAndWrite.length === 0, resolveAndWrite.join(" ; ") || "no resolving function writes");

  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({ verifierId: "ontology-admission-census", sourceUrl: import.meta.url, results });
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  if (failed.length) process.exit(1);
}

const INVOKED = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (INVOKED) {
  try { run(); } catch (error) {
    console.error(`FAIL ontology-admission-census — ${error?.stack || error}`);
    process.exit(1);
  }
}
