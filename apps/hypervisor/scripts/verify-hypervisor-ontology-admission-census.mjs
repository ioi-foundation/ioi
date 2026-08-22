#!/usr/bin/env node
// The ontology plane's ADMISSION CENSUS — entailed from the daemon's source by a REAL RUST PARSER.
//
// WHY THIS EXISTS. Next-legs XIII spent five merge-blocking rounds strengthening a black-box JOURNEY
// gate's proof that "no second admission path writes ontology truth"; each round a review defeated
// the PROOF while the code stayed correct. The owner ruled the claim mis-scoped for its observer —
// the observer sat inside the system it was bounding — and commissioned the proof to be built HERE,
// from module source, where the whole program is visible at once.
//
// WHY IT IS NOT A REGEX, AND WHY THE FIRST PARSER DID NOT COUNT. XIV Leg 3a first built this by
// hand-scanning Rust; three review rounds defeated it, and the defeats sorted cleanly into CENSUS
// LOGIC (a rule wrong or decorative) and LANGUAGE READING (a construct the scanner mis-modelled).
// The owner PRE-COMMITTED the rule before round three ran: modelling the next construct retires an
// INSTANCE, a real parser retires the CLASS. The first attempt at that ruling ADDED `syn` and KEPT
// the hand-rolled walk — a fifteen-variant `expr_children` under an AST, with a zero-override
// `Visit` impl driven across every expression so the code READ as though a complete visitor ran. A
// fourth review demonstrated ordinary second-admitter constructs passing green against it —
// `.await`, `tokio::spawn`, impl methods, arm guards, struct literals, nested items, macro
// arguments. THE SCAR: A PRE-COMMITTED BOUNDARY IS EXECUTED BY ITS MECHANISM, NOT BY ITS DEPENDENCY.
// The traversal in `crates/ontology-census` is `syn::visit::Visit` itself now, and every one of
// those constructs is a committed anchor in `ontology-admission-census.mutants.v1.json` — the count
// is whatever the battery prints, because a count that reproduces nowhere is the falsified-claim
// class this program keeps finding in ledgers, applied to the evidence for the gates themselves.
//
// AND WHY EVERY JUDGEMENT BELOW READS A CLASSIFICATION RATHER THAN AN ABSENCE. That same review
// found the deeper defect: a construct the walk missed produced no entry, and every judgement was
// derived from the entries — so a COVERAGE GAP was indistinguishable from SAFETY. The extractor now
// reports every mention of a name of interest WITH the syntactic role it sits in, and this file
// holds a closed set of roles it can classify. An unlisted role is RED.
//
// AND WHY THAT WAS STILL NOT ENOUGH — THE OWNER'S SCAR, VERBATIM. A fifth review defeated the
// closed role set, and the diagnosis is the whole reason this file's shape changed again:
//
//     A CLOSED SET OF ROLES CLOSES NOTHING UNLESS THE SET OF THINGS THAT PRODUCE A ROLE IS ITSELF
//     ENTAILED.
//
// Roles were produced by AST positions the extractor happened to override, so a family name in a
// position no override reached produced NO MENTION AT ALL — and there is no role to be unknown
// about when there is no mention. TEN mutants of that class were planted against the landing tree.
// SEVEN passed completely green once their commit re-derived its own population pins, which is what
// a landing commit does as a matter of routine: a `match` arm PATTERN carrying the family to a
// writer, an `if let` pattern doing the same, a raw-filesystem write behind a pattern, a byte string
// through `from_utf8`, `concat!("od", "k-domain-ontologies")`, a `#[serde(rename)]` minting the name,
// and an `include!` of an unwalked file containing the entire second admitter.
//
// SO MENTIONS ARE DERIVED FROM THE RAW TOKEN STREAM AND THE AST ONLY ASSIGNS ROLES. The extractor
// tokenises each file ONCE, walks that stream exhaustively — every literal and every constant-shaped
// identifier, at every depth of every group — and hands the SAME stream to syn. The token population
// is total by construction, because a name that is in the file is a token in the file. This file
// matches the two by SOURCE POSITION: a token that resolves to a family with no AST mention on it is
// a SILENT MENTION and is RED.
//
// AND THAT WAS FALSIFIED TOO, WHICH IS WHY THE CLAIM BELOW IS SMALLER THAN THE ONE IT REPLACES. A
// sixth review demonstrated six compiling second-admission paths passing green, and the diagnosis is
// the same scar ONE LAYER DOWN:
//
//     A TOTAL TOKEN POPULATION CLOSES NOTHING UNLESS RESOLUTION OVER IT IS TOTAL.
//
// The token walk is total. The population this gate JUDGES is `token ∩ resolves-to-a-family`, and
// resolution is a PARTIAL FUNCTION — it reads the declarations this census can see, and there are
// thousands of constant-shaped names it cannot tie to one. Those were `continue`d in silence, with
// no assertion over them, so the silence check adjudicated 282 of 106,724 tokens while a qualified
// constant inside macro tokens — where the token walk flattens the path and loses the qualification
// — reached a writer completely green.
//
// THE OWNER RULED: NO THIRD HARDENING EDGE. Entailing the resolver is construct-modelling one layer
// up, and a design falsified twice does not get to try again. What was wrong is the LABELS' REACH,
// not the gate's existence — the entailed core is real. So every label below is re-scoped to the
// RESOLVED population, and EVERY NAME THIS CENSUS CANNOT ADJUDICATE IS COUNTED IN A NAMED BUCKET,
// PINNED IN BOTH DIRECTIONS. A new unadjudicable name beyond the pin is RED; a name that becomes
// resolvable shrinks the pin in the commit that resolves it. The buckets are the honest boundary of
// this gate, stated as a number per cause rather than as a silence — and burning them down, together
// with entailing the resolver itself, is next-legs XV work beside the atlas `denies` schema.
//
// WHAT IT ENTAILS, scoped by owner ruling. For each of the four ONTOLOGY families, exactly one
// module admits it. That is the commissioned claim, and four assertions below carry it.
//
// AND WHAT IT RATCHETS, which is weaker and labelled as such. The extractor derives every string in
// this daemon that begins `odk-`. Their admitter and toucher maps are RECORDED here and asserted in
// both directions per scar 4: a gain beyond the record is RED; a loss makes the record STALE and is
// re-derived in the commit that removes it. The label claims exactly that ratchet — NOT that every
// ODK family has one admitter, because THREE DO NOT. Those three are recorded UNDER ADJUDICATION,
// neither endorsed nor condemned; all three share one second admitter, `connector_execution_routes`,
// which makes them one question rather than three, and answering it is next-legs XV work: is that
// module a legitimate co-caller of kernel-owned admission paths, or does it hand-mint records
// beside them — the W3.1 shape.
//
// THE MAP WAS WRONG IN BOTH DIRECTIONS BEFORE IT WAS DERIVED PROPERLY, WHICH IS THE POINT. The
// hand-written table this replaced named FOUR families and structurally could not have seen the
// other twenty-one. Its first derived replacement reported FIVE multi-admitter families — also
// wrong, because that census applied no test filter, and three of the five were multi-admitter only
// on the strength of `#[cfg(test)]` fixtures. Recording a fixture as an admitter PRE-AUTHORISES its
// module to write that family for real. Hand-written filter, derived replacement, finding;
// unfiltered census, filtered census, correction. Scar 4's whole argument, twice over.
//
// TEST CLASSIFICATION FAILS TOWARD PRODUCTION and test writes are CLASSIFIED, not dropped: only a
// bare `#[cfg(test)]` marks a subtree, `cfg(any(test, …))` and feature gates count as production,
// and the test-write map is pinned too — so moving a production write under a test attribute shrinks
// the production map into a stale-pin RED rather than passing as a silent green.
//
// WHAT IT DOES NOT ENTAIL, stated so the residual is named rather than implied. `syn` reads this
// crate's source: a write performed by a DEPENDENCY CRATE on the daemon's behalf, by a
// user-defined macro's EXPANSION, or by another process, is outside it. Production writer calls that
// take their family as a RUNTIME PARAMETER cannot be resolved from source at all; that count is
// pinned as its own ratchet rather than waved through. And within that bucket one specific evasion
// survives: a family name assembled AT RUNTIME from pieces that are each innocent — no piece a
// family name, no piece a fragment inside the writer's own arguments — bound to a local and passed
// to the writer. Compile-time assembly is followed into its expansion and closed; runtime assembly
// is closed only where it sits inside the writer's own argument subtree. Adjudicating the rest needs
// dataflow this census deliberately does not do, and it is a NAMED RESIDUAL, not a silence: the
// population it hides in is counted, and growing it moves a pin.
//
// AND THE SECOND NAMED RESIDUAL, found by the review of the re-scope and NOT closed here, because a
// design falsified twice does not earn another hardening edge: ONE-HOP INDIRECTION WITHIN A MODULE.
// The conservative rule that catches "the function names a family and writes with something it will
// not spell" is scoped to ONE FUNCTION. Move the literal one function away —
// `fn put(d, k, i, r) { persist_record(d, k, i, r) }` called as `put(d, "odk-…", i, r)` — and the
// writer's function names no family while the caller's does. In a module already RECORDED as a
// toucher of that family, nothing moves at all. Widening the rule to module scope is what would
// close it, and that fires on 198 of this daemon's production writer functions — a pinned exception
// list, not a gate. So it is named here, anchored in the battery in both directions, and it is what
// the XV run that entails the resolver should take up alongside the buckets.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// NO ENV OVERRIDE. A merge-blocking gate that can be re-pointed at another tree by an environment
// variable certifies whichever tree it was aimed at while reporting the same number — the "gate as
// its own oracle" shape this file exists to remove, wearing a different hat.
const ROOT = path.resolve(HERE, "..", "..", "..");
const EXTRACTOR_SRC = path.join(ROOT, "crates/ontology-census/src/main.rs");
const EXTRACTOR_BIN = path.join(ROOT, "target/debug/ioi-ontology-census");
const DAEMON_MAIN = path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

/** The four families this leg's entailment covers, by owner ruling. Keyed by module PATH tail. */
const ONTOLOGY_FAMILIES = {
  "odk-domain-ontologies": "hypervisor_daemon_routes/odk_routes.rs",
  "odk-ontology-receipts": "hypervisor_daemon_routes/odk_routes.rs",
  "odk-ontology-proposals": "hypervisor_daemon_routes/ontology_workbench_routes.rs",
  "odk-saved-object-sets": "hypervisor_daemon_routes/ontology_workbench_routes.rs",
};

/**
 * EVERY SYNTACTIC ROLE A FAMILY NAME MAY APPEAR IN, and what each one means for admission.
 *
 * This table is the closed world that makes a coverage gap a finding. The extractor labels every
 * mention with its role; a role missing from here is RED whatever it turns out to mean. `admits`
 * roles put the module in the admitter map. `names` roles put it in the weaker TOUCHER map, because
 * a family name reaching a function body outside any call this census recognises cannot be shown
 * harmless without dataflow this census deliberately does not do — so it is ratcheted, not waved
 * through.
 */
const ROLE_MEANING = {
  "write-arg": "admits",
  "fs-arg": "admits",
  "read-arg": "names",
  "const-init": "declares",
  "static-init": "declares",
  // THE DECLARATION SITE OF A NAME IS A MENTION OF IT. The token walk finds `KIND_ONT` where it is
  // declared as surely as where it is used, and an unlabelled token position is by construction a
  // silent mention — so the declaration's own identifier is labelled and classified here.
  "decl-name": "declares",
  "use-path": "names",
  // A PATTERN carried a family name to a writer in two of the seven mutants that passed green.
  "pattern-lit": "names",
  "pattern-path": "names",
  "type-path": "names",
  "fn-body": "names",
  "macro:json": "names",
  "macro:format": "names",
  "macro:assert": "names",
  "macro:assert_eq": "names",
};

const RECORDED_PLANE = {
  "odk-capability-lease-plan-receipts": { admits: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs"] },
  "odk-capability-lease-plans": { admits: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/connector_session_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"] },
  "odk-connector-mapping-receipts": { admits: ["hypervisor_daemon_routes/connector_mapping_routes.rs"], touches: ["hypervisor_daemon_routes/connector_mapping_routes.rs"] },
  "odk-connector-mappings": { admits: ["hypervisor_daemon_routes/connector_mapping_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/connector_mapping_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs", "hypervisor_daemon_routes/policy_bound_data_view_routes.rs", "hypervisor_daemon_routes/transformation_run_routes.rs"] },
  "odk-connector-session-receipts": { admits: ["hypervisor_daemon_routes/connector_session_routes.rs"], touches: ["hypervisor_daemon_routes/connector_session_routes.rs"] },
  "odk-connector-sessions": { admits: ["hypervisor_daemon_routes/connector_session_routes.rs"], touches: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/connector_session_routes.rs"] },
  "odk-data-recipes": { admits: [], touches: ["hypervisor_daemon_routes/domain_apps_routes.rs", "hypervisor_daemon_routes/governance_routes.rs", "hypervisor_daemon_routes/marketplace_routes.rs", "hypervisor_daemon_routes/odk_routes.rs"] },
  "odk-domain-ontologies": { admits: ["hypervisor_daemon_routes/odk_routes.rs"], touches: ["hypervisor_daemon_routes/connector_mapping_routes.rs", "hypervisor_daemon_routes/domain_apps_routes.rs", "hypervisor_daemon_routes/governance_routes.rs", "hypervisor_daemon_routes/marketplace_routes.rs", "hypervisor_daemon_routes/odk_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs", "hypervisor_daemon_routes/ontology_workbench_routes.rs"] },
  "odk-manifest": { admits: [], touches: ["hypervisor_daemon_routes/odk_routes.rs"] },
  "odk-manifest://": { admits: [], touches: ["hypervisor_daemon_routes/odk_routes.rs"] },
  "odk-manifests": { admits: [], touches: ["hypervisor_daemon_routes/domain_apps_routes.rs", "hypervisor_daemon_routes/governance_routes.rs", "hypervisor_daemon_routes/marketplace_routes.rs", "hypervisor_daemon_routes/odk_routes.rs", "hypervisor_daemon_routes/package_registry_routes.rs"] },
  "odk-materialized-object-sets": { admits: ["hypervisor_daemon_routes/connector_execution_routes.rs"], touches: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/ontology_workbench_routes.rs", "hypervisor_daemon_routes/orchestration_routes.rs"] },
  "odk-materializing-run-receipts": { admits: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"], touches: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"] },
  "odk-materializing-runs": { admits: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"], touches: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/connector_session_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs"] },
  "odk-materializing-runs/{id}/lease": { admits: [], touches: ["hypervisor_daemon_routes/materializing_run_routes.rs"] },
  "odk-ontology-projection-receipts": { admits: ["hypervisor_daemon_routes/ontology_projection_routes.rs"], touches: ["hypervisor_daemon_routes/ontology_projection_routes.rs"] },
  "odk-ontology-projections": { admits: ["hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/connector_execution_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs"] },
  "odk-ontology-proposals": { admits: ["hypervisor_daemon_routes/ontology_workbench_routes.rs"], touches: ["hypervisor_daemon_routes/ontology_workbench_routes.rs"] },
  "odk-ontology-receipts": { admits: ["hypervisor_daemon_routes/odk_routes.rs"], touches: ["hypervisor_daemon_routes/odk_routes.rs"] },
  "odk-policy-bound-data-view-receipts": { admits: [], touches: ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"] },
  "odk-policy-bound-data-views": { admits: ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs", "hypervisor_daemon_routes/policy_bound_data_view_routes.rs", "hypervisor_daemon_routes/transformation_run_routes.rs"] },
  "odk-saved-object-sets": { admits: ["hypervisor_daemon_routes/ontology_workbench_routes.rs"], touches: ["hypervisor_daemon_routes/ontology_workbench_routes.rs"] },
  "odk-surface-descriptors": { admits: ["hypervisor_daemon_routes/odk_routes.rs"], touches: ["hypervisor_daemon_routes/domain_apps_routes.rs", "hypervisor_daemon_routes/governance_routes.rs", "hypervisor_daemon_routes/marketplace_routes.rs", "hypervisor_daemon_routes/odk_routes.rs", "hypervisor_daemon_routes/package_registry_routes.rs"] },
  "odk-transformation-run-receipts": { admits: ["hypervisor_daemon_routes/transformation_run_routes.rs"], touches: ["hypervisor_daemon_routes/transformation_run_routes.rs"] },
  "odk-transformation-runs": { admits: ["hypervisor_daemon_routes/transformation_run_routes.rs"], touches: ["hypervisor_daemon_routes/capability_lease_plan_routes.rs", "hypervisor_daemon_routes/materializing_run_routes.rs", "hypervisor_daemon_routes/ontology_projection_routes.rs", "hypervisor_daemon_routes/transformation_run_routes.rs"] },
};

/**
 * WRITES UNDER A BARE `#[cfg(test)]`, recorded rather than discarded. Pinning what the filter
 * EXCLUDES is what stops the exclusion becoming a hiding place: a production write relocated under a
 * test attribute leaves the production map and arrives here, failing twice rather than passing once.
 */
const RECORDED_TEST_WRITES = {
  "odk-connector-mappings": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
  "odk-domain-ontologies": ["hypervisor_daemon_routes/odk_routes.rs"],
  "odk-ontology-projections": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
  "odk-ontology-receipts": ["hypervisor_daemon_routes/odk_routes.rs"],
  "odk-policy-bound-data-view-receipts": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
  "odk-policy-bound-data-views": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
  "odk-surface-descriptors": ["hypervisor_daemon_routes/odk_routes.rs"],
  "odk-transformation-runs": ["hypervisor_daemon_routes/policy_bound_data_view_routes.rs"],
};

/**
 * THE TRAVERSAL'S OWN REACH, pinned. Every assertion here reads the census, so a walk that quietly
 * stops reaching a construct weakens all of them at once without failing any of them.
 */
const PINNED = {
  modules: 90,
  familyMentions: 300,
  tokenMentions: 110455,
  judgedTokenPositions: 282,
  productionWriterCalls: { family: 72, nonFamilyLiteral: 224, runtimeParameter: 294 },
  productionFsCalls: 231,
  /**
   * THE NAMES THIS CENSUS CANNOT ADJUDICATE, by cause. Pinned exactly, both directions.
   *
   *   foreign-qualified   — the qualifier names a module this walk does not contain (`StatusCode::…`,
   *                         `header::AUTHORIZATION`). Structurally cannot be a daemon family constant.
   *   opaque-initialiser  — a daemon constant whose initialiser this census cannot read to a literal.
   *                         The sharp one: it IS a daemon name and its value is unknown here.
   *   bare-undeclared     — a constant-shaped identifier tied to no declaration this census can see.
   *                         Where a qualified name inside MACRO TOKENS lands, because the token walk
   *                         flattens the path to its tail.
   *   ambiguous-module    — two modules share the stem the qualifier names.
   *   not-a-visible-const — the qualifier resolves, the item is not a constant this census can read.
   *   resolution-cycle    — const-of-const deeper than the resolver follows.
   *
   * Burning these down, and entailing the resolver so they need not exist, is next-legs XV.
   */
  unadjudicable: {
    "foreign-qualified": 3602,
    "opaque-initialiser": 1595,
    "bare-undeclared": 522,
    "ambiguous-module": 0,
    "not-a-visible-const": 0,
    "resolution-cycle": 0,
  },
  /** `include!` splices code and is followed; the data forms carry no Rust and are pinned. */
  includes: { splicedCode: 0, dataStr: 32, dataBytes: 0, dataOpaqueArg: 7 },
  /** Compile-time name assembly. Every production one must be READABLE and is followed. */
  compileAssembly: { production: 0, test: 9 },
};

/**
 * THE EXTRACTOR SOURCE PIN — a COMMITTED expectation, compared against a fresh computation.
 *
 * The previous guard hashed the extractor source on disk and compared it against the digest the
 * binary baked in with `include_str!`. That certified nothing: this file runs `cargo build` FIRST,
 * so the build makes the two agree by construction, and an edit to the extractor moves BOTH sides
 * together. The gate was its own oracle — the same class as a fixture built in a world the product
 * does not produce.
 *
 * The expectation therefore lives HERE, in tracked source. Both sides are compared against it: the
 * bytes on disk, and the digest the binary carries from its own compile. Moving this pin is a
 * GOVERNED COMMIT ACT — it appears in the diff of any change to the extractor, which is the point.
 */
const EXTRACTOR_SOURCE_PIN = "522060618a90ba05";

/** FNV-1a/64 — the digest the extractor bakes its own source under at compile time. */
function fnv1a64(bytes) {
  const mask = 0xffffffffffffffffn;
  let h = 0xcbf29ce484222325n;
  for (const b of bytes) {
    h = (h ^ BigInt(b)) & mask;
    h = (h * 0x100000001b3n) & mask;
  }
  return h.toString(16).padStart(16, "0");
}

/**
 * Build the extractor and read the census out of it.
 *
 * BOTH SIDES ARE COMPARED AGAINST A COMMITTED PIN, NOT AGAINST EACH OTHER. Comparing the binary's
 * baked-in digest against the source on disk was self-referential: this function builds the binary
 * from that source first, so the two agree by construction and tampering moves both. The pin above
 * is the expectation; the two computations below are the fresh evidence. A timestamp guard is not
 * used at all — cargo treats a source whose mtime moved BACKWARDS as up-to-date, so an mtime
 * comparison passes on exactly the hazard it names.
 */
function deriveCensus() {
  // `--locked`, NOT `--offline`. Offline was a network optimisation that fails closed for the wrong
  // reason — CI has no populated crates.io index at this point and the gate died on
  // "no matching package named `serde_json`", which says nothing about the census. `--locked` is
  // what the rest of this estate's CI uses and it carries a real property the pin does not: the
  // extractor is built from the resolution `Cargo.lock` records, so a dependency move cannot change
  // its behaviour without a lockfile diff.
  const build = spawnSync("cargo", ["build", "--locked", "-p", "ioi-ontology-census"], { cwd: ROOT, encoding: "utf8" });
  if (build.status !== 0) throw new Error(`extractor build failed: ${build.stderr || build.stdout}`);
  const run = spawnSync(EXTRACTOR_BIN, ["--interest", "odk-", DAEMON_MAIN], { cwd: ROOT, encoding: "utf8", maxBuffer: 512 * 1024 * 1024 });
  if (run.status !== 0) throw new Error(`extractor failed (${run.status}): ${run.stderr}`);
  const census = JSON.parse(run.stdout);
  const onDisk = fnv1a64(fs.readFileSync(EXTRACTOR_SRC));
  const baked = census.extractor_source_fnv1a64;
  ok("THE EXTRACTOR SOURCE AND THE BINARY BUILT FROM IT BOTH MATCH A COMMITTED PIN — not each other, which is what the previous guard checked and why it certified nothing: this gate runs `cargo build` before it reads the census, so the binary agrees with whatever the source says and an edit moves both sides together, leaving the gate as its own oracle; the expectation is tracked here and moving it is a governed commit act",
    baked === EXTRACTOR_SOURCE_PIN && onDisk === EXTRACTOR_SOURCE_PIN,
    baked === EXTRACTOR_SOURCE_PIN && onDisk === EXTRACTOR_SOURCE_PIN
      ? `binary and source both at the pinned ${EXTRACTOR_SOURCE_PIN}`
      : `pin ${EXTRACTOR_SOURCE_PIN}, binary carries ${baked}, source hashes to ${onDisk}`);
  return census;
}

function run() {
  const census = deriveCensus();
  const modules = census.modules;
  const isFamily = (s) => typeof s === "string" && census.interests.some((p) => s.startsWith(p));
  // MODULE IDENTITY IS THE PATH, all the way down. Shortening a key to its basename for comparison
  // re-introduces the very collapse the path key exists to prevent: a shadow module at
  // `shadow_odk/odk_routes.rs` compares equal to the real `odk_routes.rs`, and two admitters report
  // as one. The prefix is stripped for legibility only, and it is common to every module here.
  const PREFIX = "crates/node/src/bin/";
  const modId = (k) => (k.startsWith(PREFIX) ? k.slice(PREFIX.length) : k);

  // ---------------------------------------------------------------- the module graph
  // KEYED BY REPO PATH, NOT BY FILE STEM. Two files sharing a basename collapse into one module
  // under a stem key, which MERGES their admitters — a second admitter then reports as the recorded
  // one, and "exactly one module admits" passes while two do.
  const byKey = new Map(modules.map((m) => [m.key, m]));
  const byStem = new Map();
  for (const m of modules) {
    if (!byStem.has(m.stem)) byStem.set(m.stem, []);
    byStem.get(m.stem).push(m);
  }
  ok("the census walks the module graph it can SEE from the daemon's entry point — every `mod` declaration it can see, with a bare `#[path]` honoured and the rest resolved in rustc's own nested-before-sibling order, with an unresolvable declaration or an unreadable file aborting extraction rather than silently shrinking the world; it is NOT rustc's file set and does not claim to be, because `mod` has no totality edge and is not getting one: a `#[cfg_attr(…, path = …)]` redirect is invisible here and a `mod` declared inside a `macro_rules!` body never reaches the visitor at all, so rustc would compile one file while this reads another — neither construct exists in this daemon today and entailing the file set belongs to the run that entails the resolver",
    modules.length === PINNED.modules && byKey.size === modules.length,
    `${modules.length} modules reached, ${byKey.size} distinct paths (pinned ${PINNED.modules})`);

  // ---------------------------------------------------------------- name resolution
  /**
   * Resolve a written name to the literal it stands for, or report why it cannot be tied to a
   * declaration this census can see. THERE IS NO GLOBAL-UNIQUE FALLBACK: a name the census cannot
   * tie to a declaration is UNRESOLVED, and unresolved is RED. The fallback that used to sit here
   * did not merely miss a renamed import — it disguised the miss as a different hole.
   */
  function resolveName(m, name, depth = 0) {
    if (depth > 6) return { kind: "UNRESOLVED", bucket: "resolution-cycle", why: "resolution cycle" };
    if (isFamily(name)) return { kind: "LITERAL", value: name };
    const segs = name.split("::");
    const last = segs[segs.length - 1];
    if (!/^[A-Z0-9_]+$/.test(last)) return { kind: "NOT-CONST" };
    if (segs.length >= 2) {
      // `impl Shadow { const FAM: &str = "<family>"; }` then `Shadow::FAM`. Associated constants are
      // namespaced by their type, so they are resolved under their QUALIFIED spelling and never
      // flattened into the module's constant map, where one impl's constant would answer for a bare
      // name it does not define.
      const qualified = segs.slice(-2).join("::");
      if (m.assoc_consts && m.assoc_consts[qualified] !== undefined) return { kind: "LITERAL", value: m.assoc_consts[qualified] };
      // `use super::odk_routes as ont;` then `ont::KIND_ONT` — the module ALIAS, which the previous
      // resolver could not follow and reported as an unresolvable runtime value instead. Both this
      // form and the plain `use super::m;` are in this daemon today.
      const q = segs[segs.length - 2];
      const alias = m.imports.find((i) => i.module_only && i.local === q);
      const stem = alias ? alias.item : q;
      const cands = byStem.get(stem);
      if (!cands) return { kind: "UNRESOLVED", bucket: "foreign-qualified", why: `no module named ${stem}` };
      if (cands.length > 1) return { kind: "UNRESOLVED", bucket: "ambiguous-module", why: `module name ${stem} is ambiguous` };
      const t = cands[0];
      if (t.consts[last] !== undefined) return { kind: "LITERAL", value: t.consts[last] };
      if (t.const_refs[last] !== undefined) return resolveName(t, t.const_refs[last], depth + 1);
      if (t.const_opaque.includes(last)) return { kind: "OPAQUE", bucket: "opaque-initialiser", why: `${stem}::${last} has an initialiser this census cannot read` };
      return { kind: "UNRESOLVED", bucket: "not-a-visible-const", why: `${stem}::${last} is not a constant this census can see` };
    }
    if (m.consts[last] !== undefined) return { kind: "LITERAL", value: m.consts[last] };
    // `const LOCAL: &str = super::odk_routes::KIND_ONT;` — a constant defined as another constant.
    if (m.const_refs[last] !== undefined) return resolveName(m, m.const_refs[last], depth + 1);
    if (m.const_opaque.includes(last)) return { kind: "OPAQUE", bucket: "opaque-initialiser", why: `${last} has an initialiser this census cannot read` };
    const imp = m.imports.find((i) => !i.module_only && !i.glob && i.local === last);
    if (imp && imp.from) {
      const cands = byStem.get(imp.from);
      if (cands && cands.length === 1) {
        const t = cands[0];
        if (t.consts[imp.item] !== undefined) return { kind: "LITERAL", value: t.consts[imp.item] };
        if (t.const_refs[imp.item] !== undefined) return resolveName(t, t.const_refs[imp.item], depth + 1);
      }
    }
    for (const g of m.imports.filter((i) => i.glob && i.from)) {
      const cands = byStem.get(g.from);
      if (cands && cands.length === 1 && cands[0].consts[last] !== undefined) return { kind: "LITERAL", value: cands[0].consts[last] };
    }
    return { kind: "UNRESOLVED", bucket: "bare-undeclared", why: `${last} is neither declared here nor imported` };
  }

  // ---------------------------------------------------------------- TOTALITY: token vs role
  //
  // THE POPULATION COMES FROM THE TOKENS; THE ROLES COME FROM THE AST. Every judgement below reads a
  // ROLE, and a role exists only where the extractor's visitor labelled a position — so for as long
  // as the mention population was ALSO produced by that visitor, a construct it did not reach
  // produced no mention, no role, and no finding. Seven mutants of that class passed green.
  //
  // The extractor now tokenises each file once and hands the SAME stream to syn, so a token's span
  // and a labelled mention's span are the same object. Matching them by position turns a coverage
  // gap into a FINDING: a token that resolves to a family and carries no label is a SILENT MENTION.
  const posKey = (x) => `${x.src}:${x.line}:${x.col}`;
  const silent = [];
  const orphan = [];
  let judgedTokens = 0;
  let tokenMentions = 0;
  for (const m of modules) {
    const labelled = new Map();
    for (const men of m.mentions) if (!men.synthesized) labelled.set(posKey(men), men);
    const tokenAt = new Set(m.token_mentions.map(posKey));
    tokenMentions += m.token_mentions.length;
    for (const t of m.token_mentions) {
      const r = resolveName(m, t.text);
      if (r.kind !== "LITERAL" || !isFamily(r.value)) continue;
      judgedTokens++;
      if (!labelled.has(posKey(t))) silent.push(`${modId(m.key)} ${t.src}:${t.line}:${t.col} \`${t.text}\` (${t.kind}) resolves to "${r.value}" and no rule labelled it`);
    }
    // The reverse edge, so a label cannot be minted for a position no token occupies — which is how
    // a mention population could drift back to being the visitor's own product.
    for (const men of m.mentions) {
      if (men.synthesized) continue;
      const r = resolveName(m, men.name);
      if (r.kind !== "LITERAL" || !isFamily(r.value)) continue;
      if (!tokenAt.has(posKey(men))) orphan.push(`${modId(m.key)} ${men.src}:${men.line}:${men.col} \`${men.name}\` is labelled \`${men.role}\` at a position holding no token`);
    }
  }

  // ----------------------------------------------------- THE BOUNDARY, COUNTED BY CAUSE
  //
  // THE TOKEN POPULATION IS TOTAL; RESOLUTION OVER IT IS NOT. A string literal is self-describing —
  // its value IS its meaning, so testing it against the interest prefix adjudicates it outright. A
  // constant-shaped IDENTIFIER is a NAME, and adjudicating it means resolving it to a declaration
  // this census can see. Thousands cannot be, and they used to be `continue`d in silence, which is
  // how a qualified constant inside macro tokens reached a writer completely green: the token walk
  // flattens `super::odk_routes::KIND_ONT` to the bare tail `KIND_ONT`, which resolves to nothing.
  //
  // Every one of them is now COUNTED IN A NAMED BUCKET and the buckets are pinned in BOTH
  // directions. This is not a hardening edge — resolution is not entailed and this gate does not
  // claim it is. It is the boundary made adjudicable: a number per cause, so a reviewer can read
  // what the gate cannot see rather than infer it from a silence. A new unadjudicable name beyond
  // the pin is RED. A name that becomes resolvable SHRINKS the pin in the commit that resolves it.
  const dropped = {};
  const dropMembers = {};
  const bumpDrop = (b, name, where) => {
    dropped[b] = (dropped[b] ?? 0) + 1;
    (dropMembers[b] ??= new Map()).set(`${name} @${where}`, (dropMembers[b]?.get(`${name} @${where}`) ?? 0) + 1);
  };
  for (const m of modules) {
    const labelledAt = new Map();
    for (const men of m.mentions) if (!men.synthesized) labelledAt.set(posKey(men), men);
    for (const t of m.token_mentions) {
      if (t.kind !== "ident") continue;
      // Prefer the AST's QUALIFIED spelling where it has one. The token carries only the tail, and
      // judging `StatusCode::BAD_REQUEST` by `BAD_REQUEST` alone would file a foreign constant in
      // the same bucket as a daemon name nobody can find — which would make the pin unreadable.
      const men = labelledAt.get(posKey(t));
      const spelling = men && men.name.includes("::") ? men.name : t.text;
      const r = resolveName(m, spelling);
      if (r.kind === "LITERAL") continue;
      bumpDrop(r.bucket ?? r.kind, spelling, modId(m.key));
    }
  }
  // A MOVED BUCKET MUST BE ADJUDICABLE IN THE MOMENT IT MOVES. A bare `792/791` cannot tell a second
  // admitter's +1 from an ordinary feature commit's +49, and a pin nobody can read in the moment is
  // a pin that gets widened away. So a moved bucket prints its RAREST members with their module: a
  // name that has just arrived occurs once, and sorting by frequency floats it to the top.
  const rarest = (b) => [...(dropMembers[b] ?? new Map())].sort((x, y) => x[1] - y[1]).slice(0, 6).map(([k]) => k).join(", ");
  const dropGain = [], dropStale = [];
  for (const [b, n] of Object.entries(dropped)) {
    if (PINNED.unadjudicable[b] === undefined) dropGain.push(`UNRECORDED BUCKET ${b} (${n}) rarest: ${rarest(b)}`);
    else if (n !== PINNED.unadjudicable[b]) dropGain.push(`${b} ${n}/${PINNED.unadjudicable[b]} — rarest members: ${rarest(b)}`);
  }
  for (const [b, n] of Object.entries(PINNED.unadjudicable)) if (dropped[b] === undefined && n !== 0) dropStale.push(`${b} vanished (pinned ${n})`);

  ok("EVERY CONSTANT-SHAPED NAME THIS CENSUS CANNOT ADJUDICATE IS COUNTED IN A NAMED BUCKET, AND THE BUCKETS ARE PINNED IN BOTH DIRECTIONS — the token population is total, but the population this gate JUDGES is `token ∩ resolves-to-a-family`, and resolution is a PARTIAL function whose failures used to be skipped in silence; that is the same defect one layer down from the one this file was rebuilt to fix, and it is answered by COUNTING rather than by a third hardening edge, because a name the census cannot tie to a declaration is exactly what a second admitter looks like from here and a landfill of five thousand is not a residual — a bucket with a cause and a number is",
    dropGain.length === 0 && dropStale.length === 0,
    [...dropGain, ...dropStale].join(" ; ") || Object.entries(dropped).sort((a, b) => b[1] - a[1]).map(([b, n]) => `${b}=${n}`).join(" "));

  ok("EVERY TOKEN THAT RESOLVES TO AN ODK FAMILY CARRIES A SYNTACTIC LABEL — the claim is over the RESOLVED population and says so, because a review demonstrated the wider reading false: mentions come from the file's raw token stream, which is total by construction, but a token this census cannot RESOLVE is not judged here at all, it is counted in the bucket pin above; what this assertion entails is that no name the census CAN read reaches a position the role-assigner never labelled",
    silent.length === 0,
    silent.slice(0, 8).join(" ; ") || `${judgedTokens} family-resolving token positions, every one labelled`);

  ok("AND NO LABEL SITS WHERE NO TOKEN DOES — the reverse edge of the same claim: a mention the extractor synthesises rather than reads would let the population drift back into being the visitor's own product, so the only synthesised mentions permitted are the followed expansions of compile-time assembly, and they are counted separately rather than matched",
    orphan.length === 0,
    orphan.slice(0, 8).join(" ; ") || `${tokenMentions} tokens walked, every family label anchored on one`);

  ok("THE TOKEN POPULATION ITSELF IS PINNED — the totality claim is only as good as the walk that produces it, and a tokeniser that quietly stops descending into a group would shrink the population and the silence check together without failing either; this count moves whenever the daemon's literals or constants move, which is the intent",
    tokenMentions === PINNED.tokenMentions && judgedTokens === PINNED.judgedTokenPositions,
    `${tokenMentions}/${PINNED.tokenMentions} tokens, ${judgedTokens}/${PINNED.judgedTokenPositions} of them family-resolving`);

  // ---------------------------------------------------------------- TOTALITY: spliced files
  const unsplicedCode = [];
  let dataStr = 0, dataBytes = 0, splicedCode = 0, dataOpaqueArg = 0;
  for (const m of modules) {
    for (const inc of m.includes) {
      if (inc.mac === "include") {
        if (inc.spliced) splicedCode++; else unsplicedCode.push(`${modId(m.key)} ${inc.src}:${inc.line} include!(${inc.arg ?? "«unreadable»"})`);
        continue;
      }
      if (inc.mac === "include_str") dataStr++; else dataBytes++;
      if (inc.arg === null) dataOpaqueArg++;
    }
  }
  ok("EVERY `include!` HAS BEEN SPLICED INTO THE MODULE THAT INCLUDES IT — an `include!` puts another file's TOKENS into this file, so a target the walk has not read is a hole exactly the size of that file, and it was a fully green second admitter: the whole shadow admitter lived in the unwalked file and the including module's census was unchanged; a target that cannot be resolved or read aborts extraction rather than reporting an absence",
    unsplicedCode.length === 0 && splicedCode === PINNED.includes.splicedCode,
    unsplicedCode.join(" ; ") || `${splicedCode}/${PINNED.includes.splicedCode} spliced code includes`);

  ok("THE DATA-INCLUDING FORMS ARE PINNED RATHER THAN FOLLOWED, and that is sound for a different reason than the code form — `include_str!`/`include_bytes!` put BYTES in the program, not Rust, so no writer call can live in one; a constant initialised from one is UNREADABLE to this census and therefore OPAQUE, which is COUNTED IN THE `opaque-initialiser` BUCKET above rather than refused: an earlier version of this sentence claimed the resolver assertion refused it outright, and that assertion iterates writer calls only, so an OPAQUE constant reaching a RAW FILESYSTEM call was neither refused nor counted",
    dataStr === PINNED.includes.dataStr && dataBytes === PINNED.includes.dataBytes && dataOpaqueArg === PINNED.includes.dataOpaqueArg,
    `include_str!=${dataStr}/${PINNED.includes.dataStr} include_bytes!=${dataBytes}/${PINNED.includes.dataBytes} with ${dataOpaqueArg}/${PINNED.includes.dataOpaqueArg} non-literal arguments`);

  // ---------------------------------------------------------------- TOTALITY: constructed names
  //
  // A CONSTRUCTED NAME IS IN NO TOKEN. `concat!("od", "k-domain-ontologies")` puts a family name in a
  // writer's arguments while neither piece is one, so the token population cannot see it and neither
  // could the role set. The extractor FOLLOWS compile-time assembly into its expansion and emits the
  // assembled value as a synthesised mention, which then carries the ordinary role of wherever it
  // sits. An assembly with a piece this census cannot read is reported unreadable and refused here.
  const unreadableAsm = [], testAsm = [];
  let prodAsm = 0;
  for (const m of modules) {
    for (const a of m.assemblies) {
      if (!a.compile_time) continue;
      if (a.in_test) { testAsm.push(`${modId(m.key)}::${a.in_fn}`); continue; }
      prodAsm++;
      if (!a.readable) unreadableAsm.push(`${modId(m.key)} ${a.src}:${a.line} ${a.kind}! has a piece this census cannot read`);
    }
  }
  ok("EVERY COMPILE-TIME NAME ASSEMBLY IN PRODUCTION IS READABLE AND IS FOLLOWED INTO ITS EXPANSION — `concat!` and `stringify!` are the two constructs that can produce a `&'static str` family name that exists in no token, so evaluating them is what keeps the token population total for constructed names; an assembly this census cannot evaluate is REFUSED rather than assumed innocent, and the test-region population is pinned so a production one cannot be relocated into it",
    unreadableAsm.length === 0 && prodAsm === PINNED.compileAssembly.production && testAsm.length === PINNED.compileAssembly.test,
    unreadableAsm.join(" ; ") || `${prodAsm}/${PINNED.compileAssembly.production} production, ${testAsm.length}/${PINNED.compileAssembly.test} under a bare #[cfg(test)]`);

  // A fragment is a proper substring of a recorded family name: the material an assembly needs. The
  // daemon contains dozens of them as ordinary words — "receipts", "session", "ontology" — so their
  // mere presence is not a finding. What must be impossible is a fragment inside an ASSEMBLING
  // construct in a writer's or filesystem call's own arguments, which is where an assembled family
  // name reaches a write without ever being a name.
  const FAMILY_NAMES = Object.keys(RECORDED_PLANE);
  const isFragment = (s) => typeof s === "string" && s.length >= 2 && !FAMILY_NAMES.includes(s) && FAMILY_NAMES.some((f) => f.includes(s));
  const assembledInWrite = [];
  for (const m of modules) {
    for (const a of m.assemblies) {
      if (a.in_test || !(a.in_write_arg || a.in_fs_arg)) continue;
      const frags = [...new Set(a.pieces.filter(isFragment))];
      if (frags.length) assembledInWrite.push(`${modId(m.key)}::${a.in_fn} assembles with ${a.kind} from ${frags.map((f) => JSON.stringify(f)).join(", ")}`);
    }
  }
  ok("NO STRING-ASSEMBLING CONSTRUCT INSIDE A PRODUCTION WRITER'S OR FILESYSTEM CALL'S OWN ARGUMENTS TAKES A FRAGMENT OF A FAMILY NAME AS A PIECE — the fragments themselves are ordinary words this daemon uses everywhere and are not a finding; what is refused is the ASSEMBLY, because a name built from `\"od\"` and `\"k-domain-ontologies\"` is a family name in the writer's hand and a family name in no token anywhere",
    assembledInWrite.length === 0,
    assembledInWrite.slice(0, 8).join(" ; ") || `${modules.reduce((a, m) => a + m.assemblies.filter((x) => !x.in_test && (x.in_write_arg || x.in_fs_arg)).length, 0)} assemblies inside production writer arguments, none from a fragment`);

  // ---------------------------------------------------------------- classify every mention
  const observedRoles = new Set();
  const unknownRoles = [];
  const observed = new Map();   // family -> { admits:Set, touches:Set }
  const testWrites = new Map(); // family -> Set
  let familyMentions = 0;
  for (const m of modules) {
    for (const men of m.mentions) {
      const r = resolveName(m, men.name);
      if (r.kind !== "LITERAL" || !isFamily(r.value)) continue;
      familyMentions++;
      observedRoles.add(men.role);
      const meaning = ROLE_MEANING[men.role];
      if (!meaning) {
        unknownRoles.push(`${modId(m.key)}::${men.in_fn} names "${r.value}" in role \`${men.role}\``);
        continue;
      }
      if (!observed.has(r.value)) observed.set(r.value, { admits: new Set(), touches: new Set() });
      if (men.in_test) {
        if (meaning === "admits") {
          if (!testWrites.has(r.value)) testWrites.set(r.value, new Set());
          testWrites.get(r.value).add(modId(m.key));
        }
        continue;
      }
      const e = observed.get(r.value);
      e.touches.add(modId(m.key));
      if (meaning === "admits") e.admits.add(modId(m.key));
    }
  }

  // A WRITER CALL WHOSE FAMILY THIS CENSUS CANNOT READ, IN A FUNCTION THAT NAMES ONE, ADMITS IT.
  //
  // This census does no dataflow, by design — so `let fams = ["<family>"]; persist_record(d, fams[0],
  // …)` puts the literal in the function body and an unreadable expression at the call. Five
  // constructs of exactly that shape (struct-literal field, array element, tuple element, arm guard,
  // macro argument) reached the writer without the family ever appearing in the writer's own
  // arguments. The conservative reading — the function names it, the function writes with something
  // it will not spell — is that the module admits it. On the tree as it stands this rule attributes
  // NOTHING, which is what makes it safe to state in this direction: it is inert until an
  // indirection appears, and then it is a finding.
  for (const m of modules) {
    for (const c of m.calls) {
      if (c.kind !== "write" || c.in_test) continue;
      if (c.leaves.some((l) => { const r = resolveName(m, l); return r.kind === "LITERAL" && isFamily(r.value); })) continue;
      for (const l of m.fn_leaves[c.in_fn] ?? []) {
        const r = resolveName(m, l);
        if (r.kind !== "LITERAL" || !isFamily(r.value)) continue;
        if (!observed.has(r.value)) observed.set(r.value, { admits: new Set(), touches: new Set() });
        observed.get(r.value).admits.add(modId(m.key));
        observed.get(r.value).touches.add(modId(m.key));
      }
    }
  }

  // THE ROLE WORLD IS CLOSED. Every judgement below reads a role; a role this file cannot classify
  // is a mention whose meaning is unknown, and unknown must be RED rather than skipped.
  ok("every mention of an ODK family sits in a SYNTACTIC ROLE this gate classifies — a family name reaching a position no rule below understands is reported as an unclassified mention and fails, so a construct the census stops reading becomes a FINDING rather than an absence, which is the only direction a judgement derived from absence can be trusted in",
    unknownRoles.length === 0,
    unknownRoles.join(" ; ") || `${observedRoles.size} roles observed, all classified: ${[...observedRoles].sort().join(", ")}`);

  // ---------------------------------------------------------------- the commissioned claim
  for (const [family, owner] of Object.entries(ONTOLOGY_FAMILIES)) {
    const admits = [...(observed.get(family)?.admits ?? [])].sort();
    ok(`EXACTLY ONE MODULE ADMITS \`${family}\` — entailed from the whole daemon's source rather than from a probe of the surface that would answer the same either way, and keyed by module PATH so that two files sharing a basename cannot report as one`,
      admits.length === 1 && admits[0] === owner,
      admits.length ? `admitted by ${admits.join(", ")}` : "no module admits it — the census has lost the owner, which is not the same as proving the claim");
  }

  // ---------------------------------------------------------------- the plane ratchet
  const gainedAdmit = [], gainedTouch = [], staleAdmit = [], staleTouch = [], unrecorded = [];
  for (const [family, e] of observed) {
    const rec = RECORDED_PLANE[family];
    if (!rec) { unrecorded.push(`${family} (admitted by ${[...e.admits].sort().join(", ") || "nobody"})`); continue; }
    for (const mod of e.admits) if (!rec.admits.includes(mod)) gainedAdmit.push(`${family} gained ${mod}`);
    for (const mod of e.touches) if (!rec.touches.includes(mod)) gainedTouch.push(`${family} newly named by ${mod}`);
    for (const mod of rec.admits) if (!e.admits.has(mod)) staleAdmit.push(`${family} no longer admitted by ${mod}`);
    for (const mod of rec.touches) if (!e.touches.has(mod)) staleTouch.push(`${family} no longer named by ${mod}`);
  }
  for (const family of Object.keys(RECORDED_PLANE)) if (!observed.has(family)) staleTouch.push(`${family} has vanished from the daemon entirely`);

  ok("NO ODK FAMILY GAINS AN ADMISSION PATH BEYOND THE RECORDED MAP — the weaker ratchet this run is entitled to claim, and deliberately not the no-second-spine property: three families have two production admitters today and are recorded UNDER ADJUDICATION rather than endorsed",
    gainedAdmit.length === 0 && unrecorded.length === 0,
    [...gainedAdmit, ...unrecorded.map((u) => `unrecorded family ${u}`)].join(" ; ") || `${observed.size} families, admitter map unchanged`);

  ok("NO MODULE NAMES AN ODK FAMILY IT IS NOT RECORDED AS NAMING — the ratchet a rung below admission, because a family name reaching a new module's function body cannot be shown harmless without dataflow this census deliberately does not do; the conservative reading is that it is a finding to run down, not a fact to wave through",
    gainedTouch.length === 0,
    gainedTouch.join(" ; ") || `${[...observed.values()].reduce((a, e) => a + e.touches.size, 0)} module-family references, all recorded`);

  ok("THE RECORDED MAP IS NOT STALE IN EITHER DIRECTION — scar 4's second half: a derived closed world is only as wide as what it derives over, so an admitter or a reference that DISAPPEARS must re-derive the pin in the commit that removes it rather than leaving a record that quietly over-claims what is still true",
    staleAdmit.length === 0 && staleTouch.length === 0,
    [...staleAdmit, ...staleTouch].join(" ; ") || "every recorded admitter and reference is still present in source");

  // ---------------------------------------------------------------- the test filter, both ways
  const testGain = [], testStale = [];
  for (const [family, mods] of testWrites) {
    const rec = RECORDED_TEST_WRITES[family] ?? [];
    for (const mod of mods) if (!rec.includes(mod)) testGain.push(`${family} gained a test write in ${mod}`);
  }
  for (const [family, rec] of Object.entries(RECORDED_TEST_WRITES)) {
    for (const mod of rec) if (!(testWrites.get(family) ?? new Set()).has(mod)) testStale.push(`${family} no longer written under test by ${mod}`);
  }
  ok("WRITES UNDER A BARE `#[cfg(test)]` ARE CLASSIFIED AS TEST WRITES AND PINNED AS SUCH, never dropped — the filter fails toward PRODUCTION (`cfg(any(test, …))`, `cfg_attr` and feature gates all count as production), and pinning what it EXCLUDES is what stops the exclusion becoming a hiding place: a production write relocated under a test attribute leaves the production map and arrives here, failing twice rather than passing once",
    testGain.length === 0 && testStale.length === 0,
    [...testGain, ...testStale].join(" ; ") || `${[...testWrites.values()].reduce((a, s) => a + s.size, 0)} test writes across ${testWrites.size} families, all recorded`);

  // ---------------------------------------------------------------- resolution is total
  let wFamily = 0, wLiteral = 0, wRuntime = 0;
  const wUnresolved = [];
  for (const m of modules) {
    for (const c of m.calls) {
      if (c.kind !== "write" || c.in_test) continue;
      const rs = c.leaves.map((l) => resolveName(m, l));
      if (rs.some((r) => r.kind === "LITERAL" && isFamily(r.value))) { wFamily++; continue; }
      const bad = c.leaves.filter((_, i) => rs[i].kind === "UNRESOLVED" || rs[i].kind === "OPAQUE");
      if (bad.length) { wUnresolved.push(`${modId(m.key)}::${c.in_fn} → ${bad.join(", ")}`); continue; }
      if (rs.some((r) => r.kind === "LITERAL")) wLiteral++; else wRuntime++;
    }
  }
  ok("EVERY CONSTANT-SHAPED NAME IN A PRODUCTION WRITER CALL RESOLVES TO A DECLARATION THIS CENSUS CAN SEE — no name is waved through as probably-harmless, because a name the census cannot tie to a declaration it can see is exactly what a second admitter looks like from here",
    wUnresolved.length === 0,
    wUnresolved.slice(0, 8).join(" ; ") || `${wFamily} name a family, ${wLiteral} name a non-ODK family, ${wRuntime} take it as a runtime parameter`);

  ok("THE WRITER-CALL POPULATION IS PINNED IN ALL THREE BUCKETS — including the calls whose family is a RUNTIME PARAMETER and therefore cannot be resolved from source at all; naming that bucket and pinning its size is what keeps it from silently absorbing the calls this census is supposed to be reading",
    wFamily === PINNED.productionWriterCalls.family && wLiteral === PINNED.productionWriterCalls.nonFamilyLiteral && wRuntime === PINNED.productionWriterCalls.runtimeParameter,
    `family=${wFamily}/${PINNED.productionWriterCalls.family} non-ODK=${wLiteral}/${PINNED.productionWriterCalls.nonFamilyLiteral} runtime=${wRuntime}/${PINNED.productionWriterCalls.runtimeParameter}`);

  // ---------------------------------------------------------------- the traversal's own reach
  const prodFs = modules.reduce((a, m) => a + m.fs_calls.filter((c) => !c.in_test).length, 0);
  ok("THE TRAVERSAL'S REACH IS PINNED UNDER THE JUDGEMENTS THAT DEPEND ON IT — every assertion here reads the census, so a walk that quietly stops reaching a construct weakens all of them at once without failing any one of them; these counts collapse when the walk regresses even where no rule above has an opinion about the construct it stopped reaching",
    familyMentions === PINNED.familyMentions && prodFs === PINNED.productionFsCalls,
    `${familyMentions}/${PINNED.familyMentions} family mentions, ${prodFs}/${PINNED.productionFsCalls} production filesystem calls`);

  // ---------------------------------------------------------------- who may mint the name
  // READ FROM THE MENTION, NOT FROM THE CONSTANT TABLE. A scalar `const X: &str = "<family>"` lands
  // in `consts`, but the same literal inside `const XS: &[&str] = &["<family>"]` does not — and both
  // mint the name just as effectively. The mention carries its role, so both forms are one rule.
  // `static` is covered because `static-init` is a declaring role; `concat!("odk-", "…")` is covered
  // by the role-closure assertion above, because its tokens surface under the role `macro:concat`,
  // which this gate does not classify and therefore fails on.
  const foreignDeclarations = [];
  for (const m of modules) {
    const here = modId(m.key);
    const seen = new Set();
    for (const men of m.mentions) {
      if (men.role !== "const-init" && men.role !== "static-init") continue;
      const r = resolveName(m, men.name);
      if (r.kind !== "LITERAL") continue;
      const owner = ONTOLOGY_FAMILIES[r.value];
      if (!owner || owner === here || seen.has(r.value)) continue;
      seen.add(r.value);
      foreignDeclarations.push(`${here} declares "${r.value}" (owned by ${owner})`);
    }
  }
  ok("ONLY THE OWNING MODULE DECLARES A CONSTANT NAMING ONE OF ITS ONTOLOGY FAMILIES — a second name minted elsewhere makes every later use of it read as innocent local code, which is how a family reference slips past a census that only inspects call sites; `static` declares as surely as `const` does, and a literal inside an array declares as surely as a scalar, and the previous census could see neither",
    foreignDeclarations.length === 0,
    foreignDeclarations.join(" ; ") || "every ontology family constant is declared by its owner");

  // ---------------------------------------------------------------- the raw filesystem lane
  const rawWrites = [];
  for (const m of modules) {
    for (const c of m.fs_calls) {
      if (c.in_test) continue;
      const near = [...(m.fn_leaves[c.in_fn] ?? []), ...c.leaves];
      const fams = [...new Set(near.map((l) => resolveName(m, l)).filter((r) => r.kind === "LITERAL" && isFamily(r.value)).map((r) => r.value))]
        .filter((f) => ONTOLOGY_FAMILIES[f] && ONTOLOGY_FAMILIES[f] !== modId(m.key));
      if (fams.length) rawWrites.push(`${modId(m.key)}::${c.in_fn} calls ${c.callee} and names ${fams.join(", ")}`);
    }
  }
  ok("NO PRODUCTION FUNCTION MAKES A RAW FILESYSTEM CALL AND NAMES AN ONTOLOGY FAMILY IT DOES NOT OWN — the record-writer census cannot see a lane that bypasses the writers entirely and puts bytes in a family directory itself; the enclosing function is read for EVERY declaration form, and reading it only for free functions left this rule dead for every production filesystem call sitting in an impl method",
    rawWrites.length === 0,
    rawWrites.join(" ; ") || `${prodFs} production filesystem calls, none in a function naming a family it does not own`);

  // ---------------------------------------------------------------- resolve-and-write
  const resolveAndWrite = [];
  for (const m of modules) {
    for (const fn of m.resolve_and_write_fns ?? []) {
      const arms = (m.resolver_arms ?? {})[fn] ?? [];
      if (arms.some((a) => { const r = resolveName(m, a); return r.kind === "LITERAL" && isFamily(r.value); })) resolveAndWrite.push(`${modId(m.key)}::${fn}`);
    }
  }
  ok("no function that RESOLVES a family name through a `match` arm also WRITES a record — conservative, dataflow-free and fail-closed: a scheme-mapper that admits is a second spine whatever the plumbing between them looks like, and widening this rule later is a governed act rather than a convenience",
    resolveAndWrite.length === 0,
    resolveAndWrite.join(" ; ") || "no resolving function writes");

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
