#!/usr/bin/env node
// check:foundry-capability-build — M10.6: the production Foundry capability-build pipeline, as a gate
// (docs/architecture/components/hypervisor/foundry.md § The Production Capability-Build Pipeline;
// ACC-16; R-235).
//
// CANON. One eligible, immutable snapshot through a registered spec and run plan, isolated training,
// checkpoint and resume, artifact and cost lineage, and an independent evaluation. Success produces a
// governed worker CANDIDATE and stops. A resumed run must be equivalent to an uninterrupted one under
// its declared determinism class. Torn or unavailable inputs fail closed.
//
// MOST OF THAT WAS ALREADY BUILT, and this gate says which parts rather than claiming them. v1 already
// binds the dataset and recipe content hashes, the trainer backend profile and the `seed`;
// `verify_checkpoint_projection` already fails closed six ways; and `qualification.promotion_boundary`
// already pins three constants, so a Foundry run promoting its own output is unrepresentable. Those are
// TRIPWIRES here — read from source so a regression is caught, and named as structure so nobody reads
// an unfalsifiable clause as proof.
//
// WHAT WAS MISSING WAS ONE COMPARISON AND FOUR BINDINGS. `verify_checkpoint_projection` has always
// returned model, optimizer, scheduler and rng digests and COMPARED NONE OF THEM — and it could not,
// because equivalence is a claim about two runs and the uninterrupted one never happened here. So the
// caller submits both digest sets, the plane derives the verdict from the DECLARED class, and clause 4
// is the unit.
//
//   PURE    — the deriver over the registered fixtures: the three laws the contract could not carry.
//   SEAM    — the v2 successor: the four bindings required, the class closed, v1 still valid.
//   SOURCE  — the daemon: the class table, the derived verdict, the six fail-closed refusals, the
//             promotion boundary's constants, and the version-spanning read.
//   PLANE   — full mode, one isolated daemon: a recipe, a materialized snapshot, a v2 program, and
//             THE SAME rng difference judged by two declared classes with opposite verdicts.
//
//   --drills           CI-bound, seconds: PURE, SEAM, SOURCE, the binding and the verdict rules.
//   --mutation         planted defects against the deriver — each must go red.
//   (default)          the drills, then PLANE. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/foundry-capability-build.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "foundry-capability-build.mjs");
const META = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const PLANE_SRC = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "foundry_execution_routes.rs");
const CANON = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "foundry.md");
const FIXTURES = path.join(META, "fixtures", "foundry-training-program-v2");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-235";

const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const SEAM = self("seam");
const SOURCE = self("source");
const PLANE = self("plane");

export const CLAUSES = [
  { n: 1, demand: "EVERY OUTPUT BINDS ITS LINEAGE, and this unit added the four that were missing: the policy-bound view AT ITS EXACT REVISION, the retention class, the declared determinism class and the spend accounting — beside the dataset and recipe content hashes, the trainer backend profile and the `seed` that v1 already carried. A view bound by name rather than by revision is one whose supersession is undetectable", executed_by: [SEAM, PURE, PLANE] },
  { n: 2, demand: "THE SUCCESSOR DID NOT MAKE ITS PREDECESSOR DISAPPEAR: v1's `wire_mutation_policy` is `forbidden` so the bindings landed as v2, and v1 REMAINS VALID for programs already admitted under it — the program reads span both versions, because a read that filtered on one would be a disappearance wearing a migration's clothes", executed_by: [SEAM, SOURCE, PLANE] },
  { n: 3, demand: "THE DETERMINISM CLASS IS DECLARED BEFORE THE RUN, from a closed set of three: a class chosen once the digests are known describes what happened instead of committing to something the run can fail, and `statistical` makes no state claim at all so it must be stated in advance rather than retreated to", executed_by: [SEAM, PURE] },
  { n: 4, demand: "THE CLASS ACTUALLY SELECTS, WHICH IS THIS UNIT: `verify_checkpoint_projection` has always computed model, optimizer, scheduler and rng digests and compared NONE of them, so the resume guarantee asserted something nothing checked. The declared class names which digests must match — `bitwise` all four, `state_equivalent` three, `statistical` none — and the SAME rng difference is a divergence under one class and equivalence under another", executed_by: [PURE, SOURCE, PLANE] },
  { n: 5, demand: "A DIVERGENCE NOBODY MEASURED IS NOT A FINDING, and a divergence measured and ignored is worse: a `resume_divergent` program carries the comparison that produced it, and a comparison whose class was not satisfied moves the program to that terminal status rather than leaving it running", executed_by: [PURE, PLANE] },
  { n: 6, demand: "THE VERDICT IS THE PLANE'S, NEVER THE CALLER'S: the caller submits two digest sets and nothing else, because the party that ran the two trainings does not grade them. A body carrying `class_satisfied` is refused by its own typed code before the parse, rather than by a generic unknown-field error the caller would have to guess at", executed_by: [SOURCE, PLANE] },
  { n: 7, demand: "TORN OR UNAVAILABLE INPUTS FAIL CLOSED and are never recreated from mutable source — an incomplete checkpoint, destroyed material, material not on disk, bytes whose digest is not the admitted artifact hash, a checkpoint whose program fingerprints disagree, and one whose status, cursor or token count disagree with the projection are six typed refusals. ALREADY BUILT: this clause is a tripwire on work v1 did, not a claim this unit constructed it", executed_by: [SOURCE] },
  { n: 8, demand: "SPEND IS PART OF THE ARTIFACT: every external training resource carries an admitted reservation, a reconciled outcome and a cleanup obligation, and an unreconciled or exceeded outcome FORBIDS a candidate — a successful artifact with unknown spend is a failed run, not a successful one with an accounting note. Unknown spend and zero spend are different facts, and the member named `reconciliation` is the interrupted-run resume pointer and not this", executed_by: [PURE, SEAM] },
  { n: 9, demand: "SUCCESS PRODUCES A CANDIDATE AND STOPS: `proposal_only`, `governance_approval_required` and `runtime_activation_performed` are constants, so a Foundry run that published, installed, granted authority or promoted its own output is UNREPRESENTABLE. ALREADY BUILT — a tripwire, and named as one", executed_by: [SOURCE, PURE] },
  { n: 10, demand: "THE THREE LAWS THE REGISTERED CONTRACT COULD NOT CARRY ARE ENFORCED AND NAMED WHERE THEY LIVE: `non_empty` is never satisfied by an object, an invariant path cannot reach into a nullable member, and the operator set has no form for \"empty when that reads X\" or \"compare only the digests this enum selects\" — so the laws are in the deriver and the plane, and the contract says so rather than reading as a contract with nothing to enforce", executed_by: [SOURCE, PURE] },
  { n: 11, demand: "THE DERIVER REACHES NOTHING — no plane, no file, no clock, no network — so a relying party holding a program can re-derive every one of these answers without the estate being up", executed_by: [SOURCE] },
  { n: 12, demand: "THE PIPELINE'S OWN CHAIN RUNS: a recipe admitted, a snapshot materialized from it, and a program admitted against that exact snapshot under the successor", executed_by: [PLANE], absence: { what: "THE INDEPENDENT EVALUATION IS NAMED, NOT DRIVEN, AND M10.5's GATE IS PINNED BY NOTHING. (1) Canon asks this pipeline for 'an independent evaluation' of the candidate it produces. The evaluator plane is M10.4's — five registered evaluation contracts with their own determinism vocabulary — and this gate does not stand it up or drive a candidate through it, so the evaluation half is a correctly-typed pointer whose far end is unproven here. (2) MEASURED 2026-09-22, and it is a finding about the layer below this unit: `verify-hypervisor-foundry-spec-contracts.mjs` is M10.5's gate, it HAS an npm script (`check:foundry-spec-contracts`), and it has NO floor row and ZERO hits in ci.yml. Its only executor is `check-acceptance-bounded-improvement.mjs` clause N1, and no acceptance runner is CI-bound either — which is by design, since the ACC runners are this program's hand-run verdict table. So a unit gate's only path to execution is a hand-run composer and nothing pins its assertion count. It is M10.5's gate, not this unit's, so it is named rather than adopted: binding another unit's gate silently changes what that unit claims", owner: `M10.4's evaluator plane for the independent evaluation, and M10.5's owner for whether its spec-contract gate should be floored and CI-bound (${OWNER_Q})` } },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.foundry-capability-build-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, seam: null, source: null, plane: null, verdict: null, mutation: null };
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  results.push(row);
  evidence.drills.push({ ...row, at: new Date().toISOString() });
  console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`);
  return row.pass;
}
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `foundry-capability-build-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const fixture = (name) => readJson(path.join(FIXTURES, `${name}.json`));
const spoil = (record, mutate) => { const copy = JSON.parse(JSON.stringify(record)); mutate(copy); return copy; };

const EQUIVALENT = () => fixture("positive-resumed-and-equivalent");
const NEVER = () => fixture("positive-never-interrupted");
const DIVERGENT = () => fixture("positive-resume-divergent-and-measured");

// ---- PURE ----------------------------------------------------------------------------------------------------
export function pureFindings(lib) {
  const f = [];
  const must = (what, findings, shouldBeEmpty) => {
    const empty = findings.length === 0;
    if (empty !== shouldBeEmpty) f.push(`${what}: ${shouldBeEmpty ? `refused a clean program (${findings.slice(0, 2).join("; ")})` : "accepted a spoiled one"}`);
  };

  must("clean/never-interrupted", lib.programFindings(NEVER()), true);
  must("clean/resumed-equivalent", lib.programFindings(EQUIVALENT()), true);
  must("clean/divergent-and-measured", lib.programFindings(DIVERGENT()), true);

  // LAW 1 — the divergence was measured, both edges. EACH CASE ISOLATES ITS OWN CHECK: the obvious
  // spoiling of `class_satisfied` on an otherwise-matching comparison ALSO trips law 2's
  // "unsatisfied while everything matches", so a case asserting only "some finding appeared" let
  // law 1's second edge be deleted while law 2 still caught it. Making the digests differ removes
  // law 2 from the picture and leaves only the edge this case is named for.
  must("law1/divergent-with-no-comparison", lib.programFindings(spoil(DIVERGENT(), (p) => { p.resume_equivalence = null; })), false);
  const ignored = lib.programFindings(spoil(EQUIVALENT(), (p) => {
    p.resume_equivalence.class_satisfied = false;
    p.resume_equivalence.resumed.model_state_hash = `sha256:${"9".repeat(64)}`;
  }));
  must("law1/measured-and-ignored", ignored, false);
  if (!ignored.some((line) => /measured and not acted on/u.test(line))) {
    f.push("law1/measured-and-ignored: refused for some other reason than the divergence being ignored");
  }

  // LAW 2 — the class selects. THE TWO HALVES ARE ASSERTED SEPARATELY, because a check that only
  // proved `bitwise` catches an rng change would pass just as well if every class caught it.
  const rngMoved = (p) => { p.resume_equivalence.resumed.rng_state_hash = `sha256:${"9".repeat(64)}`; };
  must("law2/bitwise-sees-an-rng-change", lib.programFindings(spoil(EQUIVALENT(), (p) => { p.determinism_class = "bitwise"; rngMoved(p); })), false);
  must("law2/state-equivalent-does-not", lib.programFindings(spoil(EQUIVALENT(), (p) => { p.determinism_class = "state_equivalent"; rngMoved(p); })), true);
  must("law2/claims-satisfied-while-model-differs", lib.programFindings(spoil(EQUIVALENT(), (p) => { p.resume_equivalence.resumed.model_state_hash = `sha256:${"9".repeat(64)}`; })), false);
  must("law2/invented-class", lib.programFindings(spoil(EQUIVALENT(), (p) => { p.determinism_class = "mostly_the_same"; })), false);
  // A DIVERGENT record whose selected digests MATCH isolates the "unsatisfied while everything
  // matches" edge: law 1 is content (the status and the comparison agree) and only law 2 fires.
  const falseAlarm = lib.programFindings(spoil(DIVERGENT(), (p) => { p.resume_equivalence.resumed = { ...p.resume_equivalence.uninterrupted }; }));
  must("law2/unsatisfied-while-everything-matches", falseAlarm, false);
  if (!falseAlarm.some((line) => /does not actually see/u.test(line))) {
    f.push("law2/unsatisfied-while-everything-matches: refused for some other reason than the class not seeing the claimed divergence");
  }
  // STATISTICAL IS ABOUT THE STATUS, not the claim — a statistical program selects no digests, so
  // an unsatisfied statistical claim is already law 2's generic edge and a second rule saying the
  // same thing could be deleted unnoticed. What only this rule catches is going TERMINAL on state.
  const statistical = lib.programFindings(spoil(DIVERGENT(), (p) => {
    p.determinism_class = "statistical";
    p.resume_equivalence.resumed = { ...p.resume_equivalence.uninterrupted };
    p.resume_equivalence.class_satisfied = true;
  }));
  must("law2/statistical-went-terminal-on-state", statistical, false);
  if (!statistical.some((line) => /makes no state claim at all/u.test(line))) {
    f.push("law2/statistical-went-terminal-on-state: refused for some other reason than a statistical class going terminal");
  }
  // A one-sided comparison is compared against nothing; no other check sees it.
  const oneSided = lib.programFindings(spoil(EQUIVALENT(), (p) => { delete p.resume_equivalence.resumed; }));
  must("law2/one-sided-comparison", oneSided, false);
  if (!oneSided.some((line) => /missing one of its two sides/u.test(line))) {
    f.push("law2/one-sided-comparison: refused for some other reason than a side being absent");
  }

  // LAW 3 — spend.
  // BY MESSAGE: an absent `spend` also trips the reservation and cleanup checks, so a case asserting
  // only "some finding appeared" let the early guard be deleted while those two still caught it.
  const noSpend = lib.programFindings(spoil(NEVER(), (p) => { delete p.spend; }));
  must("law3/no-spend", noSpend, false);
  if (!noSpend.some((line) => /carries no spend accounting at all/u.test(line))) {
    f.push("law3/no-spend: refused for some other reason than spend being absent entirely");
  }
  must("law3/no-reservation", lib.programFindings(spoil(NEVER(), (p) => { delete p.spend.reservation_ref; })), false);
  must("law3/no-cleanup-obligation", lib.programFindings(spoil(NEVER(), (p) => { delete p.spend.cleanup_obligation_ref; })), false);
  must("law3/invented-outcome", lib.programFindings(spoil(NEVER(), (p) => { p.spend.reconciled_outcome = "probably_fine"; })), false);
  for (const outcome of lib.SPEND_FORBIDS_CANDIDATE) {
    must(`law3/${outcome}-with-a-candidate`, lib.programFindings(spoil(NEVER(), (p) => { p.spend.reconciled_outcome = outcome; p.qualification = { verdict: "qualified" }; })), false);
  }
  // And the converse: a forbidding outcome with NO candidate is not itself a finding, because a run
  // may legitimately end unable to determine its spend.
  must("law3/unreconciled-without-a-candidate", lib.programFindings(spoil(NEVER(), (p) => { p.spend.reconciled_outcome = "spend_unreconciled"; })), true);

  // The bindings this unit added.
  must("binding/no-view", lib.programFindings(spoil(NEVER(), (p) => { delete p.policy_bound_data_view_ref; })), false);
  must("binding/view-without-a-revision", lib.programFindings(spoil(NEVER(), (p) => { delete p.policy_bound_data_view_revision_ref; })), false);
  must("binding/no-retention-class", lib.programFindings(spoil(NEVER(), (p) => { delete p.retention_class_ref; })), false);
  must("binding/divergent-still-claims-a-candidate", lib.programFindings(spoil(DIVERGENT(), (p) => { p.qualification = { verdict: "qualified" }; })), false);

  // The promotion boundary, read as a TRIPWIRE.
  const withBoundary = (over) => spoil(NEVER(), (p) => { p.qualification = { promotion_boundary: { proposal_only: true, governance_approval_required: true, runtime_activation_performed: false, ...over } }; });
  if (lib.promotionBoundaryFindings(withBoundary({})).length !== 0) f.push("tripwire/promotion: refused a boundary that pins all three");
  for (const [member, value] of [["proposal_only", false], ["governance_approval_required", false], ["runtime_activation_performed", true]]) {
    if (lib.promotionBoundaryFindings(withBoundary({ [member]: value })).length === 0) f.push(`tripwire/promotion: a boundary with ${member}=${value} read clean`);
  }

  // Vocabulary.
  if (lib.DETERMINISM_CLASSES.length !== 3) f.push("vocabulary: three determinism classes");
  if (lib.DIGESTS_BY_CLASS.bitwise.length !== 4) f.push("vocabulary: bitwise selects all four digests");
  if (lib.DIGESTS_BY_CLASS.state_equivalent.includes("rng_state_hash")) f.push("vocabulary: state_equivalent must not select rng, or a legitimately advanced generator reads as a divergence");
  if (lib.DIGESTS_BY_CLASS.statistical.length !== 0) f.push("vocabulary: statistical makes no state claim and selects nothing");
  if (lib.SPEND_FORBIDS_CANDIDATE.length !== 2) f.push("vocabulary: two spend outcomes forbid a candidate");
  return f;
}

// ---- SEAM ----------------------------------------------------------------------------------------------------
export function seamFindings({ registry, v2, v1 }) {
  const f = [];
  const row = registry.contracts.find((c) => c.contract_id === "schema://ioi/components/hypervisor/foundry-training-program/v2");
  const previous = registry.contracts.find((c) => c.contract_id === "schema://ioi/components/hypervisor/foundry-training-program/v1");
  if (!row) { f.push("the v2 successor is not registered"); return f; }
  if (!previous) { f.push("v1 is no longer registered"); return f; }

  // THE SUCCESSION, both directions.
  if (row.evolution?.successor_of !== previous.contract_id) f.push("v2 does not name v1 as its predecessor");
  if (previous.evolution?.successor_contract_id !== row.contract_id) f.push("v1 does not point at its successor");
  if (previous.evolution?.predecessor_remains_valid !== true) f.push("v1 is not marked as remaining valid, so admitted programs would be orphaned");
  if (row.evolution?.compatibility !== "breaking") f.push("a successor adding required members is not marked breaking");

  for (const member of ["policy_bound_data_view_ref", "policy_bound_data_view_revision_ref", "retention_class_ref", "determinism_class", "spend"]) {
    if (!v2.required.includes(member)) f.push(`the successor does not REQUIRE \`${member}\`, so a regulated run could omit it`);
    if (v1.required.includes(member)) f.push(`v1 already required \`${member}\`, so this unit's premise is wrong`);
  }
  const classes = v2.properties?.determinism_class?.enum ?? [];
  if (JSON.stringify([...classes].sort()) !== JSON.stringify([...LIB.DETERMINISM_CLASSES].sort())) {
    f.push("the determinism class is not the closed set of three");
  }
  const outcomes = v2.properties?.spend?.$ref ? (v2.$defs?.spendAccounting?.properties?.reconciled_outcome?.enum ?? []) : [];
  for (const forbidding of LIB.SPEND_FORBIDS_CANDIDATE) {
    if (!outcomes.includes(forbidding)) f.push(`the spend outcomes cannot express \`${forbidding}\`, so unknown spend would be indistinguishable from none`);
  }
  if (!(v2.properties?.status?.enum ?? []).includes("resume_divergent")) f.push("the status cannot express a terminal resume divergence");
  if (v2.additionalProperties !== false) f.push("the successor accepts additional members");

  // The contract carries NO invariants, and that must be a stated limit rather than a silence.
  if ((row.cross_field_invariant_refs ?? []).length !== 0) f.push("the successor registers invariants; the gate's clause 10 describes a contract that carries none");
  if (!/could not be satisfied by any record at all/u.test(String(v2.description))) {
    f.push("the successor does not record WHY it carries no invariants, so a reader would take the silence for an oversight");
  }
  if (row.positive_fixture_refs.length < 3) f.push("fewer than three positives: never-interrupted, resumed-equivalent and divergent are different shapes");
  if (row.negative_fixture_refs.length < 10) f.push(`${row.negative_fixture_refs.length} negative fixtures is too few`);
  return f;
}

// ---- SOURCE --------------------------------------------------------------------------------------------------
export function sourceFindings({ plane, canon, lib }) {
  const f = [];

  // THE CLASS TABLE, and the one entry whose absence would be silent.
  if (!/fn digests_for_class/u.test(plane)) f.push("the plane has no determinism-class table");
  // THE ARM ITSELF, not a window around it. A character-count window swept in the unit tests that
  // sit between this function and the next one — and those tests legitimately name both
  // `state_equivalent` and `rng_state_hash`, in the course of asserting they are never together.
  // A check that cannot tell an assertion from a violation is a check that reports its own fixtures.
  const armOf = (name) => {
    const start = plane.indexOf(`"${name}" => Some(`);
    if (start < 0) return "";
    const end = plane.indexOf("]),", start);
    return end < 0 ? plane.slice(start) : plane.slice(start, end);
  };
  if (armOf("state_equivalent").includes("rng_state_hash")) {
    f.push("the plane's state_equivalent arm selects rng, so a legitimately advanced generator would read as a divergence");
  }
  if (!armOf("bitwise").includes("rng_state_hash")) {
    f.push("the plane's bitwise arm does not select rng, so the strictest class stopped being the strictest");
  }
  if (!/"statistical" => Some\(&\[\]\)/u.test(plane)) f.push("statistical does not select an empty set, so it either claims state or is unknown");

  // THE VERDICT IS DERIVED, AND THE REFUSAL IS TYPED.
  if (!/foundry_program_resume_verdict_authored/u.test(plane)) f.push("the plane accepts a caller-authored verdict");
  if (!/next\["status"\] = json!\("resume_divergent"\)/u.test(plane)) f.push("an unsatisfied class does not move the program to the terminal status");
  if (!/foundry_program_resume_equivalence_incomplete/u.test(plane)) f.push("a one-sided comparison is not refused by its own code");

  // THE SIX FAIL-CLOSED REFUSALS — a tripwire on v1's work, not a claim this unit built them.
  for (const refusal of [
    "foundry_checkpoint_incomplete",
    "foundry_checkpoint_material_unavailable",
    "foundry_checkpoint_material_tampered",
    "foundry_checkpoint_compatibility_failure",
    "foundry_checkpoint_completeness_failure",
    "refuse_if_material_destroyed_public",
  ]) {
    if (!plane.includes(refusal)) f.push(`the checkpoint path no longer fails closed on ${refusal}`);
  }

  // THE VERSION-SPANNING READ.
  if (!/fn list_program_heads/u.test(plane)) f.push("program reads do not span both schema versions");
  if (!/ioi\.foundry-training-program\.v1/u.test(plane)) f.push("the plane can no longer read a v1 program, so the successor orphaned them");
  if (!/"schema_version":"ioi\.foundry-training-program\.v2"/u.test(plane)) f.push("the plane does not admit under the successor");

  // THE DERIVER REACHES NOTHING.
  if (/fetch\(|readFileSync|Date\.now\(|new Date\(/u.test(lib)) {
    f.push("the deriver reaches a plane, a file or a clock, so it cannot be run by a party holding only a program");
  }
  // AND IT NAMES THE LAWS IT CARRIES FOR THE CONTRACT.
  for (const marker of ["could not be registered", "DIGESTS_BY_CLASS", "SPEND_FORBIDS_CANDIDATE"]) {
    // Case-insensitive: the deriver states the first of these in prose, and prose gets emphasis.
    if (!lib.toLowerCase().includes(marker.toLowerCase())) f.push(`the deriver no longer names \`${marker}\`, so a law the contract cannot carry has lost its stated home`);
  }

  // CANON'S BINDING.
  // Whitespace-normalised before matching. Canon is hard-wrapped prose, so any phrase long enough
  // to be worth pinning will eventually straddle a line break — this is the second time in this
  // program a source pin has reported a sentence missing that was merely on two lines.
  const prose = canon.replace(/\s+/gu, " ");
  if (!/The Production Capability-Build Pipeline/u.test(prose)) f.push("canon no longer carries this unit's section");
  // The phrase this canon actually uses. An earlier draft copied M09.10's marker, which is the
  // same idea in another document's words — a source pin that matches the wrong file is a pin on
  // nothing.
  if (!/rather than claiming it as proof/u.test(prose)) f.push("canon no longer records that the already-structural parts are not proof");
  return f;
}

export function sourceInputs() {
  return { plane: readText(PLANE_SRC), canon: readText(CANON), lib: readText(LIB_PATH) };
}

// ---- the binding ---------------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate }) {
  const f = [];
  for (const script of ["check:foundry-capability-build", "mutate:foundry-capability-build"]) {
    if (!rootPkg.scripts?.[script]) f.push(`root_script_missing:${script}`);
  }
  if (!appPkg.scripts?.["check:foundry-capability-build"]) f.push("app_drills_script_missing");
  const row = (floors.verifiers ?? []).find((r) => r.id === "foundry-capability-build");
  if (!row) f.push("floor_row_missing");
  else {
    if (!fs.existsSync(path.join(ROOT, row.source))) f.push(`floor_source_absent:${row.source}`);
    if (!(row.runtime_assertions > 0)) f.push("floor_not_pinned");
  }
  if (!/npm run check:foundry-capability-build --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("ci_not_bound_in_the_recognised_form");
  if (!/mutate:foundry-capability-build/u.test(ci)) f.push("ci_mutation_not_bound");
  if (!floorsGate.includes("check-foundry-capability-build")) {
    f.push("floors_gate_does_not_recognise_this_runner: it is a `check-*` script and the floors gate discovers those from an explicit allow-list");
  }
  for (const clause of CLAUSES) {
    if (!clause.executed_by?.length && !clause.absence) f.push(`clause_${clause.n}_neither_executed_nor_named`);
    if (clause.absence && !clause.absence.owner) f.push(`clause_${clause.n}_absence_without_owner`);
  }
  if (CLAUSES.length !== 12) f.push(`clause_count:${CLAUSES.length}`);
  return f;
}

// ---- the verdict ---------------------------------------------------------------------------------------------
export function verdict(rows) {
  const failures = [];
  const absences = [];
  for (const clause of CLAUSES) {
    const row = rows.find((r) => r.n === clause.n);
    if (!row) { failures.push(`row_missing:${clause.n}`); continue; }
    if (row.fabricated) { failures.push(`clause_${clause.n}_fabricated: ${row.fabricated}`); continue; }
    if (row.below_floor) { failures.push(`clause_${clause.n}_below_floor: ${row.below_floor}`); continue; }
    if (row.red) { failures.push(`clause_${clause.n}_red: ${row.red}`); continue; }
    if (row.absent) absences.push({ n: clause.n, ...clause.absence });
  }
  if (failures.length) return { kind: "fail", failures, absences };
  if (absences.length) return { kind: "named_failure", failures, absences };
  return { kind: "pass", failures, absences };
}

// ---- run -----------------------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = pure;
  ok("PURE — the three laws the registered contract could not carry: a divergence carries the comparison that produced it and a measured divergence is acted on; the DECLARED class selects which digests must match, so the same rng change is a divergence under bitwise and equivalence under state_equivalent; and an unreconciled or exceeded spend forbids a candidate while the same outcome WITHOUT a candidate is not itself a finding", pure.length === 0, pure.slice(0, 4).join(" ; "));

  const seam = seamFindings({
    registry: readJson(path.join(META, "architecture-contract-registry.v1.json")),
    v2: readJson(path.join(META, "foundry-training-program.v2.schema.json")),
    v1: readJson(path.join(META, "foundry-training-program.v1.schema.json")),
  });
  evidence.seam = seam;
  ok("SEAM — the successor requires all four bindings and v1 required none of them, the determinism class is the closed set of three, the spend outcomes can express unknown spend, the status can express a terminal divergence, the succession points BOTH ways with v1 still valid, and the contract RECORDS why it carries no invariants rather than leaving the silence to be read as an oversight", seam.length === 0, seam.slice(0, 4).join(" ; "));

  const src = sourceFindings(sourceInputs());
  evidence.source = src;
  ok("SOURCE — the plane's class table does not let state_equivalent select rng and does not let statistical claim state, the verdict is derived with a typed refusal for a caller-authored one, an unsatisfied class moves the program to the terminal status, the six fail-closed checkpoint refusals are intact, program reads span BOTH schema versions, and the deriver reaches no plane, file or clock", src.length === 0, src.slice(0, 4).join(" ; "));

  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP_DIR, "package.json")),
    floors: readJson(FLOORS),
    ci: readText(path.join(ROOT, ".github", "workflows", "ci.yml")),
    floorsGate: readText(path.join(APP_DIR, "scripts", "check-verifier-floors.mjs")),
  });
  ok("BINDING — the gate is floored with an existing source, CI-bound in the form the FLOORS GATE recognises, and every clause is executed or named with an owner", binding.length === 0, binding.slice(0, 4).join(" ; "));

  const all = CLAUSES.map((c) => ({ n: c.n }));
  ok("VERDICT — a table missing eleven of its twelve rows is a FAIL, not a pass", verdict([{ n: 1 }]).kind === "fail");
  ok("VERDICT — twelve green rows with no absence is a PASS", verdict(all).kind === "pass");
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", verdict(all.map((r) => (r.n === 12 ? { ...r, absent: true } : r))).kind === "named_failure");
  ok("VERDICT — a gate that reports success without evidence is fabricated, not green", verdict(all.map((r) => (r.n === 1 ? { ...r, fabricated: "x" } : r))).kind === "fail");
  ok("VERDICT — a gate below its floor fails even at exit 0", verdict(all.map((r) => (r.n === 1 ? { ...r, below_floor: "x" } : r))).kind === "fail");

  return { pure, seam, src, binding };
}

async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "foundry-capability-mutation-"));
  let planted = 0;
  let caught = 0;
  const mutate = async (what, transform) => {
    planted += 1;
    const file = path.join(dir, `m${planted}.mjs`);
    const text = transform(original);
    if (text === original) { console.log(`FAIL  mutation ${planted} (${what}) — the planted defect changed nothing`); return; }
    fs.writeFileSync(file, text);
    let findings = [];
    try { findings = pureFindings(await import(pathToFileURL(file).href)); } catch (error) { findings = [`threw:${error.message}`]; }
    const red = findings.length > 0;
    if (red) caught += 1;
    console.log(`${red ? "  ok  " : " FAIL "} mutation ${planted} — ${what}${red ? "" : " SURVIVED"}`);
  };

  await mutate("CLASS — bitwise stops selecting rng", (t) => t.replace('bitwise: Object.freeze(["model_state_hash", "optimizer_state_hash", "scheduler_state_hash", "rng_state_hash"]),', 'bitwise: Object.freeze(["model_state_hash", "optimizer_state_hash", "scheduler_state_hash"]),'));
  await mutate("CLASS — state_equivalent starts selecting rng", (t) => t.replace('state_equivalent: Object.freeze(["model_state_hash", "optimizer_state_hash", "scheduler_state_hash"]),', 'state_equivalent: Object.freeze(["model_state_hash", "optimizer_state_hash", "scheduler_state_hash", "rng_state_hash"]),'));
  await mutate("CLASS — statistical starts claiming state", (t) => t.replace("statistical: Object.freeze([]),", 'statistical: Object.freeze(["model_state_hash"]),'));
  await mutate("CLASS — any class name is accepted", (t) => t.replace("  if (!DETERMINISM_CLASSES.includes(declared)) {", "  if (false) {"));
  await mutate("LAW2 — a satisfied claim over differing digests passes", (t) => t.replace("  if (claimed && mismatched.length > 0) {", "  if (false) {"));
  await mutate("LAW2 — an unsatisfied claim over matching digests passes", (t) => t.replace("  if (!claimed && mismatched.length === 0) {", "  if (false) {"));
  await mutate("LAW2 — a statistical program may go terminal on state", (t) => t.replace('  if (declared === "statistical" && str(program, "status") === "resume_divergent") {', "  if (false) {"));
  await mutate("LAW2 — a one-sided comparison is compared anyway", (t) => t.replace("  if (left == null || right == null) {", "  if (false) {"));
  await mutate("LAW1 — a divergence needs no comparison", (t) => t.replace('  if (status === "resume_divergent" && (equivalence == null || typeof equivalence !== "object")) {', "  if (false) {"));
  await mutate("LAW1 — a measured divergence may be ignored", (t) => t.replace('  if (equivalence != null && typeof equivalence === "object" && equivalence.class_satisfied === false && status !== "resume_divergent") {', "  if (false) {"));
  await mutate("LAW3 — spend may be absent entirely", (t) => t.replace('  if (spend == null || typeof spend !== "object") {', "  if (false) {\n    void 0;\n  }\n  if (false) {"));
  await mutate("LAW3 — any spend outcome will do", (t) => t.replace("  if (!SPEND_OUTCOMES.includes(outcome)) {", "  if (false) {"));
  await mutate("LAW3 — a run needs no reservation", (t) => t.replace('  if (!str(spend, "reservation_ref")) {', "  if (false) {"));
  await mutate("LAW3 — a run needs no cleanup obligation", (t) => t.replace('  if (!str(spend, "cleanup_obligation_ref")) {', "  if (false) {"));
  await mutate("LAW3 — unknown spend may still produce a candidate", (t) => t.replace("  if (SPEND_FORBIDS_CANDIDATE.includes(outcome) && candidateClaimed(program)) {", "  if (false) {"));
  await mutate("LAW3 — the forbidding set empties", (t) => t.replace('export const SPEND_FORBIDS_CANDIDATE = Object.freeze(["spend_unreconciled", "spend_exceeded_reservation"]);', "export const SPEND_FORBIDS_CANDIDATE = Object.freeze([]);"));
  await mutate("BINDING — a program may read through no view", (t) => t.replace('if (!str(program, "policy_bound_data_view_ref")) findings.push("program: reads through no policy-bound view");', ""));
  await mutate("BINDING — a view may be bound without a revision", (t) => t.replace('  if (!str(program, "policy_bound_data_view_revision_ref")) {', "  if (false) {"));
  await mutate("BINDING — a program needs no retention class", (t) => t.replace('if (!str(program, "retention_class_ref")) findings.push("program: names no retention class for its artifacts");', ""));
  await mutate("BINDING — a divergent program may claim a candidate", (t) => t.replace('  if (str(program, "status") === "resume_divergent" && candidateClaimed(program)) {', "  if (false) {"));
  await mutate("TRIPWIRE — the promotion boundary stops being read", (t) => t.replace('if (boundary.proposal_only !== true) findings.push("promotion: the qualification is not proposal-only");', ""));
  await mutate("CANDIDATE — nothing counts as a candidate", (t) => t.replace("  return qualification != null && typeof qualification === \"object\";", "  return false;"));

  console.log(`\n${caught}/${planted} planted defects caught`);
  evidence.mutation = { planted, caught };
  return caught === planted;
}

async function main() {
  if (MODE === "mutation") {
    const green = await mutation();
    const file = writeEvidence();
    console.log(`evidence: ${path.relative(ROOT, file)}`);
    process.exit(green ? 0 : 1);
  }

  const { pure, seam, src, binding } = await drills();
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} drills passed`);
  emitVerifierCensus({ verifierId: "foundry-capability-build", sourceUrl: import.meta.url, results });

  if (MODE === "drills") {
    const file = writeEvidence();
    console.log(`evidence: ${path.relative(ROOT, file)}`);
    process.exit(passed === results.length ? 0 : 1);
  }

  const { planeLeg } = await import("./lib/foundry-capability-build-plane.mjs");
  let plane;
  try { plane = await planeLeg({ ROOT }); } catch (error) { plane = { findings: [`plane leg threw: ${error.message}`], seconds: 0 }; }
  evidence.plane = plane;
  const planeGreen = plane.findings.length === 0;
  console.log(`\n# PLANE — ${planeGreen ? "green" : plane.findings.join("; ")} in ${plane.seconds}s`);

  const rows = CLAUSES.map((clause) => {
    const row = { n: clause.n };
    const red = [];
    if (clause.executed_by.some((e) => e.script.startsWith("pure")) && pure.length) red.push("PURE");
    if (clause.executed_by.some((e) => e.script.startsWith("seam")) && seam.length) red.push("SEAM");
    if (clause.executed_by.some((e) => e.script.startsWith("source")) && src.length) red.push("SOURCE");
    if (clause.executed_by.some((e) => e.script.startsWith("plane")) && !planeGreen) red.push("PLANE");
    if (red.length) row.red = `${red.join("+")} (this runner)`;
    if (clause.absence) row.absent = true;
    return row;
  });
  if (binding.length) rows.find((r) => r.n === 12).red = `BINDING: ${binding.join("; ")}`;

  const result = verdict(rows);
  evidence.verdict = result;
  console.log(`\n=== VERDICT: ${result.kind.toUpperCase()}${result.failures.length ? ` — ${result.failures.join(" ; ")}` : ""}`);
  for (const absence of result.absences) console.log(`NAMED  clause ${absence.n}: ${absence.what}`);
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(result.kind === "pass" ? 0 : result.kind === "named_failure" ? 2 : 1);
}

main().catch((error) => { console.error(error); writeEvidence(); process.exit(1); });
