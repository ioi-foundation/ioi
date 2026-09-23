#!/usr/bin/env node
// check:capability-construction-cycle — M10.8: the governed experiment-optimization and
// capability-construction cycle, as a gate
// (docs/architecture/foundations/objects/model-foundry-and-training.md
//  § CapabilityConstructionCycleEnvelope; ACC-12, ACC-19, ACC-16; R-237).
//
// CANON. Foundry's `ExperimentOptimizationCycleEnvelope` is Foundry's OWN specialized cycle and
// stays that. `CapabilityConstructionCycleEnvelope` is the GENERIC subordinate cycle the same
// machinery serves for twenty-three other admitted target classes, and Foundry's cycle is neither
// its owner nor a prerequisite for it — it participates only through a versioned
// `OptimizationTargetAdapter`.
//
// WHAT THIS UNIT IS. Three registered contracts and the five laws none of them could carry. Three
// of those five are comparisons BETWEEN records (an adapter against the envelope offered to it),
// one is a NOT-BOTH over two spellings of the same fact, and one is about ORDER rather than shape
// (a released evaluator is a legitimate judge everywhere except backwards over its own parent).
// M10.6 measured why: the portable invariant operator set has no form for any of them.
//
//   PURE          — the deriver over the registered fixtures: the five laws, each edge isolated.
//   SEAM          — the three contracts as registered, and Foundry's own cycle left unchanged.
//   SOURCE        — canon, the deriver, and the agreement between canon's vocabulary and both
//                   contracts' enums, read from the files rather than assumed.
//   CONFORMANCE   — deterministic records: one registered-valid cycle for EVERY vocabulary member,
//                   plus six compact cycles spanning canon's named shape groups, plus the
//                   commitment proved by tampering under a seal.
//
//   --drills           CI-bound, seconds: PURE, SEAM, SOURCE, CONFORMANCE, the binding, the verdict.
//   --mutation         planted defects against the deriver — each must go red.
//   (default)          the drills, then the verdict. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/capability-construction-cycle.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "capability-construction-cycle.mjs");
const META = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const CANON = path.join(ROOT, "docs", "architecture", "foundations", "objects", "model-foundry-and-training.md");

const CYCLE_CONTRACT = "schema://ioi/foundations/capability-construction-cycle/v1";
const REPAIR_CONTRACT = "schema://ioi/foundations/repair-proposal/v1";
const ADAPTER_CONTRACT = "schema://ioi/foundations/optimization-target-adapter/v1";

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-237";

const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const SEAM = self("seam");
const SOURCE = self("source");
const CONFORMANCE = self("conformance");

export const CLAUSES = [
  { n: 1, demand: "THREE CONTRACTS ARE REGISTERED AS CANON SPECIFIES THEM — the generic cycle, the proposal that applies nothing and the versioned adapter — each owned by the canon section that defines it, each projected into BOTH the Rust and TypeScript surfaces, and each carrying positives and negatives rather than a shape nobody ever instantiated", executed_by: [SEAM] },
  { n: 2, demand: "FOUNDRY'S OWN CYCLE IS UNTOUCHED AND IS NOT THE GENERIC OWNER. `ExperimentOptimizationCycleEnvelope` is a CANON-ONLY object — measured, it is in none of the 358 registered contracts — so `left unchanged` is checked against canon: its section is intact and its five distinct members (`optimization_cycle_id`, `foundry_job_ref`, `best_candidate_ref`, `promotion_bundle_candidate_ref`, `typed_patch_candidate_ref`) are still there and have NOT migrated onto the generic cycle. The generic cycle declares `successor_of: null` with `compatibility: initial`, because a generic object that succeeded a specialized one would have made the specialized one's records history", executed_by: [SEAM, SOURCE] },
  { n: 3, demand: "THE OPTIMIZER IS AN ACTOR AND SELECTION CONFERS ELIGIBILITY ONLY, both on the wire as constants rather than left to a reader. THE ENVELOPE CANNOT NAME A MODEL AT ALL — there is no member for one — which is what makes mounted-cognition substitution unable to rewrite the optimizer, the target, the evidence or the authority envelope: not a rule that could be forgotten, but a shape with nowhere to put the claim", executed_by: [PURE, SEAM, SOURCE] },
  { n: 4, demand: "FOUR SEPARATE DISPOSITION LISTS, NOT ONE LIST WITH A STATUS. All four are required, so a cycle cannot drop the one that embarrasses it; a cycle that ran trials and recorded no disposition of any kind is refused because its own record cannot explain how it got where it is; and collapsing a disposition into a status member is refused by the contract itself", executed_by: [PURE, SEAM] },
  { n: 5, demand: "THE `target_class` VOCABULARY IS CLOSED AT TWENTY-THREE AND THE SAME TWENTY-THREE IN FOUR PLACES — canon's block, the cycle contract's enum, the adapter contract's enum and the deriver — read from the files and compared, because a vocabulary maintained in four copies is a vocabulary that will disagree with itself. It FAILS CLOSED: a class canon does not recognise is refused before the first trial, not after the last", executed_by: [SOURCE, SEAM, CONFORMANCE] },
  { n: 6, demand: "THE THREE ADAPTER REFUSALS ARE EACH REACHABLE AND EACH DISTINCT — `missing_adapter`, `cross_version`, `downgrade` — and an UNKNOWN CLASS is refused as a fourth thing rather than folded into the first, because \"we have not built that yet\" and \"that is not a thing\" are different sentences and only one of them is somebody's backlog item", executed_by: [PURE] },
  { n: 7, demand: "CANONICAL STATE DOES NOT EMIT BOTH. The deprecated `target_training_pipeline_ref` is admissible on the wire INTO a versioned adapter and never as canonical state, and a record carrying it beside the canonical pair has not been normalized — it has been annotated. A NOT-BOTH over two spellings of one fact is the second law the portable operator set has no form for", executed_by: [PURE, SOURCE] },
  { n: 8, demand: "A BUILDER-CREATED ASSET CANNOT JUDGE ITS OWN FAMILY, and the hard edge is ORDER rather than identity: an evaluator, world, simulator or scoring asset produced by a cycle may not judge its parent or a sibling, may not enter a judging epoch before Evaluations validates, custodies, affiliation-checks, releases and freezes it, and may not RETROACTIVELY judge that producing cycle even after release — so a gate that asked only \"is it released?\" would admit exactly the case canon forbids", executed_by: [PURE, SOURCE] },
  { n: 9, demand: "A REPAIR PROPOSAL SUGGESTS AND APPLIES NOTHING: it is parented by a cycle, clusters at least one real failure, names one of canon's seven change kinds and carries a rationale a reviewer could act on — because applying a proposal is a separate governed act by the target's own owner, and review is the only thing standing between a suggestion and a change", executed_by: [PURE, SEAM, CONFORMANCE] },
  { n: 10, demand: "DETERMINISTIC CONFORMANCE OVER THE WHOLE VOCABULARY: every one of the twenty-three classes gets a registered-valid cycle, and six compact cycles span canon's named shape groups — a non-model component, a preprocessor/recipe/mapping, a harness/workflow, an integration/contact requirement, a world/simulator and a training/model/route — including an HONEST BOUNDED NON-SUCCESS that stops at its declared stop policy having accepted nothing, and an artifact-conversion cycle that binds its baseline root and resolved snapshot", executed_by: [CONFORMANCE] },
  { n: 11, demand: "THE COMMITMENT IS ENFORCED, NOT DECORATIVE: each family registers one `jcs_sha256_equals` over EVERY other member, so a record edited underneath its own seal is refused — and the cycle's proof case is a DROPPED DISPOSITION LIST, which is the whole reason the four lists are four", executed_by: [SEAM, CONFORMANCE] },
  { n: 12, demand: "THE GATE IS FLOORED WITH AN EXISTING SOURCE, CI-BOUND IN THE FORM THE FLOORS GATE RECOGNISES, AND EVERY CLAUSE IS EXECUTED OR NAMED WITH AN OWNER", executed_by: [SEAM], absence: { what: "NO OWNING PLANE ADMITS A CAPABILITY-CONSTRUCTION CYCLE, SO NOTHING ON THIS ESTATE HAS EVER RUN ONE. This unit registers three contracts and enforces the five laws none of them could carry; it does not stand up a route that admits a cycle, and it therefore cannot prove four things the unit's own scope names. (1) CRASH AND RESUME: the status vocabulary can EXPRESS a stopped cycle and conformance instantiates one, but no run was interrupted and resumed. (2) BUDGET AND CUTOFF ENFORCEMENT: `budget_policy_ref` and `stop_policy_ref` are required and bound, and an honest bounded non-success is instantiated, but no budget was consumed and no cutoff fired. (3) INDEPENDENT RE-EVALUATION OF EVERY SELECTED CANDIDATE: the cycle binds `evaluation_epoch_ref` and carries `selection_confers_eligibility_only`, and M10.4's five evaluation contracts are the far end — this gate does not drive a candidate through them. (4) ZERO PUBLICATION, ACTIVATION, AUTHORITY OR EVALUATOR WRITES FROM THE OPTIMIZER: proved here STRUCTURALLY — the envelope has no member for a model, a publication, an activation or a grant, so the claim is unrepresentable rather than unperformed — but a live optimizer writing nothing is a plane observation and no plane exists. ALSO: `missing_adapter` is the refusal for a class canon knows and this deployment cannot translate, and this estate registers NO production adapter for any of the twenty-three. That is the correct state for a registration unit and it is why the conformance leg proves the protocol with fixture adapters and claims no production adapter exists", owner: `the owning plane for CapabilityConstructionCycle admission, and M10.4's evaluator plane for the independent re-evaluation half (${OWNER_Q})` } },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.capability-construction-cycle-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, seam: null, source: null, conformance: null, verdict: null, mutation: null };
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  results.push(row);
  evidence.drills.push({ ...row, at: new Date().toISOString() });
  console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 240)}` : ""}`);
  return row.pass;
}
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `capability-construction-cycle-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const fixture = (family, name) => readJson(path.join(META, "fixtures", family, `${name}.json`));
const spoil = (record, mutate) => { const copy = JSON.parse(JSON.stringify(record)); mutate(copy); return copy; };

const CYCLE = () => fixture("capability-construction-cycle-v1", "positive-bounded-cycle-with-every-disposition");
const CAMPAIGN = () => fixture("capability-construction-cycle-v1", "positive-campaign-coordinated-under-a-frozen-epoch");
const REPAIR = () => fixture("repair-proposal-v1", "positive-clustered-rubric-suggestion");
const ADAPTER = () => fixture("optimization-target-adapter-v1", "positive-normalizes-the-deprecated-pipeline-key");
const NO_NORM_ADAPTER = () => fixture("optimization-target-adapter-v1", "positive-nothing-to-normalize-and-says-so");

// ---- PURE ----------------------------------------------------------------------------------------------------
export function pureFindings(lib) {
  const f = [];
  const must = (what, findings, shouldBeEmpty) => {
    const empty = findings.length === 0;
    if (empty !== shouldBeEmpty) f.push(`${what}: ${shouldBeEmpty ? `refused a clean record (${findings.slice(0, 2).join("; ")})` : "accepted a spoiled one"}`);
  };
  // BY MESSAGE THROUGHOUT. A case that trips two checks isolates neither, and this program has now
  // found the same survivor class in five units: a drill asserting only "some finding appeared"
  // lets the rule it is named for be deleted while a neighbour still fires.
  const says = (what, findings, pattern) => {
    if (!findings.some((line) => pattern.test(line))) f.push(`${what}: refused for some other reason — ${findings.slice(0, 2).join("; ")}`);
  };

  must("clean/bounded-cycle", lib.cycleFindings(CYCLE()), true);
  must("clean/campaign-coordinated", lib.cycleFindings(CAMPAIGN()), true);
  must("clean/repair", lib.repairFindings(REPAIR()), true);

  // LAW — THE OPTIMIZER IS AN ACTOR. Both spellings a reader would reach for are refused.
  for (const impostor of ["model://acme/gpt-style-7b", "model_route://acme/primary"]) {
    const found = lib.cycleFindings(spoil(CYCLE(), (c) => { c.optimizer_ref = impostor; }));
    must(`law/optimizer-is-${impostor.split("://")[0]}`, found, false);
    says(`law/optimizer-is-${impostor.split("://")[0]}`, found, /not an optimizer identity/u);
  }
  must("law/optimizer-scheme-absent", lib.cycleFindings(spoil(CYCLE(), (c) => { delete c.optimizer_ref; })), false);
  const disclaimed = lib.cycleFindings(spoil(CYCLE(), (c) => { c.optimizer_is_not_a_model = false; }));
  must("law/disclaimer-withdrawn", disclaimed, false);
  says("law/disclaimer-withdrawn", disclaimed, /does not disclaim/u);
  const overclaimed = lib.cycleFindings(spoil(CYCLE(), (c) => { c.selection_confers_eligibility_only = false; }));
  must("law/selection-claims-more", overclaimed, false);
  says("law/selection-claims-more", overclaimed, /may not evaluate or promote itself/u);

  // LAW — FOUR LISTS STAY FOUR. Each member separately, because a loop over the deriver's own list
  // would still pass if that list were emptied.
  for (const member of ["trial_refs", "accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs", "exploit_or_invalid_change_refs"]) {
    const found = lib.cycleFindings(spoil(CYCLE(), (c) => { delete c[member]; }));
    must(`law/${member}-absent`, found, false);
    says(`law/${member}-absent`, found, new RegExp(`\`${member}\` is not a preserved list`, "u"));
  }
  // TRIALS WITH NO DISPOSITION AT ALL, and the converse: a cycle that rejected nothing is legal.
  const undisposed = lib.cycleFindings(spoil(CYCLE(), (c) => {
    c.accepted_change_refs = []; c.rejected_change_refs = []; c.inconclusive_change_refs = []; c.exploit_or_invalid_change_refs = [];
  }));
  must("law/trials-with-no-disposition", undisposed, false);
  says("law/trials-with-no-disposition", undisposed, /cannot explain how it got where it is/u);
  must("law/rejected-nothing-is-legal", lib.cycleFindings(spoil(CYCLE(), (c) => { c.rejected_change_refs = []; })), true);
  // EACH DISPOSITION COUNTS, ONE AT A TIME. FOUND BY A SURVIVING MUTATION: emptying all four lists
  // at once is satisfied just as well by a sum that stopped counting one of them, because the total
  // is zero either way. A cycle whose ONLY disposition is the one under test must read clean, and
  // that is false the moment the sum drops it.
  for (const only of ["accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs", "exploit_or_invalid_change_refs"]) {
    must(`law/${only}-alone-is-a-disposition`, lib.cycleFindings(spoil(CYCLE(), (c) => {
      for (const member of ["accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs", "exploit_or_invalid_change_refs"]) {
        c[member] = member === only ? ["artifact://acme/change/only-1"] : [];
      }
    })), true);
  }
  must("law/no-trials-and-no-dispositions-is-legal", lib.cycleFindings(spoil(CYCLE(), (c) => {
    c.trial_refs = []; c.accepted_change_refs = []; c.rejected_change_refs = []; c.inconclusive_change_refs = []; c.exploit_or_invalid_change_refs = [];
  })), true);

  // LAW — THE CLOSED VOCABULARY FAILS CLOSED.
  const unknownClass = lib.cycleFindings(spoil(CYCLE(), (c) => { c.target_class = "vibe_engine"; }));
  must("law/unknown-target-class", unknownClass, false);
  says("law/unknown-target-class", unknownClass, /is not one of canon's \d+ target classes/u);
  for (const member of lib.TARGET_CLASSES) {
    must(`vocabulary/${member}-is-nameable`, lib.cycleFindings(spoil(CYCLE(), (c) => { c.target_class = member; })), true);
  }

  // LAW — THE THREE ADAPTER REFUSALS, each isolated, plus the fourth thing that is not one of them.
  const registry = [ADAPTER(), NO_NORM_ADAPTER()];
  const offered = (over) => ({ schema_version: "ioi.foundry-experiment-optimization-cycle.v1", target_class: "training_pipeline", ...over });
  must("adapter/clean", lib.adapterFindings(offered(), registry), true);
  const missing = lib.adapterFindings(offered({ target_class: "simulator" }), registry);
  must("adapter/missing", missing, false);
  says("adapter/missing", missing, /^missing_adapter:/u);
  const crossVersion = lib.adapterFindings(offered({ schema_version: "ioi.foundry-experiment-optimization-cycle.v9" }), registry);
  must("adapter/cross-version", crossVersion, false);
  says("adapter/cross-version", crossVersion, /^cross_version:/u);
  const downgrade = lib.adapterFindings(offered({ schema_version: "ioi.thing.v3" }), [
    { ...ADAPTER(), accepts_envelope_schema: "ioi.thing.v3", emits_envelope_schema: "ioi.thing.v2" },
  ]);
  must("adapter/downgrade", downgrade, false);
  says("adapter/downgrade", downgrade, /^downgrade:/u);
  // A TRANSLATION ACROSS FAMILIES IS THE ADAPTER'S WHOLE JOB and must not read as a downgrade —
  // the clean case above already emits a different family, and this makes the converse explicit at
  // a lower major, which is the exact pair a family-blind comparison would refuse.
  must("adapter/cross-family-lower-major-is-a-translation", lib.adapterFindings(offered({ schema_version: "ioi.left.v3" }), [
    { ...ADAPTER(), accepts_envelope_schema: "ioi.left.v3", emits_envelope_schema: "ioi.right.v1" },
  ]), true);
  // AND THE VERSION SHAPE IS THE ONE THE ESTATE USES. A version this build cannot parse is not
  // silently treated as "not older": both sides unparseable must not produce a false clean.
  must("adapter/same-family-same-major-is-not-a-downgrade", lib.adapterFindings(offered({ schema_version: "ioi.thing.v2" }), [
    { ...ADAPTER(), accepts_envelope_schema: "ioi.thing.v2", emits_envelope_schema: "ioi.thing.v2" },
  ]), true);
  // AN UNREADABLE VERSION IS REPORTED RATHER THAN PASSED OVER. Both sides, separately: a check that
  // only tried the accepted side would be satisfied by one that never looked at the emitted one.
  for (const [side, over] of [
    ["accepts", { accepts_envelope_schema: "ioi.thing", emits_envelope_schema: "ioi.thing.v1" }],
    ["emits", { accepts_envelope_schema: "ioi.thing.v2", emits_envelope_schema: "ioi.thing" }],
  ]) {
    const found = lib.adapterFindings(offered({ schema_version: over.accepts_envelope_schema }), [{ ...ADAPTER(), ...over }]);
    must(`adapter/unparseable-${side}`, found, false);
    says(`adapter/unparseable-${side}`, found, /^unparseable_envelope_version:/u);
  }
  const unknownForAdapter = lib.adapterFindings(offered({ target_class: "vibe_engine" }), registry);
  must("adapter/unknown-class", unknownForAdapter, false);
  says("adapter/unknown-class", unknownForAdapter, /^unknown_target_class:/u);
  if (unknownForAdapter.some((line) => /^missing_adapter:/u.test(line))) {
    f.push("adapter/unknown-class: reported as a missing adapter, which sends a reader looking for an adapter nobody should write");
  }

  // LAW — CANONICAL STATE DOES NOT EMIT BOTH.
  //
  // THE KEY IS SPELLED OUT HERE, NOT READ FROM THE LIB. FOUND BY A SURVIVING MUTATION: a drill that
  // builds its record from `lib.DEPRECATED_TARGET_KEY` renames the record whenever the constant is
  // renamed, so the two always match and the law can be pointed at a key canon never deprecated.
  // Canon names exactly one deprecated wire key, so the gate names it too.
  const DEPRECATED = "target_training_pipeline_ref";
  if (lib.DEPRECATED_TARGET_KEY !== DEPRECATED) f.push(`normalization: the deriver watches \`${lib.DEPRECATED_TARGET_KEY}\`, and canon deprecates \`${DEPRECATED}\``);
  must("normalization/canonical-only", lib.normalizationFindings({ target_ref: "x", target_class: "training_pipeline" }), true);
  const both = lib.normalizationFindings({ [DEPRECATED]: "p", target_ref: "x", target_class: "training_pipeline" });
  must("normalization/both", both, false);
  says("normalization/both", both, /has not been normalized, it has been annotated/u);
  const deprecatedOnly = lib.normalizationFindings({ [DEPRECATED]: "p" });
  must("normalization/deprecated-only", deprecatedOnly, false);
  says("normalization/deprecated-only", deprecatedOnly, /never as canonical state/u);

  // LAW — ORDER, NOT IDENTITY. The released-but-retroactive case is the one a shape cannot hold.
  const asset = (over) => ({ asset_id: "evaluator://acme/built-1", produced_by_cycle_ref: "constrcycle://acme/7", ...over });
  must("judging/unrelated-asset", lib.judgingFindings({ asset: { asset_id: "evaluator://acme/bought" }, judgement: { judged_cycle_ref: "constrcycle://acme/7" } }), true);
  must("judging/released-elsewhere", lib.judgingFindings({ asset: asset({ evaluations_released: true }), judgement: { judged_cycle_ref: "constrcycle://acme/8" } }), true);
  const parent = lib.judgingFindings({ asset: asset({ evaluations_released: false }), judgement: { judged_cycle_ref: "constrcycle://acme/7" } });
  must("judging/parent-unreleased", parent, false);
  says("judging/parent-unreleased", parent, /judging the cycle that produced it/u);
  const retroactive = lib.judgingFindings({ asset: asset({ evaluations_released: true }), judgement: { judged_cycle_ref: "constrcycle://acme/7" } });
  must("judging/parent-after-release", retroactive, false);
  says("judging/parent-after-release", retroactive, /everywhere EXCEPT backwards over its own parent/u);
  const early = lib.judgingFindings({ asset: asset({ evaluations_released: false }), judgement: { judged_cycle_ref: "constrcycle://acme/8" } });
  must("judging/epoch-before-release", early, false);
  says("judging/epoch-before-release", early, /before Evaluations validated/u);
  const sibling = lib.judgingFindings({ asset: asset({ evaluations_released: true }), judgement: { judged_sibling_of: "constrcycle://acme/7" } });
  must("judging/sibling", sibling, false);
  says("judging/sibling", sibling, /judging a sibling/u);

  // LAW — THE PROPOSAL APPLIES NOTHING.
  const applies = lib.repairFindings(spoil(REPAIR(), (r) => { r.applies_nothing = false; }));
  must("repair/applies-itself", applies, false);
  says("repair/applies-itself", applies, /separate governed act/u);
  const invented = lib.repairFindings(spoil(REPAIR(), (r) => { r.change_kind = "vibes"; }));
  must("repair/invented-kind", invented, false);
  says("repair/invented-kind", invented, /canon's seven change kinds/u);
  for (const kind of lib.CHANGE_KINDS) {
    must(`repair/${kind}-is-a-kind`, lib.repairFindings(spoil(REPAIR(), (r) => { r.change_kind = kind; })), true);
  }
  const unclustered = lib.repairFindings(spoil(REPAIR(), (r) => { r.clustered_failure_refs = []; }));
  must("repair/no-cluster", unclustered, false);
  says("repair/no-cluster", unclustered, /no evidence behind it/u);
  const orphan = lib.repairFindings(spoil(REPAIR(), (r) => { delete r.parent_cycle_ref; }));
  must("repair/no-parent", orphan, false);
  says("repair/no-parent", orphan, /suggestion from nowhere/u);
  const terse = lib.repairFindings(spoil(REPAIR(), (r) => { r.rationale = "tighten it"; }));
  must("repair/no-rationale", terse, false);
  says("repair/no-rationale", terse, /review is the only thing/u);

  // Vocabulary sizes, pinned rather than read from the thing being checked.
  if (lib.TARGET_CLASSES.length !== 23) f.push(`vocabulary: canon closes target_class at twenty-three, the deriver carries ${lib.TARGET_CLASSES.length}`);
  if (lib.CHANGE_KINDS.length !== 7) f.push(`vocabulary: canon's iteration loop names seven change kinds, the deriver carries ${lib.CHANGE_KINDS.length}`);
  if (lib.OPTIMIZER_SCHEMES.length !== 3) f.push("vocabulary: three optimizer schemes and a model is not among them");
  if (lib.OPTIMIZER_SCHEMES.includes("model")) f.push("vocabulary: `model` became an optimizer scheme, which makes a model a truth owner");
  if (lib.ADAPTER_REFUSALS.length !== 3) f.push("vocabulary: canon defines the adapter by three refusals");
  if (Object.keys(lib.COMMITMENT_DOMAINS).length !== 3) f.push("vocabulary: one commitment domain per family");
  if (new Set(Object.values(lib.COMMITMENT_DOMAINS)).size !== 3) f.push("vocabulary: two families share a commitment domain, so one family's digest would replay as another's");
  return f;
}

// ---- SEAM ----------------------------------------------------------------------------------------------------
export function seamFindings({ registry, cycle, repair, adapter, invariants, canon }) {
  const f = [];
  const row = (id) => registry.contracts.find((c) => c.contract_id === id);
  const cycleRow = row(CYCLE_CONTRACT);
  const repairRow = row(REPAIR_CONTRACT);
  const adapterRow = row(ADAPTER_CONTRACT);
  for (const [name, r] of [["cycle", cycleRow], ["repair", repairRow], ["adapter", adapterRow]]) {
    if (!r) f.push(`the ${name} contract is not registered`);
  }
  if (!cycleRow || !repairRow || !adapterRow) return f;

  // FOUNDRY'S OWN CYCLE, UNCHANGED.
  //
  // CHECKED AGAINST CANON AND NOT THE REGISTRY, because MEASURED 2026-09-23 it is not in the
  // registry: `ExperimentOptimizationCycleEnvelope` is a canon-only object across all 358 contracts.
  // An earlier draft of this check asked the registry for it and reported it "no longer registered",
  // which would have been a true sentence about a thing that was never there. What this unit
  // promised was to leave it ALONE, so the check is that its section and its own distinct members
  // are still where canon put them — and that no registered contract of this unit claims to
  // succeed anything.
  const foundrySection = canon.match(/## ExperimentOptimizationCycleEnvelope\n([\s\S]*?)\n## /u);
  if (!foundrySection) f.push("Foundry's own ExperimentOptimizationCycleEnvelope section is gone from canon, so this unit absorbed what it promised to leave alone");
  else {
    // Members Foundry's cycle has and the generic one deliberately does NOT — if these migrated,
    // the generic object quietly became the specialized one.
    for (const member of ["optimization_cycle_id", "foundry_job_ref", "best_candidate_ref", "promotion_bundle_candidate_ref", "typed_patch_candidate_ref"]) {
      if (!foundrySection[1].includes(`${member}:`)) f.push(`Foundry's cycle lost \`${member}\`, so the specialized object was edited by a unit that promised not to`);
      if (cycle.properties?.[member]) f.push(`the generic cycle gained Foundry's \`${member}\`, so it absorbed the specialized shape instead of adapting to it`);
    }
    if (!/`ExperimentOptimizationCycleEnvelope` above is Foundry's OWN specialized cycle/u.test(canon.replace(/\s+/gu, " "))) {
      f.push("canon no longer states that Foundry's cycle is its own and stays that");
    }
  }
  if (cycleRow.evolution?.successor_of !== null) f.push("the generic cycle declares a predecessor; it succeeds nothing and must say so");
  if (cycleRow.evolution?.compatibility !== "initial") f.push("the generic cycle is not marked initial");
  // THE ADAPTER'S ACCEPTED ENVELOPE NEED NOT BE A REGISTERED CONTRACT, and that is the point: an
  // adapter exists so a foreign or canon-only envelope — Foundry's among them — can participate
  // without being absorbed. Asserting only that the adapter EMITS the registered generic cycle.
  if (adapter.properties?.emits_envelope_schema?.const) f.push("the adapter's emitted schema is pinned to one constant, which would stop it emitting anything but the current generic cycle");

  for (const [name, r, schema] of [["cycle", cycleRow, cycle], ["repair", repairRow, repair], ["adapter", adapterRow, adapter]]) {
    if (r.canonical_owner_ref !== "canon://docs/architecture/foundations/objects/model-foundry-and-training.md") f.push(`${name}: the registered owner is not the canon section that defines it`);
    const kinds = (r.generated_targets ?? []).map((t) => t.kind).sort();
    if (JSON.stringify(kinds) !== JSON.stringify(["rust_projection", "typescript_projection"])) f.push(`${name}: not projected into both surfaces`);
    if ((r.positive_fixture_refs ?? []).length < 2) f.push(`${name}: fewer than two positives, so no shape is contrasted with another`);
    if ((r.negative_fixture_refs ?? []).length < 6) f.push(`${name}: ${(r.negative_fixture_refs ?? []).length} negatives is too few`);
    if (schema.additionalProperties !== false) f.push(`${name}: accepts additional members`);
    if (!schema.required.includes("content_hash")) f.push(`${name}: does not require its own content commitment`);
    // THE COMMITMENT IS REGISTERED AND COVERS EVERYTHING.
    const refs = r.cross_field_invariant_refs ?? [];
    if (refs.length !== 1) { f.push(`${name}: expected exactly one registered invariant, found ${refs.length}`); continue; }
    const file = invariants[name];
    const rule = (file?.rules ?? []).find((x) => x.expression?.operator === "jcs_sha256_equals");
    if (!rule) { f.push(`${name}: the registered invariant is not a content commitment`); continue; }
    if (rule.expression.expected_path !== "$.content_hash") f.push(`${name}: the commitment does not bind content_hash`);
    const committed = Object.keys(rule.expression.material_fields).filter((k) => k !== "domain").sort();
    const expected = schema.required.filter((m) => m !== "content_hash").sort();
    if (JSON.stringify(committed) !== JSON.stringify(expected)) {
      const missing = expected.filter((m) => !committed.includes(m));
      f.push(`${name}: the commitment does not cover every member — ${missing.length ? `uncommitted: ${missing.join(", ")}` : "it commits members the contract does not require"}`);
    }
    // EVERY MATERIAL MEMBER MUST BE REQUIRED, or the Rust projection drops it and the digest the
    // daemon derives stops being the digest this invariant describes. Only the Rust golden oracle
    // sees that, which is exactly why it is asserted here in a form a reader can check.
    for (const member of committed) {
      if (!schema.required.includes(member)) f.push(`${name}: \`${member}\` is committed but not required`);
    }
    // And a tampered-commitment negative exists, so the hash is proved rather than described.
    if (!(r.negative_fixture_refs ?? []).some((n) => n.expected_failure === "invariant")) {
      f.push(`${name}: no negative fixture fails on the commitment, so content_hash is a string nothing compares`);
    }
  }

  // THE TWO CONSTANTS AND THE FOUR LISTS ARE CONTRACT SHAPE, not deriver opinion.
  for (const member of ["selection_confers_eligibility_only", "optimizer_is_not_a_model"]) {
    if (cycle.properties?.[member]?.const !== true) f.push(`the cycle does not carry \`${member}\` as a wire constant`);
    if (!cycle.required.includes(member)) f.push(`\`${member}\` is not required, so a cycle could omit the law`);
  }
  for (const member of ["trial_refs", "accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs", "exploit_or_invalid_change_refs"]) {
    if (!cycle.required.includes(member)) f.push(`the cycle does not require \`${member}\`, so a disposition could be dropped`);
  }
  // NO MEMBER FOR A MODEL. This is clause 3's structural half: substitution cannot rewrite what the
  // envelope has nowhere to say.
  for (const forbidden of ["model_ref", "mounted_model_ref", "model_route_ref", "published_ref", "activation_ref", "granted_authority_ref"]) {
    if (cycle.properties?.[forbidden]) f.push(`the cycle gained a \`${forbidden}\` member, so a model or an authority can now be named by the cycle itself`);
  }
  if (repair.properties?.applies_nothing?.const !== true) f.push("the proposal does not carry `applies_nothing` as a wire constant");
  if ((repair.properties?.clustered_failure_refs?.minItems ?? 0) < 1) f.push("a proposal may cluster nothing");
  if (!(repair.properties?.rationale?.minLength > 0)) f.push("a proposal's rationale has no floor, so a phrase would pass for a review");
  if (JSON.stringify(repair.properties?.change_kind?.enum) !== JSON.stringify([...LIB.CHANGE_KINDS])) f.push("the change kinds are not canon's seven, in canon's order");
  if (adapter.properties?.accepts_envelope_schema?.enum) f.push("the adapter's accepted schema became an enum; it is one EXACT version, because a range is how an adapter comes to guess");
  return f;
}

// ---- SOURCE --------------------------------------------------------------------------------------------------
export function sourceFindings({ canon, lib, cycle, adapter }) {
  const f = [];
  // Whitespace-normalised: canon is hard-wrapped, and a phrase worth pinning eventually straddles a
  // line break. This program has had a pin report a sentence missing that was merely on two lines.
  const prose = canon.replace(/\s+/gu, " ");
  for (const marker of [
    "CapabilityConstructionCycleEnvelope",
    "RepairProposalEnvelope",
    "OptimizationTargetAdapter",
    "THE `target_class` VOCABULARY IS CLOSED",
    "canonical state does not emit both",
    "retroactively judge that producing cycle",
    "AN ACTOR, NEVER A MODEL",
    "SELECTION CONFERS ELIGIBILITY AND NOTHING ELSE",
    "EVERY TRIAL SURVIVES ITS OWN VERDICT",
  ]) {
    if (!prose.includes(marker)) f.push(`canon no longer carries \`${marker}\``);
  }
  // THE VOCABULARY, IN FOUR PLACES. Canon's block is the source; the two enums and the deriver are
  // copies, and a copy that is not compared is a copy that will drift.
  const block = canon.match(/THE `target_class` VOCABULARY IS CLOSED[^\n]*\n+```\n([\s\S]*?)\n```/u);
  if (!block) f.push("canon's target_class vocabulary block is gone, so there is nothing for the enums to be read against");
  else {
    const fromCanon = block[1].split(/\s+/u).filter(Boolean).sort();
    const compare = (what, list) => {
      const sorted = [...list].sort();
      if (JSON.stringify(sorted) !== JSON.stringify(fromCanon)) {
        const extra = sorted.filter((m) => !fromCanon.includes(m));
        const missing = fromCanon.filter((m) => !sorted.includes(m));
        f.push(`${what} disagrees with canon's vocabulary — ${extra.length ? `not in canon: ${extra.join(", ")}` : ""}${missing.length ? ` missing: ${missing.join(", ")}` : ""}`);
      }
    };
    compare("the cycle contract's enum", cycle.properties?.target_class?.enum ?? []);
    compare("the adapter contract's enum", adapter.properties?.target_class?.enum ?? []);
    compare("the deriver's TARGET_CLASSES", LIB.TARGET_CLASSES);
  }
  // THE DERIVER REACHES NOTHING — no plane, no file, no clock, no network. `node:crypto` is pure
  // computation and is deliberately not on this list.
  if (/fetch\(|readFileSync|Date\.now\(|new Date\(|createServer/u.test(lib)) {
    f.push("the deriver reaches a plane, a file, a clock or a socket, so a relying party holding a cycle could not re-derive these answers offline");
  }
  // AND IT NAMES THE LAWS IT CARRIES ON THE CONTRACTS' BEHALF, so a reader of the contract is not
  // left thinking the silence means there is nothing to enforce.
  for (const marker of ["ADAPTER_REFUSALS", "DEPRECATED_TARGET_KEY", "TARGET_CLASSES", "COMMITMENT_DOMAINS", "no single-record invariant can see"]) {
    if (!lib.includes(marker)) f.push(`the deriver no longer names \`${marker}\`, so a law the contract cannot carry has lost its stated home`);
  }
  // The schema-version comparison reads the shape this estate uses. Asserting the ARM, not a window
  // around it: the file's own prose legitimately names the semver triple it stopped using.
  if (!/\^\(\.\*\)\\\.v\(\\d\+\)\$/u.test(lib)) f.push("the deriver no longer parses `<family>.v<major>`, which is the only version shape this estate's 358 contracts use");
  return f;
}

export function sourceInputs() {
  return {
    canon: readText(CANON),
    lib: readText(LIB_PATH),
    cycle: readJson(path.join(META, "capability-construction-cycle.v1.schema.json")),
    adapter: readJson(path.join(META, "optimization-target-adapter.v1.schema.json")),
  };
}

// ---- CONFORMANCE ----------------------------------------------------------------------------------------------
function ajvFor(schema) {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  ajv.addKeyword("x-ioi-schema-version");
  return ajv.compile(schema);
}

/** The six shape groups canon names, each a compact positive cycle rather than a claim. */
export const SHAPE_GROUPS = Object.freeze([
  { group: "a non-model component", target_class: "connector_mapping", status: "proposed_for_review" },
  { group: "a preprocessor, data recipe or mapping", target_class: "data_recipe", status: "proposed_for_review" },
  { group: "a harness or workflow", target_class: "workflow_template", status: "running" },
  { group: "an integration or contact requirement", target_class: "contact_delivery_channel_requirement", status: "planned" },
  { group: "a world or simulator", target_class: "simulator", status: "stopped", bounded_non_success: true },
  { group: "a training, model or route shape", target_class: "model_route_policy", status: "proposed_for_review" },
]);

export async function conformanceFindings({ cycleSchema, repairSchema, adapterSchema }) {
  const f = [];
  let validCycle;
  let validRepair;
  let validAdapter;
  try {
    validCycle = ajvFor(cycleSchema);
    validRepair = ajvFor(repairSchema);
    validAdapter = ajvFor(adapterSchema);
  } catch (error) { return [`a registered schema does not compile: ${String(error.message).slice(0, 120)}`]; }

  const material = (schema) => schema.required.filter((m) => m !== "content_hash");
  const seal = async (record, domain, schema) => ({ ...record, content_hash: await LIB.contentHash(record, domain, material(schema)) });

  const base = (over) => {
    const { content_hash: _drop, ...rest } = CYCLE();
    return { ...rest, ...over };
  };

  // EVERY VOCABULARY MEMBER GETS A REGISTERED-VALID CYCLE. Not a claim that each production owner
  // adapter exists — canon's list is what a cycle may NAME, and this proves the envelope can carry
  // every one of them without a single class needing a shape of its own.
  for (const [index, targetClass] of LIB.TARGET_CLASSES.entries()) {
    const record = await seal(base({
      construction_cycle_id: `constrcycle://conformance/${targetClass}/1`,
      target_ref: `${targetClass}://conformance/subject`,
      target_class: targetClass,
    }), LIB.COMMITMENT_DOMAINS.cycle, cycleSchema);
    if (!validCycle(record)) f.push(`conformance/${targetClass}: not registered-valid — ${validCycle.errors?.[0]?.instancePath} ${validCycle.errors?.[0]?.message}`);
    const found = LIB.cycleFindings(record);
    if (found.length) f.push(`conformance/${targetClass}: the deriver refused it — ${found[0]}`);
    if (index === 0 && record.content_hash === CYCLE().content_hash) f.push("conformance: a changed cycle kept the fixture's hash, so the seal is not a function of the content");
  }

  // THE SIX COMPACT CYCLES CANON'S SHAPE GROUPS NAME.
  for (const shape of SHAPE_GROUPS) {
    const over = {
      construction_cycle_id: `constrcycle://conformance/shape/${shape.target_class}`,
      target_ref: `${shape.target_class}://conformance/subject`,
      target_class: shape.target_class,
      status: shape.status,
    };
    if (shape.bounded_non_success) {
      // AN HONEST BOUNDED NON-SUCCESS: stopped at the declared stop policy having accepted nothing,
      // with every trial still carrying a disposition. A cycle that stopped and kept no record of
      // what it tried would be the failure the four lists exist to prevent, wearing a stop's
      // clothes.
      over.accepted_change_refs = [];
      over.rejected_change_refs = ["artifact://conformance/rejected-1", "artifact://conformance/rejected-2"];
      over.inconclusive_change_refs = ["artifact://conformance/inconclusive-1"];
      over.exploit_or_invalid_change_refs = [];
    }
    if (shape.target_class === "model_route_policy") {
      // ARTIFACT AND CONVERSION LINEAGE: the baseline root and the resolved component snapshot are
      // required members, so a selected candidate always names what it was measured against.
      if (!cycleSchema.required.includes("baseline_target_root") || !cycleSchema.required.includes("resolved_component_snapshot_ref")) {
        f.push("conformance: a cycle may be admitted without a baseline root or a resolved snapshot, so its lineage is unbound");
      }
    }
    const record = await seal(base(over), LIB.COMMITMENT_DOMAINS.cycle, cycleSchema);
    if (!validCycle(record)) f.push(`shape/${shape.group}: not registered-valid — ${validCycle.errors?.[0]?.instancePath} ${validCycle.errors?.[0]?.message}`);
    const found = LIB.cycleFindings(record);
    if (found.length) f.push(`shape/${shape.group}: the deriver refused it — ${found[0]}`);
  }
  if (new Set(SHAPE_GROUPS.map((s) => s.target_class)).size !== 6) f.push("conformance: the six shape groups do not span six distinct classes");
  if (!SHAPE_GROUPS.some((s) => s.bounded_non_success)) f.push("conformance: no shape group is an honest bounded non-success, so only successful cycles were instantiated");

  // A FAILED-TRIAL REPAIR, PARENTED BACK. The clustered failures must be trials the parent ran, or
  // the proposal clusters somebody else's evidence.
  const parent = await seal(base({
    construction_cycle_id: "constrcycle://conformance/repair/parent",
    trial_refs: ["trial://conformance/1", "trial://conformance/2", "trial://conformance/3"],
    rejected_change_refs: ["artifact://conformance/rejected-1"],
    accepted_change_refs: [],
    repair_proposal_refs: ["repair-proposal://conformance/repair/1"],
  }), LIB.COMMITMENT_DOMAINS.cycle, cycleSchema);
  const { content_hash: _r, ...repairRest } = REPAIR();
  const proposal = await seal({
    ...repairRest,
    repair_proposal_id: "repair-proposal://conformance/repair/1",
    parent_cycle_ref: parent.construction_cycle_id,
    clustered_failure_refs: ["trial://conformance/2", "trial://conformance/3"],
  }, LIB.COMMITMENT_DOMAINS.repair, repairSchema);
  if (!validCycle(parent)) f.push("repair/parent: the parent cycle is not registered-valid");
  if (!validRepair(proposal)) f.push(`repair/proposal: not registered-valid — ${validRepair.errors?.[0]?.message}`);
  if (LIB.repairFindings(proposal).length) f.push(`repair/proposal: the deriver refused it — ${LIB.repairFindings(proposal)[0]}`);
  if (!parent.repair_proposal_refs.includes(proposal.repair_proposal_id)) f.push("repair: the parent does not carry the proposal it produced");
  for (const trial of proposal.clustered_failure_refs) {
    if (!parent.trial_refs.includes(trial)) f.push(`repair: clusters \`${trial}\`, which its parent never ran`);
  }

  // THE COMMITMENT, PROVED BY TAMPERING. Sealed first, then edited underneath the seal.
  const tamper = async (what, record, domain, schema, mutate) => {
    const sealed = await seal(record, domain, schema);
    const edited = spoil(sealed, mutate);
    const rederived = await LIB.contentHash(edited, domain, material(schema));
    if (rederived === sealed.content_hash) f.push(`commitment/${what}: the edit did not change the derived hash, so the member is outside the commitment`);
  };
  await tamper("a-dropped-disposition", base({}), LIB.COMMITMENT_DOMAINS.cycle, cycleSchema, (c) => { c.rejected_change_refs = []; });
  await tamper("a-swapped-cluster", repairRest, LIB.COMMITMENT_DOMAINS.repair, repairSchema, (r) => { r.clustered_failure_refs = ["trial://elsewhere/1"]; });
  const { content_hash: _a, ...adapterRest } = ADAPTER();
  await tamper("an-emptied-translation", adapterRest, LIB.COMMITMENT_DOMAINS.adapter, adapterSchema, (a) => { a.normalizations = []; });
  if (!validAdapter(await seal(adapterRest, LIB.COMMITMENT_DOMAINS.adapter, adapterSchema))) f.push("commitment: the resealed adapter is not registered-valid");

  // AND THE SEAL AGREES WITH THE BYTES ON DISK. If this drifts, every conformance record above was
  // sealed by a function the registered fixtures do not use.
  for (const [what, record, domain, schema] of [
    ["cycle", CYCLE(), LIB.COMMITMENT_DOMAINS.cycle, cycleSchema],
    ["repair", REPAIR(), LIB.COMMITMENT_DOMAINS.repair, repairSchema],
    ["adapter", ADAPTER(), LIB.COMMITMENT_DOMAINS.adapter, adapterSchema],
  ]) {
    const derived = await LIB.contentHash(record, domain, material(schema));
    if (derived !== record.content_hash) f.push(`commitment/${what}: the registered fixture's own hash is not the one this canonicalization derives`);
  }
  return f;
}

// ---- the binding ---------------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate }) {
  const f = [];
  for (const script of ["check:capability-construction-cycle", "mutate:capability-construction-cycle"]) {
    if (!rootPkg.scripts?.[script]) f.push(`root_script_missing:${script}`);
  }
  if (!appPkg.scripts?.["check:capability-construction-cycle"]) f.push("app_drills_script_missing");
  const row = (floors.verifiers ?? []).find((r) => r.id === "capability-construction-cycle");
  if (!row) f.push("floor_row_missing");
  else {
    if (!fs.existsSync(path.join(ROOT, row.source))) f.push(`floor_source_absent:${row.source}`);
    if (!(row.runtime_assertions > 0)) f.push("floor_not_pinned");
  }
  if (!/npm run check:capability-construction-cycle --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("ci_not_bound_in_the_recognised_form");
  if (!/mutate:capability-construction-cycle/u.test(ci)) f.push("ci_mutation_not_bound");
  if (!floorsGate.includes("check-capability-construction-cycle")) {
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
  ok("PURE — the five laws no registered contract could carry: the optimizer is an actor and a model named there would be a truth owner; the four dispositions stay four and a cycle that disposed of nothing cannot explain itself; the three adapter refusals are each reachable and an unknown class is a fourth thing; canonical state does not emit the deprecated key beside the canonical pair; and a builder-created asset may not judge its parent even after release", pure.length === 0, pure.slice(0, 4).join(" ; "));

  const seam = seamFindings({
    registry: readJson(path.join(META, "architecture-contract-registry.v1.json")),
    cycle: readJson(path.join(META, "capability-construction-cycle.v1.schema.json")),
    repair: readJson(path.join(META, "repair-proposal.v1.schema.json")),
    adapter: readJson(path.join(META, "optimization-target-adapter.v1.schema.json")),
    invariants: {
      cycle: readJson(path.join(META, "invariants", "capability-construction-cycle.v1.invariants.json")),
      repair: readJson(path.join(META, "invariants", "repair-proposal.v1.invariants.json")),
      adapter: readJson(path.join(META, "invariants", "optimization-target-adapter.v1.invariants.json")),
    },
    canon: readText(CANON),
  });
  evidence.seam = seam;
  ok("SEAM — three contracts registered against the canon section that owns them, projected into both surfaces, the two laws carried as wire constants, all four disposition lists required, NO member the cycle could name a model or an authority in, one commitment per family covering every required member, and Foundry's own canon-only cycle left where canon put it, with none of its five distinct members migrated onto the generic one", seam.length === 0, seam.slice(0, 4).join(" ; "));

  const src = sourceFindings(sourceInputs());
  evidence.source = src;
  ok("SOURCE — canon still carries all three objects and the four laws it states in its own words, the closed twenty-three are IDENTICAL in canon, both contract enums and the deriver, and the deriver reaches no plane, file, clock or socket so a relying party can re-derive every answer offline", src.length === 0, src.slice(0, 4).join(" ; "));

  const conformance = await conformanceFindings({
    cycleSchema: readJson(path.join(META, "capability-construction-cycle.v1.schema.json")),
    repairSchema: readJson(path.join(META, "repair-proposal.v1.schema.json")),
    adapterSchema: readJson(path.join(META, "optimization-target-adapter.v1.schema.json")),
  });
  evidence.conformance = conformance;
  ok(`CONFORMANCE — a registered-valid cycle for every one of the ${LIB.TARGET_CLASSES.length} classes, six compact cycles spanning canon's shape groups including an honest bounded non-success, a failed-trial repair parented back to the trials its parent actually ran, and the commitment proved by editing three records underneath their own seals`, conformance.length === 0, conformance.slice(0, 4).join(" ; "));

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

  return { pure, seam, src, conformance, binding };
}

async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "capability-construction-mutation-"));
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

  // THE OPTIMIZER.
  await mutate("OPTIMIZER — a model becomes an actor", (t) => t.replace('export const OPTIMIZER_SCHEMES = Object.freeze(["worker", "conductor", "runtime"]);', 'export const OPTIMIZER_SCHEMES = Object.freeze(["worker", "conductor", "runtime", "model"]);'));
  await mutate("OPTIMIZER — the scheme stops being checked", (t) => t.replace("  if (!OPTIMIZER_SCHEMES.includes(scheme)) {", "  if (false) {"));
  await mutate("OPTIMIZER — the disclaimer may be withdrawn", (t) => t.replace('  if (cycle?.optimizer_is_not_a_model !== true) findings.push', "  if (false) findings.push"));
  await mutate("SELECTION — a selection may claim more than eligibility", (t) => t.replace("  if (cycle?.selection_confers_eligibility_only !== true) {", "  if (false) {"));
  // THE FOUR LISTS.
  await mutate("LISTS — the exploit list drops out of the preserved set", (t) => t.replace('for (const member of ["trial_refs", "accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs", "exploit_or_invalid_change_refs"]) {', 'for (const member of ["trial_refs", "accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs"]) {'));
  await mutate("LISTS — a list need not be a list", (t) => t.replace("    if (!Array.isArray(cycle?.[member])) findings.push", "    if (false) findings.push"));
  await mutate("LISTS — trials with no disposition read clean", (t) => t.replace("  if (trials > 0 && dispositions === 0) {", "  if (false) {"));
  await mutate("LISTS — the disposition count stops counting the exploit list", (t) => t.replace('const dispositions = ["accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs", "exploit_or_invalid_change_refs"]', 'const dispositions = ["accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs"]'));
  // THE VOCABULARY.
  await mutate("VOCABULARY — target_class stops being checked", (t) => t.replace("  if (!TARGET_CLASSES.includes(targetClass)) {\n    findings.push(`cycle:", "  if (false) {\n    findings.push(`cycle:"));
  await mutate("VOCABULARY — a class is quietly dropped", (t) => t.replace('  "contact_delivery_channel_requirement",\n', ""));
  await mutate("VOCABULARY — a class is quietly added", (t) => t.replace('  "simulator",\n]);', '  "simulator",\n  "vibe_engine",\n]);'));
  // THE ADAPTER.
  await mutate("ADAPTER — missing_adapter stops firing", (t) => t.replace("  if (candidates.length === 0) {", "  if (false) {"));
  await mutate("ADAPTER — cross_version stops firing", (t) => t.replace("  if (reading.length === 0) {", "  if (false) {"));
  await mutate("ADAPTER — downgrade stops firing", (t) => t.replace("    if (from !== null && to !== null && from.family === to.family && to.major < from.major) {", "    if (false) {"));
  await mutate("ADAPTER — downgrade compares across families, so every translation reads as one", (t) => t.replace("from.family === to.family && to.major < from.major", "to.major < from.major"));
  await mutate("ADAPTER — an unparseable version passes as not-older", (t) => t.replace("  return match === null ? null : { family: match[1], major: Number.parseInt(match[2], 10) };", "  return match === null ? { family: \"\", major: 0 } : { family: match[1], major: Number.parseInt(match[2], 10) };"));
  await mutate("ADAPTER — an unreadable version is passed over in silence", (t) => t.replace("      if (parsed === null) {", "      if (false) {"));
  await mutate("ADAPTER — only the accepted side is read for legibility", (t) => t.replace('for (const [side, parsed, raw] of [["accepts", from, accepts], ["emits", to, emits]]) {', 'for (const [side, parsed, raw] of [["accepts", from, accepts]]) {'));
  await mutate("ADAPTER — an unknown class is folded into missing_adapter", (t) => t.replace("  if (!TARGET_CLASSES.includes(targetClass)) {\n    findings.push(`unknown_target_class:", "  if (false) {\n    findings.push(`unknown_target_class:"));
  await mutate("ADAPTER — the candidate filter ignores the class", (t) => t.replace('.filter((a) => str(a, "target_class") === targetClass)', ".filter(() => true)"));
  // NOT BOTH.
  await mutate("NOT-BOTH — a record may carry the deprecated key beside the canonical pair", (t) => t.replace("  if (carriesDeprecated && carriesCanonical) {", "  if (false) {"));
  await mutate("NOT-BOTH — the deprecated key alone becomes canonical state", (t) => t.replace("  if (carriesDeprecated && !carriesCanonical) {", "  if (false) {"));
  await mutate("NOT-BOTH — the deprecated key is renamed, so nothing matches it", (t) => t.replace('export const DEPRECATED_TARGET_KEY = "target_training_pipeline_ref";', 'export const DEPRECATED_TARGET_KEY = "target_pipeline_ref";'));
  // ORDER.
  await mutate("ORDER — an asset may judge its parent", (t) => t.replace("  if (judged === producedBy) {", "  if (false) {"));
  await mutate("ORDER — release excuses judging the parent", (t) => t.replace("  if (judged === producedBy) {", "  if (judged === producedBy && !released) {"));
  await mutate("ORDER — an unreleased asset may enter a judging epoch", (t) => t.replace("  if (!released && judged && judged !== producedBy) {", "  if (false) {"));
  await mutate("ORDER — a sibling may be judged", (t) => t.replace('  if (str(judgement, "judged_sibling_of") === producedBy) {', "  if (false) {"));
  await mutate("ORDER — every asset is treated as bought rather than built", (t) => t.replace("  if (!producedBy) return findings;", "  return findings;\n  if (!producedBy) return findings;"));
  // THE PROPOSAL.
  await mutate("REPAIR — a proposal may apply its own change", (t) => t.replace("  if (proposal?.applies_nothing !== true) {", "  if (false) {"));
  await mutate("REPAIR — any change kind will do", (t) => t.replace("  if (!CHANGE_KINDS.includes(kind)) {", "  if (false) {"));
  await mutate("REPAIR — a change kind is quietly added", (t) => t.replace('export const CHANGE_KINDS = Object.freeze(["data", "recipe", "gate", "rubric", "tool", "model", "workflow"]);', 'export const CHANGE_KINDS = Object.freeze(["data", "recipe", "gate", "rubric", "tool", "model", "workflow", "vibes"]);'));
  await mutate("REPAIR — a proposal may cluster nothing", (t) => t.replace('  if (list(proposal, "clustered_failure_refs").length === 0) {', "  if (false) {"));
  await mutate("REPAIR — a proposal may be parented by nothing", (t) => t.replace('  if (!str(proposal, "parent_cycle_ref")) findings.push', "  if (false) findings.push"));
  await mutate("REPAIR — a rationale needs no floor", (t) => t.replace('  if (str(proposal, "rationale").trim().length < 20) {', "  if (false) {"));
  // THE COMMITMENT.
  await mutate("COMMITMENT — two families share a domain", (t) => t.replace('  repair: "ioi.repair-proposal-content-commitment-jcs-sha256.v1",', '  repair: "ioi.capability-construction-cycle-content-commitment-jcs-sha256.v1",'));

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

  const { pure, seam, src, conformance, binding } = await drills();
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} drills passed`);
  emitVerifierCensus({ verifierId: "capability-construction-cycle", sourceUrl: import.meta.url, results });

  if (MODE === "drills") {
    const file = writeEvidence();
    console.log(`evidence: ${path.relative(ROOT, file)}`);
    process.exit(passed === results.length ? 0 : 1);
  }

  const rows = CLAUSES.map((clause) => {
    const row = { n: clause.n };
    const red = [];
    if (clause.executed_by.some((e) => e.script.startsWith("pure")) && pure.length) red.push("PURE");
    if (clause.executed_by.some((e) => e.script.startsWith("seam")) && seam.length) red.push("SEAM");
    if (clause.executed_by.some((e) => e.script.startsWith("source")) && src.length) red.push("SOURCE");
    if (clause.executed_by.some((e) => e.script.startsWith("conformance")) && conformance.length) red.push("CONFORMANCE");
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
