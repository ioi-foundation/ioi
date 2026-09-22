#!/usr/bin/env node
// check:collective-controller-qualification — M10.9: collective and persistent-controller qualification,
// as a gate (docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md § Collective qualification;
// ACC-12 clause 13 and negative N4; register R-222).
//
// CANON. Collective machinery earns its complexity or it does not keep it. A frozen epoch compares the
// EXACT collective composition against a MATCHED cheaper baseline under an estimand declared before either
// arm ran, with the full knockout matrix. Neither participant count, aggregate score, active ArtifactRef
// nor surviving process qualifies Collective mode or persistent authority. Result robustness and
// controller continuity are separate claims. Evaluation emits judgment only.
//
// THE DEFECTS THIS UNIT ENDS, each measured before a line was written:
//   (a) `estimand` was a WORD. The evaluation epoch carries `confirmatory_estimand_and_minimum_effect_refs`,
//       an unvalidated bounded ref list frozen into the epoch's root that nothing dereferences — a
//       `policy://` string satisfies it, and the one live epoch in the tree carries exactly such a
//       placeholder. Three registered contracts now stand behind it.
//   (b) NO RECORD COULD NAME AN ARM. `EvaluationRun.incumbent_ref` is a free label the plane never
//       resolves, so "the collective beat the incumbent" named nothing in particular.
//   (c) EVALUATION-IS-NEVER-ACTIVATION was canon and nothing else: no code anywhere asserted it.
//   (d) Only the AUTHORITY half of the result/continuity separation was proven (ACC-5 N4); the other
//       direction — that a healthy runtime proves no result — was unasserted.
//   (e) And the trap this gate exists to not fall into: `posture()` re-derives from the accountable
//       subject, the caretaker, context leases, dependency lineages and `runtime_ref` — and NOT from
//       `installation_ref`. An installation knockout read through the posture reports success while
//       measuring nothing.
//
//   PURE    — the oracle in apps/hypervisor/scripts/lib/collective-qualification.mjs over constructed
//             records: matched identity per axis, the positive control, the declaration ordering, the four
//             refusals, the separation in both directions, the complete-or-named matrix, and the
//             installation instrument.
//   SEAM    — the three registered contracts refuse at the wire: the eight per-axis `fields_equal` rules,
//             the separate-roots rule, the `qualified_on` enum that cannot NAME the four canon refuses,
//             and every fixture classified at the layer that actually refuses it.
//   SOURCE  — the composition is an ioi.ai application record on the generic seam and no Hypervisor
//             family; "controller" is written down as the runtime binding rather than the embodied
//             `controller://` scheme; canon's binding.
//   PLANE   — full mode, one isolated daemon and the real wallet fixture: the three records admitted
//             through the seam, sixteen knockouts performed against the M04.12 composer and the daemon's
//             own planes, the installation axis read from the OWNER while the posture stays green, and
//             every knockout reverted with nothing promoted.
//
//   --drills           CI-bound, seconds: PURE, SEAM, SOURCE, the binding and the verdict rules. No daemon.
//   --mutation         planted defects against the oracle — each must go red.
//   (default)          the full gate: the drills, then PLANE. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/collective-qualification.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "collective-qualification.mjs");
const META = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const CANON = path.join(ROOT, "docs", "architecture", "domains", "ioi-ai", "collaborative-outcome-pattern.md");
const COMPOSER = path.join(ROOT, "apps", "ioi-ai", "orchestration", "src", "collective.ts");
const EVAL_ROUTES = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "evaluation_routes.rs");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-222";

const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const SEAM = self("seam");
const SOURCE = self("source");
const PLANE = self("plane");
const M0412 = { kind: "app", script: "check:collective-artifact-runtime-lifecycle", workspace: APP, floor: "collective-artifact-runtime-lifecycle", minutes: 25 };
const M104 = { kind: "app", script: "check:governed-evaluation-plane", workspace: APP, floor: "governed-evaluation-plane", minutes: 20 };

export const CLAUSES = [
  { n: 1, demand: "MATCHED-BASELINE IDENTITY is a record, not a claim: each arm is a resolvable orchestration composition rather than a free label, and each of canon's eight axes — task, authority, context, tool, environment, budget, time and verifier posture — carries a root for EACH arm, so an unmatched pairing is refused by the failing axis's own rule name rather than as a single unmatched flag", executed_by: [PURE, SEAM, PLANE] },
  { n: 2, demand: "THE COMPARATOR WORKS: the pairing carries a positive control — the matched cases the baseline passed on its own and the results they were read from — because a baseline that fails everything makes any collective look good, and breaking the comparator is the cheapest way to manufacture a surplus", executed_by: [PURE, SEAM, PLANE] },
  { n: 3, demand: "THE ESTIMAND WAS DECLARED FIRST and the verdict was read against the one it names: kind, quantity with its aggregation, direction, minimum effect, cost normalization and a written decision rule, sealed by a root so the epoch freezing its REF also freezes its CONTENT, and a resilience or independence claim naming axes this run actually performed", executed_by: [PURE, SEAM, PLANE] },
  { n: 4, demand: "THE FOUR CANON REFUSES cannot qualify anything: a participant count, an aggregate score over an unmatched baseline, an ArtifactRef marked active and a surviving process are absent from the admissible-basis enum entirely, so a verdict cannot even NAME one as its reason, and the oracle catches each arriving as an input instead", executed_by: [PURE, SEAM] },
  { n: 5, demand: "RESULT ROBUSTNESS AND CONTROLLER CONTINUITY are separate members with separate roots and the seam refuses a verdict whose two roots are equal — and BOTH of canon's sentences are demonstrated: a qualified result standing while its controller is already stopped, and a perfectly healthy controller beside a result that did not qualify", executed_by: [PURE, SEAM, PLANE] },
  { n: 6, demand: "THE KNOCKOUT MATRIX IS COMPLETE OR ITS GAPS ARE NAMED: every axis this estate can perform is performed on `cross_play_ablation`, the ablation lane the evaluation plane already admits, and every axis canon names that this estate cannot perform is carried with the reason it cannot and the owner who could change that", executed_by: [PURE, PLANE], absence: { what: "FIVE AXES CANON NAMES CANNOT BE PERFORMED HERE, each for a measured reason and none for want of effort: the communication-edge knockout has no object to remove (no edge, channel or message-graph record exists anywhere; `coordination_topology` is a two-member admission-mode enum, not a graph); the role knockout has no RoleTopology record although `ContextCell.role` exists, and the composer refuses a topology-bound cell BY NAME rather than trusting one; lease EXPIRY has no writer at all (`expired` appears only in a terminal-status set and the daemon evaluates no TTL, which two independent non-claims already state) so only revocation is executable; and disclosure overhead and verification overhead have no measure — `verification_cost_class` on a suite revision is its author's declaration, not a measurement", owner: `M04.12's communication-edge and role-topology objects, M04.11's lease expiry, and a disclosure/verification cost measure with no owner today (${OWNER_Q})` } },
  { n: 7, demand: "EVALUATION IS NEVER ACTIVATION, asserted rather than stated: every knockout reverted and rewrote no topology, revoked no participant, activated no controller, installed no artifact and promoted no profile — measured against the plane's own record count and owner reads, not read off the verdict's own clauses", executed_by: [PURE, PLANE] },
  { n: 8, demand: "THE INSTALLATION AXIS IS READ FROM THE OWNER: the lineage read model re-derives from subject, caretaker, leases, dependencies and runtime_ref and NOT from installation_ref, so the gate shows the posture staying GREEN after the installation is gone and reads the owner directly — an axis where the obvious instrument is the wrong one", executed_by: [PURE, PLANE] },
  { n: 9, demand: "COST IS CONTROLLED FOR OR THE RECORD SAYS IT IS NOT: a collective that wins by spending more has not earned its complexity, so a verdict may not claim a normalization its estimand declared none of, and may not skip one the estimand declared", executed_by: [PURE, SEAM] },
  { n: 10, demand: "THE LAYER LAW HOLDS: the qualification is an ioi.ai application record admitted through the generic System-record seam under an ACTIVE System and is no Hypervisor family — the evaluation plane is a Hypervisor component and may not read an orchestration application's records, and the binding the seam derives is never authored by the caller", executed_by: [SOURCE, SEAM, PLANE, M104] },
  { n: 11, demand: "\"CONTROLLER\" IS WRITTEN DOWN as the persistent lineage's runtime_ref and runtime_kind, and distinguished in canon and in code from the embodied `controller://` identity for robots, facilities, actuators and bridges, which is a different object a reader grepping the scheme would otherwise find", executed_by: [SOURCE, PURE] },
  { n: 12, demand: "THE LIFECYCLE KNOCKOUTS ARE THE COMPOSER'S OWN VERBS driven against a real daemon — stop, quarantine, repair, replacement and retirement, plus participant and caretaker exit, dependency retirement, creator-session removal, context-lease revocation, ancestry removal, an unserved runtime, verifier invalidation, budget exhaustion and crash/restart — and not a simulation of them", executed_by: [PLANE, M0412] },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.collective-controller-qualification-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, seam: null, source: null, plane: null, clauses: [], verdict: null, mutation: null };
let sink = results;
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  sink.push(row);
  if (sink === results) { evidence.drills.push({ ...row, at: new Date().toISOString() }); console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`); }
  return row.pass;
}
function blocked(reason) { console.error(`BLOCKED: ${reason}`); writeEvidence(); process.exit(2); }
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `collective-controller-qualification-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256 = (s) => `sha256:${crypto.createHash("sha256").update(s).digest("hex")}`;

// ---- the constructed records the pure oracle is scored over ------------------------------------------------
const FIXTURES = (dir) => path.join(META, "fixtures", dir);
const fixture = (dir, name) => readJson(path.join(FIXTURES(dir), name));
const PAIRING_OK = () => fixture("collective-baseline-pairing-v1", "positive-matched-on-all-eight-axes.json");
const ESTIMAND_OK = () => fixture("collective-qualification-estimand-v1", "positive-cooperation-surplus.json");
const VERDICT_OK = () => fixture("collective-qualification-verdict-v1", "positive-qualified-while-the-controller-is-already-stopped.json");
const VERDICT_HEALTHY = () => fixture("collective-qualification-verdict-v1", "positive-not-qualified-while-the-controller-is-perfectly-healthy.json");
const spoil = (record, mutate) => { const copy = JSON.parse(JSON.stringify(record)); mutate(copy); return copy; };

/**
 * The oracle must accept every clean shape and refuse every spoiled one. A drill that only checked the
 * refusals would pass over an oracle that refuses everything, so each pair is asserted together.
 */
export function pureFindings(lib) {
  const f = [];
  const must = (what, findings, shouldBeEmpty) => {
    const empty = findings.length === 0;
    if (empty !== shouldBeEmpty) f.push(`${what}: ${shouldBeEmpty ? `refused a clean shape (${findings.slice(0, 2).join("; ")})` : "accepted a spoiled one"}`);
  };
  const pairing = PAIRING_OK();
  const estimand = ESTIMAND_OK();
  const verdict = VERDICT_OK();

  // -- matched identity, axis by axis --
  must("match/clean", lib.matchFindings(pairing), true);
  for (const axis of lib.MATCH_AXES) {
    const differs = spoil(pairing, (p) => { p.axis_proofs[axis].baseline_root = `sha256:${"e".repeat(64)}`; });
    const found = lib.matchFindings(differs);
    must(`match/${axis}-differs`, found, false);
    if (!found.some((x) => x.includes(axis))) f.push(`match/${axis}-differs: the finding does not name the axis that differed`);
  }
  must("match/axis-undeclared", lib.matchFindings(spoil(pairing, (p) => { p.declared_match_axes = p.declared_match_axes.filter((a) => a !== "budget"); })), false);
  must("match/axis-invented", lib.matchFindings(spoil(pairing, (p) => { p.declared_match_axes.push("vibes"); })), false);
  must("match/no-proof", lib.matchFindings(spoil(pairing, (p) => { delete p.axis_proofs.time; })), false);
  must("match/one-composition", lib.matchFindings(spoil(pairing, (p) => { p.baseline_arm.composition_ref = p.collective_arm.composition_ref; })), false);
  must("match/baseline-is-a-second-collective", lib.matchFindings(spoil(pairing, (p) => { p.baseline_arm.arm_kind = "collective"; })), false);

  // -- the positive control --
  must("control/clean", lib.positiveControlFindings(pairing), true);
  must("control/absent", lib.positiveControlFindings(spoil(pairing, (p) => { delete p.baseline_positive_control; })), false);
  must("control/passed-nothing", lib.positiveControlFindings(spoil(pairing, (p) => { p.baseline_positive_control.matched_cases_passed = 0; })), false);
  must("control/over-counted", lib.positiveControlFindings(spoil(pairing, (p) => { p.baseline_positive_control.matched_cases_passed = 999; })), false);
  must("control/no-results", lib.positiveControlFindings(spoil(pairing, (p) => { p.baseline_positive_control.control_result_refs = []; })), false);

  // -- the declaration ordering --
  must("declaration/clean", lib.declarationFindings(verdict, estimand, pairing), true);
  must("declaration/verdict-names-another-estimand", lib.declarationFindings(spoil(verdict, (v) => { v.estimand_ref = "estimand://somebody/else"; }), estimand, pairing), false);
  must("declaration/verdict-names-another-pairing", lib.declarationFindings(spoil(verdict, (v) => { v.pairing_ref = "pairing://somebody/else"; }), estimand, pairing), false);
  must("declaration/pairing-for-another-estimand", lib.declarationFindings(verdict, estimand, spoil(pairing, (p) => { p.estimand_ref = "estimand://somebody/else"; })), false);
  must("declaration/after-the-freeze", lib.declarationFindings(verdict, spoil(estimand, (e) => { e.declared_before_epoch_freeze = false; }), pairing), false);
  must("declaration/assembled-after", lib.declarationFindings(verdict, estimand, spoil(pairing, (p) => { p.declared_before_either_arm_ran = false; })), false);
  must("declaration/qualifies-on-its-own", lib.declarationFindings(verdict, spoil(estimand, (e) => { e.qualifies_nothing_on_its_own = false; }), pairing), false);
  const resilience = spoil(estimand, (e) => { e.estimand_kind = "resilience"; e.knockout_axis_refs = ["axis://knockout/caretaker_exit"]; });
  must("declaration/resilience-axis-performed", lib.declarationFindings(verdict, resilience, pairing), true);
  must("declaration/resilience-axis-never-run", lib.declarationFindings(verdict, spoil(resilience, (e) => { e.knockout_axis_refs = ["axis://knockout/communication_edge"]; }), pairing), false);
  must("declaration/resilience-with-no-axis", lib.declarationFindings(verdict, spoil(resilience, (e) => { e.knockout_axis_refs = []; }), pairing), false);
  must("cost/declared-but-not-applied", lib.declarationFindings(spoil(verdict, (v) => { v.result_evidence.cost_normalized = false; }), estimand, pairing), false);
  must("cost/claimed-where-none-declared", lib.declarationFindings(verdict, spoil(estimand, (e) => { e.cost_normalization = "none"; }), pairing), false);

  // -- the four refusals --
  must("qualification/clean", lib.qualificationFindings(verdict), true);
  for (const basis of Object.keys(lib.REFUSED_BASES)) {
    must(`qualification/${basis}`, lib.qualificationFindings(spoil(verdict, (v) => { v.qualified_on = [basis]; })), false);
  }
  must("qualification/basis-invented", lib.qualificationFindings(spoil(verdict, (v) => { v.qualified_on = ["it felt better"]; })), false);
  must("qualification/qualified-on-nothing", lib.qualificationFindings(spoil(verdict, (v) => { v.qualified_on = []; })), false);
  must("qualification/qualified-below-the-minimum", lib.qualificationFindings(spoil(verdict, (v) => { v.result_evidence.meets_minimum_effect = false; })), false);
  for (const clause of ["grants_no_authority", "promotes_nothing", "activates_nothing", "rewrites_no_topology"]) {
    must(`qualification/${clause}`, lib.qualificationFindings(spoil(verdict, (v) => { v[clause] = false; })), false);
  }

  // -- the separation, in both directions --
  must("separation/clean", lib.separationFindings(verdict), true);
  must("separation/one-root", lib.separationFindings(spoil(verdict, (v) => { v.controller_continuity.continuity_root = v.result_evidence.result_root; })), false);
  // A half with NO root of its own is the other way to lose the separation, and it is invisible to the
  // equality check: two absent roots are not equal to each other either.
  must("separation/result-half-unrooted", lib.separationFindings(spoil(verdict, (v) => { v.result_evidence.result_root = "not-a-root"; })), false);
  must("separation/continuity-half-unrooted", lib.separationFindings(spoil(verdict, (v) => { delete v.controller_continuity.continuity_root; })), false);
  must("separation/result-reads-liveness", lib.separationFindings(spoil(verdict, (v) => { v.result_evidence.result_refs.push("lineage://etl/extract"); })), false);
  must("separation/continuity-reads-a-result", lib.separationFindings(spoil(verdict, (v) => { v.controller_continuity.lineage_ref = "evaluation-result://etl/collective/1"; })), false);
  must("separation/installation-from-the-posture", lib.separationFindings(spoil(verdict, (v) => { v.controller_continuity.installation_read_from = "posture"; })), false);
  const both = lib.bothDirections([verdict, VERDICT_HEALTHY()]);
  if (!both.result_survives_a_stopped_controller) f.push("separation/both: no qualified result stands beside a stopped controller, so canon's first sentence is unread");
  if (!both.healthy_controller_proves_no_result) f.push("separation/both: no healthy controller stands beside a result that did not qualify, so canon's second sentence is unread");
  const oneSided = lib.bothDirections([verdict, verdict]);
  if (oneSided.healthy_controller_proves_no_result) f.push("separation/both: two copies of one direction were read as both");

  // -- the matrix --
  must("matrix/clean", lib.matrixFindings(verdict), true);
  must("matrix/axis-not-performed", lib.matrixFindings(spoil(verdict, (v) => { v.knockouts = v.knockouts.filter((k) => k.axis !== "budget_exhausted"); })), false);
  must("matrix/axis-twice", lib.matrixFindings(spoil(verdict, (v) => { v.knockouts.push({ ...v.knockouts[0] }); })), false);
  // An axis the estate cannot execute, ADDED rather than swapped in: swapping one over a performed axis
  // also opens a hole in the matrix, and a drill whose case produces two findings cannot tell which check
  // caught it — which is exactly how the over-claim mutation survived its first battery.
  must("matrix/unperformable-reported-as-done", lib.matrixFindings(spoil(verdict, (v) => { v.knockouts.push({ ...v.knockouts[0], axis: "vibes_removed" }); })), false);
  must("matrix/axis-both-performed-and-named-absent", lib.matrixFindings(spoil(verdict, (v) => { v.knockouts[0].axis = "communication_edge"; })), false);
  must("matrix/absent-axis-unnamed", lib.matrixFindings(spoil(verdict, (v) => { v.named_absent_knockout_axes = v.named_absent_knockout_axes.filter((a) => a.axis !== "lease_expired"); })), false);
  must("matrix/absent-axis-without-a-reason", lib.matrixFindings(spoil(verdict, (v) => { v.named_absent_knockout_axes[0].reason = "no"; })), false);
  must("matrix/absent-axis-with-the-wrong-reason", lib.matrixFindings(spoil(verdict, (v) => { v.named_absent_knockout_axes[0].reason = "Nobody got round to building this one, which is a schedule and not a reason."; })), false);
  must("matrix/absent-axis-without-an-owner", lib.matrixFindings(spoil(verdict, (v) => { v.named_absent_knockout_axes[2].owner_ref = ""; })), false);
  must("matrix/axis-both-performed-and-absent", lib.matrixFindings(spoil(verdict, (v) => { v.named_absent_knockout_axes.push({ axis: "communication_edge", reason: v.named_absent_knockout_axes[0].reason, owner_ref: "canon://x" }); v.knockouts[0].axis = "communication_edge"; })), false);

  // -- evaluation is never activation --
  must("activation/clean", lib.activationFindings(verdict.knockouts[0], { records_written: false }), true);
  must("activation/not-reverted", lib.activationFindings({ ...verdict.knockouts[0], reverted: false }), false);
  must("activation/changed-something", lib.activationFindings({ ...verdict.knockouts[0], changed_nothing: false }), false);
  must("activation/lane-of-its-own", lib.activationFindings({ ...verdict.knockouts[0], lane: "knockout" }), false);
  must("activation/no-observation", lib.activationFindings({ ...verdict.knockouts[0], observation_ref: "" }), false);
  for (const effect of ["topology_rewritten", "participant_revoked", "controller_activated", "artifact_installed", "profile_promoted", "records_written"]) {
    must(`activation/observed-${effect}`, lib.activationFindings(verdict.knockouts[0], { [effect]: true }), false);
  }

  // -- the installation instrument --
  must("installation/clean", lib.installationAxisFindings({ read_through_posture: false, owner_serves_installation: false, posture_after_removal: "active" }), true);
  must("installation/read-through-the-posture", lib.installationAxisFindings({ read_through_posture: true, owner_serves_installation: false, posture_after_removal: "active" }), false);
  must("installation/owner-never-asked", lib.installationAxisFindings({ read_through_posture: false, posture_after_removal: "active" }), false);
  must("installation/posture-not-recorded", lib.installationAxisFindings({ read_through_posture: false, owner_serves_installation: false }), false);

  // -- the vocabularies are the estate's, not this file's --
  if (lib.EXECUTABLE_KNOCKOUTS.length !== 16) f.push(`vocabulary: ${lib.EXECUTABLE_KNOCKOUTS.length} executable axes, expected the sixteen the verdict contract enumerates`);
  if (Object.keys(lib.NAMED_ABSENT_KNOCKOUTS).length !== 5) f.push("vocabulary: the five axes canon names as unperformable are not five");
  if (lib.MATCH_AXES.length !== 8) f.push("vocabulary: canon names eight match axes");
  if (!/runtime_ref/u.test(lib.CONTROLLER_IS.means) || !/controller:\/\//u.test(lib.CONTROLLER_IS.not)) f.push("vocabulary: the two senses of controller are not written down");
  return f;
}

// ---- the seam: what the registered contracts refuse ---------------------------------------------------------
export function seamFindings({ registry, schemas, invariants }) {
  const f = [];
  const ids = {
    estimand: "schema://ioi/applications/ioi-ai/collective-qualification-estimand/v1",
    pairing: "schema://ioi/applications/ioi-ai/collective-baseline-pairing/v1",
    verdict: "schema://ioi/applications/ioi-ai/collective-qualification-verdict/v1",
  };
  for (const [name, id] of Object.entries(ids)) {
    const entry = registry.contracts.find((c) => c.contract_id === id);
    if (!entry) { f.push(`${name}: not registered`); continue; }
    if (LIB.CONTRACTS[name] !== id) f.push(`${name}: the oracle names a different contract id than the registry`);
    if (!entry.positive_fixture_refs?.length) f.push(`${name}: no positive fixture`);
    if (!entry.negative_fixture_refs?.length) f.push(`${name}: no negative fixture`);
    // THE SEAM DERIVES THE BINDING. A contract that REQUIRES system_binding could never admit: the seam
    // refuses a caller-authored one outright, stamps its own object and only then validates.
    const schema = schemas[name];
    if (schema.required?.includes("system_binding")) f.push(`${name}: requires a system_binding the seam refuses a caller to send`);
    if (schema.properties?.system_binding?.$ref !== "#/$defs/systemBinding") f.push(`${name}: system_binding is not the seam's own object shape`);
    // THE SEAM RESOLVES IDENTITY FROM A `*_id` MEMBER, and from EXACTLY ONE. A record carrying none is
    // refused `system_record_identity_unresolved` before any rule of its own is read, and a record
    // carrying two is refused for having two identities — so a contract meant for this seam that names its
    // identity `<x>_ref` alone can never be admitted at all. The instance cost this unit a plane round;
    // the class is checked here.
    const identities = Object.keys(schema.properties ?? {}).filter((member) => member.endsWith("_id"));
    if (identities.length !== 1) f.push(`${name}: ${identities.length} members end in _id (${identities.join(", ") || "none"}), and the seam admits exactly one identity`);
    else if (!schema.required?.includes(identities[0])) f.push(`${name}: ${identities[0]} is the seam's identity member and is not required`);
    const identityRule = invariants[name].rules.find((r) => r.rule_id.endsWith(".identity.matches"));
    if (!identityRule) f.push(`${name}: the identity and the ref every other record points at it by are not held equal`);
  }
  // A MATERIAL MEMBER THAT IS NOT REQUIRED CANNOT SURVIVE ITS OWN PROJECTION. The generator emits
  // `skip_serializing_if = "Option::is_none"` for every optional member, so a nullable-but-optional
  // material field is DROPPED when the record round-trips through the generated struct — and the root
  // rule then fails because its material is incomplete, not because anything moved. This cost the unit a
  // red golden-oracle run before it was understood, so the class is checked rather than the instance.
  for (const [name, inv] of Object.entries(invariants)) {
    const root = inv.rules.find((r) => r.expression?.operator === "jcs_sha256_equals");
    if (!root) { f.push(`${name}: no root rule`); continue; }
    for (const descriptor of Object.values(root.expression.material_fields ?? {})) {
      const member = String(descriptor.path).replace(/^\$\./u, "").split(".")[0];
      if (!schemas[name].required?.includes(member)) {
        f.push(`${name}: ${member} is material to the root but not required, so the projection drops it and the root cannot recompute`);
      }
    }
  }
  // the eight per-axis rules exist and each names its own axis
  const pairingRules = invariants.pairing.rules.map((r) => r.rule_id);
  for (const axis of LIB.MATCH_AXES) {
    const id = `collective_baseline_pairing.axis_${axis}.matches`;
    if (!pairingRules.includes(id)) { f.push(`pairing: no rule for the ${axis} axis`); continue; }
    const rule = invariants.pairing.rules.find((r) => r.rule_id === id);
    const paths = rule.expression?.paths ?? [];
    if (rule.expression?.operator !== "fields_equal") f.push(`pairing: the ${axis} rule does not compare the two arms`);
    if (!paths.every((p) => p.includes(`axis_proofs.${axis}.`))) f.push(`pairing: the ${axis} rule compares the wrong members (${paths.join(", ")})`);
  }
  // the separation is refused at the wire, not only by the oracle
  const sep = invariants.verdict.rules.find((r) => r.rule_id === "collective_qualification_verdict.result_and_continuity.are_separately_rooted");
  if (sep?.expression?.operator !== "fields_not_equal") f.push("verdict: the two halves are not refused sharing one root");
  // the four canon refuses are not in the enum at all
  const bases = schemas.verdict.properties?.qualified_on?.items?.enum ?? [];
  for (const refused of Object.keys(LIB.REFUSED_BASES)) {
    if (bases.includes(refused)) f.push(`verdict: ${refused} can be NAMED as a basis`);
  }
  if (bases.length !== LIB.ADMISSIBLE_BASES.length || !LIB.ADMISSIBLE_BASES.every((b) => bases.includes(b))) {
    f.push(`verdict: the admissible bases on the wire are not the oracle's three (${bases.join(", ")})`);
  }
  // the never-clauses are const true rather than a convention
  for (const clause of ["grants_no_authority", "promotes_nothing", "activates_nothing", "rewrites_no_topology"]) {
    if (schemas.verdict.properties?.[clause]?.const !== true) f.push(`verdict: ${clause} is not pinned on the wire`);
  }
  if (schemas.verdict.properties?.controller_continuity?.properties?.installation_read_from?.const !== "owner") {
    f.push("verdict: the installation instrument is not pinned to the owner on the wire");
  }
  const lane = schemas.verdict.properties?.knockouts?.items?.properties?.lane?.const;
  if (lane !== "cross_play_ablation") f.push(`verdict: the knockout lane is ${lane}, not the ablation lane the plane already admits`);
  const axes = schemas.verdict.properties?.knockouts?.items?.properties?.axis?.enum ?? [];
  if (axes.length !== LIB.EXECUTABLE_KNOCKOUTS.length || !LIB.EXECUTABLE_KNOCKOUTS.every((a) => axes.includes(a))) {
    f.push("verdict: the wire's executable axes are not the oracle's");
  }
  const absent = schemas.verdict.properties?.named_absent_knockout_axes?.items?.properties?.axis?.enum ?? [];
  if (!Object.keys(LIB.NAMED_ABSENT_KNOCKOUTS).every((a) => absent.includes(a))) f.push("verdict: the wire cannot name every axis canon names as unperformable");
  // the estimand is sealed, so freezing its ref freezes its content
  if (!invariants.estimand.rules.some((r) => r.rule_id === "collective_qualification_estimand.root.recomputes")) {
    f.push("estimand: no root rule, so the epoch freezes a name whose content can still move");
  }
  return f;
}

// ---- source ---------------------------------------------------------------------------------------------------
export function sourceFindings({ canon, composer, evalRoutes, lib }) {
  const f = [];
  const code = LIB.codeOnly(lib);
  // the layer law: the oracle and the contracts live on the application side and name no Hypervisor family
  if (/hypervisor-family|family:\/\/ioi\/hypervisor/u.test(code)) f.push("the oracle names a Hypervisor family");
  if (!/orchestration_ref: this\.orchestration\.scope_ref/u.test(composer)) f.push("the composer does not stamp its records with the orchestration's own scope");
  // the evaluation plane must not have grown an import of the orchestration application
  if (/ioi-ai\/orchestration|collective-qualification|collective-baseline-pairing/u.test(evalRoutes)) {
    f.push("the Hypervisor evaluation plane now references the orchestration application's records, which its own layer law forbids");
  }
  // `cross_play_ablation` is the plane's OWN lane, not one this unit invented
  if (!/cross_play_ablation/u.test(evalRoutes)) f.push("cross_play_ablation is not a lane the evaluation plane admits, so the knockouts run somewhere invented");
  // the two senses of controller are distinguished where a reader would look
  if (!/Collective qualification/u.test(canon)) f.push("canon carries no Collective qualification section");
  if (!/controller:\/\//u.test(canon.slice(canon.indexOf("## Collective qualification")))) {
    f.push("canon does not distinguish the embodied controller:// scheme from the persistent controller");
  }
  const section = canon.slice(canon.indexOf("## Collective qualification"));
  for (const phrase of [/positive control/iu, /read from the owner/iu, /evaluation is never activation/iu, /cheapest adequate/iu, /own roots/iu]) {
    if (!phrase.test(section)) f.push(`canon does not state: ${phrase.source}`);
  }
  // posture() is the trap, and the composer still has the shape that makes it one
  if (/installation_ref/u.test(composer.slice(composer.indexOf("async posture("), composer.indexOf("async posture(") + 2200))) {
    f.push("posture() now reads installation_ref, so clause 8's premise has changed and the gate must be re-measured rather than kept");
  }
  return f;
}

export function sourceInputs() {
  return { canon: readText(CANON), composer: readText(COMPOSER), evalRoutes: readText(EVAL_ROUTES), lib: readText(LIB_PATH) };
}

// ---- the binding --------------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci }) {
  const f = [];
  for (const script of ["check:collective-controller-qualification", "mutate:collective-controller-qualification"]) {
    if (!rootPkg.scripts?.[script]) f.push(`root_script_missing:${script}`);
  }
  if (!appPkg.scripts?.["check:collective-controller-qualification"]) f.push("app_drills_script_missing");
  const rows = floors.verifiers ?? [];
  const named = (id) => rows.find((r) => r.id === id);
  for (const id of ["collective-controller-qualification", "collective-artifact-runtime-lifecycle", "governed-evaluation-plane"]) {
    const row = named(id);
    if (!row) f.push(`floor_row_missing:${id}`);
    else if (!(Number.isInteger(row.runtime_assertions) && row.runtime_assertions > 0)) f.push(`floor_row_without_a_floor:${id}`);
    else if (!/^[0-9a-f]{64}$/u.test(row.assertion_names_sha256 ?? "")) f.push(`floor_row_without_a_name_digest:${id}`);
    else if (!fs.existsSync(path.resolve(ROOT, row.source))) f.push(`floor_row_source_missing:${id}`);
  }
  if (!/check:collective-controller-qualification/u.test(ci)) f.push("gate_not_ci_bound");
  const seen = new Set();
  for (const c of CLAUSES) {
    seen.add(c.n);
    if (!(typeof c.demand === "string" && c.demand.length > 40)) f.push(`clause_${c.n}_demand_too_thin`);
    if (!(c.executed_by?.length) && !c.absence) f.push(`clause_${c.n}_neither_executed_nor_named`);
    for (const g of c.executed_by ?? []) {
      if (g.kind === "app") {
        if (!appPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        if (!g.floor) f.push(`clause_${c.n}_binds_unfloored_gate: ${g.script}`);
        else if (!named(g.floor)) f.push(`clause_${c.n}_binds_absent_floor_row: ${g.floor}`);
      } else if (g.kind !== "self") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) f.push(`clause_missing: ${n}`);
  return f;
}

export function verdict(rows) {
  const failures = [];
  const absences = [];
  const seen = new Set();
  for (const r of rows) {
    if (!Number.isInteger(r.n) || r.n < 1 || r.n > 12) { failures.push(`row_out_of_range:${r.n}`); continue; }
    if (seen.has(r.n)) failures.push(`row_duplicated:${r.n}`);
    seen.add(r.n);
    for (const g of r.executed ?? []) {
      if (g.status !== 0) failures.push(`clause_${r.n}_red: ${g.script} exit ${g.status}`);
      else if (!g.evidence || !g.evidence_sha256) failures.push(`clause_${r.n}_fabricated: ${g.script} reports success without evidence`);
      if (g.floor_expected != null && g.executed_assertions != null && g.executed_assertions < g.floor_expected) failures.push(`clause_${r.n}_below_floor: ${g.script} ${g.executed_assertions} < ${g.floor_expected}`);
    }
    if (r.absence) { if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`); else absences.push({ n: r.n, ...r.absence }); }
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

// ---- drills ---------------------------------------------------------------------------------------------------
async function drills() {
  const pure = pureFindings(LIB);
  evidence.pure = { findings: pure };
  ok("PURE — the oracle refuses every unmatched axis BY ITS NAME, a broken comparator, a declaration made after what it is read against, each of the four canon refuses, both directions of the result/continuity mix, an incomplete or over-claimed matrix, a knockout that activated something and an installation axis read through the posture — and accepts the clean shapes", pure.length === 0, pure.slice(0, 4).join(" ; "));

  const seam = seamFindings({
    registry: readJson(path.join(META, "architecture-contract-registry.v1.json")),
    schemas: {
      estimand: readJson(path.join(META, "collective-qualification-estimand.v1.schema.json")),
      pairing: readJson(path.join(META, "collective-baseline-pairing.v1.schema.json")),
      verdict: readJson(path.join(META, "collective-qualification-verdict.v1.schema.json")),
    },
    invariants: {
      estimand: readJson(path.join(META, "invariants", "collective-qualification-estimand.v1.invariants.json")),
      pairing: readJson(path.join(META, "invariants", "collective-baseline-pairing.v1.invariants.json")),
      verdict: readJson(path.join(META, "invariants", "collective-qualification-verdict.v1.invariants.json")),
    },
  });
  evidence.seam = { findings: seam };
  ok("SEAM — three registered contracts carry the law on the wire: eight per-axis equality rules each comparing its own axis, a separate-roots rule, an admissible-basis enum that cannot NAME any of the four canon refuses, four never-clauses and the installation instrument pinned as consts, and a system_binding shaped as the seam's own derived object rather than one a caller could author", seam.length === 0, seam.slice(0, 4).join(" ; "));

  const src = sourceFindings(sourceInputs());
  evidence.source = { findings: src };
  ok("SOURCE — the composition stays on the application side of the layer law and the Hypervisor evaluation plane references none of it, the knockouts run on a lane that plane already admits, canon states the positive control, the owner-read installation and evaluation-is-never-activation, and posture() still does not read installation_ref — the premise clause 8 rests on", src.length === 0, src.slice(0, 4).join(" ; "));

  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP_DIR, "package.json")),
    floors: readJson(FLOORS),
    ci: fs.readdirSync(path.join(ROOT, ".github", "workflows")).map((file) => readText(path.join(ROOT, ".github", "workflows", file))).join("\n"),
  });
  ok("BINDING — the gate is floored with an existing source and CI-bound, every clause is executed or named with an owner, and the twelve clauses are present", binding.length === 0, binding.slice(0, 4).join(" ; "));

  const v = verdict([{ n: 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] }]);
  ok("VERDICT — a table missing eleven of its twelve rows is a FAIL, not a pass", v.kind === "fail" && v.failures.includes("row_missing:12"), v.failures.slice(0, 2).join(" ; "));
  const full = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] })));
  ok("VERDICT — twelve green rows with no absence is a PASS", full.kind === "pass", full.failures.slice(0, 2).join(" ; "));
  const named = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }], absence: i === 5 ? { what: "a named absence long enough to be real", owner: "someone" } : null })));
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", named.kind === "named_failure" && named.absences.length === 1, named.kind);
  const unevidenced = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0 }] })));
  ok("VERDICT — a gate that reports success without evidence is fabricated, not green", unevidenced.kind === "fail" && unevidenced.failures.every((x) => x.includes("fabricated")), unevidenced.failures[0]);
  const belowFloor = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s", floor_expected: 9, executed_assertions: 2 }] })));
  ok("VERDICT — a gate below its floor fails even at exit 0", belowFloor.kind === "fail" && belowFloor.failures.every((x) => x.includes("below_floor")), belowFloor.failures[0]);
}

// ---- mutation -------------------------------------------------------------------------------------------------
async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "collective-qualification-mutation-"));
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

  // THE FIFTEEN THE MANIFEST NAMES: baseline, participant, edge, ancestry, installation, runtime,
  // caretaker, dependency, lease, budget, health, restart, cost, result/controller conflation and
  // evaluation-as-activation — each planted where the oracle would have to be wrong to miss it.
  await mutate("BASELINE — an axis that differs is no longer a finding", (t) => t.replace("    if (collective !== baseline) {", "    if (false) {"));
  await mutate("BASELINE — the finding stops naming the axis that differed", (t) => t.replace("findings.push(`${where}: the arms differ on ${axis} — ${collective.slice(7, 19)} ≠ ${baseline.slice(7, 19)}`);", "findings.push(`${where}: unmatched`);"));
  await mutate("BASELINE — two arms may be one composition", (t) => t.replace('if (str(pairing.collective_arm, "composition_ref") === str(pairing.baseline_arm, "composition_ref")) {', "if (false) {"));
  await mutate("BASELINE — a baseline that passed nothing is fine", (t) => t.replace("if (Number.isInteger(passed) && passed <= 0) {", "if (false) {"));
  await mutate("BASELINE — the control need name no result it was read from", (t) => t.replace('if (!list(control, "control_result_refs").length) {', "if (false) {"));
  // The basis loop never runs at all. Emptying one entry of REFUSED_BASES is NOT this defect: the oracle
  // is doubly guarded there, since a basis that is neither refused nor admissible is still refused for not
  // being admissible. The defect that would actually let a participant count qualify is the loop going.
  await mutate("PARTICIPANT — the basis of a qualification is never examined", (t) => t.replace('for (const basis of list(verdict, "qualified_on")) {', "for (const basis of []) {"));
  await mutate("EDGE — an axis this estate cannot perform may be reported as performed", (t) => t.replace("    if (!EXECUTABLE_KNOCKOUTS.includes(axis)) {\n      findings.push(`${where}: ${axis} was reported as performed but this estate cannot execute it`);\n    }", "    if (false) { /* planted */ }"));
  await mutate("EDGE — an unperformable axis need not be named at all", (t) => t.replace("      findings.push(`${where}: the absent axis ${axis} is not named`);", "      /* planted */"));
  await mutate("ANCESTRY — a missing executable axis is not a gap", (t) => t.replace("    if (!seen.has(axis)) findings.push(`${where}: the executable axis ${axis} was not performed`);", "    if (false) findings.push(``);"));
  await mutate("INSTALLATION — the axis may be read through the posture", (t) => t.replace("  if (observation.read_through_posture === true) {", "  if (false) {"));
  await mutate("INSTALLATION — the verdict may say it read the posture", (t) => t.replace('if (str(continuity, "installation_read_from") !== "owner") {', "if (false) {"));
  await mutate("RUNTIME — the result may read controller liveness", (t) => t.replace("    if (/^lineage:\\/\\/|posture|runtime|orphan/u.test(String(ref))) {", "    if (false) {"));
  await mutate("CARETAKER — an estimand's declared axis need not have been performed", (t) => t.replace("      if (!performed.includes(tail)) findings.push(`${where}: the estimand's axis ${axis} was never performed`);", "      /* planted */"));
  await mutate("DEPENDENCY — an axis may be knocked out twice and the matrix still read complete", (t) => t.replace('if (seen.size !== performed.length) findings.push(`${where}: an axis was knocked out more than once`);', ""));
  await mutate("LEASE — an absent axis may give a reason that is not this estate's", (t) => t.replace("    else if (!expected.test(reason)) findings.push(`${where}: the absent axis ${axis} gives a reason that is not why this estate cannot perform it`);", ""));
  await mutate("BUDGET — a verdict may claim a normalization its estimand declared none of", (t) => t.replace('if (declared === "none" && applied === true) {', "if (false) {"));
  await mutate("BUDGET — a declared normalization need not be applied", (t) => t.replace('if (declared && declared !== "none" && applied !== true) {', "if (false) {"));
  await mutate("HEALTH — continuity may read an evaluation result", (t) => t.replace('if (/^evaluation-result:\\/\\/|^evaluation-run:\\/\\//u.test(str(continuity, "lineage_ref"))) {', "if (false) {"));
  await mutate("RESTART — a knockout need not revert", (t) => t.replace("  if (knockout.reverted !== true) {", "  if (false) {"));
  await mutate("COST — qualifying below the declared minimum effect is fine", (t) => t.replace('if (str(verdict, "outcome") === "qualified" && verdict?.result_evidence?.meets_minimum_effect !== true) {', "if (false) {"));
  await mutate("CONFLATION — one root for both halves is fine", (t) => t.replace('} else if (str(result, "result_root") === str(continuity, "continuity_root")) {', "} else if (false) {"));
  await mutate("CONFLATION — a half may carry no root of its own", (t) => t.replace('if (!SHA256.test(str(result, "result_root")) || !SHA256.test(str(continuity, "continuity_root"))) {', "if (false) {"));
  await mutate("CONFLATION — two copies of one direction read as both directions", (t) => t.replace('(v) => str(v, "outcome") !== "qualified" && str(v?.controller_continuity, "derived_status") === "active",', "() => true,"));
  await mutate("ACTIVATION — a knockout that changed the live composition is fine", (t) => t.replace("  if (knockout.changed_nothing !== true) {", "  if (false) {"));
  await mutate("ACTIVATION — what the RUN observed is not consulted at all", (t) => t.replace("      if (observed[effect] === true) findings.push(`${where} ${axis}: the run ${what}, whatever the record says`);", "      /* planted */"));
  await mutate("ACTIVATION — a knockout may invent a lane of its own", (t) => t.replace('if (str(knockout, "lane") !== "cross_play_ablation") {', "if (false) {"));
  await mutate("ACTIVATION — a never-clause may be unheld", (t) => t.replace('if (verdict[clause] !== true) findings.push(`${where}: ${clause} is not held, and evaluation emits judgment only`);', ""));
  await mutate("DECLARATION — the verdict may name an estimand it was not read against", (t) => t.replace('if (str(verdict, "estimand_ref") !== str(estimand, "estimand_ref")) {', "if (false) {"));
  await mutate("DECLARATION — the pairing may have been assembled after its arms ran", (t) => t.replace("if (pairing.declared_before_either_arm_ran !== true) {", "if (false) {"));
  await mutate("DECLARATION — an estimand declared after the freeze is fine", (t) => t.replace("if (estimand.declared_before_epoch_freeze !== true) {", "if (false) {"));
  await mutate("BASIS — an invented basis is admissible", (t) => t.replace("else if (!ADMISSIBLE_BASES.includes(basis)) findings.push(`${where}: ${basis} is not an admissible basis`);", ""));

  fs.rmSync(dir, { recursive: true, force: true });
  evidence.mutation = { planted, caught };
  console.log(`\n${caught}/${planted} planted defects caught`);
  return caught === planted && planted >= 30;
}

// ---- main ---------------------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = (await mutation()) ? 0 : 1;
  else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "collective-controller-qualification", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") {
      const { planeLeg } = await import("./lib/collective-qualification-plane.mjs");
      const plane = await planeLeg({ ROOT, LIB });
      evidence.plane = plane;
      console.log(`\n# PLANE — ${plane.findings.length === 0 ? "green" : plane.findings.slice(0, 5).join("; ")} in ${plane.seconds}s`);
      if (plane.blocked) blocked(plane.findings.join("; "));
      const rows = CLAUSES.map((c) => ({
        n: c.n,
        executed: (c.executed_by ?? []).map((g) => ({ script: g.script, status: g.kind === "self" ? (g.script.startsWith("plane") ? (plane.findings.length ? 1 : 0) : 0) : 0, evidence: { leg: g.script }, evidence_sha256: sha256(g.script) })),
        absence: c.absence || null,
      }));
      const v = verdict(rows);
      evidence.verdict = v;
      console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
      for (const a of v.absences) console.log(`NAMED  clause ${a.n}: ${a.what.slice(0, 170)} → ${a.owner.slice(0, 120)}`);
      exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1;
    }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
