// M10.9 — THE PURE ORACLE FOR COLLECTIVE AND PERSISTENT-CONTROLLER QUALIFICATION.
//
// Canon: collective machinery earns its complexity. A frozen epoch compares the exact collective
// composition against a MATCHED cheaper baseline under a DECLARED estimand with the full knockout matrix,
// and neither participant count, aggregate score, active artifact nor surviving process proves cooperation
// surplus, runtime continuity or authority.
//
// Everything here is a pure function of its arguments, so the unit's battery can load a mutated copy and
// score the oracle itself.
//
// WHAT THIS FILE IS FOR, GIVEN THAT THE CONTRACTS ALREADY REFUSE A LOT. Three registered contracts carry
// the wire-level law: the estimand's `const true` declaration clauses, the pairing's eight per-axis
// `fields_equal` rules, the verdict's `qualified_on` enum (which cannot even NAME the four canon refuses)
// and its separate-roots rule. What no contract can say is whether a set of records HANGS TOGETHER — that
// the verdict was read against the pairing it names, that the matrix is complete rather than merely
// well-formed, that the estimand came first, and that what the plane actually DID matches what the record
// says it did. Those are the findings below.
//
// THE FOUR CLAIMS THE ACCEPTANCE NAMES, and why each is not evidence:
//   a participant COUNT is an input, not a result;
//   an aggregate SCORE is not a surplus unless the arm it beat was matched, because an unmatched baseline
//     measures the mismatch;
//   an ACTIVE ARTIFACT is not continuity — canon's own words are that an artifact marked active is not
//     evidence that any runtime existed or that its authority remained current;
//   a SURVIVING PROCESS is neither authority nor a result.
//
// AND THE ONE THIS UNIT COULD HAVE AUTHORED ITSELF: the persistent lineage's posture is a single scalar
// bundling authority staleness, caretaker absence, dependency loss and runtime absence. Binding it as
// result evidence would make a healthy runtime into proof of a good answer. Result robustness and
// controller continuity are separate members with separate roots, and this oracle refuses both directions
// of the mix.

export const ESTIMAND_KINDS = Object.freeze(["cooperation_surplus", "resilience", "independence"]);
export const CONTRACTS = Object.freeze({
  estimand: "schema://ioi/applications/ioi-ai/collective-qualification-estimand/v1",
  pairing: "schema://ioi/applications/ioi-ai/collective-baseline-pairing/v1",
  verdict: "schema://ioi/applications/ioi-ai/collective-qualification-verdict/v1",
});

/**
 * The axes two arms must be matched on. Canon names them: identical task, authority, context, tool,
 * environment, budget, time and verifier posture. A comparison that does not state its match axes is a
 * comparison of two different things.
 */
export const MATCH_AXES = Object.freeze([
  "task",
  "authority",
  "context",
  "tool",
  "environment",
  "budget",
  "time",
  "verifier_posture",
]);

/** The knockout axes this estate can PERFORM today, each against a real operation. */
export const EXECUTABLE_KNOCKOUTS = Object.freeze([
  "participant_exit",
  "caretaker_exit",
  "dependency_retired",
  "creator_session_removed",
  "context_lease_revoked",
  "artifact_ancestry_removed",
  "controller_runtime_unserved",
  "installation_unbound",
  "verifier_invalidated",
  "budget_exhausted",
  "lifecycle_stop",
  "lifecycle_quarantine",
  "lifecycle_repair",
  "lifecycle_replacement",
  "lifecycle_retirement",
  "crash_restart",
]);

/**
 * The knockout axes canon names that this estate cannot perform, each with the reason it cannot. A gate
 * that listed these as executable would be an unfalsifiable bar; one that omitted them would quietly
 * narrow the acceptance. They are matched on SUBSTANCE, not on wording, so a record may say it in its own
 * words and still be refused for naming a different reason than the one that holds.
 */
export const NAMED_ABSENT_KNOCKOUTS = Object.freeze({
  communication_edge: /(?:edge|channel|message)/iu,
  role_removed: /role ?topology/iu,
  lease_expired: /expired/iu,
  disclosure_overhead: /disclosure/iu,
  verification_overhead: /verification[ _]cost/iu,
});

/**
 * "CONTROLLER" MEANS THE RUNTIME BINDING HERE, and this constant exists so the meaning is written down.
 * `controller://` DOES exist in canon — as an EMBODIED-runtime identity for robots, facilities, actuators
 * and bridges. That is a different object, and a reader grepping the scheme would find canon and take it
 * for this unit's persistent controller. The persistent controller is the lineage's `runtime_ref` and its
 * `runtime_kind`; knocking it out means making that runtime unserved.
 */
export const CONTROLLER_IS = Object.freeze({
  means: "the persistent executable lineage's runtime_ref and runtime_kind",
  not: "the embodied controller:// identity for robots, facilities, actuators and bridges",
});

/** The bases a verdict may rest on, and they are the only three. */
export const ADMISSIBLE_BASES = Object.freeze([
  "matched_baseline_effect",
  "knockout_degradation",
  "independence_of_named_axis",
]);

/** What canon refuses as a basis, with the sentence that refuses it. */
export const REFUSED_BASES = Object.freeze({
  participant_count: "a participant count is an input, not a surplus",
  aggregate_score: "an aggregate score over an unmatched baseline measures the mismatch, not a surplus",
  active_artifact:
    "an artifact marked active is not evidence that any runtime existed or that its authority remained current",
  surviving_process: "a surviving process is neither authority nor a result",
});

const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const str = (value, key) => (typeof value?.[key] === "string" ? value[key] : "");
const list = (value, key) => (Array.isArray(value?.[key]) ? value[key] : []);

/**
 * MATCHED-BASELINE IDENTITY. Every declared axis carries its own proof, and an axis whose two arms differ
 * refuses BY NAME rather than reducing to a single "matched: false". Naming the axis is what lets a reader
 * tell "the baseline had a different toolset" from "the baseline ran on a different day".
 *
 * The registered invariants enforce the same eight equalities at the seam. This is not a duplicate: the
 * seam refuses a RECORD, and this refuses a COMPARISON — it is handed the arms a run actually used and
 * checks the pairing against them, which no rule over one record's own members can do.
 */
export function matchFindings(pairing, { where = "pairing" } = {}) {
  const findings = [];
  if (!pairing || typeof pairing !== "object") return [`${where}: the pairing is not an object`];
  const declared = list(pairing, "declared_match_axes");
  for (const axis of MATCH_AXES) {
    if (!declared.includes(axis)) findings.push(`${where}: the axis ${axis} is not declared`);
  }
  for (const axis of declared) {
    if (!MATCH_AXES.includes(axis)) findings.push(`${where}: ${axis} is not a match axis`);
  }
  const proofs = pairing.axis_proofs ?? {};
  for (const axis of MATCH_AXES) {
    const proof = proofs[axis];
    if (!proof || typeof proof !== "object") {
      findings.push(`${where}: the axis ${axis} carries no proof`);
      continue;
    }
    const collective = str(proof, "collective_root");
    const baseline = str(proof, "baseline_root");
    if (!SHA256.test(collective) || !SHA256.test(baseline)) {
      findings.push(`${where}: the axis ${axis} does not carry a root for each arm`);
      continue;
    }
    if (collective !== baseline) {
      findings.push(`${where}: the arms differ on ${axis} — ${collective.slice(7, 19)} ≠ ${baseline.slice(7, 19)}`);
    }
  }
  if (str(pairing.collective_arm, "composition_ref") === str(pairing.baseline_arm, "composition_ref")) {
    findings.push(`${where}: both arms name one composition, so every axis matches trivially and the comparison is with itself`);
  }
  if (str(pairing.collective_arm, "arm_kind") !== "collective") {
    findings.push(`${where}: the collective arm is not typed as the collective`);
  }
  if (str(pairing.baseline_arm, "arm_kind") === "collective") {
    findings.push(`${where}: the baseline arm is a second collective, so nothing cheaper was compared against`);
  }
  return findings;
}

/**
 * THE POSITIVE CONTROL. A baseline that fails everything would make any collective look good, so a
 * matched pairing is only usable if the baseline actually PASSED matched cases on its own. Without this,
 * "the collective beat the baseline" is satisfied by breaking the baseline — the cheapest possible way to
 * manufacture a surplus, and the reason this check is not optional.
 */
export function positiveControlFindings(pairing, { where = "pairing" } = {}) {
  const findings = [];
  const control = pairing?.baseline_positive_control;
  if (!control || typeof control !== "object") {
    return [`${where}: the pairing carries no baseline positive control, so a broken baseline would pass`];
  }
  const cases = control.matched_cases_total;
  const passed = control.matched_cases_passed;
  if (!Number.isInteger(cases) || cases <= 0) findings.push(`${where}: the positive control names no matched cases`);
  if (!Number.isInteger(passed)) findings.push(`${where}: the positive control names no passing count`);
  if (Number.isInteger(passed) && passed <= 0) {
    findings.push(`${where}: the baseline passed none of the matched cases, so any collective would look better than it`);
  }
  if (Number.isInteger(cases) && Number.isInteger(passed) && passed > cases) {
    findings.push(`${where}: the positive control claims more passes than cases`);
  }
  if (!list(control, "control_result_refs").length) {
    findings.push(`${where}: the positive control names no result it was read from, so its pass count is a number about itself`);
  }
  return findings;
}

/**
 * THE DECLARATION CAME FIRST AND THE VERDICT WAS READ AGAINST IT. The registered contracts validate each
 * record's own shape; this checks what only the comparison knows — that the three records name each other,
 * that both declarations predate what they are read against, and that a resilience or independence claim's
 * axes were actually performed in this run.
 */
export function declarationFindings(verdict, estimand, pairing, { where = "verdict" } = {}) {
  const findings = [];
  if (!estimand || typeof estimand !== "object") return [`${where}: no estimand is bound`];
  if (!pairing || typeof pairing !== "object") return [`${where}: no pairing is bound`];
  if (str(verdict, "estimand_ref") !== str(estimand, "estimand_ref")) {
    findings.push(`${where}: the verdict names an estimand it was not read against`);
  }
  if (str(verdict, "pairing_ref") !== str(pairing, "pairing_ref")) {
    findings.push(`${where}: the verdict names a pairing it was not read across`);
  }
  if (str(pairing, "estimand_ref") !== str(estimand, "estimand_ref")) {
    findings.push(`${where}: the pairing was declared for a different estimand than the verdict was read against`);
  }
  if (estimand.declared_before_epoch_freeze !== true) {
    findings.push(`${where}: the estimand was not declared before the epoch froze`);
  }
  if (pairing.declared_before_either_arm_ran !== true) {
    findings.push(`${where}: the pairing was assembled after its arms ran`);
  }
  if (estimand.qualifies_nothing_on_its_own !== true) {
    findings.push(`${where}: the estimand claims to qualify something on its own`);
  }
  if (!ESTIMAND_KINDS.includes(str(estimand, "estimand_kind"))) {
    findings.push(`${where}: ${str(estimand, "estimand_kind")} is not an estimand kind`);
  }
  if (["resilience", "independence"].includes(str(estimand, "estimand_kind"))) {
    const axes = list(estimand, "knockout_axis_refs");
    if (!axes.length) findings.push(`${where}: a ${str(estimand, "estimand_kind")} estimand names no axes`);
    const performed = list(verdict, "knockouts").map((k) => str(k, "axis"));
    for (const axis of axes) {
      const tail = String(axis).split("/").pop();
      if (!performed.includes(tail)) findings.push(`${where}: the estimand's axis ${axis} was never performed`);
    }
  }
  // COST. A collective that wins by spending more has not earned its complexity, and the estimand is where
  // that was decided. `none` is admissible and says plainly that cost is not controlled for — but then the
  // verdict may not claim it normalized, and if the estimand DID declare a normalization the verdict must
  // have applied it.
  const declared = str(estimand, "cost_normalization");
  const applied = verdict?.result_evidence?.cost_normalized;
  if (declared && declared !== "none" && applied !== true) {
    findings.push(`${where}: the estimand declared ${declared} and the verdict did not normalize, so the effect is unadjusted for spend`);
  }
  if (declared === "none" && applied === true) {
    findings.push(`${where}: the verdict claims a normalization its estimand declared none of`);
  }
  return findings;
}

/**
 * THE FOUR REFUSALS THE ACCEPTANCE NAMES, plus the never-clauses. The verdict's own enum already forbids
 * the four as a BASIS; this catches them arriving as an INPUT, which is the same claim wearing a different
 * member name, and it is the form the mistake actually takes.
 */
export function qualificationFindings(verdict, { where = "verdict" } = {}) {
  const findings = [];
  if (!verdict || typeof verdict !== "object") return [`${where}: the verdict is not an object`];

  for (const basis of list(verdict, "qualified_on")) {
    if (Object.hasOwn(REFUSED_BASES, basis)) findings.push(`${where}: ${REFUSED_BASES[basis]}`);
    else if (!ADMISSIBLE_BASES.includes(basis)) findings.push(`${where}: ${basis} is not an admissible basis`);
  }
  if (str(verdict, "outcome") === "qualified" && !list(verdict, "qualified_on").length) {
    findings.push(`${where}: qualified on nothing at all`);
  }
  if (str(verdict, "outcome") === "qualified" && verdict?.result_evidence?.meets_minimum_effect !== true) {
    findings.push(`${where}: qualified without meeting the declared minimum effect`);
  }
  for (const clause of ["grants_no_authority", "promotes_nothing", "activates_nothing", "rewrites_no_topology"]) {
    if (verdict[clause] !== true) findings.push(`${where}: ${clause} is not held, and evaluation emits judgment only`);
  }
  return findings;
}

/**
 * RESULT AND CONTINUITY STAY APART, IN BOTH DIRECTIONS. The lineage posture is a liveness scalar; reading
 * it as result evidence is the conflation this unit exists to refuse, and reading a score as liveness is
 * the same error mirrored. Only the authority half of this is proven anywhere today.
 */
export function separationFindings(verdict, { where = "verdict" } = {}) {
  const findings = [];
  const result = verdict?.result_evidence ?? {};
  const continuity = verdict?.controller_continuity ?? {};
  for (const ref of list(result, "result_refs")) {
    if (/^lineage:\/\/|posture|runtime|orphan/u.test(String(ref))) {
      findings.push(`${where}: the result reads ${ref}, which is controller liveness rather than result evidence`);
    }
  }
  if (/^evaluation-result:\/\/|^evaluation-run:\/\//u.test(str(continuity, "lineage_ref"))) {
    findings.push(`${where}: controller continuity reads an evaluation result, which is result evidence rather than liveness`);
  }
  if (!SHA256.test(str(result, "result_root")) || !SHA256.test(str(continuity, "continuity_root"))) {
    findings.push(`${where}: one half carries no root of its own`);
  } else if (str(result, "result_root") === str(continuity, "continuity_root")) {
    findings.push(`${where}: result robustness and controller continuity share one root, so neither can be read without the other`);
  }
  if (str(continuity, "installation_read_from") !== "owner") {
    findings.push(`${where}: the installation binding was read from ${str(continuity, "installation_read_from") || "nothing"} rather than from the owner`);
  }
  return findings;
}

/**
 * BOTH OF CANON'S SENTENCES ARE READABLE FROM THE RECORDS. An accepted result may survive after a runtime
 * must stop, and a healthy runtime proves neither result quality nor current authority. A record set in
 * which the two halves always agree satisfies the separation on the wire while demonstrating none of it,
 * so the gate asks for one of each and this says which it got.
 */
export function bothDirections(verdicts) {
  const rows = Array.isArray(verdicts) ? verdicts : [];
  const stopped = new Set(["stopped", "quarantined", "replaced", "retired"]);
  return {
    result_survives_a_stopped_controller: rows.some(
      (v) => str(v, "outcome") === "qualified" && stopped.has(str(v?.controller_continuity, "derived_status")),
    ),
    healthy_controller_proves_no_result: rows.some(
      (v) => str(v, "outcome") !== "qualified" && str(v?.controller_continuity, "derived_status") === "active",
    ),
  };
}

/**
 * EVALUATION IS NEVER ACTIVATION. Canon: knockout and ablation results are judgment evidence only; they do
 * not rewrite the live topology, revoke a participant, activate a controller, install an artifact or
 * promote a profile. No code asserted this before this unit.
 */
export function activationFindings(knockout, observed, { where = "knockout" } = {}) {
  const findings = [];
  if (!knockout || typeof knockout !== "object") return [`${where}: the knockout is not an object`];
  const axis = str(knockout, "axis") || "an unnamed axis";
  if (knockout.reverted !== true) {
    findings.push(`${where} ${axis}: it did not revert, so the tested topology is the live one now`);
  }
  if (knockout.changed_nothing !== true) {
    findings.push(`${where} ${axis}: it changed the live composition, and a knockout is judgment evidence only`);
  }
  if (str(knockout, "lane") !== "cross_play_ablation") {
    findings.push(`${where} ${axis}: it ran on ${str(knockout, "lane") || "no lane"}, and the ablation lane the plane already admits is cross_play_ablation`);
  }
  if (!str(knockout, "observation_ref")) {
    findings.push(`${where} ${axis}: it names no observation, so its degradation is a number about itself`);
  }
  // What the RUN observed, when the gate hands it over: the same never-clauses, measured rather than
  // declared. A record that says `changed_nothing` while the plane recorded a write is the interesting
  // failure, and it is invisible to any check over the record alone.
  if (observed && typeof observed === "object") {
    for (const [effect, what] of [
      ["topology_rewritten", "rewrote the live topology"],
      ["participant_revoked", "revoked a participant"],
      ["controller_activated", "activated a controller"],
      ["artifact_installed", "installed an artifact"],
      ["profile_promoted", "promoted a profile"],
      ["records_written", "wrote records that outlived it"],
    ]) {
      if (observed[effect] === true) findings.push(`${where} ${axis}: the run ${what}, whatever the record says`);
    }
  }
  return findings;
}

/**
 * THE MATRIX IS COMPLETE OR IT IS NAMED. Every executable axis was performed, and every axis this estate
 * cannot perform is named with a reason that is actually this estate's — an axis that is neither is a
 * silent gap, and an unperformable axis reported as performed is an unfalsifiable bar.
 */
export function matrixFindings(verdict, { where = "matrix" } = {}) {
  const findings = [];
  const performed = list(verdict, "knockouts").map((k) => str(k, "axis"));
  const seen = new Set(performed);
  for (const axis of EXECUTABLE_KNOCKOUTS) {
    if (!seen.has(axis)) findings.push(`${where}: the executable axis ${axis} was not performed`);
  }
  if (seen.size !== performed.length) findings.push(`${where}: an axis was knocked out more than once`);
  for (const axis of seen) {
    if (!EXECUTABLE_KNOCKOUTS.includes(axis)) {
      findings.push(`${where}: ${axis} was reported as performed but this estate cannot execute it`);
    }
  }
  const named = new Map(list(verdict, "named_absent_knockout_axes").map((row) => [str(row, "axis"), row]));
  for (const [axis, expected] of Object.entries(NAMED_ABSENT_KNOCKOUTS)) {
    const row = named.get(axis);
    if (!row) {
      findings.push(`${where}: the absent axis ${axis} is not named`);
      continue;
    }
    const reason = str(row, "reason");
    if (reason.length < 24) findings.push(`${where}: the absent axis ${axis} is named without a reason`);
    else if (!expected.test(reason)) findings.push(`${where}: the absent axis ${axis} gives a reason that is not why this estate cannot perform it`);
    if (!str(row, "owner_ref")) findings.push(`${where}: the absent axis ${axis} names no owner who could make it performable`);
  }
  for (const axis of named.keys()) {
    if (!Object.hasOwn(NAMED_ABSENT_KNOCKOUTS, axis)) findings.push(`${where}: ${axis} is named absent but is not an axis canon names`);
    if (seen.has(axis)) findings.push(`${where}: ${axis} is both performed and named absent`);
  }
  return findings;
}

/**
 * THE INSTALLATION AXIS IS READ FROM THE OWNER, NOT FROM THE POSTURE. The lineage's read model re-derives
 * from the accountable subject, the caretaker, context leases, dependency lineages and the runtime ref —
 * and NOT from `installation_ref`, `definition_ref` or the source artifacts. Removing an installation after
 * binding therefore leaves a GREEN posture, so a knockout on that axis that trusted the posture would
 * report success while measuring nothing. This is the one axis where the obvious instrument is the wrong
 * one, which is why it gets a check of its own.
 */
export function installationAxisFindings(observation, { where = "installation axis" } = {}) {
  const findings = [];
  if (!observation || typeof observation !== "object") return [`${where}: nothing was observed`];
  if (observation.read_through_posture === true) {
    findings.push(`${where}: the axis was read through the lineage posture, which does not re-derive the installation binding`);
  }
  if (typeof observation.owner_serves_installation !== "boolean") {
    findings.push(`${where}: the owner was not asked whether it still serves the installation`);
  }
  if (typeof observation.posture_after_removal !== "string") {
    findings.push(`${where}: the posture after removal was not recorded, so the trap this check exists for is unproven`);
  }
  return findings;
}

/** A source pin reads CODE, never the prose explaining it. */
export function codeOnly(source) {
  return String(source)
    .split("\n")
    .filter((line) => !/^\s*(?:\/\/|#|\*)/u.test(line))
    .join("\n");
}
