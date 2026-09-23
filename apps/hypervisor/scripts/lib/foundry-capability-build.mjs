// M10.6 — the production capability-build pipeline's deriver.
//
// THIS FILE REACHES NOTHING. No plane, no file, no clock, no network: every function takes the
// records it judges and returns findings, so a relying party holding a program can re-derive the
// same answers without the estate being up.
//
// IT EXISTS BECAUSE THREE LAWS COULD NOT BE REGISTERED. `FoundryTrainingProgram` v2 carries no
// cross-field invariants, and the contract says why at length: `non_empty` is never satisfied by an
// object, an invariant path cannot reach into a nullable member, and the portable operator set has
// no form for "this member must be EMPTY when that one reads X" or "compare these digests, but only
// the ones this enum selects". Bending the shape to fit an operator would be bending a canonical
// name for codegen. So the laws live here, named, rather than being quietly dropped:
//
//   1. A `resume_divergent` program carries the comparison that produced the divergence.
//   2. `class_satisfied` agrees with the digests the DECLARED class actually selects.
//   3. An unreconciled or exceeded spend forbids a candidate.
//
// WHAT THIS UNIT DOES NOT RE-PROVE. v1 already binds the dataset and recipe content hashes, the
// trainer backend profile, the `seed`, the rights and authority grants; `verify-restore` already
// fails closed six ways; and `qualification.promotion_boundary` already pins `proposal_only`,
// `governance_approval_required` and `runtime_activation_performed` as constants. Those are read as
// tripwires elsewhere and are not restated as findings here.

export const DETERMINISM_CLASSES = Object.freeze(["bitwise", "state_equivalent", "statistical"]);

/**
 * WHICH DIGESTS EACH CLASS ACTUALLY SELECTS. This table is the whole content of law 2 — the reason
 * a conditional operator could not express it is that the comparison set depends on an enum value.
 * `statistical` selects NONE: it makes no state claim at all, which is why a program must declare
 * it in advance rather than retreat to it once the digests disagree.
 */
export const DIGESTS_BY_CLASS = Object.freeze({
  bitwise: Object.freeze(["model_state_hash", "optimizer_state_hash", "scheduler_state_hash", "rng_state_hash"]),
  state_equivalent: Object.freeze(["model_state_hash", "optimizer_state_hash", "scheduler_state_hash"]),
  statistical: Object.freeze([]),
});

/** Outcomes that forbid a candidate. Unknown spend and zero spend are different facts. */
export const SPEND_FORBIDS_CANDIDATE = Object.freeze(["spend_unreconciled", "spend_exceeded_reservation"]);
export const SPEND_OUTCOMES = Object.freeze([
  "reconciled_exact",
  "reconciled_within_reservation",
  ...SPEND_FORBIDS_CANDIDATE,
]);

const str = (value, key) => (typeof value?.[key] === "string" ? value[key] : "");
const at = (value, ...keys) => keys.reduce((node, key) => (node == null ? undefined : node[key]), value);

/** LAW 1 — a divergence nobody measured is not a finding. */
export function divergenceFindings(program) {
  const findings = [];
  const status = str(program, "status");
  const equivalence = program?.resume_equivalence;
  if (status === "resume_divergent" && (equivalence == null || typeof equivalence !== "object")) {
    findings.push("program: reports resume_divergent and carries no comparison, so the divergence it reports was never measured");
  }
  // The reverse edge is NOT a finding: a program may hold a satisfied comparison and still be
  // running, because measuring equivalence at one step says nothing about whether the run is done.
  if (equivalence != null && typeof equivalence === "object" && equivalence.class_satisfied === false && status !== "resume_divergent") {
    findings.push(`program: the comparison says the declared class was not satisfied and the status reads ${status || "(absent)"}, so a divergence was measured and not acted on`);
  }
  return findings;
}

/**
 * LAW 2 — `class_satisfied` agrees with the digests the declared class selects. This is the one the
 * registered contract most obviously could not carry: which digests matter is chosen by an enum.
 */
export function equivalenceFindings(program) {
  const findings = [];
  const declared = str(program, "determinism_class");
  if (!DETERMINISM_CLASSES.includes(declared)) {
    findings.push(`program: \`${declared || "(absent)"}\` is not one of the three determinism classes`);
    return findings;
  }
  const equivalence = program?.resume_equivalence;
  if (equivalence == null) return findings;
  if (typeof equivalence !== "object") {
    findings.push("program: the resume comparison is not a record");
    return findings;
  }

  const selected = DIGESTS_BY_CLASS[declared];
  const left = equivalence.uninterrupted;
  const right = equivalence.resumed;
  if (left == null || right == null) {
    findings.push("program: the comparison is missing one of its two sides, so nothing was compared");
    return findings;
  }

  const mismatched = selected.filter((digest) => str(left, digest) !== str(right, digest));
  const claimed = equivalence.class_satisfied === true;
  if (claimed && mismatched.length > 0) {
    findings.push(`program: claims the ${declared} class was satisfied while ${mismatched.join(", ")} differ between the runs`);
  }
  if (!claimed && mismatched.length === 0) {
    findings.push(`program: claims the ${declared} class was NOT satisfied while every digest that class selects matches — a divergence the declared class does not actually see`);
  }
  // A `statistical` program selects no digests, so it can never legitimately report a STATE
  // divergence. Saying it did means the class was chosen after the fact, which is the thing
  // declaring it in advance exists to prevent.
  if (declared === "statistical" && !claimed) {
    findings.push("program: declares the statistical class, which makes no state claim, and then reports a state divergence — the class was chosen after the digests were known");
  }
  return findings;
}

/** LAW 3 — a successful artifact with unknown spend, or a live orphan, is a FAILED run. */
export function spendFindings(program) {
  const findings = [];
  const spend = program?.spend;
  if (spend == null || typeof spend !== "object") {
    findings.push("program: carries no spend accounting at all");
    return findings;
  }
  const outcome = str(spend, "reconciled_outcome");
  if (!SPEND_OUTCOMES.includes(outcome)) {
    findings.push(`program: \`${outcome || "(absent)"}\` is not a typed spend outcome`);
  }
  if (!str(spend, "reservation_ref")) {
    findings.push("program: drew on an external resource with no admitted reservation — that is unauthorized spend, not unknown spend");
  }
  if (!str(spend, "cleanup_obligation_ref")) {
    findings.push("program: names no cleanup obligation, so a settled bill cannot distinguish a closed resource from a live orphan");
  }
  if (SPEND_FORBIDS_CANDIDATE.includes(outcome) && candidateClaimed(program)) {
    findings.push(`program: spend is ${outcome} and the run still produced a candidate — a successful artifact with unknown or excess spend is a FAILED run, not a successful one with an accounting note`);
  }
  return findings;
}

/**
 * Whether this program is claiming to have produced a governed worker candidate. Read from the
 * qualification rather than from the status alone, because `completed` describes the run and the
 * qualification describes what the run yielded.
 */
export function candidateClaimed(program) {
  const qualification = program?.qualification;
  return qualification != null && typeof qualification === "object";
}

/** LAW 1+2+3 together, plus the bindings this unit added. */
export function programFindings(program) {
  const findings = [
    ...divergenceFindings(program),
    ...equivalenceFindings(program),
    ...spendFindings(program),
  ];
  // THE BINDINGS ARE AT REVISIONS. A view bound by name cannot be found superseded, which is the
  // whole reason the revision member exists beside the view ref.
  if (!str(program, "policy_bound_data_view_ref")) findings.push("program: reads through no policy-bound view");
  if (!str(program, "policy_bound_data_view_revision_ref")) {
    findings.push("program: binds a view without the exact revision it read, so a superseded view would be undetectable");
  }
  if (!str(program, "retention_class_ref")) findings.push("program: names no retention class for its artifacts");
  // A candidate may not stand on a divergent resume, whatever the spend says.
  if (str(program, "status") === "resume_divergent" && candidateClaimed(program)) {
    findings.push("program: diverged on resume and still claims a candidate");
  }
  return findings;
}

/**
 * The promotion boundary v1 ALREADY pins as three constants, read here as a TRIPWIRE. This unit did
 * not build it and does not claim to; the check exists so a regression is caught rather than
 * inherited silently.
 */
export function promotionBoundaryFindings(program) {
  const boundary = at(program, "qualification", "promotion_boundary");
  if (boundary == null) return [];
  const findings = [];
  if (boundary.proposal_only !== true) findings.push("promotion: the qualification is not proposal-only");
  if (boundary.governance_approval_required !== true) findings.push("promotion: governance approval is not required");
  if (boundary.runtime_activation_performed !== false) findings.push("promotion: the run activated its own output at runtime");
  return findings;
}
