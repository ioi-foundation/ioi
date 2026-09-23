// M10.8 — the governed experiment-optimization and capability-construction cycle's deriver.
//
// THIS FILE REACHES NOTHING. No plane, no file, no clock, no network.
//
// IT CARRIES THE LAWS THE REGISTERED CONTRACTS COULD NOT. Three of them are cross-member
// conditionals of exactly the kind M10.6 found the portable operator set has no form for:
//
//   ADAPTER  missing_adapter / cross_version / downgrade — each is a comparison BETWEEN an
//            adapter and the envelope offered to it, which no single-record invariant can see.
//   NOT BOTH canon: the deprecated `target_training_pipeline_ref` is normalized to `target_ref`
//            with `target_class: training_pipeline`, and "canonical state does not emit both".
//            A record carrying the deprecated key AND the canonical pair has not been normalized;
//            it has been annotated.
//   ORDER    a builder-created evaluator may not retroactively judge the cycle that produced it.
//            This one is about ORDER rather than identity, so no shape can hold it: a released
//            evaluator is a legitimate judge everywhere except backwards over its own parent.

/** Canon's closed set of seven, from worker-training-lifecycle.md's Iteration Loop. */
export const CHANGE_KINDS = Object.freeze(["data", "recipe", "gate", "rubric", "tool", "model", "workflow"]);

/** The only three schemes an optimizer identity may take. A model is not among them. */
export const OPTIMIZER_SCHEMES = Object.freeze(["worker", "conductor", "runtime"]);

export const ADAPTER_REFUSALS = Object.freeze(["missing_adapter", "cross_version", "downgrade"]);

/** The deprecated key canon names, and what it normalizes to. */
export const DEPRECATED_TARGET_KEY = "target_training_pipeline_ref";

const str = (value, key) => (typeof value?.[key] === "string" ? value[key] : "");
const list = (value, key) => (Array.isArray(value?.[key]) ? value[key] : []);
const has = (value, key) => value != null && Object.prototype.hasOwnProperty.call(value, key);

/**
 * A SCHEMA VERSION IN THIS ESTATE IS `<family>.v<major>` — measured, not assumed: all 358
 * registered contracts end `.v<major>` and not one uses a dotted triple. An earlier draft compared
 * semver triples and split the family on a trailing `.<digit>`, which meant `a.1.10.0` and
 * `a.1.9.0` parsed as DIFFERENT families and the downgrade went unreported. Rather than harden a
 * comparison for a shape the estate does not use, this reads the shape it does: split once on the
 * final `.v`, compare the majors as integers. A version that does not match returns null, and a
 * pair where either side is null is not compared — an unrecognised version is a translation
 * question for the adapter's owner, not a silent pass.
 */
function schemaFamilyAndMajor(value) {
  const match = String(value).match(/^(.*)\.v(\d+)$/u);
  return match === null ? null : { family: match[1], major: Number.parseInt(match[2], 10) };
}

/** The cycle declares; it never grants, promotes, or names a model as its optimizer. */
export function cycleFindings(cycle) {
  const findings = [];
  const optimizer = str(cycle, "optimizer_ref");
  const scheme = optimizer.split("://")[0];
  if (!OPTIMIZER_SCHEMES.includes(scheme)) {
    findings.push(`cycle: \`${optimizer || "(absent)"}\` is not an optimizer identity — an optimizer is an actor (${OPTIMIZER_SCHEMES.join(", ")}), and a model named here would be a truth owner`);
  }
  if (cycle?.optimizer_is_not_a_model !== true) findings.push("cycle: does not disclaim that its optimizer is a model");
  if (cycle?.selection_confers_eligibility_only !== true) {
    findings.push("cycle: claims its selection confers more than eligibility — the optimizer may not evaluate or promote itself, activate, publish, authorize, or rewrite the target");
  }

  // EVERY TRIAL SURVIVES ITS OWN VERDICT, and the four lists stay four.
  for (const member of ["trial_refs", "accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs", "exploit_or_invalid_change_refs"]) {
    if (!Array.isArray(cycle?.[member])) findings.push(`cycle: \`${member}\` is not a preserved list`);
  }
  // A cycle that ran trials and kept no disposition at all has discarded its own history. Counting
  // rather than requiring each list non-empty: a cycle may legitimately have rejected nothing.
  const trials = list(cycle, "trial_refs").length;
  const dispositions = ["accepted_change_refs", "rejected_change_refs", "inconclusive_change_refs", "exploit_or_invalid_change_refs"]
    .reduce((total, member) => total + list(cycle, member).length, 0);
  if (trials > 0 && dispositions === 0) {
    findings.push(`cycle: ran ${trials} trial(s) and recorded no disposition of any kind, so its own record cannot explain how it got where it is`);
  }
  return findings;
}

/** A proposal suggests; applying one is somebody else's act. */
export function repairFindings(proposal) {
  const findings = [];
  if (proposal?.applies_nothing !== true) {
    findings.push("repair: claims to apply its own change — a repair proposal SUGGESTS, and applying one is a separate governed act by the target's owner");
  }
  const kind = str(proposal, "change_kind");
  if (!CHANGE_KINDS.includes(kind)) {
    findings.push(`repair: \`${kind || "(absent)"}\` is not one of canon's seven change kinds`);
  }
  if (list(proposal, "clustered_failure_refs").length === 0) {
    findings.push("repair: clusters no failures, so it is a suggestion with no evidence behind it");
  }
  if (!str(proposal, "parent_cycle_ref")) findings.push("repair: names no parent cycle, so it is a suggestion from nowhere");
  if (str(proposal, "rationale").trim().length < 20) {
    findings.push("repair: carries no rationale a reviewer could act on, and review is the only thing between a suggestion and a change");
  }
  return findings;
}

/**
 * THE THREE ADAPTER REFUSALS. Each is a comparison BETWEEN an adapter and the envelope offered to
 * it, which is why none could be a single-record invariant. `adapters` is every adapter the estate
 * has registered; `envelope` is what is being offered.
 */
export function adapterFindings(envelope, adapters) {
  const findings = [];
  const targetClass = str(envelope, "target_class");
  const offered = str(envelope, "schema_version");
  const candidates = (Array.isArray(adapters) ? adapters : []).filter((a) => str(a, "target_class") === targetClass);

  if (candidates.length === 0) {
    findings.push(`missing_adapter: no registered adapter for target class \`${targetClass || "(absent)"}\` — an unadapted target is not one this estate can reason about`);
    return findings;
  }
  // An adapter that reads a different envelope than the one offered is refused rather than tried.
  const reading = candidates.filter((a) => str(a, "accepts_envelope_schema") === offered);
  if (reading.length === 0) {
    findings.push(`cross_version: every adapter for \`${targetClass}\` reads a different envelope than the \`${offered || "(absent)"}\` offered — an adapter that guesses is a translator inventing meaning`);
    return findings;
  }
  for (const adapter of reading) {
    const accepts = str(adapter, "accepts_envelope_schema");
    const emits = str(adapter, "emits_envelope_schema");
    // Same family, lower major: a cycle that silently lowers its own wire version loses whatever
    // the newer one added. A DIFFERENT family is a translation and not a downgrade — that is the
    // adapter's whole job, so comparing across families would refuse the normal case.
    const from = schemaFamilyAndMajor(accepts);
    const to = schemaFamilyAndMajor(emits);
    if (from !== null && to !== null && from.family === to.family && to.major < from.major) {
      findings.push(`downgrade: \`${str(adapter, "adapter_id")}\` accepts ${accepts} and emits ${emits}, lowering its own wire version`);
    }
  }
  return findings;
}

/**
 * CANON'S "DOES NOT EMIT BOTH". The deprecated key is accepted only by a versioned adapter that
 * normalizes it; canonical state carries the canonical pair and not the deprecated key beside it.
 */
export function normalizationFindings(record) {
  const findings = [];
  const carriesDeprecated = has(record, DEPRECATED_TARGET_KEY);
  const carriesCanonical = has(record, "target_ref") || has(record, "target_class");
  if (carriesDeprecated && carriesCanonical) {
    findings.push(`normalization: carries \`${DEPRECATED_TARGET_KEY}\` beside the canonical target members — canonical state does not emit both, and a record holding each has not been normalized, it has been annotated`);
  }
  if (carriesDeprecated && !carriesCanonical) {
    findings.push(`normalization: carries only \`${DEPRECATED_TARGET_KEY}\`, which is admissible on the wire into a versioned adapter and never as canonical state`);
  }
  return findings;
}

/**
 * THE ORDER LAW. A builder-created evaluator, world, simulator or scoring asset produced BY a cycle
 * remains a candidate: it may not judge its parent or a sibling, may not enter a judging epoch
 * before Evaluations releases it, and may NOT RETROACTIVELY judge the producing cycle even after
 * release. The third is why this cannot be a shape — a released evaluator is a legitimate judge
 * everywhere except backwards over its own parent, so the check needs the judging EVENT and not
 * just the asset.
 */
export function judgingFindings({ asset, judgement }) {
  const findings = [];
  const producedBy = str(asset, "produced_by_cycle_ref");
  if (!producedBy) return findings; // not a builder-created asset; this law does not reach it

  const judged = str(judgement, "judged_cycle_ref");
  const released = asset?.evaluations_released === true;

  if (judged === producedBy) {
    findings.push(
      released
        ? `judging: \`${str(asset, "asset_id")}\` was released and is judging the very cycle that produced it — release makes it a judge everywhere EXCEPT backwards over its own parent`
        : `judging: \`${str(asset, "asset_id")}\` is judging the cycle that produced it`,
    );
  }
  if (!released && judged && judged !== producedBy) {
    findings.push(`judging: \`${str(asset, "asset_id")}\` entered a judging epoch before Evaluations validated, custodied, affiliation-checked, released and froze it`);
  }
  if (str(judgement, "judged_sibling_of") === producedBy) {
    findings.push(`judging: \`${str(asset, "asset_id")}\` is judging a sibling from the cycle that produced it`);
  }
  return findings;
}
