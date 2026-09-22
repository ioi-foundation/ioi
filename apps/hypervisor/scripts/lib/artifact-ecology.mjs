// M08.17 — THE ONE DERIVER for the persistent artifact ecology.
//
// Canon (domains/ioi-ai/collaborative-outcome-pattern.md § Persistent Artifact Ecology): the useful
// collective view is an ARTIFACT ECOLOGY, not a wall of agent chat bubbles. It shows what persistent
// systems exist, what is running, their ancestry and dependents, who can maintain or stop them, their
// current authority and budget, and what remains operational when participants and Sessions are removed.
//
// THE CLAIM THIS FILE EXISTS TO REFUSE. An `ArtifactRef` marked `active` is not evidence that any runtime
// exists or that its authority is current. A stored artifact, an installed definition and an
// actually-running healthy instance are THREE DIFFERENT FACTS, and a view that lets a reader slide between
// them has told them something the estate never admitted. M10.9 put the same sentence on the wire as a
// forbidden qualification basis; here it is a forbidden RENDERING.
//
// AND THE RUNG IS DERIVED FROM THE BINDINGS, NEVER FROM THE STATUS WORD. `posture.status` is what was
// ADMITTED; the rung is what the record's own refs support. A lineage recorded `active` whose `runtime_ref`
// is null is not running, whatever its status says — and that disagreement is itself a finding, because a
// record in that shape was admitted by something that skipped a transition.
//
// Every function is pure, so the unit's battery can load a mutated copy and score the deriver itself.

/** The three rungs canon names, in the order a reader climbs them. */
export const RUNGS = Object.freeze(["stored", "installed", "running"]);

/** The lineage postures the composer can admit. */
export const POSTURES = Object.freeze([
  "observed", "reused", "forked", "installed", "active",
  "stopped", "quarantined", "repairing", "replaced", "retired",
]);

/** Postures from which nothing runs again without a governed successor. */
export const TERMINAL = Object.freeze(["replaced", "retired"]);

/** The typed orphan reasons; `quarantined` requires one. */
export const ORPHAN_REASONS = Object.freeze([
  "owner_absent", "caretaker_absent", "dependency_unavailable",
  "artifact_unavailable", "health_stale", "authority_stale",
]);

/**
 * The composition's own verbs. THE SURFACE OFFERS THEM AND EXECUTES NONE: R-192 ruled goal pursuit out of
 * the Hypervisor and the daemon serves no collective, lineage or caretaker route at all, so these live in
 * the ioi.ai composer. A surface that appeared to run them would be claiming an authority no route backs.
 */
export const INTERVENTIONS = Object.freeze([
  "stop", "quarantine", "repair", "replace", "retire",
]);

/** The lease schemes, kept apart because they answer different questions. */
export const LEASE_KINDS = Object.freeze({
  "context-lease://": "context",
  "authority-lease://": "authority",
  "resource-lease://": "resource",
  "budget-lease://": "budget",
});

export const CONTRACTS = Object.freeze({
  receipt: "schema://ioi/applications/ioi-ai/collective-resolution-receipt/v1",
  lineage: "schema://ioi/applications/ioi-ai/persistent-executable-lineage/v1",
  estimand: "schema://ioi/applications/ioi-ai/collective-qualification-estimand/v1",
  pairing: "schema://ioi/applications/ioi-ai/collective-baseline-pairing/v1",
  verdict: "schema://ioi/applications/ioi-ai/collective-qualification-verdict/v1",
});

const str = (value, key) => (typeof value?.[key] === "string" ? value[key] : "");
const list = (value, key) => (Array.isArray(value?.[key]) ? value[key] : []);

/**
 * THE RUNG, derived from what the record BINDS rather than from what it says. A lineage is `running` only
 * when it binds a runtime AND its posture is one in which a runtime may be live; `installed` when it binds
 * an installation but no live runtime; `stored` otherwise. This is the whole refusal in one function.
 */
export function rungOf(lineage) {
  const posture = str(lineage?.posture, "status");
  const runtime = str(lineage, "runtime_ref");
  const kind = str(lineage, "runtime_kind");
  const installation = str(lineage, "installation_ref");
  const live = posture === "active" || posture === "repairing";
  if (runtime && kind && kind !== "none" && live) return "running";
  if (installation) return "installed";
  return "stored";
}

/**
 * The projection one lineage renders as. Every member says where it came from, so a view cannot add a fact
 * the record did not carry, and the gate can compare the rendering to the admitted record member by member.
 */
export function projectLineage(lineage, { dependents = [] } = {}) {
  const posture = str(lineage?.posture, "status");
  const leases = { context: [], authority: [], resource: [], budget: [], unknown: [] };
  for (const ref of list(lineage, "lease_refs")) {
    const scheme = Object.keys(LEASE_KINDS).find((prefix) => String(ref).startsWith(prefix));
    leases[scheme ? LEASE_KINDS[scheme] : "unknown"].push(ref);
  }
  return {
    lineage_id: str(lineage, "lineage_id"),
    rung: rungOf(lineage),
    recorded_posture: posture,
    orphan_reason: lineage?.posture?.orphan_reason ?? null,
    terminal: TERMINAL.includes(posture),
    artifact_ref: str(lineage, "artifact_ref"),
    artifact_sha256: str(lineage, "artifact_sha256"),
    definition_ref: str(lineage, "definition_ref"),
    installation_ref: lineage?.installation_ref ?? null,
    runtime_ref: lineage?.runtime_ref ?? null,
    runtime_kind: str(lineage, "runtime_kind") || "none",
    accountable_subject_ref: str(lineage, "accountable_subject_ref"),
    caretaker_ref: lineage?.caretaker_ref ?? null,
    stop_policy_ref: str(lineage, "stop_policy_ref"),
    ancestry: {
      source_artifact_refs: list(lineage, "source_artifact_refs"),
      successor_artifact_ref: lineage?.successor_artifact_ref ?? null,
      successor_of: lineage?.successor_of ?? null,
      transformation_receipt_refs: list(lineage, "transformation_receipt_refs"),
    },
    dependency_lineage_refs: list(lineage, "dependency_lineage_refs"),
    dependents,
    leases,
    effect_receipt_refs: list(lineage, "effect_receipt_refs"),
    health_ref: lineage?.health_ref ?? null,
    // THE SURFACE OWNS NOTHING. Offered, and executed by their owners.
    offered_interventions: TERMINAL.includes(posture) ? [] : [...INTERVENTIONS],
    executes_no_intervention: true,
    grants_no_authority: true,
    derived_from: ["posture", "runtime_ref", "runtime_kind", "installation_ref", "lease_refs"],
  };
}

/** Which lineages name this one as a dependency — the "what breaks if this goes" question. */
export function dependentsOf(lineageId, allLineages) {
  return (Array.isArray(allLineages) ? allLineages : [])
    .filter((other) => list(other, "dependency_lineage_refs").includes(lineageId))
    .map((other) => str(other, "lineage_id"))
    .filter(Boolean);
}

/**
 * THE PROJECTION MAY NOT CLAIM MORE THAN THE RECORD. Each finding is a rendering that would tell a reader
 * something the admitted record does not support.
 */
export function projectionFindings(lineage, projected, { where = "ecology" } = {}) {
  const findings = [];
  if (!lineage || typeof lineage !== "object") return [`${where}: no lineage`];
  if (!projected || typeof projected !== "object") return [`${where}: no projection`];

  if (projected.rung !== rungOf(lineage)) {
    findings.push(`${where}: the rung was not derived from the record's own bindings`);
  }
  if (!RUNGS.includes(projected.rung)) findings.push(`${where}: ${projected.rung} is not one of the three rungs`);

  // THE CENTRAL REFUSAL, in both directions.
  if (projected.rung === "running" && !str(lineage, "runtime_ref")) {
    findings.push(`${where}: rendered as running with no runtime bound — an artifact marked active is not evidence that any runtime exists`);
  }
  if (projected.rung === "running" && str(lineage, "runtime_kind") === "none") {
    findings.push(`${where}: rendered as running with runtime_kind none`);
  }
  if (projected.rung !== "stored" && !str(lineage, "installation_ref") && !str(lineage, "runtime_ref")) {
    findings.push(`${where}: rendered above the stored rung while binding neither an installation nor a runtime`);
  }
  // A record whose status and bindings disagree was admitted by something that skipped a transition, and
  // the view must not smooth that over by picking whichever reads better.
  if (str(lineage?.posture, "status") === "active" && !str(lineage, "runtime_ref")) {
    findings.push(`${where}: the record is recorded active with no runtime_ref, which no admitted transition produces`);
  }

  for (const member of ["artifact_ref", "artifact_sha256", "definition_ref", "accountable_subject_ref", "stop_policy_ref"]) {
    if (projected[member] !== str(lineage, member)) findings.push(`${where}: ${member} was altered in the rendering`);
  }
  if ((projected.installation_ref ?? null) !== (lineage.installation_ref ?? null)) findings.push(`${where}: installation_ref was altered`);
  if ((projected.runtime_ref ?? null) !== (lineage.runtime_ref ?? null)) findings.push(`${where}: runtime_ref was altered`);
  if ((projected.caretaker_ref ?? null) !== (lineage.caretaker_ref ?? null)) findings.push(`${where}: caretaker_ref was altered`);
  if (projected.recorded_posture !== str(lineage?.posture, "status")) findings.push(`${where}: the recorded posture was altered`);

  if (projected.executes_no_intervention !== true) findings.push(`${where}: the projection claims to execute an intervention`);
  if (projected.grants_no_authority !== true) findings.push(`${where}: the projection claims authority`);
  if (projected.terminal && projected.offered_interventions.length) {
    findings.push(`${where}: interventions offered on a terminal lineage, which admits no further verb`);
  }
  for (const verb of projected.offered_interventions) {
    if (!INTERVENTIONS.includes(verb)) findings.push(`${where}: ${verb} is not one of the composition's verbs`);
  }
  return findings;
}

/**
 * CARETAKER AND STOP COVERAGE. Canon: an orphaned condition is TYPED, and a caretaker's absence is the
 * typed reason `caretaker_absent`. A running lineage with nobody who can stop it is the finding an
 * operator most needs, and the easiest one for a view to leave implicit.
 */
export function coverageFindings(projected, { where = "coverage" } = {}) {
  const findings = [];
  if (projected.rung === "running" && !projected.caretaker_ref) {
    findings.push(`${where}: ${projected.lineage_id} is running with no caretaker — nobody the composition can resolve may stop it`);
  }
  if (!projected.stop_policy_ref) {
    findings.push(`${where}: ${projected.lineage_id} carries no stop policy`);
  }
  if (projected.recorded_posture === "quarantined" && !projected.orphan_reason) {
    findings.push(`${where}: ${projected.lineage_id} is quarantined with no typed orphan reason`);
  }
  if (projected.orphan_reason && !ORPHAN_REASONS.includes(projected.orphan_reason)) {
    findings.push(`${where}: ${projected.orphan_reason} is not a typed orphan reason`);
  }
  if (projected.recorded_posture !== "quarantined" && projected.orphan_reason && projected.recorded_posture !== "stopped") {
    findings.push(`${where}: ${projected.lineage_id} carries an orphan reason at posture ${projected.recorded_posture}`);
  }
  return findings;
}

/**
 * WHAT REMAINS OPERATIONAL WHEN A PARTICIPANT OR SESSION IS REMOVED — canon's own question, answered from
 * the accountable subject rather than from who happens to be present. A durable subject survives its
 * creator; a session or participation as accountable subject is refused by the composer and would be a
 * lineage that dies with whoever started it.
 */
const DURABLE_SUBJECT = /^(?:system|installation|worker|automation|automation-run|service|controller|runtime-assignment|managed-worker-instance):\/\//u;

export function survivalFindings(projected, { where = "survival" } = {}) {
  const findings = [];
  if (!DURABLE_SUBJECT.test(projected.accountable_subject_ref || "")) {
    findings.push(`${where}: ${projected.lineage_id} names ${projected.accountable_subject_ref || "nothing"} as its accountable subject, which does not outlive a session`);
  }
  return findings;
}

/** Everything that survives the removal, and what goes with it. */
export function survivesRemoval(projected) {
  return {
    lineage_id: projected.lineage_id,
    survives: DURABLE_SUBJECT.test(projected.accountable_subject_ref || "") && !projected.terminal,
    because: projected.accountable_subject_ref,
    takes_with_it: projected.dependents,
  };
}

/**
 * NO FABRICATED EVALUATION. A qualification verdict is rendered only when one was READ, and only with the
 * outcome it carried. A view that computes a verdict from what it can see has manufactured evidence, which
 * is the thing M10.9's whole contract set exists to prevent.
 */
export function evaluationFindings(rendered, verdicts, { where = "evaluation" } = {}) {
  const findings = [];
  const admitted = new Map((Array.isArray(verdicts) ? verdicts : []).map((v) => [str(v, "verdict_ref"), v]));
  for (const row of Array.isArray(rendered) ? rendered : []) {
    const ref = str(row, "verdict_ref");
    if (!ref) { findings.push(`${where}: a verdict is rendered with no ref`); continue; }
    const source = admitted.get(ref);
    if (!source) { findings.push(`${where}: ${ref} was rendered but no such verdict was read`); continue; }
    if (str(row, "outcome") !== str(source, "outcome")) {
      findings.push(`${where}: ${ref} is rendered as ${str(row, "outcome")} and was admitted as ${str(source, "outcome")}`);
    }
    if (row.qualifies_the_collective === true) {
      findings.push(`${where}: ${ref} is rendered as qualifying the collective, and a verdict grants nothing`);
    }
  }
  return findings;
}

/**
 * THE RENDERING ITSELF. A projection may be perfect and the page still tell a reader the wrong thing, so
 * these read the served bytes: the word "running" may not appear against a lineage that is not, the three
 * rungs must be distinguishable, and no chat transcript may stand in for the ecology.
 */
export function renderingFindings({ html, projected }, { where = "rendering" } = {}) {
  const findings = [];
  const text = String(html ?? "");
  if (!text) return [`${where}: nothing was rendered`];
  for (const rung of RUNGS) {
    if (!new RegExp(`data-ioi-rung="${rung}"`, "u").test(text) && projected.some((p) => p.rung === rung)) {
      findings.push(`${where}: a ${rung} lineage exists and the rendering does not mark it as one`);
    }
  }
  for (const p of projected) {
    const marked = new RegExp(`data-ioi-lineage="${p.lineage_id.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}"[^>]*data-ioi-rung="([a-z]+)"`, "u").exec(text);
    if (!marked) { findings.push(`${where}: ${p.lineage_id} is not rendered with its rung`); continue; }
    if (marked[1] !== p.rung) findings.push(`${where}: ${p.lineage_id} is rendered as ${marked[1]} and projects as ${p.rung}`);
  }
  // CHAT IS NOT THE VIEW. Canon: not a wall of agent chat bubbles.
  if (/data-ioi-chat|class="[^"]*chat-bubble/u.test(text)) {
    findings.push(`${where}: the ecology renders a chat transcript, and canon's view is persistent systems and blockers first`);
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
