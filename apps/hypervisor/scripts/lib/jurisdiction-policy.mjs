// M06.10 — THE ONE DERIVER for jurisdiction-policy decisions and privacy-filtered audit export.
//
// Canon: foundations/ecosystem-assurance-certification-liability.md. A `JurisdictionPolicyPack` declares
// obligations in a machine-readable shape and COMPILES INTO OWNERS THAT ALREADY EXIST — wallet.network
// identity and step-up gates, daemon policy checks, Agentgres retention and export validity, marketplace
// listing restrictions, sas.xyz service obligations. It is not legal advice. A
// `ComplianceAuditExportBundle` is an export MANIFEST over evidence that already exists, for one named
// audience, and a replay or proof view must not bypass it.
//
// THE SENTENCE THIS FILE EXISTS TO ENFORCE, which canon already wrote and nothing checked:
// "Generated projections must always emit `legal_conformity_claim: not_determined`; no score, current
// deadline, attestation posture, submitted report, crypto-shredding receipt, certification, or
// policy-pack match is a legal determination." The contracts pin that word as a `const`; this file
// refuses the ways a technical evaluator could still BEHAVE as though it had decided one.
//
// AND THE ONE ACC-18 TURNS ON: a bundle must FAIL OFFLINE for the wrong audience, a moved policy
// revision, the wrong jurisdiction, subject, reviewer, redaction, retention or evidence hash. Offline
// means offline: `offlineFindings` takes a bundle and a relying party's own expectations and reaches
// nothing — no daemon, no clock, no network. A verifier that had to ask something cannot be run by the
// party that most needs to run it.
//
// Every function is pure, so the unit's battery can load a mutated copy and score the deriver itself.

export const CONTRACTS = Object.freeze({
  pack: "schema://ioi/foundations/jurisdiction-policy-pack/v1",
  decision: "schema://ioi/foundations/jurisdiction-policy-decision/v1",
  export: "schema://ioi/foundations/compliance-audit-export-bundle/v1",
});

/** The owners canon names as the places a pack compiles INTO. Nothing else may be an enforcer. */
export const ENFORCING_OWNERS = Object.freeze([
  "wallet_network",
  "daemon_policy",
  "agentgres_retention",
  "marketplace_listing",
  "sas_service_obligation",
  "public_anchor",
]);

/** The four instants a reporting window may run from. They are genuinely different moments. */
export const CLOCK_STARTS = Object.freeze([
  "detected_at",
  "confirmed_at",
  "materiality_determined_at",
  "authority_request_received_at",
]);

export const AUDIENCES = Object.freeze([
  "customer", "external_auditor", "regulator", "counterparty",
  "insurer", "procurement", "internal_auditor", "public",
]);

/** Why a ref did not travel. A withheld artifact with no reason is indistinguishable from none. */
export const EXCLUSION_REASONS = Object.freeze([
  "retention_locked", "restricted_view", "no_export_authority",
  "protected_plaintext", "unrelated", "expired", "policy_blocked",
]);

/**
 * THE VALUE THAT IS THE WHOLE POINT. Canon permits exactly one, and a technical evaluator that could
 * express any other would be making a legal determination — which is the defect this unit exists to end.
 */
export const LEGAL_CONFORMITY_CLAIM = "not_determined";

const str = (value, key) => (typeof value?.[key] === "string" ? value[key] : "");
const list = (value, key) => (Array.isArray(value?.[key]) ? value[key] : []);
const SHA256 = /^sha256:[0-9a-f]{64}$/u;

/**
 * DOES THE PACK REACH THIS SUBJECT. Applicability is derived from the classes the subject actually
 * carries against the classes the pack declares — never from the subject's own say-so about whether it
 * is regulated, which is the one party with an interest in the answer.
 */
export function applicabilityOf(pack, subject) {
  const declared = pack?.applies_to ?? {};
  const matched = [];
  for (const [member, kind] of [
    ["action_classes", "action_class"],
    ["data_classes", "data_class"],
    ["service_classes", "service_class"],
  ]) {
    for (const name of list(declared, member)) {
      if (list(subject, kind === "action_class" ? "action_classes" : kind === "data_class" ? "data_classes" : "service_classes").includes(name)) {
        matched.push({ class_kind: kind, class_name: name });
      }
    }
  }
  return { applies: matched.length > 0, matched_classes: matched };
}

/**
 * THE DECISION SAYS WHAT IT DECIDED AND NOTHING MORE. Each finding is a decision behaving as though it
 * had authority, performed an action, or determined a question of law.
 */
export function decisionFindings(decision, { where = "decision" } = {}) {
  const findings = [];
  if (!decision || typeof decision !== "object") return [`${where}: the decision is not an object`];

  if (str(decision, "legal_conformity_claim") !== LEGAL_CONFORMITY_CLAIM) {
    findings.push(`${where}: legal_conformity_claim is ${str(decision, "legal_conformity_claim") || "absent"} — no score, deadline, attestation posture, report, receipt, certification or pack match is a legal determination`);
  }
  if (decision.grants_no_authority !== true) findings.push(`${where}: the decision claims authority`);
  if (decision.performs_no_action !== true) findings.push(`${where}: the decision claims to perform an action`);

  for (const obligation of list(decision, "obligations")) {
    const kind = str(obligation, "obligation_kind") || "an unnamed obligation";
    const owner = str(obligation, "enforcing_owner");
    if (!owner) { findings.push(`${where}: ${kind} names no enforcing owner, so the decision is asserting an obligation of its own`); continue; }
    if (!ENFORCING_OWNERS.includes(owner)) {
      findings.push(`${where}: ${kind} names ${owner} as its enforcer, which is not one of the owners a pack compiles into`);
    }
    if (!str(obligation, "owner_ref")) findings.push(`${where}: ${kind} names an enforcing owner with no ref to reach it by`);
    // AN UNSATISFIED OBLIGATION THAT CITES NOTHING IS AN OPINION. A satisfied one must cite evidence.
    if (str(obligation, "status") === "satisfied" && !list(obligation, "evidence_refs").length) {
      findings.push(`${where}: ${kind} is recorded satisfied with no evidence behind it`);
    }
  }
  // `not_evaluated` and `evidence_unavailable` must not be smoothed into `satisfied`.
  const unseen = list(decision, "obligations").filter((o) => ["not_evaluated", "evidence_unavailable"].includes(str(o, "status")));
  if (unseen.length && !list(decision, "unmet_evidence").length) {
    findings.push(`${where}: ${unseen.length} obligation(s) were not evaluated or had no evidence and the decision names nothing it could not establish`);
  }
  return findings;
}

/**
 * DEADLINE ARITHMETIC RETAINS ITS INPUTS. Canon: it must retain the exact pack version and triggering
 * timestamp. A window recomputed later against whatever the pack says by then is a different window, and
 * a decision that did not keep its inputs cannot be checked by anyone who was not there.
 */
export function deadlineFindings(decision, pack, { where = "deadline" } = {}) {
  const findings = [];
  const basis = decision?.clock_start_basis ?? null;
  if (basis === null) {
    if (decision?.triggering_timestamp) findings.push(`${where}: a triggering timestamp with no clock-start basis to apply it to`);
    return findings;
  }
  if (!CLOCK_STARTS.includes(basis)) { findings.push(`${where}: ${basis} is not one of the four instants a window may run from`); return findings; }
  if (!decision?.triggering_timestamp) {
    findings.push(`${where}: the window runs from ${basis} and the decision did not keep the instant itself, so it cannot be recomputed`);
  }
  if (str(decision, "pack_version") !== str(pack, "version")) {
    findings.push(`${where}: the decision was taken under version ${str(decision, "pack_version")} and the pack now reads ${str(pack, "version")} — canon requires the EXACT version be retained`);
  }
  if (!SHA256.test(str(decision, "pack_root"))) findings.push(`${where}: the decision binds no pack root, so an in-place edit would be invisible to it`);
  else if (str(decision, "pack_root") !== str(pack, "pack_root")) {
    findings.push(`${where}: the pack's content moved after this decision was taken — a change that should have been a new version is passing as the same one`);
  }
  // The basis must be one the pack actually declares for some incident class.
  const declared = list(pack?.incident_reporting, "deadlines").map((d) => str(d, "clock_start"));
  if (declared.length && !declared.includes(basis)) {
    findings.push(`${where}: the decision runs its window from ${basis} and the pack declares no deadline on that basis`);
  }
  return findings;
}

/**
 * THE EXPORT MAKES THREE THINGS OBVIOUS. Canon: what was included and why; what was redacted, withheld,
 * protected or excluded AND WHY; and which refs support it. These are the ways a manifest can be
 * well-formed and still not do that.
 */
export function exportFindings(bundle, { where = "export" } = {}) {
  const findings = [];
  if (!bundle || typeof bundle !== "object") return [`${where}: the bundle is not an object`];
  const manifest = bundle.export_manifest ?? {};

  if (!AUDIENCES.includes(str(bundle, "audience"))) {
    findings.push(`${where}: ${str(bundle, "audience") || "no audience"} is not an audience this estate exports to`);
  }
  if (str(bundle, "legal_conformity_claim") !== LEGAL_CONFORMITY_CLAIM) {
    findings.push(`${where}: composing decisions and receipts into a package does not add up to a legal determination`);
  }
  if (bundle.carries_no_protected_plaintext !== true) findings.push(`${where}: the bundle carries protected plaintext`);
  if (bundle.bypasses_no_export_manifest !== true) findings.push(`${where}: the bundle offers a way around its own manifest`);

  // EVERY EXCLUDED REF NAMES ITS REASON, and every reason names a ref that was excluded.
  const excluded = list(manifest, "excluded_refs");
  const reasons = new Map(list(manifest, "exclusion_reasons").map((r) => [str(r, "excluded_ref"), str(r, "reason")]));
  for (const ref of excluded) {
    if (!reasons.has(ref)) findings.push(`${where}: ${ref} was withheld and the bundle does not say why`);
    else if (!EXCLUSION_REASONS.includes(reasons.get(ref))) findings.push(`${where}: ${ref} was withheld for ${reasons.get(ref)}, which is not a typed reason`);
  }
  for (const ref of reasons.keys()) {
    if (!excluded.includes(ref)) findings.push(`${where}: a reason is given for ${ref}, which the manifest does not list as excluded`);
  }
  // A PROTECTED PAYLOAD IS NAMED, NEVER CARRIED — and never quietly counted as included.
  for (const ref of list(manifest, "protected_payload_refs")) {
    if (list(manifest, "included_refs").includes(ref)) {
      findings.push(`${where}: ${ref} is named as a protected payload and also listed as included — raw private payloads stay under their own policy`);
    }
  }
  // A redacted ref is one that TRAVELLED. It cannot also have been excluded.
  for (const ref of list(manifest, "redacted_refs")) {
    if (excluded.includes(ref)) findings.push(`${where}: ${ref} is reported both redacted and excluded, which are different fates`);
  }
  if (["generated", "delivered"].includes(str(bundle, "status")) && !list(bundle, "authority_refs").length) {
    findings.push(`${where}: a generated export names no authority that supported it`);
  }
  return findings;
}

/**
 * THE OFFLINE VERIFIER — ACC-18's first clause, and the reason this file reaches nothing. A relying
 * party holds a bundle and its own expectations; every mismatch must be findable HERE, with no daemon,
 * no clock and no network. A check that had to ask something cannot be run by the party that most needs
 * to run it, which is usually the party the exporter would rather not satisfy.
 *
 * `expected` is what the relying party believes it asked for. Nothing in it comes from the bundle.
 */
export function offlineFindings(bundle, expected, { where = "offline" } = {}) {
  const findings = [];
  if (!bundle || typeof bundle !== "object") return [`${where}: nothing to verify`];
  if (!expected || typeof expected !== "object") return [`${where}: the relying party stated no expectation, so nothing can fail`];

  if (expected.audience && str(bundle, "audience") !== expected.audience) {
    findings.push(`${where}: WRONG AUDIENCE — built for ${str(bundle, "audience")}, presented to ${expected.audience}`);
  }
  if (expected.subject_ref && !list(bundle, "subject_refs").includes(expected.subject_ref)) {
    findings.push(`${where}: WRONG SUBJECT — the bundle is not about ${expected.subject_ref}`);
  }
  if (expected.pack_ref && !list(bundle, "jurisdiction_policy_pack_refs").includes(expected.pack_ref)) {
    findings.push(`${where}: WRONG JURISDICTION — the bundle rests on no decision under ${expected.pack_ref}`);
  }
  if (expected.pack_version && expected.decision && str(expected.decision, "pack_version") !== expected.pack_version) {
    findings.push(`${where}: POLICY REVISION MOVED — the decision was taken under ${str(expected.decision, "pack_version")} and ${expected.pack_version} was asked for`);
  }
  if (expected.reviewer_ref && !list(bundle, "authority_refs").includes(expected.reviewer_ref)) {
    findings.push(`${where}: WRONG REVIEWER — ${expected.reviewer_ref} is not among the authorities that supported this export`);
  }
  if (expected.redaction_profile_ref && str(bundle, "redaction_profile_ref") !== expected.redaction_profile_ref) {
    findings.push(`${where}: WRONG REDACTION — built under ${str(bundle, "redaction_profile_ref")}, expected ${expected.redaction_profile_ref}`);
  }
  if (expected.retention_lock_ref && !list(bundle, "retention_lock_refs").includes(expected.retention_lock_ref)) {
    findings.push(`${where}: RETENTION — ${expected.retention_lock_ref} does not stand behind this bundle`);
  }
  // THE EVIDENCE HASH. A bundle whose root does not match what was delivered is not the bundle that was
  // generated, whatever its status says — and `revoked` and `superseded` mean nothing without this.
  if (expected.export_root && str(bundle, "export_root") !== expected.export_root) {
    findings.push(`${where}: EVIDENCE HASH — the bundle presented is not the one that was generated`);
  }
  if (expected.export_root && !SHA256.test(expected.export_root)) {
    findings.push(`${where}: the relying party's expected hash is not a sha256, so it could never match`);
  }
  return findings;
}

/**
 * A REJECTED EVALUATION CANNOT MUTATE THE TARGET WORKFLOW — ACC-18's closing clause. The decision is
 * judgment; refusing, stopping and escalating belong to the owners the pack compiles into. `observed` is
 * what the run actually did, so a record claiming `performs_no_action` while the plane recorded a write
 * is caught by what happened rather than by what it says.
 */
export const FORBIDDEN_EFFECTS = Object.freeze([
  "workflow_mutated",
  "target_stopped",
  "authority_issued",
  "export_released",
  "policy_rewritten",
]);

export function mutationFindings(decision, observed, { where = "mutation" } = {}) {
  const findings = [];
  if (decision && decision.performs_no_action !== true) findings.push(`${where}: the decision record claims to act`);
  if (!observed || typeof observed !== "object") return findings;
  for (const effect of FORBIDDEN_EFFECTS) {
    if (observed[effect] === true) {
      findings.push(`${where}: the evaluation ${effect.replace(/_/gu, " ")}, and a rejected evaluation cannot change the target workflow`);
    }
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
