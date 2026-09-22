// M09.9 — the regulated-workload assurance deriver.
//
// THIS FILE REACHES NOTHING. No plane, no file, no clock, no network: every function here takes the
// records it judges as arguments and returns findings. That is what lets a relying party holding a
// case and the profile it names re-derive the verdict for themselves, which is the only form of
// verification that survives the estate being unavailable.
//
// WHAT IT JUDGES. A `RegulatedWorkloadAssuranceProfile` BINDS owners rather than restating them:
// residency, retention, deletion and export belong to the bound `JurisdictionPolicyPack`, and
// purpose, allowed uses, data classes, redaction and egress belong to the bound
// `PolicyBoundDataView`. A `RegulatedWorkloadAdmissionCase` records one evaluation and is technical
// evidence, never a legal determination.
//
// THE CONFLATION THIS UNIT EXISTS TO REFUSE. `custody` names at least four different objects in this
// estate and `egress` names five. A profile that required a bare `custody` would bind whichever one
// its reader assumed and a gate would go green on the wrong object, so every binding is the exact
// member of the exact owner and this deriver checks that the exact member is what is there.
import crypto from "node:crypto";

export const LEGAL_CONFORMITY_CLAIM = "not_determined";

export const REFUSAL_REASONS = Object.freeze([
  "binding_missing",
  "binding_stale",
  "binding_substituted",
  "binding_broader_than_purpose",
  "binding_owner_absent",
]);

export const PRIVACY_CLASSES = Object.freeze([
  "confidential",
  "restricted",
  "regulated",
  "safety_critical",
]);

export const PROCESS_CUSTODY = Object.freeze(["local", "brokered", "delegated_attested"]);

/** The three bindings canon requires and nothing in this estate resolves. */
export const UNOWNED_MEMBERS = Object.freeze([
  "data_processor_terms_ref",
  "key_control_ref",
  "access_log_binding_ref",
]);

/**
 * Members another owner already holds. A profile carrying any of these has made a second copy of a
 * rule, free to drift from the policy it was copied from. The schema forbids them structurally;
 * this list exists so the finding can NAME the owner being duplicated instead of saying "unexpected
 * property", which is the difference between a message an author can act on and one they cannot.
 */
export const OWNED_ELSEWHERE = Object.freeze({
  residency_policy_ref: "the bound JurisdictionPolicyPack's data_requirements",
  retention_policy_ref: "the bound JurisdictionPolicyPack's data_requirements",
  deletion_policy_ref: "the bound JurisdictionPolicyPack's data_requirements",
  export_policy_ref: "the bound JurisdictionPolicyPack's data_requirements",
  allowed_uses: "the bound PolicyBoundDataView revision",
  data_classes: "the bound PolicyBoundDataView revision",
  redaction: "the bound PolicyBoundDataView revision",
  retention_and_hold: "the bound PolicyBoundDataView revision",
  destination_and_egress: "the bound PolicyBoundDataView revision",
  egress_policy: "the bound RuntimeToolContract revision",
  custody: "no single owner — `custody` names at least four different objects, so a bare member binds whichever one its reader assumed",
});

const str = (value, key) => (typeof value?.[key] === "string" ? value[key] : "");
const at = (value, ...keys) => keys.reduce((node, key) => (node == null ? undefined : node[key]), value);
const atStr = (value, ...keys) => { const v = at(value, ...keys); return typeof v === "string" ? v : ""; };
const list = (value) => (Array.isArray(value) ? value : []);

const canonical = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
};

/** The same seal the registered invariant recomputes. A seal computed differently is not a seal. */
export function rootOf(record, members) {
  const material = {};
  for (const member of members) material[member] = record?.[member] ?? null;
  return `sha256:${crypto.createHash("sha256").update(canonical(material)).digest("hex")}`;
}

export const PROFILE_MATERIAL = Object.freeze([
  "schema_version", "profile_id", "version", "issued_at", "supersedes_ref", "subject",
  "policy_bindings", "route_bindings", "custody_bindings", "operational_bindings",
  "unowned_bindings", "grants_no_authority", "is_not_legal_advice",
]);

export const CASE_MATERIAL = Object.freeze([
  "schema_version", "case_id", "profile_ref", "profile_version", "profile_root", "evaluated_at",
  "verdict", "refusals", "legal_conformity_claim", "grants_no_authority", "performs_no_action",
]);

/** A profile declares; it never grants, and it never restates what it binds. */
export function profileFindings(profile) {
  const findings = [];
  const where = "profile";
  if (profile?.grants_no_authority !== true) findings.push(`${where}: the profile claims authority`);
  if (profile?.is_not_legal_advice !== true) findings.push(`${where}: the profile claims to be legal advice`);

  for (const [member, owner] of Object.entries(OWNED_ELSEWHERE)) {
    if (profile != null && Object.prototype.hasOwnProperty.call(profile, member)) {
      findings.push(`${where}: restates \`${member}\`, which is owned by ${owner} — a second copy of a rule is free to drift from it`);
    }
  }

  const purpose = atStr(profile, "subject", "declared_purpose");
  if (purpose.trim().length < 12) {
    findings.push(`${where}: the declared purpose is too short to compare against a view's allowed uses`);
  }
  const privacy = atStr(profile, "subject", "privacy_class");
  if (!PRIVACY_CLASSES.includes(privacy)) {
    findings.push(`${where}: \`${privacy}\` is not one of the four privacy classes that require this profile`);
  }

  // EVERY BINDING IS PINNED TO A REVISION. A profile that binds an owner by NAME can never be found
  // stale or substituted, because there is nothing to compare a moved revision against.
  for (const [member, kind] of [
    ["jurisdiction_policy_pack_version", "the pack's exact version"],
    ["policy_bound_data_view_revision_ref", "the view's exact revision"],
  ]) {
    if (!atStr(profile, "policy_bindings", member)) {
      findings.push(`${where}: binds an owner without ${kind}, so a moved revision would be undetectable`);
    }
  }

  if (!PROCESS_CUSTODY.includes(atStr(profile, "custody_bindings", "process_custody"))) {
    findings.push(`${where}: process custody is not one of the three declared postures`);
  }
  if (list(at(profile, "custody_bindings", "locality_and_custody_refs")).length === 0) {
    findings.push(`${where}: names no locality or custody policy, so where this workload's data may sit is undeclared`);
  }

  for (const member of UNOWNED_MEMBERS) {
    if (!atStr(profile, "unowned_bindings", member)) {
      findings.push(`${where}: drops \`${member}\`, an obligation canon places on a regulated workload — dropping it would admit a workload that cannot satisfy it`);
    }
  }
  return findings;
}

/** A case reports; it never determines a question of law and never acts on its subject. */
export function caseFindings(record) {
  const findings = [];
  const where = "case";
  if (str(record, "legal_conformity_claim") !== LEGAL_CONFORMITY_CLAIM) {
    findings.push(`${where}: expresses a legal conformity claim, which no technical evaluation may determine`);
  }
  if (record?.grants_no_authority !== true) findings.push(`${where}: the case claims authority`);
  if (record?.performs_no_action !== true) findings.push(`${where}: the case claims to act on its subject`);

  const refusals = list(record?.refusals);
  const verdict = str(record, "verdict");
  if (verdict === "refused" && refusals.length === 0) {
    findings.push(`${where}: refuses and names nothing, so the owner cannot tell which binding failed`);
  }
  if (verdict === "admitted" && refusals.length > 0) {
    findings.push(`${where}: admits while carrying ${refusals.length} refusal(s)`);
  }
  if (verdict !== "admitted" && verdict !== "refused") {
    findings.push(`${where}: \`${verdict}\` is not one of the two verdicts this object may reach`);
  }

  const seen = new Set();
  for (const refusal of refusals) {
    const reason = str(refusal, "reason");
    const member = str(refusal, "member");
    if (!REFUSAL_REASONS.includes(reason)) findings.push(`${where}: \`${reason}\` is not a typed refusal reason`);
    if (member.trim().length < 3) findings.push(`${where}: a refusal names no member, so it cannot be acted on`);
    if (str(refusal, "detail").trim().length < 12) findings.push(`${where}: a refusal carries no detail`);
    const key = `${reason}|${member}`;
    if (seen.has(key)) findings.push(`${where}: ${reason} recorded twice for ${member}, which turns a count of problems into a count of entries`);
    seen.add(key);
  }
  if (!/^sha256:[0-9a-f]{64}$/u.test(str(record, "profile_root"))) {
    findings.push(`${where}: binds no profile root, so an in-place edit of a binding would be invisible to it`);
  }
  return findings;
}

const refusal = (reason, member, detail) => ({ reason, member, detail });

/**
 * THE EVALUATION, and the JS side of the same law the Rust plane enforces. `pack` and `view` are the
 * records the ESTATE ADMITTED, or null when it holds none — which is the whole point: a profile can
 * seal itself, but only something holding the admitted records can tell whether what it bound is
 * still what is there.
 */
export function evaluate(profile, { pack = null, view = null } = {}) {
  const out = [];

  const packRef = atStr(profile, "policy_bindings", "jurisdiction_policy_pack_ref");
  if (pack == null) {
    out.push(refusal("binding_missing", "policy_bindings.jurisdiction_policy_pack_ref",
      `this estate holds no admitted jurisdiction policy pack at ${packRef}`));
  } else {
    const bound = atStr(profile, "policy_bindings", "jurisdiction_policy_pack_version");
    const admitted = str(pack, "version");
    if (bound !== admitted) {
      out.push(refusal("binding_stale", "policy_bindings.jurisdiction_policy_pack_version",
        `the profile pins pack version ${bound} and the admitted pack reads ${admitted}`));
    }
  }

  const viewRef = atStr(profile, "policy_bindings", "policy_bound_data_view_ref");
  if (view == null) {
    out.push(refusal("binding_missing", "policy_bindings.policy_bound_data_view_ref",
      `this estate holds no admitted policy-bound data view at ${viewRef}`));
  } else {
    const bound = atStr(profile, "policy_bindings", "policy_bound_data_view_revision_ref");
    const admitted = str(view, "revision_ref");
    if (bound !== admitted) {
      out.push(refusal("binding_stale", "policy_bindings.policy_bound_data_view_revision_ref",
        `the profile pins view revision ${bound} and the view's current revision is ${admitted}`));
    }
    // This cannot rank two prose statements for breadth, so it requires them to be identical. A view
    // built for another purpose may be wider than what the workload declared.
    if (atStr(profile, "subject", "declared_purpose") !== str(view, "purpose")) {
      out.push(refusal("binding_broader_than_purpose", "policy_bindings.policy_bound_data_view_ref",
        "the bound view's purpose is not the workload's declared purpose; this plane requires them to be identical because it cannot rank prose for breadth, and a view built for another purpose may be wider than what this workload declared"));
    }
  }

  // THE NAMED ABSENCE, unconditional because nothing resolves these refs anywhere in the estate.
  for (const member of UNOWNED_MEMBERS) {
    out.push(refusal("binding_owner_absent", `unowned_bindings.${member}`,
      `no plane in this estate resolves a ${member.replace(/_ref$/u, "")} ref, so this obligation cannot be verified`));
  }
  return out;
}

export const verdictOf = (refusals) => (list(refusals).length === 0 ? "admitted" : "refused");

/**
 * WHAT A RELYING PARTY CAN CHECK HOLDING ONLY THE BUNDLE. No daemon, no clock, no network: the case,
 * the profile it names, and the admitted records that party independently holds. A verifier that has
 * to ask the estate whether its own evidence is good cannot be run by the party that most needs it.
 *
 * `expectations` is what the relying party believes. An EMPTY or non-object expectation is refused
 * rather than satisfied — a verifier that passes when asked nothing produces a green someone will
 * cite, which is worse than no verifier at all.
 */
export function relyingPartyFindings(record, profile, expectations) {
  const findings = [];
  if (expectations == null || typeof expectations !== "object" || Array.isArray(expectations)
    || Object.keys(expectations).length === 0) {
    return ["relying party: no expectation was stated, and a check that asks nothing confirms nothing"];
  }

  if (rootOf(profile, PROFILE_MATERIAL) !== str(profile, "profile_root")) {
    findings.push("relying party: the profile's content does not recompute to the root it carries");
  }
  if (rootOf(record, CASE_MATERIAL) !== str(record, "case_root")) {
    findings.push("relying party: the case's content does not recompute to the root it carries");
  }
  if (str(record, "profile_root") !== str(profile, "profile_root")) {
    findings.push("relying party: this case was evaluated against different profile content than the profile in hand");
  }
  if (str(record, "profile_ref") !== str(profile, "profile_id")) {
    findings.push("relying party: this case names a different profile than the one in hand");
  }

  if (typeof expectations.workload_ref === "string"
    && expectations.workload_ref !== atStr(profile, "subject", "workload_ref")) {
    findings.push("relying party: the profile governs a different workload than expected");
  }
  if (typeof expectations.declared_purpose === "string"
    && expectations.declared_purpose !== atStr(profile, "subject", "declared_purpose")) {
    findings.push("relying party: the workload declared a different purpose than expected");
  }
  if (typeof expectations.jurisdiction_policy_pack_ref === "string"
    && expectations.jurisdiction_policy_pack_ref !== atStr(profile, "policy_bindings", "jurisdiction_policy_pack_ref")) {
    findings.push("relying party: the profile binds a different jurisdiction policy pack than expected");
  }
  if (typeof expectations.verdict === "string" && expectations.verdict !== str(record, "verdict")) {
    findings.push("relying party: the case reached a different verdict than expected");
  }

  // THE RE-DERIVATION. The party holding the admitted records recomputes the refusals itself rather
  // than believing the ones the case carries.
  if (expectations.admitted != null && typeof expectations.admitted === "object") {
    const derived = evaluate(profile, expectations.admitted);
    const shape = (rows) => list(rows).map((r) => `${str(r, "reason")}|${str(r, "member")}`).sort().join(",");
    if (shape(derived) !== shape(record?.refusals)) {
      findings.push("relying party: re-deriving the evaluation against the records in hand does not reproduce this case's refusals");
    }
    if (verdictOf(derived) !== str(record, "verdict")) {
      findings.push("relying party: re-deriving the evaluation does not reproduce this case's verdict");
    }
  }
  return findings;
}
