#!/usr/bin/env node
// check:regulated-workload-assurance — M09.9: the regulated and sensitive-workload deployment
// profile, as a gate
// (docs/architecture/foundations/ecosystem-assurance-certification-liability.md; ACC-18; R-230/R-231).
//
// CANON. A regulated workload must bind residency and data-processor terms, a `PolicyBoundDataView`,
// access logging, custody, key control, incident handling, backup and retention classes, egress
// policy, and every model or tool route it uses. Admission fails when any required binding is
// missing, stale, substituted or BROADER THAN THE WORKER'S DECLARED PURPOSE. The result is technical
// assurance evidence, not a legal conclusion.
//
// THIS IS A COMPOSITION UNIT, NOT A REGISTRATION ONE (R-230). Canon does not hold this profile's
// shape anywhere; its bindings are owned by at least five planes. Four of them acquired an owner one
// day before this unit: `JurisdictionPolicyPack.data_requirements` requires retention, deletion,
// export and residency policy refs, and states in its own schema that "the pack names them; it does
// not restate them, because a restated policy is a second copy that can drift." That sentence binds
// this unit too — so the profile BINDS and never re-declares, and this gate checks that it does.
//
// THE CONFLATION IT REFUSES. `custody` names at least four different objects in this estate
// (credential custody, process custody, data locality, custody tier) and `egress` names five. A
// profile requiring a bare `custody` would bind whichever one its reader assumed, and a gate would
// go green on the wrong object. Every binding names the exact member of the exact owner.
//
//   PURE    — the deriver in apps/hypervisor/scripts/lib/regulated-workload-assurance.mjs over the
//             registered fixtures: the profile restates nothing, the case determines no question of
//             law, refusals are typed and name their member, and the evaluation is exact.
//   OFFLINE — a relying party holding the case, the profile it names and its own admitted records
//             re-derives the verdict. No daemon, no clock, no network — and no vacuous pass.
//   SEAM    — the two registered contracts refuse at the wire: `const not_determined` inherited from
//             M06.10, the closed refusal-reason and privacy-class sets, the required unowned
//             bindings, the sealed roots, and every fixture classified at the layer that refuses it.
//   SOURCE  — the plane derives the verdict rather than accepting one, refuses a caller-authored
//             recorder, resolves identity BEFORE the record, and recomputes the profile root.
//   PLANE   — full mode, one isolated daemon: a profile admitted, a case derived over it, the three
//             owner-absent refusals present and nothing else, a caller-authored verdict refused, a
//             pack the estate never admitted refused `binding_missing`, and a cross-tenant read
//             refused without an existence oracle.
//
//   --drills           CI-bound, seconds: PURE, OFFLINE, SEAM, SOURCE, the binding and the verdict rules.
//   --mutation         planted defects against the deriver — each must go red.
//   (default)          the full gate: the drills, then PLANE. Exit 0 pass, 2 named failure, 1 fail.
//   --evidence <path>  also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import * as LIB from "../apps/hypervisor/scripts/lib/regulated-workload-assurance.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "regulated-workload-assurance.mjs");
const META = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const PLANE_SRC = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "regulated_workload_routes.rs");
const ROUTER = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor-daemon.rs");
const CANON = path.join(ROOT, "docs", "architecture", "foundations", "ecosystem-assurance-certification-liability.md");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-231";

const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const OFFLINE = self("offline");
const SEAM = self("seam");
const SOURCE = self("source");
const PLANE = self("plane");

export const CLAUSES = [
  { n: 1, demand: "THE PROFILE BINDS OWNERS AND RESTATES NOTHING: residency, retention, deletion and export belong to the bound JurisdictionPolicyPack's `data_requirements`, and purpose, allowed uses, data classes, redaction and egress to the bound PolicyBoundDataView revision — a member copied inline is a second copy of a rule, free to drift from the policy it came from", executed_by: [SEAM, PURE] },
  { n: 2, demand: "EVERY BINDING IS PINNED TO A REVISION AND THE PROFILE IS SEALED: an owner bound by NAME can never be found stale or substituted because there is nothing to compare against, and a case binds the profile's ROOT rather than its name, so editing a binding in place breaks every recorded case instead of silently rewriting what they decided", executed_by: [SEAM, SOURCE, PLANE] },
  { n: 3, demand: "`custody` AND `egress` ARE NEVER USED BARE: those two words name roughly fifteen different objects across this estate, so each binding names the exact member of the exact owner — credential custody, process custody and data locality are separate members, and a profile requiring a bare `custody` would bind whichever one its reader assumed while the gate went green on the wrong object", executed_by: [SEAM, PURE] },
  { n: 4, demand: "THE THREE UNOWNED BINDINGS ARE REQUIRED ANYWAY: data-processor terms, key control and access logging are obligations canon places on a regulated workload and nothing in this estate resolves them, so they are required refs with no resolver — dropping one would admit a regulated workload that cannot be audited, which is the outcome the requirement exists to prevent", executed_by: [SEAM, PURE] },
  { n: 5, demand: "TECHNICAL EVIDENCE IS NEVER A LEGAL DETERMINATION: `legal_conformity_claim` is `const not_determined` on the case, INHERITED from the rule M06.10 put on the wire rather than restated, so no admitted verdict, complete binding set or current evidence can be expressed as a legal conclusion about the workload", executed_by: [SEAM, PURE, PLANE] },
  { n: 6, demand: "THE VERDICT IS DERIVED BY THE PLANE, NEVER ACCEPTED FROM THE CALLER: a POST carries only a `profile_ref`, because a caller-authored verdict is the subject grading its own homework — the same defect class as a caller-authored recorder, which this plane also refuses rather than corrects", executed_by: [SOURCE, PLANE] },
  { n: 7, demand: "A REFUSAL NAMES ITS MEMBER AND ITS REASON: every entry carries a typed reason from the closed set and the exact profile member it is about, dotted from the profile root, and the same reason is never recorded twice for one member — a refusal that cannot say which binding failed cannot be acted on, and duplicates turn a count of problems into a count of entries", executed_by: [PURE, SEAM] },
  { n: 8, demand: "THE REFUSALS ONLY A PLANE CAN MAKE: `binding_missing` names a ref the estate holds nothing at, `binding_stale` one whose owner moved past the pinned revision, and `binding_substituted` one whose CONTENT is not what the profile was written against — all three need the ADMITTED record to compare with, and a contract can seal a profile but cannot know what the estate admitted", executed_by: [SOURCE, PLANE] },
  { n: 9, demand: "BROADER THAN THE DECLARED PURPOSE IS REFUSED: the bound view's own purpose must BE the workload's declared purpose, because this estate cannot rank two prose statements for breadth and a view built for another purpose may be wider than what the workload stated — binding it would let a workload read under a purpose it never declared", executed_by: [PURE, PLANE] },
  { n: 10, demand: "IT VERIFIES OFFLINE, AND REFUSES TO PASS VACUOUSLY: a relying party holding the case, the profile it names and its own admitted records recomputes both roots and RE-DERIVES the refusals rather than believing the ones the case carries — with no daemon, no clock and no network, and an empty or non-object expectation is refused rather than satisfied, because a verifier that passes when asked nothing produces a green someone will cite", executed_by: [OFFLINE, PURE] },
  { n: 11, demand: "A REFUSED EVALUATION MUTATES NOTHING: the case reports and the owners act, so it quarantines no workload, revokes no lease and narrows no policy — `performs_no_action` is on the wire as a const and the plane writes to neither of the owners it reads", executed_by: [PURE, SOURCE, PLANE] },
  { n: 12, demand: "THE TENANT LINE HOLDS: identity is resolved BEFORE the record is loaded so an unauthenticated caller is owed 401 and never an existence oracle, and a cross-tenant read answers the scope refusal rather than the record or a 404 that would leak whether it exists", executed_by: [SOURCE, PLANE], absence: { what: "TWO BINDINGS ARE REQUIRED AND NOT DRIVEN, and the difference between them matters. (1) THE THREE UNOWNED REFS have no resolver anywhere in this estate — measured 2026-09-22 across the 353-schema registry and every daemon route module, `data_processor`/`subprocessor`/`processor_terms`, `key_control`/`key_custody`/`kms`/`hsm` and `access_log`/`audit_log`/`read_log`/`access_record` return zero hits under every one of those names. That absence is DRIVEN as a refusal: every regulated admission is refused `binding_owner_absent` naming which one, which is the gate working rather than a gap in it. (2) ROUTE-REVISION CURRENTNESS IS NOT DRIVEN AT ALL. `route_bindings.model_route_revision_refs` and `.tool_contract_revision_refs` are required and pinned on the profile, and this plane does not compare them against what the model-route and tool-contract planes admitted, because those stores' revision semantics were not measured and R-230's own finding is that a binding which exists is not a binding this unit may require until it has been read. A profile may therefore pin a route revision the estate never admitted and this gate will not say so. THIRD, ACC-18 HAS NO RUNNER: fourteen `check-acceptance-*` runners exist under `scripts/` and none is this journey's", owner: "the model-route and runtime-tool-contract planes for revision currentness; a data-processor-terms owner, a key-control owner and an access-log owner for the three unresolved refs; and ACC-18's own runner (" + OWNER_Q + ")" } },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.regulated-workload-assurance-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, offline: null, seam: null, source: null, plane: null, verdict: null, mutation: null };
let sink = results;
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  sink.push(row);
  if (sink === results) { evidence.drills.push({ ...row, at: new Date().toISOString() }); console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`); }
  return row.pass;
}
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `regulated-workload-assurance-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const fixture = (dir, name) => readJson(path.join(META, "fixtures", dir, name));

const PROFILE = () => fixture("regulated-workload-assurance-profile-v1", "positive-a-regulated-claims-workload.json");
const CASE = () => fixture("regulated-workload-admission-case-v1", "positive-refused-and-names-each-member.json");
const spoil = (record, mutate) => { const copy = JSON.parse(JSON.stringify(record)); mutate(copy); return copy; };

/** The admitted records that make the fixture profile's bindings current. */
const CURRENT = () => ({
  pack: { version: "4.2.0" },
  view: { revision_ref: "revision://acme/claims-member-scope/17", purpose: PROFILE().subject.declared_purpose },
});

// ---- PURE ----------------------------------------------------------------------------------------------------
export function pureFindings(lib) {
  const f = [];
  const must = (what, findings, shouldBeEmpty) => {
    const empty = findings.length === 0;
    if (empty !== shouldBeEmpty) f.push(`${what}: ${shouldBeEmpty ? `refused a clean shape (${findings.slice(0, 2).join("; ")})` : "accepted a spoiled one"}`);
  };
  const profile = PROFILE();
  const record = CASE();

  must("profile/clean", lib.profileFindings(profile), true);
  must("profile/claims-authority", lib.profileFindings(spoil(profile, (p) => { p.grants_no_authority = false; })), false);
  must("profile/claims-legal-advice", lib.profileFindings(spoil(profile, (p) => { p.is_not_legal_advice = false; })), false);
  must("profile/purpose-too-short", lib.profileFindings(spoil(profile, (p) => { p.subject.declared_purpose = "claims"; })), false);
  must("profile/invented-privacy-class", lib.profileFindings(spoil(profile, (p) => { p.subject.privacy_class = "public"; })), false);
  must("profile/binds-a-pack-with-no-version", lib.profileFindings(spoil(profile, (p) => { p.policy_bindings.jurisdiction_policy_pack_version = ""; })), false);
  must("profile/binds-a-view-with-no-revision", lib.profileFindings(spoil(profile, (p) => { p.policy_bindings.policy_bound_data_view_revision_ref = ""; })), false);
  must("profile/invented-process-custody", lib.profileFindings(spoil(profile, (p) => { p.custody_bindings.process_custody = "trusted"; })), false);
  must("profile/no-locality", lib.profileFindings(spoil(profile, (p) => { p.custody_bindings.locality_and_custody_refs = []; })), false);
  for (const member of lib.UNOWNED_MEMBERS) {
    must(`profile/drops-${member}`, lib.profileFindings(spoil(profile, (p) => { delete p.unowned_bindings[member]; })), false);
  }
  // EACH RESTATEMENT BY MESSAGE, because the finding's value is that it NAMES the owner being
  // duplicated — a generic "unexpected member" would not tell an author where the rule already lives.
  for (const [member, owner] of Object.entries(lib.OWNED_ELSEWHERE)) {
    const findings = lib.profileFindings(spoil(profile, (p) => { p[member] = "policy://somewhere"; }));
    must(`profile/restates-${member}`, findings, false);
    if (!findings.some((line) => line.includes(member) && line.includes(owner.slice(0, 24)))) {
      f.push(`profile/restates-${member}: refused without naming the owner it duplicates`);
    }
  }

  must("case/clean", lib.caseFindings(record), true);
  must("case/legal-verdict", lib.caseFindings(spoil(record, (c) => { c.legal_conformity_claim = "compliant"; })), false);
  must("case/claims-authority", lib.caseFindings(spoil(record, (c) => { c.grants_no_authority = false; })), false);
  must("case/acts-on-its-subject", lib.caseFindings(spoil(record, (c) => { c.performs_no_action = false; })), false);
  must("case/refuses-and-says-nothing", lib.caseFindings(spoil(record, (c) => { c.refusals = []; })), false);
  must("case/admits-while-refusing", lib.caseFindings(spoil(record, (c) => { c.verdict = "admitted"; })), false);
  must("case/invented-verdict", lib.caseFindings(spoil(record, (c) => { c.verdict = "provisional"; })), false);
  must("case/invented-reason", lib.caseFindings(spoil(record, (c) => { c.refusals[0].reason = "binding_suspicious"; })), false);
  must("case/refusal-names-no-member", lib.caseFindings(spoil(record, (c) => { c.refusals[0].member = ""; })), false);
  must("case/refusal-carries-no-detail", lib.caseFindings(spoil(record, (c) => { c.refusals[0].detail = "x"; })), false);
  must("case/one-reason-twice", lib.caseFindings(spoil(record, (c) => { c.refusals.push(JSON.parse(JSON.stringify(c.refusals[0]))); })), false);
  must("case/binds-no-profile-root", lib.caseFindings(spoil(record, (c) => { c.profile_root = ""; })), false);

  // -- THE EVALUATION IS EXACT --
  const current = lib.evaluate(profile, CURRENT());
  if (current.length !== 3 || !current.every((r) => r.reason === "binding_owner_absent")) {
    f.push(`evaluate: a fully current profile should produce exactly the three owner-absent refusals, got ${JSON.stringify(current.map((r) => r.reason))}`);
  }
  const noPack = lib.evaluate(profile, { ...CURRENT(), pack: null });
  if (!noPack.some((r) => r.reason === "binding_missing" && r.member === "policy_bindings.jurisdiction_policy_pack_ref")) {
    f.push("evaluate: a pack the estate never admitted was not named missing");
  }
  // THE VIEW HALF OF THE SAME CHECK. Its absence let a mutation that deleted the view's
  // `binding_missing` refusal survive, because nothing exercised the null-view branch at all.
  const noView = lib.evaluate(profile, { ...CURRENT(), view: null });
  if (!noView.some((r) => r.reason === "binding_missing" && r.member === "policy_bindings.policy_bound_data_view_ref")) {
    f.push("evaluate: a view the estate never admitted was not named missing");
  }
  const movedPack = lib.evaluate(profile, { ...CURRENT(), pack: { version: "4.3.0" } });
  if (!movedPack.some((r) => r.reason === "binding_stale" && r.member === "policy_bindings.jurisdiction_policy_pack_version")) {
    f.push("evaluate: a pack version that moved past the pin was not named stale");
  }
  const movedView = lib.evaluate(profile, { ...CURRENT(), view: { ...CURRENT().view, revision_ref: "revision://acme/claims-member-scope/18" } });
  if (!movedView.some((r) => r.reason === "binding_stale" && r.member === "policy_bindings.policy_bound_data_view_revision_ref")) {
    f.push("evaluate: a view revision that moved past the pin was not named stale");
  }
  const broader = lib.evaluate(profile, { ...CURRENT(), view: { ...CURRENT().view, purpose: "Adjudicate claims and produce secondary analytics." } });
  if (!broader.some((r) => r.reason === "binding_broader_than_purpose")) {
    f.push("evaluate: a view built for another purpose was not refused as broader");
  }
  if (lib.verdictOf([]) !== "admitted" || lib.verdictOf(current) !== "refused") {
    f.push("verdict: the verdict does not follow from whether anything was refused");
  }

  // -- the seal is the one the registered invariant recomputes --
  if (lib.rootOf(profile, lib.PROFILE_MATERIAL) !== profile.profile_root) f.push("seal: the profile root this deriver computes is not the one the fixture carries");
  if (lib.rootOf(record, lib.CASE_MATERIAL) !== record.case_root) f.push("seal: the case root this deriver computes is not the one the fixture carries");
  if (lib.PROFILE_MATERIAL.includes("recorded_by_ref") || lib.CASE_MATERIAL.includes("recorded_by_ref")) {
    f.push("seal: the server-stamped recorder is inside a root the caller seals before the server stamps it");
  }

  // -- the vocabularies are canon's --
  // THE EXPECTED MEMBERS ARE PINNED HERE, NOT READ FROM THE LIB. The restatement loop above walks
  // `lib.OWNED_ELSEWHERE`, so emptying that list made the loop test nothing and the defect survived:
  // a drill whose coverage comes from the mutant's own data cannot catch the mutant.
  for (const member of ["residency_policy_ref", "retention_policy_ref", "deletion_policy_ref", "export_policy_ref", "allowed_uses", "data_classes", "redaction", "retention_and_hold", "destination_and_egress", "egress_policy", "custody"]) {
    if (!Object.prototype.hasOwnProperty.call(lib.OWNED_ELSEWHERE, member)) {
      f.push(`vocabulary: \`${member}\` is owned elsewhere and the deriver no longer knows it, so restating it would pass`);
    }
  }
  if (lib.REFUSAL_REASONS.length !== 5) f.push("vocabulary: five typed refusal reasons");
  if (lib.PRIVACY_CLASSES.length !== 4) f.push("vocabulary: four privacy classes require this profile");
  if (lib.PROCESS_CUSTODY.length !== 3) f.push("vocabulary: three process-custody postures");
  if (lib.UNOWNED_MEMBERS.length !== 3) f.push("vocabulary: three bindings with no owner");
  if (lib.LEGAL_CONFORMITY_CLAIM !== "not_determined") f.push("vocabulary: the only admissible legal-conformity claim is not_determined");
  return f;
}

// ---- OFFLINE -------------------------------------------------------------------------------------------------
export function offlineFindings(lib) {
  const f = [];
  const profile = PROFILE();
  const admitted = CURRENT();
  // A case this party can check: derived from the profile they hold, against the records they hold.
  const refusals = lib.evaluate(profile, admitted);
  const base = {
    schema_version: "ioi.foundations.regulated-workload-admission-case.v1",
    case_id: "regulated_workload_admission_case://acme/offline/1",
    profile_ref: profile.profile_id,
    profile_version: profile.version,
    profile_root: profile.profile_root,
    evaluated_at: "2026-09-22T11:00:00Z",
    verdict: lib.verdictOf(refusals),
    refusals,
    legal_conformity_claim: "not_determined",
    grants_no_authority: true,
    performs_no_action: true,
  };
  const record = { ...base, recorded_by_ref: "principal://acme/compliance-engineering", case_root: lib.rootOf(base, lib.CASE_MATERIAL) };
  const expect = {
    workload_ref: profile.subject.workload_ref,
    declared_purpose: profile.subject.declared_purpose,
    jurisdiction_policy_pack_ref: profile.policy_bindings.jurisdiction_policy_pack_ref,
    verdict: "refused",
    admitted,
  };

  const must = (what, findings, shouldBeEmpty) => {
    const empty = findings.length === 0;
    if (empty !== shouldBeEmpty) f.push(`${what}: ${shouldBeEmpty ? `refused a clean bundle (${findings.slice(0, 2).join("; ")})` : "accepted a spoiled one"}`);
  };

  must("offline/clean", lib.relyingPartyFindings(record, profile, expect), true);
  // THE VACUOUS PASS. A verifier that confirms everything when asked nothing is worse than none.
  must("offline/no-expectation", lib.relyingPartyFindings(record, profile, {}), false);
  must("offline/null-expectation", lib.relyingPartyFindings(record, profile, null), false);
  must("offline/array-expectation", lib.relyingPartyFindings(record, profile, []), false);
  must("offline/wrong-workload", lib.relyingPartyFindings(record, profile, { ...expect, workload_ref: "worker://acme/something-else" }), false);
  must("offline/wrong-purpose", lib.relyingPartyFindings(record, profile, { ...expect, declared_purpose: "Something else entirely." }), false);
  must("offline/wrong-pack", lib.relyingPartyFindings(record, profile, { ...expect, jurisdiction_policy_pack_ref: "jurisdiction_policy_pack://acme/other/v1" }), false);
  must("offline/wrong-verdict", lib.relyingPartyFindings(record, profile, { ...expect, verdict: "admitted" }), false);
  must("offline/case-root-moved", lib.relyingPartyFindings(spoil(record, (c) => { c.evaluated_at = "2026-09-23T11:00:00Z"; }), profile, expect), false);
  must("offline/profile-root-moved", lib.relyingPartyFindings(record, spoil(profile, (p) => { p.version = "9.9.9"; }), expect), false);
  // BY MESSAGE, and RE-SEALED. Changing `profile_ref` also moves the case root, so a case that only
  // asserted "some finding appeared" was satisfied by the root check and the profile-identity check
  // could be deleted without the drill noticing. Re-sealing removes the root finding, so the only
  // thing left to catch it is the check this case is named for.
  const differentProfile = (() => {
    const { recorded_by_ref, case_root, ...material } = record;
    const moved = { ...material, profile_ref: "regulated_workload_assurance_profile://acme/other/v1" };
    return { ...moved, recorded_by_ref, case_root: lib.rootOf(moved, lib.CASE_MATERIAL) };
  })();
  const differentFindings = lib.relyingPartyFindings(differentProfile, profile, expect);
  must("offline/a-different-profile", differentFindings, false);
  if (!differentFindings.some((line) => /names a different profile/u.test(line))) {
    f.push("offline/a-different-profile: refused for some other reason than the case naming a different profile");
  }
  // THE RE-DERIVATION. The party recomputes rather than believing what the case carries.
  must("offline/refusals-do-not-re-derive", lib.relyingPartyFindings(spoil(record, (c) => { c.refusals = c.refusals.slice(0, 1); }), profile, expect), false);
  must("offline/records-in-hand-disagree", lib.relyingPartyFindings(record, profile, { ...expect, admitted: { ...admitted, pack: null } }), false);
  // THE VERDICT IS RE-DERIVED TOO, and this case isolates that from the refusals. The refusals still
  // reproduce exactly; only the verdict word is wrong, and it is re-sealed so no root check masks it.
  // Without this, deleting the verdict re-derivation survived: every other case tripped some other
  // check first.
  const wrongVerdict = (() => {
    const { recorded_by_ref, case_root, ...material } = record;
    const moved = { ...material, verdict: "admitted" };
    return { ...moved, recorded_by_ref, case_root: lib.rootOf(moved, lib.CASE_MATERIAL) };
  })();
  const verdictFindings = lib.relyingPartyFindings(wrongVerdict, profile, { ...expect, verdict: "admitted" });
  must("offline/verdict-does-not-re-derive", verdictFindings, false);
  if (!verdictFindings.some((line) => /does not reproduce this case's verdict/u.test(line))) {
    f.push("offline/verdict-does-not-re-derive: refused for some other reason than the verdict failing to re-derive");
  }
  return f;
}

// ---- SEAM ----------------------------------------------------------------------------------------------------
export function seamFindings({ registry, profileSchema, caseSchema, profileInv, caseInv }) {
  const f = [];
  const named = (id) => registry.contracts.find((c) => c.contract_id === id);
  const profileRow = named("schema://ioi/foundations/regulated-workload-assurance-profile/v1");
  const caseRow = named("schema://ioi/foundations/regulated-workload-admission-case/v1");
  if (!profileRow) f.push("the profile is not a registered contract");
  if (!caseRow) f.push("the admission case is not a registered contract");
  if (!profileRow || !caseRow) return f;

  // THE CONST THIS UNIT INHERITS RATHER THAN RESTATES.
  if (caseSchema.properties?.legal_conformity_claim?.const !== "not_determined") {
    f.push("the case does not pin legal_conformity_claim, so a legal verdict is representable");
  }
  for (const [schema, member] of [[profileSchema, "grants_no_authority"], [caseSchema, "grants_no_authority"], [profileSchema, "is_not_legal_advice"], [caseSchema, "performs_no_action"]]) {
    if (schema.properties?.[member]?.const !== true) f.push(`${schema.title}: ${member} is not pinned on the wire`);
  }

  // EVERY MATERIAL MEMBER IS REQUIRED. A material member the projection may drop is a root that
  // silently stops recomputing — `check:architecture-contracts` cannot see this, only the Rust
  // golden oracle can, so the seam asserts the property directly.
  for (const [schema, inv, rootMember] of [[profileSchema, profileInv, "profile_root"], [caseSchema, caseInv, "case_root"]]) {
    const rule = inv.rules.find((r) => r.expression.operator === "jcs_sha256_equals");
    if (!rule) { f.push(`${schema.title}: no root invariant`); continue; }
    for (const member of Object.keys(rule.expression.material_fields)) {
      if (!schema.required.includes(member)) f.push(`${schema.title}: \`${member}\` is material to ${rootMember} and not required, so the projection may drop it`);
    }
    if (Object.keys(rule.expression.material_fields).includes("recorded_by_ref")) {
      f.push(`${schema.title}: the server-stamped recorder is inside the root the caller seals`);
    }
    if (!schema.required.includes("recorded_by_ref")) {
      f.push(`${schema.title}: no recorded_by_ref, so an admitted record would be readable by nobody`);
    }
  }

  // THE CLOSED SETS ARE CANON'S.
  const reasons = caseSchema.properties?.refusals?.items?.properties?.reason?.enum ?? [];
  if (JSON.stringify([...reasons].sort()) !== JSON.stringify([...LIB.REFUSAL_REASONS].sort())) {
    f.push("the case's refusal reasons are not the five typed reasons");
  }
  const classes = profileSchema.properties?.subject?.properties?.privacy_class?.enum ?? [];
  if (JSON.stringify([...classes].sort()) !== JSON.stringify([...LIB.PRIVACY_CLASSES].sort())) {
    f.push("the profile's privacy classes are not the four that require it");
  }

  // THE UNOWNED BINDINGS ARE REQUIRED, and `custody`/`egress` are never bare.
  const unowned = profileSchema.properties?.unowned_bindings?.required ?? [];
  for (const member of LIB.UNOWNED_MEMBERS) {
    if (!unowned.includes(member)) f.push(`the profile does not require \`${member}\`, so a regulated workload could be admitted without it`);
  }
  if (profileSchema.additionalProperties !== false) f.push("the profile accepts additional members, so a restated rule could ride along");
  const custody = profileSchema.properties?.custody_bindings?.properties ?? {};
  if (Object.prototype.hasOwnProperty.call(custody, "custody")) f.push("the profile carries a bare `custody` member, which binds whichever of four objects its reader assumed");
  for (const member of ["residency_policy_ref", "retention_policy_ref", "export_policy_ref", "deletion_policy_ref"]) {
    if (Object.prototype.hasOwnProperty.call(profileSchema.properties ?? {}, member)) {
      f.push(`the profile restates \`${member}\`, which the bound pack's data_requirements already owns`);
    }
  }

  // EVERY FIXTURE IS CLASSIFIED AT THE LAYER THAT REFUSES IT.
  for (const row of [profileRow, caseRow]) {
    if (row.positive_fixture_refs.length < 1) f.push(`${row.canonical_name}: no positive fixture`);
    if (row.negative_fixture_refs.length < 8) f.push(`${row.canonical_name}: ${row.negative_fixture_refs.length} negative fixtures is too few to bound this shape`);
    for (const negative of row.negative_fixture_refs) {
      if (!["schema", "invariant"].includes(negative.expected_failure)) f.push(`${row.canonical_name}: ${negative.path} is classified \`${negative.expected_failure}\``);
    }
  }
  return f;
}

// ---- SOURCE --------------------------------------------------------------------------------------------------
export function sourceFindings({ plane, router, canon, lib }) {
  const f = [];
  const code = LIB.codeOnly ? LIB.codeOnly(plane) : plane;
  for (const contract of ["regulated-workload-assurance-profile/v1", "regulated-workload-admission-case/v1"]) {
    if (!code.includes(contract)) f.push(`the plane does not name ${contract}, so that record is admitted unvalidated`);
  }
  if (!/validate_architecture_contract\(/u.test(code)) f.push("the plane does not validate the registered contract at admission");
  // THE VERDICT IS DERIVED, NEVER ACCEPTED.
  if (!/verdict_authored/u.test(code)) f.push("the plane accepts a caller-authored verdict, so the subject can grade its own homework");
  if (!/recorder_authored/u.test(code)) f.push("the plane accepts a caller-authored recorder");
  // THE REFUSALS ONLY A PLANE CAN MAKE.
  for (const [reason, why] of [["binding_missing", "a ref the estate holds nothing at"], ["binding_stale", "an owner that moved past the pinned revision"], ["binding_substituted", "content that is not what the profile was written against"], ["binding_owner_absent", "a binding with no resolver anywhere"]]) {
    if (!code.includes(reason)) f.push(`the plane never refuses ${reason} (${why})`);
  }
  // IDENTITY PRECEDES THE RECORD.
  const authorized = code.slice(code.indexOf("fn authorized("), code.indexOf("fn store("));
  if (authorized.indexOf("resolve_request_identity") > authorized.indexOf("load(")) {
    f.push("the plane loads the record before resolving identity, so an unauthenticated caller gets an existence oracle");
  }
  if (!/authorizes_tenant/u.test(code)) f.push("the plane does not scope reads to the caller's tenant");
  // THE PROFILE ROOT IS RECOMPUTED, NOT READ.
  if (!/recomputed\s*!=\s*text\(&profile, "profile_root"\)/u.test(code)) {
    f.push("the plane trusts the profile root the record carries instead of recomputing it");
  }
  // IT WRITES TO NEITHER OWNER IT READS.
  for (const owned of ["jurisdiction-policy-packs", "odk-policy-bound-data-views"]) {
    if (new RegExp(`persist_record\\([^)]*${owned}`, "u").test(code)) f.push(`the plane writes to ${owned}, which it may only read`);
  }
  // THE ROUTES EXIST.
  for (const route of ["/v1/hypervisor/regulated-workload-assurance-profiles", "/v1/hypervisor/regulated-workload-admission-cases"]) {
    if (!router.includes(`"${route}"`)) f.push(`the router registers no ${route}`);
  }
  // CANON'S BINDING.
  if (!/RegulatedWorkloadAssuranceProfile/u.test(canon)) f.push("canon no longer carries the profile this unit registers");
  if (!/not restate them/u.test(canon)) f.push("canon no longer states the bind-never-restate rule this unit enforces");
  // THE DERIVER STAYS PURE.
  if (/fetch\(|readFileSync|Date\.now\(|new Date\(/u.test(lib)) {
    f.push("the deriver reaches a plane, a file or a clock, so its offline verifier is not offline");
  }
  return f;
}

export function sourceInputs() {
  return { plane: readText(PLANE_SRC), router: readText(ROUTER), canon: readText(CANON), lib: readText(LIB_PATH) };
}

// ---- the binding ---------------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate }) {
  const f = [];
  for (const script of ["check:regulated-workload-assurance", "mutate:regulated-workload-assurance"]) {
    if (!rootPkg.scripts?.[script]) f.push(`root_script_missing:${script}`);
  }
  if (!appPkg.scripts?.["check:regulated-workload-assurance"]) f.push("app_drills_script_missing");
  const row = (floors.verifiers ?? []).find((r) => r.id === "regulated-workload-assurance");
  if (!row) f.push("floor_row_missing");
  else {
    if (!fs.existsSync(path.join(ROOT, row.source))) f.push(`floor_source_absent:${row.source}`);
    if (!(row.runtime_assertions > 0)) f.push("floor_not_pinned");
  }
  // CI-BOUND IN THE FORM THE FLOORS GATE RECOGNISES, not merely by its bare name — R-225's defect was
  // a gate named in ci.yml in a form check:verifier-floors could not see, which reads as unfloored.
  if (!/npm run check:regulated-workload-assurance --workspace=@ioi\/hypervisor-app/u.test(ci)) {
    f.push("ci_not_bound_in_the_recognised_form");
  }
  if (!/mutate:regulated-workload-assurance/u.test(ci)) f.push("ci_mutation_not_bound");
  // AND THE FLOORS GATE MUST ACTUALLY RECOGNISE THIS SCRIPT. R-225's defect was a gate named in
  // ci.yml in a form check:verifier-floors could not see, which reads as unfloored. That gate
  // discovers non-`verify-*` runners from an explicit allow-list of basenames, so a `check-*` gate
  // absent from it is CI-bound in ci.yml and invisible to the floor — exactly the state this drill
  // passed over on its first run, because asking whether the floors gate mentions "check-" at all
  // is a question that cannot fail.
  if (!floorsGate.includes("check-regulated-workload-assurance")) {
    f.push("floors_gate_does_not_recognise_this_runner: it is a `check-*` script and the floors gate discovers those from an explicit allow-list");
  }
  // Every clause is executed or named with an owner.
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
  ok("PURE — the profile binds owners and restates none of them, every binding is pinned to a revision, the three unowned bindings are required, the case determines no question of law and acts on nothing, every refusal is typed and names its member, and the evaluation is exact", pure.length === 0, pure.slice(0, 4).join(" ; "));

  const offline = offlineFindings(LIB);
  evidence.offline = offline;
  ok("OFFLINE — a relying party holding the case, the profile it names and its own admitted records recomputes both roots and RE-DERIVES the refusals rather than believing them, with no daemon, no clock and no network — and an empty, null or non-object expectation is REFUSED rather than satisfied", offline.length === 0, offline.slice(0, 4).join(" ; "));

  const seam = seamFindings({
    registry: readJson(path.join(META, "architecture-contract-registry.v1.json")),
    profileSchema: readJson(path.join(META, "regulated-workload-assurance-profile.v1.schema.json")),
    caseSchema: readJson(path.join(META, "regulated-workload-admission-case.v1.schema.json")),
    profileInv: readJson(path.join(META, "invariants", "regulated-workload-assurance-profile.v1.invariants.json")),
    caseInv: readJson(path.join(META, "invariants", "regulated-workload-admission-case.v1.invariants.json")),
  });
  evidence.seam = seam;
  ok("SEAM — two registered contracts carry the law on the wire: `legal_conformity_claim` const not_determined inherited from M06.10, the closed refusal-reason and privacy-class sets, the three unowned bindings required, no bare `custody` and no member the bound pack already owns, every material member required so the projection cannot drop it, and the server-stamped recorder outside the root the caller seals", seam.length === 0, seam.slice(0, 4).join(" ; "));

  const src = sourceFindings(sourceInputs());
  evidence.source = src;
  ok("SOURCE — the plane validates each registered contract at admission, DERIVES the verdict instead of accepting one, refuses a caller-authored recorder, recomputes the profile root rather than trusting it, resolves identity BEFORE the record, scopes every read to the caller's tenant, writes to neither owner it reads — and the deriver reaches no plane, file or clock", src.length === 0, src.slice(0, 4).join(" ; "));

  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP_DIR, "package.json")),
    floors: readJson(FLOORS),
    ci: readText(path.join(ROOT, ".github", "workflows", "ci.yml")),
    floorsGate: readText(path.join(APP_DIR, "scripts", "check-verifier-floors.mjs")),
  });
  ok("BINDING — the gate is floored with an existing source, CI-bound in the form the FLOORS GATE recognises rather than by its bare name, and every clause is executed or named with an owner", binding.length === 0, binding.slice(0, 4).join(" ; "));

  // THE VERDICT RULES ARE THEMSELVES DRILLED, because a verdict function that cannot fail is a
  // rubber stamp and this is the one function nothing else checks.
  const all = CLAUSES.map((c) => ({ n: c.n }));
  ok("VERDICT — a table missing eleven of its twelve rows is a FAIL, not a pass", verdict([{ n: 1 }]).kind === "fail", verdict([{ n: 1 }]).failures.slice(0, 2).join(" ; "));
  ok("VERDICT — twelve green rows with no absence is a PASS", verdict(all).kind === "pass");
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", verdict(all.map((r) => (r.n === 12 ? { ...r, absent: true } : r))).kind === "named_failure", verdict(all.map((r) => (r.n === 12 ? { ...r, absent: true } : r))).kind);
  ok("VERDICT — a gate that reports success without evidence is fabricated, not green", verdict(all.map((r) => (r.n === 1 ? { ...r, fabricated: "x reports success without evidence" } : r))).kind === "fail");
  ok("VERDICT — a gate below its floor fails even at exit 0", verdict(all.map((r) => (r.n === 1 ? { ...r, below_floor: "x 2 < 9" } : r))).kind === "fail");

  return { pure, offline, seam, src, binding };
}

async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "regulated-workload-mutation-"));
  let planted = 0;
  let caught = 0;
  const mutate = async (what, transform, score = pureFindings) => {
    planted += 1;
    const file = path.join(dir, `m${planted}.mjs`);
    const text = transform(original);
    if (text === original) { console.log(`FAIL  mutation ${planted} (${what}) — the planted defect changed nothing`); return; }
    fs.writeFileSync(file, text);
    let findings = [];
    try { findings = score(await import(pathToFileURL(file).href)); } catch (error) { findings = [`threw:${error.message}`]; }
    const red = findings.length > 0;
    if (red) caught += 1;
    console.log(`${red ? "  ok  " : " FAIL "} mutation ${planted} — ${what}${red ? "" : " SURVIVED"}`);
  };

  await mutate("LEGAL VERDICT — a case may determine a question of law", (t) => t.replace('if (str(record, "legal_conformity_claim") !== LEGAL_CONFORMITY_CLAIM) {', "if (false) {"));
  await mutate("LEGAL VERDICT — the only admissible claim becomes anything", (t) => t.replace('export const LEGAL_CONFORMITY_CLAIM = "not_determined";', 'export const LEGAL_CONFORMITY_CLAIM = "";'));
  await mutate("AUTHORITY — a profile may claim it", (t) => t.replace('if (profile?.grants_no_authority !== true) findings.push(`${where}: the profile claims authority`);', ""));
  await mutate("AUTHORITY — a case may claim it", (t) => t.replace('if (record?.grants_no_authority !== true) findings.push(`${where}: the case claims authority`);', ""));
  await mutate("ACTION — a case may act on its subject", (t) => t.replace('if (record?.performs_no_action !== true) findings.push(`${where}: the case claims to act on its subject`);', ""));
  await mutate("RESTATEMENT — a profile may restate what it binds", (t) => t.replace("for (const [member, owner] of Object.entries(OWNED_ELSEWHERE)) {", "for (const [member, owner] of []) {"));
  await mutate("RESTATEMENT — the owned-elsewhere list becomes empty", (t) => t.replace("export const OWNED_ELSEWHERE = Object.freeze({", "export const OWNED_ELSEWHERE = Object.freeze({} ?? {"));
  await mutate("PURPOSE — a label passes as a declared purpose", (t) => t.replace("if (purpose.trim().length < 12) {", "if (false) {"));
  await mutate("PRIVACY — any class may require this profile", (t) => t.replace("if (!PRIVACY_CLASSES.includes(privacy)) {", "if (false) {"));
  await mutate("REVISION — an owner may be bound by name with no revision", (t) => t.replace('if (!atStr(profile, "policy_bindings", member)) {', "if (false) {"));
  await mutate("CUSTODY — any process-custody posture will do", (t) => t.replace('if (!PROCESS_CUSTODY.includes(atStr(profile, "custody_bindings", "process_custody"))) {', "if (false) {"));
  await mutate("CUSTODY — a profile may name no locality at all", (t) => t.replace('if (list(at(profile, "custody_bindings", "locality_and_custody_refs")).length === 0) {', "if (false) {"));
  await mutate("UNOWNED — a profile may drop an obligation with no owner", (t) => t.replace("for (const member of UNOWNED_MEMBERS) {\n    if (!atStr(profile, \"unowned_bindings\", member)) {", "for (const member of []) {\n    if (!atStr(profile, \"unowned_bindings\", member)) {"));
  await mutate("UNOWNED — the unowned list becomes empty", (t) => t.replace('export const UNOWNED_MEMBERS = Object.freeze([\n  "data_processor_terms_ref",', "export const UNOWNED_MEMBERS = Object.freeze([\n  // removed\n  \"data_processor_terms_ref_x\","));
  await mutate("REFUSAL — a case may refuse and say nothing", (t) => t.replace('if (verdict === "refused" && refusals.length === 0) {', "if (false) {"));
  await mutate("REFUSAL — a case may admit while carrying refusals", (t) => t.replace('if (verdict === "admitted" && refusals.length > 0) {', "if (false) {"));
  await mutate("REFUSAL — any verdict word will do", (t) => t.replace('if (verdict !== "admitted" && verdict !== "refused") {', "if (false) {"));
  await mutate("REFUSAL — any reason will do", (t) => t.replace("if (!REFUSAL_REASONS.includes(reason)) findings.push(`${where}: \\`${reason}\\` is not a typed refusal reason`);", ""));
  await mutate("REFUSAL — a refusal need name no member", (t) => t.replace("if (member.trim().length < 3) findings.push(`${where}: a refusal names no member, so it cannot be acted on`);", ""));
  await mutate("REFUSAL — a refusal need carry no detail", (t) => t.replace('if (str(refusal, "detail").trim().length < 12) findings.push(`${where}: a refusal carries no detail`);', ""));
  await mutate("REFUSAL — one reason twice for one member is fine", (t) => t.replace("if (seen.has(key)) findings.push(`${where}: ${reason} recorded twice for ${member}, which turns a count of problems into a count of entries`);", ""));
  await mutate("SEAL — a case need bind no profile root", (t) => t.replace('if (!/^sha256:[0-9a-f]{64}$/u.test(str(record, "profile_root"))) {', "if (false) {"));
  await mutate("EVALUATE — a pack the estate never admitted is fine", (t) => t.replace('out.push(refusal("binding_missing", "policy_bindings.jurisdiction_policy_pack_ref",', 'void 0 && out.push(refusal("binding_missing", "policy_bindings.jurisdiction_policy_pack_ref",'));
  await mutate("EVALUATE — a moved pack version is not stale", (t) => t.replace("    if (bound !== admitted) {\n      out.push(refusal(\"binding_stale\", \"policy_bindings.jurisdiction_policy_pack_version\",", "    if (false) {\n      out.push(refusal(\"binding_stale\", \"policy_bindings.jurisdiction_policy_pack_version\","));
  await mutate("EVALUATE — a view the estate never admitted is fine", (t) => t.replace('out.push(refusal("binding_missing", "policy_bindings.policy_bound_data_view_ref",', 'void 0 && out.push(refusal("binding_missing", "policy_bindings.policy_bound_data_view_ref",'));
  await mutate("EVALUATE — a moved view revision is not stale", (t) => t.replace("      out.push(refusal(\"binding_stale\", \"policy_bindings.policy_bound_data_view_revision_ref\",", "      void 0 && out.push(refusal(\"binding_stale\", \"policy_bindings.policy_bound_data_view_revision_ref\","));
  await mutate("EVALUATE — a view built for another purpose is not broader", (t) => t.replace('if (atStr(profile, "subject", "declared_purpose") !== str(view, "purpose")) {', "if (false) {"));
  await mutate("EVALUATE — the named absence stops being named", (t) => t.replace("  for (const member of UNOWNED_MEMBERS) {\n    out.push(refusal(\"binding_owner_absent\"", "  for (const member of []) {\n    out.push(refusal(\"binding_owner_absent\""));
  await mutate("VERDICT — refusals no longer decide the verdict", (t) => t.replace('export const verdictOf = (refusals) => (list(refusals).length === 0 ? "admitted" : "refused");', 'export const verdictOf = () => "admitted";'));
  await mutate("SEAL — the profile root is computed over the wrong members", (t) => t.replace('"schema_version", "profile_id", "version", "issued_at", "supersedes_ref", "subject",', '"profile_id", "version", "issued_at", "supersedes_ref", "subject",'));
  await mutate("SEAL — the case root is computed over the wrong members", (t) => t.replace('"schema_version", "case_id", "profile_ref", "profile_version", "profile_root", "evaluated_at",', '"case_id", "profile_ref", "profile_version", "profile_root", "evaluated_at",'));
  await mutate("SEAL — the recorder is folded into the root the caller seals", (t) => t.replace('"unowned_bindings", "grants_no_authority", "is_not_legal_advice",\n]);', '"unowned_bindings", "grants_no_authority", "is_not_legal_advice", "recorded_by_ref",\n]);'));
  await mutate("OFFLINE — an empty expectation is satisfied by anything", (t) => t.replace("|| Object.keys(expectations).length === 0) {", ") {"), offlineFindings);
  await mutate("OFFLINE — a non-object expectation is satisfied by anything", (t) => t.replace("if (expectations == null || typeof expectations !== \"object\" || Array.isArray(expectations)", "if (false && (expectations == null || typeof expectations !== \"object\" || Array.isArray(expectations))"), offlineFindings);
  await mutate("OFFLINE — a wrong workload passes", (t) => t.replace('if (typeof expectations.workload_ref === "string"', "if (false && typeof expectations.workload_ref === \"string\""), offlineFindings);
  await mutate("OFFLINE — a wrong purpose passes", (t) => t.replace('if (typeof expectations.declared_purpose === "string"', "if (false && typeof expectations.declared_purpose === \"string\""), offlineFindings);
  await mutate("OFFLINE — a wrong pack passes", (t) => t.replace('if (typeof expectations.jurisdiction_policy_pack_ref === "string"', "if (false && typeof expectations.jurisdiction_policy_pack_ref === \"string\""), offlineFindings);
  await mutate("OFFLINE — a wrong verdict passes", (t) => t.replace('if (typeof expectations.verdict === "string" && expectations.verdict !== str(record, "verdict")) {', "if (false) {"), offlineFindings);
  await mutate("OFFLINE — a case that does not recompute passes", (t) => t.replace("if (rootOf(record, CASE_MATERIAL) !== str(record, \"case_root\")) {", "if (false) {"), offlineFindings);
  await mutate("OFFLINE — a profile that does not recompute passes", (t) => t.replace("if (rootOf(profile, PROFILE_MATERIAL) !== str(profile, \"profile_root\")) {", "if (false) {"), offlineFindings);
  await mutate("OFFLINE — a case about a different profile passes", (t) => t.replace('if (str(record, "profile_ref") !== str(profile, "profile_id")) {', "if (false) {"), offlineFindings);
  await mutate("OFFLINE — the refusals are believed rather than re-derived", (t) => t.replace("if (shape(derived) !== shape(record?.refusals)) {", "if (false) {"), offlineFindings);
  await mutate("OFFLINE — the verdict is believed rather than re-derived", (t) => t.replace('if (verdictOf(derived) !== str(record, "verdict")) {', "if (false) {"), offlineFindings);

  console.log(`\n${caught}/${planted} planted defects caught`);
  evidence.mutation = { planted, caught };
  return caught === planted;
}

async function main() {
  let exit = 0;
  if (MODE === "mutation") {
    exit = (await mutation()) ? 0 : 1;
    const file = writeEvidence();
    console.log(`evidence: ${path.relative(ROOT, file)}`);
    process.exit(exit);
  }

  const { pure, offline, seam, src, binding } = await drills();
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} drills passed`);

  emitVerifierCensus({ verifierId: "regulated-workload-assurance", sourceUrl: import.meta.url, results });

  if (MODE === "drills") {
    const file = writeEvidence();
    console.log(`evidence: ${path.relative(ROOT, file)}`);
    process.exit(passed === results.length ? 0 : 1);
  }

  // ---- full: the plane leg --------------------------------------------------------------------
  const { planeLeg } = await import("./lib/regulated-workload-plane.mjs");
  let plane;
  try {
    plane = await planeLeg({ ROOT });
  } catch (error) {
    plane = { findings: [`plane leg threw: ${error.message}`], seconds: 0 };
  }
  evidence.plane = plane;
  const planeGreen = plane.findings.length === 0;
  console.log(`\n# PLANE — ${planeGreen ? "green" : plane.findings.join("; ")} in ${plane.seconds}s`);

  const red = (names) => names.some((n) => !results.find((r) => r.name.startsWith(n))?.pass);
  const rows = CLAUSES.map((clause) => {
    const row = { n: clause.n };
    const usesPlane = clause.executed_by.some((e) => e.script.startsWith("plane"));
    const selfRed = [];
    if (clause.executed_by.some((e) => e.script.startsWith("pure")) && pure.length) selfRed.push("PURE");
    if (clause.executed_by.some((e) => e.script.startsWith("offline")) && offline.length) selfRed.push("OFFLINE");
    if (clause.executed_by.some((e) => e.script.startsWith("seam")) && seam.length) selfRed.push("SEAM");
    if (clause.executed_by.some((e) => e.script.startsWith("source")) && src.length) selfRed.push("SOURCE");
    if (usesPlane && !planeGreen) selfRed.push("PLANE");
    if (selfRed.length) row.red = `${selfRed.join("+")} (this runner)`;
    if (clause.absence) row.absent = true;
    return row;
  });
  if (binding.length) rows.find((r) => r.n === 12).red = `BINDING: ${binding.join("; ")}`;
  void red;

  const result = verdict(rows);
  evidence.verdict = result;
  console.log(`\n=== VERDICT: ${result.kind.toUpperCase()}${result.failures.length ? ` — ${result.failures.join(" ; ")}` : ""}`);
  for (const absence of result.absences) console.log(`NAMED  clause ${absence.n}: ${absence.what}`);
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  exit = result.kind === "pass" ? 0 : result.kind === "named_failure" ? 2 : 1;
  process.exit(exit);
}

main().catch((error) => { console.error(error); writeEvidence(); process.exit(1); });
