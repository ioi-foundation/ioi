#!/usr/bin/env node
// check:jurisdiction-policy-audit-export — M06.10: jurisdiction-policy decisions and
// privacy-filtered audit export, as a gate
// (docs/architecture/foundations/ecosystem-assurance-certification-liability.md; ACC-18; R-228).
//
// CANON. A `JurisdictionPolicyPack` declares jurisdiction, eligibility, retention, regulated-action, tax
// and export obligations in a machine-readable shape, and COMPILES INTO OWNERS THAT ALREADY EXIST. A
// `ComplianceAuditExportBundle` is an export MANIFEST over evidence that already exists, for one named
// audience, and must make three things obvious: what was included, what was withheld AND WHY, and which
// refs support it. A replay or proof view must not bypass it.
//
// THE SENTENCE THIS UNIT EXISTS TO ENFORCE, which canon wrote and nothing checked: "Generated projections
// must always emit `legal_conformity_claim: not_determined`; no score, current deadline, attestation
// posture, submitted report, crypto-shredding receipt, certification, or policy-pack match is a legal
// determination." It is `const` on two contracts, so a legal verdict is UNREPRESENTABLE rather than
// merely detectable.
//
// AND THE LAW ONLY A PLANE CAN ENFORCE. Canon requires a NEW PACK VERSION for any change to a deadline,
// clock-start rule, recipient, responsible party or accountable issuer, and forbids rewriting an
// already-recorded decision. A schema can seal a pack with a root; only the daemon can compare that root
// against THE PACK THE ESTATE ADMITTED — so an in-place edit makes every decision taken under it
// unadmittable instead of silently reinterpreting what was decided.
//
//   PURE    — the deriver in apps/hypervisor/scripts/lib/jurisdiction-policy.mjs over the registered
//             fixtures: applicability, obligations and their enforcing owners, deadline inputs, the
//             export manifest, the offline verifier and the no-mutation rule.
//   OFFLINE — ACC-18's first clause, run the way a relying party must be able to: a bundle, that party's
//             OWN expectations, and nothing else. No daemon, no clock, no network.
//   SEAM    — the three registered contracts refuse at the wire: `const not_determined`, the closed
//             enforcing-owner and exclusion-reason sets, the sealed roots, and every fixture classified
//             at the layer that actually refuses it.
//   SOURCE  — the plane validates each registered contract at admission, resolves identity BEFORE the
//             record, and refuses a decision whose bound pack root is not the admitted pack's.
//   PLANE   — full mode, one isolated daemon: a pack admitted, a decision admitted against it, the pack
//             EDITED IN PLACE and the next decision refused, an export over an unadmitted decision
//             refused, and a cross-tenant read refused without an existence oracle.
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
import * as LIB from "../apps/hypervisor/scripts/lib/jurisdiction-policy.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "jurisdiction-policy.mjs");
const META = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const PLANE_SRC = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "jurisdiction_routes.rs");
const ROUTER = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor-daemon.rs");
const CANON = path.join(ROOT, "docs", "architecture", "foundations", "ecosystem-assurance-certification-liability.md");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : "full";
const OWNER_Q = "owner question, R-228";

const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const PURE = self("pure");
const OFFLINE = self("offline");
const SEAM = self("seam");
const SOURCE = self("source");
const PLANE = self("plane");
const RETENTION = { kind: "app", script: "check:learning-lineage-retention", workspace: APP, floor: "learning-lineage-retention", minutes: 20 };

export const CLAUSES = [
  { n: 1, demand: "THE PACK IS A REGISTERED SHAPE, not a paragraph: jurisdiction, eligibility, identity, authority, data, regulated-action, tax, audit, incident-reporting and erasure obligations each carry their canon member names, so an obligation is something the estate can refuse rather than something a reader has to interpret", executed_by: [SEAM, PURE] },
  { n: 2, demand: "A NEW VERSION, NEVER AN EDIT: the pack is sealed by a root, a decision binds THAT ROOT rather than the pack's name, and the PLANE refuses a decision whose bound root is not the admitted pack's — so changing a deadline in place makes every decision taken under it unadmittable instead of silently reinterpreting what was decided", executed_by: [SEAM, SOURCE, PLANE] },
  { n: 3, demand: "DEADLINE ARITHMETIC RETAINS ITS INPUTS: a decision keeps the EXACT pack version and the triggering timestamp, and names which of the four clock-start instants its window runs from — a window recomputed later against whatever the pack says by then is a different window", executed_by: [PURE, SEAM, PLANE] },
  { n: 4, demand: "THE PACK COMPILES INTO OWNERS THAT ALREADY EXIST: every obligation names its enforcer from the closed set canon lists, and the pack itself grants no authority — it names required scopes and issues none", executed_by: [PURE, SEAM] },
  { n: 5, demand: "TECHNICAL EVIDENCE IS NEVER A LEGAL DETERMINATION: `legal_conformity_claim` is `const not_determined` on both the decision and the export, so no score, deadline, attestation posture, report, receipt, certification or pack match can be expressed as a legal verdict — the refusal is unrepresentable, not merely detectable", executed_by: [SEAM, PURE, PLANE] },
  { n: 6, demand: "WHAT COULD NOT BE ESTABLISHED IS NAMED: missing law, contract, qualification, current evidence or processor reference is carried with its reason, and an obligation that was not evaluated or had no evidence is distinct from one that was found unsatisfied — collapsing them turns an absent evaluator into a clean bill", executed_by: [PURE, SEAM] },
  { n: 7, demand: "AN EXPORT IS FOR ONE NAMED AUDIENCE, from the closed set, because ACC-18's first clause is that the WRONG AUDIENCE fails offline and a bundle whose audience is implicit can only be checked by asking its author", executed_by: [SEAM, OFFLINE, PURE] },
  { n: 8, demand: "EXCLUSION IS TYPED AND NEVER SILENT: every withheld ref carries exactly one reason from the closed set, every reason names a ref the manifest actually excluded, and a generated export names the authority that supported it — an export that omits what it could not release is indistinguishable from one that had nothing to release", executed_by: [PURE, SEAM] },
  { n: 9, demand: "A PROTECTED PAYLOAD IS NAMED AND NEVER CARRIED, a redacted ref is not also an excluded one, and no replay or proof view bypasses the manifest — raw private payloads stay under storage, retention, restricted-view and authority policy", executed_by: [PURE, SEAM] },
  { n: 10, demand: "IT FAILS OFFLINE. A wrong audience, a moved policy revision, the wrong jurisdiction, subject, reviewer, redaction, retention or evidence hash is findable by a relying party holding the bundle and its OWN expectations — with no daemon, no clock and no network, because a check that has to ask something cannot be run by the party that most needs to run it", executed_by: [OFFLINE, PURE] },
  { n: 11, demand: "A REJECTED EVALUATION CANNOT MUTATE THE TARGET WORKFLOW: the decision reports and the owners act, so a record claiming it performs no action while the run rewrote a workflow, stopped a target, issued authority, released an export or rewrote a policy is caught by what HAPPENED rather than by what it says", executed_by: [PURE, PLANE] },
  { n: 12, demand: "THE TENANT LINE HOLDS: identity is resolved BEFORE the record is loaded so an unauthenticated caller is owed 401 and never an existence oracle, and a cross-tenant read answers the scope refusal rather than the record or a 404 that would leak whether it exists", executed_by: [SOURCE, PLANE], absence: { what: "THE COMPILATION INTO OWNERS IS NAMED, NOT DRIVEN. Canon's sentence is that a pack compiles into wallet.network identity/eligibility/step-up gates, daemon policy checks, Agentgres retention and export validity, marketplace listing restrictions and sas.xyz SLA/refund/bond obligations. This gate proves every obligation NAMES one of those owners from the closed set and that this plane enforces none of them itself — it does NOT drive those owners and prove the obligation actually reaches them, because wallet.network and Agentgres are separate estates this verifier does not stand up, and sas.xyz and the marketplace have no obligation-consuming surface at all. An obligation naming `wallet_network` is therefore a correctly-typed pointer whose far end is unproven here. AND ACC-18 HAS NO RUNNER: fourteen `check-acceptance-*` runners exist under `scripts/` and none of them is this journey's, so the proposal/review/effect/response reconstruction has no executable form anywhere on this tree. This gate is the executable artifact for the EXPORT clauses — a relying party holding the bundle catches each of ACC-18's eight mismatches offline, with no daemon, clock or network — and what is owed is the runner that would replay the workflow which produced the bundle, not the verification of its contents", owner: `each named owner's own plane, a cross-estate obligation conformance leg, and ACC-18's own runner (${OWNER_Q})` } },
];

// ---- infrastructure ----------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.jurisdiction-policy-audit-export-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], pure: null, offline: null, seam: null, source: null, plane: null, verdict: null, mutation: null };
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
  const file = path.join(dir, `jurisdiction-policy-audit-export-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readText = (p) => fs.readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256 = (s) => `sha256:${crypto.createHash("sha256").update(s).digest("hex")}`;
const fixture = (dir, name) => readJson(path.join(META, "fixtures", dir, name));

const PACK = () => fixture("jurisdiction-policy-pack-v1", "positive-eu-serious-incident.json");
const DECISION = () => fixture("jurisdiction-policy-decision-v1", "positive-applies-with-an-open-obligation.json");
const EXPORT = () => fixture("compliance-audit-export-bundle-v1", "positive-regulator-request.json");
const spoil = (record, mutate) => { const copy = JSON.parse(JSON.stringify(record)); mutate(copy); return copy; };

export function pureFindings(lib) {
  const f = [];
  const must = (what, findings, shouldBeEmpty) => {
    const empty = findings.length === 0;
    if (empty !== shouldBeEmpty) f.push(`${what}: ${shouldBeEmpty ? `refused a clean shape (${findings.slice(0, 2).join("; ")})` : "accepted a spoiled one"}`);
  };
  const pack = PACK();
  const decision = DECISION();
  const bundle = EXPORT();

  // -- applicability is derived from what the SUBJECT carries, never from its own say-so --
  const reached = lib.applicabilityOf(pack, { action_classes: ["high_risk_model_inference"], data_classes: [], service_classes: [] });
  if (!reached.applies || reached.matched_classes.length !== 1) f.push(`applicability: a subject carrying a declared action class did not match (${JSON.stringify(reached)})`);
  const missed = lib.applicabilityOf(pack, { action_classes: ["something_else"], data_classes: [], service_classes: [] });
  if (missed.applies) f.push("applicability: a subject carrying no declared class matched anyway");
  const claimed = lib.applicabilityOf(pack, { applies: true, action_classes: [], data_classes: [], service_classes: [] });
  if (claimed.applies) f.push("applicability: a subject that simply asserted it applies was believed");

  // -- the decision decides nothing --
  must("decision/clean", lib.decisionFindings(decision), true);
  must("decision/legal-verdict", lib.decisionFindings(spoil(decision, (d) => { d.legal_conformity_claim = "compliant"; })), false);
  must("decision/claims-authority", lib.decisionFindings(spoil(decision, (d) => { d.grants_no_authority = false; })), false);
  must("decision/performs-an-action", lib.decisionFindings(spoil(decision, (d) => { d.performs_no_action = false; })), false);
  must("decision/no-enforcing-owner", lib.decisionFindings(spoil(decision, (d) => { delete d.obligations[0].enforcing_owner; })), false);
  must("decision/invented-enforcer", lib.decisionFindings(spoil(decision, (d) => { d.obligations[0].enforcing_owner = "this_record"; })), false);
  must("decision/enforcer-with-no-ref", lib.decisionFindings(spoil(decision, (d) => { d.obligations[0].owner_ref = ""; })), false);
  must("decision/satisfied-citing-nothing", lib.decisionFindings(spoil(decision, (d) => { d.obligations[1].evidence_refs = []; })), false);
  must("decision/unseen-obligations-unnamed", lib.decisionFindings(spoil(decision, (d) => { d.unmet_evidence = []; })), false);

  // -- deadline arithmetic keeps its inputs --
  must("deadline/clean", lib.deadlineFindings(decision, spoil(pack, (p) => { p.pack_root = decision.pack_root; })), true);
  must("deadline/version-moved", lib.deadlineFindings(decision, spoil(pack, (p) => { p.pack_root = decision.pack_root; p.version = "2.0.0"; })), false);
  must("deadline/content-moved", lib.deadlineFindings(decision, pack), false);
  must("deadline/no-triggering-timestamp", lib.deadlineFindings(spoil(decision, (d) => { d.triggering_timestamp = null; }), spoil(pack, (p) => { p.pack_root = decision.pack_root; })), false);
  must("deadline/no-pack-root-bound", lib.deadlineFindings(spoil(decision, (d) => { d.pack_root = ""; }), spoil(pack, (p) => { p.pack_root = ""; })), false);
  // BY MESSAGE, because an invented basis over a pack whose root also differs trips TWO checks and the
  // case could not then isolate the one it is named for.
  const inventedBasis = lib.deadlineFindings(spoil(decision, (d) => { d.clock_start_basis = "whenever"; }), spoil(pack, (p) => { p.pack_root = decision.pack_root; }));
  must("deadline/invented-basis", inventedBasis, false);
  if (!inventedBasis.some((line) => /not one of the four instants/u.test(line))) {
    f.push("deadline/invented-basis: refused for some other reason than the basis being invented");
  }
  must("deadline/basis-the-pack-never-declares", lib.deadlineFindings(spoil(decision, (d) => { d.clock_start_basis = "confirmed_at"; }), spoil(pack, (p) => { p.pack_root = decision.pack_root; })), false);
  must("deadline/timestamp-with-no-basis", lib.deadlineFindings(spoil(decision, (d) => { d.clock_start_basis = null; }), pack), false);

  // -- the export makes three things obvious --
  must("export/clean", lib.exportFindings(bundle), true);
  must("export/invented-audience", lib.exportFindings(spoil(bundle, (e) => { e.audience = "whoever_asked"; })), false);
  must("export/legal-verdict", lib.exportFindings(spoil(bundle, (e) => { e.legal_conformity_claim = "compliant"; })), false);
  must("export/carries-plaintext", lib.exportFindings(spoil(bundle, (e) => { e.carries_no_protected_plaintext = false; })), false);
  must("export/bypasses-the-manifest", lib.exportFindings(spoil(bundle, (e) => { e.bypasses_no_export_manifest = false; })), false);
  must("export/withheld-with-no-reason", lib.exportFindings(spoil(bundle, (e) => { e.export_manifest.exclusion_reasons = []; })), false);
  must("export/untyped-reason", lib.exportFindings(spoil(bundle, (e) => { e.export_manifest.exclusion_reasons[0].reason = "no comment"; })), false);
  must("export/reason-for-a-ref-not-excluded", lib.exportFindings(spoil(bundle, (e) => { e.export_manifest.exclusion_reasons.push({ excluded_ref: "artifact://never-mentioned", reason: "unrelated" }); })), false);
  must("export/protected-payload-also-included", lib.exportFindings(spoil(bundle, (e) => { e.export_manifest.included_refs.push(e.export_manifest.protected_payload_refs[0]); })), false);
  must("export/redacted-and-excluded", lib.exportFindings(spoil(bundle, (e) => { e.export_manifest.excluded_refs.push(e.export_manifest.redacted_refs[0]); e.export_manifest.exclusion_reasons.push({ excluded_ref: e.export_manifest.redacted_refs[0], reason: "policy_blocked" }); })), false);
  must("export/generated-with-no-authority", lib.exportFindings(spoil(bundle, (e) => { e.authority_refs = []; })), false);

  // -- a rejected evaluation cannot mutate the target workflow --
  must("mutation/clean", lib.mutationFindings(decision, {}), true);
  // The record's own claim is checked even when the run observed nothing — otherwise a decision could
  // declare that it acts and the gate would only notice if the plane also caught it doing so.
  must("mutation/record-claims-it-acts", lib.mutationFindings(spoil(decision, (d) => { d.performs_no_action = false; }), {}), false);
  for (const effect of lib.FORBIDDEN_EFFECTS) {
    must(`mutation/${effect}`, lib.mutationFindings(decision, { [effect]: true }), false);
  }

  // -- the vocabularies are canon's --
  if (lib.ENFORCING_OWNERS.length !== 6) f.push("vocabulary: canon names six owners a pack compiles into");
  if (lib.CLOCK_STARTS.length !== 4) f.push("vocabulary: four clock-start instants");
  if (lib.EXCLUSION_REASONS.length !== 7) f.push("vocabulary: seven typed exclusion reasons");
  if (lib.AUDIENCES.length !== 8) f.push("vocabulary: eight audiences");
  if (lib.LEGAL_CONFORMITY_CLAIM !== "not_determined") f.push("vocabulary: the only admissible legal-conformity claim is not_determined");
  return f;
}

/**
 * ACC-18's FIRST CLAUSE, run the way a relying party must be able to run it. Each case is one thing the
 * exporter could have got wrong, and each must be findable from the bundle and the party's own
 * expectations alone.
 */
export function offlineFindings(lib) {
  const f = [];
  const bundle = EXPORT();
  const decision = DECISION();
  const expected = {
    audience: "regulator",
    subject_ref: "run://ioi/inference/1",
    pack_ref: "jurisdiction_policy_pack://eu/ai-act/serious-incident/v1",
    pack_version: "1.0.0",
    decision,
    reviewer_ref: "grant://ioi/export/regulator/1",
    redaction_profile_ref: "policy://ioi/redaction/regulator",
    retention_lock_ref: "retention_lock://ioi/eu/1",
    export_root: bundle.export_root,
  };
  const clean = lib.offlineFindings(bundle, expected);
  if (clean.length) f.push(`offline/clean: a correct bundle was refused (${clean.slice(0, 2).join("; ")})`);

  // EVERY ONE OF ACC-18's EIGHT, each on its own so the failing one is named.
  const cases = [
    ["WRONG AUDIENCE", { audience: "public" }],
    ["WRONG SUBJECT", { subject_ref: "run://somebody/else" }],
    ["WRONG JURISDICTION", { pack_ref: "jurisdiction_policy_pack://us/other/v1" }],
    ["POLICY REVISION MOVED", { pack_version: "2.0.0" }],
    ["WRONG REVIEWER", { reviewer_ref: "grant://somebody/else" }],
    ["WRONG REDACTION", { redaction_profile_ref: "policy://ioi/redaction/public" }],
    ["RETENTION", { retention_lock_ref: "retention_lock://somebody/else" }],
    ["EVIDENCE HASH", { export_root: `sha256:${"9".repeat(64)}` }],
  ];
  for (const [label, override] of cases) {
    const found = lib.offlineFindings(bundle, { ...expected, ...override });
    if (!found.length) { f.push(`offline/${label}: was not caught`); continue; }
    if (!found.some((line) => line.includes(label))) f.push(`offline/${label}: caught, but the finding does not name it (${found[0]})`);
    if (found.length !== 1) f.push(`offline/${label}: ${found.length} findings for one spoiled expectation, so the case cannot isolate its own check`);
  }
  // A relying party that states nothing cannot be satisfied by anything.
  if (!lib.offlineFindings(bundle, {}).length) f.push("offline: an empty expectation passed, so a bundle could satisfy a party that asked for nothing");
  if (!lib.offlineFindings(bundle, null).length) f.push("offline: a relying party that stated nothing at all was satisfied");
  if (!lib.offlineFindings(bundle, { ...expected, export_root: "not-a-hash" }).length) f.push("offline: an expectation whose hash could never match was not called out");
  return f;
}

// ---- the seam ---------------------------------------------------------------------------------------------
export function seamFindings({ registry, schemas, invariants }) {
  const f = [];
  const ids = {
    pack: "schema://ioi/foundations/jurisdiction-policy-pack/v1",
    decision: "schema://ioi/foundations/jurisdiction-policy-decision/v1",
    export: "schema://ioi/foundations/compliance-audit-export-bundle/v1",
  };
  for (const [name, id] of Object.entries(ids)) {
    const entry = registry.contracts.find((c) => c.contract_id === id);
    if (!entry) { f.push(`${name}: not registered`); continue; }
    if (LIB.CONTRACTS[name] !== id) f.push(`${name}: the deriver names a different contract id than the registry`);
    if (!entry.positive_fixture_refs?.length) f.push(`${name}: no positive fixture`);
    if (!entry.negative_fixture_refs?.length) f.push(`${name}: no negative fixture`);
    // EVERY MATERIAL MEMBER IS REQUIRED — the class that cost M10.9 a red golden-oracle run, because the
    // generator emits skip_serializing_if for an optional one and the round-trip then drops it.
    const root = invariants[name].rules.find((r) => r.expression?.operator === "jcs_sha256_equals");
    if (!root) { f.push(`${name}: no root rule, so the record is not sealed`); continue; }
    for (const descriptor of Object.values(root.expression.material_fields ?? {})) {
      const member = String(descriptor.path).replace(/^\$\./u, "").split(".")[0];
      if (!schemas[name].required?.includes(member)) f.push(`${name}: ${member} is material to the root but not required, so the projection drops it`);
    }
  }
  // THE WORD, PINNED. A legal verdict must be unrepresentable, not merely detectable.
  for (const name of ["decision", "export"]) {
    if (schemas[name].properties?.legal_conformity_claim?.const !== "not_determined") {
      f.push(`${name}: legal_conformity_claim is not pinned to not_determined on the wire`);
    }
  }
  // the closed sets are canon's
  const owners = schemas.decision.properties?.obligations?.items?.properties?.enforcing_owner?.enum ?? [];
  if (owners.length !== LIB.ENFORCING_OWNERS.length || !LIB.ENFORCING_OWNERS.every((o) => owners.includes(o))) {
    f.push("decision: the wire's enforcing owners are not the ones canon names a pack compiles into");
  }
  const reasons = schemas.export.properties?.export_manifest?.properties?.exclusion_reasons?.items?.properties?.reason?.enum ?? [];
  if (reasons.length !== LIB.EXCLUSION_REASONS.length) f.push("export: the wire's exclusion reasons are not canon's closed set");
  const audiences = schemas.export.properties?.audience?.enum ?? [];
  if (audiences.length !== LIB.AUDIENCES.length) f.push("export: the wire's audiences are not canon's closed set");
  const clocks = schemas.pack.properties?.incident_reporting?.properties?.deadlines?.items?.properties?.clock_start?.enum ?? [];
  if (clocks.length !== LIB.CLOCK_STARTS.length) f.push("pack: the wire's clock-start instants are not canon's four");
  // the never-clauses
  for (const [name, clause] of [["pack", "grants_no_authority"], ["pack", "is_not_legal_advice"], ["decision", "grants_no_authority"], ["decision", "performs_no_action"], ["export", "carries_no_protected_plaintext"], ["export", "bypasses_no_export_manifest"]]) {
    if (schemas[name].properties?.[clause]?.const !== true) f.push(`${name}: ${clause} is not pinned on the wire`);
  }
  // a pack must reach something, and only an invariant can say it
  if (!invariants.pack.rules.some((r) => r.expression?.operator === "any_non_empty")) {
    f.push("pack: nothing requires a pack to reach any class, so a pack that constrains nothing is admissible");
  }
  return f;
}

// ---- source ---------------------------------------------------------------------------------------------------
export function sourceFindings({ plane, router, canon, lib }) {
  const f = [];
  const code = LIB.codeOnly(plane);
  // the plane validates each registered contract at admission
  for (const contract of Object.values(LIB.CONTRACTS)) {
    if (!code.includes(contract)) f.push(`the plane does not name ${contract}, so that record is admitted unvalidated`);
  }
  if (!/validate_architecture_contract\(contract, body\)/u.test(code)) f.push("the plane does not validate the registered contract at admission");
  // THE REFUSAL ONLY A PLANE CAN MAKE
  if (!/pack_content_moved/u.test(code)) f.push("the plane does not refuse a decision whose bound pack root is not the admitted pack's");
  if (!/pack_version_moved/u.test(code)) f.push("the plane does not refuse a decision taken under a version the admitted pack no longer carries");
  if (!/pack_unadmitted/u.test(code)) f.push("the plane admits a decision against a pack nobody holds");
  if (!/decision_unadmitted/u.test(code)) f.push("the plane admits an export over a decision nobody holds");
  if (!/already_admitted/u.test(code)) f.push("the plane lets a record be re-admitted at the same id, so an edit can pass as a version");
  // identity precedes the record
  const authorized = code.slice(code.indexOf("fn authorized("), code.indexOf("fn admit("));
  if (authorized.indexOf("resolve_request_identity") > authorized.indexOf("load(")) {
    f.push("the plane loads the record before resolving identity, so an unauthenticated caller gets an existence oracle");
  }
  if (!/authorizes_tenant/u.test(code)) f.push("the plane does not scope reads to the caller's tenant");
  // the routes exist
  for (const route of ["/v1/hypervisor/jurisdiction-policy-packs", "/v1/hypervisor/jurisdiction-policy-decisions", "/v1/hypervisor/compliance-audit-exports"]) {
    if (!router.includes(`"${route}"`)) f.push(`the router registers no ${route}`);
  }
  // canon's binding
  if (!/legal_conformity_claim: not_determined/u.test(canon)) f.push("canon no longer states the not_determined rule this unit enforces");
  if (!/not legal advice/iu.test(canon)) f.push("canon no longer states that a pack is not legal advice");
  // the deriver stays pure — the offline verifier must reach NOTHING
  const libCode = LIB.codeOnly(lib);
  if (/fetch\(|require\(|readFileSync|Date\.now\(|new Date\(/u.test(libCode)) {
    f.push("the deriver reaches a plane, a file or a clock, so its offline verifier is not offline");
  }
  return f;
}

export function sourceInputs() {
  return { plane: readText(PLANE_SRC), router: readText(ROUTER), canon: readText(CANON), lib: readText(LIB_PATH) };
}

// ---- the binding --------------------------------------------------------------------------------------------
export function bindingFindings({ rootPkg, appPkg, floors, ci, floorsGate }) {
  const f = [];
  for (const script of ["check:jurisdiction-policy-audit-export", "mutate:jurisdiction-policy-audit-export"]) {
    if (!rootPkg.scripts?.[script]) f.push(`root_script_missing:${script}`);
  }
  if (!appPkg.scripts?.["check:jurisdiction-policy-audit-export"]) f.push("app_drills_script_missing");
  const rows = floors.verifiers ?? [];
  const named = (id) => rows.find((r) => r.id === id);
  for (const id of ["jurisdiction-policy-audit-export", "learning-lineage-retention"]) {
    const row = named(id);
    if (!row) f.push(`floor_row_missing:${id}`);
    else if (!(Number.isInteger(row.runtime_assertions) && row.runtime_assertions > 0)) f.push(`floor_row_without_a_floor:${id}`);
    else if (!/^[0-9a-f]{64}$/u.test(row.assertion_names_sha256 ?? "")) f.push(`floor_row_without_a_name_digest:${id}`);
    else if (!fs.existsSync(path.resolve(ROOT, row.source))) f.push(`floor_row_source_missing:${id}`);
  }
  // CI-BOUND MEANS WHAT THE FLOORS GATE MEANS BY IT (R-225).
  if (!/check:jurisdiction-policy-audit-export --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("gate_not_ci_bound_in_the_hypervisor_workspace");
  if (!/mutate:jurisdiction-policy-audit-export --workspace=@ioi\/hypervisor-app/u.test(ci)) f.push("battery_not_ci_bound");
  if (!floorsGate.includes("check-jurisdiction-policy-audit-export")) {
    f.push("floors_gate_does_not_recognise_this_verifier: the floor would gate nothing and check:verifier-floors goes red");
  }
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
  ok("PURE — applicability comes from what the SUBJECT carries and never from its own claim; the decision grants nothing, performs nothing and cannot express a legal verdict; deadline arithmetic keeps its exact version, root and triggering timestamp; the export names one audience, reasons every exclusion, never carries a protected payload and never bypasses its own manifest; and a rejected evaluation mutates nothing", pure.length === 0, pure.slice(0, 4).join(" ; "));

  const offline = offlineFindings(LIB);
  evidence.offline = { findings: offline };
  ok("OFFLINE — ACC-18's eight, each caught ON ITS OWN by a relying party holding the bundle and its own expectations: wrong audience, subject, jurisdiction, reviewer, redaction and retention, a moved policy revision, and an evidence hash that is not the bundle that was generated — with no daemon, no clock and no network", offline.length === 0, offline.slice(0, 4).join(" ; "));

  const seam = seamFindings({
    registry: readJson(path.join(META, "architecture-contract-registry.v1.json")),
    schemas: {
      pack: readJson(path.join(META, "jurisdiction-policy-pack.v1.schema.json")),
      decision: readJson(path.join(META, "jurisdiction-policy-decision.v1.schema.json")),
      export: readJson(path.join(META, "compliance-audit-export-bundle.v1.schema.json")),
    },
    invariants: {
      pack: readJson(path.join(META, "invariants", "jurisdiction-policy-pack.v1.invariants.json")),
      decision: readJson(path.join(META, "invariants", "jurisdiction-policy-decision.v1.invariants.json")),
      export: readJson(path.join(META, "invariants", "compliance-audit-export-bundle.v1.invariants.json")),
    },
  });
  evidence.seam = { findings: seam };
  ok("SEAM — three registered contracts carry the law on the wire: `legal_conformity_claim` pinned to not_determined so a legal verdict is UNREPRESENTABLE, canon's closed sets for enforcing owners, exclusion reasons, audiences and clock-start instants, six never-clauses as consts, every material member required so the projection cannot drop it, and a pack that reaches nothing refused by the one rule that can say so", seam.length === 0, seam.slice(0, 4).join(" ; "));

  const src = sourceFindings(sourceInputs());
  evidence.source = { findings: src };
  ok("SOURCE — the plane validates each registered contract at admission, refuses a decision whose bound pack root or version is not the admitted pack's, refuses a decision or export over records nobody holds, resolves identity BEFORE loading the record, scopes every read to the caller's tenant — and the deriver reaches no plane, file or clock, so its offline verifier is genuinely offline", src.length === 0, src.slice(0, 4).join(" ; "));

  const binding = bindingFindings({
    rootPkg: readJson(path.join(ROOT, "package.json")),
    appPkg: readJson(path.join(APP_DIR, "package.json")),
    floors: readJson(FLOORS),
    ci: fs.readdirSync(path.join(ROOT, ".github", "workflows")).map((file) => readText(path.join(ROOT, ".github", "workflows", file))).join("\n"),
    floorsGate: readText(path.join(APP_DIR, "scripts", "check-verifier-floors.mjs")),
  });
  ok("BINDING — the gate is floored with an existing source, CI-bound in the form the FLOORS GATE recognises rather than by its bare name, and every clause is executed or named with an owner", binding.length === 0, binding.slice(0, 4).join(" ; "));

  const v = verdict([{ n: 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] }]);
  ok("VERDICT — a table missing eleven of its twelve rows is a FAIL, not a pass", v.kind === "fail" && v.failures.includes("row_missing:12"), v.failures.slice(0, 2).join(" ; "));
  const full = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }] })));
  ok("VERDICT — twelve green rows with no absence is a PASS", full.kind === "pass", full.failures.slice(0, 2).join(" ; "));
  const named = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s" }], absence: i === 11 ? { what: "a named absence long enough to be real", owner: "someone" } : null })));
  ok("VERDICT — one named absence is a NAMED FAILURE, never a pass", named.kind === "named_failure" && named.absences.length === 1, named.kind);
  const unevidenced = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0 }] })));
  ok("VERDICT — a gate that reports success without evidence is fabricated, not green", unevidenced.kind === "fail" && unevidenced.failures.every((x) => x.includes("fabricated")), unevidenced.failures[0]);
  const belowFloor = verdict([...Array(12)].map((_, i) => ({ n: i + 1, executed: [{ script: "x", status: 0, evidence: {}, evidence_sha256: "s", floor_expected: 9, executed_assertions: 2 }] })));
  ok("VERDICT — a gate below its floor fails even at exit 0", belowFloor.kind === "fail" && belowFloor.failures.every((x) => x.includes("below_floor")), belowFloor.failures[0]);
}

// ---- mutation -------------------------------------------------------------------------------------------------
async function mutation() {
  const original = readText(LIB_PATH);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jurisdiction-policy-mutation-"));
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

  await mutate("LEGAL VERDICT — a decision may determine a question of law", (t) => t.replace('if (str(decision, "legal_conformity_claim") !== LEGAL_CONFORMITY_CLAIM) {', "if (false) {"));
  await mutate("LEGAL VERDICT — the only admissible claim becomes anything", (t) => t.replace('export const LEGAL_CONFORMITY_CLAIM = "not_determined";', 'export const LEGAL_CONFORMITY_CLAIM = "";'));
  await mutate("LEGAL VERDICT — an export may determine one", (t) => t.replace('if (str(bundle, "legal_conformity_claim") !== LEGAL_CONFORMITY_CLAIM) {', "if (false) {"));
  await mutate("AUTHORITY — a decision may claim it", (t) => t.replace("if (decision.grants_no_authority !== true) findings.push(`${where}: the decision claims authority`);", ""));
  await mutate("ACTION — a decision may perform one", (t) => t.replace("if (decision.performs_no_action !== true) findings.push(`${where}: the decision claims to perform an action`);", ""));
  await mutate("OWNER — an obligation needs no enforcer", (t) => t.replace("    if (!owner) { findings.push(`${where}: ${kind} names no enforcing owner, so the decision is asserting an obligation of its own`); continue; }", "    if (!owner) { continue; }"));
  await mutate("OWNER — any enforcer will do", (t) => t.replace("    if (!ENFORCING_OWNERS.includes(owner)) {", "    if (false) {"));
  await mutate("OWNER — an enforcer needs no ref to reach it by", (t) => t.replace('if (!str(obligation, "owner_ref")) findings.push(`${where}: ${kind} names an enforcing owner with no ref to reach it by`);', ""));
  await mutate("EVIDENCE — satisfied may cite nothing", (t) => t.replace('if (str(obligation, "status") === "satisfied" && !list(obligation, "evidence_refs").length) {', "if (false) {"));
  await mutate("EVIDENCE — an absent evaluator reads as a clean bill", (t) => t.replace("  if (unseen.length && !list(decision, \"unmet_evidence\").length) {", "  if (false) {"));
  await mutate("VERSION — the exact pack version need not be retained", (t) => t.replace('if (str(decision, "pack_version") !== str(pack, "version")) {', "if (false) {"));
  await mutate("ROOT — a decision may be read against content it never saw", (t) => t.replace('else if (str(decision, "pack_root") !== str(pack, "pack_root")) {', "else if (false) {"));
  await mutate("ROOT — a decision need bind no pack root at all", (t) => t.replace('if (!SHA256.test(str(decision, "pack_root"))) findings.push(`${where}: the decision binds no pack root, so an in-place edit would be invisible to it`);', ""));
  await mutate("TIMESTAMP — a window need not keep the instant it runs from", (t) => t.replace("  if (!decision?.triggering_timestamp) {\n    findings.push(`${where}: the window runs from ${basis} and the decision did not keep the instant itself, so it cannot be recomputed`);\n  }", "  if (false) { /* planted */ }"));
  await mutate("BASIS — an invented clock start is accepted", (t) => t.replace("  if (!CLOCK_STARTS.includes(basis)) {", "  if (false) {"));
  await mutate("BASIS — a window may run from an instant the pack never declares", (t) => t.replace("  if (declared.length && !declared.includes(basis)) {", "  if (false) {"));
  await mutate("AUDIENCE — any audience is admissible", (t) => t.replace('if (!AUDIENCES.includes(str(bundle, "audience"))) {', "if (false) {"));
  await mutate("EXCLUSION — a withheld ref need not say why", (t) => t.replace("    if (!reasons.has(ref)) findings.push(`${where}: ${ref} was withheld and the bundle does not say why`);", ""));
  await mutate("EXCLUSION — an untyped reason is accepted", (t) => t.replace("    else if (!EXCLUSION_REASONS.includes(reasons.get(ref))) findings.push(`${where}: ${ref} was withheld for ${reasons.get(ref)}, which is not a typed reason`);", ""));
  await mutate("EXCLUSION — a reason may name a ref that was not excluded", (t) => t.replace("    if (!excluded.includes(ref)) findings.push(`${where}: a reason is given for ${ref}, which the manifest does not list as excluded`);", ""));
  await mutate("PLAINTEXT — a protected payload may also be included", (t) => t.replace("    if (list(manifest, \"included_refs\").includes(ref)) {", "    if (false) {"));
  await mutate("PLAINTEXT — the bundle may carry it", (t) => t.replace("if (bundle.carries_no_protected_plaintext !== true) findings.push(`${where}: the bundle carries protected plaintext`);", ""));
  await mutate("MANIFEST — a replay may bypass it", (t) => t.replace("if (bundle.bypasses_no_export_manifest !== true) findings.push(`${where}: the bundle offers a way around its own manifest`);", ""));
  await mutate("MANIFEST — redacted and excluded are the same fate", (t) => t.replace("    if (excluded.includes(ref)) findings.push(`${where}: ${ref} is reported both redacted and excluded, which are different fates`);", ""));
  await mutate("AUTHORITY — a generated export needs none behind it", (t) => t.replace('if (["generated", "delivered"].includes(str(bundle, "status")) && !list(bundle, "authority_refs").length) {', "if (false) {"));
  await mutate("APPLICABILITY — a subject's own claim is believed", (t) => t.replace("  return { applies: matched.length > 0, matched_classes: matched };", "  return { applies: matched.length > 0 || subject?.applies === true, matched_classes: matched };"));
  await mutate("MUTATION — a rejected evaluation may change the workflow", (t) => t.replace("    if (observed[effect] === true) {", "    if (false) {"));
  await mutate("MUTATION — the record's own claim is enough", (t) => t.replace("if (decision && decision.performs_no_action !== true) findings.push(`${where}: the decision record claims to act`);", ""));

  // The offline verifier is scored by its own drill, because a mutation there is invisible to pureFindings.
  const offlineScore = (mod) => offlineFindings(mod);
  await mutate("OFFLINE — a wrong audience passes", (t) => t.replace("  if (expected.audience && str(bundle, \"audience\") !== expected.audience) {", "  if (false) {"), offlineScore);
  await mutate("OFFLINE — a moved evidence hash passes", (t) => t.replace('if (expected.export_root && str(bundle, "export_root") !== expected.export_root) {', "if (false) {"), offlineScore);
  await mutate("OFFLINE — a wrong reviewer passes", (t) => t.replace("  if (expected.reviewer_ref && !list(bundle, \"authority_refs\").includes(expected.reviewer_ref)) {", "  if (false) {"), offlineScore);
  await mutate("OFFLINE — a moved policy revision passes", (t) => t.replace('if (expected.pack_version && expected.decision && str(expected.decision, "pack_version") !== expected.pack_version) {', "if (false) {"), offlineScore);
  await mutate("OFFLINE — an empty expectation is satisfied by anything", (t) => t.replace("  if (!stated.length) {", "  if (false) {"), offlineScore);
  await mutate("OFFLINE — a non-object expectation is satisfied by anything", (t) => t.replace('if (!expected || typeof expected !== "object") return [`${where}: the relying party stated no expectation, so nothing can fail`];', 'if (!expected || typeof expected !== "object") return [];'), offlineScore);

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
    emitVerifierCensus({ verifierId: "jurisdiction-policy-audit-export", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") {
      const { planeLeg } = await import("./lib/jurisdiction-policy-plane.mjs");
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
