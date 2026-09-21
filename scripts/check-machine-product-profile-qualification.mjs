#!/usr/bin/env node
// check:machine-product-profile-qualification — M12.15: the Workstation and attached-Infrastructure profile
// qualification, as a gate (docs/architecture/components/hypervisor/providers-and-environments.md § Machine-control
// contract family; core-clients-surfaces.md § the bundles; _meta/public-web-estate.md § Subject-specific compute
// claims; byo-provider-plane.md § Attached-estate claim journey; register R-216, executing R-121, R-139 and R-215).
//
// CANON. Every Workstation or attached-Infrastructure statement binds one subject-specific claim, the exact
// release/profile/backend matrix and fresh evidence, closable and withdrawable on its own; evidence for one
// subject never closes another; simulated-only evidence may validate the contract and never qualify a public host
// or attached-estate matrix; a VM boot, a hostile-guest test, a binary, an image, a dashboard, a declaration or an
// autonomy proof is not qualification.
//
// WHAT THIS RUNNER IS. Two certificates — `workstation_hosted_v1` and `infrastructure_attached_v1` — are
// GENERATED at run time from a tracked, hash-committed record set minted from a real isolated run of the machine
// plane against the two simulated reference backends, and verified offline. On this tree both read
// `qualification: not_qualified` with `evidence_basis: simulated` and their typed reasons: that is the truthful
// output, never a lesser positive, and the gate goes RED if either ever reads higher than its evidence. The
// positive hosted and attached crossings are SCHEDULED by name. The acceptance's demands are CLAUSES, each
// EXECUTED by one of this runner's legs, by a floored gate, or NAMED (typed failure with an owner) or SCHEDULED
// (prerequisite + ruling). The runner's own legs:
//   CONTRACT   — the certificate contract is registered (schema, invariant, fixtures); every positive fixture
//                validates and every negative fixture is refused for its declared cause; the schema refuses
//                `qualified` on any basis but live.
//   PROFILES   — the two profile matrices (canon's verbs and the bundles' resource relationships) pinned by digest.
//   GENERATION — the tracked record set's rows re-hash to the committed set hash; both certificates are assembled
//                from it, regenerate their attested hashes byte for byte, and read not_qualified/simulated with
//                the reasons the evidence carries.
//   VERIFY     — the offline verifier accepts both; the two are independent (distinct backends, declarations and
//                receipts; each disclaims the other); the attached certificate claims no VMM ownership.
//   REFUSALS   — every artifact kind canon refuses is refused by kind and never enters the runs; the other
//                profile's declaration is refused as cross-profile evidence; a declared-mode declaration reads
//                declared; a certificate relabelled qualified is refused by schema and verifier; a declaration
//                whose bytes moved under an unchanged carried hash is caught; a missing delivery form is named.
//   FRESHNESS  — an expired certificate withdraws with its reason and still verifies as withdrawn; a daemon
//                other than the one that ran withdraws it; withdrawal only ever moves down.
//   RUN        — full mode: the same records minted afresh in this runner's own isolated plane (both reference
//                declarations planted, the App as the integrated form and the daemon's API as the thin client),
//                the two certificates generated from THAT run and verified, with the same downgrade.
// Nothing is read back and called verified; the verdict is a pure function of the clause rows.
//
//   --drills            CI-bound, seconds: BINDING, CONTRACT, PROFILES, GENERATION, VERIFY, REFUSALS, FRESHNESS,
//                       VERDICT, CANON. No daemon.
//   --mutation          planted defects against the drills' oracles — each must go red.
//   --mint-records <p>  full-mode RUN only, writing the record set to <p> with both attested certificate hashes.
//   (default)           the full gate: the drills, RUN, then every composed gate inside the isolated-egress
//                       harness. Exit 0 pass, 2 named failure, 1 fail. Spend-free by construction.
//   --evidence <path>   also write the evidence there.

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";
import * as Q from "../apps/hypervisor/scripts/lib/machine-profile-qualification.mjs";
import { MACHINES_API, MACHINES_ROUTE, MACHINE_LANE_PATH, projectMachineSpine, spineFromRenderedDetail, spineParity } from "../apps/hypervisor/scripts/lib/machine-product-composition.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP_DIR = path.join(ROOT, "apps", "hypervisor");
const APP = "@ioi/hypervisor-app";
const FLOORS = path.join(APP_DIR, "verifier-floors.v1.json");
const SCHEMAS = path.join(ROOT, "docs", "architecture", "_meta", "schemas");
const REGISTRY = path.join(SCHEMAS, "architecture-contract-registry.v1.json");
const SCHEMA_FILE = path.join(SCHEMAS, "hypervisor-machine-profile-qualification-certificate.v1.schema.json");
const RECORD_SET = path.join(ROOT, "docs", "architecture", "_meta", "evidence", "m12-15-machine-reference-runs-2026-09-20.v1.json");
const LIB_PATH = path.join(APP_DIR, "scripts", "lib", "machine-profile-qualification.mjs");
const CANON_PE = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "providers-and-environments.md");
const CANON_SURFACES = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "core-clients-surfaces.md");
const CANON_WEB = path.join(ROOT, "docs", "architecture", "_meta", "public-web-estate.md");
const CANON_BYO = path.join(ROOT, "docs", "architecture", "components", "hypervisor", "byo-provider-plane.md");
const SERVE = path.join(APP_DIR, "scripts", "serve-product-ui.mjs");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--drills") ? "drills" : flag("--mint-records") ? "mint" : "full";
const GENESIS = `sha256:${"0".repeat(64)}`;
const HASH = /^sha256:[0-9a-f]{64}$/u;
const SET_SCHEMA = "ioi.evidence.m12-15-machine-reference-runs.v1";
const ISSUER = { verifier_identity_ref: "verifier://ioi/check-machine-product-profile-qualification/v1", verifier_build_hash: null };
const OWNER_Q = "owner question, R-216";
const HOSTED_PREREQ = "an ordinary-OS backend registered against the MACHINE plane with a `live` capability declaration on this host's KVM — the environment plane's microVM provider is a different object and does not count — driven through this gate (IOI_ACC20_SOAK_EVIDENCE with hosted-backend-evidence.json)";
const ATTACHED_PREREQ = "an independently implemented attached-estate backend registered against the machine family with a `live` declaration (IOI_ACC20_SOAK_EVIDENCE with attached-backend-evidence.json), attachment beginning read-only and mutation as a separate graduation (byo-provider-plane.md § Attached-estate claim journey)";
const SCHED_RULING = "the journey's own text (simulated-only evidence may validate the contract and never qualify a public host or attached-estate matrix), R-121 (the two profiles qualify independently), R-139 (2026-09-14) and R-216 (2026-09-20): a missing backend or host blocks a RUN, never the unit — the certificates read not_qualified until the live crossing";

const gate = (script, floor, minutes) => ({ kind: "app", script, workspace: APP, floor, minutes });
const rootGate = (script, minutes, undrilled) => ({ kind: "root", script, minutes, undrilled });
const CONFORMANCE = rootGate("check:machine-lifecycle-backend-conformance", 15, "M09.11's own gate; its drill battery is M09.11's to author (named in its module record)");
const COMPOSITION = gate("check:machine-product-composition", "machine-product-composition", 20);
const ZERO_TO_OPERABLE = gate("check:zero-to-operable", "zero-to-operable", 20);
const self = (name) => ({ kind: "self", script: `${name} (this runner)` });
const CONTRACT = self("contract");
const PROFILES = self("profiles");
const GENERATION = self("generation");
const VERIFY = self("verify");
const REFUSALS = self("refusals");
const FRESHNESS = self("freshness");
const RUN = self("run");

export const CLAUSES = [
  { n: 1, demand: "contracts precede claims: the profile qualification certificate is a registered contract with an invariant and fixtures; the schema itself refuses `qualified` on any basis but live and refuses an attached certificate that claims VMM ownership", executed_by: [CONTRACT] },
  { n: 2, demand: "the matrix is consulted, not assumed: unsupported, drifted, stale and replayed cells refuse before effect with the declaration's own reason; a non-simulated backend is admitted and never executed by the reference executor", executed_by: [CONFORMANCE] },
  { n: 3, demand: "both delivery forms render the same truth over the lifecycle the certificate binds: the integrated form and the thin client agree member for member, and the certificate carries each form's evidence by hash", executed_by: [COMPOSITION, GENERATION, RUN] },
  { n: 4, demand: "the release identity the daemon ran under is bound — source commit, daemon binary digest, and the packaged release manifest when there is one — and an unbound release is a named reason, never an omission", executed_by: [GENERATION, ZERO_TO_OPERABLE], absence: { what: "no packaged release is built from this tree: the certificates bind the source commit and the daemon binary digest and carry `release_unbound`; binding a signed release manifest and its signer key needs M12.2's packaged journey on this tree (the owed differing-daemon run)", owner: "M12.2's scheduled release qualification (R-206)" } },
  { n: 5, demand: "the workstation_hosted_v1 certificate is generated from the tracked record set, regenerates its attested hash byte for byte, reads not_qualified with evidence_basis simulated and its typed reasons, and verifies offline", executed_by: [GENERATION, VERIFY] },
  { n: 6, demand: "the infrastructure_attached_v1 certificate likewise, with vmm_ownership_claimed false as a constant and the attached estate's console withheld by the declaration's own reason", executed_by: [GENERATION, VERIFY] },
  { n: 7, demand: "the two certificates are independent: distinct backends, declarations and receipts; each names the other among what it does not qualify; a certificate assembled from the other profile's declaration is refused as cross-profile evidence", executed_by: [VERIFY, REFUSALS] },
  { n: 8, demand: "a VM boot, a hostile-guest test, a downloadable binary, a bootable image, a generated dashboard, a backend declaration, an autonomy proof, provider-portability or packaging evidence and simulated-only runs presented as host compatibility are refused by kind and never enter the evidence runs; a certificate relabelled qualified on a simulated basis is refused by schema and verifier", executed_by: [REFUSALS, CONTRACT] },
  { n: 9, demand: "freshness and drift withdraw: an expired certificate withdraws with its reason and verifies as withdrawn; a declaration whose bytes moved under an unchanged carried hash withdraws; a daemon other than the one that ran withdraws; withdrawal only ever moves down", executed_by: [FRESHNESS, REFUSALS] },
  { n: 10, demand: "the hosted Workstation POSITIVE crossing: a live ordinary-OS backend on this host's KVM registered against the machine plane, its declaration `live`, the sixteen-verb matrix exercised through both delivery forms, the certificate reading qualified", executed_by: [], scheduled: { what: "the hosted positive crossing through this gate (--soak evidence validated by the same verifier)", prerequisite: HOSTED_PREREQ, ruling: SCHED_RULING } },
  { n: 11, demand: "the attached-Infrastructure POSITIVE crossing: an independently implemented attached-estate backend, discovery, desired/observed reconciliation, lifecycle, failure and recovery, without claiming Hypervisor is the estate's VMM, the certificate reading qualified", executed_by: [], scheduled: { what: "the attached positive crossing through this gate (--soak evidence validated by the same verifier)", prerequisite: ATTACHED_PREREQ, ruling: SCHED_RULING } },
  { n: 12, demand: "an issuer and a withdrawal authority, a backend registration route, a declaration contract with observed_at/valid_until and guest profiles, and a per-profile verifier_profile_ref on the daemon's receipts", executed_by: [], absence: { what: "the certificate is issued by this verifier under no key and withdrawn by rule (expiry, drift, release), not by an owner's receipted act; declarations are planted records (no registration route); the registered declaration contract carries two opaque currentness refs and no timestamps or guest members, so freshness is derived from the runs' submission times and the guest matrix is declared empty; the daemon stamps every receipt `verifier-profile://hypervisor/machine-admission/v1`, so evidence is selected by backend registration and declaration, never by profile", owner: `the issuer/withdrawal authority (${OWNER_Q}) · M09.11 (registration route, the declaration contract's successor, the receipts' profile ref)` } },
];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.machine-product-profile-qualification-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], contract: null, profiles: null, generation: null, verify: null, refusals: null, freshness: null, run: null, clauses: [], verdict: null, mutation: null };
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
  const file = path.join(dir, `machine-product-profile-qualification-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256File = (f) => (fs.existsSync(f) ? `sha256:${crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")}` : null);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- the reference declarations (the same pair M09.11 and M08.15 plant) --------------------------------------
const PORTABLE = Q.VERBS.filter((v) => !["clone", "restore", "migrate"].includes(v));
function declaration(reference, hash, supported, unsupported) {
  return { schema_version: "ioi.components.hypervisor.backend-capability-declaration.v1", declaration_ref: `capability://backend/${reference}/1`, declaration_hash: hash, producer_ref: "runtime://daemon/node-1", producer_release_ref: "release://hypervisor/0.1.0", backend_registration_ref: `backend://reference/${reference}`, adapter_release_ref: `release://adapter/${reference}/0.1.0`, scope_ref: "runtime-node://local/node-1", observed_backend_version: "1.0.0", evidence_mode: "simulated", discovery_method_ref: "evaluator://backend-preflight/v1", supported_machine_architectures: ["x86_64"], supported_operations: supported, unsupported_operations: unsupported, limitations: [], evaluator_ref: "evaluator://backend-capability/v1", signature_or_attestation_ref: "evidence://signature/backend-capability-1", temporal_verification_evidence_ref: "evidence://temporal/backend-capability-1", currentness_evaluation_ref: "evaluation://currentness/backend-capability-1", provenance_evidence_refs: ["evidence://preflight/backend-capability-1"] };
}
const HOSTED = declaration("workstation-hosted", `sha256:${"a".repeat(64)}`, [...PORTABLE, "clone", "restore"], [{ operation: "migrate", reason_code: "backend_is_single_host" }]);
const ATTACHED = declaration("infrastructure-attached", `sha256:${"b".repeat(64)}`, [...PORTABLE.filter((v) => !v.endsWith("_console")), "migrate"], [{ operation: "open_console", reason_code: "attached_estate_withholds_console" }, { operation: "close_console", reason_code: "attached_estate_withholds_console" }]);

// ---- the record set: rows hashed, the set hashed, the certificates attested -----------------------------------
export function setRowsHash(set) { return Q.digestOf({ declarations: set.declarations, read_models: set.read_models, delivery_forms: set.delivery_forms, release: set.release, minted_at: set.minted_at, presented: set.presented ?? [] }); }
export function recordSetFindings(set) {
  const f = [];
  if (set?.schema_version !== SET_SCHEMA) f.push("set_schema_invalid");
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T/u.test(String(set?.minted_at))) f.push("set_minted_at_missing");
  for (const k of ["hosted", "attached"]) {
    const d = set?.declarations?.[k];
    if (!d || d.evidence_mode !== "simulated") f.push(`declaration_not_simulated:${k}`);
    if (!HASH.test(String(set?.declaration_bytes_sha256?.[k] ?? "")) || Q.digestOf(d) !== set?.declaration_bytes_sha256?.[k]) f.push(`declaration_digest_mismatch:${k}`);
  }
  const models = Array.isArray(set?.read_models) ? set.read_models : [];
  if (models.length < 2) f.push("read_models_missing");
  for (const m of models) if (!(HASH.test(String(m.head ?? "")) && Array.isArray(m.receipts) && m.receipts.length > 0 && m.derived_from?.rule)) f.push(`read_model_malformed:${m.workload_id}`);
  for (const k of ["hosted", "attached"]) for (const form of ["integrated", "standalone"]) if (!HASH.test(String(set?.delivery_forms?.[k]?.[form]?.evidence_sha256 ?? ""))) f.push(`delivery_evidence_missing:${k}:${form}`);
  if (set?.delivery_forms?.hosted?.integrated?.evidence_sha256 !== set?.delivery_forms?.hosted?.standalone?.evidence_sha256) f.push("delivery_forms_disagree:hosted");
  if (set?.delivery_forms?.attached?.integrated?.evidence_sha256 !== set?.delivery_forms?.attached?.standalone?.evidence_sha256) f.push("delivery_forms_disagree:attached");
  if (!/^[0-9a-f]{40}$/u.test(String(set?.release?.source_commit ?? "")) || !HASH.test(String(set?.release?.daemon_binary_sha256 ?? ""))) f.push("release_basis_malformed");
  if (set?.release?.release_manifest_sha256 !== null) f.push("release_manifest_claimed_without_a_packaged_release");
  if (setRowsHash(set) !== set?.set_sha256) f.push("set_sha256_mismatch");
  for (const k of ["workstation_hosted_v1", "infrastructure_attached_v1"]) if (!HASH.test(String(set?.attested?.[k] ?? ""))) f.push(`attested_missing:${k}`);
  const serialized = JSON.stringify(set ?? {});
  if ([/ioi_sess_[A-Za-z0-9_-]+/u, /ioi_bootstrap_[A-Za-z0-9_-]+/u, /"(?:password|session_token|api_key)"\s*:/iu].some((p) => p.test(serialized))) f.push("secret_bearing_set");
  return f;
}
export function generateFromSet(set, profile_id, lib = Q) {
  const k = profile_id === "workstation_hosted_v1" ? "hosted" : "attached";
  const declarationRecord = set.declarations[k];
  const workloadId = k === "hosted" ? set.workloads.hosted : set.workloads.attached;
  const readModels = set.read_models.filter((m) => m.workload_id === workloadId);
  return lib.assembleProfileCertificate({ profile_id, declaration: declarationRecord, readModels, deliveryForms: set.delivery_forms[k], release: set.release, issuedAt: set.minted_at, presented: set.presented ?? [], issuer: ISSUER });
}
export function generationFindings(set, lib = Q) {
  const f = [];
  const certificates = {};
  for (const profile_id of ["workstation_hosted_v1", "infrastructure_attached_v1"]) {
    let cert = null;
    try { cert = generateFromSet(set, profile_id, lib); } catch (error) { f.push(`assembly_refused:${profile_id}:${String(error.message).slice(0, 60)}`); continue; }
    certificates[profile_id] = cert;
    if (cert.certificate_hash !== set.attested?.[profile_id]) f.push(`regenerated_hash_differs:${profile_id}:${cert.certificate_hash.slice(7, 19)}!=${String(set.attested?.[profile_id]).slice(7, 19)}`);
    if (cert.qualification !== "not_qualified" || cert.evidence_basis !== "simulated") f.push(`certificate_reads_above_its_evidence:${profile_id}:${cert.qualification}/${cert.evidence_basis}`);
    for (const r of ["evidence_basis_simulated", "no_live_backend_registered", "release_unbound", "guest_matrix_undeclared"]) if (!cert.not_qualified_reasons.includes(r)) f.push(`reason_missing:${profile_id}:${r}`);
    if (!(cert.delivery_forms.integrated?.form === "hypervisor_app" && cert.delivery_forms.standalone?.form === "thin_client")) f.push(`delivery_forms_not_carried:${profile_id}`);
    if (cert.delivery_forms.integrated?.evidence_sha256 !== cert.delivery_forms.standalone?.evidence_sha256) f.push(`delivery_forms_disagree:${profile_id}`);
    if (!(cert.release.source_commit && cert.release.daemon_binary_sha256 && cert.release.release_manifest_sha256 === null)) f.push(`release_binding:${profile_id}`);
    if (profile_id === "infrastructure_attached_v1" && !(cert.subject.vmm_ownership_claimed === false && cert.matrix.verbs.find((v) => v.operation === "open_console")?.reason_code === "attached_estate_withholds_console")) f.push("attached_console_reason_not_carried");
    if (profile_id === "workstation_hosted_v1" && cert.matrix.verbs.find((v) => v.operation === "migrate")?.reason_code !== "backend_is_single_host") f.push("hosted_migrate_reason_not_carried");
    if (!cert.matrix.verbs.some((v) => v.status === "supported") || !cert.matrix.verbs.some((v) => v.status === "untested")) f.push(`matrix_not_derived_from_evidence:${profile_id}`);
    if (cert.subject.capability_declaration_bytes_sha256 !== set.declaration_bytes_sha256?.[profile_id === "workstation_hosted_v1" ? "hosted" : "attached"]) f.push(`declaration_digest_not_recomputed:${profile_id}`);
  }
  return { findings: f, certificates };
}

// ---- drills: contract, profiles, verify, refusals, freshness -------------------------------------------------
function ajvFor(schema) {
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  ajv.addKeyword("x-ioi-schema-version");
  return ajv.compile(schema);
}
export function contractFindings({ registry, schema, fixtures }) {
  const f = [];
  const row = (registry?.contracts ?? []).find((c) => c.contract_id === Q.CERTIFICATE_CONTRACT_ID);
  if (!row) return ["registry_row_missing"];
  if (row.schema_version !== Q.CERTIFICATE_SCHEMA) f.push("registry_schema_version_mismatch");
  if (!(row.cross_field_invariant_refs ?? []).some((r) => /reads-down/u.test(r.invariant_id))) f.push("registry_invariant_missing");
  if ((row.positive_fixture_refs ?? []).length < 3 || (row.negative_fixture_refs ?? []).length < 5) f.push("registry_fixtures_thin");
  let validate = null;
  try { validate = ajvFor(schema); } catch (error) { return [...f, `schema_does_not_compile:${String(error.message).slice(0, 80)}`]; }
  for (const [name, fixture] of Object.entries(fixtures.positive ?? {})) { if (!validate(fixture)) f.push(`positive_fixture_rejected:${name}`); const v = Q.validateProfileCertificate(fixture); if (!v.ok) f.push(`positive_fixture_refused_by_verifier:${name}:${v.failures[0]?.code}`); }
  for (const [name, { fixture, expected_failure }] of Object.entries(fixtures.negative ?? {})) {
    const schemaAccepts = validate(fixture);
    if (expected_failure === "schema" && schemaAccepts) f.push(`negative_fixture_accepted_by_schema:${name}`);
    if (expected_failure === "invariant" && !schemaAccepts) f.push(`negative_fixture_rejected_by_schema_not_invariant:${name}`);
    if (Q.validateProfileCertificate(fixture).ok) f.push(`negative_fixture_accepted_by_verifier:${name}`);
  }
  // the schema's own refusals, exercised: qualified on simulated; attached claiming VMM
  const positive = Object.values(fixtures.positive ?? {}).find((c) => c.profile_id === "workstation_hosted_v1");
  const attached = Object.values(fixtures.positive ?? {}).find((c) => c.profile_id === "infrastructure_attached_v1");
  if (positive) { const m = structuredClone(positive); delete m.certificate_hash; m.qualification = "qualified"; m.not_qualified_reasons = []; if (validate(Q.sealProfileCertificate(m))) f.push("schema_admits_qualified_on_simulated"); }
  if (attached) { const m = structuredClone(attached); delete m.certificate_hash; m.subject.vmm_ownership_claimed = true; if (validate(Q.sealProfileCertificate(m))) f.push("schema_admits_attached_vmm_ownership"); }
  return f;
}
// The two profiles, the verbs, the refused kinds, the reasons and the nonclaims, pinned as one digest (2026-09-21, R-216).
export const PROFILES_PIN = "sha256:47c99560a98cce05df31e68c378923211d21e547710ddf860f707a457d66e143";
export function profilesDigest(lib = Q) { return lib.digestOf({ verbs: lib.VERBS, profiles: lib.PROFILES, refused: lib.EVIDENCE_KINDS_REFUSED, reasons: lib.NOT_QUALIFIED_REASONS, withdrawal: lib.WITHDRAWAL_REASONS, nonclaims: lib.NONCLAIMS, members: lib.CERTIFICATE_MEMBERS }); }
export function profilesFindings(lib = Q, pin = PROFILES_PIN) {
  const f = [];
  if (lib.VERBS.length !== 16 || new Set(lib.VERBS).size !== 16) f.push("verbs_not_sixteen");
  const h = lib.PROFILES.workstation_hosted_v1; const a = lib.PROFILES.infrastructure_attached_v1;
  if (!(h?.resource_relationship === "local" && a?.resource_relationship === "customer_attached")) f.push("resource_relationships");
  if (!(h?.other_profile === "infrastructure_attached_v1" && a?.other_profile === "workstation_hosted_v1")) f.push("other_profile_links");
  if (!(h?.required_supported.includes("clone") && h.required_supported.includes("restore") && !h.required_supported.includes("migrate"))) f.push("hosted_matrix");
  if (!(a?.required_supported.includes("migrate") && !a.required_supported.includes("open_console") && !a.required_supported.includes("close_console"))) f.push("attached_matrix");
  if (h?.admitted_backends.some((b) => a?.admitted_backends.includes(b))) f.push("admitted_backends_shared");
  if (lib.EVIDENCE_KINDS_REFUSED.length < 11 || !["vm_boot", "hostile_guest_test", "downloadable_binary", "bootable_image", "generated_dashboard", "backend_declaration", "autonomy_proof", "other_profile_evidence"].every((k) => lib.EVIDENCE_KINDS_REFUSED.includes(k))) f.push("refused_kinds_incomplete");
  if (lib.NONCLAIMS.length < 6) f.push("nonclaims_thin");
  if (profilesDigest(lib) !== pin) f.push(`profiles_digest_moved:${profilesDigest(lib).slice(7, 19)}`);
  return f;
}
export function verifyFindings(certs, lib = Q) {
  const f = [];
  const hosted = certs.workstation_hosted_v1; const attached = certs.infrastructure_attached_v1;
  if (!hosted || !attached) return ["certificates_missing"];
  for (const [k, c] of Object.entries(certs)) { const v = lib.validateProfileCertificate(c); if (!v.ok) f.push(`verifier_refuses:${k}:${v.failures.map((x) => x.code).join("/")}`); if (v.withdraw) f.push(`verifier_withdraws_fresh:${k}`); }
  const ind = lib.independenceFindings(hosted, attached);
  if (ind.length) f.push(`not_independent:${ind.join("/")}`);
  // a certificate built from the OTHER profile's runs shares evidence: independence must see it
  const borrowed = structuredClone(hosted); delete borrowed.certificate_hash; borrowed.evidence_runs = structuredClone(attached.evidence_runs);
  if (!lib.independenceFindings(lib.sealProfileCertificate(borrowed), attached).includes("evidence_shared")) f.push("independence_blind_to_shared_evidence");
  if (attached.subject.vmm_ownership_claimed !== false) f.push("attached_claims_vmm");
  return f;
}
export function refusalFindings(set, lib = Q) {
  const f = [];
  for (const kind of lib.EVIDENCE_KINDS_REFUSED) { const r = lib.refuseEvidenceArtifact(kind, `artifact://${kind}`); if (!(r.refused === true && r.code === "not_qualification_evidence")) f.push(`kind_not_refused:${kind}`); }
  if (lib.refuseEvidenceArtifact("machine_lifecycle_run", "x").refused !== false) f.push("lifecycle_run_refused");
  const presented = lib.EVIDENCE_KINDS_REFUSED.map((kind) => ({ kind, ref: `artifact://${kind}` }));
  const hostedModels = set.read_models.filter((m) => m.workload_id === set.workloads.hosted);
  const withPresented = lib.assembleProfileCertificate({ profile_id: "workstation_hosted_v1", declaration: set.declarations.hosted, readModels: hostedModels, deliveryForms: set.delivery_forms.hosted, release: set.release, issuedAt: set.minted_at, presented, issuer: ISSUER });
  if (withPresented.refused_evidence.length !== lib.EVIDENCE_KINDS_REFUSED.length || withPresented.evidence_runs.some((r) => r.kind !== "machine_lifecycle_run") || withPresented.qualification !== "not_qualified") f.push("presented_artifacts_entered_the_runs");
  // cross-profile: the hosted profile assembled from the attached declaration
  const cross = lib.assembleProfileCertificate({ profile_id: "workstation_hosted_v1", declaration: set.declarations.attached, readModels: set.read_models.filter((m) => m.workload_id === set.workloads.attached), deliveryForms: set.delivery_forms.attached, release: set.release, issuedAt: set.minted_at, issuer: ISSUER });
  if (!cross.not_qualified_reasons.includes("cross_profile_evidence") || !lib.validateProfileCertificate(cross).failures.some((x) => x.code === "cross_profile_evidence")) f.push("cross_profile_evidence_admitted");
  // a declared-mode declaration reads declared, never simulated or live
  const declared = lib.assembleProfileCertificate({ profile_id: "workstation_hosted_v1", declaration: { ...set.declarations.hosted, evidence_mode: "declared" }, readModels: hostedModels, deliveryForms: set.delivery_forms.hosted, release: set.release, issuedAt: set.minted_at, issuer: ISSUER });
  if (!(declared.evidence_basis === "declared" && declared.qualification === "not_qualified" && declared.not_qualified_reasons.includes("evidence_basis_declared"))) f.push("declared_mode_relabelled");
  // relabelled qualified: verifier refuses
  const genuine = generateFromSet(set, "workstation_hosted_v1", lib);
  const relabelled = structuredClone(genuine); delete relabelled.certificate_hash; relabelled.qualification = "qualified"; relabelled.not_qualified_reasons = [];
  if (!lib.validateProfileCertificate(lib.sealProfileCertificate(relabelled)).failures.some((x) => x.code === "qualified_without_live_basis")) f.push("relabelled_qualified_accepted");
  const relabelledBasis = structuredClone(genuine); delete relabelledBasis.certificate_hash; relabelledBasis.evidence_basis = "live";
  if (!lib.validateProfileCertificate(lib.sealProfileCertificate(relabelledBasis)).failures.some((x) => x.code === "evidence_mode_relabelled")) f.push("relabelled_basis_accepted");
  // drift under an unchanged carried hash: the recomputed digest catches it
  const moved = { ...set.declarations.hosted, limitations: ["edited in place"] };
  const v = lib.validateProfileCertificate(genuine, { currentDeclarationBytesSha256: lib.digestOf(moved) });
  if (!(v.withdraw === "declaration_drifted" && v.failures.some((x) => x.code === "declaration_digest_mismatch"))) f.push("drift_under_unchanged_hash_unseen");
  if (moved.declaration_hash !== set.declarations.hosted.declaration_hash) f.push("drift_case_changed_the_carried_hash");
  // a missing delivery form is a named reason
  const oneForm = lib.assembleProfileCertificate({ profile_id: "workstation_hosted_v1", declaration: set.declarations.hosted, readModels: hostedModels, deliveryForms: { integrated: set.delivery_forms.hosted.integrated, standalone: null }, release: set.release, issuedAt: set.minted_at, issuer: ISSUER });
  if (!oneForm.not_qualified_reasons.includes("delivery_form_missing")) f.push("missing_delivery_form_unnamed");
  // vmm ownership on the attached profile is refused by the verifier
  const attachedCert = generateFromSet(set, "infrastructure_attached_v1", lib);
  const vmm = structuredClone(attachedCert); delete vmm.certificate_hash; vmm.subject.vmm_ownership_claimed = true;
  if (!lib.validateProfileCertificate(lib.sealProfileCertificate(vmm)).failures.some((x) => x.code === "vmm_ownership_claimed")) f.push("vmm_ownership_accepted");
  // a run of a refused kind is refused by the verifier
  const bootRun = structuredClone(genuine); delete bootRun.certificate_hash; bootRun.evidence_runs[0].kind = "vm_boot";
  if (!lib.validateProfileCertificate(lib.sealProfileCertificate(bootRun)).failures.some((x) => x.code === "refused_evidence_kind_admitted")) f.push("vm_boot_run_accepted");
  return f;
}
export function freshnessFindings(set, lib = Q) {
  const f = [];
  const genuine = generateFromSet(set, "workstation_hosted_v1", lib);
  const later = new Date(new Date(genuine.freshness.valid_until).getTime() + 86_400_000).toISOString();
  const v = lib.validateProfileCertificate(genuine, { now: later });
  if (!(v.withdraw === "freshness_expired" && v.failures.some((x) => x.code === "freshness_expired"))) f.push("expiry_unseen");
  const before = lib.validateProfileCertificate(genuine, { now: genuine.freshness.issued_at });
  if (before.withdraw !== null) f.push("fresh_certificate_withdrawn");
  const withdrawn = lib.withdraw(genuine, "freshness_expired", later, "valid_until passed");
  if (!(withdrawn.qualification === "withdrawn" && withdrawn.withdrawal?.reason === "freshness_expired" && withdrawn.not_qualified_reasons.includes("freshness_expired") && lib.validateProfileCertificate(withdrawn, { now: later }).ok && withdrawn.certificate_hash !== genuine.certificate_hash)) f.push("withdrawal_malformed");
  const other = lib.validateProfileCertificate(genuine, { currentDaemonSha256: `sha256:${"c".repeat(64)}` });
  if (!(other.withdraw === "release_unbound" && other.failures.some((x) => x.code === "release_daemon_mismatch"))) f.push("other_daemon_unseen");
  const same = lib.validateProfileCertificate(genuine, { currentDaemonSha256: genuine.release.daemon_binary_sha256 });
  if (same.withdraw !== null) f.push("same_daemon_withdrawn");
  let threw = false; try { lib.withdraw(genuine, "requalified", later, "up"); } catch { threw = true; }
  if (!threw) f.push("withdrawal_moves_up");
  if (typeof lib.requalify === "function" || typeof lib.qualify === "function") f.push("library_exports_an_upgrade");
  const twice = lib.withdraw(withdrawn, "owner_withdrawn", later, "again");
  if (twice.qualification !== "withdrawn") f.push("second_withdrawal_moved_up");
  return f;
}
export function canonFindings({ pe, surfaces, web, byo }) {
  const f = [];
  const n = (t) => t.replace(/\s+/gu, " ");
  const need = [["pe_gate", n(pe), /`check:machine-product-profile-qualification`/u], ["pe_generated", n(pe), /generated, never read pre-sealed/u], ["surfaces_profiles", n(surfaces), /`workstation_hosted_v1`/u], ["surfaces_reads_down", n(surfaces), /reads `qualified` only from `live` backend evidence/u], ["surfaces_gate", n(surfaces), /`check:machine-product-profile-qualification`/u], ["web_claim_id", n(web), /`workstation_hosted_v1` or `infrastructure_attached_v1`/u], ["byo_attached_certificate", n(byo), /`infrastructure_attached_v1` certificate/u]];
  for (const [name, text, re] of need) if (!re.test(text)) f.push(`canon_${name}_missing`);
  return f;
}
export function bindingFindings(clauses, { rootPkg, appPkg, floors }) {
  const f = [];
  const seen = new Set();
  for (const c of clauses) {
    if (!Number.isInteger(c.n) || c.n < 1 || c.n > 12) f.push(`clause_out_of_range: ${c.n}`);
    if (seen.has(c.n)) f.push(`clause_duplicated: ${c.n}`);
    seen.add(c.n);
    if ((c.executed_by ?? []).length === 0 && !c.absence && !c.scheduled) f.push(`clause_${c.n}_neither_executed_nor_named`);
    for (const g of c.executed_by ?? []) {
      if (g.kind === "app") {
        if (!appPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        const row = (floors.verifiers ?? []).find((r) => r.id === g.floor);
        if (!row) f.push(`clause_${c.n}_floor_missing: ${g.floor}`);
        else if (!(row.runtime_assertions >= 1) || row.npm_script !== g.script) f.push(`clause_${c.n}_floor_mismatch: ${g.floor}`);
      } else if (g.kind === "root") {
        if (!rootPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        if (!rootPkg.scripts?.[g.script.replace(/^check:/u, "mutate:")] && !(typeof g.undrilled === "string" && g.undrilled.length > 20)) f.push(`clause_${c.n}_binds_undrilled_root_script: ${g.script}`);
      } else if (g.kind !== "self") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
    if (c.scheduled && !(typeof c.scheduled.prerequisite === "string" && c.scheduled.prerequisite.length > 20 && typeof c.scheduled.ruling === "string" && /R-\d+/u.test(c.scheduled.ruling))) f.push(`clause_${c.n}_scheduled_without_prerequisite_or_ruling`);
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
      if (g.ledger && g.ledger.reach > 0) failures.push(`clause_${r.n}_undeclared_egress: ${g.script} reached ${g.ledger.reach} non-loopback destination(s)`);
      if (g.floor_expected != null && g.executed_assertions != null && g.executed_assertions < g.floor_expected) failures.push(`clause_${r.n}_below_floor: ${g.script} ${g.executed_assertions} < ${g.floor_expected}`);
    }
    if (r.absence) { if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`); else absences.push({ n: r.n, ...r.absence }); }
    if (r.scheduled) { if (!(r.scheduled.prerequisite && r.scheduled.ruling)) failures.push(`clause_${r.n}_scheduled_without_prerequisite_or_ruling`); else absences.push({ n: r.n, what: `SCHEDULED-OUTSTANDING: ${r.scheduled.what}`, owner: `prerequisite: ${r.scheduled.prerequisite} · ${r.scheduled.ruling}` }); }
    if (r.not_executed) absences.push({ n: r.n, what: `not executed in this run: ${r.not_executed}`, owner: "this runner (on demand)" });
  }
  for (let n = 1; n <= 12; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

function loadFixtures(registry) {
  const row = (registry?.contracts ?? []).find((c) => c.contract_id === Q.CERTIFICATE_CONTRACT_ID);
  const positive = {}; const negative = {};
  for (const p of row?.positive_fixture_refs ?? []) positive[path.basename(p)] = readJson(path.join(SCHEMAS, p));
  for (const n of row?.negative_fixture_refs ?? []) negative[path.basename(n.path)] = { fixture: readJson(path.join(SCHEMAS, n.path)), expected_failure: n.expected_failure };
  return { positive, negative };
}
async function drills() {
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(APP_DIR, "package.json"));
  const floors = readJson(FLOORS);
  const b = bindingFindings(CLAUSES, { rootPkg, appPkg, floors });
  ok("BINDING — the acceptance's demands are twelve clauses, each executed by a floored gate, M09.11's own gate or this runner's legs, or named with an owner, or scheduled with its prerequisite and ruling (both positive crossings)", b.length === 0, b.join("; ") || `${CLAUSES.length} clauses`);
  const registry = fs.existsSync(REGISTRY) ? readJson(REGISTRY) : null;
  const schema = fs.existsSync(SCHEMA_FILE) ? readJson(SCHEMA_FILE) : null;
  const cf = registry && schema ? contractFindings({ registry, schema, fixtures: loadFixtures(registry) }) : ["contract_files_missing"];
  evidence.contract = cf;
  ok("CONTRACT — the certificate contract is registered with its reads-down invariant and fixtures; every positive fixture validates under the schema and the verifier, every negative fixture is refused for its declared cause, and the schema itself refuses `qualified` on a simulated basis and an attached certificate claiming VMM ownership", cf.length === 0, cf.join("; ") || "registered");
  const pf = profilesFindings();
  evidence.profiles = { findings: pf, digest: profilesDigest() };
  ok("PROFILES — the two profile matrices are canon's: sixteen verbs, the hosted profile requiring clone and restore and not migrate, the attached profile requiring migrate and not the console, distinct admitted backends, each naming the other; the refused-evidence kinds and the nonclaims complete; the whole pinned by digest", pf.length === 0, pf.join("; ") || evidence.profiles.digest.slice(0, 19));
  const set = fs.existsSync(RECORD_SET) ? readJson(RECORD_SET) : null;
  const sf = set ? recordSetFindings(set) : ["record_set_missing"];
  const g = set && sf.length === 0 ? generationFindings(set) : { findings: ["not_generated"], certificates: {} };
  evidence.generation = { set_findings: sf, findings: g.findings, set_sha256: set?.set_sha256 ?? null, attested: set?.attested ?? null, certificates: Object.fromEntries(Object.entries(g.certificates).map(([k, c]) => [k, { certificate_ref: c.certificate_ref, certificate_hash: c.certificate_hash, qualification: c.qualification, evidence_basis: c.evidence_basis, reasons: c.not_qualified_reasons, matrix: c.matrix.verbs.map((v) => `${v.operation}:${v.status}`) }])) };
  ok("GENERATION — the tracked record set (minted from a real isolated run against the two simulated reference backends) re-hashes to its committed set hash with the declarations' digests recomputed; both certificates are assembled from it, regenerate their attested hashes byte for byte, read not_qualified with evidence_basis simulated and the reasons the evidence carries, bind the source commit and daemon digest with the release named unbound, carry both delivery forms' agreeing evidence, and derive the matrix from the receipts", sf.length === 0 && g.findings.length === 0, [...sf, ...g.findings].join("; ") || `hosted ${g.certificates.workstation_hosted_v1?.certificate_hash.slice(7, 19)} · attached ${g.certificates.infrastructure_attached_v1?.certificate_hash.slice(7, 19)}`);
  const vf = Object.keys(g.certificates).length === 2 ? verifyFindings(g.certificates) : ["certificates_missing"];
  evidence.verify = vf;
  ok("VERIFY — the offline verifier accepts both certificates and withdraws neither while fresh; the two are independent (distinct backends, declarations and receipts, each disclaiming the other) and independence sees a certificate built on the other's evidence; the attached certificate claims no VMM ownership", vf.length === 0, vf.join("; ") || "independent");
  const rf = set && sf.length === 0 ? refusalFindings(set) : ["not_run"];
  evidence.refusals = rf;
  ok("REFUSALS — every artifact kind canon refuses is refused by kind and never enters the runs; the other profile's declaration reads cross-profile evidence; a declared-mode declaration reads declared; a certificate relabelled qualified or relabelled to a live basis is refused; a declaration edited under an unchanged carried hash is caught by the recomputed digest; a missing delivery form is named; VMM ownership and a VM-boot run are refused", rf.length === 0, rf.join("; ") || "refused by kind");
  const ff = set && sf.length === 0 ? freshnessFindings(set) : ["not_run"];
  evidence.freshness = ff;
  ok("FRESHNESS — an expired certificate withdraws with its reason and verifies as withdrawn; a fresh one is not withdrawn; a daemon other than the one that ran withdraws it and the same daemon does not; withdrawal only ever moves down and the library exports no upgrade", ff.length === 0, ff.join("; ") || "reads down only");
  const c = canonFindings({ pe: fs.readFileSync(CANON_PE, "utf8"), surfaces: fs.readFileSync(CANON_SURFACES, "utf8"), web: fs.readFileSync(CANON_WEB, "utf8"), byo: fs.readFileSync(CANON_BYO, "utf8") });
  ok("CANON — providers-and-environments.md, core-clients-surfaces.md, public-web-estate.md and byo-provider-plane.md bind the two profiles, the certificate's read-down rule and the gate", c.length === 0, c.join("; ") || "bound");
  const rows = CLAUSES.map((x) => ({ n: x.n, executed: (x.executed_by ?? []).map((g2) => ({ script: g2.script, status: 0, evidence: "x", evidence_sha256: "sha256:x", ledger: { reach: 0 } })), absence: x.absence || null, scheduled: x.scheduled || null }));
  const v = verdict(rows);
  const v2 = verdict(rows.map((r) => (r.n === 5 ? { ...r, executed: [{ ...r.executed[0], status: 1 }] } : r)));
  const v3 = verdict(rows.map((r) => (r.n === 5 ? { ...r, executed: [{ ...r.executed[0], evidence: null }] } : r)));
  const v4 = verdict(rows.map((r) => (r.n === 5 ? { ...r, executed: [{ ...r.executed[0], ledger: { reach: 1 } }] } : r)));
  const v5 = verdict(rows.filter((r) => r.n !== 7));
  ok("VERDICT — pass only when every clause is executed green with evidence and no absence is named; a named absence or scheduled leg is a NAMED FAILURE (exit 2); a red, an evidence-less green, an undeclared egress or a missing row is a FAIL", v.kind === "named_failure" && v2.kind === "fail" && v3.kind === "fail" && v4.kind === "fail" && v5.kind === "fail", `${v.kind}/${v2.kind}/${v3.kind}/${v4.kind}/${v5.kind}`);
}

// ---- mutation ----------------------------------------------------------------------------------------------
async function mutantLib(transform) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-mpq-mutant-"));
  const file = path.join(dir, `lib-${crypto.randomBytes(4).toString("hex")}.mjs`);
  fs.writeFileSync(file, transform(fs.readFileSync(LIB_PATH, "utf8")));
  const mod = await import(pathToFileURL(file).href);
  return { mod, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
async function mutation() {
  const rows = [];
  sink = [];
  const plant = (name, detected, detail) => { rows.push({ name, detected: !!detected, detail: String(detail ?? "").slice(0, 160) }); console.log(`${detected ? "RED " : "MISS"}  ${name}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const set = readJson(RECORD_SET);
  const registry = readJson(REGISTRY); const schema = readJson(SCHEMA_FILE); const fixtures = loadFixtures(registry);
  const mutate = async (name, transform, probe) => {
    let m = null;
    try { m = await mutantLib(transform); const f = probe(m.mod); plant(name, f.length > 0, f[0]); } catch (error) { plant(name, true, `mutant does not load: ${String(error?.message || error).slice(0, 80)}`); } finally { m?.cleanup(); }
  };
  await mutate("an assembler that reads qualified on a simulated basis", (t) => t.replace('const qualification = reasons.size === 0 && evidenceMode === "live" ? "qualified" : "not_qualified";', 'const qualification = evidenceMode === "none" ? "not_qualified" : "qualified";'), (lib) => generationFindings(set, lib).findings.filter((x) => /reads_above_its_evidence/u.test(x)));
  await mutate("a verifier that lets qualified through without a live basis", (t) => t.replace('if (c.qualification === "qualified" && c.evidence_basis !== "live") fail("qualified_without_live_basis"', 'if (false) fail("qualified_without_live_basis"'), (lib) => refusalFindings(set, lib).filter((x) => x === "relabelled_qualified_accepted"));
  await mutate("a verifier blind to a relabelled evidence basis", (t) => t.replace('if (c.evidence_basis !== "none" && c.evidence_basis !== s.evidence_mode) fail("evidence_mode_relabelled"', 'if (false) fail("evidence_mode_relabelled"'), (lib) => refusalFindings(set, lib).filter((x) => x === "relabelled_basis_accepted"));
  await mutate("an assembler that forgets to disclaim the other profile", (t) => t.replace("does_not_qualify: [profile.other_profile, ...DOES_NOT_QUALIFY_ALWAYS],", "does_not_qualify: [...DOES_NOT_QUALIFY_ALWAYS],"), (lib) => { const g = generationFindings(set, lib); return [...g.findings, ...verifyFindings(g.certificates, lib)].filter((x) => /regenerated_hash_differs|verifier_refuses|not_independent/u.test(x)); });
  await mutate("a verifier blind to VMM ownership on the attached profile", (t) => t.replace('if (s.vmm_ownership_claimed !== false) fail("vmm_ownership_claimed"', 'if (false) fail("vmm_ownership_claimed"'), (lib) => refusalFindings(set, lib).filter((x) => x === "vmm_ownership_accepted"));
  await mutate("an assembler that trusts the carried declaration hash instead of recomputing the digest", (t) => t.replace("capability_declaration_bytes_sha256: digestOf(declaration),", "capability_declaration_bytes_sha256: String(declaration.declaration_hash ?? \"\"),"), (lib) => { const g = generationFindings(set, lib); return g.findings.filter((x) => /declaration_digest_not_recomputed|regenerated_hash_differs/u.test(x)); });
  await mutate("a withdrawal that moves a certificate UP", (t) => t.replace('next.qualification = "withdrawn";', 'next.qualification = "qualified"; next.evidence_basis = "live";'), (lib) => freshnessFindings(set, lib).filter((x) => /withdrawal_malformed|second_withdrawal_moved_up/u.test(x)));
  await mutate("an independence check blind to shared evidence", (t) => t.replace('if ([...a].some((x) => b.has(x))) f.push("evidence_shared");', 'if (false) f.push("evidence_shared");'), (lib) => { const g = generationFindings(set, lib); return verifyFindings(g.certificates, lib).filter((x) => x === "independence_blind_to_shared_evidence"); });
  await mutate("a verifier that admits a VM boot as an evidence run", (t) => t.replace('if (r.kind !== "machine_lifecycle_run") fail("refused_evidence_kind_admitted"', 'if (false) fail("refused_evidence_kind_admitted"'), (lib) => refusalFindings(set, lib).filter((x) => x === "vm_boot_run_accepted"));
  await mutate("an assembler that admits presented artifacts into the runs", (t) => t.replace("refused_evidence: presented.filter((p) => EVIDENCE_KINDS_REFUSED.includes(p?.kind)).map((p) => ({ kind: p.kind, ref: String(p.ref), reason: \"not_qualification_evidence\" })),", "refused_evidence: [],"), (lib) => refusalFindings(set, lib).filter((x) => x === "presented_artifacts_entered_the_runs"));
  await mutate("a hosted profile that no longer requires restore", (t) => t.replace('required_supported: Object.freeze([...PORTABLE, "clone", "restore"]),', 'required_supported: Object.freeze([...PORTABLE, "clone"]),'), (lib) => profilesFindings(lib).filter((x) => /hosted_matrix|profiles_digest_moved/u.test(x)));
  await mutate("a verifier blind to expiry", (t) => t.replace('if (now && INSTANT.test(String(f.valid_until)) && String(now) > String(f.valid_until) && c.qualification !== "withdrawn")', "if (false)"), (lib) => freshnessFindings(set, lib).filter((x) => x === "expiry_unseen"));
  await mutate("a verifier blind to a moved declaration", (t) => t.replace('if (currentDeclarationBytesSha256 && currentDeclarationBytesSha256 !== s.capability_declaration_bytes_sha256 && c.qualification !== "withdrawn")', "if (false)"), (lib) => refusalFindings(set, lib).filter((x) => x === "drift_under_unchanged_hash_unseen"));
  const altered = structuredClone(set); altered.read_models[0].head = `sha256:${"f".repeat(64)}`;
  let f = recordSetFindings(altered);
  plant("a record set whose row moved under its committed hash", f.includes("set_sha256_mismatch"), f[0]);
  const relabelledSet = structuredClone(set); relabelledSet.declarations.hosted.evidence_mode = "live";
  f = recordSetFindings(relabelledSet);
  plant("a record set whose declaration was relabelled live", f.some((x) => /declaration_not_simulated|declaration_digest_mismatch|set_sha256_mismatch/u.test(x)), f[0]);
  const schemaOpen = structuredClone(schema); schemaOpen.allOf = schemaOpen.allOf.filter((rule) => rule?.if?.properties?.qualification?.const !== "qualified");
  f = contractFindings({ registry, schema: schemaOpen, fixtures });
  plant("a schema that admits qualified on a simulated basis", f.includes("schema_admits_qualified_on_simulated") || f.some((x) => x.startsWith("negative_fixture_accepted_by_schema")), f[0]);
  const registryWithout = { ...registry, contracts: registry.contracts.filter((c) => c.contract_id !== Q.CERTIFICATE_CONTRACT_ID) };
  f = contractFindings({ registry: registryWithout, schema, fixtures });
  plant("a registry without the certificate contract", f.includes("registry_row_missing"), f[0]);
  const c = canonFindings({ pe: fs.readFileSync(CANON_PE, "utf8").replace(/`check:machine-product-profile-qualification`/gu, "`check:something-else`"), surfaces: fs.readFileSync(CANON_SURFACES, "utf8"), web: fs.readFileSync(CANON_WEB, "utf8"), byo: fs.readFileSync(CANON_BYO, "utf8") });
  plant("canon that no longer names the gate", c.includes("canon_pe_gate_missing"), c[0]);
  const fake = verdict(CLAUSES.map((x) => ({ n: x.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
  plant("a run whose every clause reports success without evidence", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
  const unbound = bindingFindings(CLAUSES.map((x) => (x.n === 10 ? { n: 10, demand: x.demand, executed_by: [] } : x)), { rootPkg: readJson(path.join(ROOT, "package.json")), appPkg: readJson(path.join(APP_DIR, "package.json")), floors: readJson(FLOORS) });
  plant("a scheduled crossing dropped without a prerequisite or ruling", unbound.includes("clause_10_neither_executed_nor_named"), unbound[0]);
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the RUN leg: mint the records afresh in this runner's own plane -------------------------------------------
const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };
let nonce = 0;
function proposal(workload, verb, decl, { head = GENESIS, generation = 1 } = {}) {
  nonce += 1;
  return { schema_version: "ioi.hypervisor.machine-operation.v1", operation_ref: "machine-operation://caller-chose-this", operation: verb, workload_ref: `virtual-machine-workload://${workload}`, desired_generation: generation, expected_head: head, owner_ref: "principal://owner_01", environment_ref: "environment://env_01", backend_registration_ref: decl.backend_registration_ref, capability_declaration_ref: decl.declaration_ref, capability_declaration_hash: decl.declaration_hash, affected_image_bindings: [], affected_volume_bindings: [], affected_network_bindings: [], affected_device_bindings: [], authority_refs: ["authority://wallet_network_01"], policy_refs: [], idempotency_key_hash: `sha256:${String(nonce).padStart(64, "d")}`, cleanup_obligation_ref: null, durability_boundary_ref: "durability-boundary://declared_01", observation_boundary_ref: "observation-boundary://declared_01" };
}
function bootstrapTokenIn(dataDir) {
  const logs = fs.readdirSync(dataDir).filter((f) => /^isolated-daemon.*\.log$/u.test(f)).sort();
  for (const f of logs.reverse()) { const t = fs.readFileSync(path.join(dataDir, f), "utf8").match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1); if (t) return t; }
  return null;
}
function sourceBasis(binary) {
  const commit = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).stdout.trim();
  const dirty = spawnSync("git", ["status", "--porcelain"], { cwd: ROOT, encoding: "utf8" }).stdout.trim().length > 0;
  return { source_commit: /^[0-9a-f]{40}$/u.test(commit) ? commit : null, daemon_binary_sha256: sha256File(binary), release_manifest_sha256: null, release_version: null, signer_key_id: null, dirty_state_declaration: dirty ? "source_build:working_tree_dirty" : "source_build:working_tree_clean" };
}
async function runLeg({ mintTo = null } = {}) {
  const findings = [];
  const out = {};
  const binary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-mpq-plane-"));
  let plane = null; let serve = null;
  try {
    fs.mkdirSync(path.join(dataDir, "machine-capability-declarations"), { recursive: true });
    fs.writeFileSync(path.join(dataDir, "machine-capability-declarations", "hosted.json"), JSON.stringify(HOSTED));
    fs.writeFileSync(path.join(dataDir, "machine-capability-declarations", "attached.json"), JSON.stringify(ATTACHED));
    plane = await startIsolatedPlane({ baseEnv: process.env, env: { IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1", IOI_HYPERVISOR_DAEMON_BINARY: binary }, dataDir });
    if (!plane) { findings.push("isolated_plane_did_not_start"); return { findings }; }
    const DAEMON = plane.daemonUrl;
    const token = bootstrapTokenIn(dataDir);
    const boot = await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "machine-profile-qualification-pass-1", email: "machine-profile-qualification@ioi.local" }) });
    const bootBody = await boot.json().catch(() => ({}));
    const cookie = bootBody.session_token ? `ioi_session=${bootBody.session_token}` : "";
    if (!cookie) findings.push(`bootstrap:${boot.status}`);
    const jd = (base, p, init = {}) => fetch(`${base}${p}`, { ...init, redirect: "manual", headers: { ...(init.body ? { "content-type": "application/json" } : {}), cookie, ...(init.headers || {}) } }).then(async (r) => { const text = await r.text(); let body = {}; try { body = text ? JSON.parse(text) : {}; } catch { body = {}; } return { status: r.status, body, text }; });
    const servePort = await freePort(); const productUiPort = await freePort();
    const SERVE_URL = `http://127.0.0.1:${servePort}`;
    serve = spawn(process.execPath, [SERVE], { cwd: APP_DIR, env: { ...sanitizedVerifierBaseEnv(process.env), PORT: String(servePort), PRODUCT_UI_PORT: String(productUiPort), IOI_PRODUCT_UI_PUBLIC: path.join(APP_DIR, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON }, stdio: ["ignore", "pipe", "pipe"] });
    if (!(await waitFor(`${SERVE_URL}/__ioi/login`, 90000))) findings.push("serve_did_not_start");
    const W = "vm_profile_hosted"; const W2 = "vm_profile_attached";
    const thinSpine = async (w) => (await jd(DAEMON, `${MACHINES_API}/${w}`)).body?.machine;
    const appSubmit = (w, p) => jd(SERVE_URL, MACHINE_LANE_PATH, { method: "POST", body: JSON.stringify({ workload: w, proposal: p }) });
    const thinSubmit = (w, p) => jd(DAEMON, `${MACHINES_API}/${w}/operations`, { method: "POST", body: JSON.stringify(p) });
    const head = async (w) => (await thinSpine(w))?.head ?? GENESIS;
    // hosted: create (App), start (thin), snapshot (App), stop (thin), a refusal (stale head, App), delete (thin)
    const steps = [];
    steps.push(await appSubmit(W, proposal(W, "create", HOSTED, { generation: 1 })));
    steps.push(await thinSubmit(W, proposal(W, "start", HOSTED, { head: await head(W), generation: 2 })));
    steps.push(await appSubmit(W, proposal(W, "snapshot", HOSTED, { head: await head(W), generation: 3 })));
    steps.push(await thinSubmit(W, proposal(W, "stop", HOSTED, { head: await head(W), generation: 4 })));
    steps.push(await appSubmit(W, proposal(W, "reboot", HOSTED, { head: GENESIS, generation: 5 })));
    steps.push(await thinSubmit(W, proposal(W, "delete", HOSTED, { head: await head(W), generation: 5 })));
    // attached: create (thin), migrate → ambiguous (App), start (thin)
    steps.push(await thinSubmit(W2, proposal(W2, "create", ATTACHED, { generation: 1 })));
    steps.push(await appSubmit(W2, proposal(W2, "migrate", ATTACHED, { head: await head(W2), generation: 2 })));
    steps.push(await thinSubmit(W2, proposal(W2, "start", ATTACHED, { head: await head(W2), generation: 2 })));
    const outcomes = steps.map((s) => `${s.status}:${s.body?.state ?? s.body?.reason ?? "?"}`);
    const expected = ["200:succeeded", "200:succeeded", "200:succeeded", "200:succeeded", "200:expected_head_stale", "200:succeeded", "200:succeeded", "200:ambiguous", "200:succeeded"];
    if (outcomes.join(",") !== expected.join(",")) findings.push(`lifecycle:${outcomes.join(",")}`);
    const hostedSpine = await thinSpine(W); const attachedSpine = await thinSpine(W2);
    const appHosted = spineFromRenderedDetail((await jd(SERVE_URL, `${MACHINES_ROUTE}/${W}`)).text);
    const appAttached = spineFromRenderedDetail((await jd(SERVE_URL, `${MACHINES_ROUTE}/${W2}`)).text);
    const p1 = spineParity(appHosted, hostedSpine); const p2 = spineParity(appAttached, attachedSpine);
    if (p1.length || p2.length) findings.push(`delivery_forms_disagree:${[...p1, ...p2].slice(0, 3).join("|")}`);
    const forms = (appSpine, thin, w) => ({ integrated: { form: "hypervisor_app", evidence_ref: `page://${MACHINES_ROUTE}/${w}`, evidence_sha256: Q.digestOf(projectMachineSpine(appSpine)) }, standalone: { form: "thin_client", evidence_ref: `api://${MACHINES_API}/${w}`, evidence_sha256: Q.digestOf(projectMachineSpine(thin)) } });
    const set = { schema_version: SET_SCHEMA, minted_at: new Date().toISOString(), minted_by: "scripts/check-machine-product-profile-qualification.mjs (RUN leg)", source: "an isolated daemon with the two simulated reference declarations planted; the hosted workload through create/start/snapshot/stop/(stale reboot refused)/delete across the App lane and the thin client, the attached workload through create/migrate(ambiguous)/start; the daemon's own read models, the declarations as records, both delivery forms' evidence, the source basis", workloads: { hosted: W, attached: W2 }, declarations: { hosted: HOSTED, attached: ATTACHED }, declaration_bytes_sha256: { hosted: Q.digestOf(HOSTED), attached: Q.digestOf(ATTACHED) }, read_models: [hostedSpine, attachedSpine], delivery_forms: { hosted: forms(appHosted, hostedSpine, W), attached: forms(appAttached, attachedSpine, W2) }, release: sourceBasis(binary), presented: [{ kind: "vm_boot", ref: "check:microvm-model-broker (a VM boot on this host)" }, { kind: "backend_declaration", ref: HOSTED.declaration_ref }, { kind: "autonomy_proof", ref: "check:undeniable-product-proof" }, { kind: "packaging", ref: "check:zero-to-operable" }, { kind: "simulated_only_as_host_compatibility", ref: "check:machine-lifecycle-backend-conformance" }] };
    set.set_sha256 = setRowsHash(set);
    set.attested = {};
    for (const profile_id of ["workstation_hosted_v1", "infrastructure_attached_v1"]) set.attested[profile_id] = generateFromSet(set, profile_id).certificate_hash;
    const sf = recordSetFindings(set);
    if (sf.length) findings.push(`fresh_set:${sf.join("|")}`);
    const g = generationFindings(set);
    if (g.findings.length) findings.push(`fresh_generation:${g.findings.join("|")}`);
    const vf = Object.keys(g.certificates).length === 2 ? verifyFindings(g.certificates) : ["certificates_missing"];
    if (vf.length) findings.push(`fresh_verify:${vf.join("|")}`);
    // the fresh certificates downgrade for the SAME reasons as the tracked ones
    if (fs.existsSync(RECORD_SET)) {
      const tracked = generationFindings(readJson(RECORD_SET)).certificates;
      for (const k of ["workstation_hosted_v1", "infrastructure_attached_v1"]) if (g.certificates[k] && tracked[k] && JSON.stringify(g.certificates[k].not_qualified_reasons) !== JSON.stringify(tracked[k].not_qualified_reasons)) findings.push(`fresh_reasons_differ:${k}`);
    }
    if (mintTo) { fs.mkdirSync(path.dirname(mintTo), { recursive: true }); fs.writeFileSync(mintTo, `${JSON.stringify(set, null, 2)}\n`); out.minted = path.relative(ROOT, mintTo); }
    out.set_sha256 = set.set_sha256; out.attested = set.attested; out.outcomes = outcomes; out.certificates = Object.fromEntries(Object.entries(g.certificates).map(([k, c]) => [k, { certificate_hash: c.certificate_hash, qualification: c.qualification, evidence_basis: c.evidence_basis, reasons: c.not_qualified_reasons }]));
  } catch (error) {
    findings.push(`leg_crashed:${String(error?.stack || error).slice(0, 300)}`);
  } finally {
    if (serve) { try { serve.kill("SIGTERM"); } catch { /* gone */ } }
    if (plane) { try { await plane.stop(); } catch { /* gone */ } }
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
  return { findings, ...out };
}

async function runGate(g, workDir, floors, n) {
  const label = `${n}-${(g.floor || g.script).replace(/[^A-Za-z0-9]+/gu, "-")}`;
  const censusDir = path.join(workDir, "census", label);
  fs.mkdirSync(censusDir, { recursive: true });
  const env = { ...sanitizedVerifierBaseEnv(), ...process.env, IOI_VERIFIER_CENSUS_DIR: path.relative(ROOT, censusDir), CARGO_NET_OFFLINE: "true", IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS: process.env.IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS || "120000" };
  const argvRun = ["npm", "run", "-s", g.script, ...(g.workspace ? [`--workspace=${g.workspace}`] : [])];
  const iso = await runIsolated({ label, argv: argvRun, cwd: ROOT, env, workDir, bridges: [], timeoutMs: g.minutes * 60_000 });
  const classified = classifyLedger(iso.ledger, { declaredHosts: g.declaredHosts ?? [], declaredNames: g.declaredNames ?? [] });
  const logFile = path.join(workDir, `${label}.log`);
  const files = fs.existsSync(censusDir) ? fs.readdirSync(censusDir).filter((f) => f.endsWith(".json")).map((f) => path.join(censusDir, f)) : [];
  const evidenceFile = files[0] || (fs.existsSync(logFile) ? logFile : null);
  const floorRow = g.floor ? (floors.verifiers ?? []).find((r) => r.id === g.floor) : null;
  const censusJson = files[0] ? readJson(files[0]) : null;
  const logAssertions = !censusJson && fs.existsSync(logFile) ? Number((fs.readFileSync(logFile, "utf8").match(/(\d+)\/(\d+) assertion/u) ?? [])[1] ?? NaN) : NaN;
  return { script: g.script, kind: g.kind, status: iso.status, seconds: iso.seconds, isolation: iso.isolation, ledger: { attempts: classified.counts?.attempts ?? 0, loopback: classified.counts?.loopback ?? 0, reach: (classified.undeclared?.length ?? 0) + (classified.undeclared_names?.length ?? 0) }, evidence: evidenceFile ? path.relative(ROOT, evidenceFile) : null, evidence_sha256: evidenceFile ? sha256File(evidenceFile) : null, executed_assertions: censusJson?.executed_assertions ?? (Number.isFinite(logAssertions) ? logAssertions : null), floor_expected: floorRow?.runtime_assertions ?? null };
}
async function full() {
  const probe = probeIsolation();
  if (!probe.strace.available) blocked(`the harness cannot record: ${probe.strace.detail}`);
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary} (the harness must not build)`);
  process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-mpq-gate-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  console.log("\n# RUN: the records minted afresh in this runner's own isolated plane, both certificates generated from that run and verified");
  const run = await runLeg();
  evidence.run = run;
  console.log(`  → RUN ${run.findings.length === 0 ? `minted, generated, verified: hosted ${run.certificates?.workstation_hosted_v1?.qualification}/${run.certificates?.workstation_hosted_v1?.evidence_basis}, attached ${run.certificates?.infrastructure_attached_v1?.qualification}/${run.certificates?.infrastructure_attached_v1?.evidence_basis}` : run.findings.join("; ")}`);
  const selfEvidence = path.join(workDir, "self-legs.json");
  fs.writeFileSync(selfEvidence, `${JSON.stringify({ contract: evidence.contract, profiles: evidence.profiles, generation: evidence.generation, verify: evidence.verify, refusals: evidence.refusals, freshness: evidence.freshness, run: evidence.run }, null, 2)}\n`);
  const legGreen = { "contract (this runner)": (evidence.contract?.length ?? 1) === 0, "profiles (this runner)": (evidence.profiles?.findings?.length ?? 1) === 0, "generation (this runner)": (evidence.generation?.findings?.length ?? 1) === 0 && (evidence.generation?.set_findings?.length ?? 1) === 0, "verify (this runner)": (evidence.verify?.length ?? 1) === 0, "refusals (this runner)": (evidence.refusals?.length ?? 1) === 0, "freshness (this runner)": (evidence.freshness?.length ?? 1) === 0, "run (this runner)": run.findings.length === 0 };
  const selfRun = (name) => ({ script: name, status: legGreen[name] ? 0 : 1, seconds: 0, isolation: "in-process", ledger: { attempts: 0, loopback: 0, reach: 0 }, evidence: path.relative(ROOT, selfEvidence), evidence_sha256: sha256File(selfEvidence), executed_assertions: null, floor_expected: null });
  const done = new Map();
  const rows = [];
  for (const c of CLAUSES) {
    const row = { n: c.n, demand: c.demand, executed: [], absence: c.absence || null, scheduled: c.scheduled || null };
    for (const g of c.executed_by ?? []) {
      if (g.kind === "self") { row.executed.push(selfRun(g.script)); continue; }
      if (!done.has(g.script)) {
        console.log(`\n# ${g.script} — inside the harness (clause ${c.n})`);
        done.set(g.script, await runGate(g, workDir, floors, c.n));
        const r = done.get(g.script);
        console.log(`  → exit ${r.status} in ${r.seconds}s · ${r.executed_assertions ?? "?"}${r.floor_expected != null ? `/${r.floor_expected}` : ""} · ledger ${r.ledger.attempts} attempts, ${r.ledger.loopback} loopback, ${r.ledger.reach} reach`);
      }
      row.executed.push(done.get(g.script));
    }
    rows.push(row);
  }
  const v = verdict(rows);
  evidence.clauses = rows;
  evidence.verdict = v;
  console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
  for (const a of v.absences) console.log(`NAMED  clause ${a.n}: ${a.what.slice(0, 170)} → ${a.owner.slice(0, 120)}`);
  return v;
}

// ---- main -------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = (await mutation()) ? 0 : 1;
  else if (MODE === "mint") {
    const target = path.resolve(ROOT, flagValue("--mint-records"));
    const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
    if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary}`);
    process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
    const run = await runLeg({ mintTo: target });
    evidence.run = run;
    console.log(`RUN ${run.findings.length === 0 ? "green" : run.findings.join("; ")} · records ${run.minted ?? "not written"} · attested ${JSON.stringify(run.attested ?? {})}`);
    exit = run.findings.length === 0 ? 0 : 1;
  } else {
    await drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "machine-product-profile-qualification", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
