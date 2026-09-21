// M12.15 — the machine-product profile qualification certificate, as pure functions.
// (docs/architecture/components/hypervisor/providers-and-environments.md § Machine-control contract family;
// core-clients-surfaces.md § the bundles; _meta/public-web-estate.md § Subject-specific compute claims;
// byo-provider-plane.md § Attached-estate claim journey; register R-216.)
//
// A CERTIFICATE THAT CAN ONLY READ DOWN. Canon binds every Workstation and attached-Infrastructure statement to
// one subject-specific claim, the exact release/profile/backend matrix and fresh evidence, closable and
// withdrawable on its own, and says that simulated-only evidence may validate the contract and never qualify a
// public host or attached-estate matrix. So `assembleProfileCertificate` derives `qualification` from the
// evidence and never takes it as an input: `qualified` is reachable from `live` backend evidence with no reason
// against it, `not_qualified` names its typed reasons, and `withdraw` moves a certificate down when its evidence
// expires, its declaration drifts or its release is no longer the one that ran. Nothing here fetches, reads a
// file or reads the environment: the runner hands in records, this module hands back a certificate.
//
// The two profiles are DEFINED here as canon's matrices — the verbs a backend must support for the bundle and
// the resource relationship the bundle names — and pinned by digest in the gate's drills. The admitted backend
// set of each profile is, in this cut, the simulated reference pair (declarations planted as records; a
// registration route is M09.11's named absence); a real backend joins a profile by registration, never by
// editing this table.

import crypto from "node:crypto";

export const CERTIFICATE_SCHEMA = "ioi.hypervisor.machine-profile-qualification-certificate.v1";
export const CERTIFICATE_CONTRACT_ID = "schema://ioi/components/hypervisor/hypervisor-machine-profile-qualification-certificate/v1";
export const VERBS = Object.freeze(["discover", "define", "import", "create", "start", "stop", "pause", "resume", "reboot", "open_console", "close_console", "snapshot", "clone", "restore", "migrate", "delete"]);
const PORTABLE = VERBS.filter((v) => !["clone", "restore", "migrate"].includes(v));
export const PROFILES = Object.freeze({
  workstation_hosted_v1: Object.freeze({
    bundle: "hypervisor_workstation",
    resource_relationship: "local",
    other_profile: "infrastructure_attached_v1",
    required_supported: Object.freeze([...PORTABLE, "clone", "restore"]),
    admitted_backends: Object.freeze(["backend://reference/workstation-hosted"]),
  }),
  infrastructure_attached_v1: Object.freeze({
    bundle: "hypervisor_infrastructure",
    resource_relationship: "customer_attached",
    other_profile: "workstation_hosted_v1",
    required_supported: Object.freeze([...PORTABLE.filter((v) => !v.endsWith("_console")), "migrate"]),
    admitted_backends: Object.freeze(["backend://reference/infrastructure-attached"]),
  }),
});
export const DOES_NOT_QUALIFY_ALWAYS = Object.freeze(["hypervisoros_node_root_v1", "type_1", "type_2", "legacy_replacement"]);
export const EVIDENCE_KINDS_REFUSED = Object.freeze(["vm_boot", "hostile_guest_test", "downloadable_binary", "bootable_image", "generated_dashboard", "backend_declaration", "autonomy_proof", "provider_portability", "packaging", "simulated_only_as_host_compatibility", "other_profile_evidence"]);
export const NOT_QUALIFIED_REASONS = Object.freeze(["evidence_basis_simulated", "evidence_basis_declared", "no_live_backend_registered", "release_unbound", "supported_cells_untested", "guest_matrix_undeclared", "limitations_undeclared", "delivery_form_missing", "freshness_expired", "declaration_drifted", "evidence_window_empty", "required_cell_unsupported", "cross_profile_evidence"]);
export const WITHDRAWAL_REASONS = Object.freeze(["freshness_expired", "declaration_drifted", "release_unbound", "evidence_basis_downgraded", "owner_withdrawn"]);
export const CERTIFICATE_MEMBERS = Object.freeze(["schema_version", "certificate_ref", "certificate_hash", "profile_id", "bundle", "does_not_qualify", "subject", "release", "matrix", "delivery_forms", "evidence_runs", "freshness", "qualification", "evidence_basis", "not_qualified_reasons", "refused_evidence", "nonclaims", "issuer", "withdrawal"]);
export const VALIDITY_POLICY_REF = "policy://ioi/hypervisor/machine-profile-qualification/validity/30d";
export const VALIDITY_DAYS = 30;
export const NONCLAIMS = Object.freeze([
  "A VM boot, hostile-guest test, downloadable binary, bootable image, generated dashboard, backend declaration or autonomy proof is not profile qualification.",
  "A focused standalone client is not a second runtime, database, machine owner, provider owner, authority path or receipt writer.",
  "The portable subset does not erase backend-specific extensions or turn an unsupported operation into simulated success.",
  "ODK scaffolding does not certify correctness, compatibility or authority and need not generate native streaming, graphics, device or host integrations.",
  "Attached-Infrastructure qualification does not claim that Hypervisor is the attached estate's underlying VMM.",
  "This certificate grants no HypervisorOS, Type-1, cluster, HA, live-migration, disaster-recovery, drop-in replacement or supersession claim.",
  "Simulated-only evidence validates the contract and never qualifies a public host or attached-estate matrix; a not_qualified certificate is not a lesser positive.",
  "Evidence for one profile never promotes the other; each certificate is closable and withdrawable on its own.",
]);

export function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}
export const sha256 = (text) => `sha256:${crypto.createHash("sha256").update(text).digest("hex")}`;
export const digestOf = (value) => sha256(stableStringify(value));
export function certificateHash(certificate) {
  const copy = structuredClone(certificate);
  delete copy.certificate_hash;
  return digestOf(copy);
}
export function sealProfileCertificate(unsealed) {
  const certificate = structuredClone(unsealed);
  certificate.schema_version = CERTIFICATE_SCHEMA;
  certificate.certificate_hash = certificateHash(certificate);
  return certificate;
}

const HASH = /^sha256:[0-9a-f]{64}$/u;
const INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$/u;
const REF = /^[a-z][a-z0-9+.-]*:\/\/\S+$/u;
const SECRET_PATTERNS = [/"(?:password|session_token|api_key|sealed_token|recovery_material|mnemonic|private_key)"\s*:/iu, /ioi_sess_[A-Za-z0-9_-]+/u, /ioi_bootstrap_[A-Za-z0-9_-]+/u, /(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}/u];
const isoPlusDays = (iso, days) => new Date(new Date(iso).getTime() + days * 86_400_000).toISOString().replace(/\.\d{3}Z$/u, ".000Z");

/**
 * Assemble ONE profile's certificate from durable records. Derives everything; takes no verdict.
 *   profile_id        workstation_hosted_v1 | infrastructure_attached_v1
 *   declaration       the backend capability declaration RECORD as the daemon holds it (bytes → digest here)
 *   readModels        the daemon's read model for every workload evidenced (GET /v1/hypervisor/machines/:workload → machine)
 *   deliveryForms     { integrated: {form, evidence_ref, evidence_sha256}|null, standalone: {...}|null }
 *   release           { source_commit, daemon_binary_sha256, release_manifest_sha256, release_version, signer_key_id, dirty_state_declaration }
 *   issuedAt          the instant the certificate is issued (from the record set, so regeneration is byte-identical)
 *   presented         artifacts presented as evidence: [{kind, ref}] — refused by kind, never admitted
 *   issuer            { verifier_identity_ref, verifier_build_hash }
 */
export function assembleProfileCertificate({ profile_id, declaration, readModels, deliveryForms, release, issuedAt, presented = [], issuer, validityDays = VALIDITY_DAYS }) {
  const profile = PROFILES[profile_id];
  if (!profile) throw new Error(`unknown_profile:${profile_id}`);
  if (!declaration || typeof declaration !== "object") throw new Error("declaration_required");
  if (!Array.isArray(readModels) || readModels.length === 0) throw new Error("read_models_required");
  if (!INSTANT.test(String(issuedAt))) throw new Error("issued_at_required");
  const reasons = new Set();
  const backendRef = String(declaration.backend_registration_ref ?? "");
  if (!profile.admitted_backends.includes(backendRef)) reasons.add("cross_profile_evidence");
  const evidenceMode = ["live", "simulated", "declared"].includes(declaration.evidence_mode) ? declaration.evidence_mode : "none";
  if (evidenceMode === "simulated") reasons.add("evidence_basis_simulated");
  if (evidenceMode === "declared") reasons.add("evidence_basis_declared");
  if (evidenceMode !== "live") reasons.add("no_live_backend_registered");
  // the evidence runs: every workload's receipts, by ref and hash, with the verb each answers
  const runs = readModels.map((m) => {
    const ops = Array.isArray(m.operations) ? m.operations : [];
    const verbOf = (operationRef) => ops.find((o) => o.operation_ref === operationRef)?.operation ?? "unknown";
    const times = ops.map((o) => o.submitted_at).filter((t) => INSTANT.test(String(t))).sort();
    const receipts = (Array.isArray(m.receipts) ? m.receipts : []).map((r) => ({ receipt_ref: r.receipt_ref, receipt_sha256: digestOf(r), operation: verbOf(r.operation_ref), result: r.result }));
    return { kind: "machine_lifecycle_run", workload_ref: m.workload_ref, head: m.head ?? null, operation_count: ops.length, receipts, window: { from: times[0] ?? issuedAt, to: times.at(-1) ?? issuedAt } };
  });
  const exercised = new Set(runs.flatMap((r) => r.receipts.filter((x) => x.result === "succeeded").map((x) => x.operation)));
  if (runs.every((r) => r.receipts.length === 0)) reasons.add("evidence_window_empty");
  const unsupported = new Map((Array.isArray(declaration.unsupported_operations) ? declaration.unsupported_operations : []).map((u) => [u.operation, u.reason_code]));
  const supported = new Set(Array.isArray(declaration.supported_operations) ? declaration.supported_operations : []);
  const verbs = VERBS.map((operation) => {
    if (unsupported.has(operation)) return { operation, status: "unsupported", reason_code: unsupported.get(operation) ?? "unsupported_by_declaration" };
    if (supported.has(operation)) return { operation, status: exercised.has(operation) ? "supported" : "untested", reason_code: null };
    return { operation, status: "unsupported", reason_code: "not_declared" };
  });
  if (verbs.some((v) => v.status === "untested")) reasons.add("supported_cells_untested");
  if (profile.required_supported.some((v) => verbs.find((x) => x.operation === v)?.status === "unsupported")) reasons.add("required_cell_unsupported");
  const guests = [];
  if (guests.length === 0) reasons.add("guest_matrix_undeclared");
  const limitations = Array.isArray(declaration.limitations) ? declaration.limitations.map(String) : [];
  if (limitations.length === 0) reasons.add("limitations_undeclared");
  const forms = { integrated: deliveryForms?.integrated ?? null, standalone: deliveryForms?.standalone ?? null };
  if (!forms.integrated || !forms.standalone) reasons.add("delivery_form_missing");
  const rel = release ?? {};
  if (!HASH.test(String(rel.release_manifest_sha256 ?? ""))) reasons.add("release_unbound");
  const froms = runs.map((r) => r.window.from).sort(); const tos = runs.map((r) => r.window.to).sort();
  const subject = { backend_registration_ref: backendRef, capability_declaration_ref: String(declaration.declaration_ref ?? ""), capability_declaration_hash_declared: String(declaration.declaration_hash ?? ""), capability_declaration_bytes_sha256: digestOf(declaration), evidence_mode: evidenceMode === "none" ? "declared" : evidenceMode, resource_relationship: profile.resource_relationship, vmm_ownership_claimed: false };
  const qualification = reasons.size === 0 && evidenceMode === "live" ? "qualified" : "not_qualified";
  const unsealed = {
    schema_version: CERTIFICATE_SCHEMA,
    certificate_ref: `machine-profile-certificate://${profile_id}/${digestOf({ subject, from: froms[0], to: tos.at(-1), runs: runs.map((r) => r.workload_ref) }).slice(7, 31)}`,
    profile_id,
    bundle: profile.bundle,
    does_not_qualify: [profile.other_profile, ...DOES_NOT_QUALIFY_ALWAYS],
    subject,
    release: { source_commit: rel.source_commit ?? null, daemon_binary_sha256: rel.daemon_binary_sha256 ?? null, release_manifest_sha256: rel.release_manifest_sha256 ?? null, release_version: rel.release_version ?? null, signer_key_id: rel.signer_key_id ?? null, dirty_state_declaration: String(rel.dirty_state_declaration ?? "unknown") },
    matrix: { verbs, architectures: Array.isArray(declaration.supported_machine_architectures) ? declaration.supported_machine_architectures.map(String) : [], guests, limitations },
    delivery_forms: forms,
    evidence_runs: runs,
    freshness: { evidence_window: { from: froms[0], to: tos.at(-1) }, issued_at: issuedAt, valid_until: isoPlusDays(issuedAt, validityDays), validity_policy_ref: VALIDITY_POLICY_REF, currentness_evaluation_ref: String(declaration.currentness_evaluation_ref ?? "evaluation://unrecorded") },
    qualification,
    evidence_basis: evidenceMode,
    not_qualified_reasons: [...reasons].filter((r) => NOT_QUALIFIED_REASONS.includes(r)).sort(),
    refused_evidence: presented.filter((p) => EVIDENCE_KINDS_REFUSED.includes(p?.kind)).map((p) => ({ kind: p.kind, ref: String(p.ref), reason: "not_qualification_evidence" })),
    nonclaims: [...NONCLAIMS],
    issuer: { verifier_identity_ref: String(issuer?.verifier_identity_ref ?? "verifier://ioi/check-machine-product-profile-qualification/v1"), verifier_build_hash: issuer?.verifier_build_hash ?? null },
    withdrawal: null,
  };
  return sealProfileCertificate(unsealed);
}

/** Present an artifact as evidence: it is refused by kind and never enters the runs. */
export function refuseEvidenceArtifact(kind, ref) {
  if (!EVIDENCE_KINDS_REFUSED.includes(kind)) return { refused: false, code: "kind_not_in_refusal_vocabulary" };
  return { refused: true, code: "not_qualification_evidence", kind, ref: String(ref) };
}

/** Move a certificate DOWN. Never up. */
export function withdraw(certificate, reason, at, detail) {
  if (!WITHDRAWAL_REASONS.includes(reason)) throw new Error(`withdrawal_reason_unknown:${reason}`);
  const next = structuredClone(certificate);
  delete next.certificate_hash;
  next.qualification = "withdrawn";
  const reasons = new Set(next.not_qualified_reasons ?? []);
  if (NOT_QUALIFIED_REASONS.includes(reason)) reasons.add(reason);
  if (reasons.size === 0) reasons.add("no_live_backend_registered");
  next.not_qualified_reasons = [...reasons].sort();
  next.withdrawal = { reason, at, detail: String(detail ?? reason) };
  return sealProfileCertificate(next);
}

/**
 * The OFFLINE verifier. Structural checks restate the registered contract; the context checks are what a
 * relying party asks with what it holds now: the current declaration bytes, the current daemon, the clock.
 */
export function validateProfileCertificate(certificate, { now = null, currentDeclarationBytesSha256 = null, currentDaemonSha256 = null } = {}) {
  const failures = [];
  const fail = (code, path, detail) => failures.push({ code, path, detail });
  const c = certificate ?? {};
  if (c.schema_version !== CERTIFICATE_SCHEMA) fail("schema_version_invalid", "schema_version", "not this contract");
  for (const k of Object.keys(c)) if (!CERTIFICATE_MEMBERS.includes(k)) fail("unknown_member", k, "the contract closes the certificate against extra members");
  for (const k of CERTIFICATE_MEMBERS) if (!(k in c)) fail("member_missing", k, "a required member is absent");
  if (!HASH.test(String(c.certificate_hash ?? "")) || certificateHash(c) !== c.certificate_hash) fail("certificate_hash_mismatch", "certificate_hash", "the hash does not cover these bytes");
  const profile = PROFILES[c.profile_id];
  if (!profile) fail("profile_unknown", "profile_id", String(c.profile_id));
  if (profile && c.bundle !== profile.bundle) fail("bundle_mismatch", "bundle", `${c.bundle} is not ${profile.bundle}`);
  if (profile && !(Array.isArray(c.does_not_qualify) && c.does_not_qualify.includes(profile.other_profile))) fail("does_not_qualify_missing_other_profile", "does_not_qualify", "evidence from one profile never promotes the other");
  if (Array.isArray(c.does_not_qualify) && !DOES_NOT_QUALIFY_ALWAYS.every((x) => c.does_not_qualify.includes(x))) fail("does_not_qualify_missing_external_mappings", "does_not_qualify", "Type 1, Type 2, node-root and supersession are never claimed");
  const s = c.subject ?? {};
  if (s.vmm_ownership_claimed !== false) fail("vmm_ownership_claimed", "subject.vmm_ownership_claimed", "Hypervisor is never the estate's VMM");
  if (profile && s.resource_relationship !== profile.resource_relationship) fail("resource_relationship_mismatch", "subject.resource_relationship", `${s.resource_relationship} is not ${profile.resource_relationship}`);
  if (profile && !profile.admitted_backends.includes(String(s.backend_registration_ref))) fail("cross_profile_evidence", "subject.backend_registration_ref", "the backend is not admitted to this profile");
  if (!HASH.test(String(s.capability_declaration_bytes_sha256 ?? "")) || !HASH.test(String(s.capability_declaration_hash_declared ?? ""))) fail("declaration_binding_malformed", "subject", "both the carried hash and the recomputed digest are required");
  if (!["live", "simulated", "declared"].includes(s.evidence_mode)) fail("evidence_mode_invalid", "subject.evidence_mode", String(s.evidence_mode));
  if (c.evidence_basis !== "none" && c.evidence_basis !== s.evidence_mode) fail("evidence_mode_relabelled", "evidence_basis", `${c.evidence_basis} is not the declaration's ${s.evidence_mode}`);
  if (c.qualification === "qualified" && c.evidence_basis !== "live") fail("qualified_without_live_basis", "qualification", "only live backend evidence qualifies");
  if (c.qualification === "qualified" && (c.not_qualified_reasons ?? []).length > 0) fail("qualified_with_reasons", "not_qualified_reasons", "a qualified certificate carries no reason against it");
  if (c.qualification === "qualified" && c.withdrawal !== null) fail("qualified_with_withdrawal", "withdrawal", "a qualified certificate is not withdrawn");
  if (["not_qualified", "withdrawn"].includes(c.qualification) && !(Array.isArray(c.not_qualified_reasons) && c.not_qualified_reasons.length > 0)) fail("not_qualified_without_reason", "not_qualified_reasons", "a downgrade names its reasons");
  if (Array.isArray(c.not_qualified_reasons) && !c.not_qualified_reasons.every((r) => NOT_QUALIFIED_REASONS.includes(r))) fail("reason_not_in_vocabulary", "not_qualified_reasons", "closed vocabulary");
  if (c.qualification === "withdrawn" && !(c.withdrawal && WITHDRAWAL_REASONS.includes(c.withdrawal.reason) && INSTANT.test(String(c.withdrawal.at)))) fail("withdrawn_without_withdrawal", "withdrawal", "a withdrawal names its reason and time");
  if (c.qualification !== "withdrawn" && c.withdrawal !== null) fail("withdrawal_without_withdrawn", "withdrawal", "only a withdrawn certificate carries a withdrawal");
  if (!["qualified", "not_qualified", "withdrawn"].includes(c.qualification)) fail("qualification_invalid", "qualification", String(c.qualification));
  const verbs = Array.isArray(c.matrix?.verbs) ? c.matrix.verbs : [];
  if (verbs.length !== 16 || new Set(verbs.map((v) => v.operation)).size !== 16 || !VERBS.every((v) => verbs.some((x) => x.operation === v))) fail("verb_matrix_incomplete", "matrix.verbs", "the sixteen verbs, each once");
  for (const v of verbs) {
    if (!["supported", "unsupported", "untested"].includes(v.status)) fail("verb_status_invalid", `matrix.verbs.${v.operation}`, String(v.status));
    if (v.status === "unsupported" && !(typeof v.reason_code === "string" && v.reason_code.length > 0)) fail("unsupported_cell_without_reason", `matrix.verbs.${v.operation}`, "an unsupported cell names its reason");
    if (v.status !== "unsupported" && v.reason_code !== null) fail("supported_cell_with_reason", `matrix.verbs.${v.operation}`, "only an unsupported cell carries a reason");
  }
  if (profile && c.qualification === "qualified" && profile.required_supported.some((v) => verbs.find((x) => x.operation === v)?.status !== "supported")) fail("qualified_with_required_cell_not_supported", "matrix.verbs", "a qualified profile exercised every required verb");
  if (verbs.some((v) => v.status === "untested") && !(c.not_qualified_reasons ?? []).includes("supported_cells_untested")) fail("untested_cell_unnamed", "not_qualified_reasons", "an untested cell is named as a reason");
  if (!Array.isArray(c.matrix?.limitations)) fail("limitations_missing", "matrix.limitations", "the declared limitations are carried, empty or not");
  const runs = Array.isArray(c.evidence_runs) ? c.evidence_runs : [];
  if (runs.length === 0) fail("evidence_runs_empty", "evidence_runs", "at least one run");
  for (const r of runs) {
    if (r.kind !== "machine_lifecycle_run") fail("refused_evidence_kind_admitted", "evidence_runs.kind", String(r.kind));
    if (!REF.test(String(r.workload_ref))) fail("evidence_run_malformed", "evidence_runs.workload_ref", String(r.workload_ref));
    for (const x of Array.isArray(r.receipts) ? r.receipts : []) if (!HASH.test(String(x.receipt_sha256 ?? "")) || !["succeeded", "refused", "ambiguous"].includes(x.result)) fail("receipt_binding_malformed", "evidence_runs.receipts", String(x.receipt_ref));
  }
  for (const p of Array.isArray(c.refused_evidence) ? c.refused_evidence : []) if (!EVIDENCE_KINDS_REFUSED.includes(p.kind) || p.reason !== "not_qualification_evidence") fail("refused_evidence_malformed", "refused_evidence", String(p.kind));
  const f = c.freshness ?? {};
  if (!(INSTANT.test(String(f.issued_at)) && INSTANT.test(String(f.valid_until)) && f.valid_until > f.issued_at)) fail("freshness_malformed", "freshness", "issued_at and a later valid_until are required");
  if (!c.delivery_forms || !("integrated" in c.delivery_forms) || !("standalone" in c.delivery_forms)) fail("delivery_forms_missing", "delivery_forms", "both members, null when absent");
  else if ((!c.delivery_forms.integrated || !c.delivery_forms.standalone) && !(c.not_qualified_reasons ?? []).includes("delivery_form_missing")) fail("delivery_form_missing_unnamed", "delivery_forms", "a missing form is named as a reason");
  if (!(Array.isArray(c.nonclaims) && c.nonclaims.length >= 6 && NONCLAIMS.every((n) => c.nonclaims.includes(n)))) fail("nonclaims_missing", "nonclaims", "the ACC-20 negative clauses are carried verbatim");
  if (!REF.test(String(c.issuer?.verifier_identity_ref ?? ""))) fail("issuer_missing", "issuer", "the verifier that issued it");
  const serialized = JSON.stringify(c);
  if (SECRET_PATTERNS.some((p) => p.test(serialized))) fail("secret_bearing_artifact", "$", "certificate contains credential or bearer material");
  // context: what the relying party holds now
  let withdrawReason = null;
  if (now && INSTANT.test(String(f.valid_until)) && String(now) > String(f.valid_until) && c.qualification !== "withdrawn") { fail("freshness_expired", "freshness.valid_until", `expired at ${f.valid_until}`); withdrawReason ??= "freshness_expired"; }
  if (currentDeclarationBytesSha256 && currentDeclarationBytesSha256 !== s.capability_declaration_bytes_sha256 && c.qualification !== "withdrawn") { fail("declaration_digest_mismatch", "subject.capability_declaration_bytes_sha256", "the declaration's bytes moved under the certificate"); withdrawReason ??= "declaration_drifted"; }
  if (currentDaemonSha256 && c.release?.daemon_binary_sha256 && currentDaemonSha256 !== c.release.daemon_binary_sha256 && c.qualification !== "withdrawn") { fail("release_daemon_mismatch", "release.daemon_binary_sha256", "the daemon that runs now is not the one that ran"); withdrawReason ??= "release_unbound"; }
  return { ok: failures.length === 0, failures, withdraw: withdrawReason };
}

/** Two certificates, one per profile: independent or not. */
export function independenceFindings(hosted, attached) {
  const f = [];
  if (hosted?.profile_id !== "workstation_hosted_v1" || attached?.profile_id !== "infrastructure_attached_v1") f.push("profiles_not_the_pair");
  if (hosted?.subject?.backend_registration_ref === attached?.subject?.backend_registration_ref) f.push("backends_shared");
  if (hosted?.subject?.capability_declaration_ref === attached?.subject?.capability_declaration_ref) f.push("declarations_shared");
  const receipts = (c) => new Set((c?.evidence_runs ?? []).flatMap((r) => r.receipts.map((x) => x.receipt_sha256)));
  const a = receipts(hosted); const b = receipts(attached);
  if ([...a].some((x) => b.has(x))) f.push("evidence_shared");
  if (!(hosted?.does_not_qualify ?? []).includes("infrastructure_attached_v1") || !(attached?.does_not_qualify ?? []).includes("workstation_hosted_v1")) f.push("other_profile_not_disclaimed");
  if (hosted?.certificate_hash === attached?.certificate_hash) f.push("certificates_identical");
  if (attached?.subject?.vmm_ownership_claimed !== false) f.push("attached_claims_vmm");
  return f;
}
