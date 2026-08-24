import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { stableStringify } from "./c7-c8-certificate.mjs";

export const C8_V3_SCHEMA = "ioi.components.hypervisor.c8-certificate.v3";
export const BUNDLE_V1_SCHEMA = "ioi.components.hypervisor.c8-portable-evidence-bundle.v1";

const SELF_HASH_FIELDS = new Map([
  [C8_V3_SCHEMA, "certificate_hash"],
  [BUNDLE_V1_SCHEMA, "bundle_hash"],
  ["ioi.foundations.relying-party-acceptance-policy.v1", "policy_hash"],
  ["ioi.foundations.verifier-independence-profile.v1", "profile_hash"],
  ["ioi.components.hypervisor.governed-effect-claim-manifest.v1", "manifest_hash"],
  ["ioi.components.hypervisor.workload-isolation-binding.v1", "binding_hash"],
  ["ioi.components.hypervisor.workload-isolation-requirements.v1", "requirements_hash"],
  ["ioi.foundations.standing-authority-envelope.v1", "body_hash"],
  ["ioi.foundations.authority-trajectory-state.v1", "trajectory_state_hash"],
  ["ioi.foundations.trajectory-admission-decision.v1", "decision_hash"],
  ["ioi.aft.measured-results-registry.v1", "state_hash"],
  ["ioi.aft.measured-result-row.v1", "row_hash"],
  ["ioi.foundations.certificate-acceptance-receipt.v1", "receipt_hash"],
  ["ioi.hypervisor.auth-factor-receipt.v1", "receipt_hash"],
]);

const sha256 = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
const clone = (value) => structuredClone(value);
const hashPattern = /^sha256:[0-9a-f]{64}$/u;
const refPattern = /^[a-z][a-z0-9+.-]*:\/\/\S{1,500}$/u;
const filePattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}[.]json$/u;
const bindingKey = (ref, hash) => `${ref}\u0000${hash}`;
const CANONICAL_JSON_PREIMAGE_V1 = "ioi.foundations.canonical-json-preimage.v1";

export function hashWithout(value, field) {
  const copy = clone(value);
  delete copy[field];
  return sha256(stableStringify(copy));
}

export function contentHash(value) {
  if (value?.schema_version === CANONICAL_JSON_PREIMAGE_V1) {
    if (typeof value.canonical_json !== "string") throw new Error("canonical JSON preimage is missing canonical_json");
    JSON.parse(value.canonical_json);
    return sha256(value.canonical_json);
  }
  const field = SELF_HASH_FIELDS.get(value?.schema_version);
  return field ? hashWithout(value, field) : sha256(stableStringify(value));
}

export function sealSelfHash(value) {
  const copy = clone(value);
  const field = SELF_HASH_FIELDS.get(copy?.schema_version);
  if (!field) throw new Error(`object schema has no registered self-hash field: ${copy?.schema_version}`);
  copy[field] = hashWithout(copy, field);
  return copy;
}

const requireRef = (value, label) => {
  if (!refPattern.test(value || "")) throw new Error(`${label} is not a canonical ref`);
};

export function indexPortableArtifacts(entries) {
  const byBinding = new Map();
  const byRef = new Map();
  for (const entry of entries) {
    const key = bindingKey(entry.ref, entry.hash);
    if (byBinding.has(key)) throw new Error(`duplicate portable object binding: ${entry.ref} ${entry.hash}`);
    byBinding.set(key, entry);
    const candidates = byRef.get(entry.ref) || [];
    candidates.push(entry);
    byRef.set(entry.ref, candidates);
  }
  return { byBinding, byRef };
}

export function resolvePortableArtifact(index, ref, preferredHash = null) {
  const candidates = index.byRef.get(ref) || [];
  if (hashPattern.test(preferredHash || "")) {
    const exact = index.byBinding.get(bindingKey(ref, preferredHash));
    if (!exact) throw new Error(`portable object binding is missing: ${ref} ${preferredHash}`);
    return exact;
  }
  if (candidates.length === 1) return candidates[0];
  if (candidates.length === 0) throw new Error(`portable object is missing: ${ref}`);
  throw new Error(`portable object ref is version-ambiguous without a hash: ${ref}`);
}

const bind = (certificate, objectIndex, refField, hashField) => {
  const ref = certificate[refField];
  requireRef(ref, refField);
  const entry = resolvePortableArtifact(objectIndex, ref, certificate[hashField]);
  certificate[hashField] = entry.hash;
};

const bindNested = (certificate, objectIndex, objectField, pairs) => {
  const object = certificate[objectField];
  if (!object || typeof object !== "object") throw new Error(`${objectField} is missing`);
  for (const [refField, hashField] of pairs) bind(object, objectIndex, refField, hashField);
};

const bindList = (certificate, objectIndex, field) => {
  if (!Array.isArray(certificate[field]) || certificate[field].length === 0) throw new Error(`${field} must be a non-empty array`);
  certificate[field] = certificate[field].map((value) => {
    const ref = typeof value === "string" ? value : value?.ref;
    requireRef(ref, `${field}.ref`);
    const entry = resolvePortableArtifact(objectIndex, ref, typeof value === "string" ? null : value?.hash);
    return { ref, hash: entry.hash };
  });
};

export function bindAndSealC8V3(draft, objectIndex) {
  const certificate = clone(draft);
  certificate.schema_version = C8_V3_SCHEMA;
  for (const [refField, hashField] of [
    ["predecessor_certificate_ref", "predecessor_certificate_hash"],
    ["governed_request_ref", "governed_request_hash"],
    ["claim_manifest_ref", "claim_manifest_hash"],
    ["isolation_binding_ref", "isolation_binding_hash"],
    ["campaign_certificate_ref", "campaign_certificate_hash"],
    ["result_contract_ref", "result_contract_hash"],
    ["result_ref", "result_hash"],
    ["result_retrieval_receipt_ref", "result_retrieval_receipt_hash"],
    ["environment_ref", "environment_hash"],
    ["variance_evidence_ref", "variance_evidence_hash"],
    ["terminal_settlement_ref", "terminal_settlement_hash"],
  ]) bind(certificate, objectIndex, refField, hashField);
  for (const field of ["source_basis_refs", "workload_readiness_evidence", "secret_use_evidence", "terminal_acceptance_prerequisites"]) {
    bindList(certificate, objectIndex, field);
  }
  bindNested(certificate, objectIndex, "authority_draw", [
    ["standing_envelope_ref", "standing_envelope_hash"],
    ["draw_request_ref", "draw_request_hash"],
    ["draw_receipt_ref", "draw_receipt_hash"],
  ]);
  bindNested(certificate, objectIndex, "trajectory_binding", [
    ["state_before_ref", "state_before_hash"],
    ["decision_ref", "decision_hash"],
    ["state_after_ref", "state_after_hash"],
  ]);
  certificate.certificate_hash = hashWithout(certificate, "certificate_hash");
  return certificate;
}

function safeArtifact(spec, kind) {
  requireRef(spec?.ref, `${kind}.ref`);
  if (!filePattern.test(spec?.file || "")) throw new Error(`${kind}.file is unsafe`);
  if (typeof spec?.schema_ref !== "string" || !spec.schema_ref.startsWith("schema://")) throw new Error(`${kind}.schema_ref is invalid`);
  const source = path.resolve(spec.path);
  const stat = fs.lstatSync(source);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024 * 1024) throw new Error(`${kind}.path is unsafe`);
  let value = JSON.parse(fs.readFileSync(source, "utf8"));
  if (SELF_HASH_FIELDS.has(value?.schema_version)) value = sealSelfHash(value);
  return { ref: spec.ref, file: spec.file, schema_ref: spec.schema_ref, value, hash: contentHash(value) };
}

function assertNoSecretMaterial(value) {
  const serialized = JSON.stringify(value);
  const patterns = [
    /"(?:password|session_token|api_key|sealed_token|recovery_material|mnemonic|private_key|unlock_secret)"\s*:/iu,
    /ioi_sess_[A-Za-z0-9_-]+/u,
    /ioi_bootstrap_[A-Za-z0-9_-]+/u,
    /(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}/u,
  ];
  if (patterns.some((pattern) => pattern.test(serialized))) throw new Error("portable bundle contains secret-bearing material");
}

export function assemblePortableBundle(spec, outputDirectory) {
  if (fs.existsSync(outputDirectory)) throw new Error("output directory already exists");
  const objects = (spec.objects || []).map((entry) => safeArtifact(entry, "object"));
  const trustInputs = (spec.trust_inputs || []).map((entry) => safeArtifact(entry, "trust_input"));
  const names = new Set();
  const bindings = new Set();
  for (const entry of [...objects, ...trustInputs]) {
    const key = bindingKey(entry.ref, entry.hash);
    if (names.has(entry.file) || bindings.has(key)) throw new Error("duplicate portable filename or ref/hash binding");
    names.add(entry.file);
    bindings.add(key);
  }
  const objectIndex = indexPortableArtifacts([...objects, ...trustInputs]);
  const claimEntry = objects.find((entry) => entry.schema_ref === "schema://ioi/components/hypervisor/governed-effect-claim-manifest/v1");
  if (!claimEntry) throw new Error("claim manifest object is required");
  const governedRequest = resolvePortableArtifact(objectIndex, claimEntry.value?.subject_ref, claimEntry.value?.subject_hash);
  if (!governedRequest || claimEntry.value?.subject_hash !== governedRequest.hash) throw new Error("claim manifest subject must bind the governed request object");
  const draft = JSON.parse(fs.readFileSync(path.resolve(spec.certificate_draft_path), "utf8"));
  const certificate = bindAndSealC8V3(draft, objectIndex);
  requireRef(spec.bundle_ref, "bundle_ref");
  requireRef(certificate.certificate_ref, "certificate_ref");
  const certificateFile = spec.certificate_file || "certificate.json";
  if (!filePattern.test(certificateFile) || names.has(certificateFile) || certificateFile === "bundle.json") throw new Error("certificate filename is unsafe or duplicated");
  const descriptor = (entry) => ({ ref: entry.ref, hash: entry.hash, schema_ref: entry.schema_ref, file: entry.file });
  const bundle = sealSelfHash({
    schema_version: BUNDLE_V1_SCHEMA,
    bundle_ref: spec.bundle_ref,
    certificate_ref: certificate.certificate_ref,
    certificate_hash: certificate.certificate_hash,
    certificate_file: certificateFile,
    objects: objects.map(descriptor),
    trust_inputs: trustInputs.map(descriptor),
    created_at: spec.created_at || new Date().toISOString(),
  });
  assertNoSecretMaterial({ bundle, certificate, objects: objects.map((entry) => entry.value), trust_inputs: trustInputs.map((entry) => entry.value) });
  fs.mkdirSync(outputDirectory, { recursive: false, mode: 0o700 });
  const write = (file, value) => fs.writeFileSync(path.join(outputDirectory, file), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  for (const entry of [...objects, ...trustInputs]) write(entry.file, entry.value);
  write(certificateFile, certificate);
  write("bundle.json", bundle);
  return { bundle, certificate };
}

export function validatePortableBundleShape(bundle) {
  const failures = [];
  if (bundle?.schema_version !== BUNDLE_V1_SCHEMA) failures.push("bundle_schema_invalid");
  if (!hashPattern.test(bundle?.bundle_hash || "") || contentHash(bundle) !== bundle.bundle_hash) failures.push("bundle_hash_mismatch");
  if (!refPattern.test(bundle?.bundle_ref || "") || !refPattern.test(bundle?.certificate_ref || "")) failures.push("bundle_ref_invalid");
  if (!filePattern.test(bundle?.certificate_file || "")) failures.push("certificate_file_invalid");
  if (!Array.isArray(bundle?.objects) || bundle.objects.length < 10) failures.push("bundle_objects_incomplete");
  if (!Array.isArray(bundle?.trust_inputs) || bundle.trust_inputs.length < 2) failures.push("bundle_trust_inputs_incomplete");
  return { ok: failures.length === 0, failures };
}
