// M06.11 — THE CLEAN-ROOM VERIFIER. A second, independent implementation of C8 v3 portable-evidence-bundle
// verification, written from the published schemas, the published canonicalization rule and the published
// vector corpus — and from nothing else.
//
// WHY A SECOND IMPLEMENTATION EXISTS AT ALL. The estate had exactly one bundle verifier, `crates/aft-c8-verifier`.
// A single verifier can be right or wrong and nobody can tell from the outside: "the published bytes are
// sufficient" is a claim about a SPECIFICATION, and a specification with one reader has never been read. This
// file is the second reader. It reaches the same verdict and the same typed refusal code as the canonical
// verifier over every published vector, or the gate that runs both goes red.
//
// WHAT THIS FILE MAY NOT DO, and what the gate asserts over its import closure rather than trusting this
// comment: it imports NOTHING but `node:` builtins. Not the estate's canonicalization (`stableStringify`), not
// its hashing (`contentHash`), not its generated contract projections, not a schema file read out of the repo.
// Its canonical JSON, its hashing rules, its self-hash table and its refusal vocabulary are all written out
// here from the published specification. If it imported the canonical implementation's helpers, both sides
// would move together and the differential would prove nothing — the one defect this file exists to rule out.
//
// WHAT IT CLAIMS AND DOES NOT CLAIM (ADR 0032's four axes). Separate binary: yes, a different program in a
// different language. Separate codegen: yes, its types are read from the published schemas by hand and never
// from a generated projection. Separate transport: yes, it reads a directory of bytes. Separate authoring
// party: NO — the same estate wrote both, and no run of this file may claim otherwise. That fourth axis needs
// a disclosed external principal, which is the unit's scheduled leg.
//
// REFUSAL PARITY IS THE CONTRACT. The canonical verifier bails on its FIRST failing rule and reports the first
// `:`-separated token of that failure as the code. This file follows the same order and the same vocabulary,
// because "both refuse" is not parity — a verifier that refused everything would satisfy it. The code must
// match.
//
//   node clean-room-bundle-verifier.mjs verify --bundle <dir> --policy <file> --now <rfc3339> [--json]
//
// Exit 0 accepted, 1 refused (the code on stdout as JSON with --json, on stderr otherwise), 2 usage.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const CLEAN_ROOM_VERIFIER_VERSION = "ioi.clean-room-bundle-verifier.v1";
const BUNDLE_V1 = "ioi.components.hypervisor.c8-portable-evidence-bundle.v1";
const POLICY_V1 = "ioi.foundations.relying-party-acceptance-policy.v1";
const PROFILE_V1 = "ioi.foundations.verifier-independence-profile.v1";
const C8_V3 = "ioi.components.hypervisor.c8-certificate.v3";
const RESULT_V1 = "ioi.aft.benchmark-campaign.v1";
const CLAIM_MANIFEST_V1 = "ioi.components.hypervisor.governed-effect-claim-manifest.v1";
const CANONICAL_JSON_PREIMAGE_V1 = "ioi.foundations.canonical-json-preimage.v1";
const STANDING_ENVELOPE_V1 = "ioi.foundations.standing-authority-envelope.v1";
const TRAJECTORY_DECISION_V1 = "ioi.foundations.trajectory-admission-decision.v1";
const MAX_JSON_BYTES = 16 * 1024 * 1024;

// The published self-hash table: which member each schema's content hash is computed WITHOUT.
const SELF_HASH_FIELDS = new Map([
  ["ioi.hypervisor.c7-c8-certificate.v2", "certificate_hash"],
  [C8_V3, "certificate_hash"],
  [BUNDLE_V1, "bundle_hash"],
  [POLICY_V1, "policy_hash"],
  [PROFILE_V1, "profile_hash"],
  [CLAIM_MANIFEST_V1, "manifest_hash"],
  ["ioi.components.hypervisor.workload-isolation-binding.v1", "binding_hash"],
  ["ioi.components.hypervisor.workload-isolation-requirements.v1", "requirements_hash"],
  [STANDING_ENVELOPE_V1, "body_hash"],
  ["ioi.foundations.authority-trajectory-state.v1", "trajectory_state_hash"],
  [TRAJECTORY_DECISION_V1, "decision_hash"],
  ["ioi.aft.measured-results-registry.v1", "state_hash"],
  ["ioi.aft.measured-result-row.v1", "row_hash"],
  ["ioi.foundations.certificate-acceptance-receipt.v1", "receipt_hash"],
  ["ioi.hypervisor.auth-factor-receipt.v1", "receipt_hash"],
]);

/** A refusal carrying the published typed code. Never a message a caller has to parse. */
export class Refusal extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
    this.detail = detail ?? null;
  }
}
const refuse = (code, detail) => { throw new Refusal(code, detail); };
const ensureEq = (actual, expected, code) => { if (actual !== expected) refuse(code, `${String(actual).slice(0, 80)} != ${String(expected).slice(0, 80)}`); };
const requiredStr = (value, key) => {
  const found = value && typeof value === "object" ? value[key] : undefined;
  if (typeof found !== "string") refuse(`missing_${key}`);
  return found;
};
const ensureValueStr = (value, key, expected) => ensureEq(requiredStr(value, key), expected, key);

// ---- canonical JSON (RFC 8785 for the value shapes the published schemas admit) ---------------------------
// Objects: members sorted by key as UTF-16 code units (what `Array.prototype.sort` does), no whitespace.
// Numbers: the shortest round-tripping form, which is what ECMAScript's own serializer produces for every
// finite double. Strings: JSON escaping. The published corpus carries no value this treatment cannot express;
// a NaN, an Infinity or a non-finite number is refused rather than serialized.
export function canonicalJson(value) {
  if (value === null) return "null";
  const type = typeof value;
  if (type === "boolean") return value ? "true" : "false";
  if (type === "number") {
    if (!Number.isFinite(value)) refuse("canonical_json_invalid", "non-finite number");
    return JSON.stringify(value);
  }
  if (type === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (type === "object") {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  }
  return refuse("canonical_json_invalid", `unserializable ${type}`);
}
const sha256 = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
export const hashValue = (value) => sha256(canonicalJson(value));
export function hashWithout(value, field) {
  const copy = { ...value };
  delete copy[field];
  return hashValue(copy);
}
/** The published content-hash rule, including its three schema-specific preimages. */
export function contentHash(value) {
  const schema = value && typeof value === "object" ? value.schema_version : undefined;
  if (schema === CANONICAL_JSON_PREIMAGE_V1) {
    const canonical = requiredStr(value, "canonical_json");
    try { JSON.parse(canonical); } catch { refuse("canonical_json_invalid"); }
    return sha256(canonical);
  }
  if (schema === STANDING_ENVELOPE_V1) {
    const copy = { ...value };
    delete copy.body_hash;
    return hashValue({ ...copy, domain: "ioi.standing-authority-envelope-jcs-sha256.v1" });
  }
  if (schema === TRAJECTORY_DECISION_V1) {
    const copy = { ...value };
    delete copy.decision_hash;
    delete copy.decision_ref;
    return hashValue(copy);
  }
  const field = SELF_HASH_FIELDS.get(schema);
  return field ? hashWithout(value, field) : hashValue(value);
}
const validateHashField = (value, field, expected, code) => ensureEq(hashWithout(value, field), expected, code);

// ---- bytes on disk ------------------------------------------------------------------------------------------
const HASH_RE = /^sha256:[0-9a-f]{64}$/u;
const FILE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}[.]json$/u;
function validateFileName(name) {
  if (typeof name !== "string" || !FILE_RE.test(name) || name.includes("/") || name.includes("\\") || name.startsWith(".")) refuse("unsafe_bundle_filename");
}
function readJsonFile(file) {
  const stat = fs.lstatSync(file, { throwIfNoEntry: false });
  if (!stat) refuse("bundle_member_missing", path.basename(file));
  if (stat.isSymbolicLink() || !stat.isFile()) refuse("unsafe_bundle_object", path.basename(file));
  if (stat.size > MAX_JSON_BYTES) refuse("json_too_large", path.basename(file));
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return refuse("json_invalid", path.basename(file)); }
}
const bindingKey = (ref, hash) => `${ref}\u0000${hash}`;

/** Index every declared object and trust input by (ref, hash), re-deriving each content hash from its bytes. */
function indexObjects(bundleDir, entries) {
  const all = new Map();
  const canonicalDir = fs.realpathSync(bundleDir);
  for (const entry of entries) {
    if (typeof entry?.ref !== "string" || !HASH_RE.test(entry?.hash ?? "") || typeof entry?.schema_ref !== "string") refuse("bundle_object_entry_invalid");
    validateFileName(entry.file);
    const file = path.join(bundleDir, entry.file);
    const stat = fs.lstatSync(file, { throwIfNoEntry: false });
    if (!stat || stat.isSymbolicLink() || !stat.isFile()) refuse("unsafe_bundle_object", entry.file);
    if (path.dirname(fs.realpathSync(file)) !== canonicalDir) refuse("bundle_path_escape", entry.file);
    const value = readJsonFile(file);
    if (contentHash(value) !== entry.hash) refuse("bundle_object_hash", entry.ref);
    const key = bindingKey(entry.ref, entry.hash);
    if (all.has(key)) refuse("duplicate_object_binding", entry.ref);
    all.set(key, [entry, value]);
  }
  return all;
}
/** Resolve a ref without its hash: ambiguous when two bindings share it, which is a refusal, not a choice. */
function objectByRef(all, ref, missingCode) {
  const found = [...all.values()].filter(([entry]) => entry.ref === ref);
  if (found.length === 0) refuse(missingCode, ref);
  if (found.length > 1) refuse("ambiguous_object_ref", ref);
  return found[0][1];
}
function objectBound(all, ref, hash, missingCode) {
  const found = all.get(bindingKey(ref, hash));
  if (!found) refuse(missingCode, `${ref}:${hash}`);
  return found[1];
}

// ---- the certificate's declared bindings ----------------------------------------------------------------------
// Every (ref, hash) pair the certificate carries, wherever it carries it: the flat `*_ref`/`*_hash` pairs, the
// list members that are themselves {ref, hash}, and the two nested binding objects. A binding the certificate
// states and the bundle does not carry is a refusal; so is one whose bytes hash to something else.
// The binding set is ENUMERATED, never discovered by walking the certificate for `*_ref`/`*_hash` pairs. A
// walk would bind the certificate to itself (`certificate_ref` + `certificate_hash` name the very document
// doing the binding, and the bundle carries it as its certificate rather than as an object) and would silently
// widen or narrow as the contract gains members. The published contract states the list; this is the list.
const FLAT_BINDINGS = [
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
];
const LIST_BINDINGS = ["source_basis_refs", "workload_readiness_evidence", "secret_use_evidence", "terminal_acceptance_prerequisites"];
const NESTED_BINDINGS = [
  ["authority_draw", [["standing_envelope_ref", "standing_envelope_hash"], ["draw_request_ref", "draw_request_hash"], ["draw_receipt_ref", "draw_receipt_hash"]]],
  ["trajectory_binding", [["state_before_ref", "state_before_hash"], ["decision_ref", "decision_hash"], ["state_after_ref", "state_after_hash"]]],
];
function certificateBindings(cert) {
  const bindings = [];
  for (const [refKey, hashKey] of FLAT_BINDINGS) bindings.push({ ref: requiredStr(cert, refKey), hash: requiredStr(cert, hashKey) });
  for (const key of LIST_BINDINGS) {
    const values = cert[key];
    if (!Array.isArray(values)) refuse(`${key}_missing`);
    if (values.length === 0) refuse(`${key}_empty`);
    for (const value of values) bindings.push({ ref: requiredStr(value, "ref"), hash: requiredStr(value, "hash") });
  }
  for (const [objectKey, pairs] of NESTED_BINDINGS) {
    const nested = cert[objectKey];
    if (!nested || typeof nested !== "object") refuse(`${objectKey}_missing`);
    for (const [refKey, hashKey] of pairs) bindings.push({ ref: requiredStr(nested, refKey), hash: requiredStr(nested, hashKey) });
  }
  return bindings;
}

// ---- campaign statistics (re-derived, never read) ---------------------------------------------------------------
const approximatelyEqual = (left, right) => Math.abs(left - right) <= 1e-9 * Math.max(1, Math.abs(left), Math.abs(right));
function median(values) {
  if (!values.length) refuse("campaign_metric_values_invalid");
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}
function percentile(values, fraction) {
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
  return sorted[index];
}
/** The exact bootstrap over every resample, which for n samples is n^n medians. */
function exactBootstrapMedianInterval(values) {
  if (!values.length || values.some((v) => !Number.isFinite(v))) refuse("campaign_metric_values_invalid");
  const n = values.length;
  const total = n ** n;
  const medians = new Array(total);
  for (let encoded = 0; encoded < total; encoded += 1) {
    let cursor = encoded;
    const sample = new Array(n);
    for (let i = 0; i < n; i += 1) { sample[i] = values[cursor % n]; cursor = Math.floor(cursor / n); }
    medians[encoded] = median(sample);
  }
  return [percentile(medians, 0.025), percentile(medians, 0.975)];
}
const requiredNonNegativeNumber = (value, key) => {
  const found = value?.[key];
  if (typeof found !== "number" || !Number.isFinite(found) || found < 0) refuse(`campaign_metric_${key}_invalid`);
  return found;
};

const EXPECTED_ROWS = [
  "paper_guardian_majority_4v\u0000base_final", "paper_guardian_majority_7v\u0000base_final",
  "paper_asymptote_4v\u0000base_final", "paper_asymptote_4v\u0000canonical_ordering",
  "paper_asymptote_4v\u0000durable_collapse", "paper_asymptote_4v\u0000sealed_final",
  "paper_asymptote_7v\u0000base_final", "paper_asymptote_7v\u0000canonical_ordering",
  "paper_asymptote_7v\u0000durable_collapse", "paper_asymptote_7v\u0000sealed_final",
].sort();
const METRIC_NAMES = ["injection_tps", "sustained_tps", "commit_p50_ms", "commit_p95_ms", "commit_p99_ms", "commit_max_ms"];

export function validateCampaignResult(result) {
  if (result.measured_passes !== 5 || result.row_count_per_pass !== 10 || (result.pass_artifacts ?? []).length !== 5) refuse("campaign_protocol_mismatch");
  if (new Set(result.pass_artifacts).size !== result.pass_artifacts.length || (result.summaries ?? []).length !== 10) refuse("campaign_coverage_invalid");
  const observed = new Set();
  let everyRowWithin = true;
  for (const summary of result.summaries) {
    const scenario = requiredStr(summary, "scenario");
    const lane = requiredStr(summary, "lane");
    const key = `${scenario}\u0000${lane}`;
    if (observed.has(key)) refuse("campaign_duplicate_scenario_lane");
    observed.add(key);
    const within = summary?.within_threshold;
    if (typeof within !== "boolean") refuse("campaign_row_threshold_missing");
    everyRowWithin &&= within;
    const metrics = summary?.metrics;
    if (!metrics || typeof metrics !== "object" || Array.isArray(metrics)) refuse("campaign_metrics_missing");
    if (Object.keys(metrics).length !== METRIC_NAMES.length) refuse("campaign_metric_set_mismatch");
    let rowMetricsWithin = true;
    for (const name of METRIC_NAMES) {
      const metric = metrics[name];
      if (metric === undefined) refuse("campaign_metric_missing", name);
      if (!metric || typeof metric !== "object" || Array.isArray(metric)) refuse("campaign_metric_invalid", name);
      const values = metric.values;
      if (!Array.isArray(values)) refuse("campaign_metric_values_missing", name);
      if (values.length !== result.measured_passes || values.some((v) => typeof v !== "number" || !Number.isFinite(v) || v < 0)) refuse("campaign_metric_values_invalid", name);
      if (Object.keys(metric).length !== 10) refuse("campaign_metric_set_invalid", name);
      const samples = values.slice();
      const observedMin = Math.min(...samples);
      const observedMax = Math.max(...samples);
      const observedMedian = median(samples);
      const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
      const observedMad = median(samples.map((s) => Math.abs(s - observedMedian)));
      const sampleVariance = samples.reduce((a, s) => a + (s - mean) ** 2, 0) / (samples.length - 1);
      const observedCv = mean === 0 ? (observedMax === observedMin ? 0 : Infinity) : Math.sqrt(sampleVariance) / mean;
      const observedSpread = observedMedian === 0 ? (observedMax === observedMin ? 0 : Infinity) : (observedMax - observedMin) / observedMedian;
      const [bootLow, bootHigh] = exactBootstrapMedianInterval(samples);
      const min = requiredNonNegativeNumber(metric, "min");
      const med = requiredNonNegativeNumber(metric, "median");
      const max = requiredNonNegativeNumber(metric, "max");
      const mad = requiredNonNegativeNumber(metric, "median_absolute_deviation");
      const cv = requiredNonNegativeNumber(metric, "coefficient_of_variation");
      const spread = requiredNonNegativeNumber(metric, "relative_spread");
      const interval = metric.bootstrap_median_95;
      if (!Array.isArray(interval) || interval.length !== 2 || interval.some((v) => typeof v !== "number" || !Number.isFinite(v) || v < 0)) refuse("campaign_metric_bootstrap_invalid", name);
      if (!approximatelyEqual(min, observedMin) || !approximatelyEqual(med, observedMedian) || !approximatelyEqual(max, observedMax)
        || !approximatelyEqual(mad, observedMad) || !approximatelyEqual(cv, observedCv) || !approximatelyEqual(spread, observedSpread)
        || !approximatelyEqual(interval[0], bootLow) || !approximatelyEqual(interval[1], bootHigh)) refuse("campaign_metric_summary_inconsistent", name);
      const threshold = requiredNonNegativeNumber(metric, "threshold");
      const declared = result.threshold_policy?.[name];
      if (typeof declared !== "number" || !Number.isFinite(declared)) refuse("campaign_threshold_missing", name);
      if (threshold !== declared) refuse("campaign_threshold_substitution", name);
      const metricWithin = metric.within_threshold;
      if (typeof metricWithin !== "boolean") refuse("campaign_metric_verdict_missing", name);
      if (metricWithin !== (observedSpread <= threshold)) refuse("campaign_metric_verdict_inconsistent", name);
      rowMetricsWithin &&= metricWithin;
    }
    if (within !== rowMetricsWithin) refuse("campaign_row_verdict_inconsistent");
    everyRowWithin &&= rowMetricsWithin;
  }
  const observedSorted = [...observed].sort();
  if (observedSorted.length !== EXPECTED_ROWS.length || observedSorted.some((row, i) => row !== EXPECTED_ROWS[i])) refuse("campaign_scenario_lane_matrix_mismatch");
  if (result.all_rows_within_threshold !== everyRowWithin) refuse("result_verdict_inconsistent");
  if ((result.verdict === "reproduced_within_threshold") !== everyRowWithin) refuse("result_verdict_inconsistent");
  if (!["reproduced_within_threshold", "variance_caveated"].includes(result.verdict)) refuse("result_verdict_unknown");
}

// ---- the semantic chain ------------------------------------------------------------------------------------
// Every object the certificate binds is read for what it SAYS, not merely that it hashes. A fully resealed
// mutation — one where the producer edited an object and re-sealed every hash above it so the binding layer is
// perfectly consistent — is caught here or not at all. That is what the forty published negatives are.
function projectedRequest(all, requestRef) {
  const raw = objectByRef(all, requestRef, "governed_request_missing");
  if (raw?.schema_version !== CANONICAL_JSON_PREIMAGE_V1) return raw;
  const canonical = JSON.parse(requiredStr(raw, "canonical_json"));
  const facets = canonical?.facets;
  if (facets === undefined) refuse("governed_request_facets_missing");
  const projection = raw.projection;
  if (projection === undefined) refuse("governed_request_projection_missing");
  for (const [projected, native] of [["operation", "op"], ["campaign_id", "campaign_id"], ["benchmark_source_commit", "benchmark_source_commit"], ["image_digest", "image_digest"], ["provider_ref", "provider_ref"], ["provider_address", "provider_address"]]) {
    if (projection[projected] !== undefined && facets[native] !== undefined && projection[projected] !== facets[native]) refuse("governed_request_projection_mismatch", projected);
  }
  return projection;
}

function validateSemanticChain(cert, all, result) {
  const campaignId = requiredStr(cert, "campaign_id");
  const sourceCommit = requiredStr(cert, "benchmark_source_commit");
  const imageDigest = requiredStr(cert, "workload_image_digest");
  const requestRef = requiredStr(cert, "governed_request_ref");
  const request = projectedRequest(all, requestRef);

  // the governed request the certificate is about
  ensureValueStr(request, "campaign_id", campaignId);
  ensureValueStr(request, "benchmark_source_commit", sourceCommit);
  ensureValueStr(request, "image_digest", imageDigest);
  if (requiredStr(request, "operation") !== "create_deployment") refuse("governed_request_operation_invalid");

  // settlement: the money and the lease are closed, and nothing is open or unknown
  const settlement = objectByRef(all, requiredStr(cert, "terminal_settlement_ref"), "settlement_missing");
  ensureValueStr(settlement, "campaign_id", campaignId);
  ensureValueStr(settlement, "lease_status", "closed");
  ensureValueStr(settlement, "deployment_status", "closed");
  ensureValueStr(settlement, "escrow_status", "closed");
  if (settlement.open_unknown_exposure_microusd !== 0 || settlement.teardown_verified !== true) refuse("terminal_settlement_incomplete");
  const providerRef = requiredStr(settlement, "provider_ref");
  const providerAddress = requiredStr(settlement, "provider_address");
  ensureValueStr(request, "provider_ref", providerRef);
  ensureValueStr(request, "provider_address", providerAddress);

  // the environment the campaign ran in
  const environment = objectByRef(all, requiredStr(cert, "environment_ref"), "environment_missing");
  ensureValueStr(environment, "campaign_id", campaignId);
  ensureValueStr(environment, "provider_ref", providerRef);
  ensureValueStr(environment, "environment_class", requiredStr(cert, "environment_class"));
  ensureValueStr(environment, "image_digest", imageDigest);

  // readiness: the workload the certificate names was actually ready
  for (const evidence of cert.workload_readiness_evidence ?? []) {
    const value = objectBound(all, evidence.ref, evidence.hash, "readiness_evidence_missing");
    ensureValueStr(value, "status", "ready");
    ensureValueStr(value, "provider_ref", providerRef);
    ensureValueStr(value, "image_digest", imageDigest);
    if (!(typeof value.ready_replicas === "number" && value.ready_replicas > 0)) refuse("workload_not_ready");
  }

  // the result was retrieved, authenticated, and is the one the certificate binds
  const retrieval = objectByRef(all, requiredStr(cert, "result_retrieval_receipt_ref"), "retrieval_missing");
  ensureValueStr(retrieval, "status", "verified");
  ensureValueStr(retrieval, "campaign_id", campaignId);
  ensureValueStr(retrieval, "result_ref", requiredStr(cert, "result_ref"));
  ensureValueStr(retrieval, "result_hash", requiredStr(cert, "result_hash"));
  if (retrieval.authenticated !== true) refuse("result_retrieval_not_authenticated");

  // the campaign certificate agrees with this one
  const campaign = objectByRef(all, requiredStr(cert, "campaign_certificate_ref"), "campaign_certificate_missing");
  ensureValueStr(campaign, "status", "complete");
  for (const [field, expected] of [
    ["campaign_id", campaignId], ["provider_ref", providerRef], ["image_digest", imageDigest], ["source_commit", sourceCommit],
    ["result_ref", requiredStr(cert, "result_ref")], ["result_hash", requiredStr(cert, "result_hash")],
    ["environment_ref", requiredStr(cert, "environment_ref")], ["environment_hash", requiredStr(cert, "environment_hash")],
    ["terminal_settlement_ref", requiredStr(cert, "terminal_settlement_ref")], ["terminal_settlement_hash", requiredStr(cert, "terminal_settlement_hash")],
  ]) ensureValueStr(campaign, field, expected);

  // isolation: the binding governs the action, its requirements are hostile-guest safe, and every enforcement
  // evidence it names demonstrates the boundary rather than describing it
  const isolation = objectByRef(all, requiredStr(cert, "isolation_binding_ref"), "isolation_binding_missing");
  ensureValueStr(isolation, "route_policy_ref", "policy://network/deny-default");
  ensureValueStr(isolation, "final_invoker_ref", "final-invoker://hypervisor/provider-operation");
  ensureValueStr(isolation, "required_terminal_disposition", "destroyed_verified");
  if (!(isolation.governed_action_classes ?? []).includes("provider_operation")) refuse("isolation_provider_action_not_governed");
  const requirements = objectByRef(all, requiredStr(isolation, "requirements_ref"), "isolation_requirements_missing");
  ensureEq(contentHash(requirements), requiredStr(isolation, "requirements_hash"), "isolation_requirements_hash");
  ensureValueStr(requirements, "hostile_to_boundary_requirement", "hostile_to_guest_kernel");
  ensureValueStr(requirements, "minimum_isolation", "vm_kernel");
  ensureValueStr(requirements, "host_mount_policy", "none");
  if (requirements.daemon_socket_exposed !== false || requirements.host_pid_namespace_exposed !== false
    || requirements.raw_secret_material_in_guest !== false
    || requirements.output_admission?.quarantine_required !== true
    || requirements.teardown?.verify_all_resources !== true) refuse("isolation_requirements_not_hostile_guest_safe");
  const coverage = isolation.enforcement_coverage_refs_and_hashes;
  if (!Array.isArray(coverage) || coverage.length === 0) refuse("isolation_enforcement_coverage_missing");
  for (const binding of coverage) {
    const evidence = objectByRef(all, requiredStr(binding, "ref"), "isolation_enforcement_evidence_missing");
    ensureEq(contentHash(evidence), requiredStr(binding, "hash"), "isolation_enforcement_evidence_hash");
    ensureValueStr(evidence, "protection_profile", "trusted_host_hostile_guest");
    ensureValueStr(evidence, "network_posture", "no_nic");
    ensureValueStr(evidence, "final_invoker_audience", "hypervisor-final-invoker");
    if (evidence.direct_protected_effect_invocations !== 0 || evidence.final_invoker_calls !== 1 || evidence.guest_uid !== 0
      || evidence.output_quarantined !== true || evidence.capability_replay !== "refused" || evidence.monitor_terminal !== true) refuse("isolation_boundary_not_demonstrated");
  }

  // the worker never held the secret
  for (const evidence of cert.secret_use_evidence ?? []) {
    const value = objectBound(all, evidence.ref, evidence.hash, "secret_evidence_missing");
    if (value.secret_findings !== 0 || value.provider_credential_observed !== false) refuse("worker_secret_non_possession_not_demonstrated");
  }

  // the terminal acceptance prerequisites are satisfied
  for (const prerequisite of cert.terminal_acceptance_prerequisites ?? []) {
    const value = objectByRef(all, requiredStr(prerequisite, "ref"), "terminal_prerequisite_missing");
    ensureValueStr(value, "campaign_id", campaignId);
    if (value.terminal !== true || value.cleanup_verified !== true || value.result_verified !== true) refuse("terminal_prerequisite_unsatisfied");
  }
  if (result.campaign_id !== campaignId) refuse("campaign_result_binding_mismatch");

  // the standing envelope actually covered this request
  const draw = cert.authority_draw ?? {};
  const envelopeRef = requiredStr(draw, "standing_envelope_ref");
  const envelope = objectByRef(all, envelopeRef, "standing_envelope_missing");
  ensureValueStr(envelope, "approval_mode", "standing_envelope");
  ensureValueStr(envelope, "authority_scope", "scope:hypervisor.live-route.hypervisor-provider-op");
  ensureValueStr(envelope, "recovery_posture", "recovery_never_widens_or_resets_drawdown");
  const facets = envelope.facet_template;
  if (facets === undefined) refuse("standing_envelope_facets_missing");
  const providerSelector = facets.provider_selector;
  if (providerSelector === undefined) refuse("standing_envelope_provider_selector_missing");
  if (facets.auto_topup !== false || facets.teardown_policy !== "always_teardown_required"
    || !(facets.image_digests ?? []).includes(imageDigest)
    || !(providerSelector.provider_addresses ?? []).includes(providerAddress)
    || !(facets.operations ?? []).includes("create")) refuse("standing_envelope_does_not_cover_request");

  // the draw was requested for exactly this operation and terminally consumed
  const drawRequestRef = requiredStr(draw, "draw_request_ref");
  const drawRequest = objectByRef(all, drawRequestRef, "authority_draw_request_missing");
  const requestHash = requiredStr(cert, "governed_request_hash");
  ensureValueStr(drawRequest, "standing_envelope_ref", envelopeRef);
  ensureValueStr(drawRequest, "candidate_operation_ref", requestRef);
  ensureValueStr(drawRequest, "candidate_operation_hash", requestHash);
  const drawReceipt = objectByRef(all, requiredStr(draw, "draw_receipt_ref"), "authority_draw_receipt_missing");
  ensureValueStr(drawReceipt, "standing_envelope_ref", envelopeRef);
  ensureValueStr(drawReceipt, "draw_request_ref", drawRequestRef);
  ensureValueStr(drawReceipt, "candidate_operation_hash", requestHash);
  ensureValueStr(drawReceipt, "decision", "consumed");
  if (drawReceipt.atomic_consumption !== true || drawReceipt.revoked !== false) refuse("authority_draw_not_terminally_consumed");

  // the trajectory admitted it, and the state advanced by exactly this call
  const trajectory = cert.trajectory_binding ?? {};
  const before = objectBound(all, requiredStr(trajectory, "state_before_ref"), requiredStr(trajectory, "state_before_hash"), "trajectory_before_missing");
  const decision = objectByRef(all, requiredStr(trajectory, "decision_ref"), "trajectory_decision_missing");
  const after = objectBound(all, requiredStr(trajectory, "state_after_ref"), requiredStr(trajectory, "state_after_hash"), "trajectory_after_missing");
  ensureValueStr(decision, "decision", "admit");
  ensureValueStr(decision, "candidate_operation_ref", requestRef);
  ensureValueStr(decision, "candidate_operation_hash", requestHash);
  for (const key of ["state_before_ref", "state_before_hash", "state_after_ref", "state_after_hash"]) ensureValueStr(decision, key, requiredStr(trajectory, key));
  ensureValueStr(decision, "policy_ref", requiredStr(envelope, "trajectory_policy_ref"));
  ensureValueStr(decision, "policy_hash", requiredStr(envelope, "trajectory_policy_hash"));
  const constraints = decision.constraint_results;
  if (!Array.isArray(constraints)) refuse("trajectory_constraints_missing");
  if (constraints.length === 0 || constraints.some((item) => item?.satisfied !== true)) refuse("trajectory_constraint_not_satisfied");
  for (const field of ["owner_ref", "bounded_system_ref", "principal_ref", "revocation_epoch", "window_started_at", "window_ends_at"]) {
    if (canonicalJson(before[field] ?? null) !== canonicalJson(after[field] ?? null)) refuse("trajectory_identity_or_window_changed", field);
  }
  // This certificate binds exactly one governed operation and carries no chain to a previously accepted
  // decision, so the only predecessor state it can anchor is the genesis one. A non-genesis predecessor is
  // refused rather than trusted: nothing in the bundle would independently establish it.
  const beforeCalls = before.admitted_call_count;
  if (typeof beforeCalls !== "number") refuse("trajectory_before_count_missing");
  const emptyArray = (value, field) => Array.isArray(value?.[field]) && value[field].length === 0;
  if (beforeCalls !== 0 || requiredNonNegativeNumber(before, "cumulative_spend_usd") !== 0 || requiredNonNegativeNumber(before, "cumulative_deposit_usd") !== 0
    || !emptyArray(before, "admitted_events")
    || ["active_resource_refs", "provider_refs", "destination_refs", "data_class_refs"].some((field) => !emptyArray(before, field))) refuse("trajectory_predecessor_not_anchored");
  if (after.admitted_call_count !== beforeCalls + 1
    || requiredNonNegativeNumber(after, "cumulative_spend_usd") < requiredNonNegativeNumber(before, "cumulative_spend_usd")
    || requiredNonNegativeNumber(after, "cumulative_deposit_usd") < requiredNonNegativeNumber(before, "cumulative_deposit_usd")
    || !(after.provider_refs ?? []).includes(providerRef)
    || !(after.envelope_ancestor_refs ?? []).includes(envelopeRef)) refuse("trajectory_state_transition_invalid");
  return { providerRef, providerAddress };
}

// ---- the whole verification ------------------------------------------------------------------------------------
/**
 * Verify one bundle against one policy at one instant, exactly as the published specification says.
 * `ownBuildHash` is the digest of THIS verifier, which the profile the policy names must carry: a verifier that
 * accepted a profile naming a different build would be verifying on another implementation's behalf.
 */
export function verifyBundle({ bundleDir, policyPath, now, ownBuildHash }) {
  const bundleValue = readJsonFile(path.join(bundleDir, "bundle.json"));
  ensureEq(bundleValue.schema_version, BUNDLE_V1, "bundle_schema");
  if (typeof bundleValue.bundle_ref !== "string" || !bundleValue.bundle_ref.startsWith("evidence-bundle://")) refuse("bundle_ref_invalid");
  validateHashField(bundleValue, "bundle_hash", bundleValue.bundle_hash, "bundle_hash");
  const createdAt = Date.parse(requiredStr(bundleValue, "created_at"));
  if (Number.isNaN(createdAt)) refuse("bundle_created_at_invalid");

  const policyValue = readJsonFile(policyPath);
  ensureEq(policyValue.schema_version, POLICY_V1, "policy_schema");
  validateHashField(policyValue, "policy_hash", policyValue.policy_hash, "policy_hash");
  const nowMs = Date.parse(now);
  if (Number.isNaN(nowMs)) refuse("now_invalid");
  const validFrom = Date.parse(requiredStr(policyValue, "valid_from"));
  const validUntil = Date.parse(requiredStr(policyValue, "valid_until"));
  if (nowMs < validFrom || nowMs > validUntil) refuse("policy_not_current");
  const target = policyValue.target_transition ?? {};
  if (target.target_registry_ref !== "registry://aft/measured-results" || target.mutation_kind !== "aft_measured_result_promote" || target.target_schema_ref !== "schema://ioi/aft/measured-result-row/v1") refuse("policy_target_transition_invalid");

  const all = indexObjects(bundleDir, [...(bundleValue.objects ?? []), ...(bundleValue.trust_inputs ?? [])]);
  validateFileName(bundleValue.certificate_file);
  const certificatePath = path.join(bundleDir, bundleValue.certificate_file);
  const certificateStat = fs.lstatSync(certificatePath, { throwIfNoEntry: false });
  if (!certificateStat || certificateStat.isSymbolicLink() || !certificateStat.isFile() || certificateStat.size > MAX_JSON_BYTES) refuse("unsafe_certificate_file");
  if (path.dirname(fs.realpathSync(certificatePath)) !== fs.realpathSync(bundleDir)) refuse("certificate_path_escape");
  const certificate = readJsonFile(certificatePath);
  ensureValueStr(certificate, "schema_version", C8_V3);
  validateHashField(certificate, "certificate_hash", bundleValue.certificate_hash, "certificate_hash");
  ensureValueStr(certificate, "certificate_ref", bundleValue.certificate_ref);
  if (!(policyValue.accepted_certificate_schema_refs ?? []).includes("schema://ioi/components/hypervisor/c8-certificate/v3")) refuse("certificate_schema_not_accepted");
  ensureValueStr(certificate, "relying_party_audience_ref", requiredStr(policyValue, "audience_ref"));
  const generated = Date.parse(requiredStr(certificate, "generated_at"));
  if (Number.isNaN(generated)) refuse("certificate_generated_at_invalid");
  if (generated > nowMs || (nowMs - generated) / 1000 > policyValue.maximum_certificate_age_seconds) refuse("certificate_stale");
  if (policyValue.revocation_check_required === true && !(bundleValue.trust_inputs ?? []).some((o) => String(o.schema_ref).includes("revocation"))) refuse("revocation_input_missing");

  for (const binding of certificateBindings(certificate)) {
    const found = all.get(bindingKey(binding.ref, binding.hash));
    if (!found) refuse("bound_object_missing", `${binding.ref}:${binding.hash}`);
    ensureEq(found[0].hash, binding.hash, "bound_object_hash");
  }

  const predecessorRef = requiredStr(certificate, "predecessor_certificate_ref");
  const predecessorHash = requiredStr(certificate, "predecessor_certificate_hash");
  const predecessor = objectBound(all, predecessorRef, predecessorHash, "predecessor_certificate_missing");
  ensureValueStr(predecessor, "schema_version", requiredStr(certificate, "predecessor_certificate_schema_version"));
  ensureValueStr(predecessor, "certificate_hash", predecessorHash);
  if (predecessor.ok !== true || typeof predecessor.journal !== "object" || predecessor.journal === null || typeof predecessor.provider !== "object" || predecessor.provider === null) refuse("predecessor_certificate_not_complete");

  const manifestRef = requiredStr(certificate, "claim_manifest_ref");
  const manifest = objectByRef(all, manifestRef, "claim_manifest_missing");
  ensureEq(manifest.schema_version, CLAIM_MANIFEST_V1, "claim_manifest_schema");
  ensureEq(manifest.manifest_ref, manifestRef, "claim_manifest_ref");
  ensureEq(manifest.manifest_hash, requiredStr(certificate, "claim_manifest_hash"), "claim_manifest_hash");
  ensureEq(manifest.subject_ref, requiredStr(certificate, "governed_request_ref"), "claim_subject_ref");
  ensureEq(manifest.subject_hash, requiredStr(certificate, "governed_request_hash"), "claim_subject_hash");
  ensureEq(manifest.protection_profile, "trusted_host_hostile_guest", "protection_profile");
  if (Number.isNaN(Date.parse(requiredStr(manifest, "generated_at")))) refuse("claim_manifest_generated_at_invalid");
  if (!(manifest.source_basis_refs ?? []).length) refuse("claim_source_basis_missing");
  const claims = new Map();
  for (const claim of manifest.claims ?? []) {
    if (claims.has(claim.claim_id)) refuse("duplicate_claim_id");
    claims.set(claim.claim_id, claim);
  }
  for (const id of policyValue.required_claim_ids ?? []) {
    const claim = claims.get(id);
    if (!claim) refuse("required_claim_missing", id);
    if (claim.status !== "demonstrated" || !(claim.evidence_refs ?? []).length || !claim.limitation_note) refuse("required_claim_not_demonstrated", id);
  }
  for (const claim of manifest.claims ?? []) {
    const required = (policyValue.required_claim_ids ?? []).includes(claim.claim_id);
    const tolerated = (policyValue.tolerated_nonclaim_ids ?? []).includes(claim.claim_id);
    if (!required && !tolerated) refuse("unsupported_claim_id", claim.claim_id);
    if (claim.status !== "demonstrated" && !tolerated) refuse("untolerated_nonclaim", claim.claim_id);
    if (tolerated && claim.status === "demonstrated") refuse("nonclaim_inflated_to_claim", claim.claim_id);
  }

  const resultRef = requiredStr(certificate, "result_ref");
  const resultHash = requiredStr(certificate, "result_hash");
  const resultEntry = all.get(bindingKey(resultRef, resultHash));
  if (!resultEntry) refuse("result_missing", resultRef);
  if (!(policyValue.accepted_result_schema_refs ?? []).includes(resultEntry[0].schema_ref)) refuse("result_schema_not_accepted");
  const result = resultEntry[1];
  ensureEq(result.schema_version, RESULT_V1, "result_schema");
  ensureEq(result.campaign_id, requiredStr(certificate, "campaign_id"), "result_campaign");
  validateCampaignResult(result);
  ensureEq(resultEntry[0].hash, resultHash, "result_hash");

  const environmentClass = requiredStr(certificate, "environment_class");
  if (!(policyValue.accepted_environment_classes ?? []).includes(environmentClass)) refuse("environment_class_not_accepted");
  const honestyClass = requiredStr(certificate, "honesty_class");
  if (!(policyValue.accepted_honesty_classes ?? []).includes(honestyClass)) refuse("honesty_class_not_accepted");
  if (!(policyValue.accepted_result_verdicts ?? []).includes(result.verdict)) refuse("result_verdict_not_accepted");
  if (honestyClass === "attested_pinned_bare_metal" && environmentClass !== "attested_pinned_bare_metal") refuse("bare_metal_claim_inflated");

  const journal = certificate.journal_binding;
  if (!journal || typeof journal !== "object") refuse("journal_binding_missing");
  if (journal.intent_root !== journal.outcome_predecessor_root) refuse("outcome_predecessor_mismatch");
  if (journal.intent_root === journal.outcome_root) refuse("outcome_root_did_not_advance");

  const { providerRef } = validateSemanticChain(certificate, all, result);

  const profileEntry = all.get(bindingKey(requiredStr(policyValue, "verifier_profile_ref"), requiredStr(policyValue, "verifier_profile_hash")));
  if (!profileEntry) refuse("verifier_profile_missing");
  const profile = profileEntry[1];
  ensureEq(profileEntry[0].hash, policyValue.verifier_profile_hash, "verifier_profile_hash");
  ensureEq(profile.schema_version, PROFILE_V1, "verifier_profile_schema");
  ensureEq(profile.profile_ref, policyValue.verifier_profile_ref, "verifier_profile_ref");
  ensureEq(profile.profile_hash, policyValue.verifier_profile_hash, "profile_self_hash");
  if (profile.separate_binary !== true || profile.separate_codegen !== true || profile.separate_transport !== true || profile.separate_authoring_party !== false) refuse("verifier_independence_profile_invalid");
  if (!(profile.contract_schema_refs ?? []).length || (profile.evidence_refs ?? []).length < 3 || !profile.accountable_authoring_party_ref) refuse("verifier_profile_evidence_incomplete");
  ensureEq(profile.verifier_build_hash, ownBuildHash, "verifier_build_hash");
  if (!profile.verifier_identity_ref) refuse("verifier_identity_missing");

  for (const root of policyValue.trust_roots ?? []) {
    const found = all.get(bindingKey(root.ref, root.hash));
    if (!found) refuse("trust_root_missing", root.ref);
    ensureEq(found[0].hash, root.hash, "trust_root_hash");
  }

  return {
    ok: true,
    certificate_ref: bundleValue.certificate_ref,
    certificate_hash: bundleValue.certificate_hash,
    claim_identity: { campaign_id: requiredStr(certificate, "campaign_id"), result_ref: resultRef, result_hash: resultHash, provider_ref: providerRef, environment_class: environmentClass, honesty_class: honestyClass, verdict: result.verdict },
    verifier: { identity_ref: profile.verifier_identity_ref, build_hash: ownBuildHash, implementation: CLEAN_ROOM_VERIFIER_VERSION },
  };
}

/** The digest of this verifier's own bytes — every file of it, in sorted order. */
export function ownBuildHashOf(files) {
  const hash = crypto.createHash("sha256");
  for (const file of [...files].sort()) { hash.update(path.basename(file)); hash.update("\u0000"); hash.update(fs.readFileSync(file)); }
  return `sha256:${hash.digest("hex")}`;
}

export function runCli(argv) {
  const flag = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
  if (argv[0] !== "verify") return { exit: 2, output: { ok: false, failure_codes: ["usage"], detail: "verify --bundle <dir> --policy <file> --now <rfc3339>" } };
  const bundleDir = flag("--bundle");
  const policyPath = flag("--policy");
  const now = flag("--now");
  if (!bundleDir || !policyPath || !now) return { exit: 2, output: { ok: false, failure_codes: ["usage"], detail: "--bundle, --policy and --now are required" } };
  // The verifier's own identity is COMPUTED FROM ITS OWN BYTES and never accepted from the caller. A verifier
  // that could be told its build hash would verify on any implementation's behalf, and the profile's whole
  // point is that a relying party provisioned this one.
  const ownBuildHash = ownBuildHashOf([new URL(import.meta.url).pathname]);
  try {
    const verified = verifyBundle({ bundleDir, policyPath, now, ownBuildHash });
    return { exit: 0, output: { ...verified, failure_codes: [] } };
  } catch (error) {
    if (error instanceof Refusal) return { exit: 1, output: { ok: false, failure_codes: [error.code], detail: error.detail } };
    return { exit: 1, output: { ok: false, failure_codes: ["verification_failed"], detail: String(error?.message ?? error).slice(0, 300) } };
  }
}

if (process.argv[1] && new URL(import.meta.url).pathname === fs.realpathSync(process.argv[1])) {
  const { exit, output } = runCli(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(output)}\n`);
  process.exit(exit);
}
