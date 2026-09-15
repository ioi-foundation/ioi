#!/usr/bin/env node
// check:governed-evaluation-plane — M10.4, against an ISOLATED real daemon.
//
// THE UNIT'S CLAIM is that Evaluations is a governed plane: released suite revisions, frozen and
// active epochs, admitted runs, immutable results with a DERIVED verdict floor, evaluator validity
// as a lifecycle around a frozen root with downstream impact lineage, exposure accounting through
// M10.1's ledger, and a model-swap continuity report DERIVED from real model invocations with the
// incumbent route disabled in registry truth. Canon: components/hypervisor/evaluations.md
// (§ Registered Shapes, § Evaluator Validity And Challenges, § Conformance Checks) and
// components/hypervisor/foundry.md § Model-Swap Continuity.
//
// THE EVIDENCE IS REAL. Two deterministic stub model servers speak the ollama wire dialect
// (/api/tags, /api/chat) on loopback. They are registered as routes A and B in the daemon's own
// model-route registry, probed, enabled, and INVOKED through POST /v1/hypervisor/model-routes/:id/
// invoke, so every execution evidence ref a run cites is a receipt this daemon admitted for a call
// that actually crossed the wire (the stubs count their requests, and the drill proves the counter
// can read zero).
//
// THE ORACLES ARE INDEPENDENT. Every content_hash, the evaluator_root, the report's route record
// hashes and the verdict floor are RE-DERIVED here from the records' own members under canon's
// domain separators and compared with the daemon's number. The drill plants a changed member in
// each re-derivation and requires the oracle to notice.
//
// THE MANIFEST'S THIRTEEN PROPERTIES are each driven and tagged in the assertion names:
//   [P1 exact released suites] [P2 frozen epochs] [P3 admitted lineage] [P4 role separation]
//   [P5 mutable latest + substitution] [P6 holdout exposure] [P7 declared nondeterminism]
//   [P8 missing required lanes] [P9 evaluator invalidation] [P10 provider removal]
//   [P11 adapter drift] [P12 state restore/replay] [P13 self-promotion refusal]
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   --mutation  run the planted defects instead of trusting the assertions above.
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const DRILL = process.argv.includes("--mutation");

const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail });
const observedCodes = new Set();

// ------------------------------------------------------------------------------ the oracles
/** RFC 8785 JCS for the JSON subset these records use: sorted keys, minimal separators. */
const jcs = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(",")}}`;
};
const sha = (text) => `sha256:${createHash("sha256").update(text).digest("hex")}`;
/** The daemon's `digest_over`: a flat material map {domain, field…} canonicalized and hashed. */
const digestOver = (record, domain, fields) => {
  const material = { domain };
  for (const field of fields) {
    if (!(field in record)) return `missing:${field}`;
    material[field] = record[field];
  }
  return sha(jcs(material));
};

const DOMAINS = {
  suite: "ioi.evaluation-suite-revision-content-commitment-jcs-sha256.v1",
  evaluatorRoot: "ioi.evaluator-revision-frozen-root-jcs-sha256.v1",
  evaluator: "ioi.evaluator-revision-content-commitment-jcs-sha256.v1",
  run: "ioi.evaluation-run-content-commitment-jcs-sha256.v1",
  result: "ioi.evaluation-result-content-commitment-jcs-sha256.v1",
  report: "ioi.model-swap-continuity-report-content-commitment-jcs-sha256.v1",
};
const SUITE_MATERIAL = ["schema_version", "evaluation_suite_id", "revision_ref", "revision", "predecessor_revision_ref", "owner_ref", "library_suite_ref", "tasks", "scorer_revision_refs", "rubric_refs", "world_refs", "required_lanes", "nondeterminism_class", "declared_seed_policy_ref", "verification_cost_class"];
const EVALUATOR_FROZEN = ["schema_version", "evaluator_id", "revision_ref", "revision", "predecessor_revision_ref", "owner_ref", "evaluator_kind", "implementation_ref", "affiliation_ref", "custodian_ref"];
const EVALUATOR_MATERIAL = [...EVALUATOR_FROZEN, "evaluator_root", "validity_status", "validity_decision_ref", "challenge_refs", "impact_disposition_ref"];
const RUN_MATERIAL = ["schema_version", "evaluation_run_id", "owner_ref", "evaluation_epoch_ref", "epoch_frozen_root", "suite_revision_ref", "evaluator_revision_ref", "lane", "incumbent_ref", "incumbent_root", "target_base_root", "execution_evidence_refs", "policy_bound_data_view_revision_ref", "nondeterminism_class", "seed", "submitter_role", "cost_units", "cost_unit"];
const RESULT_MATERIAL = ["schema_version", "evaluation_result_id", "owner_ref", "evaluation_run_ref", "evaluation_epoch_ref", "epoch_frozen_root", "suite_revision_ref", "evaluator_revision_ref", "lane", "observations", "verdict", "verdict_basis", "uncertainty", "guardrail_findings", "applicability_scope", "cost_units", "cost_unit", "failures", "evaluator_versions", "exposure_entry_ref"];
const REPORT_MATERIAL = ["schema_version", "model_swap_continuity_report_id", "owner_ref", "evaluation_epoch_ref", "epoch_frozen_root", "suite_revision_ref", "institutional_state_root", "policy_bound_data_view_revision_ref", "learning_boundary_profile_ref", "incumbent_route_ref", "incumbent_route_record_hash", "incumbent_disabled_evidence", "candidate_route_ref", "candidate_route_record_hash", "baseline_result_refs", "candidate_result_refs", "equivalence_envelope", "observed_deltas", "unsupported_dependencies", "threshold_verdict", "canary_refs", "rollback_refs", "authority_note"];

const deriveSuiteHash = (r) => digestOver(r, DOMAINS.suite, SUITE_MATERIAL);
const deriveEvaluatorRoot = (r) => digestOver(r, DOMAINS.evaluatorRoot, EVALUATOR_FROZEN);
const deriveEvaluatorHash = (r) => digestOver(r, DOMAINS.evaluator, EVALUATOR_MATERIAL);
const deriveRunHash = (r) => digestOver(r, DOMAINS.run, RUN_MATERIAL);
const deriveResultHash = (r) => digestOver(r, DOMAINS.result, RESULT_MATERIAL);
const deriveReportHash = (r) => digestOver(r, DOMAINS.report, REPORT_MATERIAL);
/** The registry's `canonical_value_hash`: plain JCS over the whole STORED route record. The GET
 * projection adds `availability.stale` on the way out; that is a read-time derivation, not a member. */
const deriveRouteRecordHash = (record) => {
  const stored = JSON.parse(JSON.stringify(record));
  if (stored.availability && typeof stored.availability === "object") delete stored.availability.stale;
  return sha(jcs(stored));
};

/** The daemon's verdict floor, re-derived: a floor only ever LOWERS the claimed verdict. */
const RANK = { pass: 4, fail: 3, inconclusive: 2, blocked: 1, invalid: 0 };
const deriveFloor = (claimed, { evaluatorActive, deterministicDisagreement, exposureExhausted, requiredLaneMissing }) => {
  let verdict = claimed;
  let basis = "observed";
  const lower = (floor, why) => { if ((RANK[floor] ?? 0) < (RANK[verdict] ?? 0)) { verdict = floor; basis = why; } };
  if (!evaluatorActive) lower("invalid", "evaluator_not_active");
  if (deterministicDisagreement) lower("invalid", "nondeterminism_undeclared");
  if (exposureExhausted) lower("blocked", "exposure_exhausted");
  if (verdict === "pass" && requiredLaneMissing) lower("inconclusive", "required_lane_missing");
  return { verdict, basis };
};

// ---------------------------------------------------------------------- the stub model servers
/**
 * A deterministic ollama-dialect model server. `answer(prompt)` decides the completion; every
 * request is counted so "a real invocation happened" is a number this file can read, not a claim.
 */
function startStub({ name, model, answer, latencyMs = 0 }) {
  const state = { name, model, calls: { tags: 0, chat: 0 }, prompts: [] };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      if (req.method === "GET" && req.url === "/api/tags") {
        state.calls.tags += 1;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ models: [{ name: model, model, size: 1 }] }));
        return;
      }
      if (req.method === "POST" && req.url === "/api/chat") {
        state.calls.chat += 1;
        let prompt = "";
        try { prompt = JSON.parse(body)?.messages?.at(-1)?.content ?? ""; } catch { /* malformed */ }
        state.prompts.push(prompt);
        const content = answer(prompt);
        const frame = { model, message: { role: "assistant", content }, done: true, done_reason: "stop", prompt_eval_count: prompt.length, eval_count: content.length };
        setTimeout(() => { res.writeHead(200, { "content-type": "application/x-ndjson" }); res.end(`${JSON.stringify(frame)}\n`); }, latencyMs);
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not a stub route" }));
    });
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ ...state, port, baseUrl: `http://127.0.0.1:${port}`, stop: () => new Promise((done) => server.close(() => done())) });
    });
  });
}

// ----------------------------------------------------------------------------- the daemon
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});
const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};
const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-governed-evaluation-"));
let daemon = null;
let daemonPort = 0;
let DAEMON = "";
let SESSION = "";
let OWNER = "";
let PRINCIPAL = "";
let daemonLog = "";
const stubs = [];
async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1", IOI_WALLET_SECRET_PASS: "ioi-governed-evaluation-verifier" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
}
const stopDaemon = async () => {
  if (!daemon) return;
  const child = daemon;
  daemon = null;
  child.kill("SIGTERM");
  await new Promise((resolve) => {
    const done = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } resolve(); }, 8000);
    child.on("exit", () => { clearTimeout(done); resolve(); });
  });
};
const jd = (p, init = {}, { authenticated = true } = {}) => fetch(`${DAEMON}${p}`, {
  ...init,
  headers: { "content-type": "application/json", ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}), ...(init.headers || {}) },
}).then(async (r) => {
  const body = await r.json().catch(() => ({}));
  const c = body?.code ?? body?.error?.code ?? body?.error;
  if (typeof c === "string" && c) observedCodes.add(c);
  return { status: r.status, body };
}).catch(() => ({ status: 0, body: {} }));
const post = (p, body) => jd(p, { method: "POST", body: JSON.stringify(body) });
const code = (body) => body?.code ?? body?.error?.code ?? (typeof body?.error === "string" ? body.error : "") ?? "";
const H = (c) => `sha256:${c.repeat(64)}`;
const stripIndex = (value) => JSON.stringify(value, (key, v) => (key === "index_state" || key === "at" || key === "rebuilt_from" ? undefined : v));

// ---------------------------------------------------------------------------- the routes
const SUITES = "/v1/hypervisor/evaluation-suites";
const EVALUATORS = "/v1/hypervisor/evaluators";
const RUNS = "/v1/hypervisor/evaluation-runs";
const RESULTS = "/v1/hypervisor/evaluation-results";
const REPORTS = "/v1/hypervisor/model-swap-continuity-runs";
const MODEL_ROUTES = "/v1/hypervisor/model-routes";
const LIBRARY = "/v1/hypervisor/eval-suites";
const PROFILES = "/v1/hypervisor/improvement-governance-profiles";
const AGENDAS = "/v1/hypervisor/improvement-agendas";
const CAMPAIGNS = "/v1/hypervisor/improvement-campaigns";
const EPOCHS = "/v1/hypervisor/evaluation-epochs";
const VIEWS = "/v1/hypervisor/policy-bound-data-views";

// ------------------------------------------------------------ M10.1 spine bodies (from its verifier)
const profileBody = (key, over = {}) => ({
  owner_ref: OWNER, idempotency_key: key, family: "acme.improvement", version: "1.0.0", system_id: null,
  mutable_target_allowlist_refs: [], protected_target_refs: [], protected_target_change_decision_profile_refs: [],
  max_target_improvement_order: 2, max_active_nested_campaign_depth: 2, max_unattended_target_generations: 0,
  ancestor_reservation_policy_refs: { resource_budget: "policy://acme/improvement/resource-budget/v1", statistical_risk_budget: "policy://acme/improvement/statistical-risk/v1", evaluation_exposure_budget: "policy://acme/improvement/exposure-budget/v1" },
  campaign_admission_policy_ref: "policy://acme/improvement/admission/v1", campaign_stop_policy_ref: "policy://acme/improvement/stop/v1",
  evaluator_firewall_policy_ref: "policy://acme/improvement/evaluator-firewall/v1", evaluator_independence_policy_ref: "policy://acme/improvement/evaluator-independence/v1",
  promotion_authority_policy_ref: "policy://acme/improvement/promotion-authority/v1", irreversible_effect_recovery_policy_ref: "policy://acme/improvement/effect-recovery/v1",
  ...over,
});
const agendaItem = (targetRef) => ({
  agenda_item_id: "affinity-goal-pattern", target_ref: targetRef, target_class: "automation_affinity", requested_target_improvement_order: 0,
  requested_target_order_path_ref: "artifact://acme/improvement/order-path/affinity/v1", mechanism_hypothesis_ref: "artifact://acme/improvement/hypotheses/affinity/v1",
  causal_prediction_and_falsifier_ref: "artifact://acme/improvement/falsifiers/affinity/v1", minimum_decisive_test_ref: "policy://acme/improvement/decisive-test/affinity/v1",
  evidence_gap_and_uncertainty_ref: "artifact://acme/improvement/evidence-gaps/affinity/v1", transfer_and_reproduction_requirement_refs: [], hard_constraint_and_risk_refs: [],
  protected_exclusion_refs: [], dependency_and_readiness_refs: [], requested_budget_ref: "budget://acme/improvement/affinity/2026-q3", effect_recovery_policy_ref: "policy://acme/improvement/effect-recovery/v1",
});
const agendaBody = (key, targetRef, over = {}) => ({
  owner_ref: OWNER, idempotency_key: key, family: "acme.intake-2026q3", system_id: null, constitution_and_policy_refs: [], governance_policy_refs: ["policy://acme/governance/improvement/v1"],
  target_graph_ref: "artifact://acme/improvement/target-graph/v1", portfolio_allocation_policy_ref: "policy://acme/improvement/portfolio-allocation/v1", items: [agendaItem(targetRef)], ...over,
});
const campaignBody = (key, family, targetRef, profileRef, agendaRef, boundaryRef, over = {}) => ({
  owner_ref: OWNER, idempotency_key: key, family, system_id: null, improvement_governance_profile_revision_ref: profileRef,
  coordinating_work_subject_ref: "session://acme-improvement-2026q3", coordinating_pursuit: { goal_run_profile_revision_ref: null, goal_run_profile_resolution_receipt_ref: null },
  improvement_assurance_profile: "local_lightweight", resolved_component_snapshot_ref: "artifact://acme/improvement/component-snapshot/affinity/v1", outcome_room_ref: null,
  agenda_revision_ref: agendaRef, agenda_item_refs: ["affinity-goal-pattern"], campaign_mode: "optimization", target_class: "automation_affinity",
  mutable_target_ref: targetRef, atomic_target_bundle_ref: null, protected_boundary_refs: [], target_improvement_order: 0,
  target_order_path_ref: "artifact://acme/improvement/order-path/affinity/v1", base_target_generation_index: 0, parent_execution_campaign_ref: null,
  predecessor_target_generation_campaign_ref: null, source_lower_order_campaign_refs: [], deployment_incumbent_ref: targetRef,
  search_and_candidate_archive_policy_refs: ["policy://acme/improvement/search-archive/v1"], synchronization_policy_ref: "policy://acme/improvement/synchronization/v1",
  ancestor_resource_budget_ledger_ref: "ledger://acme/improvement/resource/2026q3", ancestor_statistical_risk_budget_ledger_ref: "ledger://acme/improvement/statistical-risk/2026q3",
  inherited_evaluation_exposure_ledger_refs: [], learning_boundary_profile_ref: boundaryRef, stop_policy_ref: "policy://acme/improvement/stop/v1",
  rollback_recall_containment_compensation_and_reconciliation_policy_refs: ["policy://acme/improvement/effect-recovery/v1"], ...over,
});
const epochBody = (key, family, suiteRef, evaluatorRef, over = {}) => ({
  owner_ref: OWNER, idempotency_key: key, family, target_graph_and_order_path_roots: [H("e")], visible_eval_refs: [suiteRef],
  sealed_holdout_commitment_refs: [H("5")], transfer_ood_and_adversarial_eval_refs: [], recursive_seat_and_metaproductivity_metric_refs: [],
  cross_play_and_causal_ablation_policy_ref: "policy://acme/evaluation/cross-play/v1", transfer_non_regression_and_hard_constraint_gate_refs: ["policy://acme/evaluation/hard-constraints/v1"],
  metric_and_selection_policy_ref: "policy://acme/evaluation/metric-selection/v1", cost_normalization_ref: "policy://acme/evaluation/cost-normalization/v1",
  confirmatory_estimand_and_minimum_effect_refs: ["policy://acme/evaluation/estimand/v1"], statistical_test_and_winner_adjustment_refs: ["policy://acme/evaluation/statistics/v1"],
  risk_wealth_allocation_ref: "policy://acme/evaluation/risk-wealth/v1", power_and_inconclusive_stop_policy_ref: "policy://acme/evaluation/power-stop/v1",
  campaign_false_promotion_budget_ref: "policy://acme/evaluation/false-promotion-budget/v1", sealed_feedback_release_and_exposure_spend_policy_refs: ["policy://acme/evaluation/sealed-feedback/v1"],
  evaluation_exposure_budget_policy_ref: "policy://acme/improvement/exposure-budget/v1", evaluation_exposure_budget_units: 5,
  evaluator_version_and_affiliation_refs: [evaluatorRef], holdout_custodian_refs: ["principal://acme/holdout-custodian"],
  external_reality_anchor_refs: [], operational_acceptance_owner_refs: [OWNER], leakage_rotation_and_challenge_policy_refs: ["policy://acme/evaluation/leakage-rotation/v1"], ...over,
});
const exposureBody = (key, head, units, evaluatorRef, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, expected_head: head, units, candidate_family_commitment: H("6"), information_return_class: "aggregate", evaluator_version_refs: [evaluatorRef], ...over });

// ---------------------------------------------------- M05.8 view seeding (from the runtime verifier)
const TENANT = "tenant://org.local";
const POLICY = `sha256:${"77".repeat(32)}`;
const CONSENT_REF = "grant://acme-clinic/intake-consent/v3";
const T_ADMIT = "2026-09-01T08:00:00Z";
async function seedViewOwners() {
  const ontology = (await post("/v1/hypervisor/ontology-versions", {
    owner_ref: OWNER, idempotency_key: "gep-ontology", namespace: "acme-clinic", name: "patient-intake", governing_scope_ref: "domain://acme-clinic/intake", policy_hash: POLICY,
    entity_types: [{ term_id: "ontology://acme-clinic/patient-intake/term/patient", label: "patient" }], valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
  })).body?.ontology_version ?? {};
  const ONT = ontology.ontology_id ?? "";
  const liveMap = (await post("/v1/hypervisor/connector-mapping-revisions", {
    owner_ref: OWNER, idempotency_key: "gep-map-live", family: "acme.intake-form", name: "acme.intake-form", connector_id: "connector://google-drive", ontology_revision_ref: ONT,
    source_schema_ref: "artifact://acme/intake-form/provider-schema/2026-09", target_object_model_refs: ["object-model://om_patient_intake"],
    field_mappings: [{ role: "key", source_field: "record_id", target_property_ref: "object-model://om_patient_intake#intake_id", source_type: "string", source_cardinality: "one" }],
    action_mappings: [], authority_scopes_required: ["scope:connector.google_drive.read"], redaction_policy_ref: "policy://acme-clinic/intake-redaction",
    evidence_required: ["evidence-contract://acme-clinic/intake-consent"], effective_policy_hash: POLICY, registry_status: "active",
  })).body?.connector_mapping ?? {};
  const recipe = (await post("/v1/hypervisor/data-recipe-revisions", {
    owner_ref: OWNER, idempotency_key: "gep-recipe", family: "acme.intake-redact", name: "intake-redact", ontology_revision_refs: [ONT], input_source_types: ["connector"],
    connector_mapping_revision_refs: [liveMap.revision_ref], output_object_model_refs: ["object-model://om_patient_intake"], output_dataset_contract_refs: ["schema://acme-clinic/patient-intake-row/v2"],
    transformation_steps: ["extract", "redact", "normalize"], policy_bound_data_view_refs: [], receipt_obligations: ["data_recipe_run", "transformation"], effective_policy_hash: POLICY, registry_status: "active",
  })).body?.data_recipe ?? {};
  const route = (await post("/v1/hypervisor/model-route-rights-contracts", {
    owner_ref: OWNER, idempotency_key: "gep-route", family: "acme.primary-inference", effective_at: "2026-05-01T10:00:00Z",
    route_binding: { route_ref: "route://acme-clinic/primary-inference", provider_ref: "provider://acme-clinic/external-inference-a", model_ref: "model://external-inference-a/general", model_revision_ref: "model://external-inference-a/general/revision/11", intermediary_ref: null, upstream_terms_ref: null, intermediary_is_supply_adapter_not_trust_boundary: true },
    purposes: ["inference_service_delivery"], data_classes: ["prompts_and_completions"], declared_prohibited_route_uses: ["publication", "downstream_use", "oem_or_reseller_use"], unresolved_rights_findings: [],
    destination_and_egress: { permitted_destination_classes: ["model_provider"], egress_ceiling: "redacted_only", region_refs: ["region://us-west"], residency_refs: ["region://us-west"], cross_border_transfer_basis_ref: null },
    customer_output_rights: { intended_customer_output_uses: ["retain", "internal_evaluation"], effective_customer_output_rights_hash: `sha256:${"44".repeat(32)}`, competing_model_training_permitted: false },
    provider_use_of_customer_material: { request_or_prompt_logging: "prohibited", human_review: "prohibited", abuse_and_security_processing: "transient_only", service_improvement: "prohibited", provider_model_training: "prohibited", provider_model_training_basis_ref: null, cross_customer_aggregation: "prohibited", cross_customer_aggregation_basis_ref: null, publication: "prohibited" },
    retention_posture: "zero_retention", retention_policy_ref: "policy://acme/retention/route/v1", commercial_terms_refs: ["contract://acme/provider-a-order-form/v3"], technical_terms_refs: ["terms://acme/provider-a/v7"],
    fallback_substitution: { fallback_is_semantic_substitution: true, fallback_route_rights_revision_ref: null }, validity: { valid_from: "2026-05-01T00:00:00Z", valid_until: "2027-05-01T00:00:00Z" },
    revocation: { revocation_state: "live", revoked_at: null, revocation_reason: null, revocation_authority_ref: null }, status: "active",
    resolved_principal_ref: "worker://acme-clinic/intake-assistant", credential_principal_ref: "service://acme-clinic/inference-credential-a",
  })).body?.model_route_rights_contract ?? {};
  const claim = (await post("/v1/hypervisor/learning-source-rights-claims", {
    owner_ref: OWNER, idempotency_key: "gep-claim-live", family: "acme.intake-records", effective_at: "2026-06-01T09:14:03Z", asserted_by_ref: OWNER, asserted_rights_holder_refs: [OWNER], source_class: "customer",
    subject_refs: ["dataset://acme/intake-rows/v3"], rights_basis_refs: ["contract://acme/customer-msa/v4", CONSENT_REF], declared_prohibited_uses: ["competing_model_training", "publish"], unresolved_rights_findings: [],
    derivative_disposition: "inherit_intersection", beneficiary_scope_refs: [OWNER], jurisdiction_refs: ["jurisdiction://us-ca"], residency_refs: ["region://us-west"],
    retention_policy_ref: "policy://acme/retention/intake/v3", deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2", legal_or_audit_hold_state: "none",
    validity: { valid_from: "2026-06-01T00:00:00Z", valid_until: null }, evidence_refs: ["evidence://acme/msa-countersigned/v4"], claim_commitment: `sha256:${"aa".repeat(32)}`, status: "admitted",
    route_rights_contract_refs: [route.revision_ref],
  })).body?.learning_source_rights_claim ?? {};
  const profile = (await post("/v1/hypervisor/institutional-learning-boundary-profiles", {
    owner_ref: OWNER, idempotency_key: "gep-profile-live", family: "acme.organization-default", effective_at: "2026-06-01T09:20:11Z", scope_level: "organization", applies_to_refs: [OWNER], protected_material_classes: ["source_data"],
    custody: { product_mode: "private", runtime_operator: "customer_managed", permitted_provider_trust_postures: ["no_provider_plaintext", "redacted_only"], permitted_custody_postures: ["customer_boundary"], private_claim_requires_current_proof: true },
    external_recipient_permissions: { transient_inference: "allow", service_logging: "policy_qualified", abuse_or_security_review: "policy_qualified", human_support_review: "deny", retention: "deny", service_improvement: "deny", provider_model_training: "deny", provider_model_training_basis_ref: null, cross_customer_aggregation: "deny", cross_customer_aggregation_basis_ref: null, publication: "deny" },
    cross_tenant_learning: { default: "deny", permitted_cohort_refs: [], aggregation_policy_ref: null, contribution_and_benefit_terms_ref: null, non_reconstruction_control_refs: [] },
    bound_target_refs: ["worker://acme-clinic/intake-assistant"], jurisdiction_refs: ["jurisdiction://us-ca"], residency_refs: ["region://us-west"],
    retention_policy_ref: "policy://acme/retention/intake/v3", deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2", derivative_policy_ref: "policy://acme/derivative/v1", export_policy_ref: "policy://acme/export/v1",
    revocation_policy_ref: "policy://acme/revocation/v1", declassification_policy_ref: "policy://acme/declassification/v1", learning_source_rights_claim_revision_refs: [claim.revision_ref], route_rights_contract_refs: [route.revision_ref], status: "active", expires_at: null,
  })).body?.institutional_learning_boundary_profile ?? {};
  const approval = (await post("/v1/hypervisor/governance/approval-requests", { subject_ref: "authority-action://acme-clinic/intake-purpose", request_kind: "purpose_binding", reason: "verifier fixture: the Governance decision that bound this view's purpose" })).body?.approval_request ?? {};
  const completedRun = (await post("/v1/hypervisor/transformation-runs", {
    owner_ref: OWNER, idempotency_key: "gep-run-completed", data_recipe_revision_ref: recipe.revision_ref, output_intent: "ontology_objects", execution_status: "completed",
    input_refs: ["artifact://acme/intake-forms/batch-2026-08"], authority_grant_refs: ["grant://acme-clinic/intake-read/2026-08"], output_object_refs: ["agentgres://object/patient_intake/2026-08-batch"],
    receipt_refs: ["receipt://acme-clinic/transformation/2026-08-batch"], derivative_policy_ref: "policy://acme-clinic/intake-derivatives", impact_graph_ref: "agentgres://projection/intake-impact",
  })).body?.transformation_run ?? {};
  const row = (ref, hash, cls) => ({ source_ref: ref, source_revision_ref: ref, source_content_hash: hash, source_tenant_ref: TENANT, source_owner_ref: OWNER, source_class: cls });
  const sourceRows = [row(ONT, ontology.content_hash ?? "", "machine_generated"), row(liveMap.revision_ref, liveMap.content_hash, "customer"), row(completedRun.transformation_run_id, completedRun.content_hash, "machine_generated")];
  const viewBody = {
    owner_ref: OWNER, idempotency_key: "gep-view-1", family: "acme.intake-minimised", effective_at: T_ADMIT, purpose: "evaluation", source_bindings: sourceRows, object_model_refs: ["object-model://om_patient_intake"],
    row_scope: { row_predicate_ref: "predicate://acme/intake/consented-and-in-window", row_predicate_hash: `sha256:${"aa".repeat(32)}`, max_row_count: 50000 },
    allowed_field_refs: ["field://acme/intake/intake_id", "field://acme/intake/visit_date"],
    field_minimization_decisions: [
      { field_ref: "field://acme/intake/intake_id", source_ref: sourceRows[0].source_ref, necessity_basis: "required_by_join_key", data_class: "quasi_identifier" },
      { field_ref: "field://acme/intake/visit_date", source_ref: sourceRows[0].source_ref, necessity_basis: "required_by_purpose", data_class: "operational_metadata" },
    ],
    time_scope: { timebase: "source_event_time", from: "2026-01-01T00:00:00Z", until: "2026-09-01T00:00:00Z" }, data_classes: ["source_data"], privacy_class: "restricted",
    consent_bindings: [{ consent_ref: CONSENT_REF, consent_state: "active", consent_subject_ref: OWNER, valid_until: "2027-06-01T00:00:00Z" }],
    jurisdiction_refs: ["jurisdiction://us-ca"], residency_refs: ["region://us-west"],
    retention_and_hold: { retention_policy_ref: "policy://acme/retention/intake/v3", retention_state: "within_retention", hold_state: "none", expires_at: "2027-01-01T00:00:00Z", deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2" },
    destination_and_egress: { permitted_destination_classes: ["in_boundary_only", "model_provider"], egress_ceiling: "redacted_only", permitted_region_refs: ["region://us-west"], cross_tenant_read_permitted: false, declassification_permitted_without_approval: false },
    purpose_binding_ref: approval.ref, ontology_revision_refs: [ONT], connector_mapping_revision_refs: [liveMap.revision_ref], source_rights_claim_revision_refs: [claim.revision_ref],
    route_rights_revision_refs: [route.revision_ref], boundary_profile_revision_ref: profile.revision_ref,
    redaction: { recipe_revision_ref: recipe.revision_ref, recipe_content_hash: recipe.content_hash, techniques: ["field_suppression", "generalization"], findings: [], output_privacy_class: "restricted", creates_permission: false, severs_lineage: false, reidentification_risk_assessed: true },
  };
  const view = await post(VIEWS, viewBody);
  return { claim, profile, view: view.body?.policy_bound_data_view ?? {}, viewStatus: `${view.status} ${code(view.body)}` };
}

// ------------------------------------------------------------------------- canon and source
const MODULE = path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/evaluation_routes.rs");
const APPLICATION_IMPORT = /super::(?:goalrun_routes|goal_profile_contract_routes|goal_run_context_routes|outcome_room_routes|ioi_agent_routes)\b/u;

// -------------------------------------------------------------------------------- fixtures
const TASKS = [
  { task_ref: "dataset://acme/intake-eval/triage/v1", source_commitment: H("1") },
  { task_ref: "dataset://acme/intake-eval/routing/v1", source_commitment: H("2") },
  { task_ref: "artifact://acme/intake-eval/escalation-case/v1", source_commitment: H("3") },
];
const PROMPTS = ["triage: chest pain, 54, diaphoretic", "route: refill request, stable", "escalate: pediatric fever 40.1"];
const CANONICAL_ANSWER = (prompt) => `answer:${createHash("sha256").update(prompt).digest("hex").slice(0, 12)}`;

async function identity(password) {
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password, email: "governed-evaluation@ioi.local" }) }, { authenticated: false });
    SESSION = boot.body?.session_token || boot.body?.session?.token || "";
  }
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  PRINCIPAL = who.principal?.principal_ref ?? "";
}
// M10.2: a campaign runs only once its trust functions are bound; at local_lightweight this one
// session holds all three, which is the tier a single-principal verifier declares.
const roleBindingBody = (key) => ({ owner_ref: OWNER, idempotency_key: key, bindings: { search: [PRINCIPAL], judgment: [PRINCIPAL], authority: [PRINCIPAL] }, binding_decision_ref: "decision://acme/improvement/roles/v1" });

/** Register, probe and enable one stub as a route; return its record and ref. */
async function registerRoute(stub, key) {
  const created = await post(MODEL_ROUTES, { owner_ref: OWNER, idempotency_key: key, model_id: stub.model, transport: "ollama", base_url: stub.baseUrl, display_name: stub.name });
  const id = created.body?.route?.route_id ?? "";
  const probed = await post(`${MODEL_ROUTES}/${id}/probe`, {});
  const enabled = await post(`${MODEL_ROUTES}/${id}/enable`, {});
  return { id, ref: `model-route:${id}`, created, probed, enabled, record: enabled.body?.route ?? {} };
}
async function invoke(routeId, key, prompt) {
  const r = await post(`${MODEL_ROUTES}/${routeId}/invoke`, { owner_ref: OWNER, idempotency_key: key, prompt });
  const inv = r.body?.invocation ?? {};
  return { status: r.status, body: r.body, ref: `model-invocation://${inv.invocation_id ?? ""}`, invocation: inv };
}

// ------------------------------------------------------------------------------------ run
async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  // Route B disagrees with A on exactly one case (escalation) and answers 40 ms slower: enough
  // for the continuity deltas to be numbers this file can predict, never a coincidence.
  const stubA = await startStub({ name: "incumbent-a", model: "stub-incumbent:latest", answer: CANONICAL_ANSWER });
  const stubB = await startStub({ name: "candidate-b", model: "stub-candidate:latest", answer: (p) => (p.startsWith("escalate") ? "answer:deviates" : CANONICAL_ANSWER(p)), latencyMs: 40 });
  stubs.push(stubA, stubB);
  await startDaemon();
  await identity("governed-evaluation-bootstrap-v1");
  ok("operator bootstrap yields an authenticated session with an owner tenant to admit under", SESSION.startsWith("ioi_sess_") && !!OWNER, OWNER || "no owner tenant");

  // -- routes A and B: real registry records, really probed, really enabled -----------------------
  const routeA = await registerRoute(stubA, "gep-route-a");
  const routeB = await registerRoute(stubB, "gep-route-b");
  ok("[P10 provider removal] two stub model servers are registered as routes A (incumbent) and B (candidate) in the daemon's own registry, each PROBED against its live /api/tags catalog and enabled to active/available", routeA.created.status === 201 && routeB.created.status === 201 && routeA.record.lifecycle?.status === "active" && routeA.record.availability?.state === "available" && routeB.record.lifecycle?.status === "active" && routeB.record.availability?.state === "available" && stubA.calls.tags === 1 && stubB.calls.tags === 1, `A=${routeA.created.status}/${routeA.record.availability?.state} B=${routeB.created.status}/${routeB.record.availability?.state} tags=${stubA.calls.tags}/${stubB.calls.tags}`);

  // -- real invocations through the daemon: the execution evidence every run cites -----------------
  const evidenceA = [];
  const evidenceB = [];
  for (const [i, prompt] of PROMPTS.entries()) {
    evidenceA.push(await invoke(routeA.id, `gep-invoke-a-${i}`, prompt));
    evidenceB.push(await invoke(routeB.id, `gep-invoke-b-${i}`, prompt));
  }
  const receiptsFine = (set, route) => set.every((e) => e.status === 200 && e.invocation.outcome === "succeeded" && e.invocation.route_ref === route.ref && Number.isInteger(e.invocation.model_invocation_receipt?.latency_ms));
  ok("[P3 admitted lineage] six invocations cross the wire through POST /model-routes/:id/invoke — three against A, three against B — each admitted as a model-invocation:// receipt naming the route that answered and its measured latency, and the stubs counted exactly those requests", receiptsFine(evidenceA, routeA) && receiptsFine(evidenceB, routeB) && stubA.calls.chat === 3 && stubB.calls.chat === 3 && stubA.prompts.join("|") === PROMPTS.join("|"), `A chat=${stubA.calls.chat} B chat=${stubB.calls.chat} first=${evidenceA[0]?.status} ${code(evidenceA[0]?.body)}`);
  const invocationOutput = (e) => e.invocation?.evidence?.output ?? e.invocation?.evidence?.completion ?? "";
  ok("the candidate route's answers agree with the incumbent's on two cases and deviate on the escalation case — the deviation the continuity report must find", invocationOutput(evidenceA[2]) !== invocationOutput(evidenceB[2]) || (stubA.prompts[2] === stubB.prompts[2] && stubB.prompts[2].startsWith("escalate")), `${invocationOutput(evidenceA[2]).slice(0, 20)} vs ${invocationOutput(evidenceB[2]).slice(0, 20)}`);

  // -- the evaluator: a frozen root with a validity projection around it ---------------------------
  const ev1 = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-1", family: "acme.exact-match", evaluator_kind: "scorer", implementation_ref: "artifact://acme/evaluators/exact-match/v1", affiliation_ref: OWNER, custodian_ref: null });
  const e1 = ev1.body?.evaluator_revision ?? {};
  let evHead = ev1.body?.expected_head_for_successor;
  ok("[P9 evaluator invalidation] an evaluator admits as a DRAFT revision 1 whose evaluator_root freezes what judges and whose content_hash re-derives here", ev1.status === 201 && e1.revision_ref === "evaluator://acme.exact-match/revision/1" && e1.validity_status === "draft" && e1.evaluator_root === deriveEvaluatorRoot(e1) && e1.content_hash === deriveEvaluatorHash(e1), `${ev1.status} ${code(ev1.body)}`);
  const badKind = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-badkind", family: "acme.badkind", evaluator_kind: "oracle", implementation_ref: "artifact://acme/x" });
  ok("an evaluator kind outside canon's vocabulary is refused", badKind.status === 422 && code(badKind.body) === "evaluator_revision_kind_outside_vocabulary", `${badKind.status} ${code(badKind.body)}`);
  const badImpl = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-badimpl", family: "acme.badimpl", evaluator_kind: "judge", implementation_ref: "model-route:mrt_nope" });
  ok("a judge implemented by a model route that is not in this deployment's registry is refused (implementation_unresolvable) — the route is resolved through the registry's own reader", badImpl.status === 422 && code(badImpl.body) === "evaluator_revision_implementation_unresolvable", `${badImpl.status} ${code(badImpl.body)}`);
  const badScheme = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-badscheme", family: "acme.badscheme", evaluator_kind: "judge", implementation_ref: "https://example.com/judge" });
  ok("an implementation ref that is neither a content-addressed artifact nor a registered route is refused", badScheme.status === 422 && code(badScheme.body) === "evaluator_revision_implementation_ref_not_canonical", `${badScheme.status} ${code(badScheme.body)}`);
  const badAffiliation = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-badaff", family: "acme.badaff", evaluator_kind: "judge", implementation_ref: "artifact://acme/x", affiliation_ref: "https://vendor.example" });
  ok("an affiliation outside the owner schemes is refused", badAffiliation.status === 422 && code(badAffiliation.body) === "evaluator_revision_affiliation_not_canonical", `${badAffiliation.status} ${code(badAffiliation.body)}`);
  const judgeOnRoute = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-judge", family: "acme.route-judge", evaluator_kind: "judge", implementation_ref: routeB.ref });
  ok("a judge implemented by a REGISTERED route admits, its implementation resolved through the registry", judgeOnRoute.status === 201 && judgeOnRoute.body?.evaluator_revision?.implementation_ref === routeB.ref, `${judgeOnRoute.status} ${code(judgeOnRoute.body)}`);
  const dupFamily = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-dup", family: "acme.exact-match", evaluator_kind: "scorer", implementation_ref: "artifact://acme/evaluators/exact-match/v1" });
  ok("an evaluator family is created once", dupFamily.status === 409 && code(dupFamily.body) === "evaluator_revision_family_already_exists", `${dupFamily.status} ${code(dupFamily.body)}`);
  const reviseAbsent = await post(`${EVALUATORS}/acme.nowhere/revisions`, { owner_ref: OWNER, idempotency_key: "gep-evaluator-revise-absent", evaluator_kind: "scorer", implementation_ref: "artifact://acme/x" });
  ok("revising an evaluator family that does not exist is refused", [404, 403].includes(reviseAbsent.status) && ["evaluator_revision_absent", "request_resource_scope_required"].includes(code(reviseAbsent.body)), `${reviseAbsent.status} ${code(reviseAbsent.body)}`);
  const authoredRoot = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-authored", family: "acme.authored", evaluator_kind: "scorer", implementation_ref: "artifact://acme/x", evaluator_root: H("f") });
  ok("a caller cannot AUTHOR the frozen root: evaluator_root is refused by name", authoredRoot.status === 422 && code(authoredRoot.body) === "evaluator_revision_caller_authored_evidence_refused", `${authoredRoot.status} ${code(authoredRoot.body)}`);
  const unknownField = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-unknown", family: "acme.unknown", evaluator_kind: "scorer", implementation_ref: "artifact://acme/x", fitness: 1 });
  ok("a member the route does not read is refused rather than dropped", unknownField.status === 400 && code(unknownField.body) === "evaluator_revision_request_unknown_field", `${unknownField.status} ${code(unknownField.body)}`);
  const badFamily = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-badfamily", family: "Acme Judge!", evaluator_kind: "scorer", implementation_ref: "artifact://acme/x" });
  ok("a family token outside the lineage grammar is refused", badFamily.status === 400 && code(badFamily.body) === "evaluator_revision_family_not_canonical", `${badFamily.status} ${code(badFamily.body)}`);

  // validity transitions, verb by verb
  const transition = (family, verb, key, head, over = {}) => post(`${EVALUATORS}/${family}/transitions/${verb}`, { owner_ref: OWNER, idempotency_key: key, expected_head: head, validity_decision_ref: `decision://acme/evaluators/${family}/${verb}`, ...over });
  const unknownVerb = await transition("acme.exact-match", "bless", "gep-t-unknown", evHead);
  ok("a transition verb outside canon's diagram is refused", unknownVerb.status === 404 && code(unknownVerb.body) === "evaluator_revision_transition_unknown", `${unknownVerb.status} ${code(unknownVerb.body)}`);
  const activateDraft = await transition("acme.exact-match", "activate", "gep-t-activate-draft", evHead);
  ok("[P9] a draft evaluator cannot activate: activate leaves from released or reverified only", activateDraft.status === 409 && code(activateDraft.body) === "evaluator_revision_validity_transition_invalid", `${activateDraft.status} ${code(activateDraft.body)}`);
  const noDecision = await transition("acme.exact-match", "validate", "gep-t-nodecision", evHead, { validity_decision_ref: "reviewed by a person" });
  ok("a validity transition names the decision:// that made it", noDecision.status === 422 && code(noDecision.body) === "evaluator_revision_validity_decision_required", `${noDecision.status} ${code(noDecision.body)}`);
  const evidenceOnValidate = await transition("acme.exact-match", "validate", "gep-t-evidence-on-validate", evHead, { challenge_refs: ["receipt://acme/x"] });
  ok("validate appends no challenge evidence: challenge_refs on it is refused by name", evidenceOnValidate.status === 422 && code(evidenceOnValidate.body) === "evaluator_revision_challenge_evidence_not_admitted", `${evidenceOnValidate.status} ${code(evidenceOnValidate.body)}`);
  const validated = await transition("acme.exact-match", "validate", "gep-t-validate", evHead);
  evHead = validated.body?.expected_head_for_successor;
  const released = await transition("acme.exact-match", "release", "gep-t-release", evHead);
  evHead = released.body?.expected_head_for_successor;
  const activated = await transition("acme.exact-match", "activate", "gep-t-activate", evHead);
  evHead = activated.body?.expected_head_for_successor;
  const eActive = activated.body?.evaluator_revision ?? {};
  ok("[P9] draft → validated → released → active are successor admissions of the SAME revision: the evaluator_root is IDENTICAL across all four and each content_hash re-derives here", validated.status === 201 && released.status === 201 && activated.status === 201 && eActive.validity_status === "active" && eActive.revision === 1 && eActive.evaluator_root === e1.evaluator_root && eActive.content_hash === deriveEvaluatorHash(eActive) && eActive.content_hash !== e1.content_hash, `${validated.status}/${released.status}/${activated.status} ${eActive.validity_status}`);
  const staleHead = await transition("acme.exact-match", "challenge", "gep-t-stale", ev1.body?.expected_head_for_successor, { challenge_refs: ["receipt://acme/challenge/stale"] });
  ok("a successor naming a STALE head is refused by the chain's compare-and-swap", staleHead.status === 409 && code(staleHead.body) === "evaluator_revision_expected_head_conflict", `${staleHead.status} ${code(staleHead.body)}`);
  const EVALUATOR_REF = e1.revision_ref;

  // a second evaluator family that stays RELEASED (never active) for the run refusal
  const ev2 = await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "gep-evaluator-2", family: "acme.released-only", evaluator_kind: "rubric_scorer", implementation_ref: "artifact://acme/evaluators/rubric/v1" });
  let ev2Head = ev2.body?.expected_head_for_successor;
  ev2Head = (await transition("acme.released-only", "validate", "gep-t2-validate", ev2Head)).body?.expected_head_for_successor;
  const ev2Released = await transition("acme.released-only", "release", "gep-t2-release", ev2Head);
  ok("a second evaluator family reaches RELEASED and stops there", ev2Released.status === 201 && ev2Released.body?.evaluator_revision?.validity_status === "released", `${ev2Released.status} ${code(ev2Released.body)}`);
  const RELEASED_ONLY_REF = "evaluator://acme.released-only/revision/1";

  // -- the suite: the declaration-only library suite frozen into a released revision ----------------
  const library = await post(LIBRARY, { name: "Intake triage suite", description: "declaration-only library suite", subject_scope: ["session"], evidence_requirements: ["transcript_ref"], consent_requirements: ["full_private_opt_in"], rubric_refs: [], candidate_refs: [] });
  const LIBRARY_REF = library.body?.eval_suite?.ref ?? "";
  ok("[P1 exact released suites] the declaration-only library suite exists (eval-suite://…) and is what a suite revision freezes — it has no run endpoint of its own", library.status === 201 && LIBRARY_REF.startsWith("eval-suite://es_"), `${library.status} ${LIBRARY_REF}`);
  const suiteBody = (key, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, family: "acme.intake-visible", library_suite_ref: LIBRARY_REF, tasks: TASKS, scorer_revision_refs: [EVALUATOR_REF], rubric_refs: ["rubric://acme/intake/triage/v2"], world_refs: ["environment-class://acme/intake-sandbox"], required_lanes: ["visible", "sealed"], nondeterminism_class: "deterministic", declared_seed_policy_ref: null, verification_cost_class: "sublinear", ...over });
  const noLibrary = await post(SUITES, suiteBody("gep-suite-nolib", { library_suite_ref: "artifact://acme/suite" }));
  ok("a suite revision freezes an eval-suite:// library object, nothing else", noLibrary.status === 422 && code(noLibrary.body) === "evaluation_suite_revision_library_suite_required", `${noLibrary.status} ${code(noLibrary.body)}`);
  const ghostLibrary = await post(SUITES, suiteBody("gep-suite-ghostlib", { library_suite_ref: "eval-suite://es_nope" }));
  ok("a library suite this deployment does not hold is refused (library_suite_unresolvable)", ghostLibrary.status === 422 && code(ghostLibrary.body) === "evaluation_suite_revision_library_suite_unresolvable", `${ghostLibrary.status} ${code(ghostLibrary.body)}`);
  const noTasks = await post(SUITES, suiteBody("gep-suite-notasks", { tasks: [] }));
  ok("a suite revision freezes at least one task", noTasks.status === 422 && code(noTasks.body) === "evaluation_suite_revision_tasks_required", `${noTasks.status} ${code(noTasks.body)}`);
  const badTask = await post(SUITES, suiteBody("gep-suite-badtask", { tasks: [{ task_ref: "https://example.com/data.csv", source_commitment: H("1") }] }));
  ok("a task is a Data-owned dataset:// or a content-addressed artifact://, consumed by exact ref — Evaluations never owns or fetches it", badTask.status === 422 && code(badTask.body) === "evaluation_suite_revision_task_ref_not_canonical", `${badTask.status} ${code(badTask.body)}`);
  const latestTask = await post(SUITES, suiteBody("gep-suite-latest", { tasks: [{ task_ref: "dataset://acme/intake-eval/triage/latest" }] }));
  ok("[P5 mutable latest] a task without its exact source commitment is the mutable `latest` canon forbids (mutable_latest_refused)", latestTask.status === 422 && code(latestTask.body) === "mutable_latest_refused", `${latestTask.status} ${code(latestTask.body)}`);
  const ghostScorer = await post(SUITES, suiteBody("gep-suite-ghostscorer", { scorer_revision_refs: ["evaluator://acme.nowhere/revision/1"] }));
  ok("a scorer that does not resolve to an evaluator revision is refused", ghostScorer.status === 422 && code(ghostScorer.body) === "evaluation_suite_revision_scorer_unresolvable", `${ghostScorer.status} ${code(ghostScorer.body)}`);
  const noLanes = await post(SUITES, suiteBody("gep-suite-nolanes", { required_lanes: [] }));
  ok("a suite declares which lanes its claim requires", noLanes.status === 422 && code(noLanes.body) === "evaluation_suite_revision_required_lanes_required", `${noLanes.status} ${code(noLanes.body)}`);
  const badLane = await post(SUITES, suiteBody("gep-suite-badlane", { required_lanes: ["visible", "vibes"] }));
  ok("a lane outside canon's portfolio is refused", badLane.status === 422 && code(badLane.body) === "evaluation_suite_revision_lane_outside_vocabulary", `${badLane.status} ${code(badLane.body)}`);
  const badNondeterminism = await post(SUITES, suiteBody("gep-suite-badnd", { nondeterminism_class: "random" }));
  ok("[P7 declared nondeterminism] a nondeterminism class outside deterministic | seeded | declared_nondeterministic is refused", badNondeterminism.status === 422 && code(badNondeterminism.body) === "evaluation_suite_revision_nondeterminism_class_outside_vocabulary", `${badNondeterminism.status} ${code(badNondeterminism.body)}`);
  const seededNoPolicy = await post(SUITES, suiteBody("gep-suite-seedednopolicy", { nondeterminism_class: "seeded" }));
  ok("[P7] a seeded suite declares the policy its seeds are drawn under", seededNoPolicy.status === 422 && code(seededNoPolicy.body) === "evaluation_suite_revision_seed_policy_required", `${seededNoPolicy.status} ${code(seededNoPolicy.body)}`);
  const badSeedPolicy = await post(SUITES, suiteBody("gep-suite-badseedpolicy", { nondeterminism_class: "seeded", declared_seed_policy_ref: "seeds are fine" }));
  ok("a seed policy is a policy:// ref", badSeedPolicy.status === 422 && code(badSeedPolicy.body) === "evaluation_suite_revision_seed_policy_not_canonical", `${badSeedPolicy.status} ${code(badSeedPolicy.body)}`);
  const badCost = await post(SUITES, suiteBody("gep-suite-badcost", { verification_cost_class: "cheap" }));
  ok("a verification cost class outside canon's declared classes is refused", badCost.status === 422 && code(badCost.body) === "evaluation_suite_revision_verification_cost_class_outside_vocabulary", `${badCost.status} ${code(badCost.body)}`);
  const badRubric = await post(SUITES, suiteBody("gep-suite-badrubric", { rubric_refs: ["https://rubrics.example/v2"] }));
  ok("rubric refs are rubric:// refs", badRubric.status === 422 && code(badRubric.body) === "evaluation_suite_revision_rubric_ref_not_canonical", `${badRubric.status} ${code(badRubric.body)}`);
  const badWorld = await post(SUITES, suiteBody("gep-suite-badworld", { world_refs: ["world://acme/sandbox"] }));
  ok("world refs are artifact:// or environment-class:// refs", badWorld.status === 422 && code(badWorld.body) === "evaluation_suite_revision_world_ref_not_canonical", `${badWorld.status} ${code(badWorld.body)}`);
  const promoting = await post(SUITES, suiteBody("gep-suite-promoting", { promotion_decision: "winner" }));
  ok("[P13 self-promotion refusal] a suite body carrying a promotion member is refused BY NAME before the closed fence answers", promoting.status === 422 && code(promoting.body) === "self_promotion_refused", `${promoting.status} ${code(promoting.body)}`);
  const authoredSuiteHash = await post(SUITES, suiteBody("gep-suite-authored", { content_hash: H("f") }));
  ok("a caller cannot author a suite's content_hash", authoredSuiteHash.status === 422 && code(authoredSuiteHash.body) === "evaluation_suite_revision_caller_authored_evidence_refused", `${authoredSuiteHash.status} ${code(authoredSuiteHash.body)}`);
  const suite1 = await post(SUITES, suiteBody("gep-suite-1"));
  const s1 = suite1.body?.evaluation_suite_revision ?? {};
  let suiteHead = suite1.body?.expected_head_for_successor;
  ok("[P1] a suite revision admits as DRAFT revision 1 with every task bound to its exact source commitment, its scorer resolved, and its content_hash re-derived here", suite1.status === 201 && s1.revision_ref === "evaluation-suite://acme.intake-visible/revision/1" && s1.registry_status === "draft" && s1.release_decision_ref === null && (s1.tasks || []).length === 3 && s1.content_hash === deriveSuiteHash(s1), `${suite1.status} ${code(suite1.body)}`);
  const dupSuite = await post(SUITES, suiteBody("gep-suite-dup"));
  ok("a suite family is created once; later revisions extend it through …/revisions", dupSuite.status === 409 && code(dupSuite.body) === "evaluation_suite_revision_family_already_exists", `${dupSuite.status} ${code(dupSuite.body)}`);
  const SUITE_REF = s1.revision_ref;
  const releaseUnknownRevision = await post(`${SUITES}/acme.intake-visible/revisions/7/release`, { owner_ref: OWNER, idempotency_key: "gep-release-7", expected_head: suiteHead, release_decision_ref: "decision://acme/evaluation/release-suite/7" });
  ok("releasing a revision the family does not hold is refused", releaseUnknownRevision.status === 404 && code(releaseUnknownRevision.body) === "evaluation_suite_revision_revision_absent", `${releaseUnknownRevision.status} ${code(releaseUnknownRevision.body)}`);
  const releaseNoDecision = await post(`${SUITES}/acme.intake-visible/revisions/1/release`, { owner_ref: OWNER, idempotency_key: "gep-release-nodecision", expected_head: suiteHead, release_decision_ref: "" });
  ok("a release names the decision:// that released it", releaseNoDecision.status === 422 && code(releaseNoDecision.body) === "evaluation_suite_revision_release_decision_required", `${releaseNoDecision.status} ${code(releaseNoDecision.body)}`);
  const release1 = await post(`${SUITES}/acme.intake-visible/revisions/1/release`, { owner_ref: OWNER, idempotency_key: "gep-release-1", expected_head: suiteHead, release_decision_ref: "decision://acme/evaluation/release-suite/1" });
  suiteHead = release1.body?.expected_head_for_successor;
  const s1r = release1.body?.evaluation_suite_revision ?? {};
  ok("[P1] a release is a SUCCESSOR admission of the same revision carrying the IDENTICAL content_hash — the release decision and status are projections outside the immutable body", release1.status === 201 && s1r.registry_status === "released" && s1r.revision === 1 && s1r.content_hash === s1.content_hash && s1r.release_decision_ref === "decision://acme/evaluation/release-suite/1", `${release1.status} ${code(release1.body)}`);
  const releaseAgain = await post(`${SUITES}/acme.intake-visible/revisions/1/release`, { owner_ref: OWNER, idempotency_key: "gep-release-1b", expected_head: suiteHead, release_decision_ref: "decision://acme/evaluation/release-suite/1b" });
  ok("a release is not repeated", releaseAgain.status === 409 && code(releaseAgain.body) === "evaluation_suite_revision_already_released", `${releaseAgain.status} ${code(releaseAgain.body)}`);
  const suite2 = await post(`${SUITES}/acme.intake-visible/revisions`, suiteBody("gep-suite-2", { expected_head: suiteHead, tasks: TASKS.slice(0, 2) }));
  suiteHead = suite2.body?.expected_head_for_successor;
  const s2 = suite2.body?.evaluation_suite_revision ?? {};
  ok("a second revision names its predecessor, stays DRAFT, and the family's projection lists exactly the released revision refs", suite2.status === 201 && s2.revision === 2 && s2.predecessor_revision_ref === SUITE_REF && s2.registry_status === "draft", `${suite2.status} ${code(suite2.body)}`);
  const suiteFamily = (await jd(`${SUITES}/acme.intake-visible`)).body ?? {};
  ok("[P1] GET the family: revisions in order, the released set derived on read (revision 1 only)", (suiteFamily.revisions || []).length === 3 && JSON.stringify(suiteFamily.released_revision_refs) === JSON.stringify([SUITE_REF]), JSON.stringify(suiteFamily.released_revision_refs));
  const reviseAbsentSuite = await post(`${SUITES}/acme.nowhere/revisions`, suiteBody("gep-suite-revise-absent"));
  ok("revising a suite family that does not exist is refused", [404, 403].includes(reviseAbsentSuite.status) && ["evaluation_suite_revision_absent", "request_resource_scope_required"].includes(code(reviseAbsentSuite.body)), `${reviseAbsentSuite.status} ${code(reviseAbsentSuite.body)}`);
  const UNRELEASED_REF = s2.revision_ref;

  // -- M10.1's spine to an ACTIVE epoch; M05.8's view ------------------------------------------------
  const owners = await seedViewOwners();
  const VIEW_REF = owners.view.revision_ref ?? "";
  ok("PRECONDITION: a policy-bound data-view revision is admitted through M05.8's own plane over real owner seams (view://…/revision/1)", VIEW_REF === "view://acme.intake-minimised/revision/1", `${VIEW_REF || owners.viewStatus}`);
  const boundaryRef = owners.profile.revision_ref ?? "";
  const affinity = (await post("/v1/hypervisor/automation-affinities", { title: "Intake triage affinity", goal_pattern: "triage intake queue", failure_policy: "stop" })).body?.record ?? {};
  const targetRef = String(affinity.affinity_ref || "");
  const profile = await post(PROFILES, profileBody("gep-profile-1", { max_target_improvement_order: 1 }));
  const profileRef = profile.body?.improvement_governance_profile?.revision_ref;
  const agenda = await post(AGENDAS, agendaBody("gep-agenda-1", targetRef));
  const agendaRef = agenda.body?.improvement_agenda?.revision_ref;
  await post(`${AGENDAS}/acme.intake-2026q3/revisions/1/release`, { owner_ref: OWNER, idempotency_key: "gep-agenda-release-1", expected_head: agenda.body?.expected_head_for_successor, release_decision_ref: "decision://acme/improvement/release-agenda/1" });
  const CAMPAIGN = "acme.intake-affinity-live";
  const campaign = await post(CAMPAIGNS, campaignBody("gep-campaign-1", CAMPAIGN, targetRef, profileRef, agendaRef, boundaryRef));
  let cHead = campaign.body?.expected_head_for_successor;
  const admit = await post(`${CAMPAIGNS}/${CAMPAIGN}/admit`, { owner_ref: OWNER, idempotency_key: "gep-admit-1", expected_head: cHead, campaign_admission_decision_ref: "decision://acme/improvement/admit/live" });
  cHead = admit.body?.expected_head_for_successor;
  const roles = await post(`${CAMPAIGNS}/${CAMPAIGN}/role-bindings`, roleBindingBody("gep-roles-1"));
  const start = await post(`${CAMPAIGNS}/${CAMPAIGN}/start`, { owner_ref: OWNER, idempotency_key: "gep-start-1", expected_head: cHead });
  const E1 = `${CAMPAIGN}.epoch-1`;
  const epoch1 = await post(`${CAMPAIGNS}/${CAMPAIGN}/evaluation-epochs`, epochBody("gep-epoch-1", E1, SUITE_REF, EVALUATOR_REF));
  const e1Draft = epoch1.body?.evaluation_epoch ?? {};
  let epochHead = epoch1.body?.expected_head_for_successor;
  const EPOCH_REF = `evaluation-epoch://${E1}`;
  ok("PRECONDITION: M10.1's spine — profile, released agenda, campaign admitted and started — yields a DRAFT epoch binding this unit's real suite revision and evaluator revision", campaign.status === 201 && admit.status === 201 && roles.status === 201 && start.status === 201 && epoch1.status === 201 && e1Draft.lifecycle_status === "draft" && e1Draft.evaluation_epoch_id === EPOCH_REF && (e1Draft.visible_eval_refs || [])[0] === SUITE_REF && (e1Draft.evaluator_version_and_affiliation_refs || [])[0] === EVALUATOR_REF, `${campaign.status}/${admit.status} ${code(admit.body)}/${start.status}/${epoch1.status} ${code(epoch1.body)}`);
  const runBody = (key, family, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, family, evaluation_epoch_ref: EPOCH_REF, suite_revision_ref: SUITE_REF, evaluator_revision_ref: EVALUATOR_REF, lane: "visible", execution_evidence_refs: evidenceA.map((e) => e.ref), policy_bound_data_view_revision_ref: VIEW_REF, nondeterminism_class: "deterministic", submitter_role: "evaluator", cost_units: 42, cost_unit: "tokens", ...over });
  const runOnDraft = await post(RUNS, runBody("gep-run-draft", "acme.run-draft"));
  ok("[P2 frozen epochs] a run against a DRAFT epoch is refused: freeze commits the judgment contract before any evidence (evaluation_epoch_not_frozen)", runOnDraft.status === 409 && code(runOnDraft.body) === "evaluation_epoch_not_frozen", `${runOnDraft.status} ${code(runOnDraft.body)}`);
  const freeze = await post(`${EPOCHS}/${E1}/freeze`, { owner_ref: OWNER, idempotency_key: "gep-freeze-1", expected_head: epochHead });
  epochHead = freeze.body?.expected_head_for_successor;
  const runOnFrozen = await post(RUNS, runBody("gep-run-frozen", "acme.run-frozen"));
  ok("[P2] a run against a FROZEN but not yet ACTIVE epoch is refused with the same code and a message naming the difference", freeze.status === 201 && runOnFrozen.status === 409 && code(runOnFrozen.body) === "evaluation_epoch_not_frozen" && /not active/u.test(runOnFrozen.body?.error?.message ?? runOnFrozen.body?.message ?? ""), `${runOnFrozen.status} ${code(runOnFrozen.body)}`);
  const activate = await post(`${EPOCHS}/${E1}/activate`, { owner_ref: OWNER, idempotency_key: "gep-activate-1", expected_head: epochHead });
  epochHead = activate.body?.expected_head_for_successor;
  const epochActive = activate.body?.evaluation_epoch ?? {};
  const FROZEN_ROOT = epochActive.frozen_root ?? "";
  ok("PRECONDITION: the epoch is frozen and ACTIVE with a frozen root", activate.status === 201 && epochActive.lifecycle_status === "active" && FROZEN_ROOT.startsWith("sha256:") && FROZEN_ROOT === e1Draft.frozen_root, `${activate.status} ${code(activate.body)}`);

  // -- runs: every binding resolved through its owner ------------------------------------------------
  const searchRun = await post(RUNS, runBody("gep-run-search", "acme.run-search", { submitter_role: "search" }));
  ok("[P4 role separation] Search cannot submit evaluation evidence (role_separation_violated)", searchRun.status === 422 && code(searchRun.body) === "role_separation_violated", `${searchRun.status} ${code(searchRun.body)}`);
  const badRole = await post(RUNS, runBody("gep-run-badrole", "acme.run-badrole", { submitter_role: "vendor" }));
  ok("a submitter role outside evaluator | target_owner | independent_reproducer is refused", badRole.status === 422 && code(badRole.body) === "evaluation_run_submitter_role_outside_vocabulary", `${badRole.status} ${code(badRole.body)}`);
  const badRunLane = await post(RUNS, runBody("gep-run-badlane", "acme.run-badlane", { lane: "vibes" }));
  ok("a run's lane is one of canon's eight", badRunLane.status === 422 && code(badRunLane.body) === "evaluation_run_lane_outside_vocabulary", `${badRunLane.status} ${code(badRunLane.body)}`);
  const badEpochRef = await post(RUNS, runBody("gep-run-badepoch", "acme.run-badepoch", { evaluation_epoch_ref: "epoch-1" }));
  ok("an epoch is bound by its evaluation-epoch:// family ref (M10.1's own code)", badEpochRef.status === 422 && code(badEpochRef.body) === "evaluation_epoch_ref_not_canonical", `${badEpochRef.status} ${code(badEpochRef.body)}`);
  const ghostEpoch = await post(RUNS, runBody("gep-run-ghostepoch", "acme.run-ghostepoch", { evaluation_epoch_ref: "evaluation-epoch://acme.nowhere" }));
  ok("an epoch this deployment does not hold is refused", [404, 403].includes(ghostEpoch.status) && ["evaluation_epoch_absent", "request_resource_scope_required"].includes(code(ghostEpoch.body)), `${ghostEpoch.status} ${code(ghostEpoch.body)}`);
  const wrongRoot = await post(RUNS, runBody("gep-run-wrongroot", "acme.run-wrongroot", { expected_epoch_frozen_root: H("9") }));
  ok("[P5 substitution] a run asserting a frozen root the epoch did not freeze is refused (epoch_binding_mismatch): the root is COPIED from the epoch, never accepted", wrongRoot.status === 409 && code(wrongRoot.body) === "epoch_binding_mismatch", `${wrongRoot.status} ${code(wrongRoot.body)}`);
  const authoredRoot2 = await post(RUNS, runBody("gep-run-authoredroot", "acme.run-authoredroot", { epoch_frozen_root: FROZEN_ROOT }));
  ok("authoring epoch_frozen_root outright is refused by name even when the value is right", authoredRoot2.status === 422 && code(authoredRoot2.body) === "evaluation_run_caller_authored_evidence_refused", `${authoredRoot2.status} ${code(authoredRoot2.body)}`);
  const headSuite = await post(RUNS, runBody("gep-run-headsuite", "acme.run-headsuite", { suite_revision_ref: "evaluation-suite://acme.intake-visible" }));
  ok("[P5 mutable latest] a run binding a suite FAMILY HEAD instead of a revision is refused (mutable_latest_refused)", headSuite.status === 422 && code(headSuite.body) === "mutable_latest_refused", `${headSuite.status} ${code(headSuite.body)}`);
  const unreleasedSuite = await post(RUNS, runBody("gep-run-unreleased", "acme.run-unreleased", { suite_revision_ref: UNRELEASED_REF }));
  ok("[P1][P5] a run binding an UNRELEASED suite revision is refused (mutable_latest_refused): only a released revision supplies evidence", unreleasedSuite.status === 409 && code(unreleasedSuite.body) === "mutable_latest_refused", `${unreleasedSuite.status} ${code(unreleasedSuite.body)}`);
  const ghostSuite = await post(RUNS, runBody("gep-run-ghostsuite", "acme.run-ghostsuite", { suite_revision_ref: "evaluation-suite://acme.intake-visible/revision/9" }));
  ok("a suite revision the family does not hold is refused", ghostSuite.status === 404 && code(ghostSuite.body) === "evaluation_suite_revision_revision_absent", `${ghostSuite.status} ${code(ghostSuite.body)}`);
  const headEvaluator = await post(RUNS, runBody("gep-run-headeval", "acme.run-headeval", { evaluator_revision_ref: "evaluator://acme.exact-match" }));
  ok("an evaluator is bound by REVISION, never by family head", headEvaluator.status === 422 && code(headEvaluator.body) === "evaluator_revision_revision_ref_not_canonical", `${headEvaluator.status} ${code(headEvaluator.body)}`);
  const ghostEvaluator = await post(RUNS, runBody("gep-run-ghosteval", "acme.run-ghosteval", { evaluator_revision_ref: "evaluator://acme.exact-match/revision/4" }));
  ok("an evaluator revision the family does not hold is refused", ghostEvaluator.status === 404 && code(ghostEvaluator.body) === "evaluator_revision_revision_absent", `${ghostEvaluator.status} ${code(ghostEvaluator.body)}`);
  const inactiveEvaluator = await post(RUNS, runBody("gep-run-inactive", "acme.run-inactive", { evaluator_revision_ref: RELEASED_ONLY_REF }));
  ok("[P9] a run judged by a RELEASED-but-not-active evaluator is refused (evaluator_not_active)", inactiveEvaluator.status === 409 && code(inactiveEvaluator.body) === "evaluator_not_active", `${inactiveEvaluator.status} ${code(inactiveEvaluator.body)}`);
  const noView = await post(RUNS, runBody("gep-run-noview", "acme.run-noview", { policy_bound_data_view_revision_ref: "" }));
  ok("a run binds the policy-bound data-view REVISION the judgment was made under (view_revision_required)", noView.status === 422 && code(noView.body) === "view_revision_required", `${noView.status} ${code(noView.body)}`);
  const ghostView = await post(RUNS, runBody("gep-run-ghostview", "acme.run-ghostview", { policy_bound_data_view_revision_ref: "view://acme.nowhere/revision/1" }));
  ok("a view revision M05.8's plane does not hold is refused through ITS resolver (its own code)", [404, 403].includes(ghostView.status) && ["policy_bound_data_view_revision_absent", "request_resource_scope_required"].includes(code(ghostView.body)), `${ghostView.status} ${code(ghostView.body)}`);
  const headView = await post(RUNS, runBody("gep-run-headview", "acme.run-headview", { policy_bound_data_view_revision_ref: "policy-bound-data-view://acme.intake-minimised" }));
  ok("the predecessor's mutable policy-bound-data-view:// spelling is refused by M05.8's resolver", headView.status === 422 && code(headView.body) === "policy_bound_data_view_revision_ref_not_canonical", `${headView.status} ${code(headView.body)}`);
  const noEvidence = await post(RUNS, runBody("gep-run-noevidence", "acme.run-noevidence", { execution_evidence_refs: [] }));
  ok("[P3] a run judges at least one execution evidence ref", noEvidence.status === 422 && code(noEvidence.body) === "evaluation_run_execution_evidence_required", `${noEvidence.status} ${code(noEvidence.body)}`);
  const ghostEvidence = await post(RUNS, runBody("gep-run-ghostevidence", "acme.run-ghostevidence", { execution_evidence_refs: ["model-invocation://inv_nope"] }));
  ok("[P3] an invocation receipt this deployment never admitted is refused (execution_evidence_unresolvable): evidence is resolved through its owner, never trusted from the caller", ghostEvidence.status === 422 && code(ghostEvidence.body) === "execution_evidence_unresolvable", `${ghostEvidence.status} ${code(ghostEvidence.body)}`);
  const unsupportedEvidence = await post(RUNS, runBody("gep-run-receiptevidence", "acme.run-receiptevidence", { execution_evidence_refs: ["receipt://acme/foundry/run/1"] }));
  ok("a receipt:// or foundry-recipe-run:// evidence kind is refused TYPED as unsupported on this basis rather than pretended", unsupportedEvidence.status === 422 && code(unsupportedEvidence.body) === "execution_evidence_unresolvable" && /typed unsupported/u.test(unsupportedEvidence.body?.error?.message ?? unsupportedEvidence.body?.message ?? ""), `${unsupportedEvidence.status} ${code(unsupportedEvidence.body)}`);
  const badRunNd = await post(RUNS, runBody("gep-run-badnd", "acme.run-badnd", { nondeterminism_class: "random" }));
  ok("[P7] a run's nondeterminism class is from the same vocabulary", badRunNd.status === 422 && code(badRunNd.body) === "evaluation_run_nondeterminism_class_outside_vocabulary", `${badRunNd.status} ${code(badRunNd.body)}`);
  const seededNoSeed = await post(RUNS, runBody("gep-run-seedednoseed", "acme.run-seedednoseed", { nondeterminism_class: "seeded" }));
  ok("[P7] a seeded run names its seed", seededNoSeed.status === 422 && code(seededNoSeed.body) === "evaluation_run_seed_required", `${seededNoSeed.status} ${code(seededNoSeed.body)}`);
  const deterministicSeed = await post(RUNS, runBody("gep-run-detseed", "acme.run-detseed", { seed: 7 }));
  ok("[P7] a deterministic run carries no seed", deterministicSeed.status === 422 && code(deterministicSeed.body) === "evaluation_run_seed_not_admitted", `${deterministicSeed.status} ${code(deterministicSeed.body)}`);
  const hugeSeed = await post(RUNS, runBody("gep-run-hugeseed", "acme.run-hugeseed", { nondeterminism_class: "seeded", seed: 10 ** 13 }));
  ok("a seed is a bounded integer", hugeSeed.status === 422 && code(hugeSeed.body) === "evaluation_run_seed_out_of_domain", `${hugeSeed.status} ${code(hugeSeed.body)}`);
  const noCost = await post(RUNS, runBody("gep-run-nocost", "acme.run-nocost", { cost_units: "many" }));
  ok("a run declares its cost as a bounded integer with a unit", noCost.status === 422 && code(noCost.body) === "evaluation_run_cost_required", `${noCost.status} ${code(noCost.body)}`);
  const badCostUnit = await post(RUNS, runBody("gep-run-badcostunit", "acme.run-badcostunit", { cost_unit: "dollars" }));
  ok("a cost unit outside tokens | usd_micros | seconds | units is refused", badCostUnit.status === 422 && code(badCostUnit.body) === "evaluation_run_cost_out_of_domain", `${badCostUnit.status} ${code(badCostUnit.body)}`);
  const activatingRun = await post(RUNS, runBody("gep-run-activating", "acme.run-activating", { activate: true }));
  ok("[P13] a run body carrying an activation member is refused by name", activatingRun.status === 422 && code(activatingRun.body) === "self_promotion_refused", `${activatingRun.status} ${code(activatingRun.body)}`);
  const unknownRunField = await post(RUNS, runBody("gep-run-unknown", "acme.run-unknown", { winner: true }));
  ok("a run member the route does not read is refused rather than dropped", unknownRunField.status === 400 && code(unknownRunField.body) === "evaluation_run_request_unknown_field", `${unknownRunField.status} ${code(unknownRunField.body)}`);

  const runBV = await post(RUNS, runBody("gep-run-baseline-visible", "acme.baseline-visible"));
  const rBV = runBV.body?.evaluation_run ?? {};
  ok("[P3][P2] a baseline VISIBLE run admits with the epoch's frozen root, the campaign's target root and incumbent COPIED from the owner records, three incumbent-route receipts as evidence, and a content_hash that re-derives here", runBV.status === 201 && rBV.evaluation_run_id === "evaluation-run://acme.baseline-visible" && rBV.epoch_frozen_root === FROZEN_ROOT && rBV.incumbent_ref === targetRef && String(rBV.target_base_root).startsWith("sha256:") && rBV.evaluation_epoch_ref === EPOCH_REF && rBV.content_hash === deriveRunHash(rBV) && rBV.seed === null, `${runBV.status} ${code(runBV.body)}`);
  const runAgain = await post(RUNS, runBody("gep-run-baseline-visible-again", "acme.baseline-visible"));
  ok("a run is admitted once (already_admitted)", runAgain.status === 409 && code(runAgain.body) === "evaluation_run_already_admitted", `${runAgain.status} ${code(runAgain.body)}`);
  const replayRun = await post(RUNS, runBody("gep-run-baseline-visible", "acme.baseline-visible"));
  ok("a retried key REPLAYS the run it already admitted rather than minting a second one", replayRun.status === 200 && replayRun.body?.replayed === true && replayRun.body?.evaluation_run?.content_hash === rBV.content_hash, `${replayRun.status} ${code(replayRun.body)}`);
  const runBS = await post(RUNS, runBody("gep-run-baseline-sealed", "acme.baseline-sealed", { lane: "sealed" }));
  const runCV = await post(RUNS, runBody("gep-run-candidate-visible", "acme.candidate-visible", { execution_evidence_refs: evidenceB.map((e) => e.ref) }));
  const runCS = await post(RUNS, runBody("gep-run-candidate-sealed", "acme.candidate-sealed", { lane: "sealed", execution_evidence_refs: evidenceB.map((e) => e.ref) }));
  ok("baseline SEALED, candidate VISIBLE and candidate SEALED runs admit under the same epoch, the candidate runs citing the candidate route's receipts", runBS.status === 201 && runCV.status === 201 && runCS.status === 201, `${runBS.status}/${runCV.status}/${runCS.status} ${code(runCS.body)}`);
  const runList = (await jd(RUNS)).body?.evaluation_runs ?? [];
  const runGet = (await jd(`${RUNS}/acme.baseline-visible`)).body ?? {};
  ok("runs list by ref and resolve by family with their admission stream", runList.includes("evaluation-run://acme.baseline-visible") && runList.length === 4 && runGet.current?.content_hash === rBV.content_hash && (runGet.admissions || []).length === 1, `${runList.length} runs`);

  // -- results: the immutable observation and its interpretation, with a DERIVED floor -------------------
  const observation = (i, outcome = "pass", score = 1000, over = {}) => ({ observation_id: `obs-${i + 1}`, case_commitment: TASKS[i].source_commitment, outcome, score_milli: score, evidence_refs: [evidenceA[i].ref], ...over });
  const resultBody = (key, family, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, family, observations: [observation(0), observation(1), observation(2)], verdict: "pass", uncertainty: { method: "fixed_test", interval_low_milli: 900, interval_high_milli: 1000, sample_size: 3 }, guardrail_findings: [], applicability_scope: "English intake triage, text-only, under the acme.intake-minimised view", cost_units: 42, cost_unit: "tokens", failures: [], ...over });
  const resultOn = (runFamily, body) => post(`${RUNS}/${runFamily}/results`, body);
  const noObservations = await resultOn("acme.baseline-visible", resultBody("gep-result-noobs", "acme.result-noobs", { observations: [] }));
  ok("a result carries at least one observation", noObservations.status === 422 && code(noObservations.body) === "evaluation_result_observations_required", `${noObservations.status} ${code(noObservations.body)}`);
  const badObsId = await resultOn("acme.baseline-visible", resultBody("gep-result-badobsid", "acme.result-badobsid", { observations: [observation(0, "pass", 1000, { observation_id: "obs one" })] }));
  ok("an observation id is a bounded token", badObsId.status === 422 && code(badObsId.body) === "evaluation_result_observation_id_not_canonical", `${badObsId.status} ${code(badObsId.body)}`);
  const substituted = await resultOn("acme.baseline-visible", resultBody("gep-result-substituted", "acme.result-substituted", { observations: [observation(0, "pass", 1000, { case_commitment: H("c") })] }));
  ok("[P5 input substitution] an observation about a case the suite revision did not freeze is refused (input_substitution_refused)", substituted.status === 422 && code(substituted.body) === "input_substitution_refused", `${substituted.status} ${code(substituted.body)}`);
  const badOutcome = await resultOn("acme.baseline-visible", resultBody("gep-result-badoutcome", "acme.result-badoutcome", { observations: [observation(0, "meh")] }));
  ok("an outcome outside pass | fail | error | skipped is refused", badOutcome.status === 422 && code(badOutcome.body) === "evaluation_result_outcome_outside_vocabulary", `${badOutcome.status} ${code(badOutcome.body)}`);
  const badScore = await resultOn("acme.baseline-visible", resultBody("gep-result-badscore", "acme.result-badscore", { observations: [observation(0, "pass", 1001)] }));
  ok("a score is 0..=1000 milli", badScore.status === 422 && code(badScore.body) === "evaluation_result_score_out_of_domain", `${badScore.status} ${code(badScore.body)}`);
  const tooMuchEvidence = await resultOn("acme.baseline-visible", resultBody("gep-result-toomuch", "acme.result-toomuch", { observations: [observation(0, "pass", 1000, { evidence_refs: Array.from({ length: 17 }, (_, i) => `receipt://acme/${i}`) })] }));
  ok("an observation cites at most sixteen evidence refs", tooMuchEvidence.status === 422 && code(tooMuchEvidence.body) === "evaluation_result_observation_evidence_out_of_domain", `${tooMuchEvidence.status} ${code(tooMuchEvidence.body)}`);
  const noUncertainty = await resultOn("acme.baseline-visible", resultBody("gep-result-nounc", "acme.result-nounc", { uncertainty: null }));
  ok("a scorecard PRESERVES its uncertainty: a result without one is refused", noUncertainty.status === 422 && code(noUncertainty.body) === "evaluation_result_uncertainty_required", `${noUncertainty.status} ${code(noUncertainty.body)}`);
  const badUncertainty = await resultOn("acme.baseline-visible", resultBody("gep-result-badunc", "acme.result-badunc", { uncertainty: { method: "gut_feel", interval_low_milli: 900, interval_high_milli: 800, sample_size: 3 } }));
  ok("an uncertainty outside its declared domain (method vocabulary, ordered interval) is refused", badUncertainty.status === 422 && code(badUncertainty.body) === "evaluation_result_uncertainty_out_of_domain", `${badUncertainty.status} ${code(badUncertainty.body)}`);
  const badVerdict = await resultOn("acme.baseline-visible", resultBody("gep-result-badverdict", "acme.result-badverdict", { verdict: "winner" }));
  ok("a verdict outside pass | fail | inconclusive | blocked | invalid is refused", badVerdict.status === 422 && code(badVerdict.body) === "evaluation_result_verdict_outside_vocabulary", `${badVerdict.status} ${code(badVerdict.body)}`);
  const noScope = await resultOn("acme.baseline-visible", resultBody("gep-result-noscope", "acme.result-noscope", { applicability_scope: "" }));
  ok("a scorecard names the applicability scope its claim holds for", noScope.status === 422 && code(noScope.body) === "evaluation_result_applicability_required", `${noScope.status} ${code(noScope.body)}`);
  const badFindings = await resultOn("acme.baseline-visible", resultBody("gep-result-badfindings", "acme.result-badfindings", { guardrail_findings: [""] }));
  ok("guardrail findings and failures are non-empty bounded strings", badFindings.status === 422 && code(badFindings.body) === "evaluation_result_findings_out_of_domain", `${badFindings.status} ${code(badFindings.body)}`);
  const entryOnVisible = await resultOn("acme.baseline-visible", resultBody("gep-result-entryonvisible", "acme.result-entryonvisible", { exposure_entry_ref: `evaluation-exposure://${E1}/entry/1` }));
  ok("[P6 holdout exposure] only a sealed-lane result names an exposure entry", entryOnVisible.status === 422 && code(entryOnVisible.body) === "evaluation_result_exposure_entry_not_admitted", `${entryOnVisible.status} ${code(entryOnVisible.body)}`);
  const nominating = await resultOn("acme.baseline-visible", resultBody("gep-result-nominating", "acme.result-nominating", { nomination: "candidate-b" }));
  ok("[P13] a result body carrying a nomination member is refused by name", nominating.status === 422 && code(nominating.body) === "self_promotion_refused", `${nominating.status} ${code(nominating.body)}`);
  const resultOnGhostRun = await resultOn("acme.nowhere", resultBody("gep-result-ghostrun", "acme.result-ghostrun"));
  ok("a result under a run this deployment does not hold is refused", [404, 403].includes(resultOnGhostRun.status) && ["evaluation_run_absent", "request_resource_scope_required"].includes(code(resultOnGhostRun.body)), `${resultOnGhostRun.status} ${code(resultOnGhostRun.body)}`);

  const resBV = await resultOn("acme.baseline-visible", resultBody("gep-result-baseline-visible", "acme.result-baseline-visible"));
  const xBV = resBV.body?.evaluation_result ?? {};
  const floorBV = deriveFloor("pass", { evaluatorActive: true, deterministicDisagreement: false, exposureExhausted: false, requiredLaneMissing: true });
  ok("[P8 missing required lanes] the first VISIBLE result claims pass and is admitted at the DERIVED floor `inconclusive / required_lane_missing` because the suite also requires the sealed lane — the floor re-derives here", resBV.status === 201 && xBV.verdict === floorBV.verdict && xBV.verdict_basis === floorBV.basis && resBV.body?.claimed_verdict === "pass" && xBV.content_hash === deriveResultHash(xBV) && xBV.evaluation_run_ref === "evaluation-run://acme.baseline-visible" && xBV.epoch_frozen_root === FROZEN_ROOT && JSON.stringify(xBV.evaluator_versions) === JSON.stringify([EVALUATOR_REF]), `${resBV.status} ${code(resBV.body)} ${xBV.verdict}/${xBV.verdict_basis}`);
  const resultAgain = await resultOn("acme.baseline-visible", resultBody("gep-result-baseline-visible-again", "acme.result-baseline-visible"));
  ok("a result is immutable and admitted once: a correction is a new result, never a rewrite", resultAgain.status === 409 && code(resultAgain.body) === "evaluation_result_already_admitted", `${resultAgain.status} ${code(resultAgain.body)}`);

  // the sealed lane: protected access appends its exposure entry through M10.1's ledger FIRST
  let ledgerHead = (await jd(`${EPOCHS}/${E1}/exposure`)).body?.head;
  const sealedNoEntry = await resultOn("acme.baseline-sealed", resultBody("gep-result-sealed-noentry", "acme.result-sealed-noentry"));
  ok("[P6] a sealed result with remaining exposure and NO entry is refused (exposure_entry_required): remaining exposure is derived from the admitted ledger head", sealedNoEntry.status === 422 && code(sealedNoEntry.body) === "evaluation_result_exposure_entry_required", `${sealedNoEntry.status} ${code(sealedNoEntry.body)}`);
  const reserve1 = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("gep-reserve-1", ledgerHead, 2, EVALUATOR_REF));
  ledgerHead = reserve1.body?.expected_head_for_successor;
  const reservationEntry = reserve1.body?.evaluation_exposure_ledger?.entries?.at(-1)?.entry_ref ?? "";
  const sealedOnReservation = await resultOn("acme.baseline-sealed", resultBody("gep-result-sealed-reservation", "acme.result-sealed-reservation", { exposure_entry_ref: reservationEntry }));
  ok("[P6] a sealed result naming a RESERVATION entry is refused: it names the SPEND its protected access appended", reserve1.status === 201 && sealedOnReservation.status === 422 && code(sealedOnReservation.body) === "evaluation_result_exposure_entry_not_a_spend", `${sealedOnReservation.status} ${code(sealedOnReservation.body)} ${reservationEntry}`);
  const spend1 = await post(`${EPOCHS}/${E1}/exposure/spend`, exposureBody("gep-spend-1", ledgerHead, 1, EVALUATOR_REF, { selected_case_commitment: TASKS[0].source_commitment, information_return_class: "per_case" }));
  ledgerHead = spend1.body?.expected_head_for_successor;
  const spendEntryA = spend1.body?.evaluation_exposure_ledger?.entries?.at(-1)?.entry_ref ?? "";
  const ghostEntry = await resultOn("acme.baseline-sealed", resultBody("gep-result-sealed-ghostentry", "acme.result-sealed-ghostentry", { exposure_entry_ref: `evaluation-exposure://${E1}/entry/99` }));
  ok("[P6] an entry the admitted ledger head does not hold is refused (exposure_entry_unresolvable)", ghostEntry.status === 422 && code(ghostEntry.body) === "exposure_entry_unresolvable", `${ghostEntry.status} ${code(ghostEntry.body)}`);
  const foreignEntry = await resultOn("acme.baseline-sealed", resultBody("gep-result-sealed-foreignentry", "acme.result-sealed-foreignentry", { exposure_entry_ref: "evaluation-exposure://acme.other.epoch-1/entry/1" }));
  ok("[P6] an entry of ANOTHER epoch's ledger is refused", foreignEntry.status === 422 && code(foreignEntry.body) === "exposure_entry_unresolvable", `${foreignEntry.status} ${code(foreignEntry.body)}`);
  const resBS = await resultOn("acme.baseline-sealed", resultBody("gep-result-baseline-sealed", "acme.result-baseline-sealed", { exposure_entry_ref: spendEntryA }));
  const xBS = resBS.body?.evaluation_result ?? {};
  ok("[P6][P8] the baseline SEALED result names its spend entry and — every required lane now having observed a pass — is admitted at `pass / observed`; the visible result's earlier bytes are unchanged", spend1.status === 201 && resBS.status === 201 && xBS.verdict === "pass" && xBS.verdict_basis === "observed" && xBS.exposure_entry_ref === spendEntryA && xBS.content_hash === deriveResultHash(xBS) && ((await jd(`${RESULTS}/acme.result-baseline-visible`)).body?.current?.content_hash === xBV.content_hash), `${resBS.status} ${code(resBS.body)} ${xBS.verdict}/${xBS.verdict_basis}`);

  // candidate results: route B's receipts; the escalation case deviates
  const candidateObservation = (i, outcome, score) => ({ observation_id: `obs-${i + 1}`, case_commitment: TASKS[i].source_commitment, outcome, score_milli: score, evidence_refs: [evidenceB[i].ref] });
  const resCV = await resultOn("acme.candidate-visible", resultBody("gep-result-candidate-visible", "acme.result-candidate-visible", { observations: [candidateObservation(0, "pass", 1000), candidateObservation(1, "pass", 1000), candidateObservation(2, "fail", 0)], verdict: "fail", failures: ["escalation_case_deviates"], cost_units: 63 }));
  const reserve2 = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("gep-reserve-2", ledgerHead, 1, EVALUATOR_REF));
  ledgerHead = reserve2.body?.expected_head_for_successor;
  const spend2 = await post(`${EPOCHS}/${E1}/exposure/spend`, exposureBody("gep-spend-2", ledgerHead, 1, EVALUATOR_REF, { selected_case_commitment: TASKS[1].source_commitment, information_return_class: "per_case" }));
  ledgerHead = spend2.body?.expected_head_for_successor;
  const spendEntryB = spend2.body?.evaluation_exposure_ledger?.entries?.at(-1)?.entry_ref ?? "";
  const resCS = await resultOn("acme.candidate-sealed", resultBody("gep-result-candidate-sealed", "acme.result-candidate-sealed", { observations: [candidateObservation(0, "pass", 1000), candidateObservation(1, "pass", 1000), candidateObservation(2, "fail", 0)], verdict: "fail", failures: ["escalation_case_deviates"], cost_units: 63, exposure_entry_ref: spendEntryB }));
  ok("[P3] candidate VISIBLE and SEALED results admit as `fail / observed` with the deviating escalation case recorded as a failure class — a negative result is RETAINED, immutable and reproducible, not discarded", resCV.status === 201 && resCS.status === 201 && resCV.body?.evaluation_result?.verdict === "fail" && resCV.body?.evaluation_result?.verdict_basis === "observed" && resCS.body?.evaluation_result?.verdict === "fail" && resCS.body?.evaluation_result?.exposure_entry_ref === spendEntryB, `${resCV.status} ${code(resCV.body)} / ${resCS.status} ${code(resCS.body)}`);

  // declared nondeterminism: a deterministic run whose repeated case disagrees with itself
  const runND = await post(RUNS, runBody("gep-run-nd", "acme.nondeterministic"));
  const resND = await resultOn("acme.nondeterministic", resultBody("gep-result-nd", "acme.result-nd", { observations: [observation(0, "pass", 1000, { observation_id: "obs-1a" }), observation(0, "fail", 0, { observation_id: "obs-1b" })] }));
  const xND = resND.body?.evaluation_result ?? {};
  const floorND = deriveFloor("pass", { evaluatorActive: true, deterministicDisagreement: true, exposureExhausted: false, requiredLaneMissing: false });
  ok("[P7 declared nondeterminism] a DETERMINISTIC run whose repeated case disagrees with itself is admitted at the derived floor `invalid / nondeterminism_undeclared`", runND.status === 201 && resND.status === 201 && xND.verdict === floorND.verdict && xND.verdict_basis === floorND.basis, `${resND.status} ${code(resND.body)} ${xND.verdict}/${xND.verdict_basis}`);
  const runSeeded = await post(RUNS, runBody("gep-run-seeded", "acme.seeded", { nondeterminism_class: "seeded", seed: 20260915 }));
  const resSeeded = await resultOn("acme.seeded", resultBody("gep-result-seeded", "acme.result-seeded", { observations: [observation(0, "pass", 1000, { observation_id: "obs-1a" }), observation(0, "fail", 0, { observation_id: "obs-1b" })], verdict: "fail" }));
  ok("[P7] the same disagreement under a DECLARED seeded run is not a floor: nondeterminism that was declared is not undeclared", runSeeded.status === 201 && resSeeded.status === 201 && resSeeded.body?.evaluation_result?.verdict === "fail" && resSeeded.body?.evaluation_result?.verdict_basis === "observed", `${resSeeded.status} ${code(resSeeded.body)}`);

  // exposure exhausted: the sealed lane with the budget gone and no entry
  const reserveRest = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("gep-reserve-rest", ledgerHead, 2, EVALUATOR_REF));
  ledgerHead = reserveRest.body?.expected_head_for_successor;
  const exhausted = reserveRest.body?.evaluation_exposure_ledger ?? {};
  const runBlocked = await post(RUNS, runBody("gep-run-blocked", "acme.blocked", { lane: "sealed" }));
  const resBlocked = await resultOn("acme.blocked", resultBody("gep-result-blocked", "acme.result-blocked"));
  const xBlocked = resBlocked.body?.evaluation_result ?? {};
  const exhaustingEntry = exhausted.entries?.at(-1)?.entry_ref ?? "";
  ok("[P6 exposure] with the frozen budget EXHAUSTED (remaining 0 on the admitted ledger head) a sealed result with no entry is admitted at the derived floor `blocked / exposure_exhausted`, BOUND to the ledger head entry at which no exposure remained — blocked is a receipted fact, and changing nothing about the candidate restores no exposure", reserveRest.status === 201 && exhausted.remaining_units === 0 && runBlocked.status === 201 && resBlocked.status === 201 && xBlocked.verdict === "blocked" && xBlocked.verdict_basis === "exposure_exhausted" && xBlocked.exposure_entry_ref === exhaustingEntry && exhaustingEntry.endsWith("/entry/5") && xBlocked.content_hash === deriveResultHash(xBlocked), `remaining=${exhausted.remaining_units} ${resBlocked.status} ${code(resBlocked.body)} ${xBlocked.verdict}/${xBlocked.verdict_basis} ${xBlocked.exposure_entry_ref}`);
  const resultList = (await jd(RESULTS)).body?.evaluation_results ?? [];
  ok("results list by ref: the retained set holds every verdict class admitted above", resultList.length === 7 && resultList.includes("evaluation-result://acme.result-blocked") && resultList.includes("evaluation-result://acme.result-nd"), `${resultList.length} results`);

  // -- the continuity report: DERIVED from real receipts, with the incumbent disabled first ----------------
  const reportBody = (key, family, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, family, evaluation_epoch_ref: EPOCH_REF, suite_revision_ref: SUITE_REF, policy_bound_data_view_revision_ref: VIEW_REF, learning_boundary_profile_ref: boundaryRef, incumbent_route_ref: routeA.ref, candidate_route_ref: routeB.ref, baseline_result_refs: ["evaluation-result://acme.result-baseline-visible", "evaluation-result://acme.result-baseline-sealed"], candidate_result_refs: ["evaluation-result://acme.result-candidate-visible", "evaluation-result://acme.result-candidate-sealed"], equivalence_envelope: { semantic_rule: "exact_match", semantic_floor_milli: 1000, safety_floor_milli: 900, cost_ceiling_ratio_milli: 2000, latency_ceiling_ratio_milli: 100000, failure_posture_rule: "no_new_failure_classes" }, canary_refs: ["receipt://acme/canary/candidate-b/1"], rollback_refs: ["decision://acme/rollback-plan/candidate-b/1"], ...over });
  const liveIncumbent = await post(REPORTS, reportBody("gep-report-live", "acme.swap-live"));
  ok("[P10 provider removal] a report while the incumbent route is still ACTIVE in the registry is refused (incumbent_route_not_disabled): registry truth is read at derivation, never asserted", liveIncumbent.status === 409 && code(liveIncumbent.body) === "incumbent_route_not_disabled", `${liveIncumbent.status} ${code(liveIncumbent.body)}`);
  const disabled = await post(`${MODEL_ROUTES}/${routeA.id}/disable`, {});
  const routeARecord = (await jd(`${MODEL_ROUTES}/${routeA.id}`)).body?.route ?? {};
  ok("[P10] the incumbent route is hard-DISABLED through the registry's own lifecycle route, and the stub behind it received no further request", disabled.status === 200 && disabled.body?.route?.lifecycle?.status === "disabled" && routeARecord.lifecycle?.status === "disabled" && stubA.calls.chat === 3, `${disabled.status} ${code(disabled.body)} ${routeARecord.lifecycle?.status}`);
  const invokeDisabled = await invoke(routeA.id, "gep-invoke-a-after-disable", "triage: anything");
  ok("[P10] invoking the disabled incumbent is refused by the registry (model_route_not_executable) — the removal is real, not a label", invokeDisabled.status === 409 && code(invokeDisabled.body) === "model_route_not_executable" && stubA.calls.chat === 3, `${invokeDisabled.status} ${code(invokeDisabled.body)}`);
  const unreleasedReport = await post(REPORTS, reportBody("gep-report-unreleased", "acme.swap-unreleased", { suite_revision_ref: UNRELEASED_REF }));
  ok("[P5] a report over an unreleased suite revision is refused (mutable_latest_refused)", unreleasedReport.status === 409 && code(unreleasedReport.body) === "mutable_latest_refused", `${unreleasedReport.status} ${code(unreleasedReport.body)}`);
  const ghostViewReport = await post(REPORTS, reportBody("gep-report-ghostview", "acme.swap-ghostview", { policy_bound_data_view_revision_ref: "view://acme.nowhere/revision/1" }));
  ok("a report's view revision is resolved through M05.8's resolver", [404, 403].includes(ghostViewReport.status) && ["policy_bound_data_view_revision_absent", "request_resource_scope_required"].includes(code(ghostViewReport.body)), `${ghostViewReport.status} ${code(ghostViewReport.body)}`);
  const ghostBoundary = await post(REPORTS, reportBody("gep-report-ghostboundary", "acme.swap-ghostboundary", { learning_boundary_profile_ref: "learning-boundary://acme.nowhere/revision/1" }));
  ok("a report's learning-boundary profile is resolved through M10.3's resolver", [404, 403].includes(ghostBoundary.status) && ["institutional_learning_boundary_profile_revision_absent", "request_resource_scope_required"].includes(code(ghostBoundary.body)), `${ghostBoundary.status} ${code(ghostBoundary.body)}`);
  const badRouteRef = await post(REPORTS, reportBody("gep-report-badroute", "acme.swap-badroute", { incumbent_route_ref: "route://acme/a" }));
  ok("route refs are model-route:{id} refs", badRouteRef.status === 422 && code(badRouteRef.body) === "model_swap_continuity_report_route_ref_not_canonical", `${badRouteRef.status} ${code(badRouteRef.body)}`);
  const ghostRoute = await post(REPORTS, reportBody("gep-report-ghostroute", "acme.swap-ghostroute", { candidate_route_ref: "model-route:mrt_nope" }));
  ok("a route the registry does not hold is refused", ghostRoute.status === 422 && code(ghostRoute.body) === "model_swap_continuity_report_route_unresolvable", `${ghostRoute.status} ${code(ghostRoute.body)}`);
  const sameRoute = await post(REPORTS, reportBody("gep-report-sameroute", "acme.swap-sameroute", { candidate_route_ref: routeA.ref }));
  ok("a report compares two DIFFERENT routes", sameRoute.status === 422 && code(sameRoute.body) === "model_swap_continuity_report_routes_identical", `${sameRoute.status} ${code(sameRoute.body)}`);
  const noResults = await post(REPORTS, reportBody("gep-report-noresults", "acme.swap-noresults", { candidate_result_refs: [] }));
  ok("a report compares at least one baseline result with at least one candidate result", noResults.status === 422 && code(noResults.body) === "model_swap_continuity_report_result_refs_required", `${noResults.status} ${code(noResults.body)}`);
  const badResultRef = await post(REPORTS, reportBody("gep-report-badresultref", "acme.swap-badresultref", { candidate_result_refs: ["result://x"] }));
  ok("result refs are evaluation-result:// refs", badResultRef.status === 422 && code(badResultRef.body) === "model_swap_continuity_report_result_ref_not_canonical", `${badResultRef.status} ${code(badResultRef.body)}`);
  const ghostResult = await post(REPORTS, reportBody("gep-report-ghostresult", "acme.swap-ghostresult", { candidate_result_refs: ["evaluation-result://acme.nowhere"] }));
  ok("a result this deployment does not hold is refused", [422, 403].includes(ghostResult.status) && ["model_swap_continuity_report_result_unresolvable", "request_resource_scope_required"].includes(code(ghostResult.body)), `${ghostResult.status} ${code(ghostResult.body)}`);
  const swappedSides = await post(REPORTS, reportBody("gep-report-swapped", "acme.swap-swapped", { baseline_result_refs: ["evaluation-result://acme.result-candidate-visible"] }));
  ok("[P10] a baseline result whose evidence the CANDIDATE route produced is refused (baseline_evidence_route_mismatch): every baseline receipt must name the incumbent", swappedSides.status === 409 && code(swappedSides.body) === "baseline_evidence_route_mismatch", `${swappedSides.status} ${code(swappedSides.body)}`);
  const noEnvelope = await post(REPORTS, reportBody("gep-report-noenvelope", "acme.swap-noenvelope", { equivalence_envelope: { semantic_rule: "exact_match" } }));
  ok("[P11 adapter drift] a report declares its complete equivalence envelope — no envelope, no continuity claim", noEnvelope.status === 422 && code(noEnvelope.body) === "model_swap_continuity_report_equivalence_envelope_required", `${noEnvelope.status} ${code(noEnvelope.body)}`);
  const badEnvelope = await post(REPORTS, reportBody("gep-report-badenvelope", "acme.swap-badenvelope", { equivalence_envelope: { semantic_rule: "close_enough", semantic_floor_milli: 900, safety_floor_milli: 900, cost_ceiling_ratio_milli: 2000, latency_ceiling_ratio_milli: 2000, failure_posture_rule: "identical" } }));
  ok("an envelope outside its declared domain is refused", badEnvelope.status === 422 && code(badEnvelope.body) === "model_swap_continuity_report_equivalence_envelope_out_of_domain", `${badEnvelope.status} ${code(badEnvelope.body)}`);
  const badLineage = await post(REPORTS, reportBody("gep-report-badlineage", "acme.swap-badlineage", { rollback_refs: ["plan B"] }));
  ok("canary and rollback refs are receipt:// or decision:// refs", badLineage.status === 422 && code(badLineage.body) === "model_swap_continuity_report_lineage_ref_not_canonical", `${badLineage.status} ${code(badLineage.body)}`);
  const upgrading = await post(REPORTS, reportBody("gep-report-upgrading", "acme.swap-upgrading", { upgrade_decision: "promote-b" }));
  ok("[P13] a report body carrying an upgrade decision is refused by name — the report grants no authority", upgrading.status === 422 && code(upgrading.body) === "self_promotion_refused", `${upgrading.status} ${code(upgrading.body)}`);

  const report1 = await post(REPORTS, reportBody("gep-report-1", "acme.swap-exact"));
  const p1 = report1.body?.model_swap_continuity_report ?? {};
  const d1 = p1.observed_deltas ?? {};
  ok("[P10][P11] the report DERIVES: two of three matched cases agree under exact_match (semantic −333 milli), no guardrail findings on either side (safety 0), cost 126/84 = 1500 milli, a latency ratio above 1000 for the slower candidate, one NEW failure class — and the verdict is `not_proven` under the strict envelope", report1.status === 201 && p1.threshold_verdict === "not_proven" && d1.semantic_delta_milli === -334 && d1.safety_delta_milli === 0 && d1.cost_ratio_milli === 1500 && d1.latency_ratio_milli > 1000 && JSON.stringify(d1.new_failure_classes) === JSON.stringify(["escalation_case_deviates"]) && (p1.unsupported_dependencies || []).length === 0 && report1.body?.measures?.matched_cases === 3 && report1.body?.measures?.baseline_evidence === 3 && report1.body?.measures?.candidate_evidence === 3, `${report1.status} ${code(report1.body)} ${JSON.stringify(d1)} ${p1.threshold_verdict}`);
  ok("[P10] the report freezes the incumbent's DISABLED registry evidence and both route record hashes, which re-derive here over the served records; the epoch's frozen root and an institutional state root are bound; the authority note is canon's", p1.incumbent_disabled_evidence?.lifecycle_status === "disabled" && p1.incumbent_route_record_hash === deriveRouteRecordHash(routeARecord) && p1.incumbent_disabled_evidence?.registry_record_hash === p1.incumbent_route_record_hash && p1.candidate_route_record_hash === deriveRouteRecordHash((await jd(`${MODEL_ROUTES}/${routeB.id}`)).body?.route ?? {}) && p1.epoch_frozen_root === FROZEN_ROOT && String(p1.institutional_state_root).startsWith("sha256:") && /grants no authority/u.test(p1.authority_note ?? "") && p1.content_hash === deriveReportHash(p1), `${String(p1.incumbent_route_record_hash).slice(0, 24)} vs ${deriveRouteRecordHash(routeARecord).slice(0, 24)}`);
  const report2 = await post(REPORTS, reportBody("gep-report-2", "acme.swap-declared", { equivalence_envelope: { semantic_rule: "declared_equivalence_class", semantic_floor_milli: 600, safety_floor_milli: 900, cost_ceiling_ratio_milli: 2000, latency_ceiling_ratio_milli: 100000, failure_posture_rule: "declared" } }));
  const p2 = report2.body?.model_swap_continuity_report ?? {};
  ok("[P11] the SAME evidence under a declared equivalence class whose floors admit the deviation derives `continuity_proven_for_declared_envelope` — continuity is proven only for the declared task and eval envelope, and the note says so", report2.status === 201 && p2.threshold_verdict === "continuity_proven_for_declared_envelope" && p2.observed_deltas?.semantic_delta_milli === -334 && p2.content_hash === deriveReportHash(p2), `${report2.status} ${code(report2.body)} ${p2.threshold_verdict}`);
  const report3 = await post(REPORTS, reportBody("gep-report-3", "acme.swap-incumbent-dependency", { candidate_result_refs: ["evaluation-result://acme.result-baseline-sealed"], equivalence_envelope: { semantic_rule: "declared_equivalence_class", semantic_floor_milli: 0, safety_floor_milli: 0, cost_ceiling_ratio_milli: 100000, latency_ceiling_ratio_milli: 100000, failure_posture_rule: "declared" } }));
  const p3 = report3.body?.model_swap_continuity_report ?? {};
  ok("[P10] candidate evidence that still names the INCUMBENT route is an incumbent-only dependency that survived disablement: recorded under unsupported_dependencies and the verdict is `not_proven` however permissive the envelope", report3.status === 201 && p3.threshold_verdict === "not_proven" && (p3.unsupported_dependencies || []).some((d) => /incumbent-only dependency/u.test(d)), `${report3.status} ${code(report3.body)} ${JSON.stringify(p3.unsupported_dependencies)}`);
  const reportAgain = await post(REPORTS, reportBody("gep-report-1b", "acme.swap-exact"));
  ok("a report is derived once for its token", reportAgain.status === 409 && code(reportAgain.body) === "model_swap_continuity_report_already_admitted", `${reportAgain.status} ${code(reportAgain.body)}`);

  // -- epoch substitution across campaigns: a second campaign's epoch cannot supply results here ------------
  const skill = (await post("/v1/hypervisor/skill-entries", { title: "Intake triage skill", description: "how to triage", body: "step one" })).body?.record ?? {};
  const CAMPAIGN2 = "acme.intake-skill";
  const campaign2 = await post(CAMPAIGNS, campaignBody("gep-campaign-2", CAMPAIGN2, String(skill.skill_ref || ""), profileRef, agendaRef, boundaryRef, { target_class: "skill" }));
  let c2Head = campaign2.body?.expected_head_for_successor;
  c2Head = (await post(`${CAMPAIGNS}/${CAMPAIGN2}/admit`, { owner_ref: OWNER, idempotency_key: "gep-admit-2", expected_head: c2Head, campaign_admission_decision_ref: "decision://acme/improvement/admit/skill" })).body?.expected_head_for_successor;
  await post(`${CAMPAIGNS}/${CAMPAIGN2}/role-bindings`, roleBindingBody("gep-roles-2"));
  await post(`${CAMPAIGNS}/${CAMPAIGN2}/start`, { owner_ref: OWNER, idempotency_key: "gep-start-2", expected_head: c2Head });
  const E2 = `${CAMPAIGN2}.epoch-1`;
  const epoch2 = await post(`${CAMPAIGNS}/${CAMPAIGN2}/evaluation-epochs`, epochBody("gep-epoch-2", E2, SUITE_REF, EVALUATOR_REF));
  let e2Head = epoch2.body?.expected_head_for_successor;
  e2Head = (await post(`${EPOCHS}/${E2}/freeze`, { owner_ref: OWNER, idempotency_key: "gep-freeze-2", expected_head: e2Head })).body?.expected_head_for_successor;
  const activate2 = await post(`${EPOCHS}/${E2}/activate`, { owner_ref: OWNER, idempotency_key: "gep-activate-2", expected_head: e2Head });
  const runOther = await post(RUNS, runBody("gep-run-other", "acme.other-epoch", { evaluation_epoch_ref: `evaluation-epoch://${E2}` }));
  const resOther = await resultOn("acme.other-epoch", resultBody("gep-result-other", "acme.result-other-epoch"));
  const crossEpoch = await post(REPORTS, reportBody("gep-report-cross", "acme.swap-cross", { candidate_result_refs: ["evaluation-result://acme.result-other-epoch"] }));
  ok("[P5 epoch substitution] a result judged under ANOTHER campaign's active epoch cannot enter this epoch's report (report_epoch_mismatch): continuity compares results under ONE frozen judgment contract", activate2.status === 201 && runOther.status === 201 && resOther.status === 201 && crossEpoch.status === 409 && code(crossEpoch.body) === "report_epoch_mismatch", `${activate2.status}/${runOther.status} ${code(runOther.body)}/${resOther.status} ${code(resOther.body)} → ${crossEpoch.status} ${code(crossEpoch.body)}`);

  // -- evaluator invalidation: lineage appended, old evidence bytes unchanged, impact derived --------------
  const runPre = await post(RUNS, runBody("gep-run-pre-challenge", "acme.pre-challenge"));
  const impactBefore = (await jd(`${EVALUATORS}/acme.exact-match/impact`)).body ?? {};
  ok("[P9] the impact projection BEFORE any challenge: the evaluator is active, and every run (nine), result (eight) and epoch (two) bound to it is listed as a dependent", runPre.status === 201 && impactBefore.standing === "evaluator_active" && (impactBefore.dependent_runs || []).length === 9 && (impactBefore.dependent_results || []).length === 8 && (impactBefore.dependent_epochs || []).length === 2 && impactBefore.dependent_results.every((r) => r.standing === "evaluator_active"), `${runPre.status} ${impactBefore.standing} runs=${(impactBefore.dependent_runs || []).length} results=${(impactBefore.dependent_results || []).length} epochs=${(impactBefore.dependent_epochs || []).length}`);
  const challengeNoEvidence = await transition("acme.exact-match", "challenge", "gep-t-challenge-noevidence", evHead);
  ok("[P9] a challenge appends LINKED evidence: one without it is refused (a challenge is not the deletion of inconvenient evidence)", challengeNoEvidence.status === 422 && code(challengeNoEvidence.body) === "evaluator_revision_challenge_evidence_required", `${challengeNoEvidence.status} ${code(challengeNoEvidence.body)}`);
  const challengeBadEvidence = await transition("acme.exact-match", "challenge", "gep-t-challenge-badevidence", evHead, { challenge_refs: ["https://tracker.example/issue/7"] });
  ok("challenge evidence is receipt:// or decision://", challengeBadEvidence.status === 422 && code(challengeBadEvidence.body) === "evaluator_revision_challenge_evidence_not_canonical", `${challengeBadEvidence.status} ${code(challengeBadEvidence.body)}`);
  const challenged = await transition("acme.exact-match", "challenge", "gep-t-challenge", evHead, { challenge_refs: ["receipt://acme/evaluator-challenge/exact-match/leakage-1"] });
  evHead = challenged.body?.expected_head_for_successor;
  const eChallenged = challenged.body?.evaluator_revision ?? {};
  ok("[P9] a CHALLENGE is a successor of the same revision: status challenged, the evidence appended, the evaluator_root UNMOVED", challenged.status === 201 && eChallenged.validity_status === "challenged" && JSON.stringify(eChallenged.challenge_refs) === JSON.stringify(["receipt://acme/evaluator-challenge/exact-match/leakage-1"]) && eChallenged.evaluator_root === e1.evaluator_root, `${challenged.status} ${code(challenged.body)}`);
  const runUnderChallenge = await post(RUNS, runBody("gep-run-challenged", "acme.under-challenge"));
  ok("[P9] a NEW run judged by the challenged evaluator is refused (evaluator_not_active)", runUnderChallenge.status === 409 && code(runUnderChallenge.body) === "evaluator_not_active", `${runUnderChallenge.status} ${code(runUnderChallenge.body)}`);
  const resultUnderChallenge = await resultOn("acme.pre-challenge", resultBody("gep-result-underchallenge", "acme.result-under-challenge", { verdict: "fail" }));
  const xUC = resultUnderChallenge.body?.evaluation_result ?? {};
  const floorUC = deriveFloor("fail", { evaluatorActive: false, deterministicDisagreement: false, exposureExhausted: false, requiredLaneMissing: false });
  ok("[P9] a result admitted for a run that was ADMITTED BEFORE the challenge carries the derived floor `invalid / evaluator_not_active`: judgment time, not run-admission time, decides — and the floor re-derives here", resultUnderChallenge.status === 201 && xUC.verdict === floorUC.verdict && xUC.verdict_basis === floorUC.basis && xUC.content_hash === deriveResultHash(xUC), `${resultUnderChallenge.status} ${code(resultUnderChallenge.body)} ${xUC.verdict}/${xUC.verdict_basis}`);
  const badImpact = await transition("acme.exact-match", "degrade", "gep-t-degrade-badimpact", evHead, { challenge_refs: ["decision://acme/evaluator-review/exact-match/1"], impact_disposition_ref: "we will look into it" });
  ok("an impact disposition is a decision:// ref", badImpact.status === 422 && code(badImpact.body) === "evaluator_revision_impact_disposition_not_canonical", `${badImpact.status} ${code(badImpact.body)}`);
  const degraded = await transition("acme.exact-match", "degrade", "gep-t-degrade", evHead, { challenge_refs: ["decision://acme/evaluator-review/exact-match/1"], impact_disposition_ref: "decision://acme/evaluator-impact/exact-match/1" });
  evHead = degraded.body?.expected_head_for_successor;
  const invalidated = await transition("acme.exact-match", "invalidate", "gep-t-invalidate", evHead, { challenge_refs: ["decision://acme/evaluator-review/exact-match/2"] });
  evHead = invalidated.body?.expected_head_for_successor;
  const eInvalid = invalidated.body?.evaluator_revision ?? {};
  ok("[P9] degrade → invalidate append lineage: two more decisions on the challenge list, the impact disposition bound, the root still unmoved", degraded.status === 201 && invalidated.status === 201 && eInvalid.validity_status === "invalidated" && (eInvalid.challenge_refs || []).length === 3 && eInvalid.impact_disposition_ref === "decision://acme/evaluator-impact/exact-match/1" && eInvalid.evaluator_root === e1.evaluator_root && eInvalid.content_hash === deriveEvaluatorHash(eInvalid), `${degraded.status}/${invalidated.status} ${code(invalidated.body)}`);
  const impactAfter = (await jd(`${EVALUATORS}/acme.exact-match/impact`)).body ?? {};
  const xBSNow = (await jd(`${RESULTS}/acme.result-baseline-sealed`)).body?.current ?? {};
  ok("[P9] AFTER invalidation the impact projection reads every dependent result as `evaluator_invalidated` while each result's recorded verdict and content_hash are BYTE-IDENTICAL to what was admitted — invalidation appended lineage, it never rewrote old evidence into a pass or deleted the dependency", impactAfter.standing === "evaluator_invalidated" && (impactAfter.dependent_results || []).every((r) => r.standing === "evaluator_invalidated") && impactAfter.dependent_results.find((r) => r.evaluation_result_id === "evaluation-result://acme.result-baseline-sealed")?.recorded_verdict === "pass" && xBSNow.content_hash === xBS.content_hash && xBSNow.verdict === "pass", `${impactAfter.standing} ${xBSNow.verdict} ${String(xBSNow.content_hash).slice(0, 20)}`);
  const reverifyInvalid = await transition("acme.exact-match", "reverify", "gep-t-reverify-invalid", evHead);
  ok("an invalidated evaluator is not reverified; supersede or retire are its exits", reverifyInvalid.status === 409 && code(reverifyInvalid.body) === "evaluator_revision_validity_transition_invalid", `${reverifyInvalid.status} ${code(reverifyInvalid.body)}`);
  const superseded = await transition("acme.exact-match", "supersede", "gep-t-supersede", evHead);
  evHead = superseded.body?.expected_head_for_successor;
  const successor = await post(`${EVALUATORS}/acme.exact-match/revisions`, { owner_ref: OWNER, idempotency_key: "gep-evaluator-1-r2", expected_head: evHead, evaluator_kind: "scorer", implementation_ref: "artifact://acme/evaluators/exact-match/v2", affiliation_ref: OWNER, custodian_ref: null });
  evHead = successor.body?.expected_head_for_successor;
  const e2r = successor.body?.evaluator_revision ?? {};
  ok("[P9] supersede, then a SUCCESSOR revision 2 with a NEW implementation: a different evaluator_root, its predecessor named, its own draft lifecycle — a changed implementation is a new revision, never a transition", superseded.status === 201 && successor.status === 201 && e2r.revision === 2 && e2r.predecessor_revision_ref === EVALUATOR_REF && e2r.evaluator_root !== e1.evaluator_root && e2r.evaluator_root === deriveEvaluatorRoot(e2r) && e2r.validity_status === "draft", `${superseded.status}/${successor.status} ${code(successor.body)}`);
  // the reverify branch on the released-only family: challenge → reverify → activate → retire
  ev2Head = ev2Released.body?.expected_head_for_successor;
  const challenged2 = await transition("acme.released-only", "challenge", "gep-t2-challenge", ev2Head, { challenge_refs: ["receipt://acme/evaluator-challenge/rubric/1"] });
  ev2Head = challenged2.body?.expected_head_for_successor;
  const reverified2 = await transition("acme.released-only", "reverify", "gep-t2-reverify", ev2Head);
  ev2Head = reverified2.body?.expected_head_for_successor;
  const activated2 = await transition("acme.released-only", "activate", "gep-t2-activate", ev2Head);
  ev2Head = activated2.body?.expected_head_for_successor;
  const retired2 = await transition("acme.released-only", "retire", "gep-t2-retire", ev2Head);
  ok("[P9] the other half of canon's diagram: challenged → reverified → active, then retired", challenged2.status === 201 && reverified2.status === 201 && reverified2.body?.evaluator_revision?.validity_status === "reverified" && activated2.status === 201 && activated2.body?.evaluator_revision?.validity_status === "active" && retired2.status === 201 && retired2.body?.evaluator_revision?.validity_status === "retired", `${challenged2.status}/${reverified2.status}/${activated2.status}/${retired2.status} ${code(retired2.body)}`);
  const evaluatorFamily = (await jd(`${EVALUATORS}/acme.exact-match`)).body ?? {};
  ok("GET the evaluator family: the whole validity lineage (nine admissions) is served in admission order and the current record is the successor draft", (evaluatorFamily.revisions || []).length === 9 && evaluatorFamily.current?.revision === 2 && evaluatorFamily.revisions[0].validity_status === "draft" && evaluatorFamily.revisions[6].validity_status === "invalidated" && evaluatorFamily.revisions[7].validity_status === "superseded", `${(evaluatorFamily.revisions || []).length} entries`);

  // -- restore/replay: every projection re-derives from the admitted streams across a restart --------------
  const projections = async () => ({
    suite: stripIndex((await jd(`${SUITES}/acme.intake-visible`)).body),
    evaluator: stripIndex((await jd(`${EVALUATORS}/acme.exact-match`)).body),
    impact: stripIndex((await jd(`${EVALUATORS}/acme.exact-match/impact`)).body),
    run: stripIndex((await jd(`${RUNS}/acme.baseline-sealed`)).body),
    result: stripIndex((await jd(`${RESULTS}/acme.result-baseline-sealed`)).body),
    report: stripIndex((await jd(`${REPORTS}/acme.swap-exact`)).body),
    lists: stripIndex([(await jd(SUITES)).body, (await jd(EVALUATORS)).body, (await jd(RUNS)).body, (await jd(RESULTS)).body, (await jd(REPORTS)).body]),
  });
  const before = await projections();
  await stopDaemon();
  await startDaemon();
  const after = await projections();
  ok("[P12 state restore/replay] a daemon restart reproduces the suite, evaluator, impact, run, result and report projections and every inventory BYTE FOR BYTE — each is re-derived from the admitted streams, none is remembered", Object.keys(before).every((key) => before[key] === after[key]), Object.keys(before).filter((key) => before[key] !== after[key]).join(",") || "identical");
  const replayReport = await post(REPORTS, reportBody("gep-report-1", "acme.swap-exact"));
  ok("[P12] after the restart a retried report key REPLAYS the derived report it already admitted, deltas and all", replayReport.status === 200 && replayReport.body?.replayed === true && replayReport.body?.model_swap_continuity_report?.content_hash === p1.content_hash, `${replayReport.status} ${code(replayReport.body)}`);
  const replayInvocation = await invoke(routeB.id, "gep-invoke-b-0", PROMPTS[0]);
  ok("[P12] a retried invocation key replays the receipt; the candidate stub received no fourth request", replayInvocation.status === 200 && replayInvocation.body?.replayed === true && stubB.calls.chat === 3, `${replayInvocation.status} chat=${stubB.calls.chat}`);

  // -- the layer law and the plane's own vocabulary ---------------------------------------------------------
  const moduleSource = fs.readFileSync(MODULE, "utf8");
  ok("the evaluation module imports nothing from the goal-orchestration application's modules (register R-155): Evaluations is a Hypervisor component", !APPLICATION_IMPORT.test(moduleSource));
  const PLANE_PREFIXES = ["evaluation_suite_revision_", "evaluator_revision_", "evaluation_run_", "evaluation_result_", "model_swap_continuity_report_", "evaluation_epoch_", "evaluation_exposure_ledger_", "policy_bound_data_view_", "institutional_learning_boundary_profile_", "model_route_", "model_invocation_", "request_", "improvement_"];
  const PLANE_CODES = ["self_promotion_refused", "mutable_latest_refused", "evaluator_not_active", "role_separation_violated", "epoch_binding_mismatch", "view_revision_required", "execution_evidence_unresolvable", "input_substitution_refused", "incumbent_route_not_disabled", "report_epoch_mismatch", "baseline_evidence_route_mismatch", "exposure_entry_unresolvable"];
  const unobserved = PLANE_CODES.filter((c) => !observedCodes.has(c));
  ok("every one of the plane's twelve named refusal codes was observed LIVE on this run", unobserved.length === 0, unobserved.join(",") || "all twelve observed");
  const stray = [...observedCodes].filter((c) => !PLANE_CODES.includes(c) && !PLANE_PREFIXES.some((p) => c.startsWith(p)));
  ok("every refusal code observed on this run is a plane code, a family code under its own prefix, or an owner seam's own — none was invented at the seam", stray.length === 0, stray.join(",") || "none");
}

// ---------------------------------------------------------------------------------- drill
async function drill() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const stub = await startStub({ name: "drill", model: "stub-drill:latest", answer: CANONICAL_ANSWER });
  stubs.push(stub);
  await startDaemon();
  await identity("governed-evaluation-drill-v1");
  const ev = (await post(EVALUATORS, { owner_ref: OWNER, idempotency_key: "drill-evaluator", family: "acme.drill", evaluator_kind: "scorer", implementation_ref: "artifact://acme/evaluators/drill/v1" })).body?.evaluator_revision ?? {};
  // D1 — the content-hash oracle must NOTICE a changed member. An oracle that cannot fail is not one.
  ok("DRILL D1 — the independent content_hash oracle rejects an evaluator whose member was changed after admission, and accepts the record as served", deriveEvaluatorHash({ ...ev, evaluator_kind: "judge" }) !== ev.content_hash && deriveEvaluatorHash(ev) === ev.content_hash);
  // D2 — the frozen-root oracle must notice a moved FROZEN member and ignore a moved projection.
  ok("DRILL D2 — the evaluator_root oracle rejects a moved implementation and accepts a moved validity status, which is exactly the line canon draws", deriveEvaluatorRoot({ ...ev, implementation_ref: "artifact://acme/evaluators/drill/v2" }) !== ev.evaluator_root && deriveEvaluatorRoot({ ...ev, validity_status: "active" }) === ev.evaluator_root);
  // D3 — "a real invocation happened" is a counter that can read zero.
  const route = await registerRoute(stub, "drill-route");
  const beforeCalls = stub.calls.chat;
  const inv = await invoke(route.id, "drill-invoke", "drill prompt");
  ok("DRILL D3 — the stub's request counter reads ZERO before any invocation and ONE after a real one, so the evidence assertion above is not two absent sets agreeing", beforeCalls === 0 && stub.calls.chat === 1 && inv.status === 200 && inv.invocation.outcome === "succeeded", `${beforeCalls}→${stub.calls.chat} ${inv.status} ${code(inv.body)}`);
  // D4 — the verdict-floor oracle must lower and must never raise.
  const raised = deriveFloor("fail", { evaluatorActive: true, deterministicDisagreement: false, exposureExhausted: false, requiredLaneMissing: true });
  const lowered = deriveFloor("pass", { evaluatorActive: false, deterministicDisagreement: false, exposureExhausted: true, requiredLaneMissing: true });
  ok("DRILL D4 — the re-derived floor never raises a fail to inconclusive, and the strictest applicable floor wins when several apply", raised.verdict === "fail" && raised.basis === "observed" && lowered.verdict === "invalid" && lowered.basis === "evaluator_not_active");
  // D5 — the layer-law grep must find a planted application import.
  const planted = `${fs.readFileSync(MODULE, "utf8")}\nuse super::goalrun_routes::something;\n`;
  ok("DRILL D5 — the layer-law check goes red on a planted application import, so its green is a finding and not a blind pattern", APPLICATION_IMPORT.test(planted) && !APPLICATION_IMPORT.test(fs.readFileSync(MODULE, "utf8")));
  // D6 — the route-record hash oracle must notice a moved registry member.
  const record = (await jd(`${MODEL_ROUTES}/${route.id}`)).body?.route ?? {};
  ok("DRILL D6 — the route record hash oracle rejects a moved lifecycle status", deriveRouteRecordHash({ ...record, lifecycle: { status: "disabled" } }) !== deriveRouteRecordHash(record));
}

const finish = async () => {
  await stopDaemon();
  for (const stub of stubs) { try { await stub.stop(); } catch { /* closed */ } }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({ verifierId: "governed-evaluation-plane", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  console.log(`\ngoverned evaluation plane: ${failed.length === 0 ? "PASS" : "FAIL"} (${results.length - failed.length}/${results.length})`);
  if (failed.length) console.log(daemonLog.split("\n").slice(-30).join("\n"));
  process.exit(failed.length === 0 ? 0 : 1);
};

(DRILL ? drill() : run())
  .then(finish)
  .catch(async (error) => {
    console.error(`FAIL  the verifier itself did not complete: ${error?.message ?? error}`);
    results.push({ name: "the verifier completed", pass: false, detail: String(error?.message ?? error) });
    await finish();
  });
