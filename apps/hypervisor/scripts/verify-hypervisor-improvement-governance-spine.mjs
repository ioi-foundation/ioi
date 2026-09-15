#!/usr/bin/env node
// check:improvement-governance-spine — M10.1, against an ISOLATED real daemon.
//
// THE UNIT'S CLAIM is that the six objects of the bounded improvement campaign spine — governance
// profile, agenda, campaign, evaluation epoch, exposure ledger and order-cutoff receipt — are
// immutable, owner-scoped, successor-lineaged registered records on the shared mutation chain,
// that the direct proposal path works with no campaign anywhere near it, and that the campaign
// owns no production mutation. Canon: foundations/objects/bounded-improvement.md;
// components/daemon-runtime/improvement-governance-gates.md § Bounded improvement campaign spine.
//
// THE ORACLES ARE INDEPENDENT. Every commitment the daemon serves — `content_hash`,
// `campaign_contract_root`, `operation_head_root`, `frozen_root`, `ledger_head_root`, each ledger
// `entry_root` and `receipt_root` — is RE-DERIVED HERE in JavaScript from the record's own members
// under canon's domain separators and compared with the daemon's number. Reading the daemon's hash
// back and calling it verified would be asking the committer whether it committed. The self-drill
// plants a changed member in the re-derived copy and requires these oracles to notice.
//
// "THE CAMPAIGN OWNS NO PRODUCTION MUTATION" IS MEASURED, NOT ASSERTED. Every other observable
// family is read before and after every campaign operation and required to be byte-identical; the
// one operation allowed to differ — the upgrade-proposal handoff — must differ by EXACTLY one
// pending proposal, and the drill writes a real record between two reads to prove the comparison
// can go red.
//
// THE REASON-CODE FAMILY IS ENTAILED IN BOTH DIRECTIONS at the level canon declares: canon's
// seventeen are parsed from the fenced block itself, the ten canon marks implemented must each be
// observed live on this run, and none of the seven canon marks target may appear in the module's
// source. The direct path is proven green BEFORE any campaign object exists and AGAIN after all six
// do, on the same daemon.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   --mutation  run the planted defects instead of trusting the assertions above.
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
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
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
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
  profile: "ioi.improvement-governance-profile-content-commitment-jcs-sha256.v1",
  agenda: "ioi.improvement-agenda-content-commitment-jcs-sha256.v1",
  campaignContract: "ioi.improvement-campaign-contract-root-jcs-sha256.v1",
  campaign: "ioi.improvement-campaign-content-commitment-jcs-sha256.v1",
  campaignHead: "ioi.improvement-campaign-operation-head-jcs-sha256.v1",
  epochFrozen: "ioi.evaluation-epoch-frozen-root-jcs-sha256.v1",
  epoch: "ioi.evaluation-epoch-content-commitment-jcs-sha256.v1",
  ledger: "ioi.evaluation-exposure-ledger-content-commitment-jcs-sha256.v1",
  entry: "ioi.evaluation-exposure-entry-root-jcs-sha256.v1",
  cutoffReceipt: "ioi.improvement-order-cutoff-receipt-root-jcs-sha256.v1",
  cutoff: "ioi.improvement-order-cutoff-receipt-content-commitment-jcs-sha256.v1",
};
const PROFILE_MATERIAL = ["schema_version", "improvement_governance_profile_id", "revision_ref", "version", "predecessor_revision_ref", "owner_ref", "system_id", "mutable_target_allowlist_refs", "protected_target_refs", "protected_target_change_decision_profile_refs", "max_target_improvement_order", "max_active_nested_campaign_depth", "max_unattended_target_generations", "ancestor_reservation_policy_refs", "campaign_admission_policy_ref", "campaign_stop_policy_ref", "evaluator_firewall_policy_ref", "evaluator_independence_policy_ref", "promotion_authority_policy_ref", "irreversible_effect_recovery_policy_ref"];
const AGENDA_MATERIAL = ["schema_version", "improvement_agenda_id", "revision_ref", "revision", "predecessor_revision_ref", "owner_ref", "system_id", "constitution_and_policy_refs", "governance_policy_refs", "target_graph_ref", "portfolio_allocation_policy_ref", "items"];
const CAMPAIGN_CONTRACT = ["schema_version", "improvement_campaign_id", "campaign_contract_revision_ref", "campaign_contract_revision", "predecessor_contract_revision_ref", "owner_ref", "system_id", "improvement_governance_profile_revision_ref", "coordinating_work_subject_ref", "coordinating_pursuit", "improvement_assurance_profile", "resolved_component_snapshot_ref", "outcome_room_ref", "agenda_revision_ref", "agenda_item_refs", "campaign_mode", "target_class", "mutable_target_ref", "atomic_target_bundle_ref", "target_base_root", "protected_boundary_refs", "target_improvement_order", "pursuit_method_order", "target_to_pursuit_method_edge_ref", "target_order_path_ref", "base_target_generation_index", "parent_execution_campaign_ref", "predecessor_target_generation_campaign_ref", "source_lower_order_campaign_refs", "deployment_incumbent_ref", "deployment_incumbent_root", "search_and_candidate_archive_policy_refs", "synchronization_policy_ref", "ancestor_resource_budget_ledger_ref", "ancestor_statistical_risk_budget_ledger_ref", "inherited_evaluation_exposure_ledger_refs", "learning_boundary_profile_ref", "effective_learning_policy_hash", "stop_policy_ref", "rollback_recall_containment_compensation_and_reconciliation_policy_refs"];
const CAMPAIGN_CONTENT = [...CAMPAIGN_CONTRACT, "campaign_contract_root", "effective_governance_snapshot_ref", "campaign_admission_decision_ref", "campaign_admission_receipt_ref", "admission_authority_and_constitution_snapshot_refs", "target_order_assignment_receipt_ref", "effective_target_order_ceiling", "effective_target_order_ceiling_ref", "max_active_nested_campaign_depth", "child_work_subject_refs", "candidate_archive_ref", "candidate_resolved_component_snapshot_refs", "active_evaluation_epoch_ref", "historical_evaluation_epoch_refs", "improvement_order_cutoff_receipt_refs", "resource_reservation_refs", "statistical_risk_reservation_refs", "evaluation_exposure_reservation_refs", "operation_head_sequence", "derived_state_projection_ref", "lifecycle_status"];
const EPOCH_FROZEN = ["schema_version", "evaluation_epoch_id", "campaign_ref", "campaign_contract_revision_ref", "campaign_contract_root", "predecessor_epoch_ref", "pursuit_goal_run_profile_revision_ref", "pursuit_profile_resolution_and_component_snapshot_refs", "target_improvement_order", "pursuit_method_order", "base_target_generation_index", "target_graph_and_order_path_roots", "deployment_incumbent_ref", "deployment_incumbent_root", "synchronization_cutoff_receipt_ref", "visible_eval_refs", "sealed_holdout_commitment_refs", "transfer_ood_and_adversarial_eval_refs", "recursive_seat_and_metaproductivity_metric_refs", "cross_play_and_causal_ablation_policy_ref", "transfer_non_regression_and_hard_constraint_gate_refs", "metric_and_selection_policy_ref", "cost_normalization_ref", "confirmatory_estimand_and_minimum_effect_refs", "statistical_test_and_winner_adjustment_refs", "risk_wealth_allocation_ref", "power_and_inconclusive_stop_policy_ref", "campaign_false_promotion_budget_ref", "ancestor_statistical_risk_budget_ledger_ref", "inherited_evaluation_exposure_ledger_refs", "sealed_feedback_release_and_exposure_spend_policy_refs", "evaluation_exposure_budget_policy_ref", "evaluation_exposure_budget_units", "evaluator_version_and_affiliation_refs", "holdout_custodian_refs", "external_reality_anchor_refs", "operational_acceptance_owner_refs", "leakage_rotation_and_challenge_policy_refs"];
const EPOCH_CONTENT = [...EPOCH_FROZEN, "frozen_root", "lifecycle_ref", "lifecycle_status", "challenge_evidence_refs"];
const LEDGER_CONTENT = ["schema_version", "evaluation_exposure_ledger_id", "evaluation_epoch_ref", "ancestor_exposure_ledger_refs", "steward_refs", "sealed_suite_and_world_commitment_refs", "exposure_budget_ref", "exposure_budget_units", "reserved_units", "spent_units", "returned_units", "remaining_units", "contaminated", "entries", "admitted_entry_refs", "ledger_head_sequence", "ledger_head_root", "derived_exposure_and_contamination_projection_ref", "lifecycle_decision_refs"];
const ENTRY_ROOT = ["entry_seq", "entry_ref", "entry_kind", "units", "candidate_family_commitment", "selected_case_commitment", "information_return_class", "evaluator_version_refs", "access_receipt_refs", "contamination_flag", "previous_entry_root"];
const CUTOFF_RECEIPT = ["schema_version", "receipt_id", "receipt_profile", "receipt_profile_ref", "source_campaign_ref", "source_evaluation_epoch_ref", "synchronization_wave_ref", "source_campaign_epoch_and_archive_roots", "source_target_improvement_order", "source_target_generation_cutoff", "intended_destination_target_order", "per_order_source_version_and_cutoff_vector_ref", "destination_base_root", "agenda_revision_ref", "agenda_and_task_distribution_roots", "boundary_crossing", "eligible_finding_and_outcome_refs", "learning_evidence_eligibility_refs", "learning_egress_receipt_refs", "boundary_enforcement_access_and_custody_receipt_refs", "effective_learning_policy_hash", "denied_or_quarantined_information_class_refs", "source_incumbent_resolved_component_snapshot_ref", "inherited_budget_risk_and_exposure_reservation_roots", "dependency_and_statistical_assumption_delta_ref", "signal_bundle_ref", "terminal_disposition", "previous_cutoff_receipt_root"];
const CUTOFF_CONTENT = [...CUTOFF_RECEIPT, "receipt_root"];

const deriveProfileHash = (r) => digestOver(r, DOMAINS.profile, PROFILE_MATERIAL);
const deriveAgendaHash = (r) => digestOver(r, DOMAINS.agenda, AGENDA_MATERIAL);
const deriveContractRoot = (r) => digestOver(r, DOMAINS.campaignContract, CAMPAIGN_CONTRACT);
const deriveCampaignHash = (r) => digestOver(r, DOMAINS.campaign, CAMPAIGN_CONTENT);
const deriveHeadRoot = (previous, contentHash) => digestOver({ previous_operation_head_root: previous, content_hash: contentHash }, DOMAINS.campaignHead, ["previous_operation_head_root", "content_hash"]);
const deriveFrozenRoot = (r) => digestOver(r, DOMAINS.epochFrozen, EPOCH_FROZEN);
const deriveEpochHash = (r) => digestOver(r, DOMAINS.epoch, EPOCH_CONTENT);
const deriveLedgerHash = (r) => digestOver(r, DOMAINS.ledger, LEDGER_CONTENT);
const deriveEntryRoot = (e) => digestOver(e, DOMAINS.entry, ENTRY_ROOT);
const deriveGenesisLedgerRoot = (id) => digestOver({ evaluation_exposure_ledger_id: id }, DOMAINS.entry, ["evaluation_exposure_ledger_id"]);
const deriveReceiptRoot = (r) => digestOver(r, DOMAINS.cutoffReceipt, CUTOFF_RECEIPT);
const deriveCutoffHash = (r) => digestOver(r, DOMAINS.cutoff, CUTOFF_CONTENT);
const deriveTargetRoot = (targetRef, record) => sha(jcs({ domain: "ioi.improvement-mutable-target-root-jcs-sha256.v1", target_ref: targetRef, record }));

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
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-improvement-spine-"));
let daemon = null;
let daemonPort = 0;
let DAEMON = "";
let SESSION = "";
let OWNER = "";
let daemonLog = "";
async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
}
const stopDaemon = async () => {
  if (!daemon) return;
  daemon.kill("SIGTERM");
  await new Promise((resolve) => {
    const done = setTimeout(() => { daemon.kill("SIGKILL"); resolve(); }, 8000);
    daemon.on("exit", () => { clearTimeout(done); resolve(); });
  });
  daemon = null;
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

// ---------------------------------------------------------------------------- the fixtures
const PROFILES = "/v1/hypervisor/improvement-governance-profiles";
const AGENDAS = "/v1/hypervisor/improvement-agendas";
const CAMPAIGNS = "/v1/hypervisor/improvement-campaigns";
const EPOCHS = "/v1/hypervisor/evaluation-epochs";
const PROPOSALS = "/v1/hypervisor/intelligence/improvement-proposals";
const H = (c) => `sha256:${c.repeat(64)}`;

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
  improvement_assurance_profile: "independent_review", resolved_component_snapshot_ref: "artifact://acme/improvement/component-snapshot/affinity/v1", outcome_room_ref: null,
  agenda_revision_ref: agendaRef, agenda_item_refs: ["affinity-goal-pattern"], campaign_mode: "optimization", target_class: "automation_affinity",
  mutable_target_ref: targetRef, atomic_target_bundle_ref: null, protected_boundary_refs: [], target_improvement_order: 0,
  target_order_path_ref: "artifact://acme/improvement/order-path/affinity/v1", base_target_generation_index: 0, parent_execution_campaign_ref: null,
  predecessor_target_generation_campaign_ref: null, source_lower_order_campaign_refs: [], deployment_incumbent_ref: targetRef,
  search_and_candidate_archive_policy_refs: ["policy://acme/improvement/search-archive/v1"], synchronization_policy_ref: "policy://acme/improvement/synchronization/v1",
  ancestor_resource_budget_ledger_ref: "ledger://acme/improvement/resource/2026q3", ancestor_statistical_risk_budget_ledger_ref: "ledger://acme/improvement/statistical-risk/2026q3",
  inherited_evaluation_exposure_ledger_refs: [], learning_boundary_profile_ref: boundaryRef, stop_policy_ref: "policy://acme/improvement/stop/v1",
  rollback_recall_containment_compensation_and_reconciliation_policy_refs: ["policy://acme/improvement/effect-recovery/v1"], ...over,
});
const epochBody = (key, family, over = {}) => ({
  owner_ref: OWNER, idempotency_key: key, family, target_graph_and_order_path_roots: [H("e")], visible_eval_refs: ["evaluation-suite://acme/intake-visible/revision/4"],
  sealed_holdout_commitment_refs: [H("5")], transfer_ood_and_adversarial_eval_refs: [], recursive_seat_and_metaproductivity_metric_refs: [],
  cross_play_and_causal_ablation_policy_ref: "policy://acme/evaluation/cross-play/v1", transfer_non_regression_and_hard_constraint_gate_refs: ["policy://acme/evaluation/hard-constraints/v1"],
  metric_and_selection_policy_ref: "policy://acme/evaluation/metric-selection/v1", cost_normalization_ref: "policy://acme/evaluation/cost-normalization/v1",
  confirmatory_estimand_and_minimum_effect_refs: ["policy://acme/evaluation/estimand/v1"], statistical_test_and_winner_adjustment_refs: ["policy://acme/evaluation/statistics/v1"],
  risk_wealth_allocation_ref: "policy://acme/evaluation/risk-wealth/v1", power_and_inconclusive_stop_policy_ref: "policy://acme/evaluation/power-stop/v1",
  campaign_false_promotion_budget_ref: "policy://acme/evaluation/false-promotion-budget/v1", sealed_feedback_release_and_exposure_spend_policy_refs: ["policy://acme/evaluation/sealed-feedback/v1"],
  evaluation_exposure_budget_policy_ref: "policy://acme/improvement/exposure-budget/v1", evaluation_exposure_budget_units: 5,
  evaluator_version_and_affiliation_refs: ["evaluator://acme/intake-judge/revision/7"], holdout_custodian_refs: ["principal://acme/holdout-custodian"],
  external_reality_anchor_refs: [], operational_acceptance_owner_refs: [OWNER], leakage_rotation_and_challenge_policy_refs: ["policy://acme/evaluation/leakage-rotation/v1"], ...over,
});
const exposureBody = (key, head, units, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, expected_head: head, units, candidate_family_commitment: H("6"), information_return_class: "aggregate", evaluator_version_refs: ["evaluator://acme/intake-judge/revision/7"], ...over });
const claimBody = (key) => ({
  owner_ref: OWNER, idempotency_key: key, family: "acme.intake-records", effective_at: "2026-06-01T09:14:03Z", asserted_by_ref: OWNER, asserted_rights_holder_refs: [OWNER], source_class: "customer",
  subject_refs: ["dataset://acme/intake-rows/v3"], rights_basis_refs: ["contract://acme/customer-msa/v4"], declared_prohibited_uses: ["fine_tune", "distill", "competing_model_training"],
  unresolved_rights_findings: [{ use: "export", resolution: "missing", subject_ref: "dataset://acme/intake-rows/v3" }], derivative_disposition: "inherit_intersection", beneficiary_scope_refs: [OWNER],
  jurisdiction_refs: ["jurisdiction://us-ca"], residency_refs: ["region://us-west"], retention_policy_ref: "policy://acme/retention/intake/v3", deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2",
  legal_or_audit_hold_state: "none", validity: { valid_from: "2026-06-01T00:00:00Z", valid_until: null }, evidence_refs: ["evidence://acme/msa-countersigned/v4"], claim_commitment: H("a"), status: "admitted",
});
const boundaryBody = (key, claimRef) => ({
  owner_ref: OWNER, idempotency_key: key, family: "acme.organization-default", effective_at: "2026-06-01T09:20:11Z", scope_level: "organization", applies_to_refs: [OWNER],
  protected_material_classes: ["source_data", "prompts_and_completions"], learning_source_rights_claim_revision_refs: [claimRef],
  custody: { product_mode: "private", runtime_operator: "customer_managed", permitted_provider_trust_postures: ["no_provider_plaintext", "redacted_only"], permitted_custody_postures: ["customer_boundary", "customer_vpc"], private_claim_requires_current_proof: true },
  external_recipient_permissions: { transient_inference: "allow", service_logging: "policy_qualified", abuse_or_security_review: "policy_qualified", human_support_review: "deny", retention: "deny", service_improvement: "deny", provider_model_training: "deny", provider_model_training_basis_ref: null, cross_customer_aggregation: "deny", cross_customer_aggregation_basis_ref: null, publication: "deny" },
  cross_tenant_learning: { default: "deny", permitted_cohort_refs: [], aggregation_policy_ref: null, contribution_and_benefit_terms_ref: null, non_reconstruction_control_refs: [] },
  bound_target_refs: ["worker://acme-clinic/intake-assistant"], jurisdiction_refs: ["jurisdiction://us-ca"], residency_refs: ["region://us-west"],
  retention_policy_ref: "policy://acme/retention/intake/v3", deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2", derivative_policy_ref: "policy://acme/derivative/v1",
  export_policy_ref: "policy://acme/export/v1", revocation_policy_ref: "policy://acme/revocation/v1", declassification_policy_ref: "policy://acme/declassification/v1", status: "active",
});
const eligibilityBody = (key, boundaryRef, claimRef, over = {}) => ({
  owner_ref: OWNER, idempotency_key: key, family: "acme.intake-corrections", effective_at: "2026-09-12T08:02:19Z", eligibility_profile: "general_learning", learning_use: "internal_evaluation",
  intended_use: "benchmark", learning_use_posture: "full_private_opt_in", contamination_posture: "clean", subject_refs: ["finding://acme/intake-correction/0431"],
  requester_ref: "foundry_job://acme-clinic/intake-adapter-build/07", allowed_improvement_target_refs: ["worker://acme-clinic/intake-assistant"], owner_and_tenant_scope_refs: [OWNER],
  local_policy_refs: ["policy://acme/learning/intake/v2"], consent_refs: ["grant://acme-clinic/intake-consent/v3"], authority_requirement_posture: "none", authority_requirement_kinds: [],
  provider_trust_posture: "no_provider_plaintext", retention_policy_ref: "policy://acme/retention/intake/v3", derivative_policy_ref: "policy://acme/derivative/v1",
  lineage_root: H("1"), receipt_root: H("2"), admitted_by_ref: "operation://acme-clinic/eligibility-admit/8821", boundary_profile_revision_ref: boundaryRef,
  learning_source_rights_claim_revision_refs: [claimRef], ...over,
});

// Families read before and after every campaign operation: the campaign owns no production
// mutation, so the direct path's own record families, sessions, routes and profiles must not move.
const OBSERVED = ["/v1/hypervisor/automation-affinities", "/v1/hypervisor/skill-entries", PROPOSALS, "/v1/hypervisor/sessions", "/v1/hypervisor/model-routes", "/v1/hypervisor/harness-profiles"];
const snapshot = async () => {
  const out = {};
  for (const route of OBSERVED) {
    const r = await jd(route);
    const body = r.body && typeof r.body === "object" ? { ...r.body } : r.body;
    if (body && typeof body === "object") delete body.at;
    out[route] = `${r.status}:${jcs(body ?? null)}`;
  }
  return out;
};
const drifted = (before, after) => OBSERVED.filter((route) => before[route] !== after[route]);
const stripIndex = (value) => JSON.stringify(value, (key, v) => (key === "index_state" || key === "at" ? undefined : v));

// ------------------------------------------------------------------------- canon and source
const CANON = path.join(ROOT, "docs/architecture/components/daemon-runtime/improvement-governance-gates.md");
const MODULE = path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/improvement_campaign_routes.rs");
const INTELLIGENCE = path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/ioi_intelligence_routes.rs");
/** The first token of every line of the fenced block that follows `marker`. */
function fencedCodes(text, marker) {
  const at = text.indexOf(marker);
  if (at < 0) return [];
  const open = text.indexOf("```text", at);
  const close = text.indexOf("```", open + 7);
  if (open < 0 || close < 0) return [];
  // A code sits at column 0; a wrapped description continues indented and is not a member.
  return text.slice(open + 7, close).split("\n").filter((line) => /^[a-z_]/u.test(line)).map((line) => line.split(/\s+/u)[0]).filter((token) => /^[a-z_]+$/u.test(token));
}
function readCanonFamily() {
  const text = fs.readFileSync(CANON, "utf8");
  return {
    family: fencedCodes(text, "The planned deterministic failure family includes:"),
    implemented: fencedCodes(text, "Implemented on this basis (M10.1"),
    target: fencedCodes(text, "Target contract on this basis, with the unit that owns each:"),
  };
}

// ------------------------------------------------------------------------------------ run
async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();

  // -- identity ----------------------------------------------------------------------------------
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "improvement-spine-bootstrap-v1", email: "improvement-spine@ioi.local" }) }, { authenticated: false });
    SESSION = boot.body?.session_token || boot.body?.session?.token || "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  ok("the session authenticates a principal with an owner tenant to admit under", !!OWNER, OWNER || "no owner tenant");

  // -- the direct path BEFORE any campaign object exists (ACC-12 clause 1) ---------------------------
  const affinity = (await post("/v1/hypervisor/automation-affinities", { title: "Intake triage affinity", goal_pattern: "triage intake queue", failure_policy: "stop" })).body?.record ?? {};
  const targetRef = String(affinity.affinity_ref || "");
  ok("a core-owned mutable target exists for the campaign to bind (an automation affinity, this daemon's own record family)", targetRef.startsWith("automation-affinity://"), targetRef);
  const direct1 = (await post(PROPOSALS, { proposal_kind: "automation_readiness", signal: "repeated_successful_goal_pattern", evidence_refs: ["ioi-agent-launch://spine-before"], suggested: { title: "Affinity before", goal_pattern: "zzz-before" } })).body?.proposal ?? {};
  await post(`${PROPOSALS}/${direct1.improvement_id}/approve`, {});
  const applied1 = (await post(`${PROPOSALS}/${direct1.improvement_id}/apply`, {})).body?.proposal ?? {};
  ok("DIRECT PATH, BEFORE: a campaign-less low-impact proposal creates, approves and applies with no campaign object in existence", applied1.state === "applied" && String(applied1.applied_ref || "").startsWith("automation-affinity://") && applied1.improvement_campaign_ref === null, `${applied1.state} ${applied1.applied_ref}`);
  const policy1 = (await post(PROPOSALS, { proposal_kind: "launch_policy_suggestion", signal: "repeated_harness_model_preference", evidence_refs: ["ioi-agent-launch://spine-before"], suggested: { display_name: "policy before" } })).body?.proposal ?? {};
  await post(`${PROPOSALS}/${policy1.improvement_id}/approve`, {});
  const gated1 = await post(`${PROPOSALS}/${policy1.improvement_id}/apply`, {});
  ok("DIRECT PATH, BEFORE: the unchanged gate still refuses an unsimulated launch-policy suggestion (simulation_required)", gated1.status === 409 && code(gated1.body) === "simulation_required", `${gated1.status} ${code(gated1.body)}`);
  const authored = await post(PROPOSALS, { proposal_kind: "automation_readiness", signal: "x", evidence_refs: ["ioi-agent-launch://x"], suggested: { title: "x" }, improvement_campaign_ref: "improvement-campaign://acme.fake" });
  ok("a caller-supplied campaign binding on the public create is refused by name — the daemon never synthesizes campaign truth from a caller-supplied claim", authored.status === 400 && code(authored.body) === "improvement_campaign_binding_not_caller_authored", `${authored.status} ${code(authored.body)}`);

  // -- the learning-boundary prerequisites, through M10.3's own routes -----------------------------
  const claim = (await post("/v1/hypervisor/learning-source-rights-claims", claimBody("spine-claim-1"))).body?.learning_source_rights_claim ?? {};
  const boundary = (await post("/v1/hypervisor/institutional-learning-boundary-profiles", boundaryBody("spine-boundary-1", claim.revision_ref))).body?.institutional_learning_boundary_profile ?? {};
  const boundaryRef = String(boundary.revision_ref || "");
  const eligibility = (await post("/v1/hypervisor/learning-evidence-eligibilities", eligibilityBody("spine-elig-1", boundaryRef, claim.revision_ref))).body?.learning_evidence_eligibility ?? {};
  ok("the learning-boundary plane admits the profile and an ELIGIBLE decision the cutoff will cite (M10.3's routes, not restated here)", boundaryRef.startsWith("learning-boundary://") && eligibility.status === "eligible", `${boundaryRef} · ${eligibility.status}`);
  const excluded = (await post("/v1/hypervisor/learning-evidence-eligibilities", eligibilityBody("spine-elig-excluded", boundaryRef, claim.revision_ref, { family: "acme.sealed-material", contamination_posture: "exposed", subject_refs: ["finding://acme/sealed-leak/0001"] }))).body?.learning_evidence_eligibility ?? {};
  ok("and an EXCLUDED decision over exposed material, so an ineligible finding is one a real decision excluded rather than one nobody decided", excluded.status === "excluded", String(excluded.status));

  // -- campaign admission with NO profile: a null profile disables admission ------------------------
  const noProfileCampaign = await post(CAMPAIGNS, campaignBody("spine-campaign-noprofile", "acme.noprofile", targetRef, "improvement-governance-profile://acme.improvement/revision/1", "improvement-agenda://acme.intake-2026q3/revision/1", boundaryRef));
  ok("a campaign contract is created as PROPOSED while its governance profile does not yet exist — creation records, admission resolves", noProfileCampaign.status === 201 && noProfileCampaign.body?.improvement_campaign?.lifecycle_status === "proposed", `${noProfileCampaign.status} ${code(noProfileCampaign.body)}`);
  const noProfileAdmit = await post(`${CAMPAIGNS}/acme.noprofile/admit`, { owner_ref: OWNER, idempotency_key: "spine-admit-noprofile", expected_head: noProfileCampaign.body?.expected_head_for_successor, campaign_admission_decision_ref: "decision://acme/improvement/admit/noprofile" });
  ok("admitting it is refused: no governance profile revision resolves under the owner (improvement_governance_profile_required)", noProfileAdmit.status === 422 && code(noProfileAdmit.body) === "improvement_governance_profile_required", `${noProfileAdmit.status} ${code(noProfileAdmit.body)}`);

  // -- the governance profile: immutable, owner-scoped, successor-lineaged ----------------------------
  const beforeProfile = await snapshot();
  const profile1 = await post(PROFILES, profileBody("spine-profile-1"));
  const p1 = profile1.body?.improvement_governance_profile ?? {};
  ok("a governance profile admits as a registered record whose identity is DERIVED from the stream (revision 1, no predecessor, active)", profile1.status === 201 && p1.revision_ref === "improvement-governance-profile://acme.improvement/revision/1" && p1.predecessor_revision_ref === null && p1.registry_status === "active", `${profile1.status} ${code(profile1.body)}`);
  ok("its content_hash RE-DERIVES here over the immutable body under canon's domain separator — the registry projections and the admission stamp are outside it", p1.content_hash === deriveProfileHash(p1), `${String(p1.content_hash).slice(0, 24)} vs ${deriveProfileHash(p1).slice(0, 24)}`);
  ok("admitting a profile leaves every other observable family byte-identical", drifted(beforeProfile, await snapshot()).length === 0);
  const authoredHash = await post(PROFILES, profileBody("spine-profile-authored", { content_hash: H("f") }));
  ok("a caller cannot AUTHOR a server-resolved member: content_hash is refused by name (assert it through expected_content_hash instead)", authoredHash.status === 422 && code(authoredHash.body) === "improvement_governance_profile_caller_authored_evidence_refused", `${authoredHash.status} ${code(authoredHash.body)}`);
  const unknownField = await post(PROFILES, profileBody("spine-profile-unknown", { fitness: 1 }));
  ok("a member the route does not read is refused rather than dropped", unknownField.status === 400 && code(unknownField.body) === "improvement_governance_profile_request_unknown_field", `${unknownField.status} ${code(unknownField.body)}`);
  const systemScoped = await post(PROFILES, profileBody("spine-profile-system", { family: "acme.system", system_id: "system://acme/primary" }));
  ok("a System-scoped profile is refused TYPED: the constitution's protected profile binding is not built and is not pretended", systemScoped.status === 422 && code(systemScoped.body) === "improvement_governance_profile_system_scope_not_admitted", `${systemScoped.status} ${code(systemScoped.body)}`);
  const noHead = await post(PROFILES, profileBody("spine-profile-2-nohead", { version: "1.1.0" }));
  ok("a successor that names no head is refused: the stream already has admissions and a successor names the exact current head", noHead.status === 409 && code(noHead.body) === "improvement_governance_profile_expected_head_conflict", `${noHead.status} ${code(noHead.body)}`);
  const profile2 = await post(PROFILES, profileBody("spine-profile-2", { version: "1.1.0", expected_head: profile1.body?.expected_head_for_successor, protected_target_refs: ["automation-affinity://aff_protected"], max_target_improvement_order: 1 }));
  const p2 = profile2.body?.improvement_governance_profile ?? {};
  ok("a successor revision names its predecessor and becomes the owner's CURRENT governance", profile2.status === 201 && p2.revision_ref.endsWith("/revision/2") && p2.predecessor_revision_ref === p1.revision_ref && p2.content_hash === deriveProfileHash(p2), `${profile2.status} ${code(profile2.body)}`);
  const profileRevisions = (await jd(`${PROFILES}?family=acme.improvement`)).body?.revisions ?? [];
  ok("the served registry status is DERIVED on read: revision 1 now reads superseded and revision 2 active, while revision 1's immutable content_hash is unchanged", profileRevisions.length === 2 && profileRevisions[0].registry_status === "superseded" && profileRevisions[1].registry_status === "active" && profileRevisions[0].content_hash === p1.content_hash, JSON.stringify(profileRevisions.map((r) => r.registry_status)));
  const rev1 = (await jd(`${PROFILES}/acme.improvement/revisions/1`)).body?.resolved ?? {};
  ok("one exact revision resolves by path", rev1.revision_ref === p1.revision_ref && rev1.registry_status === "superseded");
  const profileRef = p2.revision_ref;

  // -- the agenda: draft, released, superseded — and the release carries the identical hash -----------
  const agenda1 = await post(AGENDAS, agendaBody("spine-agenda-1", targetRef));
  const a1 = agenda1.body?.improvement_agenda ?? {};
  ok("an agenda admits as a DRAFT revision 1 whose content_hash re-derives here", agenda1.status === 201 && a1.registry_status === "draft" && a1.revision === 1 && a1.content_hash === deriveAgendaHash(a1), `${agenda1.status} ${code(agenda1.body)}`);
  const draftCampaign = await post(CAMPAIGNS, campaignBody("spine-campaign-draftagenda", "acme.draftagenda", targetRef, profileRef, a1.revision_ref, boundaryRef));
  const draftAdmit = await post(`${CAMPAIGNS}/acme.draftagenda/admit`, { owner_ref: OWNER, idempotency_key: "spine-admit-draftagenda", expected_head: draftCampaign.body?.expected_head_for_successor, campaign_admission_decision_ref: "decision://acme/improvement/admit/draftagenda" });
  ok("a campaign citing a DRAFT agenda revision is refused admission: only a released revision is campaign-admission eligible", draftAdmit.status === 409 && code(draftAdmit.body) === "improvement_agenda_revision_not_released", `${draftAdmit.status} ${code(draftAdmit.body)}`);
  const release1 = await post(`${AGENDAS}/acme.intake-2026q3/revisions/1/release`, { owner_ref: OWNER, idempotency_key: "spine-agenda-release-1", expected_head: agenda1.body?.expected_head_for_successor, release_decision_ref: "decision://acme/improvement/release-agenda/1" });
  const a1r = release1.body?.improvement_agenda ?? {};
  ok("a release is a SUCCESSOR admission of the same revision carrying the IDENTICAL content_hash — lifecycle is a projection outside the immutable body", release1.status === 201 && a1r.registry_status === "released" && a1r.revision === 1 && a1r.content_hash === a1.content_hash && a1r.release_decision_ref === "decision://acme/improvement/release-agenda/1", `${release1.status} ${code(release1.body)}`);
  const releaseAgain = await post(`${AGENDAS}/acme.intake-2026q3/revisions/1/release`, { owner_ref: OWNER, idempotency_key: "spine-agenda-release-1b", expected_head: release1.body?.expected_head_for_successor, release_decision_ref: "decision://acme/improvement/release-agenda/1b" });
  ok("a release is not repeated", releaseAgain.status === 409 && code(releaseAgain.body) === "improvement_agenda_already_released", `${releaseAgain.status} ${code(releaseAgain.body)}`);
  const agendaRef = a1.revision_ref;

  // -- the campaign contract: created, then admitted against RESOLVED governance -----------------------
  const unresolvable = await post(CAMPAIGNS, campaignBody("spine-campaign-unresolvable", "acme.unresolvable", "ioi-agent-policy://pol_auto_default", profileRef, agendaRef, boundaryRef));
  ok("a target this core plane cannot read through its owner is refused typed — a launch policy is the goal-orchestration application's and is deliberately NOT a campaign target (mutable_target_unresolvable)", unresolvable.status === 422 && code(unresolvable.body) === "mutable_target_unresolvable", `${unresolvable.status} ${code(unresolvable.body)}`);
  const halfPursuit = await post(CAMPAIGNS, campaignBody("spine-campaign-halfpursuit", "acme.halfpursuit", targetRef, profileRef, agendaRef, boundaryRef, { coordinating_pursuit: { goal_run_profile_revision_ref: "goal-run-profile://acme/x/revision/1", goal_run_profile_resolution_receipt_ref: null } }));
  ok("a coordinating pursuit is the application's declaration — profile revision AND resolution receipt together or not at all; core records the pair and resolves neither (improvement_campaign_pursuit_binding_incomplete)", halfPursuit.status === 422 && code(halfPursuit.body) === "improvement_campaign_pursuit_binding_incomplete", `${halfPursuit.status} ${code(halfPursuit.body)}`);
  const bundle = await post(CAMPAIGNS, campaignBody("spine-campaign-bundle", "acme.bundle", targetRef, profileRef, agendaRef, boundaryRef, { atomic_target_bundle_ref: "artifact://acme/bundle/1" }));
  ok("an atomic target bundle is refused typed rather than pretended", bundle.status === 422 && code(bundle.body) === "improvement_campaign_atomic_bundle_not_admitted", `${bundle.status} ${code(bundle.body)}`);
  const beforeCampaign = await snapshot();
  const campaign1 = await post(CAMPAIGNS, campaignBody("spine-campaign-1", "acme.intake-affinity", targetRef, profileRef, agendaRef, boundaryRef));
  const c1 = campaign1.body?.improvement_campaign ?? {};
  ok("a campaign contract admits as PROPOSED with its identity derived (revision 1, no predecessor) and the four resolved members filled: the target root, the incumbent root, the pursuit-method order and the learning-boundary policy hash", campaign1.status === 201 && c1.lifecycle_status === "proposed" && c1.campaign_contract_revision === 1 && c1.pursuit_method_order === 1 && c1.effective_learning_policy_hash === boundary.compiled_policy_hash && /^sha256:/u.test(c1.target_base_root) && c1.deployment_incumbent_root === c1.target_base_root, `${campaign1.status} ${code(campaign1.body)}`);
  const affinityNow = ((await jd("/v1/hypervisor/automation-affinities")).body?.affinities ?? []).find((r) => r.affinity_ref === targetRef);
  ok("the frozen target_base_root RE-DERIVES here from the target's own served record — the daemon read the target through its owner rather than copying a caller's claim", !!affinityNow && c1.target_base_root === deriveTargetRoot(targetRef, affinityNow), `${String(c1.target_base_root).slice(0, 24)} vs ${affinityNow ? deriveTargetRoot(targetRef, affinityNow).slice(0, 24) : "no record"}`);
  ok("campaign_contract_root RE-DERIVES here over the contract subset, content_hash over the whole entry, and operation_head_root chains from a null genesis", c1.campaign_contract_root === deriveContractRoot(c1) && c1.content_hash === deriveCampaignHash(c1) && c1.operation_head_root === deriveHeadRoot(null, c1.content_hash));
  ok("creating a campaign leaves every other observable family byte-identical", drifted(beforeCampaign, await snapshot()).length === 0);
  const startEarly = await post(`${CAMPAIGNS}/acme.intake-affinity/start`, { owner_ref: OWNER, idempotency_key: "spine-start-early", expected_head: campaign1.body?.expected_head_for_successor });
  ok("a proposed campaign cannot start: only admission makes it runnable", startEarly.status === 409 && code(startEarly.body) === "improvement_campaign_lifecycle_invalid", `${startEarly.status} ${code(startEarly.body)}`);
  const epochEarly = await post(`${CAMPAIGNS}/acme.intake-affinity/evaluation-epochs`, epochBody("spine-epoch-early", "acme.intake-affinity.epoch-early"));
  ok("an epoch is created only under an ACTIVE campaign", epochEarly.status === 409 && code(epochEarly.body) === "improvement_campaign_not_active", `${epochEarly.status} ${code(epochEarly.body)}`);

  // admission refusals, each on its own campaign contract
  const staleProfile = await post(CAMPAIGNS, campaignBody("spine-campaign-staleprofile", "acme.staleprofile", targetRef, p1.revision_ref, agendaRef, boundaryRef));
  const staleProfileAdmit = await post(`${CAMPAIGNS}/acme.staleprofile/admit`, { owner_ref: OWNER, idempotency_key: "spine-admit-staleprofile", expected_head: staleProfile.body?.expected_head_for_successor, campaign_admission_decision_ref: "decision://acme/improvement/admit/staleprofile" });
  ok("a campaign citing a SUPERSEDED profile revision is refused: admission binds the owner's CURRENT governance (campaign_binding_mismatch)", staleProfileAdmit.status === 409 && code(staleProfileAdmit.body) === "campaign_binding_mismatch", `${staleProfileAdmit.status} ${code(staleProfileAdmit.body)}`);
  const protectedAff = (await post("/v1/hypervisor/automation-affinities", { title: "Protected affinity", goal_pattern: "protected pattern", failure_policy: "stop" })).body?.record ?? {};
  const protectedProfile = await post(PROFILES, profileBody("spine-profile-3", { version: "1.2.0", expected_head: profile2.body?.expected_head_for_successor, protected_target_refs: [protectedAff.affinity_ref], max_target_improvement_order: 1 }));
  const profileRef3 = protectedProfile.body?.improvement_governance_profile?.revision_ref;
  const protectedCampaign = await post(CAMPAIGNS, campaignBody("spine-campaign-protected", "acme.protectedtarget", protectedAff.affinity_ref, profileRef3, agendaRef, boundaryRef));
  const protectedAdmit = await post(`${CAMPAIGNS}/acme.protectedtarget/admit`, { owner_ref: OWNER, idempotency_key: "spine-admit-protected", expected_head: protectedCampaign.body?.expected_head_for_successor, campaign_admission_decision_ref: "decision://acme/improvement/admit/protected" });
  ok("a target the profile PROTECTS is refused admission", protectedAdmit.status === 409 && code(protectedAdmit.body) === "improvement_campaign_target_protected", `${protectedAdmit.status} ${code(protectedAdmit.body)}`);
  const highOrder = await post(CAMPAIGNS, campaignBody("spine-campaign-highorder", "acme.highorder", targetRef, profileRef3, agendaRef, boundaryRef, { target_improvement_order: 3 }));
  const highOrderAdmit = await post(`${CAMPAIGNS}/acme.highorder/admit`, { owner_ref: OWNER, idempotency_key: "spine-admit-highorder", expected_head: highOrder.body?.expected_head_for_successor, campaign_admission_decision_ref: "decision://acme/improvement/admit/highorder" });
  ok("a target order above the profile's ceiling is refused admission", highOrderAdmit.status === 409 && code(highOrderAdmit.body) === "improvement_campaign_order_ceiling_exceeded", `${highOrderAdmit.status} ${code(highOrderAdmit.body)}`);
  const noRecovery = await post(CAMPAIGNS, campaignBody("spine-campaign-norecovery", "acme.norecovery", targetRef, profileRef3, agendaRef, boundaryRef, { rollback_recall_containment_compensation_and_reconciliation_policy_refs: [] }));
  const noRecoveryAdmit = await post(`${CAMPAIGNS}/acme.norecovery/admit`, { owner_ref: OWNER, idempotency_key: "spine-admit-norecovery", expected_head: noRecovery.body?.expected_head_for_successor, campaign_admission_decision_ref: "decision://acme/improvement/admit/norecovery" });
  ok("a campaign with no recovery posture bound is refused admission (effect_recovery_posture_missing)", noRecoveryAdmit.status === 409 && code(noRecoveryAdmit.body) === "effect_recovery_posture_missing", `${noRecoveryAdmit.status} ${code(noRecoveryAdmit.body)}`);
  const movingAff = (await post("/v1/hypervisor/automation-affinities", { title: "Moving affinity", goal_pattern: "moving pattern", failure_policy: "stop" })).body?.record ?? {};
  const movingCampaign = await post(CAMPAIGNS, campaignBody("spine-campaign-moving", "acme.movingtarget", movingAff.affinity_ref, profileRef3, agendaRef, boundaryRef));
  await jd(`/v1/hypervisor/automation-affinities/${movingAff.affinity_id}`, { method: "PATCH", body: JSON.stringify({ goal_pattern: "moved pattern" }) });
  const movingAdmit = await post(`${CAMPAIGNS}/acme.movingtarget/admit`, { owner_ref: OWNER, idempotency_key: "spine-admit-moving", expected_head: movingCampaign.body?.expected_head_for_successor, campaign_admission_decision_ref: "decision://acme/improvement/admit/moving" });
  ok("a target that MOVED between creation and admission is refused (target_base_stale): the root is re-resolved through the owner, never trusted from the contract", movingAdmit.status === 409 && code(movingAdmit.body) === "target_base_stale", `${movingAdmit.status} ${code(movingAdmit.body)}`);

  // the real admission and lifecycle
  const campaign1b = await post(CAMPAIGNS, campaignBody("spine-campaign-1b", "acme.intake-affinity-live", targetRef, profileRef3, agendaRef, boundaryRef));
  const c1b = campaign1b.body?.improvement_campaign ?? {};
  let head = campaign1b.body?.expected_head_for_successor;
  const admit = await post(`${CAMPAIGNS}/acme.intake-affinity-live/admit`, { owner_ref: OWNER, idempotency_key: "spine-admit-1b", expected_head: head, campaign_admission_decision_ref: "decision://acme/improvement/admit/live" });
  const admitted = admit.body?.improvement_campaign ?? {};
  head = admit.body?.expected_head_for_successor;
  ok("ADMISSION resolves and freezes the admission facts: the decision, a derived admission receipt, the profile/agenda/boundary snapshot refs, the profile's ceilings — and the contract root is UNMOVED", admit.status === 201 && admitted.lifecycle_status === "admitted" && admitted.campaign_contract_root === c1b.campaign_contract_root && admitted.effective_target_order_ceiling === 1 && admitted.campaign_admission_decision_ref === "decision://acme/improvement/admit/live" && String(admitted.campaign_admission_receipt_ref).startsWith("receipt://improvement-campaign/acme.intake-affinity-live/admission/") && (admitted.admission_authority_and_constitution_snapshot_refs || []).length === 3, `${admit.status} ${code(admit.body)}`);
  ok("the admission entry re-hashes here: contract root over the contract subset, content_hash over the entry, and the operation head chained from the genesis head", admitted.campaign_contract_root === deriveContractRoot(admitted) && admitted.content_hash === deriveCampaignHash(admitted) && admitted.operation_head_root === deriveHeadRoot(c1b.operation_head_root, admitted.content_hash) && admitted.operation_head_sequence === 2);
  const start = await post(`${CAMPAIGNS}/acme.intake-affinity-live/start`, { owner_ref: OWNER, idempotency_key: "spine-start-1b", expected_head: head });
  head = start.body?.expected_head_for_successor;
  ok("start makes an admitted campaign active", start.status === 201 && start.body?.improvement_campaign?.lifecycle_status === "active", `${start.status} ${code(start.body)}`);
  const pause = await post(`${CAMPAIGNS}/acme.intake-affinity-live/pause`, { owner_ref: OWNER, idempotency_key: "spine-pause-1b", expected_head: head });
  head = pause.body?.expected_head_for_successor;
  const resume = await post(`${CAMPAIGNS}/acme.intake-affinity-live/start`, { owner_ref: OWNER, idempotency_key: "spine-resume-1b", expected_head: head });
  head = resume.body?.expected_head_for_successor;
  ok("pause and resume are successors on the campaign's own stream; the contract root holds across every one", pause.body?.improvement_campaign?.lifecycle_status === "paused" && resume.body?.improvement_campaign?.lifecycle_status === "active" && resume.body?.improvement_campaign?.campaign_contract_root === c1b.campaign_contract_root, `${pause.status}/${resume.status}`);
  const staleHead = await post(`${CAMPAIGNS}/acme.intake-affinity-live/pause`, { owner_ref: OWNER, idempotency_key: "spine-pause-stale", expected_head: campaign1b.body?.expected_head_for_successor });
  ok("a successor naming a STALE head is refused — the compare-and-swap is the chain's, not this module's", staleHead.status === 409 && code(staleHead.body) === "improvement_campaign_expected_head_conflict", `${staleHead.status} ${code(staleHead.body)}`);
  const CAMPAIGN_LIVE = "acme.intake-affinity-live";

  // -- the epoch: draft → frozen (ledger genesis) → active; frozen root binding ----------------------------
  const beforeEpoch = await snapshot();
  const epoch1 = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/evaluation-epochs`, epochBody("spine-epoch-1", "acme.intake-affinity-live.epoch-1"));
  const e1 = epoch1.body?.evaluation_epoch ?? {};
  let epochHead = epoch1.body?.expected_head_for_successor;
  ok("an epoch is created DRAFT under the active campaign, copying its coordinates from the campaign contract (root, orders, incumbent) rather than accepting them", epoch1.status === 201 && e1.lifecycle_status === "draft" && e1.campaign_contract_root === c1b.campaign_contract_root && e1.pursuit_method_order === 1 && e1.deployment_incumbent_root === c1b.deployment_incumbent_root && e1.predecessor_epoch_ref === null, `${epoch1.status} ${code(epoch1.body)}`);
  ok("frozen_root and content_hash RE-DERIVE here", e1.frozen_root === deriveFrozenRoot(e1) && e1.content_hash === deriveEpochHash(e1));
  ok("creating an epoch leaves every other observable family byte-identical", drifted(beforeEpoch, await snapshot()).length === 0);
  const E1 = "acme.intake-affinity-live.epoch-1";
  const reserveDraft = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("spine-reserve-draft", null, 1));
  ok("exposure against a DRAFT epoch is refused: freeze commits the evaluator contract before any confirmatory access (evaluation_epoch_not_frozen)", reserveDraft.status === 409 && code(reserveDraft.body) === "evaluation_epoch_not_frozen", `${reserveDraft.status} ${code(reserveDraft.body)}`);
  const activateDraft = await post(`${EPOCHS}/${E1}/activate`, { owner_ref: OWNER, idempotency_key: "spine-activate-draft", expected_head: epochHead });
  ok("a draft epoch cannot activate (evaluation_epoch_not_frozen)", activateDraft.status === 409 && code(activateDraft.body) === "evaluation_epoch_not_frozen", `${activateDraft.status} ${code(activateDraft.body)}`);
  const freeze = await post(`${EPOCHS}/${E1}/freeze`, { owner_ref: OWNER, idempotency_key: "spine-freeze-1", expected_head: epochHead });
  epochHead = freeze.body?.expected_head_for_successor;
  const frozen = freeze.body?.evaluation_epoch ?? {};
  ok("freeze is a successor whose frozen_root is IDENTICAL to the draft's — the judgment contract did not move, only the projection", freeze.status === 201 && frozen.lifecycle_status === "frozen" && frozen.frozen_root === e1.frozen_root && frozen.content_hash !== e1.content_hash, `${freeze.status} ${code(freeze.body)}`);
  const ledgerGenesis = (await jd(`${EPOCHS}/${E1}/exposure`)).body?.evaluation_exposure_ledger ?? {};
  ok("freeze CREATED the epoch's exposure ledger with the frozen budget, zero counters, and a genesis head root that re-derives here", ledgerGenesis.exposure_budget_units === 5 && ledgerGenesis.remaining_units === 5 && ledgerGenesis.ledger_head_sequence === 0 && ledgerGenesis.ledger_head_root === deriveGenesisLedgerRoot(ledgerGenesis.evaluation_exposure_ledger_id) && ledgerGenesis.content_hash === deriveLedgerHash(ledgerGenesis), JSON.stringify({ budget: ledgerGenesis.exposure_budget_units, seq: ledgerGenesis.ledger_head_sequence }));
  const freezeAgain = await post(`${EPOCHS}/${E1}/freeze`, { owner_ref: OWNER, idempotency_key: "spine-freeze-1b", expected_head: epochHead });
  ok("a frozen epoch does not freeze again", freezeAgain.status === 409 && code(freezeAgain.body) === "evaluation_epoch_lifecycle_invalid", `${freezeAgain.status} ${code(freezeAgain.body)}`);
  const activate = await post(`${EPOCHS}/${E1}/activate`, { owner_ref: OWNER, idempotency_key: "spine-activate-1", expected_head: epochHead });
  epochHead = activate.body?.expected_head_for_successor;
  ok("activate makes the frozen epoch the campaign's active epoch", activate.status === 201 && activate.body?.evaluation_epoch?.lifecycle_status === "active", `${activate.status} ${code(activate.body)}`);
  const derivedC = (await jd(`${CAMPAIGNS}/${CAMPAIGN_LIVE}`)).body?.derived_state ?? {};
  ok("the campaign's active epoch is a DERIVED projection rebuilt from the epoch streams, not a second pointer written beside them", derivedC.active_evaluation_epoch_ref === e1.evaluation_epoch_id && (derivedC.epochs || []).length === 1, JSON.stringify(derivedC));
  const epoch2 = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/evaluation-epochs`, epochBody("spine-epoch-2", "acme.intake-affinity-live.epoch-2"));
  const E2 = "acme.intake-affinity-live.epoch-2";
  let epoch2Head = epoch2.body?.expected_head_for_successor;
  const freeze2 = await post(`${EPOCHS}/${E2}/freeze`, { owner_ref: OWNER, idempotency_key: "spine-freeze-2", expected_head: epoch2Head });
  epoch2Head = freeze2.body?.expected_head_for_successor;
  const activate2 = await post(`${EPOCHS}/${E2}/activate`, { owner_ref: OWNER, idempotency_key: "spine-activate-2", expected_head: epoch2Head });
  ok("a second epoch names its predecessor and cannot activate while one is active: a campaign references exactly one active frozen epoch", epoch2.body?.evaluation_epoch?.predecessor_epoch_ref === e1.evaluation_epoch_id && activate2.status === 409 && code(activate2.body) === "evaluation_epoch_already_active", `${activate2.status} ${code(activate2.body)}`);

  // -- exposure: a subtraction against the frozen budget, chained entries ------------------------------
  let ledgerHead = (await jd(`${EPOCHS}/${E1}/exposure`)).body?.head;
  const r1 = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("spine-reserve-1", ledgerHead, 3));
  ledgerHead = r1.body?.expected_head_for_successor;
  const l1 = r1.body?.evaluation_exposure_ledger ?? {};
  ok("a reservation appends an entry: reserved 3, remaining 2, head sequence 1, the entry root chained from a null predecessor and re-derived here", r1.status === 201 && l1.reserved_units === 3 && l1.remaining_units === 2 && l1.ledger_head_sequence === 1 && l1.entries?.[0]?.previous_entry_root === null && l1.entries?.[0]?.entry_root === deriveEntryRoot(l1.entries[0]) && l1.ledger_head_root === l1.entries[0].entry_root && l1.content_hash === deriveLedgerHash(l1), `${r1.status} ${code(r1.body)}`);
  const over = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("spine-reserve-over", ledgerHead, 3));
  ok("a reservation beyond the frozen budget is refused (evaluation_exposure_exhausted): changing nothing about the candidate restores no exposure", over.status === 409 && code(over.body) === "evaluation_exposure_exhausted", `${over.status} ${code(over.body)}`);
  const s1 = await post(`${EPOCHS}/${E1}/exposure/spend`, exposureBody("spine-spend-1", ledgerHead, 2, { selected_case_commitment: H("7"), information_return_class: "per_case" }));
  ledgerHead = s1.body?.expected_head_for_successor;
  const l2 = s1.body?.evaluation_exposure_ledger ?? {};
  ok("a spend draws from the outstanding reservation and chains its entry root from the previous entry", s1.status === 201 && l2.spent_units === 2 && l2.remaining_units === 2 && l2.entries?.[1]?.previous_entry_root === l1.entries[0].entry_root && l2.entries?.[1]?.entry_root === deriveEntryRoot(l2.entries[1]) && l2.ledger_head_root === l2.entries[1].entry_root, `${s1.status} ${code(s1.body)}`);
  const overReturn = await post(`${EPOCHS}/${E1}/exposure/release`, exposureBody("spine-return-over", ledgerHead, 2));
  ok("returning more than the outstanding reservation is refused the same way", overReturn.status === 409 && code(overReturn.body) === "evaluation_exposure_exhausted", `${overReturn.status} ${code(overReturn.body)}`);
  const ret = await post(`${EPOCHS}/${E1}/exposure/release`, exposureBody("spine-return-1", ledgerHead, 1));
  ledgerHead = ret.body?.expected_head_for_successor;
  const l3 = ret.body?.evaluation_exposure_ledger ?? {};
  ok("a return gives exposure back: remaining = budget − (reserved − returned) = 5 − (3 − 1) = 3", ret.status === 201 && l3.returned_units === 1 && l3.remaining_units === 3, JSON.stringify({ reserved: l3.reserved_units, spent: l3.spent_units, returned: l3.returned_units, remaining: l3.remaining_units }));
  const zero = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("spine-reserve-zero", ledgerHead, 0));
  ok("a zero-unit reservation is refused: units are bounded integers with a stated domain", zero.status === 422 && code(zero.body) === "evaluation_exposure_ledger_units_invalid", `${zero.status} ${code(zero.body)}`);
  const rot = await post(`${EPOCHS}/${E1}/rotate`, exposureBody("spine-rotate-1", ledgerHead, 0, { contamination_flag: true }));
  ledgerHead = rot.body?.expected_head_for_successor;
  const l4 = rot.body?.evaluation_exposure_ledger ?? {};
  ok("a rotation carries zero units, and a contamination flag marks the ledger contaminated for the rest of its life", rot.status === 201 && l4.ledger_head_sequence === 4 && l4.contaminated === true && l4.entries?.[3]?.entry_kind === "rotation", `${rot.status} ${code(rot.body)}`);
  const chainIntact = (l4.entries || []).every((entry, index) => entry.entry_root === deriveEntryRoot(entry) && entry.previous_entry_root === (index === 0 ? null : l4.entries[index - 1].entry_root));
  ok("every ledger entry root re-derives here and chains to its predecessor, so an edited counter or a dropped entry fails offline", chainIntact && (l4.entries || []).length === 4 && l4.ledger_head_root === l4.entries?.[3]?.entry_root);

  // -- the handoff: the campaign's ONLY exit is an ordinary pending proposal (ACC-12 clause 5) --------------
  const beforeHandoff = await snapshot();
  const nominate = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/upgrade-proposals`, { owner_ref: OWNER, candidate_ref: "artifact://acme/candidates/affinity/gen-3", suggested: { goal_pattern: "triage intake queue faster" }, evidence_refs: ["attempt://acme/campaign/attempt-12"], reason: "candidate gen-3 beat the incumbent under the frozen epoch" });
  const nominated = nominate.body?.proposal ?? {};
  const afterHandoff = await snapshot();
  ok("NOMINATION writes an ordinary PENDING improvement proposal bound to the campaign, its active frozen epoch and the frozen contract root — through the direct path's own creator", nominate.status === 201 && nominated.state === "pending" && nominated.improvement_campaign_ref === `improvement-campaign://${CAMPAIGN_LIVE}` && nominated.evaluation_epoch_ref === e1.evaluation_epoch_id && nominated.campaign_contract_root === c1b.campaign_contract_root && nominated.proposal_kind === "automation_readiness" && nominated.target_ref === targetRef, `${nominate.status} ${code(nominate.body)}`);
  const handoffDrift = drifted(beforeHandoff, afterHandoff);
  const proposalsBefore = JSON.parse(beforeHandoff[PROPOSALS].slice(4)).proposals?.length ?? -1;
  const proposalsAfter = JSON.parse(afterHandoff[PROPOSALS].slice(4)).proposals?.length ?? -2;
  ok("the handoff's ONLY effect outside the six families is exactly one pending proposal: no target, session, route or profile moved", handoffDrift.length === 1 && handoffDrift[0] === PROPOSALS && proposalsAfter === proposalsBefore + 1, `${handoffDrift.join(",")} · ${proposalsBefore} → ${proposalsAfter}`);
  const nominateAgain = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/upgrade-proposals`, { owner_ref: OWNER, candidate_ref: "artifact://acme/candidates/affinity/gen-4", suggested: { goal_pattern: "triage intake queue gently" }, evidence_refs: [] });
  const nominated2 = nominateAgain.body?.proposal ?? {};
  const applyPending = await post(`${PROPOSALS}/${nominated.improvement_id}/apply`, {});
  ok("a nominated proposal is NOT applied by the campaign: apply requires the target owner's ordinary review first (improvement_not_approved)", applyPending.status === 409 && code(applyPending.body) === "improvement_not_approved", `${applyPending.status} ${code(applyPending.body)}`);
  const affinityBeforeApply = ((await jd("/v1/hypervisor/automation-affinities")).body?.affinities ?? []).find((r) => r.affinity_ref === targetRef);
  await post(`${PROPOSALS}/${nominated.improvement_id}/approve`, {});
  const applied = (await post(`${PROPOSALS}/${nominated.improvement_id}/apply`, {})).body?.proposal ?? {};
  const affinityAfterApply = ((await jd("/v1/hypervisor/automation-affinities")).body?.affinities ?? []).find((r) => r.affinity_ref === targetRef);
  ok("once the TARGET OWNER's ordinary path approves and applies it, the target moves — and it is that path, never the campaign, that moved it", applied.state === "applied" && affinityAfterApply?.goal_pattern === "triage intake queue faster" && affinityBeforeApply?.goal_pattern !== affinityAfterApply?.goal_pattern, `${applied.state} · ${affinityAfterApply?.goal_pattern}`);
  await post(`${PROPOSALS}/${nominated2.improvement_id}/approve`, {});
  const staleApply = await post(`${PROPOSALS}/${nominated2.improvement_id}/apply`, {});
  ok("APPLY-TIME BINDING: a second campaign-bound proposal now finds the target moved since the contract froze its root and is refused (target_base_stale), beside the unchanged direct gate", staleApply.status === 409 && code(staleApply.body) === "target_base_stale", `${staleApply.status} ${code(staleApply.body)}`);
  const staleNominate = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/upgrade-proposals`, { owner_ref: OWNER, candidate_ref: "artifact://acme/candidates/affinity/gen-5", suggested: {}, evidence_refs: [] });
  ok("and a NEW nomination against the moved target is refused at the handoff (target_base_stale)", staleNominate.status === 409 && code(staleNominate.body) === "target_base_stale", `${staleNominate.status} ${code(staleNominate.body)}`);

  // -- a second campaign on a skill entry: epoch invalidity and campaign stop at apply time ------------------
  const skill = (await post("/v1/hypervisor/skill-entries", { title: "Intake triage skill", description: "how to triage", body: "step one" })).body?.record ?? {};
  const skillRef = String(skill.skill_ref || "");
  const campaignS = await post(CAMPAIGNS, campaignBody("spine-campaign-skill", "acme.intake-skill", skillRef, profileRef3, agendaRef, boundaryRef, { target_class: "skill" }));
  let headS = campaignS.body?.expected_head_for_successor;
  const admitS = await post(`${CAMPAIGNS}/acme.intake-skill/admit`, { owner_ref: OWNER, idempotency_key: "spine-admit-skill", expected_head: headS, campaign_admission_decision_ref: "decision://acme/improvement/admit/skill" });
  headS = admitS.body?.expected_head_for_successor;
  const startS = await post(`${CAMPAIGNS}/acme.intake-skill/start`, { owner_ref: OWNER, idempotency_key: "spine-start-skill", expected_head: headS });
  headS = startS.body?.expected_head_for_successor;
  const epochS = await post(`${CAMPAIGNS}/acme.intake-skill/evaluation-epochs`, epochBody("spine-epoch-skill", "acme.intake-skill.epoch-1"));
  const ES = "acme.intake-skill.epoch-1";
  let headES = epochS.body?.expected_head_for_successor;
  const freezeS = await post(`${EPOCHS}/${ES}/freeze`, { owner_ref: OWNER, idempotency_key: "spine-freeze-skill", expected_head: headES });
  headES = freezeS.body?.expected_head_for_successor;
  const activateS = await post(`${EPOCHS}/${ES}/activate`, { owner_ref: OWNER, idempotency_key: "spine-activate-skill", expected_head: headES });
  headES = activateS.body?.expected_head_for_successor;
  ok("a second campaign on a SKILL ENTRY target admits, starts and activates its epoch (the second core-owned target family)", skillRef.startsWith("skill-entry://") && startS.body?.improvement_campaign?.lifecycle_status === "active" && activateS.body?.evaluation_epoch?.lifecycle_status === "active", `${admitS.status}/${startS.status}/${activateS.status} ${code(admitS.body)}${code(startS.body)}${code(activateS.body)}`);
  const nomS1 = (await post(`${CAMPAIGNS}/acme.intake-skill/upgrade-proposals`, { owner_ref: OWNER, candidate_ref: "artifact://acme/candidates/skill/gen-1", suggested: { title: "Intake triage skill", description: "how to triage, better", body: "step one; step two" }, evidence_refs: [] })).body?.proposal ?? {};
  const nomS2 = (await post(`${CAMPAIGNS}/acme.intake-skill/upgrade-proposals`, { owner_ref: OWNER, candidate_ref: "artifact://acme/candidates/skill/gen-2", suggested: { title: "Intake triage skill", description: "how to triage, again", body: "step one; step three" }, evidence_refs: [] })).body?.proposal ?? {};
  ok("two nominations are pending under the skill campaign's active epoch", nomS1.state === "pending" && nomS2.state === "pending" && nomS1.proposal_kind === "skill_improvement");
  const challengeS = await post(`${EPOCHS}/${ES}/challenge`, { owner_ref: OWNER, idempotency_key: "spine-challenge-skill", expected_head: headES, challenge_evidence_refs: ["finding://acme/evaluator-leak/0912"] });
  headES = challengeS.body?.expected_head_for_successor;
  ok("a challenge appends linked evidence and makes the epoch challenged", challengeS.status === 201 && challengeS.body?.evaluation_epoch?.lifecycle_status === "challenged" && (challengeS.body?.evaluation_epoch?.challenge_evidence_refs || []).length === 1, `${challengeS.status} ${code(challengeS.body)}`);
  const noEvidence = await post(`${EPOCHS}/${E2}/challenge`, { owner_ref: OWNER, idempotency_key: "spine-challenge-noevidence", expected_head: epoch2Head, challenge_evidence_refs: [] });
  ok("a challenge without evidence is refused (a frozen-but-inactive epoch also cannot be challenged, and the evidence fence answers first)", noEvidence.status === 422 || noEvidence.status === 409, `${noEvidence.status} ${code(noEvidence.body)}`);
  const reserveChallenged = await post(`${EPOCHS}/${ES}/exposure/reserve`, exposureBody("spine-reserve-challenged", (await jd(`${EPOCHS}/${ES}/exposure`)).body?.head, 1));
  ok("exposure against a CHALLENGED epoch is refused (evaluation_epoch_invalid): adjudication is not built, so a challenged epoch stays invalid until closed or invalidated", reserveChallenged.status === 409 && code(reserveChallenged.body) === "evaluation_epoch_invalid", `${reserveChallenged.status} ${code(reserveChallenged.body)}`);
  await post(`${PROPOSALS}/${nomS1.improvement_id}/approve`, {});
  const applyChallenged = await post(`${PROPOSALS}/${nomS1.improvement_id}/apply`, {});
  ok("APPLY-TIME BINDING: an approved campaign-bound proposal whose epoch became challenged is refused (evaluation_epoch_invalid) even though the direct gate would pass it", applyChallenged.status === 409 && code(applyChallenged.body) === "evaluation_epoch_invalid", `${applyChallenged.status} ${code(applyChallenged.body)}`);
  const stopS = await post(`${CAMPAIGNS}/acme.intake-skill/stop`, { owner_ref: OWNER, idempotency_key: "spine-stop-skill", expected_head: headS });
  await post(`${PROPOSALS}/${nomS2.improvement_id}/approve`, {});
  const applyStopped = await post(`${PROPOSALS}/${nomS2.improvement_id}/apply`, {});
  ok("APPLY-TIME BINDING: once the campaign is STOPPED, its bound proposal is refused (campaign_binding_mismatch) — a stopped campaign revokes future promotion, never past evidence", stopS.body?.improvement_campaign?.lifecycle_status === "stopped" && applyStopped.status === 409 && code(applyStopped.body) === "campaign_binding_mismatch", `${stopS.status} · ${applyStopped.status} ${code(applyStopped.body)}`);
  const skillAfter = ((await jd("/v1/hypervisor/skill-entries")).body?.skills ?? []).find((r) => r.skill_ref === skillRef);
  ok("and the skill entry is untouched: two nominations, two approvals, zero mutation — the campaign owns no production mutation", skillAfter?.description === "how to triage" && skillAfter?.body === "step one", JSON.stringify({ description: skillAfter?.description }));
  const nominateStopped = await post(`${CAMPAIGNS}/acme.intake-skill/upgrade-proposals`, { owner_ref: OWNER, candidate_ref: "artifact://acme/candidates/skill/gen-3", suggested: {}, evidence_refs: [] });
  ok("a stopped campaign nominates nothing", nominateStopped.status === 409 && code(nominateStopped.body) === "improvement_campaign_not_active", `${nominateStopped.status} ${code(nominateStopped.body)}`);

  // -- the cutoff: at epoch close, one adjacent edge, resolved eligibility ------------------------------------
  const cutoffEarly = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, { owner_ref: OWNER, idempotency_key: "spine-cutoff-early", source_evaluation_epoch_ref: e1.evaluation_epoch_id, synchronization_wave_ref: "artifact://acme/sync-wave/1", source_target_generation_cutoff: 1, intended_destination_target_order: 1, per_order_source_version_and_cutoff_vector_ref: "artifact://acme/cutoff-vector/1", destination_base_root: H("9"), agenda_revision_ref: agendaRef, boundary_crossing: "same_boundary", eligible_finding_and_outcome_refs: ["finding://acme/intake-correction/0431"], learning_evidence_eligibility_refs: [eligibility.revision_ref], dependency_and_statistical_assumption_delta_ref: "artifact://acme/assumption-delta/1" });
  ok("a cutoff against an ACTIVE epoch is refused: a cutoff happens at epoch close (improvement_order_cutoff_invalid)", cutoffEarly.status === 409 && code(cutoffEarly.body) === "improvement_order_cutoff_invalid", `${cutoffEarly.status} ${code(cutoffEarly.body)}`);
  const close1 = await post(`${EPOCHS}/${E1}/close`, { owner_ref: OWNER, idempotency_key: "spine-close-1", expected_head: epochHead });
  epochHead = close1.body?.expected_head_for_successor;
  ok("close ends the active epoch", close1.status === 201 && close1.body?.evaluation_epoch?.lifecycle_status === "closed", `${close1.status} ${code(close1.body)}`);
  const cutoffBase = (key, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, source_evaluation_epoch_ref: e1.evaluation_epoch_id, synchronization_wave_ref: "artifact://acme/sync-wave/1", source_target_generation_cutoff: 1, intended_destination_target_order: 1, per_order_source_version_and_cutoff_vector_ref: "artifact://acme/cutoff-vector/1", destination_base_root: H("9"), agenda_revision_ref: agendaRef, boundary_crossing: "same_boundary", eligible_finding_and_outcome_refs: ["finding://acme/intake-correction/0431"], learning_evidence_eligibility_refs: [eligibility.revision_ref], dependency_and_statistical_assumption_delta_ref: "artifact://acme/assumption-delta/1", ...over });
  const skipEdge = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, cutoffBase("spine-cutoff-skip", { intended_destination_target_order: 2 }));
  ok("a destination two orders up is refused: evidence moves one adjacent edge per cutoff", skipEdge.status === 409 && code(skipEdge.body) === "improvement_order_cutoff_invalid", `${skipEdge.status} ${code(skipEdge.body)}`);
  const agenda2 = await post(AGENDAS, agendaBody("spine-agenda-2", targetRef, { expected_head: release1.body?.expected_head_for_successor }));
  const a2 = agenda2.body?.improvement_agenda ?? {};
  await post(`${AGENDAS}/acme.intake-2026q3/revisions/2/release`, { owner_ref: OWNER, idempotency_key: "spine-agenda-release-2", expected_head: agenda2.body?.expected_head_for_successor, release_decision_ref: "decision://acme/improvement/release-agenda/2" });
  const successorAgenda = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, cutoffBase("spine-cutoff-successor-agenda", { agenda_revision_ref: a2.revision_ref }));
  ok("a cutoff naming a RELEASED SUCCESSOR of the admitted agenda is refused (same_cutoff_mutual_validation): the agenda successor would be selected on the evidence it is about to govern", a2.revision === 2 && successorAgenda.status === 409 && code(successorAgenda.body) === "same_cutoff_mutual_validation", `${successorAgenda.status} ${code(successorAgenda.body)}`);
  const agendaRevs = (await jd(`${AGENDAS}?family=acme.intake-2026q3`)).body?.revisions ?? [];
  ok("releasing revision 2 makes revision 1 read superseded, derived on read, with its hash unchanged", agendaRevs.find((r) => r.revision === 1)?.registry_status === "superseded" && agendaRevs.find((r) => r.revision === 2)?.registry_status === "released" && agendaRevs.find((r) => r.revision === 1)?.content_hash === a1.content_hash);
  const undecided = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, cutoffBase("spine-cutoff-undecided", { eligible_finding_and_outcome_refs: ["finding://acme/nobody-decided/1"] }));
  ok("a finding no cited eligibility admits is refused (learning_evidence_ineligible): observed work is not improvement evidence until a decision says so", undecided.status === 409 && code(undecided.body) === "learning_evidence_ineligible", `${undecided.status} ${code(undecided.body)}`);
  const excludedFinding = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, cutoffBase("spine-cutoff-excluded", { eligible_finding_and_outcome_refs: ["finding://acme/sealed-leak/0001"], learning_evidence_eligibility_refs: [excluded.revision_ref] }));
  ok("a finding a real decision EXCLUDED is refused the same way — the decision is read through the learning-boundary plane, never copied", excludedFinding.status === 409 && code(excludedFinding.body) === "learning_evidence_ineligible", `${excludedFinding.status} ${code(excludedFinding.body)}`);
  const noEgress = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, cutoffBase("spine-cutoff-noegress", { boundary_crossing: "institutional_boundary" }));
  ok("an institutional-boundary crossing with no admitted egress receipt is refused (learning_egress_denied)", noEgress.status === 409 && code(noEgress.body) === "learning_egress_denied", `${noEgress.status} ${code(noEgress.body)}`);
  const beforeCutoff = await snapshot();
  const cutoff1 = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, cutoffBase("spine-cutoff-1"));
  const x1 = cutoff1.body?.improvement_order_cutoff_receipt ?? {};
  ok("a well-formed cutoff EMITS a receipt: the source roots are the campaign's contract root and the epoch's frozen root, the denied classes carry the epoch's sealed commitments, the reservation roots carry the ledger head, and the disposition is evidence_ready", cutoff1.status === 201 && x1.receipt_id === `receipt://improvement-order-cutoff/${CAMPAIGN_LIVE}/1` && x1.source_campaign_epoch_and_archive_roots?.[0] === c1b.campaign_contract_root && x1.source_campaign_epoch_and_archive_roots?.[1] === e1.frozen_root && (x1.denied_or_quarantined_information_class_refs || []).includes(H("5")) && x1.inherited_budget_risk_and_exposure_reservation_roots?.[0] === l4.ledger_head_root && x1.terminal_disposition === "evidence_ready" && x1.previous_cutoff_receipt_root === null && x1.agenda_and_task_distribution_roots?.[0] === a1.content_hash, `${cutoff1.status} ${code(cutoff1.body)}`);
  ok("receipt_root and content_hash RE-DERIVE here", x1.receipt_root === deriveReceiptRoot(x1) && x1.content_hash === deriveCutoffHash(x1));
  ok("emitting a cutoff leaves every other observable family byte-identical", drifted(beforeCutoff, await snapshot()).length === 0);
  const cutoff2 = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, cutoffBase("spine-cutoff-2", { expected_head: cutoff1.body?.expected_head_for_successor, eligible_finding_and_outcome_refs: [], learning_evidence_eligibility_refs: [] }));
  const x2 = cutoff2.body?.improvement_order_cutoff_receipt ?? {};
  ok("a second cutoff chains to the first through previous_cutoff_receipt_root and reads no_change when nothing moves", cutoff2.status === 201 && x2.previous_cutoff_receipt_root === x1.receipt_root && x2.terminal_disposition === "no_change" && x2.receipt_root === deriveReceiptRoot(x2), `${cutoff2.status} ${code(cutoff2.body)}`);
  const invalidate2 = await post(`${EPOCHS}/${E2}/invalidate`, { owner_ref: OWNER, idempotency_key: "spine-invalidate-2", expected_head: epoch2Head });
  const invalidSource = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, cutoffBase("spine-cutoff-invalid", { expected_head: cutoff2.body?.expected_head_for_successor, source_evaluation_epoch_ref: `evaluation-epoch://${E2}` }));
  ok("an INVALIDATED epoch is not a cutoff source (evaluation_epoch_invalid)", invalidate2.body?.evaluation_epoch?.lifecycle_status === "invalidated" && invalidSource.status === 409 && code(invalidSource.body) === "evaluation_epoch_invalid", `${invalidSource.status} ${code(invalidSource.body)}`);
  const cutoffs = (await jd(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`)).body?.receipts ?? [];
  ok("the campaign's cutoffs list in order", cutoffs.length === 2 && cutoffs[0].receipt_id === x1.receipt_id);

  // -- restart: every projection is re-derived from the admitted streams -------------------------------------
  const before = {
    campaign: stripIndex((await jd(`${CAMPAIGNS}/${CAMPAIGN_LIVE}`)).body),
    epoch: stripIndex((await jd(`${EPOCHS}/${E1}`)).body),
    ledger: stripIndex((await jd(`${EPOCHS}/${E1}/exposure`)).body),
    cutoffs: stripIndex((await jd(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`)).body),
    profiles: stripIndex((await jd(`${PROFILES}?family=acme.improvement`)).body),
  };
  await stopDaemon();
  await startDaemon();
  const after = {
    campaign: stripIndex((await jd(`${CAMPAIGNS}/${CAMPAIGN_LIVE}`)).body),
    epoch: stripIndex((await jd(`${EPOCHS}/${E1}`)).body),
    ledger: stripIndex((await jd(`${EPOCHS}/${E1}/exposure`)).body),
    cutoffs: stripIndex((await jd(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`)).body),
    profiles: stripIndex((await jd(`${PROFILES}?family=acme.improvement`)).body),
  };
  ok("a daemon restart reproduces the SAME campaign, epoch, ledger, cutoff and profile projections byte for byte — every one is re-derived from the admitted streams, none is remembered", Object.keys(before).every((key) => before[key] === after[key]) && before.campaign.includes("rebuilt_from"), Object.keys(before).filter((key) => before[key] !== after[key]).join(",") || "identical");
  const replay = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/order-cutoffs`, cutoffBase("spine-cutoff-1"));
  ok("after the restart a retried key REPLAYS the receipt it already emitted rather than minting a second one", replay.status === 200 && replay.body?.replayed === true && replay.body?.improvement_order_cutoff_receipt?.receipt_id === x1.receipt_id, `${replay.status} ${code(replay.body)}`);

  // -- the direct path AFTER all six objects exist (ACC-12 clause 1, again) ---------------------------------
  const direct2 = (await post(PROPOSALS, { proposal_kind: "automation_readiness", signal: "repeated_successful_goal_pattern", evidence_refs: ["ioi-agent-launch://spine-after"], suggested: { title: "Affinity after", goal_pattern: "zzz-after" } })).body?.proposal ?? {};
  await post(`${PROPOSALS}/${direct2.improvement_id}/approve`, {});
  const applied2 = (await post(`${PROPOSALS}/${direct2.improvement_id}/apply`, {})).body?.proposal ?? {};
  ok("DIRECT PATH, AFTER: a campaign-less proposal still creates, approves and applies exactly as before, with every campaign object in existence beside it", applied2.state === "applied" && applied2.improvement_campaign_ref === null && String(applied2.applied_ref || "").startsWith("automation-affinity://"), `${applied2.state}`);

  // -- the reason-code family, entailed in both directions -----------------------------------------------
  const canon = readCanonFamily();
  const moduleSource = fs.readFileSync(MODULE, "utf8") + fs.readFileSync(INTELLIGENCE, "utf8");
  ok("canon's campaign-grade failure family parses to seventeen members split into ten implemented and seven target, with no member in both", canon.family.length === 17 && canon.implemented.length === 10 && canon.target.length === 7 && canon.implemented.every((c) => canon.family.includes(c)) && canon.target.every((c) => canon.family.includes(c)) && canon.implemented.every((c) => !canon.target.includes(c)), `${canon.family.length}/${canon.implemented.length}/${canon.target.length}`);
  const unobserved = canon.implemented.filter((c) => !observedCodes.has(c));
  ok("EVERY implemented member was observed LIVE on this run — a declared code the daemon never emits would be a finding", unobserved.length === 0, unobserved.join(",") || "all ten observed");
  const leakedTarget = canon.target.filter((c) => moduleSource.includes(`"${c}"`));
  ok("NO target member appears in the module's source — an emitted code the contract does not declare as implemented would be a finding", leakedTarget.length === 0, leakedTarget.join(",") || "none");
  const familyPrefixes = ["improvement_governance_profile_", "improvement_agenda_", "improvement_campaign_", "evaluation_epoch_", "evaluation_exposure_ledger_", "improvement_order_cutoff_", "mutation_", "learning_", "model_route_", "institutional_learning_", "intelligence_", "improvement_", "automation_affinity_", "memory_", "skill_", "simulation_", "request_"];
  const strayCodes = [...observedCodes].filter((c) => !canon.family.includes(c) && !familyPrefixes.some((prefix) => c.startsWith(prefix)) && c !== "mutable_target_unresolvable");
  ok("every refusal code observed on this run is a canon family member, a spine family code under its own prefix, or the target-resolver's own — no code was invented at the seam", strayCodes.length === 0, strayCodes.join(",") || "none");

  // -- typed absences, named rather than omitted -----------------------------------------------------------
  const candidates = await jd(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/candidates`);
  const claims = await post(`${CAMPAIGNS}/${CAMPAIGN_LIVE}/evidence-claims`, {});
  ok("there is no registered route for candidates, attempts, findings or evidence claims on this basis — the candidate objects are M10.2's and M10.8's, the claim object is M12.5's, and api.md annotates each as planned", candidates.status === 404 && claims.status === 404, `${candidates.status}/${claims.status}`);
  const appImports = /super::(?:goalrun_routes|goal_profile_contract_routes|goal_run_context_routes|outcome_room_routes|ioi_agent_routes)\b/u.test(fs.readFileSync(MODULE, "utf8"));
  ok("the campaign module imports nothing from the goal-orchestration application's modules: the coordinating pursuit is recorded, never resolved, because core publishes no reader for that application's families (register R-155)", !appImports);
}

// ---------------------------------------------------------------------------------- drill
async function drill() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "improvement-spine-drill-v1", email: "improvement-spine-drill@ioi.local" }) }, { authenticated: false });
    SESSION = boot.body?.session_token || boot.body?.session?.token || "";
  }
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  const profile = (await post(PROFILES, profileBody("drill-profile-1"))).body?.improvement_governance_profile ?? {};

  // D1 — the content-hash oracle must NOTICE a changed member. An oracle that cannot fail is not one.
  ok("DRILL D1 — the independent content_hash oracle rejects a profile whose member was changed after admission", deriveProfileHash({ ...profile, max_target_improvement_order: 9 }) !== profile.content_hash && deriveProfileHash(profile) === profile.content_hash);

  // D2 — the contract-root oracle must notice a moved CONTRACT member and ignore a moved projection.
  const affinity = (await post("/v1/hypervisor/automation-affinities", { title: "Drill affinity", goal_pattern: "drill", failure_policy: "stop" })).body?.record ?? {};
  const claim = (await post("/v1/hypervisor/learning-source-rights-claims", claimBody("drill-claim-1"))).body?.learning_source_rights_claim ?? {};
  const boundary = (await post("/v1/hypervisor/institutional-learning-boundary-profiles", boundaryBody("drill-boundary-1", claim.revision_ref))).body?.institutional_learning_boundary_profile ?? {};
  const campaign = (await post(CAMPAIGNS, campaignBody("drill-campaign-1", "acme.drill", affinity.affinity_ref, profile.revision_ref, "improvement-agenda://acme.intake-2026q3/revision/1", boundary.revision_ref))).body?.improvement_campaign ?? {};
  ok("DRILL D2 — the contract-root oracle rejects a moved contract member (target order) and accepts a moved projection (lifecycle status), which is exactly the line canon draws", deriveContractRoot({ ...campaign, target_improvement_order: 1 }) !== campaign.campaign_contract_root && deriveContractRoot({ ...campaign, lifecycle_status: "active" }) === campaign.campaign_contract_root);

  // D3 — the no-effect comparison must be able to go RED, or it passes for the wrong reason.
  const before = await snapshot();
  await post("/v1/hypervisor/skill-entries", { title: "Drill skill", description: "d", body: "d" });
  const afterWrite = await snapshot();
  ok("DRILL D3 — the byte-identity comparison goes RED when a real record IS written, so its green is not two empty sets agreeing", drifted(before, afterWrite).length > 0, drifted(before, afterWrite).join(","));

  // D4 — the refusals must be keyed on the STATE, not on every successor failing.
  const profile2 = await post(PROFILES, profileBody("drill-profile-2", { version: "1.1.0", expected_head: (await jd(`${PROFILES}?family=acme.improvement`)).body?.head }));
  ok("DRILL D4 — a legal successor is admitted, so the head-conflict and lifecycle refusals are not a blanket refusal of every successor", profile2.status === 201, `${profile2.status} ${code(profile2.body)}`);

  // D5 — the canon parser must find the family, or the entailment is over an empty set.
  const canon = readCanonFamily();
  ok("DRILL D5 — the canon parser finds seventeen family members, so the both-directions entailment is over the real family and not an empty one", canon.family.length === 17 && canon.family.includes("campaign_binding_mismatch") && canon.family.includes("effect_recovery_posture_missing"), String(canon.family.length));
}

const finish = async () => {
  await stopDaemon();
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({ verifierId: "improvement-governance-spine", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  console.log(`\nimprovement governance spine: ${failed.length === 0 ? "PASS" : "FAIL"} (${results.length - failed.length}/${results.length})`);
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
