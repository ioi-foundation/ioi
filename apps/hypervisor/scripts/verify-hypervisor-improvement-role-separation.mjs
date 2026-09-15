#!/usr/bin/env node
// check:improvement-role-separation — M10.2, against an ISOLATED real daemon.
//
// THE UNIT'S CLAIM is that Search, Judgment and Authority are independently controlled by
// PRINCIPALS, not by labels: a campaign binds its three trust functions to admitted deployment
// principals in a registered ImprovementRoleBinding, every role-separated seam refuses a caller
// the binding does not name for that function, the independence obligation follows the campaign's
// declared assurance profile, a nomination discloses its accountable selector and selection policy
// and cites evidence the daemon resolves under the active epoch, negative and inconclusive
// evidence is retained, and the candidate archive is not a promotion queue. Canon:
// foundations/bounded-recursive-improvement.md § Search, Judgment, And Authority and § Improvement
// Assurance Profiles; components/hypervisor/improvement.md § Conformance Checks.
//
// THE THREE PLANTED MUTATIONS are driven by THREE REAL PRINCIPALS sharing one organization — A
// (search), B (judgment), C (authority), minted through the daemon's own principal routes and
// logged in separately — so a refusal here is about WHO called, never about a string in a body:
//   [M1 search redefines the epoch]   A freezes / activates / challenges the epoch, moves its ledger
//   [M2 judgment activates]           B nominates, approves and applies the candidate it judged
//   [M3 authority fabricates evidence] C admits an evaluation run under the epoch
// Each is refused role_separation_violated; the principal the binding DOES name then does the same
// thing and succeeds, so the refusal is keyed on the binding and not on the operation.
//
// THE ORACLES ARE INDEPENDENT: the binding's content_hash is re-derived here under canon's domain
// separator, the independence verdict is re-derived from the profile and the sets, and the
// drill plants a changed member, an overlapping set and a `rank` member to prove each notices.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   --mutation  run the planted defects instead of trusting the assertions above.
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
const jcs = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(",")}}`;
};
const sha = (text) => `sha256:${createHash("sha256").update(text).digest("hex")}`;
const digestOver = (record, domain, fields) => {
  const material = { domain };
  for (const field of fields) {
    if (!(field in record)) return `missing:${field}`;
    material[field] = record[field];
  }
  return sha(jcs(material));
};
const ROLE_BINDING_DOMAIN = "ioi.improvement-role-binding-content-commitment-jcs-sha256.v1";
const ROLE_BINDING_MATERIAL = ["schema_version", "improvement_role_binding_id", "revision_ref", "revision", "predecessor_revision_ref", "owner_ref", "campaign_ref", "improvement_assurance_profile", "bindings", "independence", "binding_decision_ref"];
const deriveRoleBindingHash = (r) => digestOver(r, ROLE_BINDING_DOMAIN, ROLE_BINDING_MATERIAL);
/** The daemon's independence rule, re-derived: the declared profile decides which sets must be disjoint. */
const deriveIndependence = (profile, bindings) => {
  const overlap = (a, b) => (a || []).filter((x) => (b || []).includes(x));
  if (profile === "local_lightweight") return "separately_identifiable";
  if (profile === "independent_review") {
    return overlap(bindings.judgment, bindings.authority).length === 0 && overlap(bindings.search, bindings.judgment).length === 0 ? "distinct_principals" : "role_independence_violated";
  }
  return "assurance_profile_not_evidenced";
};
/** "Not a promotion queue" is a structural absence: no rank, order or promote member anywhere. */
const PROMOTION_MEMBERS = ["rank", "order", "promote", "promotion_decision", "winner", "queue_position", "next"];
const promotionMembersIn = (value, at = "$") => {
  if (Array.isArray(value)) return value.flatMap((item, i) => promotionMembersIn(item, `${at}[${i}]`));
  if (value && typeof value === "object") {
    return [...Object.keys(value).filter((k) => PROMOTION_MEMBERS.includes(k)).map((k) => `${at}.${k}`), ...Object.entries(value).flatMap(([k, v]) => promotionMembersIn(v, `${at}.${k}`))];
  }
  return [];
};

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
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-role-separation-"));
let daemon = null;
let daemonPort = 0;
let DAEMON = "";
let OWNER = "";
let daemonLog = "";
const SESSIONS = { A: "", B: "", C: "" };
const PRINCIPALS = { A: "", B: "", C: "" };
const TENANTS = { A: [], B: [], C: [] };
async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1", IOI_WALLET_SECRET_PASS: "ioi-role-separation-verifier" },
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
/** A request AS one of the three principals (or anonymous with `as: null`). */
const jd = (p, init = {}, as = "A") => fetch(`${DAEMON}${p}`, {
  ...init,
  headers: { "content-type": "application/json", ...(as && SESSIONS[as] ? { cookie: `ioi_session=${SESSIONS[as]}` } : {}), ...(init.headers || {}) },
}).then(async (r) => {
  const body = await r.json().catch(() => ({}));
  const c = body?.code ?? body?.error?.code ?? body?.error;
  if (typeof c === "string" && c) observedCodes.add(c);
  return { status: r.status, body };
}).catch(() => ({ status: 0, body: {} }));
const post = (p, body, as = "A") => jd(p, { method: "POST", body: JSON.stringify(body) }, as);
const get = (p, as = "A") => jd(p, {}, as);
const code = (body) => body?.code ?? body?.error?.code ?? (typeof body?.error === "string" ? body.error : "") ?? "";
const H = (c) => `sha256:${c.repeat(64)}`;
const stripIndex = (value) => JSON.stringify(value, (key, v) => (key === "index_state" || key === "at" || key === "rebuilt_from" ? undefined : v));
const refused = (reply, status, expected) => reply.status === status && code(reply.body) === expected;

// ---------------------------------------------------------------------------- the routes
const PROFILES = "/v1/hypervisor/improvement-governance-profiles";
const AGENDAS = "/v1/hypervisor/improvement-agendas";
const CAMPAIGNS = "/v1/hypervisor/improvement-campaigns";
const EPOCHS = "/v1/hypervisor/evaluation-epochs";
const PROPOSALS = "/v1/hypervisor/intelligence/improvement-proposals";
const RUNS = "/v1/hypervisor/evaluation-runs";
const SELECTION_POLICY = "policy://acme/improvement/search-archive/v1";

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
  improvement_assurance_profile: "independent_review", resolved_component_snapshot_ref: "artifact://acme/improvement/component-snapshot/affinity/v1", outcome_room_ref: null,
  agenda_revision_ref: agendaRef, agenda_item_refs: ["affinity-goal-pattern"], campaign_mode: "optimization", target_class: "automation_affinity",
  mutable_target_ref: targetRef, atomic_target_bundle_ref: null, protected_boundary_refs: [], target_improvement_order: 0,
  target_order_path_ref: "artifact://acme/improvement/order-path/affinity/v1", base_target_generation_index: 0, parent_execution_campaign_ref: null,
  predecessor_target_generation_campaign_ref: null, source_lower_order_campaign_refs: [], deployment_incumbent_ref: targetRef,
  search_and_candidate_archive_policy_refs: [SELECTION_POLICY], synchronization_policy_ref: "policy://acme/improvement/synchronization/v1",
  ancestor_resource_budget_ledger_ref: "ledger://acme/improvement/resource/2026q3", ancestor_statistical_risk_budget_ledger_ref: "ledger://acme/improvement/statistical-risk/2026q3",
  inherited_evaluation_exposure_ledger_refs: [], learning_boundary_profile_ref: boundaryRef, stop_policy_ref: "policy://acme/improvement/stop/v1",
  rollback_recall_containment_compensation_and_reconciliation_policy_refs: ["policy://acme/improvement/effect-recovery/v1"], ...over,
});
const epochBody = (key, family, over = {}) => ({
  owner_ref: OWNER, idempotency_key: key, family, target_graph_and_order_path_roots: [H("e")], visible_eval_refs: ["evaluation-suite://acme.intake-visible/revision/1"],
  sealed_holdout_commitment_refs: [H("5")], transfer_ood_and_adversarial_eval_refs: [], recursive_seat_and_metaproductivity_metric_refs: [],
  cross_play_and_causal_ablation_policy_ref: "policy://acme/evaluation/cross-play/v1", transfer_non_regression_and_hard_constraint_gate_refs: ["policy://acme/evaluation/hard-constraints/v1"],
  metric_and_selection_policy_ref: "policy://acme/evaluation/metric-selection/v1", cost_normalization_ref: "policy://acme/evaluation/cost-normalization/v1",
  confirmatory_estimand_and_minimum_effect_refs: ["policy://acme/evaluation/estimand/v1"], statistical_test_and_winner_adjustment_refs: ["policy://acme/evaluation/statistics/v1"],
  risk_wealth_allocation_ref: "policy://acme/evaluation/risk-wealth/v1", power_and_inconclusive_stop_policy_ref: "policy://acme/evaluation/power-stop/v1",
  campaign_false_promotion_budget_ref: "policy://acme/evaluation/false-promotion-budget/v1", sealed_feedback_release_and_exposure_spend_policy_refs: ["policy://acme/evaluation/sealed-feedback/v1"],
  evaluation_exposure_budget_policy_ref: "policy://acme/improvement/exposure-budget/v1", evaluation_exposure_budget_units: 5,
  evaluator_version_and_affiliation_refs: ["evaluator://acme.exact-match/revision/1"], holdout_custodian_refs: ["principal://acme/holdout-custodian"],
  external_reality_anchor_refs: [], operational_acceptance_owner_refs: [OWNER], leakage_rotation_and_challenge_policy_refs: ["policy://acme/evaluation/leakage-rotation/v1"], ...over,
});
const exposureBody = (key, head, units, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, expected_head: head, units, candidate_family_commitment: H("6"), information_return_class: "aggregate", evaluator_version_refs: ["evaluator://acme.exact-match/revision/1"], ...over });
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
const bindingBody = (key, bindings, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, bindings, binding_decision_ref: "decision://acme/improvement/roles/v1", ...over });
const nominationBody = (key, candidate, over = {}) => ({ owner_ref: OWNER, candidate_ref: candidate, suggested: { goal_pattern: `triage intake queue ${key}` }, evidence_refs: [], selection_policy_ref: SELECTION_POLICY, reason: `nomination ${key}`, ...over });

// ------------------------------------------------------------------------- identities
async function threePrincipals(password) {
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password, email: "role-separation-a@ioi.local" }) }, null);
    SESSIONS.A = boot.body?.session_token || boot.body?.session?.token || "";
  }
  const whoA = (await get("/v1/hypervisor/auth/whoami", "A")).body || {};
  OWNER = (whoA.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  PRINCIPALS.A = whoA.principal?.principal_ref ?? "";
  TENANTS.A = whoA.principal?.tenant_refs ?? [];
  for (const [name, email] of [["B", "role-separation-b@ioi.local"], ["C", "role-separation-c@ioi.local"]]) {
    const created = await post("/v1/hypervisor/principals", { email, name: `Principal ${name}`, role: "member", password: `${password}-${name}` }, "A");
    const pid = created.body?.principal?.principal_id ?? "";
    await post(`/v1/hypervisor/principals/${pid}/tenant-memberships`, { tenant_ref: OWNER, expected_revision: 0, idempotency_key: `roles-grant-${name}`, reason: "verifier fixture: a member of the deployment's only organization" }, "A");
    const login = await post("/v1/hypervisor/auth/login", { email, password: `${password}-${name}` }, null);
    SESSIONS[name] = login.body?.session_token ?? "";
    const who = (await get("/v1/hypervisor/auth/whoami", name)).body || {};
    PRINCIPALS[name] = who.principal?.principal_ref ?? "";
    TENANTS[name] = who.principal?.tenant_refs ?? [];
  }
}

// ------------------------------------------------------------------------------------ run
async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();
  await threePrincipals("role-separation-v1");
  ok("PRECONDITION: three REAL authenticated principals share the deployment's single organization — A (to be Search), B (to be Judgment), C (to be Authority) — so every refusal below is about the PRINCIPAL, not the tenant", !!OWNER && [PRINCIPALS.A, PRINCIPALS.B, PRINCIPALS.C].every((p) => p.startsWith("user://")) && new Set(Object.values(PRINCIPALS)).size === 3 && Object.values(SESSIONS).every((s) => s.startsWith("ioi_sess_")) && ["A", "B", "C"].every((n) => TENANTS[n].includes(OWNER)), `${PRINCIPALS.A} ${PRINCIPALS.B} ${PRINCIPALS.C} tenants=${["A", "B", "C"].map((n) => TENANTS[n].includes(OWNER)).join("/")}`);

  // -- the spine to an admitted campaign (M10.1's own routes) --------------------------------
  // The spine's fixtures are AUTHORITY's: the campaign resolves its profile, agenda and boundary
  // through their owners under the creating principal, and request scopes are principal-bound.
  const claim = (await post("/v1/hypervisor/learning-source-rights-claims", claimBody("roles-claim-1"), "C")).body?.learning_source_rights_claim ?? {};
  const boundary = (await post("/v1/hypervisor/institutional-learning-boundary-profiles", boundaryBody("roles-boundary-1", claim.revision_ref), "C")).body?.institutional_learning_boundary_profile ?? {};
  const affinity = (await post("/v1/hypervisor/automation-affinities", { title: "Intake triage affinity", goal_pattern: "triage intake queue", failure_policy: "stop" }, "C")).body?.record ?? {};
  const targetRef = String(affinity.affinity_ref || "");
  const profile = await post(PROFILES, profileBody("roles-profile-1", { max_target_improvement_order: 1 }), "C");
  const profileRef = profile.body?.improvement_governance_profile?.revision_ref;
  const agenda = await post(AGENDAS, agendaBody("roles-agenda-1", targetRef), "C");
  const agendaRef = agenda.body?.improvement_agenda?.revision_ref;
  await post(`${AGENDAS}/acme.intake-2026q3/revisions/1/release`, { owner_ref: OWNER, idempotency_key: "roles-agenda-release-1", expected_head: agenda.body?.expected_head_for_successor, release_decision_ref: "decision://acme/improvement/release-agenda/1" }, "C");
  const CAMPAIGN = "acme.intake-affinity-live";
  const campaign = await post(CAMPAIGNS, campaignBody("roles-campaign-1", CAMPAIGN, targetRef, profileRef, agendaRef, boundary.revision_ref), "C");
  let cHead = campaign.body?.expected_head_for_successor;
  const admit = await post(`${CAMPAIGNS}/${CAMPAIGN}/admit`, { owner_ref: OWNER, idempotency_key: "roles-admit-1", expected_head: cHead, campaign_admission_decision_ref: "decision://acme/improvement/admit/live" }, "C");
  cHead = admit.body?.expected_head_for_successor;
  ok("PRECONDITION: C (to be Authority) creates and admits a campaign at `independent_review` through M10.1's spine (profile, released agenda, learning boundary, core-owned target) — the campaign's scope is Authority's, as canon has Authority admit scope and budgets", campaign.status === 201 && admit.status === 201 && admit.body?.improvement_campaign?.improvement_assurance_profile === "independent_review", `${campaign.status} ${code(campaign.body)} / ${admit.status} ${code(admit.body)}`);
  const unboundRead = await get(`${CAMPAIGNS}/${CAMPAIGN}`, "A");
  ok("PRECONDITION: before any binding, A cannot even READ the campaign — the substrate's request scopes are principal-bound (M05.8's isolation), which is why the binding must delegate", unboundRead.status === 403 && code(unboundRead.body) === "request_resource_scope_required", `${unboundRead.status} ${code(unboundRead.body)}`);
  const startUnbound = await post(`${CAMPAIGNS}/${CAMPAIGN}/start`, { owner_ref: OWNER, idempotency_key: "roles-start-unbound", expected_head: cHead }, "C");
  ok("[bound before it runs] an admitted campaign does not START until a role binding is admitted (role_bindings_required)", refused(startUnbound, 409, "role_bindings_required"), `${startUnbound.status} ${code(startUnbound.body)}`);

  // -- the binding: refusals first, keyed on the declared profile ---------------------------------
  const ROLES = `${CAMPAIGNS}/${CAMPAIGN}/role-bindings`;
  const unknownFunction = await post(ROLES, bindingBody("roles-bind-unknownfn", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C], oracle: [PRINCIPALS.A] }), "C");
  ok("a function outside search | judgment | authority is refused by name", refused(unknownFunction, 422, "improvement_role_binding_function_unknown"), `${unknownFunction.status} ${code(unknownFunction.body)}`);
  const emptyJudgment = await post(ROLES, bindingBody("roles-bind-empty", { search: [PRINCIPALS.A], judgment: [], authority: [PRINCIPALS.C] }), "C");
  ok("every function binds at least one principal (function_required)", refused(emptyJudgment, 422, "improvement_role_binding_function_required"), `${emptyJudgment.status} ${code(emptyJudgment.body)}`);
  const ghostPrincipal = await post(ROLES, bindingBody("roles-bind-ghost", { search: [PRINCIPALS.A], judgment: ["user://nobody-here"], authority: [PRINCIPALS.C] }), "C");
  ok("a principal this deployment never admitted is refused (principal_unresolvable): a function is held by an accountable principal, never by a label", refused(ghostPrincipal, 422, "improvement_role_binding_principal_unresolvable"), `${ghostPrincipal.status} ${code(ghostPrincipal.body)}`);
  const labelPrincipal = await post(ROLES, bindingBody("roles-bind-label", { search: [PRINCIPALS.A], judgment: ["service://judge-bot"], authority: [PRINCIPALS.C] }), "C");
  ok("a service label in the principal slot is refused the same way", refused(labelPrincipal, 422, "improvement_role_binding_principal_unresolvable"), `${labelPrincipal.status} ${code(labelPrincipal.body)}`);
  const noDecision = await post(ROLES, bindingBody("roles-bind-nodecision", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }, { binding_decision_ref: "the owner said so" }), "C");
  ok("a binding names the decision:// that bound the functions", refused(noDecision, 422, "improvement_role_binding_binding_decision_required"), `${noDecision.status} ${code(noDecision.body)}`);
  const authoredIndependence = await post(ROLES, bindingBody("roles-bind-authored", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }, { independence: "distinct_principals" }), "C");
  ok("the independence verdict is DERIVED: authoring it is refused by name", refused(authoredIndependence, 422, "improvement_role_binding_caller_authored_evidence_refused"), `${authoredIndependence.status} ${code(authoredIndependence.body)}`);
  const unknownField = await post(ROLES, bindingBody("roles-bind-unknownfield", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }, { fitness: 1 }), "C");
  ok("a member the route does not read is refused rather than dropped", refused(unknownField, 400, "improvement_role_binding_request_unknown_field"), `${unknownField.status} ${code(unknownField.body)}`);
  const judgeIsAuthority = await post(ROLES, bindingBody("roles-bind-judgeauthority", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.B, PRINCIPALS.C] }), "C");
  ok("[independence follows the profile] at independent_review a principal holding BOTH judgment and authority is refused (role_independence_violated): judgment and promotion are distinct accountable principals", refused(judgeIsAuthority, 422, "role_independence_violated") && deriveIndependence("independent_review", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.B, PRINCIPALS.C] }) === "role_independence_violated", `${judgeIsAuthority.status} ${code(judgeIsAuthority.body)}`);
  const searchIsJudge = await post(ROLES, bindingBody("roles-bind-searchjudge", { search: [PRINCIPALS.A, PRINCIPALS.B], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }), "C");
  ok("[independence] a principal holding BOTH search and judgment is refused at independent_review: a candidate cannot control its evaluator (invariant 2)", refused(searchIsJudge, 422, "role_independence_violated"), `${searchIsJudge.status} ${code(searchIsJudge.body)}`);
  const bound = await post(ROLES, bindingBody("roles-bind-1", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }), "C");
  const b1 = bound.body?.improvement_role_binding ?? {};
  let bindHead = bound.body?.expected_head_for_successor;
  ok("the DISJOINT binding admits as revision 1: the campaign's profile COPIED, independence DERIVED as distinct_principals (re-derived here), the three sets frozen, content_hash re-derived under canon's domain separator", bound.status === 201 && b1.revision === 1 && b1.predecessor_revision_ref === null && b1.improvement_assurance_profile === "independent_review" && b1.independence === deriveIndependence("independent_review", b1.bindings) && b1.campaign_ref === `improvement-campaign://${CAMPAIGN}` && b1.content_hash === deriveRoleBindingHash(b1) && b1.revision_ref === `improvement-role-binding://${CAMPAIGN}/revision/1`, `${bound.status} ${code(bound.body)} ${b1.independence}`);
  const replayBind = await post(ROLES, bindingBody("roles-bind-1", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }), "C");
  ok("a retried key REPLAYS the binding it already admitted", replayBind.status === 200 && replayBind.body?.replayed === true, `${replayBind.status} ${code(replayBind.body)}`);
  const staleSuccessor = await post(ROLES, bindingBody("roles-bind-stale", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }), "C");
  ok("a successor that names no head is refused by the chain: the binding is a revision family, not a mutable row", refused(staleSuccessor, 409, "improvement_role_binding_expected_head_conflict"), `${staleSuccessor.status} ${code(staleSuccessor.body)}`);
  const successor = await post(ROLES, bindingBody("roles-bind-2", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }, { expected_head: bindHead, binding_decision_ref: "decision://acme/improvement/roles/v2" }), "C");
  const b2 = successor.body?.improvement_role_binding ?? {};
  bindHead = successor.body?.expected_head_for_successor;
  ok("a successor revision names its predecessor and becomes the campaign's CURRENT binding", successor.status === 201 && b2.revision === 2 && b2.predecessor_revision_ref === b1.revision_ref && b2.binding_decision_ref === "decision://acme/improvement/roles/v2" && b2.content_hash === deriveRoleBindingHash(b2), `${successor.status} ${code(successor.body)}`);
  const bindings = await get(ROLES, "C");
  ok("GET the binding: both revisions in order, the current one revision 2", (bindings.body?.revisions || []).length === 2 && bindings.body?.current?.revision === 2, `${bindings.status}`);
  ok("[delegation] the binding DELEGATED reads: A and B — who could not read the campaign a moment ago — now read the binding and the campaign identically to C; the binding is the campaign's, not the caller's, and only reads were widened", (await get(ROLES, "A")).body?.current?.content_hash === b2.content_hash && (await get(ROLES, "B")).body?.current?.content_hash === b2.content_hash && (await get(`${CAMPAIGNS}/${CAMPAIGN}`, "A")).status === 200 && (await get(`${CAMPAIGNS}/${CAMPAIGN}`, "B")).status === 200);
  const startBySearch = await post(`${CAMPAIGNS}/${CAMPAIGN}/start`, { owner_ref: OWNER, idempotency_key: "roles-start-by-a", expected_head: cHead }, "A");
  ok("[M1] A (Search) starting the campaign is refused role_separation_violated: starting, pausing and stopping work is Authority's", refused(startBySearch, 403, "role_separation_violated"), `${startBySearch.status} ${code(startBySearch.body)}`);
  const start = await post(`${CAMPAIGNS}/${CAMPAIGN}/start`, { owner_ref: OWNER, idempotency_key: "roles-start-1", expected_head: cHead }, "C");
  cHead = start.body?.expected_head_for_successor;
  ok("[bound before it runs] once bound, C starts the campaign", start.status === 201 && start.body?.improvement_campaign?.lifecycle_status === "active", `${start.status} ${code(start.body)}`);

  // -- M1: Search cannot redefine the epoch ------------------------------------------------------------
  const E1 = `${CAMPAIGN}.epoch-1`;
  const EPOCH_REF = `evaluation-epoch://${E1}`;
  const epochBySearch = await post(`${CAMPAIGNS}/${CAMPAIGN}/evaluation-epochs`, epochBody("roles-epoch-by-a", E1), "A");
  ok("[M1 search redefines the epoch] A (Search) creating the epoch is refused role_separation_violated: the judgment contract is Judgment's to write from its first byte", refused(epochBySearch, 403, "role_separation_violated"), `${epochBySearch.status} ${code(epochBySearch.body)}`);
  const epoch = await post(`${CAMPAIGNS}/${CAMPAIGN}/evaluation-epochs`, epochBody("roles-epoch-1", E1), "B");
  let epochHead = epoch.body?.expected_head_for_successor;
  ok("B (Judgment) creates the epoch DRAFT under the active campaign, and A reads it: the epoch's scope was delegated to the binding's principals at creation", epoch.status === 201 && epoch.body?.evaluation_epoch?.lifecycle_status === "draft" && (await get(`${EPOCHS}/${E1}`, "A")).status === 200 && (await get(`${EPOCHS}/${E1}`, "C")).status === 200, `${epoch.status} ${code(epoch.body)}`);
  const freezeBySearch = await post(`${EPOCHS}/${E1}/freeze`, { owner_ref: OWNER, idempotency_key: "roles-freeze-by-a", expected_head: epochHead }, "A");
  ok("[M1 search redefines the epoch] A (Search) freezing the epoch is refused role_separation_violated — the resolved principal holds neither judgment nor authority", refused(freezeBySearch, 403, "role_separation_violated"), `${freezeBySearch.status} ${code(freezeBySearch.body)}`);
  const freezeByJudge = await post(`${EPOCHS}/${E1}/freeze`, { owner_ref: OWNER, idempotency_key: "roles-freeze-by-b", expected_head: epochHead }, "B");
  epochHead = freezeByJudge.body?.expected_head_for_successor;
  ok("[M1] the SAME operation by B (Judgment) succeeds: the refusal was keyed on the binding, not on the operation", freezeByJudge.status === 201 && freezeByJudge.body?.evaluation_epoch?.lifecycle_status === "frozen", `${freezeByJudge.status} ${code(freezeByJudge.body)}`);
  const activateBySearch = await post(`${EPOCHS}/${E1}/activate`, { owner_ref: OWNER, idempotency_key: "roles-activate-by-a", expected_head: epochHead }, "A");
  ok("[M1] A activating the frozen epoch is refused the same way", refused(activateBySearch, 403, "role_separation_violated"), `${activateBySearch.status} ${code(activateBySearch.body)}`);
  const activateByAuthority = await post(`${EPOCHS}/${E1}/activate`, { owner_ref: OWNER, idempotency_key: "roles-activate-by-c", expected_head: epochHead }, "C");
  ok("[M3] C (Authority) activating the epoch is refused too: activation of the judgment contract is Judgment's — Authority activates releases, not the contract that judges them", refused(activateByAuthority, 403, "role_separation_violated"), `${activateByAuthority.status} ${code(activateByAuthority.body)}`);
  const activateByJudge = await post(`${EPOCHS}/${E1}/activate`, { owner_ref: OWNER, idempotency_key: "roles-activate-by-b", expected_head: epochHead }, "B");
  epochHead = activateByJudge.body?.expected_head_for_successor;
  ok("B (Judgment) activates it", activateByJudge.status === 201 && activateByJudge.body?.evaluation_epoch?.lifecycle_status === "active", `${activateByJudge.status} ${code(activateByJudge.body)}`);
  const challengeBySearch = await post(`${EPOCHS}/${E1}/challenge`, { owner_ref: OWNER, idempotency_key: "roles-challenge-by-a", expected_head: epochHead, challenge_evidence_refs: ["finding://acme/leak/1"] }, "A");
  ok("[M1] A challenging the active epoch is refused: Search cannot alter sealed evidence or the contract that judges it", refused(challengeBySearch, 403, "role_separation_violated"), `${challengeBySearch.status} ${code(challengeBySearch.body)}`);
  let ledgerHead = (await get(`${EPOCHS}/${E1}/exposure`, "B")).body?.head;
  const reserveBySearch = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("roles-reserve-by-a", ledgerHead, 2), "A");
  ok("[M1] A reserving exposure is refused: the ledger is Judgment's accounting", refused(reserveBySearch, 403, "role_separation_violated"), `${reserveBySearch.status} ${code(reserveBySearch.body)}`);
  const reserveByAuthority = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("roles-reserve-by-c", ledgerHead, 2), "C");
  ok("[M3] C reserving exposure is refused too: Authority does not account for evidence it will decide on", refused(reserveByAuthority, 403, "role_separation_violated"), `${reserveByAuthority.status} ${code(reserveByAuthority.body)}`);
  const reserveByJudge = await post(`${EPOCHS}/${E1}/exposure/reserve`, exposureBody("roles-reserve-by-b", ledgerHead, 2), "B");
  ledgerHead = reserveByJudge.body?.expected_head_for_successor;
  const RESERVATION = reserveByJudge.body?.evaluation_exposure_ledger?.entries?.at(-1)?.entry_ref ?? "";
  const spendByJudge = await post(`${EPOCHS}/${E1}/exposure/spend`, exposureBody("roles-spend-by-b", ledgerHead, 1, { selected_case_commitment: H("7"), information_return_class: "per_case" }), "B");
  ledgerHead = spendByJudge.body?.expected_head_for_successor;
  const SPEND = spendByJudge.body?.evaluation_exposure_ledger?.entries?.at(-1)?.entry_ref ?? "";
  ok("B reserves and spends: the ledger holds a reservation entry and a SPEND entry appended by Judgment", reserveByJudge.status === 201 && spendByJudge.status === 201 && RESERVATION.endsWith("/entry/1") && SPEND.endsWith("/entry/2"), `${reserveByJudge.status}/${spendByJudge.status} ${SPEND}`);

  // -- M3: Authority cannot create evaluation evidence -------------------------------------------------
  const runBody = (key, family) => ({ owner_ref: OWNER, idempotency_key: key, family, evaluation_epoch_ref: EPOCH_REF, suite_revision_ref: "evaluation-suite://acme.intake-visible/revision/1", evaluator_revision_ref: "evaluator://acme.exact-match/revision/1", lane: "visible", execution_evidence_refs: ["model-invocation://inv_nope"], policy_bound_data_view_revision_ref: "view://acme.intake-minimised/revision/1", nondeterminism_class: "deterministic", submitter_role: "evaluator", cost_units: 1, cost_unit: "tokens" });
  const runByAuthority = await post(RUNS, runBody("roles-run-by-c", "acme.run-by-c"), "C");
  ok("[M3 authority fabricates evidence] C admitting an evaluation run under the epoch is refused role_separation_violated BEFORE any evidence seam answers", refused(runByAuthority, 403, "role_separation_violated"), `${runByAuthority.status} ${code(runByAuthority.body)}`);
  const runBySearch = await post(RUNS, runBody("roles-run-by-a", "acme.run-by-a"), "A");
  ok("[M3] A admitting an evaluation run is refused the same way: Search requests evaluation, it does not produce it", refused(runBySearch, 403, "role_separation_violated"), `${runBySearch.status} ${code(runBySearch.body)}`);
  const runByJudge = await post(RUNS, runBody("roles-run-by-b", "acme.run-by-b"), "B");
  ok("[M3] the SAME run by B (Judgment) passes the role seam and is refused only by the evidence seams behind it (no suite family exists under B, so the suite resolver refuses) — the refusal is about who, not what", code(runByJudge.body) !== "role_separation_violated" && ["request_resource_scope_required", "evaluation_suite_revision_revision_absent", "mutable_latest_refused"].includes(code(runByJudge.body)), `${runByJudge.status} ${code(runByJudge.body)}`);
  const runAsTargetOwner = await post(RUNS, runBody("roles-run-owner-by-b", "acme.run-owner-by-b"), "B");
  const runAsTargetOwnerByC = await post(RUNS, { ...runBody("roles-run-owner-by-c", "acme.run-owner-by-c"), submitter_role: "target_owner" }, "C");
  const runAsTargetOwnerByB = await post(RUNS, { ...runBody("roles-run-owner-by-b2", "acme.run-owner-by-b2"), submitter_role: "target_owner" }, "B");
  ok("[M3] a `target_owner` submitter must hold Judgment AND Authority, which independent_review forbids in one principal: C (authority only) and B (judgment only) are both refused", refused(runAsTargetOwnerByC, 403, "role_separation_violated") && refused(runAsTargetOwnerByB, 403, "role_separation_violated") && code(runAsTargetOwner.body) !== "role_separation_violated", `${runAsTargetOwnerByC.status}/${runAsTargetOwnerByB.status}`);

  // -- the nomination: Search's, accountable, policy-declared, evidence-cited --------------------------
  const NOMINATE = `${CAMPAIGNS}/${CAMPAIGN}/upgrade-proposals`;
  const nominateByJudge = await post(NOMINATE, nominationBody("by-b", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: [SPEND] }), "B");
  ok("[M2 judgment activates] B (Judgment) nominating the candidate it judged is refused role_separation_violated", refused(nominateByJudge, 403, "role_separation_violated"), `${nominateByJudge.status} ${code(nominateByJudge.body)}`);
  const nominateByAuthority = await post(NOMINATE, nominationBody("by-c", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: [SPEND] }), "C");
  ok("C (Authority) nominating is refused too: Authority decides on candidates, it does not propose them", refused(nominateByAuthority, 403, "role_separation_violated"), `${nominateByAuthority.status} ${code(nominateByAuthority.body)}`);
  const noPolicy = await post(NOMINATE, nominationBody("nopolicy", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: [SPEND], selection_policy_ref: undefined }), "A");
  ok("[disclosure] a nomination without a selection policy is refused (selection_policy_undeclared)", refused(noPolicy, 422, "selection_policy_undeclared"), `${noPolicy.status} ${code(noPolicy.body)}`);
  const foreignPolicy = await post(NOMINATE, nominationBody("foreignpolicy", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: [SPEND], selection_policy_ref: "policy://acme/improvement/some-other-archive/v9" }), "A");
  ok("[disclosure] a selection policy the campaign contract did not declare is refused: the policy that selects a generation is frozen with the contract", refused(foreignPolicy, 422, "selection_policy_undeclared"), `${foreignPolicy.status} ${code(foreignPolicy.body)}`);
  const authoredSelector = await post(NOMINATE, nominationBody("authoredselector", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: [SPEND], accountable_selector_ref: PRINCIPALS.C }), "A");
  ok("[disclosure] the accountable selector is the RESOLVED caller: a body naming one is refused by that member's name", refused(authoredSelector, 422, "improvement_campaign_caller_authored_evidence_refused"), `${authoredSelector.status} ${code(authoredSelector.body)}`);
  const noEvidence = await post(NOMINATE, nominationBody("noevidence", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: ["attempt://acme/campaign/attempt-12"] }), "A");
  ok("[M3, the ledger half] a nomination citing nothing the daemon can resolve under the active epoch is refused (nomination_evidence_required): a promotion attempted without the ledger's records", refused(noEvidence, 422, "nomination_evidence_required"), `${noEvidence.status} ${code(noEvidence.body)}`);
  const ghostResult = await post(NOMINATE, nominationBody("ghostresult", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: ["evaluation-result://acme.nowhere"] }), "A");
  ok("[M3] a fabricated evaluation result ref is refused (nomination_evidence_unresolvable): evidence is resolved through the evaluation plane's reader, never trusted from the nominator", refused(ghostResult, 422, "nomination_evidence_unresolvable"), `${ghostResult.status} ${code(ghostResult.body)}`);
  const reservationAsEvidence = await post(NOMINATE, nominationBody("reservation", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: [RESERVATION] }), "A");
  ok("[M3] a RESERVATION offered as evidence is refused: evidence is the spend a protected access appended, not the intent to access", refused(reservationAsEvidence, 422, "nomination_evidence_unresolvable"), `${reservationAsEvidence.status} ${code(reservationAsEvidence.body)}`);
  const foreignEntry = await post(NOMINATE, nominationBody("foreignentry", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: ["evaluation-exposure://acme.other.epoch-1/entry/2"] }), "A");
  ok("[M3] an entry of another epoch's ledger is refused the same way", refused(foreignEntry, 422, "nomination_evidence_unresolvable"), `${foreignEntry.status} ${code(foreignEntry.body)}`);
  const nominated = await post(NOMINATE, nominationBody("gen-1", "artifact://acme/candidates/affinity/gen-1", { evidence_refs: ["attempt://acme/campaign/attempt-12", SPEND] }), "A");
  const p1 = nominated.body?.proposal ?? {};
  ok("[selection stops at eligibility] A (Search) nominates with the spend entry cited and the policy declared: an ORDINARY PENDING proposal bound to the campaign, its active epoch and the frozen contract root, with the accountable selector RESOLVED to A and the policy recorded", nominated.status === 201 && p1.state === "pending" && p1.improvement_campaign_ref === `improvement-campaign://${CAMPAIGN}` && p1.evaluation_epoch_ref === EPOCH_REF && p1.accountable_selector_ref === PRINCIPALS.A && p1.selection_policy_ref === SELECTION_POLICY && p1.candidate_ref === "artifact://acme/candidates/affinity/gen-1", `${nominated.status} ${code(nominated.body)} selector=${p1.accountable_selector_ref}`);

  const nominated2 = await post(NOMINATE, nominationBody("gen-2", "artifact://acme/candidates/affinity/gen-2", { evidence_refs: [SPEND] }), "A");
  const p2 = nominated2.body?.proposal ?? {};
  ok("a second nomination (gen-2) is pending beside the first — the archive will keep both whatever Authority decides", nominated2.status === 201 && p2.state === "pending" && p2.candidate_ref === "artifact://acme/candidates/affinity/gen-2", `${nominated2.status} ${code(nominated2.body)}`);

  // -- M2: Judgment cannot activate; Authority does, and it is a principal ------------------------------
  const anonymousApprove = await post(`${PROPOSALS}/${p1.improvement_id}/approve`, {}, null);
  ok("[authority is a principal] an ANONYMOUS approve is refused 401 before any record is read — review is no longer nobody's", anonymousApprove.status === 401, `${anonymousApprove.status} ${code(anonymousApprove.body)}`);
  const approveByJudge = await post(`${PROPOSALS}/${p1.improvement_id}/approve`, {}, "B");
  ok("[M2 judgment activates] B (Judgment) approving the candidate it judged is refused role_separation_violated", refused(approveByJudge, 403, "role_separation_violated"), `${approveByJudge.status} ${code(approveByJudge.body)}`);
  const approveBySearch = await post(`${PROPOSALS}/${p1.improvement_id}/approve`, {}, "A");
  ok("[M2] A (Search) approving its own nomination is refused: Search cannot grant authority", refused(approveBySearch, 403, "role_separation_violated"), `${approveBySearch.status} ${code(approveBySearch.body)}`);
  const applyUnapprovedByJudge = await post(`${PROPOSALS}/${p1.improvement_id}/apply`, {}, "B");
  ok("[M2] B applying is refused by the role seam before the approval state is even consulted", refused(applyUnapprovedByJudge, 403, "role_separation_violated"), `${applyUnapprovedByJudge.status} ${code(applyUnapprovedByJudge.body)}`);
  const approveByAuthority = await post(`${PROPOSALS}/${p1.improvement_id}/approve`, {}, "C");
  ok("C (Authority) approves, and the review records the accountable reviewer", approveByAuthority.status === 200 && approveByAuthority.body?.proposal?.state === "approved" && approveByAuthority.body?.proposal?.reviewed_by_ref === PRINCIPALS.C, `${approveByAuthority.status} ${code(approveByAuthority.body)} ${approveByAuthority.body?.proposal?.reviewed_by_ref}`);
  const applyByJudge = await post(`${PROPOSALS}/${p1.improvement_id}/apply`, {}, "B");
  ok("[M2] B applying the APPROVED candidate is still refused: judgment never makes a release canonical", refused(applyByJudge, 403, "role_separation_violated"), `${applyByJudge.status} ${code(applyByJudge.body)}`);
  const affinityBefore = ((await get("/v1/hypervisor/automation-affinities")).body?.affinities ?? []).find((r) => r.affinity_ref === targetRef);
  const applyByAuthority = await post(`${PROPOSALS}/${p1.improvement_id}/apply`, {}, "C");
  const affinityAfter = ((await get("/v1/hypervisor/automation-affinities")).body?.affinities ?? []).find((r) => r.affinity_ref === targetRef);
  ok("[selection stops at eligibility] C applies through the target owner's ordinary path and the target moves — only then", applyByAuthority.status === 200 && applyByAuthority.body?.proposal?.state === "applied" && affinityBefore?.goal_pattern !== affinityAfter?.goal_pattern && affinityAfter?.goal_pattern === "triage intake queue gen-1", `${applyByAuthority.status} ${code(applyByAuthority.body)} · ${affinityAfter?.goal_pattern}`);

  // -- negative evidence retained: a rejected nomination stays in the archive -----------------------------
  const rejectByJudge = await post(`${PROPOSALS}/${p2.improvement_id}/reject`, { reason: "judge dislikes it" }, "B");
  ok("[M2] B rejecting is refused as well: rejection is a decision, and decisions are Authority's", refused(rejectByJudge, 403, "role_separation_violated"), `${rejectByJudge.status} ${code(rejectByJudge.body)}`);
  const rejectByAuthority = await post(`${PROPOSALS}/${p2.improvement_id}/reject`, { reason: "the escalation case regressed" }, "C");
  ok("C rejects the second nomination with a reason, and the record names C", rejectByAuthority.status === 200 && rejectByAuthority.body?.proposal?.state === "rejected" && rejectByAuthority.body?.proposal?.reviewed_by_ref === PRINCIPALS.C, `${rejectByAuthority.status} ${code(rejectByAuthority.body)}`);
  // a nomination against the moved target is stale — refused at the handoff, so the archive holds exactly two
  const staleNomination = await post(NOMINATE, nominationBody("gen-3", "artifact://acme/candidates/affinity/gen-3", { evidence_refs: [SPEND] }), "A");
  ok("after the apply the target moved, so a further nomination is refused target_base_stale (M10.1's binding, unchanged beside the new seams)", refused(staleNomination, 409, "target_base_stale"), `${staleNomination.status} ${code(staleNomination.body)}`);

  // -- the archive: derived, retained, not a queue --------------------------------------------------------
  const anonymousArchive = await get(`${CAMPAIGNS}/${CAMPAIGN}/candidates`, null);
  ok("the archive is read under an identity: anonymous is refused 401", anonymousArchive.status === 401, `${anonymousArchive.status}`);
  const archive = (await get(`${CAMPAIGNS}/${CAMPAIGN}/candidates`, "B")).body ?? {};
  const byCandidate = Object.fromEntries((archive.candidates || []).map((c) => [c.candidate_ref, c]));
  ok("[archive, retained] the candidate archive lists BOTH nominations — the applied gen-1 and the REJECTED gen-2 — each retained with its accountable selector, its declared policy and its evidence resolved to the ledger's spend entry; a rejection is kept, never erased", archive.count === 2 && byCandidate["artifact://acme/candidates/affinity/gen-1"]?.state === "applied" && byCandidate["artifact://acme/candidates/affinity/gen-2"]?.state === "rejected" && (archive.candidates || []).every((c) => c.retained === true && c.accountable_selector_ref === PRINCIPALS.A && c.selection_policy_ref === SELECTION_POLICY && c.evidence.some((e) => e.kind === "exposure_entry" && e.entry_kind === "spend" && e.ref === SPEND) && c.evidence.some((e) => e.kind === "opaque" || e.kind === "exposure_entry")), `count=${archive.count} ${JSON.stringify((archive.candidates || []).map((c) => c.state))}`);
  ok("[archive, not a promotion queue] no rank, order, promote, winner, queue-position or next member exists anywhere in the projection — a structural absence, asserted over every key of every entry", promotionMembersIn(archive).length === 0 && /not a promotion queue/u.test(archive.note ?? ""), promotionMembersIn(archive).join(",") || "none");
  const archiveAsA = (await get(`${CAMPAIGNS}/${CAMPAIGN}/candidates`, "A")).body ?? {};
  ok("the archive reads identically to Search, Judgment and Authority: it is the campaign's record, not a role's view", stripIndex(archiveAsA) === stripIndex(archive) && stripIndex((await get(`${CAMPAIGNS}/${CAMPAIGN}/candidates`, "C")).body) === stripIndex(archive));

  // -- the profile decides: local_lightweight accepts one accountable principal; a higher tier fails closed --
  const SOLO = "acme.solo-notes";
  const solo = await post(CAMPAIGNS, campaignBody("roles-campaign-solo", SOLO, targetRef, profileRef, agendaRef, boundary.revision_ref, { improvement_assurance_profile: "local_lightweight" }), "C");
  const soloAdmit = await post(`${CAMPAIGNS}/${SOLO}/admit`, { owner_ref: OWNER, idempotency_key: "roles-admit-solo", expected_head: solo.body?.expected_head_for_successor, campaign_admission_decision_ref: "decision://acme/improvement/admit/solo" }, "C");
  const soloBinding = await post(`${CAMPAIGNS}/${SOLO}/role-bindings`, bindingBody("roles-bind-solo", { search: [PRINCIPALS.C], judgment: [PRINCIPALS.C], authority: [PRINCIPALS.C] }), "C");
  const sb = soloBinding.body?.improvement_role_binding ?? {};
  ok("[independence follows the profile] the SAME overlap that independent_review refused is ACCEPTED at local_lightweight as separately_identifiable: the tier decides, not prose — and the target is stale for a new campaign only at nomination, so admission and binding proceed", solo.status === 201 && soloAdmit.status === 201 && soloBinding.status === 201 && sb.independence === "separately_identifiable" && sb.improvement_assurance_profile === "local_lightweight" && sb.content_hash === deriveRoleBindingHash(sb), `${solo.status} ${code(solo.body)} / ${soloAdmit.status} ${code(soloAdmit.body)} / ${soloBinding.status} ${code(soloBinding.body)}`);
  const PROTECTED = "acme.protected-build";
  const protectedCampaign = await post(CAMPAIGNS, campaignBody("roles-campaign-protected", PROTECTED, targetRef, profileRef, agendaRef, boundary.revision_ref, { improvement_assurance_profile: "protected_build" }), "C");
  const protectedBinding = await post(`${CAMPAIGNS}/${PROTECTED}/role-bindings`, bindingBody("roles-bind-protected", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }), "C");
  ok("[fails closed] a campaign declaring protected_build cannot bind: the tiers above independent_review need evidence this build does not evaluate (assurance_profile_not_evidenced) — a declared profile the deployment cannot evidence fails closed, it is not rounded down", protectedCampaign.status === 201 && refused(protectedBinding, 422, "assurance_profile_not_evidenced") && deriveIndependence("protected_build", {}) === "assurance_profile_not_evidenced", `${protectedCampaign.status} / ${protectedBinding.status} ${code(protectedBinding.body)}`);
  const bindingOnGhost = await post(`${CAMPAIGNS}/acme.nowhere/role-bindings`, bindingBody("roles-bind-ghost-campaign", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }), "C");
  ok("a binding on a campaign that does not exist is refused", [404, 403].includes(bindingOnGhost.status), `${bindingOnGhost.status} ${code(bindingOnGhost.body)}`);

  // -- restart: the binding, the archive and the proposals are re-derived from the admitted streams -------------
  const projections = async () => ({
    binding: stripIndex((await get(ROLES, "C")).body),
    archive: stripIndex((await get(`${CAMPAIGNS}/${CAMPAIGN}/candidates`, "C")).body),
    campaign: stripIndex((await get(`${CAMPAIGNS}/${CAMPAIGN}`, "C")).body),
    epoch: stripIndex((await get(`${EPOCHS}/${E1}`, "C")).body),
  });
  const before = await projections();
  await stopDaemon();
  await startDaemon();
  const after = await projections();
  ok("a daemon restart reproduces the binding, the archive, the campaign and the epoch projections byte for byte — every one is re-derived from the admitted streams", Object.keys(before).every((key) => before[key] === after[key]), Object.keys(before).filter((key) => before[key] !== after[key]).join(",") || "identical");
  const freezeAfterRestart = await post(`${EPOCHS}/${E1}/close`, { owner_ref: OWNER, idempotency_key: "roles-close-by-a", expected_head: epochHead }, "A");
  const stillDelegated = await get(`${EPOCHS}/${E1}/exposure`, "A");
  ok("after the restart A still READS the ledger Judgment appended (the delegation is a successor on the scope's own stream, durable and replayed), and still cannot move it", stillDelegated.status === 200 && (stillDelegated.body?.evaluation_exposure_ledger?.entries || []).length === 2, `${stillDelegated.status}`);
  ok("after the restart the seam still refuses A on the epoch: the binding is durable truth, not a process memory", refused(freezeAfterRestart, 403, "role_separation_violated"), `${freezeAfterRestart.status} ${code(freezeAfterRestart.body)}`);

  // -- the plane's vocabulary, observed live --------------------------------------------------------------------
  const PLANE_CODES = ["role_bindings_required", "role_separation_violated", "role_independence_violated", "assurance_profile_not_evidenced", "selection_policy_undeclared", "nomination_evidence_required", "nomination_evidence_unresolvable"];
  const unobserved = PLANE_CODES.filter((c) => !observedCodes.has(c));
  ok("every one of the seven role-separation codes was observed LIVE on this run", unobserved.length === 0, unobserved.join(",") || "all seven observed");
  const canonGates = fs.readFileSync(path.join(ROOT, "docs/architecture/components/daemon-runtime/improvement-governance-gates.md"), "utf8");
  ok("every one of the seven codes is documented in the gates canon's role-separation section, and none of them is inside the campaign-grade family M10.1's gate entails", PLANE_CODES.every((c) => canonGates.includes(`${c} `)) && !canonGates.slice(0, canonGates.indexOf("## Search, judgment and authority separation")).includes("role_separation_violated"));
}

// ---------------------------------------------------------------------------------- drill
async function drill() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();
  await threePrincipals("role-separation-drill-v1");
  const claim = (await post("/v1/hypervisor/learning-source-rights-claims", claimBody("drill-claim-1"))).body?.learning_source_rights_claim ?? {};
  const boundary = (await post("/v1/hypervisor/institutional-learning-boundary-profiles", boundaryBody("drill-boundary-1", claim.revision_ref))).body?.institutional_learning_boundary_profile ?? {};
  const affinity = (await post("/v1/hypervisor/automation-affinities", { title: "Drill affinity", goal_pattern: "drill", failure_policy: "stop" })).body?.record ?? {};
  const profile = await post(PROFILES, profileBody("drill-profile-1"));
  const agenda = await post(AGENDAS, agendaBody("drill-agenda-1", affinity.affinity_ref));
  const campaign = await post(CAMPAIGNS, campaignBody("drill-campaign-1", "acme.drill", affinity.affinity_ref, profile.body?.improvement_governance_profile?.revision_ref, agenda.body?.improvement_agenda?.revision_ref, boundary.revision_ref));
  const bound = await post(`${CAMPAIGNS}/acme.drill/role-bindings`, bindingBody("drill-bind-1", { search: [PRINCIPALS.A], judgment: [PRINCIPALS.B], authority: [PRINCIPALS.C] }));
  const b = bound.body?.improvement_role_binding ?? {};
  ok("DRILL D1 — the independent content_hash oracle rejects a binding whose judgment set was changed after admission, and accepts the record as served", campaign.status === 201 && bound.status === 201 && deriveRoleBindingHash({ ...b, bindings: { ...b.bindings, judgment: [PRINCIPALS.A] } }) !== b.content_hash && deriveRoleBindingHash(b) === b.content_hash, `${campaign.status} ${code(campaign.body)} / ${bound.status} ${code(bound.body)}`);
  ok("DRILL D2 — the independence oracle goes red on an overlapping set at independent_review and green on the same set at local_lightweight", deriveIndependence("independent_review", { search: ["user://x"], judgment: ["user://x"], authority: ["user://y"] }) === "role_independence_violated" && deriveIndependence("local_lightweight", { search: ["user://x"], judgment: ["user://x"], authority: ["user://x"] }) === "separately_identifiable");
  ok("DRILL D3 — the promotion-member scan goes red on a planted `rank` nested inside an entry, so the archive's structural absence is a finding and not a blind pattern", promotionMembersIn({ candidates: [{ candidate_ref: "x", evidence: [{ rank: 1 }] }] }).length === 1 && promotionMembersIn({ candidates: [{ candidate_ref: "x" }] }).length === 0);
  const okReply = { status: 201, body: { ok: true } };
  ok("DRILL D4 — the refusal predicate reads a 201 as NOT refused, so a planted mutation that succeeds turns its assertion red rather than passing on a coincidence of shapes", !refused(okReply, 403, "role_separation_violated") && refused({ status: 403, body: { error: { code: "role_separation_violated" } } }, 403, "role_separation_violated"));
}

const finish = async () => {
  await stopDaemon();
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({ verifierId: "improvement-role-separation", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  console.log(`\nimprovement role separation: ${failed.length === 0 ? "PASS" : "FAIL"} (${results.length - failed.length}/${results.length})`);
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
