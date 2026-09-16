#!/usr/bin/env node
// check:learning-lineage-retention — M06.9, against an ISOLATED real daemon.
//
// THE UNIT'S CLAIM is that retention, hold, erasure and residual exposure are DERIVED facts over
// the daemon's own learning lineage, never a rewrite of it: a source-right revocation walks from
// the claim through the view, the data recipe and its transformation run, the Foundry recipe, the
// dataset snapshot, the program, its checkpoints and its qualification, and each affected record
// earns the disposition its family says (fenced, quarantined, rebuild_required, retrain_required,
// recall_required, residual_exposure); the impact is admitted as a LearningImpactRecord whose graph
// root and content hash are re-derived here; a run, a Foundry materialization, a program or a
// qualification over a quarantined input is refused; Foundry's content-addressed blobs are
// retention subjects — held, then destroyed with the fact written estate-wide so a restored copy
// still refuses and the same bytes cannot be re-materialized — while the admitted records and
// receipts survive; and no unlearning claim is admitted without the evidence its kind names.
// Canon: foundations/institutional-learning-boundary.md § Derived Rights, Revocation, And Honest
// Unlearning; security-privacy-policy-invariants.md § DataRetentionDisposition; ACC-16 clause 12.
//
// THE MUTATIONS the manifest names are each driven: restart, backup/restore (a blob copied aside
// before destruction and put back), hold, erasure, stale projection, derived artifact, recall
// impact, false unlearning, de-identified lineage.
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
const IMPACT_DOMAIN = "ioi.learning-impact-record-content-commitment-jcs-sha256.v1";
const GRAPH_DOMAIN = "ioi.learning-impact-graph-root-jcs-sha256.v1";
const IMPACT_MATERIAL = ["schema_version", "learning_impact_record_id", "owner_ref", "trigger", "impact_graph_root", "affected", "residual_exposure", "minimum_audit_commitment_ref", "unlearning_claim", "unlearning_evidence_refs"];
const deriveImpactHash = (r) => digestOver(r, IMPACT_DOMAIN, IMPACT_MATERIAL);
const deriveGraphRoot = (edges) => digestOver({ edges }, GRAPH_DOMAIN, ["edges"]);
/** The disposition each family earns, as canon assigns it — re-derived here, never read back. */
const EXPECTED_DISPOSITION = { policy_bound_data_view: "fenced", transformation_run: "quarantined", foundry_recipe_run: "quarantined", foundry_dataset_snapshot: "rebuild_required", foundry_program: "retrain_required", foundry_checkpoint: "retrain_required", foundry_qualification_proposal: "retrain_required", foundry_artifact_intent: "recall_required" };
/** De-identified lineage: a record carries refs and hashes, never payload. */
const PAYLOAD_MEMBERS = ["rows", "input_rows", "text", "bytes", "material", "content", "token_counts"];
const payloadMembersIn = (value, at = "$") => {
  if (Array.isArray(value)) return value.flatMap((item, i) => payloadMembersIn(item, `${at}[${i}]`));
  if (value && typeof value === "object") return [...Object.keys(value).filter((k) => PAYLOAD_MEMBERS.includes(k)).map((k) => `${at}.${k}`), ...Object.entries(value).flatMap(([k, v]) => payloadMembersIn(v, `${at}.${k}`))];
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
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-learning-lineage-"));
let daemon = null;
let daemonPort = 0;
let DAEMON = "";
let SESSION = "";
let OWNER = "";
let daemonLog = "";
async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1", IOI_WALLET_SECRET_PASS: "ioi-learning-lineage-verifier" },
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
const get = (p) => jd(p);
const code = (body) => body?.code ?? body?.error?.code ?? (typeof body?.error === "string" ? body.error : "") ?? "";
const message = (body) => body?.error?.message ?? body?.message ?? "";
const enc = (v) => encodeURIComponent(v);
const stripIndex = (value) => JSON.stringify(value, (key, v) => (key === "index_state" || key === "at" || key === "rebuilt_from" || key === "updated_at" ? undefined : v));
const refused = (reply, status, expected) => reply.status === status && code(reply.body) === expected;

// ---------------------------------------------------------------------------- the routes
const IMPACT = "/v1/hypervisor/learning-impact-records";
const WALK = "/v1/hypervisor/learning-lineage/impact";
const RETENTION = "/v1/hypervisor/retention/dispositions";
const TRUNS = "/v1/hypervisor/transformation-runs";
const FOUNDRY = "/v1/hypervisor/foundry";
const TENANT = "tenant://org.local";
const POLICY = `sha256:${"77".repeat(32)}`;
const CONSENT_REF = "grant://acme-clinic/intake-consent/v3";
const T_ADMIT = "2026-09-01T08:00:00Z";

// ------------------------------------------------------ M05.8 / M10.3 seeds (from the M10.4 gate)
const claimBody = (key, over = {}) => ({
  owner_ref: OWNER, idempotency_key: key, family: "acme.intake-records", effective_at: "2026-06-01T09:14:03Z", asserted_by_ref: OWNER, asserted_rights_holder_refs: [OWNER], source_class: "customer",
  subject_refs: ["dataset://acme/intake-rows/v3"], rights_basis_refs: ["contract://acme/customer-msa/v4", CONSENT_REF], declared_prohibited_uses: ["competing_model_training", "publish"], unresolved_rights_findings: [],
  derivative_disposition: "inherit_intersection", beneficiary_scope_refs: [OWNER], jurisdiction_refs: ["jurisdiction://us-ca"], residency_refs: ["region://us-west"],
  retention_policy_ref: "policy://acme/retention/intake/v3", deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2", legal_or_audit_hold_state: "none",
  validity: { valid_from: "2026-06-01T00:00:00Z", valid_until: null }, evidence_refs: ["evidence://acme/msa-countersigned/v4"], claim_commitment: `sha256:${"aa".repeat(32)}`, status: "admitted", ...over,
});
async function seed() {
  const ontology = (await post("/v1/hypervisor/ontology-versions", { owner_ref: OWNER, idempotency_key: "llr-ontology", namespace: "acme-clinic", name: "patient-intake", governing_scope_ref: "domain://acme-clinic/intake", policy_hash: POLICY, entity_types: [{ term_id: "ontology://acme-clinic/patient-intake/term/patient", label: "patient" }], valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null } })).body?.ontology_version ?? {};
  const ONT = ontology.ontology_id ?? "";
  const liveMap = (await post("/v1/hypervisor/connector-mapping-revisions", { owner_ref: OWNER, idempotency_key: "llr-map-live", family: "acme.intake-form", name: "acme.intake-form", connector_id: "connector://google-drive", ontology_revision_ref: ONT, source_schema_ref: "artifact://acme/intake-form/provider-schema/2026-09", target_object_model_refs: ["object-model://om_patient_intake"], field_mappings: [{ role: "key", source_field: "record_id", target_property_ref: "object-model://om_patient_intake#intake_id", source_type: "string", source_cardinality: "one" }], action_mappings: [], authority_scopes_required: ["scope:connector.google_drive.read"], redaction_policy_ref: "policy://acme-clinic/intake-redaction", evidence_required: ["evidence-contract://acme-clinic/intake-consent"], effective_policy_hash: POLICY, registry_status: "active" })).body?.connector_mapping ?? {};
  const route = (await post("/v1/hypervisor/model-route-rights-contracts", { owner_ref: OWNER, idempotency_key: "llr-route", family: "acme.primary-inference", effective_at: "2026-05-01T10:00:00Z", route_binding: { route_ref: "route://acme-clinic/primary-inference", provider_ref: "provider://acme-clinic/external-inference-a", model_ref: "model://external-inference-a/general", model_revision_ref: "model://external-inference-a/general/revision/11", intermediary_ref: null, upstream_terms_ref: null, intermediary_is_supply_adapter_not_trust_boundary: true }, purposes: ["inference_service_delivery"], data_classes: ["prompts_and_completions"], declared_prohibited_route_uses: ["publication", "downstream_use", "oem_or_reseller_use"], unresolved_rights_findings: [], destination_and_egress: { permitted_destination_classes: ["model_provider"], egress_ceiling: "redacted_only", region_refs: ["region://us-west"], residency_refs: ["region://us-west"], cross_border_transfer_basis_ref: null }, customer_output_rights: { intended_customer_output_uses: ["retain", "internal_evaluation"], effective_customer_output_rights_hash: `sha256:${"44".repeat(32)}`, competing_model_training_permitted: false }, provider_use_of_customer_material: { request_or_prompt_logging: "prohibited", human_review: "prohibited", abuse_and_security_processing: "transient_only", service_improvement: "prohibited", provider_model_training: "prohibited", provider_model_training_basis_ref: null, cross_customer_aggregation: "prohibited", cross_customer_aggregation_basis_ref: null, publication: "prohibited" }, retention_posture: "zero_retention", retention_policy_ref: "policy://acme/retention/route/v1", commercial_terms_refs: ["contract://acme/provider-a-order-form/v3"], technical_terms_refs: ["terms://acme/provider-a/v7"], fallback_substitution: { fallback_is_semantic_substitution: true, fallback_route_rights_revision_ref: null }, validity: { valid_from: "2026-05-01T00:00:00Z", valid_until: "2027-05-01T00:00:00Z" }, revocation: { revocation_state: "live", revoked_at: null, revocation_reason: null, revocation_authority_ref: null }, status: "active", resolved_principal_ref: "worker://acme-clinic/intake-assistant", credential_principal_ref: "service://acme-clinic/inference-credential-a" })).body?.model_route_rights_contract ?? {};
  const claimReply = await post("/v1/hypervisor/learning-source-rights-claims", claimBody("llr-claim-live", { route_rights_contract_refs: [route.revision_ref] }));
  const claim = claimReply.body?.learning_source_rights_claim ?? {};
  const claimHead = claimReply.body?.expected_head_for_successor;
  // a SECOND claim that is never revoked, so a "clean" Foundry recipe can bind a live right after the first is revoked
  const cleanClaim = (await post("/v1/hypervisor/learning-source-rights-claims", claimBody("llr-claim-clean", { family: "acme.intake-records-clean", subject_refs: ["dataset://acme/intake-rows-clean/v1"] }))).body?.learning_source_rights_claim ?? {};
  const profile = (await post("/v1/hypervisor/institutional-learning-boundary-profiles", { owner_ref: OWNER, idempotency_key: "llr-profile-live", family: "acme.organization-default", effective_at: "2026-06-01T09:20:11Z", scope_level: "organization", applies_to_refs: [OWNER], protected_material_classes: ["source_data"], custody: { product_mode: "private", runtime_operator: "customer_managed", permitted_provider_trust_postures: ["no_provider_plaintext", "redacted_only"], permitted_custody_postures: ["customer_boundary"], private_claim_requires_current_proof: true }, external_recipient_permissions: { transient_inference: "allow", service_logging: "policy_qualified", abuse_or_security_review: "policy_qualified", human_support_review: "deny", retention: "deny", service_improvement: "deny", provider_model_training: "deny", provider_model_training_basis_ref: null, cross_customer_aggregation: "deny", cross_customer_aggregation_basis_ref: null, publication: "deny" }, cross_tenant_learning: { default: "deny", permitted_cohort_refs: [], aggregation_policy_ref: null, contribution_and_benefit_terms_ref: null, non_reconstruction_control_refs: [] }, bound_target_refs: ["worker://acme-clinic/intake-assistant"], jurisdiction_refs: ["jurisdiction://us-ca"], residency_refs: ["region://us-west"], retention_policy_ref: "policy://acme/retention/intake/v3", deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2", derivative_policy_ref: "policy://acme/derivative/v1", export_policy_ref: "policy://acme/export/v1", revocation_policy_ref: "policy://acme/revocation/v1", declassification_policy_ref: "policy://acme/declassification/v1", learning_source_rights_claim_revision_refs: [claim.revision_ref], route_rights_contract_refs: [route.revision_ref], status: "active", expires_at: null })).body?.institutional_learning_boundary_profile ?? {};
  const recipe = (await post("/v1/hypervisor/data-recipe-revisions", { owner_ref: OWNER, idempotency_key: "llr-recipe", family: "acme.intake-redact", name: "intake-redact", ontology_revision_refs: [ONT], input_source_types: ["connector"], connector_mapping_revision_refs: [liveMap.revision_ref], output_object_model_refs: ["object-model://om_patient_intake"], output_dataset_contract_refs: ["schema://acme-clinic/patient-intake-row/v2"], transformation_steps: ["extract", "redact", "normalize"], policy_bound_data_view_refs: [], receipt_obligations: ["data_recipe_run", "transformation"], effective_policy_hash: POLICY, registry_status: "active" })).body?.data_recipe ?? {};
  const approval = (await post("/v1/hypervisor/governance/approval-requests", { subject_ref: "authority-action://acme-clinic/intake-purpose", request_kind: "purpose_binding", reason: "verifier fixture: the Governance decision that bound this view's purpose" })).body?.approval_request ?? {};
  const runBody = (key) => ({ owner_ref: OWNER, idempotency_key: key, data_recipe_revision_ref: recipe.revision_ref, output_intent: "ontology_objects", execution_status: "completed", input_refs: ["artifact://acme/intake-forms/batch-2026-08"], authority_grant_refs: ["grant://acme-clinic/intake-read/2026-08"], output_object_refs: ["agentgres://object/patient_intake/2026-08-batch"], receipt_refs: ["receipt://acme-clinic/transformation/2026-08-batch"], derivative_policy_ref: "policy://acme-clinic/intake-derivatives", impact_graph_ref: "agentgres://projection/intake-impact" });
  const completedReply = await post(TRUNS, runBody("llr-run-completed"));
  const completedRun = completedReply.body?.transformation_run ?? {};
  const row = (ref, hash, cls) => ({ source_ref: ref, source_revision_ref: ref, source_content_hash: hash, source_tenant_ref: TENANT, source_owner_ref: OWNER, source_class: cls });
  const sourceRows = [row(ONT, ontology.content_hash ?? "", "machine_generated"), row(liveMap.revision_ref, liveMap.content_hash, "customer"), row(completedRun.transformation_run_id, completedRun.content_hash, "machine_generated")];
  const view = (await post("/v1/hypervisor/policy-bound-data-views", { owner_ref: OWNER, idempotency_key: "llr-view-1", family: "acme.intake-minimised", effective_at: T_ADMIT, purpose: "evaluation", source_bindings: sourceRows, object_model_refs: ["object-model://om_patient_intake"], row_scope: { row_predicate_ref: "predicate://acme/intake/consented-and-in-window", row_predicate_hash: `sha256:${"aa".repeat(32)}`, max_row_count: 50000 }, allowed_field_refs: ["field://acme/intake/intake_id", "field://acme/intake/visit_date"], field_minimization_decisions: [{ field_ref: "field://acme/intake/intake_id", source_ref: sourceRows[0].source_ref, necessity_basis: "required_by_join_key", data_class: "quasi_identifier" }, { field_ref: "field://acme/intake/visit_date", source_ref: sourceRows[0].source_ref, necessity_basis: "required_by_purpose", data_class: "operational_metadata" }], time_scope: { timebase: "source_event_time", from: "2026-01-01T00:00:00Z", until: "2026-09-01T00:00:00Z" }, data_classes: ["source_data"], privacy_class: "restricted", consent_bindings: [{ consent_ref: CONSENT_REF, consent_state: "active", consent_subject_ref: OWNER, valid_until: "2027-06-01T00:00:00Z" }], jurisdiction_refs: ["jurisdiction://us-ca"], residency_refs: ["region://us-west"], retention_and_hold: { retention_policy_ref: "policy://acme/retention/intake/v3", retention_state: "within_retention", hold_state: "none", expires_at: "2027-01-01T00:00:00Z", deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2" }, destination_and_egress: { permitted_destination_classes: ["in_boundary_only", "model_provider"], egress_ceiling: "redacted_only", permitted_region_refs: ["region://us-west"], cross_tenant_read_permitted: false, declassification_permitted_without_approval: false }, purpose_binding_ref: approval.ref, ontology_revision_refs: [ONT], connector_mapping_revision_refs: [liveMap.revision_ref], source_rights_claim_revision_refs: [claim.revision_ref], route_rights_revision_refs: [route.revision_ref], boundary_profile_revision_ref: profile.revision_ref, redaction: { recipe_revision_ref: recipe.revision_ref, recipe_content_hash: recipe.content_hash, techniques: ["field_suppression", "generalization"], findings: [], output_privacy_class: "restricted", creates_permission: false, severs_lineage: false, reidentification_risk_assessed: true } })).body?.policy_bound_data_view ?? {};
  // a SECOND data recipe bound to the view, so the view → recipe → run edge is real
  const viewRecipe = (await post("/v1/hypervisor/data-recipe-revisions", { owner_ref: OWNER, idempotency_key: "llr-recipe-view", family: "acme.intake-train", name: "intake-train", ontology_revision_refs: [ONT], input_source_types: ["connector"], connector_mapping_revision_refs: [liveMap.revision_ref], output_object_model_refs: ["object-model://om_patient_intake"], output_dataset_contract_refs: ["schema://acme-clinic/patient-intake-row/v2"], transformation_steps: ["extract", "normalize"], policy_bound_data_view_refs: [view.revision_ref], receipt_obligations: ["data_recipe_run", "transformation"], effective_policy_hash: POLICY, registry_status: "active" })).body?.data_recipe ?? {};
  const viewRunReply = await post(TRUNS, { ...runBody("llr-run-view"), data_recipe_revision_ref: viewRecipe.revision_ref, input_refs: ["artifact://acme/intake-forms/batch-2026-09"] });
  return { ONT, liveMap, route, claim, claimHead, cleanClaim, profile, recipe, viewRecipe, view, completedRun, completedRunHead: completedReply.body?.expected_head_for_successor, viewRun: viewRunReply.body?.transformation_run ?? {}, viewRunHead: viewRunReply.body?.expected_head_for_successor, viewRunStatus: `${viewRunReply.status} ${code(viewRunReply.body)}`, runBody };
}

// ------------------------------------------------------------------------- Foundry (from the smoke)
const RECIPE_ID = "foundry-recipe://acme/intake-tokens";
const recipeBody = (seeds, key, over = {}) => ({
  recipe_id: RECIPE_ID, owner_ref: OWNER, predecessor_recipe_ref: null, expected_head: null, data_recipe_ref: seeds.viewRecipe.revision_ref, source_snapshot_refs: ["source-snapshot://acme/intake-rows/v3"],
  institutional_learning_boundary_ref: seeds.profile.revision_ref, learning_source_rights_claim_refs: [seeds.claim.revision_ref],
  tokenizer_ref: "tokenizer://acme/whitespace-v1", sequence_format_ref: "format://acme/json-row-v1", packing_policy_ref: "policy://acme/no-packing", loss_mask_policy_ref: "policy://acme/full-row-loss",
  harness_variant_refs: ["harness-variant://acme/reference"], environment_profile_ref: "environment-profile://acme/local-reference",
  operators: [{ kind: "normalize_whitespace", field: "text" }, { kind: "filter_nonempty", field: "text" }, { kind: "select_fields", fields: ["text", "source"] }, { kind: "deduplicate", fields: ["text", "source"] }],
  split_seed: 17, idempotency_key: key, ...over,
});
const ROWS = [{ text: "  alpha   beta  ", source: "fixture-a" }, { text: "alpha beta", source: "fixture-a" }, { text: "gamma delta", source: "fixture-b" }];
const runFoundry = (recipe, key, rows = ROWS) => post(`${FOUNDRY}/recipes/${enc(recipe.recipe_id)}/runs`, { expected_recipe_head: recipe.agentgres.head, expected_recipe_content_hash: recipe.content_hash, rights_grant_refs: ["rights-grant://acme/training-v1"], input_rows: rows, splits: { train: 10_000, validation: 0, test: 0 }, idempotency_key: key });
const programBody = (programId, snapshot, recipe, key, seed = 23) => ({ program_id: programId, owner_ref: OWNER, foundry_spec_ref: null, dataset_snapshot_ref: snapshot.dataset_snapshot_ref, expected_recipe_content_hash: recipe.content_hash, training_mode: "sft", trainer_backend_profile_ref: "trainer-backend://ioi/reference-token-frequency/v1", text_field: "text", checkpoint_every_rows: 2, seed, authority_grant_refs: ["grant://acme/foundry-run"], rights_grant_refs: ["rights-grant://acme/training-v1"], idempotency_key: key });
async function trainProgram(programId, snapshot, recipe, key) {
  const created = await post(`${FOUNDRY}/programs`, programBody(programId, snapshot, recipe, `${key}-create`));
  const started = await post(`${FOUNDRY}/programs/${enc(programId)}/start`, { expected_head: created.body?.program?.agentgres?.head, idempotency_key: `${key}-start` });
  const stepped = await post(`${FOUNDRY}/programs/${enc(programId)}/step`, { expected_head: started.body?.program?.agentgres?.head, idempotency_key: `${key}-step`, max_rows: 10 });
  return { created, started, stepped, program: stepped.body?.program ?? {} };
}
const blobPath = (family, hash) => path.join(dataDir, family, `${String(hash).replace(/^sha256:/u, "")}.json`);

// ------------------------------------------------------------------------------------ run
async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "learning-lineage-v1", email: "learning-lineage@ioi.local" }) }, { authenticated: false });
    SESSION = boot.body?.session_token || boot.body?.session?.token || "";
  }
  const who = (await get("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  ok("operator bootstrap yields an authenticated session with an owner tenant", SESSION.startsWith("ioi_sess_") && !!OWNER, OWNER || "no owner tenant");

  const seeds = await seed();
  ok("PRECONDITION: the governed source and its lineage are REAL admitted revisions across three owner planes — a source-rights claim and boundary profile (M10.3), an ontology, a mapping, two data recipes and two transformation runs (M05.1/M05.7), a route-rights contract (M07.2) and a policy-bound data view bound to the claim (M05.8)", seeds.claim.revision_ref === "learning-source-rights://acme.intake-records/revision/1" && seeds.view.revision_ref === "view://acme.intake-minimised/revision/1" && seeds.viewRecipe.revision_ref === "data-recipe://acme.intake-train/revision/1" && String(seeds.viewRun.transformation_run_id || "").startsWith("transform://") , `claim=${seeds.claim.revision_ref} view=${seeds.view.revision_ref} viewRun=${seeds.viewRunStatus}`);

  const recipeReply = await post(`${FOUNDRY}/recipes`, recipeBody(seeds, "llr-foundry-recipe-1"));
  const recipe = recipeReply.body?.recipe ?? {};
  ok("PRECONDITION: a Foundry recipe revision binds the view's data recipe, the claim revision and the boundary revision — the lineage hooks the walker follows", recipeReply.status === 201 && recipe.revision === 1 && recipe.data_recipe_ref === seeds.viewRecipe.revision_ref, `${recipeReply.status} ${code(recipeReply.body)} ${message(recipeReply.body).slice(0, 120)}`);
  const snapshotReply = await runFoundry(recipe, "llr-foundry-run-1");
  const snapshot = snapshotReply.body?.dataset_snapshot ?? {};
  ok("PRECONDITION: the recipe run materializes a content-addressed dataset snapshot whose bytes exist in daemon custody", snapshotReply.status === 201 && snapshot.status === "materialized" && fs.existsSync(blobPath("foundry-dataset-artifacts", snapshot.content_hash)), `${snapshotReply.status} ${code(snapshotReply.body)} ${snapshot.dataset_snapshot_ref}`);
  const PROGRAM_1 = "trainpipe://acme/intake-tokens-1";
  const PROGRAM_2 = "trainpipe://acme/intake-tokens-2";
  const p1 = await trainProgram(PROGRAM_1, snapshot, recipe, "llr-program-1");
  const p2 = await trainProgram(PROGRAM_2, snapshot, recipe, "llr-program-2");
  const ckpt1 = p1.program.current_checkpoint ?? {};
  const ckpt2 = p2.program.current_checkpoint ?? {};
  ok("PRECONDITION: two programs train on the snapshot (same rows, same seed) and checkpoint to DIFFERENT bytes — a checkpoint's bytes commit to its program, and a snapshot's ref IS its content hash — so on this basis no two Foundry records share one blob and custody of a blob is exactly one record's", p1.stepped.status === 200 && p2.stepped.status === 200 && p1.program.status === "completed" && p2.program.status === "completed" && ckpt1.artifact_hash !== ckpt2.artifact_hash && ckpt1.checkpoint_ref !== ckpt2.checkpoint_ref && snapshot.dataset_snapshot_ref === `dataset-snapshot://foundry/${String(snapshot.content_hash).replace(/^sha256:/u, "")}` && fs.existsSync(blobPath("foundry-checkpoint-artifacts", ckpt1.artifact_hash)) && fs.existsSync(blobPath("foundry-checkpoint-artifacts", ckpt2.artifact_hash)), `${p1.stepped.status} ${code(p1.stepped.body)} / ${p2.stepped.status} ${code(p2.stepped.body)} ${ckpt1.checkpoint_ref} ${ckpt2.checkpoint_ref}`);
  const verify1 = await post(`${FOUNDRY}/checkpoints/${enc(ckpt1.artifact_hash)}/verify-restore`, { expected_program_head: p1.program.agentgres?.head, idempotency_key: "llr-verify-1" });
  const qualified = await post(`${FOUNDRY}/programs/${enc(PROGRAM_1)}/qualify`, { expected_head: verify1.body?.program?.agentgres?.head, idempotency_key: "llr-qualify-1", evaluation_rows: [{ text: "alpha beta" }, { text: "gamma delta" }], quality_gate: { minimum_token_coverage: 0, maximum_mean_negative_log_likelihood: 100 }, workload_fingerprint: { runtime_node_ref: "runtime://acme/local-node", environment_ref: "environment://acme/local-reference", trainer_backend_profile_ref: "trainer-backend://ioi/reference-token-frequency/v1", hardware_architecture: "x86_64", logical_cpu_count: 4, memory_bytes: 8_589_934_592, operating_system: "linux", daemon_release_ref: "release://ioi/hypervisor-daemon/dev" }, cost_basis_ref: "cost://acme/local-reference", failure_schedule_ref: "schedule://acme/no-faults" });
  ok("PRECONDITION: program 1's checkpoint verifies from custody and the program is qualified (proposal-only)", verify1.status === 200 && verify1.body?.verification?.verified === true && qualified.status === 200 && qualified.body?.qualification?.promotion_boundary?.proposal_only === true, `${verify1.status} ${code(verify1.body)} / ${qualified.status} ${code(qualified.body)}`);
  const intents = (await get(`${FOUNDRY}/artifact-intents`)).body?.artifact_intents ?? [];
  ok("PRECONDITION: the materializations recorded artifact intents naming the blobs", intents.length >= 2 && intents.some((i) => String(i.artifact_hash).replace(/^sha256:/u, "") === String(ckpt1.artifact_hash).replace(/^sha256:/u, "")), `${intents.length} intents`);

  // -- the walker refuses to invent an invalidation ------------------------------------------------
  const notInvalid = await get(`${WALK}?trigger_kind=source_right_revoked&subject_ref=${enc(seeds.claim.revision_ref)}`);
  ok("[trigger resolved] the walker over a claim that is still ADMITTED refuses impact_trigger_not_invalid — an impact follows an invalidation the owner admitted, it never causes one", refused(notInvalid, 409, "impact_trigger_not_invalid"), `${notInvalid.status} ${code(notInvalid.body)}`);
  const unsupported = await get(`${WALK}?trigger_kind=consent_withdrawn&subject_ref=${enc(CONSENT_REF)}`);
  ok("[typed frontier] a trigger this basis holds no owner record for (consent withdrawal) is refused impact_trigger_unsupported naming the owner, never walked from a guess", refused(unsupported, 422, "impact_trigger_unsupported"), `${unsupported.status} ${code(unsupported.body)}`);
  const badKind = await get(`${WALK}?trigger_kind=vibes&subject_ref=x`);
  ok("a trigger kind outside canon's vocabulary is refused", refused(badKind, 422, "learning_impact_record_trigger_kind_outside_vocabulary"), `${badKind.status} ${code(badKind.body)}`);
  const liveRoute = await get(`${WALK}?trigger_kind=route_contract_revoked&subject_ref=${enc(seeds.route.revision_ref)}`);
  ok("[trigger resolved] a LIVE route-rights contract cannot be an impact trigger either", refused(liveRoute, 409, "impact_trigger_not_invalid"), `${liveRoute.status} ${code(liveRoute.body)}`);

  // -- the invalidation: the claim is REVOKED through its own plane ---------------------------------
  const revoke = await post("/v1/hypervisor/learning-source-rights-claims", claimBody("llr-claim-revoke", { expected_head: seeds.claimHead, status: "revoked", route_rights_contract_refs: [seeds.route.revision_ref] }));
  const revoked = revoke.body?.learning_source_rights_claim ?? {};
  ok("the source right is REVOKED through M10.3's own plane as a successor revision of the claim family", revoke.status === 201 && revoked.status === "revoked" && String(revoked.revision_ref).endsWith("/revision/2") && String(revoked.revision_ref).startsWith(`${seeds.claim.source_rights_claim_id}/`), `${revoke.status} ${code(revoke.body)} ${revoked.revision_ref} status=${revoked.status}`);
  const REVOKED_REF = revoked.revision_ref;

  // -- the walk ---------------------------------------------------------------------------------------
  const walkReply = await get(`${WALK}?trigger_kind=source_right_revoked&subject_ref=${enc(REVOKED_REF)}`);
  const walked = walkReply.body ?? {};
  const byRef = Object.fromEntries((walked.affected || []).map((a) => [a.ref, a]));
  const has = (ref, family) => byRef[ref] && byRef[ref].family === family && byRef[ref].disposition === EXPECTED_DISPOSITION[family];
  ok("[impact graph] the walk from the revoked claim reaches the VIEW (fenced), the view's data recipe and its transformation run (quarantined), the Foundry recipe (quarantined), the dataset snapshot (rebuild_required), both programs and their checkpoints (retrain_required) — each disposition re-derived here from the family, not read back", walkReply.status === 200 && has(seeds.view.revision_ref, "policy_bound_data_view") && has(seeds.viewRecipe.revision_ref, "transformation_run") && has(seeds.viewRun.transformation_run_id, "transformation_run") && has(recipe.recipe_revision_ref, "foundry_recipe_run") && has(snapshot.dataset_snapshot_ref, "foundry_dataset_snapshot") && has(PROGRAM_1, "foundry_program") && has(PROGRAM_2, "foundry_program") && has(ckpt1.checkpoint_ref, "foundry_checkpoint") && has(ckpt2.checkpoint_ref, "foundry_checkpoint"), `${walkReply.status} ${code(walkReply.body)} affected=${(walked.affected || []).length} ${JSON.stringify((walked.affected || []).map((a) => `${a.family}:${a.disposition}`))}`);
  ok("[impact graph] the graph root RE-DERIVES here over the walked edges under canon's domain separator, every edge lands on an affected record, and the frontier names what this basis cannot see past (models, workers, packages, releases, exports)", walked.impact_graph_root === deriveGraphRoot(walked.edges || []) && (walked.edges || []).every((e) => byRef[e.to]) && (walked.frontier || []).some((f) => /models, workers, packages/u.test(f)), `${String(walked.impact_graph_root).slice(0, 20)} vs ${deriveGraphRoot(walked.edges || []).slice(0, 20)}`);
  ok("[derived artifact] the checkpoint's disposition is retrain_required and its bytes are UNTOUCHED by the walk: the record says what the invalidation means, deletion is a separate governed act", byRef[ckpt1.checkpoint_ref]?.disposition === "retrain_required" && fs.existsSync(blobPath("foundry-checkpoint-artifacts", ckpt1.artifact_hash)));
  ok("[de-identified lineage] the walk carries refs and hashes only — no rows, text, bytes or token counts anywhere in the projection", payloadMembersIn(walked).length === 0, payloadMembersIn(walked).join(",") || "none");

  // -- the record: refusals, then the admission ---------------------------------------------------
  const recordBody = (key, family, over = {}) => ({ owner_ref: OWNER, idempotency_key: key, family, trigger: { kind: "source_right_revoked", subject_ref: REVOKED_REF, decision_ref: "decision://acme/rights/intake-records/revoke/1" }, minimum_audit_commitment_ref: "policy://acme/retention/intake/v3", unlearning_claim: "none", unlearning_evidence_refs: [], ...over });
  const unknownField = await post(IMPACT, recordBody("llr-impact-unknown", "acme.impact-unknown", { fitness: 1 }));
  ok("a member the route does not read is refused rather than dropped", refused(unknownField, 400, "learning_impact_record_request_unknown_field"), `${unknownField.status} ${code(unknownField.body)}`);
  const authoredAffected = await post(IMPACT, recordBody("llr-impact-authored", "acme.impact-authored", { affected: [] }));
  ok("the affected list is DERIVED: authoring it is refused by name", refused(authoredAffected, 422, "learning_impact_record_caller_authored_evidence_refused"), `${authoredAffected.status} ${code(authoredAffected.body)}`);
  const authoredRevision = await post(IMPACT, recordBody("llr-impact-authoredrev", "acme.impact-authoredrev", { trigger: { kind: "source_right_revoked", subject_ref: REVOKED_REF, subject_revision_ref: REVOKED_REF, decision_ref: "decision://acme/x" } }));
  ok("the trigger's revision is resolved through its owner: authoring it is refused by name", refused(authoredRevision, 422, "learning_impact_record_caller_authored_evidence_refused"), `${authoredRevision.status} ${code(authoredRevision.body)}`);
  const noDecision = await post(IMPACT, recordBody("llr-impact-nodecision", "acme.impact-nodecision", { trigger: { kind: "source_right_revoked", subject_ref: REVOKED_REF, decision_ref: "someone decided" } }));
  ok("the trigger names the decision:// that invalidated the subject", refused(noDecision, 422, "learning_impact_record_trigger_required"), `${noDecision.status} ${code(noDecision.body)}`);
  const noAudit = await post(IMPACT, recordBody("llr-impact-noaudit", "acme.impact-noaudit", { minimum_audit_commitment_ref: "keep some" }));
  ok("a minimum audit commitment is a policy:// — deletion removes content, never the evidence that content existed", refused(noAudit, 422, "learning_impact_record_audit_commitment_required"), `${noAudit.status} ${code(noAudit.body)}`);
  const stillLive = await post(IMPACT, recordBody("llr-impact-live", "acme.impact-live", { trigger: { kind: "route_contract_revoked", subject_ref: seeds.route.revision_ref, decision_ref: "decision://acme/x" } }));
  ok("[trigger resolved] a record over a subject that is NOT invalid is refused impact_trigger_not_invalid — and, refused before any scope is bound, squats no family name", refused(stillLive, 409, "impact_trigger_not_invalid"), `${stillLive.status} ${code(stillLive.body)}`);
  const unsupportedRecord = await post(IMPACT, recordBody("llr-impact-consent", "acme.impact-consent", { trigger: { kind: "label_corrected", subject_ref: "episode://acme/1", decision_ref: "decision://acme/x" } }));
  ok("[typed frontier] a label correction has no owner record on this basis and is refused impact_trigger_unsupported (M05.9)", refused(unsupportedRecord, 422, "impact_trigger_unsupported"), `${unsupportedRecord.status} ${code(unsupportedRecord.body)}`);
  const falseNoEvidence = await post(IMPACT, recordBody("llr-impact-false-1", "acme.impact-false-1", { unlearning_claim: "verified_unlearning" }));
  ok("[false unlearning] a verified_unlearning claim with NO evidence is refused false_unlearning_claim before the registered invariant would", refused(falseNoEvidence, 422, "false_unlearning_claim"), `${falseNoEvidence.status} ${code(falseNoEvidence.body)}`);
  const falseGhostResult = await post(IMPACT, recordBody("llr-impact-false-2", "acme.impact-false-2", { unlearning_claim: "verified_unlearning", unlearning_evidence_refs: ["evaluation-result://acme.nowhere"] }));
  ok("[false unlearning] a verified_unlearning claim naming a result the evaluation plane never admitted is refused", refused(falseGhostResult, 422, "false_unlearning_claim"), `${falseGhostResult.status} ${code(falseGhostResult.body)}`);
  const falseDeletion = await post(IMPACT, recordBody("llr-impact-false-3", "acme.impact-false-3", { unlearning_claim: "deletion", unlearning_evidence_refs: ["retention-disposition://rdsp_nope"] }));
  ok("[false unlearning] a deletion claim naming a disposition that never executed is refused", refused(falseDeletion, 422, "false_unlearning_claim"), `${falseDeletion.status} ${code(falseDeletion.body)}`);
  const falseRetrain = await post(IMPACT, recordBody("llr-impact-false-4", "acme.impact-false-4", { unlearning_claim: "clean_retraining", unlearning_evidence_refs: [PROGRAM_2] }));
  ok("[false unlearning] a clean_retraining claim naming a program trained on the very snapshot this invalidation affects is refused — retraining over the tainted snapshot is not clean", refused(falseRetrain, 422, "false_unlearning_claim"), `${falseRetrain.status} ${code(falseRetrain.body)}`);
  const falseRemoval = await post(IMPACT, recordBody("llr-impact-false-5", "acme.impact-false-5", { unlearning_claim: "removal_from_future_datasets", unlearning_evidence_refs: [recipe.recipe_revision_ref] }));
  ok("[false unlearning] a removal claim naming a recipe that STILL binds the revoked claim is refused", refused(falseRemoval, 422, "false_unlearning_claim"), `${falseRemoval.status} ${code(falseRemoval.body)}`);
  const badClaim = await post(IMPACT, recordBody("llr-impact-badclaim", "acme.impact-badclaim", { unlearning_claim: "forgot" }));
  ok("an unlearning claim outside canon's vocabulary is refused", refused(badClaim, 422, "learning_impact_record_unlearning_claim_outside_vocabulary"), `${badClaim.status} ${code(badClaim.body)}`);
  const admitted = await post(IMPACT, recordBody("llr-impact-1", "acme.intake-records.revoked-1"));
  const rec = admitted.body?.learning_impact_record ?? {};
  ok("[impact record] the revocation is admitted as a registered LearningImpactRecord: the trigger's revision RESOLVED, the affected set and graph root IDENTICAL to the walk, residual exposure listed, the claim `none`, and content_hash re-derived here", admitted.status === 201 && rec.trigger?.subject_revision_ref === REVOKED_REF && rec.impact_graph_root === walked.impact_graph_root && JSON.stringify(rec.affected) === JSON.stringify(walked.affected) && rec.unlearning_claim === "none" && rec.content_hash === deriveImpactHash(rec), `${admitted.status} ${code(admitted.body)} ${message(admitted.body).slice(0, 100)}`);
  ok("[de-identified lineage] the admitted record carries no payload member", payloadMembersIn(rec).length === 0, payloadMembersIn(rec).join(",") || "none");
  const replay = await post(IMPACT, recordBody("llr-impact-1", "acme.intake-records.revoked-1"));
  ok("a retried key REPLAYS the record it already admitted", replay.status === 200 && replay.body?.replayed === true, `${replay.status} ${code(replay.body)}`);
  const again = await post(IMPACT, recordBody("llr-impact-1b", "acme.intake-records.revoked-1"));
  ok("a record is admitted once for its token; a later invalidation is a new record over the graph as it then stands", refused(again, 409, "learning_impact_record_already_admitted"), `${again.status} ${code(again.body)}`);
  const inventory = (await get(IMPACT)).body?.learning_impact_records ?? [];
  ok("the inventory lists only the admitted record — the refused attempts squatted nothing", inventory.length === 1 && inventory[0] === "learning-impact://acme.intake-records.revoked-1", JSON.stringify(inventory));

  // -- the fences ------------------------------------------------------------------------------------
  const fencedRun = await post(TRUNS, { ...seeds.runBody("llr-run-fenced"), data_recipe_revision_ref: seeds.viewRecipe.revision_ref, expected_head: seeds.viewRunHead });
  ok("[fence] a transformation run over the quarantined data recipe is refused learning_source_quarantined naming the impact record", refused(fencedRun, 409, "learning_source_quarantined") && /learning-impact:\/\/acme\.intake-records\.revoked-1/u.test(message(fencedRun.body)), `${fencedRun.status} ${code(fencedRun.body)}`);
  const cleanRun = await post(TRUNS, { ...seeds.runBody("llr-run-clean"), expected_head: seeds.completedRunHead });
  ok("[fence] a run over the OTHER data recipe — not bound to the view — still admits: the fence is the graph, not a blanket", cleanRun.status === 201, `${cleanRun.status} ${code(cleanRun.body)}`);
  const fencedFoundryRun = await runFoundry(recipe, "llr-foundry-run-fenced", [{ text: "epsilon zeta", source: "fixture-c" }]);
  ok("[fence] a Foundry materialization over the quarantined recipe is refused", refused(fencedFoundryRun, 409, "learning_source_quarantined"), `${fencedFoundryRun.status} ${code(fencedFoundryRun.body)}`);
  const fencedProgram = await post(`${FOUNDRY}/programs`, programBody("trainpipe://acme/intake-tokens-3", snapshot, recipe, "llr-program-3", 29));
  ok("[fence] a new program over the rebuild_required snapshot is refused", refused(fencedProgram, 409, "learning_source_quarantined"), `${fencedProgram.status} ${code(fencedProgram.body)}`);
  const fencedQualify = await post(`${FOUNDRY}/programs/${enc(PROGRAM_2)}/qualify`, { expected_head: p2.program.agentgres?.head, idempotency_key: "llr-qualify-2", evaluation_rows: [{ text: "alpha beta" }], quality_gate: { minimum_token_coverage: 0, maximum_mean_negative_log_likelihood: 100 }, workload_fingerprint: { runtime_node_ref: "runtime://acme/local-node", environment_ref: "environment://acme/local-reference", trainer_backend_profile_ref: "trainer-backend://ioi/reference-token-frequency/v1", hardware_architecture: "x86_64", logical_cpu_count: 4, memory_bytes: 8_589_934_592, operating_system: "linux", daemon_release_ref: "release://ioi/hypervisor-daemon/dev" }, cost_basis_ref: "cost://acme/local-reference", failure_schedule_ref: "schedule://acme/no-faults" });
  ok("[fence] qualifying the retrain_required program is refused", refused(fencedQualify, 409, "learning_source_quarantined"), `${fencedQualify.status} ${code(fencedQualify.body)}`);

  // -- retention over the content-addressed derived artifacts ---------------------------------------
  const declare = (key, kind, subject) => post(RETENTION, { owner_ref: OWNER, idempotency_key: key, subject_kind: kind, subject_ref: subject, policy_basis_ref: "policy://acme/retention/intake/v3" });
  const ghostKind = await declare("llr-rd-ghostkind", "foundry_embedding", "x");
  ok("[retention owner] a subject kind the owner ruling did not bind is refused, not interpreted", refused(ghostKind, 400, "retention_subject_kind_unsupported"), `${ghostKind.status} ${code(ghostKind.body)}`);
  const programTail = String(ckpt1.checkpoint_ref).split("/")[3];
  const ghostCkpt = await declare("llr-rd-ghostckpt", "foundry_checkpoint_artifact", `checkpoint://foundry/${programTail}/9/${"0".repeat(64)}`);
  const spelledCkpt = await declare("llr-rd-spelledckpt", "foundry_checkpoint_artifact", `checkpoint://foundry/${PROGRAM_1}/9/${"0".repeat(64)}`);
  ok("[retention owner] a checkpoint the program's stream never admitted cannot be a subject (404 at a real program coordinate), and a caller's spelling of the program id in place of the stream coordinate is refused as malformed (400), never resolved by name", refused(ghostCkpt, 404, "foundry_checkpoint_absent") && refused(spelledCkpt, 400, "foundry_checkpoint_ref_invalid"), `${ghostCkpt.status} ${code(ghostCkpt.body)} / ${spelledCkpt.status} ${code(spelledCkpt.body)}`);
  const rdCkpt1 = await declare("llr-rd-ckpt1", "foundry_checkpoint_artifact", ckpt1.checkpoint_ref);
  const d1 = rdCkpt1.body?.disposition ?? {};
  ok("[retention owner] program 1's checkpoint is declared a retention subject with its ARTIFACT HASH as the payload state root — the coordinate the owner served, never the caller's spelling", rdCkpt1.status === 201 && d1.subject?.subject_kind === "foundry_checkpoint_artifact" && d1.subject?.subject_ref === ckpt1.checkpoint_ref && d1.subject?.payload_state_root === ckpt1.artifact_hash && d1.state === "declared", `${rdCkpt1.status} ${code(rdCkpt1.body)} ${message(rdCkpt1.body).slice(0, 80)}`);
  const D1 = d1.disposition_id;
  const d1id = String(D1).replace("retention-disposition://", "");
  const hold = await post(`${RETENTION}/${enc(d1id)}/legal-hold`, { owner_ref: OWNER, idempotency_key: "llr-hold-1", expected_head: d1.admitted_head, hold: true, reason: "litigation hold over the intake corpus" });
  const held = hold.body?.disposition ?? {};
  ok("[hold] a legal hold is an admitted transition with a server-resolved holder", hold.status === 200 && held.legal_hold?.held === true && String(held.legal_hold?.held_by || "").startsWith("user://"), `${hold.status} ${code(hold.body)}`);
  const deleteHeld = await post(`${RETENTION}/${enc(d1id)}/delete`, { owner_ref: OWNER, idempotency_key: "llr-delete-held", expected_head: held.admitted_head });
  ok("[hold] deletion under a legal hold is refused typed, and the bytes stay", deleteHeld.status === 409 && code(deleteHeld.body).startsWith("retention_") && fs.existsSync(blobPath("foundry-checkpoint-artifacts", ckpt1.artifact_hash)), `${deleteHeld.status} ${code(deleteHeld.body)}`);
  const release = await post(`${RETENTION}/${enc(d1id)}/legal-hold`, { owner_ref: OWNER, idempotency_key: "llr-release-1", expected_head: held.admitted_head, hold: false, reason: "hold lifted" });
  const released = release.body?.disposition ?? {};
  // On this basis no two Foundry records share one blob (asserted above), so the shape a second
  // declarant takes is a second DISPOSITION over the same subject; the substrate's shared-custody
  // refusal (retention_subject_shared) guards a custodian the API cannot mint today and is proven by
  // the module's own unit test over a planted second head.
  const rdCkpt1b = await declare("llr-rd-ckpt1b", "foundry_checkpoint_artifact", ckpt1.checkpoint_ref);
  const d1b = rdCkpt1b.body?.disposition ?? {};
  const d1bid = String(d1b.disposition_id).replace("retention-disposition://", "");
  ok("[custody] a second disposition over the SAME checkpoint declares independently, with the same payload state root and its own id — declaring is not destroying, and the bytes stay", rdCkpt1b.status === 201 && d1b.disposition_id !== D1 && d1b.subject?.payload_state_root === ckpt1.artifact_hash && fs.existsSync(blobPath("foundry-checkpoint-artifacts", ckpt1.artifact_hash)), `${rdCkpt1b.status} ${code(rdCkpt1b.body)}`);
  const backupCopy = fs.readFileSync(blobPath("foundry-checkpoint-artifacts", ckpt1.artifact_hash));
  const deleteCkpt1 = await post(`${RETENTION}/${enc(d1id)}/delete`, { owner_ref: OWNER, idempotency_key: "llr-delete-ckpt1", expected_head: released.admitted_head });
  const del1 = deleteCkpt1.body?.disposition ?? {};
  ok("[erasure] with the hold released the delete DESTROYS the blob: state delete_executed, material removed, the tombstone naming the artifact hash and the estate-wide destroyed-content fact, the admitted program stream and its receipts untouched", deleteCkpt1.status === 200 && del1.state === "delete_executed" && del1.deletion?.evidence?.material_removed === true && del1.deletion?.subject_tombstone?.artifact_hash === ckpt1.artifact_hash && typeof del1.deletion?.subject_tombstone?.destroyed_content_fact === "string" && !fs.existsSync(blobPath("foundry-checkpoint-artifacts", ckpt1.artifact_hash)) && (await get(`${FOUNDRY}/programs/${enc(PROGRAM_1)}`)).status === 200, `${deleteCkpt1.status} ${code(deleteCkpt1.body)} ${message(deleteCkpt1.body).slice(0, 120)} ${JSON.stringify(deleteCkpt1.body?.error?.subject_refusal ?? "").slice(0, 200)}`);
  const verifyGone = await post(`${FOUNDRY}/checkpoints/${enc(ckpt1.artifact_hash)}/verify-restore`, { expected_program_head: (await get(`${FOUNDRY}/programs/${enc(PROGRAM_1)}`)).body?.program?.agentgres?.head, idempotency_key: "llr-verify-gone" });
  ok("[erasure] a hash-verified restore of the destroyed checkpoint refuses", verifyGone.status >= 400 && verifyGone.status < 500, `${verifyGone.status} ${code(verifyGone.body)}`);
  fs.mkdirSync(path.dirname(blobPath("foundry-checkpoint-artifacts", ckpt1.artifact_hash)), { recursive: true });
  fs.writeFileSync(blobPath("foundry-checkpoint-artifacts", ckpt1.artifact_hash), backupCopy);
  const verifyResurrected = await post(`${FOUNDRY}/checkpoints/${enc(ckpt1.artifact_hash)}/verify-restore`, { expected_program_head: (await get(`${FOUNDRY}/programs/${enc(PROGRAM_1)}`)).body?.program?.agentgres?.head, idempotency_key: "llr-verify-resurrected" });
  ok("[backup/restore] the blob's bytes put BACK from a copy taken before destruction still refuse — the destroyed-content fact is estate-wide and durable, so no backup resurrects what a disposition destroyed", verifyResurrected.status >= 400 && verifyResurrected.status < 500 && /destroyed/u.test(message(verifyResurrected.body)), `${verifyResurrected.status} ${code(verifyResurrected.body)} ${message(verifyResurrected.body).slice(0, 100)}`);
  fs.rmSync(blobPath("foundry-checkpoint-artifacts", ckpt1.artifact_hash), { force: true });
  const deleteCkpt1b = await post(`${RETENTION}/${enc(d1bid)}/delete`, { owner_ref: OWNER, idempotency_key: "llr-delete-ckpt1b", expected_head: d1b.admitted_head });
  ok("[erasure] the second disposition's delete executes over already-destroyed bytes: material_present_before false, evidence retained, and the destroyed-content fact is ONE fact keyed by the content, not two", deleteCkpt1b.status === 200 && deleteCkpt1b.body?.disposition?.state === "delete_executed" && deleteCkpt1b.body?.disposition?.deletion?.evidence?.material_present_before === false && deleteCkpt1b.body?.disposition?.deletion?.subject_tombstone?.destroyed_content_fact === del1.deletion?.subject_tombstone?.destroyed_content_fact, `${deleteCkpt1b.status} ${code(deleteCkpt1b.body)} ${JSON.stringify(deleteCkpt1b.body?.error?.subject_refusal ?? "").slice(0, 200)}`);
  const rdSnap = await declare("llr-rd-snap", "foundry_dataset_snapshot", snapshot.dataset_snapshot_ref);
  const ds = rdSnap.body?.disposition ?? {};
  const dsid = String(ds.disposition_id).replace("retention-disposition://", "");
  const deleteSnap = await post(`${RETENTION}/${enc(dsid)}/delete`, { owner_ref: OWNER, idempotency_key: "llr-delete-snap", expected_head: ds.admitted_head });
  ok("[erasure] the dataset snapshot's blob is destroyed through the same one delete route", rdSnap.status === 201 && ds.subject?.payload_state_root === snapshot.content_hash && deleteSnap.status === 200 && !fs.existsSync(blobPath("foundry-dataset-artifacts", snapshot.content_hash)), `${rdSnap.status} ${code(rdSnap.body)} / ${deleteSnap.status} ${code(deleteSnap.body)} ${JSON.stringify(deleteSnap.body?.error?.subject_refusal ?? "").slice(0, 200)}`);
  const freshRecipe = (await post(`${FOUNDRY}/recipes`, recipeBody(seeds, "llr-foundry-recipe-2", { recipe_id: "foundry-recipe://acme/intake-tokens-clean", data_recipe_ref: seeds.recipe.revision_ref, learning_source_rights_claim_refs: [seeds.cleanClaim.revision_ref] }))).body?.recipe ?? {};
  const cleanSnapReply = await runFoundry(freshRecipe, "llr-foundry-run-clean", ROWS);
  const cleanSnap = cleanSnapReply.body?.dataset_snapshot ?? {};
  ok("[custody] the SAME rows under a clean (unquarantined) recipe revision materialize DIFFERENT bytes — dataset material commits its recipe revision, so content identity is (recipe revision, rows, seed, splits), never rows alone", cleanSnapReply.status === 201 && !!cleanSnap.content_hash && cleanSnap.content_hash !== snapshot.content_hash && fs.existsSync(blobPath("foundry-dataset-artifacts", cleanSnap.content_hash)), `${cleanSnapReply.status} ${code(cleanSnapReply.body)} ${message(cleanSnapReply.body).slice(0, 100)}`);
  const rdClean = await declare("llr-rd-cleansnap", "foundry_dataset_snapshot", cleanSnap.dataset_snapshot_ref);
  const dc = rdClean.body?.disposition ?? {};
  const deleteClean = await post(`${RETENTION}/${enc(String(dc.disposition_id).replace("retention-disposition://", ""))}/delete`, { owner_ref: OWNER, idempotency_key: "llr-delete-cleansnap", expected_head: dc.admitted_head });
  ok("[erasure] the clean snapshot's blob is destroyed by its own disposition", rdClean.status === 201 && deleteClean.status === 200 && !fs.existsSync(blobPath("foundry-dataset-artifacts", cleanSnap.content_hash)), `${rdClean.status} ${code(rdClean.body)} / ${deleteClean.status} ${code(deleteClean.body)} ${JSON.stringify(deleteClean.body?.error?.subject_refusal ?? "").slice(0, 200)}`);
  const rematerialize = await runFoundry(freshRecipe, "llr-foundry-run-clean-again", ROWS);
  ok("[erasure] re-materializing the SAME bytes (same recipe revision, same rows) under a NEW run key is refused by the destroyed-content fact before any admission — the content, not the coordinate, is what was destroyed", rematerialize.status >= 400 && /destroyed/u.test(message(rematerialize.body)) && !fs.existsSync(blobPath("foundry-dataset-artifacts", cleanSnap.content_hash)), `${rematerialize.status} ${code(rematerialize.body)} ${message(rematerialize.body).slice(0, 120)}`);
  const differentBytes = await runFoundry(freshRecipe, "llr-foundry-run-clean-2", [{ text: "eta theta", source: "fixture-d" }]);
  ok("[erasure] different bytes under the same clean recipe still materialize: the refusal is the hash's, not the recipe's", differentBytes.status === 201, `${differentBytes.status} ${code(differentBytes.body)}`);

  // -- the record over the deletion, with the evidence its claim names ---------------------------------
  const deletionRecord = await post(IMPACT, recordBody("llr-impact-2", "acme.intake-records.deleted-1", { trigger: { kind: "retention_deleted", subject_ref: D1, decision_ref: "decision://acme/retention/intake/delete/1" }, unlearning_claim: "deletion", unlearning_evidence_refs: [D1] }));
  const rec2 = deletionRecord.body?.learning_impact_record ?? {};
  ok("[recall impact] a record over the EXECUTED deletion admits with the `deletion` claim evidenced by the disposition itself; the walk from the checkpoint reaches its artifact intents (recall_required) and names the frontier", deletionRecord.status === 201 && rec2.unlearning_claim === "deletion" && rec2.trigger?.kind === "retention_deleted" && (rec2.affected || []).some((a) => a.family === "foundry_artifact_intent" && a.disposition === "recall_required") && rec2.content_hash === deriveImpactHash(rec2), `${deletionRecord.status} ${code(deletionRecord.body)} ${message(deletionRecord.body).slice(0, 100)} affected=${JSON.stringify((rec2.affected || []).map((a) => a.family))}`);
  const holdRecordNotHeld = await post(IMPACT, recordBody("llr-impact-3", "acme.intake-records.hold-1", { trigger: { kind: "legal_hold_placed", subject_ref: D1, decision_ref: "decision://acme/hold/1" } }));
  ok("[trigger resolved] a legal_hold_placed record over a disposition whose hold was RELEASED is refused: the record follows the admitted act", refused(holdRecordNotHeld, 409, "impact_trigger_not_invalid"), `${holdRecordNotHeld.status} ${code(holdRecordNotHeld.body)}`);

  // -- restart and the stale projection ------------------------------------------------------------------
  const projections = async () => ({
    record: stripIndex((await get(`${IMPACT}/acme.intake-records.revoked-1`)).body),
    record2: stripIndex((await get(`${IMPACT}/acme.intake-records.deleted-1`)).body),
    walk: stripIndex((await get(`${WALK}?trigger_kind=source_right_revoked&subject_ref=${enc(REVOKED_REF)}`)).body),
    disposition: stripIndex((await get(`${RETENTION}/${enc(d1id)}`)).body),
    inventory: stripIndex((await get(IMPACT)).body),
  });
  const before = await projections();
  await stopDaemon();
  fs.rmSync(path.join(dataDir, "retention-dispositions"), { recursive: true, force: true });
  await startDaemon();
  const after = await projections();
  ok("[restart] the impact records, the walk and the inventory reproduce byte for byte across a restart: every one is re-derived from the admitted streams", ["record", "record2", "walk", "inventory"].every((k) => before[k] === after[k]), ["record", "record2", "walk", "inventory"].filter((k) => before[k] !== after[k]).join(",") || "identical");
  ok("[stale projection] with the retention read projection DESTROYED before the restart, the disposition reads back from the durable chain identically — or the daemon says it cannot, typed", before.disposition === after.disposition || (after.disposition.includes("\"ok\":false") && /projection|rebuild|absent/u.test(after.disposition)), before.disposition === after.disposition ? "identical" : after.disposition.slice(0, 160));
  const fenceAfterRestart = await runFoundry(recipe, "llr-foundry-run-fenced-2", [{ text: "iota kappa", source: "fixture-e" }]);
  ok("[restart] the quarantine fence still holds after the restart: it reads admitted records, not a process memory", refused(fenceAfterRestart, 409, "learning_source_quarantined"), `${fenceAfterRestart.status} ${code(fenceAfterRestart.body)}`);

  // -- the plane's vocabulary ------------------------------------------------------------------------------
  const PLANE_CODES = ["impact_trigger_not_invalid", "impact_trigger_unsupported", "false_unlearning_claim", "learning_source_quarantined"];
  const unobserved = PLANE_CODES.filter((c) => !observedCodes.has(c));
  ok("every one of the plane's four API-reachable refusal codes was observed LIVE on this run (retention_subject_shared guards a second custodian the Foundry plane cannot mint — content-addressed snapshot refs, program-bound checkpoint bytes — and is proven by the daemon's unit test, not claimed here)", unobserved.length === 0 && !observedCodes.has("retention_subject_shared"), unobserved.join(",") || "all four observed");
  const module = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/learning_lineage_routes.rs"), "utf8");
  ok("the lineage module offers no verb that retro-edits an admitted revision: its handlers are one walker GET, one record POST and two reads, and it imports nothing from the goal-orchestration application", (module.match(/pub\(crate\) async fn handle_/gu) || []).length === 4 && !/super::(?:goalrun_routes|goal_profile_contract_routes|goal_run_context_routes|outcome_room_routes|ioi_agent_routes)\b/u.test(module));
}

// ---------------------------------------------------------------------------------- drill
async function drill() {
  const edges = [{ from: "a", to: "b" }, { from: "b", to: "c" }];
  ok("DRILL D1 — the graph-root oracle rejects a dropped edge and a reordered edge list, and accepts the list as walked", deriveGraphRoot(edges) !== deriveGraphRoot(edges.slice(0, 1)) && deriveGraphRoot(edges) !== deriveGraphRoot([edges[1], edges[0]]) && deriveGraphRoot(edges) === deriveGraphRoot([...edges]));
  const record = { schema_version: "ioi.learning-impact-record.v1", learning_impact_record_id: "learning-impact://x", owner_ref: "org://local", trigger: { kind: "source_right_revoked", subject_ref: "s", subject_revision_ref: "s/revision/1", decision_ref: "decision://d" }, impact_graph_root: deriveGraphRoot(edges), affected: [{ ref: "b", family: "policy_bound_data_view", edge: "a", disposition: "fenced", basis: "x" }], residual_exposure: [], minimum_audit_commitment_ref: "policy://p", unlearning_claim: "none", unlearning_evidence_refs: [], admitted_at: "2026-09-16T00:00:00Z" };
  record.content_hash = deriveImpactHash(record);
  ok("DRILL D2 — the content-hash oracle rejects a record whose affected list was edited after admission, and accepts the record as served", deriveImpactHash({ ...record, affected: [] }) !== record.content_hash && deriveImpactHash(record) === record.content_hash);
  ok("DRILL D3 — the payload scan goes red on a planted `rows` member nested in an affected entry, so the de-identified-lineage assertion is a finding and not a blind pattern", payloadMembersIn({ affected: [{ ref: "x", rows: [1] }] }).length === 1 && payloadMembersIn(record).length === 0);
  ok("DRILL D4 — the disposition table names a disposition for every family the walker can reach, so a family added without a rule cannot pass", ["policy_bound_data_view", "transformation_run", "foundry_recipe_run", "foundry_dataset_snapshot", "foundry_program", "foundry_checkpoint", "foundry_qualification_proposal", "foundry_artifact_intent"].every((f) => typeof EXPECTED_DISPOSITION[f] === "string"));
  ok("DRILL D5 — the refusal predicate reads a 201 as NOT refused", !refused({ status: 201, body: {} }, 409, "learning_source_quarantined") && refused({ status: 409, body: { error: { code: "learning_source_quarantined" } } }, 409, "learning_source_quarantined"));
}

const finish = async () => {
  await stopDaemon();
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({ verifierId: "learning-lineage-retention", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
  console.log(`\nlearning lineage retention: ${failed.length === 0 ? "PASS" : "FAIL"} (${results.length - failed.length}/${results.length})`);
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
