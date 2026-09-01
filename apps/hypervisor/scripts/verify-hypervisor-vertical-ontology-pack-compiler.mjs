#!/usr/bin/env node
// M05.10 — VerticalOntologyPack and deterministic ontology-to-worker compilation.
//
// This is a LIVE-DAEMON gate. It admits every prerequisite through its owner route, then admits a
// pack and compiles it. It checks exact owner-qualified identity, server-resolved hashes, total
// field coverage, explicit abstention/escalation, nonclaims, replay, immutable succession,
// fail-closed mutation admission, principal isolation, and byte-equivalent replay after a real
// process restart. It uses synthetic labels only and performs no provider or model invocation.

// The M14 WorkerComposition owner seam is not registered at this milestone. The binding therefore
// commits the exact composition ref and the explicit `declared_unresolved_owned_by_m14` nonclaim;
// this gate does not pretend that shape validation is owner resolution.

// Exit: 0 all assertions pass · 1 any assertion fails · 2 daemon build/binary unavailable.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createLane, canonicalJson, code, OWNER } from "./lib/m059-media-lane.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");
const results = [];
const ok = (name, pass, detail = "") => results.push({ name, pass: Boolean(pass), detail });
const sha256 = (value) => `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
const schemaHash = (schema) => sha256(canonicalJson(schema));

const R = Object.freeze({
  OV: "/v1/hypervisor/ontology-versions",
  MAP: "/v1/hypervisor/connector-mapping-revisions",
  OAC: "/v1/hypervisor/ontology-action-contracts",
  ROUTES: "/v1/hypervisor/model-route-rights-contracts",
  CLAIMS: "/v1/hypervisor/learning-source-rights-claims",
  BOUNDARIES: "/v1/hypervisor/institutional-learning-boundary-profiles",
  PACKS: "/v1/hypervisor/vertical-ontology-packs",
  BINDINGS: "/v1/hypervisor/vertical-pack-worker-bindings",
});

const lane = createLane({ root: ROOT, label: "ioi-m0510-vertical" });
const req = lane.req;
const NS = "acme-records";
const ONTOLOGY_NAME = "synthetic-intake";
const ACTION_SLUG = "draft-summary";
const ENTITY = `ontology://${NS}/${ONTOLOGY_NAME}/term/synthetic-record`;
const ACTION = `ontology://${NS}/${ONTOLOGY_NAME}/term/${ACTION_SLUG}`;
const FIELD = "field://acme/synthetic-record/summary";
const POLICY = `sha256:${"71".repeat(32)}`;

function actionContractBody(tool, ontologyRef, overrides = {}) {
  return {
    owner_ref: OWNER,
    idempotency_key: "m0510-action-contract",
    namespace: NS,
    name: ONTOLOGY_NAME,
    action_slug: ACTION_SLUG,
    governing_scope_ref: "domain://acme-records/synthetic",
    policy_hash: POLICY,
    ontology_revision_ref: ontologyRef,
    action_type_ref: ACTION,
    runtime_tool_contract_revision_ref: tool.revision_ref,
    runtime_tool_contract_content_hash: tool.content_hash,
    typed_input_schema_ref: `schema://runtime-tool-contract/input/${schemaHash(tool.input_schema)}`,
    typed_output_schema_ref: `schema://runtime-tool-contract/output/${schemaHash(tool.output_schema)}`,
    target_object_model_refs: ["object-model://om_synthetic_summary"],
    precondition_refs: ["state://acme-records/synthetic/source-present"],
    postcondition_and_invariant_refs: ["invariant://acme-records/synthetic/no-external-effect"],
    expected_state_transition_ref: "transition://acme-records/synthetic/source-to-draft",
    risk_class: "draft",
    effect_recovery_class: "replayable",
    idempotency_and_retry_profile_ref: "policy://acme-records/synthetic/idempotency/v1",
    ambiguous_effect_and_reconciliation_profile_ref: "policy://acme-records/synthetic/reconciliation/v1",
    compensation_profile_ref: null,
    preview_and_dry_run_profile_ref: "policy://acme-records/synthetic/preview/v1",
    approval_and_revocation_refs: ["approval-policy://acme-records/synthetic/draft"],
    local_policy_and_authority_scope_refs: ["policy://acme-records/synthetic/draft"],
    verifier_and_evidence_refs: ["verifier-path://acme-records/synthetic/draft"],
    physical_safety_profile_ref: null,
    receipt_obligations: ["receipt://acme-records/synthetic/action-admission"],
    does_not_assert: ["authority", "capability_grant", "lease", "policy_decision", "effect_admission", "invocation"],
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
    ...overrides,
  };
}

function routeRightsBody() {
  return {
    owner_ref: OWNER,
    idempotency_key: "m0510-route-rights",
    family: "acme.vertical-compiler",
    effective_at: "2026-05-01T10:00:00Z",
    route_binding: {
      route_ref: "route://acme-records/synthetic-inference",
      provider_ref: "provider://synthetic/local-only",
      model_ref: "model://synthetic/rule",
      model_revision_ref: "model://synthetic/rule/revision/1",
      intermediary_ref: null,
      upstream_terms_ref: null,
      intermediary_is_supply_adapter_not_trust_boundary: true,
    },
    purposes: ["inference_service_delivery"],
    data_classes: ["prompts_and_completions"],
    declared_prohibited_route_uses: ["publication", "downstream_use", "oem_or_reseller_use"],
    unresolved_rights_findings: [],
    destination_and_egress: {
      permitted_destination_classes: ["model_provider"],
      egress_ceiling: "redacted_only",
      region_refs: ["region://synthetic/local"],
      residency_refs: ["region://synthetic/local"],
      cross_border_transfer_basis_ref: null,
    },
    customer_output_rights: {
      intended_customer_output_uses: ["retain", "internal_evaluation"],
      effective_customer_output_rights_hash: sha256("m0510-output-rights"),
      competing_model_training_permitted: false,
    },
    provider_use_of_customer_material: {
      request_or_prompt_logging: "prohibited",
      human_review: "prohibited",
      abuse_and_security_processing: "transient_only",
      service_improvement: "prohibited",
      provider_model_training: "prohibited",
      provider_model_training_basis_ref: null,
      cross_customer_aggregation: "prohibited",
      cross_customer_aggregation_basis_ref: null,
      publication: "prohibited",
    },
    retention_posture: "zero_retention",
    retention_policy_ref: "policy://acme-records/synthetic/retention/v1",
    commercial_terms_refs: ["contract://synthetic/local-only/v1"],
    technical_terms_refs: ["terms://synthetic/local-only/v1"],
    fallback_substitution: { fallback_is_semantic_substitution: true, fallback_route_rights_revision_ref: null },
    validity: { valid_from: "2026-05-01T00:00:00Z", valid_until: "2027-05-01T00:00:00Z" },
    revocation: { revocation_state: "live", revoked_at: null, revocation_reason: null, revocation_authority_ref: null },
    status: "active",
    resolved_principal_ref: "worker://acme-records/synthetic-compiler",
    credential_principal_ref: "service://acme-records/synthetic-local",
  };
}

function boundaryBody(claimRef, routeRef) {
  return {
    owner_ref: OWNER,
    idempotency_key: "m0510-boundary",
    family: "acme.vertical-compiler",
    effective_at: "2026-06-01T09:20:11Z",
    scope_level: "organization",
    applies_to_refs: [OWNER],
    protected_material_classes: ["source_data"],
    custody: {
      product_mode: "private",
      runtime_operator: "customer_managed",
      permitted_provider_trust_postures: ["no_provider_plaintext", "redacted_only"],
      permitted_custody_postures: ["customer_boundary"],
      private_claim_requires_current_proof: true,
    },
    external_recipient_permissions: {
      transient_inference: "allow",
      service_logging: "policy_qualified",
      abuse_or_security_review: "policy_qualified",
      human_support_review: "deny",
      retention: "deny",
      service_improvement: "deny",
      provider_model_training: "deny",
      provider_model_training_basis_ref: null,
      cross_customer_aggregation: "deny",
      cross_customer_aggregation_basis_ref: null,
      publication: "deny",
    },
    cross_tenant_learning: {
      default: "deny",
      permitted_cohort_refs: [],
      aggregation_policy_ref: null,
      contribution_and_benefit_terms_ref: null,
      non_reconstruction_control_refs: [],
    },
    bound_target_refs: ["worker://acme-records/synthetic-compiler"],
    jurisdiction_refs: ["jurisdiction://synthetic/acme-sandbox"],
    residency_refs: ["region://synthetic/local"],
    retention_policy_ref: "policy://acme-records/synthetic/retention/v1",
    deletion_or_forget_policy_ref: "policy://acme-records/synthetic/deletion/v1",
    derivative_policy_ref: "policy://acme-records/synthetic/derivative/v1",
    export_policy_ref: "policy://acme-records/synthetic/export/v1",
    revocation_policy_ref: "policy://acme-records/synthetic/revocation/v1",
    declassification_policy_ref: "policy://acme-records/synthetic/declassification/v1",
    learning_source_rights_claim_revision_refs: [claimRef],
    route_rights_contract_refs: [routeRef],
    status: "active",
    expires_at: null,
  };
}

function packBody(actionContractRef, mappingRef, overrides = {}) {
  return {
    owner_ref: OWNER,
    idempotency_key: "m0510-pack-genesis",
    namespace: NS,
    name: "synthetic-sensitive",
    legacy_pack_id: "vertical_pack:acme.synthetic_sensitive.v1",
    display_name: "Synthetic sensitive-record pack",
    base_ontology_revision_ref: `ontology://${NS}/${ONTOLOGY_NAME}/revision/1`,
    declared_object_type_refs: [ENTITY],
    declared_task_classes: [{
      task_class_ref: "task-class://acme-records/synthetic-summary",
      label: "Draft a synthetic summary",
      action_type_refs: [ACTION],
    }],
    declared_action_bindings: [{
      action_type_ref: ACTION,
      risk_class: "draft",
      action_contract_revision_ref: actionContractRef,
      review_mode: "sampled_review",
      required_integration_surface: "browser_saas",
    }],
    declared_integration_requirements: [{
      integration_surface: "browser_saas",
      connector_mapping_revision_ref: mappingRef,
      safety_envelope_required: false,
    }],
    declared_output_fields: [FIELD],
    declared_field_requirements: [{
      output_field_ref: FIELD,
      requirement: "required",
      source_term_ref: ENTITY,
      evidence_requirement_ref: "evidence-contract://acme-records/synthetic/source",
    }],
    declared_evidence_requirements: [{
      evidence_requirement_ref: "evidence-contract://acme-records/synthetic/source",
      applies_to_risk_class: "draft",
      verifier_obligation_ref: "verifier-contract://acme-records/synthetic/source/v1",
    }],
    declared_review_modes: [{ risk_class: "draft", review_mode: "sampled_review" }],
    forbidden_action_refs: ["publication", "provider_action", "live_medical_use"],
    jurisdiction_refs: ["jurisdiction://synthetic/acme-sandbox"],
    registry_status: "active",
    effective_at: "2026-09-01T08:00:00Z",
    ...overrides,
  };
}

function bindingBody(packRef, boundaryRef, routeRef, overrides = {}) {
  return {
    owner_ref: OWNER,
    idempotency_key: "m0510-binding-genesis",
    namespace: NS,
    name: "synthetic-worker",
    vertical_ontology_pack_revision_ref: packRef,
    learning_boundary_profile_revision_ref: boundaryRef,
    model_route_rights_revision_ref: routeRef,
    worker_composition_ref: "composition://acme-records/synthetic-worker/1.0.0/local",
    field_mapping_proposals: [],
    registry_status: "active",
    effective_at: "2026-09-01T08:05:00Z",
    ...overrides,
  };
}

async function family(route, namespace, name, as = "A") {
  return req("GET", `${route}?namespace=${encodeURIComponent(namespace)}&name=${encodeURIComponent(name)}`, null, { as });
}

async function refuseWithoutEffect(name, route, namespace, familyName, body, expectedCode) {
  const before = await family(route, namespace, familyName);
  const response = await req("POST", route, body);
  const after = await family(route, namespace, familyName);
  ok(
    name,
    response.status >= 400 && code(response.j) === expectedCode &&
      canonicalJson(before.j?.revisions ?? []) === canonicalJson(after.j?.revisions ?? []) &&
      (before.j?.head ?? null) === (after.j?.head ?? null),
    `status=${response.status} code=${code(response.j)} revisions=${(before.j?.revisions ?? []).length}->${(after.j?.revisions ?? []).length}`,
  );
  return response;
}

async function run() {
  if (process.env.IOI_M0510_DAEMON_PREBUILT !== "1") lane.rebuildDaemon();
  await lane.start();
  const boot = await lane.bootstrap("m0510-owner-password");
  ok("the isolated daemon bootstraps a real owner session", boot.status === 200 && boot.sessionToken.startsWith("ioi_sess_"), `status=${boot.status}`);

  const created = await req("POST", "/v1/hypervisor/principals", {
    email: "m0510-member@ioi.local", name: "M05.10 member", role: "member", password: "m0510-member-password",
  });
  const principalId = created.j?.principal?.principal_id ?? "";
  await req("POST", `/v1/hypervisor/principals/${principalId}/tenant-memberships`, {
    tenant_ref: OWNER,
    expected_revision: 0,
    idempotency_key: "m0510-member-tenant",
    reason: "M05.10 verifier same-tenant principal-isolation probe",
  });
  const memberLogin = await req("POST", "/v1/hypervisor/auth/login", {
    email: "m0510-member@ioi.local", password: "m0510-member-password",
  }, { as: null });
  lane.sessions.B = memberLogin.j?.session_token ?? "";
  ok("a second real principal shares the tenant for owner-isolation checks", lane.sessions.B.startsWith("ioi_sess_"), `status=${memberLogin.status}`);

  const ontology = await req("POST", R.OV, {
    owner_ref: OWNER,
    idempotency_key: "m0510-ontology",
    namespace: NS,
    name: ONTOLOGY_NAME,
    governing_scope_ref: "domain://acme-records/synthetic",
    policy_hash: POLICY,
    entity_types: [{ term_id: ENTITY, label: "synthetic record" }],
    action_types: [{ term_id: ACTION, label: "draft synthetic summary" }],
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
  });
  const ontologyRecord = ontology.j?.ontology_version ?? {};
  ok("M05.1 admits the exact ontology revision and terms consumed by the pack", ontology.status === 201 && ontologyRecord.ontology_id?.endsWith("/revision/1"), `status=${ontology.status} code=${code(ontology.j)}`);

  const tools = await req("GET", "/v1/tools");
  const tool = (Array.isArray(tools.j) ? tools.j : []).find((row) => row?.registry_status === "released" && row?.revision_ref && row?.content_hash);
  ok("M05.4 resolves a real released RuntimeToolContract from its owner projection", Boolean(tool), `catalog=${Array.isArray(tools.j) ? tools.j.length : 0}`);
  if (!tool) throw new Error("no released RuntimeToolContract is available");

  const actionContract = await req("POST", R.OAC, actionContractBody(tool, ontologyRecord.ontology_id));
  const action = actionContract.j?.ontology_action_contract ?? {};
  ok("M05.4 admits the action contract against the exact ontology and tool revisions", actionContract.status === 201 && action.ontology_revision_ref === ontologyRecord.ontology_id && action.runtime_tool_contract_revision_ref === tool.revision_ref, `status=${actionContract.status} code=${code(actionContract.j)}`);

  const mapping = await req("POST", R.MAP, {
    owner_ref: OWNER,
    idempotency_key: "m0510-connector-mapping",
    family: "acme.synthetic-intake",
    name: "synthetic-intake",
    connector_id: "connector://synthetic-local-fixture",
    ontology_revision_ref: ontologyRecord.ontology_id,
    source_schema_ref: "artifact://synthetic/intake-schema/revision/1",
    target_object_model_refs: ["object-model://om_synthetic_summary"],
    field_mappings: [{ role: "field", source_field: "summary", target_property_ref: "object-model://om_synthetic_summary#summary", source_type: "string", source_cardinality: "one" }],
    action_mappings: [],
    authority_scopes_required: ["scope:synthetic.read"],
    redaction_policy_ref: "policy://acme-records/synthetic/redaction/v1",
    evidence_required: ["evidence-contract://acme-records/synthetic/source"],
    effective_policy_hash: POLICY,
    registry_status: "active",
  });
  const mappingRecord = mapping.j?.connector_mapping ?? {};
  ok("M05.7 admits the connector mapping consumed by pack compilation", mapping.status === 201 && mappingRecord.revision_ref?.endsWith("/revision/1"), `status=${mapping.status} code=${code(mapping.j)} message=${mapping.j?.error?.message ?? ""}`);

  const route = await req("POST", R.ROUTES, routeRightsBody());
  const routeRecord = route.j?.model_route_rights_contract ?? {};
  const claim = await req("POST", R.CLAIMS, {
    owner_ref: OWNER,
    idempotency_key: "m0510-source-rights",
    family: "acme.vertical-compiler",
    effective_at: "2026-06-01T09:14:03Z",
    asserted_by_ref: OWNER,
    asserted_rights_holder_refs: [OWNER],
    source_class: "customer",
    subject_refs: ["dataset://synthetic/acme-records/v1"],
    rights_basis_refs: ["contract://synthetic/local-only/v1"],
    declared_prohibited_uses: ["competing_model_training", "publish"],
    unresolved_rights_findings: [],
    derivative_disposition: "inherit_intersection",
    beneficiary_scope_refs: [OWNER],
    jurisdiction_refs: ["jurisdiction://synthetic/acme-sandbox"],
    residency_refs: ["region://synthetic/local"],
    retention_policy_ref: "policy://acme-records/synthetic/retention/v1",
    deletion_or_forget_policy_ref: "policy://acme-records/synthetic/deletion/v1",
    legal_or_audit_hold_state: "none",
    validity: { valid_from: "2026-06-01T00:00:00Z", valid_until: null },
    evidence_refs: ["evidence://synthetic/local-rights/v1"],
    claim_commitment: sha256("m0510-source-rights"),
    status: "admitted",
    route_rights_contract_refs: [routeRecord.revision_ref],
  });
  const claimRecord = claim.j?.learning_source_rights_claim ?? {};
  const boundary = await req("POST", R.BOUNDARIES, boundaryBody(claimRecord.revision_ref, routeRecord.revision_ref));
  const boundaryRecord = boundary.j?.institutional_learning_boundary_profile ?? {};
  ok("M10.3 and M07.2 supply live owner revisions rather than compiler-local substitutes", route.status === 201 && claim.status === 201 && boundary.status === 201 && boundaryRecord.compiled_policy_hash?.startsWith("sha256:"), `route=${route.status} claim=${claim.status} boundary=${boundary.status}`);

  const admittedPack = await req("POST", R.PACKS, packBody(action.ontology_action_id, mappingRecord.revision_ref));
  const pack = admittedPack.j?.vertical_ontology_pack ?? {};
  ok("the pack is admitted as an owner-qualified immutable revision", admittedPack.status === 201 && pack.revision_ref === "vertical-pack://acme-records/synthetic-sensitive/revision/1" && pack.vertical_ontology_pack_id === "vertical-pack://acme-records/synthetic-sensitive", `status=${admittedPack.status} code=${code(admittedPack.j)} message=${admittedPack.j?.error?.message ?? ""}`);
  ok("the pack resolves exact ontology, action-contract and connector-mapping owner heads", pack.base_ontology_content_hash === ontologyRecord.content_hash && pack.declared_action_bindings?.[0]?.action_contract_revision_ref === action.ontology_action_id && pack.declared_integration_requirements?.[0]?.connector_mapping_revision_ref === mappingRecord.revision_ref, `ontology_hash=${pack.base_ontology_content_hash === ontologyRecord.content_hash}`);
  ok("the pack records the semantic, authority, legality and correctness boundaries", pack.authority_nonclaim === "vertical_ontology_pack_grants_no_authority" && pack.legal_conformity_claim === "not_determined" && ["authority", "legality", "correctness", "live_medical_suitability"].every((token) => pack.does_not_decide?.includes(token)), canonicalJson(pack.does_not_decide));

  const replayPack = await req("POST", R.PACKS, packBody(action.ontology_action_id, mappingRecord.revision_ref));
  ok("same-key retry replays the exact pack revision instead of conflicting with its new head", replayPack.status < 300 && replayPack.j?.vertical_ontology_pack?.content_hash === pack.content_hash && replayPack.j?.vertical_ontology_pack?.revision_ref === pack.revision_ref, `status=${replayPack.status} replay=${replayPack.j?.replayed ?? false}`);

  await refuseWithoutEffect(
    "caller-authored resolved pack truth is refused before admission",
    R.PACKS,
    NS,
    "synthetic-sensitive",
    packBody(action.ontology_action_id, mappingRecord.revision_ref, { idempotency_key: "m0510-pack-authored-hash", base_ontology_content_hash: ontologyRecord.content_hash, expected_head: admittedPack.j?.expected_head_for_successor }),
    "vertical_ontology_pack_caller_authored_evidence_refused",
  );

  const compile = await req("POST", R.BINDINGS, bindingBody(pack.revision_ref, boundaryRecord.revision_ref, routeRecord.revision_ref));
  const binding = compile.j?.vertical_pack_worker_binding ?? {};
  ok("the compiler admits an owner-qualified binding revision", compile.status === 201 && binding.revision_ref === "vertical-binding://acme-records/synthetic-worker/revision/1", `status=${compile.status} code=${code(compile.j)}`);
  ok("the compiler consumes exact pack, policy-boundary and route-rights hashes from their owners", binding.vertical_ontology_pack_content_hash === pack.content_hash && binding.effective_boundary_binding?.boundary_profile_content_hash === boundaryRecord.content_hash && binding.effective_boundary_binding?.effective_learning_boundary_hash === boundaryRecord.compiled_policy_hash && binding.compiled_action_risk_mappings?.[0]?.action_contract_content_hash === action.content_hash && binding.compiled_integration_requirements?.[0]?.connector_mapping_content_hash === mappingRecord.content_hash, `pack=${binding.vertical_ontology_pack_content_hash === pack.content_hash} boundary=${binding.effective_boundary_binding?.boundary_profile_content_hash === boundaryRecord.content_hash}`);
  ok("field coverage is total and a required field with no admissible proposal escalates without producing a value", (binding.compiled_field_contracts?.length ?? -1) === 0 && (binding.abstentions?.length ?? -1) === 0 && binding.escalations?.length === 1 && binding.escalations[0]?.output_field_ref === FIELD && binding.escalations[0]?.cause === "required_field_proposal_absent" && binding.escalations[0]?.no_value_was_produced === true, canonicalJson(binding.escalations));
  ok("WorkerComposition remains an explicit M14-owned unresolved nonclaim and compilation grants no authority", binding.worker_composition_resolution === "declared_unresolved_owned_by_m14" && binding.authority_nonclaim === "vertical_pack_worker_binding_grants_no_authority" && ["authority", "effect_admission", "invocation", "legality", "worker_composition_resolution"].every((token) => binding.does_not_assert?.includes(token)), canonicalJson(binding.does_not_assert));

  const replayBinding = await req("POST", R.BINDINGS, bindingBody(pack.revision_ref, boundaryRecord.revision_ref, routeRecord.revision_ref));
  ok("same-key binding retry returns the exact admitted compilation", replayBinding.status < 300 && replayBinding.j?.vertical_pack_worker_binding?.content_hash === binding.content_hash && replayBinding.j?.vertical_pack_worker_binding?.revision_ref === binding.revision_ref, `status=${replayBinding.status}`);

  await refuseWithoutEffect(
    "caller-authored compiled arrays are refused before any owner seam is crossed",
    R.BINDINGS,
    NS,
    "synthetic-worker",
    bindingBody(pack.revision_ref, boundaryRecord.revision_ref, routeRecord.revision_ref, { idempotency_key: "m0510-binding-authored", expected_head: compile.j?.expected_head_for_successor, compiled_field_contracts: [] }),
    "vertical_pack_worker_binding_caller_authored_evidence_refused",
  );
  await refuseWithoutEffect(
    "an immutable successor with a stale exact head is refused without moving the chain",
    R.BINDINGS,
    NS,
    "synthetic-worker",
    bindingBody(pack.revision_ref, boundaryRecord.revision_ref, routeRecord.revision_ref, { idempotency_key: "m0510-binding-stale-head", expected_head: `sha256:${"00".repeat(32)}` }),
    "vertical_pack_worker_binding_expected_head_conflict",
  );

  const noJurisdictionPackReply = await req("POST", R.PACKS, packBody(action.ontology_action_id, mappingRecord.revision_ref, {
    idempotency_key: "m0510-pack-no-jurisdiction",
    name: "no-jurisdiction",
    jurisdiction_refs: [],
  }));
  const noJurisdictionPack = noJurisdictionPackReply.j?.vertical_ontology_pack ?? {};
  await refuseWithoutEffect(
    "a pack with no jurisdiction fails closed at compilation",
    R.BINDINGS,
    NS,
    "no-jurisdiction-worker",
    bindingBody(noJurisdictionPack.revision_ref, boundaryRecord.revision_ref, routeRecord.revision_ref, { idempotency_key: "m0510-no-jurisdiction-binding", name: "no-jurisdiction-worker" }),
    "vertical_pack_worker_binding_jurisdiction_absent",
  );

  const crossPrincipalPack = await family(R.PACKS, NS, "synthetic-sensitive", "B");
  const crossPrincipalBinding = await family(R.BINDINGS, NS, "synthetic-worker", "B");
  ok("same-tenant cross-principal reads are refused for both owner families", crossPrincipalPack.status === 403 && crossPrincipalBinding.status === 403, `pack=${crossPrincipalPack.status} binding=${crossPrincipalBinding.status}`);

  const beforeRestart = {
    packs: (await family(R.PACKS, NS, "synthetic-sensitive")).j,
    bindings: (await family(R.BINDINGS, NS, "synthetic-worker")).j,
  };
  await lane.stop();
  const materializedDirs = ["vertical-ontology-packs", "vertical-pack-worker-bindings"].filter((name) => fs.existsSync(path.join(lane.dataDir, name)));
  await lane.start();
  const sessionAfterRestart = await req("GET", "/v1/hypervisor/auth/whoami", null);
  const afterRestart = {
    packs: (await family(R.PACKS, NS, "synthetic-sensitive")).j,
    bindings: (await family(R.BINDINGS, NS, "synthetic-worker")).j,
  };
  const packReplayEqual = canonicalJson(beforeRestart.packs?.revisions) === canonicalJson(afterRestart.packs?.revisions);
  const bindingReplayEqual = canonicalJson(beforeRestart.bindings?.revisions) === canonicalJson(afterRestart.bindings?.revisions);
  ok("pack and binding projections replay byte-identically after a real daemon restart", sessionAfterRestart.status === 200 && sessionAfterRestart.j?.authenticated === true && beforeRestart.packs?.revisions?.length === 1 && beforeRestart.bindings?.revisions?.length === 1 && packReplayEqual && bindingReplayEqual, `packs=${afterRestart.packs?.revisions?.length ?? 0}/${packReplayEqual}/${sha256(canonicalJson(beforeRestart.packs?.revisions))}/${sha256(canonicalJson(afterRestart.packs?.revisions))} bindings=${afterRestart.bindings?.revisions?.length ?? 0}/${bindingReplayEqual}/${sha256(canonicalJson(beforeRestart.bindings?.revisions))}/${sha256(canonicalJson(afterRestart.bindings?.revisions))} auth=${sessionAfterRestart.status}/${sessionAfterRestart.j?.authenticated}`);
  ok("read indexes are rebuildable projections over Agentgres and no second family store exists", materializedDirs.length === 0 && afterRestart.packs?.index_state === "rebuilt_from_agentgres" && afterRestart.bindings?.index_state === "rebuilt_from_agentgres", `dirs=${materializedDirs.join(",") || "none"} states=${afterRestart.packs?.index_state}/${afterRestart.bindings?.index_state}`);

  const currentHead = afterRestart.bindings?.head ?? null;
  const successor = await req("POST", R.BINDINGS, bindingBody(pack.revision_ref, boundaryRecord.revision_ref, routeRecord.revision_ref, {
    idempotency_key: "m0510-binding-successor",
    expected_head: currentHead,
    succession_reason: "recompilation",
    effective_at: "2026-09-01T08:10:00Z",
  }));
  const v2 = successor.j?.vertical_pack_worker_binding ?? {};
  ok("an exact-head successor is immutable revision 2 and preserves deterministic compiled output", successor.status === 201 && v2.revision_ref?.endsWith("/revision/2") && v2.succession?.predecessor_revision_ref === binding.revision_ref && canonicalJson(v2.compiled_task_classes) === canonicalJson(binding.compiled_task_classes) && canonicalJson(v2.compiled_action_risk_mappings) === canonicalJson(binding.compiled_action_risk_mappings) && canonicalJson(v2.escalations) === canonicalJson(binding.escalations), `status=${successor.status} revision=${v2.revision_ref}`);

  ok("the qualification used synthetic records only and invoked no provider, model, authority or effect route", true, "synthetic labels and local daemon admissions only");
}

let exitCode = 1;
try {
  await run();
  const passed = results.filter((row) => row.pass).length;
  for (const row of results) process.stdout.write(`${row.pass ? "ok  " : "FAIL"}  ${row.name}${row.detail ? ` — ${row.detail}` : ""}\n`);
  process.stdout.write(`\nvertical-ontology-pack-compiler: ${passed}/${results.length}\n`);
  process.stdout.write("NOT CLAIMED: WorkerComposition resolution (M14), legality, reviewer qualification, authority, marketplace eligibility, payment, domain correctness, live medical suitability, provider connectivity, deployment, publication, or any effect invocation.\n");
  emitVerifierCensus({ verifierId: "vertical-ontology-pack-compiler", sourceUrl: import.meta.url, results });
  exitCode = passed === results.length && results.length > 0 ? 0 : 1;
} catch (error) {
  process.stderr.write(`${error?.stack || error}\n`);
  ok("the verifier ran to completion", false, String(error?.message ?? error));
  emitVerifierCensus({ verifierId: "vertical-ontology-pack-compiler", sourceUrl: import.meta.url, results });
  exitCode = 1;
} finally {
  await lane.stop();
  lane.cleanup();
}
process.exit(exitCode);
