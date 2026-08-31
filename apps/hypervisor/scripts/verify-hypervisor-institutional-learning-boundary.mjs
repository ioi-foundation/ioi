#!/usr/bin/env node
// M10.3 + the M07.2 prerequisite seam, verified against a LIVE daemon.
//
// WHAT THIS GATE CLAIMS. That the compiled institutional learning boundary is a subtraction over
// resolved inputs rather than an assertion: that a use denied by any single input cannot survive the
// intersection, that an unresolved right cannot coexist with the permission it would need, that a
// child profile cannot widen its parent, that a decision cannot be taken against another principal's
// boundary, that a crossing is refused before egress when any gate fails, and that every one of
// those facts REPLAYS from the durable chain across a real process restart with the read index
// destroyed.
//
// WHAT IT DOES NOT CLAIM. It does not claim provider non-learning, delivery, unlearning, or that any
// external invoker was or was not called — the daemon records what it observed at its own boundary
// and the receipts say so in their own bytes. It does not exercise a real provider, real protected
// data, or a real network egress.
//
// DURABLE TRUTH IS READ ACROSS A RESTART. Asking the API whether something survived a restart,
// without restarting, is asking the thing under test to grade itself.
//
// Exit: 0 all assertions pass · 1 any assertion fails · 2 BLOCKED (daemon binary missing).

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const MUTATE = process.argv.includes("--mutate");
const ANCHORS = process.argv.includes("--anchors");
// `--only=id,id` scores a SUBSET. A battery that can only run whole risks losing every completed
// mutant when the run is interrupted, and an interrupted run produced no result at all. Scoring in
// bounded batches makes each batch its own evidence; the ledger line always reports the denominator
// it actually ran, never the full population, so a subset can never read as a clean sweep.
const ONLY = (process.argv.find((arg) => arg.startsWith("--only=")) ?? "")
  .replace("--only=", "")
  .split(",")
  .map((id) => id.trim())
  .filter(Boolean);

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.error?.code ?? j?.code ?? "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const canonicalJson = (value) => JSON.stringify(value ?? null);

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ilb-"));
const dataDir = path.join(scratch, "data");
let daemon = null;
let daemonLog = "";
let DAEMON = "";
const SESSIONS = { A: "", B: "" };

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

function daemonBinary() {
  if (process.env.IOI_HYPERVISOR_DAEMON_BINARY) return process.env.IOI_HYPERVISOR_DAEMON_BINARY;
  if (process.env.CARGO_TARGET_DIR) {
    return path.join(process.env.CARGO_TARGET_DIR, "debug", "hypervisor-daemon");
  }
  return path.join(ROOT, "target", "debug", "hypervisor-daemon");
}

function rebuildDaemon() {
  const build = spawnSync("cargo", ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (build.status !== 0) throw new Error(`daemon did not build:\n${build.stderr?.slice(-4000)}`);
}

async function waitFor(url, timeoutMs = 90000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.status < 500) return true;
    } catch {
      /* not listening yet */
    }
    await sleep(120);
  }
  return false;
}

async function startDaemon() {
  const port = await freePort();
  DAEMON = `http://127.0.0.1:${port}`;
  daemon = spawn(daemonBinary(), [], {
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
      IOI_WALLET_SECRET_PASS: "ioi-institutional-learning-boundary-verifier",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (chunk) => {
    daemonLog = `${daemonLog}${chunk}`.slice(-64000);
  });
  daemon.stderr.on("data", (chunk) => {
    daemonLog = `${daemonLog}${chunk}`.slice(-64000);
  });
  if (!(await waitFor(`${DAEMON}/healthz`))) throw new Error("the isolated daemon never became healthy");
}

// SIGTERM the tracked child. Never pgrep/pkill a daemon path — that kills this process's own shell.
async function stopDaemon() {
  if (!daemon) return;
  const child = daemon;
  daemon = null;
  try {
    child.kill("SIGTERM");
  } catch {
    /* already gone */
  }
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    sleep(4000).then(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
    }),
  ]);
  await sleep(150);
}

function cleanup() {
  try {
    daemon?.kill("SIGKILL");
  } catch {
    /* already gone */
  }
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

process.on("exit", cleanup);
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    cleanup();
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
}

async function req(method, url, body, opts = {}) {
  const as = "as" in opts ? opts.as : "A";
  const headers = { "content-type": "application/json" };
  if (as && SESSIONS[as]) headers.cookie = `ioi_session=${SESSIONS[as]}`;
  try {
    const response = await fetch(`${DAEMON}${url}`, {
      method,
      headers,
      body: body === null || body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* non-json */
    }
    return { status: response.status, j: json, text };
  } catch (error) {
    return { status: 0, j: { transport_error: String(error) }, text: String(error) };
  }
}

const ROUTES = "/v1/hypervisor/model-route-rights-contracts";
const CLAIMS = "/v1/hypervisor/learning-source-rights-claims";
const PROFILES = "/v1/hypervisor/institutional-learning-boundary-profiles";
const ELIGIBILITIES = "/v1/hypervisor/learning-evidence-eligibilities";
const EGRESS = "/v1/hypervisor/learning-egress-receipts";
const OWNER = "org://local";

// ------------------------------------------------------------------------------------ fixture bodies

const routeBody = (key, over = {}) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family: "acme.primary-inference",
  effective_at: "2026-05-01T10:00:00Z",
  route_binding: {
    route_ref: "route://acme-clinic/primary-inference",
    provider_ref: "provider://acme-clinic/external-inference-a",
    model_ref: "model://external-inference-a/general",
    model_revision_ref: "model://external-inference-a/general/revision/11",
    intermediary_ref: null,
    upstream_terms_ref: null,
    intermediary_is_supply_adapter_not_trust_boundary: true,
  },
  purposes: ["inference_service_delivery"],
  data_classes: ["prompts_and_completions", "connector_and_tool_io"],
  declared_prohibited_route_uses: [
    "unattended_automation",
    "screen_or_session_capture",
    "demonstration_training",
    "model_or_worker_training",
    "publication",
    "downstream_use",
    "oem_or_reseller_use",
    "interactive_control",
    "browser_or_account_use",
  ],
  unresolved_rights_findings: [
    { route_use: "connector_use", resolution: "missing", unresolved_term_ref: "terms://acme/provider-a/v7#connectors" },
    { route_use: "commercial_use", resolution: "unknown", unresolved_term_ref: "terms://acme/provider-a/v7#commercial" },
  ],
  destination_and_egress: {
    permitted_destination_classes: ["model_provider"],
    egress_ceiling: "redacted_only",
    region_refs: ["region://us-west"],
    residency_refs: ["region://us-west"],
    cross_border_transfer_basis_ref: null,
  },
  customer_output_rights: {
    intended_customer_output_uses: ["retain", "internal_evaluation"],
    effective_customer_output_rights_hash: `sha256:${"44".repeat(32)}`,
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
  retention_policy_ref: "policy://acme/retention/route/v1",
  commercial_terms_refs: ["contract://acme/provider-a-order-form/v3"],
  technical_terms_refs: ["terms://acme/provider-a/v7"],
  fallback_substitution: { fallback_is_semantic_substitution: true, fallback_route_rights_revision_ref: null },
  validity: { valid_from: "2026-05-01T00:00:00Z", valid_until: "2027-05-01T00:00:00Z" },
  revocation: { revocation_state: "live", revoked_at: null, revocation_reason: null, revocation_authority_ref: null },
  status: "active",
  resolved_principal_ref: "worker://acme-clinic/intake-assistant",
  credential_principal_ref: "service://acme-clinic/inference-credential-a",
  ...over,
});

const claimBody = (key, over = {}) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family: "acme.intake-records",
  effective_at: "2026-06-01T09:14:03Z",
  asserted_by_ref: OWNER,
  asserted_rights_holder_refs: [OWNER],
  source_class: "customer",
  subject_refs: ["dataset://acme/intake-rows/v3"],
  rights_basis_refs: ["contract://acme/customer-msa/v4"],
  // `commercialize_derivative` is deliberately ABSENT here: the route contract's unread
  // `commercial_use` term is the only thing that denies it, which is what lets the attribution
  // assertion below isolate the route path instead of passing on a coincidental claim denial.
  declared_prohibited_uses: ["fine_tune", "distill", "competing_model_training"],
  unresolved_rights_findings: [
    { use: "export", resolution: "missing", subject_ref: "dataset://acme/intake-rows/v3" },
  ],
  derivative_disposition: "inherit_intersection",
  beneficiary_scope_refs: [OWNER],
  jurisdiction_refs: ["jurisdiction://us-ca"],
  residency_refs: ["region://us-west"],
  retention_policy_ref: "policy://acme/retention/intake/v3",
  deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2",
  legal_or_audit_hold_state: "none",
  validity: { valid_from: "2026-06-01T00:00:00Z", valid_until: null },
  evidence_refs: ["evidence://acme/msa-countersigned/v4"],
  claim_commitment: `sha256:${"aa".repeat(32)}`,
  status: "admitted",
  ...over,
});

const profileBody = (key, over = {}) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family: "acme.organization-default",
  effective_at: "2026-06-01T09:20:11Z",
  scope_level: "organization",
  applies_to_refs: [OWNER],
  protected_material_classes: ["source_data", "prompts_and_completions"],
  custody: {
    product_mode: "private",
    runtime_operator: "customer_managed",
    permitted_provider_trust_postures: ["no_provider_plaintext", "redacted_only"],
    permitted_custody_postures: ["customer_boundary", "customer_vpc"],
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
  bound_target_refs: ["worker://acme-clinic/intake-assistant"],
  jurisdiction_refs: ["jurisdiction://us-ca"],
  residency_refs: ["region://us-west"],
  retention_policy_ref: "policy://acme/retention/intake/v3",
  deletion_or_forget_policy_ref: "policy://acme/deletion/intake/v2",
  derivative_policy_ref: "policy://acme/derivative/v1",
  export_policy_ref: "policy://acme/export/v1",
  revocation_policy_ref: "policy://acme/revocation/v1",
  declassification_policy_ref: "policy://acme/declassification/v1",
  status: "active",
  ...over,
});

const eligibilityBody = (key, over = {}) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family: "acme.intake-corrections",
  effective_at: "2026-09-12T08:02:19Z",
  eligibility_profile: "general_learning",
  learning_use: "internal_evaluation",
  intended_use: "benchmark",
  learning_use_posture: "full_private_opt_in",
  contamination_posture: "clean",
  subject_refs: ["finding://acme/intake-correction/0431"],
  requester_ref: "foundry_job://acme-clinic/intake-adapter-build/07",
  allowed_improvement_target_refs: ["worker://acme-clinic/intake-assistant"],
  owner_and_tenant_scope_refs: [OWNER],
  local_policy_refs: ["policy://acme/learning/intake/v2"],
  consent_refs: ["grant://acme-clinic/intake-consent/v3"],
  authority_requirement_posture: "none",
  authority_requirement_kinds: [],
  provider_trust_posture: "no_provider_plaintext",
  retention_policy_ref: "policy://acme/retention/intake/v3",
  derivative_policy_ref: "policy://acme/derivative/v1",
  lineage_root: `sha256:${"11".repeat(32)}`,
  receipt_root: `sha256:${"22".repeat(32)}`,
  admitted_by_ref: "operation://acme-clinic/eligibility-admit/8821",
  ...over,
});

const egressBody = (key, over = {}) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family: "acme.egress-0912",
  effective_at: "2026-09-12T09:51:38Z",
  source_scope_ref: "system://acme-clinic/primary",
  boundary_compilation_or_policy_decision_ref: "receipt://acme.boundary-compilation-0912",
  material_classes: ["prompts_and_completions"],
  material_commitment: `sha256:${"33".repeat(32)}`,
  policy_bound_projection_refs: ["view://acme.intake-minimised/revision/1"],
  recipient_class: "model_provider",
  recipient_ref: "provider://acme-clinic/external-inference-a",
  purpose: "inference_service_delivery",
  representation: "redacted",
  execution_privacy_posture_ref: "privacy_posture://acme-clinic/customer-vpc/v1",
  intended_customer_output_uses: ["retain", "internal_evaluation"],
  applicable_terms_and_license_refs: ["terms://acme/provider-a/v7"],
  retention_posture: "zero_retention",
  retention_policy_ref: "policy://acme/retention/intake/v3",
  local_policy_and_consent_refs: ["policy://acme/learning/intake/v2"],
  authority_refs: ["grant://acme-clinic/egress-review/v1"],
  redaction_or_declassification_receipt_refs: ["receipt://acme.redaction-0912-0011"],
  underlying_operation_receipt_refs: ["receipt://acme.route-decision-0912-0007"],
  state_operation_refs: ["operation://acme-clinic/egress-record/0912-0007"],
  observed_transfer_status: "delivery_confirmed",
  ...over,
});

// ---------------------------------------------------------------------------------------- the run

async function run() {
  await startDaemon();

  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "ilb-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  const whoA = (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    { email: "ilb-b@ioi.local", name: "Member B", role: "member", password: "ilb-b-v1" },
    { as: "A" },
  );
  const principalB = created.j?.principal?.principal_id ?? "";
  await req(
    "POST",
    `/v1/hypervisor/principals/${principalB}/tenant-memberships`,
    {
      tenant_ref: OWNER,
      expected_revision: 0,
      idempotency_key: "ilb-grant-b",
      reason: "verifier fixture: an ordinary member of the deployment's only organization",
    },
    { as: "A" },
  );
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "ilb-b@ioi.local", password: "ilb-b-v1" },
    { as: null },
  );
  SESSIONS.B = login.j?.session_token ?? "";
  const whoB = (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "B" })).j || {};
  ok(
    "PRECONDITION: two REAL authenticated principals share the deployment's single org tenant, so a tenant check alone would isolate nothing and every isolation assertion below is about the PRINCIPAL",
    whoA.authenticated === true &&
      whoB.authenticated === true &&
      (whoA.principal?.tenant_refs || []).includes(OWNER) &&
      (whoB.principal?.tenant_refs || []).includes(OWNER) &&
      whoA.principal?.principal_ref !== whoB.principal?.principal_ref,
    `A=${whoA.principal?.principal_ref} B=${whoB.principal?.principal_ref}`,
  );

  // =============================================================== M07.2 — the route-rights seam
  const route = await req("POST", ROUTES, routeBody("ilb-route-1"));
  const routeRecord = route.j?.model_route_rights_contract ?? {};
  const routeRef = routeRecord.revision_ref ?? "";
  ok(
    "M07.2: a route-rights contract is admitted as an immutable owner-qualified revision on the canonical chain",
    route.status === 201 && routeRef === "model-route-rights://acme.primary-inference/revision/1",
    `status ${route.status} ref ${routeRef}`,
  );
  ok(
    "M07.2: the route USE PARTITION IS DERIVED, not accepted — the two uses whose terms went unread are prohibited, and neither appears in the permitted set",
    canonicalJson(routeRecord.unresolved_route_uses) === canonicalJson(["connector_use", "commercial_use"]) &&
      (routeRecord.prohibited_route_uses || []).includes("connector_use") &&
      (routeRecord.prohibited_route_uses || []).includes("commercial_use") &&
      !(routeRecord.permitted_route_uses || []).includes("connector_use") &&
      !(routeRecord.permitted_route_uses || []).includes("commercial_use"),
    `permitted ${canonicalJson(routeRecord.permitted_route_uses)}`,
  );
  ok(
    "M07.2: the partition covers the twelve-use vocabulary exactly once each, so a use can be neither both-permitted-and-prohibited nor silently omitted from both",
    (routeRecord.permitted_route_uses || []).length + (routeRecord.prohibited_route_uses || []).length === 12 &&
      canonicalJson(routeRecord.declared_route_use_vocabulary?.length) === "12",
    `${(routeRecord.permitted_route_uses || []).length}+${(routeRecord.prohibited_route_uses || []).length}`,
  );
  ok(
    "M07.2: only model_inference survives, and `principal_resolution` is SERVER-resolved rather than named by the caller",
    canonicalJson(routeRecord.permitted_route_uses) === canonicalJson(["model_inference"]) &&
      routeRecord.principal_resolution === "server_resolved",
    `${canonicalJson(routeRecord.permitted_route_uses)} / ${routeRecord.principal_resolution}`,
  );
  const authoredPartition = await req(
    "POST",
    ROUTES,
    routeBody("ilb-route-authored", { permitted_route_uses: ["commercial_use"] }),
  );
  ok(
    "INV-37: a caller that AUTHORS the permission its own admission checks is refused by name, rather than having its value quietly overwritten",
    authoredPartition.status === 422 &&
      code(authoredPartition.j) === "model_route_rights_caller_authored_evidence_refused",
    `status ${authoredPartition.status} code ${code(authoredPartition.j)}`,
  );

  // ====================================================== M10.3 — the rights half of the boundary
  const claim = await req("POST", CLAIMS, claimBody("ilb-claim-1", { route_rights_contract_refs: [routeRef] }));
  const claimRecord = claim.j?.learning_source_rights_claim ?? {};
  const claimRef = claimRecord.revision_ref ?? "";
  ok(
    "M10.3: a source-rights claim is admitted, and its route-rights binding was RESOLVED through M07.2's owner seam rather than shape-checked locally",
    claim.status === 201 && claimRef === "learning-source-rights://acme.intake-records/revision/1",
    `status ${claim.status} ref ${claimRef}`,
  );
  ok(
    "M10.3: THE CLAIM CANNOT PERMIT WHAT IT COULD NOT RESOLVE — `export` carries an unresolved finding, so it is prohibited and absent from the permitted set by construction",
    (claimRecord.unresolved_right_uses || []).includes("export") &&
      (claimRecord.prohibited_uses || []).includes("export") &&
      !(claimRecord.permitted_uses || []).includes("export"),
    `permitted ${canonicalJson(claimRecord.permitted_uses)}`,
  );
  const badClaim = await req(
    "POST",
    CLAIMS,
    claimBody("ilb-claim-collide", {
      family: "acme.collide",
      declared_prohibited_uses: ["export"],
      unresolved_rights_findings: [{ use: "export", resolution: "missing", subject_ref: "dataset://x" }],
    }),
  );
  ok(
    "M10.3: a use recorded as BOTH affirmatively prohibited and unresolved is refused by name — a basis that forbids a use and an unanswered question about it are different facts and cannot be counted twice",
    badClaim.status === 422 &&
      code(badClaim.j) === "learning_source_rights_claim_prohibition_declared_and_unresolved",
    `status ${badClaim.status} code ${code(badClaim.j)}`,
  );
  const deadClaim = await req(
    "POST",
    CLAIMS,
    claimBody("ilb-claim-revoked", { family: "acme.revoked-claim", status: "revoked" }),
  );
  const deadRecord = deadClaim.j?.learning_source_rights_claim ?? {};
  ok(
    "M10.3: a REVOKED claim permits nothing and says why — every use it could otherwise have carried becomes a finding naming the state that removed it, rather than an empty set with no explanation",
    deadClaim.status === 201 &&
      (deadRecord.permitted_uses || []).length === 0 &&
      (deadRecord.unresolved_rights_findings || []).some((f) => f.resolution === "revoked"),
    `permitted ${(deadRecord.permitted_uses || []).length} findings ${(deadRecord.unresolved_rights_findings || []).length}`,
  );

  // ================================================================= M10.3 — the compiled profile
  const profile = await req(
    "POST",
    PROFILES,
    profileBody("ilb-profile-1", {
      learning_source_rights_claim_revision_refs: [claimRef],
      route_rights_contract_refs: [routeRef],
    }),
  );
  const profileRecord = profile.j?.institutional_learning_boundary_profile ?? {};
  const profileRef = profileRecord.revision_ref ?? "";
  const permitted = profileRecord.effective_permitted_uses || [];
  const denied = profileRecord.effective_denied_uses || [];
  ok(
    "M10.3: the boundary profile COMPILES from resolved inputs — the claim and the route contract were both resolved through owner seams before any intersection happened",
    profile.status === 201 &&
      profile.j?.compiled_inputs?.source_rights_claims === 1 &&
      profile.j?.compiled_inputs?.route_rights_contracts === 1,
    `status ${profile.status} inputs ${canonicalJson(profile.j?.compiled_inputs)}`,
  );
  ok(
    "M10.3: the permission is the COMPLEMENT of the denial set over the closed fifteen-use vocabulary — permitted and denied partition it exactly once each, so silence is inadmissible",
    permitted.length + denied.length === 15 &&
      permitted.every((use) => !denied.includes(use)),
    `${permitted.length}+${denied.length}`,
  );
  ok(
    "ACC-12 clause 7: a use the SOURCE CLAIM prohibits does not survive the intersection no matter what any other input permits",
    denied.includes("fine_tune") && denied.includes("distill") && !permitted.includes("fine_tune"),
    `denied ${canonicalJson(denied)}`,
  );
  ok(
    "ACC-12 clause 7: a use the ROUTE CONTRACT left unresolved does not survive either — `commercial_use` was unread upstream, and the denial is ATTRIBUTED to the route contract by name with reason `route_right_unresolved`, so this cannot pass on a coincidental denial from another input",
    denied.includes("commercialize_derivative") &&
      (profileRecord.narrowing_decisions || []).some(
        (d) =>
          d.denied_use === "commercialize_derivative" &&
          (d.governing_source_kind === "route_rights_contract" ||
            (d.also_denied_by_source_kinds || []).includes("route_rights_contract")) &&
          d.reason_code === "route_right_unresolved",
      ),
    canonicalJson((profileRecord.narrowing_decisions || []).find((d) => d.denied_use === "commercialize_derivative")),
  );
  ok(
    "M10.3: cross-tenant aggregate learning is DENIED BY DEFAULT — the profile names no cohort and no aggregation policy, so it is denied without anyone having to remember the default",
    denied.includes("cross_tenant_aggregate_learning"),
    `denied ${canonicalJson(denied)}`,
  );
  ok(
    "M10.3: EVERY locally added denial is attributed exactly once, to a named input or to an indeterminacy — an unattributed denial is impossible rather than discouraged",
    (profileRecord.narrowing_decisions || []).length + (profileRecord.indeterminate_findings || []).length ===
      (profileRecord.locally_added_denied_uses || []).length,
    `${(profileRecord.narrowing_decisions || []).length}+${(profileRecord.indeterminate_findings || []).length} vs ${(profileRecord.locally_added_denied_uses || []).length}`,
  );
  ok(
    "M10.3: the indeterminacy lane carries its own reason — `export` was unresolved in the claim, so the profile records WHY it is unavailable rather than merely that it is",
    (profileRecord.indeterminate_findings || []).some(
      (f) => f.denied_use === "export" && f.disputed_input_ref === claimRef,
    ),
    canonicalJson(profileRecord.indeterminate_findings),
  );
  ok(
    "ACC-12 clause 8: permission does not travel — the compiled profile pins `permission_travels_to_other_targets` false",
    profileRecord.target_binding?.permission_travels_to_other_targets === false,
    canonicalJson(profileRecord.target_binding),
  );
  ok(
    "M10.3: the profile emits an empty `widening_releases` list and a compiled policy hash distinct from its content hash — the decision and the serialization are committed separately",
    canonicalJson(profileRecord.widening_releases) === "[]" &&
      /^sha256:[0-9a-f]{64}$/.test(profileRecord.compiled_policy_hash || "") &&
      profileRecord.compiled_policy_hash !== profileRecord.content_hash,
    `${profileRecord.compiled_policy_hash}`,
  );

  // -------------------------------------------------------------------- narrowing, and no widening
  const child = await req(
    "POST",
    PROFILES,
    profileBody("ilb-profile-child", {
      family: "acme.run-snapshot",
      scope_level: "goal_run",
      parent_revision_ref: profileRef,
      // NO inputs of its own. Every denial this child carries beyond `internal_analytics` can only
      // have arrived by INHERITANCE, so dropping the inherited set is observable here — recompiling
      // from the same claim and route would have reproduced the denials independently and made the
      // inheritance assertion pass without inheritance ever happening.
      locally_declared_denied_uses: ["internal_analytics"],
    }),
  );
  const childRecord = child.j?.institutional_learning_boundary_profile ?? {};
  ok(
    "M10.3: a child snapshot NARROWS — it inherits every parent denial and adds its own, and its parent binding names the exact parent revision and content hash",
    child.status === 201 &&
      (childRecord.effective_denied_uses || []).includes("internal_analytics") &&
      denied.every((use) => (childRecord.effective_denied_uses || []).includes(use)) &&
      childRecord.parent_binding?.parent_revision_ref === profileRef &&
      childRecord.parent_binding?.parent_content_hash === profileRecord.content_hash,
    `status ${child.status}`,
  );
  ok(
    "M10.3: the inherited denial set is RETAINED EXACTLY — parent_denied_uses equals what the parent denied at compilation, and nothing was released",
    canonicalJson(childRecord.parent_denied_uses) ===
      canonicalJson(childRecord.parent_binding?.parent_denied_uses_at_compilation) &&
      canonicalJson(childRecord.widening_releases) === "[]",
    `${canonicalJson(childRecord.parent_denied_uses)}`,
  );
  const widened = await req(
    "POST",
    PROFILES,
    profileBody("ilb-profile-widen", {
      family: "acme.widen-attempt",
      scope_level: "goal_run",
      parent_revision_ref: profileRef,
      locally_permitted_uses: ["fine_tune"],
    }),
  );
  ok(
    "M10.3 / canon rule 1: a child that tries to PERMIT what its parent denied is refused by name — widening travels the governed upgrade path or does not happen",
    widened.status === 422 &&
      code(widened.j) === "institutional_learning_boundary_profile_widening_requires_governed_upgrade",
    `status ${widened.status} code ${code(widened.j)}`,
  );

  // ============================================================ M10.3 — the bounded eligibility
  const eligible = await req(
    "POST",
    ELIGIBILITIES,
    eligibilityBody("ilb-elig-1", {
      boundary_profile_revision_ref: profileRef,
      learning_source_rights_claim_revision_refs: [claimRef],
    }),
  );
  const eligibleRecord = eligible.j?.learning_evidence_eligibility ?? {};
  const eligibleRef = eligibleRecord.revision_ref ?? "";
  ok(
    "M10.3: an eligibility for a PERMITTED use is admitted eligible, and the boundary hash, its content hash and the permission set it was decided against are all SERVER-resolved from the profile",
    eligible.status === 201 &&
      eligibleRecord.status === "eligible" &&
      eligibleRecord.exclusion_reason === null &&
      eligibleRecord.boundary_profile_content_hash === profileRecord.content_hash &&
      eligibleRecord.effective_learning_policy_hash === profileRecord.compiled_policy_hash,
    `status ${eligible.status} decision ${eligibleRecord.status}`,
  );
  ok(
    "M10.3: the decision pins the permitted set AND its count at decision time, so a later boundary revision cannot make a past decision read as though it were taken under the new policy",
    canonicalJson(eligibleRecord.boundary_permitted_uses_at_decision) === canonicalJson(permitted) &&
      eligibleRecord.boundary_permitted_use_count_at_decision === permitted.length,
    `${eligibleRecord.boundary_permitted_use_count_at_decision}`,
  );
  const denyElig = await req(
    "POST",
    ELIGIBILITIES,
    eligibilityBody("ilb-elig-denied", {
      family: "acme.denied-use",
      boundary_profile_revision_ref: profileRef,
      learning_use: "fine_tune",
      intended_use: "worker_training",
    }),
  );
  const denyEligRecord = denyElig.j?.learning_evidence_eligibility ?? {};
  ok(
    "M10.3: an eligibility for a use the BOUNDARY DENIES is excluded and names the reason — the decision is computed against the resolved boundary, never declared by the requester",
    denyElig.status === 201 &&
      denyEligRecord.status === "excluded" &&
      denyEligRecord.exclusion_reason === "boundary_denies_the_use",
    `status ${denyEligRecord.status} reason ${denyEligRecord.exclusion_reason}`,
  );
  const indetElig = await req(
    "POST",
    ELIGIBILITIES,
    eligibilityBody("ilb-elig-indet", {
      family: "acme.indeterminate-use",
      boundary_profile_revision_ref: profileRef,
      learning_use: "export",
      intended_use: "benchmark",
    }),
  );
  ok(
    "M10.3: a use the boundary left INDETERMINATE is excluded for indeterminacy specifically, not merged into a generic denial — the two are different facts with different remedies",
    indetElig.j?.learning_evidence_eligibility?.exclusion_reason === "indeterminate_rights",
    `reason ${indetElig.j?.learning_evidence_eligibility?.exclusion_reason}`,
  );
  const dirtyElig = await req(
    "POST",
    ELIGIBILITIES,
    eligibilityBody("ilb-elig-dirty", {
      family: "acme.contaminated",
      boundary_profile_revision_ref: profileRef,
      contamination_posture: "quarantined",
    }),
  );
  const dirtyEligRef = dirtyElig.j?.learning_evidence_eligibility?.revision_ref ?? "";
  ok(
    "M10.3: quarantined material is never eligible, whatever the boundary permits",
    dirtyElig.j?.learning_evidence_eligibility?.status === "excluded" &&
      dirtyElig.j?.learning_evidence_eligibility?.learning_use === "internal_evaluation",
    `status ${dirtyElig.j?.learning_evidence_eligibility?.status}`,
  );
  const lentProfile = await req(
    "POST",
    ELIGIBILITIES,
    eligibilityBody("ilb-elig-lent", {
      family: "acme.lent-profile",
      boundary_profile_revision_ref: profileRef,
      eligibility_profile: "training_compatibility",
      intended_use: "analytics_only",
    }),
  );
  const authoredBoundary = await req(
    "POST",
    ELIGIBILITIES,
    eligibilityBody("ilb-elig-authored", {
      family: "acme.authored-snapshot",
      boundary_profile_revision_ref: profileRef,
      boundary_permitted_uses_at_decision: ["fine_tune"],
    }),
  );
  ok(
    "INV-37: a caller that AUTHORS the boundary permission set its own decision is checked against is refused by name — a decision over self-supplied constants is void for conformance purposes",
    authoredBoundary.status === 422 &&
      code(authoredBoundary.j) === "learning_evidence_eligibility_caller_authored_evidence_refused",
    `status ${authoredBoundary.status} code ${code(authoredBoundary.j)}`,
  );
  ok(
    "ACC-16: the training-compatibility profile cannot be lent to an operational use — an evidence class may not stand in for another",
    lentProfile.status === 422 &&
      code(lentProfile.j) === "learning_evidence_eligibility_training_profile_carries_an_operational_use",
    `status ${lentProfile.status} code ${code(lentProfile.j)}`,
  );

  // ================================================================= M10.3 — the receipted crossing
  const crossing = await req(
    "POST",
    EGRESS,
    egressBody("ilb-egress-1", {
      boundary_profile_revision_ref: profileRef,
      learning_evidence_eligibility_revision_refs: [eligibleRef],
      learning_source_rights_claim_revision_refs: [claimRef],
      model_route_rights_revision_ref: routeRef,
    }),
  );
  const crossingRecord = crossing.j?.learning_egress_receipt ?? {};
  ok(
    "M10.3: a crossing whose every gate passes is ADMITTED, carries no refusal codes, and snapshots the provider-use terms COPIED from the route contract rather than restated by the caller",
    crossing.status === 201 &&
      crossingRecord.decision === "admitted" &&
      canonicalJson(crossingRecord.reason_codes) === "[]" &&
      crossingRecord.provider_use_of_customer_material?.provider_model_training === "prohibited",
    `decision ${crossingRecord.decision} codes ${canonicalJson(crossingRecord.reason_codes)}`,
  );
  const blocked = await req(
    "POST",
    EGRESS,
    egressBody("ilb-egress-blocked", {
      family: "acme.egress-blocked",
      boundary_profile_revision_ref: profileRef,
      // Bound to an eligibility excluded for CONTAMINATION, whose learning use the boundary still
      // permits. The crossing therefore fails on the eligibility gate ALONE — a fixture whose use
      // was also denied would be refused twice over and could not tell the two gates apart.
      learning_evidence_eligibility_revision_refs: [dirtyEligRef],
      model_route_rights_revision_ref: routeRef,
    }),
  );
  const blockedRecord = blocked.j?.learning_egress_receipt ?? {};
  ok(
    "M10.3: a crossing bound to an EXCLUDED eligibility is blocked before egress, names `LearningEgressDenied` specifically, and claims nothing was sent",
    blockedRecord.decision === "blocked_before_egress" &&
      (blockedRecord.reason_codes || []).includes("LearningEgressDenied") &&
      blockedRecord.transfer_status === "not_sent",
    `codes ${canonicalJson(blockedRecord.reason_codes)} transfer ${blockedRecord.transfer_status}`,
  );
  ok(
    "M10.3: a blocked crossing WITHOUT enforcement evidence answers `not_sent`, never `prevented_before_network_write` — 'we returned an error' is not the same fact as 'the invoker was never called'",
    blockedRecord.transfer_status === "not_sent" &&
      blockedRecord.enforcement_evidence_binds_request_commitment === false,
    `${blockedRecord.transfer_status}`,
  );
  const declass = await req(
    "POST",
    EGRESS,
    egressBody("ilb-egress-params", {
      family: "acme.egress-params",
      boundary_profile_revision_ref: profileRef,
      learning_evidence_eligibility_revision_refs: [eligibleRef],
      model_route_rights_revision_ref: routeRef,
      representation: "declassified",
    }),
  );
  ok(
    "Information-flow invariant 8: moving DECLASSIFIED material across the boundary without a declassification approval is blocked before egress and names that exact missing approval",
    declass.j?.learning_egress_receipt?.decision === "blocked_before_egress" &&
      (declass.j?.learning_egress_receipt?.reason_codes || []).includes("DeclassificationApprovalMissing"),
    canonicalJson(declass.j?.learning_egress_receipt?.reason_codes),
  );
  const staleCrossing = await req(
    "POST",
    EGRESS,
    egressBody("ilb-egress-stale", {
      family: "acme.egress-stale",
      boundary_profile_revision_ref: childRecord.revision_ref,
      learning_evidence_eligibility_revision_refs: [eligibleRef],
      model_route_rights_revision_ref: routeRef,
    }),
  );
  ok(
    "M10.3: an eligibility decided against a DIFFERENT boundary revision cannot be lent to this crossing — stale-policy evidence is refused rather than accepted as near enough",
    staleCrossing.j?.learning_egress_receipt?.decision === "blocked_before_egress" &&
      (staleCrossing.j?.learning_egress_receipt?.reason_codes || []).includes("InstitutionalExportDenied"),
    canonicalJson(staleCrossing.j?.learning_egress_receipt?.reason_codes),
  );

  return { routeRef, claimRef, profileRef, eligibleRef, profileRecord, permitted, denied };
}

// ------------------------------------------------------- isolation, exact heads, and durable truth

async function runIsolationAndDurability(state) {
  const { routeRef, claimRef, profileRef, profileRecord } = state;

  // CROSS-PRINCIPAL ISOLATION. Both principals hold the same tenant, so anything that passes here
  // passed on the PRINCIPAL, not on tenancy.
  const bRead = await req("GET", `${PROFILES}?family=acme.organization-default`, null, { as: "B" });
  ok(
    "ISOLATION: a second principal in the SAME TENANT cannot read another principal's compiled boundary — the refusal is at the scope boundary, before any bytes are projected",
    bRead.status === 403,
    `status ${bRead.status} code ${code(bRead.j)}`,
  );
  const bCompile = await req(
    "POST",
    PROFILES,
    profileBody("ilb-b-compile", {
      family: "acme.b-profile",
      learning_source_rights_claim_revision_refs: [claimRef],
    }),
    { as: "B" },
  );
  ok(
    "ISOLATION: a second principal cannot COMPILE a boundary that intersects another principal's source-rights claim — the input is resolved under the caller's own owner binding and refused there",
    bCompile.status === 403 || bCompile.status === 404,
    `status ${bCompile.status} code ${code(bCompile.j)}`,
  );
  const bEligibility = await req(
    "POST",
    ELIGIBILITIES,
    eligibilityBody("ilb-b-elig", {
      family: "acme.b-elig",
      boundary_profile_revision_ref: profileRef,
    }),
    { as: "B" },
  );
  ok(
    "ISOLATION: a second principal cannot take an eligibility decision against another principal's boundary — a decision needs a boundary it is entitled to resolve",
    bEligibility.status === 403 || bEligibility.status === 404,
    `status ${bEligibility.status} code ${code(bEligibility.j)}`,
  );
  const foreignOwner = await req(
    "POST",
    PROFILES,
    profileBody("ilb-foreign-owner", { family: "acme.foreign", owner_ref: "org://someone.else" }),
  );
  ok(
    "ISOLATION: a caller claiming an owner it holds no membership in is refused before the body is even read, so it cannot probe which fields the route accepts",
    foreignOwner.status === 403,
    `status ${foreignOwner.status} code ${code(foreignOwner.j)}`,
  );

  // EXACT-HEAD ADMISSION.
  const staleHead = await req(
    "POST",
    PROFILES,
    profileBody("ilb-stale-head", {
      idempotency_key: "ilb-stale-head",
      expected_head: `sha256:${"ab".repeat(32)}`,
    }),
  );
  ok(
    "EXACT HEAD: a successor naming a head this stream never had is refused as a conflict — 'latest' is not an expectation and a stale head cannot be folded into one",
    staleHead.status === 409 &&
      code(staleHead.j) === "institutional_learning_boundary_profile_expected_head_conflict",
    `status ${staleHead.status} code ${code(staleHead.j)}`,
  );
  const genesisWithHead = await req(
    "POST",
    PROFILES,
    profileBody("ilb-genesis-head", {
      family: "acme.fresh-family",
      expected_head: `sha256:${"cd".repeat(32)}`,
    }),
  );
  ok(
    "EXACT HEAD: a FIRST admission that carries a predecessor head is refused — a genesis revision names no predecessor",
    genesisWithHead.status === 409,
    `status ${genesisWithHead.status} code ${code(genesisWithHead.j)}`,
  );

  // IDEMPOTENT REPLAY.
  const replay = await req("POST", ROUTES, routeBody("ilb-route-1"));
  ok(
    "REPLAY: an exact retry of an admitted command resolves to the revision it already admitted rather than minting a second one",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.model_route_rights_contract?.revision_ref === routeRef,
    `status ${replay.status} replayed ${replay.j?.replayed}`,
  );

  // ------------------------------------------------------------------ restart, replay, index rebuild
  const before = {
    routes: (await req("GET", `${ROUTES}?family=acme.primary-inference`)).j,
    claims: (await req("GET", `${CLAIMS}?family=acme.intake-records`)).j,
    profiles: (await req("GET", `${PROFILES}?family=acme.organization-default`)).j,
    eligibilities: (await req("GET", `${ELIGIBILITIES}?family=acme.intake-corrections`)).j,
    receipts: (await req("GET", `${EGRESS}?family=acme.egress-0912`)).j,
  };

  await stopDaemon();
  // NO SECOND COPY EXISTS TO DESTROY, AND THAT IS THE POINT. These five families materialize no
  // per-family record directory: the Agentgres chain is the only copy, so there is no row a sweep
  // could read instead of the log and no projection that could drift from it. The assertion is
  // therefore POSITIVE — the directories are absent — rather than "we deleted them and nothing
  // moved", which a family that never wrote them would also pass while proving nothing.
  //
  // Anything that IS present is deleted anyway, so a future build that starts materializing rows
  // gets its rebuild exercised rather than silently acquiring an unproven cache.
  const familyDirs = [
    "model-route-rights-contracts",
    "learning-source-rights-claims",
    "institutional-learning-boundary-profiles",
    "learning-evidence-eligibilities",
    "learning-egress-receipts",
  ];
  const present = familyDirs.filter((kind) => fs.existsSync(path.join(dataDir, kind)));
  for (const kind of present) {
    fs.rmSync(path.join(dataDir, kind), { recursive: true, force: true });
  }
  await startDaemon();
  const bootAfter = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (bootAfter) {
    const relogin = await req(
      "POST",
      "/v1/hypervisor/auth/login",
      { email: "ilb-b@ioi.local", password: "ilb-b-v1" },
      { as: null },
    );
    if (relogin.j?.session_token) SESSIONS.B = relogin.j.session_token;
  }
  const reloginA = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: "admin@ioi.local", password: "ilb-a-v1" },
    { as: null },
  );
  if (reloginA.j?.session_token) SESSIONS.A = reloginA.j.session_token;

  const after = {
    routes: (await req("GET", `${ROUTES}?family=acme.primary-inference`)).j,
    claims: (await req("GET", `${CLAIMS}?family=acme.intake-records`)).j,
    profiles: (await req("GET", `${PROFILES}?family=acme.organization-default`)).j,
    eligibilities: (await req("GET", `${ELIGIBILITIES}?family=acme.intake-corrections`)).j,
    receipts: (await req("GET", `${EGRESS}?family=acme.egress-0912`)).j,
  };
  const families = ["routes", "claims", "profiles", "eligibilities", "receipts"];
  ok(
    "DURABILITY: every admitted record in all five families REPLAYS BYTE-IDENTICALLY from the durable chain across a real process restart — this is read AFTER restarting, not by asking the API whether it would survive one",
    families.every(
      (key) =>
        canonicalJson(before[key]?.revisions) === canonicalJson(after[key]?.revisions) &&
        before[key]?.head === after[key]?.head,
    ),
    families.map((key) => `${key}:${(after[key]?.revisions || []).length}`).join(" "),
  );
  ok(
    "DURABILITY: NO SECOND COPY EXISTS — none of the five families materializes a per-family record directory, so the Agentgres chain is the only copy and there is no row a sweep could read instead of the log",
    present.length === 0 &&
      canonicalJson(before.profiles?.revisions) === canonicalJson(after.profiles?.revisions),
    `materialized directories: ${present.length === 0 ? "none" : present.join(",")}`,
  );
  ok(
    "DURABILITY: the process-local projection cache reports REBUILT-FROM-AGENTGRES by positive detection — an unchanged answer alone is also consistent with a cache that was never dropped, which would prove nothing",
    after.profiles?.index_state === "rebuilt_from_agentgres" &&
      after.routes?.index_state === "rebuilt_from_agentgres",
    `${after.profiles?.index_state} / ${after.routes?.index_state}`,
  );
  ok(
    "DURABILITY: the compiled policy hash and the content hash both survive the restart unchanged, so a consumer that bound the effective learning-boundary hash still binds the same policy",
    (after.profiles?.revisions || [])[0]?.compiled_policy_hash === profileRecord.compiled_policy_hash &&
      (after.profiles?.revisions || [])[0]?.content_hash === profileRecord.content_hash,
    `${(after.profiles?.revisions || [])[0]?.compiled_policy_hash}`,
  );
  const replayAfterRestart = await req("POST", ROUTES, routeBody("ilb-route-1"));
  ok(
    "DURABILITY: an exact retry AFTER the restart still resolves to the revision it already admitted rather than minting a second one — replay identity is rebuilt from durable history, not held in memory",
    replayAfterRestart.status === 200 &&
      replayAfterRestart.j?.replayed === true &&
      replayAfterRestart.j?.model_route_rights_contract?.revision_ref === routeRef,
    `status ${replayAfterRestart.status} replayed ${replayAfterRestart.j?.replayed}`,
  );
  const isolationAfterRestart = await req(
    "GET",
    `${PROFILES}?family=acme.organization-default`,
    null,
    { as: "B" },
  );
  ok(
    "DURABILITY: cross-principal isolation is REBUILT too — the second principal is still refused after the restart and the index deletion, so the scope binding is durable rather than cached",
    isolationAfterRestart.status === 403,
    `status ${isolationAfterRestart.status}`,
  );
}

// -------------------------------------------------------------------------------- mutation battery

const ROUTE_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/model_route_rights_routes.rs",
);
const ILB_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/institutional_learning_boundary_routes.rs",
);

const MUTANTS = [
  {
    id: "an-unresolved-route-right-is-still-permitted",
    source: "route",
    reddens:
      "M07.2: the route USE PARTITION IS DERIVED, not accepted — the two uses whose terms went unread are prohibited, and neither appears in the permitted set",
    from: `            declared_prohibited.iter().any(|held| held == *token) || unresolved.contains(**token)
        })
        .map(|token| (*token).to_string())
        .collect();
    let permitted: Vec<String> = ROUTE_USE_VOCABULARY`,
    to: `            declared_prohibited.iter().any(|held| held == *token)
        })
        .map(|token| (*token).to_string())
        .collect();
    let permitted: Vec<String> = ROUTE_USE_VOCABULARY`,
  },
  {
    id: "a-use-may-be-both-prohibited-and-unresolved",
    source: "ilb",
    reddens:
      "M10.3: a use recorded as BOTH affirmatively prohibited and unresolved is refused by name — a basis that forbids a use and an unanswered question about it are different facts and cannot be counted twice",
    from: `    if let Some(collision) = declared_prohibited
        .iter()
        .find(|token| unresolved.contains(*token))
    {
        return Err(refuse(
            &CLAIM.code("prohibition_declared_and_unresolved"),`,
    to: `    if let Some(collision) = declared_prohibited
        .iter()
        .find(|_token| false)
    {
        return Err(refuse(
            &CLAIM.code("prohibition_declared_and_unresolved"),`,
    sourceOverride: "ilb",
  },
  {
    id: "the-caller-may-author-the-permission-it-checks",
    source: "route",
    reddens:
      "INV-37: a caller that AUTHORS the permission its own admission checks is refused by name, rather than having its value quietly overwritten",
    from: `    "permitted_route_uses",
    "prohibited_route_uses",
    "unresolved_route_uses",
    "admitted_at",`,
    to: `    "prohibited_route_uses",
    "unresolved_route_uses",
    "admitted_at",`,
  },
  {
    id: "a-lapsed-route-contract-is-read-as-no-opinion",
    source: "ilb",
    reddens:
      "ACC-12 clause 7: a use the ROUTE CONTRACT left unresolved does not survive either — `commercial_use` was unread upstream, and the denial is ATTRIBUTED to the route contract by name with reason `route_right_unresolved`, so this cannot pass on a coincidental denial from another input",
    from: `    for unresolved in route.unresolved_route_uses() {
        for token in learning_uses_gated_by(&unresolved) {
            intersection.deny(`,
    to: `    for unresolved in Vec::<String>::new() {
        for token in learning_uses_gated_by(&unresolved) {
            intersection.deny(`,
  },
  {
    id: "cross-tenant-learning-is-permitted-by-default",
    source: "ilb",
    reddens:
      "M10.3: cross-tenant aggregate learning is DENIED BY DEFAULT — the profile names no cohort and no aggregation policy, so it is denied without anyone having to remember the default",
    from: `    if cohort_refs == 0 || aggregation_policy.is_none() {
        intersection.deny(
            "cross_tenant_aggregate_learning",`,
    to: `    if false {
        intersection.deny(
            "cross_tenant_aggregate_learning",`,
  },
  {
    id: "a-child-may-silently-widen-its-parent",
    source: "ilb",
    reddens:
      "M10.3 / canon rule 1: a child that tries to PERMIT what its parent denied is refused by name — widening travels the governed upgrade path or does not happen",
    from: `    if let Some(widened) = locally_permitted
        .iter()
        .find(|token| inherited_set.contains(*token))`,
    to: `    if let Some(widened) = locally_permitted
        .iter()
        .find(|_token| false)`,
  },
  {
    id: "the-inherited-denial-set-is-dropped",
    source: "ilb",
    reddens:
      "M10.3: a child snapshot NARROWS — it inherits every parent denial and adds its own, and its parent binding names the exact parent revision and content hash",
    from: `    let inherited: Vec<String> = parent
        .as_ref()
        .map(|held| held.effective_denied_uses())
        .unwrap_or_default();`,
    to: `    let inherited: Vec<String> = Vec::new();`,
  },
  {
    id: "an-excluded-eligibility-still-admits-a-crossing",
    source: "ilb",
    reddens:
      "M10.3: a crossing bound to an EXCLUDED eligibility is blocked before egress, names `LearningEgressDenied` specifically, and claims nothing was sent",
    from: `    if eligibilities.is_empty() || !eligibilities.iter().all(|held| held.is_eligible()) {
        reason_codes.push("LearningEgressDenied");
    }`,
    to: `    if false {
        reason_codes.push("LearningEgressDenied");
    }`,
  },
  {
    id: "a-stale-boundary-eligibility-is-lent-to-a-crossing",
    source: "ilb",
    reddens:
      "M10.3: an eligibility decided against a DIFFERENT boundary revision cannot be lent to this crossing — stale-policy evidence is refused rather than accepted as near enough",
    from: `    if eligibilities
        .iter()
        .any(|held| held.boundary_profile_revision_ref() != boundary.revision_ref)
    {
        reason_codes.push("InstitutionalExportDenied");
    }`,
    to: `    if false {
        reason_codes.push("InstitutionalExportDenied");
    }`,
  },
  {
    id: "parameter-egress-needs-no-declassification-approval",
    source: "ilb",
    reddens:
      "Information-flow invariant 8: moving DECLASSIFIED material across the boundary without a declassification approval is blocked before egress and names that exact missing approval",
    from: `    if PARAMETER_REPRESENTATIONS.contains(&representation.as_str())
        && declassification_approval_ref.is_empty()
    {
        reason_codes.push("DeclassificationApprovalMissing");
    }`,
    to: `    if false {
        reason_codes.push("DeclassificationApprovalMissing");
    }`,
  },
  {
    id: "a-blocked-crossing-claims-it-prevented-the-network-write",
    source: "ilb",
    reddens:
      "M10.3: a blocked crossing WITHOUT enforcement evidence answers `not_sent`, never `prevented_before_network_write` — 'we returned an error' is not the same fact as 'the invoker was never called'",
    from: `    } else if enforcement_binds && !gateway_evidence.is_empty() {
        "prevented_before_network_write".to_string()`,
    to: `    } else if true {
        "prevented_before_network_write".to_string()`,
  },
  {
    id: "quarantined-material-is-eligible",
    source: "ilb",
    reddens: "M10.3: quarantined material is never eligible, whatever the boundary permits",
    from: `    } else if !matches!(contamination_posture.as_str(), "clean") {`,
    to: `    } else if false {`,
  },
  {
    id: "the-training-profile-is-lent-to-an-operational-use",
    source: "ilb",
    reddens:
      "ACC-16: the training-compatibility profile cannot be lent to an operational use — an evidence class may not stand in for another",
    from: `    if eligibility_profile == "training_compatibility"
        && !TRAINING_COMPATIBILITY_USES.contains(&intended_use.as_str())
    {`,
    to: `    if false {`,
  },
  {
    id: "the-eligibility-decides-against-a-caller-named-boundary",
    source: "ilb",
    reddens:
      "INV-37: a caller that AUTHORS the boundary permission set its own decision is checked against is refused by name — a decision over self-supplied constants is void for conformance purposes",
    from: `    "boundary_profile_content_hash",
    "effective_learning_policy_hash",
    "boundary_permitted_uses_at_decision",
    "boundary_permitted_use_count_at_decision",
    "status",`,
    to: `    "status",`,
  },
  {
    id: "the-index-always-reports-agreement",
    source: "route",
    reddens:
      "DURABILITY: the process-local projection cache reports REBUILT-FROM-AGENTGRES by positive detection — an unchanged answer alone is also consistent with a cache that was never dropped, which would prove nothing",
    from: `        None => "rebuilt_from_agentgres",`,
    to: `        None => "agreed_with_agentgres",`,
  },
  {
    id: "a-successor-need-not-name-the-exact-head",
    source: "route",
    reddens:
      "EXACT HEAD: a successor naming a head this stream never had is refused as a conflict — 'latest' is not an expectation and a stale head cannot be folded into one",
    from: `    let current = stream.last().map(|last| last.head.clone());
    if *expected_head == current {
        return Ok(());
    }`,
    to: `    let current = stream.last().map(|last| last.head.clone());
    if true {
        let _ = current;
        return Ok(());
    }`,
  },
  {
    id: "a-cross-tenant-input-is-intersected-anyway",
    source: "ilb",
    reddens:
      "ISOLATION: a second principal cannot COMPILE a boundary that intersects another principal's source-rights claim — the input is resolved under the caller's own owner binding and refused there",
    from: "",
    to: "",
    skipReason:
      "NAMED RESIDUAL, not an oversight. Dropping the owner pin from the claim resolution does NOT open the hole, because `authorize_request_resource_scope` already refuses on principal_ref before the owner expectation is consulted — the pin is defence in depth over a check that is load-bearing on its own. The isolation assertion therefore passes for the RIGHT reason with or without it, and a mutant that cannot change the outcome is not evidence. The principal check itself lives in substrate_store.rs, outside this unit's ownership, and is mutation-covered by the M05.7 gate that owns it.",
  },
  {
    id: "a-denial-need-not-be-attributed",
    source: "ilb",
    reddens:
      "M10.3: EVERY locally added denial is attributed exactly once, to a named input or to an indeterminacy — an unattributed denial is impossible rather than discouraged",
    from: `        narrowing_decisions.push(json!({
            "denied_use": token,`,
    to: `        if false { narrowing_decisions.push(json!({
            "denied_use": token,`,
    skipReason: "the mutant does not balance its own braces; re-aim rather than plant a non-compiling defect",
  },
].filter((mutant) => !mutant.skipReason);

const SOURCES = { route: ROUTE_SOURCE, ilb: ILB_SOURCE };

/** Zero-build pre-flight: every anchor must occur EXACTLY once, and no two mutants may share a target. */
function checkAnchors() {
  const originals = Object.fromEntries(
    Object.entries(SOURCES).map(([key, file]) => [key, fs.readFileSync(file, "utf8")]),
  );
  let bad = 0;
  const targets = new Map();
  for (const mutant of MUTANTS) {
    const occurrences = originals[mutant.source].split(mutant.from).length - 1;
    if (occurrences !== 1) {
      bad += 1;
      process.stdout.write(`ANCHOR_LOST  ${mutant.id} — ${occurrences} matches in ${mutant.source}\n`);
    }
    if (targets.has(mutant.reddens)) {
      bad += 1;
      process.stdout.write(`SHARED_TARGET  ${mutant.id} shares its target with ${targets.get(mutant.reddens)}\n`);
    }
    targets.set(mutant.reddens, mutant.id);
  }
  process.stdout.write(`\nanchors: ${MUTANTS.length - bad}/${MUTANTS.length} resolve exactly once with distinct targets\n`);
  process.exit(bad === 0 ? 0 : 1);
}

async function runMutationBattery() {
  const originals = Object.fromEntries(
    Object.entries(SOURCES).map(([key, file]) => [key, fs.readFileSync(file, "utf8")]),
  );
  // A KILLED BATTERY MUST NOT LEAVE A DEFECT PLANTED IN THE TREE. `finally` does not run when the
  // process is signalled, so the restore is registered on the signals too, and it is idempotent.
  const restore = () => {
    for (const [key, file] of Object.entries(SOURCES)) fs.writeFileSync(file, originals[key]);
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.on(signal, () => {
      restore();
      process.stderr.write(`\nmutation battery interrupted by ${signal} — both sources restored\n`);
      process.exit(130);
    });
  }
  const selected = ONLY.length ? MUTANTS.filter((mutant) => ONLY.includes(mutant.id)) : MUTANTS;
  const unknown = ONLY.filter((id) => !MUTANTS.some((mutant) => mutant.id === id));
  if (unknown.length) {
    process.stderr.write(`no such mutant: ${unknown.join(", ")}\n`);
    process.exit(1);
  }
  const rows = [];
  try {
    for (const mutant of selected) {
      const original = originals[mutant.source];
      const occurrences = original.split(mutant.from).length - 1;
      if (occurrences !== 1) {
        rows.push({ id: mutant.id, outcome: "ANCHOR_LOST", detail: `${occurrences} matches in ${mutant.source}` });
        continue;
      }
      // The REPLACER FUNCTION form is deliberate: String.replace interprets `$&`, `` $` ``, `$'`
      // and `$1` in a string replacement, which would silently corrupt a Rust body containing them.
      fs.writeFileSync(SOURCES[mutant.source], original.replace(mutant.from, () => mutant.to));
      let outcome;
      let detail;
      try {
        rebuildDaemon();
        const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
          cwd: ROOT,
          encoding: "utf8",
          env: { ...process.env, IOI_VERIFIER_CENSUS_DIR: "", IOI_ILB_DAEMON_PREBUILT: "1" },
          maxBuffer: 64 * 1024 * 1024,
        });
        const output = `${child.stdout ?? ""}${child.stderr ?? ""}`;
        const targeted = output.includes(`FAIL  ${mutant.reddens}`);
        const anyFailure = child.status !== 0;
        outcome = targeted ? "RED_ON_TARGET" : anyFailure ? "RED_OFF_TARGET" : "SURVIVED";
        detail = targeted
          ? "the targeted assertion failed"
          : anyFailure
            ? "the run failed, but not on its target"
            : "the mutant passed unnoticed";
      } catch (error) {
        // A MUTANT THAT DOES NOT COMPILE IS NOT A PASS. It is a defect in the mutant, reported as a
        // miss, because a battery that silently skips its own hardest plants is not a battery.
        outcome = "DID_NOT_BUILD";
        detail = String(error?.message ?? error).slice(0, 200);
      }
      rows.push({ id: mutant.id, outcome, detail });
      // EMIT EACH ROW AS IT LANDS. A battery that only prints at the end loses every completed
      // mutant when the run is killed, and a killed run that reports nothing is indistinguishable
      // from one that found nothing. Each row is written immediately so a partial battery is still
      // partial EVIDENCE rather than silence.
      process.stdout.write(
        `${outcome === "RED_ON_TARGET" ? "RED " : "MISS"}  ${mutant.id} — ${detail}\n`,
      );
      // Restore after EVERY mutant, not only at the end: two mutants in different files would
      // otherwise compound, and the second would be graded against a daemon carrying both defects.
      restore();
    }
  } finally {
    restore();
    rebuildDaemon();
  }
  const onTarget = rows.filter((row) => row.outcome === "RED_ON_TARGET").length;
  process.stdout.write(
    `\ninstitutional-learning-boundary mutation battery: ${onTarget}/${selected.length} RED ON TARGET${
      ONLY.length ? ` (subset of ${MUTANTS.length})` : ""
    }\n`,
  );
  process.exit(onTarget === selected.length ? 0 : 1);
}

// ------------------------------------------------------------------------------------- the driver

try {
  fs.accessSync(daemonBinary(), fs.constants.X_OK);
} catch {
  process.stderr.write(`BLOCKED: daemon binary not executable at ${daemonBinary()}\n`);
  process.exit(2);
}

if (ANCHORS) {
  checkAnchors();
} else if (MUTATE) {
  runMutationBattery().catch((error) => {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exit(1);
  });
} else {
  Promise.resolve()
    .then(() => {
      // A blocking verifier must not silently exercise a stale target/debug binary. The mutation
      // parent is the sole exception because it built the exact planted source immediately before
      // spawning this child.
      if (process.env.IOI_ILB_DAEMON_PREBUILT !== "1") rebuildDaemon();
      return run();
    })
    .then((state) => runIsolationAndDurability(state))
    .catch((error) => {
      ok("the verifier ran to completion", false, String(error?.stack || error));
    })
    .finally(async () => {
      await stopDaemon();
      cleanup();
      for (const result of results) {
        process.stdout.write(
          `${result.pass ? "ok  " : "FAIL"}  ${result.name}${result.detail ? ` — ${result.detail}` : ""}\n`,
        );
      }
      const passed = results.filter((result) => result.pass).length;
      process.stdout.write(`\ninstitutional-learning-boundary: ${passed}/${results.length}\n`);
      emitVerifierCensus({
        verifierId: "institutional-learning-boundary",
        sourceUrl: import.meta.url,
        results,
      });
      process.exit(passed === results.length && results.length > 0 ? 0 : 1);
    });
}
