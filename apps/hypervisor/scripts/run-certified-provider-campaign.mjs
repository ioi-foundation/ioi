#!/usr/bin/env node
/**
 * Two-phase certified Akash campaign driver.
 *
 * Phase 1 (`--prepare-only`) performs no provider mutation and emits the exact
 * challenge. Phase 2 requires an owner-authored approval file binding those
 * exact hashes and facets before it can mint or cast the one-shot grant.
 */
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  certifiedRemainingDelayMs,
  certifiedWorkloadDeadlineMs,
  materializeReviewedSdl,
  validateBenchmarkBuildIdentity,
  validateCertifiedCampaignConfig,
  validateProviderPreflight,
  validateProviderPreflightResponse,
} from "./lib/certified-campaign-config.mjs";
import { captureCertifiedDaemonSourceBasis } from "./lib/certified-daemon-source-basis.mjs";
import { stableStringify } from "./lib/c7-c8-certificate.mjs";
import {
  approvalCeremonyContextHash,
  randomHex32,
  sealStandingAuthorityEnvelope,
} from "./lib/standing-authority-evidence.mjs";
import { issueSoftwarePasskeyAuthorityFactor } from "./lib/software-passkey-ceremony.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..", "..", "..");
const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};
const prepareOnly = process.argv.includes("--prepare-only");
const configArg = arg("--config");
const artifactsArg = arg("--artifacts");
const configPath = configArg ? path.resolve(configArg) : null;
const artifactDir = artifactsArg ? path.resolve(artifactsArg) : null;
const approvalPath = arg("--approval-file") ? path.resolve(arg("--approval-file")) : null;
if (!configPath || !artifactDir || (!prepareOnly && !approvalPath)) {
  throw new Error("usage: --config <json> --artifacts <dir> (--prepare-only | --approval-file <json>)");
}
const sha256 = (value) => `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
mkdirSync(artifactDir, { recursive: true, mode: 0o700 });
const config = validateCertifiedCampaignConfig(JSON.parse(readFileSync(configPath, "utf8")));
const imageBuildIdentityBytes = readFileSync(path.resolve(config.image_build_identity_path));
const imageBuildIdentity = validateBenchmarkBuildIdentity(
  JSON.parse(imageBuildIdentityBytes.toString("utf8")),
  config,
);
if (sha256(`${JSON.stringify(imageBuildIdentity, null, 2)}\n`) !== config.plan.image_build_identity_sha256) {
  throw new Error("immutable image build identity differs from the reviewed semantic SHA-256");
}
const providerPreflight = validateProviderPreflight(
  JSON.parse(readFileSync(path.resolve(config.provider_preflight_path), "utf8")),
  config,
);
if (sha256(`${JSON.stringify(providerPreflight, null, 2)}\n`) !== config.plan.provider_preflight_sha256) {
  throw new Error("provider preflight differs from the reviewed semantic SHA-256");
}
const providerResponseBytes = readFileSync(path.resolve(config.provider_response_path));
validateProviderPreflightResponse(providerResponseBytes, providerPreflight, config);
const daemonUrl = config.daemon_url || "http://127.0.0.1:8765";
const operatorEmail = process.env.IOI_C7_EMAIL || "";
const operatorPassword = process.env.IOI_C7_PASSWORD_FILE
  ? readFileSync(process.env.IOI_C7_PASSWORD_FILE, "utf8").trimEnd()
  : "";
const walletPass = process.env.IOI_WALLET_SECRET_PASS_FILE
  ? readFileSync(process.env.IOI_WALLET_SECRET_PASS_FILE, "utf8").trimEnd()
  : (process.env.IOI_WALLET_SECRET_PASS || "");
if (!operatorEmail || !operatorPassword || !walletPass) {
  throw new Error("IOI_C7_EMAIL, IOI_C7_PASSWORD_FILE, and an ephemeral IOI_WALLET_SECRET_PASS (or file) are required");
}
if (!String(config.environment_ref || "").startsWith("env-")) throw new Error("environment_ref must start with env-");
if (!String(config.idempotency_key || "").trim()) throw new Error("idempotency_key is required");

const save = (name, value) => writeFileSync(path.join(artifactDir, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
const saveBytes = (name, value) => writeFileSync(path.join(artifactDir, name), value, { mode: 0o600 });
const log = (message) => {
  const line = `[certified-campaign] ${message}`;
  console.log(line);
  appendFileSync(path.join(artifactDir, "run.log"), `${line}\n`, { mode: 0o600 });
};
const headers = (session = "") => ({
  "Content-Type": "application/json",
  ...(session ? { cookie: `ioi_session=${session}` } : {}),
});
const sdlTemplate = readFileSync(path.resolve(config.sdl_path), "utf8");
const request = {
  provider_id: config.provider_id,
  op: "create",
  environment_ref: config.environment_ref,
  owner_ref: config.owner_ref,
  idempotency_key: config.idempotency_key,
  plan: { ...config.plan, sdl_yaml: materializeReviewedSdl(sdlTemplate, config) },
};
const expectedSdlHash = sha256(request.plan.sdl_yaml);
const daemonSourceBasis = captureCertifiedDaemonSourceBasis({ repo });
save("daemon-source-basis.json", daemonSourceBasis);
save("image-build-identity.json", imageBuildIdentity);
save("provider-preflight.json", providerPreflight);
saveBytes("provider-response.json", providerResponseBytes);

async function daemonReady(timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`${daemonUrl}/v1/hypervisor/auth/bootstrap-status`)).status < 500) return;
    } catch {}
    await sleep(1_000);
  }
  throw new Error("daemon did not become ready");
}

async function postProvider(session, op, suffix = op) {
  const response = await fetch(`${daemonUrl}/v1/hypervisor/provider-ops`, {
    method: "POST",
    headers: headers(session),
    body: JSON.stringify({
      provider_id: config.provider_id,
      op,
      environment_ref: config.environment_ref,
      owner_ref: config.owner_ref,
      idempotency_key: `${config.idempotency_key}.${suffix}`,
    }),
  });
  const value = await response.json();
  save(`${op}-${suffix.replaceAll(".", "-")}.json`, value);
  log(`${op}: HTTP ${response.status}, ok=${value.ok === true}`);
  return { response, value };
}

async function capture(session) {
  for (const [name, endpoint] of [
    ["reconciliation", "/v1/hypervisor/provider-spend/reconciliation"],
    ["receipts", "/v1/hypervisor/provider-receipts"],
    ["deployments", "/v1/hypervisor/akash-deployments"],
    ["operations", "/v1/hypervisor/provider-operations"],
  ]) {
    const value = await fetch(`${daemonUrl}${endpoint}`, { headers: headers(session) }).then((response) => response.json());
    save(`${name}.json`, value);
    save(`c7-${name}.json`, value);
  }
}

function verifyFacets(challenge) {
  const facets = challenge.lease_request_facets || {};
  const expected = {
    deposit_usd: request.plan.deposit_usd,
    ceiling_amount: request.plan.ceiling_amount,
    ceiling_denom: request.plan.ceiling_denom,
    provider_selector: request.plan.provider_selector,
    auto_topup: false,
    teardown_policy: request.plan.teardown_policy,
    execution_mode: "live",
    sdl_hash: expectedSdlHash,
    registry_credential_ref: request.plan.registry_credential_ref ?? null,
    result_credential_ref: request.plan.result_credential_ref ?? null,
    result_tls_server_certificate_sha256: request.plan.result_tls_server_certificate_sha256 ?? null,
    campaign_id: request.plan.campaign_id ?? null,
    benchmark_source_commit: request.plan.benchmark_source_commit ?? null,
    image_digest: request.plan.image_digest ?? null,
    image_build_identity_sha256: request.plan.image_build_identity_sha256 ?? null,
    provider_preflight_sha256: request.plan.provider_preflight_sha256 ?? null,
    benchmark_protocol_version: request.plan.benchmark_protocol_version ?? null,
    result_schema_version: request.plan.result_schema_version ?? null,
    benchmark_warmups: request.plan.benchmark_warmups ?? null,
    benchmark_repeats: request.plan.benchmark_repeats ?? null,
    max_duration_seconds: request.plan.max_duration_seconds ?? null,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (JSON.stringify(facets[key] ?? null) !== JSON.stringify(value)) {
      throw new Error(`facet checkpoint refused ${key}`);
    }
  }
  return { facets, expected };
}

let fixture;
let session = "";
let dseq = "";
let terminal = false;
let whoamiPrincipal = null;
try {
  if (!prepareOnly) {
    fixture = await startRealWalletNetworkPrincipalAuthorityFixture({
      wallClockChain: config.standing_authority?.enabled === true,
      baseEnv: {
        ...process.env,
        IOI_WALLET_SECRET_PASS: walletPass,
        IOI_WALLET_FIXTURE_TEE_LOG: path.join(artifactDir, "wallet-authority.log"),
      },
    });
  } else {
    log("prepare-only: wallet authority plane intentionally not started");
  }
  const portOwner = spawnSync("bash", ["-lc", "ss -tlnp 2>/dev/null | awk '/:8765 / {match($0,/pid=[0-9]+/); if (RSTART) print substr($0,RSTART+4,RLENGTH-4)}'"], { encoding: "utf8" }).stdout.trim();
  if (portOwner && /^\d+$/u.test(portOwner)) process.kill(Number(portOwner), "SIGTERM");
  await sleep(2_000);
  const daemonLog = openSync(path.join(artifactDir, "daemon.log"), "a", 0o600);
  const daemon = spawn(path.join(repo, "target/debug/hypervisor-daemon"), [], {
    detached: true,
    env: {
      ...process.env,
      ...(fixture?.env || {}),
      IOI_WALLET_SECRET_PASS: walletPass,
      IOI_HYPERVISOR_DATA_DIR: config.data_dir,
      IOI_HYPERVISOR_DAEMON_ADDR: "127.0.0.1:8765",
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: config.authority_principal_ref,
      IOI_HYPERVISOR_WEBAUTHN_RP_ID: "localhost",
      IOI_HYPERVISOR_WEBAUTHN_ORIGIN: "http://localhost:8766",
    },
    stdio: ["ignore", daemonLog, daemonLog],
  });
  daemon.unref();
  await daemonReady();

  const login = await fetch(`${daemonUrl}/v1/hypervisor/auth/login`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ email: operatorEmail, password: operatorPassword }),
  });
  const loginBody = await login.json();
  session = loginBody.session_token || "";
  if (!session.startsWith("ioi_sess_")) throw new Error(`operator login refused: HTTP ${login.status}`);
  save("operator.json", { principal_ref: loginBody.principal_ref || null, email_hash: sha256(operatorEmail) });
  const whoamiResponse = await fetch(`${daemonUrl}/v1/hypervisor/auth/whoami`, {
    headers: headers(session),
  });
  const whoami = await whoamiResponse.json();
  if (!whoamiResponse.ok || whoami.authenticated !== true) {
    throw new Error(`operator whoami refused: HTTP ${whoamiResponse.status}`);
  }
  whoamiPrincipal = whoami.principal || null;
  if (!String(whoamiPrincipal?.principal_ref || "").startsWith("user://")) {
    throw new Error("operator whoami did not resolve a user principal reference");
  }
  save("c7-whoami.json", whoami);

  const dryResponse = await fetch(`${daemonUrl}/v1/hypervisor/provider-ops`, {
    method: "POST",
    headers: headers(session),
    body: JSON.stringify(request),
  });
  const challenge = await dryResponse.json();
  save("challenge.json", challenge);
  save("c7-challenge.json", challenge);
  const policyHash = challenge.approval?.policy_hash;
  const requestHash = challenge.approval?.request_hash;
  if (!policyHash || !requestHash || challenge.host_mutation !== false) throw new Error("dry challenge was not a spend-free authority refusal");
  const { facets } = verifyFacets(challenge);
  const reviewBundle = {
    policy_hash: policyHash,
    request_hash: requestHash,
    environment_ref: config.environment_ref,
    provider_id: request.provider_id,
    operation: request.op,
    owner_ref: request.owner_ref,
    idempotency_key: request.idempotency_key,
    reviewed_facets: facets,
    workload_effect_broker: config.workload_effect_broker?.enabled === true
      ? config.workload_effect_broker
      : null,
    standing_authority: config.standing_authority?.enabled === true
      ? config.standing_authority
      : null,
  };
  const approvalRequest = {
    schema_version: "ioi.hypervisor.certified-provider-approval.v1",
    approved: false,
    ...reviewBundle,
    review_bundle_sha256: sha256(JSON.stringify(reviewBundle)),
  };
  save("approval-request.json", approvalRequest);
  if (prepareOnly) {
    log("prepare-only complete; no grant minted and no provider mutation attempted");
  } else {
    const approval = JSON.parse(readFileSync(approvalPath, "utf8"));
    for (const key of [
      "policy_hash",
      "request_hash",
      "environment_ref",
      "provider_id",
      "operation",
      "owner_ref",
      "idempotency_key",
      "review_bundle_sha256",
    ]) {
      if (approval[key] !== approvalRequest[key]) throw new Error(`approval does not bind exact ${key}`);
    }
    if (JSON.stringify(approval.reviewed_facets) !== JSON.stringify(approvalRequest.reviewed_facets)) {
      throw new Error("approval does not bind exact reviewed_facets");
    }
    if (approval.schema_version !== approvalRequest.schema_version || approval.approved !== true) {
      throw new Error("approval file does not carry approved=true under the expected schema");
    }
    let grant;
    let admitted;
    if (config.standing_authority?.enabled === true) {
      const standing = config.standing_authority;
      // wallet.network validates portable authority against the committed
      // chain timestamp, not the host wall clock. A debug AFT fixture may lag
      // wall time by several seconds while it commits its setup blocks. Read
      // the current chain clock immediately before the ceremony so a real
      // WebAuthn receipt and the signed grant share the wallet's clock domain.
      const now = await fixture.readChainTimestampMs();
      const envelope = sealStandingAuthorityEnvelope({
        schema_version: "ioi.foundations.standing-authority-envelope.v1",
        standing_envelope_ref: standing.standing_envelope_ref,
        owner_ref: config.owner_ref,
        bounded_system_ref: standing.bounded_system_ref,
        principal_ref: config.authority_principal_ref,
        audience_ref: "wallet-client://hypervisor/provider-ops",
        authority_scope: "scope:hypervisor.live-route.hypervisor-provider-op",
        facet_template: {
          provider_id: config.provider_id,
          operations: ["create"],
          provider_selector: {
            mode: "exact",
            provider_addresses: [facets.provider_address],
            selection: "only_qualified_bid_from_exact_provider",
          },
          per_operation_deposit_microusd: Math.round(facets.deposit_usd * 1_000_000),
          pricing_ceiling: { amount: facets.ceiling_amount, denom: facets.ceiling_denom },
          sdl_hashes: [facets.sdl_hash],
          image_digests: [facets.image_digest],
          registry_hosts: [facets.registry_host],
          result_destination_refs: [facets.result_credential_ref],
          result_transport_certificate_hashes: [facets.result_tls_server_certificate_sha256],
          auto_topup: false,
          teardown_policy: facets.teardown_policy,
          max_duration_seconds: facets.max_duration_seconds,
        },
        aggregate_bounds: standing.aggregate_bounds,
        not_before_ms: now - 30_000,
        expires_at_ms: now + standing.expires_in_seconds * 1_000,
        revocation_epoch: standing.revocation_epoch,
        trajectory_policy_ref: standing.trajectory_policy_ref,
        trajectory_policy_hash: standing.trajectory_policy_hash,
        approval_mode: "standing_envelope",
        recovery_posture: "recovery_never_widens_or_resets_drawdown",
      });
      const authorizationSubject = {
        kind: "standing_envelope",
        subject_ref: envelope.standing_envelope_ref,
        subject_hash: envelope.body_hash,
        validation_profile_ref: "schema://ioi/foundations/standing-authority-envelope/v1",
      };
      const context = {
        schema_version: "ioi.foundations.approval-ceremony-context.v1",
        approval_ceremony_context_ref: `approval-ceremony-context://aft/${request.plan.campaign_id}`,
        authority_request_ref: `authority-request://aft/${request.plan.campaign_id}`,
        authority_request_body_hash: requestHash,
        authority_review_ref: `review://aft/${request.plan.campaign_id}`,
        authority_review_body_hash: approval.review_bundle_sha256,
        predecessor_authority_review_ref: null,
        predecessor_authority_review_body_hash: null,
        predecessor_authority_request_ref: null,
        predecessor_authority_request_body_hash: null,
        predecessor_authority_review_receipt_ref: null,
        predecessor_authority_review_receipt_hash: null,
        reviewed_representation_hash: approval.review_bundle_sha256,
        principal_ref: whoamiPrincipal.principal_ref,
        acting_subject_ref: "runtime://hypervisor/operator",
        product_session_ref: `session://aft/${request.plan.campaign_id}`,
        origin_binding_ref: "origin://hypervisor/local",
        authorization_subject: authorizationSubject,
        presentation_surface_ref: "wallet-client://hypervisor/local",
        presentation_evidence_profile_ref: "policy://presentation/software-passkey/v1",
        principal_authority_resolution_ref: null,
        principal_authority_resolution_hash: null,
        required_auth_factor_posture_refs: ["auth_factor://passkey/software/trusted-host"],
        required_guardian_surface_refs: [],
        posture_satisfaction_profile_ref: "policy://auth-posture/step-up/v1",
        interaction_mode: "interactive",
        authentication_posture: "step_up",
        receipt_timing: "before_effect",
        policy_decision_receipt_ref: `receipt://aft/review/${request.plan.campaign_id}`,
        policy_decision_receipt_hash: approval.review_bundle_sha256,
        policy_hash: standing.trajectory_policy_hash,
        risk_classes: ["external_spend", "standing_authority"],
        revocation_epoch: standing.revocation_epoch,
        nonce_b64url: randomHex32(),
        issued_at: new Date(now - 1_000).toISOString(),
        expires_at: new Date(now + 4 * 60_000).toISOString(),
        single_use: true,
      };
      const contextHash = approvalCeremonyContextHash(context);
      const factor = await issueSoftwarePasskeyAuthorityFactor({
        daemonUrl,
        session,
        approvalContext: context,
        approvalContextHash: contextHash,
      });
      const factorReceiptId = factor.authority_receipt_ref.split("/").at(-1);
      const factorReceipt = JSON.parse(readFileSync(
        path.join(config.data_dir, "auth-factor-receipts", `${factorReceiptId}.json`),
        "utf8",
      ));
      if (factorReceipt.receipt_hash !== factor.authority_receipt_hash) {
        throw new Error("persisted passkey authority receipt differs from the ceremony response");
      }
      grant = fixture.mintStandingForCapability(config.authority_principal_ref, {
        standingEnvelopeHash: envelope.body_hash,
        policyHash: standing.trajectory_policy_hash,
        nonce: randomHex32(),
        counter: 1,
        issuedAtMs: now,
        expiresAtMs: now + standing.expires_in_seconds * 1_000,
        maxUsages: standing.aggregate_bounds.max_usages,
        maxCumulativeDepositMicrousd: standing.aggregate_bounds.max_cumulative_deposit_microusd,
        maxCumulativeSpendMicrousd: standing.aggregate_bounds.max_cumulative_spend_microusd,
        reviewReceiptHash: approval.review_bundle_sha256,
        approvalCeremonyContextHash: contextHash,
        authFactorReceiptHash: factorReceipt.receipt_hash,
      });
      // Retain the exact non-secret ceremony tuple even when wallet.network refuses it. A clean
      // refusal must be reproducible without weakening the chain validator or recovering secrets.
      save("standing-authority-envelope.json", envelope);
      save("approval-ceremony-context.json", context);
      save("auth-factor-receipt.json", factorReceipt);
      save("grant.json", grant);
      save("software-passkey-evidence.json", {
        profile: factor.profile,
        credential_ref: factor.credential_ref,
        enrollment_receipt_ref: factor.enrollment_receipt_ref,
        authority_receipt_ref: factor.authority_receipt_ref,
        authority_receipt_hash: factor.authority_receipt_hash,
        hardware_backed: false,
      });
      const recorded = await fixture.recordStandingApprovalGrant(
        config.authority_principal_ref,
        grant,
        envelope,
        context,
        factorReceipt,
      );
      save("standing-authority-recording.json", recorded);
      admitted = {
        ...request,
        wallet_standing_approval_grant: grant,
        standing_authority_envelope: envelope,
      };
    } else {
      grant = await fixture.mintRecorded(
        config.authority_principal_ref,
        policyHash,
        requestHash,
        "scope:hypervisor.live-route.hypervisor-provider-op",
      );
      admitted = { ...request, wallet_approval_grant: grant };
    }
    save("grant.json", grant);
    // Proposal admission is intentionally fresh and short-lived. Keep its idempotency identity
    // separate from the durable, owner-approved provider operation key so a clean pre-effect
    // refusal never poisons a later, separately prepared attempt.
    const proposalRequest = {
      ...admitted,
      proposal_idempotency_key: `${config.idempotency_key}.proposal.${randomHex32()}`,
    };
    const proposalResponse = await fetch(`${daemonUrl}/v1/hypervisor/provider-operation-proposals`, {
      method: "POST",
      headers: headers(session),
      body: JSON.stringify(proposalRequest),
    });
    const proposal = await proposalResponse.json();
    save("proposal.json", proposal);
    save("c7-proposal-admission.json", proposal);
    if (!proposalResponse.ok || proposal.ok !== true) throw new Error("daemon proposal issuance refused");
    const fullProviderRequest = { ...admitted, operation_proposal_ref: proposal.proposal_ref };
    let castResponse;
    let cast;
    if (config.workload_effect_broker?.enabled === true) {
      const broker = config.workload_effect_broker;
      const mintedResponse = await fetch(`${daemonUrl}/v1/hypervisor/workload-effect-capabilities`, {
        method: "POST",
        headers: headers(session),
        body: JSON.stringify({
          isolation_binding_ref: broker.isolation_binding_ref,
          isolation_binding_hash: broker.isolation_binding_hash,
          guest_principal_ref: broker.guest_principal_ref,
          proposal_nonce: broker.proposal_nonce,
          resource_ref: broker.resource_ref,
          result_destination_ref: broker.result_destination_ref,
          full_provider_request: fullProviderRequest,
          expires_at_ms: Date.now() + broker.expires_in_seconds * 1_000,
        }),
      });
      const minted = await mintedResponse.json();
      const guestProposal = minted.broker_bundle?.guest_proposal;
      const hostTrigger = minted.broker_bundle?.host_trigger || "";
      if (!mintedResponse.ok || minted.ok !== true || !guestProposal || !hostTrigger.startsWith("wbt_")) {
        throw new Error(`workload effect capability mint refused: ${minted.code || mintedResponse.status}`);
      }
      const guestProposalBytes = Buffer.from(stableStringify(guestProposal));
      save("workload-effect-mint.json", {
        ok: true,
        schema_version: minted.broker_bundle.schema_version,
        capability_ref: guestProposal.capability_ref,
        guest_proposal_hash: sha256(guestProposalBytes),
        host_trigger_hash: sha256(hostTrigger),
        host_trigger_persisted: false,
      });
      const roundtripResponse = await fetch(
        `${daemonUrl}/v1/hypervisor/workload-effect-capabilities/hostile-guest-roundtrip`,
        {
          method: "POST",
          headers: headers(session),
          body: JSON.stringify({ proposal_jcs_base64: guestProposalBytes.toString("base64") }),
        },
      );
      const roundtrip = await roundtripResponse.json();
      if (!roundtripResponse.ok || roundtrip.ok !== true || !roundtrip.proposal_jcs_base64) {
        throw new Error(`hostile guest roundtrip refused: ${roundtrip.code || roundtripResponse.status}`);
      }
      save("workload-effect-isolation-evidence.json", roundtrip.enforcement_evidence);
      const returnedBytes = Buffer.from(roundtrip.proposal_jcs_base64, "base64");
      if (!returnedBytes.equals(guestProposalBytes)) {
        throw new Error("hostile guest changed proposal bytes after daemon quarantine");
      }
      const consumedResponse = await fetch(
        `${daemonUrl}/v1/hypervisor/workload-effect-capabilities/consume`,
        {
          method: "POST",
          headers: headers(),
          body: JSON.stringify({
            proposal_jcs_base64: roundtrip.proposal_jcs_base64,
            host_trigger: hostTrigger,
          }),
        },
      );
      const consumed = await consumedResponse.json();
      save("workload-effect-consumption.json", consumed);
      castResponse = consumedResponse;
      cast = consumed.receipts?.effect_receipt || consumed;
      if (consumedResponse.ok && consumed.ok === true && consumed.receipts?.consumption_receipt) {
        log("cast crossed fresh no-NIC hostile guest and host-triggered governed final invoker");
      }
    } else {
      castResponse = await fetch(`${daemonUrl}/v1/hypervisor/provider-ops`, {
        method: "POST",
        headers: headers(session),
        body: JSON.stringify(fullProviderRequest),
      });
      cast = await castResponse.json();
    }
    save("cast.json", cast);
    save("c7-cast.json", cast);
    dseq = String(
      cast.evidence?.dseq
      || cast.evidence?.provider_native?.dseq
      || String(cast.reason || "").match(/dseq=(\d+)/u)?.[1]
      || "",
    );
    if (!castResponse.ok || cast.ok !== true || !dseq) throw new Error(`cast refused: ${cast.reason || cast.code || castResponse.status}`);

    let started = await postProvider(session, "start");
    save("c7-start.json", started.value);
    if (started.value.ok !== true || started.value.evidence?.endpoint_discovered !== true) throw new Error("provider endpoint was not discovered");
    for (let attempt = 1; started.value.evidence?.workload_readiness_proven !== true; attempt += 1) {
      if (attempt > 120) throw new Error("provider workload readiness was not proven");
      await sleep(Number(config.result_poll_interval_ms || 15_000));
      started = await postProvider(session, "start", `readiness.${attempt}`);
      save("c7-start.json", started.value);
      if (started.value.ok !== true || started.value.evidence?.endpoint_discovered !== true) {
        throw new Error("provider endpoint readiness readback failed");
      }
    }
    const readinessProvenAtMs = Date.now();
    const workloadDeadlineMs = certifiedWorkloadDeadlineMs(
      readinessProvenAtMs,
      request.plan.max_duration_seconds,
    );
    save("workload-deadline.json", {
      schema_version: "ioi.hypervisor.workload-deadline.v1",
      readiness_proven_at: new Date(readinessProvenAtMs).toISOString(),
      max_duration_seconds: request.plan.max_duration_seconds,
      deadline: new Date(workloadDeadlineMs).toISOString(),
    });
    let proof;
    for (let attempt = 1; Date.now() < workloadDeadlineMs; attempt += 1) {
      proof = await postProvider(session, "logs", `logs.${attempt}`);
      save("c7-logs.json", proof.value);
      if (proof.value.ok === true && (!request.plan.result_credential_ref || proof.value.evidence?.workload_result?.retrieved_live === true)) break;
      if (String(proof.value.reason || "").startsWith("akash_workload_campaign_failed")) {
        throw new Error(`provider workload reported a terminal failed campaign: ${proof.value.reason}`);
      }
      const delay = certifiedRemainingDelayMs(
        Date.now(),
        workloadDeadlineMs,
        Number(config.result_poll_interval_ms || 15_000),
      );
      if (delay > 0) await sleep(delay);
    }
    if (Date.now() >= workloadDeadlineMs
        && proof?.value?.evidence?.workload_result?.retrieved_live !== true) {
      throw new Error("authenticated workload result was not retrieved inside max_duration_seconds after readiness");
    }
    if (proof?.value.ok !== true || proof.value.evidence?.lease_state_proof?.retrieved_live !== true) throw new Error("provider-native proof was not retrieved");
    if (request.plan.result_credential_ref && proof.value.evidence?.workload_result?.retrieved_live !== true) throw new Error("authenticated workload result was not retrieved");

    let closed = await postProvider(session, "delete");
    save("c7-delete.json", closed.value);
    for (let attempt = 1; attempt <= 20 && closed.value.evidence?.settlement?.provider_terminal !== true; attempt += 1) {
      await sleep(6_000);
      closed = await postProvider(session, "reconcile", `reconcile.${attempt}`);
      save("c7-reconcile.json", closed.value);
    }
    terminal = closed.value.evidence?.settlement?.provider_terminal === true;
    if (!terminal) throw new Error("provider settlement did not reach terminal readback");
    await capture(session);
    log(`campaign complete, dseq=${dseq}, provider settlement terminal`);
  }
} catch (error) {
  log(`ERROR: ${error.message}`);
  save("error.json", { message: error.message, stack: error.stack });
  process.exitCode = 1;
  if (session && dseq && !terminal) {
    try {
      let closed = await postProvider(session, "delete", "compensation-delete");
      save("c7-delete.json", closed.value);
      for (let attempt = 1; attempt <= 20 && closed.value.evidence?.settlement?.provider_terminal !== true; attempt += 1) {
        await sleep(6_000);
        closed = await postProvider(session, "reconcile", `compensation-reconcile.${attempt}`);
        save("c7-reconcile.json", closed.value);
      }
      terminal = closed.value.evidence?.settlement?.provider_terminal === true;
    } catch (cleanupError) {
      log(`COMPENSATION ERROR: ${cleanupError.message}`);
    }
  }
  if (session) await capture(session).catch(() => {});
} finally {
  if (fixture) await fixture.stop().catch(() => {});
}
