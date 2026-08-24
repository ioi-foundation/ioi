#!/usr/bin/env node
//
// T3 exit, local slice: SECRET-FREE UNATTENDED AUTHORITY, composed live.
//
// Two things were previously true only in separate places. The device-custody
// route mints a real WebAuthn authority factor receipt; the wallet.network
// broker validates, records and revokes a standing grant. The broker gate proved
// the second with a deliberately synthetic receipt, and the composition of the
// two only ever ran inside a PAID campaign. This gate runs that composition
// spend-free, against the real daemon and the real broker.
//
// It then answers the question the existing hostile-guest probe cannot: that
// probe runs with no broker present at all, so it says nothing about a broker
// that is actually holding authority. Here the broker is live, holding a
// recorded standing grant, with a canary seeded inside its own protection
// domain — and the UID-0 guest must reach neither.
//
//   --live      also run the KVM guest probe against the live broker
//   --mutation  prove each assertion fails on its own finding
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

import { startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "../apps/hypervisor/scripts/lib/wallet-network-principal-authority-fixture.mjs";
import { issueSoftwarePasskeyAuthorityFactor } from "../apps/hypervisor/scripts/lib/software-passkey-ceremony.mjs";
import {
  approvalCeremonyContextHash,
  randomHex32,
  sealStandingAuthorityEnvelope,
} from "../apps/hypervisor/scripts/lib/standing-authority-evidence.mjs";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const live = process.argv.includes("--live");
const mutation = process.argv.includes("--mutation");
const principalRef = "org://acme/research";
const findings = [];
const observations = {};
const hash = () => `sha256:${randomHex32()}`;

const record = (name, satisfied, detail) => {
  if (!satisfied) findings.push({ assertion: name, detail });
  return satisfied;
};
const must = (name, satisfied, detail) => {
  if (!record(name, satisfied, detail)) throw new Error(`${name}: ${detail}`);
};

const refused = async (name, run) => {
  try {
    await run();
  } catch (error) {
    return String(error?.message || error).split("\n", 1)[0];
  }
  findings.push({ assertion: name, detail: "the real broker accepted it" });
  throw new Error(`${name}: the real broker accepted what it must refuse`);
};

const buildEnvelope = (marker, now, policyHash) => sealStandingAuthorityEnvelope({
  schema_version: "ioi.foundations.standing-authority-envelope.v1",
  standing_envelope_ref: `standing-envelope://t3-secret-free/${marker}`,
  owner_ref: principalRef,
  bounded_system_ref: "system://aft/u1",
  principal_ref: principalRef,
  audience_ref: "wallet-client://hypervisor/provider-ops",
  authority_scope: "scope:hypervisor.live-route.hypervisor-provider-op",
  facet_template: {
    provider_id: "pacc_18cd245812ad55b9",
    operations: ["create", "delete", "reconcile"],
    provider_selector: {
      mode: "exact",
      provider_addresses: ["akash1aaul837r7en7hpk9wv2svg8u78fdq0t2j2e82z"],
      selection: "only_qualified_bid_from_exact_provider",
    },
    per_operation_deposit_microusd: 1_000_000,
    pricing_ceiling: { amount: "1000", denom: "uact" },
    sdl_hashes: [hash()],
    image_digests: [hash()],
    registry_hosts: ["ghcr.io"],
    result_destination_refs: ["connector://result/aft-u1"],
    result_transport_certificate_hashes: [hash()],
    auto_topup: false,
    teardown_policy: "always_teardown_required",
    max_duration_seconds: 7200,
  },
  aggregate_bounds: {
    max_cumulative_deposit_microusd: 1_000_000,
    max_cumulative_spend_microusd: 1_000_000,
    max_usages: 1,
    max_concurrent_resources: 1,
    max_provider_fanout: 1,
    max_failures: 1,
  },
  not_before_ms: Math.max(0, now - 30_000),
  expires_at_ms: now + 30 * 60_000,
  revocation_epoch: 0,
  trajectory_policy_ref: "policy://aft/u1/trajectory/v1",
  trajectory_policy_hash: policyHash,
  approval_mode: "standing_envelope",
  recovery_posture: "recovery_never_widens_or_resets_drawdown",
});

const buildContext = (marker, envelope, now, policyHash, reviewReceiptHash, devicePrincipalRef) => {
  const authorizationSubject = {
    kind: "standing_envelope",
    subject_ref: envelope.standing_envelope_ref,
    subject_hash: envelope.body_hash,
    validation_profile_ref: "schema://ioi/foundations/standing-authority-envelope/v1",
  };
  return {
    schema_version: "ioi.foundations.approval-ceremony-context.v1",
    approval_ceremony_context_ref: `approval-ceremony-context://t3-secret-free/${marker}`,
    authority_request_ref: `authority-request://t3-secret-free/${marker}`,
    authority_request_body_hash: hash(),
    authority_review_ref: `review://t3-secret-free/${marker}`,
    authority_review_body_hash: hash(),
    predecessor_authority_review_ref: null,
    predecessor_authority_review_body_hash: null,
    predecessor_authority_request_ref: null,
    predecessor_authority_request_body_hash: null,
    predecessor_authority_review_receipt_ref: null,
    predecessor_authority_review_receipt_hash: null,
    reviewed_representation_hash: hash(),
    // The ceremony proves a DEVICE identity; the broker records authority for the
    // ORGANISATION principal. Identity bootstraps custody and never becomes authority,
    // so these two refs are deliberately different planes and must not be collapsed.
    principal_ref: devicePrincipalRef,
    acting_subject_ref: "runtime://hypervisor/operator",
    product_session_ref: `session://t3-secret-free/${marker}`,
    origin_binding_ref: "origin://hypervisor/local",
    authorization_subject: authorizationSubject,
    presentation_surface_ref: "wallet-client://hypervisor/local",
    presentation_evidence_profile_ref: "policy://presentation/passkey/v1",
    principal_authority_resolution_ref: null,
    principal_authority_resolution_hash: null,
    required_auth_factor_posture_refs: ["auth_factor://passkey/operator/device"],
    required_guardian_surface_refs: [],
    posture_satisfaction_profile_ref: "policy://auth-posture/step-up/v1",
    interaction_mode: "interactive",
    authentication_posture: "step_up",
    receipt_timing: "before_effect",
    policy_decision_receipt_ref: `receipt://t3-secret-free/review/${marker}`,
    policy_decision_receipt_hash: reviewReceiptHash,
    policy_hash: policyHash,
    risk_classes: ["external_spend", "standing_authority"],
    revocation_epoch: 0,
    nonce_b64url: randomHex32().replaceAll("+", "-").replaceAll("/", "_"),
    issued_at: new Date(Math.max(0, now - 1_000)).toISOString(),
    expires_at: new Date(now + 4 * 60_000).toISOString(),
    single_use: true,
  };
};

let plane;
let fixture;
try {
  // The software-passkey ceremony drives a headless Chromium virtual authenticator
  // against a real localhost origin, so the daemon must be configured for exactly
  // that relying-party identity before any ceremony starts.
  const webauthnOrigin = "http://localhost:8766";
  plane = await startIsolatedPlane({
    env: {
      IOI_HYPERVISOR_WEBAUTHN_RP_ID: "localhost",
      IOI_HYPERVISOR_WEBAUTHN_ORIGIN: webauthnOrigin,
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: principalRef,
    },
  });
  if (!plane) {
    console.log(JSON.stringify({
      check: "check:secret-free-unattended-authority",
      verdict: "BLOCKED",
      reason: "target/debug/hypervisor-daemon is not built",
    }, null, 2));
    process.exit(0);
  }
  const daemonUrl = plane.daemonUrl;
  const daemonLog = readFileSync(join(plane.dataDir, "isolated-daemon.log"), "utf8");
  const bootstrapToken = (daemonLog.match(/(ioi_bootstrap_[0-9a-f]+)/u) || [])[1];
  must("an isolated daemon published a bootstrap token", !!bootstrapToken, "no bootstrap token in the daemon log");
  const bootstrap = await fetch(`${daemonUrl}/v1/hypervisor/auth/bootstrap`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: bootstrapToken, password: "t3-secret-free-authority" }),
  }).then((response) => response.json());
  const session = bootstrap.session_token;
  must("an operator session was issued", typeof session === "string" && session.length > 0, JSON.stringify(bootstrap).slice(0, 200));

  fixture = await startRealWalletNetworkPrincipalAuthorityFixture({ wallClockChain: true });
  const now = await fixture.readChainTimestampMs();
  const marker = randomHex32().slice(0, 16);
  const policyHash = hash();
  const reviewReceiptHash = hash();
  const envelope = buildEnvelope(marker, now, policyHash);
  const whoami = await fetch(`${daemonUrl}/v1/hypervisor/auth/whoami`, {
    headers: { cookie: `ioi_session=${session}` },
  }).then((response) => response.json());
  const devicePrincipalRef = whoami?.principal?.principal_ref;
  must("the daemon resolved a device identity principal for the ceremony",
    typeof devicePrincipalRef === "string" && devicePrincipalRef.startsWith("user://"),
    JSON.stringify(whoami).slice(0, 200));
  must("the device identity is not the authority principal the broker records",
    devicePrincipalRef !== principalRef, `both are ${devicePrincipalRef}`);
  observations.device_principal_ref = devicePrincipalRef;
  observations.authority_principal_ref = principalRef;
  const context = buildContext(marker, envelope, now, policyHash, reviewReceiptHash, devicePrincipalRef);
  const contextHash = approvalCeremonyContextHash(context);

  // ------------------------------------------------------- the real ceremony
  const ceremony = await issueSoftwarePasskeyAuthorityFactor({
    daemonUrl, session, approvalContext: context, approvalContextHash: contextHash, webauthnOrigin,
  });
  const receiptId = ceremony.authority_receipt_ref.split("/").at(-1);
  const factorReceipt = JSON.parse(readFileSync(
    join(plane.dataDir, "auth-factor-receipts", `${receiptId}.json`), "utf8",
  ));
  must("the daemon persisted the exact ceremony receipt it returned",
    factorReceipt.receipt_hash === ceremony.authority_receipt_hash,
    `persisted=${factorReceipt.receipt_hash} returned=${ceremony.authority_receipt_hash}`);
  must("a real WebAuthn authority ceremony minted the factor receipt, not a fixture seal",
    factorReceipt.factor_kind === "passkey"
      && factorReceipt.purpose === "standing_effect_authority"
      && factorReceipt.user_verification === "required_and_verified",
    JSON.stringify({ kind: factorReceipt.factor_kind, purpose: factorReceipt.purpose }));
  must("identity remained separate from effect authority at the ceremony",
    factorReceipt.effect_authority_created === false, "the ceremony claimed effect authority");
  must("the receipt binds the exact approval-ceremony context",
    factorReceipt.approval_ceremony_context_hash === contextHash
      && factorReceipt.authorization_subject?.subject_hash === envelope.body_hash,
    JSON.stringify(factorReceipt.authorization_subject));
  observations.factor_receipt_origin = "real_webauthn_ceremony_at_the_daemon_device_route";

  const mintGrant = (overrides = {}) => fixture.mintStandingForCapability(principalRef, {
    standingEnvelopeHash: envelope.body_hash,
    policyHash,
    nonce: randomHex32(),
    counter: 1,
    issuedAtMs: now,
    expiresAtMs: now + 20 * 60_000,
    maxUsages: 1,
    maxCumulativeDepositMicrousd: 1_000_000,
    maxCumulativeSpendMicrousd: 1_000_000,
    reviewReceiptHash,
    approvalCeremonyContextHash: contextHash,
    authFactorReceiptHash: factorReceipt.receipt_hash,
    ...overrides,
  });

  // -------------------------------------- the real broker consumes the receipt
  const recorded = await fixture.recordStandingApprovalGrant(
    principalRef, mintGrant(), envelope, context, factorReceipt,
  );
  must("the real broker recorded the standing grant bound to the real ceremony receipt",
    recorded.ok === true && recorded.standing_envelope_hash === envelope.body_hash.slice(7)
      || recorded.standing_envelope_hash === envelope.body_hash.replace(/^sha256:/u, ""),
    JSON.stringify(recorded));
  observations.standing_grant_hash = recorded.standing_grant_hash;

  // ------------------------------------------------ negatives, at the broker
  const refusals = {};
  refusals.substituted_receipt_hash = await refused(
    "the broker refuses a grant bound to a receipt hash the ceremony never produced",
    () => fixture.recordStandingApprovalGrant(
      principalRef, mintGrant({ authFactorReceiptHash: hash(), nonce: randomHex32() }), envelope, context, factorReceipt,
    ),
  );
  refusals.tampered_receipt_body = await refused(
    "the broker refuses a receipt whose body no longer hashes to what the grant names",
    () => fixture.recordStandingApprovalGrant(
      principalRef, mintGrant({ nonce: randomHex32() }), envelope, context,
      { ...factorReceipt, user_verification: "not_required" },
    ),
  );
  refusals.foreign_context = await refused(
    "the broker refuses a receipt minted for a different approval-ceremony context",
    () => {
      const other = buildContext(randomHex32().slice(0, 16), envelope, now, policyHash, reviewReceiptHash, devicePrincipalRef);
      return fixture.recordStandingApprovalGrant(
        principalRef, mintGrant({ approvalCeremonyContextHash: approvalCeremonyContextHash(other), nonce: randomHex32() }),
        envelope, other, factorReceipt,
      );
    },
  );
  refusals.widened_envelope = await refused(
    "the broker refuses a grant that widens the envelope the receipt authorised",
    () => {
      const widened = buildEnvelope(randomHex32().slice(0, 16), now, policyHash);
      return fixture.recordStandingApprovalGrant(
        principalRef, mintGrant({ standingEnvelopeHash: widened.body_hash, nonce: randomHex32() }),
        widened, context, factorReceipt,
      );
    },
  );

  // The daemon side of replay: the consumed WebAuthn ceremony cannot be reused.
  const replay = await fetch(`${daemonUrl}/v1/hypervisor/auth/passkeys/authority/finish`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: `ioi_session=${session}` },
    body: JSON.stringify({ ceremony_id: factorReceipt.ceremony_id, credential: {} }),
  });
  const replayBody = await replay.json();
  must("the consumed authority ceremony cannot be replayed at the daemon",
    replay.status !== 200 && replayBody.ok !== true, `status=${replay.status} body=${JSON.stringify(replayBody).slice(0, 160)}`);
  refusals.ceremony_replay = replayBody.code || `http_${replay.status}`;
  observations.broker_refusals = refusals;

  // ----------------------------- worker-root non-possession, broker LIVE
  let guestProbe = "not_run";
  if (live) {
    const canary = `ioi-t3-broker-canary-${randomBytes(24).toString("hex")}`;
    writeFileSync(join(fixture.resourceDir, "ioi-t3-broker-canary.txt"), `${canary}\n`, { mode: 0o600 });
    const rpcPort = new URL(fixture.env.IOI_WALLET_NETWORK_RPC_ADDR).port;
    must("the live broker published an RPC port to probe against", !!rpcPort, fixture.env.IOI_WALLET_NETWORK_RPC_ADDR);
    // The FULL test path, because `--exact` on a bare name matches nothing and
    // cargo still exits 0 — a green probe that ran no test is the exact defect
    // this gate exists to catch. The run count below is what makes it a check.
    const probe = spawnSync("cargo", [
      "test", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon",
      "microvm::tests::root_guest_cannot_reach_a_live_authority_broker_or_its_material",
      "--", "--exact", "--ignored", "--nocapture",
    ], {
      cwd: repo,
      encoding: "utf8",
      env: {
        ...process.env,
        IOI_T3_BROKER_RPC_PORT: rpcPort,
        IOI_T3_BROKER_DIR: fixture.resourceDir,
        IOI_T3_BROKER_CANARY: canary,
      },
    });
    const probeOutput = `${probe.stdout || ""}${probe.stderr || ""}`;
    const ran = probeOutput.match(/test result: ok\. (\d+) passed; (\d+) failed/u);
    must("the live-broker guest probe actually executed",
      !!ran && Number(ran[1]) === 1 && Number(ran[2]) === 0,
      probeOutput.split("\n").slice(-25).join("\n"));
    must("the UID-0 guest reached neither the live authority broker nor its protection domain",
      probe.status === 0, probeOutput.split("\n").slice(-25).join("\n"));
    guestProbe = "passed";

    // The probing guest consumed nothing: the grant the broker recorded before
    // the probe is still exactly one live, revocable standing authority.
    const revoked = await fixture.revokeStandingApprovalGrant(principalRef, recorded.standing_grant_hash);
    must("the standing grant survived the hostile guest unchanged and still revokes",
      revoked.standing_grant_status === "revoked", JSON.stringify(revoked));
    observations.standing_grant_status_after_guest = revoked.standing_grant_status;
  } else {
    const revoked = await fixture.revokeStandingApprovalGrant(principalRef, recorded.standing_grant_hash);
    must("the recorded standing grant revokes terminally",
      revoked.standing_grant_status === "revoked", JSON.stringify(revoked));
    observations.standing_grant_status_after_guest = revoked.standing_grant_status;
  }
  observations.live_broker_guest_probe = guestProbe;

  // A revoked grant cannot be resurrected by re-recording the same tuple.
  refusals.record_after_revocation = await refused(
    "a revoked standing grant cannot be resurrected by re-recording the same ceremony tuple",
    () => fixture.recordStandingApprovalGrant(
      principalRef, mintGrant({ nonce: randomHex32() }), envelope, context, factorReceipt,
    ),
  );

  if (mutation) {
    // Mutation-test this gate against its own finding: each assertion helper
    // must fail when handed the outcome it exists to forbid. The planted
    // findings are discarded afterwards — a self-test must not be able to
    // manufacture a real failure, nor to hide one raised before it.
    const realFindings = findings.length;
    const mutations = [];
    let raised = false;
    try { must("planted", false, "planted"); } catch { raised = true; }
    mutations.push({ mutation: "assertion_handed_a_false_finding", detected_by: raised ? "must" : "NOTHING" });
    if (!raised) throw new Error("the assertion helper cannot fail on its own finding");
    raised = false;
    try { await refused("planted", async () => {}); } catch { raised = true; }
    mutations.push({ mutation: "refusal_probe_handed_an_acceptance", detected_by: raised ? "refused" : "NOTHING" });
    if (!raised) throw new Error("the refusal probe cannot fail on its own finding");
    observations.mutations = mutations;
    findings.length = realFindings;
  }

  console.log(JSON.stringify({
    check: "check:secret-free-unattended-authority",
    verdict: findings.length === 0 ? "PASS" : "FAIL",
    ...observations,
    factor_profile: "software_passkey_trusted_host_not_hardware_backed",
    // A label claims only what was checked. Without --live no guest ran at all,
    // and saying otherwise would be exactly the inflation this program exists to
    // refuse.
    claim_boundary: guestProbe === "passed"
      ? "A real WebAuthn authority ceremony at the daemon device route produced the factor receipt the real wallet.network broker required before recording one standing envelope, and a UID-0 KVM guest reached neither that live broker nor any byte of its protection domain. The passkey is a software authenticator on a trusted host: this claims no hardware-backed custody, and no resistance to a compromised host kernel, VMM, daemon, or broker process."
      : "A real WebAuthn authority ceremony at the daemon device route produced the factor receipt the real wallet.network broker required before recording one standing envelope, and the broker refused every tested substitution, tamper, foreign-context, widening, replay and post-revocation reuse. NO GUEST RAN: worker non-possession against the live broker is claimed only by the --live lane, which did not run here.",
    findings,
  }, null, 2));
  process.exit(findings.length === 0 ? 0 : 1);
} catch (error) {
  console.error(JSON.stringify({
    check: "check:secret-free-unattended-authority",
    verdict: "FAIL",
    error: String(error?.message || error).split("\n").slice(0, 20).join("\n"),
    findings,
  }, null, 2));
  process.exitCode = 1;
} finally {
  await fixture?.stop();
  await plane?.stop();
}
