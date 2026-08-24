#!/usr/bin/env node
//
// STAGING EVIDENCE for retiring the development plaintext recovery credential.
// It authorises no deletion and performs none.
//
// The owner held that retirement behind one proof: that the passkey/recovery
// path carries a throwaway account end to end WITHOUT the plaintext credential.
// This gate splits that into the half that is provable today and the half that
// is not, and refuses to let the second half read as passing.
//
//   PROVABLE   a throwaway account enrols one passkey, then the password is
//              dropped for the rest of the run: the passkey alone mints a
//              session, drives a full authority ceremony, and the real
//              wallet.network broker records a standing envelope from it.
//   ABSENT     there is NO account-recovery route on the daemon. Not "it
//              failed" — it does not exist, and this gate enumerates the
//              registered auth surface to say so as a typed absence.
//   CONSEQUENCE with the only credential revoked and the password withheld, the
//              account has no way back. Deleting the plaintext credential today
//              is therefore irreversible, which is exactly what the owner's
//              sealed-offline-export condition exists to fix.
//
//   --mutation  prove each finding fails on its own
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

import { startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "../apps/hypervisor/scripts/lib/wallet-network-principal-authority-fixture.mjs";
import { openSoftwarePasskeyDevice } from "../apps/hypervisor/scripts/lib/software-passkey-ceremony.mjs";
import {
  approvalCeremonyContextHash,
  randomHex32,
  sealStandingAuthorityEnvelope,
} from "../apps/hypervisor/scripts/lib/standing-authority-evidence.mjs";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");
const principalRef = "org://acme/research";
const findings = [];
const observations = {};
const hash = () => `sha256:${randomHex32()}`;

const must = (name, satisfied, detail) => {
  if (!satisfied) {
    findings.push({ assertion: name, detail });
    throw new Error(`${name}: ${detail}`);
  }
  return true;
};

// The registered auth surface, read from the daemon's own router. An absence
// claimed from a grep of a guess is not a typed absence; this reads the exact
// file that decides which routes exist.
function registeredAuthRoutes() {
  const router = readFileSync(join(repo, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
  return [...router.matchAll(/"(\/v1\/hypervisor\/auth[^"]*)"/gu)].map((m) => m[1]).sort();
}

let plane;
let fixture;
let device;
try {
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
      check: "check:passkey-only-authority",
      verdict: "BLOCKED",
      reason: "target/debug/hypervisor-daemon is not built",
    }, null, 2));
    process.exit(0);
  }
  const daemonUrl = plane.daemonUrl;

  // ---- the throwaway account, created with a password that is then dropped ----
  const daemonLog = readFileSync(join(plane.dataDir, "isolated-daemon.log"), "utf8");
  const bootstrapToken = (daemonLog.match(/(ioi_bootstrap_[0-9a-f]+)/u) || [])[1];
  must("the throwaway plane published a bootstrap token", !!bootstrapToken, "no bootstrap token in the daemon log");
  const throwawayPassword = `throwaway-${randomBytes(18).toString("hex")}`;
  const bootstrap = await fetch(`${daemonUrl}/v1/hypervisor/auth/bootstrap`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: bootstrapToken, password: throwawayPassword }),
  }).then((response) => response.json());
  const passwordSession = bootstrap.session_token;
  must("the throwaway account exists", typeof passwordSession === "string" && passwordSession.length > 0,
    JSON.stringify(bootstrap).slice(0, 200));

  device = await openSoftwarePasskeyDevice({ daemonUrl, session: passwordSession, webauthnOrigin });
  const enrolled = await device.register();
  must("one passkey is enrolled on the throwaway account",
    String(enrolled.credential_ref || "").length > 0 && enrolled.effect_authority_created === false,
    JSON.stringify(enrolled).slice(0, 200));
  observations.enrolled_credential_ref = enrolled.credential_ref;

  // ---- from here the plaintext credential is gone for this run ----
  const withheldPassword = throwawayPassword;
  const sealedAway = "the throwaway password is not used again in this run";
  observations.plaintext_credential_after_enrolment = sealedAway;

  // The account's address identifies which principal to challenge. It is not a
  // secret and it is not the plaintext credential being retired.
  const principalRecords = readdirSync(join(plane.dataDir, "principals"))
    .filter((name) => name.endsWith(".json"))
    .map((name) => JSON.parse(readFileSync(join(plane.dataDir, "principals", name), "utf8")))
    .filter((record) => record.status === "active");
  must("the throwaway plane holds exactly one active principal", principalRecords.length === 1,
    `observed ${principalRecords.length} active principals`);
  const accountEmail = principalRecords[0].email;
  must("the throwaway account has a resolvable address to be challenged by",
    typeof accountEmail === "string" && accountEmail.includes("@"), JSON.stringify(principalRecords[0]).slice(0, 160));
  // The daemon stores only a password HASH; the plaintext credential under
  // discussion is the operator's on-disk password FILE, not daemon state.
  observations.daemon_stores_password_plaintext = Object.hasOwn(principalRecords[0], "password_hash")
    && !Object.hasOwn(principalRecords[0], "password");
  observations.account_identifier_kind = "email address — an identifier, not a credential";
  const passkeyLogin = await device.login({ email: accountEmail });
  must("the passkey alone mints a session, with no password presented",
    passkeyLogin.ok === true && typeof passkeyLogin.session_token === "string"
      && passkeyLogin.session_token !== passwordSession,
    JSON.stringify(passkeyLogin).slice(0, 200));
  must("the passkey login created no effect authority by itself",
    passkeyLogin.effect_authority_created !== true, JSON.stringify(passkeyLogin).slice(0, 200));

  // ---- passkey-derived session drives a real authority ceremony and the broker ----
  fixture = await startRealWalletNetworkPrincipalAuthorityFixture({ wallClockChain: true });
  const now = await fixture.readChainTimestampMs();
  const marker = randomHex32().slice(0, 16);
  const policyHash = hash();
  const reviewReceiptHash = hash();
  const envelope = sealStandingAuthorityEnvelope({
    schema_version: "ioi.foundations.standing-authority-envelope.v1",
    standing_envelope_ref: `standing-envelope://passkey-only/${marker}`,
    owner_ref: principalRef,
    bounded_system_ref: "system://aft/u1/passkey-only",
    principal_ref: principalRef,
    audience_ref: "wallet-client://hypervisor/provider-ops",
    authority_scope: "scope:hypervisor.live-route.hypervisor-provider-op",
    facet_template: {
      provider_id: "pacc_18cd245812ad55b9",
      operations: ["create"],
      provider_selector: {
        mode: "exact",
        provider_addresses: ["akash1aaul837r7en7hpk9wv2svg8u78fdq0t2j2e82z"],
        selection: "only_qualified_bid_from_exact_provider",
      },
      per_operation_deposit_microusd: 1_000_000,
      pricing_ceiling: { amount: "1000", denom: "uact" },
      sdl_hashes: [hash()], image_digests: [hash()], registry_hosts: ["ghcr.io"],
      result_destination_refs: ["connector://result/passkey-only"],
      result_transport_certificate_hashes: [hash()],
      auto_topup: false, teardown_policy: "always_teardown_required", max_duration_seconds: 7200,
    },
    aggregate_bounds: {
      max_cumulative_deposit_microusd: 1_000_000, max_cumulative_spend_microusd: 1_000_000,
      max_usages: 1, max_concurrent_resources: 1, max_provider_fanout: 1, max_failures: 1,
    },
    not_before_ms: Math.max(0, now - 30_000),
    expires_at_ms: now + 30 * 60_000,
    revocation_epoch: 0,
    trajectory_policy_ref: "policy://passkey-only/trajectory/v1",
    trajectory_policy_hash: policyHash,
    approval_mode: "standing_envelope",
    recovery_posture: "recovery_never_widens_or_resets_drawdown",
  });
  const authorizationSubject = {
    kind: "standing_envelope",
    subject_ref: envelope.standing_envelope_ref,
    subject_hash: envelope.body_hash,
    validation_profile_ref: "schema://ioi/foundations/standing-authority-envelope/v1",
  };
  const whoami = await fetch(`${daemonUrl}/v1/hypervisor/auth/whoami`, {
    headers: { cookie: `ioi_session=${device.session}` },
  }).then((response) => response.json());
  const devicePrincipalRef = whoami?.principal?.principal_ref;
  must("the passkey session resolves the same device identity",
    typeof devicePrincipalRef === "string" && devicePrincipalRef.startsWith("user://"),
    JSON.stringify(whoami).slice(0, 200));

  const context = {
    schema_version: "ioi.foundations.approval-ceremony-context.v1",
    approval_ceremony_context_ref: `approval-ceremony-context://passkey-only/${marker}`,
    authority_request_ref: `authority-request://passkey-only/${marker}`,
    authority_request_body_hash: hash(),
    authority_review_ref: `review://passkey-only/${marker}`,
    authority_review_body_hash: hash(),
    predecessor_authority_review_ref: null, predecessor_authority_review_body_hash: null,
    predecessor_authority_request_ref: null, predecessor_authority_request_body_hash: null,
    predecessor_authority_review_receipt_ref: null, predecessor_authority_review_receipt_hash: null,
    reviewed_representation_hash: hash(),
    principal_ref: devicePrincipalRef,
    acting_subject_ref: "runtime://hypervisor/operator",
    product_session_ref: `session://passkey-only/${marker}`,
    origin_binding_ref: "origin://hypervisor/local",
    authorization_subject: authorizationSubject,
    presentation_surface_ref: "wallet-client://hypervisor/local",
    presentation_evidence_profile_ref: "policy://presentation/passkey/v1",
    principal_authority_resolution_ref: null, principal_authority_resolution_hash: null,
    required_auth_factor_posture_refs: ["auth_factor://passkey/operator/device"],
    required_guardian_surface_refs: [],
    posture_satisfaction_profile_ref: "policy://auth-posture/step-up/v1",
    interaction_mode: "interactive", authentication_posture: "step_up",
    receipt_timing: "before_effect",
    policy_decision_receipt_ref: `receipt://passkey-only/review/${marker}`,
    policy_decision_receipt_hash: reviewReceiptHash,
    policy_hash: policyHash,
    risk_classes: ["external_spend", "standing_authority"],
    revocation_epoch: 0,
    nonce_b64url: randomHex32(),
    issued_at: new Date(Math.max(0, now - 1_000)).toISOString(),
    expires_at: new Date(now + 4 * 60_000).toISOString(),
    single_use: true,
  };
  const contextHash = approvalCeremonyContextHash(context);
  const authorized = await device.authority(context, contextHash);
  const factorReceipt = JSON.parse(readFileSync(
    join(plane.dataDir, "auth-factor-receipts", `${authorized.receipt_ref.split("/").at(-1)}.json`), "utf8",
  ));
  must("the authority ceremony ran on the passkey-minted session",
    factorReceipt.receipt_hash === authorized.receipt_hash
      && factorReceipt.purpose === "standing_effect_authority",
    JSON.stringify(factorReceipt).slice(0, 200));

  const grant = fixture.mintStandingForCapability(principalRef, {
    standingEnvelopeHash: envelope.body_hash, policyHash, nonce: randomHex32(), counter: 1,
    issuedAtMs: now, expiresAtMs: now + 20 * 60_000, maxUsages: 1,
    maxCumulativeDepositMicrousd: 1_000_000, maxCumulativeSpendMicrousd: 1_000_000,
    reviewReceiptHash, approvalCeremonyContextHash: contextHash,
    authFactorReceiptHash: factorReceipt.receipt_hash,
  });
  const recorded = await fixture.recordStandingApprovalGrant(principalRef, grant, envelope, context, factorReceipt);
  must("the real broker recorded standing authority rooted in a passkey-only session",
    recorded.ok === true, JSON.stringify(recorded).slice(0, 200));
  observations.standing_grant_hash = recorded.standing_grant_hash;
  observations.password_used_after_enrolment = false;

  // ---- the typed absence ----
  const authRoutes = registeredAuthRoutes();
  const recoveryShaped = authRoutes.filter((route) => /recover|reset|restore/u.test(route));
  observations.registered_auth_routes = authRoutes;
  must("no account-recovery route is registered — recorded as a typed absence, not a failure",
    recoveryShaped.length === 0, `unexpected recovery-shaped auth routes: ${recoveryShaped.join(", ")}`);
  observations.account_recovery_route = "ABSENT — the daemon registers no account-recovery ceremony";
  observations.recovery_attempts_route_is_not_account_recovery =
    "/v1/hypervisor/recovery-attempts is the WS-9 ENVIRONMENT incident projection and cannot recover an account";

  // ---- the consequence ----
  // Read the credential the daemon actually holds rather than reconstructing an
  // id from the enrolment reply: the route keys on the record's own ref tail.
  const listed = await fetch(`${daemonUrl}/v1/hypervisor/auth/passkeys`, {
    headers: { cookie: `ioi_session=${device.session}` },
  }).then((response) => response.json());
  const held = (listed.factors || []).filter((entry) => entry.status !== "revoked");
  must("the daemon holds exactly one active credential for this account", held.length === 1,
    JSON.stringify(listed).slice(0, 300));
  const credentialRefTail = String(held[0].credential_ref || "").split("/").at(-1);
  observations.revoked_credential_ref = held[0].credential_ref;
  // The custody boundary the enrolment itself declares.
  observations.credential_can_hold_grant = held[0].can_hold_grant;
  observations.credential_can_release_secret = held[0].can_release_secret;
  const revoked = await fetch(
    `${daemonUrl}/v1/hypervisor/auth/passkeys/${credentialRefTail}`,
    { method: "DELETE", headers: { cookie: `ioi_session=${device.session}` } },
  );
  const revokedBody = await revoked.json().catch(() => ({}));
  must("the only enrolled credential can be revoked",
    revoked.status === 200 && revokedBody.ok === true, `status=${revoked.status} ${JSON.stringify(revokedBody).slice(0, 160)}`);
  must("revocation created or changed no effect authority",
    revokedBody.effect_authority_changed !== true, JSON.stringify(revokedBody).slice(0, 160));
  const afterRevocation = await device.login({ adopt: false, email: accountEmail });
  must("with its only credential revoked, the passkey can no longer mint a session",
    afterRevocation.ok === false, JSON.stringify(afterRevocation).slice(0, 200));
  observations.passkey_login_after_revocation = afterRevocation.code || `stage_${afterRevocation.stage}`;
  observations.remaining_paths_without_the_plaintext_credential = 0;
  observations.withheld_password_length = withheldPassword.length;

  if (mutation) {
    const mutations = [];
    let raised = false;
    try { must("planted", false, "planted"); } catch { raised = true; }
    mutations.push({ mutation: "assertion_handed_a_false_finding", detected_by: raised ? "must" : "NOTHING" });
    if (!raised) throw new Error("the assertion helper cannot fail on its own finding");
    // The absence claim must be falsifiable: a recovery-shaped route would break it.
    const planted = [...authRoutes, "/v1/hypervisor/auth/account-recovery/start"].filter((r) => /recover|reset|restore/u.test(r));
    mutations.push({
      mutation: "a_recovery_route_appears_in_the_router",
      detected_by: planted.length > 0 ? "typed_absence_assertion" : "NOTHING",
    });
    if (planted.length === 0) throw new Error("the absence assertion cannot detect a recovery route");
    observations.mutations = mutations;
    findings.length = 0;
  }

  console.log(JSON.stringify({
    check: "check:passkey-only-authority",
    verdict: findings.length === 0 ? "PASS" : "FAIL",
    ...observations,
    retirement_precondition: "NOT MET — the owner's condition is an end-to-end RECOVERY proof, and no account-recovery path exists to prove. What is proven here is the narrower fact that passkey-rooted authority does not need the plaintext credential once a credential is already enrolled.",
    claim_boundary: "Software authenticator on a trusted host; no hardware-backed custody claim. The throwaway account's password was used only to bootstrap and enrol, and never after. This gate deletes no credential and authorises no deletion.",
    findings,
  }, null, 2));
  process.exit(findings.length === 0 ? 0 : 1);
} catch (error) {
  console.error(JSON.stringify({
    check: "check:passkey-only-authority",
    verdict: "FAIL",
    error: String(error?.message || error).split("\n").slice(0, 12).join("\n"),
    findings,
  }, null, 2));
  process.exitCode = 1;
} finally {
  await device?.close();
  await fixture?.stop();
  await plane?.stop();
}
