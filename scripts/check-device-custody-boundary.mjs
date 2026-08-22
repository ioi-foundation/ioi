#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const routePath = join(
  repo,
  "crates/node/src/bin/hypervisor_daemon_routes/device_custody_routes.rs",
);
const lifecyclePath = join(
  repo,
  "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs",
);
const daemonPath = join(repo, "crates/node/src/bin/hypervisor-daemon.rs");
const routeSource = readFileSync(routePath, "utf8");
const lifecycleSource = readFileSync(lifecyclePath, "utf8");
const daemonSource = readFileSync(daemonPath, "utf8");

function inspect(routes, lifecycle, daemon = daemonSource) {
  const findings = [];
  const requireRoute = (text, code) => {
    if (!routes.includes(text)) findings.push(code);
  };
  const requireLifecycle = (text, code) => {
    if (!lifecycle.includes(text)) findings.push(code);
  };
  const requireDaemon = (text, code) => {
    if (!daemon.includes(text)) findings.push(code);
  };

  for (const [text, code] of [
    ["start_passkey_registration", "registration_ceremony_missing"],
    ["finish_passkey_registration", "registration_verification_missing"],
    ["start_passkey_authentication", "authentication_ceremony_missing"],
    ["finish_passkey_authentication", "authentication_verification_missing"],
    ['.filter(|record| record["status"].as_str() == Some("active"))', "revocation_not_enforced"],
    ["passkey_credential_already_revoked", "durable_revocation_missing"],
    ["passkey_ceremony_already_consumed", "ceremony_replay_refusal_missing"],
    ["persist_record_durable(data_dir, CEREMONY_FAMILY", "durable_ceremony_state_missing"],
    ['"user_verification": "required_and_verified"', "user_verification_receipt_missing"],
    ["if !result.user_verified()", "user_verification_enforcement_missing"],
    ['"effect_authority_created": false', "identity_authority_separation_missing"],
    ['"effect_authority_changed": false', "revocation_authority_separation_missing"],
    ["passkey_counter_persistence_failed", "counter_before_session_missing"],
    ['issue_session(&st.data_dir, principal_id, "passkey")', "passkey_session_issue_missing"],
    ["identity_factor_receipt_never_claims_effect_authority", "identity_authority_regression_missing"],
    ["consumed_ceremony_is_durable_and_never_replayable", "ceremony_replay_regression_missing"],
    ["revoked_passkeys_are_not_authentication_candidates", "revocation_regression_missing"],
    ["IOI-APPROVAL-CEREMONY-CONTEXT-V1\\0", "authority_context_domain_missing"],
    ["options.public_key.challenge = challenge.to_vec().into()", "authority_context_not_used_as_challenge"],
    ['consume_ceremony(&st.data_dir, ceremony_id, "effect_authority")', "authority_ceremony_replay_refusal_missing"],
    ['"standing_effect_authority"', "authority_factor_receipt_missing"],
    ["standing_authority_context_is_the_exact_passkey_challenge", "authority_context_regression_missing"],
    ["authority_context_refuses_future_or_overlong_validity", "authority_context_validity_regression_missing"],
    ["authority_context_refuses_malformed_optional_hashes", "authority_context_optional_hash_regression_missing"],
    ["authority_factor_receipt_binds_context_but_creates_no_authority", "authority_factor_receipt_regression_missing"],
  ]) {
    requireRoute(text, code);
  }

  requireLifecycle(
    '"/v1/hypervisor/auth/passkeys/login/start"',
    "passkey_login_start_not_reachable",
  );
  requireLifecycle(
    '"/v1/hypervisor/auth/passkeys/login/finish"',
    "passkey_login_finish_not_reachable",
  );
  requireDaemon(
    '"/v1/hypervisor/auth/passkeys/authority/start"',
    "passkey_authority_start_not_reachable",
  );
  requireDaemon(
    '"/v1/hypervisor/auth/passkeys/authority/finish"',
    "passkey_authority_finish_not_reachable",
  );

  for (const route of [
    "/v1/hypervisor/auth/passkeys/register/start",
    "/v1/hypervisor/auth/passkeys/register/finish",
    "/v1/hypervisor/auth/passkeys",
    "/v1/hypervisor/auth/passkeys/authority/start",
    "/v1/hypervisor/auth/passkeys/authority/finish",
  ]) {
    const exemption = `\"${route}\",`;
    if (lifecycle.includes(exemption)) {
      findings.push("passkey_management_route_auth_gate_bypassed");
    }
  }

  const loginFinishStart = routes.indexOf("pub(crate) async fn handle_login_finish");
  const loginFinish = routes.slice(loginFinishStart);
  const consumeIndex = loginFinish.indexOf(
    'consume_ceremony(&st.data_dir, ceremony_id, "authentication")',
  );
  const verifyIndex = loginFinish.indexOf("finish_passkey_authentication");
  const counterIndex = loginFinish.indexOf("passkey_counter_persistence_failed");
  const sessionIndex = loginFinish.indexOf(
    'issue_session(&st.data_dir, principal_id, "passkey")',
  );
  if (consumeIndex < 0 || verifyIndex < 0 || consumeIndex > verifyIndex) {
    findings.push("challenge_not_consumed_before_verification");
  }
  if (counterIndex < 0 || sessionIndex < 0 || counterIndex > sessionIndex) {
    findings.push("credential_counter_not_durable_before_session");
  }

  const authorityFinishStart = routes.indexOf(
    "pub(crate) async fn handle_authority_finish",
  );
  const authorityFinishEnd = routes.indexOf(
    "pub(crate) async fn handle_login_start",
    authorityFinishStart,
  );
  const authorityFinish = routes.slice(authorityFinishStart, authorityFinishEnd);
  const authorityConsumeIndex = authorityFinish.indexOf(
    'consume_ceremony(&st.data_dir, ceremony_id, "effect_authority")',
  );
  const authorityVerifyIndex = authorityFinish.indexOf(
    "finish_passkey_authentication",
  );
  const authorityReceiptIndex = authorityFinish.indexOf("persist_factor_receipt");
  if (
    authorityFinishStart < 0 ||
    authorityConsumeIndex < 0 ||
    authorityVerifyIndex < 0 ||
    authorityConsumeIndex > authorityVerifyIndex
  ) {
    findings.push("authority_challenge_not_consumed_before_verification");
  }
  if (authorityReceiptIndex < authorityVerifyIndex) {
    findings.push("authority_factor_receipt_emitted_before_verification");
  }

  if (/IOI_WALLET_SECRET_PASS|IOI_C7_PASSWORD|local-mode|provider_routes|governed_authority/u.test(routes)) {
    findings.push("effect_secret_or_authority_imported_into_identity_factor_plane");
  }
  if (routes.includes('"effect_authority_created": true')) {
    findings.push("identity_authority_separation_missing");
  }
  return [...new Set(findings)].sort();
}

function runFocusedTests() {
  const result = spawnSync(
    "cargo",
    [
      "test",
      "-p",
      "ioi-node",
      "--bin",
      "hypervisor-daemon",
      "device_custody_routes::tests",
      "--",
      "--nocapture",
    ],
    { cwd: repo, encoding: "utf8", stdio: "inherit" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

if (process.argv.includes("--mutation")) {
  const mutations = [
    {
      name: "make_revoked_passkeys_authentication_candidates",
      source: routeSource.replace(
        '.filter(|record| record["status"].as_str() == Some("active"))',
        ".filter(|_record| true)",
      ),
      expected: "revocation_not_enforced",
    },
    {
      name: "claim_identity_factor_creates_effect_authority",
      source: routeSource.replace(
        '"effect_authority_created": false',
        '"effect_authority_created": true',
      ),
      expected: "identity_authority_separation_missing",
    },
    {
      name: "import_wallet_unlock_into_identity_factor_plane",
      source: `${routeSource}\n// planted: IOI_WALLET_SECRET_PASS\n`,
      expected: "effect_secret_or_authority_imported_into_identity_factor_plane",
    },
    {
      name: "replace_bound_authority_challenge_with_random_challenge",
      source: routeSource.replace(
        "options.public_key.challenge = challenge.to_vec().into()",
        "let _ = challenge",
      ),
      expected: "authority_context_not_used_as_challenge",
    },
    {
      name: "make_authority_factor_claim_effect_authority",
      source: routeSource.replace(
        '"standing_effect_authority",\n        Some((context, context_hash)),',
        '"standing_effect_authority",\n        Some((context, context_hash)),\n        // planted: "effect_authority_created": true',
      ),
      expected: "identity_authority_separation_missing",
    },
  ];
  const survived = mutations.filter(
    (mutation) => !inspect(mutation.source, lifecycleSource).includes(mutation.expected),
  );
  if (survived.length > 0) {
    console.error(
      JSON.stringify(
        {
          check: "mutate:device-custody-boundary",
          verdict: "FAIL",
          survived: survived.map(({ name, expected }) => ({ name, expected })),
        },
        null,
        2,
      ),
    );
    process.exit(1);
  }
  console.log(
    JSON.stringify(
      {
        check: "mutate:device-custody-boundary",
        verdict: "PASS",
        mutations: mutations.map(({ name, expected }) => ({ name, detected_by: expected })),
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

const findings = inspect(routeSource, lifecycleSource);
if (findings.length > 0) {
  console.error(
    JSON.stringify(
      { check: "check:device-custody-boundary", verdict: "FAIL", findings },
      null,
      2,
    ),
  );
  process.exit(1);
}

runFocusedTests();
console.log(
  JSON.stringify(
    {
      check: "check:device-custody-boundary",
      verdict: "PASS",
      claim_boundary:
        "Passkeys authenticate a Hypervisor operator identity and a distinct single-use, exact-context effect-consent ceremony. The factor receipt creates no effect authority; a separately signed standing envelope and isolated wallet broker remain required before passwordless unattended effects can be claimed.",
    },
    null,
    2,
  ),
);
