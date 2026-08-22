#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const walletPath = join(repo, "crates/services/src/wallet_network/support.rs");
const lifecyclePath = join(
  repo,
  "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs",
);
const providerPath = join(
  repo,
  "crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs",
);
const storagePath = join(
  repo,
  "crates/node/src/bin/hypervisor_daemon_routes/storage_backend_routes.rs",
);

const sources = {
  wallet: readFileSync(walletPath, "utf8"),
  lifecycle: readFileSync(lifecyclePath, "utf8"),
  provider: readFileSync(providerPath, "utf8"),
  storage: readFileSync(storagePath, "utf8"),
};

function inspect({ wallet, lifecycle, provider, storage }) {
  const findings = [];
  const requireText = (source, text, code) => {
    if (!source.includes(text)) findings.push(code);
  };

  requireText(wallet, 'const SECRET_CUSTODY_PROFILE_ENV: &str = "IOI_SECRET_CUSTODY_PROFILE";', "wallet_profile_selection_missing");
  requireText(wallet, 'profile == Some("development_cooperative")', "wallet_development_only_fallback_missing");
  requireText(wallet, "profile.is_none() && development_test_fixture", "wallet_unspecified_profile_not_refused_in_release");
  requireText(wallet, "conforming profiles have no local-mode fallback", "wallet_fail_closed_reason_missing");
  requireText(wallet, "development_profile_is_the_only_well_known_fallback", "wallet_profile_regression_test_missing");
  requireText(lifecycle, 'std::env::var("IOI_SECRET_CUSTODY_PROFILE")', "daemon_profile_selection_missing");
  requireText(lifecycle, 'profile == Some("development_cooperative")', "daemon_development_only_fallback_missing");
  requireText(lifecycle, "profile.is_none() && development_test_fixture", "daemon_unspecified_profile_not_refused_in_release");
  requireText(lifecycle, '"custody-key-unavailable"', "daemon_unavailable_custody_label_missing");
  requireText(lifecycle, "conforming_profiles_never_use_the_well_known_fallback", "daemon_profile_regression_test_missing");
  requireText(provider, "super::lifecycle_routes::scm_key_source()", "provider_custody_label_not_server_derived");
  requireText(storage, "custody key unavailable for selected profile", "archive_custody_refusal_missing");

  for (const [name, source] of Object.entries({ wallet, lifecycle })) {
    if (/unwrap_or(?:_else)?\([^\n]*["']local-mode["']/u.test(source)) {
      findings.push(`${name}_unconditional_local_mode_fallback`);
    }
  }
  return [...new Set(findings)].sort();
}

if (process.argv.includes("--mutation")) {
  const mutations = [
    {
      name: "wallet_fallback_applies_to_every_profile",
      sources: {
        ...sources,
        wallet: sources.wallet.replace(
          'profile == Some("development_cooperative")',
          'profile.is_some()',
        ),
      },
      expected: "wallet_development_only_fallback_missing",
    },
    {
      name: "daemon_fallback_applies_to_every_profile",
      sources: {
        ...sources,
        lifecycle: sources.lifecycle.replace(
          'profile == Some("development_cooperative")',
          'profile.is_some()',
        ),
      },
      expected: "daemon_development_only_fallback_missing",
    },
    {
      name: "provider_claims_custody_from_ambient_env",
      sources: {
        ...sources,
        provider: sources.provider.replace(
          "super::lifecycle_routes::scm_key_source()",
          'std::env::var("IOI_WALLET_SECRET_PASS").map(|_| "wallet-secret").unwrap_or("local-mode")',
        ),
      },
      expected: "provider_custody_label_not_server_derived",
    },
  ];
  const survived = mutations.filter(
    ({ sources: mutated, expected }) => !inspect(mutated).includes(expected),
  );
  if (survived.length > 0) {
    console.error(JSON.stringify({
      check: "mutate:secret-custody-profile",
      verdict: "FAIL",
      survived: survived.map(({ name, expected }) => ({ name, expected })),
    }, null, 2));
    process.exit(1);
  }
  console.log(JSON.stringify({
    check: "mutate:secret-custody-profile",
    verdict: "PASS",
    mutations: mutations.map(({ name, expected }) => ({ name, detected_by: expected })),
  }, null, 2));
  process.exit(0);
}

const findings = inspect(sources);
if (findings.length > 0) {
  console.error(JSON.stringify({
    check: "check:secret-custody-profile",
    verdict: "FAIL",
    findings,
  }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({
  check: "check:secret-custody-profile",
  verdict: "PASS",
  development_fallback: "explicit development_cooperative profile only",
  conforming_profile_without_key: "refused",
}, null, 2));
