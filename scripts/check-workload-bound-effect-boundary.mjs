#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const microvmPath = join(
  repo,
  "crates/node/src/bin/hypervisor_daemon_routes/microvm.rs",
);
const environmentPath = join(
  repo,
  "crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs",
);
const originalMicrovm = readFileSync(microvmPath, "utf8");
const environment = readFileSync(environmentPath, "utf8");
const broker = readFileSync(
  join(
    repo,
    "crates/node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs",
  ),
  "utf8",
);
const providerRoutes = readFileSync(
  join(
    repo,
    "crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs",
  ),
  "utf8",
);

function inspect(microvm, brokerSource = broker) {
  const findings = [];
  const requireText = (text, code) => {
    if (!microvm.includes(text)) findings.push(code);
  };

  for (const [pattern, code] of [
    [/\.arg\(\s*"--net"/u, "network_device_argument"],
    [/\.arg\(\s*"-net"/u, "network_device_argument"],
    [/virtio-net|vhost-user-net|network-interfaces/u, "network_device_argument"],
    [/\.arg\(\s*"--disk"/u, "host_disk_argument"],
    [/\.arg\(\s*"-virtfs"/u, "host_filesystem_argument"],
    [/virtiofs|9p-local|vhost-user-fs/u, "host_filesystem_argument"],
  ]) {
    if (pattern.test(microvm)) findings.push(code);
  }

  requireText("network_device_count: 0", "zero_network_declaration_missing");
  requireText("host_mount_count: 0", "zero_mount_declaration_missing");
  requireText(
    "host_control_socket_count: 0",
    "zero_control_socket_declaration_missing",
  );
  requireText(
    "spec.enforce_hostile_guest_floor()?",
    "prelaunch_enforcement_missing",
  );
  requireText(
    "admit_guest_transfer_len(",
    "bounded_guest_transfer_missing",
  );
  requireText(
    "validate_tar_for_host_extract(tar)?",
    "output_quarantine_validation_missing",
  );
  requireText(
    "commit quarantine stage",
    "atomic_output_quarantine_commit_missing",
  );
  requireText(
    "host_extract_rejects_duplicate_and_path_type_collisions",
    "archive_collision_regression_missing",
  );
  requireText(
    "new_quarantine_destination_is_absent_after_late_extractor_failure",
    "partial_quarantine_failure_regression_missing",
  );
  requireText(
    "hostile_guest_floor_refuses_each_planted_bypass_before_launch",
    "planted_bypass_regression_missing",
  );
  requireText(
    "root_guest_cannot_reach_a_host_canary_or_find_protected_material",
    "live_root_guest_probe_missing",
  );
  requireText(
    "arm_monitor_parent_death(&mut cmd);",
    "monitor_parent_death_cleanup_missing",
  );
  requireText(
    "monitor_is_killed_when_its_daemon_parent_disappears",
    "monitor_parent_death_regression_missing",
  );
  requireText(
    "killed_guest_monitor_reaches_terminal_cleanup",
    "guest_crash_cleanup_regression_missing",
  );
  requireText("workload_binding: None", "generic_vm_scope_truth_missing");
  requireText(
    "workload_bound_enforcement_declaration",
    "workload_bound_declaration_gate_missing",
  );

  if (/reqwest|AKASH_CONSOLE|provider_routes/u.test(microvm)) {
    findings.push("provider_client_inside_guest_runtime");
  }
  if (/reqwest|AKASH_CONSOLE/u.test(environment)) {
    findings.push("provider_client_inside_environment_runtime");
  }
  for (const [text, code] of [
    ["token_hash", "hash_only_guest_capability_record_missing"],
    ["isolation_binding_hash", "binding_hash_channel_binding_missing"],
    ["proposal_nonce", "proposal_nonce_channel_binding_missing"],
    ["result_destination_ref", "result_destination_channel_binding_missing"],
    ["workload_effect_capability_already_consumed", "replay_refusal_missing"],
    ["prior_process_lost_after_durable_claim", "restart_ambiguity_refusal_missing"],
    ["workload_effect_claimed", "durable_boundary_crash_hook_missing"],
    ["final_invoker_calls", "final_invoker_counter_missing"],
    ["consume_guest_effect_proposal_bytes", "canonical_guest_byte_boundary_missing"],
    [
      "reconcile_guest_static_provider_operation",
      "ambiguous_claim_reconciliation_missing",
    ],
    ["original_effect_reinvoked", "reconciliation_non_reinvocation_evidence_missing"],
    [
      "reconciliation_observes_and_cleans_an_effect_without_duplicate_create",
      "observed_effect_cleanup_regression_missing",
    ],
    [
      "reconciliation_proves_no_effect_without_reinvoking_the_original",
      "no_effect_reconciliation_regression_missing",
    ],
    [
      "daemon_kill_after_durable_claim_never_duplicates_provider_effect",
      "durable_claim_sigkill_regression_missing",
    ],
  ]) {
    if (!brokerSource.includes(text)) findings.push(code);
  }
  if (/reqwest|AKASH_CONSOLE|open_scm_token/u.test(brokerSource)) {
    findings.push("provider_or_secret_client_inside_guest_broker");
  }
  for (const [text, code] of [
    [
      "consume_guest_static_provider_operation_bytes",
      "static_provider_broker_composition_missing",
    ],
    [
      "super::provider_routes::invoke_static_provider_operation",
      "shared_static_final_invoker_call_missing",
    ],
  ]) {
    if (!brokerSource.includes(text)) findings.push(code);
  }
  for (const [text, code] of [
    [
      "pub(crate) fn invoke_static_provider_operation",
      "shared_static_final_invoker_missing",
    ],
    [
      "invoke_static_provider_operation(data_dir, &body)",
      "http_route_not_using_shared_static_final_invoker",
    ],
  ]) {
    if (!providerRoutes.includes(text)) findings.push(code);
  }
  return [...new Set(findings)].sort();
}

function runCargo(name, extra = []) {
  const result = spawnSync(
    "cargo",
    [
      "test",
      "-p",
      "ioi-node",
      "--bin",
      "hypervisor-daemon",
      name,
      "--",
      ...extra,
      "--nocapture",
    ],
    { cwd: repo, encoding: "utf8", stdio: "inherit" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

if (process.argv.includes("--mutation")) {
  const planted = originalMicrovm.replace(
    '.arg("--kernel")',
    '.arg("--net").arg("tap=evil0").arg("--kernel")',
  );
  const findings = inspect(planted);
  if (!findings.includes("network_device_argument")) {
    console.error("MUTATION SURVIVED: planted guest network device was not detected");
    process.exit(1);
  }
  const plantedProvider = `${broker}\nfn planted_second_provider_path() { let _ = reqwest::Client::new(); }\n`;
  const providerFindings = inspect(originalMicrovm, plantedProvider);
  if (!providerFindings.includes("provider_or_secret_client_inside_guest_broker")) {
    console.error("MUTATION SURVIVED: planted second provider path was not detected");
    process.exit(1);
  }
  console.log(
    JSON.stringify(
      {
        check: "mutate:workload-bound-effect-boundary",
        verdict: "PASS",
        mutations: [
          {
            mutation: "plant_virtual_network_device_in_cloud_hypervisor_launch",
            detected_by: "network_device_argument",
          },
          {
            mutation: "plant_second_provider_client_inside_guest_broker",
            detected_by: "provider_or_secret_client_inside_guest_broker",
          },
        ],
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

const findings = inspect(originalMicrovm);
if (findings.length > 0) {
  console.error(
    JSON.stringify(
      {
        check: "check:workload-bound-effect-boundary",
        verdict: "FAIL",
        findings,
      },
      null,
      2,
    ),
  );
  process.exit(1);
}

runCargo("hostile_guest_floor_refuses_each_planted_bypass_before_launch");
runCargo("workload_effect_boundary::tests");
runCargo("daemon_kill_after_durable_claim_never_duplicates_provider_effect", [
  "--ignored",
]);
runCargo("monitor_is_killed_when_its_daemon_parent_disappears", ["--ignored"]);
if (process.argv.includes("--live")) {
  runCargo("killed_guest_monitor_reaches_terminal_cleanup", ["--ignored"]);
  runCargo("root_guest_cannot_reach_a_host_canary_or_find_protected_material", [
    "--ignored",
  ]);
}

console.log(
  JSON.stringify(
    {
      check: "check:workload-bound-effect-boundary",
      verdict: "PASS",
      live_kvm_probe: process.argv.includes("--live") ? "passed" : "not_run",
      floor_status:
        "not_yet_in_global_verifier_floor_pending_live_c2_authority_composition_and_complete_failure_matrix",
      claim_boundary:
        "The local KVM/no-NIC guest launch, canonical output quarantine, exact authenticated proposal, durable one-use claim, and shared static-provider final-invoker composition are enforced and mutation-tested. This check does not yet claim live C2/wallet-authority composition, external-provider non-bypassability, or the complete T2 fault matrix.",
    },
    null,
    2,
  ),
);
