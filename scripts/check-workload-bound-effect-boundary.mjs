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
const daemon = readFileSync(
  join(repo, "crates/node/src/bin/hypervisor-daemon.rs"),
  "utf8",
);

function inspect(microvm, brokerSource = broker, daemonSource = daemon) {
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
    "pub(crate) fn hostile_guest_proposal_roundtrip",
    "hostile_guest_proposal_roundtrip_missing",
  );
  requireText(
    "if returned != proposal_bytes",
    "guest_proposal_roundtrip_exactness_missing",
  );
  requireText(
    '"host_trigger_in_guest": false',
    "host_trigger_guest_nonpossession_evidence_missing",
  );
  requireText(
    '"direct_protected_provider_invocations": 0',
    "direct_provider_invocation_counter_missing",
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
      "mint_guest_governed_provider_effect_capability",
      "host_authority_compartment_mint_missing",
    ],
    [
      "host_authority_attachment_hash",
      "host_authority_attachment_binding_missing",
    ],
    [
      "consume_guest_governed_provider_operation_bytes",
      "governed_provider_broker_composition_missing",
    ],
    ["host_trigger_hash", "host_trigger_hash_only_storage_missing"],
    [
      "verify_host_trigger(&record, host_trigger)?;",
      "host_trigger_finalizer_gate_missing",
    ],
    [
      "governed_guest_proposal_contains_no_wallet_authority_or_operator_session",
      "guest_host_trigger_nonpossession_regression_missing",
    ],
    [
      "handle_governed_capability_mint",
      "authenticated_host_controller_mint_missing",
    ],
    [
      "handle_governed_capability_consume",
      "capability_authenticated_host_finalizer_missing",
    ],
    [
      "handle_hostile_guest_roundtrip",
      "hostile_guest_roundtrip_handler_missing",
    ],
    [
      "authorize_hostile_guest_roundtrip",
      "hostile_guest_roundtrip_host_binding_missing",
    ],
    [
      "invoke_workload_brokered_provider_operation",
      "full_provider_final_invoker_call_missing",
    ],
    [
      "governed_guest_proposal_contains_no_wallet_authority_or_operator_session",
      "guest_authority_nonpossession_regression_missing",
    ],
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
      "pub(crate) async fn invoke_workload_brokered_provider_operation",
      "governed_provider_final_invoker_missing",
    ],
    [
      "handle_provider_op_internal(st, HeaderMap::new(), body, Some(authority)).await",
      "governed_provider_route_not_shared_with_http_lane",
    ],
    [
      "invoke_static_provider_operation(data_dir, &body)",
      "http_route_not_using_shared_static_final_invoker",
    ],
  ]) {
    if (!providerRoutes.includes(text)) findings.push(code);
  }
  for (const [text, code] of [
    [
      '"/v1/hypervisor/workload-effect-capabilities"',
      "host_controller_mint_route_missing",
    ],
    [
      '"/v1/hypervisor/workload-effect-capabilities/consume"',
      "host_finalizer_route_missing",
    ],
    [
      '"/v1/hypervisor/workload-effect-capabilities/hostile-guest-roundtrip"',
      "hostile_guest_roundtrip_route_missing",
    ],
  ]) {
    if (!daemonSource.includes(text)) findings.push(code);
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
  const bypassedGovernedProvider = broker.replace(
    "super::provider_routes::invoke_workload_brokered_provider_operation(",
    "super::provider_routes::invoke_static_provider_operation(",
  );
  const governedFindings = inspect(originalMicrovm, bypassedGovernedProvider);
  if (!governedFindings.includes("full_provider_final_invoker_call_missing")) {
    console.error(
      "MUTATION SURVIVED: governed guest broker was diverted to the static provider lane",
    );
    process.exit(1);
  }
  const bypassedHostTrigger = broker.replace(
    "verify_host_trigger(&record, host_trigger)?;",
    "let _ = host_trigger;",
  );
  const hostTriggerFindings = inspect(originalMicrovm, bypassedHostTrigger);
  if (!hostTriggerFindings.includes("host_trigger_finalizer_gate_missing")) {
    console.error(
      "MUTATION SURVIVED: host finalizer accepted a guest proposal without the host-only trigger",
    );
    process.exit(1);
  }
  const inexactRoundtrip = originalMicrovm.replace(
    "if returned != proposal_bytes",
    "if false",
  );
  const roundtripFindings = inspect(inexactRoundtrip);
  if (!roundtripFindings.includes("guest_proposal_roundtrip_exactness_missing")) {
    console.error(
      "MUTATION SURVIVED: hostile guest could substitute proposal bytes across quarantine",
    );
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
          {
            mutation: "divert_governed_guest_broker_to_static_provider_lane",
            detected_by: "full_provider_final_invoker_call_missing",
          },
          {
            mutation: "remove_host_only_trigger_from_governed_finalizer",
            detected_by: "host_trigger_finalizer_gate_missing",
          },
          {
            mutation: "remove_byte_exact_hostile_guest_proposal_roundtrip_check",
            detected_by: "guest_proposal_roundtrip_exactness_missing",
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
  runCargo(
    "governed_proposal_crosses_the_real_hostile_guest_roundtrip_without_host_authority",
    ["--ignored"],
  );
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
        "The local KVM/no-NIC guest launch, canonical output quarantine, exact authenticated proposal, durable one-use claim, host-only authority compartment, and shared full-provider final-invoker implementation are enforced and mutation-tested. The full-provider seam now reaches the wallet/proposal/C2/provider implementation without retaining a bearer operator session, but this check does not claim the live external-provider composition until the integrated paid capstone and complete T2 fault matrix pass.",
    },
    null,
    2,
  ),
);
