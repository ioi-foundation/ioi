#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..", "..");
const provider = fs.readFileSync(path.join(root, "crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs"), "utf8");
const consoleAdapter = fs.readFileSync(path.join(root, "crates/drivers/src/provisioning/akash_console.rs"), "utf8");
const failures = [];
const requireText = (text, needle, code) => { if (!text.includes(needle)) failures.push({ code, detail: needle }); };

for (const [needle, code] of [
  ["deposit_funded", "deposit_funded_state_absent"],
  ["deployment_close_accepted", "close_accepted_state_absent"],
  ["refund_pending", "refund_pending_state_absent"],
  ["reconciliation_required", "reconciliation_required_state_absent"],
  ["close_deployment(&api_key, &dseq)", "no_bid_compensation_close_absent"],
  ["select_lowest_qualified_bid", "exact_ceiling_selector_absent"],
  ["parse_c7_sdl_ceiling", "sdl_derived_exact_ceiling_absent"],
  ["parse_active_lease_endpoint", "positive_endpoint_readback_absent"],
  ["endpoint_discovered", "endpoint_discovery_semantics_absent"],
  ["workload_readiness_proven", "workload_readiness_semantics_absent"],
  ["only_qualified_bid_from_exact_provider", "exact_selector_contract_absent"],
  ["direct_akash_provider_pin", "exact_selector_gate_absent"],
  ["parse_pinned_bid_priced", "exact_provider_price_readback_absent"],
  ["bid_passes_ceiling", "exact_provider_ceiling_gate_absent"],
  ["validate_akash_sdl_secret_refs", "secret_reference_gate_absent"],
  ["materialize_akash_sdl", "execution_boundary_secret_injection_absent"],
  ["connector_credential_unresolvable", "sealed_connector_resolution_absent"],
  ["akash-workload-results", "receipted_workload_result_channel_absent"],
  ["credential_exposed_to_caller", "result_credential_nonexposure_claim_absent"],
  ["retrieved_live", "c6_live_readback_absent"],
  ["state\"] = json!(\"exhausted\")", "one_shot_lease_terminalization_absent"],
]) requireText(provider, needle, code);
requireText(consoleAdapter, "provider_terminal", "provider_terminal_settlement_absent");
requireText(consoleAdapter, "refund_settled", "refund_settled_state_absent");
requireText(consoleAdapter, "final_debit_settled", "final_debit_state_absent");
requireText(consoleAdapter, "settled_at_height", "settled_height_absent");
requireText(consoleAdapter, "active_lease_count", "active_lease_check_absent");

const tests = spawnSync("cargo", ["test", "-p", "ioi-drivers", "akash_console", "--no-fail-fast"], {
  cwd: root,
  encoding: "utf8",
  maxBuffer: 16 * 1024 * 1024,
});
if (tests.status !== 0) failures.push({ code: "akash_console_tests_failed", detail: (tests.stderr || tests.stdout).slice(-4000) });
for (const name of [
  "settlement_requires_closed_provider_readback_and_computes_zero_debit_refund",
  "positive_branch_requires_active_lease_and_provider_reported_endpoint",
  "select_lowest_qualified_bid_is_deterministic_and_ceiling_bounded",
  "endpoint_discovery_does_not_inflate_zero_ready_replicas",
  "parse_pinned_bid_priced_extracts_exact_price_and_denom",
  "bid_passes_ceiling_enforces_denom_and_amount_exactly",
]) {
  if (!(tests.stdout || "").includes(name)) failures.push({ code: "required_branch_test_not_executed", detail: name });
}

for (const filter of ["sdl_secret", "direct_akash_"]) {
  const containment = spawnSync("cargo", ["test", "-p", "ioi-node", "--bin", "hypervisor-daemon", filter, "--no-fail-fast"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (containment.status !== 0 || !/test result: ok/u.test(containment.stdout || "")) {
    failures.push({ code: "provider_containment_tests_failed", detail: `${filter}: ${(containment.stderr || containment.stdout).slice(-4000)}` });
  }
}

console.log(JSON.stringify({
  schema_version: "ioi.check.akash-live-lifecycle.v1",
  ok: failures.length === 0,
  branches: ["no-qualified-bid -> close -> provider settlement", "qualified bid -> active lease -> provider endpoint discovery", "endpoint discovery != workload readiness", "exact provider + exact denomination/ceiling", "sealed secret refs -> post-intent injection -> authenticated result receipt"],
  failures,
}, null, 2));
process.exit(failures.length ? 1 : 0);
