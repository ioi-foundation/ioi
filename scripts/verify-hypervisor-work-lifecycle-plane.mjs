#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const checks = [];

function assertSource(name, condition) {
  checks.push({ name, pass: Boolean(condition) });
  if (!condition) {
    console.error(`FAIL: ${name}`);
    process.exit(1);
  }
  console.log(`PASS: ${name}`);
}

function run(command, args) {
  console.log(`\n[work-lifecycle] ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    env: process.env,
    stdio: "inherit",
  });
  if (result.error) {
    console.error(`failed to start ${command}: ${result.error.message}`);
    process.exit(result.status ?? 1);
  }
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const service = readFileSync(
  "crates/services/src/agentic/runtime/kernel/work_lifecycle.rs",
  "utf8",
);
const store = readFileSync(
  "crates/node/src/bin/hypervisor_daemon_routes/work_lifecycle.rs",
  "utf8",
);
const daemon = readFileSync(
  "crates/node/src/bin/hypervisor-daemon.rs",
  "utf8",
);
const invariants = readFileSync(
  "docs/architecture/foundations/invariants.md",
  "utf8",
);

assertSource(
  "independent legality matcher remains present",
  service.includes("pub fn reference_transition_is_legal"),
);
assertSource(
  "non-cancel cancellation metadata fails closed",
  service.includes("work_lifecycle_cancellation_intent_unexpected"),
);
assertSource(
  "compensation and effect-reconciliation policies remain bound",
  service.includes("work_lifecycle_compensation_policy_required") &&
    service.includes("work_lifecycle_effect_reconciliation_policy_required") &&
    service.includes("effect_reconciliation_policy_ref"),
);
assertSource(
  "durable adapter reports owner-route nonbinding honestly",
  store.includes('"live_owner_route_bindings": []') &&
    store.includes('"live_owner_route_status": "not_bound"'),
);
assertSource(
  "read-only lifecycle status route remains mounted",
  daemon.includes('"/v1/hypervisor/work-lifecycle/status"') &&
    daemon.includes("handle_work_lifecycle_status"),
);
assertSource(
  "canon keeps shared mechanics below domain ownership",
  invariants.includes("INV-35") &&
    invariants.includes("Shared lifecycle mechanics never seize domain ownership"),
);

run("cargo", [
  "test",
  "-p",
  "ioi-services",
  "work_lifecycle",
  "--lib",
  "--",
  "--nocapture",
]);
run("cargo", [
  "test",
  "-p",
  "ioi-node",
  "--bin",
  "hypervisor-daemon",
  "work_lifecycle",
  "--",
  "--nocapture",
]);

console.log(`\nPASS: shared work-lifecycle conformance (${checks.length} source checks)`);
