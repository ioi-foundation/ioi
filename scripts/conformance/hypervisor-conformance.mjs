#!/usr/bin/env node
import { spawnSync } from "node:child_process";

const npmRun = (script) => ["npm", ["run", script]];
const node = (...args) => ["node", args];
const nodeTest = (...files) => ["node", ["--test", ...files]];

const TIERS = {
  docs: [
    npmRun("check:architecture-docs"),
    node("scripts/check-pre-next-leg-readiness.mjs"),
  ],
  abi: [node("scripts/generate-runtime-action-contracts.mjs", "--check")],
  bridge: [
    npmRun("check:runtime-layout"),
    npmRun("check:hypervisor-code-editor-adapter-host-paths"),
  ],
  receipts: [
    npmRun("check:service-composition-evidence"),
    npmRun("check:artifact-availability-incident"),
  ],
  app: [
    npmRun("build:workbench"),
    ["npm", ["run", "build", "--workspace=@ioi/hypervisor-app"]],
    npmRun("check:hypervisor-app-shell"),
    npmRun("test:hypervisor-app-harness"),
  ],
  compositor: [
    npmRun("build:workbench"),
    nodeTest(
      "apps/hypervisor/src/windows/HypervisorShellWindow/harnessAdapterModel.test.ts",
      "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorAutomationCompositorModel.test.ts",
      "apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorSessionOperationsModel.test.ts",
    ),
  ],
  wallet: [npmRun("check:wallet-packaging")],
  candidates: [npmRun("check:candidate-evidence")],
  negative: [npmRun("check:runtime-layout")],
  // The unified-Rust-daemon lifecycle ratchet: the Rust hypervisor-daemon owns the
  // thread/agent/run/turn/events/control/MCP/task/job/subagent surface (spawns the
  // Rust daemon and asserts the lifecycle contract). See
  // internal-docs/implementation/hypervisor-unified-rust-daemon-lifecycle-migration.md.
  "rust-lifecycle": [node("scripts/validate-runtime-lifecycle-e2e.mjs")],
};

const DEFAULT_TIERS = [
  "abi",
  "docs",
  "bridge",
  "receipts",
  "app",
  "compositor",
  "wallet",
  "candidates",
  "negative",
  "rust-lifecycle",
];

function usage() {
  const tierList = Object.keys(TIERS).sort().join(", ");
  return [
    "Usage: node scripts/conformance/hypervisor-conformance.mjs [tier...]",
    "",
    `Tiers: ${tierList}`,
    "No arguments run the current full conformance suite.",
  ].join("\n");
}

function runCommand(tier, command, args) {
  console.log(`\n[hypervisor-conformance:${tier}] ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    env: process.env,
    stdio: "inherit",
  });

  if (result.error) {
    console.error(
      `[hypervisor-conformance:${tier}] failed to start ${command}: ${result.error.message}`,
    );
    process.exit(result.status ?? 1);
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(usage());
  process.exit(0);
}

const tiers = args.length > 0 ? args : DEFAULT_TIERS;
const unknown = tiers.filter((tier) => !Object.hasOwn(TIERS, tier));
if (unknown.length > 0) {
  console.error(`Unknown hypervisor conformance tier: ${unknown.join(", ")}`);
  console.error(usage());
  process.exit(1);
}

for (const tier of tiers) {
  for (const [command, commandArgs] of TIERS[tier]) {
    runCommand(tier, command, commandArgs);
  }
}

console.log(
  JSON.stringify(
    {
      ok: true,
      schema_version: "ioi.hypervisor.conformance_run.v1",
      tiers,
    },
    null,
    2,
  ),
);
