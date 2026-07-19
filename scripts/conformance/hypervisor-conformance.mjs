#!/usr/bin/env node
import { spawnSync } from "node:child_process";

const npmRun = (script) => ["npm", ["run", script]];
const node = (...args) => ["node", args];

const TIERS = {
  docs: [
    npmRun("check:architecture-docs"),
    node("scripts/check-pre-next-leg-readiness.mjs"),
  ],
  abi: [node("scripts/generate-runtime-action-contracts.mjs", "--check")],
  contracts: [
    npmRun("check:architecture-contracts"),
    npmRun("test:architecture-contract-projections"),
    ["cargo", ["test", "-p", "ioi-types", "architecture_contracts"]],
    npmRun("build:workbench"),
  ],
  proofs: [
    node("scripts/generate-portable-authority-fixtures.mjs", "--check"),
    node("scripts/generate-receipt-proof-fixtures.mjs", "--check"),
    npmRun("check:architecture-contracts"),
    ["cargo", ["test", "-p", "ioi-validator", "portable_authority"]],
    ["cargo", ["test", "-p", "ioi-validator", "portable_receipt_proof"]],
    npmRun("test:portable-authority"),
    npmRun("test:portable-receipt-proof"),
    npmRun("check:authority-grant-offline"),
    npmRun("check:receipt-proof-offline"),
  ],
  ifc: [
    npmRun("check:architecture-contracts"),
    node("scripts/generate-architecture-contracts.mjs", "--check"),
    ["cargo", ["test", "-p", "ioi-services", "information_flow", "--no-fail-fast"]],
    ["cargo", ["test", "-p", "ioi-services", "browser::handler", "--no-fail-fast"]],
    ["cargo", ["test", "-p", "ioi-services", "runtime_mcp_live_backend", "--no-fail-fast"]],
    ["cargo", ["test", "-p", "ioi-services", "hosted_provider", "--no-fail-fast"]],
    ["cargo", ["test", "-p", "ioi-node", "--bin", "hypervisor-daemon", "webhook_tests"]],
    ["cargo", ["test", "-p", "ioi-node", "--bin", "hypervisor-daemon", "work_result_tests"]],
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-services",
        "provider_invocation_executes_hosted_transport_contract_in_rust_owner",
      ],
    ],
    ["cargo", ["check", "-p", "ioi-node", "--bin", "hypervisor-daemon"]],
    [
      "npx",
      [
        "--no-install",
        "tsx",
        "--test",
        "packages/hypervisor-workbench/src/runtime/information-flow.test.ts",
      ],
    ],
    npmRun("build:workbench"),
  ],
  operability: [
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-services",
        "agentic::runtime::kernel::platform_",
        "--lib",
        "--no-fail-fast",
      ],
    ],
    npmRun("check:architecture-docs"),
  ],
  attestation: [
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-services",
        "attestation_assurance",
        "--lib",
        "--no-fail-fast",
      ],
    ],
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-services",
        "deployment_policy_obligations",
        "--lib",
        "--no-fail-fast",
      ],
    ],
    npmRun("check:architecture-docs"),
  ],
  billing: [
    npmRun("check:architecture-contracts"),
    npmRun("test:architecture-contract-projections"),
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-services",
        "managed_work_billing",
        "--lib",
        "--no-fail-fast",
      ],
    ],
    npmRun("check:architecture-docs"),
  ],
  disputes: [
    npmRun("check:architecture-contracts"),
    npmRun("test:architecture-contract-projections"),
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-services",
        "dispute_rail",
        "--lib",
        "--no-fail-fast",
      ],
    ],
    npmRun("check:architecture-docs"),
  ],
  fencing: [
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-services",
        "distributed_fencing",
        "--lib",
        "--no-fail-fast",
      ],
    ],
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-node",
        "--bin",
        "hypervisor-daemon",
        "distributed_fencing",
      ],
    ],
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-node",
        "--bin",
        "hypervisor-daemon",
        "substrate_store::system_owner_tests",
      ],
    ],
    [
      "cargo",
      [
        "test",
        "-p",
        "agentgres",
        "promotion_fences_stale_primary",
      ],
    ],
    npmRun("check:architecture-docs"),
  ],
  "work-lifecycle": [
    node("scripts/verify-hypervisor-work-lifecycle-plane.mjs"),
  ],
  physical: [
    npmRun("check:architecture-contracts"),
    node("scripts/generate-architecture-contracts.mjs", "--check"),
    npmRun("test:architecture-contract-projections"),
    [
      "cargo",
      [
        "test",
        "-p",
        "ioi-services",
        "physical_action",
        "--lib",
        "--no-fail-fast",
      ],
    ],
    npmRun("check:architecture-docs"),
  ],
  bridge: [
    npmRun("check:runtime-layout"),
    npmRun("check:hypervisor-code-editor-adapter-host-paths"),
  ],
  receipts: [
    npmRun("check:service-composition-evidence"),
    npmRun("check:artifact-availability-incident"),
  ],
  app: [
    node("apps/hypervisor/scripts/verify-hypervisor-product-surface-catalog.mjs"),
    node("apps/hypervisor/scripts/verify-hypervisor-product-surface-live-smoke.mjs"),
    npmRun("build:workbench"),
    ["npm", ["run", "build", "--workspace=@ioi/hypervisor-app"]],
    // check:hypervisor-app-shell retired: it e2e-tested the legacy ?view= shell and the
    // reference-parity React UI, both removed. The product UI is now served as the live
    // reference (serve-live-reference.mjs); see apps/hypervisor/docs/reference-api-integration.md.
    npmRun("test:hypervisor-app-harness"),
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
  "contracts",
  "proofs",
  "ifc",
  "operability",
  "attestation",
  "billing",
  "disputes",
  "fencing",
  "work-lifecycle",
  "physical",
  "docs",
  "bridge",
  "receipts",
  "app",
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
