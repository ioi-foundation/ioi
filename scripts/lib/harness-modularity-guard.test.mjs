import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../..");

const requiredP0ComponentKinds = [
  "planner",
  "prompt_assembler",
  "task_state",
  "uncertainty_gate",
  "budget_gate",
  "capability_sequencer",
  "model_router",
  "model_call",
  "tool_router",
  "tool_call",
  "policy_gate",
  "approval_gate",
  "verifier",
  "retry_policy",
  "completion_gate",
  "receipt_writer",
  "output_writer",
];

const clusterRequirements = new Map([
  [
    "cognition",
    [
      "planner",
      "prompt_assembler",
      "task_state",
      "uncertainty_gate",
      "budget_gate",
      "capability_sequencer",
    ],
  ],
  ["routing_model", ["model_router", "model_call", "tool_router"]],
  [
    "verification_output",
    [
      "postcondition_synthesizer",
      "verifier",
      "completion_gate",
      "receipt_writer",
      "quality_ledger",
      "output_writer",
    ],
  ],
  [
    "authority_tooling",
    [
      "policy_gate",
      "approval_gate",
      "dry_run_simulator",
      "mcp_provider",
      "mcp_tool_call",
      "tool_call",
      "connector_call",
      "wallet_capability",
    ],
  ],
]);

const harnessAuthorityTokens = [
  "workflow_component_adapter_live",
  "workflow_component_adapter_gated",
  "HarnessActionFrame",
  "HarnessComponentAdapterResult",
  "HarnessNodeAttemptRecord",
  "invoke_default_harness_component",
];

const harnessAuthorityAllowlist = [
  "crates/services/src/agentic/runtime/README.md",
  "crates/services/src/agentic/runtime/harness.rs",
  "packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx",
  "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts",
  "packages/hypervisor-workbench/src/runtime/harness-workflow/core.ts",
  "packages/hypervisor-workbench/src/runtime/workflow-rail-model.ts",
  "packages/hypervisor-workbench/src/runtime/workflow-run-history-model.ts",
  "packages/hypervisor-workbench/src/types/graph.ts",
  "scripts/lib/hypervisor-app-harness-validation/core.mjs",
  "scripts/lib/harness-contract-consistency.test.mjs",
  "scripts/lib/harness-modularity-guard.test.mjs",
];

const retiredHarnessRuntimeTokens = [
  ["legacy", "runtime"].join("_"),
  ["legacy", "runtime", "model", "invocation"].join("_"),
  ["legacy", "runtime", "output", "writer"].join("_"),
  ["legacy", "runtime", "tool", "authority"].join("_"),
  ["retain", "legacy", "runtime", "default"].join("_"),
  ["rollback", "to", "legacy", "runtime"].join("_"),
  ["existing", "runtime", "service"].join("_"),
  ["Legacy", "Runtime"].join(""),
];

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function readMany(relativePaths) {
  return relativePaths.map(read).join("\n");
}

function readRustHarnessContract() {
  return readMany([
    "crates/types/src/app/harness/core.rs",
    "crates/types/src/app/harness/promotion.rs",
    "crates/types/src/app/harness/components.rs",
    "crates/types/src/app/harness/worker_binding.rs",
    "crates/types/src/app/harness/activation.rs",
    "crates/types/src/app/harness/receipts.rs",
    "crates/types/src/app/harness/serde_bridge.rs",
  ]);
}

function readTsHarnessWorkflow() {
  return read("packages/hypervisor-workbench/src/runtime/harness-workflow/core.ts");
}

function readGuiHarnessValidation() {
  return read("scripts/lib/hypervisor-app-harness-validation/core.mjs");
}

function rustImplBlock(source, implName) {
  const start = source.indexOf(`impl ${implName}`);
  assert.notEqual(start, -1, `missing Rust impl ${implName}`);
  const nextEnum = source.indexOf("\n#[derive", start + 1);
  return source.slice(start, nextEnum > start ? nextEnum : undefined);
}

function rustAsStrValues(source, implName) {
  const implBlock = rustImplBlock(source, implName);
  const matchBlock = implBlock.match(
    /pub fn as_str[\s\S]*?match self \{([\s\S]*?)\n\s+\}/,
  );
  assert.ok(matchBlock, `missing ${implName}::as_str match block`);
  return new Set(
    [...matchBlock[1].matchAll(/Self::[A-Za-z0-9]+ => "([^"]+)"/g)].map(
      (match) => match[1],
    ),
  );
}

function tsUnionValues(source, typeName) {
  const match = source.match(
    new RegExp(`export type ${typeName} =[\\s\\S]*?;`),
  );
  assert.ok(match, `missing TS type ${typeName}`);
  return new Set([...match[0].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]));
}

function tsInterfaceBlock(source, typeName) {
  const match = source.match(
    new RegExp(`export interface ${typeName} \\{[\\s\\S]*?\\n\\}`),
  );
  assert.ok(match, `missing TS interface ${typeName}`);
  return match[0];
}

function rustStructBlock(source, typeName) {
  const match = source.match(new RegExp(`pub struct ${typeName} \\{[\\s\\S]*?\\n\\}`));
  assert.ok(match, `missing Rust struct ${typeName}`);
  return match[0];
}

function walkSourceFiles(rootRelativePath) {
  const root = path.join(repoRoot, rootRelativePath);
  const files = [];
  if (!fs.existsSync(root)) {
    return files;
  }
  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(fullPath);
        continue;
      }
      if (/\.(rs|ts|tsx|mjs|md)$/.test(entry.name)) {
        files.push(path.relative(repoRoot, fullPath).split(path.sep).join("/"));
      }
    }
  };
  visit(root);
  return files;
}

test("runtime README carries the default harness modularity contract", () => {
  const readme = read("crates/services/src/agentic/runtime/README.md");
  assert.match(readme, /## Maintainability Guardrails/);
  assert.match(readme, /### Default Harness Modularity Contract/);
  assert.match(readme, /workflow-addressable runtime authority/);
  assert.match(readme, /HarnessComponentKind/);
  assert.match(readme, /HarnessActionFrame/);
  assert.match(readme, /HarnessComponentAdapterResult/);
  assert.match(readme, /HarnessNodeAttemptRecord/);
  assert.match(readme, /receipt refs and evidence refs/);
  assert.match(readme, /replay metadata/);
  assert.match(readme, /worker binding and rollback proof/);
  assert.match(readme, /Agent checklist before modifying harness-sensitive runtime behavior/);
  assert.match(readme, /Keep TypeScript graph\/runtime definitions in parity with Rust/);
  assert.match(readme, /Run `npm run test:harness-contract`/);
});

test("Rust and TS retain the guarded P0 harness component surface", () => {
  const rust = readRustHarnessContract();
  const graph = read("packages/hypervisor-workbench/src/types/graph.ts");
  const rustKinds = rustAsStrValues(rust, "HarnessComponentKind");
  const tsKinds = tsUnionValues(graph, "WorkflowHarnessComponentKind");

  for (const kind of requiredP0ComponentKinds) {
    assert.ok(rustKinds.has(kind), `Rust missing P0 component ${kind}`);
    assert.ok(tsKinds.has(kind), `TS missing P0 component ${kind}`);
    assert.match(rust, new RegExp(`Self::[A-Za-z0-9]+ => "${kind}"`));
    assert.match(graph, new RegExp(`\\| "${kind}"`));
  }

  for (const [clusterId, componentKinds] of clusterRequirements) {
    assert.match(graph, new RegExp(`\\| "${clusterId}"`));
    for (const kind of componentKinds) {
      assert.ok(rustKinds.has(kind), `Rust cluster ${clusterId} missing ${kind}`);
      assert.ok(tsKinds.has(kind), `TS cluster ${clusterId} missing ${kind}`);
    }
  }

  for (const proofType of [
    "WorkflowHarnessWorkerBinding",
    "WorkflowHarnessWorkerBindingRegistryRecord",
    "WorkflowHarnessWorkerAttachReceipt",
    "WorkflowHarnessWorkerSessionRecord",
    "WorkflowHarnessWorkerHandoffReceipt",
    "WorkflowHarnessActivationRollbackProof",
    "WorkflowHarnessActivationRollbackExecution",
    "WorkflowHarnessActiveRuntimeRollbackExecutionProof",
    "WorkflowHarnessActiveRuntimeRollbackApplyProof",
  ]) {
    assert.match(graph, new RegExp(`export interface ${proofType}`));
  }
});

test("adapter contracts expose action frame, node attempt, readiness, receipts, replay, and slots", () => {
  const rust = readRustHarnessContract();
  const graph = read("packages/hypervisor-workbench/src/types/graph.ts");

  const tsActionFrame = tsInterfaceBlock(graph, "WorkflowHarnessActionFrame");
  for (const field of [
    "workflowId",
    "nodeId",
    "componentId",
    "componentKind",
    "executionMode",
    "readiness",
    "slotIds",
    "replay",
    "eventKinds",
    "evidenceKeys",
  ]) {
    assert.match(tsActionFrame, new RegExp(`\\b${field}\\b`));
  }

  const tsAttempt = tsInterfaceBlock(graph, "WorkflowHarnessNodeAttemptRecord");
  for (const field of [
    "attemptId",
    "workflowNodeId",
    "componentKind",
    "executionMode",
    "readiness",
    "status",
    "inputHash",
    "outputHash",
    "errorClass",
    "policyDecision",
    "durationMs",
    "receiptIds",
    "evidenceRefs",
    "replay",
  ]) {
    assert.match(tsAttempt, new RegExp(`\\b${field}\\b`));
  }

  const tsResult = tsInterfaceBlock(graph, "WorkflowHarnessComponentAdapterResult");
  for (const field of [
    "actionFrame",
    "nodeAttempt",
    "slotIds",
    "resultHash",
    "errorClass",
    "readiness",
    "receiptIds",
    "replay",
  ]) {
    assert.match(tsResult, new RegExp(`\\b${field}\\b`));
  }

  const rustResult = rustStructBlock(rust, "HarnessComponentAdapterResult");
  for (const field of [
    "pub action_frame: HarnessActionFrame",
    "pub node_attempt: HarnessNodeAttemptRecord",
    "pub slot_ids: Vec<String>",
    "pub result_hash: Option<String>",
    "pub error_class: Option<String>",
    "pub readiness: HarnessComponentReadiness",
    "pub receipt_ids: Vec<String>",
    "pub replay: HarnessReplayEnvelope",
  ]) {
    assert.match(rustResult, new RegExp(field.replace(/[<>]/g, "\\$&")));
  }
});

test("P0 clusters keep explicit workflow component adapter proof", () => {
  const graph = read("packages/hypervisor-workbench/src/types/graph.ts");
  const workflow = readTsHarnessWorkflow();
  const guiValidation = readGuiHarnessValidation();

  for (const pattern of [
    /cognitionExecutionAdapterMode[\s\S]*workflow_component_adapter_live/,
    /cognitionExecutionAdapterResults: WorkflowHarnessComponentAdapterResult\[\]/,
    /cognitionExecutionGateAdapterMode[\s\S]*workflow_component_adapter_gated/,
    /routingModelAdapterMode[\s\S]*workflow_component_adapter_gated/,
    /routingModelAdapterResults: WorkflowHarnessComponentAdapterResult\[\]/,
    /verificationOutputAdapterMode[\s\S]*workflow_component_adapter_gated/,
    /verificationOutputAdapterResults: WorkflowHarnessComponentAdapterResult\[\]/,
    /authorityToolingAdapterMode[\s\S]*workflow_component_adapter_gated/,
    /authorityToolingAdapterResults: WorkflowHarnessComponentAdapterResult\[\]/,
  ]) {
    assert.match(graph, pattern);
  }

  for (const pattern of [
    /makeDefaultCognitionAdapterResults/,
    /makeDefaultCognitionGateAdapterResults/,
    /makeDefaultRoutingModelGateAdapterResults/,
    /makeDefaultVerificationOutputGateAdapterResults/,
    /makeDefaultAuthorityToolingGateAdapterResults/,
    /makeHarnessDefaultRuntimeDispatchProof/,
    /workflow_component_adapter_live/,
    /workflow_component_adapter_gated/,
    /livePromotionReadinessProof/,
    /workerBindingRegistryRecord/,
    /workerAttachReceipt/,
    /workerSessionRecord/,
    /activationRollbackProof/,
    /activationRollbackExecution/,
  ]) {
    assert.match(workflow, pattern);
  }

  for (const pattern of [
    /cognitionExecutionAdapterResults/,
    /routingModelAdapterResults/,
    /verificationOutputAdapterResults/,
    /authorityToolingAdapterResults/,
    /workerBindingRegistryBound/,
    /workerAttachAccepted/,
    /workerSessionRecordBound/,
    /activeRuntimeRollbackProofWorkbench/,
    /activeRuntimeRollbackApplyExecution/,
  ]) {
    assert.match(guiValidation, pattern);
  }
});

test("harness authority tokens only appear in approved substrate surfaces", () => {
  const sourceRoots = [
    "crates/services/src/agentic/runtime",
    "packages/hypervisor-workbench/src",
    "scripts/lib",
  ];
  const sourceFiles = sourceRoots.flatMap(walkSourceFiles);
  const tokenPattern = new RegExp(harnessAuthorityTokens.join("|"));
  const filesWithAuthorityTokens = sourceFiles
    .filter((relativePath) => tokenPattern.test(read(relativePath)))
    .sort();

  assert.deepEqual(filesWithAuthorityTokens, [...harnessAuthorityAllowlist].sort());
});

test("active harness sources do not reintroduce retired runtime fallback authority", () => {
  const sourceRoots = [
    "crates/services/src/agentic/runtime",
    "crates/types/src/app",
    "apps/hypervisor/src/windows/HypervisorShellWindow",
    "packages/hypervisor-workbench/src",
    "scripts/lib",
    ".internal/plans",
  ];
  const sourceFiles = sourceRoots.flatMap(walkSourceFiles).filter(
    (relativePath) =>
      relativePath !== "scripts/lib/harness-modularity-guard.test.mjs",
  );
  const offenders = [];

  for (const relativePath of sourceFiles) {
    const source = read(relativePath);
    for (const token of retiredHarnessRuntimeTokens) {
      if (source.includes(token)) {
        offenders.push(`${relativePath}: ${token}`);
      }
    }
  }

  assert.deepEqual(offenders, []);
});
