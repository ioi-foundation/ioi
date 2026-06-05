#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const GUIDE = "docs/architecture/_meta/hypervisor-kernel-substrate-unification-master-guide.md";
const MATRIX = "docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md";
const IMPLEMENTATION_MATRIX = "docs/architecture/_meta/implementation-matrix.md";
const SOURCE_OF_TRUTH = "docs/architecture/_meta/source-of-truth-map.md";

const TIERS = ["docs", "abi", "bridge", "receipts", "ctee", "compositor", "negative"];
const COMMANDS = [
  "hypervisor-conformance",
  ...TIERS.map((tier) => `hypervisor-conformance:${tier}`),
];

const REQUIRED_NEGATIVE_CASES = [
  "direct JS authoritative mutation fails",
  "direct accepted receipt append outside the Rust core fails",
  "Agentgres operation append without expected heads/state-root binding fails",
  "storage backend write without Agentgres ArtifactRef/PayloadRef fails",
  "cTEE private workspace plaintext mount on an untrusted node fails",
  "external capability exit without wallet.network authority fails",
  "L1 settlement attempt without trigger fails",
  "workflow compositor attempt to create accepted truth directly fails",
];

function relativePath(absolutePath) {
  return path.relative(repoRoot, absolutePath);
}

function absolutePath(relative) {
  return path.join(repoRoot, relative);
}

function exists(relative) {
  return fs.existsSync(absolutePath(relative));
}

function read(relative) {
  return fs.readFileSync(absolutePath(relative), "utf8");
}

function listTrackedMarkdownUnder(relativeRoot) {
  const result = spawnSync("git", ["ls-files", relativeRoot], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `git ls-files ${relativeRoot} failed`);
  }
  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.endsWith(".md") && exists(line));
}

function collectFiles(relativeRoot, predicate) {
  const root = absolutePath(relativeRoot);
  if (!fs.existsSync(root)) return [];
  const entries = fs.readdirSync(root, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const child = path.join(relativeRoot, entry.name);
    if (entry.isDirectory()) return collectFiles(child, predicate);
    return predicate(child) ? [child] : [];
  });
}

function createTierResult(tier) {
  return {
    tier,
    checks: [],
    failures: [],
  };
}

function pass(result, id, evidence, message) {
  result.checks.push({ id, status: "passed", evidence, message });
}

function fail(result, id, evidence, message) {
  result.checks.push({ id, status: "failed", evidence, message });
  result.failures.push(`${id}: ${message}`);
}

function assertCheck(result, id, condition, evidence, message) {
  if (condition) {
    pass(result, id, evidence, message);
  } else {
    fail(result, id, evidence, message);
  }
}

function requireText(result, id, content, text, evidence) {
  assertCheck(result, id, content.includes(text), evidence, `missing required text: ${text}`);
}

function staleTermAllowed(file, line) {
  if (file === GUIDE) return true;
  if (file === "docs/architecture/_meta/canon-readability-audit.md") return true;
  if (/deprecated|historical|legacy|supersedes|watchlist|wrong;|not a peer runtime/i.test(line)) {
    return true;
  }
  return false;
}

function checkStaleLiveTerminology(result) {
  const patterns = [
    {
      name: "Default Harness Runtime",
      pattern: /\bDefault Harness Runtime\b/,
    },
    {
      name: "Rust/WASM runtime beside daemon",
      pattern: /\bRust\/WASM runtime\b/i,
    },
    {
      name: "Autopilot live architecture naming",
      pattern: /\bAutopilot\b/,
    },
  ];
  const offenders = [];
  for (const file of listTrackedMarkdownUnder("docs/architecture")) {
    const lines = read(file).split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const { name, pattern } of patterns) {
        if (pattern.test(line) && !staleTermAllowed(file, line)) {
          offenders.push(`${file}:${index + 1}: ${name}: ${line.trim()}`);
        }
      }
    });
  }
  assertCheck(
    result,
    "docs-stale-live-terminology",
    offenders.length === 0,
    offenders.length === 0 ? ["docs/architecture"] : offenders,
    "stale live-architecture terminology must be qualified or removed",
  );
}

function runDocs() {
  const result = createTierResult("docs");
  const requiredFiles = [
    GUIDE,
    MATRIX,
    IMPLEMENTATION_MATRIX,
    SOURCE_OF_TRUTH,
    "docs/architecture/components/daemon-runtime/default-harness-profile.md",
    "docs/architecture/components/daemon-runtime/doctrine.md",
    "docs/architecture/components/daemon-runtime/private-workspace-ctee.md",
    "docs/architecture/components/agentgres/doctrine.md",
    "docs/architecture/components/agentgres/artifact-ref-plane.md",
    "docs/architecture/components/wallet-network/doctrine.md",
    "docs/architecture/components/storage-backends/doctrine.md",
    "packages/runtime-daemon/src/coding-tools.mjs",
    "crates/services/src/agentic/runtime/kernel/invocation.rs",
    "crates/vm/wasm/src/lib.rs",
    "crates/client/src/workload_client/mod.rs",
  ];

  for (const file of requiredFiles) {
    assertCheck(result, `exists:${file}`, exists(file), [file], `${file} must exist`);
  }
  if (result.failures.length > 0) return result;

  const guide = read(GUIDE);
  const matrix = read(MATRIX);
  const implementationMatrix = read(IMPLEMENTATION_MATRIX);
  const sourceMap = read(SOURCE_OF_TRUTH);
  const packageJson = JSON.parse(read("package.json"));

  requireText(result, "guide-terminal-condition", guide, "### Terminal condition", [GUIDE]);
  requireText(result, "guide-command-contract", guide, "### Conformance command contract", [GUIDE]);
  requireText(result, "guide-slice-template", guide, "ImplementationSlice:", [GUIDE]);
  for (const command of COMMANDS) {
    requireText(result, `guide-command:${command}`, guide, command, [GUIDE]);
  }
  for (const negativeCase of REQUIRED_NEGATIVE_CASES) {
    requireText(result, `guide-negative:${negativeCase}`, guide, negativeCase, [GUIDE]);
  }

  const routeFamilies = [
    "coding-tools",
    "approvals-gates",
    "runtime-events-replay-trace",
    "model-mounting",
    "agentgres-admission",
    "receipt-binding",
    "ctee-private-workspace",
    "workload-client-wasm",
    "workflow-compositor",
    "worker-service-packages",
    "meta-improvement",
    "rust-daemon-core",
    "js-facade-retirement",
  ];
  for (const routeFamily of routeFamilies) {
    requireText(result, `matrix-route:${routeFamily}`, matrix, `\`${routeFamily}\``, [MATRIX]);
  }

  for (const concept of [
    "StepModuleInvocation",
    "StepModuleResult",
    "StepModuleRouter",
    "HypervisorKernelSubstrateMigration",
  ]) {
    requireText(result, `implementation-matrix:${concept}`, implementationMatrix, `\`${concept}\``, [
      IMPLEMENTATION_MATRIX,
    ]);
  }

  requireText(result, "source-map-master-guide", sourceMap, "hypervisor-kernel-substrate-unification-master-guide.md", [
    SOURCE_OF_TRUTH,
  ]);
  requireText(result, "source-map-migration-matrix", sourceMap, "hypervisor-kernel-substrate-migration-matrix.md", [
    SOURCE_OF_TRUTH,
  ]);

  const expectedScripts = new Map([
    ["hypervisor-conformance", "node scripts/conformance/hypervisor-conformance.mjs all"],
    ["hypervisor-conformance:docs", "node scripts/conformance/hypervisor-conformance.mjs docs"],
    ["hypervisor-conformance:abi", "node scripts/conformance/hypervisor-conformance.mjs abi"],
    ["hypervisor-conformance:bridge", "node scripts/conformance/hypervisor-conformance.mjs bridge"],
    ["hypervisor-conformance:receipts", "node scripts/conformance/hypervisor-conformance.mjs receipts"],
    ["hypervisor-conformance:ctee", "node scripts/conformance/hypervisor-conformance.mjs ctee"],
    ["hypervisor-conformance:compositor", "node scripts/conformance/hypervisor-conformance.mjs compositor"],
    ["hypervisor-conformance:negative", "node scripts/conformance/hypervisor-conformance.mjs negative"],
  ]);
  for (const [script, command] of expectedScripts.entries()) {
    assertCheck(
      result,
      `package-script:${script}`,
      packageJson.scripts?.[script] === command,
      ["package.json"],
      `${script} must be wired to ${command}`,
    );
  }

  checkStaleLiveTerminology(result);
  return result;
}

function codeCorpusContains(pattern) {
  const files = [
    ...collectFiles("packages/runtime-daemon/src", (file) => /\.(mjs|js|ts)$/.test(file)),
    ...collectFiles("crates/services/src/agentic/runtime", (file) => file.endsWith(".rs")),
    ...collectFiles("crates/client/src", (file) => file.endsWith(".rs")),
    ...collectFiles("crates/vm/wasm/src", (file) => file.endsWith(".rs")),
  ];
  return files.some((file) => pattern.test(read(file)));
}

function runAbi() {
  const result = createTierResult("abi");
  const rustInvocation = exists("crates/services/src/agentic/runtime/kernel/invocation.rs")
    ? read("crates/services/src/agentic/runtime/kernel/invocation.rs")
    : "";
  const jsTools = exists("packages/runtime-daemon/src/coding-tools.mjs")
    ? read("packages/runtime-daemon/src/coding-tools.mjs")
    : "";
  const stepModuleAbi = exists("packages/runtime-daemon/src/step-module-abi.mjs")
    ? read("packages/runtime-daemon/src/step-module-abi.mjs")
    : "";

  assertCheck(
    result,
    "rust-invocation-envelopes-exist",
    /ToolInvocationEnvelope/.test(rustInvocation) &&
      /ModelInvocationEnvelope/.test(rustInvocation) &&
      /WorkflowInvocationEnvelope/.test(rustInvocation) &&
      /GraphInvocationEnvelope/.test(rustInvocation),
    ["crates/services/src/agentic/runtime/kernel/invocation.rs"],
    "Rust-side existing invocation envelopes must be present as ABI input anchors",
  );
  assertCheck(
    result,
    "js-coding-tool-contracts-exist",
    /codingToolContracts/.test(jsTools) && /workspace\.status/.test(jsTools) && /file\.apply_patch/.test(jsTools),
    ["packages/runtime-daemon/src/coding-tools.mjs"],
    "JS coding tool contracts must be present as live route-family anchors",
  );
  assertCheck(
    result,
    "step-module-invocation-schema-implemented",
    codeCorpusContains(/ioi\.step_module_invocation\.v1/) &&
      codeCorpusContains(/StepModuleInvocation/) &&
      exists("crates/services/src/agentic/runtime/kernel/step_module.rs"),
    [
      "crates/services/src/agentic/runtime/kernel/step_module.rs",
      "packages/runtime-daemon/src",
      "docs/architecture/_meta/hypervisor-kernel-substrate-unification-master-guide.md",
    ],
    "Phase 1 is pending: implement StepModuleInvocation schema outside docs and map every live route family",
  );
  assertCheck(
    result,
    "step-module-result-schema-implemented",
    codeCorpusContains(/ioi\.step_module_result\.v1/) &&
      codeCorpusContains(/StepModuleResult/) &&
      exists("crates/services/src/agentic/runtime/kernel/step_module.rs"),
    [
      "crates/services/src/agentic/runtime/kernel/step_module.rs",
      "packages/runtime-daemon/src",
      "docs/architecture/_meta/hypervisor-kernel-substrate-unification-master-guide.md",
    ],
    "Phase 1 is pending: implement StepModuleResult schema outside docs and bind observations, receipts, refs, and projections",
  );
  assertCheck(
    result,
    "js-coding-tool-abi-projection-wrapper",
    exists("packages/runtime-daemon/src/step-module-abi.mjs") &&
      /createCodingToolStepModuleProjection/.test(stepModuleAbi) &&
      /codingToolStepModuleProjection/.test(read("packages/runtime-daemon/src/coding-tools.mjs")) &&
      /moduleKind = "workload_job"/.test(stepModuleAbi) &&
      /executionBackend = "workload_grpc"/.test(stepModuleAbi) &&
      !/executionBackend = "daemon_js"/.test(stepModuleAbi),
    ["packages/runtime-daemon/src/step-module-abi.mjs", "packages/runtime-daemon/src/coding-tools.mjs"],
    "Phase 1 is pending: JS coding tool contracts must emit Step/Module wrappers in projection mode",
  );
  assertCheck(
    result,
    "js-model-mount-abi-projection-wrapper",
    /createModelMountStepModuleProjection/.test(stepModuleAbi) &&
      /createStepModuleInvocationForModelMount/.test(stepModuleAbi) &&
      /createStepModuleResultForModelMount/.test(stepModuleAbi) &&
      /kind: "model_mount"/.test(stepModuleAbi) &&
      /backend: "model_mount"/.test(stepModuleAbi),
    ["packages/runtime-daemon/src/step-module-abi.mjs"],
    "Phase 1/4 is pending: model mount invocation receipts must project into the shared Step/Module ABI",
  );
  assertCheck(
    result,
    "js-coding-tool-abi-coverage-test",
    exists("packages/runtime-daemon/src/step-module-abi.test.mjs") &&
      /every coding tool contract/.test(read("packages/runtime-daemon/src/step-module-abi.test.mjs")),
    ["packages/runtime-daemon/src/step-module-abi.test.mjs"],
    "Phase 1 is pending: add JS coverage proving every coding tool contract projects into the ABI",
  );
  return result;
}

function runBridge() {
  const result = createTierResult("bridge");
  const bridgeBin = exists("crates/node/src/bin/ioi-step-module-bridge.rs")
    ? read("crates/node/src/bin/ioi-step-module-bridge.rs")
    : "";
  const bridgeModule = exists("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    ? read("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    : "";
  const runtimeDaemonIndex = exists("packages/runtime-daemon/src/index.mjs")
    ? read("packages/runtime-daemon/src/index.mjs")
    : "";
  const modelMountingState = exists("packages/runtime-daemon/src/model-mounting.mjs")
    ? read("packages/runtime-daemon/src/model-mounting.mjs")
    : "";
  const modelMountAdmissionRunner = exists("packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs")
    : "";
  const modelRoutes = exists("packages/runtime-daemon/src/model-mounting/routes.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/routes.mjs")
    : "";
  const modelRouteDecisionModule = exists("packages/runtime-daemon/src/model-mounting/route-decision.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/route-decision.mjs")
    : "";
  const modelRouteDecisionTest = exists("packages/runtime-daemon/src/model-mounting/route-decision.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/route-decision.test.mjs")
    : "";
  const modelProjections = exists("packages/runtime-daemon/src/model-mounting/projections.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/projections.mjs")
    : "";
  const modelProjectionsTest = exists("packages/runtime-daemon/src/model-mounting/projections.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/projections.test.mjs")
    : "";
  const modelWorkflowNode = exists("packages/runtime-daemon/src/model-mounting/workflow-node.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/workflow-node.mjs")
    : "";
  const modelWorkflowNodeTest = exists("packages/runtime-daemon/src/model-mounting/workflow-node.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/workflow-node.test.mjs")
    : "";
  const modelInvocationOps = exists("packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs")
    : "";
  const modelMountingReadModel = exists("packages/runtime-daemon/src/model-mounting/read-model.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/read-model.mjs")
    : "";
  const modelMountingReadModelTest = exists("packages/runtime-daemon/src/model-mounting/read-model.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/read-model.test.mjs")
    : "";
  const modelMountingReadProjectionFacade = exists("packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs")
    : "";
  const modelMountingReadProjectionFacadeTest = exists(
    "packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs",
  )
    ? read("packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs")
    : "";
  const stepModuleRunner = exists("packages/runtime-daemon/src/step-module-runner.mjs")
    ? read("packages/runtime-daemon/src/step-module-runner.mjs")
    : "";
  const runtimeCodingToolInvocationSurface = exists("packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs")
    : "";
  const runtimeCodingToolInvocationSurfaceTest = exists("packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs")
    : "";
  const runtimeCodingToolGovernanceSurface = exists("packages/runtime-daemon/src/runtime-coding-tool-governance-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-governance-surface.mjs")
    : "";
  const runtimeCodingToolGovernanceSurfaceTest = exists("packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs")
    : "";
  const codingTools = exists("packages/runtime-daemon/src/coding-tools.mjs")
    ? read("packages/runtime-daemon/src/coding-tools.mjs")
    : "";
  const governedImprovementRunner = exists("packages/runtime-daemon/src/runtime-governed-improvement-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-governed-improvement-runner.mjs")
    : "";
  const governedImprovementRunnerTest = exists("packages/runtime-daemon/src/runtime-governed-improvement-runner.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-governed-improvement-runner.test.mjs")
    : "";
  const governedImprovementStoreTest = exists("packages/runtime-daemon/src/runtime-governed-improvement-store.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-governed-improvement-store.test.mjs")
    : "";
  const governedImprovementSurface = exists("packages/runtime-daemon/src/runtime-governed-improvement-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-governed-improvement-surface.mjs")
    : "";
  const governedImprovementSurfaceTest = exists("packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs")
    : "";
  const runtimeRouteHandlers = exists("packages/runtime-daemon/src/runtime-route-handlers.mjs")
    ? read("packages/runtime-daemon/src/runtime-route-handlers.mjs")
    : "";
  const runtimeRouteHandlersTest = exists("packages/runtime-daemon/src/runtime-route-handlers.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-route-handlers.test.mjs")
    : "";
  const runtimeThreadControlSurface = exists("packages/runtime-daemon/src/runtime-thread-control-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-thread-control-surface.mjs")
    : "";
  const runtimeThreadControlSurfaceTest = exists("packages/runtime-daemon/src/runtime-thread-control-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-thread-control-surface.test.mjs")
    : "";
  const threadRuntimeControls = exists("packages/runtime-daemon/src/threads/thread-runtime-controls.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-runtime-controls.mjs")
    : "";
  const threadRuntimeControlsTest = exists("packages/runtime-daemon/src/threads/thread-runtime-controls.test.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-runtime-controls.test.mjs")
    : "";
  const workerServicePackageRunner = exists("packages/runtime-daemon/src/runtime-worker-service-package-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-worker-service-package-runner.mjs")
    : "";
  const workerServicePackageRunnerTest = exists("packages/runtime-daemon/src/runtime-worker-service-package-runner.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-worker-service-package-runner.test.mjs")
    : "";
  const workerServicePackageStoreTest = exists("packages/runtime-daemon/src/runtime-worker-service-package-store.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-worker-service-package-store.test.mjs")
    : "";
  const workerServicePackageSurface = exists("packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs")
    : "";
  const workerServicePackageSurfaceTest = exists("packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs")
    : "";
  const agentSdkSubstrateClient = exists("packages/agent-sdk/src/substrate-client.ts")
    ? read("packages/agent-sdk/src/substrate-client.ts")
    : "";
  const agentSdkMessages = exists("packages/agent-sdk/src/messages.ts")
    ? read("packages/agent-sdk/src/messages.ts")
    : "";
  const agentSdkOptions = exists("packages/agent-sdk/src/options.ts")
    ? read("packages/agent-sdk/src/options.ts")
    : "";
  const workflowStructuredPolicyComposer = exists(
    "packages/agent-ide/src/runtime/workflow-structured-policy-composer.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-structured-policy-composer.ts")
    : "";
  const workflowStructuredPolicyComposerTest = exists(
    "packages/agent-ide/src/runtime/workflow-structured-policy-composer.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-structured-policy-composer.test.ts")
    : "";
  const workflowModelCapabilityBinding = exists(
    "packages/agent-ide/src/runtime/workflow-model-capability-binding.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-model-capability-binding.ts")
    : "";
  const workflowModelCapabilityBindingTest = exists(
    "packages/agent-ide/src/runtime/workflow-model-capability-binding.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-model-capability-binding.test.ts")
    : "";
  const workerServicePackageAdmissionResultType =
    agentSdkSubstrateClient.match(
      /export interface RuntimeWorkerServicePackageInvocationAdmissionResult[\s\S]*?\n}\n/,
    )?.[0] ?? "";
  const workerServicePackageAdmissionCamelAliasPropertyPattern =
    /\b(?:schemaVersion|invocationAdmitted|threadId|agentId|packageKind|packageRef|manifestRef|invocationId|routerAdmission|receiptBinding|acceptedReceiptAppend|agentgresAdmission|projectionRecord|receiptRefs|artifactRefs|payloadRefs|authorityGrantRefs)\s*:/;
  const workerServicePackageAdmissionCamelAliasTypePattern =
    /\b(?:schemaVersion|invocationAdmitted|threadId|agentId|packageKind|packageRef|manifestRef|invocationId|routerAdmission|receiptBinding|acceptedReceiptAppend|agentgresAdmission|projectionRecord|receiptRefs|artifactRefs|payloadRefs|authorityGrantRefs)\?:/;
  const governedImprovementAdmissionResultType =
    agentSdkSubstrateClient.match(
      /export interface RuntimeGovernedImprovementProposalAdmissionResult[\s\S]*?\n}\n/,
    )?.[0] ?? "";
  const governedImprovementAdmissionCamelAliasPropertyPattern =
    /\b(?:schemaVersion|proposalAdmitted|mutationExecuted|threadId|agentId|proposalId|admissionHash|agentgresOperationRef|stateRootBefore|stateRootAfter|resultingHead|approvalRef|rollbackRef)\s*:/;
  const governedImprovementAdmissionCamelAliasTypePattern =
    /\b(?:schemaVersion|proposalAdmitted|mutationExecuted|threadId|agentId|proposalId|admissionHash|agentgresOperationRef|stateRootBefore|stateRootAfter|resultingHead|approvalRef|rollbackRef)\?:/;
  const l1SettlementAdmissionResultType =
    agentSdkSubstrateClient.match(
      /export interface RuntimeL1SettlementAttemptAdmissionResult[\s\S]*?\n}\n/,
    )?.[0] ?? "";
  const l1SettlementAdmissionCamelAliasPropertyPattern =
    /\b(?:schemaVersion|settlementAdmitted|threadId|agentId|settlementRef|domainRef|stateRootRef|triggerRefs|receiptRefs|admissionHash)\s*:/;
  const l1SettlementAdmissionCamelAliasTypePattern =
    /\b(?:schemaVersion|settlementAdmitted|threadId|agentId|settlementRef|domainRef|stateRootRef|triggerRefs|receiptRefs|admissionHash)\?:/;
  const agentSdkTest = exists("packages/agent-sdk/test/sdk.test.mjs")
    ? read("packages/agent-sdk/test/sdk.test.mjs")
    : "";
  const agentIdeIndex = exists("packages/agent-ide/src/index.ts")
    ? read("packages/agent-ide/src/index.ts")
    : "";
  const graphRuntimeTypes = exists("packages/agent-ide/src/runtime/graph-runtime-types.ts")
    ? read("packages/agent-ide/src/runtime/graph-runtime-types.ts")
    : "";
  const governedImprovementControlNodes = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.ts")
    : "";
  const governedImprovementControlNodesTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.test.ts")
    : "";
  const workerServicePackageControlNodes = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.ts")
    : "";
  const workerServicePackageControlNodesTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.test.ts")
    : "";
  const l1SettlementRunner = exists("packages/runtime-daemon/src/runtime-l1-settlement-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-l1-settlement-runner.mjs")
    : "";
  const l1SettlementRunnerTest = exists("packages/runtime-daemon/src/runtime-l1-settlement-runner.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-l1-settlement-runner.test.mjs")
    : "";
  const l1SettlementStoreTest = exists("packages/runtime-daemon/src/runtime-l1-settlement-store.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-l1-settlement-store.test.mjs")
    : "";
  const l1SettlementSurface = exists("packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs")
    : "";
  const l1SettlementSurfaceTest = exists("packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs")
    : "";
  const l1SettlementControlNodes = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.ts")
    : "";
  const l1SettlementControlNodesTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.test.ts")
    : "";
  const cliMain = exists("crates/cli/src/main.rs") ? read("crates/cli/src/main.rs") : "";
  const cliRuntime = exists("crates/cli/src/commands/runtime.rs")
    ? read("crates/cli/src/commands/runtime.rs")
    : "";
  const retiredCodingToolJsBodyPattern =
    /function (?:computerUseLeaseRequestTool|workspaceStatusTool|gitDiffTool|fileInspectTool|fileApplyPatchTool|testRunTool|lspDiagnosticsTool|artifactReadTool|toolRetrieveResultTool)\(/;
  const retiredCodingToolJsImportPattern =
    /(?:node:child_process|node:fs|node:path|node:crypto|computerUseProviderForLane|computerUseProviderRegistryReport|computerUseThreadToolNameForProvider)/;
  const openAiCompatibleDriver = exists("packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.mjs")
    : "";
  const providerLocalDrivers = exists("packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs")
    : "";
  const nativeLocalFixture = exists("packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs")
    : "";
  const retiredNativeFixtureResponseFiles = [
    "packages/runtime-daemon/src/model-mounting/native-fixture-artifacts.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-intent.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-intent.test.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-repo-aware.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-repo-aware.test.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-stage2-web-repair.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-stage2-web-repair.test.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-stage5-stop-hook-repair.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-stage5-stop-hook-repair.test.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-tool-catalogue.mjs",
    "packages/runtime-daemon/src/model-mounting/native-fixture-tool-catalogue.test.mjs",
    "scripts/lib/workflow-native-fixture-intent-refactor-proof.mjs",
  ];
  const openAiBackendDrivers = exists("packages/runtime-daemon/src/model-mounting/provider-openai-backend-drivers.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-openai-backend-drivers.mjs")
    : "";
  const lmStudioDriver = exists("packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs")
    : "";
  const openAiCompatibleProviderDrivers = [openAiCompatibleDriver, openAiBackendDrivers, lmStudioDriver].join("\n");
  const openAiCompatRoutes = exists("packages/runtime-daemon/src/openai-compat-routes.mjs")
    ? read("packages/runtime-daemon/src/openai-compat-routes.mjs")
    : "";
  const retiredRouteDecisionEnvPattern = new RegExp("MODEL_MOUNT_" + "ROUTE_DECISION_COMMAND_ENV");
  assertCheck(
    result,
    "step-module-runner-interface",
    codeCorpusContains(/StepModuleRunner/),
    ["packages/runtime-daemon/src", "crates/services/src/agentic/runtime"],
    "Phase 2 is pending: add StepModuleRunner interface and runner selection",
  );
  assertCheck(
    result,
    "rust-workload-step-module-runner",
    /RustWorkloadStepModuleRunner/.test(stepModuleRunner) &&
      /IOI_STEP_MODULE_BACKEND/.test(stepModuleRunner) &&
      /IOI_WORKLOAD_GRPC_ADDR/.test(stepModuleRunner) &&
      /options\.backend \?\? env\[STEP_MODULE_BACKEND_ENV\] \?\? "rust_workload_live"/.test(stepModuleRunner) &&
      /String\(value \?\? ""\)\.trim\(\)\.toLowerCase\(\) \|\| "rust_workload_live"/.test(stepModuleRunner) &&
      !/DaemonJsStepModuleRunner/.test(stepModuleRunner) &&
      !/"daemon_js",/.test(stepModuleRunner) &&
      /daemon-js StepModule backend selection fails closed/.test(
        read("packages/runtime-daemon/src/step-module-runner.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/step-module-runner.mjs",
      "packages/runtime-daemon/src/step-module-runner.test.mjs",
      "crates/client/src/workload_client/mod.rs",
    ],
    "Phase 2 is pending: default StepModule execution must be Rust workload live and explicit daemon_js backend selection must fail closed",
  );
  assertCheck(
    result,
    "migrated-coding-tools-rust-command-bridge",
    exists("crates/node/src/bin/ioi-step-module-bridge.rs") &&
      exists("crates/node/src/bin/ioi_step_module_bridge/mod.rs") &&
      exists("packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs") &&
      /run_bridge_response_from_stdin/.test(bridgeBin) &&
      /workspace\.status/.test(bridgeModule) &&
      /inspect_workspace_status/.test(bridgeModule) &&
      !/workspace_status_shadow_response/.test(bridgeModule) &&
      /git\.diff/.test(bridgeModule) &&
      /file\.inspect/.test(bridgeModule) &&
      /file\.apply_patch/.test(bridgeModule) &&
      /apply_workspace_patch/.test(bridgeModule) &&
      /AgentgresAdmissionCore/.test(bridgeModule) &&
      /test\.run/.test(bridgeModule) &&
      /inspect_test_run/.test(bridgeModule) &&
      /npm\.test/.test(bridgeModule) &&
      /cargo\.test/.test(bridgeModule) &&
      /cargo\.check/.test(bridgeModule) &&
      /lsp\.diagnostics/.test(bridgeModule) &&
      /inspect_lsp_diagnostics/.test(bridgeModule) &&
      /typescript\.check/.test(bridgeModule) &&
      /run_typescript_check/.test(bridgeModule) &&
      /local_tsc_executable/.test(bridgeModule) &&
      /artifact\.read/.test(bridgeModule) &&
      /tool\.retrieve_result/.test(bridgeModule) &&
      /normalize_prefetched_artifact_result/.test(bridgeModule) &&
      /computer_use\.request_lease/.test(bridgeModule) &&
      /build_computer_use_lease_request/.test(bridgeModule) &&
      /ioi\.step_module\.command_bridge\.v1/.test(bridgeModule) &&
      /StepModuleRouterCore/.test(bridgeModule) &&
      /router_admission/.test(bridgeModule) &&
      /RUST_WORKLOAD_LIVE_TOOL_IDS/.test(runtimeCodingToolInvocationSurface) &&
      /workspace\.status/.test(runtimeCodingToolInvocationSurface) &&
      /git\.diff/.test(runtimeCodingToolInvocationSurface) &&
      /file\.inspect/.test(runtimeCodingToolInvocationSurface) &&
      /file\.apply_patch/.test(runtimeCodingToolInvocationSurface) &&
      /test\.run/.test(runtimeCodingToolInvocationSurface) &&
      /lsp\.diagnostics/.test(runtimeCodingToolInvocationSurface) &&
      /artifact\.read/.test(runtimeCodingToolInvocationSurface) &&
      /tool\.retrieve_result/.test(runtimeCodingToolInvocationSurface) &&
      /computer_use\.request_lease/.test(runtimeCodingToolInvocationSurface) &&
      /rustWorkloadDataPlane/.test(runtimeCodingToolInvocationSurface) &&
      /rust_workload_live/.test(runtimeCodingToolInvocationSurface) &&
      /coding_tool_rust_workload_live_required/.test(runtimeCodingToolInvocationSurface) &&
      !/executeCodingTool/.test(runtimeCodingToolInvocationSurface) &&
      !/executeCodingTool/.test(codingTools) &&
      !/executeCodingTool/.test(runtimeDaemonIndex) &&
      !retiredCodingToolJsBodyPattern.test(codingTools) &&
      !retiredCodingToolJsImportPattern.test(codingTools) &&
      /coding tool invocation surface rejects non-live coding-tool runners before JS execution/.test(
        runtimeCodingToolInvocationSurfaceTest,
      ),
    [
      "crates/node/src/bin/ioi-step-module-bridge.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/coding-tools.mjs",
      "packages/runtime-daemon/src/index.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs",
    ],
    "Phase 3/10 is pending: route migrated coding tools through the Rust command bridge, StepModuleRouter, and live workload path without daemon_js",
  );
  assertCheck(
    result,
    "coding-tool-result-router-admission-alias-retired",
    !/\brouterAdmission\s*:/.test(runtimeCodingToolInvocationSurface) &&
      /result\.result\.router_admission\.schema_version/.test(
        runtimeCodingToolInvocationSurfaceTest,
      ) &&
      /Object\.hasOwn\(result\.result,\s*"routerAdmission"\),\s*false/.test(
        runtimeCodingToolInvocationSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs",
    ],
    "Phase 10/11 is pending: Rust live coding-tool results must expose canonical router_admission without the retired routerAdmission response alias",
  );
  assertCheck(
    result,
    "coding-tool-budget-usage-response-alias-retired",
    !/budgetUsageTelemetry:\s*budgetPolicy\.usageTelemetry/.test(
      runtimeCodingToolInvocationSurface,
    ) &&
      !/budgetUsageTelemetry:\s*budgetPolicy\.usageTelemetry/.test(
        runtimeCodingToolGovernanceSurface,
      ) &&
      /budget_usage_telemetry:\s*budgetPolicy\.usage_telemetry/.test(
        runtimeCodingToolInvocationSurface,
      ) &&
      /budget_usage_telemetry:\s*budgetPolicy\.usage_telemetry/.test(
        runtimeCodingToolGovernanceSurface,
      ) &&
      /hasOwnProperty\.call\(\s*error\.details,\s*"budgetUsageTelemetry"/.test(
        runtimeCodingToolInvocationSurfaceTest,
      ) &&
      /hasOwnProperty\.call\(\s*result\.result\.error\.details,\s*"budgetUsageTelemetry"/.test(
        runtimeCodingToolGovernanceSurfaceTest,
      ) &&
      /hasOwnProperty\.call\(\s*result\.event\.payload_summary,\s*"budgetUsageTelemetry"/.test(
        runtimeCodingToolGovernanceSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-invocation-surface.test.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-governance-surface.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-governance-surface.test.mjs",
    ],
    "Phase 10/11 is pending: coding-tool budget block responses must expose canonical budget_usage_telemetry without duplicate budgetUsageTelemetry",
  );
  assertCheck(
    result,
    "model-mount-route-decision-live-bridge",
    /admit_model_mount_route_decision/.test(bridgeModule) &&
      /ModelMountCore/.test(bridgeModule) &&
      /ModelMountRouteDecisionRequest/.test(bridgeModule) &&
      /bridge_admits_model_mount_route_decision_through_rust_core/.test(bridgeModule) &&
      /RustModelMountAdmissionRunner/.test(modelMountAdmissionRunner) &&
      /MODEL_MOUNT_ADMISSION_COMMAND_ENV/.test(modelMountAdmissionRunner) &&
      !retiredRouteDecisionEnvPattern.test(modelMountAdmissionRunner) &&
      /model_mount_admission_bridge_unconfigured/.test(modelMountAdmissionRunner) &&
      /admitModelMountRouteDecision/.test(modelMountingState) &&
      /createModelMountAdmissionRunnerFromEnv/.test(modelMountingState) &&
      /modelMountRouteDecisionRequestForSelection/.test(modelRoutes) &&
      /model_mount_route_decision_admission_required/.test(modelRoutes) &&
      /model_mount_route_decision_receipt_id_required/.test(modelRoutes) &&
      /model_mount_route_decision_ref/.test(modelRoutes) &&
      !/modelMountRouteDecision(?:SchemaVersion|Ref|Hash|Source|Backend|ReceiptRefs)?\s*:/.test(modelRoutes) &&
      /model_route_decision_schema_version/.test(modelRoutes) &&
      /model_route_decision_event_kind/.test(modelRoutes) &&
      /model_route_decision_id/.test(modelRoutes) &&
      /model_route_decision:\s*modelRouteDecision/.test(modelRoutes) &&
      !/modelRouteDecision(?:SchemaVersion|EventKind|Id)/.test(modelRoutes) &&
      /details\?\.model_route_decision/.test(modelRouteDecisionModule) &&
      !/details\?\.modelRouteDecision/.test(modelRouteDecisionModule) &&
      /model_route_decision:\s*receipt\.details\?\.model_route_decision/.test(modelProjections) &&
      !/modelRouteDecision:\s*receipt\.details/.test(modelProjections) &&
      /route_decision:\s*invocation\.routeReceipt\?\.details\?\.model_route_decision/.test(modelWorkflowNode) &&
      !/route_decision:\s*invocation\.routeReceipt\?\.details\?\.modelRouteDecision/.test(modelWorkflowNode) &&
      /route_decision:\s*invocation\.routeReceipt\?\.details\?\.model_route_decision/.test(openAiCompatRoutes) &&
      !/route_decision:\s*invocation\.routeReceipt\?\.details\?\.modelRouteDecision/.test(openAiCompatRoutes) &&
      /allow_hosted_fallback/.test(modelRoutes) &&
      !/allowHostedFallback/.test(modelRoutes) &&
      /allow_hosted_fallback/.test(
        modelRouteDecisionModule,
      ) &&
      !/allowHostedFallback/.test(modelRouteDecisionModule) &&
      /request\.fallback_triggered/.test(modelRouteDecisionModule) &&
      /request\.fallback_reason/.test(modelRouteDecisionModule) &&
      !/request\.fallbackTriggered/.test(modelRouteDecisionModule) &&
      !/request\.fallbackReason/.test(modelRouteDecisionModule) &&
      /ignore retired hosted fallback policy alias/.test(
        read("packages/runtime-daemon/src/model-mounting/routes.test.mjs"),
      ) &&
      /canonical hosted fallback policy constraint/.test(
        modelRouteDecisionTest,
      ) &&
      /ignore retired camelCase fallback request aliases/.test(
        modelRouteDecisionTest,
      ) &&
      /ignore retired legacy model route decision detail/.test(
        modelRouteDecisionTest,
      ) &&
      /model_route_decision/.test(modelProjectionsTest) &&
      /canonical route decision details/.test(
        read("packages/runtime-daemon/src/openai-compat-routes.test.mjs"),
      ) &&
      /canonical route decision details/.test(
        modelWorkflowNodeTest,
      ) &&
      !/modelMountRouteDecisionRef/.test(modelInvocationOps),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/runtime-daemon/src/model-mounting/projections.mjs",
      "packages/runtime-daemon/src/model-mounting/projections.test.mjs",
      "packages/runtime-daemon/src/model-mounting/workflow-node.mjs",
      "packages/runtime-daemon/src/model-mounting/workflow-node.test.mjs",
      "packages/runtime-daemon/src/openai-compat-routes.mjs",
      "packages/runtime-daemon/src/openai-compat-routes.test.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.test.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 3/9 is pending: model-mounting route decisions must call Rust model_mount core and fail closed before provider invocation",
  );
  assertCheck(
    result,
    "runtime-thread-hosted-fallback-alias-retired",
    /allow_hosted_fallback/.test(threadRuntimeControls) &&
      /allow_hosted_fallback/.test(runtimeThreadControlSurface) &&
      !/allowHostedFallback/.test(threadRuntimeControls) &&
      !/allowHostedFallback/.test(runtimeThreadControlSurface) &&
      /retiredAliasInput/.test(threadRuntimeControlsTest) &&
      /Object\.hasOwn\(retiredAliasInput\.model,\s*"allowHostedFallback"\),\s*false/.test(
        threadRuntimeControlsTest,
      ) &&
      /Object\.hasOwn\(result\.control\.model,\s*"allowHostedFallback"\),\s*false/.test(
        runtimeThreadControlSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/threads/thread-runtime-controls.mjs",
      "packages/runtime-daemon/src/threads/thread-runtime-controls.test.mjs",
      "packages/runtime-daemon/src/runtime-thread-control-surface.mjs",
      "packages/runtime-daemon/src/runtime-thread-control-surface.test.mjs",
    ],
    "Phase 10 is pending: thread/runtime control model policy helpers must use canonical allow_hosted_fallback without the retired allowHostedFallback translator",
  );
  assertCheck(
    result,
    "sdk-ide-hosted-fallback-alias-retired",
    /allow_hosted_fallback/.test(agentSdkSubstrateClient) &&
      /allow_hosted_fallback/.test(agentSdkMessages) &&
      /allow_hosted_fallback/.test(agentSdkOptions) &&
      /allow_hosted_fallback/.test(workflowStructuredPolicyComposer) &&
      !/allowHostedFallback/.test(agentSdkSubstrateClient) &&
      !/allowHostedFallback/.test(agentSdkMessages) &&
      !/allowHostedFallback/.test(agentSdkOptions) &&
      !/allowHostedFallback/.test(workflowStructuredPolicyComposer) &&
      /canonical hosted fallback field/.test(workflowStructuredPolicyComposerTest) &&
      /Object\.prototype\.hasOwnProperty\.call\(compiled\.modelRules\[0\],\s*"allowHostedFallback"\)/.test(
        workflowStructuredPolicyComposerTest,
      ),
    [
      "packages/agent-sdk/src/substrate-client.ts",
      "packages/agent-sdk/src/messages.ts",
      "packages/agent-sdk/src/options.ts",
      "packages/agent-ide/src/runtime/workflow-structured-policy-composer.ts",
      "packages/agent-ide/src/runtime/workflow-structured-policy-composer.test.ts",
    ],
    "Phase 10 is pending: SDK/IDE model policy helper types must use canonical allow_hosted_fallback without the retired allowHostedFallback alias",
  );
  assertCheck(
    result,
    "ide-model-capability-legacy-id-projection-retired",
    /modelCapabilityRefForRoute/.test(workflowModelCapabilityBinding) &&
      !/legacyModelIdToModelCapabilityRef/.test(workflowModelCapabilityBinding) &&
      !/model-capability:legacy/.test(workflowModelCapabilityBinding) &&
      !/Legacy model id binding/.test(workflowModelCapabilityBinding) &&
      !/Compatibility grant posture/.test(workflowModelCapabilityBinding) &&
      /raw graph model ids do not mint legacy model capability refs/.test(
        workflowModelCapabilityBindingTest,
      ) &&
      /canonical graph model capability readiness remains executable/.test(
        workflowModelCapabilityBindingTest,
      ) &&
      /workflowModelBindingIsReady\(binding\),\s*false/.test(workflowModelCapabilityBindingTest),
    [
      "packages/agent-ide/src/runtime/workflow-model-capability-binding.ts",
      "packages/agent-ide/src/runtime/workflow-model-capability-binding.test.ts",
    ],
    "Phase 10/11 is pending: IDE model capability binding must not mint executable capability refs or readiness from raw legacy model ids",
  );
  assertCheck(
    result,
    "model-mount-invocation-admission-live-bridge",
    /admit_model_mount_invocation/.test(bridgeModule) &&
      /ModelMountInvocationAdmissionRequest/.test(bridgeModule) &&
      /bridge_admits_model_mount_invocation_through_rust_core/.test(bridgeModule) &&
      /admitInvocation/.test(modelMountAdmissionRunner) &&
      /rust_model_mount_invocation_command/.test(modelMountAdmissionRunner) &&
      /admitModelMountInvocation/.test(modelMountingState) &&
      /modelMountInvocationAdmissionRequestForReceipt/.test(modelInvocationOps) &&
      /model_mount_invocation_receipt_id_required/.test(modelInvocationOps) &&
      /model_mount_invocation_admission_ref/.test(modelInvocationOps) &&
      !/modelMountInvocationAdmission(?:SchemaVersion|Ref|Hash|Source|Backend|ReceiptRefs)?\s*:/.test(modelInvocationOps),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 4/9 is pending: model invocation receipts must be admitted by Rust model_mount core before JS persistence",
  );
  assertCheck(
    result,
    "model-mount-provider-execution-live-bridge",
    /admit_model_mount_provider_execution/.test(bridgeModule) &&
      /ModelMountProviderExecutionRequest/.test(bridgeModule) &&
      /bridge_admits_model_mount_provider_execution_through_rust_core/.test(bridgeModule) &&
      /admitProviderExecution/.test(modelMountAdmissionRunner) &&
      /rust_model_mount_provider_execution_command/.test(modelMountAdmissionRunner) &&
      /admitModelMountProviderExecution/.test(modelMountingState) &&
      /modelMountProviderExecutionRequestForInvocation/.test(modelInvocationOps) &&
      /model_mount_provider_execution_admission_required/.test(modelInvocationOps) &&
      /model_mount_provider_execution_ref/.test(modelInvocationOps) &&
      !/modelMountProviderExecution(?:SchemaVersion|Ref|Hash|Source|Backend|ReceiptRefs)?\s*:/.test(modelInvocationOps),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 9/10 is pending: provider execution must be admitted by Rust model_mount core before JS provider driver calls",
  );
  assertCheck(
    result,
    "model-mount-local-provider-invocation-live-bridge",
    /execute_model_mount_provider_invocation/.test(bridgeModule) &&
      /ModelMountProviderInvocationRequest/.test(bridgeModule) &&
      /bridge_executes_model_mount_provider_invocation_through_rust_core/.test(bridgeModule) &&
      /bridge_executes_native_local_model_mount_provider_invocation_through_rust_core/.test(bridgeModule) &&
      /executeProviderInvocation/.test(modelMountAdmissionRunner) &&
      /rust_model_mount_provider_invocation_command/.test(modelMountAdmissionRunner) &&
      /executeModelMountProviderInvocation/.test(modelMountingState) &&
      /modelMountProviderInvocationRequestForExecution/.test(modelInvocationOps) &&
      /modelMountProviderInvocationRequiresRust/.test(modelInvocationOps) &&
      /rust_model_mount_native_local/.test(modelInvocationOps) &&
      /model_mount_provider_invocation_execution_required/.test(modelInvocationOps),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 9/10 is pending: migrated local provider backends must execute through Rust model_mount instead of the JS provider driver",
  );
  assertCheck(
    result,
    "model-mount-native-local-stream-invocation-live-bridge",
    /execute_model_mount_provider_stream_invocation/.test(bridgeModule) &&
      /bridge_executes_native_local_model_mount_provider_stream_through_rust_core/.test(bridgeModule) &&
      /executeProviderStreamInvocation/.test(modelMountAdmissionRunner) &&
      /rust_model_mount_provider_stream_invocation_command/.test(modelMountAdmissionRunner) &&
      /executeModelMountProviderStreamInvocation/.test(modelMountingState) &&
      /modelMountProviderStreamInvocationRequestForExecution/.test(modelInvocationOps) &&
      /modelMountProviderStreamInvocationRequiresRust/.test(modelInvocationOps) &&
      /rust_model_mount_native_local_stream/.test(modelInvocationOps) &&
      /withTextChunksReadableStream/.test(modelInvocationOps) &&
      /model_mount_provider_stream_invocation_execution_required/.test(modelInvocationOps) &&
      /model_mount_local_provider_direct_stream_retired/.test(providerLocalDrivers) &&
      !exists("packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs") &&
      !exists("packages/runtime-daemon/src/model-mounting/native-local-fixture.test.mjs") &&
      retiredNativeFixtureResponseFiles.every((file) => !exists(file)) &&
      !/nativeLocalStreamRecords/.test(providerLocalDrivers) &&
      !/jsonLineReadableStream/.test(providerLocalDrivers) &&
      !/nativeLocalStreamRecords/.test(nativeLocalFixture) &&
      !/jsonLineReadableStream/.test(nativeLocalFixture) &&
      !/providerStreamFrameDelayMs/.test(nativeLocalFixture),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs",
      "packages/runtime-daemon/src/model-mounting/native-local-fixture.mjs",
      ...retiredNativeFixtureResponseFiles,
    ],
    "Phase 9/10 is pending: native-local stream frame planning must execute through Rust model_mount while JS only adapts returned chunks to protocol streams",
  );
  assertCheck(
    result,
    "model-mount-native-local-lifecycle-live-bridge",
    /plan_model_mount_provider_lifecycle/.test(bridgeModule) &&
      /ModelMountProviderLifecycleRequest/.test(bridgeModule) &&
      /bridge_plans_native_local_model_mount_provider_lifecycle_through_rust_core/.test(bridgeModule) &&
      /planProviderLifecycle/.test(modelMountAdmissionRunner) &&
      /rust_model_mount_provider_lifecycle_command/.test(modelMountAdmissionRunner) &&
      /RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND/.test(modelMountAdmissionRunner) &&
      /planModelMountProviderLifecycle/.test(modelMountingState) &&
      /nativeLocalLifecycleRequest/.test(providerLocalDrivers) &&
      /fixtureLifecycleRequest/.test(providerLocalDrivers) &&
      /RUST_MODEL_MOUNT_NATIVE_LOCAL_LIFECYCLE_BACKEND/.test(providerLocalDrivers) &&
      /RUST_MODEL_MOUNT_FIXTURE_LIFECYCLE_BACKEND/.test(providerLocalDrivers) &&
      /state\.planModelMountProviderLifecycle/.test(providerLocalDrivers) &&
      /provider_status/.test(providerLocalDrivers) &&
      /model_mount_provider_lifecycle/.test(providerLocalDrivers) &&
      /lifecycle_hash/.test(providerLocalDrivers) &&
      !/modelMountProviderLifecycle/.test(providerLocalDrivers) &&
      /model_mount_provider_lifecycle_planning_required/.test(providerLocalDrivers) &&
      /model_mount_fixture_provider_lifecycle_planning_required/.test(providerLocalDrivers) &&
      /plans health through Rust model_mount/.test(read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs")) &&
      /fixture provider driver plans health and lifecycle through Rust model_mount/.test(read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs")) &&
      /rust_model_mount_provider_lifecycle/.test(read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs")),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 9/10 is pending: native-local health/load/unload lifecycle envelopes must be planned by Rust model_mount while JS only supervises process state",
  );
  assertCheck(
    result,
    "model-mount-local-provider-inventory-live-bridge",
    /plan_model_mount_provider_inventory/.test(bridgeModule) &&
      /ModelMountProviderInventoryRequest/.test(bridgeModule) &&
      /bridge_plans_local_model_mount_provider_inventory_through_rust_core/.test(bridgeModule) &&
      /planProviderInventory/.test(modelMountAdmissionRunner) &&
      /rust_model_mount_provider_inventory_command/.test(modelMountAdmissionRunner) &&
      /RUST_MODEL_MOUNT_FIXTURE_INVENTORY_BACKEND/.test(modelMountAdmissionRunner) &&
      /planModelMountProviderInventory/.test(modelMountingState) &&
      /nativeLocalInventoryRequest/.test(providerLocalDrivers) &&
      /fixtureInventoryRequest/.test(providerLocalDrivers) &&
      /RUST_MODEL_MOUNT_NATIVE_LOCAL_INVENTORY_BACKEND/.test(providerLocalDrivers) &&
      /RUST_MODEL_MOUNT_FIXTURE_INVENTORY_BACKEND/.test(providerLocalDrivers) &&
      /state\??\.planModelMountProviderInventory/.test(providerLocalDrivers) &&
      /model_mount_provider_inventory/.test(providerLocalDrivers) &&
      /inventory_hash/.test(providerLocalDrivers) &&
      !/modelMountProviderInventory/.test(providerLocalDrivers) &&
      !/\binventoryHash\b/.test(providerLocalDrivers) &&
      !/\binventoryEvidenceRefs\b/.test(providerLocalDrivers) &&
      !/\binventoryItemCount\b/.test(providerLocalDrivers) &&
      /model_mount_provider_inventory_planning_required/.test(providerLocalDrivers) &&
      /model_mount_fixture_provider_inventory_planning_required/.test(providerLocalDrivers) &&
      /plan model and loaded inventory through Rust model_mount/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs"),
      ) &&
      /rust_model_mount_provider_inventory/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs"),
      ),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 9/10 is pending: local provider model/list-loaded inventory envelopes must be planned and hash-bound by Rust model_mount while JS still reads daemon state records",
  );
  assertCheck(
    result,
    "model-mount-instance-lifecycle-live-bridge",
    /plan_model_mount_instance_lifecycle/.test(bridgeModule) &&
      /ModelMountInstanceLifecycleRequest/.test(bridgeModule) &&
      /bridge_plans_model_mount_instance_lifecycle_through_rust_core/.test(bridgeModule) &&
      /planInstanceLifecycle/.test(modelMountAdmissionRunner) &&
      /rust_model_mount_instance_lifecycle_command/.test(modelMountAdmissionRunner) &&
      /RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND/.test(modelMountAdmissionRunner) &&
      /provider_lifecycle_hash/.test(modelMountAdmissionRunner) &&
      !/providerLifecycleHash/.test(modelMountAdmissionRunner) &&
      /provider_lifecycle_hash/.test(bridgeModule) &&
      /response\.get\("providerLifecycleHash"\)\.is_none/.test(bridgeModule) &&
      /planModelMountInstanceLifecycle/.test(modelMountingState) &&
      /planModelMountInstanceLifecycleForMigratedProvider/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /state\.planModelMountInstanceLifecycle/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /model_mount_instance_lifecycle_planning_required/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /model_mount_instance_lifecycle_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /model_mount_instance_lifecycle_action/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /model_mount_provider_lifecycle_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      !/providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      !/modelMountInstanceLifecycle(?:Action|Status|Hash|EvidenceRefs)/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /model_mount_provider_lifecycle_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/loaded-instances.mjs"),
      ) &&
      !/providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/loaded-instances.mjs"),
      ) &&
      !/modelMountInstanceLifecycle(?:Action|Status|Hash|EvidenceRefs)/.test(
        read("packages/runtime-daemon/src/model-mounting/loaded-instances.mjs"),
      ) &&
      /model_mount_provider_lifecycle_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs"),
      ) &&
      !/providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs"),
      ) &&
      !/modelMountInstanceLifecycle(?:Action|Status|Hash|EvidenceRefs)/.test(
        read("packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs"),
      ) &&
      /action: "evict"/.test(read("packages/runtime-daemon/src/model-mounting/loaded-instances.mjs")) &&
      /action: "supersede"/.test(read("packages/runtime-daemon/src/model-mounting/loaded-instances.mjs")) &&
      /idle TTL eviction plans Rust lifecycle/.test(
        read("packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs"),
      ) &&
      /explicit supersede plans Rust lifecycle/.test(
        read("packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs"),
      ) &&
      /fails closed for migrated local provider without Rust instance lifecycle plan/.test(
        read("packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs"),
      ),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs",
      "packages/runtime-daemon/src/model-mounting/loaded-instances.mjs",
      "packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 9/10 is pending: migrated local provider model load/unload/evict/supersede instance transitions must be planned and hash-bound by Rust model_mount before JS writes model-instance state",
  );
  assertCheck(
    result,
    "model-mount-local-provider-direct-invoke-retired",
    /model_mount_local_provider_direct_invoke_retired/.test(providerLocalDrivers) &&
      !/deterministicOutput/.test(providerLocalDrivers) &&
      !/reason:\s*"model_invoke"/.test(providerLocalDrivers) &&
      !/event:\s*"invoke"/.test(providerLocalDrivers),
    [
      "packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-local-drivers.test.mjs",
    ],
    "Phase 9/10 is pending: migrated local provider non-stream execution must fail closed if called through JS provider drivers",
  );
  assertCheck(
    result,
    "model-mount-provider-result-admission-live-bridge",
    /admit_model_mount_provider_result/.test(bridgeModule) &&
      /ModelMountProviderResultAdmissionRequest/.test(bridgeModule) &&
      /bridge_admits_model_mount_provider_result_through_rust_core/.test(bridgeModule) &&
      /admitProviderResult/.test(modelMountAdmissionRunner) &&
      /rust_model_mount_provider_result_command/.test(modelMountAdmissionRunner) &&
      /admitModelMountProviderResult/.test(modelMountingState) &&
      /modelMountProviderResultAdmissionRequestForExecution/.test(modelInvocationOps) &&
      /model_mount_provider_result_admission_required/.test(modelInvocationOps) &&
      /js_provider_driver_observation/.test(modelInvocationOps) &&
      /model_mount_provider_result_admission_ref/.test(modelInvocationOps) &&
      !/modelMountProviderResultAdmission(?:SchemaVersion|Ref|Hash|Source|Backend|ReceiptRefs|EvidenceRefs)?\s*:/.test(modelInvocationOps),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 9/10 is pending: non-migrated provider driver results must be Rust-admitted before accepted model invocation receipts",
  );
  assertCheck(
    result,
    "model-mount-provider-responses-chat-fallback-retired",
    /\/responses/.test(openAiCompatibleDriver) &&
      !/allowResponsesFallback/.test(openAiCompatibleProviderDrivers) &&
      !/compatTranslation:\s*"chat_completions"/.test(openAiCompatibleProviderDrivers) &&
      !/kind:\s*"chat\.completions"[\s\S]*body:\s*responseBody/.test(openAiCompatibleDriver),
    [
      "packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-openai-compatible-driver.test.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-openai-backend-drivers.mjs",
    ],
    "Phase 9/10 is pending: responses provider calls must fail closed instead of downgrading to chat completions",
  );
  assertCheck(
    result,
    "model-mount-provider-compat-translation-receipt-retired",
    /model_mount_provider_compat_translation_forbidden/.test(modelInvocationOps) &&
      !/compatTranslation:\s*providerResult\.compatTranslation/.test(modelInvocationOps) &&
      !/compat_translation:\s*invocation\.compatTranslation/.test(openAiCompatRoutes) &&
      /rejects provider compatibility translations before result admission/.test(
        read("packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs"),
      ) &&
      /rejects provider compatibility translations before admission/.test(
        read("packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
      "packages/runtime-daemon/src/openai-compat-routes.mjs",
    ],
    "Phase 9/11 is pending: provider compatibility translation markers must fail closed instead of entering accepted receipts or native protocol responses",
  );
  assertCheck(
    result,
    "model-mount-protocol-response-facade-reexport-retired",
    /from "\.\/model-mounting\/protocol-responses\.mjs"/.test(openAiCompatRoutes) &&
      !/protocol-responses\.mjs/.test(modelMountingState) &&
      !/openAiChatCompletion as compatOpenAiChatCompletion/.test(
        read("packages/runtime-daemon/src/model-mounting/protocol-responses.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/openai-compat-routes.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
      "packages/runtime-daemon/src/model-mounting/protocol-responses.test.mjs",
    ],
    "Phase 11 is pending: protocol response helpers must live behind the stable protocol module, not the broad model-mounting compatibility facade",
  );
  assertCheck(
    result,
    "model-mount-legacy-model-list-facade-retired",
    !/legacyModelList/.test(
      [
        runtimeDaemonIndex,
        modelMountingState,
        modelMountingReadModel,
        modelMountingReadProjectionFacade,
      ].join("\n"),
    ) &&
      /runtimeModelCatalogList/.test(runtimeDaemonIndex) &&
      /runtimeModelCatalogList/.test(modelMountingState) &&
      /runtimeModelCatalogList/.test(modelMountingReadModel) &&
      /runtimeModelCatalogList/.test(modelMountingReadProjectionFacade) &&
      /runtimeModelCatalogList/.test(modelMountingReadModelTest) &&
      /runtimeModelCatalogList/.test(modelMountingReadProjectionFacadeTest),
    [
      "packages/runtime-daemon/src/index.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
      "packages/runtime-daemon/src/model-mounting/read-model.mjs",
      "packages/runtime-daemon/src/model-mounting/read-model.test.mjs",
      "packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs",
      "packages/runtime-daemon/src/model-mounting/read-projection-facade.test.mjs",
    ],
    "Phase 11 is pending: public model listing must use the runtime model catalog projection instead of a legacy model-list facade name",
  );
  assertCheck(
    result,
    "model-mount-stream-provider-result-admission-live-bridge",
    /startModelStream/.test(modelInvocationOps) &&
      /requireModelMountProviderResultAdmission/.test(modelInvocationOps) &&
      /modelMountProviderResultAdmissionRequestForExecution/.test(modelInvocationOps) &&
      /streamStatus: "started"/.test(modelInvocationOps) &&
      /model_mount_provider_result_admission_ref/.test(modelInvocationOps) &&
      /model_mount_provider_result_admission_required/.test(modelInvocationOps) &&
      !/model\.provider_stream_request_shape/.test(modelInvocationOps) &&
      !/model_provider_stream_request_shape/.test(modelInvocationOps),
    [
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
    ],
    "Phase 9/10 is pending: native stream-start provider observations must be Rust-admitted without a duplicate JS request-shape operation append",
  );
  assertCheck(
    result,
    "model-mount-native-stream-no-downgrade-live-bridge",
    /model_mount_native_stream_result_required/.test(modelInvocationOps) &&
      !/if \(!providerResult\?\.stream\) \{\s*return\s*\{[\s\S]*?state\.invokeModel\(\{ authorization, requiredScope, kind, body: \{ \.\.\.body, stream: false \} \}\)/.test(modelInvocationOps),
    [
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
    ],
    "Phase 9/10 is pending: admitted native stream starts must fail closed instead of downgrading to a second JS non-stream invocation",
  );
  assertCheck(
    result,
    "model-mount-native-stream-pre-admission-downgrade-retired",
    /model_mount_native_stream_backend_required/.test(modelInvocationOps) &&
      /model_mount_native_stream_capability_required/.test(modelInvocationOps) &&
      !/state\.invokeModel\(\{ authorization, requiredScope, kind, body: \{ \.\.\.body, stream: false \} \}\)/.test(modelInvocationOps),
    [
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
    ],
    "Phase 9/10 is pending: native stream requests must fail closed before Rust stream-start admission instead of downgrading to non-stream JS invocation",
  );
  assertCheck(
    result,
    "model-mount-invocation-receipt-binding-live-bridge",
    /bind_model_mount_invocation_receipt/.test(bridgeModule) &&
      /ModelMountInvocationReceiptBindingBridgeRequest/.test(bridgeModule) &&
      /bridge_binds_model_mount_invocation_receipt_through_rust_core/.test(bridgeModule) &&
      /ReceiptBinder/.test(bridgeModule) &&
      /AgentgresAdmissionCore/.test(bridgeModule) &&
      /AcceptedReceiptAppendIssuer::RustReceiptCore/.test(bridgeModule) &&
      /bindInvocationReceipt/.test(modelMountAdmissionRunner) &&
      /bindModelMountInvocationReceipt/.test(modelMountingState) &&
      /modelMountInvocationReceiptBindingRequestForReceipt/.test(modelInvocationOps) &&
      /model_mount_invocation_receipt_binding_required/.test(modelInvocationOps) &&
      /model_mount_agentgres_head_required/.test(modelInvocationOps) &&
      /model_mount_receipt_binding_ref/.test(modelInvocationOps) &&
      /model_mount_agentgres_admission/.test(modelInvocationOps) &&
      /model_mount_accepted_receipt_append_hash/.test(modelInvocationOps),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 4 is pending: model invocation receipts must be bound by Rust receipt_binder before JS persistence",
  );
  assertCheck(
    result,
    "worker-service-package-invocation-live-bridge",
    /admit_worker_service_package_invocation/.test(bridgeModule) &&
      /WorkerServicePackageInvocationBridgeRequest/.test(bridgeModule) &&
      /WorkerServicePackageInvocationCore/.test(bridgeModule) &&
      /rust_worker_service_package_invocation_command/.test(bridgeModule) &&
      /accepted_receipt_append/.test(bridgeModule) &&
      /bridge_admits_worker_service_package_invocation_through_rust_core/.test(bridgeModule),
    ["crates/node/src/bin/ioi_step_module_bridge/mod.rs"],
    "Phase 8 is pending: worker/service package invocation admission must be exposed through the daemon command bridge",
  );
  assertCheck(
    result,
    "worker-service-package-daemon-runner",
    /WORKER_SERVICE_PACKAGE_COMMAND_ENV/.test(workerServicePackageRunner) &&
      /IOI_WORKER_SERVICE_PACKAGE_COMMAND/.test(workerServicePackageRunner) &&
      /RustWorkerServicePackageRunner/.test(workerServicePackageRunner) &&
      /createWorkerServicePackageRunnerFromEnv/.test(workerServicePackageRunner) &&
      /createWorkerServicePackageRunnerFromEnv/.test(runtimeDaemonIndex) &&
      /this\.workerServicePackageRunner/.test(runtimeDaemonIndex) &&
      /admitInvocation/.test(workerServicePackageRunner) &&
      /admit_worker_service_package_invocation/.test(workerServicePackageRunner) &&
      /rust_package_invocation/.test(workerServicePackageRunner) &&
      /worker_service_package_bridge_unconfigured/.test(workerServicePackageRunner) &&
      /worker\/service package runner sends invocation admission bridge request/.test(
        workerServicePackageRunnerTest,
      ) &&
      /worker\/service package runner fails closed without command/.test(
        workerServicePackageRunnerTest,
      ) &&
      /worker\/service package runner surfaces Rust package rejection/.test(
        workerServicePackageRunnerTest,
      ) &&
      /runtime store mounts worker\/service package runner from options/.test(
        workerServicePackageStoreTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-worker-service-package-runner.mjs",
      "packages/runtime-daemon/src/runtime-worker-service-package-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-worker-service-package-store.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 8 is pending: daemon worker/service package facade must call the Rust package admission bridge and fail closed when unconfigured",
  );
  assertCheck(
    result,
    "worker-service-package-product-route",
    /createRuntimeWorkerServicePackageSurface/.test(runtimeDaemonIndex) &&
      /this\.workerServicePackageSurface/.test(runtimeDaemonIndex) &&
      /admitWorkerServicePackageInvocation/.test(runtimeDaemonIndex) &&
      /WORKER_SERVICE_PACKAGE_ADMISSION_RESPONSE_SCHEMA_VERSION/.test(workerServicePackageSurface) &&
      /invocation_admitted:\s*true/.test(workerServicePackageSurface) &&
      /store\.workerServicePackageRunner\.admitInvocation/.test(workerServicePackageSurface) &&
      /worker-service-package-invocations/.test(runtimeRouteHandlers) &&
      /store\.admitWorkerServicePackageInvocation/.test(runtimeRouteHandlers) &&
      /thread route admits worker\/service package invocations through store facade/.test(runtimeRouteHandlersTest) &&
      /thread route does not expose worker\/service package apply shortcut/.test(runtimeRouteHandlersTest) &&
      /worker\/service package surface admits nested invocation through Rust runner/.test(
        workerServicePackageSurfaceTest,
      ) &&
      /worker\/service package surface fails closed without invocation payload/.test(
        workerServicePackageSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs",
      "packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs",
      "packages/runtime-daemon/src/runtime-route-handlers.mjs",
      "packages/runtime-daemon/src/runtime-route-handlers.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 8 is pending: product/API worker-service package route must call Rust package admission and expose no JS apply shortcut",
  );
  assertCheck(
    result,
    "worker-service-package-admission-response-aliases-retired",
    !workerServicePackageAdmissionCamelAliasPropertyPattern.test(workerServicePackageSurface) &&
      !workerServicePackageAdmissionCamelAliasTypePattern.test(
        workerServicePackageAdmissionResultType,
      ) &&
      /worker\/service package surface exposes only canonical snake_case admission fields/.test(
        workerServicePackageSurfaceTest,
      ) &&
      /WORKER_SERVICE_PACKAGE_ADMISSION_CAMEL_ALIASES/.test(workerServicePackageSurfaceTest) &&
      /Object\.hasOwn\(result, key\)/.test(workerServicePackageSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs",
      "packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 8/11 is pending: worker/service package admission responses must not preserve camelCase compatibility aliases after the canonical route is verified",
  );
  assertCheck(
    result,
    "worker-service-package-sdk-ide-admission-surface",
    /admitWorkerServicePackageInvocation/.test(agentSdkSubstrateClient) &&
      /RuntimeWorkerServicePackageInvocationAdmissionInput/.test(agentSdkSubstrateClient) &&
      /worker-service-package-invocations/.test(agentSdkSubstrateClient) &&
      /SDK admits worker\/service package invocations through the thread route/.test(agentSdkTest) &&
      /WORKFLOW_RUNTIME_WORKER_SERVICE_PACKAGE_CONTROL_SCHEMA_VERSION/.test(
        workerServicePackageControlNodes,
      ) &&
      /createRuntimeWorkerServicePackageControlRequest/.test(workerServicePackageControlNodes) &&
      /RUNTIME_WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION/.test(
        workerServicePackageControlNodes,
      ) &&
      /worker-service-package-invocations/.test(workerServicePackageControlNodes) &&
      /admission_only:\s*true/.test(workerServicePackageControlNodes) &&
      /direct_truth_write_allowed:\s*false/.test(workerServicePackageControlNodes) &&
      !/\/apply/.test(workerServicePackageControlNodes) &&
      /builds worker\/service package controls for daemon admission/.test(
        workerServicePackageControlNodesTest,
      ) &&
      /worker\/service package controls fail closed without admission refs/.test(
        workerServicePackageControlNodesTest,
      ) &&
      /createRuntimeWorkerServicePackageControlRequest/.test(agentIdeIndex) &&
      /RuntimeWorkerServicePackageControlRequest/.test(graphRuntimeTypes),
    [
      "packages/agent-sdk/src/substrate-client.ts",
      "packages/agent-sdk/test/sdk.test.mjs",
      "packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.test.ts",
      "packages/agent-ide/src/runtime/graph-runtime-types.ts",
      "packages/agent-ide/src/index.ts",
    ],
    "Phase 8 is pending: SDK and IDE worker-service package clients must consume the package route without exposing a JS apply shortcut",
  );
  assertCheck(
    result,
    "worker-service-package-cli-admission-surface",
    /Runtime\(runtime::RuntimeArgs\)/.test(cliMain) &&
      /runtime::run\(args\)\.await/.test(cliMain) &&
      /WorkerServicePackageCommands::Admit/.test(cliRuntime) &&
      /worker_service_package_invocations_route/.test(cliRuntime) &&
      /worker-service-package-invocations/.test(cliRuntime) &&
      /"source":\s*"cli_client"/.test(cliRuntime) &&
      /"invocation":\s*invocation/.test(cliRuntime) &&
      /worker_service_package_route_encodes_thread_id/.test(cliRuntime) &&
      /worker_service_package_body_is_cli_admission_only/.test(cliRuntime) &&
      !/invocation_admitted:\s*true/.test(cliRuntime),
    [
      "crates/cli/src/main.rs",
      "crates/cli/src/commands/mod.rs",
      "crates/cli/src/commands/runtime.rs",
    ],
    "Phase 8/11 is pending: CLI worker/service package client must post invocations to the daemon route without minting accepted truth",
  );
  assertCheck(
    result,
    "l1-settlement-admission-live-bridge",
    /admit_l1_settlement_attempt/.test(bridgeModule) &&
      /L1SettlementAdmissionBridgeRequest/.test(bridgeModule) &&
      /L1SettlementTriggerGuard/.test(bridgeModule) &&
      /rust_l1_settlement_guard_command/.test(bridgeModule) &&
      /l1_settlement_guard/.test(bridgeModule) &&
      /l1_settlement_admission_invalid/.test(bridgeModule) &&
      /bridge_admits_l1_settlement_attempt_through_rust_core/.test(bridgeModule),
    ["crates/node/src/bin/ioi_step_module_bridge/mod.rs"],
    "Phase 8/11 is pending: L1 settlement attempts must be admitted through the Rust trigger guard before any product surface can settle",
  );
  assertCheck(
    result,
    "l1-settlement-daemon-runner",
    /L1_SETTLEMENT_COMMAND_ENV/.test(l1SettlementRunner) &&
      /IOI_L1_SETTLEMENT_COMMAND/.test(l1SettlementRunner) &&
      /RustL1SettlementRunner/.test(l1SettlementRunner) &&
      /createL1SettlementRunnerFromEnv/.test(l1SettlementRunner) &&
      /createL1SettlementRunnerFromEnv/.test(runtimeDaemonIndex) &&
      /this\.l1SettlementRunner/.test(runtimeDaemonIndex) &&
      /admitAttempt/.test(l1SettlementRunner) &&
      /admit_l1_settlement_attempt/.test(l1SettlementRunner) &&
      /l1_settlement_guard/.test(l1SettlementRunner) &&
      /l1_settlement_bridge_unconfigured/.test(l1SettlementRunner) &&
      /L1 settlement runner sends admission bridge request/.test(l1SettlementRunnerTest) &&
      /L1 settlement runner fails closed without command/.test(l1SettlementRunnerTest) &&
      /L1 settlement runner surfaces Rust settlement rejection/.test(l1SettlementRunnerTest) &&
      /runtime store mounts L1 settlement runner from options/.test(l1SettlementStoreTest),
    [
      "packages/runtime-daemon/src/runtime-l1-settlement-runner.mjs",
      "packages/runtime-daemon/src/runtime-l1-settlement-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-l1-settlement-store.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 8/11 is pending: daemon L1 settlement facade must call the Rust trigger guard bridge and fail closed when unconfigured",
  );
  assertCheck(
    result,
    "l1-settlement-product-route",
    /createRuntimeL1SettlementSurface/.test(runtimeDaemonIndex) &&
      /this\.l1SettlementSurface/.test(runtimeDaemonIndex) &&
      /admitL1SettlementAttempt/.test(runtimeDaemonIndex) &&
      /L1_SETTLEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION/.test(l1SettlementSurface) &&
      /settlement_admitted:\s*true/.test(l1SettlementSurface) &&
      /store\.l1SettlementRunner\.admitAttempt/.test(l1SettlementSurface) &&
      /l1-settlement-attempts/.test(runtimeRouteHandlers) &&
      /store\.admitL1SettlementAttempt/.test(runtimeRouteHandlers) &&
      /thread route admits L1 settlement attempts through store facade/.test(runtimeRouteHandlersTest) &&
      /thread route does not expose L1 settlement apply shortcut/.test(runtimeRouteHandlersTest) &&
      /L1 settlement surface admits nested attempt through Rust runner/.test(l1SettlementSurfaceTest) &&
      /L1 settlement surface fails closed without attempt payload/.test(l1SettlementSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs",
      "packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs",
      "packages/runtime-daemon/src/runtime-route-handlers.mjs",
      "packages/runtime-daemon/src/runtime-route-handlers.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 8/11 is pending: product/API L1 settlement route must call Rust trigger admission and expose no JS apply shortcut",
  );
  assertCheck(
    result,
    "l1-settlement-admission-response-aliases-retired",
    !l1SettlementAdmissionCamelAliasPropertyPattern.test(l1SettlementSurface) &&
      !l1SettlementAdmissionCamelAliasTypePattern.test(l1SettlementAdmissionResultType) &&
      /L1 settlement surface exposes only canonical snake_case admission fields/.test(
        l1SettlementSurfaceTest,
      ) &&
      /L1_SETTLEMENT_ADMISSION_CAMEL_ALIASES/.test(l1SettlementSurfaceTest) &&
      /Object\.hasOwn\(result, key\)/.test(l1SettlementSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs",
      "packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 8/11 is pending: L1 settlement admission responses must not preserve camelCase compatibility aliases after the canonical route is verified",
  );
  assertCheck(
    result,
    "l1-settlement-sdk-ide-admission-surface",
    /admitL1SettlementAttempt/.test(agentSdkSubstrateClient) &&
      /RuntimeL1SettlementAttemptAdmissionInput/.test(agentSdkSubstrateClient) &&
      /l1-settlement-attempts/.test(agentSdkSubstrateClient) &&
      /SDK admits L1 settlement attempts through the thread route/.test(agentSdkTest) &&
      /WORKFLOW_RUNTIME_L1_SETTLEMENT_CONTROL_SCHEMA_VERSION/.test(l1SettlementControlNodes) &&
      /createRuntimeL1SettlementControlRequest/.test(l1SettlementControlNodes) &&
      /RUNTIME_L1_SETTLEMENT_ATTEMPT_SCHEMA_VERSION/.test(l1SettlementControlNodes) &&
      /l1-settlement-attempts/.test(l1SettlementControlNodes) &&
      /admission_only:\s*true/.test(l1SettlementControlNodes) &&
      /direct_truth_write_allowed:\s*false/.test(l1SettlementControlNodes) &&
      /default_runtime_settlement_allowed:\s*false/.test(l1SettlementControlNodes) &&
      /settlement_trigger_checked_by_rust:\s*true/.test(l1SettlementControlNodes) &&
      !/\/apply/.test(l1SettlementControlNodes) &&
      /builds L1 settlement controls for daemon admission/.test(l1SettlementControlNodesTest) &&
      /L1 settlement controls fail closed without trigger refs/.test(l1SettlementControlNodesTest) &&
      /createRuntimeL1SettlementControlRequest/.test(agentIdeIndex) &&
      /RuntimeL1SettlementControlRequest/.test(graphRuntimeTypes),
    [
      "packages/agent-sdk/src/substrate-client.ts",
      "packages/agent-sdk/test/sdk.test.mjs",
      "packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.test.ts",
      "packages/agent-ide/src/runtime/graph-runtime-types.ts",
      "packages/agent-ide/src/index.ts",
    ],
    "Phase 8/11 is pending: SDK and IDE L1 settlement clients must consume the L1 route without exposing a JS apply shortcut",
  );
  assertCheck(
    result,
    "l1-settlement-cli-admission-surface",
    /Runtime\(runtime::RuntimeArgs\)/.test(cliMain) &&
      /runtime::run\(args\)\.await/.test(cliMain) &&
      /L1SettlementCommands::Admit/.test(cliRuntime) &&
      /l1_settlement_attempts_route/.test(cliRuntime) &&
      /l1-settlement-attempts/.test(cliRuntime) &&
      /"source":\s*"cli_client"/.test(cliRuntime) &&
      /"attempt":\s*attempt/.test(cliRuntime) &&
      /l1_settlement_route_encodes_thread_id/.test(cliRuntime) &&
      /l1_settlement_body_is_cli_admission_only/.test(cliRuntime) &&
      !/settlement_admitted:\s*true/.test(cliRuntime),
    [
      "crates/cli/src/main.rs",
      "crates/cli/src/commands/mod.rs",
      "crates/cli/src/commands/runtime.rs",
    ],
    "Phase 8/11 is pending: CLI L1 settlement client must post attempts to the daemon route without minting accepted truth",
  );
  assertCheck(
    result,
    "ctee-private-workspace-cli-admission-surface",
    /Runtime\(runtime::RuntimeArgs\)/.test(cliMain) &&
      /runtime::run\(args\)\.await/.test(cliMain) &&
      /CteePrivateWorkspaceCommands::Execute/.test(cliRuntime) &&
      /ctee_private_workspace_actions_route/.test(cliRuntime) &&
      /ctee-private-workspace-actions/.test(cliRuntime) &&
      /"source":\s*"cli_client"/.test(cliRuntime) &&
      /"action":\s*action/.test(cliRuntime) &&
      /ctee_private_workspace_route_encodes_thread_id/.test(cliRuntime) &&
      /ctee_private_workspace_body_is_cli_admission_only/.test(cliRuntime) &&
      !/action_executed:\s*true/.test(cliRuntime),
    [
      "crates/cli/src/main.rs",
      "crates/cli/src/commands/mod.rs",
      "crates/cli/src/commands/runtime.rs",
    ],
    "Phase 7/11 is pending: CLI cTEE Private Workspace client must post actions to the daemon route without minting accepted truth",
  );
  assertCheck(
    result,
    "governed-meta-improvement-proposal-live-bridge",
    /admit_governed_runtime_improvement_proposal/.test(bridgeModule) &&
      /GovernedRuntimeImprovementBridgeRequest/.test(bridgeModule) &&
      /GovernedRuntimeImprovementProposal/.test(bridgeModule) &&
      /GovernedEvolutionCore/.test(bridgeModule) &&
      /rust_governed_meta_improvement_command/.test(bridgeModule) &&
      /bridge_admits_governed_runtime_improvement_proposal_through_rust_core/.test(bridgeModule),
    ["crates/node/src/bin/ioi_step_module_bridge/mod.rs"],
    "Phase 9 is pending: governed meta-improvement proposal admission must be exposed through the daemon command bridge",
  );
  assertCheck(
    result,
    "governed-meta-improvement-daemon-runner",
    /GOVERNED_IMPROVEMENT_COMMAND_ENV/.test(governedImprovementRunner) &&
      /IOI_GOVERNED_IMPROVEMENT_COMMAND/.test(governedImprovementRunner) &&
      /RustGovernedImprovementRunner/.test(governedImprovementRunner) &&
      /createGovernedImprovementRunnerFromEnv/.test(governedImprovementRunner) &&
      /createGovernedImprovementRunnerFromEnv/.test(runtimeDaemonIndex) &&
      /this\.governedImprovementRunner/.test(runtimeDaemonIndex) &&
      /admitProposal/.test(governedImprovementRunner) &&
      /admit_governed_runtime_improvement_proposal/.test(governedImprovementRunner) &&
      /rust_governed_evolution/.test(governedImprovementRunner) &&
      /governed_improvement_bridge_unconfigured/.test(governedImprovementRunner) &&
      /governed improvement runner sends proposal admission bridge request/.test(governedImprovementRunnerTest) &&
      /governed improvement runner fails closed without command/.test(governedImprovementRunnerTest) &&
      /governed improvement runner surfaces Rust proposal rejection/.test(governedImprovementRunnerTest) &&
      /runtime store mounts governed improvement runner from options/.test(governedImprovementStoreTest),
    [
      "packages/runtime-daemon/src/runtime-governed-improvement-runner.mjs",
      "packages/runtime-daemon/src/runtime-governed-improvement-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-governed-improvement-store.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 9 is pending: daemon meta-improvement facade must call the Rust governed proposal bridge and fail closed when unconfigured",
  );
  assertCheck(
    result,
    "governed-meta-improvement-product-route",
    /createRuntimeGovernedImprovementSurface/.test(runtimeDaemonIndex) &&
      /this\.governedImprovementSurface/.test(runtimeDaemonIndex) &&
      /admitGovernedImprovementProposal/.test(runtimeDaemonIndex) &&
      /GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION/.test(governedImprovementSurface) &&
      /mutation_executed:\s*false/.test(governedImprovementSurface) &&
      /store\.governedImprovementRunner\.admitProposal/.test(governedImprovementSurface) &&
      /governed-improvement-proposals/.test(runtimeRouteHandlers) &&
      /store\.admitGovernedImprovementProposal/.test(runtimeRouteHandlers) &&
      /thread route admits governed improvement proposals through store facade/.test(runtimeRouteHandlersTest) &&
      /thread route does not expose governed improvement apply shortcut/.test(runtimeRouteHandlersTest) &&
      /governed improvement surface admits nested proposal through Rust runner/.test(governedImprovementSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-governed-improvement-surface.mjs",
      "packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs",
      "packages/runtime-daemon/src/runtime-route-handlers.mjs",
      "packages/runtime-daemon/src/runtime-route-handlers.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 9 is pending: product/API governed-improvement route must call Rust proposal admission and expose no JS apply shortcut",
  );
  assertCheck(
    result,
    "governed-meta-improvement-admission-response-aliases-retired",
    !governedImprovementAdmissionCamelAliasPropertyPattern.test(governedImprovementSurface) &&
      !governedImprovementAdmissionCamelAliasTypePattern.test(
        governedImprovementAdmissionResultType,
      ) &&
      /governed improvement surface exposes only canonical snake_case admission fields/.test(
        governedImprovementSurfaceTest,
      ) &&
      /GOVERNED_IMPROVEMENT_ADMISSION_CAMEL_ALIASES/.test(
        governedImprovementSurfaceTest,
      ) &&
      /Object\.hasOwn\(result, key\)/.test(governedImprovementSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-governed-improvement-surface.mjs",
      "packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 9/11 is pending: governed-improvement admission responses must not preserve camelCase compatibility aliases after the canonical route is verified",
  );
  assertCheck(
    result,
    "governed-meta-improvement-sdk-ide-review-surface",
    /admitGovernedImprovementProposal/.test(agentSdkSubstrateClient) &&
      /RuntimeGovernedImprovementProposalAdmissionInput/.test(agentSdkSubstrateClient) &&
      /governed-improvement-proposals/.test(agentSdkSubstrateClient) &&
      /SDK admits governed improvement proposals through the thread route/.test(agentSdkTest) &&
      /WORKFLOW_RUNTIME_GOVERNED_IMPROVEMENT_CONTROL_SCHEMA_VERSION/.test(
        governedImprovementControlNodes,
      ) &&
      /createRuntimeGovernedImprovementControlRequest/.test(governedImprovementControlNodes) &&
      /RUNTIME_GOVERNED_IMPROVEMENT_PROPOSAL_SCHEMA_VERSION/.test(
        governedImprovementControlNodes,
      ) &&
      /governed-improvement-proposals/.test(governedImprovementControlNodes) &&
      /mutation_executed:\s*false/.test(governedImprovementControlNodes) &&
      !/\/apply/.test(governedImprovementControlNodes) &&
      /builds governed improvement proposal controls for daemon admission/.test(
        governedImprovementControlNodesTest,
      ) &&
      /governed improvement controls fail closed without admission refs/.test(
        governedImprovementControlNodesTest,
      ) &&
      /createRuntimeGovernedImprovementControlRequest/.test(agentIdeIndex) &&
      /RuntimeGovernedImprovementControlRequest/.test(graphRuntimeTypes),
    [
      "packages/agent-sdk/src/substrate-client.ts",
      "packages/agent-sdk/test/sdk.test.mjs",
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.test.ts",
      "packages/agent-ide/src/runtime/graph-runtime-types.ts",
      "packages/agent-ide/src/index.ts",
    ],
    "Phase 9 is pending: SDK and IDE review clients must consume the governed-improvement proposal route without exposing a JS apply shortcut",
  );
  assertCheck(
    result,
    "governed-meta-improvement-cli-admission-surface",
    /Runtime\(runtime::RuntimeArgs\)/.test(cliMain) &&
      /runtime::run\(args\)\.await/.test(cliMain) &&
      /GovernedImprovementCommands::Admit/.test(cliRuntime) &&
      /governed_improvement_proposals_route/.test(cliRuntime) &&
      /governed-improvement-proposals/.test(cliRuntime) &&
      /"source":\s*"cli_client"/.test(cliRuntime) &&
      /"proposal":\s*proposal/.test(cliRuntime) &&
      /governed_improvement_route_encodes_thread_id/.test(cliRuntime) &&
      /governed_improvement_body_is_cli_admission_only/.test(cliRuntime) &&
      !/proposal_admitted:\s*true/.test(cliRuntime) &&
      !/mutation_executed:\s*true/.test(cliRuntime),
    [
      "crates/cli/src/main.rs",
      "crates/cli/src/commands/mod.rs",
      "crates/cli/src/commands/runtime.rs",
    ],
    "Phase 9/11 is pending: CLI governed-improvement client must post proposals to the daemon route without minting accepted truth or applying mutations",
  );
  return result;
}

function runReceipts() {
  const result = createTierResult("receipts");
  const bridgeModule = exists("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    ? read("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    : "";
  const modelInvocationOps = exists("packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs")
    : "";
  const conversationOps = exists("packages/runtime-daemon/src/model-mounting/conversation-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/conversation-operations.mjs")
    : "";
  const providerProtocol = exists("packages/runtime-daemon/src/model-mounting/provider-protocol.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-protocol.mjs")
    : "";
  const providerTransport = exists("packages/runtime-daemon/src/model-mounting/provider-transport.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-transport.mjs")
    : "";
  const walletAuthority = exists("packages/runtime-daemon/src/model-mounting/wallet-authority.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/wallet-authority.mjs")
    : "";
  const vaultPort = exists("packages/runtime-daemon/src/model-mounting/vault-port.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/vault-port.mjs")
    : "";
  const modelMountStore = exists("packages/runtime-daemon/src/model-mounting/store.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/store.mjs")
    : "";
  const modelMountIo = exists("packages/runtime-daemon/src/model-mounting/io.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/io.mjs")
    : "";
  const modelMountReceiptOperations = exists("packages/runtime-daemon/src/model-mounting/receipt-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/receipt-operations.mjs")
    : "";
  const openAiCompatRoutes = exists("packages/runtime-daemon/src/openai-compat-routes.mjs")
    ? read("packages/runtime-daemon/src/openai-compat-routes.mjs")
    : "";
  const memoryStore = exists("packages/runtime-daemon/src/memory-store.mjs")
    ? read("packages/runtime-daemon/src/memory-store.mjs")
    : "";
  const runtimeBridgeThread = exists("packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs")
    ? read("packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs")
    : "";
  const threadStore = exists("packages/runtime-daemon/src/threads/thread-store.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-store.mjs")
    : "";
  const threadPersistence = exists("packages/runtime-daemon/src/threads/thread-persistence.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-persistence.mjs")
    : "";
  const runtimeDaemonIndex = exists("packages/runtime-daemon/src/index.mjs")
    ? read("packages/runtime-daemon/src/index.mjs")
    : "";
  const runtimeAgentgresRunner = exists("packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs")
    : "";
  const agentgresAdmissionCore = exists("crates/services/src/agentic/runtime/kernel/agentgres_admission.rs")
    ? read("crates/services/src/agentic/runtime/kernel/agentgres_admission.rs")
    : "";
  const marketplaceCore = exists("crates/services/src/agentic/runtime/kernel/marketplace.rs")
    ? read("crates/services/src/agentic/runtime/kernel/marketplace.rs")
    : "";
  const evolutionCore = exists("crates/services/src/agentic/evolution.rs")
    ? read("crates/services/src/agentic/evolution.rs")
    : "";
  const runtimeKernelModule = exists("crates/services/src/agentic/runtime/kernel/mod.rs")
    ? read("crates/services/src/agentic/runtime/kernel/mod.rs")
    : "";
  const runtimeRunReadSurface = exists("packages/runtime-daemon/src/runtime-run-read-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-run-read-surface.mjs")
    : "";
  const runtimeDoctorReport = exists("packages/runtime-daemon/src/runtime-doctor-report.mjs")
    ? read("packages/runtime-daemon/src/runtime-doctor-report.mjs")
    : "";
  const runtimeToolCatalog = exists("packages/runtime-daemon/src/runtime-tool-catalog.mjs")
    ? read("packages/runtime-daemon/src/runtime-tool-catalog.mjs")
    : "";
  const threadTurnProjection = exists("packages/runtime-daemon/src/threads/thread-turn-projection.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-turn-projection.mjs")
    : "";
  const runtimeRunStateSurfaces = [
    threadPersistence,
    runtimeDaemonIndex,
    runtimeRunReadSurface,
    runtimeDoctorReport,
    runtimeToolCatalog,
    threadTurnProjection,
  ].join("\n");
  const modelMountingConstructorArgs =
    runtimeDaemonIndex.match(/this\.modelMounting = new ModelMountingState\(\{[\s\S]*?\n    \}\);/)?.[0] ?? "";
  const writeAgentRecordBody =
    threadPersistence.match(/export function writeAgentRecord[\s\S]*?\n}\n/)?.[0] ?? "";
  const writeSubagentRecordBody =
    threadPersistence.match(/export function writeSubagentRecord[\s\S]*?\n}\n/)?.[0] ?? "";
  const writeRunRecordBody =
    threadPersistence.match(/export function writeRunRecord[\s\S]*$/)?.[0] ?? "";
  const modelMountReceiptWriteGuards = exists("packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs")
    : "";
  assertCheck(
    result,
    "receipt-binder-core",
    exists("crates/services/src/agentic/runtime/kernel/receipt_binder.rs") &&
      /STEP_MODULE_RECEIPT_BINDING_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/receipt_binder.rs"),
      ) &&
      /receipt_binding/.test(bridgeModule),
    [
      "crates/services/src/agentic/runtime/kernel/receipt_binder.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
    ],
    "Phase 4 is pending: one Rust receipt/state-root binder must own accepted result binding",
  );
  assertCheck(
    result,
    "model-mount-route-decision-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ModelMountCore/.test(read("crates/services/src/agentic/runtime/kernel/model_mount.rs")) &&
      /UnresolvedAutoModel/.test(read("crates/services/src/agentic/runtime/kernel/model_mount.rs")) &&
      /PrivateWorkspacePlaintextNotAllowed/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /admit_model_mount_route_decision/.test(read("crates/services/src/agentic/runtime/kernel/mod.rs")),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
    ],
    "Phase 9 is pending: Rust model_mount core must own resolved route decisions, receipts, and cTEE custody metadata",
  );
  assertCheck(
    result,
    "model-mount-invocation-admission-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ModelMountInvocationAdmissionRequest/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /MissingRouteReceiptRef/.test(read("crates/services/src/agentic/runtime/kernel/model_mount.rs")) &&
      /MissingInvocationReceiptRef/.test(read("crates/services/src/agentic/runtime/kernel/model_mount.rs")) &&
      /admit_model_mount_invocation/.test(read("crates/services/src/agentic/runtime/kernel/mod.rs")),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
    ],
    "Phase 4/9 is pending: Rust model_mount core must own invocation receipt admission and route-decision binding",
  );
  assertCheck(
    result,
    "model-mount-provider-execution-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ModelMountProviderExecutionRequest/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /MissingProviderExecutionRouteReceiptRef/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /admit_model_mount_provider_execution/.test(
        read("crates/services/src/agentic/runtime/kernel/mod.rs"),
      ) &&
      /model_mount_provider_execution_admission_required/.test(modelInvocationOps),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
    ],
    "Phase 9/10 is pending: Rust model_mount core must own provider execution admission before model provider driver calls",
  );
  assertCheck(
    result,
    "model-mount-local-provider-invocation-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ModelMountProviderInvocationRequest/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /MissingProviderExecutionAdmission/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /UnsupportedProviderInvocationBackend/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /StreamProviderInvocationUnsupported/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /rust_model_mount_native_local/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /deterministic_native_local_fixture/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /invoke_model_mount_provider/.test(
        read("crates/services/src/agentic/runtime/kernel/mod.rs"),
      ) &&
      /model_mount_provider_invocation_execution_required/.test(modelInvocationOps),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
    ],
    "Phase 9/10 is pending: Rust model_mount core must own migrated local provider invocation execution",
  );
  assertCheck(
    result,
    "model-mount-native-local-stream-invocation-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ModelMountProviderStreamInvocationResult/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /invoke_provider_stream/.test(read("crates/services/src/agentic/runtime/kernel/model_mount.rs")) &&
      /rust_model_mount_native_local_stream/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /native_local_stream_chunks/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /invoke_model_mount_provider_stream/.test(
        read("crates/services/src/agentic/runtime/kernel/mod.rs"),
      ) &&
      /model_mount_provider_stream_invocation_execution_required/.test(modelInvocationOps),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
    ],
    "Phase 9/10 is pending: Rust model_mount core must own native-local stream output text, chunk planning, evidence, and hash binding",
  );
  assertCheck(
    result,
    "model-mount-native-local-lifecycle-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ModelMountProviderLifecycleRequest/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /UnsupportedProviderLifecycleBackend/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /rust_model_mount_fixture_lifecycle/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /plan_provider_lifecycle/.test(read("crates/services/src/agentic/runtime/kernel/model_mount.rs")) &&
      /rust_model_mount_native_local_lifecycle/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /provider_lifecycle_evidence_refs/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /plan_model_mount_provider_lifecycle/.test(
        read("crates/services/src/agentic/runtime/kernel/mod.rs"),
      ),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
    ],
    "Phase 9/10 is pending: Rust model_mount core must own native-local health/load/unload lifecycle backend, evidence, and hash planning",
  );
  assertCheck(
    result,
    "model-mount-local-provider-inventory-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ModelMountProviderInventoryRequest/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /UnsupportedProviderInventoryBackend/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /UnsupportedProviderInventoryAction/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /rust_model_mount_fixture_inventory/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /rust_model_mount_native_local_inventory/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /plan_provider_inventory/.test(read("crates/services/src/agentic/runtime/kernel/model_mount.rs")) &&
      /provider_inventory_evidence_refs/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /plan_model_mount_provider_inventory/.test(
        read("crates/services/src/agentic/runtime/kernel/mod.rs"),
      ),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
    ],
    "Phase 9/10 is pending: Rust model_mount core must own local provider model/list-loaded inventory backend, evidence, and hash planning",
  );
  assertCheck(
    result,
    "model-mount-instance-lifecycle-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ModelMountInstanceLifecycleRequest/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /UnsupportedInstanceLifecycleBackend/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /InstanceLifecycleStatusMismatch/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /"evict" if self\.target_status\.trim\(\) == "evicted"/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /"supersede" if self\.target_status\.trim\(\) == "superseded"/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /model_instance_eviction_and_supersede_lifecycle_are_planned/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /plan_instance_lifecycle/.test(read("crates/services/src/agentic/runtime/kernel/model_mount.rs")) &&
      /rust_model_mount_instance_lifecycle/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /instance_lifecycle_evidence_refs/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /plan_model_mount_instance_lifecycle/.test(
        read("crates/services/src/agentic/runtime/kernel/mod.rs"),
      ),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
    ],
    "Phase 9/10 is pending: Rust model_mount core must own migrated local provider model-instance load/unload/evict/supersede transition backend, evidence, provider lifecycle hash binding, and transition hash planning",
  );
  assertCheck(
    result,
    "model-mount-instance-map-direct-write-guard",
    /assertModelInstanceMapRustBound/.test(
      read("packages/runtime-daemon/src/model-mounting/state-persistence.mjs"),
    ) &&
      /model_mount_instance_map_direct_write_forbidden/.test(
        read("packages/runtime-daemon/src/model-mounting/state-persistence.mjs"),
      ) &&
      /RUST_MODEL_MOUNT_INSTANCE_LIFECYCLE_BACKEND/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /model_mount_instance_lifecycle_action/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /model_mount_instance_lifecycle_status/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /model_mount_provider_lifecycle_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      !/providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/state-persistence.mjs"),
      ) &&
      !/modelMountInstanceLifecycle(?:Action|Status|Hash|EvidenceRefs)/.test(
        read("packages/runtime-daemon/src/model-mounting/state-persistence.mjs"),
      ) &&
      /model_mount_provider_lifecycle_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs"),
      ) &&
      /model instance map writes require Rust lifecycle binding/.test(
        read("packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs"),
      ) &&
      /reject lifecycle action\/status drift/.test(
        read("packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs",
      "packages/runtime-daemon/src/model-mounting/state-persistence.mjs",
      "packages/runtime-daemon/src/model-mounting/state-persistence.test.mjs",
    ],
    "Phase 9/10 is pending: direct JS model-instance map persistence for migrated local providers must fail closed without Rust model_mount instance lifecycle binding",
  );
  assertCheck(
    result,
    "model-mount-instance-lifecycle-receipt-direct-write-guard",
    /assertModelInstanceLifecycleReceiptRustBound/.test(
      read("packages/runtime-daemon/src/model-mounting/receipt-operations.mjs"),
    ) &&
      /model_mount_instance_lifecycle_receipt_direct_write_forbidden/.test(
        read("packages/runtime-daemon/src/model-mounting/receipt-operations.mjs"),
      ) &&
      /model_supersede/.test(read("packages/runtime-daemon/src/model-mounting/receipt-operations.mjs")) &&
      /assertModelMountingReceiptWriteBound/.test(modelMountStore) &&
      /assertModelInstanceLifecycleReceiptBound/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /model_mount_instance_lifecycle_receipt_direct_append_forbidden/.test(
        modelMountReceiptWriteGuards,
      ) &&
      !/modelMountInstanceLifecycle(?:Action|Status|Hash|EvidenceRefs)/.test(
        read("packages/runtime-daemon/src/model-mounting/receipt-operations.mjs"),
      ) &&
      !/providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/receipt-operations.mjs"),
      ) &&
      !/modelMountInstanceLifecycle(?:Action|Status|Hash|EvidenceRefs)/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /model_mount_provider_lifecycle_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs"),
      ) &&
      /providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs"),
      ) &&
      /providerKind/.test(read("packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs")) &&
      /providerKind/.test(read("packages/runtime-daemon/src/model-mounting/loaded-instances.mjs")) &&
      /model instance lifecycle receipts require Rust binding/.test(
        read("packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs"),
      ) &&
      /model lifecycle receipt writes fail closed without provider kind/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/store.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs",
      "packages/runtime-daemon/src/model-mounting/store.test.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/loaded-instances.mjs",
    ],
    "Phase 9/10 is pending: direct JS model-instance lifecycle receipt persistence for migrated local providers must fail closed without provider kind and Rust model_mount instance lifecycle binding",
  );
  assertCheck(
    result,
    "model-mount-provider-inventory-receipt-direct-write-guard",
    /model_mount_provider_inventory/.test(
      read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs"),
    ) &&
      /inventory_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs"),
      ) &&
      !/modelMountProviderInventory/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs"),
      ) &&
      !/\binventoryHash\b/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs"),
      ) &&
      /providerInventoryReceiptFields/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      /model_mount_provider_inventory_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      !/modelMountProviderInventory/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      !/\binventoryHash\b/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      /assertModelMountingReceiptWriteBound/.test(modelMountStore) &&
      /assertProviderInventoryReceiptBound/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /model_mount_provider_inventory_hash/.test(
        modelMountReceiptWriteGuards,
      ) &&
      !/modelMountProviderInventory/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /model_mount_provider_inventory_receipt_direct_append_forbidden/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /local provider model and loaded list receipts carry Rust inventory bindings/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs"),
      ) &&
      /modelMountProviderInventoryHash/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ) &&
      /provider inventory receipt writes fail closed without provider kind/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/store.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs",
      "packages/runtime-daemon/src/model-mounting/store.test.mjs",
    ],
    "Phase 9/10 is pending: direct JS provider inventory lifecycle receipt persistence for migrated local providers must fail closed without provider kind and Rust model_mount inventory binding",
  );
  assertCheck(
    result,
    "model-mount-provider-health-receipt-direct-write-guard",
    /model_mount_provider_lifecycle/.test(
      read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs"),
    ) &&
      /providerLifecycleReceiptFields/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      /assertModelMountingReceiptWriteBound/.test(modelMountStore) &&
      /assertProviderHealthReceiptBound/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /model_mount_provider_health_receipt_direct_append_forbidden/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /model_mount_provider_lifecycle_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      /model_mount_provider_lifecycle_hash/.test(modelMountReceiptWriteGuards) &&
      !/modelMountProviderLifecycle|providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      !/modelMountProviderLifecycle|providerLifecycleHash/.test(modelMountReceiptWriteGuards) &&
      /local provider health receipts carry Rust lifecycle bindings/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs"),
      ) &&
      /provider health receipt writes fail closed without provider kind/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/store.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs",
      "packages/runtime-daemon/src/model-mounting/store.test.mjs",
    ],
    "Phase 9/10 is pending: direct JS provider health receipt persistence for migrated local providers must fail closed without provider kind and Rust model_mount lifecycle binding",
  );
  assertCheck(
    result,
    "model-mount-provider-control-receipt-direct-write-guard",
      /model_mount_provider_control_lifecycle_planning_required/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      /assertModelMountingReceiptWriteBound/.test(modelMountStore) &&
      /assertProviderControlReceiptBound/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /model_mount_provider_control_receipt_direct_append_forbidden/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /model_mount_provider_lifecycle_hash/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      /model_mount_provider_lifecycle_hash/.test(modelMountReceiptWriteGuards) &&
      !/modelMountProviderLifecycle|providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      !/modelMountProviderLifecycle|providerLifecycleHash/.test(modelMountReceiptWriteGuards) &&
      /local provider start and stop fail closed without Rust lifecycle bindings/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs"),
      ) &&
      /provider control receipt writes fail closed without provider kind/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/provider-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/store.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs",
      "packages/runtime-daemon/src/model-mounting/store.test.mjs",
    ],
    "Phase 9/10 is pending: migrated local provider start/stop control must fail closed unless backed by Rust model_mount lifecycle binding",
  );
  assertCheck(
    result,
    "model-mount-provider-result-admission-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ModelMountProviderResultAdmissionRequest/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /ProviderResultOutputHashMismatch/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /UnsupportedProviderResultBackend/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /admit_model_mount_provider_result/.test(
        read("crates/services/src/agentic/runtime/kernel/mod.rs"),
      ) &&
      /model_mount_provider_result_admission_required/.test(modelInvocationOps),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
    ],
    "Phase 9/10 is pending: non-migrated provider results must be Rust-admitted observations bound to provider execution",
  );
  assertCheck(
    result,
    "model-mount-stream-provider-result-admission-core",
    exists("crates/services/src/agentic/runtime/kernel/model_mount.rs") &&
      /admits_stream_start_provider_result_observation_bound_to_execution/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ) &&
      /stream_status/.test(read("crates/services/src/agentic/runtime/kernel/model_mount.rs")) &&
      /ProviderExecutionRefMismatch/.test(
        read("crates/services/src/agentic/runtime/kernel/model_mount.rs"),
      ),
    [
      "crates/services/src/agentic/runtime/kernel/model_mount.rs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
    ],
    "Phase 9/10 is pending: stream-start provider result admission must bind to the same stream-status provider execution record",
  );
  assertCheck(
    result,
    "model-mount-stream-request-shape-append-retired",
    /modelMountProviderResultAdmissionRequestForExecution/.test(modelInvocationOps) &&
      /streamStatus: "started"/.test(modelInvocationOps) &&
      !/model\.provider_stream_request_shape/.test(modelInvocationOps) &&
      !/model_provider_stream_request_shape/.test(modelInvocationOps),
    ["packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs"],
    "Phase 4/9 is pending: stream request-shape evidence must not append a duplicate JS operation outside Rust provider admission",
  );
  assertCheck(
    result,
    "model-mount-stream-request-shape-trace-helper-retired",
    !/summarizeProviderRequestBodyForTrace/.test(providerProtocol),
    ["packages/runtime-daemon/src/model-mounting/provider-protocol.mjs"],
    "Phase 4/9 is pending: legacy stream request-shape trace helpers must not remain after Rust provider-result admission owns stream-start evidence",
  );
  assertCheck(
    result,
    "model-mount-provider-open-retry-append-retired",
    !/appendOperation\?\.\("model\.provider_open_retry"/.test(providerTransport) &&
      !/model\.provider_open_retry/.test(providerTransport) &&
      /provider transport retries without appending operation-like records/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-transport.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/provider-transport.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-transport.test.mjs",
    ],
    "Phase 5/11 is pending: provider transport retry traces must not append JS operation-like records outside Rust Agentgres admission",
  );
  assertCheck(
    result,
    "model-mount-wallet-authority-audit-append-retired",
    !/\bappendOperation\b/.test(walletAuthority) &&
      /wallet authority creates grants and records authorization use without local operation append/.test(
        read("packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/wallet-authority.mjs",
      "packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs",
    ],
    "Phase 7/11 is pending: wallet authority audit mirroring must not append JS operation-like records outside wallet.network and admitted receipt paths",
  );
  assertCheck(
    result,
    "model-mount-vault-audit-append-retired",
    !/\bappendOperation\b/.test(vaultPort) &&
      /vault port resolves environment aliases and keeps metadata public without local operation append/.test(
        read("packages/runtime-daemon/src/model-mounting/vault-port.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/vault-port.mjs",
      "packages/runtime-daemon/src/model-mounting/vault-port.test.mjs",
    ],
    "Phase 7/11 is pending: vault audit mirroring must not append JS operation-like records outside wallet.network and admitted receipt paths",
  );
  assertCheck(
    result,
    "model-mount-receipt-store-operation-append-retired",
    !/\bappendOperation\b/.test(modelMountStore) &&
      !/operationCount|operation-log\.jsonl/.test(modelMountIo) &&
      !/local_operation_log|agentgres_canonical_operation_log/.test(modelMountStore) &&
      !/agentgres_canonical_operation_log/.test(modelMountReceiptOperations) &&
      /local_receipt_projection_store/.test(modelMountStore) &&
      /agentgres_receipt_projection_boundary/.test(modelMountReceiptOperations) &&
      /model invocation receipt writes persist only after Rust receipt and Agentgres admission without operation append/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ) &&
      /const sequence = this\.listReceipts\(\)\.length/.test(read("packages/runtime-daemon/src/model-mounting.mjs")) &&
      /watermark: receipts\.length/.test(read("packages/runtime-daemon/src/model-mounting/projections.mjs")),
    [
      "packages/runtime-daemon/src/model-mounting/store.mjs",
      "packages/runtime-daemon/src/model-mounting/store.test.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
      "packages/runtime-daemon/src/model-mounting/projections.mjs",
    ],
    "Phase 5/11 is pending: receipt persistence must not append duplicate JS operation-log records after Rust binding and Agentgres admission",
  );
  assertCheck(
    result,
    "openai-provider-stream-shape-append-retired",
    !/appendOperation\?\.\(\s*"model\.provider_stream_shape_summary"/.test(openAiCompatRoutes) &&
      /providerStreamShapeSummary: finalizeOpenAiProviderStreamShape/.test(openAiCompatRoutes) &&
      /providerStreamShapeSummary/.test(conversationOps) &&
      /OpenAI provider stream shape is bound to the stream receipt without operation append/.test(
        read("packages/runtime-daemon/src/openai-compat-routes.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/openai-compat-routes.mjs",
      "packages/runtime-daemon/src/openai-compat-routes.test.mjs",
      "packages/runtime-daemon/src/model-mounting/conversation-operations.mjs",
    ],
    "Phase 5/11 is pending: provider stream-shape evidence must be bound into the stream-completion receipt instead of appended as duplicate JS operation-like truth",
  );
  assertCheck(
    result,
    "model-mount-state-append-operation-injection-retired",
    /new ModelMountingState/.test(modelMountingConstructorArgs) &&
      /modelMountAdmissionRunner: options\.modelMountAdmissionRunner/.test(modelMountingConstructorArgs) &&
      !/\bappendOperation\b/.test(modelMountingConstructorArgs),
    ["packages/runtime-daemon/src/index.mjs"],
    "Phase 5/11 is pending: the runtime store must not inject daemon-local appendOperation into the model-mounting state facade after receipt/Agentgres admission owns model-mounting truth",
  );
  assertCheck(
    result,
    "agent-memory-operation-append-retired",
    !/\bappendOperation\b/.test(memoryStore) &&
      /this\.memory = new AgentMemoryStore\(this\.stateDir\);/.test(runtimeDaemonIndex) &&
      /agent memory store writes records, edits, deletes, and policies without local operation append/.test(
        read("packages/runtime-daemon/src/memory-store.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/memory-store.mjs",
      "packages/runtime-daemon/src/memory-store.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 5/11 is pending: memory record and policy updates must not mirror daemon-local operation-log records outside admitted receipt/Agentgres paths",
  );
  assertCheck(
    result,
    "runtime-bridge-turn-operation-append-retired",
    !/turn\.runtime_bridge\.submit_(?:budget|error)/.test(runtimeBridgeThread) &&
      /assert\.equal\(store\.calls\.some\(\(call\) => call\.operation === "append_operation"\), false\)/.test(
        read("packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs",
      "packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs",
    ],
    "Phase 5/11 is pending: runtime bridge turn submit budget/error mirrors must not append duplicate daemon-local operation records outside run receipts/projections",
  );
  assertCheck(
    result,
    "thread-agent-delete-operation-append-retired",
    !/agent\.delete/.test(threadStore) &&
      /assert\.equal\(store\.calls\.some\(\(call\) => call\.operation === "append_operation"\), false\)/.test(
        read("packages/runtime-daemon/src/threads/thread-store.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/threads/thread-store.mjs",
      "packages/runtime-daemon/src/threads/thread-store.test.mjs",
    ],
    "Phase 5/11 is pending: agent deletion must not append a duplicate daemon-local operation record outside the guarded deletion state transition",
  );
  assertCheck(
    result,
    "thread-agent-subagent-operation-append-retired",
    /writeAgentRecord/.test(writeAgentRecordBody) &&
      /writeSubagentRecord/.test(writeSubagentRecordBody) &&
      !/\bappendOperation\b/.test(writeAgentRecordBody) &&
      !/\bappendOperation\b/.test(writeSubagentRecordBody) &&
      /thread persistence writes agent records without operation entries/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /thread persistence writes subagent records without operation entries/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/threads/thread-persistence.mjs",
      "packages/runtime-daemon/src/threads/thread-persistence.test.mjs",
    ],
    "Phase 5/11 is pending: agent and subagent persistence must not append duplicate daemon-local operation records outside their persisted state records",
  );
  assertCheck(
    result,
    "thread-run-operation-log-append-retired",
    !/appendOperationRecord|operationCountRecord|operation-log\.jsonl|agentgres_canonical_operation_log/.test(
      runtimeRunStateSurfaces,
    ) &&
      !/\bappendOperation\s*\(/.test(runtimeRunStateSurfaces) &&
      !/\boperationCount\s*\(/.test(runtimeRunStateSurfaces) &&
      /commitRunState\(store, run, operationKind\)/.test(threadPersistence) &&
      /thread persistence writes run projections without operation entries/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /agentgres_canonical_state_projection/.test(runtimeRunReadSurface) &&
      /runStateWatermark/.test(runtimeRunReadSurface) &&
      /agentgres_canonical_state_projection/.test(runtimeDoctorReport) &&
      /runStateWatermark/.test(runtimeDoctorReport),
    [
      "packages/runtime-daemon/src/threads/thread-persistence.mjs",
      "packages/runtime-daemon/src/threads/thread-persistence.test.mjs",
      "packages/runtime-daemon/src/runtime-run-read-surface.mjs",
      "packages/runtime-daemon/src/runtime-doctor-report.mjs",
      "packages/runtime-daemon/src/runtime-tool-catalog.mjs",
      "packages/runtime-daemon/src/threads/thread-turn-projection.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 5/11 is pending: run persistence and read surfaces must not append or expose duplicate daemon-local operation-log records outside Agentgres state projections and admitted receipts",
  );
  assertCheck(
    result,
    "thread-run-state-transition-rust-planned",
    /RUNTIME_STATE_TRANSITION_SCHEMA_VERSION/.test(agentgresAdmissionCore) &&
      /RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION/.test(agentgresAdmissionCore) &&
      /RuntimeStateTransitionRequest/.test(agentgresAdmissionCore) &&
      /RuntimeRunStateCommitRequest/.test(agentgresAdmissionCore) &&
      /RuntimeRunStateCommitRecord/.test(agentgresAdmissionCore) &&
      /plan_runtime_state_transition/.test(agentgresAdmissionCore) &&
      /commit_runtime_run_state/.test(agentgresAdmissionCore) &&
      /runtime_run_state_hash/.test(agentgresAdmissionCore) &&
      /runtime_task_state_hash/.test(agentgresAdmissionCore) &&
      /runtime_task_record_for_run/.test(agentgresAdmissionCore) &&
      /runtime_job_record_for_run/.test(agentgresAdmissionCore) &&
      /runtime_checklist_record_for_run/.test(agentgresAdmissionCore) &&
      /runtime_state_transition_requires_expected_heads_state_root_and_receipts/.test(agentgresAdmissionCore) &&
      /commits_runtime_run_state_with_rust_derived_transition_and_persistence/.test(agentgresAdmissionCore) &&
      /commits_runtime_run_state_from_previous_transition_head/.test(agentgresAdmissionCore) &&
      /commit_runtime_run_state/.test(bridgeModule) &&
      /rust_agentgres_runtime_run_state_commit_command/.test(bridgeModule) &&
      !/plan_runtime_run_state_transition/.test(bridgeModule) &&
      !/rust_runtime_agentgres_transition_command/.test(bridgeModule) &&
      /bridge_commits_runtime_run_state_through_rust_core/.test(bridgeModule) &&
      /RustRuntimeAgentgresAdmissionRunner/.test(runtimeAgentgresRunner) &&
      /commitRuntimeRunState/.test(runtimeAgentgresRunner) &&
      !/planRunStateTransition/.test(runtimeAgentgresRunner) &&
      !/persistRuntimeStateRecords/.test(runtimeAgentgresRunner) &&
      /runtime_agentgres_admission_bridge_unconfigured/.test(runtimeAgentgresRunner) &&
      !/RUNTIME_AGENTGRES_FALLBACK/.test(runtimeAgentgresRunner) &&
      /createRuntimeAgentgresAdmissionRunnerFromEnv/.test(runtimeDaemonIndex) &&
      /commitRuntimeRunState\(request\)/.test(runtimeDaemonIndex) &&
      !/currentRunStateTransition/.test(runtimeDaemonIndex) &&
      !/planRunStateTransition\(request\)/.test(runtimeDaemonIndex) &&
      !/persistRuntimeStateRecords\(request\)/.test(runtimeDaemonIndex) &&
      /commitRunState\(store, run, operationKind\)/.test(threadPersistence) &&
      !/runStateProjectionWatermark/.test(threadPersistence) &&
      !/initialRunStateHead/.test(threadPersistence) &&
      !/initialRunStateRoot/.test(threadPersistence) &&
      !/planRunStateTransition/.test(threadPersistence) &&
      !/persistRunStateRecords/.test(threadPersistence) &&
      !/run,\s+projection_ref/s.test(threadPersistence) &&
      !/run_state_hash:\s*runStateHash/.test(threadPersistence) &&
      !/task_state_hash:\s*runStateHash/.test(threadPersistence) &&
      /normalizeRunStateCommit/.test(threadPersistence) &&
      /Object\.hasOwn\(store\.commitRequests\[0\], "expected_heads"\), false/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /Object\.hasOwn\(store\.commitRequests\[0\], "receipt_refs"\), false/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /thread persistence leaves previous run-state transition lookup to Rust commit/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /runtime Agentgres runner sends runtime run-state commit bridge request/.test(
        read("packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs"),
      ) &&
      /runtime Agentgres runner requires explicit runtime admission command env/.test(
        read("packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs"),
      ),
    [
      "crates/services/src/agentic/runtime/kernel/agentgres_admission.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs",
      "packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs",
      "packages/runtime-daemon/src/threads/thread-persistence.mjs",
      "packages/runtime-daemon/src/threads/thread-persistence.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 5/11 is pending: run persistence must require a single Rust Agentgres run-state commit that derives expected heads, state roots, resulting head, projection watermark, refs, and durable writes before JS observes committed state",
  );
  assertCheck(
    result,
    "thread-run-state-storage-write-rust-admitted",
    /StorageBackendWriteProposal/.test(agentgresAdmissionCore) &&
      /RuntimeStateRecordMaterializationRequest/.test(agentgresAdmissionCore) &&
      /materialize_runtime_state_records/.test(agentgresAdmissionCore) &&
      /runtime_task_record_for_run/.test(agentgresAdmissionCore) &&
      /runtime_job_record_for_run/.test(agentgresAdmissionCore) &&
      /runtime_checklist_record_for_run/.test(agentgresAdmissionCore) &&
      /RuntimeStateStorageWriteSetRequest/.test(agentgresAdmissionCore) &&
      /plan_runtime_state_storage_writes/.test(agentgresAdmissionCore) &&
      /RuntimeStatePersistenceRequest/.test(agentgresAdmissionCore) &&
      /RuntimeStatePersistenceRecord/.test(agentgresAdmissionCore) &&
      /plan_runtime_state_persistence/.test(agentgresAdmissionCore) &&
      /RuntimeStateRecordMaterializationRequest/.test(runtimeKernelModule) &&
      /RuntimeStateRecordMaterializationRecord/.test(runtimeKernelModule) &&
      /pub fn materialize_runtime_state_records/.test(runtimeKernelModule) &&
      /RuntimeStateStorageWriteSetRequest/.test(runtimeKernelModule) &&
      /RuntimeStateStorageWriteSetRecord/.test(runtimeKernelModule) &&
      /pub fn plan_runtime_state_storage_writes/.test(runtimeKernelModule) &&
      /RuntimeStatePersistenceRequest/.test(runtimeKernelModule) &&
      /RuntimeStatePersistenceRecord/.test(runtimeKernelModule) &&
      /pub fn plan_runtime_state_persistence/.test(runtimeKernelModule) &&
      /materializes_runtime_state_records_in_rust/.test(agentgresAdmissionCore) &&
      /plans_runtime_state_storage_write_set_with_rust_content_hash_and_admissions/.test(agentgresAdmissionCore) &&
      /plans_runtime_state_persistence_with_materialization_and_storage_write_set/.test(agentgresAdmissionCore) &&
      /admit_storage_backend_write/.test(bridgeModule) &&
      /commit_runtime_run_state/.test(bridgeModule) &&
      !/materialize_runtime_state_records/.test(bridgeModule) &&
      !/plan_runtime_state_storage_writes/.test(bridgeModule) &&
      !/persist_runtime_state_records/.test(bridgeModule) &&
      !/plan_runtime_run_state_transition/.test(bridgeModule) &&
      /rust_agentgres_storage_write_admission_command/.test(bridgeModule) &&
      /rust_agentgres_runtime_run_state_commit_command/.test(bridgeModule) &&
      !/rust_agentgres_runtime_state_record_materialization_command/.test(bridgeModule) &&
      !/rust_agentgres_runtime_state_storage_write_set_command/.test(bridgeModule) &&
      !/rust_agentgres_runtime_state_persistence_command/.test(bridgeModule) &&
      !/rust_runtime_agentgres_transition_command/.test(bridgeModule) &&
      /bridge_admits_storage_backend_write_through_rust_core/.test(bridgeModule) &&
      /bridge_commits_runtime_run_state_through_rust_core/.test(bridgeModule) &&
      !/bridge_materializes_runtime_state_records_through_rust_core/.test(bridgeModule) &&
      !/bridge_plans_runtime_state_storage_writes_through_rust_core/.test(bridgeModule) &&
      !/bridge_persists_runtime_state_records_through_rust_core/.test(bridgeModule) &&
      !/bridge_plans_runtime_run_state_transition_through_rust_core/.test(bridgeModule) &&
      /admitStorageBackendWrite/.test(runtimeAgentgresRunner) &&
      /commitRuntimeRunState/.test(runtimeAgentgresRunner) &&
      !/persistRuntimeStateRecords/.test(runtimeAgentgresRunner) &&
      !/materializeRuntimeStateRecords/.test(runtimeAgentgresRunner) &&
      !/planRuntimeStateStorageWrites/.test(runtimeAgentgresRunner) &&
      !/normalizeRuntimeStateRecordMaterializationBridgeResult/.test(runtimeAgentgresRunner) &&
      !/normalizeRuntimeStateStorageWriteSetBridgeResult/.test(runtimeAgentgresRunner) &&
      /RUST_AGENTGRES_STORAGE_BACKEND/.test(runtimeAgentgresRunner) &&
      /runtime Agentgres runner sends storage write admission bridge request/.test(
        read("packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs"),
      ) &&
      !/runtime Agentgres runner sends runtime-state record materialization bridge request/.test(
        read("packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs"),
      ) &&
      !/runtime Agentgres runner sends runtime-state storage write-set bridge request/.test(
        read("packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs"),
      ) &&
      /runtime Agentgres runner sends runtime run-state commit bridge request/.test(
        read("packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs"),
      ) &&
      /commitRuntimeRunState\(request\)/.test(runtimeDaemonIndex) &&
      !/persistRuntimeStateRecords\(request\)/.test(runtimeDaemonIndex) &&
      !/materializeRuntimeStateRecords\(request\)/.test(runtimeDaemonIndex) &&
      !/planRuntimeStateStorageWrites\(request\)/.test(runtimeDaemonIndex) &&
      !/admitRuntimeStateStorageWrite/.test(runtimeDaemonIndex) &&
      /commitRunState/.test(threadPersistence) &&
      !/persistRunStateRecords/.test(threadPersistence) &&
      !/materializeRunStateRecords/.test(threadPersistence) &&
      !/planRunStateStorageWrites/.test(threadPersistence) &&
      !/writeJsonWithPlannedStorage/.test(threadPersistence) &&
      !/runtime_task:/.test(threadPersistence) &&
      !/runtime_job:/.test(threadPersistence) &&
      !/runtime_checklist:/.test(threadPersistence) &&
      /RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION/.test(threadPersistence) &&
      !/RUNTIME_STATE_PERSISTENCE_SCHEMA_VERSION/.test(threadPersistence) &&
      !/RUNTIME_STATE_RECORD_MATERIALIZATION_SCHEMA_VERSION/.test(threadPersistence) &&
      !/RUNTIME_STATE_STORAGE_WRITE_SET_SCHEMA_VERSION/.test(threadPersistence) &&
      /RUNTIME_STATE_STORAGE_BACKEND_REF/.test(threadPersistence) &&
      /commitRequests/.test(read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs")) &&
      /persistenceRequests/.test(read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs")) &&
      /Object\.hasOwn\(store\.persistenceRequests\[0\], "runtime_task"\), false/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /store\.materializationRequests\.length, 0/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /store\.storageWriteSetRequests\.length, 0/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /store\.writes, \[\]/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /persists records in Rust/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ),
    [
      "crates/services/src/agentic/runtime/kernel/agentgres_admission.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-agentgres-admission-runner.mjs",
      "packages/runtime-daemon/src/runtime-agentgres-admission-runner.test.mjs",
      "packages/runtime-daemon/src/threads/thread-persistence.mjs",
      "packages/runtime-daemon/src/threads/thread-persistence.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 5/11 is pending: run-state writes must be materialized, storage-admitted, and persisted by the Rust Agentgres command path with Rust content hashes, Agentgres PayloadRefs, and receipt refs before any durable file mutation",
  );
  assertCheck(
    result,
    "thread-run-state-sidecar-storage-write-rust-admitted",
    /writeRunRecord/.test(writeRunRecordBody) &&
      !/\bwriteJson\(store\.pathFor/.test(writeRunRecordBody) &&
      /commitRunState\(store, run/.test(writeRunRecordBody) &&
      !/persistRunStateRecords\(store, run/.test(writeRunRecordBody) &&
      !/materializeRunStateRecords\(store, run/.test(writeRunRecordBody) &&
      !/planRunStateStorageWrites\(store, run/.test(writeRunRecordBody) &&
      !/writeJsonWithPlannedStorage/.test(writeRunRecordBody) &&
      !/runtimeTaskRecordForRun/.test(writeRunRecordBody) &&
      !/runtimeJobRecordForRun/.test(writeRunRecordBody) &&
      !/runtimeChecklistRecordForRun/.test(writeRunRecordBody) &&
      !/stateRecords\.push/.test(writeRunRecordBody) &&
      /commitRequests\[0\]\.canonical_projection/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /store\.rustWrites\.map/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ) &&
      /persists records in Rust/.test(
        read("packages/runtime-daemon/src/threads/thread-persistence.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/threads/thread-persistence.mjs",
      "packages/runtime-daemon/src/threads/thread-persistence.test.mjs",
    ],
    "Phase 5/11 is pending: run-state sidecar records must be materialized, storage-admitted, and persisted by Rust before durable local JSON mutation",
  );
  assertCheck(
    result,
    "model-mount-invocation-receipt-binder-core",
    /bind_model_mount_invocation_receipt/.test(bridgeModule) &&
      /ReceiptBinder/.test(bridgeModule) &&
      /AgentgresAdmissionCore/.test(bridgeModule) &&
      /append_accepted_receipt/.test(bridgeModule) &&
      /RustProjectionCore/.test(bridgeModule) &&
      /model_mount_receipt_binding_ref/.test(modelInvocationOps) &&
      /model_mount_accepted_receipt_append/.test(modelInvocationOps) &&
      /model_mount_agentgres_admission/.test(modelInvocationOps) &&
      /model_mount_agentgres_operation_ref/.test(modelInvocationOps) &&
      /model_mount_agentgres_head_required/.test(modelInvocationOps) &&
      /agentgresOperationRefs/.test(modelInvocationOps) &&
      /stateRootAfter/.test(modelInvocationOps) &&
      /resultingHead/.test(modelInvocationOps) &&
      /model_mount_step_module_invocation/.test(modelInvocationOps) &&
      /model_mount_step_module_result/.test(modelInvocationOps) &&
      !/(?:modelMountReceiptBinding|modelMountAcceptedReceiptAppend|modelMountStepModuleInvocation|modelMountStepModuleResult|modelMountRouterAdmission|modelMountAgentgres|modelMountProjectionRecord)/.test(modelInvocationOps),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
    ],
    "Phase 4 is pending: Rust receipt_binder must bind model invocation accepted receipts before persistence",
  );
  assertCheck(
    result,
    "model-mount-invocation-agentgres-admission-core",
    /bind_model_mount_invocation_receipt/.test(bridgeModule) &&
      /AgentgresAdmissionCore/.test(bridgeModule) &&
      /agentgres_admission/.test(bridgeModule) &&
      /modelMountInvocationAgentgresTransitionForReceipt/.test(modelInvocationOps) &&
      /model_mount_agentgres_expected_heads/.test(modelInvocationOps) &&
      /model_mount_agentgres_state_root_before/.test(modelInvocationOps) &&
      /model_mount_agentgres_state_root_after/.test(modelInvocationOps) &&
      /model_mount_agentgres_resulting_head/.test(modelInvocationOps),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
    ],
    "Phase 4 is pending: model invocation receipt operations must pass through Rust Agentgres admission with expected heads and state-root binding",
  );
  assertCheck(
    result,
    "model-mount-invocation-direct-store-append-guard",
    /assertModelMountingReceiptWriteBound/.test(modelMountStore) &&
      /assertAcceptedModelInvocationReceiptBound/.test(modelMountReceiptWriteGuards) &&
      /model_mount_invocation_receipt_direct_append_forbidden/.test(modelMountReceiptWriteGuards) &&
      /model_invocation_stream_completed/.test(modelMountReceiptWriteGuards) &&
      /model_mount_receipt_binding_ref/.test(modelMountReceiptWriteGuards) &&
      /model_mount_accepted_receipt_append_hash/.test(modelMountReceiptWriteGuards) &&
      /model_mount_agentgres_operation_ref/.test(modelMountReceiptWriteGuards) &&
      /model_mount_agentgres_admission_hash/.test(modelMountReceiptWriteGuards) &&
      !/(?:modelMountReceiptBinding|modelMountAcceptedReceiptAppend|modelMountStepModuleInvocation|modelMountStepModuleResult|modelMountAgentgres)/.test(modelMountReceiptWriteGuards),
    [
      "packages/runtime-daemon/src/model-mounting/store.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs",
    ],
    "Phase 4/11 is pending: JS model-mounting store must reject direct model invocation receipt appends without Rust receipt_binder and Agentgres admission",
  );
  assertCheck(
    result,
    "model-mount-stream-completion-receipt-binder-core",
    /recordModelStreamCompleted/.test(conversationOps) &&
      /model_invocation_stream_completed/.test(conversationOps) &&
      /modelMountInvocationAdmissionRequestForReceipt/.test(conversationOps) &&
      /modelMountInvocationAgentgresTransitionForReceipt/.test(conversationOps) &&
      /modelMountInvocationReceiptBindingRequestForReceipt/.test(conversationOps) &&
      /model_mount_stream_completion_receipt_binding_required/.test(conversationOps) &&
      /withModelMountInvocationReceiptBinding/.test(conversationOps),
    ["packages/runtime-daemon/src/model-mounting/conversation-operations.mjs"],
    "Phase 4/9 is pending: model stream completion receipts must be Rust-bound and Agentgres-admitted before persistence",
  );
  assertCheck(
    result,
    "worker-service-package-invocation-admission-core",
    /WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION/.test(marketplaceCore) &&
      /WorkerServicePackageInvocationRequest/.test(marketplaceCore) &&
      /WorkerServicePackageInvocationRecord/.test(marketplaceCore) &&
      /WorkerServicePackageInvocationCore/.test(marketplaceCore) &&
      /StepModuleRouterCore/.test(marketplaceCore) &&
      /ReceiptBinder/.test(marketplaceCore) &&
      /AgentgresAdmissionCore/.test(marketplaceCore) &&
      /RustProjectionCore/.test(marketplaceCore) &&
      /admits_worker_package_invocation_through_step_module_contract/.test(marketplaceCore) &&
      /package_invocation_agentgres_transition_requires_expected_heads/.test(marketplaceCore) &&
      /admit_worker_service_package_invocation/.test(runtimeKernelModule),
    [
      "crates/services/src/agentic/runtime/kernel/marketplace.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
    ],
    "Phase 8 is pending: worker/service package invocations must use shared StepModule ABI, receipt binding, Agentgres admission, and Rust projection",
  );
  assertCheck(
    result,
    "governed-meta-improvement-proposal-core",
    /GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION/.test(evolutionCore) &&
      /GovernedRuntimeImprovementProposal/.test(evolutionCore) &&
      /GovernedRuntimeImprovementAdmissionRecord/.test(evolutionCore) &&
      /GovernedEvolutionCore/.test(evolutionCore) &&
      /eval_receipt_refs/.test(evolutionCore) &&
      /verifier_receipt_refs/.test(evolutionCore) &&
      /approval_ref/.test(evolutionCore) &&
      /rollback_ref/.test(evolutionCore) &&
      /agentgres_operation_ref/.test(evolutionCore) &&
      /expected_heads/.test(evolutionCore) &&
      /governed_improvement_proposal_admits_eval_approval_rollback_and_agentgres/.test(evolutionCore) &&
      /direct_self_mutation_without_governed_proposal_fails_closed/.test(evolutionCore),
    ["crates/services/src/agentic/evolution.rs"],
    "Phase 9 is pending: meta-improvement must be proposal-mediated with eval receipts, approval, rollback, and Agentgres binding",
  );
  assertCheck(
    result,
    "direct-evolution-manifest-mutation-retired",
    /DIRECT_EVOLUTION_MUTATION_RETIRED/.test(evolutionCore) &&
      /direct_evolve_manifest_mutation_is_retired_fail_closed/.test(evolutionCore) &&
      !/evolution::manifest::/.test(evolutionCore) &&
      !/evolution::latest::/.test(evolutionCore) &&
      !/evolution::rationale::/.test(evolutionCore) &&
      !/active_service_key/.test(evolutionCore) &&
      !/AgentManifest/.test(evolutionCore),
    ["crates/services/src/agentic/evolution.rs"],
    "Phase 9 is pending: direct EvolutionService::evolve manifest mutation must be retired behind governed proposal admission",
  );
  assertCheck(
    result,
    "agentgres-expected-heads",
    codeCorpusContains(/expected_heads|projection_watermark|resulting_head/),
    ["crates/services/src/agentic/runtime", "packages/runtime-daemon/src"],
    "Phase 4 is pending: Agentgres admission must require expected heads and state-root binding",
  );
  return result;
}

function runCtee() {
  const result = createTierResult("ctee");
  const cteeModule = exists("crates/services/src/agentic/runtime/kernel/ctee.rs")
    ? read("crates/services/src/agentic/runtime/kernel/ctee.rs")
    : "";
  const kernelModule = exists("crates/services/src/agentic/runtime/kernel/mod.rs")
    ? read("crates/services/src/agentic/runtime/kernel/mod.rs")
    : "";
  const bridgeModule = exists("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    ? read("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    : "";
  const runtimeDaemonIndex = exists("packages/runtime-daemon/src/index.mjs")
    ? read("packages/runtime-daemon/src/index.mjs")
    : "";
  const cteePrivateWorkspaceRunner = exists("packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.mjs")
    : "";
  const cteePrivateWorkspaceRunnerTest = exists("packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.test.mjs")
    : "";
  const cteePrivateWorkspaceStoreTest = exists("packages/runtime-daemon/src/runtime-ctee-private-workspace-store.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-ctee-private-workspace-store.test.mjs")
    : "";
  const cteePrivateWorkspaceSurface = exists("packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs")
    : "";
  const cteePrivateWorkspaceSurfaceTest = exists("packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs")
    : "";
  const runtimeRouteHandlers = exists("packages/runtime-daemon/src/runtime-route-handlers.mjs")
    ? read("packages/runtime-daemon/src/runtime-route-handlers.mjs")
    : "";
  const runtimeRouteHandlersTest = exists("packages/runtime-daemon/src/runtime-route-handlers.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-route-handlers.test.mjs")
    : "";
  const agentSdkSubstrateClient = exists("packages/agent-sdk/src/substrate-client.ts")
    ? read("packages/agent-sdk/src/substrate-client.ts")
    : "";
  const cteePrivateWorkspaceActionResultType =
    agentSdkSubstrateClient.match(
      /export interface RuntimeCteePrivateWorkspaceActionResult[\s\S]*?\n}\n/,
    )?.[0] ?? "";
  const cteePrivateWorkspaceAdmissionCamelAliasPropertyPattern =
    /\b(?:schemaVersion|actionExecuted|threadId|agentId|invocationId|receiptRef|receiptBinding|acceptedReceiptAppend|agentgresAdmission|projectionRecord|receiptRefs|evidenceRefs)\s*:/;
  const cteePrivateWorkspaceAdmissionCamelAliasTypePattern =
    /\b(?:schemaVersion|actionExecuted|threadId|agentId|invocationId|receiptRef|receiptBinding|acceptedReceiptAppend|agentgresAdmission|projectionRecord|receiptRefs|evidenceRefs)\?:/;
  const agentSdkTest = exists("packages/agent-sdk/test/sdk.test.mjs")
    ? read("packages/agent-sdk/test/sdk.test.mjs")
    : "";
  const agentIdeIndex = exists("packages/agent-ide/src/index.ts")
    ? read("packages/agent-ide/src/index.ts")
    : "";
  const graphRuntimeTypes = exists("packages/agent-ide/src/runtime/graph-runtime-types.ts")
    ? read("packages/agent-ide/src/runtime/graph-runtime-types.ts")
    : "";
  const cteePrivateWorkspaceControlNodes = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.ts")
    : "";
  const cteePrivateWorkspaceControlNodesTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.test.ts")
    : "";
  assertCheck(
    result,
    "ctee-core-module",
    /PrivateWorkspaceCteeModule/.test(cteeModule) &&
      /CteePrivateWorkspaceRunner/.test(cteeModule) &&
      /ctee_private_workspace_module_path/.test(cteeModule),
    [
      "crates/services/src/agentic/runtime/kernel/ctee.rs",
      "docs/architecture/components/daemon-runtime/private-workspace-ctee.md",
    ],
    "Phase 6 is pending: cTEE private workspace action must route through the shared ABI",
  );
  assertCheck(
    result,
    "ctee-plaintext-negative-test",
    /cTEE private workspace plaintext mount on an untrusted node fails/.test(cteeModule) &&
      /UntrustedNodePlaintextMountForbidden|CteePlaintextCustodyForbidden/.test(cteeModule),
    ["crates/services/src/agentic/runtime/kernel/ctee.rs"],
    "Phase 6/11 is pending: untrusted-node plaintext mount must fail closed in executable tests",
  );
  assertCheck(
    result,
    "ctee-execution-admission-projection-bundle",
    /CteePrivateWorkspaceExecutionRecord/.test(cteeModule) &&
      /execute_and_admit/.test(cteeModule) &&
      /ReceiptBinder/.test(cteeModule) &&
      /AgentgresAdmissionCore/.test(cteeModule) &&
      /RustProjectionCore/.test(cteeModule) &&
      /StepModuleProjectionStatus::Live/.test(cteeModule) &&
      /execute_private_workspace_ctee_action/.test(kernelModule),
    [
      "crates/services/src/agentic/runtime/kernel/ctee.rs",
      "crates/services/src/agentic/runtime/kernel/mod.rs",
    ],
    "Phase 6 is pending: cTEE execution must bind receipts, admit Agentgres truth, and emit Rust projection records",
  );
  assertCheck(
    result,
    "ctee-execution-bridge-command",
    /CteePrivateWorkspaceBridgeRequest/.test(bridgeModule) &&
      /execute_private_workspace_ctee_action/.test(bridgeModule) &&
      /PrivateWorkspaceCteeModule/.test(bridgeModule) &&
      /rust_ctee_private_workspace_command/.test(bridgeModule) &&
      /accepted_receipt_append/.test(bridgeModule) &&
      /bridge_executes_private_workspace_ctee_action_through_rust_core/.test(bridgeModule),
    ["crates/node/src/bin/ioi_step_module_bridge/mod.rs"],
    "Phase 7 is pending: daemon command bridge must expose Rust cTEE execution with receipt/admission/projection artifacts",
  );
  assertCheck(
    result,
    "ctee-daemon-runner",
    /CTEE_PRIVATE_WORKSPACE_COMMAND_ENV/.test(cteePrivateWorkspaceRunner) &&
      /IOI_CTEE_PRIVATE_WORKSPACE_COMMAND/.test(cteePrivateWorkspaceRunner) &&
      /RustCteePrivateWorkspaceRunner/.test(cteePrivateWorkspaceRunner) &&
      /createCteePrivateWorkspaceRunnerFromEnv/.test(cteePrivateWorkspaceRunner) &&
      /createCteePrivateWorkspaceRunnerFromEnv/.test(runtimeDaemonIndex) &&
      /this\.cteePrivateWorkspaceRunner/.test(runtimeDaemonIndex) &&
      /executeAction/.test(cteePrivateWorkspaceRunner) &&
      /execute_private_workspace_ctee_action/.test(cteePrivateWorkspaceRunner) &&
      /ctee_operator/.test(cteePrivateWorkspaceRunner) &&
      /ctee_private_workspace_bridge_unconfigured/.test(cteePrivateWorkspaceRunner) &&
      /cTEE private workspace runner sends execution bridge request/.test(cteePrivateWorkspaceRunnerTest) &&
      /cTEE private workspace runner fails closed without command/.test(cteePrivateWorkspaceRunnerTest) &&
      /cTEE private workspace runner surfaces Rust execution rejection/.test(cteePrivateWorkspaceRunnerTest) &&
      /runtime store mounts cTEE private workspace runner from options/.test(
        cteePrivateWorkspaceStoreTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.mjs",
      "packages/runtime-daemon/src/runtime-ctee-private-workspace-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-ctee-private-workspace-store.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 7 is pending: daemon cTEE Private Workspace facade must call the Rust cTEE bridge and fail closed when unconfigured",
  );
  assertCheck(
    result,
    "ctee-product-route",
    /createRuntimeCteePrivateWorkspaceSurface/.test(runtimeDaemonIndex) &&
      /this\.cteePrivateWorkspaceSurface/.test(runtimeDaemonIndex) &&
      /executeCteePrivateWorkspaceAction/.test(runtimeDaemonIndex) &&
      /CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION/.test(cteePrivateWorkspaceSurface) &&
      /action_executed:\s*true/.test(cteePrivateWorkspaceSurface) &&
      /store\.cteePrivateWorkspaceRunner\.executeAction/.test(cteePrivateWorkspaceSurface) &&
      /ctee-private-workspace-actions/.test(runtimeRouteHandlers) &&
      /store\.executeCteePrivateWorkspaceAction/.test(runtimeRouteHandlers) &&
      /thread route executes cTEE private workspace actions through store facade/.test(
        runtimeRouteHandlersTest,
      ) &&
      /thread route does not expose cTEE private workspace apply shortcut/.test(
        runtimeRouteHandlersTest,
      ) &&
      /cTEE private workspace surface executes nested action through Rust runner/.test(
        cteePrivateWorkspaceSurfaceTest,
      ) &&
      /cTEE private workspace surface fails closed without action payload/.test(
        cteePrivateWorkspaceSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs",
      "packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs",
      "packages/runtime-daemon/src/runtime-route-handlers.mjs",
      "packages/runtime-daemon/src/runtime-route-handlers.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 7 is pending: product/API cTEE Private Workspace route must call Rust cTEE admission and expose no JS apply shortcut",
  );
  assertCheck(
    result,
    "ctee-admission-response-aliases-retired",
    !cteePrivateWorkspaceAdmissionCamelAliasPropertyPattern.test(cteePrivateWorkspaceSurface) &&
      !cteePrivateWorkspaceAdmissionCamelAliasTypePattern.test(
        cteePrivateWorkspaceActionResultType,
      ) &&
      /cTEE private workspace surface exposes only canonical snake_case admission fields/.test(
        cteePrivateWorkspaceSurfaceTest,
      ) &&
      /CTEE_PRIVATE_WORKSPACE_ADMISSION_CAMEL_ALIASES/.test(cteePrivateWorkspaceSurfaceTest) &&
      /Object\.hasOwn\(result, key\)/.test(cteePrivateWorkspaceSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs",
      "packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 7/11 is pending: cTEE Private Workspace admission responses must not preserve camelCase compatibility aliases after the canonical route is verified",
  );
  assertCheck(
    result,
    "ctee-sdk-ide-admission-surface",
    /executeCteePrivateWorkspaceAction/.test(agentSdkSubstrateClient) &&
      /RuntimeCteePrivateWorkspaceActionInput/.test(agentSdkSubstrateClient) &&
      /ctee-private-workspace-actions/.test(agentSdkSubstrateClient) &&
      /SDK executes cTEE private workspace actions through the thread route/.test(agentSdkTest) &&
      /WORKFLOW_RUNTIME_CTEE_PRIVATE_WORKSPACE_CONTROL_SCHEMA_VERSION/.test(
        cteePrivateWorkspaceControlNodes,
      ) &&
      /createRuntimeCteePrivateWorkspaceControlRequest/.test(cteePrivateWorkspaceControlNodes) &&
      /ctee-private-workspace-actions/.test(cteePrivateWorkspaceControlNodes) &&
      /admission_only:\s*true/.test(cteePrivateWorkspaceControlNodes) &&
      /direct_truth_write_allowed:\s*false/.test(cteePrivateWorkspaceControlNodes) &&
      /plaintext_custody_checked_by_rust:\s*true/.test(cteePrivateWorkspaceControlNodes) &&
      !/\/apply/.test(cteePrivateWorkspaceControlNodes) &&
      /builds cTEE private workspace controls for daemon admission/.test(
        cteePrivateWorkspaceControlNodesTest,
      ) &&
      /cTEE private workspace controls fail closed without admission refs/.test(
        cteePrivateWorkspaceControlNodesTest,
      ) &&
      /createRuntimeCteePrivateWorkspaceControlRequest/.test(agentIdeIndex) &&
      /RuntimeCteePrivateWorkspaceControlRequest/.test(graphRuntimeTypes),
    [
      "packages/agent-sdk/src/substrate-client.ts",
      "packages/agent-sdk/test/sdk.test.mjs",
      "packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.test.ts",
      "packages/agent-ide/src/runtime/graph-runtime-types.ts",
      "packages/agent-ide/src/index.ts",
    ],
    "Phase 7 is pending: SDK and IDE cTEE Private Workspace clients must consume the cTEE route without exposing a JS apply shortcut",
  );
  return result;
}

function runCompositor() {
  const result = createTierResult("compositor");
  const projectionCore = exists("crates/services/src/agentic/runtime/kernel/projection.rs")
    ? read("crates/services/src/agentic/runtime/kernel/projection.rs")
    : "";
  const bridgeModule = exists("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    ? read("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    : "";
  const runtimeDaemonIndex = exists("packages/runtime-daemon/src/index.mjs")
    ? read("packages/runtime-daemon/src/index.mjs")
    : "";
  const runtimeRunReadSurface = exists("packages/runtime-daemon/src/runtime-run-read-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-run-read-surface.mjs")
    : "";
  const runtimeRunReadSurfaceTest = exists("packages/runtime-daemon/src/runtime-run-read-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-run-read-surface.test.mjs")
    : "";
  const runtimeTaskJobSurface = exists("packages/runtime-daemon/src/runtime-task-job-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-task-job-surface.mjs")
    : "";
  const runtimeTaskJobSurfaceTest = exists("packages/runtime-daemon/src/runtime-task-job-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-task-job-surface.test.mjs")
    : "";
  const runtimeAgentRunLifecycle = exists("packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs")
    ? read("packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs")
    : "";
  const runtimeAgentRunLifecycleTest = exists(
    "packages/runtime-daemon/src/runtime-agent-run-lifecycle.test.mjs",
  )
    ? read("packages/runtime-daemon/src/runtime-agent-run-lifecycle.test.mjs")
    : "";
  const runtimeRecordProjections = exists("packages/runtime-daemon/src/runtime-record-projections.mjs")
    ? read("packages/runtime-daemon/src/runtime-record-projections.mjs")
    : "";
  const runtimeRecordProjectionsTest = exists(
    "packages/runtime-daemon/src/runtime-record-projections.test.mjs",
  )
    ? read("packages/runtime-daemon/src/runtime-record-projections.test.mjs")
    : "";
  const runtimeEventPayloads = exists("packages/runtime-daemon/src/runtime-event-payloads.mjs")
    ? read("packages/runtime-daemon/src/runtime-event-payloads.mjs")
    : "";
  const runtimeEventPayloadsTest = exists("packages/runtime-daemon/src/runtime-event-payloads.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-event-payloads.test.mjs")
    : "";
  const runtimeUsageEvents = exists("packages/runtime-daemon/src/runtime-usage-events.mjs")
    ? read("packages/runtime-daemon/src/runtime-usage-events.mjs")
    : "";
  const runtimeUsageEventsTest = exists("packages/runtime-daemon/src/runtime-usage-events.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-usage-events.test.mjs")
    : "";
  const usageTelemetry = exists("packages/runtime-daemon/src/usage-telemetry.mjs")
    ? read("packages/runtime-daemon/src/usage-telemetry.mjs")
    : "";
  const usageTelemetryTest = exists("packages/runtime-daemon/src/usage-telemetry.test.mjs")
    ? read("packages/runtime-daemon/src/usage-telemetry.test.mjs")
    : "";
  const contextBudgetPolicy = exists("packages/runtime-daemon/src/threads/context-budget-policy.mjs")
    ? read("packages/runtime-daemon/src/threads/context-budget-policy.mjs")
    : "";
  const contextBudgetPolicyTest = exists(
    "packages/runtime-daemon/src/threads/context-budget-policy.test.mjs",
  )
    ? read("packages/runtime-daemon/src/threads/context-budget-policy.test.mjs")
    : "";
  const subagentManager = exists("packages/runtime-daemon/src/subagent-manager.mjs")
    ? read("packages/runtime-daemon/src/subagent-manager.mjs")
    : "";
  const subagentBudgetForRequestBlock =
    subagentManager.match(
      /export function subagentBudgetForRequest[\s\S]*?\n}\n\nexport function subagentBudgetUsageTelemetryForRequest/,
    )?.[0] ?? "";
  const subagentBudgetUsageTelemetryNormalizer =
    subagentManager.match(
      /export function normalizeSubagentBudgetUsageTelemetry[\s\S]*?\n}\n\nexport function normalizeSubagentBudget/,
    )?.[0] ?? "";
  const subagentUsageTelemetryForRunBlock =
    subagentManager.match(
      /export function subagentUsageTelemetryForRun[\s\S]*?\n}\n\nexport function subagentBudgetStatusForRun/,
    )?.[0] ?? "";
  const subagentResultForRunBlock =
    subagentManager.match(
      /export function subagentResultForRun[\s\S]*?\n}\n\nexport function subagentManagerEventPayload/,
    )?.[0] ?? "";
  const subagentManagerEventPayloadBlock =
    subagentManager.match(
      /export function subagentManagerEventPayload[\s\S]*?\n}\n\nexport function subagentOperatorControlKind/,
    )?.[0] ?? "";
  const subagentManagerTest = exists("packages/runtime-daemon/src/subagent-manager.test.mjs")
    ? read("packages/runtime-daemon/src/subagent-manager.test.mjs")
    : "";
  const runtimeSubagentSurface = exists("packages/runtime-daemon/src/runtime-subagent-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-subagent-surface.mjs")
    : "";
  const runtimeSubagentSurfaceTest = exists("packages/runtime-daemon/src/runtime-subagent-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-subagent-surface.test.mjs")
    : "";
  const runtimeSubagentListEnvelopeBlock =
    runtimeSubagentSurface.match(
      /listSubagents\(store, threadId, options = \{\}\) \{[\s\S]*?\n    \},\n    getSubagent/,
    )?.[0] ?? "";
  const runtimeSubagentGetBlock =
    runtimeSubagentSurface.match(
      /getSubagent\(store, threadId, subagentId\) \{[\s\S]*?\n    \},\n    spawnSubagent/,
    )?.[0] ?? "";
  const runtimeSubagentWaitResultReadBlocks = [
    runtimeSubagentSurface.match(
      /waitSubagent\(store, threadId, subagentId, request = \{\}\) \{[\s\S]*?\n    \},\n    getSubagentResult/,
    )?.[0] ?? "",
    runtimeSubagentSurface.match(
      /getSubagentResult\(store, threadId, subagentId\) \{[\s\S]*?\n    \},\n    sendSubagentInput/,
    )?.[0] ?? "",
  ]
    .filter(Boolean)
    .join("\n");
  const runtimeSubagentSpawnBlock =
    runtimeSubagentSurface.match(
      /spawnSubagent\(store, threadId, request = \{\}\) \{[\s\S]*?\n    \},\n    waitSubagent/,
    )?.[0] ?? "";
  const runtimeSubagentSendInputBlock =
    runtimeSubagentSurface.match(
      /sendSubagentInput\(store, threadId, subagentId, request = \{\}\) \{[\s\S]*?\n    \},\n    resumeSubagent/,
    )?.[0] ?? "";
  const runtimeSubagentResumeBlock =
    runtimeSubagentSurface.match(
      /resumeSubagent\(store, threadId, subagentId, request = \{\}\) \{[\s\S]*?\n    \},\n    assignSubagent/,
    )?.[0] ?? "";
  const runtimeSubagentAssignBlock =
    runtimeSubagentSurface.match(
      /assignSubagent\(store, threadId, subagentId, request = \{\}\) \{[\s\S]*?\n    \},\n    cancelSubagent/,
    )?.[0] ?? "";
  const runtimeSubagentCancelBlock =
    runtimeSubagentSurface.match(
      /cancelSubagent\(store, threadId, subagentId, request = \{\}\) \{[\s\S]*?\n    \},\n    propagateSubagentCancellation/,
    )?.[0] ?? "";
  const runtimeSubagentPropagationEnvelopeBlock =
    runtimeSubagentSurface.match(
      /propagateSubagentCancellation\(store, threadId, request = \{\}\) \{[\s\S]*?\n    \},\n    subagentProjection/,
    )?.[0] ?? "";
  const runtimeSubagentInputRecordBlock =
    runtimeSubagentSurface.match(/const inputRecord = \{[\s\S]*?\n      \};/)?.[0] ?? "";
  const runtimeSubagentResumeRecordBlock =
    runtimeSubagentSurface.match(/const resumeRecord = \{[\s\S]*?\n      \};/)?.[0] ?? "";
  const runtimeSubagentAssignmentRecordBlock =
    runtimeSubagentSurface.match(/const assignmentRecord = \{[\s\S]*?\n      \};/)?.[0] ?? "";
  const runtimeSubagentCancellationObjectBlock =
    runtimeSubagentSurface.match(
      /cancellation:\s*\{[\s\S]*?\n        \},\n        updated_at:/,
    )?.[0] ?? "";
  const runtimeSubagentBudgetErrorDetailBlocks =
    runtimeSubagentSurface.match(
      /throw policyErrorDep\("Subagent budget limit exceeded\.", \{[\s\S]*?\n        \}\);/g,
    ) ?? [];
  const runtimeSubagentErrorDetailBlocks = [
    runtimeSubagentSurface.match(
      /throw notFoundDep\(`Subagent not found: \$\{subagentId\}`,[\s\S]*?\n        \}\);/,
    )?.[0] ?? "",
    runtimeSubagentSurface.match(/code: "subagent_prompt_required"[\s\S]*?\n        \}\);/)?.[0] ?? "",
    runtimeSubagentSurface.match(
      /throw policyErrorDep\("Subagent role concurrency limit reached\.", \{[\s\S]*?\n          \}\);/,
    )?.[0] ?? "",
    ...runtimeSubagentBudgetErrorDetailBlocks,
    runtimeSubagentSurface.match(
      /throw policyErrorDep\("Cannot send input to a canceled subagent\.", \{[\s\S]*?\n        \}\);/,
    )?.[0] ?? "",
    runtimeSubagentSurface.match(/code: "subagent_input_required"[\s\S]*?\n        \}\);/)?.[0] ?? "",
  ]
    .filter(Boolean)
    .join("\n");
  const runtimeSubagentLifecycleResultEnvelopeBlocks = [
    runtimeSubagentSurface.match(
      /waitSubagent\(store, threadId, subagentId, request = \{\}\) \{[\s\S]*?\n    \},\n    getSubagentResult/,
    )?.[0] ?? "",
    runtimeSubagentSurface.match(
      /resumeSubagent\(store, threadId, subagentId, request = \{\}\) \{[\s\S]*?\n    \},\n    assignSubagent/,
    )?.[0] ?? "",
    runtimeSubagentSurface.match(
      /cancelSubagent\(store, threadId, subagentId, request = \{\}\) \{[\s\S]*?\n    \},\n    propagateSubagentCancellation/,
    )?.[0] ?? "",
  ]
    .filter(Boolean)
    .join("\n");
  const runtimeSubagentPostSpawnLifecycleStagingBlocks =
    runtimeSubagentSurface.match(/const updated = \{[\s\S]*?\n      \};/g) ?? [];
  const runtimeSubagentSpawnStagingBlock =
    runtimeSubagentSurface.match(/const record = \{[\s\S]*?\n      \};\n      record\.result =/)?.[0] ?? "";
  const runtimeSubagentControlEventBlock =
    runtimeSubagentSurface.match(
      /appendThreadSubagentControlEvent\(store, \{[\s\S]*?\n    \},\n  \};/,
    )?.[0] ?? "";
  const runtimeSubagentListEnvelopeAliasPattern =
    /^\s*(?:schemaVersion|threadId|parentAgentId|activeCount)\s*[:,]/m;
  const runtimeSubagentPropagationEnvelopeAliasPattern =
    /^\s*(?:schemaVersion|threadId|parentAgentId|propagationPolicy|candidateCount|canceledCount|skippedCount|canceledSubagents|skippedSubagents|eventRefs|receiptRefs|skipReason|cancellationInheritance)\s*[:,]/m;
  const runtimeSubagentNestedInputAliasPattern =
    /^\s*(?:schemaVersion|inputId|runId|previousRunId|createdAt|workflowGraphId|workflowNodeId)\s*[:,]/m;
  const runtimeSubagentNestedResumeAliasPattern =
    /^\s*(?:schemaVersion|resumeId|runId|previousRunId|previousStatus|modelRouteId|restartCount|createdAt|workflowGraphId|workflowNodeId)\s*[:,]/m;
  const runtimeSubagentNestedAssignmentAliasPattern =
    /^\s*(?:schemaVersion|assignmentId|previousRole|targetAgentId|toolPack|modelRouteId|mergePolicy|cancellationInheritance|assignmentCount|createdAt|workflowGraphId|workflowNodeId)\s*[:,]/m;
  const runtimeSubagentNestedCancellationAliasPattern =
    /^\s*(?:previousStatus|requestedBy|propagatedFromThreadId)\s*[:,]/m;
  const runtimeSubagentErrorDetailAliasPattern =
    /^\s*(?:threadId|subagentId|activeForRole|maxConcurrency|budgetStatus|eventId|receiptRefs|policyDecisionRefs)\s*[:,]/m;
  const runtimeSubagentLifecycleResultEnvelopeAliasPattern =
    /^\s*receiptRefs\s*[:,]/m;
  const runtimeSubagentListRequestAliasReadPattern =
    /options\.subagentRole\b/;
  const runtimeSubagentPropagationRequestAliasPattern =
    /request\.workflowNodeId\b|^\s*workflowNodeId\s*[:,]/m;
  const runtimeSubagentListLookupRecordAliasReadPattern =
    /(?:record\.parentThreadId|(?:left|right)\.createdAt)\b/;
  const runtimeSubagentPropagationRecordAliasReadPattern =
    /(?:record\.(?:parentThreadId|subagentId|agentId|cancellationInheritance|lifecycleStatus)|(?:left|right)\.createdAt)\b/;
  const runtimeSubagentWaitResultRecordAliasReadPattern =
    /record\.(?:runId|outputContract|lifecycleStatus)\b|^\s*outputContractStatus\s*[:,]/m;
  const runtimeSubagentSendInputRecordAliasReadPattern =
    /record\.(?:lifecycleStatus|runId|agentId|outputContract|inputHistory|previousRunIds)\b|updated\.evidenceRefs\b/;
  const runtimeSubagentResumeRecordAliasReadPattern =
    /record\.(?:runId|lifecycleStatus|agentId|modelRouteId|outputContract|restartCount|resumeHistory|cancellationHistory|previousRunIds)\b|updated\.evidenceRefs\b/;
  const runtimeSubagentAssignRecordAliasReadPattern =
    /record\.(?:toolPack|modelRouteId|mergePolicy|cancellationInheritance|agentId|assignmentCount|assignmentHistory|runId|outputContract)\b|updated\.evidenceRefs\b/;
  const runtimeSubagentCancelRecordAliasReadPattern =
    /record\.(?:lifecycleStatus|runId|outputContract)\b|updated\.evidenceRefs\b|subagentBudgetForRequestDep\(record\)/;
  const runtimeSubagentBudgetRecordRequestAliasReadPattern =
    /subagentBudgetForRequestDep\(record\)/;
  const runtimeSubagentControlEventRecordAliasReadPattern =
    /record\.(?:subagentId|workflowGraphId|workflowNodeId|budgetPolicyDecision|budgetStatus|parentTurnId)\b/;
  const runtimeSubagentControlEventRequestAliasReadPattern =
    /request\.(?:workflowGraphId|workflowNodeId|receiptRefs|policyDecisionRefs|idempotencyKey)\b/;
  const runtimeSubagentSpawnRequestAliasReadPattern =
    /request\.(?:subagentPrompt|subagentRole|maxConcurrency|subagentMaxConcurrency|modelRouteId|subagentModelRoute|outputContract|subagentOutputContract|workflowGraphId|workflowNodeId|parentTurnId|turnId|contextPressureAction|contextPressure|pressureStatus|alertId|sourceEventId|receiptRefs|policyDecisionRefs|toolPack|subagentToolPack|forkContext|mergePolicy|cancellationInheritance)\b/;
  const runtimeSubagentSendInputRequestAliasReadPattern =
    /request\.(?:subagentInput|workflowGraphId|workflowNodeId)\b/;
  const runtimeSubagentResumeRequestAliasReadPattern =
    /request\.(?:subagentRole|modelRouteId|subagentModelRoute|resumePrompt|workflowGraphId|workflowNodeId)\b/;
  const runtimeSubagentAssignRequestAliasReadPattern =
    /request\.(?:subagentRole|toolPack|subagentToolPack|modelRouteId|subagentModelRoute|mergePolicy|cancellationInheritance|targetAgentId|workflowGraphId|workflowNodeId)\b/;
  const runtimeSubagentCancelRequestAliasReadPattern =
    /request\.(?:cancellationReason|cancellationInherited|propagatedFromThreadId)\b|(?:cancellationInherited|propagatedFromThreadId)\s*:/;
  const runtimeSubagentProjectionBlock =
    runtimeSubagentSurface.match(
      /subagentProjection\(record = \{\}\) \{[\s\S]*?\n    \},\n    appendThreadSubagentControlEvent/,
    )?.[0] ?? "";
  const runtimeSubagentRecordOutputAliasPattern =
    /^\s*(?:schemaVersion|subagentId|agentId|childThreadId|runId|parentThreadId|parentAgentId|parentTurnId|toolPack|modelRouteId|workflowGraphId|workflowNodeId|sessionBootId|lifecycleStatus|restartStatus|restartCount|forkContext|contextMode|maxConcurrency|budgetUsageTelemetry|budgetStatus|budgetPolicyDecision|blockReason|outputContract|outputContractStatus|outputContractValidation|mergePolicy|cancellationInheritance|contextPressureAction|contextPressure|pressure|pressureStatus|alertId|sourceEventId|sourceReceiptRefs|sourcePolicyDecisionRefs|createdAt|updatedAt|eventId|receiptRefs|policyDecisionRefs|evidenceRefs|waitEventId|waitedAt|inputId|inputCount|inputHistory|inputEventId|lastInput|lastInputAt|previousRunIds|resumeId|resumeHistory|resumeEventId|resumedAt|cancellationReason|cancellationInherited|propagatedFromThreadId|cancellationClearedAt|cancellationHistory|assignmentId|assignmentCount|assignmentHistory|assignEventId|assignedAt|targetAgentId|cancelEventId|canceledAt)\s*[:,]/m;
  const runtimeSubagentCanonicalSavedRecordWrites = (
    runtimeSubagentSurface.match(/const saved = withoutRetiredSubagentRecordOutputAliases\(\{/g) ??
    []
  ).length;
  const runtimeSubagentSavedRecordWriteCalls = (
    runtimeSubagentSurface.match(/store\.writeSubagent\(saved,\s*"subagent\./g) ?? []
  ).length;
  const runtimeEventEnvelopes = exists("packages/runtime-daemon/src/runtime-event-envelopes.mjs")
    ? read("packages/runtime-daemon/src/runtime-event-envelopes.mjs")
    : "";
  const runtimeEventEnvelopesTest = exists("packages/runtime-daemon/src/runtime-event-envelopes.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-event-envelopes.test.mjs")
    : "";
  const runtimeHttpUtils = exists("packages/runtime-daemon/src/runtime-http-utils.mjs")
    ? read("packages/runtime-daemon/src/runtime-http-utils.mjs")
    : "";
  const runtimeHttpUtilsTest = exists("packages/runtime-daemon/src/runtime-http-utils.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-http-utils.test.mjs")
    : "";
  const threadReplay = exists("packages/runtime-daemon/src/threads/thread-replay.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-replay.mjs")
    : "";
  const threadTurnProjection = exists("packages/runtime-daemon/src/threads/thread-turn-projection.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-turn-projection.mjs")
    : "";
  const threadTurnProjectionTest = exists(
    "packages/runtime-daemon/src/threads/thread-turn-projection.test.mjs",
  )
    ? read("packages/runtime-daemon/src/threads/thread-turn-projection.test.mjs")
    : "";
  const runtimeBridgeThread = exists("packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs")
    ? read("packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs")
    : "";
  const runtimeBridgeThreadTest = exists(
    "packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs",
  )
    ? read("packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs")
    : "";
  const runtimeMcpHelpers = exists("packages/runtime-daemon/src/runtime-mcp-helpers.mjs")
    ? read("packages/runtime-daemon/src/runtime-mcp-helpers.mjs")
    : "";
  const runtimeMcpHelpersTest = exists("packages/runtime-daemon/src/runtime-mcp-helpers.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-mcp-helpers.test.mjs")
    : "";
  const agentIdeTerminalRunLaunch = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.ts")
    : "";
  const agentIdeTerminalRunLaunchTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.test.ts")
    : "";
  const agentIdeComputerUseReplayTimeline = exists(
    "packages/agent-ide/src/runtime/workflow-computer-use-replay-timeline.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-computer-use-replay-timeline.ts")
    : "";
  const computerUseReplayTimelineProof = exists(
    "scripts/lib/workflow-computer-use-replay-timeline-proof.mjs",
  )
    ? read("scripts/lib/workflow-computer-use-replay-timeline-proof.mjs")
    : "";
  const agentIdeEventIdentity = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-event-identity.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-event-identity.ts")
    : "";
  const agentIdeEventIdentityTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-event-identity.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-event-identity.test.ts")
    : "";
  const agentIdeContextBudgetControlNodes = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.ts")
    : "";
  const agentIdeContextBudgetControlNodesTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.test.ts")
    : "";
  const agentIdeCodingToolControlNodes = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.ts")
    : "";
  const agentIdeCodingToolControlNodesTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.test.ts")
    : "";
  const agentIdeSubagentControlNodes = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.ts")
    : "";
  const agentIdeSubagentControlNodesTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.test.ts")
    : "";
  const agentIdeDelegationMatrix = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-delegation-matrix.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-delegation-matrix.ts")
    : "";
  const agentIdeTelemetrySourceBinding = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.ts")
    : "";
  const agentIdeTelemetryBudgetChainSubflow = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.ts")
    : "";
  const agentIdeTelemetryBudgetChainMaterialization = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.ts")
    : "";
  const agentIdeTelemetryBudgetChainMaterializationTest = exists(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.test.ts",
  )
    ? read("packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.test.ts")
    : "";
  const agentIdeMixedRuntimePanels = [
    "packages/agent-ide/src/runtime/workflow-runtime-goal-verification-panel.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-policy-lease-panel.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-receipt-first-tool-timeline.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-delegation-matrix.ts",
  ]
    .filter((file) => exists(file))
    .map((file) => read(file))
    .join("\n");
  const agentIdeTypedRuntimePanels = [
    "packages/agent-ide/src/runtime/workflow-workspace-trust-gate.ts",
    "packages/agent-ide/src/runtime/workflow-hunk-decision-receipt-panel.ts",
    "packages/agent-ide/src/runtime/workflow-signed-replay-notebook.ts",
    "packages/agent-ide/src/runtime/workflow-context-lifecycle-panel.ts",
    "packages/agent-ide/src/runtime/workflow-worker-contribution-trace.ts",
  ]
    .filter((file) => exists(file))
    .map((file) => read(file))
    .join("\n");
  const agentSdkRuntimeEvents = exists("packages/agent-sdk/src/runtime-events.ts")
    ? read("packages/agent-sdk/src/runtime-events.ts")
    : "";
  const agentSdkSubstrateClient = exists("packages/agent-sdk/src/substrate-client.ts")
    ? read("packages/agent-sdk/src/substrate-client.ts")
    : "";
  const agentSdkTest = exists("packages/agent-sdk/test/sdk.test.mjs")
    ? read("packages/agent-sdk/test/sdk.test.mjs")
    : "";
  const liveRuntimeDaemonContract = exists("scripts/lib/live-runtime-daemon-contract.test.mjs")
    ? read("scripts/lib/live-runtime-daemon-contract.test.mjs")
    : "";
  function blockBetween(text, startMarker, endMarker) {
    const startIndex = text.indexOf(startMarker);
    if (startIndex < 0) return "";
    const remainder = text.slice(startIndex);
    const endIndex = remainder.indexOf(endMarker, startMarker.length);
    return endIndex < 0 ? remainder : remainder.slice(0, endIndex);
  }
  const runtimeUsageSdkTelemetryBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeUsageTelemetry",
    "export interface RuntimeUsageListInput",
  );
  const runtimeUsageSdkListInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeUsageListInput",
    "export interface RuntimeUsageListResult",
  );
  const runtimeUsageSdkListResultBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeUsageListResult",
    "export interface RuntimeTaskRecord",
  );
  const runtimeUsageSdkListQueryBlock = blockBetween(
    agentSdkSubstrateClient,
    "function runtimeUsageListQuery",
    "function memoryListQuery",
  );
  const runtimeTaskSdkListOptionsBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeTaskListOptions",
    "export interface RuntimeTaskCreateOptions",
  );
  const runtimeTaskSdkCreateOptionsBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeTaskCreateOptions",
    "export interface RuntimeJobRecord",
  );
  const runtimeJobSdkListOptionsBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeJobListOptions",
    "export type RuntimeSubagentLifecycleStatus",
  );
  const runtimeTaskSdkListMethodBlock = blockBetween(
    agentSdkSubstrateClient,
    "async listTasks",
    "async getTask",
  );
  const runtimeJobSdkListMethodBlock = blockBetween(
    agentSdkSubstrateClient,
    "async listJobs",
    "async getJob",
  );
  const runtimeTaskJobListJobsBlock = blockBetween(
    runtimeTaskJobSurface,
    "listJobs(store, options = {})",
    "createTask(store",
  );
  const runtimeTaskJobCreateTaskBlock = blockBetween(
    runtimeTaskJobSurface,
    "createTask(store, body = {})",
    "listTasks(store",
  );
  const runtimeTaskJobListTasksBlock = blockBetween(
    runtimeTaskJobSurface,
    "listTasks(store, options = {})",
    "getTask(store",
  );
  const runtimeSubagentSdkOutputContractStatusBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentOutputContractStatus",
    "export interface RuntimeSubagentUsageTelemetry",
  );
  const runtimeSubagentSdkUsageTelemetryBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentUsageTelemetry",
    "export interface RuntimeSubagentBudgetStatus",
  );
  const runtimeSubagentSdkControlInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentControlInput",
    "export interface RuntimeSubagentListInput",
  );
  const runtimeSubagentSdkListInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentListInput",
    "export interface RuntimeSubagentRecord",
  );
  const runtimeSubagentSdkRecordBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentRecord",
    "export interface RuntimeSubagentListResult",
  );
  const runtimeSubagentSdkListResultBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentListResult",
    "export interface RuntimeSubagentResult",
  );
  const runtimeSubagentSdkResultBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentResult",
    "export interface RuntimeSubagentCancellationPropagationResult",
  );
  const runtimeSubagentSdkCancellationPropagationResultBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentCancellationPropagationResult",
    "export interface AgentMemoryProjection",
  );
  const agentIdeSubagentDelegationMatrixBlock = blockBetween(
    agentIdeDelegationMatrix,
    'if (payloadObject === "ioi.runtime_subagent_manager_event")',
    'if (payloadEventKind === "SubagentMemoryInheritance")',
  );
  const runtimeUsagePayloadSummaryBlocks = [
    blockBetween(
      runtimeEventPayloads,
      'if (event.type === "usage_delta")',
      'if (event.type === "context_pressure_delta")',
    ),
    blockBetween(
      runtimeEventPayloads,
      'if (event.type === "context_pressure_delta")',
      'if (event.type === "context_pressure_alert")',
    ),
    blockBetween(
      runtimeEventPayloads,
      'if (event.type === "context_pressure_alert")',
      'if (event.type === "usage_final")',
    ),
    blockBetween(
      runtimeEventPayloads,
      'if (event.type === "usage_final")',
      'if (event.type !== "model_route_decision")',
    ),
  ].join("\n");
  assertCheck(
    result,
    "rust-projection-core",
    /RustProjectionCore/.test(projectionCore) &&
      /StepModuleProjectionRecord/.test(projectionCore) &&
      /workflow_projection_watermark_from_agentgres/.test(projectionCore) &&
      /projection_record/.test(bridgeModule),
    [
      "crates/services/src/agentic/runtime/kernel/projection.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
    ],
    "Phase 5 is pending: compositor projections must come from Rust projection records and Agentgres watermarks",
  );
  assertCheck(
    result,
    "compositor-truth-negative-guard",
    /workflow compositor attempt to create accepted truth directly fails/.test(projectionCore) &&
      /WorkflowCompositorAcceptedTruthForbidden/.test(projectionCore),
    ["crates/services/src/agentic/runtime/kernel/projection.rs"],
    "Phase 11 is pending: compositor must be unable to create accepted truth directly",
  );
  assertCheck(
    result,
    "runtime-run-legacy-event-read-alias-retired",
    !/legacyEventsForRun/.test(`${runtimeDaemonIndex}\n${runtimeRunReadSurface}`) &&
      /replayFromCanonicalState/.test(runtimeDaemonIndex) &&
      /replayFromCanonicalState/.test(runtimeRunReadSurface) &&
      /canonicalProjection/.test(runtimeRunReadSurface) &&
      /Object\.hasOwn\(surface,\s*"legacyEventsForRun"\),\s*false/.test(runtimeRunReadSurfaceTest),
    [
      "packages/runtime-daemon/src/index.mjs",
      "packages/runtime-daemon/src/runtime-run-read-surface.mjs",
      "packages/runtime-daemon/src/runtime-run-read-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime run reads must use canonical replay/projection APIs instead of the legacy event alias",
  );
  assertCheck(
    result,
    "runtime-event-legacy-payload-aliases-retired",
    !/legacy_event_(?:id|type)/.test(
      `${runtimeEventPayloads}\n${agentSdkRuntimeEvents}\n${agentSdkSubstrateClient}`,
    ) &&
      !/eventKind:\s*event\.data\?\.eventKind\s*\?\?\s*"Runtime(?:UsageTelemetry|ContextPressure)/.test(
        runtimeEventPayloads,
      ) &&
      /retiredPayloadKeys/.test(runtimeEventPayloadsTest) &&
      /Object\.hasOwn\(usage,\s*"eventKind"\),\s*false/.test(runtimeEventPayloadsTest) &&
      /Object\.hasOwn\(contextDelta,\s*"eventKind"\),\s*false/.test(runtimeEventPayloadsTest) &&
      /Object\.hasOwn\(alert,\s*"eventKind"\),\s*false/.test(runtimeEventPayloadsTest) &&
      /Object\.hasOwn\(usageFinal,\s*"eventKind"\),\s*false/.test(runtimeEventPayloadsTest) &&
      /retiredPayloadKeys/.test(agentSdkTest),
    [
      "packages/runtime-daemon/src/runtime-event-payloads.mjs",
      "packages/runtime-daemon/src/runtime-event-payloads.test.mjs",
      "packages/agent-sdk/src/runtime-events.ts",
      "packages/agent-sdk/src/substrate-client.ts",
      "packages/agent-sdk/test/sdk.test.mjs",
    ],
    "Phase 10/11 is pending: runtime event payloads and SDK projection must use canonical envelope ids/kinds instead of legacy payload aliases",
  );
  assertCheck(
    result,
    "runtime-event-usage-summary-reader-aliases-retired",
    runtimeUsagePayloadSummaryBlocks.length > 0 &&
      !/event\.data\?\.(?:eventKind|schemaVersion|runId|threadId|turnId|totalTokens|inputTokens|outputTokens|estimatedCostUsd|contextPressure|contextPressureStatus|workflowNodeId|componentKind|usageTotalTokens|usageCostEstimateUsd|usageContextPressure|usageContextPressureStatus|alertId|alertLevel|pressureStatus|recommendedAction)/.test(
        runtimeUsagePayloadSummaryBlocks,
      ) &&
      /retiredUsageSummaryReaderAliasKeys/.test(runtimeEventPayloadsTest) &&
      /retiredContextPressureDeltaSummaryReaderAliasKeys/.test(runtimeEventPayloadsTest) &&
      /retiredContextPressureAlertSummaryReaderAliasKeys/.test(runtimeEventPayloadsTest) &&
      /retiredUsageFinalSummaryReaderAliasKeys/.test(runtimeEventPayloadsTest),
    [
      "packages/runtime-daemon/src/runtime-event-payloads.mjs",
      "packages/runtime-daemon/src/runtime-event-payloads.test.mjs",
    ],
    "Phase 10/11 is pending: runtime event payload summaries must ignore retired camelCase usage/context-pressure payload data aliases",
  );
  assertCheck(
    result,
    "runtime-usage-event-producer-aliases-retired",
    !/schemaVersion:\s*RUNTIME_(?:USAGE_DELTA|CONTEXT_PRESSURE_(?:DELTA|ALERT))_SCHEMA_VERSION/.test(
      runtimeUsageEvents,
    ) &&
      !/eventKind:\s*"Runtime(?:UsageTelemetry|ContextPressure)\.(?:Delta|Alert)"/.test(
        runtimeUsageEvents,
      ) &&
      !/workflowNodeId:\s*"runtime\./.test(runtimeUsageEvents) &&
      !/componentKind:\s*"(?:usage_telemetry|context_pressure|context_pressure_alert)"/.test(
        runtimeUsageEvents,
      ) &&
      !/contextPressureSummary:/.test(runtimeUsageEvents) &&
      !/(?:inputTokens|outputTokens|totalTokens|estimatedCostUsd|contextWindowTokens|contextUsedTokens|contextPressure|contextPressureStatus|usageTotalTokens|usageCostEstimateUsd|usageContextPressure|usageContextPressureStatus|recommendedAction|sourceUsageDeltaRef|receiptRefs|policyDecisionRefs):/.test(
        runtimeUsageEvents,
      ) &&
      !/usageTelemetry\.(?:inputTokens|outputTokens|totalTokens|estimatedCostUsd|contextWindowTokens|contextUsedTokens|contextPressure|contextPressureStatus|routeId)/.test(
        runtimeUsageEvents,
      ) &&
      /retiredUsagePayloadAliasKeys/.test(runtimeUsageEventsTest) &&
      /retiredUsageTelemetryInputAliasKeys/.test(runtimeUsageEventsTest) &&
      /retiredContextPressurePayloadAliasKeys/.test(runtimeUsageEventsTest) &&
      /retiredContextPressureAlertAliasKeys/.test(runtimeUsageEventsTest) &&
      /retiredContextPressureAlertActionAliasKeys/.test(runtimeUsageEventsTest),
    [
      "packages/runtime-daemon/src/runtime-usage-events.mjs",
      "packages/runtime-daemon/src/runtime-usage-events.test.mjs",
    ],
    "Phase 10/11 is pending: daemon runtime usage event producers must emit canonical snake_case payload fields without compatibility aliases",
  );
  assertCheck(
    result,
    "runtime-usage-telemetry-output-aliases-retired",
    !/schemaVersion:\s*RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION/.test(usageTelemetry) &&
      !/^\s*generatedAt\s*:/m.test(usageTelemetry) &&
      !/^\s*groupBy\s*[:,]/m.test(usageTelemetry) &&
      /retiredUsageTelemetryOutputAliasKeys/.test(usageTelemetryTest) &&
      /retiredUsageTelemetrySummaryAliasKeys/.test(usageTelemetryTest) &&
      /retiredUsageTelemetryListAliasKeys/.test(usageTelemetryTest) &&
      /runtime run usage telemetry emits canonical fields only/.test(usageTelemetryTest) &&
      /runtime thread usage telemetry aggregate emits canonical fields only/.test(usageTelemetryTest) &&
      /runtime usage telemetry list envelope emits canonical fields only/.test(usageTelemetryTest),
    [
      "packages/runtime-daemon/src/usage-telemetry.mjs",
      "packages/runtime-daemon/src/usage-telemetry.test.mjs",
    ],
    "Phase 10/11 is pending: runtime usage telemetry producers must emit canonical snake_case output fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "runtime-usage-telemetry-input-aliases-retired",
    !/(?:run|explicit|providerUsage|route|agent|record|usage|thread|subagent)(?:\?\.|\.)(?:usageTelemetry|runtimeUsage|providerUsage|modelRouteDecision|modelRouteId|routeId|selectedModel|providerId|inputTokens|outputTokens|promptTokens|completionTokens|reasoningTokens|cachedInputTokens|toolResultTokens|compactedTokens|totalTokens|estimatedCostUsd|estimatedCostMicros|costEstimateUsd|contextWindowTokens|modelContextWindowTokens|maxContextTokens|contextUsedTokens|contextPressure|contextPressureStatus|latencyMs|sourceCounts|sourceRefs|parentThreadId|parentTurnId|subagentId|runId|agentId|threadId|turnId)/.test(
      usageTelemetry,
    ) &&
      /retiredUsageTelemetryInputAliasKeys/.test(usageTelemetryTest) &&
      /runtime run usage telemetry ignores retired input aliases/.test(usageTelemetryTest) &&
      /runtime thread usage telemetry ignores retired aggregate and subagent aliases/.test(
        usageTelemetryTest,
      ),
    [
      "packages/runtime-daemon/src/usage-telemetry.mjs",
      "packages/runtime-daemon/src/usage-telemetry.test.mjs",
    ],
    "Phase 10/11 is pending: runtime usage telemetry producers must ignore retired camelCase input data aliases",
  );
  assertCheck(
    result,
    "runtime-thread-turn-usage-aliases-retired",
    !/^\s*usageTelemetry,?\s*$/m.test(threadTurnProjection) &&
      !/^\s*runtime_usage:\s*usageTelemetry,?\s*$/m.test(threadTurnProjection) &&
      !/^\s*runtimeUsage:\s*usageTelemetry,?\s*$/m.test(threadTurnProjection) &&
      !/run\.(?:usageTelemetry|runtimeUsage)/.test(threadTurnProjection) &&
      /retiredUsageProjectionAliasKeys/.test(threadTurnProjectionTest) &&
      /turn projection ignores retired run usage aliases/.test(threadTurnProjectionTest),
    [
      "packages/runtime-daemon/src/threads/thread-turn-projection.mjs",
      "packages/runtime-daemon/src/threads/thread-turn-projection.test.mjs",
    ],
    "Phase 10/11 is pending: thread/turn usage projections must not emit or read retired usage telemetry aliases",
  );
  assertCheck(
    result,
    "runtime-agent-run-lifecycle-usage-aliases-retired",
    !/^\s*usageTelemetry,?\s*$/m.test(runtimeAgentRunLifecycle) &&
      !/^\s*runtimeUsage:\s*usageTelemetry,?\s*$/m.test(runtimeAgentRunLifecycle) &&
      /retiredRuntimeRunUsageAliasKeys/.test(runtimeAgentRunLifecycleTest) &&
      /assertMissingKeys\(run,\s*retiredRuntimeRunUsageAliasKeys\)/.test(
        runtimeAgentRunLifecycleTest,
      ) &&
      /assertMissingKeys\(run\.trace,\s*retiredRuntimeRunUsageAliasKeys\)/.test(
        runtimeAgentRunLifecycleTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs",
      "packages/runtime-daemon/src/runtime-agent-run-lifecycle.test.mjs",
    ],
    "Phase 10/11 is pending: runtime agent run lifecycle records must not emit retired usage telemetry aliases",
  );
  assertCheck(
    result,
    "runtime-bridge-run-record-usage-aliases-retired",
    !/^\s*usageTelemetry,?\s*$/m.test(runtimeRecordProjections) &&
      !/^\s*runtimeUsage:\s*usageTelemetry,?\s*$/m.test(runtimeRecordProjections) &&
      /retiredRuntimeBridgeUsageAliasKeys/.test(runtimeRecordProjectionsTest) &&
      /runtime bridge run record emits canonical usage telemetry only/.test(
        runtimeRecordProjectionsTest,
      ) &&
      /assertMissingKeys\(run\.trace,\s*retiredRuntimeBridgeUsageAliasKeys\)/.test(
        runtimeRecordProjectionsTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-record-projections.mjs",
      "packages/runtime-daemon/src/runtime-record-projections.test.mjs",
    ],
    "Phase 10/11 is pending: runtime bridge run records must not emit retired usage telemetry aliases",
  );
  assertCheck(
    result,
    "runtime-bridge-turn-usage-aliases-retired",
    !/bridgeResult\?\.(?:usageTelemetry|runtime_usage|runtimeUsage)/.test(
      runtimeBridgeThread,
    ) &&
      /retiredRuntimeBridgeTurnUsageAliasKeys/.test(runtimeBridgeThreadTest) &&
      /runtime bridge turn submit normalization ignores retired usage aliases/.test(
        runtimeBridgeThreadTest,
      ),
    [
      "packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs",
      "packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs",
    ],
    "Phase 10/11 is pending: runtime bridge turn normalization must not read retired usage telemetry aliases",
  );
  assertCheck(
    result,
    "runtime-daemon-index-usage-aliases-retired",
    !/request\.(?:usageTelemetry|runtime_usage|runtimeUsage)/.test(runtimeDaemonIndex) &&
      !/^\s*usageTelemetry,?\s*$/m.test(runtimeDaemonIndex) &&
      !/^\s*runtimeUsage:\s*usageTelemetry,?\s*$/m.test(runtimeDaemonIndex) &&
      /model_route_decision:\s*modelRouteDecision/.test(runtimeDaemonIndex),
    ["packages/runtime-daemon/src/index.mjs"],
    "Phase 10/11 is pending: monolithic daemon run/trace assembly must not accept or emit retired usage telemetry aliases",
  );
  assertCheck(
    result,
    "runtime-context-budget-usage-input-aliases-retired",
    !/(?:request|codingPack)(?:\?\.|\.)(?:usageTelemetry|runtimeUsageMeter|runtime_usage_meter|budgetUsageTelemetry|runtimeTelemetrySummary|runtime_telemetry_summary)/.test(
      contextBudgetPolicy,
    ) &&
      !/entry\.(?:totalTokens|estimatedCostUsd|contextPressure)/.test(
        contextBudgetPolicy,
      ) &&
      !/usageTelemetry(?:\?\.|\.)(?:threadId|runId)/.test(
        contextBudgetPolicy,
      ) &&
      /retiredContextBudgetUsageInputAliasKeys/.test(contextBudgetPolicyTest) &&
      /context budget usage telemetry ignores retired request aliases/.test(
        contextBudgetPolicyTest,
      ) &&
      /context budget usage summary ignores retired data aliases/.test(
        contextBudgetPolicyTest,
      ),
    [
      "packages/runtime-daemon/src/threads/context-budget-policy.mjs",
      "packages/runtime-daemon/src/threads/context-budget-policy.test.mjs",
    ],
    "Phase 10/11 is pending: context-budget usage telemetry must ignore retired request and data aliases before policy evaluation",
  );
  assertCheck(
    result,
    "runtime-subagent-usage-input-aliases-retired",
    !/(?:request|request\.options)(?:\?\.|\.)(?:budgetUsageTelemetry|runtimeTelemetrySummary|runtime_telemetry_summary)/.test(
      subagentManager,
    ) &&
      !/(?:usage|previousUsage)(?:\?\.|\.)(?:cumulativeInputTokens|inputTokens|cumulativeOutputTokens|outputTokens|cumulativeTotalTokens|totalTokens|cumulativeCostEstimateUsd|costEstimateUsd|estimatedCostUsd|sourceCounts|sourceRefs|receiptRefs|policyDecisionRefs|runtimeTelemetrySummarySchemaVersion)/.test(
        subagentManager,
      ) &&
      !/run\.modelRouteDecision/.test(subagentManager) &&
      /retiredSubagentBudgetUsageRequestAliasKeys/.test(subagentManagerTest) &&
      /subagent budget usage telemetry ignores retired request aliases/.test(
        subagentManagerTest,
      ) &&
      /subagent budget usage telemetry ignores retired data aliases/.test(
        subagentManagerTest,
      ) &&
      /subagent usage telemetry ignores retired previous usage aliases/.test(
        subagentManagerTest,
      ),
    [
      "packages/runtime-daemon/src/subagent-manager.mjs",
      "packages/runtime-daemon/src/subagent-manager.test.mjs",
    ],
    "Phase 10/11 is pending: subagent budget usage telemetry must ignore retired request and data aliases before budget policy evaluation",
  );
  assertCheck(
    result,
    "runtime-subagent-budget-request-aliases-retired",
    subagentBudgetForRequestBlock.length > 0 &&
      !/request\.subagentBudget/.test(subagentBudgetForRequestBlock) &&
      /retiredSubagentBudgetRequestAliasKeys/.test(subagentManagerTest) &&
      /subagent budget ignores retired request aliases/.test(
        subagentManagerTest,
      ),
    [
      "packages/runtime-daemon/src/subagent-manager.mjs",
      "packages/runtime-daemon/src/subagent-manager.test.mjs",
    ],
    "Phase 10/11 is pending: subagent budget request parsing must ignore the retired subagentBudget alias before budget policy evaluation",
  );
  assertCheck(
    result,
    "runtime-subagent-budget-usage-output-aliases-retired",
    !/(?:schemaVersion|cumulativeInputTokens|cumulativeOutputTokens|cumulativeTotalTokens|cumulativeCostEstimateUsd|sourceCounts|sourceRefs|receiptRefs|policyDecisionRefs|runtimeTelemetrySummarySchemaVersion)\s*:/.test(
      subagentBudgetUsageTelemetryNormalizer,
    ) &&
      /retiredSubagentBudgetUsageOutputAliasKeys/.test(subagentManagerTest) &&
      /assertCanonicalSubagentBudgetUsageOutput/.test(subagentManagerTest),
    [
      "packages/runtime-daemon/src/subagent-manager.mjs",
      "packages/runtime-daemon/src/subagent-manager.test.mjs",
    ],
    "Phase 10/11 is pending: subagent budget usage telemetry output must expose canonical snake_case fields only",
  );
  assertCheck(
    result,
    "runtime-subagent-run-usage-output-aliases-retired",
    !/(?:schemaVersion|runId|inputTokens|outputTokens|totalTokens|cumulativeInputTokens|cumulativeOutputTokens|cumulativeTotalTokens|costEstimateUsd|cumulativeCostEstimateUsd|modelRouteId)\s*:/.test(
      subagentUsageTelemetryForRunBlock,
    ) &&
      /retiredSubagentUsageTelemetryOutputAliasKeys/.test(
        subagentManagerTest,
      ) &&
      /assertCanonicalSubagentUsageTelemetryOutput/.test(
        subagentManagerTest,
      ),
    [
      "packages/runtime-daemon/src/subagent-manager.mjs",
      "packages/runtime-daemon/src/subagent-manager.test.mjs",
    ],
    "Phase 10/11 is pending: subagent run usage telemetry output must expose canonical snake_case fields only",
  );
  assertCheck(
    result,
    "runtime-subagent-manager-usage-output-alias-retired",
    !/record\??\.usageTelemetry/.test(subagentManager) &&
      !/^\s*usageTelemetry:/m.test(subagentManager) &&
      /usage_telemetry:\s*record\??\.usage_telemetry/.test(
        subagentManager,
      ) &&
      /assertCanonicalSubagentManagerUsageTelemetry/.test(
        subagentManagerTest,
      ) &&
      /hasOwnProperty\.call\(record,\s*"usageTelemetry"\)/.test(
        subagentManagerTest,
      ) &&
      /subagent result and manager events emit canonical usage telemetry only/.test(
        subagentManagerTest,
      ),
    [
      "packages/runtime-daemon/src/subagent-manager.mjs",
      "packages/runtime-daemon/src/subagent-manager.test.mjs",
    ],
    "Phase 10/11 is pending: subagent manager projections must expose canonical usage_telemetry without duplicate usageTelemetry",
  );
  assertCheck(
    result,
    "runtime-subagent-result-output-aliases-retired",
    !/^\s*(?:schemaVersion|subagentId|agentId|runId|lifecycleStatus|outputContractStatus|budgetStatus|receiptRefs)\s*[:,]/m.test(
      subagentResultForRunBlock,
    ) &&
      /retiredSubagentResultOutputAliasKeys/.test(subagentManagerTest) &&
      /assertCanonicalSubagentResultOutput/.test(subagentManagerTest),
    [
      "packages/runtime-daemon/src/subagent-manager.mjs",
      "packages/runtime-daemon/src/subagent-manager.test.mjs",
    ],
    "Phase 10/11 is pending: subagent result output must expose canonical snake_case fields only",
  );
  assertCheck(
    result,
    "runtime-subagent-manager-event-output-aliases-retired",
    !/^\s*(?:schemaVersion|eventKind|threadId|parentThreadId|parentTurnId|childThreadId|subagentId|agentId|runId|toolPack|modelRouteId|lifecycleStatus|outputContractStatus|maxConcurrency|budgetStatus|costEstimateUsd|tokenEstimate|mergePolicy|cancellationInheritance|contextPressureAction|contextPressure|pressure|pressureStatus|alertId|sourceEventId|sourceReceiptRefs|sourcePolicyDecisionRefs|inputId|inputCount|cancellationReason|cancellationInherited|propagatedFromThreadId|restartStatus|restartCount|resumeId|assignmentId|assignmentCount|targetAgentId)\s*[:,]/m.test(
      subagentManagerEventPayloadBlock,
    ) &&
      /retiredSubagentManagerEventOutputAliasKeys/.test(
        subagentManagerTest,
      ) &&
      /assertCanonicalSubagentManagerEventOutput/.test(
        subagentManagerTest,
      ) &&
      !/stringField\(payload,\s*"(?:lifecycleStatus|parentThreadId|parentTurnId|childThreadId|runId|subagentId|mergePolicy|cancellationInheritance|cancellationReason)"/.test(
        agentIdeSubagentDelegationMatrixBlock,
      ) &&
      !/(?:arrayField|objectField|stringField)\(payload,\s*"(?:outputContractStatus|receiptRefs|sourceReceiptRefs|policyDecisionRefs|sourcePolicyDecisionRefs)"/.test(
        agentIdeDelegationMatrix,
      ) &&
      /payload\.context_pressure_action/.test(liveRuntimeDaemonContract) &&
      !/payload\.contextPressureAction/.test(liveRuntimeDaemonContract),
    [
      "packages/runtime-daemon/src/subagent-manager.mjs",
      "packages/runtime-daemon/src/subagent-manager.test.mjs",
      "packages/agent-ide/src/runtime/workflow-runtime-delegation-matrix.ts",
      "scripts/lib/live-runtime-daemon-contract.test.mjs",
    ],
    "Phase 10/11 is pending: subagent manager event payloads must expose canonical snake_case fields only and IDE/SDK proofs must not consume retired raw payload aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-manager-event-input-aliases-retired",
    !/record(?:\?\.|\.)(?:parentThreadId|parentTurnId|childThreadId|subagentId|agentId|runId|toolPack|modelRouteId|lifecycleStatus|status|outputContractStatus|maxConcurrency|budgetStatus|mergePolicy|cancellationInheritance|contextPressureAction|contextPressure|pressureStatus|pressure|alertId|sourceEventId|sourceReceiptRefs|sourcePolicyDecisionRefs|inputId|inputCount|cancellationReason|cancellationInherited|propagatedFromThreadId|restartStatus|restartCount|resumeId|assignmentId|assignmentCount|targetAgentId)(?![A-Za-z0-9_])/.test(
      subagentManagerEventPayloadBlock,
    ) &&
      !/record\.cancellation\?\.(?:reason|inherited|propagated_from_thread_id|propagatedFromThreadId)/.test(
        subagentManagerEventPayloadBlock,
      ) &&
      /retiredSubagentManagerEventInputAliasRecord/.test(
        subagentManagerTest,
      ) &&
      /subagent manager event payload ignores retired record input aliases/.test(
        subagentManagerTest,
      ),
    [
      "packages/runtime-daemon/src/subagent-manager.mjs",
      "packages/runtime-daemon/src/subagent-manager.test.mjs",
    ],
    "Phase 10/11 is pending: subagent manager event payloads must ignore retired camelCase-only record input aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-surface-usage-input-alias-retired",
    !/record\.usageTelemetry/.test(runtimeSubagentSurface) &&
      /subagent surface ignores retired usageTelemetry previous usage fallback/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent surface must ignore retired usageTelemetry record input fallback",
  );
  assertCheck(
    result,
    "runtime-subagent-budget-usage-output-alias-retired",
    !/^\s*budgetUsageTelemetry,?\s*$/m.test(runtimeSubagentSurface) &&
      /budget_usage_telemetry:\s*budgetUsageTelemetry/.test(runtimeSubagentSurface) &&
      /assertCanonicalSubagentBudgetUsageTelemetry/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /hasOwnProperty\.call\(record,\s*"budgetUsageTelemetry"\)/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent records must expose canonical budget_usage_telemetry without duplicate budgetUsageTelemetry",
  );
  assertCheck(
    result,
    "runtime-subagent-usage-output-alias-retired",
    !/^\s*usageTelemetry:\s*budgetStatus\.usage,?\s*$/m.test(
      runtimeSubagentSurface,
    ) &&
      /usage_telemetry:\s*budgetStatus\.usage/.test(runtimeSubagentSurface) &&
      /assertCanonicalSubagentUsageTelemetry/.test(runtimeSubagentSurfaceTest) &&
      /hasOwnProperty\.call\(record,\s*"usageTelemetry"\)/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent records must expose canonical usage_telemetry without duplicate usageTelemetry",
  );
  assertCheck(
    result,
    "runtime-subagent-record-output-aliases-retired",
    runtimeSubagentProjectionBlock.length > 0 &&
      !runtimeSubagentRecordOutputAliasPattern.test(runtimeSubagentProjectionBlock) &&
      /retiredSubagentRecordOutputAliasKeys/.test(runtimeSubagentSurface) &&
      /withoutRetiredSubagentRecordOutputAliases/.test(runtimeSubagentSurface) &&
      /retiredSubagentRecordOutputAliasKeys/.test(runtimeSubagentSurfaceTest) &&
      /assertCanonicalSubagentRecordOutput/.test(runtimeSubagentSurfaceTest) &&
      /assertCanonicalSubagentRecordOutput\(result\.canceled_subagents\[0\]\)/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent record projections must expose canonical snake_case fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-record-write-output-aliases-retired",
    runtimeSubagentSavedRecordWriteCalls === 6 &&
      runtimeSubagentCanonicalSavedRecordWrites === runtimeSubagentSavedRecordWriteCalls &&
      /assertCanonicalSubagentStoreWrites/.test(runtimeSubagentSurfaceTest) &&
      /assertCanonicalSubagentRecordOutput\(saved\)/.test(runtimeSubagentSurfaceTest) &&
      /"eventId"/.test(runtimeSubagentSurfaceTest) &&
      /"waitedAt"/.test(runtimeSubagentSurfaceTest) &&
      /"assignedAt"/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent lifecycle writes must persist canonical snake_case records without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-list-propagation-envelope-aliases-retired",
    runtimeSubagentListEnvelopeBlock.length > 0 &&
      runtimeSubagentPropagationEnvelopeBlock.length > 0 &&
      !runtimeSubagentListEnvelopeAliasPattern.test(runtimeSubagentListEnvelopeBlock) &&
      !runtimeSubagentPropagationEnvelopeAliasPattern.test(
        runtimeSubagentPropagationEnvelopeBlock,
      ) &&
      /retiredSubagentListEnvelopeAliasKeys/.test(runtimeSubagentSurfaceTest) &&
      /retiredSubagentPropagationEnvelopeAliasKeys/.test(runtimeSubagentSurfaceTest) &&
      /retiredSubagentSkippedRecordAliasKeys/.test(runtimeSubagentSurfaceTest) &&
      /assertNoOwnKeys\(listed,\s*retiredSubagentListEnvelopeAliasKeys\)/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /assertNoOwnKeys\(result,\s*retiredSubagentPropagationEnvelopeAliasKeys\)/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent list and propagation envelopes must expose canonical snake_case fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-list-request-aliases-retired",
    runtimeSubagentListEnvelopeBlock.length > 0 &&
      !runtimeSubagentListRequestAliasReadPattern.test(
        runtimeSubagentListEnvelopeBlock,
      ) &&
      /subagent list ignores retired camelCase request aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /subagentRole: "worker"/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent list filters must ignore retired camelCase request aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-list-lookup-record-aliases-retired",
    runtimeSubagentListEnvelopeBlock.length > 0 &&
      runtimeSubagentGetBlock.length > 0 &&
      !runtimeSubagentListLookupRecordAliasReadPattern.test(
        `${runtimeSubagentListEnvelopeBlock}\n${runtimeSubagentGetBlock}`,
      ) &&
      /subagent list and lookup ignore retired camelCase record aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /parentThreadId: "thread_1"/.test(runtimeSubagentSurfaceTest) &&
      /createdAt: "1999-01-01T00:00:00\.000Z"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /createdAt: "1900-01-01T00:00:00\.000Z"/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent list/get read paths must ignore retired camelCase persisted record aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-propagation-record-aliases-retired",
    runtimeSubagentPropagationEnvelopeBlock.length > 0 &&
      !runtimeSubagentPropagationRecordAliasReadPattern.test(
        runtimeSubagentPropagationEnvelopeBlock,
      ) &&
      /propagates parent cancellation and ignores retired record aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /parentThreadId: "thread_1"/.test(runtimeSubagentSurfaceTest) &&
      /cancellationInheritance: "propagate"/.test(runtimeSubagentSurfaceTest) &&
      /lifecycleStatus: "running"/.test(runtimeSubagentSurfaceTest) &&
      /createdAt: "1900-01-01T00:00:00\.000Z"/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent cancellation propagation must ignore retired camelCase persisted record aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-propagation-request-aliases-retired",
    runtimeSubagentPropagationEnvelopeBlock.length > 0 &&
      !runtimeSubagentPropagationRequestAliasPattern.test(
        runtimeSubagentPropagationEnvelopeBlock,
      ) &&
      /workflowNodeId: "node_parent_cancel_alias"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /hasOwnProperty\.call\(store\.eventInputs\[0\]\.request, "workflowNodeId"\)/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent cancellation propagation must ignore retired camelCase request aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-wait-result-record-aliases-retired",
    runtimeSubagentWaitResultReadBlocks.length > 0 &&
      !runtimeSubagentWaitResultRecordAliasReadPattern.test(
        runtimeSubagentWaitResultReadBlocks,
      ) &&
      /subagent wait and result reads ignore retired camelCase record aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /runId: "run_2"/.test(runtimeSubagentSurfaceTest) &&
      /runId: "run_1"/.test(runtimeSubagentSurfaceTest) &&
      /outputContract: \["MISSING_SECTION"\]/.test(runtimeSubagentSurfaceTest) &&
      /lifecycleStatus: "blocked"/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent wait/result reads must ignore retired camelCase persisted record aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-spawn-request-aliases-retired",
    runtimeSubagentSpawnBlock.length > 0 &&
      !runtimeSubagentSpawnRequestAliasReadPattern.test(
        runtimeSubagentSpawnBlock,
      ) &&
      /subagent spawn ignores retired camelCase request aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /subagentPrompt: "Alias spawn request"/.test(runtimeSubagentSurfaceTest) &&
      /subagentRole: "Reviewer"/.test(runtimeSubagentSurfaceTest) &&
      /toolPack: "alias-tools"/.test(runtimeSubagentSurfaceTest) &&
      /modelRouteId: "route\.spawn\.alias"/.test(runtimeSubagentSurfaceTest) &&
      /outputContract: \["MISSING_SECTION"\]/.test(runtimeSubagentSurfaceTest) &&
      /workflowGraphId: "graph_spawn_alias"/.test(runtimeSubagentSurfaceTest) &&
      /receiptRefs: \["receipt_spawn_alias"\]/.test(runtimeSubagentSurfaceTest) &&
      /policyDecisionRefs: \["policy_spawn_alias"\]/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent spawn must ignore retired camelCase request aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-send-input-record-aliases-retired",
    runtimeSubagentSendInputBlock.length > 0 &&
      !runtimeSubagentSendInputRecordAliasReadPattern.test(
        runtimeSubagentSendInputBlock,
      ) &&
      /subagent send input ignores retired camelCase record aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /lifecycleStatus: "canceled"/.test(runtimeSubagentSurfaceTest) &&
      /runId: "run_2"/.test(runtimeSubagentSurfaceTest) &&
      /agentId: "agent_alias_child"/.test(runtimeSubagentSurfaceTest) &&
      /inputHistory: \[\{ input_id: "input_alias" \}\]/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /previousRunIds: \["run_alias"\]/.test(runtimeSubagentSurfaceTest) &&
      /evidenceRefs: \["evidence_alias"\]/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent send-input lifecycle must ignore retired camelCase persisted record aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-send-input-request-aliases-retired",
    runtimeSubagentSendInputBlock.length > 0 &&
      !runtimeSubagentSendInputRequestAliasReadPattern.test(
        runtimeSubagentSendInputBlock,
      ) &&
      /subagent send input ignores retired camelCase request aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /subagentInput: "Alias-only follow up"/.test(runtimeSubagentSurfaceTest) &&
      /workflowGraphId: "graph_input_alias"/.test(runtimeSubagentSurfaceTest) &&
      /workflowNodeId: "node_input_alias"/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent send-input lifecycle must ignore retired camelCase request aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-resume-record-aliases-retired",
    runtimeSubagentResumeBlock.length > 0 &&
      !runtimeSubagentResumeRecordAliasReadPattern.test(
        runtimeSubagentResumeBlock,
      ) &&
      /subagent resume ignores retired camelCase record aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /runId: "run_2"/.test(runtimeSubagentSurfaceTest) &&
      /lifecycleStatus: "running"/.test(runtimeSubagentSurfaceTest) &&
      /agentId: "agent_alias_resume"/.test(runtimeSubagentSurfaceTest) &&
      /modelRouteId: "route\.resume\.alias"/.test(runtimeSubagentSurfaceTest) &&
      /outputContract: \["MISSING_SECTION"\]/.test(runtimeSubagentSurfaceTest) &&
      /restartCount: 99/.test(runtimeSubagentSurfaceTest) &&
      /resumeHistory: \[\{ resume_id: "resume_alias" \}\]/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /cancellationHistory: \[\{ reason: "alias_cancel" \}\]/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /previousRunIds: \["run_alias"\]/.test(runtimeSubagentSurfaceTest) &&
      /evidenceRefs: \["evidence_resume_alias"\]/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent resume lifecycle must ignore retired camelCase persisted record aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-resume-request-aliases-retired",
    runtimeSubagentResumeBlock.length > 0 &&
      !runtimeSubagentResumeRequestAliasReadPattern.test(
        runtimeSubagentResumeBlock,
      ) &&
      /subagent resume ignores retired camelCase request aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /resumePrompt: "Alias resume prompt"/.test(runtimeSubagentSurfaceTest) &&
      /subagentRole: "AliasRole"/.test(runtimeSubagentSurfaceTest) &&
      /modelRouteId: "route\.resume\.alias"/.test(runtimeSubagentSurfaceTest) &&
      /subagentModelRoute: "route\.resume\.subagent\.alias"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /workflowGraphId: "graph_resume_alias"/.test(runtimeSubagentSurfaceTest) &&
      /workflowNodeId: "node_resume_alias"/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent resume lifecycle must ignore retired camelCase request aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-budget-record-request-aliases-retired",
    runtimeSubagentSendInputBlock.length > 0 &&
      runtimeSubagentResumeBlock.length > 0 &&
      !runtimeSubagentBudgetRecordRequestAliasReadPattern.test(
        `${runtimeSubagentSendInputBlock}\n${runtimeSubagentResumeBlock}`,
      ) &&
      /subagentBudget: \{ max_tokens: 1 \}/.test(runtimeSubagentSurfaceTest) &&
      /assert\.equal\(saved\.budget_status,\s*"within_budget"\)/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent send/resume budget lookup must ignore retired persisted request-budget aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-assign-record-aliases-retired",
    runtimeSubagentAssignBlock.length > 0 &&
      !runtimeSubagentAssignRecordAliasReadPattern.test(
        runtimeSubagentAssignBlock,
      ) &&
      /subagent assign ignores retired camelCase record aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /toolPack: "alias-tools"/.test(runtimeSubagentSurfaceTest) &&
      /modelRouteId: "route\.assign\.alias"/.test(runtimeSubagentSurfaceTest) &&
      /mergePolicy: "alias-merge"/.test(runtimeSubagentSurfaceTest) &&
      /cancellationInheritance: "propagate"/.test(runtimeSubagentSurfaceTest) &&
      /agentId: "agent_alias_assign"/.test(runtimeSubagentSurfaceTest) &&
      /assignmentCount: 99/.test(runtimeSubagentSurfaceTest) &&
      /assignmentHistory: \[\{ assignment_id: "assignment_alias" \}\]/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /runId: "run_2"/.test(runtimeSubagentSurfaceTest) &&
      /outputContract: \["MISSING_SECTION"\]/.test(runtimeSubagentSurfaceTest) &&
      /evidenceRefs: \["evidence_assign_alias"\]/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent assign lifecycle must ignore retired camelCase persisted record aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-assign-request-aliases-retired",
    runtimeSubagentAssignBlock.length > 0 &&
      !runtimeSubagentAssignRequestAliasReadPattern.test(
        runtimeSubagentAssignBlock,
      ) &&
      /subagent assign ignores retired camelCase request aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /subagentRole: "AliasRole"/.test(runtimeSubagentSurfaceTest) &&
      /toolPack: "alias-tools"/.test(runtimeSubagentSurfaceTest) &&
      /subagentToolPack: "subagent-alias-tools"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /modelRouteId: "route\.assign\.alias"/.test(runtimeSubagentSurfaceTest) &&
      /subagentModelRoute: "route\.assign\.subagent\.alias"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /mergePolicy: "alias-merge"/.test(runtimeSubagentSurfaceTest) &&
      /cancellationInheritance: "propagate"/.test(runtimeSubagentSurfaceTest) &&
      /targetAgentId: "agent_alias_assign"/.test(runtimeSubagentSurfaceTest) &&
      /workflowGraphId: "graph_assign_alias"/.test(runtimeSubagentSurfaceTest) &&
      /workflowNodeId: "node_assign_alias"/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent assign lifecycle must ignore retired camelCase request aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-cancel-record-aliases-retired",
    runtimeSubagentCancelBlock.length > 0 &&
      !runtimeSubagentCancelRecordAliasReadPattern.test(
        runtimeSubagentCancelBlock,
      ) &&
      /subagent cancel ignores retired camelCase record aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /lifecycleStatus: "completed"/.test(runtimeSubagentSurfaceTest) &&
      /runId: "run_2"/.test(runtimeSubagentSurfaceTest) &&
      /outputContract: \["MISSING_SECTION"\]/.test(runtimeSubagentSurfaceTest) &&
      /evidenceRefs: \["evidence_cancel_alias"\]/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent cancel lifecycle must ignore retired camelCase persisted record aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-cancel-request-aliases-retired",
    runtimeSubagentCancelBlock.length > 0 &&
      runtimeSubagentPropagationEnvelopeBlock.length > 0 &&
      !runtimeSubagentCancelRequestAliasReadPattern.test(
        `${runtimeSubagentCancelBlock}\n${runtimeSubagentPropagationEnvelopeBlock}`,
      ) &&
      /subagent cancel ignores retired camelCase request aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /cancellationReason: "alias_cancel"/.test(runtimeSubagentSurfaceTest) &&
      /cancellationInherited: true/.test(runtimeSubagentSurfaceTest) &&
      /propagatedFromThreadId: "thread_alias"/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent cancel lifecycle must ignore retired camelCase request aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-nested-helper-output-aliases-retired",
    runtimeSubagentInputRecordBlock.length > 0 &&
      runtimeSubagentResumeRecordBlock.length > 0 &&
      runtimeSubagentAssignmentRecordBlock.length > 0 &&
      runtimeSubagentCancellationObjectBlock.length > 0 &&
      !runtimeSubagentNestedInputAliasPattern.test(runtimeSubagentInputRecordBlock) &&
      !runtimeSubagentNestedResumeAliasPattern.test(runtimeSubagentResumeRecordBlock) &&
      !runtimeSubagentNestedAssignmentAliasPattern.test(
        runtimeSubagentAssignmentRecordBlock,
      ) &&
      !runtimeSubagentNestedCancellationAliasPattern.test(
        runtimeSubagentCancellationObjectBlock,
      ) &&
      /retiredSubagentNestedInputAliasKeys/.test(runtimeSubagentSurfaceTest) &&
      /retiredSubagentNestedResumeAliasKeys/.test(runtimeSubagentSurfaceTest) &&
      /retiredSubagentNestedAssignmentAliasKeys/.test(runtimeSubagentSurfaceTest) &&
      /retiredSubagentNestedCancellationAliasKeys/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /assertNoOwnKeys\(result\.input,\s*retiredSubagentNestedInputAliasKeys\)/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /assertNoOwnKeys\(saved\.resume_history\[0\],\s*retiredSubagentNestedResumeAliasKeys\)/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /assertNoOwnKeys\(saved\.assignment_history\[0\],\s*retiredSubagentNestedAssignmentAliasKeys\)/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /assertNoOwnKeys\(saved\.cancellation,\s*retiredSubagentNestedCancellationAliasKeys\)/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent nested helper objects must expose canonical snake_case fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-error-detail-aliases-retired",
    runtimeSubagentErrorDetailBlocks.length > 0 &&
      runtimeSubagentBudgetErrorDetailBlocks.length === 3 &&
      !runtimeSubagentErrorDetailAliasPattern.test(
        runtimeSubagentErrorDetailBlocks,
      ) &&
      /retiredSubagentErrorDetailAliasKeys/.test(runtimeSubagentSurfaceTest) &&
      /assertNoOwnKeys\(error\.details,\s*retiredSubagentErrorDetailAliasKeys\)/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /error\.details\.thread_id/.test(runtimeSubagentSurfaceTest) &&
      /error\.details\.subagent_id/.test(runtimeSubagentSurfaceTest) &&
      /error\.details\.event_id/.test(runtimeSubagentSurfaceTest) &&
      /error\.details\.receipt_refs/.test(runtimeSubagentSurfaceTest) &&
      /error\.details\.policy_decision_refs/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent error details must expose canonical snake_case fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-lifecycle-result-envelope-aliases-retired",
    runtimeSubagentLifecycleResultEnvelopeBlocks.length > 0 &&
      !runtimeSubagentLifecycleResultEnvelopeAliasPattern.test(
        runtimeSubagentLifecycleResultEnvelopeBlocks,
      ) &&
      /retiredSubagentLifecycleResultEnvelopeAliasKeys/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      (
        runtimeSubagentSurfaceTest.match(
          /assertNoOwnKeys\(result,\s*retiredSubagentLifecycleResultEnvelopeAliasKeys\)/g,
        ) ?? []
      ).length >= 3 &&
      (
        runtimeSubagentSurfaceTest.match(
          /assert\.deepEqual\(result\.receipt_refs,\s*result\.event\.receipt_refs\)/g,
        ) ?? []
      ).length >= 3,
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent lifecycle result envelopes must expose canonical receipt_refs without duplicate receiptRefs aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-post-spawn-lifecycle-staging-aliases-retired",
    runtimeSubagentPostSpawnLifecycleStagingBlocks.length === 5 &&
      !runtimeSubagentRecordOutputAliasPattern.test(
        runtimeSubagentPostSpawnLifecycleStagingBlocks.join("\n"),
      ) &&
      /assertCanonicalPostSpawnSubagentLifecycleStagingRecord/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      (
        runtimeSubagentSurfaceTest.match(
          /assertCanonicalPostSpawnSubagentLifecycleStagingRecord\(store\.eventInputs\[0\]\.record\)/g,
        ) ?? []
      ).length >= 6,
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent post-spawn lifecycle staging records must be canonical before event construction and write filtering",
  );
  assertCheck(
    result,
    "runtime-subagent-spawn-staging-aliases-retired",
    runtimeSubagentSpawnStagingBlock.length > 0 &&
      !runtimeSubagentRecordOutputAliasPattern.test(
        runtimeSubagentSpawnStagingBlock,
      ) &&
      /assertCanonicalSpawnSubagentStagingRecord/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      (
        runtimeSubagentSurfaceTest.match(
          /assertCanonicalSpawnSubagentStagingRecord\(store\.eventInputs\[0\]\.record\)/g,
        ) ?? []
      ).length >= 2,
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent spawn staging records must be canonical before event construction and write filtering",
  );
  assertCheck(
    result,
    "runtime-subagent-control-event-record-aliases-retired",
    runtimeSubagentControlEventBlock.length > 0 &&
      !runtimeSubagentControlEventRecordAliasReadPattern.test(
        runtimeSubagentControlEventBlock,
      ) &&
      /subagent control event ignores retired camelCase record aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /subagentId: "subagent_alias"/.test(runtimeSubagentSurfaceTest) &&
      /workflowGraphId: "graph_alias"/.test(runtimeSubagentSurfaceTest) &&
      /budgetPolicyDecision: \{ id: "policy_alias" \}/.test(
        runtimeSubagentSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent control event construction must ignore retired camelCase record aliases",
  );
  assertCheck(
    result,
    "runtime-subagent-control-event-request-aliases-retired",
    runtimeSubagentControlEventBlock.length > 0 &&
      !runtimeSubagentControlEventRequestAliasReadPattern.test(
        runtimeSubagentControlEventBlock,
      ) &&
      /subagent control event ignores retired camelCase request aliases/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /workflowGraphId: "graph_alias"/.test(runtimeSubagentSurfaceTest) &&
      /workflowNodeId: "node_alias"/.test(runtimeSubagentSurfaceTest) &&
      /receiptRefs: \["receipt_alias"\]/.test(runtimeSubagentSurfaceTest) &&
      /policyDecisionRefs: \["policy_alias"\]/.test(runtimeSubagentSurfaceTest) &&
      /idempotencyKey: "idempotency_alias"/.test(runtimeSubagentSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime subagent control event construction must ignore retired camelCase request aliases",
  );
  assertCheck(
    result,
    "ide-context-budget-usage-request-aliases-retired",
    !/(?:usageTelemetryField|params\.usageTelemetry|params\.runtimeTelemetrySummary|body\.usageTelemetry|runtimeContextBudgetUsageField: "runtimeUsageMeter"|runtimeContextBudgetUsageField: "usageTelemetry"|runtimeContextBudgetUsageField: "runtimeTelemetrySummary")/.test(
      agentIdeContextBudgetControlNodes,
    ) &&
      /usage_telemetry_field/.test(agentIdeContextBudgetControlNodes) &&
      /usage_telemetry:\s*usageTelemetry/.test(agentIdeContextBudgetControlNodes) &&
      /canonicalContextBudgetUsageField/.test(agentIdeContextBudgetControlNodes) &&
      /retiredRuntimeContextBudgetUsageInputAliasKeys/.test(
        agentIdeContextBudgetControlNodesTest,
      ) &&
      /runtime_context_budget helper ignores retired usage input aliases/.test(
        agentIdeContextBudgetControlNodesTest,
      ) &&
      /runtimeContextBudgetUsageField: "usage_telemetry"/.test(
        agentIdeTelemetrySourceBinding,
      ) &&
      /runtimeContextBudgetUsageField: "usage_telemetry"/.test(
        agentIdeTelemetryBudgetChainSubflow,
      ) &&
      !/edge\.(?:fromPort|toPort)\s*===\s*"runtimeUsageMeter"/.test(
        agentIdeTelemetryBudgetChainMaterialization,
      ) &&
      /edge\.fromPort\s*===\s*"usage_telemetry"/.test(
        agentIdeTelemetryBudgetChainMaterialization,
      ) &&
      /edge\.toPort\s*===\s*"usage_telemetry"/.test(
        agentIdeTelemetryBudgetChainMaterialization,
      ) &&
      /usageToContextEdge\?\.fromPort,\s*"usage_telemetry"/.test(
        agentIdeTelemetryBudgetChainMaterializationTest,
      ) &&
      /usageToContextEdge\?\.toPort,\s*"usage_telemetry"/.test(
        agentIdeTelemetryBudgetChainMaterializationTest,
      ),
    [
      "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.test.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.test.ts",
    ],
    "Phase 10/11 is pending: IDE context-budget control nodes must send canonical usage_telemetry without retired usage request aliases",
  );
  assertCheck(
    result,
    "ide-coding-tool-budget-usage-request-output-alias-retired",
    !/^\s*budgetUsageTelemetry:\s*unknown \| null;$/m.test(
      agentIdeCodingToolControlNodes,
    ) &&
      !/^\s*budgetUsageTelemetry,?\s*$/m.test(
        agentIdeCodingToolControlNodes,
      ) &&
      /budget_usage_telemetry:\s*budgetUsageTelemetry/.test(
        agentIdeCodingToolControlNodes,
      ) &&
      /hasOwnProperty\.call\(request\.body,\s*"budgetUsageTelemetry"\)/.test(
        agentIdeCodingToolControlNodesTest,
      ),
    [
      "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.test.ts",
    ],
    "Phase 10/11 is pending: IDE coding-tool control request bodies must emit canonical budget_usage_telemetry without duplicate budgetUsageTelemetry",
  );
  assertCheck(
    result,
    "ide-subagent-budget-usage-request-output-alias-retired",
    !/^\s*budgetUsageTelemetry:\s*unknown \| null;$/m.test(
      agentIdeSubagentControlNodes,
    ) &&
      !/^\s*budgetUsageTelemetry,?\s*$/m.test(
        agentIdeSubagentControlNodes,
      ) &&
      /budget_usage_telemetry:\s*budgetUsageTelemetry/.test(
        agentIdeSubagentControlNodes,
      ) &&
      /hasOwnProperty\.call\(request\.body,\s*"budgetUsageTelemetry"\)/.test(
        agentIdeSubagentControlNodesTest,
      ),
    [
      "packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.test.ts",
    ],
    "Phase 10/11 is pending: IDE subagent control request bodies must emit canonical budget_usage_telemetry without duplicate budgetUsageTelemetry",
  );
  assertCheck(
    result,
    "agent-sdk-runtime-usage-telemetry-identity-route-aliases-retired",
    runtimeUsageSdkTelemetryBlock.length > 0 &&
      /^\s*schema_version\?: "ioi\.runtime\.usage-telemetry\.v1" \| string;/m.test(
        runtimeUsageSdkTelemetryBlock,
      ) &&
      /^\s*thread_id\?: string \| null;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*turn_id\?: string \| null;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*run_id\?: string \| null;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*agent_id\?: string \| null;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*route_id\?: string \| null;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*model_route_id\?: string \| null;/m.test(
        runtimeUsageSdkTelemetryBlock,
      ) &&
      !/^\s*(?:schemaVersion|threadId|turnId|runId|agentId|routeId|modelRouteId)\?:/m.test(
        runtimeUsageSdkTelemetryBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK runtime usage telemetry types must not advertise retired identity/route aliases",
  );
  assertCheck(
    result,
    "agent-sdk-runtime-usage-telemetry-scalar-metric-aliases-retired",
    runtimeUsageSdkTelemetryBlock.length > 0 &&
      /^\s*input_tokens: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*output_tokens: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*reasoning_tokens: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*cached_input_tokens: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*tool_result_tokens: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*compacted_tokens: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*total_tokens: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*estimated_cost_micros: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*estimated_cost_usd\?: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*latency_ms: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      !/^\s*(?:inputTokens|outputTokens|reasoningTokens|cachedInputTokens|toolResultTokens|compactedTokens|totalTokens|estimatedCostMicros|estimatedCostUsd|latencyMs)\?:/m.test(
        runtimeUsageSdkTelemetryBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK runtime usage telemetry types must not advertise retired scalar metric aliases",
  );
  assertCheck(
    result,
    "agent-sdk-runtime-usage-telemetry-context-source-aliases-retired",
    runtimeUsageSdkTelemetryBlock.length > 0 &&
      /^\s*context_window_tokens\?: number;/m.test(
        runtimeUsageSdkTelemetryBlock,
      ) &&
      /^\s*context_used_tokens\?: number;/m.test(
        runtimeUsageSdkTelemetryBlock,
      ) &&
      /^\s*context_pressure\?: number;/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*context_pressure_status\?: "nominal" \| "elevated" \| "high" \| string;/m.test(
        runtimeUsageSdkTelemetryBlock,
      ) &&
      /^\s*source_counts\?: \{ runs\?: number; subagents\?: number; \[key: string\]: unknown \};/m.test(
        runtimeUsageSdkTelemetryBlock,
      ) &&
      /^\s*source_refs\?: string\[\];/m.test(runtimeUsageSdkTelemetryBlock) &&
      /^\s*generated_at\?: string;/m.test(runtimeUsageSdkTelemetryBlock) &&
      !/^\s*(?:contextWindowTokens|contextUsedTokens|contextPressure|contextPressureStatus|sourceCounts|sourceRefs|generatedAt)\?:/m.test(
        runtimeUsageSdkTelemetryBlock,
      ) &&
      !/^\s*\[key: string\]: unknown;/m.test(runtimeUsageSdkTelemetryBlock),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK runtime usage telemetry types must not advertise retired context/source aliases or arbitrary key escape hatches",
  );
  assertCheck(
    result,
    "agent-sdk-runtime-usage-list-aliases-retired",
    runtimeUsageSdkListInputBlock.length > 0 &&
      runtimeUsageSdkListResultBlock.length > 0 &&
      runtimeUsageSdkListQueryBlock.length > 0 &&
      /^\s*group_by\?: "run" \| "thread" \| string;/m.test(
        runtimeUsageSdkListInputBlock,
      ) &&
      /^\s*agent_id\?: string;/m.test(runtimeUsageSdkListInputBlock) &&
      /^\s*schema_version\?: "ioi\.runtime\.usage-telemetry\.v1" \| string;/m.test(
        runtimeUsageSdkListResultBlock,
      ) &&
      /^\s*group_by\?: string;/m.test(runtimeUsageSdkListResultBlock) &&
      /^\s*generated_at\?: string;/m.test(runtimeUsageSdkListResultBlock) &&
      /input\.group_by/.test(runtimeUsageSdkListQueryBlock) &&
      /input\.agent_id/.test(runtimeUsageSdkListQueryBlock) &&
      /params\.set\("group_by",/.test(runtimeUsageSdkListQueryBlock) &&
      /params\.set\("agent_id",/.test(runtimeUsageSdkListQueryBlock) &&
      !/^\s*(?:groupBy|agentId)\?:/m.test(runtimeUsageSdkListInputBlock) &&
      !/^\s*(?:schemaVersion|groupBy|generatedAt)\?:/m.test(
        runtimeUsageSdkListResultBlock,
      ) &&
      !/input\.(?:groupBy|agentId)|params\.set\("agentId"/.test(
        runtimeUsageSdkListQueryBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK runtime usage list request/result types and query helpers must not advertise or emit retired aliases",
  );
  assertCheck(
    result,
    "runtime-task-job-list-request-aliases-retired",
    runtimeTaskSdkListOptionsBlock.length > 0 &&
      runtimeJobSdkListOptionsBlock.length > 0 &&
      runtimeTaskSdkListMethodBlock.length > 0 &&
      runtimeJobSdkListMethodBlock.length > 0 &&
      runtimeTaskJobListJobsBlock.length > 0 &&
      runtimeTaskJobListTasksBlock.length > 0 &&
      /^\s*agent_id\?: string;/m.test(runtimeTaskSdkListOptionsBlock) &&
      /^\s*agent_id\?: string;/m.test(runtimeJobSdkListOptionsBlock) &&
      /options\.agent_id/.test(runtimeTaskSdkListMethodBlock) &&
      /options\.agent_id/.test(runtimeJobSdkListMethodBlock) &&
      /params\.set\("agent_id",/.test(runtimeTaskSdkListMethodBlock) &&
      /params\.set\("agent_id",/.test(runtimeJobSdkListMethodBlock) &&
      /options\.agent_id/.test(runtimeTaskJobListJobsBlock) &&
      /options\.agent_id/.test(runtimeTaskJobListTasksBlock) &&
      /legacy-agent/.test(runtimeTaskJobSurfaceTest) &&
      !/^\s*agentId\?: string;/m.test(runtimeTaskSdkListOptionsBlock) &&
      !/^\s*agentId\?: string;/m.test(runtimeJobSdkListOptionsBlock) &&
      !/options\.agentId|params\.set\("agentId"/.test(runtimeTaskSdkListMethodBlock) &&
      !/options\.agentId|params\.set\("agentId"/.test(runtimeJobSdkListMethodBlock) &&
      !/options\.agentId/.test(runtimeTaskJobListJobsBlock) &&
      !/options\.agentId/.test(runtimeTaskJobListTasksBlock),
    [
      "packages/agent-sdk/src/substrate-client.ts",
      "packages/runtime-daemon/src/runtime-task-job-surface.mjs",
      "packages/runtime-daemon/src/runtime-task-job-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime task/job list request types, query helpers, and daemon list surfaces must not advertise or read retired agentId aliases",
  );
  assertCheck(
    result,
    "runtime-task-create-request-aliases-retired",
    runtimeTaskSdkCreateOptionsBlock.length > 0 &&
      runtimeTaskJobCreateTaskBlock.length > 0 &&
      /^\s*agent_id\?: string;/m.test(runtimeTaskSdkCreateOptionsBlock) &&
      /^\s*agent_options\?: Record<string, unknown>;/m.test(
        runtimeTaskSdkCreateOptionsBlock,
      ) &&
      /^\s*cwd\?: string;/m.test(runtimeTaskSdkCreateOptionsBlock) &&
      /^\s*prompt\?: string;/m.test(runtimeTaskSdkCreateOptionsBlock) &&
      /body\.agent_id/.test(runtimeTaskJobCreateTaskBlock) &&
      /body\.agent_options/.test(runtimeTaskJobCreateTaskBlock) &&
      /body\.cwd/.test(runtimeTaskJobCreateTaskBlock) &&
      /prompt: body\.prompt \?\? ""/.test(runtimeTaskJobCreateTaskBlock) &&
      /legacy-agent/.test(runtimeTaskJobSurfaceTest) &&
      /route\.legacy-options/.test(runtimeTaskJobSurfaceTest) &&
      /Retired objective ignored/.test(runtimeTaskJobSurfaceTest) &&
      /Retired goal ignored/.test(runtimeTaskJobSurfaceTest) &&
      !/^\s*(?:agentId|agentOptions|workspace)\?:/m.test(
        runtimeTaskSdkCreateOptionsBlock,
      ) &&
      !/^\s*(?:objective|goal)\?: string;/m.test(
        runtimeTaskSdkCreateOptionsBlock,
      ) &&
      !/^\s*\[key: string\]: unknown;/m.test(runtimeTaskSdkCreateOptionsBlock) &&
      !/body\.(?:agentId|agentOptions|workspace|objective|goal)/.test(
        runtimeTaskJobCreateTaskBlock,
      ) &&
      !/\.\.\.body/.test(runtimeTaskJobCreateTaskBlock),
    [
      "packages/agent-sdk/src/substrate-client.ts",
      "packages/runtime-daemon/src/runtime-task-job-surface.mjs",
      "packages/runtime-daemon/src/runtime-task-job-surface.test.mjs",
    ],
    "Phase 10/11 is pending: runtime task create request types and daemon create surfaces must not advertise, read, or forward retired identity/options/workspace/prompt aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-output-contract-status-aliases-retired",
    runtimeSubagentSdkOutputContractStatusBlock.length > 0 &&
      /^\s*schema_version\?: string;/m.test(
        runtimeSubagentSdkOutputContractStatusBlock,
      ) &&
      /^\s*required_sections\?: string\[\];/m.test(
        runtimeSubagentSdkOutputContractStatusBlock,
      ) &&
      /^\s*present_sections\?: string\[\];/m.test(
        runtimeSubagentSdkOutputContractStatusBlock,
      ) &&
      /^\s*missing_sections\?: string\[\];/m.test(
        runtimeSubagentSdkOutputContractStatusBlock,
      ) &&
      /^\s*validated_at\?: string;/m.test(
        runtimeSubagentSdkOutputContractStatusBlock,
      ) &&
      !/^\s*(?:schemaVersion|requiredSections|presentSections|missingSections|validatedAt)\?:/m.test(
        runtimeSubagentSdkOutputContractStatusBlock,
      ) &&
      !/^\s*\[key: string\]: unknown;/m.test(
        runtimeSubagentSdkOutputContractStatusBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent output-contract status type must not advertise retired camelCase aliases or arbitrary-key escape hatches",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-usage-telemetry-aliases-retired",
    runtimeSubagentSdkUsageTelemetryBlock.length > 0 &&
      /^\s*schema_version\?: string;/m.test(runtimeSubagentSdkUsageTelemetryBlock) &&
      /^\s*input_tokens\?: number;/m.test(runtimeSubagentSdkUsageTelemetryBlock) &&
      /^\s*output_tokens\?: number;/m.test(runtimeSubagentSdkUsageTelemetryBlock) &&
      /^\s*total_tokens\?: number;/m.test(runtimeSubagentSdkUsageTelemetryBlock) &&
      /^\s*cumulative_input_tokens\?: number;/m.test(
        runtimeSubagentSdkUsageTelemetryBlock,
      ) &&
      /^\s*cumulative_output_tokens\?: number;/m.test(
        runtimeSubagentSdkUsageTelemetryBlock,
      ) &&
      /^\s*cumulative_total_tokens\?: number;/m.test(
        runtimeSubagentSdkUsageTelemetryBlock,
      ) &&
      /^\s*cost_estimate_usd\?: number;/m.test(
        runtimeSubagentSdkUsageTelemetryBlock,
      ) &&
      /^\s*cumulative_cost_estimate_usd\?: number;/m.test(
        runtimeSubagentSdkUsageTelemetryBlock,
      ) &&
      /^\s*model_route_id\?: string \| null;/m.test(
        runtimeSubagentSdkUsageTelemetryBlock,
      ) &&
      !/^\s*(?:schemaVersion|inputTokens|outputTokens|totalTokens|cumulativeInputTokens|cumulativeOutputTokens|cumulativeTotalTokens|costEstimateUsd|cumulativeCostEstimateUsd|modelRouteId)\?:/m.test(
        runtimeSubagentSdkUsageTelemetryBlock,
      ) &&
      !/^\s*\[key: string\]: unknown;/m.test(
        runtimeSubagentSdkUsageTelemetryBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent usage telemetry type must not advertise retired camelCase aliases or arbitrary-key escape hatches",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-budget-request-type-alias-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      /^\s*budget\?: Record<string, unknown>;/m.test(
        runtimeSubagentSdkControlInputBlock,
      ) &&
      !/^\s*subagentBudget\?:/m.test(runtimeSubagentSdkControlInputBlock),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise the retired subagentBudget alias",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-role-request-type-alias-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      runtimeSubagentSdkListInputBlock.length > 0 &&
      /^\s*role\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      /^\s*subagent_role\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      /^\s*role\?: string;/m.test(runtimeSubagentSdkListInputBlock) &&
      /^\s*subagent_role\?: string;/m.test(runtimeSubagentSdkListInputBlock) &&
      !/^\s*subagentRole\?:/m.test(
        `${runtimeSubagentSdkControlInputBlock}\n${runtimeSubagentSdkListInputBlock}`,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent request types must not advertise the retired subagentRole alias",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-tool-pack-request-type-aliases-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      /^\s*tool_pack\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      !/^\s*(?:toolPack|subagentToolPack)\?:/m.test(
        runtimeSubagentSdkControlInputBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired toolPack/subagentToolPack aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-model-route-request-type-aliases-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      /^\s*model_route_id\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      !/^\s*(?:modelRouteId|subagentModelRoute)\?:/m.test(
        runtimeSubagentSdkControlInputBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired modelRouteId/subagentModelRoute aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-concurrency-request-type-aliases-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      /^\s*max_concurrency\?: number;/m.test(runtimeSubagentSdkControlInputBlock) &&
      !/^\s*(?:maxConcurrency|subagentMaxConcurrency)\?:/m.test(
        runtimeSubagentSdkControlInputBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired maxConcurrency/subagentMaxConcurrency aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-output-contract-request-type-aliases-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      /^\s*output_contract\?: string\[\] \| Record<string, unknown>;/m.test(
        runtimeSubagentSdkControlInputBlock,
      ) &&
      !/^\s*(?:outputContract|subagentOutputContract)\?:/m.test(
        runtimeSubagentSdkControlInputBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired outputContract/subagentOutputContract aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-policy-request-type-aliases-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      /^\s*merge_policy\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      /^\s*cancellation_inheritance\?: "propagate" \| "isolated" \| string;/m.test(
        runtimeSubagentSdkControlInputBlock,
      ) &&
      !/^\s*(?:mergePolicy|cancellationInheritance)\?:/m.test(
        runtimeSubagentSdkControlInputBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired mergePolicy/cancellationInheritance aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-cancellation-metadata-request-type-aliases-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      /^\s*cancellation_reason\?: string;/m.test(
        runtimeSubagentSdkControlInputBlock,
      ) &&
      /^\s*inherited\?: boolean;/m.test(runtimeSubagentSdkControlInputBlock) &&
      /^\s*cancellation_inherited\?: boolean;/m.test(
        runtimeSubagentSdkControlInputBlock,
      ) &&
      /^\s*propagated_from_thread_id\?: string;/m.test(
        runtimeSubagentSdkControlInputBlock,
      ) &&
      !/^\s*(?:cancellationReason|cancellationInherited|propagatedFromThreadId)\?:/m.test(
        runtimeSubagentSdkControlInputBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired cancellation metadata aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-context-routing-request-type-aliases-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      /^\s*fork_context\?: boolean;/m.test(runtimeSubagentSdkControlInputBlock) &&
      /^\s*parent_turn_id\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      /^\s*turn_id\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      /^\s*target_agent_id\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      !/^\s*(?:forkContext|parentTurnId|turnId|targetAgentId)\?:/m.test(
        runtimeSubagentSdkControlInputBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired context routing aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-workflow-request-type-aliases-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      /^\s*workflow_graph_id\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      /^\s*workflow_node_id\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      /^\s*idempotency_key\?: string;/m.test(runtimeSubagentSdkControlInputBlock) &&
      !/^\s*(?:workflowGraphId|workflowNodeId|idempotencyKey)\?:/m.test(
        runtimeSubagentSdkControlInputBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired workflow/idempotency aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-request-type-escape-hatches-retired",
    runtimeSubagentSdkControlInputBlock.length > 0 &&
      runtimeSubagentSdkListInputBlock.length > 0 &&
      !/^\s*\[key: string\]: unknown;/m.test(
        `${runtimeSubagentSdkControlInputBlock}\n${runtimeSubagentSdkListInputBlock}`,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent request types must not retain arbitrary key escape hatches",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-record-identity-output-aliases-retired",
    runtimeSubagentSdkRecordBlock.length > 0 &&
      /^\s*schema_version\?: string;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*subagent_id\?: string;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*agent_id\?: string;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*child_thread_id\?: string;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*run_id\?: string;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*parent_thread_id\?: string;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*parent_agent_id\?: string;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*parent_turn_id\?: string \| null;/m.test(runtimeSubagentSdkRecordBlock) &&
      !/^\s*(?:schemaVersion|subagentId|agentId|childThreadId|runId|parentThreadId|parentAgentId|parentTurnId)\?:/m.test(
        runtimeSubagentSdkRecordBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent record types must not advertise retired identity output aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-record-route-output-aliases-retired",
    runtimeSubagentSdkRecordBlock.length > 0 &&
      /^\s*tool_pack\?: string \| null;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*model_route_id\?: string \| null;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*workflow_graph_id\?: string \| null;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*workflow_node_id\?: string \| null;/m.test(runtimeSubagentSdkRecordBlock) &&
      !/^\s*(?:toolPack|modelRouteId|workflowGraphId|workflowNodeId)\?:/m.test(
        runtimeSubagentSdkRecordBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent record types must not advertise retired route/workflow output aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-record-lifecycle-output-aliases-retired",
    runtimeSubagentSdkRecordBlock.length > 0 &&
      /^\s*lifecycle_status\?: RuntimeSubagentLifecycleStatus;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      /^\s*restart_status\?: string \| null;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*restart_count\?: number;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*input_count\?: number;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*assignment_count\?: number;/m.test(runtimeSubagentSdkRecordBlock) &&
      !/^\s*(?:lifecycleStatus|restartStatus|restartCount|inputCount|assignmentCount)\?:/m.test(
        runtimeSubagentSdkRecordBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent record types must not advertise retired lifecycle/count output aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-record-cancellation-output-aliases-retired",
    runtimeSubagentSdkRecordBlock.length > 0 &&
      /^\s*cancellation_inheritance\?: string \| null;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      /^\s*cancellation_reason\?: string \| null;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      /^\s*cancellation_inherited\?: boolean \| null;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      /^\s*propagated_from_thread_id\?: string \| null;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      !/^\s*(?:cancellationInheritance|cancellationReason|cancellationInherited|propagatedFromThreadId)\?:/m.test(
        runtimeSubagentSdkRecordBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent record types must not advertise retired cancellation metadata output aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-record-status-output-aliases-retired",
    runtimeSubagentSdkRecordBlock.length > 0 &&
      /^\s*output_contract_status\?: string \| null;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      /^\s*budget_status\?: string \| null;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      !/^\s*(?:outputContractStatus|budgetStatus)\?:/m.test(
        runtimeSubagentSdkRecordBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent record types must not advertise retired output/budget status aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-record-telemetry-estimate-output-aliases-retired",
    runtimeSubagentSdkRecordBlock.length > 0 &&
      /^\s*usage_telemetry\?: RuntimeSubagentUsageTelemetry \| null;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      /^\s*cost_estimate_usd\?: number \| null;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      /^\s*token_estimate\?: number \| null;/m.test(
        runtimeSubagentSdkRecordBlock,
      ) &&
      !/^\s*(?:usageTelemetry|costEstimateUsd|tokenEstimate)\?:/m.test(
        runtimeSubagentSdkRecordBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent record types must not advertise retired telemetry/estimate output aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-record-ref-output-aliases-retired",
    runtimeSubagentSdkRecordBlock.length > 0 &&
      /^\s*receipt_refs\?: string\[\];/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*evidence_refs\?: string\[\];/m.test(runtimeSubagentSdkRecordBlock) &&
      !/^\s*(?:receiptRefs|evidenceRefs)\?:/m.test(
        runtimeSubagentSdkRecordBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent record types must not advertise retired receipt/evidence ref output aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-record-timestamp-output-aliases-retired",
    runtimeSubagentSdkRecordBlock.length > 0 &&
      /^\s*created_at\?: string;/m.test(runtimeSubagentSdkRecordBlock) &&
      /^\s*updated_at\?: string;/m.test(runtimeSubagentSdkRecordBlock) &&
      !/^\s*(?:createdAt|updatedAt)\?:/m.test(runtimeSubagentSdkRecordBlock),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent record types must not advertise retired timestamp output aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-record-escape-hatch-retired",
    runtimeSubagentSdkRecordBlock.length > 0 &&
      !/^\s*\[key: string\]: unknown;/m.test(runtimeSubagentSdkRecordBlock),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent record types must not retain arbitrary key escape hatches",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-list-result-aliases-retired",
    runtimeSubagentSdkListResultBlock.length > 0 &&
      /^\s*schema_version\?: string;/m.test(runtimeSubagentSdkListResultBlock) &&
      /^\s*thread_id\?: string;/m.test(runtimeSubagentSdkListResultBlock) &&
      /^\s*parent_agent_id\?: string;/m.test(runtimeSubagentSdkListResultBlock) &&
      /^\s*active_count\?: number;/m.test(runtimeSubagentSdkListResultBlock) &&
      !/^\s*(?:schemaVersion|threadId|parentAgentId|activeCount)\?:/m.test(
        runtimeSubagentSdkListResultBlock,
      ) &&
      !/^\s*\[key: string\]: unknown;/m.test(runtimeSubagentSdkListResultBlock),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent list result types must not advertise retired camelCase aliases or arbitrary key escape hatches",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-result-identity-lifecycle-aliases-retired",
    runtimeSubagentSdkResultBlock.length > 0 &&
      /^\s*schema_version\?: string;/m.test(runtimeSubagentSdkResultBlock) &&
      /^\s*subagent_id\?: string \| null;/m.test(runtimeSubagentSdkResultBlock) &&
      /^\s*agent_id\?: string \| null;/m.test(runtimeSubagentSdkResultBlock) &&
      /^\s*run_id\?: string \| null;/m.test(runtimeSubagentSdkResultBlock) &&
      /^\s*lifecycle_status\?: RuntimeSubagentLifecycleStatus \| null;/m.test(
        runtimeSubagentSdkResultBlock,
      ) &&
      !/^\s*(?:schemaVersion|subagentId|agentId|runId|lifecycleStatus)\?:/m.test(
        runtimeSubagentSdkResultBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent result types must not advertise retired identity/lifecycle aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-result-status-telemetry-aliases-retired",
    runtimeSubagentSdkResultBlock.length > 0 &&
      /^\s*output_contract_status\?: string \| null;/m.test(
        runtimeSubagentSdkResultBlock,
      ) &&
      /^\s*budget_status\?: string \| null;/m.test(
        runtimeSubagentSdkResultBlock,
      ) &&
      /^\s*usage_telemetry\?: RuntimeSubagentUsageTelemetry \| null;/m.test(
        runtimeSubagentSdkResultBlock,
      ) &&
      /^\s*cost_estimate_usd\?: number \| null;/m.test(
        runtimeSubagentSdkResultBlock,
      ) &&
      /^\s*token_estimate\?: number \| null;/m.test(
        runtimeSubagentSdkResultBlock,
      ) &&
      !/^\s*(?:outputContractStatus|budgetStatus|usageTelemetry|costEstimateUsd|tokenEstimate)\?:/m.test(
        runtimeSubagentSdkResultBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent result types must not advertise retired status/telemetry aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-result-ref-escape-aliases-retired",
    runtimeSubagentSdkResultBlock.length > 0 &&
      /^\s*receipt_refs\?: string\[\];/m.test(runtimeSubagentSdkResultBlock) &&
      !/^\s*receiptRefs\?:/m.test(runtimeSubagentSdkResultBlock) &&
      !/^\s*\[key: string\]: unknown;/m.test(runtimeSubagentSdkResultBlock),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent result types must not advertise retired receipt ref aliases or arbitrary key escape hatches",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-cancellation-propagation-result-scalar-aliases-retired",
    runtimeSubagentSdkCancellationPropagationResultBlock.length > 0 &&
      /^\s*schema_version\?: string;/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      /^\s*thread_id\?: string;/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      /^\s*parent_agent_id\?: string;/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      /^\s*propagation_policy\?: string;/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      /^\s*candidate_count\?: number;/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      /^\s*canceled_count\?: number;/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      /^\s*skipped_count\?: number;/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      !/^\s*(?:schemaVersion|threadId|parentAgentId|propagationPolicy|candidateCount|canceledCount|skippedCount)\?:/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent cancellation propagation result types must not advertise retired scalar aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-cancellation-propagation-result-collection-aliases-retired",
    runtimeSubagentSdkCancellationPropagationResultBlock.length > 0 &&
      /^\s*canceled_subagents\?: RuntimeSubagentRecord\[\];/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      /^\s*skipped_subagents\?: RuntimeSubagentRecord\[\];/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      /^\s*event_refs\?: string\[\];/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      /^\s*receipt_refs\?: string\[\];/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      !/^\s*(?:canceledSubagents|skippedSubagents|eventRefs|receiptRefs)\?:/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ) &&
      !/^\s*\[key: string\]: unknown;/m.test(
        runtimeSubagentSdkCancellationPropagationResultBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent cancellation propagation result types must not advertise retired collection/ref aliases or arbitrary key escape hatches",
  );
  assertCheck(
    result,
    "agent-sdk-runtime-event-dead-mock-helpers-retired",
    /runtimeThreadEventFromEnvelope/.test(agentSdkRuntimeEvents) &&
      !/mockRuntime(?:CursorSeq|EnvelopeForSdkEvent|EventEnvelope)|runtimePayloadStringRecord|runtimeEventKindForSdkMessage|runtimeEventStatusForSdkMessage|componentKindForSdkMessage|workflowNodeIdForSdkMessage|sourceEventKindForSdkMessage|payloadSchemaVersionForSdkMessage|turnIdForRun|eventStreamIdForThread|runtimeTurnStatusForRun|\(event as \{ id\?: string \}\)\.id/.test(
        agentSdkRuntimeEvents,
      ),
    ["packages/agent-sdk/src/runtime-events.ts"],
    "Phase 10/11 is pending: SDK runtime event projection must not retain dead mock-envelope helpers or noncanonical event.id cursor fallback",
  );
  assertCheck(
    result,
    "runtime-event-envelope-compat-aliases-retired",
    !/\bid:\s*String\(seq\)|timestamp_ms:|event:\s*eventKind/.test(runtimeEventEnvelopes) &&
      /retiredEnvelopeAliasKeys/.test(runtimeEventEnvelopesTest) &&
      /event\.event_id\s*\?\?\s*event\.seq/.test(runtimeHttpUtils) &&
      !/event\.id\s*\?\?\s*event\.seq/.test(runtimeHttpUtils) &&
      /writeSse uses canonical runtime event ids/.test(runtimeHttpUtilsTest) &&
      /event\.event_id === lastEventId/.test(threadReplay) &&
      !/event\.id === lastEventId/.test(threadReplay),
    [
      "packages/runtime-daemon/src/runtime-event-envelopes.mjs",
      "packages/runtime-daemon/src/runtime-event-envelopes.test.mjs",
      "packages/runtime-daemon/src/runtime-http-utils.mjs",
      "packages/runtime-daemon/src/runtime-http-utils.test.mjs",
      "packages/runtime-daemon/src/threads/thread-replay.mjs",
    ],
    "Phase 10/11 is pending: daemon runtime event envelopes must not emit legacy id/event/timestamp aliases, and SSE/cursors must use canonical event_id",
  );
  assertCheck(
    result,
    "runtime-mcp-event-id-alias-retired",
    /event_id:\s*invocation\.event\?\.event_id\s*\?\?\s*null/.test(runtimeMcpHelpers) &&
      !/event_id:\s*invocation\.event\?\.event_id\s*\?\?\s*invocation\.event\?\.id/.test(
        runtimeMcpHelpers,
      ) &&
      /retiredAlias\.structuredContent\.event_id,\s*null/.test(runtimeMcpHelpersTest),
    [
      "packages/runtime-daemon/src/runtime-mcp-helpers.mjs",
      "packages/runtime-daemon/src/runtime-mcp-helpers.test.mjs",
    ],
    "Phase 10/11 is pending: MCP serve result projection must use canonical runtime event_id and ignore retired event.id aliases",
  );
  assertCheck(
    result,
    "ide-terminal-run-launch-event-id-alias-retired",
    /cleanString\(event\.event_id\)\s*\?\?\s*cleanString\(resultObject\?\.event_id\)/.test(
      agentIdeTerminalRunLaunch,
    ) &&
      !/cleanString\(event\.id\)|resultObject\?\.eventId/.test(agentIdeTerminalRunLaunch) &&
      /legacy-nested-event-id/.test(agentIdeTerminalRunLaunchTest) &&
      /runtimeThreadEvents\?\s*\.length,\s*0/.test(agentIdeTerminalRunLaunchTest),
    [
      "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.test.ts",
    ],
    "Phase 10/11 is pending: IDE terminal coding-loop run launch must ignore retired runtime event id aliases",
  );
  assertCheck(
    result,
    "ide-computer-use-replay-event-id-alias-retired",
    /function eventIdForEvent\(event: RuntimeEventInput\): string \| null \{\s*return stringField\(event, "event_id"\);\s*\}/.test(
      agentIdeComputerUseReplayTimeline,
    ) &&
      !/return stringField\(event,\s*"event_id",\s*"eventId",\s*"id"\)/.test(
        agentIdeComputerUseReplayTimeline,
      ) &&
      /legacy-only-computer-use-event/.test(computerUseReplayTimelineProof) &&
      /legacyAliasTimeline\.frames\[0\]\?\.eventId,\s*null/.test(
        computerUseReplayTimelineProof,
      ),
    [
      "packages/agent-ide/src/runtime/workflow-computer-use-replay-timeline.ts",
      "scripts/lib/workflow-computer-use-replay-timeline-proof.mjs",
    ],
    "Phase 10/11 is pending: IDE computer-use replay timeline must ignore retired runtime event id aliases",
  );
  assertCheck(
    result,
    "ide-runtime-event-identity-helper-alias-retired",
    /workflowRuntimeEventId/.test(agentIdeEventIdentity) &&
      /isProjectedRuntimeThreadEvent/.test(agentIdeEventIdentity) &&
      !/"eventId",\s*"id"|"eventKind",\s*"event_kind",\s*"event"/.test(
        agentIdeEventIdentity,
      ) &&
      /workflow runtime event identity ignores raw retired aliases/.test(
        agentIdeEventIdentityTest,
      ) &&
      /workflowRuntimeEventId\(event\)/.test(agentIdeMixedRuntimePanels) &&
      /workflowRuntimeEventKind\(event\)/.test(agentIdeMixedRuntimePanels) &&
      !/stringField\(event,\s*"event_id",\s*"eventId",\s*"id"\)|stringField\(event,\s*"eventKind",\s*"event_kind",\s*"event"\)/.test(
        agentIdeMixedRuntimePanels,
      ),
    [
      "packages/agent-ide/src/runtime/workflow-runtime-event-identity.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-event-identity.test.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-goal-verification-panel.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-policy-lease-panel.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-receipt-first-tool-timeline.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-delegation-matrix.ts",
    ],
    "Phase 10/11 is pending: mixed IDE runtime panels must share canonical event identity handling and ignore raw retired id/event aliases",
  );
  assertCheck(
    result,
    "ide-typed-runtime-panels-event-identity-helper",
    /workflowRuntimeEventId/.test(agentIdeTypedRuntimePanels) &&
      /workflowRuntimeEventKind/.test(agentIdeTypedRuntimePanels) &&
      !/stringField\(event,\s*"event_id",\s*"id"\)|cleanString\(event\.id\)\s*\?\?\s*stringField\(event,\s*"event_id",\s*"eventId"\)/.test(
        agentIdeTypedRuntimePanels,
      ),
    [
      "packages/agent-ide/src/runtime/workflow-workspace-trust-gate.ts",
      "packages/agent-ide/src/runtime/workflow-hunk-decision-receipt-panel.ts",
      "packages/agent-ide/src/runtime/workflow-signed-replay-notebook.ts",
      "packages/agent-ide/src/runtime/workflow-context-lifecycle-panel.ts",
      "packages/agent-ide/src/runtime/workflow-worker-contribution-trace.ts",
    ],
    "Phase 10/11 is pending: typed IDE runtime panels must use the shared event identity helper instead of local id fallbacks",
  );
  return result;
}

function runNegative() {
  const result = createTierResult("negative");
  const testFiles = [
    ...collectFiles("scripts/lib", (file) => /\.(test\.)?mjs$/.test(file)),
    ...collectFiles("crates/services/src/agentic/runtime", (file) => file.endsWith(".rs")),
  ];
  const corpus = testFiles.map((file) => read(file)).join("\n");
  for (const negativeCase of REQUIRED_NEGATIVE_CASES) {
    const probe = negativeCase
      .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
      .replace(/\s+/g, "[\\s_-]+");
    assertCheck(
      result,
      `negative-case:${negativeCase}`,
      new RegExp(probe, "i").test(corpus),
      ["scripts/lib", "crates/services/src/agentic/runtime"],
      `Phase 11 is pending: add executable negative conformance for "${negativeCase}"`,
    );
  }
  return result;
}

function runTier(tier) {
  switch (tier) {
    case "docs":
      return runDocs();
    case "abi":
      return runAbi();
    case "bridge":
      return runBridge();
    case "receipts":
      return runReceipts();
    case "ctee":
      return runCtee();
    case "compositor":
      return runCompositor();
    case "negative":
      return runNegative();
    default:
      throw new Error(`Unknown hypervisor conformance tier: ${tier}`);
  }
}

function printResult(result) {
  for (const check of result.checks) {
    console.log(`${check.status === "passed" ? "pass" : "fail"} ${result.tier}:${check.id}`);
    if (check.status !== "passed") {
      console.log(`  ${check.message}`);
      for (const evidence of check.evidence ?? []) {
        console.log(`  evidence: ${evidence}`);
      }
    }
  }
}

function main() {
  const requested = process.argv[2] ?? "all";
  if (requested === "--list" || requested === "list") {
    for (const command of COMMANDS) console.log(command);
    return;
  }
  const tiers = requested === "all" ? TIERS : [requested];
  for (const tier of tiers) {
    if (!TIERS.includes(tier)) {
      console.error(`Unknown hypervisor conformance tier "${tier}". Expected one of: all, ${TIERS.join(", ")}`);
      process.exit(2);
    }
  }

  const results = tiers.map((tier) => runTier(tier));
  for (const result of results) printResult(result);

  const failed = results.flatMap((result) => result.failures);
  const summary = {
    schemaVersion: "ioi.hypervisor.conformance.v1",
    generatedAt: new Date().toISOString(),
    tier: requested,
    status: failed.length === 0 ? "passed" : "failed",
    checks: results.flatMap((result) => result.checks.map((check) => ({ tier: result.tier, ...check }))),
  };
  const summaryPath = "docs/evidence/hypervisor-conformance/latest-summary.json";
  fs.mkdirSync(path.dirname(absolutePath(summaryPath)), { recursive: true });
  fs.writeFileSync(absolutePath(summaryPath), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`Evidence: ${summaryPath}`);

  if (failed.length > 0) {
    console.error(`hypervisor-conformance ${requested} failed with ${failed.length} failed check(s).`);
    process.exit(1);
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
