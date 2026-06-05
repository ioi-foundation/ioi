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
  const modelRouteSelectionDetailsObject =
    modelRoutes.match(/const payload = \{[\s\S]*?details: \{([\s\S]*?)\n    \},\n  \};/)?.[1] ?? "";
  const modelRouteDecisionModule = exists("packages/runtime-daemon/src/model-mounting/route-decision.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/route-decision.mjs")
    : "";
  const modelRouteDecisionObject =
    modelRouteDecisionModule.match(/const decision = \{[\s\S]*?\n  \};/)?.[0] ?? "";
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
  const modelInvocationOpsTest = exists("packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs")
    : "";
  const modelInvocationReceiptDetailsObject =
    modelInvocationOps.match(/const details = \{[\s\S]*?\n  \};/)?.[0] ?? "";
  const modelMountingValidation = exists("packages/runtime-daemon/src/model-mounting/validation.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/validation.mjs")
    : "";
  const modelMountingValidationTest = exists("packages/runtime-daemon/src/model-mounting/validation.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/validation.test.mjs")
    : "";
  const modelReceiptGateStart = modelMountingValidation.indexOf("export function validateReceiptGate");
  const modelReceiptGateEnd =
    modelReceiptGateStart >= 0
      ? modelMountingValidation.indexOf("\nexport function ", modelReceiptGateStart + 1)
      : -1;
  const modelReceiptGateValidation =
    modelReceiptGateStart >= 0
      ? modelMountingValidation.slice(
          modelReceiptGateStart,
          modelReceiptGateEnd >= 0 ? modelReceiptGateEnd : undefined,
        )
      : "";
  const modelConversationOps = exists("packages/runtime-daemon/src/model-mounting/conversation-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/conversation-operations.mjs")
    : "";
  const modelConversationOpsTest = exists("packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs")
    : "";
  const modelConversationStateRecordObject =
    modelConversationOps.match(/const record = \{[\s\S]*?\n  \};/)?.[0] ?? "";
  const modelStreamCompletionReceiptDetailsObject =
    modelConversationOps.match(/const receiptDetails = \{[\s\S]*?\n  \};/)?.[0] ?? "";
  const modelSchemaRelations = exists("packages/runtime-daemon/src/model-mounting/schema-relations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/schema-relations.mjs")
    : "";
  const modelConversationSchemaRelations =
    modelSchemaRelations.match(/modelConversationStates: \[[\s\S]*?\]/)?.[0] ?? "";
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
  const runtimeRecordProjections = exists("packages/runtime-daemon/src/runtime-record-projections.mjs")
    ? read("packages/runtime-daemon/src/runtime-record-projections.mjs")
    : "";
  const threadTurnProjection = exists("packages/runtime-daemon/src/threads/thread-turn-projection.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-turn-projection.mjs")
    : "";
  const agentTuiCli = exists("crates/cli/src/commands/agent_tui.rs")
    ? read("crates/cli/src/commands/agent_tui.rs")
    : "";
  const agentgresAdmissionCoreForBridge = exists("crates/services/src/agentic/runtime/kernel/agentgres_admission.rs")
    ? read("crates/services/src/agentic/runtime/kernel/agentgres_admission.rs")
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
  const modelRouteSelectionTest = exists("packages/runtime-daemon/src/threads/model-route-selection.test.mjs")
    ? read("packages/runtime-daemon/src/threads/model-route-selection.test.mjs")
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
  const agentSdkModelRouteDecisionType =
    agentSdkMessages.match(/export interface ModelRouteDecision \{[\s\S]*?\n}\n/)?.[0] ?? "";
  const agentSdkOptions = exists("packages/agent-sdk/src/options.ts")
    ? read("packages/agent-sdk/src/options.ts")
    : "";
  const agentSdkModelMounts = exists("packages/agent-sdk/src/model-mounts.ts")
    ? read("packages/agent-sdk/src/model-mounts.ts")
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
  const openAiCompatRoutesTest = exists("packages/runtime-daemon/src/openai-compat-routes.test.mjs")
    ? read("packages/runtime-daemon/src/openai-compat-routes.test.mjs")
    : "";
  const modelStreamCancelDetailsObject =
    openAiCompatRoutes.match(/details: \{\n {6}stream_kind[\s\S]*?\n {4}\},/)?.[0] ?? "";
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
    "model-mount-route-decision-fallback-aliases-retired",
    /fallback_allowed:\s*Boolean\(fallback\.endpointId\)/.test(modelRouteDecisionObject) &&
      /fallback_triggered:\s*fallbackTriggered/.test(modelRouteDecisionObject) &&
      /fallback_reason:\s*fallbackReason/.test(modelRouteDecisionObject) &&
      !/fallbackAllowed\s*:/.test(modelRouteDecisionObject) &&
      !/^ {4}fallbackTriggered,\s*$/m.test(modelRouteDecisionObject) &&
      !/^ {4}fallbackReason,\s*$/m.test(modelRouteDecisionObject) &&
      /fallback_allowed:\s*boolean/.test(agentSdkModelRouteDecisionType) &&
      /fallback_triggered\?:\s*boolean/.test(agentSdkModelRouteDecisionType) &&
      /fallback_reason\?:\s*string \| null/.test(agentSdkModelRouteDecisionType) &&
      !/fallbackAllowed/.test(agentSdkModelRouteDecisionType) &&
      !/fallbackTriggered/.test(agentSdkModelRouteDecisionType) &&
      !/fallbackReason/.test(agentSdkModelRouteDecisionType) &&
      /Object\.hasOwn\(decision,\s*"fallbackAllowed"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"fallbackTriggered"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"fallbackReason"\),\s*false/.test(modelRouteDecisionTest),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/agent-sdk/src/messages.ts",
    ],
    "Phase 3/10 is pending: model route decisions must emit canonical fallback metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-route-decision-lineage-aliases-retired",
    /response_id:\s*responseId/.test(modelRouteDecisionObject) &&
      /previous_response_id:\s*previousResponseId/.test(modelRouteDecisionObject) &&
      !/^ {4}responseId,\s*$/m.test(modelRouteDecisionObject) &&
      !/^ {4}previousResponseId,\s*$/m.test(modelRouteDecisionObject) &&
      /response_id:\s*responseId/.test(modelRouteSelectionDetailsObject) &&
      /previous_response_id:\s*previousResponseId/.test(modelRouteSelectionDetailsObject) &&
      !/^ {6}responseId,\s*$/m.test(modelRouteSelectionDetailsObject) &&
      !/^ {6}previousResponseId,\s*$/m.test(modelRouteSelectionDetailsObject) &&
      /response_id:\s*string \| null/.test(agentSdkModelRouteDecisionType) &&
      /previous_response_id:\s*string \| null/.test(agentSdkModelRouteDecisionType) &&
      !/responseId/.test(agentSdkModelRouteDecisionType) &&
      !/previousResponseId/.test(agentSdkModelRouteDecisionType) &&
      /Object\.hasOwn\(decision,\s*"responseId"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"previousResponseId"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(created\[0\]\.details,\s*"responseId"\),\s*false/.test(read("packages/runtime-daemon/src/model-mounting/routes.test.mjs")) &&
      /Object\.hasOwn\(created\[0\]\.details,\s*"previousResponseId"\),\s*false/.test(read("packages/runtime-daemon/src/model-mounting/routes.test.mjs")),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.test.mjs",
      "packages/agent-sdk/src/messages.ts",
    ],
    "Phase 3/10 is pending: model route decisions and route-selection receipts must emit canonical response lineage fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-route-decision-identity-aliases-retired",
    /schema_version:\s*MODEL_ROUTE_DECISION_SCHEMA_VERSION/.test(modelRouteDecisionObject) &&
      /event_kind:\s*MODEL_ROUTE_DECISION_EVENT_KIND/.test(modelRouteDecisionObject) &&
      /decision_id:\s*stableHash/.test(modelRouteDecisionObject) &&
      !/schemaVersion\s*:/.test(modelRouteDecisionObject) &&
      !/eventKind\s*:/.test(modelRouteDecisionObject) &&
      !/decisionId\s*:/.test(modelRouteDecisionObject) &&
      /model_route_decision_id:\s*modelRouteDecision\.decision_id/.test(modelRoutes) &&
      /requiredRef\("decision_id",\s*modelRouteDecision\.decision_id\)/.test(modelRoutes) &&
      !/modelRouteDecision\.decisionId/.test(modelRoutes) &&
      /schema_version:\s*"ioi\.model-route-decision\.v1"/.test(agentSdkModelRouteDecisionType) &&
      /event_kind:\s*"ModelRouteDecision"/.test(agentSdkModelRouteDecisionType) &&
      /decision_id:\s*string/.test(agentSdkModelRouteDecisionType) &&
      !/schemaVersion/.test(agentSdkModelRouteDecisionType) &&
      !/eventKind/.test(agentSdkModelRouteDecisionType) &&
      !/decisionId/.test(agentSdkModelRouteDecisionType) &&
      /modelRouteDecision\?\.decision_id/.test(runtimeRecordProjections) &&
      /modelRouteDecision\?\.decision_id/.test(threadTurnProjection) &&
      /json_path_string\(value,\s*"\/decision_id"\)/.test(agentTuiCli) &&
      /json_string\(value,\s*"decision_id"\)/.test(agentgresAdmissionCoreForBridge) &&
      /Object\.hasOwn\(decision,\s*"schemaVersion"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"eventKind"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"decisionId"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(created\[0\]\.details\.model_route_decision,\s*"decisionId"\),\s*false/.test(read("packages/runtime-daemon/src/model-mounting/routes.test.mjs")),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.test.mjs",
      "packages/runtime-daemon/src/runtime-record-projections.mjs",
      "packages/runtime-daemon/src/threads/thread-turn-projection.mjs",
      "packages/agent-sdk/src/messages.ts",
      "crates/cli/src/commands/agent_tui.rs",
      "crates/services/src/agentic/runtime/kernel/agentgres_admission.rs",
    ],
    "Phase 3/10 is pending: model route decisions and direct model-route decision id readers must use canonical identity fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-route-decision-route-model-aliases-retired",
      /^ {4}route_id:\s*route\?\.id/m.test(modelRouteDecisionObject) &&
      /^ {4}requested_model:\s*requestedModel/m.test(modelRouteDecisionObject) &&
      /^ {4}requested_model_mode:/m.test(modelRouteDecisionObject) &&
      /^ {4}auto_resolved:\s*autoResolved/m.test(modelRouteDecisionObject) &&
      /^ {4}selected_model:\s*selectedModel/m.test(modelRouteDecisionObject) &&
      /^ {4}upstream_model:\s*selectedModel/m.test(modelRouteDecisionObject) &&
      /^ {4}never_send_auto_upstream:/m.test(modelRouteDecisionObject) &&
      /^ {4}endpoint_id:\s*endpoint\?\.id/m.test(modelRouteDecisionObject) &&
      /^ {4}provider_id:\s*provider\?\.id/m.test(modelRouteDecisionObject) &&
      /^ {4}provider_kind:\s*provider\?\.kind/m.test(modelRouteDecisionObject) &&
      /^ {4}provider_label:\s*provider\?\.label/m.test(modelRouteDecisionObject) &&
      /endpoint_id:\s*candidate\.endpointId/.test(modelRouteDecisionObject) &&
      /provider_id:\s*candidate\.providerId/.test(modelRouteDecisionObject) &&
      !/^ {4}(?:routeId|requestedModel|requestedModelMode|autoResolved|selectedModel|upstreamModel|neverSendAutoUpstream|endpointId|providerId|providerKind|providerLabel)\s*[:,]/m.test(modelRouteDecisionObject) &&
      /^\s*route_id:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*requested_model:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*requested_model_mode:\s*"auto" \| "explicit" \| "route_default" \| string;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*auto_resolved:\s*boolean;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*selected_model:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*upstream_model:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*never_send_auto_upstream:\s*boolean;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*endpoint_id:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*provider_id:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*provider_kind:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*provider_label:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*endpoint_id:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*provider_id:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      !/^\s*(?:routeId|requestedModel|requestedModelMode|autoResolved|selectedModel|upstreamModel|neverSendAutoUpstream|endpointId|providerId|providerKind|providerLabel)\s*[:?]/m.test(agentSdkModelRouteDecisionType) &&
      /Object\.hasOwn\(decision,\s*"routeId"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"selectedModel"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"providerKind"\),\s*false/.test(modelRouteDecisionTest),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/agent-sdk/src/messages.ts",
    ],
    "Phase 3/10 is pending: accepted model route decisions must use canonical route/model/provider identity fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-route-decision-descriptor-aliases-retired",
    /^ {4}reasoning_effort:\s*reasoningEffort/m.test(modelRouteDecisionObject) &&
      /^ {4}local_remote_placement:\s*placement/m.test(modelRouteDecisionObject) &&
      /^ {4}privacy_posture:\s*privacyPosture/m.test(modelRouteDecisionObject) &&
      /^ {4}cost_estimate_usd:\s*costEstimate\.value/m.test(modelRouteDecisionObject) &&
      /^ {4}cost_estimate_source:\s*costEstimate\.source/m.test(modelRouteDecisionObject) &&
      /^ {4}fallback_model:\s*fallback\.model/m.test(modelRouteDecisionObject) &&
      /^ {4}fallback_endpoint_id:\s*fallback\.endpointId/m.test(modelRouteDecisionObject) &&
      !/^ {4}(?:reasoningEffort|localRemotePlacement|privacyPosture|costEstimateUsd|costEstimateSource|fallbackModel|fallbackEndpointId)\s*[:,]/m.test(modelRouteDecisionObject) &&
      /^\s*reasoning_effort:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*local_remote_placement:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*privacy_posture:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*cost_estimate_usd:\s*number;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*cost_estimate_source:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*fallback_model:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*fallback_endpoint_id:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      !/^\s*(?:reasoningEffort|localRemotePlacement|privacyPosture|costEstimateUsd|costEstimateSource|fallbackModel|fallbackEndpointId)\s*[:?]/m.test(agentSdkModelRouteDecisionType) &&
      /agent\.modelRouteDecision\?\.reasoning_effort/.test(threadTurnProjection) &&
      !/agent\.modelRouteDecision\?\.reasoningEffort/.test(threadTurnProjection) &&
      /model_route_decision[\s\S]*json_path_string\(value,\s*"\/reasoning_effort"\)/.test(agentTuiCli) &&
      !/model_route_decision\.and_then\(\|value\| json_path_string\(value,\s*"\/reasoningEffort"\)\)/.test(
        agentTuiCli,
      ) &&
      /tui_mode_status_reads_canonical_model_route_decision_reasoning/.test(agentTuiCli) &&
      /Object\.hasOwn\(decision,\s*"reasoningEffort"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"costEstimateUsd"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"fallbackModel"\),\s*false/.test(modelRouteDecisionTest) &&
      /modelRouteDecision:\s*\{\s*reasoning_effort:\s*"medium"\s*\}/.test(read("packages/runtime-daemon/src/threads/thread-turn-projection.test.mjs")),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/runtime-daemon/src/threads/thread-turn-projection.mjs",
      "packages/runtime-daemon/src/threads/thread-turn-projection.test.mjs",
      "packages/agent-sdk/src/messages.ts",
      "crates/cli/src/commands/agent_tui.rs",
    ],
    "Phase 3/10 is pending: accepted model route decisions and direct reasoning readers must use canonical descriptor fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-route-decision-policy-evaluation-aliases-retired",
    /^ {4}policy_constraints:\s*policyConstraints/m.test(modelRouteDecisionObject) &&
      /^ {4}evaluated_candidate_count:\s*evaluatedCandidates\.length/m.test(modelRouteDecisionObject) &&
      /^ {4}rejected_candidates:\s*evaluatedCandidates/m.test(modelRouteDecisionObject) &&
      /^\s*route_privacy:\s*route\.privacy/m.test(modelRouteDecisionModule) &&
      /^\s*requested_privacy:\s*policy\.privacy/m.test(modelRouteDecisionModule) &&
      /^\s*provider_eligibility:\s*Array\.isArray\(route\.providerEligibility\)/m.test(modelRouteDecisionModule) &&
      /^\s*denied_providers:\s*Array\.isArray\(route\.deniedProviders\)/m.test(modelRouteDecisionModule) &&
      /^\s*max_cost_usd:\s*Number\(/m.test(modelRouteDecisionModule) &&
      /^\s*max_latency_ms:\s*Number\(/m.test(modelRouteDecisionModule) &&
      /^\s*local_only:\s*policy\.privacy/m.test(modelRouteDecisionModule) &&
      !/^ {4}(?:policyConstraints|evaluatedCandidateCount|rejectedCandidates)\s*[:,]/m.test(modelRouteDecisionObject) &&
      !/^\s*(?:routePrivacy|requestedPrivacy|providerEligibility|deniedProviders|maxCostUsd|maxLatencyMs|localOnly)\s*:/m.test(
        modelRouteDecisionModule,
      ) &&
      /^\s*policy_constraints:\s*\{/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*route_privacy:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*requested_privacy:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*provider_eligibility:\s*string\[\];/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*denied_providers:\s*string\[\];/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*max_cost_usd:\s*number;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*max_latency_ms:\s*number;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*local_only:\s*boolean;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*evaluated_candidate_count:\s*number;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*rejected_candidates:\s*Array<\{/m.test(agentSdkModelRouteDecisionType) &&
      !/^\s*(?:policyConstraints|evaluatedCandidateCount|rejectedCandidates|routePrivacy|requestedPrivacy|providerEligibility|deniedProviders|maxCostUsd|maxLatencyMs|localOnly)\s*[:?]/m.test(
        agentSdkModelRouteDecisionType,
      ) &&
      /Object\.hasOwn\(decision,\s*"policyConstraints"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision\.policy_constraints,\s*"maxCostUsd"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"evaluatedCandidateCount"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"rejectedCandidates"\),\s*false/.test(modelRouteDecisionTest),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/agent-sdk/src/messages.ts",
    ],
    "Phase 3/10 is pending: accepted model route-decision policy/evaluation metadata must use canonical snake_case fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-route-decision-workflow-aliases-retired",
    /^ {4}workflow_graph_id:\s*workflow\.workflowGraphId/m.test(modelRouteDecisionObject) &&
      /^ {4}workflow_node_id:\s*workflow\.workflowNodeId/m.test(modelRouteDecisionObject) &&
      /^ {4}workflow_node_type:\s*workflow\.workflowNodeType/m.test(modelRouteDecisionObject) &&
      !/^ {4}(?:workflowGraphId|workflowNodeId|workflowNodeType)\s*[:,]/m.test(modelRouteDecisionObject) &&
      /^\s*workflow_graph_id:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*workflow_node_id:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*workflow_node_type:\s*string \| null;/m.test(agentSdkModelRouteDecisionType) &&
      !/^\s*(?:workflowGraphId|workflowNodeId|workflowNodeType)\s*[:?]/m.test(agentSdkModelRouteDecisionType) &&
      /Object\.hasOwn\(decision,\s*"workflowGraphId"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"workflowNodeId"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"workflowNodeType"\),\s*false/.test(modelRouteDecisionTest),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/agent-sdk/src/messages.ts",
    ],
    "Phase 3/10 is pending: accepted model route-decision workflow metadata must use canonical snake_case fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-route-decision-ref-aliases-retired",
    /^ {6}policy_hash:\s*policyHash/m.test(modelRouteDecisionObject) &&
      /^ {4}policy_hash:\s*policyHash/m.test(modelRouteDecisionObject) &&
      /^ {4}evidence_refs:\s*\[/m.test(modelRouteDecisionObject) &&
      !/^ {4}(?:policyHash|evidenceRefs)\s*[:,]/m.test(modelRouteDecisionObject) &&
      /^\s*policy_hash\?:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*evidence_refs:\s*string\[\];/m.test(agentSdkModelRouteDecisionType) &&
      !/^\s*(?:policyHash|evidenceRefs)\s*[:?]/m.test(agentSdkModelRouteDecisionType) &&
      /Object\.hasOwn\(decision,\s*"policyHash"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decision,\s*"evidenceRefs"\),\s*false/.test(modelRouteDecisionTest) &&
      /modelRouteDecision\?\.evidence_refs/.test(runtimeDaemonIndex) &&
      /modelRouteDecision\.evidence_refs/.test(runtimeDaemonIndex) &&
      !/modelRouteDecision\??\.evidenceRefs/.test(runtimeDaemonIndex),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
      "packages/agent-sdk/src/messages.ts",
    ],
    "Phase 3/10 is pending: accepted model route-decision policy/evidence refs and direct run readers must use canonical snake_case fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-route-decision-projection-receipt-aliases-retired",
    /receipt_id:\s*receipt\.id/.test(modelRouteDecisionModule) &&
      /receipt_created_at:\s*receipt\.createdAt/.test(modelRouteDecisionModule) &&
      /receipt_kind:\s*receipt\.kind/.test(modelRouteDecisionModule) &&
      !/(?:receiptId|receiptCreatedAt|receiptKind):\s*receipt\./.test(modelRouteDecisionModule) &&
      /^\s*receipt_id\?:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*receipt_created_at\?:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      /^\s*receipt_kind\?:\s*string;/m.test(agentSdkModelRouteDecisionType) &&
      !/^\s*(?:receiptId|receiptCreatedAt|receiptKind)\?:/m.test(agentSdkModelRouteDecisionType) &&
      /modelRouteDecision\?\.receipt_id/.test(runtimeDaemonIndex) &&
      !/modelRouteDecision\?\.receiptId/.test(runtimeDaemonIndex) &&
      /receipt_id:\s*modelRouteReceiptId/.test(runtimeDaemonIndex) &&
      !/receiptId:\s*modelRouteReceiptId/.test(runtimeDaemonIndex) &&
      /Object\.hasOwn\(projection,\s*"receiptId"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(projection,\s*"receiptCreatedAt"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(projection,\s*"receiptKind"\),\s*false/.test(modelRouteDecisionTest) &&
      /Object\.hasOwn\(decisions\[0\],\s*"receiptId"\),\s*false/.test(read("packages/runtime-daemon/src/model-mounting/projections.test.mjs")),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
      "packages/runtime-daemon/src/model-mounting/projections.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
      "packages/agent-sdk/src/messages.ts",
    ],
    "Phase 3/10 is pending: model route-decision projection receipt metadata and direct run readers must use canonical snake_case fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-route-selection-detail-aliases-retired",
    /^ {6}route_id:\s*selection\.route\.id/m.test(modelRouteSelectionDetailsObject) &&
      /^ {6}selected_model:\s*selection\.endpoint\.modelId/m.test(modelRouteSelectionDetailsObject) &&
      /^ {6}endpoint_id:\s*selection\.endpoint\.id/m.test(modelRouteSelectionDetailsObject) &&
      /^ {6}provider_id:\s*selection\.endpoint\.providerId/m.test(modelRouteSelectionDetailsObject) &&
      /^ {6}policy_hash:\s*policyHash/m.test(modelRouteSelectionDetailsObject) &&
      /^ {6}workflow_graph_id:\s*workflow\.workflowGraphId/m.test(modelRouteSelectionDetailsObject) &&
      /^ {6}workflow_node_id:\s*workflow\.workflowNodeId/m.test(modelRouteSelectionDetailsObject) &&
      /^ {6}workflow_node_type:\s*workflow\.workflowNodeType/m.test(modelRouteSelectionDetailsObject) &&
      !/^ {6}(?:routeId|selectedModel|endpointId|providerId|policyHash|workflowGraphId|workflowNodeId|workflowNodeType)\s*[:,]/m.test(
        modelRouteSelectionDetailsObject,
      ) &&
      /receipt\.details\?\.route_id/.test(modelProjections) &&
      /receipt\.details\?\.endpoint_id/.test(modelProjections) &&
      /receipt\.details\?\.provider_id/.test(modelProjections) &&
      !/receipt\.details\?\.(?:routeId|endpointId|providerId)/.test(modelProjections) &&
      /details:\s*\{\s*route_id:\s*route\.id,\s*capability,\s*policy,\s*evaluated_candidates:\s*evaluatedCandidates\s*\}/.test(
        modelRoutes,
      ) &&
      !/details:\s*\{\s*routeId:\s*route\.id,\s*capability,\s*policy,\s*evaluatedCandidates\s*\}/.test(
        modelRoutes,
      ) &&
      /routeReceipt\?\.details\?\.workflow_graph_id/.test(modelInvocationOps) &&
      /routeReceipt\?\.details\?\.workflow_node_id/.test(modelInvocationOps) &&
      !/routeReceipt\?\.details\?\.(?:workflowGraphId|workflowNodeId)/.test(modelInvocationOps) &&
      /Object\.hasOwn\(error\.details,\s*"routeId"\),\s*false/.test(read("packages/runtime-daemon/src/model-mounting/routes.test.mjs")) &&
      /Object\.hasOwn\(error\.details,\s*"evaluatedCandidates"\),\s*false/.test(read("packages/runtime-daemon/src/model-mounting/routes.test.mjs")) &&
      /Object\.hasOwn\(created\[0\]\.details,\s*"routeId"\),\s*false/.test(read("packages/runtime-daemon/src/model-mounting/routes.test.mjs")) &&
      /Object\.hasOwn\(created\[0\]\.details,\s*"policyHash"\),\s*false/.test(read("packages/runtime-daemon/src/model-mounting/routes.test.mjs")) &&
      /Object\.hasOwn\(created\[0\]\.details,\s*"workflowNodeId"\),\s*false/.test(read("packages/runtime-daemon/src/model-mounting/routes.test.mjs")) &&
      /assert\.equal\(replay\.model_route_decision\.route_id/.test(modelProjectionsTest),
    [
      "packages/runtime-daemon/src/model-mounting/routes.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.test.mjs",
      "packages/runtime-daemon/src/model-mounting/projections.mjs",
      "packages/runtime-daemon/src/model-mounting/projections.test.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
    ],
    "Phase 3/10 is pending: model route-selection receipt details and direct readers must use canonical snake_case fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-native-response-route-decision-aliases-retired",
    /model_route_decision:\s*\{\s*route_id:\s*"route\.local-first",\s*selected_model:\s*"model\.local"\s*\}/.test(
      modelWorkflowNodeTest,
    ) &&
      /model_route_decision:\s*\{\s*route_id:\s*"route\.native",\s*selected_model:\s*"model\.native"\s*\}/.test(
        openAiCompatRoutesTest,
      ) &&
      /Object\.hasOwn\(response\.route_decision,\s*"routeId"\),\s*false/.test(modelWorkflowNodeTest) &&
      /Object\.hasOwn\(response\.route_decision,\s*"selectedModel"\),\s*false/.test(modelWorkflowNodeTest) &&
      /Object\.hasOwn\(response\.route_decision,\s*"routeId"\),\s*false/.test(openAiCompatRoutesTest) &&
      /Object\.hasOwn\(response\.route_decision,\s*"selectedModel"\),\s*false/.test(openAiCompatRoutesTest) &&
      !/model_route_decision:\s*\{\s*(?:routeId|selectedModel)/.test(modelWorkflowNodeTest) &&
      !/model_route_decision:\s*\{\s*(?:routeId|selectedModel)/.test(openAiCompatRoutesTest),
    [
      "packages/runtime-daemon/src/model-mounting/workflow-node.test.mjs",
      "packages/runtime-daemon/src/openai-compat-routes.test.mjs",
    ],
    "Phase 3/10 is pending: native response route-decision projections must use canonical snake_case fixtures without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-receipt-gate-route-detail-aliases-retired",
    /requiredString\(body\.receipt_id,\s*"receipt_id"\)/.test(modelReceiptGateValidation) &&
      /const requiredRouteId = body\.route_id/.test(modelReceiptGateValidation) &&
      /const requiredSelectedModel = body\.selected_model/.test(modelReceiptGateValidation) &&
      /body\.selected_endpoint \?\? body\.endpoint_id/.test(modelReceiptGateValidation) &&
      /body\.selected_backend \?\? body\.backend_id/.test(modelReceiptGateValidation) &&
      /body\.required_tool_receipt_ids/.test(modelReceiptGateValidation) &&
      /receipt\.details\?\.route_id/.test(modelReceiptGateValidation) &&
      /receipt\.details\?\.selected_model/.test(modelReceiptGateValidation) &&
      /receipt\.details\?\.endpoint_id/.test(modelReceiptGateValidation) &&
      /receipt\.details\?\.tool_receipt_ids/.test(modelReceiptGateValidation) &&
      /receipt_id:\s*receiptId/.test(modelReceiptGateValidation) &&
      /gate_receipt_id:\s*blockedReceipt\.id/.test(modelReceiptGateValidation) &&
      /required_tool_receipt_ids:\s*requiredToolReceiptIds/.test(modelReceiptGateValidation) &&
      !/body\.(?:receiptId|routeId|selectedModel|selectedEndpoint|endpointId|selectedBackend|backendId|requiredToolReceiptIds|redactionClass)/.test(
        modelReceiptGateValidation,
      ) &&
      !/receipt\.details\?\.(?:routeId|selectedModel|endpointId|backendId|selectedBackend|toolReceiptIds)/.test(
        modelReceiptGateValidation,
      ) &&
      !/(?:receiptId|routeId|selectedModel|endpointId|backendId|requiredToolReceiptIds|gateReceiptId):/.test(
        modelReceiptGateValidation,
      ) &&
      /Object\.hasOwn\(createdReceipts\[0\]\.details,\s*"routeId"\),\s*false/.test(modelMountingValidationTest) &&
      /Object\.hasOwn\(error\.details,\s*"gateReceiptId"\),\s*false/.test(modelMountingValidationTest),
    [
      "packages/runtime-daemon/src/model-mounting/validation.mjs",
      "packages/runtime-daemon/src/model-mounting/validation.test.mjs",
    ],
    "Phase 3/10 is pending: receipt-gate route/detail validation must use canonical snake_case request and receipt metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-invocation-receipt-detail-aliases-retired",
    /^ {4}route_id:\s*selection\.route\.id/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}route_receipt_id:\s*routeReceipt\.id/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}selected_model:\s*selection\.endpoint\.modelId/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}endpoint_id:\s*selection\.endpoint\.id/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}provider_id:\s*selection\.endpoint\.providerId/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}instance_id:\s*instance\.id/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}backend_id:\s*providerResult\.backendId/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}selected_backend:\s*providerResult\.backendId/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}policy_hash:\s*hash/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}grant_id:\s*token\.grantId/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}token_count:\s*tokenCount/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}latency_ms:\s*latencyMs/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}input_hash:\s*hash\(input\)/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}output_hash:\s*hash\(outputText\)/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}provider_response_kind:\s*providerResult\.providerResponseKind/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}backend_evidence_refs:\s*providerResult\.backendEvidenceRefs/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}provider_auth_evidence_refs:\s*providerResult\.providerAuthEvidenceRefs/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}tool_receipt_ids:\s*ephemeralMcp\.toolReceiptIds/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}ephemeral_mcp_server_ids:\s*ephemeralMcp\.serverIds/m.test(modelInvocationReceiptDetailsObject) &&
      /^ {4}response_id:\s*responseId/m.test(modelInvocationReceiptDetailsObject) &&
      /details\.send_options\s*=\s*body\.send_options/.test(modelInvocationOps) &&
      /details\.coalesce_key_hash\s*=\s*coalesceKey/.test(modelInvocationOps) &&
      !/^ {4}(?:routeId|routeReceiptId|selectedModel|endpointId|providerId|instanceId|backendId|selectedBackend|policyHash|grantId|tokenCount|latencyMs|inputHash|outputHash|providerResponseKind|backendProcess|backendProcessId|backendProcessPidHash|backendEvidenceRefs|authVaultRefHash|providerAuthEvidenceRefs|providerAuthHeaderNames|toolReceiptIds|ephemeralMcpServerIds|responseId)\s*[:,]/m.test(
        modelInvocationReceiptDetailsObject,
      ) &&
      !/details\.(?:sendOptions|coalesceKeyHash)\s*=/.test(modelInvocationOps) &&
      /receiptDetails\.route_id/.test(modelInvocationOps) &&
      /receiptDetails\.provider_id/.test(modelInvocationOps) &&
      /receiptDetails\.endpoint_id/.test(modelInvocationOps) &&
      /receiptDetails\.selected_model/.test(modelInvocationOps) &&
      /receiptDetails\.policy_hash/.test(modelInvocationOps) &&
      /receiptDetails\.input_hash/.test(modelInvocationOps) &&
      /receiptDetails\.output_hash/.test(modelInvocationOps) &&
      /receiptDetails\.tool_receipt_ids/.test(modelInvocationOps) &&
      /receiptDetails\.grant_id/.test(modelInvocationOps) &&
      /receiptDetails\.provider_auth_evidence_refs/.test(modelInvocationOps) &&
      /receiptDetails\.backend_evidence_refs/.test(modelInvocationOps) &&
      /receiptDetails\.response_id/.test(modelInvocationOps) &&
      /receiptDetails\.stream_status/.test(modelInvocationOps) &&
      !/receiptDetails\.(?:routeId|providerId|endpointId|selectedModel|policyHash|inputHash|outputHash|toolReceiptIds|grantId|providerAuthEvidenceRefs|backendEvidenceRefs|responseId|streamStatus)/.test(
        modelInvocationOps,
      ) &&
      /^ {4}stream_kind:\s*streamKind/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}stream_source:\s*"provider_native"/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}invocation_receipt_id:\s*invocation\.receipt\.id/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}route_id:\s*invocation\.route\.id/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}selected_model:\s*invocation\.model/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}endpoint_id:\s*invocation\.endpoint\.id/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}backend_id:\s*invocation\.instance\.backendId/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}tool_receipt_ids:\s*invocation\.toolReceiptIds/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}output_hash:\s*stableHash\(outputText\)/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}provider_stream_shape_summary:\s*providerStreamShapeSummary/m.test(modelStreamCompletionReceiptDetailsObject) &&
      /^ {4}response_id:\s*invocation\.responseId/m.test(modelStreamCompletionReceiptDetailsObject) &&
      !/^ {4}(?:streamKind|streamSource|invocationReceiptId|routeId|selectedModel|endpointId|providerId|instanceId|backendId|selectedBackend|providerResponseKind|providerAuthEvidenceRefs|backendEvidenceRefs|toolReceiptIds|tokenCount|policyHash|inputHash|outputHash|chunksForwarded|finishReason|providerStreamShapeSummary|responseId)\s*[:,]/m.test(
        modelStreamCompletionReceiptDetailsObject,
      ) &&
      /receipt\.details\?\.instance_id/.test(modelProjections) &&
      /receipt\.details\?\.tool_receipt_ids/.test(modelProjections) &&
      !/receipt\.details\?\.(?:instanceId|toolReceiptIds)/.test(modelProjections) &&
      /receipt\.details\?\.backend_id/.test(modelWorkflowNode) &&
      /receipt\.details\?\.send_options/.test(modelWorkflowNode) &&
      /receipt\.details\?\.backend_id/.test(openAiCompatRoutes) &&
      !/receipt\.details\?\.(?:backendId|sendOptions|selectedBackend|providerResponseKind|backendEvidenceRefs)/.test(
        modelWorkflowNode + openAiCompatRoutes,
      ) &&
      /Object\.hasOwn\(result\.receipt\.details,\s*"routeId"\),\s*false/.test(modelInvocationOpsTest) &&
      /Object\.hasOwn\(result\.receipt\.details,\s*"toolReceiptIds"\),\s*false/.test(modelInvocationOpsTest) &&
      /Object\.hasOwn\(secondResult\.receipt\.details,\s*"coalesceKeyHash"\),\s*false/.test(modelInvocationOpsTest) &&
      /Object\.hasOwn\(receipt\.details,\s*"toolReceiptIds"\),\s*false/.test(modelConversationOpsTest) &&
      /Object\.hasOwn\(receipt\.details,\s*"providerStreamShapeSummary"\),\s*false/.test(modelConversationOpsTest),
    [
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/conversation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/projections.mjs",
      "packages/runtime-daemon/src/model-mounting/workflow-node.mjs",
      "packages/runtime-daemon/src/openai-compat-routes.mjs",
    ],
    "Phase 3/10 is pending: model invocation and stream-completion receipt details must serialize canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-stream-cancel-receipt-detail-aliases-retired",
    /^ {6}stream_kind:\s*streamKind/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}invocation_receipt_id:\s*invocation\.receipt\.id/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}route_id:\s*invocation\.route\.id/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}selected_model:\s*invocation\.model/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}endpoint_id:\s*invocation\.endpoint\.id/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}provider_id:\s*invocation\.endpoint\.providerId/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}instance_id:\s*invocation\.instance\.id/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}backend_id:\s*invocation\.instance\.backendId/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}selected_backend:\s*invocation\.receipt\.details\?\.selected_backend/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}stream_source:\s*invocation\.receipt\.details\?\.stream_source/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}provider_response_kind:\s*invocation\.providerResponseKind/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}backend_evidence_refs:\s*invocation\.receipt\.details\?\.backend_evidence_refs/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}tool_receipt_ids:\s*invocation\.toolReceiptIds/m.test(modelStreamCancelDetailsObject) &&
      /^ {6}frames_written:\s*framesWritten/m.test(modelStreamCancelDetailsObject) &&
      !/^ {6}(?:streamKind|invocationReceiptId|routeId|selectedModel|endpointId|providerId|instanceId|backendId|selectedBackend|streamSource|providerResponseKind|backendEvidenceRefs|toolReceiptIds|framesWritten)\s*[:,]/m.test(
        modelStreamCancelDetailsObject,
      ) &&
      /stream cancellation receipts use canonical detail metadata/.test(openAiCompatRoutesTest) &&
      /Object\.hasOwn\(receipts\[0\]\.payload\.details,\s*"streamKind"\),\s*false/.test(openAiCompatRoutesTest) &&
      /Object\.hasOwn\(receipts\[0\]\.payload\.details,\s*"providerResponseKind"\),\s*false/.test(openAiCompatRoutesTest) &&
      /Object\.hasOwn\(receipts\[0\]\.payload\.details,\s*"framesWritten"\),\s*false/.test(openAiCompatRoutesTest),
    [
      "packages/runtime-daemon/src/openai-compat-routes.mjs",
      "packages/runtime-daemon/src/openai-compat-routes.test.mjs",
    ],
    "Phase 3/10 is pending: stream cancellation receipts must serialize canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "runtime-thread-model-route-decision-reader-aliases-retired",
    /modelRoute\.decision\?\.reasoning_effort/.test(threadRuntimeControls) &&
      /modelRoute\.decision\?\.workflow_graph_id/.test(threadRuntimeControls) &&
      /modelRoute\.decision\?\.workflow_node_id/.test(threadRuntimeControls) &&
      /agent\.modelRouteDecision\?\.reasoning_effort/.test(threadRuntimeControls) &&
      /agent\.modelRouteDecision\?\.workflow_graph_id/.test(threadRuntimeControls) &&
      /agent\.modelRouteDecision\?\.workflow_node_id/.test(threadRuntimeControls) &&
      /decision\?\.requested_model/.test(threadRuntimeControls) &&
      /decision\?\.selected_model/.test(threadRuntimeControls) &&
      /decision\?\.route_id/.test(threadRuntimeControls) &&
      /decision\?\.endpoint_id/.test(threadRuntimeControls) &&
      /decision\?\.provider_id/.test(threadRuntimeControls) &&
      !/modelRoute\.decision\?\.(?:reasoningEffort|workflowGraphId|workflowNodeId|workflowNodeType)/.test(
        threadRuntimeControls,
      ) &&
      !/agent\.modelRouteDecision\?\.(?:reasoningEffort|workflowGraphId|workflowNodeId|workflowNodeType)/.test(
        threadRuntimeControls,
      ) &&
      !/decision\?\.(?:requestedModel|selectedModel|routeId|endpointId|providerId)/.test(threadRuntimeControls) &&
      /reasoningEffort:\s*"legacy-high"/.test(threadRuntimeControlsTest) &&
      /requestedModel:\s*"legacy-requested"/.test(threadRuntimeControlsTest) &&
      /assert\.equal\(binding\.routeId,\s*"route\.local-first"\)/.test(threadRuntimeControlsTest),
    [
      "packages/runtime-daemon/src/threads/thread-runtime-controls.mjs",
      "packages/runtime-daemon/src/threads/thread-runtime-controls.test.mjs",
    ],
    "Phase 3/10 is pending: runtime thread-control model-route readers must consume canonical route-decision fields without retired camelCase fallbacks",
  );
  assertCheck(
    result,
    "runtime-run-model-route-decision-reader-aliases-retired",
    /modelRouteDecision\?\.selected_model/.test(runtimeDaemonIndex) &&
      /modelRouteDecision\.route_id/.test(runtimeDaemonIndex) &&
      /modelRouteDecision\.selected_model/.test(runtimeDaemonIndex) &&
      !/modelRouteDecision\?\.selectedModel/.test(runtimeDaemonIndex) &&
      !/modelRouteDecision\.(?:routeId|selectedModel)/.test(runtimeDaemonIndex) &&
      /model_route_decision:\s*\{/.test(modelRouteSelectionTest) &&
      /requested_model:\s*body\.model/.test(modelRouteSelectionTest) &&
      /selected_model:\s*selection\.endpoint/.test(modelRouteSelectionTest) &&
      /fallback_triggered:\s*Boolean\(body\.fallback_triggered\)/.test(modelRouteSelectionTest) &&
      /assert\.equal\(route\.decision\.fallback_triggered,\s*true\)/.test(modelRouteSelectionTest) &&
      !/details:\s*\{\s*modelRouteDecision\s*:/.test(modelRouteSelectionTest) &&
      !/route\.decision\.fallbackTriggered/.test(modelRouteSelectionTest),
    [
      "packages/runtime-daemon/src/index.mjs",
      "packages/runtime-daemon/src/threads/model-route-selection.test.mjs",
    ],
    "Phase 3/10 is pending: runtime run assembly must consume canonical route-decision fields without retired camelCase route/model fallbacks",
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
    "model-mount-continuation-lineage-aliases-retired",
    /previous_response_id:\s*null/.test(modelMountingValidation) &&
      /fallback_allowed:\s*false/.test(modelMountingValidation) &&
      /mismatch_fields:\s*\[\]/.test(modelMountingValidation) &&
      /previous_response_id:\s*previousState\.id/.test(modelMountingValidation) &&
      /fallback_allowed:\s*allowFallback/.test(modelMountingValidation) &&
      /mismatch_fields:\s*mismatchFields/.test(modelMountingValidation) &&
      !/previousResponseId:\s*previousState\.id/.test(modelMountingValidation) &&
      !/fallbackAllowed:\s*allowFallback/.test(modelMountingValidation) &&
      !/mismatchFields:\s*mismatchFields/.test(modelMountingValidation) &&
      /previous_response_ref:\s*optionalRef\(receiptDetails\.previous_response_id\)/.test(modelInvocationOps) &&
      /previous_response_id:\s*previousResponseId/.test(modelInvocationReceiptDetailsObject) &&
      !/previous_response_ref:\s*optionalRef\(receiptDetails\.previousResponseId\)/.test(modelInvocationOps) &&
      !/^\s*previousResponseId,\s*$/m.test(modelInvocationReceiptDetailsObject) &&
      /previous_response_id:\s*previousState\?\.id/.test(modelConversationOps) &&
      /root_response_id:\s*previousState\?\.root_response_id/.test(modelConversationOps) &&
      /previous_response_id:\s*invocation\.previousResponseId/.test(modelConversationOps) &&
      !/previousResponseId:\s*previousState\?\.id/.test(modelConversationOps) &&
      !/rootResponseId:\s*previousState/.test(modelConversationOps) &&
      !/previousResponseId:\s*invocation\.previousResponseId/.test(modelConversationOps) &&
      /"previous_response_id"/.test(modelSchemaRelations) &&
      !/"previousResponseId"/.test(modelSchemaRelations) &&
      /previous_response_id\?:\s*string \| null/.test(agentSdkModelMounts) &&
      /root_response_id:\s*string/.test(agentSdkModelMounts) &&
      /fallback_allowed\?:\s*boolean/.test(agentSdkModelMounts) &&
      /mismatch_fields\?:\s*string\[\]/.test(agentSdkModelMounts) &&
      !/previousResponseId/.test(agentSdkModelMounts) &&
      !/rootResponseId/.test(agentSdkModelMounts) &&
      !/fallbackAllowed/.test(agentSdkModelMounts) &&
      !/mismatchFields/.test(agentSdkModelMounts),
    [
      "packages/runtime-daemon/src/model-mounting/validation.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/conversation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/schema-relations.mjs",
      "packages/agent-sdk/src/model-mounts.ts",
    ],
    "Phase 4/10 is pending: model-mount continuation and response-lineage metadata must use canonical snake_case accepted fields without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-conversation-state-metadata-aliases-retired",
    /^ {4}created_at:\s*now/m.test(modelConversationStateRecordObject) &&
      /^ {4}route_id:\s*selection\.route\.id/m.test(modelConversationStateRecordObject) &&
      /^ {4}endpoint_id:\s*selection\.endpoint\.id/m.test(modelConversationStateRecordObject) &&
      /^ {4}selected_model:\s*selection\.endpoint\.modelId/m.test(modelConversationStateRecordObject) &&
      /^ {4}provider_id:\s*selection\.endpoint\.providerId/m.test(modelConversationStateRecordObject) &&
      /^ {4}backend_id:\s*instance\?\.backendId/m.test(modelConversationStateRecordObject) &&
      /^ {4}instance_id:\s*instance\?\.id/m.test(modelConversationStateRecordObject) &&
      /^ {4}receipt_id:\s*receipt\.id/m.test(modelConversationStateRecordObject) &&
      /^ {4}route_receipt_id:\s*routeReceipt\?\.id/m.test(modelConversationStateRecordObject) &&
      /^ {4}stream_receipt_id:\s*streamReceiptId/m.test(modelConversationStateRecordObject) &&
      /^ {4}input_hash:\s*stableHash\(input\)/m.test(modelConversationStateRecordObject) &&
      /^ {4}output_hash:\s*stableHash\(outputText\)/m.test(modelConversationStateRecordObject) &&
      /^ {4}token_count:\s*tokenCount/m.test(modelConversationStateRecordObject) &&
      /^ {4}message_count:\s*Number\(previousState\?\.message_count/m.test(modelConversationStateRecordObject) &&
      /plaintext_persisted:\s*false/.test(modelConversationStateRecordObject) &&
      /left\.created_at/.test(modelConversationOps) &&
      /previousState\.route_id/.test(modelMountingValidation) &&
      /previousState\.endpoint_id/.test(modelMountingValidation) &&
      /previousState\.selected_model/.test(modelMountingValidation) &&
      !/^ {4}(?:createdAt|routeId|endpointId|selectedModel|providerId|backendId|instanceId|receiptId|routeReceiptId|streamReceiptId|inputHash|outputHash|tokenCount|messageCount)\s*:/m.test(
        modelConversationStateRecordObject,
      ) &&
      !/plaintextPersisted\s*:/.test(modelConversationStateRecordObject) &&
      !/previousState\.(?:routeId|endpointId|selectedModel)\b/.test(modelMountingValidation) &&
      /"route_id"/.test(modelConversationSchemaRelations) &&
      /"endpoint_id"/.test(modelConversationSchemaRelations) &&
      /"selected_model"/.test(modelConversationSchemaRelations) &&
      /"receipt_id"/.test(modelConversationSchemaRelations) &&
      /"input_hash"/.test(modelConversationSchemaRelations) &&
      /"output_hash"/.test(modelConversationSchemaRelations) &&
      !/"(?:routeId|endpointId|selectedModel|receiptId|inputHash|outputHash)"/.test(modelConversationSchemaRelations) &&
      /Object\.hasOwn\(record,\s*"routeId"\),\s*false/.test(modelConversationOpsTest) &&
      /Object\.hasOwn\(record,\s*"tokenCount"\),\s*false/.test(modelConversationOpsTest) &&
      /Object\.hasOwn\(record\.replay,\s*"plaintextPersisted"\),\s*false/.test(modelConversationOpsTest),
    [
      "packages/runtime-daemon/src/model-mounting/conversation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/conversation-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/validation.mjs",
      "packages/runtime-daemon/src/model-mounting/validation.test.mjs",
      "packages/runtime-daemon/src/model-mounting/schema-relations.mjs",
    ],
    "Phase 4/10 is pending: model-mount redacted conversation state must use canonical snake_case route, receipt, hash, replay, and token metadata without duplicate camelCase aliases",
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
      !/compatTranslation\??:/.test(agentSdkModelMounts) &&
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
      "packages/agent-sdk/src/model-mounts.ts",
    ],
    "Phase 9/11 is pending: provider compatibility translation markers must fail closed instead of entering accepted receipts, native protocol responses, or SDK receipt types",
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
  const providerTransportTest = exists("packages/runtime-daemon/src/model-mounting/provider-transport.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-transport.test.mjs")
    : "";
  const providerAuth = exists("packages/runtime-daemon/src/model-mounting/provider-auth.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-auth.mjs")
    : "";
  const providerAuthTest = exists("packages/runtime-daemon/src/model-mounting/provider-auth.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-auth.test.mjs")
    : "";
  const lmStudioProviderDriver = exists("packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs")
    : "";
  const lmStudioProviderDriverTest = exists("packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.test.mjs")
    : "";
  const localSystemProbes = exists("packages/runtime-daemon/src/model-mounting/local-system-probes.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/local-system-probes.mjs")
    : "";
  const localSystemProbesTest = exists("packages/runtime-daemon/src/model-mounting/local-system-probes.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/local-system-probes.test.mjs")
    : "";
  const providerOperations = exists("packages/runtime-daemon/src/model-mounting/provider-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs")
    : "";
  const providerOperationsTest = exists("packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs")
    : "";
  const catalogProviderConfig = exists("packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs")
    : "";
  const catalogProviderConfigTest = exists("packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs")
    : "";
  const oauthCredentialProvider = exists("packages/runtime-daemon/src/model-mounting/oauth-credential-provider.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/oauth-credential-provider.mjs")
    : "";
  const oauthCredentialProviderTest = exists("packages/runtime-daemon/src/model-mounting/oauth-credential-provider.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/oauth-credential-provider.test.mjs")
    : "";
  const oauthBoundary = exists("packages/runtime-daemon/src/model-mounting/oauth-boundary.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/oauth-boundary.mjs")
    : "";
  const oauthBoundaryTest = exists("packages/runtime-daemon/src/model-mounting/oauth-boundary.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/oauth-boundary.test.mjs")
    : "";
  const catalogProviderOAuth = exists("packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.mjs")
    : "";
  const catalogProviderOAuthTest = exists("packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.test.mjs")
    : "";
  const backendLifecycle = exists("packages/runtime-daemon/src/model-mounting/backend-lifecycle.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/backend-lifecycle.mjs")
    : "";
  const backendLifecycleTest = exists("packages/runtime-daemon/src/model-mounting/backend-lifecycle.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/backend-lifecycle.test.mjs")
    : "";
  const backendProcesses = exists("packages/runtime-daemon/src/model-mounting/backend-processes.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/backend-processes.mjs")
    : "";
  const backendProcessesTest = exists("packages/runtime-daemon/src/model-mounting/backend-processes.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/backend-processes.test.mjs")
    : "";
  const capabilityTokenOperations = exists("packages/runtime-daemon/src/model-mounting/capability-token-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/capability-token-operations.mjs")
    : "";
  const capabilityTokenOperationsTest = exists("packages/runtime-daemon/src/model-mounting/capability-token-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/capability-token-operations.test.mjs")
    : "";
  const walletAuthority = exists("packages/runtime-daemon/src/model-mounting/wallet-authority.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/wallet-authority.mjs")
    : "";
  const walletAuthorityTest = exists("packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs")
    : "";
  const vaultPort = exists("packages/runtime-daemon/src/model-mounting/vault-port.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/vault-port.mjs")
    : "";
  const vaultPortTest = exists("packages/runtime-daemon/src/model-mounting/vault-port.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/vault-port.test.mjs")
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
  const modelMountReceiptOperationsTest = exists("packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs")
    : "";
  const modelLoadingOperations = exists("packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs")
    : "";
  const modelLoadingOperationsTest = exists("packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs")
    : "";
  const loadedInstances = exists("packages/runtime-daemon/src/model-mounting/loaded-instances.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/loaded-instances.mjs")
    : "";
  const loadedInstancesTest = exists("packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs")
    : "";
  const storageOperations = exists("packages/runtime-daemon/src/model-mounting/storage-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/storage-operations.mjs")
    : "";
  const storageOperationsTest = exists("packages/runtime-daemon/src/model-mounting/storage-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/storage-operations.test.mjs")
    : "";
  const artifactEndpointOperations = exists("packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.mjs")
    : "";
  const artifactEndpointOperationsTest = exists("packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.test.mjs")
    : "";
  const mcpWorkflowOperations = exists("packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.mjs")
    : "";
  const mcpWorkflowOperationsTest = exists("packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.test.mjs")
    : "";
  const catalogHelpers = exists("packages/runtime-daemon/src/model-mounting/catalog-helpers.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-helpers.mjs")
    : "";
  const catalogHelpersTest = exists("packages/runtime-daemon/src/model-mounting/catalog-helpers.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-helpers.test.mjs")
    : "";
  const catalogDownloadOperations = exists("packages/runtime-daemon/src/model-mounting/catalog-download-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-download-operations.mjs")
    : "";
  const catalogDownloadOperationsTest = exists("packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs")
    : "";
  const runtimeEngines = exists("packages/runtime-daemon/src/model-mounting/runtime-engines.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/runtime-engines.mjs")
    : "";
  const runtimeEnginesTest = exists("packages/runtime-daemon/src/model-mounting/runtime-engines.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/runtime-engines.test.mjs")
    : "";
  const runtimeSurveyModule = exists("packages/runtime-daemon/src/model-mounting/runtime-survey.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/runtime-survey.mjs")
    : "";
  const runtimeSurveyTest = exists("packages/runtime-daemon/src/model-mounting/runtime-survey.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/runtime-survey.test.mjs")
    : "";
  const stateAccessors = exists("packages/runtime-daemon/src/model-mounting/state-accessors.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/state-accessors.mjs")
    : "";
  const stateAccessorsTest = exists("packages/runtime-daemon/src/model-mounting/state-accessors.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/state-accessors.test.mjs")
    : "";
  const modelMountStoreTest = exists("packages/runtime-daemon/src/model-mounting/store.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/store.test.mjs")
    : "";
  const modelTokenizerOperations = exists("packages/runtime-daemon/src/model-mounting/tokenizer-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/tokenizer-operations.mjs")
    : "";
  const modelTokenizerOperationsTest = exists("packages/runtime-daemon/src/model-mounting/tokenizer-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/tokenizer-operations.test.mjs")
    : "";
  const modelInstanceLifecycleReceiptBlocks = [
    modelLoadingOperations.match(/state\.lifecycleReceipt\("model_load",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
    modelLoadingOperations.match(/state\.lifecycleReceipt\("model_unload",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
    loadedInstances.match(/state\.lifecycleReceipt\("model_idle_evict",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
    loadedInstances.match(/state\.lifecycleReceipt\("model_supersede",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
  ].join("\n");
  const modelTokenizerReceiptDetailsObject =
    modelTokenizerOperations.match(/details:\s*\{[\s\S]*?context_window:\s*contextWindow,\n\s+\},/)?.[0] ?? "";
  const artifactEndpointReceiptBlocks = [
    artifactEndpointOperations.match(/state\.lifecycleReceipt\("model_import_dry_run",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
    artifactEndpointOperations.match(/state\.lifecycleReceipt\("model_import",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
    artifactEndpointOperations.match(/state\.lifecycleReceipt\("model_mount",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
    artifactEndpointOperations.match(/state\.lifecycleReceipt\("model_unmount",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
  ].join("\n");
  const storageLifecycleReceiptBlocks = [
    storageOperations.match(/state\.lifecycleReceipt\("model_download_canceled",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
    storageOperations.match(/state\.lifecycleReceipt\("model_artifact_delete_dry_run",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
    storageOperations.match(/state\.lifecycleReceipt\("model_artifact_delete",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
    storageOperations.match(/state\.lifecycleReceipt\("model_storage_cleanup",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "",
  ].join("\n");
  const mcpServerReceiptDetailsHelper =
    mcpWorkflowOperations.match(/function mcpServerReceiptDetails\(server\) \{[\s\S]*?\n\}/)?.[0] ?? "";
  const mcpToolReceiptDetailsObject =
    mcpWorkflowOperations.match(/details:\s*\{\n\s+server_id:\s*serverId,[\s\S]*?\n\s+\},/)?.[0] ?? "";
  const catalogImportUrlReceiptDetailsObject =
    catalogDownloadOperations.match(/state\.lifecycleReceipt\("model_catalog_import_url",\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "";
  const catalogDownloadReceiptBlocks = [
    ...catalogDownloadOperations.matchAll(/state\.lifecycleReceipt\("model_download_(?:queued|failed|running|completed)",\s*\{[\s\S]*?\n\s+\}\);/g),
  ].map((match) => match[0]).join("\n");
  const catalogDownloadTransferReceiptObject =
    catalogDownloadOperations.match(/state\.lifecycleReceipt\(operation,\s*\{[\s\S]*?\n\s+\}\);/)?.[0] ?? "";
  const catalogDownloadErrorDetailsHelper =
    catalogDownloadOperations.match(/function catalogDownloadErrorDetails\(sourceHash,\s*evidenceRefs\) \{[\s\S]*?\n\}/)?.[0] ?? "";
  const catalogAuthReceiptDetailsHelper =
    catalogDownloadOperations.match(/function catalogAuthReceiptDetails\(evidence\) \{[\s\S]*?\n\}/)?.[0] ?? "";
  const catalogDownloadPolicyReceiptDetailsHelper =
    catalogDownloadOperations.match(/function downloadPolicyReceiptDetails\(policy\) \{[\s\S]*?\n\}/)?.[0] ?? "";
  const catalogDownloadTransferReceiptDetailsHelper =
    catalogDownloadOperations.match(/function transferReceiptDetails\(transfer\) \{[\s\S]*?\n\}/)?.[0] ?? "";
  const catalogDownloadTransferEventDetailsHelper =
    catalogDownloadOperations.match(/function transferEventReceiptDetails\(details = \{\}\) \{[\s\S]*?\n\}/)?.[0] ?? "";
  const runtimeEngineReceiptBlocks = [
    ...runtimeEngines.matchAll(/state\.lifecycleReceipt\("runtime_engine_(?:select|update|profile_remove)",\s*\{[\s\S]*?\n\s+\}\);/g),
  ].map((match) => match[0]).join("\n");
  const runtimeEngineLatestReceiptFilter =
    runtimeEngines.match(/latestReceipts:\s*state\.listReceipts\(\)[\s\S]*?\.slice\(-8\),/)?.[0] ?? "";
  const runtimeSurveyReceiptDetailsObject =
    runtimeSurveyModule.match(/details:\s*\{[\s\S]*?lm_studio:\s*lmStudio,\n\s+\},/)?.[0] ?? "";
  const stateAccessorNotFoundBlocks = [
    ...stateAccessors.matchAll(/throw notFound\([\s\S]*?\);/g),
  ].map((match) => match[0]).join("\n");
  const lmStudioRequireLmsPathBlock =
    lmStudioProviderDriver.match(/requireLmsPath\(provider\) \{[\s\S]*?\n  \}/)?.[0] ?? "";
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
      /provider_kind:\s*provider\.kind/.test(modelLoadingOperations) &&
      /provider_kind:\s*providerForInstance\(state,\s*instance\)\?\.kind/.test(loadedInstances) &&
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
    "model-mount-instance-lifecycle-detail-aliases-retired",
    /instance_id:\s*instance\.id/.test(modelLoadingOperations) &&
      /endpoint_id:\s*endpoint\.id/.test(modelLoadingOperations) &&
      /model_id:\s*endpoint\.modelId/.test(modelLoadingOperations) &&
      /provider_id:\s*endpoint\.providerId/.test(modelLoadingOperations) &&
      /provider_kind:\s*provider\.kind/.test(modelLoadingOperations) &&
      /backend_process:\s*driverResult\.process/.test(modelLoadingOperations) &&
      /command_args_hash:\s*driverResult\.commandArgsHash/.test(modelLoadingOperations) &&
      /instance_id:\s*instance\.id/.test(loadedInstances) &&
      /notFound\(`No loaded model instance for endpoint: \$\{endpointId\}`,\s*\{ endpoint_id: endpointId \}\)/.test(
        loadedInstances,
      ) &&
      /superseded_by:\s*keepInstanceId/.test(loadedInstances) &&
      /provider_kind:\s*providerForInstance\(state,\s*instance\)\?\.kind/.test(loadedInstances) &&
      /const providerId = details\.provider_id;/.test(modelMountReceiptOperations) &&
      /provider_id:\s*providerId \?\? null/.test(modelMountReceiptOperations) &&
      /const providerKind = optionalNonEmptyString\(details\.provider_kind\)/.test(modelMountReceiptWriteGuards) &&
      /provider_kind:\s*providerKind/.test(modelMountReceiptWriteGuards) &&
      !/\b(?:instanceId|endpointId|modelId|providerId|providerKind|backendId|runtimeEngineId|providerEvidenceRefs|backendProcess|commandArgsHash|supersededBy)\s*:/.test(
        modelInstanceLifecycleReceiptBlocks,
      ) &&
      !/notFound\(`No loaded model instance for endpoint: \$\{endpointId\}`,\s*\{ endpointId \}\)/.test(
        loadedInstances,
      ) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"providerKind"\),\s*false/.test(modelLoadingOperationsTest) &&
      /assert\.equal\(error\.details\.endpoint_id,\s*"endpoint_missing"\)/.test(loadedInstancesTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\[1\],\s*"providerKind"\),\s*false/.test(loadedInstancesTest) &&
      /Object\.hasOwn\(error\.details,\s*"endpointId"\),\s*false/.test(loadedInstancesTest) &&
      /Object\.hasOwn\(error\.details,\s*"providerId"\) === false/.test(modelMountReceiptOperationsTest) &&
      /receipt\.legacy-model-lifecycle/.test(modelMountStoreTest) &&
      /Object\.hasOwn\(error\.details,\s*"providerKind"\) === false/.test(modelMountStoreTest),
    [
      "packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/loaded-instances.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs",
      "packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/loaded-instances.test.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/store.test.mjs",
    ],
    "Phase 9/11 is pending: model-instance lifecycle receipts and fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-tokenizer-receipt-detail-aliases-retired",
    /route_id:\s*selection\.route\.id/.test(modelTokenizerReceiptDetailsObject) &&
      /route_receipt_id:\s*routeReceipt\.id/.test(modelTokenizerReceiptDetailsObject) &&
      /selected_model:\s*selection\.endpoint\.modelId/.test(modelTokenizerReceiptDetailsObject) &&
      /endpoint_id:\s*selection\.endpoint\.id/.test(modelTokenizerReceiptDetailsObject) &&
      /provider_id:\s*selection\.endpoint\.providerId/.test(modelTokenizerReceiptDetailsObject) &&
      /backend_id:\s*selection\.endpoint\.backendId/.test(modelTokenizerReceiptDetailsObject) &&
      /selected_backend:\s*selection\.endpoint\.backendId/.test(modelTokenizerReceiptDetailsObject) &&
      /grant_id:\s*token\.grantId/.test(modelTokenizerReceiptDetailsObject) &&
      /tokenizer_source:\s*"deterministic_estimator"/.test(modelTokenizerReceiptDetailsObject) &&
      /input_hash:\s*stableHash\(input\)/.test(modelTokenizerReceiptDetailsObject) &&
      /token_count:\s*\{/.test(modelTokenizerReceiptDetailsObject) &&
      /context_window:\s*contextWindow/.test(modelTokenizerReceiptDetailsObject) &&
      !/\b(?:routeId|routeReceiptId|selectedModel|endpointId|providerId|backendId|selectedBackend|grantId|tokenizerSource|inputHash|tokenCount|contextWindow)\s*:/.test(
        modelTokenizerReceiptDetailsObject,
      ) &&
      /Object\.hasOwn\(utility\.receipt\.payload\.details,\s*"routeId"\),\s*false/.test(modelTokenizerOperationsTest) &&
      /Object\.hasOwn\(utility\.receipt\.payload\.details,\s*"tokenCount"\),\s*false/.test(modelTokenizerOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.payload\.details,\s*"contextWindow"\),\s*false/.test(
        modelTokenizerOperationsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/tokenizer-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/tokenizer-operations.test.mjs",
    ],
    "Phase 9/11 is pending: tokenizer and context-fit receipts must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-artifact-endpoint-receipt-detail-aliases-retired",
    /model_id:\s*modelId/.test(artifactEndpointReceiptBlocks) &&
      /provider_id:\s*body\.provider_id/.test(artifactEndpointReceiptBlocks) &&
      /source_path_hash:\s*sourceInfo\?\.path/.test(artifactEndpointReceiptBlocks) &&
      /target_path_hash:\s*targetPreview/.test(artifactEndpointReceiptBlocks) &&
      /import_mode:\s*importMode/.test(artifactEndpointReceiptBlocks) &&
      /artifact_id:\s*artifact\.id/.test(artifactEndpointReceiptBlocks) &&
      /artifact_path_hash:\s*artifact\.artifactPath/.test(artifactEndpointReceiptBlocks) &&
      /endpoint_id:\s*endpoint\.id/.test(artifactEndpointReceiptBlocks) &&
      /endpoint_id:\s*endpointId/.test(artifactEndpointReceiptBlocks) &&
      /load_policy:\s*endpoint\.loadPolicy/.test(artifactEndpointReceiptBlocks) &&
      !/\b(?:artifactId|modelId|providerId|sourcePathHash|targetPathHash|importMode|artifactPathHash|endpointId|loadPolicy)\s*:/.test(
        artifactEndpointReceiptBlocks,
      ) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"sourcePathHash"\),\s*false/.test(
        artifactEndpointOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"artifactPathHash"\),\s*false/.test(
        artifactEndpointOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"loadPolicy"\),\s*false/.test(
        artifactEndpointOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"endpointId"\),\s*false/.test(
        artifactEndpointOperationsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.test.mjs",
    ],
    "Phase 9/11 is pending: artifact endpoint lifecycle receipts must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-storage-lifecycle-detail-aliases-retired",
    /job_id:\s*jobId/.test(storageLifecycleReceiptBlocks) &&
      /model_id:\s*job\.modelId/.test(storageLifecycleReceiptBlocks) &&
      /provider_id:\s*job\.providerId/.test(storageLifecycleReceiptBlocks) &&
      /bytes_completed:\s*job\.bytesCompleted/.test(storageLifecycleReceiptBlocks) &&
      /bytes_total:\s*job\.bytesTotal/.test(storageLifecycleReceiptBlocks) &&
      /cleanup_partial:\s*cleanupPartial/.test(storageLifecycleReceiptBlocks) &&
      /cleanup_state:\s*cleanupState/.test(storageLifecycleReceiptBlocks) &&
      /projected_freed_bytes:\s*projectedFreedBytes/.test(storageLifecycleReceiptBlocks) &&
      /artifact_id:\s*artifact\.id/.test(storageLifecycleReceiptBlocks) &&
      /artifact_path_hash:\s*artifact\.artifactPath/.test(storageLifecycleReceiptBlocks) &&
      /affected_endpoint_ids:\s*endpointIds/.test(storageLifecycleReceiptBlocks) &&
      /affected_instance_ids:\s*instanceIds/.test(storageLifecycleReceiptBlocks) &&
      /endpoint_ids:\s*endpointIds/.test(storageLifecycleReceiptBlocks) &&
      /scanned_file_count:\s*files\.length/.test(storageLifecycleReceiptBlocks) &&
      /orphan_count:\s*orphans\.length/.test(storageLifecycleReceiptBlocks) &&
      /orphan_path_hashes:\s*orphans\.map/.test(storageLifecycleReceiptBlocks) &&
      /orphan_bytes:\s*orphanBytes/.test(storageLifecycleReceiptBlocks) &&
      /remove_orphans:\s*removeOrphans/.test(storageLifecycleReceiptBlocks) &&
      /cleaned_bytes:\s*cleanedBytes/.test(storageLifecycleReceiptBlocks) &&
      /removed_orphan_count:\s*removedOrphanCount/.test(storageLifecycleReceiptBlocks) &&
      /destructive_confirmation:\s*destructiveConfirmation/.test(storageLifecycleReceiptBlocks) &&
      /details:\s*\{\s*artifact_id:\s*artifact\.id,\s*instance_ids:\s*instanceIds\s*\}/.test(storageOperations) &&
      /details:\s*\{\s*orphan_count:\s*orphans\.length,\s*projected_freed_bytes:\s*orphanBytes\s*\}/.test(
        storageOperations,
      ) &&
      /notFound\(`Download job not found: \$\{jobId\}`,\s*\{ job_id: jobId \}\)/.test(storageOperations) &&
      !/\b(?:jobId|modelId|providerId|bytesCompleted|bytesTotal|cleanupPartial|cleanupState|projectedFreedBytes|downloadPolicy|artifactId|artifactPathHash|affectedEndpointIds|affectedInstanceIds|endpointIds|scannedFileCount|orphanCount|orphanPathHashes|orphanBytes|removeOrphans|cleanedBytes|removedOrphanCount|destructiveConfirmation)\s*:/.test(
        storageLifecycleReceiptBlocks,
      ) &&
      !/notFound\(`Download job not found: \$\{jobId\}`,\s*\{ jobId \}\)/.test(storageOperations) &&
      !/details:\s*\{\s*(?:artifactId|orphanCount)\b/.test(storageOperations) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"projectedFreedBytes"\),\s*false/.test(
        storageOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"artifactPathHash"\),\s*false/.test(
        storageOperationsTest,
      ) &&
      /assert\.equal\(error\.details\.job_id,\s*"missing"\)/.test(storageOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"jobId"\),\s*false/.test(storageOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"artifactId"\)\s*===\s*false/.test(storageOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"orphanCount"\)\s*===\s*false/.test(storageOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/storage-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/storage-operations.test.mjs",
    ],
    "Phase 9/11 is pending: model storage lifecycle receipts and fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-mcp-receipt-detail-aliases-retired",
    /details:\s*mcpServerReceiptDetails\(stored\)/.test(mcpWorkflowOperations) &&
      /details:\s*mcpServerReceiptDetails\(server\)/.test(mcpWorkflowOperations) &&
      /server_url:\s*server\.serverUrl/.test(mcpServerReceiptDetailsHelper) &&
      /allowed_tools:\s*Array\.isArray\(server\.allowedTools\)/.test(mcpServerReceiptDetailsHelper) &&
      /secret_refs:\s*\{ \.\.\.\(server\.secretRefs/.test(mcpServerReceiptDetailsHelper) &&
      /redacted_headers:\s*\{ \.\.\.\(server\.redactedHeaders/.test(mcpServerReceiptDetailsHelper) &&
      /imported_at:\s*server\.importedAt/.test(mcpServerReceiptDetailsHelper) &&
      /server_id:\s*serverId/.test(mcpToolReceiptDetailsObject) &&
      /input_hash:\s*stableHash\(body\.input/.test(mcpToolReceiptDetailsObject) &&
      /output_hash:\s*stableHash\(\{ ok: true, tool \}\)/.test(mcpToolReceiptDetailsObject) &&
      /notFound\(`MCP server not found: \$\{serverId\}`,\s*\{ server_id: serverId \}\)/.test(mcpWorkflowOperations) &&
      /details:\s*\{ server_id: serverId, tool \}/.test(mcpWorkflowOperations) &&
      /workflow_node_id:\s*base\.workflow_node_id/.test(mcpWorkflowOperations) &&
      !/\b(?:serverUrl|allowedTools|secretRefs|redactedHeaders|importedAt)\s*:/.test(mcpServerReceiptDetailsHelper) &&
      !/\b(?:serverId|inputHash|outputHash)\s*:/.test(mcpToolReceiptDetailsObject) &&
      !/details:\s*\{ serverId/.test(mcpWorkflowOperations) &&
      !/details:\s*\{\s*serverId/m.test(mcpWorkflowOperations) &&
      !/workflowNodeId:\s*base\.workflow_node_id/.test(mcpWorkflowOperations) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.payload\.details,\s*"allowedTools"\),\s*false/.test(
        mcpWorkflowOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\[1\]\.payload\.details,\s*"serverUrl"\),\s*false/.test(
        mcpWorkflowOperationsTest,
      ) &&
      /Object\.hasOwn\(result\.receipt\.payload\.details,\s*"serverId"\),\s*false/.test(mcpWorkflowOperationsTest) &&
      /Object\.hasOwn\(result\.receipt\.payload\.details,\s*"inputHash"\),\s*false/.test(mcpWorkflowOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"serverId"\)\s*===\s*false/.test(mcpWorkflowOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"workflowNodeId"\)\s*===\s*false/.test(mcpWorkflowOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.test.mjs",
    ],
    "Phase 9/11 is pending: MCP registration, import, tool invocation receipts, and fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-catalog-download-receipt-detail-aliases-retired",
    /source_url_hash:\s*sourceHash/.test(catalogDownloadErrorDetailsHelper) &&
      /evidence_refs:\s*evidenceRefs/.test(catalogDownloadErrorDetailsHelper) &&
      /auth_vault_ref_hash:\s*evidence\.authVaultRefHash/.test(catalogAuthReceiptDetailsHelper) &&
      /resolved_material:\s*Boolean/.test(catalogAuthReceiptDetailsHelper) &&
      /evidence_refs:\s*evidence\.evidenceRefs/.test(catalogAuthReceiptDetailsHelper) &&
      /max_bytes:\s*policy\.maxBytes/.test(catalogDownloadPolicyReceiptDetailsHelper) &&
      /bandwidth_limit_bps:\s*policy\.bandwidthLimitBps/.test(catalogDownloadPolicyReceiptDetailsHelper) &&
      /retry_limit:\s*policy\.retryLimit/.test(catalogDownloadPolicyReceiptDetailsHelper) &&
      /approval_decision:\s*policy\.approvalDecision/.test(catalogDownloadPolicyReceiptDetailsHelper) &&
      /attempt_count:\s*transfer\.attemptCount/.test(catalogDownloadTransferReceiptDetailsHelper) &&
      /resume_metadata_path_hash:\s*transfer\.resumeMetadataPathHash/.test(catalogDownloadTransferReceiptDetailsHelper) &&
      /next_attempt:\s*details\.nextAttempt/.test(catalogDownloadTransferEventDetailsHelper) &&
      /retry_count:\s*details\.retryCount/.test(catalogDownloadTransferEventDetailsHelper) &&
      /model_id:\s*modelId/.test(catalogImportUrlReceiptDetailsObject) &&
      /provider_id:\s*body\.provider_id/.test(catalogImportUrlReceiptDetailsObject) &&
      /source_url_hash:\s*hash\(sourceUrl\)/.test(catalogImportUrlReceiptDetailsObject) &&
      /source_label:\s*variant\.sourceLabel/.test(catalogImportUrlReceiptDetailsObject) &&
      /parameter_count:\s*variant\.parameterCount/.test(catalogImportUrlReceiptDetailsObject) &&
      /backend_compatibility:\s*variant\.backendCompatibility/.test(catalogImportUrlReceiptDetailsObject) &&
      /download_risk:\s*variant\.downloadRisk/.test(catalogImportUrlReceiptDetailsObject) &&
      /benchmark_readiness:\s*variant\.benchmarkReadiness/.test(catalogImportUrlReceiptDetailsObject) &&
      /selection_receipt_fields:\s*variant\.selectionReceiptFields/.test(catalogImportUrlReceiptDetailsObject) &&
      /catalog_provider_id:\s*variant\.catalogProviderId/.test(catalogImportUrlReceiptDetailsObject) &&
      /catalog_auth:\s*catalogAuthReceiptDetails/.test(catalogImportUrlReceiptDetailsObject) &&
      /approval_decision:\s*approvalDecision/.test(catalogImportUrlReceiptDetailsObject) &&
      /live_download_gate:/.test(catalogImportUrlReceiptDetailsObject) &&
      /job_id:\s*jobBase\.id/.test(catalogDownloadReceiptBlocks) &&
      /model_id:\s*modelId/.test(catalogDownloadReceiptBlocks) &&
      /provider_id:\s*providerId/.test(catalogDownloadReceiptBlocks) &&
      /source_hash:\s*hash\(source\)/.test(catalogDownloadReceiptBlocks) &&
      /target_path_hash:\s*hash\(targetPath\)/.test(catalogDownloadReceiptBlocks) &&
      /max_bytes:\s*maxBytes/.test(catalogDownloadReceiptBlocks) &&
      /download_mode:/.test(catalogDownloadReceiptBlocks) &&
      /download_policy:\s*downloadPolicyReceiptDetails/.test(catalogDownloadReceiptBlocks) &&
      /failure_reason:\s*failureReason/.test(catalogDownloadReceiptBlocks) &&
      /cleanup_state:\s*cleanupState/.test(catalogDownloadReceiptBlocks) &&
      /error_hash:\s*hash/.test(catalogDownloadReceiptBlocks) &&
      /artifact_id:\s*artifact\.id/.test(catalogDownloadReceiptBlocks) &&
      /bytes_completed:\s*completedBytes/.test(catalogDownloadReceiptBlocks) &&
      /resume_offset:\s*materialized\.resumeOffset/.test(catalogDownloadReceiptBlocks) &&
      /attempt_count:\s*materialized\.attemptCount/.test(catalogDownloadReceiptBlocks) &&
      /retry_count:\s*materialized\.retryCount/.test(catalogDownloadReceiptBlocks) &&
      /resume_metadata_path_hash:\s*materialized\.resumeMetadataPathHash/.test(catalogDownloadReceiptBlocks) &&
      /transfer:\s*transferReceiptDetails/.test(catalogDownloadReceiptBlocks) &&
      /\.\.\.transferEventReceiptDetails\(details\)/.test(catalogDownloadTransferReceiptObject) &&
      !/\b(?:modelId|providerId|sourceUrlHash|sourceLabel|parameterCount|backendCompatibility|downloadRisk|benchmarkReadiness|selectionReceiptFields|catalogProviderId|catalogAuth|approvalDecision|liveDownloadGate)\s*:/.test(
        catalogImportUrlReceiptDetailsObject,
      ) &&
      !/\b(?:jobId|modelId|providerId|sourceHash|sourceLabel|targetPathHash|maxBytes|downloadMode|downloadPolicy|failureReason|cleanupState|errorHash|artifactId|bytesCompleted|bytesTotal|resumeOffset|attemptCount|retryCount|resumeMetadataPathHash|backendCompatibility|downloadRisk|benchmarkReadiness|selectionReceiptFields|catalogProviderId|catalogAuth|approvalDecision)\s*:/.test(
        `${catalogDownloadReceiptBlocks}\n${catalogDownloadTransferReceiptObject}`,
      ) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"sourceUrlHash"\),\s*false/.test(catalogDownloadOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"modelId"\),\s*false/.test(catalogDownloadOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details\.catalog_auth,\s*"resolvedMaterial"\),\s*false/.test(
        catalogDownloadOperationsTest,
      ) &&
      /Object\.hasOwn\(error\.details,\s*"evidenceRefs"\) === false/.test(catalogDownloadOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"jobId"\),\s*false/.test(catalogDownloadOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"downloadPolicy"\),\s*false/.test(
        catalogDownloadOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details\.download_policy,\s*"maxBytes"\),\s*false/.test(
        catalogDownloadOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\[2\]\.details,\s*"failureReason"\),\s*false/.test(catalogDownloadOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"artifactId"\),\s*false/.test(
        catalogDownloadOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"bytesCompleted"\),\s*false/.test(
        catalogDownloadOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"resumeOffset"\),\s*false/.test(
        catalogDownloadOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\[2\]\.details,\s*"retryCount"\),\s*false/.test(catalogDownloadOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\[3\]\.details,\s*"attemptCount"\),\s*false/.test(catalogDownloadOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\[3\]\.details,\s*"resumeMetadataPathHash"\),\s*false/.test(
        catalogDownloadOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\[3\]\.details\.transfer,\s*"attemptCount"\),\s*false/.test(
        catalogDownloadOperationsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs",
    ],
    "Phase 9/11 is pending: catalog import/download receipts and fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-catalog-helper-error-detail-aliases-retired",
    /details:\s*\{ import_mode: mode \}/.test(catalogHelpers) &&
      !/details:\s*\{ importMode: mode \}/.test(catalogHelpers) &&
      /assert\.equal\(error\.details\.import_mode,\s*"side_load"\)/.test(catalogHelpersTest) &&
      /Object\.hasOwn\(error\.details,\s*"importMode"\),\s*false/.test(catalogHelpersTest),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-helpers.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-helpers.test.mjs",
    ],
    "Phase 9/11 is pending: catalog helper fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-runtime-engine-detail-aliases-retired",
    /engine_id:\s*engineId/.test(runtimeEngineReceiptBlocks) &&
      /engine_kind:\s*engine\.kind/.test(runtimeEngineReceiptBlocks) &&
      /engine_status:\s*engine\.status/.test(runtimeEngineReceiptBlocks) &&
      /model_format:\s*engine\.modelFormat/.test(runtimeEngineReceiptBlocks) &&
      /default_load_options:\s*engine\.operatorProfile/.test(runtimeEngineReceiptBlocks) &&
      /checked_at:\s*checkedAt/.test(runtimeEngineReceiptBlocks) &&
      /previous_profile_hash:\s*stableHash/.test(runtimeEngineReceiptBlocks) &&
      /had_profile:\s*Boolean/.test(runtimeEngineReceiptBlocks) &&
      /evidence_refs:\s*\["operator_runtime_engine_profile/.test(runtimeEngineReceiptBlocks) &&
      /notFound\(`Runtime engine not found: \$\{engineId\}`,\s*\{ engine_id: engineId \}\)/.test(runtimeEngines) &&
      /details:\s*\{ engine_id: engineId,\s*receipt_id: engine\.operatorProfile\.receiptId/.test(runtimeEngines) &&
      /details\?\.runtime_engine_id === engineId/.test(runtimeEngineLatestReceiptFilter) &&
      /details\?\.engine_id === engineId/.test(runtimeEngineLatestReceiptFilter) &&
      /details\?\.backend_id === engineId/.test(runtimeEngineLatestReceiptFilter) &&
      !/\b(?:engineId|engineKind|engineStatus|modelFormat|defaultLoadOptions|checkedAt|previousProfileHash|hadProfile|evidenceRefs)\s*:/.test(
        runtimeEngineReceiptBlocks,
      ) &&
      !/details:\s*\{\s*engineId\b/.test(runtimeEngines) &&
      !/details\?\.(?:runtimeEngineId|engineId|backendId)\b/.test(runtimeEngineLatestReceiptFilter) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"engineId"\),\s*false/.test(runtimeEnginesTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"defaultLoadOptions"\),\s*false/.test(runtimeEnginesTest) &&
      /Object\.hasOwn\(state\.receipts\[1\]\.details,\s*"previousProfileHash"\),\s*false/.test(runtimeEnginesTest) &&
      /Object\.hasOwn\(error\.details,\s*"engineId"\),\s*false/.test(runtimeEnginesTest) &&
      /Object\.hasOwn\(error\.details,\s*"receiptId"\),\s*false/.test(runtimeEnginesTest) &&
      /receipt_legacy/.test(runtimeEnginesTest) &&
      /details:\s*\{ runtime_engine_id:\s*"backend\.llama-cpp" \}/.test(runtimeEnginesTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"hadProfile"\),\s*false/.test(runtimeEnginesTest),
    [
      "packages/runtime-daemon/src/model-mounting/runtime-engines.mjs",
      "packages/runtime-daemon/src/model-mounting/runtime-engines.test.mjs",
    ],
    "Phase 9/11 is pending: runtime-engine receipts, fail-closed errors, and latest-receipt readers must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-runtime-survey-receipt-detail-aliases-retired",
    /checked_at:\s*checkedAt/.test(runtimeSurveyReceiptDetailsObject) &&
      /engine_count:\s*engines\.length/.test(runtimeSurveyReceiptDetailsObject) &&
      /selected_engines:\s*selectedEngines/.test(runtimeSurveyReceiptDetailsObject) &&
      /runtime_preference:\s*runtimePreference/.test(runtimeSurveyReceiptDetailsObject) &&
      /lm_studio:\s*lmStudio/.test(runtimeSurveyReceiptDetailsObject) &&
      /receipt\.details\?\.checked_at/.test(runtimeSurveyModule) &&
      /receipt\.details\?\.engine_count/.test(runtimeSurveyModule) &&
      /receipt\.details\?\.selected_engines/.test(runtimeSurveyModule) &&
      /receipt\.details\?\.runtime_preference/.test(runtimeSurveyModule) &&
      /receipt\.details\?\.lm_studio/.test(runtimeSurveyModule) &&
      !/\b(?:checkedAt|engineCount|selectedEngines|runtimePreference|lmStudio)\s*:/.test(
        runtimeSurveyReceiptDetailsObject,
      ) &&
      !/receipt\.details\?\.(?:checkedAt|engineCount|selectedEngines|runtimePreference|lmStudio)\b/.test(
        runtimeSurveyModule,
      ) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"checkedAt"\),\s*false/.test(runtimeSurveyTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"engineCount"\),\s*false/.test(runtimeSurveyTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"selectedEngines"\),\s*false/.test(runtimeSurveyTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"runtimePreference"\),\s*false/.test(
        runtimeSurveyTest,
      ) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.details,\s*"lmStudio"\),\s*false/.test(runtimeSurveyTest),
    [
      "packages/runtime-daemon/src/model-mounting/runtime-survey.mjs",
      "packages/runtime-daemon/src/model-mounting/runtime-survey.test.mjs",
    ],
    "Phase 9/11 is pending: runtime survey receipts and readback must use canonical snake_case metadata without duplicate camelCase aliases",
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
    "model-mount-provider-transport-auth-error-aliases-retired",
    /details:\s*\{\s*provider_id:\s*provider\.id,\s*provider_kind:\s*provider\.kind\s*\}/.test(providerTransport) &&
      /provider_id:\s*provider\.id/.test(providerTransport) &&
      /provider_kind:\s*provider\.kind/.test(providerTransport) &&
      /http_status:\s*result\.status/.test(providerTransport) &&
      /provider_error_hash:\s*stableHash/.test(providerTransport) &&
      /provider_error_code:\s*providerError\.code/.test(providerTransport) &&
      /command_exit_code:\s*result\.status/.test(providerTransport) &&
      /stderr_hash:\s*stableHash/.test(providerTransport) &&
      !/(?:providerId|providerKind|httpStatus|providerErrorHash|providerErrorCode|providerErrorType|providerErrorMessage|providerErrorText|commandExitCode|stderrHash)\s*:/.test(
        providerTransport,
      ) &&
      /provider_id:\s*provider\.id/.test(providerAuth) &&
      /provider_kind:\s*provider\.kind/.test(providerAuth) &&
      /vault_ref_configured:\s*false/.test(providerAuth) &&
      /vault_ref_hash:\s*stableHash/.test(providerAuth) &&
      /resolved_material:\s*false/.test(providerAuth) &&
      /auth_scheme:\s*scheme/.test(providerAuth) &&
      /auth_header_name:\s*SECRET_REDACTION/.test(providerAuth) &&
      /auth_header_name:\s*headerName/.test(providerAuth) &&
      !/(?:providerId:\s*provider\.id|providerKind:\s*provider\.kind|vaultRefConfigured:\s*false|vaultRefHash:\s*stableHash|resolvedMaterial:\s*false|authScheme:\s*scheme|authHeaderName:\s*(?:SECRET_REDACTION|headerName))/.test(
        providerAuth,
      ) &&
      /Object\.hasOwn\(httpError\.details,\s*"providerId"\),\s*false/.test(providerTransportTest) &&
      /Object\.hasOwn\(httpError\.details,\s*"httpStatus"\),\s*false/.test(providerTransportTest) &&
      /Object\.hasOwn\(commandError\.details,\s*"commandExitCode"\),\s*false/.test(providerTransportTest) &&
      /Object\.hasOwn\(error\.details,\s*"providerId"\),\s*false/.test(providerAuthTest) &&
      /Object\.hasOwn\(error\.details,\s*"vaultRefHash"\),\s*false/.test(providerAuthTest) &&
      /Object\.hasOwn\(error\.details,\s*"authHeaderName"\),\s*false/.test(providerAuthTest),
    [
      "packages/runtime-daemon/src/model-mounting/provider-transport.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-transport.test.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-auth.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-auth.test.mjs",
    ],
    "Phase 5/11 is pending: provider transport and auth fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-lm-studio-provider-error-aliases-retired",
    /details:\s*\{\s*provider_id:\s*provider\.id,\s*evidence_refs:\s*\["lm_studio_public_cli_absent"\]\s*\}/.test(
      lmStudioRequireLmsPathBlock,
    ) &&
      !/\b(?:providerId|evidenceRefs)\s*:/.test(lmStudioRequireLmsPathBlock) &&
      /assert\.equal\(error\.details\.provider_id,\s*"provider\.lmstudio"\)/.test(lmStudioProviderDriverTest) &&
      /Object\.hasOwn\(error\.details,\s*"providerId"\),\s*false/.test(lmStudioProviderDriverTest) &&
      /Object\.hasOwn\(error\.details,\s*"evidenceRefs"\),\s*false/.test(lmStudioProviderDriverTest),
    [
      "packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-lm-studio-driver.test.mjs",
    ],
    "Phase 5/11 is pending: LM Studio provider fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-state-accessor-error-aliases-retired",
    /notFound\(`Provider not found: \$\{providerId\}`,\s*\{ provider_id: providerId \}\)/.test(
      stateAccessorNotFoundBlocks,
    ) &&
      /notFound\(`Endpoint not found: \$\{endpointId\}`,\s*\{ endpoint_id: endpointId \}\)/.test(
        stateAccessorNotFoundBlocks,
      ) &&
      /notFound\(`Model instance not found: \$\{instanceId\}`,\s*\{ instance_id: instanceId \}\)/.test(
        stateAccessorNotFoundBlocks,
      ) &&
      /notFound\(`Route not found: \$\{routeId\}`,\s*\{ route_id: routeId \}\)/.test(
        stateAccessorNotFoundBlocks,
      ) &&
      /notFound\(`Model not found: \$\{id\}`,\s*\{ model_id: id \}\)/.test(stateAccessorNotFoundBlocks) &&
      !/\b(?:providerId|endpointId|instanceId|routeId|modelId)\s*:/.test(stateAccessorNotFoundBlocks) &&
      /hasCanonicalNotFoundDetail\(error,\s*"provider_id",\s*"missing",\s*"providerId"\)/.test(
        stateAccessorsTest,
      ) &&
      /hasCanonicalNotFoundDetail\(error,\s*"endpoint_id",\s*"endpoint\.unmounted",\s*"endpointId"\)/.test(
        stateAccessorsTest,
      ) &&
      /hasCanonicalNotFoundDetail\(error,\s*"instance_id",\s*"missing",\s*"instanceId"\)/.test(
        stateAccessorsTest,
      ) &&
      /hasCanonicalNotFoundDetail\(error,\s*"route_id",\s*"missing",\s*"routeId"\)/.test(stateAccessorsTest) &&
      /hasCanonicalNotFoundDetail\(error,\s*"model_id",\s*"missing",\s*"modelId"\)/.test(stateAccessorsTest) &&
      /Object\.hasOwn\(error\.details,\s*retiredKey\),\s*false/.test(stateAccessorsTest),
    [
      "packages/runtime-daemon/src/model-mounting/state-accessors.mjs",
      "packages/runtime-daemon/src/model-mounting/state-accessors.test.mjs",
    ],
    "Phase 9/11 is pending: model-mount state accessor fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-catalog-provider-auth-error-detail-aliases-retired",
    /details:\s*\{\s*provider_id:\s*providerId\s*\}/.test(catalogProviderConfig) &&
      /details:\s*\{\s*auth_scheme:\s*scheme\s*\}/.test(catalogProviderConfig) &&
      /catalog_provider_id:\s*providerId/.test(catalogProviderConfig) &&
      /auth_vault_ref_hash:\s*config\.authVaultRefHash/.test(catalogProviderConfig) &&
      /auth_vault_ref_hash:\s*resolved\?\.vaultRefHash/.test(catalogProviderConfig) &&
      /resolved_material:\s*false/.test(catalogProviderConfig) &&
      /catalog_auth_scheme:\s*authScheme/.test(catalogProviderConfig) &&
      /catalog_auth_header_name_hash:\s*stableHash\(headerName\)/.test(catalogProviderConfig) &&
      /evidence_refs:\s*\["catalog_auth_fail_closed",\s*"vault_ref_required"\]/.test(catalogProviderConfig) &&
      /evidence_refs:\s*normalizeScopes/.test(catalogProviderConfig) &&
      !/details:\s*\{[^}]*\b(?:providerId|authScheme|catalogProviderId|authVaultRefHash|resolvedMaterial|catalogAuthScheme|catalogAuthHeaderNameHash|evidenceRefs)\s*:/.test(
        catalogProviderConfig,
      ) &&
      /Object\.hasOwn\(error\.details,\s*"providerId"\),\s*false/.test(catalogProviderConfigTest) &&
      /Object\.hasOwn\(error\.details,\s*"authScheme"\),\s*false/.test(catalogProviderConfigTest) &&
      /Object\.hasOwn\(error\.details,\s*"catalogProviderId"\),\s*false/.test(catalogProviderConfigTest) &&
      /Object\.hasOwn\(error\.details,\s*"authVaultRefHash"\),\s*false/.test(catalogProviderConfigTest) &&
      /Object\.hasOwn\(error\.details,\s*"resolvedMaterial"\),\s*false/.test(catalogProviderConfigTest) &&
      /Object\.hasOwn\(error\.details,\s*"catalogAuthScheme"\),\s*false/.test(catalogProviderConfigTest) &&
      /Object\.hasOwn\(error\.details,\s*"catalogAuthHeaderNameHash"\),\s*false/.test(catalogProviderConfigTest) &&
      /Object\.hasOwn\(error\.details,\s*"evidenceRefs"\),\s*false/.test(catalogProviderConfigTest),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs",
    ],
    "Phase 7/11 is pending: catalog provider auth/config fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-oauth-error-detail-aliases-retired",
    /details:\s*\{\s*provider_id:\s*providerId\s*\}/.test(oauthCredentialProvider) &&
      /state_provider_id:\s*stateRecord\.providerId/.test(oauthCredentialProvider) &&
      /oauth_state_hash:\s*stableHash\(stateRecord\.id\)/.test(oauthCredentialProvider) &&
      /callback_state_hash:\s*stableHash\(callbackState\)/.test(oauthCredentialProvider) &&
      /client_secret:\s*SECRET_REDACTION/.test(oauthCredentialProvider) &&
      /client_secret_vault_ref_hash:\s*clientSecret\?\.vaultRefHash/.test(oauthCredentialProvider) &&
      /oauth_session_hash:\s*stableHash\(session\.id\)/.test(oauthCredentialProvider) &&
      /auth_vault_ref_hash:\s*access\?\.vaultRefHash/.test(oauthCredentialProvider) &&
      /resolved_material:\s*false/.test(oauthCredentialProvider) &&
      /catalog_auth_scheme:\s*"oauth2"/.test(oauthCredentialProvider) &&
      /catalog_auth_header_name_hash:\s*stableHash\(headerName\)/.test(oauthCredentialProvider) &&
      /oauth_boundary:\s*oauthBoundaryForSession/.test(oauthCredentialProvider) &&
      /evidence_refs:\s*normalizeScopes/.test(oauthCredentialProvider) &&
      /token_endpoint_hash:\s*stableHash\(tokenEndpoint\)/.test(oauthBoundary) &&
      /error_hash:\s*stableHash\(`oauth:\$\{response\.status\}`\)/.test(oauthBoundary) &&
      /details:\s*\{\s*evidence_refs:\s*\["OAuthCredentialProvider\.tokenEndpoint",\s*"oauth_access_token_required"\]\s*\}/.test(
        oauthBoundary,
      ) &&
      !/details:\s*\{\s*(?:providerId|clientSecret|oauthSessionHash|tokenEndpointHash|evidenceRefs)\b/.test(
        `${oauthCredentialProvider}\n${oauthBoundary}`,
      ) &&
      /Object\.hasOwn\(error\.details,\s*"providerId"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"stateProviderId"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"oauthStateHash"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"callbackStateHash"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"clientSecret"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"clientSecretVaultRefHash"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"oauthSessionHash"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"authVaultRefHash"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"resolvedMaterial"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"catalogAuthScheme"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"catalogAuthHeaderNameHash"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"oauthBoundary"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"evidenceRefs"\),\s*false/.test(oauthCredentialProviderTest) &&
      /Object\.hasOwn\(error\.details,\s*"tokenEndpointHash"\),\s*false/.test(oauthBoundaryTest) &&
      /Object\.hasOwn\(error\.details,\s*"errorHash"\),\s*false/.test(oauthBoundaryTest) &&
      /Object\.hasOwn\(error\.details,\s*"evidenceRefs"\),\s*false/.test(oauthBoundaryTest),
    [
      "packages/runtime-daemon/src/model-mounting/oauth-credential-provider.mjs",
      "packages/runtime-daemon/src/model-mounting/oauth-credential-provider.test.mjs",
      "packages/runtime-daemon/src/model-mounting/oauth-boundary.mjs",
      "packages/runtime-daemon/src/model-mounting/oauth-boundary.test.mjs",
    ],
    "Phase 7/11 is pending: OAuth credential and token-endpoint fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-catalog-oauth-receipt-detail-aliases-retired",
    /provider_id:\s*providerId/.test(catalogProviderOAuth) &&
      /oauth_state:\s*started\.evidence/.test(catalogProviderOAuth) &&
      /authorization_url_hash:\s*started\.authorizationUrlHash/.test(catalogProviderOAuth) &&
      /authorization_url_redacted:\s*started\.authorizationUrlRedacted/.test(catalogProviderOAuth) &&
      /catalog_provider:\s*publicRecord/.test(catalogProviderOAuth) &&
      /oauth_session:\s*(?:completed\.sessionEvidence|evidence|publicOAuthSession)/.test(catalogProviderOAuth) &&
      /oauth_session_hash:\s*config\?\.oauthSessionId/.test(catalogProviderOAuth) &&
      !/details:\s*\{\s*providerId\b/.test(catalogProviderOAuth) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.payload\.details,\s*"providerId"\),\s*false/.test(catalogProviderOAuthTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.payload\.details,\s*"oauthState"\),\s*false/.test(catalogProviderOAuthTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.payload\.details,\s*"authorizationUrlHash"\),\s*false/.test(catalogProviderOAuthTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.payload\.details,\s*"authorizationUrlRedacted"\),\s*false/.test(catalogProviderOAuthTest) &&
      /Object\.hasOwn\(state\.receipts\[0\]\.payload\.details,\s*"catalogProvider"\),\s*false/.test(catalogProviderOAuthTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.payload\.details,\s*"oauthSession"\),\s*false/.test(catalogProviderOAuthTest) &&
      /Object\.hasOwn\(error\.details,\s*"providerId"\),\s*false/.test(catalogProviderOAuthTest) &&
      /Object\.hasOwn\(error\.details,\s*"oauthSessionHash"\),\s*false/.test(catalogProviderOAuthTest),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-provider-oauth.test.mjs",
    ],
    "Phase 7/11 is pending: catalog OAuth accepted receipts and missing-session errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-backend-lifecycle-detail-aliases-retired",
    /backend_id:\s*backendId/.test(backendLifecycle) &&
      /model_id:\s*backend\.label/.test(backendLifecycle) &&
      /evidence_refs:\s*backend\.evidenceRefs/.test(backendLifecycle) &&
      /details:\s*\{\s*backend_id:\s*backendId,\s*backend_kind:\s*backend\.kind,\s*evidence_refs:\s*backend\.evidenceRefs/.test(backendLifecycle) &&
      /log_count:\s*resolved\.length/.test(backendLifecycle) &&
      !/details:\s*\{\s*backendId\b/.test(backendLifecycle) &&
      /details\.model_id\s*\?\?\s*details\.modelId/.test(modelMountReceiptOperations) &&
      /lifecycle receipt summary accepts canonical snake_case subject fields/.test(modelMountReceiptOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"backendId"\),\s*false/.test(backendLifecycleTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"modelId"\),\s*false/.test(backendLifecycleTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"logCount"\),\s*false/.test(backendLifecycleTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"evidenceRefs"\),\s*false/.test(backendLifecycleTest) &&
      /Object\.hasOwn\(error\.details,\s*"backendId"\),\s*false/.test(backendLifecycleTest) &&
      /Object\.hasOwn\(error\.details,\s*"backendKind"\),\s*false/.test(backendLifecycleTest) &&
      /Object\.hasOwn\(error\.details,\s*"evidenceRefs"\),\s*false/.test(backendLifecycleTest),
    [
      "packages/runtime-daemon/src/model-mounting/backend-lifecycle.mjs",
      "packages/runtime-daemon/src/model-mounting/backend-lifecycle.test.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-operations.test.mjs",
    ],
    "Phase 10/11 is pending: backend lifecycle receipts and fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-backend-process-error-aliases-retired",
    /notFound\(`Model backend not found: \$\{backendId\}`,\s*\{ backend_id: backendId \}\)/.test(
      backendProcesses,
    ) &&
      !/notFound\(`Model backend not found: \$\{backendId\}`,\s*\{ backendId \}\)/.test(backendProcesses) &&
      /assert\.equal\(error\.details\.backend_id,\s*"backend\.missing"\)/.test(backendProcessesTest) &&
      /Object\.hasOwn\(error\.details,\s*"backendId"\),\s*false/.test(backendProcessesTest),
    [
      "packages/runtime-daemon/src/model-mounting/backend-processes.mjs",
      "packages/runtime-daemon/src/model-mounting/backend-processes.test.mjs",
    ],
    "Phase 10/11 is pending: backend process lookup fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-local-system-probe-error-aliases-retired",
    /notFound\(`Local model artifact path not found: \$\{sourcePath\}`,\s*\{ source_path: absolutePath \}\)/.test(
      localSystemProbes,
    ) &&
      /notFound\(`No model artifact files found in \$\{dir\}`,\s*\{ dir_path: dir \}\)/.test(localSystemProbes) &&
      !/notFound\(`Local model artifact path not found: \$\{sourcePath\}`,\s*\{ sourcePath: absolutePath \}\)/.test(
        localSystemProbes,
      ) &&
      !/notFound\(`No model artifact files found in \$\{dir\}`,\s*\{ dir \}\)/.test(localSystemProbes) &&
      /assert\.equal\(error\.details\.source_path,\s*path\.join\(tempDir,\s*"missing\.gguf"\)\)/.test(
        localSystemProbesTest,
      ) &&
      /assert\.equal\(error\.details\.dir_path,\s*emptyDir\)/.test(localSystemProbesTest) &&
      /Object\.hasOwn\(error\.details,\s*"sourcePath"\),\s*false/.test(localSystemProbesTest) &&
      /Object\.hasOwn\(error\.details,\s*"dir"\),\s*false/.test(localSystemProbesTest),
    [
      "packages/runtime-daemon/src/model-mounting/local-system-probes.mjs",
      "packages/runtime-daemon/src/model-mounting/local-system-probes.test.mjs",
    ],
    "Phase 9/11 is pending: local system probe fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-provider-operation-detail-aliases-retired",
    /provider_id:\s*providerId/.test(providerOperations) &&
      /provider_kind:\s*provider\.kind/.test(providerOperations) &&
      /http_status:\s*driverResult\.httpStatus/.test(providerOperations) &&
      /auth_vault_ref_hash:\s*driverResult\.authEvidence\?\.vaultRefHash/.test(providerOperations) &&
      /provider_auth_evidence_refs:\s*driverResult\.authEvidence\?\.evidenceRefs/.test(providerOperations) &&
      /failure_code:\s*error\?\.code/.test(providerOperations) &&
      /provider_health_status:\s*status/.test(providerOperations) &&
      /provider_health_receipt_id:\s*receipt\.id/.test(providerOperations) &&
      /model_count:\s*resolved\.length/.test(providerOperations) &&
      /loaded_count:\s*resolved\.length/.test(providerOperations) &&
      !/details:\s*\{[^}]*\b(?:providerId|providerKind|httpStatus|authVaultRefHash|providerAuthEvidenceRefs|providerAuthHeaderNames|failureCode|failureStatus|providerErrorHash|vaultRefConfigured|resolvedMaterial|modelId|modelCount|loadedCount|evidenceRefs|providerHealthStatus|providerHealthReceiptId)\s*:/.test(
        providerOperations,
      ) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.payload\.details,\s*"providerId"\),\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.payload\.details,\s*"httpStatus"\),\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"providerHealthStatus"\),\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-2\)\.details,\s*"modelCount"\),\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"loadedCount"\),\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"providerId"\)\s*===\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(receipt\.details,\s*"providerKind"\)/.test(providerOperationsTest) &&
      /details\.providerId \?\? details\.provider_id/.test(modelMountReceiptWriteGuards) &&
      /missing\.push\("provider_kind"\)/.test(modelMountReceiptWriteGuards),
    [
      "packages/runtime-daemon/src/model-mounting/provider-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-write-guards.mjs",
    ],
    "Phase 9/11 is pending: provider operation receipts and fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-wallet-authority-audit-append-retired",
    !/\bappendOperation\b/.test(walletAuthority) &&
      /wallet authority creates grants and records authorization use without local operation append/.test(walletAuthorityTest),
    [
      "packages/runtime-daemon/src/model-mounting/wallet-authority.mjs",
      "packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs",
    ],
    "Phase 7/11 is pending: wallet authority audit mirroring must not append JS operation-like records outside wallet.network and admitted receipt paths",
  );
  assertCheck(
    result,
    "model-mount-capability-token-error-detail-aliases-retired",
    /details:\s*\{\s*required_scope:\s*requiredScope\s*\}/.test(capabilityTokenOperations) &&
      /notFoundDep\(`Token not found: \$\{tokenId\}`,\s*\{\s*token_id:\s*tokenId\s*\}\)/.test(
        capabilityTokenOperations,
      ) &&
      !/details:\s*\{\s*requiredScope\s*\}/.test(capabilityTokenOperations) &&
      !/notFoundDep\(`Token not found: \$\{tokenId\}`,\s*\{\s*tokenId\s*\}\)/.test(
        capabilityTokenOperations,
      ) &&
      /Object\.hasOwn\(error\.details,\s*"requiredScope"\),\s*false/.test(capabilityTokenOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"tokenId"\),\s*false/.test(capabilityTokenOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/capability-token-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/capability-token-operations.test.mjs",
    ],
    "Phase 7/11 is pending: capability token fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-wallet-vault-error-detail-aliases-retired",
    /details:\s*\{\s*required_scope:\s*requiredScope,\s*grant_id:\s*token\.grantId,\s*revocation_epoch:\s*token\.revocationEpoch\s*\}/.test(
      walletAuthority,
    ) &&
      /details:\s*\{\s*required_scope:\s*requiredScope,\s*grant_id:\s*token\.grantId\s*\}/.test(walletAuthority) &&
      /details:\s*\{\s*vault_ref:\s*SECRET_REDACTION\s*\}/.test(walletAuthority) &&
      !/details:\s*\{[^}]*\b(?:requiredScope|grantId|revocationEpoch|vaultRef)\s*:/.test(walletAuthority) &&
      /details:\s*\{\s*adapter:\s*"encrypted_keychain_vault_adapter",\s*path_hash:\s*stableHash\(this\.filePath\),\s*error:/.test(
        vaultPort,
      ) &&
      /path_configured:\s*Boolean\(this\.filePath\)/.test(vaultPort) &&
      /key_configured:\s*Boolean\(this\.keyMaterial\)/.test(vaultPort) &&
      /details:\s*\{\s*vault_ref:\s*SECRET_REDACTION,\s*purpose\s*\}/.test(vaultPort) &&
      /details:\s*\{\s*vault_ref:\s*SECRET_REDACTION,\s*material:\s*SECRET_REDACTION\s*\}/.test(vaultPort) &&
      !/details:\s*\{[^}]*\b(?:pathHash|pathConfigured|keyConfigured|vaultRef)\s*:/.test(vaultPort) &&
      /Object\.hasOwn\(error\.details,\s*"requiredScope"\),\s*false/.test(walletAuthorityTest) &&
      /Object\.hasOwn\(error\.details,\s*"grantId"\),\s*false/.test(walletAuthorityTest) &&
      /Object\.hasOwn\(error\.details,\s*"revocationEpoch"\),\s*false/.test(walletAuthorityTest) &&
      /Object\.hasOwn\(error\.details,\s*"vaultRef"\),\s*false/.test(walletAuthorityTest) &&
      /Object\.hasOwn\(error\.details,\s*"pathConfigured"\),\s*false/.test(vaultPortTest) &&
      /Object\.hasOwn\(error\.details,\s*"keyConfigured"\),\s*false/.test(vaultPortTest) &&
      /Object\.hasOwn\(error\.details,\s*"vaultRef"\),\s*false/.test(vaultPortTest),
    [
      "packages/runtime-daemon/src/model-mounting/wallet-authority.mjs",
      "packages/runtime-daemon/src/model-mounting/wallet-authority.test.mjs",
      "packages/runtime-daemon/src/model-mounting/vault-port.mjs",
      "packages/runtime-daemon/src/model-mounting/vault-port.test.mjs",
    ],
    "Phase 7/11 is pending: wallet authority and vault fail-closed errors must use canonical snake_case metadata without duplicate camelCase aliases",
  );
  assertCheck(
    result,
    "model-mount-vault-audit-append-retired",
    !/\bappendOperation\b/.test(vaultPort) &&
      /vault port resolves environment aliases and keeps metadata public without local operation append/.test(vaultPortTest),
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
      /notFound\(`Receipt not found: \$\{receiptId\}`,\s*\{ receipt_id: receiptId \}\)/.test(modelMountStore) &&
      !/notFound\(`Receipt not found: \$\{receiptId\}`,\s*\{ receiptId \}\)/.test(modelMountStore) &&
      /agentgres_receipt_projection_boundary/.test(modelMountReceiptOperations) &&
      /model invocation receipt writes persist only after Rust receipt and Agentgres admission without operation append/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ) &&
      /receipt lookup returns persisted receipts and fails closed with canonical details/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ) &&
      /assert\.equal\(error\.details\.receipt_id,\s*"receipt\.missing"\)/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ) &&
      /Object\.hasOwn\(error\.details,\s*"receiptId"\),\s*false/.test(
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
      /provider_stream_shape_summary/.test(conversationOps) &&
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
    /request\.(?:message|input|subagent_prompt|subagentPrompt|subagentRole|maxConcurrency|subagentMaxConcurrency|modelRouteId|subagentModelRoute|outputContract|subagentOutputContract|workflowGraphId|workflowNodeId|parentTurnId|turnId|contextPressureAction|contextPressure|pressureStatus|alertId|sourceEventId|receiptRefs|policyDecisionRefs|toolPack|subagentToolPack|forkContext|mergePolicy|cancellationInheritance)\b/;
  const runtimeSubagentSendInputRequestAliasReadPattern =
    /request\.(?:message|prompt|text|subagent_input|subagentInput|workflowGraphId|workflowNodeId)\b/;
  const runtimeSubagentResumeRequestAliasReadPattern =
    /request\.(?:message|input|resume_prompt|resumePrompt|subagentRole|modelRouteId|subagentModelRoute|workflowGraphId|workflowNodeId)\b/;
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
  const agentSdkTesting = exists("packages/agent-sdk/src/testing.ts")
    ? read("packages/agent-sdk/src/testing.ts")
    : "";
  const agentSdkQuickstartLocal = exists("packages/agent-sdk/examples/quickstart-local.ts")
    ? read("packages/agent-sdk/examples/quickstart-local.ts")
    : "";
  const agentSdkTest = exists("packages/agent-sdk/test/sdk.test.mjs")
    ? read("packages/agent-sdk/test/sdk.test.mjs")
    : "";
  const runtimeCompletePlus = exists("scripts/evidence/runtime-complete-plus.mjs")
    ? read("scripts/evidence/runtime-complete-plus.mjs")
    : "";
  const cursorSdkParityContract = exists("scripts/lib/cursor-sdk-parity-contract.mjs")
    ? read("scripts/lib/cursor-sdk-parity-contract.mjs")
    : "";
  const preNextLegReadiness = exists("scripts/check-pre-next-leg-readiness.mjs")
    ? read("scripts/check-pre-next-leg-readiness.mjs")
    : "";
  const runtimeLayoutCheck = exists("scripts/check-runtime-layout.mjs")
    ? read("scripts/check-runtime-layout.mjs")
    : "";
  const runtimeActionContractsGenerator = exists("scripts/generate-runtime-action-contracts.mjs")
    ? read("scripts/generate-runtime-action-contracts.mjs")
    : "";
  const executionSurfaceLeg = exists("scripts/check-execution-surface-leg.mjs")
    ? read("scripts/check-execution-surface-leg.mjs")
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
  const runtimeSubagentSdkBudgetStatusBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentBudgetStatus",
    "export interface RuntimeSubagentRequestMetadataInput",
  );
  const runtimeSubagentSdkRequestMetadataInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentRequestMetadataInput",
    "export interface RuntimeSubagentBudgetControlInput",
  );
  const runtimeSubagentSdkBudgetControlInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentBudgetControlInput",
    "export interface RuntimeSubagentSpawnInput",
  );
  const runtimeSubagentSdkSpawnInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentSpawnInput",
    "export interface RuntimeSubagentWaitInput",
  );
  const runtimeSubagentSdkWaitInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentWaitInput",
    "export interface RuntimeSubagentSendInput",
  );
  const runtimeSubagentSdkSendInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentSendInput",
    "export interface RuntimeSubagentCancelInput",
  );
  const runtimeSubagentSdkCancelInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentCancelInput",
    "export interface RuntimeSubagentResumeInput",
  );
  const runtimeSubagentSdkResumeInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentResumeInput",
    "export interface RuntimeSubagentAssignInput",
  );
  const runtimeSubagentSdkAssignInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentAssignInput",
    "export interface RuntimeSubagentCancellationPropagationInput",
  );
  const runtimeSubagentSdkCancellationPropagationInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentCancellationPropagationInput",
    "export interface RuntimeSubagentListInput",
  );
  const runtimeSubagentSdkListInputBlock = blockBetween(
    agentSdkSubstrateClient,
    "export interface RuntimeSubagentListInput",
    "export interface RuntimeSubagentRecord",
  );
  const runtimeSubagentSdkRequestInputBlocks = [
    runtimeSubagentSdkRequestMetadataInputBlock,
    runtimeSubagentSdkBudgetControlInputBlock,
    runtimeSubagentSdkSpawnInputBlock,
    runtimeSubagentSdkWaitInputBlock,
    runtimeSubagentSdkSendInputBlock,
    runtimeSubagentSdkCancelInputBlock,
    runtimeSubagentSdkResumeInputBlock,
    runtimeSubagentSdkAssignInputBlock,
    runtimeSubagentSdkCancellationPropagationInputBlock,
  ].join("\n");
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
      /message: "Message alias spawn request"/.test(runtimeSubagentSurfaceTest) &&
      /input: "Input alias spawn request"/.test(runtimeSubagentSurfaceTest) &&
      /subagent_prompt: "Snake alias spawn request"/.test(
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
      /message: "Message alias-only follow up"/.test(runtimeSubagentSurfaceTest) &&
      /prompt: "Prompt alias-only follow up"/.test(runtimeSubagentSurfaceTest) &&
      /text: "Text alias-only follow up"/.test(runtimeSubagentSurfaceTest) &&
      /subagent_input: "Snake alias-only follow up"/.test(
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
      /message: "Message alias-only resume prompt"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /input: "Input alias-only resume prompt"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /resume_prompt: "Snake alias-only resume prompt"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /resumePrompt: "Camel alias-only resume prompt"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /prompt: "Canonical resume prompt"/.test(runtimeSubagentSurfaceTest) &&
      /message: "Message alias resume prompt"/.test(runtimeSubagentSurfaceTest) &&
      /input: "Input alias resume prompt"/.test(runtimeSubagentSurfaceTest) &&
      /resume_prompt: "Snake alias resume prompt"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /resumePrompt: "Camel alias resume prompt"/.test(
        runtimeSubagentSurfaceTest,
      ) &&
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
    "agent-sdk-subagent-budget-status-aliases-retired",
    runtimeSubagentSdkBudgetStatusBlock.length > 0 &&
      /^\s*schema_version\?: string;/m.test(runtimeSubagentSdkBudgetStatusBlock) &&
      /^\s*policy_decision\?: Record<string, unknown> \| null;/m.test(
        runtimeSubagentSdkBudgetStatusBlock,
      ) &&
      /^\s*checked_at\?: string;/m.test(runtimeSubagentSdkBudgetStatusBlock) &&
      !/^\s*(?:schemaVersion|policyDecision|checkedAt)\?:/m.test(
        runtimeSubagentSdkBudgetStatusBlock,
      ) &&
      !/^\s*\[key: string\]: unknown;/m.test(
        runtimeSubagentSdkBudgetStatusBlock,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent budget status type must not advertise retired camelCase aliases or arbitrary-key escape hatches",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-method-request-types-split",
    runtimeSubagentSdkRequestMetadataInputBlock.length > 0 &&
      runtimeSubagentSdkBudgetControlInputBlock.length > 0 &&
      runtimeSubagentSdkSpawnInputBlock.length > 0 &&
      runtimeSubagentSdkWaitInputBlock.length > 0 &&
      runtimeSubagentSdkSendInputBlock.length > 0 &&
      runtimeSubagentSdkCancelInputBlock.length > 0 &&
      runtimeSubagentSdkResumeInputBlock.length > 0 &&
      runtimeSubagentSdkAssignInputBlock.length > 0 &&
      runtimeSubagentSdkCancellationPropagationInputBlock.length > 0 &&
      /spawnSubagent\(threadId: string, input: RuntimeSubagentSpawnInput\)/.test(
        agentSdkSubstrateClient,
      ) &&
      /input\?: RuntimeSubagentWaitInput/.test(agentSdkSubstrateClient) &&
      /input: RuntimeSubagentSendInput/.test(agentSdkSubstrateClient) &&
      /input\?: RuntimeSubagentCancelInput/.test(agentSdkSubstrateClient) &&
      /input\?: RuntimeSubagentResumeInput/.test(agentSdkSubstrateClient) &&
      /input\?: RuntimeSubagentAssignInput/.test(agentSdkSubstrateClient) &&
      /input\?: RuntimeSubagentCancellationPropagationInput/.test(
        agentSdkSubstrateClient,
      ) &&
      !/RuntimeSubagentControlInput/.test(agentSdkSubstrateClient),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent methods must expose operation-specific request input types instead of the retired shared control bag",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-budget-request-type-alias-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*budget\?: Record<string, unknown>;/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ) &&
      !/^\s*subagentBudget\?:/m.test(runtimeSubagentSdkRequestInputBlocks),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise the retired subagentBudget alias",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-prompt-request-type-aliases-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*prompt: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*input: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      !/^\s*(?:message|text)\?: string;/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired message/text prompt aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-role-request-type-alias-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      runtimeSubagentSdkListInputBlock.length > 0 &&
      /^\s*role\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*subagent_role\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*role\?: string;/m.test(runtimeSubagentSdkListInputBlock) &&
      /^\s*subagent_role\?: string;/m.test(runtimeSubagentSdkListInputBlock) &&
      !/^\s*subagentRole\?:/m.test(
        `${runtimeSubagentSdkRequestInputBlocks}\n${runtimeSubagentSdkListInputBlock}`,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent request types must not advertise the retired subagentRole alias",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-tool-pack-request-type-aliases-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*tool_pack\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      !/^\s*(?:toolPack|subagentToolPack)\?:/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired toolPack/subagentToolPack aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-model-route-request-type-aliases-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*model_route_id\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      !/^\s*(?:modelRouteId|subagentModelRoute)\?:/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired modelRouteId/subagentModelRoute aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-concurrency-request-type-aliases-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*max_concurrency\?: number;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      !/^\s*(?:maxConcurrency|subagentMaxConcurrency)\?:/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired maxConcurrency/subagentMaxConcurrency aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-output-contract-request-type-aliases-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*output_contract\?: string\[\] \| Record<string, unknown>;/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ) &&
      !/^\s*(?:outputContract|subagentOutputContract)\?:/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired outputContract/subagentOutputContract aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-policy-request-type-aliases-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*merge_policy\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*cancellation_inheritance\?: "propagate" \| "isolated" \| string;/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ) &&
      !/^\s*(?:mergePolicy|cancellationInheritance)\?:/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired mergePolicy/cancellationInheritance aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-cancellation-metadata-request-type-aliases-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*cancellation_reason\?: string;/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ) &&
      /^\s*inherited\?: boolean;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*cancellation_inherited\?: boolean;/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ) &&
      /^\s*propagated_from_thread_id\?: string;/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ) &&
      !/^\s*(?:cancellationReason|cancellationInherited|propagatedFromThreadId)\?:/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired cancellation metadata aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-context-routing-request-type-aliases-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*fork_context\?: boolean;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*parent_turn_id\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*turn_id\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*target_agent_id\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      !/^\s*(?:forkContext|parentTurnId|turnId|targetAgentId)\?:/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired context routing aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-workflow-request-type-aliases-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      /^\s*workflow_graph_id\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*workflow_node_id\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      /^\s*idempotency_key\?: string;/m.test(runtimeSubagentSdkRequestInputBlocks) &&
      !/^\s*(?:workflowGraphId|workflowNodeId|idempotencyKey)\?:/m.test(
        runtimeSubagentSdkRequestInputBlocks,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent control request types must not advertise retired workflow/idempotency aliases",
  );
  assertCheck(
    result,
    "agent-sdk-subagent-request-type-escape-hatches-retired",
    runtimeSubagentSdkRequestInputBlocks.length > 0 &&
      runtimeSubagentSdkListInputBlock.length > 0 &&
      !/^\s*\[key: string\]: unknown;/m.test(
        `${runtimeSubagentSdkRequestInputBlocks}\n${runtimeSubagentSdkListInputBlock}`,
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
    "agent-sdk-testing-mock-client-helper-retired",
    !/createMockRuntimeSubstrateClient/.test(
      [
        agentSdkSubstrateClient,
        agentSdkTesting,
        agentSdkQuickstartLocal,
        runtimeCompletePlus,
      ].join("\n"),
    ) &&
      !/explicitMockFactory:/.test(agentSdkSubstrateClient) &&
      /!\("explicitMockFactory" in error\.details\)/.test(agentSdkTest) &&
      /mock_projection_helper_retired/.test(cursorSdkParityContract) &&
      /!\("createMockRuntimeSubstrateClient" in sdk\)/.test(
        cursorSdkParityContract,
      ) &&
      /!\("createMockRuntimeSubstrateClient" in testing\)/.test(
        cursorSdkParityContract,
      ) &&
      !/testing\.createMockRuntimeSubstrateClient/.test(
        cursorSdkParityContract,
      ) &&
      /sdk\.createRuntimeSubstrateClient/.test(cursorSdkParityContract) &&
      /createRuntimeSubstrateClient/.test(agentSdkQuickstartLocal) &&
      /createRuntimeSubstrateClient/.test(runtimeCompletePlus) &&
      /must not retain the retired mock projection client/.test(
        preNextLegReadiness,
      ) &&
      /SDK retired mock boundary/.test(executionSurfaceLeg),
    [
      "packages/agent-sdk/src/testing.ts",
      "packages/agent-sdk/src/substrate-client.ts",
      "packages/agent-sdk/examples/quickstart-local.ts",
      "scripts/evidence/runtime-complete-plus.mjs",
      "scripts/lib/cursor-sdk-parity-contract.mjs",
    ],
    "Phase 10/11 is pending: SDK testing and evidence paths must not retain the retired mock runtime client helper",
  );
  assertCheck(
    result,
    "autopilot-tauri-active-runtime-paths-retired",
    /internal-docs/.test(runtimeActionContractsGenerator) &&
      /legacy/.test(runtimeActionContractsGenerator) &&
      /autopilot-tauri-src/.test(runtimeActionContractsGenerator) &&
      !/"apps",\s*"autopilot",\s*"src-tauri",\s*"src",\s*"generated"/s.test(
        runtimeActionContractsGenerator,
      ) &&
      /activeTauriRuntimeProjection/.test(preNextLegReadiness) &&
      /internal-docs\/legacy\/autopilot-tauri-src\/src\/runtime_projection\.rs/.test(
        preNextLegReadiness,
      ) &&
      /internal-docs\/legacy\/autopilot-tauri-src\/src\/generated\/runtime_action_schema\.rs/.test(
        preNextLegReadiness,
      ) &&
      /const activeTauriSrc = "apps\/autopilot\/src-tauri\/src"/.test(
        runtimeLayoutCheck,
      ) &&
      /const legacyTauriSrc = "internal-docs\/legacy\/autopilot-tauri-src\/src"/.test(
        runtimeLayoutCheck,
      ) &&
      /!exists\(activeTauriSrc\)/.test(runtimeLayoutCheck) &&
      /Tauri Rust projection must stay legacy-only/.test(runtimeLayoutCheck),
    [
      "scripts/generate-runtime-action-contracts.mjs",
      "scripts/check-pre-next-leg-readiness.mjs",
      "scripts/check-runtime-layout.mjs",
    ],
    "Phase 10/11 is pending: active gates must not require retired Autopilot Tauri Rust runtime paths",
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
