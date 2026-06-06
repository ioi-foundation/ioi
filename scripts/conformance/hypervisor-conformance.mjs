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

  assertCheck(
    result,
    "guide-live-status-reconciled",
    !/JS direct tool dispatch remains the normal path|JS fallback remains default until shadow mode proves stable/.test(
      guide,
    ) &&
      /Current conformance requires `rust_workload_live`/.test(guide) &&
      /(?:rejects explicit `daemon_js`|explicit\s+`daemon_js` selection fails closed)/.test(guide),
    [GUIDE],
    "master guide live status must reflect the current Rust workload live default and fail-closed daemon_js selection",
  );
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
  const runtimeHttpUtilsBridge = exists("packages/runtime-daemon/src/runtime-http-utils.mjs")
    ? read("packages/runtime-daemon/src/runtime-http-utils.mjs")
    : "";
  const modelMountingState = exists("packages/runtime-daemon/src/model-mounting.mjs")
    ? read("packages/runtime-daemon/src/model-mounting.mjs")
    : "";
  const modelMountIoBridge = exists("packages/runtime-daemon/src/model-mounting/io.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/io.mjs")
    : "";
  const modelMountAdmissionRunner = exists("packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs")
    : "";
  const modelMountReceiptOperationsBridge = exists("packages/runtime-daemon/src/model-mounting/receipt-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/receipt-operations.mjs")
    : "";
  const modelRoutes = exists("packages/runtime-daemon/src/model-mounting/routes.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/routes.mjs")
    : "";
  const modelRoutesTest = exists("packages/runtime-daemon/src/model-mounting/routes.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/routes.test.mjs")
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
  const providerDriverHelpers = exists("packages/runtime-daemon/src/model-mounting/provider-driver-helpers.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-driver-helpers.mjs")
    : "";
  const providerDriverHelpersTest = exists("packages/runtime-daemon/src/model-mounting/provider-driver-helpers.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/provider-driver-helpers.test.mjs")
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
  const approvalCore = exists("crates/services/src/agentic/runtime/kernel/approval.rs")
    ? read("crates/services/src/agentic/runtime/kernel/approval.rs")
    : "";
  const policyCore = exists("crates/services/src/agentic/runtime/kernel/policy.rs")
    ? read("crates/services/src/agentic/runtime/kernel/policy.rs")
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
  const runtimeCodingToolApproval = exists("packages/runtime-daemon/src/runtime-coding-tool-approval.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-approval.mjs")
    : "";
  const runtimeCodingToolApprovalTest = exists("packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs")
    : "";
  const runtimeCodingToolApprovalRunner = exists("packages/runtime-daemon/src/runtime-coding-tool-approval-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-approval-runner.mjs")
    : "";
  const runtimeCodingToolApprovalRunnerTest = exists("packages/runtime-daemon/src/runtime-coding-tool-approval-runner.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-approval-runner.test.mjs")
    : "";
  const runtimeApprovalSurface = exists("packages/runtime-daemon/src/runtime-approval-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-approval-surface.mjs")
    : "";
  const runtimeApprovalSurfaceTest = exists("packages/runtime-daemon/src/runtime-approval-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-approval-surface.test.mjs")
    : "";
  const runtimeApprovalStateRunner = exists("packages/runtime-daemon/src/runtime-approval-state-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-approval-state-runner.mjs")
    : "";
  const runtimeApprovalStateRunnerTest = exists("packages/runtime-daemon/src/runtime-approval-state-runner.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-approval-state-runner.test.mjs")
    : "";
  const runtimeContextPolicyRunner = exists("packages/runtime-daemon/src/runtime-context-policy-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-context-policy-runner.mjs")
    : "";
  const runtimeContextPolicyRunnerTest = exists("packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs")
    : "";
  const codingToolBudgetPolicySurface = exists("packages/runtime-daemon/src/threads/context-budget-policy.mjs")
    ? read("packages/runtime-daemon/src/threads/context-budget-policy.mjs")
    : "";
  const codingToolBudgetPolicySurfaceTest = exists("packages/runtime-daemon/src/threads/context-budget-policy.test.mjs")
    ? read("packages/runtime-daemon/src/threads/context-budget-policy.test.mjs")
    : "";
  const runtimeCodingToolBudgetRecoverySurface = exists("packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.mjs")
    : "";
  const runtimeCodingToolBudgetRecoverySurfaceTest = exists("packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs")
    : "";
  const runtimeDiagnosticsRepairSurface = exists("packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs")
    : "";
  const runtimeDiagnosticsRepairSurfaceTest = exists("packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs")
    : "";
  const runtimeContextPolicySurface = exists("packages/runtime-daemon/src/runtime-context-policy-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-context-policy-surface.mjs")
    : "";
  const runtimeContextPolicySurfaceTest = exists("packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs")
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
  const runtimeMcpControlSurface = exists("packages/runtime-daemon/src/runtime-mcp-control-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-mcp-control-surface.mjs")
    : "";
  const runtimeMcpControlSurfaceTest = exists("packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs")
    : "";
  const runtimeThreadMemoryState = exists("packages/runtime-daemon/src/threads/thread-memory-state.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-memory-state.mjs")
    : "";
  const runtimeThreadMemoryStateTest = exists("packages/runtime-daemon/src/threads/thread-memory-state.test.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-memory-state.test.mjs")
    : "";
  const runtimeBridgeThread = exists("packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs")
    ? read("packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs")
    : "";
  const runtimeBridgeThreadTest = exists("packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs")
    ? read("packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs")
    : "";
  const threadStore = exists("packages/runtime-daemon/src/threads/thread-store.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-store.mjs")
    : "";
  const threadStoreTest = exists("packages/runtime-daemon/src/threads/thread-store.test.mjs")
    ? read("packages/runtime-daemon/src/threads/thread-store.test.mjs")
    : "";
  const runtimeThreadControlTest = exists("packages/runtime-daemon/src/runtime-thread-control.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-thread-control.test.mjs")
    : "";
  const runtimeRunCancellation = exists("packages/runtime-daemon/src/runtime-run-cancellation.mjs")
    ? read("packages/runtime-daemon/src/runtime-run-cancellation.mjs")
    : "";
  const runtimeRunCancellationTest = exists("packages/runtime-daemon/src/runtime-run-cancellation.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-run-cancellation.test.mjs")
    : "";
  const runtimeAgentRunLifecycle = exists("packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs")
    ? read("packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs")
    : "";
  const runtimeAgentRunLifecycleTest = exists(
    "packages/runtime-daemon/src/runtime-agent-run-lifecycle.test.mjs",
  )
    ? read("packages/runtime-daemon/src/runtime-agent-run-lifecycle.test.mjs")
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
  const workspaceRestoreKernel = exists("crates/services/src/agentic/runtime/kernel/workspace_restore.rs")
    ? read("crates/services/src/agentic/runtime/kernel/workspace_restore.rs")
    : "";
  const workspaceRestoreRunner = exists("packages/runtime-daemon/src/runtime-workspace-restore-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-workspace-restore-runner.mjs")
    : "";
  const workspaceRestoreRunnerTest = exists("packages/runtime-daemon/src/runtime-workspace-restore-runner.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-workspace-restore-runner.test.mjs")
    : "";
  const runtimeWorkspaceSnapshotSurface = exists("packages/runtime-daemon/src/runtime-workspace-snapshot-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-workspace-snapshot-surface.mjs")
    : "";
  const runtimeWorkspaceSnapshotSurfaceTest = exists("packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs")
    : "";
  const workspaceRestoreHelpers = exists("packages/runtime-daemon/src/workspace-restore.mjs")
    ? read("packages/runtime-daemon/src/workspace-restore.mjs")
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
  const agentSdkModelInvocationReceiptType =
    agentSdkModelMounts.match(/export interface ModelInvocationReceipt \{[\s\S]*?\n}\n\nexport interface ModelConversationState/)?.[0] ?? "";
  const agentSdkModelConversationStateType =
    agentSdkModelMounts.match(/export interface ModelConversationState \{[\s\S]*?\n}\n\nexport interface TokenizerToken/)?.[0] ?? "";
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
  const modelMountDefaultRecords = exists("packages/runtime-daemon/src/model-mounting/default-records.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/default-records.mjs")
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
    "coding-tool-approval-retry-manifest-alias-retired",
    !/camelCaseKey/.test(runtimeCodingToolApproval) &&
      !/requestedManifest\[camelCaseKey\(key\)\]/.test(runtimeCodingToolApproval) &&
      !/retryManifest\[camelCaseKey\(key\)\]/.test(runtimeCodingToolApproval) &&
      /requestedManifest\[key\]/.test(runtimeCodingToolApproval) &&
      /retryManifest\[key\]/.test(runtimeCodingToolApproval) &&
      /coding tool approval retry match rejects retired camelCase manifests/.test(runtimeCodingToolApprovalTest) &&
      /Object\.hasOwn\(camelRetry,\s*"threadId"\)/.test(runtimeCodingToolApprovalTest),
    [
      "packages/runtime-daemon/src/runtime-coding-tool-approval.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs",
    ],
    "Phase 10/11 is pending: coding-tool approval retry matching must fail closed on retired camelCase manifest fields",
  );
  assertCheck(
    result,
    "coding-tool-approval-manifest-live-bridge",
    /CodingToolApprovalCore/.test(approvalCore) &&
      /CodingToolApprovalRequest/.test(approvalCore) &&
      /CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION/.test(approvalCore) &&
      /CODING_TOOL_APPROVAL_MANIFEST_SCHEMA_VERSION/.test(approvalCore) &&
      /rust_authority_plans_coding_tool_approval_manifest/.test(approvalCore) &&
      /plan_coding_tool_approval_manifest/.test(bridgeModule) &&
      /CodingToolApprovalBridgeRequest/.test(bridgeModule) &&
      /rust_coding_tool_approval_command/.test(bridgeModule) &&
      /bridge_plans_coding_tool_approval_manifest_through_rust_core/.test(bridgeModule) &&
      /createCodingToolApprovalRunnerFromEnv/.test(runtimeCodingToolApprovalRunner) &&
      /RustCodingToolApprovalRunner/.test(runtimeCodingToolApprovalRunner) &&
      /planApprovalManifest/.test(runtimeCodingToolApprovalRunner) &&
      /coding tool approval runner sends Rust authority bridge request/.test(
        runtimeCodingToolApprovalRunnerTest,
      ) &&
      /coding tool approval runner fails closed without bridge command/.test(
        runtimeCodingToolApprovalRunnerTest,
      ) &&
      /approvalRunner\.planApprovalManifest/.test(runtimeCodingToolApproval) &&
      !/codingToolEffectRequiresApproval/.test(runtimeCodingToolApproval) &&
      !/codingToolWorkflowApprovalPolicy/.test(runtimeCodingToolApproval) &&
      !/codingToolEffectRequiresApproval/.test(runtimeDaemonIndex) &&
      !/codingToolWorkflowApprovalPolicy/.test(runtimeDaemonIndex) &&
      !/const modeRequiresApproval/.test(runtimeCodingToolApproval) &&
      /coding tool approval manifest is planned by Rust authority runner/.test(
        runtimeCodingToolApprovalTest,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/approval.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-coding-tool-approval-runner.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-approval-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-approval.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-approval.test.mjs",
    ],
    "Phase 9/10 is pending: coding-tool approval manifests must be planned by Rust authority core through the command bridge",
  );
  assertCheck(
    result,
    "approval-request-state-update-live-bridge",
    /ApprovalRequestStateUpdateCore/.test(approvalCore) &&
      /ApprovalRequestStateUpdateRequest/.test(approvalCore) &&
      /APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(approvalCore) &&
      /rust_authority_plans_approval_request_state_update/.test(approvalCore) &&
      /rust_authority_plans_approval_request_agent_state_update/.test(approvalCore) &&
      /plan_approval_request_state_update/.test(bridgeModule) &&
      /ApprovalRequestStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_approval_request_state_update_command/.test(bridgeModule) &&
      /bridge_plans_approval_request_state_update_through_rust_core/.test(bridgeModule) &&
      /bridge_plans_approval_request_agent_state_update_through_rust_core/.test(
        bridgeModule,
      ) &&
      /createRuntimeApprovalStateRunnerFromEnv/.test(runtimeApprovalStateRunner) &&
      /RustRuntimeApprovalStateRunner/.test(runtimeApprovalStateRunner) &&
      /planApprovalRequestStateUpdate/.test(runtimeApprovalStateRunner) &&
      /approval request state runner sends Rust authority bridge request/.test(
        runtimeApprovalStateRunnerTest,
      ) &&
      /approval request state runner normalizes Rust agent target updates/.test(
        runtimeApprovalStateRunnerTest,
      ) &&
      /approval request state runner fails closed without bridge command/.test(
        runtimeApprovalStateRunnerTest,
      ) &&
      /approval state runner fails closed without Rust-planned operation kinds/.test(
        runtimeApprovalStateRunnerTest,
      ) &&
      !/operation_kind:\s*optionalString\(result\.operation_kind\s*\?\?\s*record\.operation_kind\)\s*\?\?\s*"approval\.required"/.test(
        runtimeApprovalStateRunner,
      ) &&
      /approvalStateRunnerDep\.planApprovalRequestStateUpdate/.test(runtimeApprovalSurface) &&
      /plannedApprovalRunRecord/.test(runtimeApprovalSurface) &&
      /plannedApprovalAgentRecord/.test(runtimeApprovalSurface) &&
      /requiredApprovalOperationKind/.test(runtimeApprovalSurface) &&
      /target_kind:\s*"agent"/.test(runtimeApprovalSurface) &&
      /planApprovalRequestStateUpdate/.test(runtimeApprovalSurfaceTest) &&
      /approval surface fails closed without Rust-planned run approval updates/.test(
        runtimeApprovalSurfaceTest,
      ) &&
      /approval surface fails closed without Rust-planned operation kinds/.test(
        runtimeApprovalSurfaceTest,
      ) &&
      /approval surface routes runless agent approval updates through Rust planner/.test(
        runtimeApprovalSurfaceTest,
      ) &&
      !/control:\s*"approval_request"|appendRunApprovalControl\(run,\s*control,\s*"approvalRequests"\)/.test(
        runtimeApprovalSurface,
      ) &&
      !/stateUpdate\.run\s*\?\?\s*run/.test(runtimeApprovalSurface) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"approval\.required"/.test(runtimeApprovalSurface) &&
      !/const updatedAgent = \{\s*\.\.\.agent,\s*updatedAt: event\.created_at\s*\}/.test(
        runtimeApprovalSurface,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/approval.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-approval-state-runner.mjs",
      "packages/runtime-daemon/src/runtime-approval-state-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-approval-surface.mjs",
      "packages/runtime-daemon/src/runtime-approval-surface.test.mjs",
    ],
    "Phase 9/10 is pending: approval request run state updates must be planned by Rust authority core through the command bridge",
  );
  assertCheck(
    result,
    "approval-decision-state-update-live-bridge",
    /ApprovalDecisionStateUpdateCore/.test(approvalCore) &&
      /ApprovalDecisionStateUpdateRequest/.test(approvalCore) &&
      /APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(approvalCore) &&
      /rust_authority_plans_approval_decision_state_update/.test(approvalCore) &&
      /rust_authority_plans_approval_decision_agent_state_update/.test(approvalCore) &&
      /plan_approval_decision_state_update/.test(bridgeModule) &&
      /ApprovalDecisionStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_approval_decision_state_update_command/.test(bridgeModule) &&
      /bridge_plans_approval_decision_state_update_through_rust_core/.test(bridgeModule) &&
      /planApprovalDecisionStateUpdate/.test(runtimeApprovalStateRunner) &&
      /APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeApprovalStateRunner,
      ) &&
      /approval decision state runner sends Rust authority bridge request/.test(
        runtimeApprovalStateRunnerTest,
      ) &&
      /approval state runner fails closed without Rust-planned operation kinds/.test(
        runtimeApprovalStateRunnerTest,
      ) &&
      !/operation_kind:\s*optionalString\(result\.operation_kind\s*\?\?\s*record\.operation_kind\)\s*\?\?\s*"approval\.approve"/.test(
        runtimeApprovalStateRunner,
      ) &&
      /approvalStateRunnerDep\.planApprovalDecisionStateUpdate/.test(runtimeApprovalSurface) &&
      /plannedApprovalRunRecord/.test(runtimeApprovalSurface) &&
      /plannedApprovalAgentRecord/.test(runtimeApprovalSurface) &&
      /requiredApprovalOperationKind/.test(runtimeApprovalSurface) &&
      /target_kind:\s*"agent"/.test(runtimeApprovalSurface) &&
      /planApprovalDecisionStateUpdate/.test(runtimeApprovalSurfaceTest) &&
      /approval surface fails closed without Rust-planned run approval updates/.test(
        runtimeApprovalSurfaceTest,
      ) &&
      /approval surface fails closed without Rust-planned operation kinds/.test(
        runtimeApprovalSurfaceTest,
      ) &&
      /approval surface routes runless agent approval updates through Rust planner/.test(
        runtimeApprovalSurfaceTest,
      ) &&
      !/control:\s*"approval_decision"/.test(
        runtimeApprovalSurface,
      ) &&
      !/stateUpdate\.run\s*\?\?\s*run/.test(runtimeApprovalSurface) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*`approval\.\$\{decision\}`/.test(
        runtimeApprovalSurface,
      ) &&
      !/const updatedAgent = \{\s*\.\.\.agent,\s*updatedAt: event\.created_at\s*\}/.test(
        runtimeApprovalSurface,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/approval.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-approval-state-runner.mjs",
      "packages/runtime-daemon/src/runtime-approval-state-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-approval-surface.mjs",
      "packages/runtime-daemon/src/runtime-approval-surface.test.mjs",
    ],
    "Phase 9/10 is pending: approval decision run state updates must be planned by Rust authority core through the command bridge",
  );
  assertCheck(
    result,
    "approval-revoke-state-update-live-bridge",
    /ApprovalRevokeStateUpdateCore/.test(approvalCore) &&
      /ApprovalRevokeStateUpdateRequest/.test(approvalCore) &&
      /APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(approvalCore) &&
      /rust_authority_plans_approval_revoke_state_update/.test(approvalCore) &&
      /rust_authority_plans_approval_revoke_agent_state_update/.test(approvalCore) &&
      /plan_approval_revoke_state_update/.test(bridgeModule) &&
      /ApprovalRevokeStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_approval_revoke_state_update_command/.test(bridgeModule) &&
      /bridge_plans_approval_revoke_state_update_through_rust_core/.test(bridgeModule) &&
      /planApprovalRevokeStateUpdate/.test(runtimeApprovalStateRunner) &&
      /APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeApprovalStateRunner,
      ) &&
      /approval revoke state runner sends Rust authority bridge request/.test(
        runtimeApprovalStateRunnerTest,
      ) &&
      /approval state runner fails closed without Rust-planned operation kinds/.test(
        runtimeApprovalStateRunnerTest,
      ) &&
      !/operation_kind:\s*optionalString\(result\.operation_kind\s*\?\?\s*record\.operation_kind\)\s*\?\?\s*"approval\.revoke"/.test(
        runtimeApprovalStateRunner,
      ) &&
      /approvalStateRunnerDep\.planApprovalRevokeStateUpdate/.test(runtimeApprovalSurface) &&
      /plannedApprovalRunRecord/.test(runtimeApprovalSurface) &&
      /plannedApprovalAgentRecord/.test(runtimeApprovalSurface) &&
      /requiredApprovalOperationKind/.test(runtimeApprovalSurface) &&
      /target_kind:\s*"agent"/.test(runtimeApprovalSurface) &&
      /planApprovalRevokeStateUpdate/.test(runtimeApprovalSurfaceTest) &&
      /approval surface fails closed without Rust-planned run approval updates/.test(
        runtimeApprovalSurfaceTest,
      ) &&
      /approval surface fails closed without Rust-planned operation kinds/.test(
        runtimeApprovalSurfaceTest,
      ) &&
      /approval surface routes runless agent approval updates through Rust planner/.test(
        runtimeApprovalSurfaceTest,
      ) &&
      !/control:\s*"approval_revoke"|appendRunApprovalControl|appendOperatorControl/.test(
        runtimeApprovalSurface,
      ) &&
      !/stateUpdate\.run\s*\?\?\s*run/.test(runtimeApprovalSurface) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"approval\.revoke"/.test(runtimeApprovalSurface) &&
      !/const updatedAgent = \{\s*\.\.\.agent,\s*updatedAt: event\.created_at\s*\}/.test(
        runtimeApprovalSurface,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/approval.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-approval-state-runner.mjs",
      "packages/runtime-daemon/src/runtime-approval-state-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-approval-surface.mjs",
      "packages/runtime-daemon/src/runtime-approval-surface.test.mjs",
    ],
    "Phase 9/10 is pending: approval revoke run state updates must be planned by Rust authority core through the command bridge",
  );
  assertCheck(
    result,
    "context-budget-policy-live-bridge",
    /ContextBudgetPolicyCore/.test(policyCore) &&
      /ContextBudgetPolicyRequest/.test(policyCore) &&
      /CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_blocks_context_budget_excess/.test(policyCore) &&
      /runtime_event_item_id/.test(policyCore) &&
      /runtime_event_idempotency_key/.test(policyCore) &&
      /evaluate_context_budget_policy/.test(bridgeModule) &&
      /ContextBudgetPolicyBridgeRequest/.test(bridgeModule) &&
      /rust_context_budget_policy_command/.test(bridgeModule) &&
      /bridge_evaluates_context_budget_policy_through_rust_core/.test(bridgeModule) &&
      /runtime_event_idempotency_key/.test(bridgeModule) &&
      /createContextPolicyRunnerFromEnv/.test(runtimeContextPolicyRunner) &&
      /RustContextPolicyRunner/.test(runtimeContextPolicyRunner) &&
      /evaluateContextBudgetPolicy/.test(runtimeContextPolicyRunner) &&
      /runtime_event_item_id/.test(runtimeContextPolicyRunner) &&
      /context budget policy runner sends generic Rust policy bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /result\.runtime_event_item_id/.test(runtimeContextPolicySurface) &&
      /result\.runtime_event_idempotency_key/.test(runtimeContextPolicySurface) &&
      !/context-budget:\$\{safeIdDep\(result\.policy_decision_id\)\}/.test(
        runtimeContextPolicySurface,
      ) &&
      /context policy runner fails closed without bridge command/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /budgetRunner\.evaluateContextBudgetPolicy/.test(codingToolBudgetPolicySurface) &&
      /capturedRequest\.schema_version,\s*"ioi\.runtime\.context-budget-policy-request\.v1"/.test(
        codingToolBudgetPolicySurfaceTest,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/threads/context-budget-policy.mjs",
      "packages/runtime-daemon/src/threads/context-budget-policy.test.mjs",
    ],
    "Phase 9/10 is pending: generic context-budget policy must be evaluated by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "coding-tool-budget-policy-live-bridge",
    /ContextBudgetPolicyCore/.test(policyCore) &&
      /ContextBudgetPolicyRequest/.test(policyCore) &&
      /CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_blocks_coding_tool_budget_excess/.test(policyCore) &&
      /evaluate_coding_tool_budget_policy/.test(bridgeModule) &&
      /ContextBudgetPolicyBridgeRequest/.test(bridgeModule) &&
      /rust_coding_tool_budget_policy_command/.test(bridgeModule) &&
      /bridge_evaluates_coding_tool_budget_policy_through_rust_core/.test(bridgeModule) &&
      /createContextPolicyRunnerFromEnv/.test(runtimeContextPolicyRunner) &&
      /RustContextPolicyRunner/.test(runtimeContextPolicyRunner) &&
      /evaluateCodingToolBudgetPolicy/.test(runtimeContextPolicyRunner) &&
      /coding tool budget runner sends Rust policy bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /budgetRunner\.evaluateCodingToolBudgetPolicy/.test(codingToolBudgetPolicySurface) &&
      /coding tool budget policy reads canonical tool pack fields and annotates runtime context/.test(
        codingToolBudgetPolicySurfaceTest,
      ) &&
      /capturedRequest\.schema_version,\s*"ioi\.runtime\.coding-tool-budget-policy-request\.v1"/.test(
        codingToolBudgetPolicySurfaceTest,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/threads/context-budget-policy.mjs",
      "packages/runtime-daemon/src/threads/context-budget-policy.test.mjs",
    ],
    "Phase 9/10 is pending: coding-tool budget preflight must be evaluated by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "coding-tool-budget-recovery-state-update-live-bridge",
    /CodingToolBudgetRecoveryStateUpdateCore/.test(policyCore) &&
      /CodingToolBudgetRecoveryStateUpdateRequest/.test(policyCore) &&
      /CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_coding_tool_budget_recovery_state_update/.test(policyCore) &&
      /plan_coding_tool_budget_recovery_state_update/.test(bridgeModule) &&
      /CodingToolBudgetRecoveryStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_coding_tool_budget_recovery_state_update_command/.test(bridgeModule) &&
      /bridge_plans_coding_tool_budget_recovery_state_update_through_rust_core/.test(
        bridgeModule,
      ) &&
      /planCodingToolBudgetRecoveryStateUpdate/.test(runtimeContextPolicyRunner) &&
      /CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /coding tool budget recovery state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunnerDep\.planCodingToolBudgetRecoveryStateUpdate/.test(
        runtimeCodingToolBudgetRecoverySurface,
      ) &&
      /plannedCodingToolBudgetRecoveryRunRecord/.test(
        runtimeCodingToolBudgetRecoverySurface,
      ) &&
      /plannedCodingToolBudgetRecoveryOperationKind/.test(
        runtimeCodingToolBudgetRecoverySurface,
      ) &&
      /planCodingToolBudgetRecoveryStateUpdate/.test(
        runtimeCodingToolBudgetRecoverySurfaceTest,
      ) &&
      /budget recovery surface fails closed without Rust-planned retry run/.test(
        runtimeCodingToolBudgetRecoverySurfaceTest,
      ) &&
      /budget recovery surface fails closed without Rust-planned operation kind/.test(
        runtimeCodingToolBudgetRecoverySurfaceTest,
      ) &&
      !/stateUpdate\.run\s*\?\?\s*run/.test(runtimeCodingToolBudgetRecoverySurface) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"workflow\.run\.retry_completed"/.test(
        runtimeCodingToolBudgetRecoverySurface,
      ) &&
      !/appendOperatorControl/.test(runtimeCodingToolBudgetRecoverySurface),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.mjs",
      "packages/runtime-daemon/src/runtime-coding-tool-budget-recovery-surface.test.mjs",
    ],
    "Phase 9/10 is pending: coding-tool budget recovery retry state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "diagnostics-operator-override-state-update-live-bridge",
    /DiagnosticsOperatorOverrideStateUpdateCore/.test(policyCore) &&
      /DiagnosticsOperatorOverrideStateUpdateRequest/.test(policyCore) &&
      /DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_diagnostics_operator_override_state_update/.test(policyCore) &&
      /plan_diagnostics_operator_override_state_update/.test(bridgeModule) &&
      /DiagnosticsOperatorOverrideStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_diagnostics_operator_override_state_update_command/.test(bridgeModule) &&
      /bridge_plans_diagnostics_operator_override_state_update_through_rust_core/.test(
        bridgeModule,
      ) &&
      /planDiagnosticsOperatorOverrideStateUpdate/.test(runtimeContextPolicyRunner) &&
      /DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /diagnostics operator override state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunnerDep\.planDiagnosticsOperatorOverrideStateUpdate/.test(
        runtimeDiagnosticsRepairSurface,
      ) &&
      /plannedDiagnosticsOperatorOverrideRunRecord/.test(runtimeDiagnosticsRepairSurface) &&
      /plannedDiagnosticsOperatorOverrideOperationKind/.test(runtimeDiagnosticsRepairSurface) &&
      /planDiagnosticsOperatorOverrideStateUpdate/.test(runtimeDiagnosticsRepairSurfaceTest) &&
      /diagnostics repair surface fails closed without Rust-planned override run/.test(
        runtimeDiagnosticsRepairSurfaceTest,
      ) &&
      /diagnostics repair surface fails closed without Rust-planned override operation kind/.test(
        runtimeDiagnosticsRepairSurfaceTest,
      ) &&
      !/control:\s*"diagnostics_operator_override"|appendOperatorControl/.test(
        runtimeDiagnosticsRepairSurface,
      ) &&
      !/stateUpdate\.run\s*\?\?\s*run/.test(runtimeDiagnosticsRepairSurface) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"diagnostics\.operator_override\.event"/.test(
        runtimeDiagnosticsRepairSurface,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs",
      "packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs",
    ],
    "Phase 9/10 is pending: diagnostics operator override run state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "operator-interrupt-state-update-live-bridge",
    /OperatorInterruptStateUpdateCore/.test(policyCore) &&
      /OperatorInterruptStateUpdateRequest/.test(policyCore) &&
      /OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_operator_interrupt_state_update/.test(policyCore) &&
      /plan_operator_interrupt_state_update/.test(bridgeModule) &&
      /OperatorInterruptStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_operator_interrupt_state_update_command/.test(bridgeModule) &&
      /bridge_plans_operator_interrupt_state_update_through_rust_core/.test(
        bridgeModule,
      ) &&
      /planOperatorInterruptStateUpdate/.test(runtimeContextPolicyRunner) &&
      /OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /operator interrupt state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /createContextPolicyRunnerFromEnv/.test(runtimeDaemonIndex) &&
      /this\.contextPolicyRunner/.test(runtimeDaemonIndex) &&
      /this\.contextPolicyRunner\.planOperatorInterruptStateUpdate/.test(runtimeDaemonIndex) &&
      /plannedOperatorControlRunRecord/.test(runtimeDaemonIndex) &&
      /requiredOperatorControlOperationKind/.test(runtimeDaemonIndex) &&
      !/control:\s*"interrupt"/.test(runtimeDaemonIndex) &&
      !/stateUpdate\.run\s*\?\?\s*run/.test(runtimeDaemonIndex) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"turn\.interrupt"/.test(runtimeDaemonIndex) &&
      /contextPolicyRunner\(calls\)/.test(runtimeThreadControlTest) &&
      /runtime-backed operator controls fail closed without Rust-planned runs/.test(
        runtimeThreadControlTest,
      ) &&
      /runtime-backed operator controls fail closed without Rust-planned operation kinds/.test(
        runtimeThreadControlTest,
      ) &&
      /plan_operator_interrupt_state_update/.test(runtimeThreadControlTest),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
      "packages/runtime-daemon/src/runtime-thread-control.test.mjs",
    ],
    "Phase 9/10 is pending: operator interrupt run state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "operator-steer-state-update-live-bridge",
    /OperatorSteerStateUpdateCore/.test(policyCore) &&
      /OperatorSteerStateUpdateRequest/.test(policyCore) &&
      /OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_operator_steer_state_update/.test(policyCore) &&
      /plan_operator_steer_state_update/.test(bridgeModule) &&
      /OperatorSteerStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_operator_steer_state_update_command/.test(bridgeModule) &&
      /bridge_plans_operator_steer_state_update_through_rust_core/.test(bridgeModule) &&
      /planOperatorSteerStateUpdate/.test(runtimeContextPolicyRunner) &&
      /OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(runtimeContextPolicyRunner) &&
      /operator steer state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /this\.contextPolicyRunner\.planOperatorSteerStateUpdate/.test(runtimeDaemonIndex) &&
      /plannedOperatorControlRunRecord/.test(runtimeDaemonIndex) &&
      /requiredOperatorControlOperationKind/.test(runtimeDaemonIndex) &&
      !/control:\s*"steer"|appendOperatorControl/.test(runtimeDaemonIndex) &&
      !/stateUpdate\.run\s*\?\?\s*run/.test(runtimeDaemonIndex) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"turn\.steer"/.test(runtimeDaemonIndex) &&
      /runtime-backed steering routes run update through Rust policy planner/.test(
        runtimeThreadControlTest,
      ) &&
      /runtime-backed operator controls fail closed without Rust-planned runs/.test(
        runtimeThreadControlTest,
      ) &&
      /runtime-backed operator controls fail closed without Rust-planned operation kinds/.test(
        runtimeThreadControlTest,
      ) &&
      /plan_operator_steer_state_update/.test(runtimeThreadControlTest),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
      "packages/runtime-daemon/src/runtime-thread-control.test.mjs",
    ],
    "Phase 9/10 is pending: operator steer run state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "run-cancel-state-update-live-bridge",
    /RunCancelStateUpdateCore/.test(policyCore) &&
      /RunCancelStateUpdateRequest/.test(policyCore) &&
      /RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_run_cancel_state_update/.test(policyCore) &&
      /plan_run_cancel_state_update/.test(bridgeModule) &&
      /RunCancelStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_run_cancel_state_update_command/.test(bridgeModule) &&
      /bridge_plans_run_cancel_state_update_through_rust_core/.test(bridgeModule) &&
      /planRunCancelStateUpdate/.test(runtimeContextPolicyRunner) &&
      /RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(runtimeContextPolicyRunner) &&
      /run cancel state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunner\.planRunCancelStateUpdate/.test(runtimeRunCancellation) &&
      /plannedRunCancelRecord/.test(runtimeRunCancellation) &&
      /plannedRunCancelOperationKind/.test(runtimeRunCancellation) &&
      !/runtimeTaskRecord|runtimeJobRecord|runtimeChecklistRecord|makeEvent|artifact\(/.test(
        runtimeRunCancellation,
      ) &&
      !/stateUpdate\.run\s*\?\?\s*run/.test(runtimeRunCancellation) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"run\.cancel"/.test(runtimeRunCancellation) &&
      /plan_run_cancel_state_update/.test(runtimeRunCancellationTest) &&
      /cancelRun fails closed without Rust-planned run record/.test(runtimeRunCancellationTest) &&
      /cancelRun fails closed without Rust-planned operation kind/.test(
        runtimeRunCancellationTest,
      ) &&
      /contextPolicyRunner: this\.contextPolicyRunner/.test(runtimeDaemonIndex),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-run-cancellation.mjs",
      "packages/runtime-daemon/src/runtime-run-cancellation.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 9/10 is pending: run cancellation state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "thread-control-agent-state-update-live-bridge",
    /ThreadControlAgentStateUpdateCore/.test(policyCore) &&
      /ThreadControlAgentStateUpdateRequest/.test(policyCore) &&
      /THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_thread_mode_agent_state_update/.test(policyCore) &&
      /rust_policy_plans_thread_model_agent_state_update/.test(policyCore) &&
      /plan_thread_control_agent_state_update/.test(bridgeModule) &&
      /ThreadControlAgentStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_thread_control_agent_state_update_command/.test(bridgeModule) &&
      /bridge_plans_thread_control_agent_state_update_through_rust_core/.test(
        bridgeModule,
      ) &&
      /planThreadControlAgentStateUpdate/.test(runtimeContextPolicyRunner) &&
      /THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /thread control agent state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunner:\s*this\.contextPolicyRunner/.test(runtimeDaemonIndex) &&
      /contextPolicyRunnerDep\.planThreadControlAgentStateUpdate/.test(
        runtimeThreadControlSurface,
      ) &&
      /requiredThreadControlOperationKind/.test(runtimeThreadControlSurface) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*`thread\.\$\{controlKind\}`/.test(
        runtimeThreadControlSurface,
      ) &&
      !/modelId:\s*modelRoute\.selectedModel|runtimeControls:\s*nextControls/.test(
        runtimeThreadControlSurface,
      ) &&
      /thread control surface updates mode controls through Rust planner/.test(
        runtimeThreadControlSurfaceTest,
      ) &&
      /thread control surface updates model controls through route selection and Rust planner/.test(
        runtimeThreadControlSurfaceTest,
      ) &&
      /thread control surface fails closed without Rust-planned operation kind/.test(
        runtimeThreadControlSurfaceTest,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-thread-control-surface.mjs",
      "packages/runtime-daemon/src/runtime-thread-control-surface.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 9/10 is pending: thread-control agent state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "mcp-control-agent-state-update-live-bridge",
    /McpControlAgentStateUpdateCore/.test(policyCore) &&
      /McpControlAgentStateUpdateRequest/.test(policyCore) &&
      /MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_mcp_control_agent_state_update/.test(policyCore) &&
      /rust_policy_rejects_invalid_mcp_control_agent_state_update_schema/.test(policyCore) &&
      /plan_mcp_control_agent_state_update/.test(bridgeModule) &&
      /McpControlAgentStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_mcp_control_agent_state_update_command/.test(bridgeModule) &&
      /bridge_plans_mcp_control_agent_state_update_through_rust_core/.test(bridgeModule) &&
      /planMcpControlAgentStateUpdate/.test(runtimeContextPolicyRunner) &&
      /MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /mcp control agent state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunnerDep\.planMcpControlAgentStateUpdate/.test(
        runtimeMcpControlSurface,
      ) &&
      /requiredMcpControlOperationKind/.test(runtimeMcpControlSurface) &&
      /mcpStatusForAgent/.test(runtimeMcpControlSurface) &&
      !/store\.agents\.set\(agent\.id,\s*updatedAgent\)/.test(runtimeMcpControlSurface) &&
      !/store\.writeAgent\(updatedAgent,\s*`thread\.\$\{controlKind\}`\)/.test(
        runtimeMcpControlSurface,
      ) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*`thread\.\$\{controlKind\}`/.test(
        runtimeMcpControlSurface,
      ) &&
      /planMcpControlAgentStateUpdate/.test(runtimeMcpControlSurfaceTest) &&
      /runtime MCP control surface fails closed without Rust-planned operation kind/.test(
        runtimeMcpControlSurfaceTest,
      ) &&
      /contextPolicyRunner:\s*this\.contextPolicyRunner/.test(runtimeDaemonIndex),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-mcp-control-surface.mjs",
      "packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 9/10 is pending: MCP control agent state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "thread-memory-agent-state-update-live-bridge",
    /ThreadMemoryAgentStateUpdateCore/.test(policyCore) &&
      /ThreadMemoryAgentStateUpdateRequest/.test(policyCore) &&
      /THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_thread_memory_agent_state_update/.test(policyCore) &&
      /rust_policy_rejects_invalid_thread_memory_agent_state_update_schema/.test(policyCore) &&
      /plan_thread_memory_agent_state_update/.test(bridgeModule) &&
      /ThreadMemoryAgentStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_thread_memory_agent_state_update_command/.test(bridgeModule) &&
      /bridge_plans_thread_memory_agent_state_update_through_rust_core/.test(
        bridgeModule,
      ) &&
      /planThreadMemoryAgentStateUpdate/.test(runtimeContextPolicyRunner) &&
      /THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /thread memory agent state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunner\.planThreadMemoryAgentStateUpdate/.test(
        runtimeThreadMemoryState,
      ) &&
      /requiredThreadMemoryOperationKind/.test(runtimeThreadMemoryState) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*`thread\.\$\{controlKind\}`/.test(
        runtimeThreadMemoryState,
      ) &&
      /thread memory state fails closed without Rust-planned agent projection/.test(
        runtimeThreadMemoryStateTest,
      ) &&
      /thread memory state fails closed without Rust-planned operation kind/.test(
        runtimeThreadMemoryStateTest,
      ) &&
      !/const updatedAgent = \{ \.\.\.agent, updatedAt: event\.created_at \}/.test(
        runtimeThreadMemoryState,
      ) &&
      /runtimeError/.test(runtimeDaemonIndex),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/threads/thread-memory-state.mjs",
      "packages/runtime-daemon/src/threads/thread-memory-state.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 9/10 is pending: thread-memory agent state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "runtime-bridge-thread-start-agent-state-update-live-bridge",
    /RuntimeBridgeThreadStartAgentStateUpdateCore/.test(policyCore) &&
      /RuntimeBridgeTurnRunStateUpdateCore/.test(policyCore) &&
      /RuntimeBridgeThreadStartAgentStateUpdateRequest/.test(policyCore) &&
      /RuntimeBridgeTurnRunStateUpdateRequest/.test(policyCore) &&
      /RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_runtime_bridge_thread_start_agent_state_update/.test(policyCore) &&
      /rust_policy_plans_runtime_bridge_turn_run_state_update/.test(policyCore) &&
      /rust_policy_rejects_invalid_runtime_bridge_thread_start_agent_state_update_schema/.test(
        policyCore,
      ) &&
      /rust_policy_rejects_invalid_runtime_bridge_turn_run_state_update_schema/.test(
        policyCore,
      ) &&
      /plan_runtime_bridge_thread_start_agent_state_update/.test(bridgeModule) &&
      /plan_runtime_bridge_turn_run_state_update/.test(bridgeModule) &&
      /RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest/.test(bridgeModule) &&
      /RuntimeBridgeTurnRunStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_runtime_bridge_thread_start_agent_state_update_command/.test(bridgeModule) &&
      /rust_runtime_bridge_turn_run_state_update_command/.test(bridgeModule) &&
      /bridge_plans_runtime_bridge_thread_start_agent_state_update_through_rust_core/.test(
        bridgeModule,
      ) &&
      /bridge_plans_runtime_bridge_turn_run_state_update_through_rust_core/.test(
        bridgeModule,
      ) &&
      /planRuntimeBridgeThreadStartAgentStateUpdate/.test(runtimeContextPolicyRunner) &&
      /planRuntimeBridgeTurnRunStateUpdate/.test(runtimeContextPolicyRunner) &&
      /RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /runtime bridge thread start agent state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /runtime bridge turn run state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunner\.planRuntimeBridgeThreadStartAgentStateUpdate/.test(
        runtimeBridgeThread,
      ) &&
      /contextPolicyRunner\.planRuntimeBridgeTurnRunStateUpdate/.test(
        runtimeBridgeThread,
      ) &&
      /requiredRuntimeBridgeOperationKind/.test(runtimeBridgeThread) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"thread\.runtime_bridge\.start"/.test(
        runtimeBridgeThread,
      ) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"turn\.runtime_bridge\.submit"/.test(
        runtimeBridgeThread,
      ) &&
      /runtime bridge thread creation fails closed without Rust-planned agent projection/.test(
        runtimeBridgeThreadTest,
      ) &&
      /runtime bridge thread creation fails closed without Rust-planned operation kind/.test(
        runtimeBridgeThreadTest,
      ) &&
      /runtime bridge turn creation fails closed without Rust-planned run projection/.test(
        runtimeBridgeThreadTest,
      ) &&
      /runtime bridge turn creation fails closed without Rust-planned operation kind/.test(
        runtimeBridgeThreadTest,
      ) &&
      !/const updated = \{\s*\.\.\.agent,\s*runtimeProfile,\s*runtimeSessionId/s.test(
        runtimeBridgeThread,
      ) &&
      !/store\.runs\.set\(runDraft\.id,\s*runDraft\)/.test(
        runtimeBridgeThread,
      ) &&
      !/store\.writeRun\(runDraft,/.test(
        runtimeBridgeThread,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/threads/runtime-bridge-thread.mjs",
      "packages/runtime-daemon/src/threads/runtime-bridge-thread.test.mjs",
    ],
    "Phase 9/10 is pending: runtime bridge thread-start agent updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "agent-run-create-state-update-live-bridge",
    /AgentCreateStateUpdateCore/.test(policyCore) &&
      /RunCreateStateUpdateCore/.test(policyCore) &&
      /AgentStatusStateUpdateCore/.test(policyCore) &&
      /AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_agent_create_state_update/.test(policyCore) &&
      /rust_policy_plans_run_create_state_update/.test(policyCore) &&
      /rust_policy_plans_agent_status_state_update/.test(policyCore) &&
      /plan_agent_create_state_update/.test(bridgeModule) &&
      /plan_run_create_state_update/.test(bridgeModule) &&
      /plan_agent_status_state_update/.test(bridgeModule) &&
      /AgentCreateStateUpdateBridgeRequest/.test(bridgeModule) &&
      /RunCreateStateUpdateBridgeRequest/.test(bridgeModule) &&
      /AgentStatusStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_agent_create_state_update_command/.test(bridgeModule) &&
      /rust_run_create_state_update_command/.test(bridgeModule) &&
      /rust_agent_status_state_update_command/.test(bridgeModule) &&
      /bridge_plans_agent_create_state_update_through_rust_core/.test(bridgeModule) &&
      /bridge_plans_run_create_state_update_through_rust_core/.test(bridgeModule) &&
      /bridge_plans_agent_status_state_update_through_rust_core/.test(bridgeModule) &&
      /planAgentCreateStateUpdate/.test(runtimeContextPolicyRunner) &&
      /planRunCreateStateUpdate/.test(runtimeContextPolicyRunner) &&
      /planAgentStatusStateUpdate/.test(runtimeContextPolicyRunner) &&
      /AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(runtimeContextPolicyRunner) &&
      /RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(runtimeContextPolicyRunner) &&
      /AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(runtimeContextPolicyRunner) &&
      /agent create state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /run create state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /agent status state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunner\.planAgentCreateStateUpdate/.test(runtimeAgentRunLifecycle) &&
      /contextPolicyRunner\.planRunCreateStateUpdate/.test(runtimeAgentRunLifecycle) &&
      /requiredPlannedOperationKind\(stateUpdate,\s*"agent\.create",\s*"agent"\)/.test(
        runtimeAgentRunLifecycle,
      ) &&
      /requiredPlannedOperationKind\(stateUpdate,\s*"run\.create",\s*"run"\)/.test(
        runtimeAgentRunLifecycle,
      ) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"agent\.create"/.test(runtimeAgentRunLifecycle) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"run\.create"/.test(runtimeAgentRunLifecycle) &&
      /contextPolicyRunner\.planAgentStatusStateUpdate/.test(threadStore) &&
      /agent_status_state_update_operation_kind_missing/.test(threadStore) &&
      /agent_status_state_update_operation_kind_mismatch/.test(threadStore) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*operationKind/.test(threadStore) &&
      !/store\.agents\.set\(agent\.id,\s*agent\)|store\.runs\.set\(runtimeRun\.id,\s*runtimeRun\)/.test(
        runtimeAgentRunLifecycle,
      ) &&
      /contextPolicyRunner:\s*this\.contextPolicyRunner/.test(runtimeDaemonIndex) &&
      /plan_agent_create_state_update/.test(runtimeAgentRunLifecycleTest) &&
      /plan_run_create_state_update/.test(runtimeAgentRunLifecycleTest) &&
      /createAgent fails closed without Rust-planned operation kind/.test(
        runtimeAgentRunLifecycleTest,
      ) &&
      /createRun fails closed without Rust-planned operation kind/.test(
        runtimeAgentRunLifecycleTest,
      ) &&
      /thread store fails closed without Rust-planned status agent/.test(threadStoreTest) &&
      /thread store fails closed without Rust-planned status operation kind/.test(
        threadStoreTest,
      ) &&
      /thread store fails closed on mismatched Rust-planned status operation kind/.test(
        threadStoreTest,
      ) &&
      !/const updated = \{ \.\.\.agent, status, updatedAt: new Date\(\)\.toISOString\(\) \}/.test(
        threadStore,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-agent-run-lifecycle.mjs",
      "packages/runtime-daemon/src/runtime-agent-run-lifecycle.test.mjs",
      "packages/runtime-daemon/src/threads/thread-store.mjs",
      "packages/runtime-daemon/src/threads/thread-store.test.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 9/10 is pending: agent/run create state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "compaction-policy-live-bridge",
    /CompactionPolicyCore/.test(policyCore) &&
      /CompactionPolicyRequest/.test(policyCore) &&
      /COMPACTION_POLICY_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_requires_compaction_approval_before_compacting/.test(policyCore) &&
      /rust_policy_compacts_when_approval_is_granted/.test(policyCore) &&
      /runtime_event_item_id/.test(policyCore) &&
      /compact_idempotency_key/.test(policyCore) &&
      /evaluate_compaction_policy/.test(bridgeModule) &&
      /CompactionPolicyBridgeRequest/.test(bridgeModule) &&
      /rust_compaction_policy_command/.test(bridgeModule) &&
      /bridge_evaluates_compaction_policy_through_rust_core/.test(bridgeModule) &&
      /runtime_event_idempotency_key/.test(bridgeModule) &&
      /createContextPolicyRunnerFromEnv/.test(runtimeContextPolicyRunner) &&
      /RustContextPolicyRunner/.test(runtimeContextPolicyRunner) &&
      /evaluateCompactionPolicy/.test(runtimeContextPolicyRunner) &&
      /runtime_event_item_id/.test(runtimeContextPolicyRunner) &&
      /compaction policy runner sends Rust policy bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /result\.runtime_event_item_id/.test(runtimeContextPolicySurface) &&
      /result\.runtime_event_idempotency_key/.test(runtimeContextPolicySurface) &&
      /result\.compact_idempotency_key/.test(runtimeContextPolicySurface) &&
      !/compaction-policy:\$\{safeIdDep\(result\.policy_decision_id\)\}/.test(
        runtimeContextPolicySurface,
      ) &&
      /policyRunner\.evaluateCompactionPolicy/.test(codingToolBudgetPolicySurface) &&
      /capturedRequest\.schema_version,\s*"ioi\.runtime\.compaction-policy-request\.v1"/.test(
        codingToolBudgetPolicySurfaceTest,
      ) &&
      !/compactionExecuted|compactionEventId|compactionSeq|approvalId/.test(
        `${codingToolBudgetPolicySurface}\n${runtimeContextPolicySurface}`,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/threads/context-budget-policy.mjs",
      "packages/runtime-daemon/src/threads/context-budget-policy.test.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-surface.mjs",
    ],
    "Phase 9/10 is pending: compaction policy decisions must be evaluated by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "context-compaction-plan-live-bridge",
    /ContextCompactionPlanCore/.test(policyCore) &&
      /ContextCompactionPlanRequest/.test(policyCore) &&
      /CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_context_compaction_event_record/.test(policyCore) &&
      /rust_policy_plans_runless_context_compaction_against_agent_ref/.test(policyCore) &&
      /plan_context_compaction/.test(bridgeModule) &&
      /ContextCompactionPlanBridgeRequest/.test(bridgeModule) &&
      /rust_context_compaction_plan_command/.test(bridgeModule) &&
      /bridge_plans_context_compaction_through_rust_core/.test(bridgeModule) &&
      /planContextCompaction/.test(runtimeContextPolicyRunner) &&
      /CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION/.test(runtimeContextPolicyRunner) &&
      /context compaction runner sends Rust plan bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunnerDep\.planContextCompaction/.test(runtimeContextPolicySurface) &&
      /planContextCompaction/.test(runtimeContextPolicySurfaceTest) &&
      !/compactHash|createHash/.test(runtimeContextPolicySurface),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-surface.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs",
    ],
    "Phase 9/10 is pending: context-compaction event planning must be produced by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "context-compaction-state-update-live-bridge",
    /ContextCompactionStateUpdateCore/.test(policyCore) &&
      /ContextCompactionStateUpdateRequest/.test(policyCore) &&
      /CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_context_compaction_run_state_update/.test(policyCore) &&
      /rust_policy_plans_context_compaction_runless_agent_update/.test(policyCore) &&
      /plan_context_compaction_state_update/.test(bridgeModule) &&
      /ContextCompactionStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_context_compaction_state_update_command/.test(bridgeModule) &&
      /bridge_plans_context_compaction_state_update_through_rust_core/.test(bridgeModule) &&
      /planContextCompactionStateUpdate/.test(runtimeContextPolicyRunner) &&
      /CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /context compaction state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /requiredContextPolicyBridgeOperationKind/.test(runtimeContextPolicyRunner) &&
      /context policy state update runner fails closed without Rust-planned operation kinds/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      !/operation_kind:\s*optionalString\(result\.operation_kind\s*\?\?\s*record\.operation_kind\)\s*\?\?/.test(
        runtimeContextPolicyRunner,
      ) &&
      /contextPolicyRunnerDep\.planContextCompactionStateUpdate/.test(
        runtimeContextPolicySurface,
      ) &&
      /plannedContextCompactionRunRecord/.test(runtimeContextPolicySurface) &&
      /plannedContextCompactionAgentRecord/.test(runtimeContextPolicySurface) &&
      /plannedContextCompactionOperationKind/.test(runtimeContextPolicySurface) &&
      /planContextCompactionStateUpdate/.test(runtimeContextPolicySurfaceTest) &&
      /context policy surface fails closed without Rust-planned compaction target records/.test(
        runtimeContextPolicySurfaceTest,
      ) &&
      /context policy surface fails closed without Rust-planned compaction operation kind/.test(
        runtimeContextPolicySurfaceTest,
      ) &&
      !/appendOperatorControlDep|contextCompaction:\s*\{/.test(runtimeContextPolicySurface) &&
      !/stateUpdate\.run\s*\?\?\s*latestRun/.test(runtimeContextPolicySurface) &&
      !/stateUpdate\.agent\s*\?\?\s*\{\s*\.\.\.agent,\s*updatedAt: event\.created_at\s*\}/.test(
        runtimeContextPolicySurface,
      ) &&
      !/stateUpdate\.operation_kind\s*\?\?\s*"thread\.compact"/.test(
        runtimeContextPolicySurface,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-surface.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-surface.test.mjs",
    ],
    "Phase 9/10 is pending: context-compaction run/agent state updates must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "daemon-static-scan-marker-comments-retired",
    !/Static scan pattern compliance markers|Static check markers to satisfy/.test(
      `${runtimeDaemonIndex}\n${modelMountingState}`,
    ),
    [
      "packages/runtime-daemon/src/index.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 11 is pending: daemon JS surfaces must not retain static scan-marker comment blocks as compatibility shims for conformance evidence",
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
      !/IOI_ENABLE_INTERNAL_FIXTURE_MODELS/.test(modelMountAdmissionRunner) &&
      !/mockFixtureResponse/.test(modelMountAdmissionRunner) &&
      !/isFixtureRequest/.test(modelMountAdmissionRunner) &&
      /export function defaultRouteRecords\(\)/.test(modelMountDefaultRecords) &&
      !/internalFixtureModelsEnabled/.test(modelMountDefaultRecords) &&
      !/defaultRouteRecords\(env/.test(modelMountDefaultRecords) &&
      !/fallback:\s*isFixtureEnabled/.test(modelMountDefaultRecords) &&
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
      !/formatModelRouteDecision/.test(threadTurnProjection) &&
      !/^\s*(?:schemaVersion|eventKind|decisionId)\s*:/m.test(threadTurnProjection) &&
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
    "model-mount-provider-request-policy-alias-retired",
    /const policy = originalBody\.model_policy \?\? \{\};/.test(modelRouteDecisionModule) &&
      !/originalBody\.modelPolicy\b/.test(modelRouteDecisionModule) &&
      /provider request body ignores retired modelPolicy reasoning alias/.test(modelRouteDecisionTest),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
    ],
    "Phase 10/11 is pending: provider-native request shaping must read canonical model_policy only and ignore retired modelPolicy request aliases",
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
    "model-mount-route-decision-workflow-request-aliases-retired",
    /workflowGraphId:\s*optionalString\(body\.workflow_graph_id\)/.test(modelRouteDecisionModule) &&
      /workflowNodeId:\s*optionalString\(body\.workflow_node_id\)/.test(modelRouteDecisionModule) &&
      /workflowNodeType:\s*optionalString\(body\.workflow_node_type\)/.test(modelRouteDecisionModule) &&
      !/body\.(?:workflowGraphId|workflowNodeId|node_id|nodeId|workflowNodeType|node)\b/.test(
        modelRouteDecisionModule,
      ) &&
      /route decision workflow context ignores retired request aliases/.test(modelRouteDecisionTest),
    [
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.test.mjs",
    ],
    "Phase 3/10 is pending: model route-decision workflow context extraction must ignore retired workflow request aliases",
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
    "model-mount-camelcase-fallback-wrapper-retired",
    !/(?:withCamelCaseFallback|camelCaseFallback|Symbol\.for\("withCamelCaseFallback"\)|snakeToCamel)/.test(
      [
        modelMountIoBridge,
        runtimeHttpUtilsBridge,
        modelRoutes,
        modelRouteDecisionModule,
        modelMountingReadProjectionFacade,
        modelMountReceiptOperationsBridge,
      ].join("\n"),
    ) &&
      /details:\s*redact\(error\?\.details \?\? \{\}\)/.test(runtimeHttpUtilsBridge) &&
      /return state\.store\.listReceipts\(\);/.test(modelMountReceiptOperationsBridge) &&
      /return state\.store\.getReceipt\(receiptId\);/.test(modelMountReceiptOperationsBridge) &&
      /return buildModelMountingProjection\(state,\s*\{ schemaVersion: modelMountSchemaVersion \}\);/.test(
        modelMountingReadProjectionFacade,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/io.mjs",
      "packages/runtime-daemon/src/runtime-http-utils.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.mjs",
      "packages/runtime-daemon/src/model-mounting/route-decision.mjs",
      "packages/runtime-daemon/src/model-mounting/read-projection-facade.mjs",
      "packages/runtime-daemon/src/model-mounting/receipt-operations.mjs",
    ],
    "Phase 10/11 is pending: model-mounting read, receipt, route-decision, and HTTP error surfaces must not expose prototype-based camelCase compatibility wrappers",
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
    "model-mount-route-selection-request-aliases-retired",
    /RETIRED_ROUTE_SELECTION_REQUEST_ALIASES/.test(modelRoutes) &&
      /model_mount_route_selection_request_aliases_retired/.test(modelRoutes) &&
      (modelRoutes.match(/assertCanonicalRouteSelectionRequestBody\(body\);/g) ?? []).length >= 2 &&
      /const policy = body\.model_policy \?\? \{\};/.test(modelRoutes) &&
      /const requestedModel = body\.model \?\? body\.model_id \?\? null;/.test(modelRoutes) &&
      /modelId:\s*body\.model \?\? body\.model_id/.test(modelRoutes) &&
      /policy:\s*body\.model_policy \?\? \{\}/.test(modelRoutes) &&
      !/body\.(?:modelId|modelPolicy|workflowGraphId|workflowNodeId|nodeId|node_id|workflowNodeType)\b/.test(modelRoutes) &&
      /route receipt rejects retired request aliases before receipt allocation/.test(modelRoutesTest) &&
      /test route rejects retired request aliases before route lookup/.test(modelRoutesTest) &&
      /retired_aliases/.test(modelRoutesTest) &&
      /canonical_fields/.test(modelRoutesTest),
    [
      "packages/runtime-daemon/src/model-mounting/routes.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.test.mjs",
    ],
    "Phase 3/10 is pending: model route-selection and test-route request bodies must fail closed on retired model/workflow aliases before receipt allocation or route lookup",
  );
  assertCheck(
    result,
    "model-mount-route-selection-authority-request-aliases-retired",
    (modelRoutes.match(/assertCanonicalRouteSelectionRequestBody\(body\);/g) ?? []).length >= 3 &&
      /"authorityGrantRefs"/.test(modelRoutes) &&
      /"authorityReceiptRefs"/.test(modelRoutes) &&
      /"custodyRef"/.test(modelRoutes) &&
      /"privacyProfile"/.test(modelRoutes) &&
      /"nodePlaintextAllowed"/.test(modelRoutes) &&
      /authority_grant_refs:\s*normalizeRefs\(body\.authority_grant_refs\)/.test(modelRoutes) &&
      /authority_receipt_refs:\s*normalizeRefs\(body\.authority_receipt_refs\)/.test(modelRoutes) &&
      /body\.custody_ref \?\?\s*selection\?\.endpoint\?\.custodyRef/.test(modelRoutes) &&
      /body\.privacy_profile \?\?\s*policy\.privacy_profile/.test(modelRoutes) &&
      /body\.node_plaintext_allowed \?\?\s*selection\?\.endpoint\?\.nodePlaintextAllowed/.test(modelRoutes) &&
      !/body\.(?:authorityGrantRefs|authorityReceiptRefs|custodyRef|privacyProfile|nodePlaintextAllowed)\b/.test(
        modelRoutes,
      ) &&
      !/policy\.privacyProfile\b/.test(modelRoutes) &&
      /route receipt rejects retired authority request aliases before receipt allocation/.test(modelRoutesTest) &&
      /route request rejects retired authority aliases before Rust admission request build/.test(modelRoutesTest) &&
      /route request ignores retired policy privacy profile alias/.test(modelRoutesTest),
    [
      "packages/runtime-daemon/src/model-mounting/routes.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.test.mjs",
    ],
    "Phase 3/10 is pending: model route-selection Rust admission request fields must fail closed on retired authority/custody aliases and ignore retired nested privacyProfile policy aliases",
  );
  assertCheck(
    result,
    "model-mount-route-upsert-request-aliases-retired",
    /RETIRED_ROUTE_UPSERT_REQUEST_ALIASES/.test(modelRoutes) &&
      /model_mount_route_upsert_request_aliases_retired/.test(modelRoutes) &&
      /assertCanonicalRouteUpsertRequestBody\(body\);/.test(modelRoutes) &&
      /maxCostUsd:\s*Number\(body\.max_cost_usd \?\? 0\.25\)/.test(modelRoutes) &&
      /maxLatencyMs:\s*Number\(body\.max_latency_ms \?\? 30000\)/.test(modelRoutes) &&
      /providerEligibility:\s*normalizeScopes\(body\.provider_eligibility,\s*\[\]\)/.test(modelRoutes) &&
      /deniedProviders:\s*normalizeScopes\(body\.denied_providers,\s*\[\]\)/.test(modelRoutes) &&
      /lastSelectedModel:\s*body\.last_selected_model \?\? null/.test(modelRoutes) &&
      /lastReceiptId:\s*body\.last_receipt_id \?\? null/.test(modelRoutes) &&
      !/body\.(?:maxCostUsd|maxLatencyMs|providerEligibility|deniedProviders|lastSelectedModel|lastReceiptId)\b/.test(
        modelRoutes,
      ) &&
      /route upsert rejects retired request aliases before state write/.test(modelRoutesTest) &&
      /retired_aliases,\s*\[\s*"maxCostUsd",\s*"maxLatencyMs",\s*"providerEligibility",\s*"deniedProviders",\s*"lastSelectedModel",\s*"lastReceiptId",\s*\]/.test(
        modelRoutesTest,
      ) &&
      /canonical_fields,\s*\[\s*"max_cost_usd",\s*"max_latency_ms",\s*"provider_eligibility",\s*"denied_providers",\s*"last_selected_model",\s*"last_receipt_id",\s*\]/.test(
        modelRoutesTest,
      ) &&
      !/(?:providerEligibility|deniedProviders)/.test(
        read("scripts/lib/live-runtime-daemon-contract.test.mjs"),
      ),
    [
      "packages/runtime-daemon/src/model-mounting/routes.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.test.mjs",
      "scripts/lib/live-runtime-daemon-contract.test.mjs",
    ],
    "Phase 3/10 is pending: model route upsert request bodies must fail closed on retired camelCase policy/status aliases before route state writes",
  );
  assertCheck(
    result,
    "model-mount-anthropic-messages-request-aliases-retired",
    /RETIRED_ANTHROPIC_MESSAGES_REQUEST_ALIASES/.test(openAiCompatRoutes) &&
      /model_mount_anthropic_messages_request_aliases_retired/.test(openAiCompatRoutes) &&
      /assertCanonicalAnthropicMessagesRequestBody\(body\);/.test(openAiCompatRoutes) &&
      /max_tokens:\s*body\.max_tokens/.test(openAiCompatRoutes) &&
      !/body\.maxTokens\b/.test(openAiCompatRoutes) &&
      /Anthropic messages canonical body preserves canonical max_tokens/.test(openAiCompatRoutesTest) &&
      /Anthropic messages canonical body rejects retired maxTokens alias/.test(openAiCompatRoutesTest) &&
      /retired_aliases,\s*\[\s*"maxTokens"\s*\]/.test(openAiCompatRoutesTest) &&
      /canonical_fields,\s*\[\s*"max_tokens"\s*\]/.test(openAiCompatRoutesTest),
    [
      "packages/runtime-daemon/src/openai-compat-routes.mjs",
      "packages/runtime-daemon/src/openai-compat-routes.test.mjs",
    ],
    "Phase 10/11 is pending: Anthropic-compatible messages requests must fail closed on the retired maxTokens alias and forward canonical max_tokens only",
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
    "model-mount-invocation-request-aliases-retired",
    /RETIRED_MODEL_INVOCATION_REQUEST_ALIASES/.test(modelInvocationOps) &&
      /model_mount_invocation_request_aliases_retired/.test(modelInvocationOps) &&
      (modelInvocationOps.match(/assertCanonicalModelInvocationRequestBody\(body\)/g) ?? []).length >= 2 &&
      !/body\.(?:routeId|modelPolicy|responseId|previousResponseId|sendOptions)\b/.test(
        modelInvocationOps,
      ) &&
      /model invocations reject retired camelCase request aliases before authorization/.test(
        modelInvocationOpsTest,
      ) &&
      /retired_aliases,\s*\[\s*"routeId",\s*"modelPolicy",\s*"responseId",\s*"previousResponseId",\s*"sendOptions",\s*\]/.test(
        modelInvocationOpsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
    ],
    "Phase 10/11 is pending: model invocation request bodies must fail closed on retired camelCase routing, policy, response, and send-option aliases",
  );
  assertCheck(
    result,
    "model-mount-invocation-coalesce-policy-alias-retired",
    /policyHash:\s*stableHash\(body\.model_policy \?\? \{\}\)/.test(providerDriverHelpers) &&
      !/body\.modelPolicy\b/.test(providerDriverHelpers) &&
      /coalesce keys ignore retired modelPolicy policy alias/.test(providerDriverHelpersTest),
    [
      "packages/runtime-daemon/src/model-mounting/provider-driver-helpers.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-driver-helpers.test.mjs",
    ],
    "Phase 10/11 is pending: model invocation coalesce keys must hash canonical model_policy only and ignore retired modelPolicy request aliases",
  );
  assertCheck(
    result,
    "model-mount-invocation-authority-request-aliases-retired",
    /"authorityGrantRefs"/.test(modelInvocationOps) &&
      /"authorityReceiptRefs"/.test(modelInvocationOps) &&
      /"custodyRef"/.test(modelInvocationOps) &&
      /"privacyProfile"/.test(modelInvocationOps) &&
      /"nodePlaintextAllowed"/.test(modelInvocationOps) &&
      (modelInvocationOps.match(/assertCanonicalModelInvocationRequestBody\(body\)/g) ?? []).length >= 4 &&
      /authority_grant_refs:\s*uniqueRefs\(\[\s*optionalRef\(receiptDetails\.grant_id\),\s*\.\.\.\(Array\.isArray\(body\.authority_grant_refs\)/.test(
        modelInvocationOps,
      ) &&
      /authority_grant_refs:\s*uniqueRefs\(\[\s*optionalRef\(token\.grantId\),\s*\.\.\.\(Array\.isArray\(body\.authority_grant_refs\)/.test(
        modelInvocationOps,
      ) &&
      /authority_receipt_refs:\s*uniqueRefs\(\[\s*\.\.\.\(Array\.isArray\(body\.authority_receipt_refs\)/.test(
        modelInvocationOps,
      ) &&
      /body\.custody_ref \?\?\s*selection\?\.endpoint\?\.custodyRef/.test(modelInvocationOps) &&
      /body\.privacy_profile \?\?\s*policy\.privacy_profile/.test(modelInvocationOps) &&
      /body\.node_plaintext_allowed \?\?\s*selection\?\.endpoint\?\.nodePlaintextAllowed/.test(
        modelInvocationOps,
      ) &&
      !/body\.(?:authorityGrantRefs|authorityReceiptRefs|custodyRef|privacyProfile|nodePlaintextAllowed)\b/.test(
        modelInvocationOps,
      ) &&
      !/policy\.privacyProfile\b/.test(modelInvocationOps) &&
      /model invocations reject retired authority request aliases before authorization/.test(modelInvocationOpsTest) &&
      /modelMountInvocationAdmissionRequestForReceipt rejects retired authority aliases before ref validation/.test(
        modelInvocationOpsTest,
      ) &&
      /modelMountProviderExecutionRequestForInvocation rejects retired authority aliases before route receipt validation/.test(
        modelInvocationOpsTest,
      ) &&
      /model mount invocation admission builders ignore retired policy privacy profile alias/.test(
        modelInvocationOpsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs",
    ],
    "Phase 10/11 is pending: model invocation admission/provider-execution request bodies must fail closed on retired authority/custody aliases and ignore retired nested privacyProfile policy aliases",
  );
  assertCheck(
    result,
    "model-mount-sdk-receipt-metadata-aliases-retired",
    /route_id:\s*string/.test(agentSdkModelInvocationReceiptType) &&
      /route_receipt_id\?:\s*string/.test(agentSdkModelInvocationReceiptType) &&
      /selected_model:\s*string/.test(agentSdkModelInvocationReceiptType) &&
      /token_count:\s*\{/.test(agentSdkModelInvocationReceiptType) &&
      /response_id\?:\s*string \| null/.test(agentSdkModelInvocationReceiptType) &&
      !/(?:routeId|routeReceiptId|selectedModel|endpointId|providerId|instanceId|backendId|selectedBackend|policyHash|grantId|tokenCount|latencyMs|inputHash|outputHash|providerResponseKind|backendEvidenceRefs|toolReceiptIds|ephemeralMcpServerIds|responseId)\??:/.test(
        agentSdkModelInvocationReceiptType,
      ) &&
      /created_at:\s*string/.test(agentSdkModelConversationStateType) &&
      /route_id:\s*string/.test(agentSdkModelConversationStateType) &&
      /endpoint_id:\s*string/.test(agentSdkModelConversationStateType) &&
      /selected_model:\s*string/.test(agentSdkModelConversationStateType) &&
      /token_count:\s*\{/.test(agentSdkModelConversationStateType) &&
      /message_count:\s*number/.test(agentSdkModelConversationStateType) &&
      /plaintext_persisted:\s*false/.test(agentSdkModelConversationStateType) &&
      !/(?:createdAt|routeId|endpointId|selectedModel|providerId|backendId|instanceId|receiptId|routeReceiptId|streamReceiptId|inputHash|outputHash|tokenCount|messageCount|plaintextPersisted)\??:/.test(
        agentSdkModelConversationStateType,
      ),
    ["packages/agent-sdk/src/model-mounts.ts"],
    "Phase 10/11 is pending: SDK model-mount receipt and conversation-state types must expose canonical snake_case metadata only",
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
      !/responsesFallbackStatus/.test(openAiCompatibleDriver) &&
      !/error\?\.details\?\.httpStatus/.test(openAiCompatibleDriver) &&
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
      /const compatTranslation = optionalRef\(providerResult\.compat_translation\)/.test(modelInvocationOps) &&
      /retired_aliases: retiredAliases/.test(modelInvocationOps) &&
      !/providerResult\.compatTranslation\s*\?\?\s*providerResult\.compat_translation/.test(modelInvocationOps) &&
      !/compatTranslation:\s*providerResult\.compatTranslation/.test(modelInvocationOps) &&
      !/error\.details = \{ compatTranslation \}/.test(modelInvocationOps) &&
      !/compat_translation:\s*invocation\.compatTranslation/.test(openAiCompatRoutes) &&
      !/compatTranslation\??:/.test(agentSdkModelMounts) &&
      /rejects provider compatibility translations before result admission/.test(
        read("packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs"),
      ) &&
      /retired_aliases\.includes\("compatTranslation"\)/.test(
        read("packages/runtime-daemon/src/model-mounting/model-invocation-operations.test.mjs"),
      ) &&
      /Object\.hasOwn\(error\.details,\s*"compatTranslation"\)\s*===\s*false/.test(
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
      /providerId:\s*"provider\.autopilot\.local"/.test(modelMountingReadModelTest) &&
      /assert\.equal\(nativeModel\.provider,\s*"ioi-daemon-local"\)/.test(modelMountingReadModelTest) &&
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
    "workspace-restore-apply-policy-live-bridge",
    /WorkspaceRestoreApplyPolicyCore/.test(workspaceRestoreKernel) &&
      /plan_apply_policy/.test(workspaceRestoreKernel) &&
      /WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION/.test(workspaceRestoreKernel) &&
      /operation_apply_blocked_reason/.test(workspaceRestoreKernel) &&
      /WorkspaceRestoreApplyPolicyBridgeRequest/.test(bridgeModule) &&
      /plan_workspace_restore_apply_policy/.test(bridgeModule) &&
      /rust_workspace_restore_policy_command/.test(bridgeModule) &&
      /workspace_restore_apply_policy_invalid/.test(bridgeModule) &&
      /bridge_plans_workspace_restore_apply_policy_through_rust_core/.test(bridgeModule),
    [
      "crates/services/src/agentic/runtime/kernel/workspace_restore.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
    ],
    "Phase 10 is pending: workspace restore apply policy must be planned by the Rust daemon core and exposed through the command bridge",
  );
  assertCheck(
    result,
    "workspace-restore-operations-live-bridge",
    /WorkspaceRestoreOperationsCore/.test(workspaceRestoreKernel) &&
      /preview_operations/.test(workspaceRestoreKernel) &&
      /apply_operations/.test(workspaceRestoreKernel) &&
      /WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION/.test(workspaceRestoreKernel) &&
      /WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION/.test(workspaceRestoreKernel) &&
      /WorkspaceRestoreOperationsBridgeRequest/.test(bridgeModule) &&
      /preview_workspace_restore_operations/.test(bridgeModule) &&
      /apply_workspace_restore_operations/.test(bridgeModule) &&
      /rust_workspace_restore_operations_command/.test(bridgeModule) &&
      /workspace_restore_operations_invalid/.test(bridgeModule) &&
      /bridge_applies_workspace_restore_operations_through_rust_core/.test(bridgeModule),
    [
      "crates/services/src/agentic/runtime/kernel/workspace_restore.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
    ],
    "Phase 10 is pending: workspace restore preview/apply operations must be executed by the Rust daemon core and exposed through the command bridge",
  );
  assertCheck(
    result,
    "workspace-snapshot-capture-live-bridge",
    /WorkspaceSnapshotCaptureCore/.test(workspaceRestoreKernel) &&
      /capture_files/.test(workspaceRestoreKernel) &&
      /WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION/.test(workspaceRestoreKernel) &&
      /WORKSPACE_SNAPSHOT_CAPTURE_RESULT_SCHEMA_VERSION/.test(workspaceRestoreKernel) &&
      /WorkspaceSnapshotCaptureBridgeRequest/.test(bridgeModule) &&
      /capture_workspace_snapshot_files/.test(bridgeModule) &&
      /rust_workspace_snapshot_capture_command/.test(bridgeModule) &&
      /workspace_snapshot_capture_invalid/.test(bridgeModule) &&
      /bridge_captures_workspace_snapshot_files_through_rust_core/.test(bridgeModule),
    [
      "crates/services/src/agentic/runtime/kernel/workspace_restore.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
    ],
    "Phase 10 is pending: workspace snapshot capture must be produced by the Rust daemon core and exposed through the command bridge",
  );
  assertCheck(
    result,
    "workspace-restore-daemon-runner",
    /WORKSPACE_RESTORE_COMMAND_ENV/.test(workspaceRestoreRunner) &&
      /IOI_WORKSPACE_RESTORE_COMMAND/.test(workspaceRestoreRunner) &&
      /RustWorkspaceRestoreRunner/.test(workspaceRestoreRunner) &&
      /createWorkspaceRestoreRunnerFromEnv/.test(workspaceRestoreRunner) &&
      /createWorkspaceRestoreRunnerFromEnv/.test(runtimeDaemonIndex) &&
      /this\.workspaceRestoreRunner/.test(runtimeDaemonIndex) &&
      /planApplyPolicy/.test(workspaceRestoreRunner) &&
      /previewOperations/.test(workspaceRestoreRunner) &&
      /applyOperations/.test(workspaceRestoreRunner) &&
      /captureSnapshotFiles/.test(workspaceRestoreRunner) &&
      /plan_workspace_restore_apply_policy/.test(workspaceRestoreRunner) &&
      /preview_workspace_restore_operations/.test(workspaceRestoreRunner) &&
      /apply_workspace_restore_operations/.test(workspaceRestoreRunner) &&
      /capture_workspace_snapshot_files/.test(workspaceRestoreRunner) &&
      /rust_workspace_restore/.test(workspaceRestoreRunner) &&
      /workspace_restore_bridge_unconfigured/.test(workspaceRestoreRunner) &&
      /workspace restore runner sends apply policy bridge request/.test(
        workspaceRestoreRunnerTest,
      ) &&
      /workspace restore runner sends preview operations bridge request/.test(
        workspaceRestoreRunnerTest,
      ) &&
      /workspace restore runner sends apply operations bridge request/.test(
        workspaceRestoreRunnerTest,
      ) &&
      /workspace restore runner sends snapshot capture bridge request/.test(
        workspaceRestoreRunnerTest,
      ) &&
      /workspace restore runner fails closed without command/.test(
        workspaceRestoreRunnerTest,
      ) &&
      /workspace restore runner surfaces Rust policy rejection/.test(
        workspaceRestoreRunnerTest,
      ) &&
      /workspaceRestoreRunner/.test(runtimeWorkspaceSnapshotSurface) &&
      /planWorkspaceRestoreApplyPolicy/.test(runtimeWorkspaceSnapshotSurface) &&
      /previewWorkspaceRestoreOperations/.test(runtimeWorkspaceSnapshotSurface) &&
      /applyWorkspaceRestoreOperations/.test(runtimeWorkspaceSnapshotSurface) &&
      /captureWorkspaceSnapshotFiles/.test(runtimeWorkspaceSnapshotSurface) &&
      /workspace_restore_bridge_unconfigured/.test(runtimeWorkspaceSnapshotSurface) &&
      !/workspaceRestoreApplyApprovalForRequest/.test(runtimeWorkspaceSnapshotSurface) &&
      !/workspaceRestoreApplyAllowsConflicts/.test(runtimeWorkspaceSnapshotSurface) &&
      !/workspaceRestoreApplyPolicyDecisionRefs/.test(runtimeWorkspaceSnapshotSurface) &&
      !/workspaceRestorePreviewOperation/.test(runtimeWorkspaceSnapshotSurface) &&
      !/workspaceRestoreApplyOperations/.test(runtimeWorkspaceSnapshotSurface) &&
      !/workspaceSnapshotFileForPatch/.test(runtimeWorkspaceSnapshotSurface) &&
      !/workspaceSnapshotContentDraftsByPath/.test(runtimeWorkspaceSnapshotSurface) &&
      !/workspaceRestorePreviewOperation/.test(workspaceRestoreHelpers) &&
      !/workspaceRestoreApplyOperations/.test(workspaceRestoreHelpers) &&
      !/applyWorkspaceRestoreFile/.test(workspaceRestoreHelpers) &&
      !/workspaceSnapshotFileForPatch/.test(workspaceRestoreHelpers) &&
      !/workspaceSnapshotCaptureSide/.test(workspaceRestoreHelpers) &&
      /workspaceRestoreRunner/.test(runtimeWorkspaceSnapshotSurfaceTest),
    [
      "packages/runtime-daemon/src/runtime-workspace-restore-runner.mjs",
      "packages/runtime-daemon/src/runtime-workspace-restore-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-workspace-snapshot-surface.mjs",
      "packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs",
      "packages/runtime-daemon/src/workspace-restore.mjs",
      "packages/runtime-daemon/src/index.mjs",
    ],
    "Phase 10 is pending: daemon workspace restore facade must call the Rust bridge for policy and file operations without JS restore IO fallback",
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
    "worker-service-package-admission-request-aliases-retired",
    /RETIRED_WORKER_SERVICE_PACKAGE_REQUEST_ALIASES/.test(workerServicePackageSurface) &&
      /CANONICAL_WORKER_SERVICE_PACKAGE_REQUEST_FIELDS/.test(workerServicePackageSurface) &&
      /worker_service_package_invocation_request_aliases_retired/.test(workerServicePackageSurface) &&
      /assertCanonicalWorkerServicePackageRequestBody\(body\);[\s\S]*objectRecord\(body\.invocation\)/.test(
        workerServicePackageSurface,
      ) &&
      !/body\.(?:packageInvocation|package_invocation)\b/.test(workerServicePackageSurface) &&
      /worker\/service package surface rejects retired request aliases before agent lookup or Rust runner/.test(
        workerServicePackageSurfaceTest,
      ) &&
      /assert\.deepEqual\(runtimeStore\.calls,\s*\[\]\)/.test(workerServicePackageSurfaceTest) &&
      /retiredWorkerServicePackageRequestAliases/.test(workerServicePackageControlNodesTest) &&
      /Object\.prototype\.hasOwnProperty\.call\(request\.body,\s*key\)/.test(
        workerServicePackageControlNodesTest,
      ) &&
      !/^\s*package_invocation:\s*RuntimeWorkerServicePackageInvocation;/m.test(
        workerServicePackageControlNodes,
      ) &&
      !/^\s*packageInvocation:\s*RuntimeWorkerServicePackageInvocation;/m.test(
        workerServicePackageControlNodes,
      ) &&
      !/package_invocation:\s*invocation/.test(workerServicePackageControlNodes) &&
      !/packageInvocation:\s*invocation/.test(workerServicePackageControlNodes),
    [
      "packages/runtime-daemon/src/runtime-worker-service-package-surface.mjs",
      "packages/runtime-daemon/src/runtime-worker-service-package-surface.test.mjs",
      "packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-worker-service-package-control-nodes.test.ts",
    ],
    "Phase 8/11 is pending: worker/service package admission requests must fail closed on retired invocation wrapper aliases and IDE clients must emit canonical request bodies",
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
    "l1-settlement-admission-request-aliases-retired",
    /RETIRED_L1_SETTLEMENT_REQUEST_ALIASES/.test(l1SettlementSurface) &&
      /CANONICAL_L1_SETTLEMENT_REQUEST_FIELDS/.test(l1SettlementSurface) &&
      /l1_settlement_attempt_request_aliases_retired/.test(l1SettlementSurface) &&
      /assertCanonicalL1SettlementRequestBody\(body\);[\s\S]*objectRecord\(body\.attempt\)/.test(
        l1SettlementSurface,
      ) &&
      !/body\.(?:settlementAttempt|settlement_attempt)\b/.test(l1SettlementSurface) &&
      /L1 settlement surface rejects retired request aliases before agent lookup or Rust runner/.test(
        l1SettlementSurfaceTest,
      ) &&
      /assert\.deepEqual\(runtimeStore\.calls,\s*\[\]\)/.test(l1SettlementSurfaceTest) &&
      /retiredL1SettlementRequestAliases/.test(l1SettlementControlNodesTest) &&
      /Object\.prototype\.hasOwnProperty\.call\(request\.body,\s*key\)/.test(
        l1SettlementControlNodesTest,
      ) &&
      !/^\s*settlement_attempt:\s*RuntimeL1SettlementAttempt;/m.test(
        l1SettlementControlNodes,
      ) &&
      !/^\s*settlementAttempt:\s*RuntimeL1SettlementAttempt;/m.test(
        l1SettlementControlNodes,
      ) &&
      !/settlement_attempt:\s*attempt/.test(l1SettlementControlNodes) &&
      !/settlementAttempt:\s*attempt/.test(l1SettlementControlNodes),
    [
      "packages/runtime-daemon/src/runtime-l1-settlement-surface.mjs",
      "packages/runtime-daemon/src/runtime-l1-settlement-surface.test.mjs",
      "packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-l1-settlement-control-nodes.test.ts",
    ],
    "Phase 8/11 is pending: L1 settlement admission requests must fail closed on retired attempt wrapper aliases and IDE clients must emit canonical request bodies",
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
    "governed-meta-improvement-admission-request-aliases-retired",
    /RETIRED_GOVERNED_IMPROVEMENT_REQUEST_ALIASES/.test(governedImprovementSurface) &&
      /CANONICAL_GOVERNED_IMPROVEMENT_REQUEST_FIELDS/.test(governedImprovementSurface) &&
      /governed_improvement_proposal_request_aliases_retired/.test(
        governedImprovementSurface,
      ) &&
      /assertCanonicalGovernedImprovementRequestBody\(body\);[\s\S]*objectRecord\(body\.proposal\)/.test(
        governedImprovementSurface,
      ) &&
      !/body\.(?:proposalPayload|proposal_payload)\b/.test(governedImprovementSurface) &&
      /governed improvement surface rejects retired request aliases before agent lookup or Rust runner/.test(
        governedImprovementSurfaceTest,
      ) &&
      /assert\.deepEqual\(runtimeStore\.calls,\s*\[\]\)/.test(
        governedImprovementSurfaceTest,
      ) &&
      /retiredGovernedImprovementRequestAliases/.test(
        governedImprovementControlNodesTest,
      ) &&
      /Object\.prototype\.hasOwnProperty\.call\(request\.body,\s*key\)/.test(
        governedImprovementControlNodesTest,
      ) &&
      !/^\s*proposal_payload:\s*RuntimeGovernedImprovementProposal;/m.test(
        governedImprovementControlNodes,
      ) &&
      !/^\s*proposalPayload:\s*RuntimeGovernedImprovementProposal;/m.test(
        governedImprovementControlNodes,
      ) &&
      !/proposal_payload:\s*proposal/.test(governedImprovementControlNodes) &&
      !/proposalPayload:\s*proposal/.test(governedImprovementControlNodes),
    [
      "packages/runtime-daemon/src/runtime-governed-improvement-surface.mjs",
      "packages/runtime-daemon/src/runtime-governed-improvement-surface.test.mjs",
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.test.ts",
    ],
    "Phase 9/11 is pending: governed-improvement admission requests must fail closed on retired proposal wrapper aliases and IDE clients must emit canonical request bodies",
  );
  assertCheck(
    result,
    "governed-meta-improvement-proposal-input-aliases-retired",
    /RETIRED_GOVERNED_IMPROVEMENT_PROPOSAL_INPUT_FIELDS/.test(
      governedImprovementControlNodes,
    ) &&
      /assertCanonicalGovernedImprovementProposalInputField\(proposalField\)/.test(
        governedImprovementControlNodes,
      ) &&
      !/objectAtPath\(params\.input,\s*"proposal_payload"\)/.test(
        governedImprovementControlNodes,
      ) &&
      !/objectAtPath\(params\.input,\s*"proposalPayload"\)/.test(
        governedImprovementControlNodes,
      ) &&
      /builds governed improvement controls from canonical input proposal/.test(
        governedImprovementControlNodesTest,
      ) &&
      /governed improvement controls reject retired proposal input field aliases/.test(
        governedImprovementControlNodesTest,
      ) &&
      /retiredGovernedImprovementProposalInputFields/.test(
        governedImprovementControlNodesTest,
      ),
    [
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.test.ts",
    ],
    "Phase 10/11 is pending: governed-improvement IDE clients must not preserve retired proposal input wrapper fallbacks after canonical request bodies are verified",
  );
  assertCheck(
    result,
    "governed-meta-improvement-proposal-payload-aliases-retired",
    /RETIRED_GOVERNED_IMPROVEMENT_PROPOSAL_PAYLOAD_FIELDS/.test(
      governedImprovementControlNodes,
    ) &&
      /assertCanonicalGovernedImprovementProposalPayload\(proposalSeed\);/.test(
        governedImprovementControlNodes,
      ) &&
      /assertCanonicalGovernedImprovementProposalPayload\(params\.input\);/.test(
        governedImprovementControlNodes,
      ) &&
      !/proposalSeed\.schemaVersion/.test(governedImprovementControlNodes) &&
      !/stringField\(proposalSeed,\s*"(?:proposalId|targetRef|candidateRef|sourceTraceRef|approvalRef|rollbackRef|agentgresOperationRef|stateRootBefore|stateRootAfter|resultingHead)"\)/.test(
        governedImprovementControlNodes,
      ) &&
      !/stringArrayField\(proposalSeed,\s*"(?:evalReceiptRefs|verifierReceiptRefs|expectedHeads)"\)/.test(
        governedImprovementControlNodes,
      ) &&
      !/stringAtPath\(params\.input,\s*"(?:proposalId|targetRef|candidateRef|sourceTraceRef|approvalRef|rollbackRef|agentgresOperationRef|stateRootBefore|stateRootAfter|resultingHead)"\)/.test(
        governedImprovementControlNodes,
      ) &&
      !/stringArrayAtPath\(params\.input,\s*"(?:evalReceiptRefs|verifierReceiptRefs|expectedHeads)"\)/.test(
        governedImprovementControlNodes,
      ) &&
      /retiredGovernedImprovementProposalPayloadAliases/.test(
        governedImprovementControlNodesTest,
      ) &&
      /Object\.prototype\.hasOwnProperty\.call\(request\.body\.proposal,\s*key\)/.test(
        governedImprovementControlNodesTest,
      ) &&
      /governed improvement controls reject retired proposal payload aliases/.test(
        governedImprovementControlNodesTest,
      ) &&
      /governed improvement controls reject raw input proposal payload aliases/.test(
        governedImprovementControlNodesTest,
      ),
    [
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.test.ts",
    ],
    "Phase 10/11 is pending: governed-improvement IDE proposal payloads must fail closed on retired camelCase aliases instead of forwarding them inside canonical proposal requests",
  );
  assertCheck(
    result,
    "governed-meta-improvement-workflow-logic-aliases-retired",
    /RETIRED_GOVERNED_IMPROVEMENT_WORKFLOW_LOGIC_FIELDS/.test(
      governedImprovementControlNodes,
    ) &&
      /assertCanonicalGovernedImprovementWorkflowLogic\(logic\);/.test(
        governedImprovementControlNodes,
      ) &&
      !/objectField\(logic,\s*"governedImprovement"\)/.test(
        governedImprovementControlNodes,
      ) &&
      !/objectField\(logic,\s*"runtimeImprovementProposal"\)/.test(
        governedImprovementControlNodes,
      ) &&
      !/stringField\(logic,\s*"workflowNodeId"/.test(
        governedImprovementControlNodes,
      ) &&
      /retiredGovernedImprovementWorkflowLogicAliases/.test(
        governedImprovementControlNodesTest,
      ) &&
      /governed improvement controls reject retired workflow logic aliases/.test(
        governedImprovementControlNodesTest,
      ) &&
      /proposal:\s*proposal\(\)/.test(governedImprovementControlNodesTest),
    [
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-governed-improvement-control-nodes.test.ts",
    ],
    "Phase 10/11 is pending: governed-improvement workflow nodes must use canonical proposal and workflow_node_id logic fields without retired governedImprovement/runtimeImprovementProposal/workflowNodeId fallbacks",
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
  const providerSecretInputBlock =
    providerAuth.match(/export function providerSecretInput[\s\S]*?function assertCanonicalProviderSecretRequestBody/)?.[0] ?? "";
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
  const providerUpsertBlock =
    providerOperations.match(/export function upsertProvider[\s\S]*?function assertCanonicalProviderUpsertRequestBody/)?.[0] ?? "";
  const catalogProviderConfig = exists("packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs")
    : "";
  const catalogProviderConfigTest = exists("packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs")
    : "";
  const catalogProviderRuntimeMaterialFromBodyBlock =
    catalogProviderConfig.match(/export function catalogProviderRuntimeMaterialFromBody[\s\S]*?export function catalogProviderAuthConfig/)?.[0] ?? "";
  const catalogProviderAuthConfigBlock =
    catalogProviderConfig.match(/export function catalogProviderAuthConfig[\s\S]*?function assertCanonicalCatalogProviderAuthRequestBody/)?.[0] ?? "";
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
  const vaultOperations = exists("packages/runtime-daemon/src/model-mounting/vault-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/vault-operations.mjs")
    : "";
  const vaultOperationsTest = exists("packages/runtime-daemon/src/model-mounting/vault-operations.test.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/vault-operations.test.mjs")
    : "";
  const vaultOperationsRequestBlocks =
    vaultOperations.match(/export function bindVaultRef[\s\S]*?function assertCanonicalVaultOperationRequestBody/)?.[0] ?? "";
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
  const artifactEndpointImportBlock =
    artifactEndpointOperations.match(/export function importModel[\s\S]*?export function mountEndpoint/)?.[0] ?? "";
  const artifactEndpointMountBlock =
    artifactEndpointOperations.match(/export function mountEndpoint[\s\S]*?export function unmountEndpoint/)?.[0] ?? "";
  const artifactEndpointUnmountBlock =
    artifactEndpointOperations.match(/export function unmountEndpoint[\s\S]*?function assertCanonicalEndpointMountRequestBody/)?.[0] ?? "";
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
  const destructiveConfirmationStateBlock =
    catalogHelpers.match(/export function destructiveConfirmationState[\s\S]*?export function inferModelArchitecture/)?.[0] ?? "";
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
  const cancelDownloadBlock =
    storageOperations.match(/export function cancelDownload[\s\S]*?export function downloadStatus/)?.[0] ?? "";
  const deleteModelArtifactBlock =
    storageOperations.match(/export function deleteModelArtifact[\s\S]*?export function cleanupModelStorage/)?.[0] ?? "";
  const cleanupModelStorageBlock =
    storageOperations.match(/export function cleanupModelStorage[\s\S]*?function assertCanonicalModelStorageRequestBody/)?.[0] ?? "";
  const mcpServerReceiptDetailsHelper =
    mcpWorkflowOperations.match(/function mcpServerReceiptDetails\(server\) \{[\s\S]*?\n\}/)?.[0] ?? "";
  const mcpToolReceiptDetailsObject =
    mcpWorkflowOperations.match(/details:\s*\{\n\s+server_id:\s*serverId,[\s\S]*?\n\s+\},/)?.[0] ?? "";
  const catalogImportUrlBlock =
    catalogDownloadOperations.match(/export async function catalogImportUrl[\s\S]*?export async function downloadModel/)?.[0] ?? "";
  const downloadModelBlock =
    catalogDownloadOperations.match(/export async function downloadModel[\s\S]*$/)?.[0] ?? "";
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
  const catalogApprovalDecisionBlock =
    catalogHelpers.match(/export function catalogApprovalDecision[\s\S]*?export function normalizeDownloadPolicy/)?.[0] ?? "";
  const normalizeDownloadPolicyBlock =
    catalogHelpers.match(/export function normalizeDownloadPolicy[\s\S]*?export function assertDownloadPolicyAllowed/)?.[0] ?? "";
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
      /assertNoRetiredProviderDetailAliases/.test(modelMountReceiptWriteGuards) &&
      /retiredProviderDetailAliases/.test(modelMountReceiptWriteGuards) &&
      !/details\.providerId \?\? details\.provider_id/.test(modelMountReceiptWriteGuards) &&
      !/details\.providerKind \?\? details\.provider_kind/.test(modelMountReceiptWriteGuards) &&
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
      /retired_aliases\.includes\("providerKind"\)/.test(modelMountStoreTest) &&
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
    "model-mount-loading-request-aliases-retired",
    /RETIRED_MODEL_LOADING_REQUEST_ALIASES/.test(modelLoadingOperations) &&
      /model_mount_loading_request_aliases_retired/.test(modelLoadingOperations) &&
      (modelLoadingOperations.match(/assertCanonicalModelLoadingRequestBody\(body\);/g) ?? []).length >= 2 &&
      /state\.resolveEndpoint\(body\.endpoint_id,\s*body\.model_id\)/.test(modelLoadingOperations) &&
      /normalizeLoadPolicy\(body\.load_policy \?\? endpoint\.loadPolicy\)/.test(modelLoadingOperations) &&
      /const requestLoadOptions = body\.load_options \?\? \{\};/.test(modelLoadingOperations) &&
      /const instanceId = body\.instance_id \?\? body\.id;/.test(modelLoadingOperations) &&
      !/body\.(?:endpointId|modelId|loadPolicy|loadOptions|workflowScope|agentScope|instanceId)\b/.test(
        modelLoadingOperations,
      ) &&
      /loadModel rejects retired request aliases before endpoint resolution/.test(modelLoadingOperationsTest) &&
      /unloadModel rejects retired request aliases before instance lookup/.test(modelLoadingOperationsTest) &&
      /retired_aliases,\s*\[\s*"endpointId",\s*"modelId",\s*"loadPolicy",\s*"loadOptions",\s*"workflowScope",\s*"agentScope",\s*"instanceId",\s*\]/.test(
        modelLoadingOperationsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/model-loading-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/model-loading-operations.test.mjs",
    ],
    "Phase 9/11 is pending: model loading/unloading request bodies must fail closed on retired camelCase endpoint/model/load/scope/instance aliases",
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
    "model-mount-tokenizer-request-aliases-retired",
    /RETIRED_MODEL_TOKENIZER_REQUEST_ALIASES/.test(modelTokenizerOperations) &&
      /model_mount_tokenizer_request_aliases_retired/.test(modelTokenizerOperations) &&
      /assertCanonicalModelTokenizerRequestBody\(body\);/.test(modelTokenizerOperations) &&
      /routeId:\s*body\.route_id/.test(modelTokenizerOperations) &&
      /policy:\s*body\.model_policy \?\? \{\}/.test(modelTokenizerOperations) &&
      /body\.max_output_tokens,\s*\n\s*0/.test(modelTokenizerOperations) &&
      /const explicit = Number\(body\.context_length\);/.test(modelTokenizerOperations) &&
      !/body\.(?:routeId|modelPolicy|contextLength|contextWindow|maxOutputTokens|reserveOutputTokens|reserve_output_tokens)\b/.test(
        modelTokenizerOperations,
      ) &&
      /modelTokenizerUtility rejects retired request aliases before authorization/.test(
        modelTokenizerOperationsTest,
      ) &&
      /retired_aliases,\s*\[\s*"routeId",\s*"modelPolicy",\s*"contextLength",\s*"contextWindow",\s*"maxOutputTokens",\s*"reserveOutputTokens",\s*"reserve_output_tokens",\s*\]/.test(
        modelTokenizerOperationsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/tokenizer-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/tokenizer-operations.test.mjs",
    ],
    "Phase 10/11 is pending: tokenizer and context-fit request bodies must fail closed on retired route, policy, context-window, and output-token aliases",
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
    "model-mount-import-request-aliases-retired",
    /RETIRED_MODEL_IMPORT_REQUEST_ALIASES/.test(artifactEndpointOperations) &&
      /model_import_request_aliases_retired/.test(artifactEndpointOperations) &&
      /assertCanonicalModelImportRequestBody\(body\);/.test(artifactEndpointImportBlock) &&
      /requiredString\(body\.model_id,\s*"model_id"\)/.test(artifactEndpointImportBlock) &&
      /body\.path \?\? body\.source_path \?\? body\.local_path/.test(artifactEndpointImportBlock) &&
      /normalizeImportMode\(body\.import_mode \?\? body\.mode/.test(artifactEndpointImportBlock) &&
      /provider_id:\s*body\.provider_id \?\?/.test(artifactEndpointImportBlock) &&
      /providerId:\s*body\.provider_id \?\?/.test(artifactEndpointImportBlock) &&
      /displayName:\s*body\.display_name \?\? modelId/.test(artifactEndpointImportBlock) &&
      /sizeBytes:\s*body\.size_bytes \?\? importedInfo\?\.sizeBytes/.test(artifactEndpointImportBlock) &&
      /contextWindow:\s*body\.context_window \?\? metadata\.contextWindow/.test(artifactEndpointImportBlock) &&
      /privacyClass:\s*body\.privacy_class \?\? "local_private"/.test(artifactEndpointImportBlock) &&
      !/body\.(?:modelId|sourcePath|localPath|importMode|providerId|displayName|sizeBytes|contextWindow|privacyClass)\b/.test(
        artifactEndpointImportBlock,
      ) &&
      /model import rejects retired request aliases before artifact inspection/.test(artifactEndpointOperationsTest) &&
      /retired_aliases,\s*\[\s*"modelId",\s*"sourcePath",\s*"localPath",\s*"importMode",\s*"providerId",\s*"displayName",\s*"sizeBytes",\s*"contextWindow",\s*"privacyClass",\s*\]/.test(
        artifactEndpointOperationsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.test.mjs",
    ],
    "Phase 9/11 is pending: model import request bodies must fail closed on retired camelCase model/source/provider/metadata aliases before artifact inspection or writes",
  );
  assertCheck(
    result,
    "model-mount-endpoint-request-aliases-retired",
    /RETIRED_ENDPOINT_MOUNT_REQUEST_ALIASES/.test(artifactEndpointOperations) &&
      /RETIRED_ENDPOINT_UNMOUNT_REQUEST_ALIASES/.test(artifactEndpointOperations) &&
      /model_mount_endpoint_request_aliases_retired/.test(artifactEndpointOperations) &&
      /model_unmount_endpoint_request_aliases_retired/.test(artifactEndpointOperations) &&
      /assertCanonicalEndpointMountRequestBody\(body\);/.test(artifactEndpointMountBlock) &&
      /assertCanonicalEndpointUnmountRequestBody\(body\);/.test(artifactEndpointUnmountBlock) &&
      /const modelId = body\.model_id;/.test(artifactEndpointMountBlock) &&
      /const explicitProviderId = body\.provider_id;/.test(artifactEndpointMountBlock) &&
      /apiFormat:\s*body\.api_format \?\? provider\.apiFormat/.test(artifactEndpointMountBlock) &&
      /body\.base_url \?\?\s*provider\.baseUrl/.test(artifactEndpointMountBlock) &&
      /privacyClass:\s*body\.privacy_class \?\? provider\.privacyClass/.test(artifactEndpointMountBlock) &&
      /backendId:\s*body\.backend_id \?\? defaultBackendForProvider\(provider\)/.test(artifactEndpointMountBlock) &&
      /loadPolicy:\s*normalizeLoadPolicy\(body\.load_policy\)/.test(artifactEndpointMountBlock) &&
      /requiredString\(body\.endpoint_id \?\? body\.id,\s*"endpoint_id"\)/.test(artifactEndpointUnmountBlock) &&
      !/body\.(?:modelId|providerId|apiFormat|baseUrl|privacyClass|backendId|loadPolicy)\b/.test(
        artifactEndpointMountBlock,
      ) &&
      !/body\.endpointId\b/.test(artifactEndpointUnmountBlock) &&
      /mount endpoint rejects retired request aliases before provider lookup/.test(artifactEndpointOperationsTest) &&
      /unmount endpoint rejects retired request aliases before endpoint lookup/.test(artifactEndpointOperationsTest) &&
      /retired_aliases,\s*\[\s*"modelId",\s*"providerId",\s*"apiFormat",\s*"baseUrl",\s*"privacyClass",\s*"backendId",\s*"loadPolicy",\s*\]/.test(
        artifactEndpointOperationsTest,
      ) &&
      /retired_aliases,\s*\[\s*"endpointId"\s*\]/.test(artifactEndpointOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/artifact-endpoint-operations.test.mjs",
    ],
    "Phase 9/11 is pending: endpoint mount/unmount request bodies must fail closed on retired camelCase endpoint/provider/backend/load aliases before state lookup or writes",
  );
  assertCheck(
    result,
    "model-mount-storage-request-aliases-retired",
    /RETIRED_MODEL_STORAGE_REQUEST_ALIASES/.test(storageOperations) &&
      /CANONICAL_MODEL_STORAGE_REQUEST_FIELDS/.test(storageOperations) &&
      /model_storage_request_aliases_retired/.test(storageOperations) &&
      /assertCanonicalModelStorageRequestBody\(body\);[\s\S]*state\.downloadStatus\(jobId\)/.test(
        cancelDownloadBlock,
      ) &&
      /assertCanonicalModelStorageRequestBody\(body\);[\s\S]*state\.getModel\(id\)/.test(
        deleteModelArtifactBlock,
      ) &&
      /assertCanonicalModelStorageRequestBody\(body\);[\s\S]*listModelFiles\(state\.modelRoot\)/.test(
        cleanupModelStorageBlock,
      ) &&
      /truthy\(body\.cleanup_partial \?\? true\)/.test(cancelDownloadBlock) &&
      /truthy\(body\.dry_run\)/.test(deleteModelArtifactBlock) &&
      /truthy\(body\.remove_orphans \?\? false\)/.test(cleanupModelStorageBlock) &&
      !/body\.(?:cleanupPartial|dryRun|removeOrphans)\b/.test(storageOperations) &&
      /cancelDownload rejects retired cleanup alias before job lookup/.test(storageOperationsTest) &&
      /deleteModelArtifact rejects retired dry-run alias before artifact lookup/.test(
        storageOperationsTest,
      ) &&
      /cleanupModelStorage rejects retired cleanup alias before scanning/.test(storageOperationsTest) &&
      /retired_aliases,\s*\[\s*"cleanupPartial"\s*\]/.test(storageOperationsTest) &&
      /retired_aliases,\s*\[\s*"dryRun"\s*\]/.test(storageOperationsTest) &&
      /retired_aliases,\s*\[\s*"removeOrphans"\s*\]/.test(storageOperationsTest) &&
      /canonical_fields,\s*\[\s*"cleanup_partial",\s*"dry_run",\s*"remove_orphans",\s*\]/.test(
        storageOperationsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/storage-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/storage-operations.test.mjs",
    ],
    "Phase 9/11 is pending: model storage request bodies must fail closed on retired camelCase cleanup/dry-run/orphan aliases before state lookup or filesystem scanning",
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
    "model-mount-workflow-node-request-aliases-retired",
    /RETIRED_WORKFLOW_NODE_EXECUTION_REQUEST_ALIASES/.test(mcpWorkflowOperations) &&
      /model_mount_workflow_node_request_aliases_retired/.test(mcpWorkflowOperations) &&
      /assertCanonicalWorkflowNodeExecutionRequestBody\(body\);/.test(mcpWorkflowOperations) &&
      /const node = requiredString\(body\.node \?\? body\.node_type,\s*"node"\);/.test(
        mcpWorkflowOperations,
      ) &&
      /model:\s*body\.model_id \?\? body\.model/.test(mcpWorkflowOperations) &&
      /route_id:\s*body\.route_id/.test(mcpWorkflowOperations) &&
      /model_policy:\s*body\.model_policy \?\? \{\}/.test(mcpWorkflowOperations) &&
      /max_tokens:\s*body\.max_tokens/.test(mcpWorkflowOperations) &&
      /workflow_graph_id:\s*body\.workflow_graph_id/.test(mcpWorkflowOperations) &&
      /workflow_node_id:\s*body\.workflow_node_id/.test(mcpWorkflowOperations) &&
      /workflow_node_type:\s*body\.workflow_node_type \?\? node/.test(mcpWorkflowOperations) &&
      !/body\.(?:nodeType|modelId|routeId|modelPolicy|maxTokens|workflowGraphId|workflowNodeId|nodeId|node_id|workflowNodeType)\b/.test(
        mcpWorkflowOperations,
      ) &&
      /executeWorkflowNode rejects retired request aliases before authorization/.test(
        mcpWorkflowOperationsTest,
      ) &&
      /retired_aliases,\s*\[\s*"nodeType",\s*"modelId",\s*"routeId",\s*"modelPolicy",\s*"maxTokens",\s*"workflowGraphId",\s*"workflowNodeId",\s*"nodeId",\s*"node_id",\s*"workflowNodeType",\s*\]/.test(
        mcpWorkflowOperationsTest,
      ) &&
      /Object\.hasOwn\(state\.modelInvocations\.at\(-1\)\.body,\s*"workflowNodeId"\),\s*false/.test(
        mcpWorkflowOperationsTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/mcp-workflow-operations.test.mjs",
    ],
    "Phase 10/11 is pending: workflow node execution request bodies must fail closed on retired model-route and workflow-node aliases",
  );
  assertCheck(
    result,
    "model-mount-catalog-import-url-request-aliases-retired",
    /RETIRED_CATALOG_IMPORT_URL_REQUEST_ALIASES/.test(catalogDownloadOperations) &&
      /CANONICAL_CATALOG_IMPORT_URL_REQUEST_FIELDS/.test(catalogDownloadOperations) &&
      /model_catalog_import_url_request_aliases_retired/.test(catalogDownloadOperations) &&
      /assertCanonicalCatalogImportUrlRequestBody\(body\);[\s\S]*requireString\(body\.source_url \?\? body\.url,\s*"source_url"\)/.test(
        catalogImportUrlBlock,
      ) &&
      /const modelId = body\.model_id \?\? modelIdForSource\(sourceUrl\);/.test(catalogImportUrlBlock) &&
      /provider_id:\s*body\.provider_id \?\? "provider\.autopilot\.local"/.test(catalogImportUrlBlock) &&
      /file_name:\s*body\.file_name \?\? `\$\{makeSafeFileName\(modelId\)\}\.\$\{variant\.format\}`/.test(
        catalogImportUrlBlock,
      ) &&
      /fixture_content:\s*body\.fixture_content \?\?/.test(catalogImportUrlBlock) &&
      /transfer_approved:\s*Boolean\(body\.transfer_approved \?\? isFixture\)/.test(
        catalogImportUrlBlock,
      ) &&
      !/body\.(?:sourceUrl|modelId|providerId|fileName|fixtureContent|transferApproved)\b/.test(
        catalogImportUrlBlock,
      ) &&
      /catalogImportUrl rejects retired request aliases before receipt or download/.test(
        catalogDownloadOperationsTest,
      ) &&
      /retired_aliases,\s*\[\s*"sourceUrl",\s*"modelId",\s*"providerId",\s*"fileName",\s*"fixtureContent",\s*"transferApproved",\s*\]/.test(
        catalogDownloadOperationsTest,
      ) &&
      /canonical_fields,\s*\[\s*"source_url",\s*"model_id",\s*"provider_id",\s*"file_name",\s*"fixture_content",\s*"transfer_approved",\s*\]/.test(
        catalogDownloadOperationsTest,
      ) &&
      /assert\.equal\(state\.receipts\.length,\s*0\)/.test(catalogDownloadOperationsTest) &&
      /assert\.equal\(state\.downloadBody,\s*undefined\)/.test(catalogDownloadOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs",
    ],
    "Phase 9/11 is pending: catalog import URL request bodies must fail closed on retired camelCase source/provider/download aliases before receipt creation or download forwarding",
  );
  assertCheck(
    result,
    "model-mount-download-identity-request-aliases-retired",
    /RETIRED_MODEL_DOWNLOAD_IDENTITY_REQUEST_ALIASES/.test(catalogDownloadOperations) &&
      /CANONICAL_MODEL_DOWNLOAD_IDENTITY_REQUEST_FIELDS/.test(catalogDownloadOperations) &&
      /model_download_identity_request_aliases_retired/.test(catalogDownloadOperations) &&
      /assertCanonicalModelDownloadIdentityRequestBody\(body\);[\s\S]*const now = state\.nowIso\(\);/.test(
        downloadModelBlock,
      ) &&
      /const modelId = requireString\(body\.model_id,\s*"model_id"\);/.test(downloadModelBlock) &&
      /const providerId = body\.provider_id \?\? "provider\.autopilot\.local";/.test(
        downloadModelBlock,
      ) &&
      /const source = body\.source_url \?\? body\.source \?\? "deterministic_fixture_download";/.test(
        downloadModelBlock,
      ) &&
      /const sourceLabel = body\.source_label \?\? labelForSource\(source\);/.test(downloadModelBlock) &&
      /const catalogProviderId = body\.catalog_provider_id \?\? variantMetadata\.catalogProviderId \?\? null;/.test(
        downloadModelBlock,
      ) &&
      /const targetPath = path\.join\(targetDir,\s*body\.file_name \?\? `\$\{makeSafeFileName\(modelId\)\}\.gguf`\);/.test(
        downloadModelBlock,
      ) &&
      /const fixtureContent = String\(body\.fixture_content \?\? `deterministic model bytes for \$\{modelId\}\\n`\);/.test(
        downloadModelBlock,
      ) &&
      !/body\.(?:modelId|providerId|sourceUrl|sourceLabel|catalogProviderId|fileName|fixtureContent)\b/.test(
        downloadModelBlock,
      ) &&
      /downloadModel rejects retired identity request aliases before timestamp or receipt/.test(
        catalogDownloadOperationsTest,
      ) &&
      /retired_aliases,\s*\[\s*"modelId",\s*"providerId",\s*"sourceUrl",\s*"sourceLabel",\s*"catalogProviderId",\s*"fileName",\s*"fixtureContent",\s*\]/.test(
        catalogDownloadOperationsTest,
      ) &&
      /canonical_fields,\s*\[\s*"model_id",\s*"provider_id",\s*"source_url",\s*"source_label",\s*"catalog_provider_id",\s*"file_name",\s*"fixture_content",\s*\]/.test(
        catalogDownloadOperationsTest,
      ) &&
      /assert\.equal\(nowCount,\s*0\)/.test(catalogDownloadOperationsTest) &&
      /assert\.equal\(state\.receipts\.length,\s*0\)/.test(catalogDownloadOperationsTest) &&
      /assert\.equal\(state\.writes\.length,\s*0\)/.test(catalogDownloadOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs",
    ],
    "Phase 9/11 is pending: direct model download request bodies must fail closed on retired camelCase identity/source aliases before timestamping or receipt creation",
  );
  assertCheck(
    result,
    "model-mount-download-control-request-aliases-retired",
    /RETIRED_MODEL_DOWNLOAD_CONTROL_REQUEST_ALIASES/.test(catalogDownloadOperations) &&
      /CANONICAL_MODEL_DOWNLOAD_CONTROL_REQUEST_FIELDS/.test(catalogDownloadOperations) &&
      /model_download_control_request_aliases_retired/.test(catalogDownloadOperations) &&
      /assertCanonicalModelDownloadControlRequestBody\(body\);[\s\S]*const now = state\.nowIso\(\);/.test(
        downloadModelBlock,
      ) &&
      /const bytesTotal = Number\(body\.bytes_total \?\? \(isFixture \? Buffer\.byteLength\(fixtureContent\) : 0\)\);/.test(
        downloadModelBlock,
      ) &&
      /const maxBytes = normalizeBytes\(body\.max_bytes \?\? env\.IOI_MODEL_DOWNLOAD_MAX_BYTES\);/.test(
        downloadModelBlock,
      ) &&
      /isTruthy\(body\.fail \?\? body\.simulate_failure\)/.test(downloadModelBlock) &&
      /failureReason:\s*body\.failure_reason \?\? "deterministic_fixture_failure"/.test(
        downloadModelBlock,
      ) &&
      /isTruthy\(body\.queued_only\)/.test(downloadModelBlock) &&
      /expectedChecksum:\s*body\.expected_checksum \?\? body\.checksum \?\? null/.test(
        downloadModelBlock,
      ) &&
      !/body\.(?:bytesTotal|maxBytes|simulateFailure|failureReason|queuedOnly|expectedChecksum)\b/.test(
        downloadModelBlock,
      ) &&
      /downloadModel rejects retired control request aliases before timestamp or receipt/.test(
        catalogDownloadOperationsTest,
      ) &&
      /retired_aliases,\s*\[\s*"bytesTotal",\s*"maxBytes",\s*"simulateFailure",\s*"failureReason",\s*"queuedOnly",\s*"expectedChecksum",\s*\]/.test(
        catalogDownloadOperationsTest,
      ) &&
      /canonical_fields,\s*\[\s*"bytes_total",\s*"max_bytes",\s*"simulate_failure",\s*"failure_reason",\s*"queued_only",\s*"expected_checksum",\s*\]/.test(
        catalogDownloadOperationsTest,
      ) &&
      /assert\.equal\(nowCount,\s*0\)/.test(catalogDownloadOperationsTest) &&
      /assert\.equal\(state\.receipts\.length,\s*0\)/.test(catalogDownloadOperationsTest) &&
      /assert\.equal\(state\.writes\.length,\s*0\)/.test(catalogDownloadOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs",
    ],
    "Phase 9/11 is pending: direct model download request bodies must fail closed on retired camelCase control aliases before timestamping or receipt creation",
  );
  assertCheck(
    result,
    "model-mount-download-metadata-request-aliases-retired",
    /RETIRED_MODEL_DOWNLOAD_METADATA_REQUEST_ALIASES/.test(catalogDownloadOperations) &&
      /CANONICAL_MODEL_DOWNLOAD_METADATA_REQUEST_FIELDS/.test(catalogDownloadOperations) &&
      /model_download_metadata_request_aliases_retired/.test(catalogDownloadOperations) &&
      /assertCanonicalModelDownloadMetadataRequestBody\(body\);[\s\S]*const now = state\.nowIso\(\);/.test(
        downloadModelBlock,
      ) &&
      /displayName:\s*body\.display_name \?\? modelId/.test(downloadModelBlock) &&
      /contextWindow:\s*body\.context_window \?\? metadata\.contextWindow \?\? null/.test(
        downloadModelBlock,
      ) &&
      /privacyClass:\s*body\.privacy_class \?\? "local_private"/.test(downloadModelBlock) &&
      !/body\.(?:displayName|contextWindow|privacyClass)\b/.test(downloadModelBlock) &&
      /downloadModel rejects retired metadata request aliases before timestamp or receipt/.test(
        catalogDownloadOperationsTest,
      ) &&
      /retired_aliases,\s*\[\s*"displayName",\s*"contextWindow",\s*"privacyClass",\s*\]/.test(
        catalogDownloadOperationsTest,
      ) &&
      /canonical_fields,\s*\[\s*"display_name",\s*"context_window",\s*"privacy_class",\s*\]/.test(
        catalogDownloadOperationsTest,
      ) &&
      /assert\.equal\(nowCount,\s*0\)/.test(catalogDownloadOperationsTest) &&
      /assert\.equal\(state\.receipts\.length,\s*0\)/.test(catalogDownloadOperationsTest) &&
      /assert\.equal\(state\.writes\.length,\s*0\)/.test(catalogDownloadOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-download-operations.test.mjs",
    ],
    "Phase 9/11 is pending: direct model download request bodies must fail closed on retired camelCase metadata aliases before timestamping or receipt creation",
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
    "model-mount-catalog-download-policy-request-aliases-retired",
    /RETIRED_CATALOG_DOWNLOAD_POLICY_REQUEST_ALIASES/.test(catalogHelpers) &&
      /CANONICAL_CATALOG_DOWNLOAD_POLICY_REQUEST_FIELDS/.test(catalogHelpers) &&
      /catalog_download_policy_request_aliases_retired/.test(catalogHelpers) &&
      /assertCanonicalCatalogDownloadPolicyRequestBody\(body\);[\s\S]*const approved = Boolean\(body\.transfer_approved \?\? isFixture\);/.test(
        catalogApprovalDecisionBlock,
      ) &&
      /assertCanonicalCatalogDownloadPolicyRequestBody\(body\);[\s\S]*body\.bandwidth_bps \?\?[\s\S]*body\.bandwidth_limit_bps \?\?[\s\S]*process\.env\.IOI_MODEL_DOWNLOAD_BANDWIDTH_BPS/.test(
        normalizeDownloadPolicyBlock,
      ) &&
      /const retryLimit = normalizeNonNegativeInteger\(body\.retry_limit \?\? body\.retries \?\? 0,\s*0\);/.test(
        normalizeDownloadPolicyBlock,
      ) &&
      /const resume = truthy\(body\.resume \?\? body\.resume_download \?\? true\);/.test(
        normalizeDownloadPolicyBlock,
      ) &&
      /const cleanupPartialOnCancel = truthy\(body\.cleanup_partial \?\? true\);/.test(
        normalizeDownloadPolicyBlock,
      ) &&
      !/body\.(?:transferApproved|bandwidthBps|bandwidthLimitBps|retryLimit|resumeDownload|cleanupPartial)\b/.test(
        `${catalogApprovalDecisionBlock}\n${normalizeDownloadPolicyBlock}`,
      ) &&
      /catalog download policy accepts canonical request fields/.test(catalogHelpersTest) &&
      /catalog download policy rejects retired request aliases/.test(catalogHelpersTest) &&
      /retired_aliases,\s*\[\s*"transferApproved",\s*"bandwidthBps",\s*"bandwidthLimitBps",\s*"retryLimit",\s*"resumeDownload",\s*"cleanupPartial",\s*\]/.test(
        catalogHelpersTest,
      ) &&
      /canonical_fields,\s*\[\s*"transfer_approved",\s*"bandwidth_bps",\s*"bandwidth_limit_bps",\s*"retry_limit",\s*"resume_download",\s*"cleanup_partial",\s*\]/.test(
        catalogHelpersTest,
      ) &&
      /catalogApprovalDecision\(\{ isFixture: false,\s*body: \{ transferApproved: true \} \}\)/.test(
        catalogHelpersTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-helpers.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-helpers.test.mjs",
    ],
    "Phase 9/11 is pending: catalog download policy helpers must fail closed on retired camelCase policy aliases before approval or transfer policy evaluation",
  );
  assertCheck(
    result,
    "model-mount-destructive-confirmation-request-aliases-retired",
    /RETIRED_DESTRUCTIVE_CONFIRMATION_REQUEST_ALIASES/.test(catalogHelpers) &&
      /CANONICAL_DESTRUCTIVE_CONFIRMATION_REQUEST_FIELDS/.test(catalogHelpers) &&
      /destructive_confirmation_request_aliases_retired/.test(catalogHelpers) &&
      /assertCanonicalDestructiveConfirmationRequestBody\(body\);[\s\S]*const confirmed = Boolean\(body\.confirm_destructive \?\? body\.destructive_confirmed \?\? false\);/.test(
        destructiveConfirmationStateBlock,
      ) &&
      !/body\.(?:confirmDestructive|destructiveConfirmed)\b/.test(destructiveConfirmationStateBlock) &&
      /destructive confirmation accepts canonical request fields/.test(catalogHelpersTest) &&
      /destructive confirmation rejects retired request aliases/.test(catalogHelpersTest) &&
      /retired_aliases,\s*\[\s*"confirmDestructive"\s*,\s*"destructiveConfirmed"\s*,?\s*\]/.test(
        catalogHelpersTest,
      ) &&
      /canonical_fields,\s*\[\s*"confirm_destructive"\s*,\s*"destructive_confirmed"\s*,?\s*\]/.test(
        catalogHelpersTest,
      ) &&
      !/body\.confirmDestructive\b/.test(storageOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-helpers.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-helpers.test.mjs",
      "packages/runtime-daemon/src/model-mounting/storage-operations.test.mjs",
    ],
    "Phase 9/11 is pending: destructive confirmation helpers must fail closed on retired camelCase request aliases before destructive action evaluation",
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
      /assertNoRetiredProviderDetailAliases/.test(modelMountReceiptWriteGuards) &&
      /retired_aliases\.includes\("providerKind"\)/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
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
      /assertNoRetiredProviderDetailAliases/.test(modelMountReceiptWriteGuards) &&
      !/modelMountProviderLifecycle|providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      !/modelMountProviderLifecycle|providerLifecycleHash/.test(modelMountReceiptWriteGuards) &&
      /retired_aliases\.includes\("providerKind"\)/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ) &&
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
      /assertNoRetiredProviderDetailAliases/.test(modelMountReceiptWriteGuards) &&
      !/modelMountProviderLifecycle|providerLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      !/modelMountProviderLifecycle|providerLifecycleHash/.test(modelMountReceiptWriteGuards) &&
      /retired_aliases\.includes\("providerKind"\)/.test(
        read("packages/runtime-daemon/src/model-mounting/store.test.mjs"),
      ) &&
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
    "model-mount-provider-secret-request-aliases-retired",
    /RETIRED_PROVIDER_SECRET_REQUEST_ALIASES/.test(providerAuth) &&
      /CANONICAL_PROVIDER_SECRET_REQUEST_FIELDS/.test(providerAuth) &&
      /provider_secret_request_aliases_retired/.test(providerAuth) &&
      /assertCanonicalProviderSecretRequestBody\(body\);[\s\S]*for \(const key of CANONICAL_PROVIDER_SECRET_REQUEST_FIELDS\)/.test(
        providerSecretInputBlock,
      ) &&
      !/"(?:secretRef|authVaultRef|apiKeyVaultRef)"/.test(providerSecretInputBlock) &&
      /provider secret input rejects retired request aliases/.test(providerAuthTest) &&
      /retired_aliases,\s*\[\s*"secretRef"\s*,\s*"authVaultRef"\s*,\s*"apiKeyVaultRef"\s*,?\s*\]/.test(
        providerAuthTest,
      ) &&
      /canonical_fields,\s*\[\s*"secret_ref"\s*,\s*"auth_vault_ref"\s*,\s*"api_key_vault_ref"\s*,?\s*\]/.test(
        providerAuthTest,
      ) &&
      /api_key_vault_ref:\s*"vault:\/\/provider\/openai"/.test(providerOperationsTest) &&
      !/Object\.prototype\.hasOwnProperty\.call\(body,\s*"apiKeyVaultRef"\)/.test(providerOperationsTest) &&
      !/Object\.prototype\.hasOwnProperty\.call\(body,\s*"secretRef"\)/.test(providerOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/provider-auth.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-auth.test.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs",
    ],
    "Phase 5/11 is pending: provider secret request bodies must fail closed on retired camelCase vault-ref aliases before provider state writes or vault resolution",
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
    "model-mount-catalog-provider-source-request-aliases-retired",
    /RETIRED_CATALOG_PROVIDER_SOURCE_REQUEST_ALIASES/.test(catalogProviderConfig) &&
      /CANONICAL_CATALOG_PROVIDER_SOURCE_REQUEST_FIELDS/.test(catalogProviderConfig) &&
      /catalog_provider_source_request_aliases_retired/.test(catalogProviderConfig) &&
      /assertCanonicalCatalogProviderSourceRequestBody\(body\);[\s\S]*body\.manifest_path \?\? body\.path \?\? null/.test(
        catalogProviderRuntimeMaterialFromBodyBlock,
      ) &&
      /body\.base_url \?\? body\.url \?\? null/.test(catalogProviderRuntimeMaterialFromBodyBlock) &&
      !/body\.(?:manifestPath|baseUrl)\b/.test(catalogProviderConfig) &&
      /catalog provider source request aliases fail closed before vault binding/.test(
        catalogProviderConfigTest,
      ) &&
      /retired_aliases,\s*\[\s*"manifestPath"\s*\]/.test(catalogProviderConfigTest) &&
      /retired_aliases,\s*\[\s*"baseUrl"\s*\]/.test(catalogProviderConfigTest) &&
      /canonical_fields,\s*\[\s*"manifest_path",\s*"base_url"\s*\]/.test(catalogProviderConfigTest) &&
      /assert\.equal\(state\.bound\.length,\s*0\)/.test(catalogProviderConfigTest) &&
      /assert\.equal\(state\.writeVaultRefsCount\(\),\s*0\)/.test(catalogProviderConfigTest) &&
      /catalogProviderRuntimeMaterialFromBody\("catalog\.local_manifest",\s*\{ manifest_path:/.test(
        catalogProviderConfigTest,
      ) &&
      /catalogProviderRuntimeMaterialFromBody\("catalog\.custom_http",\s*\{ base_url:/.test(
        catalogProviderConfigTest,
      ),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs",
    ],
    "Phase 7/11 is pending: catalog provider source request bodies must fail closed on retired camelCase source aliases before vault binding",
  );
  assertCheck(
    result,
    "model-mount-catalog-provider-auth-request-aliases-retired",
    /RETIRED_CATALOG_PROVIDER_AUTH_REQUEST_ALIASES/.test(catalogProviderConfig) &&
      /CANONICAL_CATALOG_PROVIDER_AUTH_REQUEST_FIELDS/.test(catalogProviderConfig) &&
      /catalog_provider_auth_request_aliases_retired/.test(catalogProviderConfig) &&
      /export function catalogProviderConfigUpdate[\s\S]*?assertCanonicalCatalogProviderAuthRequestBody\(body\);[\s\S]*?state\.vault\.bindVaultRef/.test(
        catalogProviderConfig,
      ) &&
      /firstOwn\(body,\s*\["auth_vault_ref"\]\)/.test(catalogProviderAuthConfigBlock) &&
      /body\.auth_scheme \?\? existing\?\.catalogAuthScheme \?\? "bearer"/.test(
        catalogProviderAuthConfigBlock,
      ) &&
      /body\.auth_header_name \?\? existing\?\.catalogAuthHeaderName \?\? "authorization"/.test(
        catalogProviderAuthConfigBlock,
      ) &&
      /firstOwn\(body,\s*\["oauth_session_id"\]\)/.test(catalogProviderAuthConfigBlock) &&
      !/body\.(?:authVaultRef|vaultRef|apiKeyVaultRef|authScheme|authHeaderName|oauthSessionId)\b/.test(
        catalogProviderAuthConfigBlock,
      ) &&
      !/firstOwn\(body,\s*\[[^\]]*(?:"vault_ref"|"api_key_vault_ref"|"authVaultRef"|"vaultRef"|"apiKeyVaultRef"|"oauthSessionId")/.test(
        catalogProviderAuthConfigBlock,
      ) &&
      /catalog provider auth request aliases fail closed before source or auth binding/.test(
        catalogProviderConfigTest,
      ) &&
      /catalog provider auth config accepts canonical request fields/.test(catalogProviderConfigTest) &&
      /"authVaultRef"[\s\S]*"vault_ref"[\s\S]*"vaultRef"[\s\S]*"api_key_vault_ref"[\s\S]*"apiKeyVaultRef"[\s\S]*"authScheme"[\s\S]*"authHeaderName"[\s\S]*"oauthSessionId"/.test(
        catalogProviderConfigTest,
      ) &&
      /canonical_fields,\s*\[\s*"auth_vault_ref"\s*,\s*"auth_scheme"\s*,\s*"auth_header_name"\s*,\s*"oauth_session_id"\s*,?\s*\]/.test(
        catalogProviderConfigTest,
      ) &&
      /assert\.equal\(state\.bound\.length,\s*0\)/.test(catalogProviderConfigTest) &&
      /assert\.equal\(state\.writeVaultRefsCount\(\),\s*0\)/.test(catalogProviderConfigTest) &&
      /assert\.equal\(authResolveCount,\s*0\)/.test(catalogProviderConfigTest),
    [
      "packages/runtime-daemon/src/model-mounting/catalog-provider-config.mjs",
      "packages/runtime-daemon/src/model-mounting/catalog-provider-config.test.mjs",
    ],
    "Phase 7/11 is pending: catalog provider auth request bodies must fail closed on retired auth aliases before source vault binding or auth resolution",
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
      /assertNoRetiredLifecycleSubjectAliases\(details\)/.test(modelMountReceiptOperations) &&
      /model_lifecycle_receipt_detail_aliases_retired/.test(modelMountReceiptOperations) &&
      !/details\.model_id\s*\?\?\s*details\.modelId/.test(modelMountReceiptOperations) &&
      !/details\.endpoint_id\s*\?\?\s*details\.endpointId/.test(modelMountReceiptOperations) &&
      /lifecycle receipt summary accepts canonical snake_case subject fields/.test(modelMountReceiptOperationsTest) &&
      /lifecycle receipt subject aliases are retired/.test(modelMountReceiptOperationsTest) &&
      /retired_aliases\.includes\("modelId"\)/.test(modelMountReceiptOperationsTest) &&
      /retired_aliases\.includes\("endpointId"\)/.test(modelMountReceiptOperationsTest) &&
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
    "model-mount-provider-upsert-request-aliases-retired",
    /RETIRED_PROVIDER_UPSERT_REQUEST_ALIASES/.test(providerOperations) &&
      /CANONICAL_PROVIDER_UPSERT_REQUEST_FIELDS/.test(providerOperations) &&
      /provider_upsert_request_aliases_retired/.test(providerOperations) &&
      /assertCanonicalProviderUpsertRequestBody\(body\);[\s\S]*state\.normalizeProviderSecretRef/.test(
        providerUpsertBlock,
      ) &&
      /normalizeProviderAuthScheme\(body\.auth_scheme \?\? existing\.authScheme\)/.test(providerUpsertBlock) &&
      /normalizeProviderAuthHeaderName\(\s*body\.auth_header_name \?\? existing\.authHeaderName,\s*\)/.test(
        providerUpsertBlock,
      ) &&
      /apiFormat:\s*body\.api_format \?\? existing\.apiFormat \?\? "custom"/.test(providerUpsertBlock) &&
      /baseUrl:\s*body\.base_url \?\? existing\.baseUrl \?\? null/.test(providerUpsertBlock) &&
      /privacyClass:\s*body\.privacy_class \?\? existing\.privacyClass \?\? "workspace"/.test(
        providerUpsertBlock,
      ) &&
      /evidenceRefs:\s*normalizeScopes\(body\.evidence_refs,\s*existing\.discovery\?\.evidenceRefs/.test(
        providerUpsertBlock,
      ) &&
      !/body\.(?:authScheme|authHeaderName|apiFormat|baseUrl|privacyClass|evidenceRefs)\b/.test(
        providerUpsertBlock,
      ) &&
      /provider upsert rejects retired request aliases before vault resolution or state write/.test(
        providerOperationsTest,
      ) &&
      /retired_aliases,\s*\[\s*"authScheme"\s*,\s*"authHeaderName"\s*,\s*"apiFormat"\s*,\s*"baseUrl"\s*,\s*"privacyClass"\s*,\s*"evidenceRefs"\s*,?\s*\]/.test(
        providerOperationsTest,
      ) &&
      /canonical_fields,\s*\[\s*"auth_scheme"\s*,\s*"auth_header_name"\s*,\s*"api_format"\s*,\s*"base_url"\s*,\s*"privacy_class"\s*,\s*"evidence_refs"\s*,?\s*\]/.test(
        providerOperationsTest,
      ) &&
      /assert\.deepEqual\(state\.resolvedVaultRefs,\s*\[\]\)/.test(providerOperationsTest) &&
      /assert\.deepEqual\(state\.writes,\s*\[\]\)/.test(providerOperationsTest) &&
      /api_key_vault_ref:\s*"vault:\/\/provider\/openai"/.test(providerOperationsTest) &&
      /auth_header_name:\s*"X-API-Key"/.test(providerOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/provider-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs",
    ],
    "Phase 5/11 is pending: provider upsert request bodies must fail closed on retired metadata aliases before vault resolution or provider state writes",
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
      /adapter:\s*failureDetails\.adapter/.test(providerOperations) &&
      /model_count:\s*resolved\.length/.test(providerOperations) &&
      /loaded_count:\s*resolved\.length/.test(providerOperations) &&
      !/details:\s*\{[^}]*\b(?:providerId|providerKind|httpStatus|authVaultRefHash|providerAuthEvidenceRefs|providerAuthHeaderNames|failureCode|failureStatus|providerErrorHash|vaultRefConfigured|resolvedMaterial|modelId|modelCount|loadedCount|evidenceRefs|providerHealthStatus|providerHealthReceiptId)\s*:/.test(
        providerOperations,
      ) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.payload\.details,\s*"providerId"\),\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.payload\.details,\s*"httpStatus"\),\s*false/.test(providerOperationsTest) &&
      /assert\.equal\(error\.details\.adapter,\s*"remote_provider_adapter"\)/.test(providerOperationsTest) &&
      /assert\.equal\(state\.receipts\.at\(-1\)\.payload\.details\.adapter,\s*"remote_provider_adapter"\)/.test(providerOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"providerHealthStatus"\),\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-2\)\.details,\s*"modelCount"\),\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(state\.receipts\.at\(-1\)\.details,\s*"loadedCount"\),\s*false/.test(providerOperationsTest) &&
      /Object\.hasOwn\(error\.details,\s*"providerId"\)\s*===\s*false/.test(providerOperationsTest) &&
      /retiredProviderDetailAliases/.test(modelMountReceiptWriteGuards) &&
      !/details\.providerId \?\? details\.provider_id/.test(modelMountReceiptWriteGuards) &&
      !/details\.providerKind \?\? details\.provider_kind/.test(modelMountReceiptWriteGuards) &&
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
    "model-mount-vault-operation-request-aliases-retired",
    /RETIRED_VAULT_OPERATION_REQUEST_ALIASES/.test(vaultOperations) &&
      /CANONICAL_VAULT_OPERATION_REQUEST_FIELDS/.test(vaultOperations) &&
      /vault_operation_request_aliases_retired/.test(vaultOperations) &&
      /assertCanonicalVaultOperationRequestBody\(body\);[\s\S]*const vaultRef = requiredStringDep\(body\.vault_ref,\s*"vault_ref"\);[\s\S]*const material = requiredStringDep\(body\.material,\s*"material"\);/.test(
        vaultOperationsRequestBlocks,
      ) &&
      /export function vaultRefMetadata[\s\S]*?assertCanonicalVaultOperationRequestBody\(body\);[\s\S]*requiredStringDep\(body\.vault_ref,\s*"vault_ref"\)/.test(
        vaultOperationsRequestBlocks,
      ) &&
      /export function removeVaultRef[\s\S]*?assertCanonicalVaultOperationRequestBody\(body\);[\s\S]*requiredStringDep\(body\.vault_ref,\s*"vault_ref"\)/.test(
        vaultOperationsRequestBlocks,
      ) &&
      !/body\.(?:vaultRef|secret|value)\b/.test(vaultOperationsRequestBlocks) &&
      /vault operations reject retired request aliases before vault access/.test(vaultOperationsTest) &&
      /retired_aliases,\s*\[\s*"vaultRef",\s*"secret",\s*"value"\s*\]/.test(vaultOperationsTest) &&
      /canonical_fields,\s*\[\s*"vault_ref",\s*"material"\s*\]/.test(vaultOperationsTest) &&
      /assert\.deepEqual\(state\.calls,\s*\[\]\)/.test(vaultOperationsTest),
    [
      "packages/runtime-daemon/src/model-mounting/vault-operations.mjs",
      "packages/runtime-daemon/src/model-mounting/vault-operations.test.mjs",
    ],
    "Phase 7/11 is pending: vault operation request bodies must fail closed on retired aliases before vault lookup, binding, or removal",
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
      /completionReceipt\.details\?\.token_count/.test(openAiCompatRoutes) &&
      !/completionReceipt\.details\?\.tokenCount/.test(openAiCompatRoutes) &&
      /provider_stream_shape_summary/.test(conversationOps) &&
      /Object\.hasOwn\(finalPayload\.usage,\s*"tokenCount"\),\s*false/.test(
        read("packages/runtime-daemon/src/openai-compat-routes.test.mjs"),
      ) &&
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
      !/IOI_ENABLE_INTERNAL_FIXTURE_MODELS/.test(runtimeAgentgresRunner) &&
      !/mockRuntimeAgentgresResponse/.test(runtimeAgentgresRunner) &&
      !/fs\.writeFileSync/.test(runtimeAgentgresRunner) &&
      !/mkdirSync/.test(runtimeAgentgresRunner) &&
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
      !/IOI_ENABLE_INTERNAL_FIXTURE_MODELS/.test(runtimeAgentgresRunner) &&
      !/mockRuntimeAgentgresResponse/.test(runtimeAgentgresRunner) &&
      !/fs\.writeFileSync/.test(runtimeAgentgresRunner) &&
      !/mkdirSync/.test(runtimeAgentgresRunner) &&
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
    "ctee-admission-request-aliases-retired",
    /RETIRED_CTEE_PRIVATE_WORKSPACE_REQUEST_ALIASES/.test(cteePrivateWorkspaceSurface) &&
      /CANONICAL_CTEE_PRIVATE_WORKSPACE_REQUEST_FIELDS/.test(cteePrivateWorkspaceSurface) &&
      /ctee_private_workspace_action_request_aliases_retired/.test(
        cteePrivateWorkspaceSurface,
      ) &&
      /assertCanonicalCteePrivateWorkspaceRequestBody\(body\);[\s\S]*objectRecord\(body\.action\)/.test(
        cteePrivateWorkspaceSurface,
      ) &&
      !/body\.(?:cteeAction|ctee_action)\b/.test(cteePrivateWorkspaceSurface) &&
      /cTEE private workspace surface rejects retired request aliases before agent lookup or Rust runner/.test(
        cteePrivateWorkspaceSurfaceTest,
      ) &&
      /assert\.deepEqual\(runtimeStore\.calls,\s*\[\]\)/.test(cteePrivateWorkspaceSurfaceTest) &&
      /retiredCteePrivateWorkspaceRequestAliases/.test(cteePrivateWorkspaceControlNodesTest) &&
      /Object\.prototype\.hasOwnProperty\.call\(request\.body,\s*key\)/.test(
        cteePrivateWorkspaceControlNodesTest,
      ) &&
      !/^\s*ctee_action:\s*RuntimeCteePrivateWorkspaceAction;/m.test(
        cteePrivateWorkspaceControlNodes,
      ) &&
      !/^\s*cteeAction:\s*RuntimeCteePrivateWorkspaceAction;/m.test(
        cteePrivateWorkspaceControlNodes,
      ) &&
      !/ctee_action:\s*action/.test(cteePrivateWorkspaceControlNodes) &&
      !/cteeAction:\s*action/.test(cteePrivateWorkspaceControlNodes),
    [
      "packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.mjs",
      "packages/runtime-daemon/src/runtime-ctee-private-workspace-surface.test.mjs",
      "packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.ts",
      "packages/agent-ide/src/runtime/workflow-runtime-ctee-private-workspace-control-nodes.test.ts",
    ],
    "Phase 7/11 is pending: cTEE Private Workspace admission requests must fail closed on retired action wrapper aliases and IDE clients must emit canonical request bodies",
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
  const policyCore = exists("crates/services/src/agentic/runtime/kernel/policy.rs")
    ? read("crates/services/src/agentic/runtime/kernel/policy.rs")
    : "";
  const bridgeModule = exists("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    ? read("crates/node/src/bin/ioi_step_module_bridge/mod.rs")
    : "";
  const runtimeContextPolicyRunner = exists("packages/runtime-daemon/src/runtime-context-policy-runner.mjs")
    ? read("packages/runtime-daemon/src/runtime-context-policy-runner.mjs")
    : "";
  const runtimeContextPolicyRunnerTest = exists("packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs")
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
  const runtimeWorkspaceSnapshotSurface = exists("packages/runtime-daemon/src/runtime-workspace-snapshot-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-workspace-snapshot-surface.mjs")
    : "";
  const runtimeWorkspaceSnapshotSurfaceTest = exists("packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs")
    : "";
  const diagnosticsRepairExecution = exists("packages/runtime-daemon/src/diagnostics-repair-execution.mjs")
    ? read("packages/runtime-daemon/src/diagnostics-repair-execution.mjs")
    : "";
  const diagnosticsRepairExecutionTest = exists("packages/runtime-daemon/src/diagnostics-repair-execution.test.mjs")
    ? read("packages/runtime-daemon/src/diagnostics-repair-execution.test.mjs")
    : "";
  const workspaceRestoreApplyApprovalHelper =
    diagnosticsRepairExecution.match(
      /function workspaceRestoreApplyApprovalForRequest\(request = \{\}\) \{[\s\S]*?\n  \}/,
    )?.[0] ?? "";
  const workspaceRestoreApplyConflictHelper =
    diagnosticsRepairExecution.match(
      /function workspaceRestoreApplyAllowsConflicts\(request = \{\}\) \{[\s\S]*?\n  \}/,
    )?.[0] ?? "";
  const runtimeDiagnosticsRepairSurface = exists("packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs")
    : "";
  const runtimeDiagnosticsRepairSurfaceTest = exists("packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs")
    ? read("packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs")
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
    /options\.(?:subagentRole|subagent_role)\b/;
  const runtimeSubagentPropagationRequestAliasPattern =
    /request(?:\.workflowNodeId\b|\[\s*["']workflowNodeId["']\s*\])|^\s*workflowNodeId\s*[:,]/m;
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
    /request\.(?:workflowGraphId|workflowNodeId|receiptRefs|policyDecisionRefs|idempotencyKey)\b|request\[\s*["'](?:workflowGraphId|workflowNodeId|receiptRefs|policyDecisionRefs|idempotencyKey)["']\s*\]/;
  const runtimeSubagentSpawnRequestAliasReadPattern =
    /request\.(?:message|input|subagent_prompt|subagentPrompt|subagent_role|subagentRole|maxConcurrency|subagentMaxConcurrency|modelRouteId|subagentModelRoute|outputContract|subagentOutputContract|workflowGraphId|workflowNodeId|parentTurnId|turnId|contextPressureAction|contextPressure|pressureStatus|alertId|sourceEventId|receiptRefs|policyDecisionRefs|toolPack|subagentToolPack|forkContext|mergePolicy|cancellationInheritance)\b|request\[\s*["'](?:message|input|subagent_prompt|subagentPrompt|subagent_role|subagentRole|maxConcurrency|subagentMaxConcurrency|modelRouteId|subagentModelRoute|outputContract|subagentOutputContract|workflowGraphId|workflowNodeId|parentTurnId|turnId|contextPressureAction|contextPressure|pressureStatus|alertId|sourceEventId|receiptRefs|policyDecisionRefs|toolPack|subagentToolPack|forkContext|mergePolicy|cancellationInheritance)["']\s*\]/;
  const runtimeSubagentSendInputRequestAliasReadPattern =
    /request\.(?:message|prompt|text|subagent_input|subagentInput|workflowGraphId|workflowNodeId)\b|request\[\s*["'](?:message|prompt|text|subagent_input|subagentInput|workflowGraphId|workflowNodeId)["']\s*\]/;
  const runtimeSubagentResumeRequestAliasReadPattern =
    /request\.(?:message|input|resume_prompt|resumePrompt|subagent_role|subagentRole|modelRouteId|subagentModelRoute|workflowGraphId|workflowNodeId)\b|request\[\s*["'](?:message|input|resume_prompt|resumePrompt|subagent_role|subagentRole|modelRouteId|subagentModelRoute|workflowGraphId|workflowNodeId)["']\s*\]/;
  const runtimeSubagentAssignRequestAliasReadPattern =
    /request\.(?:subagent_role|subagentRole|toolPack|subagentToolPack|modelRouteId|subagentModelRoute|mergePolicy|cancellationInheritance|targetAgentId|workflowGraphId|workflowNodeId)\b|request\[\s*["'](?:subagent_role|subagentRole|toolPack|subagentToolPack|modelRouteId|subagentModelRoute|mergePolicy|cancellationInheritance|targetAgentId|workflowGraphId|workflowNodeId)["']\s*\]/;
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
  const runtimeMcpManager = exists("packages/runtime-daemon/src/mcp-manager.mjs")
    ? read("packages/runtime-daemon/src/mcp-manager.mjs")
    : "";
  const runtimeMcpCatalogSurface = exists("packages/runtime-daemon/src/runtime-mcp-catalog-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-mcp-catalog-surface.mjs")
    : "";
  const runtimeMcpCatalogSurfaceTest = exists(
    "packages/runtime-daemon/src/runtime-mcp-catalog-surface.test.mjs",
  )
    ? read("packages/runtime-daemon/src/runtime-mcp-catalog-surface.test.mjs")
    : "";
  const runtimeMcpControlSurface = exists("packages/runtime-daemon/src/runtime-mcp-control-surface.mjs")
    ? read("packages/runtime-daemon/src/runtime-mcp-control-surface.mjs")
    : "";
  const runtimeMcpControlSurfaceTest = exists(
    "packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs",
  )
    ? read("packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs")
    : "";
  const runtimeMcpInvokeToolBlock =
    runtimeMcpControlSurface.match(
      /async invokeMcpTool\(store, request = \{\}\) \{[\s\S]*?\n    \},\n    async invokeThreadMcpTool/,
    )?.[0] ?? "";
  const runtimeMcpInvokeThreadToolBlock =
    runtimeMcpControlSurface.match(
      /async invokeThreadMcpTool\(store, threadId, toolId, request = \{\}\) \{[\s\S]*?\n    \},\n    async recordThreadMcpStatus/,
    )?.[0] ?? "";
  const runtimeMcpRemoveThreadServerBlock =
    runtimeMcpControlSurface.match(
      /removeThreadMcpServer\(store, threadId, serverId, request = \{\}\) \{[\s\S]*?\n    \},\n    applyThreadMcpServerMutation/,
    )?.[0] ?? "";
  const runtimeMcpGetToolFromCatalogBlock =
    runtimeMcpCatalogSurface.match(
      /async getMcpToolFromCatalog\(store, toolId, request = \{\}\) \{[\s\S]*?\n    \},\n    async searchMcpToolCatalog/,
    )?.[0] ?? "";
  const runtimeMcpSearchToolCatalogBlock =
    runtimeMcpCatalogSurface.match(
      /async searchMcpToolCatalog\(store, request = \{\}\) \{[\s\S]*?\n    \},\n    validateMcp/,
    )?.[0] ?? "";
  const runtimeMcpCatalogPreviewLimitBlock =
    runtimeMcpHelpers.match(
      /export function mcpCatalogPreviewLimit\(request = \{\}\) \{[\s\S]*?\n}\n\nexport function mcpToolSearchLimit/,
    )?.[0] ?? "";
  const runtimeMcpResolveToolRecordBlock =
    runtimeMcpHelpers.match(
      /export function resolveMcpToolRecord\(servers = \[\], toolId, request = \{\}\) \{[\s\S]*?\n}\n\nexport function mcpServeAllowedToolIds/,
    )?.[0] ?? "";
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
  const runtimeMcpSdkListOptionsBlock =
    agentSdkSubstrateClient.match(/export interface RuntimeMcpListOptions[\s\S]*?\n}\n/)?.[0] ??
    "";
  const runtimeMcpSdkToolSearchInputBlock =
    agentSdkSubstrateClient.match(/export interface RuntimeMcpToolSearchInput[\s\S]*?\n}\n/)?.[0] ??
    "";
  const runtimeMcpSdkValidationInputBlock =
    agentSdkSubstrateClient.match(/export interface RuntimeMcpValidationInput[\s\S]*?\n}\n/)?.[0] ??
    "";
  const runtimeMcpSdkServerControlInputBlock =
    agentSdkSubstrateClient.match(/export interface RuntimeMcpServerControlInput[\s\S]*?\n}\n/)?.[0] ??
    "";
  const runtimeMcpSdkToolInvokeInputBlock =
    agentSdkSubstrateClient.match(/export interface RuntimeMcpToolInvokeInput[\s\S]*?\n}\n/)?.[0] ??
    "";
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
  const liveRuntimeDaemonMcpFixtures = exists("scripts/lib/live-runtime-daemon-contract/mcp-fixtures.mjs")
    ? read("scripts/lib/live-runtime-daemon-contract/mcp-fixtures.mjs")
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
  const runtimeModelRouteDecisionPayloadBlock = blockBetween(
    runtimeEventPayloads,
    'if (event.type !== "model_route_decision") return summary;',
    "  }\n  \n\n  return",
  );
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
    "runtime-model-route-decision-payload-aliases-retired",
    runtimeModelRouteDecisionPayloadBlock.length > 0 &&
      /event\.data\?\.event_kind/.test(runtimeModelRouteDecisionPayloadBlock) &&
      /event\.data\?\.decision_id/.test(runtimeModelRouteDecisionPayloadBlock) &&
      /event\.data\?\.route_id/.test(runtimeModelRouteDecisionPayloadBlock) &&
      /event\.data\?\.fallback_triggered/.test(runtimeModelRouteDecisionPayloadBlock) &&
      !/event\.data\?\.(?:eventKind|decisionId|routeId|requestedModel|requestedModelMode|selectedModel|endpointId|providerId|providerKind|reasoningEffort|localRemotePlacement|privacyPosture|costEstimateUsd|fallbackTriggered)/.test(
        runtimeModelRouteDecisionPayloadBlock,
      ) &&
      /eventKind:\s*"LegacyModelRouteDecision"/.test(runtimeEventPayloadsTest) &&
      /assert\.equal\(legacyRoute\.model_route_decision_id,\s*null\)/.test(
        runtimeEventPayloadsTest,
      ) &&
      /assert\.equal\(legacyRoute\.fallback_triggered,\s*false\)/.test(
        runtimeEventPayloadsTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-event-payloads.mjs",
      "packages/runtime-daemon/src/runtime-event-payloads.test.mjs",
    ],
    "Phase 10/11 is pending: model-route-decision payload summaries must ignore retired camelCase route-decision aliases",
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
      !/contextBudgetUsageSummary/.test(contextBudgetPolicy) &&
      !/contextBudgetCheck/.test(contextBudgetPolicy) &&
      /retiredContextBudgetUsageInputAliasKeys/.test(contextBudgetPolicyTest) &&
      /context budget usage telemetry ignores retired request aliases/.test(
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
    runtimeSubagentSavedRecordWriteCalls === 0 &&
      runtimeSubagentCanonicalSavedRecordWrites === 6 &&
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
    "runtime-subagent-wait-state-update-live-bridge",
    /SubagentRecordStateUpdateCore/.test(policyCore) &&
      /SubagentRecordStateUpdateRequest/.test(policyCore) &&
      /SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(policyCore) &&
      /rust_policy_plans_subagent_record_state_update/.test(policyCore) &&
      /rust_policy_rejects_subagent_record_state_update_thread_mismatch/.test(
        policyCore,
      ) &&
      /plan_subagent_record_state_update/.test(bridgeModule) &&
      /SubagentRecordStateUpdateBridgeRequest/.test(bridgeModule) &&
      /rust_subagent_record_state_update_command/.test(bridgeModule) &&
      /bridge_plans_subagent_record_state_update_through_rust_core/.test(
        bridgeModule,
      ) &&
      /planSubagentRecordStateUpdate/.test(runtimeContextPolicyRunner) &&
      /SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION/.test(
        runtimeContextPolicyRunner,
      ) &&
      /subagent record state update runner sends Rust state update bridge request/.test(
        runtimeContextPolicyRunnerTest,
      ) &&
      /contextPolicyRunner\.planSubagentRecordStateUpdate/.test(
        runtimeSubagentSurface,
      ) &&
      /subagent wait fails closed without Rust-planned subagent record/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /requiredPlannedSubagentOperationKind\(stateUpdate,\s*"subagent\.wait"/.test(
        runtimeSubagentSurface,
      ) &&
      !/stateUpdate\.operation_kind \?\? "subagent\.wait"/.test(
        runtimeSubagentSurface,
      ) &&
      !/store\.writeSubagent\(saved,\s*"subagent\.wait"\)/.test(
        runtimeSubagentSurface,
      ),
    [
      "crates/services/src/agentic/runtime/kernel/policy.rs",
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-context-policy-runner.test.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: subagent wait lifecycle persistence must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "runtime-subagent-spawn-state-update-live-bridge",
    /planSubagentRecordStateUpdate/.test(runtimeContextPolicyRunner) &&
      /contextPolicyRunner\.planSubagentRecordStateUpdate/.test(
        runtimeSubagentSurface,
      ) &&
      /subagent spawn fails closed without Rust-planned subagent record/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /subagent spawn fails closed without Rust-planned operation kind/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /operation_kind:\s*"subagent\.spawn"/.test(runtimeSubagentSurface) &&
      /requiredPlannedSubagentOperationKind\(stateUpdate,\s*"subagent\.spawn"/.test(
        runtimeSubagentSurface,
      ) &&
      !/stateUpdate\.operation_kind \?\? "subagent\.spawn"/.test(
        runtimeSubagentSurface,
      ) &&
      !/store\.writeSubagent\(saved,\s*"subagent\.spawn"\)/.test(
        runtimeSubagentSurface,
      ),
    [
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: subagent spawn persistence must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "runtime-subagent-input-state-update-live-bridge",
    /planSubagentRecordStateUpdate/.test(runtimeContextPolicyRunner) &&
      /contextPolicyRunner\.planSubagentRecordStateUpdate/.test(
        runtimeSubagentSurface,
      ) &&
      /subagent send input fails closed without Rust-planned subagent record/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /operation_kind:\s*"subagent\.input"/.test(runtimeSubagentSurface) &&
      /requiredPlannedSubagentOperationKind\(stateUpdate,\s*"subagent\.input"/.test(
        runtimeSubagentSurface,
      ) &&
      !/stateUpdate\.operation_kind \?\? "subagent\.input"/.test(
        runtimeSubagentSurface,
      ) &&
      !/store\.writeSubagent\(saved,\s*"subagent\.input"\)/.test(
        runtimeSubagentSurface,
      ),
    [
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: subagent input lifecycle persistence must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "runtime-subagent-resume-state-update-live-bridge",
    /planSubagentRecordStateUpdate/.test(runtimeContextPolicyRunner) &&
      /contextPolicyRunner\.planSubagentRecordStateUpdate/.test(
        runtimeSubagentSurface,
      ) &&
      /subagent resume fails closed without Rust-planned subagent record/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /operation_kind:\s*"subagent\.resume"/.test(runtimeSubagentSurface) &&
      /requiredPlannedSubagentOperationKind\(stateUpdate,\s*"subagent\.resume"/.test(
        runtimeSubagentSurface,
      ) &&
      !/stateUpdate\.operation_kind \?\? "subagent\.resume"/.test(
        runtimeSubagentSurface,
      ) &&
      !/store\.writeSubagent\(saved,\s*"subagent\.resume"\)/.test(
        runtimeSubagentSurface,
      ),
    [
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: subagent resume lifecycle persistence must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "runtime-subagent-assign-state-update-live-bridge",
    /planSubagentRecordStateUpdate/.test(runtimeContextPolicyRunner) &&
      /contextPolicyRunner\.planSubagentRecordStateUpdate/.test(
        runtimeSubagentSurface,
      ) &&
      /subagent assign fails closed without Rust-planned subagent record/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /operation_kind:\s*"subagent\.assign"/.test(runtimeSubagentSurface) &&
      /requiredPlannedSubagentOperationKind\(stateUpdate,\s*"subagent\.assign"/.test(
        runtimeSubagentSurface,
      ) &&
      !/stateUpdate\.operation_kind \?\? "subagent\.assign"/.test(
        runtimeSubagentSurface,
      ) &&
      !/store\.writeSubagent\(saved,\s*"subagent\.assign"\)/.test(
        runtimeSubagentSurface,
      ),
    [
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: subagent assignment persistence must be planned by Rust policy core through the command bridge",
  );
  assertCheck(
    result,
    "runtime-subagent-cancel-state-update-live-bridge",
    /planSubagentRecordStateUpdate/.test(runtimeContextPolicyRunner) &&
      /contextPolicyRunner\.planSubagentRecordStateUpdate/.test(
        runtimeSubagentSurface,
      ) &&
      /subagent cancel fails closed without Rust-planned subagent record/.test(
        runtimeSubagentSurfaceTest,
      ) &&
      /operation_kind:\s*"subagent\.cancel"/.test(runtimeSubagentSurface) &&
      /requiredPlannedSubagentOperationKind\(stateUpdate,\s*"subagent\.cancel"/.test(
        runtimeSubagentSurface,
      ) &&
      !/stateUpdate\.operation_kind \?\? "subagent\.cancel"/.test(
        runtimeSubagentSurface,
      ) &&
      !/store\.writeSubagent\(saved,\s*"subagent\.cancel"\)/.test(
        runtimeSubagentSurface,
      ),
    [
      "packages/runtime-daemon/src/runtime-context-policy-runner.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.mjs",
      "packages/runtime-daemon/src/runtime-subagent-surface.test.mjs",
    ],
    "Phase 10/11 is pending: subagent cancellation persistence must be planned by Rust policy core through the command bridge",
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
      /subagent_role: "SnakeReviewer"/.test(runtimeSubagentSurfaceTest) &&
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
      /subagent_role: "SnakeAliasRole"/.test(runtimeSubagentSurfaceTest) &&
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
      /subagent_role: "SnakeAliasRole"/.test(runtimeSubagentSurfaceTest) &&
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
      /^\s*role\?: string;/m.test(runtimeSubagentSdkListInputBlock) &&
      !/^\s*(?:subagent_role|subagentRole)\?:/m.test(
        `${runtimeSubagentSdkRequestInputBlocks}\n${runtimeSubagentSdkListInputBlock}`,
      ),
    ["packages/agent-sdk/src/substrate-client.ts"],
    "Phase 10/11 is pending: SDK subagent request types must not advertise retired subagent role aliases",
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
    "live-runtime-daemon-exec-helper-boundary",
    /execFileWithInput/.test(liveRuntimeDaemonContract) &&
      /export async function execFileWithInput/.test(liveRuntimeDaemonMcpFixtures) &&
      /from "node:child_process"/.test(liveRuntimeDaemonMcpFixtures) &&
      !/function execFileWithInput/.test(liveRuntimeDaemonContract),
    [
      "scripts/lib/live-runtime-daemon-contract.test.mjs",
      "scripts/lib/live-runtime-daemon-contract/mcp-fixtures.mjs",
    ],
    "Phase 10/11 is pending: live runtime daemon contract tests must share subprocess input helpers through the fixture boundary instead of duplicating local helper bodies",
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
    "workspace-restore-request-aliases-retired",
    /RETIRED_WORKSPACE_RESTORE_REQUEST_ALIASES/.test(runtimeWorkspaceSnapshotSurface) &&
      /CANONICAL_WORKSPACE_RESTORE_REQUEST_FIELDS/.test(runtimeWorkspaceSnapshotSurface) &&
      /workspace_restore_request_aliases_retired/.test(runtimeWorkspaceSnapshotSurface) &&
      /assertCanonicalWorkspaceRestoreRequestBody\(request\);[\s\S]*optionalString\(request\.workflow_graph_id\)/.test(
        runtimeWorkspaceSnapshotSurface,
      ) &&
      /"approvalDecision"/.test(runtimeWorkspaceSnapshotSurface) &&
      /"restoreConflictPolicy"/.test(runtimeWorkspaceSnapshotSurface) &&
      /"approval_decision"/.test(runtimeWorkspaceSnapshotSurface) &&
      /"restore_conflict_policy"/.test(runtimeWorkspaceSnapshotSurface) &&
      !/request\.(?:workflowGraphId|workflowNodeId|idempotencyKey|approvalDecision|policyDecision|confirmRestoreApply|applyConfirmed|approvalGranted|allowConflicts|overrideConflicts|restoreConflictPolicy|conflictPolicy|restorePolicy)\b/.test(
        runtimeWorkspaceSnapshotSurface,
      ) &&
      /request\.approval_decision/.test(workspaceRestoreApplyApprovalHelper) &&
      /request\.approval_granted/.test(workspaceRestoreApplyApprovalHelper) &&
      !/request\.(?:approvalDecision|policyDecision|confirmRestoreApply|applyConfirmed|approvalGranted)\b/.test(
        workspaceRestoreApplyApprovalHelper,
      ) &&
      /request\.restore_conflict_policy/.test(workspaceRestoreApplyConflictHelper) &&
      /request\.allow_conflicts/.test(workspaceRestoreApplyConflictHelper) &&
      !/request\.(?:restoreConflictPolicy|conflictPolicy|restorePolicy|allowConflicts|overrideConflicts)\b/.test(
        workspaceRestoreApplyConflictHelper,
      ) &&
      /workspace snapshot restore rejects retired request aliases before agent lookup/.test(
        runtimeWorkspaceSnapshotSurfaceTest,
      ) &&
      /agent lookup must not run for retired workspace restore request aliases/.test(
        runtimeWorkspaceSnapshotSurfaceTest,
      ) &&
      /workflow_node_id:\s*"restore_node"/.test(runtimeWorkspaceSnapshotSurfaceTest) &&
      /approvalDecision: "approved"/.test(runtimeWorkspaceSnapshotSurfaceTest) &&
      /restoreConflictPolicy: "allow_override"/.test(runtimeWorkspaceSnapshotSurfaceTest) &&
      /workspaceRestoreApplyApprovalForRequest\(\{ approvalDecision: "approved" \}\)\.satisfied,[\s\S]*false/.test(
        diagnosticsRepairExecutionTest,
      ) &&
      /workspaceRestoreApplyAllowsConflicts\(\{ restoreConflictPolicy: "allow_override" \}\), false/.test(
        diagnosticsRepairExecutionTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-workspace-snapshot-surface.mjs",
      "packages/runtime-daemon/src/runtime-workspace-snapshot-surface.test.mjs",
      "packages/runtime-daemon/src/diagnostics-repair-execution.mjs",
      "packages/runtime-daemon/src/diagnostics-repair-execution.test.mjs",
    ],
    "Phase 10/11 is pending: workspace restore preview/apply requests must fail closed on retired workflow/idempotency/apply-policy camelCase aliases before projection events are emitted",
  );
  assertCheck(
    result,
    "diagnostics-repair-restore-request-aliases-retired",
    /RETIRED_DIAGNOSTICS_REPAIR_RESTORE_REQUEST_ALIASES/.test(runtimeDiagnosticsRepairSurface) &&
      /CANONICAL_DIAGNOSTICS_REPAIR_RESTORE_REQUEST_FIELDS/.test(runtimeDiagnosticsRepairSurface) &&
      /diagnostics_repair_restore_request_aliases_retired/.test(runtimeDiagnosticsRepairSurface) &&
      /assertCanonicalDiagnosticsRepairRestoreRequestBody\(action, request\);[\s\S]*optionalString\(request\.snapshot_id\)/.test(
        runtimeDiagnosticsRepairSurface,
      ) &&
      !/request\.(?:snapshotId|workflowGraphId|workflowNodeId|restorePreviewIdempotencyKey|restoreApplyIdempotencyKey|approvalDecision|policyDecision|confirmRestoreApply|applyConfirmed|approvalGranted|allowConflicts|overrideConflicts|restoreConflictPolicy|conflictPolicy)\b/.test(
        runtimeDiagnosticsRepairSurface,
      ) &&
      /diagnostics repair surface routes restore apply with canonical request fields/.test(
        runtimeDiagnosticsRepairSurfaceTest,
      ) &&
      /diagnostics repair restore rejects retired request aliases before workspace restore call/.test(
        runtimeDiagnosticsRepairSurfaceTest,
      ) &&
      /workspace restore call must not run for retired diagnostics repair restore request aliases/.test(
        runtimeDiagnosticsRepairSurfaceTest,
      ),
    [
      "packages/runtime-daemon/src/runtime-diagnostics-repair-surface.mjs",
      "packages/runtime-daemon/src/runtime-diagnostics-repair-surface.test.mjs",
    ],
    "Phase 10/11 is pending: diagnostics repair restore decisions must fail closed on retired restore request aliases before calling workspace restore preview/apply",
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
    "runtime-mcp-config-source-request-aliases-retired",
    /request\.config_source/.test(runtimeMcpHelpers) &&
      /request\.mcp_config_source_mode/.test(runtimeMcpHelpers) &&
      /request\.config_source_mode/.test(runtimeMcpHelpers) &&
      /options\.mcp_config_source_mode\s*\?\?\s*options\.config_source_mode/.test(
        runtimeMcpManager,
      ) &&
      /^\s*mcp_config_source_mode\?: string;/m.test(runtimeMcpSdkListOptionsBlock) &&
      /^\s*config_source_mode\?: string;/m.test(runtimeMcpSdkListOptionsBlock) &&
      /configSource: "retired-camel-source"/.test(runtimeMcpHelpersTest) &&
      /configSourceMode: "workspace"/.test(runtimeMcpHelpersTest) &&
      /mcpConfigSourceMode: "global"/.test(runtimeMcpHelpersTest) &&
      !/request\.(?:configSource|mcpConfigSourceMode|configSourceMode)\b/.test(
        runtimeMcpHelpers,
      ) &&
      !/options\.(?:mcpConfigSourceMode|configSourceMode)\b/.test(runtimeMcpManager) &&
      !/^\s*(?:threadId|agentId|serverId)\?:/m.test(runtimeMcpSdkListOptionsBlock) &&
      !/^\s*\[key: string\]: unknown;/m.test(runtimeMcpSdkListOptionsBlock),
    [
      "packages/runtime-daemon/src/runtime-mcp-helpers.mjs",
      "packages/runtime-daemon/src/runtime-mcp-helpers.test.mjs",
      "packages/runtime-daemon/src/mcp-manager.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 10/11 is pending: MCP source-mode requests must use canonical snake_case fields without camelCase compatibility aliases or SDK escape hatches",
  );
  assertCheck(
    result,
    "runtime-mcp-catalog-identity-request-aliases-retired",
    /options\.thread_id/.test(runtimeMcpCatalogSurface) &&
      /options\.agent_id/.test(runtimeMcpCatalogSurface) &&
      /options\.server_id/.test(runtimeMcpCatalogSurface) &&
      /threadId: "thread-retired"/.test(runtimeMcpCatalogSurfaceTest) &&
      /agentId: "retired-agent"/.test(runtimeMcpCatalogSurfaceTest) &&
      /serverId: "retired-server"/.test(runtimeMcpCatalogSurfaceTest) &&
      /^\s*thread_id\?: string;/m.test(runtimeMcpSdkListOptionsBlock) &&
      /^\s*agent_id\?: string;/m.test(runtimeMcpSdkListOptionsBlock) &&
      /^\s*server_id\?: string;/m.test(runtimeMcpSdkListOptionsBlock) &&
      !/options\.(?:threadId|agentId|serverId)\b/.test(runtimeMcpCatalogSurface) &&
      !/^\s*(?:threadId|agentId|serverId)\?:/m.test(runtimeMcpSdkListOptionsBlock),
    [
      "packages/runtime-daemon/src/runtime-mcp-catalog-surface.mjs",
      "packages/runtime-daemon/src/runtime-mcp-catalog-surface.test.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 10/11 is pending: MCP catalog/list/search requests must use canonical snake_case identity fields without camelCase compatibility aliases",
  );
  assertCheck(
    result,
    "runtime-mcp-tool-search-request-aliases-retired",
    /request\.tool_id/.test(runtimeMcpSearchToolCatalogBlock) &&
      /request\.server_id/.test(runtimeMcpSearchToolCatalogBlock) &&
      /request\.live_discovery/.test(runtimeMcpSearchToolCatalogBlock) &&
      /request\.catalog_preview_limit/.test(runtimeMcpCatalogPreviewLimitBlock) &&
      /request\.mcp_catalog_preview_limit/.test(runtimeMcpCatalogPreviewLimitBlock) &&
      /request\.preview_limit/.test(runtimeMcpCatalogPreviewLimitBlock) &&
      /^\s*tool_id\?: string;/m.test(runtimeMcpSdkToolSearchInputBlock) &&
      /^\s*tool_name\?: string;/m.test(runtimeMcpSdkToolSearchInputBlock) &&
      /^\s*live_discovery\?: boolean;/m.test(runtimeMcpSdkToolSearchInputBlock) &&
      /^\s*catalog_preview_limit\?: number;/m.test(runtimeMcpSdkToolSearchInputBlock) &&
      /toolId: "mcp\.workspace\.docs\.search"/.test(runtimeMcpCatalogSurfaceTest) &&
      /serverId: "mcp\.workspace\.docs"/.test(runtimeMcpCatalogSurfaceTest) &&
      /liveDiscovery: true/.test(runtimeMcpCatalogSurfaceTest) &&
      /catalogPreviewLimit: 1/.test(runtimeMcpCatalogSurfaceTest) &&
      !/request\.(?:toolId|serverId|liveDiscovery)\b/.test(
        `${runtimeMcpSearchToolCatalogBlock}\n${runtimeMcpGetToolFromCatalogBlock}`,
      ) &&
      !/request\.(?:catalogPreviewLimit|mcpCatalogPreviewLimit|previewLimit)\b/.test(
        runtimeMcpCatalogPreviewLimitBlock,
      ) &&
      !/^\s*(?:toolId|serverId|liveDiscovery|catalogPreviewLimit)\?:/m.test(
        runtimeMcpSdkToolSearchInputBlock,
      ),
    [
      "packages/runtime-daemon/src/runtime-mcp-catalog-surface.mjs",
      "packages/runtime-daemon/src/runtime-mcp-catalog-surface.test.mjs",
      "packages/runtime-daemon/src/runtime-mcp-helpers.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 10/11 is pending: MCP tool search/fetch requests must use canonical snake_case fields without camelCase compatibility aliases",
  );
  assertCheck(
    result,
    "runtime-mcp-control-thread-request-alias-retired",
    /input\.thread_id/.test(runtimeMcpControlSurface) &&
      /request\.thread_id/.test(runtimeMcpControlSurface) &&
      /threadId: "thread-retired"/.test(runtimeMcpControlSurfaceTest) &&
      /surface\.importMcp\(store, \{ threadId: "thread-agent-one"/.test(
        runtimeMcpControlSurfaceTest,
      ) &&
      /surface\.invokeMcpTool\(store, \{\s*threadId: "thread-agent-one"/.test(
        runtimeMcpControlSurfaceTest,
      ) &&
      /^\s*thread_id\?: string;/m.test(runtimeMcpSdkServerControlInputBlock) &&
      /^\s*thread_id\?: string;/m.test(runtimeMcpSdkToolInvokeInputBlock) &&
      !/(?:input|request)\.threadId\b/.test(runtimeMcpControlSurface) &&
      !/^\s*threadId\?:/m.test(
        `${runtimeMcpSdkServerControlInputBlock}\n${runtimeMcpSdkToolInvokeInputBlock}`,
      ),
    [
      "packages/runtime-daemon/src/runtime-mcp-control-surface.mjs",
      "packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 10/11 is pending: MCP control/invoke requests must use canonical thread_id without the retired threadId compatibility alias",
  );
  assertCheck(
    result,
    "runtime-mcp-control-server-request-alias-retired",
    /request\.server_id/.test(runtimeMcpRemoveThreadServerBlock) &&
      /serverId: "mcp\.extra"/.test(runtimeMcpControlSurfaceTest) &&
      /serverId: "mcp\.retired"/.test(runtimeMcpControlSurfaceTest) &&
      /^\s*server_id\?: string;/m.test(runtimeMcpSdkServerControlInputBlock) &&
      !/request\.serverId\b/.test(runtimeMcpRemoveThreadServerBlock) &&
      !/^\s*serverId\?:/m.test(runtimeMcpSdkServerControlInputBlock),
    [
      "packages/runtime-daemon/src/runtime-mcp-control-surface.mjs",
      "packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 10/11 is pending: MCP server-control requests must use canonical server_id without the retired serverId compatibility alias",
  );
  assertCheck(
    result,
    "runtime-mcp-control-workflow-node-request-alias-retired",
    /request\.workflow_node_id/.test(runtimeMcpControlSurface) &&
      /workflowNodeId: "runtime\.mcp-server\.extra\.retired"/.test(runtimeMcpControlSurfaceTest) &&
      /workflowNodeId: "runtime\.mcp-server\.remove\.retired"/.test(runtimeMcpControlSurfaceTest) &&
      /^\s*workflow_node_id\?: string;/m.test(runtimeMcpSdkValidationInputBlock) &&
      !/request\.workflowNodeId\b/.test(runtimeMcpControlSurface) &&
      !/^\s*workflowNodeId\?:/m.test(runtimeMcpSdkValidationInputBlock),
    [
      "packages/runtime-daemon/src/runtime-mcp-control-surface.mjs",
      "packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 10/11 is pending: MCP control requests must use canonical workflow_node_id without the retired workflowNodeId compatibility alias",
  );
  assertCheck(
    result,
    "runtime-mcp-invoke-identity-request-aliases-retired",
    /request\.tool_id/.test(runtimeMcpResolveToolRecordBlock) &&
      /request\.server_id/.test(runtimeMcpResolveToolRecordBlock) &&
      /request\.tool_name/.test(runtimeMcpResolveToolRecordBlock) &&
      /request\.tool_id/.test(runtimeMcpControlSurface) &&
      /^\s*server_id\?: string;/m.test(runtimeMcpSdkToolInvokeInputBlock) &&
      /^\s*tool_id\?: string;/m.test(runtimeMcpSdkToolInvokeInputBlock) &&
      /^\s*tool_name\?: string;/m.test(runtimeMcpSdkToolInvokeInputBlock) &&
      /toolId: "mcp\.retired\.nope"/.test(
        `${runtimeMcpHelpersTest}\n${runtimeMcpControlSurfaceTest}`,
      ) &&
      /serverId: "mcp\.retired"/.test(
        `${runtimeMcpHelpersTest}\n${runtimeMcpControlSurfaceTest}`,
      ) &&
      /toolName: "retired"/.test(
        `${runtimeMcpHelpersTest}\n${runtimeMcpControlSurfaceTest}`,
      ) &&
      !/request\.(?:toolId|serverId|toolName)\b/.test(
        `${runtimeMcpResolveToolRecordBlock}\n${runtimeMcpInvokeToolBlock}\n${runtimeMcpInvokeThreadToolBlock}`,
      ) &&
      !/input\.(?:toolId|serverId|toolName)\b/.test(agentSdkSubstrateClient) &&
      !/^\s*(?:toolId|serverId|toolName)\?:/m.test(runtimeMcpSdkToolInvokeInputBlock),
    [
      "packages/runtime-daemon/src/runtime-mcp-helpers.mjs",
      "packages/runtime-daemon/src/runtime-mcp-helpers.test.mjs",
      "packages/runtime-daemon/src/runtime-mcp-control-surface.mjs",
      "packages/runtime-daemon/src/runtime-mcp-control-surface.test.mjs",
      "packages/agent-sdk/src/substrate-client.ts",
    ],
    "Phase 10/11 is pending: MCP invoke requests must use canonical tool_id/server_id/tool_name without retired camelCase identity aliases",
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
