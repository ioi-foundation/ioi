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
  const modelMountingState = exists("packages/runtime-daemon/src/model-mounting.mjs")
    ? read("packages/runtime-daemon/src/model-mounting.mjs")
    : "";
  const modelMountAdmissionRunner = exists("packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs")
    : "";
  const modelRoutes = exists("packages/runtime-daemon/src/model-mounting/routes.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/routes.mjs")
    : "";
  const modelInvocationOps = exists("packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs")
    ? read("packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs")
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
  const codingTools = exists("packages/runtime-daemon/src/coding-tools.mjs")
    ? read("packages/runtime-daemon/src/coding-tools.mjs")
    : "";
  const runtimeDaemonIndex = exists("packages/runtime-daemon/src/index.mjs")
    ? read("packages/runtime-daemon/src/index.mjs")
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
      /modelMountRouteDecisionRef/.test(modelRoutes),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/routes.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 3/9 is pending: model-mounting route decisions must call Rust model_mount core and fail closed before provider invocation",
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
      /modelMountInvocationAdmissionRef/.test(modelInvocationOps),
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
      /modelMountProviderExecutionRef/.test(modelInvocationOps),
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
      /modelMountInstanceLifecycleHash/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /modelMountInstanceLifecycleAction/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
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
      /modelMountProviderResultAdmissionRef/.test(modelInvocationOps),
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
    "model-mount-stream-provider-result-admission-live-bridge",
    /startModelStream/.test(modelInvocationOps) &&
      /requireModelMountProviderResultAdmission/.test(modelInvocationOps) &&
      /modelMountProviderResultAdmissionRequestForExecution/.test(modelInvocationOps) &&
      /streamStatus: "started"/.test(modelInvocationOps) &&
      /modelMountProviderResultAdmissionRef/.test(modelInvocationOps) &&
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
      /modelMountReceiptBindingRef/.test(modelInvocationOps) &&
      /modelMountAgentgresAdmission/.test(modelInvocationOps) &&
      /modelMountAcceptedReceiptAppendHash/.test(modelInvocationOps),
    [
      "crates/node/src/bin/ioi_step_module_bridge/mod.rs",
      "packages/runtime-daemon/src/model-mounting/model-mount-admission-runner.mjs",
      "packages/runtime-daemon/src/model-mounting/model-invocation-operations.mjs",
      "packages/runtime-daemon/src/model-mounting.mjs",
    ],
    "Phase 4 is pending: model invocation receipts must be bound by Rust receipt_binder before JS persistence",
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
      /modelMountInstanceLifecycleAction/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
      ) &&
      /modelMountInstanceLifecycleStatus/.test(
        read("packages/runtime-daemon/src/model-mounting/model-instance-lifecycle.mjs"),
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
    /modelMountProviderInventory/.test(
      read("packages/runtime-daemon/src/model-mounting/provider-local-drivers.mjs"),
    ) &&
      /providerInventoryReceiptFields/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.mjs"),
      ) &&
      /assertModelMountingReceiptWriteBound/.test(modelMountStore) &&
      /assertProviderInventoryReceiptBound/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /model_mount_provider_inventory_receipt_direct_append_forbidden/.test(
        modelMountReceiptWriteGuards,
      ) &&
      /local provider model and loaded list receipts carry Rust inventory bindings/.test(
        read("packages/runtime-daemon/src/model-mounting/provider-operations.test.mjs"),
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
    /modelMountProviderLifecycle/.test(
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
      /modelMountReceiptBindingRef/.test(modelInvocationOps) &&
      /modelMountAcceptedReceiptAppend/.test(modelInvocationOps) &&
      /modelMountAgentgresAdmission/.test(modelInvocationOps) &&
      /modelMountAgentgresOperationRef/.test(modelInvocationOps) &&
      /model_mount_agentgres_head_required/.test(modelInvocationOps) &&
      /agentgresOperationRefs/.test(modelInvocationOps) &&
      /stateRootAfter/.test(modelInvocationOps) &&
      /resultingHead/.test(modelInvocationOps) &&
      /modelMountStepModuleInvocation/.test(modelInvocationOps) &&
      /modelMountStepModuleResult/.test(modelInvocationOps),
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
      /modelMountAgentgresExpectedHeads/.test(modelInvocationOps) &&
      /modelMountAgentgresStateRootBefore/.test(modelInvocationOps) &&
      /modelMountAgentgresStateRootAfter/.test(modelInvocationOps) &&
      /modelMountAgentgresResultingHead/.test(modelInvocationOps),
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
      /modelMountReceiptBindingRef/.test(modelMountReceiptWriteGuards) &&
      /modelMountAcceptedReceiptAppendHash/.test(modelMountReceiptWriteGuards) &&
      /modelMountAgentgresOperationRef/.test(modelMountReceiptWriteGuards) &&
      /modelMountAgentgresAdmissionHash/.test(modelMountReceiptWriteGuards),
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
