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
      /createCodingToolStepModuleProjection/.test(read("packages/runtime-daemon/src/step-module-abi.mjs")) &&
      /codingToolStepModuleProjection/.test(read("packages/runtime-daemon/src/coding-tools.mjs")),
    ["packages/runtime-daemon/src/step-module-abi.mjs", "packages/runtime-daemon/src/coding-tools.mjs"],
    "Phase 1 is pending: JS coding tool contracts must emit Step/Module wrappers in projection mode",
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
    codeCorpusContains(/RustWorkloadStepModuleRunner|IOI_STEP_MODULE_BACKEND|IOI_WORKLOAD_GRPC_ADDR/),
    ["packages/runtime-daemon/src", "crates/client/src/workload_client/mod.rs"],
    "Phase 2 is pending: add Rust workload bridge configuration and fail-closed runner",
  );
  assertCheck(
    result,
    "workspace-status-rust-command-bridge",
    exists("crates/node/src/bin/ioi-step-module-bridge.rs") &&
      /workspace\.status/.test(read("crates/node/src/bin/ioi-step-module-bridge.rs")) &&
      /ioi\.step_module\.command_bridge\.v1/.test(read("crates/node/src/bin/ioi-step-module-bridge.rs")),
    ["crates/node/src/bin/ioi-step-module-bridge.rs"],
    "Phase 3 is pending: add a Rust command bridge for the first shadowed daemon tool",
  );
  return result;
}

function runReceipts() {
  const result = createTierResult("receipts");
  assertCheck(
    result,
    "receipt-binder-core",
    exists("crates/services/src/agentic/runtime/kernel/receipt_binder.rs") &&
      /STEP_MODULE_RECEIPT_BINDING_SCHEMA_VERSION/.test(
        read("crates/services/src/agentic/runtime/kernel/receipt_binder.rs"),
      ) &&
      /receipt_binding/.test(read("crates/node/src/bin/ioi-step-module-bridge.rs")),
    [
      "crates/services/src/agentic/runtime/kernel/receipt_binder.rs",
      "crates/node/src/bin/ioi-step-module-bridge.rs",
    ],
    "Phase 4 is pending: one Rust receipt/state-root binder must own accepted result binding",
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
  return result;
}

function runCompositor() {
  const result = createTierResult("compositor");
  const projectionCore = exists("crates/services/src/agentic/runtime/kernel/projection.rs")
    ? read("crates/services/src/agentic/runtime/kernel/projection.rs")
    : "";
  assertCheck(
    result,
    "rust-projection-core",
    /RustProjectionCore/.test(projectionCore) &&
      /StepModuleProjectionRecord/.test(projectionCore) &&
      /workflow_projection_watermark_from_agentgres/.test(projectionCore) &&
      /projection_record/.test(read("crates/node/src/bin/ioi-step-module-bridge.rs")),
    [
      "crates/services/src/agentic/runtime/kernel/projection.rs",
      "crates/node/src/bin/ioi-step-module-bridge.rs",
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
