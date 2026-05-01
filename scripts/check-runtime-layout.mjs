#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];
const report = [];

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function exists(relativePath) {
  return fs.existsSync(path.join(root, relativePath));
}

function allFiles(dir, predicate = () => true) {
  const absolute = path.join(root, dir);
  if (!fs.existsSync(absolute)) return [];
  return fs.readdirSync(absolute, { withFileTypes: true }).flatMap((entry) => {
    const relative = path.join(dir, entry.name);
    if (entry.isDirectory()) return allFiles(relative, predicate);
    return predicate(relative) ? [relative] : [];
  });
}

function assert(id, condition, evidence, message) {
  report.push({ id, status: condition ? "passed" : "failed", evidence, message });
  if (!condition) failures.push(`${id}: ${message}`);
}

const packageJson = JSON.parse(read("package.json"));
const daemonSource = read("packages/runtime-daemon/src/index.mjs");
const sdkSubstrate = read("packages/agent-sdk/src/substrate-client.ts");
const sdkIndex = read("packages/agent-sdk/src/index.ts");
const ideRuntimeFiles = allFiles("packages/agent-ide/src/runtime", (file) => /\.(ts|tsx)$/.test(file));
const autopilotRootProofFiles = allFiles("apps/autopilot/src-tauri/src", (file) =>
  /_proof\.rs$/.test(file) && !file.includes(`${path.sep}bin${path.sep}`) && !file.includes(`${path.sep}proofs${path.sep}`),
);
const builtinFiles = allFiles("crates/services/src/agentic/runtime/tools/builtins", (file) =>
  file.endsWith(".rs"),
);
const runtimeServiceFiles = allFiles("crates/services/src/agentic/runtime/service", (file) =>
  /\.(rs|md)$/.test(file),
);
const activeRuntimeSwarmFiles = [
  ...allFiles("apps/autopilot/src", (file) => /\.(ts|tsx|css)$/.test(file)),
  ...allFiles("apps/autopilot/src-tauri/src", (file) => file.endsWith(".rs")),
  ...allFiles("crates/api/src", (file) => file.endsWith(".rs")),
  ...allFiles("crates/services/src/agentic/runtime", (file) => file.endsWith(".rs")),
  "crates/types/src/app/chat.rs",
].filter((file) => exists(file));
const allowedSwarmCompatibilityFiles = new Set([
  "apps/autopilot/src-tauri/src/models/chat.rs",
  "apps/autopilot/src-tauri/src/models/runtime_view_tests.rs",
  "apps/autopilot/src-tauri/src/models/session.rs",
  "apps/autopilot/src/types/work-graph-compat.ts",
  "crates/api/src/chat/types.rs",
  "crates/services/src/agentic/runtime/service/memory/context.rs",
  "crates/services/src/agentic/runtime/legacy.rs",
  "crates/services/src/agentic/runtime/types.rs",
  "crates/types/src/app/chat.rs",
]);
const generatedTs = read("packages/agent-ide/src/runtime/generated/action-schema.ts");
const generatedRust = read("apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs");
const actionSchema = JSON.parse(read("docs/architecture/operations/runtime-action-schema.json"));

assert(
  "daemon-promoted",
  exists("packages/runtime-daemon/src/index.mjs") && !exists("scripts/lib/local-runtime-daemon.mjs"),
  ["packages/runtime-daemon/src/index.mjs"],
  "daemon implementation must live outside scripts/lib",
);
assert(
  "daemon-product-names",
  daemonSource.includes("startRuntimeDaemonService") &&
    daemonSource.includes("AgentgresRuntimeStateStore") &&
    !daemonSource.includes("startLocalRuntimeDaemon") &&
    !daemonSource.includes("AgentgresRuntimeStore"),
  ["packages/runtime-daemon/src/index.mjs"],
  "daemon implementation must use product runtime names",
);
assert(
  "stable-conformance-scripts",
  exists("scripts/conformance/runtime-complete-plus.mjs") &&
    exists("scripts/evidence/runtime-complete-plus.mjs") &&
    packageJson.scripts["validate:runtime-complete-plus"] &&
    packageJson.scripts["evidence:runtime-complete-plus"],
  ["scripts/conformance/runtime-complete-plus.mjs", "scripts/evidence/runtime-complete-plus.mjs", "package.json"],
  "runtime conformance/evidence must have durable names",
);
assert(
  "roadmap-wrappers-only",
  read("scripts/run-architectural-improvements-broad-validation.mjs").includes("Deprecated roadmap-name wrapper") &&
    read("scripts/run-architectural-improvements-broad-evidence.mjs").includes("Deprecated roadmap-name wrapper"),
  ["scripts/run-architectural-improvements-broad-validation.mjs", "scripts/run-architectural-improvements-broad-evidence.mjs"],
  "roadmap-specific scripts may only remain as thin deprecated wrappers",
);
assert(
  "runtime-module-map",
  exists("docs/architecture/operations/runtime-module-map.md") &&
    read("docs/architecture/operations/runtime-module-map.md").includes("RuntimeSubstrate") &&
    read("docs/architecture/operations/runtime-package-boundaries.md").includes("runtime-module-map.md"),
  ["docs/architecture/operations/runtime-module-map.md", "docs/architecture/operations/runtime-package-boundaries.md"],
  "runtime module map must identify canonical homes and be linked from boundary docs",
);
assert(
  "contract-family-modules",
  [
    "adapters",
    "agentgres",
    "authority",
    "cognition",
    "envelope",
    "events",
    "policy",
    "quality",
    "tools",
    "trace",
  ].every((name) => exists(`crates/types/src/app/runtime/${name}.rs`)) &&
    read("crates/types/src/app/mod.rs").includes("pub mod runtime;"),
  ["crates/types/src/app/runtime", "crates/types/src/app/mod.rs"],
  "runtime contract families must have concern-oriented module paths",
);
assert(
  "step-ownership-map",
  exists("crates/services/src/agentic/runtime/service/README.md") &&
    read("crates/services/src/agentic/runtime/service/README.md").includes("decision_loop") &&
    read("crates/services/src/agentic/runtime/service/README.md").includes("tool_execution") &&
    read("crates/services/src/agentic/runtime/service/decision_loop/README.md").includes("guarded service lane"),
  [
    "crates/services/src/agentic/runtime/service/README.md",
    "crates/services/src/agentic/runtime/service/decision_loop/README.md",
  ],
  "runtime service must have explicit lane ownership boundaries",
);
assert(
  "step-physical-split",
  !exists("crates/services/src/agentic/runtime/service/step") &&
    runtimeServiceFiles.every((file) => !read(file).includes("service::step")),
  ["crates/services/src/agentic/runtime/service"],
  "runtime service implementation must be physically split into named lanes with no service::step imports",
);
assert(
  "builtin-tool-family-names",
  builtinFiles.every((file) => {
    const base = path.basename(file);
    return (
      base === "tests.rs" ||
      /^[a-z][a-z0-9_]*\.rs$/.test(base) &&
        !base.includes("deterministic_system_tools_are_available") &&
        !base.includes("tier_1_deterministic") &&
        !base.includes("only_expose_screen")
    );
  }),
  builtinFiles,
  "built-in production tool files must use tool-family names",
);
assert(
  "proofs-isolated",
  autopilotRootProofFiles.length === 0 &&
    exists("apps/autopilot/src-tauri/src/proofs/mod.rs") &&
    read("apps/autopilot/src-tauri/src/lib.rs").includes("pub mod proofs;"),
  ["apps/autopilot/src-tauri/src/proofs/mod.rs", "apps/autopilot/src-tauri/src/lib.rs"],
  "Autopilot proof modules must live under proofs/ rather than root product modules",
);
assert(
  "sdk-no-gui-harness-imports",
  !/apps\/autopilot|agent-ide|scripts\/lib|benchmarks/.test(sdkSubstrate + sdkIndex),
  ["packages/agent-sdk/src"],
  "SDK must not import GUI, harness, benchmark, or script internals",
);
assert(
  "projection-adapter-names",
  exists("packages/agent-ide/src/runtime/runtime-projection-adapter.ts") &&
    !exists("packages/agent-ide/src/runtime/agent-execution-substrate.ts") &&
    exists("apps/autopilot/src-tauri/src/runtime_projection.rs") &&
    !exists("apps/autopilot/src-tauri/src/agent_runtime_substrate.rs"),
  ["packages/agent-ide/src/runtime/runtime-projection-adapter.ts", "apps/autopilot/src-tauri/src/runtime_projection.rs"],
  "client projection adapters must not be named as canonical execution substrates",
);
assert(
  "ide-projection-boundary",
  ideRuntimeFiles.every((file) => !read(file).includes("AgentgresRuntimeStateStore")) &&
    read("packages/agent-ide/src/runtime/workflow-composer-model.ts").includes("non-canonical"),
  ["packages/agent-ide/src/runtime"],
  "agent-ide runtime helpers must remain non-canonical projections",
);
assert(
  "capability-tiers",
  read("crates/types/src/app/runtime_contracts.rs").includes("primitive_capabilities: Vec<String>") &&
    read("crates/types/src/app/runtime_contracts.rs").includes("authority_scope_requirements: Vec<String>") &&
    read("crates/services/src/agentic/runtime/tools/contracts.rs").includes("authority_scopes_for") &&
    !read("crates/types/src/app/runtime_contracts.rs").includes("capability_lease_requirements"),
  ["crates/types/src/app/runtime_contracts.rs", "crates/services/src/agentic/runtime/tools/contracts.rs"],
  "primitive capabilities and authority scopes must stay separated",
);
assert(
  "action-schema-drift",
  actionSchema.actionKinds.every((kind) => generatedTs.includes(`"${kind}"`) && generatedRust.includes(`"${kind}"`)),
  ["docs/architecture/operations/runtime-action-schema.json", "packages/agent-ide/src/runtime/generated/action-schema.ts", "apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs"],
  "generated action schema projections must match shared runtime-action-schema.json",
);
assert(
  "public-swarm-boundary",
  !read("crates/types/src/app/chat.rs").includes('alias = "swarm"') &&
    !read("crates/types/src/app/chat.rs").includes("MicroSwarm") &&
    read("docs/architecture/operations/runtime-vocabulary.md").includes("adaptive_work_graph") &&
    activeRuntimeSwarmFiles.every((file) => {
      const content = read(file);
      if (!/\bswarm\b|Swarm|swarm[A-Z_]/.test(content)) return true;
      return allowedSwarmCompatibilityFiles.has(file);
    }),
  ["crates/types/src/app/chat.rs", "apps/autopilot/src", "crates/services/src/agentic/runtime"],
  "active public runtime vocabulary must use adaptive work graph terminology; legacy swarm decoding must stay isolated",
);
assert(
  "debt-ledger-closed",
  read("docs/evidence/runtime-layout-refactor/remaining-debt.md").includes(
    "No remaining runtime-layout refactor debt",
  ),
  ["docs/evidence/runtime-layout-refactor/remaining-debt.md"],
  "runtime-layout debt ledger must be closed before claiming completion",
);

const evidenceDir = path.join(root, "docs/evidence/runtime-layout-refactor");
fs.mkdirSync(evidenceDir, { recursive: true });
const summary = {
  schemaVersion: "ioi.runtime-layout-refactor.check.v1",
  generatedAt: new Date().toISOString(),
  status: failures.length ? "failed" : "passed",
  report,
  failures,
};
fs.writeFileSync(path.join(evidenceDir, "guardrail-report.json"), `${JSON.stringify(summary, null, 2)}\n`);

if (failures.length) {
  console.error("Runtime layout check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Runtime layout check passed.");
console.log(`Evidence: ${path.relative(root, path.join(evidenceDir, "guardrail-report.json"))}`);
