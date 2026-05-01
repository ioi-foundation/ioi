#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];
const checklist = [];

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function assertLane(id, lane, condition, evidence, risk) {
  checklist.push({
    id,
    lane,
    status: condition ? "Complete" : "Missing",
    evidence,
    risk: condition ? "guarded" : risk,
  });
  if (!condition) failures.push(`${id} ${lane}: ${risk}`);
}

function assertText(id, lane, content, patterns, evidence, risk) {
  assertLane(
    id,
    lane,
    patterns.every((pattern) =>
      typeof pattern === "string" ? content.includes(pattern) : pattern.test(content),
    ),
    evidence,
    risk,
  );
}

const guide = read("docs/plans/architectural-improvements-broad-master-guide.md");
const packageJson = readJson("package.json");
const sdkSubstrate = read("packages/agent-sdk/src/substrate-client.ts");
const sdkAgent = read("packages/agent-sdk/src/agent.ts");
const sdkOptions = read("packages/agent-sdk/src/options.ts");
const sdkMessages = read("packages/agent-sdk/src/messages.ts");
const sdkIndex = read("packages/agent-sdk/src/index.ts");
const sdkTests = read("packages/agent-sdk/test/sdk.test.mjs");
const localDaemon = read("packages/runtime-daemon/src/index.mjs");
const broadEvidence = read("scripts/evidence/runtime-complete-plus.mjs");
const runtimeContracts = read("crates/types/src/app/runtime_contracts.rs");
const toolContracts = read("crates/services/src/agentic/runtime/tools/contracts.rs");
const chatTypes = read("crates/types/src/app/chat.rs");
const developerDocs = read("apps/developers-ioi-ai/src/content/docs.tsx");
const workflowController = read("packages/agent-ide/src/WorkflowComposer/controller.tsx");

assertText(
  "A1",
  "capability-tier contract",
  `${runtimeContracts}\n${toolContracts}`,
  ["primitive_capabilities", "authority_scope_requirements", "scope:host.controlled_execution"],
  [
    "crates/types/src/app/runtime_contracts.rs",
    "crates/services/src/agentic/runtime/tools/contracts.rs",
  ],
  "primitive and authority scope tiers are not separated",
);
assertLane(
  "A2",
  "retired capability aliases",
  !runtimeContracts.includes("capability_lease_requirements") &&
    !runtimeContracts.includes("legacy_capability_projection"),
  ["crates/types/src/app/runtime_contracts.rs"],
  "old flattened capability projection remains",
);

const daemonRoutes = [
  "/v1/agents",
  "/v1/runs",
  "/v1/models",
  "/v1/repositories",
  "/v1/account",
  "/v1/runtime/nodes",
  "/v1/tools",
];
assertLane(
  "B1",
  "daemon SDK route coverage",
  daemonRoutes.every((route) => sdkSubstrate.includes(route)),
  ["packages/agent-sdk/src/substrate-client.ts"],
  "SDK daemon client does not address the public runtime API surface",
);
assertText(
  "B2",
  "event streaming and reconnect transport",
  `${sdkSubstrate}\n${localDaemon}`,
  ["requestEvents", "text/event-stream", "parseServerSentEvents", "lastEventId", "last-event-id"],
  ["packages/agent-sdk/src/substrate-client.ts", "packages/runtime-daemon/src/index.mjs"],
  "daemon event stream cannot parse SSE or resume by cursor",
);
assertText(
  "B3",
  "live local daemon service",
  localDaemon,
  [
    "startRuntimeDaemonService",
    "AgentgresRuntimeStateStore",
    "/v1/agents",
    "/v1/runs",
    "operation-log.jsonl",
  ],
  ["packages/runtime-daemon/src/index.mjs"],
  "local daemon service is not implemented as a reusable long-running public API",
);

assertText(
  "C1",
  "SDK live bridge default",
  sdkSubstrate,
  ["class DaemonRuntimeSubstrateClient", "createRuntimeSubstrateClient", "external_blocker"],
  ["packages/agent-sdk/src/substrate-client.ts"],
  "SDK default is not daemon-backed and fail-closed",
);
assertText(
  "C2",
  "SDK public live surface",
  `${sdkAgent}\n${sdkSubstrate}\n${sdkMessages}`,
  ["AgentSubagent", "listRuntimeNodes", "RuntimeToolCatalogEntry", "RuntimeAccountProfile"],
  [
    "packages/agent-sdk/src/agent.ts",
    "packages/agent-sdk/src/substrate-client.ts",
    "packages/agent-sdk/src/messages.ts",
  ],
  "SDK does not expose account/runtime/tool/subagent surface",
);
assertLane(
  "C3",
  "SDK mock boundary",
  !/\bcreateMockRuntimeSubstrateClient\b/.test(sdkIndex) &&
    sdkSubstrate.includes("explicitMockFactory") &&
    fs.existsSync(path.join(root, "packages/agent-sdk/src/testing.ts")),
  ["packages/agent-sdk/src/index.ts", "packages/agent-sdk/src/testing.ts"],
  "mock runtime client leaked into canonical SDK exports",
);

assertText(
  "D1",
  "event golden behavior",
  sdkTests,
  ["text/event-stream", "lastEventId", "run_http%3A0"],
  ["packages/agent-sdk/test/sdk.test.mjs"],
  "event stream tests do not prove SSE cursor resume",
);

assertText(
  "E1",
  "tool catalog contract",
  `${sdkSubstrate}\n${sdkMessages}`,
  ["listTools", "primitiveCapabilities", "authorityScopeRequirements", "RuntimeToolCatalogEntry"],
  ["packages/agent-sdk/src/substrate-client.ts", "packages/agent-sdk/src/messages.ts"],
  "SDK lacks governed runtime tool catalog surface",
);

assertText(
  "F1",
  "MCP skills hooks provenance",
  sdkSubstrate,
  ["loadCursorCompatibilityConfig", "mcpServers", "hookNames", "skillNames"],
  ["packages/agent-sdk/src/substrate-client.ts"],
  "SDK does not import cursor MCP/skills/hooks into substrate summaries",
);

assertText(
  "G1",
  "subagent execution surface",
  `${sdkAgent}\n${sdkTests}`,
  ["AgentSubagent", "agents.reviewer", "handoff_quality"],
  ["packages/agent-sdk/src/agent.ts", "packages/agent-sdk/test/sdk.test.mjs"],
  "SDK subagent map is not behaviorally exercised",
);

assertText(
  "H1",
  "runtime catalogs",
  `${sdkSubstrate}\n${sdkAgent}\n${sdkTests}`,
  ["listModels", "listRepositories", "getAccount", "listRuntimeNodes"],
  ["packages/agent-sdk/src/substrate-client.ts", "packages/agent-sdk/test/sdk.test.mjs"],
  "model/repository/account/runtime node catalogs are not exposed",
);

assertText(
  "I1",
  "canonical persistence boundary",
  `${guide}\n${sdkSubstrate}\n${localDaemon}`,
  ["Agentgres", "non-authoritative", "agent-sdk-mock", "schemaVersion", "ioi.agentgres.runtime.v0"],
  [
    "docs/plans/architectural-improvements-broad-master-guide.md",
    "packages/agent-sdk/src/substrate-client.ts",
    "packages/runtime-daemon/src/index.mjs",
  ],
  "SDK checkpoint projection is not clearly non-canonical relative to Agentgres",
);
assertText(
  "I2",
  "Agentgres canonical live proof",
  `${localDaemon}\n${broadEvidence}`,
  [
    "daemon_backed_canonical_operation_log",
    "agentgres_canonical_operation_log",
    "cross-surface-compatibility-report.json",
    "canonical_live",
  ],
  ["packages/runtime-daemon/src/index.mjs", "scripts/evidence/runtime-complete-plus.mjs"],
  "Agentgres evidence still looks projection-only instead of daemon-backed canonical replay",
);

assertText(
  "J1",
  "CLI remains client",
  read("crates/cli/src/commands/agent.rs"),
  ["struct CliAgentRuntimeClient", "submit_runtime_call", "CLI command handlers are clients"],
  ["crates/cli/src/commands/agent.rs"],
  "CLI agent command owns runtime semantics instead of client helper",
);

assertText(
  "K1",
  "hosted/self-hosted provider shape",
  sdkOptions,
  ["HostedWorkerProvider", "SelfHostedWorkerProvider", "SelfHostedWorkerOptions"],
  ["packages/agent-sdk/src/options.ts"],
  "hosted/self-hosted provider contracts are absent from SDK surface",
);

assertLane(
  "L1",
  "GUI and workflow substrate guardrails",
  workflowController.includes("Proposal blocked by runtime substrate") &&
    workflowController.includes("Run blocked by runtime substrate"),
  ["packages/agent-ide/src/WorkflowComposer/controller.tsx"],
  "workflow compositor can still fabricate durable truth after substrate adapter failure",
);

assertText(
  "M1",
  "smarter-agent behavioral projections",
  sdkMessages,
  [
    "TaskStateProjection",
    "UncertaintyProjection",
    "ProbeProjection",
    "PostconditionProjection",
    "SemanticImpactProjection",
    "StopConditionProjection",
    "AgentQualityLedgerProjection",
  ],
  ["packages/agent-sdk/src/messages.ts"],
  "smarter-agent records are not represented in public trace bundles",
);

assertLane(
  "Z1",
  "public vocabulary and retired product names",
  developerDocs.includes("@ioi/agent-sdk") &&
    !developerDocs.includes("ioi-swarm") &&
    !chatTypes.includes('alias = "swarm"'),
  ["apps/developers-ioi-ai/src/content/docs.tsx", "crates/types/src/app/chat.rs"],
  "retired swarm/SDK compatibility naming remains in active public surface",
);

const requiredScripts = [
  "check:execution-surface-leg",
  "test:daemon-runtime-api",
  "test:sdk-live-daemon",
  "test:runtime-events",
  "test:mcp-skills-hooks",
  "test:subagents",
  "test:agentgres-runtime-state",
  "test:workflow-compositor-dogfood",
  "test:hosted-workers",
  "validate:runtime-complete-plus",
  "evidence:runtime-complete-plus",
];
assertLane(
  "Z2",
  "repeatable validation commands",
  requiredScripts.every((scriptName) => Object.hasOwn(packageJson.scripts, scriptName)),
  ["package.json"],
  "master-guide validation commands are not registered",
);

const evidenceDir = path.join(root, "docs/evidence/architectural-improvements-broad");
fs.mkdirSync(evidenceDir, { recursive: true });
const completeCount = checklist.filter((item) => item.status === "Complete").length;
const report = {
  schemaVersion: "ioi.architectural-improvements-broad.check.v1",
  generatedAt: new Date().toISOString(),
  status: failures.length === 0 ? "passed" : "failed",
  completeCount,
  itemCount: checklist.length,
  checklist,
  failures,
};
fs.writeFileSync(path.join(evidenceDir, "checklist.json"), `${JSON.stringify(report, null, 2)}\n`);
fs.writeFileSync(
  path.join(evidenceDir, "checklist.md"),
  [
    "# Architectural Improvements Broad Checklist",
    "",
    `Status: ${report.status}`,
    `Complete: ${completeCount}/${checklist.length}`,
    "",
    "| ID | Lane | Status | Evidence |",
    "| --- | --- | --- | --- |",
    ...checklist.map((item) => `| ${item.id} | ${item.lane} | ${item.status} | ${item.evidence.join("<br>")} |`),
    "",
  ].join("\n"),
);

if (failures.length > 0) {
  console.error("Execution surface leg check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Execution surface leg check passed.");
console.log(`Evidence: ${path.relative(root, path.join(evidenceDir, "checklist.json"))}`);
