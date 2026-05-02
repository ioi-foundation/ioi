#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function assert(condition, message) {
  if (!condition) failures.push(message);
}

function allFiles(dir, predicate = () => true) {
  const absolute = path.join(root, dir);
  if (!fs.existsSync(absolute)) return [];
  const entries = fs.readdirSync(absolute, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const relative = path.join(dir, entry.name);
    if (entry.isDirectory()) return allFiles(relative, predicate);
    return predicate(relative) ? [relative] : [];
  });
}

const runtimeContracts = read("crates/types/src/app/runtime_contracts.rs");
assert(
  runtimeContracts.includes("primitive_capabilities: Vec<String>"),
  "RuntimeToolContract must expose primitive_capabilities.",
);
assert(
  runtimeContracts.includes("authority_scope_requirements: Vec<String>"),
  "RuntimeToolContract must expose authority_scope_requirements.",
);
assert(
  !runtimeContracts.includes("capability_lease_requirements") &&
    !runtimeContracts.includes("legacy_capability_projection"),
  "RuntimeToolContract must not retain the old flattened capability lease projection.",
);

const toolContracts = read("crates/services/src/agentic/runtime/tools/contracts.rs");
assert(
  toolContracts.includes("primitive_capabilities_for") &&
    toolContracts.includes("authority_scopes_for") &&
    toolContracts.includes("scope:host.controlled_execution"),
  "Tool contracts must derive primitive capabilities separately from authority scopes.",
);

const sdkSubstrate = read("packages/agent-sdk/src/substrate-client.ts");
assert(
  sdkSubstrate.includes("class DaemonRuntimeSubstrateClient"),
  "Agent SDK default client must be daemon/substrate backed.",
);
assert(
  sdkSubstrate.includes("createMockRuntimeSubstrateClient") &&
    sdkSubstrate.includes("class MockRuntimeSubstrateClient"),
  "Agent SDK mock projection client must be explicit.",
);
assert(
  /createRuntimeSubstrateClient[\s\S]*?return new DaemonRuntimeSubstrateClient/.test(sdkSubstrate),
  "createRuntimeSubstrateClient must not default to the mock projection client.",
);
assert(
  sdkSubstrate.includes("fetch(url") &&
    sdkSubstrate.includes("/v1/agents") &&
    sdkSubstrate.includes("/v1/runs") &&
    !/return this\.unavailable\(/.test(sdkSubstrate),
  "DaemonRuntimeSubstrateClient must implement the public substrate transport instead of method stubs.",
);
assert(
  !sdkSubstrate.includes("LocalRuntimeSubstrateClient"),
  "Agent SDK must not expose the former LocalRuntimeSubstrateClient naming.",
);

const sdkIndex = read("packages/agent-sdk/src/index.ts");
assert(
  !/\bMockRuntimeSubstrateClient\b/.test(sdkIndex) &&
    !/\bLocalRuntimeSubstrateClient\b/.test(sdkIndex) &&
    !/\bcreateMockRuntimeSubstrateClient\b/.test(sdkIndex),
  "Agent SDK root exports must not expose mock/local clients as canonical runtime classes.",
);
assert(
  sdkIndex.includes("primitiveCapabilities") && sdkIndex.includes("authorityScopeRequirements"),
  "Agent SDK RuntimeToolContract type must expose primitiveCapabilities and authorityScopeRequirements.",
);
const sdkTesting = read("packages/agent-sdk/src/testing.ts");
assert(
  sdkTesting.includes("createMockRuntimeSubstrateClient"),
  "Agent SDK mock projection client must live behind the explicit testing subpath.",
);

const tsSubstrate = read("packages/agent-ide/src/runtime/runtime-projection-adapter.ts");
const rustSubstrate = read("apps/autopilot/src-tauri/src/runtime_projection.rs");
const actionSchema = readJson("docs/implementation/runtime-action-schema.json");
const generatedTsActionSchema = read("packages/agent-ide/src/runtime/generated/action-schema.ts");
const generatedRustActionSchema = read(
  "apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs",
);
for (const nodeKind of actionSchema.actionKinds) {
  assert(
    generatedTsActionSchema.includes(`"${nodeKind}"`),
    `Generated TypeScript action schema missing ${nodeKind}.`,
  );
  assert(
    generatedRustActionSchema.includes(`"${nodeKind}"`),
    `Generated Rust action schema missing ${nodeKind}.`,
  );
  assert(tsSubstrate.includes(`"${nodeKind}"`), `Agent IDE action schema missing ${nodeKind}.`);
  const rustActiveEvidence =
    nodeKind === "source_input"
      ? rustSubstrate.includes("SourceInput")
      : nodeKind === "adapter_connector"
        ? rustSubstrate.includes("AdapterConnector")
        : rustSubstrate.includes(`"${nodeKind}"`);
  assert(rustActiveEvidence, `Autopilot Rust action schema missing ${nodeKind}.`);
}
assert(
  generatedTsActionSchema.includes(actionSchema.schemaVersion) &&
    generatedRustActionSchema.includes(actionSchema.schemaVersion),
  "Generated runtime action contracts must carry the shared schema version.",
);

const workflowComposer = read("packages/agent-ide/src/runtime/workflow-composer-model.ts");
const workflowController = read("packages/agent-ide/src/WorkflowComposer/controller.tsx");
assert(
  workflowComposer.includes("non-canonical") &&
    workflowComposer.includes("createSubstrateProjectionProposal") &&
    workflowComposer.includes("createSubstrateProjectionRunSummary") &&
    workflowComposer.includes("createSubstrateProjectionTestResult"),
  "Agent IDE fallback helpers must be named and documented as non-canonical substrate projections.",
);
assert(
  !workflowComposer.includes("createLocalProposal") &&
    !workflowComposer.includes("createLocalRunSummary") &&
    !workflowComposer.includes("createLocalTestResult"),
  "Agent IDE must not keep local helper names that imply canonical runtime ownership.",
);
assert(
  !workflowController.includes("} catch {\n          const proposal = createSubstrateProjectionProposal") &&
    !workflowController.includes("} catch (error) {\n        const proposal = createSubstrateProjectionProposal") &&
    workflowController.includes("Proposal blocked by runtime substrate") &&
    workflowController.includes("Run blocked by runtime substrate"),
  "Agent IDE must not create local durable proposal/run projections when a runtime adapter exists but fails.",
);

const cliAgent = read("crates/cli/src/commands/agent.rs");
const desktopAgentLiteralCount = (cliAgent.match(/"desktop_agent"/g) ?? []).length;
assert(
  desktopAgentLiteralCount === 1 && cliAgent.includes("DESKTOP_AGENT_SERVICE_ID"),
  "CLI desktop_agent service id must be centralized.",
);
assert(
  cliAgent.includes("CLI command handlers are clients of this service"),
  "CLI agent command must document client-vs-daemon ownership.",
);
assert(
  cliAgent.includes("struct CliAgentRuntimeClient") &&
    cliAgent.includes("submit_runtime_call") &&
    (cliAgent.match(/PublicApiClient::new/g) ?? []).length <= 2 &&
    cliAgent.includes("async fn fetch_runtime_snapshot"),
  "CLI agent commands must route daemon service submission through one runtime client helper while snapshot queries stay read-only.",
);
const servicesIntent = read("crates/services/src/agentic/intent.rs");
assert(
  (servicesIntent.match(/"desktop_agent"/g) ?? []).length === 1 &&
    servicesIntent.includes("DESKTOP_AGENT_SERVICE_ID"),
  "Service intent helpers must centralize the desktop_agent service id.",
);

const boundaryDoc = read("docs/implementation/runtime-package-boundaries.md");
for (const required of [
  "ioi-daemon",
  "@ioi/agent-sdk",
  "@ioi/agent-ide",
  "Agentgres",
  "wallet.network",
  "Primitive execution capabilities",
  "Authority scopes",
  "Adaptive Work Graph",
]) {
  assert(boundaryDoc.includes(required), `Runtime package boundary doc missing ${required}.`);
}

const circ = read("docs/conformance/agentic-runtime/CIRC.md");
assert(
  circ.includes("prim:sys.exec") && circ.includes("scope:*"),
  "CIRC must keep primitive capabilities separate from authority scopes.",
);

const connectorDoc = read("docs/architecture/components/connectors-tools/doctrine.md");
assert(
  connectorDoc.includes("primitive_capabilities") &&
    connectorDoc.includes("authority_scope_required") &&
    !connectorDoc.includes("capability_lease_requirements"),
  "Connector/tool architecture doc must show split primitive and authority scope fields without the old flattened projection.",
);

const daemonDoc = read("docs/architecture/components/daemon-runtime/doctrine.md");
assert(
  daemonDoc.includes("The IOI CLI is a terminal/TUI client") &&
    /must not own a separate agent\s+runtime/.test(daemonDoc),
  "Daemon architecture doc must distinguish daemon execution from CLI client behavior.",
);

const workGraphPlan = read("docs/plans/adaptive-scoped-swarm-execution-plan.md");
assert(
  workGraphPlan.includes("`swarm` is an execution strategy, not a product surface") ||
    workGraphPlan.includes("adaptive work graph is an execution strategy"),
  "Adaptive work graph plan must keep the execution strategy separate from product/runtime surfaces.",
);
assert(
  !read("crates/types/src/app/chat.rs").includes('alias = "swarm"'),
  "Chat execution strategy must not retain the old swarm wire alias.",
);
const developerDocs = read("apps/developers-ioi-ai/src/content/docs.tsx");
assert(
  developerDocs.includes("@ioi/agent-sdk") && !developerDocs.includes("ioi-swarm"),
  "Developer docs must route SDK-first agent development to @ioi/agent-sdk, not the retired ioi-swarm product surface.",
);
const preLegChecklist = read("docs/plans/pre-next-leg-cleanup-checklist.md");
assert(
  !preLegChecklist.includes("Follow-On Debt") &&
    preLegChecklist.includes("Status: pre-leg ready") &&
    preLegChecklist.includes("daemon-backed") &&
    preLegChecklist.includes("runtime-layout checks"),
  "Pre-next-leg checklist must not leave guardrail-only follow-on debt.",
);

const workflowValidation = read("packages/agent-ide/src/runtime/workflow-validation.ts");
assert(
  workflowValidation.includes("mock_binding_active") &&
    workflowValidation.includes("Switch to live credentials before activation"),
  "Workflow validation must block explicit mock bindings when production readiness requires it.",
);

for (const productFile of allFiles("packages/agent-ide/src", (file) => /\.(ts|tsx)$/.test(file)).concat(
  allFiles("packages/agent-sdk/src", (file) => /\.(ts|tsx)$/.test(file)),
)) {
  const content = read(productFile);
  assert(!/\bCIRC\b|\bCEC\b/.test(content), `${productFile} leaks hidden CIRC/CEC vocabulary.`);
}

if (failures.length > 0) {
  console.error("Pre-next-leg readiness failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Pre-next-leg readiness passed.");
