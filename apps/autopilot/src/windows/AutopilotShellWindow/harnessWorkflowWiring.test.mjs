import assert from "node:assert/strict";
import fs from "node:fs";

const graphTypes = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/types/graph.ts",
    import.meta.url,
  ),
  "utf8",
);
const harnessWorkflow = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/harness-workflow.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowComposer = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/WorkflowComposer.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowRailPanel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/features/Workflows/WorkflowRailPanel.tsx",
    import.meta.url,
  ),
  "utf8",
);
const workflowValidation = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-validation.ts",
    import.meta.url,
  ),
  "utf8",
);
const tauriProjectTypes = fs.readFileSync(
  new URL(
    "../../../src-tauri/src/project/types.rs",
    import.meta.url,
  ),
  "utf8",
);
const localEngineSupport = fs.readFileSync(
  new URL(
    "../../../src-tauri/src/kernel/data/commands/local_engine_support.rs",
    import.meta.url,
  ),
  "utf8",
);

assert.match(
  graphTypes,
  /WorkflowHarnessComponentSpec[\s\S]*inputSchema[\s\S]*outputSchema[\s\S]*errorSchema[\s\S]*WorkflowHarnessWorkerBinding[\s\S]*harnessWorkflowId[\s\S]*harnessActivationId[\s\S]*harnessHash/,
  "Harness contracts should declare schemas, errors, and worker harness identity.",
);

assert.match(
  harnessWorkflow,
  /DEFAULT_AGENT_HARNESS_COMPONENTS[\s\S]*kind: "planner"[\s\S]*kind: "mcp_provider"[\s\S]*kind: "mcp_tool_call"[\s\S]*kind: "receipt_writer"[\s\S]*makeDefaultAgentHarnessWorkflow[\s\S]*readOnly: true/,
  "Default Agent Harness should project runtime kernels as read-only workflow components.",
);

assert.match(
  harnessWorkflow,
  /forkDefaultAgentHarnessWorkflow[\s\S]*forkedFrom[\s\S]*activationState: "blocked"[\s\S]*proposal-[\s\S]*activation-gates/,
  "Default Agent Harness forks should carry lineage, package metadata, tests, and activation blockers.",
);

assert.match(
  workflowValidation,
  /(?=[\s\S]*workflowIsHarnessFork)(?=[\s\S]*harness_required_slot_unbound)(?=[\s\S]*harness_activation_not_validated)(?=[\s\S]*harness_self_mutation_not_proposal_only)/,
  "Harness readiness should block unvalidated forks and direct AI-authored self-mutation.",
);

assert.match(
  workflowComposer,
  /(?=[\s\S]*workflow-open-default-harness)(?=[\s\S]*handleOpenDefaultHarness)(?=[\s\S]*workflow-fork-harness-button)(?=[\s\S]*handleForkDefaultHarness)(?=[\s\S]*workflow-readonly-badge)(?=[\s\S]*workflow-harness-worker-binding)/,
  "Workflow composer should expose read-only harness inspection and a fork path.",
);

assert.match(
  workflowRailPanel,
  /workflow-settings-harness-summary[\s\S]*workflow-harness-slots[\s\S]*workflow-selected-node-harness-component[\s\S]*workflow-selected-node-harness-receipts[\s\S]*workflow-selected-node-replay-binding/,
  "Rail inspection should render component ids, slots, receipt events, and replay metadata.",
);

assert.match(
  tauriProjectTypes,
  /WorkflowPortablePackageManifest[\s\S]*pub harness: Option<Value>[\s\S]*pub worker_harness_binding: Option<Value>/,
  "Portable packages should preserve harness metadata and worker binding identity.",
);

assert.match(
  localEngineSupport,
  /harness_workflow_id: Some\([\s\S]*DEFAULT_AGENT_HARNESS_WORKFLOW_ID[\s\S]*harness_activation_id: Some\([\s\S]*DEFAULT_AGENT_HARNESS_ACTIVATION_ID[\s\S]*harness_hash: Some\([\s\S]*DEFAULT_AGENT_HARNESS_HASH/,
  "Worker workflow records should point at the blessed default harness identity.",
);

console.log("harnessWorkflowWiring.test.mjs: ok");
