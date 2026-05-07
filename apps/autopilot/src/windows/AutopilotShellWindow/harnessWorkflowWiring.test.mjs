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
const workflowComposer = [
  "../../../../../packages/agent-ide/src/WorkflowComposer.tsx",
  "../../../../../packages/agent-ide/src/WorkflowComposer/content.tsx",
  "../../../../../packages/agent-ide/src/WorkflowComposer/support.tsx",
  "../../../../../packages/agent-ide/src/WorkflowComposer/controller.tsx",
  "../../../../../packages/agent-ide/src/WorkflowComposer/view.tsx",
]
  .map((path) => fs.readFileSync(new URL(path, import.meta.url), "utf8"))
  .join("\n");
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
  /(?=[\s\S]*WorkflowHarnessExecutionMode)(?=[\s\S]*WorkflowHarnessComponentReadiness)(?=[\s\S]*WorkflowHarnessReplayEnvelope)(?=[\s\S]*WorkflowHarnessGroupView)(?=[\s\S]*WorkflowHarnessPromotionCluster)(?=[\s\S]*WorkflowHarnessGatedClusterRun)(?=[\s\S]*WorkflowHarnessLiveHandoffProof)(?=[\s\S]*WorkflowHarnessRuntimeSelectorDecision)(?=[\s\S]*WorkflowHarnessCanaryExecutionBoundary)(?=[\s\S]*canaryExecutionBoundaries)(?=[\s\S]*WorkflowHarnessComponentSpec[\s\S]*readiness[\s\S]*inputSchema[\s\S]*outputSchema[\s\S]*errorSchema)(?=[\s\S]*WorkflowHarnessWorkerBinding[\s\S]*harnessWorkflowId[\s\S]*harnessActivationId[\s\S]*harnessHash)/,
  "Harness contracts should declare mode, readiness, replay, collapsible group views, promotion clusters, live handoff, selector routing, canary execution boundaries, schemas, errors, and worker harness identity.",
);

assert.match(
  harnessWorkflow,
  /DEFAULT_HARNESS_EXECUTION_MODE[\s\S]*HARNESS_PROMOTION_CLUSTER_COMPONENTS[\s\S]*cognition[\s\S]*DEFAULT_AGENT_HARNESS_COMPONENTS[\s\S]*kind: "planner"[\s\S]*kind: "prompt_assembler"[\s\S]*kind: "mcp_provider"[\s\S]*kind: "mcp_tool_call"[\s\S]*kind: "receipt_writer"[\s\S]*defaultHarnessPromotionClusters[\s\S]*requiredExecutionMode: "gated"[\s\S]*makeDefaultAgentHarnessWorkflow[\s\S]*readOnly: true/,
  "Default Agent Harness should project runtime kernels and gated promotion clusters as read-only workflow components.",
);

assert.match(
  harnessWorkflow,
  /forkDefaultAgentHarnessWorkflow[\s\S]*proposal-\$\{slug\}-activation-gates[\s\S]*forkedFrom[\s\S]*activationState: "blocked"[\s\S]*activationRecord/,
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
  workflowComposer,
  /(?=[\s\S]*harnessGroupViews)(?=[\s\S]*selectedHarnessGroup)(?=[\s\S]*handleInspectHarnessGroupNode)(?=[\s\S]*collapsedHarnessGroupByNodeId)(?=[\s\S]*collapsedGroupEdge)(?=[\s\S]*workflow-harness-group-controls)(?=[\s\S]*workflow-harness-collapse-groups)(?=[\s\S]*workflow-harness-expand-groups)(?=[\s\S]*HARNESS_WORKBENCH_DEEP_LINK_PREFIX)(?=[\s\S]*encodeHarnessWorkbenchDeepLink)(?=[\s\S]*parseHarnessWorkbenchDeepLink)(?=[\s\S]*applyHarnessWorkbenchDeepLink)(?=[\s\S]*window\.history\.replaceState)(?=[\s\S]*navigator\.clipboard)(?=[\s\S]*selectedHarnessReceiptRef)(?=[\s\S]*selectedHarnessReplayFixtureRef)/,
  "Workflow composer should collapse, expand, select, inspect, deep-link, restore, and copy harness promotion cluster state without mutating the saved component graph.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-settings-harness-summary)(?=[\s\S]*Mode)(?=[\s\S]*Live-ready)(?=[\s\S]*Gated clusters)(?=[\s\S]*workflow-harness-slots)(?=[\s\S]*workflow-harness-promotion-clusters)(?=[\s\S]*workflow-harness-canary-execution-boundaries)(?=[\s\S]*workflow-harness-canary-execution-boundary)(?=[\s\S]*workflow-harness-default-runtime-dispatch)(?=[\s\S]*workflow-harness-read-only-routing-proof)(?=[\s\S]*workflow-harness-read-only-routing-node-kinds)(?=[\s\S]*workflow-harness-read-only-routing-receipts)(?=[\s\S]*workflow-harness-deep-link-state)(?=[\s\S]*workflow-copy-harness-deep-link)(?=[\s\S]*workflow-harness-group-inspector)(?=[\s\S]*workflow-harness-group-components)(?=[\s\S]*workflow-harness-group-receipt-refs)(?=[\s\S]*workflow-harness-group-receipt-ref-)(?=[\s\S]*workflow-harness-group-replay-fixtures)(?=[\s\S]*workflow-harness-group-replay-ref-)(?=[\s\S]*workflow-harness-group-shadow-comparison)(?=[\s\S]*workflow-run-harness-timeline)(?=[\s\S]*workflow-run-harness-shadow-comparison)(?=[\s\S]*workflow-selected-node-harness-component)(?=[\s\S]*workflow-selected-node-harness-receipts)(?=[\s\S]*workflow-selected-node-replay-binding)(?=[\s\S]*workflow-selected-node-harness-attempt)(?=[\s\S]*workflow-selected-node-read-only-routing-proof)(?=[\s\S]*workflow-selected-node-read-only-routing-receipts)(?=[\s\S]*workflow-selected-node-read-only-routing-no-mutation)(?=[\s\S]*replayEnvelope)/,
  "Rail inspection should render mode, readiness, component ids, slots, promotion clusters, deep-link controls, group inspectors, canary execution boundaries, default dispatch, read-only routing proof, receipt events, replay metadata, attempts, no-mutation proof, and shadow comparison.",
);

assert.match(
  tauriProjectTypes,
  /(?=[\s\S]*WorkflowNodeRun[\s\S]*pub harness_attempt: Option<Value>)(?=[\s\S]*WorkflowRunResult[\s\S]*pub harness_attempts: Vec<Value>[\s\S]*pub harness_shadow_comparisons: Vec<Value>[\s\S]*pub harness_gated_cluster_runs: Vec<Value>)(?=[\s\S]*WorkflowPortablePackageManifest[\s\S]*pub harness: Option<Value>[\s\S]*pub worker_harness_binding: Option<Value>)/,
  "Portable packages and run records should preserve harness metadata, worker binding identity, node attempts, shadow comparisons, and gated cluster runs.",
);

assert.match(
  localEngineSupport,
  /harness_workflow_id: Some\([\s\S]*DEFAULT_AGENT_HARNESS_WORKFLOW_ID[\s\S]*harness_activation_id: Some\([\s\S]*DEFAULT_AGENT_HARNESS_ACTIVATION_ID[\s\S]*harness_hash: Some\([\s\S]*DEFAULT_AGENT_HARNESS_HASH/,
  "Worker workflow records should point at the blessed default harness identity.",
);

console.log("harnessWorkflowWiring.test.mjs: ok");
