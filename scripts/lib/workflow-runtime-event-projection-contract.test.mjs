import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

test("React Flow runtime event projection consumes canonical Thread.events shape", () => {
  const projection = read(
    "packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts",
  );
  const exports = read("packages/agent-ide/src/index.ts");
  const typeTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-event-projection.test.ts",
  );
  const controlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts",
  );
  const usageControlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-usage-control-nodes.ts",
  );
  const contextBudgetControlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.ts",
  );
  const codingToolControlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.ts",
  );
  const codingToolBudgetRecoveryPolicy = read(
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-budget-recovery-policy.ts",
  );
  const codingToolBudgetRecoveryBinding = read(
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-budget-recovery-binding.ts",
  );
  const telemetryBudgetChainSubflow = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.ts",
  );
  const telemetryBudgetChainMaterialization = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.ts",
  );
  const telemetryBudgetChainMaterializationTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.test.ts",
  );
  const telemetryBudgetChainCreatorGuiProbe = read(
    "scripts/lib/workflow-telemetry-budget-chain-creator-gui-probe.mjs",
  );
  const telemetryBudgetChainRunInspectorProbe = read(
    "scripts/lib/workflow-telemetry-budget-chain-run-inspector-probe.mjs",
  );
  const terminalCodingLoopSubflow = read(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-subflow.ts",
  );
  const terminalCodingLoopMaterialization = read(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-materialization.ts",
  );
  const terminalCodingLoopExecution = read(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-execution.ts",
  );
  const terminalCodingLoopRunLaunch = read(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.ts",
  );
  const terminalCodingLoopSubflowTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-subflow.test.ts",
  );
  const terminalCodingLoopMaterializationTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-materialization.test.ts",
  );
  const terminalCodingLoopExecutionTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-execution.test.ts",
  );
  const terminalCodingLoopRunLaunchTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.test.ts",
  );
  const terminalCodingLoopRunActivation = read(
    "packages/agent-ide/src/WorkflowComposer/terminalCodingLoopRunActivation.ts",
  );
  const terminalCodingLoopRunActivationTest = read(
    "packages/agent-ide/src/WorkflowComposer/terminalCodingLoopRunActivation.test.ts",
  );
  const terminalCodingLoopCreatorGuiProbe = read(
    "scripts/lib/workflow-terminal-coding-loop-creator-gui-probe.mjs",
  );
  const terminalCodingLoopRunInspectorProbe = read(
    "scripts/lib/workflow-terminal-coding-loop-run-inspector-probe.mjs",
  );
  const terminalCodingLoopRunButtonProbe = read(
    "scripts/lib/workflow-terminal-coding-loop-run-button-gui-probe.mjs",
  );
  const sandboxedComputerRunButtonProbe = read(
    "scripts/lib/workflow-sandboxed-computer-run-button-gui-probe.mjs",
  );
  const nativeBrowserPromptPipelineProbe = read(
    "scripts/lib/workflow-native-browser-prompt-pipeline-gui-probe.mjs",
  );
  const visualGuiPromptPipelineProbe = read(
    "scripts/lib/workflow-visual-gui-prompt-pipeline-gui-probe.mjs",
  );
  const computerUseTriLaneScorecardTest = read(
    "scripts/lib/workflow-computer-use-tri-lane-scorecard.test.mjs",
  );
  const telemetryBudgetChainRuntimeSubflowInsertion = read(
    "packages/agent-ide/src/WorkflowComposer/runtimeSubflowInsertion.ts",
  );
  const guiHarnessContract = read(
    "scripts/lib/autopilot-gui-harness-contract.mjs",
  );
  const guiHarnessValidation = read(
    "scripts/lib/autopilot-gui-harness-validation/core.mjs",
  );
  const liveRuntimeDaemonContract = read(
    "scripts/lib/live-runtime-daemon-contract.test.mjs",
  );
  const compactionPolicyControlNodes = read(
    "packages/agent-ide/src/runtime/workflow-runtime-compaction-policy-control-nodes.ts",
  );
  const controlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-control-nodes.test.ts",
  );
  const usageControlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-usage-control-nodes.test.ts",
  );
  const contextBudgetControlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.test.ts",
  );
  const codingToolControlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.test.ts",
  );
  const compactionPolicyControlNodesTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-compaction-policy-control-nodes.test.ts",
  );
  const runHistoryModel = read(
    "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
  );
  const telemetrySummary = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-summary.ts",
  );
  const telemetrySourceBinding = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.ts",
  );
  const telemetrySummaryTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-summary.test.ts",
  );
  const telemetrySourceBindingTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.test.ts",
  );
  const runHistoryModelTest = read(
    "packages/agent-ide/src/runtime/workflow-run-history-model.test.ts",
  );
  const readinessModel = read(
    "packages/agent-ide/src/runtime/workflow-readiness-model.ts",
  );
  const readinessModelTest = read(
    "packages/agent-ide/src/runtime/workflow-readiness-model.test.ts",
  );
  const codingToolBudgetRecoveryBindingTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-budget-recovery-binding.test.ts",
  );
  const telemetryBudgetChainSubflowTest = read(
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.test.ts",
  );
  const workflowValidation = read(
    "packages/agent-ide/src/runtime/workflow-validation.ts",
  );
  const readinessPanel = read(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx",
  );
  const runsPanel = read(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
  );
  const railPanel = read(
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx",
  );
  const composerController = read(
    "packages/agent-ide/src/WorkflowComposer/controller.tsx",
  );
  const composerView = read("packages/agent-ide/src/WorkflowComposer/view.tsx");
  const composerSupport = read(
    "packages/agent-ide/src/WorkflowComposer/support.tsx",
  );
  const graphRuntimeTypes = read(
    "packages/agent-ide/src/runtime/graph-runtime-types.ts",
  );
  const tauriRuntime = read("apps/autopilot/src/services/TauriRuntime.ts");

  assert.match(
    projection,
    /ioi\.workflow\.runtime-event-projection\.v1/,
  );
  assert.match(projection, /WorkflowRuntimeThreadEventLike/);
  for (const field of [
    "cursor",
    "seq",
    "threadId",
    "turnId",
    "eventKind",
    "sourceEventKind",
    "componentKind",
    "workflowNodeId",
    "workflowGraphId",
    "payloadSchemaVersion",
    "receiptRefs",
    "artifactRefs",
    "policyDecisionRefs",
    "rollbackRefs",
  ]) {
    assert.match(projection, new RegExp(`${field}:`));
  }
  for (const eventType of [
    "thread_forked",
    "reasoning_delta",
    "tool_completed",
    "tool_failed",
    "turn_interrupted",
    "turn_steered",
    "context_compacted",
    "approval_required",
    "compaction_policy_evaluated",
    "policy_blocked",
    "receipt_emitted",
    "model_route_decision",
    "tool_route_decision",
  ]) {
    assert.match(projection, new RegExp(`"${eventType}"`));
  }
  assert.match(projection, /projectRuntimeThreadEventsToWorkflowProjection/);
  assert.match(projection, /projectRuntimeThreadEventsToWorkflowNodes/);
  assert.match(projection, /reactFlowNodes/);
  assert.match(projection, /reactFlowEdges/);
  assert.match(projection, /runtimeEventProjection/);
  assert.match(projection, /runtimeEventTransition/);
  assert.match(projection, /WorkflowRuntimeSubagentChildSubflowDescriptor/);
  assert.match(projection, /subagentChildSubflowReactFlowNodes/);
  assert.match(projection, /subagentBudgetStatus/);
  assert.match(projection, /subagentCostEstimateUsd/);
  assert.match(projection, /subagentTokenEstimate/);
  assert.match(projection, /usage_status/);
  assert.match(projection, /usageTotalTokens/);
  assert.match(projection, /usageCostEstimateUsd/);
  assert.match(projection, /coding_tool/);
  assert.match(projection, /codingToolRowCount/);
  assert.match(projection, /coding_tool_budget/);
  assert.match(projection, /codingToolBudgetRowCount/);
  assert.match(projection, /codingToolBudgetStatus/);
  assert.match(projection, /codingToolBudgetViolationCount/);
  assert.match(projection, /codingToolMutationBlocked/);
  assert.match(projection, /codingToolBudgetRecoveryActions/);
  assert.match(projection, /recoveryPolicy/);
  assert.match(projection, /WorkflowRunCodingToolBudgetApprovedRetry/);
  assert.match(projection, /ioi\.workflow\.coding-tool-budget-recovery\.v1/);
  assert.match(projection, /ioi\.workflow\.computer-use-projection\.v1/);
  assert.match(projection, /WorkflowRuntimeComputerUseProjection/);
  assert.match(projection, /computerUseProjectionForRuntimeThreadEvent/);
  for (const computerUseField of [
    "computerUse",
    "computer_use_step",
    "computer_use_lane",
    "computer_use_session_mode",
    "computer_use_lease_id",
    "computer_use_observation_ref",
    "computer_use_target_index_ref",
    "computer_use_affordance_graph_ref",
    "computer_use_browser_discovery_ref",
    "computer_use_proposal_ref",
    "computer_use_action_ref",
    "computer_use_verification_ref",
    "computer_use_trajectory_ref",
    "computer_use_cleanup_ref",
    "computer_use_blocker",
    "computer_use_execution_result",
    "executionProviderId",
    "executionRequiresReobserve",
  ]) {
    assert.match(projection, new RegExp(computerUseField));
  }
  assert.match(
    codingToolBudgetRecoveryPolicy,
    /ioi\.workflow\.coding-tool-budget-recovery-policy\.v1/,
  );
  assert.match(
    codingToolBudgetRecoveryPolicy,
    /workflowCodingToolBudgetRecoveryPolicyFromWorkflow/,
  );
  assert.match(codingToolBudgetRecoveryPolicy, /budgetRecoveryApprovalScope/);
  assert.match(codingToolBudgetRecoveryPolicy, /budgetRecoveryRetryLimit/);
  assert.match(codingToolBudgetRecoveryPolicy, /budgetRecoveryOperatorRole/);
  assert.match(projection, /workflow\.run\.retry_completed/);
  assert.match(projection, /coding_tool_budget_preflight_blocked/);
  assert.match(
    telemetryBudgetChainSubflow,
    /ioi\.workflow\.runtime-telemetry-budget-chain-subflow\.v1/,
  );
  assert.match(
    telemetryBudgetChainSubflow,
    /createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow/,
  );
  for (const nodeType of [
    "runtime_usage_meter",
    "runtime_context_budget",
    "runtime_compaction_policy",
    "plugin_tool",
  ]) {
    assert.match(telemetryBudgetChainSubflow, new RegExp(`"${nodeType}"`));
  }
  assert.match(telemetryBudgetChainSubflow, /runtimeUsageMeter/);
  assert.match(telemetryBudgetChainSubflow, /runtimeContextBudget/);
  assert.match(telemetryBudgetChainSubflow, /runtimeCompactionPolicy/);
  assert.match(telemetryBudgetChainSubflow, /budgetUsageField: "runtimeTelemetrySummary"/);
  assert.match(
    telemetryBudgetChainSubflowTest,
    /generated telemetry budget chain nodes compile into daemon requests/,
  );
  assert.match(
    telemetryBudgetChainSubflowTest,
    /missing_runtime_telemetry_source_usage_binding/,
  );
  assert.match(
    exports,
    /createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow/,
  );
  assert.match(
    exports,
    /materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry/,
  );
  assert.match(
    telemetryBudgetChainMaterialization,
    /ioi\.workflow\.runtime-telemetry-budget-chain-materialization\.v1/,
  );
  assert.match(
    telemetryBudgetChainMaterialization,
    /materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry/,
  );
  assert.match(
    telemetryBudgetChainMaterialization,
    /workflowRuntimeTelemetryBudgetChainIdsFromWorkflow/,
  );
  assert.match(telemetryBudgetChainMaterialization, /mode: "materialized"/);
  assert.match(telemetryBudgetChainMaterialization, /mode: "hydrated"/);
  assert.match(
    telemetryBudgetChainMaterialization,
    /targetNodeIds: chainNodeIds/,
  );
  assert.match(
    telemetryBudgetChainMaterializationTest,
    /run-inspector telemetry evidence materializes and binds a budget chain/,
  );
  assert.match(
    telemetryBudgetChainMaterializationTest,
    /hydrates an existing compatible chain/,
  );
  assert.match(
    composerController,
    /handleInsertRuntimeTelemetryBudgetChainTemplate/,
  );
  assert.match(
    composerController,
    /handleMaterializeRuntimeTelemetryBudgetChain/,
  );
  assert.match(
    composerController,
    /materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry/,
  );
  assert.match(
    composerView,
    /workflow-add-runtime-telemetry-budget-chain-template/,
  );
  assert.match(runsPanel, /workflow-run-telemetry-budget-chain-materialize/);
  assert.match(runsPanel, /onMaterializeRuntimeTelemetryBudgetChain/);
  assert.match(runsPanel, /workflow-run-computer-use-scorecard/);
  assert.match(runsPanel, /Computer Use Scorecard/);
  assert.match(runsPanel, /data-external-deferral-count/);
  assert.match(runsPanel, /workflow-run-computer-use-trace/);
  assert.match(runsPanel, /data-computer-use-lane/);
  assert.match(runsPanel, /data-computer-use-browser-discovery-ref/);
  assert.match(runsPanel, /data-computer-use-proposal-ref/);
  assert.match(runsPanel, /data-computer-use-verification-ref/);
  assert.match(runsPanel, /data-execution-provider-id/);
  assert.match(runsPanel, /data-execution-requires-reobserve/);
  assert.match(runsPanel, /data-cleanup-status/);
  assert.match(runsPanel, /data-workflow-node-id/);
  assert.match(runsPanel, /data-tool-ref/);
  assert.match(runsPanel, /data-authority-scopes/);
  assert.match(railPanel, /onMaterializeRuntimeTelemetryBudgetChain/);
  assert.match(composerView, /handleMaterializeRuntimeTelemetryBudgetChain/);
  assert.match(
    telemetryBudgetChainRuntimeSubflowInsertion,
    /workflowRuntimeSubflowReactFlowElements/,
  );
  assert.match(
    telemetryBudgetChainRuntimeSubflowInsertion,
    /sourceHandle: edge\.fromPort/,
  );
  assert.match(
    telemetryBudgetChainRuntimeSubflowInsertion,
    /targetHandle: edge\.toPort/,
  );
  assert.match(
    telemetryBudgetChainCreatorGuiProbe,
    /workflow_telemetry_budget_chain_creator_click/,
  );
  assert.match(
    telemetryBudgetChainCreatorGuiProbe,
    /workflow-add-runtime-telemetry-budget-chain-template/,
  );
  assert.match(
    telemetryBudgetChainCreatorGuiProbe,
    /workflowRuntimeSubflowReactFlowElements/,
  );
  assert.match(
    telemetryBudgetChainCreatorGuiProbe,
    /readinessFailsWhenUpstreamBindingRemoved/,
  );
  assert.match(
    telemetryBudgetChainCreatorGuiProbe,
    /missing_runtime_telemetry_source_usage_binding/,
  );
  assert.match(
    telemetryBudgetChainRunInspectorProbe,
    /workflow_telemetry_budget_chain_run_inspector_materialize/,
  );
  assert.match(
    telemetryBudgetChainRunInspectorProbe,
    /workflow-run-telemetry-budget-chain-materialize/,
  );
  assert.match(
    telemetryBudgetChainRunInspectorProbe,
    /materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry/,
  );
  assert.match(
    telemetryBudgetChainRunInspectorProbe,
    /hydratesExistingChain/,
  );
  assert.match(
    telemetryBudgetChainRunInspectorProbe,
    /readinessFailsWhenUpstreamBindingRemoved/,
  );
  assert.match(
    terminalCodingLoopSubflow,
    /ioi\.workflow\.runtime-terminal-coding-loop-subflow\.v1/,
  );
  assert.match(
    terminalCodingLoopSubflow,
    /createWorkflowRuntimeTerminalCodingLoopTemplateSubflow/,
  );
  for (const toolId of [
    "workspace.status",
    "git.diff",
    "file.inspect",
    "file.apply_patch",
    "test.run",
    "lsp.diagnostics",
    "artifact.read",
    "tool.retrieve_result",
  ]) {
    assert.match(terminalCodingLoopSubflow, new RegExp(toolId.replace(".", "\\.")));
  }
  assert.match(terminalCodingLoopSubflow, /runtimeTerminalCodingLoopTuiReopen/);
  assert.match(terminalCodingLoopSubflow, /bindingKind: "coding_tool_pack"/);
  assert.match(terminalCodingLoopSubflow, /diagnosticsRepairDefault/);
  assert.match(
    terminalCodingLoopSubflowTest,
    /generated terminal coding loop nodes compile into daemon coding-tool requests/,
  );
  assert.match(
    terminalCodingLoopSubflowTest,
    /terminal coding loop template materializes to React Flow elements/,
  );
  assert.match(
    terminalCodingLoopMaterialization,
    /ioi\.workflow\.runtime-terminal-coding-loop-materialization\.v1/,
  );
  assert.match(
    terminalCodingLoopMaterialization,
    /materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow/,
  );
  assert.match(
    terminalCodingLoopMaterialization,
    /workflowRuntimeTerminalCodingLoopIdsFromWorkflow/,
  );
  assert.match(terminalCodingLoopMaterialization, /mode: "materialized"/);
  assert.match(terminalCodingLoopMaterialization, /mode: "hydrated"/);
  assert.match(
    terminalCodingLoopMaterializationTest,
    /run-inspector coding-tool evidence materializes a terminal coding loop/,
  );
  assert.match(
    terminalCodingLoopMaterializationTest,
    /hydrates an existing terminal loop/,
  );
  assert.match(
    terminalCodingLoopExecution,
    /ioi\.workflow\.runtime-terminal-coding-loop-execution\.v1/,
  );
  assert.match(
    terminalCodingLoopExecution,
    /createRuntimeTerminalCodingLoopStepRequest/,
  );
  assert.match(
    terminalCodingLoopExecution,
    /updateRuntimeTerminalCodingLoopExecutionContextFromToolResult/,
  );
  assert.match(
    terminalCodingLoopExecution,
    /workflowRuntimeTerminalCodingLoopNodesInExecutionOrder/,
  );
  assert.match(
    terminalCodingLoopExecutionTest,
    /resolves upstream artifact and tool result placeholders/,
  );
  assert.match(
    terminalCodingLoopRunLaunch,
    /ioi\.workflow\.runtime-terminal-coding-loop-run-launch\.v1/,
  );
  assert.match(
    terminalCodingLoopRunLaunch,
    /createRuntimeTerminalCodingLoopRunLaunchPlan/,
  );
  assert.match(
    terminalCodingLoopRunLaunch,
    /runRuntimeTerminalCodingLoopWorkflowLaunch/,
  );
  assert.match(
    terminalCodingLoopRunLaunch,
    /WorkflowRunResult/,
  );
  assert.match(
    terminalCodingLoopRunLaunch,
    /workflowRuntimeThreadEventFromToolResult/,
  );
  assert.match(
    terminalCodingLoopRunLaunchTest,
    /dispatches saved workflow nodes in run-history order/,
  );
  assert.match(
    terminalCodingLoopRunActivation,
    /ioi\.workflow\.composer-terminal-coding-loop-run-activation\.v1/,
  );
  assert.match(
    terminalCodingLoopRunActivation,
    /workflowComposerTerminalCodingLoopRunLaunchEligible/,
  );
  assert.match(
    terminalCodingLoopRunActivation,
    /runWorkflowComposerTerminalCodingLoopActivation/,
  );
  assert.match(
    terminalCodingLoopRunActivation,
    /runtime_approval_decision/,
  );
  assert.match(
    terminalCodingLoopRunActivationTest,
    /launches pure saved workflow/,
  );
  assert.match(
    exports,
    /createWorkflowRuntimeTerminalCodingLoopTemplateSubflow/,
  );
  assert.match(
    exports,
    /materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow/,
  );
  assert.match(
    exports,
    /createRuntimeTerminalCodingLoopStepRequest/,
  );
  assert.match(
    exports,
    /runRuntimeTerminalCodingLoopWorkflowLaunch/,
  );
  assert.match(
    exports,
    /runWorkflowComposerTerminalCodingLoopActivation/,
  );
  assert.match(
    exports,
    /workflowRunHistoryModel/,
  );
  assert.match(
    composerController,
    /handleInsertRuntimeTerminalCodingLoopTemplate/,
  );
  assert.match(
    composerController,
    /workflowComposerTerminalCodingLoopRunLaunchEligible/,
  );
  assert.match(
    composerController,
    /runWorkflowComposerTerminalCodingLoopActivation/,
  );
  assert.match(
    composerController,
    /workflowComposerTerminalCodingLoopControlRequestForRuntime/,
  );
  assert.match(
    composerController,
    /handleMaterializeRuntimeTerminalCodingLoop/,
  );
  assert.match(
    composerController,
    /materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow/,
  );
  assert.match(
    composerView,
    /workflow-add-runtime-terminal-coding-loop-template/,
  );
  assert.match(runsPanel, /workflow-run-terminal-coding-loop-materialize-/);
  assert.match(runsPanel, /onMaterializeRuntimeTerminalCodingLoop/);
  assert.match(runsPanel, /data-coding-tool-row-count/);
  assert.match(railPanel, /onMaterializeRuntimeTerminalCodingLoop/);
  assert.match(composerView, /handleMaterializeRuntimeTerminalCodingLoop/);
  assert.match(
    terminalCodingLoopCreatorGuiProbe,
    /workflow_terminal_coding_loop_creator_click/,
  );
  assert.match(
    terminalCodingLoopCreatorGuiProbe,
    /workflow-add-runtime-terminal-coding-loop-template/,
  );
  assert.match(
    terminalCodingLoopCreatorGuiProbe,
    /workflowRuntimeSubflowReactFlowElements/,
  );
  assert.match(
    terminalCodingLoopRunInspectorProbe,
    /workflow_terminal_coding_loop_run_inspector_materialize/,
  );
  assert.match(
    terminalCodingLoopRunInspectorProbe,
    /workflow-run-terminal-coding-loop-materialize-/,
  );
  assert.match(
    terminalCodingLoopRunInspectorProbe,
    /materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow/,
  );
  assert.match(
    terminalCodingLoopRunInspectorProbe,
    /hydratesExistingLoop/,
  );
  assert.match(
    terminalCodingLoopRunButtonProbe,
    /workflow_terminal_coding_loop_run_button_activation/,
  );
  assert.match(terminalCodingLoopRunButtonProbe, /workflow-run-button/);
  assert.match(
    terminalCodingLoopRunButtonProbe,
    /runWorkflowComposerTerminalCodingLoopActivation/,
  );
  assert.match(
    terminalCodingLoopRunButtonProbe,
    /workflowRunHistoryModel/,
  );
  assert.match(
    terminalCodingLoopRunButtonProbe,
    /approvalDecisionEvidence/,
  );
  assert.match(
    sandboxedComputerRunButtonProbe,
    /workflow_sandboxed_computer_run_button_activation/,
  );
  assert.match(sandboxedComputerRunButtonProbe, /workflow-run-button/);
  assert.match(sandboxedComputerRunButtonProbe, /Sandboxed Computer/);
  assert.match(
    sandboxedComputerRunButtonProbe,
    /workflowComposerComputerUseRunOptions/,
  );
  assert.match(
    sandboxedComputerRunButtonProbe,
    /mergeWorkflowComposerComputerUseRunOptions/,
  );
  assert.match(sandboxedComputerRunButtonProbe, /local_sandbox_fixture/);
  assert.match(sandboxedComputerRunButtonProbe, /workflowRunHistoryModel/);
  assert.match(sandboxedComputerRunButtonProbe, /glassBoxWorkbench/);
  assert.match(
    nativeBrowserPromptPipelineProbe,
    /workflow_native_browser_prompt_pipeline/,
  );
  assert.match(nativeBrowserPromptPipelineProbe, /workflow-run-button/);
  assert.match(nativeBrowserPromptPipelineProbe, /Browser Use/);
  assert.match(nativeBrowserPromptPipelineProbe, /demo-mounted-browser-model/);
  assert.match(
    nativeBrowserPromptPipelineProbe,
    /workflowComposerComputerUseRunOptions/,
  );
  assert.match(
    nativeBrowserPromptPipelineProbe,
    /workflowRunHistoryModel/,
  );
  assert.match(
    nativeBrowserPromptPipelineProbe,
    /modelInvocationTraceVisible/,
  );
  assert.match(nativeBrowserPromptPipelineProbe, /traceCrossesModelToBrowser/);
  assert.match(
    visualGuiPromptPipelineProbe,
    /workflow_visual_gui_prompt_pipeline/,
  );
  assert.match(visualGuiPromptPipelineProbe, /workflow-run-button/);
  assert.match(visualGuiPromptPipelineProbe, /Visual Observation/);
  assert.match(visualGuiPromptPipelineProbe, /Computer Use/);
  assert.match(visualGuiPromptPipelineProbe, /demo-mounted-visual-model/);
  assert.match(
    visualGuiPromptPipelineProbe,
    /workflowComposerComputerUseRunOptions/,
  );
  assert.match(visualGuiPromptPipelineProbe, /workflowRunHistoryModel/);
  assert.match(visualGuiPromptPipelineProbe, /modelInvocationTraceVisible/);
  assert.match(visualGuiPromptPipelineProbe, /traceCrossesModelToVisual/);
  assert.match(visualGuiPromptPipelineProbe, /targetOverlayEvidence/);
  assert.match(runHistoryModelTest, /computerUseScorecard/);
  assert.match(runHistoryModelTest, /hosted_provider_backends/);
  assert.match(
    computerUseTriLaneScorecardTest,
    /collectWorkflowComputerUseTriLaneScorecard/,
  );
  assert.match(
    computerUseTriLaneScorecardTest,
    /workflow_computer_use_tri_lane_scorecard/,
  );
  assert.match(computerUseTriLaneScorecardTest, /operatorSummary/);
  assert.match(computerUseTriLaneScorecardTest, /summaryRows/);
  assert.match(
    computerUseTriLaneScorecardTest,
    /renderWorkflowComputerUseTriLaneScorecardMarkdown/,
  );
  assert.match(computerUseTriLaneScorecardTest, /Computer Use Scorecard/);
  assert.match(computerUseTriLaneScorecardTest, /blockers/);
  assert.match(computerUseTriLaneScorecardTest, /hosted_provider_backends/);
  assert.match(
    liveRuntimeDaemonContract,
    /React Flow run-inspector-created telemetry budget chain executes/,
  );
  assert.match(
    liveRuntimeDaemonContract,
    /materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry/,
  );
  assert.match(liveRuntimeDaemonContract, /mode, "hydrated"/);
  assert.match(
    liveRuntimeDaemonContract,
    /run_inspector_created_telemetry_chain_budget_blocked/,
  );
  assert.match(
    liveRuntimeDaemonContract,
    /React Flow terminal coding-loop template executes against daemon with TUI row parity/,
  );
  assert.match(
    liveRuntimeDaemonContract,
    /runWorkflowComposerTerminalCodingLoopActivation/,
  );
  assert.match(
    liveRuntimeDaemonContract,
    /workflowComposerTerminalCodingLoopRunLaunchEligible/,
  );
  assert.match(
    liveRuntimeDaemonContract,
    /\.agents\/workflows\/terminal-coding-loop-live\.workflow\.json/,
  );
  assert.match(
    liveRuntimeDaemonContract,
    /workflowRunHistoryModel/,
  );
  assert.match(
    liveRuntimeDaemonContract,
    /composerThreadToolCallPrefix/,
  );
  assert.match(
    liveRuntimeDaemonContract,
    /runtime_approval_decision/,
  );
  assert.match(
    liveRuntimeDaemonContract,
    /runHistory\.visibleTuiControlStateRows/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_telemetry_budget_chain_creator/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_telemetry_budget_chain_run_inspector/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_telemetry_budget_chain_creator_proof_present/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_telemetry_budget_chain_run_inspector_proof_present/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_terminal_coding_loop_creator/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_terminal_coding_loop_run_inspector/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_terminal_coding_loop_run_button/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_sandboxed_computer_run_button/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_native_browser_prompt_pipeline/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_visual_gui_prompt_pipeline/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_computer_use_tri_lane_scorecard/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_terminal_coding_loop_creator_proof_present/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_terminal_coding_loop_run_inspector_proof_present/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_terminal_coding_loop_run_button_proof_present/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_sandboxed_computer_run_button_proof_present/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_native_browser_prompt_pipeline_proof_present/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_visual_gui_prompt_pipeline_proof_present/,
  );
  assert.match(
    guiHarnessContract,
    /workflow_computer_use_tri_lane_scorecard_present/,
  );
  assert.match(
    guiHarnessValidation,
    /collectWorkflowTelemetryBudgetChainCreatorProof/,
  );
  assert.match(
    guiHarnessValidation,
    /collectWorkflowTelemetryBudgetChainRunInspectorProof/,
  );
  assert.match(
    guiHarnessValidation,
    /collectWorkflowTerminalCodingLoopCreatorProof/,
  );
  assert.match(
    guiHarnessValidation,
    /collectWorkflowTerminalCodingLoopRunInspectorProof/,
  );
  assert.match(
    guiHarnessValidation,
    /collectWorkflowTerminalCodingLoopRunButtonProof/,
  );
  assert.match(
    guiHarnessValidation,
    /collectWorkflowSandboxedComputerRunButtonProof/,
  );
  assert.match(
    guiHarnessValidation,
    /collectWorkflowNativeBrowserPromptPipelineProof/,
  );
  assert.match(
    guiHarnessValidation,
    /workflowTelemetryBudgetChainCreatorProof/,
  );
  assert.match(
    guiHarnessValidation,
    /workflowTelemetryBudgetChainRunInspectorProof/,
  );
  assert.match(
    guiHarnessValidation,
    /workflowTerminalCodingLoopCreatorProof/,
  );
  assert.match(
    guiHarnessValidation,
    /workflowTerminalCodingLoopRunInspectorProof/,
  );
  assert.match(
    guiHarnessValidation,
    /workflowTerminalCodingLoopRunButtonProof/,
  );
  assert.match(
    guiHarnessValidation,
    /workflowSandboxedComputerRunButtonProof/,
  );
  assert.match(
    guiHarnessValidation,
    /workflowNativeBrowserPromptPipelineProof/,
  );
  assert.match(
    guiHarnessValidation,
    /workflowVisualGuiPromptPipelineProof/,
  );
  assert.match(
    guiHarnessValidation,
    /workflowComputerUseTriLaneScorecard/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_telemetry_budget_chain_creator/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_telemetry_budget_chain_run_inspector/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_terminal_coding_loop_creator/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_terminal_coding_loop_run_inspector/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_terminal_coding_loop_run_button/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_sandboxed_computer_run_button/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_native_browser_prompt_pipeline/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_visual_gui_prompt_pipeline/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_computer_use_tri_lane_scorecard/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_telemetry_budget_chain_creator_proof_present/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_telemetry_budget_chain_run_inspector_proof_present/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_terminal_coding_loop_creator_proof_present/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_terminal_coding_loop_run_inspector_proof_present/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_terminal_coding_loop_run_button_proof_present/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_sandboxed_computer_run_button_proof_present/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_native_browser_prompt_pipeline_proof_present/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_visual_gui_prompt_pipeline_proof_present/,
  );
  assert.match(
    guiHarnessValidation,
    /workflow_computer_use_tri_lane_scorecard_present/,
  );
  assert.match(projection, /Coding tool budget/);
  assert.match(projection, /runtimeSubagentSubflow/);
  assert.match(projection, /runtimeSubagentRun/);
  assert.match(projection, /runtime_thread_fork/);
  assert.match(projection, /runtime_operator_interrupt/);
  assert.match(projection, /runtime_operator_steer/);
  assert.match(projection, /runtime_context_compact/);
  assert.match(projection, /runtime_context_budget/);
  assert.match(projection, /runtime_compaction_policy/);
  assert.match(controlNodes, /createRuntimeThreadForkControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeOperatorInterruptControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeOperatorSteerControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeContextCompactControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeRollbackSnapshotControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /createRuntimeRestoreGateControlRequestFromWorkflowNode/);
  assert.match(controlNodes, /runtime_thread_fork/);
  assert.match(controlNodes, /runtime_operator_interrupt/);
  assert.match(controlNodes, /runtime_operator_steer/);
  assert.match(controlNodes, /runtime_context_compact/);
  assert.match(controlNodes, /runtime_rollback_snapshot/);
  assert.match(controlNodes, /runtime_restore_gate/);
  assert.match(controlNodes, /runtime\.thread-fork/);
  assert.match(controlNodes, /runtime\.operator-interrupt/);
  assert.match(controlNodes, /runtime\.operator-steer/);
  assert.match(controlNodes, /runtime\.context-compact/);
  assert.match(controlNodes, /runtime\.rollback-snapshot/);
  assert.match(controlNodes, /runtime\.restore-gate/);
  assert.match(controlNodes, /source: RUNTIME_THREAD_FORK_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_OPERATOR_INTERRUPT_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_OPERATOR_STEER_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_CONTEXT_COMPACT_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_ROLLBACK_SNAPSHOT_SOURCE/);
  assert.match(controlNodes, /source: RUNTIME_RESTORE_GATE_SOURCE/);
  assert.match(controlNodes, /workflowGraphId/);
  assert.match(controlNodes, /workflowNodeId/);
  assert.match(usageControlNodes, /createRuntimeUsageMeterControlRequestFromWorkflowNode/);
  assert.match(usageControlNodes, /runtime_usage_meter/);
  assert.match(usageControlNodes, /\/v1\/threads\/\{threadId\}\/usage/);
  assert.match(usageControlNodes, /RuntimeUsageTelemetry\.Read/);
  assert.match(usageControlNodes, /usage_meter_scope/);
  assert.match(contextBudgetControlNodes, /createRuntimeContextBudgetControlRequestFromWorkflowNode/);
  assert.match(contextBudgetControlNodes, /runtime_context_budget/);
  assert.match(contextBudgetControlNodes, /\/v1\/threads\/\{threadId\}\/context-budget/);
  assert.match(contextBudgetControlNodes, /RuntimeContextBudget\.Evaluate/);
  assert.match(codingToolControlNodes, /createRuntimeCodingToolControlRequestFromWorkflowNode/);
  assert.match(codingToolControlNodes, /runtimeTelemetrySummary/);
  assert.match(codingToolControlNodes, /budgetUsageTelemetry/);
  assert.match(codingToolControlNodes, /budgetUsageTelemetryField/);
  assert.match(codingToolControlNodes, /workflowRuntimeTelemetrySummaryToUsageTelemetry/);
  assert.match(telemetrySourceBinding, /bindWorkflowRuntimeTelemetrySourceToWorkflow/);
  assert.match(telemetrySourceBinding, /runtime_usage_meter/);
  assert.match(telemetrySourceBinding, /runtime_context_budget/);
  assert.match(telemetrySourceBinding, /runtime_compaction_policy/);
  assert.match(telemetrySourceBinding, /react_flow_quick_fix/);
  assert.match(telemetrySourceBinding, /boundWorkflowNodeId/);
  assert.match(telemetrySourceBinding, /boundCompactWorkflowNodeId/);
  assert.match(telemetrySourceBinding, /runtimeContextBudgetUsageField: "runtimeUsageMeter"/);
  assert.match(telemetrySourceBindingTest, /wires selected summary into runtime budget nodes/);
  assert.match(telemetrySourceBindingTest, /liveRuntimeContextBudget/);
  assert.ok(
    contextBudgetControlNodes.indexOf(
      'valueAtPath(params.input, params.usageTelemetryField ?? "runtimeUsageMeter")',
    ) < contextBudgetControlNodes.indexOf("params.usageTelemetry"),
  );
  assert.ok(
    compactionPolicyControlNodes.indexOf(
      'valueAtPath(params.input, params.contextBudgetField ?? "runtimeContextBudget")',
    ) < compactionPolicyControlNodes.indexOf("params.contextBudget"),
  );
  assert.ok(
    codingToolControlNodes.indexOf("valueAtPath(params.input, budgetUsageField)") <
      codingToolControlNodes.indexOf("params.runtimeTelemetrySummary"),
  );
  assert.match(compactionPolicyControlNodes, /createRuntimeCompactionPolicyControlRequestFromWorkflowNode/);
  assert.match(compactionPolicyControlNodes, /runtime_compaction_policy/);
  assert.match(compactionPolicyControlNodes, /\/v1\/threads\/\{threadId\}\/compaction-policy/);
  assert.match(compactionPolicyControlNodes, /RuntimeCompactionPolicy\.Evaluate/);
  assert.match(read("packages/agent-ide/src/runtime/workflow-node-registry.ts"), /creatorId: "usage\.meter"/);
  assert.match(read("packages/agent-ide/src/runtime/workflow-node-registry.ts"), /creatorId: "context\.budget"/);
  assert.match(read("packages/agent-ide/src/runtime/workflow-node-registry.ts"), /creatorId: "compaction\.policy"/);
  assert.match(controlNodesTest, /React Flow daemon request/);
  assert.match(usageControlNodesTest, /workflow\.react-flow\.usage-meter-proof/);
  assert.match(contextBudgetControlNodesTest, /workflow\.react-flow\.context-budget-proof/);
  assert.match(codingToolControlNodesTest, /runtime telemetry summary budget gates/);
  assert.match(typeTest, /projects coding tool budget blocks/);
  assert.match(typeTest, /projects TUI coding-tool success rows/);
  assert.match(typeTest, /projects TUI coding-tool budget rows/);
  assert.match(runHistoryModelTest, /componentKind: "coding_tool"/);
  assert.match(runsPanel, /data-coding-tool-budget-row-count/);
  assert.match(runsPanel, /data-coding-tool-budget-status/);
  assert.match(runsPanel, /data-coding-tool-mutation-blocked/);
  assert.match(compactionPolicyControlNodesTest, /workflow\.react-flow\.compaction-policy-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.thread-fork-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.operator-interrupt-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.operator-steer-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.context-compact-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.rollback-snapshot-proof/);
  assert.match(controlNodesTest, /workflow\.react-flow\.restore-gate-proof/);
  assert.match(exports, /workflow-runtime-event-projection/);
  assert.match(exports, /workflow-runtime-telemetry-summary/);
  assert.match(exports, /workflow-runtime-control-nodes/);
  assert.match(exports, /workflow-runtime-usage-control-nodes/);
  assert.match(exports, /workflow-runtime-context-budget-control-nodes/);
  assert.match(exports, /workflow-runtime-compaction-policy-control-nodes/);
  assert.match(typeTest, /projects Thread\.events runtime events/);
  assert.match(typeTest, /runtime_thread_fork/);
  assert.match(typeTest, /runtime_operator_interrupt/);
  assert.match(typeTest, /runtime_operator_steer/);
  assert.match(typeTest, /runtime_context_compact/);
  assert.match(typeTest, /runtime_compaction_policy/);
  assert.match(typeTest, /approval_required/);
  assert.match(typeTest, /policy_blocked/);
  assert.match(runHistoryModel, /projectRuntimeThreadEventsToWorkflowProjection/);
  assert.match(runHistoryModel, /runtimeThreadEvents\?: WorkflowRuntimeThreadEventLike\[\]/);
  assert.match(runHistoryModel, /runtimeEventProjection: WorkflowRuntimeEventProjection/);
  assert.match(runHistoryModel, /runtimeTelemetrySummary: WorkflowRuntimeTelemetrySummary/);
  assert.match(runHistoryModel, /runtimeTelemetrySourceFilters/);
  assert.match(runHistoryModel, /runtimeCodingToolBudgetEvidence/);
  assert.match(runHistoryModel, /visibleTuiControlStateRows/);
  assert.match(runHistoryModel, /workflowRuntimeTelemetrySummaryFromProjection/);
  assert.match(runHistoryModel, /runtimeThreadEventsForRunResult/);
  assert.match(runHistoryModelTest, /projects canonical runtime thread events/);
  assert.match(runHistoryModelTest, /source-filtered TUI coding-tool budget evidence/);
  assert.match(readinessModel, /WorkflowCodingToolBudgetPreflight/);
  assert.match(readinessModel, /WorkflowCodingToolBudgetRunLaunchAnnotation/);
  assert.match(readinessModel, /runtimeCodingToolBudgetEvidence/);
  assert.match(readinessModel, /prior_coding_tool_budget_evidence/);
  assert.match(readinessModel, /workflowCodingToolBudgetRecoveryPolicyFromWorkflow/);
  assert.match(readinessModel, /workflowCodingToolBudgetRunLaunchAnnotation/);
  assert.match(readinessModel, /Coding budget preflight/);
  assert.match(workflowValidation, /workflowRuntimeCodingToolBudgetRecoveryBindingIssues/);
  assert.match(workflowValidation, /missing_runtime_coding_tool_budget_recovery_policy_binding/);
  assert.match(workflowValidation, /workflowRuntimeTelemetrySourceBindingIssues/);
  assert.match(workflowValidation, /missing_runtime_telemetry_source_usage_binding/);
  assert.match(codingToolBudgetRecoveryBinding, /bindWorkflowRuntimeCodingToolBudgetRecoveryTemplateToEvidence/);
  assert.match(codingToolBudgetRecoveryBinding, /workflowRuntimeCodingToolBudgetRecoveryEvidenceAction/);
  assert.match(codingToolBudgetRecoveryBinding, /react_flow_quick_fix/);
  assert.match(codingToolBudgetRecoveryBindingTest, /wires selected evidence into template nodes/);
  assert.match(readinessModelTest, /prior TUI budget evidence/);
  assert.match(readinessModelTest, /unbound coding-tool budget recovery templates/);
  assert.match(readinessModelTest, /run launch annotations/);
  assert.match(readinessPanel, /workflow-readiness-coding-tool-budget-preflight/);
  assert.match(readinessPanel, /data-tool-call-ids/);
  assert.match(readinessPanel, /data-policy-decision-refs/);
  assert.match(telemetrySummary, /ioi\.workflow\.runtime-telemetry-summary\.v1/);
  assert.match(telemetrySummary, /workflowRuntimeTelemetrySummaryToUsageTelemetry/);
  assert.match(telemetrySummary, /estimated_cost_usd/);
  assert.match(telemetrySummary, /runtime_usage_events/);
  assert.match(telemetrySummary, /runtime_context_pressure_events/);
  assert.match(telemetrySummary, /runtime_context_pressure_alerts/);
  assert.match(telemetrySummary, /tui_usage_rows/);
  assert.match(telemetrySummary, /tui_context_rows/);
  assert.match(telemetrySummary, /tui_subagent_rows/);
  assert.match(telemetrySummary, /tui_coding_tool_rows/);
  assert.match(telemetrySummary, /codingToolBudgetRowCount/);
  assert.match(telemetrySummaryTest, /merges usage, context, TUI, and subagent rows/);
  assert.match(telemetrySummaryTest, /TUI coding-tool budget rows/);
  assert.match(telemetrySummaryTest, /converts to daemon budget usage telemetry/);
  assert.match(contextBudgetControlNodes, /runtimeTelemetrySummary/);
  assert.match(contextBudgetControlNodesTest, /runtime telemetry summary input/);
  assert.match(railPanel, /runtimeThreadEvents\?: WorkflowRuntimeThreadEventLike\[\]/);
  assert.match(railPanel, /runtimeThreadEvents,/);
  assert.match(railPanel, /runtimeCodingToolBudgetEvidence/);
  assert.match(composerController, /workflowRunHistoryModel/);
  assert.match(composerController, /workflowRunCodingBudgetPreflight/);
  assert.match(composerController, /coding_tool_budget_preflight_blocked/);
  assert.match(composerController, /codingToolBudgetPreflight/);
  assert.match(composerController, /codingToolBudgetRecovery/);
  assert.match(composerController, /handleExecuteRuntimeCodingToolBudgetRecovery/);
  assert.match(composerController, /handleBindRuntimeCodingToolBudgetRecoveryTemplate/);
  assert.match(composerController, /bindWorkflowRuntimeCodingToolBudgetRecoveryTemplateToEvidence/);
  assert.match(composerController, /handleBindRuntimeTelemetrySource/);
  assert.match(composerController, /bindWorkflowRuntimeTelemetrySourceToWorkflow/);
  assert.match(composerController, /coding-tool-budget-approved-retry/);
  assert.match(composerController, /loadWorkflowRuntimeThreadEvents/);
  assert.match(composerController, /setRuntimeThreadEvents/);
  assert.match(composerView, /runtimeThreadEvents=\{runtimeThreadEvents\}/);
  assert.match(composerView, /workflowRunLaunchBlocked/);
  assert.match(composerView, /data-workflow-run-launch-blocked/);
  assert.match(composerView, /data-coding-tool-budget-preflight-status/);
  assert.match(composerSupport, /data-disabled-reason/);
  assert.match(graphRuntimeTypes, /WorkflowRunRequestOptions/);
  assert.match(graphRuntimeTypes, /codingToolBudgetPreflight/);
  assert.match(graphRuntimeTypes, /codingToolBudgetRecovery/);
  assert.match(graphRuntimeTypes, /loadWorkflowRuntimeThreadEvents/);
  assert.match(tauriRuntime, /loadWorkflowRuntimeThreadEvents/);
  assert.match(typeTest, /WorkflowRunCodingToolBudgetPreflightBlocked/);
  assert.match(runHistoryModelTest, /daemon-owned coding budget preflight/);
  assert.match(runsPanel, /workflow-run-runtime-event-graph/);
  assert.match(runsPanel, /workflow-run-telemetry-summary/);
  assert.match(runsPanel, /workflow-run-source-filter/);
  assert.match(runsPanel, /workflow-run-coding-tool-budget-evidence/);
  assert.match(runsPanel, /workflow-run-coding-tool-budget-recovery-action/);
  assert.match(runsPanel, /workflow-run-coding-tool-budget-recovery-bind-template-/);
  assert.match(runsPanel, /workflow-run-telemetry-bind-source/);
  assert.match(runsPanel, /data-coding-tool-budget-recovery-action-count/);
  assert.match(runsPanel, /data-recovery-policy-operator-role/);
  assert.match(runsPanel, /workflow-run-telemetry-source-kinds/);
  assert.match(runsPanel, /data-telemetry-status/);
  assert.match(runsPanel, /data-context-pressure-event-count/);
  assert.match(runsPanel, /data-visible-row-count/);
  assert.match(runsPanel, /workflow-run-runtime-event-node-/);
  assert.match(runsPanel, /workflow-run-runtime-event-edge-/);
  assert.match(runsPanel, /data-event-id/);
  assert.match(runsPanel, /data-event-cursor/);
  assert.match(runsPanel, /data-receipt-refs/);
  assert.match(runsPanel, /data-artifact-refs/);
  assert.match(runsPanel, /data-policy-decision-refs/);
  assert.match(runsPanel, /data-rollback-refs/);
  assert.match(runsPanel, /workflow-run-subagent-subflows/);
  assert.match(runsPanel, /data-subagent-child-subflow-count/);
  assert.match(runsPanel, /data-subagent-budget-status/);
  assert.match(runsPanel, /data-subagent-cost-estimate-usd/);
  assert.match(runsPanel, /data-subagent-token-estimate/);
  assert.match(runsPanel, /data-usage-total-tokens/);
  assert.match(runsPanel, /data-usage-cost-estimate-usd/);
  assert.match(runsPanel, /data-usage-context-pressure-status/);
  assert.match(runsPanel, /data-child-thread-id/);
});
