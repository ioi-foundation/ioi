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
const workflowRailModel = fs.readFileSync(
  new URL(
    "../../../../../packages/agent-ide/src/runtime/workflow-rail-model.ts",
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
const guiHarnessValidation = fs.readFileSync(
  new URL(
    "../../../../../scripts/run-autopilot-gui-harness-validation.mjs",
    import.meta.url,
  ),
  "utf8",
);
const guiHarnessContract = fs.readFileSync(
  new URL(
    "../../../../../scripts/lib/autopilot-gui-harness-contract.mjs",
    import.meta.url,
  ),
  "utf8",
);
const promotionTransitionGuiProbe = fs.readFileSync(
  new URL(
    "../../../../../scripts/lib/harness-promotion-transition-gui-probe.mjs",
    import.meta.url,
  ),
  "utf8",
);

assert.match(
  graphTypes,
  /(?=[\s\S]*WorkflowHarnessExecutionMode)(?=[\s\S]*WorkflowHarnessComponentReadiness)(?=[\s\S]*WorkflowHarnessReplayEnvelope)(?=[\s\S]*WorkflowHarnessActionFrame)(?=[\s\S]*WorkflowHarnessComponentInvocation)(?=[\s\S]*WorkflowHarnessComponentAdapterResult)(?=[\s\S]*WorkflowHarnessGroupView)(?=[\s\S]*WorkflowHarnessPromotionCluster)(?=[\s\S]*WorkflowHarnessGatedClusterRun)(?=[\s\S]*WorkflowRevisionBinding)(?=[\s\S]*WorkflowRevisionRestoreRequest)(?=[\s\S]*dryRun\?: boolean)(?=[\s\S]*WorkflowRevisionRestoreResult)(?=[\s\S]*git_show_file_restore)(?=[\s\S]*workflowContentHash)(?=[\s\S]*actualWorkflowContentHash)(?=[\s\S]*hashVerified)(?=[\s\S]*rollbackRevision)(?=[\s\S]*WorkflowHarnessRollbackRestoreCanary)(?=[\s\S]*rollbackRestoreCanary)(?=[\s\S]*WorkflowHarnessForkActivationCandidate)(?=[\s\S]*revisionBindingPreview: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationAuditEvent)(?=[\s\S]*previousRevisionBinding\?: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationRollbackProof)(?=[\s\S]*activeRevisionBinding\?: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationRollbackExecution)(?=[\s\S]*activationAudit\?: WorkflowHarnessActivationAuditEvent\[\])(?=[\s\S]*activationRollbackProof\?: WorkflowHarnessActivationRollbackProof)(?=[\s\S]*activationRollbackExecution\?: WorkflowHarnessActivationRollbackExecution)(?=[\s\S]*revisionBinding\?: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationCandidateGateResult)(?=[\s\S]*WorkflowHarnessLiveHandoffProof)(?=[\s\S]*WorkflowHarnessRuntimeSelectorDecision)(?=[\s\S]*WorkflowHarnessCanaryExecutionBoundary)(?=[\s\S]*canaryExecutionBoundaries)(?=[\s\S]*WorkflowHarnessComponentSpec[\s\S]*readiness[\s\S]*inputSchema[\s\S]*outputSchema[\s\S]*errorSchema)(?=[\s\S]*WorkflowHarnessWorkerBinding[\s\S]*harnessWorkflowId[\s\S]*harnessActivationId[\s\S]*harnessHash)/,
  "Harness contracts should declare mode, readiness, replay, callable adapter envelopes, collapsible group views, promotion clusters, activation candidates, live handoff, selector routing, canary execution boundaries, schemas, errors, and worker harness identity.",
);

assert.match(
  graphTypes,
  /WorkflowRevisionRestoreResult[\s\S]*receiptBindingRef\?: string[\s\S]*WorkflowHarnessRollbackRestoreCanary[\s\S]*receiptBindingRef\?: string[\s\S]*evidenceRefs/,
  "Rollback restore contracts should carry durable receipt binding refs from the backend restore canary into activation evidence.",
);

assert.match(
  graphTypes,
  /WorkflowHarnessActivationAuditEvent[\s\S]*receiptRefs: string\[\][\s\S]*WorkflowHarnessActivationRollbackExecution[\s\S]*receiptRefs: string\[\][\s\S]*restoreReceiptBindingRef\?: string/,
  "Activation audit and rollback execution contracts should preserve restore-canary receipt refs.",
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
  /(?=[\s\S]*workflowIsHarnessFork)(?=[\s\S]*harness_required_slot_unbound)(?=[\s\S]*harness_activation_not_validated)(?=[\s\S]*harness_self_mutation_not_proposal_only)(?=[\s\S]*createWorkflowHarnessActivationCandidate)(?=[\s\S]*activationIdPreview)(?=[\s\S]*workerBindingPreview)(?=[\s\S]*revisionBindingPreview)(?=[\s\S]*workflowRevisionBindingFor)(?=[\s\S]*rollback_restore_canary_not_run)(?=[\s\S]*gateId: "rollback-restore")(?=[\s\S]*dryRunOnly: true)/,
  "Harness readiness should block unvalidated forks and direct AI-authored self-mutation while activation dry runs produce non-mutating candidates.",
);

assert.match(
  harnessWorkflow,
  /(?=[\s\S]*workflowRevisionBindingFor)(?=[\s\S]*workflowSourceProjection)(?=[\s\S]*stableContentHash)(?=[\s\S]*recordWorkflowHarnessActivationDryRun)(?=[\s\S]*recordWorkflowHarnessRollbackTargetSelection)(?=[\s\S]*executeWorkflowHarnessRollbackDrill)(?=[\s\S]*rollback_drill_restored_previous_worker_binding)(?=[\s\S]*executeWorkflowHarnessRevisionRollback)(?=[\s\S]*restoredWorkflow)(?=[\s\S]*git_show_file_restore)(?=[\s\S]*rollback_execution_restored_verified_workflow_revision)(?=[\s\S]*rollback_executed)(?=[\s\S]*activationRollbackExecution)(?=[\s\S]*activeRevisionBinding)(?=[\s\S]*restoredRevisionBinding)(?=[\s\S]*applyWorkflowHarnessActivationCandidate)(?=[\s\S]*activation_mint_blocked)(?=[\s\S]*activation_minted)(?=[\s\S]*candidate_not_mintable)(?=[\s\S]*activation_id_missing)(?=[\s\S]*activationState: "validated")(?=[\s\S]*workerHarnessBinding: workerBinding)(?=[\s\S]*revisionBinding)(?=[\s\S]*rollbackRevisionBinding)(?=[\s\S]*rollbackTarget)(?=[\s\S]*componentVersionSet: candidate\.componentVersionSet)/,
  "Minting a fork activation should only apply mintable candidates, persist audit history, prove rollback drills, and update activation id, worker binding, rollback target, and component version set together.",
);

assert.match(
  harnessWorkflow,
  /(?=[\s\S]*activationCandidateReceiptRefs)(?=[\s\S]*recordWorkflowHarnessActivationDryRun[\s\S]*receiptRefs)(?=[\s\S]*activation_mint_blocked[\s\S]*receiptRefs)(?=[\s\S]*activation_minted[\s\S]*receiptRefs)(?=[\s\S]*workflowRollbackReceiptRefs)(?=[\s\S]*executeWorkflowHarnessRollbackDrill[\s\S]*receiptRefs)(?=[\s\S]*executeWorkflowHarnessRevisionRollback[\s\S]*restoreReceiptBindingRef)/,
  "Harness activation, rollback drill, and rollback execution should keep restore-canary receipt continuity.",
);

assert.match(
  workflowComposer,
  /(?=[\s\S]*workflow-open-default-harness)(?=[\s\S]*handleOpenDefaultHarness)(?=[\s\S]*workflow-fork-harness-button)(?=[\s\S]*handleForkDefaultHarness)(?=[\s\S]*handleRunHarnessActivationDryRun)(?=[\s\S]*runWorkflowHarnessRollbackRestoreCanaryProbe)(?=[\s\S]*recordWorkflowHarnessActivationDryRun)(?=[\s\S]*rollbackRestoreResult)(?=[\s\S]*rollbackRestoreBlockers)(?=[\s\S]*handleApplyHarnessActivationCandidate)(?=[\s\S]*applyWorkflowHarnessActivationCandidate)(?=[\s\S]*handleRunHarnessRollbackDrill)(?=[\s\S]*executeWorkflowHarnessRollbackDrill)(?=[\s\S]*handleExecuteHarnessRollback)(?=[\s\S]*restoreWorkflowRevision)(?=[\s\S]*executeWorkflowHarnessRevisionRollback)(?=[\s\S]*createWorkflowHarnessActivationCandidate)(?=[\s\S]*harnessActivationCandidate)(?=[\s\S]*selectedHarnessRollbackTarget)(?=[\s\S]*workflow-readonly-badge)(?=[\s\S]*workflow-harness-worker-binding)/,
  "Workflow composer should expose read-only harness inspection, a fork path, audited activation dry runs, rollback target selection, guarded activation minting, and rollback drill execution.",
);

assert.match(
  workflowComposer,
  /(?=[\s\S]*harnessGroupViews)(?=[\s\S]*selectedHarnessGroup)(?=[\s\S]*handleInspectHarnessGroupNode)(?=[\s\S]*collapsedHarnessGroupByNodeId)(?=[\s\S]*collapsedGroupEdge)(?=[\s\S]*workflow-harness-group-controls)(?=[\s\S]*workflow-harness-collapse-groups)(?=[\s\S]*workflow-harness-expand-groups)(?=[\s\S]*HARNESS_WORKBENCH_DEEP_LINK_PREFIX)(?=[\s\S]*encodeHarnessWorkbenchDeepLink)(?=[\s\S]*parseHarnessWorkbenchDeepLink)(?=[\s\S]*applyHarnessWorkbenchDeepLink)(?=[\s\S]*window\.history\.replaceState)(?=[\s\S]*navigator\.clipboard)(?=[\s\S]*selectedHarnessReceiptRef)(?=[\s\S]*selectedHarnessReplayFixtureRef)(?=[\s\S]*selectedHarnessSelectorDecisionId)(?=[\s\S]*selectedHarnessDefaultDispatchId)(?=[\s\S]*selectedHarnessWorkerBindingId)(?=[\s\S]*selectorDecisionId)(?=[\s\S]*dispatchId)(?=[\s\S]*workerBindingId)(?=[\s\S]*rollbackTarget)/,
  "Workflow composer should collapse, expand, select, inspect, deep-link, restore, and copy harness promotion cluster, active runtime binding, rollback, receipt, and replay state without mutating the saved component graph.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-settings-harness-summary)(?=[\s\S]*Mode)(?=[\s\S]*Live-ready)(?=[\s\S]*Gated clusters)(?=[\s\S]*workflow-harness-activation-wizard)(?=[\s\S]*workflow-harness-activation-wizard-summary)(?=[\s\S]*workflow-harness-activation-candidate)(?=[\s\S]*workflow-harness-activation-candidate-decision)(?=[\s\S]*workflow-harness-activation-candidate-worker-binding)(?=[\s\S]*workflow-harness-rollback-restore-canary)(?=[\s\S]*workflow-harness-worker-binding-rollback-targets)(?=[\s\S]*workflow-harness-worker-binding-rollback-target-\$\{index\})(?=[\s\S]*workflow-harness-worker-binding-apply-candidate)(?=[\s\S]*workflow-harness-worker-binding-run-rollback-drill)(?=[\s\S]*workflow-harness-worker-binding-execute-rollback)(?=[\s\S]*workflow-harness-rollback-drill-proof)(?=[\s\S]*workflow-harness-rollback-execution-proof)(?=[\s\S]*workflow-harness-git-restore-proof)(?=[\s\S]*workflow-harness-git-restore-summary)(?=[\s\S]*workflow-harness-git-restore-paths)(?=[\s\S]*workflow-harness-git-restore-hashes)(?=[\s\S]*workflow-harness-git-restore-blockers)(?=[\s\S]*harnessActivationRollbackExecution)(?=[\s\S]*workflow-harness-revision-binding)(?=[\s\S]*workflow-harness-revision-binding-current)(?=[\s\S]*workflow-harness-revision-binding-candidate)(?=[\s\S]*workflow-harness-revision-binding-rollback)(?=[\s\S]*harnessRevisionBinding)(?=[\s\S]*harnessCandidateRevisionBinding)(?=[\s\S]*harnessRollbackRevisionBinding)(?=[\s\S]*workflow-harness-activation-audit)(?=[\s\S]*workflow-harness-activation-audit-list)(?=[\s\S]*workflow-harness-activation-audit-event-\$\{event\.eventId\})(?=[\s\S]*onSelectHarnessRollbackTarget)(?=[\s\S]*onApplyHarnessActivationCandidate)(?=[\s\S]*onRunHarnessRollbackDrill)(?=[\s\S]*onExecuteHarnessRollback)(?=[\s\S]*workflow-harness-activation-candidate-gates)(?=[\s\S]*workflow-harness-activation-candidate-gate-\$\{gate\.gateId\})(?=[\s\S]*workflow-harness-activation-candidate-blockers)(?=[\s\S]*workflow-harness-activation-candidate-empty)(?=[\s\S]*workflow-harness-activation-dry-run)(?=[\s\S]*workflow-harness-activation-step-\$\{step\.id\})(?=[\s\S]*id: "slots")(?=[\s\S]*id: "tests")(?=[\s\S]*id: "replay-fixtures")(?=[\s\S]*id: "policy-posture")(?=[\s\S]*id: "receipt-coverage")(?=[\s\S]*id: "canary")(?=[\s\S]*id: "rollback-restore")(?=[\s\S]*id: "rollback")(?=[\s\S]*id: "activation-id")(?=[\s\S]*id: "worker-binding")(?=[\s\S]*workflow-harness-activation-blocked-proof)(?=[\s\S]*workflow-harness-activation-minted-proof)(?=[\s\S]*workflow-harness-activation-run-readiness)(?=[\s\S]*workflow-harness-activation-review-proposal)(?=[\s\S]*workflow-harness-slots)(?=[\s\S]*workflow-harness-promotion-clusters)(?=[\s\S]*workflow-harness-canary-execution-boundaries)(?=[\s\S]*workflow-harness-canary-execution-boundary)(?=[\s\S]*workflow-harness-default-runtime-dispatch)(?=[\s\S]*workflow-harness-read-only-routing-proof)(?=[\s\S]*workflow-harness-read-only-routing-node-kinds)(?=[\s\S]*workflow-harness-read-only-routing-receipts)(?=[\s\S]*workflow-harness-deep-link-state)(?=[\s\S]*workflow-copy-harness-deep-link)(?=[\s\S]*workflow-harness-group-inspector)(?=[\s\S]*workflow-harness-group-components)(?=[\s\S]*workflow-harness-group-receipt-refs)(?=[\s\S]*workflow-harness-group-receipt-ref-)(?=[\s\S]*workflow-harness-group-replay-fixtures)(?=[\s\S]*workflow-harness-group-replay-ref-)(?=[\s\S]*workflow-harness-group-shadow-comparison)(?=[\s\S]*workflow-run-harness-timeline)(?=[\s\S]*workflow-run-harness-shadow-comparison)(?=[\s\S]*workflow-selected-node-harness-component)(?=[\s\S]*workflow-selected-node-harness-receipts)(?=[\s\S]*workflow-selected-node-replay-binding)(?=[\s\S]*workflow-selected-node-harness-attempt)(?=[\s\S]*workflow-selected-node-read-only-routing-proof)(?=[\s\S]*workflow-selected-node-read-only-routing-receipts)(?=[\s\S]*workflow-selected-node-read-only-routing-no-mutation)(?=[\s\S]*replayEnvelope)/,
  "Rail inspection should render mode, readiness, component ids, activation wizard gates and dry-run candidates, slots, promotion clusters, deep-link controls, group inspectors, canary execution boundaries, default dispatch, read-only routing proof, receipt events, replay metadata, attempts, no-mutation proof, and shadow comparison.",
);

assert.match(
  workflowRailPanel,
  /workflow-harness-rollback-restore-canary[\s\S]*data-receipt-binding-ref[\s\S]*receiptBindingRef/,
  "Activation rail should expose rollback restore canary receipt bindings for GUI evidence.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-harness-activation-audit[\s\S]*data-receipt-refs[\s\S]*data-audit-receipt-refs)(?=[\s\S]*workflow-harness-rollback-execution-proof[\s\S]*data-restore-receipt-binding-ref)/,
  "Activation audit and rollback execution panels should expose receipt refs for GUI evidence.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-selected-receipt-ref)(?=[\s\S]*workflow-harness-activation-audit-summary-receipt-\$\{index\})(?=[\s\S]*workflow-harness-activation-audit-receipt-\$\{event\.eventId\}-\$\{index\})(?=[\s\S]*workflow-harness-rollback-drill-receipt-\$\{index\})(?=[\s\S]*workflow-harness-rollback-execution-receipt-\$\{index\})(?=[\s\S]*selectedHarnessReceiptRef === receiptRef)(?=[\s\S]*onSelectHarnessReceiptRef\?\.\(receiptRef\))/,
  "Activation audit and rollback receipt refs should be clickable deep-link controls with selected receipt state.",
);

assert.match(
  `${workflowRailPanel}\n${workflowComposer}\n${workflowValidation}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessActivationWizardStep)(?=[\s\S]*WorkflowHarnessActivationGateAction)(?=[\s\S]*gateAction)(?=[\s\S]*selectedHarnessActivationGateInspection)(?=[\s\S]*workflow-harness-activation-gate-inspector)(?=[\s\S]*workflow-harness-activation-gate-summary)(?=[\s\S]*workflow-harness-activation-gate-actions)(?=[\s\S]*workflow-harness-activation-gate-action)(?=[\s\S]*workflow-harness-activation-step-action-\$\{step\.id\})(?=[\s\S]*workflow-harness-activation-candidate-gate-action-\$\{gate\.gateId\})(?=[\s\S]*workflow-harness-activation-gate-evidence-refs)(?=[\s\S]*workflow-harness-activation-gate-receipt-refs)(?=[\s\S]*workflow-harness-activation-gate-replay-refs)(?=[\s\S]*data-evidence-ref-count)(?=[\s\S]*data-gate-action-id)(?=[\s\S]*data-gate-action-kind)(?=[\s\S]*data-gate-action-command)(?=[\s\S]*data-selected-activation-gate-evidence-ref)(?=[\s\S]*data-activation-gate-evidence-ref)(?=[\s\S]*activationGateEvidenceRef)(?=[\s\S]*activationGateReceiptRef)(?=[\s\S]*activationGateReplayFixtureRef)(?=[\s\S]*selectedRailTestId: "workflow-harness-activation-gate-inspector")(?=[\s\S]*gateResults:[\s\S]*evidenceRefs)(?=[\s\S]*activationGateEvidenceInspectable)(?=[\s\S]*activationGateActionWorkbench)(?=[\s\S]*routeStatefulActivationGateReferenceDeepLinks)(?=[\s\S]*harness_activation_gate_evidence_inspector)(?=[\s\S]*harness_activation_gate_evidence_inspector_present)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_action_workbench)(?=[\s\S]*harness_activation_gate_action_workbench_present)/,
  "Activation gate deep links should restore into a selected gate evidence inspector with evidence, receipt, and replay refs.",
);

assert.match(
  workflowComposer,
  /(?=[\s\S]*handleSelectHarnessReceiptRef[\s\S]*setSelectedHarnessReceiptRef\(receiptRef\))(?=[\s\S]*receiptRef: selectedHarnessReceiptRef)/,
  "Selecting a harness receipt should update the workbench deep link state.",
);

assert.match(
  `${workflowRailModel}\n${workflowRailPanel}`,
  /(?=[\s\S]*export function resolveWorkflowHarnessReceiptInspection)(?=[\s\S]*workflowHarnessReceiptKind)(?=[\s\S]*workflowRedactedReceiptPayload)(?=[\s\S]*selectedHarnessReceiptInspection)(?=[\s\S]*sourceKind: "node_attempt")(?=[\s\S]*sourceKind: "activation_audit")(?=[\s\S]*sourceKind: "rollback_execution")(?=[\s\S]*sourceKind: "default_runtime_dispatch")(?=[\s\S]*workflow-harness-receipt-inspector)(?=[\s\S]*data-receipt-source-kind)(?=[\s\S]*data-producer-component)(?=[\s\S]*workflow-harness-receipt-inspector-metadata)(?=[\s\S]*workflow-harness-receipt-payload-preview)(?=[\s\S]*workflow-harness-receipt-evidence-refs)/,
  "Selected harness receipts should resolve into a redacted receipt detail inspector with source, policy, attempt, replay, hashes, and evidence refs.",
);

assert.match(
  `${workflowRailModel}\n${workflowRailPanel}`,
  /(?=[\s\S]*export interface WorkflowHarnessReplayInspection)(?=[\s\S]*export function resolveWorkflowHarnessReplayInspection)(?=[\s\S]*workflowUniqueReplayFixtureRefs)(?=[\s\S]*selectedHarnessReplayInspection)(?=[\s\S]*sourceKind: "node_attempt")(?=[\s\S]*sourceKind: "gated_cluster")(?=[\s\S]*sourceKind: "runtime_binding")(?=[\s\S]*sourceKind: "default_runtime_dispatch")(?=[\s\S]*sourceKind: "read_only_routing_proof")(?=[\s\S]*sourceKind: "authority_gate_proof")(?=[\s\S]*sourceKind: "harness_group")(?=[\s\S]*workflow-harness-replay-inspector)(?=[\s\S]*data-replay-source-kind)(?=[\s\S]*data-determinism)(?=[\s\S]*workflow-harness-replay-inspector-metadata)(?=[\s\S]*workflow-harness-replay-capture-flags)(?=[\s\S]*workflow-harness-replay-payload-preview)(?=[\s\S]*workflow-harness-replay-evidence-refs)/,
  "Selected harness replay fixtures should resolve into a redacted fixture inspector with source, policy, attempt, receipt, determinism, capture flags, and evidence refs.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-harness-active-runtime-binding)(?=[\s\S]*data-binding-matched)(?=[\s\S]*data-selected-selector-decision-id)(?=[\s\S]*data-selected-default-dispatch-id)(?=[\s\S]*data-selected-worker-binding-id)(?=[\s\S]*data-selected-rollback-target)(?=[\s\S]*workflow-harness-active-runtime-binding-selector-link)(?=[\s\S]*selectorDecisionId)(?=[\s\S]*workflow-harness-active-runtime-binding-dispatch-link)(?=[\s\S]*dispatchId)(?=[\s\S]*workflow-harness-active-runtime-binding-worker-link)(?=[\s\S]*workerBindingId)(?=[\s\S]*workflow-harness-active-runtime-binding-rollback-link)(?=[\s\S]*rollbackTarget)(?=[\s\S]*workflow-harness-active-runtime-binding-receipt-\$\{index\})(?=[\s\S]*workflow-harness-active-runtime-binding-replay-\$\{index\})(?=[\s\S]*workflow-harness-active-runtime-binding-blockers)/,
  "The harness rail should expose route-restorable active runtime binding identity, links, receipts, replay fixtures, and activation blockers.",
);

assert.match(
  `${graphTypes}\n${harnessWorkflow}\n${workflowComposer}\n${workflowRailPanel}\n${workflowValidation}`,
  /(?=[\s\S]*WorkflowHarnessReplayDrillResult)(?=[\s\S]*WorkflowHarnessReplayGateResult)(?=[\s\S]*WorkflowHarnessPromotionClusterReplayGateProof)(?=[\s\S]*WorkflowHarnessReplayDrillDivergenceClass)(?=[\s\S]*replayGateProof\?: WorkflowHarnessPromotionClusterReplayGateProof)(?=[\s\S]*replayDrills\?: WorkflowHarnessReplayDrillResult\[\])(?=[\s\S]*replayGates\?: WorkflowHarnessReplayGateResult\[\])(?=[\s\S]*executeWorkflowHarnessReplayDrill)(?=[\s\S]*executeWorkflowHarnessReplayGate)(?=[\s\S]*workflowHarnessPromotionClustersWithReplayGateProof)(?=[\s\S]*replay_drill_passed)(?=[\s\S]*replay_gate_passed)(?=[\s\S]*replay_gate_blocked)(?=[\s\S]*handleRunHarnessReplayDrill)(?=[\s\S]*handleRunHarnessReplayGate)(?=[\s\S]*onRunHarnessReplayGate)(?=[\s\S]*workflow-harness-run-replay-drill)(?=[\s\S]*workflow-harness-run-replay-gate)(?=[\s\S]*workflow-harness-replay-gate-result)(?=[\s\S]*workflow-harness-promotion-cluster-replay-gate)(?=[\s\S]*workflow-harness-group-replay-gate-proof)(?=[\s\S]*data-replay-divergence-class)(?=[\s\S]*data-activation-gate-impact)(?=[\s\S]*replayDrillBlockers)(?=[\s\S]*replayGateBlockers)(?=[\s\S]*promotionClusterReplayGateBlockers)/,
  "Selected harness replay fixtures should run replay drills and batch replay gates, classify divergence, persist cluster replay gate proofs, surface receipt refs, and feed activation readiness.",
);

assert.match(
  `${graphTypes}\n${harnessWorkflow}\n${workflowComposer}\n${workflowRailPanel}`,
  /(?=[\s\S]*WorkflowHarnessPromotionTransitionEligibility)(?=[\s\S]*WorkflowHarnessPromotionTransitionAttempt)(?=[\s\S]*promotionStatus\?: WorkflowHarnessClusterPromotionStatus)(?=[\s\S]*promotionTransitions\?: WorkflowHarnessPromotionTransitionAttempt\[\])(?=[\s\S]*workflowHarnessPromotionTransitionEligibility)(?=[\s\S]*executeWorkflowHarnessPromotionTransition)(?=[\s\S]*promotion_transition_blocked)(?=[\s\S]*promotion_transition_promoted)(?=[\s\S]*handleRunHarnessPromotionTransition)(?=[\s\S]*onRunHarnessPromotionTransition)(?=[\s\S]*workflow-harness-group-promotion-actions)(?=[\s\S]*workflow-harness-promote-cluster-gated)(?=[\s\S]*workflow-harness-promote-cluster-live)(?=[\s\S]*workflow-harness-group-promotion-eligibility)(?=[\s\S]*workflow-harness-group-promotion-attempt)/,
  "Cluster promotion transitions should have typed eligibility, audited attempts, disabled GUI controls with blockers, and promoted status persistence.",
);

assert.match(
  `${guiHarnessValidation}\n${guiHarnessContract}\n${promotionTransitionGuiProbe}`,
  /(?=[\s\S]*collectPromotionTransitionGuiBehaviorProof)(?=[\s\S]*harness-promotion-transition-gui-probe\.mjs)(?=[\s\S]*harness_promotion_transition_gui_behavior)(?=[\s\S]*harness_promotion_transition_gui_behavior_present)(?=[\s\S]*promotionTransitionBehavior)(?=[\s\S]*render WorkflowRailPanel markup)(?=[\s\S]*blockedGatedButtonDisabled)(?=[\s\S]*liveClickPromotesCluster)/,
  "Autopilot GUI harness validation should require behavioral promotion control proof that renders the rail, invokes promotion transitions, and records blocked/gated/live attempts.",
);

assert.match(
  `${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*VITE_AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI)(?=[\s\S]*HARNESS_PROMOTION_LIVE_GUI_SCRIPT)(?=[\s\S]*__AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI_RESULT)(?=[\s\S]*handleHarnessPromotionLiveGuiProbe)(?=[\s\S]*runHarnessDeepLinkReplayProbe)(?=[\s\S]*runHarnessColdStartDeepLinkRestoreProbe)(?=[\s\S]*runHarnessActivationBlockerDeepLinkProbe)(?=[\s\S]*runHarnessActivationGateDeepLinkProbe)(?=[\s\S]*default-agent-harness-live-gui-promotion-proof\.workflow\.json)(?=[\s\S]*collectPromotionTransitionLiveGuiInteractionProof)(?=[\s\S]*promotion-transition-live-gui-interaction-proof\.json)(?=[\s\S]*routeStatefulDeepLinks)(?=[\s\S]*routeStatefulActiveRuntimeBindingDeepLinks)(?=[\s\S]*routeStatefulRevisionBindingDeepLink)(?=[\s\S]*routeStatefulActivationBlockerDeepLink)(?=[\s\S]*routeStatefulActivationAuditDeepLink)(?=[\s\S]*routeStatefulActivationGateDeepLink)(?=[\s\S]*routeStatefulActivationGateReferenceDeepLinks)(?=[\s\S]*activationGateActionWorkbench)(?=[\s\S]*revisionBindingKind)(?=[\s\S]*revisionBindingRef)(?=[\s\S]*activationBlockerRef)(?=[\s\S]*activationAuditEventId)(?=[\s\S]*activationGateId)(?=[\s\S]*activationGateEvidenceRef)(?=[\s\S]*activationGateReceiptRef)(?=[\s\S]*activationGateReplayFixtureRef)(?=[\s\S]*deepLinkReplayProof)(?=[\s\S]*coldStartDeepLinkRestoreProof)(?=[\s\S]*activationBlockerDeepLinkProof)(?=[\s\S]*activationGateDeepLinkProof)(?=[\s\S]*routeStatefulDeepLinkReplay)(?=[\s\S]*coldStartDeepLinkRestore)(?=[\s\S]*harness_route_stateful_deep_link_replay)(?=[\s\S]*harness_route_stateful_deep_link_replay_present)(?=[\s\S]*harness_cold_start_deep_link_restore)(?=[\s\S]*harness_cold_start_deep_link_restore_present)(?=[\s\S]*harness_revision_binding_deep_link_restore)(?=[\s\S]*harness_revision_binding_deep_link_restore_present)(?=[\s\S]*harness_activation_blocker_deep_link_restore)(?=[\s\S]*harness_activation_blocker_deep_link_restore_present)(?=[\s\S]*harness_activation_audit_deep_link_restore)(?=[\s\S]*harness_activation_audit_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_deep_link_restore)(?=[\s\S]*harness_activation_gate_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_action_workbench)(?=[\s\S]*harness_activation_gate_action_workbench_present)(?=[\s\S]*harness_promotion_transition_live_gui_interaction)(?=[\s\S]*harness_promotion_transition_live_gui_interaction_present)(?=[\s\S]*harness_chat_runtime_binding)(?=[\s\S]*harness_chat_runtime_binding_matches_workflow_activation)(?=[\s\S]*HarnessDefaultRuntimeBinding)(?=[\s\S]*harnessDefaultRuntimeBindingMatchedCount)(?=[\s\S]*promotionTransitionLiveGui)/,
  "Autopilot GUI harness validation should launch the live Workflows surface and require saved-workflow, screenshot, route-stateful active binding, and replay-hydration proof for promotion controls.",
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
