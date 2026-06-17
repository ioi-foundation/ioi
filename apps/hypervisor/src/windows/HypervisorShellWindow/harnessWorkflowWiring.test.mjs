import assert from "node:assert/strict";
import fs from "node:fs";

const graphTypes = fs.readFileSync(
  new URL(
    "../../../../../packages/hypervisor-workbench/src/types/graph.ts",
    import.meta.url,
  ),
  "utf8",
);
const harnessWorkflow = fs.readFileSync(
  new URL(
    "../../../../../packages/hypervisor-workbench/src/runtime/harness-workflow/core.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowComposer = [
  "../../../../../packages/hypervisor-workbench/src/WorkflowComposer.tsx",
  "../../../../../packages/hypervisor-workbench/src/WorkflowComposer/content.tsx",
  "../../../../../packages/hypervisor-workbench/src/WorkflowComposer/support.tsx",
  "../../../../../packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx",
  "../../../../../packages/hypervisor-workbench/src/WorkflowComposer/view.tsx",
]
  .map((path) => fs.readFileSync(new URL(path, import.meta.url), "utf8"))
  .join("\n");
const workflowRailPanelDir = new URL(
  "../../../../../packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/",
  import.meta.url,
);
const workflowRailPanel = fs
  .readdirSync(workflowRailPanelDir)
  .filter((name) => /\.(ts|tsx)$/.test(name))
  .map((name) => fs.readFileSync(new URL(name, workflowRailPanelDir), "utf8"))
  .join("\n");
const workflowRailModel = fs.readFileSync(
  new URL(
    "../../../../../packages/hypervisor-workbench/src/runtime/workflow-rail-model.ts",
    import.meta.url,
  ),
  "utf8",
);
const workflowValidation = fs.readFileSync(
  new URL(
    "../../../../../packages/hypervisor-workbench/src/runtime/workflow-validation.ts",
    import.meta.url,
  ),
  "utf8",
);
const rustHarnessService = fs.readFileSync(
  new URL(
    "../../../../../crates/services/src/agentic/runtime/harness.rs",
    import.meta.url,
  ),
  "utf8",
);
const guiHarnessValidation = fs.readFileSync(
  new URL(
    "../../../../../scripts/lib/hypervisor-app-harness-validation/core.mjs",
    import.meta.url,
  ),
  "utf8",
);
const guiHarnessContract = fs.readFileSync(
  new URL(
    "../../../../../scripts/lib/hypervisor-app-harness-contract.mjs",
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
  /(?=[\s\S]*WorkflowHarnessExecutionMode)(?=[\s\S]*WorkflowHarnessComponentReadiness)(?=[\s\S]*WorkflowHarnessReplayEnvelope)(?=[\s\S]*WorkflowHarnessActionFrame)(?=[\s\S]*WorkflowHarnessComponentInvocation)(?=[\s\S]*WorkflowHarnessComponentAdapterResult)(?=[\s\S]*WorkflowHarnessGroupView)(?=[\s\S]*WorkflowHarnessPromotionCluster)(?=[\s\S]*WorkflowHarnessGatedClusterRun)(?=[\s\S]*WorkflowRevisionBinding)(?=[\s\S]*WorkflowRevisionRestoreRequest)(?=[\s\S]*dryRun\?: boolean)(?=[\s\S]*WorkflowRevisionRestoreResult)(?=[\s\S]*git_show_file_restore)(?=[\s\S]*workflowContentHash)(?=[\s\S]*actualWorkflowContentHash)(?=[\s\S]*hashVerified)(?=[\s\S]*rollbackRevision)(?=[\s\S]*WorkflowHarnessRollbackRestoreCanary)(?=[\s\S]*rollbackRestoreCanary)(?=[\s\S]*WorkflowHarnessForkActivationCandidate)(?=[\s\S]*revisionBindingPreview: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationAuditEvent)(?=[\s\S]*previousRevisionBinding\?: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationRollbackProof)(?=[\s\S]*activeRevisionBinding\?: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationRollbackExecution)(?=[\s\S]*WorkflowHarnessActiveRuntimeRollbackExecutionProof)(?=[\s\S]*WorkflowHarnessActiveRuntimeRollbackApplyProof)(?=[\s\S]*WorkflowHarnessActiveRuntimeRollbackNegativeApplyProof)(?=[\s\S]*activeRuntimeRollbackExecutionProof\?: WorkflowHarnessActiveRuntimeRollbackExecutionProof)(?=[\s\S]*activeRuntimeRollbackApplyProof\?: WorkflowHarnessActiveRuntimeRollbackApplyProof)(?=[\s\S]*activeRuntimeRollbackNegativeApplyProof\?: WorkflowHarnessActiveRuntimeRollbackNegativeApplyProof)(?=[\s\S]*activationAudit\?: WorkflowHarnessActivationAuditEvent\[\])(?=[\s\S]*activationRollbackProof\?: WorkflowHarnessActivationRollbackProof)(?=[\s\S]*activationRollbackExecution\?: WorkflowHarnessActivationRollbackExecution)(?=[\s\S]*revisionBinding\?: WorkflowRevisionBinding)(?=[\s\S]*WorkflowHarnessActivationCandidateGateResult)(?=[\s\S]*WorkflowHarnessLiveHandoffProof)(?=[\s\S]*WorkflowHarnessRuntimeSelectorDecision)(?=[\s\S]*WorkflowHarnessCanaryExecutionBoundary)(?=[\s\S]*canaryExecutionBoundaries)(?=[\s\S]*WorkflowHarnessComponentSpec[\s\S]*readiness[\s\S]*inputSchema[\s\S]*outputSchema[\s\S]*errorSchema)(?=[\s\S]*WorkflowHarnessWorkerBinding[\s\S]*harnessWorkflowId[\s\S]*harnessActivationId[\s\S]*harnessHash)/,
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
	  graphTypes,
	  /(?=[\s\S]*WorkflowHarnessForkMutationCanary)(?=[\s\S]*workflow\.harness\.fork-mutation-canary\.v1)(?=[\s\S]*WorkflowHarnessPackageEvidenceManifest)(?=[\s\S]*workflow\.harness\.package-evidence-manifest\.v1)(?=[\s\S]*forkMutationCanary\?: WorkflowHarnessForkMutationCanary)(?=[\s\S]*forkMutationCanaryReceiptRefs: string\[\])(?=[\s\S]*workerHandoffNodeAttemptIds: string\[\])(?=[\s\S]*rollbackRestoreReceiptRefs: string\[\])(?=[\s\S]*deepLinks: WorkflowHarnessPackageEvidenceLink\[\])(?=[\s\S]*packageManifest\?: WorkflowHarnessPackageEvidenceManifest)(?=[\s\S]*harnessPackageManifest\?: WorkflowHarnessPackageEvidenceManifest)/,
  "Harness contracts should package fork evidence, receipt refs, replay refs, worker handoff attempts, rollback restore refs, and deep links for portable workflow bundles.",
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
	  /(?=[\s\S]*workflowIsHarnessFork)(?=[\s\S]*harness_required_slot_unbound)(?=[\s\S]*harness_activation_not_validated)(?=[\s\S]*harness_self_mutation_not_proposal_only)(?=[\s\S]*harness_fork_mutation_canary_not_passed)(?=[\s\S]*harness_package_manifest_incomplete)(?=[\s\S]*workflowHarnessPackageEvidenceReview)(?=[\s\S]*createWorkflowHarnessActivationCandidate)(?=[\s\S]*activationIdPreview)(?=[\s\S]*workerBindingPreview)(?=[\s\S]*revisionBindingPreview)(?=[\s\S]*workflowRevisionBindingFor)(?=[\s\S]*rollback_restore_canary_not_run)(?=[\s\S]*gateId: "mutation-canary")(?=[\s\S]*gateId: "package-evidence")(?=[\s\S]*gateId: "rollback-restore")(?=[\s\S]*dryRunOnly: true)/,
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
	  harnessWorkflow,
	  /(?=[\s\S]*harnessWorkbenchDeepLinkHash)(?=[\s\S]*makeWorkflowHarnessPackageEvidenceManifest)(?=[\s\S]*makeWorkflowHarnessForkMutationCanary)(?=[\s\S]*workflow\.harness\.package-evidence-manifest\.v1)(?=[\s\S]*fork_mutation_canary)(?=[\s\S]*withWorkflowHarnessPackageManifest)(?=[\s\S]*canary_boundary)(?=[\s\S]*rollback_drill)(?=[\s\S]*rollback_restore)(?=[\s\S]*worker_handoff)(?=[\s\S]*activationGateNodeAttemptId)(?=[\s\S]*activationGateReceiptRef)/,
  "Harness workflow packaging should mint route-restorable evidence deep links for activation gates, rollback restore canaries, and worker handoff node attempts.",
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
	  /(?=[\s\S]*workflow-settings-harness-summary)(?=[\s\S]*Mode)(?=[\s\S]*Live-ready)(?=[\s\S]*Gated clusters)(?=[\s\S]*workflow-harness-activation-wizard)(?=[\s\S]*workflow-harness-activation-wizard-summary)(?=[\s\S]*workflow-harness-activation-candidate)(?=[\s\S]*workflow-harness-activation-candidate-decision)(?=[\s\S]*workflow-harness-fork-mutation-canary)(?=[\s\S]*workflow-harness-activation-candidate-worker-binding)(?=[\s\S]*workflow-harness-rollback-restore-canary)(?=[\s\S]*workflow-harness-worker-binding-rollback-targets)(?=[\s\S]*workflow-harness-worker-binding-rollback-target-\$\{index\})(?=[\s\S]*workflow-harness-worker-binding-apply-candidate)(?=[\s\S]*workflow-harness-worker-binding-run-rollback-drill)(?=[\s\S]*workflow-harness-worker-binding-execute-rollback)(?=[\s\S]*workflow-harness-rollback-drill-proof)(?=[\s\S]*workflow-harness-rollback-execution-proof)(?=[\s\S]*workflow-harness-git-restore-proof)(?=[\s\S]*workflow-harness-git-restore-summary)(?=[\s\S]*workflow-harness-git-restore-paths)(?=[\s\S]*workflow-harness-git-restore-hashes)(?=[\s\S]*workflow-harness-git-restore-blockers)(?=[\s\S]*harnessActivationRollbackExecution)(?=[\s\S]*workflow-harness-revision-binding)(?=[\s\S]*workflow-harness-revision-binding-current)(?=[\s\S]*workflow-harness-revision-binding-candidate)(?=[\s\S]*workflow-harness-revision-binding-rollback)(?=[\s\S]*harnessRevisionBinding)(?=[\s\S]*harnessCandidateRevisionBinding)(?=[\s\S]*harnessRollbackRevisionBinding)(?=[\s\S]*workflow-harness-activation-audit)(?=[\s\S]*workflow-harness-activation-audit-list)(?=[\s\S]*workflow-harness-activation-audit-event-\$\{event\.eventId\})(?=[\s\S]*onSelectHarnessRollbackTarget)(?=[\s\S]*onApplyHarnessActivationCandidate)(?=[\s\S]*onRunHarnessRollbackDrill)(?=[\s\S]*onExecuteHarnessRollback)(?=[\s\S]*workflow-harness-activation-candidate-gates)(?=[\s\S]*workflow-harness-activation-candidate-gate-\$\{gate\.gateId\})(?=[\s\S]*workflow-harness-activation-candidate-blockers)(?=[\s\S]*workflow-harness-activation-candidate-empty)(?=[\s\S]*workflow-harness-activation-dry-run)(?=[\s\S]*workflow-harness-activation-step-\$\{step\.id\})(?=[\s\S]*id: "slots")(?=[\s\S]*id: "tests")(?=[\s\S]*id: "replay-fixtures")(?=[\s\S]*id: "policy-posture")(?=[\s\S]*id: "mutation-canary")(?=[\s\S]*id: "receipt-coverage")(?=[\s\S]*id: "package-evidence")(?=[\s\S]*id: "canary")(?=[\s\S]*id: "rollback-restore")(?=[\s\S]*id: "rollback")(?=[\s\S]*id: "activation-id")(?=[\s\S]*id: "worker-binding")(?=[\s\S]*id: "worker-invariant")(?=[\s\S]*workflow-harness-activation-blocked-proof)(?=[\s\S]*workflow-harness-activation-minted-proof)(?=[\s\S]*workflow-harness-activation-run-readiness)(?=[\s\S]*workflow-harness-activation-review-proposal)(?=[\s\S]*workflow-harness-slots)(?=[\s\S]*workflow-harness-promotion-clusters)(?=[\s\S]*workflow-harness-canary-execution-boundaries)(?=[\s\S]*workflow-harness-canary-execution-boundary)(?=[\s\S]*workflow-harness-default-runtime-dispatch)(?=[\s\S]*workflow-harness-read-only-routing-proof)(?=[\s\S]*workflow-harness-read-only-routing-node-kinds)(?=[\s\S]*workflow-harness-read-only-routing-receipts)(?=[\s\S]*workflow-harness-deep-link-state)(?=[\s\S]*workflow-copy-harness-deep-link)(?=[\s\S]*workflow-harness-group-inspector)(?=[\s\S]*workflow-harness-group-components)(?=[\s\S]*workflow-harness-group-receipt-refs)(?=[\s\S]*workflow-harness-group-receipt-ref-)(?=[\s\S]*workflow-harness-group-replay-fixtures)(?=[\s\S]*workflow-harness-group-replay-ref-)(?=[\s\S]*workflow-harness-group-shadow-comparison)(?=[\s\S]*workflow-run-harness-timeline)(?=[\s\S]*workflow-run-harness-timeline-node-\$\{attempt\.attemptId\})(?=[\s\S]*workflow-run-harness-shadow-comparison)(?=[\s\S]*workflow-harness-node-attempt-inspector)(?=[\s\S]*workflow-harness-live-shadow-comparison-inspector)(?=[\s\S]*data-shadow-attempt-id)(?=[\s\S]*data-live-replay-fixture-ref)(?=[\s\S]*data-harness-workflow-id)(?=[\s\S]*data-replay-fixture-ref)(?=[\s\S]*workflow-selected-node-harness-component)(?=[\s\S]*workflow-selected-node-harness-receipts)(?=[\s\S]*workflow-selected-node-replay-binding)(?=[\s\S]*workflow-selected-node-harness-attempt)(?=[\s\S]*workflow-selected-node-read-only-routing-proof)(?=[\s\S]*workflow-selected-node-read-only-routing-receipts)(?=[\s\S]*workflow-selected-node-read-only-routing-no-mutation)(?=[\s\S]*replayEnvelope)/,
  "Rail inspection should render mode, readiness, component ids, activation wizard gates and dry-run candidates, slots, promotion clusters, deep-link controls, group inspectors, canary execution boundaries, default dispatch, read-only routing proof, receipt events, replay metadata, attempts, no-mutation proof, and shadow comparison.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-cognition-node-authority-mode)(?=[\s\S]*data-cognition-node-authority-authoritative)(?=[\s\S]*data-cognition-node-authority-policy-decision)(?=[\s\S]*data-cognition-node-authority-replay-fixture-refs)/,
  "Default runtime dispatch should expose node-authoritative cognition gate state, policy, receipts, and replay refs in the rail.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-routing-model-node-authority-mode)(?=[\s\S]*data-routing-model-node-authority-authoritative)(?=[\s\S]*data-routing-model-node-authority-policy-decision)(?=[\s\S]*data-routing-model-node-authority-replay-fixture-refs)/,
  "Default runtime dispatch should expose gated node-authoritative routing/model gate state, policy, receipts, and replay refs in the rail.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-verification-output-node-authority-mode)(?=[\s\S]*data-verification-output-node-authority-authoritative)(?=[\s\S]*data-verification-output-node-authority-policy-decision)(?=[\s\S]*data-verification-output-node-authority-visible-write-committed)(?=[\s\S]*data-verification-output-node-authority-replay-fixture-refs)/,
  "Default runtime dispatch should expose gated node-authoritative verification/output gate state, visible-write readiness, receipts, and replay refs in the rail.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*data-authority-tooling-node-authority-mode)(?=[\s\S]*data-authority-tooling-node-authority-authoritative)(?=[\s\S]*data-authority-tooling-node-authority-policy-decision)(?=[\s\S]*data-authority-tooling-node-authority-read-only-route-accepted)(?=[\s\S]*data-authority-tooling-node-authority-destructive-route-denied)(?=[\s\S]*data-authority-tooling-node-authority-replay-fixture-refs)/,
  "Default runtime dispatch should expose gated node-authoritative authority/tooling gate state, route decisions, receipts, and replay refs in the rail.",
);

assert.match(
  workflowRailPanel,
  /workflow-harness-rollback-restore-canary[\s\S]*data-receipt-binding-ref[\s\S]*receiptBindingRef/,
  "Activation rail should expose rollback restore canary receipt bindings for GUI evidence.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-package-summary)(?=[\s\S]*harnessPackageManifest)(?=[\s\S]*data-harness-package-manifest-present)(?=[\s\S]*data-harness-package-receipt-ref-count)(?=[\s\S]*data-harness-package-replay-fixture-ref-count)(?=[\s\S]*data-harness-package-deep-link-count)/,
  "Package export UI should expose harness package evidence manifest presence, receipt coverage, replay fixture coverage, and deep-link counts for GUI validation.",
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
  /(?=[\s\S]*WorkflowHarnessActivationWizardStep)(?=[\s\S]*WorkflowHarnessActivationGateAction)(?=[\s\S]*WorkflowHarnessActivationGateActionClickProof)(?=[\s\S]*gateAction)(?=[\s\S]*runHarnessActivationGateActionClickProbe)(?=[\s\S]*selectedHarnessActivationGateInspection)(?=[\s\S]*workflow-harness-activation-gate-inspector)(?=[\s\S]*workflow-harness-activation-gate-summary)(?=[\s\S]*workflow-harness-activation-gate-actions)(?=[\s\S]*workflow-harness-activation-gate-action)(?=[\s\S]*workflow-harness-activation-step-action-\$\{step\.id\})(?=[\s\S]*workflow-harness-activation-candidate-gate-action-\$\{gate\.gateId\})(?=[\s\S]*workflow-harness-activation-gate-evidence-refs)(?=[\s\S]*workflow-harness-activation-gate-node-attempt-refs)(?=[\s\S]*workflow-harness-activation-gate-node-timeline)(?=[\s\S]*workflow-harness-activation-gate-receipt-refs)(?=[\s\S]*workflow-harness-activation-gate-replay-refs)(?=[\s\S]*data-evidence-ref-count)(?=[\s\S]*data-node-attempt-ref-count)(?=[\s\S]*data-gate-action-id)(?=[\s\S]*data-gate-action-kind)(?=[\s\S]*data-gate-action-command)(?=[\s\S]*data-selected-activation-gate-evidence-ref)(?=[\s\S]*data-selected-activation-gate-node-attempt-id)(?=[\s\S]*data-activation-gate-evidence-ref)(?=[\s\S]*data-activation-gate-node-attempt-id)(?=[\s\S]*activationGateEvidenceRef)(?=[\s\S]*activationGateNodeAttemptId)(?=[\s\S]*activationGateReceiptRef)(?=[\s\S]*activationGateReplayFixtureRef)(?=[\s\S]*selectedRailTestId: "workflow-harness-activation-gate-inspector")(?=[\s\S]*gateResults:[\s\S]*evidenceRefs)(?=[\s\S]*activationGateEvidenceInspectable)(?=[\s\S]*activationGateActionWorkbench)(?=[\s\S]*activationGateActionClickProof)(?=[\s\S]*routeStatefulActivationGateReferenceDeepLinks)(?=[\s\S]*harness_activation_gate_evidence_inspector)(?=[\s\S]*harness_activation_gate_evidence_inspector_present)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_action_workbench)(?=[\s\S]*harness_activation_gate_action_workbench_present)(?=[\s\S]*harness_activation_gate_action_click_proof)(?=[\s\S]*harness_activation_gate_action_click_proof_present)/,
  "Activation gate deep links should restore into a selected gate evidence inspector with evidence, receipt, and replay refs.",
);

assert.match(
  `${workflowRailPanel}\n${workflowComposer}\n${guiHarnessValidation}`,
  /(?=[\s\S]*workflow-harness-canary-execution-boundaries)(?=[\s\S]*data-selected-canary-boundary-id)(?=[\s\S]*data-selected-rollback-drill-id)(?=[\s\S]*data-canary-boundary-id)(?=[\s\S]*data-rollback-drill-id)(?=[\s\S]*activation-gate-canary-boundary)(?=[\s\S]*activation-gate-canary-rollback-drill)(?=[\s\S]*routeStatefulActivationGateReferenceDeepLinks)/,
  "Canary boundary and rollback drill rows should be route-stateful activation gate deep-link targets.",
);

assert.match(
  `${graphTypes}\n${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessActivationGateCollectEvidenceClickProof)(?=[\s\S]*runHarnessActivationGateCollectEvidenceClickProbe)(?=[\s\S]*activationGateCollectEvidenceClickProof)(?=[\s\S]*activationGateReplayFixtureRefs)(?=[\s\S]*selectedHarnessActivationGateId === "replay-fixtures")(?=[\s\S]*__AUTOPILOT_HARNESS_REPLAY_GATE_CLICK_RESULT)(?=[\s\S]*workflow-harness-gate-action-replay-fixtures)(?=[\s\S]*harness_activation_gate_collect_evidence_click_proof)(?=[\s\S]*harness_activation_gate_collect_evidence_click_proof_present)/,
  "Activation replay fixture gate actions should have live click proof that collects persisted replay-gate evidence.",
);

assert.match(
  `${graphTypes}\n${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessActivationGateRollbackRestoreClickProof)(?=[\s\S]*runHarnessActivationGateRollbackRestoreClickProbe)(?=[\s\S]*activationGateRollbackRestoreClickProof)(?=[\s\S]*__AUTOPILOT_HARNESS_ACTIVATION_DRY_RUN_CLICK_RESULT)(?=[\s\S]*workflow-harness-gate-action-rollback-restore)(?=[\s\S]*rollbackRestoreReceiptBindingRef)(?=[\s\S]*rollbackRestoreDeepLink)(?=[\s\S]*data-selected-rollback-restore-canary-id)(?=[\s\S]*harness_activation_gate_rollback_restore_click_proof)(?=[\s\S]*harness_activation_gate_rollback_restore_click_proof_present)/,
  "Rollback restore activation gate actions should have live click proof that collects restore canary receipt evidence.",
);

assert.match(
  `${graphTypes}\n${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessActivationIdGateClickProof)(?=[\s\S]*workflowHarnessActivationIdGateClickProofBlockers)(?=[\s\S]*activation_id_gate_click_proof_missing)(?=[\s\S]*runHarnessActivationIdGateClickProbe)(?=[\s\S]*activationIdGateClickProof)(?=[\s\S]*__AUTOPILOT_HARNESS_ACTIVATION_MINT_CLICK_RESULT)(?=[\s\S]*workflow-harness-gate-action-activation-id)(?=[\s\S]*workerHandoffDeepLink)(?=[\s\S]*workerHandoffTimelineVisible)(?=[\s\S]*activation_id_gate_mint_handoff_timeline_missing)(?=[\s\S]*activationIdBlockedDryRunDecision)(?=[\s\S]*activationIdMintedActivationId)(?=[\s\S]*harness_activation_id_gate_click_proof)(?=[\s\S]*harness_activation_id_gate_click_proof_present)/,
  "Activation id gate actions should have live click proof for both blocked dry-run and minting paths.",
);

assert.match(
  `${graphTypes}\n${workflowRailPanel}\n${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
	  /(?=[\s\S]*WorkflowHarnessPackageEvidenceGateClickProof)(?=[\s\S]*runHarnessPackageEvidenceGateClickProbe)(?=[\s\S]*packageEvidenceGateClickProof)(?=[\s\S]*workflow-harness-package-evidence-review)(?=[\s\S]*workflow-harness-package-evidence-row-\$\{row\.id\})(?=[\s\S]*workflow-harness-package-evidence-row-ref-\$\{row\.id\}-\$\{index\})(?=[\s\S]*data-harness-package-evidence-ready)(?=[\s\S]*data-harness-package-fork-mutation-receipt-count)(?=[\s\S]*data-harness-package-receipt-ref-count)(?=[\s\S]*data-harness-package-replay-fixture-ref-count)(?=[\s\S]*data-harness-package-worker-handoff-attempt-count)(?=[\s\S]*workflowHarnessPackageDeepLinkTarget)(?=[\s\S]*harness_package_evidence_gate_click_proof)(?=[\s\S]*harness_package_evidence_gate_click_proof_present)/,
  "Package evidence activation gates should have a live click-through proof with inspectable manifest rows and route-restorable refs.",
);

assert.match(
  `${graphTypes}\n${harnessWorkflow}\n${workflowRailPanel}\n${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*WorkflowHarnessPackageEvidenceImportRoundTripProof)(?=[\s\S]*WorkflowHarnessPackageImportReviewProof)(?=[\s\S]*WorkflowHarnessPackageImportActivationHandoffProof)(?=[\s\S]*WorkflowHarnessPackageImportActivationApplyProof)(?=[\s\S]*WorkflowHarnessPackageImportActivationReplayIntegrityProof)(?=[\s\S]*WorkflowPackageImportReview)(?=[\s\S]*WorkflowPackageImportActivationHandoff)(?=[\s\S]*workflowHarnessPackageImportActivationApplyProofBlockers)(?=[\s\S]*package_import_activation_replay_integrity_snapshot_hash_mismatch)(?=[\s\S]*package_import_activation_replay_integrity_workflow_hash_mismatch)(?=[\s\S]*package_import_activation_apply_proof_missing)(?=[\s\S]*defaultLivePromotionInvariantBlockers)(?=[\s\S]*reviewedImportActivationApplyGate)(?=[\s\S]*reviewedPackageSnapshotHash)(?=[\s\S]*reviewed_import_activation_apply)(?=[\s\S]*runHarnessPackageEvidenceImportRoundTripProbe)(?=[\s\S]*packageEvidenceImportRoundTripProof)(?=[\s\S]*packageImportReviewProof)(?=[\s\S]*packageImportActivationHandoffProof)(?=[\s\S]*packageImportActivationApplyProof)(?=[\s\S]*packageImportActivationReplayIntegrityProof)(?=[\s\S]*exportWorkflowPackage)(?=[\s\S]*importWorkflowPackage)(?=[\s\S]*workflow-harness-package-import-review)(?=[\s\S]*workflow-harness-package-import-handoff)(?=[\s\S]*workflow-harness-package-import-handoff-activation-link)(?=[\s\S]*workflow-harness-package-import-handoff-canary-link)(?=[\s\S]*workflow-harness-package-import-handoff-rollback-link)(?=[\s\S]*workflow-harness-package-import-handoff-worker-link)(?=[\s\S]*workflow-harness-package-import-activate)(?=[\s\S]*data-package-import-source-reviewed-package-snapshot-hash)(?=[\s\S]*data-package-import-source-workflow-path)(?=[\s\S]*data-package-import-imported-workflow-path)(?=[\s\S]*data-package-import-handoff-reviewed-package-snapshot-hash)(?=[\s\S]*data-package-import-handoff-worker-binding-id)(?=[\s\S]*data-package-import-replay-integrity-blocker-count)(?=[\s\S]*packageEvidenceImportRoundTripPassed)(?=[\s\S]*packageImportReviewPassed)(?=[\s\S]*packageImportActivationHandoffPassed)(?=[\s\S]*packageImportActivationApplyPassed)(?=[\s\S]*packageImportActivationReplayIntegrityPassed)(?=[\s\S]*harness_package_evidence_import_roundtrip)(?=[\s\S]*harness_package_import_review_mode)(?=[\s\S]*harness_package_import_activation_handoff)(?=[\s\S]*harness_package_import_activation_apply)(?=[\s\S]*harness_package_import_activation_replay_integrity)(?=[\s\S]*harness_selector_reviewed_import_activation_apply_invariant)(?=[\s\S]*harness_package_import_review_mode_present)(?=[\s\S]*harness_package_import_activation_handoff_present)(?=[\s\S]*harness_package_import_activation_apply_present)(?=[\s\S]*harness_package_import_activation_replay_integrity_present)(?=[\s\S]*harness_selector_reviewed_import_activation_apply_invariant_present)/,
  "Package evidence should prove export/import round-trip preservation, open source/import activation review, expose the reviewed-import activation handoff, and commit that reviewed activation.",
);

assert.match(
  workflowComposer,
  /(?=[\s\S]*handleSelectHarnessReceiptRef[\s\S]*setSelectedHarnessReceiptRef\(receiptRef\))(?=[\s\S]*receiptRef: selectedHarnessReceiptRef)/,
  "Selecting a harness receipt should update the workbench deep link state.",
);

assert.match(
  `${workflowRailModel}\n${workflowRailPanel}`,
  /(?=[\s\S]*export function resolveWorkflowHarnessReceiptInspection)(?=[\s\S]*workflowHarnessReceiptKind)(?=[\s\S]*workflowRedactedReceiptPayload)(?=[\s\S]*selectedHarnessReceiptInspection)(?=[\s\S]*sourceKind: "node_attempt")(?=[\s\S]*sourceKind: "activation_audit")(?=[\s\S]*sourceKind: "activation_worker_handoff")(?=[\s\S]*sourceKind: "rollback_execution")(?=[\s\S]*sourceKind: "default_runtime_dispatch")(?=[\s\S]*workflow-harness-receipt-inspector)(?=[\s\S]*data-receipt-source-kind)(?=[\s\S]*data-producer-component)(?=[\s\S]*workflow-harness-receipt-inspector-metadata)(?=[\s\S]*workflow-harness-receipt-payload-preview)(?=[\s\S]*workflow-harness-receipt-evidence-refs)/,
  "Selected harness receipts should resolve into a redacted receipt detail inspector with source, policy, attempt, replay, hashes, and evidence refs.",
);

assert.match(
  `${workflowRailModel}\n${workflowRailPanel}`,
  /(?=[\s\S]*export interface WorkflowHarnessReplayInspection)(?=[\s\S]*export function resolveWorkflowHarnessReplayInspection)(?=[\s\S]*workflowUniqueReplayFixtureRefs)(?=[\s\S]*selectedHarnessReplayInspection)(?=[\s\S]*sourceKind: "node_attempt")(?=[\s\S]*sourceKind: "gated_cluster")(?=[\s\S]*sourceKind: "runtime_binding")(?=[\s\S]*sourceKind: "activation_worker_handoff")(?=[\s\S]*sourceKind: "default_runtime_dispatch")(?=[\s\S]*sourceKind: "read_only_routing_proof")(?=[\s\S]*sourceKind: "authority_gate_proof")(?=[\s\S]*sourceKind: "harness_group")(?=[\s\S]*workflow-harness-replay-inspector)(?=[\s\S]*data-replay-source-kind)(?=[\s\S]*data-determinism)(?=[\s\S]*workflow-harness-replay-inspector-metadata)(?=[\s\S]*workflow-harness-replay-capture-flags)(?=[\s\S]*workflow-harness-replay-payload-preview)(?=[\s\S]*workflow-harness-replay-evidence-refs)/,
  "Selected harness replay fixtures should resolve into a redacted fixture inspector with source, policy, attempt, receipt, determinism, capture flags, and evidence refs.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*workflow-harness-active-runtime-binding)(?=[\s\S]*data-binding-matched)(?=[\s\S]*data-worker-launch-reviewed-import-invariant-bound)(?=[\s\S]*data-worker-session-launch-authority-invariant-ids)(?=[\s\S]*data-worker-launch-envelope-invariant-ids)(?=[\s\S]*data-worker-handoff-receipt-invariant-ids)(?=[\s\S]*DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT)(?=[\s\S]*data-selected-selector-decision-id)(?=[\s\S]*data-selected-default-dispatch-id)(?=[\s\S]*data-selected-worker-binding-id)(?=[\s\S]*data-selected-rollback-target)(?=[\s\S]*data-rollback-proof-bound)(?=[\s\S]*data-rollback-live-shadow-gate-id)(?=[\s\S]*data-rollback-execution-dry-run-status)(?=[\s\S]*data-rollback-execution-canary-result-id)(?=[\s\S]*data-rollback-execution-apply-disabled)(?=[\s\S]*data-rollback-apply-execution-status)(?=[\s\S]*data-rollback-apply-receipt-id)(?=[\s\S]*data-rollback-apply-audit-event-id)(?=[\s\S]*rollback_harness_hash_stale)(?=[\s\S]*rollback_node_attempt_stale)(?=[\s\S]*rollback_replay_fixture_stale)(?=[\s\S]*rollback_launch_envelope_missing)(?=[\s\S]*rollback_handoff_receipt_missing)(?=[\s\S]*rollback_node_attempt_missing)(?=[\s\S]*rollback_replay_fixture_missing)(?=[\s\S]*rollback_node_attempt_orphaned)(?=[\s\S]*workflow-harness-active-runtime-rollback-proof)(?=[\s\S]*workflow-harness-active-runtime-rollback-dry-run)(?=[\s\S]*workflow-harness-active-runtime-rollback-apply)(?=[\s\S]*onRunActiveRuntimeRollbackDryRun)(?=[\s\S]*onApplyActiveRuntimeRollback)(?=[\s\S]*workflow-harness-active-runtime-binding-selector-link)(?=[\s\S]*selectorDecisionId)(?=[\s\S]*workflow-harness-active-runtime-binding-dispatch-link)(?=[\s\S]*dispatchId)(?=[\s\S]*workflow-harness-active-runtime-binding-worker-link)(?=[\s\S]*workerBindingId)(?=[\s\S]*workflow-harness-active-runtime-binding-rollback-link)(?=[\s\S]*rollbackTarget)(?=[\s\S]*workflow-harness-active-runtime-rollback-proof-launch-envelope-link)(?=[\s\S]*workflow-harness-active-runtime-rollback-proof-handoff-receipt-link)(?=[\s\S]*workflow-harness-active-runtime-rollback-proof-node-attempt-link)(?=[\s\S]*workflow-harness-active-runtime-rollback-proof-replay-link)(?=[\s\S]*workflow-harness-active-runtime-binding-receipt-\$\{index\})(?=[\s\S]*workflow-harness-active-runtime-binding-replay-\$\{index\})(?=[\s\S]*workflow-harness-active-runtime-binding-blockers)/,
  "The harness rail should expose route-restorable active runtime binding identity, links, receipts, replay fixtures, and activation blockers.",
);

assert.match(
  workflowRailPanel,
  /(?=[\s\S]*id: "worker-invariant")(?=[\s\S]*workflow-harness-activation-step-\$\{step\.id\})(?=[\s\S]*data-required-invariant-ids)(?=[\s\S]*data-invariant-blockers)(?=[\s\S]*workflow-harness-activation-gate-inspector)(?=[\s\S]*data-invariant-blocker-count)(?=[\s\S]*DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT)/,
  "The activation wizard should expose reviewed-import worker launch invariants as a selectable gate with GUI-visible blockers.",
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
  "Hypervisor App harness validation should require behavioral promotion control proof that renders the rail, invokes promotion transitions, and records blocked/gated/live attempts.",
);

assert.match(
  `${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*VITE_AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI)(?=[\s\S]*HARNESS_PROMOTION_LIVE_GUI_SCRIPT)(?=[\s\S]*__AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI_RESULT)(?=[\s\S]*handleHarnessPromotionLiveGuiProbe)(?=[\s\S]*runHarnessDeepLinkReplayProbe)(?=[\s\S]*runHarnessLiveTurnNodeInspectorDeepLinkProbe)(?=[\s\S]*runHarnessLiveShadowComparisonDeepLinkProbe)(?=[\s\S]*runHarnessActiveRuntimeRollbackProofProbe)(?=[\s\S]*runHarnessActiveRuntimeRollbackExecutionWorkbenchProbe)(?=[\s\S]*__AUTOPILOT_HARNESS_ACTIVE_RUNTIME_ROLLBACK_DRY_RUN_RESULT)(?=[\s\S]*__AUTOPILOT_HARNESS_ACTIVE_RUNTIME_ROLLBACK_APPLY_RESULT)(?=[\s\S]*runHarnessActiveRuntimeRollbackNegativeApplyProbe)(?=[\s\S]*activeRuntimeRollbackApplyProof)(?=[\s\S]*activeRuntimeRollbackNegativeApplyProof)(?=[\s\S]*detached-launch-envelope-missing)(?=[\s\S]*detached-handoff-receipt-missing)(?=[\s\S]*detached-node-attempt-missing)(?=[\s\S]*detached-node-attempt-orphaned)(?=[\s\S]*detached-replay-fixture-missing)(?=[\s\S]*runHarnessColdStartDeepLinkRestoreProbe)(?=[\s\S]*runHarnessActivationBlockerDeepLinkProbe)(?=[\s\S]*runHarnessActivationGateDeepLinkProbe)(?=[\s\S]*activation-gate-worker-invariant)(?=[\s\S]*liveActivationGateDeepLinkProof)(?=[\s\S]*liveTurnNodeInspectorDeepLinkProof)(?=[\s\S]*liveShadowComparisonDeepLinkProof)(?=[\s\S]*activeRuntimeRollbackProofWorkbenchProof)(?=[\s\S]*activeRuntimeRollbackExecutionProof)(?=[\s\S]*live-shadow-comparison)(?=[\s\S]*live-turn-node-inspector)(?=[\s\S]*runHarnessWorkerInvariantNegativeEnforcementProbe)(?=[\s\S]*workerInvariantNegativeEnforcementProof)(?=[\s\S]*workerInvariantNegativeEnforcement)(?=[\s\S]*default-agent-harness-live-gui-promotion-proof\.workflow\.json)(?=[\s\S]*collectPromotionTransitionLiveGuiInteractionProof)(?=[\s\S]*promotion-transition-live-gui-interaction-proof\.json)(?=[\s\S]*routeStatefulDeepLinks)(?=[\s\S]*routeStatefulActiveRuntimeBindingDeepLinks)(?=[\s\S]*routeStatefulRevisionBindingDeepLink)(?=[\s\S]*routeStatefulActivationBlockerDeepLink)(?=[\s\S]*routeStatefulActivationAuditDeepLink)(?=[\s\S]*routeStatefulActivationGateDeepLink)(?=[\s\S]*routeStatefulActivationGateReferenceDeepLinks)(?=[\s\S]*activationGateWorkerInvariantDeepLink)(?=[\s\S]*activationGateWorkerInvariantInspector)(?=[\s\S]*activationGateActionWorkbench)(?=[\s\S]*activationGateActionClickProof)(?=[\s\S]*revisionBindingKind)(?=[\s\S]*revisionBindingRef)(?=[\s\S]*activationBlockerRef)(?=[\s\S]*activationAuditEventId)(?=[\s\S]*activationGateId)(?=[\s\S]*activationGateEvidenceRef)(?=[\s\S]*activationGateReceiptRef)(?=[\s\S]*activationGateReplayFixtureRef)(?=[\s\S]*deepLinkReplayProof)(?=[\s\S]*coldStartDeepLinkRestoreProof)(?=[\s\S]*activationBlockerDeepLinkProof)(?=[\s\S]*activationGateDeepLinkProof)(?=[\s\S]*routeStatefulDeepLinkReplay)(?=[\s\S]*coldStartDeepLinkRestore)(?=[\s\S]*liveTurnNodeInspectorDeepLink)(?=[\s\S]*harness_route_stateful_deep_link_replay)(?=[\s\S]*harness_route_stateful_deep_link_replay_present)(?=[\s\S]*harness_cold_start_deep_link_restore)(?=[\s\S]*harness_cold_start_deep_link_restore_present)(?=[\s\S]*harness_revision_binding_deep_link_restore)(?=[\s\S]*harness_revision_binding_deep_link_restore_present)(?=[\s\S]*harness_activation_blocker_deep_link_restore)(?=[\s\S]*harness_activation_audit_deep_link_restore)(?=[\s\S]*harness_activation_audit_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_deep_link_restore)(?=[\s\S]*harness_activation_gate_deep_link_restore_present)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore)(?=[\s\S]*harness_activation_gate_ref_deep_link_restore_present)(?=[\s\S]*harness_worker_launch_reviewed_import_activation_apply_invariant_gate_deep_link)(?=[\s\S]*harness_worker_launch_reviewed_import_activation_apply_invariant_gate_deep_link_present)(?=[\s\S]*harness_worker_launch_reviewed_import_activation_apply_invariant_negative_enforcement)(?=[\s\S]*harness_worker_launch_reviewed_import_activation_apply_invariant_negative_enforcement_present)(?=[\s\S]*harness_activation_gate_action_workbench)(?=[\s\S]*harness_activation_gate_action_workbench_present)(?=[\s\S]*harness_activation_gate_action_click_proof)(?=[\s\S]*harness_activation_gate_action_click_proof_present)(?=[\s\S]*harness_promotion_transition_live_gui_interaction)(?=[\s\S]*harness_promotion_transition_live_gui_interaction_present)(?=[\s\S]*harness_chat_runtime_binding)(?=[\s\S]*harness_chat_runtime_binding_matches_workflow_activation)(?=[\s\S]*harness_active_runtime_rollback_proof_workbench)(?=[\s\S]*harness_active_runtime_rollback_proof_workbench_present)(?=[\s\S]*harness_active_runtime_rollback_execution_workbench)(?=[\s\S]*harness_active_runtime_rollback_execution_workbench_present)(?=[\s\S]*harness_active_runtime_rollback_apply_execution)(?=[\s\S]*harness_active_runtime_rollback_apply_execution_present)(?=[\s\S]*harness_active_runtime_rollback_negative_apply)(?=[\s\S]*harness_active_runtime_rollback_negative_apply_present)(?=[\s\S]*harness_live_turn_node_timeline)(?=[\s\S]*harness_live_turn_node_timeline_present)(?=[\s\S]*harness_live_turn_node_inspector)(?=[\s\S]*harness_live_turn_node_inspector_present)(?=[\s\S]*harness_live_turn_node_inspector_deep_link)(?=[\s\S]*harness_live_turn_node_inspector_deep_link_present)(?=[\s\S]*harness_live_shadow_comparison)(?=[\s\S]*harness_live_shadow_comparison_present)(?=[\s\S]*harnessLiveTurnNodeTimelineCount)(?=[\s\S]*harnessLiveTurnNodeInspectorCount)(?=[\s\S]*harnessLiveShadowComparisonCount)(?=[\s\S]*HarnessDefaultRuntimeBinding)(?=[\s\S]*harnessDefaultRuntimeBindingMatchedCount)(?=[\s\S]*promotionTransitionLiveGui)/,
  "Hypervisor App harness validation should launch the live Workflows surface and require saved-workflow, screenshot, route-stateful active binding, and replay-hydration proof for promotion controls.",
);

assert.match(
  `${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*activationGateCollectEvidenceClickProof)(?=[\s\S]*activationGateCollectEvidenceClickPassed)(?=[\s\S]*activationGateCollectEvidenceCommand)(?=[\s\S]*activationGateCollectEvidenceReplayGateId)(?=[\s\S]*harness_activation_gate_collect_evidence_click_proof)(?=[\s\S]*harness_activation_gate_collect_evidence_click_proof_present)/,
  "Live promotion GUI validation should include replay-fixture collect-evidence gate click proof in the retained evidence contract.",
);

assert.match(
  `${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*activationGateRollbackRestoreClickProof)(?=[\s\S]*activationGateRollbackRestoreClickPassed)(?=[\s\S]*activationGateRollbackRestoreCommand)(?=[\s\S]*activationGateRollbackRestoreCanaryStatus)(?=[\s\S]*activationGateRollbackRestoreReceiptBindingRef)(?=[\s\S]*harness_activation_gate_rollback_restore_click_proof)(?=[\s\S]*harness_activation_gate_rollback_restore_click_proof_present)/,
  "Live promotion GUI validation should include rollback restore gate click proof in the retained evidence contract.",
);

assert.match(
  `${workflowComposer}\n${guiHarnessValidation}\n${guiHarnessContract}`,
  /(?=[\s\S]*activationIdGateClickProof)(?=[\s\S]*activationIdGateClickPassed)(?=[\s\S]*activationIdBlockedDryRunDecision)(?=[\s\S]*activationIdMintedActivationId)(?=[\s\S]*harness_activation_id_gate_click_proof)(?=[\s\S]*harness_activation_id_gate_click_proof_present)/,
  "Live promotion GUI validation should include activation-id blocked and mint gate click proof in the retained evidence contract.",
);

assert.match(
  graphTypes,
  /(?=[\s\S]*interface WorkflowNodeRun[\s\S]*harnessAttempt\?: WorkflowHarnessNodeAttemptRecord)(?=[\s\S]*interface WorkflowRunResult[\s\S]*harnessAttempts\?: WorkflowHarnessNodeAttemptRecord\[\][\s\S]*harnessShadowComparisons\?: WorkflowHarnessShadowComparison\[\])(?=[\s\S]*interface WorkflowPortablePackageManifest[\s\S]*workerHarnessBinding\?: WorkflowHarnessWorkerBinding)/,
  "Portable packages and run records should preserve harness metadata, worker binding identity, node attempts, shadow comparisons, and gated cluster runs.",
);

assert.match(
  rustHarnessService,
  /(?=[\s\S]*HarnessWorkerSessionRecord)(?=[\s\S]*DEFAULT_AGENT_HARNESS_WORKFLOW_ID)(?=[\s\S]*DEFAULT_AGENT_HARNESS_ACTIVATION_ID)(?=[\s\S]*DEFAULT_AGENT_HARNESS_HASH)/,
  "Worker workflow records should point at the blessed default harness identity.",
);

console.log("harnessWorkflowWiring.test.mjs: ok");
