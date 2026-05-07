import { useState } from "react";
import type {
  GraphGlobalConfig,
  Node,
  WorkflowBindingCheckResult,
  WorkflowBindingManifest,
  WorkflowCheckpoint,
  WorkflowConnectionClass,
  WorkflowHarnessComponentKind,
  WorkflowDogfoodRun,
  WorkflowHarnessForkActivationCandidate,
  WorkflowHarnessGroupView,
  WorkflowNodeFixture,
  WorkflowPortablePackage,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRightPanel,
  WorkflowRunResult,
  WorkflowRunSummary,
  WorkflowStreamEvent,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowTestRunResult,
  WorkflowValidationResult,
} from "../../types/graph";
import { workflowInterruptPreview } from "../../runtime/workflow-bottom-panel-model";
import {
  harnessNodeEvidenceSummary,
  harnessSlotsForWorkflow,
  workflowHarnessWorkerBinding,
  workflowIsBlessedHarness,
  workflowIsHarness,
  workflowIsHarnessFork,
} from "../../runtime/harness-workflow";
import { workflowValuePreview } from "../../runtime/workflow-value-preview";
import {
  compareRunRecords,
  workflowBindingCheckResult,
  workflowBindingRegistryRows,
  workflowBindingRegistrySummary,
  workflowDurationLabel,
  workflowEnvironmentProfile,
  workflowEventLabel,
  workflowFileBundleItems,
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowNodeRunChildLineage,
  workflowNodeName,
  workflowRailSearchResults,
  workflowReadinessStatusLabel,
  workflowSelectedNodeBindingSummary,
  workflowWorkbenchCheckSummary,
  workflowWorkbenchCheckTitle,
  workflowTimeLabel,
} from "../../runtime/workflow-rail-model";

type WorkflowHarnessAuthorityGateProofView = {
  id: "policy-gate" | "destructive-denial" | "approval-gate";
  label: string;
  componentKind: Extract<WorkflowHarnessComponentKind, "policy_gate" | "approval_gate">;
  node: Node | null;
  ready: boolean;
  status: "live_ready" | "blocked";
  attemptIds: string[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  policyDecision: string;
  blockerState: string;
  componentId: string;
  runId: string;
  selectedPanel: WorkflowRightPanel;
};

function workflowProofStringArray(
  proof: Record<string, unknown> | null | undefined,
  key: string,
  fallback: string[] = [],
): string[] {
  const value = proof?.[key];
  if (!Array.isArray(value)) return fallback;
  return value.filter((item): item is string => typeof item === "string");
}

function workflowProofString(
  proof: Record<string, unknown> | null | undefined,
  key: string,
  fallback: string,
): string {
  const value = proof?.[key];
  return typeof value === "string" ? value : fallback;
}

function workflowProofBoolean(
  proof: Record<string, unknown> | null | undefined,
  key: string,
  fallback: boolean,
): boolean {
  const value = proof?.[key];
  return typeof value === "boolean" ? value : fallback;
}

function workflowHarnessAuthorityGateBlockerState(
  gate: Pick<
    WorkflowHarnessAuthorityGateProofView,
    "ready" | "attemptIds" | "receiptIds" | "replayFixtureRefs"
  >,
): string {
  if (gate.ready) return "none";
  if (gate.attemptIds.length === 0) return "missing attempt";
  if (gate.receiptIds.length === 0) return "missing receipt";
  if (gate.replayFixtureRefs.length === 0) return "missing replay fixture";
  return "needs activation review";
}

export function WorkflowRailPanel({
  panel,
  selectedNode,
  selectedHarnessGroup,
  harnessWorkbenchDeepLink,
  harnessActivationCandidate,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  tests,
  proposals,
  runs,
  validationResult,
  readinessResult,
  testResult,
  workflow,
  lastRunResult,
  selectedRunId,
  compareRunResult,
  compareRunId,
  runEvents,
  dogfoodRun,
  portablePackage,
  bindingManifest,
  selectedNodeFixtures,
  checkpoints,
  onSelectRun,
  onCompareRun,
  onOpenExecutions,
  onInspectNode,
  onInspectHarnessGroupNode,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
  onCopyHarnessDeepLink,
  onCheckActivationReadiness,
  onRunHarnessActivationDryRun,
  onConfigureNode,
  onSelectProposal,
  onExportPackage,
  onOpenImportPackage,
  onGenerateBindingManifest,
  onUpdateEnvironmentProfile,
  onUpdateProductionProfile,
  onCheckBinding,
  onResolveIssue,
  onRunNode,
  onRunUpstream,
  onCaptureFixtureForNode,
  onDryRunFixtureForNode,
  onPinFixtureForNode,
  onAddTestFromOutput,
}: {
  panel: WorkflowRightPanel;
  selectedNode: Node | null;
  selectedHarnessGroup?: WorkflowHarnessGroupView | null;
  harnessWorkbenchDeepLink?: string | null;
  harnessActivationCandidate?: WorkflowHarnessForkActivationCandidate | null;
  selectedHarnessReceiptRef?: string | null;
  selectedHarnessReplayFixtureRef?: string | null;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
  runs: WorkflowRunSummary[];
  validationResult: WorkflowValidationResult | null;
  readinessResult: WorkflowValidationResult | null;
  testResult: WorkflowTestRunResult | null;
  workflow: WorkflowProject;
  lastRunResult: WorkflowRunResult | null;
  selectedRunId: string | null;
  compareRunResult: WorkflowRunResult | null;
  compareRunId: string | null;
  runEvents: WorkflowStreamEvent[];
  dogfoodRun: WorkflowDogfoodRun | null;
  portablePackage: WorkflowPortablePackage | null;
  bindingManifest: WorkflowBindingManifest | null;
  selectedNodeFixtures: WorkflowNodeFixture[];
  checkpoints: WorkflowCheckpoint[];
  onSelectRun: (run: WorkflowRunSummary) => void;
  onCompareRun: (run: WorkflowRunSummary) => void;
  onOpenExecutions?: () => void;
  onInspectNode: (nodeId: string) => void;
  onInspectHarnessGroupNode?: (groupId: string, nodeId: string) => void;
  onSelectHarnessReceiptRef?: (receiptRef: string) => void;
  onSelectHarnessReplayFixtureRef?: (replayFixtureRef: string) => void;
  onCopyHarnessDeepLink?: () => void;
  onCheckActivationReadiness?: () => void;
  onRunHarnessActivationDryRun?: () => void;
  onConfigureNode: () => void;
  onSelectProposal: (proposal: WorkflowProposal) => void;
  onExportPackage: () => void;
  onOpenImportPackage: () => void;
  onGenerateBindingManifest: () => void;
  onUpdateEnvironmentProfile: (updates: Partial<NonNullable<GraphGlobalConfig["environmentProfile"]>>) => void;
  onUpdateProductionProfile: (updates: NonNullable<GraphGlobalConfig["production"]>) => void;
  onCheckBinding?: (
    row: ReturnType<typeof workflowBindingRegistryRows>[number],
  ) => WorkflowBindingCheckResult | Promise<WorkflowBindingCheckResult>;
  onResolveIssue: (issue: WorkflowValidationIssue) => void;
  onRunNode: (node: Node, fixture?: WorkflowNodeFixture) => void;
  onRunUpstream: (node: Node) => void;
  onCaptureFixtureForNode: (node: Node) => void;
  onDryRunFixtureForNode: (node: Node, fixture?: WorkflowNodeFixture) => void;
  onPinFixtureForNode: (node: Node, fixture: WorkflowNodeFixture) => void;
  onAddTestFromOutput: (node: Node) => void;
}) {
  const [railSearchQuery, setRailSearchQuery] = useState("");
  const [unitTestSearchQuery, setUnitTestSearchQuery] = useState("");
  const [runSearchQuery, setRunSearchQuery] = useState("");
  const [runStatusFilter, setRunStatusFilter] = useState<string>("all");
  const [bindingCheckResults, setBindingCheckResults] = useState<
    Record<string, WorkflowBindingCheckResult>
  >({});
  const normalizedRailSearch = railSearchQuery.trim().toLowerCase();
  const normalizedUnitTestSearch = unitTestSearchQuery.trim().toLowerCase();
  const normalizedRunSearch = runSearchQuery.trim().toLowerCase();
  const outputNodes = workflow.nodes.filter((nodeItem) => nodeItem.type === "output");
  const workflowSearchResults = workflowRailSearchResults(workflow, tests, normalizedRailSearch);
  const sourceAndTriggerNodes = workflow.nodes.filter(
    (nodeItem) => nodeItem.type === "source" || nodeItem.type === "trigger",
  );
  const triggerNodes = workflow.nodes.filter((nodeItem) => nodeItem.type === "trigger");
  const fileBundleItems = workflowFileBundleItems(
    workflow,
    tests,
    proposals,
    runs,
    portablePackage,
    bindingManifest,
  );
  const testResultById = new Map((testResult?.results ?? []).map((result) => [result.testId, result]));
  const filteredUnitTests = tests.filter((test) => {
    if (!normalizedUnitTestSearch) return true;
    return [
      test.id,
      test.name,
      test.status,
      test.lastMessage,
      test.assertion.kind,
      ...test.targetNodeIds,
    ].join(" ").toLowerCase().includes(normalizedUnitTestSearch);
  });
  const coveredNodeIds = new Set(tests.flatMap((test) => test.targetNodeIds));
  const uncoveredNodes = workflow.nodes.filter((nodeItem) => !coveredNodeIds.has(nodeItem.id));
  const testStatusCounts = tests.reduce(
    (counts, test) => {
      const status = test.status ?? "idle";
      counts[status] = (counts[status] ?? 0) + 1;
      return counts;
    },
    {} as Record<string, number>,
  );
  const modelBindingItems = Object.entries(workflow.global_config.modelBindings ?? {});
  const requiredCapabilityItems = Object.entries(workflow.global_config.requiredCapabilities ?? {}).filter(
    ([, requirement]) => requirement.required,
  );
  const workflowPolicy = workflow.global_config.policy;
  const productionProfile = workflow.global_config.production ?? {};
  const workflowReadOnly = workflow.metadata.readOnly === true;
  const harnessWorkflow = workflowIsHarness(workflow);
  const blessedHarnessWorkflow = workflowIsBlessedHarness(workflow);
  const harnessForkWorkflow = workflowIsHarnessFork(workflow);
  const harnessSlots = harnessSlotsForWorkflow(workflow);
  const harnessWorkerBinding = harnessWorkflow ? workflowHarnessWorkerBinding(workflow) : null;
  const harnessPromotionClusters = workflow.metadata.harness?.promotionClusters ?? [];
  const harnessActivationRecord = workflow.metadata.harness?.activationRecord;
  const harnessLiveHandoffProof = workflow.metadata.harness?.liveHandoffProof;
  const harnessRuntimeSelectorDecision = workflow.metadata.harness?.runtimeSelectorDecision;
  const harnessCanaryExecutionBoundary = workflow.metadata.harness?.canaryExecutionBoundary;
  const harnessCanaryExecutionBoundaries =
    workflow.metadata.harness?.canaryExecutionBoundaries ??
    (harnessCanaryExecutionBoundary ? [harnessCanaryExecutionBoundary] : []);
  const harnessDefaultRuntimeDispatchProof = workflow.metadata.harness?.defaultRuntimeDispatchProof;
  const harnessReadOnlyRoutingProof =
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingProof ?? null;
  const harnessReadOnlyRoutingNodeKinds =
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingWorkflowOwnedNodeKinds ?? [];
  const harnessReadOnlyRoutingRequiredScenarios =
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingRequiredScenarioSet ??
    (Array.isArray(harnessReadOnlyRoutingProof?.requiredScenarioSet)
      ? harnessReadOnlyRoutingProof.requiredScenarioSet.filter(
          (scenario): scenario is string => typeof scenario === "string",
        )
      : []);
  const harnessReadOnlyRoutingReady =
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReady === true &&
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingSelected === true &&
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingNoMutationReady === true &&
    harnessReadOnlyRoutingProof?.sideEffectsExecuted === false &&
    harnessReadOnlyRoutingProof?.mutationExecuted === false;
  const harnessAuthorityToolingProof =
    harnessDefaultRuntimeDispatchProof?.authorityToolingProof ?? null;
  const harnessAuthorityPolicyGateNode =
    workflow.nodes.find(
      (node) => node.runtimeBinding?.componentKind === "policy_gate",
    ) ?? null;
  const harnessAuthorityApprovalGateNode =
    workflow.nodes.find(
      (node) => node.runtimeBinding?.componentKind === "approval_gate",
    ) ?? null;
  const harnessAuthorityGateLiveProofSeeds: Array<
    Omit<WorkflowHarnessAuthorityGateProofView, "blockerState">
  > = harnessDefaultRuntimeDispatchProof
    ? [
        {
          id: "policy-gate",
          label: "Policy gate",
          componentKind: "policy_gate",
          node: harnessAuthorityPolicyGateNode,
          ready:
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveReady === true &&
            workflowProofBoolean(harnessAuthorityToolingProof, "policyGateLiveReady", true),
          status:
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveReady === true
              ? "live_ready"
              : "blocked",
          attemptIds: workflowProofStringArray(
            harnessAuthorityToolingProof,
            "policyGateLiveAttemptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveAttemptIds,
          ),
          receiptIds: workflowProofStringArray(
            harnessAuthorityToolingProof,
            "policyGateLiveReceiptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveReceiptIds,
          ),
          replayFixtureRefs: workflowProofStringArray(
            harnessAuthorityToolingProof,
            "policyGateLiveReplayFixtureRefs",
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveReplayFixtureRefs,
          ),
          policyDecision: workflowProofString(
            harnessAuthorityToolingProof,
            "policyGateDecision",
            "allow_read_only_route_through_workflow_authority",
          ),
          componentId:
            harnessAuthorityPolicyGateNode?.runtimeBinding?.componentId ??
            "ioi.agent-harness.policy_gate.v1",
          runId: selectedRunId ?? harnessDefaultRuntimeDispatchProof.dispatchId,
          selectedPanel: panel,
        },
        {
          id: "destructive-denial",
          label: "Destructive denial",
          componentKind: "policy_gate",
          node: harnessAuthorityPolicyGateNode,
          ready:
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveReady === true &&
            workflowProofBoolean(
              harnessAuthorityToolingProof,
              "destructiveDenialLiveReady",
              true,
            ),
          status:
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveReady === true
              ? "live_ready"
              : "blocked",
          attemptIds: workflowProofStringArray(
            harnessAuthorityToolingProof,
            "destructiveDenialLiveAttemptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveAttemptIds,
          ),
          receiptIds: workflowProofStringArray(
            harnessAuthorityToolingProof,
            "destructiveDenialLiveReceiptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveReceiptIds,
          ),
          replayFixtureRefs: workflowProofStringArray(
            harnessAuthorityToolingProof,
            "destructiveDenialLiveReplayFixtureRefs",
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveReplayFixtureRefs,
          ),
          policyDecision: workflowProofString(
            harnessAuthorityToolingProof,
            "destructiveDenialPolicyDecision",
            "deny_destructive_request_without_side_effect",
          ),
          componentId:
            harnessAuthorityPolicyGateNode?.runtimeBinding?.componentId ??
            "ioi.agent-harness.policy_gate.v1",
          runId: selectedRunId ?? harnessDefaultRuntimeDispatchProof.dispatchId,
          selectedPanel: panel,
        },
        {
          id: "approval-gate",
          label: "Approval gate",
          componentKind: "approval_gate",
          node: harnessAuthorityApprovalGateNode,
          ready:
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReady === true &&
            workflowProofBoolean(harnessAuthorityToolingProof, "approvalGateLiveReady", true),
          status:
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReady === true
              ? "live_ready"
              : "blocked",
          attemptIds: workflowProofStringArray(
            harnessAuthorityToolingProof,
            "approvalGateLiveAttemptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveAttemptIds,
          ),
          receiptIds: workflowProofStringArray(
            harnessAuthorityToolingProof,
            "approvalGateLiveReceiptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReceiptIds,
          ),
          replayFixtureRefs: workflowProofStringArray(
            harnessAuthorityToolingProof,
            "approvalGateLiveReplayFixtureRefs",
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReplayFixtureRefs,
          ),
          policyDecision: workflowProofString(
            harnessAuthorityToolingProof,
            "approvalGatePolicyDecision",
            "require_legacy_approval_for_mutating_tooling",
          ),
          componentId:
            harnessAuthorityApprovalGateNode?.runtimeBinding?.componentId ??
            "ioi.agent-harness.approval_gate.v1",
          runId: selectedRunId ?? harnessDefaultRuntimeDispatchProof.dispatchId,
          selectedPanel: panel,
        },
      ]
    : [];
  const harnessAuthorityGateLiveProofs: WorkflowHarnessAuthorityGateProofView[] =
    harnessAuthorityGateLiveProofSeeds.map((gate) => ({
      ...gate,
      blockerState: workflowHarnessAuthorityGateBlockerState(gate),
    }));
  const harnessAuthorityGateLiveReady =
    harnessDefaultRuntimeDispatchProof?.authorityToolingGateLiveReady === true &&
    workflowProofBoolean(harnessAuthorityToolingProof, "gateLiveReady", true) &&
    harnessAuthorityGateLiveProofs.length > 0 &&
    harnessAuthorityGateLiveProofs.every((gate) => gate.ready);
  const harnessAuthorityGateReadyCount = harnessAuthorityGateLiveProofs.filter(
    (gate) => gate.ready,
  ).length;
  const renderHarnessAuthorityGateProofRows = (
    gates: WorkflowHarnessAuthorityGateProofView[],
    options: {
      listTestId: string;
      gateTestIdPrefix: string;
    },
  ) => (
    <div
      className="workflow-rail-list workflow-harness-authority-gate-list"
      data-testid={options.listTestId}
    >
      {gates.map((gate) => {
        const receiptRef = gate.receiptIds[0] ?? null;
        const replayFixtureRef = gate.replayFixtureRefs[0] ?? null;
        return (
          <article
            key={gate.id}
            className={`workflow-test-row workflow-harness-authority-gate-row is-${
              gate.ready ? "passed" : "blocked"
            }`}
            data-testid={`${options.gateTestIdPrefix}-${gate.id}`}
            data-component-kind={gate.componentKind}
            data-authority-gate-status={gate.status}
          >
            <strong>{gate.label}</strong>
            <span>
              {gate.componentKind} · {gate.status} · {gate.attemptIds.length} attempts
            </span>
            <small>{gate.policyDecision}</small>
            <small data-testid={`${options.gateTestIdPrefix}-deep-links-${gate.id}`}>
              component {gate.componentId} · run {gate.runId} · replay{" "}
              {replayFixtureRef ?? "pending"} · panel {gate.selectedPanel}
            </small>
            <small>blocker {gate.blockerState}</small>
            <div className="workflow-harness-authority-gate-actions">
              <button
                type="button"
                className="workflow-harness-ref-button"
                data-testid={`${options.gateTestIdPrefix}-component-${gate.id}`}
                disabled={!gate.node}
                onClick={() => gate.node && onInspectNode(gate.node.id)}
              >
                <code>{gate.componentId}</code>
              </button>
              <button
                type="button"
                className={`workflow-harness-ref-button ${
                  receiptRef && selectedHarnessReceiptRef === receiptRef
                    ? "is-active"
                    : ""
                }`}
                data-testid={`${options.gateTestIdPrefix}-receipt-${gate.id}`}
                disabled={!receiptRef}
                onClick={() => receiptRef && onSelectHarnessReceiptRef?.(receiptRef)}
              >
                <code>{receiptRef ?? "receipt pending"}</code>
              </button>
              <button
                type="button"
                className={`workflow-harness-ref-button ${
                  replayFixtureRef &&
                  selectedHarnessReplayFixtureRef === replayFixtureRef
                    ? "is-active"
                    : ""
                }`}
                data-testid={`${options.gateTestIdPrefix}-replay-${gate.id}`}
                disabled={!replayFixtureRef}
                onClick={() =>
                  replayFixtureRef &&
                  onSelectHarnessReplayFixtureRef?.(replayFixtureRef)
                }
              >
                <code>{replayFixtureRef ?? "replay pending"}</code>
              </button>
            </div>
          </article>
        );
      })}
    </div>
  );
  const harnessActivationReady =
    !harnessForkWorkflow ||
    Boolean(
      workflow.metadata.harness?.activationId &&
        workflow.metadata.harness?.activationState === "validated" &&
        harnessActivationRecord?.activationState === "validated" &&
        harnessActivationRecord.canaryStatus === "passed" &&
        harnessActivationRecord.rollbackAvailable === true &&
        harnessActivationRecord.liveAuthorityTransferred === false,
    );
  const harnessActivationIssues = [
    ...(readinessResult?.errors ?? []),
    ...(readinessResult?.warnings ?? []),
    ...(readinessResult?.executionReadinessIssues ?? []),
    ...(validationResult?.errors ?? []),
    ...(validationResult?.warnings ?? []),
    ...(validationResult?.executionReadinessIssues ?? []),
  ];
  const harnessActivationBlockers = Array.from(
    new Map(
      harnessActivationIssues
        .filter((issue) =>
          [
            "harness_required_slot_unbound",
            "harness_activation_not_validated",
            "harness_self_mutation_not_proposal_only",
            "missing_replay_fixture",
            "missing_unit_tests",
            "mcp_access_not_reviewed",
            "missing_ai_evaluation_coverage",
            "unbound_model_ref",
          ].includes(issue.code),
        )
        .map((issue) => [`${issue.code}:${issue.nodeId ?? ""}:${issue.message}`, issue]),
    ).values(),
  );
  const firstHarnessActivationBlocker = harnessActivationBlockers[0] ?? null;
  const activationGateProposal = proposals.find(
    (proposal) =>
      proposal.id.includes("activation") ||
      proposal.sidecarDiff?.changedRoles?.includes("activation"),
  );
  const gatedHarnessClusters = harnessPromotionClusters.filter(
    (cluster) => cluster.requiredExecutionMode === "gated",
  );
  const boundHarnessSlotIds = new Set(workflow.nodes.flatMap((node) => node.runtimeBinding?.slotIds ?? []));
  const requiredHarnessSlots = harnessSlots.filter((slot) => slot.required);
  const boundRequiredHarnessSlotCount = requiredHarnessSlots.filter((slot) =>
    boundHarnessSlotIds.has(slot.slotId),
  ).length;
  const receiptReadyHarnessComponents = workflow.nodes.filter(
    (node) => (node.runtimeBinding?.receiptKinds ?? []).length > 0,
  ).length;
  const replayFixtureBlockers = harnessActivationBlockers.filter(
    (issue) => issue.code === "missing_replay_fixture",
  );
  const policyPostureReady =
    workflow.metadata.harness?.aiMutationMode === "proposal_only" &&
    (workflow.global_config.environmentProfile?.mockBindingPolicy ?? "block") === "block" &&
    (workflow.global_config.production?.mcpAccessReviewed === true ||
      !workflow.nodes.some((node) => node.type === "mcp_tool_call"));
  const canaryReady =
    harnessActivationRecord?.canaryStatus === "passed" ||
    (harnessCanaryExecutionBoundaries.length > 0 &&
      harnessCanaryExecutionBoundaries.every(
        (boundary) =>
          boundary.status === "passed" &&
          boundary.canaryEligible === true &&
          boundary.rollbackDrill.drillStatus === "passed",
      ));
  const rollbackReady =
    harnessActivationRecord?.rollbackAvailable === true &&
    Boolean(harnessActivationRecord.rollbackTarget);
  const workerActivationBindingReady =
    Boolean(harnessWorkerBinding?.harnessWorkflowId) &&
    (!workflow.metadata.harness?.activationId ||
      harnessWorkerBinding?.harnessActivationId === workflow.metadata.harness.activationId);
  const harnessActivationWizardSteps = [
    {
      id: "slots",
      label: "Slots",
      ready: boundRequiredHarnessSlotCount === requiredHarnessSlots.length,
      value: `${boundRequiredHarnessSlotCount}/${requiredHarnessSlots.length}`,
      detail: "required component slots bound",
    },
    {
      id: "tests",
      label: "Tests",
      ready: tests.length > 0,
      value: `${tests.length}`,
      detail: "activation test cases available",
    },
    {
      id: "replay-fixtures",
      label: "Replay fixtures",
      ready: replayFixtureBlockers.length === 0,
      value: replayFixtureBlockers.length === 0 ? "ready" : `${replayFixtureBlockers.length} missing`,
      detail: "required expensive or external nodes replayable",
    },
    {
      id: "policy-posture",
      label: "Policy posture",
      ready: policyPostureReady,
      value: harnessActivationRecord?.policyPosture ?? "proposal_only",
      detail: "proposal-only mutation, blocked mock policy, MCP review",
    },
    {
      id: "receipt-coverage",
      label: "Receipt coverage",
      ready: receiptReadyHarnessComponents === workflow.nodes.length,
      value: `${receiptReadyHarnessComponents}/${workflow.nodes.length}`,
      detail: "components emit mapped receipt refs",
    },
    {
      id: "canary",
      label: "Canary",
      ready: canaryReady,
      value: harnessActivationRecord?.canaryStatus ?? "not_run",
      detail: "workflow canary boundary and retained scenario proof",
    },
    {
      id: "rollback",
      label: "Rollback",
      ready: rollbackReady,
      value: harnessActivationRecord?.rollbackTarget ?? "not set",
      detail: "rollback target and rollback drill available",
    },
    {
      id: "activation-id",
      label: "Activation id",
      ready: harnessActivationReady,
      value: workflow.metadata.harness?.activationId ?? "not minted",
      detail: "minted only after validation gates pass",
    },
    {
      id: "worker-binding",
      label: "Worker binding",
      ready: workerActivationBindingReady,
      value: harnessWorkerBinding?.harnessActivationId ?? "blocked",
      detail: "worker binding matches workflow, hash, and activation",
    },
  ];
  const harnessComponentReadiness = workflow.nodes
    .map((node) => node.runtimeBinding?.readiness)
    .filter((readiness): readiness is NonNullable<typeof readiness> => Boolean(readiness));
  const liveReadyHarnessComponents = harnessComponentReadiness.filter(
    (readiness) => readiness === "live_ready",
  ).length;
  const environmentProfile = workflowEnvironmentProfile(workflow);
  const bindingRegistryRows = workflowBindingRegistryRows(workflow);
  const bindingRegistrySummary = workflowBindingRegistrySummary(bindingRegistryRows);
  const handleCheckBinding = async (
    row: ReturnType<typeof workflowBindingRegistryRows>[number],
  ) => {
    let result: WorkflowBindingCheckResult;
    try {
      result = onCheckBinding
        ? await onCheckBinding(row)
        : workflowBindingCheckResult(row, environmentProfile);
    } catch (error) {
      const fallback = workflowBindingCheckResult(row, environmentProfile);
      result = {
        ...fallback,
        status: "blocked",
        summary: "Binding check could not run",
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    setBindingCheckResults((current) => ({
      ...current,
      [row.id]: result,
    }));
  };
  const hasErrorOrRetryPath =
    Boolean(productionProfile.errorWorkflowPath?.trim()) ||
    workflow.edges.some((edge) => {
      const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
      return edgeClass === "error" || edgeClass === "retry" || edge.fromPort === "error" || edge.fromPort === "retry";
    });
  const operationalSideEffectNodes = workflow.nodes.filter((nodeItem) => {
    const logic = nodeItem.config?.logic ?? {};
    if (nodeItem.type === "adapter") {
      const sideEffectClass = logic.connectorBinding?.sideEffectClass ?? "none";
      return !["none", "read"].includes(sideEffectClass);
    }
    if (nodeItem.type === "plugin_tool") {
      const sideEffectClass = logic.toolBinding?.sideEffectClass ?? "none";
      return !["none", "read"].includes(sideEffectClass);
    }
    if (nodeItem.type === "output") {
      const targetKind = logic.deliveryTarget?.targetKind ?? "none";
      return logic.materialization?.enabled === true || ["local_file", "repo_patch", "connector_write", "deploy"].includes(targetKind);
    }
    return false;
  });
  const criticalAiNodeIds = workflow.nodes.filter((nodeItem) => nodeItem.type === "model_call").map((nodeItem) => nodeItem.id);
  const mcpToolNodes = workflow.nodes.filter(
    (nodeItem) => nodeItem.type === "plugin_tool" && nodeItem.config?.logic?.toolBinding?.bindingKind === "mcp_tool",
  );
  if (panel === "unit_tests") {
    return (
      <>
        <h3>Unit tests</h3>
        <input
          data-testid="workflow-unit-test-search-input"
          placeholder="Search tests, assertions, targets..."
          value={unitTestSearchQuery}
          onChange={(event) => setUnitTestSearchQuery(event.target.value)}
        />
        <dl className="workflow-rail-stats" data-testid="workflow-unit-test-summary">
          <div>
            <dt>Total</dt>
            <dd>{tests.length}</dd>
          </div>
          <div>
            <dt>Covered</dt>
            <dd>{coveredNodeIds.size}</dd>
          </div>
          <div>
            <dt>Uncovered</dt>
            <dd>{uncoveredNodes.length}</dd>
          </div>
          <div>
            <dt>Last run</dt>
            <dd>{testResult?.status ?? "none"}</dd>
          </div>
        </dl>
        <p data-testid="workflow-unit-test-status-counts">
          Passed {testStatusCounts.passed ?? 0} · Failed {testStatusCounts.failed ?? 0} · Blocked {testStatusCounts.blocked ?? 0}
        </p>
        <div className="workflow-rail-list" data-testid="workflow-unit-test-list">
          {filteredUnitTests.map((test) => {
            const latestResult = testResultById.get(test.id);
            const targetNode = test.targetNodeIds[0]
              ? workflow.nodes.find((nodeItem) => nodeItem.id === test.targetNodeIds[0]) ?? null
              : null;
            return (
              <article key={test.id} className={`workflow-test-row is-${latestResult?.status ?? test.status ?? "idle"}`} data-testid={`workflow-unit-test-${test.id}`}>
                <strong>{test.name}</strong>
                <span>{latestResult?.message || test.lastMessage || `${test.targetNodeIds.length} covered targets`}</span>
                <small>{test.assertion.kind}</small>
                {targetNode ? (
                  <button
                    type="button"
                    className="workflow-inline-link"
                    data-testid={`workflow-unit-test-target-${test.id}`}
                    onClick={() => onInspectNode(targetNode.id)}
                  >
                    {targetNode.name}
                  </button>
                ) : null}
              </article>
            );
          })}
          {filteredUnitTests.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No matching tests</strong>
              <span>Try a test name, assertion kind, status, or target node id.</span>
            </article>
          ) : null}
        </div>
        {uncoveredNodes.length > 0 ? (
          <section className="workflow-rail-section" data-testid="workflow-unit-test-uncovered">
            <h4>Untested nodes</h4>
            {uncoveredNodes.slice(0, 6).map((nodeItem) => (
              <button
                key={nodeItem.id}
                type="button"
                className="workflow-search-result"
                data-testid={`workflow-unit-test-uncovered-${nodeItem.id}`}
                onClick={() => onInspectNode(nodeItem.id)}
              >
                <strong>{nodeItem.name}</strong>
                <span>{nodeItem.type} · {nodeItem.status ?? "idle"}</span>
              </button>
            ))}
          </section>
        ) : null}
      </>
    );
  }
  if (panel === "changes") {
    return (
      <>
        <h3>Changes</h3>
        <p>{proposals.length === 0 ? "No proposals for this workflow." : `${proposals.length} proposal${proposals.length === 1 ? "" : "s"} with bounded targets.`}</p>
        <div className="workflow-rail-list" data-testid="workflow-changes-list">
          {proposals.map((proposal) => (
            <button
              key={proposal.id}
              type="button"
              className={`workflow-proposal-card is-${proposal.status}`}
              data-testid={`workflow-change-proposal-${proposal.id}`}
              onClick={() => onSelectProposal(proposal)}
            >
              <strong>{proposal.title}</strong>
              <span>{proposal.status} · {proposal.boundedTargets.length} target{proposal.boundedTargets.length === 1 ? "" : "s"}</span>
              <small>{proposal.summary}</small>
              {proposal.boundedTargets.length > 0 ? (
                <code>{proposal.boundedTargets.slice(0, 4).join(", ")}</code>
              ) : null}
            </button>
          ))}
          {proposals.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No proposed changes</strong>
              <span>Create a proposal from validation blockers or the proposal node when a graph or code change should be reviewed.</span>
            </article>
          ) : null}
        </div>
      </>
    );
  }
  if (panel === "runs") {
    const selectedRun = lastRunResult?.summary.id === selectedRunId ? lastRunResult : null;
    const comparison =
      selectedRun && compareRunResult && compareRunResult.summary.id !== selectedRun.summary.id
        ? compareRunRecords(workflow, selectedRun, compareRunResult)
        : null;
    const defaultCompareRun = runs.find((run) => run.id !== selectedRunId);
    const timelineEvents = selectedRun?.events ?? runEvents;
    const interruptPreview = workflowInterruptPreview(lastRunResult);
    const runStatuses = Array.from(new Set(runs.map((run) => run.status))).sort();
    const filteredRuns = runs.filter((run) => {
      const matchesStatus = runStatusFilter === "all" || run.status === runStatusFilter;
      const matchesSearch =
        !normalizedRunSearch ||
        [run.id, run.status, run.summary]
          .join(" ")
          .toLowerCase()
          .includes(normalizedRunSearch);
      return matchesStatus && matchesSearch;
    });
    const visibleRuns = filteredRuns.slice(0, 8);
    const harnessAttempts = selectedRun?.harnessAttempts ?? [];
    const harnessComparisons = selectedRun?.harnessShadowComparisons ?? [];
    return (
      <>
        <h3>Runs</h3>
        <p>
          {runs.length === 0
            ? "No runs yet."
            : `Showing ${visibleRuns.length} of ${filteredRuns.length} matching runs. Select one to inspect attempts and state changes.`}
        </p>
        {onOpenExecutions ? (
          <button
            type="button"
            className="workflow-secondary-action"
            data-testid="workflow-open-executions"
            onClick={onOpenExecutions}
          >
            Open Executions
          </button>
        ) : null}
        {runs.length > 0 ? (
          <div className="workflow-run-filters" data-testid="workflow-run-filters">
            <input
              data-testid="workflow-run-search-input"
              placeholder="Search runs..."
              value={runSearchQuery}
              onChange={(event) => setRunSearchQuery(event.target.value)}
            />
            <div className="workflow-node-group-filter" data-testid="workflow-run-status-filter">
              {["all", ...runStatuses].map((status) => (
                <button
                  key={status}
                  type="button"
                  className={runStatusFilter === status ? "is-active" : ""}
                  data-testid={`workflow-run-status-${status}`}
                  onClick={() => setRunStatusFilter(status)}
                >
                  {status}
                  <small>
                    {status === "all"
                      ? runs.length
                      : runs.filter((run) => run.status === status).length}
                  </small>
                </button>
              ))}
            </div>
          </div>
        ) : null}
        <div className="workflow-run-list" data-testid="workflow-runs-list">
          {visibleRuns.map((run) => (
            <button
              key={run.id}
              type="button"
              className={`workflow-run-card is-${run.status} ${selectedRunId === run.id ? "is-active" : ""} ${compareRunId === run.id ? "is-compare" : ""}`}
              data-testid={`workflow-run-${run.id}`}
              onClick={() => onSelectRun(run)}
            >
              <strong>{run.status}</strong>
              <span>{run.summary}</span>
              <small>
                {workflowDurationLabel(run.startedAtMs, run.finishedAtMs)} · {run.checkpointCount ?? 0} checkpoints
              </small>
            </button>
          ))}
          {runs.length > 0 && visibleRuns.length === 0 ? (
            <article className="workflow-output-row" data-testid="workflow-runs-empty-filtered">
              <strong>No matching runs</strong>
              <span>Adjust the status filter or search by run summary, status, or id.</span>
            </article>
          ) : null}
        </div>
        {selectedRun && defaultCompareRun ? (
          <button
            type="button"
            className="workflow-secondary-action"
            data-testid="workflow-compare-run"
            onClick={() => onCompareRun(defaultCompareRun)}
          >
            Compare with previous run
          </button>
        ) : null}
        {comparison ? (
          <article className="workflow-run-comparison" data-testid="workflow-run-compare">
            <strong>Run comparison</strong>
            <span>
              {comparison.baselineStatus} to {comparison.targetStatus} · {comparison.changedNodes.length} node changes
            </span>
            <dl>
              <div>
                <dt>Duration</dt>
                <dd>
                  {comparison.durationDeltaMs === null
                    ? "running"
                    : `${comparison.durationDeltaMs >= 0 ? "+" : ""}${comparison.durationDeltaMs} ms`}
                </dd>
              </div>
              <div>
                <dt>Checkpoints</dt>
                <dd>{comparison.checkpointDelta >= 0 ? "+" : ""}{comparison.checkpointDelta}</dd>
              </div>
              <div>
                <dt>Events</dt>
                <dd>{comparison.eventDelta >= 0 ? "+" : ""}{comparison.eventDelta}</dd>
              </div>
              <div>
                <dt>State</dt>
                <dd>{comparison.stateChanges.length} changes</dd>
              </div>
            </dl>
            {comparison.changedNodes.slice(0, 5).map((change) => (
              <button
                key={change.nodeId}
                type="button"
                className="workflow-run-comparison-node"
                data-testid={`workflow-run-compare-node-${change.nodeId}`}
                onClick={() => onInspectNode(change.nodeId)}
              >
                <strong>{change.nodeName}</strong>
                <span>{change.before}{" -> "}{change.after}</span>
                <small>
                  {change.inputChanged ? "input changed" : "input stable"}
                  {" · "}
                  {change.outputChanged ? "output changed" : "output stable"}
                  {change.errorChanged ? " · error changed" : ""}
                </small>
              </button>
            ))}
          </article>
        ) : null}
        {lastRunResult?.interrupt ? (
          <article className="workflow-output-row" data-testid="workflow-run-interrupt">
            <strong>Paused at human input</strong>
            <span>{lastRunResult.interrupt.prompt}</span>
            {interruptPreview?.binding ? (
              <small data-testid="workflow-interrupt-preview">
                {interruptPreview.binding.bindingKind ?? "action"} · {interruptPreview.binding.ref ?? "configured node"} · {interruptPreview.binding.sideEffectClass ?? "side effect"}
              </small>
            ) : null}
          </article>
        ) : null}
        {selectedRun ? (
          <div className="workflow-run-inspector" data-testid="workflow-run-inspector">
            <h4>Attempts</h4>
            {selectedRun.nodeRuns.slice(0, 8).map((nodeRun) => {
              const childLineage = workflowNodeRunChildLineage(nodeRun);
              return (
                <button
                  key={`${nodeRun.nodeId}-${nodeRun.attempt}-${nodeRun.startedAtMs}`}
                  type="button"
                  className={`workflow-run-attempt is-${nodeRun.status}`}
                  data-testid={`workflow-run-attempt-${nodeRun.nodeId}`}
                  onClick={() => onInspectNode(nodeRun.nodeId)}
                >
                  <strong>{workflowNodeName(workflow, nodeRun.nodeId)}</strong>
                  <span>{nodeRun.status} · attempt {nodeRun.attempt}</span>
                  <small>
                    {workflowDurationLabel(nodeRun.startedAtMs, nodeRun.finishedAtMs)}
                    {" · "}
                    {nodeRun.input === undefined ? "input not captured" : "input captured"}
                  </small>
                  <small
                    className="workflow-run-lifecycle"
                    data-testid="workflow-run-attempt-lifecycle"
                  >
                    {(nodeRun.lifecycle?.length ?? 0) > 0
                      ? `${nodeRun.lifecycle?.length} run steps`
                      : "run steps pending"}
                    {nodeRun.checkpointId ? ` · checkpoint saved` : ""}
                  </small>
                  {childLineage ? (
                    <small
                      className="workflow-run-child-lineage"
                      data-testid="workflow-run-child-lineage"
                      data-node-id={nodeRun.nodeId}
                    >
                      Child run {childLineage.childRunStatus} · {childLineage.childRunId}
                    </small>
                  ) : null}
                  {nodeRun.harnessAttempt ? (
                    <small data-testid="workflow-run-harness-attempt">
                      {nodeRun.harnessAttempt.executionMode} · {nodeRun.harnessAttempt.readiness} · {nodeRun.harnessAttempt.replay.determinism}
                    </small>
                  ) : null}
                </button>
              );
            })}
            {harnessAttempts.length > 0 ? (
              <>
                <h4>Harness timeline</h4>
                <ol className="workflow-run-timeline" data-testid="workflow-run-harness-timeline">
                  {harnessAttempts.slice(-10).map((attempt) => (
                    <li key={attempt.attemptId} className={`is-${attempt.status}`}>
                      <strong>{workflowNodeName(workflow, attempt.workflowNodeId)}</strong>
                      <span>
                        {attempt.executionMode} · {attempt.readiness} · {attempt.replay.determinism}
                      </span>
                      <small>
                        {attempt.receiptIds.length} receipts · {attempt.replay.redactionPolicy}
                      </small>
                    </li>
                  ))}
                </ol>
              </>
            ) : null}
            {harnessComparisons.length > 0 ? (
              <>
                <h4>Live vs shadow</h4>
                <ol className="workflow-run-timeline" data-testid="workflow-run-harness-shadow-comparison">
                  {harnessComparisons.slice(-6).map((comparison) => (
                    <li key={`${comparison.liveAttemptId}-${comparison.shadowAttemptId}`} className={`is-${comparison.divergence}`}>
                      <strong>{comparison.divergence}</strong>
                      <span>{comparison.summary}</span>
                      <small>{comparison.blocking ? "blocking" : "non-blocking"}</small>
                    </li>
                  ))}
                </ol>
              </>
            ) : null}
            <h4>Timeline</h4>
            <ol className="workflow-run-timeline" data-testid="workflow-run-timeline">
              {timelineEvents.slice(-10).map((event) => (
                <li key={event.id} className={`is-${event.status ?? event.kind}`}>
                  <strong>{workflowEventLabel(event)}</strong>
                  <span>{event.message ?? workflowNodeName(workflow, event.nodeId)}</span>
                  <small>{workflowTimeLabel(event.createdAtMs)}</small>
                </li>
              ))}
            </ol>
          </div>
        ) : null}
        {checkpoints.slice(0, 4).map((checkpoint) => (
          <article key={checkpoint.id} className="workflow-output-row" data-testid={`workflow-checkpoint-${checkpoint.id}`}>
            <strong>{checkpoint.status}</strong>
            <span>{checkpoint.summary}</span>
          </article>
        ))}
        {dogfoodRun ? (
          <article className="workflow-output-row" data-testid="workflow-dogfood-result">
            <strong>{workflowWorkbenchCheckTitle(dogfoodRun.status)}</strong>
            <span>{workflowWorkbenchCheckSummary(dogfoodRun.workflowPaths.length)}</span>
          </article>
        ) : null}
      </>
    );
  }
  if (panel === "readiness") {
    const result = readinessResult ?? validationResult;
    const blockers = result
      ? [
          ...result.errors,
          ...(result.executionReadinessIssues ?? []),
          ...result.missingConfig,
          ...result.connectorBindingIssues,
          ...(result.verificationIssues ?? []),
        ]
      : [];
    const readinessWarnings = result?.warnings ?? [];
    const policyRequiredNodeIds = result?.policyRequiredNodes ?? [];
    const hasIncomingConnectionClass = (nodeId: string, connectionClass: WorkflowConnectionClass) =>
      workflow.edges.some((edge) => {
        if (edge.to !== nodeId) return false;
        const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
        return edgeClass === connectionClass || edge.toPort === connectionClass;
      });
    const readinessItems = [
      { label: "Trigger or source", ready: workflow.nodes.some((node) => node.type === "trigger" || node.type === "source") },
      { label: "Model binding", ready: !workflow.nodes.some((node) => {
        if (node.type !== "model_call") return false;
        const modelRef = String(node.config?.logic?.modelRef ?? "");
        return !workflow.global_config.modelBindings?.[modelRef]?.modelId && !hasIncomingConnectionClass(node.id, "model");
      }) },
      { label: "Mock/live mode explicit", ready: !workflow.nodes.some((node) => {
        const logic = node.config?.logic ?? {};
        const binding = logic.toolBinding ?? logic.connectorBinding ?? logic.modelBinding ?? logic.parserBinding;
        return binding && typeof binding.mockBinding !== "boolean";
      }) },
      { label: "Live bindings for activation", ready: !workflow.nodes.some((node) => {
        const logic = node.config?.logic ?? {};
        const binding = logic.toolBinding ?? logic.connectorBinding ?? logic.modelBinding ?? logic.parserBinding;
        return binding?.mockBinding === true;
      }) },
      { label: "Error handling", ready: operationalSideEffectNodes.length === 0 || hasErrorOrRetryPath },
      { label: "Evaluation coverage", ready: criticalAiNodeIds.length === 0 || Boolean(productionProfile.evaluationSetPath?.trim()) || criticalAiNodeIds.every((nodeId) => coveredNodeIds.has(nodeId)) },
      { label: "Replay samples", ready: !readinessWarnings.some((issue: any) => issue.code === "missing_replay_fixture") },
      { label: "MCP access reviewed", ready: mcpToolNodes.length === 0 || productionProfile.mcpAccessReviewed === true },
      { label: "Value estimate", ready: Number(productionProfile.expectedTimeSavedMinutes ?? 0) > 0 },
      { label: "Outputs defined", ready: workflow.nodes.some((node) => node.type === "output") },
      { label: "Tests present", ready: tests.length > 0 },
      { label: "Harness slots", ready: !harnessWorkflow || harnessSlots.every((slot) => boundHarnessSlotIds.has(slot.slotId)) },
      { label: "Harness activation", ready: harnessActivationReady },
      {
        label: "Authority gate live",
        ready:
          !harnessWorkflow ||
          !harnessDefaultRuntimeDispatchProof ||
          harnessAuthorityGateLiveReady,
      },
      { label: "Readiness checked", ready: readinessResult !== null },
      { label: "No blockers", ready: blockers.length === 0 && result?.status !== "blocked" },
    ];
    const passedReadinessChecks = readinessItems.filter((item) => item.ready).length;
    const attentionIssues = [
      ...blockers.map((issue) => ({ issue, status: "blocked" as const })),
      ...readinessWarnings.map((issue) => ({ issue, status: "warning" as const })),
    ];
    return (
      <>
        <h3>Readiness</h3>
        <dl className="workflow-rail-stats" data-testid="workflow-readiness-summary">
          <div>
            <dt>Status</dt>
            <dd>{workflowReadinessStatusLabel(result)}</dd>
          </div>
          <div>
            <dt>Checks</dt>
            <dd>{passedReadinessChecks}/{readinessItems.length}</dd>
          </div>
          <div>
            <dt>Blockers</dt>
            <dd>{blockers.length}</dd>
          </div>
          <div>
            <dt>Warnings</dt>
            <dd>{readinessWarnings.length}</dd>
          </div>
        </dl>
        {attentionIssues.length > 0 ? (
          <section className="workflow-rail-section" data-testid="workflow-readiness-attention">
            <h4>Needs attention</h4>
            {attentionIssues.slice(0, 4).map(({ issue, status }, index) => {
              const nodeName = issue.nodeId ? workflowNodeName(workflow, issue.nodeId) : "Workflow";
              return (
                <button
                  key={`${status}-${issue.code}-${issue.nodeId ?? "workflow"}-${index}`}
                  type="button"
                  className={`workflow-search-result is-${status}`}
                  data-testid={`workflow-readiness-attention-${index}`}
                  onClick={() => onResolveIssue(issue)}
                >
                  <strong>{workflowIssueTitle(issue)}</strong>
                  <span>{nodeName}</span>
                  <small>{issue.message || issue.code}</small>
                  <small>{workflowIssueActionLabel(issue)}</small>
                </button>
              );
            })}
          </section>
        ) : null}
        <div className="workflow-rail-list" data-testid="workflow-readiness-checklist">
          {readinessItems.map((item) => (
            <article key={item.label} className={`workflow-test-row is-${item.ready ? "passed" : "blocked"}`}>
              <strong>{item.label}</strong>
              <span>{item.ready ? "Ready" : "Needs attention"}</span>
            </article>
          ))}
        </div>
        {blockers.length > 0 ? (
          <section className="workflow-rail-section" data-testid="workflow-readiness-blockers">
            <h4>Blockers</h4>
            {blockers.slice(0, 8).map((issue: WorkflowValidationIssue, index) => {
              const nodeName = issue.nodeId ? workflowNodeName(workflow, issue.nodeId) : "Workflow";
              return (
                <button
                  key={`${issue.code ?? "issue"}-${issue.nodeId}-${index}`}
                  type="button"
                  className="workflow-search-result is-blocked"
                  data-testid={`workflow-readiness-blocker-${index}`}
                  onClick={() => onResolveIssue(issue)}
                >
                  <strong>{workflowIssueTitle(issue)}</strong>
                  <span>{nodeName}</span>
                  <small>{issue.message || issue.code}</small>
                  <small>{workflowIssueActionLabel(issue)}</small>
                </button>
              );
            })}
          </section>
        ) : null}
        {readinessWarnings.length > 0 ? (
          <section className="workflow-rail-section" data-testid="workflow-readiness-warnings">
            <h4>Warnings</h4>
            {readinessWarnings.slice(0, 6).map((issue, index) => (
              <button
                key={`${issue.code}-${index}`}
                type="button"
                className="workflow-search-result is-warning"
                data-testid={`workflow-readiness-warning-${index}`}
                onClick={() => onResolveIssue(issue)}
              >
                <strong>{workflowIssueTitle(issue)}</strong>
                <span>{issue.message}</span>
                <small>{workflowIssueActionLabel(issue)}</small>
              </button>
            ))}
          </section>
        ) : null}
        {policyRequiredNodeIds.length > 0 ? (
          <section className="workflow-rail-section" data-testid="workflow-readiness-policy-nodes">
            <h4>Policy required</h4>
            {policyRequiredNodeIds.slice(0, 6).map((nodeId) => (
              <button
                key={nodeId}
                type="button"
                className="workflow-search-result is-blocked"
                data-testid={`workflow-readiness-policy-node-${nodeId}`}
                onClick={() => {
                  onInspectNode(nodeId);
                  onConfigureNode();
                }}
              >
                <strong>{workflowNodeName(workflow, nodeId)}</strong>
                <span>Privileged boundary needs an approval or policy gate.</span>
                <small>Open configuration</small>
              </button>
            ))}
          </section>
        ) : null}
        <section className="workflow-package-readiness" data-testid="workflow-portable-package">
          <h4>Portable package</h4>
          <p>Export graph, tests, fixtures, functions, bindings, policies, and output definitions for another checkout.</p>
          <div className="workflow-package-actions">
            <button type="button" data-testid="workflow-export-package" onClick={onExportPackage}>Export package</button>
            <button type="button" data-testid="workflow-import-package-open" onClick={onOpenImportPackage}>Import package</button>
          </div>
          {portablePackage ? (
            <article className={`workflow-test-row is-${portablePackage.manifest.portable ? "passed" : "blocked"}`} data-testid="workflow-package-summary">
              <strong>{portablePackage.manifest.portable ? "Portable" : "Exported with blockers"}</strong>
              <span>{portablePackage.manifest.files.length} files, readiness {portablePackage.manifest.readinessStatus}</span>
            </article>
          ) : null}
        </section>
      </>
    );
  }
  if (panel === "search") {
    return (
      <>
        <h3>Search</h3>
        <input
          data-testid="workflow-rail-search-input"
          placeholder="Search nodes, tests, outputs..."
          value={railSearchQuery}
          onChange={(event) => setRailSearchQuery(event.target.value)}
        />
        <p>{workflow.nodes.length} nodes, {tests.length} tests, and {outputNodes.length} outputs indexed.</p>
        <div className="workflow-search-results" data-testid="workflow-rail-search-results">
          {workflowSearchResults.slice(0, 18).map((item) => (
            <button
              key={item.id}
              type="button"
              className="workflow-search-result"
              data-testid={`workflow-rail-search-result-${item.id}`}
              disabled={!item.nodeId}
              onClick={() => item.nodeId && onInspectNode(item.nodeId)}
            >
              <strong>{item.title}</strong>
              <span>{item.resultKind} · {item.subtitle}</span>
              {item.detail ? <small>{item.detail}</small> : null}
            </button>
          ))}
          {workflowSearchResults.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No matches</strong>
              <span>Try a node name, binding, test id, status, or output format.</span>
            </article>
          ) : null}
        </div>
      </>
    );
  }
  if (panel === "sources") {
    return (
      <>
        <h3>Sources</h3>
        <p>{sourceAndTriggerNodes.length === 0 ? "No start points configured." : `${sourceAndTriggerNodes.length} start point${sourceAndTriggerNodes.length === 1 ? "" : "s"} in this workflow.`}</p>
        <div className="workflow-rail-list" data-testid="workflow-sources-list">
          {sourceAndTriggerNodes.map((nodeItem) => {
            const logic = nodeItem.config?.logic ?? {};
            const sourceStatus =
              nodeItem.type === "trigger"
                ? logic.triggerKind === "scheduled"
                  ? logic.cronSchedule
                    ? "scheduled"
                    : "needs schedule"
                  : logic.triggerKind === "event"
                    ? logic.eventSourceRef
                      ? "event"
                      : "needs event source"
                    : "manual"
                : logic.payload === undefined
                  ? "needs payload"
                  : "payload ready";
            return (
              <button
                key={nodeItem.id}
                type="button"
                className="workflow-search-result"
                data-testid={`workflow-source-node-${nodeItem.id}`}
                onClick={() => onInspectNode(nodeItem.id)}
              >
                <strong>{nodeItem.name}</strong>
                <span>{nodeItem.type} · {sourceStatus}</span>
                <small>
                  {nodeItem.type === "trigger"
                    ? String(logic.eventSourceRef ?? logic.cronSchedule ?? logic.triggerKind ?? "manual")
                    : typeof logic.payload === "string"
                      ? logic.payload
                      : logic.payload === undefined
                        ? "No payload configured"
                        : "Structured payload configured"}
                </small>
              </button>
            );
          })}
        </div>
      </>
    );
  }
  if (panel === "files") {
    return (
      <>
        <h3>Files</h3>
        <p>Git-backed bundle surfaces stay separate from run state and local UI state.</p>
        <div className="workflow-rail-list" data-testid="workflow-files-list">
          {fileBundleItems.map((item) => (
            <article key={item.label} className="workflow-file-row">
              <strong>{item.label}</strong>
              <code>{item.path}</code>
              <span>{item.status}</span>
            </article>
          ))}
        </div>
      </>
    );
  }
  if (panel === "schedules") {
    return (
      <>
        <h3>Schedules</h3>
        <p>{triggerNodes.length === 0 ? "No trigger nodes configured." : `${triggerNodes.length} trigger node${triggerNodes.length === 1 ? "" : "s"} configured.`}</p>
        <div className="workflow-rail-list" data-testid="workflow-schedules-list">
          {triggerNodes.map((nodeItem) => {
            const logic = nodeItem.config?.logic ?? {};
            const triggerKind = logic.triggerKind ?? "manual";
            const ready =
              triggerKind === "scheduled"
                ? Boolean(logic.cronSchedule)
                : triggerKind === "event"
                  ? Boolean(logic.eventSourceRef)
                  : true;
            return (
              <button
                key={nodeItem.id}
                type="button"
                className={`workflow-search-result is-${ready ? "ready" : "blocked"}`}
                data-testid={`workflow-schedule-node-${nodeItem.id}`}
                onClick={() => onInspectNode(nodeItem.id)}
              >
                <strong>{nodeItem.name}</strong>
                <span>{triggerKind} · {ready ? "ready" : "needs configuration"}</span>
                <small>
                  {triggerKind === "scheduled"
                    ? String(logic.cronSchedule ?? "No schedule")
                    : triggerKind === "event"
                      ? String(logic.eventSourceRef ?? "No event source")
                      : "Manual invocation"}
                </small>
              </button>
            );
          })}
          {triggerNodes.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No trigger</strong>
              <span>Add a Trigger primitive when this workflow needs scheduled or event-driven execution.</span>
            </article>
          ) : null}
        </div>
      </>
    );
  }
  if (panel === "settings") {
    return (
      <>
        <h3>Settings</h3>
        <dl className="workflow-rail-stats" data-testid="workflow-settings-summary">
          <div>
            <dt>Kind</dt>
            <dd>{workflow.metadata.workflowKind}</dd>
          </div>
          <div>
            <dt>Mode</dt>
            <dd>{workflow.metadata.executionMode}</dd>
          </div>
          <div>
            <dt>Validation</dt>
            <dd>{validationResult?.status ?? "not run"}</dd>
          </div>
          <div>
            <dt>Readiness</dt>
            <dd>{readinessResult?.status ?? "not run"}</dd>
          </div>
        </dl>
        <section className="workflow-rail-section" data-testid="workflow-settings-metadata">
          <h4>Workflow</h4>
          <article className="workflow-file-row">
            <strong>{workflow.metadata.name}</strong>
            <code>{workflow.metadata.gitLocation || `.agents/workflows/${workflow.metadata.slug}.workflow.json`}</code>
            <span>{workflow.metadata.branch ?? "main"} · {workflow.metadata.dirty ? "modified" : "saved"}</span>
          </article>
        </section>
        {harnessWorkflow ? (
          <section className="workflow-rail-section" data-testid="workflow-settings-harness-summary">
            <h4>Harness</h4>
            <dl className="workflow-rail-stats">
              <div>
                <dt>Template</dt>
                <dd>{blessedHarnessWorkflow ? "blessed" : "fork"}</dd>
              </div>
              <div>
                <dt>Activation</dt>
                <dd>{workflow.metadata.harness?.activationId ?? workflow.metadata.harness?.activationState ?? "blocked"}</dd>
              </div>
              <div>
                <dt>Mode</dt>
                <dd>{workflow.metadata.harness?.executionMode ?? harnessWorkerBinding?.executionMode ?? "projection"}</dd>
              </div>
              <div>
                <dt>Components</dt>
                <dd>{workflow.metadata.harness?.componentIds?.length ?? 0}</dd>
              </div>
              <div>
                <dt>Live-ready</dt>
                <dd>{liveReadyHarnessComponents}/{harnessComponentReadiness.length}</dd>
              </div>
              <div>
                <dt>Gated clusters</dt>
                <dd>{gatedHarnessClusters.length}/{harnessPromotionClusters.length}</dd>
              </div>
              <div data-testid="workflow-harness-authority-gate-status">
                <dt>Authority gates</dt>
                <dd>{harnessAuthorityGateReadyCount}/{harnessAuthorityGateLiveProofs.length}</dd>
              </div>
              <div>
                <dt>Slots</dt>
                <dd>{harnessSlots.filter((slot) => boundHarnessSlotIds.has(slot.slotId)).length}/{harnessSlots.length}</dd>
              </div>
            </dl>
            {harnessWorkerBinding ? (
              <article className="workflow-output-row" data-testid="workflow-harness-worker-identity">
                <strong>{harnessWorkerBinding.harnessWorkflowId}</strong>
                <span>{harnessWorkerBinding.harnessActivationId ?? "activation blocked"}</span>
                <small>{harnessWorkerBinding.executionMode ?? "projection"} · {harnessWorkerBinding.harnessHash}</small>
              </article>
            ) : null}
            {harnessActivationRecord ? (
              <article className="workflow-output-row" data-testid="workflow-harness-activation-record">
                <strong>{harnessActivationRecord.activationId ?? "activation not minted"}</strong>
                <span>
                  {harnessActivationRecord.activationState} · canary {harnessActivationRecord.canaryStatus}
                </span>
                <small>
                  rollback {harnessActivationRecord.rollbackAvailable ? "ready" : "blocked"} · {harnessActivationRecord.rollbackTarget}
                </small>
              </article>
            ) : null}
            {harnessForkWorkflow ? (
              <section
                className="workflow-rail-section workflow-harness-activation-wizard"
                data-testid="workflow-harness-activation-wizard"
                data-activation-state={
                  workflow.metadata.harness?.activationState ?? "blocked"
                }
              >
                <h4>Activation wizard</h4>
                <dl
                  className="workflow-rail-stats"
                  data-testid="workflow-harness-activation-wizard-summary"
                >
                  <div>
                    <dt>State</dt>
                    <dd>{workflow.metadata.harness?.activationState ?? "blocked"}</dd>
                  </div>
                  <div>
                    <dt>Policy</dt>
                    <dd>{harnessActivationRecord?.policyPosture ?? "proposal_only"}</dd>
                  </div>
                  <div>
                    <dt>Canary</dt>
                    <dd>{harnessActivationRecord?.canaryStatus ?? "not_run"}</dd>
                  </div>
                  <div>
                    <dt>Rollback</dt>
                    <dd>{rollbackReady ? "ready" : "blocked"}</dd>
                  </div>
                </dl>
                <article
                  className={`workflow-output-row is-${harnessActivationReady ? "ready" : "blocked"}`}
                  data-testid={
                    harnessActivationReady
                      ? "workflow-harness-activation-minted-proof"
                      : "workflow-harness-activation-blocked-proof"
                  }
                >
                  <strong>
                    {harnessActivationReady
                      ? workflow.metadata.harness?.activationId
                      : "Activation blocked"}
                  </strong>
                  <span>
                    {harnessActivationReady
                      ? "activation id minted and worker binding validated"
                      : `${harnessActivationBlockers.length} blocker${
                          harnessActivationBlockers.length === 1 ? "" : "s"
                        } remain`}
                  </span>
                  <small>
                    rollback {harnessActivationRecord?.rollbackTarget ?? "not set"} · worker{" "}
                    {harnessWorkerBinding?.harnessWorkflowId ?? "unbound"}
                  </small>
                </article>
                {harnessActivationCandidate ? (
                  <section
                    className="workflow-rail-section"
                    data-testid="workflow-harness-activation-candidate"
                    data-candidate-decision={harnessActivationCandidate.decision}
                  >
                    <h4>Dry run candidate</h4>
                    <article
                      className={`workflow-output-row is-${
                        harnessActivationCandidate.decision === "mintable"
                          ? "ready"
                          : "blocked"
                      }`}
                      data-testid="workflow-harness-activation-candidate-decision"
                    >
                      <strong>{harnessActivationCandidate.candidateId}</strong>
                      <span>
                        {harnessActivationCandidate.decision}
                        {" · "}
                        {harnessActivationCandidate.activationIdPreview ??
                          "activation id blocked"}
                      </span>
                      <small>
                        canary {harnessActivationCandidate.canaryStatus} · rollback{" "}
                        {harnessActivationCandidate.rollbackAvailable
                          ? harnessActivationCandidate.rollbackTarget
                          : "blocked"}
                      </small>
                    </article>
                    <article
                      className="workflow-output-row"
                      data-testid="workflow-harness-activation-candidate-worker-binding"
                    >
                      <strong>
                        {harnessActivationCandidate.workerBindingPreview.harnessWorkflowId}
                      </strong>
                      <span>
                        {harnessActivationCandidate.workerBindingPreview.harnessActivationId ??
                          "activation blocked"}
                      </span>
                      <small>
                        {harnessActivationCandidate.workerBindingPreview.source} ·{" "}
                        {harnessActivationCandidate.workerBindingPreview.harnessHash}
                      </small>
                    </article>
                    <div
                      className="workflow-harness-activation-candidate-gates"
                      data-testid="workflow-harness-activation-candidate-gates"
                    >
                      {harnessActivationCandidate.gateResults.map((gate) => (
                        <article
                          key={gate.gateId}
                          className={`workflow-test-row is-${gate.status}`}
                          data-testid={`workflow-harness-activation-candidate-gate-${gate.gateId}`}
                        >
                          <strong>{gate.label}</strong>
                          <span>{gate.value}</span>
                          <small>{gate.detail}</small>
                        </article>
                      ))}
                    </div>
                    {harnessActivationCandidate.activationBlockers.length > 0 ? (
                      <div
                        className="workflow-rail-list"
                        data-testid="workflow-harness-activation-candidate-blockers"
                      >
                        {harnessActivationCandidate.activationBlockers
                          .slice(0, 5)
                          .map((blocker) => (
                            <article
                              key={blocker}
                              className="workflow-test-row is-blocked"
                            >
                              <strong>Blocked</strong>
                              <span>{blocker}</span>
                            </article>
                          ))}
                      </div>
                    ) : null}
                  </section>
                ) : (
                  <article
                    className="workflow-output-row"
                    data-testid="workflow-harness-activation-candidate-empty"
                  >
                    <strong>No activation candidate</strong>
                    <span>Run a dry run to preview mintability without changing activation state.</span>
                    <small>Dry-run candidates keep invalid forks blocked.</small>
                  </article>
                )}
                <div
                  className="workflow-harness-activation-steps"
                  data-testid="workflow-harness-activation-steps"
                >
                  {harnessActivationWizardSteps.map((step) => (
                    <article
                      key={step.id}
                      className={`workflow-test-row is-${step.ready ? "passed" : "blocked"}`}
                      data-testid={`workflow-harness-activation-step-${step.id}`}
                    >
                      <strong>{step.label}</strong>
                      <span>{step.value}</span>
                      <small>{step.detail}</small>
                    </article>
                  ))}
                </div>
                {harnessActivationBlockers.length > 0 ? (
                  <div
                    className="workflow-rail-list"
                    data-testid="workflow-harness-activation-wizard-blockers"
                  >
                    {harnessActivationBlockers.slice(0, 5).map((issue, index) => (
                      <button
                        key={`${issue.code}-${issue.nodeId ?? "workflow"}-${index}`}
                        type="button"
                        className="workflow-search-result is-blocked"
                        data-testid={`workflow-harness-activation-blocker-${index}`}
                        onClick={() => onResolveIssue(issue)}
                      >
                        <strong>{workflowIssueTitle(issue)}</strong>
                        <span>{workflowNodeName(workflow, issue.nodeId)}</span>
                        <small>{issue.message}</small>
                      </button>
                    ))}
                  </div>
                ) : null}
                <div
                  className="workflow-harness-activation-actions"
                  data-testid="workflow-harness-activation-actions"
                >
                  <button
                    type="button"
                    data-testid="workflow-harness-activation-dry-run"
                    onClick={onRunHarnessActivationDryRun}
                  >
                    Dry run
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-activation-run-readiness"
                    onClick={onCheckActivationReadiness}
                  >
                    Check readiness
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-activation-review-proposal"
                    disabled={!activationGateProposal}
                    onClick={() => {
                      if (activationGateProposal) {
                        onSelectProposal(activationGateProposal);
                      }
                    }}
                  >
                    Review proposal
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-activation-first-blocker"
                    disabled={!firstHarnessActivationBlocker}
                    onClick={() => {
                      if (firstHarnessActivationBlocker) {
                        onResolveIssue(firstHarnessActivationBlocker);
                      }
                    }}
                  >
                    Inspect blocker
                  </button>
                </div>
              </section>
            ) : null}
            {harnessLiveHandoffProof ? (
              <article className="workflow-output-row" data-testid="workflow-harness-live-handoff">
                <strong>{harnessLiveHandoffProof.selector}</strong>
                <span>
                  canary {harnessLiveHandoffProof.canaryStatus} · rollback {harnessLiveHandoffProof.rollbackAvailable ? "ready" : "blocked"}
                </span>
                <small>
                  default {harnessLiveHandoffProof.productionDefaultSelector} · {harnessLiveHandoffProof.runtimeAuthority}
                </small>
              </article>
            ) : null}
            {harnessRuntimeSelectorDecision ? (
              <article className="workflow-output-row" data-testid="workflow-harness-runtime-selector">
                <strong>{harnessRuntimeSelectorDecision.selectedSelector}</strong>
                <span>
                  default {harnessRuntimeSelectorDecision.productionDefaultSelector} · {harnessRuntimeSelectorDecision.executionMode}
                </span>
                <small>{harnessRuntimeSelectorDecision.policyDecision}</small>
              </article>
            ) : null}
            {harnessDefaultRuntimeDispatchProof ? (
              <article className="workflow-output-row" data-testid="workflow-harness-default-runtime-dispatch">
                <strong>{harnessDefaultRuntimeDispatchProof.selectedSelector}</strong>
                <span>
                  {harnessDefaultRuntimeDispatchProof.executionMode} · {harnessDefaultRuntimeDispatchProof.outputWriterStatus}
                </span>
                <small>
                  {harnessDefaultRuntimeDispatchProof.acceptedClusterIds.length} clusters · {harnessDefaultRuntimeDispatchProof.dispatchNodeAttemptIds.length} attempts
                </small>
              </article>
            ) : null}
            {harnessDefaultRuntimeDispatchProof ? (
              <section
                className="workflow-rail-section workflow-harness-authority-gates"
                data-testid="workflow-harness-authority-gate-live"
              >
                <h4>Authority tooling gates</h4>
                <dl
                  className="workflow-rail-stats"
                  data-testid="workflow-harness-authority-gate-summary"
                >
                  <div>
                    <dt>Ready</dt>
                    <dd>
                      {harnessAuthorityGateReadyCount}/{harnessAuthorityGateLiveProofs.length}
                    </dd>
                  </div>
                  <div>
                    <dt>Receipts</dt>
                    <dd>
                      {harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveReceiptIds.length}
                    </dd>
                  </div>
                  <div>
                    <dt>Replay</dt>
                    <dd>
                      {harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveReplayFixtureRefs.length}
                    </dd>
                  </div>
                  <div>
                    <dt>Status</dt>
                    <dd>{harnessAuthorityGateLiveReady ? "live" : "blocked"}</dd>
                  </div>
                </dl>
                <article
                  className={`workflow-output-row is-${
                    harnessAuthorityGateLiveReady ? "ready" : "blocked"
                  }`}
                  data-testid="workflow-harness-authority-gate-rollup"
                >
                  <strong>
                    {workflowProofString(
                      harnessAuthorityToolingProof,
                      "policyDecision",
                      "authority gate proof pending",
                    )}
                  </strong>
                  <span>
                    destructive denied{" "}
                    {harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveRouteDenied
                      ? "yes"
                      : "review"} · approvals blocked{" "}
                    {harnessDefaultRuntimeDispatchProof.authorityToolingMutatingToolCallsBlocked
                      ? "yes"
                      : "review"}
                  </span>
                  <small>
                    side effects{" "}
                    {harnessDefaultRuntimeDispatchProof.authorityToolingSideEffectsExecuted
                      ? "executed"
                      : "not executed"} · rollback{" "}
                    {harnessDefaultRuntimeDispatchProof.authorityToolingRollbackAvailable
                      ? "ready"
                      : "blocked"}
                  </small>
                </article>
                {renderHarnessAuthorityGateProofRows(
                  harnessAuthorityGateLiveProofs,
                  {
                    listTestId: "workflow-harness-authority-gate-list",
                    gateTestIdPrefix: "workflow-harness-authority-gate",
                  },
                )}
              </section>
            ) : null}
            {harnessReadOnlyRoutingProof ? (
              <section
                className="workflow-rail-section"
                data-testid="workflow-harness-read-only-routing-proof"
              >
                <h4>Read-only routing</h4>
                <dl className="workflow-rail-stats" data-testid="workflow-harness-read-only-routing-summary">
                  <div>
                    <dt>Mode</dt>
                    <dd>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingMode ?? String(harnessReadOnlyRoutingProof.mode ?? "unknown")}</dd>
                  </div>
                  <div>
                    <dt>Scenario</dt>
                    <dd>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenario ?? String(harnessReadOnlyRoutingProof.scenario ?? "pending")}</dd>
                  </div>
                  <div>
                    <dt>Nodes</dt>
                    <dd>{harnessReadOnlyRoutingNodeKinds.length}</dd>
                  </div>
                  <div>
                    <dt>Mutation</dt>
                    <dd>{harnessReadOnlyRoutingReady ? "blocked" : "review"}</dd>
                  </div>
                </dl>
                <article className="workflow-output-row" data-testid="workflow-harness-read-only-routing-no-mutation">
                  <strong>{harnessReadOnlyRoutingReady ? "No mutation proof ready" : "No mutation proof incomplete"}</strong>
                  <span>
                    side effects {harnessReadOnlyRoutingProof.sideEffectsExecuted === false ? "not executed" : "review"} · mutation {harnessReadOnlyRoutingProof.mutationExecuted === false ? "not executed" : "review"}
                  </span>
                  <small>
                    source material {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingSourceMaterialReady ? "ready" : "pending"} · rollback {harnessReadOnlyRoutingProof.rollbackAvailable ? "ready" : "blocked"}
                  </small>
                </article>
                <div className="workflow-rail-list" data-testid="workflow-harness-read-only-routing-node-kinds">
                  {harnessReadOnlyRoutingNodeKinds.map((kind) => {
                    const nodeItem = workflow.nodes.find(
                      (candidate) => candidate.runtimeBinding?.componentKind === kind,
                    );
                    return (
                      <button
                        key={kind}
                        type="button"
                        className="workflow-search-result is-ready"
                        data-testid={`workflow-harness-read-only-routing-node-${kind}`}
                        disabled={!nodeItem}
                        onClick={() => nodeItem && onInspectNode(nodeItem.id)}
                      >
                        <strong>{nodeItem?.name ?? kind}</strong>
                        <span>{kind} · workflow-owned</span>
                        <small>{nodeItem?.runtimeBinding?.readiness ?? "binding pending"}</small>
                      </button>
                    );
                  })}
                </div>
                <div className="workflow-rail-list" data-testid="workflow-harness-read-only-routing-receipts">
                  <article className="workflow-output-row">
                    <strong>Attempts</strong>
                    <span>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingAttemptIds.length ?? 0} node attempts</span>
                    <small>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingAttemptIds.slice(0, 2).join(", ") ?? "pending"}</small>
                  </article>
                  <article className="workflow-output-row">
                    <strong>Receipts</strong>
                    <span>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReceiptIds.length ?? 0} receipt refs</span>
                    <small>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReceiptIds.slice(0, 2).join(", ") ?? "pending"}</small>
                  </article>
                  <article className="workflow-output-row">
                    <strong>Replay fixtures</strong>
                    <span>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReplayFixtureRefs.length ?? 0} fixture refs</span>
                    <small>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReplayFixtureRefs.slice(0, 2).join(", ") ?? "pending"}</small>
                  </article>
                </div>
                {harnessReadOnlyRoutingRequiredScenarios.length > 0 ? (
                  <div
                    className="workflow-rail-list"
                    data-testid="workflow-harness-read-only-routing-scenarios"
                  >
                    {harnessReadOnlyRoutingRequiredScenarios.map((scenario) => (
                      <article
                        key={scenario}
                        className={`workflow-test-row is-${
                          scenario === harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenarioCoverageKey
                            ? "passed"
                            : "idle"
                        }`}
                      >
                        <strong>{scenario}</strong>
                        <span>
                          {scenario === harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenarioCoverageKey
                            ? "current coverage key"
                            : "retained requirement"}
                        </span>
                      </article>
                    ))}
                  </div>
                ) : null}
              </section>
            ) : null}
            {harnessCanaryExecutionBoundaries.length > 0 ? (
              <div className="workflow-rail-list" data-testid="workflow-harness-canary-execution-boundaries">
                {harnessCanaryExecutionBoundaries.map((boundary) => (
                  <article
                    key={boundary.boundaryId}
                    className="workflow-output-row"
                    data-testid="workflow-harness-canary-execution-boundary"
                  >
                    <strong>{boundary.clusterLabel}</strong>
                    <span>
                      {boundary.status} · {boundary.executorKind}
                    </span>
                    <small>
                      rollback drill {boundary.rollbackDrill.drillStatus} · {boundary.executedComponentKinds.length} nodes
                    </small>
                  </article>
                ))}
              </div>
            ) : null}
            {workflow.metadata.harness?.forkedFrom ? (
              <article className="workflow-output-row" data-testid="workflow-harness-lineage">
                <strong>Fork lineage</strong>
                <span>{workflow.metadata.harness.forkedFrom.harnessWorkflowId}</span>
                <small>{workflow.metadata.harness.forkedFrom.harnessHash}</small>
              </article>
            ) : null}
            <div className="workflow-rail-list" data-testid="workflow-harness-slots">
              {harnessSlots.map((slot) => {
                const ready = boundHarnessSlotIds.has(slot.slotId);
                return (
                  <article key={slot.slotId} className={`workflow-test-row is-${ready ? "passed" : "blocked"}`}>
                    <strong>{slot.label}</strong>
                    <span>{ready ? "bound" : "unbound"} · {slot.kind}</span>
                    <small>{slot.description}</small>
                  </article>
                );
              })}
            </div>
            <div className="workflow-rail-list" data-testid="workflow-harness-promotion-clusters">
              {harnessPromotionClusters.map((cluster) => (
                <article
                  key={cluster.clusterId}
                  className={`workflow-test-row is-${cluster.clusterId === "cognition" ? "passed" : "idle"}`}
                >
                  <strong>{cluster.label}</strong>
                  <span>
                    {cluster.requiredExecutionMode} · order {cluster.activationOrder}
                  </span>
                  <small>{cluster.componentKinds.length} components · rollback {cluster.rollbackTarget}</small>
                </article>
              ))}
            </div>
            {harnessForkWorkflow ? (
              <article className="workflow-output-row" data-testid="workflow-harness-activation-blockers">
                <strong>Activation blockers</strong>
                <span>
                  {(harnessActivationRecord?.activationBlockers ?? []).length > 0
                    ? harnessActivationRecord?.activationBlockers.join(", ")
                    : "None"}
                </span>
                <small>{workflow.metadata.harness?.activationState ?? "blocked"}</small>
              </article>
            ) : null}
          </section>
        ) : null}
        <section className="workflow-rail-section" data-testid="workflow-environment-profile">
          <h4>Environment</h4>
          <dl className="workflow-rail-stats">
            <div>
              <dt>Target</dt>
              <dd>{environmentProfile.target}</dd>
            </div>
            <div>
              <dt>Credentials</dt>
              <dd>{environmentProfile.credentialScope || "local"}</dd>
            </div>
            <div>
              <dt>Mock policy</dt>
              <dd>{environmentProfile.mockBindingPolicy || "warn"}</dd>
            </div>
            <div>
              <dt>Bindings</dt>
              <dd>{bindingRegistrySummary.ready}/{bindingRegistrySummary.total}</dd>
            </div>
          </dl>
          <div className="workflow-settings-production-editor">
            <label>
              Target
              <select
                data-testid="workflow-environment-target"
                value={environmentProfile.target}
                disabled={workflowReadOnly}
                onChange={(event) =>
                  onUpdateEnvironmentProfile({
                    target: event.target.value as NonNullable<GraphGlobalConfig["environmentProfile"]>["target"],
                  })
                }
              >
                <option value="local">Local</option>
                <option value="sandbox">Sandbox</option>
                <option value="staging">Staging</option>
                <option value="production">Production</option>
              </select>
            </label>
            <label>
              Credential scope
              <input
                data-testid="workflow-environment-credential-scope"
                value={environmentProfile.credentialScope ?? ""}
                disabled={workflowReadOnly}
                placeholder="local, sandbox, staging, production"
                onChange={(event) => onUpdateEnvironmentProfile({ credentialScope: event.target.value })}
              />
            </label>
            <label>
              Mock bindings
              <select
                data-testid="workflow-environment-mock-policy"
                value={environmentProfile.mockBindingPolicy ?? "warn"}
                disabled={workflowReadOnly}
                onChange={(event) =>
                  onUpdateEnvironmentProfile({
                    mockBindingPolicy: event.target.value as NonNullable<GraphGlobalConfig["environmentProfile"]>["mockBindingPolicy"],
                  })
                }
              >
                <option value="allow">Allow in this environment</option>
                <option value="warn">Warn before activation</option>
                <option value="block">Block activation</option>
              </select>
            </label>
          </div>
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-binding-registry">
          <h4>Binding registry</h4>
          <dl className="workflow-rail-stats" data-testid="workflow-binding-registry-summary">
            <div>
              <dt>Total</dt>
              <dd>{bindingRegistrySummary.total}</dd>
            </div>
            <div>
              <dt>Ready</dt>
              <dd>{bindingRegistrySummary.ready}</dd>
            </div>
            <div>
              <dt>Mock</dt>
              <dd>{bindingRegistrySummary.mock}</dd>
            </div>
            <div>
              <dt>Approvals</dt>
              <dd>{bindingRegistrySummary.approval}</dd>
            </div>
          </dl>
          <div className="workflow-rail-list">
            {bindingRegistryRows.map((row) => (
              <article
                key={row.id}
                className={`workflow-binding-row is-${
                  bindingCheckResults[row.id]?.status ?? (row.ready ? "ready" : "blocked")
                }`}
                data-testid={`workflow-binding-registry-row-${row.nodeItem.id}`}
              >
                <header>
                  <div>
                    <strong>{row.nodeItem.name}</strong>
                    <span>
                      {row.bindingKind} · {row.mode} · {row.ready ? "ready" : "needs setup"}
                    </span>
                  </div>
                  <div className="workflow-binding-actions">
                    <button
                      type="button"
                      data-testid={`workflow-binding-check-${row.id}`}
                      onClick={() => void handleCheckBinding(row)}
                    >
                      Check
                    </button>
                    <button
                      type="button"
                      data-testid={`workflow-binding-inspect-${row.nodeItem.id}`}
                      onClick={() => onInspectNode(row.nodeItem.id)}
                    >
                      Configure
                    </button>
                  </div>
                </header>
                <dl>
                  <div>
                    <dt>Ref</dt>
                    <dd>{row.ref || "not set"}</dd>
                  </div>
                  <div>
                    <dt>Scope</dt>
                    <dd>{row.scope}</dd>
                  </div>
                  <div>
                    <dt>Side effect</dt>
                    <dd>{row.sideEffectClass}</dd>
                  </div>
                  <div>
                    <dt>Approval</dt>
                    <dd>{row.approval}</dd>
                  </div>
                </dl>
                {bindingCheckResults[row.id] ? (
                  <p
                    className="workflow-binding-check-result"
                    data-testid={`workflow-binding-check-result-${row.id}`}
                    data-status={bindingCheckResults[row.id].status}
                  >
                    <strong>{bindingCheckResults[row.id].summary}</strong>
                    <span>{bindingCheckResults[row.id].detail}</span>
                  </p>
                ) : null}
              </article>
            ))}
            {bindingRegistryRows.length === 0 ? (
              <article className="workflow-output-row">
                <strong>No bindings</strong>
                <span>Add model, connector, parser, or tool primitives to populate this registry.</span>
              </article>
            ) : null}
          </div>
        </section>
        <section className="workflow-rail-section" data-testid="workflow-binding-manifest">
          <h4>Binding manifest</h4>
          <div className="workflow-package-actions">
            <button
              type="button"
              data-testid="workflow-generate-binding-manifest"
              onClick={onGenerateBindingManifest}
            >
              Refresh manifest
            </button>
          </div>
          {bindingManifest ? (
            <>
              <dl className="workflow-rail-stats" data-testid="workflow-binding-manifest-summary">
                <div>
                  <dt>Total</dt>
                  <dd>{bindingManifest.summary.total}</dd>
                </div>
                <div>
                  <dt>Ready</dt>
                  <dd>{bindingManifest.summary.ready}</dd>
                </div>
                <div>
                  <dt>Blocked</dt>
                  <dd>{bindingManifest.summary.blocked}</dd>
                </div>
                <div>
                  <dt>Approvals</dt>
                  <dd>{bindingManifest.summary.approvalRequired}</dd>
                </div>
              </dl>
              <p data-testid="workflow-binding-manifest-environment">
                {bindingManifest.environmentProfile.target} · {bindingManifest.environmentProfile.credentialScope ?? "local"} · mocks {bindingManifest.environmentProfile.mockBindingPolicy ?? "block"}
              </p>
            </>
          ) : (
            <article className="workflow-output-row">
              <strong>No manifest generated</strong>
              <span>Refresh after binding changes to capture environment readiness for packaging.</span>
            </article>
          )}
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-model-bindings">
          <h4>Model bindings</h4>
          {modelBindingItems.map(([bindingKey, binding]) => (
            <article key={bindingKey} className={`workflow-test-row is-${binding.modelId ? "passed" : binding.required ? "blocked" : "idle"}`}>
              <strong>{bindingKey}</strong>
              <span>{binding.modelId || (binding.required ? "required" : "optional")}</span>
            </article>
          ))}
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-capabilities">
          <h4>Required capabilities</h4>
          {requiredCapabilityItems.length > 0 ? (
            requiredCapabilityItems.map(([capability, requirement]) => (
              <article key={capability} className="workflow-output-row">
                <strong>{capability}</strong>
                <span>{requirement.bindingKey ? `binding: ${requirement.bindingKey}` : requirement.notes ?? "required"}</span>
              </article>
            ))
          ) : (
            <article className="workflow-output-row">
              <strong>No required capabilities</strong>
              <span>Nodes can still declare their own binding requirements.</span>
            </article>
          )}
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-policy">
          <h4>Run policy</h4>
          <dl className="workflow-rail-stats">
            <div>
              <dt>Budget</dt>
              <dd>{workflowPolicy.maxBudget}</dd>
            </div>
            <div>
              <dt>Steps</dt>
              <dd>{workflowPolicy.maxSteps}</dd>
            </div>
            <div>
              <dt>Timeout</dt>
              <dd>{workflowPolicy.timeoutMs} ms</dd>
            </div>
            <div>
              <dt>Package</dt>
              <dd>{portablePackage ? portablePackage.manifest.readinessStatus : "not exported"}</dd>
            </div>
          </dl>
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-production-profile">
          <h4>Production checklist</h4>
          <dl className="workflow-rail-stats">
            <div>
              <dt>Error path</dt>
              <dd>{productionProfile.errorWorkflowPath || (hasErrorOrRetryPath ? "graph path" : "not set")}</dd>
            </div>
            <div>
              <dt>Evaluations</dt>
              <dd>{productionProfile.evaluationSetPath || `${criticalAiNodeIds.length} model node${criticalAiNodeIds.length === 1 ? "" : "s"}`}</dd>
            </div>
            <div>
              <dt>Value estimate</dt>
              <dd>{productionProfile.expectedTimeSavedMinutes ? `${productionProfile.expectedTimeSavedMinutes} min/run` : "not set"}</dd>
            </div>
            <div>
              <dt>MCP access</dt>
              <dd>{mcpToolNodes.length === 0 ? "not used" : productionProfile.mcpAccessReviewed ? "reviewed" : "needs review"}</dd>
            </div>
          </dl>
          <div className="workflow-settings-production-editor" data-testid="workflow-production-profile-editor">
            <label>
              Error workflow path
              <input
                data-testid="workflow-production-error-path"
                value={productionProfile.errorWorkflowPath ?? ""}
                disabled={workflowReadOnly}
                placeholder=".agents/workflows/error-handler.workflow.json"
                onChange={(event) => onUpdateProductionProfile({ errorWorkflowPath: event.target.value })}
              />
            </label>
            <label>
              Evaluation set path
              <input
                data-testid="workflow-production-evaluation-path"
                value={productionProfile.evaluationSetPath ?? ""}
                disabled={workflowReadOnly}
                placeholder=".agents/workflows/evaluations/reporting.tests.json"
                onChange={(event) => onUpdateProductionProfile({ evaluationSetPath: event.target.value })}
              />
            </label>
            <label>
              Expected time saved per run
              <input
                data-testid="workflow-production-time-saved"
                type="number"
                min={0}
                step={1}
                value={productionProfile.expectedTimeSavedMinutes ?? 0}
                disabled={workflowReadOnly}
                onChange={(event) =>
                  onUpdateProductionProfile({
                    expectedTimeSavedMinutes: Number(event.target.value || 0),
                  })
                }
              />
            </label>
            <label className="workflow-config-checkbox">
              <input
                data-testid="workflow-production-mcp-reviewed"
                type="checkbox"
                checked={productionProfile.mcpAccessReviewed === true}
                disabled={workflowReadOnly}
                onChange={(event) => onUpdateProductionProfile({ mcpAccessReviewed: event.target.checked })}
              />
              MCP access reviewed
            </label>
          </div>
        </section>
      </>
    );
  }
  const selectedNodeRun = selectedNode
    ? lastRunResult?.nodeRuns.find((nodeRun) => nodeRun.nodeId === selectedNode.id) ?? null
    : null;
  const selectedNodeIssues = selectedNode
    ? [
        ...(validationResult?.errors ?? []),
        ...(validationResult?.warnings ?? []),
        ...(validationResult?.missingConfig ?? []),
        ...(validationResult?.connectorBindingIssues ?? []),
        ...(validationResult?.executionReadinessIssues ?? []),
        ...(validationResult?.verificationIssues ?? []),
        ...(readinessResult?.errors ?? []),
        ...(readinessResult?.warnings ?? []),
        ...(readinessResult?.missingConfig ?? []),
        ...(readinessResult?.connectorBindingIssues ?? []),
        ...(readinessResult?.executionReadinessIssues ?? []),
        ...(readinessResult?.verificationIssues ?? []),
      ].filter((issue) => issue.nodeId === selectedNode.id)
    : [];
  const selectedNodeTests = selectedNode
    ? tests.filter((test) => test.targetNodeIds.includes(selectedNode.id))
    : [];
  const selectedInputPorts = selectedNode?.ports?.filter((port) => port.direction === "input") ?? [];
  const selectedOutputPorts = selectedNode?.ports?.filter((port) => port.direction === "output") ?? [];
  const selectedLogic = selectedNode?.config?.logic ?? {};
  const bindingSummary = selectedNode ? workflowSelectedNodeBindingSummary(selectedNode, selectedLogic) : [];
  const selectedHarnessEvidence = selectedNode ? harnessNodeEvidenceSummary(selectedNode) : [];
  const selectedHarnessAttempt = selectedNodeRun?.harnessAttempt ?? null;
  const selectedReadOnlyRoutingNodeIndex =
    selectedNode?.runtimeBinding && harnessDefaultRuntimeDispatchProof
      ? harnessReadOnlyRoutingNodeKinds.findIndex(
          (kind) => kind === selectedNode.runtimeBinding?.componentKind,
        )
      : -1;
  const selectedReadOnlyRoutingAttemptId =
    selectedReadOnlyRoutingNodeIndex >= 0
      ? harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingAttemptIds[
          selectedReadOnlyRoutingNodeIndex
        ] ?? null
      : null;
  const selectedReadOnlyRoutingReceiptId =
    selectedReadOnlyRoutingNodeIndex >= 0
      ? harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReceiptIds[
          selectedReadOnlyRoutingNodeIndex
        ] ?? null
      : null;
  const selectedReadOnlyRoutingReplayRef =
    selectedReadOnlyRoutingNodeIndex >= 0
      ? harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReplayFixtureRefs[
          selectedReadOnlyRoutingNodeIndex
        ] ?? null
      : null;
  const selectedAuthorityGateLiveProofs =
    selectedNode?.runtimeBinding &&
    (selectedNode.runtimeBinding.componentKind === "policy_gate" ||
      selectedNode.runtimeBinding.componentKind === "approval_gate")
      ? harnessAuthorityGateLiveProofs.filter(
          (gate) =>
            gate.node?.id === selectedNode.id ||
            gate.componentKind === selectedNode.runtimeBinding?.componentKind,
        )
      : [];
  const selectedPinnedFixture =
    selectedNodeFixtures.find((fixture) => fixture.pinned) ??
    selectedNodeFixtures[0] ??
    null;
  const selectedStaleFixtureCount = selectedNodeFixtures.filter(
    (fixture) => fixture.stale || fixture.validationStatus === "stale",
  ).length;
  const selectedInputPreview = workflowValuePreview(
    selectedNodeRun?.input ?? selectedPinnedFixture?.input ?? selectedLogic.payload ?? null,
  );
  const selectedOutputPreview = workflowValuePreview(
    selectedNodeRun?.output ?? selectedPinnedFixture?.output ?? null,
  );
  const selectedErrorPreview = workflowValuePreview(selectedNodeRun?.error ?? null);
  const selectedAttachmentEdges = selectedNode
    ? workflow.edges.filter((edge) => {
        if (edge.to !== selectedNode.id) return false;
        const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
        return ["model", "memory", "tool", "parser", "approval"].includes(String(edgeClass));
      })
    : [];
  const selectedAttachmentNodeById = new Map(workflow.nodes.map((nodeItem) => [nodeItem.id, nodeItem]));
  const selectedAttachmentRows = selectedAttachmentEdges.map((edge) => {
    const edgeClass = String(edge.connectionClass ?? edge.data?.connectionClass ?? edge.toPort ?? "data");
    const sourceNode = selectedAttachmentNodeById.get(edge.from);
    return {
      id: edge.id,
      edgeClass,
      nodeId: sourceNode?.id ?? edge.from,
      nodeName: sourceNode?.name ?? edge.from,
      nodeType: sourceNode?.type ?? "node",
    };
  });
  const showAiCluster =
    selectedNode?.type === "model_call" ||
    selectedNode?.config?.logic?.viewMacro?.expandedFrom === "agent_loop_macro" ||
    selectedAttachmentRows.length > 0;
  const hasAttachmentClass = (connectionClass: string) =>
    selectedAttachmentRows.some((row) => row.edgeClass === connectionClass);
  const modelBindingReady =
    bindingSummary.find((item) => item.label === "Model")?.ready ??
    hasAttachmentClass("model");
  const parserReady =
    hasAttachmentClass("parser") ||
    Boolean(selectedLogic.parserBinding?.resultSchema || selectedLogic.outputSchema);
  const toolRows = selectedAttachmentRows.filter((row) => row.edgeClass === "tool");
  const approvalRows = selectedAttachmentRows.filter((row) => row.edgeClass === "approval");
  const memoryReady = hasAttachmentClass("memory") || hasAttachmentClass("state");
  const selectedHarnessGroupNodeIds = new Set(selectedHarnessGroup?.innerNodeIds ?? []);
  const selectedHarnessGroupNodes = selectedHarnessGroup
    ? selectedHarnessGroup.innerNodeIds
        .map((nodeId) => workflow.nodes.find((nodeItem) => nodeItem.id === nodeId))
        .filter((nodeItem): nodeItem is Node => Boolean(nodeItem))
    : [];
  const selectedHarnessGroupAttempts = selectedHarnessGroup
    ? (lastRunResult?.harnessAttempts ?? []).filter((attempt) =>
        selectedHarnessGroupNodeIds.has(attempt.workflowNodeId),
      )
    : [];
  const selectedHarnessGroupComparisons = selectedHarnessGroup
    ? (lastRunResult?.harnessShadowComparisons ?? []).filter((comparison) =>
        selectedHarnessGroupNodeIds.has(comparison.workflowNodeId),
      )
    : [];
  const selectedHarnessGroupGatedRun = selectedHarnessGroup
    ? (lastRunResult?.harnessGatedClusterRuns ?? []).find(
        (run) => String(run.clusterId) === String(selectedHarnessGroup.groupId),
      ) ?? null
    : null;
  const selectedHarnessGroupIssues = selectedHarnessGroup
    ? [
        ...(validationResult?.errors ?? []),
        ...(validationResult?.warnings ?? []),
        ...(validationResult?.executionReadinessIssues ?? []),
        ...(readinessResult?.errors ?? []),
        ...(readinessResult?.warnings ?? []),
        ...(readinessResult?.executionReadinessIssues ?? []),
      ].filter((issue) => issue.nodeId && selectedHarnessGroupNodeIds.has(issue.nodeId))
    : [];
  return (
    <>
      <h3>Outputs</h3>
      {harnessWorkbenchDeepLink ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-harness-deep-link-state"
        >
          <h4>Deep link</h4>
          <article className="workflow-output-row">
            <strong>Workbench state</strong>
            <span>
              {selectedHarnessGroup
                ? `group ${selectedHarnessGroup.groupId}`
                : selectedNode?.runtimeBinding?.componentId ??
                  selectedNode?.id ??
                  "run"}
            </span>
            <small>{harnessWorkbenchDeepLink}</small>
          </article>
          <button
            type="button"
            data-testid="workflow-copy-harness-deep-link"
            onClick={onCopyHarnessDeepLink}
          >
            Copy link
          </button>
        </section>
      ) : null}
      {harnessDefaultRuntimeDispatchProof ? (
        <section
          className="workflow-rail-section workflow-harness-authority-gates"
          data-testid="workflow-harness-authority-gate-live"
        >
          <h4>Authority tooling gates</h4>
          <dl
            className="workflow-rail-stats"
            data-testid="workflow-harness-authority-gate-summary"
          >
            <div>
              <dt>Ready</dt>
              <dd>
                {harnessAuthorityGateReadyCount}/{harnessAuthorityGateLiveProofs.length}
              </dd>
            </div>
            <div>
              <dt>Attempts</dt>
              <dd>{harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveAttemptIds.length}</dd>
            </div>
            <div>
              <dt>Receipts</dt>
              <dd>{harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveReceiptIds.length}</dd>
            </div>
            <div>
              <dt>Replay</dt>
              <dd>{harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveReplayFixtureRefs.length}</dd>
            </div>
          </dl>
          <article
            className={`workflow-output-row is-${
              harnessAuthorityGateLiveReady ? "ready" : "blocked"
            }`}
            data-testid="workflow-harness-authority-gate-rollup"
          >
            <strong>
              {workflowProofString(
                harnessAuthorityToolingProof,
                "policyDecision",
                "authority gate proof pending",
              )}
            </strong>
            <span>
              destructive denied{" "}
              {harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveRouteDenied
                ? "yes"
                : "review"} · approval gate{" "}
              {harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReady
                ? "live"
                : "blocked"}
            </span>
            <small>
              side effects{" "}
              {harnessDefaultRuntimeDispatchProof.authorityToolingSideEffectsExecuted
                ? "executed"
                : "not executed"} · rollback{" "}
              {harnessDefaultRuntimeDispatchProof.authorityToolingRollbackAvailable
                ? "ready"
                : "blocked"}
            </small>
          </article>
          {renderHarnessAuthorityGateProofRows(harnessAuthorityGateLiveProofs, {
            listTestId: "workflow-harness-authority-gate-list",
            gateTestIdPrefix: "workflow-harness-authority-gate",
          })}
        </section>
      ) : null}
      {selectedHarnessGroup ? (
        <section
          className="workflow-node-inspector workflow-harness-group-inspector"
          data-testid="workflow-harness-group-inspector"
          data-harness-group-id={selectedHarnessGroup.groupId}
        >
          <header>
            <div>
              <strong>{selectedHarnessGroup.label}</strong>
              <span>
                {selectedHarnessGroup.collapsed ? "collapsed" : "expanded"} · {selectedHarnessGroup.innerNodeIds.length} nodes
              </span>
            </div>
            <small>{selectedHarnessGroup.statusRollup.executionMode}</small>
          </header>
          <dl
            className="workflow-rail-stats"
            data-testid="workflow-harness-group-readiness-rollup"
          >
            <div>
              <dt>Readiness</dt>
              <dd>{selectedHarnessGroup.statusRollup.readiness}</dd>
            </div>
            <div>
              <dt>Live-ready</dt>
              <dd>{selectedHarnessGroup.statusRollup.liveReadyCount}/{selectedHarnessGroup.innerNodeIds.length}</dd>
            </div>
            <div>
              <dt>Receipts</dt>
              <dd>{selectedHarnessGroup.statusRollup.receiptKindCount}</dd>
            </div>
            <div>
              <dt>Replay</dt>
              <dd>{selectedHarnessGroup.statusRollup.replayFixtureCount}</dd>
            </div>
            <div>
              <dt>Divergence</dt>
              <dd>{selectedHarnessGroup.statusRollup.divergenceCount}</dd>
            </div>
            <div>
              <dt>Activation</dt>
              <dd>{selectedHarnessGroup.statusRollup.activationState ?? "unknown"}</dd>
            </div>
          </dl>
          <section
            className="workflow-rail-section"
            data-testid="workflow-harness-group-components"
          >
            <h4>Components</h4>
            {selectedHarnessGroupNodes.map((nodeItem) => (
              <button
                key={nodeItem.id}
                type="button"
                className="workflow-search-result"
                data-testid={`workflow-harness-group-component-${nodeItem.id}`}
                onClick={() => {
                  if (onInspectHarnessGroupNode) {
                    onInspectHarnessGroupNode(
                      String(selectedHarnessGroup.groupId),
                      nodeItem.id,
                    );
                    return;
                  }
                  onInspectNode(nodeItem.id);
                }}
              >
                <strong>{nodeItem.name}</strong>
                <span>
                  {nodeItem.runtimeBinding?.componentKind ?? nodeItem.type}
                  {" · "}
                  {nodeItem.runtimeBinding?.readiness ?? "projection_only"}
                </span>
                <small>
                  {nodeItem.runtimeBinding?.componentId ?? nodeItem.id}
                </small>
              </button>
            ))}
          </section>
          <section
            className="workflow-rail-section"
            data-testid="workflow-harness-group-run-status"
          >
            <h4>Run and gates</h4>
            <article className="workflow-output-row" data-testid="workflow-harness-group-run-link">
              <strong>{selectedHarnessGroup.deepLinks.runId ?? "no selected run"}</strong>
              <span>{selectedHarnessGroupGatedRun?.status ?? "gated run not selected"}</span>
              <small>
                {selectedHarnessGroupGatedRun?.gateDecision ??
                  "Select a retained harness run to inspect gate policy decisions."}
              </small>
            </article>
            {selectedHarnessGroupGatedRun ? (
              <article
                className={`workflow-test-row is-${selectedHarnessGroupGatedRun.promotionBlocked ? "blocked" : "passed"}`}
                data-testid="workflow-harness-group-gated-run"
              >
                <strong>{selectedHarnessGroupGatedRun.clusterLabel}</strong>
                <span>
                  canary {selectedHarnessGroupGatedRun.canaryStatus} · rollback {selectedHarnessGroupGatedRun.rollbackTarget}
                </span>
                <small>
                  {selectedHarnessGroupGatedRun.nodeAttemptIds.length} attempts · {selectedHarnessGroupGatedRun.receiptIds.length} receipts
                </small>
              </article>
            ) : null}
          </section>
          <section
            className="workflow-rail-section"
            data-testid="workflow-harness-group-receipt-refs"
          >
            <h4>Receipts</h4>
            {selectedHarnessGroup.deepLinks.receiptRefs.slice(0, 8).map((receiptRef) => (
              <button
                key={receiptRef}
                type="button"
                className={`workflow-harness-ref-button ${
                  selectedHarnessReceiptRef === receiptRef ? "is-active" : ""
                }`}
                data-testid={`workflow-harness-group-receipt-ref-${receiptRef}`}
                onClick={() => onSelectHarnessReceiptRef?.(receiptRef)}
              >
                <code>{receiptRef}</code>
              </button>
            ))}
            {selectedHarnessGroup.deepLinks.receiptRefs.length === 0 ? (
              <span>No receipt refs captured for this group yet.</span>
            ) : null}
          </section>
          <section
            className="workflow-rail-section"
            data-testid="workflow-harness-group-replay-fixtures"
          >
            <h4>Replay</h4>
            {selectedHarnessGroup.deepLinks.replayFixtureRefs.slice(0, 8).map((fixtureRef) => (
              <button
                key={fixtureRef}
                type="button"
                className={`workflow-harness-ref-button ${
                  selectedHarnessReplayFixtureRef === fixtureRef ? "is-active" : ""
                }`}
                data-testid={`workflow-harness-group-replay-ref-${fixtureRef}`}
                onClick={() => onSelectHarnessReplayFixtureRef?.(fixtureRef)}
              >
                <code>{fixtureRef}</code>
              </button>
            ))}
            {selectedHarnessGroup.deepLinks.replayFixtureRefs.length === 0 ? (
              <span>No replay fixture refs captured for this group yet.</span>
            ) : null}
          </section>
          {(selectedHarnessGroupIssues.length > 0 ||
            (selectedHarnessGroupGatedRun?.activationBlockers.length ?? 0) > 0) ? (
            <section
              className="workflow-rail-section"
              data-testid="workflow-harness-group-activation-blockers"
            >
              <h4>Activation blockers</h4>
              {(selectedHarnessGroupGatedRun?.activationBlockers ?? []).slice(0, 4).map((blocker) => (
                <article key={blocker} className="workflow-test-row is-blocked">
                  <strong>Gate blocker</strong>
                  <span>{blocker}</span>
                </article>
              ))}
              {selectedHarnessGroupIssues.slice(0, 4).map((issue, index) => (
                <button
                  key={`${issue.code}-${issue.nodeId}-${index}`}
                  type="button"
                  className="workflow-search-result is-warning"
                  data-testid={`workflow-harness-group-issue-${index}`}
                  onClick={() => onResolveIssue(issue)}
                >
                  <strong>{workflowIssueTitle(issue)}</strong>
                  <span>{workflowNodeName(workflow, issue.nodeId)}</span>
                  <small>{issue.message}</small>
                </button>
              ))}
            </section>
          ) : null}
          {selectedHarnessGroupComparisons.length > 0 ? (
            <section
              className="workflow-rail-section"
              data-testid="workflow-harness-group-shadow-comparison"
            >
              <h4>Live vs shadow</h4>
              {selectedHarnessGroupComparisons.slice(-5).map((comparison) => (
                <article
                  key={`${comparison.liveAttemptId}-${comparison.shadowAttemptId}`}
                  className={`workflow-test-row is-${comparison.blocking ? "blocked" : "passed"}`}
                >
                  <strong>{comparison.divergence}</strong>
                  <span>{workflowNodeName(workflow, comparison.workflowNodeId)}</span>
                  <small>{comparison.summary}</small>
                </article>
              ))}
            </section>
          ) : null}
          {selectedHarnessGroupAttempts.length > 0 ? (
            <section
              className="workflow-rail-section"
              data-testid="workflow-harness-group-attempts"
            >
              <h4>Attempts</h4>
              {selectedHarnessGroupAttempts.slice(-6).map((attempt) => (
                <article
                  key={attempt.attemptId}
                  className={`workflow-test-row is-${attempt.status}`}
                >
                  <strong>{workflowNodeName(workflow, attempt.workflowNodeId)}</strong>
                  <span>
                    {attempt.executionMode} · {attempt.readiness}
                  </span>
                  <small>
                    {attempt.receiptIds.length} receipts · {attempt.replay.determinism}
                  </small>
                </article>
              ))}
            </section>
          ) : null}
        </section>
      ) : null}
      {selectedNode ? (
        <section className="workflow-node-inspector" data-testid="workflow-selected-node-inspector">
          <header>
            <div>
              <strong>{selectedNode.name}</strong>
              <span>{selectedNode.type} · {selectedNodeRun?.status ?? selectedNode.status ?? "idle"}</span>
            </div>
            <button
              type="button"
              data-testid="workflow-rail-configure-node"
              disabled={workflowReadOnly}
              onClick={onConfigureNode}
            >
              Configure
            </button>
          </header>
          <section
            className="workflow-node-inspector-lifecycle"
            data-testid="workflow-selected-node-quick-actions"
          >
            <button
              type="button"
              data-testid="workflow-inspector-run-node"
              disabled={workflowReadOnly}
              onClick={() => onRunNode(selectedNode, selectedPinnedFixture ?? undefined)}
            >
              Execute node
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-run-upstream"
              disabled={workflowReadOnly}
              onClick={() => onRunUpstream(selectedNode)}
            >
              Execute upstream
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-replay-fixture"
              disabled={workflowReadOnly || !selectedPinnedFixture}
              onClick={() =>
                onDryRunFixtureForNode(selectedNode, selectedPinnedFixture ?? undefined)
              }
            >
              Replay fixture
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-capture-fixture"
              disabled={workflowReadOnly}
              onClick={() => onCaptureFixtureForNode(selectedNode)}
            >
              Capture fixture
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-pin-fixture"
              disabled={workflowReadOnly || !selectedPinnedFixture || selectedPinnedFixture.pinned === true}
              onClick={() => {
                if (selectedPinnedFixture) {
                  onPinFixtureForNode(selectedNode, selectedPinnedFixture);
                }
              }}
            >
              Pin fixture
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-add-test-from-output"
              disabled={workflowReadOnly}
              onClick={() => onAddTestFromOutput(selectedNode)}
            >
              Add test from output
            </button>
          </section>
          <dl className="workflow-node-inspector-stats" data-testid="workflow-selected-node-status">
            <div>
              <dt>Run</dt>
              <dd>{selectedNodeRun?.status ?? "not run"}</dd>
            </div>
            <div>
              <dt>Attempt</dt>
              <dd>{selectedNodeRun?.attempt ?? "none"}</dd>
            </div>
            <div>
              <dt>Tests</dt>
              <dd>{selectedNodeTests.length}</dd>
            </div>
            <div>
              <dt>Issues</dt>
              <dd>{selectedNodeIssues.length}</dd>
            </div>
          </dl>
          {selectedHarnessEvidence.length > 0 ? (
            <section
              className="workflow-node-inspector-section"
              data-testid="workflow-selected-node-harness-component"
            >
              <h4>Harness component</h4>
              <div className="workflow-rail-list" data-testid="workflow-selected-node-harness-receipts">
                {selectedHarnessEvidence.map((item) => (
                  <article key={item.label} className="workflow-output-row">
                    <strong>{item.label}</strong>
                    <span>{item.value}</span>
                  </article>
                ))}
              </div>
              {selectedNode.runtimeBinding ? (
                <article className="workflow-output-row" data-testid="workflow-selected-node-replay-binding">
                  <strong>Replay envelope</strong>
                  <span>
                    {selectedNode.runtimeBinding.executionMode ?? "projection"}
                    {" · "}
                    {selectedNode.runtimeBinding.readiness ?? "projection_only"}
                    {" · "}
                    {selectedNode.runtimeBinding.replayEnvelope?.determinism
                      ?? (selectedNode.runtimeBinding.replay.deterministicEnvelope ? "deterministic" : "best effort")}
                    {" · "}
                    {selectedNode.runtimeBinding.slotIds?.join(", ") || "no slots"}
                  </span>
                  <small>
                    {selectedNode.runtimeBinding.replayEnvelope?.redactionPolicy ?? "runtime_redacted"}
                    {" · "}
                    {selectedNode.runtimeBinding.evidenceEventKinds.join(", ")}
                  </small>
                </article>
              ) : null}
              {selectedHarnessAttempt ? (
                <article className="workflow-output-row" data-testid="workflow-selected-node-harness-attempt">
                  <strong>Latest attempt</strong>
                  <span>
                    {selectedHarnessAttempt.executionMode}
                    {" · "}
                    {selectedHarnessAttempt.status}
                    {" · "}
                    {selectedHarnessAttempt.receiptIds.length} receipts
                  </span>
                  <small>
                    {selectedHarnessAttempt.inputHash ?? "input hash pending"}
                    {" · "}
                    {selectedHarnessAttempt.outputHash ?? "output hash pending"}
                  </small>
                </article>
              ) : null}
              {selectedReadOnlyRoutingNodeIndex >= 0 && harnessReadOnlyRoutingProof ? (
                <section
                  className="workflow-node-inspector-section"
                  data-testid="workflow-selected-node-read-only-routing-proof"
                >
                  <h4>Read-only routing proof</h4>
                  <dl className="workflow-node-inspector-stats">
                    <div>
                      <dt>Scenario</dt>
                      <dd>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenario ?? "pending"}</dd>
                    </div>
                    <div>
                      <dt>Coverage</dt>
                      <dd>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenarioCoverageKey ?? "pending"}</dd>
                    </div>
                    <div>
                      <dt>Mutation</dt>
                      <dd>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingNoMutationReady ? "blocked" : "review"}</dd>
                    </div>
                    <div>
                      <dt>Source</dt>
                      <dd>{harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingSourceMaterialReady ? "ready" : "pending"}</dd>
                    </div>
                  </dl>
                  <article
                    className="workflow-output-row"
                    data-testid="workflow-selected-node-read-only-routing-receipts"
                  >
                    <strong>{selectedNode.runtimeBinding?.componentKind}</strong>
                    <span>
                      {selectedReadOnlyRoutingAttemptId ?? "attempt pending"} · {selectedReadOnlyRoutingReceiptId ?? "receipt pending"}
                    </span>
                    <small>{selectedReadOnlyRoutingReplayRef ?? "replay fixture pending"}</small>
                  </article>
                  <article className="workflow-output-row" data-testid="workflow-selected-node-read-only-routing-no-mutation">
                    <strong>
                      {harnessReadOnlyRoutingProof.sideEffectsExecuted === false &&
                      harnessReadOnlyRoutingProof.mutationExecuted === false
                        ? "Side effects blocked"
                        : "Side effects need review"}
                    </strong>
                    <span>
                      mode {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingMode ?? String(harnessReadOnlyRoutingProof.mode ?? "unknown")}
                    </span>
                    <small>
                      {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingWorkflowOwnedNodeKinds.join(", ") ?? "node kinds pending"}
                    </small>
                  </article>
                </section>
              ) : null}
            </section>
          ) : null}
          {selectedAuthorityGateLiveProofs.length > 0 ? (
            <section
              className="workflow-node-inspector-section workflow-harness-authority-gates"
              data-testid="workflow-selected-node-authority-gate-live"
            >
              <h4>Authority gate live proof</h4>
              <dl className="workflow-node-inspector-stats">
                <div>
                  <dt>Gates</dt>
                  <dd>{selectedAuthorityGateLiveProofs.length}</dd>
                </div>
                <div>
                  <dt>Ready</dt>
                  <dd>
                    {
                      selectedAuthorityGateLiveProofs.filter((gate) => gate.ready)
                        .length
                    }/{selectedAuthorityGateLiveProofs.length}
                  </dd>
                </div>
                <div>
                  <dt>Receipts</dt>
                  <dd>
                    {selectedAuthorityGateLiveProofs.reduce(
                      (count, gate) => count + gate.receiptIds.length,
                      0,
                    )}
                  </dd>
                </div>
                <div>
                  <dt>Replay</dt>
                  <dd>
                    {selectedAuthorityGateLiveProofs.reduce(
                      (count, gate) => count + gate.replayFixtureRefs.length,
                      0,
                    )}
                  </dd>
                </div>
              </dl>
              {renderHarnessAuthorityGateProofRows(
                selectedAuthorityGateLiveProofs,
                {
                  listTestId: "workflow-selected-node-authority-gate-list",
                  gateTestIdPrefix: "workflow-selected-node-authority-gate",
                },
              )}
            </section>
          ) : null}
          <section
            className="workflow-node-inspector-zones"
            data-testid="workflow-selected-node-io-workbench"
          >
            <article data-testid="workflow-selected-node-input-zone">
              <header>
                <strong>Input</strong>
                <span>
                  {selectedNodeRun
                    ? "latest run"
                    : selectedPinnedFixture
                      ? "pinned fixture"
                      : "empty"}
                </span>
              </header>
              <span>{selectedInputPreview.summary}</span>
              <small>{selectedInputPreview.detail}</small>
            </article>
            <article data-testid="workflow-selected-node-config-zone">
              <header>
                <strong>Config</strong>
                <span>
                  {bindingSummary.every((item) => item.ready)
                    ? "ready"
                    : "needs setup"}
                </span>
              </header>
              <span>
                {bindingSummary
                  .map((item) => `${item.label}: ${item.value}`)
                  .join(" · ") || "basic settings"}
              </span>
              <small>
                {selectedNodeFixtures.length} fixture
                {selectedNodeFixtures.length === 1 ? "" : "s"}
                {selectedStaleFixtureCount > 0
                  ? ` · ${selectedStaleFixtureCount} stale`
                  : ""}
              </small>
            </article>
            <article data-testid="workflow-selected-node-output-zone">
              <header>
                <strong>Output</strong>
                <span>{selectedNodeRun?.status ?? "not run"}</span>
              </header>
              <span>{selectedOutputPreview.summary}</span>
              <small>
                {selectedNodeRun?.error
                  ? selectedErrorPreview.summary
                  : selectedOutputPreview.detail}
              </small>
            </article>
          </section>
          {showAiCluster ? (
            <section
              className="workflow-node-inspector-section workflow-node-ai-cluster"
              data-testid="workflow-selected-node-ai-cluster"
            >
              <h4>AI cluster</h4>
              <dl className="workflow-node-inspector-ai-grid">
                <div data-status={modelBindingReady ? "ready" : "blocked"}>
                  <dt>Model</dt>
                  <dd>{modelBindingReady ? "ready" : "missing"}</dd>
                </div>
                <div data-status={memoryReady ? "ready" : "idle"}>
                  <dt>Memory</dt>
                  <dd>{memoryReady ? "connected" : "none"}</dd>
                </div>
                <div data-status={toolRows.length > 0 ? "ready" : "idle"}>
                  <dt>Tools</dt>
                  <dd>
                    {toolRows.length}
                    {approvalRows.length > 0 ? " · approval" : ""}
                  </dd>
                </div>
                <div data-status={parserReady ? "ready" : "idle"}>
                  <dt>Parser</dt>
                  <dd>{parserReady ? "schema ready" : "none"}</dd>
                </div>
              </dl>
              {selectedAttachmentRows.length > 0 ? (
                <div className="workflow-node-ai-attachments">
                  {selectedAttachmentRows.map((row) => (
                    <button
                      key={row.id}
                      type="button"
                      data-testid="workflow-selected-node-ai-attachment"
                      data-connection-class={row.edgeClass}
                      onClick={() => onInspectNode(row.nodeId)}
                    >
                      <strong>{row.nodeName}</strong>
                      <span>{row.edgeClass} · {row.nodeType}</span>
                    </button>
                  ))}
                </div>
              ) : null}
            </section>
          ) : null}
          <section className="workflow-node-inspector-section" data-testid="workflow-selected-node-ports">
            <h4>Ports</h4>
            <div className="workflow-node-inspector-port-groups">
              <div>
                <span>Inputs</span>
                {selectedInputPorts.length > 0
                  ? selectedInputPorts.map((port) => (
                      <em key={`input-${port.id}`} data-connection-class={port.connectionClass}>
                        {port.label} · {port.connectionClass}
                      </em>
                    ))
                  : <small>none</small>}
              </div>
              <div>
                <span>Outputs</span>
                {selectedOutputPorts.length > 0
                  ? selectedOutputPorts.map((port) => (
                      <em key={`output-${port.id}`} data-connection-class={port.connectionClass}>
                        {port.label} · {port.connectionClass}
                      </em>
                    ))
                  : <small>none</small>}
              </div>
            </div>
          </section>
          <section className="workflow-node-inspector-section" data-testid="workflow-selected-node-bindings">
            <h4>Configuration</h4>
            {bindingSummary.map((item) => (
              <article key={item.label} className={`workflow-test-row is-${item.ready ? "passed" : "blocked"}`}>
                <strong>{item.label}</strong>
                <span>{item.value}</span>
              </article>
            ))}
          </section>
          {selectedNodeIssues.length > 0 ? (
            <section className="workflow-node-inspector-section" data-testid="workflow-selected-node-blockers">
              <h4>Needs attention</h4>
              {selectedNodeIssues.slice(0, 5).map((issue, index) => (
                <button
                  key={`${issue.code}-${index}`}
                  type="button"
                  className="workflow-search-result is-blocked"
                  data-testid={`workflow-selected-node-issue-${index}`}
                  onClick={() => onResolveIssue(issue)}
                >
                  <strong>{workflowIssueTitle(issue)}</strong>
                  <span>{issue.message}</span>
                  <small>{workflowIssueActionLabel(issue)}</small>
                </button>
              ))}
            </section>
          ) : null}
          {selectedNodeRun?.output !== undefined ? (
            <section className="workflow-node-inspector-section" data-testid="workflow-selected-node-latest-output">
              <h4>Latest output</h4>
              {(() => {
                const preview = workflowValuePreview(selectedNodeRun.output);
                return (
                  <article className="workflow-output-row" data-testid="workflow-selected-node-latest-output-preview">
                    <strong>{preview.kind}</strong>
                    <span>{preview.summary}</span>
                    <small>{preview.detail}</small>
                  </article>
                );
              })()}
            </section>
          ) : null}
        </section>
      ) : (
        <>
          <p>{outputNodes.length === 0 ? "No output nodes configured." : `${outputNodes.length} workflow output${outputNodes.length === 1 ? "" : "s"} configured.`}</p>
          <div className="workflow-rail-list" data-testid="workflow-output-node-list">
            {outputNodes.map((nodeItem) => {
              const logic = nodeItem.config?.logic ?? {};
              return (
                <button
                  key={nodeItem.id}
                  type="button"
                  className="workflow-search-result"
                  data-testid={`workflow-output-node-${nodeItem.id}`}
                  onClick={() => onInspectNode(nodeItem.id)}
                >
                  <strong>{nodeItem.name}</strong>
                  <span>{String(logic.format ?? "output")} · {String(logic.deliveryTarget?.targetKind ?? "no delivery")}</span>
                  <small>
                    {logic.materialization?.enabled
                      ? `asset: ${logic.materialization.assetPath ?? "configured"}`
                      : "renderer-only until materialization or delivery is configured"}
                  </small>
                </button>
              );
            })}
            {outputNodes.length === 0 ? (
              <article className="workflow-output-row">
                <strong>No outputs</strong>
                <span>Add an Output primitive to define what the workflow produces.</span>
              </article>
            ) : null}
          </div>
        </>
      )}
    </>
  );
}
