import { useState } from "react";
import type {
  GraphGlobalConfig,
  Node,
  WorkflowBindingCheckResult,
  WorkflowBindingManifest,
  WorkflowCheckpoint,
  WorkflowHarnessActivationCandidateGateResult,
  WorkflowDogfoodRun,
  WorkflowHarnessForkActivationCandidate,
  WorkflowHarnessGroupView,
  WorkflowHarnessPromotionTransitionTarget,
  WorkflowNodeFixture,
  WorkflowPackageImportReview,
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
} from "../../../types/graph";
import {
  WORKFLOW_RUNTIME_UI_STRING_CATALOG,
  normalizeWorkflowRuntimeLocale,
  workflowRuntimeAccessibleStatusLabel,
  workflowRuntimeNodeChrome,
} from "../../../runtime/workflow-runtime-ui-strings";
import {
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
  DEFAULT_AGENT_HARNESS_COMPONENTS,
  DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
  harnessNodeEvidenceSummary,
  harnessSlotsForWorkflow,
  workflowHarnessLivePromotionReadinessProofBlockers,
  workflowHarnessPromotionTransitionEligibility,
  workflowHarnessWorkerAttachBlockers,
  workflowHarnessWorkerAttachLifecycleComplete,
  workflowHarnessWorkerSessionBlockers,
  workflowHarnessWorkerBinding,
  workflowHarnessWorkerBindingRegistryBlockers,
  workflowHarnessForkMutationCanaryNodeAttempts,
  workflowIsBlessedHarness,
  workflowIsHarness,
  workflowIsHarnessFork,
} from "../../../runtime/harness-workflow";
import { workflowValuePreview } from "../../../runtime/workflow-value-preview";
import { workflowTestReadinessModel } from "../../../runtime/workflow-test-readiness-model";
import { workflowRunHistoryModel } from "../../../runtime/workflow-run-history-model";
import type { WorkflowRuntimeTelemetrySummary } from "../../../runtime/workflow-runtime-telemetry-summary";
import { workflowRailSearchModel } from "../../../runtime/workflow-rail-search-model";
import { workflowEntrypointsModel } from "../../../runtime/workflow-entrypoints-model";
import { workflowFileBundleModel } from "../../../runtime/workflow-file-bundle-model";
import { workflowSettingsModel } from "../../../runtime/workflow-settings-model";
import { workflowSettingsHarnessModel } from "../../../runtime/workflow-settings-harness-model";
import type {
  WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  WorkflowRuntimeContextPressureActionDescriptor,
  WorkflowRuntimeDiagnosticsRepairActionDescriptor,
  WorkflowRuntimeTuiControlStateRow,
  WorkflowRuntimeThreadEventLike,
  WorkflowRuntimeWorkspaceTrustActionDescriptor,
} from "../../../runtime/workflow-runtime-event-projection";
import {
  resolveWorkflowHarnessNodeAttemptInspection,
  resolveWorkflowHarnessReceiptInspection,
  resolveWorkflowHarnessReplayInspection,
  workflowBindingCheckResult,
  workflowBindingRegistryRows,
  workflowEnvironmentProfile,
  workflowGithubPrCreatePlanSummary,
  workflowGithubPrCreatePlanStatus,
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowNodeName,
  workflowPackageNodeOutputSummary,
  workflowPackageNodeOutputStatus,
  workflowSelectedNodeBindingSummary,
  workflowUniqueReceiptRefs,
  workflowUniqueReplayFixtureRefs,
  workflowTimeLabel,
  type WorkflowGithubPrCreatePlanSummary,
  type WorkflowPackageNodeOutputSummary,
} from "../../../runtime/workflow-rail-model";

import type {
  WorkflowHarnessActivationGateAction,
  WorkflowHarnessActivationWizardStep,
  WorkflowHarnessAuthorityGateProofView,
  WorkflowHarnessWorkbenchDeepLinkTarget,
} from "./types";
import {
  workflowHarnessAuthorityGateBlockerState,
  workflowHarnessHasReviewedImportActivationInvariant,
  workflowHarnessInvariantBlockers,
  workflowHarnessInvariantIds,
  workflowHarnessUniqueStrings,
  workflowProofBoolean,
  workflowProofString,
  workflowProofStringArray,
  workflowRevisionBindingDeepLinkRef,
} from "./statusPrimitives";
import { WorkflowReadinessPanel } from "./readinessPanel";
import { WorkflowUnitTestsPanel } from "./unitTestsPanel";
import { WorkflowRunsPanel } from "./runsPanel";
import { WorkflowSearchPanel } from "./searchPanel";
import { WorkflowEntrypointsPanel } from "./entrypointsPanel";
import { WorkflowFilesPanel } from "./filesPanel";
import { WorkflowSettingsPanel } from "./settingsPanel";
import { WorkflowSettingsHarnessPanel } from "./settingsHarnessPanel";

function workflowPackageSummaryBoolean(value: boolean | null): string {
  if (value === true) return "true";
  if (value === false) return "false";
  return "";
}

function workflowPrCreateSummaryBoolean(value: boolean | null): string {
  if (value === true) return "true";
  if (value === false) return "false";
  return "";
}

function WorkflowPackageOutputSummaryCard({
  summary,
  testId,
}: {
  summary: WorkflowPackageNodeOutputSummary;
  testId: string;
}) {
  const evidenceLabel =
    summary.packageEvidenceReady === true
      ? "evidence ready"
      : summary.packageEvidenceReady === false
        ? "evidence pending"
        : "evidence unknown";
  const localeLabel =
    summary.kind === "import"
      ? `${summary.sourceWorkflowChromeLocale ?? "default"} -> ${
          summary.importedWorkflowChromeLocale ?? "default"
        }`
      : (summary.workflowChromeLocale ?? "default");
  return (
    <article
      className={`workflow-output-row is-${workflowPackageNodeOutputStatus(
        summary,
      )}`}
      data-testid={testId}
      data-package-node-kind={summary.kind}
      data-package-tool-name={summary.toolName}
      data-package-status={summary.status}
      data-package-path={summary.packagePath ?? ""}
      data-package-manifest-path={summary.manifestPath ?? ""}
      data-package-readiness-status={summary.readinessStatus ?? ""}
      data-package-portable={workflowPackageSummaryBoolean(summary.portable)}
      data-package-evidence-ready={workflowPackageSummaryBoolean(
        summary.packageEvidenceReady,
      )}
      data-imported-workflow-path={summary.importedWorkflowPath ?? ""}
      data-workflow-chrome-locale={summary.workflowChromeLocale ?? ""}
      data-package-import-source-chrome-locale={
        summary.sourceWorkflowChromeLocale ?? ""
      }
      data-package-import-imported-chrome-locale={
        summary.importedWorkflowChromeLocale ?? ""
      }
      data-workflow-chrome-locale-preserved={workflowPackageSummaryBoolean(
        summary.workflowChromeLocalePreserved,
      )}
    >
      <strong>
        {summary.kind === "export" ? "Package export output" : "Package import output"}
      </strong>
      <span>
        {summary.status} · {summary.readinessStatus ?? "readiness pending"} ·{" "}
        {evidenceLabel}
      </span>
      <small>
        {summary.kind === "import"
          ? (summary.importedWorkflowPath ?? "imported workflow pending")
          : (summary.packagePath ?? "package path pending")}
      </small>
      <small>
        locale {localeLabel}
        {summary.kind === "import"
          ? ` · preserved ${
              summary.workflowChromeLocalePreserved === true ? "yes" : "review"
            }`
          : ` · portable ${
              summary.portable === true
                ? "yes"
                : summary.portable === false
                  ? "no"
                  : "unknown"
            }`}
      </small>
    </article>
  );
}

function WorkflowGithubPrCreateOutputSummaryCard({
  summary,
  testId,
  receiptRefs = [],
  replayFixtureRef = null,
}: {
  summary: WorkflowGithubPrCreatePlanSummary;
  testId: string;
  receiptRefs?: string[];
  replayFixtureRef?: string | null;
}) {
  const allReceiptRefs = workflowUniqueReceiptRefs([
    summary.receiptId,
    ...receiptRefs,
  ]);
  const scopeLabel =
    summary.missingScopes.length > 0
      ? `missing ${summary.missingScopes.join(", ")}`
      : summary.scopeGranted === true
        ? "scope granted"
        : "scope pending";
  const mutationLabel =
    summary.mutationExecuted === true
      ? "mutation executed"
      : summary.mutationExecuted === false
        ? "mutation blocked"
        : "mutation pending";
  return (
    <article
      className={`workflow-output-row is-${workflowGithubPrCreatePlanStatus(
        summary,
      )}`}
      data-testid={testId}
      data-github-pr-create-tool-name={summary.toolName}
      data-github-pr-create-action={summary.action}
      data-github-pr-create-status={summary.status}
      data-github-pr-create-decision={summary.decision}
      data-github-pr-create-dry-run={workflowPrCreateSummaryBoolean(
        summary.dryRun,
      )}
      data-github-pr-create-preview-only={workflowPrCreateSummaryBoolean(
        summary.previewOnly,
      )}
      data-github-pr-create-mutation-attempted={workflowPrCreateSummaryBoolean(
        summary.mutationAttempted,
      )}
      data-github-pr-create-mutation-executed={workflowPrCreateSummaryBoolean(
        summary.mutationExecuted,
      )}
      data-github-pr-create-network-lookup={workflowPrCreateSummaryBoolean(
        summary.networkLookupPerformed,
      )}
      data-github-pr-create-request-method={summary.requestMethod ?? ""}
      data-github-pr-create-request-path={summary.requestPath ?? ""}
      data-github-pr-create-request-hash={summary.requestPayloadHash ?? ""}
      data-github-pr-create-request-body-included={workflowPrCreateSummaryBoolean(
        summary.requestBodyIncluded,
      )}
      data-github-pr-create-request-token-included={workflowPrCreateSummaryBoolean(
        summary.requestTokenIncluded,
      )}
      data-github-pr-create-repo={summary.repoFullName ?? ""}
      data-github-pr-create-base-branch={summary.baseBranch ?? ""}
      data-github-pr-create-head-branch={summary.headBranch ?? ""}
      data-github-pr-create-review-gate-status={
        summary.reviewGateStatus ?? ""
      }
      data-github-pr-create-review-satisfied={workflowPrCreateSummaryBoolean(
        summary.reviewSatisfied,
      )}
      data-github-pr-create-required-scopes={summary.requiredScopes.join("|")}
      data-github-pr-create-missing-scopes={summary.missingScopes.join("|")}
      data-github-pr-create-scope-granted={workflowPrCreateSummaryBoolean(
        summary.scopeGranted,
      )}
      data-github-pr-create-plan-id={summary.planId ?? ""}
      data-github-pr-create-receipt-id={summary.receiptId ?? ""}
      data-github-pr-create-receipt-refs={allReceiptRefs.join("|")}
      data-github-pr-create-replay-fixture-ref={replayFixtureRef ?? ""}
      data-github-pr-create-blockers={summary.blockers.join("|")}
      data-github-pr-create-evidence-refs={summary.evidenceRefs.join("|")}
    >
      <strong>GitHub PR create dry-run</strong>
      <span>
        {summary.status} · {mutationLabel} · {scopeLabel}
      </span>
      <small>
        {summary.requestPayloadHash ?? "request hash pending"}
        {" · "}
        {summary.reviewGateStatus ?? "review gate pending"}
        {" · "}
        {allReceiptRefs.length} receipt{allReceiptRefs.length === 1 ? "" : "s"}
      </small>
    </article>
  );
}

export function WorkflowRailPanel({
  panel,
  selectedNode,
  selectedHarnessGroup,
  harnessWorkbenchDeepLink,
  harnessActivationCandidate,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  selectedHarnessRollbackTarget,
  selectedHarnessSelectorDecisionId,
  selectedHarnessDefaultDispatchId,
  selectedHarnessWorkerBindingId,
  selectedHarnessActivationAuditEventId,
  selectedHarnessActivationBlockerIndex,
  selectedHarnessActivationBlockerRef,
  selectedHarnessActivationGateEvidenceRef,
  selectedHarnessActivationGateId,
  selectedHarnessActivationGateNodeAttemptId,
  selectedHarnessActivationGateReceiptRef,
  selectedHarnessActivationGateReplayFixtureRef,
  selectedHarnessNodeAttemptId,
  selectedHarnessRevisionBindingKind,
  selectedHarnessRevisionBindingRef,
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
  runtimeThreadEvents,
  dogfoodRun,
  packageImportReview,
  portablePackage,
  bindingManifest,
  selectedNodeFixtures,
  checkpoints,
  onSelectRun,
  onCompareRun,
  onOpenExecutions,
  onInspectNode,
  onExecuteRuntimeDiagnosticsRepair,
  onExecuteRuntimeContextPressureAction,
  onExecuteRuntimeWorkspaceTrustAction,
  onExecuteRuntimeCodingToolBudgetRecovery,
  onCreateRuntimeCodingToolBudgetRecoverySubflow,
  onBindRuntimeCodingToolBudgetRecoveryTemplate,
  onBindRuntimeTelemetrySource,
  onMaterializeRuntimeTelemetryBudgetChain,
  onMaterializeRuntimeTerminalCodingLoop,
  onInspectHarnessGroupNode,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
  onSelectHarnessRollbackTarget,
  onCopyHarnessDeepLink,
  onCheckActivationReadiness,
  onRunHarnessActivationDryRun,
  onRunHarnessReplayDrill,
  onRunHarnessReplayGate,
  onRunHarnessPromotionTransition,
  onApplyHarnessActivationCandidate,
  onRunHarnessRollbackDrill,
  onExecuteHarnessRollback,
  onRunActiveRuntimeRollbackDryRun,
  onApplyActiveRuntimeRollback,
  onConfigureNode,
  onSelectProposal,
  onExportPackage,
  onOpenImportPackage,
  onGenerateBindingManifest,
  onUpdateWorkflowChromeLocale,
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
  selectedHarnessRollbackTarget?: string | null;
  selectedHarnessSelectorDecisionId?: string | null;
  selectedHarnessDefaultDispatchId?: string | null;
  selectedHarnessWorkerBindingId?: string | null;
  selectedHarnessActivationAuditEventId?: string | null;
  selectedHarnessActivationBlockerIndex?: string | null;
  selectedHarnessActivationBlockerRef?: string | null;
  selectedHarnessActivationGateEvidenceRef?: string | null;
  selectedHarnessActivationGateId?: string | null;
  selectedHarnessActivationGateNodeAttemptId?: string | null;
  selectedHarnessActivationGateReceiptRef?: string | null;
  selectedHarnessActivationGateReplayFixtureRef?: string | null;
  selectedHarnessNodeAttemptId?: string | null;
  selectedHarnessRevisionBindingKind?: string | null;
  selectedHarnessRevisionBindingRef?: string | null;
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
  runtimeThreadEvents?: WorkflowRuntimeThreadEventLike[];
  dogfoodRun: WorkflowDogfoodRun | null;
  packageImportReview: WorkflowPackageImportReview | null;
  portablePackage: WorkflowPortablePackage | null;
  bindingManifest: WorkflowBindingManifest | null;
  selectedNodeFixtures: WorkflowNodeFixture[];
  checkpoints: WorkflowCheckpoint[];
  onSelectRun: (run: WorkflowRunSummary) => void;
  onCompareRun: (run: WorkflowRunSummary) => void;
  onOpenExecutions?: () => void;
  onInspectNode: (nodeId: string) => void;
  onExecuteRuntimeDiagnosticsRepair?: (
    action: WorkflowRuntimeDiagnosticsRepairActionDescriptor,
  ) => void | Promise<void>;
  onExecuteRuntimeContextPressureAction?: (
    action: WorkflowRuntimeContextPressureActionDescriptor,
  ) => void | Promise<void>;
  onExecuteRuntimeWorkspaceTrustAction?: (
    action: WorkflowRuntimeWorkspaceTrustActionDescriptor,
  ) => void | Promise<void>;
  onExecuteRuntimeCodingToolBudgetRecovery?: (
    action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  ) => void | Promise<void>;
  onCreateRuntimeCodingToolBudgetRecoverySubflow?: (
    action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  ) => void;
  onBindRuntimeCodingToolBudgetRecoveryTemplate?: (
    action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  ) => void;
  onBindRuntimeTelemetrySource?: (
    summary: WorkflowRuntimeTelemetrySummary,
  ) => void;
  onMaterializeRuntimeTelemetryBudgetChain?: (
    summary: WorkflowRuntimeTelemetrySummary,
  ) => void;
  onMaterializeRuntimeTerminalCodingLoop?: (
    row: WorkflowRuntimeTuiControlStateRow,
  ) => void;
  onInspectHarnessGroupNode?: (groupId: string, nodeId: string) => void;
  onSelectHarnessReceiptRef?: (receiptRef: string) => void;
  onSelectHarnessReplayFixtureRef?: (replayFixtureRef: string) => void;
  onSelectHarnessRollbackTarget?: (rollbackTarget: string) => void;
  onCopyHarnessDeepLink?: (
    target?: WorkflowHarnessWorkbenchDeepLinkTarget,
  ) => void;
  onCheckActivationReadiness?: () => void;
  onRunHarnessActivationDryRun?: () => void;
  onRunHarnessReplayDrill?: () => void;
  onRunHarnessReplayGate?: () => void;
  onRunHarnessPromotionTransition?: (
    targetExecutionMode: WorkflowHarnessPromotionTransitionTarget,
  ) => void;
  onApplyHarnessActivationCandidate?: () => void;
  onRunHarnessRollbackDrill?: () => void;
  onExecuteHarnessRollback?: () => void;
  onRunActiveRuntimeRollbackDryRun?: () => void;
  onApplyActiveRuntimeRollback?: () => void;
  onConfigureNode: () => void;
  onSelectProposal: (proposal: WorkflowProposal) => void;
  onExportPackage: () => void;
  onOpenImportPackage: () => void;
  onGenerateBindingManifest: () => void;
  onUpdateWorkflowChromeLocale?: (locale: string) => void;
  onUpdateEnvironmentProfile: (
    updates: Partial<NonNullable<GraphGlobalConfig["environmentProfile"]>>,
  ) => void;
  onUpdateProductionProfile: (
    updates: NonNullable<GraphGlobalConfig["production"]>,
  ) => void;
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
  const [runSourceFilter, setRunSourceFilter] = useState<string>("all");
  const [bindingCheckResults, setBindingCheckResults] = useState<
    Record<string, WorkflowBindingCheckResult>
  >({});
  const outputNodes = workflow.nodes.filter(
    (nodeItem) => nodeItem.type === "output",
  );
  const workflowSearchModel = workflowRailSearchModel({
    workflow,
    tests,
    searchQuery: railSearchQuery,
  });
  const entrypointsModel = workflowEntrypointsModel(workflow);
  const fileBundleModel = workflowFileBundleModel({
    workflow,
    tests,
    proposals,
    runs,
    portablePackage,
    bindingManifest,
  });
  const unitTestModel = workflowTestReadinessModel({
    workflow,
    tests,
    testResult,
    searchQuery: unitTestSearchQuery,
  });
  const { coveredNodeIds } = unitTestModel;
  const runHistoryModel = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult,
    compareRunResult,
    selectedRunId,
    compareRunId,
    runEvents,
    runtimeThreadEvents,
    searchQuery: runSearchQuery,
    statusFilter: runStatusFilter,
    sourceFilter: runSourceFilter,
  });
  const productionProfile = workflow.global_config.production ?? {};
  const globalWorkflowChromeLocale = normalizeWorkflowRuntimeLocale(
    workflow.global_config.workflowChromeLocale,
  );
  const workflowReadOnly = workflow.metadata.readOnly === true;
  const harnessWorkflow = workflowIsHarness(workflow);
  const blessedHarnessWorkflow = workflowIsBlessedHarness(workflow);
  const harnessForkWorkflow = workflowIsHarnessFork(workflow);
  const harnessSlots = harnessSlotsForWorkflow(workflow);
  const harnessWorkerBinding = harnessWorkflow
    ? workflowHarnessWorkerBinding(workflow)
    : null;
  const harnessPromotionClusters =
    workflow.metadata.harness?.promotionClusters ?? [];
  const harnessActivationRecord = workflow.metadata.harness?.activationRecord;
  const harnessActivationAudit =
    workflow.metadata.harness?.activationAudit ?? [];
  const harnessActivationRollbackProof =
    workflow.metadata.harness?.activationRollbackProof ?? null;
  const harnessActivationRollbackExecution =
    workflow.metadata.harness?.activationRollbackExecution ?? null;
  const harnessRevisionBinding =
    workflow.metadata.harness?.revisionBinding ??
    harnessActivationRecord?.revisionBinding ??
    null;
  const harnessCandidateRevisionBinding =
    harnessActivationCandidate?.revisionBindingPreview ?? null;
  const harnessRollbackRevisionBinding =
    harnessActivationRollbackProof?.restoredRevisionBinding ??
    harnessActivationRecord?.rollbackRevisionBinding ??
    null;
  const harnessRevisionBindingRef = workflowRevisionBindingDeepLinkRef(
    harnessRevisionBinding,
  );
  const harnessCandidateRevisionBindingRef = workflowRevisionBindingDeepLinkRef(
    harnessCandidateRevisionBinding,
  );
  const harnessRollbackRevisionBindingRef = workflowRevisionBindingDeepLinkRef(
    harnessRollbackRevisionBinding,
  );
  const harnessLiveHandoffProof = workflow.metadata.harness?.liveHandoffProof;
  const harnessRuntimeSelectorDecision =
    workflow.metadata.harness?.runtimeSelectorDecision;
  const harnessCanaryExecutionBoundary =
    workflow.metadata.harness?.canaryExecutionBoundary;
  const harnessCanaryExecutionBoundaries =
    workflow.metadata.harness?.canaryExecutionBoundaries ??
    (harnessCanaryExecutionBoundary ? [harnessCanaryExecutionBoundary] : []);
  const harnessDefaultRuntimeDispatchProof =
    workflow.metadata.harness?.defaultRuntimeDispatchProof;
  const harnessCognitionNodeAuthorityGate =
    harnessDefaultRuntimeDispatchProof?.cognitionNodeAuthorityGate ?? null;
  const harnessRoutingModelNodeAuthorityGate =
    harnessDefaultRuntimeDispatchProof?.routingModelNodeAuthorityGate ?? null;
  const harnessVerificationOutputNodeAuthorityGate =
    harnessDefaultRuntimeDispatchProof?.verificationOutputNodeAuthorityGate ??
    null;
  const harnessAuthorityToolingNodeAuthorityGate =
    harnessDefaultRuntimeDispatchProof?.authorityToolingNodeAuthorityGate ??
    null;
  const harnessLivePromotionReadinessProof =
    harnessDefaultRuntimeDispatchProof?.livePromotionReadinessProof ?? null;
  const harnessSelectorLivePromotionReadinessProof =
    harnessRuntimeSelectorDecision?.livePromotionReadinessProof ??
    harnessLiveHandoffProof?.livePromotionReadinessProof ??
    harnessLivePromotionReadinessProof;
  const harnessSelectorLivePromotionReadinessReady =
    harnessRuntimeSelectorDecision?.livePromotionReadinessReady ??
    harnessLiveHandoffProof?.livePromotionReadinessReady ??
    harnessSelectorLivePromotionReadinessProof?.defaultLiveActivationReady ??
    false;
  const harnessSelectorLivePromotionReadinessBlockers =
    harnessRuntimeSelectorDecision?.livePromotionReadinessBlockers ??
    harnessLiveHandoffProof?.livePromotionReadinessBlockers ??
    harnessSelectorLivePromotionReadinessProof?.activationBlockers ??
    [];
  const harnessActiveRuntimeBindingReceiptRefs = workflowUniqueReceiptRefs([
    ...(harnessDefaultRuntimeDispatchProof?.receiptIds ?? []),
    ...(harnessLiveHandoffProof?.receiptIds ?? []),
  ]);
  const harnessActiveRuntimeBindingReplayFixtureRefs =
    workflowUniqueReceiptRefs([
      ...(harnessDefaultRuntimeDispatchProof?.replayFixtureRefs ?? []),
      ...(harnessLiveHandoffProof?.replayFixtureRefs ?? []),
    ]);
  const harnessActiveRuntimeBinding =
    harnessRuntimeSelectorDecision && harnessDefaultRuntimeDispatchProof
      ? (() => {
          const workflowId =
            harnessRuntimeSelectorDecision.workflowId ??
            harnessDefaultRuntimeDispatchProof.workflowId ??
            workflow.metadata.harness?.harnessWorkflowId ??
            workflow.metadata.id;
          const activationId =
            harnessRuntimeSelectorDecision.activationId ??
            harnessDefaultRuntimeDispatchProof.activationId ??
            harnessWorkerBinding?.harnessActivationId ??
            workflow.metadata.harness?.activationId ??
            "";
          const harnessHash =
            harnessRuntimeSelectorDecision.harnessHash ??
            harnessDefaultRuntimeDispatchProof.harnessHash ??
            harnessWorkerBinding?.harnessHash ??
            workflow.metadata.harness?.harnessHash ??
            "";
          const workflowIdentityMatches =
            harnessRuntimeSelectorDecision.workflowId === workflowId &&
            harnessDefaultRuntimeDispatchProof.workflowId === workflowId &&
            (!harnessLiveHandoffProof ||
              harnessLiveHandoffProof.workflowId === workflowId) &&
            (!harnessWorkerBinding ||
              harnessWorkerBinding.harnessWorkflowId === workflowId);
          const activationIdentityMatches =
            harnessRuntimeSelectorDecision.activationId === activationId &&
            harnessDefaultRuntimeDispatchProof.activationId === activationId &&
            (!harnessLiveHandoffProof ||
              harnessLiveHandoffProof.activationId === activationId) &&
            (!harnessWorkerBinding?.harnessActivationId ||
              harnessWorkerBinding.harnessActivationId === activationId);
          const harnessHashMatches =
            harnessRuntimeSelectorDecision.harnessHash === harnessHash &&
            harnessDefaultRuntimeDispatchProof.harnessHash === harnessHash &&
            (!harnessLiveHandoffProof ||
              harnessLiveHandoffProof.harnessHash === harnessHash) &&
            (!harnessWorkerBinding ||
              harnessWorkerBinding.harnessHash === harnessHash);
          const selectorDecisionLinksDispatch =
            harnessDefaultRuntimeDispatchProof.selectorDecisionId ===
            harnessRuntimeSelectorDecision.decisionId;
          const rollbackTarget =
            harnessRuntimeSelectorDecision.rollbackTarget ??
            harnessLiveHandoffProof?.rollbackTarget ??
            harnessDefaultRuntimeDispatchProof.rollbackTarget ??
            "not set";
          const rollbackTargetMatches =
            Boolean(rollbackTarget) &&
            harnessRuntimeSelectorDecision.rollbackTarget === rollbackTarget &&
            (!harnessLiveHandoffProof ||
              harnessLiveHandoffProof.rollbackTarget === rollbackTarget) &&
            (!harnessDefaultRuntimeDispatchProof.rollbackTarget ||
              harnessDefaultRuntimeDispatchProof.rollbackTarget ===
                rollbackTarget);
          const authorityTransferred =
            harnessRuntimeSelectorDecision.actualRuntimeAuthority ===
              "blessed_workflow_activation_default" &&
            harnessLiveHandoffProof?.defaultAuthorityTransferred === true &&
            harnessDefaultRuntimeDispatchProof.runtimeAuthority ===
              "blessed_workflow_activation_default";
          const drivesRuntimeDecision =
            harnessDefaultRuntimeDispatchProof.drivesRuntimeDecision === true;
          const rollbackAvailable =
            harnessRuntimeSelectorDecision.rollbackAvailable === true &&
            (harnessLiveHandoffProof?.rollbackAvailable ?? true) === true &&
            harnessDefaultRuntimeDispatchProof.rollbackAvailable === true;
          const selectorProof =
            harnessRuntimeSelectorDecision.livePromotionReadinessProof ?? null;
          const liveHandoffProof =
            harnessLiveHandoffProof?.livePromotionReadinessProof ?? null;
          const dispatchProof =
            harnessDefaultRuntimeDispatchProof.livePromotionReadinessProof ??
            null;
          const selectorProofId = selectorProof?.proofId ?? "";
          const liveHandoffProofId = liveHandoffProof?.proofId ?? "";
          const dispatchProofId = dispatchProof?.proofId ?? "";
          const dispatchLivePromotionReadinessBlockers =
            workflowHarnessLivePromotionReadinessProofBlockers(dispatchProof);
          const selectorLivePromotionReadinessReady =
            harnessRuntimeSelectorDecision.livePromotionReadinessReady ===
              true &&
            (
              harnessRuntimeSelectorDecision.livePromotionReadinessBlockers ??
              []
            ).length === 0 &&
            workflowHarnessLivePromotionReadinessProofBlockers(selectorProof)
              .length === 0;
          const liveHandoffLivePromotionReadinessReady =
            (harnessLiveHandoffProof?.livePromotionReadinessReady ?? true) ===
              true &&
            (harnessLiveHandoffProof?.livePromotionReadinessBlockers ?? [])
              .length === 0 &&
            (!harnessLiveHandoffProof ||
              workflowHarnessLivePromotionReadinessProofBlockers(
                liveHandoffProof,
              ).length === 0);
          const dispatchLivePromotionReadinessReady =
            dispatchLivePromotionReadinessBlockers.length === 0;
          const livePromotionReadinessProofIdsMatch =
            Boolean(selectorProofId) &&
            selectorProofId === dispatchProofId &&
            (!harnessLiveHandoffProof ||
              selectorProofId === liveHandoffProofId);
          const invalidForkLiveActivationBlocked =
            selectorProof?.invalidForkLiveActivationBlocked === true &&
            dispatchProof?.invalidForkLiveActivationBlocked === true &&
            (!harnessLiveHandoffProof ||
              liveHandoffProof?.invalidForkLiveActivationBlocked === true);
          const activationRecordBindingMatches =
            !harnessActivationRecord ||
            (harnessActivationRecord.activationState === "active" &&
              harnessActivationRecord.liveAuthorityTransferred === true &&
              harnessActivationRecord.policyPosture === "live" &&
              harnessActivationRecord.activationId === activationId &&
              harnessActivationRecord.workerBinding?.harnessActivationId ===
                activationId &&
              harnessActivationRecord.workerBinding?.harnessHash ===
                harnessHash);
          const workerBindingRegistryRecord =
            harnessDefaultRuntimeDispatchProof.workerBindingRegistryRecord ??
            harnessActivationRecord?.workerBindingRegistryRecord ??
            workflow.metadata.harness?.workerBindingRegistryRecord ??
            null;
          const workerBindingRegistryBlockers =
            workflowHarnessWorkerBindingRegistryBlockers(
              workerBindingRegistryRecord,
            );
          const workerBindingRegistryBound =
            workerBindingRegistryRecord?.bindingStatus === "bound" &&
            workerBindingRegistryBlockers.length === 0;
          const workerAttachReceipt =
            harnessDefaultRuntimeDispatchProof.workerAttachReceipt ??
            harnessActivationRecord?.workerAttachReceipt ??
            workflow.metadata.harness?.workerAttachReceipt ??
            null;
          const workerAttachLifecycle =
            harnessDefaultRuntimeDispatchProof.workerAttachLifecycle ??
            harnessActivationRecord?.workerAttachLifecycle ??
            workflow.metadata.harness?.workerAttachLifecycle ??
            [];
          const workerAttachResumeReceipt =
            harnessDefaultRuntimeDispatchProof.workerAttachResumeReceipt ??
            workerAttachLifecycle.find((event) => event.phase === "resume")
              ?.receipt ??
            null;
          const workerAttachRollbackReceipt =
            harnessDefaultRuntimeDispatchProof.workerAttachRollbackReceipt ??
            workerAttachLifecycle.find((event) => event.phase === "rollback")
              ?.receipt ??
            null;
          const workerAttachLifecycleComplete =
            workflowHarnessWorkerAttachLifecycleComplete(workerAttachLifecycle);
          const workerAttachLifecycleStatuses = workerAttachLifecycle.map(
            (event) => event.attachStatus,
          );
          const workerAttachLifecycleAttemptIds = workerAttachLifecycle.map(
            (event) => event.attemptId,
          );
          const workerSessionRecord =
            harnessDefaultRuntimeDispatchProof.workerSessionRecord ??
            harnessActivationRecord?.workerSessionRecord ??
            workflow.metadata.harness?.workerSessionRecord ??
            null;
          const workerSessionBlockers =
            workflowHarnessWorkerSessionBlockers(workerSessionRecord);
          const workerSessionAccepted = workerSessionBlockers.length === 0;
          const workerLaunchEnvelopes =
            harnessDefaultRuntimeDispatchProof.workerLaunchEnvelopes ??
            harnessActivationRecord?.workerLaunchEnvelopes ??
            workflow.metadata.harness?.workerLaunchEnvelopes ??
            [];
          const workerHandoffReceipts =
            harnessDefaultRuntimeDispatchProof.workerHandoffReceipts ??
            harnessActivationRecord?.workerHandoffReceipts ??
            workflow.metadata.harness?.workerHandoffReceipts ??
            [];
          const workerLaunchEnvelopeIds = workerLaunchEnvelopes.map(
            (envelope) => envelope.envelopeId,
          );
          const workerHandoffReceiptIds = workerHandoffReceipts.map(
            (receipt) => receipt.receiptId,
          );
          const workerHandoffNodeAttempts =
            harnessDefaultRuntimeDispatchProof.workerHandoffNodeAttempts ?? [];
          const workerHandoffNodeAttemptIds =
            harnessDefaultRuntimeDispatchProof.workerHandoffNodeAttemptIds ??
            workerHandoffNodeAttempts.map((attempt) => attempt.attemptId);
          const workerHandoffReplayFixtureRefs =
            harnessDefaultRuntimeDispatchProof.workerHandoffReplayFixtureRefs ??
            workerHandoffNodeAttempts
              .map((attempt) => attempt.replay.fixtureRef)
              .filter((fixtureRef): fixtureRef is string =>
                Boolean(fixtureRef),
              );
          const workerLaunchEnvelopePhases = new Set(
            workerLaunchEnvelopes.map((envelope) => envelope.phase),
          );
          const workerHandoffReceiptStatuses = new Set(
            workerHandoffReceipts.map((receipt) => receipt.handoffStatus),
          );
          const workerLaunchEnvelopesAccepted =
            workerLaunchEnvelopes.length >= 3 &&
            workerLaunchEnvelopes.every(
              (envelope) =>
                envelope.accepted === true &&
                (envelope.blockers ?? []).length === 0,
            ) &&
            workerLaunchEnvelopePhases.has("launch") &&
            workerLaunchEnvelopePhases.has("resume") &&
            workerLaunchEnvelopePhases.has("rollback");
          const workerHandoffReceiptsAccepted =
            workerHandoffReceipts.length >= 3 &&
            workerHandoffReceipts.every(
              (receipt) =>
                receipt.accepted === true &&
                (receipt.blockers ?? []).length === 0,
            ) &&
            workerHandoffReceiptStatuses.has("launched") &&
            workerHandoffReceiptStatuses.has("resumed") &&
            workerHandoffReceiptStatuses.has("rollback_handoff_ready");
          const workerHandoffNodeTimelineBound =
            workerHandoffNodeAttempts.length >= 3 &&
            workerHandoffNodeAttemptIds.length >= 3 &&
            workerHandoffReplayFixtureRefs.length >= 3 &&
            workerHandoffNodeAttempts.every(
              (attempt) =>
                attempt.workflowNodeId === "harness.handoff_bridge" &&
                attempt.componentKind === "handoff_bridge" &&
                attempt.receiptIds.some((receiptId) =>
                  workerHandoffReceiptIds.includes(receiptId),
                ) &&
                Boolean(attempt.replay.fixtureRef),
            );
          const workerRollbackExpectedLiveShadowGateId =
            dispatchProof?.liveShadowComparisonGate?.gateId ??
            harnessDefaultRuntimeDispatchProof.liveShadowComparisonGate
              ?.gateId ??
            "p0-live-shadow-comparison-gate";
          const workerRollbackExpectedPolicyDecision =
            "allow_default_harness_worker_rollback_from_live_shadow_gate";
          const workerRollbackLaunchEnvelope =
            workerLaunchEnvelopes.find(
              (envelope) => envelope.phase === "rollback",
            ) ?? null;
          const workerRollbackHandoffReceipt =
            workerHandoffReceipts.find(
              (receipt) => receipt.phase === "rollback",
            ) ?? null;
          const workerRollbackNodeAttempt =
            workerHandoffNodeAttempts.find(
              (attempt) =>
                Boolean(workerRollbackHandoffReceipt?.receiptId) &&
                attempt.receiptIds.includes(
                  workerRollbackHandoffReceipt?.receiptId ?? "",
                ),
            ) ??
            workerHandoffNodeAttempts.find((attempt) =>
              attempt.attemptId.includes(":rollback:"),
            ) ??
            null;
          const workerRollbackNodeAttemptBound =
            Boolean(workerRollbackNodeAttempt) &&
            Boolean(workerRollbackHandoffReceipt?.receiptId) &&
            workerRollbackNodeAttempt?.receiptIds.includes(
              workerRollbackHandoffReceipt?.receiptId ?? "",
            ) === true;
          const workerRollbackReplayFixtureRef =
            workerRollbackNodeAttempt?.replay.fixtureRef ??
            workerHandoffReplayFixtureRefs.find((fixtureRef) =>
              fixtureRef.includes(":rollback:"),
            ) ??
            "";
          const workerRollbackReplayFixtureBound =
            Boolean(workerRollbackReplayFixtureRef) &&
            workerHandoffReplayFixtureRefs.includes(
              workerRollbackReplayFixtureRef,
            );
          const workerRollbackReadinessProofId =
            workerBindingRegistryRecord?.rollbackReadinessProofId ??
            workerSessionRecord?.rollbackReadinessProofId ??
            workerRollbackLaunchEnvelope?.rollbackReadinessProofId ??
            workerRollbackHandoffReceipt?.rollbackReadinessProofId ??
            "";
          const workerRollbackLiveShadowComparisonGateId =
            workerBindingRegistryRecord?.rollbackLiveShadowComparisonGateId ??
            workerSessionRecord?.rollbackLiveShadowComparisonGateId ??
            workerRollbackLaunchEnvelope?.rollbackLiveShadowComparisonGateId ??
            workerRollbackHandoffReceipt
              ?.rollbackLiveShadowComparisonGateId ??
            "";
          const workerRollbackLiveShadowComparisonGateReady =
            (workerBindingRegistryRecord
              ?.rollbackLiveShadowComparisonGateReady ??
              workerSessionRecord?.rollbackLiveShadowComparisonGateReady ??
              workerRollbackLaunchEnvelope
                ?.rollbackLiveShadowComparisonGateReady ??
              workerRollbackHandoffReceipt
                ?.rollbackLiveShadowComparisonGateReady ??
              false) === true;
          const workerRollbackActivationId =
            workerBindingRegistryRecord?.rollbackActivationId ??
            workerSessionRecord?.rollbackActivationId ??
            workerRollbackLaunchEnvelope?.rollbackActivationId ??
            workerRollbackHandoffReceipt?.rollbackActivationId ??
            "";
          const workerRollbackHarnessHash =
            workerBindingRegistryRecord?.rollbackHarnessHash ??
            workerSessionRecord?.rollbackHarnessHash ??
            workerRollbackLaunchEnvelope?.rollbackHarnessHash ??
            workerRollbackHandoffReceipt?.rollbackHarnessHash ??
            "";
          const workerRollbackPolicyDecision =
            workerBindingRegistryRecord?.rollbackPolicyDecision ??
            workerSessionRecord?.rollbackPolicyDecision ??
            workerRollbackLaunchEnvelope?.rollbackPolicyDecision ??
            workerRollbackHandoffReceipt?.rollbackPolicyDecision ??
            "";
          const workerRollbackProofBlockers =
            workflowHarnessUniqueStrings([
              ...(workerRollbackReadinessProofId === selectorProofId
                ? []
                : ["rollback_readiness_proof_mismatch"]),
              ...(workerRollbackLiveShadowComparisonGateId ===
              workerRollbackExpectedLiveShadowGateId
                ? []
                : ["rollback_live_shadow_gate_mismatch"]),
              ...(workerRollbackLiveShadowComparisonGateReady
                ? []
                : ["rollback_live_shadow_gate_not_ready"]),
              ...(workerRollbackActivationId === activationId
                ? []
                : ["rollback_activation_mismatch"]),
              ...(workerRollbackHarnessHash === harnessHash
                ? []
                : ["rollback_harness_hash_mismatch"]),
              ...(workerRollbackPolicyDecision ===
              workerRollbackExpectedPolicyDecision
                ? []
                : ["rollback_policy_decision_mismatch"]),
              ...(workerRollbackLaunchEnvelope?.accepted === true &&
              workerRollbackLaunchEnvelope.phase === "rollback" &&
              workerRollbackLaunchEnvelope.rollbackHandoffReady === true &&
              (workerRollbackLaunchEnvelope.blockers ?? []).length === 0
                ? []
                : ["rollback_launch_envelope_not_ready"]),
              ...(workerRollbackLaunchEnvelope
                ? []
                : ["rollback_launch_envelope_missing"]),
              ...(workerRollbackHandoffReceipt?.accepted === true &&
              workerRollbackHandoffReceipt.phase === "rollback" &&
              workerRollbackHandoffReceipt.handoffStatus ===
                "rollback_handoff_ready" &&
              (workerRollbackHandoffReceipt.blockers ?? []).length === 0
                ? []
                : ["rollback_handoff_receipt_not_ready"]),
              ...(workerRollbackHandoffReceipt
                ? []
                : ["rollback_handoff_receipt_missing"]),
              ...(workerRollbackNodeAttempt?.workflowNodeId ===
                "harness.handoff_bridge" &&
              workerRollbackNodeAttempt.componentKind === "handoff_bridge" &&
              Boolean(workerRollbackReplayFixtureRef) &&
              Boolean(workerRollbackHandoffReceipt?.receiptId) &&
              workerRollbackNodeAttempt.receiptIds.includes(
                workerRollbackHandoffReceipt?.receiptId ?? "",
              )
                ? []
                : ["rollback_node_attempt_not_bound"]),
              ...(workerRollbackNodeAttempt
                ? []
                : ["rollback_node_attempt_missing"]),
              ...(workerRollbackReplayFixtureRef
                ? []
                : ["rollback_replay_fixture_missing"]),
              ...(workerRollbackNodeAttempt && !workerRollbackNodeAttemptBound
                ? ["rollback_node_attempt_orphaned"]
                : []),
              ...(workerRollbackReplayFixtureRef &&
              !workerRollbackReplayFixtureBound
                ? ["rollback_replay_fixture_orphaned"]
                : []),
            ]);
          const workerRollbackProof = {
            bound: workerRollbackProofBlockers.length === 0,
            blockers: workerRollbackProofBlockers,
            readinessProofId: workerRollbackReadinessProofId,
            liveShadowComparisonGateId:
              workerRollbackLiveShadowComparisonGateId,
            liveShadowComparisonGateReady:
              workerRollbackLiveShadowComparisonGateReady,
            expectedLiveShadowComparisonGateId:
              workerRollbackExpectedLiveShadowGateId,
            activationId: workerRollbackActivationId,
            harnessHash: workerRollbackHarnessHash,
            policyDecision: workerRollbackPolicyDecision,
            launchEnvelope: workerRollbackLaunchEnvelope,
            handoffReceipt: workerRollbackHandoffReceipt,
            nodeAttempt: workerRollbackNodeAttempt,
            replayFixtureRef: workerRollbackReplayFixtureRef,
          };
          const workerAttachBlockers =
            workflowHarnessWorkerAttachBlockers(workerAttachReceipt);
          const workerAttachAccepted =
            workerAttachReceipt?.accepted === true &&
            workerAttachReceipt.attachStatus === "bound" &&
            workerAttachBlockers.length === 0;
          const workerBindingRequiredInvariantIds = workflowHarnessInvariantIds(
            harnessWorkerBinding?.requiredInvariantIds,
            workerBindingRegistryRecord?.workerBinding?.requiredInvariantIds,
          );
          const workerBindingInvariantBlockers =
            workflowHarnessInvariantBlockers(
              harnessWorkerBinding?.invariantBlockers,
              workerBindingRegistryRecord?.workerBinding?.invariantBlockers,
            );
          const workerRegistryRequiredInvariantIds =
            workflowHarnessInvariantIds(
              workerBindingRegistryRecord?.requiredInvariantIds,
              workerBindingRegistryRecord?.workerBinding?.requiredInvariantIds,
            );
          const workerRegistryInvariantBlockers =
            workflowHarnessInvariantBlockers(
              workerBindingRegistryRecord?.invariantBlockers,
              workerBindingRegistryRecord?.workerBinding?.invariantBlockers,
            );
          const workerAttachRequiredInvariantIds = workflowHarnessInvariantIds(
            workerAttachReceipt?.requiredInvariantIds,
            workerAttachReceipt?.workerBinding?.requiredInvariantIds,
          );
          const workerAttachInvariantBlockers =
            workflowHarnessInvariantBlockers(
              workerAttachReceipt?.invariantBlockers,
              workerAttachReceipt?.workerBinding?.invariantBlockers,
            );
          const workerAttachLifecycleRequiredInvariantIds =
            workflowHarnessInvariantIds(
              ...workerAttachLifecycle.map(
                (event) => event.requiredInvariantIds,
              ),
            );
          const workerAttachLifecycleInvariantBlockers =
            workflowHarnessInvariantBlockers(
              ...workerAttachLifecycle.map((event) => event.invariantBlockers),
            );
          const workerSessionRequiredInvariantIds = workflowHarnessInvariantIds(
            workerSessionRecord?.requiredInvariantIds,
          );
          const workerSessionInvariantBlockers =
            workflowHarnessInvariantBlockers(
              workerSessionRecord?.invariantBlockers,
            );
          const workerSessionLaunchAuthorityInvariantIds =
            workflowHarnessInvariantIds(
              workerSessionRecord?.launchAuthorityInvariantIds,
            );
          const workerSessionLaunchAuthorityInvariantBlockers =
            workflowHarnessInvariantBlockers(
              workerSessionRecord?.launchAuthorityInvariantBlockers,
            );
          const workerLaunchEnvelopeInvariantIds = workflowHarnessInvariantIds(
            ...workerLaunchEnvelopes.map(
              (envelope) => envelope.launchAuthorityInvariantIds,
            ),
          );
          const workerLaunchEnvelopeInvariantBlockers =
            workflowHarnessInvariantBlockers(
              ...workerLaunchEnvelopes.map(
                (envelope) => envelope.launchAuthorityInvariantBlockers,
              ),
            );
          const workerHandoffReceiptInvariantIds = workflowHarnessInvariantIds(
            ...workerHandoffReceipts.map(
              (receipt) => receipt.requiredInvariantIds,
            ),
          );
          const workerHandoffReceiptInvariantBlockers =
            workflowHarnessInvariantBlockers(
              ...workerHandoffReceipts.map(
                (receipt) => receipt.invariantBlockers,
              ),
            );
          const workerLaunchReviewedImportInvariantBound =
            workflowHarnessHasReviewedImportActivationInvariant(
              workerBindingRequiredInvariantIds,
            ) &&
            workerBindingInvariantBlockers.length === 0 &&
            workflowHarnessHasReviewedImportActivationInvariant(
              workerRegistryRequiredInvariantIds,
            ) &&
            workerRegistryInvariantBlockers.length === 0 &&
            workflowHarnessHasReviewedImportActivationInvariant(
              workerAttachRequiredInvariantIds,
            ) &&
            workerAttachInvariantBlockers.length === 0 &&
            workerAttachLifecycle.length >= 3 &&
            workerAttachLifecycle.every(
              (event) =>
                workflowHarnessHasReviewedImportActivationInvariant(
                  event.requiredInvariantIds,
                ) && (event.invariantBlockers ?? []).length === 0,
            ) &&
            workflowHarnessHasReviewedImportActivationInvariant(
              workerSessionLaunchAuthorityInvariantIds,
            ) &&
            workerSessionLaunchAuthorityInvariantBlockers.length === 0 &&
            workerLaunchEnvelopes.length >= 3 &&
            workerLaunchEnvelopes.every(
              (envelope) =>
                workflowHarnessHasReviewedImportActivationInvariant(
                  envelope.launchAuthorityInvariantIds,
                ) &&
                (envelope.launchAuthorityInvariantBlockers ?? []).length === 0,
            ) &&
            workerHandoffReceipts.length >= 3 &&
            workerHandoffReceipts.every(
              (receipt) =>
                workflowHarnessHasReviewedImportActivationInvariant(
                  receipt.requiredInvariantIds,
                ) && (receipt.invariantBlockers ?? []).length === 0,
            );
          const workerRegistryReviewedPackageBound =
            Boolean(workerBindingRegistryRecord?.reviewedPackageSnapshotHash) &&
            workerBindingRegistryRecord?.reviewedWorkflowContentHash ===
              workerAttachReceipt?.reviewedWorkflowContentHash &&
            workerBindingRegistryRecord?.reviewedActivationId ===
              workerAttachReceipt?.reviewedActivationId &&
            workerBindingRegistryRecord?.reviewedWorkerBindingActivationId ===
              workerAttachReceipt?.reviewedWorkerBindingActivationId &&
            workerBindingRegistryRecord?.reviewedActivationId ===
              workerBindingRegistryRecord
                ?.reviewedWorkerBindingActivationId &&
            workerBindingRegistryRecord?.reviewedRollbackTarget ===
              workerBindingRegistryRecord?.rollbackTarget &&
            workerBindingRegistryRecord?.reviewedPolicyPosture === "canary" &&
            (workerBindingRegistryRecord?.reviewedReplayFixtureRefs?.length ??
              0) > 0 &&
            (workerBindingRegistryRecord
              ?.reviewedWorkerHandoffNodeAttemptIds?.length ?? 0) > 0 &&
            (workerBindingRegistryRecord?.reviewedWorkerHandoffReceiptIds
              ?.length ?? 0) > 0 &&
            (workerAttachReceipt?.reviewedReplayFixtureRefs?.length ?? 0) > 0;
          const workerInvariantBlockers = workflowHarnessInvariantBlockers(
            workerBindingInvariantBlockers,
            workerRegistryInvariantBlockers,
            workerAttachInvariantBlockers,
            workerAttachLifecycleInvariantBlockers,
            workerSessionInvariantBlockers,
            workerSessionLaunchAuthorityInvariantBlockers,
            workerLaunchEnvelopeInvariantBlockers,
            workerHandoffReceiptInvariantBlockers,
          );
          const workerBindingAuthorityBlockers = workflowHarnessUniqueStrings([
            ...(workflowIdentityMatches ? [] : ["workflow_identity_mismatch"]),
            ...(activationIdentityMatches
              ? []
              : ["activation_identity_mismatch"]),
            ...(harnessHashMatches ? [] : ["harness_hash_mismatch"]),
            ...(selectorDecisionLinksDispatch
              ? []
              : ["selector_dispatch_not_linked"]),
            ...(rollbackTargetMatches ? [] : ["rollback_target_mismatch"]),
            ...(authorityTransferred
              ? []
              : ["default_authority_not_transferred"]),
            ...(drivesRuntimeDecision ? [] : ["dispatch_not_driving_runtime"]),
            ...(rollbackAvailable ? [] : ["rollback_not_available"]),
            ...(harnessRuntimeSelectorDecision.selectedSelector ===
            "blessed_workflow_live_default"
              ? []
              : ["selector_not_default_live"]),
            ...(harnessRuntimeSelectorDecision.productionDefaultSelector ===
            "blessed_workflow_live_default"
              ? []
              : ["production_default_not_live"]),
            ...(harnessDefaultRuntimeDispatchProof.executionMode === "live"
              ? []
              : ["execution_mode_not_live"]),
            ...(selectorLivePromotionReadinessReady
              ? []
              : ["selector_live_promotion_readiness_not_ready"]),
            ...(liveHandoffLivePromotionReadinessReady
              ? []
              : ["live_handoff_live_promotion_readiness_not_ready"]),
            ...(dispatchLivePromotionReadinessReady
              ? []
              : ["dispatch_live_promotion_readiness_not_ready"]),
            ...(livePromotionReadinessProofIdsMatch
              ? []
              : ["live_promotion_readiness_proof_mismatch"]),
            ...(invalidForkLiveActivationBlocked
              ? []
              : ["invalid_fork_live_activation_not_blocked"]),
            ...(activationRecordBindingMatches
              ? []
              : ["activation_record_binding_mismatch"]),
            ...(workerBindingRegistryBound
              ? []
              : ["worker_binding_registry_not_bound"]),
            ...(workerAttachAccepted ? [] : ["worker_attach_not_accepted"]),
            ...(workerAttachLifecycleComplete
              ? []
              : ["worker_attach_lifecycle_incomplete"]),
            ...(workerSessionAccepted ? [] : ["worker_session_not_ready"]),
            ...(workerLaunchEnvelopesAccepted
              ? []
              : ["worker_launch_envelopes_not_ready"]),
            ...(workerHandoffReceiptsAccepted
              ? []
              : ["worker_handoff_receipts_not_ready"]),
            ...(workerHandoffNodeTimelineBound
              ? []
              : ["worker_handoff_node_timeline_not_bound"]),
            ...(workerLaunchReviewedImportInvariantBound
              ? []
              : [
                  "worker_launch_reviewed_import_activation_invariant_not_bound",
                ]),
            ...(workerRegistryReviewedPackageBound
              ? []
              : ["worker_registry_reviewed_package_snapshot_not_bound"]),
            ...workerBindingRegistryBlockers,
            ...workerAttachBlockers,
            ...workerSessionBlockers,
            ...workerInvariantBlockers,
          ]);
          const workerBindingAuthorityReady =
            workerBindingAuthorityBlockers.length === 0;
          const effectiveWorkerBinding = harnessWorkerBinding
            ? {
                ...harnessWorkerBinding,
                selectorDecisionId: harnessRuntimeSelectorDecision.decisionId,
                defaultDispatchId:
                  harnessDefaultRuntimeDispatchProof.dispatchId,
                rollbackTarget,
                authorityBindingReady: workerBindingAuthorityReady,
                authorityBindingBlockers: workerBindingAuthorityBlockers,
                livePromotionReadinessProofId: selectorProofId,
                policyDecision: harnessRuntimeSelectorDecision.policyDecision,
              }
            : null;
          return {
            workflowId,
            activationId,
            harnessHash,
            selectorDecisionId: harnessRuntimeSelectorDecision.decisionId,
            defaultDispatchId: harnessDefaultRuntimeDispatchProof.dispatchId,
            workerBindingId:
              harnessWorkerBinding?.harnessActivationId ?? activationId,
            selectedSelector: harnessRuntimeSelectorDecision.selectedSelector,
            productionDefaultSelector:
              harnessRuntimeSelectorDecision.productionDefaultSelector,
            executionMode: harnessDefaultRuntimeDispatchProof.executionMode,
            runtimeAuthority:
              harnessDefaultRuntimeDispatchProof.runtimeAuthority,
            rollbackTarget,
            rollbackAvailable,
            workerBinding: effectiveWorkerBinding,
            bindingMatched: workerBindingAuthorityReady,
            selectorDecisionLinksDispatch,
            drivesRuntimeDecision,
            selectorLivePromotionReadinessReady,
            liveHandoffLivePromotionReadinessReady,
            dispatchLivePromotionReadinessReady,
            selectorLivePromotionReadinessProofId: selectorProofId,
            liveHandoffLivePromotionReadinessProofId: liveHandoffProofId,
            dispatchLivePromotionReadinessProofId: dispatchProofId,
            livePromotionReadinessProofIdsMatch,
            invalidForkLiveActivationBlocked,
            workerBindingAuthorityReady,
            workerBindingAuthorityBlockers,
            workerLaunchReviewedImportInvariantBound,
            workerRegistryReviewedPackageBound,
            workerBindingRequiredInvariantIds,
            workerBindingInvariantBlockers,
            workerRegistryRequiredInvariantIds,
            workerRegistryInvariantBlockers,
            workerAttachRequiredInvariantIds,
            workerAttachInvariantBlockers,
            workerAttachLifecycleRequiredInvariantIds,
            workerAttachLifecycleInvariantBlockers,
            workerSessionRequiredInvariantIds,
            workerSessionInvariantBlockers,
            workerSessionLaunchAuthorityInvariantIds,
            workerSessionLaunchAuthorityInvariantBlockers,
            workerLaunchEnvelopeInvariantIds,
            workerLaunchEnvelopeInvariantBlockers,
            workerHandoffReceiptInvariantIds,
            workerHandoffReceiptInvariantBlockers,
            workerInvariantBlockers,
            workerBindingRegistryRecord,
            workerBindingRegistryBound,
            workerBindingRegistryStatus:
              workerBindingRegistryRecord?.bindingStatus ?? "missing",
            workerBindingRegistryBlockers,
            workerAttachReceipt,
            workerAttachResumeReceipt,
            workerAttachRollbackReceipt,
            workerAttachLifecycle,
            workerAttachLifecycleComplete,
            workerAttachLifecycleStatuses,
            workerAttachLifecycleAttemptIds,
            workerSessionRecord,
            workerSessionAccepted,
            workerSessionStatus:
              workerSessionRecord?.currentStatus ?? "missing",
            workerSessionRecordId:
              workerSessionRecord?.sessionRecordId ?? "missing",
            workerSessionBlockers,
            workerLaunchEnvelopes,
            workerHandoffReceipts,
            workerLaunchEnvelopeIds,
            workerHandoffReceiptIds,
            workerHandoffNodeAttempts,
            workerHandoffNodeAttemptIds,
            workerHandoffReplayFixtureRefs,
            workerHandoffNodeTimelineBound,
            workerRollbackProof,
            workerLaunchEnvelopesAccepted,
            workerHandoffReceiptsAccepted,
            workerAttachAccepted,
            workerAttachStatus: workerAttachReceipt?.attachStatus ?? "missing",
            workerAttachBlockers,
            receiptRefs: harnessActiveRuntimeBindingReceiptRefs,
            replayFixtureRefs: harnessActiveRuntimeBindingReplayFixtureRefs,
            blockers: workerBindingAuthorityBlockers,
          };
        })()
      : null;
  const harnessActiveRuntimeRollbackExecutionProof =
    workflow.metadata.harness?.activeRuntimeRollbackExecutionProof ?? null;
  const harnessActiveRuntimeRollbackApplyProof =
    workflow.metadata.harness?.activeRuntimeRollbackApplyProof ?? null;
  const harnessActiveRuntimeRollbackDryRunPassed =
    harnessActiveRuntimeRollbackExecutionProof?.dryRun.passed === true &&
    harnessActiveRuntimeRollbackExecutionProof.passed === true;
  const harnessActiveRuntimeRollbackProofStillBound =
    harnessActiveRuntimeBinding?.workerRollbackProof.bound === true &&
    harnessActiveRuntimeRollbackExecutionProof?.readinessProofId ===
      harnessActiveRuntimeBinding.workerRollbackProof.readinessProofId &&
    harnessActiveRuntimeRollbackExecutionProof?.liveShadowComparisonGateId ===
      harnessActiveRuntimeBinding.workerRollbackProof
        .liveShadowComparisonGateId &&
    harnessActiveRuntimeRollbackExecutionProof?.activationId ===
      harnessActiveRuntimeBinding.workerRollbackProof.activationId &&
    harnessActiveRuntimeRollbackExecutionProof?.harnessHash ===
      harnessActiveRuntimeBinding.workerRollbackProof.harnessHash &&
    harnessActiveRuntimeRollbackExecutionProof?.launchEnvelopeId ===
      (harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
        ?.envelopeId ?? null) &&
    harnessActiveRuntimeRollbackExecutionProof?.handoffReceiptId ===
      (harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
        ?.receiptId ?? null) &&
    harnessActiveRuntimeRollbackExecutionProof?.nodeAttemptId ===
      (harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt?.attemptId ??
        null) &&
    harnessActiveRuntimeRollbackExecutionProof?.replayFixtureRef ===
      (harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef ||
        null);
  const harnessActiveRuntimeRollbackProofBindingBlockers =
    harnessActiveRuntimeRollbackExecutionProof && harnessActiveRuntimeBinding
      ? [
          ...(harnessActiveRuntimeBinding.workerRollbackProof.bound === true
            ? []
            : ["rollback_proof_not_bound"]),
          ...(harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
            ? []
            : ["rollback_launch_envelope_missing"]),
          ...(harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
            ? []
            : ["rollback_handoff_receipt_missing"]),
          ...(harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
            ? []
            : ["rollback_node_attempt_missing"]),
          ...(harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef
            ? []
            : ["rollback_replay_fixture_missing"]),
          ...(harnessActiveRuntimeBinding.workerRollbackProof.blockers.includes(
            "rollback_node_attempt_orphaned",
          )
            ? ["rollback_node_attempt_orphaned"]
            : []),
          ...(harnessActiveRuntimeBinding.workerRollbackProof.blockers.includes(
            "rollback_replay_fixture_orphaned",
          )
            ? ["rollback_replay_fixture_orphaned"]
            : []),
          ...(harnessActiveRuntimeRollbackExecutionProof.readinessProofId ===
          harnessActiveRuntimeBinding.workerRollbackProof.readinessProofId
            ? []
            : ["rollback_readiness_proof_stale"]),
          ...(harnessActiveRuntimeRollbackExecutionProof.liveShadowComparisonGateId ===
          harnessActiveRuntimeBinding.workerRollbackProof
            .liveShadowComparisonGateId
            ? []
            : ["rollback_live_shadow_gate_stale"]),
          ...(harnessActiveRuntimeRollbackExecutionProof.activationId ===
          harnessActiveRuntimeBinding.workerRollbackProof.activationId
            ? []
            : ["rollback_activation_stale"]),
          ...(harnessActiveRuntimeRollbackExecutionProof.harnessHash ===
          harnessActiveRuntimeBinding.workerRollbackProof.harnessHash
            ? []
            : [
                "rollback_harness_hash_stale",
                "rollback_apply_hash_not_verified",
              ]),
          ...(harnessActiveRuntimeRollbackExecutionProof.launchEnvelopeId ===
          (harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
            ?.envelopeId ?? null)
            ? []
            : ["rollback_launch_envelope_stale"]),
          ...(harnessActiveRuntimeRollbackExecutionProof.handoffReceiptId ===
          (harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
            ?.receiptId ?? null)
            ? []
            : ["rollback_handoff_receipt_stale"]),
          ...(harnessActiveRuntimeRollbackExecutionProof.nodeAttemptId ===
          (harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
            ?.attemptId ?? null)
            ? []
            : ["rollback_node_attempt_stale"]),
          ...(harnessActiveRuntimeRollbackExecutionProof.replayFixtureRef ===
          (harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef ||
            null)
            ? []
            : ["rollback_replay_fixture_stale"]),
        ]
      : [];
  const harnessActiveRuntimeRollbackApplyDisabled =
    !onApplyActiveRuntimeRollback ||
    !harnessActiveRuntimeRollbackDryRunPassed ||
    !harnessActiveRuntimeRollbackProofStillBound;
  const harnessActiveRuntimeRollbackApplyBlockers = [
    ...(harnessActiveRuntimeRollbackApplyProof?.blockers ?? []),
    ...harnessActiveRuntimeRollbackProofBindingBlockers,
  ];
  const harnessReadOnlyRoutingProof =
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingProof ?? null;
  const harnessReadOnlyRoutingNodeKinds =
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingWorkflowOwnedNodeKinds ??
    [];
  const harnessReadOnlyRoutingRequiredScenarios =
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingRequiredScenarioSet ??
    (Array.isArray(harnessReadOnlyRoutingProof?.requiredScenarioSet)
      ? harnessReadOnlyRoutingProof.requiredScenarioSet.filter(
          (scenario): scenario is string => typeof scenario === "string",
        )
      : []);
  const harnessReadOnlyRoutingReady =
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReady ===
      true &&
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingSelected ===
      true &&
    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingNoMutationReady ===
      true &&
    harnessReadOnlyRoutingProof?.sideEffectsExecuted === false &&
    harnessReadOnlyRoutingProof?.mutationExecuted === false;
  const harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds =
    workflowHarnessInvariantIds(
      harnessDefaultRuntimeDispatchProof?.workerSessionRecord
        ?.launchAuthorityInvariantIds,
    );
  const harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers =
    workflowHarnessInvariantBlockers(
      harnessDefaultRuntimeDispatchProof?.workerSessionRecord
        ?.launchAuthorityInvariantBlockers,
    );
  const harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds =
    workflowHarnessInvariantIds(
      ...(harnessDefaultRuntimeDispatchProof?.workerLaunchEnvelopes ?? []).map(
        (envelope) => envelope.launchAuthorityInvariantIds,
      ),
    );
  const harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers =
    workflowHarnessInvariantBlockers(
      ...(harnessDefaultRuntimeDispatchProof?.workerLaunchEnvelopes ?? []).map(
        (envelope) => envelope.launchAuthorityInvariantBlockers,
      ),
    );
  const harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds =
    workflowHarnessInvariantIds(
      ...(harnessDefaultRuntimeDispatchProof?.workerHandoffReceipts ?? []).map(
        (receipt) => receipt.requiredInvariantIds,
      ),
    );
  const harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers =
    workflowHarnessInvariantBlockers(
      ...(harnessDefaultRuntimeDispatchProof?.workerHandoffReceipts ?? []).map(
        (receipt) => receipt.invariantBlockers,
      ),
    );
  const harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound =
    workflowHarnessHasReviewedImportActivationInvariant(
      harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds,
    ) &&
    harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers.length ===
      0 &&
    (harnessDefaultRuntimeDispatchProof?.workerLaunchEnvelopes ?? []).length >=
      3 &&
    (harnessDefaultRuntimeDispatchProof?.workerLaunchEnvelopes ?? []).every(
      (envelope) =>
        workflowHarnessHasReviewedImportActivationInvariant(
          envelope.launchAuthorityInvariantIds,
        ) && (envelope.launchAuthorityInvariantBlockers ?? []).length === 0,
    ) &&
    (harnessDefaultRuntimeDispatchProof?.workerHandoffReceipts ?? []).length >=
      3 &&
    (harnessDefaultRuntimeDispatchProof?.workerHandoffReceipts ?? []).every(
      (receipt) =>
        workflowHarnessHasReviewedImportActivationInvariant(
          receipt.requiredInvariantIds,
        ) && (receipt.invariantBlockers ?? []).length === 0,
    );
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
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveReady ===
              true &&
            workflowProofBoolean(
              harnessAuthorityToolingProof,
              "policyGateLiveReady",
              true,
            ),
          status:
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveReady ===
            true
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
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveReady ===
              true &&
            workflowProofBoolean(
              harnessAuthorityToolingProof,
              "destructiveDenialLiveReady",
              true,
            ),
          status:
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveReady ===
            true
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
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReady ===
              true &&
            workflowProofBoolean(
              harnessAuthorityToolingProof,
              "approvalGateLiveReady",
              true,
            ),
          status:
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReady ===
            true
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
            "require_governed_approval_for_mutating_tooling",
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
    harnessDefaultRuntimeDispatchProof?.authorityToolingGateLiveReady ===
      true &&
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
              {gate.componentKind} · {gate.status} · {gate.attemptIds.length}{" "}
              attempts
            </span>
            <small>{gate.policyDecision}</small>
            <small
              data-testid={`${options.gateTestIdPrefix}-deep-links-${gate.id}`}
            >
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
                onClick={() =>
                  receiptRef && onSelectHarnessReceiptRef?.(receiptRef)
                }
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
  const harnessActivationWorkerLaunchEnvelopes =
    harnessActivationRecord?.workerLaunchEnvelopes ??
    workflow.metadata.harness?.workerLaunchEnvelopes ??
    [];
  const harnessActivationWorkerHandoffReceipts =
    harnessActivationRecord?.workerHandoffReceipts ??
    workflow.metadata.harness?.workerHandoffReceipts ??
    [];
  const harnessActivationWorkerHandoffNodeAttempts =
    harnessActivationRecord?.workerHandoffNodeAttempts ??
    workflow.metadata.harness?.workerHandoffNodeAttempts ??
    [];
  const harnessActivationWorkerHandoffNodeAttemptIds =
    harnessActivationRecord?.workerHandoffNodeAttemptIds ??
    workflow.metadata.harness?.workerHandoffNodeAttemptIds ??
    harnessActivationWorkerHandoffNodeAttempts.map(
      (attempt) => attempt.attemptId,
    );
  const harnessActivationWorkerHandoffReplayFixtureRefs =
    harnessActivationRecord?.workerHandoffReplayFixtureRefs ??
    workflow.metadata.harness?.workerHandoffReplayFixtureRefs ??
    harnessActivationWorkerHandoffNodeAttempts
      .map((attempt) => attempt.replay.fixtureRef)
      .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));
  const harnessActivationWorkerLaunchEnvelopePhases = new Set(
    harnessActivationWorkerLaunchEnvelopes.map((envelope) => envelope.phase),
  );
  const harnessActivationWorkerHandoffReceiptStatuses = new Set(
    harnessActivationWorkerHandoffReceipts.map(
      (receipt) => receipt.handoffStatus,
    ),
  );
  const harnessActivationWorkerHandoffReceiptIds =
    harnessActivationWorkerHandoffReceipts.map((receipt) => receipt.receiptId);
  const harnessActivationWorkerBindingRegistryRecord =
    harnessActivationRecord?.workerBindingRegistryRecord ??
    workflow.metadata.harness?.workerBindingRegistryRecord ??
    null;
  const harnessActivationWorkerAttachReceipt =
    harnessActivationRecord?.workerAttachReceipt ??
    workflow.metadata.harness?.workerAttachReceipt ??
    null;
  const harnessActivationWorkerAttachLifecycle =
    harnessActivationRecord?.workerAttachLifecycle ??
    workflow.metadata.harness?.workerAttachLifecycle ??
    [];
  const harnessActivationWorkerSessionRecord =
    harnessActivationRecord?.workerSessionRecord ??
    workflow.metadata.harness?.workerSessionRecord ??
    null;
  const harnessActivationWorkerBindingInvariantIds =
    workflowHarnessInvariantIds(
      harnessWorkerBinding?.requiredInvariantIds,
      harnessActivationRecord?.workerBinding?.requiredInvariantIds,
      harnessActivationWorkerBindingRegistryRecord?.workerBinding
        ?.requiredInvariantIds,
    );
  const harnessActivationWorkerBindingInvariantBlockers =
    workflowHarnessInvariantBlockers(
      harnessWorkerBinding?.invariantBlockers,
      harnessActivationRecord?.workerBinding?.invariantBlockers,
      harnessActivationWorkerBindingRegistryRecord?.workerBinding
        ?.invariantBlockers,
    );
  const harnessActivationWorkerRegistryInvariantIds =
    workflowHarnessInvariantIds(
      harnessActivationWorkerBindingRegistryRecord?.requiredInvariantIds,
      harnessActivationWorkerBindingRegistryRecord?.workerBinding
        ?.requiredInvariantIds,
    );
  const harnessActivationWorkerRegistryInvariantBlockers =
    workflowHarnessInvariantBlockers(
      harnessActivationWorkerBindingRegistryRecord?.invariantBlockers,
      harnessActivationWorkerBindingRegistryRecord?.workerBinding
        ?.invariantBlockers,
    );
  const harnessActivationWorkerAttachInvariantIds = workflowHarnessInvariantIds(
    harnessActivationWorkerAttachReceipt?.requiredInvariantIds,
    harnessActivationWorkerAttachReceipt?.workerBinding?.requiredInvariantIds,
  );
  const harnessActivationWorkerAttachInvariantBlockers =
    workflowHarnessInvariantBlockers(
      harnessActivationWorkerAttachReceipt?.invariantBlockers,
      harnessActivationWorkerAttachReceipt?.workerBinding?.invariantBlockers,
      ...harnessActivationWorkerAttachLifecycle.map(
        (event) => event.invariantBlockers,
      ),
    );
  const harnessActivationWorkerSessionLaunchAuthorityInvariantIds =
    workflowHarnessInvariantIds(
      harnessActivationWorkerSessionRecord?.launchAuthorityInvariantIds,
    );
  const harnessActivationWorkerSessionInvariantBlockers =
    workflowHarnessInvariantBlockers(
      harnessActivationWorkerSessionRecord?.invariantBlockers,
      harnessActivationWorkerSessionRecord?.launchAuthorityInvariantBlockers,
    );
  const harnessActivationWorkerLaunchEnvelopeInvariantIds =
    workflowHarnessInvariantIds(
      ...harnessActivationWorkerLaunchEnvelopes.map(
        (envelope) => envelope.launchAuthorityInvariantIds,
      ),
    );
  const harnessActivationWorkerLaunchEnvelopeInvariantBlockers =
    workflowHarnessInvariantBlockers(
      ...harnessActivationWorkerLaunchEnvelopes.map(
        (envelope) => envelope.launchAuthorityInvariantBlockers,
      ),
    );
  const harnessActivationWorkerHandoffReceiptInvariantIds =
    workflowHarnessInvariantIds(
      ...harnessActivationWorkerHandoffReceipts.map(
        (receipt) => receipt.requiredInvariantIds,
      ),
    );
  const harnessActivationWorkerHandoffReceiptInvariantBlockers =
    workflowHarnessInvariantBlockers(
      ...harnessActivationWorkerHandoffReceipts.map(
        (receipt) => receipt.invariantBlockers,
      ),
    );
  const harnessActivationWorkerRequiredInvariantIds =
    workflowHarnessInvariantIds(
      harnessActivationWorkerBindingInvariantIds,
      harnessActivationWorkerRegistryInvariantIds,
      harnessActivationWorkerAttachInvariantIds,
      harnessActivationWorkerSessionLaunchAuthorityInvariantIds,
      harnessActivationWorkerLaunchEnvelopeInvariantIds,
      harnessActivationWorkerHandoffReceiptInvariantIds,
    );
  const harnessActivationWorkerRawInvariantBlockers =
    workflowHarnessInvariantBlockers(
      harnessActivationWorkerBindingInvariantBlockers,
      harnessActivationWorkerRegistryInvariantBlockers,
      harnessActivationWorkerAttachInvariantBlockers,
      harnessActivationWorkerSessionInvariantBlockers,
      harnessActivationWorkerLaunchEnvelopeInvariantBlockers,
      harnessActivationWorkerHandoffReceiptInvariantBlockers,
    );
  const harnessActivationWorkerInvariantReady =
    workflowHarnessHasReviewedImportActivationInvariant(
      harnessActivationWorkerBindingInvariantIds,
    ) &&
    workflowHarnessHasReviewedImportActivationInvariant(
      harnessActivationWorkerRegistryInvariantIds,
    ) &&
    workflowHarnessHasReviewedImportActivationInvariant(
      harnessActivationWorkerAttachInvariantIds,
    ) &&
    harnessActivationWorkerAttachLifecycle.length >= 3 &&
    harnessActivationWorkerAttachLifecycle.every(
      (event) =>
        workflowHarnessHasReviewedImportActivationInvariant(
          event.requiredInvariantIds,
        ) && (event.invariantBlockers ?? []).length === 0,
    ) &&
    workflowHarnessHasReviewedImportActivationInvariant(
      harnessActivationWorkerSessionLaunchAuthorityInvariantIds,
    ) &&
    harnessActivationWorkerLaunchEnvelopes.length >= 3 &&
    harnessActivationWorkerLaunchEnvelopes.every(
      (envelope) =>
        workflowHarnessHasReviewedImportActivationInvariant(
          envelope.launchAuthorityInvariantIds,
        ) && (envelope.launchAuthorityInvariantBlockers ?? []).length === 0,
    ) &&
    harnessActivationWorkerHandoffReceipts.length >= 3 &&
    harnessActivationWorkerHandoffReceipts.every(
      (receipt) =>
        workflowHarnessHasReviewedImportActivationInvariant(
          receipt.requiredInvariantIds,
        ) && (receipt.invariantBlockers ?? []).length === 0,
    ) &&
    harnessActivationWorkerRawInvariantBlockers.length === 0;
  const harnessActivationWorkerInvariantBlockers =
    harnessActivationWorkerInvariantReady
      ? []
      : workflowHarnessUniqueStrings([
          ...harnessActivationWorkerRawInvariantBlockers,
          "worker_launch_reviewed_import_activation_invariant_not_bound",
        ]);
  const harnessActivationWorkerLaunchHandoffReady =
    harnessActivationWorkerInvariantReady &&
    harnessActivationWorkerLaunchEnvelopes.length >= 3 &&
    harnessActivationWorkerLaunchEnvelopes.every(
      (envelope) =>
        envelope.accepted === true && (envelope.blockers ?? []).length === 0,
    ) &&
    harnessActivationWorkerLaunchEnvelopePhases.has("launch") &&
    harnessActivationWorkerLaunchEnvelopePhases.has("resume") &&
    harnessActivationWorkerLaunchEnvelopePhases.has("rollback") &&
    harnessActivationWorkerHandoffReceipts.length >= 3 &&
    harnessActivationWorkerHandoffReceipts.every(
      (receipt) =>
        receipt.accepted === true && (receipt.blockers ?? []).length === 0,
    ) &&
    harnessActivationWorkerHandoffReceiptStatuses.has("launched") &&
    harnessActivationWorkerHandoffReceiptStatuses.has("resumed") &&
    harnessActivationWorkerHandoffReceiptStatuses.has("rollback_handoff_ready");
	  const harnessActivationWorkerHandoffTimelineReady =
	    harnessActivationWorkerLaunchHandoffReady &&
	    harnessActivationWorkerHandoffNodeAttempts.length >= 3 &&
    harnessActivationWorkerHandoffNodeAttemptIds.length >= 3 &&
    harnessActivationWorkerHandoffReplayFixtureRefs.length >= 3 &&
    harnessActivationWorkerHandoffNodeAttempts.every(
      (attempt) =>
        attempt.workflowNodeId === "harness.handoff_bridge" &&
        attempt.componentKind === "handoff_bridge" &&
        attempt.receiptIds.some((receiptId) =>
          harnessActivationWorkerHandoffReceiptIds.includes(receiptId),
        ) &&
	        Boolean(attempt.replay.fixtureRef),
	    );
		  const harnessForkMutationCanary =
		    harnessActivationRecord?.forkMutationCanary ??
		    workflow.metadata.harness?.forkMutationCanary ??
		    harnessActivationCandidate?.forkMutationCanary ??
		    null;
  const harnessForkMutationCanaryNodeAttempts =
    workflowHarnessForkMutationCanaryNodeAttempts(harnessForkMutationCanary);
  const harnessForkMutationCanaryNodeAttemptIds =
    harnessForkMutationCanaryNodeAttempts.map((attempt) => attempt.attemptId);
  const harnessActivationGateNodeAttempts = Array.from(
    new Map(
      [
        ...harnessActivationWorkerHandoffNodeAttempts,
        ...harnessForkMutationCanaryNodeAttempts,
      ].map((attempt) => [attempt.attemptId, attempt]),
    ).values(),
  );
		  const harnessForkMutationCanaryReady = Boolean(
		    harnessForkMutationCanary &&
		      harnessForkMutationCanary.status === "passed" &&
		      harnessForkMutationCanary.canaryStatus === "passed" &&
		      harnessForkMutationCanary.rollbackAvailable === true &&
		      harnessForkMutationCanary.receiptRefs.length > 0 &&
		      harnessForkMutationCanary.replayFixtureRefs.length > 0 &&
		      harnessForkMutationCanaryNodeAttempts.length > 0 &&
		      harnessForkMutationCanary.blockers.length === 0,
		  );
	  const harnessActivationReady =
	    !harnessForkWorkflow ||
	    Boolean(
	      workflow.metadata.harness?.activationId &&
	      workflow.metadata.harness?.activationState === "validated" &&
	      harnessActivationRecord?.activationState === "validated" &&
	      harnessActivationRecord.canaryStatus === "passed" &&
	      harnessForkMutationCanaryReady &&
	      harnessActivationRecord.rollbackAvailable === true &&
	      harnessActivationRecord.liveAuthorityTransferred === false &&
	      harnessActivationWorkerHandoffTimelineReady,
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
	            "harness_fork_mutation_canary_not_passed",
	            "harness_package_manifest_incomplete",
            "missing_replay_fixture",
            "missing_unit_tests",
            "mcp_access_not_reviewed",
            "missing_ai_evaluation_coverage",
            "unbound_model_ref",
          ].includes(issue.code),
        )
        .map((issue) => [
          `${issue.code}:${issue.nodeId ?? ""}:${issue.message}`,
          issue,
        ]),
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
  const boundHarnessSlotIds = new Set(
    workflow.nodes.flatMap((node) => node.runtimeBinding?.slotIds ?? []),
  );
  const requiredHarnessSlots = harnessSlots.filter((slot) => slot.required);
  const boundRequiredHarnessSlotCount = requiredHarnessSlots.filter((slot) =>
    boundHarnessSlotIds.has(slot.slotId),
  ).length;
  const receiptReadyHarnessComponents = workflow.nodes.filter(
    (node) => (node.runtimeBinding?.receiptKinds ?? []).length > 0,
  ).length;
  const harnessPackageManifest =
    workflow.metadata.harness?.packageManifest ??
    harnessActivationRecord?.packageManifest ??
    null;
  const harnessPackageManifestRequired =
    workflow.metadata.harness?.activationState === "validated" ||
    Boolean(workflow.metadata.harness?.activationId) ||
    harnessActivationRecord?.activationState === "validated" ||
    Boolean(harnessActivationRecord?.activationId);
  const harnessPackageEvidenceRefValues = Array.isArray(
    harnessPackageManifest?.evidenceRefs,
  )
    ? harnessPackageManifest.evidenceRefs
    : [];
  const harnessPackageReceiptRefValues = Array.isArray(
    harnessPackageManifest?.receiptRefs,
  )
    ? harnessPackageManifest.receiptRefs
    : [];
  const harnessPackageReplayFixtureRefValues = Array.isArray(
    harnessPackageManifest?.replayFixtureRefs,
  )
    ? harnessPackageManifest.replayFixtureRefs
    : [];
  const harnessPackageDeepLinks = Array.isArray(
    harnessPackageManifest?.deepLinks,
  )
    ? harnessPackageManifest.deepLinks
    : [];
  const harnessPackageInspectableDeepLinks = [...harnessPackageDeepLinks].sort(
    (left, right) => {
      if (left?.kind === "activation" && right?.kind !== "activation") return 1;
      if (right?.kind === "activation" && left?.kind !== "activation")
        return -1;
      return 0;
    },
  );
  const harnessPackageWorkerHandoffNodeAttemptIds = Array.isArray(
    harnessPackageManifest?.workerHandoffNodeAttemptIds,
  )
    ? harnessPackageManifest.workerHandoffNodeAttemptIds
    : [];
  const harnessPackageWorkerHandoffReceiptIds = Array.isArray(
    harnessPackageManifest?.workerHandoffReceiptIds,
  )
    ? harnessPackageManifest.workerHandoffReceiptIds
    : [];
  const harnessPackageRollbackRestoreReceiptRefs = Array.isArray(
    harnessPackageManifest?.rollbackRestoreReceiptRefs,
  )
    ? harnessPackageManifest.rollbackRestoreReceiptRefs
    : [];
  const harnessPackageForkMutationCanary =
    harnessPackageManifest?.forkMutationCanary ?? harnessForkMutationCanary;
  const harnessPackageForkMutationCanaryReceiptRefs = Array.isArray(
    harnessPackageManifest?.forkMutationCanaryReceiptRefs,
  )
    ? harnessPackageManifest.forkMutationCanaryReceiptRefs
    : (harnessPackageForkMutationCanary?.receiptRefs ?? []);
  const harnessPackageForkMutationCanaryReplayFixtureRefs = Array.isArray(
    harnessPackageManifest?.forkMutationCanaryReplayFixtureRefs,
  )
    ? harnessPackageManifest.forkMutationCanaryReplayFixtureRefs
    : (harnessPackageForkMutationCanary?.replayFixtureRefs ?? []);
	  const harnessPackageForkMutationCanaryNodeAttemptIds = Array.isArray(
	    harnessPackageManifest?.forkMutationCanaryNodeAttemptIds,
	  )
	    ? harnessPackageManifest.forkMutationCanaryNodeAttemptIds
	    : workflowHarnessForkMutationCanaryNodeAttempts(
	        harnessPackageForkMutationCanary,
	      ).map((attempt) => attempt.attemptId);
  const harnessPackageEvidenceGate =
    harnessActivationCandidate?.gateResults.find(
      (gate) => gate.gateId === "package-evidence",
    ) ?? null;
  const harnessPackageEvidenceReady = harnessPackageEvidenceGate
    ? harnessPackageEvidenceGate.status === "passed"
    : !harnessPackageManifestRequired ||
      Boolean(
        harnessPackageManifest &&
	        harnessPackageReceiptRefValues.length > 0 &&
	        harnessPackageReplayFixtureRefValues.length > 0 &&
	        harnessPackageDeepLinks.length > 0 &&
	        harnessPackageForkMutationCanaryReceiptRefs.length > 0 &&
	        harnessPackageForkMutationCanaryReplayFixtureRefs.length > 0 &&
	        harnessPackageForkMutationCanaryNodeAttemptIds.length > 0 &&
	        harnessPackageWorkerHandoffNodeAttemptIds.length > 0 &&
	        harnessPackageWorkerHandoffReceiptIds.length > 0 &&
        harnessPackageRollbackRestoreReceiptRefs.length > 0,
      );
  const harnessPackageEvidenceRefs = workflowUniqueReceiptRefs([
    harnessPackageManifest?.activationId,
    harnessPackageManifest?.workflowContentHash,
    harnessPackageManifest?.rollbackTarget,
    ...harnessPackageEvidenceRefValues,
    ...harnessPackageReceiptRefValues,
    ...harnessPackageRollbackRestoreReceiptRefs,
    ...harnessPackageForkMutationCanaryReceiptRefs,
    ...harnessPackageForkMutationCanaryReplayFixtureRefs,
    ...harnessPackageForkMutationCanaryNodeAttemptIds,
    harnessPackageForkMutationCanary?.canaryId,
    harnessPackageForkMutationCanary?.diffHash,
    ...harnessPackageWorkerHandoffNodeAttemptIds,
    ...harnessPackageWorkerHandoffReceiptIds,
    ...harnessPackageDeepLinks.map((link) => link?.ref),
  ]);
  const harnessPackageReplayFixtureRefs = workflowUniqueReplayFixtureRefs(
    harnessPackageReplayFixtureRefValues,
  );
  const harnessPackageEvidenceReviewRows = [
    {
      id: "manifest",
      label: "Manifest",
      ready:
        Boolean(harnessPackageManifest) &&
        harnessPackageManifest?.schemaVersion ===
          "workflow.harness.package-evidence-manifest.v1",
      value: harnessPackageManifest?.schemaVersion ?? "missing",
      detail: "portable package evidence sidecar schema",
      refs: workflowUniqueReceiptRefs([
        harnessPackageManifest?.workflowId,
        harnessPackageManifest?.workflowContentHash,
        harnessPackageManifest?.activationId,
      ]),
      kind: "evidence",
    },
    {
      id: "receipts",
      label: "Receipts",
      ready: harnessPackageReceiptRefValues.length > 0,
      value: `${harnessPackageReceiptRefValues.length}`,
      detail: "activation, audit, canary, dispatch, and handoff receipts",
      refs: harnessPackageReceiptRefValues,
      kind: "receipt",
    },
    {
      id: "replay-fixtures",
      label: "Replay fixtures",
      ready: harnessPackageReplayFixtureRefValues.length > 0,
      value: `${harnessPackageReplayFixtureRefValues.length}`,
      detail: "portable replay fixtures preserved with the fork",
      refs: harnessPackageReplayFixtureRefValues,
      kind: "replay",
    },
    {
      id: "rollback-restore",
      label: "Rollback restore",
      ready: harnessPackageRollbackRestoreReceiptRefs.length > 0,
      value: `${harnessPackageRollbackRestoreReceiptRefs.length}`,
      detail: "restore canary receipt bindings",
      refs: harnessPackageRollbackRestoreReceiptRefs,
      kind: "receipt",
    },
    {
      id: "fork-mutation-canary",
      label: "Mutation canary",
      ready:
        Boolean(harnessPackageForkMutationCanary) &&
        harnessPackageForkMutationCanary?.status === "passed" &&
        harnessPackageForkMutationCanaryReceiptRefs.length > 0 &&
        harnessPackageForkMutationCanaryReplayFixtureRefs.length > 0 &&
        harnessPackageForkMutationCanaryNodeAttemptIds.length > 0,
      value:
        harnessPackageForkMutationCanary?.mutationKind ??
        `${harnessPackageForkMutationCanaryReceiptRefs.length}`,
      detail: "proposal-bound workflow diff canary refs",
      refs: workflowUniqueReceiptRefs([
        harnessPackageForkMutationCanary?.canaryId,
        harnessPackageForkMutationCanary?.mutationId,
        harnessPackageForkMutationCanary?.diffHash,
        ...harnessPackageForkMutationCanaryReceiptRefs,
        ...harnessPackageForkMutationCanaryReplayFixtureRefs,
        ...harnessPackageForkMutationCanaryNodeAttemptIds,
      ]),
      kind: "mutation_canary",
    },
    {
      id: "worker-handoff-attempts",
      label: "Handoff attempts",
      ready: harnessPackageWorkerHandoffNodeAttemptIds.length > 0,
      value: `${harnessPackageWorkerHandoffNodeAttemptIds.length}`,
      detail: "launch, resume, and rollback handoff node attempts",
      refs: harnessPackageWorkerHandoffNodeAttemptIds,
      kind: "node_attempt",
    },
    {
      id: "worker-handoff-receipts",
      label: "Handoff receipts",
      ready: harnessPackageWorkerHandoffReceiptIds.length > 0,
      value: `${harnessPackageWorkerHandoffReceiptIds.length}`,
      detail: "worker handoff receipts from the activation package",
      refs: harnessPackageWorkerHandoffReceiptIds,
      kind: "receipt",
    },
    {
      id: "deep-links",
      label: "Deep links",
      ready: harnessPackageDeepLinks.length > 0,
      value: `${harnessPackageDeepLinks.length}`,
      detail: "route-restorable proof links preserved in the package",
      refs: workflowUniqueReceiptRefs(
        harnessPackageInspectableDeepLinks.map((link) => link?.ref),
      ),
      kind: "package_deep_link",
    },
  ];
  const harnessPackageEvidenceBlockerCount =
    harnessPackageEvidenceReviewRows.filter((row) => !row.ready).length;
  const packageImportActivationHandoff =
    packageImportReview?.activationHandoff ?? null;
  const packageImportHandoffWorkerBindingId =
    packageImportActivationHandoff?.workerBinding?.harnessActivationId ??
    packageImportActivationHandoff?.workerBinding?.harnessWorkflowId ??
    "";
  const packageImportReplayIntegrityBlockers = workflowUniqueReceiptRefs([
    packageImportReview?.source.reviewedPackageSnapshotHash &&
    packageImportActivationHandoff?.reviewedPackageSnapshotHash &&
    packageImportReview.source.reviewedPackageSnapshotHash !==
      packageImportActivationHandoff.reviewedPackageSnapshotHash
      ? "package_import_activation_replay_integrity_snapshot_hash_mismatch"
      : null,
    !packageImportReview?.source.workflowContentHash
      ? "package_import_activation_replay_integrity_workflow_hash_missing"
      : packageImportActivationHandoff?.workflowContentHash &&
          packageImportActivationHandoff.workflowContentHash !==
            packageImportReview.source.workflowContentHash
        ? "package_import_activation_replay_integrity_workflow_hash_mismatch"
        : null,
    packageImportReview?.source.activationId &&
    packageImportActivationHandoff?.activationIdPreview &&
    packageImportReview.source.activationId !==
      packageImportActivationHandoff.activationIdPreview
      ? "package_import_activation_replay_integrity_activation_id_mismatch"
      : null,
    packageImportReview?.source.workerBindingActivationId &&
    packageImportHandoffWorkerBindingId &&
    packageImportReview.source.workerBindingActivationId !==
      packageImportHandoffWorkerBindingId
      ? "package_import_activation_replay_integrity_worker_binding_mismatch"
      : null,
    packageImportReview?.source.rollbackTarget &&
    packageImportActivationHandoff?.rollbackTarget &&
    packageImportReview.source.rollbackTarget !==
      packageImportActivationHandoff.rollbackTarget
      ? "package_import_activation_replay_integrity_rollback_target_mismatch"
      : null,
	    packageImportReview?.source.policyPosture &&
	    packageImportActivationHandoff?.policyPosture &&
	    packageImportReview.source.policyPosture !==
	      packageImportActivationHandoff.policyPosture
	      ? "package_import_activation_replay_integrity_policy_posture_mismatch"
	      : null,
    packageImportReview?.source.forkMutationCanaryId &&
    packageImportActivationHandoff?.forkMutationCanaryId &&
    packageImportReview.source.forkMutationCanaryId !==
      packageImportActivationHandoff.forkMutationCanaryId
      ? "package_import_activation_replay_integrity_fork_mutation_canary_mismatch"
      : null,
    packageImportReview?.source.forkMutationCanaryDiffHash &&
    packageImportActivationHandoff?.forkMutationCanaryDiffHash &&
    packageImportReview.source.forkMutationCanaryDiffHash !==
      packageImportActivationHandoff.forkMutationCanaryDiffHash
      ? "package_import_activation_replay_integrity_fork_mutation_canary_diff_mismatch"
      : null,
    packageImportReview?.source.forkMutationCanaryRollbackTarget &&
    packageImportActivationHandoff?.forkMutationCanaryRollbackTarget &&
    packageImportReview.source.forkMutationCanaryRollbackTarget !==
      packageImportActivationHandoff.forkMutationCanaryRollbackTarget
      ? "package_import_activation_replay_integrity_fork_mutation_canary_rollback_mismatch"
      : null,
	    (packageImportReview?.source.replayFixtureRefs?.length ?? 0) === 0
      ? "package_import_activation_replay_integrity_replay_fixture_missing"
      : packageImportActivationHandoff?.replayFixtureRefs?.length &&
          !packageImportActivationHandoff.replayFixtureRefs.every((fixtureRef) =>
            (packageImportReview?.source.replayFixtureRefs ?? []).includes(
              fixtureRef,
            ),
          )
        ? "package_import_activation_replay_integrity_replay_fixture_mismatch"
        : null,
  ]);
  const packageImportActivationEnabled =
    Boolean(packageImportReview) &&
    harnessPackageEvidenceReady &&
    harnessPackageEvidenceBlockerCount === 0 &&
    packageImportReplayIntegrityBlockers.length === 0 &&
    (packageImportActivationHandoff?.mintable ?? true) &&
    readinessResult?.status !== "blocked" &&
    Boolean(onApplyHarnessActivationCandidate);
  const replayFixtureBlockers = harnessActivationBlockers.filter(
    (issue) => issue.code === "missing_replay_fixture",
  );
  const policyPostureReady =
    workflow.metadata.harness?.aiMutationMode === "proposal_only" &&
    (workflow.global_config.environmentProfile?.mockBindingPolicy ??
      "block") === "block" &&
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
  const rollbackRestoreCanary =
    harnessActivationCandidate?.rollbackRestoreCanary ??
    harnessActivationRecord?.rollbackRestoreCanary ??
    null;
  const rollbackRestoreCanaryReady =
    rollbackRestoreCanary?.status === "passed" ||
    rollbackRestoreCanary?.status === "not_required";
  const workerActivationBindingReady =
    Boolean(harnessWorkerBinding?.harnessWorkflowId) &&
    (!workflow.metadata.harness?.activationId ||
      harnessWorkerBinding?.harnessActivationId ===
        workflow.metadata.harness.activationId);
  const harnessReplayGateRefs = workflowUniqueReplayFixtureRefs([
    ...replayFixtureBlockers.map((issue) => issue.nodeId ?? issue.code),
    ...(workflow.metadata.harness?.replayDrills ?? []).map(
      (drill) => drill.drillId,
    ),
    ...(workflow.metadata.harness?.replayGates ?? []).map(
      (gate) => gate.gateId,
    ),
    ...harnessPromotionClusters.map(
      (cluster) => cluster.replayGateProof?.gateId ?? null,
    ),
  ]);
  const harnessReplayFixtureRefs = workflowUniqueReplayFixtureRefs([
    ...(workflow.metadata.harness?.replayDrills ?? []).map(
      (drill) => drill.replayFixtureRef,
    ),
    ...(workflow.metadata.harness?.replayGates ?? []).flatMap(
      (gate) => gate.replayFixtureRefs,
    ),
    ...harnessPromotionClusters.flatMap(
      (cluster) => cluster.replayGateProof?.replayFixtureRefs ?? [],
    ),
    ...(harnessDefaultRuntimeDispatchProof?.replayFixtureRefs ?? []),
  ]);
  const firstHarnessActivationBlockerByCode = (
    codes: string[],
  ): WorkflowValidationIssue | null =>
    harnessActivationBlockers.find((issue) => codes.includes(issue.code)) ??
    null;
  const missingSlotBlocker = firstHarnessActivationBlockerByCode([
    "harness_required_slot_unbound",
    "unbound_model_ref",
  ]);
  const missingTestBlocker = firstHarnessActivationBlockerByCode([
    "missing_unit_tests",
    "missing_ai_evaluation_coverage",
  ]);
  const missingReplayFixtureBlocker = firstHarnessActivationBlockerByCode([
    "missing_replay_fixture",
  ]);
  const policyPostureBlocker = firstHarnessActivationBlockerByCode([
    "harness_self_mutation_not_proposal_only",
    "mcp_access_not_reviewed",
  ]);
  const packageEvidenceBlocker = firstHarnessActivationBlockerByCode([
    "harness_package_manifest_incomplete",
  ]);
  const activationValidationBlocker = firstHarnessActivationBlockerByCode([
    "harness_activation_not_validated",
  ]);
  const makeReadinessGateAction = ({
    gateId,
    label,
    detail,
    blocker,
  }: {
    gateId: string;
    label: string;
    detail: string;
    blocker?: WorkflowValidationIssue | null;
  }): WorkflowHarnessActivationGateAction =>
    blocker
      ? {
          actionId: `activation-gate-action:${gateId}:inspect-blocker`,
          kind: "inspect_blocker",
          impact: "clear_blocker",
          label: "Inspect blocker",
          detail: blocker.message,
          commandTestId: `workflow-harness-gate-action-${gateId}`,
          disabled: false,
          onRun: () => onResolveIssue(blocker),
        }
      : {
          actionId: `activation-gate-action:${gateId}:check-readiness`,
          kind: "check_readiness",
          impact: "inspect",
          label,
          detail,
          commandTestId: `workflow-harness-gate-action-${gateId}`,
          disabled: !onCheckActivationReadiness,
          disabledReason: onCheckActivationReadiness
            ? undefined
            : "readiness check unavailable",
          onRun: onCheckActivationReadiness,
        };
  const harnessActivationGateActions: Record<
    string,
    WorkflowHarnessActivationGateAction
  > = {
    slots: makeReadinessGateAction({
      gateId: "slots",
      label: "Check slots",
      detail:
        "Re-run activation readiness against required component slot bindings.",
      blocker: missingSlotBlocker,
    }),
    tests: makeReadinessGateAction({
      gateId: "tests",
      label: "Check tests",
      detail: "Re-run activation readiness and retained test coverage checks.",
      blocker: missingTestBlocker,
    }),
    "replay-fixtures": missingReplayFixtureBlocker
      ? {
          actionId: "activation-gate-action:replay-fixtures:run-replay-gate",
          kind: "run_replay_gate",
          impact: "collect_evidence",
          label: "Run replay gate",
          detail: missingReplayFixtureBlocker.message,
          commandTestId: "workflow-harness-gate-action-replay-fixtures",
          disabled: !onRunHarnessReplayGate,
          disabledReason: onRunHarnessReplayGate
            ? undefined
            : "replay gate unavailable",
          onRun: onRunHarnessReplayGate,
        }
      : {
          actionId: "activation-gate-action:replay-fixtures:run-replay-gate",
          kind: "run_replay_gate",
          impact: "collect_evidence",
          label: "Run replay gate",
          detail: "Refresh replay gate proof for external and expensive nodes.",
          commandTestId: "workflow-harness-gate-action-replay-fixtures",
          disabled: !onRunHarnessReplayGate,
          disabledReason: onRunHarnessReplayGate
            ? undefined
            : "replay gate unavailable",
          onRun: onRunHarnessReplayGate,
        },
	    "policy-posture": activationGateProposal
	      ? {
          actionId: "activation-gate-action:policy-posture:review-proposal",
          kind: "review_proposal",
          impact: "clear_blocker",
          label: "Review proposal",
          detail: activationGateProposal.summary,
          commandTestId: "workflow-harness-gate-action-policy-posture",
          disabled: false,
          onRun: () => onSelectProposal(activationGateProposal),
        }
      : makeReadinessGateAction({
          gateId: "policy-posture",
          label: "Check policy",
          detail:
            "Re-run policy posture checks for mutation mode, mocks, and MCP review.",
	          blocker: policyPostureBlocker,
	        }),
	    "mutation-canary": {
	      actionId: "activation-gate-action:mutation-canary:run-dry-run",
	      kind: "run_activation_dry_run",
	      impact: "collect_evidence",
	      label: "Run mutation canary",
	      detail:
	        "Refresh the proposal-bound workflow diff canary and its receipt, replay, node-attempt, and rollback refs.",
	      commandTestId: "workflow-harness-gate-action-mutation-canary",
	      disabled: !onRunHarnessActivationDryRun,
	      disabledReason: onRunHarnessActivationDryRun
	        ? undefined
	        : "dry run unavailable",
	      onRun: onRunHarnessActivationDryRun,
	    },
	    "receipt-coverage": makeReadinessGateAction({
      gateId: "receipt-coverage",
      label: "Check receipts",
      detail: "Re-run receipt coverage checks for harness component bindings.",
      blocker: null,
    }),
    "package-evidence": makeReadinessGateAction({
      gateId: "package-evidence",
      label: "Review package evidence",
      detail:
        "Re-run package evidence checks for portable receipt, replay, rollback restore, handoff, and deep-link continuity.",
      blocker: packageEvidenceBlocker,
    }),
    canary: {
      actionId: "activation-gate-action:canary:run-dry-run",
      kind: "run_activation_dry_run",
      impact: "collect_evidence",
      label: "Run canary dry run",
      detail:
        "Generate a dry-run activation candidate and retained-scenario canary proof.",
      commandTestId: "workflow-harness-gate-action-canary",
      disabled: !onRunHarnessActivationDryRun,
      disabledReason: onRunHarnessActivationDryRun
        ? undefined
        : "dry run unavailable",
      onRun: onRunHarnessActivationDryRun,
    },
    "rollback-restore": {
      actionId: "activation-gate-action:rollback-restore:run-dry-run",
      kind: "run_activation_dry_run",
      impact: "collect_evidence",
      label: "Run restore canary",
      detail: "Dry-run the rollback restore probe before activation can mint.",
      commandTestId: "workflow-harness-gate-action-rollback-restore",
      disabled: !onRunHarnessActivationDryRun,
      disabledReason: onRunHarnessActivationDryRun
        ? undefined
        : "dry run unavailable",
      onRun: onRunHarnessActivationDryRun,
    },
    rollback: {
      actionId: "activation-gate-action:rollback:run-drill",
      kind: "run_rollback_drill",
      impact: "collect_evidence",
      label: "Run rollback drill",
      detail:
        "Validate that the current rollback target can be restored safely.",
      commandTestId: "workflow-harness-gate-action-rollback",
      disabled: !onRunHarnessRollbackDrill,
      disabledReason: onRunHarnessRollbackDrill
        ? undefined
        : "rollback drill unavailable",
      onRun: onRunHarnessRollbackDrill,
    },
    "activation-id":
      harnessActivationCandidate?.decision === "mintable"
        ? {
            actionId: "activation-gate-action:activation-id:mint",
            kind: "mint_activation",
            impact: "mint_activation",
            label: "Mint activation",
            detail:
              "Apply the validated candidate and mint the workflow activation id.",
            commandTestId: "workflow-harness-gate-action-activation-id",
            disabled: !onApplyHarnessActivationCandidate,
            disabledReason: onApplyHarnessActivationCandidate
              ? undefined
              : "activation apply unavailable",
            onRun: onApplyHarnessActivationCandidate,
          }
        : {
            actionId: "activation-gate-action:activation-id:run-dry-run",
            kind: "run_activation_dry_run",
            impact: "collect_evidence",
            label: "Run activation dry run",
            detail:
              activationValidationBlocker?.message ??
              "Create a mintable activation candidate before applying it.",
            commandTestId: "workflow-harness-gate-action-activation-id",
            disabled: !onRunHarnessActivationDryRun,
            disabledReason: onRunHarnessActivationDryRun
              ? undefined
              : "dry run unavailable",
            onRun: onRunHarnessActivationDryRun,
          },
    "worker-binding": makeReadinessGateAction({
      gateId: "worker-binding",
      label: "Check worker binding",
      detail:
        "Re-run worker binding readiness against workflow id, activation id, and hash.",
      blocker: activationValidationBlocker,
    }),
    "worker-invariant": makeReadinessGateAction({
      gateId: "worker-invariant",
      label: "Check launch invariant",
      detail:
        "Re-run worker launch readiness against reviewed import activation apply invariants.",
      blocker: activationValidationBlocker,
    }),
    "worker-handoff": makeReadinessGateAction({
      gateId: "worker-handoff",
      label: "Check handoff",
      detail:
        "Re-run worker handoff timeline readiness against launch, replay, and rollback refs.",
      blocker: activationValidationBlocker,
    }),
  };
  const harnessActivationWizardSteps: WorkflowHarnessActivationWizardStep[] = [
    {
      id: "slots",
      label: "Slots",
      ready: boundRequiredHarnessSlotCount === requiredHarnessSlots.length,
      value: `${boundRequiredHarnessSlotCount}/${requiredHarnessSlots.length}`,
      detail: "required component slots bound",
      evidenceRefs: requiredHarnessSlots.map((slot) => slot.slotId),
      gateAction: harnessActivationGateActions.slots,
    },
    {
      id: "tests",
      label: "Tests",
      ready: tests.length > 0,
      value: `${tests.length}`,
      detail: "activation test cases available",
      evidenceRefs: tests.map((test) => test.id),
      gateAction: harnessActivationGateActions.tests,
    },
    {
      id: "replay-fixtures",
      label: "Replay fixtures",
      ready: replayFixtureBlockers.length === 0,
      value:
        replayFixtureBlockers.length === 0
          ? "ready"
          : `${replayFixtureBlockers.length} missing`,
      detail: "required expensive or external nodes replayable",
      evidenceRefs: harnessReplayGateRefs,
      replayFixtureRefs: harnessReplayFixtureRefs,
      gateAction: harnessActivationGateActions["replay-fixtures"],
    },
    {
      id: "policy-posture",
      label: "Policy posture",
      ready: policyPostureReady,
      value: harnessActivationRecord?.policyPosture ?? "proposal_only",
      detail: "proposal-only mutation, blocked mock policy, MCP review",
      evidenceRefs: workflowUniqueReceiptRefs([
        activationGateProposal?.id,
        workflow.metadata.harness?.aiMutationMode,
        productionProfile.mcpAccessReviewed === true
          ? "mcp_access_reviewed"
          : null,
      ]),
      gateAction: harnessActivationGateActions["policy-posture"],
    },
    {
      id: "mutation-canary",
      label: "Mutation canary",
      ready: harnessForkMutationCanaryReady,
      value: harnessForkMutationCanary
        ? `${harnessForkMutationCanary.mutationKind}:${harnessForkMutationCanary.status}`
        : "missing",
      detail: "real workflow diff canaried with receipt, replay, and rollback refs",
      evidenceRefs: workflowUniqueReceiptRefs([
        harnessForkMutationCanary?.canaryId,
        harnessForkMutationCanary?.mutationId,
        harnessForkMutationCanary?.diffHash,
        ...(harnessForkMutationCanary?.evidenceRefs ?? []),
      ]),
      receiptRefs: harnessForkMutationCanary?.receiptRefs ?? [],
      replayFixtureRefs: harnessForkMutationCanary?.replayFixtureRefs ?? [],
	      nodeAttemptIds: harnessForkMutationCanaryNodeAttemptIds,
      gateAction: harnessActivationGateActions["mutation-canary"],
    },
    {
      id: "receipt-coverage",
      label: "Receipt coverage",
      ready: receiptReadyHarnessComponents === workflow.nodes.length,
      value: `${receiptReadyHarnessComponents}/${workflow.nodes.length}`,
      detail: "components emit mapped receipt refs",
      evidenceRefs: workflow.nodes.flatMap(
        (node) => node.runtimeBinding?.receiptKinds ?? [],
      ),
      gateAction: harnessActivationGateActions["receipt-coverage"],
    },
    {
      id: "package-evidence",
      label: "Package evidence",
      ready: harnessPackageEvidenceReady,
      value:
        harnessPackageEvidenceGate?.value ??
        (harnessPackageManifestRequired
          ? harnessPackageEvidenceReady
            ? "verified"
            : "blocked"
          : harnessPackageManifest
            ? "recorded"
            : "not required"),
      detail:
        "portable package receipts, replay fixtures, rollback restore refs, worker handoff refs, and deep links",
      evidenceRefs: harnessPackageEvidenceRefs,
      receiptRefs: workflowUniqueReceiptRefs([
        ...harnessPackageReceiptRefValues,
        ...harnessPackageRollbackRestoreReceiptRefs,
        ...harnessPackageWorkerHandoffReceiptIds,
      ]),
      replayFixtureRefs: harnessPackageReplayFixtureRefs,
      gateAction: harnessActivationGateActions["package-evidence"],
    },
    {
      id: "canary",
      label: "Canary",
      ready: canaryReady,
      value: harnessActivationRecord?.canaryStatus ?? "not_run",
      detail: "workflow canary boundary and retained scenario proof",
      evidenceRefs: workflowUniqueReceiptRefs([
        ...harnessCanaryExecutionBoundaries.map(
          (boundary) => boundary.boundaryId,
        ),
        ...harnessCanaryExecutionBoundaries.map(
          (boundary) => boundary.rollbackDrill.drillId,
        ),
      ]),
      receiptRefs: harnessCanaryExecutionBoundaries.flatMap(
        (boundary) => boundary.receiptIds,
      ),
      replayFixtureRefs: harnessCanaryExecutionBoundaries.flatMap(
        (boundary) => boundary.replayFixtureRefs,
      ),
      gateAction: harnessActivationGateActions.canary,
    },
    {
      id: "rollback-restore",
      label: "Rollback restore",
      ready: rollbackRestoreCanaryReady,
      value: rollbackRestoreCanary?.status ?? "not_run",
      detail: "non-mutating git restore probe verifies rollback revision",
      evidenceRefs: rollbackRestoreCanary?.evidenceRefs ?? [],
      receiptRefs: workflowUniqueReceiptRefs([
        rollbackRestoreCanary?.receiptBindingRef,
      ]),
      gateAction: harnessActivationGateActions["rollback-restore"],
    },
    {
      id: "rollback",
      label: "Rollback",
      ready: rollbackReady,
      value: harnessActivationRecord?.rollbackTarget ?? "not set",
      detail: "rollback target and rollback drill available",
      evidenceRefs: workflowUniqueReceiptRefs([
        harnessActivationRecord?.rollbackTarget,
        harnessActivationRollbackProof?.drillId,
        harnessActivationRollbackExecution?.executionId,
      ]),
      receiptRefs: workflowUniqueReceiptRefs([
        ...(harnessActivationRollbackProof?.receiptRefs ?? []),
        ...(harnessActivationRollbackExecution?.receiptRefs ?? []),
      ]),
      gateAction: harnessActivationGateActions.rollback,
    },
    {
      id: "activation-id",
      label: "Activation id",
      ready: harnessActivationReady,
      value: workflow.metadata.harness?.activationId ?? "not minted",
      detail: "minted only after validation gates pass",
      evidenceRefs: workflowUniqueReceiptRefs([
        workflow.metadata.harness?.activationId,
        harnessActivationCandidate?.activationIdPreview,
      ]),
      gateAction: harnessActivationGateActions["activation-id"],
    },
    {
      id: "worker-binding",
      label: "Worker binding",
      ready: workerActivationBindingReady,
      value: harnessWorkerBinding?.harnessActivationId ?? "blocked",
      detail: "worker binding matches workflow, hash, and activation",
      evidenceRefs: workflowUniqueReceiptRefs([
        harnessWorkerBinding?.harnessWorkflowId,
        harnessWorkerBinding?.harnessActivationId,
        harnessWorkerBinding?.harnessHash,
      ]),
      gateAction: harnessActivationGateActions["worker-binding"],
    },
    {
      id: "worker-invariant",
      label: "Worker invariant",
      ready: harnessActivationWorkerInvariantReady,
      value: harnessActivationWorkerInvariantReady ? "bound" : "blocked",
      detail:
        "worker launch is bound to reviewed import activation apply across binding, attach, session, envelope, and handoff",
      evidenceRefs: workflowUniqueReceiptRefs([
        DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
        ...harnessActivationWorkerRequiredInvariantIds,
        ...harnessActivationWorkerInvariantBlockers,
      ]),
      receiptRefs: workflowUniqueReceiptRefs([
        ...harnessActivationWorkerHandoffReceiptIds,
      ]),
      replayFixtureRefs: workflowUniqueReplayFixtureRefs([
        ...harnessActivationWorkerHandoffReplayFixtureRefs,
      ]),
      requiredInvariantIds: harnessActivationWorkerRequiredInvariantIds,
      invariantBlockers: harnessActivationWorkerInvariantBlockers,
      gateAction: harnessActivationGateActions["worker-invariant"],
    },
    {
      id: "worker-handoff",
      label: "Worker handoff",
      ready: harnessActivationWorkerHandoffTimelineReady,
      value: harnessActivationWorkerHandoffTimelineReady
        ? "timeline"
        : "blocked",
      detail:
        "launch, resume, rollback handoff attempts bound to replay refs and reviewed import launch invariant",
      evidenceRefs: workflowUniqueReceiptRefs([
        ...harnessActivationWorkerHandoffNodeAttemptIds,
        ...harnessActivationWorkerHandoffReplayFixtureRefs,
        ...harnessActivationWorkerRequiredInvariantIds,
        ...harnessActivationWorkerInvariantBlockers,
      ]),
      nodeAttemptIds: workflowUniqueReceiptRefs([
        ...harnessActivationWorkerHandoffNodeAttemptIds,
      ]),
      receiptRefs: workflowUniqueReceiptRefs([
        ...harnessActivationWorkerHandoffReceiptIds,
      ]),
      replayFixtureRefs: workflowUniqueReplayFixtureRefs([
        ...harnessActivationWorkerHandoffReplayFixtureRefs,
      ]),
      requiredInvariantIds: harnessActivationWorkerRequiredInvariantIds,
      invariantBlockers: harnessActivationWorkerInvariantBlockers,
      gateAction: harnessActivationGateActions["worker-handoff"],
    },
  ];
  const selectedHarnessCandidateGate = selectedHarnessActivationGateId
    ? (harnessActivationCandidate?.gateResults.find(
        (gate) => gate.gateId === selectedHarnessActivationGateId,
      ) ?? null)
    : null;
  const selectedHarnessActivationWizardStep = selectedHarnessActivationGateId
    ? (harnessActivationWizardSteps.find(
        (step) => step.id === selectedHarnessActivationGateId,
      ) ?? null)
    : null;
	  const selectedHarnessActivationGateInspection:
    | (WorkflowHarnessActivationCandidateGateResult & {
        sourceKind: "activation_candidate" | "wizard_step";
        nodeAttemptIds: string[];
        receiptRefs: string[];
        replayFixtureRefs: string[];
        requiredInvariantIds: string[];
        invariantBlockers: string[];
        gateAction: WorkflowHarnessActivationGateAction | null;
      })
    | null = selectedHarnessActivationGateId
    ? {
        gateId: selectedHarnessActivationGateId,
        label:
          selectedHarnessCandidateGate?.label ??
          selectedHarnessActivationWizardStep?.label ??
          selectedHarnessActivationGateId,
        status:
          selectedHarnessCandidateGate?.status ??
          (selectedHarnessActivationWizardStep?.ready ? "passed" : "blocked"),
        value:
          selectedHarnessCandidateGate?.value ??
          selectedHarnessActivationWizardStep?.value ??
          "not resolved",
        detail:
          selectedHarnessCandidateGate?.detail ??
          selectedHarnessActivationWizardStep?.detail ??
          "Activation gate is selected but no wizard evidence has been resolved yet.",
        evidenceRefs: workflowUniqueReceiptRefs([
          ...(selectedHarnessCandidateGate?.evidenceRefs ?? []),
          ...(selectedHarnessActivationWizardStep?.evidenceRefs ?? []),
        ]),
        nodeAttemptIds: workflowUniqueReceiptRefs([
          ...(selectedHarnessActivationWizardStep?.nodeAttemptIds ?? []),
        ]),
        receiptRefs: workflowUniqueReceiptRefs([
          ...(selectedHarnessActivationWizardStep?.receiptRefs ?? []),
          ...(selectedHarnessCandidateGate?.evidenceRefs ?? []).filter((ref) =>
            ref.startsWith("workflow_restore_canary:"),
          ),
        ]),
        replayFixtureRefs:
          selectedHarnessActivationGateId === "replay-fixtures"
            ? harnessReplayFixtureRefs
            : workflowUniqueReplayFixtureRefs(
                selectedHarnessActivationWizardStep?.replayFixtureRefs ?? [],
              ),
        requiredInvariantIds: workflowHarnessInvariantIds(
          selectedHarnessActivationWizardStep?.requiredInvariantIds,
        ),
        invariantBlockers: workflowHarnessInvariantBlockers(
          selectedHarnessActivationWizardStep?.invariantBlockers,
        ),
        gateAction:
          harnessActivationGateActions[selectedHarnessActivationGateId] ??
          selectedHarnessActivationWizardStep?.gateAction ??
          null,
        sourceKind: selectedHarnessCandidateGate
          ? "activation_candidate"
          : "wizard_step",
	      }
	    : null;
  const selectedHarnessActivationGateNodeAttempt =
    harnessActivationGateNodeAttempts.find(
      (attempt) =>
        attempt.attemptId === selectedHarnessActivationGateNodeAttemptId ||
        attempt.attemptId === selectedHarnessNodeAttemptId,
    ) ?? null;
  const selectedHarnessActivationGateMutationCanary =
    selectedHarnessActivationGateInspection?.gateId === "mutation-canary"
      ? harnessForkMutationCanary
      : null;
	  const selectedHarnessCanaryBoundary =
    selectedHarnessActivationGateId === "canary"
      ? (harnessCanaryExecutionBoundaries.find(
          (boundary) =>
            selectedHarnessActivationGateEvidenceRef === boundary.boundaryId ||
            selectedHarnessActivationGateEvidenceRef ===
              boundary.rollbackDrill.drillId ||
            (selectedHarnessActivationGateReceiptRef
              ? boundary.receiptIds.includes(
                  selectedHarnessActivationGateReceiptRef,
                )
              : false) ||
            (selectedHarnessReceiptRef
              ? boundary.receiptIds.includes(selectedHarnessReceiptRef)
              : false) ||
            (selectedHarnessActivationGateReplayFixtureRef
              ? boundary.replayFixtureRefs.includes(
                  selectedHarnessActivationGateReplayFixtureRef,
                )
              : false) ||
            (selectedHarnessReplayFixtureRef
              ? boundary.replayFixtureRefs.includes(
                  selectedHarnessReplayFixtureRef,
                )
              : false),
        ) ?? null)
      : null;
  const selectedHarnessRollbackDrillId =
    selectedHarnessCanaryBoundary &&
    (selectedHarnessActivationGateEvidenceRef ===
      selectedHarnessCanaryBoundary.rollbackDrill.drillId ||
      selectedHarnessActivationGateEvidenceRef ===
        selectedHarnessCanaryBoundary.boundaryId ||
      Boolean(selectedHarnessActivationGateReceiptRef) ||
      Boolean(selectedHarnessActivationGateReplayFixtureRef))
      ? selectedHarnessCanaryBoundary.rollbackDrill.drillId
      : "";
  const selectedHarnessRollbackRestoreCanaryId =
    selectedHarnessActivationGateId === "rollback-restore" &&
    rollbackRestoreCanary &&
    (selectedHarnessActivationGateEvidenceRef ===
      rollbackRestoreCanary.canaryId ||
      rollbackRestoreCanary.evidenceRefs.includes(
        selectedHarnessActivationGateEvidenceRef ?? "",
      ) ||
      selectedHarnessActivationGateReceiptRef ===
        rollbackRestoreCanary.receiptBindingRef ||
      selectedHarnessReceiptRef === rollbackRestoreCanary.receiptBindingRef)
      ? rollbackRestoreCanary.canaryId
      : "";
  const selectedHarnessRollbackRestoreReceiptRef =
    selectedHarnessRollbackRestoreCanaryId
      ? (rollbackRestoreCanary?.receiptBindingRef ?? "")
      : "";
  const harnessComponentReadiness = workflow.nodes
    .map((node) => node.runtimeBinding?.readiness)
    .filter((readiness): readiness is NonNullable<typeof readiness> =>
      Boolean(readiness),
    );
  const liveReadyHarnessComponents = harnessComponentReadiness.filter(
    (readiness) => readiness === "live_ready",
  ).length;
  const harnessComponentBindingById = new Map(
    workflow.nodes
      .filter(
        (
          node,
        ): node is Node & {
          runtimeBinding: NonNullable<Node["runtimeBinding"]>;
        } => Boolean(node.runtimeBinding),
      )
      .map((node) => [
        node.runtimeBinding.componentId,
        { node, binding: node.runtimeBinding },
      ]),
  );
  const blessedHarnessComponentById = new Map(
    DEFAULT_AGENT_HARNESS_COMPONENTS.map((component) => [
      component.componentId,
      component,
    ]),
  );
  const harnessForkComponentDiffRows = workflow.metadata.harness?.forkedFrom
    ? Array.from(
        new Set([
          ...DEFAULT_AGENT_HARNESS_COMPONENTS.map(
            (component) => component.componentId,
          ),
          ...harnessComponentBindingById.keys(),
        ]),
      ).map((componentId) => {
        const blessedComponent =
          blessedHarnessComponentById.get(componentId) ?? null;
        const forkBinding =
          harnessComponentBindingById.get(componentId) ?? null;
        const forkReadiness =
          forkBinding?.binding.readiness ??
          workflow.metadata.harness?.componentReadiness?.[componentId] ??
          "missing";
        const blessedVersion = blessedComponent?.version ?? "missing";
        const forkVersion = forkBinding?.binding.componentVersion ?? "missing";
        const status = !blessedComponent
          ? "fork_only"
          : !forkBinding
            ? "missing_from_fork"
            : blessedVersion !== forkVersion ||
                blessedComponent.kind !== forkBinding.binding.componentKind
              ? "changed"
              : "unchanged";
        return {
          componentId,
          nodeId: forkBinding?.node.id ?? null,
          label:
            forkBinding?.node.name ?? blessedComponent?.label ?? componentId,
          kind:
            forkBinding?.binding.componentKind ??
            blessedComponent?.kind ??
            "unknown",
          blessedVersion,
          forkVersion,
          blessedReadiness: blessedComponent?.readiness ?? "missing",
          forkReadiness,
          status,
        };
      })
    : [];
  const harnessForkComponentDiffStats = harnessForkComponentDiffRows.reduce(
    (stats, row) => {
      stats[row.status] = (stats[row.status] ?? 0) + 1;
      return stats;
    },
    {} as Record<string, number>,
  );
  const harnessDefaultComponentVersionSet = Object.fromEntries(
    DEFAULT_AGENT_HARNESS_COMPONENTS.map((component) => [
      component.componentId,
      component.version,
    ]),
  );
  const harnessCurrentWorkerBinding =
    harnessWorkerBinding ?? harnessActivationRecord?.workerBinding ?? null;
  const harnessCandidateWorkerBinding =
    harnessActivationCandidate?.workerBindingPreview ?? null;
  const harnessBindingVersionSet =
    harnessActivationCandidate?.componentVersionSet ??
    harnessActivationRecord?.componentVersionSet ??
    harnessDefaultComponentVersionSet;
  const harnessBindingVersionEntries = Object.entries(harnessBindingVersionSet);
  const harnessBindingRollbackTarget =
    harnessActivationRecord?.rollbackTarget ??
    workflow.metadata.harness?.forkedFrom?.harnessWorkflowId ??
    (blessedHarnessWorkflow ? DEFAULT_AGENT_HARNESS_ACTIVATION_ID : "not set");
  const harnessBindingRollbackHash =
    workflow.metadata.harness?.forkedFrom?.harnessHash ??
    harnessActivationRecord?.harnessHash ??
    workflow.metadata.harness?.harnessHash ??
    harnessCurrentWorkerBinding?.harnessHash ??
    "unbound";
  const harnessBindingRollbackAvailable =
    harnessActivationRecord?.rollbackAvailable === true ||
    Boolean(workflow.metadata.harness?.forkedFrom?.harnessWorkflowId);
  const harnessBindingRollbackTargets = Array.from(
    new Set(
      [
        harnessActivationCandidate?.rollbackTarget,
        harnessActivationRecord?.rollbackTarget,
        workflow.metadata.harness?.forkedFrom?.harnessWorkflowId,
        blessedHarnessWorkflow ? DEFAULT_AGENT_HARNESS_ACTIVATION_ID : null,
      ].filter((target): target is string => Boolean(target)),
    ),
  );
  const harnessSelectedRollbackTarget =
    selectedHarnessRollbackTarget ??
    harnessBindingRollbackTargets[0] ??
    harnessBindingRollbackTarget;
  const latestHarnessActivationAudit =
    harnessActivationAudit[harnessActivationAudit.length - 1] ?? null;
  const latestHarnessActivationAuditReceiptRefs = workflowUniqueReceiptRefs(
    latestHarnessActivationAudit?.receiptRefs ?? [],
  );
  const harnessActivationAuditReceiptRefs = workflowUniqueReceiptRefs(
    harnessActivationAudit.flatMap((event) => event.receiptRefs ?? []),
  );
  const harnessRollbackDrillReceiptRefs = workflowUniqueReceiptRefs(
    harnessActivationRollbackProof?.receiptRefs ?? [],
  );
  const harnessRollbackExecutionReceiptRefs = workflowUniqueReceiptRefs([
    harnessActivationRollbackExecution?.restoreReceiptBindingRef,
    ...(harnessActivationRollbackExecution?.receiptRefs ?? []),
  ]);
  const harnessBindingInspectorStatus =
    harnessActivationCandidate?.decision ??
    harnessActivationRecord?.activationState ??
    workflow.metadata.harness?.activationState ??
    "projection";
  const environmentProfile = workflowEnvironmentProfile(workflow);
  const bindingRegistryRows = workflowBindingRegistryRows(workflow);
  const selectedRuntimeChrome = selectedNode
    ? workflowRuntimeNodeChrome(selectedNode, {
        fallbackLabel: selectedNode.name ?? selectedNode.type,
        locale: globalWorkflowChromeLocale,
      })
    : null;
  const workflowChromeLocale = selectedRuntimeChrome?.locale ?? globalWorkflowChromeLocale;
  const accessibleStatusLabel = (status: unknown) =>
    workflowRuntimeAccessibleStatusLabel(status, workflowChromeLocale);
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
      return (
        edgeClass === "error" ||
        edgeClass === "retry" ||
        edge.fromPort === "error" ||
        edge.fromPort === "retry"
      );
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
      return (
        logic.materialization?.enabled === true ||
        ["local_file", "repo_patch", "connector_write", "deploy"].includes(
          targetKind,
        )
      );
    }
    return false;
  });
  const criticalAiNodeIds = workflow.nodes
    .filter((nodeItem) => nodeItem.type === "model_call")
    .map((nodeItem) => nodeItem.id);
  const mcpToolNodes = workflow.nodes.filter(
    (nodeItem) =>
      nodeItem.type === "plugin_tool" &&
      nodeItem.config?.logic?.toolBinding?.bindingKind === "mcp_tool",
  );
  const settingsModel = workflowSettingsModel({
    workflow,
    validationResult,
    readinessResult,
    bindingRegistryRows,
    portablePackage,
    criticalAiNodeCount: criticalAiNodeIds.length,
    mcpToolNodeCount: mcpToolNodes.length,
    hasErrorOrRetryPath,
  });
  const settingsHarnessModel = workflowSettingsHarnessModel({
    workflow,
    blessedHarnessWorkflow,
    harnessWorkerExecutionMode: harnessWorkerBinding?.executionMode,
    liveReadyHarnessComponents,
    harnessComponentReadinessCount: harnessComponentReadiness.length,
    gatedHarnessClusterCount: gatedHarnessClusters.length,
    harnessPromotionClusterCount: harnessPromotionClusters.length,
  });
  if (panel === "unit_tests") {
    return (
      <WorkflowUnitTestsPanel
        model={unitTestModel}
        searchQuery={unitTestSearchQuery}
        lastRunStatus={testResult?.status ?? "none"}
        onSearchQueryChange={setUnitTestSearchQuery}
        onInspectNode={onInspectNode}
      />
    );
  }
  if (panel === "changes") {
    return (
      <>
        <h3>Changes</h3>
        <p>
          {proposals.length === 0
            ? "No proposals for this workflow."
            : `${proposals.length} proposal${proposals.length === 1 ? "" : "s"} with bounded targets.`}
        </p>
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
              <span>
                {proposal.status} · {proposal.boundedTargets.length} target
                {proposal.boundedTargets.length === 1 ? "" : "s"}
              </span>
              <small>{proposal.summary}</small>
              {proposal.boundedTargets.length > 0 ? (
                <code>{proposal.boundedTargets.slice(0, 4).join(", ")}</code>
              ) : null}
            </button>
          ))}
          {proposals.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No proposed changes</strong>
              <span>
                Create a proposal from validation blockers or the proposal node
                when a graph or code change should be reviewed.
              </span>
            </article>
          ) : null}
        </div>
      </>
    );
  }
  if (panel === "runs") {
    return (
      <WorkflowRunsPanel
        workflow={workflow}
        model={runHistoryModel}
        runSearchQuery={runSearchQuery}
        runStatusFilter={runStatusFilter}
        runSourceFilter={runSourceFilter}
        checkpoints={checkpoints}
        dogfoodRun={dogfoodRun}
        accessibleStatusLabel={accessibleStatusLabel}
        onRunSearchQueryChange={setRunSearchQuery}
        onRunStatusFilterChange={setRunStatusFilter}
        onRunSourceFilterChange={setRunSourceFilter}
        onOpenExecutions={onOpenExecutions}
        onSelectRun={onSelectRun}
        onCompareRun={onCompareRun}
        onInspectNode={onInspectNode}
        onExecuteRuntimeDiagnosticsRepair={onExecuteRuntimeDiagnosticsRepair}
        onExecuteRuntimeContextPressureAction={
          onExecuteRuntimeContextPressureAction
        }
        onExecuteRuntimeWorkspaceTrustAction={
          onExecuteRuntimeWorkspaceTrustAction
        }
        onExecuteRuntimeCodingToolBudgetRecovery={
          onExecuteRuntimeCodingToolBudgetRecovery
        }
        onCreateRuntimeCodingToolBudgetRecoverySubflow={
          onCreateRuntimeCodingToolBudgetRecoverySubflow
        }
        onBindRuntimeCodingToolBudgetRecoveryTemplate={
          onBindRuntimeCodingToolBudgetRecoveryTemplate
        }
        onBindRuntimeTelemetrySource={onBindRuntimeTelemetrySource}
        onMaterializeRuntimeTelemetryBudgetChain={
          onMaterializeRuntimeTelemetryBudgetChain
        }
        onMaterializeRuntimeTerminalCodingLoop={
          onMaterializeRuntimeTerminalCodingLoop
        }
      />
    );
  }
  if (panel === "readiness") {
    return (
      <WorkflowReadinessPanel
        validationResult={validationResult}
        readinessResult={readinessResult}
        workflow={workflow}
        tests={tests}
        portablePackage={portablePackage}
        operationalSideEffectNodes={operationalSideEffectNodes}
        hasErrorOrRetryPath={hasErrorOrRetryPath}
        criticalAiNodeIds={criticalAiNodeIds}
        productionProfile={productionProfile}
        coveredNodeIds={coveredNodeIds}
        mcpToolNodes={mcpToolNodes}
        harnessWorkflow={harnessWorkflow}
        harnessSlots={harnessSlots}
        boundHarnessSlotIds={boundHarnessSlotIds}
        harnessActivationReady={harnessActivationReady}
        harnessDefaultRuntimeDispatchProof={harnessDefaultRuntimeDispatchProof}
        harnessAuthorityGateLiveReady={harnessAuthorityGateLiveReady}
        runtimeCodingToolBudgetEvidence={
          runHistoryModel.runtimeCodingToolBudgetEvidence
        }
        onResolveIssue={onResolveIssue}
        onInspectNode={onInspectNode}
        onConfigureNode={onConfigureNode}
        onExportPackage={onExportPackage}
        onOpenImportPackage={onOpenImportPackage}
      />
    );
  }
  if (panel === "search") {
    return (
      <WorkflowSearchPanel
        model={workflowSearchModel}
        searchQuery={railSearchQuery}
        onSearchQueryChange={setRailSearchQuery}
        onInspectNode={onInspectNode}
      />
    );
  }
  if (panel === "sources") {
    return (
      <WorkflowEntrypointsPanel
        mode="sources"
        model={entrypointsModel}
        onInspectNode={onInspectNode}
      />
    );
  }
  if (panel === "files") {
    return <WorkflowFilesPanel model={fileBundleModel} />;
  }
  if (panel === "schedules") {
    return (
      <WorkflowEntrypointsPanel
        mode="schedules"
        model={entrypointsModel}
        onInspectNode={onInspectNode}
      />
    );
  }
  if (panel === "settings") {
    return (
      <WorkflowSettingsPanel
        model={settingsModel}
        supportedLocales={WORKFLOW_RUNTIME_UI_STRING_CATALOG.supportedLocales}
        bindingRegistryRows={bindingRegistryRows}
        bindingCheckResults={bindingCheckResults}
        bindingManifest={bindingManifest}
        onUpdateWorkflowChromeLocale={onUpdateWorkflowChromeLocale}
        onUpdateEnvironmentProfile={onUpdateEnvironmentProfile}
        onUpdateProductionProfile={onUpdateProductionProfile}
        onGenerateBindingManifest={onGenerateBindingManifest}
        onCheckBindingRow={(row) => void handleCheckBinding(row)}
        onInspectNode={onInspectNode}
      >
        <WorkflowSettingsHarnessPanel
          model={settingsHarnessModel}
          activationGateProposal={activationGateProposal}
          blessedHarnessWorkflow={blessedHarnessWorkflow}
          boundHarnessSlotIds={boundHarnessSlotIds}
          firstHarnessActivationBlocker={firstHarnessActivationBlocker}
          harnessActivationAudit={harnessActivationAudit}
          harnessActivationAuditReceiptRefs={harnessActivationAuditReceiptRefs}
          harnessActivationBlockers={harnessActivationBlockers}
          harnessActivationCandidate={harnessActivationCandidate}
          harnessActivationGateActions={harnessActivationGateActions}
          harnessActivationGateNodeAttempts={harnessActivationGateNodeAttempts}
          harnessActivationReady={harnessActivationReady}
          harnessActivationRecord={harnessActivationRecord}
          harnessActivationRollbackExecution={harnessActivationRollbackExecution}
          harnessActivationRollbackProof={harnessActivationRollbackProof}
          harnessActivationWizardSteps={harnessActivationWizardSteps}
          harnessActivationWorkerHandoffNodeAttemptIds={harnessActivationWorkerHandoffNodeAttemptIds}
          harnessActivationWorkerHandoffNodeAttempts={harnessActivationWorkerHandoffNodeAttempts}
          harnessActivationWorkerHandoffReplayFixtureRefs={harnessActivationWorkerHandoffReplayFixtureRefs}
          harnessActivationWorkerHandoffTimelineReady={harnessActivationWorkerHandoffTimelineReady}
          harnessActivationWorkerInvariantBlockers={harnessActivationWorkerInvariantBlockers}
          harnessActivationWorkerInvariantReady={harnessActivationWorkerInvariantReady}
          harnessActivationWorkerRequiredInvariantIds={harnessActivationWorkerRequiredInvariantIds}
          harnessActiveRuntimeBinding={harnessActiveRuntimeBinding}
          harnessActiveRuntimeRollbackApplyBlockers={harnessActiveRuntimeRollbackApplyBlockers}
          harnessActiveRuntimeRollbackApplyDisabled={harnessActiveRuntimeRollbackApplyDisabled}
          harnessActiveRuntimeRollbackApplyProof={harnessActiveRuntimeRollbackApplyProof}
          harnessActiveRuntimeRollbackDryRunPassed={harnessActiveRuntimeRollbackDryRunPassed}
          harnessActiveRuntimeRollbackExecutionProof={harnessActiveRuntimeRollbackExecutionProof}
          harnessActiveRuntimeRollbackProofBindingBlockers={harnessActiveRuntimeRollbackProofBindingBlockers}
          harnessActiveRuntimeRollbackProofStillBound={harnessActiveRuntimeRollbackProofStillBound}
          harnessAuthorityGateLiveProofs={harnessAuthorityGateLiveProofs}
          harnessAuthorityGateLiveReady={harnessAuthorityGateLiveReady}
          harnessAuthorityGateReadyCount={harnessAuthorityGateReadyCount}
          harnessAuthorityToolingNodeAuthorityGate={harnessAuthorityToolingNodeAuthorityGate}
          harnessAuthorityToolingProof={harnessAuthorityToolingProof}
          harnessBindingInspectorStatus={harnessBindingInspectorStatus}
          harnessBindingRollbackAvailable={harnessBindingRollbackAvailable}
          harnessBindingRollbackHash={harnessBindingRollbackHash}
          harnessBindingRollbackTargets={harnessBindingRollbackTargets}
          harnessBindingVersionEntries={harnessBindingVersionEntries}
          harnessCanaryExecutionBoundaries={harnessCanaryExecutionBoundaries}
          harnessCandidateRevisionBinding={harnessCandidateRevisionBinding}
          harnessCandidateRevisionBindingRef={harnessCandidateRevisionBindingRef}
          harnessCandidateWorkerBinding={harnessCandidateWorkerBinding}
          harnessCognitionNodeAuthorityGate={harnessCognitionNodeAuthorityGate}
          harnessCurrentWorkerBinding={harnessCurrentWorkerBinding}
          harnessDefaultRuntimeDispatchProof={harnessDefaultRuntimeDispatchProof}
          harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers={harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers}
          harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds={harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds}
          harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers={harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers}
          harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds={harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds}
          harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound={harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound}
          harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers={harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers}
          harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds={harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds}
          harnessForkComponentDiffRows={harnessForkComponentDiffRows}
          harnessForkComponentDiffStats={harnessForkComponentDiffStats}
          harnessForkMutationCanary={harnessForkMutationCanary}
          harnessForkMutationCanaryNodeAttemptIds={harnessForkMutationCanaryNodeAttemptIds}
          harnessForkWorkflow={harnessForkWorkflow}
          harnessLiveHandoffProof={harnessLiveHandoffProof}
          harnessPackageDeepLinks={harnessPackageDeepLinks}
          harnessPackageEvidenceBlockerCount={harnessPackageEvidenceBlockerCount}
          harnessPackageEvidenceReady={harnessPackageEvidenceReady}
          harnessPackageEvidenceRefValues={harnessPackageEvidenceRefValues}
          harnessPackageEvidenceReviewRows={harnessPackageEvidenceReviewRows}
          harnessPackageForkMutationCanary={harnessPackageForkMutationCanary}
          harnessPackageForkMutationCanaryNodeAttemptIds={harnessPackageForkMutationCanaryNodeAttemptIds}
          harnessPackageForkMutationCanaryReceiptRefs={harnessPackageForkMutationCanaryReceiptRefs}
          harnessPackageForkMutationCanaryReplayFixtureRefs={harnessPackageForkMutationCanaryReplayFixtureRefs}
          harnessPackageManifest={harnessPackageManifest}
          harnessPackageReceiptRefValues={harnessPackageReceiptRefValues}
          harnessPackageReplayFixtureRefValues={harnessPackageReplayFixtureRefValues}
          harnessPackageRollbackRestoreReceiptRefs={harnessPackageRollbackRestoreReceiptRefs}
          harnessPackageWorkerHandoffNodeAttemptIds={harnessPackageWorkerHandoffNodeAttemptIds}
          harnessPackageWorkerHandoffReceiptIds={harnessPackageWorkerHandoffReceiptIds}
          harnessPromotionClusters={harnessPromotionClusters}
          harnessReadOnlyRoutingNodeKinds={harnessReadOnlyRoutingNodeKinds}
          harnessReadOnlyRoutingProof={harnessReadOnlyRoutingProof}
          harnessReadOnlyRoutingReady={harnessReadOnlyRoutingReady}
          harnessReadOnlyRoutingRequiredScenarios={harnessReadOnlyRoutingRequiredScenarios}
          harnessRevisionBinding={harnessRevisionBinding}
          harnessRevisionBindingRef={harnessRevisionBindingRef}
          harnessRollbackDrillReceiptRefs={harnessRollbackDrillReceiptRefs}
          harnessRollbackExecutionReceiptRefs={harnessRollbackExecutionReceiptRefs}
          harnessRollbackRevisionBinding={harnessRollbackRevisionBinding}
          harnessRollbackRevisionBindingRef={harnessRollbackRevisionBindingRef}
          harnessRoutingModelNodeAuthorityGate={harnessRoutingModelNodeAuthorityGate}
          harnessRuntimeSelectorDecision={harnessRuntimeSelectorDecision}
          harnessSelectedRollbackTarget={harnessSelectedRollbackTarget}
          harnessSelectorLivePromotionReadinessBlockers={harnessSelectorLivePromotionReadinessBlockers}
          harnessSelectorLivePromotionReadinessProof={harnessSelectorLivePromotionReadinessProof}
          harnessSelectorLivePromotionReadinessReady={harnessSelectorLivePromotionReadinessReady}
          harnessSlots={harnessSlots}
          harnessVerificationOutputNodeAuthorityGate={harnessVerificationOutputNodeAuthorityGate}
          harnessWorkerBinding={harnessWorkerBinding}
          harnessWorkflow={harnessWorkflow}
          latestHarnessActivationAudit={latestHarnessActivationAudit}
          latestHarnessActivationAuditReceiptRefs={latestHarnessActivationAuditReceiptRefs}
          onApplyActiveRuntimeRollback={onApplyActiveRuntimeRollback}
          onApplyHarnessActivationCandidate={onApplyHarnessActivationCandidate}
          onCheckActivationReadiness={onCheckActivationReadiness}
          onCopyHarnessDeepLink={onCopyHarnessDeepLink}
          onExecuteHarnessRollback={onExecuteHarnessRollback}
          onInspectNode={onInspectNode}
          onResolveIssue={onResolveIssue}
          onRunActiveRuntimeRollbackDryRun={onRunActiveRuntimeRollbackDryRun}
          onRunHarnessActivationDryRun={onRunHarnessActivationDryRun}
          onRunHarnessRollbackDrill={onRunHarnessRollbackDrill}
          onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
          onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
          onSelectHarnessRollbackTarget={onSelectHarnessRollbackTarget}
          onSelectProposal={onSelectProposal}
          packageImportActivationEnabled={packageImportActivationEnabled}
          packageImportActivationHandoff={packageImportActivationHandoff}
          packageImportHandoffWorkerBindingId={packageImportHandoffWorkerBindingId}
          packageImportReplayIntegrityBlockers={packageImportReplayIntegrityBlockers}
          packageImportReview={packageImportReview}
          rollbackReady={rollbackReady}
          selectedHarnessActivationAuditEventId={selectedHarnessActivationAuditEventId}
          selectedHarnessActivationBlockerIndex={selectedHarnessActivationBlockerIndex}
          selectedHarnessActivationBlockerRef={selectedHarnessActivationBlockerRef}
          selectedHarnessActivationGateEvidenceRef={selectedHarnessActivationGateEvidenceRef}
          selectedHarnessActivationGateId={selectedHarnessActivationGateId}
          selectedHarnessActivationGateInspection={selectedHarnessActivationGateInspection}
          selectedHarnessActivationGateMutationCanary={selectedHarnessActivationGateMutationCanary}
          selectedHarnessActivationGateNodeAttempt={selectedHarnessActivationGateNodeAttempt}
          selectedHarnessActivationGateNodeAttemptId={selectedHarnessActivationGateNodeAttemptId}
          selectedHarnessActivationGateReceiptRef={selectedHarnessActivationGateReceiptRef}
          selectedHarnessActivationGateReplayFixtureRef={selectedHarnessActivationGateReplayFixtureRef}
          selectedHarnessCanaryBoundary={selectedHarnessCanaryBoundary}
          selectedHarnessDefaultDispatchId={selectedHarnessDefaultDispatchId}
          selectedHarnessNodeAttemptId={selectedHarnessNodeAttemptId}
          selectedHarnessReceiptRef={selectedHarnessReceiptRef}
          selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
          selectedHarnessRevisionBindingKind={selectedHarnessRevisionBindingKind}
          selectedHarnessRevisionBindingRef={selectedHarnessRevisionBindingRef}
          selectedHarnessRollbackDrillId={selectedHarnessRollbackDrillId}
          selectedHarnessRollbackRestoreCanaryId={selectedHarnessRollbackRestoreCanaryId}
          selectedHarnessRollbackRestoreReceiptRef={selectedHarnessRollbackRestoreReceiptRef}
          selectedHarnessRollbackTarget={selectedHarnessRollbackTarget}
          selectedHarnessSelectorDecisionId={selectedHarnessSelectorDecisionId}
          selectedHarnessWorkerBindingId={selectedHarnessWorkerBindingId}
          workflow={workflow}
        />
      </WorkflowSettingsPanel>
    );
  }
  const selectedNodeRun = selectedNode
    ? (lastRunResult?.nodeRuns.find(
        (nodeRun) => nodeRun.nodeId === selectedNode.id,
      ) ?? null)
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
  const selectedInputPorts =
    selectedNode?.ports?.filter((port) => port.direction === "input") ?? [];
  const selectedOutputPorts =
    selectedNode?.ports?.filter((port) => port.direction === "output") ?? [];
  const selectedLogic = selectedNode?.config?.logic ?? {};
  const bindingSummary = selectedNode
    ? workflowSelectedNodeBindingSummary(selectedNode, selectedLogic)
    : [];
  const selectedHarnessEvidence = selectedNode
    ? harnessNodeEvidenceSummary(selectedNode)
    : [];
  const selectedHarnessAttempt = selectedNodeRun?.harnessAttempt ?? null;
  const selectedReadOnlyRoutingNodeIndex =
    selectedNode?.runtimeBinding && harnessDefaultRuntimeDispatchProof
      ? harnessReadOnlyRoutingNodeKinds.findIndex(
          (kind) => kind === selectedNode.runtimeBinding?.componentKind,
        )
      : -1;
  const selectedReadOnlyRoutingAttemptId =
    selectedReadOnlyRoutingNodeIndex >= 0
      ? (harnessDefaultRuntimeDispatchProof
          ?.readOnlyCapabilityRoutingAttemptIds[
          selectedReadOnlyRoutingNodeIndex
        ] ?? null)
      : null;
  const selectedReadOnlyRoutingReceiptId =
    selectedReadOnlyRoutingNodeIndex >= 0
      ? (harnessDefaultRuntimeDispatchProof
          ?.readOnlyCapabilityRoutingReceiptIds[
          selectedReadOnlyRoutingNodeIndex
        ] ?? null)
      : null;
  const selectedReadOnlyRoutingReplayRef =
    selectedReadOnlyRoutingNodeIndex >= 0
      ? (harnessDefaultRuntimeDispatchProof
          ?.readOnlyCapabilityRoutingReplayFixtureRefs[
          selectedReadOnlyRoutingNodeIndex
        ] ?? null)
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
  const selectedPackageOutputSummary = workflowPackageNodeOutputSummary(
    selectedNode?.type,
    selectedNodeRun?.output ?? selectedPinnedFixture?.output ?? null,
  );
  const selectedGithubPrCreatePlanSummary = workflowGithubPrCreatePlanSummary(
    selectedNode?.type,
    selectedNodeRun?.output ??
      selectedPinnedFixture?.output ??
      selectedNode?.config?.logic ??
      null,
  );
  const selectedStaleFixtureCount = selectedNodeFixtures.filter(
    (fixture) => fixture.stale || fixture.validationStatus === "stale",
  ).length;
  const selectedInputPreview = workflowValuePreview(
    selectedNodeRun?.input ??
      selectedPinnedFixture?.input ??
      selectedLogic.payload ??
      null,
  );
  const selectedOutputPreview = workflowValuePreview(
    selectedNodeRun?.output ?? selectedPinnedFixture?.output ?? null,
  );
  const selectedErrorPreview = workflowValuePreview(
    selectedNodeRun?.error ?? null,
  );
  const selectedAttachmentEdges = selectedNode
    ? workflow.edges.filter((edge) => {
        if (edge.to !== selectedNode.id) return false;
        const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
        return ["model", "memory", "tool", "parser", "approval"].includes(
          String(edgeClass),
        );
      })
    : [];
  const selectedAttachmentNodeById = new Map(
    workflow.nodes.map((nodeItem) => [nodeItem.id, nodeItem]),
  );
  const selectedAttachmentRows = selectedAttachmentEdges.map((edge) => {
    const edgeClass = String(
      edge.connectionClass ??
        edge.data?.connectionClass ??
        edge.toPort ??
        "data",
    );
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
    selectedNode?.config?.logic?.viewMacro?.expandedFrom ===
      "agent_loop_macro" ||
    selectedAttachmentRows.length > 0;
  const hasAttachmentClass = (connectionClass: string) =>
    selectedAttachmentRows.some((row) => row.edgeClass === connectionClass);
  const modelBindingReady =
    bindingSummary.find((item) => item.label === "Model")?.ready ??
    hasAttachmentClass("model");
  const parserReady =
    hasAttachmentClass("parser") ||
    Boolean(
      selectedLogic.parserBinding?.resultSchema || selectedLogic.outputSchema,
    );
  const toolRows = selectedAttachmentRows.filter(
    (row) => row.edgeClass === "tool",
  );
  const approvalRows = selectedAttachmentRows.filter(
    (row) => row.edgeClass === "approval",
  );
  const memoryReady =
    hasAttachmentClass("memory") || hasAttachmentClass("state");
  const selectedHarnessGroupNodeIds = new Set(
    selectedHarnessGroup?.innerNodeIds ?? [],
  );
  const selectedHarnessGroupNodes = selectedHarnessGroup
    ? selectedHarnessGroup.innerNodeIds
        .map((nodeId) =>
          workflow.nodes.find((nodeItem) => nodeItem.id === nodeId),
        )
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
    ? ((lastRunResult?.harnessGatedClusterRuns ?? []).find(
        (run) => String(run.clusterId) === String(selectedHarnessGroup.groupId),
      ) ?? null)
    : null;
  const selectedHarnessGroupPromotionCluster = selectedHarnessGroup
    ? (harnessPromotionClusters.find(
        (cluster) =>
          String(cluster.clusterId) === String(selectedHarnessGroup.groupId),
      ) ?? null)
    : null;
  const selectedHarnessGroupReplayGateProof =
    selectedHarnessGroupPromotionCluster?.replayGateProof ?? null;
  const selectedHarnessGroupGatedEligibility = selectedHarnessGroup
    ? workflowHarnessPromotionTransitionEligibility(
        workflow,
        String(selectedHarnessGroup.groupId),
        "gated",
        { nowMs: selectedHarnessGroupReplayGateProof?.verifiedAtMs ?? 0 },
      )
    : null;
  const selectedHarnessGroupLiveEligibility = selectedHarnessGroup
    ? workflowHarnessPromotionTransitionEligibility(
        workflow,
        String(selectedHarnessGroup.groupId),
        "live",
        { nowMs: selectedHarnessGroupReplayGateProof?.verifiedAtMs ?? 0 },
      )
    : null;
  const selectedHarnessGroupPromotionAttempts = selectedHarnessGroup
    ? (workflow.metadata.harness?.promotionTransitions ?? []).filter(
        (attempt) =>
          String(attempt.clusterId) === String(selectedHarnessGroup.groupId),
      )
    : [];
  const selectedHarnessGroupLatestPromotionAttempt =
    selectedHarnessGroupPromotionAttempts[
      selectedHarnessGroupPromotionAttempts.length - 1
    ] ?? null;
  const selectedHarnessGroupPromotionBlockers = Array.from(
    new Set([
      ...(selectedHarnessGroupGatedEligibility?.blockers ?? []),
      ...(selectedHarnessGroupLiveEligibility?.blockers ?? []),
    ]),
  );
  const selectedHarnessGroupIssues = selectedHarnessGroup
    ? [
        ...(validationResult?.errors ?? []),
        ...(validationResult?.warnings ?? []),
        ...(validationResult?.executionReadinessIssues ?? []),
        ...(readinessResult?.errors ?? []),
        ...(readinessResult?.warnings ?? []),
        ...(readinessResult?.executionReadinessIssues ?? []),
      ].filter(
        (issue) =>
          issue.nodeId && selectedHarnessGroupNodeIds.has(issue.nodeId),
      )
    : [];
  const selectedHarnessReceiptInspection =
    resolveWorkflowHarnessReceiptInspection({
      receiptRef: selectedHarnessReceiptRef,
      workflow,
      lastRunResult,
      selectedRunId,
      selectedHarnessGroup,
      harnessActivationCandidate,
      readOnlyRoutingReady: harnessReadOnlyRoutingReady,
      authorityToolingProof: harnessAuthorityToolingProof,
    });
  const selectedHarnessReplayInspection =
    resolveWorkflowHarnessReplayInspection({
      replayFixtureRef: selectedHarnessReplayFixtureRef,
      workflow,
      lastRunResult,
      selectedRunId,
      selectedHarnessGroup,
      readOnlyRoutingReady: harnessReadOnlyRoutingReady,
      authorityToolingProof: harnessAuthorityToolingProof,
    });
  const selectedHarnessNodeAttemptInspection =
    resolveWorkflowHarnessNodeAttemptInspection({
      nodeAttemptId: selectedHarnessNodeAttemptId,
      workflow,
      lastRunResult,
      selectedRunId,
      selectedHarnessGroup,
    });
  const selectedHarnessReplayDrill = selectedHarnessReplayInspection
    ? ([...(workflow.metadata.harness?.replayDrills ?? [])]
        .reverse()
        .find(
          (drill) =>
            drill.replayFixtureRef ===
            selectedHarnessReplayInspection.replayFixtureRef,
        ) ?? null)
    : null;
  const selectedHarnessReplayGateTarget = selectedHarnessGroup
    ? String(selectedHarnessGroup.groupId)
    : (workflow.metadata.harness?.activationId ?? workflow.metadata.id);
  const selectedHarnessReplayGate =
    [...(workflow.metadata.harness?.replayGates ?? [])]
      .reverse()
      .find(
        (gate) =>
          gate.targetId === selectedHarnessReplayGateTarget ||
          (!selectedHarnessGroup && gate.scopeKind === "activation_candidate"),
      ) ?? null;
  return (
    <>
      <h3>Outputs</h3>
      {harnessWorkbenchDeepLink ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-harness-deep-link-state"
          data-selected-receipt-ref={selectedHarnessReceiptRef ?? ""}
          data-selected-replay-fixture-ref={
            selectedHarnessReplayFixtureRef ?? ""
          }
          data-selected-selector-decision-id={
            selectedHarnessSelectorDecisionId ?? ""
          }
          data-selected-default-dispatch-id={
            selectedHarnessDefaultDispatchId ?? ""
          }
          data-selected-worker-binding-id={selectedHarnessWorkerBindingId ?? ""}
          data-selected-rollback-target={selectedHarnessRollbackTarget ?? ""}
          data-selected-revision-binding-kind={
            selectedHarnessRevisionBindingKind ?? ""
          }
          data-selected-revision-binding-ref={
            selectedHarnessRevisionBindingRef ?? ""
          }
          data-selected-activation-blocker-index={
            selectedHarnessActivationBlockerIndex ?? ""
          }
          data-selected-activation-blocker-ref={
            selectedHarnessActivationBlockerRef ?? ""
          }
          data-selected-activation-audit-event-id={
            selectedHarnessActivationAuditEventId ?? ""
          }
          data-selected-activation-gate-id={
            selectedHarnessActivationGateId ?? ""
          }
          data-selected-activation-gate-evidence-ref={
            selectedHarnessActivationGateEvidenceRef ?? ""
          }
          data-selected-node-attempt-id={selectedHarnessNodeAttemptId ?? ""}
          data-selected-activation-gate-node-attempt-id={
            selectedHarnessActivationGateNodeAttemptId ?? ""
          }
          data-selected-activation-gate-receipt-ref={
            selectedHarnessActivationGateReceiptRef ?? ""
          }
          data-selected-activation-gate-replay-fixture-ref={
            selectedHarnessActivationGateReplayFixtureRef ?? ""
          }
        >
          <h4>Deep link</h4>
          <article className="workflow-output-row">
            <strong>Workbench state</strong>
            <span>
              {selectedHarnessGroup
                ? `group ${selectedHarnessGroup.groupId}`
                : (selectedNode?.runtimeBinding?.componentId ??
                  selectedNode?.id ??
                  "run")}
            </span>
            <small>{harnessWorkbenchDeepLink}</small>
          </article>
          <button
            type="button"
            data-testid="workflow-copy-harness-deep-link"
            onClick={() => onCopyHarnessDeepLink?.()}
          >
            Copy link
          </button>
        </section>
      ) : null}
      {selectedHarnessNodeAttemptInspection ? (
        <section
          className="workflow-rail-section workflow-harness-node-attempt-inspector"
          data-testid="workflow-harness-node-attempt-inspector"
          data-node-attempt-id={selectedHarnessNodeAttemptInspection.attemptId}
          data-node-attempt-source-kind={
            selectedHarnessNodeAttemptInspection.sourceKind
          }
          data-workflow-node-id={
            selectedHarnessNodeAttemptInspection.workflowNodeId ?? ""
          }
          data-component-kind={
            selectedHarnessNodeAttemptInspection.componentKind
          }
          data-component-id={
            selectedHarnessNodeAttemptInspection.producerComponent
          }
          data-harness-workflow-id={
            selectedHarnessNodeAttemptInspection.harnessWorkflowId
          }
          data-harness-activation-id={
            selectedHarnessNodeAttemptInspection.harnessActivationId
          }
          data-harness-hash={selectedHarnessNodeAttemptInspection.harnessHash}
          data-execution-mode={
            selectedHarnessNodeAttemptInspection.executionMode
          }
          data-readiness={selectedHarnessNodeAttemptInspection.readiness}
          data-status={selectedHarnessNodeAttemptInspection.status}
          data-policy-decision={
            selectedHarnessNodeAttemptInspection.policyDecision
          }
          data-receipt-refs={selectedHarnessNodeAttemptInspection.receiptRefs.join(
            "|",
          )}
          data-receipt-ref-count={
            selectedHarnessNodeAttemptInspection.receiptRefs.length
          }
          data-replay-fixture-ref={
            selectedHarnessNodeAttemptInspection.replayFixtureRef
          }
	          data-replay-determinism={
	            selectedHarnessNodeAttemptInspection.replayDeterminism
	          }
	          data-input-hash={selectedHarnessNodeAttemptInspection.inputHash}
	          data-output-hash={selectedHarnessNodeAttemptInspection.outputHash}
	          data-mutation-diff-hash={
	            selectedHarnessNodeAttemptInspection.mutationDiffHash ?? ""
	          }
	          data-rollback-target={
	            selectedHarnessNodeAttemptInspection.rollbackTarget ?? ""
	          }
	          data-shadow-comparison-live-attempt-id={
	            selectedHarnessNodeAttemptInspection.shadowComparison
              ?.liveAttemptId ?? ""
          }
          data-shadow-comparison-shadow-attempt-id={
            selectedHarnessNodeAttemptInspection.shadowComparison
              ?.shadowAttemptId ?? ""
          }
          data-shadow-comparison-divergence={
            selectedHarnessNodeAttemptInspection.shadowComparison?.divergence ??
            ""
          }
          data-shadow-comparison-blocking={
            selectedHarnessNodeAttemptInspection.shadowComparison
              ? selectedHarnessNodeAttemptInspection.shadowComparison.blocking
                ? "true"
                : "false"
              : ""
          }
        >
          <h4>Node attempt</h4>
          <article
            className={`workflow-output-row is-${selectedHarnessNodeAttemptInspection.status}`}
          >
            <strong>{selectedHarnessNodeAttemptInspection.attemptId}</strong>
            <span>
              {selectedHarnessNodeAttemptInspection.sourceLabel}
              {" · "}
              {selectedHarnessNodeAttemptInspection.componentKind}
              {" · "}
              {selectedHarnessNodeAttemptInspection.status}
            </span>
            <small>
              {selectedHarnessNodeAttemptInspection.executionMode}
              {" · "}
              {selectedHarnessNodeAttemptInspection.readiness}
              {" · "}
              {selectedHarnessNodeAttemptInspection.nodeLabel}
            </small>
          </article>
          <dl className="workflow-node-inspector-stats">
            <div>
              <dt>Receipts</dt>
              <dd>{selectedHarnessNodeAttemptInspection.receiptRefs.length}</dd>
            </div>
            <div>
              <dt>Replay</dt>
              <dd>{selectedHarnessNodeAttemptInspection.replayDeterminism}</dd>
            </div>
            <div>
              <dt>Policy</dt>
              <dd>{selectedHarnessNodeAttemptInspection.policyDecision}</dd>
            </div>
            <div>
              <dt>Binding</dt>
              <dd>
                {selectedHarnessNodeAttemptInspection.harnessActivationId}
              </dd>
            </div>
          </dl>
          <article className="workflow-output-row">
            <strong>Replay fixture</strong>
            <span>{selectedHarnessNodeAttemptInspection.replayFixtureRef}</span>
	            <small>
	              {selectedHarnessNodeAttemptInspection.inputHash}
	              {" · "}
	              {selectedHarnessNodeAttemptInspection.outputHash}
	            </small>
	            {selectedHarnessNodeAttemptInspection.mutationDiffHash ||
	            selectedHarnessNodeAttemptInspection.rollbackTarget ? (
	              <small>
	                diff{" "}
	                {selectedHarnessNodeAttemptInspection.mutationDiffHash ??
	                  "not recorded"}{" "}
	                · rollback{" "}
	                {selectedHarnessNodeAttemptInspection.rollbackTarget ??
	                  "not recorded"}
	              </small>
	            ) : null}
	          </article>
	        </section>
      ) : null}
      {selectedHarnessNodeAttemptInspection?.shadowComparison ? (
        <section
          className="workflow-rail-section workflow-harness-live-shadow-comparison-inspector"
          data-testid="workflow-harness-live-shadow-comparison-inspector"
          data-live-attempt-id={
            selectedHarnessNodeAttemptInspection.shadowComparison.liveAttemptId
          }
          data-shadow-attempt-id={
            selectedHarnessNodeAttemptInspection.shadowComparison
              .shadowAttemptId
          }
          data-workflow-node-id={
            selectedHarnessNodeAttemptInspection.shadowComparison.workflowNodeId
          }
          data-component-kind={
            selectedHarnessNodeAttemptInspection.shadowComparison.componentKind
          }
          data-divergence={
            selectedHarnessNodeAttemptInspection.shadowComparison.divergence
          }
          data-blocking={
            selectedHarnessNodeAttemptInspection.shadowComparison.blocking
              ? "true"
              : "false"
          }
          data-summary={
            selectedHarnessNodeAttemptInspection.shadowComparison.summary
          }
          data-live-receipt-refs={selectedHarnessNodeAttemptInspection.shadowComparison.liveReceiptRefs.join(
            "|",
          )}
          data-shadow-receipt-refs={selectedHarnessNodeAttemptInspection.shadowComparison.shadowReceiptRefs.join(
            "|",
          )}
          data-live-replay-fixture-ref={
            selectedHarnessNodeAttemptInspection.shadowComparison
              .liveReplayFixtureRef
          }
          data-shadow-replay-fixture-ref={
            selectedHarnessNodeAttemptInspection.shadowComparison
              .shadowReplayFixtureRef
          }
          data-live-input-hash={
            selectedHarnessNodeAttemptInspection.shadowComparison.liveInputHash
          }
          data-shadow-input-hash={
            selectedHarnessNodeAttemptInspection.shadowComparison
              .shadowInputHash
          }
          data-live-output-hash={
            selectedHarnessNodeAttemptInspection.shadowComparison.liveOutputHash
          }
          data-shadow-output-hash={
            selectedHarnessNodeAttemptInspection.shadowComparison
              .shadowOutputHash
          }
        >
          <h4>Live vs shadow</h4>
          <article
            className={`workflow-output-row is-${selectedHarnessNodeAttemptInspection.shadowComparison.divergence}`}
          >
            <strong>
              {selectedHarnessNodeAttemptInspection.shadowComparison.divergence}
            </strong>
            <span>
              {selectedHarnessNodeAttemptInspection.shadowComparison.summary}
            </span>
            <small>
              {selectedHarnessNodeAttemptInspection.shadowComparison.blocking
                ? "blocking"
                : "non-blocking"}
            </small>
          </article>
          <dl className="workflow-node-inspector-stats">
            <div>
              <dt>Live receipts</dt>
              <dd>
                {
                  selectedHarnessNodeAttemptInspection.shadowComparison
                    .liveReceiptRefs.length
                }
              </dd>
            </div>
            <div>
              <dt>Shadow receipts</dt>
              <dd>
                {
                  selectedHarnessNodeAttemptInspection.shadowComparison
                    .shadowReceiptRefs.length
                }
              </dd>
            </div>
            <div>
              <dt>Live fixture</dt>
              <dd>
                {
                  selectedHarnessNodeAttemptInspection.shadowComparison
                    .liveReplayFixtureRef
                }
              </dd>
            </div>
            <div>
              <dt>Shadow fixture</dt>
              <dd>
                {
                  selectedHarnessNodeAttemptInspection.shadowComparison
                    .shadowReplayFixtureRef
                }
              </dd>
            </div>
          </dl>
        </section>
      ) : null}
      {selectedHarnessReceiptInspection ? (
        <section
          className="workflow-rail-section workflow-harness-receipt-inspector"
          data-testid="workflow-harness-receipt-inspector"
          data-receipt-ref={selectedHarnessReceiptInspection.receiptRef}
          data-receipt-source-kind={selectedHarnessReceiptInspection.sourceKind}
          data-receipt-kind={selectedHarnessReceiptInspection.receiptKind}
          data-producer-component={
            selectedHarnessReceiptInspection.producerComponent
          }
          data-policy-decision={selectedHarnessReceiptInspection.policyDecision}
          data-attempt-id={selectedHarnessReceiptInspection.attemptId}
          data-replay-fixture-ref={
            selectedHarnessReceiptInspection.replayFixtureRef
          }
        >
          <h4>Receipt inspector</h4>
          <article
            className={`workflow-output-row is-${
              selectedHarnessReceiptInspection.sourceKind === "unresolved"
                ? "blocked"
                : "ready"
            }`}
            data-testid="workflow-harness-receipt-inspector-summary"
          >
            <strong>{selectedHarnessReceiptInspection.receiptRef}</strong>
            <span>
              {selectedHarnessReceiptInspection.sourceLabel}
              {" · "}
              {selectedHarnessReceiptInspection.status}
            </span>
            <small>
              {selectedHarnessReceiptInspection.producerComponent}
              {" · "}
              {selectedHarnessReceiptInspection.receiptKind}
            </small>
          </article>
          <dl
            className="workflow-rail-stats"
            data-testid="workflow-harness-receipt-inspector-metadata"
          >
            <div>
              <dt>Policy</dt>
              <dd>{selectedHarnessReceiptInspection.policyDecision}</dd>
            </div>
            <div>
              <dt>Attempt</dt>
              <dd>{selectedHarnessReceiptInspection.attemptId}</dd>
            </div>
            <div>
              <dt>Replay</dt>
              <dd>{selectedHarnessReceiptInspection.replayFixtureRef}</dd>
            </div>
            <div>
              <dt>Node</dt>
              <dd>{selectedHarnessReceiptInspection.nodeLabel}</dd>
            </div>
            <div>
              <dt>Input</dt>
              <dd>{selectedHarnessReceiptInspection.inputHash}</dd>
            </div>
            <div>
              <dt>Output</dt>
              <dd>{selectedHarnessReceiptInspection.outputHash}</dd>
            </div>
          </dl>
          <article
            className="workflow-output-row"
            data-testid="workflow-harness-receipt-payload-preview"
            data-payload-preview-kind={
              selectedHarnessReceiptInspection.payloadPreview.kind
            }
          >
            <strong>Redacted payload</strong>
            <span>
              {selectedHarnessReceiptInspection.payloadPreview.summary}
            </span>
            <small>
              {selectedHarnessReceiptInspection.payloadPreview.detail}
            </small>
          </article>
          <div
            className="workflow-inline-metadata"
            data-testid="workflow-harness-receipt-evidence-refs"
            data-evidence-ref-count={
              selectedHarnessReceiptInspection.evidenceRefs.length
            }
          >
            <span>
              {selectedHarnessReceiptInspection.createdAtMs
                ? workflowTimeLabel(
                    selectedHarnessReceiptInspection.createdAtMs,
                  )
                : "timestamp pending"}
            </span>
            <code>
              {selectedHarnessReceiptInspection.evidenceRefs
                .slice(0, 4)
                .join(" | ") || "evidence pending"}
            </code>
          </div>
        </section>
      ) : null}
      {selectedHarnessReplayInspection ? (
        <section
          className="workflow-rail-section workflow-harness-replay-inspector"
          data-testid="workflow-harness-replay-inspector"
          data-replay-fixture-ref={
            selectedHarnessReplayInspection.replayFixtureRef
          }
          data-replay-source-kind={selectedHarnessReplayInspection.sourceKind}
          data-producer-component={
            selectedHarnessReplayInspection.producerComponent
          }
          data-policy-decision={selectedHarnessReplayInspection.policyDecision}
          data-attempt-id={selectedHarnessReplayInspection.attemptId}
          data-receipt-ref={selectedHarnessReplayInspection.receiptRef}
          data-determinism={selectedHarnessReplayInspection.determinism}
          data-redaction-policy={
            selectedHarnessReplayInspection.redactionPolicy
          }
          data-captures-input={selectedHarnessReplayInspection.capturesInput}
          data-captures-output={selectedHarnessReplayInspection.capturesOutput}
          data-captures-policy-decision={
            selectedHarnessReplayInspection.capturesPolicyDecision
          }
          data-replay-drill-status={
            selectedHarnessReplayDrill?.drillStatus ?? "not_run"
          }
          data-replay-divergence-class={
            selectedHarnessReplayDrill?.divergenceClass ?? "not_run"
          }
        >
          <h4>Replay inspector</h4>
          <article
            className={`workflow-output-row is-${
              selectedHarnessReplayInspection.sourceKind === "unresolved"
                ? "blocked"
                : "ready"
            }`}
            data-testid="workflow-harness-replay-inspector-summary"
          >
            <strong>{selectedHarnessReplayInspection.replayFixtureRef}</strong>
            <span>
              {selectedHarnessReplayInspection.sourceLabel}
              {" · "}
              {selectedHarnessReplayInspection.status}
            </span>
            <small>
              {selectedHarnessReplayInspection.producerComponent}
              {" · "}
              {selectedHarnessReplayInspection.determinism}
            </small>
          </article>
          <dl
            className="workflow-rail-stats"
            data-testid="workflow-harness-replay-inspector-metadata"
          >
            <div>
              <dt>Mode</dt>
              <dd>{selectedHarnessReplayInspection.executionMode}</dd>
            </div>
            <div>
              <dt>Readiness</dt>
              <dd>{selectedHarnessReplayInspection.readiness}</dd>
            </div>
            <div>
              <dt>Attempt</dt>
              <dd>{selectedHarnessReplayInspection.attemptId}</dd>
            </div>
            <div>
              <dt>Receipt</dt>
              <dd>{selectedHarnessReplayInspection.receiptRef}</dd>
            </div>
            <div>
              <dt>Node</dt>
              <dd>{selectedHarnessReplayInspection.nodeLabel}</dd>
            </div>
            <div>
              <dt>Policy</dt>
              <dd>{selectedHarnessReplayInspection.policyDecision}</dd>
            </div>
          </dl>
          <div
            className="workflow-inline-metadata"
            data-testid="workflow-harness-replay-capture-flags"
          >
            <span>
              envelope{" "}
              {selectedHarnessReplayInspection.deterministicEnvelope
                ? "deterministic"
                : "not deterministic"}
            </span>
            <code>
              input {String(selectedHarnessReplayInspection.capturesInput)} |
              output {String(selectedHarnessReplayInspection.capturesOutput)} |
              policy{" "}
              {String(selectedHarnessReplayInspection.capturesPolicyDecision)}
            </code>
          </div>
          <article
            className="workflow-output-row"
            data-testid="workflow-harness-replay-payload-preview"
            data-payload-preview-kind={
              selectedHarnessReplayInspection.payloadPreview.kind
            }
          >
            <strong>Redacted fixture context</strong>
            <span>
              {selectedHarnessReplayInspection.payloadPreview.summary}
            </span>
            <small>
              {selectedHarnessReplayInspection.payloadPreview.detail}
            </small>
          </article>
          <div
            className="workflow-inline-metadata"
            data-testid="workflow-harness-replay-evidence-refs"
            data-evidence-ref-count={
              selectedHarnessReplayInspection.evidenceRefs.length
            }
          >
            <span>{selectedHarnessReplayInspection.redactionPolicy}</span>
            <code>
              {selectedHarnessReplayInspection.evidenceRefs
                .slice(0, 4)
                .join(" | ") || "evidence pending"}
            </code>
            <small>
              {selectedHarnessReplayInspection.nondeterminismReason}
            </small>
          </div>
          <div
            className="workflow-harness-activation-actions"
            data-testid="workflow-harness-replay-drill-actions"
          >
            <button
              type="button"
              data-testid="workflow-harness-run-replay-drill"
              disabled={!onRunHarnessReplayDrill}
              onClick={onRunHarnessReplayDrill}
            >
              Run replay
            </button>
          </div>
          <article
            className={`workflow-output-row is-${
              selectedHarnessReplayDrill?.drillStatus === "passed"
                ? "ready"
                : "blocked"
            }`}
            data-testid="workflow-harness-replay-drill-result"
            data-drill-status={
              selectedHarnessReplayDrill?.drillStatus ?? "not_run"
            }
            data-divergence-class={
              selectedHarnessReplayDrill?.divergenceClass ?? "not_run"
            }
            data-drill-id={selectedHarnessReplayDrill?.drillId ?? ""}
            data-receipt-refs={
              selectedHarnessReplayDrill?.receiptRefs.join("|") ?? ""
            }
          >
            <strong>
              {selectedHarnessReplayDrill?.divergenceClass ??
                "Replay drill not run"}
            </strong>
            <span>
              {selectedHarnessReplayDrill?.drillStatus ?? "not_run"}
              {" · "}
              expected{" "}
              {selectedHarnessReplayDrill?.expectedOutputHash ?? "pending"}
              {" · "}
              actual {selectedHarnessReplayDrill?.actualOutputHash ?? "pending"}
            </span>
            <small>
              {selectedHarnessReplayDrill?.blockers.join(" | ") ||
                selectedHarnessReplayDrill?.policyDecision ||
                "Run replay to classify divergence."}
            </small>
          </article>
          {selectedHarnessReplayDrill?.receiptRefs.length ? (
            <div
              className="workflow-harness-authority-gate-actions"
              data-testid="workflow-harness-replay-drill-receipt-refs"
            >
              {selectedHarnessReplayDrill.receiptRefs.map(
                (receiptRef, index) => (
                  <button
                    key={receiptRef}
                    type="button"
                    className={`workflow-harness-ref-button ${
                      selectedHarnessReceiptRef === receiptRef
                        ? "is-active"
                        : ""
                    }`}
                    data-testid={`workflow-harness-replay-drill-receipt-${index}`}
                    data-receipt-ref={receiptRef}
                    onClick={() => onSelectHarnessReceiptRef?.(receiptRef)}
                  >
                    <code>{receiptRef}</code>
                  </button>
                ),
              )}
            </div>
          ) : null}
        </section>
      ) : null}
      {workflow.metadata.harness ? (
        <section
          className="workflow-rail-section workflow-harness-replay-gate"
          data-testid="workflow-harness-replay-gate"
          data-replay-gate-status={
            selectedHarnessReplayGate?.gateStatus ?? "not_run"
          }
          data-replay-gate-scope={
            selectedHarnessReplayGate?.scopeKind ??
            (selectedHarnessGroup ? "harness_group" : "activation_candidate")
          }
          data-replay-gate-target={selectedHarnessReplayGateTarget}
          data-total-fixtures={selectedHarnessReplayGate?.totalFixtures ?? 0}
          data-blocking-fixtures={
            selectedHarnessReplayGate?.blockingReplayFixtureRefs.length ?? 0
          }
          data-activation-gate-impact={
            selectedHarnessReplayGate?.activationGateImpact ?? "not_run"
          }
        >
          <h4>Replay gate</h4>
          <div
            className="workflow-harness-activation-actions"
            data-testid="workflow-harness-replay-gate-actions"
          >
            <button
              type="button"
              data-testid="workflow-harness-run-replay-gate"
              disabled={!onRunHarnessReplayGate}
              onClick={onRunHarnessReplayGate}
            >
              Run replay gate
            </button>
          </div>
          <dl
            className="workflow-rail-stats"
            data-testid="workflow-harness-replay-gate-rollup"
            data-divergence-counts={
              selectedHarnessReplayGate
                ? JSON.stringify(selectedHarnessReplayGate.divergenceCounts)
                : "{}"
            }
          >
            <div>
              <dt>Total</dt>
              <dd>{selectedHarnessReplayGate?.totalFixtures ?? 0}</dd>
            </div>
            <div>
              <dt>Passed</dt>
              <dd>{selectedHarnessReplayGate?.passedCount ?? 0}</dd>
            </div>
            <div>
              <dt>Blocked</dt>
              <dd>{selectedHarnessReplayGate?.blockedCount ?? 0}</dd>
            </div>
            <div>
              <dt>Receipts</dt>
              <dd>{selectedHarnessReplayGate?.receiptRefs.length ?? 0}</dd>
            </div>
          </dl>
          <article
            className={`workflow-output-row is-${
              selectedHarnessReplayGate?.gateStatus === "passed"
                ? "ready"
                : "blocked"
            }`}
            data-testid="workflow-harness-replay-gate-result"
            data-replay-gate-id={selectedHarnessReplayGate?.gateId ?? ""}
            data-blocking-replay-fixture-refs={
              selectedHarnessReplayGate?.blockingReplayFixtureRefs.join("|") ??
              ""
            }
            data-receipt-refs={
              selectedHarnessReplayGate?.receiptRefs.join("|") ?? ""
            }
          >
            <strong>
              {selectedHarnessReplayGate?.gateStatus ?? "Replay gate not run"}
            </strong>
            <span>
              impact{" "}
              {selectedHarnessReplayGate?.activationGateImpact ?? "pending"}
              {" · "}
              target {selectedHarnessReplayGateTarget}
            </span>
            <small>
              {selectedHarnessReplayGate?.blockers.join(" | ") ||
                selectedHarnessReplayGate?.blockingReplayFixtureRefs.join(
                  " | ",
                ) ||
                "Run replay gate to prove the selected scope."}
            </small>
          </article>
          {selectedHarnessReplayGate?.receiptRefs.length ? (
            <div
              className="workflow-harness-authority-gate-actions"
              data-testid="workflow-harness-replay-gate-receipt-refs"
            >
              {selectedHarnessReplayGate.receiptRefs
                .slice(0, 8)
                .map((receiptRef, index) => (
                  <button
                    key={receiptRef}
                    type="button"
                    className={`workflow-harness-ref-button ${
                      selectedHarnessReceiptRef === receiptRef
                        ? "is-active"
                        : ""
                    }`}
                    data-testid={`workflow-harness-replay-gate-receipt-${index}`}
                    data-receipt-ref={receiptRef}
                    onClick={() => onSelectHarnessReceiptRef?.(receiptRef)}
                  >
                    <code>{receiptRef}</code>
                  </button>
                ))}
            </div>
          ) : null}
        </section>
      ) : null}
      {harnessLivePromotionReadinessProof ? (
        <section
          className="workflow-rail-section workflow-harness-live-promotion-readiness"
          data-testid="workflow-harness-live-promotion-readiness"
          data-proof-id={harnessLivePromotionReadinessProof.proofId}
          data-default-live-activation-ready={
            harnessLivePromotionReadinessProof.defaultLiveActivationReady
          }
          data-promotion-eligible={
            harnessLivePromotionReadinessProof.promotionEligible
          }
          data-policy-decision={
            harnessLivePromotionReadinessProof.policyDecision
          }
          data-cluster-count={
            harnessLivePromotionReadinessProof.clusterReadiness.length
          }
          data-activation-blockers={harnessLivePromotionReadinessProof.activationBlockers.join(
            "|",
          )}
        >
          <h4>Live promotion readiness</h4>
          <dl
            className="workflow-rail-stats"
            data-testid="workflow-harness-live-promotion-readiness-summary"
          >
            <div>
              <dt>Clusters</dt>
              <dd>
                {
                  harnessLivePromotionReadinessProof.clusterReadiness.filter(
                    (cluster) => cluster.blockers.length === 0,
                  ).length
                }
                /{harnessLivePromotionReadinessProof.requiredClusterIds.length}
              </dd>
            </div>
            <div>
              <dt>Receipts</dt>
              <dd>
                {harnessLivePromotionReadinessProof.clusterReadiness.reduce(
                  (total, cluster) => total + cluster.receiptRefs.length,
                  0,
                )}
              </dd>
            </div>
            <div>
              <dt>Replay</dt>
              <dd>
                {harnessLivePromotionReadinessProof.clusterReadiness.reduce(
                  (total, cluster) => total + cluster.replayFixtureRefs.length,
                  0,
                )}
              </dd>
            </div>
            <div>
              <dt>Rollback</dt>
              <dd>
                {harnessLivePromotionReadinessProof.rollbackAvailable
                  ? "ready"
                  : "blocked"}
              </dd>
            </div>
          </dl>
          <article
            className={`workflow-output-row is-${
              harnessLivePromotionReadinessProof.defaultLiveActivationReady
                ? "ready"
                : "blocked"
            }`}
            data-testid="workflow-harness-live-promotion-readiness-rollup"
            data-invalid-fork-live-activation-blocked={
              harnessLivePromotionReadinessProof.invalidForkLiveActivationBlocked
            }
            data-rollback-target={
              harnessLivePromotionReadinessProof.rollbackTarget
            }
          >
            <strong>{harnessLivePromotionReadinessProof.policyDecision}</strong>
            <span>
              target {harnessLivePromotionReadinessProof.targetExecutionMode}
              {" · "}
              invalid forks{" "}
              {harnessLivePromotionReadinessProof.invalidForkLiveActivationBlocked
                ? "blocked"
                : "review"}
            </span>
            <small>
              {harnessLivePromotionReadinessProof.activationBlockers.join(
                " | ",
              ) || harnessLivePromotionReadinessProof.rollbackTarget}
            </small>
          </article>
          <div
            className="workflow-harness-authority-gate-list"
            data-testid="workflow-harness-live-promotion-readiness-clusters"
          >
            {harnessLivePromotionReadinessProof.clusterReadiness.map(
              (cluster) => (
                <article
                  key={cluster.clusterId}
                  className={`workflow-test-row is-${
                    cluster.blockers.length === 0 ? "passed" : "blocked"
                  }`}
                  data-testid={`workflow-harness-live-promotion-cluster-${cluster.clusterId}`}
                  data-cluster-id={cluster.clusterId}
                  data-current-status={cluster.currentStatus}
                  data-blocking-divergence-count={
                    cluster.blockingDivergenceCount
                  }
                  data-unclassified-divergence-count={
                    cluster.unclassifiedDivergenceCount
                  }
                  data-blockers={cluster.blockers.join("|")}
                >
                  <strong>{cluster.label}</strong>
                  <span>
                    {cluster.currentStatus} to {cluster.targetExecutionMode}
                    {" · "}
                    receipts {cluster.receiptRefs.length}
                    {" · "}
                    replay {cluster.replayFixtureRefs.length}
                  </span>
                  <small>{cluster.decision}</small>
                </article>
              ),
            )}
          </div>
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
                {harnessAuthorityGateReadyCount}/
                {harnessAuthorityGateLiveProofs.length}
              </dd>
            </div>
            <div>
              <dt>Attempts</dt>
              <dd>
                {
                  harnessDefaultRuntimeDispatchProof
                    .authorityToolingGateLiveAttemptIds.length
                }
              </dd>
            </div>
            <div>
              <dt>Receipts</dt>
              <dd>
                {
                  harnessDefaultRuntimeDispatchProof
                    .authorityToolingGateLiveReceiptIds.length
                }
              </dd>
            </div>
            <div>
              <dt>Replay</dt>
              <dd>
                {
                  harnessDefaultRuntimeDispatchProof
                    .authorityToolingGateLiveReplayFixtureRefs.length
                }
              </dd>
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
                : "review"}{" "}
              · approval gate{" "}
              {harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReady
                ? "live"
                : "blocked"}
            </span>
            <small>
              side effects{" "}
              {harnessDefaultRuntimeDispatchProof.authorityToolingSideEffectsExecuted
                ? "executed"
                : "not executed"}{" "}
              · rollback{" "}
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
                {selectedHarnessGroup.collapsed ? "collapsed" : "expanded"} ·{" "}
                {selectedHarnessGroup.innerNodeIds.length} nodes
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
              <dd>
                {selectedHarnessGroup.statusRollup.liveReadyCount}/
                {selectedHarnessGroup.innerNodeIds.length}
              </dd>
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
              <dt>Replay gate</dt>
              <dd>{selectedHarnessGroup.statusRollup.replayGateStatus}</dd>
            </div>
            <div>
              <dt>Divergence</dt>
              <dd>{selectedHarnessGroup.statusRollup.divergenceCount}</dd>
            </div>
            <div>
              <dt>Activation</dt>
              <dd>
                {selectedHarnessGroup.statusRollup.activationState ?? "unknown"}
              </dd>
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
            <article
              className="workflow-output-row"
              data-testid="workflow-harness-group-run-link"
            >
              <strong>
                {selectedHarnessGroup.deepLinks.runId ?? "no selected run"}
              </strong>
              <span>
                {selectedHarnessGroupGatedRun?.status ??
                  "gated run not selected"}
              </span>
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
                  canary {selectedHarnessGroupGatedRun.canaryStatus} · rollback{" "}
                  {selectedHarnessGroupGatedRun.rollbackTarget}
                </span>
                <small>
                  {selectedHarnessGroupGatedRun.nodeAttemptIds.length} attempts
                  · {selectedHarnessGroupGatedRun.receiptIds.length} receipts
                </small>
              </article>
            ) : null}
            <article
              className={`workflow-test-row is-${
                selectedHarnessGroupReplayGateProof?.gateStatus === "passed" &&
                selectedHarnessGroupReplayGateProof.activationGateImpact ===
                  "passed"
                  ? "passed"
                  : selectedHarnessGroupReplayGateProof?.gateStatus ===
                        "blocked" ||
                      selectedHarnessGroupReplayGateProof?.gateStatus ===
                        "failed"
                    ? "blocked"
                    : "idle"
              }`}
              data-testid="workflow-harness-group-replay-gate-proof"
              data-replay-gate-status={
                selectedHarnessGroupReplayGateProof?.gateStatus ?? "not_run"
              }
              data-activation-gate-impact={
                selectedHarnessGroupReplayGateProof?.activationGateImpact ??
                "pending"
              }
              data-replay-gate-id={
                selectedHarnessGroupReplayGateProof?.gateId ?? ""
              }
              data-blocking-replay-fixture-refs={
                selectedHarnessGroupReplayGateProof?.blockingReplayFixtureRefs.join(
                  "|",
                ) ?? ""
              }
            >
              <strong>Replay gate</strong>
              <span>
                {selectedHarnessGroupReplayGateProof?.gateStatus ?? "not_run"}
                {" · "}
                impact{" "}
                {selectedHarnessGroupReplayGateProof?.activationGateImpact ??
                  "pending"}
              </span>
              <small>
                {selectedHarnessGroupReplayGateProof
                  ? `${selectedHarnessGroupReplayGateProof.totalFixtures} fixtures · ${selectedHarnessGroupReplayGateProof.receiptRefs.length} receipts`
                  : "Run replay gate for this promotion cluster before gated or live promotion."}
              </small>
            </article>
            <div
              className="workflow-harness-activation-actions"
              data-testid="workflow-harness-group-promotion-actions"
            >
              <button
                type="button"
                data-testid="workflow-harness-promote-cluster-gated"
                disabled={
                  !onRunHarnessPromotionTransition ||
                  selectedHarnessGroupGatedEligibility?.eligible !== true
                }
                onClick={() => onRunHarnessPromotionTransition?.("gated")}
              >
                Promote gated
              </button>
              <button
                type="button"
                data-testid="workflow-harness-promote-cluster-live"
                disabled={
                  !onRunHarnessPromotionTransition ||
                  selectedHarnessGroupLiveEligibility?.eligible !== true
                }
                onClick={() => onRunHarnessPromotionTransition?.("live")}
              >
                Promote live
              </button>
            </div>
            <article
              className={`workflow-output-row is-${
                selectedHarnessGroupGatedEligibility?.eligible ||
                selectedHarnessGroupLiveEligibility?.eligible
                  ? "ready"
                  : "blocked"
              }`}
              data-testid="workflow-harness-group-promotion-eligibility"
              data-gated-eligible={
                selectedHarnessGroupGatedEligibility?.eligible
                  ? "true"
                  : "false"
              }
              data-live-eligible={
                selectedHarnessGroupLiveEligibility?.eligible ? "true" : "false"
              }
              data-gated-blockers={
                selectedHarnessGroupGatedEligibility?.blockers.join("|") ?? ""
              }
              data-live-blockers={
                selectedHarnessGroupLiveEligibility?.blockers.join("|") ?? ""
              }
            >
              <strong>Promotion transition</strong>
              <span>
                gated{" "}
                {selectedHarnessGroupGatedEligibility?.eligible
                  ? "eligible"
                  : "blocked"}{" "}
                · live{" "}
                {selectedHarnessGroupLiveEligibility?.eligible
                  ? "eligible"
                  : "blocked"}
              </span>
              <small>
                {selectedHarnessGroupPromotionBlockers
                  .slice(0, 4)
                  .join(" | ") ||
                  "readiness, receipts, replay, canary, and rollback are ready"}
              </small>
            </article>
            {selectedHarnessGroupLatestPromotionAttempt ? (
              <article
                className={`workflow-test-row is-${
                  selectedHarnessGroupLatestPromotionAttempt.attemptStatus ===
                  "promoted"
                    ? "passed"
                    : "blocked"
                }`}
                data-testid="workflow-harness-group-promotion-attempt"
                data-transition-id={
                  selectedHarnessGroupLatestPromotionAttempt.transitionId
                }
                data-attempt-status={
                  selectedHarnessGroupLatestPromotionAttempt.attemptStatus
                }
                data-target-execution-mode={
                  selectedHarnessGroupLatestPromotionAttempt.targetExecutionMode
                }
                data-receipt-refs={selectedHarnessGroupLatestPromotionAttempt.receiptRefs.join(
                  "|",
                )}
                data-evidence-refs={selectedHarnessGroupLatestPromotionAttempt.evidenceRefs.join(
                  "|",
                )}
              >
                <strong>
                  {selectedHarnessGroupLatestPromotionAttempt.gateDecision}
                </strong>
                <span>
                  {selectedHarnessGroupLatestPromotionAttempt.previousStatus}
                  {" -> "}
                  {selectedHarnessGroupLatestPromotionAttempt.nextStatus}
                </span>
                <small>
                  {selectedHarnessGroupLatestPromotionAttempt.blockers.join(
                    " | ",
                  ) ||
                    `${selectedHarnessGroupLatestPromotionAttempt.receiptRefs.length} receipts · ${selectedHarnessGroupLatestPromotionAttempt.replayFixtureRefs.length} replay fixtures`}
                </small>
              </article>
            ) : null}
          </section>
          <section
            className="workflow-rail-section"
            data-testid="workflow-harness-group-receipt-refs"
          >
            <h4>Receipts</h4>
            {selectedHarnessGroup.deepLinks.receiptRefs
              .slice(0, 8)
              .map((receiptRef) => (
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
            {selectedHarnessGroup.deepLinks.replayFixtureRefs
              .slice(0, 8)
              .map((fixtureRef) => (
                <button
                  key={fixtureRef}
                  type="button"
                  className={`workflow-harness-ref-button ${
                    selectedHarnessReplayFixtureRef === fixtureRef
                      ? "is-active"
                      : ""
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
          {selectedHarnessGroupIssues.length > 0 ||
          (selectedHarnessGroupGatedRun?.activationBlockers.length ?? 0) > 0 ? (
            <section
              className="workflow-rail-section"
              data-testid="workflow-harness-group-activation-blockers"
            >
              <h4>Activation blockers</h4>
              {(selectedHarnessGroupGatedRun?.activationBlockers ?? [])
                .slice(0, 4)
                .map((blocker) => (
                  <article
                    key={blocker}
                    className="workflow-test-row is-blocked"
                  >
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
                  <span>
                    {workflowNodeName(workflow, comparison.workflowNodeId)}
                  </span>
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
                  <strong>
                    {workflowNodeName(workflow, attempt.workflowNodeId)}
                  </strong>
                  <span>
                    {attempt.executionMode} · {attempt.readiness}
                  </span>
                  <small>
                    {attempt.receiptIds.length} receipts ·{" "}
                    {attempt.replay.determinism}
                  </small>
                </article>
              ))}
            </section>
          ) : null}
        </section>
      ) : null}
      {selectedNode ? (
        <section
          className="workflow-node-inspector"
          data-testid="workflow-selected-node-inspector"
          tabIndex={0}
          data-runtime-ui-locale={selectedRuntimeChrome?.locale}
          data-accessible-status={selectedRuntimeChrome?.accessibleStatusValue}
          data-accessible-status-text={selectedRuntimeChrome?.statusText}
          aria-label={selectedRuntimeChrome?.ariaLabel}
        >
          <header>
            <div>
              <strong>{selectedRuntimeChrome?.label ?? selectedNode.name}</strong>
              <span>
                {selectedNode.type} ·{" "}
                {selectedRuntimeChrome?.statusText ??
                  accessibleStatusLabel(selectedNodeRun?.status ?? selectedNode.status ?? "idle")}
              </span>
              {selectedRuntimeChrome?.isRuntimeChrome ? (
                <small
                  data-testid="workflow-selected-node-status-announcement"
                  aria-live="polite"
                >
                  {selectedRuntimeChrome.statusAnnouncement}
                </small>
              ) : null}
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
              onClick={() =>
                onRunNode(selectedNode, selectedPinnedFixture ?? undefined)
              }
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
                onDryRunFixtureForNode(
                  selectedNode,
                  selectedPinnedFixture ?? undefined,
                )
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
              disabled={
                workflowReadOnly ||
                !selectedPinnedFixture ||
                selectedPinnedFixture.pinned === true
              }
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
          <dl
            className="workflow-node-inspector-stats"
            data-testid="workflow-selected-node-status"
          >
            <div>
              <dt>Run</dt>
              <dd>{accessibleStatusLabel(selectedNodeRun?.status ?? "not_run")}</dd>
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
              <div
                className="workflow-rail-list"
                data-testid="workflow-selected-node-harness-receipts"
              >
                {selectedHarnessEvidence.map((item) => (
                  <article key={item.label} className="workflow-output-row">
                    <strong>{item.label}</strong>
                    <span>{item.value}</span>
                  </article>
                ))}
              </div>
              {selectedNode.runtimeBinding ? (
                <article
                  className="workflow-output-row"
                  data-testid="workflow-selected-node-replay-binding"
                >
                  <strong>Replay envelope</strong>
                  <span>
                    {selectedNode.runtimeBinding.executionMode ?? "projection"}
                    {" · "}
                    {selectedNode.runtimeBinding.readiness ?? "projection_only"}
                    {" · "}
                    {selectedNode.runtimeBinding.replayEnvelope?.determinism ??
                      (selectedNode.runtimeBinding.replay.deterministicEnvelope
                        ? "deterministic"
                        : "best effort")}
                    {" · "}
                    {selectedNode.runtimeBinding.slotIds?.join(", ") ||
                      "no slots"}
                  </span>
                  <small>
                    {selectedNode.runtimeBinding.replayEnvelope
                      ?.redactionPolicy ?? "runtime_redacted"}
                    {" · "}
                    {selectedNode.runtimeBinding.evidenceEventKinds.join(", ")}
                  </small>
                </article>
              ) : null}
              {selectedHarnessAttempt ? (
                <article
                  className="workflow-output-row"
                  data-testid="workflow-selected-node-harness-attempt"
                  data-node-attempt-id={selectedHarnessAttempt.attemptId}
                  data-workflow-node-id={selectedHarnessAttempt.workflowNodeId}
                  data-component-kind={selectedHarnessAttempt.componentKind}
                  data-component-id={selectedHarnessAttempt.componentId}
                  data-harness-workflow-id={
                    selectedHarnessAttempt.harnessWorkflowId
                  }
                  data-harness-activation-id={
                    selectedHarnessAttempt.harnessActivationId
                  }
                  data-harness-hash={selectedHarnessAttempt.harnessHash}
                  data-execution-mode={selectedHarnessAttempt.executionMode}
                  data-readiness={selectedHarnessAttempt.readiness}
                  data-status={selectedHarnessAttempt.status}
                  data-policy-decision={
                    selectedHarnessAttempt.policyDecision ?? ""
                  }
                  data-receipt-refs={selectedHarnessAttempt.receiptIds.join(
                    "|",
                  )}
                  data-replay-fixture-ref={
                    selectedHarnessAttempt.replay.fixtureRef ?? ""
                  }
                  data-input-hash={selectedHarnessAttempt.inputHash ?? ""}
                  data-output-hash={selectedHarnessAttempt.outputHash ?? ""}
                >
                  <strong>Latest attempt</strong>
                  <span>
                    {selectedHarnessAttempt.executionMode}
                    {" · "}
                    {selectedHarnessAttempt.status}
                    {" · "}
                    {selectedHarnessAttempt.policyDecision ?? "policy pending"}
                    {" · "}
                    {selectedHarnessAttempt.receiptIds.length} receipts
                  </span>
                  <small>
                    {selectedHarnessAttempt.attemptId}
                    {" · "}
                    {selectedHarnessAttempt.replay.fixtureRef ??
                      "replay pending"}
                    {" · "}
                    {selectedHarnessAttempt.inputHash ?? "input hash pending"}
                    {" · "}
                    {selectedHarnessAttempt.outputHash ?? "output hash pending"}
                  </small>
                </article>
              ) : null}
              {selectedReadOnlyRoutingNodeIndex >= 0 &&
              harnessReadOnlyRoutingProof ? (
                <section
                  className="workflow-node-inspector-section"
                  data-testid="workflow-selected-node-read-only-routing-proof"
                >
                  <h4>Read-only routing proof</h4>
                  <dl className="workflow-node-inspector-stats">
                    <div>
                      <dt>Scenario</dt>
                      <dd>
                        {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenario ??
                          "pending"}
                      </dd>
                    </div>
                    <div>
                      <dt>Coverage</dt>
                      <dd>
                        {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenarioCoverageKey ??
                          "pending"}
                      </dd>
                    </div>
                    <div>
                      <dt>Mutation</dt>
                      <dd>
                        {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingNoMutationReady
                          ? "blocked"
                          : "review"}
                      </dd>
                    </div>
                    <div>
                      <dt>Source</dt>
                      <dd>
                        {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingSourceMaterialReady
                          ? "ready"
                          : "pending"}
                      </dd>
                    </div>
                  </dl>
                  <article
                    className="workflow-output-row"
                    data-testid="workflow-selected-node-read-only-routing-receipts"
                  >
                    <strong>
                      {selectedNode.runtimeBinding?.componentKind}
                    </strong>
                    <span>
                      {selectedReadOnlyRoutingAttemptId ?? "attempt pending"} ·{" "}
                      {selectedReadOnlyRoutingReceiptId ?? "receipt pending"}
                    </span>
                    <small>
                      {selectedReadOnlyRoutingReplayRef ??
                        "replay fixture pending"}
                    </small>
                  </article>
                  <article
                    className="workflow-output-row"
                    data-testid="workflow-selected-node-read-only-routing-no-mutation"
                  >
                    <strong>
                      {harnessReadOnlyRoutingProof.sideEffectsExecuted ===
                        false &&
                      harnessReadOnlyRoutingProof.mutationExecuted === false
                        ? "Side effects blocked"
                        : "Side effects need review"}
                    </strong>
                    <span>
                      mode{" "}
                      {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingMode ??
                        String(harnessReadOnlyRoutingProof.mode ?? "unknown")}
                    </span>
                    <small>
                      {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingWorkflowOwnedNodeKinds.join(
                        ", ",
                      ) ?? "node kinds pending"}
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
                      selectedAuthorityGateLiveProofs.filter(
                        (gate) => gate.ready,
                      ).length
                    }
                    /{selectedAuthorityGateLiveProofs.length}
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
                <span>{accessibleStatusLabel(selectedNodeRun?.status ?? "not_run")}</span>
              </header>
              <span>{selectedOutputPreview.summary}</span>
              <small>
                {selectedNodeRun?.error
                  ? selectedErrorPreview.summary
                  : selectedOutputPreview.detail}
              </small>
            </article>
          </section>
          {selectedPackageOutputSummary ? (
            <section
              className="workflow-node-inspector-section"
              data-testid="workflow-selected-node-package-output"
            >
              <h4>Package output</h4>
              <WorkflowPackageOutputSummaryCard
                summary={selectedPackageOutputSummary}
                testId="workflow-selected-node-package-output-summary"
              />
            </section>
          ) : null}
          {selectedGithubPrCreatePlanSummary ? (
            <section
              className="workflow-node-inspector-section"
              data-testid="workflow-selected-node-github-pr-create-output"
            >
              <h4>GitHub PR create plan</h4>
              <WorkflowGithubPrCreateOutputSummaryCard
                summary={selectedGithubPrCreatePlanSummary}
                testId="workflow-selected-node-github-pr-create-output-summary"
                receiptRefs={selectedHarnessAttempt?.receiptIds ?? []}
                replayFixtureRef={
                  selectedHarnessAttempt?.replay.fixtureRef ?? null
                }
              />
            </section>
          ) : null}
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
                      <span>
                        {row.edgeClass} · {row.nodeType}
                      </span>
                    </button>
                  ))}
                </div>
              ) : null}
            </section>
          ) : null}
          <section
            className="workflow-node-inspector-section"
            data-testid="workflow-selected-node-ports"
          >
            <h4>Ports</h4>
            <div className="workflow-node-inspector-port-groups">
              <div>
                <span>Inputs</span>
                {selectedInputPorts.length > 0 ? (
                  selectedInputPorts.map((port) => (
                    <em
                      key={`input-${port.id}`}
                      data-connection-class={port.connectionClass}
                    >
                      {port.label} · {port.connectionClass}
                    </em>
                  ))
                ) : (
                  <small>none</small>
                )}
              </div>
              <div>
                <span>Outputs</span>
                {selectedOutputPorts.length > 0 ? (
                  selectedOutputPorts.map((port) => (
                    <em
                      key={`output-${port.id}`}
                      data-connection-class={port.connectionClass}
                    >
                      {port.label} · {port.connectionClass}
                    </em>
                  ))
                ) : (
                  <small>none</small>
                )}
              </div>
            </div>
          </section>
          <section
            className="workflow-node-inspector-section"
            data-testid="workflow-selected-node-bindings"
          >
            <h4>Configuration</h4>
            {bindingSummary.map((item) => (
              <article
                key={item.label}
                className={`workflow-test-row is-${item.ready ? "passed" : "blocked"}`}
              >
                <strong>{item.label}</strong>
                <span>{item.value}</span>
              </article>
            ))}
          </section>
          {selectedNodeIssues.length > 0 ? (
            <section
              className="workflow-node-inspector-section"
              data-testid="workflow-selected-node-blockers"
            >
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
            <section
              className="workflow-node-inspector-section"
              data-testid="workflow-selected-node-latest-output"
            >
              <h4>Latest output</h4>
              {(() => {
                const preview = workflowValuePreview(selectedNodeRun.output);
                return (
                  <article
                    className="workflow-output-row"
                    data-testid="workflow-selected-node-latest-output-preview"
                  >
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
          <p>
            {outputNodes.length === 0
              ? "No output nodes configured."
              : `${outputNodes.length} workflow output${outputNodes.length === 1 ? "" : "s"} configured.`}
          </p>
          <div
            className="workflow-rail-list"
            data-testid="workflow-output-node-list"
          >
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
                  <span>
                    {String(logic.format ?? "output")} ·{" "}
                    {String(logic.deliveryTarget?.targetKind ?? "no delivery")}
                  </span>
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
                <span>
                  Add an Output primitive to define what the workflow produces.
                </span>
              </article>
            ) : null}
          </div>
        </>
      )}
    </>
  );
}
