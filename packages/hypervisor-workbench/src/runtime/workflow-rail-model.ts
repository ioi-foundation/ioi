import type {
  GraphEnvironmentProfile,
  Node,
  WorkflowBindingCheckResult,
  WorkflowBindingManifest,
  WorkflowDogfoodRun,
  WorkflowHarnessForkActivationCandidate,
  WorkflowHarnessGroupView,
  WorkflowHarnessNodeAttemptRecord,
  WorkflowHarnessReplayDeterminism,
  WorkflowHarnessReplayEnvelope,
  WorkflowHarnessShadowComparison,
  WorkflowPortablePackage,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRunResult,
  WorkflowRunSummary,
  WorkflowStreamEvent,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import { workflowHarnessForkMutationCanaryNodeAttempts } from "./harness-workflow";
import {
  normalizeGraphModelBinding,
  normalizeWorkflowModelBinding,
  workflowModelBindingIsReady,
} from "./workflow-model-capability-binding";
import {
  normalizeWorkflowConnectorBinding,
  normalizeWorkflowToolBinding,
  workflowConnectorBindingIsReady,
  workflowToolBindingIsReady,
} from "./workflow-tool-connector-capability-binding";
import {
  workflowValuePreview,
  type WorkflowValuePreview,
} from "./workflow-value-preview";

export interface WorkflowBindingSummaryItem {
  label: string;
  value: string;
  ready: boolean;
}

export interface WorkflowBindingRegistryRow {
  id: string;
  nodeItem: Node;
  bindingKind: string;
  ref: string;
  mode: "mock" | "live" | "local";
  ready: boolean;
  scope: string;
  sideEffectClass: string;
  approval: string;
}

export interface WorkflowBindingRegistrySummary {
  total: number;
  ready: number;
  mock: number;
  approval: number;
}

export interface WorkflowLifecycleState {
  id:
    | "draft"
    | "local"
    | "sandbox"
    | "scheduled"
    | "production"
    | "blocked";
  label: string;
  detail: string;
  status: "idle" | "ready" | "warning" | "blocked";
}

export interface WorkflowRailSearchResult {
  id: string;
  resultKind: "Node" | "Test" | "Output";
  title: string;
  subtitle: string;
  detail?: string;
  nodeId: string | null;
  searchable: string;
}

export interface WorkflowFileBundleItem {
  label: string;
  path: string;
  status: string;
}

export interface WorkflowRunComparison {
  baselineRunId: string;
  targetRunId: string;
  baselineStatus: string;
  targetStatus: string;
  durationDeltaMs: number | null;
  checkpointDelta: number;
  eventDelta: number;
  changedNodes: Array<{
    nodeId: string;
    nodeName: string;
    before: string;
    after: string;
    inputChanged: boolean;
    outputChanged: boolean;
    errorChanged: boolean;
  }>;
  stateChanges: Array<{
    key: string;
    change: "added" | "removed" | "changed";
  }>;
}

export interface WorkflowChildRunLineage {
  childRunId: string;
  childRunStatus: string;
  childWorkflowPath: string;
  childThreadId: string;
}

export interface WorkflowPackageNodeOutputSummary {
  kind: "export" | "import";
  status: string;
  toolName: string;
  packagePath: string | null;
  manifestPath: string | null;
  readinessStatus: string | null;
  portable: boolean | null;
  workflowChromeLocale: string | null;
  packageEvidenceReady: boolean | null;
  importedWorkflowPath: string | null;
  workflowChromeLocalePreserved: boolean | null;
  sourceWorkflowChromeLocale: string | null;
  importedWorkflowChromeLocale: string | null;
}

export interface WorkflowGithubPrCreatePlanSummary {
  status: string;
  decision: string;
  toolName: string;
  action: string;
  planId: string | null;
  receiptId: string | null;
  dryRun: boolean | null;
  previewOnly: boolean | null;
  mutationAttempted: boolean | null;
  mutationExecuted: boolean | null;
  networkLookupPerformed: boolean | null;
  requestMethod: string | null;
  requestPath: string | null;
  requestPayloadHash: string | null;
  requestBodyIncluded: boolean | null;
  requestTokenIncluded: boolean | null;
  repoFullName: string | null;
  baseBranch: string | null;
  headBranch: string | null;
  reviewGateStatus: string | null;
  reviewSatisfied: boolean | null;
  requiredScopes: string[];
  missingScopes: string[];
  scopeGranted: boolean | null;
  blockers: string[];
  evidenceRefs: string[];
}

function workflowUnknownRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function workflowUniqueReceiptRefs(
  refs: Array<string | null | undefined> = [],
): string[] {
  return Array.from(
    new Set(
      refs.filter((ref): ref is string => typeof ref === "string" && ref.length > 0),
    ),
  );
}

export function workflowUniqueReplayFixtureRefs(
  refs: Array<string | null | undefined> = [],
): string[] {
  return workflowUniqueReceiptRefs(refs);
}

const WORKFLOW_RECEIPT_SECRET_KEY_PATTERN =
  /api[_-]?key|authorization|bearer|credential|password|secret|token/i;

function workflowRedactedReceiptPayload(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") {
    return value.length > 180 ? `${value.slice(0, 177)}...` : value;
  }
  if (typeof value !== "object") return value;
  if (Array.isArray(value)) {
    if (depth >= 2) return `${value.length} item${value.length === 1 ? "" : "s"}`;
    return value.slice(0, 6).map((item) => workflowRedactedReceiptPayload(item, depth + 1));
  }
  const entries = Object.entries(value as Record<string, unknown>).slice(0, 18);
  return Object.fromEntries(
    entries.map(([key, item]) => [
      key,
      WORKFLOW_RECEIPT_SECRET_KEY_PATTERN.test(key)
        ? "[redacted]"
        : depth >= 2 && item && typeof item === "object"
          ? `${Object.keys(workflowUnknownRecord(item)).length} fields`
          : workflowRedactedReceiptPayload(item, depth + 1),
    ]),
  );
}

export function workflowHarnessReceiptKind(receiptRef: string): string {
  const receiptMarker = "receipt-";
  const markerIndex = receiptRef.indexOf(receiptMarker);
  if (markerIndex >= 0) {
    return receiptRef
      .slice(markerIndex + receiptMarker.length)
      .replace(/[_:.-]+/g, " ");
  }
  if (receiptRef.startsWith("workflow_restore_canary:")) {
    return "workflow restore canary";
  }
  const segments = receiptRef.split(":").filter(Boolean);
  return (segments[segments.length - 1] ?? receiptRef).replace(/[_:.-]+/g, " ");
}

function workflowProofString(
  proof: Record<string, unknown> | null | undefined,
  key: string,
  fallback: string,
): string {
  const value = proof?.[key];
  return typeof value === "string" ? value : fallback;
}

function workflowStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function workflowProofStringArray(
  proof: Record<string, unknown> | null | undefined,
  key: string,
  fallback: string[] = [],
): string[] {
  const value = proof?.[key];
  if (!Array.isArray(value)) return fallback;
  return workflowStringList(value);
}

function workflowOutputString(
  value: Record<string, unknown>,
  key: string,
): string | null {
  const item = value[key];
  return typeof item === "string" && item.length > 0 ? item : null;
}

function workflowOutputBoolean(
  value: Record<string, unknown>,
  key: string,
): boolean | null {
  const item = value[key];
  return typeof item === "boolean" ? item : null;
}

function workflowOutputRecord(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  return workflowUnknownRecord(value[key]);
}

function workflowPackageOutputKind(
  nodeType: string | null | undefined,
  output: Record<string, unknown>,
): WorkflowPackageNodeOutputSummary["kind"] | null {
  const toolName = workflowOutputString(output, "toolName");
  if (nodeType === "workflow_package_export" || toolName === "workflow.package.export") {
    return "export";
  }
  if (nodeType === "workflow_package_import" || toolName === "workflow.package.import") {
    return "import";
  }
  return null;
}

export function workflowPackageNodeOutputSummary(
  nodeType: string | null | undefined,
  outputValue: unknown,
): WorkflowPackageNodeOutputSummary | null {
  const output = workflowUnknownRecord(outputValue);
  const hasPackageOutput =
    workflowOutputString(output, "toolName") ||
    workflowOutputString(output, "schemaVersion")?.startsWith(
      "workflow.package-",
    ) ||
    output.workflowPackageExport !== undefined ||
    output.workflowPackageImport !== undefined ||
    output.workflowPackageImportReview !== undefined ||
    workflowOutputString(output, "packagePath");
  if (!hasPackageOutput) return null;
  const kind = workflowPackageOutputKind(nodeType, output);
  if (!kind) return null;

  const manifest = workflowOutputRecord(output, "manifest");
  const exportPackage = workflowOutputRecord(output, "workflowPackageExport");
  const exportPackageManifest = workflowOutputRecord(exportPackage, "manifest");
  const review =
    workflowOutputRecord(output, "workflowPackageImportReview").schemaVersion
      ? workflowOutputRecord(output, "workflowPackageImportReview")
      : workflowOutputRecord(output, "review");
  const reviewSource = workflowOutputRecord(review, "source");
  const reviewImported = workflowOutputRecord(review, "imported");
  const reviewEvidence = workflowOutputRecord(review, "evidence");
  const importPackage = workflowOutputRecord(output, "workflowPackageImport");

  const exportedManifest =
    Object.keys(manifest).length > 0 ? manifest : exportPackageManifest;
  const packageEvidenceReady =
    workflowOutputBoolean(output, "packageEvidenceReady") ??
    workflowOutputBoolean(reviewEvidence, "packageEvidenceReady") ??
    (exportedManifest.harnessPackageManifest !== undefined
      ? Boolean(exportedManifest.harnessPackageManifest)
      : null);
  const workflowChromeLocale =
    workflowOutputString(output, "workflowChromeLocale") ??
    workflowOutputString(exportedManifest, "workflowChromeLocale") ??
    workflowOutputString(reviewSource, "workflowChromeLocale") ??
    workflowOutputString(reviewImported, "workflowChromeLocale");
  const importedWorkflowChromeLocale =
    workflowOutputString(output, "importedWorkflowChromeLocale") ??
    workflowOutputString(reviewImported, "workflowChromeLocale");

  return {
    kind,
    status: workflowOutputString(output, "status") ?? "unknown",
    toolName:
      workflowOutputString(output, "toolName") ??
      (kind === "export" ? "workflow.package.export" : "workflow.package.import"),
    packagePath:
      workflowOutputString(output, "packagePath") ??
      workflowOutputString(exportPackage, "packagePath") ??
      workflowOutputString(importPackage, "packagePath") ??
      workflowOutputString(reviewSource, "packagePath"),
    manifestPath:
      workflowOutputString(output, "manifestPath") ??
      workflowOutputString(exportPackage, "manifestPath"),
    readinessStatus:
      workflowOutputString(output, "readinessStatus") ??
      workflowOutputString(exportedManifest, "readinessStatus") ??
      workflowOutputString(reviewSource, "readinessStatus"),
    portable:
      workflowOutputBoolean(output, "portable") ??
      workflowOutputBoolean(exportedManifest, "portable"),
    workflowChromeLocale,
    packageEvidenceReady,
    importedWorkflowPath:
      workflowOutputString(output, "importedWorkflowPath") ??
      workflowOutputString(reviewImported, "workflowPath") ??
      workflowOutputString(importPackage, "workflowPath"),
    workflowChromeLocalePreserved:
      workflowOutputBoolean(output, "workflowChromeLocalePreserved") ??
      workflowOutputBoolean(reviewEvidence, "workflowChromeLocalePreserved"),
    sourceWorkflowChromeLocale:
      workflowOutputString(output, "sourceWorkflowChromeLocale") ??
      workflowOutputString(reviewSource, "workflowChromeLocale"),
    importedWorkflowChromeLocale,
  };
}

export function workflowPackageNodeOutputStatus(
  summary: WorkflowPackageNodeOutputSummary,
): "ready" | "blocked" | "warning" {
  if (summary.status === "dry_run") {
    return "warning";
  }
  if (
    summary.status === "ok" ||
    summary.readinessStatus === "passed" ||
    summary.packageEvidenceReady === true
  ) {
    return "ready";
  }
  if (summary.status === "blocked" || summary.packageEvidenceReady === false) {
    return "blocked";
  }
  return "warning";
}

export function workflowGithubPrCreatePlanSummary(
  nodeType: string | null | undefined,
  outputValue: unknown,
): WorkflowGithubPrCreatePlanSummary | null {
  const output = workflowUnknownRecord(outputValue);
  const nestedPlan = workflowOutputRecord(output, "githubPrCreatePlan");
  const plan = Object.keys(nestedPlan).length > 0 ? nestedPlan : output;
  const hasPlan =
    nodeType === "github_pr_create" ||
    workflowOutputString(plan, "schemaVersion") ===
      "ioi.agent-runtime.github-pr-create-plan.v1" ||
    workflowOutputString(plan, "object") === "ioi.github_pr_create_plan" ||
    workflowOutputString(plan, "toolName") === "github__pr_create" ||
    output.githubPrCreatePlan !== undefined;
  if (!hasPlan || Object.keys(plan).length === 0) return null;

  const authority = workflowOutputRecord(plan, "authority");
  const request = workflowOutputRecord(plan, "request");

  return {
    status: workflowOutputString(plan, "status") ?? "unknown",
    decision: workflowOutputString(plan, "decision") ?? "unknown",
    toolName: workflowOutputString(plan, "toolName") ?? "github__pr_create",
    action: workflowOutputString(plan, "action") ?? "pr_create",
    planId: workflowOutputString(plan, "planId"),
    receiptId:
      workflowOutputString(output, "receiptId") ??
      workflowOutputString(plan, "receiptId"),
    dryRun: workflowOutputBoolean(plan, "dryRun"),
    previewOnly: workflowOutputBoolean(plan, "previewOnly"),
    mutationAttempted: workflowOutputBoolean(plan, "mutationAttempted"),
    mutationExecuted: workflowOutputBoolean(plan, "mutationExecuted"),
    networkLookupPerformed: workflowOutputBoolean(plan, "networkLookupPerformed"),
    requestMethod: workflowOutputString(request, "method"),
    requestPath: workflowOutputString(request, "path"),
    requestPayloadHash:
      workflowOutputString(request, "payloadHash") ??
      workflowOutputString(output, "requestPayloadHash"),
    requestBodyIncluded: workflowOutputBoolean(request, "bodyIncluded"),
    requestTokenIncluded: workflowOutputBoolean(request, "tokenIncluded"),
    repoFullName: workflowOutputString(plan, "repoFullName"),
    baseBranch: workflowOutputString(plan, "baseBranch"),
    headBranch: workflowOutputString(plan, "headBranch"),
    reviewGateStatus: workflowOutputString(plan, "reviewGateStatus"),
    reviewSatisfied: workflowOutputBoolean(plan, "reviewSatisfied"),
    requiredScopes: workflowStringList(authority.requiredScopes),
    missingScopes: workflowStringList(authority.missingScopes),
    scopeGranted: workflowOutputBoolean(authority, "scopeGranted"),
    blockers: workflowStringList(plan.blockers),
    evidenceRefs: workflowStringList(plan.evidenceRefs),
  };
}

export function workflowGithubPrCreatePlanStatus(
  summary: WorkflowGithubPrCreatePlanSummary,
): "ready" | "blocked" | "warning" {
  if (summary.status === "blocked" || summary.decision === "blocked") {
    return "blocked";
  }
  if (
    summary.status === "ok" ||
    summary.status === "passed" ||
    summary.decision === "allowed" ||
    summary.decision === "created"
  ) {
    return "ready";
  }
  if (
    summary.dryRun === true ||
    summary.missingScopes.length > 0 ||
    summary.reviewSatisfied === false ||
    summary.mutationExecuted === false
  ) {
    return "warning";
  }
  return "warning";
}

export interface WorkflowHarnessReceiptInspection {
  receiptRef: string;
  sourceKind: string;
  sourceLabel: string;
  status: string;
  producerComponent: string;
  receiptKind: string;
  policyDecision: string;
  attemptId: string;
  replayFixtureRef: string;
  nodeId: string | null;
  nodeLabel: string;
  runId: string;
  inputHash: string;
  outputHash: string;
  createdAtMs: number | null;
  evidenceRefs: string[];
  payloadPreview: WorkflowValuePreview;
}

export interface WorkflowHarnessReplayInspection {
  replayFixtureRef: string;
  sourceKind: string;
  sourceLabel: string;
  status: string;
  producerComponent: string;
  policyDecision: string;
  attemptId: string;
  receiptRef: string;
  nodeId: string | null;
  nodeLabel: string;
  runId: string;
  executionMode: string;
  readiness: string;
  inputHash: string;
  outputHash: string;
  deterministicEnvelope: boolean;
  capturesInput: boolean;
  capturesOutput: boolean;
  capturesPolicyDecision: boolean;
  determinism: WorkflowHarnessReplayDeterminism | string;
  redactionPolicy: string;
  nondeterminismReason: string;
  evidenceRefs: string[];
  payloadPreview: WorkflowValuePreview;
}

export interface WorkflowHarnessNodeAttemptInspection {
  attemptId: string;
  sourceKind: string;
  sourceLabel: string;
  status: string;
  producerComponent: string;
  componentKind: string;
  workflowNodeId: string | null;
  nodeLabel: string;
  runId: string;
  harnessWorkflowId: string;
  harnessActivationId: string;
  harnessHash: string;
  executionMode: string;
  readiness: string;
  policyDecision: string;
  attemptIndex: number | null;
  inputHash: string;
  outputHash: string;
  startedAtMs: number | null;
  durationMs: number | null;
  receiptRefs: string[];
  replayFixtureRef: string;
  replayDeterminism: WorkflowHarnessReplayDeterminism | string;
  replayRedactionPolicy: string;
  evidenceRefs: string[];
  shadowComparison?: WorkflowHarnessNodeAttemptComparisonInspection | null;
  mutationDiffHash?: string | null;
  rollbackTarget?: string | null;
  payloadPreview: WorkflowValuePreview;
}

export interface WorkflowHarnessNodeAttemptComparisonInspection {
  workflowNodeId: string;
  componentKind: string;
  liveAttemptId: string;
  shadowAttemptId: string;
  divergence: string;
  blocking: boolean;
  summary: string;
  evidenceRefs: string[];
  liveReceiptRefs: string[];
  shadowReceiptRefs: string[];
  liveReplayFixtureRef: string;
  shadowReplayFixtureRef: string;
  liveInputHash: string;
  shadowInputHash: string;
  liveOutputHash: string;
  shadowOutputHash: string;
}

export interface ResolveWorkflowHarnessReceiptInspectionOptions {
  receiptRef?: string | null;
  workflow: WorkflowProject;
  lastRunResult?: WorkflowRunResult | null;
  selectedRunId?: string | null;
  selectedHarnessGroup?: WorkflowHarnessGroupView | null;
  harnessActivationCandidate?: WorkflowHarnessForkActivationCandidate | null;
  readOnlyRoutingReady?: boolean;
  authorityToolingProof?: Record<string, unknown> | null;
}

export interface ResolveWorkflowHarnessReplayInspectionOptions {
  replayFixtureRef?: string | null;
  workflow: WorkflowProject;
  lastRunResult?: WorkflowRunResult | null;
  selectedRunId?: string | null;
  selectedHarnessGroup?: WorkflowHarnessGroupView | null;
  readOnlyRoutingReady?: boolean;
  authorityToolingProof?: Record<string, unknown> | null;
}

export interface ResolveWorkflowHarnessNodeAttemptInspectionOptions {
  nodeAttemptId?: string | null;
  workflow: WorkflowProject;
  lastRunResult?: WorkflowRunResult | null;
  selectedRunId?: string | null;
  selectedHarnessGroup?: WorkflowHarnessGroupView | null;
}

function workflowHarnessNodeAttemptInspectionFromAttempt(
  attempt: WorkflowHarnessNodeAttemptRecord,
  {
    workflow,
    runId,
    sourceKind,
    sourceLabel,
    shadowComparison = null,
  }: {
    workflow: WorkflowProject;
    runId: string;
    sourceKind: string;
    sourceLabel: string;
    shadowComparison?: WorkflowHarnessNodeAttemptComparisonInspection | null;
  },
): WorkflowHarnessNodeAttemptInspection {
  return {
    attemptId: attempt.attemptId,
    sourceKind,
    sourceLabel,
    status: attempt.status,
    producerComponent: attempt.componentId,
    componentKind: attempt.componentKind,
    workflowNodeId: attempt.workflowNodeId,
    nodeLabel: workflowNodeName(workflow, attempt.workflowNodeId),
    runId,
    harnessWorkflowId: attempt.harnessWorkflowId,
    harnessActivationId: attempt.harnessActivationId,
    harnessHash: attempt.harnessHash,
    executionMode: attempt.executionMode,
    readiness: attempt.readiness,
    policyDecision: attempt.policyDecision ?? "not recorded",
    attemptIndex: attempt.attemptIndex,
    inputHash: attempt.inputHash ?? "input hash pending",
    outputHash: attempt.outputHash ?? "output hash pending",
    startedAtMs: attempt.startedAtMs ?? null,
    durationMs: attempt.durationMs ?? null,
    receiptRefs: workflowUniqueReceiptRefs(attempt.receiptIds),
    replayFixtureRef: attempt.replay.fixtureRef ?? "not captured",
    replayDeterminism: attempt.replay.determinism,
    replayRedactionPolicy: attempt.replay.redactionPolicy,
    evidenceRefs: workflowUniqueReceiptRefs(attempt.evidenceRefs),
    shadowComparison,
    payloadPreview: workflowValuePreview(
      workflowRedactedReceiptPayload(attempt),
    ),
  };
}

function workflowHarnessNodeAttemptComparisonInspection(
  comparison: WorkflowHarnessShadowComparison,
  attempts: WorkflowHarnessNodeAttemptRecord[],
): WorkflowHarnessNodeAttemptComparisonInspection {
  const liveAttempt =
    attempts.find((attempt) => attempt.attemptId === comparison.liveAttemptId) ??
    null;
  const shadowAttempt =
    attempts.find((attempt) => attempt.attemptId === comparison.shadowAttemptId) ??
    null;
  return {
    workflowNodeId: comparison.workflowNodeId,
    componentKind: comparison.componentKind,
    liveAttemptId: comparison.liveAttemptId,
    shadowAttemptId: comparison.shadowAttemptId,
    divergence: comparison.divergence,
    blocking: comparison.blocking,
    summary: comparison.summary,
    evidenceRefs: workflowUniqueReceiptRefs(comparison.evidenceRefs),
    liveReceiptRefs: workflowUniqueReceiptRefs([
      ...(comparison.liveReceiptRefs ?? []),
      ...(liveAttempt?.receiptIds ?? []),
    ]),
    shadowReceiptRefs: workflowUniqueReceiptRefs([
      ...(comparison.shadowReceiptRefs ?? []),
      ...(shadowAttempt?.receiptIds ?? []),
    ]),
    liveReplayFixtureRef:
      comparison.liveReplayFixtureRef ??
      liveAttempt?.replay.fixtureRef ??
      "not captured",
    shadowReplayFixtureRef:
      comparison.shadowReplayFixtureRef ??
      shadowAttempt?.replay.fixtureRef ??
      "not captured",
    liveInputHash:
      comparison.liveInputHash ?? liveAttempt?.inputHash ?? "not captured",
    shadowInputHash:
      comparison.shadowInputHash ?? shadowAttempt?.inputHash ?? "not captured",
    liveOutputHash:
      comparison.liveOutputHash ?? liveAttempt?.outputHash ?? "not captured",
    shadowOutputHash:
      comparison.shadowOutputHash ??
      shadowAttempt?.outputHash ??
      "not captured",
  };
}

function workflowHarnessComparisonForAttempt(
  attemptId: string,
  comparisons: WorkflowHarnessShadowComparison[],
  attempts: WorkflowHarnessNodeAttemptRecord[],
): WorkflowHarnessNodeAttemptComparisonInspection | null {
  const comparison =
    comparisons.find(
      (candidate) =>
        candidate.liveAttemptId === attemptId ||
        candidate.shadowAttemptId === attemptId,
    ) ?? null;
  return comparison
    ? workflowHarnessNodeAttemptComparisonInspection(comparison, attempts)
    : null;
}

function workflowHarnessDefaultRuntimeNodeAttempts(
  workflow: WorkflowProject,
): WorkflowHarnessNodeAttemptRecord[] {
  const dispatch = workflow.metadata.harness?.defaultRuntimeDispatchProof;
  if (!dispatch) return [];
  const adapterAttempts = [
    ...(dispatch.cognitionExecutionAdapterResults ?? []),
    ...(dispatch.cognitionExecutionShadowAdapterResults ?? []),
    ...(dispatch.cognitionExecutionGateAdapterResults ?? []),
    ...(dispatch.routingModelAdapterResults ?? []),
    ...(dispatch.routingModelShadowAdapterResults ?? []),
    ...(dispatch.verificationOutputAdapterResults ?? []),
    ...(dispatch.verificationOutputShadowAdapterResults ?? []),
    ...(dispatch.authorityToolingAdapterResults ?? []),
    ...(dispatch.authorityToolingShadowAdapterResults ?? []),
  ].map((result) => result.nodeAttempt);
  const attempts = [
    ...(dispatch.dispatchNodeAttempts ?? []),
    ...adapterAttempts,
  ].filter(
    (attempt): attempt is WorkflowHarnessNodeAttemptRecord =>
      Boolean(attempt),
  );
  const seen = new Set<string>();
  return attempts.filter((attempt) => {
    if (seen.has(attempt.attemptId)) return false;
    seen.add(attempt.attemptId);
    return true;
  });
}

export function resolveWorkflowHarnessNodeAttemptInspection({
  nodeAttemptId,
  workflow,
  lastRunResult = null,
  selectedRunId = null,
  selectedHarnessGroup = null,
}: ResolveWorkflowHarnessNodeAttemptInspectionOptions): WorkflowHarnessNodeAttemptInspection | null {
  if (!nodeAttemptId) return null;

  const runId = selectedRunId ?? lastRunResult?.summary.id ?? "run pending";
  const directAttempt =
    (lastRunResult?.harnessAttempts ?? []).find(
      (attempt) => attempt.attemptId === nodeAttemptId,
    ) ??
    (lastRunResult?.nodeRuns ?? [])
      .map((nodeRun) => nodeRun.harnessAttempt ?? null)
      .find((attempt) => attempt?.attemptId === nodeAttemptId) ??
    null;
  if (directAttempt) {
    const directAttempts = [
      ...(lastRunResult?.harnessAttempts ?? []),
      ...(lastRunResult?.nodeRuns ?? [])
        .map((nodeRun) => nodeRun.harnessAttempt ?? null)
        .filter((attempt): attempt is WorkflowHarnessNodeAttemptRecord =>
          Boolean(attempt),
        ),
    ];
    return workflowHarnessNodeAttemptInspectionFromAttempt(directAttempt, {
      workflow,
      runId,
      sourceKind: "node_attempt",
      sourceLabel: "Workflow node attempt",
      shadowComparison: workflowHarnessComparisonForAttempt(
        directAttempt.attemptId,
        lastRunResult?.harnessShadowComparisons ?? [],
        directAttempts,
      ),
    });
  }

  const defaultRuntimeDispatch =
    workflow.metadata.harness?.defaultRuntimeDispatchProof ?? null;
  const defaultRuntimeAttempts =
    workflowHarnessDefaultRuntimeNodeAttempts(workflow);
  const defaultRuntimeAttempt =
    defaultRuntimeAttempts.find(
      (attempt) => attempt.attemptId === nodeAttemptId,
    ) ?? null;
  if (defaultRuntimeAttempt) {
    return workflowHarnessNodeAttemptInspectionFromAttempt(
      defaultRuntimeAttempt,
      {
        workflow,
        runId: selectedRunId ?? defaultRuntimeDispatch?.dispatchId ?? runId,
        sourceKind: "default_runtime_dispatch",
        sourceLabel: "Default runtime dispatch node attempt",
        shadowComparison: workflowHarnessComparisonForAttempt(
          defaultRuntimeAttempt.attemptId,
          defaultRuntimeDispatch?.liveShadowComparisons ?? [],
          defaultRuntimeAttempts,
        ),
      },
    );
  }

  const harnessActivationRecord = workflow.metadata.harness?.activationRecord;
  const activationWorkerHandoffAttempts =
    harnessActivationRecord?.workerHandoffNodeAttempts ??
    workflow.metadata.harness?.workerHandoffNodeAttempts ??
    [];
  const activationWorkerHandoffAttempt =
    activationWorkerHandoffAttempts.find(
      (attempt) => attempt.attemptId === nodeAttemptId,
    ) ?? null;
  if (activationWorkerHandoffAttempt) {
    return workflowHarnessNodeAttemptInspectionFromAttempt(
      activationWorkerHandoffAttempt,
      {
        workflow,
        runId,
        sourceKind: "worker_handoff",
        sourceLabel: "Worker handoff node attempt",
      },
    );
  }

  const forkMutationCanary =
    harnessActivationRecord?.forkMutationCanary ??
    workflow.metadata.harness?.forkMutationCanary ??
    null;
  const forkMutationCanaryAttempts =
    workflowHarnessForkMutationCanaryNodeAttempts(forkMutationCanary);
  const forkMutationCanaryAttempt =
    forkMutationCanaryAttempts.find(
      (attempt) => attempt.attemptId === nodeAttemptId,
    ) ?? null;
  if (forkMutationCanary && forkMutationCanaryAttempt) {
    return {
      ...workflowHarnessNodeAttemptInspectionFromAttempt(
        forkMutationCanaryAttempt,
        {
          workflow,
          runId: forkMutationCanary.canaryId,
          sourceKind: "fork_mutation_canary",
          sourceLabel: "Fork mutation canary node attempt",
        },
      ),
      mutationDiffHash: forkMutationCanary.diffHash,
      rollbackTarget: forkMutationCanary.rollbackTarget,
    };
  }

  const selectedHarnessGroupGatedRun = selectedHarnessGroup
    ? (lastRunResult?.harnessGatedClusterRuns ?? []).find(
        (run) => String(run.clusterId) === String(selectedHarnessGroup.groupId),
      ) ?? null
    : null;
  const gatedRun =
    selectedHarnessGroupGatedRun ??
    (lastRunResult?.harnessGatedClusterRuns ?? []).find((run) =>
      run.nodeAttemptIds.includes(nodeAttemptId),
    ) ??
    null;
  if (gatedRun) {
    const attemptIndex = gatedRun.nodeAttemptIds.indexOf(nodeAttemptId);
    const componentKind =
      gatedRun.componentKinds[attemptIndex] ??
      gatedRun.componentKinds[0] ??
      "gated_cluster";
    return {
      attemptId: nodeAttemptId,
      sourceKind: "gated_cluster",
      sourceLabel: `${gatedRun.clusterLabel} node attempt`,
      status: gatedRun.status,
      producerComponent: componentKind,
      componentKind,
      workflowNodeId: null,
      nodeLabel: gatedRun.clusterId,
      runId: gatedRun.runId,
      harnessWorkflowId: gatedRun.harnessWorkflowId,
      harnessActivationId: gatedRun.harnessActivationId,
      harnessHash: gatedRun.harnessHash,
      executionMode: gatedRun.executionMode,
      readiness: gatedRun.promotionBlocked ? "blocked" : "live_ready",
      policyDecision: gatedRun.gateDecision,
      attemptIndex,
      inputHash: "cluster input hash pending",
      outputHash: "cluster output hash pending",
      startedAtMs: null,
      durationMs: null,
      receiptRefs: workflowUniqueReceiptRefs([
        gatedRun.receiptIds[attemptIndex],
      ]),
      replayFixtureRef:
        gatedRun.replayFixtureRefs[attemptIndex] ?? "not captured",
      replayDeterminism: "redacted",
      replayRedactionPolicy: "gated_cluster_fixture_redacted",
      evidenceRefs: workflowUniqueReceiptRefs(gatedRun.evidenceRefs),
      payloadPreview: workflowValuePreview(
        workflowRedactedReceiptPayload(gatedRun),
      ),
    };
  }

  return {
    attemptId: nodeAttemptId,
    sourceKind: "unresolved",
    sourceLabel: "Unresolved node attempt",
    status: "unresolved",
    producerComponent: "unknown",
    componentKind: "unknown",
    workflowNodeId: null,
    nodeLabel: "not resolved",
    runId,
    harnessWorkflowId: workflow.metadata.id,
    harnessActivationId:
      workflow.metadata.harness?.activationId ?? "activation pending",
    harnessHash: workflow.metadata.harness?.harnessHash ?? "hash pending",
    executionMode: "unknown",
    readiness: "unknown",
    policyDecision: "node attempt id pinned without a matching local record",
    attemptIndex: null,
    inputHash: "not resolved",
    outputHash: "not resolved",
    startedAtMs: null,
    durationMs: null,
    receiptRefs: [],
    replayFixtureRef: "not resolved",
    replayDeterminism: "disabled",
    replayRedactionPolicy: "not resolved",
    evidenceRefs: [nodeAttemptId],
    payloadPreview: workflowValuePreview({
      nodeAttemptId,
      status: "unresolved",
    }),
  };
}

export function resolveWorkflowHarnessReceiptInspection({
  receiptRef,
  workflow,
  lastRunResult = null,
  selectedRunId = null,
  selectedHarnessGroup = null,
  harnessActivationCandidate = null,
  readOnlyRoutingReady = false,
  authorityToolingProof = null,
}: ResolveWorkflowHarnessReceiptInspectionOptions): WorkflowHarnessReceiptInspection | null {
  if (!receiptRef) return null;

  const harnessActivationRecord = workflow.metadata.harness?.activationRecord;
  const harnessActivationAudit = workflow.metadata.harness?.activationAudit ?? [];
  const harnessActivationRollbackProof =
    workflow.metadata.harness?.activationRollbackProof ?? null;
  const harnessActivationRollbackExecution =
    workflow.metadata.harness?.activationRollbackExecution ?? null;
  const harnessDefaultRuntimeDispatchProof =
    workflow.metadata.harness?.defaultRuntimeDispatchProof;
  const activationWorkerHandoffReceipts =
    harnessActivationRecord?.workerHandoffReceipts ??
    workflow.metadata.harness?.workerHandoffReceipts ??
    [];
  const activationWorkerHandoffAttempts =
    harnessActivationRecord?.workerHandoffNodeAttempts ??
    workflow.metadata.harness?.workerHandoffNodeAttempts ??
    [];
  const forkMutationCanary =
    harnessActivationRecord?.forkMutationCanary ??
    workflow.metadata.harness?.forkMutationCanary ??
    harnessActivationCandidate?.forkMutationCanary ??
    null;
  const forkMutationCanaryAttempts =
    workflowHarnessForkMutationCanaryNodeAttempts(forkMutationCanary);
  const selectedHarnessGroupGatedRun = selectedHarnessGroup
    ? (lastRunResult?.harnessGatedClusterRuns ?? []).find(
        (run) => String(run.clusterId) === String(selectedHarnessGroup.groupId),
      ) ?? null
    : null;

  const makeHarnessReceiptInspection = (
    details: Omit<
      WorkflowHarnessReceiptInspection,
      "receiptKind" | "payloadPreview" | "receiptRef"
    > & {
      payload: unknown;
      receiptRef?: string;
    },
  ): WorkflowHarnessReceiptInspection => ({
    receiptRef: details.receiptRef ?? receiptRef,
    sourceKind: details.sourceKind,
    sourceLabel: details.sourceLabel,
    status: details.status,
    producerComponent: details.producerComponent,
    receiptKind: workflowHarnessReceiptKind(details.receiptRef ?? receiptRef),
    policyDecision: details.policyDecision,
    attemptId: details.attemptId,
    replayFixtureRef: details.replayFixtureRef,
    nodeId: details.nodeId,
    nodeLabel: details.nodeLabel,
    runId: details.runId,
    inputHash: details.inputHash,
    outputHash: details.outputHash,
    createdAtMs: details.createdAtMs,
    evidenceRefs: workflowUniqueReceiptRefs(details.evidenceRefs),
    payloadPreview: workflowValuePreview(
      workflowRedactedReceiptPayload(details.payload),
    ),
  });

  const receiptAttempt =
    (lastRunResult?.harnessAttempts ?? []).find((attempt) =>
      attempt.receiptIds.includes(receiptRef),
    ) ??
    (lastRunResult?.nodeRuns ?? [])
      .map((nodeRun) => nodeRun.harnessAttempt ?? null)
      .find((attempt) => attempt?.receiptIds.includes(receiptRef)) ??
    null;
  if (receiptAttempt) {
    return makeHarnessReceiptInspection({
      receiptRef,
      sourceKind: "node_attempt",
      sourceLabel: "Node attempt receipt",
      status: receiptAttempt.status,
      producerComponent: receiptAttempt.componentId,
      policyDecision: receiptAttempt.policyDecision ?? "not recorded",
      attemptId: receiptAttempt.attemptId,
      replayFixtureRef: receiptAttempt.replay.fixtureRef ?? "not captured",
      nodeId: receiptAttempt.workflowNodeId,
      nodeLabel: workflowNodeName(workflow, receiptAttempt.workflowNodeId),
      runId: selectedRunId ?? lastRunResult?.summary.id ?? "run pending",
      inputHash: receiptAttempt.inputHash ?? "input hash pending",
      outputHash: receiptAttempt.outputHash ?? "output hash pending",
      createdAtMs: receiptAttempt.startedAtMs ?? null,
      evidenceRefs: receiptAttempt.evidenceRefs,
      payload: receiptAttempt,
    });
  }

  const gatedRun = (lastRunResult?.harnessGatedClusterRuns ?? []).find(
    (run) => run.receiptIds.includes(receiptRef),
  );
  if (gatedRun) {
    const receiptIndex = gatedRun.receiptIds.indexOf(receiptRef);
    return makeHarnessReceiptInspection({
      receiptRef,
      sourceKind: "gated_cluster",
      sourceLabel: `${gatedRun.clusterLabel} gated receipt`,
      status: gatedRun.status,
      producerComponent: gatedRun.componentKinds.join(", "),
      policyDecision: gatedRun.gateDecision,
      attemptId: gatedRun.nodeAttemptIds[receiptIndex] ?? "attempt pending",
      replayFixtureRef:
        gatedRun.replayFixtureRefs[receiptIndex] ?? "replay fixture pending",
      nodeId: null,
      nodeLabel: gatedRun.clusterId,
      runId: gatedRun.runId,
      inputHash: "cluster input hash pending",
      outputHash: "cluster output hash pending",
      createdAtMs: null,
      evidenceRefs: gatedRun.evidenceRefs,
      payload: gatedRun,
    });
  }

  if (forkMutationCanary?.receiptRefs.includes(receiptRef)) {
    const receiptIndex = forkMutationCanary.receiptRefs.indexOf(receiptRef);
    const attempt =
      forkMutationCanaryAttempts[receiptIndex] ??
      forkMutationCanaryAttempts[0] ??
      null;
    return makeHarnessReceiptInspection({
      receiptRef,
      sourceKind: "fork_mutation_canary",
      sourceLabel: "Fork mutation canary receipt",
      status: forkMutationCanary.status,
      producerComponent: forkMutationCanary.componentId,
      policyDecision: forkMutationCanary.policyDecision,
      attemptId:
        attempt?.attemptId ??
        forkMutationCanary.nodeAttemptIds[receiptIndex] ??
        "attempt pending",
      replayFixtureRef:
        attempt?.replay.fixtureRef ??
        forkMutationCanary.replayFixtureRefs[receiptIndex] ??
        "replay fixture pending",
      nodeId: forkMutationCanary.workflowNodeId,
      nodeLabel: workflowNodeName(workflow, forkMutationCanary.workflowNodeId),
      runId: forkMutationCanary.canaryId,
      inputHash: attempt?.inputHash ?? "mutation input hash pending",
      outputHash: attempt?.outputHash ?? forkMutationCanary.diffHash,
      createdAtMs: forkMutationCanary.createdAtMs,
      evidenceRefs: forkMutationCanary.evidenceRefs,
      payload: forkMutationCanary,
    });
  }

  const auditEvent = harnessActivationAudit.find((event) =>
    event.receiptRefs.includes(receiptRef),
  );
  if (auditEvent) {
    return makeHarnessReceiptInspection({
      receiptRef,
      sourceKind: "activation_audit",
      sourceLabel: `${auditEvent.eventType} audit receipt`,
      status: auditEvent.status,
      producerComponent: "harness_activation_audit",
      policyDecision: auditEvent.summary,
      attemptId: auditEvent.eventId,
      replayFixtureRef: "audit event is durable evidence",
      nodeId: null,
      nodeLabel: auditEvent.workflowId,
      runId: selectedRunId ?? auditEvent.workflowId,
      inputHash: auditEvent.candidateId ?? "candidate pending",
      outputHash:
        auditEvent.nextActivationId ??
        auditEvent.activationId ??
        "activation pending",
      createdAtMs: auditEvent.createdAtMs,
      evidenceRefs: auditEvent.evidenceRefs,
      payload: auditEvent,
    });
  }

  if (harnessActivationRollbackExecution) {
    const executionReceiptRefs = workflowUniqueReceiptRefs([
      harnessActivationRollbackExecution.restoreReceiptBindingRef,
      ...harnessActivationRollbackExecution.receiptRefs,
    ]);
    if (executionReceiptRefs.includes(receiptRef)) {
      return makeHarnessReceiptInspection({
        receiptRef,
        sourceKind: "rollback_execution",
        sourceLabel: "Rollback execution receipt",
        status: harnessActivationRollbackExecution.executionStatus,
        producerComponent: "harness_rollback_execution",
        policyDecision: harnessActivationRollbackExecution.policyDecision,
        attemptId: harnessActivationRollbackExecution.executionId,
        replayFixtureRef:
          harnessActivationRollbackExecution.restoreReceiptBindingRef ??
          "restore receipt pending",
        nodeId: null,
        nodeLabel: harnessActivationRollbackExecution.workflowPath,
        runId:
          harnessActivationRollbackExecution.activationId ??
          selectedRunId ??
          "activation pending",
        inputHash:
          harnessActivationRollbackExecution.expectedWorkflowContentHash ??
          "expected hash pending",
        outputHash:
          harnessActivationRollbackExecution.actualWorkflowContentHash ??
          "actual hash pending",
        createdAtMs: harnessActivationRollbackExecution.createdAtMs,
        evidenceRefs: harnessActivationRollbackExecution.evidenceRefs,
        payload: harnessActivationRollbackExecution,
      });
    }
  }

  if (harnessActivationRollbackProof?.receiptRefs.includes(receiptRef)) {
    return makeHarnessReceiptInspection({
      receiptRef,
      sourceKind: "rollback_drill",
      sourceLabel: "Rollback drill receipt",
      status: harnessActivationRollbackProof.drillStatus,
      producerComponent: "harness_rollback_drill",
      policyDecision: harnessActivationRollbackProof.policyDecision,
      attemptId: harnessActivationRollbackProof.drillId,
      replayFixtureRef: "rollback drill proof",
      nodeId: null,
      nodeLabel: harnessActivationRollbackProof.workflowId,
      runId:
        harnessActivationRollbackProof.activationId ??
        selectedRunId ??
        "activation pending",
      inputHash: harnessActivationRollbackProof.rollbackTarget,
      outputHash:
        harnessActivationRollbackProof.restoredWorkerBinding?.harnessHash ??
        "restored hash pending",
      createdAtMs: harnessActivationRollbackProof.createdAtMs,
      evidenceRefs: harnessActivationRollbackProof.evidenceRefs,
      payload: harnessActivationRollbackProof,
    });
  }

  const rollbackCanary =
    harnessActivationCandidate?.rollbackRestoreCanary ??
    harnessActivationRecord?.rollbackRestoreCanary ??
    null;
  if (
    rollbackCanary &&
    (rollbackCanary.receiptBindingRef === receiptRef ||
      rollbackCanary.evidenceRefs.includes(receiptRef))
  ) {
    return makeHarnessReceiptInspection({
      receiptRef,
      sourceKind: "rollback_restore_canary",
      sourceLabel: "Rollback restore canary receipt",
      status: rollbackCanary.status,
      producerComponent: "harness_restore_canary",
      policyDecision: rollbackCanary.hashVerified
        ? "hash_verified"
        : "hash_pending_or_blocked",
      attemptId: rollbackCanary.canaryId,
      replayFixtureRef:
        rollbackCanary.receiptBindingRef ?? "receipt binding pending",
      nodeId: null,
      nodeLabel: rollbackCanary.workflowPath,
      runId: selectedRunId ?? rollbackCanary.canaryId,
      inputHash:
        rollbackCanary.expectedWorkflowContentHash ?? "expected hash pending",
      outputHash: rollbackCanary.actualWorkflowContentHash ?? "actual hash pending",
      createdAtMs: rollbackCanary.createdAtMs,
      evidenceRefs: rollbackCanary.evidenceRefs,
      payload: rollbackCanary,
    });
  }

  const activationWorkerHandoffReceipt =
    activationWorkerHandoffReceipts.find(
      (receipt) =>
        receipt.receiptId === receiptRef ||
        receipt.envelopeId === receiptRef ||
        receipt.receiptRefs.includes(receiptRef),
    ) ?? null;
  if (activationWorkerHandoffReceipt) {
    const activationWorkerHandoffAttempt =
      activationWorkerHandoffAttempts.find((attempt) =>
        attempt.receiptIds.includes(receiptRef),
      ) ??
      activationWorkerHandoffAttempts.find((attempt) =>
        attempt.receiptIds.includes(activationWorkerHandoffReceipt.receiptId),
      ) ??
      null;
    return makeHarnessReceiptInspection({
      receiptRef,
      sourceKind: "activation_worker_handoff",
      sourceLabel: `${activationWorkerHandoffReceipt.phase} worker handoff receipt`,
      status: activationWorkerHandoffReceipt.handoffStatus,
      producerComponent: "handoff_bridge",
      policyDecision: activationWorkerHandoffReceipt.policyDecision,
      attemptId:
        activationWorkerHandoffAttempt?.attemptId ??
        `handoff:${activationWorkerHandoffReceipt.phase}`,
      replayFixtureRef:
        activationWorkerHandoffAttempt?.replay.fixtureRef ??
        "worker handoff replay pending",
      nodeId: activationWorkerHandoffReceipt.workflowNodeId,
      nodeLabel: workflowNodeName(
        workflow,
        activationWorkerHandoffReceipt.workflowNodeId,
      ),
      runId:
        activationWorkerHandoffReceipt.activationId ??
        selectedRunId ??
        activationWorkerHandoffReceipt.sessionRecordId,
      inputHash:
        activationWorkerHandoffAttempt?.inputHash ??
        activationWorkerHandoffReceipt.sessionRecordId,
      outputHash:
        activationWorkerHandoffAttempt?.outputHash ??
        activationWorkerHandoffReceipt.handoffStatus,
      createdAtMs: activationWorkerHandoffReceipt.createdAtMs ?? null,
      evidenceRefs: activationWorkerHandoffReceipt.evidenceRefs,
      payload: activationWorkerHandoffReceipt,
    });
  }

  const dispatchReceiptGroups = harnessDefaultRuntimeDispatchProof
    ? [
        {
          sourceLabel: "Cognition execution receipt",
          producerComponent: "cognition",
          receipts: harnessDefaultRuntimeDispatchProof.cognitionExecutionReceiptIds,
          attempts: harnessDefaultRuntimeDispatchProof.cognitionExecutionAttemptIds,
          replay: harnessDefaultRuntimeDispatchProof.cognitionExecutionReplayFixtureRefs,
          policyDecision: workflowProofString(
            workflowUnknownRecord(
              harnessDefaultRuntimeDispatchProof.cognitionExecutionProof,
            ),
            "policyDecision",
            "accept_workflow_prompt_assembly_hash_envelope",
          ),
        },
        {
          sourceLabel: "Model execution receipt",
          producerComponent: "routing_model",
          receipts: harnessDefaultRuntimeDispatchProof.modelExecutionReceiptIds,
          attempts: harnessDefaultRuntimeDispatchProof.modelExecutionAttemptIds,
          replay: harnessDefaultRuntimeDispatchProof.modelExecutionReplayFixtureRefs,
          policyDecision: "accept_workflow_model_execution_envelope",
        },
        {
          sourceLabel: "Read-only routing receipt",
          producerComponent: "read_only_capability_routing",
          receipts:
            harnessDefaultRuntimeDispatchProof.readOnlyCapabilityRoutingReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.readOnlyCapabilityRoutingAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.readOnlyCapabilityRoutingReplayFixtureRefs,
          policyDecision: readOnlyRoutingReady
            ? "read_only_route_no_mutation"
            : "read_only_route_pending",
        },
        {
          sourceLabel: "Authority tooling receipt",
          producerComponent: "authority_tooling",
          receipts:
            harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveReplayFixtureRefs,
          policyDecision: workflowProofString(
            authorityToolingProof,
            "policyDecision",
            "allow_read_only_route_through_workflow_authority",
          ),
        },
        {
          sourceLabel: "Worker launch handoff receipt",
          producerComponent: "handoff_bridge",
          receipts: harnessDefaultRuntimeDispatchProof.workerHandoffReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.workerHandoffNodeAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.workerHandoffReplayFixtureRefs,
          policyDecision: "allow_harness_worker_handoff",
        },
      ]
    : [];
  const dispatchReceiptGroup = dispatchReceiptGroups.find((group) =>
    workflowStringList(group.receipts).includes(receiptRef),
  );
  if (dispatchReceiptGroup && harnessDefaultRuntimeDispatchProof) {
    const dispatchReceiptRefs = workflowStringList(dispatchReceiptGroup.receipts);
    const dispatchAttemptRefs = workflowStringList(dispatchReceiptGroup.attempts);
    const dispatchReplayRefs = workflowStringList(dispatchReceiptGroup.replay);
    const receiptIndex = dispatchReceiptRefs.indexOf(receiptRef);
    return makeHarnessReceiptInspection({
      receiptRef,
      sourceKind: "default_runtime_dispatch",
      sourceLabel: dispatchReceiptGroup.sourceLabel,
      status: harnessDefaultRuntimeDispatchProof.executionMode,
      producerComponent: dispatchReceiptGroup.producerComponent,
      policyDecision: dispatchReceiptGroup.policyDecision,
      attemptId: dispatchAttemptRefs[receiptIndex] ?? "attempt pending",
      replayFixtureRef:
        dispatchReplayRefs[receiptIndex] ?? "replay fixture pending",
      nodeId: null,
      nodeLabel: harnessDefaultRuntimeDispatchProof.workflowId,
      runId: harnessDefaultRuntimeDispatchProof.dispatchId,
      inputHash:
        harnessDefaultRuntimeDispatchProof.promptAssemblyPromptHash ??
        "input hash pending",
      outputHash:
        harnessDefaultRuntimeDispatchProof.modelExecutionOutputHash ??
        "output hash pending",
      createdAtMs: null,
      evidenceRefs: harnessDefaultRuntimeDispatchProof.receiptIds,
      payload: harnessDefaultRuntimeDispatchProof,
    });
  }

  if (selectedHarnessGroup?.deepLinks.receiptRefs.includes(receiptRef)) {
    return makeHarnessReceiptInspection({
      receiptRef,
      sourceKind: "harness_group",
      sourceLabel: `${selectedHarnessGroup.label} group receipt`,
      status: selectedHarnessGroup.statusRollup.executionMode,
      producerComponent: selectedHarnessGroup.componentKinds.join(", "),
      policyDecision:
        selectedHarnessGroupGatedRun?.gateDecision ?? "group receipt selected",
      attemptId: selectedHarnessGroupGatedRun?.nodeAttemptIds[0] ?? "attempt pending",
      replayFixtureRef:
        selectedHarnessGroup.deepLinks.replayFixtureRefs[0] ??
        "replay fixture pending",
      nodeId: null,
      nodeLabel: String(selectedHarnessGroup.groupId),
      runId:
        selectedHarnessGroup.deepLinks.runId ?? selectedRunId ?? "run pending",
      inputHash: "group input hash pending",
      outputHash: "group output hash pending",
      createdAtMs: null,
      evidenceRefs: selectedHarnessGroup.deepLinks.receiptRefs,
      payload: selectedHarnessGroup,
    });
  }

  return makeHarnessReceiptInspection({
    receiptRef,
    sourceKind: "unresolved",
    sourceLabel: "Unresolved harness receipt",
    status: "unresolved",
    producerComponent: "unknown",
    policyDecision: "receipt ref pinned without a matching local record",
    attemptId: "not resolved",
    replayFixtureRef: "not resolved",
    nodeId: null,
    nodeLabel: "not resolved",
    runId: selectedRunId ?? "run pending",
    inputHash: "not resolved",
    outputHash: "not resolved",
    createdAtMs: null,
    evidenceRefs: [receiptRef],
    payload: { receiptRef, status: "unresolved" },
  });
}

export function resolveWorkflowHarnessReplayInspection({
  replayFixtureRef,
  workflow,
  lastRunResult = null,
  selectedRunId = null,
  selectedHarnessGroup = null,
  readOnlyRoutingReady = false,
  authorityToolingProof = null,
}: ResolveWorkflowHarnessReplayInspectionOptions): WorkflowHarnessReplayInspection | null {
  if (!replayFixtureRef) return null;

  const harnessActivationRecord = workflow.metadata.harness?.activationRecord;
  const harnessDefaultRuntimeDispatchProof =
    workflow.metadata.harness?.defaultRuntimeDispatchProof;
  const activationWorkerHandoffReceipts =
    harnessActivationRecord?.workerHandoffReceipts ??
    workflow.metadata.harness?.workerHandoffReceipts ??
    [];
  const activationWorkerHandoffAttempts =
    harnessActivationRecord?.workerHandoffNodeAttempts ??
    workflow.metadata.harness?.workerHandoffNodeAttempts ??
    [];
  const forkMutationCanary =
    harnessActivationRecord?.forkMutationCanary ??
    workflow.metadata.harness?.forkMutationCanary ??
    null;
  const forkMutationCanaryAttempts =
    workflowHarnessForkMutationCanaryNodeAttempts(forkMutationCanary);
  const selectedHarnessGroupGatedRun = selectedHarnessGroup
    ? (lastRunResult?.harnessGatedClusterRuns ?? []).find(
        (run) => String(run.clusterId) === String(selectedHarnessGroup.groupId),
      ) ?? null
    : null;

  const makeHarnessReplayInspection = (
    details: Omit<
      WorkflowHarnessReplayInspection,
      "payloadPreview" | "replayFixtureRef"
    > & {
      payload: unknown;
      replayFixtureRef?: string;
    },
  ): WorkflowHarnessReplayInspection => ({
    replayFixtureRef: details.replayFixtureRef ?? replayFixtureRef,
    sourceKind: details.sourceKind,
    sourceLabel: details.sourceLabel,
    status: details.status,
    producerComponent: details.producerComponent,
    policyDecision: details.policyDecision,
    attemptId: details.attemptId,
    receiptRef: details.receiptRef,
    nodeId: details.nodeId,
    nodeLabel: details.nodeLabel,
    runId: details.runId,
    executionMode: details.executionMode,
    readiness: details.readiness,
    inputHash: details.inputHash,
    outputHash: details.outputHash,
    deterministicEnvelope: details.deterministicEnvelope,
    capturesInput: details.capturesInput,
    capturesOutput: details.capturesOutput,
    capturesPolicyDecision: details.capturesPolicyDecision,
    determinism: details.determinism,
    redactionPolicy: details.redactionPolicy,
    nondeterminismReason: details.nondeterminismReason,
    evidenceRefs: workflowUniqueReplayFixtureRefs(details.evidenceRefs),
    payloadPreview: workflowValuePreview(
      workflowRedactedReceiptPayload(details.payload),
    ),
  });

  const makeReplayEnvelopeDetails = (
    replay: WorkflowHarnessReplayEnvelope | null | undefined,
  ) => ({
    deterministicEnvelope: replay?.deterministicEnvelope ?? false,
    capturesInput: replay?.capturesInput ?? false,
    capturesOutput: replay?.capturesOutput ?? false,
    capturesPolicyDecision: replay?.capturesPolicyDecision ?? false,
    determinism: replay?.determinism ?? "disabled",
    redactionPolicy: replay?.redactionPolicy ?? "not recorded",
    nondeterminismReason: replay?.nondeterminismReason ?? "none",
  });

  const replayAttempt =
    (lastRunResult?.harnessAttempts ?? []).find(
      (attempt) => attempt.replay.fixtureRef === replayFixtureRef,
    ) ??
    (lastRunResult?.nodeRuns ?? [])
      .map((nodeRun) => nodeRun.harnessAttempt ?? null)
      .find((attempt) => attempt?.replay.fixtureRef === replayFixtureRef) ??
    null;
  if (replayAttempt) {
    return makeHarnessReplayInspection({
      replayFixtureRef,
      sourceKind: "node_attempt",
      sourceLabel: "Node attempt replay fixture",
      status: replayAttempt.status,
      producerComponent: replayAttempt.componentId,
      policyDecision: replayAttempt.policyDecision ?? "not recorded",
      attemptId: replayAttempt.attemptId,
      receiptRef: replayAttempt.receiptIds[0] ?? "receipt pending",
      nodeId: replayAttempt.workflowNodeId,
      nodeLabel: workflowNodeName(workflow, replayAttempt.workflowNodeId),
      runId: selectedRunId ?? lastRunResult?.summary.id ?? "run pending",
      executionMode: replayAttempt.executionMode,
      readiness: replayAttempt.readiness,
      inputHash: replayAttempt.inputHash ?? "input hash pending",
      outputHash: replayAttempt.outputHash ?? "output hash pending",
      ...makeReplayEnvelopeDetails(replayAttempt.replay),
      evidenceRefs: replayAttempt.evidenceRefs,
      payload: replayAttempt,
    });
  }

  const gatedRun = (lastRunResult?.harnessGatedClusterRuns ?? []).find(
    (run) => run.replayFixtureRefs.includes(replayFixtureRef),
  );
  if (gatedRun) {
    const replayIndex = gatedRun.replayFixtureRefs.indexOf(replayFixtureRef);
    return makeHarnessReplayInspection({
      replayFixtureRef,
      sourceKind: "gated_cluster",
      sourceLabel: `${gatedRun.clusterLabel} gated replay fixture`,
      status: gatedRun.status,
      producerComponent: gatedRun.componentKinds.join(", "),
      policyDecision: gatedRun.gateDecision,
      attemptId: gatedRun.nodeAttemptIds[replayIndex] ?? "attempt pending",
      receiptRef: gatedRun.receiptIds[replayIndex] ?? "receipt pending",
      nodeId: null,
      nodeLabel: gatedRun.clusterId,
      runId: gatedRun.runId,
      executionMode: gatedRun.executionMode,
      readiness: gatedRun.promotionBlocked ? "blocked" : "live_ready",
      inputHash: "cluster input hash pending",
      outputHash: "cluster output hash pending",
      deterministicEnvelope: true,
      capturesInput: true,
      capturesOutput: true,
      capturesPolicyDecision: true,
      determinism: "redacted",
      redactionPolicy: "gated_cluster_fixture_redacted",
      nondeterminismReason: "gated cluster proof stores refs, not fixture payloads",
      evidenceRefs: gatedRun.evidenceRefs,
      payload: gatedRun,
    });
  }

  const runtimeBindingNode = workflow.nodes.find(
    (node) => node.runtimeBinding?.replayEnvelope?.fixtureRef === replayFixtureRef,
  );
  if (runtimeBindingNode?.runtimeBinding) {
    return makeHarnessReplayInspection({
      replayFixtureRef,
      sourceKind: "runtime_binding",
      sourceLabel: "Component replay binding",
      status: runtimeBindingNode.runtimeBinding.executionMode,
      producerComponent: runtimeBindingNode.runtimeBinding.componentId,
      policyDecision: "component replay fixture bound",
      attemptId: "not attempted",
      receiptRef:
        runtimeBindingNode.runtimeBinding.receiptKinds?.[0] ??
        "receipt kind pending",
      nodeId: runtimeBindingNode.id,
      nodeLabel: workflowNodeName(workflow, runtimeBindingNode.id),
      runId: selectedRunId ?? "run pending",
      executionMode: runtimeBindingNode.runtimeBinding.executionMode,
      readiness: runtimeBindingNode.runtimeBinding.readiness,
      inputHash: "binding input hash pending",
      outputHash: "binding output hash pending",
      ...makeReplayEnvelopeDetails(
        runtimeBindingNode.runtimeBinding.replayEnvelope ?? null,
      ),
      evidenceRefs: runtimeBindingNode.runtimeBinding.evidenceEventKinds ?? [],
      payload: runtimeBindingNode.runtimeBinding,
    });
  }

  const activationWorkerHandoffAttempt =
    activationWorkerHandoffAttempts.find(
      (attempt) => attempt.replay.fixtureRef === replayFixtureRef,
    ) ?? null;
  if (activationWorkerHandoffAttempt) {
    const activationWorkerHandoffReceipt =
      activationWorkerHandoffReceipts.find((receipt) =>
        activationWorkerHandoffAttempt.receiptIds.includes(receipt.receiptId),
      ) ?? null;
    return makeHarnessReplayInspection({
      replayFixtureRef,
      sourceKind: "activation_worker_handoff",
      sourceLabel: "Worker handoff replay fixture",
      status: activationWorkerHandoffAttempt.status,
      producerComponent: activationWorkerHandoffAttempt.componentId,
      policyDecision:
        activationWorkerHandoffAttempt.policyDecision ??
        activationWorkerHandoffReceipt?.policyDecision ??
        "allow_harness_worker_handoff",
      attemptId: activationWorkerHandoffAttempt.attemptId,
      receiptRef:
        activationWorkerHandoffReceipt?.receiptId ??
        activationWorkerHandoffAttempt.receiptIds[0] ??
        "receipt pending",
      nodeId: activationWorkerHandoffAttempt.workflowNodeId,
      nodeLabel: workflowNodeName(
        workflow,
        activationWorkerHandoffAttempt.workflowNodeId,
      ),
      runId:
        activationWorkerHandoffReceipt?.activationId ??
        selectedRunId ??
        activationWorkerHandoffAttempt.harnessActivationId,
      executionMode: activationWorkerHandoffAttempt.executionMode,
      readiness: activationWorkerHandoffAttempt.readiness,
      inputHash:
        activationWorkerHandoffAttempt.inputHash ?? "input hash pending",
      outputHash:
        activationWorkerHandoffAttempt.outputHash ?? "output hash pending",
      ...makeReplayEnvelopeDetails(activationWorkerHandoffAttempt.replay),
      evidenceRefs: activationWorkerHandoffAttempt.evidenceRefs,
      payload: activationWorkerHandoffAttempt,
    });
  }

  if (forkMutationCanary?.replayFixtureRefs.includes(replayFixtureRef)) {
    const replayIndex =
      forkMutationCanary.replayFixtureRefs.indexOf(replayFixtureRef);
    const attempt =
      forkMutationCanaryAttempts[replayIndex] ??
      forkMutationCanaryAttempts[0] ??
      null;
    return makeHarnessReplayInspection({
      replayFixtureRef,
      sourceKind: "fork_mutation_canary",
      sourceLabel: "Fork mutation canary replay fixture",
      status: forkMutationCanary.status,
      producerComponent: forkMutationCanary.componentId,
      policyDecision: forkMutationCanary.policyDecision,
      attemptId:
        attempt?.attemptId ??
        forkMutationCanary.nodeAttemptIds[replayIndex] ??
        "attempt pending",
      receiptRef:
        attempt?.receiptIds[0] ??
        forkMutationCanary.receiptRefs[replayIndex] ??
        "receipt pending",
      nodeId: forkMutationCanary.workflowNodeId,
      nodeLabel: workflowNodeName(workflow, forkMutationCanary.workflowNodeId),
      runId: forkMutationCanary.canaryId,
      executionMode: attempt?.executionMode ?? "gated",
      readiness: attempt?.readiness ?? "live_ready",
      inputHash: attempt?.inputHash ?? "mutation input hash pending",
      outputHash: attempt?.outputHash ?? forkMutationCanary.diffHash,
      ...makeReplayEnvelopeDetails(attempt?.replay ?? null),
      evidenceRefs: forkMutationCanary.evidenceRefs,
      payload: forkMutationCanary,
    });
  }

  const dispatchReplayDefaults = {
    executionMode: harnessDefaultRuntimeDispatchProof?.executionMode ?? "projection",
    readiness: harnessDefaultRuntimeDispatchProof?.drivesRuntimeDecision
      ? "live_ready"
      : "shadow_ready",
    deterministicEnvelope: true,
    capturesInput: true,
    capturesOutput: true,
    capturesPolicyDecision: true,
    determinism: "redacted",
    redactionPolicy: "default_runtime_dispatch_fixture_redacted",
    nondeterminismReason: "dispatch proof stores replay refs, not fixture payloads",
  } as const;
  const dispatchReplayGroups = harnessDefaultRuntimeDispatchProof
    ? [
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Cognition execution replay fixture",
          producerComponent: "cognition",
          receipts: harnessDefaultRuntimeDispatchProof.cognitionExecutionReceiptIds,
          attempts: harnessDefaultRuntimeDispatchProof.cognitionExecutionAttemptIds,
          replay: harnessDefaultRuntimeDispatchProof.cognitionExecutionReplayFixtureRefs,
          policyDecision: workflowProofString(
            workflowUnknownRecord(
              harnessDefaultRuntimeDispatchProof.cognitionExecutionProof,
            ),
            "policyDecision",
            "accept_workflow_prompt_assembly_hash_envelope",
          ),
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Model execution replay fixture",
          producerComponent: "routing_model",
          receipts: harnessDefaultRuntimeDispatchProof.modelExecutionReceiptIds,
          attempts: harnessDefaultRuntimeDispatchProof.modelExecutionAttemptIds,
          replay: harnessDefaultRuntimeDispatchProof.modelExecutionReplayFixtureRefs,
          policyDecision: "accept_workflow_model_execution_envelope",
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Model provider canary replay fixture",
          producerComponent: "model_provider",
          receipts: harnessDefaultRuntimeDispatchProof.modelProviderCanaryReceiptIds,
          attempts: harnessDefaultRuntimeDispatchProof.modelProviderCanaryAttemptIds,
          replay: harnessDefaultRuntimeDispatchProof.modelProviderCanaryReplayFixtureRefs,
          policyDecision: "accept_workflow_provider_canary_envelope",
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Model provider visible output replay fixture",
          producerComponent: "model_provider_visible_output",
          receipts:
            harnessDefaultRuntimeDispatchProof.modelProviderGatedVisibleOutputReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.modelProviderGatedVisibleOutputAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.modelProviderGatedVisibleOutputReplayFixtureRefs,
          policyDecision: "accept_workflow_provider_visible_output_envelope",
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Model provider rollback drill replay fixture",
          producerComponent: "model_provider_rollback_drill",
          receipts:
            harnessDefaultRuntimeDispatchProof.modelProviderGatedVisibleOutputRollbackDrillReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.modelProviderGatedVisibleOutputRollbackDrillAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs,
          policyDecision: "accept_workflow_provider_rollback_drill_envelope",
        },
        {
          sourceKind: "read_only_routing_proof",
          sourceLabel: "Read-only routing replay fixture",
          producerComponent: "read_only_capability_routing",
          receipts:
            harnessDefaultRuntimeDispatchProof.readOnlyCapabilityRoutingReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.readOnlyCapabilityRoutingAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.readOnlyCapabilityRoutingReplayFixtureRefs,
          policyDecision: readOnlyRoutingReady
            ? "read_only_route_no_mutation"
            : "read_only_route_pending",
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Authority read-only routing replay fixture",
          producerComponent: "authority_tooling_read_only",
          receipts:
            harnessDefaultRuntimeDispatchProof.authorityToolingReadOnlyReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.authorityToolingReadOnlyLiveAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.authorityToolingReadOnlyReplayFixtureRefs,
          policyDecision: "allow_authority_read_only_route",
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Provider catalog replay fixture",
          producerComponent: "authority_tooling_provider_catalog",
          receipts:
            harnessDefaultRuntimeDispatchProof.authorityToolingProviderCatalogLiveReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.authorityToolingProviderCatalogLiveAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.authorityToolingProviderCatalogLiveReplayFixtureRefs,
          policyDecision: "allow_provider_catalog_listing",
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "MCP catalog replay fixture",
          producerComponent: "authority_tooling_mcp_catalog",
          receipts:
            harnessDefaultRuntimeDispatchProof.authorityToolingMcpToolCatalogLiveReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.authorityToolingMcpToolCatalogLiveAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.authorityToolingMcpToolCatalogLiveReplayFixtureRefs,
          policyDecision: "allow_mcp_catalog_listing",
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Native tool catalog replay fixture",
          producerComponent: "authority_tooling_native_catalog",
          receipts:
            harnessDefaultRuntimeDispatchProof.authorityToolingNativeToolCatalogLiveReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.authorityToolingNativeToolCatalogLiveAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.authorityToolingNativeToolCatalogLiveReplayFixtureRefs,
          policyDecision: "allow_native_tool_catalog_listing",
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Connector catalog replay fixture",
          producerComponent: "authority_tooling_connector_catalog",
          receipts:
            harnessDefaultRuntimeDispatchProof.authorityToolingConnectorCatalogLiveReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.authorityToolingConnectorCatalogLiveAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.authorityToolingConnectorCatalogLiveReplayFixtureRefs,
          policyDecision: "allow_connector_catalog_listing",
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Wallet capability dry-run replay fixture",
          producerComponent: "authority_tooling_wallet_capability",
          receipts:
            harnessDefaultRuntimeDispatchProof.authorityToolingWalletCapabilityLiveDryRunReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.authorityToolingWalletCapabilityLiveDryRunAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs,
          policyDecision: "allow_wallet_capability_dry_run",
        },
        {
          sourceKind: "authority_gate_proof",
          sourceLabel: "Authority gate replay fixture",
          producerComponent: "authority_tooling",
          receipts:
            harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveReplayFixtureRefs,
          policyDecision: workflowProofString(
            authorityToolingProof,
            "policyDecision",
            "allow_read_only_route_through_workflow_authority",
          ),
        },
        {
          sourceKind: "authority_gate_proof",
          sourceLabel: "Policy gate replay fixture",
          producerComponent: "policy_gate",
          receipts: workflowProofStringArray(
            authorityToolingProof,
            "policyGateLiveReceiptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveReceiptIds,
          ),
          attempts: workflowProofStringArray(
            authorityToolingProof,
            "policyGateLiveAttemptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveAttemptIds,
          ),
          replay: workflowProofStringArray(
            authorityToolingProof,
            "policyGateLiveReplayFixtureRefs",
            harnessDefaultRuntimeDispatchProof.authorityToolingPolicyGateLiveReplayFixtureRefs,
          ),
          policyDecision: workflowProofString(
            authorityToolingProof,
            "policyGateDecision",
            "allow_read_only_route_through_workflow_authority",
          ),
        },
        {
          sourceKind: "authority_gate_proof",
          sourceLabel: "Destructive denial replay fixture",
          producerComponent: "policy_gate",
          receipts: workflowProofStringArray(
            authorityToolingProof,
            "destructiveDenialLiveReceiptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveReceiptIds,
          ),
          attempts: workflowProofStringArray(
            authorityToolingProof,
            "destructiveDenialLiveAttemptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveAttemptIds,
          ),
          replay: workflowProofStringArray(
            authorityToolingProof,
            "destructiveDenialLiveReplayFixtureRefs",
            harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveDenialLiveReplayFixtureRefs,
          ),
          policyDecision: workflowProofString(
            authorityToolingProof,
            "destructiveDenialPolicyDecision",
            "deny_destructive_request_without_side_effect",
          ),
        },
        {
          sourceKind: "authority_gate_proof",
          sourceLabel: "Approval gate replay fixture",
          producerComponent: "approval_gate",
          receipts: workflowProofStringArray(
            authorityToolingProof,
            "approvalGateLiveReceiptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReceiptIds,
          ),
          attempts: workflowProofStringArray(
            authorityToolingProof,
            "approvalGateLiveAttemptIds",
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveAttemptIds,
          ),
          replay: workflowProofStringArray(
            authorityToolingProof,
            "approvalGateLiveReplayFixtureRefs",
            harnessDefaultRuntimeDispatchProof.authorityToolingApprovalGateLiveReplayFixtureRefs,
          ),
          policyDecision: workflowProofString(
            authorityToolingProof,
            "approvalGatePolicyDecision",
            "require_governed_approval_for_mutating_tooling",
          ),
        },
        {
          sourceKind: "default_runtime_dispatch",
          sourceLabel: "Worker launch handoff replay fixture",
          producerComponent: "handoff_bridge",
          receipts: harnessDefaultRuntimeDispatchProof.workerHandoffReceiptIds,
          attempts:
            harnessDefaultRuntimeDispatchProof.workerHandoffNodeAttemptIds,
          replay:
            harnessDefaultRuntimeDispatchProof.workerHandoffReplayFixtureRefs,
          policyDecision: "allow_harness_worker_handoff",
        },
      ]
    : [];
  const dispatchReplayGroup = dispatchReplayGroups.find((group) =>
    workflowStringList(group.replay).includes(replayFixtureRef),
  );
  if (dispatchReplayGroup && harnessDefaultRuntimeDispatchProof) {
    const dispatchReplayRefs = workflowStringList(dispatchReplayGroup.replay);
    const dispatchAttemptRefs = workflowStringList(dispatchReplayGroup.attempts);
    const dispatchReceiptRefs = workflowStringList(dispatchReplayGroup.receipts);
    const replayIndex = dispatchReplayRefs.indexOf(replayFixtureRef);
    return makeHarnessReplayInspection({
      replayFixtureRef,
      sourceKind: dispatchReplayGroup.sourceKind,
      sourceLabel: dispatchReplayGroup.sourceLabel,
      status: harnessDefaultRuntimeDispatchProof.executionMode,
      producerComponent: dispatchReplayGroup.producerComponent,
      policyDecision: dispatchReplayGroup.policyDecision,
      attemptId: dispatchAttemptRefs[replayIndex] ?? "attempt pending",
      receiptRef: dispatchReceiptRefs[replayIndex] ?? "receipt pending",
      nodeId: null,
      nodeLabel: harnessDefaultRuntimeDispatchProof.workflowId,
      runId: harnessDefaultRuntimeDispatchProof.dispatchId,
      inputHash:
        harnessDefaultRuntimeDispatchProof.promptAssemblyPromptHash ??
        "input hash pending",
      outputHash:
        harnessDefaultRuntimeDispatchProof.modelExecutionOutputHash ??
        "output hash pending",
      ...dispatchReplayDefaults,
      evidenceRefs: harnessDefaultRuntimeDispatchProof.receiptIds,
      payload: harnessDefaultRuntimeDispatchProof,
    });
  }

  if (selectedHarnessGroup?.deepLinks.replayFixtureRefs.includes(replayFixtureRef)) {
    return makeHarnessReplayInspection({
      replayFixtureRef,
      sourceKind: "harness_group",
      sourceLabel: `${selectedHarnessGroup.label} group replay fixture`,
      status: selectedHarnessGroup.statusRollup.executionMode,
      producerComponent: selectedHarnessGroup.componentKinds.join(", "),
      policyDecision:
        selectedHarnessGroupGatedRun?.gateDecision ?? "group replay fixture selected",
      attemptId: selectedHarnessGroupGatedRun?.nodeAttemptIds[0] ?? "attempt pending",
      receiptRef:
        selectedHarnessGroup.deepLinks.receiptRefs[0] ?? "receipt pending",
      nodeId: null,
      nodeLabel: String(selectedHarnessGroup.groupId),
      runId:
        selectedHarnessGroup.deepLinks.runId ?? selectedRunId ?? "run pending",
      executionMode: selectedHarnessGroup.statusRollup.executionMode,
      readiness: selectedHarnessGroup.statusRollup.readiness,
      inputHash: "group input hash pending",
      outputHash: "group output hash pending",
      deterministicEnvelope: true,
      capturesInput: true,
      capturesOutput: true,
      capturesPolicyDecision: true,
      determinism: "redacted",
      redactionPolicy: "group_fixture_refs_redacted",
      nondeterminismReason: "group view stores fixture refs, not fixture payloads",
      evidenceRefs: selectedHarnessGroup.deepLinks.replayFixtureRefs,
      payload: selectedHarnessGroup,
    });
  }

  return makeHarnessReplayInspection({
    replayFixtureRef,
    sourceKind: "unresolved",
    sourceLabel: "Unresolved harness replay fixture",
    status: "unresolved",
    producerComponent: "unknown",
    policyDecision: "replay fixture ref pinned without a matching local record",
    attemptId: "not resolved",
    receiptRef: "not resolved",
    nodeId: null,
    nodeLabel: "not resolved",
    runId: selectedRunId ?? "run pending",
    executionMode: "projection",
    readiness: "projection_only",
    inputHash: "not resolved",
    outputHash: "not resolved",
    deterministicEnvelope: false,
    capturesInput: false,
    capturesOutput: false,
    capturesPolicyDecision: false,
    determinism: "disabled",
    redactionPolicy: "not resolved",
    nondeterminismReason: "not resolved",
    evidenceRefs: [replayFixtureRef],
    payload: { replayFixtureRef, status: "unresolved" },
  });
}

export function workflowNodeRunChildLineage(
  nodeRun?: WorkflowRunResult["nodeRuns"][number] | null,
): WorkflowChildRunLineage | null {
  const output = workflowUnknownRecord(nodeRun?.output);
  const toolKind = String(output.toolKind ?? "");
  const childRunId = String(output.childRunId ?? "");
  const childWorkflowPath = String(output.childWorkflowPath ?? "");
  if (toolKind !== "workflow_tool" && !childRunId && !childWorkflowPath) {
    return null;
  }
  return {
    childRunId: childRunId || "not run",
    childRunStatus: String(output.childRunStatus ?? "unknown"),
    childWorkflowPath: childWorkflowPath || "not selected",
    childThreadId: String(output.childThreadId ?? "unknown"),
  };
}

export function workflowEnvironmentProfile(workflow: WorkflowProject): GraphEnvironmentProfile {
  return {
    target: workflow.global_config.environmentProfile?.target ?? "local",
    credentialScope: workflow.global_config.environmentProfile?.credentialScope ?? "local",
    mockBindingPolicy: workflow.global_config.environmentProfile?.mockBindingPolicy ?? "block",
  };
}

export function workflowBindingRegistryRows(workflow: WorkflowProject): WorkflowBindingRegistryRow[] {
  return workflow.nodes.flatMap((nodeItem) => {
    const logic = nodeItem.config?.logic ?? {};
    const rows: WorkflowBindingRegistryRow[] = [];
    if (nodeItem.type === "model_call") {
      const modelBinding = logic.modelBinding;
      if (modelBinding) {
        const normalized = normalizeWorkflowModelBinding(modelBinding, logic);
        rows.push({
          id: `${nodeItem.id}-model`,
          nodeItem,
          bindingKind: "Model",
          ref: normalized.modelCapabilityRef || normalized.modelRef || "model",
          mode: normalized.mockBinding ? "mock" : "live",
          ready: workflowModelBindingIsReady(normalized),
          scope: (normalized.authorityScopes ?? normalized.capabilityScope)?.join(", ") || "reasoning",
          sideEffectClass: normalized.sideEffectClass ?? "none",
          approval: normalized.requiresApproval ? "approval required" : "not required",
        });
      } else {
        const modelRef = String(logic.modelRef ?? "reasoning");
        const globalBinding = normalizeGraphModelBinding(
          modelRef,
          workflow.global_config.modelBindings?.[modelRef],
        );
        rows.push({
          id: `${nodeItem.id}-global-model`,
          nodeItem,
          bindingKind: "Model",
          ref: globalBinding.modelCapabilityRef || modelRef,
          mode: globalBinding.modelId ? "live" : "local",
          ready:
            workflowModelBindingIsReady(globalBinding) ||
            workflow.edges.some((edge) => {
              const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
              return edge.to === nodeItem.id && (edgeClass === "model" || edge.toPort === "model");
            }),
          scope: (globalBinding.authorityScopes ?? [modelRef]).join(", "),
          sideEffectClass: "none",
          approval: "not required",
        });
      }
    }
    if (nodeItem.type === "model_binding" && logic.modelBinding) {
      const normalized = normalizeWorkflowModelBinding(logic.modelBinding, logic);
      rows.push({
        id: `${nodeItem.id}-model-binding`,
        nodeItem,
        bindingKind: "Model",
        ref: normalized.modelCapabilityRef || normalized.modelRef || "model",
        mode: normalized.mockBinding ? "mock" : "live",
        ready: workflowModelBindingIsReady(normalized),
        scope: (normalized.authorityScopes ?? normalized.capabilityScope)?.join(", ") || "reasoning",
        sideEffectClass: normalized.sideEffectClass ?? "none",
        approval: normalized.requiresApproval ? "approval required" : "not required",
      });
    }
    if (nodeItem.type === "adapter" && logic.connectorBinding) {
      const normalized = normalizeWorkflowConnectorBinding(logic.connectorBinding);
      rows.push({
        id: `${nodeItem.id}-connector`,
        nodeItem,
        bindingKind: "Connector",
        ref: normalized.connectorCapabilityRef || normalized.connectorRef || "connector",
        mode: normalized.mockBinding ? "mock" : "live",
        ready: workflowConnectorBindingIsReady(normalized),
        scope: (normalized.authorityScopes?.length
          ? normalized.authorityScopes
          : normalized.capabilityScope
        ).join(", ") || "read",
        sideEffectClass: normalized.sideEffectClass ?? "read",
        approval: normalized.requiresApproval ? "approval required" : "not required",
      });
    }
    if (nodeItem.type === "plugin_tool" && logic.toolBinding) {
      const normalized = normalizeWorkflowToolBinding(logic.toolBinding);
      const isWorkflowTool = normalized.bindingKind === "workflow_tool";
      const workflowToolPath = normalized.workflowTool?.workflowPath?.trim();
      rows.push({
        id: `${nodeItem.id}-tool`,
        nodeItem,
        bindingKind: isWorkflowTool ? "Workflow tool" : "Tool",
        ref: isWorkflowTool
          ? workflowToolPath || normalized.toolCapabilityRef || normalized.toolRef
          : normalized.toolCapabilityRef || normalized.toolRef,
        mode: isWorkflowTool
          ? "local"
          : normalized.mockBinding
            ? "mock"
            : "live",
        ready: workflowToolBindingIsReady(normalized),
        scope: (normalized.authorityScopes?.length
          ? normalized.authorityScopes
          : normalized.capabilityScope
        ).join(", ") || "tool",
        sideEffectClass: normalized.sideEffectClass ?? "none",
        approval: normalized.requiresApproval ? "approval required" : "not required",
      });
    }
    if (nodeItem.type === "parser" && logic.parserBinding) {
      rows.push({
        id: `${nodeItem.id}-parser`,
        nodeItem,
        bindingKind: "Parser",
        ref: logic.parserBinding.parserRef,
        mode: logic.parserBinding.mockBinding ? "mock" : "local",
        ready: true,
        scope: logic.parserBinding.parserKind ?? "structured_output",
        sideEffectClass: "none",
        approval: "not required",
      });
    }
    return rows;
  });
}

export function workflowBindingRegistrySummary(
  rows: WorkflowBindingRegistryRow[],
): WorkflowBindingRegistrySummary {
  return {
    total: rows.length,
    ready: rows.filter((row) => row.ready).length,
    mock: rows.filter((row) => row.mode === "mock").length,
    approval: rows.filter((row) => row.approval === "approval required").length,
  };
}

export function workflowBindingCheckResult(
  row: WorkflowBindingRegistryRow,
  environment: GraphEnvironmentProfile = {
    target: "local",
    credentialScope: "local",
    mockBindingPolicy: "block",
  },
): WorkflowBindingCheckResult {
  const createdAtMs = Date.now();
  const base = {
    id: `binding-check-${row.id}-${createdAtMs}`,
    rowId: row.id,
    nodeId: row.nodeItem.id,
    bindingKind: row.bindingKind,
    reference: row.ref,
    mode: row.mode,
    createdAtMs,
  } satisfies Pick<
    WorkflowBindingCheckResult,
    | "id"
    | "rowId"
    | "nodeId"
    | "bindingKind"
    | "reference"
    | "mode"
    | "createdAtMs"
  >;
  if (row.mode === "mock") {
    const strictEnvironment =
      environment.target === "production" ||
      environment.mockBindingPolicy === "block";
    return {
      ...base,
      status: strictEnvironment ? "blocked" : "warning",
      summary: strictEnvironment
        ? "Mock binding blocked for activation"
        : "Mock binding available for sandbox use",
      detail: strictEnvironment
        ? "This binding is explicitly mocked. Switch to live credentials or relax the environment mock policy before activation."
        : "This check validates the explicit mock contract locally. It does not call a live external service.",
    };
  }
  if (row.mode === "live") {
    return row.ready
      ? {
          ...base,
          status: "passed",
          summary: "Live binding contract is ready",
          detail: "Credentials are marked ready in workflow config. No hidden vendor connectivity probe was run.",
        }
      : {
          ...base,
          status: "blocked",
          summary: "Live credentials are not ready",
          detail: "Mark credentials ready from the node configuration after the connector or tool is configured.",
        };
  }
  if (row.bindingKind === "Workflow tool") {
    return row.ready
      ? {
          ...base,
          status: "passed",
          summary: "Workflow tool reference is configured",
          detail: "The child workflow path is present. Execution will validate the child workflow and record lineage at run time.",
        }
      : {
          ...base,
          status: "blocked",
          summary: "Workflow tool needs a child workflow",
          detail: "Select a child workflow path before this binding can run as a tool.",
        };
  }
  return row.ready
    ? {
        ...base,
        status: "passed",
        summary: "Local binding contract is ready",
        detail: "This local binding can be validated without external credentials.",
      }
    : {
        ...base,
        status: "blocked",
        summary: "Binding is incomplete",
        detail: "Open the node configuration and complete the binding fields.",
      };
}

export function workflowRailSearchResults(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
  normalizedQuery: string,
): WorkflowRailSearchResult[] {
  const outputNodes = workflow.nodes.filter((nodeItem) => nodeItem.type === "output");
  return [
    ...workflow.nodes.map((nodeItem) => {
      const logic = nodeItem.config?.logic ?? {};
      const bindingSummary = workflowSelectedNodeBindingSummary(nodeItem, logic);
      return {
        id: `node-${nodeItem.id}`,
        resultKind: "Node" as const,
        title: nodeItem.name,
        subtitle: `${nodeItem.type} · ${nodeItem.status ?? "idle"}`,
        detail: bindingSummary.map((item) => `${item.label}: ${item.value}`).join(" · "),
        nodeId: nodeItem.id,
        searchable: [
          nodeItem.id,
          nodeItem.name,
          nodeItem.type,
          nodeItem.status,
          nodeItem.metricValue,
          ...bindingSummary.flatMap((item) => [item.label, item.value]),
        ].join(" ").toLowerCase(),
      };
    }),
    ...tests.map((test) => ({
      id: `test-${test.id}`,
      resultKind: "Test" as const,
      title: test.name,
      subtitle: `${test.status ?? "idle"} · ${test.targetNodeIds.length} target${test.targetNodeIds.length === 1 ? "" : "s"}`,
      detail: test.lastMessage ?? test.assertion.kind,
      nodeId: test.targetNodeIds[0] ?? null,
      searchable: [
        test.id,
        test.name,
        test.status,
        test.lastMessage,
        test.assertion.kind,
        ...test.targetNodeIds,
      ].join(" ").toLowerCase(),
    })),
    ...outputNodes.map((nodeItem) => ({
      id: `output-${nodeItem.id}`,
      resultKind: "Output" as const,
      title: nodeItem.name,
      subtitle: String(nodeItem.config?.logic?.format ?? "output"),
      detail: String(nodeItem.config?.logic?.deliveryTarget?.targetKind ?? "no delivery"),
      nodeId: nodeItem.id,
      searchable: [
        nodeItem.id,
        nodeItem.name,
        nodeItem.config?.logic?.format,
        nodeItem.config?.logic?.deliveryTarget?.targetKind,
      ].join(" ").toLowerCase(),
    })),
  ].filter((item) => normalizedQuery.length === 0 || item.searchable.includes(normalizedQuery));
}

export function workflowFileBundleItems(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
  proposals: WorkflowProposal[],
  runs: WorkflowRunSummary[],
  portablePackage: WorkflowPortablePackage | null,
  bindingManifest: WorkflowBindingManifest | null = null,
): WorkflowFileBundleItem[] {
  return [
    {
      label: "Workflow graph",
      path: workflow.metadata.gitLocation || `.agents/workflows/${workflow.metadata.slug}.workflow.json`,
      status: workflow.metadata.dirty ? "modified" : "saved",
    },
    {
      label: "Tests sidecar",
      path: `.agents/workflows/${workflow.metadata.slug}.tests.json`,
      status: `${tests.length} test${tests.length === 1 ? "" : "s"}`,
    },
    {
      label: "Proposal sidecar",
      path: `.agents/workflows/${workflow.metadata.slug}.proposals/`,
      status: `${proposals.length} proposal${proposals.length === 1 ? "" : "s"}`,
    },
    {
      label: "Run sidecar",
      path: `.agents/workflows/${workflow.metadata.slug}.runs/`,
      status: `${runs.length} run${runs.length === 1 ? "" : "s"}`,
    },
    {
      label: "Binding manifest",
      path: `.agents/workflows/${workflow.metadata.slug}.bindings.json`,
      status: bindingManifest
        ? `${bindingManifest.summary.ready}/${bindingManifest.summary.total} ready`
        : "not generated",
    },
    {
      label: "Portable package",
      path: portablePackage?.packagePath ?? `.agents/workflows/${workflow.metadata.slug}.portable/`,
      status: portablePackage
        ? portablePackage.manifest.portable
          ? `portable · ${portablePackage.manifest.workflowChromeLocale ?? "default"}`
          : `blocked: ${portablePackage.manifest.readinessStatus}`
        : "not exported",
    },
  ];
}

export function workflowTimeLabel(value?: number): string {
  return value ? new Date(value).toLocaleTimeString() : "pending";
}

export function workflowDurationLabel(startedAtMs?: number, finishedAtMs?: number): string {
  if (!startedAtMs || !finishedAtMs) return "running";
  const elapsed = Math.max(0, finishedAtMs - startedAtMs);
  if (elapsed < 1000) return `${elapsed} ms`;
  return `${(elapsed / 1000).toFixed(elapsed < 10_000 ? 1 : 0)} s`;
}

export function workflowEventLabel(event: WorkflowStreamEvent): string {
  switch (event.kind) {
    case "run_started":
      return "Run started";
    case "node_started":
      return "Node started";
    case "node_succeeded":
      return "Node finished";
    case "node_failed":
      return "Node failed";
    case "node_blocked":
      return "Node blocked";
    case "node_interrupted":
      return "Waiting for approval";
    case "model_invocation_succeeded":
      return "Model invoked";
    case "state_updated":
      return "State updated";
    case "output_created":
      return "Output created";
    case "asset_materialized":
      return "Asset materialized";
    case "test_result":
      return "Test result";
    case "child_run_completed":
      return "Child run completed";
    case "run_completed":
      return "Run completed";
    default:
      return String(event.kind).replace(/_/g, " ");
  }
}

export function workflowNodeName(workflow: WorkflowProject, nodeId?: string): string {
  if (!nodeId) return "Workflow";
  return workflow.nodes.find((node) => node.id === nodeId)?.name ?? nodeId;
}

const WORKFLOW_ISSUE_TITLES: Record<string, string> = {
  missing_model_binding: "Model binding missing",
  missing_model_tool_attachment: "Tool attachment missing",
  missing_model_parser_attachment: "Parser attachment missing",
  missing_model_memory_attachment: "Memory attachment missing",
  missing_model_output_schema: "Structured output schema missing",
  missing_model_binding_result_schema: "Model result schema missing",
  missing_parser_binding: "Parser binding missing",
  missing_parser_result_schema: "Parser result schema missing",
  missing_function_binding: "Function binding missing",
  missing_output_schema: "Output schema missing",
  missing_connector_binding: "Connector binding missing",
  missing_live_connector_credential: "Connector credential missing",
  missing_tool_binding: "Tool binding missing",
  missing_live_tool_credential: "Tool credential missing",
  missing_workflow_tool_ref: "Workflow tool target missing",
  missing_workflow_tool_argument_schema: "Workflow tool input schema missing",
  missing_workflow_tool_result_schema: "Workflow tool output schema missing",
  missing_trigger_schedule: "Schedule missing",
  missing_trigger_event_source: "Event source missing",
  missing_state_key: "State key missing",
  missing_subgraph_ref: "Subgraph target missing",
  missing_proposal_bounds: "Proposal bounds missing",
  missing_start_node: "Start node missing",
  missing_output_node: "Output node missing",
  missing_unit_tests: "Unit tests missing",
  missing_error_handling_path: "Error handling path missing",
  missing_ai_evaluation_coverage: "AI evaluation coverage missing",
  missing_replay_fixture: "Replay fixture missing",
  missing_scheduled_trigger: "Scheduled trigger missing",
  missing_event_trigger: "Event trigger missing",
  mock_binding_active: "Mock binding active",
  runtime_bridge_unavailable: "Runtime bridge unavailable",
  workflow_bundle_unavailable: "Workflow bundle unavailable",
  tool_catalog_unavailable: "Tool catalog unavailable",
  connector_catalog_unavailable: "Connector catalog unavailable",
  model_catalog_unavailable: "Model catalog unavailable",
};

function titleCaseIssueCode(code: string): string {
  return code
    .split("_")
    .filter(Boolean)
    .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

export function workflowIssueTitle(issue: Pick<WorkflowValidationIssue, "code">): string {
  return WORKFLOW_ISSUE_TITLES[issue.code] ?? titleCaseIssueCode(issue.code);
}

export function workflowIssueActionLabel(
  issue: Pick<
    WorkflowValidationIssue,
    "code" | "nodeId" | "repairLabel"
  >,
): string {
  if (issue.repairLabel) return issue.repairLabel;
  if (issue.nodeId) return "Open configuration";
  if (issue.code === "missing_output_node") return "Add an output node";
  if (issue.code === "missing_start_node") return "Add a start or source node";
  if (issue.code === "missing_unit_tests") return "Add a unit test";
  if (issue.code === "missing_error_handling_path") return "Add an error or retry path";
  if (issue.code === "mock_binding_active") return "Review binding mode";
  if (
    issue.code === "runtime_bridge_unavailable" ||
    issue.code === "workflow_bundle_unavailable" ||
    issue.code === "tool_catalog_unavailable" ||
    issue.code === "connector_catalog_unavailable" ||
    issue.code === "model_catalog_unavailable"
  )
    return "Open runtime diagnostics";
  return "Review workflow settings";
}

export function workflowReadinessStatusLabel(
  result: WorkflowValidationResult | null,
): string {
  if (!result) return "not run";
  if (result.status === "passed" && result.warnings.length > 0) {
    return "passed with warnings";
  }
  return result.status;
}

export function workflowLifecycleState(
  workflow: WorkflowProject,
  readinessResult: WorkflowValidationResult | null,
  validationResult: WorkflowValidationResult | null = null,
): WorkflowLifecycleState {
  const result = readinessResult ?? validationResult;
  const environment = workflowEnvironmentProfile(workflow);
  const hasStart = workflow.nodes.some(
    (nodeItem) => nodeItem.type === "trigger" || nodeItem.type === "source",
  );
  const hasOutput = workflow.nodes.some((nodeItem) => nodeItem.type === "output");
  const hasScheduledTrigger = workflow.nodes.some(
    (nodeItem) =>
      nodeItem.type === "trigger" &&
      nodeItem.config?.logic?.triggerKind === "scheduled",
  );

  if (result?.status === "blocked" || result?.status === "failed") {
    return {
      id: "blocked",
      label: "Blocked",
      detail: "Repair readiness blockers before activation.",
      status: "blocked",
    };
  }

  if (!hasStart || !hasOutput) {
    return {
      id: "draft",
      label: "Draft",
      detail: "Add a start and output to make this workflow runnable.",
      status: "idle",
    };
  }

  if (!result) {
    return {
      id: "local",
      label: "Runnable locally",
      detail: "Validate readiness before scheduling or production activation.",
      status: "warning",
    };
  }

  if (result.warnings.length > 0) {
    return {
      id: "sandbox",
      label: "Ready for sandbox",
      detail: "Warnings remain for production use.",
      status: "warning",
    };
  }

  if (environment.target === "production") {
    return {
      id: "production",
      label: "Ready for production",
      detail: "Readiness passed for the selected production profile.",
      status: "ready",
    };
  }

  if (hasScheduledTrigger) {
    return {
      id: "scheduled",
      label: "Ready for scheduled",
      detail: "Scheduled trigger and output are configured.",
      status: "ready",
    };
  }

  if (environment.target === "sandbox" || environment.mockBindingPolicy !== "block") {
    return {
      id: "sandbox",
      label: "Ready for sandbox",
      detail: "Readiness passed for sandbox execution.",
      status: "ready",
    };
  }

  return {
    id: "local",
    label: "Runnable locally",
    detail: "Ready for a local run.",
    status: "ready",
  };
}

export function workflowWorkbenchCheckTitle(
  status: WorkflowDogfoodRun["status"],
): string {
  return `Run checks ${status}`;
}

export function workflowWorkbenchCheckSummary(count: number): string {
  return `${count} workflow${count === 1 ? "" : "s"} checked through the workbench.`;
}

export function compareRunRecords(
  workflow: WorkflowProject,
  target: WorkflowRunResult,
  baseline: WorkflowRunResult,
): WorkflowRunComparison {
  const targetDuration = workflowRunDurationMs(target.summary);
  const baselineDuration = workflowRunDurationMs(baseline.summary);
  const baselineNodes = new Map(baseline.nodeRuns.map((run) => [run.nodeId, run]));
  const targetNodes = new Map(target.nodeRuns.map((run) => [run.nodeId, run]));
  const nodeIds = Array.from(new Set([...baselineNodes.keys(), ...targetNodes.keys()]));
  const changedNodes = nodeIds
    .map((nodeId) => {
      const before = baselineNodes.get(nodeId);
      const after = targetNodes.get(nodeId);
      const inputChanged = workflowValueFingerprint(before?.input) !== workflowValueFingerprint(after?.input);
      const outputChanged = workflowValueFingerprint(before?.output) !== workflowValueFingerprint(after?.output);
      const errorChanged = (before?.error ?? "") !== (after?.error ?? "");
      const statusChanged = (before?.status ?? "not run") !== (after?.status ?? "not run");
      if (!inputChanged && !outputChanged && !errorChanged && !statusChanged) return null;
      return {
        nodeId,
        nodeName: workflowNodeName(workflow, nodeId),
        before: before?.status ?? "not run",
        after: after?.status ?? "not run",
        inputChanged,
        outputChanged,
        errorChanged,
      };
    })
    .filter((item): item is WorkflowRunComparison["changedNodes"][number] => Boolean(item));
  const baselineState = baseline.finalState.values ?? {};
  const targetState = target.finalState.values ?? {};
  const stateKeys = Array.from(new Set([...Object.keys(baselineState), ...Object.keys(targetState)]));
  const stateChanges = stateKeys
    .map((key) => {
      if (!(key in baselineState)) return { key, change: "added" as const };
      if (!(key in targetState)) return { key, change: "removed" as const };
      return workflowValueFingerprint(baselineState[key]) === workflowValueFingerprint(targetState[key])
        ? null
        : { key, change: "changed" as const };
    })
    .filter((item): item is WorkflowRunComparison["stateChanges"][number] => Boolean(item));
  return {
    baselineRunId: baseline.summary.id,
    targetRunId: target.summary.id,
    baselineStatus: baseline.summary.status,
    targetStatus: target.summary.status,
    durationDeltaMs:
      targetDuration === null || baselineDuration === null
        ? null
        : targetDuration - baselineDuration,
    checkpointDelta: target.checkpoints.length - baseline.checkpoints.length,
    eventDelta: target.events.length - baseline.events.length,
    changedNodes,
    stateChanges,
  };
}

export function workflowSelectedNodeBindingSummary(
  node: Node,
  logic: Record<string, any>,
): WorkflowBindingSummaryItem[] {
  if (node.type === "model_call") {
    const binding = normalizeWorkflowModelBinding(logic.modelBinding, logic);
    return [
      {
        label: "Capability",
        value: binding.modelCapabilityRef ?? "not selected",
        ready: Boolean(binding.modelCapabilityRef),
      },
      {
        label: "Route",
        value: binding.routeId ?? "not selected",
        ready: Boolean(binding.routeId),
      },
      {
        label: "Receipts",
        value: binding.receiptBehavior?.receiptRequired ? "required" : "missing",
        ready: Boolean(binding.receiptBehavior?.receiptRequired),
      },
    ];
  }
  if (node.type === "model_binding") {
    const binding = normalizeWorkflowModelBinding(logic.modelBinding, logic);
    return [
      { label: "Capability", value: String(binding.modelCapabilityRef || "not selected"), ready: Boolean(binding.modelCapabilityRef) },
      { label: "Mode", value: binding.mockBinding === true ? "mock" : "live", ready: typeof binding.mockBinding === "boolean" },
      { label: "Authority", value: (binding.authorityScopes ?? binding.authorityScopeRequirements ?? []).join(", ") || "missing", ready: Boolean((binding.authorityScopes ?? binding.authorityScopeRequirements ?? []).length) },
      { label: "Result schema", value: binding.resultSchema || logic.outputSchema ? "configured" : "missing", ready: Boolean(binding.resultSchema || logic.outputSchema) },
    ];
  }
  if (node.type === "parser") {
    const binding = logic.parserBinding ?? {};
    return [
      { label: "Parser", value: String(binding.parserRef || logic.parserRef || "not selected"), ready: Boolean(binding.parserRef || logic.parserRef) },
      { label: "Kind", value: String(binding.parserKind || "json_schema"), ready: true },
      { label: "Result schema", value: binding.resultSchema || logic.outputSchema ? "configured" : "missing", ready: Boolean(binding.resultSchema || logic.outputSchema) },
    ];
  }
  if (node.type === "adapter") {
    const binding = normalizeWorkflowConnectorBinding(logic.connectorBinding ?? {});
    return [
      { label: "Capability", value: String(binding.connectorCapabilityRef || "not selected"), ready: Boolean(binding.connectorCapabilityRef && !binding.connectorCapabilityRef.endsWith(":unbound")) },
      { label: "Mode", value: binding.mockBinding === true ? "mock" : "live", ready: typeof binding.mockBinding === "boolean" },
      { label: "Authority", value: (binding.authorityScopes ?? []).join(", ") || "none", ready: binding.mockBinding === true || workflowConnectorBindingIsReady(binding) },
      { label: "Credentials", value: binding.mockBinding === true ? "mock" : binding.credentialReady ? "ready" : "missing", ready: binding.mockBinding === true || binding.credentialReady === true },
    ];
  }
  if (node.type === "plugin_tool") {
    const binding = normalizeWorkflowToolBinding(logic.toolBinding ?? {});
    return [
      { label: "Capability", value: String(binding.toolCapabilityRef || "not selected"), ready: Boolean(binding.toolCapabilityRef && !binding.toolCapabilityRef.endsWith(":unbound")) },
      { label: "Mode", value: binding.mockBinding === true ? "mock" : "live", ready: typeof binding.mockBinding === "boolean" },
      { label: "Credentials", value: binding.bindingKind === "workflow_tool" ? "local" : binding.mockBinding === true ? "mock" : binding.credentialReady ? "ready" : "missing", ready: binding.bindingKind === "workflow_tool" || binding.mockBinding === true || binding.credentialReady === true },
    ];
  }
  if (node.type === "function") {
    const binding = logic.functionBinding ?? {};
    return [
      { label: "Runtime", value: String(binding.language ?? logic.language ?? "javascript"), ready: true },
      { label: "Output schema", value: binding.outputSchema || logic.outputSchema ? "configured" : "missing", ready: Boolean(binding.outputSchema || logic.outputSchema) },
    ];
  }
  if (node.type === "trigger") {
    return [{ label: "Trigger", value: String(logic.triggerKind ?? "manual"), ready: true }];
  }
  if (node.type === "state") {
    return [{ label: "State key", value: String(logic.stateKey || "not set"), ready: Boolean(logic.stateKey) }];
  }
  if (node.type === "subgraph") {
    return [{ label: "Workflow", value: String(logic.subgraphRef?.workflowPath || "not selected"), ready: Boolean(logic.subgraphRef?.workflowPath) }];
  }
  if (node.type === "output") {
    const targetKind = logic.deliveryTarget?.targetKind ?? "none";
    return [
      { label: "Format", value: String(logic.format ?? "markdown"), ready: Boolean(logic.format) },
      { label: "Delivery", value: String(targetKind), ready: true },
    ];
  }
  if (node.type === "proposal") {
    const targetCount = logic.proposalAction?.boundedTargets?.length ?? 0;
    return [{ label: "Bounds", value: `${targetCount} target${targetCount === 1 ? "" : "s"}`, ready: targetCount > 0 }];
  }
  return [{ label: "Configuration", value: "basic settings", ready: true }];
}

function workflowRunDurationMs(run?: WorkflowRunSummary): number | null {
  if (!run?.startedAtMs || !run.finishedAtMs) return null;
  return Math.max(0, run.finishedAtMs - run.startedAtMs);
}

function workflowValueFingerprint(value: unknown): string {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? null);
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash * 31 + text.charCodeAt(index)) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}
