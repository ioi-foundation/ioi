export type ChatRuntimeProvenanceKind =
  | "real_remote_model_runtime"
  | "real_local_runtime"
  | "fixture_runtime"
  | "mock_runtime"
  | "deterministic_continuity_fallback"
  | "inference_unavailable"
  | "opaque_runtime";

export interface ChatRuntimeProvenance {
  kind: ChatRuntimeProvenanceKind;
  label: string;
  model?: string | null;
  endpoint?: string | null;
}

export type ExecutionStage =
  | "plan"
  | "dispatch"
  | "work"
  | "mutate"
  | "merge"
  | "verify"
  | "finalize";

export type ExecutionDomainKind =
  | "artifact"
  | "conversation"
  | "tool_widget"
  | "visualizer"
  | "workflow"
  | "research"
  | "reply"
  | "code"
  | "unknown";

export type ExecutionLivePreviewKind =
  | "token_stream"
  | "worker_output"
  | "change_preview"
  | "command_stream";

export function executionStageForCurrentStage(
  currentStage: string | null | undefined,
): ExecutionStage {
  switch ((currentStage || "").trim().toLowerCase()) {
    case "intake":
    case "requirements":
    case "specification":
    case "planner":
    case "plan":
      return "plan";
    case "routing":
    case "dispatch":
      return "dispatch";
    case "swarm_execution":
    case "work":
      return "work";
    case "materialization":
    case "execution":
    case "repair":
    case "mutate":
      return "mutate";
    case "merge":
      return "merge";
    case "verification":
    case "verify":
      return "verify";
    case "presentation":
    case "reply":
    case "finalize":
    case "final":
      return "finalize";
    default:
      return "work";
  }
}

export type SwarmWorkerRole =
  | "planner"
  | "coordinator"
  | "responder"
  | "skeleton"
  | "section_content"
  | "style_system"
  | "interaction"
  | "integrator"
  | "validation"
  | "repair";

export type SwarmLeaseMode = "shared_read" | "exclusive_write";

export type SwarmLeaseScopeKind = "file" | "region" | "surface";

export interface SwarmLeaseRequirement {
  target: string;
  scopeKind: SwarmLeaseScopeKind;
  mode: SwarmLeaseMode;
}

export type SwarmVerificationPolicy = "normal" | "elevated" | "blocking";

export type SwarmWorkItemStatus =
  | "pending"
  | "blocked"
  | "running"
  | "succeeded"
  | "failed"
  | "skipped"
  | "rejected";

export type SwarmWorkerResultKind =
  | "completed"
  | "noop"
  | "blocked"
  | "conflict"
  | "dependency_discovered"
  | "subtask_requested"
  | "replan_requested"
  | "verification_concern";

export interface SwarmWorkItem {
  id: string;
  title: string;
  role: SwarmWorkerRole;
  summary: string;
  spawnedFromId?: string | null;
  readPaths: string[];
  writePaths: string[];
  writeRegions: string[];
  leaseRequirements: SwarmLeaseRequirement[];
  acceptanceCriteria: string[];
  dependencyIds: string[];
  blockedOnIds: string[];
  verificationPolicy?: SwarmVerificationPolicy | null;
  retryBudget?: number | null;
  status: SwarmWorkItemStatus;
}

export interface SwarmPlan {
  version: number;
  strategy: string;
  executionDomain: string;
  adapterLabel: string;
  parallelismMode: string;
  topLevelObjective?: string | null;
  decompositionHypothesis?: string | null;
  decompositionType?: string | null;
  firstFrontierIds: string[];
  spawnConditions: string[];
  pruneConditions: string[];
  mergeStrategy?: string | null;
  verificationStrategy?: string | null;
  fallbackCollapseStrategy?: string | null;
  completionInvariant?: ExecutionCompletionInvariant | null;
  workItems: SwarmWorkItem[];
}

export interface SwarmExecutionSummary {
  enabled: boolean;
  currentStage: string;
  executionStage?: ExecutionStage | null;
  activeWorkerRole?: SwarmWorkerRole | null;
  totalWorkItems: number;
  completedWorkItems: number;
  failedWorkItems: number;
  verificationStatus: string;
  strategy: string;
  executionDomain: string;
  adapterLabel: string;
  parallelismMode: string;
}

export interface SwarmWorkerReceipt {
  workItemId: string;
  role: SwarmWorkerRole;
  status: SwarmWorkItemStatus;
  resultKind?: SwarmWorkerResultKind | null;
  summary: string;
  startedAt: string;
  finishedAt?: string | null;
  runtime: ChatRuntimeProvenance;
  readPaths: string[];
  writePaths: string[];
  writeRegions: string[];
  spawnedWorkItemIds: string[];
  blockedOnIds: string[];
  promptBytes?: number | null;
  outputBytes?: number | null;
  outputPreview?: string | null;
  previewLanguage?: string | null;
  notes: string[];
  failure?: string | null;
}

export interface SwarmChangeReceipt {
  workItemId: string;
  status: SwarmWorkItemStatus;
  summary: string;
  operationCount: number;
  touchedPaths: string[];
  touchedRegions: string[];
  operationKinds: string[];
  preview?: string | null;
  previewLanguage?: string | null;
  failure?: string | null;
}

export interface SwarmMergeReceipt {
  workItemId: string;
  status: SwarmWorkItemStatus;
  summary: string;
  appliedOperationCount: number;
  touchedPaths: string[];
  touchedRegions: string[];
  rejectedReason?: string | null;
}

export interface SwarmVerificationReceipt {
  id: string;
  kind: string;
  status: string;
  summary: string;
  details: string[];
}

export interface ExecutionGraphMutationReceipt {
  id: string;
  mutationKind: string;
  status: string;
  summary: string;
  triggeredByWorkItemId?: string | null;
  affectedWorkItemIds: string[];
  details: string[];
}

export interface ExecutionDispatchBatch {
  id: string;
  sequence: number;
  status: string;
  workItemIds: string[];
  deferredWorkItemIds: string[];
  blockedWorkItemIds: string[];
  details: string[];
}

export interface ExecutionRepairReceipt {
  id: string;
  status: string;
  summary: string;
  triggeredByVerificationId?: string | null;
  workItemIds: string[];
  details: string[];
}

export interface ExecutionReplanReceipt {
  id: string;
  status: string;
  summary: string;
  triggeredByWorkItemId?: string | null;
  spawnedWorkItemIds: string[];
  blockedWorkItemIds: string[];
  details: string[];
}

export interface ExecutionBudgetSummary {
  plannedWorkerCount?: number | null;
  dispatchedWorkerCount?: number | null;
  tokenBudget?: number | null;
  tokenUsage?: number | null;
  wallClockMs?: number | null;
  coordinationOverheadMs?: number | null;
  status: string;
}

export type ChatExecutionBudgetExpansionPolicy =
  | "fixed"
  | "confidence_gated"
  | "frontier_adaptive";

export interface ChatExecutionBudgetEnvelope {
  maxWorkers: number;
  maxParallelDepth: number;
  maxReplans: number;
  maxWallClockMs: number;
  maxTokens: number;
  maxToolCalls: number;
  maxRepairs: number;
  expansionPolicy: ChatExecutionBudgetExpansionPolicy;
}

export interface ChatExecutionModeDecision {
  requestedStrategy: ChatExecutionStrategy;
  resolvedStrategy: ChatExecutionStrategy;
  modeConfidence: number;
  oneShotSufficiency: number;
  ambiguity: number;
  workGraphSizeEstimate: number;
  hiddenDependencyLikelihood: number;
  verificationPressure: number;
  revisionCost: number;
  evidenceBreadth: number;
  mergeBurden: number;
  decompositionPayoff: number;
  workGraphRequired: boolean;
  decompositionReason: string;
  budgetEnvelope: ChatExecutionBudgetEnvelope;
}

export type ExecutionCompletionInvariantStatus =
  | "pending"
  | "satisfied"
  | "blocked";

export interface ExecutionCompletionInvariant {
  summary: string;
  status: ExecutionCompletionInvariantStatus;
  requiredWorkItemIds: string[];
  satisfiedWorkItemIds: string[];
  speculativeWorkItemIds: string[];
  prunedWorkItemIds: string[];
  requiredVerificationIds: string[];
  satisfiedVerificationIds: string[];
  requiredArtifactPaths: string[];
  remainingObligations: string[];
  allowsEarlyExit: boolean;
}

export interface ExecutionLivePreview {
  id: string;
  kind: ExecutionLivePreviewKind;
  label: string;
  workItemId?: string | null;
  role?: SwarmWorkerRole | null;
  status: string;
  language?: string | null;
  content: string;
  isFinal: boolean;
  updatedAt: string;
}

export interface ExecutionEnvelope {
  version: number;
  strategy?: ChatExecutionStrategy | null;
  modeDecision?: ChatExecutionModeDecision | null;
  budgetEnvelope?: ChatExecutionBudgetEnvelope | null;
  executionDomain: string;
  domainKind?: ExecutionDomainKind | null;
  completionInvariant?: ExecutionCompletionInvariant | null;
  plan?: SwarmPlan | null;
  executionSummary?: SwarmExecutionSummary | null;
  workerReceipts: SwarmWorkerReceipt[];
  changeReceipts: SwarmChangeReceipt[];
  mergeReceipts: SwarmMergeReceipt[];
  verificationReceipts: SwarmVerificationReceipt[];
  graphMutationReceipts: ExecutionGraphMutationReceipt[];
  dispatchBatches: ExecutionDispatchBatch[];
  repairReceipts: ExecutionRepairReceipt[];
  replanReceipts: ExecutionReplanReceipt[];
  budgetSummary?: ExecutionBudgetSummary | null;
  livePreviews: ExecutionLivePreview[];
}

export type ChatExecutionStrategy =
  | "single_pass"
  | "direct_author"
  | "plan_execute"
  | "micro_swarm"
  | "adaptive_work_graph";
