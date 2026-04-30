export interface SessionSummary {
  session_id: string;
  title: string;
  timestamp: number;
  phase?: string | null;
  current_step?: string | null;
  resume_hint?: string | null;
  workspace_root?: string | null;
}

export type SessionMemoryClass =
  | "ephemeral"
  | "carry_forward"
  | "pinned"
  | "governance_critical";

export type SessionCompactionMode = "manual" | "auto";

export interface SessionCompactionPolicy {
  carryPinnedOnly: boolean;
  preserveChecklistState: boolean;
  preserveBackgroundTasks: boolean;
  preserveLatestOutputExcerpt: boolean;
  preserveGovernanceBlockers: boolean;
  aggressiveTranscriptPruning: boolean;
}

export type SessionCompactionDisposition =
  | "carry_forward"
  | "retained_summary"
  | "pruned";

export type SessionCompactionResumeSafetyStatus = "protected" | "degraded";

export interface SessionCompactionResumeSafetyReceipt {
  status: SessionCompactionResumeSafetyStatus;
  reasons: string[];
}

export interface SessionCompactionMemoryItem {
  key: string;
  label: string;
  memoryClass: SessionMemoryClass;
  values: string[];
}

export interface SessionCompactionPruneDecision {
  key: string;
  label: string;
  disposition: SessionCompactionDisposition;
  detailCount: number;
  rationale: string;
  summary: string;
  examples: string[];
}

export interface SessionCompactionCarryForwardState {
  workspaceRoot?: string | null;
  pinnedFiles: string[];
  explicitIncludes: string[];
  explicitExcludes: string[];
  checklistLabels: string[];
  backgroundTaskLabels: string[];
  blockedOn?: string | null;
  pendingDecisionContext?: string | null;
  latestArtifactOutcome?: string | null;
  executionTargets: string[];
  latestOutputExcerpt?: string | null;
  memoryItems: SessionCompactionMemoryItem[];
}

export interface SessionCompactionPreview {
  sessionId: string;
  title: string;
  phase?: string | null;
  policy: SessionCompactionPolicy;
  preCompactionSpan: string;
  summary: string;
  resumeAnchor: string;
  carriedForwardState: SessionCompactionCarryForwardState;
  resumeSafety: SessionCompactionResumeSafetyReceipt;
  pruneDecisions: SessionCompactionPruneDecision[];
}

export interface SessionCompactionRecord {
  compactionId: string;
  sessionId: string;
  title: string;
  compactedAtMs: number;
  mode: SessionCompactionMode;
  phase?: string | null;
  policy: SessionCompactionPolicy;
  preCompactionSpan: string;
  summary: string;
  resumeAnchor: string;
  carriedForwardState: SessionCompactionCarryForwardState;
  resumeSafety: SessionCompactionResumeSafetyReceipt;
  pruneDecisions: SessionCompactionPruneDecision[];
}

export interface SessionCompactionRecommendation {
  shouldCompact: boolean;
  reasonLabels: string[];
  recommendedPolicy: SessionCompactionPolicy;
  recommendedPolicyLabel: string;
  recommendedPolicyReasonLabels: string[];
  resumeSafeguardLabels: string[];
  historyCount: number;
  eventCount: number;
  artifactCount: number;
  pinnedFileCount: number;
  explicitIncludeCount: number;
  idleAgeMs: number;
  blockedAgeMs?: number | null;
}

export interface SessionDurabilityPortfolio {
  retainedSessionCount: number;
  compactedSessionCount: number;
  replayReadySessionCount: number;
  uncompactedSessionCount: number;
  staleCompactionCount: number;
  degradedCompactionCount: number;
  recommendedCompactionCount: number;
  compactedWithoutTeamMemoryCount: number;
  teamMemoryEntryCount: number;
  teamMemoryCoveredSessionCount: number;
  teamMemoryRedactedSessionCount: number;
  teamMemoryReviewRequiredSessionCount: number;
  coverageSummary: string;
  teamMemorySummary: string;
  attentionSummary: string;
  attentionLabels: string[];
}

export interface SessionCompactionSnapshot {
  generatedAtMs: number;
  activeSessionId?: string | null;
  activeSessionTitle?: string | null;
  policyForActive: SessionCompactionPolicy;
  recordCount: number;
  latestForActive?: SessionCompactionRecord | null;
  previewForActive?: SessionCompactionPreview | null;
  recommendationForActive?: SessionCompactionRecommendation | null;
  durabilityPortfolio?: SessionDurabilityPortfolio;
  records: SessionCompactionRecord[];
}

export type TeamMemoryScopeKind = "workspace" | "session";

export type TeamMemorySyncStatus = "synced" | "redacted" | "review_required";

export interface TeamMemoryRedactionSummary {
  redactionCount: number;
  redactedFields: string[];
  redactionVersion: string;
}

export interface TeamMemorySyncEntry {
  entryId: string;
  sessionId: string;
  sessionTitle: string;
  syncedAtMs: number;
  scopeKind: TeamMemoryScopeKind;
  scopeId: string;
  scopeLabel: string;
  actorId: string;
  actorLabel: string;
  actorRole: string;
  syncStatus: TeamMemorySyncStatus;
  reviewSummary: string;
  omittedGovernanceItemCount: number;
  resumeAnchor: string;
  preCompactionSpan: string;
  summary: string;
  sharedMemoryItems: SessionCompactionMemoryItem[];
  redaction: TeamMemoryRedactionSummary;
}

export interface TeamMemorySyncSnapshot {
  generatedAtMs: number;
  activeSessionId?: string | null;
  activeScopeId?: string | null;
  activeScopeKind?: TeamMemoryScopeKind | null;
  activeScopeLabel?: string | null;
  entryCount: number;
  redactedEntryCount: number;
  reviewRequiredCount: number;
  summary: string;
  entries: TeamMemorySyncEntry[];
}

export interface SessionRewindCandidate {
  sessionId: string;
  title: string;
  timestamp: number;
  phase?: string | null;
  currentStep?: string | null;
  resumeHint?: string | null;
  workspaceRoot?: string | null;
  isCurrent: boolean;
  isLastStable: boolean;
  actionLabel: string;
  previewHeadline: string;
  previewDetail: string;
  discardSummary: string;
}

export interface SessionRewindSnapshot {
  activeSessionId?: string | null;
  activeSessionTitle?: string | null;
  lastStableSessionId?: string | null;
  candidates: SessionRewindCandidate[];
}

export interface SessionHookReceiptSummary {
  title: string;
  timestampMs: number;
  toolName: string;
  status: string;
  summary: string;
}

export interface SessionHookRecord {
  hookId: string;
  entryId?: string | null;
  label: string;
  ownerLabel: string;
  sourceLabel: string;
  sourceKind: string;
  sourceUri?: string | null;
  contributionPath?: string | null;
  triggerLabel: string;
  enabled: boolean;
  statusLabel: string;
  trustPosture: string;
  governedProfile: string;
  authorityTierLabel: string;
  availabilityLabel: string;
  sessionScopeLabel: string;
  whyActive: string;
}

export interface SessionHookSnapshot {
  generatedAtMs: number;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  activeHookCount: number;
  disabledHookCount: number;
  runtimeReceiptCount: number;
  approvalReceiptCount: number;
  hooks: SessionHookRecord[];
  recentReceipts: SessionHookReceiptSummary[];
}

export interface SessionBranchRecord {
  branchName: string;
  upstreamBranch?: string | null;
  isCurrent: boolean;
  aheadCount: number;
  behindCount: number;
  lastCommit?: string | null;
}

export interface SessionWorktreeRecord {
  path: string;
  branchName?: string | null;
  head?: string | null;
  lastCommit?: string | null;
  changedFileCount: number;
  dirty: boolean;
  isCurrent: boolean;
  locked: boolean;
  lockReason?: string | null;
  prunable: boolean;
  pruneReason?: string | null;
  statusLabel: string;
  statusDetail: string;
}

export interface SessionBranchSnapshot {
  generatedAtMs: number;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  isRepo: boolean;
  repoLabel?: string | null;
  currentBranch?: string | null;
  upstreamBranch?: string | null;
  lastCommit?: string | null;
  aheadCount: number;
  behindCount: number;
  changedFileCount: number;
  dirty: boolean;
  worktreeRiskLabel: string;
  worktreeRiskDetail: string;
  recentBranches: SessionBranchRecord[];
  worktrees: SessionWorktreeRecord[];
}

export interface SessionRemoteEnvBinding {
  key: string;
  valuePreview: string;
  sourceLabel: string;
  scopeLabel: string;
  provenanceLabel: string;
  secret: boolean;
  redacted: boolean;
}

export interface SessionRemoteEnvSnapshot {
  generatedAtMs: number;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  focusedScopeLabel: string;
  governingSourceLabel: string;
  postureLabel: string;
  postureDetail: string;
  bindingCount: number;
  controlPlaneBindingCount: number;
  processBindingCount: number;
  overlappingBindingCount: number;
  secretBindingCount: number;
  redactedBindingCount: number;
  notes: string[];
  bindings: SessionRemoteEnvBinding[];
}

export interface SessionServerSessionRecord {
  sessionId: string;
  title: string;
  timestamp: number;
  sourceLabel: string;
  presenceState: string;
  presenceLabel: string;
  resumeHint?: string | null;
  workspaceRoot?: string | null;
}

export interface SessionServerSnapshot {
  generatedAtMs: number;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  rpcUrl: string;
  rpcSourceLabel: string;
  continuityModeLabel: string;
  continuityStatusLabel: string;
  continuityDetail: string;
  kernelConnectionLabel: string;
  kernelConnectionDetail: string;
  explicitRpcTarget: boolean;
  remoteKernelTarget: boolean;
  kernelReachable: boolean;
  remoteHistoryAvailable: boolean;
  localSessionCount: number;
  remoteSessionCount: number;
  mergedSessionCount: number;
  remoteOnlySessionCount: number;
  overlappingSessionCount: number;
  remoteAttachableSessionCount: number;
  remoteHistoryOnlySessionCount: number;
  currentSessionVisibleRemotely: boolean;
  currentSessionContinuityState: string;
  currentSessionContinuityLabel: string;
  currentSessionContinuityDetail: string;
  notes: string[];
  recentRemoteSessions: SessionServerSessionRecord[];
}
