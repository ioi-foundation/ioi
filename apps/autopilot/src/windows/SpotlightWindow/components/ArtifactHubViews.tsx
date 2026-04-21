import {
  formatSessionTimeAgo,
  openStudioAssistantWorkbench,
  openStudioPolicyTarget,
  openStudioSessionTarget,
  openStudioShellView,
  type AssistantWorkbenchActivity,
  type AssistantWorkbenchSession,
} from "@ioi/agent-ide";
import { useEffect, useMemo, useRef, useState } from "react";
import type {
  WorkspaceCommitResult,
  WorkspaceSourceControlState,
  WorkspaceNode,
} from "@ioi/workspace-substrate";
import type {
  AgentTask,
  AgentEvent,
  Artifact,
  ArtifactHubViewKey,
  CapabilityRegistrySnapshot,
  CanonicalTraceBundle,
  ClarificationRequest,
  CredentialRequest,
  GateInfo,
  LocalEngineSnapshot,
  LocalEngineStagedOperation,
  PlanSummary,
  SessionBranchSnapshot,
  SessionCompactionPolicy,
  SessionCompactionPruneDecision,
  SessionCompactionSnapshot,
  SessionPluginSnapshot,
  SessionRemoteEnvSnapshot,
  SessionServerSnapshot,
  SessionRewindCandidate,
  SessionRewindSnapshot,
  SessionSummary,
  SessionHookSnapshot,
  SessionFileContext,
  TeamMemorySyncSnapshot,
  SourceBrowseRow,
  SourceSearchRow,
  ThoughtAgentSummary,
} from "../../../types";
import type { AssistantWorkbenchSummary } from "../../../lib/assistantWorkbenchSummary";
import {
  applySessionPermissionProfile,
  buildPolicyDeltaDeck,
  buildPolicyIntentDeltaDeck,
  buildPolicySimulationDeck,
  dataHandlingLabel,
  resolveConnectorPolicy,
  type AutomationPolicyMode,
  type CapabilityGovernanceRequest,
  type ConnectorPolicyOverride,
  type DataHandlingMode,
  type PolicyDecisionMode,
  type SessionPermissionProfileId,
  type ShieldApprovalScopeMode,
  type ShieldRememberedApprovalSnapshot,
  type ShieldPolicyState,
} from "../../ChatWindow/chatPolicyCenter";
import type {
  SpotlightPermissionConnectorOverrideSummary,
  SpotlightPermissionProfileSummary,
} from "../hooks/useSpotlightPermissions";
import type { SpotlightPrivacySnapshot } from "../hooks/useSpotlightPrivacySettings";
import type { SpotlightBranchesStatus } from "../hooks/useSpotlightBranches";
import type { SpotlightLocalEngineStatus } from "../hooks/useSpotlightLocalEngine";
import type { SpotlightPluginsStatus } from "../hooks/useSpotlightPlugins";
import type { SpotlightRemoteEnvStatus } from "../hooks/useSpotlightRemoteEnv";
import type { SpotlightServerModeStatus } from "../hooks/useSpotlightServerMode";
import type { SpotlightSourceControlStatus } from "../hooks/useSpotlightSourceControl";
import { useSpotlightVoiceInput } from "../hooks/useSpotlightVoiceInput";
import type { SpotlightVimModeSnapshot } from "../hooks/useSpotlightVimMode";
import { ArtifactHubCompareView } from "./ArtifactHubCompareView";
import {
  ReviewView,
  SourcesView,
  ThoughtsView,
} from "./ArtifactHubViewRegistry";
import {
  KernelView,
  ScreenshotsView,
  SecurityView,
  SubstrateView,
} from "./ArtifactHubEvidenceViews";
import { ArtifactHubReplayView } from "./ArtifactHubReplayView";
import type {
  KernelLogRow,
  SecurityPolicyRow,
  SubstrateReceiptRow,
} from "./ArtifactHubViewModels";
import type { SpotlightKeybindingSnapshot } from "../hooks/useSpotlightKeybindings";
import type { SpotlightCapabilityRegistryStatus } from "../hooks/useSpotlightCapabilityRegistry";
import type { SpotlightPlaybookRunRecord } from "../hooks/useSpotlightPlaybookRuns";
import type { ReplayTimelineRow } from "./ArtifactHubReplayModel";
import {
  traceBundleExportVariantLabel,
  type TraceBundleExportVariant,
} from "../utils/traceBundleExportModel";
import type { PromotionTarget } from "../utils/promotionStageModel";
import type { DurabilityEvidenceOverview } from "../utils/durabilityEvidenceModel";
import type { PrivacyEvidenceOverview } from "../utils/privacyEvidenceModel";
import { buildRetainedPortfolioDossier } from "../utils/retainedPortfolioDossierModel";
import { buildSavedBundleProofOverview } from "../utils/savedBundleProofModel";
import {
  buildPluginRolloutAutomationPlan,
} from "../utils/pluginRolloutAutomationModel";
import { buildAuthorityAutomationPlan } from "../utils/authorityAutomationModel";
import {
  buildArtifactPipelineAutomationPlan,
  type ArtifactPipelineAutomationQueuedAction,
} from "../utils/artifactPipelineAutomationModel";
import {
  buildRetentionReviewAutomationPlan,
  type RetentionReviewAutomationQueuedAction,
} from "../utils/retentionReviewAutomationModel";
import { buildAuthorityOverrideReviewCards } from "../utils/authorityOverrideReviewModel";
import {
  buildPluginRolloutDossier,
  buildPluginRolloutStageDraft,
} from "../utils/pluginRolloutModel";
import { SpotlightReplView } from "./SpotlightReplView";
import { ArtifactListView, FilesView } from "./ArtifactHubFileViews";
import {
  DoctorView,
  McpView,
  RemoteEnvView,
} from "./ArtifactHubRuntimeViews";
import { PlanView, TasksView } from "./ArtifactHubTaskViews";
import {
  buildVerificationNotes,
  formatTaskTimestamp,
  humanizeStatus,
  taskBlockerSummary,
} from "./ArtifactHubViewHelpers";
import {
  buildCommitOverview,
  type CommitOverviewEntry,
} from "./artifactHubCommitModel";
import {
  buildBranchLifecycleAutomationPlan,
  type BranchLifecycleAutomationQueuedAction,
} from "./artifactHubBranchAutomationModel";
import type { DoctorOverview } from "./artifactHubDoctorModel";
import type { MobileOverview } from "./artifactHubMobileModel";
import { buildHookControlOverview } from "./artifactHubHookControlModel";
import { buildServerOverview } from "./artifactHubServerModel";
import { buildRemoteContinuityGovernanceOverview } from "./artifactHubRemoteContinuityGovernanceModel";
import {
  buildMobileRemoteContinuityPolicyOverview,
  buildServerRemoteContinuityPolicyOverview,
  type RemoteContinuityPolicyAction,
  type RemoteContinuityPolicyOverview,
} from "./artifactHubRemoteContinuityPolicyModel";
import { buildVoiceOverview } from "./artifactHubVoiceModel";
import { buildPrCommentsOverview } from "./artifactHubPrCommentsModel";
import {
  canCompareFocusedRewindCandidate,
  selectFocusedRewindCandidate,
} from "./artifactHubRewindModel";
import {
  buildMobileEvidenceContinuityAction,
  buildRemoteSessionContinuityAction,
  type SpotlightRemoteContinuityLaunchRequest,
} from "./artifactHubRemoteContinuityModel";
import type { ScreenshotReceiptEvidence } from "../utils/screenshotEvidence";
import { getSessionOperatorRuntime } from "../../../services/sessionRuntime";

const DEFAULT_SESSION_COMPACTION_POLICY: SessionCompactionPolicy = {
  carryPinnedOnly: false,
  preserveChecklistState: true,
  preserveBackgroundTasks: true,
  preserveLatestOutputExcerpt: true,
  preserveGovernanceBlockers: true,
  aggressiveTranscriptPruning: false,
};

function compactionPoliciesMatch(
  left: SessionCompactionPolicy,
  right: SessionCompactionPolicy,
): boolean {
  return (
    left.carryPinnedOnly === right.carryPinnedOnly &&
    left.preserveChecklistState === right.preserveChecklistState &&
    left.preserveBackgroundTasks === right.preserveBackgroundTasks &&
    left.preserveLatestOutputExcerpt === right.preserveLatestOutputExcerpt &&
    left.preserveGovernanceBlockers === right.preserveGovernanceBlockers &&
    left.aggressiveTranscriptPruning === right.aggressiveTranscriptPruning
  );
}

const PERMISSION_PROFILE_SHORTCUTS: Record<SessionPermissionProfileId, string> = {
  safer_review: "Alt+1",
  guided_default: "Alt+2",
  autonomous: "Alt+3",
  expert: "Alt+4",
};

const PERMISSION_DECISION_OPTIONS: Array<{
  value: PolicyDecisionMode;
  label: string;
}> = [
  { value: "auto", label: "Auto-run" },
  { value: "confirm", label: "Confirm" },
  { value: "block", label: "Block" },
];

const PERMISSION_AUTOMATION_OPTIONS: Array<{
  value: AutomationPolicyMode;
  label: string;
}> = [
  { value: "confirm_on_create", label: "Confirm on create" },
  { value: "confirm_on_run", label: "Confirm on first run" },
  { value: "manual_only", label: "Manual only" },
];

const PERMISSION_DATA_OPTIONS: Array<{
  value: DataHandlingMode;
  label: string;
}> = [
  { value: "local_only", label: "Local only" },
  { value: "local_redacted", label: "Local with redacted artifacts" },
];

function clipText(value: string, maxChars: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

function formatDuration(durationMs: number): string {
  if (!Number.isFinite(durationMs) || durationMs <= 0) return "0s";
  if (durationMs < 60_000) return `${Math.max(1, Math.round(durationMs / 1000))}s`;
  if (durationMs < 3_600_000) return `${Math.round(durationMs / 60_000)}m`;
  return `${Math.round(durationMs / 3_600_000)}h`;
}

function compactionDispositionLabel(
  disposition: SessionCompactionPruneDecision["disposition"],
): string {
  switch (disposition) {
    case "carry_forward":
      return "Carry forward";
    case "retained_summary":
      return "Retained in summary";
    case "pruned":
      return "Pruned from resume context";
    default:
      return disposition;
  }
}

function compactionDecisionCounts(
  decisions: SessionCompactionPruneDecision[] | undefined | null,
): Record<SessionCompactionPruneDecision["disposition"], number> {
  return (decisions ?? []).reduce<
    Record<SessionCompactionPruneDecision["disposition"], number>
  >(
    (acc, decision) => {
      acc[decision.disposition] = (acc[decision.disposition] || 0) + 1;
      return acc;
    },
    {
      carry_forward: 0,
      retained_summary: 0,
      pruned: 0,
    },
  );
}

function compactionCarryModeLabel(policy: SessionCompactionPolicy): string {
  return policy.carryPinnedOnly ? "Pinned only" : "Pinned + scoped files";
}

function compactionTranscriptLabel(policy: SessionCompactionPolicy): string {
  return policy.aggressiveTranscriptPruning
    ? "Aggressive prune"
    : "Summary-retained";
}

function compactionPolicySummaryBits(policy: SessionCompactionPolicy): string[] {
  return [
    `Checklist: ${policy.preserveChecklistState ? "keep" : "prune"}`,
    `Background: ${policy.preserveBackgroundTasks ? "keep" : "prune"}`,
    `Output: ${policy.preserveLatestOutputExcerpt ? "keep" : "prune"}`,
    `Blockers: ${policy.preserveGovernanceBlockers ? "keep" : "prune"}`,
  ];
}

function compactionResumeSafetyLabel(status: "protected" | "degraded"): string {
  return status === "protected" ? "Resume safety: Protected" : "Resume safety: Degraded";
}

function teamMemorySyncStatusLabel(status: string): string {
  switch (status) {
    case "review_required":
      return "Review required";
    case "redacted":
      return "Redacted";
    case "synced":
      return "Synced";
    default:
      return status;
  }
}

interface ArtifactHubDetailViewProps {
  activeView: ArtifactHubViewKey;
  activeSessionId?: string | null;
  exportSessionId?: string | null;
  exportStatus: string;
  exportError: string | null;
  exportPath: string | null;
  exportTimestampMs: number | null;
  exportVariant: TraceBundleExportVariant | null;
  durabilityOverview: DurabilityEvidenceOverview;
  privacyOverview: PrivacyEvidenceOverview;
  keybindingSnapshot: SpotlightKeybindingSnapshot;
  vimModeSnapshot: SpotlightVimModeSnapshot;
  compactionSnapshot: SessionCompactionSnapshot | null;
  compactionPolicy: SessionCompactionPolicy;
  compactionStatus: string;
  compactionError: string | null;
  teamMemorySnapshot: TeamMemorySyncSnapshot | null;
  teamMemoryStatus: string;
  teamMemoryError: string | null;
  teamMemoryIncludeGovernanceCritical: boolean;
  localEngineSnapshot: LocalEngineSnapshot | null;
  localEngineStatus: SpotlightLocalEngineStatus;
  localEngineError: string | null;
  doctorOverview: DoctorOverview;
  currentTask: AgentTask | null;
  sessions: SessionSummary[];
  replayBundle: CanonicalTraceBundle | null;
  replayLoading: boolean;
  replayError: string | null;
  replayRows: ReplayTimelineRow[];
  planSummary: PlanSummary | null;
  searches: SourceSearchRow[];
  browses: SourceBrowseRow[];
  thoughtAgents: ThoughtAgentSummary[];
  playbookRuns: SpotlightPlaybookRunRecord[];
  playbookRunsLoading: boolean;
  playbookRunsBusyRunId: string | null;
  playbookRunsMessage: string | null;
  playbookRunsError: string | null;
  stagedOperations: LocalEngineStagedOperation[];
  stagedOperationsLoading: boolean;
  stagedOperationsBusyId: string | null;
  stagedOperationsMessage: string | null;
  stagedOperationsError: string | null;
  visibleSourceCount: number;
  kernelLogs: KernelLogRow[];
  securityRows: SecurityPolicyRow[];
  fileArtifacts: Artifact[];
  revisionArtifacts: Artifact[];
  fileContext: SessionFileContext | null;
  fileContextStatus: string;
  fileContextError: string | null;
  fileBrowsePath: string;
  fileBrowseEntries: WorkspaceNode[];
  fileBrowseStatus: string;
  fileBrowseError: string | null;
  branchSnapshot: SessionBranchSnapshot | null;
  branchStatus: SpotlightBranchesStatus;
  branchError: string | null;
  sourceControlState: WorkspaceSourceControlState | null;
  sourceControlStatus: SpotlightSourceControlStatus;
  sourceControlError: string | null;
  sourceControlLastCommitReceipt: WorkspaceCommitResult | null;
  assistantWorkbench: AssistantWorkbenchSession | null;
  activeWorkbenchSummary: AssistantWorkbenchSummary | null;
  retainedWorkbenchActivities: AssistantWorkbenchActivity[];
  retainedWorkbenchEvidenceThreadId: string | null;
  retainedWorkbenchTraceLoading: boolean;
  retainedWorkbenchTraceError: string | null;
  retainedWorkbenchEventCount: number;
  retainedWorkbenchArtifactCount: number;
  latestRetainedWorkbenchEvent: AgentEvent | null;
  latestRetainedWorkbenchArtifact: Artifact | null;
  retainedWorkbenchEvidenceAttachable: boolean;
  mobileOverview: MobileOverview;
  replLaunchRequest: SpotlightRemoteContinuityLaunchRequest | null;
  onSeedIntent?: (intent: string) => void;
  capabilityRegistrySnapshot: CapabilityRegistrySnapshot | null;
  capabilityRegistryStatus: SpotlightCapabilityRegistryStatus;
  capabilityRegistryError: string | null;
  pluginSnapshot: SessionPluginSnapshot | null;
  pluginStatus: SpotlightPluginsStatus;
  pluginError: string | null;
  serverSnapshot: SessionServerSnapshot | null;
  serverStatus: SpotlightServerModeStatus;
  serverError: string | null;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null;
  remoteEnvStatus: SpotlightRemoteEnvStatus;
  remoteEnvError: string | null;
  rewindSnapshot: SessionRewindSnapshot | null;
  rewindStatus: string;
  rewindError: string | null;
  selectedRewindSessionId: string | null;
  compareTargetSessionId: string | null;
  hookSnapshot: SessionHookSnapshot | null;
  hooksStatus: string;
  hooksError: string | null;
  privacySnapshot: SpotlightPrivacySnapshot;
  permissionsStatus: string;
  permissionsError: string | null;
  permissionPolicyState: ShieldPolicyState;
  permissionGovernanceRequest: CapabilityGovernanceRequest | null;
  permissionConnectorOverrides: SpotlightPermissionConnectorOverrideSummary[];
  permissionActiveOverrideCount: number;
  permissionProfiles: SpotlightPermissionProfileSummary[];
  permissionCurrentProfileId: SessionPermissionProfileId | null;
  permissionApplyingProfileId: SessionPermissionProfileId | null;
  permissionEditingConnectorId: string | null;
  permissionApplyingGovernanceRequest: boolean;
  permissionRememberedApprovals: ShieldRememberedApprovalSnapshot | null;
  screenshotReceipts: ScreenshotReceiptEvidence[];
  substrateReceipts: SubstrateReceiptRow[];
  onOpenArtifact?: (artifactId: string) => void;
  onRetryPlaybookRun?: (runId: string) => void;
  onResumePlaybookRun?: (runId: string, stepId?: string | null) => void;
  onDismissPlaybookRun?: (runId: string) => void;
  onMessageWorkerSession?: (
    runId: string,
    sessionId: string,
    message: string,
  ) => void;
  onStopWorkerSession?: (runId: string, sessionId: string) => void;
  onPromoteRunResult?: (runId: string) => void;
  onPromoteStepResult?: (runId: string, stepId: string) => void;
  onPromoteStagedOperation?: (operationId: string) => void;
  onRemoveStagedOperation?: (operationId: string) => void;
  onLoadSession?: (sessionId: string) => void;
  onStopSession?: () => void;
  onOpenGate?: () => void;
  isGated?: boolean;
  gateInfo?: GateInfo;
  isPiiGate?: boolean;
  gateDeadlineMs?: number;
  gateActionError?: string | null;
  credentialRequest?: CredentialRequest;
  clarificationRequest?: ClarificationRequest;
  onApprove?: () => void;
  onGrantScopedException?: () => void;
  onDeny?: () => void;
  onSubmitRuntimePassword?: (password: string) => Promise<void>;
  onCancelRuntimePassword?: () => void;
  onSubmitClarification?: (optionId: string, otherText: string) => Promise<void>;
  onCancelClarification?: () => void;
  onRefreshRewind?: () => Promise<unknown>;
  onSelectRewindSession?: (sessionId: string | null) => void;
  onOpenCompareForSession?: (sessionId: string | null) => void;
  onRefreshCompaction?: () => Promise<unknown>;
  onRefreshDoctor?: () => Promise<unknown>;
  onCompactSession?: (
    sessionId?: string | null,
    policy?: SessionCompactionPolicy,
  ) => Promise<unknown>;
  onSetTeamMemoryIncludeGovernanceCritical?: (value: boolean) => void;
  onRefreshTeamMemory?: () => Promise<unknown>;
  onSyncTeamMemory?: () => Promise<unknown>;
  onForgetTeamMemoryEntry?: (entryId: string) => Promise<unknown>;
  onUpdateCompactionPolicy?: (
    policy: SessionCompactionPolicy,
  ) => Promise<unknown>;
  onResetCompactionPolicy?: () => Promise<unknown>;
  onExportBundle?: (variant?: TraceBundleExportVariant) => Promise<unknown>;
  promotionStageBusyTarget: PromotionTarget | null;
  promotionStageMessage: string | null;
  promotionStageError: string | null;
  onStagePromotionCandidate?: (target: PromotionTarget) => Promise<unknown>;
  onRefreshPlugins?: () => Promise<unknown>;
  onTrustPlugin?: (
    pluginId: string,
    enableAfterTrust?: boolean,
  ) => Promise<unknown>;
  onSetPluginEnabled?: (
    pluginId: string,
    enabled: boolean,
  ) => Promise<unknown>;
  onReloadPlugin?: (pluginId: string) => Promise<unknown>;
  onRefreshPluginCatalog?: (pluginId: string) => Promise<unknown>;
  onRevokePluginTrust?: (pluginId: string) => Promise<unknown>;
  onInstallPluginPackage?: (pluginId: string) => Promise<unknown>;
  onUpdatePluginPackage?: (pluginId: string) => Promise<unknown>;
  onRemovePluginPackage?: (pluginId: string) => Promise<unknown>;
  onRefreshServer?: () => Promise<unknown>;
  onRefreshRemoteEnv?: () => Promise<unknown>;
  onRefreshHooks?: () => Promise<unknown>;
  onRefreshPermissions?: () => Promise<unknown>;
  onApplyPermissionProfile?: (
    profileId: SessionPermissionProfileId,
  ) => Promise<unknown>;
  onApplyPermissionGovernanceRequest?: () => Promise<unknown>;
  onDismissPermissionGovernanceRequest?: () => Promise<unknown>;
  onForgetRememberedApproval?: (decisionId: string) => Promise<unknown>;
  onUpdatePermissionOverride?: (
    connectorId: string,
    nextOverride: Partial<ConnectorPolicyOverride>,
  ) => Promise<unknown>;
  onResetPermissionOverride?: (connectorId: string) => Promise<unknown>;
  onSetRememberedApprovalScopeMode?: (
    decisionId: string,
    scopeMode: ShieldApprovalScopeMode,
  ) => Promise<unknown>;
  onSetRememberedApprovalExpiry?: (
    decisionId: string,
    expiresAtMs: number | null,
  ) => Promise<unknown>;
  onToggleVimMode?: () => void;
  onRequestReplLaunch?: (
    request: SpotlightRemoteContinuityLaunchRequest,
  ) => void;
  onHandleReplLaunchRequest?: () => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  onRefreshFileContext?: () => Promise<unknown>;
  onRefreshBranches?: () => Promise<unknown>;
  onCreateBranchWorktree?: (
    branchName: string,
    options?: {
      startPoint?: string | null;
      worktreeName?: string | null;
    },
  ) => Promise<unknown>;
  onSwitchBranchWorktree?: (targetWorkspaceRoot: string) => Promise<unknown>;
  onRemoveBranchWorktree?: (targetWorkspaceRoot: string) => Promise<unknown>;
  onRefreshSourceControl?: () => Promise<unknown>;
  onStageSourceControlPath?: (path: string) => Promise<unknown>;
  onStageAllSourceControl?: () => Promise<unknown>;
  onUnstageSourceControlPath?: (path: string) => Promise<unknown>;
  onUnstageAllSourceControl?: () => Promise<unknown>;
  onDiscardSourceControlPath?: (path: string) => Promise<unknown>;
  onDiscardAllWorkingSourceControl?: () => Promise<unknown>;
  onCommitSourceControl?: (
    headline: string,
    body?: string | null,
  ) => Promise<unknown>;
  onOpenFileDirectory?: (path: string) => void;
  onBrowseFileParent?: () => void;
  onRememberFilePath?: (path: string) => Promise<unknown>;
  onPinFilePath?: (path: string) => Promise<unknown>;
  onIncludeFilePath?: (path: string) => Promise<unknown>;
  onExcludeFilePath?: (path: string) => Promise<unknown>;
  onRemoveFilePath?: (path: string) => Promise<unknown>;
  onClearFileContext?: () => Promise<unknown>;
  openExternalUrl: (url: string) => Promise<void>;
  extractArtifactUrl: (artifact: Artifact) => string | null;
  formatTimestamp: (value: string) => string;
}

function approvalScopeModeLabel(
  scopeMode: ShieldApprovalScopeMode,
  policyFamily: string,
): string {
  if (scopeMode === "connector_policy_family") {
    return `${humanizeStatus(policyFamily)} family`;
  }
  return "Exact action";
}

function sessionWorkspaceLabel(workspaceRoot?: string | null): string | null {
  const trimmed = workspaceRoot?.trim();
  if (!trimmed) {
    return null;
  }

  const normalized = trimmed.replace(/\\/g, "/");
  const segments = normalized.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? normalized;
}

function sessionRewindSubtitle(candidate: SessionRewindCandidate): string | null {
  const parts = [
    candidate.phase,
    candidate.currentStep,
    candidate.resumeHint,
    sessionWorkspaceLabel(candidate.workspaceRoot),
  ].filter((value): value is string => Boolean(value?.trim()));
  return parts.length > 0 ? parts.join(" · ") : null;
}

function policyTone(value: string | null | undefined): string {
  const normalized = (value || "").trim().toLowerCase();
  if (normalized === "auto") return "auto";
  if (normalized === "confirm" || normalized === "gate") return "gate";
  if (normalized === "block" || normalized === "deny") return "deny";
  return "neutral";
}

function permissionSimulationOutcomeLabel(value: "auto" | "gate" | "deny"): string {
  switch (value) {
    case "auto":
      return "Auto";
    case "gate":
      return "Gate";
    case "deny":
      return "Deny";
  }
}

function PermissionPolicySelect<T extends string>({
  label,
  value,
  options,
  disabled = false,
  onChange,
}: {
  label: string;
  value: T;
  options: Array<{ value: T; label: string }>;
  disabled?: boolean;
  onChange: (next: T) => void;
}) {
  return (
    <label className="artifact-hub-permissions-field">
      <span>{label}</span>
      <select
        className="artifact-hub-commit-input"
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value as T)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function CompactView({
  snapshot,
  status,
  error,
  policy,
  teamMemorySnapshot,
  teamMemoryStatus,
  teamMemoryError,
  teamMemoryIncludeGovernanceCritical,
  onRefreshCompaction,
  onCompactSession,
  onSetTeamMemoryIncludeGovernanceCritical,
  onRefreshTeamMemory,
  onSyncTeamMemory,
  onForgetTeamMemoryEntry,
  onUpdateCompactionPolicy,
  onResetCompactionPolicy,
  onOpenView,
}: {
  snapshot: SessionCompactionSnapshot | null;
  status: string;
  error: string | null;
  policy: SessionCompactionPolicy;
  teamMemorySnapshot: TeamMemorySyncSnapshot | null;
  teamMemoryStatus: string;
  teamMemoryError: string | null;
  teamMemoryIncludeGovernanceCritical: boolean;
  onRefreshCompaction?: () => Promise<unknown>;
  onCompactSession?: (
    sessionId?: string | null,
    policy?: SessionCompactionPolicy,
  ) => Promise<unknown>;
  onSetTeamMemoryIncludeGovernanceCritical?: (value: boolean) => void;
  onRefreshTeamMemory?: () => Promise<unknown>;
  onSyncTeamMemory?: () => Promise<unknown>;
  onForgetTeamMemoryEntry?: (entryId: string) => Promise<unknown>;
  onUpdateCompactionPolicy?: (
    policy: SessionCompactionPolicy,
  ) => Promise<unknown>;
  onResetCompactionPolicy?: () => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const activeTitle = snapshot?.activeSessionTitle?.trim() || "No active retained session";
  const latest = snapshot?.latestForActive || null;
  const preview = snapshot?.previewForActive || null;
  const activePolicy = preview?.policy ?? snapshot?.policyForActive ?? policy;
  const policyIsDefault = compactionPoliciesMatch(
    activePolicy,
    DEFAULT_SESSION_COMPACTION_POLICY,
  );
  const teamMemoryEntries = teamMemorySnapshot?.entries ?? [];
  const teamMemoryBusy =
    teamMemoryStatus === "syncing" || teamMemoryStatus === "forgetting";
  const teamMemoryScopeLabel =
    teamMemorySnapshot?.activeScopeLabel?.trim() || "Current scope";
  const portfolio = snapshot?.durabilityPortfolio || null;
  const retentionReviewPlan = useMemo(
    () =>
      buildRetentionReviewAutomationPlan({
        compactionSnapshot: snapshot,
        teamMemorySnapshot,
      }),
    [snapshot, teamMemorySnapshot],
  );
  const memoryControls: Array<{
    key: keyof SessionCompactionPolicy;
    label: string;
    description: string;
  }> = [
    {
      key: "carryPinnedOnly",
      label: "Pinned files only",
      description: "Prune explicit include and exclude paths from carried-forward state.",
    },
    {
      key: "preserveChecklistState",
      label: "Keep checklist",
      description: "Carry the operator checklist into the compacted resume context.",
    },
    {
      key: "preserveBackgroundTasks",
      label: "Keep background tasks",
      description: "Retain labels for parallel work that is still in flight.",
    },
    {
      key: "preserveLatestOutputExcerpt",
      label: "Keep latest output",
      description: "Retain a short output excerpt in the compacted summary.",
    },
    {
      key: "preserveGovernanceBlockers",
      label: "Keep blockers",
      description: "Carry pending approvals or governance blockers forward explicitly.",
    },
    {
      key: "aggressiveTranscriptPruning",
      label: "Aggressive transcript pruning",
      description: "Drop conversational texture from the summary and keep only the compacted anchor.",
    },
  ];
  const records = snapshot?.records ?? [];
  const recommendation = snapshot?.recommendationForActive || null;
  const recommendedPolicy = recommendation?.recommendedPolicy ?? null;
  const recommendedPolicyMatches = recommendedPolicy
    ? compactionPoliciesMatch(activePolicy, recommendedPolicy)
    : false;
  const autoStateLabel = recommendation?.shouldCompact
    ? "Recommended now"
    : latest?.mode === "auto"
      ? "Recently auto-compacted"
      : "Monitoring";
  const latestModeLabel =
    latest?.mode === "auto" ? "Auto compaction" : "Manual compaction";
  const reasonLabels = recommendation?.reasonLabels ?? [];
  const memoryClassCounts = latest?.carriedForwardState.memoryItems.reduce<
    Record<string, number>
  >((acc, item) => {
    acc[item.memoryClass] = (acc[item.memoryClass] || 0) + 1;
    return acc;
  }, {});
  const previewDecisionCounts = compactionDecisionCounts(preview?.pruneDecisions);
  const latestDecisionCounts = compactionDecisionCounts(latest?.pruneDecisions);

  async function runRetentionReviewAction(action: RetentionReviewAutomationQueuedAction) {
    switch (action.kind) {
      case "compact_active_session":
        if (onCompactSession) {
          await onCompactSession(snapshot?.activeSessionId || null, activePolicy);
        }
        break;
      case "sync_team_memory":
        if (onSyncTeamMemory) {
          await onSyncTeamMemory();
        }
        break;
      case "open_view":
        if (action.recommendedView && onOpenView) {
          onOpenView(action.recommendedView);
        }
        break;
    }
  }

  function canRunRetentionReviewAction(action: RetentionReviewAutomationQueuedAction) {
    switch (action.kind) {
      case "compact_active_session":
        return Boolean(onCompactSession);
      case "sync_team_memory":
        return Boolean(onSyncTeamMemory);
      case "open_view":
        return Boolean(action.recommendedView && onOpenView);
    }
  }

  return (
    <div className="artifact-hub-rewind">
      <section className="artifact-hub-files-identity artifact-hub-rewind__identity">
        <span className="artifact-hub-files-kicker">Compact</span>
        <strong>Conversation compaction</strong>
        <p>
          Capture a resumable session summary with carried-forward file context,
          blockers, and resume anchors so long-running work stays reloadable
          across Spotlight, Studio, and the standalone REPL.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Status: {humanizeStatus(status)}</span>
          <span>{snapshot?.recordCount ?? 0} retained compaction records</span>
          <span>Active: {activeTitle}</span>
          <span>Auto policy: {autoStateLabel}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Retention review automation</strong>
          <span className="artifact-hub-policy-pill">
            {retentionReviewPlan.statusLabel}
          </span>
        </div>
        <p>{retentionReviewPlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {retentionReviewPlan.checklist.map((label) => (
            <span key={label}>{label}</span>
          ))}
        </div>
        {retentionReviewPlan.queuedActions.length > 0 ? (
          <div className="artifact-hub-generic-list">
            {retentionReviewPlan.queuedActions.map((action, index) => (
              <article
                className="artifact-hub-generic-row"
                key={`${action.kind}:${action.recommendedView ?? index}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{index === 0 ? "Primary" : "Queued"}</span>
                  <span>{humanizeStatus(retentionReviewPlan.tone)}</span>
                  <span>
                    {action.recommendedView
                      ? humanizeStatus(action.recommendedView)
                      : humanizeStatus(action.kind)}
                  </span>
                </div>
                <div className="artifact-hub-generic-title">{action.label}</div>
                <p className="artifact-hub-generic-summary">{action.detail}</p>
                {canRunRetentionReviewAction(action) ? (
                  <div className="artifact-hub-generic-actions">
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      onClick={() => {
                        void runRetentionReviewAction(action);
                      }}
                    >
                      {action.label}
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        ) : null}
      </section>

      {portfolio ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Cross-session durability</strong>
            <span className="artifact-hub-policy-pill">
              {portfolio.replayReadySessionCount}/{portfolio.retainedSessionCount} replay-ready
            </span>
          </div>
          <p>{portfolio.coverageSummary}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>Compacted: {portfolio.compactedSessionCount}</span>
            <span>Uncompacted: {portfolio.uncompactedSessionCount}</span>
            <span>Stale: {portfolio.staleCompactionCount}</span>
            <span>Degraded: {portfolio.degradedCompactionCount}</span>
            <span>Recommended now: {portfolio.recommendedCompactionCount}</span>
          </div>
          <p className="artifact-hub-note">{portfolio.teamMemorySummary}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>
              Team memory sessions: {portfolio.teamMemoryCoveredSessionCount}
            </span>
            <span>Entries: {portfolio.teamMemoryEntryCount}</span>
            <span>
              Review required: {portfolio.teamMemoryReviewRequiredSessionCount}
            </span>
            <span>
              Redacted sessions: {portfolio.teamMemoryRedactedSessionCount}
            </span>
            <span>
              Missing sync: {portfolio.compactedWithoutTeamMemoryCount}
            </span>
          </div>
          {portfolio.attentionLabels.length > 0 ? (
            <>
              <p className="artifact-hub-note">{portfolio.attentionSummary}</p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                {portfolio.attentionLabels.map((label) => (
                  <span key={label}>{label}</span>
                ))}
              </div>
            </>
          ) : (
            <p className="artifact-hub-note">
              Fresh protected compaction records and scoped team-memory coverage
              are aligned across the retained portfolio.
            </p>
          )}
        </section>
      ) : null}

      {recommendation ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Auto compaction policy</strong>
            <span className="artifact-hub-policy-pill">{autoStateLabel}</span>
          </div>
          <p>
            Conservative auto mode watches session scale, carried-forward file
            context, and blocker or idle age before capturing a resumable
            summary.
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>History: {recommendation.historyCount}</span>
            <span>Events: {recommendation.eventCount}</span>
            <span>Artifacts: {recommendation.artifactCount}</span>
            <span>Includes: {recommendation.explicitIncludeCount}</span>
            <span>Idle: {formatDuration(recommendation.idleAgeMs)}</span>
          </div>
          {reasonLabels.length > 0 ? (
            <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
              {reasonLabels.map((reason) => (
                <span key={reason}>{reason}</span>
              ))}
            </div>
          ) : (
            <p className="artifact-hub-note">
              No compaction threshold is active right now.
            </p>
          )}
        </section>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Memory controls</strong>
          <span className="artifact-hub-policy-pill">
            {policyIsDefault ? "Default manual policy" : "Custom manual policy"}
          </span>
        </div>
        <p>
          Tune what the preview and the next manual compaction pass will carry
          forward. Conservative auto compaction keeps using the default policy.
        </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>
              Carry mode: {compactionCarryModeLabel(activePolicy)}
            </span>
            <span>Transcript: {compactionTranscriptLabel(activePolicy)}</span>
            {compactionPolicySummaryBits(activePolicy).map((label) => (
              <span key={label}>{label}</span>
            ))}
          </div>
        <div className="artifact-hub-compact-policy-list">
          {memoryControls.map((control) => (
            <label className="artifact-hub-compact-policy-toggle" key={control.key}>
              <input
                type="checkbox"
                checked={activePolicy[control.key]}
                disabled={!onUpdateCompactionPolicy || status === "compacting"}
                onChange={() => {
                  if (!onUpdateCompactionPolicy) {
                    return;
                  }
                  void onUpdateCompactionPolicy({
                    ...activePolicy,
                    [control.key]: !activePolicy[control.key],
                  });
                }}
              />
              <span className="artifact-hub-compact-policy-copy">
                <strong>{control.label}</strong>
                <span>{control.description}</span>
              </span>
            </label>
          ))}
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {recommendedPolicy && onUpdateCompactionPolicy ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={recommendedPolicyMatches || status === "compacting"}
              onClick={() => {
                void onUpdateCompactionPolicy(recommendedPolicy);
              }}
            >
              {recommendedPolicyMatches
                ? "Recommended policy active"
                : "Apply recommended policy"}
            </button>
          ) : null}
          {onResetCompactionPolicy ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={policyIsDefault || status === "compacting"}
              onClick={() => {
                void onResetCompactionPolicy();
              }}
            >
              Reset defaults
            </button>
          ) : null}
        </div>
      </section>

      {recommendation ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Recommended manual policy</strong>
            <span className="artifact-hub-policy-pill">
              {recommendedPolicyMatches
                ? "Recommendation applied"
                : recommendation.recommendedPolicyLabel}
            </span>
          </div>
          <p>
            Use the recommended policy when you want the preview and the next
            manual compaction pass to follow the safest current resume posture.
          </p>
          {recommendedPolicy ? (
            <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
              <span>Carry mode: {compactionCarryModeLabel(recommendedPolicy)}</span>
              <span>Transcript: {compactionTranscriptLabel(recommendedPolicy)}</span>
              {compactionPolicySummaryBits(recommendedPolicy).map((label) => (
                <span key={`recommended-${label}`}>{label}</span>
              ))}
            </div>
          ) : null}
          {recommendation.recommendedPolicyReasonLabels.length > 0 ? (
            <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
              {recommendation.recommendedPolicyReasonLabels.map((reason) => (
                <span key={reason}>{reason}</span>
              ))}
            </div>
          ) : null}
          {recommendation.resumeSafeguardLabels.length > 0 ? (
            <>
              <p className="artifact-hub-note">
                Resume safeguards the recommendation is protecting:
              </p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                {recommendation.resumeSafeguardLabels.map((label) => (
                  <span key={label}>{label}</span>
                ))}
              </div>
            </>
          ) : null}
        </section>
      ) : null}

      {preview ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Compaction preview</strong>
            <span className="artifact-hub-policy-pill">If compacted now</span>
          </div>
          <p>
            Preview what the active session would keep, summarize, and prune
            from the carried-forward resume context. Pruned here means omitted
            from the compacted resume context, not deleted from retained evidence.
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>
              Carry forward: {previewDecisionCounts.carry_forward}
            </span>
            <span>
              Summary-retained: {previewDecisionCounts.retained_summary}
            </span>
            <span>Pruned: {previewDecisionCounts.pruned}</span>
            <span>{compactionResumeSafetyLabel(preview.resumeSafety.status)}</span>
            <span>{preview.preCompactionSpan}</span>
          </div>
          {preview.resumeSafety.reasons.length > 0 ? (
            <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
              {preview.resumeSafety.reasons.map((reason) => (
                <span key={reason}>{reason}</span>
              ))}
            </div>
          ) : null}
          <div className="artifact-hub-generic-list">
            {preview.pruneDecisions.map((decision) => (
              <article className="artifact-hub-generic-row" key={decision.key}>
                <div className="artifact-hub-generic-meta">
                  <span>{decision.label}</span>
                  <span>{compactionDispositionLabel(decision.disposition)}</span>
                  <span>{decision.detailCount} item(s)</span>
                </div>
                <div className="artifact-hub-generic-title">{decision.summary}</div>
                <p className="artifact-hub-generic-summary">{decision.rationale}</p>
                {decision.examples.length > 0 ? (
                  <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                    {decision.examples.map((example) => (
                      <span key={`${decision.key}:${example}`}>
                        {clipText(example, 72)}
                      </span>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Team memory sync</strong>
          <span className="artifact-hub-policy-pill">
            {teamMemoryBusy
              ? "Updating"
              : teamMemorySnapshot
                ? `${teamMemorySnapshot.entryCount} in scope`
                : "No scope"}
          </span>
        </div>
        <p>
          Promote carried-forward session memory into a scoped multi-actor ledger
          that preserves runtime truth, keeps governance-critical items local by
          default, and redacts sensitive values before shared sync.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Scope: {teamMemoryScopeLabel}</span>
          <span>Entries: {teamMemorySnapshot?.entryCount ?? 0}</span>
          <span>Redacted: {teamMemorySnapshot?.redactedEntryCount ?? 0}</span>
          <span>
            Review required: {teamMemorySnapshot?.reviewRequiredCount ?? 0}
          </span>
        </div>
        <p className="artifact-hub-note">
          {teamMemorySnapshot?.summary ||
            "Sync the active retained session to create the first shared team-memory entry."}
        </p>
        <label className="artifact-hub-compact-policy-toggle">
          <input
            type="checkbox"
            checked={teamMemoryIncludeGovernanceCritical}
            disabled={!onSetTeamMemoryIncludeGovernanceCritical || teamMemoryBusy}
            onChange={() =>
              onSetTeamMemoryIncludeGovernanceCritical?.(
                !teamMemoryIncludeGovernanceCritical,
              )
            }
          />
          <span className="artifact-hub-compact-policy-copy">
            <strong>Include governance-critical blockers</strong>
            <span>
              Keep this off for the safer default. When enabled, blocker and
              approval context sync into team memory but stay flagged for review.
            </span>
          </span>
        </label>
        {teamMemoryError ? (
          <p className="artifact-hub-error">{teamMemoryError}</p>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {onSyncTeamMemory ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={teamMemoryBusy}
              onClick={() => {
                void onSyncTeamMemory();
              }}
            >
              Sync active session
            </button>
          ) : null}
          {onRefreshTeamMemory ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={teamMemoryBusy}
              onClick={() => {
                void onRefreshTeamMemory();
              }}
            >
              Refresh team memory
            </button>
          ) : null}
        </div>
        {teamMemoryEntries.length > 0 ? (
          <div className="artifact-hub-generic-list">
            {teamMemoryEntries.map((entry) => (
              <article className="artifact-hub-generic-row" key={entry.entryId}>
                <div className="artifact-hub-generic-meta">
                  <span>{entry.scopeLabel}</span>
                  <span>{entry.actorLabel}</span>
                  <span>{formatSessionTimeAgo(entry.syncedAtMs)}</span>
                  <span>{teamMemorySyncStatusLabel(entry.syncStatus)}</span>
                </div>
                <div className="artifact-hub-generic-title">{entry.resumeAnchor}</div>
                <p className="artifact-hub-generic-summary">{entry.summary}</p>
                <p className="artifact-hub-generic-summary">{entry.reviewSummary}</p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>
                    Redactions: {entry.redaction.redactionCount}
                  </span>
                  <span>
                    Governance held local: {entry.omittedGovernanceItemCount}
                  </span>
                  <span>
                    Shared items: {entry.sharedMemoryItems.length}
                  </span>
                  {entry.redaction.redactedFields.map((field) => (
                    <span key={`${entry.entryId}:${field}`}>{field}</span>
                  ))}
                </div>
                {entry.sharedMemoryItems.length > 0 ? (
                  <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                    {entry.sharedMemoryItems.slice(0, 4).map((item) => (
                      <span key={`${entry.entryId}:${item.key}`}>
                        {item.label}: {item.values.join(" | ")}
                      </span>
                    ))}
                  </div>
                ) : null}
                {onForgetTeamMemoryEntry ? (
                  <div className="artifact-hub-permissions-card__actions">
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={teamMemoryBusy}
                      onClick={() => {
                        void onForgetTeamMemoryEntry(entry.entryId);
                      }}
                    >
                      Forget entry
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        ) : (
          <p className="artifact-hub-empty">
            No scoped team-memory entries are stored yet. Sync the active
            session after a meaningful run to retain shared memory with runtime
            redaction and governance posture.
          </p>
        )}
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Manual compaction</strong>
          <span className="artifact-hub-policy-pill">
            {latest ? formatSessionTimeAgo(latest.compactedAtMs) : "Not compacted yet"}
          </span>
        </div>
        <p>
          Run one manual compaction pass against the active retained session,
          then use the stored resume anchor and carried-forward state from any shell.
        </p>
        {latest ? (
          <div className="artifact-hub-generic-list">
            <article className="artifact-hub-generic-row">
              <div className="artifact-hub-generic-meta">
                <span>{latest.title}</span>
                <span>{latestModeLabel}</span>
                <span>{latest.preCompactionSpan}</span>
              </div>
              <div className="artifact-hub-generic-title">{latest.resumeAnchor}</div>
              <p className="artifact-hub-generic-summary">{latest.summary}</p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                <span>
                  Memory classes: {Object.keys(memoryClassCounts ?? {}).length || 0}
                </span>
                <span>
                  Governance: {memoryClassCounts?.governance_critical || 0}
                </span>
                <span>Pinned: {memoryClassCounts?.pinned || 0}</span>
                <span>
                  Carry-forward: {memoryClassCounts?.carry_forward || 0}
                </span>
                <span>Summary-retained: {latestDecisionCounts.retained_summary}</span>
                <span>Pruned: {latestDecisionCounts.pruned}</span>
                <span>{compactionResumeSafetyLabel(latest.resumeSafety.status)}</span>
              </div>
              {latest.resumeSafety.reasons.length > 0 ? (
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  {latest.resumeSafety.reasons.map((reason) => (
                    <span key={reason}>{reason}</span>
                  ))}
                </div>
              ) : null}
            </article>
          </div>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {onCompactSession ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onCompactSession(snapshot?.activeSessionId || null, activePolicy);
              }}
            >
              Compact active session
            </button>
          ) : null}
          {onRefreshCompaction ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => {
                void onRefreshCompaction();
              }}
            >
              Refresh compaction state
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("repl")}
            >
              Open REPL
            </button>
          ) : null}
        </div>
      </section>

      {records.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Retained compaction records</span>
            <span>{records.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {records.map((record) => (
              <article className="artifact-hub-generic-row" key={record.compactionId}>
                <div className="artifact-hub-generic-meta">
                  <span>{record.title}</span>
                  <span>{formatSessionTimeAgo(record.compactedAtMs)}</span>
                  <span>{record.mode === "auto" ? "Auto" : "Manual"}</span>
                  {record.phase ? <span>{record.phase}</span> : null}
                </div>
                <div className="artifact-hub-generic-title">{record.resumeAnchor}</div>
                <p className="artifact-hub-generic-summary">{record.preCompactionSpan}</p>
                <p className="artifact-hub-generic-summary">{record.summary}</p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>
                    Root: {record.carriedForwardState.workspaceRoot || "No workspace"}
                  </span>
                  <span>
                    Pins: {record.carriedForwardState.pinnedFiles.length}
                  </span>
                  <span>
                    Includes: {record.carriedForwardState.explicitIncludes.length}
                  </span>
                  <span>
                    Memory items: {record.carriedForwardState.memoryItems.length}
                  </span>
                  <span>{compactionResumeSafetyLabel(record.resumeSafety.status)}</span>
                  <span>
                    Pruned: {compactionDecisionCounts(record.pruneDecisions).pruned}
                  </span>
                  <span>
                    Summary-retained:{" "}
                    {compactionDecisionCounts(record.pruneDecisions).retained_summary}
                  </span>
                  <span>
                    Blocker: {record.carriedForwardState.blockedOn || "None"}
                  </span>
                </div>
                {record.resumeSafety.reasons.length > 0 ? (
                  <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                    {record.resumeSafety.reasons.map((reason) => (
                      <span key={`${record.compactionId}:${reason}`}>{reason}</span>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No compaction records are stored yet. Run a session, then compact it to
          retain a resumable long-session summary and carry-forward state.
        </p>
      )}
    </div>
  );
}

function RewindView({
  snapshot,
  status,
  error,
  onLoadSession,
  onRefreshRewind,
  selectedSessionId,
  onSelectSession,
  onOpenCompareForSession,
}: {
  snapshot: SessionRewindSnapshot | null;
  status: string;
  error: string | null;
  onLoadSession?: (sessionId: string) => void;
  onRefreshRewind?: () => Promise<unknown>;
  selectedSessionId: string | null;
  onSelectSession?: (sessionId: string | null) => void;
  onOpenCompareForSession?: (sessionId: string | null) => void;
}) {
  const candidates = snapshot?.candidates ?? [];
  const activeTitle = snapshot?.activeSessionTitle?.trim() || "No active retained session";
  const focusedCandidate = selectFocusedRewindCandidate(snapshot, selectedSessionId);
  const compareReady = canCompareFocusedRewindCandidate(
    snapshot?.activeSessionId,
    focusedCandidate,
  );
  const focusBadge = focusedCandidate?.isCurrent
    ? "Current"
    : focusedCandidate?.isLastStable
      ? "Last stable"
      : "Retained checkpoint";

  return (
    <div className="artifact-hub-rewind">
      <section className="artifact-hub-files-identity artifact-hub-rewind__identity">
        <span className="artifact-hub-files-kicker">Rewind</span>
        <strong>Retained session rewind</strong>
        <p>
          Review retained checkpoints, compare their discard surface against the
          active run, and reopen the selected session without deleting stored
          evidence or other session history.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Status: {humanizeStatus(status)}</span>
          <span>{candidates.length} retained checkpoints</span>
          <span>Active: {activeTitle}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      {focusedCandidate ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Focused rewind checkpoint</strong>
            <span className="artifact-hub-policy-pill">
              {formatSessionTimeAgo(focusedCandidate.timestamp)}
            </span>
          </div>
          <p>{focusedCandidate.previewHeadline}</p>
          <div className="artifact-hub-generic-list">
            <article className="artifact-hub-generic-row">
              <div className="artifact-hub-generic-meta">
                <span>{focusedCandidate.title}</span>
                <span>{focusBadge}</span>
                <span>{sessionRewindSubtitle(focusedCandidate) || "Retained checkpoint"}</span>
              </div>
              <p className="artifact-hub-generic-summary">
                {focusedCandidate.previewDetail}
              </p>
              <p className="artifact-hub-generic-summary">
                {focusedCandidate.discardSummary}
              </p>
            </article>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {onLoadSession ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => onLoadSession(focusedCandidate.sessionId)}
              >
                {focusedCandidate.actionLabel}
              </button>
            ) : null}
            {compareReady && onOpenCompareForSession ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => onOpenCompareForSession(focusedCandidate.sessionId)}
              >
                Review discard preview
              </button>
            ) : null}
            {onRefreshRewind ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => {
                  void onRefreshRewind();
                }}
              >
                Refresh rewind points
              </button>
            ) : null}
          </div>
        </section>
      ) : null}

      {candidates.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Retained checkpoints</span>
            <span>{candidates.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {candidates.map((candidate) => (
              <article className="artifact-hub-generic-row" key={candidate.sessionId}>
                <div className="artifact-hub-generic-meta">
                  <span>{candidate.title}</span>
                  <span>{formatSessionTimeAgo(candidate.timestamp)}</span>
                  {candidate.isCurrent ? <span>Current</span> : null}
                  {!candidate.isCurrent && candidate.isLastStable ? (
                    <span>Last stable</span>
                  ) : null}
                </div>
                <div className="artifact-hub-generic-title">
                  {candidate.previewHeadline}
                </div>
                <p className="artifact-hub-generic-summary">
                  {sessionRewindSubtitle(candidate) || candidate.previewDetail}
                </p>
                <p className="artifact-hub-generic-summary">
                  {candidate.discardSummary}
                </p>
                {onLoadSession ? (
                  <div className="artifact-hub-generic-actions">
                    {onSelectSession ? (
                      <button
                        className="artifact-hub-open-btn secondary"
                        onClick={() => onSelectSession(candidate.sessionId)}
                        type="button"
                      >
                        {candidate.sessionId === focusedCandidate?.sessionId
                          ? "Selected"
                          : "Select"}
                      </button>
                    ) : null}
                    {onOpenCompareForSession &&
                    candidate.sessionId !== snapshot?.activeSessionId ? (
                      <button
                        className="artifact-hub-open-btn secondary"
                        onClick={() => onOpenCompareForSession(candidate.sessionId)}
                        type="button"
                      >
                        Compare
                      </button>
                    ) : null}
                    <button
                      className="artifact-hub-open-btn"
                      onClick={() => onLoadSession(candidate.sessionId)}
                      type="button"
                    >
                      {candidate.actionLabel}
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No retained session checkpoints are available yet. Finish or stop a run,
          then reopen Rewind to preview the stored checkpoints.
        </p>
      )}
    </div>
  );
}

function branchSyncSummary(snapshot: SessionBranchSnapshot | null): string {
  if (!snapshot?.isRepo) {
    return "No repository";
  }
  if (!snapshot.upstreamBranch) {
    return "No upstream configured";
  }
  if (snapshot.aheadCount === 0 && snapshot.behindCount === 0) {
    return `Tracking ${snapshot.upstreamBranch}`;
  }

  const parts: string[] = [`Tracking ${snapshot.upstreamBranch}`];
  if (snapshot.aheadCount > 0) {
    parts.push(`${snapshot.aheadCount} ahead`);
  }
  if (snapshot.behindCount > 0) {
    parts.push(`${snapshot.behindCount} behind`);
  }
  return parts.join(" · ");
}

function branchRowSyncSummary(
  aheadCount: number,
  behindCount: number,
  upstreamBranch?: string | null,
): string {
  if (!upstreamBranch) {
    return "No upstream configured";
  }
  if (aheadCount === 0 && behindCount === 0) {
    return `Tracking ${upstreamBranch}`;
  }

  const parts: string[] = [`Tracking ${upstreamBranch}`];
  if (aheadCount > 0) {
    parts.push(`${aheadCount} ahead`);
  }
  if (behindCount > 0) {
    parts.push(`${behindCount} behind`);
  }
  return parts.join(" · ");
}

function commitEntryActionLabel(entry: CommitOverviewEntry): string {
  switch (entry.stage) {
    case "mixed":
      return "Mixed";
    case "staged":
      return "Staged";
    case "untracked":
      return "Untracked";
    case "working":
    default:
      return "Working";
  }
}

function workbenchSurfaceLabel(surface: AssistantWorkbenchActivity["surface"]): string {
  return surface === "reply-composer" ? "Reply composer" : "Meeting prep";
}

function workbenchActivityActionLabel(action: AssistantWorkbenchActivity["action"]): string {
  return humanizeStatus(action);
}

function PrCommentsView({
  currentTask,
  planSummary,
  branchSnapshot,
  sourceControlState,
  sourceControlLastCommitReceipt,
  replayBundle,
  visibleSourceCount,
  screenshotReceipts,
  substrateReceipts,
  onOpenView,
}: {
  currentTask: AgentTask | null;
  planSummary: PlanSummary | null;
  branchSnapshot: SessionBranchSnapshot | null;
  sourceControlState: WorkspaceSourceControlState | null;
  sourceControlLastCommitReceipt: WorkspaceCommitResult | null;
  replayBundle: CanonicalTraceBundle | null;
  visibleSourceCount: number;
  screenshotReceipts: ScreenshotReceiptEvidence[];
  substrateReceipts: SubstrateReceiptRow[];
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const overview = useMemo(() => {
    const blocker = taskBlockerSummary(currentTask);
    const commitOverview = buildCommitOverview(
      sourceControlState,
      branchSnapshot,
      sourceControlLastCommitReceipt,
    );
    return buildPrCommentsOverview({
      sessionTitle:
        replayBundle?.sessionSummary?.title ||
        currentTask?.intent ||
        currentTask?.current_step ||
        null,
      branchLabel: branchSnapshot?.currentBranch || branchSnapshot?.repoLabel || null,
      lastCommitLabel:
        sourceControlLastCommitReceipt?.commitSummary ||
        branchSnapshot?.lastCommit ||
        null,
      progressSummary: planSummary?.progressSummary || currentTask?.current_step || null,
      currentStage: planSummary?.currentStage || currentTask?.phase || null,
      selectedRoute: planSummary?.selectedRoute || null,
      changedPathCount: commitOverview.changedCount,
      stagedPathCount: commitOverview.stagedCount,
      unstagedPathCount: commitOverview.unstagedCount,
      evidenceEventCount: replayBundle?.stats.eventCount ?? 0,
      evidenceArtifactCount: replayBundle?.stats.artifactCount ?? 0,
      visibleSourceCount,
      screenshotCount: screenshotReceipts.length,
      substrateReceiptCount: substrateReceipts.length,
      verifierState: planSummary?.verifierState || null,
      verifierOutcome: planSummary?.verifierOutcome || null,
      approvalState: planSummary?.approvalState || null,
      blockerTitle: blocker?.title || null,
      blockerDetail: blocker?.detail || null,
      verificationNotes: buildVerificationNotes(planSummary),
    });
  }, [
    branchSnapshot,
    currentTask,
    planSummary,
    replayBundle,
    screenshotReceipts.length,
    sourceControlLastCommitReceipt,
    sourceControlState,
    substrateReceipts.length,
    visibleSourceCount,
  ]);
  const [copiedDraftId, setCopiedDraftId] = useState<string | null>(null);

  useEffect(() => {
    if (!copiedDraftId) {
      return;
    }
    const timeout = window.setTimeout(() => {
      setCopiedDraftId(null);
    }, 1500);
    return () => window.clearTimeout(timeout);
  }, [copiedDraftId]);

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          overview.readiness === "attention"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">PR Comments</span>
        <strong>{overview.readinessLabel}</strong>
        <p>{overview.readinessDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{overview.draftCount} comment drafts</span>
          <span>{overview.evidenceLabel}</span>
          <span>{visibleSourceCount} evidence sources</span>
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Reviewer handoff</strong>
          <span className="artifact-hub-policy-pill">Shared runtime truth</span>
        </div>
        <p>
          Draft reviewer-facing PR comments from the same plan, source-control,
          and evidence state that already backs Commit, Share, Replay, and the
          retained route summary.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("commit")}
            >
              Open Commit
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("share")}
            >
              Share Evidence
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("active_context")}
            >
              Review Plan
            </button>
          ) : null}
        </div>
      </section>

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Comment drafts</span>
          <span>{overview.drafts.length}</span>
        </div>
        <div className="artifact-hub-generic-list">
          {overview.drafts.map((draft) => (
            <article className="artifact-hub-generic-row" key={draft.id}>
              <div className="artifact-hub-generic-meta">
                <span>{draft.label}</span>
                <span>{draft.description}</span>
              </div>
              <textarea
                className="artifact-hub-commit-textarea"
                value={draft.markdown}
                readOnly
                rows={9}
              />
              <div className="artifact-hub-generic-actions">
                <button
                  type="button"
                  className="artifact-hub-open-btn"
                  onClick={() => {
                    void navigator.clipboard.writeText(draft.markdown).then(() => {
                      setCopiedDraftId(draft.id);
                    });
                  }}
                >
                  {copiedDraftId === draft.id ? "Copied" : "Copy markdown"}
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

function MobileView({
  assistantWorkbench,
  activeWorkbenchSummary,
  retainedWorkbenchActivities,
  retainedWorkbenchEvidenceThreadId,
  retainedWorkbenchTraceLoading,
  retainedWorkbenchTraceError,
  retainedWorkbenchEventCount,
  retainedWorkbenchArtifactCount,
  latestRetainedWorkbenchEvent,
  latestRetainedWorkbenchArtifact,
  retainedWorkbenchEvidenceAttachable,
  mobileOverview,
  serverSnapshot,
  remoteEnvSnapshot,
  managedSettings,
  onRequestReplLaunch,
  onOpenView,
}: {
  assistantWorkbench: AssistantWorkbenchSession | null;
  activeWorkbenchSummary: AssistantWorkbenchSummary | null;
  retainedWorkbenchActivities: AssistantWorkbenchActivity[];
  retainedWorkbenchEvidenceThreadId: string | null;
  retainedWorkbenchTraceLoading: boolean;
  retainedWorkbenchTraceError: string | null;
  retainedWorkbenchEventCount: number;
  retainedWorkbenchArtifactCount: number;
  latestRetainedWorkbenchEvent: AgentEvent | null;
  latestRetainedWorkbenchArtifact: Artifact | null;
  retainedWorkbenchEvidenceAttachable: boolean;
  mobileOverview: MobileOverview;
  serverSnapshot: SessionServerSnapshot | null;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null;
  managedSettings: LocalEngineSnapshot["managedSettings"] | null;
  onRequestReplLaunch?: (
    request: SpotlightRemoteContinuityLaunchRequest,
  ) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const activityRows = retainedWorkbenchActivities.slice(0, 6);
  const evidenceAction = buildMobileEvidenceContinuityAction({
    evidenceThreadId: retainedWorkbenchEvidenceThreadId,
    hasActiveWorkbench: Boolean(assistantWorkbench),
    hasAttachableSessionTarget: retainedWorkbenchEvidenceAttachable,
  });
  const policyOverview = useMemo(
    () =>
      buildMobileRemoteContinuityPolicyOverview({
        mobileOverview,
        mobileAction: evidenceAction,
        serverSnapshot,
        remoteEnvSnapshot,
        managedSettings,
      }),
    [evidenceAction, managedSettings, mobileOverview, remoteEnvSnapshot, serverSnapshot],
  );

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          mobileOverview.status === "attention"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">Mobile</span>
        <strong>{mobileOverview.statusLabel}</strong>
        <p>{mobileOverview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{mobileOverview.activityCount} retained activities</span>
          <span>{mobileOverview.evidenceLabel}</span>
          <span>{mobileOverview.sessionHistoryCount} retained sessions</span>
          <span>{evidenceAction.attachable ? "REPL ready" : "Evidence only"}</span>
        </div>
      </section>

      {retainedWorkbenchTraceError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {retainedWorkbenchTraceError}
        </p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Active handoff</strong>
            <span className="artifact-hub-policy-pill">
              {assistantWorkbench ? "Live" : "Retained only"}
            </span>
          </div>
          <p>
            {activeWorkbenchSummary?.summary ||
              "No native reply or meeting-prep handoff is active right now."}
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>
              {assistantWorkbench
                ? workbenchSurfaceLabel(
                    assistantWorkbench.kind === "gmail_reply"
                      ? "reply-composer"
                      : "meeting-prep",
                  )
                : "Awaiting inbox-driven handoff"}
            </span>
            <span>
              {retainedWorkbenchEvidenceThreadId
                ? clipText(retainedWorkbenchEvidenceThreadId, 72)
                : "No retained evidence thread"}
            </span>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {assistantWorkbench ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void openStudioAssistantWorkbench(assistantWorkbench);
                }}
              >
                {activeWorkbenchSummary?.resumeLabel || "Resume in Studio"}
              </button>
            ) : null}
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => onOpenView("tasks")}
              >
                Review Tasks
              </button>
            ) : null}
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Retained evidence</strong>
            <span className="artifact-hub-policy-pill">
              {mobileOverview.evidenceReady ? "Replay ready" : "Pending"}
            </span>
          </div>
          <p>
            Handoff activity stays tied to a retained evidence thread so replay,
            sharing, and later promotion can use the same runtime truth.
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{retainedWorkbenchEventCount} events</span>
            <span>{retainedWorkbenchArtifactCount} artifacts</span>
            <span>
              {retainedWorkbenchTraceLoading
                ? "Loading retained evidence"
                : mobileOverview.evidenceReady
                  ? "Evidence retained"
                  : "Evidence not ready yet"}
            </span>
            <span>{evidenceAction.attachable ? "Attachable session" : "Evidence-only continuity"}</span>
          </div>
          {!retainedWorkbenchTraceLoading ? (
            <div className="artifact-hub-generic-list">
              <article className="artifact-hub-generic-row">
                <div className="artifact-hub-generic-meta">
                  <span>{latestRetainedWorkbenchEvent?.title || "Awaiting event"}</span>
                  <span>
                    {latestRetainedWorkbenchArtifact?.title || "No artifact yet"}
                  </span>
                </div>
                <p className="artifact-hub-generic-summary">
                  {retainedWorkbenchEvidenceThreadId
                    ? clipText(retainedWorkbenchEvidenceThreadId, 132)
                    : "A retained evidence thread will appear once a reply/prep surface records activity."}
                </p>
              </article>
            </div>
          ) : null}
          <p className="artifact-hub-generic-summary">{evidenceAction.detail}</p>
          <div className="artifact-hub-permissions-card__actions">
            {(() => {
              const launchRequest = evidenceAction.launchRequest;
              if (!launchRequest || !onRequestReplLaunch) {
                return null;
              }
              return (
                <button
                  type="button"
                  className="artifact-hub-open-btn"
                  onClick={() => {
                    onRequestReplLaunch(launchRequest);
                  }}
                >
                  {evidenceAction.spotlightLabel}
                </button>
              );
            })()}
            {retainedWorkbenchEvidenceThreadId ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => {
                  void openStudioSessionTarget(retainedWorkbenchEvidenceThreadId);
                }}
              >
                {evidenceAction.studioLabel}
              </button>
            ) : null}
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => onOpenView("share")}
              >
                Share Evidence
              </button>
            ) : null}
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => onOpenView("replay")}
              >
                Review Replay
              </button>
            ) : null}
          </div>
        </section>
      </div>

      {activityRows.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Recent handoff activity</span>
            <span>{activityRows.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {activityRows.map((activity) => (
              <article className="artifact-hub-generic-row" key={activity.activityId}>
                <div className="artifact-hub-generic-meta">
                  <span>{workbenchSurfaceLabel(activity.surface)}</span>
                  <span>{workbenchActivityActionLabel(activity.action)}</span>
                  <span>{humanizeStatus(activity.status)}</span>
                  <span>{formatSessionTimeAgo(activity.timestampMs)}</span>
                </div>
                <div className="artifact-hub-generic-title">{activity.message}</div>
                {activity.detail ? (
                  <p className="artifact-hub-generic-summary">{activity.detail}</p>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No native reply or meeting-prep handoffs have been retained yet. Once
          one starts, this drawer will keep its activity trail, evidence thread,
          and continuity shortcuts together.
        </p>
      )}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Cross-shell continuity</strong>
          <span className="artifact-hub-policy-pill">Shared runtime truth</span>
        </div>
        <p>
          Spotlight, Studio, replay/export, and retained session history all stay
          aligned because the handoff state comes from the same runtime-owned
          session and evidence records.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{mobileOverview.sessionHistoryCount} retained sessions</span>
          <span>{mobileOverview.activityCount} retained handoff activities</span>
          <span>
            {evidenceAction.attachable
              ? "REPL ready"
              : mobileOverview.evidenceReady
                ? "Evidence-preserving"
                : "Awaiting evidence"}
          </span>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("repl")}
            >
              Open REPL
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("export")}
            >
              Export Evidence
            </button>
          ) : null}
        </div>
      </section>

      <RemoteContinuityPolicyCard
        title={policyOverview.statusLabel}
        overview={policyOverview}
        onRequestReplLaunch={onRequestReplLaunch}
        onOpenView={onOpenView}
      />
    </div>
  );
}

function VoiceView({
  onSeedIntent,
  onOpenView,
}: {
  onSeedIntent?: (intent: string) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [language, setLanguage] = useState("");
  const { status, error, result, fileName, reset, transcribeFile } =
    useSpotlightVoiceInput();
  const overview = buildVoiceOverview({
    status,
    fileName,
    error,
    result,
  });
  const busy = status === "reading" || status === "transcribing";
  const transcript = result?.text.trim() ?? "";
  const selectedFileLabel = result?.fileName || fileName || "No clip selected";
  const languageHint = language.trim();

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          overview.tone === "attention"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">Voice</span>
        <strong>{overview.statusLabel}</strong>
        <p>{overview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Tone: {humanizeStatus(overview.tone)}</span>
          <span>Projection: {humanizeStatus(status)}</span>
          <span>{selectedFileLabel}</span>
          <span>{result?.modelId || "Shared runtime transcription"}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Transcribe clip</strong>
            <span className="artifact-hub-policy-pill">
              {busy ? "In progress" : "Runtime-backed"}
            </span>
          </div>
          <p>
            Choose an audio clip and transcribe it through the shared inference
            runtime instead of relying on shell-local speech handling.
          </p>
          <div className="artifact-hub-commit-form">
            <label className="artifact-hub-commit-field">
              <span>Language hint</span>
              <input
                className="artifact-hub-commit-input"
                type="text"
                value={language}
                onChange={(event) => setLanguage(event.target.value)}
                placeholder="Optional, for example en or en-US"
                maxLength={16}
              />
            </label>
          </div>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>Selected: {selectedFileLabel}</span>
            <span>
              {languageHint ? `Hint: ${languageHint}` : "Language: auto-detect"}
            </span>
            <span>{busy ? "Preparing transcript" : "Ready for audio"}</span>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            <input
              ref={fileInputRef}
              type="file"
              accept="audio/*,.mp3,.wav,.m4a,.webm,.ogg,.aac,.flac"
              style={{ display: "none" }}
              onChange={(event) => {
                const nextFile = event.currentTarget.files?.[0];
                event.currentTarget.value = "";
                if (!nextFile) {
                  return;
                }
                void transcribeFile(nextFile, languageHint || null).catch(() => {
                  // The error state is already captured by the hook.
                });
              }}
            />
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={busy}
              onClick={() => fileInputRef.current?.click()}
            >
              {busy
                ? "Transcribing..."
                : result
                  ? "Choose another clip"
                  : "Choose audio clip"}
            </button>
            {result || fileName || error ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                disabled={busy}
                onClick={reset}
              >
                Reset
              </button>
            ) : null}
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Latest transcript</strong>
            <span className="artifact-hub-policy-pill">
              {transcript ? "Ready" : "Awaiting audio"}
            </span>
          </div>
          <p>
            Seed the transcribed text directly back into the composer once it is
            ready so the next plan or execution request stays tied to the same
            shared runtime truth.
          </p>
          {transcript ? (
            <div className="artifact-hub-commit-form">
              <label className="artifact-hub-commit-field">
                <span>Transcript</span>
                <textarea
                  className="artifact-hub-commit-textarea"
                  value={transcript}
                  readOnly
                  rows={6}
                />
              </label>
            </div>
          ) : (
            <p>
              No transcript is retained yet. Choose an audio clip to preview its
              text here before sending it back to the composer.
            </p>
          )}
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{result?.mimeType || "Pending mime type"}</span>
            <span>{result?.language || (languageHint || "Auto language")}</span>
            <span>{result?.modelId || "Awaiting runtime result"}</span>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {onSeedIntent && transcript ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => onSeedIntent(transcript)}
              >
                Use in composer
              </button>
            ) : null}
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => onOpenView("active_context")}
              >
                Review Plan
              </button>
            ) : null}
          </div>
        </section>
      </div>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Cross-shell continuity</strong>
          <span className="artifact-hub-policy-pill">Shared runtime truth</span>
        </div>
        <p>
          Voice transcription stays inside the same runtime plane as Server,
          Mobile, REPL, and Spotlight plan execution, so the result can move
          across shells without inventing a separate speech subsystem.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{transcript ? "Transcript retained locally" : "Awaiting transcript"}</span>
          <span>{result?.fileName || fileName || "No audio clip yet"}</span>
          <span>{result?.modelId || "Shared runtime"}</span>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("server")}
            >
              Inspect Server Mode
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("mobile")}
            >
              Open Mobile
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function CommitView({
  branchSnapshot,
  branchStatus,
  branchError,
  sourceControlState,
  sourceControlStatus,
  sourceControlError,
  sourceControlLastCommitReceipt,
  onRefreshBranches,
  onRefreshSourceControl,
  onStageSourceControlPath,
  onStageAllSourceControl,
  onUnstageSourceControlPath,
  onUnstageAllSourceControl,
  onDiscardSourceControlPath,
  onDiscardAllWorkingSourceControl,
  onCommitSourceControl,
  onOpenView,
}: {
  branchSnapshot: SessionBranchSnapshot | null;
  branchStatus: SpotlightBranchesStatus;
  branchError: string | null;
  sourceControlState: WorkspaceSourceControlState | null;
  sourceControlStatus: SpotlightSourceControlStatus;
  sourceControlError: string | null;
  sourceControlLastCommitReceipt: WorkspaceCommitResult | null;
  onRefreshBranches?: () => Promise<unknown>;
  onRefreshSourceControl?: () => Promise<unknown>;
  onStageSourceControlPath?: (path: string) => Promise<unknown>;
  onStageAllSourceControl?: () => Promise<unknown>;
  onUnstageSourceControlPath?: (path: string) => Promise<unknown>;
  onUnstageAllSourceControl?: () => Promise<unknown>;
  onDiscardSourceControlPath?: (path: string) => Promise<unknown>;
  onDiscardAllWorkingSourceControl?: () => Promise<unknown>;
  onCommitSourceControl?: (
    headline: string,
    body?: string | null,
  ) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const overview = useMemo(
    () =>
      buildCommitOverview(
        sourceControlState,
        branchSnapshot,
        sourceControlLastCommitReceipt,
      ),
    [branchSnapshot, sourceControlLastCommitReceipt, sourceControlState],
  );
  const [headline, setHeadline] = useState("");
  const [body, setBody] = useState("");

  const isBusy =
    sourceControlStatus === "mutating" || sourceControlStatus === "committing";
  const trimmedHeadline = headline.trim();

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Commit</span>
        <strong>{overview.branchLabel}</strong>
        <p>
          Build the next local commit from the same shared source-control and
          branch posture that already backs Branches and the workspace editor.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(sourceControlStatus)}</span>
          <span>Branch posture: {humanizeStatus(branchStatus)}</span>
          <span>{overview.changedCount} changed paths</span>
          <span>{overview.stagedCount} staged</span>
          <span>{overview.unstagedCount} unstaged</span>
        </div>
      </section>

      {branchError ? (
        <p className="artifact-hub-note artifact-hub-note--error">{branchError}</p>
      ) : null}
      {sourceControlError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {sourceControlError}
        </p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section
          className={`artifact-hub-permissions-card ${
            overview.readiness === "attention"
              ? "artifact-hub-permissions-card--alert"
              : ""
          }`}
        >
          <div className="artifact-hub-permissions-card__head">
            <strong>{overview.readinessLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {overview.syncLabel}
            </span>
          </div>
          <p>{overview.readinessDetail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{overview.changedCount} total changes</span>
            <span>{overview.stagedCount} staged</span>
            <span>{overview.unstagedCount} unstaged</span>
            <span>{overview.untrackedCount} untracked</span>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Latest retained commit</strong>
            <span className="artifact-hub-policy-pill">Head</span>
          </div>
          <p>
            {overview.lastCommitLabel
              ? overview.lastCommitLabel
              : "No retained commit headline is available for this checkout yet."}
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>
              {branchSnapshot?.workspaceRoot?.trim() || "No workspace root"}
            </span>
            <span>{branchSnapshot?.dirty ? "Dirty checkout" : "Clean checkout"}</span>
          </div>
        </section>
      </div>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Commit message</strong>
          <span className="artifact-hub-policy-pill">
            {sourceControlStatus === "committing" ? "Committing" : "Compose"}
          </span>
        </div>
        <p>
          Commits only include staged paths. Leave non-staged edits alone if they
          belong to later work.
        </p>
        <div className="artifact-hub-commit-form">
          <label className="artifact-hub-commit-field">
            <span>Headline</span>
            <input
              className="artifact-hub-commit-input"
              type="text"
              value={headline}
              onChange={(event) => setHeadline(event.target.value)}
              placeholder="Summarize the staged checkpoint"
              maxLength={120}
            />
          </label>
          <label className="artifact-hub-commit-field">
            <span>Body</span>
            <textarea
              className="artifact-hub-commit-textarea"
              value={body}
              onChange={(event) => setBody(event.target.value)}
              placeholder="Optional detail for reviewers, future replay, or promotion."
              rows={4}
            />
          </label>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onCommitSourceControl ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={isBusy || !overview.canCommit || trimmedHeadline.length === 0}
              onClick={() => {
                void onCommitSourceControl(trimmedHeadline, body.trim() || null)
                  .then(() => {
                    setHeadline("");
                    setBody("");
                    void onRefreshBranches?.();
                  })
                  .catch(() => {
                    // Keep the current message draft intact when commit fails.
                  });
              }}
            >
              Write commit
            </button>
          ) : null}
          {onRefreshSourceControl ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => {
                void onRefreshSourceControl();
                void onRefreshBranches?.();
              }}
            >
              Refresh state
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("branch")}
            >
              Manage Branches
            </button>
          ) : null}
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Stage controls</strong>
          <span className="artifact-hub-policy-pill">Current checkout</span>
        </div>
        <p>
          Stage only the paths that belong in the next checkpoint. Unstaged edits
          stay in the working tree and can be committed later.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          {onStageAllSourceControl && overview.changedCount > 0 ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={isBusy}
              onClick={() => {
                void onStageAllSourceControl();
              }}
            >
              Stage all
            </button>
          ) : null}
          {onUnstageAllSourceControl && overview.stagedCount > 0 ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={isBusy}
              onClick={() => {
                void onUnstageAllSourceControl();
              }}
            >
              Unstage staged
            </button>
          ) : null}
          {onDiscardAllWorkingSourceControl && overview.unstagedCount > 0 ? (
            <button
              type="button"
              className="artifact-hub-open-btn destructive"
              disabled={isBusy}
              onClick={() => {
                void onDiscardAllWorkingSourceControl();
              }}
            >
              Discard unstaged
            </button>
          ) : null}
        </div>
      </section>

      {overview.entries.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Changed paths</span>
            <span>{overview.entries.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {overview.entries.map((entry) => (
              <article className="artifact-hub-generic-row" key={entry.path}>
                <div className="artifact-hub-generic-meta">
                  <span>{commitEntryActionLabel(entry)}</span>
                  <span>{entry.statusLabel}</span>
                  {entry.originalPath ? <span>{entry.originalPath}</span> : null}
                </div>
                <div className="artifact-hub-generic-title">{entry.path}</div>
                <p className="artifact-hub-generic-summary">{entry.detail}</p>
                <div className="artifact-hub-generic-actions">
                  {entry.canStage && onStageSourceControlPath ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={isBusy}
                      onClick={() => {
                        void onStageSourceControlPath(entry.path);
                      }}
                    >
                      Stage
                    </button>
                  ) : null}
                  {entry.canUnstage && onUnstageSourceControlPath ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={isBusy}
                      onClick={() => {
                        void onUnstageSourceControlPath(entry.path);
                      }}
                    >
                      Unstage
                    </button>
                  ) : null}
                  {entry.canDiscard && onDiscardSourceControlPath ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn destructive"
                      disabled={isBusy}
                      onClick={() => {
                        void onDiscardSourceControlPath(entry.path);
                      }}
                    >
                      Discard
                    </button>
                  ) : null}
                  {onOpenView ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      onClick={() => onOpenView("files")}
                    >
                      Open Files
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No pending source-control changes are visible for this workspace yet.
        </p>
      )}
    </div>
  );
}

function BranchesView({
  snapshot,
  status,
  error,
  onRefreshBranches,
  onCreateBranchWorktree,
  onSwitchBranchWorktree,
  onRemoveBranchWorktree,
  onOpenView,
}: {
  snapshot: SessionBranchSnapshot | null;
  status: SpotlightBranchesStatus;
  error: string | null;
  onRefreshBranches?: () => Promise<unknown>;
  onCreateBranchWorktree?: (
    branchName: string,
    options?: {
      startPoint?: string | null;
      worktreeName?: string | null;
    },
  ) => Promise<unknown>;
  onSwitchBranchWorktree?: (targetWorkspaceRoot: string) => Promise<unknown>;
  onRemoveBranchWorktree?: (targetWorkspaceRoot: string) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const workspaceLabel = snapshot?.workspaceRoot?.trim() || "No active workspace";
  const repoLabel = snapshot?.repoLabel?.trim() || "No repository";
  const currentBranch = snapshot?.currentBranch?.trim() || "Detached HEAD";
  const recentBranches = snapshot?.recentBranches ?? [];
  const worktrees = snapshot?.worktrees ?? [];
  const [branchName, setBranchName] = useState("");
  const [worktreeName, setWorktreeName] = useState("");
  const [startPoint, setStartPoint] = useState("");
  const trimmedBranchName = branchName.trim();
  const trimmedWorktreeName = worktreeName.trim();
  const trimmedStartPoint = startPoint.trim();
  const isBusy = status === "loading";
  const lifecyclePlan = useMemo(
    () => buildBranchLifecycleAutomationPlan(snapshot),
    [snapshot],
  );
  const startPointOptions = useMemo(() => {
    const values = new Set<string>();
    const options: string[] = [];
    const push = (value?: string | null) => {
      const trimmed = value?.trim();
      if (!trimmed || values.has(trimmed)) {
        return;
      }
      values.add(trimmed);
      options.push(trimmed);
    };
    push(snapshot?.currentBranch);
    recentBranches.forEach((branch) => push(branch.branchName));
    push("HEAD");
    return options;
  }, [recentBranches, snapshot?.currentBranch]);

  useEffect(() => {
    if (!trimmedStartPoint && startPointOptions.length > 0) {
      setStartPoint(startPointOptions[0] ?? "HEAD");
    }
  }, [startPointOptions, trimmedStartPoint]);

  async function runLifecycleAction(action: BranchLifecycleAutomationQueuedAction) {
    switch (action.kind) {
      case "open_commit_view":
        if (action.recommendedView && onOpenView) {
          onOpenView(action.recommendedView);
        }
        break;
      case "switch_worktree":
        if (action.targetWorkspaceRoot && onSwitchBranchWorktree) {
          await onSwitchBranchWorktree(action.targetWorkspaceRoot);
        }
        break;
      case "remove_worktree":
        if (action.targetWorkspaceRoot && onRemoveBranchWorktree) {
          await onRemoveBranchWorktree(action.targetWorkspaceRoot);
        }
        break;
    }
  }

  function canRunLifecycleAction(action: BranchLifecycleAutomationQueuedAction) {
    switch (action.kind) {
      case "open_commit_view":
        return Boolean(action.recommendedView && onOpenView);
      case "switch_worktree":
        return Boolean(action.targetWorkspaceRoot && onSwitchBranchWorktree);
      case "remove_worktree":
        return Boolean(action.targetWorkspaceRoot && onRemoveBranchWorktree);
    }
  }

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Branches</span>
        <strong>{repoLabel}</strong>
        <p>
          Review the active git checkout, upstream posture, and recent local
          branches for the current session workspace, then spin up or reattach
          isolated workcells over the same shared runtime session.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(status)}</span>
          <span>Workspace: {workspaceLabel}</span>
          <span>{snapshot?.changedFileCount ?? 0} changed files</span>
          <span>{snapshot?.dirty ? "Dirty checkout" : "Clean checkout"}</span>
          <span>{worktrees.length} tracked workcells</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Lifecycle automation</strong>
          <span className="artifact-hub-policy-pill">
            {lifecyclePlan.statusLabel}
          </span>
        </div>
        <p>{lifecyclePlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {lifecyclePlan.checklist.map((label) => (
            <span key={label}>{label}</span>
          ))}
        </div>
        {lifecyclePlan.queuedActions.length > 0 ? (
          <div className="artifact-hub-generic-list">
            {lifecyclePlan.queuedActions.map((action, index) => (
              <article
                className="artifact-hub-generic-row"
                key={`${action.kind}:${action.targetWorkspaceRoot ?? action.recommendedView ?? index}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{index === 0 ? "Primary" : "Queued"}</span>
                  <span>{humanizeStatus(lifecyclePlan.tone)}</span>
                  <span>
                    {action.recommendedView
                      ? humanizeStatus(action.recommendedView)
                      : humanizeStatus(action.kind)}
                  </span>
                </div>
                <div className="artifact-hub-generic-title">{action.label}</div>
                <p className="artifact-hub-generic-summary">{action.detail}</p>
                {canRunLifecycleAction(action) ? (
                  <div className="artifact-hub-generic-actions">
                    <button
                      type="button"
                      className={`artifact-hub-open-btn ${
                        action.kind === "remove_worktree" ? "destructive" : ""
                      }`.trim()}
                      disabled={isBusy}
                      onClick={() => {
                        void runLifecycleAction(action);
                      }}
                    >
                      {action.label}
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        ) : (
          <p className="artifact-hub-note">
            The current checkout and tracked workcells are already aligned. Use
            the create form below when you need a new isolated lane.
          </p>
        )}
      </section>

      {snapshot?.isRepo ? (
        <>
          <div className="artifact-hub-permissions-grid">
            <section className="artifact-hub-permissions-card">
              <div className="artifact-hub-permissions-card__head">
                <strong>{currentBranch}</strong>
                <span className="artifact-hub-policy-pill">
                  {branchSyncSummary(snapshot)}
                </span>
              </div>
              <p>
                {snapshot.lastCommit
                  ? `Latest commit: ${snapshot.lastCommit}`
                  : "No retained commit headline is available for this checkout yet."}
              </p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                <span>Ahead: {snapshot.aheadCount}</span>
                <span>Behind: {snapshot.behindCount}</span>
                <span>
                  {snapshot.upstreamBranch
                    ? `Upstream: ${snapshot.upstreamBranch}`
                    : "Upstream: not configured"}
                </span>
              </div>
            </section>

            <section className="artifact-hub-permissions-card">
              <div className="artifact-hub-permissions-card__head">
                <strong>{snapshot.worktreeRiskLabel}</strong>
                <span className="artifact-hub-policy-pill">Worktree</span>
              </div>
              <p>{snapshot.worktreeRiskDetail}</p>
              <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                <span>{snapshot.changedFileCount} changed files</span>
                <span>{snapshot.dirty ? "Tracked changes present" : "No tracked changes"}</span>
              </div>
            </section>
          </div>

          {recentBranches.length > 0 ? (
            <section className="artifact-hub-task-section">
              <div className="artifact-hub-task-section-head">
                <span>Recent branches</span>
                <span>{recentBranches.length}</span>
              </div>
              <div className="artifact-hub-generic-list">
                {recentBranches.map((branch) => (
                  <article className="artifact-hub-generic-row" key={branch.branchName}>
                    <div className="artifact-hub-generic-meta">
                      <span>{branch.isCurrent ? "Current branch" : "Local branch"}</span>
                      <span>
                        {branchRowSyncSummary(
                          branch.aheadCount,
                          branch.behindCount,
                          branch.upstreamBranch,
                        )}
                      </span>
                    </div>
                    <div className="artifact-hub-generic-title">
                      {branch.branchName}
                    </div>
                    <p className="artifact-hub-generic-summary">
                      {branch.lastCommit
                        ? `Latest commit: ${branch.lastCommit}`
                        : "No retained commit headline for this branch yet."}
                    </p>
                    {onCreateBranchWorktree ? (
                      <div className="artifact-hub-generic-actions">
                        <button
                          type="button"
                          className="artifact-hub-open-btn secondary"
                          disabled={isBusy}
                          onClick={() => {
                            setStartPoint(branch.branchName);
                          }}
                        >
                          Use as start point
                        </button>
                      </div>
                    ) : null}
                  </article>
                ))}
              </div>
            </section>
          ) : null}

          {worktrees.length > 0 ? (
            <section className="artifact-hub-task-section">
              <div className="artifact-hub-task-section-head">
                <span>Tracked workcells</span>
                <span>{worktrees.length}</span>
              </div>
              <div className="artifact-hub-generic-list">
                {worktrees.map((worktree) => (
                  <article className="artifact-hub-generic-row" key={worktree.path}>
                    <div className="artifact-hub-generic-meta">
                      <span>{worktree.isCurrent ? "Current workcell" : "Linked workcell"}</span>
                      <span>{worktree.statusLabel}</span>
                      <span>{worktree.branchName?.trim() || "Detached HEAD"}</span>
                    </div>
                    <div className="artifact-hub-generic-title">{worktree.path}</div>
                    <p className="artifact-hub-generic-summary">
                      {worktree.lastCommit
                        ? `${worktree.statusDetail} Latest commit: ${worktree.lastCommit}`
                        : worktree.statusDetail}
                    </p>
                    <div className="artifact-hub-generic-actions">
                      {!worktree.isCurrent && onSwitchBranchWorktree ? (
                        <button
                          type="button"
                          className="artifact-hub-open-btn"
                          disabled={isBusy}
                          onClick={() => {
                            void onSwitchBranchWorktree(worktree.path);
                          }}
                        >
                          Switch session here
                        </button>
                      ) : null}
                      {!worktree.isCurrent &&
                      !worktree.dirty &&
                      !worktree.locked &&
                      onRemoveBranchWorktree ? (
                        <button
                          type="button"
                          className="artifact-hub-open-btn destructive"
                          disabled={isBusy}
                          onClick={() => {
                            void onRemoveBranchWorktree(worktree.path);
                          }}
                        >
                          {worktree.prunable ? "Remove stale workcell" : "Remove workcell"}
                        </button>
                      ) : null}
                      {onOpenView && worktree.isCurrent ? (
                        <button
                          type="button"
                          className="artifact-hub-open-btn secondary"
                          onClick={() => onOpenView("files")}
                        >
                          Open Files
                        </button>
                      ) : null}
                    </div>
                  </article>
                ))}
              </div>
            </section>
          ) : null}
        </>
      ) : (
        <p className="artifact-hub-empty">
          No repository-backed workspace is active yet. Open or resume a session
          rooted in a git checkout, then reopen Branches.
        </p>
      )}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Workcell actions</strong>
          <span className="artifact-hub-policy-pill">
            {isBusy ? "Updating" : "Shared runtime truth"}
          </span>
        </div>
        <p>
          Create a new isolated branch+worktree under the repo-local
          `.ioi-worktrees` directory and move the active session into it.
          Uncommitted edits stay in the current checkout; the new workcell starts
          from the selected branch or commit.
        </p>
        {snapshot?.isRepo && onCreateBranchWorktree ? (
          <div className="artifact-hub-commit-form">
            <label className="artifact-hub-commit-field">
              <span>Start point</span>
              <select
                className="artifact-hub-commit-input"
                value={trimmedStartPoint || ""}
                onChange={(event) => setStartPoint(event.target.value)}
              >
                {startPointOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </label>
            <label className="artifact-hub-commit-field">
              <span>New isolated branch</span>
              <input
                className="artifact-hub-commit-input"
                type="text"
                value={branchName}
                onChange={(event) => setBranchName(event.target.value)}
                placeholder="feature/workcell-review"
                maxLength={120}
              />
            </label>
            <label className="artifact-hub-commit-field">
              <span>Workcell label</span>
              <input
                className="artifact-hub-commit-input"
                type="text"
                value={worktreeName}
                onChange={(event) => setWorktreeName(event.target.value)}
                placeholder="Optional folder suffix"
                maxLength={80}
              />
            </label>
          </div>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {snapshot?.isRepo && onCreateBranchWorktree ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={isBusy || trimmedBranchName.length === 0}
              onClick={() => {
                void onCreateBranchWorktree(trimmedBranchName, {
                  startPoint: trimmedStartPoint || null,
                  worktreeName: trimmedWorktreeName || null,
                })
                  .then(() => {
                    setBranchName("");
                    setWorktreeName("");
                  })
                  .catch(() => {
                    // Keep the form intact when workcell creation fails.
                  });
              }}
            >
              Create isolated workcell
            </button>
          ) : null}
          {onRefreshBranches ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              disabled={isBusy}
              onClick={() => {
                void onRefreshBranches();
              }}
            >
              Refresh branch snapshot
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("files")}
            >
              Open Files
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("replay")}
            >
              Review Replay
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function ServerView({
  snapshot,
  status,
  error,
  remoteEnvSnapshot,
  managedSettings,
  onRefreshServer,
  onRequestReplLaunch,
  onOpenView,
}: {
  snapshot: SessionServerSnapshot | null;
  status: SpotlightServerModeStatus;
  error: string | null;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null;
  managedSettings: LocalEngineSnapshot["managedSettings"] | null;
  onRefreshServer?: () => Promise<unknown>;
  onRequestReplLaunch?: (
    request: SpotlightRemoteContinuityLaunchRequest,
  ) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const overview = buildServerOverview(snapshot);
  const governance = useMemo(
    () => buildRemoteContinuityGovernanceOverview(snapshot),
    [snapshot],
  );
  const policyOverview = useMemo(
    () =>
      buildServerRemoteContinuityPolicyOverview({
        serverSnapshot: snapshot,
        remoteEnvSnapshot,
        managedSettings,
      }),
    [managedSettings, remoteEnvSnapshot, snapshot],
  );
  const recentSessions = snapshot?.recentRemoteSessions ?? [];
  const notes = snapshot?.notes ?? [];

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Server</span>
        <strong>{snapshot?.continuityModeLabel || "Server continuity"}</strong>
        <p>{overview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Tone: {humanizeStatus(overview.tone)}</span>
          <span>Projection: {humanizeStatus(status)}</span>
          <span>{snapshot?.kernelConnectionLabel || "Unknown"}</span>
          <span>{snapshot?.rpcSourceLabel || "No RPC target"}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{overview.statusLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.kernelConnectionLabel || "Unknown"}
            </span>
          </div>
          <p>
            {snapshot?.kernelConnectionDetail ||
              "Open a retained session to inspect the kernel RPC target and continuity posture."}
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            {overview.continuityMeta.map((item) => (
              <span key={item}>{item}</span>
            ))}
          </div>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            {overview.historyMeta.map((item) => (
              <span key={item}>{item}</span>
            ))}
            <span>
              {snapshot?.currentSessionVisibleRemotely
                ? "Current session visible remotely"
                : "Current session local only"}
            </span>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Continuity notes</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.rpcUrl || "No RPC target"}
            </span>
          </div>
          {notes.length > 0 ? (
            <div className="artifact-hub-permissions-list">
              {notes.map((note, index) => (
                <div
                  key={`${note}-${index}`}
                  className="artifact-hub-permissions-list__row"
                >
                  <div>
                    <strong>Retained signal</strong>
                    <p>{note}</p>
                  </div>
                  <span>Runtime</span>
                </div>
              ))}
            </div>
          ) : (
            <p>
              No continuity notes are retained for this shell yet.
            </p>
          )}
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Current session continuity</strong>
            <span className="artifact-hub-policy-pill">
              {overview.currentSessionLabel}
            </span>
          </div>
          <p>{overview.currentSessionDetail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{snapshot?.remoteAttachableSessionCount ?? 0} remote attachable</span>
            <span>{snapshot?.remoteHistoryOnlySessionCount ?? 0} remote history-only</span>
            <span>
              {snapshot?.currentSessionVisibleRemotely
                ? "Current session mirrored"
                : "Current session local only"}
            </span>
          </div>
        </section>

        <section
          className={`artifact-hub-permissions-card ${
            governance.tone === "review" || governance.tone === "attention"
              ? "artifact-hub-permissions-card--alert"
              : ""
          }`}
        >
          <div className="artifact-hub-permissions-card__head">
            <strong>{governance.statusLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {humanizeStatus(governance.tone)}
            </span>
          </div>
          <p>{governance.detail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            {governance.checklist.map((item) => (
              <span key={item}>{item}</span>
            ))}
          </div>
          {governance.primaryAction ? (
            <p className="artifact-hub-generic-summary">
              {governance.primaryAction.detail}
            </p>
          ) : null}
          <div className="artifact-hub-permissions-card__actions">
            {governance.primaryAction && onRequestReplLaunch ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  onRequestReplLaunch(governance.primaryAction!.launchRequest);
                }}
              >
                {governance.primaryAction.label}
              </button>
            ) : null}
            {governance.secondaryAction && onRequestReplLaunch ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => {
                  onRequestReplLaunch(governance.secondaryAction!.launchRequest);
                }}
              >
                {governance.secondaryAction.label}
              </button>
            ) : null}
            {!governance.primaryAction && onRefreshServer ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void onRefreshServer();
                }}
              >
                Refresh server snapshot
              </button>
            ) : null}
          </div>
        </section>

        <RemoteContinuityPolicyCard
          title={policyOverview.statusLabel}
          overview={policyOverview}
          onRequestReplLaunch={onRequestReplLaunch}
          onOpenView={onOpenView}
          onRefreshServer={onRefreshServer}
        />
      </div>

      {recentSessions.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Recent remote sessions</span>
            <span>{recentSessions.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {recentSessions.map((session) => (
              <article className="artifact-hub-generic-row" key={session.sessionId}>
                {(() => {
                  const continuityAction = buildRemoteSessionContinuityAction(session);
                  return (
                    <>
                      <div className="artifact-hub-generic-meta">
                        <span>{session.sourceLabel}</span>
                        <span>{formatSessionTimeAgo(session.timestamp)}</span>
                        <span>{session.presenceLabel}</span>
                      </div>
                      <div className="artifact-hub-generic-title">{session.title}</div>
                      <p className="artifact-hub-generic-summary">
                        {session.resumeHint ||
                          session.workspaceRoot ||
                          "Retained remote history merged into the shared session projection."}
                      </p>
                      <p className="artifact-hub-generic-summary">
                        {continuityAction.detail}
                      </p>
                      <div className="artifact-hub-generic-actions">
                        {onRequestReplLaunch ? (
                          <button
                            type="button"
                            className="artifact-hub-open-btn"
                            onClick={() => {
                              onRequestReplLaunch(continuityAction.launchRequest);
                            }}
                          >
                            {continuityAction.spotlightLabel}
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="artifact-hub-open-btn secondary"
                          onClick={() => {
                            void openStudioSessionTarget(session.sessionId);
                          }}
                        >
                          {continuityAction.studioLabel}
                        </button>
                      </div>
                    </>
                  );
                })()}
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No remote-retained sessions are visible yet. Once the kernel publishes
          retained history, this surface will show which sessions arrived
          remotely and whether they merge cleanly with local evidence.
        </p>
      )}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Related controls</strong>
          <span className="artifact-hub-policy-pill">Next steps</span>
        </div>
        <p>
          Server continuity stays grounded in the same runtime-owned session
          projection as Spotlight, Studio, and the standalone REPL.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          {onRefreshServer ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onRefreshServer();
              }}
            >
              Refresh server
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("repl")}
            >
              Open REPL
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("remote_env")}
            >
              Inspect Runtime Env
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("mobile")}
            >
              Open Mobile
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function PluginsView({
  snapshot,
  status,
  error,
  onRefreshPlugins,
  onTrustPlugin,
  onSetPluginEnabled,
  onReloadPlugin,
  onRefreshPluginCatalog,
  onRevokePluginTrust,
  onInstallPluginPackage,
  onUpdatePluginPackage,
  onRemovePluginPackage,
  onOpenView,
}: {
  snapshot: SessionPluginSnapshot | null;
  status: SpotlightPluginsStatus;
  error: string | null;
  onRefreshPlugins?: () => Promise<unknown>;
  onTrustPlugin?: (
    pluginId: string,
    enableAfterTrust?: boolean,
  ) => Promise<unknown>;
  onSetPluginEnabled?: (
    pluginId: string,
    enabled: boolean,
  ) => Promise<unknown>;
  onReloadPlugin?: (pluginId: string) => Promise<unknown>;
  onRefreshPluginCatalog?: (pluginId: string) => Promise<unknown>;
  onRevokePluginTrust?: (pluginId: string) => Promise<unknown>;
  onInstallPluginPackage?: (pluginId: string) => Promise<unknown>;
  onUpdatePluginPackage?: (pluginId: string) => Promise<unknown>;
  onRemovePluginPackage?: (pluginId: string) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const plugins = snapshot?.plugins ?? [];
  const receipts = snapshot?.recentReceipts ?? [];
  const workspaceLabel = snapshot?.workspaceRoot?.trim() || "No active workspace";
  const busy = status === "loading";
  const rolloutDossier = useMemo(
    () => buildPluginRolloutDossier(snapshot),
    [snapshot],
  );
  const rolloutAutomationPlan = useMemo(
    () => buildPluginRolloutAutomationPlan(snapshot),
    [snapshot],
  );
  const [rolloutStageBusy, setRolloutStageBusy] = useState(false);
  const [rolloutStageMessage, setRolloutStageMessage] = useState<string | null>(
    null,
  );
  const [rolloutStageError, setRolloutStageError] = useState<string | null>(null);
  const [rolloutAutomationBusy, setRolloutAutomationBusy] = useState(false);
  const [rolloutAutomationMessage, setRolloutAutomationMessage] =
    useState<string | null>(null);
  const [rolloutAutomationError, setRolloutAutomationError] =
    useState<string | null>(null);

  const stageRolloutReview = async () => {
    setRolloutStageBusy(true);
    setRolloutStageMessage(null);
    setRolloutStageError(null);
    try {
      const draft = buildPluginRolloutStageDraft({
        dossier: rolloutDossier,
        snapshot,
      });
      await getSessionOperatorRuntime().stageLocalEngineOperation(draft);
      setRolloutStageMessage(
        `Staged '${rolloutDossier.title}' in the Local Engine queue with remote catalog context attached.`,
      );
    } catch (stageError) {
      setRolloutStageError(
        stageError instanceof Error ? stageError.message : String(stageError),
      );
    } finally {
      setRolloutStageBusy(false);
    }
  };

  const runRolloutAutomationPlan = async (
    action = rolloutAutomationPlan.queuedActions[0] ?? {
      kind: rolloutAutomationPlan.primaryActionKind,
      label: rolloutAutomationPlan.primaryActionLabel ?? "Run rollout action",
      pluginId: rolloutAutomationPlan.pluginId,
      detail: rolloutAutomationPlan.detail,
    },
  ) => {
    setRolloutAutomationBusy(true);
    setRolloutAutomationMessage(null);
    setRolloutAutomationError(null);
    try {
      switch (action.kind) {
        case "refresh_inventory":
          if (!onRefreshPlugins) {
            throw new Error("Plugin inventory refresh is unavailable.");
          }
          await onRefreshPlugins();
          setRolloutAutomationMessage(
            "Refreshed the plugin inventory for rollout automation review.",
          );
          break;
        case "refresh_catalog":
          if (!action.pluginId || !onRefreshPluginCatalog) {
            throw new Error("Catalog refresh automation is unavailable.");
          }
          await onRefreshPluginCatalog(action.pluginId);
          setRolloutAutomationMessage(
            `Triggered catalog refresh for ${action.pluginId}.`,
          );
          break;
        case "install_package":
          if (!action.pluginId || !onInstallPluginPackage) {
            throw new Error("Managed package install automation is unavailable.");
          }
          await onInstallPluginPackage(action.pluginId);
          setRolloutAutomationMessage(
            `Installed the managed package copy for ${action.pluginId}.`,
          );
          break;
        case "apply_update":
          if (!action.pluginId || !onUpdatePluginPackage) {
            throw new Error("Managed package update automation is unavailable.");
          }
          await onUpdatePluginPackage(action.pluginId);
          setRolloutAutomationMessage(
            `Applied the managed package update for ${action.pluginId}.`,
          );
          break;
        case "trust_and_enable":
          if (!action.pluginId || !onTrustPlugin) {
            throw new Error("Trust automation is unavailable.");
          }
          await onTrustPlugin(action.pluginId, true);
          setRolloutAutomationMessage(
            `Trusted and enabled ${action.pluginId} for runtime load.`,
          );
          break;
        case "stage_review":
          await stageRolloutReview();
          setRolloutAutomationMessage(
            "Staged the rollout review dossier from the automation plan.",
          );
          break;
        case "none":
        default:
          setRolloutAutomationMessage(
            "Rollout automation does not have a pending action right now.",
          );
          break;
      }
    } catch (automationError) {
      setRolloutAutomationError(
        automationError instanceof Error
          ? automationError.message
          : String(automationError),
      );
    } finally {
      setRolloutAutomationBusy(false);
    }
  };

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Plugins</span>
        <strong>Plugin trust and lifecycle posture</strong>
        <p>
          Review tracked plugins and catalog-backed packages as runtime
          subjects: authenticity signals, requested capabilities, remembered
          trust, package install posture, update posture, and the latest
          lifecycle receipts.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(status)}</span>
          <span>Workspace: {workspaceLabel}</span>
          <span>{snapshot?.pluginCount ?? 0} plugins</span>
          <span>{snapshot?.recommendedPluginCount ?? 0} recommended</span>
          <span>{snapshot?.reviewRequiredPluginCount ?? 0} review required</span>
          <span>{snapshot?.criticalUpdateCount ?? 0} critical updates</span>
          <span>{snapshot?.refreshAvailableCount ?? 0} refresh available</span>
          <span>{snapshot?.refreshFailedCount ?? 0} refresh failed</span>
          <span>{snapshot?.catalogSourceCount ?? 0} catalog sources</span>
          <span>{snapshot?.remoteCatalogSourceCount ?? 0} remote sources</span>
          <span>{snapshot?.localCatalogSourceCount ?? 0} local sources</span>
          <span>{snapshot?.failedCatalogSourceCount ?? 0} failed sources</span>
          <span>{snapshot?.catalogChannelCount ?? 0} catalog channels</span>
          <span>{snapshot?.nonconformantChannelCount ?? 0} nonconformant</span>
          <span>{snapshot?.nonconformantSourceCount ?? 0} nonconformant sources</span>
          <span>{snapshot?.staleCatalogCount ?? 0} stale catalogs</span>
          <span>{snapshot?.expiredCatalogCount ?? 0} expired catalogs</span>
          <span>{snapshot?.verifiedPluginCount ?? 0} verified</span>
          <span>{snapshot?.unverifiedPluginCount ?? 0} unsigned/unverified</span>
          <span>{snapshot?.signatureMismatchPluginCount ?? 0} mismatch</span>
          <span>{snapshot?.trustedPluginCount ?? 0} trusted</span>
          <span>{snapshot?.enabledPluginCount ?? 0} runtime enabled</span>
          <span>{snapshot?.managedPackageCount ?? 0} managed packages</span>
          <span>{snapshot?.updateAvailableCount ?? 0} updates ready</span>
          <span>{snapshot?.blockedPluginCount ?? 0} blocked</span>
          <span>{snapshot?.reloadablePluginCount ?? 0} reloadable</span>
          <span>{snapshot?.recentReceiptCount ?? 0} recent receipts</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>{rolloutDossier.title}</strong>
          <span className="artifact-hub-policy-pill">
            {rolloutDossier.readinessLabel}
          </span>
        </div>
        <p>{rolloutDossier.summary}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{rolloutDossier.sourceSummary}</span>
          <span>{snapshot?.pluginCount ?? 0} tracked plugins</span>
          <span>{snapshot?.remoteCatalogSourceCount ?? 0} remote sources</span>
        </div>
        <p className="artifact-hub-generic-summary">
          {rolloutDossier.checklist.join(" · ")}
        </p>
        {rolloutStageMessage ? (
          <p className="artifact-hub-note">{rolloutStageMessage}</p>
        ) : null}
        {rolloutStageError ? (
          <p className="artifact-hub-note artifact-hub-note--error">
            {rolloutStageError}
          </p>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => {
              void stageRolloutReview();
            }}
            disabled={rolloutStageBusy || !snapshot}
          >
            {rolloutStageBusy ? "Staging..." : "Stage rollout review"}
          </button>
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("thoughts")}
            >
              Open staged queue
            </button>
          ) : null}
        </div>
      </section>

      <section
        className={`artifact-hub-permissions-card ${
          rolloutAutomationPlan.tone === "review"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <div className="artifact-hub-permissions-card__head">
          <strong>{rolloutAutomationPlan.statusLabel}</strong>
          <span className="artifact-hub-policy-pill">
            {humanizeStatus(rolloutAutomationPlan.tone)}
          </span>
        </div>
        <p>{rolloutAutomationPlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {rolloutAutomationPlan.checklist.map((item) => (
            <span key={item}>{item}</span>
          ))}
          {rolloutAutomationPlan.queuedActions.length > 1 ? (
            <span>{rolloutAutomationPlan.queuedActions.length} queued rollout steps</span>
          ) : null}
          {rolloutAutomationPlan.governanceNotes.length > 0 ? (
            <span>
              {rolloutAutomationPlan.governanceNotes.length} governed review{" "}
              {rolloutAutomationPlan.governanceNotes.length === 1 ? "gate" : "gates"}
            </span>
          ) : null}
        </div>
        {rolloutAutomationPlan.governanceNotes.length > 0 ? (
          <div className="artifact-hub-permissions-list">
            {rolloutAutomationPlan.governanceNotes.map((note, index) => (
              <div
                key={`${note.pluginId ?? "session"}:${note.label}:${index}`}
                className="artifact-hub-permissions-list__row"
              >
                <div>
                  <strong>{note.label}</strong>
                  <p>{note.detail}</p>
                </div>
                <span className="artifact-hub-policy-pill">
                  {humanizeStatus(note.severity)}
                </span>
              </div>
            ))}
          </div>
        ) : null}
        {rolloutAutomationPlan.queuedActions.length > 1 ? (
          <div className="artifact-hub-permissions-list">
            {rolloutAutomationPlan.queuedActions.map((action, index) => (
              <div
                key={`${action.kind}:${action.pluginId ?? index}`}
                className="artifact-hub-permissions-list__row"
              >
                <div>
                  <strong>{action.label}</strong>
                  <p>{action.detail}</p>
                </div>
                <button
                  type="button"
                  className="artifact-hub-open-btn secondary"
                  disabled={rolloutAutomationBusy}
                  onClick={() => {
                    void runRolloutAutomationPlan(action);
                  }}
                >
                  Run step
                </button>
              </div>
            ))}
          </div>
        ) : null}
        {rolloutAutomationMessage ? (
          <p className="artifact-hub-note">{rolloutAutomationMessage}</p>
        ) : null}
        {rolloutAutomationError ? (
          <p className="artifact-hub-note artifact-hub-note--error">
            {rolloutAutomationError}
          </p>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {rolloutAutomationPlan.primaryActionLabel ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={rolloutAutomationBusy}
              onClick={() => {
                void runRolloutAutomationPlan();
              }}
            >
              {rolloutAutomationBusy
                ? "Running..."
                : rolloutAutomationPlan.primaryActionLabel}
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("thoughts")}
            >
              Open staged queue
            </button>
          ) : null}
        </div>
      </section>

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{snapshot?.verifiedPluginCount ?? 0} verified packages</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.signatureMismatchPluginCount ?? 0} mismatch
            </span>
          </div>
          <p>
            Authenticity and runtime trust are separate. A plugin can be
            signature-verified but still require operator trust before runtime
            load, or it can remain visible from a local or catalog source while
            authenticity stays unresolved.
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{snapshot?.managedPackageCount ?? 0} managed packages</span>
            <span>{snapshot?.installablePackageCount ?? 0} ready to install</span>
            <span>{snapshot?.recommendedPluginCount ?? 0} recommended</span>
            <span>{snapshot?.reviewRequiredPluginCount ?? 0} review required</span>
            <span>{snapshot?.criticalUpdateCount ?? 0} critical updates</span>
            <span>{snapshot?.refreshAvailableCount ?? 0} refresh available</span>
            <span>{snapshot?.refreshFailedCount ?? 0} refresh failed</span>
            <span>{snapshot?.catalogSourceCount ?? 0} catalog sources</span>
            <span>{snapshot?.remoteCatalogSourceCount ?? 0} remote sources</span>
            <span>{snapshot?.staleCatalogCount ?? 0} stale catalogs</span>
            <span>{snapshot?.filesystemSkillCount ?? 0} filesystem skills</span>
            <span>{snapshot?.hookContributionCount ?? 0} hook contributions</span>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Plugin actions</strong>
            <span className="artifact-hub-policy-pill">Lifecycle controls</span>
          </div>
          <p>
            Trust once, manage a profile-local package copy, enable or disable
            runtime load, reload with remembered trust, or revoke trust to force
            the next load back through a gate.
          </p>
          <div className="artifact-hub-permissions-card__actions">
            {onRefreshPlugins ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                disabled={busy}
                onClick={() => {
                  void onRefreshPlugins();
                }}
              >
                Refresh plugin inventory
              </button>
            ) : null}
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => void openStudioShellView("capabilities")}
            >
              Open Studio Capabilities
            </button>
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => void openStudioShellView("policy")}
            >
              Open Governing Policy
            </button>
          </div>
        </section>
      </div>

      {(snapshot?.catalogSources.length ?? 0) > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Catalog sources</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.catalogSourceCount ?? 0} visible
            </span>
          </div>
          <p>
            External marketplace sources are tracked separately from channel and
            plugin state so refresh failures, stale mirrors, and source-level
            conformance problems stay attributable to the right distribution
            origin.
          </p>
          <div className="artifact-hub-generic-list">
            {snapshot?.catalogSources.map((source) => (
              <article className="artifact-hub-generic-row" key={source.sourceId}>
                <div className="artifact-hub-generic-meta">
                  <span>{source.label}</span>
                  {source.channel ? <span>{source.channel}</span> : null}
                  <span>
                    {source.transportKind === "remote_url"
                      ? "Remote URL"
                      : "Local path"}
                  </span>
                  <span>{source.statusLabel}</span>
                  <span>{source.conformanceLabel}</span>
                  <span>{source.validCatalogCount} valid catalogs</span>
                  {source.invalidCatalogCount > 0 ? (
                    <span>{source.invalidCatalogCount} invalid catalogs</span>
                  ) : null}
                </div>
                <div className="artifact-hub-generic-title">{source.sourceId}</div>
                <p className="artifact-hub-generic-summary">
                  {source.statusDetail}
                </p>
                {source.conformanceError ? (
                  <p className="artifact-hub-generic-summary">
                    {source.conformanceError}
                  </p>
                ) : null}
                {source.refreshError ? (
                  <p className="artifact-hub-generic-summary">
                    {source.refreshError}
                  </p>
                ) : null}
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>{source.catalogCount} channel catalogs</span>
                  <span>Source URI: {source.sourceUri}</span>
                  {source.authorityBundleLabel ? (
                    <span>Authority bundle: {source.authorityBundleLabel}</span>
                  ) : null}
                  {source.authorityBundleId ? (
                    <span>Bundle ID: {source.authorityBundleId}</span>
                  ) : null}
                  {source.lastSuccessfulRefreshAtMs ? (
                    <span>
                      Last success{" "}
                      {formatTaskTimestamp(source.lastSuccessfulRefreshAtMs)}
                    </span>
                  ) : null}
                  {source.lastFailedRefreshAtMs ? (
                    <span>
                      Last failure{" "}
                      {formatTaskTimestamp(source.lastFailedRefreshAtMs)}
                    </span>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {(snapshot?.catalogChannels.length ?? 0) > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Catalog channels</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.catalogChannelCount ?? 0} visible
            </span>
          </div>
          <p>
            Signed marketplace channels are tracked separately from individual
            plugins so refresh failures, stale feeds, and nonconformant channel
            entries surface before they are mistaken for plugin-specific risk.
          </p>
          <div className="artifact-hub-generic-list">
            {snapshot?.catalogChannels.map((channel) => (
              <article
                className="artifact-hub-generic-row"
                key={`${channel.catalogId}:${channel.channel ?? "default"}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{channel.label}</span>
                  {channel.channel ? <span>{channel.channel}</span> : null}
                  <span>{channel.statusLabel}</span>
                  <span>{channel.conformanceLabel}</span>
                  <span>{channel.validPluginCount} valid</span>
                  {channel.invalidPluginCount > 0 ? (
                    <span>{channel.invalidPluginCount} invalid</span>
                  ) : null}
                </div>
                <div className="artifact-hub-generic-title">
                  {channel.catalogId}
                </div>
                <p className="artifact-hub-generic-summary">
                  {channel.statusDetail}
                </p>
                {channel.conformanceError ? (
                  <p className="artifact-hub-generic-summary">
                    {channel.conformanceError}
                  </p>
                ) : null}
                {channel.refreshError ? (
                  <p className="artifact-hub-generic-summary">
                    {channel.refreshError}
                  </p>
                ) : null}
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>{channel.pluginCount} published entries</span>
                  <span>{channel.refreshBundleCount} refresh bundles</span>
                  {channel.issuedAtMs ? (
                    <span>
                      Issued {formatTaskTimestamp(channel.issuedAtMs)}
                    </span>
                  ) : null}
                  {channel.refreshedAtMs ? (
                    <span>
                      Refreshed {formatTaskTimestamp(channel.refreshedAtMs)}
                    </span>
                  ) : null}
                  {channel.expiresAtMs ? (
                    <span>
                      Expires {formatTaskTimestamp(channel.expiresAtMs)}
                    </span>
                  ) : null}
                  {channel.refreshSource ? (
                    <span>
                      Source: {humanizeStatus(channel.refreshSource)}
                    </span>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {receipts.length > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Recent plugin lifecycle receipts</strong>
            <span className="artifact-hub-policy-pill">{receipts.length} retained</span>
          </div>
          <p>
            Latest remembered-trust, enable, reload, and revoke outcomes for the
            runtime plugin roster.
          </p>
          <div className="artifact-hub-generic-list">
            {receipts.slice(0, 4).map((receipt) => (
              <article className="artifact-hub-generic-row" key={receipt.receiptId}>
                <div className="artifact-hub-generic-meta">
                  <span>{receipt.pluginLabel}</span>
                  <span>{humanizeStatus(receipt.action)}</span>
                  <span>{humanizeStatus(receipt.status)}</span>
                  <span>{formatTaskTimestamp(receipt.timestampMs)}</span>
                </div>
                <p className="artifact-hub-generic-summary">{receipt.summary}</p>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {plugins.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Visible plugins</span>
            <span>{plugins.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {plugins.map((plugin) => (
              <article className="artifact-hub-generic-row" key={plugin.pluginId}>
                <div className="artifact-hub-generic-meta">
                  <span>{plugin.sourceLabel}</span>
                  <span>{plugin.statusLabel}</span>
                  <span>{plugin.sessionScopeLabel}</span>
                  <span>{plugin.operatorReviewLabel}</span>
                  <span>{plugin.catalogStatusLabel}</span>
                  {plugin.updateSeverityLabel ? (
                    <span>{plugin.updateSeverityLabel}</span>
                  ) : null}
                </div>
                <div className="artifact-hub-generic-title">{plugin.label}</div>
                <p className="artifact-hub-generic-summary">
                  {plugin.whyAvailable}
                </p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>{plugin.authorityTierLabel}</span>
                  <span>{humanizeStatus(plugin.trustPosture)}</span>
                  <span>{humanizeStatus(plugin.governedProfile)}</span>
                  <span>{plugin.authenticityLabel}</span>
                  <span>{plugin.runtimeTrustLabel}</span>
                  <span>{plugin.runtimeLoadLabel}</span>
                  <span>{plugin.packageInstallLabel}</span>
                  <span>Review: {plugin.operatorReviewLabel}</span>
                  <span>Catalog: {plugin.catalogStatusLabel}</span>
                  {plugin.catalogSourceLabel ? (
                    <span>Winning source: {plugin.catalogSourceLabel}</span>
                  ) : null}
                  {plugin.updateSeverityLabel ? (
                    <span>Update: {plugin.updateSeverityLabel}</span>
                  ) : null}
                  <span>{plugin.reloadabilityLabel}</span>
                  <span>{plugin.contributionCount} contributions</span>
                  <span>{plugin.filesystemSkillCount} filesystem skills</span>
                </div>
                <p className="artifact-hub-generic-summary">
                  {plugin.authenticityDetail}
                </p>
                <p className="artifact-hub-generic-summary">
                  {plugin.operatorReviewReason}
                </p>
                <p className="artifact-hub-generic-summary">
                  {plugin.catalogStatusDetail}
                </p>
                {plugin.updateDetail ? (
                  <p className="artifact-hub-generic-summary">
                    {plugin.updateDetail}
                  </p>
                ) : null}
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  {plugin.publisherLabel ? (
                    <span>Publisher: {plugin.publisherLabel}</span>
                  ) : null}
                  {plugin.catalogSourceUri ? (
                    <span>Catalog source URI: {plugin.catalogSourceUri}</span>
                  ) : null}
                  {plugin.publisherId ? (
                    <span>Publisher ID: {plugin.publisherId}</span>
                  ) : null}
                  {plugin.signerIdentity ? (
                    <span>Signer: {plugin.signerIdentity}</span>
                  ) : null}
                  {plugin.signingKeyId ? (
                    <span>Signing key: {plugin.signingKeyId}</span>
                  ) : null}
                  {plugin.verificationAlgorithm ? (
                    <span>
                      Algorithm: {plugin.verificationAlgorithm.toUpperCase()}
                    </span>
                  ) : null}
                  {plugin.verificationTimestampMs ? (
                    <span>
                      Verified {formatTaskTimestamp(plugin.verificationTimestampMs)}
                    </span>
                  ) : null}
                  {plugin.verificationSource ? (
                    <span>
                      Source: {humanizeStatus(plugin.verificationSource)}
                    </span>
                  ) : null}
                  {plugin.verifiedDigestSha256 ? (
                    <span>
                      Digest sha256:{plugin.verifiedDigestSha256.slice(0, 16)}...
                    </span>
                  ) : null}
                  {plugin.trustScoreLabel ? (
                    <span>Trust score: {plugin.trustScoreLabel}</span>
                  ) : null}
                  {plugin.trustScoreSource ? (
                    <span>Score source: {plugin.trustScoreSource}</span>
                  ) : null}
                  {plugin.publisherTrustLabel ? (
                    <span>Publisher trust: {plugin.publisherTrustLabel}</span>
                  ) : null}
                  {plugin.publisherTrustSource ? (
                    <span>
                      Publisher source: {humanizeStatus(plugin.publisherTrustSource)}
                    </span>
                  ) : null}
                  {plugin.publisherRootLabel ? (
                    <span>Trust root: {plugin.publisherRootLabel}</span>
                  ) : null}
                  {plugin.publisherRootId ? (
                    <span>Root ID: {plugin.publisherRootId}</span>
                  ) : null}
                  {plugin.authorityBundleLabel ? (
                    <span>Authority bundle: {plugin.authorityBundleLabel}</span>
                  ) : null}
                  {plugin.authorityBundleId ? (
                    <span>Bundle ID: {plugin.authorityBundleId}</span>
                  ) : null}
                  {plugin.authorityBundleIssuedAtMs ? (
                    <span>
                      Bundle issued{" "}
                      {formatTaskTimestamp(plugin.authorityBundleIssuedAtMs)}
                    </span>
                  ) : null}
                  {plugin.authorityTrustBundleLabel ? (
                    <span>
                      Trust bundle: {plugin.authorityTrustBundleLabel}
                    </span>
                  ) : null}
                  {plugin.authorityTrustBundleStatus ? (
                    <span>
                      Trust bundle status:{" "}
                      {humanizeStatus(plugin.authorityTrustBundleStatus)}
                    </span>
                  ) : null}
                  {plugin.authorityTrustBundleIssuedAtMs ? (
                    <span>
                      Trust bundle issued{" "}
                      {formatTaskTimestamp(plugin.authorityTrustBundleIssuedAtMs)}
                    </span>
                  ) : null}
                  {plugin.authorityTrustBundleExpiresAtMs ? (
                    <span>
                      Trust bundle expires{" "}
                      {formatTaskTimestamp(plugin.authorityTrustBundleExpiresAtMs)}
                    </span>
                  ) : null}
                  {plugin.authorityTrustIssuerLabel ? (
                    <span>
                      Trust issuer: {plugin.authorityTrustIssuerLabel}
                    </span>
                  ) : null}
                  {plugin.authorityTrustIssuerId ? (
                    <span>Trust issuer ID: {plugin.authorityTrustIssuerId}</span>
                  ) : null}
                  {plugin.authorityLabel ? (
                    <span>Authority: {plugin.authorityLabel}</span>
                  ) : null}
                  {plugin.authorityId ? (
                    <span>Authority ID: {plugin.authorityId}</span>
                  ) : null}
                  {plugin.publisherStatementIssuedAtMs ? (
                    <span>
                      Statement issued{" "}
                      {formatTaskTimestamp(plugin.publisherStatementIssuedAtMs)}
                    </span>
                  ) : null}
                  {plugin.publisherRevokedAtMs ? (
                    <span>
                      Revoked {formatTaskTimestamp(plugin.publisherRevokedAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogIssuedAtMs ? (
                    <span>
                      Catalog issued {formatTaskTimestamp(plugin.catalogIssuedAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshedAtMs ? (
                    <span>
                      Catalog refreshed{" "}
                      {formatTaskTimestamp(plugin.catalogRefreshedAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogExpiresAtMs ? (
                    <span>
                      Catalog expires{" "}
                      {formatTaskTimestamp(plugin.catalogExpiresAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshSource ? (
                    <span>
                      Catalog source:{" "}
                      {humanizeStatus(plugin.catalogRefreshSource)}
                    </span>
                  ) : null}
                  {plugin.catalogChannel ? (
                    <span>Catalog channel: {plugin.catalogChannel}</span>
                  ) : null}
                  {plugin.catalogRefreshBundleLabel ? (
                    <span>
                      Refresh bundle: {plugin.catalogRefreshBundleLabel}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshBundleId ? (
                    <span>Refresh bundle ID: {plugin.catalogRefreshBundleId}</span>
                  ) : null}
                  {plugin.catalogRefreshBundleIssuedAtMs ? (
                    <span>
                      Refresh bundle issued{" "}
                      {formatTaskTimestamp(plugin.catalogRefreshBundleIssuedAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshBundleExpiresAtMs ? (
                    <span>
                      Refresh bundle expires{" "}
                      {formatTaskTimestamp(plugin.catalogRefreshBundleExpiresAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshAvailableVersion ? (
                    <span>
                      Refresh advertises {plugin.catalogRefreshAvailableVersion}
                    </span>
                  ) : null}
                  {plugin.lastCatalogRefreshAtMs ? (
                    <span>
                      Last refresh{" "}
                      {formatTaskTimestamp(plugin.lastCatalogRefreshAtMs)}
                    </span>
                  ) : null}
                </div>
                {plugin.publisherTrustDetail ? (
                  <p className="artifact-hub-generic-summary">
                    {plugin.publisherTrustDetail}
                  </p>
                ) : null}
                {plugin.trustRecommendation ? (
                  <p className="artifact-hub-generic-summary">
                    {plugin.trustRecommendation}
                  </p>
                ) : null}
                <p className="artifact-hub-generic-summary">
                  {plugin.runtimeStatusDetail}
                </p>
                <p className="artifact-hub-generic-summary">
                  {plugin.packageInstallDetail}
                </p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>
                    Managed package: {plugin.packageManaged ? "yes" : "no"}
                  </span>
                  <span>
                    Install state: {humanizeStatus(plugin.packageInstallState)}
                  </span>
                  {plugin.packageInstallSourceLabel ? (
                    <span>Install source: {plugin.packageInstallSourceLabel}</span>
                  ) : null}
                  {plugin.marketplacePackageUrl ? (
                    <span>Package URI: {plugin.marketplacePackageUrl}</span>
                  ) : null}
                  {plugin.installedVersion ? (
                    <span>Installed {plugin.installedVersion}</span>
                  ) : null}
                  {plugin.availableVersion ? (
                    <span>Available {plugin.availableVersion}</span>
                  ) : null}
                </div>
                {plugin.marketplaceInstallationPolicy ||
                plugin.marketplaceAuthenticationPolicy ||
                plugin.marketplaceProducts.length > 0 ? (
                  <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                    {plugin.marketplaceDisplayName ? (
                      <span>{plugin.marketplaceDisplayName}</span>
                    ) : null}
                    {plugin.marketplaceInstallationPolicy ? (
                      <span>
                        Install policy:{" "}
                        {humanizeStatus(plugin.marketplaceInstallationPolicy)}
                      </span>
                    ) : null}
                    {plugin.marketplaceAuthenticationPolicy ? (
                      <span>
                        Auth:{" "}
                        {humanizeStatus(plugin.marketplaceAuthenticationPolicy)}
                      </span>
                    ) : null}
                    {plugin.marketplaceProducts.map((product) => (
                      <span key={`${plugin.pluginId}-${product}`}>{product}</span>
                    ))}
                  </div>
                ) : null}
                {plugin.requestedCapabilities.length > 0 ? (
                  <details className="artifact-hub-plugin-inspect">
                    <summary>
                      Inspect requested capabilities (
                      {plugin.requestedCapabilities.length})
                    </summary>
                    <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                      {plugin.requestedCapabilities.map((capability) => (
                        <span key={`${plugin.pluginId}-${capability}`}>{capability}</span>
                      ))}
                    </div>
                  </details>
                ) : null}
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>
                    Source tracked: {plugin.sourceEnabled ? "yes" : "no"}
                  </span>
                  <span>
                    Trust remembered: {plugin.trustRemembered ? "yes" : "no"}
                  </span>
                  {plugin.lastTrustedAtMs ? (
                    <span>Trusted {formatTaskTimestamp(plugin.lastTrustedAtMs)}</span>
                  ) : null}
                  {plugin.lastReloadedAtMs ? (
                    <span>Reloaded {formatTaskTimestamp(plugin.lastReloadedAtMs)}</span>
                  ) : null}
                  {plugin.lastInstalledAtMs ? (
                    <span>Installed {formatTaskTimestamp(plugin.lastInstalledAtMs)}</span>
                  ) : null}
                  {plugin.lastUpdatedAtMs ? (
                    <span>Updated {formatTaskTimestamp(plugin.lastUpdatedAtMs)}</span>
                  ) : null}
                  {plugin.lastRemovedAtMs ? (
                    <span>Removed {formatTaskTimestamp(plugin.lastRemovedAtMs)}</span>
                  ) : null}
                </div>
                {plugin.loadError ? (
                  <p className="artifact-hub-note artifact-hub-note--error">
                    {plugin.loadError}
                  </p>
                ) : null}
                {plugin.verificationError ? (
                  <p className="artifact-hub-note artifact-hub-note--error">
                    {plugin.verificationError}
                  </p>
                ) : null}
                {plugin.packageError ? (
                  <p className="artifact-hub-note artifact-hub-note--error">
                    {plugin.packageError}
                  </p>
                ) : null}
                {plugin.catalogRefreshError ? (
                  <p className="artifact-hub-note artifact-hub-note--error">
                    {plugin.catalogRefreshError}
                  </p>
                ) : null}
                <div className="artifact-hub-permissions-card__actions">
                  {(plugin.sourceKind === "marketplace_catalog" ||
                    plugin.marketplaceDisplayName) &&
                  onRefreshPluginCatalog ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onRefreshPluginCatalog(plugin.pluginId);
                      }}
                    >
                      {plugin.catalogStatus === "refresh_available"
                        ? "Apply catalog refresh"
                        : plugin.catalogStatus === "refresh_failed"
                          ? "Retry catalog refresh"
                          : "Refresh catalog"}
                    </button>
                  ) : null}
                  {!plugin.packageManaged && onInstallPluginPackage ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onInstallPluginPackage(plugin.pluginId);
                      }}
                    >
                      Install managed package
                    </button>
                  ) : null}
                  {plugin.packageManaged &&
                  plugin.updateAvailable &&
                  onUpdatePluginPackage ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onUpdatePluginPackage(plugin.pluginId);
                      }}
                    >
                      Apply package update
                    </button>
                  ) : null}
                  {plugin.packageManaged && onRemovePluginPackage ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={busy}
                      onClick={() => {
                        void onRemovePluginPackage(plugin.pluginId);
                      }}
                    >
                      Remove managed package
                    </button>
                  ) : null}
                  {plugin.runtimeTrustState !== "trusted" && onTrustPlugin ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onTrustPlugin(plugin.pluginId, true);
                      }}
                    >
                      Trust and enable
                    </button>
                  ) : null}
                  {plugin.runtimeTrustState === "trusted" &&
                  !plugin.enabled &&
                  onSetPluginEnabled ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onSetPluginEnabled(plugin.pluginId, true);
                      }}
                    >
                      Enable runtime load
                    </button>
                  ) : null}
                  {plugin.enabled && onReloadPlugin ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onReloadPlugin(plugin.pluginId);
                      }}
                    >
                      Reload plugin
                    </button>
                  ) : null}
                  {plugin.enabled && onSetPluginEnabled ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={busy}
                      onClick={() => {
                        void onSetPluginEnabled(plugin.pluginId, false);
                      }}
                    >
                      Disable runtime load
                    </button>
                  ) : null}
                  {plugin.runtimeTrustState === "trusted" && onRevokePluginTrust ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={busy}
                      onClick={() => {
                        void onRevokePluginTrust(plugin.pluginId);
                      }}
                    >
                      Revoke trust
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="artifact-hub-open-btn"
                    onClick={() => void openStudioShellView("capabilities")}
                  >
                    Open Studio Capabilities
                  </button>
                  <button
                    type="button"
                    className="artifact-hub-open-btn secondary"
                    onClick={() => void openStudioShellView("policy")}
                  >
                    Open Governing Policy
                  </button>
                  {onOpenView ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      onClick={() => onOpenView("hooks")}
                    >
                      Review Hooks
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No tracked or catalog-backed plugins are visible yet. Add a plugin
          source or refresh the active catalog, then reopen Plugins.
        </p>
      )}
    </div>
  );
}

function HooksView({
  snapshot,
  status,
  error,
  permissionCurrentProfileId,
  permissionApplyingProfileId,
  permissionRememberedApprovals,
  permissionGovernanceRequest,
  permissionActiveOverrideCount,
  onRefreshHooks,
  onApplyPermissionProfile,
  onOpenView,
}: {
  snapshot: SessionHookSnapshot | null;
  status: string;
  error: string | null;
  permissionCurrentProfileId: SessionPermissionProfileId | null;
  permissionApplyingProfileId: SessionPermissionProfileId | null;
  permissionRememberedApprovals: ShieldRememberedApprovalSnapshot | null;
  permissionGovernanceRequest: CapabilityGovernanceRequest | null;
  permissionActiveOverrideCount: number;
  onRefreshHooks?: () => Promise<unknown>;
  onApplyPermissionProfile?: (
    profileId: SessionPermissionProfileId,
  ) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const hooks = snapshot?.hooks ?? [];
  const receipts = snapshot?.recentReceipts ?? [];
  const workspaceLabel = snapshot?.workspaceRoot?.trim() || "No active workspace";
  const controlOverview = buildHookControlOverview(snapshot);
  const authorityAutomationPlan = buildAuthorityAutomationPlan({
    currentProfileId: permissionCurrentProfileId,
    hookSnapshot: snapshot,
    rememberedApprovals: permissionRememberedApprovals,
    governanceRequest: permissionGovernanceRequest,
    activeOverrideCount: permissionActiveOverrideCount,
  });

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          controlOverview.tone === "attention"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">Hooks</span>
        <strong>{controlOverview.statusLabel}</strong>
        <p>{controlOverview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(status)}</span>
          {controlOverview.meta.map((item) => (
            <span key={item}>{item}</span>
          ))}
          <span>Workspace: {workspaceLabel}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <section
        className={`artifact-hub-permissions-card ${
          authorityAutomationPlan.tone === "review"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <div className="artifact-hub-permissions-card__head">
          <strong>{authorityAutomationPlan.statusLabel}</strong>
          <span className="artifact-hub-policy-pill">
            {humanizeStatus(authorityAutomationPlan.tone)}
          </span>
        </div>
        <p>{authorityAutomationPlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {authorityAutomationPlan.checklist.map((item) => (
            <span key={item}>{item}</span>
          ))}
          <span>
            Current profile:{" "}
            {permissionCurrentProfileId
              ? humanizeStatus(permissionCurrentProfileId)
              : "Custom posture"}
          </span>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {authorityAutomationPlan.recommendedProfileId &&
          onApplyPermissionProfile ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={
                permissionApplyingProfileId ===
                authorityAutomationPlan.recommendedProfileId
              }
              onClick={() => {
                void onApplyPermissionProfile(
                  authorityAutomationPlan.recommendedProfileId!,
                );
              }}
            >
              {permissionApplyingProfileId ===
              authorityAutomationPlan.recommendedProfileId
                ? `Applying ${humanizeStatus(
                    authorityAutomationPlan.recommendedProfileId,
                  )}...`
                : authorityAutomationPlan.primaryActionLabel}
            </button>
          ) : null}
          {authorityAutomationPlan.recommendedView && onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView(authorityAutomationPlan.recommendedView!)}
            >
              {authorityAutomationPlan.recommendedView === "permissions"
                ? "Review Permissions"
                : "Review hooks"}
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openStudioPolicyTarget(null)}
          >
            Open Studio Policy
          </button>
        </div>
      </section>

      {receipts.length > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Recent runtime hook receipts</strong>
            <span className="artifact-hub-policy-pill">
              {receipts.length} retained
            </span>
          </div>
          <p>
            Latest runtime activity and approval-memory rows that look hook- or
            automation-adjacent for the active session context.
          </p>
          <div className="artifact-hub-generic-list">
            {receipts.slice(0, 4).map((receipt) => (
              <article className="artifact-hub-generic-row" key={`${receipt.timestampMs}-${receipt.toolName}`}>
                <div className="artifact-hub-generic-meta">
                  <span>{receipt.title}</span>
                  <span>{formatTaskTimestamp(receipt.timestampMs)}</span>
                  <span>{humanizeStatus(receipt.status)}</span>
                </div>
                <div className="artifact-hub-generic-title">{receipt.toolName}</div>
                <p className="artifact-hub-generic-summary">{receipt.summary}</p>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Recent runtime hook receipts</strong>
            <span className="artifact-hub-policy-pill">None retained</span>
          </div>
          <p>
            No hook-adjacent runtime receipts have been retained yet for this
            session context.
          </p>
        </section>
      )}

      {hooks.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Runtime-visible hooks</span>
            <span>{hooks.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {hooks.map((hook) => (
              <article className="artifact-hub-generic-row" key={hook.hookId}>
                <div className="artifact-hub-generic-meta">
                  <span>{hook.ownerLabel}</span>
                  <span>{hook.statusLabel}</span>
                  <span>{hook.sessionScopeLabel}</span>
                </div>
                <div className="artifact-hub-generic-title">{hook.label}</div>
                <p className="artifact-hub-generic-summary">{hook.whyActive}</p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>{hook.triggerLabel}</span>
                  <span>{humanizeStatus(hook.trustPosture)}</span>
                  <span>{humanizeStatus(hook.governedProfile)}</span>
                  <span>{hook.authorityTierLabel}</span>
                  <span>{hook.availabilityLabel}</span>
                </div>
                <div className="artifact-hub-permissions-card__actions">
                  <button
                    type="button"
                    className="artifact-hub-open-btn"
                    onClick={() => void openStudioShellView("capabilities")}
                  >
                    Open Studio Capabilities
                  </button>
                  <button
                    type="button"
                    className="artifact-hub-open-btn"
                    onClick={() => void openStudioPolicyTarget(null)}
                  >
                    Open Governing Policy
                  </button>
                  {onOpenView ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      onClick={() => onOpenView("permissions")}
                    >
                      Review session permissions
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No runtime-visible hook contributions are retained for this session yet.
          Track or enable an extension with a `hooks` contribution, then reopen
          this drawer.
        </p>
      )}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Hook control plane</strong>
          <span className="artifact-hub-policy-pill">
            {humanizeStatus(controlOverview.tone)}
          </span>
        </div>
        <p>{controlOverview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {controlOverview.meta.map((item) => (
            <span key={item}>{item}</span>
          ))}
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onRefreshHooks ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onRefreshHooks();
              }}
            >
              Refresh hooks
            </button>
          ) : null}
          {controlOverview.recommendedView && onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => onOpenView(controlOverview.recommendedView!)}
            >
              {controlOverview.recommendedActionLabel}
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => void openStudioShellView("capabilities")}
          >
            Open Studio Capabilities
          </button>
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => void openStudioPolicyTarget(null)}
          >
            Open Governing Policy
          </button>
        </div>
      </section>
    </div>
  );
}

function PromotionStageCard({
  dossier,
  exportPath,
  exportVariant,
  busyTarget,
  message,
  error,
  onStagePromotionCandidate,
  onOpenView,
}: {
  dossier?: ReturnType<typeof buildRetainedPortfolioDossier> | null;
  exportPath: string | null;
  exportVariant: TraceBundleExportVariant | null;
  busyTarget: PromotionTarget | null;
  message: string | null;
  error: string | null;
  onStagePromotionCandidate?: (target: PromotionTarget) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const latestPackLabel = traceBundleExportVariantLabel(exportVariant);
  const stageDisabled = !onStagePromotionCandidate || busyTarget !== null;

  return (
    <section className="artifact-hub-permissions-card">
      <div className="artifact-hub-permissions-card__head">
        <strong>Promotion queue</strong>
        <span className="artifact-hub-policy-pill">Evidence-preserving</span>
      </div>
      <p>
        Stage this run into the governed Local Engine queue so `sas.xyz` service
        candidate review and `Forge` productionization can continue from the
        same replay-safe trace bundle truth.
      </p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        <span>Source: canonical trace bundle</span>
        {dossier ? <span>Dossier: {dossier.title}</span> : null}
        {dossier ? <span>Recommended pack: {dossier.recommendedVariantLabel}</span> : null}
        {latestPackLabel ? <span>Latest pack: {latestPackLabel}</span> : null}
        {exportPath ? (
          <span title={exportPath}>Export path: {clipText(exportPath, 40)}</span>
        ) : null}
      </div>
      {dossier ? (
        <p className="artifact-hub-generic-summary">
          {dossier.summary} {dossier.portfolioSummary}
        </p>
      ) : null}
      {message ? <p className="artifact-hub-note">{message}</p> : null}
      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}
      <div className="artifact-hub-permissions-card__actions">
        <button
          type="button"
          className="artifact-hub-open-btn"
          onClick={() => {
            void onStagePromotionCandidate?.("sas.xyz");
          }}
          disabled={stageDisabled}
        >
          {busyTarget === "sas.xyz" ? "Staging..." : "Stage for sas.xyz"}
        </button>
        <button
          type="button"
          className="artifact-hub-open-btn"
          onClick={() => {
            void onStagePromotionCandidate?.("Forge");
          }}
          disabled={stageDisabled}
        >
          {busyTarget === "Forge" ? "Staging..." : "Stage for Forge"}
        </button>
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView("thoughts")}
          >
            Open staged queue
          </button>
        ) : null}
      </div>
    </section>
  );
}

function RetainedPortfolioDossierCard({
  dossier,
  onExportRecommendedPack,
  onOpenView,
  secondaryView = "share",
}: {
  dossier: ReturnType<typeof buildRetainedPortfolioDossier>;
  onExportRecommendedPack?: () => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  secondaryView?: ArtifactHubViewKey;
}) {
  return (
    <section className="artifact-hub-permissions-card">
      <div className="artifact-hub-permissions-card__head">
        <strong>{dossier.title}</strong>
        <span className="artifact-hub-policy-pill">{dossier.readinessLabel}</span>
      </div>
      <p>{dossier.summary}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        <span>Recommended pack: {dossier.recommendedVariantLabel}</span>
        {dossier.latestExportLabel ? (
          <span>Latest export: {dossier.latestExportLabel}</span>
        ) : (
          <span>No packaged review pack yet</span>
        )}
        <span>{dossier.portfolioSummary}</span>
      </div>
      <p className="artifact-hub-generic-summary">
        {dossier.checklist.join(" · ")}
      </p>
      <div className="artifact-hub-permissions-card__actions">
        {onExportRecommendedPack ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => {
              void onExportRecommendedPack();
            }}
          >
            {dossier.latestExportMatchesRecommendation
              ? "Refresh recommended pack"
              : "Export recommended pack"}
          </button>
        ) : null}
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView(secondaryView)}
          >
            {secondaryView === "export" ? "Export Evidence" : "Share Evidence"}
          </button>
        ) : null}
      </div>
    </section>
  );
}

function SavedBundleProofCard({
  overview,
  onExportRecommendedPack,
  onOpenView,
  secondaryView = "share",
}: {
  overview: ReturnType<typeof buildSavedBundleProofOverview>;
  onExportRecommendedPack?: () => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  secondaryView?: ArtifactHubViewKey;
}) {
  return (
    <section
      className={`artifact-hub-permissions-card ${
        overview.tone === "review"
          ? "artifact-hub-permissions-card--alert"
          : ""
      }`}
    >
      <div className="artifact-hub-permissions-card__head">
        <strong>{overview.statusLabel}</strong>
        <span className="artifact-hub-policy-pill">
          {humanizeStatus(overview.tone)}
        </span>
      </div>
      <p>{overview.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        {overview.meta.map((item) => (
          <span key={item}>{item}</span>
        ))}
      </div>
      <p className="artifact-hub-generic-summary">
        {overview.checklist.join(" · ")}
      </p>
      <div className="artifact-hub-permissions-card__actions">
        {onExportRecommendedPack ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => {
              void onExportRecommendedPack();
            }}
          >
            Refresh saved bundle proof
          </button>
        ) : null}
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView(secondaryView)}
          >
            {secondaryView === "export" ? "Export Evidence" : "Share Evidence"}
          </button>
        ) : null}
      </div>
    </section>
  );
}

function ArtifactPipelineAutomationCard({
  plan,
  busy,
  message,
  error,
  onRun,
  onOpenView,
}: {
  plan: ReturnType<typeof buildArtifactPipelineAutomationPlan>;
  busy: boolean;
  message: string | null;
  error: string | null;
  onRun?: (action?: ArtifactPipelineAutomationQueuedAction) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  return (
    <section
      className={`artifact-hub-permissions-card ${
        plan.tone === "review"
          ? "artifact-hub-permissions-card--alert"
          : ""
      }`}
    >
      <div className="artifact-hub-permissions-card__head">
        <strong>{plan.statusLabel}</strong>
        <span className="artifact-hub-policy-pill">
          {humanizeStatus(plan.tone)}
        </span>
      </div>
      <p>{plan.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        {plan.checklist.map((item) => (
          <span key={item}>{item}</span>
        ))}
        {plan.queuedActions.length > 1 ? (
          <span>{plan.queuedActions.length} queued promotion steps</span>
        ) : null}
      </div>
      {message ? <p className="artifact-hub-note">{message}</p> : null}
      {error ? <p className="artifact-hub-note artifact-hub-note--error">{error}</p> : null}
      {plan.queuedActions.length > 1 ? (
        <div className="artifact-hub-generic-list">
          {plan.queuedActions.map((action, index) => (
            <article
              className="artifact-hub-generic-row"
              key={`${action.kind}:${action.promotionTarget ?? action.label}`}
            >
              <div className="artifact-hub-generic-meta">
                <span>Step {index + 1}</span>
                <span>{action.promotionTarget ?? humanizeStatus(action.kind)}</span>
              </div>
              <div className="artifact-hub-generic-title">{action.label}</div>
              <p className="artifact-hub-generic-summary">{action.detail}</p>
              <div className="artifact-hub-generic-actions">
                {onRun ? (
                  <button
                    type="button"
                    className="artifact-hub-open-btn secondary"
                    disabled={busy}
                    onClick={() => onRun(action)}
                  >
                    {busy && index === 0 ? "Running..." : "Run step"}
                  </button>
                ) : null}
              </div>
            </article>
          ))}
        </div>
      ) : null}
      <div className="artifact-hub-permissions-card__actions">
        {plan.primaryActionLabel && onRun ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            disabled={busy}
            onClick={() => onRun(plan.queuedActions[0])}
          >
            {busy ? "Running..." : plan.primaryActionLabel}
          </button>
        ) : null}
        {plan.recommendedView && onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView(plan.recommendedView!)}
          >
            {plan.recommendedView === "compact"
              ? "Compact Session"
              : plan.recommendedView === "privacy"
                ? "Review Privacy"
                : "Open Review"}
          </button>
        ) : null}
      </div>
    </section>
  );
}

function DurabilityEvidenceCard({
  overview,
  onOpenView,
}: {
  overview: DurabilityEvidenceOverview;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  return (
    <section className="artifact-hub-permissions-card">
      <div className="artifact-hub-permissions-card__head">
        <strong>{overview.statusLabel}</strong>
        <span className="artifact-hub-policy-pill">Long-session truth</span>
      </div>
      <p>{overview.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        <span>{overview.compactionSummary}</span>
        <span>{overview.teamMemorySummary}</span>
      </div>
      <div className="artifact-hub-permissions-card__actions">
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => onOpenView("compact")}
          >
            Compact Session
          </button>
        ) : null}
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView("share")}
          >
            Share Evidence
          </button>
        ) : null}
      </div>
    </section>
  );
}

function PrivacyEvidenceCard({
  overview,
  onOpenView,
}: {
  overview: PrivacyEvidenceOverview;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  return (
    <section className="artifact-hub-permissions-card">
      <div className="artifact-hub-permissions-card__head">
        <strong>{overview.statusLabel}</strong>
        <span className="artifact-hub-policy-pill">Privacy posture</span>
      </div>
      <p>{overview.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        <span>{overview.exportSummary}</span>
        <span>{overview.recommendationLabel}</span>
      </div>
      <div className="artifact-hub-permissions-card__actions">
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => onOpenView("privacy")}
          >
            Review Privacy
          </button>
        ) : null}
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView("permissions")}
          >
            Review Permissions
          </button>
        ) : null}
      </div>
    </section>
  );
}

function RemoteContinuityPolicyCard({
  title,
  overview,
  onRequestReplLaunch,
  onOpenView,
  onRefreshServer,
}: {
  title: string;
  overview: RemoteContinuityPolicyOverview;
  onRequestReplLaunch?: (
    request: SpotlightRemoteContinuityLaunchRequest,
  ) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  onRefreshServer?: () => Promise<unknown>;
}) {
  const runAction = (action: RemoteContinuityPolicyAction) => {
    switch (action.kind) {
      case "launch_repl":
        onRequestReplLaunch?.(action.launchRequest);
        break;
      case "open_view":
        onOpenView?.(action.view);
        break;
      case "open_studio_settings":
        void openStudioShellView("settings");
        break;
      case "refresh_server":
        void onRefreshServer?.();
        break;
      default:
        break;
    }
  };

  const canRunAction = (action: RemoteContinuityPolicyAction | null): boolean => {
    if (!action) {
      return false;
    }
    switch (action.kind) {
      case "launch_repl":
        return Boolean(onRequestReplLaunch);
      case "open_view":
        return Boolean(onOpenView);
      case "open_studio_settings":
        return true;
      case "refresh_server":
        return Boolean(onRefreshServer);
      default:
        return false;
    }
  };

  return (
    <section
      className={`artifact-hub-permissions-card ${
        overview.tone === "review" || overview.tone === "attention"
          ? "artifact-hub-permissions-card--alert"
          : ""
      }`}
    >
      <div className="artifact-hub-permissions-card__head">
        <strong>{title}</strong>
        <span className="artifact-hub-policy-pill">
          {humanizeStatus(overview.tone)}
        </span>
      </div>
      <p>{overview.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        {overview.checklist.map((item) => (
          <span key={item}>{item}</span>
        ))}
        {overview.queuedActions.length > 1 ? (
          <span>{overview.queuedActions.length} queued continuity steps</span>
        ) : null}
      </div>
      {overview.primaryAction ? (
        <p className="artifact-hub-generic-summary">
          {overview.primaryAction.detail}
        </p>
      ) : null}
      {overview.queuedActions.length > 1 ? (
        <div className="artifact-hub-permissions-list">
          {overview.queuedActions.map((action, index) => (
            <div
              key={`${action.kind}:${"launchRequest" in action ? action.launchRequest.sessionId : action.label}:${index}`}
              className="artifact-hub-permissions-list__row"
            >
              <div>
                <strong>{action.label}</strong>
                <p>{action.detail}</p>
              </div>
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                disabled={!canRunAction(action)}
                onClick={() => runAction(action)}
              >
                Run step
              </button>
            </div>
          ))}
        </div>
      ) : null}
      <div className="artifact-hub-permissions-card__actions">
        {overview.primaryAction ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            disabled={!canRunAction(overview.primaryAction)}
            onClick={() => runAction(overview.primaryAction!)}
          >
            {overview.primaryAction.label}
          </button>
        ) : null}
        {overview.secondaryAction ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            disabled={!canRunAction(overview.secondaryAction)}
            onClick={() => runAction(overview.secondaryAction!)}
          >
            {overview.secondaryAction.label}
          </button>
        ) : null}
      </div>
    </section>
  );
}

function ExportView({
  exportSessionId,
  exportStatus,
  exportError,
  exportPath,
  exportTimestampMs,
  exportVariant,
  durabilityOverview,
  privacyOverview,
  compactionSnapshot,
  stagedOperations,
  replayBundle,
  replayLoading,
  replayError,
  promotionStageBusyTarget,
  promotionStageMessage,
  promotionStageError,
  onExportBundle,
  onStagePromotionCandidate,
  onOpenView,
}: {
  exportSessionId?: string | null;
  exportStatus: string;
  exportError: string | null;
  exportPath: string | null;
  exportTimestampMs: number | null;
  exportVariant: TraceBundleExportVariant | null;
  durabilityOverview: DurabilityEvidenceOverview;
  privacyOverview: PrivacyEvidenceOverview;
  compactionSnapshot: SessionCompactionSnapshot | null;
  stagedOperations: LocalEngineStagedOperation[];
  replayBundle: CanonicalTraceBundle | null;
  replayLoading: boolean;
  replayError: string | null;
  promotionStageBusyTarget: PromotionTarget | null;
  promotionStageMessage: string | null;
  promotionStageError: string | null;
  onExportBundle?: (variant?: TraceBundleExportVariant) => Promise<unknown>;
  onStagePromotionCandidate?: (target: PromotionTarget) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const sessionTitle =
    replayBundle?.sessionSummary?.title?.trim() || "Active session export";
  const sessionId = replayBundle?.sessionId || exportSessionId || "No session";
  const threadId = replayBundle?.threadId || exportSessionId || "Unavailable";
  const bundleGeneratedAt = replayBundle?.exportedAtUtc
    ? new Date(replayBundle.exportedAtUtc).toLocaleString()
    : null;
  const latestExportLabel =
    typeof exportTimestampMs === "number" && Number.isFinite(exportTimestampMs)
      ? formatTaskTimestamp(exportTimestampMs)
      : null;
  const artifactPayloadCount = replayBundle?.artifactPayloads.length ?? 0;
  const replayEventCount = replayBundle?.stats.eventCount ?? 0;
  const replayReceiptCount = replayBundle?.stats.receiptCount ?? 0;
  const replayArtifactCount = replayBundle?.stats.artifactCount ?? 0;
  const isExporting = exportStatus === "exporting";
  const lastExportVariantLabel = traceBundleExportVariantLabel(exportVariant);
  const dossier = useMemo(
    () =>
      buildRetainedPortfolioDossier({
        sessionTitle,
        bundle: replayBundle,
        portfolio: compactionSnapshot?.durabilityPortfolio ?? null,
        exportVariant,
        privacyStatusLabel: privacyOverview.statusLabel,
        privacyRecommendationLabel: privacyOverview.recommendationLabel,
        durabilityStatusLabel: durabilityOverview.statusLabel,
      }),
    [
      compactionSnapshot?.durabilityPortfolio,
      durabilityOverview.statusLabel,
      exportVariant,
      privacyOverview.recommendationLabel,
      privacyOverview.statusLabel,
      replayBundle,
      sessionTitle,
    ],
  );
  const savedBundleProof = useMemo(
    () =>
      buildSavedBundleProofOverview({
        dossier,
        exportPath,
        exportTimestampMs,
        exportVariant,
        bundle: replayBundle,
      }),
    [dossier, exportPath, exportTimestampMs, exportVariant, replayBundle],
  );
  const artifactAutomationPlan = useMemo(
    () =>
      buildArtifactPipelineAutomationPlan({
        dossier,
        savedBundleProof,
        privacyOverview,
        durabilityOverview,
        stagedOperations,
      }),
    [dossier, durabilityOverview, privacyOverview, savedBundleProof, stagedOperations],
  );
  const [artifactAutomationBusy, setArtifactAutomationBusy] = useState(false);
  const [artifactAutomationMessage, setArtifactAutomationMessage] =
    useState<string | null>(null);
  const [artifactAutomationError, setArtifactAutomationError] =
    useState<string | null>(null);

  const runArtifactAutomationPlan = async (
    action: ArtifactPipelineAutomationQueuedAction | undefined =
      artifactAutomationPlan.queuedActions[0],
  ) => {
    if (!action && artifactAutomationPlan.actionKind === "none") {
      setArtifactAutomationMessage(
        "Artifact automation does not have a pending action right now.",
      );
      return;
    }
    setArtifactAutomationBusy(true);
    setArtifactAutomationMessage(null);
    setArtifactAutomationError(null);
    try {
      const nextAction =
        action ??
        artifactAutomationPlan.queuedActions[0] ?? {
          kind: artifactAutomationPlan.actionKind,
          label: artifactAutomationPlan.primaryActionLabel || "Run artifact automation",
          recommendedView: artifactAutomationPlan.recommendedView,
          promotionTarget: artifactAutomationPlan.promotionTarget,
          detail: artifactAutomationPlan.detail,
        };
      switch (nextAction.kind) {
        case "export_recommended_pack":
          if (!onExportBundle) {
            throw new Error("Recommended pack export is unavailable.");
          }
          await onExportBundle(dossier.recommendedVariant);
          setArtifactAutomationMessage(
            `Exported the ${dossier.recommendedVariantLabel.toLowerCase()} from the shared artifact automation plan.`,
          );
          break;
        case "review_privacy":
          if (!onOpenView) {
            throw new Error("Privacy review is unavailable.");
          }
          onOpenView(nextAction.recommendedView || "privacy");
          setArtifactAutomationMessage(
            "Opened Privacy so the artifact path can review the current sharing posture.",
          );
          break;
        case "review_durability":
          if (!onOpenView) {
            throw new Error("Durability review is unavailable.");
          }
          onOpenView(nextAction.recommendedView || "compact");
          setArtifactAutomationMessage(
            "Opened Compact so the artifact path can review long-session durability.",
          );
          break;
        case "stage_promotion":
          if (!nextAction.promotionTarget || !onStagePromotionCandidate) {
            throw new Error("Promotion staging is unavailable.");
          }
          await onStagePromotionCandidate(nextAction.promotionTarget);
          setArtifactAutomationMessage(
            `Staged ${nextAction.promotionTarget} from the shared artifact automation plan.`,
          );
          break;
        default:
          setArtifactAutomationMessage(
            "Artifact automation does not have a pending action right now.",
          );
          break;
      }
    } catch (automationError) {
      setArtifactAutomationError(
        automationError instanceof Error
          ? automationError.message
          : String(automationError),
      );
    } finally {
      setArtifactAutomationBusy(false);
    }
  };

  if (!exportSessionId && !replayBundle) {
    return (
      <p className="artifact-hub-empty">
        No retained session is available to export yet.
      </p>
    );
  }

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Export</span>
        <strong>{sessionTitle}</strong>
        <p>
          Export the canonical trace bundle for the active session, including
          retained receipts, replay history, and artifact payloads.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(exportStatus)}</span>
          <span>Thread: {clipText(threadId, 24)}</span>
          <span>Session: {clipText(sessionId, 24)}</span>
          <span>Payloads: {artifactPayloadCount}</span>
          <span>Events: {replayEventCount}</span>
          <span>Receipts: {replayReceiptCount}</span>
          <span>Artifacts: {replayArtifactCount}</span>
        </div>
      </section>

      {exportError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {exportError}
        </p>
      ) : null}
      {replayError && !replayBundle ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          Replay snapshot unavailable: {replayError}
        </p>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Bundle scope</strong>
          <span className="artifact-hub-policy-pill">Canonical trace</span>
        </div>
        <p>
          This export uses the same canonical trace-bundle path as the answer
          card export action. Artifact payloads are included in the saved zip.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Share posture: local operator export</span>
          <span>Artifact payloads: included</span>
          {bundleGeneratedAt ? <span>Snapshot: {bundleGeneratedAt}</span> : null}
          {latestExportLabel ? <span>Last export: {latestExportLabel}</span> : null}
          {lastExportVariantLabel ? <span>Variant: {lastExportVariantLabel}</span> : null}
        </div>
        {exportPath ? (
          <p className="artifact-hub-generic-summary" title={exportPath}>
            Latest exported bundle: {exportPath}
          </p>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {onExportBundle ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onExportBundle("trace_bundle");
              }}
              disabled={isExporting}
            >
              {isExporting ? "Exporting..." : "Export Trace Bundle"}
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("replay")}
            >
              Review Replay
            </button>
          ) : null}
        </div>
      </section>

      <SavedBundleProofCard
        overview={savedBundleProof}
        onExportRecommendedPack={
          onExportBundle
            ? async () => {
                await onExportBundle(dossier.recommendedVariant);
              }
            : undefined
        }
        onOpenView={onOpenView}
        secondaryView="share"
      />

      <ArtifactPipelineAutomationCard
        plan={artifactAutomationPlan}
        busy={artifactAutomationBusy}
        message={artifactAutomationMessage}
        error={artifactAutomationError}
        onRun={(action) => {
          void runArtifactAutomationPlan(action);
        }}
        onOpenView={onOpenView}
      />

      <RetainedPortfolioDossierCard
        dossier={dossier}
        onExportRecommendedPack={
          onExportBundle
            ? async () => {
                await onExportBundle(dossier.recommendedVariant);
              }
            : undefined
        }
        onOpenView={onOpenView}
        secondaryView="share"
      />

      <PromotionStageCard
        dossier={dossier}
        exportPath={exportPath}
        exportVariant={exportVariant}
        busyTarget={promotionStageBusyTarget}
        message={promotionStageMessage}
        error={promotionStageError}
        onStagePromotionCandidate={onStagePromotionCandidate}
        onOpenView={onOpenView}
      />

      <DurabilityEvidenceCard overview={durabilityOverview} onOpenView={onOpenView} />
      <PrivacyEvidenceCard overview={privacyOverview} onOpenView={onOpenView} />

      {replayLoading && !replayBundle ? (
        <p className="artifact-hub-empty">
          Loading the retained replay snapshot for export preview.
        </p>
      ) : null}
    </div>
  );
}

function ShareView({
  exportSessionId,
  exportStatus,
  exportError,
  exportPath,
  exportTimestampMs,
  exportVariant,
  durabilityOverview,
  privacyOverview,
  compactionSnapshot,
  stagedOperations,
  replayBundle,
  replayLoading,
  replayError,
  promotionStageBusyTarget,
  promotionStageMessage,
  promotionStageError,
  onExportBundle,
  onStagePromotionCandidate,
  onOpenView,
}: {
  exportSessionId?: string | null;
  exportStatus: string;
  exportError: string | null;
  exportPath: string | null;
  exportTimestampMs: number | null;
  exportVariant: TraceBundleExportVariant | null;
  durabilityOverview: DurabilityEvidenceOverview;
  privacyOverview: PrivacyEvidenceOverview;
  compactionSnapshot: SessionCompactionSnapshot | null;
  stagedOperations: LocalEngineStagedOperation[];
  replayBundle: CanonicalTraceBundle | null;
  replayLoading: boolean;
  replayError: string | null;
  promotionStageBusyTarget: PromotionTarget | null;
  promotionStageMessage: string | null;
  promotionStageError: string | null;
  onExportBundle?: (variant?: TraceBundleExportVariant) => Promise<unknown>;
  onStagePromotionCandidate?: (target: PromotionTarget) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const sessionTitle =
    replayBundle?.sessionSummary?.title?.trim() || "Active session share pack";
  const latestExportLabel =
    typeof exportTimestampMs === "number" && Number.isFinite(exportTimestampMs)
      ? formatTaskTimestamp(exportTimestampMs)
      : null;
  const lastExportVariantLabel = traceBundleExportVariantLabel(exportVariant);
  const replayStats = replayBundle?.stats ?? null;
  const isExporting = exportStatus === "exporting";
  const dossier = useMemo(
    () =>
      buildRetainedPortfolioDossier({
        sessionTitle,
        bundle: replayBundle,
        portfolio: compactionSnapshot?.durabilityPortfolio ?? null,
        exportVariant,
        privacyStatusLabel: privacyOverview.statusLabel,
        privacyRecommendationLabel: privacyOverview.recommendationLabel,
        durabilityStatusLabel: durabilityOverview.statusLabel,
      }),
    [
      compactionSnapshot?.durabilityPortfolio,
      durabilityOverview.statusLabel,
      exportVariant,
      privacyOverview.recommendationLabel,
      privacyOverview.statusLabel,
      replayBundle,
      sessionTitle,
    ],
  );
  const savedBundleProof = useMemo(
    () =>
      buildSavedBundleProofOverview({
        dossier,
        exportPath,
        exportTimestampMs,
        exportVariant,
        bundle: replayBundle,
      }),
    [dossier, exportPath, exportTimestampMs, exportVariant, replayBundle],
  );
  const artifactAutomationPlan = useMemo(
    () =>
      buildArtifactPipelineAutomationPlan({
        dossier,
        savedBundleProof,
        privacyOverview,
        durabilityOverview,
        stagedOperations,
      }),
    [dossier, durabilityOverview, privacyOverview, savedBundleProof, stagedOperations],
  );
  const [artifactAutomationBusy, setArtifactAutomationBusy] = useState(false);
  const [artifactAutomationMessage, setArtifactAutomationMessage] =
    useState<string | null>(null);
  const [artifactAutomationError, setArtifactAutomationError] =
    useState<string | null>(null);

  const runArtifactAutomationPlan = async (
    action: ArtifactPipelineAutomationQueuedAction | undefined =
      artifactAutomationPlan.queuedActions[0],
  ) => {
    if (!action && artifactAutomationPlan.actionKind === "none") {
      setArtifactAutomationMessage(
        "Artifact automation does not have a pending action right now.",
      );
      return;
    }
    setArtifactAutomationBusy(true);
    setArtifactAutomationMessage(null);
    setArtifactAutomationError(null);
    try {
      const nextAction =
        action ??
        artifactAutomationPlan.queuedActions[0] ?? {
          kind: artifactAutomationPlan.actionKind,
          label: artifactAutomationPlan.primaryActionLabel || "Run artifact automation",
          recommendedView: artifactAutomationPlan.recommendedView,
          promotionTarget: artifactAutomationPlan.promotionTarget,
          detail: artifactAutomationPlan.detail,
        };
      switch (nextAction.kind) {
        case "export_recommended_pack":
          if (!onExportBundle) {
            throw new Error("Recommended pack export is unavailable.");
          }
          await onExportBundle(dossier.recommendedVariant);
          setArtifactAutomationMessage(
            `Exported the ${dossier.recommendedVariantLabel.toLowerCase()} from the shared artifact automation plan.`,
          );
          break;
        case "review_privacy":
          if (!onOpenView) {
            throw new Error("Privacy review is unavailable.");
          }
          onOpenView(nextAction.recommendedView || "privacy");
          setArtifactAutomationMessage(
            "Opened Privacy so the artifact path can review the current sharing posture.",
          );
          break;
        case "review_durability":
          if (!onOpenView) {
            throw new Error("Durability review is unavailable.");
          }
          onOpenView(nextAction.recommendedView || "compact");
          setArtifactAutomationMessage(
            "Opened Compact so the artifact path can review long-session durability.",
          );
          break;
        case "stage_promotion":
          if (!nextAction.promotionTarget || !onStagePromotionCandidate) {
            throw new Error("Promotion staging is unavailable.");
          }
          await onStagePromotionCandidate(nextAction.promotionTarget);
          setArtifactAutomationMessage(
            `Staged ${nextAction.promotionTarget} from the shared artifact automation plan.`,
          );
          break;
        default:
          setArtifactAutomationMessage(
            "Artifact automation does not have a pending action right now.",
          );
          break;
      }
    } catch (automationError) {
      setArtifactAutomationError(
        automationError instanceof Error
          ? automationError.message
          : String(automationError),
      );
    } finally {
      setArtifactAutomationBusy(false);
    }
  };

  if (!exportSessionId && !replayBundle) {
    return (
      <p className="artifact-hub-empty">
        No retained session is available to package for sharing yet.
      </p>
    );
  }

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Share</span>
        <strong>{sessionTitle}</strong>
        <p>
          Package the current session into a first-class local share artifact
          without leaving the runtime-owned canonical trace bundle path.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(exportStatus)}</span>
          <span>
            {replayStats?.eventCount ?? 0} events · {replayStats?.receiptCount ?? 0} receipts
          </span>
          <span>
            {replayStats?.artifactCount ?? 0} artifacts · {replayStats?.includedArtifactPayloadCount ?? 0} payloads
          </span>
          {latestExportLabel ? <span>Last export: {latestExportLabel}</span> : null}
          {lastExportVariantLabel ? <span>Variant: {lastExportVariantLabel}</span> : null}
        </div>
      </section>

      {exportError ? (
        <p className="artifact-hub-note artifact-hub-note--error">{exportError}</p>
      ) : null}
      {replayError && !replayBundle ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          Replay snapshot unavailable: {replayError}
        </p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Operator evidence pack</strong>
            <span className="artifact-hub-policy-pill">Full payloads</span>
          </div>
          <p>
            Export the canonical trace bundle with artifact payloads intact so a
            local reviewer can inspect receipts, replay history, and retained
            artifacts together.
          </p>
          <div className="artifact-hub-permissions-card__actions">
            {onExportBundle ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void onExportBundle("operator_share");
                }}
                disabled={isExporting}
              >
                {isExporting ? "Packaging..." : "Export Evidence Pack"}
              </button>
            ) : null}
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Redacted review pack</strong>
            <span className="artifact-hub-policy-pill">No payloads</span>
          </div>
          <p>
            Export a lighter review-oriented pack that keeps the trace, receipts,
            and bundle manifest while omitting artifact payload bodies.
          </p>
          <div className="artifact-hub-permissions-card__actions">
            {onExportBundle ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void onExportBundle("redacted_share");
                }}
                disabled={isExporting}
              >
                {isExporting ? "Packaging..." : "Export Redacted Pack"}
              </button>
            ) : null}
          </div>
        </section>
      </div>

      {exportPath ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Latest packaged artifact</strong>
            <span className="artifact-hub-policy-pill">Local path</span>
          </div>
          <p className="artifact-hub-generic-summary" title={exportPath}>
            {exportPath}
          </p>
        </section>
      ) : null}

      <SavedBundleProofCard
        overview={savedBundleProof}
        onExportRecommendedPack={
          onExportBundle
            ? async () => {
                await onExportBundle(dossier.recommendedVariant);
              }
            : undefined
        }
        onOpenView={onOpenView}
        secondaryView="export"
      />

      <ArtifactPipelineAutomationCard
        plan={artifactAutomationPlan}
        busy={artifactAutomationBusy}
        message={artifactAutomationMessage}
        error={artifactAutomationError}
        onRun={(action) => {
          void runArtifactAutomationPlan(action);
        }}
        onOpenView={onOpenView}
      />

      <RetainedPortfolioDossierCard
        dossier={dossier}
        onExportRecommendedPack={
          onExportBundle
            ? async () => {
                await onExportBundle(dossier.recommendedVariant);
              }
            : undefined
        }
        onOpenView={onOpenView}
        secondaryView="export"
      />

      <PromotionStageCard
        dossier={dossier}
        exportPath={exportPath}
        exportVariant={exportVariant}
        busyTarget={promotionStageBusyTarget}
        message={promotionStageMessage}
        error={promotionStageError}
        onStagePromotionCandidate={onStagePromotionCandidate}
        onOpenView={onOpenView}
      />

      <DurabilityEvidenceCard overview={durabilityOverview} onOpenView={onOpenView} />
      <PrivacyEvidenceCard overview={privacyOverview} onOpenView={onOpenView} />

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Related surfaces</strong>
          <span className="artifact-hub-policy-pill">Same runtime truth</span>
        </div>
        <p>
          Share stays a projection over the canonical export and replay flow so
          evidence packaging does not fork away from the underlying session truth.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("export")}
            >
              Export Evidence
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("replay")}
            >
              Review Replay
            </button>
          ) : null}
        </div>
      </section>

      {replayLoading && !replayBundle ? (
        <p className="artifact-hub-empty">
          Loading the retained replay snapshot for share preview.
        </p>
      ) : null}
    </div>
  );
}

function KeybindingsView({
  snapshot,
}: {
  snapshot: SpotlightKeybindingSnapshot;
}) {
  const groupedRecords = snapshot.records.reduce<Record<string, typeof snapshot.records>>(
    (acc, record) => {
      if (!acc[record.scope]) {
        acc[record.scope] = [];
      }
      acc[record.scope].push(record);
      return acc;
    },
    {},
  );

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Keybindings</span>
        <strong>Current shell shortcuts</strong>
        <p>
          Review the active keyboard shortcuts across Spotlight, Studio, and the
          global launcher surface.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Platform: {snapshot.platformLabel}</span>
          <span>{snapshot.records.length} shortcuts</span>
          <span>Source: live shell defaults</span>
        </div>
      </section>

      {Object.entries(groupedRecords).map(([scope, records]) => (
        <section className="artifact-hub-task-section" key={scope}>
          <div className="artifact-hub-task-section-head">
            <span>{scope}</span>
            <span>{records.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {records.map((record) => (
              <article className="artifact-hub-generic-row" key={record.id}>
                <div className="artifact-hub-generic-meta">
                  <span>{record.source}</span>
                  <span>Current: {record.binding}</span>
                  <span>Default: {record.defaultBinding}</span>
                </div>
                <div className="artifact-hub-generic-title">{record.command}</div>
                <p className="artifact-hub-generic-summary">{record.summary}</p>
              </article>
            ))}
          </div>
        </section>
      ))}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Shortcut management</strong>
          <span className="artifact-hub-policy-pill">Current defaults</span>
        </div>
        <p>
          This slice now reflects one shared shortcut registry across Spotlight,
          Studio, and the launcher surface. User-editable keymap overrides have
          not been productized yet.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => void openStudioShellView("settings")}
          >
            Open Studio Settings
          </button>
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openStudioShellView("capabilities")}
          >
            Open Studio
          </button>
        </div>
      </section>
    </div>
  );
}

function VimModeView({
  snapshot,
  onOpenView,
  onToggleVimMode,
}: {
  snapshot: SpotlightVimModeSnapshot;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  onToggleVimMode?: () => void;
}) {
  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Vim Mode</span>
        <strong>Editor input posture</strong>
        <p>
          Review whether Spotlight is following its standard shell input stack or
          a vim-style shell posture with the current supported normal-mode command set:
          `h`, `j`, `k`, `l`, `0`, `^`, `$`, `gg`, `G`, absolute-line jumps like `2gg`
          and `2G`, `w`, `b`, `e`, count prefixes like `2w`, `3x`, `2dw`, and `2dd`, `x`, `dw`, `de`, `db`, `d0`, `d^`, `dgg`, `dG`, `cw`, `ce`, `cb`,
          `c0`, `c^`, `cgg`, `cG`, `diw`, `daw`, `ciw`, `caw`, `di"`, `da"`, `ci"`, `ca"`, `di'`,
          `da'`, `ci'`, `ca'`, `di(`, `da(`, `ci(`, `ca(`, `di[`, `da[`, `ci[`, `ca[`,
          `di&#123;`, `da&#123;`, `ci&#123;`, `ca&#123;`, `D`, `C`, `dd`, `cc`, `o`, `O`, `.`, `i`, `a`,
          `I`, `A`, and `Esc`.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Status: {snapshot.statusLabel}</span>
          <span>Scope: {snapshot.scopeLabel}</span>
          <span>Source: {snapshot.sourceLabel}</span>
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>{snapshot.modeLabel}</strong>
          <span className="artifact-hub-policy-pill">{snapshot.syncLabel}</span>
        </div>
        <p>{snapshot.statusDetail}</p>
        <div className="artifact-hub-permissions-card__actions">
          {onToggleVimMode && (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => onToggleVimMode()}
              aria-label={
                snapshot.enabled
                  ? "Disable Vim Mode"
                  : "Enable Vim Mode"
              }
            >
              {snapshot.enabled
                ? "Disable Vim Mode"
                : "Enable Vim Mode"}
            </button>
          )}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openStudioShellView("settings")}
          >
            Open Studio Settings
          </button>
        </div>
      </section>

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Mode hints</span>
          <span>{snapshot.keyHints.length}</span>
        </div>
        <div className="artifact-hub-generic-list">
          {snapshot.keyHints.map((hint) => (
            <article className="artifact-hub-generic-row" key={hint.id}>
              <div className="artifact-hub-generic-meta">
                <span>{hint.availability}</span>
                <span>{hint.keys}</span>
              </div>
              <div className="artifact-hub-generic-title">{hint.label}</div>
              <p className="artifact-hub-generic-summary">{hint.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>{snapshot.parityLabel}</strong>
          <span className="artifact-hub-policy-pill">
            Honest parity status
          </span>
        </div>
        <p>{snapshot.parityDetail}</p>
        <div className="artifact-hub-permissions-card__actions">
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView?.("keybindings")}
          >
            Open Keybindings
          </button>
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openStudioShellView("settings")}
          >
            Open Studio Settings
          </button>
        </div>
      </section>
    </div>
  );
}

function PrivacyView({
  snapshot,
  permissionsStatus,
  permissionsError,
  onOpenView,
  onRefreshPermissions,
}: {
  snapshot: SpotlightPrivacySnapshot;
  permissionsStatus: string;
  permissionsError: string | null;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  onRefreshPermissions?: () => Promise<unknown>;
}) {
  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Privacy</span>
        <strong>Session privacy posture</strong>
        <p>
          Review how the active shell handles evidence, redaction, and local
          export before anything leaves the runtime.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Policy sync: {humanizeStatus(permissionsStatus)}</span>
          <span>{snapshot.activeOverrideCount} connector overrides</span>
          <span>{snapshot.redactedOverrideCount} redacted export paths</span>
        </div>
      </section>

      {permissionsError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {permissionsError}
        </p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{snapshot.focusedScopeLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot.focusedDataHandlingLabel}
            </span>
          </div>
          <p>{snapshot.focusedDataHandlingDetail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>Source: {snapshot.governingSourceLabel}</span>
            <span>{snapshot.localOnlyOverrideCount} local-only overrides</span>
            <span>{snapshot.redactedOverrideCount} redacted overrides</span>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{snapshot.sessionReviewLabel}</strong>
            <span className="artifact-hub-policy-pill">Review</span>
          </div>
          <p>{snapshot.sessionReviewDetail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{snapshot.exportSurfaceLabel}</span>
            <span>Operator initiated</span>
          </div>
          {snapshot.pendingGovernanceSummary ? (
            <p className="artifact-hub-generic-summary">
              {snapshot.pendingGovernanceSummary}
            </p>
          ) : null}
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{snapshot.governanceHistoryLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot.recentGovernanceReceipts.length} retained
            </span>
          </div>
          <p>{snapshot.governanceHistoryDetail}</p>
          {snapshot.recentGovernanceReceipts.length > 0 ? (
            <div className="artifact-hub-generic-list">
              {snapshot.recentGovernanceReceipts.map((receipt) => (
                <article
                  className="artifact-hub-generic-row"
                  key={receipt.receiptId}
                >
                  <div className="artifact-hub-generic-meta">
                    <span>{humanizeStatus(receipt.hookKind)}</span>
                    <span>{humanizeStatus(receipt.status)}</span>
                    <span>{formatSessionTimeAgo(receipt.timestampMs)}</span>
                  </div>
                  <div className="artifact-hub-generic-title">
                    {receipt.connectorId} · {receipt.actionId}
                  </div>
                  <p className="artifact-hub-generic-summary">
                    {receipt.summary}
                  </p>
                </article>
              ))}
            </div>
          ) : null}
        </section>
      </div>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Export and sharing posture</strong>
          <span className="artifact-hub-policy-pill">Canonical export</span>
        </div>
        <p>{snapshot.exportSurfaceDetail}</p>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => onOpenView("export")}
            >
              Export Evidence
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("permissions")}
            >
              Review Permissions
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openStudioShellView("policy")}
          >
            Open Studio Policy
          </button>
        </div>
      </section>

      {snapshot.connectors.length > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Connector artifact handling</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot.connectors.length} tracked
            </span>
          </div>
          <div className="artifact-hub-permissions-list">
            {snapshot.connectors.map((connector) => (
              <div
                key={connector.connectorId}
                className="artifact-hub-permissions-list__row"
              >
                <div>
                  <strong>{connector.label}</strong>
                  <p>{connector.headline}</p>
                </div>
                <span>
                  {connector.modeLabel}
                  {" · "}
                  {connector.detail}
                </span>
              </div>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No connector-specific privacy overrides are active. The session is
          currently following the global runtime privacy baseline.
        </p>
      )}

      {onRefreshPermissions ? (
        <div className="artifact-hub-permissions-card__actions">
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => {
              void onRefreshPermissions();
            }}
          >
            Refresh privacy posture
          </button>
        </div>
      ) : null}
    </div>
  );
}

function PermissionsView({
  currentTask,
  isGated,
  gateInfo,
  credentialRequest,
  clarificationRequest,
  onOpenGate,
  onOpenView,
  onRefreshPermissions,
  permissionsStatus,
  permissionsError,
  permissionPolicyState,
  permissionGovernanceRequest,
  permissionConnectorOverrides,
  permissionActiveOverrideCount,
  permissionProfiles,
  permissionCurrentProfileId,
  permissionApplyingProfileId,
  permissionEditingConnectorId,
  permissionApplyingGovernanceRequest,
  permissionRememberedApprovals,
  hookSnapshot,
  onApplyPermissionProfile,
  onApplyPermissionGovernanceRequest,
  onDismissPermissionGovernanceRequest,
  onForgetRememberedApproval,
  onUpdatePermissionOverride,
  onResetPermissionOverride,
  onSetRememberedApprovalScopeMode,
  onSetRememberedApprovalExpiry,
}: {
  currentTask: AgentTask | null;
  isGated?: boolean;
  gateInfo?: GateInfo;
  credentialRequest?: CredentialRequest;
  clarificationRequest?: ClarificationRequest;
  onOpenGate?: () => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  onRefreshPermissions?: () => Promise<unknown>;
  permissionsStatus: string;
  permissionsError: string | null;
  permissionPolicyState: ShieldPolicyState;
  permissionGovernanceRequest: CapabilityGovernanceRequest | null;
  permissionConnectorOverrides: SpotlightPermissionConnectorOverrideSummary[];
  permissionActiveOverrideCount: number;
  permissionProfiles: SpotlightPermissionProfileSummary[];
  permissionCurrentProfileId: SessionPermissionProfileId | null;
  permissionApplyingProfileId: SessionPermissionProfileId | null;
  permissionEditingConnectorId: string | null;
  permissionApplyingGovernanceRequest: boolean;
  permissionRememberedApprovals: ShieldRememberedApprovalSnapshot | null;
  hookSnapshot: SessionHookSnapshot | null;
  onApplyPermissionProfile?: (
    profileId: SessionPermissionProfileId,
  ) => Promise<unknown>;
  onApplyPermissionGovernanceRequest?: () => Promise<unknown>;
  onDismissPermissionGovernanceRequest?: () => Promise<unknown>;
  onForgetRememberedApproval?: (decisionId: string) => Promise<unknown>;
  onUpdatePermissionOverride?: (
    connectorId: string,
    nextOverride: Partial<ConnectorPolicyOverride>,
  ) => Promise<unknown>;
  onResetPermissionOverride?: (connectorId: string) => Promise<unknown>;
  onSetRememberedApprovalScopeMode?: (
    decisionId: string,
    scopeMode: ShieldApprovalScopeMode,
  ) => Promise<unknown>;
  onSetRememberedApprovalExpiry?: (
    decisionId: string,
    expiresAtMs: number | null,
  ) => Promise<unknown>;
}) {
  const blocker = taskBlockerSummary(currentTask, {
    clarificationRequest,
    credentialRequest,
    gateInfo,
    isGated,
  });
  const focusedConnectorId =
    permissionGovernanceRequest?.connectorId ||
    permissionConnectorOverrides[0]?.connectorId ||
    null;
  const focusedScopeLabel =
    permissionGovernanceRequest?.connectorLabel ||
    permissionConnectorOverrides[0]?.label ||
    "Global runtime policy";
  const effectivePolicy = focusedConnectorId
    ? resolveConnectorPolicy(permissionPolicyState, focusedConnectorId).effective
    : permissionPolicyState.global;
  const simulationDeck = buildPolicySimulationDeck(
    permissionPolicyState,
    focusedConnectorId,
  );
  const deltaDeck = buildPolicyDeltaDeck(
    permissionPolicyState,
    focusedConnectorId,
  );
  const requestCount =
    Number(Boolean(blocker)) +
    Number(Boolean(permissionGovernanceRequest)) +
    permissionActiveOverrideCount;
  const currentProfile =
    permissionProfiles.find(
      (profile) => profile.id === permissionCurrentProfileId,
    ) ?? null;
  const rememberedDecisionCount =
    permissionRememberedApprovals?.activeDecisionCount ?? 0;
  const recentHookReceiptCount =
    permissionRememberedApprovals?.recentReceiptCount ?? 0;
  const overrideReviewCards = buildAuthorityOverrideReviewCards({
    policyState: permissionPolicyState,
    connectorOverrides: permissionConnectorOverrides,
    governanceRequest: permissionGovernanceRequest,
  });
  const authorityAutomationPlan = buildAuthorityAutomationPlan({
    currentProfileId: permissionCurrentProfileId,
    hookSnapshot: hookSnapshot,
    rememberedApprovals: permissionRememberedApprovals,
    governanceRequest: permissionGovernanceRequest,
    activeOverrideCount: permissionActiveOverrideCount,
  });

  useEffect(() => {
    if (typeof window === "undefined" || !onApplyPermissionProfile) {
      return;
    }

    const shortcutProfiles: Record<string, SessionPermissionProfileId> = {
      Digit1: "safer_review",
      Numpad1: "safer_review",
      Digit2: "guided_default",
      Numpad2: "guided_default",
      Digit3: "autonomous",
      Numpad3: "autonomous",
      Digit4: "expert",
      Numpad4: "expert",
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (
        !event.altKey ||
        event.ctrlKey ||
        event.metaKey ||
        event.shiftKey
      ) {
        return;
      }

      const targetProfileId = shortcutProfiles[event.code];
      if (!targetProfileId) {
        return;
      }

      if (
        permissionCurrentProfileId === targetProfileId ||
        permissionApplyingProfileId === targetProfileId
      ) {
        event.preventDefault();
        return;
      }

      event.preventDefault();
      void onApplyPermissionProfile(targetProfileId);
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [
    onApplyPermissionProfile,
    permissionApplyingProfileId,
    permissionCurrentProfileId,
  ]);

  const policyRows = [
    {
      id: "reads",
      label: "Reads",
      value: humanizeStatus(effectivePolicy.reads),
      tone: policyTone(effectivePolicy.reads),
    },
    {
      id: "writes",
      label: "Writes",
      value: humanizeStatus(effectivePolicy.writes),
      tone: policyTone(effectivePolicy.writes),
    },
    {
      id: "admin",
      label: "Admin",
      value: humanizeStatus(effectivePolicy.admin),
      tone: policyTone(effectivePolicy.admin),
    },
    {
      id: "expert",
      label: "Expert",
      value: humanizeStatus(effectivePolicy.expert),
      tone: policyTone(effectivePolicy.expert),
    },
    {
      id: "automations",
      label: "Automations",
      value: humanizeStatus(effectivePolicy.automations),
      tone: "neutral",
    },
    {
      id: "dataHandling",
      label: "Artifacts",
      value: dataHandlingLabel(effectivePolicy.dataHandling),
      tone: "neutral",
    },
  ];

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Permissions</span>
        <strong>Session permissions</strong>
        <p>
          Live operator grants, pending runtime requests, and current Shield
          policy posture for this session.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Policy sync: {humanizeStatus(permissionsStatus)}</span>
          <span>{requestCount} active items</span>
          <span>{permissionActiveOverrideCount} connector overrides</span>
          <span>{rememberedDecisionCount} remembered approvals</span>
        </div>
      </section>

      {permissionsError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {permissionsError}
        </p>
      ) : null}

      {blocker ? (
        <section className="artifact-hub-permissions-card artifact-hub-permissions-card--alert">
          <div className="artifact-hub-permissions-card__head">
            <strong>{blocker.title}</strong>
            <span className="artifact-hub-policy-pill">Pending</span>
          </div>
          <p>{blocker.detail}</p>
          <div className="artifact-hub-permissions-card__actions">
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => onOpenView("tasks")}
              >
                Review Tasks
              </button>
            ) : null}
            {onOpenGate && isGated ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={onOpenGate}
              >
                Open Gate
              </button>
            ) : null}
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() =>
                void openStudioPolicyTarget(
                  permissionGovernanceRequest?.connectorId ?? focusedConnectorId,
                )
              }
            >
              Open Studio Policy
            </button>
          </div>
        </section>
      ) : null}

      {permissionGovernanceRequest ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{permissionGovernanceRequest.headline}</strong>
            <span className="artifact-hub-policy-pill">
              {humanizeStatus(permissionGovernanceRequest.action)}
            </span>
          </div>
          <p>{permissionGovernanceRequest.detail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{permissionGovernanceRequest.capabilityLabel}</span>
            <span>{permissionGovernanceRequest.connectorLabel}</span>
            <span>{permissionGovernanceRequest.authorityTierLabel}</span>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {onApplyPermissionGovernanceRequest ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                disabled={permissionApplyingGovernanceRequest}
                onClick={() => {
                  void onApplyPermissionGovernanceRequest();
                }}
              >
                {permissionApplyingGovernanceRequest
                  ? "Applying request..."
                  : "Apply request here"}
              </button>
            ) : null}
            {onDismissPermissionGovernanceRequest ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                disabled={permissionApplyingGovernanceRequest}
                onClick={() => {
                  void onDismissPermissionGovernanceRequest();
                }}
              >
                Dismiss request
              </button>
            ) : null}
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() =>
                void openStudioPolicyTarget(
                  permissionGovernanceRequest.connectorId || null,
                )
              }
            >
              Review in Studio
            </button>
          </div>
        </section>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Session permission profiles</strong>
          <span className="artifact-hub-policy-pill">
            {currentProfile?.label ?? "Custom posture"}
          </span>
        </div>
        <p>
          Switch between curated runtime authority profiles. Connector-specific
          overrides stay intact while the session baseline changes.
        </p>
        <p className="artifact-hub-permissions-shortcuts">
          Quick apply: Alt+1 Safer review, Alt+2 Guided default, Alt+3
          Autonomous, Alt+4 Expert.
        </p>
        <div className="artifact-hub-permissions-profile-list">
          {permissionProfiles.map((profile) => {
            const isCurrent = permissionCurrentProfileId === profile.id;
            const isApplying = permissionApplyingProfileId === profile.id;
            const shortcutLabel = PERMISSION_PROFILE_SHORTCUTS[profile.id];
            const previewDeck = buildPolicyIntentDeltaDeck(
              permissionPolicyState,
              applySessionPermissionProfile(permissionPolicyState, profile.id),
              null,
              {
                baselineLabel: currentProfile?.label ?? "Current posture",
                nextLabel: profile.label,
              },
            );

            return (
              <article
                key={profile.id}
                className={`artifact-hub-permissions-profile${
                  isCurrent ? " is-active" : ""
                }`}
              >
                <div className="artifact-hub-permissions-profile__head">
                  <div>
                    <strong>{profile.label}</strong>
                    <p>{profile.summary}</p>
                  </div>
                  <div className="artifact-hub-permissions-profile__badges">
                    <span className="artifact-hub-policy-pill">
                      {shortcutLabel}
                    </span>
                    <span className="artifact-hub-policy-pill">
                      {isCurrent
                        ? "Current"
                        : previewDeck.items.length > 0
                          ? `${previewDeck.items.length} changes`
                          : "Matches current"}
                    </span>
                  </div>
                </div>
                <p>{profile.detail}</p>
                {previewDeck.items.length > 0 ? (
                  <div className="artifact-hub-permissions-list">
                    {previewDeck.items.slice(0, 3).map((item) => (
                      <div
                        key={`${profile.id}:${item.id}`}
                        className="artifact-hub-permissions-list__row"
                      >
                        <div>
                          <strong>{item.label}</strong>
                          <p>{item.detail}</p>
                        </div>
                        <span>
                          {item.baseline}
                          {" -> "}
                          {item.next}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="artifact-hub-empty">
                    This profile already matches the current session posture.
                  </p>
                )}
                <div className="artifact-hub-permissions-card__actions">
                  <button
                    type="button"
                    className="artifact-hub-open-btn"
                    disabled={
                      isCurrent ||
                      isApplying ||
                      !onApplyPermissionProfile
                    }
                    aria-label={
                      isCurrent
                        ? `${profile.label} is the current permission profile`
                        : isApplying
                          ? `Applying ${profile.label} permission profile`
                          : `Apply ${profile.label} permission profile`
                    }
                    title={
                      isCurrent
                        ? `${profile.label} is current`
                        : `Apply ${profile.label} profile (${shortcutLabel})`
                    }
                    data-profile-id={profile.id}
                    onClick={() => {
                      if (!onApplyPermissionProfile) {
                        return;
                      }
                      void onApplyPermissionProfile(profile.id);
                    }}
                  >
                    {isApplying
                      ? `Applying ${profile.label}...`
                      : isCurrent
                        ? `${profile.label} is current`
                        : `Apply ${profile.label}`}
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      </section>

      <section
        className={`artifact-hub-permissions-card ${
          authorityAutomationPlan.tone === "review"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <div className="artifact-hub-permissions-card__head">
          <strong>{authorityAutomationPlan.statusLabel}</strong>
          <span className="artifact-hub-policy-pill">
            {humanizeStatus(authorityAutomationPlan.tone)}
          </span>
        </div>
        <p>{authorityAutomationPlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {authorityAutomationPlan.checklist.map((item) => (
            <span key={item}>{item}</span>
          ))}
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {authorityAutomationPlan.recommendedProfileId &&
          onApplyPermissionProfile ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={
                permissionApplyingProfileId ===
                authorityAutomationPlan.recommendedProfileId
              }
              onClick={() => {
                void onApplyPermissionProfile(
                  authorityAutomationPlan.recommendedProfileId!,
                );
              }}
            >
              {permissionApplyingProfileId ===
              authorityAutomationPlan.recommendedProfileId
                ? `Applying ${humanizeStatus(
                    authorityAutomationPlan.recommendedProfileId,
                  )}...`
                : authorityAutomationPlan.primaryActionLabel}
            </button>
          ) : null}
          {authorityAutomationPlan.recommendedView && onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView(authorityAutomationPlan.recommendedView!)}
            >
              {authorityAutomationPlan.recommendedView === "permissions"
                ? "Focus permissions"
                : "Review hooks"}
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openStudioPolicyTarget(focusedConnectorId)}
          >
            Open Studio Policy
          </button>
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Remembered approvals</strong>
          <span className="artifact-hub-policy-pill">
            {rememberedDecisionCount} active
          </span>
        </div>
        <p>
          Shield approval decisions remembered for repeated connector runs in
          the same governed scope.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{rememberedDecisionCount} remembered</span>
          <span>{recentHookReceiptCount} recent hook receipts</span>
          <span>Store: runtime authority memory</span>
        </div>
        {permissionRememberedApprovals?.decisions.length ? (
          <div className="artifact-hub-generic-list">
            {permissionRememberedApprovals.decisions.map((decision) => {
              const broadenedScope =
                decision.scopeMode === "connector_policy_family";
              return (
                <article
                  className="artifact-hub-generic-row"
                  key={decision.decisionId}
                >
                  <div className="artifact-hub-generic-meta">
                    <span>{humanizeStatus(decision.status)}</span>
                    <span>{decision.sourceLabel}</span>
                    <span>{decision.matchCount} matches</span>
                  </div>
                  <div className="artifact-hub-generic-title">
                    {decision.actionLabel}
                  </div>
                  <p className="artifact-hub-generic-summary">
                    {decision.scopeLabel} ·{" "}
                    {approvalScopeModeLabel(
                      decision.scopeMode,
                      decision.policyFamily,
                    )}{" "}
                    · created {formatSessionTimeAgo(decision.createdAtMs)}
                    {decision.lastMatchedAtMs
                      ? ` · last used ${formatSessionTimeAgo(
                          decision.lastMatchedAtMs,
                        )}`
                      : ""}
                    {decision.expiresAtMs
                      ? ` · expires ${formatSessionTimeAgo(decision.expiresAtMs)}`
                      : " · never expires"}
                  </p>
                  <div className="artifact-hub-permissions-card__actions">
                    {onSetRememberedApprovalScopeMode ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn secondary"
                        onClick={() => {
                          void onSetRememberedApprovalScopeMode(
                            decision.decisionId,
                            broadenedScope
                              ? "exact_action"
                              : "connector_policy_family",
                          );
                        }}
                      >
                        {broadenedScope
                          ? "Narrow to exact action"
                          : `Broaden to ${humanizeStatus(
                              decision.policyFamily,
                            )} family`}
                      </button>
                    ) : null}
                    {onSetRememberedApprovalExpiry ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn secondary"
                        onClick={() => {
                          void onSetRememberedApprovalExpiry(
                            decision.decisionId,
                            decision.expiresAtMs
                              ? null
                              : Date.now() + 24 * 60 * 60 * 1000,
                          );
                        }}
                      >
                        {decision.expiresAtMs
                          ? "Never expire"
                          : "Expire in 24h"}
                      </button>
                    ) : null}
                    {onForgetRememberedApproval ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn secondary"
                        onClick={() => {
                          void onForgetRememberedApproval(decision.decisionId);
                        }}
                      >
                        Revoke remembered approval
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      onClick={() =>
                        void openStudioPolicyTarget(decision.connectorId)
                      }
                    >
                      Open Studio Policy
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        ) : (
          <p className="artifact-hub-empty">
            No approvals have been remembered yet. The first remembered
            approval will appear here after an operator approves a rememberable
            Shield request.
          </p>
        )}
      </section>

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Permission hook receipts</span>
          <span>{recentHookReceiptCount}</span>
        </div>
        {permissionRememberedApprovals?.recentReceipts.length ? (
          <div className="artifact-hub-generic-list">
            {permissionRememberedApprovals.recentReceipts.map((receipt) => (
              <article
                className="artifact-hub-generic-row"
                key={receipt.receiptId}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{humanizeStatus(receipt.hookKind)}</span>
                  <span>{humanizeStatus(receipt.status)}</span>
                  <span>{formatSessionTimeAgo(receipt.timestampMs)}</span>
                </div>
                <div className="artifact-hub-generic-title">
                  {receipt.connectorId} · {receipt.actionId}
                </div>
                <p className="artifact-hub-generic-summary">
                  {receipt.summary}
                </p>
              </article>
            ))}
          </div>
        ) : (
          <p className="artifact-hub-empty">
            Hook receipts will appear here when a blocker escalates, a
            remembered approval auto-matches, expires, misses scope, or is
            revoked.
          </p>
        )}
      </section>

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{focusedScopeLabel}</strong>
            <span className="artifact-hub-policy-pill">Current posture</span>
          </div>
          <p>
            Effective runtime permission posture for{" "}
            {focusedConnectorId ? "the focused connector" : "the active shell"}.
          </p>
          <div className="artifact-hub-permissions-decisions">
            {policyRows.map((row) => (
              <div
                key={row.id}
                className={`artifact-hub-permissions-chip is-${row.tone}`}
              >
                <span>{row.label}</span>
                <strong>{row.value}</strong>
              </div>
            ))}
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {onRefreshPermissions ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void onRefreshPermissions();
                }}
              >
                Refresh posture
              </button>
            ) : null}
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => void openStudioPolicyTarget(focusedConnectorId)}
            >
              Open Studio Policy
            </button>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Permission simulation</strong>
            <span className="artifact-hub-policy-pill">
              {simulationDeck.summary.auto} auto · {simulationDeck.summary.gate} gate
            </span>
          </div>
          <p>{simulationDeck.artifactHandling.detail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{simulationDeck.summary.auto} auto</span>
            <span>{simulationDeck.summary.gate} gate</span>
            <span>{simulationDeck.summary.deny} deny</span>
            <span>{simulationDeck.artifactHandling.label}</span>
          </div>
          {deltaDeck.items.length > 0 ? (
            <div className="artifact-hub-permissions-list">
              {deltaDeck.items.slice(0, 4).map((item) => (
                <div key={item.id} className="artifact-hub-permissions-list__row">
                  <strong>{item.label}</strong>
                  <span>
                    {item.baseline}
                    {" -> "}
                    {item.next}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="artifact-hub-empty">
              No connector-specific widening from the baseline is active.
            </p>
          )}
          <div className="artifact-hub-permissions-list">
            {simulationDeck.scenarios.map((scenario) => (
              <div
                key={scenario.id}
                className="artifact-hub-permissions-list__row"
              >
                <div>
                  <strong>{scenario.label}</strong>
                  <p>{scenario.detail}</p>
                </div>
                <span>
                  {permissionSimulationOutcomeLabel(scenario.outcome)}
                </span>
              </div>
            ))}
            <div className="artifact-hub-permissions-list__row">
              <div>
                <strong>Artifact handling</strong>
                <p>{simulationDeck.artifactHandling.detail}</p>
              </div>
              <span>{simulationDeck.artifactHandling.label}</span>
            </div>
          </div>
        </section>
      </div>

      {overrideReviewCards.length > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Connector override review</strong>
            <span className="artifact-hub-policy-pill">
              {overrideReviewCards.length} tracked
            </span>
          </div>
          <p>
            Review connector-scoped authority changes, apply pending governance
            requests in place, and edit active overrides without leaving the
            runtime-backed Spotlight surface.
          </p>
          <div className="artifact-hub-permissions-profile-list">
            {overrideReviewCards.map((card) => {
              const isEditing = permissionEditingConnectorId === card.connectorId;
              return (
                <article
                  key={`${card.source}:${card.connectorId}`}
                  className="artifact-hub-permissions-profile"
                >
                  <div className="artifact-hub-permissions-profile__head">
                    <div>
                      <strong>{card.label}</strong>
                      <p>{card.headline}</p>
                    </div>
                    <div className="artifact-hub-permissions-profile__badges">
                      <span className="artifact-hub-policy-pill">
                        {card.source === "governance_request"
                          ? "Governance preview"
                          : "Live override"}
                      </span>
                      <span className="artifact-hub-policy-pill">
                        {card.simulationDeck.summary.auto} auto ·{" "}
                        {card.simulationDeck.summary.gate} gate
                      </span>
                    </div>
                  </div>
                  <p>{card.detail}</p>
                  {card.deltaDeck.items.length > 0 ? (
                    <div className="artifact-hub-permissions-list">
                      {card.deltaDeck.items.slice(0, 3).map((item) => (
                        <div
                          key={`${card.connectorId}:${item.id}`}
                          className="artifact-hub-permissions-list__row"
                        >
                          <div>
                            <strong>{item.label}</strong>
                            <p>{item.detail}</p>
                          </div>
                          <span>
                            {item.baseline}
                            {" -> "}
                            {item.next}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="artifact-hub-empty">
                      This connector is currently aligned with its baseline
                      posture.
                    </p>
                  )}
                  {card.canEdit ? (
                    <div className="artifact-hub-permissions-form">
                      <PermissionPolicySelect
                        label="Read actions"
                        value={card.effectivePolicy.reads}
                        options={PERMISSION_DECISION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            reads: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Write actions"
                        value={card.effectivePolicy.writes}
                        options={PERMISSION_DECISION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            writes: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Admin actions"
                        value={card.effectivePolicy.admin}
                        options={PERMISSION_DECISION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            admin: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Expert / raw actions"
                        value={card.effectivePolicy.expert}
                        options={PERMISSION_DECISION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            expert: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Automations"
                        value={card.effectivePolicy.automations}
                        options={PERMISSION_AUTOMATION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            automations: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Artifact handling"
                        value={card.effectivePolicy.dataHandling}
                        options={PERMISSION_DATA_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            dataHandling: value,
                          });
                        }}
                      />
                    </div>
                  ) : null}
                  <div className="artifact-hub-permissions-card__actions">
                    {card.canEdit && onResetPermissionOverride ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn"
                        disabled={isEditing}
                        onClick={() => {
                          void onResetPermissionOverride(card.connectorId);
                        }}
                      >
                        {isEditing
                          ? "Saving override..."
                          : "Return to global baseline"}
                      </button>
                    ) : null}
                    {card.source === "governance_request" &&
                    card.canApplyGovernanceRequest &&
                    onApplyPermissionGovernanceRequest ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn"
                        disabled={permissionApplyingGovernanceRequest}
                        onClick={() => {
                          void onApplyPermissionGovernanceRequest();
                        }}
                      >
                        {permissionApplyingGovernanceRequest
                          ? "Applying request..."
                          : "Apply requested posture"}
                      </button>
                    ) : null}
                    {card.source === "governance_request" &&
                    onDismissPermissionGovernanceRequest ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn secondary"
                        disabled={permissionApplyingGovernanceRequest}
                        onClick={() => {
                          void onDismissPermissionGovernanceRequest();
                        }}
                      >
                        Dismiss request
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      onClick={() => void openStudioPolicyTarget(card.connectorId)}
                    >
                      Open Studio Policy
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No connector-specific overrides or pending connector governance
          requests are active. The shell is currently using the global runtime
          policy baseline.
        </p>
      )}
    </div>
  );
}

export function ArtifactHubDetailView({
  activeView,
  activeSessionId,
  exportSessionId,
  exportStatus,
  exportError,
  exportPath,
  exportTimestampMs,
  exportVariant,
  durabilityOverview,
  privacyOverview,
  keybindingSnapshot,
  vimModeSnapshot,
  compactionSnapshot,
  compactionPolicy,
  compactionStatus,
  compactionError,
  teamMemorySnapshot,
  teamMemoryStatus,
  teamMemoryError,
  teamMemoryIncludeGovernanceCritical,
  localEngineSnapshot,
  localEngineStatus,
  localEngineError,
  doctorOverview,
  currentTask,
  sessions,
  replayBundle,
  replayLoading,
  replayError,
  replayRows,
  planSummary,
  searches,
  browses,
  thoughtAgents,
  playbookRuns,
  playbookRunsLoading,
  playbookRunsBusyRunId,
  playbookRunsMessage,
  playbookRunsError,
  stagedOperations,
  stagedOperationsLoading,
  stagedOperationsBusyId,
  stagedOperationsMessage,
  stagedOperationsError,
  visibleSourceCount,
  kernelLogs,
  securityRows,
  fileArtifacts,
  revisionArtifacts,
  fileContext,
  fileContextStatus,
  fileContextError,
  fileBrowsePath,
  fileBrowseEntries,
  fileBrowseStatus,
  fileBrowseError,
  branchSnapshot,
  branchStatus,
  branchError,
  sourceControlState,
  sourceControlStatus,
  sourceControlError,
  sourceControlLastCommitReceipt,
  capabilityRegistrySnapshot,
  capabilityRegistryStatus,
  capabilityRegistryError,
  pluginSnapshot,
  pluginStatus,
  pluginError,
  serverSnapshot,
  serverStatus,
  serverError,
  remoteEnvSnapshot,
  remoteEnvStatus,
  remoteEnvError,
  rewindSnapshot,
  rewindStatus,
  rewindError,
  selectedRewindSessionId,
  compareTargetSessionId,
  hookSnapshot,
  hooksStatus,
  hooksError,
  privacySnapshot,
  permissionsStatus,
  permissionsError,
  permissionPolicyState,
  permissionGovernanceRequest,
  permissionConnectorOverrides,
  permissionActiveOverrideCount,
  permissionProfiles,
  permissionCurrentProfileId,
  permissionApplyingProfileId,
  permissionEditingConnectorId,
  permissionApplyingGovernanceRequest,
  permissionRememberedApprovals,
  screenshotReceipts,
  substrateReceipts,
  onOpenArtifact,
  onRetryPlaybookRun,
  onResumePlaybookRun,
  onDismissPlaybookRun,
  onMessageWorkerSession,
  onStopWorkerSession,
  onPromoteRunResult,
  onPromoteStepResult,
  onPromoteStagedOperation,
  onRemoveStagedOperation,
  onLoadSession,
  onStopSession,
  onOpenGate,
  isGated,
  gateInfo,
  isPiiGate,
  gateDeadlineMs,
  gateActionError,
  credentialRequest,
  clarificationRequest,
  onApprove,
  onGrantScopedException,
  onDeny,
  onSubmitRuntimePassword,
  onCancelRuntimePassword,
  onSubmitClarification,
  onCancelClarification,
  onRefreshRewind,
  onSelectRewindSession,
  onOpenCompareForSession,
  onRefreshCompaction,
  onRefreshDoctor,
  onCompactSession,
  onSetTeamMemoryIncludeGovernanceCritical,
  onRefreshTeamMemory,
  onSyncTeamMemory,
  onForgetTeamMemoryEntry,
  onUpdateCompactionPolicy,
  onResetCompactionPolicy,
  onExportBundle,
  promotionStageBusyTarget,
  promotionStageMessage,
  promotionStageError,
  onStagePromotionCandidate,
  onRefreshPlugins,
  onTrustPlugin,
  onSetPluginEnabled,
  onReloadPlugin,
  onRefreshPluginCatalog,
  onRevokePluginTrust,
  onInstallPluginPackage,
  onUpdatePluginPackage,
  onRemovePluginPackage,
  onRefreshServer,
  onRefreshRemoteEnv,
  onRefreshHooks,
  onRefreshPermissions,
  onApplyPermissionProfile,
  onApplyPermissionGovernanceRequest,
  onDismissPermissionGovernanceRequest,
  onForgetRememberedApproval,
  onUpdatePermissionOverride,
  onResetPermissionOverride,
  onSetRememberedApprovalScopeMode,
  onSetRememberedApprovalExpiry,
  onToggleVimMode,
  onRequestReplLaunch,
  onHandleReplLaunchRequest,
  onOpenView,
  onRefreshFileContext,
  onRefreshBranches,
  onCreateBranchWorktree,
  onSwitchBranchWorktree,
  onRemoveBranchWorktree,
  onRefreshSourceControl,
  onStageSourceControlPath,
  onStageAllSourceControl,
  onUnstageSourceControlPath,
  onUnstageAllSourceControl,
  onDiscardSourceControlPath,
  onDiscardAllWorkingSourceControl,
  onCommitSourceControl,
  assistantWorkbench,
  activeWorkbenchSummary,
  retainedWorkbenchActivities,
  retainedWorkbenchEvidenceThreadId,
  retainedWorkbenchTraceLoading,
  retainedWorkbenchTraceError,
  retainedWorkbenchEventCount,
  retainedWorkbenchArtifactCount,
  latestRetainedWorkbenchEvent,
  latestRetainedWorkbenchArtifact,
  retainedWorkbenchEvidenceAttachable,
  mobileOverview,
  replLaunchRequest,
  onSeedIntent,
  onOpenFileDirectory,
  onBrowseFileParent,
  onRememberFilePath,
  onPinFilePath,
  onIncludeFilePath,
  onExcludeFilePath,
  onRemoveFilePath,
  onClearFileContext,
  openExternalUrl,
  extractArtifactUrl,
  formatTimestamp,
}: ArtifactHubDetailViewProps) {
  switch (activeView) {
    case "active_context":
      return <PlanView planSummary={planSummary} />;
    case "doctor":
      return (
        <DoctorView
          overview={doctorOverview}
          localEngineSnapshot={localEngineSnapshot}
          localEngineStatus={localEngineStatus}
          localEngineError={localEngineError}
          onRefreshDoctor={onRefreshDoctor}
          onOpenView={onOpenView}
        />
      );
    case "compact":
      return (
        <CompactView
          snapshot={compactionSnapshot}
          status={compactionStatus}
          error={compactionError}
          policy={compactionPolicy}
          teamMemorySnapshot={teamMemorySnapshot}
          teamMemoryStatus={teamMemoryStatus}
          teamMemoryError={teamMemoryError}
          teamMemoryIncludeGovernanceCritical={teamMemoryIncludeGovernanceCritical}
          onRefreshCompaction={onRefreshCompaction}
          onCompactSession={onCompactSession}
          onSetTeamMemoryIncludeGovernanceCritical={
            onSetTeamMemoryIncludeGovernanceCritical
          }
          onRefreshTeamMemory={onRefreshTeamMemory}
          onSyncTeamMemory={onSyncTeamMemory}
          onForgetTeamMemoryEntry={onForgetTeamMemoryEntry}
          onUpdateCompactionPolicy={onUpdateCompactionPolicy}
          onResetCompactionPolicy={onResetCompactionPolicy}
          onOpenView={onOpenView}
        />
      );
    case "branch":
      return (
        <BranchesView
          snapshot={branchSnapshot}
          status={branchStatus}
          error={branchError}
          onRefreshBranches={onRefreshBranches}
          onCreateBranchWorktree={onCreateBranchWorktree}
          onSwitchBranchWorktree={onSwitchBranchWorktree}
          onRemoveBranchWorktree={onRemoveBranchWorktree}
          onOpenView={onOpenView}
        />
      );
    case "commit":
      return (
        <CommitView
          branchSnapshot={branchSnapshot}
          branchStatus={branchStatus}
          branchError={branchError}
          sourceControlState={sourceControlState}
          sourceControlStatus={sourceControlStatus}
          sourceControlError={sourceControlError}
          sourceControlLastCommitReceipt={sourceControlLastCommitReceipt}
          onRefreshBranches={onRefreshBranches}
          onRefreshSourceControl={onRefreshSourceControl}
          onStageSourceControlPath={onStageSourceControlPath}
          onStageAllSourceControl={onStageAllSourceControl}
          onUnstageSourceControlPath={onUnstageSourceControlPath}
          onUnstageAllSourceControl={onUnstageAllSourceControl}
          onDiscardSourceControlPath={onDiscardSourceControlPath}
          onDiscardAllWorkingSourceControl={onDiscardAllWorkingSourceControl}
          onCommitSourceControl={onCommitSourceControl}
          onOpenView={onOpenView}
        />
      );
    case "review":
      return (
        <ReviewView
          currentTask={currentTask}
          planSummary={planSummary}
          branchSnapshot={branchSnapshot}
          compactionSnapshot={compactionSnapshot}
          sourceControlState={sourceControlState}
          sourceControlLastCommitReceipt={sourceControlLastCommitReceipt}
          replayBundle={replayBundle}
          visibleSourceCount={visibleSourceCount}
          screenshotReceipts={screenshotReceipts}
          substrateReceipts={substrateReceipts}
          durabilityOverview={durabilityOverview}
          privacyOverview={privacyOverview}
          exportPath={exportPath}
          exportTimestampMs={exportTimestampMs}
          exportStatus={exportStatus}
          exportVariant={exportVariant}
          verificationNotes={buildVerificationNotes(planSummary)}
          blockerSummary={taskBlockerSummary(currentTask)}
          onOpenView={onOpenView}
        />
      );
    case "pr_comments":
      return (
        <PrCommentsView
          currentTask={currentTask}
          planSummary={planSummary}
          branchSnapshot={branchSnapshot}
          sourceControlState={sourceControlState}
          sourceControlLastCommitReceipt={sourceControlLastCommitReceipt}
          replayBundle={replayBundle}
          visibleSourceCount={visibleSourceCount}
          screenshotReceipts={screenshotReceipts}
          substrateReceipts={substrateReceipts}
          onOpenView={onOpenView}
        />
      );
    case "mobile":
      return (
        <MobileView
          assistantWorkbench={assistantWorkbench}
          activeWorkbenchSummary={activeWorkbenchSummary}
          retainedWorkbenchActivities={retainedWorkbenchActivities}
          retainedWorkbenchEvidenceThreadId={retainedWorkbenchEvidenceThreadId}
          retainedWorkbenchTraceLoading={retainedWorkbenchTraceLoading}
          retainedWorkbenchTraceError={retainedWorkbenchTraceError}
          retainedWorkbenchEventCount={retainedWorkbenchEventCount}
          retainedWorkbenchArtifactCount={retainedWorkbenchArtifactCount}
          latestRetainedWorkbenchEvent={latestRetainedWorkbenchEvent}
          latestRetainedWorkbenchArtifact={latestRetainedWorkbenchArtifact}
          retainedWorkbenchEvidenceAttachable={retainedWorkbenchEvidenceAttachable}
          mobileOverview={mobileOverview}
          serverSnapshot={serverSnapshot}
          remoteEnvSnapshot={remoteEnvSnapshot}
          managedSettings={localEngineSnapshot?.managedSettings ?? null}
          onRequestReplLaunch={onRequestReplLaunch}
          onOpenView={onOpenView}
        />
      );
    case "voice":
      return <VoiceView onSeedIntent={onSeedIntent} onOpenView={onOpenView} />;
    case "server":
      return (
        <ServerView
          snapshot={serverSnapshot}
          status={serverStatus}
          error={serverError}
          remoteEnvSnapshot={remoteEnvSnapshot}
          managedSettings={localEngineSnapshot?.managedSettings ?? null}
          onRefreshServer={onRefreshServer}
          onRequestReplLaunch={onRequestReplLaunch}
          onOpenView={onOpenView}
        />
      );
    case "repl":
      return (
        <SpotlightReplView
          activeSessionId={activeSessionId}
          currentTask={currentTask}
          sessions={sessions}
          launchRequest={replLaunchRequest}
          onLoadSession={onLoadSession}
          onLaunchRequestHandled={onHandleReplLaunchRequest}
          onOpenStudioSession={(sessionId) => {
            void openStudioSessionTarget(sessionId);
          }}
          onStopSession={onStopSession}
          onOpenView={onOpenView}
        />
      );
    case "export":
      return (
        <ExportView
          exportSessionId={exportSessionId}
          exportStatus={exportStatus}
          exportError={exportError}
          exportPath={exportPath}
          exportTimestampMs={exportTimestampMs}
          exportVariant={exportVariant}
          durabilityOverview={durabilityOverview}
          privacyOverview={privacyOverview}
          compactionSnapshot={compactionSnapshot}
          stagedOperations={stagedOperations}
          replayBundle={replayBundle}
          replayLoading={replayLoading}
          replayError={replayError}
          promotionStageBusyTarget={promotionStageBusyTarget}
          promotionStageMessage={promotionStageMessage}
          promotionStageError={promotionStageError}
          onExportBundle={onExportBundle}
          onStagePromotionCandidate={onStagePromotionCandidate}
          onOpenView={onOpenView}
        />
      );
    case "share":
      return (
        <ShareView
          exportSessionId={exportSessionId}
          exportStatus={exportStatus}
          exportError={exportError}
          exportPath={exportPath}
          exportTimestampMs={exportTimestampMs}
          exportVariant={exportVariant}
          durabilityOverview={durabilityOverview}
          privacyOverview={privacyOverview}
          compactionSnapshot={compactionSnapshot}
          stagedOperations={stagedOperations}
          replayBundle={replayBundle}
          replayLoading={replayLoading}
          replayError={replayError}
          promotionStageBusyTarget={promotionStageBusyTarget}
          promotionStageMessage={promotionStageMessage}
          promotionStageError={promotionStageError}
          onExportBundle={onExportBundle}
          onStagePromotionCandidate={onStagePromotionCandidate}
          onOpenView={onOpenView}
        />
      );
    case "plugins":
      return (
        <PluginsView
          snapshot={pluginSnapshot}
          status={pluginStatus}
          error={pluginError}
          onRefreshPlugins={onRefreshPlugins}
          onTrustPlugin={onTrustPlugin}
          onSetPluginEnabled={onSetPluginEnabled}
          onReloadPlugin={onReloadPlugin}
          onRefreshPluginCatalog={onRefreshPluginCatalog}
          onRevokePluginTrust={onRevokePluginTrust}
          onInstallPluginPackage={onInstallPluginPackage}
          onUpdatePluginPackage={onUpdatePluginPackage}
          onRemovePluginPackage={onRemovePluginPackage}
          onOpenView={onOpenView}
        />
      );
    case "mcp":
      return (
        <McpView
          capabilityRegistrySnapshot={capabilityRegistrySnapshot}
          capabilityRegistryStatus={capabilityRegistryStatus}
          capabilityRegistryError={capabilityRegistryError}
          onOpenView={onOpenView}
        />
      );
    case "vim":
      return (
        <VimModeView
          snapshot={vimModeSnapshot}
          onOpenView={onOpenView}
          onToggleVimMode={onToggleVimMode}
        />
      );
    case "remote_env":
      return (
        <RemoteEnvView
          snapshot={remoteEnvSnapshot}
          status={remoteEnvStatus}
          error={remoteEnvError}
          onRefreshRemoteEnv={onRefreshRemoteEnv}
          onOpenView={onOpenView}
        />
      );
    case "privacy":
      return (
        <PrivacyView
          snapshot={privacySnapshot}
          permissionsStatus={permissionsStatus}
          permissionsError={permissionsError}
          onOpenView={onOpenView}
          onRefreshPermissions={onRefreshPermissions}
        />
      );
    case "keybindings":
      return <KeybindingsView snapshot={keybindingSnapshot} />;
    case "rewind":
      return (
        <RewindView
          snapshot={rewindSnapshot}
          status={rewindStatus}
          error={rewindError}
          onLoadSession={onLoadSession}
          onRefreshRewind={onRefreshRewind}
          selectedSessionId={selectedRewindSessionId}
          onSelectSession={onSelectRewindSession}
          onOpenCompareForSession={onOpenCompareForSession}
        />
      );
    case "hooks":
      return (
        <HooksView
          snapshot={hookSnapshot}
          status={hooksStatus}
          error={hooksError}
          permissionCurrentProfileId={permissionCurrentProfileId}
          permissionApplyingProfileId={permissionApplyingProfileId}
          permissionRememberedApprovals={permissionRememberedApprovals}
          permissionGovernanceRequest={permissionGovernanceRequest}
          permissionActiveOverrideCount={permissionActiveOverrideCount}
          onRefreshHooks={onRefreshHooks}
          onApplyPermissionProfile={onApplyPermissionProfile}
          onOpenView={onOpenView}
        />
      );
    case "permissions":
      return (
        <PermissionsView
          currentTask={currentTask}
          isGated={isGated}
          gateInfo={gateInfo}
          credentialRequest={credentialRequest}
          clarificationRequest={clarificationRequest}
          onOpenGate={onOpenGate}
          onOpenView={onOpenView}
          onRefreshPermissions={onRefreshPermissions}
          permissionsStatus={permissionsStatus}
          permissionsError={permissionsError}
          permissionPolicyState={permissionPolicyState}
          permissionGovernanceRequest={permissionGovernanceRequest}
          permissionConnectorOverrides={permissionConnectorOverrides}
          permissionActiveOverrideCount={permissionActiveOverrideCount}
          permissionProfiles={permissionProfiles}
          permissionCurrentProfileId={permissionCurrentProfileId}
          permissionApplyingProfileId={permissionApplyingProfileId}
          permissionEditingConnectorId={permissionEditingConnectorId}
          permissionApplyingGovernanceRequest={
            permissionApplyingGovernanceRequest
          }
          permissionRememberedApprovals={permissionRememberedApprovals}
          hookSnapshot={hookSnapshot}
          onApplyPermissionProfile={onApplyPermissionProfile}
          onApplyPermissionGovernanceRequest={
            onApplyPermissionGovernanceRequest
          }
          onDismissPermissionGovernanceRequest={
            onDismissPermissionGovernanceRequest
          }
          onForgetRememberedApproval={onForgetRememberedApproval}
          onUpdatePermissionOverride={onUpdatePermissionOverride}
          onResetPermissionOverride={onResetPermissionOverride}
          onSetRememberedApprovalScopeMode={
            onSetRememberedApprovalScopeMode
          }
          onSetRememberedApprovalExpiry={onSetRememberedApprovalExpiry}
        />
      );
    case "replay":
      return (
        <ArtifactHubReplayView
          loading={replayLoading}
          error={replayError}
          bundle={replayBundle}
          rows={replayRows}
          onOpenArtifact={onOpenArtifact}
        />
      );
    case "compare":
      return (
        <ArtifactHubCompareView
          activeSessionId={activeSessionId}
          sessions={sessions}
          compareTargetId={compareTargetSessionId}
          onCompareTargetChange={onOpenCompareForSession}
          onLoadSession={onLoadSession}
        />
      );
    case "tasks":
      return (
        <TasksView
          currentTask={currentTask}
          sessions={sessions}
          playbookRuns={playbookRuns}
          playbookRunsLoading={playbookRunsLoading}
          playbookRunsBusyRunId={playbookRunsBusyRunId}
          playbookRunsMessage={playbookRunsMessage}
          playbookRunsError={playbookRunsError}
          onLoadSession={onLoadSession}
          onStopSession={onStopSession}
          onOpenGate={onOpenGate}
          isGated={isGated}
          gateInfo={gateInfo}
          isPiiGate={isPiiGate}
          gateDeadlineMs={gateDeadlineMs}
          gateActionError={gateActionError}
          credentialRequest={credentialRequest}
          clarificationRequest={clarificationRequest}
          onApprove={onApprove}
          onGrantScopedException={onGrantScopedException}
          onDeny={onDeny}
          onSubmitRuntimePassword={onSubmitRuntimePassword}
          onCancelRuntimePassword={onCancelRuntimePassword}
          onSubmitClarification={onSubmitClarification}
          onCancelClarification={onCancelClarification}
          onOpenArtifact={onOpenArtifact}
          onRetryPlaybookRun={onRetryPlaybookRun}
          onResumePlaybookRun={onResumePlaybookRun}
          onDismissPlaybookRun={onDismissPlaybookRun}
          onMessageWorkerSession={onMessageWorkerSession}
          onStopWorkerSession={onStopWorkerSession}
          onPromoteRunResult={onPromoteRunResult}
          onPromoteStepResult={onPromoteStepResult}
        />
      );
    case "thoughts":
      return (
        <ThoughtsView
          planSummary={planSummary}
          searches={searches}
          browses={browses}
          thoughtAgents={thoughtAgents}
          playbookRuns={playbookRuns}
          playbookRunsLoading={playbookRunsLoading}
          playbookRunsBusyRunId={playbookRunsBusyRunId}
          playbookRunsMessage={playbookRunsMessage}
          playbookRunsError={playbookRunsError}
          stagedOperations={stagedOperations}
          stagedOperationsLoading={stagedOperationsLoading}
          stagedOperationsBusyId={stagedOperationsBusyId}
          stagedOperationsMessage={stagedOperationsMessage}
          stagedOperationsError={stagedOperationsError}
          onRetryPlaybookRun={onRetryPlaybookRun}
          onResumePlaybookRun={onResumePlaybookRun}
          onDismissPlaybookRun={onDismissPlaybookRun}
          onMessageWorkerSession={onMessageWorkerSession}
          onStopWorkerSession={onStopWorkerSession}
          onPromoteRunResult={onPromoteRunResult}
          onPromoteStepResult={onPromoteStepResult}
          onPromoteStagedOperation={onPromoteStagedOperation}
          onRemoveStagedOperation={onRemoveStagedOperation}
          onLoadSession={onLoadSession}
          onOpenArtifact={onOpenArtifact}
          openExternalUrl={openExternalUrl}
        />
      );
    case "substrate":
      return <SubstrateView substrateReceipts={substrateReceipts} />;
    case "sources":
      return (
        <SourcesView
          searches={searches}
          browses={browses}
          visibleSourceCount={visibleSourceCount}
          openExternalUrl={openExternalUrl}
        />
      );
    case "kernel_logs":
      return <KernelView kernelLogs={kernelLogs} />;
    case "security_policy":
      return (
        <SecurityView
          verificationNotes={buildVerificationNotes(planSummary)}
          selectedRoute={planSummary?.selectedRoute ?? null}
          securityRows={securityRows}
          onOpenArtifact={onOpenArtifact}
        />
      );
    case "files":
      return (
        <FilesView
          fileContext={fileContext}
          fileContextStatus={fileContextStatus}
          fileContextError={fileContextError}
          fileBrowsePath={fileBrowsePath}
          fileBrowseEntries={fileBrowseEntries}
          fileBrowseStatus={fileBrowseStatus}
          fileBrowseError={fileBrowseError}
          fileArtifacts={fileArtifacts}
          onOpenArtifact={onOpenArtifact}
          onOpenFileDirectory={onOpenFileDirectory}
          onBrowseFileParent={onBrowseFileParent}
          onRememberFilePath={onRememberFilePath}
          onPinFilePath={onPinFilePath}
          onIncludeFilePath={onIncludeFilePath}
          onExcludeFilePath={onExcludeFilePath}
          onRemoveFilePath={onRemoveFilePath}
          onRefreshFileContext={onRefreshFileContext}
          onClearFileContext={onClearFileContext}
          openExternalUrl={openExternalUrl}
          extractArtifactUrl={extractArtifactUrl}
          formatTimestamp={formatTimestamp}
        />
      );
    case "revisions":
      return (
        <ArtifactListView
          items={revisionArtifacts}
          label="Bundles"
          onOpenArtifact={onOpenArtifact}
          openExternalUrl={openExternalUrl}
          extractArtifactUrl={extractArtifactUrl}
          formatTimestamp={formatTimestamp}
        />
      );
    case "screenshots":
      return (
        <ScreenshotsView
          screenshotReceipts={screenshotReceipts}
          formatTimestamp={formatTimestamp}
        />
      );
    default:
      return null;
  }
}
