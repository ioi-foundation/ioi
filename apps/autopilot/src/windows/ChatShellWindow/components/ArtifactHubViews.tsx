import {
  formatSessionTimeAgo,
  type AssistantWorkbenchActivity,
  type AssistantWorkbenchSession,
} from "@ioi/agent-ide";
import { useEffect, useMemo, useState } from "react";
import {
  openReviewCapabilities,
  openReviewPolicyCenter,
  openEvidenceReviewSession,
} from "../../../services/reviewNavigation";
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
  SessionCompactionSnapshot,
  SessionPluginSnapshot,
  SessionRemoteEnvSnapshot,
  SessionServerSnapshot,
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
import type {
  CapabilityGovernanceRequest,
  ConnectorPolicyOverride,
  SessionPermissionProfileId,
  ShieldApprovalScopeMode,
  ShieldRememberedApprovalSnapshot,
  ShieldPolicyState,
} from "../../../surfaces/Policy/policyCenter";
import type {
  ChatPermissionConnectorOverrideSummary,
  ChatPermissionProfileSummary,
} from "../hooks/useChatPermissions";
import type { ChatPrivacySnapshot } from "../hooks/useChatPrivacySettings";
import type { ChatBranchesStatus } from "../hooks/useChatBranches";
import type { ChatLocalEngineStatus } from "../hooks/useChatLocalEngine";
import type { ChatPluginsStatus } from "../hooks/useChatPlugins";
import type { ChatRemoteEnvStatus } from "../hooks/useChatRemoteEnv";
import type { ChatServerModeStatus } from "../hooks/useChatServerMode";
import type { ChatSourceControlStatus } from "../hooks/useChatSourceControl";
import type { ChatVimModeSnapshot } from "../hooks/useChatVimMode";
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
import {
  MobileView,
  PrCommentsView,
  VoiceView,
} from "./ArtifactHubHandoffViews";
import { KeybindingsView, VimModeView } from "./ArtifactHubInputModeViews";
import { ExportView, ShareView } from "./ArtifactHubPackagingViews";
import {
  PermissionsView,
  PrivacyView,
} from "./ArtifactHubPrivacyPermissionViews";
import { ArtifactHubReplayView } from "./ArtifactHubReplayView";
import { RemoteContinuityPolicyCard } from "./ArtifactHubRemoteContinuityPolicyCard";
import { CompactView, RewindView } from "./ArtifactHubSessionContinuityViews";
import type {
  KernelLogRow,
  SecurityPolicyRow,
  SubstrateReceiptRow,
} from "./ArtifactHubViewModels";
import type { ChatKeybindingSnapshot } from "../hooks/useChatKeybindings";
import type { ChatCapabilityRegistryStatus } from "../hooks/useChatCapabilityRegistry";
import type { ChatPlaybookRunRecord } from "../../ChatShellWindow/hooks/useChatPlaybookRuns";
import type { ReplayTimelineRow } from "./ArtifactHubReplayModel";
import type { TraceBundleExportVariant } from "../utils/traceBundleExportModel";
import type { PromotionTarget } from "../utils/promotionStageModel";
import type { DurabilityEvidenceOverview } from "../utils/durabilityEvidenceModel";
import type { PrivacyEvidenceOverview } from "../utils/privacyEvidenceModel";
import { buildPluginRolloutAutomationPlan } from "../utils/pluginRolloutAutomationModel";
import { buildAuthorityAutomationPlan } from "../utils/authorityAutomationModel";
import {
  buildPluginRolloutDossier,
  buildPluginRolloutStageDraft,
} from "../utils/pluginRolloutModel";
import { ChatReplView } from "./ChatReplView";
import { ArtifactListView, FilesView } from "./ArtifactHubFileViews";
import { DoctorView, McpView, RemoteEnvView } from "./ArtifactHubRuntimeViews";
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
import { buildServerRemoteContinuityPolicyOverview } from "./artifactHubRemoteContinuityPolicyModel";
import {
  buildRemoteSessionContinuityAction,
  type ChatRemoteContinuityLaunchRequest,
} from "./artifactHubRemoteContinuityModel";
import type { ScreenshotReceiptEvidence } from "../utils/screenshotEvidence";
import { getSessionOperatorRuntime } from "../../../services/sessionRuntime";

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
  keybindingSnapshot: ChatKeybindingSnapshot;
  vimModeSnapshot: ChatVimModeSnapshot;
  compactionSnapshot: SessionCompactionSnapshot | null;
  compactionPolicy: SessionCompactionPolicy;
  compactionStatus: string;
  compactionError: string | null;
  teamMemorySnapshot: TeamMemorySyncSnapshot | null;
  teamMemoryStatus: string;
  teamMemoryError: string | null;
  teamMemoryIncludeGovernanceCritical: boolean;
  localEngineSnapshot: LocalEngineSnapshot | null;
  localEngineStatus: ChatLocalEngineStatus;
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
  playbookRuns: ChatPlaybookRunRecord[];
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
  branchStatus: ChatBranchesStatus;
  branchError: string | null;
  sourceControlState: WorkspaceSourceControlState | null;
  sourceControlStatus: ChatSourceControlStatus;
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
  replLaunchRequest: ChatRemoteContinuityLaunchRequest | null;
  onSeedIntent?: (intent: string) => void;
  capabilityRegistrySnapshot: CapabilityRegistrySnapshot | null;
  capabilityRegistryStatus: ChatCapabilityRegistryStatus;
  capabilityRegistryError: string | null;
  pluginSnapshot: SessionPluginSnapshot | null;
  pluginStatus: ChatPluginsStatus;
  pluginError: string | null;
  serverSnapshot: SessionServerSnapshot | null;
  serverStatus: ChatServerModeStatus;
  serverError: string | null;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null;
  remoteEnvStatus: ChatRemoteEnvStatus;
  remoteEnvError: string | null;
  rewindSnapshot: SessionRewindSnapshot | null;
  rewindStatus: string;
  rewindError: string | null;
  selectedRewindSessionId: string | null;
  compareTargetSessionId: string | null;
  hookSnapshot: SessionHookSnapshot | null;
  hooksStatus: string;
  hooksError: string | null;
  privacySnapshot: ChatPrivacySnapshot;
  permissionsStatus: string;
  permissionsError: string | null;
  permissionPolicyState: ShieldPolicyState;
  permissionGovernanceRequest: CapabilityGovernanceRequest | null;
  permissionConnectorOverrides: ChatPermissionConnectorOverrideSummary[];
  permissionActiveOverrideCount: number;
  permissionProfiles: ChatPermissionProfileSummary[];
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
  onSubmitClarification?: (
    optionId: string,
    otherText: string,
  ) => Promise<void>;
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
  onSetPluginEnabled?: (pluginId: string, enabled: boolean) => Promise<unknown>;
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
  onRequestReplLaunch?: (request: ChatRemoteContinuityLaunchRequest) => void;
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
  branchStatus: ChatBranchesStatus;
  branchError: string | null;
  sourceControlState: WorkspaceSourceControlState | null;
  sourceControlStatus: ChatSourceControlStatus;
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
        <p className="artifact-hub-note artifact-hub-note--error">
          {branchError}
        </p>
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
            <span>
              {branchSnapshot?.dirty ? "Dirty checkout" : "Clean checkout"}
            </span>
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
          Commits only include staged paths. Leave non-staged edits alone if
          they belong to later work.
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
              disabled={
                isBusy || !overview.canCommit || trimmedHeadline.length === 0
              }
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
          Stage only the paths that belong in the next checkpoint. Unstaged
          edits stay in the working tree and can be committed later.
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
                  {entry.originalPath ? (
                    <span>{entry.originalPath}</span>
                  ) : null}
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
  status: ChatBranchesStatus;
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
  const workspaceLabel =
    snapshot?.workspaceRoot?.trim() || "No active workspace";
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

  async function runLifecycleAction(
    action: BranchLifecycleAutomationQueuedAction,
  ) {
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

  function canRunLifecycleAction(
    action: BranchLifecycleAutomationQueuedAction,
  ) {
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
                <span>
                  {snapshot.dirty
                    ? "Tracked changes present"
                    : "No tracked changes"}
                </span>
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
                  <article
                    className="artifact-hub-generic-row"
                    key={branch.branchName}
                  >
                    <div className="artifact-hub-generic-meta">
                      <span>
                        {branch.isCurrent ? "Current branch" : "Local branch"}
                      </span>
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
                  <article
                    className="artifact-hub-generic-row"
                    key={worktree.path}
                  >
                    <div className="artifact-hub-generic-meta">
                      <span>
                        {worktree.isCurrent
                          ? "Current workcell"
                          : "Linked workcell"}
                      </span>
                      <span>{worktree.statusLabel}</span>
                      <span>
                        {worktree.branchName?.trim() || "Detached HEAD"}
                      </span>
                    </div>
                    <div className="artifact-hub-generic-title">
                      {worktree.path}
                    </div>
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
                          {worktree.prunable
                            ? "Remove stale workcell"
                            : "Remove workcell"}
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
          Uncommitted edits stay in the current checkout; the new workcell
          starts from the selected branch or commit.
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
  status: ChatServerModeStatus;
  error: string | null;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null;
  managedSettings: LocalEngineSnapshot["managedSettings"] | null;
  onRefreshServer?: () => Promise<unknown>;
  onRequestReplLaunch?: (request: ChatRemoteContinuityLaunchRequest) => void;
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
            <p>No continuity notes are retained for this shell yet.</p>
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
            <span>
              {snapshot?.remoteAttachableSessionCount ?? 0} remote attachable
            </span>
            <span>
              {snapshot?.remoteHistoryOnlySessionCount ?? 0} remote history-only
            </span>
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
                  onRequestReplLaunch(
                    governance.secondaryAction!.launchRequest,
                  );
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
              <article
                className="artifact-hub-generic-row"
                key={session.sessionId}
              >
                {(() => {
                  const continuityAction =
                    buildRemoteSessionContinuityAction(session);
                  return (
                    <>
                      <div className="artifact-hub-generic-meta">
                        <span>{session.sourceLabel}</span>
                        <span>{formatSessionTimeAgo(session.timestamp)}</span>
                        <span>{session.presenceLabel}</span>
                      </div>
                      <div className="artifact-hub-generic-title">
                        {session.title}
                      </div>
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
                              onRequestReplLaunch(
                                continuityAction.launchRequest,
                              );
                            }}
                          >
                            {continuityAction.chatShellLabel}
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="artifact-hub-open-btn secondary"
                          onClick={() => {
                            void openEvidenceReviewSession(session.sessionId);
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
          projection as Chat, retained sessions, and the standalone REPL.
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
  status: ChatPluginsStatus;
  error: string | null;
  onRefreshPlugins?: () => Promise<unknown>;
  onTrustPlugin?: (
    pluginId: string,
    enableAfterTrust?: boolean,
  ) => Promise<unknown>;
  onSetPluginEnabled?: (pluginId: string, enabled: boolean) => Promise<unknown>;
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
  const workspaceLabel =
    snapshot?.workspaceRoot?.trim() || "No active workspace";
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
  const [rolloutStageError, setRolloutStageError] = useState<string | null>(
    null,
  );
  const [rolloutAutomationBusy, setRolloutAutomationBusy] = useState(false);
  const [rolloutAutomationMessage, setRolloutAutomationMessage] = useState<
    string | null
  >(null);
  const [rolloutAutomationError, setRolloutAutomationError] = useState<
    string | null
  >(null);

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
            throw new Error(
              "Managed package install automation is unavailable.",
            );
          }
          await onInstallPluginPackage(action.pluginId);
          setRolloutAutomationMessage(
            `Installed the managed package copy for ${action.pluginId}.`,
          );
          break;
        case "apply_update":
          if (!action.pluginId || !onUpdatePluginPackage) {
            throw new Error(
              "Managed package update automation is unavailable.",
            );
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
          <span>
            {snapshot?.reviewRequiredPluginCount ?? 0} review required
          </span>
          <span>{snapshot?.criticalUpdateCount ?? 0} critical updates</span>
          <span>{snapshot?.refreshAvailableCount ?? 0} refresh available</span>
          <span>{snapshot?.refreshFailedCount ?? 0} refresh failed</span>
          <span>{snapshot?.catalogSourceCount ?? 0} catalog sources</span>
          <span>{snapshot?.remoteCatalogSourceCount ?? 0} remote sources</span>
          <span>{snapshot?.localCatalogSourceCount ?? 0} local sources</span>
          <span>{snapshot?.failedCatalogSourceCount ?? 0} failed sources</span>
          <span>{snapshot?.catalogChannelCount ?? 0} catalog channels</span>
          <span>{snapshot?.nonconformantChannelCount ?? 0} nonconformant</span>
          <span>
            {snapshot?.nonconformantSourceCount ?? 0} nonconformant sources
          </span>
          <span>{snapshot?.staleCatalogCount ?? 0} stale catalogs</span>
          <span>{snapshot?.expiredCatalogCount ?? 0} expired catalogs</span>
          <span>{snapshot?.verifiedPluginCount ?? 0} verified</span>
          <span>
            {snapshot?.unverifiedPluginCount ?? 0} unsigned/unverified
          </span>
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
            <span>
              {rolloutAutomationPlan.queuedActions.length} queued rollout steps
            </span>
          ) : null}
          {rolloutAutomationPlan.governanceNotes.length > 0 ? (
            <span>
              {rolloutAutomationPlan.governanceNotes.length} governed review{" "}
              {rolloutAutomationPlan.governanceNotes.length === 1
                ? "gate"
                : "gates"}
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
            <strong>
              {snapshot?.verifiedPluginCount ?? 0} verified packages
            </strong>
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
            <span>
              {snapshot?.installablePackageCount ?? 0} ready to install
            </span>
            <span>{snapshot?.recommendedPluginCount ?? 0} recommended</span>
            <span>
              {snapshot?.reviewRequiredPluginCount ?? 0} review required
            </span>
            <span>{snapshot?.criticalUpdateCount ?? 0} critical updates</span>
            <span>
              {snapshot?.refreshAvailableCount ?? 0} refresh available
            </span>
            <span>{snapshot?.refreshFailedCount ?? 0} refresh failed</span>
            <span>{snapshot?.catalogSourceCount ?? 0} catalog sources</span>
            <span>
              {snapshot?.remoteCatalogSourceCount ?? 0} remote sources
            </span>
            <span>{snapshot?.staleCatalogCount ?? 0} stale catalogs</span>
            <span>{snapshot?.filesystemSkillCount ?? 0} filesystem skills</span>
            <span>
              {snapshot?.hookContributionCount ?? 0} hook contributions
            </span>
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
              onClick={() => void openReviewCapabilities()}
            >
              Open Chat Capabilities
            </button>
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => void openReviewPolicyCenter()}
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
              <article
                className="artifact-hub-generic-row"
                key={source.sourceId}
              >
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
                <div className="artifact-hub-generic-title">
                  {source.sourceId}
                </div>
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
                    <span>Source: {humanizeStatus(channel.refreshSource)}</span>
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
            <span className="artifact-hub-policy-pill">
              {receipts.length} retained
            </span>
          </div>
          <p>
            Latest remembered-trust, enable, reload, and revoke outcomes for the
            runtime plugin roster.
          </p>
          <div className="artifact-hub-generic-list">
            {receipts.slice(0, 4).map((receipt) => (
              <article
                className="artifact-hub-generic-row"
                key={receipt.receiptId}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{receipt.pluginLabel}</span>
                  <span>{humanizeStatus(receipt.action)}</span>
                  <span>{humanizeStatus(receipt.status)}</span>
                  <span>{formatTaskTimestamp(receipt.timestampMs)}</span>
                </div>
                <p className="artifact-hub-generic-summary">
                  {receipt.summary}
                </p>
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
              <article
                className="artifact-hub-generic-row"
                key={plugin.pluginId}
              >
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
                      Verified{" "}
                      {formatTaskTimestamp(plugin.verificationTimestampMs)}
                    </span>
                  ) : null}
                  {plugin.verificationSource ? (
                    <span>
                      Source: {humanizeStatus(plugin.verificationSource)}
                    </span>
                  ) : null}
                  {plugin.verifiedDigestSha256 ? (
                    <span>
                      Digest sha256:{plugin.verifiedDigestSha256.slice(0, 16)}
                      ...
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
                      Publisher source:{" "}
                      {humanizeStatus(plugin.publisherTrustSource)}
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
                      {formatTaskTimestamp(
                        plugin.authorityTrustBundleIssuedAtMs,
                      )}
                    </span>
                  ) : null}
                  {plugin.authorityTrustBundleExpiresAtMs ? (
                    <span>
                      Trust bundle expires{" "}
                      {formatTaskTimestamp(
                        plugin.authorityTrustBundleExpiresAtMs,
                      )}
                    </span>
                  ) : null}
                  {plugin.authorityTrustIssuerLabel ? (
                    <span>
                      Trust issuer: {plugin.authorityTrustIssuerLabel}
                    </span>
                  ) : null}
                  {plugin.authorityTrustIssuerId ? (
                    <span>
                      Trust issuer ID: {plugin.authorityTrustIssuerId}
                    </span>
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
                      Catalog issued{" "}
                      {formatTaskTimestamp(plugin.catalogIssuedAtMs)}
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
                    <span>
                      Refresh bundle ID: {plugin.catalogRefreshBundleId}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshBundleIssuedAtMs ? (
                    <span>
                      Refresh bundle issued{" "}
                      {formatTaskTimestamp(
                        plugin.catalogRefreshBundleIssuedAtMs,
                      )}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshBundleExpiresAtMs ? (
                    <span>
                      Refresh bundle expires{" "}
                      {formatTaskTimestamp(
                        plugin.catalogRefreshBundleExpiresAtMs,
                      )}
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
                    <span>
                      Install source: {plugin.packageInstallSourceLabel}
                    </span>
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
                      <span key={`${plugin.pluginId}-${product}`}>
                        {product}
                      </span>
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
                        <span key={`${plugin.pluginId}-${capability}`}>
                          {capability}
                        </span>
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
                    <span>
                      Trusted {formatTaskTimestamp(plugin.lastTrustedAtMs)}
                    </span>
                  ) : null}
                  {plugin.lastReloadedAtMs ? (
                    <span>
                      Reloaded {formatTaskTimestamp(plugin.lastReloadedAtMs)}
                    </span>
                  ) : null}
                  {plugin.lastInstalledAtMs ? (
                    <span>
                      Installed {formatTaskTimestamp(plugin.lastInstalledAtMs)}
                    </span>
                  ) : null}
                  {plugin.lastUpdatedAtMs ? (
                    <span>
                      Updated {formatTaskTimestamp(plugin.lastUpdatedAtMs)}
                    </span>
                  ) : null}
                  {plugin.lastRemovedAtMs ? (
                    <span>
                      Removed {formatTaskTimestamp(plugin.lastRemovedAtMs)}
                    </span>
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
                  {plugin.runtimeTrustState === "trusted" &&
                  onRevokePluginTrust ? (
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
                    onClick={() => void openReviewCapabilities()}
                  >
                    Open Chat Capabilities
                  </button>
                  <button
                    type="button"
                    className="artifact-hub-open-btn secondary"
                    onClick={() => void openReviewPolicyCenter()}
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
  const workspaceLabel =
    snapshot?.workspaceRoot?.trim() || "No active workspace";
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
              onClick={() =>
                onOpenView(authorityAutomationPlan.recommendedView!)
              }
            >
              {authorityAutomationPlan.recommendedView === "permissions"
                ? "Review Permissions"
                : "Review hooks"}
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openReviewPolicyCenter()}
          >
            Open Chat Policy
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
              <article
                className="artifact-hub-generic-row"
                key={`${receipt.timestampMs}-${receipt.toolName}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{receipt.title}</span>
                  <span>{formatTaskTimestamp(receipt.timestampMs)}</span>
                  <span>{humanizeStatus(receipt.status)}</span>
                </div>
                <div className="artifact-hub-generic-title">
                  {receipt.toolName}
                </div>
                <p className="artifact-hub-generic-summary">
                  {receipt.summary}
                </p>
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
                    onClick={() => void openReviewCapabilities()}
                  >
                    Open Chat Capabilities
                  </button>
                  <button
                    type="button"
                    className="artifact-hub-open-btn"
                    onClick={() => void openReviewPolicyCenter()}
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
          No runtime-visible hook contributions are retained for this session
          yet. Track or enable an extension with a `hooks` contribution, then
          reopen this drawer.
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
            onClick={() => void openReviewCapabilities()}
          >
            Open Chat Capabilities
          </button>
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => void openReviewPolicyCenter()}
          >
            Open Governing Policy
          </button>
        </div>
      </section>
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
          teamMemoryIncludeGovernanceCritical={
            teamMemoryIncludeGovernanceCritical
          }
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
          retainedWorkbenchEvidenceAttachable={
            retainedWorkbenchEvidenceAttachable
          }
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
        <ChatReplView
          activeSessionId={activeSessionId}
          currentTask={currentTask}
          sessions={sessions}
          launchRequest={replLaunchRequest}
          onLoadSession={onLoadSession}
          onLaunchRequestHandled={onHandleReplLaunchRequest}
          onOpenStudioSession={(sessionId) => {
            void openEvidenceReviewSession(sessionId);
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
          onSetRememberedApprovalScopeMode={onSetRememberedApprovalScopeMode}
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
