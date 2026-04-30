import type {
  AssistantWorkbenchActivity,
  AssistantWorkbenchSession,
} from "@ioi/agent-ide";
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
} from "../../../../types";
import type { AssistantWorkbenchSummary } from "../../../../lib/assistantWorkbenchSummary";
import type {
  CapabilityGovernanceRequest,
  ConnectorPolicyOverride,
  SessionPermissionProfileId,
  ShieldApprovalScopeMode,
  ShieldRememberedApprovalSnapshot,
  ShieldPolicyState,
} from "../../../../surfaces/Policy/policyCenter";
import type {
  ChatPermissionConnectorOverrideSummary,
  ChatPermissionProfileSummary,
} from "../../hooks/useChatPermissions";
import type { ChatPrivacySnapshot } from "../../hooks/useChatPrivacySettings";
import type { ChatBranchesStatus } from "../../hooks/useChatBranches";
import type { ChatLocalEngineStatus } from "../../hooks/useChatLocalEngine";
import type { ChatPluginsStatus } from "../../hooks/useChatPlugins";
import type { ChatRemoteEnvStatus } from "../../hooks/useChatRemoteEnv";
import type { ChatServerModeStatus } from "../../hooks/useChatServerMode";
import type { ChatSourceControlStatus } from "../../hooks/useChatSourceControl";
import type { ChatVimModeSnapshot } from "../../hooks/useChatVimMode";
import type {
  KernelLogRow,
  SecurityPolicyRow,
  SubstrateReceiptRow,
} from "../ArtifactHubViewModels";
import type { ChatKeybindingSnapshot } from "../../hooks/useChatKeybindings";
import type { ChatCapabilityRegistryStatus } from "../../hooks/useChatCapabilityRegistry";
import type { ChatPlaybookRunRecord } from "../../hooks/useChatPlaybookRuns";
import type { ReplayTimelineRow } from "../ArtifactHubReplayModel";
import type { TraceBundleExportVariant } from "../../utils/traceBundleExportModel";
import type { PromotionTarget } from "../../utils/promotionStageModel";
import type { DurabilityEvidenceOverview } from "../../utils/durabilityEvidenceModel";
import type { PrivacyEvidenceOverview } from "../../utils/privacyEvidenceModel";
import type { DoctorOverview } from "../artifactHubDoctorModel";
import type { MobileOverview } from "../artifactHubMobileModel";
import type { ChatRemoteContinuityLaunchRequest } from "../artifactHubRemoteContinuityModel";
import type { ScreenshotReceiptEvidence } from "../../utils/screenshotEvidence";

export interface ArtifactHubDetailViewProps {
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
