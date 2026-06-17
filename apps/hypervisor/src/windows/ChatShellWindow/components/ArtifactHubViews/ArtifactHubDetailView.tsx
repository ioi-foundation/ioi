import { openEvidenceReviewSession } from "../../../../services/reviewNavigation";
import { ArtifactHubCompareView } from "../ArtifactHubCompareView";
import { ReviewView, SourcesView, ThoughtsView } from "../ArtifactHubViewRegistry";
import { KernelView, ScreenshotsView, SecurityView, SubstrateView } from "../ArtifactHubEvidenceViews";
import { MobileView, PrCommentsView, VoiceView } from "../ArtifactHubHandoffViews";
import { KeybindingsView, VimModeView } from "../ArtifactHubInputModeViews";
import { ExportView, ShareView } from "../ArtifactHubPackagingViews";
import { PermissionsView, PrivacyView } from "../ArtifactHubPrivacyPermissionViews";
import { ArtifactHubReplayView } from "../ArtifactHubReplayView";
import { CompactView, RewindView } from "../ArtifactHubSessionContinuityViews";
import { ChatReplView } from "../ChatReplView";
import { ArtifactListView, FilesView } from "../ArtifactHubFileViews";
import { DoctorView, McpView, RemoteEnvView } from "../ArtifactHubRuntimeViews";
import { PlanView, TasksView } from "../ArtifactHubTaskViews";
import { buildVerificationNotes, taskBlockerSummary } from "../ArtifactHubViewHelpers";
import { BranchesView, CommitView } from "./sourceControlViews";
import { CapabilityInventoryView, HooksView, PluginsView, ServerView } from "./runtimeGovernanceViews";
import type { ArtifactHubDetailViewProps } from "./types";

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
    case "process":
    case "active_context":
      return <PlanView planSummary={planSummary} />;
    case "tools":
      return <KernelView kernelLogs={kernelLogs} />;
    case "runtime_details":
      return (
        <SecurityView
          verificationNotes={buildVerificationNotes(planSummary)}
          selectedRoute={planSummary?.selectedRoute ?? null}
          securityRows={securityRows}
          onOpenArtifact={onOpenArtifact}
        />
      );
    case "trace_export":
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
    case "capability_inventory":
      return (
        <CapabilityInventoryView
          localEngineSnapshot={localEngineSnapshot}
          localEngineStatus={localEngineStatus}
          localEngineError={localEngineError}
        />
      );
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
          onOpenChatSession={(sessionId) => {
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
