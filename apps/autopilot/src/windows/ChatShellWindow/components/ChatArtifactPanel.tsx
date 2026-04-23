import type {
  AgentTask,
  AgentEvent,
  Artifact,
  ArtifactHubViewKey,
  ClarificationRequest,
  CredentialRequest,
  GateInfo,
  LocalEngineStagedOperation,
  SessionSummary,
  SourceSummary,
  ThoughtSummary,
} from "../../../types";
import type { ChatPlaybookRunRecord } from "../hooks/useChatPlaybookRuns";
import { icons } from "../../ChatShellWindow/components/Icons";
import { ArtifactHubSidebar } from "../../ChatShellWindow/components/ArtifactHubSidebar";
import { ArtifactSidebar } from "../../ChatShellWindow/components/ArtifactSidebar";

const TRACE_DRAWER_VIEWS = new Set<ArtifactHubViewKey>([
  "thoughts",
  "sources",
  "screenshots",
  "kernel_logs",
]);

interface ChatArtifactPanelProps {
  visible: boolean;
  artifactHubView: ArtifactHubViewKey | null;
  artifactHubTurnId: string | null;
  activeSessionId?: string | null;
  task: AgentTask | null;
  sessions: SessionSummary[];
  events: AgentEvent[];
  artifacts: Artifact[];
  selectedArtifact: Artifact | null;
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
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
  onOpenArtifact: (artifactId: string) => void;
  onRetryPlaybookRun: (runId: string) => void;
  onResumePlaybookRun: (runId: string, stepId?: string | null) => void;
  onDismissPlaybookRun: (runId: string) => void;
  onMessageWorkerSession: (
    runId: string,
    sessionId: string,
    message: string,
  ) => void;
  onStopWorkerSession: (runId: string, sessionId: string) => void;
  onPromoteRunResult: (runId: string) => void;
  onPromoteStepResult: (runId: string, stepId: string) => void;
  onPromoteStagedOperation: (operationId: string) => void;
  onRemoveStagedOperation: (operationId: string) => void;
  onLoadSession: (sessionId: string) => void;
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
  onSeedIntent?: (intent: string) => void;
  onClose: () => void;
}

export function ChatArtifactPanel({
  visible,
  artifactHubView,
  artifactHubTurnId,
  activeSessionId,
  task,
  sessions,
  events,
  artifacts,
  selectedArtifact,
  sourceSummary,
  thoughtSummary,
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
  onSeedIntent,
  onClose,
}: ChatArtifactPanelProps) {
  if (!visible) {
    return null;
  }

  if (selectedArtifact) {
    return <ArtifactSidebar artifact={selectedArtifact} onClose={onClose} />;
  }

  const showEmptyDrawer =
    !task &&
    !activeSessionId &&
    sessions.length === 0 &&
    events.length === 0 &&
    artifacts.length === 0 &&
    !sourceSummary &&
    !thoughtSummary;
  const focusedTraceDrawer =
    artifactHubView != null && TRACE_DRAWER_VIEWS.has(artifactHubView);

  if (showEmptyDrawer) {
    return (
      <div className="artifact-panel artifact-hub-panel">
        <div className="artifact-header">
          <div className="artifact-meta">
            <div className="artifact-icon">{icons.sidebar}</div>
            <span className="artifact-filename artifact-filename--drawer">
              {focusedTraceDrawer ? "Thinking inspector" : "Execution drawer"}
            </span>
            <span className="artifact-tag">
              {focusedTraceDrawer ? "Thinking" : "Plan"}
            </span>
          </div>
          <div className="artifact-actions">
            <button
              className="artifact-action-btn artifact-action-btn--back"
              onClick={onClose}
              title="Back to chat"
              type="button"
            >
              Back to chat
            </button>
            <button
              className="artifact-action-btn close"
              onClick={onClose}
              title="Close drawer"
              type="button"
            >
              {icons.close}
            </button>
          </div>
        </div>

        <div className="artifact-content">
          <div className="artifact-empty-drawer">
            <p className="artifact-empty-drawer-eyebrow">No active session</p>
            <h2>Plan and evidence appear here once a run starts.</h2>
            <p>
              Keep the drawer open for plan-first work, or start a task to
              populate execution context, sources, and validation receipts.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <ArtifactHubSidebar
      initialView={artifactHubView || undefined}
      initialTurnId={artifactHubTurnId}
      activeSessionId={activeSessionId}
      task={task}
      sessions={sessions}
      events={events}
      artifacts={artifacts}
      sourceSummary={sourceSummary}
      thoughtSummary={thoughtSummary}
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
      onOpenArtifact={onOpenArtifact}
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
      onSeedIntent={onSeedIntent}
      onClose={onClose}
    />
  );
}
