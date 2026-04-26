import type {
  AgentTask,
  ClarificationRequest,
  CredentialRequest,
  GateInfo,
  PlanSummary,
  SessionSummary,
} from "../../../types";
import type { ChatPlaybookRunRecord } from "../../ChatShellWindow/hooks/useChatPlaybookRuns";
import { buildTaskDelegationOverview } from "./artifactHubTaskGraphModel";
import { LivePlaybookRunsSection } from "./LivePlaybookRunsSection";
import { ChatGateDock } from "../../ChatShellWindow/components/ChatGateDock";
import {
  formatTaskTimestamp,
  humanizeStatus,
  latestTaskOutputs,
  taskBlockerSummary,
} from "./ArtifactHubViewHelpers";

export function PlanView({
  planSummary,
}: {
  planSummary: PlanSummary | null;
}) {
  if (!planSummary) {
    return (
      <p className="artifact-hub-empty">
        No execution plan summary was captured for this scope.
      </p>
    );
  }

  const routeLabel =
    planSummary.routeDecision?.selectedProviderRouteLabel ||
    planSummary.selectedRoute ||
    planSummary.routeFamily;
  const outputLabel =
    planSummary.routeDecision?.outputIntent?.replace(/[_-]+/g, " ") ||
    "direct response";
  const workerLabel = planSummary.activeWorkerLabel || "Autopilot";
  const verifierLabel =
    planSummary.verifierOutcome ||
    (planSummary.verifierState === "not_engaged" ? null : planSummary.verifierState);
  const rows = [
    {
      label: "Route",
      value: `${routeLabel} · ${outputLabel}`,
    },
    {
      label: "Worker",
      value: `${workerLabel}${
        planSummary.topology && planSummary.topology !== "single_agent"
          ? ` · ${planSummary.topology.replace(/[_-]+/g, " ")}`
          : ""
      }`,
    },
    (planSummary.progressSummary || planSummary.prepSummary)
      ? {
          label: "Plan note",
          value: planSummary.progressSummary || planSummary.prepSummary || "",
        }
      : null,
    verifierLabel
      ? {
          label: "Verify",
          value: verifierLabel.replace(/[_-]+/g, " "),
        }
      : null,
  ].filter(Boolean) as Array<{ label: string; value: string }>;

  return (
    <div className="artifact-hub-plan artifact-hub-plan--thoughts">
      <section className="thoughts-section">
        <div className="thoughts-agent-header">
          <span className="thoughts-agent-dot" />
          <span className="thoughts-agent-name">Autopilot</span>
          <span className="thoughts-agent-role">Plan</span>
        </div>
        <div className="thoughts-notes">
          {rows.map((row) => (
            <div className="thoughts-note" key={row.label}>
              <strong>{row.label}</strong>
              <span>{row.value}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

export function TasksView({
  currentTask,
  sessions,
  playbookRuns,
  playbookRunsLoading,
  playbookRunsBusyRunId,
  playbookRunsMessage,
  playbookRunsError,
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
  onOpenArtifact,
  onRetryPlaybookRun,
  onResumePlaybookRun,
  onDismissPlaybookRun,
  onMessageWorkerSession,
  onStopWorkerSession,
  onPromoteRunResult,
  onPromoteStepResult,
}: {
  currentTask: AgentTask | null;
  sessions: SessionSummary[];
  playbookRuns: ChatPlaybookRunRecord[];
  playbookRunsLoading: boolean;
  playbookRunsBusyRunId: string | null;
  playbookRunsMessage: string | null;
  playbookRunsError: string | null;
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
}) {
  if (!currentTask) {
    return (
      <p className="artifact-hub-empty">
        No runtime task is available yet. Start a run, then open Tasks to review
        checklist state, blockers, and output.
      </p>
    );
  }

  const sessionId = currentTask.session_id || currentTask.id;
  const sessionSummary =
    sessions.find((session) => session.session_id === sessionId) || null;
  const effectiveClarificationRequest =
    clarificationRequest ?? currentTask.clarification_request;
  const effectiveCredentialRequest =
    credentialRequest ?? currentTask.credential_request;
  const effectiveGateInfo = gateInfo ?? currentTask.gate_info;
  const effectiveIsGated =
    isGated ||
    Boolean(
      currentTask.pending_request_hash ||
        currentTask.gate_info ||
        currentTask.phase === "Gate",
    );
  const blocker = taskBlockerSummary(currentTask, {
    clarificationRequest: effectiveClarificationRequest,
    credentialRequest: effectiveCredentialRequest,
    gateInfo: effectiveGateInfo,
    isGated: effectiveIsGated,
  });
  const recentOutputs = latestTaskOutputs(currentTask);
  const delegationOverview = buildTaskDelegationOverview(playbookRuns);
  const canStop =
    currentTask.phase === "Running" ||
    currentTask.background_tasks.some((entry) => entry.can_stop);
  const completedChecklistCount = currentTask.session_checklist.filter((entry) =>
    ["complete", "completed", "done", "verified"].includes(
      entry.status.trim().toLowerCase(),
    ),
  ).length;
  const heroTitle =
    sessionSummary?.title.trim() ||
    currentTask.intent.trim() ||
    currentTask.current_step.trim() ||
    `Task ${currentTask.id.slice(0, 8)}`;
  const hasPlaceholderStep =
    currentTask.current_step.trim().length === 0 ||
    currentTask.current_step.trim().toLowerCase() === "initializing...";
  const heroDetail = effectiveClarificationRequest
    ? hasPlaceholderStep
      ? effectiveClarificationRequest.question
      : currentTask.current_step
    : effectiveCredentialRequest
      ? hasPlaceholderStep
        ? effectiveCredentialRequest.prompt ||
          humanizeStatus(effectiveCredentialRequest.kind)
        : currentTask.current_step
      : effectiveIsGated && effectiveGateInfo
        ? hasPlaceholderStep
          ? effectiveGateInfo.description ||
            effectiveGateInfo.operator_note ||
            "Waiting on an operator decision."
          : currentTask.current_step
        : currentTask.current_step || "Waiting for the next retained step.";

  return (
    <div className="artifact-hub-tasks">
      <section className="artifact-hub-task-hero">
        <div className="artifact-hub-task-hero-copy">
          <span className="artifact-hub-task-eyebrow">
            Runtime-owned task review
          </span>
          <h3>{heroTitle}</h3>
          <p>{heroDetail}</p>
        </div>
        <div className="artifact-hub-generic-actions">
          {sessionId && onLoadSession && (
            <button
              className="artifact-hub-open-btn"
              onClick={() => onLoadSession(sessionId)}
              type="button"
            >
              Resume session
            </button>
          )}
          {effectiveIsGated && onOpenGate && (
            <button
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenGate()}
              type="button"
            >
              Open gate shell
            </button>
          )}
          {canStop && onStopSession && (
            <button
              className="artifact-hub-open-btn secondary"
              onClick={() => onStopSession()}
              type="button"
            >
              Stop task
            </button>
          )}
        </div>
      </section>

      {blocker ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>{blocker.title}</span>
            <span>Needs attention</span>
          </div>
          <p className="artifact-hub-generic-summary">{blocker.detail}</p>
          {(effectiveClarificationRequest || effectiveCredentialRequest || effectiveIsGated) &&
          onApprove &&
          onDeny &&
          onSubmitRuntimePassword &&
          onCancelRuntimePassword &&
          onSubmitClarification &&
          onCancelClarification ? (
            <ChatGateDock
              inline
              isGated={effectiveIsGated}
              gateInfo={effectiveGateInfo}
              isPiiGate={Boolean(isPiiGate)}
              gateDeadlineMs={gateDeadlineMs}
              gateActionError={gateActionError ?? null}
              onApprove={onApprove}
              onGrantScopedException={onGrantScopedException ?? (() => {})}
              onDeny={onDeny}
              showPasswordPrompt={Boolean(effectiveCredentialRequest)}
              credentialRequest={effectiveCredentialRequest}
              onSubmitRuntimePassword={onSubmitRuntimePassword}
              onCancelRuntimePassword={onCancelRuntimePassword}
              showClarificationPrompt={Boolean(effectiveClarificationRequest)}
              clarificationRequest={effectiveClarificationRequest}
              onSubmitClarification={onSubmitClarification}
              onCancelClarification={onCancelClarification}
            />
          ) : null}
        </section>
      ) : null}

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Checklist</span>
          <span>
            {completedChecklistCount}/{currentTask.session_checklist.length}
          </span>
        </div>
        {currentTask.session_checklist.length > 0 ? (
          <div className="artifact-hub-generic-list">
            {currentTask.session_checklist.map((entry) => (
              <article
                className="artifact-hub-generic-row artifact-hub-task-checklist"
                key={entry.item_id}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{humanizeStatus(entry.status)}</span>
                  <span>{formatTaskTimestamp(entry.updated_at_ms)}</span>
                </div>
                <div className="artifact-hub-generic-title">{entry.label}</div>
                {entry.detail ? (
                  <p className="artifact-hub-generic-summary">{entry.detail}</p>
                ) : null}
              </article>
            ))}
          </div>
        ) : (
          <p className="artifact-hub-empty">
            This task does not have a retained checklist yet.
          </p>
        )}
      </section>

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Delegation</span>
          <span>{playbookRuns.length}</span>
        </div>
        <div className="artifact-hub-task-grid">
          <article className="artifact-hub-task-card">
            <div className="artifact-hub-task-card-head">Live runs</div>
            <strong>{delegationOverview.runCount}</strong>
            <span>Retained playbook runs for this task</span>
          </article>
          <article className="artifact-hub-task-card">
            <div className="artifact-hub-task-card-head">Ready now</div>
            <strong>{delegationOverview.readyStepCount}</strong>
            <span>Dependency-satisfied pending steps</span>
          </article>
          <article className="artifact-hub-task-card">
            <div className="artifact-hub-task-card-head">Blocked</div>
            <strong>{delegationOverview.blockedStepCount}</strong>
            <span>Blocked or failed delegated steps</span>
          </article>
          <article className="artifact-hub-task-card">
            <div className="artifact-hub-task-card-head">Outputs</div>
            <strong>{delegationOverview.promotableStepCount}</strong>
            <span>Successful worker receipts ready for review</span>
          </article>
        </div>
        {playbookRuns.length > 0 ||
        playbookRunsLoading ||
        playbookRunsMessage ||
        playbookRunsError ? (
          <LivePlaybookRunsSection
            runs={playbookRuns}
            loading={playbookRunsLoading}
            busyRunId={playbookRunsBusyRunId}
            message={playbookRunsMessage}
            error={playbookRunsError}
            onOpenArtifact={onOpenArtifact}
            onRetryRun={onRetryPlaybookRun}
            onResumeRun={onResumePlaybookRun}
            onDismissRun={onDismissPlaybookRun}
            onLoadSession={onLoadSession}
            onMessageWorker={onMessageWorkerSession}
            onStopWorker={onStopWorkerSession}
            onPromoteRunResult={onPromoteRunResult}
            onPromoteStepResult={onPromoteStepResult}
          />
        ) : (
          <p className="artifact-hub-empty">
            No delegated playbook runs are retained for this task yet.
          </p>
        )}
      </section>

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Recent output</span>
          <span>{recentOutputs.length}</span>
        </div>
        <div className="artifact-hub-generic-list">
          {recentOutputs.length > 0 ? (
            recentOutputs.map((entry, index) => (
              <article
                className="artifact-hub-generic-row artifact-hub-task-output"
                key={`${entry.timestamp}-${index}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{humanizeStatus(entry.role)}</span>
                  <span>{formatTaskTimestamp(entry.timestamp)}</span>
                </div>
                <p className="artifact-hub-generic-summary">{entry.text}</p>
              </article>
            ))
          ) : (
            <p className="artifact-hub-empty">
              No retained task output is available yet.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
