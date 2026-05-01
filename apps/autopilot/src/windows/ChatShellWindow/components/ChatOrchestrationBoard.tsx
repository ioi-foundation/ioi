import { useMemo, useState } from "react";
import type {
  AgentTask,
  ArtifactHubViewKey,
  PlanSummary,
} from "../../../types";
import { formatRuntimeStatusLabel } from "../../../services/runtimeInspection";
import type {
  ChatPlaybookRunRecord,
  ChatPlaybookStepRecord,
} from "../hooks/useChatPlaybookRuns";

type ChatOrchestrationBoardProps = {
  task: AgentTask | null;
  planSummary: PlanSummary | null;
  runs: ChatPlaybookRunRecord[];
  loading: boolean;
  busyRunId: string | null;
  message: string | null;
  error: string | null;
  onOpenView: (view: ArtifactHubViewKey) => void;
  onOpenArtifact?: (artifactId: string) => void;
  onLoadSession?: (sessionId: string) => void;
  onResumeRun?: (runId: string, stepId?: string | null) => void;
  onMessageWorker?: (runId: string, sessionId: string, message: string) => void;
  onStopWorker?: (runId: string, sessionId: string) => void;
  onStopSession?: () => void;
  onPromoteRunResult?: (runId: string) => void;
  onPromoteStepResult?: (runId: string, stepId: string) => void;
};

function familyLabel(family: PlanSummary["routeFamily"] | null): string | null {
  switch (family) {
    case "research":
      return "Research";
    case "coding":
      return "Coding";
    case "integrations":
      return "Integrations";
    case "communication":
      return "Communication";
    case "user_input":
      return "Decision";
    case "tool_widget":
      return "Tool widget";
    case "computer_use":
      return "Computer use";
    case "artifacts":
      return "Artifacts";
    case "general":
      return "General";
    default:
      return null;
  }
}

function topologyLabel(topology: PlanSummary["topology"] | null): string | null {
  switch (topology) {
    case "planner_specialist_verifier":
      return "Planner -> specialist -> verifier";
    case "planner_specialist":
      return "Planner -> specialist";
    case "single_agent":
      return "Single agent";
    default:
      return null;
  }
}

function plannerAuthorityLabel(
  authority: PlanSummary["plannerAuthority"] | null,
): string | null {
  switch (authority) {
    case "kernel":
      return "Kernel planner";
    case "primary_agent":
      return "Primary agent planner";
    default:
      return null;
  }
}

function humanizeStatus(value: string | null | undefined): string {
  return formatRuntimeStatusLabel(value);
}

function formatTimestampMs(value: number | null | undefined): string | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  return new Date(value).toLocaleString();
}

function summarizeIdentifier(value: string | null | undefined): string | null {
  const normalized = (value || "").trim();
  if (!normalized) {
    return null;
  }
  if (normalized.length <= 18) {
    return normalized;
  }
  return `${normalized.slice(0, 8)}...${normalized.slice(-6)}`;
}

function latestStepReceipt(
  step: ChatPlaybookStepRecord,
): ChatPlaybookStepRecord["receipts"][number] | null {
  return [...step.receipts].sort(
    (left, right) => right.timestampMs - left.timestampMs,
  )[0] ?? null;
}

function latestRunReceipt(
  run: ChatPlaybookRunRecord,
): ChatPlaybookRunRecord["steps"][number]["receipts"][number] | null {
  return run.steps
    .flatMap((step) => step.receipts)
    .sort((left, right) => right.timestampMs - left.timestampMs)[0] ?? null;
}

function reviewTargetForStep(step: ChatPlaybookStepRecord): {
  artifactId: string | null;
  sessionId: string | null;
} {
  const receipt = latestStepReceipt(step);
  return {
    artifactId: receipt?.artifactIds[0] ?? null,
    sessionId: step.childSessionId ?? receipt?.childSessionId ?? null,
  };
}

function reviewTargetForRun(run: ChatPlaybookRunRecord): {
  artifactId: string | null;
  sessionId: string | null;
} {
  const receipt = latestRunReceipt(run);
  return {
    artifactId: receipt?.artifactIds[0] ?? null,
    sessionId: run.activeChildSessionId ?? receipt?.childSessionId ?? null,
  };
}

function plannerNarrative(
  planSummary: PlanSummary | null,
  runs: ChatPlaybookRunRecord[],
): string {
  const planner = plannerAuthorityLabel(planSummary?.plannerAuthority ?? null);
  const topology = topologyLabel(planSummary?.topology ?? null);
  const route = planSummary?.selectedRoute || familyLabel(planSummary?.routeFamily ?? null);

  if (planner && topology && route) {
    return `${planner} is coordinating ${route.toLowerCase()} with a ${topology.toLowerCase()} contract.`;
  }
  if (planner && route) {
    return `${planner} is coordinating ${route.toLowerCase()} for this session.`;
  }
  if (runs.length > 0) {
    return `Delegated playbook work is attached to this session and can be steered here.`;
  }
  return `The runtime planner summary will hydrate here when delegated work or route evidence is available.`;
}

function taskStats(runs: ChatPlaybookRunRecord[]) {
  const steps = runs.flatMap((run) => run.steps);
  return {
    total: steps.length,
    active: steps.filter((step) =>
      ["running", "active", "in_progress"].includes(step.status),
    ).length,
    blocked: steps.filter((step) =>
      ["blocked", "failed"].includes(step.status),
    ).length,
    completed: steps.filter((step) => step.status === "completed").length,
  };
}

export function ChatOrchestrationBoard({
  task,
  planSummary,
  runs,
  loading,
  busyRunId,
  message,
  error,
  onOpenView,
  onOpenArtifact,
  onLoadSession,
  onResumeRun,
  onMessageWorker,
  onStopWorker,
  onStopSession,
  onPromoteRunResult,
  onPromoteStepResult,
}: ChatOrchestrationBoardProps) {
  const [composeTargetKey, setComposeTargetKey] = useState<string | null>(null);
  const [composeDraft, setComposeDraft] = useState("");
  const sessionChecklist = task?.session_checklist ?? [];
  const sessionBackgroundTasks = task?.background_tasks ?? [];

  const stats = useMemo(() => taskStats(runs), [runs]);
  const sessionChecklistStats = useMemo(() => {
    let active = 0;
    let blocked = 0;
    let completed = 0;

    sessionChecklist.forEach((item) => {
      switch (item.status) {
        case "completed":
          completed += 1;
          break;
        case "blocked":
          blocked += 1;
          break;
        case "pending":
        case "in_progress":
          active += 1;
          break;
        default:
          break;
      }
    });

    return {
      total: sessionChecklist.length,
      active,
      blocked,
      completed,
    };
  }, [sessionChecklist]);
  const workerCount = Math.max(
    planSummary?.workerCount ?? 0,
    task?.work_graph_tree.length ?? 0,
  );
  const hasDelegatedSignals =
    runs.length > 0 ||
    sessionChecklist.length > 0 ||
    sessionBackgroundTasks.length > 0 ||
    workerCount > 0 ||
    Boolean(planSummary?.branchCount);
  const shouldRender =
    loading ||
    hasDelegatedSignals ||
    Boolean(message) ||
    Boolean(error);

  const composeTarget = useMemo(() => {
    if (!composeTargetKey) {
      return null;
    }

    for (const run of runs) {
      if (run.activeChildSessionId) {
        const runKey = `${run.runId}:${run.activeChildSessionId}`;
        if (runKey === composeTargetKey) {
          return { runId: run.runId, sessionId: run.activeChildSessionId };
        }
      }

      for (const step of run.steps) {
        if (!step.childSessionId) {
          continue;
        }
        const stepKey = `${run.runId}:${step.childSessionId}`;
        if (stepKey === composeTargetKey) {
          return { runId: run.runId, sessionId: step.childSessionId };
        }
      }
    }

    return null;
  }, [composeTargetKey, runs]);

  if (!shouldRender) {
    return null;
  }

  return (
    <section className="spot-orchestration-board" aria-label="Session orchestration">
      <div className="spot-orchestration-board__topline">
        <div>
          <span className="spot-orchestration-board__kicker">
            Runtime planner
          </span>
          <strong className="spot-orchestration-board__headline">
            {planSummary?.selectedRoute || "Delegated execution"}
          </strong>
          <p className="spot-orchestration-board__summary">
            {plannerNarrative(planSummary, runs)}
          </p>
        </div>
        <div className="spot-orchestration-board__actions">
          <button
            type="button"
            className="live-playbook-run__action"
            onClick={() => onOpenView("active_context")}
          >
            Plan details
          </button>
          <button
            type="button"
            className="live-playbook-run__action"
            onClick={() => onOpenView("thoughts")}
          >
            Worker receipts
          </button>
        </div>
      </div>

      <div className="spot-orchestration-board__meta">
        {familyLabel(planSummary?.routeFamily ?? null) ? (
          <span className="worker-card-chip is-emphasis">
            {familyLabel(planSummary?.routeFamily ?? null)}
          </span>
        ) : null}
        {topologyLabel(planSummary?.topology ?? null) ? (
          <span className="worker-card-chip">
            {topologyLabel(planSummary?.topology ?? null)}
          </span>
        ) : null}
        {plannerAuthorityLabel(planSummary?.plannerAuthority ?? null) ? (
          <span className="worker-card-chip">
            {plannerAuthorityLabel(planSummary?.plannerAuthority ?? null)}
          </span>
        ) : null}
        {planSummary?.verifierRole ? (
          <span className="worker-card-chip">
            Verifier {planSummary.verifierRole.replace(/[_-]+/g, " ")}
          </span>
        ) : null}
        {planSummary?.approvalState && planSummary.approvalState !== "clear" ? (
          <span className="worker-card-chip">
            Approval {humanizeStatus(planSummary.approvalState)}
          </span>
        ) : null}
        {workerCount > 0 ? (
          <span className="worker-card-chip">{workerCount} workers</span>
        ) : null}
        {runs.length > 0 ? (
          <span className="worker-card-chip">{runs.length} runs</span>
        ) : null}
        {stats.total > 0 ? (
          <span className="worker-card-chip">{stats.total} tasks</span>
        ) : null}
        {stats.total === 0 && sessionChecklistStats.total > 0 ? (
          <span className="worker-card-chip">
            {sessionChecklistStats.total} checklist items
          </span>
        ) : null}
      </div>

      <div className="spot-orchestration-board__grid">
        <div className="worker-card-block is-emphasis">
          <span>Session task list</span>
          <p>
            {stats.total > 0
              ? `${stats.active} active, ${stats.blocked} blocked, ${stats.completed} completed.`
              : sessionChecklistStats.total > 0
                ? `${sessionChecklistStats.active} active, ${sessionChecklistStats.blocked} blocked, ${sessionChecklistStats.completed} completed.`
              : "The planner has not attached a delegated task list to this session yet."}
          </p>
        </div>
        <div className="worker-card-block">
          <span>Current stage</span>
          <p>
            {task?.current_step ||
              planSummary?.currentStage ||
              "Waiting for planner stage evidence"}
          </p>
        </div>
        <div className="worker-card-block">
          <span>Progress</span>
          <p>
            {planSummary?.progressSummary ||
              (stats.total > 0
                ? `${stats.completed} of ${stats.total} delegated tasks are complete.`
                : sessionChecklistStats.total > 0
                  ? `${sessionChecklistStats.completed} of ${sessionChecklistStats.total} runtime checklist items are complete.`
                  : "No delegated progress has been captured yet.")}
          </p>
        </div>
      </div>

      {message ? (
        <p className="spot-orchestration-board__note">{message}</p>
      ) : null}
      {error ? (
        <p className="spot-orchestration-board__note spot-orchestration-board__note--error">
          {error}
        </p>
      ) : null}
      {loading && runs.length === 0 ? (
        <p className="spot-orchestration-board__empty">
          Loading delegated task list from the live parent-playbook runtime.
        </p>
      ) : null}
      {sessionChecklist.length > 0 ? (
        <div className="spot-orchestration-board__section">
          <div className="spot-orchestration-board__section-head">
            <span>Runtime checklist</span>
            <p>
              Kernel-owned session checklist derived from the active task projection.
            </p>
          </div>
          <div className="spot-orchestration-board__task-list">
            {sessionChecklist.map((item) => (
              <div
                key={item.item_id}
                className={`spot-orchestration-board__task status-${item.status} ${
                  item.status === "in_progress" || item.status === "blocked"
                    ? "is-current"
                    : ""
                }`}
              >
                <div className="spot-orchestration-board__task-head">
                  <div>
                    <strong>{item.label}</strong>
                    <p>{item.detail || "Waiting for runtime detail."}</p>
                  </div>
                  <span className="spot-orchestration-board__status">
                    {humanizeStatus(item.status)}
                  </span>
                </div>
                <div className="worker-card-meta">
                  <span className="worker-card-chip">
                    Updated {formatTimestampMs(item.updated_at_ms) || "Unknown"}
                  </span>
                </div>
                {item.item_id === "review" ? (
                  <div className="spot-orchestration-board__task-actions">
                    <button
                      type="button"
                      className="live-playbook-run__action"
                      onClick={() => onOpenView("thoughts")}
                    >
                      Review output
                    </button>
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}
      {sessionBackgroundTasks.length > 0 ? (
        <div className="spot-orchestration-board__section">
          <div className="spot-orchestration-board__section-head">
            <span>Background tasks</span>
            <p>
              Live session task controls with retained output from the current runtime.
            </p>
          </div>
          <div className="spot-orchestration-board__task-list">
            {sessionBackgroundTasks.map((backgroundTask) => (
              <div
                key={backgroundTask.task_id}
                className={`spot-orchestration-board__task status-${backgroundTask.status}`}
              >
                <div className="spot-orchestration-board__task-head">
                  <div>
                    <strong>{backgroundTask.label}</strong>
                    <p>
                      {backgroundTask.detail ||
                        "The runtime has not attached a task detail yet."}
                    </p>
                  </div>
                  <span className="spot-orchestration-board__status">
                    {humanizeStatus(backgroundTask.status)}
                  </span>
                </div>
                <div className="worker-card-meta">
                  {backgroundTask.session_id ? (
                    <span className="worker-card-chip">
                      Session {summarizeIdentifier(backgroundTask.session_id)}
                    </span>
                  ) : null}
                  <span className="worker-card-chip">
                    Updated {formatTimestampMs(backgroundTask.updated_at_ms) || "Unknown"}
                  </span>
                </div>
                {backgroundTask.latest_output ? (
                  <p className="spot-orchestration-board__task-output">
                    {backgroundTask.latest_output}
                  </p>
                ) : null}
                <div className="spot-orchestration-board__task-actions">
                  <button
                    type="button"
                    className="live-playbook-run__action"
                    onClick={() => onOpenView("tasks")}
                  >
                    Open task
                  </button>
                  {backgroundTask.can_stop && onStopSession ? (
                    <button
                      type="button"
                      className="live-playbook-run__action"
                      onClick={() => onStopSession()}
                    >
                      Stop run
                    </button>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}
      {!loading &&
      runs.length === 0 &&
      sessionChecklist.length === 0 &&
      sessionBackgroundTasks.length === 0 ? (
        <p className="spot-orchestration-board__empty">
          Delegated tasks will appear here when the runtime planner opens a
          parent playbook run for this session.
        </p>
      ) : null}

      {runs.length > 0 ? (
        <div className="spot-orchestration-board__runs">
          {runs.map((run) => {
            const runBusy = busyRunId === run.runId;
            const currentStep =
              run.steps.find((step) => step.stepId === run.currentStepId) ?? null;
            const reviewTarget = reviewTargetForRun(run);
            const latestReceipt = latestRunReceipt(run);
            const activeComposeKey = run.activeChildSessionId
              ? `${run.runId}:${run.activeChildSessionId}`
              : null;

            return (
              <article
                key={run.runId}
                className={`spot-orchestration-board__run status-${run.status}`}
              >
                <div className="spot-orchestration-board__run-head">
                  <div>
                    <strong>{run.playbookLabel}</strong>
                    <p>{run.summary}</p>
                  </div>
                  <span className="spot-orchestration-board__status">
                    {humanizeStatus(run.status)}
                  </span>
                </div>

                <div className="worker-card-meta">
                  <span className="worker-card-chip">
                    Phase {humanizeStatus(run.latestPhase)}
                  </span>
                  {currentStep?.label ? (
                    <span className="worker-card-chip is-emphasis">
                      Current {currentStep.label}
                    </span>
                  ) : null}
                  <span className="worker-card-chip">
                    Updated {formatTimestampMs(run.updatedAtMs) || "Unknown"}
                  </span>
                  {run.mergeContract?.mergeMode ? (
                    <span className="worker-card-chip">
                      Merge {humanizeStatus(run.mergeContract.mergeMode)}
                    </span>
                  ) : null}
                  {latestReceipt?.receiptRef ? (
                    <span className="worker-card-chip">
                      Receipt {summarizeIdentifier(latestReceipt.receiptRef)}
                    </span>
                  ) : null}
                </div>

                <div className="spot-orchestration-board__run-actions">
                  {currentStep && onResumeRun ? (
                    <button
                      type="button"
                      className="live-playbook-run__action"
                      disabled={runBusy}
                      onClick={() => onResumeRun(run.runId, currentStep.stepId)}
                    >
                      Resume current step
                    </button>
                  ) : null}
                  {(reviewTarget.artifactId || reviewTarget.sessionId) ? (
                    <button
                      type="button"
                      className="live-playbook-run__action"
                      disabled={runBusy}
                      onClick={() => {
                        if (reviewTarget.artifactId && onOpenArtifact) {
                          onOpenArtifact(reviewTarget.artifactId);
                          return;
                        }
                        if (reviewTarget.sessionId && onLoadSession) {
                          onLoadSession(reviewTarget.sessionId);
                          return;
                        }
                        onOpenView("thoughts");
                      }}
                    >
                      Review worker
                    </button>
                  ) : null}
                  {run.activeChildSessionId && onMessageWorker ? (
                    <button
                      type="button"
                      className="live-playbook-run__action"
                      disabled={runBusy}
                      onClick={() => {
                        if (!activeComposeKey) {
                          return;
                        }
                        setComposeTargetKey((current) =>
                          current === activeComposeKey ? null : activeComposeKey,
                        );
                        setComposeDraft("");
                      }}
                    >
                      Message worker
                    </button>
                  ) : null}
                  {run.activeChildSessionId && onStopWorker ? (
                    <button
                      type="button"
                      className="live-playbook-run__action"
                      disabled={runBusy}
                      onClick={() =>
                        onStopWorker(run.runId, run.activeChildSessionId!)
                      }
                    >
                      Stop worker
                    </button>
                  ) : null}
                  {latestReceipt?.success && onPromoteRunResult ? (
                    <button
                      type="button"
                      className="live-playbook-run__action is-primary"
                      disabled={runBusy}
                      onClick={() => onPromoteRunResult(run.runId)}
                    >
                      Promote into parent plan
                    </button>
                  ) : null}
                </div>

                {composeTarget?.runId === run.runId &&
                composeTarget?.sessionId === run.activeChildSessionId ? (
                  <div className="live-playbook-run__composer">
                    <textarea
                      className="live-playbook-run__composer-input"
                      value={composeDraft}
                      onChange={(event) => setComposeDraft(event.target.value)}
                      placeholder="Send a direct operator instruction to the active worker session."
                      rows={3}
                    />
                    <div className="live-playbook-run__composer-actions">
                      <button
                        type="button"
                        className="live-playbook-run__action is-primary"
                        disabled={runBusy || !composeDraft.trim()}
                        onClick={() => {
                          if (!run.activeChildSessionId || !onMessageWorker) {
                            return;
                          }
                          onMessageWorker(
                            run.runId,
                            run.activeChildSessionId,
                            composeDraft,
                          );
                          setComposeDraft("");
                          setComposeTargetKey(null);
                        }}
                      >
                        Send to worker
                      </button>
                      <button
                        type="button"
                        className="live-playbook-run__action"
                        disabled={runBusy}
                        onClick={() => {
                          setComposeDraft("");
                          setComposeTargetKey(null);
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : null}

                <div className="spot-orchestration-board__task-list">
                  {run.steps.map((step) => {
                    const stepBusy = busyRunId === run.runId;
                    const stepLatestReceipt = latestStepReceipt(step);
                    const reviewTargetForCurrentStep = reviewTargetForStep(step);
                    const stepComposeKey = step.childSessionId
                      ? `${run.runId}:${step.childSessionId}`
                      : null;
                    const stepIsCurrent = step.stepId === run.currentStepId;

                    return (
                      <div
                        key={`${run.runId}:${step.stepId}`}
                        className={`spot-orchestration-board__task status-${step.status} ${
                          stepIsCurrent ? "is-current" : ""
                        }`}
                      >
                        <div className="spot-orchestration-board__task-head">
                          <div>
                            <strong>{step.label}</strong>
                            <p>{step.summary}</p>
                          </div>
                          <span className="spot-orchestration-board__status">
                            {humanizeStatus(step.status)}
                          </span>
                        </div>

                        <div className="worker-card-meta">
                          {step.templateId ? (
                            <span className="worker-card-chip">
                              Worker {step.templateId}
                            </span>
                          ) : null}
                          {step.workflowId ? (
                            <span className="worker-card-chip">
                              Workflow {step.workflowId}
                            </span>
                          ) : null}
                          {step.childSessionId ? (
                            <span className="worker-card-chip">
                              Session {summarizeIdentifier(step.childSessionId)}
                            </span>
                          ) : null}
                          {step.dependsOnLabels.length > 0
                            ? step.dependsOnLabels.map((dependencyLabel) => (
                                <span
                                  key={`${run.runId}:${step.stepId}:${dependencyLabel}`}
                                  className="worker-card-chip"
                                >
                                  After {dependencyLabel}
                                </span>
                              ))
                            : (
                              <span className="worker-card-chip is-emphasis">
                                Root task
                              </span>
                            )}
                          {stepLatestReceipt?.receiptRef ? (
                            <span className="worker-card-chip">
                              Receipt {summarizeIdentifier(stepLatestReceipt.receiptRef)}
                            </span>
                          ) : null}
                        </div>

                        <div className="spot-orchestration-board__task-actions">
                          {(reviewTargetForCurrentStep.artifactId ||
                            reviewTargetForCurrentStep.sessionId) ? (
                            <button
                              type="button"
                              className="live-playbook-run__action"
                              disabled={stepBusy}
                              onClick={() => {
                                if (
                                  reviewTargetForCurrentStep.artifactId &&
                                  onOpenArtifact
                                ) {
                                  onOpenArtifact(
                                    reviewTargetForCurrentStep.artifactId,
                                  );
                                  return;
                                }
                                if (
                                  reviewTargetForCurrentStep.sessionId &&
                                  onLoadSession
                                ) {
                                  onLoadSession(
                                    reviewTargetForCurrentStep.sessionId,
                                  );
                                  return;
                                }
                                onOpenView("thoughts");
                              }}
                            >
                              Review result
                            </button>
                          ) : null}
                          {step.status !== "pending" && onResumeRun ? (
                            <button
                              type="button"
                              className="live-playbook-run__action"
                              disabled={stepBusy}
                              onClick={() => onResumeRun(run.runId, step.stepId)}
                            >
                              Resume here
                            </button>
                          ) : null}
                          {step.childSessionId && onMessageWorker ? (
                            <button
                              type="button"
                              className="live-playbook-run__action"
                              disabled={stepBusy}
                              onClick={() => {
                                if (!stepComposeKey) {
                                  return;
                                }
                                setComposeTargetKey((current) =>
                                  current === stepComposeKey
                                    ? null
                                    : stepComposeKey,
                                );
                                setComposeDraft("");
                              }}
                            >
                              Message worker
                            </button>
                          ) : null}
                          {step.childSessionId && onStopWorker ? (
                            <button
                              type="button"
                              className="live-playbook-run__action"
                              disabled={stepBusy}
                              onClick={() =>
                                onStopWorker(run.runId, step.childSessionId!)
                              }
                            >
                              Stop worker
                            </button>
                          ) : null}
                          {stepLatestReceipt?.success && onPromoteStepResult ? (
                            <button
                              type="button"
                              className="live-playbook-run__action is-primary"
                              disabled={stepBusy}
                              onClick={() =>
                                onPromoteStepResult(run.runId, step.stepId)
                              }
                            >
                              Promote result
                            </button>
                          ) : null}
                        </div>

                        {composeTarget?.runId === run.runId &&
                        composeTarget?.sessionId === step.childSessionId ? (
                          <div className="live-playbook-run__composer is-inline">
                            <textarea
                              className="live-playbook-run__composer-input"
                              value={composeDraft}
                              onChange={(event) =>
                                setComposeDraft(event.target.value)
                              }
                              placeholder="Send a direct operator instruction to this worker session."
                              rows={3}
                            />
                            <div className="live-playbook-run__composer-actions">
                              <button
                                type="button"
                                className="live-playbook-run__action is-primary"
                                disabled={stepBusy || !composeDraft.trim()}
                                onClick={() => {
                                  if (!step.childSessionId || !onMessageWorker) {
                                    return;
                                  }
                                  onMessageWorker(
                                    run.runId,
                                    step.childSessionId,
                                    composeDraft,
                                  );
                                  setComposeDraft("");
                                  setComposeTargetKey(null);
                                }}
                              >
                                Send to worker
                              </button>
                              <button
                                type="button"
                                className="live-playbook-run__action"
                                disabled={stepBusy}
                                onClick={() => {
                                  setComposeDraft("");
                                  setComposeTargetKey(null);
                                }}
                              >
                                Cancel
                              </button>
                            </div>
                          </div>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              </article>
            );
          })}
        </div>
      ) : null}
    </section>
  );
}
