import { useMemo, useState } from "react";
import type { LocalEngineParentPlaybookReceiptRecord } from "../../../types";
import type { SpotlightPlaybookRunRecord } from "../hooks/useSpotlightPlaybookRuns";
import { buildRunStepDependencyStates } from "./artifactHubTaskGraphModel";

type LivePlaybookRunsSectionProps = {
  runs: SpotlightPlaybookRunRecord[];
  loading: boolean;
  busyRunId: string | null;
  message: string | null;
  error: string | null;
  onOpenArtifact?: (artifactId: string) => void;
  onRetryRun?: (runId: string) => void;
  onResumeRun?: (runId: string, stepId?: string | null) => void;
  onDismissRun?: (runId: string) => void;
  onLoadSession?: (sessionId: string) => void;
  onMessageWorker?: (runId: string, sessionId: string, message: string) => void;
  onStopWorker?: (runId: string, sessionId: string) => void;
  onPromoteRunResult?: (runId: string) => void;
  onPromoteStepResult?: (runId: string, stepId: string) => void;
};

function humanizeStatus(value: string | null | undefined): string {
  const text = (value || "").trim().replace(/[_-]+/g, " ");
  if (!text) return "Unknown";
  return text.replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatTimestampMs(value: number | null | undefined): string | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }

  return new Date(value).toLocaleString();
}

function formatDurationMs(value: number): string {
  if (!Number.isFinite(value) || value <= 0) {
    return "0m";
  }

  const totalMinutes = Math.round(value / 60000);
  if (totalMinutes < 60) {
    return `${Math.max(1, totalMinutes)}m`;
  }

  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours >= 24) {
    const days = Math.floor(hours / 24);
    const remainderHours = hours % 24;
    return remainderHours > 0 ? `${days}d ${remainderHours}h` : `${days}d`;
  }

  return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
}

function formatRunDuration(run: SpotlightPlaybookRunRecord): string {
  const endAtMs = run.completedAtMs ?? run.updatedAtMs;
  return formatDurationMs(Math.max(0, endAtMs - run.startedAtMs));
}

function summarizeIdentifier(value: string | null | undefined): string | null {
  const normalized = (value || "").trim();
  if (!normalized) {
    return null;
  }

  if (normalized.length <= 18) {
    return normalized;
  }

  return `${normalized.slice(0, 8)}…${normalized.slice(-6)}`;
}

function stepArtifactCount(run: SpotlightPlaybookRunRecord): number {
  return run.steps.reduce(
    (total, step) =>
      total +
      step.receipts.reduce(
        (stepTotal, receipt) => stepTotal + receipt.artifactIds.length,
        0,
      ),
    0,
  );
}

function latestRunReceipt(
  run: SpotlightPlaybookRunRecord,
): LocalEngineParentPlaybookReceiptRecord | null {
  return run.steps
    .flatMap((step) => step.receipts)
    .sort((left, right) => right.timestampMs - left.timestampMs)[0] ?? null;
}

function latestStepReceipt(
  run: SpotlightPlaybookRunRecord["steps"][number],
): LocalEngineParentPlaybookReceiptRecord | null {
  return [...run.receipts].sort(
    (left, right) => right.timestampMs - left.timestampMs,
  )[0] ?? null;
}

function summarizeStepStates(run: SpotlightPlaybookRunRecord): string {
  const counts = run.steps.reduce<Record<string, number>>((acc, step) => {
    acc[step.status] = (acc[step.status] ?? 0) + 1;
    return acc;
  }, {});

  return Object.entries(counts)
    .sort((left, right) => right[1] - left[1])
    .map(([status, count]) => `${count} ${humanizeStatus(status).toLowerCase()}`)
    .join(" · ");
}

function summarizeWorkerGraph(run: SpotlightPlaybookRunRecord): string {
  const owners = run.steps.reduce<Record<string, number>>((acc, step) => {
    const owner =
      step.templateId?.trim() ||
      step.workflowId?.trim() ||
      (step.childSessionId ? `Session ${summarizeIdentifier(step.childSessionId)}` : "");
    if (!owner) {
      return acc;
    }
    acc[owner] = (acc[owner] ?? 0) + 1;
    return acc;
  }, {});

  const summary = Object.entries(owners)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3)
    .map(([owner, count]) => `${owner} x${count}`)
    .join(" · ");

  return summary || "Waiting for worker assignment";
}

function summarizePromotionReadiness(run: SpotlightPlaybookRunRecord): string {
  const receipt = latestRunReceipt(run);
  if (!receipt) {
    return "Awaiting the first worker receipt";
  }
  if (!receipt.success) {
    return "Latest receipt needs review before merge";
  }
  if (receipt.artifactIds.length > 0) {
    return `Ready to merge with ${receipt.artifactIds.length} artifact${
      receipt.artifactIds.length === 1 ? "" : "s"
    }`;
  }
  return "Ready to merge into the parent plan";
}

function buildActivePathStepIds(run: SpotlightPlaybookRunRecord): Set<string> {
  const stepById = new Map(run.steps.map((step) => [step.stepId, step]));
  const activePath = new Set<string>();
  const pending = run.currentStepId ? [run.currentStepId] : [];

  while (pending.length > 0) {
    const stepId = pending.pop();
    if (!stepId || activePath.has(stepId)) {
      continue;
    }

    activePath.add(stepId);
    const step = stepById.get(stepId);
    if (!step) {
      continue;
    }

    pending.push(...step.dependsOnStepIds);
  }

  return activePath;
}

function buildGraphColumns(run: SpotlightPlaybookRunRecord): Array<{
  depth: number;
  steps: SpotlightPlaybookRunRecord["steps"];
}> {
  const stepById = new Map(run.steps.map((step) => [step.stepId, step]));
  const order = new Map(run.steps.map((step, index) => [step.stepId, index]));
  const depthMemo = new Map<string, number>();

  const depthForStep = (stepId: string): number => {
    const cached = depthMemo.get(stepId);
    if (typeof cached === "number") {
      return cached;
    }

    const step = stepById.get(stepId);
    if (!step || step.dependsOnStepIds.length === 0) {
      depthMemo.set(stepId, 0);
      return 0;
    }

    const depth =
      Math.max(...step.dependsOnStepIds.map((dependencyId) => depthForStep(dependencyId))) +
      1;
    depthMemo.set(stepId, depth);
    return depth;
  };

  const columns = new Map<number, SpotlightPlaybookRunRecord["steps"]>();
  run.steps.forEach((step) => {
    const depth = depthForStep(step.stepId);
    const current = columns.get(depth) ?? [];
    current.push(step);
    columns.set(depth, current);
  });

  return Array.from(columns.entries())
    .sort((left, right) => left[0] - right[0])
    .map(([depth, steps]) => ({
      depth,
      steps: [...steps].sort(
        (left, right) =>
          (order.get(left.stepId) ?? Number.MAX_SAFE_INTEGER) -
          (order.get(right.stepId) ?? Number.MAX_SAFE_INTEGER),
      ),
    }));
}

function ReceiptPreview({
  label,
  receipt,
  onOpenArtifact,
}: {
  label: string;
  receipt: LocalEngineParentPlaybookReceiptRecord;
  onOpenArtifact?: (artifactId: string) => void;
}) {
  const previewArtifacts = receipt.artifactIds.slice(0, 3);

  return (
    <div
      className={`live-playbook-run__receipt ${
        receipt.success ? "is-success" : "is-failure"
      }`}
    >
      <div className="live-playbook-run__receipt-topline">
        <strong>{label}</strong>
        <span>{formatTimestampMs(receipt.timestampMs) || "Unknown"}</span>
      </div>
      <p>{receipt.summary}</p>
      <div className="worker-card-meta">
        <span className="worker-card-chip">
          Phase {humanizeStatus(receipt.phase)}
        </span>
        <span className="worker-card-chip">
          Status {humanizeStatus(receipt.status)}
        </span>
        {receipt.templateId ? (
          <span className="worker-card-chip">Worker {receipt.templateId}</span>
        ) : null}
        {receipt.workflowId ? (
          <span className="worker-card-chip">Workflow {receipt.workflowId}</span>
        ) : null}
        {receipt.receiptRef ? (
          <span className="worker-card-chip">
            Receipt {summarizeIdentifier(receipt.receiptRef)}
          </span>
        ) : null}
      </div>
      {previewArtifacts.length > 0 && onOpenArtifact ? (
        <div className="live-playbook-run__receipt-artifacts">
          {previewArtifacts.map((artifactId) => (
            <button
              key={`${receipt.eventId}:${artifactId}`}
              type="button"
              className="live-playbook-run__action"
              onClick={() => onOpenArtifact(artifactId)}
            >
              Open artifact {summarizeIdentifier(artifactId)}
            </button>
          ))}
          {receipt.artifactIds.length > previewArtifacts.length ? (
            <span className="worker-card-chip">
              +{receipt.artifactIds.length - previewArtifacts.length} more
            </span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function LivePlaybookRunsSection({
  runs,
  loading,
  busyRunId,
  message,
  error,
  onOpenArtifact,
  onRetryRun,
  onResumeRun,
  onDismissRun,
  onLoadSession,
  onMessageWorker,
  onStopWorker,
  onPromoteRunResult,
  onPromoteStepResult,
}: LivePlaybookRunsSectionProps) {
  const [composeTargetKey, setComposeTargetKey] = useState<string | null>(null);
  const [composeDraft, setComposeDraft] = useState("");

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

  if (!loading && !message && !error && runs.length === 0) {
    return null;
  }

  return (
    <section className="thoughts-section">
      <div className="thoughts-agent-header">
        <span className="thoughts-agent-dot" />
        <span className="thoughts-agent-name">Live delegation</span>
        <span className="thoughts-agent-role">
          {runs.length > 0 ? `${runs.length} attached runs` : "Syncing runtime"}
        </span>
      </div>

      {message ? <p className="thoughts-note">{message}</p> : null}
      {error ? <p className="thoughts-note thoughts-note--error">{error}</p> : null}
      {loading && runs.length === 0 ? (
        <p className="thoughts-empty-state">
          Loading parent-playbook runs for this session.
        </p>
      ) : null}

      {runs.map((run) => {
        const currentStep =
          run.steps.find((step) => step.stepId === run.currentStepId) ?? null;
        const canDismissRun = ["blocked", "completed", "failed"].includes(run.status);
        const runBusy = busyRunId === run.runId;
        const activePathStepIds = buildActivePathStepIds(run);
        const graphColumns = buildGraphColumns(run);
        const dependencyStates = buildRunStepDependencyStates(run);
        const rootSteps = run.steps.filter((step) => step.dependsOnStepIds.length === 0);
        const receiptCount = run.steps.reduce(
          (total, step) => total + step.receipts.length,
          0,
        );
        const latestReceipt = latestRunReceipt(run);
        const latestArtifactId = latestReceipt?.artifactIds[0] ?? null;
        const activeWorkerComposeKey = run.activeChildSessionId
          ? `${run.runId}:${run.activeChildSessionId}`
          : null;

        return (
          <article
            key={run.runId}
            className={`worker-card live-playbook-run status-${run.status}`}
          >
            <div className="thoughts-agent-header">
              <span className="thoughts-agent-dot" />
              <span className="thoughts-agent-name">{run.playbookLabel}</span>
              <span className="thoughts-agent-role">
                {humanizeStatus(run.status)}
              </span>
            </div>

            <div className="worker-card-meta">
              <span className="worker-card-chip">
                Phase {humanizeStatus(run.latestPhase)}
              </span>
              {run.currentStepLabel ? (
                <span className="worker-card-chip is-emphasis">
                  Step {run.currentStepLabel}
                </span>
              ) : null}
              <span className="worker-card-chip">{run.steps.length} steps</span>
              {run.activeChildSessionId ? (
                <span className="worker-card-chip">
                  Child {summarizeIdentifier(run.activeChildSessionId)}
                </span>
              ) : null}
            </div>

            <div className="worker-card-grid">
              <div className="worker-card-block is-emphasis">
                <span>Outcome</span>
                <p>{run.summary}</p>
              </div>
              <div className="worker-card-block">
                <span>Current Owner</span>
                <p>
                  {currentStep?.templateId
                    ? `${currentStep.templateId}${
                        currentStep.workflowId
                          ? ` / ${currentStep.workflowId}`
                          : ""
                      }`
                    : "Waiting for a worker handoff"}
                </p>
              </div>
              <div className="worker-card-block">
                <span>Worker Graph</span>
                <p>{summarizeWorkerGraph(run)}</p>
              </div>
              <div className="worker-card-block">
                <span>Progress</span>
                <p>{summarizeStepStates(run)}</p>
              </div>
              <div className="worker-card-block">
                <span>Evidence</span>
                <p>
                  {receiptCount} receipts · {stepArtifactCount(run)} artifacts
                </p>
              </div>
              <div className="worker-card-block">
                <span>Updated</span>
                <p>{formatTimestampMs(run.updatedAtMs) || "Unknown"}</p>
              </div>
              <div className="worker-card-block">
                <span>Duration</span>
                <p>{formatRunDuration(run)}</p>
              </div>
              {latestReceipt ? (
                <div className="worker-card-block">
                  <span>Latest Receipt</span>
                  <p>{latestReceipt.summary}</p>
                </div>
              ) : null}
              {run.mergeContract ? (
                <div className="worker-card-block">
                  <span>Merge Mode</span>
                  <p>{humanizeStatus(run.mergeContract.mergeMode)}</p>
                </div>
              ) : null}
              <div className="worker-card-block">
                <span>Promotion</span>
                <p>{summarizePromotionReadiness(run)}</p>
              </div>
            </div>

            {run.mergeContract ? (
              <div className="live-playbook-run__contract">
                <div className="live-playbook-run__contract-topline">
                  <strong>Parent merge contract</strong>
                  <span>{humanizeStatus(run.mergeContract.mergeMode)}</span>
                </div>
                <div className="live-playbook-run__contract-grid">
                  <div className="worker-card-block is-emphasis">
                    <span>Success Criteria</span>
                    <p>{run.mergeContract.successCriteria}</p>
                  </div>
                  <div className="worker-card-block">
                    <span>Expected Output</span>
                    <p>{run.mergeContract.expectedOutput}</p>
                  </div>
                  {run.mergeContract.verificationHint ? (
                    <div className="worker-card-block">
                      <span>Verification Hint</span>
                      <p>{run.mergeContract.verificationHint}</p>
                    </div>
                  ) : null}
                  {run.playbookSummary ? (
                    <div className="worker-card-block">
                      <span>Playbook Intent</span>
                      <p>{run.playbookSummary}</p>
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}

            {run.errorClass ? (
              <div className="thoughts-note thoughts-note--error">
                Run issue: {run.errorClass}
              </div>
            ) : null}

            <div className="live-playbook-run__actions">
              {run.status === "blocked" && currentStep && onRetryRun ? (
                <button
                  type="button"
                  className="live-playbook-run__action is-primary"
                  disabled={runBusy}
                  onClick={() => onRetryRun(run.runId)}
                >
                  Retry step
                </button>
              ) : null}
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
              {run.activeChildSessionId && onLoadSession ? (
                <button
                  type="button"
                  className="live-playbook-run__action"
                  disabled={runBusy}
                  onClick={() => onLoadSession(run.activeChildSessionId!)}
                >
                  Open child session
                </button>
              ) : null}
              {run.activeChildSessionId && onMessageWorker ? (
                <button
                  type="button"
                  className="live-playbook-run__action"
                  disabled={runBusy}
                  onClick={() => {
                    if (!activeWorkerComposeKey) return;
                    setComposeTargetKey((current) =>
                      current === activeWorkerComposeKey
                        ? null
                        : activeWorkerComposeKey,
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
              {latestArtifactId && onOpenArtifact ? (
                <button
                  type="button"
                  className="live-playbook-run__action"
                  disabled={runBusy}
                  onClick={() => onOpenArtifact(latestArtifactId)}
                >
                  Review latest result
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
              {canDismissRun && onDismissRun ? (
                <button
                  type="button"
                  className="live-playbook-run__action"
                  disabled={runBusy}
                  onClick={() => onDismissRun(run.runId)}
                >
                  Dismiss run
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
                      if (!run.activeChildSessionId || !onMessageWorker) return;
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

            {latestReceipt ? (
              <ReceiptPreview
                label="Run result"
                receipt={latestReceipt}
                onOpenArtifact={onOpenArtifact}
              />
            ) : null}

            <div className="live-playbook-run__graph">
              <div className="live-playbook-run__graph-topline">
                <strong>Parent playbook graph</strong>
                <span>
                  {graphColumns.length} stages · {rootSteps.length} roots
                </span>
              </div>
              <div className="worker-card-meta">
                <span className="worker-card-chip is-emphasis">
                  Active path {activePathStepIds.size || 0} steps
                </span>
                <span className="worker-card-chip">
                  Completed{" "}
                  {
                    run.steps.filter((step) => step.status === "completed").length
                  }
                </span>
                <span className="worker-card-chip">
                  Blocked{" "}
                  {
                    run.steps.filter((step) =>
                      ["blocked", "failed"].includes(step.status),
                    ).length
                  }
                </span>
              </div>
              <div className="live-playbook-run__graph-board">
                {graphColumns.map((column) => (
                  <div
                    key={`${run.runId}:depth:${column.depth}`}
                    className="live-playbook-run__graph-column"
                  >
                    <div className="live-playbook-run__graph-column-head">
                      <strong>Stage {column.depth + 1}</strong>
                      <span>{column.steps.length} steps</span>
                    </div>
                    <div className="live-playbook-run__graph-column-list">
                      {column.steps.map((step) => {
                        const stepLatestReceipt = latestStepReceipt(step);
                        const stepIsCurrent = step.stepId === run.currentStepId;
                        const stepIsActivePath = activePathStepIds.has(step.stepId);
                        const dependencyState = dependencyStates.get(step.stepId) ?? null;

                        return (
                          <div
                            key={`${run.runId}:graph:${step.stepId}`}
                            className={`live-playbook-run__graph-node status-${step.status} ${
                              stepIsCurrent ? "is-current" : ""
                            } ${stepIsActivePath ? "is-active-path" : ""}`}
                          >
                            <div className="live-playbook-run__graph-node-topline">
                              <strong>{step.label}</strong>
                              <span>{humanizeStatus(step.status)}</span>
                            </div>
                            <p>{step.summary}</p>
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
                              {dependencyState ? (
                                <span
                                  className={`worker-card-chip ${
                                    dependencyState.state === "ready" ||
                                    dependencyState.state === "root"
                                      ? "is-emphasis"
                                      : ""
                                  }`}
                                >
                                  {dependencyState.label}
                                </span>
                              ) : null}
                              {stepIsCurrent ? (
                                <span className="worker-card-chip is-emphasis">
                                  Current path
                                </span>
                              ) : stepIsActivePath ? (
                                <span className="worker-card-chip">
                                  Upstream path
                                </span>
                              ) : null}
                            </div>
                            {step.dependsOnLabels.length > 0 ? (
                              <div className="live-playbook-run__graph-dependencies">
                                {step.dependsOnLabels.map((dependencyLabel) => (
                                  <span
                                    key={`${run.runId}:graph:${step.stepId}:${dependencyLabel}`}
                                    className="live-playbook-run__graph-edge"
                                  >
                                    after {dependencyLabel}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <div className="live-playbook-run__graph-dependencies">
                                <span className="live-playbook-run__graph-edge is-root">
                                  root step
                                </span>
                              </div>
                            )}
                            <div className="live-playbook-run__graph-actions">
                              {(dependencyState?.state === "ready" ||
                                dependencyState?.state === "root") &&
                              onResumeRun ? (
                                <button
                                  type="button"
                                  className="live-playbook-run__action is-primary"
                                  disabled={runBusy}
                                  onClick={() =>
                                    onResumeRun(run.runId, step.stepId)
                                  }
                                >
                                  Start step
                                </button>
                              ) : null}
                              {step.status !== "pending" && onResumeRun ? (
                                <button
                                  type="button"
                                  className="live-playbook-run__action"
                                  disabled={runBusy}
                                  onClick={() =>
                                    onResumeRun(run.runId, step.stepId)
                                  }
                                >
                                  Resume here
                                </button>
                              ) : null}
                              {step.childSessionId && onLoadSession ? (
                                <button
                                  type="button"
                                  className="live-playbook-run__action"
                                  disabled={runBusy}
                                  onClick={() => onLoadSession(step.childSessionId!)}
                                >
                                  Open child
                                </button>
                              ) : null}
                              {stepLatestReceipt?.success && onPromoteStepResult ? (
                                <button
                                  type="button"
                                  className="live-playbook-run__action is-primary"
                                  disabled={runBusy}
                                  onClick={() =>
                                    onPromoteStepResult(run.runId, step.stepId)
                                  }
                                >
                                  Promote result
                                </button>
                              ) : null}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="live-playbook-run__step-list">
              {run.steps.map((step) => {
                const artifactCount = step.receipts.reduce(
                  (total, receipt) => total + receipt.artifactIds.length,
                  0,
                );
                const stepLatestReceipt = latestStepReceipt(step);
                const stepComposeKey = step.childSessionId
                  ? `${run.runId}:${step.childSessionId}`
                  : null;
                const dependencyState = dependencyStates.get(step.stepId) ?? null;

                return (
                  <div
                    key={`${run.runId}:${step.stepId}`}
                    className={`live-playbook-run__step status-${step.status}`}
                  >
                    <div className="live-playbook-run__step-topline">
                      <strong>{step.label}</strong>
                      <span>{humanizeStatus(step.status)}</span>
                    </div>
                    <p>{step.summary}</p>
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
                      <span className="worker-card-chip">
                        {step.receipts.length} receipts
                      </span>
                      {artifactCount > 0 ? (
                        <span className="worker-card-chip">
                          {artifactCount} artifacts
                        </span>
                      ) : null}
                      {step.updatedAtMs ? (
                        <span className="worker-card-chip">
                          {formatTimestampMs(step.updatedAtMs)}
                        </span>
                      ) : null}
                      {dependencyState ? (
                        <span
                          className={`worker-card-chip ${
                            dependencyState.state === "ready" ||
                            dependencyState.state === "root"
                              ? "is-emphasis"
                              : ""
                          }`}
                        >
                          {dependencyState.label}
                        </span>
                      ) : null}
                      {step.dependsOnLabels.length === 0 ? (
                        <span className="worker-card-chip is-emphasis">
                          Root step
                        </span>
                      ) : null}
                      {step.dependsOnLabels.map((dependencyLabel) => (
                        <span
                          key={`${run.runId}:${step.stepId}:${dependencyLabel}`}
                          className="worker-card-chip"
                        >
                          After {dependencyLabel}
                        </span>
                      ))}
                    </div>
                    {step.errorClass ? (
                      <div className="thoughts-note thoughts-note--error">
                        Issue: {step.errorClass}
                      </div>
                    ) : null}
                    <div className="live-playbook-run__step-actions">
                      {(dependencyState?.state === "ready" ||
                        dependencyState?.state === "root") &&
                      onResumeRun ? (
                        <button
                          type="button"
                          className="live-playbook-run__action is-primary"
                          disabled={runBusy}
                          onClick={() => onResumeRun(run.runId, step.stepId)}
                        >
                          Start step
                        </button>
                      ) : null}
                      {step.status !== "pending" && onResumeRun ? (
                        <button
                          type="button"
                          className="live-playbook-run__action"
                          disabled={runBusy}
                          onClick={() => onResumeRun(run.runId, step.stepId)}
                        >
                          Resume here
                        </button>
                      ) : null}
                      {step.childSessionId && onLoadSession ? (
                        <button
                          type="button"
                          className="live-playbook-run__action"
                          disabled={runBusy}
                          onClick={() => onLoadSession(step.childSessionId!)}
                        >
                          Open child
                        </button>
                      ) : null}
                      {step.childSessionId && onMessageWorker ? (
                        <button
                          type="button"
                          className="live-playbook-run__action"
                          disabled={runBusy}
                          onClick={() => {
                            if (!stepComposeKey) return;
                            setComposeTargetKey((current) =>
                              current === stepComposeKey ? null : stepComposeKey,
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
                          disabled={runBusy}
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
                          disabled={runBusy}
                          onClick={() =>
                            onPromoteStepResult(run.runId, step.stepId)
                          }
                        >
                          Promote step result
                        </button>
                      ) : null}
                    </div>
                    {composeTarget?.runId === run.runId &&
                    composeTarget?.sessionId === step.childSessionId ? (
                      <div className="live-playbook-run__composer is-inline">
                        <textarea
                          className="live-playbook-run__composer-input"
                          value={composeDraft}
                          onChange={(event) => setComposeDraft(event.target.value)}
                          placeholder="Send a direct operator instruction to this worker session."
                          rows={3}
                        />
                        <div className="live-playbook-run__composer-actions">
                          <button
                            type="button"
                            className="live-playbook-run__action is-primary"
                            disabled={runBusy || !composeDraft.trim()}
                            onClick={() => {
                              if (!step.childSessionId || !onMessageWorker) return;
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
                    {stepLatestReceipt ? (
                      <ReceiptPreview
                        label="Latest step result"
                        receipt={stepLatestReceipt}
                        onOpenArtifact={onOpenArtifact}
                      />
                    ) : null}
                  </div>
                );
              })}
            </div>
          </article>
        );
      })}
    </section>
  );
}
