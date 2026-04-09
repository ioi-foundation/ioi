import type { AgentTask, ArtifactHubViewKey, PlanSummary } from "../../../types";
import type { LiveValidationSummary } from "../../../hooks/useLiveValidationSummary";

type RetainedTraceSummary = {
  title: string;
  loading: boolean;
  error: string | null;
  eventCount: number;
  artifactCount: number;
  latestEventTitle: string | null;
  latestArtifactTitle: string | null;
};

type SpotlightOperatorStripProps = {
  task: AgentTask | null;
  canOpenRewind: boolean;
  planSummary: PlanSummary | null;
  artifactCount: number;
  eventCount: number;
  validationSummary?: LiveValidationSummary | null;
  retainedTraceSummary?: RetainedTraceSummary | null;
  onOpenView: (view: ArtifactHubViewKey) => void;
  onOpenRetainedEvidence?: () => void;
  onOpenGate?: () => void;
};

function familyLabel(family: PlanSummary["routeFamily"] | null): string | null {
  switch (family) {
    case "research":
      return "Research";
    case "coding":
      return "Coding";
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

function phaseLabel(task: AgentTask | null): string {
  if (!task) return "Ready";
  switch (task.phase) {
    case "Gate":
      return "Awaiting approval";
    case "Running":
      return "Running";
    case "Complete":
      return "Complete";
    case "Failed":
      return "Needs review";
    default:
      return "Ready";
  }
}

function stripTone(task: AgentTask | null, planSummary: PlanSummary | null): string {
  if (task?.phase === "Failed" || planSummary?.approvalState === "denied") {
    return "error";
  }
  if (task?.phase === "Gate" || planSummary?.approvalState === "pending") {
    return "gate";
  }
  if (task?.phase === "Complete") {
    return "complete";
  }
  if (task?.phase === "Running") {
    return "active";
  }
  return "idle";
}

export function SpotlightOperatorStrip({
  task,
  canOpenRewind,
  planSummary,
  artifactCount,
  eventCount,
  validationSummary,
  retainedTraceSummary,
  onOpenView,
  onOpenRetainedEvidence,
  onOpenGate,
}: SpotlightOperatorStripProps) {
  const workerCount = Math.max(
    planSummary?.workerCount ?? 0,
    task?.swarm_tree.length ?? 0,
  );
  const shouldShowWorkers =
    workerCount > 0 || (planSummary?.branchCount ?? 0) > 0;
  const routeLabel = familyLabel(planSummary?.routeFamily ?? null);
  const approvalPending =
    task?.phase === "Gate" || planSummary?.approvalState === "pending";
  const permissionPending = Boolean(
    approvalPending ||
      task?.pending_request_hash ||
      task?.credential_request ||
      task?.clarification_request ||
      task?.gate_info,
  );
  const headline =
    task?.current_step ||
    planSummary?.progressSummary ||
    planSummary?.pauseSummary ||
    "Session ready for the next operator move.";

  const meta = [
    routeLabel,
    topologyLabel(planSummary?.topology ?? null),
    plannerAuthorityLabel(planSummary?.plannerAuthority ?? null),
    planSummary?.currentStage ? `Stage: ${planSummary.currentStage}` : null,
    planSummary?.activeWorkerLabel
      ? `Active: ${planSummary.activeWorkerLabel}`
      : null,
    shouldShowWorkers ? `${workerCount} workers` : null,
    planSummary?.branchCount ? `${planSummary.branchCount} branches` : null,
    artifactCount > 0 ? `${artifactCount} artifacts` : null,
    eventCount > 0 ? `${eventCount} events` : null,
    planSummary?.approvalState && planSummary.approvalState !== "clear"
      ? `Approval: ${planSummary.approvalState}`
      : null,
    planSummary?.verifierRole
      ? `Verifier: ${planSummary.verifierRole.replace(/_/g, " ")}`
      : null,
  ].filter((value): value is string => Boolean(value));

  return (
    <section
      className={`spot-operator-strip spot-operator-strip--${stripTone(
        task,
        planSummary,
      )}`}
      aria-label="Operator session summary"
    >
      <div className="spot-operator-strip__topline">
        <span className="spot-operator-strip__status">{phaseLabel(task)}</span>
        <div className="spot-operator-strip__actions">
          {onOpenGate ? (
            <button
              type="button"
              className="spot-operator-strip__action"
              onClick={onOpenGate}
            >
              {approvalPending ? "Gate" : "Queue"}
            </button>
          ) : null}
          <button
            type="button"
            className="spot-operator-strip__action"
            onClick={() => onOpenView("active_context")}
          >
            Plan
          </button>
          {eventCount > 0 || artifactCount > 0 ? (
            <button
              type="button"
              className="spot-operator-strip__action"
              onClick={() => onOpenView("replay")}
            >
              Replay
            </button>
          ) : null}
          {eventCount > 0 || artifactCount > 0 ? (
            <button
              type="button"
              className="spot-operator-strip__action"
              onClick={() => onOpenView("export")}
            >
              Export
            </button>
          ) : null}
          {shouldShowWorkers ? (
            <button
              type="button"
              className="spot-operator-strip__action"
              onClick={() => onOpenView("thoughts")}
            >
              Workers
            </button>
          ) : null}
          {permissionPending ? (
            <button
              type="button"
              className="spot-operator-strip__action"
              onClick={() => onOpenView("permissions")}
            >
              Permissions
            </button>
          ) : null}
          {canOpenRewind ? (
            <button
              type="button"
              className="spot-operator-strip__action"
              onClick={() => onOpenView("rewind")}
            >
              Rewind
            </button>
          ) : null}
          {artifactCount > 0 || !!task ? (
            <button
              type="button"
              className="spot-operator-strip__action"
              onClick={() => onOpenView("files")}
            >
              Files
            </button>
          ) : null}
        </div>
      </div>

      <strong className="spot-operator-strip__headline">{headline}</strong>

      {planSummary?.selectedRoute ? (
        <p className="spot-operator-strip__route">{planSummary.selectedRoute}</p>
      ) : null}

      {meta.length > 0 ? (
        <div className="spot-operator-strip__meta">
          {meta.map((item) => (
            <span key={item} className="spot-operator-strip__meta-chip">
              {item}
            </span>
          ))}
        </div>
      ) : null}

      {validationSummary ? (
        <div className="spot-operator-strip__validation">
          <div className="spot-operator-strip__validation-head">
            <div>
              <strong>{validationSummary.title}</strong>
              <p>{validationSummary.subtitle}</p>
            </div>
            <div className="spot-operator-strip__validation-head-meta">
              {validationSummary.lastUpdatedLabel ? (
                <span className="spot-operator-strip__validation-updated">
                  {validationSummary.lastUpdatedLabel}
                </span>
              ) : null}
              {onOpenRetainedEvidence ? (
                <button
                  type="button"
                  className="spot-operator-strip__trace-action"
                  onClick={onOpenRetainedEvidence}
                >
                  Open Evidence
                </button>
              ) : null}
            </div>
          </div>

          <div className="spot-operator-strip__validation-grid">
            {validationSummary.items.map((item) => (
              <div
                key={item.id}
                className={`spot-operator-strip__validation-card spot-operator-strip__validation-card--${item.status}`}
              >
                <div className="spot-operator-strip__validation-card-head">
                  <strong>{item.label}</strong>
                  <span className="spot-operator-strip__validation-status">
                    {item.status}
                  </span>
                </div>
                <p>{item.detail}</p>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {retainedTraceSummary ? (
        <div className="spot-operator-strip__trace">
          <div className="spot-operator-strip__trace-head">
            <div>
              <strong>{retainedTraceSummary.title}</strong>
              <p>
                Retained workbench evidence is available from the persisted
                kernel thread.
              </p>
            </div>
            {onOpenRetainedEvidence && !validationSummary ? (
              <button
                type="button"
                className="spot-operator-strip__trace-action"
                onClick={onOpenRetainedEvidence}
              >
                Open Evidence
              </button>
            ) : null}
          </div>

          {retainedTraceSummary.loading ? (
            <p className="spot-operator-strip__trace-note">
              Loading retained trace summary...
            </p>
          ) : retainedTraceSummary.error ? (
            <p className="spot-operator-strip__trace-note spot-operator-strip__trace-note--error">
              Retained trace unavailable: {retainedTraceSummary.error}
            </p>
          ) : (
            <div className="spot-operator-strip__trace-grid">
              <div className="spot-operator-strip__trace-card">
                <strong>{retainedTraceSummary.eventCount}</strong>
                <span>Persisted events</span>
              </div>
              <div className="spot-operator-strip__trace-card">
                <strong>{retainedTraceSummary.artifactCount}</strong>
                <span>Report artifacts</span>
              </div>
              <div className="spot-operator-strip__trace-card">
                <strong>{retainedTraceSummary.latestEventTitle ?? "Awaiting event"}</strong>
                <span>Latest event</span>
              </div>
              <div className="spot-operator-strip__trace-card">
                <strong>{retainedTraceSummary.latestArtifactTitle ?? "No report yet"}</strong>
                <span>Latest artifact</span>
              </div>
            </div>
          )}
        </div>
      ) : null}
    </section>
  );
}
