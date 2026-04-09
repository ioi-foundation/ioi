import type {
  SpotlightPlaybookRunRecord,
  SpotlightPlaybookStepRecord,
} from "../hooks/useSpotlightPlaybookRuns";

export type TaskGraphStepState =
  | "root"
  | "ready"
  | "waiting_on_dependencies"
  | "active"
  | "blocked"
  | "failed"
  | "completed";

export interface TaskGraphStepDependencyState {
  stepId: string;
  state: TaskGraphStepState;
  label: string;
  unmetDependencyLabels: string[];
}

export interface TaskDelegationOverview {
  statusLabel: string;
  detail: string;
  runCount: number;
  stepCount: number;
  readyStepCount: number;
  blockedStepCount: number;
  activeWorkerCount: number;
  promotableStepCount: number;
  artifactBackedStepCount: number;
  dependencyEdgeCount: number;
}

function normalizedStatus(value: string | null | undefined): string {
  return (value || "").trim().toLowerCase();
}

function isCompletedStatus(value: string | null | undefined): boolean {
  return normalizedStatus(value) === "completed";
}

function isBlockedStatus(value: string | null | undefined): boolean {
  const status = normalizedStatus(value);
  return status === "blocked" || status === "failed";
}

function isActiveStatus(value: string | null | undefined): boolean {
  const status = normalizedStatus(value);
  return status === "running" || status === "active" || status === "in_progress";
}

function latestSuccessfulReceipt(step: SpotlightPlaybookStepRecord) {
  return [...step.receipts]
    .sort((left, right) => right.timestampMs - left.timestampMs)
    .find((receipt) => receipt.success);
}

export function buildRunStepDependencyStates(
  run: SpotlightPlaybookRunRecord,
): Map<string, TaskGraphStepDependencyState> {
  const stepById = new Map(run.steps.map((step) => [step.stepId, step]));

  return new Map(
    run.steps.map((step) => {
      const unmetDependencyLabels = step.dependsOnStepIds
        .map((dependencyId) => stepById.get(dependencyId))
        .filter(
          (dependency): dependency is SpotlightPlaybookStepRecord =>
            Boolean(dependency),
        )
        .filter((dependency) => !isCompletedStatus(dependency.status))
        .map((dependency) => dependency.label);

      let state: TaskGraphStepState = "completed";
      let label = "Completed";
      if (isBlockedStatus(step.status)) {
        state = normalizedStatus(step.status) === "failed" ? "failed" : "blocked";
        label = state === "failed" ? "Failed" : "Blocked";
      } else if (isActiveStatus(step.status)) {
        state = "active";
        label = "In progress";
      } else if (isCompletedStatus(step.status)) {
        state = "completed";
        label = "Completed";
      } else if (step.dependsOnStepIds.length === 0) {
        state = "root";
        label = "Ready now";
      } else if (unmetDependencyLabels.length === 0) {
        state = "ready";
        label = "Ready now";
      } else {
        state = "waiting_on_dependencies";
        label =
          unmetDependencyLabels.length === 1
            ? `Waiting on ${unmetDependencyLabels[0]}`
            : `Waiting on ${unmetDependencyLabels.length} dependencies`;
      }

      return [
        step.stepId,
        {
          stepId: step.stepId,
          state,
          label,
          unmetDependencyLabels,
        },
      ];
    }),
  );
}

export function buildTaskDelegationOverview(
  runs: SpotlightPlaybookRunRecord[],
): TaskDelegationOverview {
  if (runs.length === 0) {
    return {
      statusLabel: "No delegated graph yet",
      detail:
        "The runtime has not attached a retained parent playbook graph to this session yet.",
      runCount: 0,
      stepCount: 0,
      readyStepCount: 0,
      blockedStepCount: 0,
      activeWorkerCount: 0,
      promotableStepCount: 0,
      artifactBackedStepCount: 0,
      dependencyEdgeCount: 0,
    };
  }

  let readyStepCount = 0;
  let blockedStepCount = 0;
  let activeWorkerCount = 0;
  let promotableStepCount = 0;
  let artifactBackedStepCount = 0;
  let dependencyEdgeCount = 0;
  let stepCount = 0;
  let firstBlockedLabel: string | null = null;

  runs.forEach((run) => {
    const dependencyStates = buildRunStepDependencyStates(run);
    run.steps.forEach((step) => {
      stepCount += 1;
      dependencyEdgeCount += step.dependsOnStepIds.length;
      const dependencyState = dependencyStates.get(step.stepId);
      if (
        dependencyState &&
        (dependencyState.state === "root" || dependencyState.state === "ready")
      ) {
        readyStepCount += 1;
      }
      if (isBlockedStatus(step.status)) {
        blockedStepCount += 1;
        if (!firstBlockedLabel) {
          firstBlockedLabel = step.label;
        }
      }
      if (step.childSessionId && isActiveStatus(step.status)) {
        activeWorkerCount += 1;
      }
      const successfulReceipt = latestSuccessfulReceipt(step);
      if (successfulReceipt) {
        promotableStepCount += 1;
      }
      if (step.receipts.some((receipt) => receipt.artifactIds.length > 0)) {
        artifactBackedStepCount += 1;
      }
    });
  });

  if (blockedStepCount > 0) {
    return {
      statusLabel: "Delegated work needs review",
      detail: firstBlockedLabel
        ? `${blockedStepCount} delegated steps are blocked or failed, including ${firstBlockedLabel}.`
        : `${blockedStepCount} delegated steps are blocked or failed.`,
      runCount: runs.length,
      stepCount,
      readyStepCount,
      blockedStepCount,
      activeWorkerCount,
      promotableStepCount,
      artifactBackedStepCount,
      dependencyEdgeCount,
    };
  }

  if (readyStepCount > 0) {
    return {
      statusLabel: "Delegated work is ready to advance",
      detail:
        readyStepCount === 1
          ? "1 pending delegated step now has all dependencies satisfied."
          : `${readyStepCount} pending delegated steps now have all dependencies satisfied.`,
      runCount: runs.length,
      stepCount,
      readyStepCount,
      blockedStepCount,
      activeWorkerCount,
      promotableStepCount,
      artifactBackedStepCount,
      dependencyEdgeCount,
    };
  }

  if (activeWorkerCount > 0) {
    return {
      statusLabel: "Delegated work is in flight",
      detail:
        activeWorkerCount === 1
          ? "1 delegated worker session is currently active."
          : `${activeWorkerCount} delegated worker sessions are currently active.`,
      runCount: runs.length,
      stepCount,
      readyStepCount,
      blockedStepCount,
      activeWorkerCount,
      promotableStepCount,
      artifactBackedStepCount,
      dependencyEdgeCount,
    };
  }

  if (promotableStepCount > 0) {
    return {
      statusLabel: "Worker outputs are ready for parent review",
      detail:
        promotableStepCount === 1
          ? "1 delegated step has a successful retained receipt ready for promotion."
          : `${promotableStepCount} delegated steps have successful retained receipts ready for promotion.`,
      runCount: runs.length,
      stepCount,
      readyStepCount,
      blockedStepCount,
      activeWorkerCount,
      promotableStepCount,
      artifactBackedStepCount,
      dependencyEdgeCount,
    };
  }

  return {
    statusLabel: "Delegated graph retained",
    detail:
      stepCount === 1
        ? "1 delegated step is retained in the runtime graph for this session."
        : `${stepCount} delegated steps are retained in the runtime graph for this session.`,
    runCount: runs.length,
    stepCount,
    readyStepCount,
    blockedStepCount,
    activeWorkerCount,
    promotableStepCount,
    artifactBackedStepCount,
    dependencyEdgeCount,
  };
}
