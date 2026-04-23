export type MobileContinuityStatus =
  | "idle"
  | "retained"
  | "active"
  | "attention";

export interface BuildMobileOverviewInput {
  hasActiveWorkbench: boolean;
  activeWorkbenchTitle?: string | null;
  activityCount: number;
  evidenceThreadId?: string | null;
  traceLoading: boolean;
  traceError?: string | null;
  eventCount: number;
  artifactCount: number;
  sessionHistoryCount: number;
}

export interface MobileOverview {
  status: MobileContinuityStatus;
  statusLabel: string;
  statusDetail: string;
  activityCount: number;
  evidenceReady: boolean;
  evidenceLabel: string;
  sessionHistoryCount: number;
}

export function buildMobileOverview(
  input: BuildMobileOverviewInput,
): MobileOverview {
  const evidenceReady =
    Boolean(input.evidenceThreadId) &&
    !input.traceLoading &&
    !input.traceError &&
    (input.eventCount > 0 || input.artifactCount > 0);

  if (input.hasActiveWorkbench) {
    return {
      status: input.traceError ? "attention" : "active",
      statusLabel: input.traceError ? "Handoff needs review" : "Handoff active",
      statusDetail: input.traceError
        ? "The active handoff session exists, but retained evidence could not be reloaded yet."
        : `${input.activeWorkbenchTitle || "A native handoff"} is active and keeps its evidence thread attached to the shared runtime.`,
      activityCount: input.activityCount,
      evidenceReady,
      evidenceLabel: evidenceReady
        ? `${input.eventCount} events · ${input.artifactCount} artifacts`
        : input.traceLoading
          ? "Loading retained evidence"
          : input.traceError
            ? "Retained evidence unavailable"
            : "Retained evidence pending",
      sessionHistoryCount: input.sessionHistoryCount,
    };
  }

  if (input.activityCount > 0 || input.evidenceThreadId) {
    return {
      status: "retained",
      statusLabel: "Retained handoff evidence",
      statusDetail:
        "A native reply or prep handoff is not active right now, but the runtime still retains its activity trail and evidence thread for replay and sharing.",
      activityCount: input.activityCount,
      evidenceReady,
      evidenceLabel: evidenceReady
        ? `${input.eventCount} events · ${input.artifactCount} artifacts`
        : input.traceLoading
          ? "Loading retained evidence"
          : input.traceError
            ? "Retained evidence unavailable"
            : "Retained evidence pending",
      sessionHistoryCount: input.sessionHistoryCount,
    };
  }

  return {
    status: "idle",
    statusLabel: "No mobile handoff active",
    statusDetail:
      "Reply-composer and meeting-prep handoffs appear here once an inbox-driven workflow activates a native assistant surface.",
    activityCount: 0,
    evidenceReady: false,
    evidenceLabel: "No retained evidence thread",
    sessionHistoryCount: input.sessionHistoryCount,
  };
}
