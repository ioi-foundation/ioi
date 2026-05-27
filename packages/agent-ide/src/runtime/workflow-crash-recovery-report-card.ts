export const WORKFLOW_CRASH_RECOVERY_REPORT_CARD_SCHEMA_VERSION =
  "ioi.workflow.crash-recovery-report-card.v1" as const;

export interface WorkflowCrashRecoveryReportInput {
  proof: Record<string, unknown>;
}

export interface WorkflowCrashRecoveryReportRow {
  rowKind: "process_exit" | "safe_boot" | "replay_integrity" | "continuation";
  status: "passed" | "blocked";
  label: string;
  detail: string;
  refs: string[];
}

export interface WorkflowCrashRecoveryReportCard {
  schemaVersion: typeof WORKFLOW_CRASH_RECOVERY_REPORT_CARD_SCHEMA_VERSION;
  status: "ready" | "blocked";
  threadId: string | null;
  workflowGraphId: string | null;
  stateDir: string | null;
  firstDaemonPid: number | null;
  secondDaemonPid: number | null;
  crashSignal: string | null;
  beforeCrashEventCount: number | null;
  afterRestartEventCount: number | null;
  finalEventCount: number | null;
  replayFromLastSeqCount: number | null;
  continuationSeqStart: number | null;
  continuationSeqEnd: number | null;
  duplicateTerminalEvents: number;
  safeBoot: {
    stateDir: string | null;
    resumeFromSeq: number | null;
    nextTurnStartsAtSeq: number | null;
  };
  rows: WorkflowCrashRecoveryReportRow[];
}

export function buildWorkflowCrashRecoveryReportCard(
  input: WorkflowCrashRecoveryReportInput,
): WorkflowCrashRecoveryReportCard {
  const proof = objectValue(input.proof) ?? {};
  const checks = objectField(proof, "checks");
  const firstDaemon = objectField(proof, "firstDaemon");
  const secondDaemon = objectField(proof, "secondDaemon");
  const crashExit = objectField(firstDaemon, "crashExit");
  const replay = objectField(proof, "replay");
  const firstTurn = objectField(proof, "firstTurn");
  const secondTurn = objectField(proof, "secondTurn");
  const duplicateTerminalEvents =
    Math.max(0, arrayField(firstTurn, "terminalEvents").length - 1) +
    Math.max(0, arrayField(secondTurn, "terminalEvents").length - 1);
  const beforeCrashLastSeq = numberField(replay, "beforeCrashLastSeq");
  const continuationSeqStart = numberField(secondTurn, "seqStart");
  const rows: WorkflowCrashRecoveryReportRow[] = [
    {
      rowKind: "process_exit",
      status: booleanField(checks, "childDaemonWasActuallyKilled") ? "passed" : "blocked",
      label: "Daemon process exit captured",
      detail: `pid ${numberField(firstDaemon, "pid") ?? "unknown"} exited with ${stringField(crashExit, "signal") ?? "unknown"}.`,
      refs: uniqueStrings([stringField(crashExit, "signal")]),
    },
    {
      rowKind: "safe_boot",
      status: numberField(secondDaemon, "pid") ? "passed" : "blocked",
      label: "Safe boot parameters",
      detail: `restart pid ${numberField(secondDaemon, "pid") ?? "unknown"} reused state dir ${stringField(proof, "stateDir") ?? "unknown"}.`,
      refs: uniqueStrings([stringField(proof, "stateDir"), stringField(secondDaemon, "endpoint")]),
    },
    {
      rowKind: "replay_integrity",
      status:
        booleanField(checks, "eventIdsReplayExactlyAfterRestart") &&
        booleanField(checks, "replayFromLastSeqIsEmptyAfterRestart") &&
        duplicateTerminalEvents === 0
          ? "passed"
          : "blocked",
      label: "Replay integrity",
      detail: `${numberField(replay, "afterRestartEventCount") ?? 0} events replayed; ${duplicateTerminalEvents} duplicate terminal events detected.`,
      refs: uniqueStrings([stringField(firstTurn, "turnId"), stringField(firstTurn, "runId")]),
    },
    {
      rowKind: "continuation",
      status:
        booleanField(checks, "postRestartTurnContinuesSequence") &&
        continuationSeqStart === (beforeCrashLastSeq ?? 0) + 1
          ? "passed"
          : "blocked",
      label: "Continuation cursor",
      detail: `next turn started at seq ${continuationSeqStart ?? "unknown"} after replay seq ${beforeCrashLastSeq ?? "unknown"}.`,
      refs: uniqueStrings([stringField(secondTurn, "turnId"), stringField(secondTurn, "runId")]),
    },
  ];
  return {
    schemaVersion: WORKFLOW_CRASH_RECOVERY_REPORT_CARD_SCHEMA_VERSION,
    status: rows.every((row) => row.status === "passed") ? "ready" : "blocked",
    threadId: stringField(proof, "threadId"),
    workflowGraphId: stringField(proof, "workflowGraphId"),
    stateDir: stringField(proof, "stateDir"),
    firstDaemonPid: numberField(firstDaemon, "pid"),
    secondDaemonPid: numberField(secondDaemon, "pid"),
    crashSignal: stringField(crashExit, "signal"),
    beforeCrashEventCount: numberField(replay, "beforeCrashEventCount"),
    afterRestartEventCount: numberField(replay, "afterRestartEventCount"),
    finalEventCount: numberField(replay, "finalEventCount"),
    replayFromLastSeqCount: numberField(replay, "replayFromLastSeqCount"),
    continuationSeqStart,
    continuationSeqEnd: numberField(secondTurn, "seqEnd"),
    duplicateTerminalEvents,
    safeBoot: {
      stateDir: stringField(proof, "stateDir"),
      resumeFromSeq: beforeCrashLastSeq,
      nextTurnStartsAtSeq: continuationSeqStart,
    },
    rows,
  };
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function objectField(record: unknown, key: string): Record<string, unknown> {
  const object = objectValue(record);
  return objectValue(object?.[key]) ?? {};
}

function stringField(record: unknown, key: string): string | null {
  const object = objectValue(record);
  const value = object?.[key];
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

function numberField(record: unknown, key: string): number | null {
  const object = objectValue(record);
  const value = object?.[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function booleanField(record: unknown, key: string): boolean {
  const object = objectValue(record);
  return object?.[key] === true;
}

function arrayField(record: unknown, key: string): unknown[] {
  const object = objectValue(record);
  const value = object?.[key];
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(
      values
        .map((value) => (value === undefined || value === null ? null : String(value).trim()))
        .filter((value): value is string => Boolean(value)),
    ),
  );
}
