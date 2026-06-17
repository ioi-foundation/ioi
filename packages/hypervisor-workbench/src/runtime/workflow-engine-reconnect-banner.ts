export const WORKFLOW_ENGINE_RECONNECT_BANNER_SCHEMA_VERSION =
  "ioi.workflow.engine-reconnect-banner.v1" as const;

export interface WorkflowEngineReconnectProbeInput {
  endpoint?: string | null;
  phase?: string | null;
  attempt?: number | string | null;
  maxAttempts?: number | string | null;
  ok?: boolean | null;
  statusCode?: number | string | null;
  latencyMs?: number | string | null;
  timeoutMs?: number | string | null;
  errorCode?: string | null;
  message?: string | null;
  at?: string | null;
}

export interface WorkflowEngineReconnectBannerInput {
  probes?: readonly WorkflowEngineReconnectProbeInput[] | null;
}

export interface WorkflowEngineReconnectRow {
  id: string;
  status: "healthy" | "failed" | "restored";
  endpoint: string | null;
  phase: string | null;
  attempt: number;
  maxAttempts: number;
  ok: boolean;
  statusCode: number | null;
  latencyMs: number | null;
  timeoutMs: number | null;
  timedOut: boolean;
  errorCode: string | null;
  message: string | null;
  at: string | null;
}

export interface WorkflowEngineReconnectBanner {
  schemaVersion: typeof WORKFLOW_ENGINE_RECONNECT_BANNER_SCHEMA_VERSION;
  status: "idle" | "reconnecting" | "restored" | "exhausted" | "blocked";
  bannerLevel: "none" | "info" | "warning" | "critical";
  bannerLabel: string;
  composerFrozen: boolean;
  composerDisabledReason: string | null;
  endpoint: string | null;
  attempt: number | null;
  maxAttempts: number | null;
  timeoutMs: number | null;
  latestLatencyMs: number | null;
  failedAttemptCount: number;
  restoredAttemptCount: number;
  timeoutCount: number;
  rows: WorkflowEngineReconnectRow[];
  evidenceRefs: string[];
}

export function buildWorkflowEngineReconnectBanner(
  input: WorkflowEngineReconnectBannerInput,
): WorkflowEngineReconnectBanner {
  const rows = normalizeProbes(input.probes);
  if (rows.length === 0) {
    return {
      schemaVersion: WORKFLOW_ENGINE_RECONNECT_BANNER_SCHEMA_VERSION,
      status: "blocked",
      bannerLevel: "critical",
      bannerLabel: "Autopilot Engine connection state is unavailable.",
      composerFrozen: true,
      composerDisabledReason: "missing_heartbeat_evidence",
      endpoint: null,
      attempt: null,
      maxAttempts: null,
      timeoutMs: null,
      latestLatencyMs: null,
      failedAttemptCount: 0,
      restoredAttemptCount: 0,
      timeoutCount: 0,
      rows,
      evidenceRefs: [],
    };
  }

  const latest = rows[rows.length - 1];
  const failedAttemptCount = rows.filter((row) => row.status === "failed").length;
  const restoredAttemptCount = rows.filter((row) => row.status === "restored").length;
  const timeoutCount = rows.filter((row) => row.timedOut).length;
  const exhausted = latest.status === "failed" && latest.attempt >= latest.maxAttempts;
  const status =
    latest.status === "restored"
      ? "restored"
      : latest.status === "failed"
        ? exhausted
          ? "exhausted"
          : "reconnecting"
        : failedAttemptCount > 0
          ? "restored"
          : "idle";
  const composerFrozen = status === "reconnecting" || status === "exhausted";
  return {
    schemaVersion: WORKFLOW_ENGINE_RECONNECT_BANNER_SCHEMA_VERSION,
    status,
    bannerLevel: bannerLevelForStatus(status),
    bannerLabel: bannerLabelForStatus(status, latest, failedAttemptCount),
    composerFrozen,
    composerDisabledReason: composerFrozen ? status : null,
    endpoint: latest.endpoint,
    attempt: latest.attempt,
    maxAttempts: latest.maxAttempts,
    timeoutMs: latest.timeoutMs,
    latestLatencyMs: latest.latencyMs,
    failedAttemptCount,
    restoredAttemptCount,
    timeoutCount,
    rows,
    evidenceRefs: uniqueStrings([
      ...rows.map((row) => row.endpoint),
      ...rows.map((row) => row.errorCode),
      ...rows.map((row) => row.statusCode),
    ]),
  };
}

function normalizeProbes(
  probes: readonly WorkflowEngineReconnectProbeInput[] | null | undefined,
): WorkflowEngineReconnectRow[] {
  let sawFailure = false;
  return (probes ?? []).map((probe, index) => {
    const attempt = attemptNumber(probe.attempt) ?? index + 1;
    const maxAttempts = positiveInteger(probe.maxAttempts) ?? Math.max(attempt, 1);
    const ok = probe.ok === true;
    const timeoutMs = positiveInteger(probe.timeoutMs);
    const latencyMs = nonNegativeNumber(probe.latencyMs);
    const errorCode = cleanString(probe.errorCode);
    const phase = cleanString(probe.phase);
    const failed = !ok || Boolean(errorCode) || phase === "reconnecting" || phase === "heartbeat_failed";
    const status =
      ok && sawFailure
        ? "restored"
        : failed
          ? "failed"
          : "healthy";
    if (status === "failed") sawFailure = true;
    return {
      id: `engine-reconnect-${attempt}`,
      status,
      endpoint: cleanString(probe.endpoint),
      phase,
      attempt,
      maxAttempts,
      ok,
      statusCode: positiveInteger(probe.statusCode),
      latencyMs,
      timeoutMs,
      timedOut:
        errorCode === "timeout" ||
        errorCode === "AbortError" ||
        (latencyMs !== null && timeoutMs !== null && latencyMs > timeoutMs),
      errorCode,
      message: cleanString(probe.message),
      at: cleanString(probe.at),
    };
  });
}

function bannerLevelForStatus(
  status: WorkflowEngineReconnectBanner["status"],
): WorkflowEngineReconnectBanner["bannerLevel"] {
  if (status === "idle") return "none";
  if (status === "restored") return "info";
  if (status === "reconnecting") return "warning";
  return "critical";
}

function bannerLabelForStatus(
  status: WorkflowEngineReconnectBanner["status"],
  latest: WorkflowEngineReconnectRow,
  failedAttemptCount: number,
): string {
  if (status === "idle") return "Autopilot Engine connected.";
  if (status === "restored") {
    return `Autopilot Engine reconnected after ${failedAttemptCount} failed attempt(s).`;
  }
  if (status === "exhausted") {
    return `Autopilot Engine reconnect exhausted after ${latest.attempt}/${latest.maxAttempts} attempt(s).`;
  }
  if (status === "reconnecting") {
    return `Reconnecting to Autopilot Engine (Attempt ${latest.attempt}/${latest.maxAttempts})...`;
  }
  return "Autopilot Engine connection state is unavailable.";
}

function positiveInteger(value: unknown): number | null {
  const number = typeof value === "string" && value.trim() ? Number(value) : value;
  return typeof number === "number" && Number.isInteger(number) && number > 0 ? number : null;
}

function attemptNumber(value: unknown): number | null {
  const number = typeof value === "string" && value.trim() ? Number(value) : value;
  return typeof number === "number" && Number.isInteger(number) && number >= 0 ? number : null;
}

function nonNegativeNumber(value: unknown): number | null {
  const number = typeof value === "string" && value.trim() ? Number(value) : value;
  return typeof number === "number" && Number.isFinite(number) && number >= 0 ? number : null;
}

function cleanString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(values.map((value) => cleanString(value)).filter((value): value is string => Boolean(value))),
  );
}
