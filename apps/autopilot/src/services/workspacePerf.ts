type MetricDetail = Record<string, unknown> | undefined;

type MetricRecord = {
  category: "app" | "workspace";
  stage: string;
  elapsedMs: number;
  detail?: Record<string, unknown>;
};

const SESSION_START_MS =
  typeof performance !== "undefined" ? performance.now() : Date.now();

const SESSION_ID =
  typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `workspace-metric-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;

declare global {
  interface Window {
    __AUTOPILOT_METRICS__?: MetricRecord[];
  }
}

function nowElapsedMs(): number {
  const now =
    typeof performance !== "undefined" ? performance.now() : Date.now();
  return Math.round(now - SESSION_START_MS);
}

function recordMetric(
  category: MetricRecord["category"],
  stage: string,
  detail?: MetricDetail,
) {
  const metric: MetricRecord = {
    category,
    stage,
    elapsedMs: nowElapsedMs(),
    detail,
  };

  if (typeof window !== "undefined") {
    window.__AUTOPILOT_METRICS__ = [
      ...(window.__AUTOPILOT_METRICS__ ?? []),
      metric,
    ].slice(-120);
  }

  console.info(`[Autopilot][${category === "app" ? "AppMetric" : "WorkspaceMetric"}]`, {
    sessionId: SESSION_ID,
    stage,
    elapsedMs: metric.elapsedMs,
    ...(detail ? { detail } : {}),
  });
}

export function markAutopilotMetric(stage: string, detail?: MetricDetail) {
  recordMetric("app", stage, detail);
}

export function markWorkspaceMetric(stage: string, detail?: MetricDetail) {
  recordMetric("workspace", stage, detail);
}
