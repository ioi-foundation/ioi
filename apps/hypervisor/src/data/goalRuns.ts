export type GoalRunAdmissionPath = "direct_non_system" | "system_bound" | "legacy_system_bound_first_cut";
export type GoalRunStatus = "draft" | "active" | "paused" | "complete" | "superseded" | "revoked";

export type GoalRunRecord = {
  schema_version: string;
  goal_run_id: string;
  goal_ref: string;
  normalized_goal: string;
  status: GoalRunStatus;
  continuation_state: string;
  active_loop_phase?: string | null;
  admission_path_status: GoalRunAdmissionPath;
  result_profile?: string;
  target_session_ref?: string | null;
  role_topology_ref?: string | null;
  work_result_refs: string[];
  receipt_refs: string[];
  lifecycle_record_refs?: string[];
  blockers?: Array<{ code?: string; message?: string }>;
  updated_at: string;
};

type GoalRunListResponse = { ok: true; goal_runs: GoalRunRecord[] };
type GoalRunEventResponse = { ok: true; events: Array<Record<string, unknown>> };

async function daemonJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "include",
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
  });
  const value = await response.json();
  if (!response.ok) throw Object.assign(new Error(value?.error?.message ?? `HTTP ${response.status}`), { status: response.status, value });
  return value as T;
}

export async function listGoalRuns(sessionRef?: string): Promise<GoalRunRecord[]> {
  const query = sessionRef ? `?session=${encodeURIComponent(sessionRef)}` : "";
  const result = await daemonJson<GoalRunListResponse>(`/v1/goal-orchestration/goal-runs${query}`);
  return result.goal_runs;
}

export async function listGoalRunEvents(goalRunId: string): Promise<Array<Record<string, unknown>>> {
  const result = await daemonJson<GoalRunEventResponse>(`/v1/goal-orchestration/goal-runs/${encodeURIComponent(goalRunId)}/events`);
  return result.events;
}
