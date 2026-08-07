export type JsonRecord = Record<string, unknown>;
export type GoalSpaceTab = "goals" | "rooms";

export function goalSpaceTabForKey(current: GoalSpaceTab, key: string): GoalSpaceTab | null {
  if (key === "Home") return "goals";
  if (key === "End") return "rooms";
  if (key === "ArrowLeft" || key === "ArrowUp" || key === "ArrowRight" || key === "ArrowDown") {
    return current === "goals" ? "rooms" : "goals";
  }
  return null;
}

export interface KernelOwnerBinding {
  key:
    | "thread"
    | "fork"
    | "managed_session"
    | "launch_recipe"
    | "harness_binding"
    | "readiness"
    | "spawn"
    | "terminal_attachment";
  label: string;
  fieldName: string;
  pattern: RegExp;
  value: string | null;
}

const KERNEL_BINDINGS = [
  {
    key: "thread",
    label: "Runtime thread events",
    fieldName: "runtime_thread_event_ref",
    pattern: /^agentgres:\/\/runtime-events\/[^\s]{1,240}\/operations\/[^\s]{1,240}$/,
  },
  {
    key: "fork",
    label: "Thread fork control",
    fieldName: "runtime_thread_fork_control_ref",
    pattern: /^agentgres:\/\/runtime-events\/[^\s]{1,240}\/operations\/[^\s]{1,240}$/,
  },
  {
    key: "managed_session",
    label: "Managed Session control",
    fieldName: "runtime_managed_session_control_ref",
    pattern: /^agentgres:\/\/runtime-events\/[^\s]{1,240}\/operations\/[^\s]{1,240}$/,
  },
  {
    key: "launch_recipe",
    label: "Session launch recipe admission",
    fieldName: "hypervisor_session_launch_recipe_admission_ref",
    pattern: /^hypervisor-session-launch-recipe-admission:[^\s]{1,280}$/,
  },
  {
    key: "harness_binding",
    label: "Harness Session binding admission",
    fieldName: "harness_session_binding_admission_ref",
    pattern: /^harness-session-binding-admission:[^\s]{1,400}$/,
  },
  {
    key: "readiness",
    label: "Readiness evidence",
    fieldName: "harness_readiness_ref",
    pattern: /^harness-session-readiness:[^\s]{1,300}$/,
  },
  {
    key: "spawn",
    label: "Spawn evidence",
    fieldName: "harness_spawn_ref",
    pattern: /^harness-session-spawn:[^\s]{1,300}$/,
  },
  {
    key: "terminal_attachment",
    label: "Terminal attachment",
    fieldName: "terminal_attachment_ref",
    pattern: /^harness-session-terminal-attach:[^\s]{1,300}$/,
  },
] as const;

function record(value: unknown): JsonRecord | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : null;
}

export function kernelOwnerBindings(value: unknown): KernelOwnerBinding[] {
  const object = record(value);
  return KERNEL_BINDINGS.map((binding) => {
    const candidate = object?.[binding.fieldName];
    return {
      ...binding,
      value: typeof candidate === "string" && binding.pattern.test(candidate) ? candidate : null,
    };
  });
}

export function requiredKernelBindingsComplete(value: unknown): boolean {
  return kernelOwnerBindings(value)
    .slice(0, 5)
    .every((binding) => binding.value !== null);
}

export function canonicalTail(value: unknown, scheme: string, idPrefix: string): string | null {
  if (typeof value !== "string") return null;
  const prefix = `${scheme}://`;
  const candidate = value.startsWith(prefix) ? value.slice(prefix.length) : value;
  return candidate.startsWith(idPrefix) && /^[A-Za-z0-9_-]+$/.test(candidate) ? candidate : null;
}

export function goalRunId(value: unknown): string | null {
  const object = record(value);
  return canonicalTail(object?.goal_run_id ?? object?.goal_ref ?? object?.id, "goal", "gr_");
}

export function outcomeRoomId(value: unknown): string | null {
  const object = record(value);
  return canonicalTail(object?.outcome_room_id ?? object?.outcome_room_ref ?? object?.id, "outcome-room", "or_");
}

export function activationId(value: unknown): string | null {
  const object = record(value);
  return canonicalTail(object?.activation_id ?? object?.activation_ref ?? object?.id, "goal-run-activation", "gra_");
}

export function textAt(value: unknown, ...path: string[]): string | null {
  let current: unknown = value;
  for (const key of path) current = record(current)?.[key];
  return typeof current === "string" && current.length > 0 ? current : null;
}

export function numberAt(value: unknown, ...path: string[]): number | null {
  let current: unknown = value;
  for (const key of path) current = record(current)?.[key];
  return typeof current === "number" && Number.isFinite(current) ? current : null;
}

export function listAt(value: unknown, ...path: string[]): unknown[] {
  let current: unknown = value;
  for (const key of path) current = record(current)?.[key];
  return Array.isArray(current) ? current : [];
}

export function errorDetail(value: unknown): { code: string; message: string; details: unknown } {
  const outer = record(value);
  const nested = record(outer?.error);
  const code =
    (typeof nested?.code === "string" && nested.code) ||
    (typeof outer?.code === "string" && outer.code) ||
    (typeof outer?.error === "string" && outer.error) ||
    "request_failed";
  const message =
    (typeof nested?.message === "string" && nested.message) ||
    (typeof outer?.message === "string" && outer.message) ||
    code;
  return { code, message, details: nested?.details ?? outer?.details ?? null };
}

export function shortRef(value: unknown, keep = 30): string {
  if (typeof value !== "string") return "—";
  if (value.length <= keep + 10) return value;
  return `${value.slice(0, keep)}…${value.slice(-8)}`;
}

export function goalTitle(value: unknown): string {
  return (
    textAt(value, "normalized_goal") ??
    textAt(value, "goal") ??
    textAt(value, "goal_text") ??
    textAt(value, "objective") ??
    textAt(value, "goal_ref") ??
    "Untitled goal"
  );
}

export function roomTitle(value: unknown): string {
  return (
    textAt(value, "display_name") ??
    textAt(value, "name") ??
    textAt(value, "objective") ??
    textAt(value, "objective_ref") ??
    textAt(value, "outcome_room_id") ??
    "Outcome room"
  );
}
