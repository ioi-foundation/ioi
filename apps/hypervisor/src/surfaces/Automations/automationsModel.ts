// Automations model — source-derived from the product-ui automations route (header → stat
// cards → list rows, with template-led empty state). The route anatomy and behavior are
// derived verbatim; only the data boundary changes: a typed daemon client instead of the
// upstream WorkflowService wire. See docs/product-ui-api-integration.md.
//
// Native contract (daemon-owned, no upstream namespace):
//   GET /v1/hypervisor/automations -> { ok, automations: AutomationRecord[] }
// Shapes are derived from the daemon JSON (handle_automation_list / handle_automation_create).
import { daemon } from "../../data/daemon";

export type AutomationTrigger = {
  kind?: string; // "manual" | "schedule" | "event" | ...
  cron?: string;
  event?: string;
};

export type AutomationStep = {
  kind?: string; // "agent" | "command" | "proposal" | ...
  prompt?: string;
  command?: string;
  title?: string;
};

export type AutomationLimits = {
  max_total?: number;
  per_exec_seconds?: number;
  budget?: number | null;
};

export type ExecutorIdentity = {
  kind?: string;
  ref?: string;
};

export type Automation = {
  automation_id: string;
  schema_version?: string;
  name?: string;
  project_id?: string;
  environment_class_id?: string;
  recipe_ref?: string | null;
  trigger?: AutomationTrigger | null;
  steps?: AutomationStep[];
  limits?: AutomationLimits | null;
  executor_identity?: ExecutorIdentity | null;
  created_at?: string;
};

export type AutomationsData = {
  automations: Automation[];
};

// Stat tiles derived from the automations collection (the route header summary).
export type AutomationStat = {
  key: string;
  label: string;
  value: number;
  accent?: boolean;
};

export function triggerLabel(t: AutomationTrigger | null | undefined): string {
  const kind = t?.kind || "manual";
  if (kind === "schedule") return t?.cron ? `Schedule · ${t.cron}` : "Schedule";
  if (kind === "event") return t?.event ? `Event · ${t.event}` : "Event";
  if (kind === "manual") return "Manual";
  return kind;
}

export function stepSummary(steps: AutomationStep[] | undefined): string {
  const list = steps || [];
  if (!list.length) return "No steps";
  const kinds = list.map((s) => s.kind || "step");
  const n = list.length;
  return `${n} step${n > 1 ? "s" : ""} · ${kinds.join(" → ")}`;
}

export function relativeTime(iso?: string): string {
  if (!iso) return "";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return `${Math.round(days / 7)}w ago`;
}

export function computeStats(automations: Automation[]): AutomationStat[] {
  const total = automations.length;
  const scheduled = automations.filter((a) => (a.trigger?.kind || "manual") === "schedule").length;
  const manual = automations.filter((a) => (a.trigger?.kind || "manual") === "manual").length;
  return [
    { key: "total", label: "Total Automations", value: total, accent: true },
    { key: "scheduled", label: "Scheduled", value: scheduled },
    { key: "manual", label: "Manual", value: manual },
  ];
}

export async function fetchAutomations(): Promise<AutomationsData> {
  const r = await daemon
    .get<{ automations?: Automation[] }>("/hypervisor/automations")
    .catch(() => ({}) as { automations?: Automation[] });
  const automations = (r.automations || []).slice().sort(
    (a, b) => Date.parse(b.created_at || "") - Date.parse(a.created_at || ""),
  );
  return { automations };
}
