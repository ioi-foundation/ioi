export type HypervisorClientKind =
  | "app"
  | "web"
  | "cli_headless"
  | "tui_presentation";

export type HypervisorSurfaceId =
  | "home"
  | "sessions"
  | "projects"
  | "missions"
  | "workbench"
  | "automations"
  | "insights"
  | "agents"
  | "models"
  | "privacy"
  | "fleet"
  | "foundry"
  | "authority"
  | "receipts"
  | "settings";

export type HypervisorShellActionId = "new_session";

export type HypervisorSurfaceKind =
  | "core"
  | "application"
  | "governance"
  | "infrastructure"
  | "settings";

export type HypervisorSessionDetailTab =
  | "agent"
  | "workbench"
  | "environment"
  | "changes"
  | "receipts"
  | "replay";

export type HypervisorInspectorPanelId =
  | "changes"
  | "ports_services"
  | "tasks"
  | "terminal"
  | "logs"
  | "authority"
  | "privacy"
  | "receipts"
  | "model_harness_provider";

export interface HypervisorShellNavigationItem {
  id: HypervisorSurfaceId;
  label: string;
  description: string;
  kind: HypervisorSurfaceKind;
  railGroup: "primary" | "applications" | "governance" | "bottom";
  defaultSessionTab?: HypervisorSessionDetailTab;
  inspectorPanels: HypervisorInspectorPanelId[];
  adapterTargets?: string[];
}

export interface HypervisorShellAction {
  id: HypervisorShellActionId;
  label: string;
  description: string;
}

export const HYPERVISOR_PRIMARY_ACTION: HypervisorShellAction = {
  id: "new_session",
  label: "New Session",
  description:
    "Launch a governed mission, workbench, agent, automation, foundry, fleet, or private workspace session.",
};

export const HYPERVISOR_PRIMARY_SURFACES: HypervisorShellNavigationItem[] = [
  {
    id: "home",
    label: "Home",
    description: "Operator cockpit for active sessions, projects, and next actions.",
    kind: "core",
    railGroup: "primary",
    inspectorPanels: ["logs", "receipts"],
  },
  {
    id: "sessions",
    label: "Sessions",
    description: "Live governed workspaces and runs managed by Hypervisor Core.",
    kind: "core",
    railGroup: "primary",
    defaultSessionTab: "agent",
    inspectorPanels: ["changes", "authority", "privacy", "receipts"],
  },
  {
    id: "projects",
    label: "Projects",
    description: "Workspace groups, repos, state roots, and restore posture.",
    kind: "core",
    railGroup: "primary",
    inspectorPanels: ["changes", "logs", "receipts"],
  },
  {
    id: "missions",
    label: "Missions",
    description: "Intent-to-outcome work with acceptance, budget, and blockers.",
    kind: "application",
    railGroup: "applications",
    defaultSessionTab: "agent",
    inspectorPanels: ["tasks", "authority", "receipts"],
  },
  {
    id: "workbench",
    label: "Workbench",
    description:
      "Code and systems surface; editors, terminals, browsers, and VMs are adapter targets.",
    kind: "application",
    railGroup: "applications",
    defaultSessionTab: "workbench",
    inspectorPanels: ["changes", "ports_services", "terminal", "model_harness_provider"],
    adapterTargets: [
      "VS Code",
      "Cursor",
      "Windsurf",
      "JetBrains",
      "Browser IDE",
      "Terminal",
    ],
  },
  {
    id: "automations",
    label: "Automations",
    description: "Workflow compositor for templates, graphs, schedules, and reusable runs.",
    kind: "application",
    railGroup: "applications",
    inspectorPanels: ["tasks", "logs", "receipts"],
  },
  {
    id: "insights",
    label: "Insights",
    description: "Run history, changes, traces, receipts, and improvement signals.",
    kind: "application",
    railGroup: "applications",
    inspectorPanels: ["logs", "receipts"],
  },
  {
    id: "agents",
    label: "Agents",
    description: "Agent identities, harness adapters, capabilities, memory, and skills.",
    kind: "application",
    railGroup: "applications",
    inspectorPanels: ["authority", "privacy", "model_harness_provider"],
  },
  {
    id: "models",
    label: "Models",
    description: "Model routes, mounts, providers, local models, and inference posture.",
    kind: "application",
    railGroup: "applications",
    inspectorPanels: ["model_harness_provider", "privacy", "receipts"],
  },
  {
    id: "privacy",
    label: "Privacy",
    description: "Private workspace, cTEE posture, declassification, and custody state.",
    kind: "governance",
    railGroup: "governance",
    inspectorPanels: ["privacy", "authority", "receipts"],
  },
  {
    id: "fleet",
    label: "Fleet",
    description: "Direct provider integrations for local, cloud, DePIN, VM, and node estate.",
    kind: "infrastructure",
    railGroup: "governance",
    inspectorPanels: ["ports_services", "logs", "receipts"],
  },
  {
    id: "foundry",
    label: "Foundry",
    description: "Evals, training, distillation, benchmarks, and package promotion.",
    kind: "application",
    railGroup: "governance",
    inspectorPanels: ["tasks", "logs", "receipts"],
  },
  {
    id: "authority",
    label: "Authority",
    description: "wallet.network approvals, leases, scopes, policies, and capability exits.",
    kind: "governance",
    railGroup: "governance",
    inspectorPanels: ["authority", "receipts"],
  },
  {
    id: "receipts",
    label: "Receipts",
    description: "Receipt-backed audit, replay, state evidence, and delivery proof.",
    kind: "governance",
    railGroup: "governance",
    inspectorPanels: ["receipts", "logs"],
  },
  {
    id: "settings",
    label: "Settings",
    description: "Client preferences, adapters, tokens, defaults, and compatibility settings.",
    kind: "settings",
    railGroup: "bottom",
    inspectorPanels: ["model_harness_provider", "authority"],
  },
];

export const HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL = [
  "active",
  "pinned",
  "waiting_for_approval",
  "blocked",
  "completed",
] as const;

export const HYPERVISOR_SESSION_DETAIL_TABS: HypervisorSessionDetailTab[] = [
  "agent",
  "workbench",
  "environment",
  "changes",
  "receipts",
  "replay",
];

export const HYPERVISOR_RIGHT_INSPECTOR_PANELS: HypervisorInspectorPanelId[] = [
  "changes",
  "authority",
  "privacy",
  "receipts",
  "model_harness_provider",
];

export const HYPERVISOR_BOTTOM_INSPECTOR_PANELS: HypervisorInspectorPanelId[] = [
  "ports_services",
  "tasks",
  "terminal",
  "logs",
];

export function getHypervisorSurfaceById(
  id: HypervisorSurfaceId,
): HypervisorShellNavigationItem {
  const surface = HYPERVISOR_PRIMARY_SURFACES.find((item) => item.id === id);
  if (!surface) {
    throw new Error(`Unknown Hypervisor surface: ${id}`);
  }
  return surface;
}

export function isHypervisorSurfaceId(
  value: string,
): value is HypervisorSurfaceId {
  return HYPERVISOR_PRIMARY_SURFACES.some((item) => item.id === value);
}
