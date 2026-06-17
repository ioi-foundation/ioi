import {
  HYPERVISOR_HARNESS_SELECTION_OPTIONS,
  type HypervisorHarnessSelectionOption,
} from "./harnessAdapterModel.ts";

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

export type HypervisorNewSessionSetupSectionId =
  | "intent"
  | "project"
  | "harness"
  | "model_route"
  | "privacy_posture"
  | "authority"
  | "receipt_preview";

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

export interface HypervisorNewSessionSetupSection {
  id: HypervisorNewSessionSetupSectionId;
  label: string;
  description: string;
  required: boolean;
}

export interface HypervisorNewSessionSetupModel {
  action: HypervisorShellAction;
  sections: HypervisorNewSessionSetupSection[];
  harnessOptions: HypervisorHarnessSelectionOption[];
  runtimeTruthSource: "daemon-runtime";
}

export interface HypervisorSessionLaunchRecipe {
  recipe_id: string;
  label: string;
  description: string;
  kind:
    | "mission"
    | "workbench"
    | "agent"
    | "automation"
    | "foundry_job"
    | "fleet_job"
    | "privacy_workspace";
  surface_id: HypervisorSurfaceId;
  required_inputs: string[];
  model_mount_policy: "inherit" | "select" | "required" | "forbidden";
  harness_profile_policy: "default" | "select" | "external_adapter";
  authority_scope_templates: string[];
  privacy_posture_templates: string[];
}

export interface HypervisorNewSessionLaunchRequest {
  recipe_id: string;
  project_id: string;
  harness_selection_ref: string;
  model_route_ref: string;
  privacy_posture_ref: string;
  authority_scope_refs: string[];
  receipt_preview_ref: string;
}

export const HYPERVISOR_PRIMARY_ACTION: HypervisorShellAction = {
  id: "new_session",
  label: "New Session",
  description:
    "Launch a governed mission, workbench, agent, automation, foundry, fleet, or private workspace session.",
};

export const HYPERVISOR_NEW_SESSION_SETUP_MODEL: HypervisorNewSessionSetupModel =
  {
    action: HYPERVISOR_PRIMARY_ACTION,
    sections: [
      {
        id: "intent",
        label: "Intent",
        description: "Goal, acceptance criteria, task type, and operator notes.",
        required: true,
      },
      {
        id: "project",
        label: "Project",
        description: "Workspace/project root, state refs, and restore posture.",
        required: true,
      },
      {
        id: "harness",
        label: "Harness",
        description:
          "Default Harness Profile or daemon-mediated AgentHarnessAdapter.",
        required: true,
      },
      {
        id: "model_route",
        label: "Model Route",
        description: "Hypervisor model mount, adapter-native route, or provider-trust route.",
        required: true,
      },
      {
        id: "privacy_posture",
        label: "Privacy",
        description: "Public trunk, redacted projection, cTEE private workspace, or explicit unsafe mount.",
        required: true,
      },
      {
        id: "authority",
        label: "Authority",
        description: "wallet.network scopes, approvals, leases, and connector capabilities.",
        required: true,
      },
      {
        id: "receipt_preview",
        label: "Receipt Preview",
        description: "Expected receipt, Agentgres operation, artifact, and replay refs.",
        required: false,
      },
    ],
    harnessOptions: HYPERVISOR_HARNESS_SELECTION_OPTIONS,
    runtimeTruthSource: "daemon-runtime",
  };

export const HYPERVISOR_SESSION_LAUNCH_RECIPES: HypervisorSessionLaunchRecipe[] =
  [
    {
      recipe_id: "mission.default",
      label: "Mission",
      description:
        "Intent-to-outcome session with acceptance criteria, blockers, receipts, and operator review.",
      kind: "mission",
      surface_id: "sessions",
      required_inputs: ["intent", "project", "harness", "model_route", "authority"],
      model_mount_policy: "select",
      harness_profile_policy: "select",
      authority_scope_templates: ["scope:workspace.read", "scope:receipt.write"],
      privacy_posture_templates: ["ctee_private_workspace", "redacted_projection"],
    },
    {
      recipe_id: "workbench.default",
      label: "Workbench",
      description:
        "Governed code/systems session that opens the selected editor, terminal, browser, or VM adapter.",
      kind: "workbench",
      surface_id: "workbench",
      required_inputs: ["project", "harness", "model_route", "privacy_posture"],
      model_mount_policy: "inherit",
      harness_profile_policy: "select",
      authority_scope_templates: ["scope:workspace.read", "scope:workspace.patch"],
      privacy_posture_templates: ["public_trunk", "redacted_projection"],
    },
    {
      recipe_id: "agent.default",
      label: "Agent",
      description:
        "Persistent worker session with skills, memory, capability leases, and revocation posture.",
      kind: "agent",
      surface_id: "agents",
      required_inputs: ["intent", "project", "harness", "authority"],
      model_mount_policy: "select",
      harness_profile_policy: "select",
      authority_scope_templates: ["scope:agent.run", "scope:capability.lease"],
      privacy_posture_templates: ["ctee_private_workspace", "redacted_projection"],
    },
    {
      recipe_id: "automation.default",
      label: "Automation",
      description:
        "Workflow compositor session for templates, graph execution, schedules, and reusable recipes.",
      kind: "automation",
      surface_id: "automations",
      required_inputs: ["intent", "project", "harness", "receipt_preview"],
      model_mount_policy: "inherit",
      harness_profile_policy: "default",
      authority_scope_templates: ["scope:workflow.compose", "scope:receipt.write"],
      privacy_posture_templates: ["public_trunk", "redacted_projection"],
    },
    {
      recipe_id: "foundry.eval",
      label: "Foundry Job",
      description:
        "Eval, benchmark, training, distillation, or promotion job with scorecard evidence.",
      kind: "foundry_job",
      surface_id: "foundry",
      required_inputs: ["project", "harness", "model_route", "receipt_preview"],
      model_mount_policy: "select",
      harness_profile_policy: "select",
      authority_scope_templates: ["scope:eval.run", "scope:artifact.write"],
      privacy_posture_templates: ["public_trunk", "redacted_projection"],
    },
    {
      recipe_id: "fleet.provider",
      label: "Fleet Job",
      description:
        "Provider, VM, node, port, service, or zero-to-idle infrastructure session.",
      kind: "fleet_job",
      surface_id: "fleet",
      required_inputs: ["project", "authority", "privacy_posture", "receipt_preview"],
      model_mount_policy: "forbidden",
      harness_profile_policy: "external_adapter",
      authority_scope_templates: ["scope:cloud.deploy", "scope:provider.spend"],
      privacy_posture_templates: ["redacted_projection", "ctee_private_workspace"],
    },
    {
      recipe_id: "privacy.workspace",
      label: "Private Workspace",
      description:
        "cTEE-backed workspace session for encrypted refs, custody state, and declassification review.",
      kind: "privacy_workspace",
      surface_id: "privacy",
      required_inputs: ["project", "privacy_posture", "authority", "receipt_preview"],
      model_mount_policy: "select",
      harness_profile_policy: "default",
      authority_scope_templates: ["scope:decrypt.view", "scope:declassify.request"],
      privacy_posture_templates: ["ctee_private_workspace"],
    },
  ];

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
