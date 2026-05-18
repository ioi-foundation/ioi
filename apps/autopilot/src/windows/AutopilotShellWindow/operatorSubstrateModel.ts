import type { PrimaryView, ProjectScope } from "./autopilotShellModel";

export type OperatorChromeMode =
  | "full"
  | "sidebar"
  | "docked"
  | "floating"
  | "embedded";

export type OperatorSurfaceRoute =
  | { kind: "primary-view"; view: PrimaryView }
  | { kind: "workflow-surface"; surface: "home" | "canvas" | "agents" | "catalog" }
  | { kind: "command-palette"; query?: string }
  | { kind: "workspace-file"; path: string; line?: number; column?: number }
  | { kind: "runtime-evidence"; evidenceRef: string }
  | { kind: "external"; href: string };

export interface OperatorRuntimeEvidenceRefs {
  runIds: string[];
  receiptIds: string[];
  artifactIds: string[];
  manifestRefs: string[];
  authorityRefs: string[];
}

export interface OperatorCommandCenterCommand {
  id: string;
  label: string;
  description: string;
  route: OperatorSurfaceRoute;
  keywords: string[];
  source: "shell-projection" | "runtime-projection" | "workspace-projection";
}

export interface OperatorCommandCenterModel {
  projectionId: string;
  activeRoute: OperatorSurfaceRoute;
  scopeLabel: string;
  placeholder: string;
  shortcutLabel: string;
  runtimeTruthSource: "daemon-runtime";
  evidenceRefs: OperatorRuntimeEvidenceRefs;
  commands: OperatorCommandCenterCommand[];
}

export interface OperatorActivityRailItem {
  id: string;
  label: string;
  route: OperatorSurfaceRoute;
  badgeCount?: number;
  dataWindowSurface: string;
  group: "primary" | "work" | "bottom" | "utility";
  source: "shell-projection" | "runtime-projection";
}

export interface OperatorActivityRailModel {
  projectionId: string;
  chromeMode: OperatorChromeMode;
  collapsed: boolean;
  activeRoute: OperatorSurfaceRoute;
  items: OperatorActivityRailItem[];
  runtimeTruthSource: "daemon-runtime";
}

export interface OperatorChatPaneModel {
  projectionId: string;
  chromeMode: OperatorChromeMode;
  activeSurface: "chat" | "workflows" | "runs" | "artifacts" | "policy" | "connections";
  controls: Array<"new" | "search" | "settings" | "expand" | "collapse" | "close">;
  showSessionList: boolean;
  runtimeTruthSource: "daemon-runtime";
  evidenceRefs: OperatorRuntimeEvidenceRefs;
}

export interface OperatorContextPickerModel {
  projectionId: string;
  allowedSources: Array<"repo" | "file" | "runtime" | "artifact" | "receipt" | "workflow" | "capability">;
  selectedRefs: string[];
  runtimeTruthSource: "daemon-runtime";
}

export interface AutonomousSystemPackageRef {
  packageId: string;
  manifestRef: string;
  workflowRef: string;
}

export interface ProjectArtifactRefs {
  fileRefs: string[];
  manifestRefs: string[];
  receiptRefs: string[];
}

export interface EvaluationFixtureRefs {
  fixtureRefs: string[];
  scorecardRefs: string[];
  expectedReceiptRefs: string[];
}

export interface WorkflowProjectMaterializationRequest {
  workflowId: string;
  projectName: string;
  packageRef?: AutonomousSystemPackageRef;
  targetRootHint?: string;
  dryRun: boolean;
}

export interface GeneratedProjectDescriptor {
  id: string;
  name: string;
  rootPath: string;
  packageRef: AutonomousSystemPackageRef;
  artifactRefs: ProjectArtifactRefs;
  evaluationRefs: EvaluationFixtureRefs;
}

export interface WorkspaceOpenReceipt {
  receiptId: string;
  projectId: string;
  rootPath: string;
  openedAtMs: number;
  surfaceRoute: OperatorSurfaceRoute;
}

export interface WorkflowProjectMaterializationReceipt {
  receiptId: string;
  request: WorkflowProjectMaterializationRequest;
  generatedProject: GeneratedProjectDescriptor;
  workspaceOpenReceipt?: WorkspaceOpenReceipt;
  status: "proposed" | "materialized" | "opened" | "blocked";
  blockers: string[];
}

export interface SubstrateElementLocator {
  kind: "dom" | "aria" | "data-attribute" | "coordinate" | "direct-webview";
  selector?: string;
  accessibleName?: string;
  dataAttribute?: string;
  coordinates?: { x: number; y: number };
  surfaceId?: string;
}

export interface DirectWebviewInspectionTarget {
  surfaceId: string;
  label: string;
  bounds: { x: number; y: number; width: number; height: number };
  screenBounds?: { x: number; y: number; width: number; height: number } | null;
}

export interface OperatorInspectionTargetModel {
  targetId: string;
  label: string;
  surface:
    | "activity-rail"
    | "command-center"
    | "explorer"
    | "editor"
    | "terminal"
    | "chat-composer"
    | "workflow-composer"
    | "run-evidence"
    | "direct-webview";
  locators: SubstrateElementLocator[];
  runtimeTruthSource: "daemon-runtime";
}

export interface BuildOperatorCommandCenterModelOptions {
  activeView: PrimaryView;
  workflowSurface: "home" | "canvas" | "agents" | "catalog";
  currentProject: ProjectScope;
  notificationCount: number;
  evidenceRefs?: Partial<OperatorRuntimeEvidenceRefs>;
}

export interface BuildOperatorActivityRailModelOptions {
  activeView: PrimaryView;
  collapsed: boolean;
  notificationCount: number;
}

const EMPTY_EVIDENCE_REFS: OperatorRuntimeEvidenceRefs = {
  runIds: [],
  receiptIds: [],
  artifactIds: [],
  manifestRefs: [],
  authorityRefs: [],
};

const PRIMARY_VIEW_LABELS: Record<PrimaryView, string> = {
  home: "Home",
  chat: "Chat",
  workspace: "Workspace",
  workflows: "Workflows",
  runs: "Runs",
  mounts: "Model Mounts",
  inbox: "Inbox",
  capabilities: "Capabilities",
  policy: "Policy",
  settings: "Settings",
};

const RAIL_VIEW_ORDER: PrimaryView[] = [
  "home",
  "chat",
  "inbox",
  "workspace",
  "workflows",
  "runs",
  "mounts",
  "capabilities",
  "policy",
  "settings",
];

function mergeEvidenceRefs(
  evidenceRefs: Partial<OperatorRuntimeEvidenceRefs> | undefined,
): OperatorRuntimeEvidenceRefs {
  return {
    runIds: evidenceRefs?.runIds ?? [],
    receiptIds: evidenceRefs?.receiptIds ?? [],
    artifactIds: evidenceRefs?.artifactIds ?? [],
    manifestRefs: evidenceRefs?.manifestRefs ?? [],
    authorityRefs: evidenceRefs?.authorityRefs ?? [],
  };
}

function primaryViewCommand(view: PrimaryView): OperatorCommandCenterCommand {
  return {
    id: `surface.${view}`,
    label: `Open ${PRIMARY_VIEW_LABELS[view]}`,
    description: `Switch to ${PRIMARY_VIEW_LABELS[view]}.`,
    route: { kind: "primary-view", view },
    keywords: [view, PRIMARY_VIEW_LABELS[view].toLowerCase()],
    source: "shell-projection",
  };
}

function railGroupForView(view: PrimaryView): OperatorActivityRailItem["group"] {
  if (view === "settings") return "bottom";
  if (view === "home" || view === "chat" || view === "inbox") return "primary";
  return "work";
}

function railItemForView(
  view: PrimaryView,
  notificationCount: number,
): OperatorActivityRailItem {
  return {
    id: `surface.${view}`,
    label: PRIMARY_VIEW_LABELS[view],
    route: { kind: "primary-view", view },
    badgeCount: view === "inbox" ? notificationCount : undefined,
    dataWindowSurface: view,
    group: railGroupForView(view),
    source: view === "inbox" ? "runtime-projection" : "shell-projection",
  };
}

export function buildOperatorActivityRailModel({
  activeView,
  collapsed,
  notificationCount,
}: BuildOperatorActivityRailModelOptions): OperatorActivityRailModel {
  return {
    projectionId: `operator-activity-rail:${activeView}:${collapsed ? "collapsed" : "expanded"}`,
    chromeMode: collapsed ? "sidebar" : "full",
    collapsed,
    activeRoute: { kind: "primary-view", view: activeView },
    runtimeTruthSource: "daemon-runtime",
    items: [
      {
        id: "command.search",
        label: "Search",
        route: { kind: "command-palette" },
        dataWindowSurface: "search",
        group: "utility",
        source: "shell-projection",
      },
      ...RAIL_VIEW_ORDER.map((view) => railItemForView(view, notificationCount)),
      {
        id: "profile.current",
        label: "Profile",
        route: { kind: "command-palette", query: "profile" },
        dataWindowSurface: "profile",
        group: "bottom",
        source: "shell-projection",
      },
    ],
  };
}

export function buildOperatorCommandCenterModel({
  activeView,
  workflowSurface,
  currentProject,
  notificationCount,
  evidenceRefs,
}: BuildOperatorCommandCenterModelOptions): OperatorCommandCenterModel {
  const mergedEvidenceRefs = mergeEvidenceRefs(evidenceRefs);
  const surfaceLabel =
    activeView === "workflows" && workflowSurface !== "home"
      ? `${PRIMARY_VIEW_LABELS.workflows}: ${workflowSurface}`
      : PRIMARY_VIEW_LABELS[activeView];
  const commands: OperatorCommandCenterCommand[] = [
    primaryViewCommand("home"),
    primaryViewCommand("chat"),
    primaryViewCommand("workspace"),
    primaryViewCommand("workflows"),
    primaryViewCommand("runs"),
    primaryViewCommand("mounts"),
    primaryViewCommand("capabilities"),
    primaryViewCommand("policy"),
    primaryViewCommand("settings"),
    {
      id: "workspace.search",
      label: "Search workspace",
      description: "Search files, commands, symbols, workflows, receipts, and settings.",
      route: { kind: "command-palette", query: "%" },
      keywords: ["search", "find", "file", "symbol", "workspace"],
      source: "workspace-projection",
    },
    {
      id: "workflow.new",
      label: "New workflow",
      description: "Create an agent workflow from the shared composer.",
      route: { kind: "workflow-surface", surface: "canvas" },
      keywords: ["workflow", "agent", "compose", "graph"],
      source: "shell-projection",
    },
    {
      id: "runtime.receipts",
      label: "Inspect receipts",
      description: "Open runtime receipts, artifacts, and retained evidence.",
      route: { kind: "primary-view", view: "runs" },
      keywords: ["receipt", "artifact", "evidence", "trace", "run"],
      source: "runtime-projection",
    },
  ];

  if (notificationCount > 0) {
    commands.push({
      id: "inbox.pending",
      label: `Open Inbox (${notificationCount})`,
      description: "Review pending approvals, prompts, and interventions.",
      route: { kind: "primary-view", view: "inbox" },
      keywords: ["inbox", "approval", "notification", "pending"],
      source: "runtime-projection",
    });
  }

  return {
    projectionId: `operator-command-center:${activeView}:${workflowSurface}:${currentProject.id}`,
    activeRoute: { kind: "primary-view", view: activeView },
    scopeLabel: `${currentProject.name} / ${surfaceLabel}`,
    placeholder: "Search Autopilot, code, workflows, runs, and commands",
    shortcutLabel: "Ctrl+K",
    runtimeTruthSource: "daemon-runtime",
    evidenceRefs: {
      ...EMPTY_EVIDENCE_REFS,
      ...mergedEvidenceRefs,
    },
    commands,
  };
}
