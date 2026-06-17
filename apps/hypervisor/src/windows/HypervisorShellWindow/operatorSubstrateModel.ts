import type { PrimaryView, ProjectScope } from "./hypervisorShellModel.ts";
import {
  HYPERVISOR_PRIMARY_SURFACES,
  type HypervisorSurfaceId,
  type HypervisorSurfaceKind,
} from "./hypervisorShellNavigationModel.ts";

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
  description: string;
  route: OperatorSurfaceRoute;
  badgeCount?: number;
  dataWindowSurface: string;
  hypervisorSurfaceId?: HypervisorSurfaceId;
  surfaceKind?: HypervisorSurfaceKind;
  routeState: "active_route" | "planned_surface";
  group: "primary" | "applications" | "governance" | "bottom" | "utility";
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
  activeSurface:
    | "sessions"
    | "automations"
    | "insights"
    | "artifacts"
    | "authority"
    | "connections";
  controls: Array<"new" | "search" | "settings" | "expand" | "collapse" | "close">;
  showSessionList: boolean;
  runtimeTruthSource: "daemon-runtime";
  evidenceRefs: OperatorRuntimeEvidenceRefs;
}

export interface OperatorChatPaneChrome {
  mode: OperatorChromeMode;
  tabLabel: string;
  showHeader: boolean;
  showSessionList: boolean;
  actionOrder: Array<"leading" | "new" | "search" | "settings" | "divider" | "expand" | "collapse" | "close" | "trailing">;
  runtimeTruthSource: "daemon-runtime";
}

export interface OperatorChatPaneAction {
  id: string;
  label: string;
  role: "session" | "command" | "settings" | "layout" | "dismiss" | "surface";
  route?: OperatorSurfaceRoute;
  source: "shell-projection" | "runtime-projection" | "workspace-projection";
}

export interface OperatorChatComposerModel {
  projectionId: string;
  placeholder: string;
  commandEntry: "slash" | "palette" | "both";
  contextControl: OperatorChatContextControlModel;
  modelControl: {
    selectedCapabilityRef: string | null;
    readiness: "ready" | "blocked" | "unknown";
  };
  toolControl: {
    selectedCapabilityRefs: string[];
    readiness: "ready" | "blocked" | "unknown";
  };
  runtimeTruthSource: "daemon-runtime";
  evidenceRefs: OperatorRuntimeEvidenceRefs;
}

export interface OperatorChatEmptyStateModel {
  title: string;
  description: string;
  suggestedActionIds: string[];
  runtimeTruthSource: "daemon-runtime";
}

export interface OperatorChatContextControlModel {
  allowedSources: Array<"repo" | "file" | "runtime" | "artifact" | "receipt" | "workflow" | "capability">;
  selectedRefs: string[];
  runtimeTruthSource: "daemon-runtime";
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

export interface WorkspaceSubstrateTargetIndex {
  schemaVersion: "ioi.workspace-substrate-target-index.v1";
  indexId: string;
  generatedAtMs: number;
  targets: OperatorInspectionTargetModel[];
  directWebview?: DirectWebviewInspectionTarget | null;
}

export interface WorkspaceSubstrateObservationBundle {
  schemaVersion: "ioi.workspace-substrate-observation-bundle.v1";
  observationId: string;
  targetIndexId: string;
  surfaceRoute: OperatorSurfaceRoute;
  generatedAtMs: number;
  evidenceRefs: OperatorRuntimeEvidenceRefs;
}

export interface WorkspaceSubstrateActionReceipt {
  schemaVersion: "ioi.workspace-substrate-action-receipt.v1";
  receiptId: string;
  targetId: string;
  actionKind: "focus" | "click" | "type" | "open" | "inspect" | "coordinate_fallback";
  locator: SubstrateElementLocator;
  status: "proposed" | "executed" | "blocked" | "failed";
  generatedAtMs: number;
  evidenceRefs: OperatorRuntimeEvidenceRefs;
}

export interface BuildOperatorInspectionTargetModelOptions {
  includeWorkspaceTargets?: boolean;
  includeWorkflowTargets?: boolean;
  includeRunEvidenceTargets?: boolean;
  directWebview?: DirectWebviewInspectionTarget | null;
}

export interface BuildWorkspaceSubstrateTargetIndexOptions
  extends BuildOperatorInspectionTargetModelOptions {
  generatedAtMs?: number;
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
  sessions: "Sessions",
  projects: "Projects",
  missions: "Missions",
  workbench: "Workbench",
  automations: "Automations",
  insights: "Insights",
  agents: "Agents",
  models: "Models",
  privacy: "Privacy",
  providers: "Providers",
  environments: "Environments",
  foundry: "Foundry",
  authority: "Authority",
  receipts: "Receipts",
  settings: "Settings",
};

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

export function getHypervisorSurfaceIdForPrimaryView(
  view: PrimaryView,
): HypervisorSurfaceId {
  return view;
}

function railItemForHypervisorSurface(
  surface: (typeof HYPERVISOR_PRIMARY_SURFACES)[number],
  notificationCount: number,
): OperatorActivityRailItem {
  const route: OperatorSurfaceRoute = {
    kind: "primary-view",
    view: surface.id,
  };

  return {
    id: `surface.${surface.id}`,
    label: surface.label,
    description: surface.description,
    route,
    badgeCount: surface.id === "missions" ? notificationCount : undefined,
    dataWindowSurface: surface.id,
    hypervisorSurfaceId: surface.id,
    surfaceKind: surface.kind,
    routeState: "active_route",
    group: surface.railGroup,
    source: surface.id === "missions" ? "runtime-projection" : "shell-projection",
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
        description: "Search sessions, surfaces, commands, receipts, and workspace context.",
        route: { kind: "command-palette" },
        dataWindowSurface: "search",
        group: "utility",
        routeState: "active_route",
        source: "shell-projection",
      },
      ...HYPERVISOR_PRIMARY_SURFACES.map((surface) =>
        railItemForHypervisorSurface(surface, notificationCount),
      ),
      {
        id: "profile.current",
        label: "Profile",
        description: "Open the operator profile and account preferences.",
        route: { kind: "command-palette", query: "profile" },
        dataWindowSurface: "profile",
        group: "bottom",
        routeState: "active_route",
        source: "shell-projection",
      },
    ],
  };
}

function dataTarget(target: string): SubstrateElementLocator {
  return {
    kind: "data-attribute",
    dataAttribute: "data-inspection-target",
    selector: `[data-inspection-target="${target}"]`,
  };
}

function testIdTarget(testId: string): SubstrateElementLocator {
  return {
    kind: "data-attribute",
    dataAttribute: "data-testid",
    selector: `[data-testid="${testId}"]`,
  };
}

export function buildOperatorInspectionTargetModel({
  includeWorkspaceTargets = true,
  includeWorkflowTargets = true,
  includeRunEvidenceTargets = true,
  directWebview = null,
}: BuildOperatorInspectionTargetModelOptions = {}): OperatorInspectionTargetModel[] {
  const targets: OperatorInspectionTargetModel[] = [
    {
      targetId: "operator.command-center",
      label: "Operator command center",
      surface: "command-center",
      runtimeTruthSource: "daemon-runtime",
      locators: [
        dataTarget("operator-command-center"),
        {
          kind: "data-attribute",
          dataAttribute: "data-operator-command-center",
          selector: "[data-operator-command-center]",
        },
        {
          kind: "aria",
          accessibleName:
            "Search Hypervisor, projects, insights, sessions, and commands",
        },
      ],
    },
    {
      targetId: "operator.activity-rail",
      label: "Operator activity rail",
      surface: "activity-rail",
      runtimeTruthSource: "daemon-runtime",
      locators: [
        dataTarget("operator-activity-rail"),
        {
          kind: "data-attribute",
          dataAttribute: "data-operator-activity-rail",
          selector: "[data-operator-activity-rail]",
        },
        {
          kind: "data-attribute",
          dataAttribute: "data-window-surface",
          selector: "[data-window-surface]",
        },
      ],
    },
  ];

  if (includeWorkspaceTargets) {
    targets.push(
      {
        targetId: "workspace.rail",
        label: "Workspace rail",
        surface: "activity-rail",
        runtimeTruthSource: "daemon-runtime",
        locators: [dataTarget("workspace-rail")],
      },
      {
        targetId: "workspace.explorer",
        label: "Workspace explorer",
        surface: "explorer",
        runtimeTruthSource: "daemon-runtime",
        locators: [
          dataTarget("workspace-explorer"),
          dataTarget("workspace-explorer-row"),
        ],
      },
      {
        targetId: "workspace.editor",
        label: "Workspace editor",
        surface: "editor",
        runtimeTruthSource: "daemon-runtime",
        locators: [
          dataTarget("workspace-editor"),
          dataTarget("workspace-editor-tab"),
          dataTarget("workspace-editor-stage"),
        ],
      },
      {
        targetId: "workspace.terminal",
        label: "Workspace terminal and bottom panel",
        surface: "terminal",
        runtimeTruthSource: "daemon-runtime",
        locators: [dataTarget("workspace-bottom-panel")],
      },
      {
        targetId: "workspace.chat-composer",
        label: "Workspace chat composer",
        surface: "chat-composer",
        runtimeTruthSource: "daemon-runtime",
        locators: [
          dataTarget("workspace-chat-composer"),
          {
            kind: "aria",
            accessibleName: "Submit workspace chat prompt",
          },
        ],
      },
    );
  }

  if (includeWorkflowTargets) {
    targets.push(
      {
        targetId: "workflow.composer",
        label: "Workflow composer",
        surface: "workflow-composer",
        runtimeTruthSource: "daemon-runtime",
        locators: [
          dataTarget("workflow-composer"),
          testIdTarget("workflow-composer"),
        ],
      },
      {
        targetId: "workflow.node",
        label: "Workflow node",
        surface: "workflow-composer",
        runtimeTruthSource: "daemon-runtime",
        locators: [
          dataTarget("workflow-node"),
          {
            kind: "data-attribute",
            dataAttribute: "data-canonical-primitive",
            selector: "[data-canonical-primitive]",
          },
        ],
      },
      {
        targetId: "workflow.palette",
        label: "Workflow palette item",
        surface: "workflow-composer",
        runtimeTruthSource: "daemon-runtime",
        locators: [
          dataTarget("workflow-palette-item"),
          testIdTarget("workflow-node-library-search"),
        ],
      },
    );
  }

  if (includeRunEvidenceTargets) {
    targets.push({
      targetId: "runtime.run-evidence",
      label: "Run and evidence rows",
      surface: "run-evidence",
      runtimeTruthSource: "daemon-runtime",
      locators: [
        dataTarget("workspace-run-row"),
        dataTarget("workflow-run-row"),
        {
          kind: "data-attribute",
          dataAttribute: "data-runtime-evidence-ref",
          selector: "[data-runtime-evidence-ref]",
        },
      ],
    });
  }

  if (directWebview) {
    targets.push({
      targetId: `direct-webview.${directWebview.surfaceId}`,
      label: directWebview.label,
      surface: "direct-webview",
      runtimeTruthSource: "daemon-runtime",
      locators: [
        dataTarget("direct-openvscode-webview"),
        {
          kind: "direct-webview",
          surfaceId: directWebview.surfaceId,
        },
      ],
    });
  }

  return targets;
}

export function buildWorkspaceSubstrateTargetIndex({
  generatedAtMs = Date.now(),
  ...options
}: BuildWorkspaceSubstrateTargetIndexOptions = {}): WorkspaceSubstrateTargetIndex {
  return {
    schemaVersion: "ioi.workspace-substrate-target-index.v1",
    indexId: `workspace-substrate-target-index:${generatedAtMs}`,
    generatedAtMs,
    directWebview: options.directWebview ?? null,
    targets: buildOperatorInspectionTargetModel(options),
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
    activeView === "automations" && workflowSurface !== "home"
      ? `${PRIMARY_VIEW_LABELS.automations}: ${workflowSurface}`
      : PRIMARY_VIEW_LABELS[activeView];
  const commands: OperatorCommandCenterCommand[] = [
    ...HYPERVISOR_PRIMARY_SURFACES.map((surface) =>
      primaryViewCommand(surface.id),
    ),
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
      route: { kind: "primary-view", view: "receipts" },
      keywords: ["receipt", "artifact", "evidence", "trace", "run"],
      source: "runtime-projection",
    },
  ];

  if (notificationCount > 0) {
    commands.push({
      id: "inbox.pending",
      label: `Open Inbox (${notificationCount})`,
      description: "Review pending approvals, prompts, and interventions.",
      route: { kind: "primary-view", view: "missions" },
      keywords: ["inbox", "approval", "notification", "pending"],
      source: "runtime-projection",
    });
  }

  return {
    projectionId: `operator-command-center:${activeView}:${workflowSurface}:${currentProject.id}`,
    activeRoute: { kind: "primary-view", view: activeView },
    scopeLabel: `${currentProject.name} / ${surfaceLabel}`,
    placeholder:
      "Search Hypervisor, projects, insights, sessions, and commands",
    shortcutLabel: "Ctrl+K",
    runtimeTruthSource: "daemon-runtime",
    evidenceRefs: {
      ...EMPTY_EVIDENCE_REFS,
      ...mergedEvidenceRefs,
    },
    commands,
  };
}
