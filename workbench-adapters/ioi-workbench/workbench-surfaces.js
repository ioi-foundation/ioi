const VIEW_DEFINITIONS = [
  {
    id: "ioi.chat",
    title: "Chat",
    eyebrow: "Outcome control plane",
    description:
      "Use Chat as a native workbench surface for code-aware prompting, patch review, and outcome shaping.",
    actions: [
      {
        label: "Review current file",
        command: "ioi.chat.reviewFile",
      },
      {
        label: "Explain selected code",
        command: "ioi.chat.explainSelection",
      },
    ],
  },
  {
    id: "ioi.overviewActivity",
    title: "Overview",
    eyebrow: "Hypervisor Home",
    description:
      "Open the IDE-native operator console for Build, Run, Govern, and Verify.",
    actions: [],
  },
  {
    id: "ioi.studio",
    title: "Studio",
    eyebrow: "Agent Studio",
    description:
      "Open the build surface for agents, workflows, model routes, and connector-safe applications.",
    actions: [],
  },
  {
    id: "ioi.workflows",
    title: "Workflows",
    eyebrow: "Agent orchestration",
    description:
      "Open the rich IDE-grade workflow compositor without an intermediate launcher pane.",
    actions: [],
  },
  {
    id: "ioi.models",
    title: "Models",
    eyebrow: "Daemon model runtime",
    description:
      "Mount, load, inspect, and bind local model routes through the IOI daemon.",
    actions: [
      {
        label: "Open Models mode",
        command: "ioi.models.open",
      },
      {
        label: "Estimate native load",
        command: "ioi.models.estimateNative",
      },
      {
        label: "Load native model",
        command: "ioi.models.loadNative",
      },
      {
        label: "Open workflow binding",
        command: "ioi.workflow.openComposer",
        payload: {
          scenarioId: "model-backed-dry-run",
          phase: "model-binding",
        },
      },
    ],
  },
  {
    id: "ioi.runs",
    title: "Runs",
    eyebrow: "Runtime evidence",
    description:
      "Track active runs, surface receipts, and jump back to impacted files and artifacts.",
    actions: [
      {
        label: "Open runs surface",
        command: "ioi.runs.refresh",
      },
      {
        label: "Review latest run in Chat",
        command: "ioi.runs.review",
      },
      {
        label: "Run browser remediation",
        command: "ioi.automation.browser",
      },
      {
        label: "Open terminal",
        command: "workbench.action.terminal.toggleTerminal",
      },
      {
        label: "Open output",
        command: "workbench.action.output.toggleOutput",
      },
    ],
  },
  {
    id: "ioi.runsActivity",
    title: "Runs",
    eyebrow: "Runtime evidence",
    description:
      "Open the persistent execution timeline and receipt surface directly.",
    actions: [],
  },
  {
    id: "ioi.artifacts",
    title: "Artifacts",
    eyebrow: "Evidence and receipts",
    description:
      "Inspect generated artifacts, provenance, and receipt-linked surfaces as a first-class workbench concern.",
    actions: [
      {
        label: "Open evidence session",
        command: "ioi.artifacts.openEvidence",
      },
      {
        label: "Review latest artifact in Chat",
        command: "ioi.artifacts.review",
      },
      {
        label: "Open connector policy",
        command: "ioi.artifacts.openPolicy",
      },
      {
        label: "Review current file",
        command: "ioi.chat.reviewFile",
      },
      {
        label: "Open explorer",
        command: "workbench.view.explorer",
      },
      {
        label: "Reveal outline",
        command: "outline.focus",
      },
    ],
  },
  {
    id: "ioi.policy",
    title: "Policy",
    eyebrow: "Governed execution",
    description:
      "Keep approvals, authority, and policy context visible while acting from the workspace.",
    actions: [
      {
        label: "Open policy context",
        command: "ioi.policy.open",
      },
      {
        label: "Show problems",
        command: "workbench.actions.view.problems",
      },
      {
        label: "Open settings",
        command: "workbench.action.openSettings",
      },
    ],
  },
  {
    id: "ioi.policyActivity",
    title: "Policy",
    eyebrow: "Governed execution",
    description:
      "Open the persistent approvals, policy, and authority surface directly.",
    actions: [],
  },
  {
    id: "ioi.connections",
    title: "Connections",
    eyebrow: "Services and integrations",
    description:
      "Inspect available services, runtime bindings, and connection posture from inside the workspace.",
    actions: [
      {
        label: "Open connections surface",
        command: "ioi.connections.inspect",
      },
      {
        label: "Open connector overview",
        command: "ioi.connections.openConnector",
      },
      {
        label: "Show source control",
        command: "workbench.view.scm",
      },
      {
        label: "Open extensions",
        command: "workbench.view.extensions",
      },
    ],
  },
  {
    id: "ioi.connectorsActivity",
    title: "Connectors",
    eyebrow: "Services and integrations",
    description:
      "Open the persistent connector posture and dry-run binding surface directly.",
    actions: [],
  },
  {
    id: "ioi.codeActivity",
    title: "Code",
    eyebrow: "IDE substrate",
    description:
      "Drill into the VS Code substrate: files, search, source control, run/debug, extensions, and terminal tooling.",
    actions: [],
  },
];

const HYPERVISOR_MODES = [
  {
    id: "home",
    title: "Home",
    viewId: "ioi.overviewActivity",
    panelViewType: "ioi.overview",
    command: "ioi.overview.open",
    activityContainer: "ioi-overview",
    phase: "home",
  },
  {
    id: "studio",
    title: "Studio",
    viewId: "ioi.studio",
    panelViewType: "ioi.studio",
    command: "ioi.studio.open",
    activityContainer: "ioi-studio",
    phase: "landing",
  },
  {
    id: "workflows",
    title: "Workflows",
    viewId: "ioi.workflows",
    panelViewType: "ioi.workflowComposer",
    command: "ioi.workflow.openComposer",
    activityContainer: "ioi-workflows",
    phase: "canvas",
  },
  {
    id: "models",
    title: "Models",
    viewId: "ioi.models",
    panelViewType: "ioi.models",
    command: "ioi.models.open",
    activityContainer: "ioi-models",
    phase: "model-library",
  },
  {
    id: "runs",
    title: "Runs",
    viewId: "ioi.runsActivity",
    panelViewId: "ioi.runs",
    panelViewType: "ioi.runsMode",
    command: "ioi.runs.refresh",
    activityContainer: "ioi-runs",
    phase: "timeline",
  },
  {
    id: "policy",
    title: "Policy",
    viewId: "ioi.policyActivity",
    panelViewId: "ioi.policy",
    panelViewType: "ioi.policyMode",
    command: "ioi.policy.open",
    activityContainer: "ioi-policy",
    phase: "approvals",
  },
  {
    id: "connectors",
    title: "Connectors",
    viewId: "ioi.connectorsActivity",
    panelViewId: "ioi.connections",
    panelViewType: "ioi.connectorsMode",
    command: "ioi.connections.inspect",
    activityContainer: "ioi-connectors",
    phase: "posture",
  },
  {
    id: "code",
    title: "Code",
    viewId: "ioi.codeActivity",
    panelViewType: "ioi.codeMode",
    command: "ioi.code.open",
    activityContainer: "ioi-code",
    phase: "substrate",
  },
];

const HYPERVISOR_MODE_BY_ID = Object.fromEntries(
  HYPERVISOR_MODES.map((mode) => [mode.id, mode]),
);
const HYPERVISOR_MODE_BY_VIEW_ID = Object.fromEntries(
  HYPERVISOR_MODES.map((mode) => [mode.viewId, mode]),
);
const HYPERVISOR_MODE_BY_PANEL_VIEW_ID = Object.fromEntries(
  HYPERVISOR_MODES
    .filter((mode) => mode.panelViewId)
    .map((mode) => [mode.panelViewId, mode]),
);

module.exports = {
  HYPERVISOR_MODE_BY_ID,
  HYPERVISOR_MODE_BY_PANEL_VIEW_ID,
  HYPERVISOR_MODE_BY_VIEW_ID,
  HYPERVISOR_MODES,
  VIEW_DEFINITIONS,
};
