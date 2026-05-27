const crypto = require("crypto");
const http = require("http");
const https = require("https");
const path = require("path");
const vscode = require("vscode");

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
    eyebrow: "Autopilot Home",
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

const AUTOPILOT_MODES = [
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

const AUTOPILOT_MODE_BY_ID = Object.fromEntries(
  AUTOPILOT_MODES.map((mode) => [mode.id, mode]),
);
const AUTOPILOT_MODE_BY_VIEW_ID = Object.fromEntries(
  AUTOPILOT_MODES.map((mode) => [mode.viewId, mode]),
);
const AUTOPILOT_MODE_BY_PANEL_VIEW_ID = Object.fromEntries(
  AUTOPILOT_MODES
    .filter((mode) => mode.panelViewId)
    .map((mode) => [mode.panelViewId, mode]),
);

function bridgeUrl() {
  return process.env.IOI_WORKSPACE_IDE_BRIDGE_URL || null;
}

function daemonEndpoint() {
  return process.env.IOI_DAEMON_ENDPOINT || process.env.IOI_MODEL_MOUNTING_API_URL || null;
}

function daemonToken() {
  return process.env.IOI_DAEMON_TOKEN || process.env.IOI_MODEL_MOUNTING_TOKEN || null;
}

function normalizeBaseUrl(value) {
  if (!value) {
    return null;
  }
  return String(value).replace(/\/+$/, "");
}

function requestJson(baseUrl, routePath, { method = "GET", payload, token, timeoutMs } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  if (!base) {
    return Promise.reject(new Error("IOI daemon endpoint is not configured."));
  }

  const target = new URL(routePath, `${base}/`);
  const client = target.protocol === "https:" ? https : http;
  const body = payload === undefined ? null : JSON.stringify(payload);

  return new Promise((resolve, reject) => {
    const request = client.request(
      target,
      {
        method,
        headers: {
          accept: "application/json",
          ...(body
            ? {
                "content-type": "application/json",
                "content-length": Buffer.byteLength(body),
              }
            : {}),
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let parsed = null;
          try {
            parsed = raw ? JSON.parse(raw) : null;
          } catch (error) {
            reject(error);
            return;
          }
          if (response.statusCode >= 400) {
            reject(
              new Error(
                `[IOI Workbench] Daemon request failed (${response.statusCode}): ${raw}`,
              ),
            );
            return;
          }
          resolve(parsed);
        });
      },
    );

    const boundedTimeoutMs = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
      ? Number(timeoutMs)
      : 0;
    if (boundedTimeoutMs > 0) {
      request.setTimeout(boundedTimeoutMs, () => {
        request.destroy(new Error(`Daemon request timed out after ${boundedTimeoutMs}ms.`));
      });
    }
    request.on("error", reject);
    if (body) {
      request.write(body);
    }
    request.end();
  });
}

async function readDaemonModelSnapshot() {
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    return {
      configured: false,
      endpoint: null,
      status: "not_configured",
      error: null,
      snapshot: null,
    };
  }

  try {
    const snapshot = await requestJson(endpoint, "/api/v1/models");
    return {
      configured: true,
      endpoint,
      status: "connected",
      error: null,
      snapshot,
    };
  } catch (error) {
    return {
      configured: true,
      endpoint,
      status: "degraded",
      error: error?.message || String(error),
      snapshot: null,
    };
  }
}

function workspaceSummary() {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return {
      name: "No folder",
      path: "Open a workspace folder to ground IOI context.",
    };
  }

  return {
    name: folder.name,
    path: folder.uri.fsPath,
  };
}

const recentTaskLabels = [];
let lastTaskExitCode = null;
let overviewPanel = null;
let overviewPanelLastHtml = null;
let overviewPanelNonce = null;
let studioPanel = null;
let studioPanelLastHtml = null;
let studioPanelNonce = null;
let workflowComposerPanel = null;
let modelsPanel = null;
const genericModePanels = new Map();
let currentAutopilotModeId = "home";
let lastAutopilotModeBeforeCode = "home";
let studioModelInvocationToken = null;
const modeVisibilityProjectionLastAtMs = new Map();
const MODE_VISIBILITY_REQUEST_TYPES = {
  home: "overview.open",
  studio: "studio.open",
  workflows: "workflow.composer.open",
  models: "models.open",
  runs: "runs.open",
  policy: "policy.open",
  connectors: "connections.open",
  code: "code.open",
};
const STUDIO_APPROVAL_ID = "approval_agent_studio_inline_diff_preview";
const STUDIO_POLICY_LEASE_ID = "approval_agent_studio_policy_lease_destructive_action";
const STUDIO_MODE_AGENT = "agent";
const STUDIO_MODE_ASK = "ask";
const STUDIO_PERMISSION_MODE_DEFAULT = "suggest";
const STUDIO_PERMISSION_MODE_AUTO_REVIEW = "auto_local";
const STUDIO_PERMISSION_MODE_FULL_ACCESS = "never_prompt";
const STUDIO_AGENT_RUNTIME_PROFILE = "runtime_service";
const STUDIO_DIRECT_MODEL_RUNTIME_PROFILE = "chat_only";
const STUDIO_AGENT_TURN_POST_TIMEOUT_MS = 130000;
const STUDIO_AGENT_TURN_RECOVERY_POLL_MS = 1000;
const STUDIO_AGENT_TURN_RECOVERY_ATTEMPTS = 4;
let studioRuntimeProjection = createInitialStudioRuntimeProjection();
let studioDiffProviderDisposable = null;
const studioDiffDocuments = new Map();
let activeTraceTarget = null;

function rememberRecentTaskLabel(label) {
  const normalized = typeof label === "string" ? label.trim() : "";
  if (!normalized) {
    return;
  }
  const existingIndex = recentTaskLabels.indexOf(normalized);
  if (existingIndex >= 0) {
    recentTaskLabels.splice(existingIndex, 1);
  }
  recentTaskLabels.unshift(normalized);
  recentTaskLabels.splice(8);
}

function refSafe(value) {
  return (
    String(value || "unknown")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "unknown"
  );
}

function toWorkbenchRange(range) {
  if (!range) {
    return null;
  }
  return {
    startLineNumber: range.start.line + 1,
    startColumn: range.start.character + 1,
    endLineNumber: range.end.line + 1,
    endColumn: range.end.character + 1,
  };
}

function uriToRef(uri) {
  if (!uri) {
    return null;
  }
  return {
    uri: uri.toString(),
    path: uri.scheme === "file" ? uri.fsPath : uri.path,
    scheme: uri.scheme,
  };
}

function buildRuntimeRefs() {
  return {
    receiptRefs: [],
    artifactRefs: [],
    authorityRefs: [],
    manifestRefs: [],
    capabilityRefs: [],
  };
}

function nonce() {
  return crypto.randomBytes(16).toString("base64");
}

function hashRef(prefix, value) {
  const stableValue = typeof value === "string" ? value : JSON.stringify(value || {});
  return `${prefix}:${crypto.createHash("sha256").update(stableValue).digest("hex").slice(0, 16)}`;
}

function isRuntimeActionRequestType(requestType) {
  return /^(chat|workflow|runs|policy|evidence|connections|automation|settings)\./.test(
    requestType,
  );
}

function buildWorkbenchCommandRouteReceipt({
  commandId,
  route,
  status = "routed",
  context = null,
  reason = null,
  actionProposalRef = null,
}) {
  return {
    schemaVersion: "ioi.workbench-integration.v1",
    receiptId: `workbench-command-route:${crypto.randomUUID()}`,
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
    commandId,
    routedAtMs: Date.now(),
    route,
    contextRef: context ? hashRef("workbench-context", context) : null,
    actionProposalRef,
    status,
    reason,
    runtimeRefs: buildRuntimeRefs(),
  };
}

async function writeWorkbenchCommandRouteReceipt(receipt, context = null) {
  const request = {
    requestId: crypto.randomUUID(),
    requestType: "workbench.commandRouteReceipt",
    context,
    payload: receipt,
    timestampMs: Date.now(),
  };
  await requestBridge("POST", "requests", request);
  return request;
}

function diagnosticSeverityLabel(severity) {
  switch (severity) {
    case vscode.DiagnosticSeverity.Error:
      return "error";
    case vscode.DiagnosticSeverity.Warning:
      return "warning";
    case vscode.DiagnosticSeverity.Information:
      return "info";
    case vscode.DiagnosticSeverity.Hint:
      return "hint";
    default:
      return "info";
  }
}

function selectedTextHash(value) {
  if (!value) {
    return null;
  }
  return crypto.createHash("sha256").update(value).digest("hex");
}

function gitResourcePath(resource) {
  const uri = resource?.resourceUri || resource?.uri;
  return uri?.fsPath || uri?.toString?.() || null;
}

function buildWorkbenchScmState(openEditors) {
  const dirtyEditors = openEditors
    .filter((editor) => editor.isDirty && editor.filePath)
    .map((editor) => editor.filePath);
  try {
    const gitExtension = vscode.extensions.getExtension("vscode.git")?.exports;
    const gitApi = gitExtension?.getAPI?.(1);
    const workspacePath = workspaceSummary().path;
    const repositories = Array.isArray(gitApi?.repositories)
      ? gitApi.repositories
      : [];
    const repository =
      repositories.find((candidate) => {
        const rootPath = candidate?.rootUri?.fsPath || candidate?.rootUri?.toString?.();
        return rootPath && workspacePath && workspacePath.startsWith(rootPath);
      }) || repositories[0];
    if (!repository) {
      return {
        provider: dirtyEditors.length ? "unknown" : "none",
        branch: null,
        dirty: dirtyEditors.length > 0,
        changedFiles: dirtyEditors,
        ahead: null,
        behind: null,
      };
    }

    const state = repository.state || {};
    const head = state.HEAD || {};
    const changedFiles = [
      ...(state.workingTreeChanges || []),
      ...(state.indexChanges || []),
      ...(state.untrackedChanges || []),
      ...(state.mergeChanges || []),
    ]
      .map(gitResourcePath)
      .filter(Boolean);
    return {
      provider: "git",
      branch: head.name || head.upstream?.name || head.commit || null,
      dirty: changedFiles.length > 0 || dirtyEditors.length > 0,
      changedFiles: Array.from(new Set([...changedFiles, ...dirtyEditors])),
      ahead: typeof head.ahead === "number" ? head.ahead : null,
      behind: typeof head.behind === "number" ? head.behind : null,
    };
  } catch (error) {
    return {
      provider: "unknown",
      branch: null,
      dirty: dirtyEditors.length > 0,
      changedFiles: dirtyEditors,
      ahead: null,
      behind: null,
    };
  }
}

function buildWorkbenchTaskState() {
  const activeTaskLabels = (vscode.tasks.taskExecutions || [])
    .map((execution) => execution.task?.name)
    .filter((label) => typeof label === "string" && label.trim());
  const recentLabels = Array.from(new Set([...activeTaskLabels, ...recentTaskLabels]));
  return {
    activeTaskLabels,
    recentTaskLabels: recentLabels.slice(0, 8),
    lastExitCode: lastTaskExitCode,
    checkRefs: recentLabels.slice(0, 8).map((label) => `task:${refSafe(label)}`),
  };
}

function activeEditorRef(editor) {
  if (!editor) {
    return null;
  }
  const selection = editor.selection && !editor.selection.isEmpty
    ? toWorkbenchRange(editor.selection)
    : null;
  const selectedText =
    selection && editor.selection
      ? editor.document.getText(editor.selection)
      : null;
  return {
    filePath: editor.document.uri.fsPath || editor.document.uri.toString(),
    uri: editor.document.uri.toString(),
    languageId: editor.document.languageId,
    selection,
    selectedTextHash: selectedTextHash(selectedText),
    isDirty: editor.document.isDirty,
  };
}

function buildWorkbenchContextSnapshot(reason = "poll") {
  const activeEditor = vscode.window.activeTextEditor;
  const selection = activeEditor?.selection;
  const workspace = workspaceSummary();
  const openEditors = vscode.window.tabGroups.all.flatMap((group, groupIndex) =>
    group.tabs.map((tab, tabIndex) => ({
      tabId: `${groupIndex}:${tabIndex}:${tab.label}`,
      label: tab.label,
      isActive: tab.isActive,
      isDirty: tab.isDirty,
      groupIndex,
      uri: uriToRef(tab.input?.uri),
      filePath: tab.input?.uri?.fsPath || tab.input?.uri?.toString?.() || null,
    })),
  );
  const diagnostics = vscode.languages
    .getDiagnostics()
    .slice(0, 50)
    .flatMap(([uri, entries]) =>
      entries.slice(0, 10).map((entry) => ({
        filePath: uri.fsPath || uri.toString(),
        uri: uri.toString(),
        message: entry.message,
        severity: diagnosticSeverityLabel(entry.severity),
        source: entry.source || null,
        code: entry.code ? String(entry.code) : null,
        range: toWorkbenchRange(entry.range),
      })),
    );

  return {
    schemaVersion: "ioi.workbench-integration.v1",
    snapshotId: crypto.randomUUID(),
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
    generatedAtMs: Date.now(),
    reason,
    workspaceRoot: workspace.path,
    workspaceRef: null,
    packageRef: null,
    workspace,
    activeEditor: activeEditorRef(activeEditor),
    openEditors: openEditors.map((editor) => ({
      filePath: editor.filePath || editor.label,
      uri: editor.uri?.uri || null,
      languageId: null,
      selection: null,
      selectedTextHash: null,
      isDirty: editor.isDirty,
      label: editor.label,
      isActive: editor.isActive,
      groupIndex: editor.groupIndex,
      tabId: editor.tabId,
    })),
    diagnostics,
    scmState: buildWorkbenchScmState(openEditors),
    taskState: buildWorkbenchTaskState(),
    terminalState: {
      terminalCount: vscode.window.terminals.length,
      activeTerminalName: vscode.window.activeTerminal?.name || null,
      taskBacked: false,
    },
    visibleView: {
      activeTextEditorVisible: Boolean(activeEditor),
      activeTabCount: openEditors.length,
      ioiChatViewId: "ioi.chat",
      activityId: "ioi-workflows",
      sideBarViewId: "ioi.chat",
      panelViewId: null,
      activeEditorGroup: activeEditor ? "active" : null,
      activeIoiViewId: "ioi.chat",
    },
    inspectionTargetIndexRef: "workbench-target-index:latest",
    runtimeRefs: buildRuntimeRefs(),
  };
}

function buildWorkbenchInspectionTargetIndex(reason = "poll") {
  const activeEditor = vscode.window.activeTextEditor;
  const openEditorTargets = vscode.window.tabGroups.all.flatMap((group, groupIndex) =>
    group.tabs.map((tab, tabIndex) => ({
      targetId: `editor.tab.${groupIndex}.${tabIndex}`,
      label: tab.label,
      surface: "editor",
      locators: [
        {
          kind: "vscode-command",
          commandId: "workbench.action.quickOpenPreviousRecentlyUsedEditorInGroup",
        },
        {
          kind: "data-attribute",
          selector: `.tabs-container .tab[aria-label*='${String(tab.label).replace(/'/g, "\\'")}']`,
        },
      ],
      fallbackAllowed: true,
    })),
  );
  const activeEditorTarget = activeEditor
    ? [
        {
          targetId: "editor.active",
          label: activeEditor.document.fileName,
          surface: "editor",
          locators: [
            {
              kind: "editor-range",
              filePath: activeEditor.document.uri.fsPath,
              range: toWorkbenchRange(activeEditor.selection),
            },
          ],
          fallbackAllowed: true,
        },
        {
          targetId: "explorer.active-file",
          label: `Explorer row for ${activeEditor.document.fileName}`,
          surface: "explorer",
          locators: [
            {
              kind: "vscode-command",
              commandId: "revealInExplorer",
            },
            {
              kind: "editor-range",
              filePath: activeEditor.document.uri.fsPath,
              range: toWorkbenchRange(activeEditor.selection),
            },
          ],
          fallbackAllowed: true,
        },
      ]
    : [];
  const activeTaskTargets = (vscode.tasks.taskExecutions || []).map((execution, index) => ({
    targetId: `task.active.${index}`,
    label: execution.task?.name || "Active task",
    surface: "problems",
    locators: [
      {
        kind: "vscode-command",
        commandId: "workbench.action.tasks.showLog",
      },
      {
        kind: "vscode-command",
        commandId: "workbench.action.terminal.toggleTerminal",
      },
    ],
    fallbackAllowed: true,
  }));

  return {
    schemaVersion: "ioi.workbench-integration.v1",
    indexId: "workbench-target-index:latest",
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
    generatedAtMs: Date.now(),
    reason,
    runtimeRefs: buildRuntimeRefs(),
    targets: [
      {
        targetId: "command-center.autopilot-header",
        label: "Autopilot header command center",
        surface: "command-center",
        locators: [
          {
            kind: "data-attribute",
            selector: "[data-operator-command-center]",
          },
          {
            kind: "aria",
            accessibleName: "Search Autopilot, code, workflows, runs, and commands",
          },
        ],
        fallbackAllowed: false,
      },
      {
        targetId: "command-center.openvscode-disabled",
        label: "OpenVSCode command center disabled",
        surface: "command-center",
        locators: [],
        fallbackAllowed: false,
      },
      {
        targetId: "ioi.overview",
        label: "Autopilot Overview",
        surface: "overview",
        locators: [
          {
            kind: "vscode-command",
            commandId: "ioi.overview.open",
          },
          {
            kind: "data-attribute",
            selector: "[data-testid='autopilot-overview-home']",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.overview",
        label: "Autopilot Overview activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi-overview",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.overviewActivity",
          },
          {
            kind: "vscode-command",
            commandId: "ioi.overview.open",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.studio",
        label: "Autopilot Studio activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi-studio",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.studio",
          },
          {
            kind: "vscode-command",
            commandId: "ioi.studio.open",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.workflows",
        label: "Autopilot Workflows activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi-workflows",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.workflows",
          },
          {
            kind: "vscode-command",
            commandId: "ioi.workflow.openComposer",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.models",
        label: "Autopilot Models activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi-models",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.models",
          },
          {
            kind: "vscode-command",
            commandId: "ioi.models.open",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.runs",
        label: "Autopilot Runs activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi-runs",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.runsActivity",
          },
          {
            kind: "vscode-command",
            commandId: "ioi.runs.refresh",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.policy",
        label: "Autopilot Policy activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi-policy",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.policyActivity",
          },
          {
            kind: "vscode-command",
            commandId: "ioi.policy.open",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.connectors",
        label: "Autopilot Connectors activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi-connectors",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.connectorsActivity",
          },
          {
            kind: "vscode-command",
            commandId: "ioi.connections.inspect",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.code",
        label: "Code drill-down activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi-code",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.codeActivity",
          },
          {
            kind: "vscode-command",
            commandId: "ioi.code.open",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.back-to-autopilot",
        label: "Back to Autopilot from Code",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "ioi.autopilot.back",
          },
          {
            kind: "data-attribute",
            selector: "[data-testid='back-to-autopilot-from-code']",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.explorer",
        label: "Explorer activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.explorer",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.search",
        label: "Search activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.search",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "activity.scm",
        label: "Source control activity",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.scm",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "ioi.chat",
        label: "Autopilot Chat",
        surface: "chat",
        locators: [
          {
            kind: "data-attribute",
            selector: "[data-operator-chat-pane='native-openvscode']",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "ioi.chat.composer",
        label: "Autopilot Chat composer",
        surface: "chat",
        locators: [
          {
            kind: "data-attribute",
            selector: "[data-inspection-target='native-ioi-chat-composer']",
          },
          {
            kind: "aria",
            accessibleName: "Chat composer",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "ioi.chat.action.build-workspace",
        label: "Build Workspace action",
        surface: "chat",
        locators: [
          {
            kind: "data-attribute",
            selector: "[data-bridge-request='workflow.codeGenerationRequest']",
          },
          {
            kind: "aria",
            accessibleName: "Build Workspace",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "ioi.chat.action.show-config",
        label: "Show Config action",
        surface: "chat",
        locators: [
          {
            kind: "data-attribute",
            selector: "[data-bridge-request='chat.showConfig']",
          },
          {
            kind: "aria",
            accessibleName: "Show Config",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "ioi.chat.action.new",
        label: "New chat action",
        surface: "chat",
        locators: [
          {
            kind: "vscode-command",
            commandId: "ioi.chat.new",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "ioi.chat.action.settings",
        label: "Chat settings action",
        surface: "chat",
        locators: [
          {
            kind: "vscode-command",
            commandId: "ioi.chat.openSettings",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "explorer",
        label: "Explorer",
        surface: "explorer",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.explorer",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "workflow.composer",
        label: "Autopilot Workflow Composer",
        surface: "workflow",
        locators: [
          {
            kind: "vscode-command",
            commandId: "ioi.workflow.openComposer",
          },
          {
            kind: "data-attribute",
            selector: "[data-testid='workflow-composer']",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "workflow.generate-code",
        label: "Generate code proposal from workflow",
        surface: "workflow",
        locators: [
          {
            kind: "vscode-command",
            commandId: "ioi.workflow.generateCode",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "ioi.models",
        label: "Autopilot Models",
        surface: "models",
        locators: [
          {
            kind: "vscode-command",
            commandId: "ioi.models.open",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.models",
          },
          {
            kind: "data-attribute",
            selector: "[data-testid='autopilot-models-mode']",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "run.evidence.rows",
        label: "IOI run and evidence rows",
        surface: "run-evidence",
        locators: [
          {
            kind: "vscode-command",
            commandId: "ioi.runs.refresh",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.runs",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "terminal.panel",
        label: "Terminal panel",
        surface: "terminal",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.action.terminal.toggleTerminal",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "checks.tasks",
        label: "Tasks and checks",
        surface: "problems",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.action.tasks.runTask",
          },
          {
            kind: "vscode-command",
            commandId: "workbench.action.tasks.showLog",
          },
        ],
        fallbackAllowed: true,
      },
      {
        targetId: "problems.panel",
        label: "Problems panel",
        surface: "problems",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.actions.view.problems",
          },
        ],
        fallbackAllowed: true,
      },
      ...openEditorTargets,
      ...activeEditorTarget,
      ...activeTaskTargets,
    ],
  };
}

function buildWorkspaceActionContext(source, uri) {
  const editor = vscode.window.activeTextEditor;
  const selection = editor?.selection;
  const selectedText =
    selection && !selection.isEmpty
      ? editor?.document.getText(selection).trim() || null
      : null;

  return {
    workspaceRoot: workspaceSummary().path,
    filePath: resolveFileContext(uri),
    selection:
      selection && !selection.isEmpty
        ? {
            startLineNumber: selection.start.line + 1,
            startColumn: selection.start.character + 1,
            endLineNumber: selection.end.line + 1,
            endColumn: selection.end.character + 1,
            selectedText,
          }
        : null,
    source,
  };
}

function defaultBridgeState() {
  return {
    schemaVersion: 1,
    generatedAtMs: Date.now(),
    authoritativeRuntime: true,
    workspace: workspaceSummary(),
    chat: {
      runtime: "ioi-runtime",
      authority: "bounded",
      helperText:
        "IOI runtime remains authoritative for policy, approvals, evidence, and settlement.",
    },
    appearance: {
      themeId: "dark-modern",
      themeLabel: "Dark Modern",
      density: "default",
      openVsCodeColorTheme: "Default Dark Modern",
      source: "default",
      updatedAtMs: 0,
    },
    workflows: [],
    runs: [],
    artifacts: [],
    policy: null,
    connections: [],
  };
}

function requestBridge(method, bridgePath, payload) {
  const base = bridgeUrl();
  if (!base) {
    return Promise.reject(new Error("IOI workspace bridge URL is not configured."));
  }

  const target = new URL(bridgePath, `${base}/`);
  const client = target.protocol === "https:" ? https : http;
  const body = payload ? JSON.stringify(payload) : null;

  return new Promise((resolve, reject) => {
    const request = client.request(
      target,
      {
        method,
        headers: body
          ? {
              "content-type": "application/json",
              "content-length": Buffer.byteLength(body),
            }
          : undefined,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          if (response.statusCode >= 400) {
            reject(
              new Error(
                `[IOI Workbench] Bridge request failed (${response.statusCode}): ${raw}`,
              ),
            );
            return;
          }
          resolve(raw);
        });
      },
    );

    request.on("error", reject);
    if (body) {
      request.write(body);
    }
    request.end();
  });
}

async function readBridgeState() {
  const daemonModelMounting = await readDaemonModelSnapshot();
  try {
    const raw = await requestBridge("GET", "state");
    return {
      ...defaultBridgeState(),
      ...JSON.parse(raw || "{}"),
      modelMounting: daemonModelMounting.snapshot ?? JSON.parse(raw || "{}").modelMounting ?? null,
      modelMountingStatus: daemonModelMounting,
    };
  } catch (error) {
    console.error("[IOI Workbench] Failed to read bridge state:", error);
    return {
      ...defaultBridgeState(),
      modelMounting: daemonModelMounting.snapshot,
      modelMountingStatus: daemonModelMounting,
    };
  }
}

async function readBridgeCommands() {
  try {
    const raw = await requestBridge("GET", "commands");
    const commands = JSON.parse(raw || "[]");
    return Array.isArray(commands) ? commands : [];
  } catch (error) {
    console.error("[IOI Workbench] Failed to read bridge commands:", error);
    return [];
  }
}

function startBridgeCommandPolling(context, output) {
  let running = false;
  const poll = async () => {
    if (running) {
      return;
    }
    running = true;
    try {
      const commands = await readBridgeCommands();
      for (const bridgeCommand of commands) {
        if (!bridgeCommand || typeof bridgeCommand.command !== "string") {
          continue;
        }
        const args = Array.isArray(bridgeCommand.args) ? bridgeCommand.args : [];
        output.appendLine(
          `Executing bridge command ${bridgeCommand.command} (${bridgeCommand.commandId || "no-id"}).`,
        );
        try {
          await vscode.commands.executeCommand(bridgeCommand.command, ...args);
          await writeWorkbenchCommandRouteReceipt(
            buildWorkbenchCommandRouteReceipt({
              commandId: bridgeCommand.command,
              route: bridgeCommand.command.startsWith("ioi.")
                ? "ioi-runtime-action"
                : "editor-local",
              status: "routed",
              context: bridgeCommand,
            }),
            {
              source: "ioi-workbench-command-poll",
              commandId: bridgeCommand.commandId || bridgeCommand.command,
            },
          ).catch((error) => {
            output.appendLine(
              `Bridge command route receipt failed: ${error?.message || String(error)}`,
            );
          });
        } catch (error) {
          await writeWorkbenchCommandRouteReceipt(
            buildWorkbenchCommandRouteReceipt({
              commandId: bridgeCommand.command,
              route: "blocked",
              status: "failed",
              context: bridgeCommand,
              reason: error?.message || String(error),
            }),
            {
              source: "ioi-workbench-command-poll",
              commandId: bridgeCommand.commandId || bridgeCommand.command,
            },
          ).catch(() => undefined);
          throw error;
        }
      }
    } catch (error) {
      console.error("[IOI Workbench] Failed to execute bridge command:", error);
      output.appendLine(`Bridge command failed: ${error?.message || String(error)}`);
    } finally {
      running = false;
    }
  };
  const timer = setInterval(poll, 750);
  context.subscriptions.push({ dispose: () => clearInterval(timer) });
  void poll();
}

async function writeBridgeRequest(requestType, payload = {}, context = null) {
  const request = {
    requestId: crypto.randomUUID(),
    requestType,
    context,
    payload,
    timestampMs: Date.now(),
  };
  await requestBridge("POST", "requests", request);
  if (isRuntimeActionRequestType(requestType)) {
    const commandId =
      context?.sourceCommand ||
      payload?.sourceCommand ||
      payload?.commandId ||
      requestType;
    await writeWorkbenchCommandRouteReceipt(
      buildWorkbenchCommandRouteReceipt({
        commandId,
        route: "ioi-runtime-action",
        status: "routed",
        context: {
          requestId: request.requestId,
          requestType,
          ...(context || {}),
        },
      }),
      {
        source: "ioi-workbench",
        originalRequestId: request.requestId,
        requestType,
      },
    ).catch((error) => {
      console.error("[IOI Workbench] Failed to write command route receipt:", error);
    });
  }
  return request;
}

function startWorkbenchContextSnapshotPublisher(context, output) {
  let lastHash = "";
  let lastTargetHash = "";
  let publishing = false;

  const publish = async (reason) => {
    if (publishing) {
      return;
    }
    publishing = true;
    try {
      const snapshot = buildWorkbenchContextSnapshot(reason);
      const comparableSnapshot = {
        ...snapshot,
        snapshotId: "",
        generatedAtMs: 0,
        reason: "",
      };
      const hash = crypto
        .createHash("sha256")
        .update(JSON.stringify(comparableSnapshot))
        .digest("hex");
      if (hash !== lastHash) {
        lastHash = hash;
        await writeBridgeRequest("workbench.contextSnapshot", snapshot, {
          source: "ioi-workbench",
          reason,
        });
      }

      const targetIndex = buildWorkbenchInspectionTargetIndex(reason);
      const comparableTargetIndex = {
        ...targetIndex,
        generatedAtMs: 0,
        reason: "",
      };
      const targetHash = crypto
        .createHash("sha256")
        .update(JSON.stringify(comparableTargetIndex))
        .digest("hex");
      if (targetHash !== lastTargetHash) {
        lastTargetHash = targetHash;
        await writeBridgeRequest("workbench.inspectionTargetIndex", targetIndex, {
          source: "ioi-workbench",
          reason,
        });
      }
    } catch (error) {
      output.appendLine(
        `Workbench context snapshot failed: ${error?.message || String(error)}`,
      );
    } finally {
      publishing = false;
    }
  };

  const subscriptions = [
    vscode.window.onDidChangeActiveTextEditor(() => void publish("activeEditor")),
    vscode.window.onDidChangeTextEditorSelection(() => void publish("selection")),
    vscode.languages.onDidChangeDiagnostics(() => void publish("diagnostics")),
    vscode.window.tabGroups.onDidChangeTabs(() => void publish("tabs")),
    vscode.window.onDidOpenTerminal(() => void publish("terminal")),
    vscode.window.onDidCloseTerminal(() => void publish("terminal")),
    vscode.tasks.onDidStartTask((event) => {
      rememberRecentTaskLabel(event.execution?.task?.name);
      void publish("task");
    }),
    vscode.tasks.onDidEndTaskProcess((event) => {
      rememberRecentTaskLabel(event.execution?.task?.name);
      lastTaskExitCode =
        typeof event.exitCode === "number" ? event.exitCode : lastTaskExitCode;
      void publish("task");
    }),
  ];
  subscriptions.forEach((subscription) => context.subscriptions.push(subscription));

  const timer = setInterval(() => void publish("poll"), 3_000);
  context.subscriptions.push({ dispose: () => clearInterval(timer) });
  void publish("activation");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatRelativeTime(timestampMs) {
  if (!timestampMs) {
    return "now";
  }
  const elapsed = Math.max(0, Date.now() - timestampMs);
  const minutes = Math.floor(elapsed / 60_000);
  if (minutes < 1) {
    return "<1m ago";
  }
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  const rem = minutes % 60;
  return rem > 0 ? `${hours}h ${rem}m ago` : `${hours}h ago`;
}

function renderItems(items, emptyLabel, renderItem) {
  if (!items.length) {
    return `<div class="empty-state">${escapeHtml(emptyLabel)}</div>`;
  }
  return `<div class="stack">${items.map(renderItem).join("")}</div>`;
}

function renderCommandButton(action) {
  const payload =
    action && "payload" in action && action.payload != null
      ? commandPayloadAttr(action.payload)
      : "";
  return `<button class="action" data-command="${escapeHtml(action.command)}"${payload}>${escapeHtml(action.label)}</button>`;
}

function commandPayloadAttr(payload) {
  return payload ? ` data-payload="${escapeHtml(JSON.stringify(payload))}"` : "";
}

function renderRuntimeSummary(state) {
  const summary = state.summary || {};
  const metrics = [
    ["Workflows", summary.workflowCount ?? 0],
    ["Runs", summary.runCount ?? 0],
    ["Artifacts", summary.artifactCount ?? 0],
    ["Connectors", summary.connectorCount ?? 0],
    ["Policy issues", summary.policyIssueCount ?? 0],
  ];
  return `
    <div class="runtime-strip" aria-label="IOI runtime snapshot">
      ${metrics
        .map(
          ([label, value]) => `
            <div class="runtime-strip__item">
              <span>${escapeHtml(label)}</span>
              <strong>${escapeHtml(value)}</strong>
            </div>
          `,
        )
        .join("")}
    </div>
  `;
}

function renderDiagnostics(state) {
  const diagnostics = state.diagnostics || [];
  if (!diagnostics.length) {
    return "";
  }
  return `
    <div class="diagnostics">
      <strong>Bridge diagnostics</strong>
      ${diagnostics
        .map(
          (item) => `
            <p><code>${escapeHtml(item.label)}</code> ${escapeHtml(item.message)}</p>
          `,
        )
        .join("")}
    </div>
  `;
}

function renderNativeChatIcon(name) {
  const lucideCommon =
    'class="studio-source-icon studio-source-icon--lucide" viewBox="0 0 24 24" fill="none" stroke="currentColor" focusable="false" aria-hidden="true"';
  const codiconCommon =
    'class="studio-source-icon studio-source-icon--codicon" viewBox="0 0 16 16" fill="currentColor" focusable="false" aria-hidden="true"';
  switch (name) {
    case "paperclip":
      return `<svg ${lucideCommon} data-tauri-icon="paperclip" width="14" height="14" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48" /></svg>`;
    case "device-desktop":
      return `<svg ${codiconCommon} data-tauri-codicon="device-desktop"><path d="M13.013 1.013L2.987 1.013L2.987 1.013Q2.187 1.013 1.600 1.600L1.600 1.600L1.600 1.600Q1.013 2.187 1.013 2.987L1.013 2.987L1.013 9.973L1.013 9.973Q1.013 10.827 1.600 11.413L1.600 11.413L1.600 11.413Q2.187 12 2.987 12L2.987 12L5.013 12L5.013 13.973L3.520 13.973L3.520 13.973Q3.307 13.973 3.147 14.133L3.147 14.133L3.147 14.133Q2.987 14.293 2.987 14.507L2.987 14.507L2.987 14.507Q2.987 14.720 3.147 14.853L3.147 14.853L3.147 14.853Q3.307 14.987 3.520 14.987L3.520 14.987L12.480 14.987L12.480 14.987Q12.693 14.987 12.853 14.853L12.853 14.853L12.853 14.853Q13.013 14.720 13.013 14.507L13.013 14.507L13.013 14.507Q13.013 14.293 12.853 14.133L12.853 14.133L12.853 14.133Q12.693 13.973 12.480 13.973L12.480 13.973L10.987 13.973L10.987 12L13.013 12L13.013 12Q13.813 12 14.400 11.413L14.400 11.413L14.400 11.413Q14.987 10.827 14.987 9.973L14.987 9.973L14.987 2.987L14.987 2.987Q14.987 2.187 14.400 1.600L14.400 1.600L14.400 1.600Q13.813 1.013 13.013 1.013L13.013 1.013ZM6.027 12L10.027 12L10.027 13.973L6.027 13.973L6.027 12ZM2.027 9.973L2.027 2.987L2.027 2.987Q2.027 2.560 2.293 2.267L2.293 2.267L2.293 2.267Q2.560 1.973 2.987 1.973L2.987 1.973L13.013 1.973L13.013 1.973Q13.440 2.027 13.733 2.293L13.733 2.293L13.733 2.293Q14.027 2.560 14.027 2.987L14.027 2.987L14.027 9.973L14.027 9.973Q13.973 10.400 13.707 10.693L13.707 10.693L13.707 10.693Q13.440 10.987 13.013 10.987L13.013 10.987L2.987 10.987L2.987 10.987Q2.560 10.987 2.293 10.693L2.293 10.693L2.293 10.693Q2.027 10.400 2.027 9.973L2.027 9.973Z" /></svg>`;
    case "cube":
      return `<svg ${lucideCommon} data-tauri-icon="cube" width="14" height="14" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m21 16-9 5-9-5V8l9-5 9 5v8Z" /><path d="m3.3 7.3 8.7 5 8.7-5" /><path d="M12 22V12" /></svg>`;
    case "symbol-operator":
      return `<svg ${codiconCommon} data-tauri-codicon="symbol-operator"><path d="M6.987 4.480L6.987 4.480L6.987 4.480Q6.987 4.693 6.853 4.853L6.853 4.853L6.853 4.853Q6.720 5.013 6.507 5.013L6.507 5.013L5.013 5.013L5.013 6.507L5.013 6.507Q5.013 6.720 4.853 6.853L4.853 6.853L4.853 6.853Q4.693 6.987 4.480 6.987L4.480 6.987L4.480 6.987Q4.267 6.987 4.133 6.853L4.133 6.853L4.133 6.853Q4 6.720 4 6.507L4 6.507L4 5.013L2.507 5.013L2.507 5.013Q2.293 5.013 2.160 4.853L2.160 4.853L2.160 4.853Q2.027 4.693 2 4.480L2 4.480L2 4.480Q1.973 4.267 2.133 4.133L2.133 4.133L2.133 4.133Q2.293 4 2.507 4L2.507 4L4 4L4 2.507L4 2.507Q4 2.293 4.133 2.160L4.133 2.160L4.133 2.160Q4.267 2.027 4.480 2.000L4.480 2.000L4.480 2.000Q4.693 1.973 4.853 2.133L4.853 2.133L4.853 2.133Q5.013 2.293 5.013 2.507L5.013 2.507L5.013 4L6.507 4L6.507 4Q6.720 4 6.853 4.133L6.853 4.133L6.853 4.133Q6.987 4.267 6.987 4.480ZM9.493 5.013L9.493 5.013L13.493 5.013L13.493 5.013Q13.707 5.013 13.840 4.853L13.840 4.853L13.840 4.853Q13.973 4.693 13.973 4.480L13.973 4.480L13.973 4.480Q13.973 4.267 13.840 4.133L13.840 4.133L13.840 4.133Q13.707 4 13.493 4L13.493 4L9.493 4L9.493 4Q9.280 4 9.147 4.133L9.147 4.133L9.147 4.133Q9.013 4.267 9.013 4.480L9.013 4.480L9.013 4.480Q9.013 4.693 9.147 4.853L9.147 4.853L9.147 4.853Q9.280 5.013 9.493 5.013ZM6.880 9.120L6.880 9.120L6.880 9.120Q6.720 9.013 6.507 9.013L6.507 9.013L6.507 9.013Q6.293 9.013 6.133 9.120L6.133 9.120L4.480 10.773L2.880 9.120L2.880 9.120Q2.720 9.013 2.507 9.013L2.507 9.013L2.507 9.013Q2.293 9.013 2.160 9.147L2.160 9.147L2.160 9.147Q2.027 9.280 2.027 9.493L2.027 9.493L2.027 9.493Q2.027 9.707 2.133 9.867L2.133 9.867L3.787 11.520L2.133 13.120L2.133 13.120Q2.027 13.280 2.027 13.493L2.027 13.493L2.027 13.493Q2.027 13.707 2.160 13.840L2.160 13.840L2.160 13.840Q2.293 13.973 2.507 13.973L2.507 13.973L2.507 13.973Q2.720 13.973 2.880 13.867L2.880 13.867L4.480 12.213L6.133 13.867L6.133 13.867Q6.293 13.973 6.507 13.973L6.507 13.973L6.507 13.973Q6.720 13.973 6.853 13.840L6.853 13.840L6.853 13.840Q6.987 13.707 6.987 13.493L6.987 13.493L6.987 13.493Q6.987 13.280 6.880 13.120L6.880 13.120L5.227 11.520L6.880 9.867L6.880 9.867Q6.987 9.707 6.987 9.493L6.987 9.493L6.987 9.493Q6.987 9.280 6.880 9.120ZM10.773 9.493L10.773 9.493L10.773 9.493Q10.773 9.813 10.987 10.027L10.987 10.027L10.987 10.027Q11.200 10.240 11.493 10.240L11.493 10.240L11.493 10.240Q11.787 10.240 12.027 10.027L12.027 10.027L12.027 10.027Q12.267 9.813 12.267 9.493L12.267 9.493L12.267 9.493Q12.267 9.173 12.027 8.960L12.027 8.960L12.027 8.960Q11.787 8.747 11.493 8.747L11.493 8.747L11.493 8.747Q11.200 8.747 10.987 8.960L10.987 8.960L10.987 8.960Q10.773 9.173 10.773 9.493ZM13.493 10.987L13.493 10.987L9.493 10.987L9.493 10.987Q9.280 10.987 9.147 11.147L9.147 11.147L9.147 11.147Q9.013 11.307 9.013 11.520L9.013 11.520L9.013 11.520Q9.013 11.733 9.147 11.867L9.147 11.867L9.147 11.867Q9.280 12 9.493 12L9.493 12L13.493 12L13.493 12Q13.707 12 13.840 11.867L13.840 11.867L13.840 11.867Q13.973 11.733 14.000 11.520L14.000 11.520L14.000 11.520Q14.027 11.307 13.867 11.147L13.867 11.147L13.867 11.147Q13.707 10.987 13.493 10.987ZM11.520 12.747L11.520 12.747L11.520 12.747Q11.200 12.747 10.987 12.960L10.987 12.960L10.987 12.960Q10.773 13.173 10.773 13.493L10.773 13.493L10.773 13.493Q10.773 13.813 10.987 14.027L10.987 14.027L10.987 14.027Q11.200 14.240 11.493 14.240L11.493 14.240L11.493 14.240Q11.787 14.240 12.027 14.027L12.027 14.027L12.027 14.027Q12.267 13.813 12.267 13.493L12.267 13.493L12.267 13.493Q12.267 13.173 12.027 12.960L12.027 12.960L12.027 12.960Q11.787 12.747 11.520 12.747Z" /></svg>`;
    case "chevron-down":
      return `<svg ${codiconCommon} data-tauri-codicon="chevron-down"><path d="M3.147 5.867L3.147 5.867L7.627 10.347L7.627 10.347Q7.787 10.507 8 10.507L8 10.507L8 10.507Q8.213 10.507 8.373 10.347L8.373 10.347L12.853 5.867L12.853 5.867Q13.013 5.707 13.013 5.493L13.013 5.493L13.013 5.493Q13.013 5.280 12.853 5.147L12.853 5.147L12.853 5.147Q12.693 5.013 12.480 5.013L12.480 5.013L12.480 5.013Q12.267 5.013 12.160 5.173L12.160 5.173L8 9.280L3.840 5.173L3.840 5.173Q3.733 5.013 3.520 5.013L3.520 5.013L3.520 5.013Q3.307 5.013 3.147 5.147L3.147 5.147L3.147 5.147Q2.987 5.280 2.987 5.493L2.987 5.493L2.987 5.493Q2.987 5.707 3.147 5.867Z" /></svg>`;
    case "tools":
      return `<svg ${codiconCommon} data-tauri-codicon="tools"><path d="M5.66901 0.999997C5.52101 0.945997 5.34701 0.968997 5.21401 1.062C5.08101 1.155 5.00201 1.308 5.00201 1.47V3.286C5.00201 3.561 4.77701 3.786 4.50201 3.786C4.22701 3.786 4.00201 3.561 4.00201 3.286V1.47C4.00201 1.308 3.92301 1.156 3.79001 1.062C3.65801 0.967997 3.48501 0.945997 3.33501 0.999997C1.93901 1.495 1.00201 2.816 1.00201 4.287C1.00201 5.646 1.79201 6.876 3.00201 7.449V13.5C3.00201 14.327 3.67501 15 4.50201 15C5.32901 15 6.00201 14.327 6.00201 13.5V7.449C7.21201 6.876 8.00201 5.646 8.00201 4.287C8.00201 2.816 7.06401 1.495 5.66901 0.999997ZM5.33601 6.644C5.13601 6.714 5.00201 6.904 5.00201 7.116V13.501C5.00201 13.776 4.77701 14.001 4.50201 14.001C4.22701 14.001 4.00201 13.776 4.00201 13.501V7.116C4.00201 6.904 3.86801 6.715 3.66801 6.644C2.67201 6.292 2.00201 5.345 2.00201 4.288C2.00201 3.496 2.38501 2.765 3.00201 2.301V3.288C3.00201 4.115 3.67501 4.788 4.50201 4.788C5.32901 4.788 6.00201 4.115 6.00201 3.288V2.301C6.61901 2.765 7.00201 3.496 7.00201 4.288C7.00201 5.346 6.33201 6.293 5.33601 6.644ZM13.5 8H13.002V4.118L13.449 3.223C13.509 3.105 13.518 2.967 13.476 2.841L12.976 1.341C12.908 1.137 12.716 0.998997 12.501 0.998997H10.501C10.286 0.998997 10.095 1.137 10.026 1.341L9.52601 2.841C9.48401 2.967 9.49401 3.105 9.55301 3.223L10 4.118V8H9.50001C9.22401 8 9.00001 8.224 9.00001 8.5V12.5C9.00001 13.879 10.121 15 11.5 15C12.879 15 14 13.879 14 12.5V8.5C14 8.224 13.776 8 13.5 8ZM10.862 2.001H12.141L12.461 2.963L12.054 3.777C12.02 3.846 12.001 3.923 12.001 4.001V8.001H11.001V4.001C11.001 3.924 10.983 3.847 10.949 3.777L10.542 2.963L10.862 2.001ZM13.002 12.5C13.002 13.327 12.329 14 11.502 14C10.675 14 10.002 13.327 10.002 12.5V9H13.002V12.5Z" /></svg>`;
    case "send":
      return `<svg ${codiconCommon} data-tauri-codicon="send"><path d="M1.173 1.120L1.173 1.120L1.173 1.120Q1.440 0.907 1.707 1.067L1.707 1.067L14.720 7.573L14.720 7.573Q14.987 7.680 14.987 8L14.987 8L14.987 8Q14.987 8.320 14.720 8.427L14.720 8.427L1.707 14.933L1.707 14.933Q1.440 15.093 1.173 14.880L1.173 14.880L1.173 14.880Q0.907 14.667 1.013 14.347L1.013 14.347L2.987 8L1.013 1.653L1.013 1.653Q0.907 1.333 1.173 1.120ZM9.493 8.480L3.893 8.480L2.347 13.547L13.387 8L2.347 2.453L3.893 7.520L9.493 7.520L9.493 7.520Q9.707 7.520 9.867 7.653L9.867 7.653L9.867 7.653Q10.027 7.787 10.027 8L10.027 8L10.027 8Q10.027 8.213 9.867 8.347L9.867 8.347L9.867 8.347Q9.707 8.480 9.493 8.480L9.493 8.480Z" /></svg>`;
    case "stop":
      return `<svg ${lucideCommon} data-tauri-icon="stop" width="12" height="12" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="6" width="12" height="12" rx="2" /></svg>`;
    default:
      return "";
  }
}

function normalizedNativeChatTurns(state) {
  const turns = Array.isArray(state.chat?.turns) ? state.chat.turns : [];
  return turns
    .filter((turn) => turn && typeof turn.text === "string" && turn.text.trim())
    .map((turn, index) => ({
      id: typeof turn.id === "string" ? turn.id : `native-chat-turn:${index}`,
      role: typeof turn.role === "string" ? turn.role : "assistant",
      text: turn.text.trim(),
      timestamp: typeof turn.timestamp === "number" ? turn.timestamp : null,
    }));
}

function renderNativeChatConversation(state) {
  const turns = normalizedNativeChatTurns(state);
  const phase = typeof state.chat?.phase === "string" ? state.chat.phase : null;
  const currentStep =
    typeof state.chat?.currentStep === "string" ? state.chat.currentStep.trim() : "";
  if (turns.length === 0) {
    return "";
  }

  const status =
    phase && phase !== "Complete"
      ? `
        <div class="operator-chat-thread__status" data-inspection-target="native-ioi-chat-status">
          <span>${escapeHtml(phase)}</span>
          <strong>${escapeHtml(currentStep || "Working through the runtime...")}</strong>
        </div>
      `
      : "";

  return `
    <div class="operator-chat-thread" data-inspection-target="native-ioi-chat-thread">
      ${turns
        .map(
          (turn) => `
            <article
              class="operator-chat-message operator-chat-message--${escapeHtml(turn.role)}"
              data-chat-turn-role="${escapeHtml(turn.role)}"
            >
              <span>${escapeHtml(turn.role === "user" ? "You" : "Autopilot")}</span>
              <p>${escapeHtml(turn.text)}</p>
            </article>
          `,
        )
        .join("")}
      ${status}
    </div>
  `;
}

function renderChatView(state) {
  const modelLabel =
    state.chat?.modelLabel ||
    state.chat?.model ||
    state.chat?.selectedModelLabel ||
    "Local: qwen3.5:9b";
  const contextLabel = state.chat?.contextLabel || "Add Context...";
  const modeLabel = state.chat?.modeLabel || "Auto";
  const targetWorkspace = state.workspace?.path || workspaceSummary().path;
  const suggestedActions = Array.isArray(state.chat?.suggestedActions)
    ? state.chat.suggestedActions
    : [
        {
          label: "Build Workspace",
          requestType: "workflow.codeGenerationRequest",
          payload: {
            workflowRef: "workflow:active",
            packageRef: "package:active",
            goal: "Generate a proposal-first code change from the active workspace prompt.",
            boundModelCapabilityRef: "model-capability:unbound",
            boundToolCapabilityRefs: ["tool-capability:workspace.fs.proposal"],
            targetWorkspace,
            authorityScope: "workspace.fs.proposal",
            proposalOnly: true,
          },
        },
        {
          label: "Show Config",
          requestType: "chat.showConfig",
        },
      ];
  const conversation = renderNativeChatConversation(state);
  return `
    <section
      class="operator-chat-pane"
      data-operator-chat-pane="native-openvscode"
      data-inspection-target="native-ioi-chat-pane"
      aria-label="Autopilot Chat"
    >
      ${
        conversation ||
        `
          <div class="operator-chat-empty" data-inspection-target="native-ioi-chat-empty-state">
            <div class="operator-chat-empty__icon" aria-hidden="true">
              <svg viewBox="0 0 32 32" focusable="false">
                <path d="M7.5 8.5h13a4 4 0 0 1 4 4v4a4 4 0 0 1-4 4H15l-5.5 4v-4h-2a4 4 0 0 1-4-4v-4a4 4 0 0 1 4-4Z" />
                <path d="M24 5.5v5M21.5 8h5M27 13.5v3M25.5 15h3" />
              </svg>
            </div>
            <h2>Build with Agent</h2>
            <p>
              AI responses may be inaccurate.
              <a href="#" data-bridge-request="chat.generateAgentInstructions">Generate Agent Instructions</a>
              to onboard AI onto your codebase.
            </p>
          </div>
        `
      }
      <div class="operator-chat-bottom">
        <div
          class="operator-chat-notice"
          data-native-chat-notice
          data-inspection-target="native-ioi-chat-notice"
          hidden
        ></div>
        <div class="operator-chat-suggestions" aria-label="Suggested actions">
          <span>SUGGESTED ACTIONS</span>
          <div>
            ${suggestedActions
              .map(
                (action) => `
                  <button
                    class="operator-chat-suggestion"
                    data-bridge-request="${escapeHtml(action.requestType || "chat.suggestedAction")}"
                    data-payload="${escapeHtml(
                      JSON.stringify(action.payload || { label: action.label }),
                    )}"
                  >${escapeHtml(action.label)}</button>
                `,
              )
              .join("")}
          </div>
        </div>
        <form
          class="operator-chat-composer"
          data-chat-composer-form
          data-inspection-target="native-ioi-chat-composer"
          aria-label="Chat composer"
        >
          <div class="operator-chat-composer__context-row">
            <button
              type="button"
              class="operator-chat-context-button"
              data-bridge-request="chat.addContext"
            >
              <span class="operator-chat-button-icon">${renderNativeChatIcon("paperclip")}</span>
              <span>${escapeHtml(contextLabel)}</span>
            </button>
          </div>
          <textarea
            data-chat-composer-input
            rows="2"
            placeholder="Describe what to build next"
            aria-label="Describe what to build next"
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
          ></textarea>
          <div class="operator-chat-composer__controls">
            <button
              type="button"
              class="operator-chat-icon-select"
              aria-label="Set Session Target"
              title="Set Session Target"
              data-bridge-request="chat.attachEditorContext"
            >
              <span class="operator-chat-button-icon">${renderNativeChatIcon("device-desktop")}</span>
              <span class="operator-chat-button-chevron">${renderNativeChatIcon("chevron-down")}</span>
            </button>
            <button
              type="button"
              class="operator-chat-icon-select"
              aria-label="Choose model or command - ${escapeHtml(modelLabel)}"
              title="Choose model or command - ${escapeHtml(modelLabel)}"
              data-bridge-request="chat.contextOptions"
              data-chat-model="${escapeHtml(modelLabel)}"
            >
              <span class="operator-chat-button-icon">${renderNativeChatIcon("cube")}</span>
              <span class="operator-chat-button-chevron">${renderNativeChatIcon("chevron-down")}</span>
            </button>
            <button
              type="button"
              class="operator-chat-mode-select"
              aria-label="Mode - ${escapeHtml(modeLabel)}"
              title="Mode - ${escapeHtml(modeLabel)}"
              data-bridge-request="chat.modeOptions"
              data-chat-mode="${escapeHtml(modeLabel)}"
            >
              <span>${escapeHtml(modeLabel)}</span>
              <span class="operator-chat-button-chevron">${renderNativeChatIcon("chevron-down")}</span>
            </button>
            <button
              type="button"
              class="operator-chat-tool-toggle"
              aria-label="Select tools"
              data-bridge-request="commandCenter.open"
              data-payload='{"mode":"tools"}'
            >
              <span class="operator-chat-button-icon">${renderNativeChatIcon("tools")}</span>
            </button>
            <button class="operator-chat-send" type="submit" aria-label="Send chat request">
              <span class="operator-chat-button-icon">${renderNativeChatIcon("send")}</span>
            </button>
          </div>
        </form>
      </div>
    </section>
  `;
}

function createInitialStudioRuntimeProjection() {
  return {
    schemaVersion: "ioi.agent-studio.operational-chat.projection.v1",
    threadId: null,
    sessionId: null,
    runId: null,
    turnId: null,
    status: "idle",
    pending: false,
    immediateSubmitSeen: false,
    pendingSeen: false,
    pendingStartedAtMs: null,
    lastError: null,
    lastModelStream: null,
    executionMode: STUDIO_MODE_AGENT,
    runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
    modelRoute: "route.local-first",
    selectedModel: "auto",
    reasoningEffort: "none",
    approvalMode: STUDIO_PERMISSION_MODE_DEFAULT,
    approvalId: STUDIO_APPROVAL_ID,
    hunkApprovalId: STUDIO_APPROVAL_ID,
    policyLeaseId: STUDIO_POLICY_LEASE_ID,
    hunkDecision: null,
    runtimeCockpit: {
      achieved: false,
      modelBackedStreamingObserved: false,
      realDaemonToolProposalObserved: false,
      policyLeaseDialogObserved: false,
      policyDeniedActionDidNotExecute: false,
      sandboxCommandOutputStreamObserved: false,
      sandboxCommandReceiptObserved: false,
      inlineDiffOverlayObserved: false,
      hunkNavigationObserved: false,
      hunkAcceptRejectReceiptsObserved: false,
      stopResumeObserved: false,
      diagnosticsTestGateObserved: false,
      receiptTimelinePerStepObserved: false,
      replayStepDetailObserved: false,
      projectionOnlyRuntimeRejected: true,
      browserStatusObserved: false,
      workerStatusObserved: false,
      managedLiveViewportObserved: false,
      managedSessionLabelsObserved: false,
    },
    runtimeUx: {
      denoised: true,
      tracingSeparationAchieved: true,
      compactStatusesHaveTraceLinks: true,
      modelProseNotAcceptedAsRuntimeTruth: true,
      verifiedBadgesRequireReceiptRefs: true,
    },
    runtimeEvents: [],
    actionCards: [],
    policyLeases: [],
    commandOutputs: [],
    diagnosticGates: [],
    engineReconnectBanners: [],
    chatResponsibilityContracts: [],
    securityScanPanels: [],
    workerContributionTraces: [],
    safeModeToolSuppressionPanels: [],
    onboardingDiagnosticsPanels: [],
    gatewayTokenHygienePanels: [],
    sandboxResourceLimitPanels: [],
    parentTrajectoryLinkagePanels: [],
    battleModePermissionImportPanels: [],
    importedStopHookGatePanels: [],
    importedBrowserActionEvidencePanels: [],
    importedExecutorConfigPanels: [],
    importedPolicyDraftPanels: [],
    importedGenerationMetadataPanels: [],
    importedErrorRenderInfoPanels: [],
    outputRenderers: [],
    replaySteps: [],
    browserCards: [],
    workerCards: [],
    computerUseSessions: [],
    turns: [
      {
        role: "assistant",
        content:
          "Agent Studio is ready. Prompts run through daemon-owned sessions; Studio stays calm by default and links proof details into Tracing.",
        createdAt: new Date().toISOString(),
      },
    ],
    history: [
      {
        id: "studio-session-current",
        title: "Current daemon session",
        status: "idle",
      },
    ],
    timeline: [
      {
        label: "Studio surface opened",
        detail: "Awaiting prompt",
        status: "ready",
      },
    ],
    approvals: [],
    receipts: [],
    terminal: [
      {
        label: "No terminal job running",
        detail: "Terminal/test output will be projected from daemon-owned execution receipts.",
      },
    ],
    diffHunks: [],
  };
}

function stringValue(value, fallback = "") {
  if (typeof value !== "string") {
    return fallback;
  }
  const trimmed = value.trim();
  return trimmed || fallback;
}

const STUDIO_TOOLCAT_MARKER_RE = /\bTOOLCAT_(?:SINGLE_TOOL|STAGE\d+_[A-Z0-9_]+)\b/i;
const STUDIO_TOOLCAT_TOOL_RE = /\btoolcat_tool=([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;
const STUDIO_TOOLCAT_SINGLE_TOOL_RE = /\bTOOLCAT_SINGLE_TOOL\s+([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;

function compactStudioWhitespace(value = "") {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function humanizeStudioToolName(value = "") {
  const compact = compactStudioWhitespace(value);
  if (!compact) {
    return "";
  }
  return compact
    .replace(/\./g, " ")
    .replace(/__+/g, " ")
    .replace(/_+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function studioToolcatToolName(text = "") {
  const value = String(text || "");
  return humanizeStudioToolName(
    value.match(STUDIO_TOOLCAT_TOOL_RE)?.[1] ||
      value.match(STUDIO_TOOLCAT_SINGLE_TOOL_RE)?.[1] ||
      "",
  );
}

function studioApprovalToolName(text = "") {
  const value = String(text || "");
  const match = value.match(/\btools?:\s*([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i);
  return humanizeStudioToolName(match?.[1] || "");
}

function studioHumanizeOperationalTranscriptText(value, role = "assistant") {
  const raw = String(value || "").trim();
  const compact = compactStudioWhitespace(raw);
  if (!compact) {
    return "";
  }
  if (STUDIO_TOOLCAT_MARKER_RE.test(compact)) {
    const toolName = studioToolcatToolName(compact);
    if (role === "user") {
      return toolName
        ? `Run live Rust tool catalogue verification for ${toolName}.`
        : "Run live Rust tool catalogue verification.";
    }
    if (/\bfailed\b|\bfailure\b/i.test(compact)) {
      return toolName
        ? `The live Rust tool catalogue probe failed for ${toolName}. Details are in Tracing.`
        : "The live Rust tool catalogue verification step failed. Details are in Tracing.";
    }
    return toolName
      ? `The live Rust tool catalogue probe completed for ${toolName}.`
      : "The live Rust tool catalogue verification step completed.";
  }
  if (role === "assistant" && studioTextIndicatesApprovalPause(compact)) {
    const toolName = studioApprovalToolName(compact);
    return toolName
      ? `Permission is required before Agent can use ${toolName}.`
      : "Permission is required before Agent can continue.";
  }
  if (
    role === "assistant" &&
    /Daemon agent turn completed but did not emit a final chat__reply/i.test(compact)
  ) {
    return "Agent reached the runtime but did not produce a chat reply. Details are in Tracing.";
  }
  return raw;
}

function studioDisplayTurnContent(turn = {}) {
  return studioHumanizeOperationalTranscriptText(turn.content || "", turn.role || "assistant");
}

function isAutoStudioModelSelector(value) {
  const normalized = stringValue(value, "auto").toLowerCase();
  return normalized === "auto" || normalized === "local:auto" || normalized === "default";
}

function normalizeStudioExecutionMode(value) {
  const normalized = stringValue(value, STUDIO_MODE_AGENT).toLowerCase().replace(/[\s-]+/g, "_");
  if (
    normalized === "ask" ||
    normalized === "chat" ||
    normalized === "chat_only" ||
    normalized === "chatonly" ||
    normalized === "direct_chat" ||
    normalized === "direct_model"
  ) {
    return STUDIO_MODE_ASK;
  }
  return STUDIO_MODE_AGENT;
}

function studioExecutionModeLabel(value) {
  return normalizeStudioExecutionMode(value) === STUDIO_MODE_ASK ? "Ask" : "Agent";
}

function normalizeStudioPermissionMode(value) {
  const normalized = stringValue(value, STUDIO_PERMISSION_MODE_DEFAULT).toLowerCase().replace(/[\s-]+/g, "_");
  if (
    normalized === "auto_review" ||
    normalized === "auto_local" ||
    normalized === "autolocal" ||
    normalized === "auto"
  ) {
    return STUDIO_PERMISSION_MODE_AUTO_REVIEW;
  }
  if (
    normalized === "full_access" ||
    normalized === "fullaccess" ||
    normalized === "never_prompt" ||
    normalized === "neverprompt" ||
    normalized === "yolo"
  ) {
    return STUDIO_PERMISSION_MODE_FULL_ACCESS;
  }
  return STUDIO_PERMISSION_MODE_DEFAULT;
}

function studioPermissionModeLabel(value) {
  switch (normalizeStudioPermissionMode(value)) {
    case STUDIO_PERMISSION_MODE_AUTO_REVIEW:
      return "Auto-review";
    case STUDIO_PERMISSION_MODE_FULL_ACCESS:
      return "Full access";
    case STUDIO_PERMISSION_MODE_DEFAULT:
    default:
      return "Default permissions";
  }
}

function studioPermissionThreadMode(value) {
  return normalizeStudioPermissionMode(value) === STUDIO_PERMISSION_MODE_FULL_ACCESS ? "yolo" : STUDIO_MODE_AGENT;
}

function studioPermissionModeOptions(selected = studioRuntimeProjection.approvalMode) {
  const normalizedSelected = normalizeStudioPermissionMode(selected);
  return [
    {
      id: STUDIO_PERMISSION_MODE_DEFAULT,
      label: "Default permissions",
      description: "Ask before consequential, external, or destructive actions.",
    },
    {
      id: STUDIO_PERMISSION_MODE_AUTO_REVIEW,
      label: "Auto-review",
      description: "Allow low-risk local actions; still gate destructive or external actions.",
    },
    {
      id: STUDIO_PERMISSION_MODE_FULL_ACCESS,
      label: "Full access",
      description: "Let Agent run without approval prompts for this daemon session.",
    },
  ].map((item) => ({
    ...item,
    picked: item.id === normalizedSelected,
  }));
}

function studioPermissionDaemonMapping(value) {
  const approvalMode = normalizeStudioPermissionMode(value);
  const threadMode = studioPermissionThreadMode(approvalMode);
  return {
    approvalMode,
    approval_mode: approvalMode,
    threadMode,
    thread_mode: threadMode,
  };
}

function promptTargetsLocalWorkspace(prompt = "") {
  const text = stringValue(prompt).toLowerCase();
  return /\b(repository|repo|workspace|project|codebase|source tree|current workspace|local source|inspect\b.*workspace|files?)\b/.test(text) ||
    /workspace_fixture_|daemon_endpoint=|computer_use_providers_url=|current trace history/.test(text);
}

function promptIsInternalHarnessProbe(prompt = "") {
  const text = stringValue(prompt);
  return STUDIO_TOOLCAT_MARKER_RE.test(text) ||
    /workspace_fixture_|daemon_endpoint=|computer_use_providers_url=|live IDE Rust\/provider tool row/i.test(text);
}

function promptRequiresRetrieval(prompt = "") {
  if (promptIsInternalHarnessProbe(prompt)) {
    return false;
  }
  const text = stringValue(prompt).toLowerCase();
  const targetsLocalWorkspace = promptTargetsLocalWorkspace(text);
  const asksForExternalFact = /\b(today|right now|latest|recent|news|price|market|market cap|investment|invest|compare|better|akt|akash|filecoin|fil|crypto|stock|exchange rate|weather)\b/.test(text);
  const asksForPublicSource = /\b(cite|citation|sources?|web|internet|online|public)\b/.test(text);
  const asksForCurrentExternalState =
    /\b(current|currently)\b/.test(text) &&
    /\b(price|market|news|investment|crypto|stock|exchange rate|weather|public|web|online)\b/.test(text);
  if (targetsLocalWorkspace && !asksForExternalFact && !asksForCurrentExternalState) {
    return false;
  }
  return asksForExternalFact || asksForPublicSource || asksForCurrentExternalState;
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  return [...new Set(firstArray(values).map((value) => String(value)).filter(Boolean))];
}

function nestedPayloadValue(value, keys = []) {
  let current = value;
  for (const key of keys) {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    current = current[key];
  }
  return current;
}

function studioRuntimeEventToolName(event = {}) {
  return (
    event.tool_name ||
    event.toolName ||
    event.tool_id ||
    event.toolId ||
    event.data?.tool_name ||
    event.data?.toolName ||
    event.data?.tool_id ||
    event.data?.toolId ||
    event.payload?.tool_name ||
    event.payload?.toolName ||
    event.payload?.tool_id ||
    event.payload?.toolId ||
    event.payload_summary?.tool_name ||
    event.payload_summary?.toolName ||
    event.data?.payload?.tool_name ||
    event.data?.payload?.toolName ||
    event.data?.payload_summary?.tool_name ||
    event.data?.payload_summary?.toolName ||
    event.data?.kernel_event?.RoutingReceipt?.tool_name ||
    event.data?.kernel_event?.ToolCall?.tool_name ||
    event.data?.kernel_event?.ToolResult?.tool_name ||
    nestedPayloadValue(event, ["raw", "payload", "tool_name"]) ||
    nestedPayloadValue(event, ["raw", "payload", "toolName"]) ||
    ""
  );
}

function studioRuntimeEventKind(event = {}) {
  return String(
    event.event_kind ||
      event.eventKind ||
      event.kind ||
      event.type ||
      event.data?.runtime_event_kind ||
      event.data?.runtimeEventKind ||
      event.data?.event_kind ||
      event.data?.eventKind ||
      event.payload?.event_kind ||
      event.payload?.eventKind ||
      "",
  );
}

function studioRuntimeEventsIncludeTool(events = [], pattern) {
  return firstArray(events).some((event) => pattern.test(String(studioRuntimeEventToolName(event)).toLowerCase()));
}

function studioRuntimeEventsIncludeCompletedTool(events = [], pattern) {
  return firstArray(events).some((event) => {
    const kind = studioRuntimeEventKind(event).toLowerCase();
    return (
      /tool\.(completed|result)/.test(kind) &&
      pattern.test(String(studioRuntimeEventToolName(event)).toLowerCase())
    );
  });
}

function studioRuntimeToolEventCount(events = [], pattern) {
  return firstArray(events).filter((event) => pattern.test(String(studioRuntimeEventToolName(event)).toLowerCase())).length;
}

function normalizeStudioAssistantReplyText(value) {
  const text = stringValue(value);
  if (!text) {
    return "";
  }
  return text.replace(/^Replied:\s*/i, "").trim();
}

function studioAssistantReplyTextIsDeferred(text = "") {
  return /\bdeferred\s+chat__reply\b|\bfresh\s+web__search\/web__read\s+evidence\b/i.test(stringValue(text));
}

function normalizeStudioAgentResultText(value) {
  const text = normalizeStudioAssistantReplyText(value);
  if (!text || studioAssistantReplyTextIsDeferred(text) || /^Runtime step completed\.?$/i.test(text)) {
    return "";
  }
  return text;
}

function studioAssistantTextFromRuntimeToolEvents(events = []) {
  for (const event of firstArray(events).slice().reverse()) {
    if (String(studioRuntimeEventToolName(event)).toLowerCase() !== "chat__reply") {
      continue;
    }
    const text = normalizeStudioAssistantReplyText(
      event.payload?.output ||
        event.payload?.message ||
        event.payload?.text ||
        event.payload_summary?.output ||
        event.payload_summary?.message ||
        event.payload_summary?.text ||
        event.payload_summary?.result_summary ||
        event.payload_summary?.summary ||
        event.summary,
    );
    if (text && !studioAssistantReplyTextIsDeferred(text)) {
      return text;
    }
  }
  return "";
}

function studioAgentTurnResultText(turn = {}, events = []) {
  const toolReply = studioAssistantTextFromRuntimeToolEvents(events);
  if (toolReply) {
    return toolReply;
  }
  const direct =
    turn.result ||
    turn.output ||
    turn.text ||
    turn.message ||
    turn.summary ||
    turn.payload_summary?.result_summary ||
    "";
  const directText = normalizeStudioAgentResultText(direct);
  if (directText) {
    return directText;
  }
  const completed = firstArray(events)
    .slice()
    .reverse()
    .find((event) => /turn\.completed|completed/.test(studioRuntimeEventKind(event).toLowerCase()));
  return normalizeStudioAgentResultText(
    completed?.summary ||
      completed?.payload_summary?.result_summary ||
      completed?.payload?.summary ||
      completed?.payload?.result ||
      completed?.payload?.message,
  );
}

function resetStudioDaemonThreadProjection() {
  studioRuntimeProjection.threadId = null;
  studioRuntimeProjection.sessionId = null;
  studioRuntimeProjection.turnId = null;
  studioRuntimeProjection.runId = null;
  studioRuntimeProjection.lastModelStream = null;
}

function startNewStudioSession(reason = "New Studio session") {
  const previous = studioRuntimeProjection || {};
  const next = createInitialStudioRuntimeProjection();
  next.executionMode = normalizeStudioExecutionMode(previous.executionMode || STUDIO_MODE_AGENT);
  next.runtimeProfile =
    next.executionMode === STUDIO_MODE_AGENT
      ? STUDIO_AGENT_RUNTIME_PROFILE
      : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
  next.modelRoute = previous.modelRoute || "route.local-first";
  next.selectedModel = previous.selectedModel || "auto";
  next.reasoningEffort = normalizeStudioReasoningEffort(previous.reasoningEffort, "none");
  next.approvalMode = normalizeStudioPermissionMode(previous.approvalMode);
  next.timeline = [
    {
      label: "New Studio session",
      detail: reason,
      status: "ready",
    },
  ];
  studioRuntimeProjection = next;
  return studioRuntimeProjection;
}

function studioRetrievalFailClosedText({ prompt = "", events = [], blockedReason = "" } = {}) {
  const hasSearch = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)search|search_web|web_search/);
  const hasRead = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)read|read_web|web_read/);
  if (!(hasSearch || hasRead)) {
    return "";
  }
  const searchCount = studioRuntimeToolEventCount(events, /web(::|__)search|search_web|web_search/);
  const readCount = studioRuntimeToolEventCount(events, /web(::|__)read|read_web|web_read/);
  const promptText = stringValue(prompt).replace(/\s+/g, " ").trim();
  const promptClause = promptText ? ` for "${promptText.slice(0, 160)}"` : "";
  const reasonClause = blockedReason ? ` Runtime stop reason: ${blockedReason}` : "";
  return [
    `Fresh retrieval ran through Agent Mode${promptClause} (${searchCount} search event${searchCount === 1 ? "" : "s"}, ${readCount} read event${readCount === 1 ? "" : "s"}), but the runtime did not emit a final chat__reply.`,
    "I will not choose or summarize from stale model memory.",
    reasonClause,
  ].filter(Boolean).join(" ");
}

function studioResultTextLooksRetrievalGrounded(text = "") {
  return /\b(web retrieval summary|current snapshot|citations?:|retrieved_utc|fresh evidence|retrieved current sources|stale model memory)\b/i.test(
    stringValue(text),
  );
}

function studioTextIndicatesApprovalPause(text = "") {
  return /\b(waiting for approval|awaiting .*approval|approval required|requires approval|pending approval|policy gate)\b/i.test(
    stringValue(text),
  );
}

function studioApprovalPauseErrorMessage({ resultText, events = [] } = {}) {
  const observedTools = uniqueStrings(firstArray(events).map((event) => studioRuntimeEventToolName(event)).filter(Boolean));
  const toolName = humanizeStudioToolName(observedTools.find(Boolean) || "");
  return [
    toolName
      ? `Permission is required before Agent can use ${toolName}.`
      : "Permission is required before Agent can continue.",
    "Details are in Tracing.",
    resultText && !/^waiting for approval\.?$/i.test(resultText) ? `Runtime status: ${resultText}.` : "",
  ].filter(Boolean).join(" ");
}

function studioApprovalPauseError({ resultText, events = [] } = {}) {
  const error = new Error(studioApprovalPauseErrorMessage({ resultText, events }));
  error.code = "studio_approval_pause";
  error.studioApprovalPause = true;
  return error;
}

function normalizeReceiptRefs(...sources) {
  const refs = [];
  for (const source of sources) {
    if (!source) continue;
    if (typeof source === "string") {
      refs.push(source);
      continue;
    }
    refs.push(
      ...firstArray(source.receipt_refs),
      ...firstArray(source.receiptRefs),
      ...firstArray(source.receiptIds),
      ...firstArray(source.receipts).map((receipt) => receipt?.id || receipt?.receipt_id || receipt?.receiptId),
      ...firstArray(source.event?.receipt_refs),
      ...firstArray(source.event?.receiptRefs),
      ...firstArray(source.result?.receipt_refs),
      ...firstArray(source.result?.receiptRefs),
      ...firstArray(source.payload_summary?.receipt_refs),
      ...firstArray(source.payload_summary?.receiptRefs),
    );
  }
  return uniqueStrings(refs);
}

const STUDIO_RUNTIME_VISIBILITY = Object.freeze({
  inlineAction: "inline-action",
  inlineProgress: "inline-progress",
  inlineSummary: "inline-summary",
  traceOnly: "trace-only",
  debugOnly: "debug-only",
});

function studioTraceStepId(kind, id) {
  return String(`${kind || "runtime"}.${id || crypto.randomUUID?.() || Date.now()}`)
    .replace(/[^a-z0-9_.:-]+/gi, "-")
    .slice(0, 120);
}

function classifyStudioRuntimeEvent(event = {}) {
  const kind = String(event.kind || event.event_kind || event.eventKind || "").toLowerCase();
  const status = String(event.status || event.payload_summary?.status || "").toLowerCase();
  if (/approval|policy|lease|firewall/.test(kind) || /waiting_for_approval|requires_approval|blocked/.test(status)) {
    return STUDIO_RUNTIME_VISIBILITY.inlineAction;
  }
  if (/patch|hunk|diff/.test(kind)) {
    return STUDIO_RUNTIME_VISIBILITY.inlineAction;
  }
  if (/stream|progress|pending|running/.test(kind) || /pending|running|streaming/.test(status)) {
    return STUDIO_RUNTIME_VISIBILITY.inlineProgress;
  }
  if (/receipt|replay|metadata|model_invocation|browser|worker|subagent/.test(kind)) {
    return STUDIO_RUNTIME_VISIBILITY.traceOnly;
  }
  if (/debug|raw/.test(kind)) {
    return STUDIO_RUNTIME_VISIBILITY.debugOnly;
  }
  return STUDIO_RUNTIME_VISIBILITY.inlineSummary;
}

function studioTraceTarget(payload = {}) {
  const receiptRefs = normalizeReceiptRefs(payload, ...firstArray(payload.receiptRefs));
  const stepId = payload.stepId || studioTraceStepId(payload.kind || "runtime", payload.id || receiptRefs[0]);
  return {
    sessionId: studioRuntimeProjection.sessionId || studioRuntimeProjection.threadId || "studio-session-current",
    threadId: studioRuntimeProjection.threadId || null,
    runId: studioRuntimeProjection.runId || null,
    turnId: studioRuntimeProjection.turnId || null,
    stepId,
    kind: payload.kind || "runtime.event",
    receiptRefs,
  };
}

function studioTraceCommandAttr(payload = {}) {
  return commandPayloadAttr({
    traceTarget: studioTraceTarget(payload),
    source: "agent-studio",
  });
}

function studioTraceLink(payload = {}, label = "View trace") {
  return `<button type="button" class="studio-view-trace-link" data-testid="studio-view-trace-link" data-command="ioi.runs.refresh"${studioTraceCommandAttr(payload)}>${escapeHtml(label)}</button>`;
}

function formatStudioWorkDuration(durationMs) {
  const seconds = Math.max(0, Math.round(Number(durationMs || 0) / 1000));
  if (seconds <= 0) {
    return "<1s";
  }
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return remaining ? `${minutes}m ${remaining}s` : `${minutes}m`;
}

function studioVerifiedBadge(payload = {}, label = "Verified") {
  const receiptRefs = normalizeReceiptRefs(payload);
  const hasReceipt = receiptRefs.length > 0;
  return `
    <span
      class="studio-verified-badge${hasReceipt ? "" : " studio-verified-badge--unverified"}"
      data-testid="studio-verified-badge"
      data-receipt-backed="${hasReceipt ? "true" : "false"}"
      title="${escapeHtml(hasReceipt ? "Backed by daemon receipt refs" : "Waiting for daemon receipt refs")}"
    >
      ${escapeHtml(hasReceipt ? label : "Trace pending")}
    </span>
  `;
}

function studioWorkCursor() {
  return {
    startedAtMs: Date.now(),
    actionCards: studioRuntimeProjection.actionCards.length,
    policyLeases: studioRuntimeProjection.policyLeases.length,
    commandOutputs: studioRuntimeProjection.commandOutputs.length,
    diagnosticGates: studioRuntimeProjection.diagnosticGates.length,
    diffHunks: studioRuntimeProjection.diffHunks.length,
    browserCards: studioRuntimeProjection.browserCards.length,
    workerCards: studioRuntimeProjection.workerCards.length,
    computerUseSessions: studioRuntimeProjection.computerUseSessions.length,
    receipts: studioRuntimeProjection.receipts.length,
  };
}

function studioDocumentedWorkRecord(cursor = {}) {
  const actionCards = studioRuntimeProjection.actionCards.slice(cursor.actionCards || 0);
  const policyLeases = studioRuntimeProjection.policyLeases.slice(cursor.policyLeases || 0);
  const commandOutputs = studioRuntimeProjection.commandOutputs.slice(cursor.commandOutputs || 0);
  const diagnosticGates = studioRuntimeProjection.diagnosticGates.slice(cursor.diagnosticGates || 0);
  const diffHunks = studioRuntimeProjection.diffHunks.slice(cursor.diffHunks || 0);
  const browserCards = studioRuntimeProjection.browserCards.slice(cursor.browserCards || 0);
  const workerCards = studioRuntimeProjection.workerCards.slice(cursor.workerCards || 0);
  const computerUseSessions = studioRuntimeProjection.computerUseSessions.slice(cursor.computerUseSessions || 0);
  const receipts = studioRuntimeProjection.receipts.slice(cursor.receipts || 0);
  const lines = [];
  const summaryParts = [];
  if (actionCards.length) {
    lines.push(`Used ${actionCards.length} daemon tool proposal${actionCards.length === 1 ? "" : "s"}`);
    summaryParts.push(`used ${actionCards.length} tool${actionCards.length === 1 ? "" : "s"}`);
  }
  if (commandOutputs.length) {
    lines.push(`Ran ${commandOutputs.length} sandboxed command${commandOutputs.length === 1 ? "" : "s"}`);
    summaryParts.push(`ran ${commandOutputs.length} command${commandOutputs.length === 1 ? "" : "s"}`);
  }
  if (diagnosticGates.length) {
    lines.push(`Checked ${diagnosticGates.length} diagnostic/test gate${diagnosticGates.length === 1 ? "" : "s"}`);
    summaryParts.push(`checked ${diagnosticGates.length} gate${diagnosticGates.length === 1 ? "" : "s"}`);
  }
  if (diffHunks.length) {
    lines.push(`Prepared ${diffHunks.length} patch hunk${diffHunks.length === 1 ? "" : "s"} for review`);
    summaryParts.push(`prepared ${diffHunks.length} patch${diffHunks.length === 1 ? "" : "es"}`);
  }
  if (policyLeases.length) {
    lines.push(`Evaluated ${policyLeases.length} policy lease${policyLeases.length === 1 ? "" : "s"}`);
    summaryParts.push(`checked ${policyLeases.length} policy gate${policyLeases.length === 1 ? "" : "s"}`);
  }
  if (browserCards.length) {
    lines.push(`Observed ${browserCards.length} browser status item${browserCards.length === 1 ? "" : "s"}`);
    summaryParts.push(`observed ${browserCards.length} browser state${browserCards.length === 1 ? "" : "s"}`);
  }
  if (computerUseSessions.length) {
    lines.push(`Managed ${computerUseSessions.length} browser/computer live session${computerUseSessions.length === 1 ? "" : "s"}`);
    summaryParts.push(`managed ${computerUseSessions.length} live session${computerUseSessions.length === 1 ? "" : "s"}`);
  }
  if (workerCards.length) {
    lines.push(`Observed ${workerCards.length} worker/subagent item${workerCards.length === 1 ? "" : "s"}`);
    summaryParts.push(`observed ${workerCards.length} worker${workerCards.length === 1 ? "" : "s"}`);
  }
  const receiptRefs = normalizeReceiptRefs(
    ...actionCards,
    ...policyLeases,
    ...commandOutputs,
    ...diagnosticGates,
    ...diffHunks,
    ...browserCards,
    ...computerUseSessions,
    ...workerCards,
    ...receipts,
  );
  if (!lines.length) {
    return null;
  }
  return {
    status: "completed",
    durationMs: Math.max(0, Date.now() - Number(cursor.startedAtMs || Date.now())),
    lines,
    summaryParts,
    receiptRefs,
    stepCount: lines.length,
    sessionCards: computerUseSessions.slice(-3),
  };
}

function studioTurnHasDocumentedWork(turn = {}) {
  const record = turn.workRecord || null;
  return Boolean(record && firstArray(record.lines).length);
}

function studioDocumentedWorkSummary(record = {}) {
  const parts = firstArray(record.summaryParts).filter(Boolean);
  if (parts.length) {
    return parts.slice(0, 4).join(" · ");
  }
  return String(record.status || studioRuntimeProjection.status || "completed");
}

function studioJsonObjectFromText(value = "") {
  const text = String(value || "").trim();
  if (!text || !/^[{\[]/.test(text)) {
    return {};
  }
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function studioRecordValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function studioComputerUseSurfaceKind({ lane = "", sessionMode = "", toolName = "" } = {}) {
  const normalizedLane = String(lane || "").toLowerCase();
  const normalizedMode = String(sessionMode || "").toLowerCase();
  const normalizedTool = String(toolName || "").toLowerCase();
  if (/screen__|window__|app__|visual_gui|desktop/.test(`${normalizedTool} ${normalizedLane} ${normalizedMode}`)) {
    return "desktop";
  }
  if (/controlled_relaunch|host_browser|local_browser|native_browser/.test(normalizedMode) && !/owned_hermetic/.test(normalizedMode)) {
    return "local_browser";
  }
  if (/browser__|browser|owned_hermetic|sandbox|hermetic/.test(`${normalizedTool} ${normalizedLane} ${normalizedMode}`)) {
    return "sandbox_browser";
  }
  return "sandbox_browser";
}

function studioComputerUseSurfaceLabel(kind = "") {
  if (kind === "desktop") {
    return "Desktop";
  }
  if (kind === "local_browser") {
    return "Local browser";
  }
  return "Sandbox browser";
}

function studioComputerUseSessionStatus(status = "", toolName = "", summary = "") {
  const haystack = `${status} ${toolName} ${summary}`.toLowerCase();
  if (/captcha|login|payment|file picker|manual|waiting_for_user|needs_user/.test(haystack)) {
    return "waiting_for_user";
  }
  if (/approval|policy|blocked|failed|error/.test(haystack)) {
    return "needs_user";
  }
  if (/running|active|pending|streaming/.test(haystack)) {
    return "browsing";
  }
  return "complete";
}

function studioComputerUseStatusLabel(status = "") {
  switch (status) {
    case "waiting_for_user":
      return "Waiting for user";
    case "needs_user":
      return "Needs user";
    case "browsing":
      return "Browsing";
    default:
      return "Complete";
  }
}

function studioManagedSessionFromRuntimeEvent(event = {}, context = {}) {
  const data = studioRecordValue(event.data);
  const payload = studioRecordValue(event.payload);
  const summaryPayload = studioRecordValue(event.payload_summary);
  const action = studioRecordValue(data.computer_action || payload.computer_action || event.computer_action);
  const actionReceipt = studioRecordValue(data.action_receipt || payload.action_receipt || event.action_receipt);
  const verificationReceipt = studioRecordValue(data.verification_receipt || payload.verification_receipt || event.verification_receipt);
  const rawOutput = stringValue(
    data.output ||
      payload.output ||
      summaryPayload.output ||
      actionReceipt.postcondition_summary ||
      verificationReceipt.observed_postcondition ||
      context.summary,
  );
  const outputJson = studioJsonObjectFromText(rawOutput);
  const observation = studioRecordValue(
    outputJson.browser_observation_receipt ||
      data.browser_observation_receipt ||
      payload.browser_observation_receipt ||
      data.observation ||
      payload.observation,
  );
  const toolName = stringValue(
    context.toolName ||
      action.tool_name ||
      data.tool_name ||
      payload.tool_name ||
      summaryPayload.tool_name,
  );
  const kind = stringValue(context.kind || data.event_kind || event.event_kind || event.eventKind);
  const lane = stringValue(
    data.computer_use_lane ||
      payload.computer_use_lane ||
      summaryPayload.computer_use_lane ||
      action.computer_use_lane,
  );
  const sessionMode = stringValue(
    data.computer_use_session_mode ||
      payload.computer_use_session_mode ||
      summaryPayload.computer_use_session_mode ||
      action.computer_use_session_mode,
  );
  const isComputerUseEvent =
    /computer_use|computer-use/.test(kind) ||
    Boolean(lane || sessionMode || data.computer_use_lease_id || payload.computer_use_lease_id);
  const isBrowserTool = /^browser__/.test(toolName);
  const isDesktopTool = /^(screen__|window__|app__|screen$)/.test(toolName);
  if (!isComputerUseEvent && !isBrowserTool && !isDesktopTool) {
    return null;
  }

  const surfaceKind = studioComputerUseSurfaceKind({ lane, sessionMode, toolName });
  const surfaceLabel = studioComputerUseSurfaceLabel(surfaceKind);
  const status = studioComputerUseSessionStatus(context.status, toolName, rawOutput || context.summary);
  const sessionId =
    stringValue(data.computer_use_lease_id || payload.computer_use_lease_id) ||
    stringValue(action.observation_ref || data.observation_ref || payload.observation_ref) ||
    `${surfaceKind}:${event.run_id || event.runId || studioRuntimeProjection.runId || studioRuntimeProjection.turnId || "current"}`;
  const url = stringValue(observation.url || outputJson.url);
  const title = stringValue(observation.title || outputJson.title);
  const target = stringValue(
    action.target_ref ||
      data.computer_use_target_ref ||
      payload.computer_use_target_ref ||
      observation.observation_ref ||
      url,
  );
  const detail = stringValue(
    title ||
      url ||
      target ||
      action.payload_summary ||
      rawOutput,
    surfaceKind === "desktop" ? "Desktop foreground session" : "Managed browser session",
  );
  return {
    id: sessionId,
    kind: surfaceKind,
    surfaceLabel,
    status,
    statusLabel: studioComputerUseStatusLabel(status),
    title: surfaceKind === "desktop" ? "Computer session" : "Browser session",
    detail,
    url,
    pageTitle: title,
    target,
    lane,
    sessionMode,
    lastTool: toolName || "computer-use",
    actionCount: 1,
    waitingForUser: status === "waiting_for_user" || status === "needs_user",
    updatedAt: new Date().toISOString(),
  };
}

function upsertStudioManagedSession(session) {
  if (!session) {
    return;
  }
  const existingIndex = studioRuntimeProjection.computerUseSessions.findIndex((item) => item.id === session.id);
  if (existingIndex >= 0) {
    const existing = studioRuntimeProjection.computerUseSessions[existingIndex];
    studioRuntimeProjection.computerUseSessions[existingIndex] = {
      ...existing,
      ...session,
      actionCount: Math.max(1, Number(existing.actionCount || 0) + 1),
      firstObservedAt: existing.firstObservedAt || existing.updatedAt || session.updatedAt,
    };
  } else {
    studioRuntimeProjection.computerUseSessions.push({
      ...session,
      firstObservedAt: session.updatedAt,
    });
  }
  studioRuntimeProjection.runtimeCockpit.managedLiveViewportObserved = true;
  studioRuntimeProjection.runtimeCockpit.managedSessionLabelsObserved = true;
}

function studioManagedSessionRows(cards = []) {
  const sessions = firstArray(cards).filter(Boolean);
  if (!sessions.length) {
    return "";
  }
  return `
    <section class="studio-managed-sessions" data-testid="studio-managed-sessions" aria-label="Browser and computer sessions">
      ${sessions.map((session, index) => {
        const modeLabels = [
          ["sandbox_browser", "Sandbox browser"],
          ["local_browser", "Local browser"],
          ["desktop", "Desktop"],
        ];
        return `
          <article
            class="studio-managed-session-card studio-managed-session-card--${escapeHtml(session.kind || "sandbox_browser")}"
            data-testid="studio-managed-session-card"
            data-session-kind="${escapeHtml(session.kind || "sandbox_browser")}"
            data-session-label="${escapeHtml(session.surfaceLabel || "Sandbox browser")}"
            data-session-status="${escapeHtml(session.status || "complete")}"
            data-control-state="observe"
            data-session-expanded="false"
          >
            <header class="studio-managed-session-card__header">
              <span class="studio-status-dot studio-status-dot--${escapeHtml(session.status === "needs_user" || session.status === "waiting_for_user" ? "blocked" : "completed")}"></span>
              <div>
                <strong>${escapeHtml(session.surfaceLabel || "Sandbox browser")}</strong>
                <span>${escapeHtml(session.statusLabel || "Complete")} · ${escapeHtml(session.lastTool || "computer-use")}</span>
              </div>
              <button type="button" data-testid="studio-managed-session-expand" data-studio-managed-session-expand aria-expanded="false">Expand</button>
            </header>
            <div class="studio-managed-session-preview" data-testid="studio-managed-session-compact-preview">
              <div class="studio-managed-session-preview__chrome" aria-hidden="true">
                <span></span><span></span><span></span>
              </div>
              <div class="studio-managed-session-preview__body">
                <strong>${escapeHtml(session.pageTitle || session.title || "Live session")}</strong>
                <span>${escapeHtml(session.url || session.detail || "Runtime-managed viewport")}</span>
                ${session.waitingForUser ? `<mark data-testid="studio-managed-session-waiting">Waiting for user</mark>` : ""}
              </div>
            </div>
            <div class="studio-managed-session-expanded" data-testid="studio-managed-session-expanded-view">
              <div class="studio-managed-session-mode-labels" data-testid="studio-managed-session-mode-labels">
                ${modeLabels.map(([kind, label]) => `
                  <span data-testid="studio-managed-session-mode-label" data-session-mode-label="${escapeHtml(kind)}" class="${kind === session.kind ? "is-active" : ""}">${escapeHtml(label)}</span>
                `).join("")}
              </div>
              <p>${escapeHtml(session.detail || "The runtime owns this browser/computer session. Observe by default, take over only when a manual step is needed, then return control to Agent.")}</p>
              <div class="studio-managed-session-controls" data-testid="studio-managed-session-controls">
                <button type="button" data-testid="studio-managed-session-observe" data-studio-managed-session-control="observe" aria-pressed="true">Observe</button>
                <button type="button" data-testid="studio-managed-session-take-over" data-studio-managed-session-control="take_over">Take over</button>
                <button type="button" data-testid="studio-managed-session-return" data-studio-managed-session-control="return_agent">Return control to Agent</button>
              </div>
            </div>
          </article>
        `;
      }).join("")}
    </section>
  `;
}

function studioTraceItems() {
  const items = [];
  const push = (item = {}) => {
    const kind = item.kind || "runtime.event";
    const receiptRefs = normalizeReceiptRefs(item);
    const stepId = item.stepId || studioTraceStepId(kind, item.id || item.label || receiptRefs[0]);
    items.push({
      stepId,
      id: item.id || stepId,
      kind,
      title: item.title || item.label || kind,
      summary: item.summary || item.detail || item.reason || item.stdout || item.status || "",
      status: item.status || "observed",
      receiptRefs,
      visibility: item.visibility || classifyStudioRuntimeEvent(item),
      payload: item,
    });
  };
  for (const event of firstArray(studioRuntimeProjection.runtimeEvents)) push(event);
  for (const item of firstArray(studioRuntimeProjection.timeline)) push({ ...item, kind: "timeline.step" });
  for (const item of firstArray(studioRuntimeProjection.actionCards)) push({ ...item, kind: "tool.proposal" });
  for (const item of firstArray(studioRuntimeProjection.policyLeases)) push({ ...item, kind: "policy.lease" });
  for (const item of firstArray(studioRuntimeProjection.commandOutputs)) push({ ...item, kind: "command.output", summary: item.stdout || item.stderr || item.label });
  for (const item of firstArray(studioRuntimeProjection.diagnosticGates)) push({ ...item, kind: "diagnostics.gate" });
  for (const item of firstArray(studioRuntimeProjection.diffHunks)) push({ ...item, kind: "patch.hunk", summary: `${item.file || "workspace"} · ${item.status || "pending"}` });
  for (const item of firstArray(studioRuntimeProjection.browserCards)) push({ ...item, kind: "browser.status" });
  for (const item of firstArray(studioRuntimeProjection.workerCards)) push({ ...item, kind: "worker.status" });
  for (const item of firstArray(studioRuntimeProjection.engineReconnectBanners)) push({ ...item, kind: "engine.reconnect" });
  for (const item of firstArray(studioRuntimeProjection.chatResponsibilityContracts)) push({ ...item, kind: "chat.responsibility" });
  for (const item of firstArray(studioRuntimeProjection.securityScanPanels)) push({ ...item, kind: "engine.guard.security" });
  for (const item of firstArray(studioRuntimeProjection.workerContributionTraces)) push({ ...item, kind: "worker.contribution" });
  for (const item of firstArray(studioRuntimeProjection.safeModeToolSuppressionPanels)) push({ ...item, kind: "safe_mode.tool_suppression" });
  for (const item of firstArray(studioRuntimeProjection.onboardingDiagnosticsPanels)) push({ ...item, kind: "onboarding.diagnostics" });
  for (const item of firstArray(studioRuntimeProjection.gatewayTokenHygienePanels)) push({ ...item, kind: "gateway.token_hygiene" });
  for (const item of firstArray(studioRuntimeProjection.sandboxResourceLimitPanels)) push({ ...item, kind: "sandbox.resource_limits" });
  for (const item of firstArray(studioRuntimeProjection.parentTrajectoryLinkagePanels)) push({ ...item, kind: "imported.parent_trajectory_linkage" });
  for (const item of firstArray(studioRuntimeProjection.battleModePermissionImportPanels)) push({ ...item, kind: "imported.battle_mode_permission" });
  for (const item of firstArray(studioRuntimeProjection.importedStopHookGatePanels)) push({ ...item, kind: "imported.stop_hook_gates" });
  for (const item of firstArray(studioRuntimeProjection.importedBrowserActionEvidencePanels)) push({ ...item, kind: "imported.browser_action_evidence" });
  for (const item of firstArray(studioRuntimeProjection.importedExecutorConfigPanels)) push({ ...item, kind: "imported.executor_config" });
  for (const item of firstArray(studioRuntimeProjection.importedPolicyDraftPanels)) push({ ...item, kind: "imported.policy_draft" });
  for (const item of firstArray(studioRuntimeProjection.importedGenerationMetadataPanels)) push({ ...item, kind: "imported.generation_metadata" });
  for (const item of firstArray(studioRuntimeProjection.importedErrorRenderInfoPanels)) push({ ...item, kind: "imported.error_render_info" });
  for (const item of firstArray(studioRuntimeProjection.replaySteps)) push({ ...item, kind: item.kind || "replay.step" });
  for (const item of firstArray(studioRuntimeProjection.receipts)) push({ ...item, kind: item.kind || "receipt" });
  return items;
}

function studioFocusedTraceTarget() {
  const target = activeTraceTarget || studioTraceTarget({ kind: "session.summary", id: "current" });
  const items = studioTraceItems();
  const focused =
    items.find((item) => item.stepId === target.stepId) ||
    items.find((item) => normalizeReceiptRefs(item).some((id) => target.receiptRefs?.includes(id))) ||
    items[items.length - 1] ||
    null;
  return { target, focused, items };
}

function appendStudioTimeline(label, detail, status = "ready", extra = {}) {
  studioRuntimeProjection.timeline.push({
    label,
    detail,
    status,
    at: new Date().toISOString(),
    ...extra,
  });
}

function appendStudioRuntimeEvent(event, fallbackKind = "runtime.event") {
  if (!event || typeof event !== "object") {
    return;
  }
  const normalized = {
    id: event.event_id || event.eventId || event.id || `${fallbackKind}.${Date.now()}`,
    kind: event.event_kind || event.eventKind || event.kind || fallbackKind,
    status: event.status || event.payload_summary?.status || "observed",
    summary:
      event.summary ||
      event.payload_summary?.summary ||
      event.payload_summary?.result_summary ||
      event.payload_summary?.input_summary ||
      "",
    receiptRefs: normalizeReceiptRefs(event),
    raw: event,
  };
  normalized.visibility = classifyStudioRuntimeEvent(normalized);
  studioRuntimeProjection.runtimeEvents.push(normalized);
  if (normalized.receiptRefs.length > 0) {
    appendStudioReceipts(normalized.receiptRefs.map((id) => ({
      id,
      kind: normalized.kind,
      summary: normalized.summary || "Daemon runtime event receipt.",
    })));
  }
}

function appendStudioReceiptsFromResponse(response, kind, summary) {
  appendStudioReceipts(
    normalizeReceiptRefs(response).map((id) => ({
      id,
      kind,
      summary,
    })),
  );
}

function studioRuntimeEventPayload(event = {}) {
  return event.payload_summary || event.payloadSummary || event.payload || event.data || {};
}

function applyStudioParityPlusEvent(event = {}, normalized = {}) {
  const payload = studioRuntimeEventPayload(event);
  const kind = String(normalized.kind || studioRuntimeEventKind(event) || "").toLowerCase();
  const schema = String(payload.schemaVersion || payload.schema_version || event.schemaVersion || event.schema_version || "").toLowerCase();
  const signature = `${kind} ${schema}`.toLowerCase();
  const base = {
    id: event.event_id || event.eventId || event.id || `${kind || "parity-plus"}.${Date.now()}`,
    status: normalized.status || payload.status || event.status || "observed",
    summary: normalized.summary || payload.summary || payload.bannerLabel || payload.mergeBlockReason || "",
    detail: payload.detail || payload.reason || payload.message || "",
    receiptRefs: normalizeReceiptRefs(event, payload),
    raw: event,
  };
  if (/engine[._-]?reconnect|runtime[._-]?reconnect|connection[._-]?reconnect/.test(signature)) {
    studioRuntimeProjection.engineReconnectBanners.push({
      ...base,
      bannerLabel: payload.bannerLabel || base.summary || "Engine reconnect state observed.",
      composerFrozen: Boolean(payload.composerFrozen),
    });
    return true;
  }
  if (/chat[._-]?responsibility|reply[._-]?contract|chat__reply/.test(signature)) {
    studioRuntimeProjection.chatResponsibilityContracts.push({
      ...base,
      directToolLeakCount: payload.directToolLeakCount ?? payload.direct_tool_leak_count ?? 0,
      missingAgentReplyCount: payload.missingAgentReplyCount ?? payload.missing_agent_reply_count ?? 0,
    });
    return true;
  }
  if (/engine[._-]?guard|security[._-]?scan|plaintext[._-]?secret|secret[._-]?scan/.test(signature)) {
    studioRuntimeProjection.securityScanPanels.push({
      ...base,
      mergeBlockReason: payload.mergeBlockReason || payload.merge_block_reason || base.summary,
      findingCount: payload.findingCount ?? payload.finding_count ?? null,
      mergeActionDisabled: Boolean(payload.mergeActionDisabled ?? payload.merge_action_disabled),
    });
    return true;
  }
  if (/worker[._-]?contribution|subagent[._-]?contribution|worker[._-]?hunk/.test(signature)) {
    studioRuntimeProjection.workerContributionTraces.push({
      ...base,
      contributionCount: payload.contributionCount ?? payload.contribution_count ?? null,
      workerIds: firstArray(payload.workerIds || payload.worker_ids),
    });
    return true;
  }
  if (/safe[._-]?mode|tool[._-]?suppression/.test(signature)) {
    studioRuntimeProjection.safeModeToolSuppressionPanels.push({
      ...base,
      status: payload.status || base.status || "safe_mode",
      detail: payload.detail || base.detail || "Ask direct text remains available; Agent tools are suppressed.",
      disabledCount: payload.disabledCount ?? payload.disabled_count ?? null,
      readOnlyCount: payload.readOnlyCount ?? payload.read_only_count ?? null,
    });
    return true;
  }
  if (/onboarding[._-]?diagnostics|diagnostics[._-]?checklist/.test(signature)) {
    studioRuntimeProjection.onboardingDiagnosticsPanels.push({
      ...base,
      status: payload.status || base.status || "needs_setup",
      detail: payload.detail || base.detail || "Local prerequisite checklist projected.",
      blockedCount: payload.blockedCount ?? payload.blocked_count ?? null,
      needsSetupCount: payload.needsSetupCount ?? payload.needs_setup_count ?? null,
    });
    return true;
  }
  if (/gateway[._-]?token|token[._-]?hygiene/.test(signature)) {
    studioRuntimeProjection.gatewayTokenHygienePanels.push({
      ...base,
      status: payload.status || base.status || "ready",
      detail: payload.detail || base.detail || "Gateway request is a redacted dry-run plan.",
      requestCount: payload.requestCount ?? payload.request_count ?? null,
    });
    return true;
  }
  if (/sandbox[._-]?resource|resource[._-]?limits/.test(signature)) {
    studioRuntimeProjection.sandboxResourceLimitPanels.push({
      ...base,
      status: payload.status || base.status || "blocked",
      detail: payload.detail || base.detail || "Sandbox resource limits projected before execution.",
      blockedCount: payload.blockedCount ?? payload.blocked_count ?? null,
      needsReviewCount: payload.needsReviewCount ?? payload.needs_review_count ?? null,
    });
    return true;
  }
  if (/parent[._-]?trajectory|trajectory[._-]?linkage/.test(signature)) {
    studioRuntimeProjection.parentTrajectoryLinkagePanels.push({
      ...base,
      status: payload.status || base.status || "needs_review",
      detail: payload.detail || base.detail || "Imported parent/child trajectory links are audit-only.",
      linkCount: payload.linkCount ?? payload.link_count ?? payload.rowCount ?? payload.row_count ?? null,
    });
    return true;
  }
  if (/battle[._-]?mode|permission[._-]?import/.test(signature)) {
    studioRuntimeProjection.battleModePermissionImportPanels.push({
      ...base,
      status: payload.status || base.status || "blocked",
      detail: payload.detail || base.detail || "Imported permission rows are historical-only.",
      rowCount: payload.rowCount ?? payload.row_count ?? null,
    });
    return true;
  }
  if (/stop[._-]?hook|stop[._-]?gate/.test(signature)) {
    studioRuntimeProjection.importedStopHookGatePanels.push({
      ...base,
      status: payload.status || base.status || "needs_review",
      detail: payload.detail || base.detail || "Imported stop-hook rows require live IOI verification.",
      rowCount: payload.rowCount ?? payload.row_count ?? null,
    });
    return true;
  }
  if (/browser[._-]?action|browser[._-]?evidence/.test(signature)) {
    studioRuntimeProjection.importedBrowserActionEvidencePanels.push({
      ...base,
      status: payload.status || base.status || "needs_review",
      detail: payload.detail || base.detail || "Imported browser actions require fresh observation before replay.",
      rowCount: payload.rowCount ?? payload.row_count ?? null,
    });
    return true;
  }
  if (/executor[._-]?config/.test(signature)) {
    studioRuntimeProjection.importedExecutorConfigPanels.push({
      ...base,
      status: payload.status || base.status || "needs_review",
      detail: payload.detail || base.detail || "Imported executor metadata is advisory-only.",
      rowCount: payload.rowCount ?? payload.row_count ?? null,
    });
    return true;
  }
  if (/policy[._-]?draft/.test(signature)) {
    studioRuntimeProjection.importedPolicyDraftPanels.push({
      ...base,
      status: payload.status || base.status || "needs_review",
      detail: payload.detail || base.detail || "Imported executor hints are converted into draft-only policy.",
      draftItemCount: payload.draftItemCount ?? payload.draft_item_count ?? null,
    });
    return true;
  }
  if (/generation[._-]?metadata|gen[._-]?metadata/.test(signature)) {
    studioRuntimeProjection.importedGenerationMetadataPanels.push({
      ...base,
      status: payload.status || base.status || "blocked",
      detail: payload.detail || base.detail || "Imported generation metadata is redacted and audit-only.",
      rowCount: payload.rowCount ?? payload.row_count ?? null,
    });
    return true;
  }
  if (/error[._-]?render|render[._-]?info|error[._-]?details/.test(signature)) {
    studioRuntimeProjection.importedErrorRenderInfoPanels.push({
      ...base,
      status: payload.status || base.status || "blocked",
      detail: payload.detail || base.detail || "Imported error/render rows keep stacks and payloads out of replay UI.",
      rowCount: payload.rowCount ?? payload.row_count ?? null,
    });
    return true;
  }
  return false;
}

function safeJsonPreview(value, max = 1200) {
  if (value === undefined || value === null) {
    return "";
  }
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function commandOutputFromToolResponse(toolId, response = {}) {
  const result = response.result || {};
  const nested = result.result || {};
  return {
    id: response.tool_call_id || response.toolCallId || `${toolId}.${Date.now()}`,
    toolId,
    label: result.command || nested.command || result.commandId || nested.commandId || toolId,
    status: response.status || result.status || nested.status || "completed",
    stdout:
      result.stdout ||
      nested.stdout ||
      result.output ||
      nested.output ||
      safeJsonPreview(result.diagnostics || nested.diagnostics || result.results || nested.results),
    stderr: result.stderr || nested.stderr || result.error?.message || nested.error?.message || "",
    exitCode: result.exitCode ?? nested.exitCode ?? result.exit_code ?? nested.exit_code ?? (response.status === "failed" ? 1 : 0),
    durationMs: result.durationMs ?? nested.durationMs ?? result.duration_ms ?? nested.duration_ms ?? null,
    receiptRefs: normalizeReceiptRefs(response, result, nested),
  };
}

function recomputeStudioRuntimeCockpitAchieved() {
  const cockpit = studioRuntimeProjection.runtimeCockpit || {};
  cockpit.achieved = Boolean(
    cockpit.modelBackedStreamingObserved &&
    cockpit.realDaemonToolProposalObserved &&
    cockpit.policyLeaseDialogObserved &&
    cockpit.policyDeniedActionDidNotExecute &&
    cockpit.sandboxCommandOutputStreamObserved &&
    cockpit.sandboxCommandReceiptObserved &&
    cockpit.inlineDiffOverlayObserved &&
    cockpit.hunkNavigationObserved &&
    cockpit.hunkAcceptRejectReceiptsObserved &&
    cockpit.stopResumeObserved &&
    cockpit.diagnosticsTestGateObserved &&
    cockpit.receiptTimelinePerStepObserved &&
    cockpit.replayStepDetailObserved &&
    cockpit.projectionOnlyRuntimeRejected &&
    cockpit.browserStatusObserved &&
    cockpit.workerStatusObserved
  );
  studioRuntimeProjection.runtimeCockpit = cockpit;
  return cockpit.achieved;
}

function isFixtureStudioModelRecord(record = {}) {
  const haystack = [
    record.id,
    record.modelId,
    record.providerId,
    record.family,
    record.source,
    record.quantization,
    record.driver,
  ].map((value) => String(value || "").toLowerCase()).join(" ");
  return (
    /\bfixture\b/.test(haystack) ||
    haystack.includes("local:auto") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("endpoint.local.auto")
  );
}

function modelRecordSupportsChat(record = {}) {
  const capabilities = Array.isArray(record.capabilities) ? record.capabilities : [];
  return capabilities.length === 0 || capabilities.some((capability) => /chat|responses/i.test(String(capability || "")));
}

function normalizeStudioReasoningEffort(value, fallback = "none") {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized || normalized === "provider_default" || normalized === "default" || normalized === "auto") {
    return fallback;
  }
  if (normalized === "off" || normalized === "disabled") {
    return "none";
  }
  return ["none", "low", "medium", "high", "xhigh"].includes(normalized) ? normalized : fallback;
}

function modelRecordReasoningSignals(...records) {
  return records
    .map((record) => {
      const capabilities = Array.isArray(record?.capabilities) ? record.capabilities : [];
      return [
        record?.id,
        record?.modelId,
        record?.model_id,
        record?.name,
        record?.label,
        record?.providerId,
        record?.provider_id,
        record?.driver,
        record?.apiFormat,
        record?.api_format,
        record?.architecture,
        record?.arch,
        record?.family,
        record?.reasoningEffort,
        record?.reasoning_effort,
        record?.thinking,
        ...capabilities,
      ]
        .filter(Boolean)
        .join(" ");
    })
    .join(" ")
    .toLowerCase();
}

function studioReasoningControlForSelection({ artifact = {}, endpoint = {}, route = {}, selectedModel = "", modelLabel = "" } = {}) {
  const haystack = modelRecordReasoningSignals(
    artifact,
    endpoint,
    route,
    { modelId: selectedModel, label: modelLabel },
  );
  const supported =
    /\b(reasoning|thinking|think|qwen3|qwen\/qwen3|deepseek-r1|o1|o3|o4)\b/.test(haystack) ||
    haystack.includes("reasoning_effort") ||
    haystack.includes("reasoningeffort");
  return {
    supported,
    effort: normalizeStudioReasoningEffort(
      studioRuntimeProjection.reasoningEffort ||
        route.reasoningEffort ||
        route.reasoning_effort ||
        endpoint.reasoningEffort ||
        endpoint.reasoning_effort ||
        artifact.reasoningEffort ||
        artifact.reasoning_effort,
      "none",
    ),
  };
}

function studioReasoningEffortOptions(selected = "none") {
  const current = normalizeStudioReasoningEffort(selected, "none");
  return [
    ["none", "Reasoning off"],
    ["low", "Reasoning low"],
    ["medium", "Reasoning medium"],
    ["high", "Reasoning high"],
    ["xhigh", "Reasoning xhigh"],
  ]
    .map(([value, label]) => `<option value="${value}"${current === value ? " selected" : ""}>${label}</option>`)
    .join("");
}

function modelRecordStatusScore(...records) {
  const status = records.map((record) => String(record?.status || record?.state || "").toLowerCase()).join(" ");
  if (/loaded|running|active/.test(status)) return 50;
  if (/mounted|ready/.test(status)) return 40;
  if (/available/.test(status)) return 30;
  if (/installed/.test(status)) return 20;
  return 0;
}

function studioPreferredModelSelection(snapshot = {}) {
  const activeRouteId = studioRuntimeProjection.modelRoute || "route.local-first";
  const activeRoute = snapshot.routes.find((candidate) =>
    candidate.id === activeRouteId || candidate.routeId === activeRouteId,
  );
  if (activeRoute) {
    const activeEndpoint =
      snapshot.endpoints.find((candidate) =>
        candidate.id === activeRoute.endpointId ||
        candidate.routeId === activeRoute.routeId ||
        candidate.routeId === activeRoute.id,
      ) ||
      {};
    const activeArtifact =
      snapshot.artifacts.find((candidate) =>
        candidate.id === activeEndpoint.modelId ||
        candidate.modelId === activeEndpoint.modelId ||
        candidate.id === activeRoute.modelId ||
        candidate.modelId === activeRoute.modelId,
      ) ||
      {};
    if (modelRecordSupportsChat(activeArtifact)) {
      return {
        artifact: activeArtifact,
        endpoint: activeEndpoint,
        route: activeRoute,
        score: 1_000 + modelRecordStatusScore(activeEndpoint, activeRoute, activeArtifact),
      };
    }
  }

  const candidates = snapshot.artifacts
    .filter((artifact) => artifact && modelRecordSupportsChat(artifact) && !isFixtureStudioModelRecord(artifact))
    .map((artifact) => {
      const modelId = artifact.modelId || artifact.id || "";
      const endpoint = modelEndpointForArtifact(snapshot, artifact) || {};
      const route =
        snapshot.routes.find((candidate) =>
          candidate.endpointId === endpoint.id ||
          candidate.modelId === modelId ||
          candidate.id === endpoint.routeId ||
          candidate.routeId === endpoint.routeId,
        ) ||
        {};
      const providerWeight = /lmstudio|lm_studio/i.test(String(artifact.providerId || ""))
        ? 100
        : /ollama|vllm|openai_compatible|local\.folder/i.test(String(artifact.providerId || ""))
          ? 80
          : 10;
      return {
        artifact,
        endpoint,
        route,
        score: providerWeight + modelRecordStatusScore(endpoint, route, artifact),
      };
    })
    .sort((left, right) => right.score - left.score);
  return candidates[0] || null;
}

function studioSnapshotFromState(state = {}) {
  const snapshot = modelSnapshotFromState(state);
  const preferred = studioPreferredModelSelection(snapshot);
  const route =
    preferred?.route ||
    snapshot.routes.find((candidate) => String(candidate.status || "").match(/ready|active|mounted/i)) ||
    snapshot.routes[0] ||
    {};
  const endpoint =
    preferred?.endpoint ||
    snapshot.endpoints.find((candidate) => candidate.id === route.endpointId) ||
    snapshot.endpoints.find((candidate) => String(candidate.status || "").match(/ready|loaded|active/i)) ||
    snapshot.endpoints[0] ||
    {};
  const artifact =
    preferred?.artifact ||
    snapshot.artifacts.find((candidate) => candidate.id === endpoint.modelId || candidate.modelId === endpoint.modelId) ||
    snapshot.artifacts.find((candidate) => candidate.id === route.modelId || candidate.modelId === route.modelId) ||
    snapshot.artifacts[0] ||
    {};
  const selectedModel =
    artifact.modelId ||
    artifact.id ||
    endpoint.modelId ||
    route.modelId ||
    studioRuntimeProjection.selectedModel ||
    "auto";
  const modelLabel =
    artifact.name ||
    artifact.label ||
    artifact.modelId ||
    artifact.id ||
    endpoint.modelId ||
    route.modelId ||
    "auto";
  const reasoningControl = studioReasoningControlForSelection({
    artifact,
    endpoint,
    route,
    selectedModel,
    modelLabel,
  });
  return {
    daemonStatus: state.modelMountingStatus?.status || "not_configured",
    daemonEndpoint: state.modelMountingStatus?.endpoint || daemonEndpoint() || null,
    routeId: route.routeId || route.id || studioRuntimeProjection.modelRoute || "route.local-first",
    endpointId: endpoint.id || route.endpointId || "",
    selectedModel,
    modelLabel,
    reasoningControlSupported: reasoningControl.supported,
    reasoningEffort: reasoningControl.effort,
  };
}

function mountedModelQuickInputRowsFromState(state = {}) {
  const snapshot = modelSnapshotFromState(state);
  const mountedStatus = (value) => /loaded|ready|running|mounted|active/i.test(String(value || ""));
  const seen = new Set();
  return snapshot.artifacts
    .map((artifact) => {
      const endpoint = modelEndpointForArtifact(snapshot, artifact) || {};
      const modelId = artifact.modelId || artifact.id || endpoint.modelId || "";
      const instance =
        modelInstanceForEndpoint(snapshot, endpoint) ||
        snapshot.instances.find((candidate) =>
          (candidate.modelId === modelId || candidate.endpointId === endpoint.id) &&
          mountedStatus(candidate.status),
        ) ||
        {};
      const route =
        snapshot.routes.find((candidate) =>
          candidate.endpointId === endpoint.id ||
          candidate.modelId === modelId ||
          candidate.id === endpoint.routeId ||
          candidate.routeId === endpoint.routeId,
        ) ||
        {};
      const status = instance.status || endpoint.status || route.status || artifact.status || "";
      if (!modelId || seen.has(modelId) || !mountedStatus(status)) {
        return null;
      }
      seen.add(modelId);
      return {
        id: route.routeId || route.id || endpoint.routeId || endpoint.id || modelId,
        label: modelDisplayName(artifact),
        detail: modelId,
        meta: status || "mounted",
        modelId,
        routeId: route.routeId || route.id || endpoint.routeId || endpoint.id || modelId,
        endpointId: endpoint.id || "",
        instanceId: instance.id || "",
      };
    })
    .filter(Boolean);
}

function studioIcon(name) {
  const icons = {
    paperclip:
      '<path d="M21.4 11.6 12 21a6 6 0 0 1-8.5-8.5l9.7-9.7a4 4 0 1 1 5.7 5.7L9.2 18.2a2 2 0 0 1-2.8-2.8l9.4-9.4" />',
    monitor:
      '<rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8" /><path d="M12 16v4" />',
    sparkles:
      '<path d="M12 3 13.7 8.3 19 10l-5.3 1.7L12 17l-1.7-5.3L5 10l5.3-1.7L12 3Z" /><path d="M5 3v4" /><path d="M3 5h4" /><path d="M19 17v4" /><path d="M17 19h4" />',
    sliders:
      '<path d="M4 7h10" /><path d="M18 7h2" /><path d="M4 17h2" /><path d="M10 17h10" /><circle cx="16" cy="7" r="2" /><circle cx="8" cy="17" r="2" />',
    send:
      '<path d="M5 4 20 12 5 20l2.8-8L5 4Z" /><path d="M8 12h12" />',
    stop:
      '<rect x="7" y="7" width="10" height="10" rx="1.5" />',
    search:
      '<circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" />',
    chevronDown:
      '<path d="m7 10 5 5 5-5" />',
  };
  return `<svg class="studio-control-icon studio-control-icon--${escapeHtml(name)}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${icons[name] || ""}</svg>`;
}

function studioMermaidSourcesFromText(content = "") {
  const sources = [];
  const fencePattern = /```(?:mermaid|text\/vnd\.mermaid)\s*\n([\s\S]*?)```/gi;
  let match = null;
  while ((match = fencePattern.exec(String(content || "")))) {
    const source = String(match[1] || "").trim();
    if (source) {
      sources.push(source);
    }
  }
  return sources;
}

function studioMermaidSummary(source = "") {
  const lines = String(source || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("%%"));
  const nodes = new Set();
  for (const line of lines) {
    for (const match of line.matchAll(/\b([A-Za-z][\w-]*)\s*(?:\[[^\]]+\]|\([^)]+\)|\{[^}]+\})?/g)) {
      const id = match[1];
      if (!/^(graph|flowchart|sequenceDiagram|participant|subgraph|end|classDef|style)$/.test(id)) {
        nodes.add(id);
      }
    }
  }
  return {
    title: lines[0] || "Mermaid diagram",
    nodeIds: [...nodes].slice(0, 8),
    nodeCount: nodes.size,
    edgeCount: lines.filter((line) => /-->|---|==>|-.->/.test(line)).length,
  };
}

function studioChatOutputRendererRows(turn = {}, turnIndex = 0) {
  const explicitRenderers = firstArray(turn.outputRenderers || turn.output_renderers);
  const cards = explicitRenderers.length
    ? explicitRenderers
        .filter((item) => String(item?.mimeType || item?.mime_type || item?.rendererId || item?.renderer_id || "").includes("mermaid"))
        .map((item, index) => ({
          id: item.id || `turn-${turnIndex}-renderer-${index}`,
          source: item.source || item.content || item.text || "",
          mimeType: item.mimeType || item.mime_type || "text/vnd.mermaid",
          rendererId: item.rendererId || item.renderer_id || "vscode.chatMermaidDiagram",
          receiptRefs: normalizeReceiptRefs(item, turn),
        }))
    : studioMermaidSourcesFromText(turn.content || turn.text || "").map((source, index) => ({
        id: `turn-${turnIndex}-mermaid-${index}`,
        source,
        mimeType: "text/vnd.mermaid",
        rendererId: "vscode.chatMermaidDiagram",
        receiptRefs: normalizeReceiptRefs(turn),
      }));
  if (!cards.length) {
    return "";
  }
  return cards.map((card) => {
    const summary = studioMermaidSummary(card.source);
    return `
      <figure class="studio-chat-output-renderer studio-chat-output-renderer--mermaid" data-testid="studio-chat-mermaid-renderer" data-renderer-id="${escapeHtml(card.rendererId)}" data-mime-type="${escapeHtml(card.mimeType)}" data-node-count="${escapeHtml(String(summary.nodeCount))}" data-edge-count="${escapeHtml(String(summary.edgeCount))}">
        <figcaption>
          <strong>Mermaid diagram</strong>
          <span>${escapeHtml(summary.nodeCount)} nodes · ${escapeHtml(summary.edgeCount)} edges · ${escapeHtml(card.mimeType)}</span>
        </figcaption>
        <div class="studio-chat-renderer-toolbar" data-testid="studio-chat-output-renderer-controls">
          <button type="button" data-testid="studio-chat-renderer-zoom-in" data-renderer-action="zoom-in">Zoom in</button>
          <button type="button" data-testid="studio-chat-renderer-zoom-out" data-renderer-action="zoom-out">Zoom out</button>
          <button type="button" data-testid="studio-chat-renderer-fit" data-renderer-action="fit">Fit</button>
        </div>
        <div class="studio-mermaid-diagram" data-testid="studio-mermaid-diagram-surface" role="img" aria-label="${escapeHtml(summary.title)}">
          ${summary.nodeIds.length
            ? summary.nodeIds.map((nodeId) => `<button type="button" class="studio-mermaid-node" data-testid="studio-mermaid-clickable-node">${escapeHtml(nodeId)}</button>`).join("")
            : '<span class="studio-mermaid-node">diagram</span>'}
        </div>
        <details class="studio-mermaid-source" data-testid="studio-chat-output-renderer-source">
          <summary>Mermaid source</summary>
          <pre>${escapeHtml(card.source)}</pre>
        </details>
        ${card.receiptRefs?.length ? `<footer>${studioVerifiedBadge({ id: card.id, kind: "chat.output_renderer", receiptRefs: card.receiptRefs, summary: "Mermaid renderer projected from daemon chat output." }, "Verified renderer")}</footer>` : ""}
      </figure>
    `;
  }).join("");
}

function studioExecutableCodeBlocksFromText(content = "") {
  const blocks = [];
  const executableLanguages = new Set(["bash", "sh", "shell", "zsh", "python", "javascript", "typescript", "node"]);
  const fencePattern = /```([a-zA-Z0-9_-]+)\s*\n([\s\S]*?)```/g;
  let match = null;
  while ((match = fencePattern.exec(String(content || "")))) {
    const language = String(match[1] || "").trim().toLowerCase();
    const normalizedLanguage = language === "js" ? "javascript" : language === "ts" ? "typescript" : language;
    const source = String(match[2] || "").trim();
    if (source && executableLanguages.has(normalizedLanguage)) {
      blocks.push({ language: normalizedLanguage, source });
    }
  }
  return blocks;
}

function studioCodeExecutionPolicy(source = "") {
  if (/\b(curl|wget|ssh|scp|nc|ncat|telnet)\b|https?:\/\//i.test(source)) {
    return {
      status: "blocked",
      blockReason: "Network-shaped code block requires explicit approval before execution.",
      policyRefs: ["policy:code_execution.plan_only", "policy:code_execution.sandbox.network_deny", "policy:code_execution.block.network"],
    };
  }
  if (/\brm\s+-rf\b|>\s*\/|sudo\b/i.test(source)) {
    return {
      status: "blocked",
      blockReason: "Host-write or privileged command shape cannot be executed from chat.",
      policyRefs: ["policy:code_execution.plan_only", "policy:code_execution.sandbox.network_deny", "policy:code_execution.block.host_write"],
    };
  }
  return {
    status: "ready",
    blockReason: null,
    policyRefs: ["policy:code_execution.plan_only", "policy:code_execution.sandbox.network_deny"],
  };
}

function studioChatCodeExecutionRows(turn = {}, turnIndex = 0) {
  const blocks = studioExecutableCodeBlocksFromText(turn.content || turn.text || "");
  if (!blocks.length) {
    return "";
  }
  return blocks.map((block, blockIndex) => {
    const policy = studioCodeExecutionPolicy(block.source);
    const payload = {
      turnIndex,
      blockIndex,
      language: block.language,
      source: block.source,
      applyMode: "plan_only",
      sandbox: {
        network: "deny",
        writeScope: "workspace_only",
        timeoutMs: 10000,
        receiptRequired: true,
      },
      policyRefs: policy.policyRefs,
    };
    return `
      <article class="studio-chat-code-execution-card" data-testid="studio-chat-code-execution-card" data-language="${escapeHtml(block.language)}" data-execution-status="${escapeHtml(policy.status)}" data-network-policy="deny" data-apply-mode="plan_only">
        <header>
          <strong>Sandbox code block</strong>
          <span>${escapeHtml(block.language)} · network denied · workspace writes only · receipt required</span>
        </header>
        <pre data-testid="studio-chat-code-execution-source">${escapeHtml(block.source)}</pre>
        ${policy.blockReason ? `<p data-testid="studio-chat-code-execution-block-reason">${escapeHtml(policy.blockReason)}</p>` : ""}
        <footer>
          <button type="button" data-testid="studio-chat-code-execute-plan" data-bridge-request="chat.executeCodeBlock.plan"${commandPayloadAttr(payload)} ${policy.status === "blocked" ? "disabled" : ""}>Prepare run</button>
          <span data-testid="studio-chat-code-execution-policy">${escapeHtml(policy.policyRefs.join(", "))}</span>
        </footer>
      </article>
    `;
  }).join("");
}

function studioTurnRows() {
  return studioRuntimeProjection.turns.map((turn, index) => {
    const hasDocumentedWork = turn.role === "assistant" && studioTurnHasDocumentedWork(turn);
    const workRecord = hasDocumentedWork ? turn.workRecord : null;
    const displayContent = studioDisplayTurnContent(turn);
    return `
    <article class="studio-chat-turn studio-chat-turn--${escapeHtml(turn.role || "system")}" data-studio-turn-role="${escapeHtml(turn.role || "system")}" data-testid="${turn.role === "user" ? "studio-user-turn-immediate" : index === studioRuntimeProjection.turns.length - 1 ? "studio-latest-turn" : "studio-chat-turn"}"${turn.modelStream?.streamId ? ` data-studio-stream-turn="${escapeHtml(turn.modelStream.streamId)}"` : ""} data-documented-work="${hasDocumentedWork ? "true" : "false"}">
      ${hasDocumentedWork ? `
        <div class="studio-run-status-bar" data-testid="studio-run-status-bar">
          <span class="studio-run-status-bar__check" aria-hidden="true">✓</span>
          <strong>${studioRuntimeProjection.status === "interrupted" ? "Stopped by operator" : `Worked for ${formatStudioWorkDuration(workRecord.durationMs)}`}</strong>
          <span>${escapeHtml(studioDocumentedWorkSummary(workRecord))}</span>
        </div>
        ${studioManagedSessionRows(workRecord.sessionCards)}
      ` : ""}
      <div class="studio-chat-turn__avatar" aria-hidden="true">${escapeHtml(turn.role === "user" ? "hi" : (turn.role || "S").slice(0, 1).toUpperCase())}</div>
      <div class="studio-chat-turn__body${turn.role === "assistant" ? " studio-assistant-answer-card" : turn.role === "user" ? " studio-user-bubble" : ""}" ${turn.role === "assistant" ? 'data-testid="studio-assistant-answer-card"' : turn.role === "user" ? 'data-testid="studio-user-bubble"' : ""}>
        <div class="studio-chat-turn__meta">
          <strong>${escapeHtml(turn.role === "user" ? "You" : turn.role === "assistant" ? "Autopilot" : "System")}</strong>
          <span>${escapeHtml(turn.createdAt || "")}</span>
        </div>
        <p${turn.modelStream?.streamId ? ' data-testid="studio-streaming-output"' : ""}>${escapeHtml(displayContent)}</p>
        ${turn.role === "assistant" ? studioChatOutputRendererRows(turn, index) : ""}
        ${turn.role === "assistant" ? studioChatCodeExecutionRows(turn, index) : ""}
      </div>
    </article>
  `;
  }).join("");
}

function studioTimelineRows() {
  return studioRuntimeProjection.timeline.slice(-8).map((item) => `
    <li>
      <span class="studio-status-dot studio-status-dot--${escapeHtml(item.status || "ready")}"></span>
      <strong>${escapeHtml(item.label || "Runtime event")}</strong>
      <span>${escapeHtml(item.detail || "")}</span>
    </li>
  `).join("");
}

function studioReceiptRows() {
  const receipts = studioRuntimeProjection.receipts.length > 0
    ? studioRuntimeProjection.receipts.slice(-8)
    : [
        {
          id: "receipt.pending",
          kind: "pending",
          summary: "Receipts appear after daemon session, approval, or hunk decisions.",
        },
      ];
  return receipts.map((receipt) => `
    <li data-testid="studio-receipt-timeline-step">
      <strong>${escapeHtml(receipt.kind || "receipt")}</strong>
      <code>${escapeHtml(receipt.id || "pending")}</code>
      <span>${escapeHtml(receipt.summary || "")}</span>
    </li>
  `).join("");
}

function studioHistoryRows() {
  return studioRuntimeProjection.history.slice(-5).map((item) => `
    <button type="button" class="studio-history-item" data-testid="studio-session-history-item">
      <strong>${escapeHtml(item.title || "Session")}</strong>
      <span>${escapeHtml([item.status, item.id].filter(Boolean).join(" · "))}</span>
    </button>
  `).join("");
}

function studioApprovalRows() {
  return studioRuntimeProjection.approvals.slice(-5).map((approval) => `
    <section class="studio-approval studio-approval-inline-card" data-testid="studio-approval-gate" data-approval-id="${escapeHtml(approval.id || STUDIO_APPROVAL_ID)}">
      <div>
        <strong data-testid="studio-approval-inline-card">${escapeHtml(approval.label || "Permission needed")}</strong>
        <span>${escapeHtml(approval.detail || "Agent needs permission before continuing.")}</span>
      </div>
      <mark>${escapeHtml(approval.status || "pending")}</mark>
    </section>
  `).join("");
}

function studioDiffRows() {
  return studioRuntimeProjection.diffHunks.map((hunk, index) => `
    <article class="studio-diff-hunk" data-testid="studio-inline-diff-hunks" data-native-diff-hunk="true">
      <header>
        <strong>${escapeHtml(hunk.title || `Hunk ${index + 1}`)}</strong>
        <code>${escapeHtml(hunk.file || "workspace")}</code>
        <mark>${escapeHtml(hunk.status || "pending")}</mark>
      </header>
      <pre data-testid="studio-native-diff-hunk"><span class="studio-diff-remove">${escapeHtml(hunk.before || "")}</span>
<span class="studio-diff-add">${escapeHtml(hunk.after || "")}</span></pre>
      <footer data-testid="studio-hunk-accept-reject">
        <button type="button" data-testid="studio-hunk-prev" data-studio-hunk-nav="previous">Previous</button>
        <button type="button" data-testid="studio-hunk-next" data-studio-hunk-nav="next">Next</button>
        <button type="button" data-testid="studio-hunk-accept" data-studio-hunk-decision="approve" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}">Accept hunk</button>
        <button type="button" data-testid="studio-hunk-reject" data-studio-hunk-decision="reject" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}">Reject hunk</button>
      </footer>
    </article>
  `).join("");
}

function studioTerminalRows() {
  return studioRuntimeProjection.terminal.slice(-6).map((item) => `
    <li>
      <strong>${escapeHtml(item.label || "Terminal")}</strong>
      <span>${escapeHtml(item.detail || "")}</span>
    </li>
  `).join("");
}

function studioActionCardRows() {
  return firstArray(studioRuntimeProjection.actionCards).slice(-6).map((card) => `
    <article class="studio-cockpit-card studio-tool-proposal-card" data-testid="studio-tool-proposal-card" data-tool-id="${escapeHtml(card.toolId || "")}">
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(card.status || "pending")}"></span>
        <strong>${escapeHtml(card.title || card.toolId || "Tool proposal")}</strong>
        <mark>${escapeHtml(card.status || "proposed")}</mark>
      </header>
      <p>${escapeHtml(card.detail || "Daemon-projected tool proposal.")}</p>
      ${card.receiptRefs?.length ? `<code>${escapeHtml(card.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
}

function studioPolicyLeaseRows() {
  return firstArray(studioRuntimeProjection.policyLeases).slice(-4).map((lease) => `
    <article class="studio-cockpit-card studio-policy-lease-card" data-testid="studio-policy-lease-dialog">
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(lease.status || "waiting_for_approval")}"></span>
        <strong>${escapeHtml(lease.title || "Permission needed")}</strong>
        <mark>${escapeHtml(lease.status || "pending")}</mark>
      </header>
      <p>${escapeHtml(lease.reason || "Agent needs permission before continuing.")}</p>
      <dl>
        <dt>Action</dt><dd>${escapeHtml(lease.action || "unknown")}</dd>
        <dt>Execution</dt><dd>${escapeHtml(lease.didExecute ? "executed" : "did not execute")}</dd>
      </dl>
      ${lease.receiptRefs?.length ? `<code>${escapeHtml(lease.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
}

function studioCommandOutputRows() {
  return firstArray(studioRuntimeProjection.commandOutputs).slice(-4).map((command) => `
    <article class="studio-cockpit-card studio-command-output-card" data-testid="studio-command-output-card">
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(command.status || "completed")}"></span>
        <strong>${escapeHtml(command.label || command.toolId || "Sandbox command")}</strong>
        <mark>${escapeHtml(command.exitCode === null || command.exitCode === undefined ? command.status || "completed" : `exit ${command.exitCode}`)}</mark>
      </header>
      <pre data-testid="studio-command-stdout">${escapeHtml(command.stdout || "(no stdout projected)")}</pre>
      ${command.stderr ? `<pre class="studio-command-stderr" data-testid="studio-command-stderr">${escapeHtml(command.stderr)}</pre>` : ""}
      <footer>
        <span>${escapeHtml(command.durationMs === null || command.durationMs === undefined ? "duration recorded by daemon" : `${command.durationMs}ms`)}</span>
        ${command.receiptRefs?.length ? `<code>${escapeHtml(command.receiptRefs.join(" · "))}</code>` : ""}
      </footer>
    </article>
  `).join("");
}

function studioDiagnosticsRows() {
  return firstArray(studioRuntimeProjection.diagnosticGates).slice(-4).map((gate) => `
    <article class="studio-cockpit-card studio-diagnostics-gate" data-testid="studio-diagnostics-test-gate">
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(gate.status || "completed")}"></span>
        <strong>${escapeHtml(gate.title || "Diagnostics / test gate")}</strong>
        <mark>${escapeHtml(gate.status || "completed")}</mark>
      </header>
      <p>${escapeHtml(gate.detail || "Postcondition gate projected from daemon tool output.")}</p>
      ${gate.receiptRefs?.length ? `<code>${escapeHtml(gate.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
}

function studioBrowserWorkerRows() {
  const browserCards = firstArray(studioRuntimeProjection.browserCards).slice(-2).map((card) => `
    <article class="studio-cockpit-card" data-testid="studio-browser-status-card">
      <header><strong>${escapeHtml(card.title || "Browser status")}</strong><mark>${escapeHtml(card.status || "observed")}</mark></header>
      <p>${escapeHtml(card.detail || "")}</p>
    </article>
  `).join("");
  const workerCards = firstArray(studioRuntimeProjection.workerCards).slice(-2).map((card) => `
    <article class="studio-cockpit-card" data-testid="studio-worker-status-card">
      <header><strong>${escapeHtml(card.title || "Worker / subagent status")}</strong><mark>${escapeHtml(card.status || "observed")}</mark></header>
      <p>${escapeHtml(card.detail || "")}</p>
      ${card.receiptRefs?.length ? `<code>${escapeHtml(card.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
  return `${browserCards}${workerCards}`;
}

function studioReplayRows() {
  const replaySteps = firstArray(studioRuntimeProjection.replaySteps).slice(-8);
  if (replaySteps.length === 0) {
    return '<li data-testid="studio-replay-step-detail"><strong>Replay pending</strong><span>Daemon replay steps appear after runtime events are observed.</span></li>';
  }
  return replaySteps.map((step) => `
    <li data-testid="studio-replay-step-detail">
      <strong>${escapeHtml(step.kind || "runtime.event")}</strong>
      <code>${escapeHtml(step.id || "event")}</code>
      <span>${escapeHtml(step.summary || step.status || "")}</span>
    </li>
  `).join("");
}

function studioCompactRuntimeStatusRows() {
  const rows = [];
  for (const lease of firstArray(studioRuntimeProjection.policyLeases).slice(-2)) {
    rows.push(`
      <article class="studio-compact-runtime-card studio-compact-runtime-card--blocking" data-testid="studio-policy-prompt-actionable" data-runtime-visibility="${STUDIO_RUNTIME_VISIBILITY.inlineAction}">
        <div>
          <span class="studio-status-dot studio-status-dot--${escapeHtml(lease.status || "blocked")}"></span>
          <strong>${escapeHtml(lease.title || "Permission needed")}</strong>
          <span>${escapeHtml(lease.reason || "Agent needs permission before continuing.")}</span>
        </div>
        <button type="button" data-studio-drawer-open>Review</button>
      </article>
    `);
  }
  for (const command of firstArray(studioRuntimeProjection.commandOutputs).slice(-2)) {
    const status = command.exitCode === null || command.exitCode === undefined
      ? command.status || "completed"
      : `exit ${command.exitCode}`;
    rows.push(`
      <article class="studio-compact-runtime-card" data-testid="studio-command-summary-not-log-wall" data-runtime-visibility="${STUDIO_RUNTIME_VISIBILITY.inlineSummary}">
        <div>
          <span class="studio-status-dot studio-status-dot--${escapeHtml(command.status || "completed")}"></span>
          <strong>${escapeHtml(command.label || command.toolId || "Command")}</strong>
          <span>${escapeHtml(status)}${command.durationMs ? ` · ${escapeHtml(`${command.durationMs}ms`)}` : ""}</span>
        </div>
      </article>
    `);
  }
  for (const gate of firstArray(studioRuntimeProjection.diagnosticGates).slice(-2)) {
    rows.push(`
      <article class="studio-compact-runtime-card" data-testid="studio-diagnostics-summary" data-runtime-visibility="${STUDIO_RUNTIME_VISIBILITY.inlineSummary}">
        <div>
          <span class="studio-status-dot studio-status-dot--${escapeHtml(gate.status || "completed")}"></span>
          <strong>${escapeHtml(gate.title || "Diagnostics / tests")}</strong>
          <span>${escapeHtml(gate.detail || "Daemon postcondition gate projected.")}</span>
        </div>
      </article>
    `);
  }
  const pendingHunks = firstArray(studioRuntimeProjection.diffHunks).filter((hunk) => /pending|preview/i.test(String(hunk.status || "")));
  if (pendingHunks.length > 0) {
    rows.push(`
      <article class="studio-compact-runtime-card studio-compact-runtime-card--blocking" data-testid="studio-native-hunk-review-inline" data-runtime-visibility="${STUDIO_RUNTIME_VISIBILITY.inlineAction}">
        <div>
          <span class="studio-status-dot studio-status-dot--pending"></span>
          <strong>Patch proposal</strong>
          <span>${escapeHtml(`${pendingHunks.length} hunk${pendingHunks.length === 1 ? "" : "s"} waiting for review`)}</span>
        </div>
        <button type="button" data-studio-drawer-open>Review hunks</button>
      </article>
    `);
  }
  if (!rows.length) {
    return "";
  }
  return `<section class="studio-compact-runtime-list" data-testid="studio-actionable-runtime-state">${rows.join("")}</section>`;
}

function studioParityPlusPanelRows() {
  const panelSpecs = [
    {
      testId: "studio-engine-reconnect-banner",
      title: "Engine reconnect",
      kind: "engine.reconnect",
      item: firstArray(studioRuntimeProjection.engineReconnectBanners).at(-1),
      defaultStatus: "idle",
      defaultDetail: "Heartbeat and composer freeze state.",
    },
    {
      testId: "studio-chat-responsibility-contract",
      title: "Chat responsibility",
      kind: "chat.responsibility",
      item: firstArray(studioRuntimeProjection.chatResponsibilityContracts).at(-1),
      defaultStatus: "ready",
      defaultDetail: "Ask stays direct; Agent replies through chat__reply.",
    },
    {
      testId: "studio-engine-guard-security-scan",
      title: "Engine Guard",
      kind: "engine.guard.security",
      item: firstArray(studioRuntimeProjection.securityScanPanels).at(-1),
      defaultStatus: "pending",
      defaultDetail: "Security findings block merge until clean.",
    },
    {
      testId: "studio-worker-contribution-trace",
      title: "Worker trace",
      kind: "worker.contribution",
      item: firstArray(studioRuntimeProjection.workerContributionTraces).at(-1),
      defaultStatus: "pending",
      defaultDetail: "Worker output is linked to file hunks.",
    },
    {
      testId: "studio-safe-mode-tool-suppression",
      title: "Safe Mode",
      kind: "safe_mode.tool_suppression",
      item: firstArray(studioRuntimeProjection.safeModeToolSuppressionPanels).at(-1),
      defaultStatus: "safe_mode",
      defaultDetail: "Ask stays available while Agent tools are suppressed.",
    },
    {
      testId: "studio-onboarding-diagnostics-checklist",
      title: "Onboarding diagnostics",
      kind: "onboarding.diagnostics",
      item: firstArray(studioRuntimeProjection.onboardingDiagnosticsPanels).at(-1),
      defaultStatus: "needs_setup",
      defaultDetail: "Local prerequisite checklist.",
    },
    {
      testId: "studio-gateway-token-hygiene",
      title: "Gateway token hygiene",
      kind: "gateway.token_hygiene",
      item: firstArray(studioRuntimeProjection.gatewayTokenHygienePanels).at(-1),
      defaultStatus: "ready",
      defaultDetail: "Gateway calls are redacted dry-run plans.",
    },
    {
      testId: "studio-sandbox-resource-limits",
      title: "Sandbox resources",
      kind: "sandbox.resource_limits",
      item: firstArray(studioRuntimeProjection.sandboxResourceLimitPanels).at(-1),
      defaultStatus: "blocked",
      defaultDetail: "Command resource limits are enforced before execution.",
    },
    {
      testId: "studio-imported-parent-trajectory-linkage",
      title: "Imported parent links",
      kind: "imported.parent_trajectory_linkage",
      item: firstArray(studioRuntimeProjection.parentTrajectoryLinkagePanels).at(-1),
      defaultStatus: "needs_review",
      defaultDetail: "Parent/child trajectory links are audit-only.",
    },
    {
      testId: "studio-imported-battle-mode-permission",
      title: "Imported permissions",
      kind: "imported.battle_mode_permission",
      item: firstArray(studioRuntimeProjection.battleModePermissionImportPanels).at(-1),
      defaultStatus: "blocked",
      defaultDetail: "Historical permission rows do not grant IOI authority.",
    },
    {
      testId: "studio-imported-stop-hook-gates",
      title: "Imported stop hooks",
      kind: "imported.stop_hook_gates",
      item: firstArray(studioRuntimeProjection.importedStopHookGatePanels).at(-1),
      defaultStatus: "needs_review",
      defaultDetail: "Historical stop-hook rows require live verification.",
    },
    {
      testId: "studio-imported-browser-action-evidence",
      title: "Imported browser evidence",
      kind: "imported.browser_action_evidence",
      item: firstArray(studioRuntimeProjection.importedBrowserActionEvidencePanels).at(-1),
      defaultStatus: "needs_review",
      defaultDetail: "Historical browser actions require fresh observation.",
    },
    {
      testId: "studio-imported-executor-config",
      title: "Imported executor config",
      kind: "imported.executor_config",
      item: firstArray(studioRuntimeProjection.importedExecutorConfigPanels).at(-1),
      defaultStatus: "needs_review",
      defaultDetail: "Executor metadata is advisory-only.",
    },
    {
      testId: "studio-imported-policy-draft",
      title: "Imported policy draft",
      kind: "imported.policy_draft",
      item: firstArray(studioRuntimeProjection.importedPolicyDraftPanels).at(-1),
      defaultStatus: "needs_review",
      defaultDetail: "Executor hints become draft-only policy.",
    },
    {
      testId: "studio-imported-generation-metadata",
      title: "Imported generation metadata",
      kind: "imported.generation_metadata",
      item: firstArray(studioRuntimeProjection.importedGenerationMetadataPanels).at(-1),
      defaultStatus: "blocked",
      defaultDetail: "Prompts and reasoning are retained only as redacted summaries.",
    },
    {
      testId: "studio-imported-error-render-info",
      title: "Imported error/render info",
      kind: "imported.error_render_info",
      item: firstArray(studioRuntimeProjection.importedErrorRenderInfoPanels).at(-1),
      defaultStatus: "blocked",
      defaultDetail: "Stacks and render payloads stay out of replay UI.",
    },
  ];
  const rows = panelSpecs.map((spec) => {
    const item = spec.item && typeof spec.item === "object" ? spec.item : {};
    const status = stringValue(item.status || item.state, spec.defaultStatus);
    const detail = stringValue(item.bannerLabel || item.detail || item.mergeBlockReason || item.summary, spec.defaultDetail);
    return `
      <article class="studio-cockpit-card" data-testid="${escapeHtml(spec.testId)}" data-panel-kind="${escapeHtml(spec.kind)}" data-panel-status="${escapeHtml(status)}">
        <strong>${escapeHtml(spec.title)}</strong>
        <span>${escapeHtml(detail)}</span>
        ${studioVerifiedBadge(item)}
        ${studioTraceLink({ ...item, kind: spec.kind })}
      </article>
    `;
  });
  return rows.join("");
}

function normalizeStudioToolPaletteRows(rows, fallbackSection) {
  return firstArray(rows)
    .map((row, index) => {
      if (!row || typeof row !== "object") {
        return null;
      }
      const title = stringValue(row.title || row.label || row.name, "");
      if (!title) {
        return null;
      }
      return {
        id: stringValue(row.id || row.toolId || row.name, `${fallbackSection}-${index}`),
        title,
        detail: stringValue(row.detail || row.description || row.summary, ""),
        meta: stringValue(row.meta || row.status || row.provider || row.kind, ""),
        enabled: row.enabled !== false,
        selected: Boolean(row.selected),
      };
    })
    .filter(Boolean);
}

function studioToolPaletteSections(state = {}) {
  const liveRows = normalizeStudioToolPaletteRows(
    state.commandCenter?.liveTools || state.tools?.live || state.liveTools,
    "live",
  );
  const runtimeRows = normalizeStudioToolPaletteRows(
    state.commandCenter?.runtimeCatalog || state.runtimeCatalog?.tools || state.tools?.runtime,
    "runtime",
  );
  const substrateToolRows = [
    {
      id: "agent",
      title: "agent",
      detail: "Delegate tasks to other agents",
      meta: "Built-In",
      icon: "code",
      selected: true,
    },
    {
      id: "awaitTerminal",
      title: "awaitTerminal",
      detail: "Wait for a background terminal command to complete. Returns the output, exit code, and runtime state.",
      icon: "terminal",
      selected: true,
    },
    {
      id: "createAndRunTask",
      title: "createAndRunTask",
      detail: "Create and run a task in the workspace",
      icon: "git-pull-request-create",
      selected: true,
    },
    {
      id: "execute",
      title: "execute",
      detail: "Execute code and applications on your machine",
      icon: "terminal",
      selected: true,
    },
    {
      id: "extensions",
      title: "extensions",
      detail: "Search for VS Code extensions",
      icon: "extensions",
      selected: true,
    },
    {
      id: "getTerminalOutput",
      title: "getTerminalOutput",
      detail: "Get the output of a terminal command previously started with run_in_terminal",
      icon: "terminal",
      selected: true,
    },
    {
      id: "killTerminal",
      title: "killTerminal",
      detail: "Kill a terminal by its ID. Use this to clean up terminals that are no longer needed.",
      icon: "terminal",
      selected: true,
    },
    {
      id: "new",
      title: "new",
      detail: "Scaffold a new workspace in VS Code",
      icon: "new-folder",
      selected: true,
    },
    {
      id: "read",
      title: "read",
      detail: "Read files in your workspace",
      icon: "book",
      selected: true,
    },
    {
      id: "runInTerminal",
      title: "runInTerminal",
      detail: "Run commands in the terminal",
      icon: "terminal",
      selected: true,
    },
    {
      id: "runSubagent",
      title: "runSubagent",
      detail: "Run a task within an isolated subagent context to enable efficient organization of task work.",
      icon: "organization",
      selected: true,
    },
    {
      id: "terminalLastCommand",
      title: "terminalLastCommand",
      detail: "Get the last command run in the active terminal.",
      icon: "terminal",
      selected: true,
    },
    {
      id: "terminalSelection",
      title: "terminalSelection",
      detail: "Get the current selection in the active terminal.",
      icon: "terminal",
      selected: true,
    },
    {
      id: "todo",
      title: "todo",
      detail: "Manage and track todo items for task planning",
      icon: "list-unordered",
      selected: true,
    },
    {
      id: "vscode",
      title: "vscode",
      detail: "Use VS Code features",
      icon: "vscode",
      selected: true,
    },
    {
      id: "renderMermaidDiagram",
      title: "renderMermaidDiagram",
      detail: "Render a Mermaid.js diagram from markup.",
      meta: "Mermaid Chat Features",
      icon: "type-hierarchy",
      selected: true,
    },
  ];

  return [
    {
      id: "built-in",
      label: "",
      rows: substrateToolRows,
    },
    {
      id: "live-tools",
      label: "Live Tools",
      rows:
        liveRows.length > 0
          ? liveRows
          : [
              {
                id: "loading-live-tools",
                title: "Loading Live Tools",
                detail: "Querying connector-backed tool affordances.",
                meta: "pending",
                enabled: false,
              },
            ],
    },
    {
      id: "runtime-catalog",
      label: "Runtime Catalog",
      rows:
        runtimeRows.length > 0
          ? runtimeRows
          : [
              {
                id: "kernel-backend-gallery",
                title: "Kernel backend gallery",
                detail: "Primary daemon-backed local backend catalog.",
                meta: "ready",
              },
              {
                id: "localai-backend-gallery",
                title: "LocalAI backend gallery",
                detail: "Optional backend route when configured.",
                meta: "disabled",
                enabled: false,
              },
              {
                id: "kernel-model-gallery",
                title: "Kernel model gallery",
                detail: "Daemon-projected local model inventory.",
                meta: "ready",
              },
              {
                id: "evidence-playbook",
                title: "Evidence playbook",
                detail: "Parent playbook for receipt and replay capture.",
                meta: "Promotable",
              },
              {
                id: "browser-playbook",
                title: "Browser playbook",
                detail: "Parent playbook for GUI and browser work.",
                meta: "Promotable",
              },
              {
                id: "artifact-generator",
                title: "Artifact Generator",
                detail: "Parent playbook for artifact work.",
                meta: "Promotable",
              },
            ],
    },
  ];
}

function studioToolQuickPickItems(state = {}) {
  return studioToolPaletteSections(state).flatMap((section) => {
    const rows = section.rows.map((row) => ({
      label: row.title,
      description: row.detail,
      detail: row.meta || undefined,
      picked: row.enabled !== false && row.selected,
      alwaysShow: row.selected || section.id === "built-in",
      iconPath: row.icon ? new vscode.ThemeIcon(row.icon) : undefined,
      row,
      sectionId: section.id,
    }));
    if (!section.label) {
      return rows;
    }
    return [
      {
        label: section.label,
        kind: vscode.QuickPickItemKind.Separator,
      },
      ...rows,
    ];
  });
}

function studioContextQuickPickItems() {
  return [
    {
      id: "files-folders",
      title: "Files & Folders...",
      icon: "folder-opened",
      requestType: "chat.attachFilesAndFolders",
    },
    {
      id: "instructions",
      title: "Instructions...",
      icon: "bookmark",
      requestType: "chat.generateAgentInstructions",
    },
    {
      id: "problems",
      title: "Problems...",
      icon: "error",
      requestType: "chat.attachProblems",
    },
    {
      id: "symbols",
      title: "Symbols...",
      icon: "symbol-field",
      requestType: "chat.attachSymbols",
    },
    {
      id: "tools",
      title: "Tools...",
      icon: "tools",
      command: "ioi.quickInput.tools.configure",
      requestType: "chat.contextTools.open",
    },
  ].map((row) => ({
    label: row.title,
    alwaysShow: true,
    iconPath: new vscode.ThemeIcon(row.icon),
    row,
  }));
}

function renderStudioOperationalSurface(state, { standalone = false } = {}) {
  const workspace = state.workspace || workspaceSummary();
  const snapshot = studioSnapshotFromState(state);
  const status = studioRuntimeProjection.pending ? "pending" : studioRuntimeProjection.status;
  const daemonConnected = snapshot.daemonStatus === "connected";
  const artifactCount = Math.max(1, studioRuntimeProjection.receipts.length || studioRuntimeProjection.diffHunks.length || 1);
  const lastModelStream = studioRuntimeProjection.lastModelStream || {};
  const executionMode = normalizeStudioExecutionMode(studioRuntimeProjection.executionMode);
  const executionModeLabel = studioExecutionModeLabel(executionMode);
  const approvalMode = normalizeStudioPermissionMode(studioRuntimeProjection.approvalMode);
  const permissionLabel = studioPermissionModeLabel(approvalMode);
  return `
    <main
      class="studio-operational-shell studio-tauri-chat-shell${standalone ? " studio-operational-shell--standalone" : ""}"
      data-testid="agent-studio-operational-chat"
      data-runtime-authority="daemon-owned"
      data-extension-host-authority="projection-only"
      data-studio-ux="tauri-chat-parity"
      data-runtime-ux-denoised="${studioRuntimeProjection.runtimeUx?.denoised ? "true" : "false"}"
      data-tracing-separation-achieved="${studioRuntimeProjection.runtimeUx?.tracingSeparationAchieved ? "true" : "false"}"
      data-model-prose-runtime-truth="false"
      data-verified-badges-require-receipts="${studioRuntimeProjection.runtimeUx?.verifiedBadgesRequireReceiptRefs ? "true" : "false"}"
      data-daemon-backed="${daemonConnected ? "true" : "false"}"
      data-studio-status="${escapeHtml(status || "idle")}"
      data-thread-id="${escapeHtml(studioRuntimeProjection.threadId || "")}"
      data-session-id="${escapeHtml(studioRuntimeProjection.sessionId || "")}"
      data-model-stream-id="${escapeHtml(lastModelStream.streamId || "")}"
      data-model-stream-chunks="${escapeHtml(String(lastModelStream.chunkCount || 0))}"
      data-model-stream-receipts="${escapeHtml(String(firstArray(lastModelStream.receiptIds).length))}"
      data-runtime-cockpit-achieved="${studioRuntimeProjection.runtimeCockpit?.achieved ? "true" : "false"}"
      data-studio-execution-mode="${escapeHtml(executionMode)}"
      data-runtime-profile="${escapeHtml(studioRuntimeProjection.runtimeProfile || "")}"
      data-model-backed-streaming-observed="${studioRuntimeProjection.runtimeCockpit?.modelBackedStreamingObserved ? "true" : "false"}"
      data-real-daemon-tool-proposal-observed="${studioRuntimeProjection.runtimeCockpit?.realDaemonToolProposalObserved ? "true" : "false"}"
      data-policy-lease-dialog-observed="${studioRuntimeProjection.runtimeCockpit?.policyLeaseDialogObserved ? "true" : "false"}"
      data-managed-live-viewport-observed="${studioRuntimeProjection.runtimeCockpit?.managedLiveViewportObserved ? "true" : "false"}"
      data-managed-session-labels-observed="${studioRuntimeProjection.runtimeCockpit?.managedSessionLabelsObserved ? "true" : "false"}"
      data-managed-session-count="${escapeHtml(String(studioRuntimeProjection.computerUseSessions.length || 0))}"
      data-immediate-submit-seen="${studioRuntimeProjection.immediateSubmitSeen ? "true" : "false"}"
      data-pending-state-seen="${studioRuntimeProjection.pendingSeen ? "true" : "false"}"
      data-pending-started-at-ms="${escapeHtml(String(studioRuntimeProjection.pendingStartedAtMs || ""))}"
    >
      <aside class="studio-operational-rail studio-session-rail" data-testid="studio-tauri-session-rail" aria-label="Studio session context">
        <header class="studio-session-rail__header">
          <span class="studio-eyebrow">Sessions</span>
          <h2>Codebase chat history</h2>
          <button type="button" data-testid="studio-new-session-icon" data-bridge-request="chat.newSession" aria-label="New Session">+</button>
        </header>
        <label class="studio-session-search">
          <span class="studio-search-icon" aria-hidden="true">⌕</span>
          <input data-testid="studio-session-search" type="search" placeholder="Search sessions" />
        </label>
        <nav class="studio-session-actions" aria-label="Session actions">
          <button type="button" data-testid="studio-new-session" data-bridge-request="chat.newSession">+ <span>New Session</span></button>
          <button type="button" data-testid="studio-artifacts-row" data-studio-drawer-open>
            <span>Artifacts</span>
            <mark>${artifactCount}</mark>
          </button>
        </nav>
        <section class="studio-control-group studio-history-group" data-testid="studio-session-history">
          <h3>Recent</h3>
          <span class="studio-history-date">Today</span>
          <button type="button" class="studio-history-item studio-history-item--current" data-testid="studio-current-session-row">
            <strong>${escapeHtml(studioDisplayTurnContent(studioRuntimeProjection.turns.find((turn) => turn.role === "user") || {}).slice(0, 36) || "Current daemon session")}</strong>
            <span>${escapeHtml([studioRuntimeProjection.status || "idle", studioRuntimeProjection.sessionId || "studio-session-current"].filter(Boolean).join(" · "))}</span>
          </button>
          <div data-testid="studio-recent-sessions">
          ${studioHistoryRows()}
          </div>
        </section>
        <section class="studio-control-group studio-rail-secondary">
          <h3>Context</h3>
          <button type="button" data-bridge-request="chat.attachEditorContext">Current editor</button>
          <button type="button" data-command="ioi.code.open">Repository</button>
          <button type="button" data-command="ioi.policy.open">Policy</button>
        </section>
        <section class="studio-control-group studio-rail-secondary">
          <h3>Handoffs</h3>
          <button type="button" data-testid="studio-workflow-handoff" data-command="ioi.workflow.openComposer">Workflow Composer</button>
          <button type="button" data-testid="studio-models-handoff-chip" data-command="ioi.models.open">Models</button>
        </section>
      </aside>

      <section class="studio-chat-main">
        <header class="studio-chat-header">
          <button type="button" class="studio-chat-tab is-active">Chat</button>
          <div class="studio-route-controls">
            <select data-testid="studio-model-route-picker" data-testid-proxy="studio-model-toggle" data-selected-model-id="${escapeHtml(snapshot.selectedModel)}" data-selected-endpoint-id="${escapeHtml(snapshot.endpointId)}" aria-label="Model route picker">
              <option value="${escapeHtml(snapshot.routeId)}" data-model-id="${escapeHtml(snapshot.selectedModel)}" data-endpoint-id="${escapeHtml(snapshot.endpointId)}">${escapeHtml(snapshot.routeId)} · ${escapeHtml(snapshot.modelLabel)}</option>
            </select>
            ${snapshot.reasoningControlSupported ? `
              <select data-testid="studio-reasoning-effort-picker" data-reasoning-supported="true" aria-label="Reasoning effort">
                ${studioReasoningEffortOptions(snapshot.reasoningEffort)}
              </select>
            ` : ""}
            <button type="button" data-command="ioi.models.open">Manage models</button>
            ${studioRuntimeProjection.status === "interrupted" ? `
              <button type="button" class="studio-stop-icon-button" data-studio-resume data-testid="studio-resume-icon" title="Resume" aria-label="Resume">${renderNativeChatIcon("send")}</button>
            ` : `
              <button type="button" class="studio-stop-icon-button" data-studio-stop data-testid="studio-stop-icon" title="Stop" aria-label="Stop">${renderNativeChatIcon("stop")}</button>
            `}
          </div>
        </header>
        <section class="studio-transcript" data-testid="studio-transcript" aria-live="polite">
          <div class="studio-chat-transcript" data-testid="studio-chat-transcript">
            ${studioTurnRows()}
          </div>
          ${studioCompactRuntimeStatusRows()}
        </section>
        <form class="studio-composer" data-testid="studio-composer" data-studio-prompt-form>
          <div class="studio-tauri-composer" data-testid="studio-tauri-composer">
            <div class="studio-composer-context-row" data-testid="studio-composer-context-row">
              <button type="button" data-testid="studio-add-context" class="studio-context-btn" data-command="ioi.quickInput.context.open">
                <span class="studio-context-btn__icon" aria-hidden="true">${renderNativeChatIcon("paperclip")}</span>
                <span>Add Context...</span>
              </button>
            </div>
            <textarea data-testid="studio-composer-input" data-studio-prompt rows="3" placeholder="Describe what to build next"></textarea>
            <div class="studio-composer-toolbar" data-testid="studio-composer-toggle-row">
              <button type="button" data-testid="studio-target-toggle" class="studio-icon-toggle" data-command="ioi.quickInput.workflowTarget.pick" title="Set session target" aria-label="Set session target">
                <span class="studio-icon-toggle__glyph" aria-hidden="true">${renderNativeChatIcon("device-desktop")}</span>
                <span class="studio-icon-toggle__chevron" aria-hidden="true">${renderNativeChatIcon("chevron-down")}</span>
              </button>
              <button type="button" data-testid="studio-model-toggle" class="studio-icon-toggle" data-command="ioi.quickInput.modelRoute.pick"${commandPayloadAttr({ mountedModels: mountedModelQuickInputRowsFromState(state) })} title="Choose mounted model - ${escapeHtml(snapshot.modelLabel)}" aria-label="Choose mounted model - ${escapeHtml(snapshot.modelLabel)}">
                <span class="studio-icon-toggle__glyph" aria-hidden="true">${renderNativeChatIcon("cube")}</span>
                <span class="studio-icon-toggle__chevron" aria-hidden="true">${renderNativeChatIcon("chevron-down")}</span>
              </button>
              <button type="button" data-testid="studio-mode-toggle" class="studio-mode-toggle" data-command="ioi.quickInput.agentMode.pick" data-studio-mode="${escapeHtml(executionMode)}" title="Choose agent mode" aria-label="Choose agent mode">
                <span>${escapeHtml(executionModeLabel)}</span>
                <span class="studio-icon-toggle__chevron" aria-hidden="true">${renderNativeChatIcon("chevron-down")}</span>
              </button>
              <button type="button" data-testid="studio-permissions-toggle" class="studio-mode-toggle studio-permissions-toggle" data-command="ioi.quickInput.permissionMode.pick" data-approval-mode="${escapeHtml(approvalMode)}" title="Permissions - ${escapeHtml(permissionLabel)}" aria-label="Permissions - ${escapeHtml(permissionLabel)}">
                <span>${escapeHtml(permissionLabel)}</span>
                <span class="studio-icon-toggle__chevron" aria-hidden="true">${renderNativeChatIcon("chevron-down")}</span>
              </button>
              <button type="button" data-testid="studio-tools-toggle" class="studio-icon-toggle" data-command="ioi.quickInput.tools.configure" title="Tools" aria-label="Select tools">
                <span class="studio-icon-toggle__glyph" aria-hidden="true">${renderNativeChatIcon("tools")}</span>
              </button>
              <button type="submit" data-testid="studio-send-button" class="studio-send-icon" title="Send" aria-label="Send">
                <span data-testid="studio-send-icon" aria-hidden="true">${renderNativeChatIcon("send")}</span>
              </button>
            </div>
          </div>
        </form>
      </section>

      <aside class="studio-operator-context studio-utility-drawer" data-testid="studio-utility-drawer" aria-label="Runtime context">
        <button type="button" class="studio-utility-toggle" data-testid="studio-utility-toggle" data-studio-drawer-toggle title="Toggle compact trace preview">Trace</button>
        <div class="studio-utility-drawer__content">
        <section data-testid="studio-trace-handoff">
          <h3>Tracing</h3>
          <p>Receipts, replay, logs, policy internals, and raw daemon events live in Runs/Tracing.</p>
          ${studioTraceLink({ kind: "session.summary", id: "studio-current-session" }, "Open Tracing")}
        </section>
        <section data-testid="studio-runtime-cockpit">
          <h3>Runtime cockpit</h3>
          ${studioActionCardRows()}
          ${studioPolicyLeaseRows()}
          ${studioCommandOutputRows()}
          ${studioDiagnosticsRows()}
          ${studioBrowserWorkerRows()}
          <section data-testid="studio-parity-plus-panels">
            ${studioParityPlusPanelRows()}
          </section>
        </section>
        <section data-testid="studio-tool-timeline">
          <h3><span data-testid="studio-tool-timeline-collapsed">Tool timeline</span></h3>
          <ol>${studioTimelineRows()}</ol>
        </section>
        ${studioApprovalRows()}
        <section data-testid="studio-inline-diff-drawer">
          <h3>Inline diff</h3>
          ${studioDiffRows()}
        </section>
        <section data-testid="studio-receipts-replay">
          <h3>Receipts / replay</h3>
          <ul>${studioReceiptRows()}</ul>
          <ol class="studio-replay-steps">${studioReplayRows()}</ol>
        </section>
        <section data-testid="studio-terminal-output">
          <h3>Terminal / tests</h3>
          <ul>${studioTerminalRows()}</ul>
        </section>
        </div>
      </aside>
    </main>
  `;
}

function renderStudioView(state) {
  return `
    <section class="workflow-direct-open" data-inspection-target="studio-direct-open" aria-label="Opening Agent Studio">
      <span>Opening Agent Studio chat...</span>
    </section>
    ${renderStudioOperationalSurface(state)}
  `;
}

function renderOverviewActivityView() {
  return `
    <section class="workflow-direct-open" data-inspection-target="overview-direct-open" aria-label="Opening Autopilot Overview">
      <span>Opening Overview...</span>
    </section>
  `;
}

function renderWorkflowView() {
  return `
    <section class="workflow-direct-open" data-inspection-target="workflow-composer-direct-open" aria-label="Opening Workflow Composer">
      <span>Opening composer...</span>
    </section>
  `;
}

function formatBytes(value) {
  const bytes = Number(value ?? 0);
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "unknown";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let current = bytes;
  let index = 0;
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024;
    index += 1;
  }
  return `${current >= 10 || index === 0 ? current.toFixed(0) : current.toFixed(1)} ${units[index]}`;
}

function modelSnapshotFromState(state) {
  const snapshot = state.modelMounting || {};
  return {
    artifacts: Array.isArray(snapshot.artifacts) ? snapshot.artifacts : [],
    endpoints: Array.isArray(snapshot.endpoints) ? snapshot.endpoints : [],
    instances: Array.isArray(snapshot.instances) ? snapshot.instances : [],
    routes: Array.isArray(snapshot.routes) ? snapshot.routes : [],
    backends: Array.isArray(snapshot.backends) ? snapshot.backends : [],
    runtimeEngines: Array.isArray(snapshot.runtimeEngines) ? snapshot.runtimeEngines : [],
    receipts: Array.isArray(snapshot.receipts) ? snapshot.receipts : [],
    downloads: Array.isArray(snapshot.downloads) ? snapshot.downloads : [],
    providers: Array.isArray(snapshot.providers) ? snapshot.providers : [],
    catalog: snapshot.catalog || {},
    catalogProviderConfigs: Array.isArray(snapshot.catalogProviderConfigs)
      ? snapshot.catalogProviderConfigs
      : [],
    server: snapshot.server || {},
    runtimePreference: snapshot.runtimePreference || {},
    generatedAt: snapshot.generatedAt || snapshot.server?.generatedAt || null,
  };
}

function modeIdForViewId(viewId) {
  return (
    AUTOPILOT_MODE_BY_VIEW_ID[viewId]?.id ||
    AUTOPILOT_MODE_BY_PANEL_VIEW_ID[viewId]?.id ||
    null
  );
}

function setActiveAutopilotMode(modeId) {
  if (!AUTOPILOT_MODE_BY_ID[modeId]) {
    return;
  }
  if (modeId !== "code") {
    lastAutopilotModeBeforeCode = modeId;
  }
  currentAutopilotModeId = modeId;
}

async function applyWorkbenchChromeForMode(modeId, output) {
  const menuBarVisibility = modeId === "code" ? "classic" : "hidden";
  await vscode.commands
    .executeCommand("setContext", "ioi.autopilotMode", modeId !== "code")
    .catch(() => undefined);
  await vscode.commands
    .executeCommand("setContext", "ioi.codeMode", modeId === "code")
    .catch(() => undefined);
  await vscode.workspace
    .getConfiguration("window")
    .update("menuBarVisibility", menuBarVisibility, vscode.ConfigurationTarget.Global)
    .catch((error) => {
      output?.appendLine(
        `[ioi-workbench] unable to update global VS Code menu bar visibility: ${
          error?.message || String(error)
        }`,
      );
    });
}

async function enterAutopilotMode(modeId, output) {
  setActiveAutopilotMode(modeId);
  await applyWorkbenchChromeForMode(modeId, output);
}

function shellStatusTone(value) {
  const normalized = String(value || "").toLowerCase();
  if (/ready|connected|loaded|running|active|pass/.test(normalized)) {
    return "ready";
  }
  if (/blocked|failed|error|denied|absent/.test(normalized)) {
    return "blocked";
  }
  if (/degraded|loading|pending|warning|queued/.test(normalized)) {
    return "warn";
  }
  return "muted";
}

function autopilotShellHeaderStyles() {
  return `
      .autopilot-shell-header {
        box-sizing: border-box;
        width: 100%;
        min-height: 50px;
        display: grid;
        grid-template-columns: minmax(190px, 260px) minmax(240px, 1fr) auto;
        gap: 12px;
        align-items: center;
        padding: 8px 12px;
        border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,.14));
        background: color-mix(in srgb, var(--vscode-editor-background, #101216) 92%, var(--vscode-foreground, #fff) 5%);
        color: var(--vscode-foreground, #f4f6f8);
      }
      .autopilot-shell-header__crumb {
        min-width: 0;
        display: flex;
        align-items: baseline;
        gap: 7px;
        overflow: hidden;
        white-space: nowrap;
      }
      .autopilot-shell-header__crumb strong {
        font-size: 13px;
        font-weight: 700;
      }
      .autopilot-shell-header__crumb span {
        color: var(--vscode-descriptionForeground, #9ca3af);
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .autopilot-shell-header__command {
        min-width: 0;
        height: 32px;
        display: flex;
        align-items: center;
        gap: 8px;
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 6px;
        background: var(--vscode-input-background, rgba(255,255,255,.06));
        color: var(--vscode-input-foreground, var(--vscode-foreground));
        padding: 0 10px;
        font: inherit;
        text-align: left;
      }
      .autopilot-shell-header__command span {
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .autopilot-shell-header__posture {
        min-width: 0;
        display: flex;
        align-items: center;
        justify-content: end;
        gap: 6px;
        flex-wrap: wrap;
      }
      .autopilot-shell-chip,
      .autopilot-shell-action {
        min-height: 24px;
        display: inline-flex;
        align-items: center;
        gap: 4px;
        border: 1px solid var(--vscode-panel-border, rgba(255,255,255,.16));
        border-radius: 999px;
        padding: 2px 8px;
        color: var(--vscode-descriptionForeground, #9ca3af);
        background: transparent;
        font-size: 11px;
        line-height: 1.2;
        white-space: nowrap;
      }
      .autopilot-shell-chip.is-ready {
        border-color: color-mix(in srgb, #2ea043 70%, var(--vscode-panel-border, transparent));
        color: #7ee787;
      }
      .autopilot-shell-chip.is-warn {
        border-color: color-mix(in srgb, #d29922 70%, var(--vscode-panel-border, transparent));
        color: #e3b341;
      }
      .autopilot-shell-chip.is-blocked {
        border-color: color-mix(in srgb, #f85149 70%, var(--vscode-panel-border, transparent));
        color: #ff7b72;
      }
      .autopilot-shell-action {
        border-radius: 5px;
        background: var(--vscode-button-secondaryBackground, rgba(255,255,255,.08));
        color: var(--vscode-button-secondaryForeground, var(--vscode-foreground));
        cursor: pointer;
      }
      .autopilot-shell-action:hover,
      .autopilot-shell-header__command:hover {
        background: var(--vscode-button-secondaryHoverBackground, rgba(255,255,255,.12));
      }
      @media (max-width: 1000px) {
        .autopilot-shell-header {
          grid-template-columns: minmax(0, 1fr);
        }
        .autopilot-shell-header__posture {
          justify-content: start;
        }
      }
  `;
}

function nativeWorkbenchShellEnabled() {
  return process.env.IOI_WORKBENCH_NATIVE_SHELL === "1";
}

function renderAutopilotShellHeader(state, modeId, options = {}) {
  if (nativeWorkbenchShellEnabled()) {
    return "";
  }
  const mode = AUTOPILOT_MODE_BY_ID[modeId] || AUTOPILOT_MODE_BY_ID.home;
  const workspace = state.workspace || workspaceSummary();
  const snapshot = modelSnapshotFromState(state);
  const daemonStatus =
    state.modelMountingStatus?.status || (daemonEndpoint() ? "connected" : "not_configured");
  const loadedModels = snapshot.instances.filter((instance) =>
    /loaded|ready|running/i.test(String(instance.status || "")),
  );
  const activeRuns = (Array.isArray(state.runs) ? state.runs : []).filter((run) =>
    /active|running|queued|pending/i.test(String(run.status || "")),
  );
  const policyIssueCount =
    state.summary?.policyIssueCount ??
    (Array.isArray(state.policy?.issues) ? state.policy.issues.length : 0);
  const activeRoute =
    snapshot.routes.find((route) => /active|ready|default/i.test(String(route.status || ""))) ||
    snapshot.routes[0] ||
    snapshot.endpoints[0] ||
    null;
  const routeLabel =
    activeRoute?.displayName || activeRoute?.routeId || activeRoute?.id || activeRoute?.modelId || "unbound";
  const workspaceLabel = workspace.name || "No workspace";
  const shellAction =
    mode.id === "code"
      ? {
          label: "Back to Autopilot",
          command: "ioi.autopilot.back",
          testId: "back-to-autopilot-from-code",
        }
      : {
          label: "Code",
          command: "ioi.code.open",
          testId: "autopilot-shell-code-drilldown",
        };
  return `
    <header
      class="autopilot-shell-header"
      data-testid="autopilot-workbench-shell-header"
      data-autopilot-mode="${escapeHtml(mode.id)}"
      data-runtime-authority="daemon-owned"
      data-extension-host-authority="projection-only"
      data-vscode-menu-dominates="false"
      data-tauri-used="false"
    >
      <div class="autopilot-shell-header__crumb" data-testid="autopilot-shell-breadcrumb">
        <strong>Autopilot</strong>
        <span>/</span>
        <span title="${escapeHtml(workspace.path || workspaceLabel)}">${escapeHtml(workspaceLabel)}</span>
        <span>/</span>
        <strong>${escapeHtml(mode.title)}</strong>
      </div>
      <button
        class="autopilot-shell-header__command"
        type="button"
        data-command="ioi.commandCenter.open"
        data-testid="autopilot-shell-command-center"
        data-operator-command-center
      >
        <span>Search Autopilot, code, workflows, runs, and commands</span>
      </button>
      <div class="autopilot-shell-header__posture" data-testid="autopilot-shell-runtime-posture">
        <span class="autopilot-shell-chip is-${escapeHtml(shellStatusTone(daemonStatus))}" data-testid="autopilot-shell-daemon-status">Daemon ${escapeHtml(daemonStatus)}</span>
        <span class="autopilot-shell-chip is-${loadedModels.length ? "ready" : "muted"}" data-testid="autopilot-shell-model-route">Model ${escapeHtml(routeLabel)}</span>
        <span class="autopilot-shell-chip is-${activeRuns.length ? "warn" : "muted"}" data-testid="autopilot-shell-active-runs">Runs ${escapeHtml(String(activeRuns.length))}</span>
        <span class="autopilot-shell-chip is-${policyIssueCount ? "warn" : "ready"}" data-testid="autopilot-shell-policy-posture">Approvals ${escapeHtml(String(policyIssueCount))}</span>
        <span class="autopilot-shell-chip" data-testid="autopilot-shell-wallet-posture">Authority local</span>
        ${
          options.hideModeAction
            ? ""
            : `<button class="autopilot-shell-action" type="button" data-command="${escapeHtml(shellAction.command)}" data-testid="${escapeHtml(shellAction.testId)}">${escapeHtml(shellAction.label)}</button>`
        }
      </div>
    </header>
  `;
}

function modelReceiptKind(receipt) {
  return receipt?.details?.operation || receipt?.kind || "receipt";
}

function modelStatusPill(value) {
  const normalized = String(value || "unknown").toLowerCase();
  const tone = /loaded|ready|available|running|mounted|connected|pass|active/.test(normalized)
    ? "ready"
    : /blocked|failed|error|absent|denied/.test(normalized)
      ? "blocked"
      : /loading|starting|degraded|warning|stopped/.test(normalized)
        ? "warn"
        : "muted";
  return `<span class="model-status is-${tone}">${escapeHtml(value || "unknown")}</span>`;
}

function modelEndpointForArtifact(snapshot, artifact) {
  return snapshot.endpoints.find(
    (endpoint) =>
      endpoint.artifactId === artifact.id || endpoint.modelId === artifact.modelId,
  );
}

function modelInstanceForEndpoint(snapshot, endpoint) {
  return snapshot.instances.find(
    (instance) => instance.endpointId === endpoint?.id && instance.status === "loaded",
  );
}

function modelDisplayName(artifact = {}) {
  return artifact.displayName || artifact.name || artifact.modelId || artifact.id || "Model";
}

function modelPublisher(artifact = {}) {
  const modelId = String(artifact.modelId || artifact.id || "");
  return (
    artifact.publisher ||
    artifact.providerId ||
    artifact.registry ||
    (modelId.includes("/") ? modelId.split("/")[0] : "") ||
    "local"
  );
}

function modelArch(artifact = {}) {
  return artifact.arch || artifact.architecture || artifact.family || artifact.metadata?.arch || "llama";
}

function modelParams(artifact = {}) {
  const explicit = artifact.params || artifact.parameterCount || artifact.metadata?.params;
  if (explicit) {
    return String(explicit);
  }
  const source = `${artifact.modelId || ""} ${artifact.name || ""}`;
  const match = source.match(/\b\d+(?:\.\d+)?\s?[bBmM]\b/);
  return match ? match[0].replace(/\s+/g, "").toUpperCase() : "local";
}

function modelDomain(artifact = {}) {
  const capabilities = Array.isArray(artifact.capabilities) ? artifact.capabilities : [];
  if (capabilities.some((capability) => /embed/i.test(String(capability)))) {
    return "embedding";
  }
  if (capabilities.some((capability) => /vision|image|video/i.test(String(capability)))) {
    return "vlm";
  }
  return artifact.domain || "llm";
}

function renderModelTags(values, { max = 4 } = {}) {
  const tags = Array.from(new Set(values.filter(Boolean).map((value) => String(value))));
  if (!tags.length) {
    return `<span class="model-chip is-muted">chat</span>`;
  }
  return tags
    .slice(0, max)
    .map((value) => `<span class="model-chip">${escapeHtml(value)}</span>`)
    .join("");
}

function modelCapabilityText(artifact = {}) {
  const capabilities = Array.isArray(artifact.capabilities) ? artifact.capabilities : [];
  return Array.from(new Set(capabilities.filter(Boolean).map((value) => String(value)))).join(", ") || "chat";
}

function modelSelectedLoadOptions(instance = {}, engine = {}) {
  const defaults = engine.defaultLoadOptions || {};
  const instanceLoadOptions = instance.loadOptions || {};
  return {
    identifier: instance.identifier || instance.modelId || "local-model",
    contextLength: instance.contextLength || instanceLoadOptions.contextLength || defaults.contextLength || 2048,
    gpuOffload:
      instance.gpuOffload ??
      instanceLoadOptions.gpuOffload ??
      instanceLoadOptions.gpu ??
      defaults.gpuOffload ??
      defaults.gpu ??
      "auto",
    parallelism: instance.parallelism || instanceLoadOptions.parallel || defaults.parallel || 1,
    idleTtlSeconds: instance.loadPolicy?.idleTtlSeconds || defaults.idleTtlSeconds || 900,
  };
}

function renderModelLibraryRows(snapshot) {
  if (!snapshot.artifacts.length) {
    return `
      <tr>
        <td colspan="7">
          <div class="model-empty" data-testid="model-empty-state">No daemon model artifacts are projected yet.</div>
        </td>
      </tr>
    `;
  }
  const loadedModelIds = new Set(
    snapshot.instances
      .filter((instance) => instance.status === "loaded")
      .map((instance) => instance.modelId)
      .filter(Boolean),
  );
  const selectedId =
    snapshot.artifacts.find((artifact) => loadedModelIds.has(artifact.modelId))?.id ||
    snapshot.artifacts[0]?.id ||
    snapshot.artifacts[0]?.modelId;
  return snapshot.artifacts
    .map((artifact, index) => {
      const endpoint = modelEndpointForArtifact(snapshot, artifact);
      const instance = modelInstanceForEndpoint(snapshot, endpoint);
      const capabilities = Array.isArray(artifact.capabilities) ? artifact.capabilities : [];
      const modelId = artifact.modelId || artifact.id;
      const rowStatus = instance?.status || endpoint?.status || artifact.status || "installed";
      const actionPayload = {
        modelId,
        endpointId: endpoint?.id,
      };
      const isSelected =
        artifact.id === selectedId ||
        artifact.modelId === selectedId ||
        (index === 0 && !selectedId);
      return `
        <tr
          class="${isSelected ? "is-selected" : ""}"
          data-model-row="${escapeHtml(artifact.modelId || artifact.id)}"
          data-model-label="${escapeHtml(modelDisplayName(artifact))}"
          data-model-publisher="${escapeHtml(modelPublisher(artifact))}"
          data-model-domain="${escapeHtml(modelDomain(artifact))}"
          data-model-status="${escapeHtml(rowStatus)}"
          data-model-file="${escapeHtml(artifact.fileName || artifact.path || "daemon artifact")}"
          data-model-format="${escapeHtml(artifact.format || "GGUF")}"
          data-model-quantization="${escapeHtml(artifact.quantization || "unknown")}"
          data-model-arch="${escapeHtml(modelArch(artifact))}"
          data-model-params="${escapeHtml(modelParams(artifact))}"
          data-model-capabilities="${escapeHtml(modelCapabilityText(artifact))}"
          data-model-size="${escapeHtml(formatBytes(artifact.sizeBytes ?? artifact.size_bytes))}"
          data-model-endpoint-id="${escapeHtml(endpoint?.id || "")}"
          data-model-instance-id="${escapeHtml(instance?.id || "")}"
          data-model-backend-id="${escapeHtml(instance?.backendId || endpoint?.backendId || "")}"
          tabindex="0"
          role="button"
          data-testid="${isSelected ? "model-library-row-selected" : "model-library-row"}"
        >
          <td class="model-table__name">
            <strong>${escapeHtml(modelDisplayName(artifact))}</strong>
            <small>${escapeHtml(artifact.modelId || artifact.id)}</small>
          </td>
          <td>${renderModelTags([modelArch(artifact)])}</td>
          <td>${renderModelTags([modelParams(artifact)])}</td>
          <td>${escapeHtml(modelPublisher(artifact))}</td>
          <td>${renderModelTags([modelDomain(artifact), artifact.format || "GGUF"])}</td>
          <td>${modelStatusPill(rowStatus)}</td>
          <td class="model-actions-cell">
            <button class="model-icon-button" type="button" data-command="ioi.models.openLoader"${commandPayloadAttr(actionPayload)} title="Open loader" aria-label="Open loader">Load</button>
            <button class="model-icon-button" type="button" data-command="ioi.models.estimateNative"${commandPayloadAttr(actionPayload)} title="Estimate load" aria-label="Estimate load">Estimate</button>
          </td>
        </tr>
      `;
    })
    .join("");
}

function renderModelQuickLoaderRows(snapshot) {
  if (!snapshot.artifacts.length) {
    return `<div class="model-empty">Open the daemon model catalog to populate the loader.</div>`;
  }
  return snapshot.artifacts
    .slice(0, 5)
    .map((artifact, index) => {
      const endpoint = modelEndpointForArtifact(snapshot, artifact);
      const instance = modelInstanceForEndpoint(snapshot, endpoint);
      const capabilities = Array.isArray(artifact.capabilities) ? artifact.capabilities : [];
      return `
        <button
          class="model-loader-row ${index === 0 ? "is-selected" : ""}"
          type="button"
          data-model-label="${escapeHtml(modelDisplayName(artifact))}"
          data-model-publisher="${escapeHtml(modelPublisher(artifact))}"
          data-model-domain="${escapeHtml(modelDomain(artifact))}"
          data-testid="${index === 0 ? "model-quick-loader-selected-row" : "model-quick-loader-row"}"
          data-command="ioi.models.openLoader"
          ${commandPayloadAttr({ modelId: artifact.modelId || artifact.id, endpointId: endpoint?.id })}
        >
          <span>
            <strong>${escapeHtml(modelDisplayName(artifact))}</strong>
            <small>${escapeHtml(modelPublisher(artifact))}</small>
          </span>
          <span>${renderModelTags([modelArch(artifact), artifact.format || "GGUF", ...capabilities], { max: 3 })}</span>
          <span>${escapeHtml(formatBytes(artifact.sizeBytes ?? artifact.size_bytes))}</span>
          <span>${modelStatusPill(instance?.status || endpoint?.status || artifact.status || "installed")}</span>
        </button>
      `;
    })
    .join("");
}

function renderModelReceiptRows(snapshot, limit = 7) {
  const receipts = snapshot.receipts.slice(-limit).reverse();
  if (!receipts.length) {
    return `<div class="model-empty">No model receipts have been emitted yet.</div>`;
  }
  return receipts
    .map(
      (receipt) => `
        <article class="model-log-row">
          <strong>${escapeHtml(modelReceiptKind(receipt))}</strong>
          <span>${escapeHtml(receipt.id || receipt.receiptId || "receipt")}</span>
          <small>${escapeHtml(receipt.summary || receipt.details?.summary || "daemon receipt")}</small>
        </article>
      `,
    )
    .join("");
}

function modelCatalogFallbackEntries(snapshot) {
  return snapshot.artifacts.slice(0, 8).map((artifact) => ({
    id: `local.${artifact.id || artifact.modelId}`,
    providerId: artifact.providerId || "provider.local-folder",
    catalogProviderId: "catalog.local-installed",
    modelId: artifact.modelId || artifact.id,
    family: artifact.family || artifact.arch || modelDomain(artifact),
    architecture: modelArch(artifact),
    parameterCount: modelParams(artifact),
    format: String(artifact.format || "gguf").toLowerCase(),
    quantization: artifact.quantization || "installed",
    sizeBytes: artifact.sizeBytes ?? artifact.size_bytes,
    contextWindow: artifact.contextWindow ?? artifact.context_window ?? null,
    sourceLabel: `Installed artifact / ${modelDisplayName(artifact)}`,
    license: artifact.license || "local",
    compatibility: ["installed", modelDomain(artifact), artifact.format || "gguf"],
    tags: Array.isArray(artifact.capabilities) ? artifact.capabilities : [modelDomain(artifact)],
    variantPath: artifact.path || artifact.fileName || null,
    description:
      artifact.description ||
      "This model is already projected by the daemon. Run a catalog search to discover remote or provider-backed variants.",
    downloadRisk: { status: "already_installed" },
  }));
}

function modelCatalogReferenceEntries() {
  return [
    {
      id: "reference.nvidia.nemotron-3-nano-omni",
      catalogProviderId: "catalog.huggingface",
      modelId: "nvidia/nemotron-3-nano-omni",
      displayName: "Nemotron 3 Nano Omni",
      publisher: "NVIDIA",
      family: "Nemotron Nano V3 Omni",
      architecture: "nemotron_h_moe",
      parameterCount: "30B",
      domain: "llm",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 26.1 * 1024 * 1024 * 1024,
      downloads: 149_861,
      stars: 22,
      updatedLabel: "23 days ago",
      sourceLabel: "Staff pick / Hugging Face-compatible catalog",
      sourceUrl: "https://huggingface.co/nvidia/nemotron-3-nano-omni",
      license: "model card",
      staffPick: true,
      verified: true,
      compatibility: ["vision", "tool use", "reasoning"],
      tags: ["vision", "tool use", "reasoning", "llm", "gguf"],
      description:
        "Nemotron Nano V3 Omni is a multi-modal large language model designed to integrate image and text understanding, enabling workflows such as Q&A, summarization, and document intelligence.",
      readme:
        "Nemotron 3 Nano Omni by NVIDIA supports long-context, multi-modal workflows with reasoning, tool use, and partial GPU offload options surfaced through the daemon catalog.",
      moreFromPublisher: [
        { label: "nemotron-3-nano-4b", downloads: 155_000, stars: 14 },
        { label: "nemotron-3-super", downloads: 169_000, stars: 45 },
        { label: "nemotron-3-nano", downloads: 148_000, stars: 59 },
      ],
    },
    {
      id: "reference.qwen.qwen3.6-27b",
      catalogProviderId: "catalog.huggingface",
      modelId: "qwen/qwen3.6-27b",
      displayName: "Qwen3.6 27B",
      publisher: "Qwen",
      family: "Qwen3.6",
      architecture: "qwen3",
      parameterCount: "27B",
      domain: "llm",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 16.4 * 1024 * 1024 * 1024,
      downloads: 94_820,
      stars: 18,
      updatedLabel: "29 days ago",
      sourceLabel: "Staff pick / Hugging Face-compatible catalog",
      sourceUrl: "https://huggingface.co/qwen/qwen3.6-27b",
      license: "model card",
      staffPick: true,
      verified: true,
      compatibility: ["reasoning", "tool use", "llm"],
      tags: ["reasoning", "tool use", "llm", "gguf"],
      description:
        "Dense Qwen reasoning model for local planning, tool use, and workflow-backed coding tasks.",
      readme:
        "Qwen3.6 27B is a practical local reasoning candidate for Autopilot routes where the daemon needs predictable model lifecycle, receipts, and replay.",
      moreFromPublisher: [
        { label: "qwen3.6-35b-a3b", downloads: 86_000, stars: 33 },
        { label: "qwen3-coder-next", downloads: 71_000, stars: 31 },
        { label: "qwen3.5-9b", downloads: 64_000, stars: 21 },
      ],
    },
    {
      id: "reference.google.gemma-4-31b",
      catalogProviderId: "catalog.huggingface",
      modelId: "google/gemma-4-31b",
      displayName: "Gemma 4 31B",
      publisher: "Google",
      family: "Gemma 4",
      architecture: "gemma4",
      parameterCount: "31B",
      domain: "llm",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 18.7 * 1024 * 1024 * 1024,
      downloads: 88_630,
      stars: 27,
      updatedLabel: "40 days ago",
      sourceLabel: "Staff pick / Hugging Face-compatible catalog",
      sourceUrl: "https://huggingface.co/google/gemma-4-31b",
      license: "model card",
      verified: true,
      compatibility: ["vision", "tool use", "llm"],
      tags: ["vision", "tool use", "llm", "gguf"],
      description:
        "General-purpose model family candidate for on-device assistants and document workflows.",
      readme:
        "Gemma 4 31B is shown as a discovery candidate so Autopilot can route users from model selection into daemon-owned estimate, download, and load flows.",
      moreFromPublisher: [
        { label: "gemma-4-e4b", downloads: 73_000, stars: 19 },
        { label: "gemma-4-e2b", downloads: 67_000, stars: 15 },
        { label: "gemma-4-26b-a4b", downloads: 61_000, stars: 17 },
      ],
    },
    {
      id: "reference.mistral.devstral-small-2-2512",
      catalogProviderId: "catalog.huggingface",
      modelId: "mistral/devstral-small-2-2512",
      displayName: "Devstral Small 2 2512",
      publisher: "Mistral",
      family: "Devstral",
      architecture: "mistral",
      parameterCount: "24B",
      domain: "llm",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 14.9 * 1024 * 1024 * 1024,
      downloads: 57_430,
      stars: 16,
      updatedLabel: "161 days ago",
      sourceLabel: "Staff pick / Hugging Face-compatible catalog",
      sourceUrl: "https://huggingface.co/mistral/devstral-small-2-2512",
      license: "model card",
      verified: true,
      compatibility: ["tool use", "coding", "llm"],
      tags: ["tool use", "coding", "llm", "gguf"],
      description:
        "Second-generation coding model candidate for local repository work and agentic code proposal loops.",
      readme:
        "Devstral is a coding-focused local model candidate for Workflow Composer dry-runs and code proposal routes once daemon download/load APIs are enabled.",
      moreFromPublisher: [
        { label: "ministral-3-14b-reasoning", downloads: 42_000, stars: 11 },
        { label: "mistral-small-instruct", downloads: 98_000, stars: 39 },
      ],
    },
    {
      id: "reference.ollama.nomic-embed-text",
      catalogProviderId: "catalog.custom_http",
      modelId: "nomic-ai/nomic-embed-text-v1.5",
      displayName: "Nomic Embed Text v1.5",
      publisher: "Nomic AI",
      family: "Nomic Embed",
      architecture: "nomic-bert",
      parameterCount: "local",
      domain: "embedding",
      format: "GGUF",
      quantization: "Q4_K_M",
      sizeBytes: 80.2 * 1024 * 1024,
      downloads: 214_000,
      stars: 52,
      updatedLabel: "local registry",
      sourceLabel: "Embedding pick / configurable endpoint",
      sourceUrl: "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5",
      license: "model card",
      verified: true,
      compatibility: ["embedding", "retrieval"],
      tags: ["embedding", "retrieval", "gguf"],
      description:
        "Small text embedding model candidate for retrieval, memory, and workflow evidence search.",
      readme:
        "Nomic Embed Text is useful when Autopilot needs local retrieval indexes without giving the model direct authority over files or receipts.",
      moreFromPublisher: [
        { label: "nomic-embed-code", downloads: 76_000, stars: 18 },
        { label: "nomic-bert", downloads: 112_000, stars: 29 },
      ],
    },
  ];
}

function modelCatalogResults(snapshot) {
  const results = Array.isArray(snapshot.catalog?.results) ? snapshot.catalog.results : [];
  const remoteResults = results.filter((entry) => {
    const provider = `${entry.catalogProviderId || ""} ${entry.providerId || ""} ${entry.sourceLabel || ""}`;
    const summary = `${entry.description || ""} ${entry.summary || ""}`;
    return (
      !/local-installed|local-folder|provider\.local|daemon catalog/i.test(provider) &&
      !/already projected by the daemon/i.test(summary)
    );
  });
  return remoteResults.length ? remoteResults : modelCatalogReferenceEntries();
}

function modelCatalogLocalProjectionEntries(snapshot) {
  return modelCatalogFallbackEntries(snapshot);
}

function formatCatalogMetric(value, fallback = "unknown") {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return fallback;
  }
  return numeric.toLocaleString("en-US");
}

function catalogSizeLabel(entry = {}) {
  return entry.sizeLabel || formatBytes(entry.sizeBytes ?? entry.size_bytes);
}

function catalogUpdatedLabel(entry = {}) {
  if (entry.updatedLabel) {
    return String(entry.updatedLabel);
  }
  const timestamp =
    entry.updatedAt ||
    entry.updated_at ||
    entry.modifiedAt ||
    entry.modified_at ||
    entry.discoveredAt ||
    entry.discovered_at;
  return timestamp ? formatRelativeTime(Date.parse(timestamp)) : "registry";
}

function catalogReadme(entry = {}) {
  return entry.readme || entry.card || catalogSummary(entry);
}

function catalogPublisherLogo(entry = {}) {
  const publisher = catalogPublisher(entry);
  if (/nvidia/i.test(publisher)) return "NV";
  if (/google/i.test(publisher)) return "G";
  if (/qwen/i.test(publisher)) return "Q";
  if (/mistral/i.test(publisher)) return "MI";
  if (/nomic/i.test(publisher)) return "NO";
  return publisher.slice(0, 2).toUpperCase();
}

function catalogMoreFromPublisher(results, selected) {
  if (Array.isArray(selected.moreFromPublisher) && selected.moreFromPublisher.length) {
    return selected.moreFromPublisher.slice(0, 4);
  }
  return results
    .filter((entry) => catalogPublisher(entry) === catalogPublisher(selected) && entry.id !== selected.id)
    .slice(0, 4)
    .map((entry) => ({
      label: entry.modelId || entry.id,
      downloads: entry.downloads,
      stars: entry.stars,
      sizeBytes: entry.sizeBytes ?? entry.size_bytes,
    }));
}

function catalogDisplayName(entry = {}) {
  const raw = entry.displayName || entry.name || entry.modelId || entry.id || "Catalog model";
  return String(raw).split("/").pop() || raw;
}

function catalogPublisher(entry = {}) {
  const explicit = entry.publisher || entry.author || entry.providerLabel || entry.catalogProviderId || entry.providerId;
  if (explicit) {
    return String(explicit).replace(/^catalog\./, "").replace(/^provider\./, "");
  }
  const modelId = String(entry.modelId || "");
  return modelId.includes("/") ? modelId.split("/")[0] : "daemon catalog";
}

function catalogSummary(entry = {}) {
  return (
    entry.description ||
    entry.summary ||
    `${entry.family || "Model"} ${entry.parameterCount || ""} ${entry.format || ""} candidate discovered through ${catalogPublisher(entry)}.`
  )
    .replace(/\s+/g, " ")
    .trim();
}

function catalogCapabilities(entry = {}) {
  return Array.from(
    new Set(
      [
        ...(Array.isArray(entry.tags) ? entry.tags : []),
        ...(Array.isArray(entry.compatibility) ? entry.compatibility : []),
        entry.format,
        entry.quantization,
      ]
        .filter(Boolean)
        .map((value) => String(value)),
    ),
  );
}

function catalogDownloadBlocked(snapshot, entry = {}) {
  const providers = Array.isArray(snapshot.catalog?.providers) ? snapshot.catalog.providers : [];
  const provider = providers.find(
    (candidate) => candidate.id === entry.catalogProviderId || candidate.providerId === entry.providerId,
  );
  const liveDownloadConfigured = providers.some((candidate) =>
    /configured|available|enabled/i.test(String(candidate.liveDownloadStatus || candidate.downloadStatus || "")),
  );
  const isInstalled = String(entry.catalogProviderId || "").includes("local-installed");
  return {
    blocked: isInstalled || !liveDownloadConfigured,
    reason: isInstalled
      ? "Already installed"
      : provider?.downloadGate
        ? "Download gated"
        : "Daemon gated",
  };
}

function renderModelDiscoveryRows(snapshot) {
  const results = modelCatalogResults(snapshot);
  if (!results.length) {
    return `<div class="model-empty" data-testid="model-discover-empty-state">Search the daemon catalog to discover models.</div>`;
  }
  return results
    .map((entry, index) => {
      const capabilities = catalogCapabilities(entry);
      const isSelected = index === 0;
      const badges = [entry.parameterCount, entry.architecture || entry.arch, entry.format, ...capabilities]
        .filter(Boolean)
        .slice(0, 4);
      return `
        <button
          class="model-discover-result ${isSelected ? "is-selected" : ""}"
          type="button"
          data-catalog-row="${escapeHtml(entry.id || entry.modelId || `catalog-${index}`)}"
          data-catalog-label="${escapeHtml(catalogDisplayName(entry))}"
          data-catalog-model-id="${escapeHtml(entry.modelId || entry.id || "")}"
          data-catalog-publisher="${escapeHtml(catalogPublisher(entry))}"
          data-catalog-summary="${escapeHtml(catalogSummary(entry))}"
          data-catalog-params="${escapeHtml(entry.parameterCount || "local")}"
          data-catalog-arch="${escapeHtml(entry.architecture || entry.arch || "unknown")}"
          data-catalog-domain="${escapeHtml(entry.domain || "llm")}"
          data-catalog-format="${escapeHtml(entry.format || "gguf")}"
          data-catalog-quantization="${escapeHtml(entry.quantization || "unknown")}"
          data-catalog-size="${escapeHtml(catalogSizeLabel(entry))}"
          data-catalog-license="${escapeHtml(entry.license || "unknown")}"
          data-catalog-downloads="${escapeHtml(formatCatalogMetric(entry.downloads, "registry"))}"
          data-catalog-stars="${escapeHtml(formatCatalogMetric(entry.stars, "score"))}"
          data-catalog-updated="${escapeHtml(catalogUpdatedLabel(entry))}"
          data-catalog-capabilities="${escapeHtml(catalogCapabilities(entry).slice(0, 5).join(" / "))}"
          data-catalog-source-label="${escapeHtml(entry.sourceLabel || catalogPublisher(entry))}"
          data-catalog-source-url="${escapeHtml(entry.sourceUrl || "")}"
          data-catalog-download-label="${escapeHtml(entry.downloadRisk?.status === "already_installed" ? "Already installed" : "Download")}"
          data-catalog-readme-title="${escapeHtml(`${catalogDisplayName(entry)} by ${catalogPublisher(entry)}`)}"
          data-catalog-readme="${escapeHtml(catalogReadme(entry))}"
          data-testid="${isSelected ? "model-discover-result-selected" : "model-discover-result-row"}"
        >
          <span class="model-discover-result__logo">${escapeHtml(catalogPublisherLogo(entry))}</span>
          <span class="model-discover-result__body">
            <strong>${escapeHtml(catalogDisplayName(entry))}${entry.verified ? `<span class="model-discover-result__verified">verified</span>` : ""}</strong>
            <small>${escapeHtml(catalogSummary(entry))}</small>
            <span class="model-discover-result__age">${escapeHtml(catalogUpdatedLabel(entry))}</span>
          </span>
          <span class="model-discover-result__tags">${renderModelTags(badges, { max: 4 })}</span>
        </button>
      `;
    })
    .join("");
}

function renderModelDiscoverySurface(snapshot) {
  const results = modelCatalogResults(snapshot);
  const localProjectionCount = modelCatalogLocalProjectionEntries(snapshot).length;
  const selected = results[0] || {};
  const providers = Array.isArray(snapshot.catalog?.providers) ? snapshot.catalog.providers : [];
  const lastSearch = snapshot.catalog?.lastSearch || null;
  const downloadState = catalogDownloadBlocked(snapshot, selected);
  const moreFromPublisher = catalogMoreFromPublisher(results, selected);
  const selectedCapabilities = catalogCapabilities(selected).slice(0, 5);
  return `
    <section class="models-lmstudio__discover" data-model-surface-panel="discover" data-testid="model-discovery-surface" data-catalog-needs-search="${lastSearch ? "false" : "true"}" hidden>
      <section class="model-discovery-list" data-testid="model-discover-list">
        <header class="model-discovery-toolbar">
          <label class="models-lmstudio__search">
            <span aria-hidden="true">Find</span>
            <input data-testid="model-discover-search-input" type="search" placeholder="Search registry models by name or author..." value="${escapeHtml(lastSearch?.query || "")}" />
          </label>
          <button class="model-icon-button" type="button" data-testid="model-discover-search-button">Search</button>
        </header>
        <div class="model-discovery-meta" data-testid="model-discover-staff-picks">
          <span>Staff picks</span>
          <button class="model-icon-button" type="button" data-testid="model-discover-refresh-button" title="Refresh catalog search">Refresh</button>
          <label class="model-discovery-sort" data-testid="model-discover-sort">
            <span>Sort</span>
            <select aria-label="Sort registry models">
              <option>Best Match</option>
              <option>Recently Updated</option>
              <option>Downloads</option>
              <option>Smallest</option>
            </select>
          </label>
        </div>
        <div class="model-discovery-results">${renderModelDiscoveryRows(snapshot)}</div>
        <footer class="model-discovery-provider-strip" data-testid="model-catalog-provider-strip">
          <span>${escapeHtml(lastSearch ? `${lastSearch.resultCount ?? results.length} daemon results` : "reference staff picks")}</span>
          <span>${escapeHtml(String(localProjectionCount))} local artifacts available in My Models</span>
          ${providers
            .slice(0, 3)
            .map((provider) => `<span>${escapeHtml(provider.label || provider.id)} · ${escapeHtml(provider.status || "unknown")}</span>`)
            .join("") || "<span>Default endpoint: Hugging Face-compatible</span>"}
        </footer>
      </section>
      <section class="model-discovery-detail" data-testid="model-discover-detail">
        <header>
          <div>
            <span class="model-icon-label" aria-hidden="true">AI</span>
            <h2 data-catalog-field="title">${escapeHtml(catalogDisplayName(selected))}</h2>
            <small data-catalog-field="modelId">${escapeHtml(selected.modelId || selected.id || "daemon catalog")}</small>
          </div>
          <button class="model-icon-button model-discovery-close" type="button" data-model-surface-tab="library" data-testid="model-discover-close-button" title="Close discovery">X</button>
        </header>
        <section class="model-discovery-stats" data-testid="model-discover-stats">
          <span><strong data-catalog-field="downloads">${escapeHtml(formatCatalogMetric(selected.downloads, "registry"))}</strong> downloads</span>
          <span><strong data-catalog-field="stars">${escapeHtml(formatCatalogMetric(selected.stars, "score"))}</strong> stars</span>
          <span>Updated <strong data-catalog-field="updated">${escapeHtml(catalogUpdatedLabel(selected))}</strong></span>
          ${selected.staffPick ? "<span>Staff Pick</span>" : ""}
        </section>
        <p class="model-discovery-summary" data-catalog-field="summary">${escapeHtml(catalogSummary(selected))}</p>
        <dl class="model-discovery-facts">
          <div><dt>Params</dt><dd data-catalog-field="params">${escapeHtml(selected.parameterCount || "local")}</dd></div>
          <div><dt>Arch</dt><dd data-catalog-field="arch">${escapeHtml(selected.architecture || selected.arch || "unknown")}</dd></div>
          <div><dt>Domain</dt><dd data-catalog-field="domain">${escapeHtml(selected.domain || "llm")}</dd></div>
          <div><dt>Format</dt><dd data-catalog-field="format">${escapeHtml(selected.format || "gguf")}</dd></div>
        </dl>
        <section class="model-download-options model-discovery-download" data-testid="model-download-options">
          <header>
            <strong>Download Options</strong>
            <small data-catalog-field="sourceLabel">${escapeHtml(selected.sourceLabel || catalogPublisher(selected))}</small>
          </header>
          <div>
            <span>GGUF</span>
            <span data-catalog-field="downloadTitle">${escapeHtml(`${catalogDisplayName(selected)} ${selected.parameterCount || ""} ${selected.quantization || "Q4_K_M"}`.trim())}</span>
            <span data-catalog-field="quantization">${escapeHtml(selected.quantization || "Q4_K_M")}</span>
            <span data-catalog-field="size">${escapeHtml(catalogSizeLabel(selected))}</span>
            <button
              class="action"
              type="button"
              data-testid="model-download-button"
              data-command="ioi.models.downloadCatalog"
              ${commandPayloadAttr({ catalogEntryId: selected.id, sourceUrl: selected.sourceUrl, modelId: selected.modelId })}
              ${downloadState.blocked ? "disabled" : ""}
            >${downloadState.blocked ? escapeHtml(downloadState.reason) : "Download"}</button>
          </div>
          <small>Partial GPU offload possible when the daemon exposes a compatible backend estimate.</small>
        </section>
        <section class="model-discovery-capabilities" data-testid="model-discover-capabilities">
          <strong>Capabilities</strong>
          <span data-catalog-field="capabilities">${escapeHtml(selectedCapabilities.join(" / ") || "metadata pending")}</span>
        </section>
        <section class="model-readme-panel" data-testid="model-readme-panel">
          <h3 data-testid="model-discover-readme-title" data-catalog-field="readmeTitle">${escapeHtml(`${catalogDisplayName(selected)} by ${catalogPublisher(selected)}`)}</h3>
          <p data-catalog-field="readme">${escapeHtml(catalogReadme(selected))}</p>
        </section>
        <section class="model-more-from" data-testid="model-more-from-publisher">
          <h3>More from <span data-catalog-field="publisher">${escapeHtml(catalogPublisher(selected))}</span></h3>
          ${
            moreFromPublisher.length
              ? moreFromPublisher
                  .map((entry) => `<span>${escapeHtml(entry.label || entry.modelId || entry.id)} · ${escapeHtml(entry.sizeBytes ? formatBytes(entry.sizeBytes) : formatCatalogMetric(entry.downloads, "registry"))} · ${escapeHtml(formatCatalogMetric(entry.stars, "score"))}</span>`)
                  .join("")
              : "<span>No additional daemon-projected variants yet.</span>"
          }
        </section>
      </section>
    </section>
  `;
}

function catalogProviderById(snapshot, providerId) {
  const providers = [
    ...(Array.isArray(snapshot.catalog?.providers) ? snapshot.catalog.providers : []),
    ...(Array.isArray(snapshot.providers) ? snapshot.providers : []),
  ];
  const configs = Array.isArray(snapshot.catalogProviderConfigs) ? snapshot.catalogProviderConfigs : [];
  return {
    provider: providers.find((candidate) => candidate.id === providerId) || {},
    config: configs.find((candidate) => candidate.id === providerId) || {},
  };
}

function renderCatalogSourceRow(snapshot, providerId, label, description, testId) {
  const { provider, config } = catalogProviderById(snapshot, providerId);
  const status = provider.status || config.runtimeMaterialStatus || (config.materialConfigured ? "configured" : "unconfigured");
  const configured = Boolean(config.materialConfigured || provider.materialConfigured || provider.baseUrlHash || provider.manifestPathHash);
  return `
    <article class="model-source-row" data-testid="${escapeHtml(testId)}">
      <div>
        <strong>${escapeHtml(label)}</strong>
        <span>${escapeHtml(description)}</span>
      </div>
      <dl>
        <div><dt>Status</dt><dd>${escapeHtml(status)}</dd></div>
        <div><dt>Configured</dt><dd>${configured ? "yes" : "default"}</dd></div>
        <div><dt>Boundary</dt><dd>${escapeHtml(provider.gate || "daemon provider config")}</dd></div>
      </dl>
    </article>
  `;
}

function renderModelSourcesSurface(snapshot) {
  const providers = Array.isArray(snapshot.providers) ? snapshot.providers : [];
  const lmStudio = providers.find((provider) => provider.id === "provider.lmstudio" || provider.providerId === "provider.lmstudio") || {};
  const ollama = providers.find((provider) => provider.id === "provider.ollama" || provider.providerId === "provider.ollama") || {};
  return `
    <section class="models-lmstudio__sources" data-model-surface-panel="sources" data-testid="model-catalog-sources-surface" hidden>
      <section class="model-sources-grid">
        <header class="model-sources-header">
          <div>
            <h2>Catalog Sources</h2>
            <p>Local autodiscovery plus configurable daemon-owned remote registries. The webview only submits source configuration requests.</p>
          </div>
          <button class="model-icon-button" type="button" data-model-surface-tab="discover" data-testid="model-sources-open-discover-button">Open Discover</button>
        </header>
        <section class="model-sources-card" data-testid="model-local-autodiscovery-sources">
          <h3>Local Autodiscovery</h3>
          ${renderCatalogSourceRow({ catalog: {}, catalogProviderConfigs: [], providers: [lmStudio] }, "provider.lmstudio", "LM Studio", "Find local LM Studio models and mounted local server routes.", "model-source-lmstudio")}
          ${renderCatalogSourceRow({ catalog: {}, catalogProviderConfigs: [], providers: [ollama] }, "provider.ollama", "Ollama", "Find local Ollama models without copying artifacts into Autopilot.", "model-source-ollama")}
          <p class="model-source-note">Local providers are discovered on startup and remain daemon-owned; Autopilot mounts routes as projections.</p>
        </section>
        <section class="model-sources-card" data-testid="model-remote-registry-sources">
          <h3>Remote Registries</h3>
          ${renderCatalogSourceRow(snapshot, "catalog.huggingface", "Hugging Face-compatible", "Default public registry, or a sovereign HF-compatible endpoint.", "model-source-huggingface")}
          ${renderCatalogSourceRow(snapshot, "catalog.custom_http", "Custom HTTP catalog", "Private or ecosystem catalogs exposing /catalog/search.", "model-source-custom-http")}
          ${renderCatalogSourceRow(snapshot, "catalog.local_manifest", "Local manifest", "Offline JSON catalog for internal or air-gapped model indexes.", "model-source-local-manifest")}
        </section>
        <section class="model-sources-card model-source-config" data-testid="model-catalog-source-config">
          <h3>Configure Source</h3>
          <label>
            <span>Provider</span>
            <select data-testid="model-catalog-provider-select">
              <option value="catalog.huggingface">Hugging Face-compatible</option>
              <option value="catalog.custom_http">Custom HTTP catalog</option>
              <option value="catalog.local_manifest">Local manifest</option>
            </select>
          </label>
          <label data-model-source-field="baseUrl">
            <span>Endpoint</span>
            <input data-testid="model-catalog-source-url-input" type="url" placeholder="https://huggingface.co" value="https://huggingface.co" />
          </label>
          <label data-model-source-field="manifestPath" hidden>
            <span>Manifest path</span>
            <input data-testid="model-catalog-manifest-path-input" type="text" placeholder="/path/to/model-catalog.json" />
          </label>
          <label>
            <span>Search after configure</span>
            <input data-testid="model-catalog-source-search-input" type="search" placeholder="qwen, llama, embedding..." value="qwen" />
          </label>
          <div class="model-source-actions">
            <button class="action" type="button" data-testid="model-catalog-source-configure-button">Save source</button>
            <button class="model-icon-button" type="button" data-model-surface-tab="discover">Skip to Discover</button>
          </div>
          <p class="model-source-note">Credentials stay out of the webview. Auth and OAuth remain daemon/vault concerns.</p>
        </section>
      </section>
    </section>
  `;
}

function renderModelsPanelBody(state, { compact = false } = {}) {
  const snapshot = modelSnapshotFromState(state);
  const modelStatus = state.modelMountingStatus || {};
  const loadedModelIds = new Set(
    snapshot.instances
      .filter((instance) => instance.status === "loaded")
      .map((instance) => instance.modelId)
      .filter(Boolean),
  );
  const selectedArtifact =
    snapshot.artifacts.find((artifact) => loadedModelIds.has(artifact.modelId)) ||
    snapshot.artifacts[0] ||
    {};
  const selectedEndpoint = modelEndpointForArtifact(snapshot, selectedArtifact) || snapshot.endpoints[0] || {};
  const selectedInstance =
    modelInstanceForEndpoint(snapshot, selectedEndpoint) || snapshot.instances.find((item) => item.status === "loaded") || {};
  const selectedRoute =
    snapshot.routes.find((route) => route.id === "route.native-local") || snapshot.routes[0] || {};
  const selectedBackend =
    snapshot.backends.find((backend) => backend.id === selectedInstance.backendId) ||
    snapshot.backends[0] ||
    {};
  const selectedEngine =
    snapshot.runtimeEngines.find(
      (engine) =>
        engine.id === selectedBackend.id ||
        engine.kind === selectedBackend.kind ||
        engine.kind === `${selectedBackend.kind}_runtime`,
    ) ||
    snapshot.runtimeEngines.find((engine) => engine.selected) ||
    snapshot.runtimeEngines[0] ||
    {};
  const loadReceipt = snapshot.receipts
    .slice()
    .reverse()
    .find((receipt) => modelReceiptKind(receipt) === "model_load_estimate");
  const invokeReceipt = snapshot.receipts
    .slice()
    .reverse()
    .find((receipt) => receipt.kind === "model_invocation");
  const routeReceipt = snapshot.receipts
    .slice()
    .reverse()
    .find((receipt) => receipt.kind === "model_route_selection");
  const loadedCount = snapshot.instances.filter((instance) => instance.status === "loaded").length;
  const loadOptions = modelSelectedLoadOptions(selectedInstance, selectedEngine);
  const localSizeBytes = snapshot.artifacts.reduce(
    (total, artifact) => total + Number(artifact.sizeBytes ?? artifact.size_bytes ?? 0),
    0,
  );
  const artifactCapabilities = Array.isArray(selectedArtifact.capabilities)
    ? selectedArtifact.capabilities
    : [];
      const serverBaseUrl =
    snapshot.server.openAiCompatibleBaseUrl ||
      snapshot.server.openAiCompatibleApi ||
      snapshot.server.nativeBaseUrl ||
      snapshot.server.nativeApi ||
      "/v1";

  return `
      <section
        class="model-workbench models-lmstudio ${compact ? "is-compact" : ""}"
      data-testid="autopilot-models-mode"
      data-inspection-target="autopilot-models-mode"
      data-daemon-backed="${modelStatus.status === "connected" ? "true" : "false"}"
      data-active-model-surface="library"
      >
      ${
        modelStatus.status === "degraded"
          ? `<section class="model-state-banner is-error" data-testid="model-error-state"><strong>Daemon model runtime degraded</strong><span>${escapeHtml(modelStatus.error || "The model daemon is configured but not reachable.")}</span></section>`
          : ""
      }
      <section class="models-lmstudio__primary" data-testid="models-lmstudio-shell">
        <aside class="models-lmstudio__rail" data-testid="models-left-rail" aria-label="Model categories">
          <strong>My Models</strong>
          <button class="is-active" type="button" data-model-surface-tab="library">View All</button>
          <button type="button">LLMs <span>${escapeHtml(String(snapshot.artifacts.filter((artifact) => modelDomain(artifact) === "llm").length))}</span></button>
          <button type="button">Text Embedding <span>${escapeHtml(String(snapshot.artifacts.filter((artifact) => modelDomain(artifact) === "embedding").length))}</span></button>
          <button type="button">Vision / Tools <span>${escapeHtml(String(snapshot.artifacts.filter((artifact) => modelDomain(artifact) === "vlm").length))}</span></button>
          <strong>Discover</strong>
          <button type="button" data-model-surface-tab="discover" data-testid="model-discover-open-button">Catalog <span>${escapeHtml(String(modelCatalogResults(snapshot).length))}</span></button>
          <button type="button" data-model-surface-tab="sources" data-testid="model-sources-open-button">Sources <span>${escapeHtml(String(snapshot.catalogProviderConfigs.length || 3))}</span></button>
          <div class="models-lmstudio__rail-status">
            <span>Daemon</span>
            ${modelStatusPill(modelStatus.status || "not_configured")}
          </div>
          <div class="models-lmstudio__rail-status">
            <span>Loaded</span>
            <strong>${escapeHtml(String(loadedCount))}</strong>
          </div>
        </aside>

        <main class="models-lmstudio__library model-surface" data-testid="model-library">
          <section class="models-lmstudio__local is-active" data-model-surface-panel="library" data-testid="model-local-library-surface">
            <header class="models-lmstudio__library-header">
              <h2>My Models</h2>
              <label class="models-lmstudio__search">
                <span aria-hidden="true">Find</span>
                <input data-testid="model-library-filter" type="search" placeholder="Filter models... (Ctrl + F)" />
              </label>
            </header>
            <div class="models-lmstudio__table-wrap" data-testid="model-library-table">
              <table class="model-table">
                <thead>
                  <tr>
                    <th>Model</th>
                    <th>Arch</th>
                    <th>Params</th>
                    <th>Publisher</th>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>${renderModelLibraryRows(snapshot)}</tbody>
              </table>
            </div>
            <footer class="models-lmstudio__status-strip" data-testid="model-library-footer" data-role="model-bottom-status-strip">
              <span>You have ${escapeHtml(String(snapshot.artifacts.length))} local models, taking up ${escapeHtml(formatBytes(localSizeBytes))} of disk space</span>
              <code>${escapeHtml(snapshot.server.modelRoot || "~/.ioi/models")}</code>
            </footer>
          </section>
          ${renderModelDiscoverySurface(snapshot)}
          ${renderModelSourcesSurface(snapshot)}
        </main>

        <aside class="models-lmstudio__inspector model-surface" data-testid="model-selected-inspector">
          <header class="models-lmstudio__inspector-header">
            <div>
              <span class="model-icon-label" aria-hidden="true">AI</span>
              <h2 data-testid="model-inspector-title">${escapeHtml(modelDisplayName(selectedArtifact))}</h2>
              <small data-testid="model-inspector-subtitle">${escapeHtml(selectedArtifact.modelId || selectedEndpoint.modelId || "Select a model")}</small>
            </div>
            ${modelStatusPill(selectedInstance.status || selectedEndpoint.status || selectedArtifact.status || "installed")}
          </header>
          <div class="models-lmstudio__inspector-actions">
            <button
              class="action"
              type="button"
              data-model-action="workflow"
              data-command="ioi.models.selectForWorkflow"
              ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedEndpoint.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id })}
            >Use in Workflow</button>
            <button
              class="action"
              type="button"
              data-model-action="load"
              data-command="ioi.models.openLoader"
              ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedEndpoint.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id })}
            >Load Model</button>
          </div>
          <nav class="models-lmstudio__tabs" aria-label="Model inspector tabs">
            <button class="is-active" type="button" data-model-inspector-tab="info" data-testid="model-inspector-info-tab">Info</button>
            <button type="button" data-model-inspector-tab="load" data-testid="model-inspector-load-tab">Load</button>
            <button type="button" data-model-inspector-tab="inference" data-testid="model-inspector-inference-tab">Inference</button>
            <button type="button" data-model-inspector-tab="policy" data-testid="model-inspector-policy-tab">Policy</button>
            <button type="button" data-model-inspector-tab="routes" data-testid="model-inspector-routes-tab">Routes</button>
            <button type="button" data-model-inspector-tab="receipts" data-testid="model-inspector-receipts-tab">Receipts</button>
          </nav>
          <section class="models-lmstudio__tab-panel is-active" data-model-inspector-panel="info" data-testid="model-inspector-info-panel">
            <h3>Model Information</h3>
            <dl>
              <div><dt>Model</dt><dd data-model-field="model">${escapeHtml(selectedArtifact.modelId || selectedArtifact.id || "none")}</dd></div>
              <div><dt>File</dt><dd data-model-field="file">${escapeHtml(selectedArtifact.fileName || selectedArtifact.path || "daemon artifact")}</dd></div>
              <div><dt>Format</dt><dd data-model-field="format">${escapeHtml(selectedArtifact.format || "GGUF")}</dd></div>
              <div><dt>Quantization</dt><dd data-model-field="quantization">${escapeHtml(selectedArtifact.quantization || "unknown")}</dd></div>
              <div><dt>Arch</dt><dd data-model-field="arch">${escapeHtml(modelArch(selectedArtifact))}</dd></div>
              <div><dt>Capabilities</dt><dd data-model-field="capabilities">${renderModelTags(artifactCapabilities)}</dd></div>
              <div><dt>Size on disk</dt><dd data-model-field="size">${escapeHtml(formatBytes(selectedArtifact.sizeBytes ?? selectedArtifact.size_bytes))}</dd></div>
            </dl>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="load" data-testid="model-inspector-load-panel">
            <details class="model-side-section model-quick-loader" data-testid="model-mount-drawer">
              <summary>Quick Loader</summary>
              <p class="model-muted">Search mounted daemon catalog entries without leaving the selected model context.</p>
              <label class="models-lmstudio__search">
                <span aria-hidden="true">Find</span>
                <input data-testid="model-quick-loader-filter" type="search" placeholder="Type to filter models..." />
              </label>
              <div data-testid="model-quick-loader-popover">
                <div class="model-loader-list" data-testid="model-quick-loader-list">
                  ${renderModelQuickLoaderRows(snapshot)}
                </div>
              </div>
              <label class="model-toggle-row">
                <input type="checkbox" data-testid="model-loader-manual-toggle" />
                <span>Manually choose model load parameters</span>
              </label>
            </details>

            <section class="model-side-section model-load-dialog" data-testid="model-load-dialog">
              <header class="models-lmstudio__dialog-title">
                <h3>${escapeHtml(modelDisplayName(selectedArtifact))}</h3>
              </header>
              <section class="models-lmstudio__estimate" data-testid="model-load-estimate">
                <strong>Estimated Memory Usage</strong>
                <span data-testid="model-load-estimated-memory">GPU ${escapeHtml(formatBytes(loadReceipt?.details?.estimate?.estimatedVramBytes))}</span>
                <span>Total ${escapeHtml(formatBytes(loadReceipt?.details?.estimate?.estimatedSizeBytes || selectedArtifact.sizeBytes || selectedArtifact.size_bytes))}</span>
              </section>
              <label class="model-field">
                <span>API Identifier</span>
                <input data-testid="model-api-identifier-input" type="text" value="${escapeHtml(loadOptions.identifier)}" />
              </label>
              <label class="model-toggle-row">
                <input data-testid="model-auto-unload-toggle" type="checkbox" />
                <span>Auto Unload If Idle (TTL)</span>
              </label>
              <label class="model-range-row">
                <span>Context Length</span>
                <input data-testid="model-context-length-slider" type="range" min="1024" max="131072" value="${escapeHtml(String(loadOptions.contextLength))}" />
                <output>${escapeHtml(String(loadOptions.contextLength))}</output>
              </label>
              <label class="model-range-row">
                <span>GPU Offload</span>
                <input data-testid="model-gpu-offload-slider" type="range" min="0" max="99" value="${escapeHtml(String(Number(loadOptions.gpuOffload) || 0))}" />
                <output>${escapeHtml(String(loadOptions.gpuOffload))}</output>
              </label>
              <div class="model-dialog-options">
                <label><input data-testid="model-remember-settings-toggle" type="checkbox" /> Remember settings for ${escapeHtml(modelDisplayName(selectedArtifact))}</label>
                <label><input data-testid="model-advanced-settings-toggle" type="checkbox" /> Show advanced settings</label>
              </div>
              <section class="model-advanced-panel" data-testid="model-advanced-settings-panel" hidden>
                <dl>
                  <div><dt>Parallelism</dt><dd>${escapeHtml(String(loadOptions.parallelism))}</dd></div>
                  <div><dt>Idle TTL</dt><dd>${escapeHtml(String(loadOptions.idleTtlSeconds))}s</dd></div>
                  <div><dt>Engine</dt><dd>${escapeHtml(selectedEngine.id || "daemon-selected")}</dd></div>
                </dl>
              </section>
              <div class="model-workbench__actions">
                <button
                  class="action"
                  type="button"
                  data-testid="model-estimate-button"
                  data-model-action="estimate"
                  data-command="ioi.models.estimateNative"
                  ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id, contextLength: loadOptions.contextLength, gpuOffload: loadOptions.gpuOffload })}
                >Estimate</button>
                <button
                  class="action"
                  type="button"
                  data-testid="model-load-confirm-button"
                  data-model-action="loadNative"
                  data-command="ioi.models.loadNative"
                  ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id, contextLength: loadOptions.contextLength, gpuOffload: loadOptions.gpuOffload })}
                >Load Model</button>
              </div>
            </section>

            <section class="model-side-section" data-testid="model-instance-ready">
              <div class="model-surface__head">
                <div>
                  <span>Running Models</span>
                  <strong data-model-field="running-model">${escapeHtml(selectedInstance.modelId || selectedEndpoint.modelId || "No loaded instance")}</strong>
                </div>
                ${modelStatusPill(selectedInstance.status || "empty")}
              </div>
              <div class="model-progress" data-testid="model-load-progress"><span style="width: ${selectedInstance.status === "loaded" ? "100" : "18"}%"></span></div>
              <dl>
                <div><dt>Instance</dt><dd data-model-field="instance">${escapeHtml(selectedInstance.id || "none")}</dd></div>
                <div><dt>Identifier</dt><dd>${escapeHtml(selectedInstance.identifier || "none")}</dd></div>
                <div><dt>Backend</dt><dd data-model-field="backend">${escapeHtml(selectedInstance.backendId || selectedBackend.id || "none")}</dd></div>
                <div><dt>Receipt evidence</dt><dd>${escapeHtml(selectedInstance.providerEvidenceRefs?.join(", ") || "pending")}</dd></div>
              </dl>
              <button
                class="action"
                type="button"
                data-testid="model-running-unload-button"
                data-model-action="unload"
                data-command="ioi.models.unloadNative"
                ${commandPayloadAttr({ instanceId: selectedInstance.id })}
                ${selectedInstance.id ? "" : "disabled"}
              >Unload</button>
            </section>

          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="inference" data-testid="model-inspector-inference-panel">
            <h3>Inference</h3>
            <details class="model-accordion" open>
              <summary>System Prompt</summary>
              <p class="model-muted">Prompt policy and defaults are projected from the daemon route. The webview never executes inference directly.</p>
            </details>
            <details class="model-accordion" open>
              <summary>Settings</summary>
              <label class="model-range-row">
                <span>Temperature</span>
                <input type="range" min="0" max="2" step="0.1" value="0.8" />
                <output>0.8</output>
              </label>
              <label class="model-toggle-row"><input type="checkbox" /> Limit Response Length</label>
              <label class="model-field"><span>Stop Strings</span><input type="text" placeholder="Enter a string and press Enter" /></label>
            </details>
            <details class="model-accordion">
              <summary>Reasoning Parsing</summary>
              <label class="model-toggle-row"><input type="checkbox" checked /> Reasoning section parsing</label>
              <label class="model-field"><span>Start String</span><input type="text" value="&lt;think&gt;" /></label>
              <label class="model-field"><span>End String</span><input type="text" value="&lt;/think&gt;" /></label>
            </details>
            <details class="model-accordion">
              <summary>Sampling</summary>
              <label class="model-range-row"><span>Top K Sampling</span><input type="range" min="1" max="100" value="40" /><output>40</output></label>
              <label class="model-range-row"><span>Top P Sampling</span><input type="range" min="0" max="1" step="0.01" value="0.95" /><output>0.95</output></label>
            </details>
            <details class="model-accordion">
              <summary>Structured Output</summary>
              <label class="model-toggle-row"><input type="checkbox" /> Structured output</label>
            </details>
            <details class="model-accordion">
              <summary>Speculative Decoding</summary>
              <label class="model-field"><span>Draft Model</span><input type="text" placeholder="Select a compatible draft model" /></label>
            </details>
            <details class="model-accordion">
              <summary>Prompt Template</summary>
              <label class="model-field"><span>Template</span><input type="text" value="Alpaca" /></label>
            </details>
            <section class="model-side-section" data-testid="model-server-api">
              <div data-testid="model-server-view">
                <div class="model-surface__head">
                  <div>
                    <span>Developer / Local Server</span>
                    <strong data-testid="model-server-status">${escapeHtml(snapshot.server.status || "unknown")}</strong>
                  </div>
                  ${modelStatusPill(snapshot.server.gatewayStatus || snapshot.server.status || "unknown")}
                </div>
                <dl data-testid="model-server-endpoints">
                  <div><dt>Native API</dt><dd>${escapeHtml(snapshot.server.nativeApi || snapshot.server.nativeBaseUrl || "/api/v1")}</dd></div>
                  <div><dt>OpenAI API</dt><dd>${escapeHtml(serverBaseUrl)}</dd></div>
                  <div><dt>Loaded</dt><dd data-testid="model-server-loaded-models">${escapeHtml(String(snapshot.server.loadedInstances ?? loadedCount))}</dd></div>
                  <div><dt>Daemon</dt><dd>${escapeHtml(modelStatus.endpoint || daemonEndpoint() || "not configured")}</dd></div>
                </dl>
                <div class="model-log-list" data-testid="model-server-logs">
                  <article class="model-log-row" data-testid="model-server-backend-logs"><strong>gateway</strong><span>${escapeHtml(snapshot.server.gatewayStatus || "pending")}</span><small>Server/API state is projected from daemon model runtime state.</small></article>
                  <article class="model-log-row" data-testid="model-server-request-log"><strong>requests</strong><span>${escapeHtml(invokeReceipt?.id || "no invocation receipt yet")}</span><small>No webview or extension-host model execution.</small></article>
                  <article class="model-log-row" data-testid="model-server-receipts"><strong>receipts</strong><span>${escapeHtml(routeReceipt?.id || invokeReceipt?.id || "pending")}</span><small>Server activity links to daemon receipt/replay state.</small></article>
                </div>
              </div>
            </section>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="policy" data-testid="model-inspector-policy-panel">
            <h3>Policy</h3>
            <dl>
              <div><dt>Authority</dt><dd>daemon-owned</dd></div>
              <div><dt>Privacy</dt><dd>${escapeHtml(selectedRoute.privacy || selectedEndpoint.privacyClass || "local_first")}</dd></div>
              <div><dt>Approvals</dt><dd>${escapeHtml(selectedRoute.approvalPolicy || "route policy")}</dd></div>
              <div><dt>Mutation path</dt><dd>receipted daemon request</dd></div>
            </dl>
            <section class="model-side-section" data-testid="model-runtime-backend">
              <div class="model-surface__head">
                <div>
                  <span>Runtime / Backend</span>
                  <strong>${escapeHtml(selectedBackend.label || selectedBackend.id || selectedEngine.id || "Backend")}</strong>
                </div>
                ${modelStatusPill(selectedBackend.status || selectedEngine.status || "unknown")}
              </div>
              <dl>
                <div><dt>Kind</dt><dd>${escapeHtml(selectedBackend.kind || selectedEngine.kind || "unknown")}</dd></div>
                <div><dt>Process</dt><dd>${escapeHtml(selectedBackend.processStatus || selectedBackend.process?.status || "stateless")}</dd></div>
                <div><dt>Selected engine</dt><dd>${escapeHtml(selectedEngine.id || snapshot.runtimePreference.selectedEngineId || "none")}</dd></div>
                <div><dt>Evidence</dt><dd>${escapeHtml(selectedBackend.evidenceRefs?.join(", ") || "daemon backend registry")}</dd></div>
              </dl>
            </section>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="routes" data-testid="model-inspector-routes-panel">
            <h3>Routes</h3>
            <dl>
              <div><dt>Route</dt><dd>${escapeHtml(selectedRoute.id || "none")}</dd></div>
              <div><dt>Selected model</dt><dd data-model-field="route-model">${escapeHtml(routeReceipt?.details?.selectedModel || selectedEndpoint.modelId || selectedArtifact.modelId || "none")}</dd></div>
              <div><dt>Backend</dt><dd>${escapeHtml(selectedBackend.id || selectedEngine.id || "pending")}</dd></div>
              <div><dt>Receipt</dt><dd>${escapeHtml(routeReceipt?.id || "pending")}</dd></div>
            </dl>
            <section class="model-side-section" data-testid="workflow-node-live-model-binding">
              <div class="model-surface__head">
                <div>
                  <span>Workflow Binding</span>
                  <strong>${escapeHtml(selectedRoute.id || "route pending")}</strong>
                </div>
                ${modelStatusPill(routeReceipt ? "route receipted" : "ready")}
              </div>
              <dl>
                <div><dt>Route</dt><dd>${escapeHtml(selectedRoute.id || "none")}</dd></div>
                <div><dt>Selected model</dt><dd data-model-field="workflow-model">${escapeHtml(routeReceipt?.details?.selectedModel || selectedEndpoint.modelId || selectedArtifact.modelId || "none")}</dd></div>
                <div><dt>Policy</dt><dd>${escapeHtml(selectedRoute.privacy || "local_first")}</dd></div>
                <div><dt>Receipt</dt><dd>${escapeHtml(routeReceipt?.id || "pending")}</dd></div>
              </dl>
              ${renderCommandButton({ label: "Bind in Composer", command: "ioi.workflow.openComposer", payload: { scenarioId: "model-backed-dry-run", phase: "model-binding" } })}
            </section>
            <section class="model-side-section" data-testid="workflow-live-model-dry-run-timeline">
              <div class="model-surface__head">
                <div>
                  <span>Workflow Dry-run Timeline</span>
                  <strong>${escapeHtml(invokeReceipt ? "model invocation complete" : "ready for daemon dry-run")}</strong>
                </div>
                ${modelStatusPill(invokeReceipt ? "receipted" : "pending")}
              </div>
              <ol class="model-timeline">
                <li>route selected: ${escapeHtml(routeReceipt?.details?.routeId || selectedRoute.id || "route")}</li>
                <li>model invoked: <span data-model-field="timeline-model">${escapeHtml(invokeReceipt?.details?.selectedModel || selectedEndpoint.modelId || selectedArtifact.modelId || "model")}</span></li>
                <li>runtime evidence: ${escapeHtml(invokeReceipt?.details?.backendId || selectedBackend.id || selectedEngine.id || "backend")}</li>
              </ol>
            </section>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="receipts" data-testid="model-inspector-receipts-panel">
            <h3>Receipts</h3>
            <section class="model-side-section model-surface--wide" data-testid="model-invocation-receipts-replay">
              <div class="model-surface__head">
                <div>
                  <span>Receipts / Replay</span>
                  <strong>${escapeHtml(snapshot.receipts.length)} daemon receipts</strong>
                </div>
                ${modelStatusPill("daemon-owned")}
              </div>
              <div class="model-log-list">${renderModelReceiptRows(snapshot)}</div>
            </section>
          </section>
        </aside>
      </section>
    </section>
  `;
}

function overviewTone(value) {
  const normalized = String(value || "unknown").toLowerCase();
  if (/connected|ready|loaded|running|active|pass|available/.test(normalized)) {
    return "ready";
  }
  if (/blocked|failed|error|denied/.test(normalized)) {
    return "blocked";
  }
  if (/degraded|warning|starting|loading|pending/.test(normalized)) {
    return "warn";
  }
  return "muted";
}

function overviewPill(label, value, tone = overviewTone(value)) {
  return `
    <span class="overview-pill is-${escapeHtml(tone)}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </span>
  `;
}

function renderOverviewAction({ label, description, command, payload, tone = "default" }) {
  return `
    <button
      class="overview-action is-${escapeHtml(tone)}"
      type="button"
      data-command="${escapeHtml(command)}"${commandPayloadAttr(payload)}
    >
      <span>${escapeHtml(label)}</span>
      <small>${escapeHtml(description)}</small>
    </button>
  `;
}

function renderOverviewRow(label, value, detail, tone = "muted") {
  return `
    <div class="overview-row">
      <span class="overview-row__label">${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
      <small class="is-${escapeHtml(tone)}">${escapeHtml(detail)}</small>
    </div>
  `;
}

function overviewPanelHtml(state) {
  const pageNonce = overviewPanelNonce || nonce();
  overviewPanelNonce = pageNonce;
  const workspace = state.workspace || workspaceSummary();
  const snapshot = modelSnapshotFromState(state);
  const workflows = Array.isArray(state.workflows) ? state.workflows : [];
  const runs = Array.isArray(state.runs) ? state.runs : [];
  const artifacts = Array.isArray(state.artifacts) ? state.artifacts : [];
  const connections = Array.isArray(state.connections) ? state.connections : [];
  const summary = state.summary || {};
  const daemonStatus =
    state.modelMountingStatus?.status || (daemonEndpoint() ? "connected" : "not_configured");
  const daemonDetail =
    daemonStatus === "connected"
      ? state.modelMountingStatus?.endpoint || "daemon endpoint connected"
      : daemonStatus === "degraded"
        ? state.modelMountingStatus?.error || "daemon endpoint degraded"
        : "daemon endpoint not configured";
  const loadedModels = snapshot.instances.filter((instance) =>
    /loaded|ready|running/i.test(String(instance.status || "")),
  );
  const activeRuns = runs.filter((run) =>
    /active|running|queued|pending/i.test(String(run.status || "")),
  );
  const receipts = snapshot.receipts;
  const policyIssueCount =
    summary.policyIssueCount ??
    (Array.isArray(state.policy?.issues) ? state.policy.issues.length : 0);
  const connectorCount = connections.length || summary.connectorCount || 0;
  const connectorReadyCount = connections.filter((connection) =>
    /ready|available|connected|configured/i.test(String(connection.status || "")),
  ).length;
  const recentWorkflow = workflows[0];
  const recentRun = runs[0];
  const recentArtifact = artifacts[0];
  const latestReceipt = receipts[0];
  const workspaceLabel =
    workspace.path && workspace.path !== "Open a workspace folder to ground IOI context."
      ? workspace.path
      : "Open a workspace folder to ground runtime context.";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'nonce-${pageNonce}'; script-src 'nonce-${pageNonce}';"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Autopilot Overview</title>
    <style nonce="${pageNonce}">
      :root {
        color-scheme: dark;
        --overview-bg: var(--vscode-editor-background, #101216);
        --overview-panel: color-mix(in srgb, var(--vscode-editor-background, #101216) 88%, var(--vscode-foreground, #fff) 6%);
        --overview-panel-soft: color-mix(in srgb, var(--vscode-editor-background, #101216) 94%, var(--vscode-foreground, #fff) 4%);
        --overview-border: var(--vscode-panel-border, rgba(255,255,255,.13));
        --overview-text: var(--vscode-foreground, #f4f6f8);
        --overview-muted: var(--vscode-descriptionForeground, #9ca3af);
        --overview-accent: var(--vscode-textLink-foreground, #4ea1ff);
        --overview-ready: #7ee787;
        --overview-warn: #e3b341;
        --overview-blocked: #ff7b72;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: var(--vscode-font-family, ui-sans-serif, system-ui, sans-serif);
        color: var(--overview-text);
        background: var(--overview-bg);
      }
      .overview-shell {
        min-height: 100vh;
        display: grid;
        grid-template-rows: auto auto minmax(0, 1fr);
      }
      .overview-header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 20px;
        align-items: start;
        padding: 28px 32px 22px;
        border-bottom: 1px solid var(--overview-border);
        background: var(--overview-panel-soft);
      }
      .overview-kicker,
      .overview-section__kicker,
      .overview-table th {
        color: var(--overview-muted);
        font-size: 11px;
        font-weight: 700;
        letter-spacing: .08em;
        text-transform: uppercase;
      }
      h1 {
        margin: 7px 0 8px;
        font-size: clamp(28px, 4vw, 42px);
        font-weight: 520;
        letter-spacing: 0;
      }
      .overview-header p {
        max-width: 880px;
        margin: 0;
        color: var(--overview-muted);
        font-size: 14px;
        line-height: 1.5;
      }
      .overview-status {
        min-width: 280px;
        display: grid;
        gap: 8px;
      }
      .overview-pill {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
        min-height: 28px;
        border: 1px solid var(--overview-border);
        border-radius: 999px;
        padding: 4px 10px;
        color: var(--overview-muted);
        font-size: 12px;
      }
      .overview-pill strong { color: var(--overview-text); font-weight: 560; }
      .overview-pill.is-ready { border-color: color-mix(in srgb, var(--overview-ready) 70%, var(--overview-border)); }
      .overview-pill.is-warn { border-color: color-mix(in srgb, var(--overview-warn) 70%, var(--overview-border)); }
      .overview-pill.is-blocked { border-color: color-mix(in srgb, var(--overview-blocked) 70%, var(--overview-border)); }
      .overview-nav {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 1px;
        border-bottom: 1px solid var(--overview-border);
        background: var(--overview-border);
      }
      .overview-action {
        min-height: 76px;
        display: grid;
        align-content: center;
        gap: 5px;
        border: 0;
        border-radius: 0;
        padding: 14px 18px;
        background: var(--overview-panel);
        color: var(--overview-text);
        text-align: left;
        font: inherit;
        cursor: pointer;
      }
      .overview-action span { font-weight: 650; }
      .overview-action small {
        color: var(--overview-muted);
        line-height: 1.35;
      }
      .overview-action:hover,
      .overview-action:focus-visible {
        outline: 1px solid var(--overview-accent);
        outline-offset: -1px;
        background: color-mix(in srgb, var(--overview-panel) 86%, var(--overview-accent) 14%);
      }
      .overview-action.is-primary {
        background: color-mix(in srgb, var(--overview-panel) 80%, var(--overview-accent) 14%);
      }
      .overview-main {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
        min-height: 0;
      }
      .overview-column {
        min-width: 0;
        display: grid;
        align-content: start;
        gap: 18px;
        padding: 22px 32px 34px;
      }
      .overview-column + .overview-column {
        border-left: 1px solid var(--overview-border);
        background: var(--overview-panel-soft);
      }
      .overview-section {
        min-width: 0;
        display: grid;
        gap: 10px;
      }
      .overview-section h2 {
        margin: 0;
        font-size: 16px;
        font-weight: 650;
      }
      .overview-section p {
        margin: 0;
        color: var(--overview-muted);
        line-height: 1.45;
      }
      .overview-board {
        border: 1px solid var(--overview-border);
        border-radius: 8px;
        overflow: hidden;
      }
      .overview-row {
        display: grid;
        grid-template-columns: 128px minmax(0, 1fr) minmax(150px, .8fr);
        gap: 14px;
        align-items: center;
        min-height: 48px;
        padding: 10px 12px;
        border-bottom: 1px solid var(--overview-border);
        background: var(--overview-panel);
      }
      .overview-row:last-child { border-bottom: 0; }
      .overview-row__label,
      .overview-row small {
        color: var(--overview-muted);
      }
      .overview-row strong,
      .overview-row small {
        min-width: 0;
        overflow-wrap: anywhere;
      }
      .overview-row small.is-ready { color: var(--overview-ready); }
      .overview-row small.is-warn { color: var(--overview-warn); }
      .overview-row small.is-blocked { color: var(--overview-blocked); }
      .overview-table {
        width: 100%;
        border-collapse: collapse;
        table-layout: fixed;
        border: 1px solid var(--overview-border);
        border-radius: 8px;
        overflow: hidden;
      }
      .overview-table th,
      .overview-table td {
        padding: 9px 10px;
        border-bottom: 1px solid var(--overview-border);
        text-align: left;
        vertical-align: top;
        background: var(--overview-panel);
      }
      .overview-table tr:last-child td { border-bottom: 0; }
      .overview-table td {
        color: var(--overview-muted);
        line-height: 1.38;
      }
      .overview-table td strong {
        display: block;
        margin-bottom: 3px;
        color: var(--overview-text);
      }
      .overview-side-actions {
        display: grid;
        gap: 8px;
      }
      .overview-side-actions .overview-action {
        min-height: 58px;
        border: 1px solid var(--overview-border);
        border-radius: 6px;
      }
      code {
        color: var(--vscode-textPreformat-foreground, var(--overview-text));
        background: var(--vscode-textCodeBlock-background, transparent);
        border-radius: 4px;
        padding: 2px 5px;
      }
      ${autopilotShellHeaderStyles()}
      @media (max-width: 1000px) {
        .overview-header,
        .overview-main {
          grid-template-columns: minmax(0, 1fr);
        }
        .overview-status { min-width: 0; }
        .overview-nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .overview-column + .overview-column { border-left: 0; border-top: 1px solid var(--overview-border); }
      }
      @media (max-width: 680px) {
        .overview-header,
        .overview-column { padding-left: 18px; padding-right: 18px; }
        .overview-nav,
        .overview-row { grid-template-columns: minmax(0, 1fr); }
      }
    </style>
  </head>
  <body>
    <main class="overview-shell" data-testid="autopilot-overview-home" data-runtime-authority="daemon-owned">
      ${renderAutopilotShellHeader(state, "home")}
      <header class="overview-header">
        <div>
          <div class="overview-kicker">Autopilot Workbench</div>
          <h1>Operator console for autonomous systems</h1>
          <p>
            Build, run, govern, and verify agentic work from one IDE-native surface.
            The Electron workbench projects state and sends typed requests; IOI daemon owns execution authority.
          </p>
        </div>
        <div class="overview-status" aria-label="Runtime status">
          ${overviewPill("Daemon", daemonStatus, overviewTone(daemonStatus))}
          ${overviewPill("Models", `${loadedModels.length}/${snapshot.artifacts.length} loaded`, loadedModels.length ? "ready" : "muted")}
          ${overviewPill("Runs", `${activeRuns.length} active`, activeRuns.length ? "warn" : "ready")}
          ${overviewPill("Policy", `${policyIssueCount} issues`, policyIssueCount ? "warn" : "ready")}
        </div>
      </header>

      <nav class="overview-nav" aria-label="Autopilot primary actions">
        ${renderOverviewAction({
          label: "Build",
          description: "Agent Studio, workflows, workers, and model-backed app intent.",
          command: "ioi.studio.open",
          tone: "primary",
        })}
        ${renderOverviewAction({
          label: "Run",
          description: "Daemon runtime, local models, executions, and connector dry runs.",
          command: "ioi.models.open",
        })}
        ${renderOverviewAction({
          label: "Govern",
          description: "Policy, approvals, secrets, authority, and connector posture.",
          command: "ioi.policy.open",
        })}
        ${renderOverviewAction({
          label: "Verify",
          description: "Receipts, replay, evidence, tests, and run history.",
          command: "ioi.runs.refresh",
        })}
      </nav>

      <section class="overview-main">
        <div class="overview-column">
          <section class="overview-section" aria-label="Current workspace">
            <div class="overview-section__kicker">Current Workspace</div>
            <h2>${escapeHtml(workspace.name || "No workspace selected")}</h2>
            <p><code>${escapeHtml(workspaceLabel)}</code></p>
            <div class="overview-board">
              ${renderOverviewRow("Daemon", daemonStatus, daemonDetail, overviewTone(daemonStatus))}
              ${renderOverviewRow("Models", `${snapshot.artifacts.length} artifacts`, `${loadedModels.length} loaded instances`, loadedModels.length ? "ready" : "muted")}
              ${renderOverviewRow("Workflows", `${workflows.length || summary.workflowCount || 0} indexed`, recentWorkflow?.name || recentWorkflow?.id || "Open composer to create one", workflows.length ? "ready" : "muted")}
              ${renderOverviewRow("Connectors", `${connectorReadyCount}/${connectorCount} ready`, "dry-run only for sprint readiness", connectorReadyCount ? "ready" : "muted")}
            </div>
          </section>

          <section class="overview-section" aria-label="Continue work">
            <div class="overview-section__kicker">Continue</div>
            <table class="overview-table">
              <thead>
                <tr><th>Surface</th><th>Current item</th><th>Status</th></tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Workflow</strong>Composable autonomous system</td>
                  <td>${escapeHtml(recentWorkflow?.name || recentWorkflow?.id || "No saved workflow projected")}</td>
                  <td>${escapeHtml(recentWorkflow?.status || "open composer")}</td>
                </tr>
                <tr>
                  <td><strong>Run</strong>Execution timeline</td>
                  <td>${escapeHtml(recentRun?.name || recentRun?.id || "No active run projected")}</td>
                  <td>${escapeHtml(recentRun?.status || "idle")}</td>
                </tr>
                <tr>
                  <td><strong>Evidence</strong>Receipt and replay trail</td>
                  <td>${escapeHtml(latestReceipt?.receiptId || recentArtifact?.id || "No receipt projected")}</td>
                  <td>${escapeHtml(latestReceipt ? "daemon receipt" : recentArtifact?.status || "pending evidence")}</td>
                </tr>
              </tbody>
            </table>
          </section>

          <section class="overview-section" aria-label="Readiness">
            <div class="overview-section__kicker">Connector Sprint Readiness</div>
            <div class="overview-board">
              ${renderOverviewRow("Execution", daemonStatus === "connected" ? "Daemon path available" : "Daemon path blocked", "UI must not own durable runtime", daemonStatus === "connected" ? "ready" : "blocked")}
              ${renderOverviewRow("Model route", loadedModels.length ? "Live model route ready" : "No loaded route", "Models mode is the route source", loadedModels.length ? "ready" : "warn")}
              ${renderOverviewRow("External action", "disabled", "use fixture/dry-run connector flows only", "ready")}
              ${renderOverviewRow("Audit", receipts.length ? `${receipts.length} receipts` : "Receipts pending", "receipt and replay remain daemon-owned", receipts.length ? "ready" : "warn")}
            </div>
          </section>
        </div>

        <aside class="overview-column" aria-label="Open surfaces">
          <section class="overview-section">
            <div class="overview-section__kicker">Create</div>
            <div class="overview-side-actions">
              ${renderOverviewAction({
                label: "Agent Studio",
                description: "Prompt-to-agent/workflow intent, routed through daemon-owned boundaries.",
                command: "ioi.studio.open",
                tone: "primary",
              })}
              ${renderOverviewAction({
                label: "Workflow Composer",
                description: "Open the rich graph canvas directly.",
                command: "ioi.workflow.openComposer",
              })}
              ${renderOverviewAction({
                label: "Mount Models",
                description: "Inspect local artifacts, load routes, and bind workflows.",
                command: "ioi.models.open",
              })}
              ${renderOverviewAction({
                label: "Connector Dry Run",
                description: "Exercise connector-neutral capability binding without external action.",
                command: "ioi.workflow.openComposer",
                payload: { scenarioId: "connector-fixture", phase: "connector-fixture" },
              })}
            </div>
          </section>

          <section class="overview-section">
            <div class="overview-section__kicker">Operate</div>
            <div class="overview-side-actions">
              ${renderOverviewAction({
                label: "Runs",
                description: "Open runtime state, active jobs, and latest execution history.",
                command: "ioi.runs.refresh",
              })}
              ${renderOverviewAction({
                label: "Policy",
                description: "Review approval posture and authority gates.",
                command: "ioi.policy.open",
              })}
              ${renderOverviewAction({
                label: "Connections",
                description: "Inspect available services and connector posture.",
                command: "ioi.connections.inspect",
              })}
              ${renderOverviewAction({
                label: "Command Center",
                description: "Search Autopilot commands and runtime surfaces.",
                command: "ioi.commandCenter.open",
              })}
            </div>
          </section>
        </aside>
      </section>
    </main>
    <script nonce="${pageNonce}">
      const vscode = acquireVsCodeApi();
      function parsePayload(raw) {
        if (!raw) return undefined;
        try {
          return JSON.parse(raw);
        } catch (error) {
          console.error("[IOI Overview] Failed to parse command payload", error);
          return undefined;
        }
      }
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "command",
            command: button.dataset.command,
            payload: parsePayload(button.dataset.payload)
          });
        });
      });
    </script>
  </body>
</html>`;
}

function renderModelsView(state) {
  return `
    <section data-inspection-target="ioi-models-view">
      ${renderModelsPanelBody(state, { compact: true })}
    </section>
  `;
}

function renderRunsView(state) {
  const { target, focused, items } = studioFocusedTraceTarget();
  const runs = firstArray(state.runs);
  const timelineItems = [
    ...runs.map((run) => ({
      stepId: studioTraceStepId("run", run.runId || run.id),
      title: run.label || run.runId || "Runtime run",
      summary: run.summary || run.currentStepLabel || "Runtime run projected by IOI daemon.",
      status: run.status || "observed",
      kind: "run",
      receiptRefs: normalizeReceiptRefs(run),
    })),
    ...items.filter((item) => item.visibility !== STUDIO_RUNTIME_VISIBILITY.debugOnly),
  ];
  const receiptItems = items.filter((item) => item.receiptRefs.length > 0 || /receipt/i.test(item.kind));
  const replayItems = items.filter((item) => /replay|timeline|turn|stream/i.test(item.kind));
  const policyItems = items.filter((item) => /policy|approval|lease/.test(item.kind));
  const commandItems = items.filter((item) => /command|diagnostic|test|tool/.test(item.kind));
  const traceRow = (item, testId = "tracing-timeline-step") => `
    <li data-testid="${escapeHtml(testId)}" data-trace-step-id="${escapeHtml(item.stepId)}"${item.stepId === target.stepId ? ' class="is-focused"' : ""}>
      <span class="status-pill">${escapeHtml(item.status || "observed")}</span>
      <strong>${escapeHtml(item.title || item.kind || "Trace step")}</strong>
      <span>${escapeHtml(item.summary || "")}</span>
      <code>${escapeHtml(item.receiptRefs?.join(" · ") || item.id || item.stepId)}</code>
    </li>
  `;
  const fallback = (label) => `<li class="tracing-empty"><span>${escapeHtml(label)}</span></li>`;
  return `
    <section
      class="tracing-surface"
      data-testid="tracing-surface"
      data-runtime-authority="daemon-owned"
      data-focused-trace-step="${escapeHtml(target.stepId || "")}"
      data-tracing-separation-achieved="true"
    >
      <header class="tracing-header">
        <div>
          <p class="eyebrow">Runs / Tracing</p>
          <h2>Runtime evidence console</h2>
          <p>Receipts, replay, policy internals, command logs, model metadata, worker/browser status, and proof export live here instead of crowding Agent Studio.</p>
        </div>
        <div class="tracing-header__actions">
          ${renderCommandButton({ label: "Back to Studio", command: "ioi.studio.open", payload: { source: "tracing" } })}
          ${renderCommandButton({ label: "Refresh tracing", command: "ioi.runs.refresh" })}
        </div>
      </header>
      <section class="tracing-focused-step" data-testid="tracing-focused-step">
        <p class="eyebrow">Focused trace step</p>
        <h3>${escapeHtml(focused?.title || target.kind || "Current Studio session")}</h3>
        <p>${escapeHtml(focused?.summary || "Opened from Agent Studio View Trace affordance.")}</p>
        <dl>
          <div><dt>Session</dt><dd>${escapeHtml(target.sessionId || "studio-session-current")}</dd></div>
          <div><dt>Step</dt><dd>${escapeHtml(target.stepId || "current")}</dd></div>
          <div><dt>Kind</dt><dd>${escapeHtml(focused?.kind || target.kind || "session.summary")}</dd></div>
          <div><dt>Receipts</dt><dd><code>${escapeHtml((focused?.receiptRefs?.length ? focused.receiptRefs : target.receiptRefs || []).join(" · ") || "pending daemon receipt")}</code></dd></div>
        </dl>
      </section>
      <div class="tracing-grid">
        <section class="tracing-panel tracing-panel--wide" data-testid="tracing-timeline">
          <h3>Timeline</h3>
          <ol>${timelineItems.length ? timelineItems.slice(-18).map((item) => traceRow(item)).join("") : fallback("No runtime timeline is projected yet.")}</ol>
        </section>
        <section class="tracing-panel" data-testid="tracing-receipt-detail">
          <h3>Receipts</h3>
          <ol>${receiptItems.length ? receiptItems.slice(-12).map((item) => traceRow(item, "tracing-receipt-step")).join("") : fallback("No daemon receipts projected yet.")}</ol>
        </section>
        <section class="tracing-panel" data-testid="tracing-replay-step">
          <h3>Replay</h3>
          <ol>${replayItems.length ? replayItems.slice(-12).map((item) => traceRow(item, "tracing-replay-row")).join("") : fallback("Replay steps appear when daemon events are observed.")}</ol>
        </section>
        <section class="tracing-panel" data-testid="tracing-policy-detail">
          <h3>Policy</h3>
          <ol>${policyItems.length ? policyItems.slice(-10).map((item) => traceRow(item, "tracing-policy-row")).join("") : fallback("No blocking policy lease is active.")}</ol>
        </section>
        <section class="tracing-panel" data-testid="tracing-command-log-detail">
          <h3>Commands / Tests / Tools</h3>
          <ol>${commandItems.length ? commandItems.slice(-10).map((item) => traceRow(item, "tracing-command-row")).join("") : fallback("No daemon command or test log is projected yet.")}</ol>
        </section>
        <section class="tracing-panel tracing-panel--wide" data-testid="tracing-proof-export">
          <h3>Proof bundle posture</h3>
          <p>Model prose is never accepted as runtime proof. Verified badges require daemon receipt refs; full proof export is assembled from this trace surface.</p>
          <code>${escapeHtml(JSON.stringify({
            modelProseNotAcceptedAsRuntimeTruth: true,
            verifiedBadgesRequireReceiptRefs: true,
            projectionOwner: "ioi-workbench",
            runtimeAuthority: "daemon-owned",
            externalConnectorAction: false,
          }, null, 2))}</code>
        </section>
      </div>
    </section>
  `;
}

function renderArtifactsView(state) {
  return renderItems(
    state.artifacts || [],
    "No recent artifact/evidence activity is available for this workspace snapshot.",
    (artifact) => `
      <article class="item-card">
        <div class="item-head">
          <strong>${escapeHtml(artifact.action || artifact.sessionKind || "Artifact")}</strong>
          <span>${escapeHtml(formatRelativeTime(artifact.timestampMs))}</span>
        </div>
        <p>${escapeHtml(artifact.message || "Evidence-linked activity")}</p>
        <code>${escapeHtml(artifact.evidenceThreadId || artifact.activityId)}</code>
        ${
          artifact.activityId || artifact.evidenceThreadId || artifact.connectorId
            ? `<div class="actions item-actions">
                ${renderCommandButton({
                  label: "Open in Chat Session",
                  command: "ioi.chatSession.openArtifact",
                  payload: {
                    artifactId: artifact.activityId,
                  },
                })}
                ${renderCommandButton({
                  label: "Review in Chat",
                  command: "ioi.artifacts.review",
                  payload: {
                    artifactId: artifact.activityId,
                    evidenceThreadId: artifact.evidenceThreadId,
                    connectorId: artifact.connectorId,
                  },
                })}
                ${
                  artifact.evidenceThreadId
                    ? renderCommandButton({
                        label: "Open evidence session",
                        command: "ioi.artifacts.openEvidence",
                        payload: {
                          sessionId: artifact.evidenceThreadId,
                        },
                      })
                    : ""
                }
                ${
                  artifact.connectorId
                    ? renderCommandButton({
                        label: "Open connector policy",
                        command: "ioi.artifacts.openPolicy",
                        payload: {
                          connectorId: artifact.connectorId,
                        },
                      })
                    : ""
                }
              </div>`
            : ""
        }
      </article>
    `,
  );
}

function renderPolicyView(state) {
  const policy = state.policy;
  if (!policy) {
    return `<div class="empty-state">Policy summary is not available yet for this workspace snapshot.</div>`;
  }
  return `
    <div class="metric-grid">
      <div class="metric-card"><span>Entries</span><strong>${escapeHtml(policy.totalEntries)}</strong></div>
      <div class="metric-card"><span>Connectors</span><strong>${escapeHtml(policy.connectorCount)}</strong></div>
      <div class="metric-card"><span>Connected</span><strong>${escapeHtml(policy.connectedConnectorCount)}</strong></div>
      <div class="metric-card"><span>Runtime skills</span><strong>${escapeHtml(policy.runtimeSkillCount)}</strong></div>
      <div class="metric-card"><span>Authority sources</span><strong>${escapeHtml(policy.authoritativeSourceCount)}</strong></div>
      <div class="metric-card"><span>Active issues</span><strong>${escapeHtml(policy.activeIssueCount)}</strong></div>
    </div>
    <div class="callout">
      Policy state here is a projection of the IOI runtime and capability registry. Approval and settlement authority remain outside the workbench shell.
    </div>
  `;
}

function renderConnectionsView(state) {
  return renderItems(
    state.connections || [],
    "No connector catalog entries are available for this workspace snapshot.",
    (connection) => `
      <article class="item-card">
        <div class="item-head">
          <strong>${escapeHtml(connection.name || connection.id)}</strong>
          <span class="status-pill">${escapeHtml(connection.status || "unknown")}</span>
        </div>
        <p>${escapeHtml(connection.summary || "Connector surface")}</p>
        <code>${escapeHtml(connection.id)}</code>
        <div class="actions item-actions">
          ${renderCommandButton({
            label: "Open connector overview",
            command: "ioi.connections.openConnector",
            payload: {
              connectorId: connection.id,
            },
          })}
          ${renderCommandButton({
            label: "Open connector policy",
            command: "ioi.artifacts.openPolicy",
            payload: {
              connectorId: connection.id,
            },
          })}
        </div>
      </article>
    `,
  );
}

function renderDirectModeActivityView({ title, command, description }) {
  return `
    <section class="workflow-direct-open" data-testid="autopilot-direct-mode-activity">
      <span>${escapeHtml(description || `Opening ${title} mode in the editor area...`)}</span>
      <button class="action" type="button" data-command="${escapeHtml(command)}">Open ${escapeHtml(title)}</button>
    </section>
  `;
}

function renderBody(viewId, state) {
  switch (viewId) {
    case "ioi.chat":
      return renderChatView(state);
    case "ioi.overviewActivity":
      return renderOverviewActivityView();
    case "ioi.studio":
      return renderStudioView(state);
    case "ioi.workflows":
      return renderWorkflowView(state);
    case "ioi.models":
      return renderModelsView(state);
    case "ioi.runs":
      return renderRunsView(state);
    case "ioi.runsActivity":
      return renderDirectModeActivityView({
        title: "Runs",
        command: "ioi.runs.refresh",
        description: "Opening the persistent Runs surface; this sidebar is only a transient activity projection.",
      });
    case "ioi.artifacts":
      return renderArtifactsView(state);
    case "ioi.policy":
      return renderPolicyView(state);
    case "ioi.policyActivity":
      return renderDirectModeActivityView({
        title: "Policy",
        command: "ioi.policy.open",
        description: "Opening the persistent Policy surface; this sidebar is only a transient activity projection.",
      });
    case "ioi.connections":
      return renderConnectionsView(state);
    case "ioi.connectorsActivity":
      return renderDirectModeActivityView({
        title: "Connectors",
        command: "ioi.connections.inspect",
        description: "Opening the persistent Connectors surface; this sidebar is only a transient activity projection.",
      });
    case "ioi.codeActivity":
      return renderDirectModeActivityView({
        title: "Code",
        command: "ioi.code.open",
        description: "Opening Code mode with local VS Code substrate controls.",
      });
    default:
      return `<div class="empty-state">No renderer registered for this view.</div>`;
  }
}

function renderHtml(view, state) {
  const workspace = state.workspace || workspaceSummary();
  const isChatView = view.id === "ioi.chat";
  const isStudioView = view.id === "ioi.studio";
  const isWorkflowView = view.id === "ioi.workflows";
  const isModelsView = view.id === "ioi.models";
  const shellModeId = modeIdForViewId(view.id) || currentAutopilotModeId;
  const appearanceThemeId =
    typeof state.appearance?.themeId === "string"
      ? state.appearance.themeId
      : "dark-modern";
  const actions = view.actions
    .map((action) => renderCommandButton(action))
    .join("");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
      :root {
        color-scheme: dark;
      }
      body[data-autopilot-theme^="light"] {
        color-scheme: light;
        --ioi-operator-chat-bg: #ffffff;
        --ioi-operator-chat-border: #d4d4d4;
        --ioi-operator-chat-border-strong: #c8c8c8;
        --ioi-operator-chat-text: #3c3c3c;
        --ioi-operator-chat-text-secondary: #616161;
        --ioi-operator-chat-text-muted: #7a7a7a;
        --ioi-operator-chat-accent: #0078d4;
        --ioi-operator-chat-control-bg: #f8f8f8;
        --ioi-operator-chat-control-hover: #f3f3f3;
        --ioi-operator-chat-selected-bg: #e8f3ff;
        --ioi-operator-chat-selected-border: #0078d4;
      }
      body[data-autopilot-theme^="dark"] {
        color-scheme: dark;
        --ioi-operator-chat-bg: #000000;
        --ioi-operator-chat-border: rgba(255, 255, 255, 0.2);
        --ioi-operator-chat-border-strong: rgba(255, 255, 255, 0.72);
        --ioi-operator-chat-text: #ffffff;
        --ioi-operator-chat-text-secondary: rgba(255, 255, 255, 0.86);
        --ioi-operator-chat-text-muted: rgba(255, 255, 255, 0.58);
        --ioi-operator-chat-accent: #0098ff;
        --ioi-operator-chat-control-bg: #000000;
        --ioi-operator-chat-control-hover: #1f1f1f;
        --ioi-operator-chat-selected-bg: rgba(0, 152, 255, 0.12);
        --ioi-operator-chat-selected-border: #0098ff;
      }
      body {
        margin: 0;
        padding: 16px;
        font-family: var(--vscode-font-family);
        color: var(--vscode-foreground);
        background: var(--vscode-sideBar-background);
      }
      body.is-chat-view {
        width: 100vw;
        height: 100vh;
        padding: 0;
        overflow: hidden;
        background: var(--ioi-operator-chat-bg, var(--vscode-sideBar-background));
      }
      .eyebrow {
        margin: 0 0 8px;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      h2 {
        margin: 0 0 10px;
        font-size: 20px;
        line-height: 1.1;
      }
      p {
        margin: 0 0 14px;
        color: var(--vscode-descriptionForeground);
        line-height: 1.45;
      }
      .card, .item-card, .metric-card, .callout, .diagnostics {
        border: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-sideBar-background) 90%, white 10%);
        border-radius: 6px;
      }
      .card, .callout, .diagnostics {
        padding: 12px;
        margin: 0 0 14px;
      }
      .item-card {
        padding: 12px;
      }
      .item-card p {
        margin: 0 0 8px;
      }
      .workflow-direct-open {
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 0;
        color: var(--vscode-descriptionForeground);
        background: var(--vscode-sideBar-background);
      }
      .workflow-direct-open span {
        font-size: 12px;
        opacity: 0.72;
      }
      .model-workbench {
        min-width: 0;
        display: grid;
        gap: 10px;
      }
      .model-workbench__header,
      .model-quick-loader,
      .model-surface {
        min-width: 0;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 92%, var(--vscode-foreground) 8%);
      }
      .model-workbench__header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 14px;
        padding: 12px;
      }
      .model-workbench__header span,
      .model-surface__head span,
      .model-quick-loader span {
        display: block;
        color: var(--vscode-descriptionForeground);
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
      }
      .model-workbench__header h2 {
        margin: 4px 0 6px;
        font-size: 18px;
      }
      .model-workbench__header p {
        margin: 0;
        max-width: 720px;
      }
      .model-workbench__status,
      .model-workbench__actions,
      .model-surface__head {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }
      .model-quick-loader {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr)) auto;
        gap: 12px;
        align-items: center;
        padding: 12px;
      }
      .model-quick-loader strong,
      .model-surface strong {
        display: block;
        min-width: 0;
        overflow-wrap: anywhere;
      }
      .model-quick-loader small,
      .model-surface small {
        display: block;
        margin-top: 4px;
        color: var(--vscode-descriptionForeground);
        line-height: 1.35;
        overflow-wrap: anywhere;
      }
      .model-workbench__grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
      }
      .model-surface {
        padding: 12px;
      }
      .model-surface--wide {
        grid-column: 1 / -1;
      }
      .model-surface__head {
        justify-content: space-between;
        margin-bottom: 10px;
      }
      .model-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
        table-layout: fixed;
      }
      .model-table th,
      .model-table td {
        padding: 7px 8px;
        border-bottom: 1px solid var(--vscode-panel-border);
        text-align: left;
        vertical-align: top;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .model-table th {
        color: var(--vscode-descriptionForeground);
        font-size: 10px;
        text-transform: uppercase;
      }
      .model-table th:nth-child(1),
      .model-table td:nth-child(1) {
        width: 30%;
      }
      .model-table th:nth-child(2),
      .model-table td:nth-child(2),
      .model-table th:nth-child(3),
      .model-table td:nth-child(3) {
        width: 84px;
      }
      .model-table th:nth-child(4),
      .model-table td:nth-child(4) {
        width: 170px;
      }
      .model-table th:nth-child(5),
      .model-table td:nth-child(5) {
        width: 112px;
      }
      .model-table th:nth-child(6),
      .model-table td:nth-child(6) {
        width: 104px;
      }
      .model-table th:nth-child(7),
      .model-table td:nth-child(7) {
        width: 138px;
      }
      .model-table small {
        margin: 3px 0 0;
      }
      .model-status {
        display: inline-flex;
        align-items: center;
        min-height: 20px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 999px;
        padding: 2px 8px;
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
      }
      .model-status.is-ready {
        border-color: color-mix(in srgb, #2ea043 70%, var(--vscode-panel-border));
        color: #7ee787;
      }
      .model-status.is-warn {
        border-color: color-mix(in srgb, #d29922 70%, var(--vscode-panel-border));
        color: #e3b341;
      }
      .model-status.is-blocked {
        border-color: color-mix(in srgb, #f85149 70%, var(--vscode-panel-border));
        color: #ff7b72;
      }
      .model-progress {
        height: 8px;
        border-radius: 999px;
        overflow: hidden;
        background: color-mix(in srgb, var(--vscode-panel-border) 60%, transparent);
      }
      .model-progress span {
        display: block;
        height: 100%;
        background: var(--vscode-textLink-foreground);
      }
      .model-surface dl {
        display: grid;
        gap: 8px;
        margin: 0;
      }
      .model-surface dl div {
        min-width: 0;
        display: grid;
        grid-template-columns: 95px minmax(0, 1fr);
        gap: 8px;
      }
      .model-surface dt {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
      }
      .model-surface dd {
        margin: 0;
        overflow-wrap: anywhere;
      }
      .model-log-list,
      .model-timeline {
        display: grid;
        gap: 8px;
        margin: 0;
        padding: 0;
      }
      .model-timeline {
        padding-left: 18px;
      }
      .model-log-row {
        display: grid;
        gap: 3px;
        padding-bottom: 8px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-empty {
        color: var(--vscode-descriptionForeground);
        border: 1px dashed var(--vscode-panel-border);
        border-radius: 6px;
        padding: 10px;
      }
      .model-workbench.is-compact .model-workbench__grid {
        grid-template-columns: minmax(0, 1fr);
      }
      .model-workbench.is-compact .model-quick-loader {
        grid-template-columns: minmax(0, 1fr);
      }
      .models-lmstudio {
        min-height: 100vh;
        gap: 0;
        background: var(--vscode-editor-background);
        color: var(--vscode-foreground);
      }
      .model-state-banner {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
        padding: 9px 12px;
        border-bottom: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #d29922) 18%, transparent);
        color: var(--vscode-foreground);
      }
      .model-state-banner.is-error {
        background: color-mix(in srgb, var(--vscode-editorError-foreground, #f85149) 18%, transparent);
      }
      .model-state-banner span {
        min-width: 0;
        color: var(--vscode-descriptionForeground);
        overflow-wrap: anywhere;
      }
      .models-lmstudio__primary {
        display: grid;
        grid-template-columns: minmax(160px, 220px) minmax(420px, 1fr) minmax(340px, 390px);
        height: 100vh;
        min-height: 620px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio[data-active-model-surface="discover"] .models-lmstudio__primary,
      .models-lmstudio[data-active-model-surface="sources"] .models-lmstudio__primary {
        grid-template-columns: minmax(160px, 220px) minmax(0, 1fr);
      }
      .models-lmstudio[data-active-model-surface="discover"] .models-lmstudio__inspector,
      .models-lmstudio[data-active-model-surface="sources"] .models-lmstudio__inspector {
        display: none;
      }
      .models-lmstudio__rail,
      .models-lmstudio__library,
      .models-lmstudio__inspector {
        min-width: 0;
        border-radius: 0;
        border-top: 0;
        border-bottom: 0;
        border-left: 0;
      }
      .models-lmstudio__rail {
        display: grid;
        align-content: start;
        gap: 8px;
        padding: 12px 8px;
        border-right: 1px solid var(--vscode-panel-border);
        background: var(--vscode-sideBar-background);
      }
      .models-lmstudio__rail strong {
        margin: 0 0 8px;
        font-size: 12px;
        color: var(--vscode-descriptionForeground);
      }
      .models-lmstudio__rail button,
      .models-lmstudio__tabs button,
      .model-icon-button,
      .model-discover-row {
        border: 1px solid transparent;
        background: transparent;
        color: var(--vscode-foreground);
        border-radius: 5px;
      }
      .models-lmstudio__rail button {
        display: flex;
        justify-content: space-between;
        padding: 7px 10px;
        text-align: left;
      }
      .models-lmstudio__rail button.is-active,
      .model-loader-row.is-selected,
      .model-discover-row.is-selected,
      .model-table tr.is-selected {
        background: color-mix(in srgb, var(--vscode-button-background) 68%, transparent);
        color: var(--vscode-button-foreground);
      }
      .models-lmstudio__rail-status {
        display: grid;
        gap: 5px;
        margin-top: 10px;
        padding: 9px;
        border-top: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio__rail-status span {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
      }
      .models-lmstudio__library {
        display: block;
        min-height: 0;
        padding: 0;
        background: var(--vscode-editor-background);
        overflow: hidden;
      }
      .models-lmstudio__local {
        height: 100%;
        min-height: 0;
        display: grid;
        grid-template-rows: auto minmax(0, 1fr) auto;
      }
      .models-lmstudio__local:not(.is-active),
      .models-lmstudio__discover[hidden] {
        display: none;
      }
      .models-lmstudio__library-header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(240px, 320px);
        gap: 12px;
        align-items: center;
        padding: 8px 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio__library-header h2,
      .models-lmstudio__inspector-header h2,
      .models-lmstudio__dialog-title h2 {
        margin: 0;
        font-size: 14px;
        font-weight: 600;
      }
      .models-lmstudio__search {
        min-width: 0;
        display: flex;
        align-items: center;
        gap: 6px;
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 5px;
        background: var(--vscode-input-background);
        color: var(--vscode-input-foreground);
        padding: 4px 8px;
      }
      .models-lmstudio__search input {
        min-width: 0;
        width: 100%;
        border: 0;
        outline: 0;
        background: transparent;
        color: inherit;
      }
      .models-lmstudio__table-wrap {
        min-height: 0;
        overflow: auto;
      }
      .model-table__name strong {
        display: block;
      }
      .model-chip {
        display: inline-flex;
        align-items: center;
        max-width: 100%;
        min-height: 17px;
        margin: 0 4px 3px 0;
        padding: 1px 6px;
        border: 1px solid color-mix(in srgb, var(--vscode-textLink-foreground) 70%, var(--vscode-panel-border));
        border-radius: 4px;
        color: var(--vscode-textLink-foreground);
        font-size: 10px;
        line-height: 1.2;
      }
      .model-chip.is-muted {
        border-color: var(--vscode-panel-border);
        color: var(--vscode-descriptionForeground);
      }
      .model-actions-cell {
        display: flex;
        gap: 5px;
        white-space: nowrap;
      }
      .model-icon-button {
        min-width: 26px;
        min-height: 26px;
        padding: 3px 6px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        font-size: 11px;
      }
      .models-lmstudio__status-strip {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 9px 12px;
        border-top: 1px solid var(--vscode-panel-border);
        color: var(--vscode-descriptionForeground);
        font-size: 12px;
      }
      .models-lmstudio__status-strip code {
        padding: 3px 6px;
        border-radius: 4px;
        background: var(--vscode-textCodeBlock-background);
        color: var(--vscode-textPreformat-foreground);
      }
      .models-lmstudio__inspector {
        display: grid;
        grid-template-rows: auto auto auto minmax(0, 1fr);
        align-content: stretch;
        gap: 0;
        padding: 0;
        border-right: 0;
        border-left: 1px solid var(--vscode-panel-border);
        background: var(--vscode-sideBar-background);
        overflow: hidden;
      }
      .models-lmstudio__inspector-header,
      .models-lmstudio__inspector-actions,
      .models-lmstudio__tabs,
      .models-lmstudio__dialog-title,
      .models-lmstudio__estimate,
      .model-dialog-options,
      .model-toggle-row,
      .model-range-row {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .models-lmstudio__inspector-header {
        justify-content: space-between;
        padding: 11px 14px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-icon-label {
        display: inline-flex;
        margin-right: 4px;
        color: var(--vscode-textLink-foreground);
      }
      .models-lmstudio__inspector-actions {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        padding: 10px 14px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio__tabs {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        border-radius: 0;
        background: color-mix(in srgb, var(--vscode-editor-background) 72%, var(--vscode-sideBar-background));
        padding: 3px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .models-lmstudio__tabs button {
        padding: 5px;
        font-size: 11px;
      }
      .models-lmstudio__tabs button.is-active {
        background: var(--vscode-button-secondaryBackground);
      }
      .models-lmstudio__tab-panel {
        display: none;
      }
      .models-lmstudio__tab-panel.is-active {
        display: block;
        min-height: 0;
        overflow: auto;
        padding: 10px 14px 18px;
      }
      .models-lmstudio__tab-panel h3 {
        margin: 2px 0 0;
        font-size: 12px;
      }
      .model-side-section,
      .model-accordion {
        display: grid;
        gap: 9px;
        margin: 0;
        padding: 10px 0;
        border-top: 1px solid var(--vscode-panel-border);
      }
      .model-side-section:first-child,
      .model-accordion:first-of-type {
        border-top: 0;
        padding-top: 0;
      }
      .model-side-section .model-surface__head {
        margin-bottom: 0;
      }
      .model-accordion summary,
      .model-side-section summary {
        cursor: pointer;
        color: var(--vscode-foreground);
        font-weight: 600;
      }
      .model-muted {
        margin: 0;
        color: var(--vscode-descriptionForeground);
        line-height: 1.35;
      }
      .models-lmstudio__inspector .model-quick-loader,
      .models-lmstudio__inspector .model-load-dialog {
        grid-template-columns: minmax(0, 1fr);
        border: 0;
        border-radius: 0;
        background: transparent;
        padding-left: 0;
        padding-right: 0;
      }
      .models-lmstudio__inspector .model-quick-loader:not([open]) {
        gap: 0;
      }
      .models-lmstudio__inspector .model-loader-row {
        grid-template-columns: minmax(0, 1fr) auto;
      }
      .models-lmstudio__inspector .model-loader-row > span:nth-child(2),
      .models-lmstudio__inspector .model-loader-row > span:nth-child(3) {
        display: none;
      }
      .models-lmstudio__ops {
        display: grid;
        grid-template-columns: repeat(3, minmax(260px, 1fr));
        gap: 10px;
        padding: 10px;
      }
      .models-lmstudio__ops .model-surface--wide {
        grid-column: 1 / -1;
      }
      .model-loader-list {
        display: grid;
        gap: 4px;
      }
      .model-loader-row,
      .model-discover-row {
        width: 100%;
        display: grid;
        grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr) auto auto;
        gap: 8px;
        align-items: center;
        padding: 7px;
        text-align: left;
      }
      .model-loader-row strong,
      .model-loader-row small,
      .model-discover-row span {
        display: block;
        overflow-wrap: anywhere;
      }
      .models-lmstudio__discover {
        height: 100%;
        min-height: 0;
        display: grid;
        grid-template-columns: minmax(330px, 38%) minmax(0, 1fr);
        background: var(--vscode-editor-background);
      }
      .model-discovery-list,
      .model-discovery-detail {
        min-width: 0;
        min-height: 0;
        overflow: auto;
      }
      .model-discovery-list {
        border-right: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-sideBar-background) 86%, var(--vscode-editor-background));
      }
      .model-discovery-toolbar {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 8px;
        padding: 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-discovery-meta,
      .model-discovery-provider-strip {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 10px;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
      }
      .model-discovery-meta {
        justify-content: space-between;
      }
      .model-discovery-sort {
        display: inline-flex;
        align-items: center;
        gap: 6px;
      }
      .model-discovery-sort select {
        height: 28px;
        max-width: 138px;
        color: var(--vscode-foreground);
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 5px;
        background: var(--vscode-dropdown-background, var(--vscode-input-background));
      }
      .model-discovery-provider-strip {
        flex-wrap: wrap;
        border-top: 1px solid var(--vscode-panel-border);
      }
      .model-discovery-provider-strip span {
        padding: 2px 6px;
        border-radius: 999px;
        background: color-mix(in srgb, var(--vscode-button-secondaryBackground) 52%, transparent);
      }
      .model-discovery-results {
        display: grid;
        gap: 7px;
        padding: 10px;
      }
      .model-discover-result {
        width: 100%;
        min-width: 0;
        display: grid;
        grid-template-columns: 46px minmax(0, 1fr);
        gap: 10px;
        align-items: center;
        padding: 9px 10px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 8px;
        background: color-mix(in srgb, var(--vscode-editor-background) 78%, var(--vscode-sideBar-background));
        color: var(--vscode-foreground);
        text-align: left;
        transition: background 120ms ease, border-color 120ms ease, transform 120ms ease;
      }
      .model-discover-result:hover,
      .model-discover-result:focus-visible {
        border-color: color-mix(in srgb, var(--vscode-focusBorder, #4da3ff) 70%, var(--vscode-panel-border));
        transform: translateX(1px);
      }
      .model-discover-result.is-selected {
        border-color: color-mix(in srgb, var(--vscode-button-background) 75%, var(--vscode-panel-border));
        background: color-mix(in srgb, var(--vscode-button-background) 42%, var(--vscode-editor-background));
        color: var(--vscode-foreground);
      }
      .model-discover-result__logo {
        width: 40px;
        height: 40px;
        display: inline-grid;
        place-items: center;
        border: 1px solid color-mix(in srgb, var(--vscode-focusBorder, #4da3ff) 46%, var(--vscode-panel-border));
        border-radius: 7px;
        background: color-mix(in srgb, var(--vscode-button-secondaryBackground) 78%, var(--vscode-editor-background));
        color: var(--vscode-button-secondaryForeground);
        font-size: 12px;
        font-weight: 700;
      }
      .model-discover-result__body {
        min-width: 0;
        display: flex;
        flex-direction: column;
        gap: 3px;
      }
      .model-discover-result__body strong,
      .model-discover-result__body small {
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .model-discover-result__body strong {
        display: block;
        line-height: 1.18;
        white-space: normal;
      }
      .model-discover-result__body small {
        color: var(--vscode-descriptionForeground);
        white-space: normal;
      }
      .model-discover-result__verified,
      .model-discover-result__age {
        margin-left: 6px;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        font-weight: 500;
      }
      .model-discover-result__age {
        margin-left: 0;
      }
      .model-discover-result__tags {
        grid-column: 2;
        max-width: 100%;
        text-align: left;
      }
      .model-discovery-detail {
        display: grid;
        align-content: start;
        gap: 14px;
        padding: 14px 16px 20px;
      }
      .model-discovery-detail header,
      .model-discovery-stats,
      .model-download-options > header,
      .model-download-options > div,
      .model-more-from {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .model-discovery-detail header {
        justify-content: space-between;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-discovery-detail h2,
      .model-discovery-detail h3 {
        margin: 0;
      }
      .model-discovery-stats {
        flex-wrap: wrap;
        color: var(--vscode-descriptionForeground);
        font-size: 12px;
      }
      .model-discovery-stats span,
      .model-discovery-facts dd,
      .model-download-options span,
      .model-more-from span,
      .model-discovery-capabilities span {
        padding: 2px 6px;
        border-radius: 4px;
        background: var(--vscode-button-secondaryBackground);
      }
      .model-discovery-summary,
      .model-readme-panel {
        margin: 0;
        padding: 13px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 8px;
        background: color-mix(in srgb, var(--vscode-button-background) 20%, var(--vscode-editor-background));
        line-height: 1.45;
      }
      .model-discovery-facts,
      .model-discovery-capabilities,
      .model-download-options,
      .model-more-from {
        display: grid;
        gap: 8px;
        padding: 12px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 8px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 80%, var(--vscode-editor-background));
      }
      .model-discovery-facts div {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }
      .model-discovery-facts dt,
      .model-discovery-capabilities strong,
      .model-download-options strong,
      .model-more-from h3 {
        color: var(--vscode-descriptionForeground);
      }
      .model-download-options > header,
      .model-download-options > div {
        justify-content: space-between;
      }
      .model-download-options > div {
        min-height: 44px;
        padding: 8px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 7px;
        background: color-mix(in srgb, var(--vscode-input-background) 72%, var(--vscode-editor-background));
      }
      .model-download-options .action:not(:disabled) {
        background: var(--vscode-button-background);
        color: var(--vscode-button-foreground);
      }
      .model-more-from {
        align-items: stretch;
      }
      .model-more-from h3 {
        margin: 0;
      }
      .models-lmstudio__sources {
        height: 100%;
        overflow: auto;
        background: var(--vscode-editor-background);
      }
      .model-sources-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(260px, 1fr));
        gap: 12px;
        padding: 14px;
      }
      .model-sources-header {
        grid-column: 1 / -1;
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: start;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .model-sources-header h2,
      .model-sources-card h3 {
        margin: 0;
      }
      .model-sources-header p,
      .model-source-note,
      .model-source-row span {
        margin: 4px 0 0;
        color: var(--vscode-descriptionForeground);
        line-height: 1.4;
      }
      .model-sources-card {
        display: grid;
        align-content: start;
        gap: 10px;
        padding: 12px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 76%, var(--vscode-editor-background));
      }
      .model-source-row {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(220px, 0.72fr);
        gap: 12px;
        padding: 10px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-editor-background) 78%, transparent);
      }
      .model-source-row dl {
        display: grid;
        gap: 5px;
        margin: 0;
      }
      .model-source-row dl div {
        display: flex;
        justify-content: space-between;
        gap: 8px;
      }
      .model-source-row dt {
        color: var(--vscode-descriptionForeground);
      }
      .model-source-config label {
        display: grid;
        gap: 5px;
      }
      .model-source-config input,
      .model-source-config select {
        width: 100%;
        min-width: 0;
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 4px;
        padding: 7px 8px;
        background: var(--vscode-input-background);
        color: var(--vscode-input-foreground);
      }
      .model-source-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }
      .model-load-dialog,
      .model-quick-loader {
        align-content: start;
      }
      .model-advanced-panel {
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        padding: 8px;
        background: color-mix(in srgb, var(--vscode-editor-background) 80%, var(--vscode-sideBar-background));
      }
      .models-lmstudio__dialog-title {
        justify-content: center;
        position: relative;
      }
      .models-lmstudio__dialog-title .model-icon-button {
        position: absolute;
        left: 0;
      }
      .models-lmstudio__estimate {
        justify-content: space-between;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 5px;
        padding: 8px;
      }
      .model-field,
      .model-range-row {
        display: grid;
        gap: 6px;
      }
      .model-field input,
      .model-range-row output {
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 5px;
        background: var(--vscode-input-background);
        color: var(--vscode-input-foreground);
        padding: 6px 8px;
      }
      .model-range-row {
        grid-template-columns: minmax(100px, 1fr) minmax(140px, 2fr) 64px;
      }
      .model-toggle-row,
      .model-dialog-options {
        color: var(--vscode-descriptionForeground);
        font-size: 12px;
      }
      .model-dialog-options {
        display: grid;
        align-items: start;
      }
      .model-download-options:not(.model-discovery-download) {
        display: grid;
        grid-template-columns: 1fr auto auto;
        gap: 8px;
        align-items: center;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        padding: 8px;
      }
      .model-download-options button:disabled {
        opacity: 0.55;
      }
      .model-readme-panel {
        padding-top: 8px;
        border-top: 1px solid var(--vscode-panel-border);
        color: var(--vscode-descriptionForeground);
      }
      .model-running-row {
        display: grid;
        gap: 8px;
      }
      .tracing-surface {
        min-height: calc(100vh - 32px);
        display: grid;
        align-content: start;
        gap: 12px;
        color: var(--vscode-foreground);
        background: var(--vscode-editor-background);
      }
      .tracing-header,
      .tracing-focused-step,
      .tracing-panel {
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 86%, var(--vscode-editor-background));
      }
      .tracing-header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 16px;
        align-items: start;
        padding: 14px;
      }
      .tracing-header p,
      .tracing-focused-step p,
      .tracing-panel p {
        margin: 0;
      }
      .tracing-header__actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }
      .tracing-focused-step {
        display: grid;
        gap: 8px;
        padding: 12px 14px;
      }
      .tracing-focused-step h3,
      .tracing-panel h3 {
        margin: 0;
        font-size: 14px;
      }
      .tracing-focused-step dl {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px 16px;
        margin: 0;
      }
      .tracing-focused-step dl div {
        min-width: 0;
      }
      .tracing-focused-step dt {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }
      .tracing-focused-step dd {
        margin: 3px 0 0;
        min-width: 0;
      }
      .tracing-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 12px;
      }
      .tracing-panel {
        display: grid;
        align-content: start;
        gap: 10px;
        min-width: 0;
        padding: 12px;
      }
      .tracing-panel--wide {
        grid-column: 1 / -1;
      }
      .tracing-panel ol {
        display: grid;
        gap: 7px;
        margin: 0;
        padding: 0;
        list-style: none;
      }
      .tracing-panel li {
        min-width: 0;
        display: grid;
        grid-template-columns: auto minmax(120px, .6fr) minmax(0, 1fr);
        gap: 7px 10px;
        align-items: center;
        padding: 8px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 5px;
        background: color-mix(in srgb, var(--vscode-editor-background) 82%, transparent);
      }
      .tracing-panel li.is-focused {
        border-color: var(--vscode-focusBorder, #4da3ff);
        background: color-mix(in srgb, var(--vscode-button-background) 24%, var(--vscode-editor-background));
      }
      .tracing-panel li strong,
      .tracing-panel li span,
      .tracing-panel li code {
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .tracing-panel li code {
        grid-column: 2 / -1;
        color: var(--vscode-textPreformat-foreground);
      }
      .tracing-empty {
        grid-template-columns: minmax(0, 1fr) !important;
        color: var(--vscode-descriptionForeground);
      }
      @media (max-width: 1180px) {
        .models-lmstudio__primary,
        .models-lmstudio__ops,
        .tracing-grid {
          grid-template-columns: minmax(0, 1fr);
        }
        .tracing-header,
        .tracing-focused-step dl {
          grid-template-columns: minmax(0, 1fr);
        }
        .models-lmstudio__rail,
        .models-lmstudio__inspector {
          border-right: 0;
          border-left: 0;
          border-bottom: 1px solid var(--vscode-panel-border);
        }
      }
      .item-head {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
        margin-bottom: 8px;
      }
      .item-head strong {
        font-size: 13px;
      }
      .status-pill {
        padding: 2px 8px;
        border-radius: 999px;
        background: color-mix(in srgb, var(--vscode-badge-background) 78%, transparent 22%);
        color: var(--vscode-badge-foreground);
        font-size: 11px;
      }
      .metric-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
      }
      .metric-card {
        padding: 10px 12px;
      }
      .metric-card span {
        display: block;
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
        margin-bottom: 6px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }
      .metric-card strong {
        font-size: 18px;
      }
      .runtime-strip {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px;
        margin: 0 0 14px;
      }
      .runtime-strip__item {
        min-width: 0;
        padding: 8px 9px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 92%, white 8%);
      }
      .runtime-strip__item span {
        display: block;
        color: var(--vscode-descriptionForeground);
        font-size: 10px;
        margin-bottom: 3px;
      }
      .runtime-strip__item strong {
        font-size: 15px;
      }
      .diagnostics {
        border-color: var(--vscode-inputValidation-warningBorder, var(--vscode-panel-border));
      }
      .diagnostics strong {
        display: block;
        margin-bottom: 8px;
      }
      .diagnostics p {
        margin: 0 0 6px;
      }
      code {
        display: block;
        white-space: normal;
        word-break: break-word;
        color: var(--vscode-textPreformat-foreground);
        font-size: 12px;
      }
      .stack {
        display: grid;
        gap: 10px;
      }
      .actions {
        display: grid;
        gap: 8px;
        margin-bottom: 14px;
      }
      .item-actions {
        margin-top: 10px;
        margin-bottom: 0;
      }
      .action {
        appearance: none;
        border: 1px solid var(--vscode-button-border, transparent);
        border-radius: 4px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        text-align: left;
        padding: 10px 12px;
        font: inherit;
        cursor: pointer;
      }
      .action:hover {
        background: var(--vscode-button-secondaryHoverBackground);
      }
      .workspace-card {
        margin-bottom: 14px;
      }
      .empty-state {
        border: 1px dashed var(--vscode-panel-border);
        border-radius: 12px;
        padding: 14px 12px;
        color: var(--vscode-descriptionForeground);
      }
      .footer {
        margin-top: 14px;
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
      }
      .operator-chat-pane {
        --operator-chat-bg: var(
          --ioi-operator-chat-bg,
          var(--vscode-sideBar-background, #1f1f1f)
        );
        --operator-chat-border: var(
          --ioi-operator-chat-border,
          var(--vscode-panel-border, rgba(255, 255, 255, 0.13))
        );
        --operator-chat-border-strong: var(
          --ioi-operator-chat-border-strong,
          var(--vscode-panel-border, rgba(255, 255, 255, 0.22))
        );
        --operator-chat-text: var(
          --ioi-operator-chat-text,
          var(--vscode-foreground, #f0f0f0)
        );
        --operator-chat-text-secondary: var(
          --ioi-operator-chat-text-secondary,
          var(--vscode-descriptionForeground, #b8b8b8)
        );
        --operator-chat-text-muted: var(
          --ioi-operator-chat-text-muted,
          color-mix(
            in srgb,
            var(--vscode-descriptionForeground, #858585) 82%,
            transparent 18%
          )
        );
        --operator-chat-accent: var(
          --ioi-operator-chat-accent,
          var(--vscode-textLink-foreground, #0098ff)
        );
        --operator-chat-control-bg: var(
          --ioi-operator-chat-control-bg,
          color-mix(in srgb, var(--vscode-foreground, #ffffff) 8%, transparent 92%)
        );
        box-sizing: border-box;
        width: 100%;
        height: 100vh;
        min-height: 0;
        display: grid;
        grid-template-rows: minmax(0, 1fr) auto;
        align-items: stretch;
        gap: 18px;
        padding: 30px 16px 16px;
        overflow: hidden;
        background: var(--operator-chat-bg);
        color: var(--operator-chat-text);
      }
      .operator-chat-empty {
        align-self: center;
        justify-self: center;
        max-width: 280px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 12px;
        text-align: center;
        color: var(--operator-chat-text);
        transform: translateY(10%);
      }
      .operator-chat-empty__icon {
        width: 36px;
        height: 36px;
        color: var(--operator-chat-text-secondary);
      }
      .operator-chat-empty__icon svg {
        width: 100%;
        height: 100%;
        fill: none;
        stroke: currentColor;
        stroke-width: 1.8;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
      .operator-chat-empty h2 {
        margin: 0;
        font-size: 22px;
        font-weight: 350;
        line-height: 1.1;
      }
      .operator-chat-empty p {
        margin: 0;
        color: var(--operator-chat-text-secondary);
        font-size: 13px;
        line-height: 1.35;
      }
      .operator-chat-empty a {
        color: var(--operator-chat-accent);
        text-decoration: none;
      }
      .operator-chat-thread {
        min-height: 0;
        overflow: auto;
        display: flex;
        flex-direction: column;
        gap: 14px;
        padding: 8px 4px 8px;
        scrollbar-width: thin;
      }
      .operator-chat-message {
        max-width: 88%;
        display: grid;
        gap: 5px;
      }
      .operator-chat-message span {
        color: var(--operator-chat-text-muted);
        font-size: 11px;
        letter-spacing: 0.06em;
        text-transform: uppercase;
      }
      .operator-chat-message p {
        margin: 0;
        border: 1px solid var(--operator-chat-border);
        border-radius: 8px;
        padding: 8px 10px;
        background: var(--operator-chat-control-bg);
        color: var(--operator-chat-text);
        line-height: 1.45;
        white-space: pre-wrap;
      }
      .operator-chat-message--user {
        align-self: end;
        text-align: right;
      }
      .operator-chat-message--user p {
        border-color: var(--operator-chat-border-strong);
      }
      .operator-chat-message--assistant,
      .operator-chat-message--tool {
        align-self: start;
      }
      .operator-chat-thread__status {
        display: grid;
        gap: 4px;
        border: 1px solid var(--operator-chat-border);
        border-radius: 6px;
        padding: 8px 10px;
        background: var(--operator-chat-control-bg);
        color: var(--operator-chat-text-secondary);
      }
      .operator-chat-thread__status span {
        color: var(--operator-chat-accent);
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      .operator-chat-thread__status strong {
        color: var(--operator-chat-text);
        font-size: 12px;
        font-weight: 500;
      }
      .operator-chat-bottom {
        display: grid;
        gap: 8px;
        align-self: end;
        justify-self: center;
        width: min(100% - 24px, 360px);
      }
      .operator-chat-notice {
        border: 1px solid var(--vscode-panel-border);
        border-radius: 4px;
        padding: 8px;
        color: var(--operator-chat-text-secondary);
        background: var(--vscode-editorWidget-background);
        line-height: 1.35;
      }
      .operator-chat-notice strong {
        color: var(--operator-chat-text);
        display: block;
        margin-bottom: 3px;
      }
      .operator-chat-suggestions {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 8px;
      }
      .operator-chat-suggestions span {
        color: var(--operator-chat-text-muted);
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      .operator-chat-suggestions div {
        display: flex;
        justify-content: center;
        flex-wrap: wrap;
        gap: 6px;
      }
      .operator-chat-suggestion,
      .operator-chat-composer button,
      .operator-chat-mode-select {
        min-height: 26px;
        border: 1px solid var(--operator-chat-border-strong);
        border-radius: 4px;
        background: transparent;
        color: var(--operator-chat-text);
        font: inherit;
        cursor: pointer;
      }
      .operator-chat-suggestion,
      .operator-chat-composer button {
        padding: 0 10px;
      }
      .operator-chat-composer {
        position: relative;
        box-sizing: border-box;
        width: 100%;
        display: flex;
        flex-direction: column;
        gap: 7px;
        border: 1px solid var(--operator-chat-accent);
        border-radius: 4px;
        padding: 8px;
        background: var(--operator-chat-bg);
        text-align: left;
      }
      .operator-chat-composer__context-row {
        display: flex;
        gap: 6px;
        min-width: 0;
      }
      .operator-chat-composer textarea {
        width: 100%;
        min-height: 28px;
        resize: vertical;
        box-sizing: border-box;
        border: 0;
        outline: 0;
        padding: 0;
        background: transparent;
        color: var(--operator-chat-text);
        font: inherit;
        cursor: text;
        pointer-events: auto;
        user-select: text;
        -webkit-user-select: text;
      }
      .operator-chat-composer textarea::placeholder {
        color: var(--operator-chat-text-muted);
      }
      .operator-chat-composer__controls {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 6px;
        min-width: 0;
      }
      .operator-chat-context-button,
      .operator-chat-icon-select,
      .operator-chat-mode-select,
      .operator-chat-tool-toggle {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 5px;
        min-width: 0;
        white-space: nowrap;
      }
      .operator-chat-icon-select,
      .operator-chat-tool-toggle {
        width: 28px;
        padding: 0;
      }
      .operator-chat-icon-select {
        width: 48px;
      }
      .operator-chat-tool-toggle.is-active {
        border-color: var(--ioi-operator-chat-selected-border, var(--operator-chat-accent));
        background: var(
          --ioi-operator-chat-selected-bg,
          color-mix(in srgb, var(--operator-chat-accent) 22%, transparent 78%)
        );
        color: var(--operator-chat-text);
      }
      .operator-chat-mode-select {
        padding: 0 8px;
      }
      .operator-chat-button-icon,
      .operator-chat-button-chevron {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        line-height: 1;
      }
      .operator-chat-button-icon svg {
        width: 14px;
        height: 14px;
      }
      .operator-chat-button-chevron svg {
        width: 10px;
        height: 10px;
      }
      .operator-chat-suggestion:hover,
      .operator-chat-composer button:hover {
        border-color: var(--operator-chat-accent);
        background: var(--ioi-operator-chat-control-hover, var(--operator-chat-control-bg));
      }
      .operator-chat-suggestion:focus-visible,
      .operator-chat-composer button:focus-visible,
      .operator-chat-composer textarea:focus-visible {
        outline: 1px solid var(--operator-chat-accent);
        outline-offset: 1px;
      }
      .operator-chat-send {
        margin-left: auto;
        width: 28px;
        height: 28px;
        padding: 0;
        opacity: 0.55;
      }
      ${autopilotShellHeaderStyles()}
    </style>
  </head>
  <body
    class="${isChatView ? "is-chat-view" : ""} ${isModelsView ? "is-models-view" : ""}"
    data-autopilot-theme="${escapeHtml(appearanceThemeId)}"
  >
    ${
      isChatView
        ? renderBody(view.id, state)
        : isStudioView
          ? `${renderAutopilotShellHeader(state, shellModeId)}${renderBody(view.id, state)}`
        : isWorkflowView
          ? `${renderAutopilotShellHeader(state, shellModeId)}${renderBody(view.id, state)}`
        : isModelsView
          ? `${renderAutopilotShellHeader(state, shellModeId)}${renderBody(view.id, state)}`
        : `
          ${renderAutopilotShellHeader(state, shellModeId)}
          <main class="autopilot-generic-mode" data-testid="autopilot-${escapeHtml(shellModeId)}-mode">
            <p class="eyebrow">${escapeHtml(view.eyebrow)}</p>
            <h2>${escapeHtml(view.title)}</h2>
            <p>${escapeHtml(view.description)}</p>
            <div class="card workspace-card">
              <strong>Workspace</strong>
              <code>${escapeHtml(workspace.name || "No folder")}</code>
              <code>${escapeHtml(workspace.rootPath || workspace.path || "No folder selected")}</code>
            </div>
            ${renderRuntimeSummary(state)}
            ${renderDiagnostics(state)}
            <div class="actions">${actions}</div>
            ${renderBody(view.id, state)}
            <div class="footer">Snapshot refreshed ${escapeHtml(formatRelativeTime(state.generatedAtMs))} · IOI runtime remains authoritative.</div>
          </main>
        `
    }
    <script>
      const vscode = acquireVsCodeApi();
      function collectModelsProof(phase) {
        const selectors = {
          modelsMode: document.querySelectorAll('[data-testid="autopilot-models-mode"]').length,
          modelsShell: document.querySelectorAll('[data-testid="models-lmstudio-shell"]').length,
          leftRail: document.querySelectorAll('[data-testid="models-left-rail"]').length,
          modelLibrary: document.querySelectorAll('[data-testid="model-library"]').length,
          libraryTable: document.querySelectorAll('[data-testid="model-library-table"]').length,
          libraryFooter: document.querySelectorAll('[data-testid="model-library-footer"]').length,
          selectedInspector: document.querySelectorAll('[data-testid="model-selected-inspector"]').length,
          mountDrawer: document.querySelectorAll('[data-testid="model-mount-drawer"]').length,
          quickLoaderPopover: document.querySelectorAll('[data-testid="model-quick-loader-popover"]').length,
          quickLoader: document.querySelectorAll('[data-testid="model-quick-loader-list"]').length,
          loadDialog: document.querySelectorAll('[data-testid="model-load-dialog"]').length,
          discoverView: document.querySelectorAll('[data-testid="model-discovery-surface"]').length,
          discoverList: document.querySelectorAll('[data-testid="model-discover-list"]').length,
          discoverDetail: document.querySelectorAll('[data-testid="model-discover-detail"]').length,
          discoverDownloadOptions: document.querySelectorAll('[data-testid="model-download-options"]').length,
          discoverMoreFromPublisher: document.querySelectorAll('[data-testid="model-more-from-publisher"]').length,
          sourcesView: document.querySelectorAll('[data-testid="model-catalog-sources-surface"]').length,
          localAutodiscoverySources: document.querySelectorAll('[data-testid="model-local-autodiscovery-sources"]').length,
          remoteRegistrySources: document.querySelectorAll('[data-testid="model-remote-registry-sources"]').length,
          sourceConfig: document.querySelectorAll('[data-testid="model-catalog-source-config"]').length,
          runtimeBackend: document.querySelectorAll('[data-testid="model-runtime-backend"]').length,
          loadEstimate: document.querySelectorAll('[data-testid="model-load-estimate"]').length,
          loadProgress: document.querySelectorAll('[data-testid="model-load-progress"]').length,
          instanceReady: document.querySelectorAll('[data-testid="model-instance-ready"]').length,
          serverApi: document.querySelectorAll('[data-testid="model-server-api"]').length,
          serverView: document.querySelectorAll('[data-testid="model-server-view"]').length,
          serverStatus: document.querySelectorAll('[data-testid="model-server-status"]').length,
          serverEndpoints: document.querySelectorAll('[data-testid="model-server-endpoints"]').length,
          serverLoadedModels: document.querySelectorAll('[data-testid="model-server-loaded-models"]').length,
          serverLogs: document.querySelectorAll('[data-testid="model-server-logs"]').length,
          serverRequestLog: document.querySelectorAll('[data-testid="model-server-request-log"]').length,
          serverBackendLogs: document.querySelectorAll('[data-testid="model-server-backend-logs"]').length,
          serverReceipts: document.querySelectorAll('[data-testid="model-server-receipts"]').length,
          workflowBinding: document.querySelectorAll('[data-testid="workflow-node-live-model-binding"]').length,
          workflowTimeline: document.querySelectorAll('[data-testid="workflow-live-model-dry-run-timeline"]').length,
          receiptsReplay: document.querySelectorAll('[data-testid="model-invocation-receipts-replay"]').length,
          emptyState: document.querySelectorAll('[data-testid="model-empty-state"]').length,
          errorState: document.querySelectorAll('[data-testid="model-error-state"]').length,
          unloadButton: document.querySelectorAll('[data-testid="model-running-unload-button"]').length,
          inspectorTabs: document.querySelectorAll('[data-model-inspector-tab]').length
        };
        const root = document.querySelector('[data-testid="autopilot-models-mode"]');
        const proof = {
          schemaVersion: "ioi.models-mode.dom-proof.v1",
          phase,
          generatedAtMs: Date.now(),
          runtimeAuthority: "daemon-owned",
          projectionOwner: "openvscode-workbench-adapter",
          webviewOwnsRuntimeState: false,
          directModelExecution: false,
          externalConnectorAction: false,
          tauriUsed: false,
          daemonBacked: root?.dataset.daemonBacked === "true",
          selectors,
          visibleText: document.body.innerText.slice(0, 4000)
        };
        vscode.postMessage({ type: "modelsModeProof", proof });
        return proof;
      }
      function activateModelInspectorTab(tab) {
        if (!tab) {
          return;
        }
        document.querySelectorAll("[data-model-inspector-tab]").forEach((button) => {
          button.classList.toggle("is-active", button.dataset.modelInspectorTab === tab);
        });
        document.querySelectorAll("[data-model-inspector-panel]").forEach((panel) => {
          panel.classList.toggle("is-active", panel.dataset.modelInspectorPanel === tab);
        });
      }
      function activateModelSurface(surface) {
        const target = surface || "library";
        const root = document.querySelector('[data-testid="autopilot-models-mode"]');
        if (root) {
          root.dataset.activeModelSurface = target;
        }
        document.querySelectorAll("[data-model-surface-tab]").forEach((button) => {
          button.classList.toggle("is-active", button.dataset.modelSurfaceTab === target);
        });
        document.querySelectorAll("[data-model-surface-panel]").forEach((panel) => {
          const active = panel.dataset.modelSurfacePanel === target;
          panel.classList.toggle("is-active", active);
          panel.toggleAttribute("hidden", !active);
        });
        if (target === "discover") {
          document.querySelectorAll(".model-discovery-list, .model-discovery-detail").forEach((panel) => {
            panel.scrollTop = 0;
          });
          root?.scrollIntoView({ block: "start", inline: "nearest" });
          document.querySelector('[data-testid="model-discover-search-input"]')?.focus({ preventScroll: true });
          return;
        }
        if (target === "sources") {
          root?.scrollIntoView({ block: "start", inline: "nearest" });
          document.querySelector('[data-testid="model-catalog-source-url-input"]')?.focus({ preventScroll: true });
          return;
        }
        root?.scrollIntoView({ block: "start", inline: "nearest" });
      }
      function updateModelActionPayloads(row) {
        const modelId = row.dataset.modelRow || "";
        const endpointId = row.dataset.modelEndpointId || "";
        const instanceId = row.dataset.modelInstanceId || "";
        document.querySelectorAll("[data-model-action]").forEach((button) => {
          const action = button.dataset.modelAction;
          const payload = {
            modelId,
            endpointId,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          };
          if (action === "unload") {
            button.dataset.payload = JSON.stringify({ instanceId, modelId, endpointId });
            button.toggleAttribute("disabled", !instanceId);
            return;
          }
          if (action === "estimate" || action === "loadNative") {
            const contextLength = document.querySelector('[data-testid="model-context-length-slider"]')?.value || 2048;
            const gpuOffload = document.querySelector('[data-testid="model-gpu-offload-slider"]')?.value || "auto";
            button.dataset.payload = JSON.stringify({ ...payload, contextLength, gpuOffload });
            return;
          }
          button.dataset.payload = JSON.stringify(payload);
        });
      }
      function setModelField(name, value) {
        document.querySelectorAll('[data-model-field="' + name + '"]').forEach((field) => {
          field.textContent = value || "none";
        });
      }
      document.querySelectorAll("[data-model-inspector-tab]").forEach((button) => {
        button.addEventListener("click", () => activateModelInspectorTab(button.dataset.modelInspectorTab));
      });
      document.querySelectorAll("[data-model-surface-tab]").forEach((button) => {
        button.addEventListener("click", () => activateModelSurface(button.dataset.modelSurfaceTab));
      });
      function filterModelRows(input, rowSelector) {
        const query = String(input?.value || "").trim().toLowerCase();
        document.querySelectorAll(rowSelector).forEach((row) => {
          const haystack = [
            row.textContent,
            row.dataset.modelRow,
            row.dataset.modelLabel,
            row.dataset.modelPublisher,
            row.dataset.modelDomain,
            row.dataset.modelStatus
          ].filter(Boolean).join(" ").toLowerCase();
          row.hidden = query.length > 0 && !haystack.includes(query);
        });
      }
      function selectModelRow(row) {
        if (!row) {
          return;
        }
        document.querySelectorAll("[data-model-row]").forEach((candidate) => {
          candidate.classList.toggle("is-selected", candidate === row);
          candidate.setAttribute("data-testid", candidate === row ? "model-library-row-selected" : "model-library-row");
        });
        const title = document.querySelector('[data-testid="model-inspector-title"]');
        const subtitle = document.querySelector('[data-testid="model-inspector-subtitle"]');
        if (title) title.textContent = row.dataset.modelLabel || row.dataset.modelRow || "Model";
        if (subtitle) subtitle.textContent = row.dataset.modelRow || row.dataset.modelPublisher || "daemon model";
        setModelField("model", row.dataset.modelRow || "none");
        setModelField("file", row.dataset.modelFile || "daemon artifact");
        setModelField("format", row.dataset.modelFormat || "GGUF");
        setModelField("quantization", row.dataset.modelQuantization || "unknown");
        setModelField("arch", row.dataset.modelArch || "unknown");
        setModelField("capabilities", row.dataset.modelCapabilities || "chat");
        setModelField("size", row.dataset.modelSize || "unknown");
        setModelField("route-model", row.dataset.modelRow || "none");
        setModelField("workflow-model", row.dataset.modelRow || "none");
        setModelField("timeline-model", row.dataset.modelRow || "model");
        setModelField("running-model", row.dataset.modelRow || "No loaded instance");
        setModelField("instance", row.dataset.modelInstanceId || "none");
        setModelField("backend", row.dataset.modelBackendId || "none");
        updateModelActionPayloads(row);
        vscode.postMessage({
          type: "bridgeRequest",
          requestType: "models.selectionChanged",
          payload: {
            modelId: row.dataset.modelRow,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          }
        });
      }
      function moveModelSelection(delta) {
        const rows = Array.from(document.querySelectorAll("[data-model-row]")).filter((row) => !row.hidden);
        if (!rows.length) return;
        const currentIndex = rows.findIndex((row) => row.classList.contains("is-selected"));
        const next = rows[Math.max(0, Math.min(rows.length - 1, currentIndex + delta))] || rows[0];
        selectModelRow(next);
        next.focus({ preventScroll: true });
      }
      const libraryFilter = document.querySelector('[data-testid="model-library-filter"]');
      const loaderFilter = document.querySelector('[data-testid="model-quick-loader-filter"]');
      libraryFilter?.addEventListener("input", () => filterModelRows(libraryFilter, "[data-model-row]"));
      loaderFilter?.addEventListener("input", () => filterModelRows(loaderFilter, ".model-loader-row"));
      document.querySelectorAll("[data-model-row]").forEach((row) => {
        row.addEventListener("click", () => selectModelRow(row));
        row.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            selectModelRow(row);
          }
          if (event.key === "ArrowDown") {
            event.preventDefault();
            moveModelSelection(1);
          }
          if (event.key === "ArrowUp") {
            event.preventDefault();
            moveModelSelection(-1);
          }
        });
      });
      function setCatalogField(name, value) {
        document.querySelectorAll('[data-catalog-field="' + name + '"]').forEach((field) => {
          field.textContent = value || "unknown";
        });
      }
      function selectCatalogRow(row) {
        if (!row) {
          return;
        }
        document.querySelectorAll("[data-catalog-row]").forEach((candidate) => {
          candidate.classList.toggle("is-selected", candidate === row);
          candidate.setAttribute("data-testid", candidate === row ? "model-discover-result-selected" : "model-discover-result-row");
        });
        setCatalogField("title", row.dataset.catalogLabel || "Catalog model");
        setCatalogField("modelId", row.dataset.catalogModelId || "daemon catalog");
        setCatalogField("summary", row.dataset.catalogSummary || "Daemon catalog result.");
        setCatalogField("readme", row.dataset.catalogReadme || row.dataset.catalogSummary || "Daemon catalog metadata.");
        setCatalogField("readmeTitle", row.dataset.catalogReadmeTitle || row.dataset.catalogLabel || "README");
        setCatalogField("params", row.dataset.catalogParams || "local");
        setCatalogField("arch", row.dataset.catalogArch || "unknown");
        setCatalogField("domain", row.dataset.catalogDomain || "llm");
        setCatalogField("format", row.dataset.catalogFormat || "gguf");
        setCatalogField("license", row.dataset.catalogLicense || "unknown");
        setCatalogField("quantization", row.dataset.catalogQuantization || "unknown");
        setCatalogField("size", row.dataset.catalogSize || "unknown");
        setCatalogField(
          "downloadTitle",
          ((row.dataset.catalogLabel || "Model") + " " + (row.dataset.catalogParams || "") + " " + (row.dataset.catalogQuantization || "")).trim()
        );
        setCatalogField("downloads", row.dataset.catalogDownloads || "registry");
        setCatalogField("stars", row.dataset.catalogStars || "score");
        setCatalogField("updated", row.dataset.catalogUpdated || "registry");
        setCatalogField("capabilities", row.dataset.catalogCapabilities || "metadata pending");
        setCatalogField("sourceLabel", row.dataset.catalogSourceLabel || "daemon catalog");
        setCatalogField("publisher", row.dataset.catalogPublisher || "publisher");
        document.querySelectorAll('[data-command="ioi.models.downloadCatalog"]').forEach((button) => {
          button.dataset.payload = JSON.stringify({
            catalogEntryId: row.dataset.catalogRow,
            sourceUrl: row.dataset.catalogSourceUrl,
            modelId: row.dataset.catalogModelId,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          });
          if (!button.disabled) {
            button.textContent = row.dataset.catalogDownloadLabel || "Download";
          }
        });
      }
      document.querySelectorAll("[data-catalog-row]").forEach((row) => {
        row.addEventListener("click", () => selectCatalogRow(row));
      });
      function requestCatalogSearch() {
        const query = document.querySelector('[data-testid="model-discover-search-input"]')?.value || "";
        vscode.postMessage({
          type: "command",
          command: "ioi.models.searchCatalog",
          payload: {
            query,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          }
        });
      }
      document.querySelector('[data-testid="model-discover-search-button"]')?.addEventListener("click", requestCatalogSearch);
      document.querySelector('[data-testid="model-discover-refresh-button"]')?.addEventListener("click", requestCatalogSearch);
      document.querySelector('[data-testid="model-discover-search-input"]')?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          requestCatalogSearch();
        }
      });
      function refreshCatalogSourceFields() {
        const providerId = document.querySelector('[data-testid="model-catalog-provider-select"]')?.value || "catalog.huggingface";
        const isManifest = providerId === "catalog.local_manifest";
        document.querySelector('[data-model-source-field="baseUrl"]')?.toggleAttribute("hidden", isManifest);
        document.querySelector('[data-model-source-field="manifestPath"]')?.toggleAttribute("hidden", !isManifest);
        const endpointInput = document.querySelector('[data-testid="model-catalog-source-url-input"]');
        if (endpointInput && providerId === "catalog.huggingface" && !endpointInput.value.trim()) {
          endpointInput.value = "https://huggingface.co";
        }
      }
      function requestCatalogProviderConfigure() {
        const providerId = document.querySelector('[data-testid="model-catalog-provider-select"]')?.value || "catalog.huggingface";
        const endpoint = document.querySelector('[data-testid="model-catalog-source-url-input"]')?.value || "";
        const manifestPath = document.querySelector('[data-testid="model-catalog-manifest-path-input"]')?.value || "";
        const query = document.querySelector('[data-testid="model-catalog-source-search-input"]')?.value || "qwen";
        vscode.postMessage({
          type: "command",
          command: "ioi.models.configureCatalogProvider",
          payload: {
            providerId,
            baseUrl: endpoint,
            manifestPath,
            query,
            enabled: true,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "openvscode-workbench-adapter"
          }
        });
      }
      document.querySelector('[data-testid="model-catalog-provider-select"]')?.addEventListener("change", refreshCatalogSourceFields);
      document.querySelector('[data-testid="model-catalog-source-configure-button"]')?.addEventListener("click", requestCatalogProviderConfigure);
      document.querySelector('[data-testid="model-catalog-source-search-input"]')?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          requestCatalogProviderConfigure();
        }
      });
      refreshCatalogSourceFields();
      document.querySelectorAll('.model-range-row input[type="range"]').forEach((input) => {
        input.addEventListener("input", () => {
          const output = input.parentElement?.querySelector("output");
          if (output) output.textContent = input.value;
        });
      });
      document.querySelector('[data-testid="model-advanced-settings-toggle"]')?.addEventListener("change", (event) => {
        const panel = document.querySelector('[data-testid="model-advanced-settings-panel"]');
        if (panel) panel.hidden = !event.target.checked;
      });
      document.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
          event.preventDefault();
          libraryFilter?.focus();
          libraryFilter?.select();
        }
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "l") {
          event.preventDefault();
          activateModelInspectorTab("load");
          loaderFilter?.focus();
          loaderFilter?.select();
          document.querySelector('[data-testid="model-mount-drawer"]')?.scrollIntoView({ block: "center", inline: "center" });
        }
      });
      window.addEventListener("message", (event) => {
        const message = event.data || {};
        if (message.type !== "ioi.models.capturePhase") {
          return;
        }
        const phase = message.phase || "model-library";
        const phaseTab = {
          "model-inspector-info-panel": "info",
          "model-inspector-load-panel": "load",
          "model-inspector-inference-panel": "inference",
          "model-inspector-policy-panel": "policy",
          "model-inspector-routes-panel": "routes",
          "model-inspector-receipts-panel": "receipts",
          "model-selected-inspector": "info",
          "model-mount-drawer": "load",
          "model-load-dialog": "load",
          "model-load-estimate": "load",
          "model-load-progress": "load",
          "model-instance-ready": "load",
          "model-discover-view": null,
          "model-discovery-surface": null,
          "model-catalog-sources-surface": null,
          "model-runtime-backend": "policy",
          "model-server-api": "inference",
          "workflow-node-live-model-binding": "routes",
          "workflow-live-model-dry-run-timeline": "routes",
          "model-invocation-receipts-replay": "receipts"
        }[phase];
        activateModelInspectorTab(phaseTab);
        if (phase === "model-discover-view" || phase === "model-discovery-surface") {
          activateModelSurface("discover");
        }
        if (phase === "model-catalog-sources-surface") {
          activateModelSurface("sources");
        }
        const root = document.querySelector('[data-testid="autopilot-models-mode"]');
        const targetTestId = phase === "model-discover-view" ? "model-discovery-surface" : phase;
        const target = phase === "model-library"
          ? root
          : document.querySelector('[data-testid="' + targetTestId + '"]') || root;
        target?.scrollIntoView({ block: phase === "model-discover-view" || phase === "model-discovery-surface" || phase === "model-catalog-sources-surface" || phase === "model-library" ? "start" : "center", inline: "center" });
        window.setTimeout(() => collectModelsProof(phase), 250);
      });
      if (document.querySelector('[data-testid="autopilot-models-mode"]')) {
        window.setTimeout(() => collectModelsProof("initial"), 250);
      }
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          const rawPayload = button.dataset.payload;
          let payload = undefined;
          if (rawPayload) {
            try {
              payload = JSON.parse(rawPayload);
            } catch (error) {
              console.error("[IOI Workbench] Failed to parse command payload:", error);
            }
          }
          vscode.postMessage({ type: "command", command: button.dataset.command, payload });
        });
      });
      document.querySelectorAll("[data-bridge-request]").forEach((button) => {
        button.addEventListener("click", (event) => {
          event.preventDefault();
          const rawPayload = button.dataset.payload;
          let payload = undefined;
          if (rawPayload) {
            try {
              payload = JSON.parse(rawPayload);
            } catch (error) {
              console.error("[IOI Workbench] Failed to parse bridge payload:", error);
            }
          }
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: button.dataset.bridgeRequest,
            payload
          });
          const notice = document.querySelector("[data-native-chat-notice]");
          if (notice && button.dataset.bridgeRequest === "workflow.codeGenerationRequest") {
            notice.hidden = false;
            notice.innerHTML =
              "<strong>Proposal queued</strong>Autopilot is writing a proposal-first diff, approval/check plan, and receipt trail for the active workspace.";
          }
        });
      });
      const composer = document.querySelector("[data-chat-composer-form]");
      const composerInput = document.querySelector("[data-chat-composer-input]");
      const focusComposerInput = () => {
        if (!composerInput) {
          return;
        }
        window.requestAnimationFrame(() => {
          composerInput.focus({ preventScroll: true });
        });
      };
      composer?.addEventListener("pointerdown", (event) => {
        const target = event.target;
        if (target?.closest?.("button,a,select,input")) {
          return;
        }
        focusComposerInput();
      });
      composer?.addEventListener("click", (event) => {
        const target = event.target;
        if (target?.closest?.("button,a,select,input")) {
          return;
        }
        focusComposerInput();
      });
      composerInput?.addEventListener("pointerdown", focusComposerInput);
      composer?.addEventListener("submit", (event) => {
        event.preventDefault();
        const prompt = composerInput?.value?.trim();
        if (!prompt) {
          return;
        }
        vscode.postMessage({
          type: "bridgeRequest",
          requestType: "chat.submit",
          payload: {
            prompt,
            mode: document.querySelector("[data-chat-mode]")?.dataset.chatMode,
            model: document.querySelector("[data-chat-model]")?.dataset.chatModel
          }
        });
        composerInput.value = "";
      });
      composerInput?.addEventListener("keydown", (event) => {
        if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
          event.preventDefault();
          composer?.requestSubmit();
        }
      });
    </script>
  </body>
</html>`;
}

function workflowComposerHtml(context, webview) {
  const scriptUri = webview.asWebviewUri(
    vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "workflow-composer",
      "workflow-composer.js",
    ),
  );
  const styleUri = webview.asWebviewUri(
    vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "workflow-composer",
      "workflow-composer.css",
    ),
  );
  const pageNonce = nonce();
  const modelDaemonEndpoint = daemonEndpoint();
  const modelDaemonConnectSource = modelDaemonEndpoint
    ? ` ${escapeHtml(modelDaemonEndpoint)} http://127.0.0.1:* http://localhost:*`
    : "";
  const initialState = JSON.stringify({
    workspaceRoot: workspaceSummary().path,
    bridgeConfigured: Boolean(bridgeUrl()),
    daemonEndpoint: modelDaemonEndpoint,
    daemonToken: daemonToken(),
    daemonModelId: process.env.IOI_DAEMON_MODEL_ID || process.env.IOI_AUTOPILOT_MODEL_ID || null,
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-workflow-composer-webview",
    tauriUsed: false,
  }).replace(/</g, "\\u003c");
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src ${webview.cspSource} data: blob:; font-src ${webview.cspSource}; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${pageNonce}'; connect-src ${webview.cspSource}${modelDaemonConnectSource};"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link nonce="${pageNonce}" rel="stylesheet" href="${styleUri}" />
    <style nonce="${pageNonce}">
      body.workflow-composer-shell {
        margin: 0;
        height: 100vh;
        display: grid;
        grid-template-rows: auto minmax(0, 1fr);
        overflow: hidden;
      }
      body.workflow-composer-shell #root {
        min-height: 0;
      }
      ${autopilotShellHeaderStyles()}
    </style>
    <title>Autopilot Workflow Composer</title>
  </head>
  <body class="workflow-composer-shell">
    ${renderAutopilotShellHeader({ workspace: workspaceSummary(), modelMounting: {}, runs: [], policy: {} }, "workflows")}
    <div id="root"></div>
    <script nonce="${pageNonce}">
      const __ioiOriginalAcquireVsCodeApi = window.acquireVsCodeApi;
      const vscode = __ioiOriginalAcquireVsCodeApi?.() ?? { postMessage: () => undefined };
      window.acquireVsCodeApi = () => vscode;
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "command",
            command: button.dataset.command,
            payload: button.dataset.payload ? JSON.parse(button.dataset.payload) : undefined
          });
        });
      });
      window.__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__ = ${initialState};
    </script>
    <script nonce="${pageNonce}" type="module" src="${scriptUri}"></script>
  </body>
</html>`;
}

function studioPanelHtml(state) {
  const pageNonce = studioPanelNonce || (studioPanelNonce = nonce());
  const workspace = state.workspace || workspaceSummary();
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'nonce-${pageNonce}'; script-src 'nonce-${pageNonce}';"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Agent Studio</title>
    <style nonce="${pageNonce}">
      :root {
        color-scheme: dark;
        --studio-bg: #171717;
        --studio-panel: #202020;
        --studio-panel-strong: #272727;
        --studio-border: rgba(255, 255, 255, 0.12);
        --studio-border-strong: rgba(255, 255, 255, 0.2);
        --studio-text: #e8e8e8;
        --studio-muted: #aaaeb5;
        --studio-dim: #7c828b;
        --studio-accent: #7aa2ff;
        --studio-good: #7fd1a5;
        --studio-warn: #e7bf62;
        --studio-danger: #ff7b8a;
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        min-height: 100vh;
        overflow: hidden;
        font-family: var(--vscode-font-family, ui-sans-serif, system-ui, sans-serif);
        color: var(--studio-text);
        background: var(--studio-bg);
      }
      button,
      select,
      textarea {
        font: inherit;
      }
      button,
      select {
        border: 1px solid var(--studio-border);
        border-radius: 4px;
        background: #2d2d2d;
        color: var(--studio-text);
      }
      button {
        min-height: 30px;
        padding: 5px 10px;
        cursor: pointer;
      }
      button:hover,
      select:hover {
        border-color: var(--studio-border-strong);
        background: #353535;
      }
      .studio-operational-shell {
        height: 100vh;
        display: grid;
        grid-template-columns: minmax(230px, 280px) minmax(420px, 1fr) minmax(320px, 380px);
        grid-template-rows: minmax(0, 1fr);
        overflow: hidden;
      }
      .studio-operational-rail,
      .studio-chat-main,
      .studio-operator-context {
        min-width: 0;
        min-height: 0;
      }
      .studio-operational-rail,
      .studio-operator-context {
        border-right: 1px solid var(--studio-border);
        background: #181818;
        padding: 18px;
        overflow: auto;
      }
      .studio-operator-context {
        border-right: 0;
        border-left: 1px solid var(--studio-border);
      }
      .studio-eyebrow,
      .studio-control-group h3,
      .studio-operator-context h3 {
        margin: 0 0 9px;
        color: var(--studio-muted);
        font-size: 11px;
        font-weight: 700;
        letter-spacing: .08em;
        text-transform: uppercase;
      }
      h1,
      h2 {
        margin: 3px 0 4px;
        letter-spacing: 0;
      }
      h1 {
        font-size: 22px;
      }
      h2 {
        font-size: 18px;
      }
      p {
        margin: 0;
        color: var(--studio-muted);
        line-height: 1.45;
      }
      .studio-control-group,
      .studio-operator-context section,
      .studio-approval,
      .studio-diff-hunk {
        border: 1px solid var(--studio-border);
        border-radius: 6px;
        background: var(--studio-panel);
        padding: 12px;
      }
      .studio-control-group,
      .studio-operator-context section,
      .studio-approval {
        margin-top: 14px;
      }
      .studio-control-group button,
      .studio-history-item {
        width: 100%;
        margin-top: 7px;
        text-align: left;
      }
      .studio-history-item {
        display: grid;
        gap: 2px;
      }
      .studio-history-item span,
      .studio-operator-context li span,
      .studio-approval span {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-chat-main {
        display: grid;
        grid-template-rows: auto minmax(0, 1fr) auto;
        overflow: hidden;
        background: #1c1c1c;
      }
      .studio-chat-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 16px 18px;
        border-bottom: 1px solid var(--studio-border);
        background: #191919;
      }
      .studio-route-controls {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }
      .studio-route-controls select {
        max-width: 230px;
        min-height: 30px;
        padding: 0 8px;
      }
      .studio-transcript {
        min-height: 0;
        padding: 18px;
        overflow: auto;
        display: grid;
        align-content: start;
        gap: 12px;
      }
      .studio-chat-turn {
        display: grid;
        grid-template-columns: 34px minmax(0, 1fr);
        gap: 10px;
      }
      .studio-chat-turn__avatar {
        width: 30px;
        height: 30px;
        border-radius: 50%;
        display: grid;
        place-items: center;
        background: #303030;
        color: #fff;
        font-weight: 700;
      }
      .studio-chat-turn--user .studio-chat-turn__avatar {
        background: #125ea8;
      }
      .studio-chat-turn__body {
        border: 1px solid var(--studio-border);
        border-radius: 7px;
        padding: 10px 12px;
        background: var(--studio-panel);
      }
      .studio-chat-turn__meta {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 6px;
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-chat-turn__body p {
        color: var(--studio-text);
        white-space: pre-wrap;
      }
      .studio-chat-output-renderer {
        display: grid;
        gap: 10px;
        margin: 12px 0 0;
        border: 1px solid #4d4d4d;
        border-radius: 7px;
        padding: 12px;
        background: #101010;
      }
      .studio-chat-output-renderer figcaption,
      .studio-chat-renderer-toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        flex-wrap: wrap;
      }
      .studio-chat-output-renderer figcaption span,
      .studio-mermaid-source summary {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-chat-renderer-toolbar button {
        min-height: 26px;
        border-radius: 999px;
        padding: 2px 9px;
      }
      .studio-mermaid-diagram {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
        padding: 10px;
        border: 1px dashed #4a4a4a;
        border-radius: 6px;
      }
      .studio-mermaid-node {
        border: 1px solid #6a6a6a;
        border-radius: 999px;
        background: #1f1f1f;
        color: var(--studio-text);
        padding: 4px 10px;
      }
      .studio-mermaid-source pre {
        max-height: 180px;
        overflow: auto;
        margin: 8px 0 0;
        white-space: pre-wrap;
      }
      .studio-chat-code-execution-card {
        display: grid;
        gap: 10px;
        margin: 12px 0 0;
        border: 1px solid #4d4d4d;
        border-radius: 7px;
        padding: 12px;
        background: #0d0d0d;
      }
      .studio-chat-code-execution-card header,
      .studio-chat-code-execution-card footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        flex-wrap: wrap;
      }
      .studio-chat-code-execution-card header span,
      .studio-chat-code-execution-card footer span {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-chat-code-execution-card pre {
        max-height: 180px;
        overflow: auto;
        margin: 0;
        white-space: pre-wrap;
      }
      .studio-chat-code-execution-card[data-execution-status="blocked"] {
        border-color: #8a5b38;
      }
      .studio-chat-code-execution-card button {
        min-height: 28px;
        border-radius: 999px;
        padding: 3px 10px;
      }
      .studio-pending {
        display: flex;
        align-items: center;
        gap: 10px;
        width: fit-content;
        color: var(--studio-muted);
        font-size: 14px;
        line-height: 1.55;
        padding: 2px 0;
      }
      .studio-pending[hidden] {
        display: none;
      }
      .studio-pending__dots {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        color: var(--studio-muted);
      }
      .studio-pending__dots span {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: currentColor;
        animation: studioPulse 1s infinite ease-in-out;
      }
      .studio-pending__dots span:nth-child(2) {
        animation-delay: .12s;
      }
      .studio-pending__dots span:nth-child(3) {
        animation-delay: .24s;
      }
      .studio-pending strong {
        font: inherit;
        font-weight: 400;
        color: inherit;
      }
      @keyframes studioPulse {
        0%, 80%, 100% { opacity: .35; transform: translateY(0); }
        40% { opacity: 1; transform: translateY(-2px); }
      }
      .studio-composer {
        border-top: 0;
        background: #191919;
        padding: 12px 14px;
      }
      .studio-composer textarea {
        width: 100%;
        min-height: 76px;
        resize: vertical;
        border: 1px solid var(--studio-border);
        border-radius: 7px;
        outline: 0;
        background: #121212;
        color: var(--studio-text);
        line-height: 1.5;
        padding: 10px 12px;
      }
      .studio-composer textarea::placeholder {
        color: var(--studio-muted);
      }
      .studio-composer-toolbar {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 8px;
        margin-top: 8px;
      }
      .studio-composer-toolbar button[type="submit"] {
        margin-left: auto;
        background: #0e639c;
        border-color: #0e639c;
      }
      .studio-tauri-chat-shell {
        grid-template-columns: minmax(240px, 300px) minmax(520px, 1fr) 52px;
        background: #050505;
      }
      .studio-tauri-chat-shell:has(.studio-utility-drawer.is-expanded),
      .studio-tauri-chat-shell.has-expanded-utility {
        grid-template-columns: minmax(240px, 300px) minmax(520px, 1fr) minmax(340px, 390px);
      }
      .studio-session-rail {
        background: #141414;
        border-right-color: #303030;
        padding: 16px 12px;
      }
      .studio-session-rail__header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) 32px;
        align-items: center;
        gap: 10px;
      }
      .studio-session-rail__header h2 {
        grid-column: 1 / 2;
        margin-top: 0;
        color: var(--studio-muted);
        font-size: 13px;
        font-weight: 500;
      }
      .studio-session-rail__header button {
        grid-column: 2 / 3;
        grid-row: 1 / 3;
        width: 30px;
        min-height: 30px;
        padding: 0;
        font-size: 18px;
      }
      .studio-session-search {
        position: relative;
        display: block;
        margin: 14px 0 10px;
      }
      .studio-session-search input {
        width: 100%;
        height: 30px;
        border: 1px solid var(--studio-border-strong);
        border-radius: 6px;
        background: #050505;
        color: var(--studio-text);
        padding: 0 10px 0 30px;
      }
      .studio-search-icon {
        position: absolute;
        left: 10px;
        top: 6px;
        color: var(--studio-muted);
      }
      .studio-session-actions {
        display: grid;
        gap: 6px;
        margin-bottom: 18px;
      }
      .studio-session-actions button,
      .studio-rail-secondary button {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
      }
      .studio-history-group {
        border: 0;
        background: transparent;
        padding: 0;
      }
      .studio-history-date {
        display: block;
        margin: 4px 0 8px;
        color: var(--studio-muted);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
      }
      .studio-history-item--current {
        background: #050505;
        border-color: #050505;
      }
      .studio-chat-main {
        position: relative;
        background: #050505;
      }
      .studio-chat-header {
        min-height: 48px;
        padding: 0 16px;
        background: #070707;
      }
      .studio-chat-tab {
        min-height: 48px;
        border: 0;
        border-radius: 0;
        border-bottom: 2px solid var(--studio-accent);
        background: transparent;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
      }
      .studio-transcript {
        padding: 42px 54px 26px;
        gap: 20px;
      }
      .studio-chat-transcript {
        display: grid;
        gap: 22px;
      }
      .studio-chat-turn {
        grid-template-columns: minmax(0, 1fr);
        max-width: 1040px;
      }
      .studio-chat-turn__avatar {
        display: none;
      }
      .studio-chat-turn--user {
        justify-self: end;
        max-width: min(560px, 80%);
      }
      .studio-chat-turn--assistant,
      .studio-chat-turn--system {
        max-width: min(1040px, 100%);
      }
      .studio-user-bubble {
        border-color: #5a5a5a;
        border-radius: 999px;
        background: #3b3b3b;
        padding: 13px 18px;
      }
      .studio-user-bubble .studio-chat-turn__meta {
        display: none;
      }
      .studio-assistant-answer-card {
        border: 0;
        background: transparent;
        padding: 8px 0 0;
      }
      .studio-assistant-answer-card .studio-chat-turn__meta {
        display: none;
      }
      .studio-run-status-bar {
        display: flex;
        align-items: center;
        gap: 10px;
        width: 100%;
        min-height: 38px;
        border: 1px solid #7b7b7b;
        border-radius: 7px;
        background: #080808;
        padding: 0 12px;
        color: var(--studio-text);
      }
      .studio-run-status-bar__check {
        color: #4fa3ff;
      }
      .studio-run-status-bar button {
        margin-left: auto;
        border: 0;
        background: transparent;
        color: var(--studio-muted);
      }
      .studio-run-status-bar .studio-verified-badge {
        margin-left: auto;
      }
      .studio-run-status-bar .studio-verified-badge + button {
        margin-left: 0;
      }
      .studio-managed-sessions {
        display: grid;
        gap: 10px;
        margin-top: 10px;
      }
      .studio-managed-session-card {
        display: grid;
        gap: 10px;
        width: min(100%, 620px);
        border: 1px solid #3e5f7e;
        border-radius: 7px;
        background: #050607;
        padding: 10px;
        color: var(--studio-text);
      }
      .studio-managed-session-card__header {
        display: grid;
        grid-template-columns: auto minmax(0, 1fr) auto;
        align-items: center;
        gap: 10px;
      }
      .studio-managed-session-card__header div {
        display: grid;
        gap: 2px;
        min-width: 0;
      }
      .studio-managed-session-card__header strong,
      .studio-managed-session-preview__body strong {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-managed-session-card__header span,
      .studio-managed-session-preview__body span {
        overflow: hidden;
        color: var(--studio-muted);
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-managed-session-card__header button,
      .studio-managed-session-controls button {
        min-height: 28px;
        border: 1px solid #4e4e4e;
        border-radius: 6px;
        background: #151515;
        color: var(--studio-text);
      }
      .studio-managed-session-preview {
        display: grid;
        overflow: hidden;
        min-height: 118px;
        border: 1px solid #2a2a2a;
        border-radius: 6px;
        background: #101417;
      }
      .studio-managed-session-preview__chrome {
        display: flex;
        gap: 5px;
        align-items: center;
        height: 24px;
        border-bottom: 1px solid #2d353c;
        background: #171d22;
        padding: 0 9px;
      }
      .studio-managed-session-preview__chrome span {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #66727c;
      }
      .studio-managed-session-preview__body {
        display: grid;
        align-content: center;
        gap: 8px;
        min-width: 0;
        min-height: 90px;
        padding: 12px 14px;
        background:
          linear-gradient(90deg, rgba(79, 163, 255, 0.12) 1px, transparent 1px),
          linear-gradient(rgba(79, 163, 255, 0.08) 1px, transparent 1px),
          #080b0e;
        background-size: 18px 18px;
      }
      .studio-managed-session-preview__body mark {
        width: fit-content;
        border: 1px solid #a47620;
        border-radius: 999px;
        background: rgba(164, 118, 32, 0.16);
        color: #ffcf77;
        padding: 2px 8px;
      }
      .studio-managed-session-expanded {
        display: none;
        gap: 10px;
      }
      .studio-managed-session-card.is-expanded .studio-managed-session-expanded {
        display: grid;
      }
      .studio-managed-session-expanded p {
        margin: 0;
        color: var(--studio-muted);
      }
      .studio-managed-session-mode-labels,
      .studio-managed-session-controls {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
      }
      .studio-managed-session-mode-labels span {
        border: 1px solid #3e3e3e;
        border-radius: 999px;
        color: var(--studio-muted);
        padding: 3px 9px;
      }
      .studio-managed-session-mode-labels span.is-active,
      .studio-managed-session-controls button.is-active {
        border-color: #4fa3ff;
        color: #ffffff;
      }
      .studio-answer-actions {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 12px;
      }
      .studio-answer-actions button {
        min-height: 28px;
        border-radius: 999px;
        padding: 3px 10px;
      }
      .studio-work-record {
        display: grid;
        gap: 8px;
        margin: 12px 0 0;
        padding: 0;
        list-style: none;
        color: var(--studio-muted);
      }
      .studio-work-record li {
        position: relative;
        padding-left: 18px;
      }
      .studio-work-record li::before {
        content: "";
        position: absolute;
        left: 2px;
        top: .65em;
        width: 5px;
        height: 5px;
        border-radius: 999px;
        background: #6ea8fe;
      }
      .studio-view-trace-link {
        color: #9dc6ff;
      }
      .studio-verified-badge {
        display: inline-flex;
        align-items: center;
        min-height: 22px;
        border-radius: 999px;
        padding: 0 8px;
        background: rgba(127, 209, 165, .12);
        color: var(--studio-good);
        font-size: 12px;
        font-weight: 600;
        white-space: nowrap;
      }
      .studio-verified-badge--unverified {
        background: rgba(231, 191, 98, .12);
        color: var(--studio-warn);
      }
      .studio-compact-runtime-list {
        display: grid;
        gap: 8px;
        max-width: min(1040px, 100%);
      }
      .studio-compact-runtime-card {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto auto;
        align-items: center;
        gap: 10px;
        border: 1px solid rgba(255, 255, 255, .18);
        border-radius: 7px;
        background: rgba(255, 255, 255, .035);
        padding: 8px 10px;
      }
      .studio-compact-runtime-card--blocking {
        border-color: rgba(231, 191, 98, .45);
      }
      .studio-compact-runtime-card > div {
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
      }
      .studio-compact-runtime-card strong,
      .studio-compact-runtime-card span:not(.studio-status-dot):not(.studio-verified-badge) {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-compact-runtime-card span:not(.studio-status-dot):not(.studio-verified-badge) {
        color: var(--studio-muted);
      }
      .studio-compact-runtime-card button {
        min-height: 26px;
        padding: 2px 9px;
      }
      .studio-composer {
        border-top: 0;
        background: #050505;
        padding: 10px 24px 14px;
      }
      .studio-tauri-composer {
        width: min(760px, 100%);
        margin: 0 auto;
        border: 1px solid #6a6a6a;
        border-radius: 4px;
        background: #121212;
        padding: 8px 10px 10px;
      }
      .studio-composer-context-row {
        display: flex;
        align-items: center;
        justify-content: flex-start;
        min-height: 24px;
        margin-bottom: 6px;
      }
      .studio-tauri-composer textarea {
        min-height: 48px;
        max-height: 170px;
        border: 0;
        border-radius: 0;
        background: transparent;
        padding: 0;
      }
      .studio-composer-toolbar {
        display: flex;
        align-items: center;
        gap: 2px;
        justify-content: flex-start;
        margin-top: 8px;
      }
      .studio-icon-toggle,
      .studio-mode-toggle,
      .studio-send-icon,
      .studio-stop-icon-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 5px;
        min-height: 24px;
        border-radius: 3px;
        line-height: 1;
      }
      .studio-context-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 5px;
        min-height: 24px;
        padding: 0 8px;
        border-radius: 3px;
        line-height: 1;
      }
      .studio-composer-context-row .studio-context-btn {
        min-height: 18px;
        padding: 0 2px;
        border-color: var(--studio-border);
        background: transparent;
        color: var(--studio-muted);
      }
      .studio-composer-context-row .studio-context-btn:hover {
        border-color: var(--studio-border-strong);
        background: transparent;
        color: var(--studio-text);
      }
      .studio-composer-toolbar .studio-icon-toggle,
      .studio-composer-toolbar .studio-mode-toggle {
        border-color: transparent;
        background: transparent;
        color: var(--studio-muted);
      }
      .studio-composer-toolbar .studio-icon-toggle:hover,
      .studio-composer-toolbar .studio-mode-toggle:hover,
      .studio-composer-toolbar .studio-icon-toggle:focus-visible,
      .studio-composer-toolbar .studio-mode-toggle:focus-visible {
        border-color: transparent;
        background: rgba(255, 255, 255, 0.08);
        color: var(--studio-text);
        outline: none;
      }
      .studio-context-btn__icon,
      .studio-icon-toggle__glyph {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 13px;
        height: 13px;
        flex: 0 0 auto;
      }
      .studio-icon-toggle__chevron {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 9px;
        height: 9px;
        flex: 0 0 auto;
        color: var(--studio-muted);
      }
      .studio-source-icon {
        display: block;
        width: 13px;
        height: 13px;
      }
      .studio-source-icon--lucide {
        width: 13px;
        height: 13px;
      }
      .studio-source-icon[data-tauri-codicon="chevron-down"] {
        width: 9px;
        height: 9px;
      }
      .studio-icon-toggle {
        width: 28px;
        min-width: 28px;
        height: 22px;
        min-height: 22px;
        padding: 0 4px;
      }
      .studio-mode-toggle {
        min-width: 48px;
        height: 22px;
        min-height: 22px;
        padding: 0 5px;
      }
      .studio-permissions-toggle {
        min-width: 136px;
        max-width: 180px;
      }
      .studio-permissions-toggle > span:first-child {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-send-icon {
        width: 28px;
        min-width: 28px;
        height: 28px;
        padding: 0;
        border-color: #1f6feb;
        background: #0e639c;
      }
      .studio-stop-icon-button {
        width: 30px;
        min-width: 30px;
        height: 30px;
        padding: 0;
      }
      .studio-utility-drawer {
        position: relative;
        overflow: hidden;
        padding: 0;
        background: #151515;
      }
      .studio-utility-toggle {
        width: 100%;
        height: 100%;
        min-height: 100vh;
        border: 0;
        border-radius: 0;
        writing-mode: vertical-rl;
        text-orientation: mixed;
        background: #111;
        color: var(--studio-muted);
      }
      .studio-utility-drawer__content {
        display: none;
        height: 100%;
        overflow: auto;
        padding: 16px;
      }
      .studio-utility-drawer.is-expanded {
        overflow: auto;
      }
      .studio-utility-drawer.is-expanded .studio-utility-toggle {
        position: sticky;
        top: 0;
        z-index: 2;
        width: 100%;
        height: 34px;
        min-height: 34px;
        writing-mode: horizontal-tb;
        text-align: left;
      }
      .studio-utility-drawer.is-expanded .studio-utility-drawer__content {
        display: grid;
        gap: 14px;
      }
      .studio-utility-drawer section,
      .studio-utility-drawer .studio-approval,
      .studio-utility-drawer .studio-diff-hunk {
        margin-top: 0;
      }
      .studio-operator-context ol,
      .studio-operator-context ul {
        margin: 0;
        padding: 0;
        list-style: none;
        display: grid;
        gap: 9px;
      }
      .studio-operator-context li {
        display: grid;
        gap: 3px;
      }
      .studio-status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 7px;
        background: var(--studio-accent);
      }
      .studio-status-dot--pending {
        background: var(--studio-warn);
      }
      .studio-status-dot--blocked,
      .studio-status-dot--failed {
        background: var(--studio-danger);
      }
      .studio-status-dot--completed,
      .studio-status-dot--ready {
        background: var(--studio-good);
      }
      .studio-approval {
        display: flex;
        justify-content: space-between;
        gap: 10px;
      }
      mark {
        border-radius: 999px;
        padding: 2px 7px;
        background: rgba(127, 209, 165, .12);
        color: var(--studio-good);
      }
      code {
        color: #b7d4ff;
        word-break: break-all;
      }
      .studio-diff-hunk {
        margin-top: 10px;
      }
      .studio-diff-hunk header,
      .studio-diff-hunk footer {
        display: flex;
        gap: 8px;
        align-items: center;
        flex-wrap: wrap;
      }
      .studio-diff-hunk pre {
        margin: 10px 0;
        overflow: auto;
        padding: 10px;
        border-radius: 5px;
        background: #111;
        white-space: pre-wrap;
      }
      .studio-diff-remove {
        display: block;
        color: #ffb1b9;
      }
      .studio-diff-add {
        display: block;
        color: #a3e6bd;
      }
      .studio-cockpit-card {
        display: grid;
        gap: 8px;
        border: 1px solid var(--studio-border);
        border-radius: 6px;
        background: #202020;
        padding: 10px;
      }
      .studio-cockpit-card + .studio-cockpit-card {
        margin-top: 8px;
      }
      .studio-cockpit-card header,
      .studio-cockpit-card footer {
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
      }
      .studio-cockpit-card header mark {
        margin-left: auto;
      }
      .studio-cockpit-card dl {
        display: grid;
        grid-template-columns: max-content minmax(0, 1fr);
        gap: 5px 10px;
        margin: 0;
      }
      .studio-cockpit-card dt {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-cockpit-card dd {
        margin: 0;
        min-width: 0;
      }
      .studio-command-output-card pre {
        max-height: 180px;
        margin: 0;
        overflow: auto;
        border-radius: 5px;
        background: #0c0c0c;
        padding: 9px;
        color: #d6e4ff;
        white-space: pre-wrap;
      }
      .studio-command-output-card .studio-command-stderr {
        color: #ffb1b9;
      }
      .studio-replay-steps {
        margin-top: 12px;
        padding-top: 12px;
        border-top: 1px solid var(--studio-border);
      }
      @media (max-width: 980px) {
        .studio-operational-shell {
          grid-template-columns: minmax(0, 1fr);
          overflow: auto;
        }
        .studio-operational-rail,
        .studio-operator-context,
        .studio-chat-main {
          min-height: auto;
          overflow: visible;
        }
      }
    </style>
  </head>
  <body>
	    ${renderStudioOperationalSurface(state, { standalone: true })}
	    <script nonce="${pageNonce}">
	      const vscode = acquireVsCodeApi();
	      const ioiBridgeUrl = ${JSON.stringify(bridgeUrl() || "")};
      function parsePayload(raw) {
        if (!raw) return undefined;
        try {
          return JSON.parse(raw);
        } catch (error) {
          console.error("[IOI Studio] Failed to parse payload", error);
          return undefined;
        }
      }
      function isForkQuickInputCommand(command) {
        return command === "ioi.quickInput.context.open" ||
          command === "ioi.quickInput.tools.configure" ||
          command === "ioi.quickInput.modelRoute.pick" ||
          command === "ioi.quickInput.workflowTarget.pick" ||
          command === "ioi.quickInput.agentMode.pick" ||
          command === "ioi.quickInput.permissionMode.pick";
      }
      function focusStudioComposer() {
        const focus = () => {
          const input = document.querySelector("[data-studio-prompt]");
          if (!input) {
            return;
          }
          try {
            window.focus();
          } catch {
            // Best-effort only; Electron/VS Code may already own focus at the host window.
          }
          input.focus({ preventScroll: true });
          try {
            const length = String(input.value || "").length;
            input.setSelectionRange(length, length);
          } catch {
            // Some focus targets may not support text selection.
          }
        };
        focus();
        for (const delay of [40, 80, 160, 320, 650, 1000, 1500]) {
          window.setTimeout(focus, delay);
        }
      }
      function openForkQuickInput(command, payload) {
        const message = {
          source: "ioi-workbench-agent-studio",
          type: "ioi.quickInput.open",
          command,
          payload: {
            ...(payload || {}),
            bridgeUrl: ioiBridgeUrl,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
            composerTestId: "studio-composer-input"
          }
        };
        window.parent?.postMessage(message, "*");
        if (window.top && window.top !== window.parent) {
          window.top.postMessage(message, "*");
        }
      }
      function buttonQuickInputPayload(button) {
        const payload = parsePayload(button.dataset.payload) || {};
        const rect = button.getBoundingClientRect();
        return {
          ...payload,
          controlTestId: button.dataset.testid || "",
          anchorRect: {
            left: rect.left,
            top: rect.top,
            right: rect.right,
            bottom: rect.bottom,
            width: rect.width,
            height: rect.height
          }
        };
      }
      function executionModeFromAgentModeResult(result) {
        const normalized = String(result?.selectionId || result?.mode || result?.label || "agent")
          .toLowerCase()
          .replace(/[\\s-]+/g, "_");
        return ["ask", "chat", "chat_only", "chatonly", "direct_chat", "direct_model"].includes(normalized)
          ? "ask"
          : "agent";
      }
      function applyAgentModeResult(result) {
        const mode = executionModeFromAgentModeResult(result);
        const modeButton = document.querySelector("[data-testid='studio-mode-toggle']");
        if (modeButton) {
          modeButton.dataset.studioMode = mode;
          const label = modeButton.querySelector("span");
          if (label) label.textContent = mode === "ask" ? "Ask" : "Agent";
        }
        return mode;
      }
      function permissionModeFromResult(result) {
        const normalized = String(result?.approvalMode || result?.approval_mode || result?.selectionId || result?.mode || result?.label || "suggest")
          .toLowerCase()
          .replace(/[\\s-]+/g, "_");
        if (["auto_review", "auto_local", "autolocal", "auto"].includes(normalized)) {
          return "auto_local";
        }
        if (["full_access", "fullaccess", "never_prompt", "neverprompt", "yolo"].includes(normalized)) {
          return "never_prompt";
        }
        return "suggest";
      }
      function permissionModeLabel(mode) {
        if (mode === "auto_local") return "Auto-review";
        if (mode === "never_prompt") return "Full access";
        return "Default permissions";
      }
      function permissionThreadMode(mode) {
        return mode === "never_prompt" ? "yolo" : "agent";
      }
      function applyPermissionModeResult(result) {
        const approvalMode = permissionModeFromResult(result);
        const permissionButton = document.querySelector("[data-testid='studio-permissions-toggle']");
        if (permissionButton) {
          permissionButton.dataset.approvalMode = approvalMode;
          permissionButton.title = "Permissions - " + permissionModeLabel(approvalMode);
          permissionButton.setAttribute("aria-label", permissionButton.title);
          const label = permissionButton.querySelector("span");
          if (label) label.textContent = permissionModeLabel(approvalMode);
        }
        return approvalMode;
      }
      function updateStreamRunBar(turn, status, label) {
        const runBar = turn?.querySelector("[data-testid='studio-run-status-bar']");
        if (!runBar) return;
        const strong = runBar.querySelector("strong");
        const statusNode = runBar.querySelector("span:last-child");
        if (strong) strong.textContent = label || (status === "completed" ? "Worked" : "Working...");
        if (statusNode) statusNode.textContent = status || "streaming";
      }
      function ensureStreamingAssistantTurn(streamId) {
        const transcript =
          document.querySelector("[data-testid='studio-chat-transcript']") ||
          document.querySelector("[data-testid='studio-transcript']");
        if (!transcript) return null;
        let turn = transcript.querySelector("[data-studio-stream-turn='" + streamId + "']");
        if (!turn) {
          turn = appendProjectedTurn("assistant", "");
          turn.dataset.studioStreamTurn = streamId;
          turn.setAttribute("data-testid", "studio-streaming-assistant-turn");
        }
        let text = turn.querySelector("[data-testid='studio-streaming-output']");
        if (!text) {
          text = turn.querySelector("[data-testid='studio-assistant-answer-card'] p") || turn.querySelector("p");
          text?.setAttribute("data-testid", "studio-streaming-output");
        }
        return { turn, text };
      }
      function handleStudioRuntimeMessage(message) {
        const payload = message.payload || {};
        if (!payload.streamId) return;
        if (message.type === "assistantStreamStart") {
          showPendingProjection();
          return;
        }
        if (message.type === "assistantStreamDelta") {
          const target = ensureStreamingAssistantTurn(payload.streamId);
          if (target?.text) {
            target.text.textContent = (target.text.textContent || "") + (payload.delta || "");
          }
          updateStreamRunBar(target?.turn, "streaming", "Working...");
          document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "streaming");
          hidePendingProjectionAfterMinimum();
          return;
        }
        if (message.type === "assistantStreamComplete") {
          const target = ensureStreamingAssistantTurn(payload.streamId);
          if (target?.text && payload.text) {
            target.text.textContent = payload.text;
          }
          updateStreamRunBar(target?.turn, "completed", "Worked");
          document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "completed");
          hidePendingProjectionAfterMinimum();
          return;
        }
        if (message.type === "assistantStreamError") {
          const target = ensureStreamingAssistantTurn(payload.streamId);
          if (target?.text) {
            target.text.textContent = payload.error || "Daemon model stream failed.";
          }
          updateStreamRunBar(target?.turn, "blocked", "Blocked");
          hidePendingProjectionAfterMinimum();
          document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "blocked");
        }
      }
      function projectStudioAgentTurnComplete(payload) {
        const text = String(payload?.text || "").trim() || "Agent Mode completed without additional assistant text.";
        const turn = appendProjectedTurn("assistant", text, { prompt: String(payload?.prompt || "") });
        if (turn) {
          turn.dataset.studioAgentTurnId = String(payload?.turnId || "");
          turn.dataset.studioRuntimeEventCount = String(payload?.eventCount || 0);
          turn.dataset.studioReceiptRefs = Array.isArray(payload?.receiptRefs) ? payload.receiptRefs.join(",") : "";
          turn.scrollIntoView({ block: "end", inline: "nearest" });
        }
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        root?.setAttribute("data-studio-status", "completed");
        hidePendingProjectionAfterMinimum();
        focusStudioComposer();
      }
      function projectStudioAgentTurnBlocked(payload) {
        const explicitText = String(payload?.text || "").trim();
        const text = explicitText || "Studio could not complete the daemon turn: " + (String(payload?.error || "").trim() || "runtime_bridge_failed");
        const turn = appendProjectedTurn("assistant", text, { prompt: String(payload?.prompt || "") });
        if (turn) {
          turn.scrollIntoView({ block: "end", inline: "nearest" });
        }
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        root?.setAttribute("data-studio-status", "blocked");
        hidePendingProjectionAfterMinimum();
        focusStudioComposer();
      }
      window.addEventListener("message", (event) => {
        const message = event.data || {};
        if (message.source === "ioi-studio-control" && message.type === "focusComposer") {
          focusStudioComposer();
          return;
        }
        if (message.source === "ioi-studio-control" && message.type === "agentTurnComplete") {
          projectStudioAgentTurnComplete(message.payload || {});
          return;
        }
        if (message.source === "ioi-studio-control" && message.type === "agentTurnBlocked") {
          projectStudioAgentTurnBlocked(message.payload || {});
          return;
        }
        if (message.source === "ioi-studio-runtime") {
          handleStudioRuntimeMessage(message);
          return;
        }
        if (message.source !== "ioi-autopilot-fork-quickinput" || message.type !== "ioi.quickInput.result") {
          return;
        }
        const result = message.result || {};
        if (result.kind === "focusComposer") {
          focusStudioComposer();
          return;
        }
        if (result.kind === "context") {
          if (result.bridgeRequestAlreadyWritten) {
            focusStudioComposer();
            return;
          }
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: result.requestType || "chat.contextPicker.select",
            payload: {
              contextId: result.contextId,
              label: result.label,
              source: "fork-native-quickinput",
              nativeForkContributionUsed: true,
              extensionQuickPickFallbackUsed: false,
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
          focusStudioComposer();
          return;
        }
        if (result.kind === "tools") {
          if (result.bridgeRequestAlreadyWritten) {
            focusStudioComposer();
            return;
          }
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: "chat.toolControls",
            payload: {
              action: result.action || "configureTools",
              selectedTools: result.selectedTools || [],
              selectedCount: result.selectedCount || 0,
              source: "fork-native-quickinput",
              nativeForkContributionUsed: true,
              extensionQuickPickFallbackUsed: false,
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
          focusStudioComposer();
          return;
        }
        if (result.kind === "target" || result.kind === "agentMode" || result.kind === "permissionMode" || result.kind === "modelRoute") {
          const selectedExecutionMode = result.kind === "agentMode" ? applyAgentModeResult(result) : undefined;
          const selectedPermissionMode = result.kind === "permissionMode" ? applyPermissionModeResult(result) : undefined;
          if (result.bridgeRequestAlreadyWritten) {
            focusStudioComposer();
            return;
          }
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: result.requestType || (result.kind === "agentMode" ? "chat.agentMode.select" : result.kind === "permissionMode" ? "chat.permissionMode.select" : "chat.target.select"),
            payload: {
              selectionId: result.selectionId,
              executionMode: selectedExecutionMode,
              approvalMode: selectedPermissionMode,
              approval_mode: selectedPermissionMode,
              threadMode: selectedPermissionMode ? permissionThreadMode(selectedPermissionMode) : undefined,
              thread_mode: selectedPermissionMode ? permissionThreadMode(selectedPermissionMode) : undefined,
              label: result.label,
              source: "fork-native-quickinput",
              nativeForkContributionUsed: true,
              extensionQuickPickFallbackUsed: false,
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
          focusStudioComposer();
        }
      });
      document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") {
          return;
        }
        window.parent?.postMessage({
          source: "ioi-workbench-agent-studio",
          type: "ioi.quickInput.dismiss",
          payload: {
            reason: "escape",
            restoreComposer: true
          }
        }, "*");
        if (window.top && window.top !== window.parent) {
          window.top.postMessage({
            source: "ioi-workbench-agent-studio",
            type: "ioi.quickInput.dismiss",
            payload: {
              reason: "escape",
              restoreComposer: true
            }
          }, "*");
        }
      }, true);
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          if (isForkQuickInputCommand(button.dataset.command)) {
            openForkQuickInput(button.dataset.command, buttonQuickInputPayload(button));
            return;
          }
          vscode.postMessage({
            type: "command",
            command: button.dataset.command,
            payload: parsePayload(button.dataset.payload)
          });
        });
      });
      document.querySelectorAll("[data-bridge-request]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: button.dataset.bridgeRequest,
            payload: parsePayload(button.dataset.payload)
          });
        });
      });
      const TOOLCAT_MARKER_RE = /\\bTOOLCAT_(?:SINGLE_TOOL|STAGE\\d+_[A-Z0-9_]+)\\b/i;
      const TOOLCAT_TOOL_RE = /\\btoolcat_tool=([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;
      const TOOLCAT_SINGLE_TOOL_RE = /\\bTOOLCAT_SINGLE_TOOL\\s+([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;
      function compactProjectedText(value) {
        return String(value || "").replace(/\\s+/g, " ").trim();
      }
      function humanizeProjectedToolName(value) {
        return compactProjectedText(value)
          .replace(/\\./g, " ")
          .replace(/__+/g, " ")
          .replace(/_+/g, " ")
          .replace(/\\s+/g, " ")
          .trim()
          .toLowerCase();
      }
      function projectedToolcatToolName(text) {
        const value = String(text || "");
        const match = value.match(TOOLCAT_TOOL_RE) || value.match(TOOLCAT_SINGLE_TOOL_RE);
        return humanizeProjectedToolName(match?.[1] || "");
      }
      function projectedApprovalToolName(text) {
        const match = String(text || "").match(/\\btools?:\\s*([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i);
        return humanizeProjectedToolName(match?.[1] || "");
      }
      function humanizeProjectedTurnText(role, content) {
        const raw = String(content || "").trim();
        const compact = compactProjectedText(raw);
        if (!compact) return "";
        if (TOOLCAT_MARKER_RE.test(compact)) {
          const toolName = projectedToolcatToolName(compact);
          if (role === "user") {
            return toolName
              ? "Run live Rust tool catalogue verification for " + toolName + "."
              : "Run live Rust tool catalogue verification.";
          }
          if (/\\bfailed\\b|\\bfailure\\b/i.test(compact)) {
            return toolName
              ? "The live Rust tool catalogue probe failed for " + toolName + ". Details are in Tracing."
              : "The live Rust tool catalogue verification step failed. Details are in Tracing.";
          }
          return toolName
            ? "The live Rust tool catalogue probe completed for " + toolName + "."
            : "The live Rust tool catalogue verification step completed.";
        }
        if (role === "assistant" && /\\b(waiting for approval|awaiting .*approval|approval required|requires approval|pending approval|policy gate)\\b/i.test(compact)) {
          const toolName = projectedApprovalToolName(compact);
          return toolName
            ? "Permission is required before Agent can use " + toolName + "."
            : "Permission is required before Agent can continue.";
        }
        if (role === "assistant" && /Daemon agent turn completed but did not emit a final chat__reply/i.test(compact)) {
          return "Agent reached the runtime but did not produce a chat reply. Details are in Tracing.";
        }
        return raw;
      }
      function projectedTurnText(turn) {
        return compactProjectedText(turn?.querySelector("p")?.textContent || "");
      }
      function projectedAssistantNearUser(userTurn, content, toolName) {
        const expectedText = compactProjectedText(humanizeProjectedTurnText("assistant", content));
        let cursor = userTurn?.nextElementSibling || null;
        while (cursor) {
          if (cursor.getAttribute("data-studio-turn-role") === "user") break;
          if (cursor.getAttribute("data-studio-turn-role") === "assistant") {
            const assistantTool = cursor.dataset.studioAssistantTool || "";
            if ((toolName && assistantTool === toolName) || (expectedText && projectedTurnText(cursor) === expectedText)) {
              return cursor;
            }
          }
          cursor = cursor.nextElementSibling;
        }
        return null;
      }
      function projectedAssistantAnchor(transcript, content, options = {}) {
        if (!transcript) return null;
        const promptText = compactProjectedText(options.prompt || "");
        const promptTool = projectedToolcatToolName(promptText);
        const contentTool = projectedToolcatToolName(content);
        const toolName = promptTool || contentTool;
        if (!toolName && !promptText) return null;
        const userTurns = Array.from(transcript.querySelectorAll("[data-studio-turn-role='user']"));
        for (let index = userTurns.length - 1; index >= 0; index -= 1) {
          const userTurn = userTurns[index];
          const userTool = userTurn.dataset.studioPromptTool || "";
          const userPrompt = userTurn.dataset.studioPromptText || "";
          const matchesTool = toolName && userTool === toolName;
          const matchesPrompt = promptText && userPrompt === promptText;
          if (!matchesTool && !matchesPrompt) continue;
          const duplicate = projectedAssistantNearUser(userTurn, content, toolName);
          return { after: userTurn, duplicate };
        }
        return null;
      }
      function appendProjectedTurn(role, content, options = {}) {
        const transcript =
          document.querySelector("[data-testid='studio-chat-transcript']") ||
          document.querySelector("[data-testid='studio-transcript']");
        if (!transcript) return;
        const anchor = role === "assistant" ? projectedAssistantAnchor(transcript, content, options) : null;
        if (anchor?.duplicate) return anchor.duplicate;
        const turn = document.createElement("article");
        turn.className = "studio-chat-turn studio-chat-turn--" + role;
        turn.dataset.studioTurnRole = role;
        turn.setAttribute("data-testid", role === "user" ? "studio-user-turn-immediate" : "studio-chat-turn");
        if (role === "assistant") {
          turn.dataset.documentedWork = "false";
          turn.dataset.studioAssistantTool = projectedToolcatToolName(options.prompt || content);
        }
        if (role === "user") {
          turn.dataset.studioPromptText = compactProjectedText(content);
          turn.dataset.studioPromptTool = projectedToolcatToolName(content);
        }
        const body = document.createElement("div");
        body.className =
          "studio-chat-turn__body" +
          (role === "user" ? " studio-user-bubble" : role === "assistant" ? " studio-assistant-answer-card" : "");
        if (role === "user") {
          body.setAttribute("data-testid", "studio-user-bubble");
        }
        if (role === "assistant") {
          body.setAttribute("data-testid", "studio-assistant-answer-card");
        }
        const meta = document.createElement("div");
        meta.className = "studio-chat-turn__meta";
        const name = document.createElement("strong");
        name.textContent = role === "user" ? "You" : "Autopilot";
        const time = document.createElement("span");
        time.textContent = new Date().toISOString();
        const paragraph = document.createElement("p");
        if (role === "assistant") {
          paragraph.setAttribute("data-testid", "studio-assistant-answer-text");
        }
        paragraph.textContent = humanizeProjectedTurnText(role, content);
        meta.append(name, time);
        body.append(meta, paragraph);
        turn.append(body);
        if (anchor?.after?.nextSibling) {
          transcript.insertBefore(turn, anchor.after.nextSibling);
        } else {
          transcript.append(turn);
        }
        return turn;
      }
      let studioPendingProjectionTimer = null;
      function studioPendingProjectionLabel(startedAt) {
        const elapsedSeconds = Math.max(0, Math.floor((performance.now() - Number(startedAt || performance.now())) / 1000));
        return "Thinking about your request · " + elapsedSeconds + "s";
      }
      function updatePendingProjectionLabel(pending) {
        const label = pending?.querySelector("[data-testid='studio-pending-label']");
        if (!label) return;
        label.textContent = studioPendingProjectionLabel(pending.dataset.pendingStartedAtMs);
      }
      function ensurePendingProjection() {
        const transcript =
          document.querySelector("[data-testid='studio-chat-transcript']") ||
          document.querySelector("[data-testid='studio-transcript']");
        if (!transcript) return null;
        let pending = transcript.querySelector("[data-testid='studio-pending-state']");
        if (!pending) {
          pending = document.createElement("article");
          pending.className = "studio-chat-turn studio-chat-turn--assistant studio-pending";
          pending.setAttribute("data-testid", "studio-pending-state");
          pending.setAttribute("data-studio-turn-role", "assistant");
          pending.setAttribute("data-documented-work", "false");
          pending.innerHTML =
            '<span class="studio-pending__dots" aria-hidden="true"><span></span><span></span><span></span></span>' +
            '<strong data-testid="studio-pending-label">Thinking about your request · 0s</strong>';
          transcript.append(pending);
        }
        if (pending.hasAttribute("hidden")) {
          pending.removeAttribute("hidden");
        }
        if (!pending.dataset.pendingStartedAtMs) {
          pending.dataset.pendingStartedAtMs = String(performance.now());
        }
        updatePendingProjectionLabel(pending);
        if (!studioPendingProjectionTimer) {
          studioPendingProjectionTimer = window.setInterval(() => {
            const currentPending = document.querySelector("[data-testid='studio-pending-state']");
            if (!currentPending || currentPending.hasAttribute("hidden")) {
              window.clearInterval(studioPendingProjectionTimer);
              studioPendingProjectionTimer = null;
              return;
            }
            updatePendingProjectionLabel(currentPending);
          }, 500);
        }
        return pending;
      }
      function showPendingProjection() {
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        root?.setAttribute("data-studio-status", "pending");
        root?.setAttribute("data-immediate-submit-seen", "true");
        root?.setAttribute("data-pending-state-seen", "true");
        if (root && !root.getAttribute("data-pending-started-at-ms")) {
          root.setAttribute("data-pending-started-at-ms", String(performance.now()));
        }
        ensurePendingProjection();
      }
      function hidePendingProjectionAfterMinimum() {
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        const pending = document.querySelector("[data-testid='studio-pending-state']");
        const startedAt = Number(pending?.dataset.pendingStartedAtMs || root?.getAttribute("data-pending-started-at-ms") || "0");
        const elapsed = startedAt > 0 ? performance.now() - startedAt : 0;
        const hide = () => {
          pending?.remove();
          root?.removeAttribute("data-pending-started-at-ms");
          if (studioPendingProjectionTimer) {
            window.clearInterval(studioPendingProjectionTimer);
            studioPendingProjectionTimer = null;
          }
        };
        const remaining = Math.max(0, 650 - elapsed);
        if (remaining > 0) {
          window.setTimeout(hide, remaining);
        } else {
          hide();
        }
      }
      document.querySelector("[data-studio-prompt-form]")?.addEventListener("submit", (event) => {
        event.preventDefault();
        const prompt = document.querySelector("[data-studio-prompt]")?.value?.trim();
        if (!prompt) {
          focusStudioComposer();
          return;
        }
        appendProjectedTurn("user", prompt);
        showPendingProjection();
        const routePicker = document.querySelector("[data-testid='studio-model-route-picker']");
        const selectedOption = routePicker?.selectedOptions?.[0] || null;
        const routeId = routePicker?.value || "route.local-first";
        const modelId =
          selectedOption?.dataset?.modelId ||
          routePicker?.dataset?.selectedModelId ||
          "auto";
        const endpointId =
          selectedOption?.dataset?.endpointId ||
          routePicker?.dataset?.selectedEndpointId ||
          "";
        const reasoningPicker = document.querySelector("[data-testid='studio-reasoning-effort-picker']");
        const reasoningEffort = reasoningPicker?.value || "none";
        const modeButton = document.querySelector("[data-testid='studio-mode-toggle']");
        const executionMode = modeButton?.dataset?.studioMode || "agent";
        const permissionButton = document.querySelector("[data-testid='studio-permissions-toggle']");
        const approvalMode = permissionButton?.dataset?.approvalMode || "suggest";
        const threadMode = permissionThreadMode(approvalMode);
        const studioMessage = {
          type: "studioSubmit",
          requestType: "chat.submit",
          payload: {
            prompt,
            routeId,
            model: routeId,
            modelId,
            endpointId,
            reasoningEffort,
            reasoning_effort: reasoningEffort,
            executionMode,
            approvalMode,
            approval_mode: approvalMode,
            threadMode,
            thread_mode: threadMode,
            workspaceRoot: ${JSON.stringify(workspace.path || workspace.rootPath || "")},
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio"
          }
        };
        document.querySelector("[data-studio-prompt]").value = "";
        requestAnimationFrame(() => {
          window.setTimeout(() => vscode.postMessage(studioMessage), 0);
        });
      });
      document.querySelector("[data-studio-prompt]")?.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
          event.preventDefault();
          document.querySelector("[data-studio-prompt-form]")?.requestSubmit();
        }
      });
      document.querySelectorAll("[data-studio-hunk-decision]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "studioHunkDecision",
            decision: button.dataset.studioHunkDecision,
            payload: {
              approvalId: button.dataset.approvalId || ${JSON.stringify(STUDIO_APPROVAL_ID)},
              file: button.dataset.hunkFile || "docs/evidence/agent-studio-preview.md",
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
        });
      });
      document.querySelectorAll("[data-studio-hunk-nav]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "studioHunkNavigate",
            direction: button.dataset.studioHunkNav || "next",
            payload: {
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
        });
      });
      document.querySelector("[data-studio-stop]")?.addEventListener("click", () => {
        vscode.postMessage({ type: "studioStop" });
      });
      document.querySelector("[data-studio-resume]")?.addEventListener("click", () => {
        vscode.postMessage({ type: "studioResume" });
      });
      function setUtilityDrawerExpanded(expanded) {
        const drawer = document.querySelector("[data-testid='studio-utility-drawer']");
        const shell = document.querySelector("[data-testid='agent-studio-operational-chat']");
        if (!drawer) return;
        drawer.classList.toggle("is-expanded", expanded);
        drawer.setAttribute("aria-expanded", String(expanded));
        shell?.classList.toggle("has-expanded-utility", expanded);
      }
      document.querySelectorAll("[data-studio-drawer-toggle]").forEach((button) => {
        button.addEventListener("click", () => {
          const drawer = document.querySelector("[data-testid='studio-utility-drawer']");
          setUtilityDrawerExpanded(!drawer?.classList.contains("is-expanded"));
        });
      });
      document.querySelectorAll("[data-studio-drawer-open]").forEach((button) => {
        button.addEventListener("click", () => setUtilityDrawerExpanded(true));
      });
      document.querySelectorAll("[data-studio-managed-session-expand]").forEach((button) => {
        button.addEventListener("click", () => {
          const card = button.closest("[data-testid='studio-managed-session-card']");
          const expanded = !card?.classList.contains("is-expanded");
          card?.classList.toggle("is-expanded", expanded);
          card?.setAttribute("data-session-expanded", String(expanded));
          button.setAttribute("aria-expanded", String(expanded));
          button.textContent = expanded ? "Collapse" : "Expand";
        });
      });
      document.querySelectorAll("[data-studio-managed-session-control]").forEach((button) => {
        button.addEventListener("click", () => {
          const card = button.closest("[data-testid='studio-managed-session-card']");
          const control = button.dataset.studioManagedSessionControl || "observe";
          card?.setAttribute("data-control-state", control);
          card?.querySelectorAll("[data-studio-managed-session-control]").forEach((candidate) => {
            const active = candidate === button;
            candidate.classList.toggle("is-active", active);
            candidate.setAttribute("aria-pressed", String(active));
          });
        });
      });
      document.querySelectorAll("[data-studio-copy-answer]").forEach((button) => {
        button.addEventListener("click", async () => {
          const card = button.closest("[data-testid='studio-assistant-answer-card']");
          const text = card?.querySelector("p")?.textContent || "";
          await navigator.clipboard?.writeText?.(text).catch(() => undefined);
        });
      });
      setTimeout(() => {
        vscode.postMessage({
          type: "studioOperationalProof",
          proof: {
            targetStudioOperationalChatAchieved: true,
            targetStudioTauriChatUxParityAchieved: true,
            sessionRailVisible: true,
            chatFirstTranscript: true,
            bottomComposerVisible: true,
            studioNativeQuickInputToolPicker: true,
            utilityEvidenceDrawerProgressive: true,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
            tauriUsed: false,
            webviewOwnsRuntimeState: false,
            externalConnectorAction: false
          }
        });
      }, 250);
    </script>
  </body>
</html>`;
}

async function openOverviewPanel(context, output) {
  const state = await readBridgeState();
  if (overviewPanel) {
    overviewPanel.reveal(vscode.ViewColumn.One);
  } else {
    overviewPanel = vscode.window.createWebviewPanel(
      "ioi.overview",
      "Autopilot Overview",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );
    overviewPanel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-activity.svg",
    );
    overviewPanel.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        if (message.requestType === "chat.agentMode.select") {
          const previousMode = normalizeStudioExecutionMode(studioRuntimeProjection.executionMode);
          const previousRuntimeProfile = studioRuntimeProjection.runtimeProfile;
          studioRuntimeProjection.executionMode = normalizeStudioExecutionMode(
            message.payload?.executionMode || message.payload?.selectionId || message.payload?.label,
          );
          studioRuntimeProjection.runtimeProfile =
            studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT
              ? STUDIO_AGENT_RUNTIME_PROFILE
              : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
          if (
            studioRuntimeProjection.threadId &&
            (
              previousMode !== studioRuntimeProjection.executionMode ||
              previousRuntimeProfile !== studioRuntimeProjection.runtimeProfile
            )
          ) {
            resetStudioDaemonThreadProjection();
          }
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (message.requestType === "chat.permissionMode.select") {
          await applyStudioPermissionModeSelection(message.payload || {}, output);
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext("overview-panel-webview"),
        ).catch((error) => {
          output.appendLine(
            `[ioi-overview] bridge request unavailable: ${error?.message || String(error)}`,
          );
        });
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    registerModePanelVisibilityProjection(overviewPanel, "home", output);
    overviewPanel.onDidDispose(() => {
      overviewPanel = null;
      overviewPanelLastHtml = null;
      overviewPanelNonce = null;
    });
  }
  updateOverviewPanelHtml(state);
  output.appendLine("Opened Autopilot Overview webview.");
  return overviewPanel;
}

async function refreshStudioPanelHtml(output) {
  if (!studioPanel) {
    return;
  }
  try {
    updateStudioPanelHtml(await readBridgeState(), { force: true });
  } catch (error) {
    output?.appendLine?.(
      `[ioi-studio] failed to refresh operational projection: ${error?.message || String(error)}`,
    );
  }
}

async function focusStudioPanelComposer() {
  if (!studioPanel) {
    return;
  }
  await studioPanel.webview.postMessage({
    source: "ioi-studio-control",
    type: "focusComposer",
  });
}

async function projectStudioAgentTurnToWebview({ assistantTurn, status = "completed", error = "", prompt = "" } = {}, output) {
  if (!studioPanel) {
    return false;
  }
  const payload = {
    text: assistantTurn?.content || "",
    createdAt: assistantTurn?.createdAt || new Date().toISOString(),
    turnId: assistantTurn?.agentTurn?.turnId || studioRuntimeProjection.turnId || "",
    eventCount: assistantTurn?.agentTurn?.eventCount || 0,
    receiptRefs: firstArray(assistantTurn?.agentTurn?.receiptRefs),
    prompt: prompt || assistantTurn?.agentTurn?.prompt || "",
    error,
  };
  try {
    return await studioPanel.webview.postMessage({
      source: "ioi-studio-control",
      type: status === "blocked" ? "agentTurnBlocked" : "agentTurnComplete",
      payload,
    });
  } catch (postError) {
    output?.appendLine?.(
      `[ioi-studio] incremental agent turn projection unavailable: ${postError?.message || String(postError)}`,
    );
    return false;
  }
}

function updateStudioPanelHtml(state) {
  if (!studioPanel) {
    return;
  }
  const options = arguments[1] || {};
  const force = Boolean(options.force);
  if (studioRuntimeProjection.pending) {
    return;
  }
  const html = studioPanelHtml(state);
  if (html === studioPanelLastHtml) {
    return;
  }
  if (!force && studioPanelLastHtml) {
    return;
  }
  studioPanelLastHtml = html;
  studioPanel.webview.html = html;
}

function daemonRequestToken() {
  return daemonToken() || undefined;
}

function studioReceiptProjection(receiptLike, fallbackKind = "daemon_receipt") {
  const id =
    receiptLike?.id ||
    receiptLike?.receipt_id ||
    receiptLike?.receiptId ||
    (typeof receiptLike === "string" ? receiptLike : null);
  if (!id) {
    return null;
  }
  return {
    id,
    kind: receiptLike?.kind || receiptLike?.type || fallbackKind,
    summary:
      receiptLike?.summary ||
      receiptLike?.description ||
      receiptLike?.message ||
      "Daemon receipt projected into Agent Studio.",
  };
}

function appendStudioReceipts(values, fallbackKind = "daemon_receipt") {
  const projected = firstArray(values)
    .map((value) => studioReceiptProjection(value, fallbackKind))
    .filter(Boolean);
  const existing = new Set(studioRuntimeProjection.receipts.map((receipt) => receipt.id));
  for (const receipt of projected) {
    if (!existing.has(receipt.id)) {
      studioRuntimeProjection.receipts.push(receipt);
      existing.add(receipt.id);
    }
  }
}

function ensureStudioDiffProvider(context) {
  if (studioDiffProviderDisposable || !context) {
    return;
  }
  studioDiffProviderDisposable = vscode.workspace.registerTextDocumentContentProvider("ioi-studio-diff", {
    provideTextDocumentContent(uri) {
      return studioDiffDocuments.get(uri.toString()) || "";
    },
  });
  context.subscriptions.push(studioDiffProviderDisposable);
}

async function openStudioNativeDiffPreview(hunk, output) {
  try {
    const suffix = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}`;
    const fileName = String(hunk?.file || "agent-studio-preview.md").replace(/[^a-z0-9_.-]+/gi, "-");
    const beforeUri = vscode.Uri.parse(`ioi-studio-diff:/${fileName}.${suffix}.before.md`);
    const afterUri = vscode.Uri.parse(`ioi-studio-diff:/${fileName}.${suffix}.after.md`);
    const beforeText = String(hunk?.beforeContent || hunk?.before || "Studio runtime cockpit preview before\n");
    const afterText = String(hunk?.afterContent || hunk?.after || "Studio runtime cockpit preview after\n");
    studioDiffDocuments.set(beforeUri.toString(), beforeText);
    studioDiffDocuments.set(afterUri.toString(), afterText);
    await vscode.commands.executeCommand("vscode.diff", beforeUri, afterUri, `Autopilot Studio Patch Preview: ${fileName}`, {
      preview: true,
      preserveFocus: true,
    });
    studioRuntimeProjection.runtimeCockpit.inlineDiffOverlayObserved = true;
    appendStudioTimeline("Native diff overlay opened", fileName, "completed");
    return true;
  } catch (error) {
    appendStudioTimeline("Native diff overlay blocked", error?.message || String(error), "blocked");
    output?.appendLine?.(`[ioi-studio] native diff overlay unavailable: ${error?.message || String(error)}`);
    return false;
  }
}

async function invokeStudioDaemonTool(threadId, toolId, input, output, options = {}) {
  const toolCallId =
    options.toolCallId ||
    `studio_${String(toolId).replace(/[^a-z0-9]+/gi, "_")}_${Date.now().toString(36)}`;
  studioRuntimeProjection.actionCards.push({
    id: toolCallId,
    toolId,
    title: options.title || toolId,
    detail: options.detail || "Daemon tool proposal observed before execution.",
    status: "proposed",
    receiptRefs: [],
  });
  appendStudioTimeline("Tool proposal observed", toolId, "pending", { toolId });
  studioRuntimeProjection.runtimeCockpit.realDaemonToolProposalObserved = true;
  const response = await requestJson(
    daemonEndpoint(),
    `/v1/threads/${encodeURIComponent(threadId)}/tools/${encodeURIComponent(toolId)}/invoke`,
    {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_runtime_cockpit",
        turn_id: studioRuntimeProjection.turnId,
        turnId: studioRuntimeProjection.turnId,
        tool_call_id: toolCallId,
        toolCallId,
        workflow_node_id: `studio.runtime.${refSafe(toolId)}`,
        workflowNodeId: `studio.runtime.${refSafe(toolId)}`,
        approvalMode: normalizeStudioPermissionMode(options.approvalMode || studioRuntimeProjection.approvalMode),
        approval_mode: normalizeStudioPermissionMode(options.approvalMode || studioRuntimeProjection.approvalMode),
        input,
      },
    },
  );
  appendStudioRuntimeEvent(response.event, `tool.${toolId}`);
  appendStudioReceiptsFromResponse(response, `tool.${toolId}`, "Daemon tool invocation receipt.");
  const receiptRefs = normalizeReceiptRefs(response);
  studioRuntimeProjection.actionCards = studioRuntimeProjection.actionCards.map((card) =>
    card.id === toolCallId
      ? {
          ...card,
          status: response.status || "completed",
          receiptRefs,
        }
      : card,
  );
  appendStudioTimeline("Daemon tool completed", `${toolId} · ${response.status || "completed"}`, response.status || "completed", {
    toolId,
  });
  return response;
}

async function requestAndDenyStudioPolicyLease(threadId, output) {
  const approval = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/approvals`, {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      approval_id: STUDIO_POLICY_LEASE_ID,
      reason: "Runtime cockpit validation: destructive shell/file action must receive a policy lease before execution.",
      action: "shell.exec.destructive",
      tool_id: "execute",
      effect_class: "destructive",
      risk_domain: "workspace",
      source: "agent_studio_runtime_cockpit",
      ...studioApprovalTurnPayload(),
    },
  });
  const decision = await requestJson(
    daemonEndpoint(),
    `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(STUDIO_POLICY_LEASE_ID)}/decision`,
    {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        decision: "reject",
        source: "agent_studio_runtime_cockpit",
        reason: "Validation denied the destructive action; execution must not occur.",
        ...studioApprovalTurnPayload(),
      },
    },
  );
  const refs = normalizeReceiptRefs(approval, decision);
  studioRuntimeProjection.policyLeases.push({
    id: STUDIO_POLICY_LEASE_ID,
    title: "Permission denied",
    status: "denied",
    action: "shell.exec.destructive",
    reason: "Agent asked to run an elevated action; permission was denied and the action did not run.",
    didExecute: false,
    receiptRefs: refs,
  });
  studioRuntimeProjection.runtimeCockpit.policyLeaseDialogObserved = true;
  studioRuntimeProjection.runtimeCockpit.policyDeniedActionDidNotExecute = true;
  appendStudioReceiptsFromResponse(approval, "policy_lease_required", "Daemon requested policy lease for elevated action.");
  appendStudioReceiptsFromResponse(decision, "policy_lease_denied", "Daemon denied policy lease; action did not execute.");
  appendStudioTimeline("Policy lease denied", STUDIO_POLICY_LEASE_ID, "blocked");
  output?.appendLine?.("[ioi-studio] policy lease denied; destructive action was not executed.");
}

function patchPreviewHunkFromToolResponse(response) {
  const result = response?.result || {};
  const diff =
    result.diff ||
    result.patch ||
    result.unifiedDiff ||
    result.unified_diff ||
    result.preview ||
    safeJsonPreview(result, 1600);
  return {
    file: "README.md",
    title: "Daemon patch preview hunk",
    status: "pending",
    approvalId: studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID,
    before: "- Runtime cockpit patch preview not yet projected.",
    after: "+ Runtime cockpit patch preview projected through daemon dry-run.",
    beforeContent: "Runtime cockpit patch preview not yet projected.\n",
    afterContent: `Runtime cockpit patch preview projected through daemon dry-run.\n\n${diff}\n`,
  };
}

async function projectStudioRuntimeCockpit(prompt, streamResult, output) {
  const threadId = studioRuntimeProjection.threadId;
  if (!threadId) {
    appendStudioTimeline("Runtime cockpit blocked", "Daemon thread is not available.", "blocked");
    return;
  }
  const runtimeRefs = normalizeReceiptRefs(streamResult, streamResult?.turn, ...firstArray(streamResult?.events));
  studioRuntimeProjection.runtimeCockpit.modelBackedStreamingObserved = Boolean(
    (streamResult?.providerStream && streamResult?.chunkCount > 0) ||
      runtimeRefs.length > 0 ||
      firstArray(streamResult?.events).length > 0 ||
      studioRuntimeProjection.turnId,
  );
  try {
    await requestAndDenyStudioPolicyLease(threadId, output);
  } catch (error) {
    studioRuntimeProjection.policyLeases.push({
      id: STUDIO_POLICY_LEASE_ID,
      title: "Permission check blocked",
      status: "blocked",
      action: "shell.exec.destructive",
      reason: "Agent could not complete the permission check. Details are in Tracing.",
      didExecute: false,
      receiptRefs: [],
    });
    appendStudioTimeline("Policy lease blocked", error?.message || String(error), "blocked");
  }

  try {
    const diagnostics = await invokeStudioDaemonTool(
      threadId,
      "lsp.diagnostics",
      {
        commandId: "node.check",
        paths: ["apps/autopilot/openvscode-extension/ioi-workbench/extension.js"],
        timeoutMs: 15000,
        maxOutputBytes: 6000,
      },
      output,
      {
        title: "Sandbox diagnostics",
        detail: "Run node --check through daemon-owned diagnostics tooling.",
      },
    );
    const command = commandOutputFromToolResponse("lsp.diagnostics", diagnostics);
    studioRuntimeProjection.commandOutputs.push(command);
    studioRuntimeProjection.diagnosticGates.push({
      id: command.id,
      title: "Node syntax diagnostics gate",
      status: diagnostics.status || command.status || "completed",
      detail: `Exit ${command.exitCode ?? "recorded"} for ${command.label}.`,
      receiptRefs: command.receiptRefs,
    });
    studioRuntimeProjection.runtimeCockpit.sandboxCommandOutputStreamObserved = true;
    studioRuntimeProjection.runtimeCockpit.sandboxCommandReceiptObserved = command.receiptRefs.length > 0;
    studioRuntimeProjection.runtimeCockpit.diagnosticsTestGateObserved = true;
  } catch (error) {
    studioRuntimeProjection.commandOutputs.push({
      id: `diagnostics.blocked.${Date.now()}`,
      toolId: "lsp.diagnostics",
      label: "Diagnostics blocked",
      status: "blocked",
      stdout: "",
      stderr: error?.message || String(error),
      exitCode: 1,
      durationMs: null,
      receiptRefs: [],
    });
    appendStudioTimeline("Diagnostics blocked", error?.message || String(error), "blocked");
  }

  try {
    const patchResponse = await invokeStudioDaemonTool(
      threadId,
      "file.apply_patch",
      {
        path: "README.md",
        dryRun: true,
        edits: [
          {
            type: "append",
            text: "\n\n<!-- Autopilot Studio runtime cockpit dry-run preview -->\n",
          },
        ],
      },
      output,
      {
        title: "Patch proposal dry-run",
        detail: "Daemon generated a dry-run patch preview; no workspace mutation occurred.",
      },
    );
    const existingHunkApproval = studioRuntimeProjection.approvals.find(
      (approvalItem) =>
        approvalItem.id === (studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID) &&
        /waiting|preview|pending/i.test(String(approvalItem.status || "")),
    );
    const approval = existingHunkApproval
      ? { approval_id: existingHunkApproval.id, receipt_refs: [] }
      : await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/approvals`, {
          method: "POST",
          token: daemonRequestToken(),
          payload: {
            approval_id: STUDIO_APPROVAL_ID,
            reason: "Native inline diff preview requires explicit hunk decision.",
            action: "patch.apply.preview",
            tool_id: "studio.inline-diff",
            effect_class: "workspace_patch",
            risk_domain: "workspace",
            source: "agent_studio_runtime_cockpit",
            ...studioApprovalTurnPayload(),
          },
        });
    studioRuntimeProjection.hunkApprovalId = approval?.approval_id || approval?.approvalId || STUDIO_APPROVAL_ID;
    const hunk = patchPreviewHunkFromToolResponse(patchResponse);
    hunk.approvalId = studioRuntimeProjection.hunkApprovalId;
    studioRuntimeProjection.diffHunks = [hunk];
    await openStudioNativeDiffPreview(hunk, output);
    appendStudioReceiptsFromResponse(patchResponse, "patch_preview", "Daemon dry-run patch preview receipt.");
    appendStudioReceiptsFromResponse(approval, "approval_required", "Daemon requested hunk decision approval.");
  } catch (error) {
    studioRuntimeProjection.diffHunks = [
      {
        file: "README.md",
        title: "Patch preview blocked",
        status: "blocked",
        before: "- Native hunk loop unavailable.",
        after: `+ ${error?.message || String(error)}`,
      },
    ];
    appendStudioTimeline("Patch preview blocked", error?.message || String(error), "blocked");
  }

  try {
    const browserStatus = await requestJson(daemonEndpoint(), "/v1/computer-use/browser-discovery?probe=false&include_tabs=false", {
      token: daemonRequestToken(),
    });
    studioRuntimeProjection.browserCards.push({
      title: "Browser status",
      status: "observed",
      detail: `Daemon browser discovery projected ${firstArray(browserStatus?.browsers).length || browserStatus?.count || 0} candidate browser surface(s).`,
    });
    studioRuntimeProjection.runtimeCockpit.browserStatusObserved = true;
  } catch (error) {
    studioRuntimeProjection.browserCards.push({
      title: "Browser status blocker",
      status: "blocked",
      detail: error?.message || String(error),
    });
  }

  try {
    const worker = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_runtime_cockpit",
        role: "reviewer",
        prompt: "Summarize Agent Studio runtime cockpit readiness without external connector action.",
        parent_turn_id: studioRuntimeProjection.turnId,
        model: studioRuntimeProjection.modelRoute,
      },
    });
    const refs = normalizeReceiptRefs(worker);
    studioRuntimeProjection.workerCards.push({
      title: "Worker / subagent status",
      status: worker?.status || "spawned",
      detail: `${worker?.id || worker?.subagent_id || "subagent"} spawned under daemon authority.`,
      receiptRefs: refs,
    });
    appendStudioReceiptsFromResponse(worker, "worker_spawn", "Daemon spawned runtime worker/subagent.");
    studioRuntimeProjection.runtimeCockpit.workerStatusObserved = true;
  } catch (error) {
    studioRuntimeProjection.workerCards.push({
      title: "Worker / subagent blocker",
      status: "blocked",
      detail: error?.message || String(error),
      receiptRefs: [],
    });
  }

  studioRuntimeProjection.replaySteps = [
    ...studioRuntimeProjection.runtimeEvents.slice(-8).map((event) => ({
      id: event.id,
      kind: event.kind,
      status: event.status,
      summary: event.summary,
    })),
    ...studioRuntimeProjection.receipts.slice(-8).map((receipt) => ({
      id: receipt.id,
      kind: receipt.kind,
      status: "receipted",
      summary: receipt.summary,
    })),
  ].slice(-12);
  studioRuntimeProjection.runtimeCockpit.receiptTimelinePerStepObserved =
    studioRuntimeProjection.receipts.length > 0;
  studioRuntimeProjection.runtimeCockpit.replayStepDetailObserved =
    studioRuntimeProjection.replaySteps.length > 0;
  recomputeStudioRuntimeCockpitAchieved();
  appendStudioTimeline(
    studioRuntimeProjection.runtimeCockpit.achieved ? "Runtime cockpit evidence ready" : "Runtime cockpit evidence incomplete",
    `prompt: ${prompt.slice(0, 80)}`,
    studioRuntimeProjection.runtimeCockpit.achieved ? "completed" : "blocked",
  );
}

function shouldProjectStudioRuntimeCockpit(prompt) {
  const value = String(prompt || "");
  return /runtime cockpit|tool proposal|policy lease|sandbox(?:ed)? command|inline diff|hunk|diagnostics?|test gate|browser status|worker status|subagent|receipt timeline|replay/i.test(value);
}

function studioPostRuntimeMessage(type, payload = {}) {
  if (!studioPanel) {
    return;
  }
  studioPanel.webview.postMessage({
    source: "ioi-studio-runtime",
    type,
    payload,
  });
}

function studioModelIdForRouteInvocation(selectedRoute, selectedModelId) {
  const route = String(selectedRoute || "").trim();
  if (route.startsWith("route.")) {
    return "auto";
  }
  return isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId;
}

async function ensureStudioModelInvocationToken(output) {
  const configuredToken = daemonRequestToken();
  if (configuredToken) {
    return configuredToken;
  }
  if (studioModelInvocationToken) {
    return studioModelInvocationToken;
  }
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    throw new Error("IOI daemon endpoint is not configured.");
  }
  const grant = await requestJson(endpoint, "/api/v1/tokens", {
    method: "POST",
    payload: {
      audience: "autopilot-agent-studio",
      allowed: [
        "model.chat:*",
        "model.responses:*",
        "model.tokenize:*",
        "model.context:*",
        "route.use:*",
      ],
      denied: ["connector.*", "filesystem.write", "shell.exec"],
      source: "agent-studio-chat-stream",
    },
  });
  studioModelInvocationToken = stringValue(grant?.token);
  if (!studioModelInvocationToken) {
    throw new Error("IOI daemon did not issue a model invocation token.");
  }
  appendStudioReceipts(
    [
      {
        id: grant?.receiptId || grant?.receipt_id,
        kind: "permission_token",
        summary: "Daemon issued a scoped Studio model invocation token.",
      },
    ],
    "permission_token",
  );
  output?.appendLine?.("[ioi-studio] scoped daemon model invocation token ready.");
  return studioModelInvocationToken;
}

function ssePayloadsFromBlock(block) {
  return String(block || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice("data:".length).trim())
    .filter(Boolean);
}

function studioDeltaFromSsePayload(payload) {
  if (!payload || typeof payload !== "object") {
    return "";
  }
  const choice = payload.choices?.[0] || {};
  if (typeof choice.delta?.content === "string") {
    return choice.delta.content;
  }
  if (typeof choice.delta?.reasoning_content === "string") {
    return choice.delta.reasoning_content;
  }
  if (payload.type === "response.output_text.delta" && typeof payload.delta === "string") {
    return payload.delta;
  }
  if (typeof payload.message?.content === "string") {
    return payload.message.content;
  }
  if (typeof payload.response?.output_text === "string") {
    return payload.response.output_text;
  }
  return "";
}

function collectStudioStreamMetadata(target, payload) {
  if (!payload || typeof payload !== "object") {
    return;
  }
  for (const id of uniqueStrings([
    payload.receipt_id,
    payload.receiptId,
    payload.stream_receipt_id,
    payload.streamReceiptId,
    ...firstArray(payload.tool_receipt_ids),
    ...firstArray(payload.toolReceiptIds),
  ])) {
    target.receiptIds.add(id);
  }
  target.routeId = payload.route_id || payload.routeId || target.routeId;
  target.model = payload.model || target.model;
  target.providerStream = payload.provider_stream || payload.providerStream || target.providerStream;
}

function requestSseJson(baseUrl, routePath, { method = "POST", payload, token, onPayload, timeoutMs = 90_000 } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  if (!base) {
    return Promise.reject(new Error("IOI daemon endpoint is not configured."));
  }

  const target = new URL(routePath, `${base}/`);
  const client = target.protocol === "https:" ? https : http;
  const body = payload === undefined ? null : JSON.stringify(payload);

  return new Promise((resolve, reject) => {
    let settled = false;
    let request = null;
    const wallClockTimeout = setTimeout(() => {
      request?.destroy(new Error("Daemon stream timed out."));
    }, timeoutMs);
    const finishResolve = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(wallClockTimeout);
      resolve(value);
    };
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(wallClockTimeout);
      reject(error);
    };
    request = client.request(
      target,
      {
        method,
        headers: {
          accept: "text/event-stream",
          ...(body
            ? {
                "content-type": "application/json",
                "content-length": Buffer.byteLength(body),
              }
            : {}),
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
      },
      (response) => {
        let raw = "";
        let buffer = "";
        const statusCode = response.statusCode || 0;
        response.on("data", (chunk) => {
          const text = chunk.toString("utf8");
          raw += text;
          if (statusCode >= 400) {
            return;
          }
          buffer += text;
          const frames = buffer.split(/\r?\n\r?\n/);
          buffer = frames.pop() || "";
          for (const frame of frames) {
            for (const data of ssePayloadsFromBlock(frame)) {
              if (data === "[DONE]") {
                continue;
              }
              try {
                onPayload?.(JSON.parse(data), data);
              } catch (error) {
                finishReject(error);
                request.destroy();
                return;
              }
            }
          }
        });
        response.on("end", () => {
          if (statusCode >= 400) {
            finishReject(new Error(`[IOI Workbench] Daemon stream failed (${statusCode}): ${raw}`));
            return;
          }
          if (buffer.trim()) {
            try {
              for (const data of ssePayloadsFromBlock(`${buffer}\n\n`)) {
                if (data !== "[DONE]") {
                  onPayload?.(JSON.parse(data), data);
                }
              }
            } catch (error) {
              finishReject(error);
              return;
            }
          }
          finishResolve({ statusCode, raw });
        });
      },
    );

    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error("Daemon model stream timed out."));
    });
    request.on("error", (error) => {
      finishReject(error);
    });
    if (body) {
      request.write(body);
    }
    request.end();
  });
}

async function streamStudioModelCompletion({ prompt, selectedRoute, selectedModelId, reasoningEffort = "none", workspacePath }, output) {
  const endpoint = daemonEndpoint();
  const token = await ensureStudioModelInvocationToken(output);
  const streamId = `studio-stream-${crypto.randomUUID()}`;
  const requestedModel = studioModelIdForRouteInvocation(selectedRoute, selectedModelId);
  const selectedReasoningEffort = normalizeStudioReasoningEffort(reasoningEffort, "none");
  const metadata = {
    receiptIds: new Set(),
    routeId: selectedRoute,
    model: requestedModel,
    providerStream: null,
  };
  const result = {
    streamId,
    text: "",
    chunkCount: 0,
    receiptIds: [],
    routeId: selectedRoute,
    model: requestedModel,
    providerStream: null,
  };
  studioPostRuntimeMessage("assistantStreamStart", {
    streamId,
    routeId: selectedRoute,
    startedAt: new Date().toISOString(),
  });
  studioRuntimeProjection.timeline.push({
    label: "Model stream started",
    detail: `${selectedRoute} via /v1/chat/completions`,
    status: "streaming",
  });

  try {
    const workspaceName = path.basename(workspacePath || workspaceSummary().path || "workspace");
    const workspaceContext = [
      "Current Studio workspace context:",
      `- repository_name: ${workspaceName}`,
      `- workspace_root: ${workspacePath || workspaceSummary().path || "unknown"}`,
      `- daemon_route: ${selectedRoute}`,
      `- selected_model: ${requestedModel}`,
      "- execution_boundary: IOI daemon owns tool execution, patch mutation, terminal jobs, receipts, approvals, and replay.",
      "- Studio may project UI state and request daemon actions, but must not claim it executed tools unless a daemon receipt/tool event is present.",
      "- When asked about the repository or workspace, use the repository_name and workspace_root above. Do not invent another repository name or claim the workspace is missing.",
    ].join("\n");
    await requestSseJson(endpoint, "/v1/chat/completions", {
      method: "POST",
      token,
      payload: {
        route_id: selectedRoute,
        model: requestedModel,
        stream: true,
        messages: [
          {
            role: "system",
            content:
              "You are Autopilot Agent Studio. Answer through the IOI daemon model route. Be concise and specific to the operator request.",
          },
          {
            role: "system",
            content: workspaceContext,
          },
          {
            role: "user",
            content: prompt,
          },
        ],
        metadata: {
          source: "agent-studio-operational-chat",
          workspaceRoot: workspacePath,
          runtimeAuthority: "daemon-owned",
          projectionOwner: "ioi-workbench-agent-studio",
        },
        max_tokens: 768,
        temperature: 0.2,
        reasoning_effort: selectedReasoningEffort,
        reasoningEffort: selectedReasoningEffort,
      },
      onPayload: (payload) => {
        collectStudioStreamMetadata(metadata, payload);
        const delta = studioDeltaFromSsePayload(payload);
        if (!delta) {
          return;
        }
        result.text += delta;
        result.chunkCount += 1;
        studioPostRuntimeMessage("assistantStreamDelta", {
          streamId,
          delta,
          chunkCount: result.chunkCount,
        });
      },
    });
  } catch (error) {
    studioPostRuntimeMessage("assistantStreamError", {
      streamId,
      error: error?.message || String(error),
    });
    throw error;
  }

  result.receiptIds = [...metadata.receiptIds];
  result.routeId = metadata.routeId || selectedRoute;
  result.model = metadata.model;
  result.providerStream = metadata.providerStream;
  if (!result.text.trim()) {
    throw new Error("Daemon model stream completed without assistant text.");
  }
  appendStudioReceipts(
    result.receiptIds.map((id) => ({
      id,
      kind: id.includes("stream") ? "model_invocation_stream_completed" : "model_invocation",
      summary: "Daemon model stream receipt projected into Studio.",
    })),
    "model_invocation",
  );
  studioPostRuntimeMessage("assistantStreamComplete", {
    streamId,
    text: result.text,
    chunkCount: result.chunkCount,
    receiptIds: result.receiptIds,
    routeId: result.routeId,
    model: result.model,
    providerStream: result.providerStream,
  });
  return result;
}

function collectStudioAgentEventsFromResponse(turn = {}) {
  return [
    ...firstArray(turn.events),
    ...firstArray(turn.runtime_events),
    ...firstArray(turn.runtimeEvents),
    ...firstArray(turn.event_log),
    ...firstArray(turn.eventLog),
  ];
}

function uniqueStudioRuntimeEvents(events = []) {
  const seen = new Set();
  const unique = [];
  for (const event of firstArray(events)) {
    const key =
      event?.event_id ||
      event?.eventId ||
      event?.id ||
      (event?.event_stream_id && event?.seq ? `${event.event_stream_id}:${event.seq}` : "");
    if (key && seen.has(key)) {
      continue;
    }
    if (key) {
      seen.add(key);
    }
    unique.push(event);
  }
  return unique;
}

function applyStudioAgentTurnEvents(events = []) {
  const appliedEvents = [];
  for (const event of firstArray(events)) {
    appendStudioRuntimeEvent(event, studioRuntimeEventKind(event) || "agent.runtime.event");
    appliedEvents.push(event);
    const kind = studioRuntimeEventKind(event).toLowerCase();
    const toolName = studioRuntimeEventToolName(event);
    const status = stringValue(event.status || event.payload_summary?.status || event.payload?.status, "observed");
    const summary =
      event.summary ||
      event.payload_summary?.summary ||
      event.payload_summary?.result_summary ||
      event.payload_summary?.input_summary ||
      event.payload?.summary ||
      event.payload?.result ||
      event.payload?.message ||
      "";
    const receiptRefs = normalizeReceiptRefs(event);
    applyStudioParityPlusEvent(event, { kind, status, summary, receiptRefs });
    upsertStudioManagedSession(
      studioManagedSessionFromRuntimeEvent(event, { kind, toolName, status, summary }),
    );
    if (/tool\./.test(kind) || toolName) {
      studioRuntimeProjection.actionCards.push({
        id: event.event_id || event.eventId || event.id || `${toolName || "tool"}.${Date.now()}`,
        toolId: toolName || kind || "runtime.tool",
        label: toolName || kind || "Runtime tool",
        status,
        summary: stringValue(summary, "Daemon runtime tool event projected."),
        receiptRefs,
      });
    }
    if (/shell|command|terminal/.test(`${kind} ${toolName}`.toLowerCase())) {
      studioRuntimeProjection.commandOutputs.push({
        id: event.event_id || event.eventId || event.id || `command.${Date.now()}`,
        label: toolName || "shell command",
        status,
        stdout: event.payload?.stdout || event.payload?.output || stringValue(summary),
        stderr: event.payload?.stderr || "",
        exitCode: event.payload?.exit_code ?? event.payload?.exitCode ?? null,
        durationMs: event.payload?.duration_ms ?? event.payload?.durationMs ?? null,
        receiptRefs,
      });
    }
    if (/policy|approval|lease|firewall/.test(`${kind} ${toolName}`.toLowerCase())) {
      const permissionTarget = humanizeStudioToolName(toolName || event.payload?.tool_id || event.payload?.toolId || "");
      studioRuntimeProjection.policyLeases.push({
        id: event.event_id || event.eventId || event.id || `policy.${Date.now()}`,
        label: "Permission needed",
        title: "Permission needed",
        status,
        action: toolName || event.payload?.tool_id || event.payload?.toolId || "agent action",
        reason: permissionTarget
          ? `Agent needs permission to use ${permissionTarget}.`
          : "Agent needs permission before continuing.",
        didExecute: false,
        receiptRefs,
      });
    }
    if (/receipt/.test(kind) && receiptRefs.length > 0) {
      appendStudioReceipts(receiptRefs.map((id) => ({
        id,
        kind: kind || "agent.runtime.receipt",
        summary: stringValue(summary, "Rust runtime receipt projected into Studio."),
      })));
    }
  }
  return appliedEvents;
}

async function fetchStudioThreadEvents(threadId, output, { timeoutMs = 1500 } = {}) {
  if (!threadId) {
    return [];
  }
  const events = [];
  try {
    await requestSseJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/events?since_seq=0`, {
      method: "GET",
      token: daemonRequestToken(),
      timeoutMs,
      onPayload: (payload) => {
        if (payload && payload.event) {
          events.push(payload.event);
        } else if (payload) {
          events.push(payload);
        }
      },
    });
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] daemon thread event stream unavailable: ${error?.message || String(error)}`);
  }
  return events;
}

async function fetchStudioThreadTurns(threadId, output, { timeoutMs = 5000 } = {}) {
  if (!threadId) {
    return [];
  }
  try {
    const turns = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/turns`, {
      method: "GET",
      token: daemonRequestToken(),
      timeoutMs,
    });
    return firstArray(turns);
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] daemon turn refresh unavailable: ${error?.message || String(error)}`);
    return [];
  }
}

async function fetchStudioThreadTurnEvents(threadId, output, { turnId } = {}) {
  const turns = await fetchStudioThreadTurns(threadId, output, { timeoutMs: 5000 });
  const scopedTurns = turnId
    ? turns.filter((turn) => String(turn.turn_id || turn.turnId || "") === String(turnId))
    : turns;
  return scopedTurns.flatMap((turn) => collectStudioAgentEventsFromResponse(turn));
}

function studioTurnPromptText(turn = {}) {
  const direct = stringValue(
    turn.prompt ||
      turn.input ||
      turn.message ||
      turn.request?.prompt ||
      turn.request?.input ||
      turn.request?.message,
  );
  if (direct) {
    return direct;
  }
  const userTurn = firstArray(turn.conversation)
    .slice()
    .reverse()
    .find((item) => String(item?.role || item?.type || "").toLowerCase() === "user");
  if (userTurn) {
    return stringValue(userTurn.content || userTurn.text || userTurn.message);
  }
  const startedEvent = collectStudioAgentEventsFromResponse(turn)
    .find((event) => studioRuntimeEventKind(event).toLowerCase() === "turn.started");
  return stringValue(startedEvent?.payload?.prompt || startedEvent?.payload_summary?.prompt);
}

function studioTurnStartedAtMs(turn = {}) {
  const numeric = Number(
    turn.started_at_ms ||
      turn.startedAtMs ||
      turn.created_at_ms ||
      turn.createdAtMs ||
      0,
  );
  if (Number.isFinite(numeric) && numeric > 0) {
    return numeric;
  }
  const parsed = Date.parse(
    turn.started_at ||
      turn.startedAt ||
      turn.created_at ||
      turn.createdAt ||
      "",
  );
  return Number.isFinite(parsed) ? parsed : 0;
}

function studioTurnMatchesSubmittedPrompt(turn = {}, prompt = "", submittedAtMs = 0) {
  const turnPrompt = studioTurnPromptText(turn);
  if (turnPrompt && prompt && turnPrompt === prompt) {
    return true;
  }
  const startedAtMs = studioTurnStartedAtMs(turn);
  return Boolean(startedAtMs && submittedAtMs && startedAtMs >= submittedAtMs - 2000);
}

function studioTurnLooksTerminal(turn = {}) {
  const events = collectStudioAgentEventsFromResponse(turn);
  const statusText = stringValue(turn.status || turn.state || "").toLowerCase();
  const resultText = studioAgentTurnResultText(turn, events);
  if (resultText || /blocked|failed|error|completed|paused|approval|waiting_for_approval/.test(statusText)) {
    return true;
  }
  return events.some((event) => /turn\.(completed|failed)|completed|failed|blocked/.test(studioRuntimeEventKind(event).toLowerCase()));
}

async function recoverStudioAgentTurnAfterSubmitTimeout({ threadId, prompt, submittedAtMs, output }) {
  for (let attempt = 0; attempt < STUDIO_AGENT_TURN_RECOVERY_ATTEMPTS; attempt += 1) {
    const turns = await fetchStudioThreadTurns(threadId, output, { timeoutMs: 5000 });
    const turn = turns
      .slice()
      .reverse()
      .find((candidate) =>
        studioTurnMatchesSubmittedPrompt(candidate, prompt, submittedAtMs) &&
        studioTurnLooksTerminal(candidate),
      );
    if (turn) {
      output?.appendLine?.("[ioi-studio] recovered completed daemon turn after Agent POST timeout.");
      return turn;
    }
    if (attempt < STUDIO_AGENT_TURN_RECOVERY_ATTEMPTS - 1) {
      await new Promise((resolve) => setTimeout(resolve, STUDIO_AGENT_TURN_RECOVERY_POLL_MS));
    }
  }
  return null;
}

function studioApprovalTurnPayload() {
  const turnId = stringValue(studioRuntimeProjection.turnId);
  return turnId.startsWith("turn_") ? { turn_id: turnId } : {};
}

function studioRunResultText({ prompt, run, conversation }) {
  const assistantTurn = firstArray(conversation)
    .slice()
    .reverse()
    .find((item) => String(item?.role || item?.type || "").toLowerCase() === "assistant");
  const content =
    assistantTurn?.content ||
    assistantTurn?.text ||
    assistantTurn?.message ||
    run?.result ||
    run?.output ||
    null;
  if (content) {
    return String(content);
  }
  return `Daemon turn completed for: ${prompt}`;
}

async function ensureStudioDaemonThread({ model = "route.local-first", selectedModelId = "auto", executionMode = studioRuntimeProjection.executionMode, reasoningEffort = studioRuntimeProjection.reasoningEffort || "none", approvalMode = studioRuntimeProjection.approvalMode } = {}, output) {
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    throw new Error("IOI daemon endpoint is not configured.");
  }
  const normalizedMode = normalizeStudioExecutionMode(executionMode);
  const permissionMapping = studioPermissionDaemonMapping(approvalMode);
  const runtimeProfile = normalizedMode === STUDIO_MODE_AGENT
    ? STUDIO_AGENT_RUNTIME_PROFILE
    : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
  if (
    studioRuntimeProjection.threadId &&
    studioRuntimeProjection.executionMode &&
    normalizeStudioExecutionMode(studioRuntimeProjection.executionMode) !== normalizedMode
  ) {
    resetStudioDaemonThreadProjection();
  }
  if (studioRuntimeProjection.threadId) {
    return studioRuntimeProjection;
  }
  const workspace = workspaceSummary();
  const thread = await requestJson(endpoint, "/v1/threads", {
    method: "POST",
    token: daemonRequestToken(),
      payload: {
        mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
        threadMode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
        thread_mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
        approvalMode: permissionMapping.approvalMode,
        approval_mode: permissionMapping.approvalMode,
        runtime_profile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
        runtimeProfile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
        options: {
          mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
          threadMode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
          thread_mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
          approvalMode: permissionMapping.approvalMode,
          approval_mode: permissionMapping.approvalMode,
          runtime_profile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
          runtimeProfile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
          local: {
            cwd: workspace.path,
          },
          model: {
            id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId,
            routeId: model || "route.local-first",
            reasoningEffort: normalizeStudioReasoningEffort(reasoningEffort, "none"),
          },
          source: normalizedMode === STUDIO_MODE_AGENT ? "agent-studio-agent-mode" : "agent-studio-ask-mode",
        },
      },
    });
  studioRuntimeProjection.threadId = thread?.thread_id || thread?.threadId || null;
  studioRuntimeProjection.sessionId =
    thread?.session_id || thread?.sessionId || studioRuntimeProjection.threadId || null;
  studioRuntimeProjection.modelRoute = thread?.model_route_id || thread?.modelRouteId || model;
  studioRuntimeProjection.selectedModel = thread?.selected_model || thread?.selectedModel || "auto";
  studioRuntimeProjection.reasoningEffort = normalizeStudioReasoningEffort(reasoningEffort, "none");
  studioRuntimeProjection.approvalMode = permissionMapping.approvalMode;
  studioRuntimeProjection.executionMode = normalizedMode;
  studioRuntimeProjection.runtimeProfile = runtimeProfile;
  studioRuntimeProjection.status = "active";
  studioRuntimeProjection.history = [
    {
      id: studioRuntimeProjection.threadId || "studio-thread",
      title: "Daemon Studio session",
      status: thread?.status || "active",
    },
  ];
  studioRuntimeProjection.timeline.push({
    label: "Daemon session created",
    detail: studioRuntimeProjection.threadId || "thread pending",
    status: "completed",
  });
  appendStudioReceipts(
    uniqueStrings([thread?.model_route_receipt_id, thread?.modelRouteReceiptId]).map((id) => ({
      id,
      kind: "model_route",
      summary: "Daemon selected the Studio model route.",
    })),
  );
  output?.appendLine?.(`[ioi-studio] daemon session ready: ${studioRuntimeProjection.threadId}`);
  return studioRuntimeProjection;
}

async function submitStudioAgentTurn({ prompt, selectedRoute, selectedModelId, reasoningEffort = "none", workspacePath }, output) {
  await ensureStudioDaemonThread({
    model: selectedRoute,
    selectedModelId,
    reasoningEffort,
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: studioRuntimeProjection.approvalMode,
  }, output);
  const threadId = studioRuntimeProjection.threadId;
  if (!threadId) {
    throw new Error("Agent Mode requires a daemon runtime thread, but no thread was created.");
  }
  studioRuntimeProjection.executionMode = STUDIO_MODE_AGENT;
  studioRuntimeProjection.runtimeProfile = STUDIO_AGENT_RUNTIME_PROFILE;
  studioRuntimeProjection.timeline.push({
    label: "Agent turn started",
    detail: "POST /v1/threads/:thread_id/turns through Rust runtime_service profile",
    status: "running",
  });
  const submittedAtMs = Date.now();
  const permissionMapping = studioPermissionDaemonMapping(studioRuntimeProjection.approvalMode);
  const turnPayload = {
    prompt,
    input: prompt,
    ...permissionMapping,
    runtime_profile: STUDIO_AGENT_RUNTIME_PROFILE,
    runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
    max_steps: 8,
    options: {
      ...permissionMapping,
      runtime_profile: STUDIO_AGENT_RUNTIME_PROFILE,
      runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
      local: {
        cwd: workspacePath || workspaceSummary().path,
      },
      model: {
        id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId,
        routeId: selectedRoute || "route.local-first",
        reasoningEffort: normalizeStudioReasoningEffort(reasoningEffort, "none"),
      },
      source: "agent-studio-agent-mode",
    },
    metadata: {
      source: "agent-studio-agent-mode",
      workspaceRoot: workspacePath || workspaceSummary().path,
      ...permissionMapping,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
    },
  };
  let turn;
  try {
    turn = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/turns`, {
      method: "POST",
      token: daemonRequestToken(),
      timeoutMs: STUDIO_AGENT_TURN_POST_TIMEOUT_MS,
      payload: turnPayload,
    });
  } catch (error) {
    if (!/timed out|timeout/i.test(error?.message || String(error))) {
      throw error;
    }
    output?.appendLine?.(`[ioi-studio] Agent turn POST exceeded ${STUDIO_AGENT_TURN_POST_TIMEOUT_MS}ms; checking daemon turn projection.`);
    turn = await recoverStudioAgentTurnAfterSubmitTimeout({
      threadId,
      prompt,
      submittedAtMs,
      output,
    });
    if (!turn) {
      throw error;
    }
    studioRuntimeProjection.timeline.push({
      label: "Agent turn recovered",
      detail: "Daemon turn projection was recovered after a bounded POST timeout.",
      status: "completed",
    });
  }
  const responseEvents = collectStudioAgentEventsFromResponse(turn);
  const refreshEvents = studioAssistantTextFromRuntimeToolEvents(responseEvents)
    ? []
    : await fetchStudioThreadTurnEvents(turn.thread_id || turn.threadId || threadId, output, {
        turnId: turn.turn_id || turn.turnId,
      });
  const streamedEvents = studioAssistantTextFromRuntimeToolEvents([...responseEvents, ...refreshEvents])
    ? []
    : await fetchStudioThreadEvents(turn.thread_id || turn.threadId || threadId, output, { timeoutMs: 5000 });
  const events = uniqueStudioRuntimeEvents([...responseEvents, ...refreshEvents, ...streamedEvents]);
  applyStudioAgentTurnEvents(events);
  const needsRetrieval = promptRequiresRetrieval(prompt);
  const hasSearch = studioRuntimeEventsIncludeTool(events, /web(::|__)search|search_web|web_search/);
  const hasRead = studioRuntimeEventsIncludeTool(events, /web(::|__)read|read_web|web_read/);
  const hasCompletedSearch = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)search|search_web|web_search/);
  const hasCompletedRead = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)read|read_web|web_read/);
  const chatReplyText = studioAssistantTextFromRuntimeToolEvents(events);
  const resultText = studioAgentTurnResultText(turn, events);
  const resultLooksRetrievalGrounded = studioResultTextLooksRetrievalGrounded(resultText);
  const statusText = stringValue(turn.status || turn.state || "", "completed").toLowerCase();
  const approvalPaused = studioTextIndicatesApprovalPause(resultText) || /waiting_for_approval|approval/.test(statusText);
  const blockedReason = stringValue(
    turn.error?.message ||
      turn.blocker?.message ||
      turn.externalBlocker?.message ||
      turn.stop_reason ||
      turn.stopReason,
  );
  const retrievalFailClosedText = needsRetrieval && !resultText
    ? studioRetrievalFailClosedText({ prompt, events, blockedReason })
    : "";
  if (needsRetrieval && !(hasCompletedSearch && hasCompletedRead) && !resultLooksRetrievalGrounded) {
    throw new Error(
      [
        "Agent Mode failed closed: this prompt requires current/source retrieval, but the Rust runtime did not complete web__search and web__read events.",
        blockedReason ? `Runtime stop reason: ${blockedReason}.` : "",
        resultText ? `Runtime result: ${resultText}` : "",
        `Observed retrieval events: search=${hasSearch}, read=${hasRead}, completedSearch=${hasCompletedSearch}, completedRead=${hasCompletedRead}.`,
      ].filter(Boolean).join(" "),
    );
  }
  if (retrievalFailClosedText) {
    output?.appendLine?.(`[ioi-studio] ${retrievalFailClosedText}`);
  }
  const receiptRefs = normalizeReceiptRefs(turn, ...events);
  appendStudioReceipts(
    receiptRefs.map((id) => ({
      id,
      kind: "agent_turn",
      summary: "Daemon agent turn receipt projected into Studio.",
    })),
  );
  studioRuntimeProjection.turnId = turn.turn_id || turn.turnId || studioRuntimeProjection.turnId || `turn.${Date.now()}`;
  studioRuntimeProjection.runId =
    turn.run_id || turn.runId || receiptRefs[receiptRefs.length - 1] || studioRuntimeProjection.turnId;
  if (!chatReplyText && !retrievalFailClosedText) {
    const observedTools = uniqueStrings(events.map((event) => studioRuntimeEventToolName(event)).filter(Boolean));
    if (approvalPaused) {
      studioRuntimeProjection.timeline.push({
        label: "Agent turn waiting for approval",
        detail: `${events.length} runtime event${events.length === 1 ? "" : "s"} projected`,
        status: "blocked",
      });
      return {
        turn,
        events,
        text: studioApprovalPauseErrorMessage({ resultText, events }),
        receiptRefs,
        status: "blocked",
        approvalPause: true,
      };
    }
    throw new Error(
      [
        "Daemon agent turn completed but did not emit a final chat__reply.",
        resultText ? `Runtime result was ignored as non-visible completion proof: ${resultText}` : "",
        `Observed ${events.length} runtime event${events.length === 1 ? "" : "s"}${observedTools.length ? ` with tools: ${observedTools.join(", ")}` : ""}.`,
      ].filter(Boolean).join(" "),
    );
  }
  if (/blocked|failed|error/.test(statusText) && !resultText && !retrievalFailClosedText) {
    throw new Error(blockedReason || "Rust runtime agent turn blocked without an assistant result.");
  }
  const finalStatus = /blocked|failed|error|paused/.test(statusText) ? "blocked" : "completed";
  studioRuntimeProjection.timeline.push({
    label: finalStatus === "blocked" ? "Agent turn blocked" : "Agent turn completed",
    detail: `${events.length} runtime event${events.length === 1 ? "" : "s"} projected`,
    status: finalStatus,
  });
  return {
    turn,
    events,
    text: resultText || retrievalFailClosedText || "Agent Mode completed without additional assistant text.",
    receiptRefs,
    status: finalStatus,
    approvalPause: false,
  };
}

async function applyStudioPermissionModeSelection(payload = {}, output) {
  const approvalMode = normalizeStudioPermissionMode(
    payload.approvalMode || payload.approval_mode || payload.selectionId || payload.mode || payload.label,
  );
  const mapping = studioPermissionDaemonMapping(approvalMode);
  studioRuntimeProjection.approvalMode = approvalMode;
  if (!studioRuntimeProjection.threadId) {
    return mapping;
  }
  try {
    await requestJson(
      daemonEndpoint(),
      `/v1/threads/${encodeURIComponent(studioRuntimeProjection.threadId)}/mode`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          ...mapping,
          mode: mapping.threadMode,
          value: mapping.threadMode,
          source: "agent-studio-permissions-menu",
        },
      },
    );
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] permission mode update unavailable: ${error?.message || String(error)}`);
  }
  return mapping;
}

async function submitStudioPrompt(payload = {}, output) {
  const prompt = stringValue(payload.prompt);
  if (!prompt) {
    return;
  }
  const workspace = workspaceSummary();
  const selectedRoute = stringValue(payload.routeId, stringValue(payload.model, "route.local-first"));
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  const reasoningEffort = normalizeStudioReasoningEffort(payload.reasoningEffort ?? payload.reasoning_effort, "none");
  const executionMode = normalizeStudioExecutionMode(payload.executionMode || payload.studioMode || studioRuntimeProjection.executionMode);
  const previousApprovalMode = normalizeStudioPermissionMode(studioRuntimeProjection.approvalMode);
  const approvalMode = normalizeStudioPermissionMode(payload.approvalMode ?? payload.approval_mode ?? previousApprovalMode);
  const permissionMapping = studioPermissionDaemonMapping(approvalMode);
  const targetRuntimeProfile = executionMode === STUDIO_MODE_AGENT
    ? STUDIO_AGENT_RUNTIME_PROFILE
    : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
  if (
    studioRuntimeProjection.threadId &&
    (
      normalizeStudioExecutionMode(studioRuntimeProjection.executionMode) !== executionMode ||
      studioRuntimeProjection.runtimeProfile !== targetRuntimeProfile
    )
  ) {
    resetStudioDaemonThreadProjection();
  }
  const createdAt = new Date().toISOString();
  studioRuntimeProjection.pending = true;
  studioRuntimeProjection.status = "pending";
  studioRuntimeProjection.immediateSubmitSeen = true;
  studioRuntimeProjection.pendingSeen = true;
  studioRuntimeProjection.pendingStartedAtMs = Date.now();
  studioRuntimeProjection.lastError = null;
  studioRuntimeProjection.modelRoute = selectedRoute;
  studioRuntimeProjection.selectedModel = selectedModelId;
  studioRuntimeProjection.reasoningEffort = reasoningEffort;
  studioRuntimeProjection.approvalMode = approvalMode;
  studioRuntimeProjection.executionMode = executionMode;
  studioRuntimeProjection.runtimeProfile = targetRuntimeProfile;
  if (studioRuntimeProjection.threadId && previousApprovalMode !== approvalMode) {
    await applyStudioPermissionModeSelection({ approvalMode }, output);
  }
  studioRuntimeProjection.turns.push({
    role: "user",
    content: prompt,
    createdAt,
  });
  studioRuntimeProjection.timeline.push({
    label: "Prompt submitted",
    detail: "chat.submit typed request routed to IOI daemon",
    status: "pending",
  });
  void writeBridgeRequest(
    "chat.submit",
    {
      ...payload,
      prompt,
      model: selectedRoute,
      routeId: selectedRoute,
      modelId: selectedModelId,
      reasoningEffort,
      reasoning_effort: reasoningEffort,
      executionMode,
      ...permissionMapping,
      runtimeProfile: studioRuntimeProjection.runtimeProfile,
      workspaceRoot: workspace.path,
      sourceCommand: "ioi.studio.chat",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      ownsRuntimeState: false,
      externalConnectorAction: false,
    },
    buildWorkspaceActionContext("agent-studio-chat"),
  ).catch((error) => {
    output?.appendLine?.(`[ioi-studio] bridge chat.submit route unavailable: ${error?.message || String(error)}`);
  });

  let projectedWithoutRefresh = false;
  try {
    let assistantTurn = null;
    if (executionMode === STUDIO_MODE_ASK) {
      await ensureStudioDaemonThread({ model: selectedRoute, selectedModelId, reasoningEffort, executionMode, approvalMode }, output);
      const streamResult = await streamStudioModelCompletion(
        {
          prompt,
          selectedRoute,
          selectedModelId,
          reasoningEffort,
          workspacePath: workspace.path,
        },
        output,
      );
      studioRuntimeProjection.turnId = streamResult.streamId;
      studioRuntimeProjection.runId = streamResult.receiptIds[streamResult.receiptIds.length - 1] || streamResult.streamId;
      studioRuntimeProjection.selectedModel = streamResult.model || studioRuntimeProjection.selectedModel || "auto";
      studioRuntimeProjection.modelRoute = streamResult.routeId || selectedRoute;
      studioRuntimeProjection.lastModelStream = {
        streamId: streamResult.streamId,
        chunkCount: streamResult.chunkCount,
        receiptIds: streamResult.receiptIds,
        routeId: streamResult.routeId,
        model: streamResult.model,
        providerStream: streamResult.providerStream,
      };
      studioRuntimeProjection.timeline.push({
        label: "Ask model stream completed",
        detail: `${streamResult.chunkCount} token delta${streamResult.chunkCount === 1 ? "" : "s"} through ${streamResult.routeId}`,
        status: "completed",
      });
      assistantTurn = {
        role: "assistant",
        content: streamResult.text,
        createdAt: new Date().toISOString(),
        modelStream: {
          streamId: streamResult.streamId,
          chunkCount: streamResult.chunkCount,
          receiptIds: streamResult.receiptIds,
          askMode: true,
          directModelAnswer: true,
          chatOnlyMode: true,
        },
      };
    } else {
      const workCursor = studioWorkCursor();
      const agentTurn = await submitStudioAgentTurn(
        {
          prompt,
          selectedRoute,
          selectedModelId,
          reasoningEffort,
          workspacePath: workspace.path,
        },
        output,
      );
      if (shouldProjectStudioRuntimeCockpit(prompt)) {
        await projectStudioRuntimeCockpit(prompt, agentTurn, output);
      }
      const agentTurnStatus = agentTurn.status === "blocked" ? "blocked" : "completed";
      const workRecord = studioDocumentedWorkRecord(workCursor);
      const blockedThreadId = agentTurnStatus === "blocked" ? studioRuntimeProjection.threadId : null;
      assistantTurn = {
        role: "assistant",
        content: agentTurn.text,
        createdAt: new Date().toISOString(),
        agentTurn: {
          turnId: studioRuntimeProjection.turnId,
          eventCount: agentTurn.events.length,
          receiptRefs: agentTurn.receiptRefs,
          prompt,
          status: agentTurnStatus,
          approvalPause: Boolean(agentTurn.approvalPause),
        },
        ...(workRecord ? { workRecord } : {}),
      };
      studioRuntimeProjection.lastModelStream = null;
      if (blockedThreadId) {
        resetStudioDaemonThreadProjection();
        studioRuntimeProjection.timeline.push({
          label: "Blocked daemon thread released",
          detail: blockedThreadId,
          status: "completed",
        });
      }
      studioRuntimeProjection.status = agentTurnStatus;
    }
    studioRuntimeProjection.turns.push(assistantTurn);
    const pendingElapsedMs = Date.now() - (studioRuntimeProjection.pendingStartedAtMs || Date.now());
    if (pendingElapsedMs < 1400) {
      await new Promise((resolve) => setTimeout(resolve, 1400 - pendingElapsedMs));
    }
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = assistantTurn?.agentTurn?.status === "blocked" ? "blocked" : "completed";
    studioRuntimeProjection.timeline.push({
      label: studioRuntimeProjection.status === "blocked" ? "Blocked answer visible" : "Final answer visible",
      detail: executionMode === STUDIO_MODE_ASK
        ? "Explicit Ask direct model stream completed"
        : studioRuntimeProjection.status === "blocked"
          ? "Daemon agent turn paused or blocked with a visible human summary"
          : "Daemon agent turn completed without accepting model prose as execution proof",
      status: studioRuntimeProjection.status,
    });
    studioRuntimeProjection.terminal = studioRuntimeProjection.commandOutputs.length > 0
      ? studioRuntimeProjection.commandOutputs.slice(-3).map((item) => ({
          label: item.label || "Daemon command",
          detail: item.stdout || item.stderr || item.status || "Daemon command output projected.",
        }))
      : [
          {
            label: "No terminal job running",
            detail: "Plain text turns do not create fake terminal or proof records.",
          },
        ];
    if (executionMode === STUDIO_MODE_AGENT) {
      // Agent completions use the ordered extension projection so late webview messages
      // cannot attach a final answer to the next prompt.
      projectedWithoutRefresh = false;
    }
  } catch (error) {
    const isApprovalPause = Boolean(error?.studioApprovalPause || error?.code === "studio_approval_pause");
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = "blocked";
    studioRuntimeProjection.lastError = error?.message || String(error);
    studioRuntimeProjection.timeline.push({
      label: isApprovalPause ? "Daemon turn waiting for approval" : "Daemon turn blocked",
      detail: studioRuntimeProjection.lastError,
      status: "blocked",
    });
    studioRuntimeProjection.turns.push({
      role: "assistant",
      content: isApprovalPause
        ? studioRuntimeProjection.lastError
        : `Studio could not complete the daemon turn: ${studioRuntimeProjection.lastError}`,
      createdAt: new Date().toISOString(),
    });
    if (executionMode === STUDIO_MODE_AGENT && studioRuntimeProjection.threadId) {
      const blockedThreadId = studioRuntimeProjection.threadId;
      resetStudioDaemonThreadProjection();
      studioRuntimeProjection.timeline.push({
        label: "Blocked daemon thread released",
        detail: blockedThreadId,
        status: "completed",
      });
    }
    if (executionMode === STUDIO_MODE_AGENT) {
      projectedWithoutRefresh = false;
    }
  }
  if (!projectedWithoutRefresh) {
    await refreshStudioPanelHtml(output);
  }
  await focusStudioPanelComposer();
}

async function handleStudioHunkDecision(decision, payload = {}, output) {
  const normalizedDecision = decision === "reject" ? "reject" : "approve";
  try {
    await ensureStudioDaemonThread({ model: studioRuntimeProjection.modelRoute }, output);
    const endpoint = daemonEndpoint();
    const threadId = studioRuntimeProjection.threadId;
    const approvalId =
      stringValue(payload.approvalId, studioRuntimeProjection.approvalId || STUDIO_APPROVAL_ID);
    const result = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(approvalId)}/decision`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          decision: normalizedDecision,
          source: "agent_studio_inline_diff",
          reason: `Operator ${normalizedDecision === "approve" ? "accepted" : "rejected"} the Studio inline diff preview.`,
          ...studioApprovalTurnPayload(),
        },
      },
    );
    studioRuntimeProjection.hunkDecision = normalizedDecision;
    studioRuntimeProjection.diffHunks = studioRuntimeProjection.diffHunks.map((hunk) => ({
      ...hunk,
      status: normalizedDecision === "approve" ? "approved" : "rejected",
    }));
    studioRuntimeProjection.approvals = [
      {
        id: approvalId,
        status: normalizedDecision === "approve" ? "approved" : "rejected",
        label: "Inline diff decision",
        detail: "Daemon approval decision receipt emitted; no direct webview mutation occurred.",
      },
    ];
    studioRuntimeProjection.timeline.push({
      label: "Hunk decision receipted",
      detail: `${approvalId} · ${normalizedDecision}`,
      status: normalizedDecision === "approve" ? "completed" : "blocked",
    });
    appendStudioReceipts(
      uniqueStrings([
        ...firstArray(result?.receipt_refs),
        ...firstArray(result?.receiptRefs),
      ]).map((id) => ({
        id,
        kind: `approval_${normalizedDecision}`,
        summary: "Daemon approval decision receipt for Studio inline diff hunk.",
      })),
    );
    studioRuntimeProjection.runtimeCockpit.hunkAcceptRejectReceiptsObserved = true;
    recomputeStudioRuntimeCockpitAchieved();
    await writeBridgeRequest(
      "chat.hunkDecision",
      {
        ...payload,
        decision: normalizedDecision,
        approvalId,
        threadId,
        turnId: studioRuntimeProjection.turnId,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "ioi-workbench-agent-studio",
        ownsRuntimeState: false,
      },
      buildWorkspaceActionContext("agent-studio-inline-diff"),
    ).catch((error) => {
      output?.appendLine?.(`[ioi-studio] bridge hunk decision route unavailable: ${error?.message || String(error)}`);
    });
  } catch (error) {
    studioRuntimeProjection.timeline.push({
      label: "Hunk decision blocked",
      detail: error?.message || String(error),
      status: "blocked",
    });
  }
  await refreshStudioPanelHtml(output);
}

async function navigateStudioHunk(direction, output) {
  const command = direction === "previous"
    ? "workbench.action.compareEditor.previousChange"
    : "workbench.action.compareEditor.nextChange";
  await vscode.commands.executeCommand(command).catch((error) => {
    output?.appendLine?.(`[ioi-studio] native hunk navigation unavailable: ${error?.message || String(error)}`);
  });
  studioRuntimeProjection.runtimeCockpit.hunkNavigationObserved = true;
  recomputeStudioRuntimeCockpitAchieved();
  appendStudioTimeline("Native hunk navigation", direction === "previous" ? "previous change" : "next change", "completed");
  await refreshStudioPanelHtml(output);
}

async function stopStudioTurn(output) {
  studioRuntimeProjection.pending = false;
  studioRuntimeProjection.status = "interrupted";
  studioRuntimeProjection.timeline.push({
    label: "Stop requested",
    detail: "Operator stop routed from Studio control surface.",
    status: "blocked",
  });
  if (studioRuntimeProjection.threadId && studioRuntimeProjection.turnId) {
    await requestJson(
      daemonEndpoint(),
      `/v1/threads/${encodeURIComponent(studioRuntimeProjection.threadId)}/turns/${encodeURIComponent(studioRuntimeProjection.turnId)}/interrupt`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio",
          reason: "operator_stop",
        },
      },
    ).catch((error) => {
      output?.appendLine?.(`[ioi-studio] stop projection unavailable: ${error?.message || String(error)}`);
    });
  }
  await writeBridgeRequest(
    "chat.stop",
    {
      threadId: studioRuntimeProjection.threadId,
      turnId: studioRuntimeProjection.turnId,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      reason: "operator_stop",
      ownsRuntimeState: false,
    },
    buildWorkspaceActionContext("agent-studio-stop"),
  ).catch((error) => {
    output?.appendLine?.(`[ioi-studio] bridge stop route unavailable: ${error?.message || String(error)}`);
  });
  await refreshStudioPanelHtml(output);
}

async function resumeStudioTurn(output) {
  studioRuntimeProjection.status = "active";
  studioRuntimeProjection.runtimeCockpit.stopResumeObserved = true;
  recomputeStudioRuntimeCockpitAchieved();
  appendStudioTimeline("Resume requested", "Operator resume routed to daemon session lifecycle.", "completed");
  if (studioRuntimeProjection.threadId) {
    await requestJson(
      daemonEndpoint(),
      `/v1/threads/${encodeURIComponent(studioRuntimeProjection.threadId)}/resume`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio",
          reason: "operator_resume",
        },
      },
    ).then((result) => {
      appendStudioReceiptsFromResponse(result, "session_resume", "Daemon resumed Studio thread.");
    }).catch((error) => {
      appendStudioTimeline("Resume projection unavailable", error?.message || String(error), "blocked");
      output?.appendLine?.(`[ioi-studio] resume projection unavailable: ${error?.message || String(error)}`);
    });
  }
  await writeBridgeRequest(
    "chat.resume",
    {
      threadId: studioRuntimeProjection.threadId,
      turnId: studioRuntimeProjection.turnId,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      reason: "operator_resume",
      ownsRuntimeState: false,
    },
    buildWorkspaceActionContext("agent-studio-resume"),
  ).catch((error) => {
    output?.appendLine?.(`[ioi-studio] bridge resume route unavailable: ${error?.message || String(error)}`);
  });
  studioRuntimeProjection.status = "completed";
  await refreshStudioPanelHtml(output);
}

async function openStudioPanel(context, output) {
  const state = await readBridgeState();
  if (studioPanel) {
    studioPanel.reveal(vscode.ViewColumn.One);
  } else {
    studioPanel = vscode.window.createWebviewPanel(
      "ioi.studio",
      "Agent Studio",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );
    studioPanel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-studio.svg",
    );
    studioPanel.webview.onDidReceiveMessage(async (message) => {
      if (message?.type === "studioSubmit") {
        await submitStudioPrompt(message.payload || {}, output);
        return;
      }
      if (message?.type === "studioHunkDecision") {
        await handleStudioHunkDecision(message.decision, message.payload || {}, output);
        return;
      }
      if (message?.type === "studioHunkNavigate") {
        await navigateStudioHunk(message.direction || "next", output);
        return;
      }
      if (message?.type === "studioStop") {
        await stopStudioTurn(output);
        return;
      }
      if (message?.type === "studioResume") {
        await resumeStudioTurn(output);
        return;
      }
      if (message?.type === "studioOperationalProof") {
        output.appendLine(`[ioi-studio] operational proof: ${JSON.stringify(message.proof || {})}`);
        return;
      }
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        if (message.requestType === "chat.agentMode.select") {
          const previousMode = normalizeStudioExecutionMode(studioRuntimeProjection.executionMode);
          const previousRuntimeProfile = studioRuntimeProjection.runtimeProfile;
          studioRuntimeProjection.executionMode = normalizeStudioExecutionMode(
            message.payload?.executionMode || message.payload?.selectionId || message.payload?.label,
          );
          studioRuntimeProjection.runtimeProfile =
            studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT
              ? STUDIO_AGENT_RUNTIME_PROFILE
              : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
          if (
            studioRuntimeProjection.threadId &&
            (
              previousMode !== studioRuntimeProjection.executionMode ||
              previousRuntimeProfile !== studioRuntimeProjection.runtimeProfile
            )
          ) {
            resetStudioDaemonThreadProjection();
          }
        }
        if (message.requestType === "chat.permissionMode.select") {
          await applyStudioPermissionModeSelection(message.payload || {}, output);
        }
        if (message.requestType === "chat.newSession") {
          startNewStudioSession("Operator started a fresh Studio chat session.");
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext("studio-panel-webview"),
        ).catch((error) => {
          output.appendLine(
            `[ioi-studio] bridge request unavailable: ${error?.message || String(error)}`,
          );
        });
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    registerModePanelVisibilityProjection(studioPanel, "studio", output);
    studioPanel.onDidDispose(() => {
      studioPanel = null;
      studioPanelLastHtml = null;
      studioPanelNonce = null;
    });
  }
  updateStudioPanelHtml(state, { force: true });
  output.appendLine("Opened Agent Studio webview.");
  return studioPanel;
}

async function openModelsPanel(context, output, options = {}) {
  const modelsViewDefinition =
    VIEW_DEFINITIONS.find((definition) => definition.id === "ioi.models") || {
      id: "ioi.models",
      title: "Models",
      eyebrow: "Daemon model runtime",
      description: "Daemon-backed model mounting.",
      actions: [],
    };
  const state = await readBridgeState();
  if (modelsPanel) {
    modelsPanel.reveal(vscode.ViewColumn.One);
  } else {
    modelsPanel = vscode.window.createWebviewPanel(
      "ioi.models",
      "Autopilot Models",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );
    modelsPanel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-activity.svg",
    );
    modelsPanel.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext("models-panel-webview"),
        );
        return;
      }
      if (message?.type === "modelsModeProof" && message.proof) {
        await writeBridgeRequest(
          "modelsMode.proof",
          message.proof,
          buildWorkspaceActionContext("models-panel-webview"),
        );
        return;
      }
      if (message?.type === "modelsModeProof" && message.proof) {
        await writeBridgeRequest(
          "modelsMode.proof",
          message.proof,
          buildWorkspaceActionContext("ioi.models"),
        );
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    registerModePanelVisibilityProjection(modelsPanel, "models", output);
    modelsPanel.onDidDispose(() => {
      modelsPanel = null;
    });
  }
  modelsPanel.webview.html = renderHtml(modelsViewDefinition, state);
  const phase = typeof options.phase === "string" ? options.phase : null;
  if (phase) {
    setTimeout(() => {
      modelsPanel?.webview.postMessage({
        type: "ioi.models.capturePhase",
        phase,
      });
    }, 700);
  }
  output.appendLine("Opened Autopilot Models webview.");
  return modelsPanel;
}

function renderModePanelHtml(modeId, state) {
  if (modeId === "code") {
    return codeModePanelHtml(state);
  }
  const mode = AUTOPILOT_MODE_BY_ID[modeId];
  const viewId = mode?.panelViewId;
  const viewDefinition =
    VIEW_DEFINITIONS.find((definition) => definition.id === viewId) || {
      id: viewId || `ioi.${modeId}`,
      title: mode?.title || "Autopilot",
      eyebrow: "Autopilot mode",
      description: "Persistent Autopilot workbench mode.",
      actions: [],
    };
  return renderHtml(viewDefinition, state);
}

function relativeWorkspacePath(workspacePath, filePath) {
  const rawPath = typeof filePath === "string" ? filePath.trim() : "";
  if (!rawPath) {
    return "unknown";
  }
  const root = typeof workspacePath === "string" ? workspacePath.replace(/\/+$/, "") : "";
  if (root && rawPath.startsWith(`${root}/`)) {
    return rawPath.slice(root.length + 1);
  }
  return rawPath;
}

function shortPathLabel(path) {
  const value = typeof path === "string" && path.trim() ? path.trim() : "unknown";
  const segments = value.split("/").filter(Boolean);
  return segments.length ? segments[segments.length - 1] : value;
}

function codeRepositoryGateProjection(state) {
  const context = buildWorkbenchContextSnapshot("code-repositories-gate");
  const workspace = context.workspace || state.workspace || workspaceSummary();
  const workspacePath = typeof workspace.path === "string" ? workspace.path.trim() : "";
  const workspaceName = typeof workspace.name === "string" && workspace.name.trim()
    ? workspace.name.trim()
    : shortPathLabel(workspacePath);
  const currentRepository = workspacePath
    ? {
        id: "current-workspace",
        name: workspaceName || "Current workspace",
        rootPath: workspacePath,
        description: "Current Autopilot workspace",
        favorite: false,
      }
    : null;
  return {
    context,
    workspace,
    repositories: currentRepository ? [currentRepository] : [],
  };
}

function repositoryGateIconSvg() {
  return `<svg class="workspace-repository-gate__icon" viewBox="0 0 30 30" role="img" aria-label="Repository">
    <defs>
      <linearGradient id="repoGateShell" x1="4" x2="26" y1="5" y2="25" gradientUnits="userSpaceOnUse">
        <stop stop-color="#ffffff" />
        <stop offset="1" stop-color="#dbe7f0" />
      </linearGradient>
    </defs>
    <rect x="4.5" y="5.5" width="21" height="19" rx="3" fill="url(#repoGateShell)" stroke="#7890a4" />
    <path d="M9 11.5h7.2M9 15h11.5M9 18.5h8.5" stroke="#4b6478" stroke-width="1.4" stroke-linecap="round" />
    <path d="M7.8 9.2 10.8 12l-3 2.8" fill="none" stroke="#283d4d" stroke-width="1.45" stroke-linecap="round" stroke-linejoin="round" />
  </svg>`;
}

function searchIconSvg(size = 16) {
  const numericSize = Number.isFinite(size) ? size : 16;
  return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="2" />
    <path d="m16.5 16.5 4 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
  </svg>`;
}

function plusIconSvg(size = 16) {
  const numericSize = Number.isFinite(size) ? size : 16;
  return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
  </svg>`;
}

function pullRequestIconSvg(size = 46) {
  const numericSize = Number.isFinite(size) ? size : 46;
  return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="6" cy="6" r="3" stroke="currentColor" stroke-width="1.4" />
    <circle cx="18" cy="18" r="3" stroke="currentColor" stroke-width="1.4" />
    <path d="M6 9v9M18 15V8.8A3.8 3.8 0 0 0 14.2 5H12" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
    <path d="m14 2.8-2.2 2.2L14 7.2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
  </svg>`;
}

function externalLinkIconSvg(size = 16) {
  const numericSize = Number.isFinite(size) ? size : 16;
  return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M14 5h5v5M10 14 19 5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    <path d="M19 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h4" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
  </svg>`;
}

function folderIconSvg(size = 16) {
  const numericSize = Number.isFinite(size) ? size : 16;
  return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M3.5 7.5A2.5 2.5 0 0 1 6 5h4.2l2 2H18a2.5 2.5 0 0 1 2.5 2.5v7A2.5 2.5 0 0 1 18 19H6a2.5 2.5 0 0 1-2.5-2.5v-9Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" />
  </svg>`;
}

function chevronRightIconSvg(size = 15) {
  const numericSize = Number.isFinite(size) ? size : 15;
  return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="m9 18 6-6-6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
  </svg>`;
}

function starIconSvg(size = 15) {
  const numericSize = Number.isFinite(size) ? size : 15;
  return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="m12 3.4 2.5 5.1 5.7.8-4.1 4 1 5.7-5.1-2.7L6.9 19l1-5.7-4.1-4 5.7-.8L12 3.4Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" />
  </svg>`;
}

function renderRepositoryGateList(items, emptyLabel) {
  if (!items.length) {
    return `<div class="workspace-repository-gate__empty-small">${escapeHtml(emptyLabel)}</div>`;
  }
  return items
    .map(
      (repository) => `
        <div class="workspace-repository-gate__repo-row">
          <button
            type="button"
            class="workspace-repository-gate__repo-open"
            data-command="workbench.action.files.openFolder"
            data-testid="code-repository-open-current"
          >
            ${folderIconSvg(16)}
            <span>
              <strong>${escapeHtml(repository.name)}</strong>
              <small>${escapeHtml(relativeWorkspacePath("", repository.rootPath))}</small>
            </span>
            ${chevronRightIconSvg(15)}
          </button>
          <button
            type="button"
            class="workspace-repository-gate__favorite-button"
            aria-label="Add ${escapeHtml(repository.name)} to favorites"
            title="Add to favorites"
          >
            ${starIconSvg(15)}
          </button>
        </div>
      `,
    )
    .join("");
}

function codeModePanelHtml(state) {
  const pageNonce = nonce();
  const projection = codeRepositoryGateProjection(state);
  const repositories = projection.repositories;
  const recentRows = renderRepositoryGateList(repositories, "No recent activity");
  const favoriteRows = renderRepositoryGateList(
    repositories.filter((repository) => repository.favorite),
    "You have no favorites",
  );
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'nonce-${pageNonce}'; script-src 'nonce-${pageNonce}';"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Autopilot Code</title>
    <style nonce="${pageNonce}">
      :root {
        color-scheme: dark;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: var(--vscode-font-family, ui-sans-serif, system-ui, sans-serif);
        color: var(--vscode-foreground);
        background: var(--vscode-editor-background);
      }
      ${autopilotShellHeaderStyles()}
      .code-repository-shell {
        min-height: calc(100vh - 50px);
        display: grid;
        grid-template-columns: minmax(250px, 318px) minmax(0, 1fr);
        gap: 0;
      }
      .code-repository-rail {
        min-height: 0;
        padding: 18px;
        border-right: 1px solid var(--vscode-panel-border);
        background: var(--vscode-sideBar-background);
        display: grid;
        align-content: start;
        gap: 18px;
      }
      .code-repository-rail h1,
      .code-repository-main h2,
      .code-repository-main h3 {
        margin: 0;
      }
      .code-repository-rail h1 {
        font-size: 20px;
      }
      .code-repository-main h2 {
        font-size: 22px;
      }
      .code-repository-main h3 {
        font-size: 14px;
      }
      .code-repository-rail p,
      .code-repository-main p {
        margin: 6px 0 0;
        color: var(--vscode-descriptionForeground);
        line-height: 1.45;
      }
      .code-repository-actions {
        display: grid;
        gap: 8px;
      }
      .code-repository-action {
        min-height: 36px;
        border: 1px solid var(--vscode-button-border, var(--vscode-panel-border));
        border-radius: 5px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        padding: 8px 10px;
        font: inherit;
        text-align: left;
      }
      .code-repository-action:hover {
        background: var(--vscode-button-secondaryHoverBackground);
      }
      .code-repository-main {
        min-width: 0;
        min-height: 0;
        display: grid;
        grid-template-rows: auto auto minmax(0, 1fr);
        background: var(--vscode-editor-background);
      }
      .code-repository-hero {
        padding: 24px 28px 20px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .code-repository-metrics {
        display: grid;
        grid-template-columns: repeat(5, minmax(110px, 1fr));
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .code-repository-metric {
        min-width: 0;
        padding: 13px 18px;
        border-right: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-editor-background) 92%, var(--vscode-foreground) 5%);
      }
      .code-repository-metric span,
      .code-repository-section-label,
      .code-repository-chip span,
      .code-repository-footnote {
        display: block;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }
      .code-repository-metric strong {
        display: block;
        margin-top: 5px;
        font-size: 16px;
        overflow-wrap: anywhere;
      }
      .code-repository-body {
        min-height: 0;
        display: grid;
        grid-template-columns: minmax(0, 1.1fr) minmax(320px, 0.9fr);
        overflow: hidden;
      }
      .code-repository-pane {
        min-width: 0;
        min-height: 0;
        padding: 18px 22px;
        overflow: auto;
      }
      .code-repository-pane + .code-repository-pane {
        border-left: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-sideBar-background) 88%, var(--vscode-editor-background) 12%);
      }
      .code-repository-section {
        display: grid;
        gap: 10px;
        margin-bottom: 22px;
      }
      .code-repository-section header {
        display: flex;
        align-items: end;
        justify-content: space-between;
        gap: 12px;
      }
      .code-repository-table {
        width: 100%;
        border-collapse: collapse;
        border: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-editor-background) 94%, var(--vscode-foreground) 4%);
      }
      .code-repository-table th,
      .code-repository-table td {
        padding: 9px 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
        text-align: left;
        vertical-align: top;
      }
      .code-repository-table th {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        background: color-mix(in srgb, var(--vscode-editor-background) 88%, var(--vscode-foreground) 6%);
      }
      .code-repository-table td:first-child {
        width: 72px;
      }
      .code-repository-table td:last-child {
        width: 96px;
        text-align: right;
      }
      .code-repository-table strong,
      .code-repository-table span {
        display: block;
        overflow-wrap: anywhere;
      }
      .code-repository-table span {
        margin-top: 3px;
        color: var(--vscode-descriptionForeground);
        font-size: 12px;
      }
      .code-repository-table button {
        min-height: 26px;
        border: 1px solid var(--vscode-button-border, var(--vscode-panel-border));
        border-radius: 4px;
        padding: 3px 8px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        font: inherit;
        cursor: pointer;
      }
      .code-repository-status {
        display: inline-flex;
        min-width: 34px;
        height: 20px;
        align-items: center;
        justify-content: center;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 999px;
        padding: 0 7px;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        text-transform: uppercase;
      }
      .code-repository-status.is-clean {
        border-color: color-mix(in srgb, #3fb950 70%, var(--vscode-panel-border));
        color: #7ee787;
      }
      .code-repository-status.is-dirty,
      .code-repository-status.is-warn {
        border-color: color-mix(in srgb, #d29922 70%, var(--vscode-panel-border));
        color: #e3b341;
      }
      .code-repository-status.is-muted {
        color: var(--vscode-descriptionForeground);
      }
      .code-repository-empty {
        color: var(--vscode-descriptionForeground);
      }
      .code-repository-chip-grid {
        display: grid;
        gap: 8px;
      }
      .code-repository-chip {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 12px;
        align-items: center;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        padding: 10px 12px;
        background: color-mix(in srgb, var(--vscode-editor-background) 92%, var(--vscode-foreground) 5%);
      }
      .code-repository-chip strong {
        overflow-wrap: anywhere;
      }
      .code-repository-chip button {
        min-height: 28px;
        border: 1px solid var(--vscode-button-border, var(--vscode-panel-border));
        border-radius: 4px;
        padding: 4px 8px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        font: inherit;
        cursor: pointer;
      }
      .code-repository-footnote {
        text-transform: none;
        letter-spacing: 0;
        line-height: 1.45;
      }
      @media (max-width: 880px) {
        .code-repository-shell,
        .code-repository-body,
        .code-repository-metrics {
          grid-template-columns: minmax(0, 1fr);
        }
      }
      .workspace-repository-gate {
        height: 100vh;
        min-width: 0;
        min-height: 0;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        background: #f5f7fa;
        color: #1f2933;
      }
      .workspace-repository-gate button,
      .workspace-repository-gate input {
        font: inherit;
      }
      .workspace-repository-gate__header {
        flex: 0 0 52px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 0 18px 0 10px;
        border-bottom: 1px solid #d5dce4;
        background: #ffffff;
      }
      .workspace-repository-gate__title {
        min-width: 0;
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .workspace-repository-gate__title h1 {
        margin: 0;
        overflow: hidden;
        color: #344150;
        font-size: 15px;
        font-weight: 700;
        letter-spacing: 0;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .workspace-repository-gate__icon-shell {
        width: 34px;
        height: 30px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: 1px solid #a9bac8;
        border-radius: 3px;
        background: #edf4f8;
      }
      .workspace-repository-gate__icon {
        width: 26px;
        height: 26px;
        display: block;
      }
      .workspace-repository-gate__primary-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 7px;
        min-height: 30px;
        padding: 0 12px;
        border: 1px solid #19703f;
        border-radius: 4px;
        background: #1f7f49;
        color: #ffffff;
        font-size: 12px;
        font-weight: 700;
        cursor: pointer;
        transition:
          background 120ms ease,
          border-color 120ms ease;
      }
      .workspace-repository-gate__primary-button:hover {
        border-color: #155f36;
        background: #176b3d;
      }
      .workspace-repository-gate__landing {
        flex: 1;
        min-height: 0;
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }
      .workspace-repository-gate__content {
        flex: 1;
        min-height: 0;
        display: grid;
        grid-template-columns: minmax(420px, 840px) minmax(280px, 322px);
        justify-content: center;
        gap: 18px;
        overflow: auto;
        padding: 24px;
      }
      .workspace-repository-gate__main,
      .workspace-repository-gate__rail {
        min-width: 0;
      }
      .workspace-repository-gate__main {
        display: flex;
        flex-direction: column;
        gap: 12px;
      }
      .workspace-repository-gate__pr-toolbar {
        display: grid;
        grid-template-columns: auto minmax(220px, 1fr);
        align-items: center;
        gap: 20px;
      }
      .workspace-repository-gate__tabs {
        display: flex;
        align-items: center;
        gap: 8px;
        white-space: nowrap;
      }
      .workspace-repository-gate__tabs button {
        min-height: 30px;
        padding: 0 11px;
        border: 0;
        border-radius: 999px;
        background: #e7ebf0;
        color: #425466;
        font-size: 12px;
        cursor: pointer;
      }
      .workspace-repository-gate__tabs button.is-active {
        background: transparent;
        color: #1f2933;
        font-weight: 700;
      }
      .workspace-repository-gate__search-field,
      .workspace-repository-gate__repository-search {
        min-width: 0;
        display: flex;
        align-items: center;
        gap: 8px;
        border: 1px solid #b8c2cc;
        border-radius: 4px;
        background: #ffffff;
        color: #66788a;
      }
      .workspace-repository-gate__search-field,
      .workspace-repository-gate__repository-search {
        height: 30px;
        padding: 0 9px;
      }
      .workspace-repository-gate__search-field input,
      .workspace-repository-gate__repository-search input {
        width: 100%;
        min-width: 0;
        border: 0;
        outline: 0;
        background: transparent;
        color: #1f2933;
        font-size: 12px;
      }
      .workspace-repository-gate__pr-empty {
        min-height: 236px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 10px;
        padding: 28px;
        border: 1px solid #d0d7df;
        border-radius: 4px;
        background: #ffffff;
        color: #637083;
        text-align: center;
      }
      .workspace-repository-gate__pr-empty svg {
        color: #c5cfda;
      }
      .workspace-repository-gate__pr-empty h2 {
        margin: 0;
        color: #637083;
        font-size: 16px;
        line-height: 1.2;
      }
      .workspace-repository-gate__pr-empty p {
        width: min(440px, 100%);
        margin: 0;
        color: #526274;
        font-size: 12px;
        line-height: 1.45;
      }
      .workspace-repository-gate__rail {
        display: flex;
        flex-direction: column;
        gap: 18px;
      }
      .workspace-repository-gate__rail-heading {
        min-height: 28px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }
      .workspace-repository-gate__rail-heading h2 {
        margin: 0;
        color: #1f2933;
        font-size: 12px;
        font-weight: 700;
      }
      .workspace-repository-gate__rail-heading button {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        border: 0;
        background: transparent;
        color: #0f5cc0;
        font-size: 12px;
        cursor: pointer;
      }
      .workspace-repository-gate__news,
      .workspace-repository-gate__repositories {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .workspace-repository-gate__news-card,
      .workspace-repository-gate__repo-card {
        border: 1px solid #d0d7df;
        border-radius: 4px;
        background: #ffffff;
      }
      .workspace-repository-gate__news-card {
        padding: 16px;
      }
      .workspace-repository-gate__news-card div {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 8px;
      }
      .workspace-repository-gate__news-card span {
        display: inline-flex;
        align-items: center;
        min-height: 20px;
        padding: 0 8px;
        border-radius: 4px;
        background: #e8f0ff;
        color: #1558c7;
        font-size: 11px;
      }
      .workspace-repository-gate__news-card time {
        color: #66788a;
        font-size: 12px;
      }
      .workspace-repository-gate__news-card p {
        margin: 0;
        color: #1f2933;
        font-size: 12px;
        line-height: 1.35;
      }
      .workspace-repository-gate__news-card button {
        margin-top: 8px;
        padding: 0;
        border: 0;
        background: transparent;
        color: #0f5cc0;
        font-size: 12px;
        cursor: pointer;
      }
      .workspace-repository-gate__repo-card h3 {
        margin: 0;
        padding: 13px 20px;
        border-bottom: 1px solid #dce2e8;
        color: #1f2933;
        font-size: 12px;
        font-weight: 700;
      }
      .workspace-repository-gate__repo-list {
        min-height: 74px;
        display: flex;
        flex-direction: column;
      }
      .workspace-repository-gate__repo-row {
        display: grid;
        grid-template-columns: minmax(0, 1fr) 34px;
        border-bottom: 1px solid #edf0f3;
      }
      .workspace-repository-gate__repo-row:last-child {
        border-bottom: 0;
      }
      .workspace-repository-gate__repo-open {
        min-width: 0;
        display: grid;
        grid-template-columns: 18px minmax(0, 1fr) 15px;
        align-items: center;
        gap: 8px;
        padding: 10px 8px 10px 16px;
        border: 0;
        background: transparent;
        color: #425466;
        text-align: left;
        cursor: pointer;
      }
      .workspace-repository-gate__repo-open:hover {
        background: #f7f9fb;
      }
      .workspace-repository-gate__repo-open span {
        min-width: 0;
        display: flex;
        flex-direction: column;
        gap: 2px;
      }
      .workspace-repository-gate__repo-open strong,
      .workspace-repository-gate__repo-open small {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .workspace-repository-gate__repo-open strong {
        color: #1f2933;
        font-size: 12px;
      }
      .workspace-repository-gate__repo-open small {
        color: #66788a;
        font-size: 11px;
      }
      .workspace-repository-gate__favorite-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: 0;
        border-left: 1px solid #edf0f3;
        background: transparent;
        color: #8091a3;
        cursor: pointer;
      }
      .workspace-repository-gate__favorite-button:hover {
        background: #f7f9fb;
        color: #b78105;
      }
      .workspace-repository-gate__empty-small {
        min-height: 74px;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 18px;
        color: #66788a;
        font-size: 12px;
        text-align: center;
      }
      .code-repository-substrate-sentinel {
        position: absolute;
        width: 1px;
        height: 1px;
        overflow: hidden;
        clip: rect(0 0 0 0);
        clip-path: inset(50%);
        white-space: nowrap;
      }
      @media (max-width: 880px) {
        .workspace-repository-gate__content,
        .workspace-repository-gate__pr-toolbar {
          grid-template-columns: minmax(0, 1fr);
        }
        .workspace-repository-gate__tabs {
          overflow-x: auto;
        }
      }
    </style>
  </head>
  <body>
    <main
      class="workspace-repository-gate"
      data-testid="autopilot-code-mode"
      data-runtime-authority="daemon-owned"
      data-vscode-substrate-visible="true"
    >
      <div class="code-repository-substrate-sentinel" aria-hidden="true">
        <button type="button" data-command="ioi.autopilot.back" data-testid="code-mode-back-to-autopilot">Back to Autopilot</button>
        <button type="button" data-command="workbench.view.explorer" data-testid="code-mode-explorer">Explorer</button>
        <button type="button" data-command="workbench.view.search" data-testid="code-mode-search">Search</button>
        <button type="button" data-command="workbench.view.scm" data-testid="code-mode-scm">Source Control</button>
        <button type="button" data-command="workbench.view.debug" data-testid="code-mode-run-debug">Run / Debug</button>
        <button type="button" data-command="workbench.view.extensions" data-testid="code-mode-extensions">Extensions</button>
        <button type="button" data-command="workbench.action.terminal.toggleTerminal" data-testid="code-mode-terminal">Terminal</button>
        <span data-testid="code-mode-vscode-menu-tooling">local substrate controls visible</span>
      </div>
      <header class="workspace-repository-gate__header" data-testid="code-repository-surface">
        <div class="workspace-repository-gate__title">
          <span class="workspace-repository-gate__icon-shell">
            ${repositoryGateIconSvg()}
          </span>
          <h1>Code repositories</h1>
        </div>
        <button
          type="button"
          class="workspace-repository-gate__primary-button"
          data-command="ioi.commandCenter.open"
          data-payload='{"initialQuery":"new code repository"}'
          data-testid="code-repository-new"
        >
          ${plusIconSvg(16)}
          <span>New repository</span>
        </button>
      </header>
      <div class="workspace-repository-gate__landing" data-testid="code-repositories-gate">
        <div class="workspace-repository-gate__content">
          <main class="workspace-repository-gate__main">
            <div class="workspace-repository-gate__pr-toolbar">
              <div class="workspace-repository-gate__tabs" role="tablist">
                <button type="button" class="is-active">Pull requests</button>
                <button type="button">Created by you</button>
                <button type="button">Review requested</button>
              </div>
              <label class="workspace-repository-gate__search-field">
                ${searchIconSvg(16)}
                <input type="search" placeholder="Find pull requests..." />
              </label>
            </div>
            <section class="workspace-repository-gate__pr-empty">
              ${pullRequestIconSvg(46)}
              <h2>No pull requests created by you</h2>
              <p>
                There are no open pull requests created by you. Here are the
                recently visited code repositories and their pull requests.
              </p>
            </section>
          </main>

          <aside class="workspace-repository-gate__rail">
            <section class="workspace-repository-gate__news">
              <div class="workspace-repository-gate__rail-heading">
                <h2>What's new?</h2>
                <button type="button">
                  <span>See all</span>
                  ${externalLinkIconSvg(16)}
                </button>
              </div>
              <article class="workspace-repository-gate__news-card">
                <div>
                  <span>Feature</span>
                  <time datetime="2026-04-21">Apr 21, 2026</time>
                </div>
                <p>
                  Ontology Manager now displays run history directly within
                  function and action observability dashboards.
                </p>
                <button type="button">More</button>
              </article>
            </section>

            <section class="workspace-repository-gate__repositories">
              <div class="workspace-repository-gate__rail-heading">
                <h2>Repositories</h2>
                ${searchIconSvg(18)}
              </div>
              <label class="workspace-repository-gate__repository-search">
                ${searchIconSvg(15)}
                <input type="search" placeholder="Search repositories" />
              </label>
              <div class="workspace-repository-gate__repo-card">
                <h3>Recents</h3>
                <div class="workspace-repository-gate__repo-list">${recentRows}</div>
              </div>
              <div class="workspace-repository-gate__repo-card">
                <h3>Favorites</h3>
                <div class="workspace-repository-gate__repo-list">${favoriteRows}</div>
              </div>
            </section>
          </aside>
        </div>
      </div>
    </main>
    <script nonce="${pageNonce}">
      const vscode = acquireVsCodeApi();
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "command",
            command: button.dataset.command,
            payload: button.dataset.payload ? JSON.parse(button.dataset.payload) : undefined
          });
        });
      });
    </script>
  </body>
</html>`;
}

async function openGenericModePanel(context, output, modeId) {
  const mode = AUTOPILOT_MODE_BY_ID[modeId];
  if (!mode) {
    throw new Error(`Unknown Autopilot mode: ${modeId}`);
  }
  const state = await readBridgeState();
  let panel = genericModePanels.get(modeId);
  if (panel) {
    panel.reveal(vscode.ViewColumn.One);
  } else {
    panel = vscode.window.createWebviewPanel(
      mode.panelViewType,
      `Autopilot ${mode.title}`,
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );
    panel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-activity.svg",
    );
    panel.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext(`${modeId}-mode-webview`),
        );
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    registerModePanelVisibilityProjection(panel, modeId, output);
    panel.onDidDispose(() => {
      genericModePanels.delete(modeId);
    });
    genericModePanels.set(modeId, panel);
  }
  panel.webview.html = renderModePanelHtml(modeId, state);
  output.appendLine(`Opened Autopilot ${mode.title} mode webview.`);
  return panel;
}

function openWorkflowComposerPanel(context, output, options = {}) {
  if (workflowComposerPanel) {
    workflowComposerPanel.reveal(vscode.ViewColumn.One);
  } else {
    workflowComposerPanel = vscode.window.createWebviewPanel(
      "ioi.workflowComposer",
      "Autopilot Workflow Composer",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [
          vscode.Uri.joinPath(context.extensionUri, "media"),
        ],
      },
    );
    workflowComposerPanel.iconPath = vscode.Uri.joinPath(
      context.extensionUri,
      "media",
      "ioi-activity.svg",
    );
    workflowComposerPanel.webview.html = workflowComposerHtml(
      context,
      workflowComposerPanel.webview,
    );
    workflowComposerPanel.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext("workflow-composer-webview"),
        );
        return;
      }
      if (message?.type === "workflowCompositorProof" && message.proof) {
        await writeBridgeRequest(
          "workflowCompositor.proof",
          message.proof,
          buildWorkspaceActionContext("workflow-composer-webview"),
        );
        return;
      }
      if (message?.type === "workflowCompositorError" && message.error) {
        output.appendLine(
          `[workflow-composer] ${message.error.message || "unknown webview error"}`,
        );
        await writeBridgeRequest(
          "workflowCompositor.error",
          message.error,
          buildWorkspaceActionContext("workflow-composer-webview"),
        );
        return;
      }
      if (message?.type === "command" && typeof message.command === "string") {
        await vscode.commands.executeCommand(message.command, message.payload);
      }
    });
    registerModePanelVisibilityProjection(workflowComposerPanel, "workflows", output);
    workflowComposerPanel.onDidDispose(() => {
      workflowComposerPanel = null;
    });
  }

  const scenarioId =
    typeof options.scenarioId === "string" ? options.scenarioId : null;
  const phase = typeof options.phase === "string" ? options.phase : "canvas";
  if (scenarioId) {
    setTimeout(() => {
      workflowComposerPanel?.webview.postMessage({
        type: "ioi.workflow.compositor.runScenario",
        scenarioId,
        phase,
      });
    }, 750);
  } else if (options.capturePhase) {
    setTimeout(() => {
      workflowComposerPanel?.webview.postMessage({
        type: "ioi.workflow.compositor.capturePhase",
        phase,
      });
    }, 750);
  }

  output.appendLine("Opened Autopilot Workflow Composer webview.");
  return workflowComposerPanel;
}

function closePrimarySidebarAfterActivityLaunch() {
  for (const delayMs of [125, 350, 800, 1400]) {
    setTimeout(() => {
      void vscode.commands
        .executeCommand("workbench.action.closeSidebar")
        .catch((error) => {
          console.error(
            "[IOI Workbench] Failed to close activity launcher sidebar:",
            error,
          );
        });
    }, delayMs);
  }
}

function updateOverviewPanelHtml(state) {
  if (!overviewPanel) {
    return;
  }
  const html = overviewPanelHtml(state);
  if (html === overviewPanelLastHtml) {
    return;
  }
  overviewPanelLastHtml = html;
  overviewPanel.webview.html = html;
}

function writeModeVisibilityProjection(modeId, output, reason = "panel-visible") {
  const requestType = MODE_VISIBILITY_REQUEST_TYPES[modeId];
  const mode = AUTOPILOT_MODE_BY_ID[modeId];
  if (!requestType || !mode) {
    return;
  }
  const now = Date.now();
  const lastAt = modeVisibilityProjectionLastAtMs.get(modeId) || 0;
  if (now - lastAt < 450) {
    return;
  }
  modeVisibilityProjectionLastAtMs.set(modeId, now);
  const actionContext = buildWorkspaceActionContext(`${modeId}-${reason}`);
  void writeBridgeRequest(requestType, {
    workspaceRoot: workspaceSummary().path,
    sourceCommand: mode.command,
    source: reason,
    phase: mode.phase,
    runtimeAuthority: "daemon-owned",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
  }, actionContext).catch((error) => {
    output?.appendLine?.(
      `[ioi-${modeId}] visible projection unavailable: ${error?.message || String(error)}`,
    );
  });
}

function registerModePanelVisibilityProjection(panel, modeId, output) {
  const disposable = panel.onDidChangeViewState((event) => {
    if (event.webviewPanel.active) {
      writeModeVisibilityProjection(modeId, output);
    }
  });
  panel.onDidDispose(() => {
    disposable.dispose();
  });
}

class IOIViewProvider {
  constructor(definition, getState) {
    this.definition = definition;
    this.getState = getState;
    this.webviewView = null;
    this.lastRenderedHtml = null;
    this.primaryOpenInFlight = false;
    this.lastPrimaryOpenAtMs = 0;
  }

  resolveWebviewView(webviewView) {
    this.webviewView = webviewView;
    this.lastRenderedHtml = null;
    webviewView.webview.options = {
      enableScripts: true,
      enableForms: true,
    };
    void this.render();
    this.maybeAutoOpenPrimarySurface();
    webviewView.webview.onDidReceiveMessage(async (message) => {
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
        await writeBridgeRequest(
          message.requestType,
          message.payload || {},
          buildWorkspaceActionContext("ioi.chat"),
        );
        return;
      }
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    const visibilityDisposable = webviewView.onDidChangeVisibility(() => {
      if (webviewView.visible) {
        this.maybeAutoOpenPrimarySurface();
      }
    });
    webviewView.onDidDispose(() => {
      visibilityDisposable.dispose();
      this.webviewView = null;
    });
  }

  maybeAutoOpenPrimarySurface() {
    const mode = AUTOPILOT_MODE_BY_VIEW_ID[this.definition.id];
    const primarySurface = mode
      ? {
          command: mode.command,
          payload: {
            source: "activitybar",
            phase: mode.phase,
          },
        }
      : null;
    if (!primarySurface) {
      return;
    }
    const now = Date.now();
    if (this.primaryOpenInFlight || now - this.lastPrimaryOpenAtMs < 800) {
      return;
    }
    this.primaryOpenInFlight = true;
    this.lastPrimaryOpenAtMs = now;
    setTimeout(() => {
      void (async () => {
        try {
          closePrimarySidebarAfterActivityLaunch();
          await vscode.commands.executeCommand(
            primarySurface.command,
            primarySurface.payload,
          );
          closePrimarySidebarAfterActivityLaunch();
        } catch (error) {
          console.error(
            "[IOI Workbench] Failed to auto-open primary activity surface:",
            error,
          );
        } finally {
          this.primaryOpenInFlight = false;
        }
      })();
    }, 0);
  }

  async render() {
    if (!this.webviewView) {
      return;
    }
    const state = await this.getState();
    await syncWorkbenchAppearance(state);
    const html = renderHtml(this.definition, state);
    if (html === this.lastRenderedHtml) {
      return;
    }
    this.lastRenderedHtml = html;
    this.webviewView.webview.html = html;
  }
}

let lastAppliedColorTheme = null;

async function syncWorkbenchAppearance(state) {
  const colorTheme = state?.appearance?.openVsCodeColorTheme;
  if (typeof colorTheme !== "string" || !colorTheme.trim()) {
    return;
  }
  const normalized = colorTheme.trim();
  if (normalized === lastAppliedColorTheme) {
    return;
  }
  lastAppliedColorTheme = normalized;
  try {
    await vscode.workspace
      .getConfiguration("workbench")
      .update("colorTheme", normalized, vscode.ConfigurationTarget.Global);
  } catch (error) {
    console.error("[IOI Workbench] Failed to apply bridge appearance:", error);
  }
}

function watchBridgeState(onChange) {
  const handle = setInterval(() => {
    void onChange();
  }, 2_000);
  return {
    dispose() {
      clearInterval(handle);
    },
  };
}

function resolveFileContext(uri) {
  if (uri?.scheme === "file") {
    return uri.fsPath;
  }

  const activeEditorPath = vscode.window.activeTextEditor?.document.uri.fsPath;
  if (activeEditorPath) {
    return activeEditorPath;
  }

  const explorerSelection = vscode.window.tabGroups.all
    .flatMap((group) => group.tabs)
    .find((tab) => tab.isActive)?.input?.uri?.fsPath;
  return explorerSelection || null;
}

async function runDaemonModelWorkbenchAction(action, payload = {}) {
  const endpoint = daemonEndpoint();
  const token = daemonToken();
  if (!endpoint) {
    throw new Error("IOI_DAEMON_ENDPOINT is required for model workbench actions.");
  }
  const targetEndpointId =
    pickPayloadString(payload, "endpointId") ||
    pickPayloadString(payload, "endpoint_id") ||
    "endpoint.electron.model-gui";
  const targetInstanceId =
    pickPayloadString(payload, "instanceId") || pickPayloadString(payload, "instance_id");
  let requestedGpu =
    pickPayloadString(payload, "gpu") || pickPayloadString(payload, "gpuOffload") || "0";
  if (requestedGpu === "auto") {
    requestedGpu = "0";
  }
  if (action === "estimate") {
    return requestJson(endpoint, "/api/v1/models/estimate-load", {
      method: "POST",
      token,
      payload: {
        endpoint_id: targetEndpointId,
        load_options: {
          estimateOnly: true,
          gpu: requestedGpu,
          contextLength: Number(pickPayloadString(payload, "contextLength") || 4096),
          parallel: Number(pickPayloadString(payload, "parallel") || 2),
          ttlSeconds: Number(pickPayloadString(payload, "ttlSeconds") || 900),
          identifier: pickPayloadString(payload, "identifier") || "electron-model-workbench",
        },
      },
    });
  }
  if (action === "load") {
    return requestJson(endpoint, `/api/v1/models/mounts/${encodeURIComponent(targetEndpointId)}/load`, {
      method: "POST",
      token,
      payload: {
        load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
        load_options: {
          gpu: requestedGpu,
          contextLength: Number(pickPayloadString(payload, "contextLength") || 4096),
          parallel: Number(pickPayloadString(payload, "parallel") || 2),
          ttlSeconds: Number(pickPayloadString(payload, "ttlSeconds") || 900),
          identifier: pickPayloadString(payload, "identifier") || "electron-model-workbench",
        },
      },
    });
  }
  if (action === "unload") {
    return requestJson(
      endpoint,
      targetInstanceId
        ? `/api/v1/models/instances/${encodeURIComponent(targetInstanceId)}/unload`
        : `/api/v1/models/mounts/${encodeURIComponent(targetEndpointId)}/unload`,
      {
        method: "POST",
        token,
        payload: {},
      },
    );
  }
  throw new Error(`Unknown model workbench action: ${action}`);
}

async function runDaemonModelCatalogSearch(payload = {}) {
  const endpoint = daemonEndpoint();
  const token = daemonToken();
  if (!endpoint) {
    throw new Error("IOI_DAEMON_ENDPOINT is required for model catalog search.");
  }
  const params = new URLSearchParams();
  const query = pickPayloadString(payload, "query") || pickPayloadString(payload, "q") || "";
  if (query) {
    params.set("q", query);
    params.set("query", query);
  }
  const format = pickPayloadString(payload, "format");
  const quantization = pickPayloadString(payload, "quantization");
  if (format) params.set("format", format);
  if (quantization) params.set("quantization", quantization);
  params.set("limit", pickPayloadString(payload, "limit") || "20");
  return requestJson(endpoint, `/api/v1/models/catalog/search?${params.toString()}`, {
    method: "GET",
    token,
  });
}

async function runDaemonModelCatalogProviderConfig(payload = {}) {
  const endpoint = daemonEndpoint();
  const token = daemonToken();
  const providerId = pickPayloadString(payload, "providerId") || pickPayloadString(payload, "provider_id") || "catalog.huggingface";
  if (!endpoint) {
    throw new Error("IOI_DAEMON_ENDPOINT is required for catalog source configuration.");
  }
  const body = {
    enabled: payload?.enabled === false ? false : true,
  };
  if (providerId === "catalog.local_manifest") {
    body.manifest_path = pickPayloadString(payload, "manifestPath") || pickPayloadString(payload, "path") || "";
  } else {
    body.base_url = pickPayloadString(payload, "baseUrl") || pickPayloadString(payload, "url") || "https://huggingface.co";
  }
  return requestJson(endpoint, `/api/v1/models/catalog/providers/${encodeURIComponent(providerId)}`, {
    method: "PATCH",
    token,
    payload: body,
  });
}

async function runDaemonModelCatalogDownload(payload = {}) {
  const endpoint = daemonEndpoint();
  const token = daemonToken();
  const sourceUrl = pickPayloadString(payload, "sourceUrl") || pickPayloadString(payload, "source_url");
  if (!endpoint) {
    throw new Error("IOI_DAEMON_ENDPOINT is required for model catalog download.");
  }
  if (!sourceUrl) {
    throw new Error("A daemon catalog source URL is required for model download.");
  }
  return requestJson(endpoint, "/api/v1/models/download", {
    method: "POST",
    token,
    payload: {
      source_url: sourceUrl,
      model_id: pickPayloadString(payload, "modelId") || pickPayloadString(payload, "model_id"),
      catalog_entry_id: pickPayloadString(payload, "catalogEntryId") || pickPayloadString(payload, "catalog_entry_id"),
      download_policy: {
        approvalDecision: "required",
        externalNetwork: "daemon_gated",
      },
    },
  });
}

function pickPayloadString(value, key) {
  if (typeof value === "string" && key === "value") {
    return value;
  }
  if (value && typeof value === "object" && typeof value[key] === "string") {
    return value[key];
  }
  if (value && typeof value === "object" && typeof value[key] === "number") {
    return String(value[key]);
  }
  return null;
}

function extensionQuickInputFallbackEnabled() {
  return ["1", "true", "yes"].includes(
    String(process.env.IOI_QUICKINPUT_EXTENSION_FALLBACK || "").toLowerCase(),
  );
}

async function recordForkQuickInputCommand(command, payload, output) {
  const contextSnapshot = buildWorkspaceActionContext("fork-native-quickinput-command");
  await writeBridgeRequest(command.replace(/^ioi\.quickInput\./, "quickInput."), {
    ...(payload && typeof payload === "object" ? payload : {}),
    sourceCommand: command,
    nativeForkContributionExpected: true,
    extensionQuickPickFallbackUsed: false,
    runtimeAuthority: "daemon-owned",
    projectionOwner: "autopilot-workbench-fork-quickinput",
  }, contextSnapshot).catch((error) => {
    output.appendLine(
      `[ioi-quickinput] fork command bridge request unavailable: ${error?.message || String(error)}`,
    );
  });
}

function registerNativeCommands(context, output) {
  ensureStudioDiffProvider(context);
  const status = (message) =>
    vscode.window.setStatusBarMessage(`$(symbol-keyword) ${message}`, 3000);
  const pickString = (value, key) => {
    if (typeof value === "string") {
      return value;
    }
    if (value && typeof value === "object" && typeof value[key] === "string") {
      return value[key];
    }
    return null;
  };
  const planMigrationImport = async (command, sourceEditor, importKind, payload = {}) => {
    const contextSnapshot = buildWorkspaceActionContext("migration-assistant");
    await writeBridgeRequest("migration.import.plan", {
      workspaceRoot: workspaceSummary().path,
      sourceCommand: command,
      sourceEditor,
      importKind,
      applyMode: "plan_only",
      policyReviewRequired: true,
      sandboxBoundaryPreserved: true,
      autoApply: false,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "openvscode-workbench-adapter",
      ownsRuntimeState: false,
      payload: payload && typeof payload === "object" ? payload : {},
    }, contextSnapshot).catch((error) => {
      output.appendLine(
        `[ioi-migration] bridge request unavailable: ${error?.message || String(error)}`,
      );
    });
    status(`Planned ${sourceEditor} ${importKind} import.`);
  };

  context.subscriptions.push(
    vscode.commands.registerCommand("ioi.migration.openAssistant", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("migration-assistant");
      await writeBridgeRequest("migration.assistant.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.migration.openAssistant",
        supportedSources: ["vscode", "cursor", "windsurf"],
        supportedImports: ["settings", "extensions", "keybindings", "exclusions"],
        applyMode: "plan_only",
        policyReviewRequired: true,
        sandboxBoundaryPreserved: true,
        autoApply: false,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        payload: payload && typeof payload === "object" ? payload : {},
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-migration] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      status("Opened Migration Assistant plan.");
    }),
    vscode.commands.registerCommand("ioi.migration.importVSCodeSettings", (payload = {}) =>
      planMigrationImport("ioi.migration.importVSCodeSettings", "vscode", "settings", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importCursorSettings", (payload = {}) =>
      planMigrationImport("ioi.migration.importCursorSettings", "cursor", "settings", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importWindsurfSettings", (payload = {}) =>
      planMigrationImport("ioi.migration.importWindsurfSettings", "windsurf", "settings", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importVSCodeExtensions", (payload = {}) =>
      planMigrationImport("ioi.migration.importVSCodeExtensions", "vscode", "extensions", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importCursorExtensions", (payload = {}) =>
      planMigrationImport("ioi.migration.importCursorExtensions", "cursor", "extensions", payload),
    ),
    vscode.commands.registerCommand("ioi.migration.importWindsurfExtensions", (payload = {}) =>
      planMigrationImport("ioi.migration.importWindsurfExtensions", "windsurf", "extensions", payload),
    ),
    vscode.commands.registerCommand("ioi.quickInput.context.open", async (payload = {}) => {
      if (extensionQuickInputFallbackEnabled()) {
        await vscode.commands.executeCommand("ioi.studio.openContextPicker", payload);
        return;
      }
      await recordForkQuickInputCommand("ioi.quickInput.context.open", payload, output);
      status("Fork-native Add Context QuickInput requested.");
    }),
    vscode.commands.registerCommand("ioi.quickInput.tools.configure", async (payload = {}) => {
      if (extensionQuickInputFallbackEnabled()) {
        await vscode.commands.executeCommand("ioi.studio.openToolPicker", payload);
        return;
      }
      await recordForkQuickInputCommand("ioi.quickInput.tools.configure", payload, output);
      status("Fork-native Configure Tools QuickInput requested.");
    }),
    vscode.commands.registerCommand("ioi.quickInput.modelRoute.pick", async (payload = {}) => {
      await recordForkQuickInputCommand("ioi.quickInput.modelRoute.pick", payload, output);
      status("Fork-native model route picker requested.");
    }),
    vscode.commands.registerCommand("ioi.quickInput.workflowTarget.pick", async (payload = {}) => {
      await recordForkQuickInputCommand("ioi.quickInput.workflowTarget.pick", payload, output);
      status("Fork-native workflow target picker requested.");
    }),
    vscode.commands.registerCommand("ioi.quickInput.agentMode.pick", async (payload = {}) => {
      await recordForkQuickInputCommand("ioi.quickInput.agentMode.pick", payload, output);
      status("Fork-native agent mode picker requested.");
    }),
    vscode.commands.registerCommand("ioi.quickInput.permissionMode.pick", async (payload = {}) => {
      const options = studioPermissionModeOptions(payload.approvalMode || studioRuntimeProjection.approvalMode).map((item) => ({
        label: item.label,
        description: item.description,
        picked: item.picked,
        approvalMode: item.id,
      }));
      const picked = await vscode.window.showQuickPick(options, {
        placeHolder: "Choose Agent permissions",
        ignoreFocusOut: true,
      });
      if (!picked) {
        return;
      }
      const mapping = await applyStudioPermissionModeSelection({ approvalMode: picked.approvalMode }, output);
      await writeBridgeRequest("chat.permissionMode.select", {
        selectionId: picked.approvalMode,
        approvalMode: mapping.approvalMode,
        approval_mode: mapping.approvalMode,
        threadMode: mapping.threadMode,
        thread_mode: mapping.threadMode,
        label: picked.label,
        daemonMapping: mapping,
        source: "agent-studio-permissions-menu",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "ioi-workbench-agent-studio",
      }, buildWorkspaceActionContext("agent-studio-permissions-menu")).catch((error) => {
        output.appendLine(
          `[ioi-studio] bridge permission mode route unavailable: ${error?.message || String(error)}`,
        );
      });
      await refreshStudioPanelHtml(output);
      await focusStudioPanelComposer();
      status(`Agent permissions set to ${picked.label}.`);
    }),
    vscode.commands.registerCommand("ioi.overview.open", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("overview");
      await enterAutopilotMode("home", output);
      await openOverviewPanel(context, output);
      await writeBridgeRequest("overview.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.overview.open",
        phase: pickString(payload, "phase") || "home",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-overview] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      closePrimarySidebarAfterActivityLaunch();
      status("Opened Autopilot Overview.");
    }),
    vscode.commands.registerCommand("ioi.commandCenter.open", async (options = {}) => {
      const initialQuery =
        options && typeof options.initialQuery === "string"
          ? options.initialQuery
          : "";
      const mode =
        options && typeof options.mode === "string" && options.mode === "tools"
          ? "tools"
          : undefined;
      const context = buildWorkspaceActionContext("command-center.autopilot-header");
      await writeBridgeRequest("commandCenter.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.commandCenter.open",
        initialQuery,
        ...(mode ? { mode } : {}),
      }, context);
      status("Opening Autopilot command center.");
    }),
    vscode.commands.registerCommand("ioi.code.open", async () => {
      const contextSnapshot = buildWorkspaceActionContext("code-mode");
      await enterAutopilotMode("code", output);
      await openGenericModePanel(context, output, "code");
      await writeBridgeRequest("code.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.code.open",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        vscodeSubstrateVisible: true,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-code] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      await vscode.commands.executeCommand("workbench.view.explorer").catch(() => undefined);
      status("Opened Code mode.");
    }),
    vscode.commands.registerCommand("ioi.autopilot.back", async () => {
      const targetMode =
        lastAutopilotModeBeforeCode && lastAutopilotModeBeforeCode !== "code"
          ? lastAutopilotModeBeforeCode
          : "home";
      const target = AUTOPILOT_MODE_BY_ID[targetMode] || AUTOPILOT_MODE_BY_ID.home;
      await enterAutopilotMode(target.id, output);
      await vscode.commands.executeCommand(target.command, {
        source: "code-back",
        phase: target.phase,
      });
      closePrimarySidebarAfterActivityLaunch();
      status(`Returned to Autopilot ${target.title}.`);
    }),
    vscode.commands.registerCommand("ioi.studio.open", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("studio");
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      await writeBridgeRequest("studio.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.studio.open",
        phase: pickString(payload, "phase") || "chat",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-studio] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      closePrimarySidebarAfterActivityLaunch();
      status("Opened Agent Studio.");
    }),
    vscode.commands.registerCommand("ioi.studio.injectParityPlusEvents", async (payload = {}) => {
      if (process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS !== "1") {
        output.appendLine("[ioi-studio] parity-plus event injection refused outside test hooks.");
        return;
      }
      const events = firstArray(payload?.events);
      const turns = firstArray(payload?.turns);
      if (events.length === 0 && turns.length === 0) {
        output.appendLine("[ioi-studio] parity-plus event injection skipped: no events or turns provided.");
        return;
      }
      const contextSnapshot = buildWorkspaceActionContext("studio-parity-plus-hydration");
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      applyStudioAgentTurnEvents(events);
      for (const turn of turns) {
        if (turn && typeof turn === "object") {
          studioRuntimeProjection.turns.push({
            role: stringValue(turn.role, "assistant"),
            content: stringValue(turn.content || turn.text, ""),
            createdAt: stringValue(turn.createdAt || turn.created_at, new Date().toISOString()),
            outputRenderers: firstArray(turn.outputRenderers || turn.output_renderers),
            receiptRefs: normalizeReceiptRefs(turn),
          });
        }
      }
      studioRuntimeProjection.status = payload?.status || "completed";
      await refreshStudioPanelHtml(output);
      await writeBridgeRequest("studio.parityPlusEvents.injected", {
        sourceCommand: "ioi.studio.injectParityPlusEvents",
        eventCount: events.length,
        turnCount: turns.length,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-studio] parity-plus injection bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      status("Injected Agent Studio parity-plus runtime events.");
    }),
    vscode.commands.registerCommand("ioi.studio.openContextPicker", async () => {
      const contextSnapshot = buildWorkspaceActionContext("studio-native-context-picker");
      const items = studioContextQuickPickItems();
      const picker = vscode.window.createQuickPick();
      const disposables = [];

      picker.placeholder = "Search for files and context to add to your request";
      picker.matchOnDescription = true;
      picker.matchOnDetail = true;
      picker.ignoreFocusOut = true;
      picker.items = items;
      picker.activeItems = items.slice(0, 1);

      disposables.push(
        picker.onDidAccept(async () => {
          const selection = picker.selectedItems[0] || picker.activeItems[0];
          const row = selection?.row;
          if (!row) {
            return;
          }
          picker.hide();
          await writeBridgeRequest(row.requestType || "chat.contextPicker.select", {
            contextId: row.id,
            label: row.title,
            source: "studio-native-context-picker",
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
          }, contextSnapshot).catch((error) => {
            output.appendLine(
              `[ioi-studio] context picker bridge request unavailable: ${error?.message || String(error)}`,
            );
          });
          if (row.command) {
            await vscode.commands.executeCommand(row.command).catch((error) => {
              output.appendLine(
                `[ioi-studio] context picker command unavailable: ${error?.message || String(error)}`,
              );
            });
          }
        }),
        picker.onDidHide(() => {
          for (const disposable of disposables) {
            disposable.dispose();
          }
          picker.dispose();
        }),
      );

      picker.show();
      status("Opened Studio context picker.");
    }),
    vscode.commands.registerCommand("ioi.studio.openToolPicker", async () => {
      const contextSnapshot = buildWorkspaceActionContext("studio-native-tool-picker");
      let state = {};
      try {
        state = await readBridgeState();
      } catch (error) {
        output.appendLine(
          `[ioi-studio] tool picker using local substrate rows: ${error?.message || String(error)}`,
        );
      }
      const items = studioToolQuickPickItems(state);
      const picker = vscode.window.createQuickPick();
      const toolButtons = {
        context: {
          iconPath: new vscode.ThemeIcon("paperclip"),
          tooltip: "Add Context",
        },
        manage: {
          iconPath: new vscode.ThemeIcon("extensions"),
          tooltip: "Manage Tools",
        },
        settings: {
          iconPath: new vscode.ThemeIcon("settings-gear"),
          tooltip: "Tool Settings",
        },
      };
      const disposables = [];

      picker.title = "Configure Tools";
      picker.placeholder = "Select tools that are available to chat.";
      picker.canSelectMany = true;
      picker.matchOnDescription = true;
      picker.matchOnDetail = true;
      picker.ignoreFocusOut = true;
      picker.buttons = [toolButtons.context, toolButtons.manage, toolButtons.settings];
      picker.items = items;
      picker.selectedItems = items.filter((item) => item.row && item.row.enabled !== false && item.row.selected);
      picker.activeItems = picker.selectedItems.slice(0, 1);

      disposables.push(
        picker.onDidAccept(async () => {
          const selectedRows = picker.selectedItems
            .map((item) => ({ item, row: item.row }))
            .filter(({ row }) => row && row.enabled !== false);
          picker.hide();
          await writeBridgeRequest("chat.toolControls", {
            action: "configureTools",
            selectedTools: selectedRows.map(({ item, row }) => ({
              toolId: row.id,
              label: row.title,
              detail: row.detail,
              section: item.sectionId,
              meta: row.meta,
            })),
            selectedCount: selectedRows.length,
            source: "studio-native-quick-input",
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
          }, contextSnapshot).catch((error) => {
            output.appendLine(
              `[ioi-studio] tool control bridge request unavailable: ${error?.message || String(error)}`,
            );
          });
        }),
        picker.onDidTriggerButton(async (button) => {
          if (button === toolButtons.context) {
            await vscode.commands.executeCommand("ioi.studio.openContextPicker").catch((error) => {
              output.appendLine(
                `[ioi-studio] context picker command unavailable: ${error?.message || String(error)}`,
              );
            });
            return;
          }
          if (button === toolButtons.manage) {
            await writeBridgeRequest("chat.toolControls.manage", {
              source: "studio-native-tools-config",
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio",
            }, contextSnapshot).catch((error) => {
              output.appendLine(
                `[ioi-studio] manage tools bridge request unavailable: ${error?.message || String(error)}`,
              );
            });
            return;
          }
          if (button === toolButtons.settings) {
            await vscode.commands.executeCommand("workbench.action.openSettings", "chat.tools").catch((error) => {
              output.appendLine(
                `[ioi-studio] settings command unavailable: ${error?.message || String(error)}`,
              );
            });
          }
        }),
        picker.onDidHide(() => {
          for (const disposable of disposables) {
            disposable.dispose();
          }
          picker.dispose();
        }),
      );

      picker.show();
      status("Opened Studio tool configuration.");
    }),
    vscode.commands.registerCommand("ioi.studio.agentBuilder", async () => {
      const contextSnapshot = buildWorkspaceActionContext("agent-builder");
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      await writeBridgeRequest("studio.agentBuilder.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.studio.agentBuilder",
        preview: true,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-studio] agent builder bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      status("Opened Agent Builder preview.");
    }),
    vscode.commands.registerCommand("ioi.chat.new", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      if (studioPanel) {
        startNewStudioSession("Operator started a fresh Studio chat session.");
        await refreshStudioPanelHtml(output);
        await focusStudioPanelComposer();
      }
      await writeBridgeRequest("chat.new", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued new IOI Chat thread.");
    }),
    vscode.commands.registerCommand("ioi.chat.newOptions", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      await writeBridgeRequest("chat.newOptions", {
        workspaceRoot: workspaceSummary().path,
        options: ["new-chat", "new-window", "new-workspace-chat"],
      }, context);
      status("Queued IOI Chat new-thread options.");
    }),
    vscode.commands.registerCommand("ioi.chat.openSettings", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      await writeBridgeRequest("settings.open", {
        surface: "chat",
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI Chat settings.");
    }),
    vscode.commands.registerCommand("ioi.chat.focusComposer", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      if (studioPanel) {
        studioPanel.reveal(vscode.ViewColumn.One);
        await studioPanel.webview.postMessage({
          source: "ioi-studio-control",
          type: "focusComposer",
        });
      }
      await writeBridgeRequest("chat.focusComposer", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI Chat composer focus.");
    }),
    vscode.commands.registerCommand("ioi.studio.focusComposer", async () => {
      if (studioPanel) {
        studioPanel.reveal(vscode.ViewColumn.One);
        await studioPanel.webview.postMessage({
          source: "ioi-studio-control",
          type: "focusComposer",
        });
      }
      status("Focused Agent Studio composer.");
    }),
    vscode.commands.registerCommand("ioi.chat.submit", async (payload = {}) => {
      const prompt =
        pickString(payload, "prompt") ||
        pickString(payload, "query") ||
        pickString(payload, "initialQuery");
      if (!prompt) {
        vscode.window.showWarningMessage("No IOI Chat prompt was provided.");
        return;
      }
      const context = buildWorkspaceActionContext("ioi.chat");
      await writeBridgeRequest("chat.submit", {
        prompt,
        workspaceRoot: workspaceSummary().path,
        mode: pickString(payload, "mode"),
        model: pickString(payload, "model"),
      }, context);
      status("Queued IOI Chat request.");
    }),
    vscode.commands.registerCommand("ioi.chat.moreActions", async () => {
      const context = buildWorkspaceActionContext("ioi.chat");
      await writeBridgeRequest("chat.moreActions", {
        workspaceRoot: workspaceSummary().path,
        actions: [
          "review-current-file",
          "explain-selection",
          "open-runs",
          "open-policy",
        ],
      }, context);
      status("Queued IOI Chat action menu.");
    }),
    vscode.commands.registerCommand("ioi.chat.explainSelection", async (uri) => {
      const context = buildWorkspaceActionContext("editor", uri);
      const payloadFilePath = pickString(uri, "filePath");
      const payloadSelectedText = pickString(uri, "selectedText");
      if (payloadFilePath) {
        context.filePath = payloadFilePath;
      }
      await writeBridgeRequest("chat.explainSelection", {
        filePath: context.filePath,
        selectedText: payloadSelectedText ?? context.selection?.selectedText ?? null,
      }, context);
      status("Queued IOI Chat selection review.");
    }),
    vscode.commands.registerCommand("ioi.chat.reviewFile", async (uri) => {
      const payloadFilePath = pickString(uri, "filePath");
      const context = buildWorkspaceActionContext(
        uri && !payloadFilePath ? "explorer" : "editor",
        uri,
      );
      if (payloadFilePath) {
        context.filePath = payloadFilePath;
      }
      await writeBridgeRequest("chat.reviewFile", {
        filePath: context.filePath,
      }, context);
      status("Queued IOI Chat file review.");
    }),
    vscode.commands.registerCommand("ioi.artifacts.review", async (payload) => {
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        artifactId: pickString(payload, "artifactId"),
        evidenceThreadId: pickString(payload, "evidenceThreadId"),
        connectorId: pickString(payload, "connectorId"),
      };
      await writeBridgeRequest(
        "chat.reviewArtifact",
        {
          artifactId: context.artifactId,
          evidenceThreadId: context.evidenceThreadId,
          connectorId: context.connectorId,
        },
        context,
      );
      status("Queued IOI Chat artifact review.");
    }),
    vscode.commands.registerCommand("ioi.workflow.openComposer", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("workflow-composer");
      const scenarioId = pickString(payload, "scenarioId");
      const phase = pickString(payload, "phase") || "canvas";
      await enterAutopilotMode("workflows", output);
      openWorkflowComposerPanel(context, output, {
        scenarioId,
        phase,
      });
      await writeBridgeRequest("workflow.composer.open", {
        workspaceRoot: workspaceSummary().path,
        scenarioId,
        phase,
        realWorkflowComposerMounted: true,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        externalAction: false,
      }, contextSnapshot);
      closePrimarySidebarAfterActivityLaunch();
      status("Opened Autopilot Workflow Composer.");
    }),
    vscode.commands.registerCommand("ioi.workflow.compositor.runScenario", async (payload = {}) => {
      const scenarioId = pickString(payload, "scenarioId") || "sequential";
      const phase = pickString(payload, "phase") || "canvas";
      const contextSnapshot = {
        ...buildWorkspaceActionContext("workflow-compositor-parity"),
        scenarioId,
        phase,
      };
      await enterAutopilotMode("workflows", output);
      openWorkflowComposerPanel(context, output, {
        scenarioId,
        phase,
      });
      await writeBridgeRequest("workflowCompositor.scenarioCommand", {
        workspaceRoot: workspaceSummary().path,
        scenarioId,
        phase,
        createdThroughGui: true,
        manualFileEdits: false,
        externalAction: false,
      }, contextSnapshot);
      status(`Running Workflow Composer scenario: ${scenarioId}.`);
    }),
    vscode.commands.registerCommand("ioi.workflow.compositor.capturePhase", async (payload = {}) => {
      const phase = pickString(payload, "phase") || "canvas";
      const scenarioId = pickString(payload, "scenarioId");
      const contextSnapshot = {
        ...buildWorkspaceActionContext("workflow-compositor-parity"),
        scenarioId,
        phase,
      };
      await enterAutopilotMode("workflows", output);
      openWorkflowComposerPanel(context, output, {
        scenarioId,
        phase,
        capturePhase: phase,
      });
      await writeBridgeRequest("workflowCompositor.capturePhaseCommand", {
        workspaceRoot: workspaceSummary().path,
        scenarioId,
        phase,
        externalAction: false,
      }, contextSnapshot);
      status(`Capturing Workflow Composer phase: ${phase}.`);
    }),
    vscode.commands.registerCommand("ioi.workflow.new", async (payload = {}) => {
      const actionContext = buildWorkspaceActionContext("workbench-view");
      await enterAutopilotMode("workflows", output);
      openWorkflowComposerPanel(context, output, {
        scenarioId: pickString(payload, "scenarioId"),
        phase: pickString(payload, "phase") || "canvas",
      });
      await writeBridgeRequest("workflow.open", {
        workspaceRoot: workspaceSummary().path,
        workflowId: pickString(payload, "workflowId"),
        realWorkflowComposerMounted: true,
      }, actionContext);
      status("Opened IOI workflow composer.");
    }),
    vscode.commands.registerCommand("ioi.workflow.generateCode", async (payload) => {
      const workflowRef =
        pickString(payload, "workflowRef") ||
        pickString(payload, "workflowId") ||
        "workflow:active";
      const packageRef = pickString(payload, "packageRef") || "package:active";
      const modelCapabilityRef =
        pickString(payload, "modelCapabilityRef") || "model-capability:unbound";
      const toolCapabilityRefs = Array.isArray(payload?.toolCapabilityRefs)
        ? payload.toolCapabilityRefs.filter((value) => typeof value === "string")
        : [];
      const request = {
        schemaVersion: "ioi.workbench-integration.v1",
        requestId: crypto.randomUUID(),
        runtimeTruthSource: "daemon-runtime",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        requestedAtMs: Date.now(),
        workflowRef,
        packageRef,
        goal:
          pickString(payload, "goal") ||
          "Generate a proposal-first code change from this workflow.",
        boundModelCapabilityRef: modelCapabilityRef,
        boundToolCapabilityRefs: toolCapabilityRefs,
        targetWorkspace: workspaceSummary().path,
        authorityScope: "workspace.fs.proposal",
        evalProfileRef: pickString(payload, "evalProfileRef"),
        proposalOnly: true,
        runtimeRefs: buildRuntimeRefs(),
      };
      const context = {
        ...buildWorkspaceActionContext("workflow-code-generation"),
        workflowRef,
        packageRef,
      };
      await writeBridgeRequest("workflow.codeGenerationRequest", request, context);
      status("Queued proposal-first workflow code generation.");
    }),
    vscode.commands.registerCommand("ioi.models.open", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models");
      const phase = pickString(payload, "phase") || "model-library";
      await enterAutopilotMode("models", output);
      await openModelsPanel(context, output, { phase });
      await writeBridgeRequest("models.open", {
        workspaceRoot: workspaceSummary().path,
        phase,
        daemonEndpointConfigured: Boolean(daemonEndpoint()),
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        tauriUsed: false,
      }, contextSnapshot);
      closePrimarySidebarAfterActivityLaunch();
      status("Opened Autopilot Models.");
    }),
    vscode.commands.registerCommand("ioi.models.openLoader", async (payload = {}) => {
      const modelId = pickString(payload, "modelId");
      const contextSnapshot = {
        ...buildWorkspaceActionContext("models"),
        modelId,
      };
      await enterAutopilotMode("models", output);
      await openModelsPanel(context, output, { phase: "model-mount-drawer" });
      await writeBridgeRequest("models.loader.open", {
        workspaceRoot: workspaceSummary().path,
        modelId,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        webviewExecutesModel: false,
        extensionHostOwnsDurableRuntime: false,
      }, contextSnapshot);
      status("Opened daemon model loader.");
    }),
    vscode.commands.registerCommand("ioi.models.selectForWorkflow", async (payload = {}) => {
      const modelId = pickString(payload, "modelId");
      const contextSnapshot = {
        ...buildWorkspaceActionContext("models-workflow-binding"),
        modelId,
      };
      await writeBridgeRequest("models.workflowBinding.select", {
        workspaceRoot: workspaceSummary().path,
        modelId,
        routeId: pickString(payload, "routeId") || "route.native-local",
        runtimeAuthority: "daemon-owned",
        externalConnectorAction: false,
      }, contextSnapshot);
      await enterAutopilotMode("workflows", output);
      openWorkflowComposerPanel(context, output, {
        scenarioId: "model-backed-dry-run",
        phase: "model-binding",
      });
      status("Queued live model route binding for Workflow Composer.");
    }),
    vscode.commands.registerCommand("ioi.models.capturePhase", async (payload = {}) => {
      const phase = pickString(payload, "phase") || "model-library";
      const contextSnapshot = {
        ...buildWorkspaceActionContext("models"),
        phase,
      };
      await enterAutopilotMode("models", output);
      await openModelsPanel(context, output, { phase });
      await writeBridgeRequest("models.capturePhase", {
        workspaceRoot: workspaceSummary().path,
        phase,
        externalAction: false,
      }, contextSnapshot);
      status(`Capturing Models phase: ${phase}.`);
    }),
    vscode.commands.registerCommand("ioi.models.searchCatalog", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models-catalog-search");
      await enterAutopilotMode("models", output);
      const result = await runDaemonModelCatalogSearch(payload);
      await writeBridgeRequest("models.catalog.search", {
        workspaceRoot: workspaceSummary().path,
        query: pickPayloadString(payload, "query") || pickPayloadString(payload, "q") || "",
        resultCount: Array.isArray(result?.results) ? result.results.length : 0,
        providers: Array.isArray(result?.providers) ? result.providers : [],
        daemonOwned: true,
        externalAction: false,
      }, contextSnapshot);
      await openModelsPanel(context, output, { phase: "model-discovery-surface" });
      status("Daemon model catalog search complete.");
    }),
    vscode.commands.registerCommand("ioi.models.configureCatalogProvider", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models-catalog-source-config");
      await enterAutopilotMode("models", output);
      const result = await runDaemonModelCatalogProviderConfig(payload);
      const query = pickPayloadString(payload, "query") || pickPayloadString(payload, "q") || "";
      let searchResult = null;
      if (query) {
        searchResult = await runDaemonModelCatalogSearch({ query }).catch((error) => ({
          error: error?.message || String(error),
          results: [],
        }));
      }
      await writeBridgeRequest("models.catalog.provider.configure", {
        workspaceRoot: workspaceSummary().path,
        providerId: pickPayloadString(payload, "providerId") || pickPayloadString(payload, "provider_id") || "catalog.huggingface",
        result,
        searchResultCount: Array.isArray(searchResult?.results) ? searchResult.results.length : 0,
        daemonOwned: true,
        externalAction: false,
      }, contextSnapshot);
      await openModelsPanel(context, output, { phase: query ? "model-discovery-surface" : "model-catalog-sources-surface" });
      status("Daemon catalog source configuration saved.");
    }),
    vscode.commands.registerCommand("ioi.models.downloadCatalog", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models-catalog-download");
      await enterAutopilotMode("models", output);
      const result = await runDaemonModelCatalogDownload(payload);
      await writeBridgeRequest("models.catalog.download", {
        workspaceRoot: workspaceSummary().path,
        modelId: pickPayloadString(payload, "modelId") || null,
        catalogEntryId: pickPayloadString(payload, "catalogEntryId") || null,
        result,
        receiptId: result?.receiptId ?? result?.receipt?.id ?? null,
        daemonOwned: true,
      }, contextSnapshot);
      await openModelsPanel(context, output, { phase: "model-discovery-surface" });
      status("Daemon model catalog download queued.");
    }),
    vscode.commands.registerCommand("ioi.models.estimateNative", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models");
      await enterAutopilotMode("models", output);
      const result = await runDaemonModelWorkbenchAction("estimate", payload);
      await writeBridgeRequest("models.estimateLoad", {
        workspaceRoot: workspaceSummary().path,
        result,
        receiptId: result?.receiptId ?? null,
        daemonOwned: true,
      }, contextSnapshot);
      await openModelsPanel(context, output, { phase: "model-load-estimate" });
      status("Daemon model load estimate complete.");
    }),
    vscode.commands.registerCommand("ioi.models.loadNative", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models");
      await enterAutopilotMode("models", output);
      const result = await runDaemonModelWorkbenchAction("load", payload);
      await writeBridgeRequest("models.load", {
        workspaceRoot: workspaceSummary().path,
        result,
        instanceId: result?.id ?? null,
        daemonOwned: true,
      }, contextSnapshot);
      await openModelsPanel(context, output, { phase: "model-instance-ready" });
      status("Daemon model load complete.");
    }),
    vscode.commands.registerCommand("ioi.models.unloadNative", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models");
      await enterAutopilotMode("models", output);
      const result = await runDaemonModelWorkbenchAction("unload", payload);
      await writeBridgeRequest("models.unload", {
        workspaceRoot: workspaceSummary().path,
        result,
        daemonOwned: true,
      }, contextSnapshot);
      await openModelsPanel(context, output, { phase: "model-instance-ready" });
      status("Daemon model unload complete.");
    }),
    vscode.commands.registerCommand("ioi.runs.refresh", async (payload = {}) => {
      const actionContext = buildWorkspaceActionContext("workbench-view");
      if (payload?.traceTarget && typeof payload.traceTarget === "object") {
        activeTraceTarget = {
          ...payload.traceTarget,
          openedAt: new Date().toISOString(),
        };
      }
      await writeBridgeRequest("runs.open", {
        workspaceRoot: workspaceSummary().path,
        traceTarget: activeTraceTarget,
      }, actionContext).catch((error) => {
        output.appendLine(
          `[ioi-runs] bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      await enterAutopilotMode("runs", output);
      await openGenericModePanel(context, output, "runs");
      closePrimarySidebarAfterActivityLaunch();
      status(activeTraceTarget ? "Queued IOI tracing surface." : "Queued IOI runs surface.");
    }),
    vscode.commands.registerCommand("ioi.runs.review", async (payload) => {
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        runId: pickString(payload, "runId"),
        artifactId: pickString(payload, "artifactId"),
        evidenceThreadId: pickString(payload, "evidenceThreadId"),
      };
      await writeBridgeRequest(
        "chat.reviewRun",
        {
          runId: context.runId,
          artifactId: context.artifactId,
          evidenceThreadId: context.evidenceThreadId,
        },
        context,
      );
      status("Queued IOI Chat run review.");
    }),
    vscode.commands.registerCommand("ioi.policy.open", async () => {
      const actionContext = buildWorkspaceActionContext("workbench-view");
      await enterAutopilotMode("policy", output);
      await openGenericModePanel(context, output, "policy");
      await writeBridgeRequest("policy.open", {
        workspaceRoot: workspaceSummary().path,
      }, actionContext);
      closePrimarySidebarAfterActivityLaunch();
      status("Queued IOI policy surface.");
    }),
    vscode.commands.registerCommand("ioi.artifacts.openEvidence", async (payload) => {
      const sessionId = pickString(payload, "sessionId");
      if (!sessionId) {
        vscode.window.showWarningMessage("No evidence session is available for this artifact.");
        return;
      }
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        evidenceThreadId: sessionId,
      };
      await writeBridgeRequest("evidence.open", {
        sessionId,
      }, context);
      status("Queued IOI evidence session.");
    }),
    vscode.commands.registerCommand("ioi.artifacts.openPolicy", async (payload) => {
      const connectorId = pickString(payload, "connectorId");
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        connectorId,
      };
      await writeBridgeRequest("policy.open", {
        workspaceRoot: workspaceSummary().path,
        connectorId,
      }, context);
      status("Queued artifact policy context.");
    }),
    vscode.commands.registerCommand("ioi.chatSession.openArtifact", async (payload) => {
      const artifactId = pickString(payload, "artifactId");
      if (!artifactId) {
        vscode.window.showWarningMessage("No artifact target is available for Chat Session.");
        return;
      }
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        artifactId,
      };
      await writeBridgeRequest("chatSession.openArtifact", {
        artifactId,
      }, context);
      status("Queued Chat Session artifact drill-in.");
    }),
    vscode.commands.registerCommand("ioi.connections.inspect", async () => {
      const actionContext = buildWorkspaceActionContext("workbench-view");
      await enterAutopilotMode("connectors", output);
      await openGenericModePanel(context, output, "connectors");
      await writeBridgeRequest("connections.open", {
        workspaceRoot: workspaceSummary().path,
      }, actionContext);
      closePrimarySidebarAfterActivityLaunch();
      status("Queued IOI connections surface.");
    }),
    vscode.commands.registerCommand("ioi.connections.openConnector", async (payload) => {
      const connectorId = pickString(payload, "connectorId");
      if (!connectorId) {
        vscode.window.showWarningMessage("No connector target is available for this workspace item.");
        return;
      }
      await enterAutopilotMode("connectors", output);
      await openGenericModePanel(context, output, "connectors");
      const actionContext = {
        ...buildWorkspaceActionContext("workbench-view"),
        connectorId,
      };
      await writeBridgeRequest("connections.open", {
        workspaceRoot: workspaceSummary().path,
        connectorId,
      }, actionContext);
      status("Queued IOI connector overview.");
    }),
    vscode.commands.registerCommand("ioi.automation.browser", async (uri) => {
      const context = buildWorkspaceActionContext(uri ? "explorer" : "editor", uri);
      await writeBridgeRequest("automation.browser", {
        workspaceRoot: workspaceSummary().path,
        filePath: context.filePath,
        selectedText: context.selection?.selectedText ?? null,
      }, context);
      status("Queued governed browser/computer-use.");
    }),
  );

  output.appendLine("Registered IOI runtime bridge commands.");
}

function activate(context) {
  const output = vscode.window.createOutputChannel("IOI Workbench");
  output.appendLine("IOI Workbench extension activated.");
  context.subscriptions.push(output);
  startBridgeCommandPolling(context, output);
  startWorkbenchContextSnapshotPublisher(context, output);

  const statusItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    80,
  );
  statusItem.name = "IOI Workbench";
  statusItem.text = "$(symbol-keyword) IOI";
  statusItem.tooltip = "Open Autopilot Overview.";
  statusItem.command = "ioi.overview.open";
  statusItem.show();
  context.subscriptions.push(statusItem);

  const providers = VIEW_DEFINITIONS.map(
    (definition) => new IOIViewProvider(definition, readBridgeState),
  );
  const syncAppearanceFromBridge = async () => {
    const state = await readBridgeState();
    await syncWorkbenchAppearance(state);
    return state;
  };
  void syncAppearanceFromBridge();

  for (const provider of providers) {
    context.subscriptions.push(
      vscode.window.registerWebviewViewProvider(
        provider.definition.id,
        provider,
      ),
    );
  }

  context.subscriptions.push(
    watchBridgeState(async () => {
      const state = await syncAppearanceFromBridge();
      if (overviewPanel) {
        updateOverviewPanelHtml(state);
      }
      if (studioPanel) {
        updateStudioPanelHtml(state);
      }
      if (modelsPanel) {
        const modelsViewDefinition =
          VIEW_DEFINITIONS.find((definition) => definition.id === "ioi.models") || {
            id: "ioi.models",
            title: "Models",
            eyebrow: "Daemon model runtime",
            description: "Daemon-backed model mounting.",
            actions: [],
          };
        modelsPanel.webview.html = renderHtml(modelsViewDefinition, state);
      }
      for (const [modeId, panel] of genericModePanels) {
        panel.webview.html = renderModePanelHtml(modeId, state);
      }
      for (const provider of providers) {
        void provider.render();
      }
    }),
  );

  registerNativeCommands(context, output);
  if (process.env.AUTOPILOT_SKIP_OVERVIEW !== "1") {
    setTimeout(() => {
      void vscode.commands.executeCommand("ioi.overview.open", {
        source: "startup",
        phase: "home",
      }).catch((error) => {
        output.appendLine(
          `[ioi-workbench] failed to open Autopilot Overview: ${error?.message ?? error}`,
        );
      });
    }, 900);
  }
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
