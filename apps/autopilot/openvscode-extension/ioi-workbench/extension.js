const crypto = require("crypto");
const http = require("http");
const https = require("https");
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
];

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

function requestJson(baseUrl, routePath, { method = "GET", payload, token } = {}) {
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
let studioPanel = null;
let workflowComposerPanel = null;
let modelsPanel = null;

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
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi-chat",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.chat",
          },
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
  const common =
    'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linecap="round" stroke-linejoin="round" focusable="false" aria-hidden="true"';
  switch (name) {
    case "paperclip":
      return `<svg ${common}><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48" /></svg>`;
    case "device-desktop":
      return `<svg ${common}><rect x="4.5" y="5" width="15" height="10.5" rx="1.4" /><path d="M9 19h6M12 15.5V19" /></svg>`;
    case "symbol-operator":
      return `<svg ${common}><path d="M7.25 4.75v5M4.75 7.25h5M14.25 7.25h5M5.5 15.5l4 4M9.5 15.5l-4 4M14.25 15.75h5M14.25 19.25h5" /><circle cx="16.75" cy="14" r=".55" fill="currentColor" stroke="none" /><circle cx="16.75" cy="21" r=".55" fill="currentColor" stroke="none" /></svg>`;
    case "chevron-down":
      return `<svg ${common}><path d="M6 9l6 6 6-6" /></svg>`;
    case "tools":
      return `<svg viewBox="0 0 16 16" fill="currentColor" focusable="false" aria-hidden="true"><path d="M5.66901 0.999997C5.52101 0.945997 5.34701 0.968997 5.21401 1.062C5.08101 1.155 5.00201 1.308 5.00201 1.47V3.286C5.00201 3.561 4.77701 3.786 4.50201 3.786C4.22701 3.786 4.00201 3.561 4.00201 3.286V1.47C4.00201 1.308 3.92301 1.156 3.79001 1.062C3.65801 0.967997 3.48501 0.945997 3.33501 0.999997C1.93901 1.495 1.00201 2.816 1.00201 4.287C1.00201 5.646 1.79201 6.876 3.00201 7.449V13.5C3.00201 14.327 3.67501 15 4.50201 15C5.32901 15 6.00201 14.327 6.00201 13.5V7.449C7.21201 6.876 8.00201 5.646 8.00201 4.287C8.00201 2.816 7.06401 1.495 5.66901 0.999997ZM5.33601 6.644C5.13601 6.714 5.00201 6.904 5.00201 7.116V13.501C5.00201 13.776 4.77701 14.001 4.50201 14.001C4.22701 14.001 4.00201 13.776 4.00201 13.501V7.116C4.00201 6.904 3.86801 6.715 3.66801 6.644C2.67201 6.292 2.00201 5.345 2.00201 4.288C2.00201 3.496 2.38501 2.765 3.00201 2.301V3.288C3.00201 4.115 3.67501 4.788 4.50201 4.788C5.32901 4.788 6.00201 4.115 6.00201 3.288V2.301C6.61901 2.765 7.00201 3.496 7.00201 4.288C7.00201 5.346 6.33201 6.293 5.33601 6.644ZM13.5 8H13.002V4.118L13.449 3.223C13.509 3.105 13.518 2.967 13.476 2.841L12.976 1.341C12.908 1.137 12.716 0.998997 12.501 0.998997H10.501C10.286 0.998997 10.095 1.137 10.026 1.341L9.52601 2.841C9.48401 2.967 9.49401 3.105 9.55301 3.223L10 4.118V8H9.50001C9.22401 8 9.00001 8.224 9.00001 8.5V12.5C9.00001 13.879 10.121 15 11.5 15C12.879 15 14 13.879 14 12.5V8.5C14 8.224 13.776 8 13.5 8ZM10.862 2.001H12.141L12.461 2.963L12.054 3.777C12.02 3.846 12.001 3.923 12.001 4.001V8.001H11.001V4.001C11.001 3.924 10.983 3.847 10.949 3.777L10.542 2.963L10.862 2.001ZM13.002 12.5C13.002 13.327 12.329 14 11.502 14C10.675 14 10.002 13.327 10.002 12.5V9H13.002V12.5Z" /></svg>`;
    case "send":
      return `<svg ${common} fill="none"><path d="M5 4.5 20 12 5 19.5v-15Z" /><path d="M5 12h9.5" /></svg>`;
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
              <span class="operator-chat-button-icon">${renderNativeChatIcon("symbol-operator")}</span>
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

function renderStudioView() {
  return `
    <section class="workflow-direct-open" data-inspection-target="studio-direct-open" aria-label="Opening Agent Studio">
      <span>Opening Studio...</span>
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
    server: snapshot.server || {},
    runtimePreference: snapshot.runtimePreference || {},
    generatedAt: snapshot.generatedAt || snapshot.server?.generatedAt || null,
  };
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
      const actionPayload = {
        modelId: artifact.modelId || artifact.id,
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
          data-model-status="${escapeHtml(instance?.status || endpoint?.status || artifact.status || "installed")}"
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
          <td>${modelStatusPill(instance?.status || endpoint?.status || artifact.status || "installed")}</td>
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
  const discoverBlocked = !snapshot.server.discoverApi && !snapshot.server.downloadApi;

  return `
      <section
        class="model-workbench models-lmstudio ${compact ? "is-compact" : ""}"
      data-testid="autopilot-models-mode"
      data-inspection-target="autopilot-models-mode"
      data-daemon-backed="${modelStatus.status === "connected" ? "true" : "false"}"
      >
      ${
        modelStatus.status === "degraded"
          ? `<section class="model-state-banner is-error" data-testid="model-error-state"><strong>Daemon model runtime degraded</strong><span>${escapeHtml(modelStatus.error || "The model daemon is configured but not reachable.")}</span></section>`
          : ""
      }
      <section class="models-lmstudio__primary" data-testid="models-lmstudio-shell">
        <aside class="models-lmstudio__rail" data-testid="models-left-rail" aria-label="Model categories">
          <strong>My Models</strong>
          <button class="is-active" type="button">View All</button>
          <button type="button">LLMs <span>${escapeHtml(String(snapshot.artifacts.filter((artifact) => modelDomain(artifact) === "llm").length))}</span></button>
          <button type="button">Text Embedding <span>${escapeHtml(String(snapshot.artifacts.filter((artifact) => modelDomain(artifact) === "embedding").length))}</span></button>
          <button type="button">Vision / Tools <span>${escapeHtml(String(snapshot.artifacts.filter((artifact) => modelDomain(artifact) === "vlm").length))}</span></button>
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
            ${renderCommandButton({ label: "Use in Workflow", command: "ioi.models.selectForWorkflow", payload: { modelId: selectedArtifact.modelId || selectedEndpoint.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id } })}
            ${renderCommandButton({ label: "Load Model", command: "ioi.models.openLoader", payload: { modelId: selectedArtifact.modelId || selectedEndpoint.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id } })}
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
              <div><dt>Model</dt><dd>${escapeHtml(selectedArtifact.modelId || selectedArtifact.id || "none")}</dd></div>
              <div><dt>File</dt><dd>${escapeHtml(selectedArtifact.fileName || selectedArtifact.path || "daemon artifact")}</dd></div>
              <div><dt>Format</dt><dd>${escapeHtml(selectedArtifact.format || "GGUF")}</dd></div>
              <div><dt>Quantization</dt><dd>${escapeHtml(selectedArtifact.quantization || "unknown")}</dd></div>
              <div><dt>Arch</dt><dd>${escapeHtml(modelArch(selectedArtifact))}</dd></div>
              <div><dt>Capabilities</dt><dd>${renderModelTags(artifactCapabilities)}</dd></div>
              <div><dt>Size on disk</dt><dd>${escapeHtml(formatBytes(selectedArtifact.sizeBytes ?? selectedArtifact.size_bytes))}</dd></div>
            </dl>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="load" data-testid="model-inspector-load-panel">
            <h3>Load Settings</h3>
            <dl>
              <div><dt>Identifier</dt><dd>${escapeHtml(loadOptions.identifier)}</dd></div>
              <div><dt>Context length</dt><dd>${escapeHtml(String(loadOptions.contextLength))}</dd></div>
              <div><dt>GPU offload</dt><dd>${escapeHtml(String(loadOptions.gpuOffload))}</dd></div>
              <div><dt>Auto unload</dt><dd>${escapeHtml(`${loadOptions.idleTtlSeconds}s idle TTL`)}</dd></div>
            </dl>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="inference" data-testid="model-inspector-inference-panel">
            <h3>Inference</h3>
            <dl>
              <div><dt>Endpoint</dt><dd>${escapeHtml(selectedEndpoint.id || "not mounted")}</dd></div>
              <div><dt>Route</dt><dd>${escapeHtml(selectedRoute.id || "route pending")}</dd></div>
              <div><dt>API</dt><dd>${escapeHtml(selectedEndpoint.apiFormat || "OpenAI compatible")}</dd></div>
              <div><dt>Last invocation</dt><dd>${escapeHtml(invokeReceipt?.id || "none")}</dd></div>
            </dl>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="policy" data-testid="model-inspector-policy-panel">
            <h3>Policy</h3>
            <dl>
              <div><dt>Authority</dt><dd>daemon-owned</dd></div>
              <div><dt>Privacy</dt><dd>${escapeHtml(selectedRoute.privacy || selectedEndpoint.privacyClass || "local_first")}</dd></div>
              <div><dt>Approvals</dt><dd>${escapeHtml(selectedRoute.approvalPolicy || "route policy")}</dd></div>
              <div><dt>Mutation path</dt><dd>receipted daemon request</dd></div>
            </dl>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="routes" data-testid="model-inspector-routes-panel">
            <h3>Routes</h3>
            <dl>
              <div><dt>Route</dt><dd>${escapeHtml(selectedRoute.id || "none")}</dd></div>
              <div><dt>Selected model</dt><dd>${escapeHtml(routeReceipt?.details?.selectedModel || selectedEndpoint.modelId || selectedArtifact.modelId || "none")}</dd></div>
              <div><dt>Backend</dt><dd>${escapeHtml(selectedBackend.id || selectedEngine.id || "pending")}</dd></div>
              <div><dt>Receipt</dt><dd>${escapeHtml(routeReceipt?.id || "pending")}</dd></div>
            </dl>
          </section>
          <section class="models-lmstudio__tab-panel" data-model-inspector-panel="receipts" data-testid="model-inspector-receipts-panel">
            <h3>Receipts</h3>
            <div class="model-log-list">${renderModelReceiptRows(snapshot, 4)}</div>
          </section>
        </aside>
      </section>

      <section class="models-lmstudio__ops" data-testid="model-ops-region">
        <article class="model-surface model-quick-loader" data-testid="model-mount-drawer">
          <div class="model-surface__head">
            <div>
              <span>Quick Loader</span>
              <strong>Type to filter models...</strong>
            </div>
            ${modelStatusPill("daemon catalog")}
          </div>
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
        </article>

        <article class="model-surface model-load-dialog" data-testid="model-load-dialog">
          <header class="models-lmstudio__dialog-title">
            <button class="model-icon-button" type="button" data-command="ioi.models.open" aria-label="Back to model library">Back</button>
            <h2>${escapeHtml(modelDisplayName(selectedArtifact))}</h2>
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
            ${renderCommandButton({ label: "Cancel", command: "ioi.models.open" })}
            <button
              class="action"
              type="button"
              data-testid="model-estimate-button"
              data-command="ioi.models.estimateNative"
              ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id, contextLength: loadOptions.contextLength, gpuOffload: loadOptions.gpuOffload })}
            >Estimate</button>
            <button
              class="action"
              type="button"
              data-testid="model-load-confirm-button"
              data-command="ioi.models.loadNative"
              ${commandPayloadAttr({ modelId: selectedArtifact.modelId || selectedArtifact.id, endpointId: selectedEndpoint.id, contextLength: loadOptions.contextLength, gpuOffload: loadOptions.gpuOffload })}
            >Load Model</button>
          </div>
        </article>

        <article class="model-surface" data-testid="model-runtime-backend">
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
        </article>

        <article class="model-surface" data-testid="model-discover-view">
          <div class="model-surface__head">
            <div>
              <span>Discover / Download</span>
              <strong>${discoverBlocked ? "daemon API blocker" : "registry connected"}</strong>
            </div>
            ${modelStatusPill(discoverBlocked ? "blocked" : "ready")}
          </div>
          <label class="models-lmstudio__search">
            <span aria-hidden="true">Find</span>
            <input data-testid="model-discover-search-input" type="search" placeholder="Search local models by name or author..." />
          </label>
          <button class="model-discover-row is-selected" type="button" data-testid="model-discover-result-row">
            <span>${escapeHtml(selectedArtifact.modelId || "registry search pending")}</span>
            ${renderModelTags([modelParams(selectedArtifact), modelArch(selectedArtifact), "GGUF"])}
          </button>
          <section data-testid="model-discover-detail">
            <h3>${escapeHtml(modelDisplayName(selectedArtifact))}</h3>
            <p>${escapeHtml(selectedArtifact.description || "Discover/download is intentionally blocked until daemon-owned registry search and artifact download APIs are available.")}</p>
          </section>
          <div class="model-download-options" data-testid="model-download-options">
            <span>${escapeHtml(selectedArtifact.quantization || "Q4_K_M")}</span>
            <strong>${escapeHtml(formatBytes(selectedArtifact.sizeBytes ?? selectedArtifact.size_bytes))}</strong>
            <button type="button" data-testid="model-download-button" disabled>Download</button>
          </div>
          <div class="model-readme-panel" data-testid="model-readme-panel">README projection awaits daemon registry metadata.</div>
        </article>

        <article class="model-surface" data-testid="model-instance-ready">
          <div class="model-surface__head">
            <div>
              <span>Running Models</span>
              <strong>${escapeHtml(selectedInstance.modelId || selectedEndpoint.modelId || "No loaded instance")}</strong>
            </div>
            ${modelStatusPill(selectedInstance.status || "empty")}
          </div>
          <div class="model-progress" data-testid="model-load-progress"><span style="width: ${selectedInstance.status === "loaded" ? "100" : "18"}%"></span></div>
          <div class="model-running-row" data-testid="model-running-instance-row">
            <dl>
              <div><dt>Instance</dt><dd>${escapeHtml(selectedInstance.id || "none")}</dd></div>
              <div><dt>Identifier</dt><dd>${escapeHtml(selectedInstance.identifier || "none")}</dd></div>
              <div><dt>Backend</dt><dd>${escapeHtml(selectedInstance.backendId || selectedBackend.id || "none")}</dd></div>
              <div><dt>Receipt evidence</dt><dd>${escapeHtml(selectedInstance.providerEvidenceRefs?.join(", ") || "pending")}</dd></div>
            </dl>
            <button
              class="action"
              type="button"
              data-testid="model-running-unload-button"
              data-command="ioi.models.unloadNative"
              ${commandPayloadAttr({ instanceId: selectedInstance.id })}
              ${selectedInstance.id ? "" : "disabled"}
            >Unload</button>
          </div>
        </article>

        <article class="model-surface" data-testid="model-server-api">
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
        </article>

        <article class="model-surface" data-testid="workflow-node-live-model-binding">
          <div class="model-surface__head">
            <div>
              <span>Workflow Binding</span>
              <strong>${escapeHtml(selectedRoute.id || "route pending")}</strong>
            </div>
            ${modelStatusPill(routeReceipt ? "route receipted" : "ready")}
          </div>
          <dl>
            <div><dt>Route</dt><dd>${escapeHtml(selectedRoute.id || "none")}</dd></div>
            <div><dt>Selected model</dt><dd>${escapeHtml(routeReceipt?.details?.selectedModel || selectedEndpoint.modelId || selectedArtifact.modelId || "none")}</dd></div>
            <div><dt>Policy</dt><dd>${escapeHtml(selectedRoute.privacy || "local_first")}</dd></div>
            <div><dt>Receipt</dt><dd>${escapeHtml(routeReceipt?.id || "pending")}</dd></div>
          </dl>
          ${renderCommandButton({ label: "Bind in Composer", command: "ioi.workflow.openComposer", payload: { scenarioId: "model-backed-dry-run", phase: "model-binding" } })}
        </article>

        <article class="model-surface" data-testid="workflow-live-model-dry-run-timeline">
          <div class="model-surface__head">
            <div>
              <span>Workflow Dry-run Timeline</span>
              <strong>${escapeHtml(invokeReceipt ? "model invocation complete" : "ready for daemon dry-run")}</strong>
            </div>
            ${modelStatusPill(invokeReceipt ? "receipted" : "pending")}
          </div>
          <ol class="model-timeline">
            <li>route selected: ${escapeHtml(routeReceipt?.details?.routeId || selectedRoute.id || "route")}</li>
            <li>model invoked: ${escapeHtml(invokeReceipt?.details?.selectedModel || selectedEndpoint.modelId || selectedArtifact.modelId || "model")}</li>
            <li>runtime evidence: ${escapeHtml(invokeReceipt?.details?.backendId || selectedBackend.id || selectedEngine.id || "backend")}</li>
          </ol>
        </article>

        <article class="model-surface model-surface--wide" data-testid="model-invocation-receipts-replay">
          <div class="model-surface__head">
            <div>
              <span>Receipts / Replay</span>
              <strong>${escapeHtml(snapshot.receipts.length)} daemon receipts</strong>
            </div>
            ${modelStatusPill("daemon-owned")}
          </div>
          <div class="model-log-list">${renderModelReceiptRows(snapshot)}</div>
        </article>
      </section>
    </section>
  `;
}

function renderModelsView(state) {
  return `
    <section data-inspection-target="ioi-models-view">
      ${renderModelsPanelBody(state, { compact: true })}
    </section>
  `;
}

function renderRunsView(state) {
  return renderItems(
    state.runs || [],
    "No active runtime runs are currently attached to this workspace snapshot.",
    (run) => `
      <article class="item-card">
        <div class="item-head">
          <strong>${escapeHtml(run.label || run.runId)}</strong>
          <span class="status-pill">${escapeHtml(run.status)}</span>
        </div>
        <p>${escapeHtml(run.summary || "Runtime run")}</p>
        <code>${escapeHtml(run.currentStepLabel || run.runId)}</code>
        <div class="actions item-actions">
          ${renderCommandButton({
            label: "Review in Chat",
            command: "ioi.runs.review",
            payload: {
              runId: run.runId,
              evidenceThreadId: run.reviewSessionId,
              artifactId: run.artifactId,
            },
          })}
          ${
            run.reviewSessionId
              ? renderCommandButton({
                  label: "Open active session",
                  command: "ioi.artifacts.openEvidence",
                  payload: {
                    sessionId: run.reviewSessionId,
                  },
                })
              : ""
          }
          ${
            run.artifactId
              ? renderCommandButton({
                  label: "Open linked artifact",
                  command: "ioi.chatSession.openArtifact",
                  payload: {
                    artifactId: run.artifactId,
                  },
                })
              : ""
          }
          ${
            run.artifactId
              ? renderCommandButton({
                  label: "Review linked artifact in Chat",
                  command: "ioi.artifacts.review",
                  payload: {
                    artifactId: run.artifactId,
                    evidenceThreadId: run.reviewSessionId,
                  },
                })
              : ""
          }
          ${renderCommandButton({
            label: "Open runs surface",
            command: "ioi.runs.refresh",
          })}
        </div>
      </article>
    `,
  );
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

function renderBody(viewId, state) {
  switch (viewId) {
    case "ioi.chat":
      return renderChatView(state);
    case "ioi.studio":
      return renderStudioView(state);
    case "ioi.workflows":
      return renderWorkflowView(state);
    case "ioi.models":
      return renderModelsView(state);
    case "ioi.runs":
      return renderRunsView(state);
    case "ioi.artifacts":
      return renderArtifactsView(state);
    case "ioi.policy":
      return renderPolicyView(state);
    case "ioi.connections":
      return renderConnectionsView(state);
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
      }
      .model-table th {
        color: var(--vscode-descriptionForeground);
        font-size: 10px;
        text-transform: uppercase;
      }
      .model-table th:nth-child(1),
      .model-table td:nth-child(1) {
        width: 23%;
      }
      .model-table th:nth-child(2),
      .model-table td:nth-child(2),
      .model-table th:nth-child(3),
      .model-table td:nth-child(3),
      .model-table th:nth-child(5),
      .model-table td:nth-child(5),
      .model-table th:nth-child(6),
      .model-table td:nth-child(6) {
        width: 92px;
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
        grid-template-columns: minmax(160px, 220px) minmax(420px, 1fr) minmax(300px, 360px);
        min-height: 540px;
        border-bottom: 1px solid var(--vscode-panel-border);
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
        display: grid;
        grid-template-rows: auto minmax(0, 1fr) auto;
        padding: 0;
        background: var(--vscode-editor-background);
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
        align-content: start;
        gap: 10px;
        padding: 10px 14px;
        border-right: 0;
        border-left: 1px solid var(--vscode-panel-border);
        background: var(--vscode-sideBar-background);
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
      }
      .model-icon-label {
        display: inline-flex;
        margin-right: 4px;
        color: var(--vscode-textLink-foreground);
      }
      .models-lmstudio__inspector-actions {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .models-lmstudio__tabs {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-editor-background) 72%, var(--vscode-sideBar-background));
        padding: 3px;
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
        display: grid;
        gap: 8px;
      }
      .models-lmstudio__tab-panel h3 {
        margin: 2px 0 0;
        font-size: 12px;
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
      .model-download-options {
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
      @media (max-width: 1180px) {
        .models-lmstudio__primary,
        .models-lmstudio__ops {
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
          ? renderBody(view.id, state)
        : isWorkflowView
          ? renderBody(view.id, state)
        : isModelsView
          ? renderBody(view.id, state)
        : `
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
          discoverView: document.querySelectorAll('[data-testid="model-discover-view"]').length,
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
      document.querySelectorAll("[data-model-inspector-tab]").forEach((button) => {
        button.addEventListener("click", () => activateModelInspectorTab(button.dataset.modelInspectorTab));
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
          "model-inspector-receipts-panel": "receipts"
        }[phase];
        activateModelInspectorTab(phaseTab);
        const root = document.querySelector('[data-testid="autopilot-models-mode"]');
        const target = phase === "model-library"
          ? root
          : document.querySelector('[data-testid="' + phase + '"]') || root;
        target?.scrollIntoView({ block: phase === "model-library" ? "start" : "center", inline: "center" });
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
    <title>Autopilot Workflow Composer</title>
  </head>
  <body>
    <div id="root"></div>
    <script nonce="${pageNonce}">
      window.__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__ = ${initialState};
    </script>
    <script nonce="${pageNonce}" type="module" src="${scriptUri}"></script>
  </body>
</html>`;
}

function studioPanelHtml(state) {
  const pageNonce = nonce();
  const workspace = state.workspace || workspaceSummary();
  const modelStatus = state.modelMountingStatus?.status || "not_configured";
  const modelLabel =
    modelStatus === "connected"
      ? "Daemon models connected"
      : modelStatus === "degraded"
        ? "Daemon models degraded"
        : "Daemon model route not configured";
  const commandPayloadAttr = (payload) =>
    payload ? ` data-payload="${escapeHtml(JSON.stringify(payload))}"` : "";
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
        --studio-bg: #1f1f1f;
        --studio-panel: #24272a;
        --studio-panel-strong: #2c3035;
        --studio-border: rgba(255, 255, 255, 0.14);
        --studio-border-strong: rgba(255, 255, 255, 0.24);
        --studio-text: #e8e8e8;
        --studio-muted: #aaaeb5;
        --studio-dim: #7c828b;
        --studio-accent: #7aa2ff;
        --studio-good: #7fd1a5;
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: start center;
        padding: clamp(44px, 8vh, 86px) 24px 56px;
        font-family: var(--vscode-font-family, ui-sans-serif, system-ui, sans-serif);
        color: var(--studio-text);
        background: var(--studio-bg);
      }
      .studio-shell {
        width: min(100%, 880px);
        display: grid;
        gap: 28px;
      }
      .studio-hero {
        text-align: center;
        display: grid;
        gap: 10px;
      }
      .studio-mark {
        width: 40px;
        height: 40px;
        margin: 0 auto 2px;
        color: var(--studio-accent);
      }
      .studio-mark svg {
        width: 100%;
        height: 100%;
      }
      h1 {
        margin: 0;
        color: #d7d7d7;
        font-size: clamp(34px, 5vw, 46px);
        font-weight: 400;
        line-height: 1.08;
        letter-spacing: 0;
      }
      .studio-hero p {
        margin: 0;
        color: var(--studio-muted);
        font-size: 17px;
        line-height: 1.45;
      }
      .studio-prompt {
        border: 1px solid var(--studio-border-strong);
        border-radius: 26px;
        padding: 18px 20px 16px;
        background: color-mix(in srgb, var(--studio-bg) 78%, white 3%);
        display: grid;
        gap: 20px;
      }
      .studio-prompt textarea {
        width: 100%;
        min-height: 42px;
        resize: vertical;
        border: 0;
        outline: 0;
        background: transparent;
        color: var(--studio-text);
        font: inherit;
        font-size: 16px;
        line-height: 1.5;
      }
      .studio-prompt textarea::placeholder {
        color: var(--studio-muted);
      }
      .studio-toolbar {
        min-width: 0;
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
      }
      .studio-tool,
      .studio-submit,
      .studio-gallery {
        border: 1px solid transparent;
        border-radius: 999px;
        background: transparent;
        color: var(--studio-text);
        font: inherit;
        cursor: pointer;
      }
      .studio-tool {
        min-height: 28px;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 0 6px;
      }
      .studio-tool svg {
        width: 16px;
        height: 16px;
      }
      .studio-tool.is-muted {
        color: var(--studio-muted);
      }
      .studio-tool:hover,
      .studio-submit:hover,
      .studio-gallery:hover {
        border-color: var(--studio-border-strong);
        background: rgba(255, 255, 255, 0.05);
      }
      .studio-submit {
        margin-left: auto;
        min-height: 30px;
        padding: 0 13px;
        background: #f0f4ff;
        color: #12151a;
      }
      .studio-status {
        min-height: 48px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 14px;
        border: 1px solid color-mix(in srgb, var(--studio-accent) 62%, transparent);
        border-radius: 999px;
        padding: 10px 16px 10px 18px;
        background: color-mix(in srgb, var(--studio-accent) 22%, transparent);
        color: #e9f0ff;
      }
      .studio-status strong {
        font-weight: 500;
      }
      .studio-status button {
        flex: 0 0 auto;
        border: 0;
        background: transparent;
        color: #ffffff;
        font: inherit;
        cursor: pointer;
      }
      .studio-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 16px;
      }
      .studio-card {
        min-height: 86px;
        border: 1px solid transparent;
        border-radius: 22px;
        padding: 18px 20px;
        display: grid;
        grid-template-columns: 34px 1fr;
        gap: 15px;
        align-items: center;
        background: var(--studio-panel);
        color: var(--studio-text);
        text-align: left;
        font: inherit;
        cursor: pointer;
      }
      .studio-card:hover,
      .studio-card:focus-visible {
        outline: 0;
        border-color: var(--studio-border-strong);
        background: var(--studio-panel-strong);
      }
      .studio-card__icon {
        color: var(--studio-accent);
      }
      .studio-card__icon svg {
        width: 24px;
        height: 24px;
      }
      .studio-card strong {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 5px;
        font-size: 16px;
        font-weight: 560;
      }
      .studio-card strong + span {
        color: var(--studio-muted);
        line-height: 1.38;
      }
      .studio-pill {
        border-radius: 4px;
        padding: 2px 5px;
        background: color-mix(in srgb, var(--studio-accent) 50%, white 30%);
        color: #10151f;
        font-size: 11px;
        font-weight: 600;
      }
      .studio-footer {
        display: flex;
        justify-content: center;
      }
      .studio-gallery {
        min-height: 36px;
        padding: 0 16px;
        color: var(--studio-accent);
        border-color: var(--studio-border-strong);
      }
      @media (max-width: 760px) {
        body {
          padding: 34px 16px 42px;
        }
        .studio-grid {
          grid-template-columns: 1fr;
        }
        .studio-status {
          align-items: flex-start;
          border-radius: 18px;
          flex-direction: column;
        }
        .studio-submit {
          margin-left: 0;
        }
      }
    </style>
  </head>
  <body>
    <main class="studio-shell" data-testid="agent-studio-landing" data-workspace="${escapeHtml(workspace.name || "ioi")}">
      <header class="studio-hero">
        <div class="studio-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none">
            <path d="M11.8 3.8 13.9 9l5.2 2.1-5.2 2.1-2.1 5.2-2.1-5.2-5.2-2.1L9.7 9l2.1-5.2Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
            <path d="m18.4 3.4.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8.8-2Z" stroke="currentColor" stroke-width="1.35" stroke-linejoin="round"/>
          </svg>
        </div>
        <h1>Agent Studio</h1>
        <p>Build agents, workflows, and applications with daemon-owned models.</p>
      </header>

      <form class="studio-prompt" data-studio-prompt-form>
        <textarea data-studio-prompt rows="2" placeholder="Describe an agent, workflow, or app to build" aria-label="Describe an agent, workflow, or app to build"></textarea>
        <div class="studio-toolbar">
          <button class="studio-tool" type="button" data-command="ioi.workflow.openComposer" title="New workflow">
            <svg viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
          </button>
          <button class="studio-tool" type="button" data-command="ioi.models.open" title="Models">
            <svg viewBox="0 0 24 24" fill="none"><path d="M4 7h16M4 17h16M6 4h12a2 2 0 0 1 2 2v4H4V6a2 2 0 0 1 2-2Zm0 10h12a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-2a2 2 0 0 1 2-2Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>
            Models
          </button>
          <button class="studio-tool" type="button" data-command="ioi.studio.agentBuilder" title="Agents">
            <svg viewBox="0 0 24 24" fill="none"><path d="M5 19 19 5m0 0-4 12-3-5-5-3 12-4Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>
            Agents
          </button>
          <span class="studio-tool is-muted">
            <svg viewBox="0 0 24 24" fill="none"><path d="m12 3 1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6L12 3Z" fill="currentColor"/></svg>
            Platform assistant
          </span>
          <span class="studio-tool is-muted">0 tokens</span>
          <button class="studio-submit" type="submit">Start</button>
        </div>
      </form>

      <section class="studio-status" data-testid="agent-studio-runtime-status">
        <strong>${escapeHtml(modelLabel)}.</strong>
        <button type="button" data-command="ioi.models.open">Open Models</button>
      </section>

      <section class="studio-grid" aria-label="Studio starters">
        <button class="studio-card" type="button" data-command="ioi.workflow.openComposer">
          <span class="studio-card__icon"><svg viewBox="0 0 24 24" fill="none"><path d="M5 6h14M5 18h14M7 6v12m10-12v12M8 10h8m-8 4h8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg></span>
          <span><strong>Workflow Composer</strong><span>Design autonomous systems with canvas, gates, receipts, and replay.</span></span>
        </button>
        <button class="studio-card" type="button" data-command="ioi.studio.agentBuilder">
          <span class="studio-card__icon"><svg viewBox="0 0 24 24" fill="none"><path d="M5 19 19 5m0 0-4 12-3-5-5-3 12-4Z" stroke="currentColor" stroke-width="1.55" stroke-linejoin="round"/></svg></span>
          <span><strong>Build an agent <small class="studio-pill">Preview</small></strong><span>Shape reusable workers that can become workflow nodes.</span></span>
        </button>
        <button class="studio-card" type="button" data-command="ioi.models.open">
          <span class="studio-card__icon"><svg viewBox="0 0 24 24" fill="none"><path d="M5 4h14v6H5V4Zm0 10h14v6H5v-6Zm3-7h2m-2 10h2m5-10h2m-2 10h2" stroke="currentColor" stroke-width="1.45" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
          <span><strong>Model routes</strong><span>Mount, load, test, and bind daemon-owned model instances.</span></span>
        </button>
        <button class="studio-card" type="button" data-command="ioi.workflow.openComposer"${commandPayloadAttr({ scenarioId: "connector-fixture", phase: "connector-fixture" })}>
          <span class="studio-card__icon"><svg viewBox="0 0 24 24" fill="none"><path d="M8 12h8M7 8h2a4 4 0 0 1 4 4 4 4 0 0 1-4 4H7m10-8h-2a4 4 0 0 0-4 4 4 4 0 0 0 4 4h2" stroke="currentColor" stroke-width="1.55" stroke-linecap="round"/></svg></span>
          <span><strong>Connector dry run</strong><span>Bind capabilities without live external action.</span></span>
        </button>
      </section>

      <footer class="studio-footer">
        <button class="studio-gallery" type="button" data-command="ioi.commandCenter.open" data-payload='{"initialQuery":"studio prompt gallery"}'>Prompt Gallery</button>
      </footer>
    </main>
    <script nonce="${pageNonce}">
      const vscode = acquireVsCodeApi();
      function parsePayload(raw) {
        if (!raw) return undefined;
        try {
          return JSON.parse(raw);
        } catch (error) {
          console.error("[IOI Studio] Failed to parse payload", error);
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
      document.querySelector("[data-studio-prompt-form]")?.addEventListener("submit", (event) => {
        event.preventDefault();
        const prompt = document.querySelector("[data-studio-prompt]")?.value?.trim();
        if (!prompt) return;
        vscode.postMessage({
          type: "bridgeRequest",
          requestType: "studio.promptSubmit",
          payload: {
            prompt,
            workspaceRoot: ${JSON.stringify(workspace.path || workspace.rootPath || "")},
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio"
          }
        });
      });
    </script>
  </body>
</html>`;
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
      if (
        message?.type === "bridgeRequest" &&
        typeof message.requestType === "string"
      ) {
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
    studioPanel.onDidDispose(() => {
      studioPanel = null;
    });
  }
  studioPanel.webview.html = studioPanelHtml(state);
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
    });
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
    const primarySurfaceByViewId = {
      "ioi.studio": {
        command: "ioi.studio.open",
        payload: {
          source: "activitybar",
          phase: "landing",
        },
      },
      "ioi.workflows": {
        command: "ioi.workflow.openComposer",
        payload: {
          source: "activitybar",
          phase: "canvas",
        },
      },
      "ioi.models": {
        command: "ioi.models.open",
        payload: {
          source: "activitybar",
          phase: "model-library",
        },
      },
    };
    const primarySurface = primarySurfaceByViewId[this.definition.id];
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
    }, 75);
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

function registerNativeCommands(context, output) {
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

  context.subscriptions.push(
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
    vscode.commands.registerCommand("ioi.studio.open", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("studio");
      await openStudioPanel(context, output);
      await writeBridgeRequest("studio.open", {
        workspaceRoot: workspaceSummary().path,
        sourceCommand: "ioi.studio.open",
        phase: pickString(payload, "phase") || "landing",
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
    vscode.commands.registerCommand("ioi.studio.agentBuilder", async () => {
      const contextSnapshot = buildWorkspaceActionContext("agent-builder");
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
      await writeBridgeRequest("chat.focusComposer", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI Chat composer focus.");
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
      await openModelsPanel(context, output, { phase });
      await writeBridgeRequest("models.capturePhase", {
        workspaceRoot: workspaceSummary().path,
        phase,
        externalAction: false,
      }, contextSnapshot);
      status(`Capturing Models phase: ${phase}.`);
    }),
    vscode.commands.registerCommand("ioi.models.estimateNative", async (payload = {}) => {
      const contextSnapshot = buildWorkspaceActionContext("models");
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
      const result = await runDaemonModelWorkbenchAction("unload", payload);
      await writeBridgeRequest("models.unload", {
        workspaceRoot: workspaceSummary().path,
        result,
        daemonOwned: true,
      }, contextSnapshot);
      await openModelsPanel(context, output, { phase: "model-instance-ready" });
      status("Daemon model unload complete.");
    }),
    vscode.commands.registerCommand("ioi.runs.refresh", async () => {
      const context = buildWorkspaceActionContext("workbench-view");
      await writeBridgeRequest("runs.open", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI runs surface.");
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
      const context = buildWorkspaceActionContext("workbench-view");
      await writeBridgeRequest("policy.open", {
        workspaceRoot: workspaceSummary().path,
      }, context);
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
      const context = buildWorkspaceActionContext("workbench-view");
      await writeBridgeRequest("connections.open", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI connections surface.");
    }),
    vscode.commands.registerCommand("ioi.connections.openConnector", async (payload) => {
      const connectorId = pickString(payload, "connectorId");
      if (!connectorId) {
        vscode.window.showWarningMessage("No connector target is available for this workspace item.");
        return;
      }
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        connectorId,
      };
      await writeBridgeRequest("connections.open", {
        workspaceRoot: workspaceSummary().path,
        connectorId,
      }, context);
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
  statusItem.tooltip = "IOI-native workbench surfaces are available.";
  statusItem.command = "workbench.view.extension.ioi-chat";
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

  void vscode.commands.executeCommand("workbench.view.extension.ioi-chat").then(
    () => undefined,
    (error) => {
      output.appendLine(
        `[ioi-workbench] failed to reveal native IOI chat container: ${error?.message ?? error}`,
      );
    },
  );

  context.subscriptions.push(
    watchBridgeState(() => {
      void syncAppearanceFromBridge();
      for (const provider of providers) {
        void provider.render();
      }
    }),
  );

  registerNativeCommands(context, output);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
