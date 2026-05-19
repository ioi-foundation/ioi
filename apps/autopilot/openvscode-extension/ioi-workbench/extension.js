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
    id: "ioi.workflows",
    title: "Workflows",
    eyebrow: "Agent orchestration",
    description:
      "Launch, inspect, and sequence agent workflows without leaving the workbench shell.",
    actions: [
      {
        label: "Open workflow surface",
        command: "ioi.workflow.new",
      },
      {
        label: "Start browser validation",
        command: "ioi.automation.browser",
      },
      {
        label: "Focus explorer",
        command: "workbench.view.explorer",
      },
      {
        label: "Open search",
        command: "workbench.view.search",
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
      activityId: "ioi",
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
        targetId: "activity.ioi",
        label: "IOI activity rail",
        surface: "activity-rail",
        locators: [
          {
            kind: "vscode-command",
            commandId: "workbench.view.extension.ioi",
          },
          {
            kind: "vscode-view",
            viewId: "ioi",
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
        targetId: "workflow.list",
        label: "IOI workflow list",
        surface: "workflow",
        locators: [
          {
            kind: "vscode-command",
            commandId: "ioi.workflow.inspect",
          },
          {
            kind: "vscode-view",
            viewId: "ioi.workflows",
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
  try {
    const raw = await requestBridge("GET", "state");
    return {
      ...defaultBridgeState(),
      ...JSON.parse(raw || "{}"),
    };
  } catch (error) {
    console.error("[IOI Workbench] Failed to read bridge state:", error);
    return defaultBridgeState();
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
      ? ` data-payload="${escapeHtml(JSON.stringify(action.payload))}"`
      : "";
  return `<button class="action" data-command="${escapeHtml(action.command)}"${payload}>${escapeHtml(action.label)}</button>`;
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
      return `<svg ${common}><path d="M7.4 20.2 20.2 7.4l-3.6-3.6L3.8 16.6l-.8 4.4Z" /><path d="m14.6 5.8 3.6 3.6M10.2 15.8l-2 2M13.6 3.8 20.2 10.4" /></svg>`;
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
              class="operator-chat-tool-toggle is-active"
              aria-label="Tool controls"
              data-bridge-request="chat.toolControls"
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

function renderWorkflowView(state) {
  return renderItems(
    state.workflows || [],
    "No workspace workflows were discovered for this repo.",
    (workflow) => `
      <article class="item-card">
        <div class="item-head">
          <strong>${escapeHtml(workflow.slashCommand)}</strong>
          <span>${escapeHtml(workflow.stepCount)} steps</span>
        </div>
        <p>${escapeHtml(workflow.description)}</p>
        <code>${escapeHtml(workflow.relativePath || workflow.workflowId)}</code>
        <div class="actions item-actions">
          ${renderCommandButton({
            label: "Open workflow surface",
            command: "ioi.workflow.new",
            payload: {
              workflowId: workflow.workflowId,
              slashCommand: workflow.slashCommand,
              relativePath: workflow.relativePath,
            },
          })}
          ${renderCommandButton({
            label: "Generate code proposal",
            command: "ioi.workflow.generateCode",
            payload: {
              workflowId: workflow.workflowId,
              workflowRef: workflow.workflowId,
              packageRef: workflow.packageRef,
              goal: workflow.description,
              relativePath: workflow.relativePath,
              modelCapabilityRef: workflow.modelCapabilityRef,
              toolCapabilityRefs: workflow.toolCapabilityRefs,
            },
          })}
          ${renderCommandButton({
            label: "Review workflow file",
            command: "ioi.chat.reviewFile",
            payload: {
              filePath: workflow.relativePath,
            },
          })}
        </div>
      </article>
    `,
  );
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
    case "ioi.workflows":
      return renderWorkflowView(state);
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
    class="${isChatView ? "is-chat-view" : ""}"
    data-autopilot-theme="${escapeHtml(appearanceThemeId)}"
  >
    ${
      isChatView
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

class IOIViewProvider {
  constructor(definition, getState) {
    this.definition = definition;
    this.getState = getState;
    this.webviewView = null;
    this.lastRenderedHtml = null;
  }

  resolveWebviewView(webviewView) {
    this.webviewView = webviewView;
    this.lastRenderedHtml = null;
    webviewView.webview.options = {
      enableScripts: true,
      enableForms: true,
    };
    void this.render();
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
    webviewView.onDidDispose(() => {
      this.webviewView = null;
    });
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
    vscode.commands.registerCommand("ioi.workflow.new", async () => {
      const context = buildWorkspaceActionContext("workbench-view");
      await writeBridgeRequest("workflow.open", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI workflow surface.");
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
