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
    scmState: {
      provider: "unknown",
      branch: null,
      dirty: openEditors.some((editor) => editor.isDirty),
      changedFiles: openEditors
        .filter((editor) => editor.isDirty && editor.filePath)
        .map((editor) => editor.filePath),
      ahead: null,
      behind: null,
    },
    taskState: {
      activeTaskLabels: [],
      recentTaskLabels: [],
      lastExitCode: null,
      checkRefs: [],
    },
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
      ]
    : [];

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
      ...activeEditorTarget,
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
  return `
    <section
      class="operator-chat-pane"
      data-operator-chat-pane="native-openvscode"
      data-inspection-target="native-ioi-chat-pane"
      aria-label="Autopilot Chat"
    >
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
      <div class="operator-chat-bottom">
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
            <button type="button" data-bridge-request="chat.addContext">${escapeHtml(contextLabel)}</button>
          </div>
          <textarea
            data-chat-composer-input
            rows="2"
            placeholder="Describe what to build next"
            aria-label="Describe what to build next"
          ></textarea>
          <div class="operator-chat-composer__controls">
            <button type="button" aria-label="Attach editor context" data-bridge-request="chat.attachEditorContext">▱</button>
            <button type="button" aria-label="Context options" data-bridge-request="chat.contextOptions">⌁</button>
            <select aria-label="Mode" data-chat-mode>
              <option>${escapeHtml(modeLabel)}</option>
            </select>
            <select aria-label="Model" data-chat-model>
              <option>${escapeHtml(modelLabel)}</option>
            </select>
            <button type="button" aria-label="Tool controls" data-bridge-request="chat.toolControls">♮</button>
            <button class="operator-chat-send" type="submit" aria-label="Send chat request">▷</button>
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
      body {
        margin: 0;
        padding: 16px;
        font-family: var(--vscode-font-family);
        color: var(--vscode-foreground);
        background: var(--vscode-sideBar-background);
      }
      body.is-chat-view {
        padding: 0 16px 16px;
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
        min-height: calc(100vh - 32px);
        display: grid;
        grid-template-rows: minmax(240px, 1fr) auto;
        gap: 16px;
        background: var(--vscode-sideBar-background);
        color: var(--vscode-foreground);
      }
      .operator-chat-empty {
        align-self: center;
        justify-self: center;
        max-width: 290px;
        text-align: center;
        color: var(--vscode-foreground);
      }
      .operator-chat-empty__icon {
        width: 42px;
        height: 42px;
        margin: 0 auto 12px;
        color: var(--vscode-foreground);
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
        margin: 0 0 8px;
        font-size: 22px;
        font-weight: 500;
        line-height: 1.2;
      }
      .operator-chat-empty p {
        margin: 0;
        color: var(--vscode-descriptionForeground);
        line-height: 1.35;
      }
      .operator-chat-empty a {
        color: var(--vscode-textLink-foreground);
        text-decoration: none;
      }
      .operator-chat-bottom {
        display: grid;
        gap: 8px;
      }
      .operator-chat-suggestions {
        display: grid;
        gap: 8px;
      }
      .operator-chat-suggestions span {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        letter-spacing: 0.08em;
      }
      .operator-chat-suggestions div {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
      }
      .operator-chat-suggestion,
      .operator-chat-composer button,
      .operator-chat-composer select {
        border: 1px solid var(--vscode-button-border, var(--vscode-panel-border));
        border-radius: 4px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        font: inherit;
      }
      .operator-chat-suggestion,
      .operator-chat-composer button {
        padding: 5px 8px;
      }
      .operator-chat-composer {
        border: 1px solid var(--vscode-focusBorder);
        border-radius: 4px;
        padding: 8px;
        background: var(--vscode-input-background);
      }
      .operator-chat-composer__context-row {
        display: flex;
        gap: 6px;
        margin-bottom: 6px;
      }
      .operator-chat-composer textarea {
        width: 100%;
        min-height: 42px;
        resize: vertical;
        box-sizing: border-box;
        border: 0;
        outline: 0;
        padding: 0;
        background: transparent;
        color: var(--vscode-input-foreground);
        font: inherit;
      }
      .operator-chat-composer__controls {
        display: flex;
        align-items: center;
        gap: 6px;
        min-width: 0;
      }
      .operator-chat-composer select {
        min-width: 0;
        max-width: 116px;
        padding: 4px 6px;
      }
      .operator-chat-send {
        margin-left: auto;
        width: 28px;
        height: 28px;
      }
    </style>
  </head>
  <body class="${isChatView ? "is-chat-view" : ""}">
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
        });
      });
      const composer = document.querySelector("[data-chat-composer-form]");
      const composerInput = document.querySelector("[data-chat-composer-input]");
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
            mode: document.querySelector("[data-chat-mode]")?.value,
            model: document.querySelector("[data-chat-model]")?.value
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
  }

  resolveWebviewView(webviewView) {
    this.webviewView = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
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
    this.webviewView.webview.html = renderHtml(this.definition, state);
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
